//! Configuration profiles, policies, error mapping, and cross-crate type adapters
//! for the Hyphae v2 Unified Rust `Node`.

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use http::StatusCode;
use hyp_crypto::{CryptoError, SecretBackend};
use hyp_proto::address::{AddressError, NodeId, is_valid_topic};
use hyp_proto::cloudevent::{
    CloudEvent, CloudEventError, DEFAULT_MAX_HOPS, HARD_MAX_HOPS, TYPE_LOCAL_EVENT_V1,
    TYPE_SCHEDULED_MESSAGE_V1,
};
use hyp_proto::filter::{
    Filter, FilterError, SubscriptionDiagnostic, TopicMetadata, matches_filters,
};
use hyp_proto::manifest::{
    CapabilityToken, KvMode, KvWriteModel, ManifestError, NegotiationError, OkpCurve,
    OkpJwk as ProtoOkpJwk, ProtocolRange,
};
use hyp_proto::problem::ProblemDetails;
use hyp_proto::scopes::ScopePreset;
use hyp_store::{PeerProfile, StoreConfig, StoreError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use hyp_proto::manifest::{E2eePolicy, NodeProfile};
pub use hyp_proto::scopes::EscalationConfig;

/// Default Hyphae v2 SemVer version advertised in signed manifests.
pub const DEFAULT_HYPHAE_VERSION: &str = "2.2.0";

/// Multi-hop transit forwarding policy mode (§2.3).
///
/// **Hard security invariant:** Defaults strictly to [`ForwardingMode::Deny`];
/// no node is ever an implicit open relay.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ForwardingMode {
    #[default]
    Deny,
    Allowlist,
}

/// Declarative transit forwarding rule permitting cross-node event forwarding
/// when `ForwardingMode::Allowlist` is enabled (§2.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForwardingRule {
    /// Upstream origin or sender node ID (or `"*"`).
    pub from_peer: String,
    /// Downstream recipient peer ID (or `"*"`).
    pub to_peer: String,
    /// Optional topic filter (`None` matches any topic).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub topic: Option<String>,
    /// Optional per-rule hop cap (clamped to [`HARD_MAX_HOPS`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_hops: Option<u8>,
}

fn default_forwarding_max_hops() -> u8 {
    DEFAULT_MAX_HOPS
}

/// Cross-node forwarding & loop-prevention policy (§2.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForwardingPolicy {
    #[serde(default)]
    pub mode: ForwardingMode,
    #[serde(default)]
    pub rules: Vec<ForwardingRule>,
    /// Maximum hop count accepted/forwarded by this node (default 2, hard cap 4).
    #[serde(default = "default_forwarding_max_hops")]
    pub max_hops: u8,
}

impl Default for ForwardingPolicy {
    fn default() -> Self {
        Self {
            mode: ForwardingMode::Deny,
            rules: Vec::new(),
            max_hops: DEFAULT_MAX_HOPS,
        }
    }
}

impl ForwardingPolicy {
    /// Returns the effective hop limit clamped to `[1, HARD_MAX_HOPS]` (`1..=4`) so an explicit
    /// `maxHops: 0` never breaks normal ingest.
    pub fn effective_max_hops(&self) -> u8 {
        self.max_hops.clamp(1, HARD_MAX_HOPS)
    }

    /// Returns `true` if transit forwarding from `from_peer` to `to_peer` on `topic`
    /// is explicitly permitted by this policy.
    pub fn permits(&self, from_peer: &str, to_peer: &str, topic: &str) -> bool {
        match self.mode {
            ForwardingMode::Deny => false,
            ForwardingMode::Allowlist => self.rules.iter().any(|r| {
                let from_ok = r.from_peer == "*" || r.from_peer == from_peer;
                let to_ok = r.to_peer == "*" || r.to_peer == to_peer;
                let topic_ok = r.topic.as_deref().is_none_or(|t| t == "*" || t == topic);
                from_ok && to_ok && topic_ok
            }),
        }
    }
}

/// Static peer link configuration entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerConfig {
    pub peer_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub profile: NodeProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e2ee_policy: Option<E2eePolicy>,
    #[serde(default = "default_true")]
    pub auto_connect: bool,
}

fn default_true() -> bool {
    true
}

/// Configured event topic advertised by this node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TopicConfig {
    pub topic: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<TopicMetadata>,
    #[serde(default = "default_true")]
    pub has_provisioned_publisher: bool,
}

/// Configured Shared KV namespace advertised in authenticated manifests.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KvNamespaceConfig {
    pub name: String,
    pub mode: KvMode,
    pub write_model: KvWriteModel,
}

/// Access mode for a `#channel`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChannelMode {
    /// Any joined peer with `channel:post` scope may post (default).
    #[default]
    Open,
    /// Read-only broadcast room: any peer with `channel:join` may join and read
    /// (including E2EE decryption), but ONLY explicitly listed `writers` may post
    /// or rotate channel epochs — even if another peer holds `channel:post=*`.
    Announcement,
}

impl ChannelMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Announcement => "announcement",
        }
    }
}

/// Per-channel authorization policy (`open` vs read-only `announcement`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelPolicy {
    pub mode: ChannelMode,
    /// Explicit writer allowlist for `ChannelMode::Announcement` (`<node-id>` or `<node-id>/<handle>`).
    #[serde(default)]
    pub writers: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl ChannelPolicy {
    /// Default open channel policy (any joined peer with `channel:post` may post).
    pub fn open() -> Self {
        Self {
            mode: ChannelMode::Open,
            writers: Vec::new(),
            description: None,
        }
    }

    /// Read-only announcement channel policy permitting ONLY `writers` to post or rotate epochs.
    pub fn announcement<I, S>(writers: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut list: Vec<String> = writers.into_iter().map(Into::into).collect();
        list.sort();
        list.dedup();
        Self {
            mode: ChannelMode::Announcement,
            writers: list,
            description: None,
        }
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Returns `true` if `node_id` (or full `<node-id>/<handle>` `address`) is authorized to write
    /// under this policy. For `ChannelMode::Announcement`, fails closed unless explicitly listed.
    pub fn is_authorized_writer(&self, node_id: &str, address: Option<&str>) -> bool {
        match self.mode {
            ChannelMode::Open => true,
            ChannelMode::Announcement => self
                .writers
                .iter()
                .any(|w| w == node_id || address.is_some_and(|addr| w == addr)),
        }
    }

    /// Returns `true` if `node_id` has ANY write authorization (either directly by `node_id` or
    /// via one of its enrolled `<node_id>/<handle>` addresses).
    pub fn node_can_post(&self, node_id: &str, enrolled_addresses: &[String]) -> bool {
        match self.mode {
            ChannelMode::Open => true,
            ChannelMode::Announcement => self.writers.iter().any(|w| {
                w == node_id
                    || enrolled_addresses.iter().any(|addr| addr == w)
                    || w.strip_prefix(node_id)
                        .is_some_and(|rest| rest.starts_with('/'))
            }),
        }
    }
}

/// Opt-in self-service read-only guest pairing policy (`POST /v1/guest/pair`),
/// powering public stream hubs such as `public.hyphae.to`.
///
/// **Hard security invariant:** `enabled` defaults strictly to `false` (opt-in only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuestPairingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_guest_scopes")]
    pub scopes: Vec<String>,
    #[serde(default = "default_max_repos_per_guest")]
    pub max_repos_per_guest: usize,
    #[serde(default = "default_max_batches_per_hour")]
    pub max_batches_per_hour: u32,
    #[serde(default = "default_max_joins_per_minute")]
    pub max_joins_per_minute: u32,
}

fn default_guest_scopes() -> Vec<String> {
    ScopePreset::GuestRo.expand()
}

const fn default_max_repos_per_guest() -> usize {
    10
}

const fn default_max_batches_per_hour() -> u32 {
    60
}

const fn default_max_joins_per_minute() -> u32 {
    20
}

impl Default for GuestPairingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            scopes: default_guest_scopes(),
            max_repos_per_guest: default_max_repos_per_guest(),
            max_batches_per_hour: default_max_batches_per_hour(),
            max_joins_per_minute: default_max_joins_per_minute(),
        }
    }
}

/// Default route ID for the built-in socket-only local event ingestion route.
pub const DEFAULT_LOCAL_INGEST_ROUTE_ID: &str = "default-schedule";
/// Default target topic for local event ingestion (`local.schedule`).
pub const DEFAULT_LOCAL_INGEST_TOPIC: &str = "schedule";
/// Default steady-state rate limit (events/min) for a local ingest route.
pub const DEFAULT_LOCAL_INGEST_MAX_PER_MINUTE: u32 = 30;
/// Default burst allowance for a local ingest route.
pub const DEFAULT_LOCAL_INGEST_BURST: u32 = 10;
/// Default maximum inbound payload byte ceiling for a local ingest route (32 KiB).
pub const DEFAULT_LOCAL_INGEST_MAX_PAYLOAD_BYTES: usize = 32 * 1024;

/// Action taken when a local ingest route's token bucket is saturated.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LocalIngestLimitAction {
    /// Reject excess events fail-closed with `{ ok: false, error: "rate_limited", action: "drop", retryAfterMs }`.
    #[default]
    Drop,
    /// Collapse bursty excess events cleanly using a mailbox coalesce slot (`coalesced: true`).
    Coalesce,
}

impl LocalIngestLimitAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Drop => "drop",
            Self::Coalesce => "coalesce",
        }
    }
}

fn default_local_ingest_allowed_types() -> Vec<String> {
    vec![
        TYPE_SCHEDULED_MESSAGE_V1.to_string(),
        TYPE_LOCAL_EVENT_V1.to_string(),
    ]
}

fn default_local_ingest_allowed_topics() -> Vec<String> {
    vec!["schedule".to_string(), "local".to_string()]
}

const fn default_local_ingest_max_per_minute() -> u32 {
    DEFAULT_LOCAL_INGEST_MAX_PER_MINUTE
}

const fn default_local_ingest_burst() -> u32 {
    DEFAULT_LOCAL_INGEST_BURST
}

const fn default_local_ingest_max_payload_bytes() -> usize {
    DEFAULT_LOCAL_INGEST_MAX_PAYLOAD_BYTES
}

fn default_local_ingest_topic() -> String {
    DEFAULT_LOCAL_INGEST_TOPIC.to_string()
}

/// Declarative policy route for the socket-only local event ingestion server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalIngestRoute {
    /// Unique identifier for this route (e.g. `"default-schedule"`).
    pub id: String,
    /// Allowed CloudEvent `type` values (exact match or `"*"` wildcard). Empty denies all.
    #[serde(default = "default_local_ingest_allowed_types")]
    pub allowed_types: Vec<String>,
    /// Allowed local topic names (exact match or `"*"` wildcard). Empty denies all.
    #[serde(default = "default_local_ingest_allowed_topics")]
    pub allowed_topics: Vec<String>,
    /// Optional CloudEvents Subscriptions API Filter AST (non-empty = event must match ALL).
    #[serde(default)]
    pub filters: Vec<Filter>,
    /// Steady-state token refill rate per minute (default: `30`).
    #[serde(default = "default_local_ingest_max_per_minute")]
    pub max_per_minute: u32,
    /// Maximum burst tokens available immediately (default: `10`).
    #[serde(default = "default_local_ingest_burst")]
    pub burst: u32,
    /// Behavior when the route token bucket is saturated (`Drop` default or `Coalesce`).
    #[serde(default)]
    pub on_limit: LocalIngestLimitAction,
    /// Maximum inbound JSON/event byte size accepted by this route (default: `32_768`).
    #[serde(default = "default_local_ingest_max_payload_bytes")]
    pub max_payload_bytes: usize,
    /// Screen inbound events through the attached `SecurityGatePipeline` (default: `true`).
    #[serde(default = "default_true")]
    pub gate: bool,
    /// Require a valid Ed25519 `hyphaesig` extension signed by an active key in
    /// `human_authorities` (default: `false`; when present, `hyphaesig` is ALWAYS verified fail-closed).
    #[serde(default)]
    pub require_signature: bool,
    /// Optional default mailbox TTL hint in seconds applied to delivered local events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_ttl_seconds: Option<u64>,
    /// Optional default mailbox coalesce key hint applied to delivered local events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_coalesce_key: Option<String>,
}

impl LocalIngestRoute {
    /// Returns the built-in default route accepting `to.hyphae.scheduled.v1` and
    /// `to.hyphae.local.v1` on `["schedule", "local"]`.
    pub fn default_schedule_route() -> Self {
        Self {
            id: DEFAULT_LOCAL_INGEST_ROUTE_ID.to_string(),
            allowed_types: default_local_ingest_allowed_types(),
            allowed_topics: default_local_ingest_allowed_topics(),
            filters: Vec::new(),
            max_per_minute: DEFAULT_LOCAL_INGEST_MAX_PER_MINUTE,
            burst: DEFAULT_LOCAL_INGEST_BURST,
            on_limit: LocalIngestLimitAction::Drop,
            max_payload_bytes: DEFAULT_LOCAL_INGEST_MAX_PAYLOAD_BYTES,
            gate: true,
            require_signature: false,
            default_ttl_seconds: None,
            default_coalesce_key: None,
        }
    }

    /// Returns `true` if `event_type` matches this route's `allowed_types` allowlist.
    pub fn matches_type(&self, event_type: &str) -> bool {
        self.allowed_types
            .iter()
            .any(|pat| pat == "*" || pat == event_type)
    }

    /// Returns `true` if bare local `topic` matches this route's `allowed_topics` allowlist.
    pub fn matches_topic(&self, topic: &str) -> bool {
        self.allowed_topics.iter().any(|pat| {
            if pat == "*" {
                return true;
            }
            let normalized = pat.strip_prefix("local.").unwrap_or(pat.as_str());
            normalized == topic
        })
    }

    /// Returns `true` if `event` satisfies ALL configured CloudEvents filters on this route.
    pub fn matches_filters(&self, event: &CloudEvent) -> bool {
        self.filters.is_empty() || matches_filters(&self.filters, event)
    }
}

impl Default for LocalIngestRoute {
    fn default() -> Self {
        Self::default_schedule_route()
    }
}

/// Configuration for the default-enabled socket-only local event ingestion route.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalIngestConfig {
    /// Enable the socket-only local ingest listener (default: `true`).
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Optional explicit socket/address path (defaults to `<state_dir>/ingest.sock` on Unix,
    /// `<state_dir>/ingest.addr` on Windows).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_path: Option<PathBuf>,
    /// Default target topic when an inbound event omits `topic` (default: `"schedule"` -> `local.schedule`).
    #[serde(default = "default_local_ingest_topic")]
    pub default_topic: String,
    /// Ordered route policy rules; when empty, `effective_routes()` returns `[LocalIngestRoute::default_schedule_route()]`.
    #[serde(default)]
    pub routes: Vec<LocalIngestRoute>,
}

impl Default for LocalIngestConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            socket_path: None,
            default_topic: default_local_ingest_topic(),
            routes: Vec::new(),
        }
    }
}

impl LocalIngestConfig {
    /// Platform-native default local ingest endpoint filename inside `<state_dir>`.
    #[cfg(unix)]
    pub const fn default_socket_filename() -> &'static str {
        "ingest.sock"
    }

    /// Platform-native default local ingest endpoint filename inside `<state_dir>`.
    #[cfg(not(unix))]
    pub const fn default_socket_filename() -> &'static str {
        "ingest.addr"
    }

    /// Resolves the socket/address path relative to `state_dir`.
    pub fn resolved_socket_path(&self, state_dir: &Path) -> PathBuf {
        self.socket_path
            .clone()
            .unwrap_or_else(|| state_dir.join(Self::default_socket_filename()))
    }

    /// Returns the configured routes, falling back to the single built-in default route when empty.
    pub fn effective_routes(&self) -> Vec<LocalIngestRoute> {
        if self.routes.is_empty() {
            vec![LocalIngestRoute::default_schedule_route()]
        } else {
            self.routes.clone()
        }
    }

    /// Returns deduplicated concrete local topics advertised by this local ingest configuration
    /// (excluding `"*"` wildcards), preserving `default_topic` first.
    pub fn advertised_topics(&self) -> Vec<String> {
        if !self.enabled {
            return Vec::new();
        }
        let mut out = Vec::new();
        let mut push_unique = |raw: &str| {
            let trimmed = raw.trim();
            if trimmed == "*" {
                return;
            }
            let bare = trimmed.strip_prefix("local.").unwrap_or(trimmed);
            if is_valid_topic(bare) && !out.iter().any(|t| t == bare) {
                out.push(bare.to_string());
            }
        };
        push_unique(&self.default_topic);
        for route in self.effective_routes() {
            for topic in &route.allowed_topics {
                push_unique(topic);
            }
        }
        out
    }
}

/// Complete configuration for a Hyphae v2 Unified `Node` (§1.3).
#[derive(Debug, Clone)]
pub struct NodeConfig {
    pub node_id: NodeId,
    pub profile: NodeProfile,
    pub state_dir: PathBuf,
    pub bind_addr: Option<SocketAddr>,
    pub public_endpoint: Option<String>,
    pub hyphae_version: String,
    pub protocol_range: ProtocolRange,
    pub e2ee_policy: E2eePolicy,
    pub forwarding: ForwardingPolicy,
    pub escalation: EscalationConfig,
    /// Opt-in self-service `guest-ro` pairing policy (`POST /v1/guest/pair`; default disabled).
    pub guest_pairing: GuestPairingConfig,
    /// Opt-in RAM-only Blind Ephemeral Drop Relay configuration (default: disabled).
    pub drop_relay: crate::engine::drop_relay::DropRelayConfig,
    /// Optional external blind drop relay base URL configured for this node (default: `None`).
    pub drop_relay_url: Option<String>,
    /// Optional self-hosted static Drop Portal UI base URL (default: `https://hyphae.to/drop`).
    /// Overridable via `node.json` (`dropPortalUrl`) or `HYPHAE_DROP_PORTAL_URL`.
    pub drop_portal_url: Option<String>,
    /// Default-enabled socket-only local event ingestion policy (`<state_dir>/ingest.sock` / `ingest.addr`).
    pub local_ingest: LocalIngestConfig,
    pub peers: Vec<PeerConfig>,
    pub topics: Vec<TopicConfig>,
    pub kv_namespaces: Vec<KvNamespaceConfig>,
    /// Declarative per-channel policies (e.g. `#announcements` -> `ChannelPolicy::announcement(...)`).
    pub channel_policies: BTreeMap<String, ChannelPolicy>,
    /// Opt-in A2A Agent Card projection at `GET /.well-known/agent.json` (default: `false` -> 404).
    pub expose_a2a_card: bool,
    /// Explicit trusted reverse-proxy IP / CIDR allowlist (e.g. `["127.0.0.1/32", "::1/128"]`)
    /// authorized to supply `X-Forwarded-For` for Drop Relay per-IP rate limiting (`H7`).
    /// Defaults to empty (= NEVER trust `X-Forwarded-For`).
    pub trusted_proxies: Vec<String>,
    pub require_pairing: bool,
    /// Optional Org Admin-CA Ed25519 root public key for verifying `am2_` grants.
    pub admin_jwk: Option<ProtoOkpJwk>,
    /// Optional explicit secret backend override (use `Some(SecretBackend::File)` in tests!).
    pub secret_backend: Option<SecretBackend>,
    pub store_config: StoreConfig,
    /// Optional override for advertised capability tokens (primarily for skew/downgrade testing).
    pub capabilities_override: Option<Vec<CapabilityToken>>,
}

impl NodeConfig {
    /// Creates a `NodeConfig` for a given `node_id`, `profile`, and `state_dir`.
    pub fn new(node_id: NodeId, profile: NodeProfile, state_dir: impl Into<PathBuf>) -> Self {
        Self {
            node_id,
            profile,
            state_dir: state_dir.into(),
            bind_addr: None,
            public_endpoint: None,
            hyphae_version: DEFAULT_HYPHAE_VERSION.to_string(),
            protocol_range: ProtocolRange { min: 1, max: 2 },
            e2ee_policy: E2eePolicy::Required,
            forwarding: ForwardingPolicy::default(),
            escalation: EscalationConfig::default(),
            guest_pairing: GuestPairingConfig::default(),
            drop_relay: crate::engine::drop_relay::DropRelayConfig::default(),
            drop_relay_url: None,
            drop_portal_url: None,
            local_ingest: LocalIngestConfig::default(),
            peers: Vec::new(),
            topics: Vec::new(),
            kv_namespaces: Vec::new(),
            channel_policies: BTreeMap::new(),
            expose_a2a_card: false,
            trusted_proxies: Vec::new(),
            require_pairing: true,
            admin_jwk: None,
            secret_backend: None,
            store_config: StoreConfig::default(),
            capabilities_override: None,
        }
    }

    pub fn local(node_id: NodeId, state_dir: impl Into<PathBuf>) -> Self {
        Self::new(node_id, NodeProfile::Local, state_dir)
    }

    pub fn router(node_id: NodeId, state_dir: impl Into<PathBuf>) -> Self {
        Self::new(node_id, NodeProfile::Router, state_dir)
    }

    pub fn p2p(node_id: NodeId, state_dir: impl Into<PathBuf>) -> Self {
        Self::new(node_id, NodeProfile::P2p, state_dir)
    }

    /// Returns the default full v2 capability token list for this node (or `capabilities_override`).
    pub fn advertised_capabilities(&self) -> Vec<CapabilityToken> {
        if let Some(ref custom) = self.capabilities_override {
            return custom.clone();
        }
        vec![
            CapabilityToken::ManifestV1,
            CapabilityToken::EnvelopeCeV1,
            CapabilityToken::DmV1,
            CapabilityToken::DmE2eeV1,
            CapabilityToken::ChannelV1,
            CapabilityToken::ChannelE2eeV1,
            CapabilityToken::TransferV1,
            CapabilityToken::TransferStreamV2,
            CapabilityToken::EventsV1,
            CapabilityToken::SubPushdownV1,
            CapabilityToken::EventsE2eeV1,
            CapabilityToken::KvV1,
            CapabilityToken::KvE2eeV1,
            CapabilityToken::PairingAdminCaV1,
            CapabilityToken::PairingP2pMutualV1,
            CapabilityToken::P2pDirectV1,
        ]
    }
}

/// Normalizes IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) into plain `IpAddr::V4`.
pub fn normalize_ip_addr(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// Pure-stdlib parsed IPv4 or IPv6 CIDR entry for `trusted_proxies` matching (`H7`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustedProxyCidr {
    V4 { network: u32, mask: u32 },
    V6 { network: u128, mask: u128 },
}

impl TrustedProxyCidr {
    /// Parses a single IP (`"127.0.0.1"`, `"::1"`) or CIDR (`"10.0.0.1/32"`, `"fd00::/8"`).
    pub fn parse(raw: &str) -> Result<Self, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("trusted proxy CIDR must not be empty".to_string());
        }
        let (addr_str, prefix_opt) = match trimmed.split_once('/') {
            Some((a, p)) => (a.trim(), Some(p.trim())),
            None => (trimmed, None),
        };
        let parsed_ip: IpAddr = addr_str
            .parse()
            .map_err(|_| format!("invalid IP address '{addr_str}' in trustedProxies '{raw}'"))?;
        match parsed_ip {
            IpAddr::V4(v4) => {
                let prefix: u32 = match prefix_opt {
                    Some(p) => p.parse().map_err(|_| {
                        format!("invalid IPv4 prefix length '{p}' in trustedProxies '{raw}'")
                    })?,
                    None => 32,
                };
                if prefix > 32 {
                    return Err(format!(
                        "IPv4 prefix length /{prefix} exceeds 32 in trustedProxies '{raw}'"
                    ));
                }
                let mask = if prefix == 0 {
                    0u32
                } else {
                    !0u32 << (32 - prefix)
                };
                Ok(Self::V4 {
                    network: u32::from(v4) & mask,
                    mask,
                })
            }
            IpAddr::V6(v6) => {
                if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                    let prefix: u32 = match prefix_opt {
                        Some(p) => {
                            let p6: u32 = p.parse().map_err(|_| {
                                format!(
                                    "invalid IPv6 prefix length '{p}' in trustedProxies '{raw}'"
                                )
                            })?;
                            if !(96..=128).contains(&p6) {
                                return Err(format!(
                                    "IPv4-mapped IPv6 prefix /{p6} must be in 96..=128 in trustedProxies '{raw}'"
                                ));
                            }
                            p6 - 96
                        }
                        None => 32,
                    };
                    let mask = if prefix == 0 {
                        0u32
                    } else {
                        !0u32 << (32 - prefix)
                    };
                    return Ok(Self::V4 {
                        network: u32::from(mapped_v4) & mask,
                        mask,
                    });
                }
                let prefix: u32 = match prefix_opt {
                    Some(p) => p.parse().map_err(|_| {
                        format!("invalid IPv6 prefix length '{p}' in trustedProxies '{raw}'")
                    })?,
                    None => 128,
                };
                if prefix > 128 {
                    return Err(format!(
                        "IPv6 prefix length /{prefix} exceeds 128 in trustedProxies '{raw}'"
                    ));
                }
                let mask = if prefix == 0 {
                    0u128
                } else {
                    !0u128 << (128 - prefix)
                };
                Ok(Self::V6 {
                    network: u128::from(v6) & mask,
                    mask,
                })
            }
        }
    }

    /// Returns `true` iff `ip` falls inside this CIDR (normalizing IPv4-mapped IPv6 addresses).
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self, normalize_ip_addr(ip)) {
            (Self::V4 { network, mask }, IpAddr::V4(v4)) => (u32::from(v4) & *mask) == *network,
            (Self::V6 { network, mask }, IpAddr::V6(v6)) => (u128::from(v6) & *mask) == *network,
            _ => false,
        }
    }
}

/// Validates a `trustedProxies` CIDR entry string.
pub fn validate_trusted_proxy_cidr(raw: &str) -> Result<TrustedProxyCidr, String> {
    TrustedProxyCidr::parse(raw)
}

/// Returns `true` iff `ip` matches ANY valid CIDR/IP entry in `trusted_proxies`.
/// Invalid entries are ignored fail-closed.
pub fn ip_matches_trusted_proxies(ip: IpAddr, trusted_proxies: &[String]) -> bool {
    let norm = normalize_ip_addr(ip);
    trusted_proxies
        .iter()
        .filter_map(|raw| TrustedProxyCidr::parse(raw).ok())
        .any(|cidr| cidr.contains(norm))
}

/// Unified error type returned by `UnifiedNode`, `PeerLink`, and HTTP server handlers.
#[derive(Debug, Error)]
pub enum NodeError {
    #[error("store error: {0}")]
    Store(#[from] StoreError),

    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("address error: {0}")]
    Address(#[from] AddressError),

    #[error("cloudevent error: {0}")]
    CloudEvent(#[from] CloudEventError),

    #[error("filter error: {0}")]
    Filter(#[from] FilterError),

    #[error("manifest error: {0}")]
    Manifest(#[from] ManifestError),

    #[error("negotiation error: {0}")]
    Negotiation(#[from] NegotiationError),

    #[error("scope denied: missing '{missing_scope}'")]
    ScopeDenied {
        missing_scope: String,
        current_scopes: Vec<String>,
        escalation_note: Option<String>,
    },

    #[error("channel '{channel}' is read-only (announcement mode)")]
    ChannelReadOnly {
        channel: String,
        escalation_note: Option<String>,
    },

    #[error("routing loop detected at '{node_id}'")]
    RoutingLoop { node_id: String, via: Vec<String> },

    #[error("hop limit exceeded: {hops} >= {max_hops}")]
    HopLimitExceeded { hops: u8, max_hops: u8 },

    #[error("capability unsupported: {}", .0.detail.as_deref().unwrap_or(&.0.title))]
    CapabilityUnsupported(Box<ProblemDetails>),

    #[error("remote peer returned HTTP {} ({}): {}", .0.status, .0.error, .0.detail.as_deref().unwrap_or(&.0.title))]
    RemoteProblem(Box<ProblemDetails>),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("peer key mismatch: {0}")]
    PeerKeyMismatch(String),

    #[error("human key mismatch: {0}")]
    HumanKeyMismatch(String),

    #[error("rate limited: {detail}")]
    RateLimited {
        detail: String,
        retry_after_secs: Option<u64>,
    },

    #[error("subscription rejected: {detail}")]
    SubscriptionRejected {
        detail: String,
        diagnostics: Vec<SubscriptionDiagnostic>,
    },

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("payload too large: {0}")]
    PayloadTooLarge(String),

    #[error("drop relay error: {0}")]
    DropRelay(#[from] crate::engine::drop_relay::DropRelayError),

    #[error("http transport error: {0}")]
    Http(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

impl NodeError {
    /// Converts this error into a standard RFC 9457 `ProblemDetails` payload.
    pub fn to_problem_details(&self) -> ProblemDetails {
        match self {
            Self::ScopeDenied {
                missing_scope,
                current_scopes,
                escalation_note,
            } => ProblemDetails::not_granted(
                missing_scope,
                current_scopes,
                escalation_note.as_deref(),
            ),
            Self::ChannelReadOnly {
                channel,
                escalation_note,
            } => {
                let mut p = ProblemDetails::new(
                    "channel_read_only",
                    "channel-read-only",
                    "Channel is read-only (announcement mode)",
                    403,
                    format!(
                        "Channel '{channel}' is in read-only announcement mode; only authorized writers may post."
                    ),
                )
                .with_extension("channel", serde_json::json!(channel));
                if let Some(note) = escalation_note {
                    p = p.with_extension("escalationNote", serde_json::json!(note));
                }
                p
            }
            Self::RoutingLoop { node_id, via } => ProblemDetails::routing_loop(node_id, via),
            Self::HopLimitExceeded { hops, max_hops } => {
                ProblemDetails::hop_limit_exceeded(*hops, *max_hops)
            }
            Self::CapabilityUnsupported(p) | Self::RemoteProblem(p) => (**p).clone(),
            Self::Negotiation(e) => e.to_problem_details(),
            Self::Unauthorized(msg) => ProblemDetails::new(
                "unauthorized",
                "unauthorized",
                "Unauthorized",
                401,
                msg.clone(),
            ),
            Self::NotFound(msg) => {
                ProblemDetails::new("not_found", "not-found", "Not Found", 404, msg.clone())
            }
            Self::Conflict(msg) => {
                ProblemDetails::new("conflict", "conflict", "Conflict", 409, msg.clone())
            }
            Self::PeerKeyMismatch(msg) => ProblemDetails::new(
                "peer_key_mismatch",
                "peer-key-mismatch",
                "Peer Key Mismatch",
                409,
                msg.clone(),
            )
            .with_extension("code", serde_json::json!("peer_key_mismatch")),
            Self::HumanKeyMismatch(msg) => ProblemDetails::new(
                "human_key_mismatch",
                "human-key-mismatch",
                "Human Key Mismatch",
                409,
                msg.clone(),
            )
            .with_extension("code", serde_json::json!("human_key_mismatch")),
            Self::RateLimited { detail, .. } => ProblemDetails::new(
                "rate_limited",
                "rate-limited",
                "Rate Limited",
                429,
                detail.clone(),
            )
            .with_extension("code", serde_json::json!("rate_limited")),
            Self::SubscriptionRejected {
                detail,
                diagnostics,
            } => {
                let mut p = ProblemDetails::new(
                    "subscription_rejected",
                    "subscription-rejected",
                    "Subscription Rejected",
                    422,
                    detail.clone(),
                )
                .with_extension("code", serde_json::json!("subscription_rejected"))
                .with_extension(
                    "diagnostics",
                    serde_json::to_value(diagnostics).unwrap_or_else(|_| serde_json::json!([])),
                );
                p.problem_type = "https://hyphae.to/problems/subscription-rejected".to_string();
                p
            }
            Self::BadRequest(msg) => ProblemDetails::new(
                "bad_request",
                "bad-request",
                "Bad Request",
                400,
                msg.clone(),
            ),
            Self::PayloadTooLarge(msg) => ProblemDetails::new(
                "too_large",
                "too-large",
                "Payload Too Large",
                413,
                msg.clone(),
            ),
            Self::Address(e) => ProblemDetails::new(
                "invalid_address",
                "invalid-address",
                "Invalid Address",
                400,
                e.to_string(),
            ),
            Self::CloudEvent(e) => {
                let status = if matches!(e, CloudEventError::TooLarge(_)) {
                    413
                } else {
                    400
                };
                ProblemDetails::new(
                    e.code(),
                    e.code(),
                    "Invalid CloudEvent",
                    status,
                    e.to_string(),
                )
            }
            Self::Filter(e) => ProblemDetails::new(
                "invalid_filter",
                "invalid-filter",
                "Invalid Filter",
                400,
                e.to_string(),
            ),
            Self::Manifest(e) => ProblemDetails::new(
                "invalid_manifest",
                "invalid-manifest",
                "Invalid Manifest",
                400,
                e.to_string(),
            ),
            Self::Crypto(e) => ProblemDetails::new(
                "crypto_error",
                "crypto-error",
                "Cryptographic Verification Failed",
                400,
                e.to_string(),
            ),
            Self::Store(err) => store_error_to_problem(err),
            Self::DropRelay(err) => err.to_problem_details(),
            Self::Http(msg) => ProblemDetails::new(
                "bad_gateway",
                "bad-gateway",
                "Upstream Peer Error",
                502,
                msg.clone(),
            ),
            Self::Json(e) => ProblemDetails::new(
                "invalid_json",
                "invalid-json",
                "Invalid JSON",
                400,
                e.to_string(),
            ),
            Self::Io(e) => ProblemDetails::new(
                "internal_error",
                "internal-error",
                "Internal I/O Error",
                500,
                e.to_string(),
            ),
        }
    }

    pub fn status_code(&self) -> StatusCode {
        let p = self.to_problem_details();
        StatusCode::from_u16(p.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

fn store_error_to_problem(err: &StoreError) -> ProblemDetails {
    match err {
        StoreError::InvalidInput(m) => {
            ProblemDetails::new("invalid_input", "invalid-input", "Invalid Input", 400, m)
        }
        StoreError::InvalidFilter { path, message } => ProblemDetails::new(
            "invalid_filter",
            "invalid-filter",
            "Invalid Filter",
            400,
            format!("{path}: {message}"),
        ),
        StoreError::NotFound(m) => {
            ProblemDetails::new("not_found", "not-found", "Not Found", 404, m)
        }
        StoreError::Unauthorized(m) => {
            ProblemDetails::new("unauthorized", "unauthorized", "Unauthorized", 403, m)
        }
        StoreError::IdConflict(m) => {
            ProblemDetails::new("id_conflict", "id-conflict", "ID Conflict", 409, m)
        }
        StoreError::TooLarge(m) => {
            ProblemDetails::new("too_large", "too-large", "Payload Too Large", 413, m)
        }
        StoreError::QuotaExceeded(m) => {
            ProblemDetails::new("quota_exceeded", "quota-exceeded", "Quota Exceeded", 429, m)
        }
        StoreError::RateLimited(m) => {
            ProblemDetails::new("rate_limited", "rate-limited", "Rate Limited", 429, m)
        }
        StoreError::VersionConflict { current_version } => {
            ProblemDetails::version_conflict(0, *current_version, None, None)
        }
        StoreError::ManifestRollback {
            peer_id,
            expected_min,
            received,
        } => ProblemDetails::manifest_rollback_detected(
            peer_id,
            (*received).max(0) as u64,
            (*expected_min).max(0) as u64,
        ),
        StoreError::CapabilityDowngrade {
            peer_id,
            missing_capabilities,
        } => {
            let tokens: Vec<CapabilityToken> = missing_capabilities
                .iter()
                .filter_map(|s| CapabilityToken::from_token_str(s).ok())
                .collect();
            ProblemDetails::capability_downgrade_detected(peer_id, &tokens)
        }
        StoreError::CheckpointRollback {
            authority_id,
            expected_min,
            received,
        } => ProblemDetails::new(
            "checkpoint_rollback",
            "checkpoint-rollback",
            "Directory Checkpoint Rollback",
            409,
            format!("Authority '{authority_id}' presented checkpoint {received} < {expected_min}."),
        ),
        StoreError::EpochConflict { scope, message } => ProblemDetails::new(
            "epoch_conflict",
            "epoch-conflict",
            "Epoch Conflict",
            409,
            format!("{scope}: {message}"),
        ),
        StoreError::InvalidState(m) => {
            ProblemDetails::new("invalid_state", "invalid-state", "Invalid State", 409, m)
        }
        StoreError::Expired(m) => {
            ProblemDetails::new("expired", "expired", "Resource Expired", 410, m)
        }
        StoreError::AlreadyPaired(m) => {
            ProblemDetails::new("already_paired", "already-paired", "Already Paired", 409, m)
        }
        other => ProblemDetails::new(
            "internal_error",
            "internal-error",
            "Internal Storage Error",
            500,
            other.to_string(),
        ),
    }
}

// ============================================================================
// Cross-crate pure type converters (`hyp-proto` <-> `hyp-crypto` <-> `hyp-store`)
// ============================================================================

pub(crate) fn crypto_jwk_to_proto(jwk: &hyp_crypto::OkpJwk) -> Result<ProtoOkpJwk, NodeError> {
    let crv = match jwk.crv.as_str() {
        "Ed25519" => OkpCurve::Ed25519,
        "X25519" => OkpCurve::X25519,
        other => {
            return Err(NodeError::BadRequest(format!(
                "unsupported OKP curve '{other}'"
            )));
        }
    };
    let out = ProtoOkpJwk {
        kty: jwk.kty.clone(),
        crv,
        x: jwk.x.clone(),
    };
    out.validate(Some(crv))?;
    Ok(out)
}

pub(crate) fn proto_jwk_to_crypto(jwk: &ProtoOkpJwk) -> hyp_crypto::OkpJwk {
    hyp_crypto::OkpJwk {
        kty: jwk.kty.clone(),
        crv: jwk.crv.as_str().to_string(),
        x: jwk.x.clone(),
    }
}

pub(crate) fn proto_filter_to_store(f: &hyp_proto::filter::Filter) -> hyp_store::Filter {
    match f {
        hyp_proto::filter::Filter::Exact(m) => hyp_store::Filter::Exact(m.clone()),
        hyp_proto::filter::Filter::Prefix(m) => hyp_store::Filter::Prefix(m.clone()),
        hyp_proto::filter::Filter::Suffix(m) => hyp_store::Filter::Suffix(m.clone()),
        hyp_proto::filter::Filter::All(v) => {
            hyp_store::Filter::All(v.iter().map(proto_filter_to_store).collect())
        }
        hyp_proto::filter::Filter::Any(v) => {
            hyp_store::Filter::Any(v.iter().map(proto_filter_to_store).collect())
        }
        hyp_proto::filter::Filter::Not(inner) => {
            hyp_store::Filter::Not(Box::new(proto_filter_to_store(inner)))
        }
    }
}

pub(crate) fn store_filter_to_proto(f: &hyp_store::Filter) -> hyp_proto::filter::Filter {
    match f {
        hyp_store::Filter::Exact(m) => hyp_proto::filter::Filter::Exact(m.clone()),
        hyp_store::Filter::Prefix(m) => hyp_proto::filter::Filter::Prefix(m.clone()),
        hyp_store::Filter::Suffix(m) => hyp_proto::filter::Filter::Suffix(m.clone()),
        hyp_store::Filter::All(v) => {
            hyp_proto::filter::Filter::All(v.iter().map(store_filter_to_proto).collect())
        }
        hyp_store::Filter::Any(v) => {
            hyp_proto::filter::Filter::Any(v.iter().map(store_filter_to_proto).collect())
        }
        hyp_store::Filter::Not(inner) => {
            hyp_proto::filter::Filter::Not(Box::new(store_filter_to_proto(inner)))
        }
    }
}

pub(crate) fn proto_ce_to_store(
    ev: &hyp_proto::cloudevent::CloudEvent,
) -> Result<hyp_store::CloudEvent, NodeError> {
    let mut extensions = BTreeMap::new();
    for (k, v) in &ev.extensions {
        let s = match v {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        };
        extensions.insert(k.clone(), s);
    }
    let data = match (&ev.data, &ev.data_base64) {
        (Some(d), _) => {
            if d.is_object() {
                d.clone()
            } else {
                serde_json::json!({ "value": d })
            }
        }
        (None, Some(b64)) => serde_json::json!({ "data_base64": b64 }),
        (None, None) => serde_json::json!({}),
    };
    Ok(hyp_store::CloudEvent {
        specversion: ev.specversion.clone(),
        id: ev.id.clone(),
        source: ev.source.clone(),
        event_type: ev.event_type.clone(),
        datacontenttype: ev
            .datacontenttype
            .clone()
            .unwrap_or_else(|| hyp_proto::cloudevent::CONTENT_TYPE_JSON.to_string()),
        subject: ev.subject.clone(),
        time: ev.time.clone(),
        dataschema: ev.dataschema.clone(),
        data,
        extensions,
    })
}

pub(crate) fn store_ce_to_proto(ev: &hyp_store::CloudEvent) -> hyp_proto::cloudevent::CloudEvent {
    let mut extensions = BTreeMap::new();
    for (k, v) in &ev.extensions {
        extensions.insert(k.clone(), serde_json::Value::String(v.clone()));
    }
    hyp_proto::cloudevent::CloudEvent {
        specversion: ev.specversion.clone(),
        id: ev.id.clone(),
        source: ev.source.clone(),
        event_type: ev.event_type.clone(),
        datacontenttype: Some(ev.datacontenttype.clone()),
        dataschema: ev.dataschema.clone(),
        subject: ev.subject.clone(),
        time: ev.time.clone(),
        data: Some(ev.data.clone()),
        data_base64: None,
        extensions,
    }
}

pub(crate) fn profile_to_store(p: NodeProfile) -> PeerProfile {
    match p {
        NodeProfile::Local => PeerProfile::Local,
        NodeProfile::Router => PeerProfile::Router,
        NodeProfile::P2p => PeerProfile::P2p,
    }
}

/// Default official static Verified Human Drops portal URL.
pub const DEFAULT_DROP_PORTAL_URL: &str = "https://hyphae.to/drop";

/// Environment variable overriding the Drop Portal base URL for self-hosted UIs.
pub const ENV_DROP_PORTAL_URL: &str = "HYPHAE_DROP_PORTAL_URL";

/// Validates and normalizes a Drop Portal base URL (must be `https://...` or loopback
/// `http://127.0.0.1` / `http://localhost`, with no `#fragment`, `?query`, whitespace, or control chars).
pub fn normalize_drop_portal_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("dropPortalUrl must not be empty".to_string());
    }
    if trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err("dropPortalUrl must not contain whitespace or control characters".to_string());
    }
    if trimmed.contains('#') || trimmed.contains('?') {
        return Err("dropPortalUrl must not include a query string or URL fragment".to_string());
    }
    let normalized = trimmed.trim_end_matches('/');
    let is_https = normalized.starts_with("https://") && normalized.len() > "https://".len();
    let is_loopback_http = normalized == "http://127.0.0.1"
        || normalized.starts_with("http://127.0.0.1:")
        || normalized.starts_with("http://127.0.0.1/")
        || normalized == "http://localhost"
        || normalized.starts_with("http://localhost:")
        || normalized.starts_with("http://localhost/");
    if !is_https && !is_loopback_http {
        return Err(
            "dropPortalUrl must use https:// (or loopback http://127.0.0.1 / http://localhost)"
                .to_string(),
        );
    }
    Ok(normalized.to_string())
}

/// Resolves the effective Drop Portal base URL from:
/// 1. `HYPHAE_DROP_PORTAL_URL` environment variable (if set and non-empty),
/// 2. Explicit `configured` (`node.json` `dropPortalUrl`),
/// 3. Default `https://hyphae.to/drop`.
///
/// Fails closed if an explicitly supplied URL is invalid.
pub fn resolve_drop_portal_url(configured: Option<&str>) -> Result<String, String> {
    if let Ok(env_val) = std::env::var(ENV_DROP_PORTAL_URL) {
        let trimmed = env_val.trim();
        if !trimmed.is_empty() {
            return normalize_drop_portal_url(trimmed);
        }
    }
    if let Some(cfg) = configured.map(str::trim).filter(|s| !s.is_empty()) {
        return normalize_drop_portal_url(cfg);
    }
    Ok(DEFAULT_DROP_PORTAL_URL.to_string())
}

#[allow(dead_code)]
pub(crate) fn store_to_profile(p: PeerProfile) -> NodeProfile {
    match p {
        PeerProfile::Local => NodeProfile::Local,
        PeerProfile::Router => NodeProfile::Router,
        PeerProfile::P2p => NodeProfile::P2p,
    }
}

#[cfg(test)]
mod drop_portal_url_tests {
    use super::*;

    #[test]
    fn normalize_drop_portal_url_accepts_https_and_loopback_and_fails_closed() {
        assert_eq!(
            normalize_drop_portal_url("https://drop.acme.com/").unwrap(),
            "https://drop.acme.com"
        );
        assert_eq!(
            normalize_drop_portal_url("https://acme.com/hyphae/drop///").unwrap(),
            "https://acme.com/hyphae/drop"
        );
        assert_eq!(
            normalize_drop_portal_url("http://127.0.0.1:8080/drop/").unwrap(),
            "http://127.0.0.1:8080/drop"
        );
        assert_eq!(
            normalize_drop_portal_url("http://localhost:3000").unwrap(),
            "http://localhost:3000"
        );

        for bad in [
            "",
            "   ",
            "http://drop.acme.com",
            "http://localhost.evil.com/drop",
            "http://127.0.0.1.evil.com/drop",
            "javascript:alert(1)",
            "https://drop.acme.com#frag",
            "https://drop.acme.com?foo=bar",
            "https://drop.acme.com/ bad",
            "https://",
        ] {
            assert!(
                normalize_drop_portal_url(bad).is_err(),
                "expected '{bad}' to be rejected"
            );
        }
    }
}
