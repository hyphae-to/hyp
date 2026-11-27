//! Standalone async native Rust `LocalDaemon` (`connector.sock` on Unix / `127.0.0.1:0` ->
//! `connector.addr` on Windows).
//!
//! Replaces the Node.js `hyp daemon` cleanly in pure Rust by wrapping:
//! - [`UnifiedNode`] (single WAL `node.sqlite`, E2EE DMs/`#channels`/KV/transfers, pushdown streams)
//! - optional [`SecurityGatePipeline`] (post-decrypt inbound screening & pre-encrypt outbound DLP)
//! - [`DeliveryEngine`] (§2.5 3-tier urgency + silent `mute` archive, Focus Mode, Burst Protection,
//!   Token-Budget Hybrid Batch Packer, and filtered cursor-paginated `query_inbox`)
//! - [`CallRegistry`] (fail-closed host-verified caller resolution for hooks & MCP)
//! - live zero-polling transports (`wait`, `watch`, and `--claude-channel` push).

mod bridges;
mod connection;
mod delivery;
mod drops;
mod inspect;
mod session_runtime;
use inspect::{
    SessionSelector, extract_backend_str, handle_session_summary, handle_sessions_summary,
    run_inspect_watch, spawn_ui_state_projector, validate_control_pattern,
};
use session_runtime::SessionTimers;

use hyp_delivery_digest::DrainScope;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hyp_crypto::rfc3339::format_rfc3339_millis;
use hyp_node::delivery::{
    DEFAULT_MIDTURN_QUEUE_DIGEST_SECONDS, DeliveryEngine, DeliveryError, DeliveryRule,
    DeliveryUrgency, InboxFilter, InboxItemState, InboxItemView, InboxQuery, InboxQueryResult,
    InboxStateFilter, SessionDeliveryPolicy, archive_muted_entry, muted_count,
    query_inbox_for_node, record_delivered_receipts, urgency_cap_gate_reason,
};
pub use hyp_node::engine::WakeRecoveryConfig;
use hyp_node::engine::{
    DEFAULT_WAKE_CHECK_INTERVAL_SECS, KvWriteRequest, PeerReconcileReport, SubscribeRequest,
    UnifiedNode, format_human_duration, spawn_wake_watcher,
};
use hyp_node::gates::{
    GateDecision, InboundContext, OutboundContext, SecurityGatePipeline, TrustTier as GateTrustTier,
};
pub use hyp_node::node_file::DeliveryRetryConfig;
use hyp_proto::cloudevent::{CONTENT_TYPE_JSON, CloudEvent as ProtoCloudEvent, EXT_TRACEPARENT};
use hyp_proto::filter::Filter as ProtoFilter;
use hyp_store::{
    AckOutcome, DaemonNoticeKind, DeliveryMode, GateAuditQuery, GateState, MailboxEntry,
    MailboxInsert, MailboxKind, MailboxPutResult, MailboxVisibility, SubscriptionMeta, WriteModel,
    format_address, now_ms, parse_address, sha256_hex, uuid_v4,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use thiserror::Error;
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::call_registry::{CallRegistry, StartCallInput, is_valid_session_id};
use hyp_harness_ipc::protocol::{
    HarnessKind, TransportHintFields, is_bridge_destination, is_valid_router_name,
    normalize_mesh_tool_name,
};
use hyp_harness_ipc::sock::{
    DEFAULT_SOCKET_FILENAME, MAX_SOCKET_LINE_BYTES, read_bounded_line_async,
    write_ndjson_line_async,
};
use hyp_harness_transport::transport::codex::{
    CodexQueueTarget, CodexQueueTransport, DEFAULT_CODEX_BIN, build_codex_queue_args,
    codex_queue_supported, default_codex_home, is_valid_codex_uuid, verify_codex_rollout_thread,
};
use hyp_harness_transport::transport::herdr::{
    DEFAULT_HERDR_BIN, DEFAULT_SPAWN_TIMEOUT, HerdrProbeOutcome, HerdrTransport,
    is_valid_herdr_template, is_valid_terminal_id, probe_herdr_terminal_detailed,
    spawn_herdr_template,
};
use hyp_harness_transport::transport::openclaw::{
    DEFAULT_OPENCLAW_AGENT_ID, DEFAULT_OPENCLAW_PROBE_TIMEOUT, OpenClawNodeConfig,
    OpenClawTransport, canonical_openclaw_session_id, parse_openclaw_agent_id_from_session_key,
    probe_openclaw_gateway, validate_openclaw_session_key,
};
use hyp_harness_transport::transport::t3::{
    DEFAULT_PROBE_TIMEOUT, DEFAULT_T3_TOKEN_SECRET, DEFAULT_T3_URL, FALLBACK_T3_TOKEN_SECRET,
    T3Target, T3Transport, default_t3_base_dir, is_allowed_t3_token_secret,
    normalize_t3_server_url_with_remote, probe_t3_server_with_remote,
    resolve_t3_thread_by_provider_session, t3_state_db_path, verify_t3_thread_exists,
};
use hyp_harness_transport::transport::{PushOutcome, PushTransport};

pub use hyp_harness_ipc::kv_auth::DAEMON_SESSION_TOKEN_KEY_SECRET;
const SESSION_TOKEN_DOMAIN_PREFIX: &str = "hyphae-session-token-v1:";

const PRIORITY_EXPLICIT: u8 = 100;
const PRIORITY_HERDR: u8 = 30;
const PRIORITY_T3: u8 = 25;
const PRIORITY_OPENCLAW: u8 = 22;
const PRIORITY_CODEX_QUEUE: u8 = 20;

/// Schema version for `session.summary`, `sessions.summary`, `inspect.watch`, and `<state_dir>/ui/state.json`.
pub const UI_STATE_SCHEMA_VERSION: u32 = 1;
/// Hard cap on metadata-only `queuedItems` returned in `session.summary` / `ui/state.json`.
pub const MAX_SUMMARY_QUEUED_ITEMS: usize = 50;
/// Debounce window coalescing burst mutations before atomically rewriting `<state_dir>/ui/state.json`.
const UI_PROJECTOR_DEBOUNCE_MS: u64 = 100;
/// Coalescing window for live `inspect.watch` push frames.
const INSPECT_WATCH_DEBOUNCE_MS: u64 = 25;
/// Maximum allowed TTL (7 days) for temporary `session.mute` rules.
const MAX_MUTE_TTL_SECS: u64 = 7 * 24 * 60 * 60;
/// Default inactivity threshold (7 days) before stale idle sessions are pruned (`U6`).
pub const DEFAULT_SESSION_PRUNE_AFTER_MS: i64 = 7 * 24 * 60 * 60 * 1_000;
/// Default periodic interval (1 hour) for background session pruning and TTL mute sweeps (`U4`/`U6`).
pub const DEFAULT_SESSION_PRUNE_INTERVAL: Duration = Duration::from_secs(60 * 60);
/// Cap on per-session in-memory metadata-only quarantine notices (`G10`).
const MAX_QUARANTINE_NOTICES_PER_SESSION: usize = 64;
/// Minimum delayed retry interval (ms) for Security Gate `Hold` verdicts (`rate_limited`, `gate_busy`).
const GATE_HOLD_RETRY_MIN_MS: u64 = 500;
/// Maximum delayed retry interval (ms) for Security Gate `Hold` verdicts.
const GATE_HOLD_RETRY_MAX_MS: u64 = 30_000;
/// Small safety margin (ms) added to `retry_after_ms` so rate-limit token buckets cleanly refill.
const GATE_HOLD_RETRY_MARGIN_MS: u64 = 25;
/// Maximum consecutive Security Gate `Hold` retries per session without clearing all held items.
const GATE_HOLD_RETRY_MAX_ATTEMPTS: u32 = 16;

/// Default timeout waiting for a live `--claude-channel` `channel.ack`.
pub const DEFAULT_CHANNEL_DELIVER_TIMEOUT: Duration = Duration::from_secs(10);
/// Default per-peer connect timeout when reconciling persisted peers during `peers.reload`.
pub const DEFAULT_PEERS_RELOAD_TIMEOUT: Duration = Duration::from_millis(1_200);
/// Default grace window waiting for a mid-turn tool hook (`PostToolUse`) to drain an `Interrupt`
/// on an `Active` hooked session before falling back to an external L2 `PushTransport`.
pub const DEFAULT_INTERRUPT_HOOK_GRACE: Duration = Duration::from_secs(2);
/// Default sliding activity lease duration after the last hook call before a hooked session
/// without a TurnEnd (`Stop` / `agent_end`) event decays to `Idle` and flushes held `Queue` batches.
pub const DEFAULT_QUEUE_ACTIVITY_LEASE: Duration = Duration::from_secs(15);
/// Bounded cooldown between lazy transport rehydration probes for the same session inside
/// `flush_session_inner` so permanently dead targets never trigger probe loops.
const LAZY_HYDRATE_COOLDOWN: Duration = Duration::from_secs(30);
/// Default delay before the single post-wake follow-up flush (lets reconnecting PeerLinks
/// pull missed messages and flush them cleanly without duplicate deliveries).
pub const DEFAULT_WAKE_FOLLOWUP_FLUSH_DELAY: Duration = Duration::from_secs(2);
/// Upper bound waiting for external plugin `system.wake` notifications during wake recovery.
const WAKE_HOOK_BROADCAST_TIMEOUT: Duration = Duration::from_secs(2);

/// Boxed `Send` future alias used by [`BridgePoster`] and [`PeersReloader`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Pluggable async callback invoked whenever a `"peers.reload"` IPC RPC arrives on
/// `connector.sock` / `connector.addr`.
///
/// Wired by `hyp node start` to reconcile outbound `PeerLink` supervisors and refresh
/// `node.status.json`, or overridden in tests. When unset, [`LocalDaemon`] reconciles
/// persisted peers directly via [`UnifiedNode::reconcile_peers`].
pub trait PeersReloader: Send + Sync {
    fn reload_peers<'a>(&'a self) -> BoxFuture<'a, Result<PeerReconcileReport, String>>;
}

/// Pluggable async callback invoked during [`LocalDaemon::handle_system_wake`]
/// (e.g. to broadcast `system.wake` JSON-RPC notifications to external subprocess plugins).
pub trait WakeHook: Send + Sync {
    fn on_system_wake<'a>(&'a self, slept_for: Duration) -> BoxFuture<'a, ()>;
}

/// Structured summary returned by [`LocalDaemon::handle_system_wake`] and the `"system.wake"`
/// local IPC RPC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WakeRecoveryReport {
    pub wake_epoch: u64,
    pub slept_ms: u64,
    pub cleared_active_sessions: Vec<String>,
    pub cleared_hold_retries: usize,
    pub notified_sessions: Vec<String>,
    pub flushed_sessions: usize,
}

/// Pluggable callback invoked by the live `gate.reload` IPC RPC to re-read, validate, and
/// signature-verify a fresh [`SecurityGatePipeline`] without restarting [`LocalDaemon`].
///
/// Returning `Err(...)` fails closed and preserves the previously active pipeline intact.
pub type GateReloader =
    Arc<dyn Fn() -> Result<Option<Arc<SecurityGatePipeline>>, String> + Send + Sync>;

pub use bridges::BridgePoster;

#[derive(Debug, Error)]
pub enum DaemonError {
    #[error("daemon already running at {0}")]
    AlreadyRunning(PathBuf),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("node error: {0}")]
    Node(#[from] hyp_node::engine::NodeError),
}

/// Input payload for [`LocalDaemon::ingest_inbound`].
#[derive(Debug, Clone)]
pub struct InboundItem {
    pub session_id: String,
    pub origin_node: String,
    pub item_id: String,
    pub source: String,
    pub text: String,
    pub kind: MailboxKind,
    pub trust_tier: GateTrustTier,
}

/// Configuration for [`LocalDaemon`].
#[derive(Debug, Clone)]
pub struct LocalDaemonConfig {
    /// Explicit socket (`connector.sock`) or address (`connector.addr`) path.
    /// Defaults to `<node.state_dir>/<DEFAULT_SOCKET_FILENAME>`.
    pub socket_path: Option<PathBuf>,
    /// Require host-verified `PreToolUse` `callId`/`callToken` (or explicit `--ephemeral`) for `tool.call`.
    /// Defaults to `true` (fail-closed!).
    pub require_verified_caller: bool,
    /// Optional explicit override for advertising `hyp_kv` in `mcp.caps`.
    /// When `None`, auto-detects from local `kv_namespaces` or paired peer manifests.
    pub enable_kv: Option<bool>,
    /// Optional explicit override for advertising `hyp_bridge` in `mcp.caps`.
    pub enable_plugins: bool,
    /// Maximum time to wait for a `--claude-channel` `channel.ack` before preserving the batch
    /// as unread for hook/`hyp_inbox` fallback. Defaults to 10 seconds.
    pub channel_deliver_timeout: Duration,
    /// Enable automatic detection & attachment of native external push transports
    /// (`Herdr`, `T3 Code`, `Codex Queue`) from hook/MCP metadata.
    /// Defaults to `false` in `LocalDaemonConfig::default()` so hermetic unit/E2E tests
    /// never probe host binaries unexpectedly; `hyp node start` / `hyp daemon` enables it.
    pub auto_detect_transports: bool,
    /// Optional override for the Herdr (`hc`) binary path during auto-detection.
    pub herdr_bin: Option<String>,
    /// Optional override for the Codex (`codex`) binary path during auto-detection.
    pub codex_bin: Option<String>,
    /// Optional override for the default T3 Code base directory during auto-detection.
    pub t3_default_base_dir: Option<PathBuf>,
    /// Optional override for the default T3 Code server URL during auto-detection.
    pub t3_default_url: Option<String>,
    /// Tier 3 bounded `Hold` retry backoff and opt-in Tier 4 cold-revival settings.
    pub delivery_retry: DeliveryRetryConfig,
    /// Inactivity age threshold (ms) after which idle sessions without quarantined items are pruned
    /// on startup and periodically (`U6`/`G16`). Set `<= 0` to disable automatic pruning.
    pub session_prune_after_ms: i64,
    /// Periodic interval for background stale-session pruning and expired TTL mute sweeping.
    pub session_prune_interval: Duration,
    /// Bounded exponential reconnect backoff delays (ms) for external Blind Drop Relay SSE watchers (`H6`).
    pub drop_watcher_backoff_ms: Vec<u64>,
    /// Grace window waiting for a mid-turn tool hook (`PostToolUse`) to drain an `Interrupt`
    /// while a hooked session is `Active` before falling back to L2 `PushTransport`.
    pub interrupt_hook_grace: Duration,
    /// Sliding activity lease duration after the last hook call before an active hooked session
    /// without TurnEnd (`Stop` / `agent_end`) decays to `Idle` and flushes held `Queue` batches to L2.
    pub queue_activity_lease: Duration,
    /// Laptop sleep/wake recovery policy (`node.json` -> `wakeRecovery`).
    pub wake_recovery: WakeRecoveryConfig,
    /// Periodic check cadence for the zero-FFI wall-vs-monotonic wake watcher (default: 5s).
    pub wake_check_interval: Duration,
    /// Delay for the single `shutdown_rx`-cancellable post-wake follow-up flush (default: 2s).
    pub wake_followup_flush_delay: Duration,
    /// Interval (seconds) between periodic mid-turn `PostToolUse` `<hyphae-inbox urgency="queue">`
    /// digest reminders during long turns (RFC 0004 Decision #4). Default `1800` (30 min); `0` = disabled.
    pub midturn_queue_digest_seconds: u64,
}

impl Default for LocalDaemonConfig {
    fn default() -> Self {
        Self {
            socket_path: None,
            require_verified_caller: true,
            enable_kv: None,
            enable_plugins: false,
            channel_deliver_timeout: DEFAULT_CHANNEL_DELIVER_TIMEOUT,
            auto_detect_transports: false,
            herdr_bin: None,
            codex_bin: None,
            t3_default_base_dir: None,
            t3_default_url: None,
            delivery_retry: DeliveryRetryConfig::default(),
            session_prune_after_ms: DEFAULT_SESSION_PRUNE_AFTER_MS,
            session_prune_interval: DEFAULT_SESSION_PRUNE_INTERVAL,
            drop_watcher_backoff_ms: vec![500, 1_000, 2_000, 5_000],
            interrupt_hook_grace: DEFAULT_INTERRUPT_HOOK_GRACE,
            queue_activity_lease: DEFAULT_QUEUE_ACTIVITY_LEASE,
            wake_recovery: WakeRecoveryConfig::default(),
            wake_check_interval: Duration::from_secs(DEFAULT_WAKE_CHECK_INTERVAL_SECS),
            wake_followup_flush_delay: DEFAULT_WAKE_FOLLOWUP_FLUSH_DELAY,
            midturn_queue_digest_seconds: DEFAULT_MIDTURN_QUEUE_DIGEST_SECONDS,
        }
    }
}

#[derive(Clone)]
struct AttachedPushTransport {
    transport: Arc<dyn PushTransport>,
    priority: u8,
}

#[derive(Debug, Clone, Default)]
struct TransportHints {
    harness: Option<HarnessKind>,
    herdr_terminal_id: Option<String>,
    herdr_created_ms: Option<i64>,
    herdr_template: Option<String>,
    codex_thread_id: Option<String>,
    codex_home: Option<PathBuf>,
    codex_remote: Option<String>,
    codex_resume: bool,
    explicit_codex_queue: bool,
    t3_thread_id: Option<String>,
    t3_base_dir: Option<PathBuf>,
    t3_url: Option<String>,
    openclaw_session_key: Option<String>,
    openclaw_session_id: Option<String>,
    openclaw_agent_id: Option<String>,
    cwd: Option<String>,
}

impl TransportHints {
    fn from_packet(packet: &Map<String, Value>, default_harness: Option<HarnessKind>) -> Self {
        let fields = TransportHintFields::from_packet(packet);
        let clean = |value: Option<String>| {
            value.and_then(|value| {
                let trimmed = value.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_owned())
                }
            })
        };
        let non_empty_str = |key: &str| {
            packet
                .get(key)
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
        };
        let harness = non_empty_str("harness")
            .or_else(|| non_empty_str("backend"))
            .and_then(|s| s.parse::<HarnessKind>().ok())
            .or(default_harness);
        let herdr_terminal_id = clean(fields.herdr_terminal_id)
            .or_else(|| non_empty_str("terminalId"))
            .filter(|tid| is_valid_terminal_id(tid));
        let herdr_created_ms = if packet.contains_key("herdrCreatedMs") {
            fields.herdr_created_ms
        } else {
            packet.get("herdr_created_ms").and_then(Value::as_i64)
        };
        let herdr_template = clean(fields.herdr_template)
            .or_else(|| non_empty_str("herdr_template"))
            .filter(|tpl| is_valid_herdr_template(tpl));
        let explicit_thread = non_empty_str("threadId");
        let codex_thread_id = explicit_thread
            .clone()
            .or_else(|| clean(fields.codex_thread_id));
        let codex_home = clean(fields.codex_home).map(PathBuf::from);
        let codex_remote = clean(fields.codex_remote).or_else(|| non_empty_str("remote"));
        let codex_resume = packet.get("resume").and_then(Value::as_bool) == Some(true);
        let explicit_codex_queue =
            explicit_thread.is_some() || codex_remote.is_some() || codex_resume;
        let t3_thread_id = clean(fields.t3_thread_id)
            .filter(|s| s.len() <= 256 && !s.chars().any(char::is_control));
        let t3_base_dir = clean(fields.t3_base_dir).map(PathBuf::from);
        let t3_url = clean(fields.t3_url);
        let openclaw_session_key = clean(fields.openclaw_session_key)
            .or_else(|| non_empty_str("sessionKey"))
            .and_then(|raw| {
                let stripped = raw.strip_prefix("openclaw:").unwrap_or(&raw);
                validate_openclaw_session_key(stripped).ok()
            });
        let openclaw_session_id = clean(fields.openclaw_session_id)
            .filter(|s| s.len() <= 200 && !s.bytes().any(|b| b <= 0x20 || b == 0x7f));
        let openclaw_agent_id = clean(fields.openclaw_agent_id)
            .or_else(|| non_empty_str("agentId"))
            .filter(|s| s.len() <= 128 && !s.bytes().any(|b| b <= 0x20 || b == 0x7f))
            .or_else(|| {
                openclaw_session_key
                    .as_deref()
                    .and_then(parse_openclaw_agent_id_from_session_key)
            });
        let cwd = clean(fields.cwd).filter(|s| s.len() <= 1024 && !s.chars().any(char::is_control));

        Self {
            harness,
            herdr_terminal_id,
            herdr_created_ms,
            herdr_template,
            codex_thread_id,
            codex_home,
            codex_remote,
            codex_resume,
            explicit_codex_queue,
            t3_thread_id,
            t3_base_dir,
            t3_url,
            openclaw_session_key,
            openclaw_session_id,
            openclaw_agent_id,
            cwd,
        }
    }

    fn from_session_backend(session_id: &str, backend_json: &str) -> Self {
        let map = serde_json::from_str::<Value>(backend_json)
            .ok()
            .and_then(|v| v.as_object().cloned())
            .unwrap_or_default();
        let persisted_harness = map
            .get("kind")
            .and_then(Value::as_str)
            .and_then(|s| s.parse::<HarnessKind>().ok());
        let inferred_harness =
            LocalDaemonInner::infer_session_harness(session_id, persisted_harness);
        Self::from_packet(&map, inferred_harness)
    }

    fn has_any_hint(&self) -> bool {
        self.herdr_terminal_id.is_some()
            || self.t3_thread_id.is_some()
            || self.t3_base_dir.is_some()
            || self.t3_url.is_some()
            || self.harness == Some(HarnessKind::T3)
            || self.harness == Some(HarnessKind::Openclaw)
            || self.harness == Some(HarnessKind::Codex)
            || self.openclaw_session_key.is_some()
            || self.codex_thread_id.is_some()
            || (self.explicit_codex_queue && self.codex_thread_id.is_some())
    }

    fn backend_patch(&self, explicit_harness: Option<HarnessKind>) -> Map<String, Value> {
        let path = |value: &Option<PathBuf>| {
            value
                .as_ref()
                .filter(|value| !value.as_os_str().is_empty())
                .map(|value| value.to_string_lossy().into_owned())
        };
        let fields = TransportHintFields {
            herdr_terminal_id: self.herdr_terminal_id.clone(),
            herdr_created_ms: self.herdr_created_ms,
            herdr_template: self.herdr_template.clone(),
            codex_thread_id: self.codex_thread_id.clone(),
            codex_home: path(&self.codex_home),
            codex_remote: self.codex_remote.clone(),
            t3_thread_id: self.t3_thread_id.clone(),
            t3_base_dir: path(&self.t3_base_dir),
            t3_url: self.t3_url.clone(),
            openclaw_session_key: self.openclaw_session_key.clone(),
            openclaw_session_id: self.openclaw_session_id.clone(),
            openclaw_agent_id: self.openclaw_agent_id.clone(),
            cwd: self.cwd.clone(),
        };
        let mut patch = Map::new();
        if let Some(harness) = explicit_harness.or(self.harness) {
            patch.insert("kind".into(), json!(harness.as_str()));
        }
        fields.write_into(&mut patch);
        patch
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WaiterKind {
    Once,
    Stream,
}

struct LiveWaiter {
    id: u64,
    mode: WaiterKind,
    tx: mpsc::UnboundedSender<Value>,
}

struct LiveChannel {
    conn_id: u64,
    tx: mpsc::UnboundedSender<ChannelDeliverCommand>,
}

struct ChannelDeliverCommand {
    delivery_id: u64,
    text: String,
    ack_tx: oneshot::Sender<bool>,
}

#[derive(Debug, Clone)]
struct OpenClawWakeAck {
    ok: bool,
    reason: Option<String>,
}

struct OpenClawWakeCommand {
    delivery_id: u64,
    session_id: String,
    session_key: String,
    agent_id: String,
    batch_id: String,
    text: String,
    ack_tx: oneshot::Sender<OpenClawWakeAck>,
}

struct LiveOpenClawService {
    conn_id: u64,
    tx: mpsc::UnboundedSender<OpenClawWakeCommand>,
}

#[derive(Debug, Clone)]
struct ClassifiedItemMeta {
    item_id: String,
    payload_sha256: Option<String>,
    urgency: DeliveryUrgency,
    burst_demoted: bool,
    burst_source_key: String,
    channel: Option<String>,
    is_announcement: bool,
    notified: bool,
    /// True only for trusted daemon-generated host sleep/wake notices.
    /// Counted in the digest and excluded from Tier 4 Herdr cold-spawn triggers.
    is_wake_notice: bool,
}

#[derive(Debug, Clone)]
struct SubscriptionRecordMeta {
    id: String,
    key: Option<String>,
    origin_node: String,
    topic: String,
    urgency: DeliveryUrgency,
}

/// Strictly metadata-only quarantine notice coalesced per receipt (`G10`).
/// NEVER stores any unscreened message body text.
#[derive(Debug, Clone)]
struct QuarantineNoticeMeta {
    receipt: String,
    source: String,
    trust_tier: String,
    reason: String,
    quarantined_at: i64,
    surfaced_in_batch: bool,
}

fn drain_scope_from_packet(packet: &Map<String, Value>) -> DrainScope {
    match packet.get("scope").and_then(Value::as_str) {
        Some("mid_turn") => DrainScope::MidTurn,
        Some("turn_boundary") => DrainScope::TurnBoundary,
        Some("pre_turn") => DrainScope::PreTurn,
        _ => DrainScope::All,
    }
}

struct FocusChange {
    policy: SessionDeliveryPolicy,
    unread: usize,
    muted: usize,
    rev: u64,
}

#[derive(Default)]
struct SessionRuntime {
    /// Private activity lease and retry state owned by the runtime lifecycle module.
    timers: SessionTimers,
    /// Most recent same-turn Queue reminder (RFC 0004 Decision #4).
    last_midturn_digest_at_ms: Option<i64>,
    /// Cooldown after trying to attach a transport persisted from an earlier session.
    lazy_hydrate_attempt_at: Option<Instant>,
    /// Serializes inbox reconciliation across async gate evaluations.
    reconcile_lock: Option<Arc<AsyncMutex<()>>>,
    quarantine_notices: Vec<QuarantineNoticeMeta>,
    herdr_bare_shell_rejection: Option<String>,
    openclaw_session_missing: bool,
    waiters: Vec<LiveWaiter>,
    channel: Option<LiveChannel>,
    attached_transport: Option<AttachedPushTransport>,
    /// Cached target from persisted backend metadata. Reads do not touch SQLite.
    openclaw_target: Option<(String, String)>,
    /// A verified SessionStart exported the daemon wait token.
    env_file_exported: bool,
    flushing: bool,
}

trait DaemonStateLock<T> {
    fn lock_state(&self, poison_message: &'static str) -> MutexGuard<'_, T>;
}

impl<T> DaemonStateLock<T> for Mutex<T> {
    #[track_caller]
    fn lock_state(&self, poison_message: &'static str) -> MutexGuard<'_, T> {
        self.lock().expect(poison_message)
    }
}

struct LocalDaemonInner {
    node: Arc<UnifiedNode>,
    gate: Arc<RwLock<Option<Arc<SecurityGatePipeline>>>>,
    gate_reloader: RwLock<Option<GateReloader>>,
    delivery: Arc<DeliveryEngine>,
    calls: Arc<CallRegistry>,
    config: LocalDaemonConfig,
    socket_path: PathBuf,
    /// Connected native OpenClaw Gateway plugin wake service (`openclaw.service.ready`).
    openclaw_service: Mutex<Option<LiveOpenClawService>>,
    /// Deterministic 256-bit HMAC-SHA256 key loaded/persisted in `SecretStore` under
    /// [`DAEMON_SESSION_TOKEN_KEY_SECRET`] (`"daemon-session-token-key"`).
    /// NEVER serialized into `ui/state.json`, SQLite, or logs.
    session_token_key: [u8; 32],
    /// Specific `session_id`s that have registered a real `PreToolUse` `call.start` (`X6`).
    /// Never poisons an entire hookless harness (e.g. OpenClaw) globally from one forged call!
    hook_registered_sessions: Mutex<HashSet<String>>,
    /// Live reverse index mapping `herdrTerminalId -> Vec<session_id>` (most-recently-seen first),
    /// hydrated from SQLite `sessions.backend_json` on startup and updated on hints/calls/transports.
    herdr_terminal_index: Mutex<HashMap<String, Vec<String>>>,
    /// Active background auto-detection probe watchers keyed by `session_id`.
    pending_probes: Mutex<HashMap<String, watch::Receiver<bool>>>,
    /// Per-session classified metadata for `Pending` receipts (`receipt -> meta`).
    item_meta: Mutex<HashMap<String, HashMap<String, ClassifiedItemMeta>>>,
    /// Per-session subscription urgency & key mappings.
    sub_meta: Mutex<HashMap<String, Vec<SubscriptionRecordMeta>>>,
    /// Receipts dismissed by Security Gate (`Block` or `Quarantine` in pipeline) so they never surface.
    dismissed_receipts: Mutex<HashSet<String>>,
    bridges: bridges::BridgeRegistry,
    /// Optional custom async hook invoked on `"peers.reload"` IPC RPCs.
    peers_reloader: Mutex<Option<Arc<dyn PeersReloader>>>,
    /// Registered async hooks invoked during [`LocalDaemon::handle_system_wake`]
    /// (e.g. broadcasting `system.wake` JSON-RPC notifications to external subprocess plugins).
    wake_hooks: Mutex<Vec<Arc<dyn WakeHook>>>,
    /// Monotonic generation deduplicating post-wake follow-up flush timers.
    wake_followup_gen: AtomicU64,
    /// Turn and delivery state keyed by session ID.
    session_runtime: Mutex<HashMap<String, SessionRuntime>>,
    /// Tier 4 per-wakeup concurrency guard (`maxConcurrentSpawns: 1`) for allowlisted Herdr cold spawns.
    active_cold_spawns: Mutex<HashSet<String>>,
    /// Optional monotonic test clock offset (ms) added to `now_ms()` for deterministic timing tests.
    clock_offset_ms: AtomicI64,
    /// Monotonic UI projection revision counter bumped on every session/sub/mailbox/policy/channel change.
    ui_rev: AtomicU64,
    /// Watch broadcaster notifying `inspect.watch` clients and the debounced `ui/state.json` projector.
    ui_rev_tx: watch::Sender<u64>,
    /// Daemon shutdown watch receiver shared with bounded retry tasks.
    shutdown_rx: watch::Receiver<bool>,
    next_id: AtomicU64,
}

/// Native async Rust Hyphae `LocalDaemon` handle.
pub struct LocalDaemon {
    inner: Arc<LocalDaemonInner>,
    tcp_addr: Option<SocketAddr>,
    shutdown_tx: watch::Sender<bool>,
    stopped: AtomicBool,
    accept_task: Mutex<Option<JoinHandle<()>>>,
    inbox_task: Mutex<Option<JoinHandle<()>>>,
    startup_flush_task: Mutex<Option<JoinHandle<()>>>,
    projector_task: Mutex<Option<JoinHandle<()>>>,
    maintenance_task: Mutex<Option<JoinHandle<()>>>,
    wake_watcher_task: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for LocalDaemon {
    fn drop(&mut self) {
        self.stop_sync();
    }
}

enum DaemonListener {
    #[cfg(unix)]
    Unix(tokio::net::UnixListener),
    Tcp(tokio::net::TcpListener, SocketAddr),
}

enum DaemonConnection {
    #[cfg(unix)]
    Unix(tokio::net::UnixStream),
    Tcp(tokio::net::TcpStream, SocketAddr),
}

impl DaemonListener {
    fn tcp_addr(&self) -> Option<SocketAddr> {
        match self {
            #[cfg(unix)]
            Self::Unix(_) => None,
            Self::Tcp(_, addr) => Some(*addr),
        }
    }

    async fn accept(&self) -> std::io::Result<DaemonConnection> {
        match self {
            #[cfg(unix)]
            Self::Unix(listener) => {
                let (stream, _) = listener.accept().await?;
                Ok(DaemonConnection::Unix(stream))
            }
            Self::Tcp(listener, addr) => {
                let (stream, _) = listener.accept().await?;
                Ok(DaemonConnection::Tcp(stream, *addr))
            }
        }
    }
}

impl DaemonConnection {
    async fn serve(self, daemon: Arc<LocalDaemonInner>, shutdown: watch::Receiver<bool>) {
        match self {
            #[cfg(unix)]
            Self::Unix(stream) => {
                let (reader, writer) = stream.into_split();
                connection::handle_connection(daemon, reader, writer, shutdown, None).await;
            }
            Self::Tcp(stream, addr) => {
                let (reader, writer) = stream.into_split();
                connection::handle_connection(daemon, reader, writer, shutdown, Some(addr)).await;
            }
        }
    }
}

impl LocalDaemon {
    /// Starts the native Rust `LocalDaemon` on the platform-native local transport:
    /// - Unix: Unix domain socket (`connector.sock`, `0600` permissions, stale-socket cleanup).
    /// - Windows (`#[cfg(not(unix))]`): loopback TCP (`127.0.0.1:0` -> writes `connector.addr`).
    #[cfg(unix)]
    pub async fn start(
        node: Arc<UnifiedNode>,
        gate: Option<Arc<SecurityGatePipeline>>,
        config: LocalDaemonConfig,
    ) -> Result<Self, DaemonError> {
        use std::os::unix::fs::PermissionsExt;

        let socket_path = config
            .socket_path
            .clone()
            .unwrap_or_else(|| node.config().state_dir.join(DEFAULT_SOCKET_FILENAME));

        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent)?;
            let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
        }

        if socket_path.exists() {
            // Probe whether an active daemon is already listening on this socket.
            if std::os::unix::net::UnixStream::connect(&socket_path).is_ok() {
                return Err(DaemonError::AlreadyRunning(socket_path));
            }
            let _ = std::fs::remove_file(&socket_path);
        }

        let listener = tokio::net::UnixListener::bind(&socket_path)?;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))?;

        Ok(Self::start_with_listener(
            node,
            gate,
            config,
            socket_path,
            DaemonListener::Unix(listener),
        )
        .await)
    }

    /// Starts the native Rust `LocalDaemon` on loopback TCP (`127.0.0.1:0` -> `connector.addr`) on Windows.
    #[cfg(not(unix))]
    pub async fn start(
        node: Arc<UnifiedNode>,
        gate: Option<Arc<SecurityGatePipeline>>,
        config: LocalDaemonConfig,
    ) -> Result<Self, DaemonError> {
        let addr_path = config
            .socket_path
            .clone()
            .unwrap_or_else(|| node.config().state_dir.join(DEFAULT_SOCKET_FILENAME));
        Self::start_tcp(node, gate, config, addr_path).await
    }

    /// Starts the native Rust `LocalDaemon` bound strictly to loopback TCP `127.0.0.1:0`,
    /// writing `<addr>\n` to `addr_file_path` (`connector.addr`).
    ///
    /// Available on ALL platforms (used by default on Windows and callable on Unix for
    /// cross-platform transport testing).
    pub async fn start_tcp(
        node: Arc<UnifiedNode>,
        gate: Option<Arc<SecurityGatePipeline>>,
        config: LocalDaemonConfig,
        addr_file_path: PathBuf,
    ) -> Result<Self, DaemonError> {
        if let Some(parent) = addr_file_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let local_addr = listener.local_addr()?;
        std::fs::write(&addr_file_path, format!("{local_addr}\n"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ =
                std::fs::set_permissions(&addr_file_path, std::fs::Permissions::from_mode(0o600));
        }

        Ok(Self::start_with_listener(
            node,
            gate,
            config,
            addr_file_path,
            DaemonListener::Tcp(listener, local_addr),
        )
        .await)
    }

    async fn start_with_listener(
        node: Arc<UnifiedNode>,
        gate: Option<Arc<SecurityGatePipeline>>,
        config: LocalDaemonConfig,
        socket_path: PathBuf,
        listener: DaemonListener,
    ) -> Self {
        let tcp_addr = listener.tcp_addr();
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let inner = Arc::new(LocalDaemonInner::new(
            node,
            gate,
            config,
            socket_path,
            shutdown_tx.subscribe(),
        ));

        let accept_inner = Arc::clone(&inner);
        let accept_task = tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    res = listener.accept() => res,
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                        continue;
                    }
                };
                let Ok(connection) = accepted else {
                    continue;
                };
                let conn_inner = Arc::clone(&accept_inner);
                let conn_shutdown = shutdown_rx.clone();
                tokio::spawn(connection.serve(conn_inner, conn_shutdown));
            }
        });

        inner.sweep_expired_mutes_and_policies(now_ms());
        let _ = inner.prune_stale_sessions_now();
        sweep_approved_local_ingest_on_startup(&inner).await;
        let inbox_task = spawn_inbox_watcher(Arc::clone(&inner), shutdown_tx.subscribe());
        let startup_pending = inner.collect_pending_sessions_for_flush();
        let startup_rehydrate = inner.collect_sessions_for_transport_rehydration(&startup_pending);
        let startup_flush_task = if startup_pending.is_empty() && startup_rehydrate.is_empty() {
            None
        } else {
            let flush_inner = Arc::clone(&inner);
            Some(tokio::spawn(async move {
                tokio::join!(
                    flush_inner.rehydrate_persisted_transports(startup_rehydrate),
                    flush_inner.flush_pending_session_list(startup_pending),
                );
            }))
        };
        let _ = inner.write_ui_state_snapshot();
        let projector_task = spawn_ui_state_projector(Arc::clone(&inner), shutdown_tx.subscribe());
        let maintenance_task = spawn_maintenance_task(Arc::clone(&inner), shutdown_tx.subscribe());
        let wake_watcher_task =
            spawn_daemon_wake_watcher(Arc::clone(&inner), shutdown_tx.subscribe());

        Self {
            inner,
            tcp_addr,
            shutdown_tx,
            stopped: AtomicBool::new(false),
            accept_task: Mutex::new(Some(accept_task)),
            inbox_task: Mutex::new(Some(inbox_task)),
            startup_flush_task: Mutex::new(startup_flush_task),
            projector_task: Mutex::new(Some(projector_task)),
            maintenance_task: Mutex::new(Some(maintenance_task)),
            wake_watcher_task: Mutex::new(wake_watcher_task),
        }
    }

    pub fn socket_path(&self) -> &Path {
        &self.inner.socket_path
    }

    /// Path to the atomic metadata-only UI projection file (`<state_dir>/ui/state.json`).
    pub fn ui_state_path(&self) -> PathBuf {
        self.inner.ui_state_path()
    }

    /// Current monotonic UI projection revision counter.
    pub fn ui_rev(&self) -> u64 {
        self.inner.current_ui_rev()
    }

    pub fn tcp_addr(&self) -> Option<SocketAddr> {
        self.tcp_addr
    }

    pub fn node(&self) -> &Arc<UnifiedNode> {
        &self.inner.node
    }

    pub fn delivery(&self) -> &Arc<DeliveryEngine> {
        &self.inner.delivery
    }

    pub fn calls(&self) -> &Arc<CallRegistry> {
        &self.inner.calls
    }

    /// Returns the shared hot-reloadable [`SecurityGatePipeline`] slot (e.g. so `LocalIngestServer`
    /// atomically observes `gate.reload` updates alongside `LocalDaemon`).
    pub fn gate_slot(&self) -> Arc<RwLock<Option<Arc<SecurityGatePipeline>>>> {
        Arc::clone(&self.inner.gate)
    }

    /// Returns a snapshot of the currently active [`SecurityGatePipeline`], if any.
    pub fn gate(&self) -> Option<Arc<SecurityGatePipeline>> {
        self.inner.current_gate()
    }

    /// Registers a live [`GateReloader`] callback invoked by the `gate.reload` IPC RPC.
    pub fn set_gate_reloader(&self, reloader: GateReloader) {
        *self
            .inner
            .gate_reloader
            .write()
            .expect("gate_reloader lock poisoned") = Some(reloader);
    }

    /// Registers an explicit native [`PushTransport`] (e.g. `HerdrTransport`, `T3Transport`,
    /// `CodexQueueTransport`, or test double) for `session_id` and immediately flushes any
    /// pending unread mailbox items through it.
    pub fn register_session_transport(
        &self,
        session_id: impl Into<String>,
        transport: Arc<dyn PushTransport>,
    ) {
        let sid = session_id.into();
        if sid.is_empty() {
            return;
        }
        self.inner
            .attach_transport_if_higher_priority(&sid, transport, PRIORITY_EXPLICIT);
        let has_pending = self
            .inner
            .node
            .db()
            .local()
            .pending_count(&sid)
            .unwrap_or(0)
            > 0;
        if has_pending {
            let flush_inner = Arc::clone(&self.inner);
            tokio::spawn(async move {
                flush_inner.flush_session(&sid).await;
            });
        }
    }

    /// Removes any attached native [`PushTransport`] for `session_id`.
    pub fn unregister_session_transport(&self, session_id: &str) -> bool {
        self.inner.unregister_session_transport(session_id)
    }

    /// Returns the active live wakeup transport kind for `session_id`, if any
    /// (`"claude_channel"`, `"herdr"`, `"t3"`, `"openclaw"`, `"codex_queue"`, `"watch"`, `"wait"`, etc.).
    pub fn session_transport_kind(&self, session_id: &str) -> Option<&'static str> {
        self.inner.active_transport_kind(session_id)
    }

    /// Registers a [`PeersReloader`] callback invoked whenever `"type": "peers.reload"`
    /// arrives on `connector.sock` / `connector.addr`.
    pub fn set_peers_reloader(&self, reloader: Arc<dyn PeersReloader>) {
        *self
            .inner
            .peers_reloader
            .lock_state("peers_reloader lock poisoned") = Some(reloader);
    }

    /// Registers an async closure invoked whenever `"type": "peers.reload"` arrives on
    /// `connector.sock` / `connector.addr`.
    pub fn on_peers_reload<F, Fut>(&self, callback: F)
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<PeerReconcileReport, String>> + Send + 'static,
    {
        struct FnPeersReloader<F>(F);
        impl<F, Fut> PeersReloader for FnPeersReloader<F>
        where
            F: Fn() -> Fut + Send + Sync + 'static,
            Fut: Future<Output = Result<PeerReconcileReport, String>> + Send + 'static,
        {
            fn reload_peers<'a>(&'a self) -> BoxFuture<'a, Result<PeerReconcileReport, String>> {
                Box::pin((self.0)())
            }
        }
        self.set_peers_reloader(Arc::new(FnPeersReloader(callback)));
    }

    /// Registers a [`WakeHook`] invoked whenever [`LocalDaemon::handle_system_wake`] runs.
    pub fn add_wake_hook(&self, hook: Arc<dyn WakeHook>) {
        self.inner
            .wake_hooks
            .lock_state("wake_hooks lock poisoned")
            .push(hook);
    }

    /// Registers an async closure invoked whenever [`LocalDaemon::handle_system_wake`] runs.
    pub fn on_system_wake<F, Fut>(&self, callback: F)
    where
        F: Fn(Duration) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        struct FnWakeHook<F>(F);
        impl<F, Fut> WakeHook for FnWakeHook<F>
        where
            F: Fn(Duration) -> Fut + Send + Sync + 'static,
            Fut: Future<Output = ()> + Send + 'static,
        {
            fn on_system_wake<'a>(&'a self, slept_for: Duration) -> BoxFuture<'a, ()> {
                Box::pin((self.0)(slept_for))
            }
        }
        self.add_wake_hook(Arc::new(FnWakeHook(callback)));
    }

    /// Executes full sleep/wake recovery deterministically (callable by the background
    /// zero-FFI wake watcher, the `"system.wake"` local IPC RPC, or tests):
    /// 1. Recycles all `PeerLink` & external Drop Relay SSE streams and kicks the scheduler.
    /// 2. Broadcasts `system.wake` to registered external plugin wake hooks.
    /// 3. Snapshots mid-turn `Active` sessions and clears stale activity leases, grace timers,
    ///    transient `hold_retries`, `openclaw_missing_sessions`, and lazy hydrate cooldowns.
    /// 4. Rehydrates any dropped persisted push transports (when `auto_detect_transports` is on).
    /// 5. Enqueues concise `[hyphae notice]` for interrupted `Active` sessions (respecting mute,
    ///    Focus Mode, deduplication, and never triggering Tier 4 cold spawns).
    /// 6. Flushes pending sessions immediately and schedules one `shutdown_rx`-cancellable
    ///    follow-up flush for newly reconnecting `PeerLink` catch-up mail.
    pub async fn handle_system_wake(&self, slept_for: Duration) -> WakeRecoveryReport {
        self.inner.handle_system_wake(slept_for).await
    }

    /// Sweeps pending local topic batches and reconciles/flushes every local session with
    /// pending unread items (enforcing Security Gates, mutes, Focus Mode, and strictly
    /// at-most-once delivery). Safe to invoke repeatedly or concurrently with live traffic.
    pub async fn flush_pending_sessions(&self) {
        self.inner.flush_all_pending_sessions().await;
    }

    /// Gracefully stops the daemon listener, background watcher, and removes the local socket/addr file.
    pub async fn stop(self) {
        self.stop_sync();
    }

    /// Stops the daemon listener and background tasks via shared reference (useful when wrapped in `Arc`).
    pub fn shutdown(&self) {
        self.stop_sync();
    }

    fn stop_sync(&self) {
        let _ = self.shutdown_tx.send(true);
        self.inner.clear_session_retries();
        if let Some(h) = self
            .accept_task
            .lock_state("accept_task lock poisoned")
            .take()
        {
            h.abort();
        }
        if let Some(h) = self
            .inbox_task
            .lock_state("inbox_task lock poisoned")
            .take()
        {
            h.abort();
        }
        if let Some(h) = self
            .startup_flush_task
            .lock_state("startup_flush_task lock poisoned")
            .take()
        {
            h.abort();
        }
        if let Some(h) = self
            .projector_task
            .lock_state("projector_task lock poisoned")
            .take()
        {
            h.abort();
        }
        if let Some(h) = self
            .maintenance_task
            .lock_state("maintenance_task lock poisoned")
            .take()
        {
            h.abort();
        }
        if let Some(h) = self
            .wake_watcher_task
            .lock_state("wake_watcher_task lock poisoned")
            .take()
        {
            h.abort();
        }
        self.inner.wake_followup_gen.fetch_add(1, Ordering::SeqCst);
        // U1 (P1): Write a final atomic offline UI snapshot (`daemon.online == false`) right
        // before removing the socket so file-based UIs immediately transition to OFFLINE.
        if !self.stopped.swap(true, Ordering::SeqCst) && self.inner.node.config().state_dir.exists()
        {
            let _ = self.inner.bump_ui_rev();
            let _ = self.inner.write_ui_state_snapshot_with_online(false);
        }
        let _ = std::fs::remove_file(&self.inner.socket_path);
    }

    /// Invokes opt-in Tier 4 allowlisted Herdr cold-spawn (`hc run <template> <prompt>`)
    /// guarded by `delivery_retry.herdr_spawn_allowlist` and a per-key concurrency limit
    /// (`maxConcurrentSpawns: 1`).
    pub async fn try_herdr_cold_spawn(
        &self,
        spawn_key: &str,
        template: &str,
        prompt: &str,
    ) -> PushOutcome {
        self.inner
            .try_herdr_cold_spawn(spawn_key, template, prompt)
            .await
    }

    /// Test hook: advances the daemon clock by `delta_ms` so time-bounded behaviour (e.g. the
    /// RFC 0004 long-turn queue reminder) can be tested without sleeping. Every timestamp the
    /// daemon takes after startup goes through this clock; `UnifiedNode` keeps real wall time.
    pub fn advance_clock_ms(&self, delta_ms: i64) {
        self.inner
            .clock_offset_ms
            .fetch_add(delta_ms, Ordering::Relaxed);
    }

    /// Directly ingests an inbound item through `SecurityGatePipeline` (if configured) ->
    /// `DeliveryEngine` -> `NodeDb` mailbox, waking live transports ONLY for non-`Mute` items.
    pub async fn ingest_inbound(
        &self,
        item: InboundItem,
    ) -> Result<Option<DeliveryUrgency>, String> {
        let InboundItem {
            session_id,
            origin_node,
            item_id,
            source,
            text,
            kind,
            trust_tier,
        } = item;
        let now = self.inner.current_time_ms();
        let mut gate_cap: Option<DeliveryUrgency> = None;
        let effective_trust_tier = if kind == MailboxKind::Plugin
            || origin_node.starts_with("bridge:")
        {
            GateTrustTier::Bridge
        } else if kind == MailboxKind::Event || raw_has_external_webhook_origin(&source, &text) {
            cap_trust_tier_to_external_webhook(trust_tier)
        } else {
            trust_tier
        };
        let mut gate_approved = false;

        if let Some(pipeline) = self.inner.current_gate() {
            let parsed =
                hyp_node::delivery::ParsedMailboxSource::parse(&origin_node, &source, kind);
            let ce = ProtoCloudEvent {
                specversion: "1.0".into(),
                id: item_id.clone(),
                source: source.clone(),
                event_type: format!("to.hyphae.mailbox.{}", kind.as_str()),
                datacontenttype: Some(CONTENT_TYPE_JSON.into()),
                dataschema: None,
                subject: parsed.channel.clone().or(parsed.topic.clone()),
                time: None,
                data: Some(json!({ "text": text })),
                data_base64: None,
                extensions: BTreeMap::new(),
            };
            let ctx = InboundContext {
                session_id: session_id.clone(),
                origin_node: origin_node.clone(),
                sender: source.clone(),
                trust_tier: effective_trust_tier,
                e2ee_verified: true,
                identity_verified: true,
                kind,
                channel: parsed.channel,
                topic: parsed.topic,
                bridge: parsed.bridge,
                event: ce,
                transfer_paths: Vec::new(),
                rendered_text: Some(text.clone()),
                human_auth: None,
            };
            let eval = pipeline
                .evaluate_inbound(&ctx, now)
                .await
                .map_err(|e| e.to_string())?;
            match eval.decision {
                GateDecision::Allow { max_urgency } => {
                    gate_cap = max_urgency;
                    let gate_reason = urgency_cap_gate_reason(gate_cap);
                    gate_approved = true;
                    if let Some(receipt) = eval.receipt {
                        // Pipeline already inserted into DB if sharing same DB; check if present in node DB.
                        let exists = {
                            let db = self.inner.node.db();
                            let found = db
                                .local()
                                .get_mailbox_entry(&receipt)
                                .ok()
                                .flatten()
                                .is_some();
                            if found {
                                let _ = db.local().mark_mailbox_gate_approved(
                                    &session_id,
                                    &receipt,
                                    gate_reason,
                                    now,
                                );
                            }
                            found
                        };
                        if exists {
                            let urgency = self
                                .inner
                                .classify_and_route_pending_entry(
                                    &session_id,
                                    &receipt,
                                    gate_cap,
                                    now,
                                )
                                .await;
                            if urgency.is_some_and(DeliveryUrgency::triggers_delivery_or_digest) {
                                self.inner.flush_session(&session_id).await;
                            }
                            self.inner.bump_ui_rev();
                            return Ok(urgency);
                        }
                    }
                }
                GateDecision::Hold { retry_after_ms, .. } => {
                    // G4 (P0): Retain held inbound items unscreened (`reviewed_at = NULL`) so they
                    // are NEVER lost and schedule a bounded delayed retry to re-reconcile cleanly.
                    let held_insert = MailboxInsert {
                        session_id: session_id.clone(),
                        origin_node,
                        item_id,
                        text,
                        kind,
                        source,
                        gate_state: GateState::Pending,
                        gate_reason: Some(format!("gate_held:{}", effective_trust_tier.as_str())),
                        traceparent: None,
                    };
                    {
                        let db = self.inner.node.db();
                        let _ = db.local().put_in_mailbox(&held_insert, now);
                    }
                    self.inner
                        .schedule_gate_hold_retry(&session_id, retry_after_ms);
                    self.inner.bump_ui_rev();
                    return Ok(None);
                }
                GateDecision::Quarantine { reason, .. } => {
                    self.inner.record_quarantine_notice(
                        &session_id,
                        eval.receipt.as_deref(),
                        &source,
                        effective_trust_tier,
                        &reason,
                        now,
                    );
                    self.inner.bump_ui_rev();
                    return Ok(None);
                }
                GateDecision::Block { .. } => {
                    self.inner.bump_ui_rev();
                    return Ok(None);
                }
            }
        }

        let insert = MailboxInsert {
            session_id: session_id.clone(),
            origin_node: origin_node.clone(),
            item_id: item_id.clone(),
            text: text.clone(),
            kind,
            source: source.clone(),
            gate_state: GateState::Pending,
            gate_reason: urgency_cap_gate_reason(gate_cap).map(str::to_string),
            traceparent: None,
        };

        let temp_entry = MailboxEntry {
            receipt: String::new(),
            session_id: session_id.clone(),
            origin_node: origin_node.clone(),
            item_id,
            text,
            received_at: now,
            kind,
            source: source.clone(),
            notified: false,
            gate_state: GateState::Pending,
            gate_reason: urgency_cap_gate_reason(gate_cap).map(str::to_string),
            traceparent: None,
            payload_sha256: None,
            reviewed_at: None,
            daemon_notice: None,
        };

        let sub_mode = self
            .inner
            .lookup_subscription_urgency(&session_id, &origin_node, &source);
        let classification = {
            let db = self.inner.node.db();
            self.inner
                .delivery
                .classify_entry(&db, &session_id, &temp_entry, sub_mode, gate_cap, now)
                .map_err(|e| e.to_string())?
        };

        if classification.effective_urgency == DeliveryUrgency::Mute {
            let db = self.inner.node.db();
            archive_muted_entry(&db, &insert, now).map_err(|e| e.to_string())?;
            self.inner.bump_ui_rev();
            return Ok(Some(DeliveryUrgency::Mute));
        }

        let receipt = {
            let db = self.inner.node.db();
            match db
                .local()
                .put_in_mailbox(&insert, now)
                .map_err(|e| e.to_string())?
            {
                MailboxPutResult::Stored { receipt } => {
                    if gate_approved {
                        let _ = db.local().mark_mailbox_gate_approved(
                            &session_id,
                            &receipt,
                            urgency_cap_gate_reason(gate_cap),
                            now,
                        );
                    }
                    receipt
                }
                MailboxPutResult::Duplicate => return Ok(Some(classification.effective_urgency)),
                MailboxPutResult::QueueFull => return Err("local_inbox_full".to_string()),
            }
        };

        let item_sha = Some(sha256_hex(insert.text.as_bytes()));
        let is_announcement = self
            .inner
            .is_announcement_channel(classification.parsed.channel.as_deref());
        self.inner.record_item_meta(
            &session_id,
            receipt,
            ClassifiedItemMeta {
                item_id: insert.item_id,
                payload_sha256: item_sha,
                urgency: classification.effective_urgency,
                burst_demoted: classification.burst.demoted,
                burst_source_key: classification.burst_source_key,
                channel: classification.parsed.channel,
                is_announcement,
                notified: false,
                is_wake_notice: false,
            },
        );
        self.inner.bump_ui_rev();
        self.inner.flush_session(&session_id).await;
        Ok(Some(classification.effective_urgency))
    }
}

fn spawn_inbox_watcher(
    inner: Arc<LocalDaemonInner>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    let mut rx = inner.node.subscribe_local_inbox();
    let mut kv_rx = inner.node.subscribe_kv_metadata();
    tokio::spawn(async move {
        loop {
            let session_id = tokio::select! {
                res = rx.recv() => match res {
                    Ok(sid) => sid,
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        // Reconcile all known sessions on lag.
                        let sessions: Vec<String> = {
                            let db = inner.node.db();
                            db.local()
                                .list_sessions()
                                .unwrap_or_default()
                                .into_iter()
                                .map(|s| s.id)
                                .collect()
                        };
                        for sid in sessions {
                            if inner.reconcile_session_inbox(&sid).await {
                                inner.flush_session(&sid).await;
                            }
                        }
                        inner.bump_ui_rev();
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                },
                change = kv_rx.changed() => {
                    if change.is_err() {
                        break;
                    }
                    inner.bump_ui_rev();
                    continue;
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                    continue;
                }
            };
            if inner.reconcile_session_inbox(&session_id).await {
                inner.flush_session(&session_id).await;
            }
            inner.bump_ui_rev();
        }
    })
}

/// Periodic background maintenance task handling persisted TTL mute expiration (`U4`) and
/// safe stale-session pruning (`U6`/`G16`) without idle busy-polling.
fn spawn_maintenance_task(
    inner: Arc<LocalDaemonInner>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let prune_interval = inner
            .config
            .session_prune_interval
            .max(Duration::from_millis(250));
        let mut next_prune_at = tokio::time::Instant::now() + prune_interval;

        loop {
            if *shutdown_rx.borrow() {
                break;
            }

            let now = inner.current_time_ms();
            let next_mute_sleep = {
                let db = inner.node.db();
                db.local().next_mute_expiry_ms().ok().flatten()
            }
            .map(|exp_ms| {
                let delta = exp_ms.saturating_sub(now);
                if delta <= 0 {
                    Duration::from_millis(25)
                } else {
                    Duration::from_millis((delta as u64).max(25))
                }
            });

            let now_inst = tokio::time::Instant::now();
            let until_prune = next_prune_at.saturating_duration_since(now_inst);
            let wait_dur = match next_mute_sleep {
                Some(mute_dur) => until_prune.min(mute_dur),
                None => until_prune,
            };

            tokio::select! {
                _ = tokio::time::sleep(wait_dur) => {}
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                    continue;
                }
            }

            if *shutdown_rx.borrow() {
                break;
            }

            inner.sweep_expired_mutes_and_policies(inner.current_time_ms());
            if tokio::time::Instant::now() >= next_prune_at {
                let _ = inner.prune_stale_sessions_now();
                next_prune_at = tokio::time::Instant::now() + prune_interval;
            }
        }
    })
}

/// Spawns the lightweight zero-FFI wall-vs-monotonic wake watcher task when
/// `config.wake_recovery.enabled` is true.
fn spawn_daemon_wake_watcher(
    inner: Arc<LocalDaemonInner>,
    shutdown_rx: watch::Receiver<bool>,
) -> Option<JoinHandle<()>> {
    if !inner.config.wake_recovery.enabled {
        return None;
    }
    let check_interval = inner.config.wake_check_interval;
    let min_sleep = inner.config.wake_recovery.min_sleep_duration();
    Some(spawn_wake_watcher(
        check_interval,
        min_sleep,
        shutdown_rx,
        move |event| {
            let daemon = Arc::clone(&inner);
            async move {
                let _ = daemon.handle_system_wake(event.slept_for).await;
            }
        },
    ))
}

impl LocalDaemonInner {
    fn new(
        node: Arc<UnifiedNode>,
        gate: Option<Arc<SecurityGatePipeline>>,
        config: LocalDaemonConfig,
        socket_path: PathBuf,
        shutdown_rx: watch::Receiver<bool>,
    ) -> Self {
        let mut hydrated_herdr_index: HashMap<String, Vec<String>> = HashMap::new();
        let mut hydrated_runtime: HashMap<String, SessionRuntime> = HashMap::new();
        let mut hydrated_sub_meta: HashMap<String, Vec<SubscriptionRecordMeta>> = HashMap::new();
        {
            let db = node.db();
            if let Ok(sessions) = db.local().list_sessions() {
                for s in sessions {
                    if let Some(tid) = extract_backend_str(&s.backend_json, "herdrTerminalId") {
                        if is_valid_terminal_id(&tid) {
                            let entry = hydrated_herdr_index.entry(tid).or_default();
                            if !entry.iter().any(|existing| existing == &s.id) {
                                entry.push(s.id.clone());
                            }
                        }
                    }
                    if let Some(target) = extract_openclaw_target_from_parts(&s.id, &s.backend_json)
                    {
                        hydrated_runtime
                            .entry(s.id.clone())
                            .or_default()
                            .openclaw_target = Some(target);
                    }
                    if backend_json_flag_true(&s.backend_json, "envFileExported") {
                        hydrated_runtime.entry(s.id).or_default().env_file_exported = true;
                    }
                }
            }
            if let Ok(subs) = db.events().list_subscriptions(None) {
                let stored_meta = db.events().list_subscription_meta().unwrap_or_default();
                for sub in subs {
                    let meta = stored_meta.get(&sub.id);
                    let key = meta.and_then(|m| m.key.clone());
                    let urgency = meta
                        .and_then(|m| m.urgency.as_deref())
                        .and_then(|raw| DeliveryUrgency::parse(raw).ok())
                        .unwrap_or_else(|| DeliveryUrgency::from_store_mode(sub.mode));
                    hydrated_sub_meta.entry(sub.subscriber).or_default().push(
                        SubscriptionRecordMeta {
                            id: sub.id,
                            key,
                            origin_node: sub.origin_node,
                            topic: sub.topic,
                            urgency,
                        },
                    );
                }
            }
        }
        let session_token_key = load_or_init_session_token_key(&node);
        let (ui_rev_tx, _) = watch::channel(1u64);
        Self {
            node,
            gate: Arc::new(RwLock::new(gate)),
            gate_reloader: RwLock::new(None),
            delivery: Arc::new(DeliveryEngine::new()),
            calls: Arc::new(CallRegistry::new()),
            config,
            socket_path,
            openclaw_service: Mutex::new(None),
            session_token_key,
            hook_registered_sessions: Mutex::new(HashSet::new()),
            herdr_terminal_index: Mutex::new(hydrated_herdr_index),
            pending_probes: Mutex::new(HashMap::new()),
            item_meta: Mutex::new(HashMap::new()),
            sub_meta: Mutex::new(hydrated_sub_meta),
            dismissed_receipts: Mutex::new(HashSet::new()),
            bridges: bridges::BridgeRegistry::default(),
            peers_reloader: Mutex::new(None),
            wake_hooks: Mutex::new(Vec::new()),
            wake_followup_gen: AtomicU64::new(0),
            session_runtime: Mutex::new(hydrated_runtime),
            active_cold_spawns: Mutex::new(HashSet::new()),
            clock_offset_ms: AtomicI64::new(0),
            ui_rev: AtomicU64::new(1),
            ui_rev_tx,
            shutdown_rx,
            next_id: AtomicU64::new(1),
        }
    }

    fn current_gate(&self) -> Option<Arc<SecurityGatePipeline>> {
        self.gate
            .read()
            .expect("gate lock poisoned")
            .as_ref()
            .map(Arc::clone)
    }

    fn reload_gate(&self) -> Result<(bool, usize, bool, u64), String> {
        let reloader = self
            .gate_reloader
            .read()
            .expect("gate_reloader lock poisoned")
            .as_ref()
            .map(Arc::clone);
        let Some(reloader) = reloader else {
            return Err(
                "gate_reload_not_configured: no gate policy reloader registered on this daemon"
                    .to_string(),
            );
        };

        let candidate = reloader()?;
        if let Some(ref pipeline) = candidate {
            pipeline
                .verify_policy_change_approval()
                .map_err(|e| format!("gate_policy_tampered: {e}"))?;
            if pipeline.is_policy_tampered() {
                return Err(
                    "gate_policy_tampered: gate policy signature verification failed".to_string(),
                );
            }
        }

        let (enabled, filter_count, require_signed_policy) = {
            let mut guard = self.gate.write().expect("gate lock poisoned");
            if candidate.is_none() {
                if let Some(previous) = guard.as_ref() {
                    if previous
                        .requires_live_policy_approval()
                        .map_err(|e| format!("gate_policy_tampered: {e}"))?
                    {
                        return Err("gate_policy_tampered: live Passkey approval required; gate.reload cannot disable a managed policy".into());
                    }
                }
            }
            let prev_locked = guard
                .as_ref()
                .is_some_and(|p| p.config().require_signed_policy);
            if prev_locked {
                let next_locked = candidate
                    .as_ref()
                    .is_some_and(|p| p.config().require_signed_policy);
                if !next_locked {
                    return Err(
                        "gate_policy_tampered: refusing to downgrade a locked Security Gate policy to unsigned or disabled via live reload"
                            .to_string(),
                    );
                }
            }
            let enabled = candidate.is_some();
            let filter_count = candidate
                .as_ref()
                .map(|p| p.active_filter_count())
                .unwrap_or(0);
            let require_signed_policy = candidate
                .as_ref()
                .is_some_and(|p| p.config().require_signed_policy);
            *guard = candidate;
            (enabled, filter_count, require_signed_policy)
        };

        let rev = self.bump_ui_rev();
        Ok((enabled, filter_count, require_signed_policy, rev))
    }

    fn current_ui_rev(&self) -> u64 {
        self.ui_rev.load(Ordering::SeqCst)
    }

    fn bump_ui_rev(&self) -> u64 {
        let next = self.ui_rev.fetch_add(1, Ordering::SeqCst) + 1;
        let _ = self.ui_rev_tx.send(next);
        next
    }

    fn subscribe_ui_rev(&self) -> watch::Receiver<u64> {
        self.ui_rev_tx.subscribe()
    }

    fn ui_state_path(&self) -> PathBuf {
        self.node.config().state_dir.join("ui").join("state.json")
    }

    fn record_herdr_terminal(&self, terminal_id: &str, session_id: &str) {
        if !is_valid_terminal_id(terminal_id) || session_id.is_empty() {
            return;
        }
        let mut index = self
            .herdr_terminal_index
            .lock_state("herdr_terminal_index lock poisoned");
        let list = index.entry(terminal_id.to_string()).or_default();
        list.retain(|existing| existing != session_id);
        list.insert(0, session_id.to_string());
    }

    fn merge_session_backend_and_index(
        &self,
        session_id: &str,
        patch: &Map<String, Value>,
        now: i64,
    ) -> Result<hyp_store::Session, hyp_store::StoreError> {
        let sess = self.node.db().local().merge_session_backend(
            session_id,
            &Value::Object(patch.clone()),
            now,
        )?;
        if let Some(tid) = patch.get("herdrTerminalId").and_then(Value::as_str) {
            self.record_herdr_terminal(tid, session_id);
        }
        if let Some(target) = extract_openclaw_target_from_parts(session_id, &sess.backend_json) {
            self.session_runtime()
                .entry(session_id.to_owned())
                .or_default()
                .openclaw_target = Some(target);
        }
        Ok(sess)
    }

    /// Returns the daemon's current wall-clock time (ms) plus any deterministic test clock offset.
    fn current_time_ms(&self) -> i64 {
        now_ms().saturating_add(self.clock_offset_ms.load(Ordering::Relaxed))
    }

    fn effective_pending_count(&self, db: &hyp_store::NodeDb, session_id: &str) -> usize {
        db.local()
            .pending_count_with_visibility(
                session_id,
                MailboxVisibility::for_gate(self.current_gate().is_some()),
            )
            .unwrap_or(0)
    }

    /// Invokes allowlisted Tier 4 Herdr cold-spawn (`hc run <template> <prompt>`)
    /// guarded by a per-key concurrency limit (`maxConcurrentSpawns: 1`).
    async fn try_herdr_cold_spawn(
        &self,
        spawn_key: &str,
        template: &str,
        prompt: &str,
    ) -> PushOutcome {
        if !is_valid_herdr_template(template)
            || !self
                .config
                .delivery_retry
                .herdr_spawn_allowlist
                .iter()
                .any(|t| t == template)
        {
            return PushOutcome::reject("herdr_template_not_allowlisted");
        }
        if prompt.is_empty() || prompt.contains('\0') {
            return PushOutcome::reject("herdr_invalid_prompt");
        }

        {
            let mut active = self
                .active_cold_spawns
                .lock_state("active_cold_spawns lock poisoned");
            if !active.insert(spawn_key.to_string()) {
                return PushOutcome::hold("herdr_spawn_already_active");
            }
        }
        struct ColdSpawnGuard<'a> {
            active: &'a Mutex<HashSet<String>>,
            spawn_key: String,
        }
        impl Drop for ColdSpawnGuard<'_> {
            fn drop(&mut self) {
                self.active
                    .lock_state("active_cold_spawns lock poisoned")
                    .remove(&self.spawn_key);
            }
        }
        let _guard = ColdSpawnGuard {
            active: &self.active_cold_spawns,
            spawn_key: spawn_key.to_string(),
        };

        let hc_bin = self
            .config
            .herdr_bin
            .as_deref()
            .unwrap_or(DEFAULT_HERDR_BIN);
        spawn_herdr_template(
            hc_bin,
            template,
            prompt,
            &self.config.delivery_retry.herdr_spawn_allowlist,
            DEFAULT_SPAWN_TIMEOUT,
        )
        .await
    }

    fn has_plugins_capability(&self) -> bool {
        self.config.enable_plugins || self.bridges.has_plugins()
    }

    fn next_seq(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    fn attach_transport_if_higher_priority(
        &self,
        session_id: &str,
        transport: Arc<dyn PushTransport>,
        priority: u8,
    ) -> bool {
        let herdr_tid = transport.herdr_terminal_id().map(ToString::to_string);
        let target_meta = transport.target_metadata();
        let replaced = {
            let mut sessions = self.session_runtime();
            let runtime = sessions.entry(session_id.to_owned()).or_default();
            if runtime
                .attached_transport
                .as_ref()
                .is_some_and(|existing| existing.priority > priority)
            {
                return false;
            }
            runtime.attached_transport.replace(AttachedPushTransport {
                transport,
                priority,
            })
        };
        // A transport's destructor may query the daemon.
        drop(replaced);
        if let Some(ref tid) = herdr_tid {
            self.record_herdr_terminal(tid, session_id);
        }
        self.clear_herdr_bare_shell_rejection(session_id);
        self.clear_lazy_hydrate_cooldown(session_id);
        if target_meta.is_object() {
            let db = self.node.db();
            if db.local().get_session(session_id).ok().flatten().is_some() {
                let _ = db.local().merge_session_backend(
                    session_id,
                    &target_meta,
                    self.current_time_ms(),
                );
            }
        }
        self.bump_ui_rev();
        true
    }

    fn current_transport_priority(&self, session_id: &str) -> u8 {
        self.session_runtime()
            .get(session_id)
            .and_then(|runtime| runtime.attached_transport.as_ref())
            .map(|t| t.priority)
            .unwrap_or(0)
    }

    fn attached_push_transport(&self, session_id: &str) -> Option<Arc<dyn PushTransport>> {
        self.session_runtime()
            .get(session_id)
            .and_then(|runtime| runtime.attached_transport.as_ref())
            .map(|attached| Arc::clone(&attached.transport))
    }

    fn unregister_session_transport(&self, session_id: &str) -> bool {
        let previous = self
            .update_runtime(session_id, |runtime| runtime.attached_transport.take())
            .flatten();
        let removed = previous.is_some();
        drop(previous);
        if removed {
            self.cancel_hold_retry(session_id);
            self.bump_ui_rev();
        }
        removed
    }

    /// Detaches the attached push transport ONLY if the exact same `Arc` instance is still
    /// registered (preventing a stale failing delivery from clobbering a newer replacement).
    fn unregister_matching_session_transport(
        &self,
        session_id: &str,
        transport: &Arc<dyn PushTransport>,
    ) -> bool {
        let should_remove = self
            .session_runtime()
            .get(session_id)
            .and_then(|runtime| runtime.attached_transport.as_ref())
            .is_some_and(|attached| Arc::ptr_eq(&attached.transport, transport));
        if should_remove {
            return self.unregister_session_transport(session_id);
        }
        false
    }

    /// Records a strictly metadata-only quarantine notice coalesced by receipt (`G10`).
    /// Never stores or logs any unscreened message body text.
    fn record_quarantine_notice(
        &self,
        session_id: &str,
        receipt: Option<&str>,
        source: &str,
        trust_tier: GateTrustTier,
        reason: &str,
        now: i64,
    ) {
        let Some(rcpt) = receipt.filter(|r| !r.is_empty()) else {
            return;
        };
        let mut sessions = self.session_runtime();
        let list = &mut sessions
            .entry(session_id.to_owned())
            .or_default()
            .quarantine_notices;
        if list.iter().any(|n| n.receipt == rcpt) {
            return;
        }
        if list.len() >= MAX_QUARANTINE_NOTICES_PER_SESSION {
            list.remove(0);
        }
        list.push(QuarantineNoticeMeta {
            receipt: rcpt.to_string(),
            source: sanitize_notice_label(source),
            trust_tier: trust_tier.as_str().to_string(),
            reason: sanitize_notice_label(reason),
            quarantined_at: now,
            surfaced_in_batch: false,
        });
    }

    fn clear_quarantine_notice(&self, session_id: Option<&str>, receipt: &str) {
        let remove = |runtime: &mut SessionRuntime| {
            runtime
                .quarantine_notices
                .retain(|notice| notice.receipt != receipt);
        };
        if let Some(session_id) = session_id {
            self.clear_runtime_field(session_id, remove);
        } else {
            self.session_runtime().retain(|_, runtime| {
                remove(runtime);
                !runtime.is_empty()
            });
        }
    }

    /// Returns active (still `gate_state == 'quarantined'` in SQLite) metadata-only notices for
    /// `session_id`, pruning any receipts already approved or rejected (`G10`).
    fn live_quarantine_notices_json(&self, session_id: &str) -> Vec<Value> {
        let has_notices = self
            .session_runtime()
            .get(session_id)
            .is_some_and(|runtime| !runtime.quarantine_notices.is_empty());
        if !has_notices {
            return Vec::new();
        }
        let still_quarantined: HashSet<String> = {
            let db = self.node.db();
            db.local()
                .list_quarantined(Some(session_id), MAX_QUARANTINE_NOTICES_PER_SESSION)
                .unwrap_or_default()
                .into_iter()
                .map(|e| e.receipt)
                .collect()
        };
        let mut live = Vec::new();
        self.clear_runtime_field(session_id, |runtime| {
            let list = &mut runtime.quarantine_notices;
            list.retain(|n| still_quarantined.contains(&n.receipt));
            for n in list.iter() {
                live.push(json!({
                    "receipt": n.receipt,
                    "source": n.source,
                    "trustTier": n.trust_tier,
                    "reason": n.reason,
                    "quarantinedAt": n.quarantined_at,
                }));
            }
        });
        live
    }

    /// Returns unsurfaced metadata-only quarantine notices for piggybacking inside an
    /// already-scheduled `<hyphae-inbox>` XML digest (`G10`).
    ///
    /// Read-only with respect to `surfaced_in_batch`: notices are marked surfaced only once
    /// the rendered digest actually commits, so speculative flushes with no live transport
    /// never drop a notice before delivery. Never leaks message body text and never emits
    /// duplicate notices for the same receipt.
    fn peek_unsurfaced_quarantine_receipts(&self, session_id: &str) -> Vec<String> {
        let still_quarantined: HashSet<String> = {
            let db = self.node.db();
            db.local()
                .list_quarantined(Some(session_id), MAX_QUARANTINE_NOTICES_PER_SESSION)
                .unwrap_or_default()
                .into_iter()
                .map(|e| e.receipt)
                .collect()
        };
        let mut out = Vec::new();
        self.clear_runtime_field(session_id, |runtime| {
            let list = &mut runtime.quarantine_notices;
            list.retain(|n| still_quarantined.contains(&n.receipt));
            for n in list.iter() {
                if !n.surfaced_in_batch {
                    out.push(n.receipt.clone());
                }
            }
        });
        out
    }

    fn mark_surfaced_quarantine_notices(&self, session_id: &str, receipts: &[String]) {
        if receipts.is_empty() {
            return;
        }
        self.clear_runtime_field(session_id, |runtime| {
            for notice in &mut runtime.quarantine_notices {
                if !notice.surfaced_in_batch && receipts.contains(&notice.receipt) {
                    notice.surfaced_in_batch = true;
                }
            }
        });
    }

    /// Enqueues a trusted daemon-generated metadata-only system notice into `session_id`'s
    /// mailbox (pre-cleared through Security Gate) and wakes any live transport (`H6`).
    async fn enqueue_system_notice(
        self: &Arc<Self>,
        session_id: &str,
        item_id: String,
        text: String,
    ) {
        let now = self.current_time_ms();
        let stored = {
            let db = self.node.db();
            if db.local().get_session(session_id).ok().flatten().is_none() {
                return;
            }
            matches!(
                db.local().put_daemon_notice(
                    session_id,
                    self.node.node_id().as_str(),
                    item_id,
                    text,
                    DaemonNoticeKind::System,
                    now,
                ),
                Ok(MailboxPutResult::Stored { .. })
            )
        };
        if stored {
            self.bump_ui_rev();
            self.flush_session(session_id).await;
        }
    }

    /// Enqueues a concise local `[hyphae notice]` for `session_id` after a host sleep/wake
    /// boundary if and only if:
    /// - the session still exists in SQLite,
    /// - it does NOT already hold a pending wake notice, and
    /// - `"hyphae:system"` is NOT muted by session policy or global/session mute rules.
    ///
    /// Does NOT trigger `flush_session` directly so callers can coalesce wake notices alongside
    /// any queued DMs in a single atomic `flush_pending_session_list` pass.
    fn enqueue_wake_notice_if_eligible(
        &self,
        session_id: &str,
        wake_epoch: u64,
        slept_for: Duration,
        was_interrupted_active: bool,
    ) -> bool {
        let now = self.current_time_ms();
        let db = self.node.db();
        if db.local().get_session(session_id).ok().flatten().is_none() {
            return false;
        }

        // Never stack multiple pending wake notices if the agent hasn't drained the previous one.
        if let Ok(pending) = db.local().peek_inbox(session_id, 500) {
            if pending.iter().any(|entry| {
                entry.trusted_daemon_notice(self.node.node_id().as_str())
                    == Some(DaemonNoticeKind::Wake)
            }) {
                return false;
            }
        }

        // Respect both per-session DeliveryPolicy mutes and persisted global/session mute rules.
        let parsed = hyp_node::delivery::ParsedMailboxSource::parse(
            self.node.node_id().as_str(),
            DaemonNoticeKind::SOURCE,
            MailboxKind::Message,
        );
        let ctx = parsed.as_context();
        if let Ok(policy) = self.delivery.policy(&db, session_id) {
            if policy.resolve_urgency(&ctx, None, None) == DeliveryUrgency::Mute {
                return false;
            }
        }
        if let Ok(mutes) = db.local().list_mutes_at(Some(session_id), now) {
            let muted = mutes.iter().any(|rule| {
                DeliveryRule::new(&rule.pattern, DeliveryUrgency::Mute)
                    .match_specificity(&ctx)
                    .is_some()
            });
            if muted {
                return false;
            }
        }

        let human_dur = format_human_duration(slept_for);
        let text = if was_interrupted_active {
            format!(
                "[hyphae notice] Host woke from sleep after {human_dur}; your previous turn may have been interrupted. Peer links reconnected."
            )
        } else {
            format!(
                "[hyphae notice] Host woke from sleep after {human_dur}. Peer links reconnected."
            )
        };

        matches!(
            db.local().put_daemon_notice(
                session_id,
                self.node.node_id().as_str(),
                format!("system-wake:{wake_epoch}"),
                text,
                DaemonNoticeKind::Wake,
                now,
            ),
            Ok(MailboxPutResult::Stored { .. })
        )
    }

    async fn broadcast_wake_hooks(&self, slept_for: Duration) {
        let hooks: Vec<Arc<dyn WakeHook>> = self
            .wake_hooks
            .lock_state("wake_hooks lock poisoned")
            .clone();
        if hooks.is_empty() {
            return;
        }
        let mut join_set = tokio::task::JoinSet::new();
        for hook in hooks {
            join_set.spawn(async move {
                let _ = tokio::time::timeout(
                    WAKE_HOOK_BROADCAST_TIMEOUT,
                    hook.on_system_wake(slept_for),
                )
                .await;
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
    }

    async fn handle_system_wake(self: &Arc<Self>, slept_for: Duration) -> WakeRecoveryReport {
        // 1. Recycle PeerLinks + external Drop Relay SSE watchers + sweep local topic batches
        //    + kick the UnifiedNode deadline scheduler immediately.
        let wake_epoch = self.node.notify_system_wake(slept_for);

        // 2. Broadcast best-effort `system.wake` notifications to running external plugins.
        self.broadcast_wake_hooks(slept_for).await;

        // 3. Snapshot sessions currently marked `Active` (mid-turn interrupted across sleep),
        //    then clear stale activity leases, grace timers, transient hold retries,
        //    `openclaw_missing_sessions`, and lazy hydrate cooldowns so nothing stays stuck.
        let (interrupted_active, cleared_hold_retries) = self.reset_runtime_after_wake();

        // 4. Rehydrate any dropped persisted push transports before flushing.
        if self.config.auto_detect_transports {
            let to_rehydrate = self.collect_sessions_for_transport_rehydration(&[]);
            self.rehydrate_persisted_transports(to_rehydrate).await;
        }

        // 5. Enqueue concise `[hyphae notice]` ONLY for mid-turn interrupted sessions
        //    (and optionally all enrolled sessions if `notify_all_enrolled` was explicitly opted in),
        //    respecting mute/Focus Mode, deduplicating pending notices, and NEVER triggering
        //    Tier 4 cold spawns.
        let mut notified_sessions: Vec<String> = Vec::new();
        let mut seen_targets: HashSet<String> = HashSet::new();
        if self.config.wake_recovery.notify_interrupted_active {
            for sid in &interrupted_active {
                if sid.starts_with("local-ingest:") || !seen_targets.insert(sid.clone()) {
                    continue;
                }
                if self.enqueue_wake_notice_if_eligible(sid, wake_epoch, slept_for, true) {
                    notified_sessions.push(sid.clone());
                }
            }
        }
        if self.config.wake_recovery.notify_all_enrolled {
            let enrolled_ids: Vec<String> = {
                let db = self.node.db();
                db.local()
                    .list_sessions()
                    .unwrap_or_default()
                    .into_iter()
                    .filter(|s| s.handle.is_some() && !s.id.starts_with("local-ingest:"))
                    .map(|s| s.id)
                    .collect()
            };
            for sid in enrolled_ids {
                if !seen_targets.insert(sid.clone()) {
                    continue;
                }
                if self.enqueue_wake_notice_if_eligible(&sid, wake_epoch, slept_for, false) {
                    notified_sessions.push(sid);
                }
            }
        }

        // 6. Flush pending sessions immediately (strictly at-most-once).
        let pending_sessions = self.collect_pending_sessions_for_flush();
        let flushed_sessions = pending_sessions.len();
        self.flush_pending_session_list(pending_sessions).await;

        // 7. Schedule ONE short `shutdown_rx`-cancellable follow-up flush (~2s later) so
        //    messages pulled by reconnecting PeerLinks flush promptly with zero duplicates.
        if !self.config.wake_followup_flush_delay.is_zero() && !*self.shutdown_rx.borrow() {
            let followup_gen = self.wake_followup_gen.fetch_add(1, Ordering::SeqCst) + 1;
            let followup_daemon = Arc::clone(self);
            let mut shutdown_rx = self.shutdown_rx.clone();
            let delay = self.config.wake_followup_flush_delay;
            tokio::spawn(async move {
                tokio::select! {
                    _ = tokio::time::sleep(delay) => {}
                    _ = shutdown_rx.changed() => {
                        return;
                    }
                }
                if *shutdown_rx.borrow() {
                    return;
                }
                if followup_daemon.wake_followup_gen.load(Ordering::SeqCst) != followup_gen {
                    return;
                }
                followup_daemon.flush_all_pending_sessions().await;
            });
        }

        self.bump_ui_rev();
        WakeRecoveryReport {
            wake_epoch,
            slept_ms: slept_for.as_millis().min(u64::MAX as u128) as u64,
            cleared_active_sessions: interrupted_active,
            cleared_hold_retries,
            notified_sessions,
            flushed_sessions,
        }
    }

    fn openclaw_gateway_push_enabled(&self) -> bool {
        read_node_file_for_state_dir(&self.node.config().state_dir)
            .and_then(|file| file.openclaw)
            .map(OpenClawNodeConfig::from_node_file)
            .unwrap_or_default()
            .gateway_push_enabled()
    }

    /// Resolves the exact `(sessionKey, agentId)` target for an `openclaw:*` session purely from
    /// the in-memory `openclaw_targets` index (or canonical `openclaw:agent:<agentId>:...` ID),
    /// NEVER locking `self.node.db()` so callers holding `db` (`daemon.status`, `sessions.summary`,
    /// `ui/state.json`) can NEVER self-deadlock.
    /// Fails closed (`None`) when no validated OpenClaw `sessionKey` exists for this session.
    fn resolve_openclaw_session_target(&self, session_id: &str) -> Option<(String, String)> {
        if !session_id.starts_with("openclaw:") {
            return None;
        }
        if let Some(cached) = self
            .session_runtime()
            .get(session_id)
            .and_then(|runtime| runtime.openclaw_target.clone())
        {
            return Some(cached);
        }
        let suffix = session_id.strip_prefix("openclaw:")?;
        if !suffix.starts_with("agent:") {
            return None;
        }
        let session_key = validate_openclaw_session_key(suffix).ok()?;
        let agent_id = parse_openclaw_agent_id_from_session_key(&session_key)
            .or_else(|| {
                read_node_file_for_state_dir(&self.node.config().state_dir)
                    .and_then(|file| file.openclaw)
                    .map(OpenClawNodeConfig::from_node_file)
                    .and_then(|cfg| cfg.agent_id)
            })
            .unwrap_or_else(|| DEFAULT_OPENCLAW_AGENT_ID.to_string());
        Some((session_key, agent_id))
    }

    fn openclaw_plugin_wake_available_for(&self, session_id: &str) -> bool {
        if !session_id.starts_with("openclaw:") {
            return false;
        }
        let has_service = self
            .openclaw_service
            .lock_state("openclaw_service lock poisoned")
            .is_some();
        if !has_service {
            return false;
        }
        if self
            .session_runtime()
            .get(session_id)
            .is_some_and(|runtime| runtime.openclaw_session_missing)
        {
            return false;
        }
        self.openclaw_gateway_push_enabled()
            && self.resolve_openclaw_session_target(session_id).is_some()
    }

    fn clear_openclaw_session_missing(&self, session_id: &str) {
        self.clear_runtime_field(session_id, |runtime| {
            runtime.openclaw_session_missing = false
        });
    }

    fn active_transport_kind(&self, session_id: &str) -> Option<&'static str> {
        if self
            .session_runtime()
            .get(session_id)
            .is_some_and(|runtime| runtime.channel.is_some())
        {
            return Some("claude_channel");
        }
        if self.openclaw_plugin_wake_available_for(session_id) {
            return Some("openclaw_plugin");
        }
        if let Some(transport) = self.attached_push_transport(session_id) {
            return Some(transport.kind());
        }
        let sessions = self.session_runtime();
        if let Some(list) = sessions.get(session_id).map(|runtime| &runtime.waiters) {
            if list.iter().any(|w| w.mode == WaiterKind::Stream) {
                return Some("watch");
            }
            if !list.is_empty() {
                return Some("wait");
            }
        }
        None
    }

    fn has_live_transport(&self, session_id: &str) -> bool {
        self.active_transport_kind(session_id).is_some()
    }

    fn record_herdr_bare_shell_rejection(&self, session_id: &str, terminal_id: &str) {
        self.session_runtime()
            .entry(session_id.to_owned())
            .or_default()
            .herdr_bare_shell_rejection = Some(terminal_id.to_owned());
    }

    fn clear_herdr_bare_shell_rejection(&self, session_id: &str) {
        self.clear_runtime_field(session_id, |runtime| {
            runtime.herdr_bare_shell_rejection = None
        });
    }

    fn herdr_bare_shell_rejection(&self, session_id: &str) -> Option<String> {
        self.session_runtime()
            .get(session_id)
            .and_then(|runtime| runtime.herdr_bare_shell_rejection.clone())
    }

    fn clear_lazy_hydrate_cooldown(&self, session_id: &str) {
        self.clear_runtime_field(session_id, |runtime| runtime.lazy_hydrate_attempt_at = None);
    }

    fn record_lazy_hydrate_attempt(&self, session_id: &str) {
        self.session_runtime()
            .entry(session_id.to_owned())
            .or_default()
            .lazy_hydrate_attempt_at = Some(Instant::now());
    }

    fn is_lazy_hydrate_in_cooldown(&self, session_id: &str) -> bool {
        self.session_runtime()
            .get(session_id)
            .and_then(|runtime| runtime.lazy_hydrate_attempt_at)
            .is_some_and(|last| last.elapsed() < LAZY_HYDRATE_COOLDOWN)
    }

    fn transport_summary_json(&self, session_id: &str) -> Value {
        match self.active_transport_kind(session_id) {
            Some(kind) => json!({ "live": true, "kind": kind }),
            None => match self.herdr_bare_shell_rejection(session_id) {
                Some(_) => json!({
                    "live": false,
                    "kind": "none",
                    "rejected": "herdr_bare_shell"
                }),
                None => json!({ "live": false, "kind": "none" }),
            },
        }
    }

    async fn wait_for_pending_probe(&self, session_id: &str) {
        let rx_opt = self
            .pending_probes
            .lock_state("pending_probes lock poisoned")
            .get(session_id)
            .cloned();
        if let Some(mut rx) = rx_opt {
            let _ =
                tokio::time::timeout(Duration::from_millis(2_500), rx.wait_for(|done| *done)).await;
        }
    }

    fn has_kv_capability(&self) -> bool {
        if let Some(explicit) = self.config.enable_kv {
            return explicit;
        }
        if !self.node.config().kv_namespaces.is_empty() {
            return true;
        }
        let db = self.node.db();
        if let Ok(peers) = db.peers().list_peers(None) {
            for p in peers {
                if let Some(ref raw) = p.manifest_json {
                    if let Ok(signed) =
                        serde_json::from_str::<hyp_proto::manifest::SignedNodeManifest>(raw)
                    {
                        if let Ok(payload) = signed.decode_payload() {
                            if !payload.advertised.kv_namespaces.is_empty() {
                                return true;
                            }
                        }
                    }
                }
            }
        }
        false
    }

    /// Deterministically derives `st_<base64url(HMAC-SHA256(k_session, "hyphae-session-token-v1:" || session_id))>`.
    /// Survives daemon restarts & `claude --resume` without storing tokens in SQLite or `ui/state.json`.
    fn session_token_for(&self, session_id: &str) -> String {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, &self.session_token_key);
        let msg = format!("{SESSION_TOKEN_DOMAIN_PREFIX}{session_id}");
        let tag = ring::hmac::sign(&key, msg.as_bytes());
        format!("st_{}", URL_SAFE_NO_PAD.encode(tag.as_ref()))
    }

    fn cache_env_file_exported(&self, session_id: &str) {
        self.session_runtime()
            .entry(session_id.to_owned())
            .or_default()
            .env_file_exported = true;
    }

    fn session_requires_wait_token(&self, session_id: &str) -> bool {
        if self
            .session_runtime()
            .get(session_id)
            .is_some_and(|runtime| runtime.env_file_exported)
        {
            return true;
        }
        let db = self.node.db();
        if let Ok(Some(sess)) = db.local().get_session(session_id) {
            if backend_json_flag_true(&sess.backend_json, "envFileExported") {
                self.cache_env_file_exported(session_id);
                return true;
            }
        }
        false
    }

    /// Verifies `sessionToken` on hook/register/hint paths:
    /// - If `sessionToken` is omitted (or `null`), returns `Ok(())` so Claude Code `PreToolUse` /
    ///   `PostToolUse` hook subprocesses (which do NOT source `CLAUDE_ENV_FILE`) never break!
    /// - If `sessionToken` IS provided, verifies it in constant time against
    ///   `session_token_for(session_id)` — rejecting wrong/forged/empty tokens fail-closed!
    fn verify_optional_session_token(
        &self,
        session_id: &str,
        packet: &Map<String, Value>,
    ) -> Result<(), &'static str> {
        match packet.get("sessionToken") {
            None | Some(Value::Null) => Ok(()),
            Some(Value::String(raw)) => {
                let expected = self.session_token_for(session_id);
                if verify_session_token_ct(&expected, Some(raw)) {
                    Ok(())
                } else {
                    Err("session_token_invalid")
                }
            }
            Some(_) => Err("session_token_invalid"),
        }
    }

    /// Verifies `sessionToken` on `wait.subscribe`:
    /// - If `sessionToken` is provided, ALWAYS verifies it in constant time against
    ///   `session_token_for(session_id)` (so Session A carrying `HYPHAE_SESSION_TOKEN(A)` trying
    ///   `hyp wait --session B` is immediately rejected fail-closed!).
    /// - If `sessionToken` is omitted, fails closed (`session_token_invalid`) whenever
    ///   `session_id` completed `SessionStart` with `envFileExported: true` (blocking even
    ///   `env -u HYPHAE_SESSION_TOKEN hyp wait --session claude:<victim>`!).
    fn verify_wait_session_auth(
        &self,
        session_id: &str,
        packet: &Map<String, Value>,
    ) -> Result<(), &'static str> {
        match packet.get("sessionToken") {
            None | Some(Value::Null) => {
                if self.session_requires_wait_token(session_id) {
                    Err("session_token_invalid")
                } else {
                    Ok(())
                }
            }
            Some(Value::String(raw)) => {
                let expected = self.session_token_for(session_id);
                if verify_session_token_ct(&expected, Some(raw)) {
                    Ok(())
                } else {
                    Err("session_token_invalid")
                }
            }
            Some(_) => Err("session_token_invalid"),
        }
    }

    /// Materializes any due local topic batches into local mailboxes and snapshots all sessions
    /// currently holding pending mailbox rows (excluding internal `local-ingest:` staging rows).
    ///
    /// Runs synchronously against local SQLite so `LocalDaemon::start` captures the exact
    /// pre-existing backlog before returning — never racing against fresh items ingested after
    /// startup!
    /// Collects active sessions with persisted native push transport hints (`herdrTerminalId`,
    /// `codexThreadId`, `t3ThreadId` / `t3Url` / `t3BaseDir`, OpenClaw hints) for non-blocking
    /// startup rehydration — INCLUDING sessions with `pending_count == 0` so `hyp inspect`
    /// immediately reports `hasLiveTransport: true` after daemon restart (Issue #34).
    fn collect_sessions_for_transport_rehydration(
        &self,
        already_pending: &[(String, String)],
    ) -> Vec<(String, String)> {
        if !self.config.auto_detect_transports || *self.shutdown_rx.borrow() {
            return Vec::new();
        }
        let pending_set: HashSet<&str> =
            already_pending.iter().map(|(id, _)| id.as_str()).collect();
        let db = self.node.db();
        let mut out = Vec::new();
        for s in db.local().list_sessions().unwrap_or_default() {
            if s.id.starts_with("local-ingest:") || pending_set.contains(s.id.as_str()) {
                continue;
            }
            let hints = TransportHints::from_session_backend(&s.id, &s.backend_json);
            if hints.has_any_hint()
                || s.id.starts_with("codex:")
                || s.id.starts_with("openclaw:")
                || s.id.starts_with("t3:")
            {
                out.push((s.id, s.backend_json));
            }
        }
        out
    }

    /// Re-probes & attaches persisted native push transports (`Herdr`, `T3`, `OpenClaw`, `CodexQueue`)
    /// concurrently on daemon startup for sessions with `pending_count == 0` (Issue #34).
    async fn rehydrate_persisted_transports(self: &Arc<Self>, sessions: Vec<(String, String)>) {
        if sessions.is_empty() || !self.config.auto_detect_transports || *self.shutdown_rx.borrow()
        {
            return;
        }
        let mut join_set = tokio::task::JoinSet::new();
        for (sid, backend_json) in sessions {
            let daemon = Arc::clone(self);
            join_set.spawn(async move {
                if *daemon.shutdown_rx.borrow() || daemon.current_transport_priority(&sid) > 0 {
                    return;
                }
                let hints = TransportHints::from_session_backend(&sid, &backend_json);
                maybe_spawn_transport_probe(&daemon, &sid, hints);
                daemon
                    .await_pending_probe_bounded(&sid, Duration::from_secs(5))
                    .await;
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
        self.bump_ui_rev();
    }

    async fn await_pending_probe_bounded(&self, session_id: &str, timeout: Duration) {
        let probe_rx = self
            .pending_probes
            .lock_state("pending_probes lock poisoned")
            .get(session_id)
            .cloned();
        if let Some(mut rx) = probe_rx {
            let mut shutdown_rx = self.shutdown_rx.clone();
            let wait_probe = async {
                while !*rx.borrow() {
                    if rx.changed().await.is_err() {
                        break;
                    }
                }
            };
            tokio::select! {
                _ = tokio::time::timeout(timeout, wait_probe) => {}
                _ = shutdown_rx.changed() => {}
            }
        }
    }

    /// Lazily hydrates a persisted native push transport inside `flush_session_inner` when
    /// `auto_detect_transports` is enabled and no push transport is currently attached (Issue #34).
    ///
    /// Bounded by [`LAZY_HYDRATE_COOLDOWN`] so permanently dead targets never enter a probe loop.
    async fn maybe_lazy_hydrate_transport(self: &Arc<Self>, session_id: &str) {
        if !self.config.auto_detect_transports
            || self.current_transport_priority(session_id) > 0
            || *self.shutdown_rx.borrow()
        {
            return;
        }
        // If a probe is already running (e.g. startup rehydration), simply await it!
        let probe_in_flight = self
            .pending_probes
            .lock_state("pending_probes lock poisoned")
            .contains_key(session_id);
        if probe_in_flight {
            self.await_pending_probe_bounded(session_id, Duration::from_secs(5))
                .await;
            return;
        }
        if self.is_lazy_hydrate_in_cooldown(session_id) {
            return;
        }
        let backend_json = {
            let db = self.node.db();
            db.local()
                .get_session(session_id)
                .ok()
                .flatten()
                .map(|s| s.backend_json)
        };
        let Some(backend_json) = backend_json else {
            return;
        };
        let hints = TransportHints::from_session_backend(session_id, &backend_json);
        let has_signal = hints.has_any_hint()
            || session_id.starts_with("codex:")
            || session_id.starts_with("openclaw:")
            || session_id.starts_with("t3:");
        if !has_signal {
            return;
        }
        self.record_lazy_hydrate_attempt(session_id);
        maybe_spawn_transport_probe(self, session_id, hints);
        self.await_pending_probe_bounded(session_id, Duration::from_secs(5))
            .await;
        if self.current_transport_priority(session_id) > 0 {
            self.clear_lazy_hydrate_cooldown(session_id);
        }
    }

    async fn default_peer_id(&self) -> Option<String> {
        let db = self.node.db();
        db.peers()
            .list_peers(None)
            .ok()?
            .into_iter()
            .find(|p| p.status == hyp_store::PeerStatus::Active)
            .map(|p| p.peer_id)
    }

    async fn dispatch_tool(
        self: &Arc<Self>,
        session_id: &str,
        raw_name: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        let name = normalize_mesh_tool_name(raw_name).unwrap_or(raw_name);
        {
            let db = self.node.db();
            let now = self.current_time_ms();
            if db.local().get_session(session_id).ok().flatten().is_none() {
                let _ = db.local().register_session(session_id, "{}", now);
            } else {
                let _ = db.local().touch_session(session_id, now);
            }
        }

        match name {
            "hyp_mesh" => self.tool_mesh(session_id, args).await,
            "hyp_send" => self.tool_send(session_id, args).await,
            "hyp_inbox" => self.tool_inbox(session_id, args).await,
            "hyp_stream" => self.tool_stream(session_id, args).await,
            "hyp_kv" => self.tool_kv(args).await,
            "hyp_bridge" => self.tool_bridge(session_id, args),
            other => Err(("unknown_tool".into(), format!("Unknown tool {other}"))),
        }
    }

    async fn tool_mesh(
        self: &Arc<Self>,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        let action = args.get("action").and_then(Value::as_str).ok_or_else(|| {
            invalid_request("Expected action: join | leave | peers | channels | status | drop_link")
        })?;
        let has_channel = args
            .get("channel")
            .and_then(Value::as_str)
            .is_some_and(|c| !c.is_empty());
        match action {
            "drop_link" => self.tool_drop_link(session_id, args).await,
            "channels" => self.tool_channels(args).await,
            "join" if has_channel => self.tool_channel_join(session_id, args).await,
            "leave" if has_channel => self.tool_channel_leave(session_id, args).await,
            "join" => self.tool_join(session_id, args).await,
            "leave" => self.tool_leave(session_id).await,
            "peers" => self.tool_peers(session_id).await,
            "status" => self.tool_capabilities(session_id).await,
            other => Err(invalid_request(format!(
                "Invalid hyp_mesh action '{other}'. Expected: join | leave | peers | channels | status | drop_link"
            ))),
        }
    }

    async fn tool_join(
        &self,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        let handle = args
            .get("handle")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_request("Expected handle"))?;
        let description = args.get("description").and_then(Value::as_str);

        // Wait for any in-flight transport probe BEFORE registering the handle so explicit
        // `--backend herdr` on a bare shell (`hc get --json` proved `status == null` /
        // `status.app == null`) fails closed cleanly without enrolling a silent dead handle (Issue #36).
        self.wait_for_pending_probe(session_id).await;
        let bare_shell_tid = self.herdr_bare_shell_rejection(session_id);
        if let Some(ref terminal_id) = bare_shell_tid {
            let explicit_herdr = session_id.starts_with("herdr:") || {
                let db = self.node.db();
                db.local()
                    .get_session(session_id)
                    .ok()
                    .flatten()
                    .and_then(|s| extract_backend_str(&s.backend_json, "kind"))
                    .is_some_and(|k| k.eq_ignore_ascii_case("herdr"))
            };
            if explicit_herdr {
                return Err((
                    "herdr_bare_shell_rejected".into(),
                    format!(
                        "Refusing --backend herdr enrollment on bare shell terminal '{terminal_id}' (no coding agent detected by `hc get --json`; status.app is null). Start a coding agent inside this Herdr terminal or omit --backend herdr."
                    ),
                ));
            }
        }

        let rec = self
            .node
            .register_handle_with_description(session_id, handle, description)
            .await
            .map_err(node_err_tuple)?;

        let (policy, unread, muted) = {
            let db = self.node.db();
            let p = self.delivery.policy(&db, session_id).unwrap_or_default();
            let u = self.effective_pending_count(&db, session_id);
            let m = muted_count(&db, session_id).unwrap_or(0);
            (p, u, m)
        };

        let has_live = self.has_live_transport(session_id);
        let transport_summary = self.transport_summary_json(session_id);

        let mut out = Map::new();
        out.insert("address".into(), json!(rec.address));
        out.insert("nodeId".into(), json!(self.node.node_id().as_str()));
        out.insert("handle".into(), json!(rec.handle));
        if let Some(ref desc) = rec.description {
            out.insert("description".into(), json!(desc));
        }
        out.insert("deliveryMode".into(), json!(policy.default_mode.as_str()));
        out.insert("focusMode".into(), json!(policy.focus_mode));
        out.insert("unread".into(), json!(unread));
        out.insert("muted".into(), json!(muted));
        out.insert("hasLiveTransport".into(), json!(has_live));
        out.insert("transport".into(), transport_summary);
        if let Some(ref terminal_id) = bare_shell_tid {
            out.insert("transportRejected".into(), json!("herdr_bare_shell"));
            out.insert(
                "warnings".into(),
                json!([format!(
                    "Herdr transport skipped for bare shell terminal '{terminal_id}' (status.app is null; no coding agent detected)"
                )]),
            );
        }

        if let Some(include) = args.get("include").and_then(Value::as_array) {
            for item in include {
                match item.as_str() {
                    Some("peers") => {
                        if let Ok(v) = self.tool_peers(session_id).await {
                            if let Some(p) = v.get("peers") {
                                out.insert("peers".into(), p.clone());
                            }
                            if let Some(pd) = v.get("peerDetails") {
                                out.insert("peerDetails".into(), pd.clone());
                            }
                            if let Some(um) = v.get("untrustedMetadata") {
                                out.insert("untrustedMetadata".into(), um.clone());
                            }
                        }
                    }
                    Some("channels") => {
                        if let Ok(v) = self.tool_channels(&Map::new()).await {
                            if let Some(c) = v.get("channels") {
                                out.insert("channels".into(), c.clone());
                            }
                        }
                    }
                    Some("topics") => {
                        if let Ok(v) = self.tool_topics(&Map::new()).await {
                            if let Some(r) = v.get("routers") {
                                out.insert("topics".into(), r.clone());
                            }
                        }
                    }
                    Some("subs") => {
                        if let Ok(v) = self.tool_subscriptions(session_id).await {
                            if let Some(s) = v.get("subscriptions") {
                                out.insert("subs".into(), s.clone());
                            }
                        }
                    }
                    Some("mutes") => {
                        if let Ok(v) = self.tool_mutes(session_id).await {
                            if let Some(m) = v.get("mutes") {
                                out.insert("mutes".into(), m.clone());
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        self.bump_ui_rev();
        Ok(Value::Object(out))
    }

    async fn tool_leave(&self, session_id: &str) -> Result<Value, (String, String)> {
        let now = self.current_time_ms();
        let left = {
            let db = self.node.db();
            let prev = db
                .local()
                .get_session(session_id)
                .map_err(store_err_tuple)?
                .and_then(|s| s.handle);
            if let Some(handle) = prev {
                let _ = db.local().set_session_handle(session_id, None, now);
                let _ = db
                    .messages()
                    .remove_handle(self.node.node_id().as_str(), &handle, now);
                true
            } else {
                false
            }
        };
        self.cancel_hold_retry(session_id);
        self.bump_ui_rev();
        Ok(json!({ "left": left }))
    }

    async fn tool_peers(&self, session_id: &str) -> Result<Value, (String, String)> {
        let self_addr = {
            let db = self.node.db();
            db.local()
                .get_session(session_id)
                .ok()
                .flatten()
                .and_then(|s| s.handle)
                .map(|h| format_address(self.node.node_id().as_str(), &h))
        };

        let discovered = self.node.discover_peer_handles().await;
        let mut peers: Vec<String> = Vec::with_capacity(discovered.len());
        let mut peer_details: Vec<Value> = Vec::with_capacity(discovered.len());
        for d in discovered {
            peers.push(d.address.clone());
            let mut obj = Map::new();
            obj.insert("address".into(), json!(d.address));
            obj.insert("nodeId".into(), json!(d.node_id));
            obj.insert("handle".into(), json!(d.handle));
            if let Some(desc) = d.description.filter(|s| !s.is_empty()) {
                obj.insert("description".into(), json!(desc));
            }
            if let Some(via) = d.via.filter(|s| !s.is_empty()) {
                obj.insert("via".into(), json!(via));
            }
            peer_details.push(Value::Object(obj));
        }

        Ok(json!({
            "self": self_addr,
            "peers": peers,
            "peerDetails": peer_details,
            "untrustedMetadata": true,
        }))
    }

    async fn tool_capabilities(
        self: &Arc<Self>,
        session_id: &str,
    ) -> Result<Value, (String, String)> {
        self.reconcile_session_inbox(session_id).await;
        let (sess, policy, unread, muted, mutes_len, peers) = {
            let db = self.node.db();
            let sess = db.local().get_session(session_id).ok().flatten();
            let policy = self.delivery.policy(&db, session_id).unwrap_or_default();
            let unread = self.effective_pending_count(&db, session_id);
            let muted = muted_count(&db, session_id).unwrap_or(0);
            let mutes_len = db
                .local()
                .list_mutes(Some(session_id))
                .map(|v| v.len())
                .unwrap_or(0);
            let peers: Vec<String> = db
                .peers()
                .list_peers(None)
                .unwrap_or_default()
                .into_iter()
                .map(|p| p.peer_id)
                .collect();
            (sess, policy, unread, muted, mutes_len, peers)
        };
        self.wait_for_pending_probe(session_id).await;
        Ok(json!({
            "sessionId": session_id,
            "nodeId": self.node.node_id().as_str(),
            "handle": sess.and_then(|s| s.handle),
            "deliveryMode": policy.default_mode.as_str(),
            "focusMode": policy.focus_mode,
            "focusAllowInterruptVips": policy.focus_allow_interrupt_vips,
            "unread": unread,
            "muted": muted,
            "mutes": mutes_len,
            "rules": policy.overrides,
            "peers": peers,
            "hasLiveTransport": self.has_live_transport(session_id),
            "transport": self.transport_summary_json(session_id),
            "hasKv": self.has_kv_capability(),
        }))
    }

    async fn set_session_focus(
        self: &Arc<Self>,
        session_id: &str,
        focus_mode: bool,
        allow_vips: Option<bool>,
        extra_rules: &[DeliveryRule],
    ) -> Result<FocusChange, (String, String)> {
        let (default_urgency, store_mode) = if focus_mode {
            (DeliveryUrgency::Notify, DeliveryMode::Notify)
        } else {
            (DeliveryUrgency::Queue, DeliveryMode::Full)
        };
        let now = self.current_time_ms();
        let (policy, unread, muted) = {
            let db = self.node.db();
            let _ = db.local().set_delivery_mode(session_id, store_mode, now);
            let policy = self
                .delivery
                .update_policy(&db, session_id, |p| {
                    p.focus_mode = focus_mode;
                    p.default_mode = default_urgency;
                    if let Some(v) = allow_vips {
                        p.focus_allow_interrupt_vips = v;
                    }
                    for rule in extra_rules {
                        p.upsert_rule(rule.clone());
                    }
                })
                .map_err(delivery_err_tuple)?;
            for rule in extra_rules {
                if rule.delivery == DeliveryUrgency::Mute {
                    let _ = db
                        .local()
                        .add_mute(session_id, &rule.target, session_id, now);
                }
            }
            let unread = self.effective_pending_count(&db, session_id);
            let muted = muted_count(&db, session_id).unwrap_or(0);
            (policy, unread, muted)
        };

        let rev = self.bump_ui_rev();
        if !focus_mode {
            let restored = self.restore_focus_buffered_items(session_id);
            if unread > 0 || restored > 0 {
                self.flush_session(session_id).await;
            }
        }

        Ok(FocusChange {
            policy,
            unread,
            muted,
            rev,
        })
    }

    async fn tool_mode(
        self: &Arc<Self>,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        let mode_raw = args
            .get("mode")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_request("Expected mode: 'queue' | 'notify'"))?;
        let allow_vips = args.get("focusAllowInterruptVips").and_then(Value::as_bool);
        let extra_rules = parse_rules_arg(args)?;

        let focus_mode = match mode_raw.trim().to_ascii_lowercase().as_str() {
            "notify" => true,
            "queue" | "full" => false,
            other => {
                return Err(invalid_request(format!(
                    "Expected mode 'queue' | 'full' | 'notify', got '{other}'"
                )));
            }
        };

        let FocusChange {
            policy,
            unread,
            muted,
            ..
        } = self
            .set_session_focus(session_id, focus_mode, allow_vips, &extra_rules)
            .await?;

        Ok(json!({
            "deliveryMode": policy.default_mode.as_str(),
            "focusMode": policy.focus_mode,
            "focusAllowInterruptVips": policy.focus_allow_interrupt_vips,
            "rules": policy.overrides,
            "unread": unread,
            "muted": muted,
        }))
    }

    fn add_mute(
        self: &Arc<Self>,
        scope: &str,
        pattern: &str,
        actor: &str,
        ttl_seconds: Option<u64>,
        policy: MutePolicyUpdate<'_>,
    ) -> Result<(hyp_store::local::MuteRule, u64), (String, String)> {
        let now = self.current_time_ms();
        let expires_at =
            ttl_seconds.map(|secs| now.saturating_add((secs as i64).saturating_mul(1_000)));
        let rule = {
            let db = self.node.db();
            let added = db
                .local()
                .add_mute_with_expiry(scope, pattern, actor, now, expires_at)
                .map_err(store_err_tuple)?;
            let (session, required) = match policy {
                MutePolicyUpdate::None => (None, false),
                MutePolicyUpdate::BestEffort(session) => (Some(session), false),
                MutePolicyUpdate::Required(session) => (Some(session), true),
            };
            if let Some(session) = session {
                let updated = self.delivery.update_policy(&db, session, |p| {
                    p.upsert_rule(DeliveryRule::new(pattern, DeliveryUrgency::Mute));
                });
                if required {
                    updated.map_err(delivery_err_tuple)?;
                }
            }
            added
        };
        if let Some(ttl) = ttl_seconds {
            let timer_daemon = Arc::clone(self);
            let mut shutdown_rx = self.shutdown_rx.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(ttl)) => {}
                    _ = shutdown_rx.changed() => return,
                }
                if !*shutdown_rx.borrow() {
                    timer_daemon.sweep_expired_mutes_and_policies(timer_daemon.current_time_ms());
                }
            });
        }
        Ok((rule, self.bump_ui_rev()))
    }

    async fn tool_mute(
        self: &Arc<Self>,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        let target = args
            .get("mute")
            .or_else(|| args.get("target"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid_request("Expected mute target"))?;
        let scope_arg = args
            .get("scope")
            .and_then(Value::as_str)
            .unwrap_or("session");
        let db_scope = if scope_arg == "connector" {
            "*"
        } else {
            session_id
        };
        let ttl_seconds = parse_mute_ttl(args.get("ttlSeconds"))?;
        let (rule, _) = self.add_mute(
            db_scope,
            target,
            session_id,
            ttl_seconds,
            MutePolicyUpdate::BestEffort(session_id),
        )?;

        let mut out = json!({
            "muted": rule.pattern,
            "scope": if db_scope == "*" { "connector" } else { "session" },
        });
        if let Some(exp) = rule.expires_at {
            out["expiresAt"] = json!(exp);
        }
        Ok(out)
    }

    async fn tool_unmute(
        &self,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        let target = args
            .get("unmute")
            .or_else(|| args.get("target"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid_request("Expected unmute target"))?;
        let scope_arg = args
            .get("scope")
            .and_then(Value::as_str)
            .unwrap_or("session");
        let db_scope = if scope_arg == "connector" {
            "*"
        } else {
            session_id
        };

        let removed = {
            let db = self.node.db();
            let db_removed = db
                .local()
                .remove_mute(db_scope, target)
                .map_err(store_err_tuple)?;
            let mut policy_removed = false;
            let _ = self.delivery.update_policy(&db, session_id, |p| {
                policy_removed = p.remove_rule(target);
            });
            db_removed || policy_removed
        };
        self.bump_ui_rev();

        Ok(json!({
            "pattern": target.to_ascii_lowercase(),
            "scope": if db_scope == "*" { "connector" } else { "session" },
            "removed": removed,
        }))
    }

    async fn tool_mutes(&self, session_id: &str) -> Result<Value, (String, String)> {
        let now = self.current_time_ms();
        self.sweep_expired_mutes_and_policies(now);
        let rules = {
            let db = self.node.db();
            db.local()
                .list_mutes_at(Some(session_id), now)
                .map_err(store_err_tuple)?
        };
        let list: Vec<Value> = rules
            .into_iter()
            .map(|r| {
                let mut item = json!({
                    "pattern": r.pattern,
                    "scope": if r.scope == "*" { "connector" } else { "session" },
                    "mutedAt": r.muted_at,
                    "mutedBy": r.muted_by,
                });
                if let Some(exp) = r.expires_at {
                    item["expiresAt"] = json!(exp);
                }
                item
            })
            .collect();
        Ok(json!({ "mutes": list }))
    }

    async fn tool_channel_join(
        &self,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        let ch = args
            .get("channel")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_request("Expected channel name"))?;
        let handle = self.require_session_handle(session_id)?;
        let resp = self
            .node
            .join_channel(ch, &handle)
            .await
            .map_err(node_err_tuple)?;
        self.bump_ui_rev();
        Ok(serde_json::to_value(resp).unwrap_or_else(|_| json!({})))
    }

    async fn tool_channel_leave(
        &self,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        let ch = args
            .get("channel")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_request("Expected channel name"))?;
        let handle = self.require_session_handle(session_id)?;
        let left = self
            .node
            .leave_channel(ch, &handle)
            .await
            .map_err(node_err_tuple)?;
        self.bump_ui_rev();
        Ok(json!({ "left": left }))
    }

    async fn tool_channel_post(
        &self,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        let ch = args
            .get("channel")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_request("Expected channel name"))?;
        let text = args
            .get("text")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid_request("Expected non-empty text"))?;
        let handle = self.require_session_handle(session_id)?;
        self.check_outbound_gate(session_id, ch, "to.hyphae.channel.v1", text)?;
        let res = self
            .node
            .post_channel(ch, &handle, text)
            .await
            .map_err(node_err_tuple)?;
        Ok(serde_json::to_value(res).unwrap_or_else(|_| json!({})))
    }

    async fn tool_channels(&self, args: &Map<String, Value>) -> Result<Value, (String, String)> {
        let filter = args.get("channel").and_then(Value::as_str);
        let host = self
            .default_peer_id()
            .await
            .unwrap_or_else(|| "local".to_string());
        let list = self
            .node
            .list_channels(&host, filter)
            .await
            .map_err(node_err_tuple)?;
        Ok(json!({ "channels": list }))
    }

    async fn tool_send(
        &self,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        let to = args
            .get("to")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_request("Expected destination 'to'"))?;
        let handle = self.require_session_handle(session_id)?;

        let reaction_present = match args.get("reaction") {
            None | Some(Value::Null) => false,
            Some(Value::String(_)) => true,
            Some(_) => {
                return Err(invalid_request("Expected string 'reaction'"));
            }
        };

        // File transfer path
        if let Some(files_val) = args.get("files").and_then(Value::as_array) {
            if reaction_present {
                return Err(invalid_request(
                    "Reactions are only supported on external chat bridge destinations (<bridge>:<target>)",
                ));
            }
            let paths: Vec<PathBuf> = files_val
                .iter()
                .filter_map(Value::as_str)
                .map(PathBuf::from)
                .collect();
            if paths.is_empty() {
                return Err(invalid_request("Expected non-empty files array"));
            }
            let (target_node, to_handle) = parse_address(to).ok_or_else(|| {
                invalid_request("File transfers require <node>/<handle> destination")
            })?;
            let note = args.get("text").and_then(Value::as_str);
            if let Some(n) = note {
                self.check_outbound_gate(session_id, to, "to.hyphae.transfer.v1", n)?;
            }
            let mut entries = Vec::with_capacity(paths.len());
            for path in &paths {
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("file.bin")
                    .to_string();
                entries.push(hyp_crypto::transfer::TarInputEntry {
                    archive_path: name,
                    source_path: path.clone(),
                });
            }
            let res = self
                .node
                .send_files(target_node, Some(to_handle), &entries, None)
                .await
                .map_err(node_err_tuple)?;
            return Ok(json!({
                "transferId": res.id,
                "to": to,
                "routedVia": res.routed_via,
                "encrypted": true,
                "ciphertextBytes": res.ciphertext_bytes,
            }));
        }

        // Local bridge `<plugin>:<target>`
        if is_bridge_destination(to) {
            return self.send_to_bridge(session_id, &handle, to, args).await;
        }

        if reaction_present {
            return Err(invalid_request(
                "Reactions are only supported on external chat bridge destinations (<bridge>:<target>)",
            ));
        }

        let text = args
            .get("text")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_request("Expected 'text'"))?;

        // `#channel` or `<node>/#channel`
        if to.starts_with('#') || to.contains("/#") {
            let mut ch_args = Map::new();
            ch_args.insert("channel".into(), json!(to));
            ch_args.insert("text".into(), json!(text));
            return self.tool_channel_post(session_id, &ch_args).await;
        }

        // Direct DM `<node>/<handle>`
        self.check_outbound_gate(session_id, to, "to.hyphae.dm.v1", text)?;
        let res = self
            .node
            .send_dm(&handle, to, text)
            .await
            .map_err(node_err_tuple)?;
        Ok(json!({
            "messageId": res.id,
            "to": res.to,
            "routedVia": res.routed_via,
            "encrypted": res.encrypted,
            "status": "stored",
        }))
    }

    async fn tool_inbox(
        self: &Arc<Self>,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        // Policy controls if present (`mode`, `mute`, `unmute`, `rules`, `focusMode`).
        if args.get("mode").and_then(Value::as_str).is_some() {
            return self.tool_mode(session_id, args).await;
        }
        if args.get("mute").and_then(Value::as_str).is_some() {
            return self.tool_mute(session_id, args).await;
        }
        if args.get("unmute").and_then(Value::as_str).is_some() {
            return self.tool_unmute(session_id, args).await;
        }

        let rules = parse_rules_arg(args)?;
        let focus_mode_opt = args.get("focusMode").and_then(Value::as_bool);
        let allow_vips_opt = args.get("focusAllowInterruptVips").and_then(Value::as_bool);

        if !rules.is_empty() || focus_mode_opt.is_some() || allow_vips_opt.is_some() {
            let now = self.current_time_ms();
            let policy = {
                let db = self.node.db();
                let p = self
                    .delivery
                    .update_policy(&db, session_id, |pol| {
                        if let Some(fm) = focus_mode_opt {
                            pol.focus_mode = fm;
                            pol.default_mode = if fm {
                                DeliveryUrgency::Notify
                            } else {
                                DeliveryUrgency::Queue
                            };
                        }
                        if let Some(v) = allow_vips_opt {
                            pol.focus_allow_interrupt_vips = v;
                        }
                        for r in &rules {
                            pol.upsert_rule(r.clone());
                        }
                    })
                    .map_err(delivery_err_tuple)?;
                for r in &rules {
                    if r.delivery == DeliveryUrgency::Mute {
                        let _ = db.local().add_mute(session_id, &r.target, session_id, now);
                    }
                }
                p
            };
            self.bump_ui_rev();
            if focus_mode_opt == Some(false) {
                let restored = self.restore_focus_buffered_items(session_id);
                let unread_now = {
                    let db = self.node.db();
                    self.effective_pending_count(&db, session_id)
                };
                if unread_now > 0 || restored > 0 {
                    self.flush_session(session_id).await;
                }
            }

            // If ONLY policy updates were provided (no read/query flags), return updated policy directly.
            let is_query = args.contains_key("state")
                || args.contains_key("filter")
                || args.contains_key("cursor")
                || args.contains_key("ack")
                || args.contains_key("acknowledge")
                || args.contains_key("ids")
                || args.contains_key("summary")
                || args.contains_key("summaryOnly")
                || args.contains_key("limit");
            if !is_query {
                let (unread, muted) = {
                    let db = self.node.db();
                    (
                        self.effective_pending_count(&db, session_id),
                        muted_count(&db, session_id).unwrap_or(0),
                    )
                };
                return Ok(json!({
                    "deliveryMode": policy.default_mode.as_str(),
                    "focusMode": policy.focus_mode,
                    "focusAllowInterruptVips": policy.focus_allow_interrupt_vips,
                    "rules": policy.overrides,
                    "unread": unread,
                    "muted": muted,
                }));
            }
        }

        // Reconcile any newly arrived entries before querying!
        self.reconcile_session_inbox(session_id).await;

        let state = match args.get("state").and_then(Value::as_str) {
            Some(raw) => InboxStateFilter::parse(raw).map_err(delivery_err_tuple)?,
            None => InboxStateFilter::Unread,
        };
        let filter = parse_inbox_filter_arg(args.get("filter"))?;
        let cursor = args
            .get("cursor")
            .and_then(Value::as_str)
            .map(ToString::to_string);
        let limit = args
            .get("limit")
            .and_then(Value::as_u64)
            .map(|n| n as usize)
            .unwrap_or(20);
        let summary_only = args
            .get("summaryOnly")
            .or_else(|| args.get("summary"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        // RFC 0004 Decision #3: `hyp_inbox` acknowledges returned `unread` items by default
        // (`ack: false` peeks without acknowledging).
        let ack = args
            .get("acknowledgeAll")
            .or_else(|| args.get("ack"))
            .and_then(Value::as_bool)
            .unwrap_or(state == InboxStateFilter::Unread);
        let ids: Vec<String> = args
            .get("acknowledge")
            .or_else(|| args.get("ids"))
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(ToString::to_string)
                    .collect()
            })
            .unwrap_or_default();

        let mut query = InboxQuery {
            state,
            filter,
            cursor,
            limit,
            summary_only,
            ack,
            ids,
        };

        let gate_active = self.current_gate().is_some();
        // Issue #32: While Focus Mode is ON, if an unfiltered `Unread` pull (`hyp_inbox({ ack: true })`)
        // runs when BOTH VIP bypass (`Interrupt`) items AND Focus-buffered `Notify` items exist
        // (e.g. a nudge-only harness like OpenClaw waking for `<hyphae-wake urgency="interrupt">`),
        // scope the pull to ONLY the VIP items so Focus-buffered items are NEVER leaked or acked
        // early while Focus Mode is still active. When zero VIP items exist (or an explicit filter
        // / ids / state is passed), Focus-buffered items remain inspectable as usual.
        if query.state == InboxStateFilter::Unread
            && query.ids.is_empty()
            && query.filter == InboxFilter::default()
            && query.cursor.is_none()
        {
            let focus_on = {
                let db = self.node.db();
                self.delivery
                    .policy(&db, session_id)
                    .map(|p| p.focus_mode)
                    .unwrap_or(false)
            };
            if focus_on {
                let pending = {
                    let db = self.node.db();
                    db.local()
                        .peek_inbox_with_visibility(
                            session_id,
                            500,
                            MailboxVisibility::for_gate(gate_active),
                        )
                        .unwrap_or_default()
                };
                let meta_map = self
                    .item_meta
                    .lock_state("item_meta lock poisoned")
                    .get(session_id)
                    .cloned()
                    .unwrap_or_default();
                let mut vip_ids = Vec::new();
                let mut has_focus_buffered = false;
                for entry in pending {
                    let urgency = meta_map
                        .get(&entry.receipt)
                        .map(|m| m.urgency)
                        .unwrap_or(DeliveryUrgency::Notify);
                    match urgency {
                        DeliveryUrgency::Interrupt | DeliveryUrgency::Queue => {
                            vip_ids.push(entry.receipt);
                        }
                        DeliveryUrgency::Notify => {
                            has_focus_buffered = true;
                        }
                        DeliveryUrgency::Mute => {}
                    }
                }
                if !vip_ids.is_empty() && has_focus_buffered {
                    query.ids = vip_ids;
                }
            }
        }

        let (result, policy) = {
            let db = self.node.db();
            let now = self.current_time_ms();
            let local_node_id = self.node.node_id().as_str();
            let res = if gate_active {
                query_inbox_gate_cleared(&db, local_node_id, session_id, &query, now)
            } else {
                query_inbox_for_node(&db, local_node_id, session_id, &query, now)
            }
            .map_err(delivery_err_tuple)?;
            let pol = self.delivery.policy(&db, session_id).unwrap_or_default();
            (res, pol)
        };

        // Clean up in-memory item_meta for acknowledged receipts, reset the mid-turn queue
        // reminder timer when unread queue traffic clears, and cancel any pending Tier 3 Hold retries.
        if result.acked_count > 0 {
            let any_queue_left = {
                let mut guard = self.item_meta.lock_state("item_meta lock poisoned");
                guard.get_mut(session_id).is_some_and(|map| {
                    for item in &result.items {
                        map.remove(&item.receipt);
                    }
                    map.values()
                        .any(|m| m.urgency == DeliveryUrgency::Queue && !m.burst_demoted)
                })
            };
            if result.unread_count == 0 || !any_queue_left {
                self.reset_midturn_digest_timer(session_id);
            }
            if result.unread_count == 0 {
                self.cancel_hold_retry(session_id);
            }
            self.bump_ui_rev();
        }

        let quarantine_notices = self.live_quarantine_notices_json(session_id);
        let mut out = json!({
            "deliveryMode": policy.default_mode.as_str(),
            "focusMode": policy.focus_mode,
            "state": result.state.as_str(),
            "unread": result.unread_count,
            "muted": result.muted_count,
            "acked": result.acked_count,
            "totalMatched": result.total_matched,
            "hasMore": result.has_more,
            "nextCursor": result.next_cursor,
            "items": result.items,
        });
        if !quarantine_notices.is_empty() {
            out["quarantinedNotices"] = Value::Array(quarantine_notices);
        }
        Ok(out)
    }

    async fn tool_stream(
        &self,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        match args.get("action").and_then(Value::as_str) {
            Some("topics") => self.tool_topics(args).await,
            Some("subscribe") => self.tool_subscribe(session_id, args).await,
            Some("unsubscribe") => self.tool_unsubscribe(session_id, args).await,
            Some("list") => self.tool_subscriptions(session_id).await,
            _ => Err(invalid_request(
                "Expected hyp_stream action: topics | subscribe | unsubscribe | list",
            )),
        }
    }

    async fn tool_topics(&self, args: &Map<String, Value>) -> Result<Value, (String, String)> {
        let router_filter = match args.get("router") {
            Some(value) => value.as_str(),
            None => args
                .get("topic")
                .and_then(Value::as_str)
                .map(|topic| {
                    topic
                        .split_once('.')
                        .map(|(router, _)| router)
                        .unwrap_or(topic)
                })
                .filter(|router| is_valid_router_name(router)),
        };
        let mut routers = Vec::new();

        if router_filter.is_none() || router_filter == Some("local") {
            let local_topics: Vec<Value> = self
                .node
                .local_topic_catalog()
                .into_iter()
                .map(|t| {
                    json!({
                        "topic": t.topic,
                        "provisioned": t.has_provisioned_publisher,
                    })
                })
                .collect();
            routers.push(json!({
                "router": "local",
                "nodeId": self.node.node_id().as_str(),
                "supported": true,
                "topics": local_topics,
            }));
        }

        let peers = {
            let db = self.node.db();
            db.peers().list_peers(None).unwrap_or_default()
        };
        for p in peers {
            if let Some(rf) = router_filter {
                if rf != "primary" && rf != p.peer_id {
                    continue;
                }
            }
            let mut peer_topics = Vec::new();
            if let Some(ref raw) = p.manifest_json {
                if let Ok(signed) =
                    serde_json::from_str::<hyp_proto::manifest::SignedNodeManifest>(raw)
                {
                    if let Ok(payload) = signed.decode_payload() {
                        for t in payload.advertised.topics {
                            peer_topics.push(json!({
                                "topic": t.topic,
                                "kind": t.kind,
                                "description": t.description,
                            }));
                        }
                    }
                }
            }
            routers.push(json!({
                "router": p.peer_id,
                "supported": true,
                "topics": peer_topics,
            }));
        }

        Ok(json!({ "routers": routers }))
    }

    async fn tool_subscribe(
        &self,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        let raw_topic = args
            .get("topic")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid_request("Expected topic"))?;
        let (router, topic) = if args.contains_key("router") {
            (args.get("router").and_then(Value::as_str), raw_topic)
        } else if let Some((router, topic)) = raw_topic
            .split_once('.')
            .filter(|(router, topic)| is_valid_router_name(router) && !topic.is_empty())
        {
            (Some(router), topic)
        } else {
            (None, raw_topic)
        };
        let qualified_topic = match router {
            Some("primary") | None => topic.to_string(),
            Some(r) => format!("{r}.{topic}"),
        };

        let filters: Vec<ProtoFilter> = match args.get("filters") {
            None | Some(Value::Null) => Vec::new(),
            Some(val) => hyp_proto::filter::validate_filters(val)
                .map_err(|e| ("invalid_filter".into(), e.to_string()))?,
        };
        let coalesce_seconds = args
            .get("coalesceSeconds")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            .min(600) as u32;
        let urgency = match args
            .get("mode")
            .or_else(|| args.get("urgency"))
            .and_then(Value::as_str)
        {
            Some(raw) => DeliveryUrgency::parse(raw).map_err(delivery_err_tuple)?,
            None => DeliveryUrgency::Queue,
        };
        let key = args
            .get("key")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToString::to_string);

        // Reuse existing subscription ID if caller supplied matching `key` (in-memory or persisted).
        let existing_id = key.as_deref().and_then(|k| {
            let cached = {
                let guard = self.sub_meta.lock_state("sub_meta lock poisoned");
                guard
                    .get(session_id)
                    .and_then(|list| list.iter().find(|s| s.key.as_deref() == Some(k)))
                    .map(|s| s.id.clone())
            };
            cached.or_else(|| {
                let db = self.node.db();
                db.events()
                    .find_subscription_by_key(session_id, k)
                    .ok()
                    .flatten()
                    .map(|s| s.id)
            })
        });

        let res = self
            .node
            .subscribe_local_or_remote(SubscribeRequest {
                id: existing_id.clone(),
                subscriber_session: session_id.to_string(),
                qualified_topic,
                filters: filters.clone(),
                coalesce_seconds,
                mode: urgency.to_store_mode(),
            })
            .await
            .map_err(node_err_tuple)?;

        let strict = args.get("strict").and_then(Value::as_bool) == Some(true);
        let has_error = res
            .diagnostics
            .iter()
            .any(|d| d.severity == hyp_proto::filter::DiagnosticSeverity::Error);
        if strict && has_error {
            let msg = res
                .diagnostics
                .iter()
                .find(|d| d.severity == hyp_proto::filter::DiagnosticSeverity::Error)
                .map(|d| d.message.clone())
                .unwrap_or_else(|| "Unreachable subscription".into());
            let _ = self
                .node
                .db()
                .events()
                .delete_subscription(&res.subscription.id);
            return Err(("unreachable_subscription".into(), msg));
        }

        {
            let db = self.node.db();
            db.events()
                .set_subscription_meta(
                    &res.subscription.id,
                    &SubscriptionMeta {
                        key: key.clone(),
                        urgency: Some(urgency.as_str().to_string()),
                    },
                )
                .map_err(store_err_tuple)?;
        }

        {
            let mut guard = self.sub_meta.lock_state("sub_meta lock poisoned");
            let list = guard.entry(session_id.to_string()).or_default();
            list.retain(|s| s.id != res.subscription.id);
            list.push(SubscriptionRecordMeta {
                id: res.subscription.id.clone(),
                key,
                origin_node: res.origin_node.clone(),
                topic: res.topic.clone(),
                urgency,
            });
        }

        self.bump_ui_rev();

        let outcome = if existing_id.is_some() {
            "updated"
        } else {
            "created"
        };
        Ok(json!({
            "id": res.subscription.id,
            "originNode": res.origin_node,
            "topic": res.topic,
            "mode": urgency.as_str(),
            "outcome": outcome,
            "filters": filters,
            "reachable": !has_error,
            "pushdownShards": res.pushdown_shards,
            "diagnostics": res.diagnostics,
        }))
    }

    fn subscription_id_for_key(&self, session_id: &str, key: &str) -> String {
        let cached = {
            let guard = self.sub_meta.lock_state("sub_meta lock poisoned");
            guard.get(session_id).and_then(|list| {
                list.iter()
                    .find(|meta| meta.key.as_deref() == Some(key) || meta.id == key)
                    .map(|meta| meta.id.clone())
            })
        };
        cached
            .or_else(|| {
                let db = self.node.db();
                db.events()
                    .find_subscription_by_key(session_id, key)
                    .ok()
                    .flatten()
                    .map(|sub| sub.id)
            })
            .unwrap_or_else(|| key.to_string())
    }

    fn delete_session_subscription(
        &self,
        session_id: &str,
        sub_id: &str,
        clear_cache_if_missing: bool,
    ) -> Result<bool, (String, String)> {
        let removed = {
            let db = self.node.db();
            db.events()
                .delete_subscription_for_subscriber(sub_id, session_id)
                .map_err(store_err_tuple)?
        };
        if removed || clear_cache_if_missing {
            let mut guard = self.sub_meta.lock_state("sub_meta lock poisoned");
            if let Some(list) = guard.get_mut(session_id) {
                list.retain(|meta| meta.id != sub_id);
            }
        }
        Ok(removed)
    }

    async fn tool_unsubscribe(
        &self,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        let key_arg = args.get("key").and_then(Value::as_str);
        let id_arg = if args.contains_key("id") {
            args.get("id").and_then(Value::as_str)
        } else {
            key_arg.filter(|key| !key.contains(':'))
        };
        let sub_id = if let Some(id) = id_arg {
            id.to_string()
        } else if let Some(key) = key_arg {
            self.subscription_id_for_key(session_id, key)
        } else {
            return Err(invalid_request("Expected id or key"));
        };

        let removed = self.delete_session_subscription(session_id, &sub_id, true)?;
        if removed {
            self.bump_ui_rev();
        }

        Ok(json!({ "removed": removed }))
    }

    async fn tool_subscriptions(&self, session_id: &str) -> Result<Value, (String, String)> {
        let (subs, stored_meta) = {
            let db = self.node.db();
            let subs = db
                .events()
                .list_subscriptions(Some(session_id))
                .map_err(store_err_tuple)?;
            let stored_meta = db.events().list_subscription_meta().unwrap_or_default();
            (subs, stored_meta)
        };
        let meta_map: HashMap<String, SubscriptionRecordMeta> = self
            .sub_meta
            .lock_state("sub_meta lock poisoned")
            .get(session_id)
            .map(|l| l.iter().map(|m| (m.id.clone(), m.clone())).collect())
            .unwrap_or_default();

        let list: Vec<Value> = subs
            .into_iter()
            .map(|s| {
                let meta = meta_map.get(&s.id);
                let persisted = stored_meta.get(&s.id);
                let key = meta
                    .and_then(|m| m.key.clone())
                    .or_else(|| persisted.and_then(|m| m.key.clone()));
                let mode_str = meta
                    .map(|m| m.urgency.as_str().to_string())
                    .or_else(|| persisted.and_then(|m| m.urgency.clone()))
                    .unwrap_or_else(|| s.mode.as_str().to_string());
                json!({
                    "id": s.id,
                    "key": key,
                    "originNode": s.origin_node,
                    "topic": s.topic,
                    "filters": s.filters,
                    "coalesceSeconds": s.coalesce_seconds,
                    "mode": mode_str,
                })
            })
            .collect();
        Ok(json!({ "subscriptions": list }))
    }

    async fn tool_kv(&self, args: &Map<String, Value>) -> Result<Value, (String, String)> {
        let action = args
            .get("action")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_request("Expected hyp_kv action"))?;
        let namespace = args
            .get("namespace")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| invalid_request("Expected namespace"))?;

        let host_node = match args.get("node").and_then(Value::as_str) {
            Some(n) if !n.is_empty() => n.to_string(),
            _ => self
                .default_peer_id()
                .await
                .unwrap_or_else(|| "local".to_string()),
        };

        match action {
            "get" => {
                let key = args
                    .get("key")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid_request("Expected key"))?;
                let entry = self
                    .node
                    .kv_get(&host_node, namespace, key)
                    .await
                    .map_err(node_err_tuple)?;
                Ok(json!({ "entry": entry }))
            }
            "set" => {
                let key = args
                    .get("key")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid_request("Expected key"))?;
                let value = args
                    .get("value")
                    .cloned()
                    .ok_or_else(|| invalid_request("Expected value"))?;
                let write_model = match args.get("writeModel").and_then(Value::as_str) {
                    Some("shared") => WriteModel::Shared,
                    Some("allowlist") => WriteModel::Allowlist,
                    _ => WriteModel::Owner,
                };
                let expected_version = args.get("expectedVersion").and_then(Value::as_u64);
                let ttl_ms = args
                    .get("ttlMs")
                    .map(|value| {
                        value
                            .as_i64()
                            .filter(|&ttl| ttl > 0)
                            .ok_or_else(|| invalid_request("ttlMs must be a positive integer"))
                    })
                    .transpose()?;
                let clear_ttl = args
                    .get("clearTtl")
                    .map(|v| {
                        v.as_bool()
                            .ok_or_else(|| invalid_request("clearTtl must be a boolean"))
                    })
                    .transpose()?
                    .unwrap_or(false);
                if clear_ttl && ttl_ms.is_some() {
                    return Err(invalid_request("ttlMs and clearTtl are mutually exclusive"));
                }
                let encrypt = args
                    .get("encrypt")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                let allowlist = args.get("allowlist").and_then(Value::as_array).map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(ToString::to_string)
                        .collect()
                });
                let e2ee_members = args
                    .get("e2eeMembers")
                    .and_then(Value::as_array)
                    .map(|arr| {
                        arr.iter()
                            .filter_map(Value::as_str)
                            .map(ToString::to_string)
                            .collect()
                    });

                let entry = self
                    .node
                    .kv_set(KvWriteRequest {
                        host_node,
                        namespace: namespace.to_string(),
                        key: key.to_string(),
                        value,
                        write_model,
                        owner_id: None,
                        allowlist,
                        expected_version,
                        ttl_ms,
                        clear_ttl,
                        encrypt,
                        e2ee_members,
                    })
                    .await
                    .map_err(node_err_tuple)?;
                Ok(json!({ "entry": entry }))
            }
            "delete" => {
                let key = args
                    .get("key")
                    .and_then(Value::as_str)
                    .ok_or_else(|| invalid_request("Expected key"))?;
                let expected_version = args.get("expectedVersion").and_then(Value::as_u64);
                let res = self
                    .node
                    .kv_delete(&host_node, namespace, key, expected_version)
                    .await
                    .map_err(node_err_tuple)?;
                Ok(serde_json::to_value(res).unwrap_or_else(|_| json!({})))
            }
            "list" => {
                let prefix = args.get("prefix").and_then(Value::as_str);
                let entries = self
                    .node
                    .kv_list(&host_node, namespace, prefix)
                    .await
                    .map_err(node_err_tuple)?;
                Ok(json!({ "entries": entries }))
            }
            other => Err(invalid_request(format!(
                "Unsupported hyp_kv action '{other}'"
            ))),
        }
    }

    fn require_session_handle(&self, session_id: &str) -> Result<String, (String, String)> {
        let db = self.node.db();
        db.local()
            .get_session(session_id)
            .map_err(store_err_tuple)?
            .and_then(|s| s.handle)
            .ok_or_else(|| {
                (
                    "not_enrolled".into(),
                    "Call hyp_mesh(action:'join', handle:'...') before sending".into(),
                )
            })
    }

    fn check_outbound_gate(
        &self,
        session_id: &str,
        destination: &str,
        event_type: &str,
        payload: &str,
    ) -> Result<(), (String, String)> {
        let Some(pipeline) = self.current_gate() else {
            return Ok(());
        };
        let dest_node = parse_address(destination).map(|(n, _)| n.to_string());
        let trust_tier = dest_node
            .as_deref()
            .map(|n| self.resolve_peer_trust_tier(n))
            .unwrap_or(GateTrustTier::Peer);
        let eval = pipeline
            .evaluate_outbound(
                &OutboundContext {
                    session_id: Some(session_id.to_string()),
                    destination_node: dest_node,
                    destination: destination.to_string(),
                    event_type: event_type.to_string(),
                    trust_tier,
                    traceparent: None,
                    payload: payload.to_string(),
                },
                self.current_time_ms(),
            )
            .map_err(|e| ("gate_error".into(), e.to_string()))?;
        match eval.decision {
            GateDecision::Allow { .. } => Ok(()),
            GateDecision::Block { reason }
            | GateDecision::Quarantine { reason, .. }
            | GateDecision::Hold { reason, .. } => Err(("outbound_dlp_blocked".into(), reason)),
        }
    }
}

fn harness_natively_uses_hooks(harness: HarnessKind) -> bool {
    matches!(
        harness,
        HarnessKind::Claude
            | HarnessKind::Antigravity
            | HarnessKind::Cursor
            | HarnessKind::Gemini
            | HarnessKind::Codex
            | HarnessKind::Opencode
            | HarnessKind::Openclaw
    )
}

fn extract_openclaw_target_from_parts(
    session_id: &str,
    backend_json: &str,
) -> Option<(String, String)> {
    if !session_id.starts_with("openclaw:") {
        return None;
    }
    let session_key = extract_backend_str(backend_json, "openclawSessionKey")
        .and_then(|raw| {
            let stripped = raw.strip_prefix("openclaw:").unwrap_or(&raw);
            validate_openclaw_session_key(stripped).ok()
        })
        .or_else(|| {
            let suffix = session_id.strip_prefix("openclaw:")?;
            suffix
                .starts_with("agent:")
                .then(|| validate_openclaw_session_key(suffix).ok())
                .flatten()
        })?;
    let agent_id = extract_backend_str(backend_json, "openclawAgentId")
        .filter(|s| !s.is_empty() && s.len() <= 128 && !s.bytes().any(|b| b <= 0x20 || b == 0x7f))
        .or_else(|| parse_openclaw_agent_id_from_session_key(&session_key))
        .unwrap_or_else(|| DEFAULT_OPENCLAW_AGENT_ID.to_string());
    Some((session_key, agent_id))
}

fn backend_json_flag_true(backend_json: &str, key: &str) -> bool {
    serde_json::from_str::<Value>(backend_json)
        .ok()
        .and_then(|v| v.get(key).and_then(Value::as_bool))
        == Some(true)
}

fn cap_trust_tier_to_external_webhook(tier: GateTrustTier) -> GateTrustTier {
    match tier {
        GateTrustTier::Bridge => GateTrustTier::Bridge,
        _ => GateTrustTier::ExternalWebhook,
    }
}

fn value_indicates_external_webhook(val: &Value) -> bool {
    let Some(obj) = val.as_object() else {
        return false;
    };
    let check_source_kind = |map: &Map<String, Value>| {
        map.get("hyphaesourcekind")
            .and_then(Value::as_str)
            .is_some_and(|s| {
                let low = s.trim().to_ascii_lowercase();
                low == "external-webhook" || low == "webhook" || low == "bridge"
            })
    };
    if check_source_kind(obj) {
        return true;
    }
    if let Some(ext) = obj.get("extensions").and_then(Value::as_object) {
        if check_source_kind(ext) {
            return true;
        }
    }
    if let Some(src) = obj.get("source").and_then(Value::as_str) {
        let low = src.trim().to_ascii_lowercase();
        if low.starts_with("webhook:")
            || low.starts_with("adapter:")
            || low.starts_with("external-webhook:")
            || low.ends_with(":webhook")
        {
            return true;
        }
    }
    if let Some(events) = obj.get("events").and_then(Value::as_array) {
        for ev in events {
            if value_indicates_external_webhook(ev) {
                return true;
            }
        }
    }
    false
}

fn raw_has_external_webhook_origin(source: &str, text: &str) -> bool {
    let low_src = source.trim().to_ascii_lowercase();
    if low_src.starts_with("webhook:")
        || low_src.starts_with("adapter:")
        || low_src.starts_with("external-webhook:")
        || low_src.contains(":webhook")
    {
        return true;
    }
    let trimmed = text.trim();
    if trimmed.starts_with('{') {
        if let Ok(parsed) = serde_json::from_str::<Value>(trimmed) {
            if value_indicates_external_webhook(&parsed) {
                return true;
            }
        }
    }
    false
}

fn generate_random_key_32() -> [u8; 32] {
    use ring::rand::{SecureRandom, SystemRandom};
    let mut buf = [0u8; 32];
    if SystemRandom::new().fill(&mut buf).is_err() {
        let fallback = format!("{}:{}:{}", uuid_v4(), uuid_v4(), now_ms());
        let digest = ring::digest::digest(&ring::digest::SHA256, fallback.as_bytes());
        buf.copy_from_slice(digest.as_ref());
    }
    buf
}

fn load_or_init_session_token_key(node: &UnifiedNode) -> [u8; 32] {
    let cfg = node.config();
    let store = match cfg.secret_backend {
        Some(backend) => hyp_crypto::SecretStore::new(cfg.state_dir.clone(), backend),
        None => hyp_crypto::SecretStore::from_env(cfg.state_dir.clone()),
    };
    if let Some(key) = hyp_harness_ipc::kv_auth::read_session_token_key(&store) {
        return key;
    }
    let key = generate_random_key_32();
    let encoded = URL_SAFE_NO_PAD.encode(key);
    let _ = store.set(DAEMON_SESSION_TOKEN_KEY_SECRET, &encoded);
    key
}

fn verify_session_token_ct(expected: &str, provided: Option<&str>) -> bool {
    let Some(cand) = provided.map(str::trim).filter(|s| !s.is_empty()) else {
        return false;
    };
    let a = expected.as_bytes();
    let b = cand.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Reads `node.json` (or legacy `connector.json`) adjacent to `state_dir`, falling back to
/// `$HYPHAE_CONFIG` when no config file sits directly inside `state_dir`.
fn read_node_file_for_state_dir(state_dir: &Path) -> Option<hyp_node::node_file::NodeFile> {
    let mut candidates = vec![
        state_dir.join("node.json"),
        state_dir.join("connector.json"),
    ];
    if let Some(env_cfg) = hyp_harness_ipc::ambient_env_var("HYPHAE_CONFIG") {
        let trimmed = env_cfg.trim();
        if !trimmed.is_empty() {
            candidates.push(PathBuf::from(trimmed));
        }
    }
    for path in candidates {
        if path.is_file() {
            if let Ok((file, _)) = hyp_node::node_file::NodeFile::read(&path) {
                return Some(file);
            }
        }
    }
    None
}

/// Exclusive `SessionStart` hook handler returning the deterministic HMAC-derived `sessionToken`
/// for writing into `$CLAUDE_ENV_FILE`. When `envFileExported: true` is passed, persists that
/// flag so `wait.subscribe` require the matching `sessionToken`.
async fn handle_session_start(
    daemon: &Arc<LocalDaemonInner>,
    packet: &Map<String, Value>,
) -> Value {
    let Some(session_id) = packet
        .get("sessionId")
        .and_then(Value::as_str)
        .filter(|s| is_valid_session_id(s))
    else {
        return json!({ "ok": false, "error": "invalid_session" });
    };
    if let Err(err) = daemon.verify_optional_session_token(session_id, packet) {
        return json!({ "ok": false, "error": err });
    }

    let env_file_exported = packet.get("envFileExported").and_then(Value::as_bool) == Some(true);
    let harness = packet
        .get("harness")
        .or_else(|| packet.get("backend"))
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<HarnessKind>().ok());
    let hints = TransportHints::from_packet(packet, harness);

    // Issue #36: If explicit Herdr enrollment probes a live bare shell (`hc get --json` succeeded
    // and proved `status == null` / `status.app == null`), fail closed explicitly!
    if harness == Some(HarnessKind::Herdr) && daemon.config.auto_detect_transports {
        if let Some(ref tid) = hints.herdr_terminal_id {
            let hc_bin = daemon
                .config
                .herdr_bin
                .as_deref()
                .unwrap_or(DEFAULT_HERDR_BIN);
            if let HerdrProbeOutcome::BareShell { terminal_id, .. } =
                probe_herdr_terminal_detailed(hc_bin, tid).await
            {
                daemon.record_herdr_bare_shell_rejection(session_id, &terminal_id);
                return json!({
                    "ok": false,
                    "code": "herdr_bare_shell_rejected",
                    "error": format!(
                        "Refusing Herdr session start on bare shell terminal '{terminal_id}' (hc get --json reported status.app == null; no coding agent running)"
                    ),
                });
            }
        }
    }

    let mut patch = hints.backend_patch(harness);
    if env_file_exported {
        patch.insert("envFileExported".into(), json!(true));
    }
    let now = daemon.current_time_ms();
    if patch.is_empty() {
        let db = daemon.node.db();
        if db.local().get_session(session_id).ok().flatten().is_none() {
            let _ = db.local().register_session(session_id, "{}", now);
        } else {
            let _ = db.local().touch_session(session_id, now);
        }
    } else if let Err(e) = daemon.merge_session_backend_and_index(session_id, &patch, now) {
        return json!({ "ok": false, "error": e.to_string() });
    }
    if env_file_exported {
        daemon.cache_env_file_exported(session_id);
    }
    daemon.clear_lazy_hydrate_cooldown(session_id);
    daemon.bump_ui_rev();
    maybe_spawn_transport_probe(daemon, session_id, hints);

    let token = daemon.session_token_for(session_id);
    json!({
        "ok": true,
        "result": {
            "sessionId": session_id,
            "sessionToken": token,
            "envFileExported": env_file_exported,
        }
    })
}

fn handle_session_hint(daemon: &Arc<LocalDaemonInner>, packet: &Map<String, Value>) -> Value {
    let Some(session_id) = packet
        .get("sessionId")
        .and_then(Value::as_str)
        .filter(|s| is_valid_session_id(s))
    else {
        return json!({ "ok": false, "error": "invalid_session" });
    };
    if let Err(err) = daemon.verify_optional_session_token(session_id, packet) {
        return json!({ "ok": false, "error": err });
    }

    let harness = packet
        .get("harness")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<HarnessKind>().ok());
    let hints = TransportHints::from_packet(packet, harness);
    let patch = hints.backend_patch(harness);
    if !patch.is_empty() {
        let _ =
            daemon.merge_session_backend_and_index(session_id, &patch, daemon.current_time_ms());
        daemon.bump_ui_rev();
    }
    daemon.clear_lazy_hydrate_cooldown(session_id);
    maybe_spawn_transport_probe(daemon, session_id, hints);

    json!({ "ok": true, "result": {} })
}

fn read_t3_secret_for_node(node: &UnifiedNode, custom_secret_name: Option<&str>) -> Option<String> {
    let cfg = node.config();
    let store = match cfg.secret_backend {
        Some(backend) => hyp_crypto::SecretStore::new(cfg.state_dir.clone(), backend),
        None => hyp_crypto::SecretStore::from_env(cfg.state_dir.clone()),
    };

    if let Some(name) = custom_secret_name.map(str::trim).filter(|s| !s.is_empty()) {
        if !is_allowed_t3_token_secret(name) {
            return None;
        }
        return store
            .get(name)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
    }

    if let Ok(val) = store.get(DEFAULT_T3_TOKEN_SECRET) {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    if let Ok(val) = store.get(FALLBACK_T3_TOKEN_SECRET) {
        let trimmed = val.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }
    None
}

fn maybe_spawn_transport_probe(
    daemon: &Arc<LocalDaemonInner>,
    session_id: &str,
    hints: TransportHints,
) {
    if !daemon.config.auto_detect_transports {
        return;
    }
    if daemon.current_transport_priority(session_id) >= PRIORITY_HERDR {
        return;
    }

    let mut node_file =
        read_node_file_for_state_dir(&daemon.node.config().state_dir).unwrap_or_default();
    let node_t3 = node_file.t3.take().unwrap_or_default();

    // Check whether we have any plausible transport signal worth probing:
    // - explicit Herdr terminal ID, T3 dir/url/harness, OpenClaw harness, or Codex harness/args
    // - OR T3 statev2.sqlite exists on disk (honoring node.json `"t3.baseDir"`!)
    let default_t3_base = daemon
        .config
        .t3_default_base_dir
        .clone()
        .or_else(|| node_t3.base_dir.clone())
        .unwrap_or_else(default_t3_base_dir);
    let t3_base_candidate = hints.t3_base_dir.clone().unwrap_or(default_t3_base);
    let has_t3_db = t3_state_db_path(&t3_base_candidate).is_file();

    let is_openclaw =
        hints.harness == Some(HarnessKind::Openclaw) || session_id.starts_with("openclaw:");
    let is_codex = hints.harness == Some(HarnessKind::Codex) || session_id.starts_with("codex:");

    if !hints.has_any_hint() && !has_t3_db && !is_openclaw && !is_codex {
        return;
    }

    let (tx, rx) = watch::channel(false);
    {
        let mut probes = daemon
            .pending_probes
            .lock()
            .expect("pending_probes lock poisoned");
        if probes.contains_key(session_id) {
            return;
        }
        probes.insert(session_id.to_string(), rx);
    }

    let daemon_arc = Arc::clone(daemon);
    let sid = session_id.to_string();
    tokio::spawn(async move {
        struct ProbeGuard {
            daemon: Arc<LocalDaemonInner>,
            session_id: String,
            tx: watch::Sender<bool>,
        }
        impl Drop for ProbeGuard {
            fn drop(&mut self) {
                let _ = self.tx.send(true);
                let mut probes = self
                    .daemon
                    .pending_probes
                    .lock()
                    .expect("pending_probes lock poisoned");
                probes.remove(&self.session_id);
            }
        }
        let _guard = ProbeGuard {
            daemon: Arc::clone(&daemon_arc),
            session_id: sid.clone(),
            tx,
        };

        let mut attached = false;

        // Priority 1: Herdr (`HC_TERMINAL_ID` verified live via `hc get --json`;
        // skipped for explicit OpenClaw sessions so ambient shell HC_TERMINAL_ID never overrides Gateway hooks)
        if !is_openclaw {
            if let Some(ref tid) = hints.herdr_terminal_id {
                let hc_bin = daemon_arc
                    .config
                    .herdr_bin
                    .as_deref()
                    .unwrap_or(DEFAULT_HERDR_BIN);
                match probe_herdr_terminal_detailed(hc_bin, tid).await {
                    HerdrProbeOutcome::LiveAgent(target) => {
                        let pin_matches = match (hints.herdr_created_ms, target.created_ms) {
                            (Some(expected), Some(actual)) => expected == actual,
                            _ => true,
                        };
                        if pin_matches {
                            daemon_arc.clear_herdr_bare_shell_rejection(&sid);
                            let mut herdr_patch = Map::new();
                            herdr_patch.insert("herdrTerminalId".into(), json!(target.terminal_id));
                            if let Some(created_ms) = target.created_ms {
                                herdr_patch.insert("herdrCreatedMs".into(), json!(created_ms));
                            }
                            if let Some(pid) = target.pid {
                                herdr_patch.insert("herdrPid".into(), json!(pid));
                            }
                            if let Some(ref app) = target.app {
                                herdr_patch.insert("herdrApp".into(), json!(app));
                            }
                            let _ = daemon_arc.merge_session_backend_and_index(
                                &sid,
                                &herdr_patch,
                                daemon_arc.current_time_ms(),
                            );
                            if daemon_arc.attach_transport_if_higher_priority(
                                &sid,
                                Arc::new(HerdrTransport::new(target)),
                                PRIORITY_HERDR,
                            ) {
                                attached = true;
                            }
                        }
                    }
                    HerdrProbeOutcome::BareShell { terminal_id, .. } => {
                        daemon_arc.record_herdr_bare_shell_rejection(&sid, &terminal_id);
                        daemon_arc.bump_ui_rev();
                    }
                    HerdrProbeOutcome::Unavailable => {
                        daemon_arc.clear_herdr_bare_shell_rejection(&sid);
                    }
                }
            }
        }

        // Priority 2: T3 Code (read-only `statev2.sqlite` match + reachable authenticated T3 server;
        // honors explicit hints/flags > LocalDaemonConfig defaults > node.json `"t3"` block!)
        if !attached && daemon_arc.current_transport_priority(&sid) < PRIORITY_T3 && has_t3_db {
            let raw_id = hints
                .t3_thread_id
                .as_deref()
                .or(hints.codex_thread_id.as_deref())
                .unwrap_or_else(|| sid.split_once(':').map(|(_, r)| r).unwrap_or(sid.as_str()));
            let resolved_t3_thread = if (hints.harness == Some(HarnessKind::T3)
                || hints.t3_thread_id.is_some())
                && verify_t3_thread_exists(raw_id, &t3_base_candidate)
            {
                Some(raw_id.to_string())
            } else {
                resolve_t3_thread_by_provider_session(raw_id, &t3_base_candidate).ok()
            };

            if let Some(thread_id) = resolved_t3_thread {
                let raw_url = hints
                    .t3_url
                    .as_deref()
                    .or(daemon_arc.config.t3_default_url.as_deref())
                    .or(node_t3.url.as_deref())
                    .unwrap_or(DEFAULT_T3_URL);
                if let Ok(origin) = normalize_t3_server_url_with_remote(
                    raw_url,
                    node_t3.allow_remote.unwrap_or(false),
                ) {
                    let token =
                        read_t3_secret_for_node(&daemon_arc.node, node_t3.token_secret.as_deref());
                    let probe = probe_t3_server_with_remote(
                        &origin,
                        token.as_deref(),
                        node_t3.allow_remote.unwrap_or(false),
                        DEFAULT_PROBE_TIMEOUT,
                    )
                    .await;
                    // X3 (P1): Attach T3Transport ONLY when a bearer token is present AND the T3
                    // server confirmed authentication succeeded (`authenticated == Some(true)`).
                    if token.is_some() && probe.is_authenticated() {
                        let mut target = T3Target::new(thread_id, origin);
                        target.base_dir = Some(t3_base_candidate.clone());
                        if let Some(ref custom_sec) = node_t3.token_secret {
                            if is_allowed_t3_token_secret(custom_sec) {
                                target.token_secret = Some(custom_sec.clone());
                            }
                        }
                        target.state_dir = Some(daemon_arc.node.config().state_dir.clone());
                        target.secret_backend = daemon_arc.node.config().secret_backend;
                        if daemon_arc.attach_transport_if_higher_priority(
                            &sid,
                            Arc::new(
                                T3Transport::new(target)
                                    .with_allow_remote(node_t3.allow_remote.unwrap_or(false)),
                            ),
                            PRIORITY_T3,
                        ) {
                            attached = true;
                        }
                    }
                }
            }
        }

        // Priority 3: OpenClaw Gateway Webhook Push (`X2`: fail-closed on missing SecretStore token
        // or unreachable `/hooks/*` endpoint; defaults to `POST /hooks/wake` targeting this
        // session's exact `(agentId, sessionKey)` and honors optional `node.json` `"openclaw"`
        // block, including `enabled: false` / `deliveryMode: "inbox"` opt-out).
        if !attached
            && is_openclaw
            && daemon_arc.current_transport_priority(&sid) < PRIORITY_OPENCLAW
        {
            let oc_cfg = node_file
                .openclaw
                .map(OpenClawNodeConfig::from_node_file)
                .unwrap_or_default();
            if oc_cfg.gateway_push_enabled() {
                let mut target = oc_cfg.to_target();
                target.state_dir = Some(daemon_arc.node.config().state_dir.clone());
                target.secret_backend = daemon_arc.node.config().secret_backend;
                let sess_opt = daemon_arc
                    .node
                    .db()
                    .local()
                    .get_session(&sid)
                    .ok()
                    .flatten();
                target.handle = sess_opt.as_ref().and_then(|s| s.handle.clone());

                let session_key = hints
                    .openclaw_session_key
                    .clone()
                    .or_else(|| {
                        sess_opt
                            .as_ref()
                            .and_then(|s| {
                                extract_backend_str(&s.backend_json, "openclawSessionKey")
                            })
                            .and_then(|raw| {
                                let stripped = raw.strip_prefix("openclaw:").unwrap_or(&raw);
                                validate_openclaw_session_key(stripped).ok()
                            })
                    })
                    .or_else(|| {
                        let suffix = sid.strip_prefix("openclaw:")?;
                        suffix
                            .starts_with("agent:")
                            .then(|| validate_openclaw_session_key(suffix).ok())
                            .flatten()
                    });
                if let Some(ref sk) = session_key {
                    target.session_key = Some(sk.clone());
                }

                let resolved_agent_id = hints
                    .openclaw_agent_id
                    .clone()
                    .or_else(|| {
                        sess_opt
                            .as_ref()
                            .and_then(|s| extract_backend_str(&s.backend_json, "openclawAgentId"))
                    })
                    .or_else(|| {
                        session_key
                            .as_deref()
                            .and_then(parse_openclaw_agent_id_from_session_key)
                    });
                if let Some(aid) = resolved_agent_id {
                    target.agent_id = aid;
                }

                let probe = probe_openclaw_gateway(&target, DEFAULT_OPENCLAW_PROBE_TIMEOUT).await;
                if probe.ok
                    && daemon_arc.attach_transport_if_higher_priority(
                        &sid,
                        Arc::new(OpenClawTransport::new(target)),
                        PRIORITY_OPENCLAW,
                    )
                {
                    attached = true;
                }
            }
        }

        // Priority 4: Codex Queue (`X8`: explicit `--thread`/`--remote`/`--resume`/`CODEX_REMOTE`
        // OR automatic zero-flag attachment for Codex UUID sessions when `codex` binary is available
        // and rollout JSONL verifies cleanly when `$CODEX_HOME/sessions/` exists).
        if !attached && daemon_arc.current_transport_priority(&sid) < PRIORITY_CODEX_QUEUE {
            let candidate_thread = hints
                .codex_thread_id
                .as_deref()
                .or_else(|| sid.strip_prefix("codex:"))
                .map(str::trim)
                .filter(|s| !s.is_empty());

            if let Some(thread_id) = candidate_thread {
                // A verified MCP call can trigger another probe after the hook's probe
                // finishes. Its connection hints may omit CODEX_HOME, so retain the
                // hook's persisted rollout location instead of inspecting the daemon's home.
                let codex_home = hints.codex_home.clone().or_else(|| {
                    daemon_arc
                        .node
                        .db()
                        .local()
                        .get_session(&sid)
                        .ok()
                        .flatten()
                        .and_then(|session| {
                            TransportHints::from_session_backend(&sid, &session.backend_json)
                                .codex_home
                        })
                });
                let codex_bin = daemon_arc
                    .config
                    .codex_bin
                    .as_deref()
                    .unwrap_or(DEFAULT_CODEX_BIN);

                let allow_attach = if hints.explicit_codex_queue {
                    true
                } else if is_codex
                    && is_valid_codex_uuid(thread_id)
                    && codex_queue_supported(codex_bin).await
                {
                    let codex_home = codex_home.clone().unwrap_or_else(default_codex_home);
                    if hints.codex_remote.is_none() && codex_home.join("sessions").is_dir() {
                        verify_codex_rollout_thread(&codex_home, thread_id)
                    } else {
                        true
                    }
                } else {
                    false
                };

                if allow_attach {
                    let mut target = CodexQueueTarget::new(thread_id.to_string())
                        .with_bin(codex_bin.to_string())
                        .with_resume(
                            hints.codex_resume || daemon_arc.config.delivery_retry.codex_resume,
                        );
                    if let Some(ref home) = codex_home {
                        target = target.with_codex_home(home.clone());
                    }
                    if let Some(ref remote) = hints.codex_remote {
                        target = target.with_remote(remote.clone());
                    }
                    if build_codex_queue_args(&target, "probe").is_ok()
                        && daemon_arc.attach_transport_if_higher_priority(
                            &sid,
                            Arc::new(CodexQueueTransport::new(target)),
                            PRIORITY_CODEX_QUEUE,
                        )
                    {
                        attached = true;
                    }
                }
            }
        }

        if attached {
            daemon_arc.flush_session(&sid).await;
        }
    });
}

fn handle_call_start(daemon: &LocalDaemonInner, packet: &Map<String, Value>) -> Value {
    let harness_str = packet
        .get("harness")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let Ok(harness) = harness_str.parse::<HarnessKind>() else {
        return json!({ "ok": false, "error": "invalid_call_start" });
    };
    let Some(session_id) = packet
        .get("sessionId")
        .and_then(Value::as_str)
        .filter(|s| is_valid_session_id(s))
    else {
        return json!({ "ok": false, "error": "invalid_call_start" });
    };
    let Some(tool) = packet.get("tool").and_then(Value::as_str) else {
        return json!({ "ok": false, "error": "invalid_call_start" });
    };

    if let Err(err) = daemon.verify_optional_session_token(session_id, packet) {
        return json!({ "ok": false, "error": err });
    }

    let call_id = packet
        .get("callId")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);

    let hints = TransportHints::from_packet(packet, Some(harness));
    let patch = hints.backend_patch(Some(harness));
    let backend_json = serde_json::to_string(&Value::Object(patch.clone()))
        .unwrap_or_else(|_| format!("{{\"kind\":\"{}\"}}", harness.as_str()));
    if let Err(e) =
        daemon.merge_session_backend_and_index(session_id, &patch, daemon.current_time_ms())
    {
        return json!({ "ok": false, "error": e.to_string() });
    }
    daemon.clear_openclaw_session_missing(session_id);
    daemon.clear_lazy_hydrate_cooldown(session_id);
    daemon
        .hook_registered_sessions
        .lock_state("hook_registered_sessions lock poisoned")
        .insert(session_id.to_string());
    daemon.mark_session_active(session_id, harness);
    daemon.bump_ui_rev();

    match daemon.calls.start_call(
        StartCallInput {
            harness,
            session_id: session_id.to_string(),
            tool: tool.to_string(),
            call_id,
            backend_json: Some(backend_json),
            ttl_ms: None,
        },
        daemon.current_time_ms(),
    ) {
        Ok(reg) => {
            let mut result = Map::new();
            result.insert("callToken".into(), json!(reg.token));
            result.insert("sessionId".into(), json!(reg.session_id));
            json!({
                "ok": true,
                "result": Value::Object(result)
            })
        }
        Err(msg) => json!({ "ok": false, "error": msg }),
    }
}

/// Strict, fail-closed session resolver for OpenClaw hooks (`before_prompt_build`, `agent_end`).
///
/// NEVER falls back across sessions (not even when only 1 `openclaw:*` session exists!) so an
/// unrelated OpenClaw thread, subagent, or cron run can NEVER drain or read another OpenClaw
/// session's mailbox.
fn resolve_openclaw_drain_session(
    daemon: &LocalDaemonInner,
    session_id: &str,
    packet: &Map<String, Value>,
) -> Option<String> {
    let db = daemon.node.db();
    if db.local().get_session(session_id).ok().flatten().is_some() {
        return Some(session_id.to_string());
    }

    let is_openclaw_hook = packet
        .get("harness")
        .and_then(Value::as_str)
        .is_some_and(|h| h.eq_ignore_ascii_case("openclaw"));
    if !is_openclaw_hook {
        return None;
    }

    let raw_sk = packet
        .get("openclawSessionKey")
        .or_else(|| packet.get("sessionKey"))
        .and_then(Value::as_str)
        .map(|s| s.strip_prefix("openclaw:").unwrap_or(s));
    if let Some(raw) = raw_sk {
        let Ok(sk) = validate_openclaw_session_key(raw) else {
            return None;
        };
        if let Ok(canonical_sid) = canonical_openclaw_session_id(&sk) {
            if db
                .local()
                .get_session(&canonical_sid)
                .ok()
                .flatten()
                .is_some()
            {
                return Some(canonical_sid);
            }
        }
        let matching_sk: Vec<_> = db
            .local()
            .list_sessions()
            .unwrap_or_default()
            .into_iter()
            .filter(|s| {
                s.id.starts_with("openclaw:")
                    && extract_backend_str(&s.backend_json, "openclawSessionKey").as_deref()
                        == Some(sk.as_str())
            })
            .collect();
        if matching_sk.len() == 1 {
            return Some(matching_sk[0].id.clone());
        }
        // Fail closed: an explicit `sessionKey` that does not match any registered OpenClaw
        // session MUST NEVER fall back to another session!
        return None;
    }

    if let Some(oc_sid) = packet
        .get("openclawSessionId")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= 200 && !s.bytes().any(|b| b <= 0x20 || b == 0x7f))
    {
        let matching_sid: Vec<_> = db
            .local()
            .list_sessions()
            .unwrap_or_default()
            .into_iter()
            .filter(|s| {
                s.id.starts_with("openclaw:")
                    && extract_backend_str(&s.backend_json, "openclawSessionId").as_deref()
                        == Some(oc_sid)
            })
            .collect();
        if matching_sid.len() == 1 {
            return Some(matching_sid[0].id.clone());
        }
    }

    None
}

async fn handle_session_idle(daemon: &Arc<LocalDaemonInner>, packet: &Map<String, Value>) -> Value {
    let Some(session_id) = packet
        .get("sessionId")
        .and_then(Value::as_str)
        .filter(|s| is_valid_session_id(s))
    else {
        return json!({ "ok": false, "error": "invalid_session" });
    };

    let Some(target_session_id) = resolve_openclaw_drain_session(daemon, session_id, packet) else {
        if let Err(err) = daemon.verify_optional_session_token(session_id, packet) {
            return json!({ "ok": false, "error": err });
        }
        return json!({ "ok": true, "result": {} });
    };

    if let Err(err) = daemon.verify_optional_session_token(&target_session_id, packet) {
        return json!({ "ok": false, "error": err });
    }
    daemon.clear_openclaw_session_missing(&target_session_id);
    daemon.mark_session_idle(&target_session_id);
    // Any Queue batch deferred while the session was Active can now flush immediately to L2!
    let flush_daemon = Arc::clone(daemon);
    let flush_sid = target_session_id.clone();
    tokio::spawn(async move {
        let _ = flush_daemon.flush_session(&flush_sid).await;
    });
    json!({ "ok": true, "result": { "sessionId": target_session_id, "idle": true } })
}

async fn handle_mailbox_drain(
    daemon: &Arc<LocalDaemonInner>,
    packet: &Map<String, Value>,
) -> Value {
    let Some(session_id) = packet
        .get("sessionId")
        .and_then(Value::as_str)
        .filter(|s| is_valid_session_id(s))
    else {
        return json!({ "ok": false, "error": "invalid_session" });
    };

    let Some(target_session_id) = resolve_openclaw_drain_session(daemon, session_id, packet) else {
        // Still verify optional sessionToken if caller supplied one (fail closed on bad token).
        if let Err(err) = daemon.verify_optional_session_token(session_id, packet) {
            return json!({ "ok": false, "error": err });
        }
        return json!({ "ok": true, "result": { "items": [] } });
    };

    if let Err(err) = daemon.verify_optional_session_token(&target_session_id, packet) {
        return json!({ "ok": false, "error": err });
    }
    daemon.clear_openclaw_session_missing(&target_session_id);

    let scope = drain_scope_from_packet(packet);
    let mark_idle_if_empty = packet
        .get("markIdleIfEmpty")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let explicit_harness = packet
        .get("harness")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<HarnessKind>().ok());
    let inferred_harness =
        LocalDaemonInner::infer_session_harness(&target_session_id, explicit_harness);

    if matches!(scope, DrainScope::MidTurn | DrainScope::PreTurn) {
        if let Some(h) = inferred_harness {
            daemon.mark_session_active(&target_session_id, h);
        }
    }

    match daemon
        .build_batch_for_session_scoped(&target_session_id, scope)
        .await
    {
        None => {
            if scope != DrainScope::MidTurn {
                daemon.cancel_hold_retry(&target_session_id);
            }
            if scope == DrainScope::TurnBoundary {
                daemon.reset_midturn_digest_timer(&target_session_id);
            }
            if mark_idle_if_empty {
                daemon.mark_session_idle(&target_session_id);
            }
            json!({ "ok": true, "result": { "items": [] } })
        }
        Some(built) => {
            let batch = built.batch;
            if built.is_midturn_queue_reminder {
                daemon
                    .record_midturn_digest_timestamp(&target_session_id, daemon.current_time_ms());
                daemon.mark_surfaced_quarantine_notices(
                    &target_session_id,
                    &batch.quarantined_receipts,
                );
            } else {
                daemon.commit_delivered_batch(&target_session_id, &batch);
                if scope == DrainScope::MidTurn {
                    daemon.record_midturn_digest_timestamp(
                        &target_session_id,
                        daemon.current_time_ms(),
                    );
                } else if scope == DrainScope::TurnBoundary {
                    daemon.reset_midturn_digest_timer(&target_session_id);
                }
            }
            if scope == DrainScope::TurnBoundary {
                if let Some(h) = inferred_harness {
                    daemon.mark_session_active(&target_session_id, h);
                }
            }
            json!({
                "ok": true,
                "result": {
                    "items": [{
                        "text": batch.rendered,
                        "notifyOnly": batch.notify_only,
                        "mutedCount": batch.muted_count,
                        "receiptIds": batch.receipt_ids,
                    }]
                }
            })
        }
    }
}

async fn handle_session_status(
    daemon: &Arc<LocalDaemonInner>,
    packet: &Map<String, Value>,
) -> Value {
    let Some(session_id) = packet.get("sessionId").and_then(Value::as_str) else {
        return json!({ "ok": false, "error": "invalid_session" });
    };
    daemon.wait_for_pending_probe(session_id).await;
    daemon.reconcile_session_inbox(session_id).await;
    let (sess, pending, muted, policy) = {
        let db = daemon.node.db();
        let sess = db.local().get_session(session_id).ok().flatten();
        let pending = daemon.effective_pending_count(&db, session_id);
        let muted = muted_count(&db, session_id).unwrap_or(0);
        let policy = daemon.delivery.policy(&db, session_id).unwrap_or_default();
        (sess, pending, muted, policy)
    };
    let enrolled = sess.as_ref().and_then(|s| s.handle.as_ref()).is_some();
    let transport_kind = daemon.active_transport_kind(session_id);
    json!({
        "ok": true,
        "result": {
            "id": session_id,
            "enrolled": enrolled,
            "handle": sess.and_then(|s| s.handle),
            "pending": pending,
            "muted": muted,
            "deliveryMode": policy.default_mode.as_str(),
            "focusMode": policy.focus_mode,
            "hasLiveTransport": transport_kind.is_some(),
            "transportKind": transport_kind,
        }
    })
}

async fn handle_daemon_status(daemon: &Arc<LocalDaemonInner>) -> Value {
    let session_ids: Vec<String> = {
        let db = daemon.node.db();
        db.local()
            .list_sessions()
            .unwrap_or_default()
            .into_iter()
            .map(|s| s.id)
            .collect()
    };
    for sid in &session_ids {
        daemon.reconcile_session_inbox(sid).await;
    }

    let (sessions_json, peers_json, total_muted, total_quarantined) = {
        let db = daemon.node.db();
        let sessions = db.local().list_sessions().unwrap_or_default();
        let mut muted_sum = 0usize;
        let mut sess_arr = Vec::with_capacity(sessions.len());
        for s in sessions {
            let m = muted_count(&db, &s.id).unwrap_or(0);
            let p = daemon.effective_pending_count(&db, &s.id);
            muted_sum += m;
            let transport_kind = daemon.active_transport_kind(&s.id);
            sess_arr.push(json!({
                "id": s.id,
                "handle": s.handle,
                "pending": p,
                "muted": m,
                "hasLiveTransport": transport_kind.is_some(),
                "transportKind": transport_kind,
            }));
        }
        let peers: Vec<Value> = db
            .peers()
            .list_peers(None)
            .unwrap_or_default()
            .into_iter()
            .map(|p| {
                json!({
                    "peerId": p.peer_id,
                    "profile": p.profile.as_str(),
                    "status": p.status.as_str(),
                })
            })
            .collect();
        let quarantined = db
            .local()
            .list_quarantined(None, 10_000)
            .map(|v| v.len())
            .unwrap_or(0);
        (sess_arr, peers, muted_sum, quarantined)
    };

    json!({
        "ok": true,
        "result": {
            "nodeId": daemon.node.node_id().as_str(),
            "version": daemon.node.config().hyphae_version,
            "binaryVersion": env!("CARGO_PKG_VERSION"),
            "pid": std::process::id(),
            "profile": daemon.node.config().profile,
            "socketPath": daemon.socket_path.display().to_string(),
            "sessions": sessions_json,
            "peers": peers_json,
            "mutedCount": total_muted,
            "quarantinedCount": total_quarantined,
        }
    })
}

async fn handle_peers_reload(daemon: &Arc<LocalDaemonInner>) -> Value {
    let custom = daemon
        .peers_reloader
        .lock_state("peers_reloader lock poisoned")
        .clone();

    let outcome = match custom {
        Some(reloader) => reloader.reload_peers().await,
        None => Ok(daemon
            .node
            .reconcile_peers(DEFAULT_PEERS_RELOAD_TIMEOUT)
            .await),
    };

    match outcome {
        Ok(report) => {
            daemon.bump_ui_rev();
            let result = json!({
                "reloaded": true,
                "activePeers": report.active_peers,
                "added": report.added,
                "removed": report.removed,
                "connectedPeers": report.connected_peers,
                "warnings": report.warnings,
            });
            json!({
                "ok": true,
                "reloaded": true,
                "activePeers": report.active_peers,
                "added": report.added,
                "removed": report.removed,
                "result": result,
            })
        }
        Err(err) => json!({
            "ok": false,
            "reloaded": false,
            "error": err,
        }),
    }
}

fn parse_rules_arg(args: &Map<String, Value>) -> Result<Vec<DeliveryRule>, (String, String)> {
    let Some(raw) = args.get("rules") else {
        return Ok(Vec::new());
    };
    let Value::Array(items) = raw else {
        return Err(invalid_request(
            "Expected 'rules' to be an array of { target, delivery }",
        ));
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let rule: DeliveryRule = serde_json::from_value(item.clone())
            .map_err(|e| invalid_request(format!("Invalid delivery rule: {e}")))?;
        rule.validate().map_err(delivery_err_tuple)?;
        out.push(rule);
    }
    Ok(out)
}

fn parse_inbox_filter_arg(raw: Option<&Value>) -> Result<InboxFilter, (String, String)> {
    let Some(val) = raw else {
        return Ok(InboxFilter::default());
    };
    if val.is_null() {
        return Ok(InboxFilter::default());
    }
    let Value::Object(map) = val else {
        return Err(("invalid_filter".into(), "Expected filter object".into()));
    };
    let from = map
        .get("from")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let node = map
        .get("node")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let topic = map
        .get("topic")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let channel = map
        .get("channel")
        .and_then(Value::as_str)
        .map(ToString::to_string);
    let kind = match map.get("kind").and_then(Value::as_str) {
        Some(k) => Some(MailboxKind::parse(k).map_err(store_err_tuple)?),
        None => None,
    };
    let ce_filters = match map.get("ceFilters").or_else(|| map.get("filters")) {
        None | Some(Value::Null) => Vec::new(),
        Some(fval) => hyp_proto::filter::validate_filters(fval)
            .map_err(|e| ("invalid_filter".into(), e.to_string()))?,
    };
    Ok(InboxFilter {
        from,
        node,
        topic,
        channel,
        kind,
        ce_filters,
    })
}

fn node_err_tuple(err: hyp_node::engine::NodeError) -> (String, String) {
    let problem = err.to_problem_details();
    (problem.error, problem.detail.unwrap_or(problem.title))
}

fn invalid_request(message: impl Into<String>) -> (String, String) {
    ("invalid_request".into(), message.into())
}

fn store_err_tuple(err: hyp_store::StoreError) -> (String, String) {
    ("store_error".into(), err.to_string())
}

fn delivery_err_tuple(err: hyp_node::delivery::DeliveryError) -> (String, String) {
    ("delivery_error".into(), err.to_string())
}

fn sanitize_notice_label(raw: &str) -> String {
    let clean: String = raw
        .chars()
        .filter(|c| !c.is_control())
        .map(|c| match c {
            '[' => '(',
            ']' => ')',
            other => other,
        })
        .take(128)
        .collect();
    let trimmed = clean.trim();
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed.to_string()
    }
}

fn parse_human_auth_meta(raw: &str) -> Option<(Option<String>, Option<String>)> {
    let val = serde_json::from_str::<Value>(raw).ok()?;
    let obj = val.as_object()?;
    let human_id = obj
        .get("humanId")
        .or_else(|| obj.get("human_id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);
    let kid = obj
        .get("kid")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);
    Some((human_id, kid))
}

fn handle_gate_reload_rpc(daemon: &LocalDaemonInner) -> Value {
    match daemon.reload_gate() {
        Ok((enabled, filter_count, require_signed_policy, rev)) => json!({
            "ok": true,
            "result": {
                "reloaded": true,
                "enabled": enabled,
                "filterCount": filter_count,
                "requireSignedPolicy": require_signed_policy,
                "rev": rev,
            }
        }),
        Err(err) => json!({
            "ok": false,
            "error": err,
        }),
    }
}

/// Re-publishes human-approved `local-ingest:<topic>` mailbox entries onto `local.<topic>`,
/// delivers matched local EventStore batches directly into subscribed local sessions (marked
/// gate-approved so they are never re-quarantined), acknowledges the staging rows, and wakes
/// every matched subscriber (`G8`).
async fn fanout_approved_local_ingest(
    daemon: &Arc<LocalDaemonInner>,
    staging_sid: &str,
    topic: &str,
    explicit_receipt: Option<&str>,
) -> bool {
    let approved_entries: Vec<MailboxEntry> = {
        let db = daemon.node.db();
        if let Some(r) = explicit_receipt {
            match db.local().get_mailbox_entry(r) {
                Ok(Some(entry))
                    if entry.session_id == staging_sid
                        && entry.gate_state == GateState::Pending
                        && entry.reviewed_at.is_some() =>
                {
                    vec![entry]
                }
                _ => Vec::new(),
            }
        } else {
            db.local()
                .peek_inbox_with_visibility(staging_sid, 100, MailboxVisibility::GateCleared)
                .unwrap_or_default()
        }
    };

    if approved_entries.is_empty() {
        return false;
    }

    let my_id = daemon.node.node_id().to_string();
    let qualified_topic = format!("local.{topic}");
    let mut sessions_to_wake: HashSet<String> = HashSet::new();

    for entry in approved_entries {
        let now = daemon.current_time_ms();
        let event_type = {
            let db = daemon.node.db();
            db.local()
                .query_gate_audit(&GateAuditQuery {
                    decision: None,
                    direction: None,
                    session_id: Some(staging_sid.to_string()),
                    since_ms: None,
                    until_ms: None,
                    limit: Some(50),
                })
                .ok()
                .and_then(|rows| {
                    rows.into_iter()
                        .find(|a| a.receipt_id.as_deref() == Some(entry.receipt.as_str()))
                        .and_then(|a| a.event_type)
                })
                .filter(|t| !t.trim().is_empty())
                .unwrap_or_else(|| "to.hyphae.local.event.v1".to_string())
        };

        let ce = if let Ok(parsed_ce) = serde_json::from_str::<ProtoCloudEvent>(&entry.text) {
            parsed_ce
        } else {
            let data_val = match serde_json::from_str::<Value>(&entry.text) {
                Ok(v @ Value::Object(_)) => v,
                _ => json!({ "text": entry.text }),
            };
            let mut extensions = BTreeMap::new();
            if let Some(ref tp) = entry.traceparent {
                extensions.insert(EXT_TRACEPARENT.to_string(), Value::String(tp.clone()));
            }
            ProtoCloudEvent {
                specversion: "1.0".to_string(),
                id: entry.item_id.clone(),
                source: if entry.source.trim().is_empty() {
                    format!("local:{topic}")
                } else {
                    entry.source.clone()
                },
                event_type,
                datacontenttype: Some(CONTENT_TYPE_JSON.to_string()),
                dataschema: None,
                subject: Some(topic.to_string()),
                time: Some(format_rfc3339_millis(entry.received_at)),
                data: Some(data_val),
                data_base64: None,
                extensions,
            }
        };

        let approved_event_id = ce.id.clone();
        if daemon
            .node
            .publish_event(&qualified_topic, ce)
            .await
            .is_err()
        {
            continue;
        }

        // G8: Flush matched local subscriber batches into their mailboxes, marking ONLY the
        // exact human-approved event (`ev.id == approved_event_id`) as gate-approved — NEVER
        // blanket-marking unrelated due batches or sibling events on the same topic!
        {
            let db = daemon.node.db();
            let _ = db.events().tick(now);

            let remote_peers: HashSet<String> = db
                .peers()
                .list_peers(None)
                .unwrap_or_default()
                .into_iter()
                .map(|p| p.peer_id)
                .filter(|pid| pid != &my_id)
                .collect();

            let local_subscribers: HashSet<String> = db
                .events()
                .list_subscriptions(None)
                .unwrap_or_default()
                .into_iter()
                .filter(|s| {
                    (s.origin_node == my_id || s.origin_node == "local")
                        && s.topic == topic
                        && !remote_peers.contains(&s.subscriber)
                })
                .map(|s| s.subscriber)
                .collect();

            for subscriber in local_subscribers {
                let mut skipped_batches: HashSet<String> = HashSet::new();
                for _ in 0..128 {
                    let due = db
                        .events()
                        .due_batches(&subscriber, |bid| skipped_batches.contains(bid), now)
                        .unwrap_or_default();
                    if due.is_empty() {
                        break;
                    }
                    let mut progressed = false;
                    let mut saw_approved = false;
                    for local_batch in due {
                        if (local_batch.origin_node != my_id && local_batch.origin_node != "local")
                            || local_batch.topic != topic
                        {
                            skipped_batches.insert(local_batch.id);
                            continue;
                        }
                        let kind = if local_batch.topic == "kv" {
                            MailboxKind::Kv
                        } else {
                            MailboxKind::Event
                        };
                        let mut approved_events = Vec::new();
                        let mut unrelated_events = Vec::new();
                        for ev in local_batch.events {
                            if ev.id == approved_event_id {
                                approved_events.push(ev);
                            } else {
                                unrelated_events.push(ev);
                            }
                        }

                        let mut queue_full = false;
                        let mut put_ok = false;

                        // 1. Deliver ONLY the exact approved event with `mark_mailbox_gate_approved`.
                        if !approved_events.is_empty() {
                            saw_approved = true;
                            let traceparent = approved_events
                                .first()
                                .and_then(|ev| ev.extensions.get(EXT_TRACEPARENT))
                                .cloned();
                            let item_id = if unrelated_events.is_empty() {
                                format!("batch:{}", local_batch.id)
                            } else {
                                format!("approved:{}:{}", local_batch.id, approved_event_id)
                            };
                            if let Ok(payload_text) = serde_json::to_string(&json!({
                                "batchId": local_batch.id,
                                "originNode": local_batch.origin_node,
                                "topic": local_batch.topic,
                                "events": approved_events,
                            })) {
                                match db.local().put_in_mailbox(
                                    &MailboxInsert {
                                        session_id: subscriber.clone(),
                                        origin_node: my_id.clone(),
                                        item_id,
                                        text: payload_text,
                                        kind,
                                        source: format!("local.{}", local_batch.topic),
                                        gate_state: GateState::Pending,
                                        gate_reason: None,
                                        traceparent,
                                    },
                                    now,
                                ) {
                                    Ok(MailboxPutResult::Stored { receipt: sub_rcpt }) => {
                                        let _ = db.local().mark_mailbox_gate_approved(
                                            &subscriber,
                                            &sub_rcpt,
                                            None,
                                            now,
                                        );
                                        sessions_to_wake.insert(subscriber.clone());
                                        put_ok = true;
                                    }
                                    Ok(MailboxPutResult::Duplicate) => {
                                        put_ok = true;
                                    }
                                    Ok(MailboxPutResult::QueueFull) => {
                                        queue_full = true;
                                    }
                                    Err(_) => {}
                                }
                            }
                        }

                        // 2. Any unrelated due events on the same topic stay UNSCREENED
                        //    (`reviewed_at = NULL`) so `reconcile_session_inbox` gates them normally!
                        if !unrelated_events.is_empty() && !queue_full {
                            let traceparent = unrelated_events
                                .first()
                                .and_then(|ev| ev.extensions.get(EXT_TRACEPARENT))
                                .cloned();
                            if let Ok(payload_text) = serde_json::to_string(&json!({
                                "batchId": local_batch.id,
                                "originNode": local_batch.origin_node,
                                "topic": local_batch.topic,
                                "events": unrelated_events,
                            })) {
                                match db.local().put_in_mailbox(
                                    &MailboxInsert {
                                        session_id: subscriber.clone(),
                                        origin_node: my_id.clone(),
                                        item_id: format!("batch:{}", local_batch.id),
                                        text: payload_text,
                                        kind,
                                        source: format!("local.{}", local_batch.topic),
                                        gate_state: GateState::Pending,
                                        gate_reason: None,
                                        traceparent,
                                    },
                                    now,
                                ) {
                                    Ok(MailboxPutResult::Stored { .. }) => {
                                        sessions_to_wake.insert(subscriber.clone());
                                        put_ok = true;
                                    }
                                    Ok(MailboxPutResult::Duplicate) => {
                                        put_ok = true;
                                    }
                                    Ok(MailboxPutResult::QueueFull) => {
                                        queue_full = true;
                                    }
                                    Err(_) => {}
                                }
                            }
                        }

                        if queue_full {
                            let _ = db.events().ack_batch(
                                &subscriber,
                                &local_batch.id,
                                &AckOutcome::Hold {
                                    reason: "local_inbox_full".to_string(),
                                    retry_after_ms: Some(5_000),
                                },
                                now,
                            );
                            skipped_batches.insert(local_batch.id);
                        } else if put_ok {
                            let _ = db.events().ack_batch(
                                &subscriber,
                                &local_batch.id,
                                &AckOutcome::Delivered,
                                now,
                            );
                            progressed = true;
                        } else {
                            skipped_batches.insert(local_batch.id);
                        }
                    }
                    if saw_approved || !progressed {
                        break;
                    }
                }
            }

            let _ = db
                .local()
                .acknowledge_inbox(staging_sid, &[entry.receipt.as_str()], now);
        }
    }

    let mut woken_any = false;
    for sub_sid in sessions_to_wake {
        // Explicit human approval (`hyp inbox approve` -> `inbox.wake`) bypasses active-turn
        // grace deferral so approved items wake subscribed sessions immediately.
        let (_, delivered) = daemon.flush_session_inner(&sub_sid, true).await;
        if delivered {
            woken_any = true;
        }
    }
    woken_any
}

/// Startup sweep fanning out any `local-ingest:<topic>` rows that were approved by a human
/// operator (`hyp inbox approve`) while the daemon was stopped (`G8`).
async fn sweep_approved_local_ingest_on_startup(daemon: &Arc<LocalDaemonInner>) {
    let staging_sessions = {
        let db = daemon.node.db();
        db.local()
            .list_approved_local_ingest_sessions()
            .unwrap_or_default()
    };
    for staging_sid in staging_sessions {
        if let Some(topic) = staging_sid.strip_prefix("local-ingest:") {
            if !topic.is_empty() {
                let _ = fanout_approved_local_ingest(daemon, &staging_sid, topic, None).await;
            }
        }
    }
}

async fn handle_inbox_wake_rpc(
    daemon: &Arc<LocalDaemonInner>,
    packet: &Map<String, Value>,
) -> Value {
    let explicit_sid = packet
        .get("sessionId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| is_valid_session_id(s))
        .map(ToString::to_string);
    let receipt = packet
        .get("receipt")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);

    let target_sid = if explicit_sid.is_some() {
        explicit_sid
    } else if let Some(ref r) = receipt {
        let db = daemon.node.db();
        db.local()
            .get_mailbox_entry(r)
            .ok()
            .flatten()
            .map(|e| e.session_id)
    } else {
        None
    };

    if let Some(ref r) = receipt {
        daemon
            .dismissed_receipts
            .lock_state("dismissed lock poisoned")
            .remove(r);
        daemon.clear_quarantine_notice(target_sid.as_deref(), r);
        if let Some(ref sid) = target_sid {
            let mut guard = daemon.item_meta.lock_state("item_meta lock poisoned");
            if let Some(map) = guard.get_mut(sid) {
                map.remove(r);
            }
        }
    }

    let mut woken = false;
    if let Some(ref sid) = target_sid {
        if let Some(topic) = sid.strip_prefix("local-ingest:") {
            if !topic.is_empty() {
                woken = fanout_approved_local_ingest(daemon, sid, topic, receipt.as_deref()).await;
            }
        } else {
            let has_pending = {
                let db = daemon.node.db();
                db.local().pending_count(sid).unwrap_or(0) > 0
            };
            if has_pending {
                let (_, delivered) = daemon.flush_session_inner(sid, true).await;
                woken = delivered;
            }
        }
    }

    let rev = daemon.bump_ui_rev();
    let (quarantined_remaining, quarantined_global) = {
        let db = daemon.node.db();
        let rem = db
            .local()
            .quarantined_count(target_sid.as_deref())
            .unwrap_or(0);
        let global = db.local().quarantined_count(None).unwrap_or(0);
        (rem, global)
    };

    json!({
        "ok": true,
        "result": {
            "woken": woken,
            "sessionId": target_sid,
            "quarantinedRemaining": quarantined_remaining,
            "quarantinedGlobal": quarantined_global,
            "rev": rev,
        }
    })
}

async fn handle_system_wake_rpc(
    daemon: &Arc<LocalDaemonInner>,
    packet: &Map<String, Value>,
) -> Value {
    const MAX_SLEPT_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
    let slept_ms: u64 = if let Some(raw) = packet.get("sleptMs") {
        let Some(ms) = raw.as_u64().filter(|&v| v <= MAX_SLEPT_MS) else {
            return json!({
                "ok": false,
                "error": "invalid_request",
                "message": "sleptMs must be a non-negative integer within 30 days",
            });
        };
        ms
    } else if let Some(raw) = packet.get("sleptSeconds") {
        let Some(secs) = raw
            .as_u64()
            .and_then(|s| s.checked_mul(1_000))
            .filter(|&v| v <= MAX_SLEPT_MS)
        else {
            return json!({
                "ok": false,
                "error": "invalid_request",
                "message": "sleptSeconds must be a non-negative integer within 30 days",
            });
        };
        secs
    } else {
        daemon
            .config
            .wake_recovery
            .min_sleep_seconds
            .max(1)
            .saturating_mul(1_000)
    };

    let report = daemon
        .handle_system_wake(Duration::from_millis(slept_ms))
        .await;
    json!({
        "ok": true,
        "result": report,
    })
}

// ============================================================================
// Fast Read-Only Summaries, Streaming `inspect.watch`, Session Controls &
// Debounced Atomic `<state_dir>/ui/state.json` Projector (v0.6.0)
// ============================================================================

fn parse_gate_trust_tier(raw: &str) -> Option<GateTrustTier> {
    match raw.trim() {
        "self" => Some(GateTrustTier::SelfHost),
        "human-verified" => Some(GateTrustTier::HumanVerified),
        "org" => Some(GateTrustTier::Org),
        "peer" => Some(GateTrustTier::Peer),
        "guest" => Some(GateTrustTier::Guest),
        "external-webhook" => Some(GateTrustTier::ExternalWebhook),
        "bridge" => Some(GateTrustTier::Bridge),
        _ => None,
    }
}

/// Gate-cleared wrapper around [`query_inbox_for_node`] guaranteeing that unscreened raw arrivals and
/// `Hold`-retained rows (`reviewed_at IS NULL AND human_auth_json IS NULL`) are NEVER returned
/// OR acknowledged by `hyp_inbox` while a `SecurityGatePipeline` is active (G3/G4).
fn query_inbox_gate_cleared(
    db: &hyp_store::NodeDb,
    local_node_id: &str,
    session_id: &str,
    query: &InboxQuery,
    now_ms: i64,
) -> Result<InboxQueryResult, DeliveryError> {
    let unscreened = db.local().list_unscreened_receipts(session_id, 10_000)?;
    if unscreened.is_empty() {
        return query_inbox_for_node(db, local_node_id, session_id, query, now_ms);
    }

    if !query.ids.is_empty() {
        let safe_ids: Vec<String> = query
            .ids
            .iter()
            .filter(|id| !unscreened.contains(id.as_str()))
            .cloned()
            .collect();
        if safe_ids.is_empty() {
            return Ok(InboxQueryResult {
                state: query.state,
                items: Vec::new(),
                next_cursor: None,
                has_more: false,
                total_matched: 0,
                unread_count: db
                    .local()
                    .pending_count_with_visibility(session_id, MailboxVisibility::GateCleared)?,
                muted_count: muted_count(db, session_id)?,
                acked_count: 0,
            });
        }
        let filtered_query = InboxQuery {
            ids: safe_ids,
            ..query.clone()
        };
        let mut res = query_inbox_for_node(db, local_node_id, session_id, &filtered_query, now_ms)?;
        res.unread_count = db
            .local()
            .pending_count_with_visibility(session_id, MailboxVisibility::GateCleared)?;
        return Ok(res);
    }

    // Collect all gate-cleared items matching the filter across pages without acknowledging
    // anything until unscreened/held items are stripped out.
    let requested_limit = query.limit.clamp(1, 50);
    let mut cleared_all: Vec<InboxItemView> = Vec::new();
    let mut cursor = query.cursor.clone();
    loop {
        let page_query = InboxQuery {
            state: query.state,
            filter: query.filter.clone(),
            cursor: cursor.clone(),
            limit: 50,
            summary_only: query.summary_only,
            ack: false,
            ids: Vec::new(),
        };
        let page = query_inbox_for_node(db, local_node_id, session_id, &page_query, now_ms)?;
        for item in page.items {
            if !unscreened.contains(&item.receipt) {
                cleared_all.push(item);
            }
        }
        if !page.has_more {
            break;
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }

    // Recompute exact total_matched across all gate-cleared items (if cursor was None,
    // `cleared_all.len()` is exact; if cursor was set, run one cursorless count only if needed,
    // or match `cleared_all.len()` when cursor is absent).
    let total_matched = if query.cursor.is_none() {
        cleared_all.len()
    } else {
        let mut count = 0usize;
        let mut c: Option<String> = None;
        loop {
            let scan_q = InboxQuery {
                state: query.state,
                filter: query.filter.clone(),
                cursor: c.clone(),
                limit: 50,
                summary_only: true,
                ack: false,
                ids: Vec::new(),
            };
            let p = query_inbox_for_node(db, local_node_id, session_id, &scan_q, now_ms)?;
            for it in p.items {
                if !unscreened.contains(&it.receipt) {
                    count += 1;
                }
            }
            if !p.has_more {
                break;
            }
            c = p.next_cursor;
            if c.is_none() {
                break;
            }
        }
        count
    };

    let has_more = cleared_all.len() > requested_limit;
    let page_items: Vec<InboxItemView> = cleared_all.into_iter().take(requested_limit).collect();
    let next_cursor = if has_more {
        page_items.last().map(|it| {
            let payload = json!({ "t": it.received_at, "r": it.receipt });
            let bytes = serde_json::to_vec(&payload).unwrap_or_default();
            URL_SAFE_NO_PAD.encode(bytes)
        })
    } else {
        None
    };

    let mut acked_count = 0usize;
    if query.ack {
        let to_ack: Vec<String> = page_items
            .iter()
            .filter(|it| it.state == InboxItemState::Unread)
            .map(|it| it.receipt.clone())
            .collect();
        if !to_ack.is_empty() {
            let refs: Vec<&str> = to_ack.iter().map(String::as_str).collect();
            acked_count = db.local().acknowledge_inbox(session_id, &refs, now_ms)?;
            record_delivered_receipts(db, session_id, &to_ack)?;
        }
    }

    let unread_count = db
        .local()
        .pending_count_with_visibility(session_id, MailboxVisibility::GateCleared)?;
    let muted_total = muted_count(db, session_id)?;

    Ok(InboxQueryResult {
        state: query.state,
        items: page_items,
        next_cursor,
        has_more,
        total_matched,
        unread_count,
        muted_count: muted_total,
        acked_count,
    })
}

async fn handle_session_focus(
    daemon: &Arc<LocalDaemonInner>,
    packet: &Map<String, Value>,
) -> Value {
    let sel = match SessionSelector::from_packet(packet) {
        Ok(s) => s,
        Err((code, msg)) => return json!({ "ok": false, "code": code, "error": msg }),
    };
    let Some(sess) = daemon.resolve_session(&sel) else {
        return json!({ "ok": false, "code": "not_found", "error": "Session not found" });
    };
    let Some(enabled) = packet
        .get("enabled")
        .or_else(|| packet.get("focusMode"))
        .and_then(Value::as_bool)
    else {
        return json!({
            "ok": false,
            "code": "invalid_request",
            "error": "Expected boolean 'enabled' (or 'focusMode')"
        });
    };
    let allow_vips = match packet
        .get("allowVips")
        .or_else(|| packet.get("focusAllowInterruptVips"))
    {
        None | Some(Value::Null) => None,
        Some(Value::Bool(b)) => Some(*b),
        Some(_) => {
            return json!({
                "ok": false,
                "code": "invalid_request",
                "error": "Expected boolean 'allowVips'"
            });
        }
    };

    let FocusChange {
        policy,
        unread,
        muted,
        rev,
    } = match daemon
        .set_session_focus(&sess.id, enabled, allow_vips, &[])
        .await
    {
        Ok(change) => change,
        Err((code, msg)) => return json!({ "ok": false, "code": code, "error": msg }),
    };

    json!({
        "ok": true,
        "result": {
            "sessionId": sess.id,
            "deliveryMode": policy.default_mode.as_str(),
            "focusMode": policy.focus_mode,
            "focusAllowInterruptVips": policy.focus_allow_interrupt_vips,
            "unread": unread,
            "muted": muted,
            "rev": rev,
        }
    })
}

enum MutePolicyUpdate<'a> {
    None,
    BestEffort(&'a str),
    Required(&'a str),
}

fn parse_mute_ttl(value: Option<&Value>) -> Result<Option<u64>, (String, String)> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .filter(|secs| (1..=MAX_MUTE_TTL_SECS).contains(secs))
            .map(Some)
            .ok_or_else(|| {
                invalid_request(format!(
                    "Expected integer ttlSeconds in 1..={MAX_MUTE_TTL_SECS}"
                ))
            }),
    }
}

fn handle_session_mute(daemon: &Arc<LocalDaemonInner>, packet: &Map<String, Value>) -> Value {
    let sel = match SessionSelector::from_packet(packet) {
        Ok(s) => s,
        Err((code, msg)) => return json!({ "ok": false, "code": code, "error": msg }),
    };
    let scope_str = match packet.get("scope") {
        None | Some(Value::Null) => "session",
        Some(Value::String(s)) => match s.trim() {
            "session" => "session",
            "connector" => "connector",
            other => {
                return json!({
                    "ok": false,
                    "code": "invalid_request",
                    "error": format!("Expected scope 'session' | 'connector', got '{other}'")
                });
            }
        },
        Some(_) => {
            return json!({
                "ok": false,
                "code": "invalid_request",
                "error": "Expected string 'scope'"
            });
        }
    };
    let resolved = daemon.resolve_session(&sel);
    if scope_str == "session" && resolved.is_none() {
        return json!({ "ok": false, "code": "not_found", "error": "Session not found" });
    }
    let Some(raw_pattern) = packet
        .get("pattern")
        .or_else(|| packet.get("source"))
        .or_else(|| packet.get("target"))
        .and_then(Value::as_str)
    else {
        return json!({
            "ok": false,
            "code": "invalid_request",
            "error": "Expected string 'source' or 'pattern'"
        });
    };
    let pattern = match validate_control_pattern(raw_pattern) {
        Ok(p) => p,
        Err((code, msg)) => return json!({ "ok": false, "code": code, "error": msg }),
    };

    let ttl_seconds = match parse_mute_ttl(packet.get("ttlSeconds")) {
        Ok(ttl) => ttl,
        Err((code, msg)) => return json!({ "ok": false, "code": code, "error": msg }),
    };
    let db_scope = if scope_str == "connector" {
        "*"
    } else {
        resolved.as_ref().map(|s| s.id.as_str()).unwrap_or("*")
    };
    let actor = resolved.as_ref().map(|s| s.id.as_str()).unwrap_or("cli");
    let policy = match &resolved {
        Some(session) if db_scope != "*" => MutePolicyUpdate::Required(&session.id),
        _ => MutePolicyUpdate::None,
    };
    let (added, rev) = match daemon.add_mute(db_scope, &pattern, actor, ttl_seconds, policy) {
        Ok(result) => result,
        Err((code, msg)) => return json!({ "ok": false, "code": code, "error": msg }),
    };

    let mut res = json!({
        "sessionId": resolved.map(|s| s.id),
        "pattern": added.pattern,
        "scope": scope_str,
        "ttlSeconds": ttl_seconds,
        "rev": rev,
    });
    if let Some(exp) = added.expires_at {
        res["expiresAt"] = json!(exp);
    }
    json!({
        "ok": true,
        "result": res,
    })
}

fn handle_session_unmute(daemon: &LocalDaemonInner, packet: &Map<String, Value>) -> Value {
    let sel = match SessionSelector::from_packet(packet) {
        Ok(s) => s,
        Err((code, msg)) => return json!({ "ok": false, "code": code, "error": msg }),
    };
    let scope_str = match packet.get("scope") {
        None | Some(Value::Null) => "session",
        Some(Value::String(s)) => match s.trim() {
            "session" => "session",
            "connector" => "connector",
            other => {
                return json!({
                    "ok": false,
                    "code": "invalid_request",
                    "error": format!("Expected scope 'session' | 'connector', got '{other}'")
                });
            }
        },
        Some(_) => {
            return json!({
                "ok": false,
                "code": "invalid_request",
                "error": "Expected string 'scope'"
            });
        }
    };
    let resolved = daemon.resolve_session(&sel);
    if scope_str == "session" && resolved.is_none() {
        return json!({ "ok": false, "code": "not_found", "error": "Session not found" });
    }
    let Some(raw_pattern) = packet
        .get("pattern")
        .or_else(|| packet.get("source"))
        .or_else(|| packet.get("target"))
        .and_then(Value::as_str)
    else {
        return json!({
            "ok": false,
            "code": "invalid_request",
            "error": "Expected string 'source' or 'pattern'"
        });
    };
    let pattern = match validate_control_pattern(raw_pattern) {
        Ok(p) => p,
        Err((code, msg)) => return json!({ "ok": false, "code": code, "error": msg }),
    };

    let db_scope = if scope_str == "connector" {
        "*"
    } else {
        resolved.as_ref().map(|s| s.id.as_str()).unwrap_or("*")
    };

    let removed = {
        let db = daemon.node.db();
        let db_removed = match db.local().remove_mute(db_scope, &pattern) {
            Ok(r) => r,
            Err(e) => {
                return json!({ "ok": false, "code": "store_error", "error": e.to_string() });
            }
        };
        let mut policy_removed = false;
        if let Some(ref sess) = resolved {
            if db_scope != "*" {
                let _ = daemon.delivery.update_policy(&db, &sess.id, |p| {
                    policy_removed = p.remove_rule(&pattern);
                });
            }
        }
        db_removed || policy_removed
    };

    let rev = daemon.bump_ui_rev();
    json!({
        "ok": true,
        "result": {
            "sessionId": resolved.map(|s| s.id),
            "pattern": pattern,
            "scope": scope_str,
            "removed": removed,
            "rev": rev,
        }
    })
}

fn handle_session_rule(daemon: &LocalDaemonInner, packet: &Map<String, Value>) -> Value {
    let sel = match SessionSelector::from_packet(packet) {
        Ok(s) => s,
        Err((code, msg)) => return json!({ "ok": false, "code": code, "error": msg }),
    };
    let Some(sess) = daemon.resolve_session(&sel) else {
        return json!({ "ok": false, "code": "not_found", "error": "Session not found" });
    };
    let Some(raw_target) = packet
        .get("source")
        .or_else(|| packet.get("target"))
        .and_then(Value::as_str)
    else {
        return json!({
            "ok": false,
            "code": "invalid_request",
            "error": "Expected string 'source' or 'target'"
        });
    };
    let target = match validate_control_pattern(raw_target) {
        Ok(t) => t,
        Err((code, msg)) => return json!({ "ok": false, "code": code, "error": msg }),
    };

    let remove_flag = packet.get("remove").and_then(Value::as_bool) == Some(true);
    let raw_delivery = packet
        .get("delivery")
        .or_else(|| packet.get("urgency"))
        .and_then(Value::as_str)
        .map(str::trim);

    let is_remove = remove_flag || raw_delivery.is_some_and(|d| d.eq_ignore_ascii_case("remove"));

    let now = daemon.current_time_ms();
    if is_remove {
        let (removed, rules) = {
            let db = daemon.node.db();
            let mut removed_rule = false;
            let policy = match daemon.delivery.update_policy(&db, &sess.id, |p| {
                removed_rule = p.remove_rule(&target);
            }) {
                Ok(p) => p,
                Err(e) => {
                    return json!({
                        "ok": false,
                        "code": "delivery_error",
                        "error": e.to_string()
                    });
                }
            };
            let mute_removed = db.local().remove_mute(&sess.id, &target).unwrap_or(false);
            (removed_rule || mute_removed, policy.overrides)
        };
        let rev = daemon.bump_ui_rev();
        return json!({
            "ok": true,
            "result": {
                "sessionId": sess.id,
                "target": target,
                "delivery": Value::Null,
                "removed": removed,
                "rules": rules,
                "rev": rev,
            }
        });
    }

    let Some(urgency_raw) = raw_delivery else {
        return json!({
            "ok": false,
            "code": "invalid_request",
            "error": "Expected 'delivery' / 'urgency' ('interrupt' | 'queue' | 'notify' | 'mute' | 'remove') or 'remove': true"
        });
    };
    let urgency = match DeliveryUrgency::parse(urgency_raw) {
        Ok(u) => u,
        Err(e) => {
            return json!({ "ok": false, "code": "invalid_request", "error": e.to_string() });
        }
    };
    let rule = DeliveryRule::new(&target, urgency);
    if let Err(e) = rule.validate() {
        return json!({ "ok": false, "code": "invalid_request", "error": e.to_string() });
    }

    let rules = {
        let db = daemon.node.db();
        let policy = match daemon.delivery.update_policy(&db, &sess.id, |p| {
            p.upsert_rule(rule.clone());
        }) {
            Ok(p) => p,
            Err(e) => {
                return json!({ "ok": false, "code": "delivery_error", "error": e.to_string() });
            }
        };
        if urgency == DeliveryUrgency::Mute {
            let _ = db.local().add_mute(&sess.id, &rule.target, &sess.id, now);
        } else {
            let _ = db.local().remove_mute(&sess.id, &rule.target);
        }
        policy.overrides
    };

    let rev = daemon.bump_ui_rev();
    json!({
        "ok": true,
        "result": {
            "sessionId": sess.id,
            "target": rule.target,
            "delivery": urgency.as_str(),
            "removed": false,
            "rules": rules,
            "rev": rev,
        }
    })
}

fn handle_session_unsubscribe(daemon: &LocalDaemonInner, packet: &Map<String, Value>) -> Value {
    let sel = match SessionSelector::from_packet(packet) {
        Ok(s) => s,
        Err((code, msg)) => return json!({ "ok": false, "code": code, "error": msg }),
    };
    let Some(sess) = daemon.resolve_session(&sel) else {
        return json!({ "ok": false, "code": "not_found", "error": "Session not found" });
    };

    let explicit_id = packet
        .get("subscriptionId")
        .or_else(|| packet.get("id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let key_arg = packet
        .get("key")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let sub_id = if let Some(id) = explicit_id {
        id.to_string()
    } else if let Some(key) = key_arg {
        daemon.subscription_id_for_key(&sess.id, key)
    } else {
        return json!({
            "ok": false,
            "code": "invalid_request",
            "error": "Expected 'subscriptionId', 'id', or 'key'"
        });
    };

    let existing = {
        let db = daemon.node.db();
        match db.events().get_subscription(&sub_id) {
            Ok(sub) => sub,
            Err(e) => {
                return json!({ "ok": false, "code": "store_error", "error": e.to_string() });
            }
        }
    };

    let Some(sub) = existing else {
        return json!({ "ok": false, "code": "not_found", "error": "Subscription not found" });
    };
    // Fail-closed ownership check: a session may ONLY unsubscribe its own subscriptions!
    if sub.subscriber != sess.id {
        return json!({
            "ok": false,
            "code": "forbidden",
            "error": "Subscription belongs to a different session"
        });
    }

    let removed = match daemon.delete_session_subscription(&sess.id, &sub_id, false) {
        Ok(removed) => removed,
        Err((code, msg)) => return json!({ "ok": false, "code": code, "error": msg }),
    };

    if removed {
        // Clean up local upstream_pushdowns cache if no remaining local subscribers watch this remote topic.
        let my_node = daemon.node.node_id().as_str();
        if sub.origin_node != "local" && sub.origin_node != my_node {
            let db = daemon.node.db();
            let remaining = db
                .events()
                .list_subscriptions(None)
                .unwrap_or_default()
                .into_iter()
                .any(|s| s.origin_node == sub.origin_node && s.topic == sub.topic);
            if !remaining {
                if let Ok(pushdowns) = db.events().list_upstream_pushdowns(Some(&sub.origin_node)) {
                    for pd in pushdowns {
                        if pd.topic == sub.topic {
                            let _ = db.events().delete_upstream_pushdown(&pd.id);
                        }
                    }
                }
            }
        }
    }

    let rev = daemon.bump_ui_rev();
    json!({
        "ok": true,
        "result": {
            "sessionId": sess.id,
            "subscriptionId": sub_id,
            "removed": removed,
            "rev": rev,
        }
    })
}

async fn handle_session_leave_channel(
    daemon: &LocalDaemonInner,
    packet: &Map<String, Value>,
) -> Value {
    let sel = match SessionSelector::from_packet(packet) {
        Ok(s) => s,
        Err((code, msg)) => return json!({ "ok": false, "code": code, "error": msg }),
    };
    let Some(sess) = daemon.resolve_session(&sel) else {
        return json!({ "ok": false, "code": "not_found", "error": "Session not found" });
    };
    let Some(handle) = sess.handle else {
        return json!({
            "ok": false,
            "code": "not_enrolled",
            "error": "Session is not enrolled with a handle"
        });
    };
    let Some(channel) = packet
        .get("channel")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return json!({
            "ok": false,
            "code": "invalid_request",
            "error": "Expected non-empty string 'channel'"
        });
    };

    match daemon.node.leave_channel(channel, &handle).await {
        Ok(false) => json!({
            "ok": false,
            "code": "not_found",
            "error": format!("Session '{}' (@{}) is not a member of channel '{channel}'", sess.id, handle),
        }),
        Ok(true) => {
            let rev = daemon.bump_ui_rev();
            json!({
                "ok": true,
                "result": {
                    "sessionId": sess.id,
                    "channel": channel,
                    "left": true,
                    "rev": rev,
                }
            })
        }
        Err(err) => {
            let (code, message) = node_err_tuple(err);
            json!({
                "ok": false,
                "code": code,
                "error": message,
            })
        }
    }
}
