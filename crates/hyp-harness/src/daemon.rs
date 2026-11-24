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

use std::collections::{BTreeMap, HashMap, HashSet};
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hyp_node::delivery::{
    DeliveryEngine, DeliveryRule, DeliveryUrgency, InboxFilter, InboxQuery, InboxStateFilter,
    PackableItem, PackedDeliveryBatch, archive_muted_entry, move_pending_to_muted, muted_count,
    pack_delivery_batch, query_inbox, record_delivered_receipts,
};
use hyp_node::engine::{ChannelMode, KvWriteRequest, SubscribeRequest, UnifiedNode};
use hyp_node::gates::{
    GateDecision, InboundContext, OutboundContext, SecurityGatePipeline, TrustTier as GateTrustTier,
};
use hyp_proto::cloudevent::{
    CONTENT_TYPE_JSON, CloudEvent as ProtoCloudEvent, parse_rfc3339_utc_nanos,
};
use hyp_proto::cron::CronTimezone;
use hyp_proto::filter::Filter as ProtoFilter;
use hyp_store::{
    BridgeLink, DEFAULT_WAKEUP_TTL_MS, DeliveryMode, FiredWakeup, GateState, MailboxEntry,
    MailboxInsert, MailboxKind, MailboxPutOptions, MailboxPutResult, PluginTargetHandoff,
    StoreError, WakeupInsert, WakeupLimits, WakeupRecord, WakeupState, WakeupTriggerKind,
    WakeupUrgency, WriteModel, epoch_ms_to_rfc3339, format_address, now_ms, parse_address, uuid_v4,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::call_registry::{
    CallRegistry, CallerResolution, DEFAULT_RESOLVE_WAIT, StartCallInput, is_valid_session_id,
};
use crate::protocol::{
    HarnessKind, UNTRUSTED_PROVENANCE, is_bridge_destination, normalize_mesh_tool_name,
};
use crate::sock::{
    DEFAULT_SOCKET_FILENAME, MAX_SOCKET_LINE_BYTES, read_bounded_line_async,
    write_ndjson_line_async,
};
use crate::transport::codex::{
    CodexQueueTarget, CodexQueueTransport, DEFAULT_CODEX_BIN, build_codex_queue_args,
};
use crate::transport::herdr::{
    DEFAULT_HERDR_BIN, DEFAULT_SPAWN_TIMEOUT, HerdrTransport, is_valid_herdr_template,
    is_valid_terminal_id, probe_herdr_terminal, spawn_herdr_template,
};
use crate::transport::t3::{
    DEFAULT_PROBE_TIMEOUT, DEFAULT_T3_TOKEN_SECRET, DEFAULT_T3_URL, FALLBACK_T3_TOKEN_SECRET,
    T3Target, T3Transport, default_t3_base_dir, normalize_t3_server_url, probe_t3_server,
    resolve_t3_thread_by_provider_session, t3_state_db_path, verify_t3_thread_exists,
};
use crate::transport::{PushMode, PushOutcome, PushTransport};

const PRIORITY_EXPLICIT: u8 = 100;
const PRIORITY_HERDR: u8 = 30;
const PRIORITY_T3: u8 = 25;
const PRIORITY_CODEX_QUEUE: u8 = 20;

/// Default timeout waiting for a live `--claude-channel` `channel.ack`.
pub const DEFAULT_CHANNEL_DELIVER_TIMEOUT: Duration = Duration::from_secs(10);

/// Boxed `Send` future alias used by [`BridgePoster`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Pluggable async outbound handler for local chat/webhook bridges (`<plugin>:<target>`).
///
/// Implemented by real external chat bridge supervisors as well as deterministic in-process
/// test bridges. Outbound DLP (`SecurityGatePipeline`) and primary target ownership
/// (`plugin_targets`) are ALWAYS enforced by [`LocalDaemon`] BEFORE invoking [`BridgePoster::post`].
pub trait BridgePoster: Send + Sync {
    fn post<'a>(
        &'a self,
        plugin: &'a str,
        target: &'a str,
        text: &'a str,
        meta: &'a Map<String, Value>,
    ) -> BoxFuture<'a, Result<Value, (String, String)>>;
}

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

/// Exposure policy for the conditional `hyp_wakeup` MCP tool in `mcp.caps`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WakeupMcpToolMode {
    /// Advertise `hyp_wakeup` to all harnesses EXCEPT those listed in `deny_backends`.
    #[default]
    Auto,
    /// Advertise `hyp_wakeup` to every MCP connection when `wakeup.enabled == true`.
    Always,
    /// Never advertise `hyp_wakeup` in MCP (CLI / OS triggers & `hyp_stream` only; 0 MCP tokens).
    Never,
}

/// Opt-in wakeup delivery, Tier 3 `Hold` retry backoff, Tier 4 cold-revival, and Security Gate
/// configuration for [`LocalDaemon`].
#[derive(Debug, Clone)]
pub struct WakeupDaemonConfig {
    pub enabled: bool,
    pub mcp_tool_mode: WakeupMcpToolMode,
    pub deny_backends: Vec<HarnessKind>,
    pub hold_retry_backoff_ms: Vec<u64>,
    pub hold_retry_max_attempts: u32,
    pub codex_resume: bool,
    pub herdr_spawn_allowlist: Vec<String>,
    pub screen_external_notes: bool,
    pub screen_agent_notes: bool,
}

impl Default for WakeupDaemonConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mcp_tool_mode: WakeupMcpToolMode::Auto,
            deny_backends: vec![HarnessKind::Openclaw, HarnessKind::Antigravity],
            hold_retry_backoff_ms: vec![5_000, 15_000, 30_000, 60_000],
            hold_retry_max_attempts: 6,
            codex_resume: false,
            herdr_spawn_allowlist: Vec::new(),
            screen_external_notes: true,
            screen_agent_notes: false,
        }
    }
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
    /// Opt-in wakeup scheduler, Tier 3 `Hold` retry backoff, and Tier 4 cold-revival settings.
    pub wakeup: WakeupDaemonConfig,
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
            wakeup: WakeupDaemonConfig::default(),
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
    codex_thread_id: Option<String>,
    codex_home: Option<PathBuf>,
    codex_remote: Option<String>,
    codex_resume: bool,
    explicit_codex_queue: bool,
    t3_base_dir: Option<PathBuf>,
    t3_url: Option<String>,
}

impl TransportHints {
    fn from_packet(packet: &Map<String, Value>, default_harness: Option<HarnessKind>) -> Self {
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
        let herdr_terminal_id = non_empty_str("herdrTerminalId")
            .or_else(|| non_empty_str("terminalId"))
            .filter(|tid| is_valid_terminal_id(tid));
        let explicit_thread = non_empty_str("threadId");
        let codex_thread_id = explicit_thread
            .clone()
            .or_else(|| non_empty_str("codexThreadId"));
        let codex_home = non_empty_str("codexHome").map(PathBuf::from);
        let codex_remote = non_empty_str("codexRemote").or_else(|| non_empty_str("remote"));
        let codex_resume = packet.get("resume").and_then(Value::as_bool) == Some(true);
        let explicit_codex_queue =
            explicit_thread.is_some() || codex_remote.is_some() || codex_resume;
        let t3_base_dir = non_empty_str("t3BaseDir").map(PathBuf::from);
        let t3_url = non_empty_str("t3Url");

        Self {
            harness,
            herdr_terminal_id,
            codex_thread_id,
            codex_home,
            codex_remote,
            codex_resume,
            explicit_codex_queue,
            t3_base_dir,
            t3_url,
        }
    }

    fn has_any_hint(&self) -> bool {
        self.herdr_terminal_id.is_some()
            || self.t3_base_dir.is_some()
            || self.t3_url.is_some()
            || self.harness == Some(HarnessKind::T3)
            || (self.explicit_codex_queue && self.codex_thread_id.is_some())
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
struct ClassifiedItemMeta {
    urgency: DeliveryUrgency,
    burst_demoted: bool,
    burst_source_key: String,
    channel: Option<String>,
    is_announcement: bool,
    notified: bool,
}

#[derive(Debug, Clone)]
struct SubscriptionRecordMeta {
    id: String,
    key: Option<String>,
    origin_node: String,
    topic: String,
    urgency: DeliveryUrgency,
}

struct LocalDaemonInner {
    node: Arc<UnifiedNode>,
    gate: Option<Arc<SecurityGatePipeline>>,
    delivery: Arc<DeliveryEngine>,
    calls: Arc<CallRegistry>,
    config: LocalDaemonConfig,
    socket_path: PathBuf,
    waiters: Mutex<HashMap<String, Vec<LiveWaiter>>>,
    channels: Mutex<HashMap<String, LiveChannel>>,
    /// Attached native external push transports (`Herdr`, `T3`, `CodexQueue`, or test doubles).
    session_transports: Mutex<HashMap<String, AttachedPushTransport>>,
    /// Active background auto-detection probe watchers keyed by `session_id`.
    pending_probes: Mutex<HashMap<String, watch::Receiver<bool>>>,
    flushing: Mutex<HashSet<String>>,
    /// Per-session classified metadata for `Pending` receipts (`receipt -> meta`).
    item_meta: Mutex<HashMap<String, HashMap<String, ClassifiedItemMeta>>>,
    /// Per-session subscription urgency & key mappings.
    sub_meta: Mutex<HashMap<String, Vec<SubscriptionRecordMeta>>>,
    /// Receipts dismissed by Security Gate (`Block` or `Quarantine` in pipeline) so they never surface.
    dismissed_receipts: Mutex<HashSet<String>>,
    /// Registered pluggable outbound bridge handlers keyed by lowercase plugin slug.
    bridge_posters: Mutex<HashMap<String, Arc<dyn BridgePoster>>>,
    /// Configured targets per bridge plugin (advertised even before any session links).
    configured_bridge_targets: Mutex<BTreeMap<String, Vec<String>>>,
    /// Tier 3 bounded `Hold` retry state (`session_id -> (attempt, generation)`).
    /// Empty when idle — zero background polling.
    hold_retries: Mutex<HashMap<String, (u32, u64)>>,
    /// Tier 4 per-wakeup concurrency guard (`maxConcurrentSpawns: 1`) for allowlisted Herdr cold spawns.
    active_cold_spawns: Mutex<HashSet<String>>,
    /// Daemon shutdown watch receiver shared with bounded retry tasks.
    shutdown_rx: watch::Receiver<bool>,
    next_id: AtomicU64,
}

/// Native async Rust Hyphae `LocalDaemon` handle.
pub struct LocalDaemon {
    inner: Arc<LocalDaemonInner>,
    tcp_addr: Option<SocketAddr>,
    shutdown_tx: watch::Sender<bool>,
    accept_task: Mutex<Option<JoinHandle<()>>>,
    inbox_task: Mutex<Option<JoinHandle<()>>>,
}

impl Drop for LocalDaemon {
    fn drop(&mut self) {
        self.stop_sync();
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
                let Ok((stream, _)) = accepted else {
                    continue;
                };
                let conn_inner = Arc::clone(&accept_inner);
                let conn_shutdown = shutdown_rx.clone();
                tokio::spawn(async move {
                    let (r, w) = stream.into_split();
                    handle_connection(conn_inner, r, w, conn_shutdown).await;
                });
            }
        });

        let inbox_task = spawn_inbox_watcher(Arc::clone(&inner), shutdown_tx.subscribe());

        Ok(Self {
            inner,
            tcp_addr: None,
            shutdown_tx,
            accept_task: Mutex::new(Some(accept_task)),
            inbox_task: Mutex::new(Some(inbox_task)),
        })
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
            let _ = std::fs::set_permissions(&addr_file_path, std::fs::Permissions::from_mode(0o600));
        }

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let inner = Arc::new(LocalDaemonInner::new(
            node,
            gate,
            config,
            addr_file_path,
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
                let Ok((stream, _)) = accepted else {
                    continue;
                };
                let conn_inner = Arc::clone(&accept_inner);
                let conn_shutdown = shutdown_rx.clone();
                tokio::spawn(async move {
                    let (r, w) = stream.into_split();
                    handle_connection(conn_inner, r, w, conn_shutdown).await;
                });
            }
        });

        let inbox_task = spawn_inbox_watcher(Arc::clone(&inner), shutdown_tx.subscribe());

        Ok(Self {
            inner,
            tcp_addr: Some(local_addr),
            shutdown_tx,
            accept_task: Mutex::new(Some(accept_task)),
            inbox_task: Mutex::new(Some(inbox_task)),
        })
    }

    pub fn socket_path(&self) -> &Path {
        &self.inner.socket_path
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
        let flush_inner = Arc::clone(&self.inner);
        tokio::spawn(async move {
            flush_inner.flush_session(&sid).await;
        });
    }

    /// Removes any attached native [`PushTransport`] for `session_id`.
    pub fn unregister_session_transport(&self, session_id: &str) -> bool {
        self.inner
            .session_transports
            .lock()
            .expect("session_transports lock poisoned")
            .remove(session_id)
            .is_some()
    }

    /// Returns the active live wakeup transport kind for `session_id`, if any
    /// (`"claude_channel"`, `"herdr"`, `"t3"`, `"codex_queue"`, `"watch"`, `"wait"`, etc.).
    pub fn session_transport_kind(&self, session_id: &str) -> Option<&'static str> {
        self.inner.active_transport_kind(session_id)
    }

    /// Registers a pluggable outbound [`BridgePoster`] for `plugin` (case-insensitive slug).
    /// Also causes `mcp.caps` to advertise `hasPlugins: true` so `hyp_bridge` is surfaced in `tools/list`.
    pub fn register_bridge_poster(
        &self,
        plugin: impl Into<String>,
        poster: Arc<dyn BridgePoster>,
    ) {
        let key = plugin.into().trim().to_ascii_lowercase();
        if !key.is_empty() {
            self.inner
                .bridge_posters
                .lock()
                .expect("bridge_posters lock poisoned")
                .insert(key, poster);
        }
    }

    /// Registers a pluggable outbound [`BridgePoster`] together with its configured target list.
    ///
    /// Configured targets are immediately advertised by `hyp_bridge({ action: "targets" })` even
    /// before any session links or claims primary ownership, so agents can discover targets like
    /// `telegram:123456789` on boot.
    pub fn register_bridge_poster_with_targets(
        &self,
        plugin: impl Into<String>,
        targets: Vec<String>,
        poster: Arc<dyn BridgePoster>,
    ) {
        let key = plugin.into().trim().to_ascii_lowercase();
        if key.is_empty() {
            return;
        }
        let mut clean_targets = Vec::new();
        for raw in targets {
            let trimmed = raw.trim();
            if !trimmed.is_empty() && !clean_targets.iter().any(|t: &String| t == trimmed) {
                clean_targets.push(trimmed.to_string());
            }
        }
        self.inner
            .bridge_posters
            .lock()
            .expect("bridge_posters lock poisoned")
            .insert(key.clone(), poster);
        let mut cfg_targets = self
            .inner
            .configured_bridge_targets
            .lock()
            .expect("configured_bridge_targets lock poisoned");
        if clean_targets.is_empty() {
            cfg_targets.remove(&key);
        } else {
            cfg_targets.insert(key, clean_targets);
        }
    }

    /// Fans out an inbound external chat/webhook bridge message to all sessions linked to
    /// `(plugin, target)` (plus any wildcard `(plugin, "*")` links).
    ///
    /// Every delivery runs through [`LocalDaemon::ingest_inbound`] (`GateTrustTier::Bridge`,
    /// `MailboxKind::Plugin`, `source = "{plugin}:{target}"`) so Local Security Gates and
    /// §2.5 Delivery Policy apply consistently and wake live sessions immediately.
    ///
    /// Returns the number of linked sessions for which ingestion was accepted.
    pub async fn deliver_bridge_inbound(
        &self,
        plugin: &str,
        target: &str,
        item_id: &str,
        text: &str,
    ) -> Result<usize, String> {
        let plugin_key = plugin.trim().to_ascii_lowercase();
        let target_trimmed = target.trim();
        if plugin_key.is_empty() || target_trimmed.is_empty() {
            return Err("plugin and target must be non-empty".to_string());
        }

        let session_ids: Vec<String> = {
            let db = self.inner.node.db();
            let mut seen = HashSet::new();
            let mut out = Vec::new();
            for link in db
                .local()
                .bridge_links(&plugin_key, target_trimmed)
                .map_err(|e| e.to_string())?
            {
                if seen.insert(link.session_id.clone()) {
                    out.push(link.session_id);
                }
            }
            if target_trimmed != "*" {
                for link in db
                    .local()
                    .bridge_links(&plugin_key, "*")
                    .map_err(|e| e.to_string())?
                {
                    if seen.insert(link.session_id.clone()) {
                        out.push(link.session_id);
                    }
                }
            }
            out
        };

        let origin_node = format!("bridge:{plugin_key}");
        let source = format!("{plugin_key}:{target_trimmed}");
        let effective_item_id = if item_id.trim().is_empty() {
            uuid_v4()
        } else {
            item_id.trim().to_string()
        };

        let mut delivered = 0usize;
        let mut last_err: Option<String> = None;
        for session_id in session_ids {
            match self
                .ingest_inbound(InboundItem {
                    session_id,
                    origin_node: origin_node.clone(),
                    item_id: effective_item_id.clone(),
                    source: source.clone(),
                    text: text.to_string(),
                    kind: MailboxKind::Plugin,
                    trust_tier: GateTrustTier::Bridge,
                })
                .await
            {
                Ok(Some(_)) => delivered += 1,
                Ok(None) => {}
                Err(e) => last_err = Some(e),
            }
        }

        if delivered == 0 {
            if let Some(err) = last_err {
                return Err(err);
            }
        }
        Ok(delivered)
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
        self.inner
            .hold_retries
            .lock()
            .expect("hold_retries lock poisoned")
            .clear();
        if let Some(h) = self
            .accept_task
            .lock()
            .expect("accept_task lock poisoned")
            .take()
        {
            h.abort();
        }
        if let Some(h) = self
            .inbox_task
            .lock()
            .expect("inbox_task lock poisoned")
            .take()
        {
            h.abort();
        }
        let _ = std::fs::remove_file(&self.inner.socket_path);
    }

    /// Delivers a fired durable wakeup (`FiredWakeup`) through the `to.hyphae.wakeup.v1`
    /// CloudEvents bus, optional Security Gate screening, coalesced durable SQLite mailbox,
    /// Tiers 1–3 delivery flush, and opt-in Tier 4 cold revival (Codex `--resume` / allowlisted
    /// Herdr `hc run <template>`), updating `wakeups.consecutive_failures` atomically.
    pub async fn deliver_fired_wakeup(&self, fired: &FiredWakeup) -> Result<bool, String> {
        self.inner.deliver_fired_wakeup(fired).await
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
        let now = now_ms();
        let mut gate_downgraded = false;

        if let Some(ref pipeline) = self.inner.gate {
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
                trust_tier,
                e2ee_verified: true,
                identity_verified: true,
                kind,
                channel: parsed.channel,
                topic: parsed.topic,
                bridge: parsed.bridge,
                event: ce,
                transfer_paths: Vec::new(),
                rendered_text: Some(text.clone()),
            };
            let eval = pipeline
                .evaluate_inbound(&ctx, now)
                .await
                .map_err(|e| e.to_string())?;
            match eval.decision {
                GateDecision::Allow {
                    downgraded_to_notify,
                } => {
                    gate_downgraded = downgraded_to_notify;
                    if let Some(receipt) = eval.receipt {
                        // Pipeline already inserted into DB if sharing same DB; check if present in node DB.
                        let exists = self
                            .inner
                            .node
                            .db()
                            .local()
                            .get_mailbox_entry(&receipt)
                            .ok()
                            .flatten()
                            .is_some();
                        if exists {
                            let urgency = self
                                .inner
                                .classify_and_route_pending_entry(
                                    &session_id,
                                    &receipt,
                                    gate_downgraded,
                                    now,
                                )
                                .await;
                            if urgency.is_some_and(DeliveryUrgency::triggers_delivery_or_digest) {
                                self.inner.flush_session(&session_id).await;
                            }
                            return Ok(urgency);
                        }
                    }
                }
                GateDecision::Quarantine { .. }
                | GateDecision::Block { .. }
                | GateDecision::Hold { .. } => {
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
            gate_reason: None,
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
            gate_reason: None,
            traceparent: None,
            payload_sha256: None,
            reviewed_at: None,
        };

        let sub_mode = self
            .inner
            .lookup_subscription_urgency(&session_id, &origin_node, &source);
        let classification = {
            let db = self.inner.node.db();
            self.inner
                .delivery
                .classify_entry(&db, &session_id, &temp_entry, sub_mode, gate_downgraded, now)
                .map_err(|e| e.to_string())?
        };

        if classification.effective_urgency == DeliveryUrgency::Mute {
            let db = self.inner.node.db();
            archive_muted_entry(&db, &insert, now).map_err(|e| e.to_string())?;
            return Ok(Some(DeliveryUrgency::Mute));
        }

        let receipt = {
            let db = self.inner.node.db();
            match db
                .local()
                .put_in_mailbox(&insert, now)
                .map_err(|e| e.to_string())?
            {
                MailboxPutResult::Stored { receipt } => receipt,
                MailboxPutResult::Duplicate => return Ok(Some(classification.effective_urgency)),
                MailboxPutResult::QueueFull => return Err("local_inbox_full".to_string()),
            }
        };

        let is_announcement = self
            .inner
            .is_announcement_channel(classification.parsed.channel.as_deref());
        self.inner.record_item_meta(
            &session_id,
            receipt,
            ClassifiedItemMeta {
                urgency: classification.effective_urgency,
                burst_demoted: classification.burst.demoted,
                burst_source_key: classification.burst_source_key,
                channel: classification.parsed.channel,
                is_announcement,
                notified: false,
            },
        );
        self.inner.flush_session(&session_id).await;
        Ok(Some(classification.effective_urgency))
    }
}

fn spawn_inbox_watcher(
    inner: Arc<LocalDaemonInner>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    let mut rx = inner.node.subscribe_local_inbox();
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
                        continue;
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                },
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
        }
    })
}

impl LocalDaemonInner {
    fn new(
        node: Arc<UnifiedNode>,
        gate: Option<Arc<SecurityGatePipeline>>,
        config: LocalDaemonConfig,
        socket_path: PathBuf,
        shutdown_rx: watch::Receiver<bool>,
    ) -> Self {
        Self {
            node,
            gate,
            delivery: Arc::new(DeliveryEngine::new()),
            calls: Arc::new(CallRegistry::new()),
            config,
            socket_path,
            waiters: Mutex::new(HashMap::new()),
            channels: Mutex::new(HashMap::new()),
            session_transports: Mutex::new(HashMap::new()),
            pending_probes: Mutex::new(HashMap::new()),
            flushing: Mutex::new(HashSet::new()),
            item_meta: Mutex::new(HashMap::new()),
            sub_meta: Mutex::new(HashMap::new()),
            dismissed_receipts: Mutex::new(HashSet::new()),
            bridge_posters: Mutex::new(HashMap::new()),
            configured_bridge_targets: Mutex::new(BTreeMap::new()),
            hold_retries: Mutex::new(HashMap::new()),
            active_cold_spawns: Mutex::new(HashSet::new()),
            shutdown_rx,
            next_id: AtomicU64::new(1),
        }
    }

    fn has_wakeup_capability(&self, backend: Option<HarnessKind>) -> bool {
        if !self.config.wakeup.enabled {
            return false;
        }
        match self.config.wakeup.mcp_tool_mode {
            WakeupMcpToolMode::Never => false,
            WakeupMcpToolMode::Always => true,
            WakeupMcpToolMode::Auto => {
                !backend.is_some_and(|b| self.config.wakeup.deny_backends.contains(&b))
            }
        }
    }

    fn cancel_hold_retry(&self, session_id: &str) {
        self.hold_retries
            .lock()
            .expect("hold_retries lock poisoned")
            .remove(session_id);
    }

    /// Schedules a single bounded Tier 3 retry task for a transient `Hold` outcome
    /// (`herdr_working`, `herdr_send_guard_refused`, `herdr_agent_not_ready`,
    /// `t3_server_unreachable`, `codex_queue_unavailable`).
    ///
    /// Zero background polling when `hold_retries` is empty; immediately invalidated
    /// whenever `commit_delivered_batch`, `mailbox.drain`, `hyp_inbox(ack)`, or daemon
    /// shutdown clears the session's pending items.
    fn schedule_hold_retry(self: &Arc<Self>, session_id: &str) {
        let max_attempts = self.config.wakeup.hold_retry_max_attempts;
        if max_attempts == 0 || self.config.wakeup.hold_retry_backoff_ms.is_empty() {
            return;
        }
        let (generation, delay_ms) = {
            let mut map = self
                .hold_retries
                .lock()
                .expect("hold_retries lock poisoned");
            let next_attempt = map
                .get(session_id)
                .map(|(attempt, _)| attempt.saturating_add(1))
                .unwrap_or(1);
            if next_attempt > max_attempts {
                map.remove(session_id);
                return;
            }
            let generation = self.next_seq();
            map.insert(session_id.to_string(), (next_attempt, generation));
            let idx = ((next_attempt - 1) as usize)
                .min(self.config.wakeup.hold_retry_backoff_ms.len() - 1);
            let delay = self.config.wakeup.hold_retry_backoff_ms[idx].max(1);
            (generation, delay)
        };

        let daemon = Arc::clone(self);
        let sid = session_id.to_string();
        let mut shutdown_rx = self.shutdown_rx.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(delay_ms)) => {}
                _ = shutdown_rx.changed() => {
                    return;
                }
            }
            if *shutdown_rx.borrow() {
                return;
            }
            let still_current = {
                let map = daemon
                    .hold_retries
                    .lock()
                    .expect("hold_retries lock poisoned");
                map.get(&sid).is_some_and(|&(_, g)| g == generation)
            };
            if !still_current {
                return;
            }
            let _ = daemon.flush_session(&sid).await;
        });
    }

    /// Invokes allowlisted Tier 4 Herdr cold-spawn (`hc run <template> <prompt>`)
    /// guarded by a per-wakeup concurrency limit (`maxConcurrentSpawns: 1`).
    async fn try_herdr_cold_spawn(
        &self,
        wakeup_id: &str,
        template: &str,
        prompt: &str,
    ) -> PushOutcome {
        if !is_valid_herdr_template(template)
            || !self
                .config
                .wakeup
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
                .lock()
                .expect("active_cold_spawns lock poisoned");
            if !active.insert(wakeup_id.to_string()) {
                return PushOutcome::hold("herdr_spawn_already_active");
            }
        }
        struct ColdSpawnGuard<'a> {
            active: &'a Mutex<HashSet<String>>,
            wakeup_id: String,
        }
        impl Drop for ColdSpawnGuard<'_> {
            fn drop(&mut self) {
                self.active
                    .lock()
                    .expect("active_cold_spawns lock poisoned")
                    .remove(&self.wakeup_id);
            }
        }
        let _guard = ColdSpawnGuard {
            active: &self.active_cold_spawns,
            wakeup_id: wakeup_id.to_string(),
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
            &self.config.wakeup.herdr_spawn_allowlist,
            DEFAULT_SPAWN_TIMEOUT,
        )
        .await
    }

    async fn screen_wakeup_via_gate(
        &self,
        req: &WakeupDeliveryRequest,
        session_id: &str,
        item_id: &str,
        formatted_text: &str,
        ce: &ProtoCloudEvent,
        now: i64,
    ) -> Result<bool, String> {
        let Some(ref pipeline) = self.gate else {
            return Ok(false);
        };
        let should_screen = if req.is_external {
            self.config.wakeup.screen_external_notes
        } else {
            self.config.wakeup.screen_agent_notes
        };
        if !should_screen {
            return Ok(false);
        }

        let topic = req
            .target_topic
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("wakeup");
        let mut gate_ce = ce.clone();
        gate_ce.id = format!("gate-wakeup:{item_id}");
        let trust_tier = if req.is_external {
            GateTrustTier::ExternalWebhook
        } else {
            GateTrustTier::SelfHost
        };
        let ctx = InboundContext {
            session_id: session_id.to_string(),
            origin_node: self.node.node_id().as_str().to_string(),
            sender: format!("wakeup:{}", req.wakeup_id),
            trust_tier,
            e2ee_verified: true,
            identity_verified: true,
            kind: MailboxKind::Event,
            channel: None,
            topic: Some(topic.to_string()),
            bridge: None,
            event: gate_ce,
            transfer_paths: Vec::new(),
            rendered_text: Some(formatted_text.to_string()),
        };

        let eval = pipeline
            .evaluate_inbound(&ctx, now)
            .await
            .map_err(|e| format!("wakeup_gate_error:{e}"))?;
        match eval.decision {
            GateDecision::Allow {
                downgraded_to_notify,
            } => {
                // Remove any duplicate non-coalesced mailbox row written by the gate pipeline
                // so our coalesced `put_in_mailbox_ex` row is the single source of truth.
                if let Some(dup_receipt) = eval.receipt {
                    self.dismissed_receipts
                        .lock()
                        .expect("dismissed lock poisoned")
                        .insert(dup_receipt.clone());
                    let db = self.node.db();
                    let _ = db
                        .local()
                        .acknowledge_inbox(session_id, &[dup_receipt.as_str()], now);
                }
                Ok(downgraded_to_notify)
            }
            GateDecision::Block { reason } => Err(format!("wakeup_gate_blocked:{reason}")),
            GateDecision::Quarantine { reason, .. } => {
                Err(format!("wakeup_gate_quarantined:{reason}"))
            }
            GateDecision::Hold { reason, .. } => Err(format!("wakeup_gate_held:{reason}")),
        }
    }

    async fn deliver_fired_wakeup(self: &Arc<Self>, fired: &FiredWakeup) -> Result<bool, String> {
        let w = &fired.wakeup;
        let coalesce_key = w.coalesce.then(|| format!("wakeup:{}", w.id));
        let req = WakeupDeliveryRequest {
            wakeup_id: w.id.clone(),
            label: w.label.clone(),
            note: w.note.clone(),
            trigger: w.trigger_kind.as_str().to_string(),
            urgency: w.urgency,
            target_session_id: w.target_session_id.clone(),
            target_handle: w.target_handle.clone(),
            target_topic: w.target_topic.clone(),
            coalesce_key,
            ttl_ms: Some(w.ttl_ms),
            scheduled_for_ms: fired.scheduled_for_ms,
            fired_at_ms: fired.fired_at_ms,
            iteration: w.iteration,
            max_iterations: w.max_iterations,
            missed_count: fired.missed_count,
            cold_revival_template: w.cold_revival_template.clone(),
            is_external: w.owner_session_id.is_none(),
            is_persisted_wakeup: true,
        };
        self.deliver_wakeup_internal(req)
            .await
            .map(|res| res.delivered)
    }

    async fn deliver_wakeup_internal(
        self: &Arc<Self>,
        req: WakeupDeliveryRequest,
    ) -> Result<WakeupDeliveryOutcome, String> {
        let now = now_ms();
        let topic = req
            .target_topic
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .unwrap_or("wakeup");
        let expires_at = req.ttl_ms.map(|ttl| now.saturating_add(ttl));

        // 1. Resolve target session (direct `target_session_id` or `session_by_handle`).
        let resolved_session: Option<(String, String)> = {
            let db = self.node.db();
            let direct = req.target_session_id.as_deref().and_then(|sid| {
                db.local()
                    .get_session(sid)
                    .ok()
                    .flatten()
                    .map(|s| (s.id, s.backend_json))
            });
            if direct.is_some() {
                direct
            } else if let Some(raw_handle) = req.target_handle.as_deref() {
                let clean = raw_handle.strip_prefix('@').unwrap_or(raw_handle);
                let lookup = parse_address(clean).map(|(_, h)| h).unwrap_or(clean);
                db.local()
                    .session_by_handle(lookup)
                    .ok()
                    .flatten()
                    .map(|s| (s.id, s.backend_json))
            } else {
                None
            }
        };

        // Compute effective missed count ahead of formatting if coalescing into an existing pending row.
        let mut effective_missed = req.missed_count;
        if let (Some((sid, _)), Some(ckey)) = (&resolved_session, &req.coalesce_key) {
            let db = self.node.db();
            if let Ok(existing) = db.local().peek_inbox_ex(sid, 500) {
                if let Some(prev) = existing
                    .iter()
                    .find(|e| e.coalesce_key.as_deref() == Some(ckey.as_str()))
                {
                    effective_missed = effective_missed
                        .saturating_add(prev.missed_count)
                        .saturating_add(1);
                }
            }
        }

        let formatted_text = format_wakeup_text(
            &req.wakeup_id,
            &req.trigger,
            &req.label,
            req.iteration,
            req.max_iterations,
            effective_missed,
            &req.note,
        );

        let ce = build_wakeup_cloudevent(
            self.node.node_id().as_str(),
            &req,
            resolved_session.as_ref().map(|(sid, _)| sid.as_str()),
            effective_missed,
            expires_at,
        );

        let item_id = format!("wkp-item-{}", uuid_v4());
        let gate_session = resolved_session
            .as_ref()
            .map(|(sid, _)| sid.as_str())
            .unwrap_or("wakeup:topic");

        // 2. Optional Security Gate evaluation (fails closed on Block/Quarantine/Hold/Error).
        let gate_downgraded = match self
            .screen_wakeup_via_gate(&req, gate_session, &item_id, &formatted_text, &ce, now)
            .await
        {
            Ok(downgraded) => downgraded,
            Err(reason) => {
                if req.is_persisted_wakeup {
                    let db = self.node.db();
                    let _ = db.wakeups().record_delivery_result(
                        &req.wakeup_id,
                        false,
                        Some(&reason),
                        WakeupLimits::default().max_consecutive_failures,
                        now,
                    );
                }
                return Err(reason);
            }
        };

        // 3. Publish `to.hyphae.wakeup.v1` CloudEvent onto local topic `wakeup` (or `target_topic`).
        let _ = self.node.publish_event(topic, ce).await;

        let wakeup_source = format!("wakeup:{}", req.wakeup_id);
        let label_source = format!("wakeup:{}", req.label);
        let base_urgency = match req.urgency {
            WakeupUrgency::Interrupt => DeliveryUrgency::Interrupt,
            WakeupUrgency::Queue => DeliveryUrgency::Queue,
            WakeupUrgency::Notify => DeliveryUrgency::Notify,
        };
        let effective_urgency = if gate_downgraded && base_urgency == DeliveryUrgency::Interrupt {
            DeliveryUrgency::Queue
        } else {
            base_urgency
        };

        // 4. Targeted session path: durable coalesced SQLite mailbox + Tier 1-3 flush + Tier 4 fallback.
        if let Some((session_id, backend_json)) = resolved_session {
            let is_muted = {
                let db = self.node.db();
                db.local()
                    .is_muted(&session_id, &[&wakeup_source, &label_source, "wakeup"])
                    .ok()
                    .flatten()
                    .is_some()
            };
            let insert = MailboxInsert {
                session_id: session_id.clone(),
                origin_node: self.node.node_id().as_str().to_string(),
                item_id,
                text: formatted_text.clone(),
                kind: MailboxKind::Event,
                source: wakeup_source.clone(),
                gate_state: GateState::Pending,
                gate_reason: None,
                traceparent: None,
            };

            if is_muted {
                let db = self.node.db();
                let _ = archive_muted_entry(&db, &insert, now);
                if req.is_persisted_wakeup {
                    let _ = db.wakeups().record_delivery_result(
                        &req.wakeup_id,
                        true,
                        None,
                        WakeupLimits::default().max_consecutive_failures,
                        now,
                    );
                }
                return Ok(WakeupDeliveryOutcome {
                    delivered: false,
                    pushed: false,
                    session_id: Some(session_id),
                    receipt: None,
                    missed_count: effective_missed,
                    cold_revived: false,
                    muted: true,
                });
            }

            let put_opts = MailboxPutOptions {
                coalesce_key: req.coalesce_key.clone(),
                expires_at,
            };
            let (receipt, stored_missed) = {
                let db = self.node.db();
                match db
                    .local()
                    .put_in_mailbox_ex(&insert, &put_opts, now)
                    .map_err(|e| e.to_string())?
                {
                    MailboxPutResult::Stored { receipt } => {
                        let mc = db
                            .local()
                            .get_mailbox_entry_ex(&receipt)
                            .ok()
                            .flatten()
                            .map(|e| e.missed_count)
                            .unwrap_or(effective_missed);
                        (receipt, mc)
                    }
                    MailboxPutResult::Duplicate => {
                        return Ok(WakeupDeliveryOutcome {
                            delivered: true,
                            pushed: false,
                            session_id: Some(session_id),
                            receipt: None,
                            missed_count: effective_missed,
                            cold_revived: false,
                            muted: false,
                        });
                    }
                    MailboxPutResult::QueueFull => return Err("local_inbox_full".to_string()),
                }
            };

            self.record_item_meta(
                &session_id,
                receipt.clone(),
                ClassifiedItemMeta {
                    urgency: effective_urgency,
                    burst_demoted: false,
                    burst_source_key: wakeup_source,
                    channel: None,
                    is_announcement: false,
                    notified: false,
                },
            );

            let mut delivered = false;
            let mut cold_revived = false;
            let mut terminal_err: Option<String> = None;

            if self.has_live_transport(&session_id) {
                terminal_err = self.flush_session(&session_id).await;
                let still_pending = {
                    let db = self.node.db();
                    db.local()
                        .get_mailbox_entry(&receipt)
                        .ok()
                        .flatten()
                        .is_some_and(|e| e.gate_state == GateState::Pending)
                };
                if !still_pending {
                    delivered = true;
                }
            }

            // Tier 4 Opt-In Cold Revival when no live transport delivered (or transport reported terminal unavailability).
            if !delivered && (!self.has_live_transport(&session_id) || terminal_err.is_some()) {
                // 4a. Codex CLI opt-in `--resume` revival when no live transport is attached.
                let is_codex = session_id.starts_with("codex:")
                    || backend_json.contains("\"codex\"");
                if !self.has_live_transport(&session_id)
                    && self.config.wakeup.codex_resume
                    && is_codex
                {
                    let thread_id = session_id
                        .strip_prefix("codex:")
                        .unwrap_or(&session_id)
                        .to_string();
                    let codex_bin = self
                        .config
                        .codex_bin
                        .as_deref()
                        .unwrap_or(DEFAULT_CODEX_BIN);
                    let target = CodexQueueTarget::new(thread_id)
                        .with_bin(codex_bin.to_string())
                        .with_resume(true);
                    let transport = CodexQueueTransport::new(target);
                    if transport
                        .deliver(&formatted_text, PushMode::Queue)
                        .await
                        .is_delivered()
                    {
                        let db = self.node.db();
                        let _ = db
                            .local()
                            .acknowledge_inbox(&session_id, &[receipt.as_str()], now);
                        self.cancel_hold_retry(&session_id);
                        delivered = true;
                        cold_revived = true;
                        terminal_err = None;
                    }
                }

                // 4b. Allowlisted Herdr cold-spawn (`hc run <template> <prompt>`).
                if !delivered {
                    if let Some(ref tpl) = req.cold_revival_template {
                        match self
                            .try_herdr_cold_spawn(&req.wakeup_id, tpl, &formatted_text)
                            .await
                        {
                            PushOutcome::Delivered => {
                                let db = self.node.db();
                                let _ = db.local().acknowledge_inbox(
                                    &session_id,
                                    &[receipt.as_str()],
                                    now,
                                );
                                self.cancel_hold_retry(&session_id);
                                delivered = true;
                                cold_revived = true;
                                terminal_err = None;
                            }
                            PushOutcome::Reject { reason, .. } => {
                                terminal_err = Some(reason);
                            }
                            PushOutcome::Hold { .. } => {}
                        }
                    }
                }
            }

            if req.is_persisted_wakeup {
                let db = self.node.db();
                let succeeded = terminal_err.is_none();
                let _ = db.wakeups().record_delivery_result(
                    &req.wakeup_id,
                    succeeded,
                    terminal_err.as_deref(),
                    WakeupLimits::default().max_consecutive_failures,
                    now,
                );
            }

            if let Some(err) = terminal_err {
                if req.cold_revival_template.is_some()
                    && matches!(
                        err.as_str(),
                        "herdr_template_not_allowlisted"
                            | "herdr_invalid_prompt"
                            | "herdr_spawn_failed"
                    )
                {
                    return Err(err);
                }
            }

            return Ok(WakeupDeliveryOutcome {
                delivered: true,
                pushed: delivered,
                session_id: Some(session_id),
                receipt: Some(receipt),
                missed_count: stored_missed,
                cold_revived,
                muted: false,
            });
        }

        // 5. No live/registered target session resolved: try Tier 4 allowlisted Herdr cold-spawn!
        if let Some(ref tpl) = req.cold_revival_template {
            let outcome = self
                .try_herdr_cold_spawn(&req.wakeup_id, tpl, &formatted_text)
                .await;
            return match outcome {
                PushOutcome::Delivered => {
                    if req.is_persisted_wakeup {
                        let db = self.node.db();
                        let _ = db.wakeups().record_delivery_result(
                            &req.wakeup_id,
                            true,
                            None,
                            WakeupLimits::default().max_consecutive_failures,
                            now,
                        );
                    }
                    Ok(WakeupDeliveryOutcome {
                        delivered: true,
                        pushed: true,
                        session_id: None,
                        receipt: None,
                        missed_count: effective_missed,
                        cold_revived: true,
                        muted: false,
                    })
                }
                PushOutcome::Hold { .. } => Ok(WakeupDeliveryOutcome {
                    delivered: false,
                    pushed: false,
                    session_id: None,
                    receipt: None,
                    missed_count: effective_missed,
                    cold_revived: false,
                    muted: false,
                }),
                PushOutcome::Reject { reason, .. } => {
                    if req.is_persisted_wakeup {
                        let db = self.node.db();
                        let _ = db.wakeups().record_delivery_result(
                            &req.wakeup_id,
                            false,
                            Some(&reason),
                            WakeupLimits::default().max_consecutive_failures,
                            now,
                        );
                    }
                    Err(reason)
                }
            };
        }

        // 6. Topic-only wakeup (no explicit session/handle) succeeded via `publish_event`.
        if req.target_session_id.is_none() && req.target_handle.is_none() {
            if req.is_persisted_wakeup {
                let db = self.node.db();
                let _ = db.wakeups().record_delivery_result(
                    &req.wakeup_id,
                    true,
                    None,
                    WakeupLimits::default().max_consecutive_failures,
                    now,
                );
            }
            return Ok(WakeupDeliveryOutcome {
                delivered: true,
                pushed: false,
                session_id: None,
                receipt: None,
                missed_count: effective_missed,
                cold_revived: false,
                muted: false,
            });
        }

        // 7. Targeted session/handle unavailable and no cold-revival configured -> record failure.
        if req.is_persisted_wakeup {
            let db = self.node.db();
            let _ = db.wakeups().record_delivery_result(
                &req.wakeup_id,
                false,
                Some("target_session_unavailable"),
                WakeupLimits::default().max_consecutive_failures,
                now,
            );
        }
        Ok(WakeupDeliveryOutcome {
            delivered: false,
            pushed: false,
            session_id: None,
            receipt: None,
            missed_count: effective_missed,
            cold_revived: false,
            muted: false,
        })
    }

    fn has_plugins_capability(&self) -> bool {
        self.config.enable_plugins
            || !self
                .bridge_posters
                .lock()
                .expect("bridge_posters lock poisoned")
                .is_empty()
            || !self
                .configured_bridge_targets
                .lock()
                .expect("configured_bridge_targets lock poisoned")
                .is_empty()
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
        let mut map = self
            .session_transports
            .lock()
            .expect("session_transports lock poisoned");
        if let Some(existing) = map.get(session_id) {
            if existing.priority > priority {
                return false;
            }
        }
        map.insert(
            session_id.to_string(),
            AttachedPushTransport {
                transport,
                priority,
            },
        );
        true
    }

    fn current_transport_priority(&self, session_id: &str) -> u8 {
        self.session_transports
            .lock()
            .expect("session_transports lock poisoned")
            .get(session_id)
            .map(|t| t.priority)
            .unwrap_or(0)
    }

    fn active_transport_kind(&self, session_id: &str) -> Option<&'static str> {
        if self
            .channels
            .lock()
            .expect("channels lock poisoned")
            .contains_key(session_id)
        {
            return Some("claude_channel");
        }
        if let Some(attached) = self
            .session_transports
            .lock()
            .expect("session_transports lock poisoned")
            .get(session_id)
        {
            return Some(attached.transport.kind());
        }
        let waiters = self.waiters.lock().expect("waiters lock poisoned");
        if let Some(list) = waiters.get(session_id) {
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

    fn transport_summary_json(&self, session_id: &str) -> Value {
        match self.active_transport_kind(session_id) {
            Some(kind) => json!({ "live": true, "kind": kind }),
            None => json!({ "live": false, "kind": "none" }),
        }
    }

    async fn wait_for_pending_probe(&self, session_id: &str) {
        let rx_opt = self
            .pending_probes
            .lock()
            .expect("pending_probes lock poisoned")
            .get(session_id)
            .cloned();
        if let Some(mut rx) = rx_opt {
            let _ = tokio::time::timeout(
                Duration::from_millis(1_500),
                rx.wait_for(|done| *done),
            )
            .await;
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

    fn is_announcement_channel(&self, channel: Option<&str>) -> bool {
        let Some(ch) = channel else {
            return false;
        };
        self.node.get_channel_policy(ch).mode == ChannelMode::Announcement
    }

    fn lookup_subscription_urgency(
        &self,
        session_id: &str,
        origin_node: &str,
        source: &str,
    ) -> Option<DeliveryUrgency> {
        let guard = self.sub_meta.lock().expect("sub_meta lock poisoned");
        let list = guard.get(session_id)?;
        let src_low = source.to_ascii_lowercase();
        let origin_low = origin_node.to_ascii_lowercase();
        list.iter()
            .find(|s| {
                let expected = format!("{}.{}", s.origin_node.to_ascii_lowercase(), s.topic.to_ascii_lowercase());
                src_low == expected || (origin_low == s.origin_node.to_ascii_lowercase() && src_low.ends_with(&format!(".{}", s.topic.to_ascii_lowercase())))
            })
            .map(|s| s.urgency)
    }

    fn record_item_meta(&self, session_id: &str, receipt: String, meta: ClassifiedItemMeta) {
        let mut guard = self.item_meta.lock().expect("item_meta lock poisoned");
        guard
            .entry(session_id.to_string())
            .or_default()
            .insert(receipt, meta);
    }

    /// Reconciles any newly arrived raw `Pending` entries in `NodeDb` for `session_id` through
    /// optional `SecurityGatePipeline` + `DeliveryEngine`:
    /// - `Quarantine`/`Block` items are removed from `Pending` (never leak to agent).
    /// - `Mute` items are silently archived (`move_pending_to_muted`) and NEVER trigger a wake.
    /// - `Interrupt`/`Queue`/`Notify` items are tagged with their resolved urgency & burst metadata.
    ///
    /// Returns `true` if at least one non-muted item is eligible for delivery/digest wake.
    async fn reconcile_session_inbox(&self, session_id: &str) -> bool {
        let pending = {
            let db = self.node.db();
            db.local().peek_inbox(session_id, 500).unwrap_or_default()
        };
        if pending.is_empty() {
            return false;
        }

        let mut wake_needed = false;
        let now = now_ms();

        for entry in pending {
            let already_dismissed = self
                .dismissed_receipts
                .lock()
                .expect("dismissed lock poisoned")
                .contains(&entry.receipt);
            if already_dismissed {
                let db = self.node.db();
                let _ = db
                    .local()
                    .acknowledge_inbox(session_id, &[entry.receipt.as_str()], now);
                continue;
            }

            let existing_meta = self
                .item_meta
                .lock()
                .expect("item_meta lock poisoned")
                .get(session_id)
                .and_then(|m| m.get(&entry.receipt).cloned());
            if let Some(meta) = existing_meta {
                if meta.urgency.triggers_delivery_or_digest() && !meta.notified {
                    wake_needed = true;
                }
                continue;
            }

            // Newly arrived raw item from `UnifiedNode`!
            // Skip re-evaluating items that were already explicitly approved by a human operator
            // via `hyp inbox approve` (`reviewed_at.is_some()`), so an approved quarantined item is
            // delivered instead of immediately re-quarantined.
            let mut gate_downgraded = false;
            if entry.reviewed_at.is_none() {
                if let Some(ref pipeline) = self.gate {
                    let parsed = hyp_node::delivery::ParsedMailboxSource::from_entry(&entry);
                    let effective_origin = self.effective_gate_origin(&entry, &parsed);
                    let trust_tier = self.resolve_peer_trust_tier(&effective_origin);
                    let ce = ProtoCloudEvent {
                        specversion: "1.0".into(),
                        id: format!("gate:{}", entry.item_id),
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
                    };
                    match pipeline.evaluate_inbound(&ctx, now).await {
                        Ok(eval) => match eval.decision {
                            GateDecision::Allow {
                                downgraded_to_notify,
                            } => {
                                gate_downgraded = downgraded_to_notify;
                                // If pipeline shares the same SQLite DB and inserted a duplicate `gate:` row,
                                // dismiss the duplicate so we keep exactly one row (`entry.receipt`).
                                if let Some(dup_receipt) = eval.receipt {
                                    if dup_receipt != entry.receipt {
                                        self.dismissed_receipts
                                            .lock()
                                            .expect("dismissed lock poisoned")
                                            .insert(dup_receipt.clone());
                                        let db = self.node.db();
                                        let _ = db.local().acknowledge_inbox(
                                            session_id,
                                            &[dup_receipt.as_str()],
                                            now,
                                        );
                                    }
                                }
                            }
                            GateDecision::Quarantine { .. }
                            | GateDecision::Block { .. }
                            | GateDecision::Hold { .. } => {
                                self.dismissed_receipts
                                    .lock()
                                    .expect("dismissed lock poisoned")
                                    .insert(entry.receipt.clone());
                                let db = self.node.db();
                                let _ = db
                                    .local()
                                    .acknowledge_inbox(session_id, &[entry.receipt.as_str()], now);
                                continue;
                            }
                        },
                        Err(_) => {
                            // Fail closed on gate error: suppress delivery.
                            self.dismissed_receipts
                                .lock()
                                .expect("dismissed lock poisoned")
                                .insert(entry.receipt.clone());
                            let db = self.node.db();
                            let _ = db
                                .local()
                                .acknowledge_inbox(session_id, &[entry.receipt.as_str()], now);
                            continue;
                        }
                    }
                }
            }

            if let Some(u) = self
                .classify_and_route_pending_entry(session_id, &entry.receipt, gate_downgraded, now)
                .await
            {
                if u.triggers_delivery_or_digest() {
                    wake_needed = true;
                }
            }
        }

        wake_needed
    }

    async fn classify_and_route_pending_entry(
        &self,
        session_id: &str,
        receipt: &str,
        gate_downgraded: bool,
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
                .classify_entry(&db, session_id, &entry, sub_mode, gate_downgraded, now)
                .ok()?
        };

        if classification.effective_urgency == DeliveryUrgency::Mute {
            let db = self.node.db();
            let _ = move_pending_to_muted(&db, session_id, &entry, now);
            return Some(DeliveryUrgency::Mute);
        }

        let is_announcement =
            self.is_announcement_channel(classification.parsed.channel.as_deref());
        self.record_item_meta(
            session_id,
            entry.receipt,
            ClassifiedItemMeta {
                urgency: classification.effective_urgency,
                burst_demoted: classification.burst.demoted,
                burst_source_key: classification.burst_source_key,
                channel: classification.parsed.channel,
                is_announcement,
                notified: entry.notified,
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

    fn resolve_peer_trust_tier(&self, origin_node: &str) -> GateTrustTier {
        if origin_node == "local" || origin_node == self.node.node_id().as_str() {
            return GateTrustTier::SelfHost;
        }
        let db = self.node.db();
        if let Ok(Some(peer)) = db.peers().get_peer(origin_node) {
            return GateTrustTier::from(peer.trust_tier);
        }
        GateTrustTier::Peer
    }

    /// Builds a token-budgeted [`PackedDeliveryBatch`] for `session_id` from pending unread items.
    ///
    /// - Excludes already-notified `Notify`-tier items when there are NO unnotified items and NO
    ///   `Interrupt`/`Queue` items (prevents re-emitting identical `notify` digests in a loop).
    /// - Strictly returns `None` when zero eligible unread items exist (even if `muted_count > 0`!).
    async fn build_batch_for_session(&self, session_id: &str) -> Option<PackedDeliveryBatch> {
        self.reconcile_session_inbox(session_id).await;

        let (policy, pending, muted) = {
            let db = self.node.db();
            let policy = self.delivery.policy(&db, session_id).ok()?;
            let pending = db.local().peek_inbox(session_id, 500).ok()?;
            let muted = muted_count(&db, session_id).unwrap_or(0);
            (policy, pending, muted)
        };

        if pending.is_empty() {
            return None;
        }

        let meta_snapshot: HashMap<String, ClassifiedItemMeta> = self
            .item_meta
            .lock()
            .expect("item_meta lock poisoned")
            .get(session_id)
            .cloned()
            .unwrap_or_default();

        let mut packable: Vec<PackableItem> = Vec::with_capacity(pending.len());
        let mut any_unnotified = false;

        for entry in pending {
            let meta = meta_snapshot.get(&entry.receipt);
            let urgency = meta
                .map(|m| m.urgency)
                .unwrap_or(policy.default_mode);
            if urgency == DeliveryUrgency::Mute {
                continue;
            }
            let burst_demoted = meta.is_some_and(|m| m.burst_demoted);
            let already_notified = entry.notified || meta.is_some_and(|m| m.notified);

            if !already_notified {
                any_unnotified = true;
            }

            // Items already notified in an earlier digest or truncated preview stay in the unread
            // footer band (Notify) when a newer unnotified item arrives so they are never re-dumped
            // or re-truncated in a loop.
            let effective_urgency = if already_notified {
                DeliveryUrgency::Notify
            } else {
                urgency
            };

            let parsed = hyp_node::delivery::ParsedMailboxSource::from_entry(&entry);
            let channel = meta
                .and_then(|m| m.channel.clone())
                .or(parsed.channel);
            let is_announcement = meta
                .map(|m| m.is_announcement)
                .unwrap_or_else(|| self.is_announcement_channel(channel.as_deref()));

            packable.push(PackableItem {
                id: entry.receipt,
                urgency: effective_urgency,
                kind: entry.kind,
                source: entry.source,
                channel,
                is_announcement,
                text: entry.text,
                created_at_ms: entry.received_at,
                burst_demoted,
            });
        }

        if packable.is_empty() || !any_unnotified {
            return None;
        }

        pack_delivery_batch(&packable, muted, &policy)
    }

    /// Commits a delivered [`PackedDeliveryBatch`]:
    /// - Inline full items -> transitioned `pending -> delivered` + recorded in delivered archive.
    /// - Spilled & truncated items -> kept `unread` (`Pending`) in `NodeDb` and marked `notified = 1`.
    fn commit_delivered_batch(&self, session_id: &str, batch: &PackedDeliveryBatch) {
        let now = now_ms();
        {
            let db = self.node.db();
            if !batch.inline_ids.is_empty() {
                let refs: Vec<&str> = batch.inline_ids.iter().map(String::as_str).collect();
                let _ = db.local().acknowledge_inbox(session_id, &refs, now);
                let _ = record_delivered_receipts(&db, session_id, &batch.inline_ids);
            }
            if !batch.spilled_ids.is_empty() || !batch.truncated_ids.is_empty() {
                let _ = db.local().mark_mailbox_notified(session_id);
            }
        }

        let mut sources_delivered: HashSet<String> = HashSet::new();
        {
            let mut guard = self.item_meta.lock().expect("item_meta lock poisoned");
            if let Some(map) = guard.get_mut(session_id) {
                for id in &batch.inline_ids {
                    if let Some(m) = map.remove(id) {
                        sources_delivered.insert(m.burst_source_key);
                    }
                }
                for id in batch.spilled_ids.iter().chain(batch.truncated_ids.iter()) {
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
    }

    /// Flushes eligible batches to live transports (`claude-channel` > `PushTransport` > `watch` stream > `wait` once).
    ///
    /// On transient `PushTransport` `Hold` outcomes (`herdr_working`, `herdr_send_guard_refused`,
    /// `herdr_agent_not_ready`, `t3_server_unreachable`, `codex_queue_unavailable`), schedules
    /// a bounded Tier 3 retry backoff task (zero polling when idle).
    ///
    /// Returns `Some(terminal_reason)` if a transport reported terminal target unavailability
    /// (`herdr_target_unavailable`, `t3_thread_deleted`, `t3_thread_not_found`).
    async fn flush_session(self: &Arc<Self>, session_id: &str) -> Option<String> {
        {
            let mut f = self.flushing.lock().expect("flushing lock poisoned");
            if !f.insert(session_id.to_string()) {
                return None;
            }
        }

        struct FlushGuard<'a> {
            flushing: &'a Mutex<HashSet<String>>,
            session_id: String,
        }
        impl Drop for FlushGuard<'_> {
            fn drop(&mut self) {
                self.flushing
                    .lock()
                    .expect("flushing lock poisoned")
                    .remove(&self.session_id);
            }
        }
        let _guard = FlushGuard {
            flushing: &self.flushing,
            session_id: session_id.to_string(),
        };

        let mut terminal_error: Option<String> = None;

        loop {
            let Some(batch) = self.build_batch_for_session(session_id).await else {
                self.cancel_hold_retry(session_id);
                break;
            };

            // Priority 1: Live Claude native channel (`--claude-channel`)
            let channel_entry = self
                .channels
                .lock()
                .expect("channels lock poisoned")
                .get(session_id)
                .map(|c| (c.conn_id, c.tx.clone()));
            if let Some((channel_conn_id, tx)) = channel_entry {
                let delivery_id = self.next_seq();
                let (ack_tx, ack_rx) = oneshot::channel();
                if tx
                    .send(ChannelDeliverCommand {
                        delivery_id,
                        text: batch.rendered.clone(),
                        ack_tx,
                    })
                    .is_ok()
                {
                    let submitted =
                        tokio::time::timeout(self.config.channel_deliver_timeout, ack_rx)
                            .await
                            .ok()
                            .and_then(Result::ok)
                            .unwrap_or(false);
                    if submitted {
                        self.commit_delivered_batch(session_id, &batch);
                        // Stop loop if notify-only (already marked notified so next iteration would break).
                        continue;
                    }
                }
                // If the same channel connection is still attached (explicit nack or timeout),
                // keep the batch preserved as unread for hook/`hyp_inbox` fallback instead of
                // spinning on the stalled channel. If the channel disconnected, fall through to
                // any live `watch`/`wait` transport!
                let still_attached = self
                    .channels
                    .lock()
                    .expect("channels lock poisoned")
                    .get(session_id)
                    .is_some_and(|c| c.conn_id == channel_conn_id);
                if still_attached {
                    break;
                }
            }

            // Priority 2: Attached native external PushTransport (Herdr > T3 Code > Codex Queue)
            let mut deferred_transient_hold = false;
            let push_transport = self
                .session_transports
                .lock()
                .expect("session_transports lock poisoned")
                .get(session_id)
                .map(|a| Arc::clone(&a.transport));
            if let Some(transport) = push_transport {
                let push_mode = if batch.max_urgency == DeliveryUrgency::Interrupt
                    && transport.supports_interrupt()
                {
                    PushMode::Interrupt
                } else {
                    PushMode::Queue
                };
                match transport.deliver(&batch.rendered, push_mode).await {
                    PushOutcome::Delivered => {
                        self.commit_delivered_batch(session_id, &batch);
                        continue;
                    }
                    PushOutcome::Hold { ref reason, .. }
                        if matches!(
                            reason.as_str(),
                            "herdr_working" | "herdr_send_guard_refused" | "herdr_agent_not_ready"
                        ) =>
                    {
                        // Target is actively working or has an in-progress user draft;
                        // preserve unread in durable SQLite and schedule bounded Tier 3 retry.
                        self.schedule_hold_retry(session_id);
                        break;
                    }
                    PushOutcome::Hold { ref reason, .. }
                        if matches!(
                            reason.as_str(),
                            "t3_server_unreachable" | "codex_queue_unavailable"
                        ) =>
                    {
                        // Transient transport unavailability: fall through to any live waiter;
                        // if none delivers, schedule bounded Tier 3 retry before exiting.
                        deferred_transient_hold = true;
                    }
                    PushOutcome::Hold { ref reason, .. } | PushOutcome::Reject { ref reason, .. } => {
                        if matches!(
                            reason.as_str(),
                            "herdr_target_unavailable"
                                | "t3_thread_deleted"
                                | "t3_thread_not_found"
                        ) {
                            terminal_error = Some(reason.clone());
                        }
                        self.cancel_hold_retry(session_id);
                        // Preserve unread in durable SQLite; fall through to any live
                        // `watch`/`wait` waiter if one is attached, else exit flush loop.
                    }
                }
            }

            // Priority 3: Streaming watcher (`hyp watch` / `inbox.watch`)
            let stream_tx = self
                .waiters
                .lock()
                .expect("waiters lock poisoned")
                .get(session_id)
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
                        "received": now_ms() / 1000,
                        "text": batch.rendered,
                        "notifyOnly": batch.notify_only,
                        "mutedCount": batch.muted_count,
                    }]
                });
                if tx.send(pkt).is_ok() {
                    self.commit_delivered_batch(session_id, &batch);
                    continue;
                }
            }

            // Priority 3: One-shot blocking waiter (`hyp wait` / `inbox.wait`)
            let once_waiter = {
                let mut map = self.waiters.lock().expect("waiters lock poisoned");
                let extracted = map.get_mut(session_id).and_then(|list| {
                    list.iter()
                        .position(|w| w.mode == WaiterKind::Once)
                        .map(|idx| list.remove(idx))
                });
                if map.get(session_id).is_some_and(Vec::is_empty) {
                    map.remove(session_id);
                }
                extracted
            };
            if let Some(waiter) = once_waiter {
                let pkt = json!({
                    "type": "wait.items",
                    "items": [{
                        "router": self.node.node_id().as_str(),
                        "received": now_ms() / 1000,
                        "text": batch.rendered,
                        "notifyOnly": batch.notify_only,
                        "mutedCount": batch.muted_count,
                    }]
                });
                if waiter.tx.send(pkt).is_ok() {
                    self.commit_delivered_batch(session_id, &batch);
                    continue;
                }
            }

            if deferred_transient_hold {
                self.schedule_hold_retry(session_id);
            }
            break;
        }

        terminal_error
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
            let now = now_ms();
            if db.local().get_session(session_id).ok().flatten().is_none() {
                let _ = db.local().register_session(session_id, "{}", now);
            } else {
                let _ = db.local().touch_session(session_id, now);
            }
        }

        match name {
            "hyp_mesh" => self.tool_mesh(session_id, args).await,
            "hyp_session" => self.tool_session(session_id, args).await,
            "hyp_join" => self.tool_join(session_id, args).await,
            "hyp_leave" => self.tool_leave(session_id).await,
            "hyp_peers" => self.tool_peers(session_id).await,
            "hyp_capabilities" => self.tool_capabilities(session_id).await,
            "hyp_mode" => self.tool_mode(session_id, args).await,
            "hyp_mute" => self.tool_mute(session_id, args).await,
            "hyp_unmute" => self.tool_unmute(session_id, args).await,
            "hyp_mutes" => self.tool_mutes(session_id).await,
            "hyp_channel" => self.tool_channel(session_id, args).await,
            "hyp_channel_join" => self.tool_channel_join(session_id, args).await,
            "hyp_channel_leave" => self.tool_channel_leave(session_id, args).await,
            "hyp_channel_post" => self.tool_channel_post(session_id, args).await,
            "hyp_channels" => self.tool_channels(args).await,
            "hyp_send" => self.tool_send(session_id, args).await,
            "hyp_inbox" => self.tool_inbox(session_id, args).await,
            "hyp_stream" => self.tool_stream(session_id, args).await,
            "hyp_subscribe" => self.tool_subscribe(session_id, args).await,
            "hyp_unsubscribe" => self.tool_unsubscribe(session_id, args).await,
            "hyp_subscriptions" => self.tool_subscriptions(session_id).await,
            "hyp_topics" => self.tool_topics(args).await,
            "hyp_kv" => self.tool_kv(args).await,
            "hyp_wakeup" => self.tool_wakeup(session_id, args).await,
            "hyp_bridge" => self.tool_bridge(session_id, args).await,
            "hyp_plugin_targets" => self.tool_bridge_targets(session_id).await,
            "hyp_bridge_link" => self.tool_bridge_link(session_id, args).await,
            "hyp_bridge_unlink" => self.tool_bridge_unlink(session_id, args).await,
            "hyp_plugin_handoff" => self.tool_bridge_handoff(session_id, args).await,
            "hyp_plugin_post" => self.tool_plugin_post(session_id, args).await,
            other => Err(("unknown_tool".into(), format!("Unknown tool {other}"))),
        }
    }

    async fn tool_mesh(
        self: &Arc<Self>,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        let action = args
            .get("action")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                (
                    "invalid_request".into(),
                    "Expected action: join | leave | peers | channels | status".into(),
                )
            })?;
        let has_channel = args
            .get("channel")
            .and_then(Value::as_str)
            .is_some_and(|c| !c.is_empty());
        match action {
            "channels" => self.tool_channels(args).await,
            "join" if has_channel => self.tool_channel_join(session_id, args).await,
            "leave" if has_channel => self.tool_channel_leave(session_id, args).await,
            _ => self.tool_session(session_id, args).await,
        }
    }

    async fn tool_session(
        self: &Arc<Self>,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        let action = args
            .get("action")
            .and_then(Value::as_str)
            .ok_or_else(|| ("invalid_request".into(), "Expected session action".into()))?;
        match action {
            "join" => self.tool_join(session_id, args).await,
            "leave" => self.tool_leave(session_id).await,
            "peers" => self.tool_peers(session_id).await,
            "status" => self.tool_capabilities(session_id).await,
            "mode" => self.tool_mode(session_id, args).await,
            "mute" => self.tool_mute(session_id, args).await,
            "unmute" => self.tool_unmute(session_id, args).await,
            "mutes" => self.tool_mutes(session_id).await,
            other => Err((
                "invalid_request".into(),
                format!("Unsupported session action '{other}'"),
            )),
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
            .ok_or_else(|| ("invalid_request".into(), "Expected handle".into()))?;
        let description = args.get("description").and_then(Value::as_str);
        let rec = self
            .node
            .register_handle_with_description(session_id, handle, description)
            .await
            .map_err(node_err_tuple)?;

        let (policy, unread, muted) = {
            let db = self.node.db();
            let p = self.delivery.policy(&db, session_id).unwrap_or_default();
            let u = db.local().pending_count(session_id).unwrap_or(0);
            let m = muted_count(&db, session_id).unwrap_or(0);
            (p, u, m)
        };

        self.wait_for_pending_probe(session_id).await;
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
        Ok(Value::Object(out))
    }

    async fn tool_leave(&self, session_id: &str) -> Result<Value, (String, String)> {
        let now = now_ms();
        let left = {
            let db = self.node.db();
            let _ = db.wakeups().cancel_owned_by_session(session_id, now);
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

    async fn tool_capabilities(&self, session_id: &str) -> Result<Value, (String, String)> {
        self.reconcile_session_inbox(session_id).await;
        let (sess, policy, unread, muted, mutes_len, peers) = {
            let db = self.node.db();
            let sess = db.local().get_session(session_id).ok().flatten();
            let policy = self.delivery.policy(&db, session_id).unwrap_or_default();
            let unread = db.local().pending_count(session_id).unwrap_or(0);
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

    async fn tool_mode(
        self: &Arc<Self>,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        let mode_raw = args
            .get("mode")
            .and_then(Value::as_str)
            .ok_or_else(|| ("invalid_request".into(), "Expected mode: 'queue' | 'notify'".into()))?;
        let allow_vips = args
            .get("focusAllowInterruptVips")
            .and_then(Value::as_bool);
        let extra_rules = parse_rules_arg(args)?;

        let (focus_mode, default_urgency, store_mode) = match mode_raw.trim().to_ascii_lowercase().as_str() {
            "notify" => (true, DeliveryUrgency::Notify, DeliveryMode::Notify),
            "queue" | "full" => (false, DeliveryUrgency::Queue, DeliveryMode::Full),
            other => {
                return Err((
                    "invalid_request".into(),
                    format!("Expected mode 'queue' | 'full' | 'notify', got '{other}'"),
                ));
            }
        };

        let now = now_ms();
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
                    for rule in &extra_rules {
                        p.upsert_rule(rule.clone());
                    }
                })
                .map_err(delivery_err_tuple)?;
            for rule in &extra_rules {
                if rule.delivery == DeliveryUrgency::Mute {
                    let _ = db.local().add_mute(session_id, &rule.target, session_id, now);
                }
            }
            let unread = db.local().pending_count(session_id).unwrap_or(0);
            let muted = muted_count(&db, session_id).unwrap_or(0);
            (policy, unread, muted)
        };

        if !focus_mode && unread > 0 {
            self.flush_session(session_id).await;
        }

        Ok(json!({
            "deliveryMode": policy.default_mode.as_str(),
            "focusMode": policy.focus_mode,
            "focusAllowInterruptVips": policy.focus_allow_interrupt_vips,
            "rules": policy.overrides,
            "unread": unread,
            "muted": muted,
        }))
    }

    async fn tool_mute(
        &self,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        let target = args
            .get("target")
            .or_else(|| args.get("mute"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ("invalid_request".into(), "Expected mute target".into()))?;
        let scope_arg = args.get("scope").and_then(Value::as_str).unwrap_or("session");
        let db_scope = if scope_arg == "connector" { "*" } else { session_id };
        let now = now_ms();

        let rule = {
            let db = self.node.db();
            let added = db
                .local()
                .add_mute(db_scope, target, session_id, now)
                .map_err(store_err_tuple)?;
            let _ = self.delivery.update_policy(&db, session_id, |p| {
                p.upsert_rule(DeliveryRule::new(target, DeliveryUrgency::Mute));
            });
            added
        };

        Ok(json!({
            "muted": rule.pattern,
            "scope": if db_scope == "*" { "connector" } else { "session" },
        }))
    }

    async fn tool_unmute(
        &self,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        let target = args
            .get("target")
            .or_else(|| args.get("unmute"))
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ("invalid_request".into(), "Expected unmute target".into()))?;
        let scope_arg = args.get("scope").and_then(Value::as_str).unwrap_or("session");
        let db_scope = if scope_arg == "connector" { "*" } else { session_id };

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

        Ok(json!({
            "pattern": target.to_ascii_lowercase(),
            "scope": if db_scope == "*" { "connector" } else { "session" },
            "removed": removed,
        }))
    }

    async fn tool_mutes(&self, session_id: &str) -> Result<Value, (String, String)> {
        let rules = {
            let db = self.node.db();
            db.local()
                .list_mutes(Some(session_id))
                .map_err(store_err_tuple)?
        };
        let list: Vec<Value> = rules
            .into_iter()
            .map(|r| {
                json!({
                    "pattern": r.pattern,
                    "scope": if r.scope == "*" { "connector" } else { "session" },
                    "mutedAt": r.muted_at,
                    "mutedBy": r.muted_by,
                })
            })
            .collect();
        Ok(json!({ "mutes": list }))
    }

    async fn tool_channel(
        &self,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        match args.get("action").and_then(Value::as_str) {
            Some("join") => self.tool_channel_join(session_id, args).await,
            Some("leave") => self.tool_channel_leave(session_id, args).await,
            Some("list") => self.tool_channels(args).await,
            _ => Err((
                "invalid_request".into(),
                "Expected channel action: join | leave | list".into(),
            )),
        }
    }

    async fn tool_channel_join(
        &self,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        let ch = args
            .get("channel")
            .and_then(Value::as_str)
            .ok_or_else(|| ("invalid_request".into(), "Expected channel name".into()))?;
        let handle = self.require_session_handle(session_id)?;
        let resp = self
            .node
            .join_channel(ch, &handle)
            .await
            .map_err(node_err_tuple)?;
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
            .ok_or_else(|| ("invalid_request".into(), "Expected channel name".into()))?;
        let handle = self.require_session_handle(session_id)?;
        let left = self
            .node
            .leave_channel(ch, &handle)
            .await
            .map_err(node_err_tuple)?;
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
            .ok_or_else(|| ("invalid_request".into(), "Expected channel name".into()))?;
        let text = args
            .get("text")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ("invalid_request".into(), "Expected non-empty text".into()))?;
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
            .ok_or_else(|| ("invalid_request".into(), "Expected destination 'to'".into()))?;
        let handle = self.require_session_handle(session_id)?;

        // File transfer path
        if let Some(files_val) = args.get("files").and_then(Value::as_array) {
            let paths: Vec<PathBuf> = files_val
                .iter()
                .filter_map(Value::as_str)
                .map(PathBuf::from)
                .collect();
            if paths.is_empty() {
                return Err(("invalid_request".into(), "Expected non-empty files array".into()));
            }
            let (target_node, to_handle) = parse_address(to).ok_or_else(|| {
                (
                    "invalid_request".into(),
                    "File transfers require <node>/<handle> destination".into(),
                )
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

        let text = args
            .get("text")
            .and_then(Value::as_str)
            .ok_or_else(|| ("invalid_request".into(), "Expected 'text'".into()))?;

        // `#channel` or `<node>/#channel`
        if to.starts_with('#') || to.contains("/#") {
            let mut ch_args = Map::new();
            ch_args.insert("channel".into(), json!(to));
            ch_args.insert("text".into(), json!(text));
            return self.tool_channel_post(session_id, &ch_args).await;
        }

        // Local bridge `<plugin>:<target>`
        if is_bridge_destination(to) {
            let (raw_plugin, raw_target) = to.split_once(':').ok_or_else(|| {
                (
                    "invalid_request".into(),
                    format!("Invalid bridge destination '{to}'"),
                )
            })?;
            return self
                .send_to_bridge(session_id, &handle, raw_plugin, raw_target, text, args)
                .await;
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
        let allow_vips_opt = args
            .get("focusAllowInterruptVips")
            .and_then(Value::as_bool);

        if !rules.is_empty() || focus_mode_opt.is_some() || allow_vips_opt.is_some() {
            let now = now_ms();
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
                        db.local().pending_count(session_id).unwrap_or(0),
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
        let ack = args
            .get("acknowledgeAll")
            .or_else(|| args.get("ack"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
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

        let query = InboxQuery {
            state,
            filter,
            cursor,
            limit,
            summary_only,
            ack,
            ids,
        };

        let (result, policy) = {
            let db = self.node.db();
            let res = query_inbox(&db, session_id, &query, now_ms()).map_err(delivery_err_tuple)?;
            let pol = self.delivery.policy(&db, session_id).unwrap_or_default();
            (res, pol)
        };

        // Clean up in-memory item_meta for acknowledged receipts, and cancel any pending
        // Tier 3 Hold retries if the session's pending inbox is now empty.
        if result.acked_count > 0 {
            let mut guard = self.item_meta.lock().expect("item_meta lock poisoned");
            if let Some(map) = guard.get_mut(session_id) {
                for item in &result.items {
                    map.remove(&item.receipt);
                }
            }
            if result.unread_count == 0 {
                self.cancel_hold_retry(session_id);
            }
        }

        Ok(json!({
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
        }))
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
            _ => Err((
                "invalid_request".into(),
                "Expected hyp_stream action: topics | subscribe | unsubscribe | list".into(),
            )),
        }
    }

    async fn tool_topics(&self, args: &Map<String, Value>) -> Result<Value, (String, String)> {
        let router_filter = args.get("router").and_then(Value::as_str);
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
            .ok_or_else(|| ("invalid_request".into(), "Expected topic".into()))?;
        let router = args.get("router").and_then(Value::as_str);
        let qualified_topic = match router {
            Some("primary") | None => raw_topic.to_string(),
            Some(r) => format!("{r}.{raw_topic}"),
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
        let urgency = match args.get("mode").and_then(Value::as_str) {
            Some(raw) => DeliveryUrgency::parse(raw).map_err(delivery_err_tuple)?,
            None => DeliveryUrgency::Queue,
        };
        let key = args
            .get("key")
            .and_then(Value::as_str)
            .map(ToString::to_string);

        // Reuse existing subscription ID if caller supplied matching `key`.
        let existing_id = key.as_deref().and_then(|k| {
            let guard = self.sub_meta.lock().expect("sub_meta lock poisoned");
            guard
                .get(session_id)?
                .iter()
                .find(|s| s.key.as_deref() == Some(k))
                .map(|s| s.id.clone())
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
            let mut guard = self.sub_meta.lock().expect("sub_meta lock poisoned");
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

    async fn tool_unsubscribe(
        &self,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        let id_arg = args.get("id").and_then(Value::as_str);
        let key_arg = args.get("key").and_then(Value::as_str);
        let target_id = if let Some(id) = id_arg {
            Some(id.to_string())
        } else if let Some(key) = key_arg {
            let guard = self.sub_meta.lock().expect("sub_meta lock poisoned");
            guard
                .get(session_id)
                .and_then(|list| {
                    list.iter()
                        .find(|s| s.key.as_deref() == Some(key) || s.id == key)
                        .map(|s| s.id.clone())
                })
                .or_else(|| Some(key.to_string()))
        } else {
            return Err(("invalid_request".into(), "Expected id or key".into()));
        };

        let removed = if let Some(sub_id) = target_id {
            let db_removed = {
                let db = self.node.db();
                db.events()
                    .delete_subscription(&sub_id)
                    .map_err(store_err_tuple)?
            };
            let mut guard = self.sub_meta.lock().expect("sub_meta lock poisoned");
            if let Some(list) = guard.get_mut(session_id) {
                list.retain(|s| s.id != sub_id);
            }
            db_removed
        } else {
            false
        };

        Ok(json!({ "removed": removed }))
    }

    async fn tool_subscriptions(&self, session_id: &str) -> Result<Value, (String, String)> {
        let subs = {
            let db = self.node.db();
            db.events()
                .list_subscriptions(Some(session_id))
                .map_err(store_err_tuple)?
        };
        let meta_map: HashMap<String, SubscriptionRecordMeta> = self
            .sub_meta
            .lock()
            .expect("sub_meta lock poisoned")
            .get(session_id)
            .map(|l| l.iter().map(|m| (m.id.clone(), m.clone())).collect())
            .unwrap_or_default();

        let list: Vec<Value> = subs
            .into_iter()
            .map(|s| {
                let meta = meta_map.get(&s.id);
                let mode_str = meta
                    .map(|m| m.urgency.as_str())
                    .unwrap_or_else(|| s.mode.as_str());
                json!({
                    "id": s.id,
                    "key": meta.and_then(|m| m.key.clone()),
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
            .ok_or_else(|| ("invalid_request".into(), "Expected hyp_kv action".into()))?;
        let namespace = args
            .get("namespace")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| ("invalid_request".into(), "Expected namespace".into()))?;

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
                    .ok_or_else(|| ("invalid_request".into(), "Expected key".into()))?;
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
                    .ok_or_else(|| ("invalid_request".into(), "Expected key".into()))?;
                let value = args
                    .get("value")
                    .cloned()
                    .ok_or_else(|| ("invalid_request".into(), "Expected value".into()))?;
                let write_model = match args.get("writeModel").and_then(Value::as_str) {
                    Some("shared") => WriteModel::Shared,
                    Some("allowlist") => WriteModel::Allowlist,
                    _ => WriteModel::Owner,
                };
                let expected_version = args.get("expectedVersion").and_then(Value::as_u64);
                let ttl_ms = args.get("ttlMs").and_then(Value::as_i64);
                let encrypt = args.get("encrypt").and_then(Value::as_bool).unwrap_or(false);
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
                        allowlist: None,
                        expected_version,
                        ttl_ms,
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
                    .ok_or_else(|| ("invalid_request".into(), "Expected key".into()))?;
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
            other => Err((
                "invalid_request".into(),
                format!("Unsupported hyp_kv action '{other}'"),
            )),
        }
    }

    async fn tool_wakeup(
        self: &Arc<Self>,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        if !self.config.wakeup.enabled {
            return Err((
                "wakeup_disabled".into(),
                "Wakeup scheduler is disabled. Enable it via `hyp wakeup enable` or node.json."
                    .into(),
            ));
        }

        let action = args
            .get("action")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                (
                    "invalid_request".into(),
                    "Expected hyp_wakeup action: set | list | cancel | fire".into(),
                )
            })?;

        let now = now_ms();
        match action {
            "set" => {
                let label = match args.get("label") {
                    Some(v) => v
                        .as_str()
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .ok_or_else(|| {
                            ("invalid_request".into(), "Expected non-empty 'label'".into())
                        })?
                        .to_string(),
                    None => "wakeup".to_string(),
                };
                let note = args
                    .get("note")
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty())
                    .ok_or_else(|| ("invalid_request".into(), "Expected non-empty 'note'".into()))?
                    .to_string();

                let (target_session_id, target_handle) = match args
                    .get("to")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    Some(raw_to) => {
                        let local_handle =
                            resolve_local_wakeup_target(raw_to, self.node.node_id().as_str())?;
                        (None, Some(local_handle))
                    }
                    None => (Some(session_id.to_string()), None),
                };

                let parsed = parse_wakeup_schedule_args(args, true, now)?;
                let urgency = parse_wakeup_urgency_arg(args)?;
                let ttl_ms = parse_wakeup_ttl_ms_arg(args, true)?;
                let coalesce = args
                    .get("coalesce")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                let id = args
                    .get("id")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string);

                let insert = WakeupInsert {
                    id,
                    owner_session_id: Some(session_id.to_string()),
                    target_session_id,
                    target_handle,
                    target_topic: None,
                    label,
                    note,
                    trigger_kind: parsed.trigger_kind,
                    cron_expr: parsed.cron_expr,
                    timezone: parsed.timezone,
                    exact_timing: parsed.exact_timing,
                    urgency,
                    ttl_ms,
                    coalesce,
                    fire_at: parsed.fire_at,
                    max_iterations: parsed.max_iterations,
                    // Agents are NEVER permitted to specify cold-revival launch templates via MCP.
                    cold_revival_template: None,
                };

                let rec = {
                    let db = self.node.db();
                    db.wakeups()
                        .create_wakeup(&insert, &WakeupLimits::default(), now)
                        .map_err(wakeup_store_err_tuple)?
                };
                // NOTE (Wave 3 integration): once `UnifiedNode::wake_scheduler()` is exposed,
                // notify it here so the zero-polling deadline loop recomputes immediately.
                Ok(wakeup_record_to_json(&rec))
            }
            "list" => {
                let state_filter = match args.get("state").and_then(Value::as_str) {
                    None | Some("all") => None,
                    Some(s) => Some(WakeupState::parse(s).map_err(wakeup_store_err_tuple)?),
                };
                let wakeups = {
                    let db = self.node.db();
                    let session_handle = db
                        .local()
                        .get_session(session_id)
                        .ok()
                        .flatten()
                        .and_then(|s| s.handle);
                    db.wakeups()
                        .list_wakeups(None, state_filter)
                        .map_err(wakeup_store_err_tuple)?
                        .into_iter()
                        .filter(|w| {
                            w.owner_session_id.as_deref() == Some(session_id)
                                || w.target_session_id.as_deref() == Some(session_id)
                                || (session_handle.is_some()
                                    && w.target_handle.as_deref() == session_handle.as_deref())
                        })
                        .map(|w| wakeup_record_to_json(&w))
                        .collect::<Vec<_>>()
                };
                Ok(json!({ "wakeups": wakeups }))
            }
            "cancel" => {
                let id = args
                    .get("id")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| ("invalid_request".into(), "Expected wakeup 'id'".into()))?;
                let rec = {
                    let db = self.node.db();
                    db.wakeups()
                        .cancel_wakeup(id, Some(session_id), now)
                        .map_err(wakeup_store_err_tuple)?
                };
                Ok(json!({
                    "cancelled": true,
                    "id": rec.id,
                    "state": rec.state.as_str(),
                }))
            }
            "fire" => {
                let label = args
                    .get("label")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or("wakeup")
                    .to_string();
                let note = args
                    .get("note")
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty())
                    .ok_or_else(|| ("invalid_request".into(), "Expected non-empty 'note'".into()))?
                    .to_string();
                let limits = WakeupLimits::default();
                if note.len() > limits.max_note_bytes {
                    return Err((
                        "invalid_request".into(),
                        format!(
                            "wakeup note is {} bytes; limit {}",
                            note.len(),
                            limits.max_note_bytes
                        ),
                    ));
                }

                let (target_session_id, target_handle) = match args
                    .get("to")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    Some(raw_to) => {
                        let local_handle =
                            resolve_local_wakeup_target(raw_to, self.node.node_id().as_str())?;
                        (None, Some(local_handle))
                    }
                    None => (Some(session_id.to_string()), None),
                };

                let urgency = parse_wakeup_urgency_arg(args)?;
                let ttl_ms = parse_wakeup_ttl_ms_arg(args, true)?;
                let wakeup_id = args
                    .get("id")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string)
                    .unwrap_or_else(|| format!("wk-agent-{}", uuid_v4()));
                let coalesce_key = args
                    .get("coalesceKey")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToString::to_string)
                    .or_else(|| {
                        if args.get("coalesce").and_then(Value::as_bool) == Some(true) {
                            Some(format!("wakeup:{wakeup_id}"))
                        } else {
                            None
                        }
                    });

                let outcome = self
                    .deliver_wakeup_internal(WakeupDeliveryRequest {
                        wakeup_id: wakeup_id.clone(),
                        label,
                        note,
                        trigger: "agent".to_string(),
                        urgency,
                        target_session_id,
                        target_handle,
                        target_topic: None,
                        coalesce_key,
                        ttl_ms: Some(ttl_ms),
                        scheduled_for_ms: now,
                        fired_at_ms: now,
                        iteration: 1,
                        max_iterations: Some(1),
                        missed_count: 0,
                        cold_revival_template: None,
                        is_external: false,
                        is_persisted_wakeup: false,
                    })
                    .await
                    .map_err(|msg| ("wakeup_delivery_failed".into(), msg))?;

                Ok(json!({
                    "fired": true,
                    "wakeupId": wakeup_id,
                    "sessionId": outcome.session_id,
                    "delivered": outcome.delivered,
                    "pushed": outcome.pushed,
                    "missedCount": outcome.missed_count,
                    "receipt": outcome.receipt,
                }))
            }
            other => Err((
                "invalid_request".into(),
                format!("Unsupported hyp_wakeup action '{other}'"),
            )),
        }
    }

    async fn tool_bridge(
        &self,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        match args.get("action").and_then(Value::as_str) {
            Some("targets") => self.tool_bridge_targets(session_id).await,
            Some("link") => self.tool_bridge_link(session_id, args).await,
            Some("unlink") => self.tool_bridge_unlink(session_id, args).await,
            Some("handoff") => self.tool_bridge_handoff(session_id, args).await,
            _ => Err((
                "invalid_request".into(),
                "Expected hyp_bridge action: targets | link | unlink | handoff".into(),
            )),
        }
    }

    async fn tool_bridge_targets(&self, session_id: &str) -> Result<Value, (String, String)> {
        let configured_snapshot: BTreeMap<String, Vec<String>> = self
            .configured_bridge_targets
            .lock()
            .expect("configured_bridge_targets lock poisoned")
            .clone();

        let mut plugins: Vec<String> = self
            .bridge_posters
            .lock()
            .expect("bridge_posters lock poisoned")
            .keys()
            .cloned()
            .collect();
        for plugin in configured_snapshot.keys() {
            if !plugins.contains(plugin) {
                plugins.push(plugin.clone());
            }
        }
        plugins.sort();

        let (links, targets) = {
            let db = self.node.db();
            let caller_links = db
                .local()
                .bridge_links_for_session(session_id)
                .map_err(store_err_tuple)?;

            let sessions = db.local().list_sessions().map_err(store_err_tuple)?;
            let handle_by_session: HashMap<String, Option<String>> = sessions
                .iter()
                .map(|s| (s.id.clone(), s.handle.clone()))
                .collect();

            let mut configured_set: HashSet<(String, String)> = HashSet::new();
            let mut target_pairs: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
            for (plugin, targets_for_plugin) in &configured_snapshot {
                for target in targets_for_plugin {
                    let pair = (plugin.clone(), target.clone());
                    configured_set.insert(pair.clone());
                    target_pairs.entry(pair).or_default();
                }
            }
            for s in &sessions {
                for l in db
                    .local()
                    .bridge_links_for_session(&s.id)
                    .unwrap_or_default()
                {
                    let readers = target_pairs.entry((l.plugin, l.target)).or_default();
                    if !readers.contains(&l.session_id) {
                        readers.push(l.session_id);
                    }
                }
            }

            let mut target_views = Vec::with_capacity(target_pairs.len());
            for ((plugin, target), readers) in target_pairs {
                let holder = db
                    .local()
                    .get_plugin_target(&plugin, &target)
                    .map_err(store_err_tuple)?;
                let primary_session = holder.as_ref().map(|h| h.session_id.clone());
                let primary_handle = primary_session
                    .as_deref()
                    .and_then(|sid| handle_by_session.get(sid).cloned().flatten());
                let is_primary = primary_session.as_deref() == Some(session_id);
                let is_linked = readers.iter().any(|r| r == session_id);
                let is_configured = configured_set.contains(&(plugin.clone(), target.clone()));
                target_views.push(json!({
                    "plugin": plugin,
                    "target": target,
                    "configured": is_configured,
                    "primarySessionId": primary_session,
                    "primarySession": primary_session,
                    "primaryHandle": primary_handle,
                    "isPrimary": is_primary,
                    "callerIsPrimary": is_primary,
                    "callerIsLinked": is_linked,
                    "readers": readers,
                }));
            }

            (caller_links, target_views)
        };

        Ok(json!({
            "plugins": plugins,
            "links": links,
            "targets": targets,
        }))
    }

    async fn tool_bridge_link(
        &self,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        let (plugin, target) = parse_bridge_plugin_target(args)?;
        let link = BridgeLink {
            plugin: plugin.clone(),
            target: target.clone(),
            session_id: session_id.to_string(),
            linked_at: now_ms(),
            linked_by: session_id.to_string(),
        };
        let primary_session = {
            let db = self.node.db();
            db.local().add_bridge_link(&link).map_err(store_err_tuple)?;
            db.local()
                .get_plugin_target(&plugin, &target)
                .map_err(store_err_tuple)?
                .map(|h| h.session_id)
        };
        let role = if primary_session.as_deref() == Some(session_id) {
            "primary"
        } else {
            "reader"
        };
        Ok(json!({
            "linked": true,
            "plugin": plugin,
            "target": target,
            "role": role,
            "primarySessionId": primary_session,
        }))
    }

    async fn tool_bridge_unlink(
        &self,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        let (plugin, target) = parse_bridge_plugin_target(args)?;
        let all = args.get("all").and_then(Value::as_bool) == Some(true);

        let removed = {
            let db = self.node.db();
            let holder = db
                .local()
                .get_plugin_target(&plugin, &target)
                .map_err(store_err_tuple)?;
            if all {
                match holder {
                    Some(ref h) if h.session_id == session_id => {}
                    Some(ref h) => {
                        return Err((
                            "not_target_holder".into(),
                            format!(
                                "Session '{session_id}' is not the primary holder of '{plugin}:{target}' (held by '{}')",
                                h.session_id
                            ),
                        ));
                    }
                    None => {
                        return Err((
                            "not_target_holder".into(),
                            format!(
                                "No primary holder assigned for '{plugin}:{target}'; cannot unlink all"
                            ),
                        ));
                    }
                }
                let count = db
                    .local()
                    .remove_bridge_link(&plugin, &target, None)
                    .map_err(store_err_tuple)?;
                let _ = db.local().remove_plugin_target(&plugin, &target);
                count
            } else {
                let count = db
                    .local()
                    .remove_bridge_link(&plugin, &target, Some(session_id))
                    .map_err(store_err_tuple)?;
                if holder.as_ref().is_some_and(|h| h.session_id == session_id) {
                    let _ = db.local().remove_plugin_target(&plugin, &target);
                }
                count
            }
        };

        Ok(json!({
            "removed": removed > 0,
            "removedCount": removed,
            "all": all,
            "plugin": plugin,
            "target": target,
        }))
    }

    async fn tool_bridge_handoff(
        &self,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        let (plugin, target) = parse_bridge_plugin_target(args)?;
        let now = now_ms();

        let (target_session, previous_session) = {
            let db = self.node.db();
            let current = db
                .local()
                .get_plugin_target(&plugin, &target)
                .map_err(store_err_tuple)?;

            if let Some(ref holder) = current {
                if holder.session_id != session_id {
                    return Err((
                        "not_target_holder".into(),
                        format!(
                            "Session '{session_id}' is not the primary holder of '{plugin}:{target}' (held by '{}')",
                            holder.session_id
                        ),
                    ));
                }
            }

            let target_session = if let Some(raw_handle) = args
                .get("handle")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                let h = raw_handle.strip_prefix('@').unwrap_or(raw_handle);
                let lookup = parse_address(h).map(|(_, h_part)| h_part).unwrap_or(h);
                db.local()
                    .session_by_handle(lookup)
                    .map_err(store_err_tuple)?
                    .ok_or_else(|| ("not_found".into(), format!("Unknown handle '{raw_handle}'")))?
                    .id
            } else {
                session_id.to_string()
            };

            let handoff = PluginTargetHandoff {
                plugin: plugin.clone(),
                target: target.clone(),
                session_id: target_session.clone(),
                set_at: now,
                set_by: session_id.to_string(),
            };
            db.local()
                .set_plugin_target(&handoff)
                .map_err(store_err_tuple)?;

            // Ensure the new primary writer is always also linked for inbound reads.
            let link = BridgeLink {
                plugin: plugin.clone(),
                target: target.clone(),
                session_id: target_session.clone(),
                linked_at: now,
                linked_by: session_id.to_string(),
            };
            db.local().add_bridge_link(&link).map_err(store_err_tuple)?;

            (target_session, current.map(|h| h.session_id))
        };

        Ok(json!({
            "handoff": true,
            "plugin": plugin,
            "target": target,
            "sessionId": target_session,
            "previousSessionId": previous_session,
        }))
    }

    async fn tool_plugin_post(
        &self,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        let (plugin, target) = parse_bridge_plugin_target(args)?;
        let text = args
            .get("text")
            .and_then(Value::as_str)
            .ok_or_else(|| ("invalid_request".into(), "Expected 'text'".into()))?;
        let handle = self.require_session_handle(session_id)?;
        self.send_to_bridge(session_id, &handle, &plugin, &target, text, args)
            .await
    }

    async fn send_to_bridge(
        &self,
        session_id: &str,
        handle: &str,
        raw_plugin: &str,
        raw_target: &str,
        text: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        let plugin = raw_plugin.trim().to_ascii_lowercase();
        let target = raw_target.trim();
        let full_dest = format!("{plugin}:{target}");

        let poster = self
            .bridge_posters
            .lock()
            .expect("bridge_posters lock poisoned")
            .get(&plugin)
            .cloned()
            .ok_or_else(|| {
                (
                    "no_plugins".into(),
                    format!("No local bridge plugin configured for '{full_dest}'"),
                )
            })?;

        let holder = self
            .node
            .db()
            .local()
            .get_plugin_target(&plugin, target)
            .map_err(store_err_tuple)?;
        match holder {
            Some(ref h) if h.session_id == session_id => {}
            Some(ref h) => {
                return Err((
                    "not_target_holder".into(),
                    format!(
                        "Session '{session_id}' is not the primary holder of '{full_dest}' (held by '{}')",
                        h.session_id
                    ),
                ));
            }
            None => {
                return Err((
                    "not_target_holder".into(),
                    format!(
                        "No primary holder assigned for '{full_dest}'; claim ownership via hyp_bridge(action:'handoff')"
                    ),
                ));
            }
        }

        // Enforce Stage 1 Outbound DLP BEFORE invoking any external chat bridge!
        self.check_outbound_gate(session_id, &full_dest, "to.hyphae.bridge.v1", text)?;

        let mut meta = Map::new();
        meta.insert("sessionId".into(), json!(session_id));
        meta.insert("handle".into(), json!(handle));
        if let Some(reply_to) = args.get("replyTo") {
            meta.insert("replyTo".into(), reply_to.clone());
        }
        if let Some(thread_ts) = args.get("threadTs") {
            meta.insert("threadTs".into(), thread_ts.clone());
        }

        let response = poster.post(&plugin, target, text, &meta).await?;
        Ok(json!({
            "delivered": true,
            "plugin": plugin,
            "target": target,
            "to": full_dest,
            "response": response,
        }))
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
        let Some(ref pipeline) = self.gate else {
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
                now_ms(),
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

#[derive(Debug, Default)]
struct McpSocketContext {
    backend: Option<HarnessKind>,
    channel: bool,
    channel_ready: bool,
    channel_session_id: Option<String>,
    ephemeral_client_id: Option<String>,
    hints: TransportHints,
}

async fn handle_connection<R, W>(
    daemon: Arc<LocalDaemonInner>,
    read_half: R,
    mut write_half: W,
    mut shutdown_rx: watch::Receiver<bool>,
) where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let conn_id = daemon.next_seq();
    let mut reader = BufReader::new(read_half);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Value>();
    let (chan_tx, mut chan_rx) = mpsc::unbounded_channel::<ChannelDeliverCommand>();

    let mut mcp_ctx: Option<McpSocketContext> = None;
    let mut attached_waiter: Option<(String, u64)> = None;
    let mut pending_channel_acks: HashMap<u64, oneshot::Sender<bool>> = HashMap::new();

    // Writer loop merged into select! so both request replies and async pushes serialize cleanly.
    loop {
        enum Ev {
            Line(Result<Option<String>, crate::sock::SockError>),
            Push(Option<Value>),
            ChannelCmd(Option<ChannelDeliverCommand>),
            Shutdown,
        }

        let ev = tokio::select! {
            res = read_bounded_line_async(&mut reader, MAX_SOCKET_LINE_BYTES) => Ev::Line(res),
            msg = out_rx.recv() => Ev::Push(msg),
            cmd = chan_rx.recv() => Ev::ChannelCmd(cmd),
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    Ev::Shutdown
                } else {
                    continue;
                }
            }
        };

        match ev {
            Ev::Shutdown => break,
            Ev::Push(Some(pkt)) => {
                let is_once_done = attached_waiter.as_ref().is_some_and(|(sid, wid)| {
                    let map = daemon.waiters.lock().expect("waiters lock poisoned");
                    !map.get(sid)
                        .is_some_and(|list| list.iter().any(|w| w.id == *wid))
                }) && pkt.get("type").and_then(Value::as_str) == Some("wait.items");

                if write_ndjson_line_async(&mut write_half, &pkt).await.is_err() {
                    break;
                }
                if is_once_done {
                    let _ = write_half.shutdown().await;
                    break;
                }
            }
            Ev::Push(None) => break,
            Ev::ChannelCmd(Some(cmd)) => {
                let pkt = json!({
                    "type": "channel.deliver",
                    "delivery": cmd.delivery_id,
                    "text": cmd.text,
                });
                if write_ndjson_line_async(&mut write_half, &pkt).await.is_ok() {
                    pending_channel_acks.insert(cmd.delivery_id, cmd.ack_tx);
                } else {
                    let _ = cmd.ack_tx.send(false);
                    break;
                }
            }
            Ev::ChannelCmd(None) => break,
            Ev::Line(Ok(None)) | Ev::Line(Err(_)) => break,
            Ev::Line(Ok(Some(line))) => {
                if line.trim().is_empty() {
                    continue;
                }
                let Ok(Value::Object(packet)) = serde_json::from_str::<Value>(&line) else {
                    let _ = write_ndjson_line_async(
                        &mut write_half,
                        &json!({ "ok": false, "error": "invalid_json" }),
                    )
                    .await;
                    break;
                };

                let pkt_type = packet
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or_default();

                match pkt_type {
                    // ---- Single-shot hook / CLI RPCs ----
                    "call.start" => {
                        let resp = handle_call_start(&daemon, &packet);
                        if resp.get("ok").and_then(Value::as_bool) == Some(true) {
                            if let Some(sid) = resp
                                .get("result")
                                .and_then(|r| r.get("sessionId"))
                                .and_then(Value::as_str)
                            {
                                let hints = TransportHints::from_packet(&packet, None);
                                maybe_spawn_transport_probe(&daemon, sid, hints);
                            }
                        }
                        let _ = write_ndjson_line_async(&mut write_half, &resp).await;
                        break;
                    }
                    "session.hint" => {
                        let resp = handle_session_hint(&daemon, &packet);
                        let _ = write_ndjson_line_async(&mut write_half, &resp).await;
                        break;
                    }
                    "call.end" | "call.finish" => {
                        let cid = packet.get("callId").and_then(Value::as_str);
                        let tok = packet.get("callToken").and_then(Value::as_str);
                        daemon.calls.finish_call(cid, tok);
                        let _ = write_ndjson_line_async(
                            &mut write_half,
                            &json!({ "ok": true, "result": {} }),
                        )
                        .await;
                        break;
                    }
                    "mailbox.drain" => {
                        let resp = handle_mailbox_drain(&daemon, &packet).await;
                        let _ = write_ndjson_line_async(&mut write_half, &resp).await;
                        break;
                    }
                    "session.status" => {
                        let resp = handle_session_status(&daemon, &packet).await;
                        let _ = write_ndjson_line_async(&mut write_half, &resp).await;
                        break;
                    }
                    "daemon.status" => {
                        let resp = handle_daemon_status(&daemon).await;
                        let _ = write_ndjson_line_async(&mut write_half, &resp).await;
                        break;
                    }
                    "mute.add" => {
                        let target = packet
                            .get("target")
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        let resp = match daemon.node.db().local().add_mute("*", target, "cli", now_ms()) {
                            Ok(rule) => json!({ "ok": true, "result": { "rule": rule } }),
                            Err(e) => json!({ "ok": false, "error": e.to_string() }),
                        };
                        let _ = write_ndjson_line_async(&mut write_half, &resp).await;
                        break;
                    }
                    "mute.remove" => {
                        let target = packet
                            .get("target")
                            .and_then(Value::as_str)
                            .unwrap_or_default();
                        let resp = match daemon.node.db().local().remove_mute("*", target) {
                            Ok(removed) => json!({ "ok": true, "result": { "removed": removed } }),
                            Err(e) => json!({ "ok": false, "error": e.to_string() }),
                        };
                        let _ = write_ndjson_line_async(&mut write_half, &resp).await;
                        break;
                    }
                    "mute.list" => {
                        let mutes = daemon
                            .node
                            .db()
                            .local()
                            .list_mutes(None)
                            .unwrap_or_default();
                        let _ = write_ndjson_line_async(
                            &mut write_half,
                            &json!({ "ok": true, "result": { "mutes": mutes } }),
                        )
                        .await;
                        break;
                    }
                    "wakeup.set" => {
                        let resp = handle_wakeup_set_rpc(&daemon, &packet).await;
                        let _ = write_ndjson_line_async(&mut write_half, &resp).await;
                        break;
                    }
                    "wakeup.list" => {
                        let resp = handle_wakeup_list_rpc(&daemon, &packet);
                        let _ = write_ndjson_line_async(&mut write_half, &resp).await;
                        break;
                    }
                    "wakeup.cancel" => {
                        let resp = handle_wakeup_cancel_rpc(&daemon, &packet);
                        let _ = write_ndjson_line_async(&mut write_half, &resp).await;
                        break;
                    }
                    "wakeup.fire" => {
                        let resp = handle_wakeup_fire_rpc(&daemon, &packet).await;
                        let _ = write_ndjson_line_async(&mut write_half, &resp).await;
                        break;
                    }
                    "wakeup.emit" => {
                        let resp = handle_wakeup_emit_rpc(&daemon, &packet).await;
                        let _ = write_ndjson_line_async(&mut write_half, &resp).await;
                        break;
                    }

                    // ---- Blocking waiter / streaming watcher ----
                    "wait.subscribe" | "inbox.wait" | "inbox.watch" => {
                        let mode = match pkt_type {
                            "inbox.wait" => WaiterKind::Once,
                            "inbox.watch" => WaiterKind::Stream,
                            _ => match packet.get("mode").and_then(Value::as_str) {
                                Some("stream") => WaiterKind::Stream,
                                _ => WaiterKind::Once,
                            },
                        };

                        let mut sid = packet
                            .get("sessionId")
                            .and_then(Value::as_str)
                            .filter(|s| is_valid_session_id(s))
                            .map(ToString::to_string);
                        if sid.is_none() {
                            if let Some(h) = packet.get("handle").and_then(Value::as_str) {
                                sid = daemon
                                    .node
                                    .db()
                                    .local()
                                    .session_by_handle(h)
                                    .ok()
                                    .flatten()
                                    .map(|s| s.id);
                            }
                        }
                        let Some(session_id) = sid else {
                            let _ = write_ndjson_line_async(
                                &mut write_half,
                                &json!({
                                    "type": "wait.error",
                                    "message": "Unknown session or handle. Join the mesh first or pass --session <id>."
                                }),
                            )
                            .await;
                            break;
                        };

                        let waiter_id = daemon.next_seq();
                        {
                            let mut map = daemon.waiters.lock().expect("waiters lock poisoned");
                            map.entry(session_id.clone()).or_default().push(LiveWaiter {
                                id: waiter_id,
                                mode,
                                tx: out_tx.clone(),
                            });
                        }
                        attached_waiter = Some((session_id.clone(), waiter_id));
                        let _ = daemon.node.db().local().touch_session(&session_id, now_ms());

                        let mode_str = match mode {
                            WaiterKind::Once => "once",
                            WaiterKind::Stream => "stream",
                        };
                        if write_ndjson_line_async(
                            &mut write_half,
                            &json!({ "type": "wait.ready", "sessionId": session_id, "mode": mode_str }),
                        )
                        .await
                        .is_err()
                        {
                            break;
                        }

                        // Spawn flush so `out_rx` in this select loop receives pushed items immediately!
                        let flush_daemon = Arc::clone(&daemon);
                        let flush_sid = session_id;
                        tokio::spawn(async move {
                            flush_daemon.flush_session(&flush_sid).await;
                        });
                    }

                    // ---- Persistent MCP shim protocol ----
                    "mcp.hello" => {
                        let backend = packet
                            .get("backend")
                            .and_then(Value::as_str)
                            .and_then(|s| s.parse::<HarnessKind>().ok());
                        let channel = packet.get("channel").and_then(Value::as_bool) == Some(true);
                        let ephemeral_client_id = packet
                            .get("clientId")
                            .and_then(Value::as_str)
                            .filter(|s| !s.is_empty() && s.len() <= 64)
                            .map(ToString::to_string);
                        let hints = TransportHints::from_packet(&packet, backend);
                        mcp_ctx = Some(McpSocketContext {
                            backend,
                            channel,
                            channel_ready: false,
                            channel_session_id: None,
                            ephemeral_client_id,
                            hints,
                        });
                    }
                    "channel.ready" => {
                        if let Some(ref mut ctx) = mcp_ctx {
                            if ctx.channel {
                                ctx.channel_ready = true;
                                if let Some(ref sid) = ctx.channel_session_id.clone() {
                                    bind_channel(&daemon, conn_id, sid, &chan_tx);
                                } else if let Some(ref cid) = ctx.ephemeral_client_id.clone() {
                                    let sid = format!("claude:{cid}");
                                    let _ = daemon.node.register_session(
                                        &sid,
                                        "{\"kind\":\"claude\",\"channel\":true}",
                                    );
                                    ctx.channel_session_id = Some(sid.clone());
                                    bind_channel(&daemon, conn_id, &sid, &chan_tx);
                                }
                            }
                        }
                    }
                    "channel.ack" => {
                        if let Some(delivery_id) = packet.get("delivery").and_then(Value::as_u64) {
                            let submitted =
                                packet.get("submitted").and_then(Value::as_bool) == Some(true);
                            if let Some(tx) = pending_channel_acks.remove(&delivery_id) {
                                let _ = tx.send(submitted);
                            }
                        }
                    }
                    "mcp.caps" => {
                        if let Some(req_id) = packet.get("id").and_then(Value::as_u64) {
                            let backend = mcp_ctx.as_ref().and_then(|c| c.backend);
                            let resp = json!({
                                "id": req_id,
                                "result": {
                                    "hasPlugins": daemon.has_plugins_capability(),
                                    "hasKv": daemon.has_kv_capability(),
                                    "hasWakeup": daemon.has_wakeup_capability(backend),
                                }
                            });
                            if write_ndjson_line_async(&mut write_half, &resp).await.is_err() {
                                break;
                            }
                        }
                    }
                    "tool.call" => {
                        let Some(req_id) = packet.get("id").and_then(Value::as_u64) else {
                            continue;
                        };
                        let Some(tool_name) = packet.get("name").and_then(Value::as_str) else {
                            let _ = write_ndjson_line_async(
                                &mut write_half,
                                &json!({
                                    "id": req_id,
                                    "error": { "code": "invalid_request", "message": "Missing tool name" }
                                }),
                            )
                            .await;
                            continue;
                        };
                        let args = packet
                            .get("args")
                            .and_then(Value::as_object)
                            .cloned()
                            .unwrap_or_default();
                        let call_id = packet.get("callId").and_then(Value::as_str);
                        let call_token = packet.get("callToken").and_then(Value::as_str);

                        let resolved_session = resolve_tool_caller(
                            &daemon,
                            mcp_ctx.as_mut(),
                            conn_id,
                            &chan_tx,
                            tool_name,
                            call_id,
                            call_token,
                        )
                        .await;

                        let resp = match resolved_session {
                            Ok(session_id) => match daemon
                                .dispatch_tool(&session_id, tool_name, &args)
                                .await
                            {
                                Ok(result) => json!({ "id": req_id, "result": result }),
                                Err((code, message)) => json!({
                                    "id": req_id,
                                    "error": { "code": code, "message": message }
                                }),
                            },
                            Err((code, message)) => json!({
                                "id": req_id,
                                "error": { "code": code, "message": message }
                            }),
                        };
                        if write_ndjson_line_async(&mut write_half, &resp).await.is_err() {
                            break;
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Cleanup registered live waiter / channel transport on disconnect.
    if let Some((sid, wid)) = attached_waiter {
        let mut map = daemon.waiters.lock().expect("waiters lock poisoned");
        if let Some(list) = map.get_mut(&sid) {
            list.retain(|w| w.id != wid);
            if list.is_empty() {
                map.remove(&sid);
            }
        }
    }
    if let Some(ref ctx) = mcp_ctx {
        if let Some(ref sid) = ctx.channel_session_id {
            let mut map = daemon.channels.lock().expect("channels lock poisoned");
            if map.get(sid).is_some_and(|c| c.conn_id == conn_id) {
                map.remove(sid);
            }
        }
    }
    for (_, tx) in pending_channel_acks.drain() {
        let _ = tx.send(false);
    }
}

fn bind_channel(
    daemon: &Arc<LocalDaemonInner>,
    conn_id: u64,
    session_id: &str,
    chan_tx: &mpsc::UnboundedSender<ChannelDeliverCommand>,
) {
    {
        let mut map = daemon.channels.lock().expect("channels lock poisoned");
        map.insert(
            session_id.to_string(),
            LiveChannel {
                conn_id,
                tx: chan_tx.clone(),
            },
        );
    }
    let flush_daemon = Arc::clone(daemon);
    let sid = session_id.to_string();
    tokio::spawn(async move {
        flush_daemon.flush_session(&sid).await;
    });
}

async fn resolve_tool_caller(
    daemon: &Arc<LocalDaemonInner>,
    mut mcp_ctx: Option<&mut McpSocketContext>,
    conn_id: u64,
    chan_tx: &mpsc::UnboundedSender<ChannelDeliverCommand>,
    tool_name: &str,
    call_id: Option<&str>,
    call_token: Option<&str>,
) -> Result<String, (String, String)> {
    // 1. Primary path: host-verified PreToolUse registration (`callToken` or `_meta` `callId`).
    if call_id.is_some_and(|s| !s.is_empty()) || call_token.is_some_and(|s| !s.is_empty()) {
        let wait = if call_token.is_some() {
            DEFAULT_RESOLVE_WAIT
        } else {
            Duration::from_millis(250)
        };
        match daemon
            .calls
            .resolve_call(tool_name, call_id, call_token, wait)
            .await
        {
            CallerResolution::Verified {
                session_id,
                harness,
                ..
            } => {
                let _ = daemon.node.register_session(
                    &session_id,
                    &format!("{{\"kind\":\"{}\"}}", harness.as_str()),
                );
                if let Some(ctx) = mcp_ctx.as_deref_mut() {
                    if ctx.channel && harness == HarnessKind::Claude {
                        ctx.channel_session_id = Some(session_id.clone());
                        if ctx.channel_ready {
                            bind_channel(daemon, conn_id, &session_id, chan_tx);
                        }
                    }
                    let mut hints = ctx.hints.clone();
                    if hints.harness.is_none() {
                        hints.harness = Some(harness);
                    }
                    maybe_spawn_transport_probe(daemon, &session_id, hints);
                }
                return Ok(session_id);
            }
            CallerResolution::Failed { code, message } => {
                if mcp_ctx
                    .as_deref()
                    .and_then(|c| c.ephemeral_client_id.as_ref())
                    .is_none()
                {
                    return Err((code.as_str().to_string(), message));
                }
            }
        }
    }

    // 2. Explicit opt-in `--ephemeral` scratch mode
    if let Some(ctx) = mcp_ctx {
        if let Some(ref cid) = ctx.ephemeral_client_id {
            let harness = ctx.backend.unwrap_or(HarnessKind::Claude);
            let session_id = format!("{}:{cid}", harness.as_str());
            let _ = daemon.node.register_session(
                &session_id,
                &format!("{{\"kind\":\"{}\"}}", harness.as_str()),
            );
            if ctx.channel && harness == HarnessKind::Claude {
                ctx.channel_session_id = Some(session_id.clone());
                if ctx.channel_ready {
                    bind_channel(daemon, conn_id, &session_id, chan_tx);
                }
            }
            let mut hints = ctx.hints.clone();
            if hints.harness.is_none() {
                hints.harness = Some(harness);
            }
            maybe_spawn_transport_probe(daemon, &session_id, hints);
            return Ok(session_id);
        }
    }

    // 3. Optional test-only bypass when `require_verified_caller == false`
    if !daemon.config.require_verified_caller {
        let sid = format!("ephemeral:{}", uuid_v4());
        let _ = daemon.node.register_session(&sid, "{\"kind\":\"claude\"}");
        return Ok(sid);
    }

    Err((
        "caller_unverifiable".into(),
        "Could not verify calling thread/conversation. Run 'hyp setup <harness>' to install PreToolUse hooks (or pass --ephemeral for scratch testing).".into(),
    ))
}

fn handle_session_hint(daemon: &Arc<LocalDaemonInner>, packet: &Map<String, Value>) -> Value {
    let Some(session_id) = packet
        .get("sessionId")
        .and_then(Value::as_str)
        .filter(|s| is_valid_session_id(s))
    else {
        return json!({ "ok": false, "error": "invalid_session" });
    };
    let harness = packet
        .get("harness")
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<HarnessKind>().ok());
    if let Some(h) = harness {
        let backend_json = format!("{{\"kind\":\"{}\"}}", h.as_str());
        let _ = daemon.node.register_session(session_id, &backend_json);
    }
    let hints = TransportHints::from_packet(packet, harness);
    maybe_spawn_transport_probe(daemon, session_id, hints);
    json!({ "ok": true, "result": {} })
}

fn read_t3_secret_for_node(node: &UnifiedNode) -> Option<String> {
    let cfg = node.config();
    let store = match cfg.secret_backend {
        Some(backend) => hyp_crypto::SecretStore::new(cfg.state_dir.clone(), backend),
        None => hyp_crypto::SecretStore::from_env(cfg.state_dir.clone()),
    };
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

    // Check whether we have any plausible transport signal worth probing:
    // - explicit Herdr terminal ID, T3 dir/url/harness, or explicit Codex Queue args
    // - OR default T3 statev2.sqlite exists on disk (Claude/Codex running inside T3 Code)
    let default_t3_base = daemon
        .config
        .t3_default_base_dir
        .clone()
        .unwrap_or_else(default_t3_base_dir);
    let t3_base_candidate = hints.t3_base_dir.clone().unwrap_or(default_t3_base);
    let has_t3_db = t3_state_db_path(&t3_base_candidate).is_file();

    if !hints.has_any_hint() && !has_t3_db {
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

        // Priority 1: Herdr (`HC_TERMINAL_ID` verified live via `hc get --json`)
        if let Some(ref tid) = hints.herdr_terminal_id {
            let hc_bin = daemon_arc
                .config
                .herdr_bin
                .as_deref()
                .unwrap_or(DEFAULT_HERDR_BIN);
            if let Some(target) = probe_herdr_terminal(hc_bin, tid).await {
                if daemon_arc.attach_transport_if_higher_priority(
                    &sid,
                    Arc::new(HerdrTransport::new(target)),
                    PRIORITY_HERDR,
                ) {
                    attached = true;
                }
            }
        }

        // Priority 2: T3 Code (read-only `statev2.sqlite` match + reachable T3 server)
        if !attached && daemon_arc.current_transport_priority(&sid) < PRIORITY_T3 && has_t3_db {
            let raw_id = hints
                .codex_thread_id
                .as_deref()
                .unwrap_or_else(|| sid.split_once(':').map(|(_, r)| r).unwrap_or(sid.as_str()));
            let resolved_t3_thread = if hints.harness == Some(HarnessKind::T3)
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
                    .unwrap_or(DEFAULT_T3_URL);
                if let Ok(origin) = normalize_t3_server_url(raw_url) {
                    let token = read_t3_secret_for_node(&daemon_arc.node);
                    let probe =
                        probe_t3_server(&origin, token.as_deref(), DEFAULT_PROBE_TIMEOUT).await;
                    if probe.ok {
                        let mut target = T3Target::new(thread_id, origin);
                        target.base_dir = Some(t3_base_candidate.clone());
                        target.state_dir = Some(daemon_arc.node.config().state_dir.clone());
                        target.secret_backend = daemon_arc.node.config().secret_backend;
                        if daemon_arc.attach_transport_if_higher_priority(
                            &sid,
                            Arc::new(T3Transport::new(target)),
                            PRIORITY_T3,
                        ) {
                            attached = true;
                        }
                    }
                }
            }
        }

        // Priority 3: Codex Queue (explicit `--thread` / `--remote` / `--resume` / `CODEX_REMOTE`)
        if !attached
            && daemon_arc.current_transport_priority(&sid) < PRIORITY_CODEX_QUEUE
            && hints.explicit_codex_queue
        {
            if let Some(ref thread_id) = hints.codex_thread_id {
                let codex_bin = daemon_arc
                    .config
                    .codex_bin
                    .as_deref()
                    .unwrap_or(DEFAULT_CODEX_BIN);
                let mut target = CodexQueueTarget::new(thread_id.clone())
                    .with_bin(codex_bin.to_string())
                    .with_resume(hints.codex_resume);
                if let Some(ref home) = hints.codex_home {
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
    let call_id = packet
        .get("callId")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);

    let backend_json = format!("{{\"kind\":\"{}\"}}", harness.as_str());
    if let Err(e) = daemon.node.register_session(session_id, &backend_json) {
        return json!({ "ok": false, "error": e.to_string() });
    }

    match daemon.calls.start_call(
        StartCallInput {
            harness,
            session_id: session_id.to_string(),
            tool: tool.to_string(),
            call_id,
            backend_json: Some(backend_json),
            ttl_ms: None,
        },
        now_ms(),
    ) {
        Ok(reg) => json!({
            "ok": true,
            "result": {
                "callToken": reg.token,
                "sessionId": reg.session_id,
            }
        }),
        Err(msg) => json!({ "ok": false, "error": msg }),
    }
}

async fn handle_mailbox_drain(daemon: &LocalDaemonInner, packet: &Map<String, Value>) -> Value {
    let Some(session_id) = packet
        .get("sessionId")
        .and_then(Value::as_str)
        .filter(|s| is_valid_session_id(s))
    else {
        return json!({ "ok": false, "error": "invalid_session" });
    };

    let session_exists = daemon
        .node
        .db()
        .local()
        .get_session(session_id)
        .ok()
        .flatten()
        .is_some();
    if !session_exists {
        return json!({ "ok": true, "result": { "items": [] } });
    }

    match daemon.build_batch_for_session(session_id).await {
        None => {
            daemon.cancel_hold_retry(session_id);
            json!({ "ok": true, "result": { "items": [] } })
        }
        Some(batch) => {
            daemon.commit_delivered_batch(session_id, &batch);
            json!({
                "ok": true,
                "result": {
                    "items": [{
                        "text": batch.rendered,
                        "notifyOnly": batch.notify_only,
                        "mutedCount": batch.muted_count,
                        "inlineIds": batch.inline_ids,
                        "spilledIds": batch.spilled_ids,
                        "truncatedIds": batch.truncated_ids,
                    }]
                }
            })
        }
    }
}

async fn handle_session_status(daemon: &LocalDaemonInner, packet: &Map<String, Value>) -> Value {
    let Some(session_id) = packet.get("sessionId").and_then(Value::as_str) else {
        return json!({ "ok": false, "error": "invalid_session" });
    };
    daemon.wait_for_pending_probe(session_id).await;
    daemon.reconcile_session_inbox(session_id).await;
    let (sess, pending, muted, policy) = {
        let db = daemon.node.db();
        let sess = db.local().get_session(session_id).ok().flatten();
        let pending = db.local().pending_count(session_id).unwrap_or(0);
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

async fn handle_daemon_status(daemon: &LocalDaemonInner) -> Value {
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
            let p = db.local().pending_count(&s.id).unwrap_or(0);
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
            "profile": daemon.node.config().profile,
            "socketPath": daemon.socket_path.display().to_string(),
            "sessions": sessions_json,
            "peers": peers_json,
            "mutedCount": total_muted,
            "quarantinedCount": total_quarantined,
        }
    })
}

fn parse_rules_arg(args: &Map<String, Value>) -> Result<Vec<DeliveryRule>, (String, String)> {
    let Some(raw) = args.get("rules") else {
        return Ok(Vec::new());
    };
    let Value::Array(items) = raw else {
        return Err((
            "invalid_request".into(),
            "Expected 'rules' to be an array of { target, delivery }".into(),
        ));
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let rule: DeliveryRule = serde_json::from_value(item.clone())
            .map_err(|e| ("invalid_request".into(), format!("Invalid delivery rule: {e}")))?;
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
    let from = map.get("from").and_then(Value::as_str).map(ToString::to_string);
    let node = map.get("node").and_then(Value::as_str).map(ToString::to_string);
    let topic = map.get("topic").and_then(Value::as_str).map(ToString::to_string);
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

fn parse_bridge_plugin_target(
    args: &Map<String, Value>,
) -> Result<(String, String), (String, String)> {
    let plugin_opt = args
        .get("plugin")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let target_raw = args
        .get("target")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ("invalid_request".into(), "Expected target".into()))?;

    let (plugin, target) = if let Some(p) = plugin_opt {
        (p.to_ascii_lowercase(), target_raw.to_string())
    } else if let Some((p, t)) = target_raw.split_once(':') {
        let p_trim = p.trim().to_ascii_lowercase();
        let t_trim = t.trim();
        if p_trim.is_empty() || t_trim.is_empty() {
            return Err((
                "invalid_request".into(),
                "Expected valid plugin and target".into(),
            ));
        }
        (p_trim, t_trim.to_string())
    } else {
        return Err(("invalid_request".into(), "Expected plugin".into()));
    };

    Ok((plugin, target))
}

fn node_err_tuple(err: hyp_node::engine::NodeError) -> (String, String) {
    let problem = err.to_problem_details();
    (problem.error, problem.detail.unwrap_or(problem.title))
}

fn store_err_tuple(err: hyp_store::StoreError) -> (String, String) {
    ("store_error".into(), err.to_string())
}

fn delivery_err_tuple(err: hyp_node::delivery::DeliveryError) -> (String, String) {
    ("delivery_error".into(), err.to_string())
}

fn wakeup_store_err_tuple(err: StoreError) -> (String, String) {
    match err {
        StoreError::QuotaExceeded(msg) => ("wakeup_quota_exceeded".into(), msg),
        StoreError::Unauthorized(msg) => ("forbidden".into(), msg),
        StoreError::NotFound(msg) => ("not_found".into(), msg),
        StoreError::IdConflict(msg) => ("id_conflict".into(), msg),
        StoreError::InvalidState(msg) => ("invalid_state".into(), msg),
        StoreError::InvalidInput(msg) | StoreError::TooLarge(msg) => ("invalid_request".into(), msg),
        other => ("store_error".into(), other.to_string()),
    }
}

struct WakeupDeliveryRequest {
    wakeup_id: String,
    label: String,
    note: String,
    trigger: String,
    urgency: WakeupUrgency,
    target_session_id: Option<String>,
    target_handle: Option<String>,
    target_topic: Option<String>,
    coalesce_key: Option<String>,
    ttl_ms: Option<i64>,
    scheduled_for_ms: i64,
    fired_at_ms: i64,
    iteration: u64,
    max_iterations: Option<u64>,
    missed_count: u64,
    cold_revival_template: Option<String>,
    is_external: bool,
    is_persisted_wakeup: bool,
}

struct WakeupDeliveryOutcome {
    delivered: bool,
    pushed: bool,
    session_id: Option<String>,
    receipt: Option<String>,
    missed_count: u64,
    cold_revived: bool,
    muted: bool,
}

struct ParsedWakeupSchedule {
    trigger_kind: WakeupTriggerKind,
    cron_expr: Option<String>,
    fire_at: Option<i64>,
    timezone: CronTimezone,
    exact_timing: bool,
    max_iterations: Option<u64>,
}

fn format_wakeup_text(
    wakeup_id: &str,
    trigger: &str,
    label: &str,
    iteration: u64,
    max_iterations: Option<u64>,
    missed_count: u64,
    note: &str,
) -> String {
    let max_part = match max_iterations {
        Some(max) => format!("/{max}"),
        None => String::new(),
    };
    let safe_label = label.replace(['\r', '\n', '"'], " ");
    format!(
        "{UNTRUSTED_PROVENANCE}\n[wakeup:{wakeup_id} trigger={trigger} label=\"{safe_label}\" iter={iteration}{max_part} missed={missed_count}]\n{note}"
    )
}

fn build_wakeup_cloudevent(
    node_id: &str,
    req: &WakeupDeliveryRequest,
    resolved_session_id: Option<&str>,
    missed_count: u64,
    expires_at: Option<i64>,
) -> ProtoCloudEvent {
    let mut extensions = BTreeMap::new();
    extensions.insert("hyphaetrigger".into(), Value::String(req.trigger.clone()));
    extensions.insert(
        "hyphaeurgency".into(),
        Value::String(req.urgency.as_str().to_string()),
    );
    let safe_wk_id: String = req.wakeup_id.chars().take(128).collect();
    extensions.insert("hyphaewakeupid".into(), Value::String(safe_wk_id));

    ProtoCloudEvent {
        specversion: "1.0".into(),
        id: format!("wkp_{}", uuid_v4()),
        source: format!("hyphae://{node_id}/wakeup/{}", req.trigger),
        event_type: "to.hyphae.wakeup.v1".into(),
        datacontenttype: Some(CONTENT_TYPE_JSON.into()),
        dataschema: None,
        subject: Some(format!("wakeup/{}", req.label)),
        time: Some(epoch_ms_to_rfc3339(req.fired_at_ms)),
        data: Some(json!({
            "wakeupId": req.wakeup_id,
            "label": req.label,
            "note": req.note,
            "targetSession": resolved_session_id.or(req.target_session_id.as_deref()),
            "targetHandle": req.target_handle,
            "targetTopic": req.target_topic,
            "urgency": req.urgency.as_str(),
            "trigger": req.trigger,
            "scheduledFor": epoch_ms_to_rfc3339(req.scheduled_for_ms),
            "firedAt": epoch_ms_to_rfc3339(req.fired_at_ms),
            "iteration": req.iteration,
            "maxIterations": req.max_iterations,
            "missedCount": missed_count,
            "expiresAt": expires_at.map(epoch_ms_to_rfc3339),
            "untrusted": true,
        })),
        data_base64: None,
        extensions,
    }
}

fn resolve_local_wakeup_target(
    raw_to: &str,
    local_node_id: &str,
) -> Result<String, (String, String)> {
    let trimmed = raw_to.trim();
    let stripped = trimmed.strip_prefix('@').unwrap_or(trimmed);
    if stripped.is_empty() {
        return Err(("invalid_request".into(), "Expected non-empty target 'to'".into()));
    }
    if stripped.starts_with('#') || stripped.contains(':') {
        return Err((
            "invalid_request".into(),
            format!("Wakeup target '{raw_to}' must be a local handle, not a channel or bridge"),
        ));
    }
    if stripped.contains('/') {
        let Some((node_part, handle_part)) = parse_address(stripped) else {
            return Err((
                "remote_target_forbidden".into(),
                format!("Wakeup target '{raw_to}' is not a valid local handle"),
            ));
        };
        if node_part != "local" && node_part != local_node_id {
            return Err((
                "remote_target_forbidden".into(),
                format!(
                    "Cross-node wakeup target '{raw_to}' is not permitted; use hyp_send for remote peers"
                ),
            ));
        }
        return Ok(handle_part.to_string());
    }
    if !hyp_store::is_handle(stripped) {
        return Err((
            "invalid_request".into(),
            format!("Invalid local handle '{raw_to}'"),
        ));
    }
    Ok(stripped.to_string())
}

fn parse_wakeup_urgency_arg(args: &Map<String, Value>) -> Result<WakeupUrgency, (String, String)> {
    match args.get("urgency").and_then(Value::as_str) {
        None => Ok(WakeupUrgency::Queue),
        Some(raw) => WakeupUrgency::parse(raw).map_err(wakeup_store_err_tuple),
    }
}

fn parse_wakeup_ttl_ms_arg(
    args: &Map<String, Value>,
    enforce_mcp_bounds: bool,
) -> Result<i64, (String, String)> {
    let Some(raw) = args.get("ttlSeconds") else {
        return Ok(DEFAULT_WAKEUP_TTL_MS);
    };
    if raw.is_null() {
        return Ok(DEFAULT_WAKEUP_TTL_MS);
    }
    let secs = raw.as_i64().ok_or_else(|| {
        (
            "invalid_request".into(),
            "Expected integer 'ttlSeconds'".into(),
        )
    })?;
    if enforce_mcp_bounds && !(30..=86_400).contains(&secs) {
        return Err((
            "invalid_request".into(),
            format!("ttlSeconds ({secs}) must be between 30 and 86400"),
        ));
    }
    if secs < 1 {
        return Err((
            "invalid_request".into(),
            "ttlSeconds must be >= 1".into(),
        ));
    }
    Ok(secs.saturating_mul(1000))
}

fn parse_wakeup_schedule_args(
    args: &Map<String, Value>,
    is_agent: bool,
    now: i64,
) -> Result<ParsedWakeupSchedule, (String, String)> {
    let in_seconds_val = args.get("inSeconds").filter(|v| !v.is_null());
    let at_val = args.get("at").filter(|v| !v.is_null());
    let cron_val = args.get("cron").filter(|v| !v.is_null());

    let provided_count = usize::from(in_seconds_val.is_some())
        + usize::from(at_val.is_some())
        + usize::from(cron_val.is_some());
    if provided_count != 1 {
        return Err((
            "invalid_request".into(),
            "Specify exactly one of 'inSeconds', 'at', or 'cron'".into(),
        ));
    }

    let timezone = match args.get("timezone").and_then(Value::as_str) {
        None => CronTimezone::Local,
        Some(tz) => CronTimezone::parse(tz).map_err(|e| ("invalid_request".into(), e.to_string()))?,
    };
    let exact_timing = args.get("exact").and_then(Value::as_bool).unwrap_or(false);

    if let Some(secs_v) = in_seconds_val {
        let secs = secs_v.as_i64().ok_or_else(|| {
            (
                "invalid_request".into(),
                "Expected integer 'inSeconds'".into(),
            )
        })?;
        let min_secs = if is_agent { 5 } else { 1 };
        if !(min_secs..=2_592_000).contains(&secs) {
            return Err((
                "invalid_request".into(),
                format!("inSeconds ({secs}) must be between {min_secs} and 2592000"),
            ));
        }
        return Ok(ParsedWakeupSchedule {
            trigger_kind: WakeupTriggerKind::Timer,
            cron_expr: None,
            fire_at: Some(now.saturating_add(secs.saturating_mul(1000))),
            timezone,
            exact_timing,
            max_iterations: Some(1),
        });
    }

    if let Some(at_v) = at_val {
        let at_str = at_v.as_str().ok_or_else(|| {
            (
                "invalid_request".into(),
                "Expected RFC 3339 string for 'at'".into(),
            )
        })?;
        let nanos = parse_rfc3339_utc_nanos(at_str).ok_or_else(|| {
            (
                "invalid_request".into(),
                format!("Invalid RFC 3339 timestamp '{at_str}'"),
            )
        })?;
        let fire_at_ms = i64::try_from(nanos.div_euclid(1_000_000))
            .map_err(|_| ("invalid_request".into(), "Timestamp out of range".into()))?;
        return Ok(ParsedWakeupSchedule {
            trigger_kind: WakeupTriggerKind::Timer,
            cron_expr: None,
            fire_at: Some(fire_at_ms),
            timezone,
            exact_timing,
            max_iterations: Some(1),
        });
    }

    let cron_str = cron_val
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            (
                "invalid_request".into(),
                "Expected non-empty 5-field cron expression".into(),
            )
        })?;

    let max_iterations = match args.get("maxIterations").filter(|v| !v.is_null()) {
        Some(v) => {
            let n = v.as_u64().ok_or_else(|| {
                (
                    "invalid_request".into(),
                    "Expected positive integer 'maxIterations'".into(),
                )
            })?;
            if n < 1 || (is_agent && n > 1000) {
                return Err((
                    "invalid_request".into(),
                    format!("maxIterations ({n}) must be in 1..=1000"),
                ));
            }
            Some(n)
        }
        None if is_agent => Some(100),
        None => None,
    };

    Ok(ParsedWakeupSchedule {
        trigger_kind: WakeupTriggerKind::Cron,
        cron_expr: Some(cron_str.to_string()),
        fire_at: None,
        timezone,
        exact_timing,
        max_iterations,
    })
}

fn wakeup_record_to_json(rec: &WakeupRecord) -> Value {
    json!({
        "id": rec.id,
        "ownerSessionId": rec.owner_session_id,
        "targetSessionId": rec.target_session_id,
        "targetHandle": rec.target_handle,
        "targetTopic": rec.target_topic,
        "label": rec.label,
        "note": rec.note,
        "trigger": rec.trigger_kind.as_str(),
        "cron": rec.cron_expr,
        "timezone": rec.timezone.as_str(),
        "exact": rec.exact_timing,
        "urgency": rec.urgency.as_str(),
        "ttlMs": rec.ttl_ms,
        "coalesce": rec.coalesce,
        "nextFireAt": rec.next_fire_at,
        "nextFireAtRfc3339": epoch_ms_to_rfc3339(rec.next_fire_at),
        "lastFiredAt": rec.last_fired_at,
        "iteration": rec.iteration,
        "maxIterations": rec.max_iterations,
        "consecutiveFailures": rec.consecutive_failures,
        "coldRevivalTemplate": rec.cold_revival_template,
        "state": rec.state.as_str(),
        "lastError": rec.last_error,
    })
}

async fn handle_wakeup_set_rpc(
    daemon: &Arc<LocalDaemonInner>,
    packet: &Map<String, Value>,
) -> Value {
    if !daemon.config.wakeup.enabled {
        return json!({ "ok": false, "error": "wakeup_disabled" });
    }
    let now = now_ms();

    let label = packet
        .get("label")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("wakeup")
        .to_string();
    let Some(note) = packet
        .get("note")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(ToString::to_string)
    else {
        return json!({ "ok": false, "error": "Expected non-empty 'note'" });
    };

    let owner_session_id = packet
        .get("ownerSessionId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);
    let target_session_id = packet
        .get("targetSessionId")
        .or_else(|| packet.get("sessionId"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);
    let target_handle = match packet
        .get("targetHandle")
        .or_else(|| packet.get("to"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw) => match resolve_local_wakeup_target(raw, daemon.node.node_id().as_str()) {
            Ok(h) => Some(h),
            Err((code, msg)) => return json!({ "ok": false, "error": format!("{code}: {msg}") }),
        },
        None => None,
    };
    let target_topic = packet
        .get("targetTopic")
        .or_else(|| packet.get("topic"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);

    let cold_revival_template = match packet
        .get("coldRevivalTemplate")
        .or_else(|| packet.get("template"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(tpl) => {
            if !is_valid_herdr_template(tpl)
                || !daemon
                    .config
                    .wakeup
                    .herdr_spawn_allowlist
                    .iter()
                    .any(|a| a == tpl)
            {
                return json!({ "ok": false, "error": "herdr_template_not_allowlisted" });
            }
            Some(tpl.to_string())
        }
        None => None,
    };

    let parsed = match parse_wakeup_schedule_args(packet, owner_session_id.is_some(), now) {
        Ok(p) => p,
        Err((code, msg)) => return json!({ "ok": false, "error": format!("{code}: {msg}") }),
    };
    let urgency = match parse_wakeup_urgency_arg(packet) {
        Ok(u) => u,
        Err((code, msg)) => return json!({ "ok": false, "error": format!("{code}: {msg}") }),
    };
    let ttl_ms = match parse_wakeup_ttl_ms_arg(packet, false) {
        Ok(t) => t,
        Err((code, msg)) => return json!({ "ok": false, "error": format!("{code}: {msg}") }),
    };
    let coalesce = packet
        .get("coalesce")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let id = packet
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);

    let insert = WakeupInsert {
        id,
        owner_session_id,
        target_session_id,
        target_handle,
        target_topic,
        label,
        note,
        trigger_kind: parsed.trigger_kind,
        cron_expr: parsed.cron_expr,
        timezone: parsed.timezone,
        exact_timing: parsed.exact_timing,
        urgency,
        ttl_ms,
        coalesce,
        fire_at: parsed.fire_at,
        max_iterations: parsed.max_iterations,
        cold_revival_template,
    };

    let res = {
        let db = daemon.node.db();
        db.wakeups()
            .create_wakeup(&insert, &WakeupLimits::default(), now)
    };
    match res {
        Ok(rec) => json!({ "ok": true, "result": wakeup_record_to_json(&rec) }),
        Err(err) => {
            let (code, msg) = wakeup_store_err_tuple(err);
            json!({ "ok": false, "error": format!("{code}: {msg}") })
        }
    }
}

fn handle_wakeup_list_rpc(daemon: &LocalDaemonInner, packet: &Map<String, Value>) -> Value {
    let owner_filter = packet
        .get("ownerSessionId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let state_filter = match packet.get("state").and_then(Value::as_str) {
        None | Some("all") => None,
        Some(raw) => match WakeupState::parse(raw) {
            Ok(s) => Some(s),
            Err(e) => return json!({ "ok": false, "error": e.to_string() }),
        },
    };
    let db = daemon.node.db();
    match db.wakeups().list_wakeups(owner_filter, state_filter) {
        Ok(list) => {
            let items: Vec<Value> = list.iter().map(wakeup_record_to_json).collect();
            json!({ "ok": true, "result": { "wakeups": items } })
        }
        Err(e) => json!({ "ok": false, "error": e.to_string() }),
    }
}

fn handle_wakeup_cancel_rpc(daemon: &LocalDaemonInner, packet: &Map<String, Value>) -> Value {
    let Some(id) = packet
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    else {
        return json!({ "ok": false, "error": "Expected wakeup 'id'" });
    };
    let owner = packet
        .get("ownerSessionId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let db = daemon.node.db();
    match db.wakeups().cancel_wakeup(id, owner, now_ms()) {
        Ok(rec) => json!({
            "ok": true,
            "result": {
                "cancelled": true,
                "wakeup": wakeup_record_to_json(&rec),
            }
        }),
        Err(err) => {
            let (code, msg) = wakeup_store_err_tuple(err);
            json!({ "ok": false, "error": format!("{code}: {msg}") })
        }
    }
}

async fn handle_wakeup_fire_rpc(
    daemon: &Arc<LocalDaemonInner>,
    packet: &Map<String, Value>,
) -> Value {
    if !daemon.config.wakeup.enabled {
        return json!({ "ok": false, "error": "wakeup_disabled" });
    }
    execute_external_wakeup_payload(daemon, packet).await
}

async fn handle_wakeup_emit_rpc(
    daemon: &Arc<LocalDaemonInner>,
    packet: &Map<String, Value>,
) -> Value {
    if !daemon.config.wakeup.enabled {
        return json!({ "ok": false, "error": "wakeup_disabled" });
    }

    // Accept either a nested CloudEvents v1.0 / compact object under `event` or `payload`,
    // or fields directly at top-level of `packet`.
    let source_obj = packet
        .get("event")
        .or_else(|| packet.get("payload"))
        .and_then(Value::as_object)
        .unwrap_or(packet);

    // If it's a CloudEvents v1.0 envelope (`specversion == "1.0"` and `data` is an object),
    // merge `data` fields with CloudEvents header fallbacks (`subject`, `hyphaeurgency`, `hyphaewakeupid`).
    let mut normalized = Map::new();
    if let Some(data_obj) = source_obj.get("data").and_then(Value::as_object) {
        for (k, v) in data_obj {
            normalized.insert(k.clone(), v.clone());
        }
        if !normalized.contains_key("label") {
            if let Some(subj) = source_obj.get("subject").and_then(Value::as_str) {
                let lbl = subj.strip_prefix("wakeup/").unwrap_or(subj);
                if !lbl.is_empty() {
                    normalized.insert("label".into(), json!(lbl));
                }
            }
        }
        if !normalized.contains_key("urgency") {
            if let Some(u) = source_obj.get("hyphaeurgency").and_then(Value::as_str) {
                normalized.insert("urgency".into(), json!(u));
            }
        }
        if !normalized.contains_key("id") && !normalized.contains_key("wakeupId") {
            if let Some(wid) = source_obj
                .get("hyphaewakeupid")
                .or_else(|| source_obj.get("id"))
                .and_then(Value::as_str)
            {
                normalized.insert("id".into(), json!(wid));
            }
        }
        if !normalized.contains_key("topic") && !normalized.contains_key("targetTopic") {
            if let Some(topic) = packet.get("topic").and_then(Value::as_str) {
                normalized.insert("topic".into(), json!(topic));
            }
        }
    } else {
        for (k, v) in source_obj {
            normalized.insert(k.clone(), v.clone());
        }
    }

    execute_external_wakeup_payload(daemon, &normalized).await
}

async fn execute_external_wakeup_payload(
    daemon: &Arc<LocalDaemonInner>,
    args: &Map<String, Value>,
) -> Value {
    let now = now_ms();
    let Some(note) = args
        .get("note")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .map(ToString::to_string)
    else {
        return json!({ "ok": false, "error": "Expected non-empty 'note'" });
    };
    let limits = WakeupLimits::default();
    if note.len() > limits.max_note_bytes {
        return json!({
            "ok": false,
            "error": format!("wakeup note is {} bytes; limit {}", note.len(), limits.max_note_bytes)
        });
    }

    let label = args
        .get("label")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("external")
        .to_string();

    let target_session_id = args
        .get("targetSessionId")
        .or_else(|| args.get("targetSession"))
        .or_else(|| args.get("sessionId"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);
    let target_handle = match args
        .get("targetHandle")
        .or_else(|| args.get("to"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        Some(raw) => match resolve_local_wakeup_target(raw, daemon.node.node_id().as_str()) {
            Ok(h) => Some(h),
            Err((code, msg)) => return json!({ "ok": false, "error": format!("{code}: {msg}") }),
        },
        None => None,
    };
    let target_topic = args
        .get("targetTopic")
        .or_else(|| args.get("topic"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);

    let cold_revival_template = args
        .get("coldRevivalTemplate")
        .or_else(|| args.get("template"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);

    if target_session_id.is_none()
        && target_handle.is_none()
        && target_topic.is_none()
        && cold_revival_template.is_none()
    {
        return json!({
            "ok": false,
            "error": "Expected target ('to', 'sessionId', 'topic', or 'coldRevivalTemplate')"
        });
    }

    let urgency = match parse_wakeup_urgency_arg(args) {
        Ok(u) => u,
        Err((code, msg)) => return json!({ "ok": false, "error": format!("{code}: {msg}") }),
    };
    let ttl_ms = match parse_wakeup_ttl_ms_arg(args, false) {
        Ok(t) => t,
        Err((code, msg)) => return json!({ "ok": false, "error": format!("{code}: {msg}") }),
    };

    let wakeup_id = args
        .get("wakeupId")
        .or_else(|| args.get("id"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string)
        .unwrap_or_else(|| format!("wk-ext-{}", uuid_v4()));

    let coalesce_key = args
        .get("coalesceKey")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToString::to_string);

    match daemon
        .deliver_wakeup_internal(WakeupDeliveryRequest {
            wakeup_id: wakeup_id.clone(),
            label,
            note,
            trigger: "external".to_string(),
            urgency,
            target_session_id,
            target_handle,
            target_topic,
            coalesce_key,
            ttl_ms: Some(ttl_ms),
            scheduled_for_ms: now,
            fired_at_ms: now,
            iteration: 1,
            max_iterations: Some(1),
            missed_count: 0,
            cold_revival_template,
            is_external: true,
            is_persisted_wakeup: false,
        })
        .await
    {
        Ok(outcome) => json!({
            "ok": true,
            "result": {
                "fired": true,
                "wakeupId": wakeup_id,
                "sessionId": outcome.session_id,
                "delivered": outcome.delivered,
                "pushed": outcome.pushed,
                "coldRevived": outcome.cold_revived,
                "muted": outcome.muted,
                "missedCount": outcome.missed_count,
                "receipt": outcome.receipt,
            }
        }),
        Err(reason) => json!({ "ok": false, "error": reason }),
    }
}
