//! Single unified cross-platform `SubprocessSupervisor` replacing BOTH v1 `PluginProcess`
//! (`src/core/plugins/supervisor.ts`) AND `RouterStreamHost` (`src/streams.ts`).
//!
//! Key guarantees:
//! - Dual cross-platform IPC transports feeding the exact same NDJSON / JSON-RPC 2.0 protocol loop:
//!   - **Unix default (`PluginTransportMode::UnixFd3`)**: explicit private bidirectional Unix fd-3
//!     IPC channel (`socketpair(AF_UNIX, SOCK_STREAM)` duped onto fd 3 with `FD_CLOEXEC` cleared in
//!     `pre_exec`, compatible with Node's `createReadStream`/`createWriteStream({ fd: 3 })` and
//!     Python's `socket.socket(fileno=3)`).
//!   - **Windows default & Unix parity mode (`PluginTransportMode::LoopbackTcp`)**: ephemeral
//!     loopback-only TCP (`127.0.0.1:0`) authenticated with a per-spawn 256-bit CSPRNG token passed
//!     strictly via scrubbed child env (`HYPHAE_PLUGIN_ADDR`, `HYPHAE_PLUGIN_TOKEN`,
//!     `HYPHAE_PLUGIN_TRANSPORT=tcp`), single-connection listener drop, bounded 4 KiB auth frame,
//!     constant-time token verification, and automatic token redaction from stderr/logs.
//! - Clean environment allowlist (never leaks arbitrary host secrets).
//! - Strictly bounded 64 KiB `hyp_proto::rpc::LineSplitter` on incoming IPC frames.
//! - Per-frame protocol auto-detection via `hyp_proto::rpc::decode_frame`, seamlessly supporting
//!   BOTH JSON-RPC 2.0 v2 (`hyphae/hello`, `hyphae/publish`, `hyphae/post`, `hyphae/status`,
//!   `hyphae/deliveryFailed`) AND legacy fd-3 v1 (`hello`, `event`, `ack`, `nack`, `request`,
//!   `response`, `status`, `delivery_failed`).
//! - Outbound `post()` request/response correlation with timeouts, exponential restart backoff on
//!   unexpected child exit, and clean shutdown on both Unix and Windows.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use hyp_proto::rpc::{
    DeliveryFailedParams, JsonRpcNotification, JsonRpcRequest, LegacyV1Frame,
    METHOD_DELIVERY_FAILED, METHOD_POST, METHOD_STATUS, METHOD_SYSTEM_WAKE, PluginFrame,
    PostParams, RpcId, StatusParams, SystemWakeParams, encode_frame,
};
use serde_json::Value;
use tokio::sync::{Mutex, Notify, mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::adapters::trait_def::{
    AdapterError, AdapterHealth, AdapterKind, BoxFuture, NodeAdapter, NodeAdapterHost,
};

/// Safe parent environment variables forwarded to supervised child processes.
/// Arbitrary host secrets (API tokens, cloud credentials, etc.) are NEVER inherited.
pub const ALLOWED_PARENT_ENV: &[&str] = &[
    "PATH",
    "HOME",
    "TMPDIR",
    "LANG",
    "XDG_RUNTIME_DIR",
    "DBUS_SESSION_BUS_ADDRESS",
    // Windows runtime essentials (OS/temp/profile paths required by Winsock, Node.js, and Python;
    // never carry user credentials).
    "SYSTEMROOT",
    "SYSTEMDRIVE",
    "WINDIR",
    "COMSPEC",
    "PATHEXT",
    "TEMP",
    "TMP",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
];

const PROTO_UNKNOWN: u8 = 0;
const PROTO_LEGACY_V1: u8 = 1;
const PROTO_JSONRPC_V2: u8 = 2;

/// IPC transport used between `SubprocessSupervisor` and supervised plugin subprocesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginTransportMode {
    /// Private bidirectional Unix `socketpair(AF_UNIX, SOCK_STREAM)` duped onto fd 3.
    #[cfg(unix)]
    UnixFd3,
    /// Authenticated loopback-only TCP (`127.0.0.1:0`) with a per-spawn 256-bit CSPRNG token.
    LoopbackTcp,
}

impl Default for PluginTransportMode {
    fn default() -> Self {
        #[cfg(unix)]
        {
            Self::UnixFd3
        }
        #[cfg(not(unix))]
        {
            Self::LoopbackTcp
        }
    }
}

/// Detected or configured wire protocol on the child's IPC channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireProtocol {
    Auto,
    LegacyV1,
    JsonRpcV2,
}

/// Controls the initial greeting sent by the supervisor when a child starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloMode {
    /// Waits up to `auto_hello_grace` for a v2 child to initiate `hyphae/hello` or `hyphae/publish`;
    /// if the child stays silent waiting for a host greeting (as unmodified v1 plugins do),
    /// sends a legacy v1 `hello` frame automatically.
    Auto,
    /// Immediately sends a JSON-RPC 2.0 `hyphae/hello` notification upon spawn.
    JsonRpcV2,
    /// Immediately sends a legacy fd-3 v1 `{"type":"hello","protocol":1,...}` upon spawn.
    LegacyV1,
}

/// Per-spawn environment resolver invoked before every child spawn/respawn to freshly resolve
/// dynamic values (such as `{ "secret": "<name>" }` references from `SecretStore`).
pub type EnvResolver = Arc<dyn Fn() -> Result<BTreeMap<String, String>, String> + Send + Sync>;

/// Configuration for a supervised plugin subprocess adapter.
#[derive(Clone)]
pub struct SubprocessConfig {
    pub id: String,
    pub kind: AdapterKind,
    pub exec: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    /// Allowed targets / topics this subprocess may publish to.
    pub targets: Vec<String>,
    /// Explicit plugin configuration environment variables (merged on top of the safe allowlist).
    pub env: BTreeMap<String, String>,
    /// Optional per-spawn dynamic environment resolver (re-invoked on every spawn & respawn,
    /// e.g. to freshly load `{ "secret": "<name>" }` references from `SecretStore` and refresh
    /// stderr redaction needles).
    pub env_resolver: Option<EnvResolver>,
    /// IPC transport (`UnixFd3` by default on Unix, `LoopbackTcp` by default on Windows and
    /// selectable on Unix for differential parity testing).
    pub transport_mode: PluginTransportMode,
    /// Bounded startup/handshake timeout for `PluginTransportMode::LoopbackTcp` (default: 10 s).
    pub startup_timeout: Duration,
    /// Protocol negotiation mode (`Auto` supports both JSON-RPC 2.0 v2 and legacy v1).
    pub hello_mode: HelloMode,
    /// Grace window in `HelloMode::Auto` before sending a legacy v1 hello to silent children.
    pub auto_hello_grace: Duration,
    /// Initial exponential restart backoff delay.
    pub initial_backoff: Duration,
    /// Maximum exponential restart backoff delay.
    pub max_backoff: Duration,
    /// Uptime threshold after which backoff resets to `initial_backoff`.
    pub reset_after: Duration,
    /// Delay between graceful termination request and forced kill during shutdown.
    pub kill_timeout: Duration,
    /// Optional explicit parent env map (defaults to `std::env::vars()` when `None`).
    pub parent_env_override: Option<BTreeMap<String, String>>,
    /// Optional bounded per-plugin stderr log file path (e.g. `<state_dir>/logs/plugin-<id>.log`).
    pub stderr_log_path: Option<PathBuf>,
    /// Maximum byte size for `stderr_log_path` before truncating/rotating (default: 1 MiB).
    pub max_stderr_log_bytes: u64,
    /// Explicit secret values to redact (`[REDACTED]`) from captured stderr, logs, and health errors.
    pub redacted_values: Vec<String>,
    /// Window under which an unexpected exit counts as a rapid crash (default: 5 s).
    pub rapid_crash_window: Duration,
    /// Number of consecutive rapid crashes that trips the circuit breaker into `CrashLoopBackOff` (default: 5; `0` disables).
    pub max_rapid_crashes: u32,
}

impl std::fmt::Debug for SubprocessConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SubprocessConfig")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("exec", &self.exec)
            .field("args", &self.args)
            .field("cwd", &self.cwd)
            .field("targets", &self.targets)
            .field("env_keys", &self.env.keys().collect::<Vec<_>>())
            .field("has_env_resolver", &self.env_resolver.is_some())
            .field("transport_mode", &self.transport_mode)
            .field("startup_timeout", &self.startup_timeout)
            .field("hello_mode", &self.hello_mode)
            .field("auto_hello_grace", &self.auto_hello_grace)
            .field("initial_backoff", &self.initial_backoff)
            .field("max_backoff", &self.max_backoff)
            .field("reset_after", &self.reset_after)
            .field("kill_timeout", &self.kill_timeout)
            .field("stderr_log_path", &self.stderr_log_path)
            .field("max_stderr_log_bytes", &self.max_stderr_log_bytes)
            .field("redacted_values_count", &self.redacted_values.len())
            .field("rapid_crash_window", &self.rapid_crash_window)
            .field("max_rapid_crashes", &self.max_rapid_crashes)
            .finish()
    }
}

/// Default bounded per-plugin stderr log file size (1 MiB).
pub const DEFAULT_MAX_STDERR_LOG_BYTES: u64 = 1024 * 1024;
/// Default rapid-crash window for circuit-breaker detection (5 seconds).
pub const DEFAULT_RAPID_CRASH_WINDOW: Duration = Duration::from_secs(5);
/// Default consecutive rapid crashes before tripping into `CrashLoopBackOff`.
pub const DEFAULT_MAX_RAPID_CRASHES: u32 = 5;
/// Default loopback-TCP plugin startup & authentication handshake timeout (10 seconds).
pub const DEFAULT_STARTUP_TIMEOUT: Duration = Duration::from_secs(10);

/// Returns `true` when an environment variable name looks like it carries a raw secret value
/// (`TOKEN`, `SECRET`, `KEY`, `PASSWORD`, `AUTH`, `PASS`), excluding `*_FILE` path pointers.
pub fn is_secret_like_env_key(key: &str) -> bool {
    let upper = key.trim().to_ascii_uppercase();
    if upper.is_empty() || upper.ends_with("_FILE") {
        return false;
    }
    ["TOKEN", "SECRET", "KEY", "PASSWORD", "AUTH", "PASS"]
        .iter()
        .any(|needle| upper.contains(needle))
}

impl SubprocessConfig {
    pub fn new(
        id: impl Into<String>,
        kind: AdapterKind,
        exec: impl Into<String>,
        args: Vec<String>,
        targets: Vec<String>,
    ) -> Self {
        Self {
            id: id.into(),
            kind,
            exec: exec.into(),
            args,
            cwd: None,
            targets,
            env: BTreeMap::new(),
            env_resolver: None,
            transport_mode: PluginTransportMode::default(),
            startup_timeout: DEFAULT_STARTUP_TIMEOUT,
            hello_mode: HelloMode::Auto,
            auto_hello_grace: Duration::from_millis(50),
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(60),
            reset_after: Duration::from_secs(60),
            kill_timeout: Duration::from_secs(5),
            parent_env_override: None,
            stderr_log_path: None,
            max_stderr_log_bytes: DEFAULT_MAX_STDERR_LOG_BYTES,
            redacted_values: Vec::new(),
            rapid_crash_window: DEFAULT_RAPID_CRASH_WINDOW,
            max_rapid_crashes: DEFAULT_MAX_RAPID_CRASHES,
        }
    }
}

/// Builds the isolated child environment from [`ALLOWED_PARENT_ENV`], explicit plugin `config.env`,
/// and standard Hyphae protocol variables (`HYPHAE_PROTOCOL=2`, `HYPHAE_FD=3` on Unix fd-3 or
/// `HYPHAE_PLUGIN_TRANSPORT=tcp` on loopback-TCP, etc.).
pub fn build_isolated_env(
    config: &SubprocessConfig,
    parent_env: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    build_isolated_env_with(config, parent_env, &config.env)
}

/// Same as [`build_isolated_env`], using an explicit resolved plugin environment map (e.g. after
/// running `config.env_resolver` on spawn/respawn).
pub fn build_isolated_env_with(
    config: &SubprocessConfig,
    parent_env: &BTreeMap<String, String>,
    plugin_env: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for (k, v) in parent_env {
        #[cfg(windows)]
        let allowed = ALLOWED_PARENT_ENV
            .iter()
            .any(|allowed_key| allowed_key.eq_ignore_ascii_case(k));
        #[cfg(not(windows))]
        let allowed = ALLOWED_PARENT_ENV.contains(&k.as_str());
        if allowed {
            env.insert(k.clone(), v.clone());
        }
    }
    for (k, v) in plugin_env {
        env.insert(k.clone(), v.clone());
    }
    #[cfg(unix)]
    if config.transport_mode == PluginTransportMode::UnixFd3 {
        env.remove("HYPHAE_PLUGIN_ADDR");
        env.remove("HYPHAE_PLUGIN_TOKEN");
        env.remove("HYPHAE_PLUGIN_TRANSPORT");
        env.insert("HYPHAE_FD".to_string(), "3".to_string());
        env.insert("AGENTS_MESH_FD".to_string(), "3".to_string());
        env.insert("T3_MESH_FD".to_string(), "3".to_string());
    } else {
        env.remove("HYPHAE_FD");
        env.remove("AGENTS_MESH_FD");
        env.remove("T3_MESH_FD");
        env.insert("HYPHAE_PLUGIN_TRANSPORT".to_string(), "tcp".to_string());
    }
    #[cfg(not(unix))]
    {
        env.remove("HYPHAE_FD");
        env.remove("AGENTS_MESH_FD");
        env.remove("T3_MESH_FD");
        env.insert("HYPHAE_PLUGIN_TRANSPORT".to_string(), "tcp".to_string());
    }
    env.insert("HYPHAE_PLUGIN".to_string(), config.id.clone());
    env.insert("HYPHAE_PROTOCOL".to_string(), "2".to_string());
    env.insert("AGENTS_MESH_PLUGIN".to_string(), config.id.clone());
    env.insert("T3_MESH_PLUGIN".to_string(), config.id.clone());
    env.insert("T3_MESH_PROTOCOL".to_string(), "1".to_string());
    if config.kind == AdapterKind::Source {
        env.insert("HYPHAE_STREAM".to_string(), config.id.clone());
        env.insert("AGENTS_MESH_STREAM".to_string(), config.id.clone());
        if let Some(first_topic) = config.targets.first() {
            env.insert("HYPHAE_TOPIC".to_string(), first_topic.clone());
            env.insert("AGENTS_MESH_TOPIC".to_string(), first_topic.clone());
        }
    }
    env
}

type PendingMap = HashMap<String, oneshot::Sender<Result<Value, AdapterError>>>;

struct ActiveConnection {
    tx: mpsc::Sender<String>,
    detected_protocol: Arc<AtomicU8>,
    pending_requests: Arc<Mutex<PendingMap>>,
}

struct SupervisorInner {
    config: SubprocessConfig,
    health: RwLock<AdapterHealth>,
    active: Mutex<Option<ActiveConnection>>,
    stopping: Arc<AtomicU8>,
    stop_notify: Arc<Notify>,
    loop_handle: Mutex<Option<JoinHandle<()>>>,
    next_req_id: AtomicU64,
    restart_count: AtomicU64,
    oversized_frames_rejected: AtomicU64,
    last_status: RwLock<Option<StatusParams>>,
    last_detected_protocol: AtomicU8,
    recent_stderr: RwLock<VecDeque<String>>,
    last_error: RwLock<Option<String>>,
    crash_loop_backoff: AtomicBool,
}

/// Unified fd-3 subprocess supervisor supporting both JSON-RPC 2.0 v2 and legacy fd-3 v1 plugins.
#[derive(Clone)]
pub struct SubprocessSupervisor {
    inner: Arc<SupervisorInner>,
}

impl SubprocessSupervisor {
    pub fn new(config: SubprocessConfig) -> Self {
        Self {
            inner: Arc::new(SupervisorInner {
                config,
                health: RwLock::new(AdapterHealth::Stopped),
                active: Mutex::new(None),
                stopping: Arc::new(AtomicU8::new(0)),
                stop_notify: Arc::new(Notify::new()),
                loop_handle: Mutex::new(None),
                next_req_id: AtomicU64::new(1),
                restart_count: AtomicU64::new(0),
                oversized_frames_rejected: AtomicU64::new(0),
                last_status: RwLock::new(None),
                last_detected_protocol: AtomicU8::new(PROTO_UNKNOWN),
                recent_stderr: RwLock::new(VecDeque::new()),
                last_error: RwLock::new(None),
                crash_loop_backoff: AtomicBool::new(false),
            }),
        }
    }

    /// Returns the number of unexpected restarts performed by this supervisor.
    pub fn restart_count(&self) -> u64 {
        self.inner.restart_count.load(Ordering::Relaxed)
    }

    /// Returns recent bounded stderr lines captured from the child process (secret values redacted).
    pub fn recent_stderr(&self) -> Vec<String> {
        self.inner
            .recent_stderr
            .read()
            .expect("stderr lock")
            .iter()
            .cloned()
            .collect()
    }

    /// Returns the most recent redacted error summary recorded by this supervisor, if any.
    pub fn last_error(&self) -> Option<String> {
        self.inner
            .last_error
            .read()
            .expect("last_error lock")
            .clone()
    }

    /// Returns `true` when the supervisor has tripped its rapid crash-loop circuit breaker.
    pub fn is_crash_loop_backoff(&self) -> bool {
        self.inner.crash_loop_backoff.load(Ordering::Acquire)
    }

    /// Returns the configured bounded per-plugin stderr log file path, if any.
    pub fn stderr_log_path(&self) -> Option<PathBuf> {
        self.inner.config.stderr_log_path.clone()
    }

    /// Returns the number of >64 KiB oversized frames rejected on fd 3.
    pub fn oversized_frames_rejected(&self) -> u64 {
        self.inner.oversized_frames_rejected.load(Ordering::Relaxed)
    }

    /// Returns the most recent `StatusParams` reported by the child, if any.
    pub fn last_status(&self) -> Option<StatusParams> {
        self.inner.last_status.read().expect("status lock").clone()
    }

    /// Returns the most recently detected wire protocol for the running/last child.
    pub fn detected_protocol(&self) -> WireProtocol {
        match self.inner.last_detected_protocol.load(Ordering::Acquire) {
            PROTO_LEGACY_V1 => WireProtocol::LegacyV1,
            PROTO_JSONRPC_V2 => WireProtocol::JsonRpcV2,
            _ => WireProtocol::Auto,
        }
    }

    /// Returns `true` when a child process is live and its fd-3 writer is active.
    pub async fn is_connected(&self) -> bool {
        self.inner.active.lock().await.is_some()
    }

    /// Sends an outbound `post` request (`hyphae/post` in v2 or `{"type":"request","method":"post",...}`
    /// in v1) and awaits the correlated response up to `timeout`.
    pub async fn post(
        &self,
        target: &str,
        params: BTreeMap<String, Value>,
        timeout: Duration,
    ) -> Result<Value, AdapterError> {
        let req_num = self.inner.next_req_id.fetch_add(1, Ordering::Relaxed);
        let req_id = format!("req-{req_num}");

        let (tx, detected, pending_map) = {
            let guard = self.inner.active.lock().await;
            let Some(conn) = guard.as_ref() else {
                return Err(AdapterError::NotRunning(self.inner.config.id.clone()));
            };
            (
                conn.tx.clone(),
                conn.detected_protocol.load(Ordering::Acquire),
                Arc::clone(&conn.pending_requests),
            )
        };

        let frame = if detected == PROTO_LEGACY_V1 {
            PluginFrame::LegacyV1(LegacyV1Frame::Request {
                id: req_id.clone(),
                method: "post".to_string(),
                target: target.to_string(),
                params,
            })
        } else {
            let post_params = PostParams {
                target: target.to_string(),
                params,
            };
            let params_val = serde_json::to_value(post_params)
                .map_err(|e| AdapterError::Protocol(e.to_string()))?;
            PluginFrame::JsonRpcRequest(JsonRpcRequest::new(
                RpcId::String(req_id.clone()),
                METHOD_POST,
                Some(params_val),
            ))
        };

        let wire = encode_frame(&frame).map_err(|e| AdapterError::Protocol(e.to_string()))?;

        let (resp_tx, resp_rx) = oneshot::channel();
        {
            let mut map = pending_map.lock().await;
            map.insert(req_id.clone(), resp_tx);
        }

        if tx.send(wire).await.is_err() {
            pending_map.lock().await.remove(&req_id);
            return Err(AdapterError::NotRunning(self.inner.config.id.clone()));
        }

        match tokio::time::timeout(timeout, resp_rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => Err(AdapterError::NotRunning(format!(
                "subprocess '{}' exited before responding to {req_id}",
                self.inner.config.id
            ))),
            Err(_) => {
                pending_map.lock().await.remove(&req_id);
                Err(AdapterError::Timeout(format!(
                    "plugin '{}' post request '{req_id}' timed out after {:?}",
                    self.inner.config.id, timeout
                )))
            }
        }
    }

    /// Sends a `status` notification to the running subprocess using its active wire protocol.
    pub async fn send_status(&self, status: StatusParams) -> Result<(), AdapterError> {
        let (tx, detected) = {
            let guard = self.inner.active.lock().await;
            let Some(conn) = guard.as_ref() else {
                return Err(AdapterError::NotRunning(self.inner.config.id.clone()));
            };
            (
                conn.tx.clone(),
                conn.detected_protocol.load(Ordering::Acquire),
            )
        };

        let frame = if detected == PROTO_LEGACY_V1 {
            PluginFrame::LegacyV1(LegacyV1Frame::Status {
                target: status.target,
                pending: status.pending,
                oldest_age_seconds: status.oldest_age_seconds,
                t3_connected: status.t3_connected,
            })
        } else {
            let val =
                serde_json::to_value(status).map_err(|e| AdapterError::Protocol(e.to_string()))?;
            PluginFrame::JsonRpcNotification(JsonRpcNotification::new(METHOD_STATUS, Some(val)))
        };

        let wire = encode_frame(&frame).map_err(|e| AdapterError::Protocol(e.to_string()))?;
        tx.send(wire)
            .await
            .map_err(|_| AdapterError::NotRunning(self.inner.config.id.clone()))
    }

    /// Sends a `delivery_failed` / `hyphae/deliveryFailed` notification to the running subprocess.
    pub async fn send_delivery_failed(
        &self,
        params: DeliveryFailedParams,
    ) -> Result<(), AdapterError> {
        let (tx, detected) = {
            let guard = self.inner.active.lock().await;
            let Some(conn) = guard.as_ref() else {
                return Err(AdapterError::NotRunning(self.inner.config.id.clone()));
            };
            (
                conn.tx.clone(),
                conn.detected_protocol.load(Ordering::Acquire),
            )
        };

        let frame = if detected == PROTO_LEGACY_V1 {
            PluginFrame::LegacyV1(LegacyV1Frame::DeliveryFailed {
                target: params.target,
                events: params.events,
                reason: params.reason,
            })
        } else {
            let val =
                serde_json::to_value(params).map_err(|e| AdapterError::Protocol(e.to_string()))?;
            PluginFrame::JsonRpcNotification(JsonRpcNotification::new(
                METHOD_DELIVERY_FAILED,
                Some(val),
            ))
        };

        let wire = encode_frame(&frame).map_err(|e| AdapterError::Protocol(e.to_string()))?;
        tx.send(wire)
            .await
            .map_err(|_| AdapterError::NotRunning(self.inner.config.id.clone()))
    }

    /// Sends a best-effort JSON-RPC 2.0 `system.wake` notification (`{ "jsonrpc": "2.0",
    /// "method": "system.wake", "params": { "sleptMs": <u64> } }`) to the running subprocess so
    /// external bridge/source plugins can recycle half-open sockets and polls immediately.
    ///
    /// Because this is a JSON-RPC 2.0 notification (no `id`), older or custom plugins that do not
    /// implement `system.wake` ignore it cleanly without crashing.
    pub async fn send_system_wake(&self, slept_for: Duration) -> Result<(), AdapterError> {
        let tx = {
            let guard = self.inner.active.lock().await;
            let Some(conn) = guard.as_ref() else {
                return Err(AdapterError::NotRunning(self.inner.config.id.clone()));
            };
            conn.tx.clone()
        };

        let slept_ms = slept_for.as_millis().min(u64::MAX as u128) as u64;
        let params = serde_json::to_value(SystemWakeParams { slept_ms })
            .map_err(|e| AdapterError::Protocol(e.to_string()))?;
        let frame = PluginFrame::JsonRpcNotification(JsonRpcNotification::new(
            METHOD_SYSTEM_WAKE,
            Some(params),
        ));
        let wire = encode_frame(&frame).map_err(|e| AdapterError::Protocol(e.to_string()))?;
        tx.send(wire)
            .await
            .map_err(|_| AdapterError::NotRunning(self.inner.config.id.clone()))
    }

    fn set_health(&self, health: AdapterHealth) {
        *self.inner.health.write().expect("health lock") = health;
    }
}

impl NodeAdapter for SubprocessSupervisor {
    fn id(&self) -> &str {
        &self.inner.config.id
    }

    fn kind(&self) -> AdapterKind {
        self.inner.config.kind
    }

    fn start<'a>(
        &'a self,
        host: Arc<dyn NodeAdapterHost>,
    ) -> BoxFuture<'a, Result<(), AdapterError>> {
        Box::pin(async move {
            let mut handle_guard = self.inner.loop_handle.lock().await;
            if handle_guard.is_some() {
                return Err(AdapterError::AlreadyStarted(self.inner.config.id.clone()));
            }

            self.inner.stopping.store(0, Ordering::Release);
            self.inner
                .crash_loop_backoff
                .store(false, Ordering::Release);
            *self.inner.last_error.write().expect("last_error lock") = None;
            self.set_health(AdapterHealth::Starting);
            host.update_status(&self.inner.config.id, AdapterHealth::Starting)
                .await;

            let inner = Arc::clone(&self.inner);
            let ready_notify = Arc::new(Notify::new());
            let ready_notify_bg = Arc::clone(&ready_notify);

            let task = tokio::spawn(async move {
                runtime::supervise_loop(inner, host, Some(ready_notify_bg)).await;
            });

            *handle_guard = Some(task);
            drop(handle_guard);

            let wait_budget = self
                .inner
                .config
                .startup_timeout
                .saturating_add(Duration::from_millis(500))
                .min(Duration::from_secs(5));
            let _ = tokio::time::timeout(wait_budget, ready_notify.notified()).await;
            Ok(())
        })
    }

    fn stop<'a>(&'a self) -> BoxFuture<'a, Result<(), AdapterError>> {
        Box::pin(async move {
            self.inner.stopping.store(1, Ordering::Release);
            self.inner.stop_notify.notify_waiters();

            let handle = self.inner.loop_handle.lock().await.take();
            if let Some(h) = handle {
                let _ = h.await;
            }
            *self.inner.active.lock().await = None;
            self.set_health(AdapterHealth::Stopped);
            Ok(())
        })
    }

    fn health(&self) -> AdapterHealth {
        self.inner.health.read().expect("health lock").clone()
    }
}

mod runtime {
    use std::collections::{BTreeMap, HashMap, VecDeque};
    use std::fs::{self, DirBuilder, OpenOptions};
    use std::io::Write as _;
    use std::net::SocketAddr;
    #[cfg(unix)]
    use std::os::fd::AsRawFd;
    #[cfg(unix)]
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
    #[cfg(unix)]
    use std::os::unix::net::UnixStream as StdUnixStream;
    use std::path::Path;
    use std::process::Stdio;
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use hyp_proto::cloudevent::{CloudEventError, check_cloudevent_v2};
    use hyp_proto::rpc::{
        DeliveryFailedParams, ERR_ID_CONFLICT, ERR_INTERNAL_ERROR, ERR_INVALID_EVENT,
        ERR_INVALID_PARAMS, ERR_INVALID_REQUEST, ERR_METHOD_NOT_FOUND, ERR_PARSE_ERROR,
        ERR_TOO_LARGE, ERR_UNAVAILABLE, ERR_UNKNOWN_TARGET, FrameError, HelloParams,
        JsonRpcNotification, JsonRpcRequest, JsonRpcResponse, LegacyAckStatus, LegacyNackError,
        LegacyV1Frame, LineSplitter, MAX_FRAME_BYTES, METHOD_DELIVERY_FAILED, METHOD_HELLO,
        METHOD_PUBLISH, METHOD_STATUS, PluginFrame, PublishParams, RpcId, StatusParams,
        decode_frame, encode_frame,
    };
    use ring::hmac;
    use ring::rand::{SecureRandom, SystemRandom};
    use serde::Deserialize;
    use serde_json::{Value, json};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
    #[cfg(unix)]
    use tokio::net::UnixStream as TokioUnixStream;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::process::{Child, Command};
    use tokio::sync::{Mutex, Notify, mpsc};
    use tokio::task::JoinHandle;

    use crate::adapters::trait_def::{
        AdapterError, AdapterHealth, NodeAdapterHost, PublishErrorCode, PublishStatus,
    };

    use super::{
        ActiveConnection, HelloMode, PROTO_JSONRPC_V2, PROTO_LEGACY_V1, PROTO_UNKNOWN, PendingMap,
        PluginTransportMode, SubprocessConfig, SupervisorInner, build_isolated_env_with,
        is_secret_like_env_key,
    };

    const MAX_OUTPUT_LINE_BYTES: usize = 2 * 1024;
    const MAX_AUTH_LINE_BYTES: usize = 4 * 1024;
    const MAX_ECHO_CHARS: usize = 256;
    const OUTBOUND_QUEUE_CAPACITY: usize = 256;
    const MAX_RECENT_STDERR_LINES: usize = 32;
    const MAX_RUN_STDERR_TAIL: usize = 4;
    const MAX_STDERR_SUMMARY_CHARS: usize = 400;

    fn collect_redacted_secrets(
        config: &SubprocessConfig,
        active_env: &BTreeMap<String, String>,
        extra_redacted: &[String],
    ) -> Vec<String> {
        let mut secrets: Vec<String> = Vec::new();
        for val in config.redacted_values.iter().chain(extra_redacted.iter()) {
            let trimmed = val.trim();
            if trimmed.len() >= 4 && !secrets.iter().any(|s| s == trimmed) {
                secrets.push(trimmed.to_string());
            }
        }
        for (k, v) in active_env {
            if is_secret_like_env_key(k) {
                let trimmed = v.trim();
                if trimmed.len() >= 4 && !secrets.iter().any(|s| s == trimmed) {
                    secrets.push(trimmed.to_string());
                }
            }
        }
        secrets.sort_by_key(|s| std::cmp::Reverse(s.len()));
        secrets
    }

    fn sanitize_and_redact(raw: &str, secrets: &[String]) -> String {
        let mut redacted = raw.to_string();
        for secret in secrets {
            if secret.len() >= 4 && redacted.contains(secret.as_str()) {
                redacted = redacted.replace(secret.as_str(), "[REDACTED]");
            }
        }
        let cleaned: String = redacted
            .chars()
            .map(|c| if c.is_control() && c != '\t' { ' ' } else { c })
            .collect();
        cleaned.trim().to_string()
    }

    fn append_stderr_log_line(path: &Path, max_bytes: u64, line: &str) {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                let mut builder = DirBuilder::new();
                builder.recursive(true);
                #[cfg(unix)]
                {
                    builder.mode(0o700);
                }
                if builder.create(parent).is_err() {
                    return;
                }
            }
        }
        // Fail closed against symlink attacks on per-plugin log files.
        if let Ok(meta) = fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                return;
            }
            if max_bytes > 0 && meta.len() >= max_bytes {
                let mut opts = OpenOptions::new();
                opts.write(true).truncate(true);
                #[cfg(unix)]
                {
                    opts.mode(0o600);
                }
                if let Ok(mut f) = opts.open(path) {
                    let _ = f.write_all(b"[log truncated]\n");
                }
            }
        }
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            opts.mode(0o600);
        }
        if let Ok(mut f) = opts.open(path) {
            let _ = writeln!(f, "[{ts_ms}] {line}");
        }
    }

    fn record_stderr_line(
        inner: &SupervisorInner,
        secrets: &[String],
        run_tail: Option<&StdMutex<VecDeque<String>>>,
        raw: &str,
    ) {
        let clean = sanitize_and_redact(raw, secrets);
        if clean.is_empty() {
            return;
        }
        {
            let mut ring = inner.recent_stderr.write().expect("stderr lock");
            ring.push_back(clean.clone());
            while ring.len() > MAX_RECENT_STDERR_LINES {
                ring.pop_front();
            }
        }
        if let Some(tail) = run_tail {
            if let Ok(mut guard) = tail.lock() {
                guard.push_back(clean.clone());
                while guard.len() > MAX_RUN_STDERR_TAIL {
                    guard.pop_front();
                }
            }
        }
        if let Some(ref log_path) = inner.config.stderr_log_path {
            append_stderr_log_line(log_path, inner.config.max_stderr_log_bytes, &clean);
        }
    }

    fn format_stderr_summary(run_tail: &StdMutex<VecDeque<String>>) -> String {
        let joined = match run_tail.lock() {
            Ok(guard) => {
                let len = guard.len();
                let start = len.saturating_sub(2);
                guard
                    .iter()
                    .skip(start)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" | ")
            }
            Err(_) => String::new(),
        };
        if joined.chars().count() <= MAX_STDERR_SUMMARY_CHARS {
            joined
        } else {
            let truncated: String = joined.chars().take(MAX_STDERR_SUMMARY_CHARS).collect();
            format!("{truncated}...")
        }
    }

    #[cfg(unix)]
    const F_SETFD: i32 = 2;
    #[cfg(unix)]
    const SIGTERM: i32 = 15;

    #[cfg(unix)]
    unsafe extern "C" {
        fn dup2(oldfd: i32, newfd: i32) -> i32;
        fn fcntl(fd: i32, cmd: i32, ...) -> i32;
        fn kill(pid: i32, sig: i32) -> i32;
    }

    fn generate_handshake_token() -> std::io::Result<String> {
        let rng = SystemRandom::new();
        let mut bytes = [0u8; 32];
        rng.fill(&mut bytes).map_err(|_| {
            std::io::Error::other("CSPRNG failed generating plugin handshake token")
        })?;
        Ok(hex::encode(bytes))
    }

    /// Length-hiding constant-time token comparison via HMAC-SHA256 over a fresh CSPRNG key.
    fn constant_time_token_eq(expected: &str, actual: &str) -> bool {
        let rng = SystemRandom::new();
        let mut rand_key = [0u8; 32];
        if rng.fill(&mut rand_key).is_err() {
            return false;
        }
        let key = hmac::Key::new(hmac::HMAC_SHA256, &rand_key);
        let tag = hmac::sign(&key, expected.as_bytes());
        hmac::verify(&key, actual.as_bytes(), tag.as_ref()).is_ok()
    }

    #[derive(Deserialize)]
    struct TcpAuthFrame {
        #[serde(rename = "type")]
        frame_type: String,
        token: String,
    }

    enum TcpHandshakeError {
        Stopped,
        ChildExited(String),
        AuthFailed(String),
    }

    #[cfg(unix)]
    fn spawn_with_fd3(
        config: &SubprocessConfig,
        plugin_env: &BTreeMap<String, String>,
    ) -> std::io::Result<(Child, TokioUnixStream)> {
        let (parent_sock, child_sock) = StdUnixStream::pair()?;
        parent_sock.set_nonblocking(true)?;
        child_sock.set_nonblocking(false)?;

        let parent_env = config
            .parent_env_override
            .clone()
            .unwrap_or_else(|| std::env::vars().collect());
        let env = build_isolated_env_with(config, &parent_env, plugin_env);

        let mut cmd = Command::new(&config.exec);
        cmd.args(&config.args)
            .env_clear()
            .envs(&env)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        if let Some(cwd) = &config.cwd {
            cmd.current_dir(cwd);
        }

        let child_raw_fd = child_sock.as_raw_fd();
        // SAFETY: `pre_exec` runs between `fork()` and `exec()` and calls only async-signal-safe
        // POSIX `dup2` and `fcntl` to install the socketpair child end onto fd 3 with CLOEXEC cleared.
        unsafe {
            cmd.pre_exec(move || {
                if child_raw_fd != 3 && dup2(child_raw_fd, 3) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if fcntl(3, F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }

        let child = cmd.spawn()?;
        // Drop the parent's copy of the child socket end immediately so EOF propagates on child exit.
        drop(child_sock);

        let tokio_stream = TokioUnixStream::from_std(parent_sock)?;
        Ok((child, tokio_stream))
    }

    fn spawn_with_loopback_tcp(
        config: &SubprocessConfig,
        plugin_env: &BTreeMap<String, String>,
        bind_addr: SocketAddr,
        handshake_token: &str,
    ) -> std::io::Result<Child> {
        let parent_env = config
            .parent_env_override
            .clone()
            .unwrap_or_else(|| std::env::vars().collect());
        let mut env = build_isolated_env_with(config, &parent_env, plugin_env);
        env.insert("HYPHAE_PLUGIN_ADDR".to_string(), bind_addr.to_string());
        env.insert(
            "HYPHAE_PLUGIN_TOKEN".to_string(),
            handshake_token.to_string(),
        );
        env.insert("HYPHAE_PLUGIN_TRANSPORT".to_string(), "tcp".to_string());

        let mut cmd = Command::new(&config.exec);
        cmd.args(&config.args)
            .env_clear()
            .envs(&env)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        if let Some(cwd) = &config.cwd {
            cmd.current_dir(cwd);
        }

        cmd.spawn()
    }

    async fn accept_and_authenticate_tcp(
        listener: TcpListener,
        expected_token: &str,
        child: &mut Child,
        inner: &SupervisorInner,
        timeout_dur: Duration,
    ) -> Result<(TcpStream, Vec<u8>), TcpHandshakeError> {
        let deadline = tokio::time::Instant::now() + timeout_dur;
        if inner.stopping.load(Ordering::Acquire) != 0 {
            return Err(TcpHandshakeError::Stopped);
        }

        let (mut stream, peer_addr) = tokio::select! {
            () = inner.stop_notify.notified() => {
                return Err(TcpHandshakeError::Stopped);
            }
            () = tokio::time::sleep_until(deadline) => {
                return Err(TcpHandshakeError::AuthFailed(format!(
                    "TCP plugin auth failed: child did not connect within {timeout_dur:?}"
                )));
            }
            wait_res = child.wait() => {
                let desc = match wait_res {
                    Ok(status) => format!("exited ({status})"),
                    Err(e) => format!("wait error: {e}"),
                };
                return Err(TcpHandshakeError::ChildExited(desc));
            }
            accept_res = listener.accept() => {
                match accept_res {
                    Ok(pair) => pair,
                    Err(e) => {
                        return Err(TcpHandshakeError::AuthFailed(format!(
                            "TCP plugin auth failed: accept error: {e}"
                        )));
                    }
                }
            }
        };

        // Immediately drop listener so no second process can ever connect.
        drop(listener);

        if !peer_addr.ip().is_loopback() {
            return Err(TcpHandshakeError::AuthFailed(format!(
                "TCP plugin auth failed: rejected non-loopback peer {}",
                peer_addr.ip()
            )));
        }
        let _ = stream.set_nodelay(true);

        let mut buf: Vec<u8> = Vec::with_capacity(256);
        let mut chunk = [0u8; MAX_AUTH_LINE_BYTES];
        let (line_bytes, leftover) = loop {
            if inner.stopping.load(Ordering::Acquire) != 0 {
                return Err(TcpHandshakeError::Stopped);
            }
            let n = tokio::select! {
                () = inner.stop_notify.notified() => {
                    return Err(TcpHandshakeError::Stopped);
                }
                () = tokio::time::sleep_until(deadline) => {
                    return Err(TcpHandshakeError::AuthFailed(format!(
                        "TCP plugin auth failed: auth frame timed out after {timeout_dur:?}"
                    )));
                }
                read_res = stream.read(&mut chunk) => {
                    match read_res {
                        Ok(0) => {
                            return Err(TcpHandshakeError::AuthFailed(
                                "TCP plugin auth failed: connection closed before auth frame"
                                    .to_string(),
                            ));
                        }
                        Ok(n) => n,
                        Err(e) => {
                            return Err(TcpHandshakeError::AuthFailed(format!(
                                "TCP plugin auth failed: I/O error reading auth frame: {e}"
                            )));
                        }
                    }
                }
            };
            buf.extend_from_slice(&chunk[..n]);
            if let Some(nl_pos) = buf.iter().position(|&b| b == b'\n') {
                if nl_pos >= MAX_AUTH_LINE_BYTES {
                    return Err(TcpHandshakeError::AuthFailed(format!(
                        "TCP plugin auth failed: auth frame exceeded {MAX_AUTH_LINE_BYTES} byte limit"
                    )));
                }
                let mut line = &buf[..nl_pos];
                if let Some(stripped) = line.strip_suffix(b"\r") {
                    line = stripped;
                }
                let line_owned = line.to_vec();
                let rest = buf[nl_pos + 1..].to_vec();
                break (line_owned, rest);
            }
            if buf.len() >= MAX_AUTH_LINE_BYTES {
                return Err(TcpHandshakeError::AuthFailed(format!(
                    "TCP plugin auth failed: auth frame exceeded {MAX_AUTH_LINE_BYTES} byte limit"
                )));
            }
        };

        let line_str = std::str::from_utf8(&line_bytes).map_err(|_| {
            TcpHandshakeError::AuthFailed(
                "TCP plugin auth failed: auth frame is not valid UTF-8".to_string(),
            )
        })?;
        let frame: TcpAuthFrame = serde_json::from_str(line_str).map_err(|_| {
            TcpHandshakeError::AuthFailed(
                "TCP plugin auth failed: expected {\"type\":\"auth\",\"token\":\"...\"}"
                    .to_string(),
            )
        })?;
        if frame.frame_type != "auth" {
            return Err(TcpHandshakeError::AuthFailed(
                "TCP plugin auth failed: first frame must have type=\"auth\"".to_string(),
            ));
        }
        if !constant_time_token_eq(expected_token, &frame.token) {
            return Err(TcpHandshakeError::AuthFailed(
                "TCP plugin auth failed: invalid handshake token".to_string(),
            ));
        }

        Ok((stream, leftover))
    }

    async fn terminate_child(child: &mut Child, kill_timeout: Duration) {
        #[cfg(unix)]
        {
            if let Some(pid) = child.id() {
                if let Ok(pid_i32) = i32::try_from(pid) {
                    if pid_i32 > 0 {
                        // SAFETY: Sending SIGTERM to a live child PID owned by this supervisor.
                        unsafe {
                            let _ = kill(pid_i32, SIGTERM);
                        }
                    }
                }
            }
            match tokio::time::timeout(kill_timeout, child.wait()).await {
                Ok(_) => {}
                Err(_) => {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                }
            }
        }

        #[cfg(not(unix))]
        {
            // On Windows, closing the TCP socket already signals EOF to well-behaved plugins;
            // allow a brief bounded grace window before TerminateProcess via `child.kill()`.
            let grace = kill_timeout.min(Duration::from_millis(500));
            match tokio::time::timeout(grace, child.wait()).await {
                Ok(_) => {}
                Err(_) => {
                    let _ = child.kill().await;
                    let _ = child.wait().await;
                }
            }
        }
    }

    async fn drain_output_tasks(
        stdout_task: Option<JoinHandle<()>>,
        stderr_task: Option<JoinHandle<()>>,
    ) {
        if let Some(t) = stdout_task {
            if tokio::time::timeout(Duration::from_secs(2), t)
                .await
                .is_err()
            {
                // Best-effort bounded drain; avoid hanging if a grandchild holds stdout open.
            }
        }
        if let Some(t) = stderr_task {
            if tokio::time::timeout(Duration::from_secs(2), t)
                .await
                .is_err()
            {
                // Best-effort bounded drain; avoid hanging if a grandchild holds stderr open.
            }
        }
    }

    async fn run_channel_io<R, W>(
        inner: &Arc<SupervisorInner>,
        host: &Arc<dyn NodeAdapterHost>,
        mut read_half: R,
        mut write_half: W,
        initial_bytes: Vec<u8>,
        first_ready: &mut Option<Arc<Notify>>,
    ) -> bool
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let (out_tx, mut out_rx) = mpsc::channel::<String>(OUTBOUND_QUEUE_CAPACITY);

        let initial_proto = match inner.config.hello_mode {
            HelloMode::LegacyV1 => PROTO_LEGACY_V1,
            HelloMode::JsonRpcV2 => PROTO_JSONRPC_V2,
            HelloMode::Auto => PROTO_UNKNOWN,
        };
        let detected_protocol = Arc::new(AtomicU8::new(initial_proto));
        if initial_proto != PROTO_UNKNOWN {
            inner
                .last_detected_protocol
                .store(initial_proto, Ordering::Release);
        }

        let pending_requests: Arc<Mutex<PendingMap>> = Arc::new(Mutex::new(HashMap::new()));
        {
            let mut active_guard = inner.active.lock().await;
            *active_guard = Some(ActiveConnection {
                tx: out_tx.clone(),
                detected_protocol: Arc::clone(&detected_protocol),
                pending_requests: Arc::clone(&pending_requests),
            });
        }

        *inner.health.write().expect("health lock") = AdapterHealth::Healthy;
        host.update_status(&inner.config.id, AdapterHealth::Healthy)
            .await;

        let writer_task = tokio::spawn(async move {
            while let Some(line) = out_rx.recv().await {
                if write_half.write_all(line.as_bytes()).await.is_err() {
                    break;
                }
                if write_half.flush().await.is_err() {
                    break;
                }
            }
        });

        let hello_cancel = Arc::new(Notify::new());
        let hello_task = match inner.config.hello_mode {
            HelloMode::LegacyV1 => {
                let hello_frame = PluginFrame::LegacyV1(LegacyV1Frame::Hello {
                    protocol: 1,
                    plugin: inner.config.id.clone(),
                    targets: inner.config.targets.clone(),
                });
                if let Ok(wire) = encode_frame(&hello_frame) {
                    let _ = out_tx.send(wire).await;
                }
                None
            }
            HelloMode::JsonRpcV2 => {
                let params = serde_json::to_value(HelloParams {
                    protocol: 2,
                    plugin: inner.config.id.clone(),
                    targets: inner.config.targets.clone(),
                })
                .ok();
                let hello_frame = PluginFrame::JsonRpcNotification(JsonRpcNotification::new(
                    METHOD_HELLO,
                    params,
                ));
                if let Ok(wire) = encode_frame(&hello_frame) {
                    let _ = out_tx.send(wire).await;
                }
                None
            }
            HelloMode::Auto => {
                let grace = inner.config.auto_hello_grace;
                let tx_clone = out_tx.clone();
                let proto_clone = Arc::clone(&detected_protocol);
                let last_proto_inner = Arc::clone(inner);
                let cancel_clone = Arc::clone(&hello_cancel);
                let plugin_id = inner.config.id.clone();
                let targets = inner.config.targets.clone();
                Some(tokio::spawn(async move {
                    tokio::select! {
                        () = cancel_clone.notified() => {}
                        () = tokio::time::sleep(grace) => {
                            if proto_clone
                                .compare_exchange(
                                    PROTO_UNKNOWN,
                                    PROTO_LEGACY_V1,
                                    Ordering::AcqRel,
                                    Ordering::Acquire,
                                )
                                .is_ok()
                            {
                                last_proto_inner
                                    .last_detected_protocol
                                    .store(PROTO_LEGACY_V1, Ordering::Release);
                                let hello_frame = PluginFrame::LegacyV1(LegacyV1Frame::Hello {
                                    protocol: 1,
                                    plugin: plugin_id,
                                    targets,
                                });
                                if let Ok(wire) = encode_frame(&hello_frame) {
                                    let _ = tx_clone.send(wire).await;
                                }
                            }
                        }
                    }
                }))
            }
        };

        if let Some(n) = first_ready.take() {
            n.notify_waiters();
        }

        let mut splitter = LineSplitter::new(MAX_FRAME_BYTES, false);
        if !initial_bytes.is_empty() {
            let mut completed: Vec<(String, bool)> = Vec::new();
            splitter.push(&initial_bytes, |line, truncated| {
                completed.push((line, truncated));
            });
            for (line, truncated) in completed {
                hello_cancel.notify_waiters();
                handle_incoming_line(
                    inner,
                    host,
                    &out_tx,
                    &detected_protocol,
                    &pending_requests,
                    line,
                    truncated,
                )
                .await;
            }
        }

        let mut buf = [0u8; 4096];
        let mut channel_closed = false;

        loop {
            if inner.stopping.load(Ordering::Acquire) != 0 {
                break;
            }
            tokio::select! {
                () = inner.stop_notify.notified() => {
                    break;
                }
                read_res = read_half.read(&mut buf) => {
                    match read_res {
                        Ok(0) => {
                            channel_closed = true;
                            break;
                        }
                        Ok(n) => {
                            let mut completed: Vec<(String, bool)> = Vec::new();
                            splitter.push(&buf[..n], |line, truncated| {
                                completed.push((line, truncated));
                            });
                            for (line, truncated) in completed {
                                hello_cancel.notify_waiters();
                                handle_incoming_line(
                                    inner,
                                    host,
                                    &out_tx,
                                    &detected_protocol,
                                    &pending_requests,
                                    line,
                                    truncated,
                                )
                                .await;
                            }
                        }
                        Err(_) => {
                            channel_closed = true;
                            break;
                        }
                    }
                }
            }
        }

        if let Some(ht) = hello_task {
            ht.abort();
        }

        {
            *inner.active.lock().await = None;
            let mut map = pending_requests.lock().await;
            for (_, sender) in map.drain() {
                let _ = sender.send(Err(AdapterError::NotRunning(format!(
                    "subprocess '{}' disconnected",
                    inner.config.id
                ))));
            }
        }
        drop(out_tx);
        let _ = writer_task.await;
        drop(read_half);

        channel_closed
    }

    #[allow(clippy::too_many_arguments)]
    async fn handle_rapid_failure_and_backoff(
        inner: &SupervisorInner,
        host: &Arc<dyn NodeAdapterHost>,
        redacted_secrets: &[String],
        first_ready: &mut Option<Arc<Notify>>,
        backoff: &mut Duration,
        consecutive_rapid_crashes: &mut u32,
        crash_loop_msg: String,
        degraded_msg: String,
    ) -> bool {
        if inner.config.max_rapid_crashes > 0
            && *consecutive_rapid_crashes >= inner.config.max_rapid_crashes
        {
            inner.crash_loop_backoff.store(true, Ordering::Release);
            record_stderr_line(inner, redacted_secrets, None, &crash_loop_msg);
            *inner.last_error.write().expect("last_error lock") = Some(crash_loop_msg.clone());
            *inner.health.write().expect("health lock") =
                AdapterHealth::Degraded(crash_loop_msg.clone());
            host.update_status(&inner.config.id, AdapterHealth::Degraded(crash_loop_msg))
                .await;
            if let Some(n) = first_ready.take() {
                n.notify_waiters();
            }
            return false;
        }

        *inner.last_error.write().expect("last_error lock") = Some(degraded_msg.clone());
        *inner.health.write().expect("health lock") = AdapterHealth::Degraded(degraded_msg.clone());
        host.update_status(&inner.config.id, AdapterHealth::Degraded(degraded_msg))
            .await;
        if let Some(n) = first_ready.take() {
            n.notify_waiters();
        }
        if !sleep_or_stop(inner, *backoff).await {
            *inner.health.write().expect("health lock") = AdapterHealth::Stopped;
            host.update_status(&inner.config.id, AdapterHealth::Stopped)
                .await;
            return false;
        }
        *backoff = (*backoff * 2).min(inner.config.max_backoff);
        inner.restart_count.fetch_add(1, Ordering::Relaxed);
        true
    }

    pub(super) async fn supervise_loop(
        inner: Arc<SupervisorInner>,
        host: Arc<dyn NodeAdapterHost>,
        mut first_ready: Option<Arc<Notify>>,
    ) {
        let mut backoff = inner.config.initial_backoff;
        let mut consecutive_rapid_crashes: u32 = 0;

        while inner.stopping.load(Ordering::Acquire) == 0 {
            let started_at = Instant::now();
            let mut spawn_env = inner.config.env.clone();
            let mut extra_redacted: Vec<String> = Vec::new();
            let mut resolve_error: Option<String> = None;

            if let Some(ref resolver) = inner.config.env_resolver {
                match resolver() {
                    Ok(resolved) => {
                        for (k, v) in resolved {
                            extra_redacted.push(v.clone());
                            spawn_env.insert(k, v);
                        }
                    }
                    Err(e) => {
                        resolve_error = Some(e);
                    }
                }
            }

            let tcp_setup = if resolve_error.is_none()
                && inner.config.transport_mode == PluginTransportMode::LoopbackTcp
            {
                match TcpListener::bind("127.0.0.1:0").await {
                    Ok(listener) => match (listener.local_addr(), generate_handshake_token()) {
                        (Ok(addr), Ok(token)) => {
                            extra_redacted.push(token.clone());
                            Ok(Some((listener, addr, token)))
                        }
                        (Err(e), _) | (_, Err(e)) => Err(e),
                    },
                    Err(e) => Err(e),
                }
            } else {
                Ok(None)
            };

            let redacted_secrets = Arc::new(collect_redacted_secrets(
                &inner.config,
                &spawn_env,
                &extra_redacted,
            ));

            enum SpawnedTransport {
                #[cfg(unix)]
                UnixFd3(Child, TokioUnixStream),
                LoopbackTcp(Child, TcpListener, String),
            }

            let spawned: std::io::Result<SpawnedTransport> = match resolve_error {
                Some(err) => Err(std::io::Error::other(format!(
                    "secret env resolution failed: {err}"
                ))),
                None => match tcp_setup {
                    Err(err) => Err(err),
                    Ok(Some((listener, addr, token))) => {
                        spawn_with_loopback_tcp(&inner.config, &spawn_env, addr, &token)
                            .map(|child| SpawnedTransport::LoopbackTcp(child, listener, token))
                    }
                    Ok(None) => {
                        #[cfg(unix)]
                        {
                            spawn_with_fd3(&inner.config, &spawn_env)
                                .map(|(child, stream)| SpawnedTransport::UnixFd3(child, stream))
                        }
                        #[cfg(not(unix))]
                        {
                            unreachable!("LoopbackTcp is the only transport on non-Unix platforms")
                        }
                    }
                },
            };

            let spawned_transport = match spawned {
                Ok(t) => t,
                Err(err) => {
                    consecutive_rapid_crashes = consecutive_rapid_crashes.saturating_add(1);
                    let err_msg =
                        sanitize_and_redact(&format!("spawn failed: {err}"), &redacted_secrets);
                    record_stderr_line(&inner, &redacted_secrets, None, &err_msg);
                    let crash_msg = format!(
                        "CrashLoopBackOff: failed to spawn {consecutive_rapid_crashes} consecutive times ({err_msg})"
                    );
                    if !handle_rapid_failure_and_backoff(
                        &inner,
                        &host,
                        &redacted_secrets,
                        &mut first_ready,
                        &mut backoff,
                        &mut consecutive_rapid_crashes,
                        crash_msg,
                        err_msg,
                    )
                    .await
                    {
                        break;
                    }
                    continue;
                }
            };

            let run_stderr_tail = Arc::new(StdMutex::new(VecDeque::new()));

            #[allow(clippy::match_single_binding, clippy::infallible_destructuring_match)]
            let (mut child, stdout_task, stderr_task, channel_closed) = match spawned_transport {
                #[cfg(unix)]
                SpawnedTransport::UnixFd3(mut child, unix_stream) => {
                    let stdout_task = child.stdout.take().map(drain_output_stream);
                    let stderr_task = child.stderr.take().map(|stderr| {
                        drain_stderr_stream(
                            stderr,
                            Arc::clone(&inner),
                            Arc::clone(&redacted_secrets),
                            Arc::clone(&run_stderr_tail),
                        )
                    });
                    let (read_half, write_half) = unix_stream.into_split();
                    let closed = run_channel_io(
                        &inner,
                        &host,
                        read_half,
                        write_half,
                        Vec::new(),
                        &mut first_ready,
                    )
                    .await;
                    (child, stdout_task, stderr_task, closed)
                }
                SpawnedTransport::LoopbackTcp(mut child, listener, expected_token) => {
                    let stdout_task = child.stdout.take().map(drain_output_stream);
                    let stderr_task = child.stderr.take().map(|stderr| {
                        drain_stderr_stream(
                            stderr,
                            Arc::clone(&inner),
                            Arc::clone(&redacted_secrets),
                            Arc::clone(&run_stderr_tail),
                        )
                    });

                    match accept_and_authenticate_tcp(
                        listener,
                        &expected_token,
                        &mut child,
                        &inner,
                        inner.config.startup_timeout,
                    )
                    .await
                    {
                        Ok((tcp_stream, leftover)) => {
                            let (read_half, write_half) = tcp_stream.into_split();
                            let closed = run_channel_io(
                                &inner,
                                &host,
                                read_half,
                                write_half,
                                leftover,
                                &mut first_ready,
                            )
                            .await;
                            (child, stdout_task, stderr_task, closed)
                        }
                        Err(TcpHandshakeError::Stopped) => {
                            terminate_child(&mut child, inner.config.kill_timeout).await;
                            drain_output_tasks(stdout_task, stderr_task).await;
                            *inner.health.write().expect("health lock") = AdapterHealth::Stopped;
                            host.update_status(&inner.config.id, AdapterHealth::Stopped)
                                .await;
                            if let Some(n) = first_ready.take() {
                                n.notify_waiters();
                            }
                            break;
                        }
                        Err(TcpHandshakeError::ChildExited(exit_desc)) => {
                            drain_output_tasks(stdout_task, stderr_task).await;
                            if inner.stopping.load(Ordering::Acquire) != 0 {
                                *inner.health.write().expect("health lock") =
                                    AdapterHealth::Stopped;
                                host.update_status(&inner.config.id, AdapterHealth::Stopped)
                                    .await;
                                if let Some(n) = first_ready.take() {
                                    n.notify_waiters();
                                }
                                break;
                            }
                            consecutive_rapid_crashes = consecutive_rapid_crashes.saturating_add(1);
                            let stderr_summary = format_stderr_summary(&run_stderr_tail);
                            let crash_msg = if stderr_summary.is_empty() {
                                format!(
                                    "CrashLoopBackOff: subprocess {exit_desc} rapidly {consecutive_rapid_crashes} consecutive times"
                                )
                            } else {
                                format!(
                                    "CrashLoopBackOff: subprocess {exit_desc} rapidly {consecutive_rapid_crashes} consecutive times: {stderr_summary}"
                                )
                            };
                            let degraded_msg = if stderr_summary.is_empty() {
                                format!("subprocess {exit_desc} unexpectedly")
                            } else {
                                format!("subprocess {exit_desc} unexpectedly: {stderr_summary}")
                            };
                            if !handle_rapid_failure_and_backoff(
                                &inner,
                                &host,
                                &redacted_secrets,
                                &mut first_ready,
                                &mut backoff,
                                &mut consecutive_rapid_crashes,
                                crash_msg,
                                degraded_msg,
                            )
                            .await
                            {
                                break;
                            }
                            continue;
                        }
                        Err(TcpHandshakeError::AuthFailed(raw_err)) => {
                            terminate_child(
                                &mut child,
                                inner.config.kill_timeout.min(Duration::from_millis(500)),
                            )
                            .await;
                            drain_output_tasks(stdout_task, stderr_task).await;
                            if inner.stopping.load(Ordering::Acquire) != 0 {
                                *inner.health.write().expect("health lock") =
                                    AdapterHealth::Stopped;
                                host.update_status(&inner.config.id, AdapterHealth::Stopped)
                                    .await;
                                if let Some(n) = first_ready.take() {
                                    n.notify_waiters();
                                }
                                break;
                            }
                            consecutive_rapid_crashes = consecutive_rapid_crashes.saturating_add(1);
                            let safe_err = sanitize_and_redact(&raw_err, &redacted_secrets);
                            record_stderr_line(&inner, &redacted_secrets, None, &safe_err);
                            let stderr_summary = format_stderr_summary(&run_stderr_tail);
                            let full_err = if stderr_summary.is_empty() {
                                safe_err
                            } else {
                                format!("{safe_err}: {stderr_summary}")
                            };
                            let crash_msg = format!(
                                "CrashLoopBackOff: TCP handshake failed {consecutive_rapid_crashes} consecutive times ({full_err})"
                            );
                            if !handle_rapid_failure_and_backoff(
                                &inner,
                                &host,
                                &redacted_secrets,
                                &mut first_ready,
                                &mut backoff,
                                &mut consecutive_rapid_crashes,
                                crash_msg,
                                full_err,
                            )
                            .await
                            {
                                break;
                            }
                            continue;
                        }
                    }
                }
            };

            let stopping_now = inner.stopping.load(Ordering::Acquire) != 0;
            let exit_desc = if stopping_now {
                terminate_child(&mut child, inner.config.kill_timeout).await;
                "stopped".to_string()
            } else if channel_closed {
                match tokio::time::timeout(Duration::from_millis(250), child.wait()).await {
                    Ok(Ok(status)) => format!("exited ({status})"),
                    _ => {
                        terminate_child(&mut child, inner.config.kill_timeout).await;
                        "channel closed".to_string()
                    }
                }
            } else {
                match child.wait().await {
                    Ok(status) => format!("exited ({status})"),
                    Err(e) => format!("wait error: {e}"),
                }
            };

            drain_output_tasks(stdout_task, stderr_task).await;

            if inner.stopping.load(Ordering::Acquire) != 0 {
                *inner.health.write().expect("health lock") = AdapterHealth::Stopped;
                host.update_status(&inner.config.id, AdapterHealth::Stopped)
                    .await;
                break;
            }

            let uptime = started_at.elapsed();
            if uptime >= inner.config.reset_after {
                backoff = inner.config.initial_backoff;
            }
            if uptime < inner.config.rapid_crash_window {
                consecutive_rapid_crashes = consecutive_rapid_crashes.saturating_add(1);
            } else {
                consecutive_rapid_crashes = 0;
            }

            let stderr_summary = format_stderr_summary(&run_stderr_tail);
            let crash_msg = if stderr_summary.is_empty() {
                format!(
                    "CrashLoopBackOff: subprocess {exit_desc} rapidly {consecutive_rapid_crashes} consecutive times"
                )
            } else {
                format!(
                    "CrashLoopBackOff: subprocess {exit_desc} rapidly {consecutive_rapid_crashes} consecutive times: {stderr_summary}"
                )
            };
            let degraded_msg = if stderr_summary.is_empty() {
                format!("subprocess {exit_desc} unexpectedly")
            } else {
                format!("subprocess {exit_desc} unexpectedly: {stderr_summary}")
            };
            if !handle_rapid_failure_and_backoff(
                &inner,
                &host,
                &redacted_secrets,
                &mut first_ready,
                &mut backoff,
                &mut consecutive_rapid_crashes,
                crash_msg,
                degraded_msg,
            )
            .await
            {
                break;
            }
        }
    }

    async fn sleep_or_stop(inner: &SupervisorInner, delay: Duration) -> bool {
        if inner.stopping.load(Ordering::Acquire) != 0 {
            return false;
        }
        tokio::select! {
            () = inner.stop_notify.notified() => false,
            () = tokio::time::sleep(delay) => inner.stopping.load(Ordering::Acquire) == 0,
        }
    }

    fn drain_output_stream<R: AsyncRead + Unpin + Send + 'static>(mut reader: R) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut splitter = LineSplitter::new(MAX_OUTPUT_LINE_BYTES, true);
            let mut buf = [0u8; 2048];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        splitter.push(&buf[..n], |_line, _truncated| {});
                    }
                }
            }
            splitter.flush(|_line, _truncated| {});
        })
    }

    fn drain_stderr_stream<R: AsyncRead + Unpin + Send + 'static>(
        mut reader: R,
        inner: Arc<SupervisorInner>,
        secrets: Arc<Vec<String>>,
        run_tail: Arc<StdMutex<VecDeque<String>>>,
    ) -> JoinHandle<()> {
        tokio::spawn(async move {
            let mut splitter = LineSplitter::new(MAX_OUTPUT_LINE_BYTES, true);
            let mut buf = [0u8; 2048];
            loop {
                match reader.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        splitter.push(&buf[..n], |line, _truncated| {
                            record_stderr_line(&inner, &secrets, Some(&run_tail), &line);
                        });
                    }
                }
            }
            splitter.flush(|line, _truncated| {
                record_stderr_line(&inner, &secrets, Some(&run_tail), &line);
            });
        })
    }

    async fn send_frame(out_tx: &mpsc::Sender<String>, frame: &PluginFrame) {
        if let Ok(wire) = encode_frame(frame) {
            let _ = out_tx.send(wire).await;
        }
    }

    fn truncate_echo(value: Option<&Value>) -> Option<String> {
        value
            .and_then(Value::as_str)
            .map(|s| s.chars().take(MAX_ECHO_CHARS).collect())
    }

    fn map_publish_error(err: &AdapterError) -> (LegacyNackError, i32, String) {
        match err {
            AdapterError::PublishFailed { code, message } => match code {
                PublishErrorCode::InvalidEvent => (
                    LegacyNackError::InvalidEvent,
                    ERR_INVALID_EVENT,
                    message.clone(),
                ),
                PublishErrorCode::TooLarge => {
                    (LegacyNackError::TooLarge, ERR_TOO_LARGE, message.clone())
                }
                PublishErrorCode::UnknownTarget => (
                    LegacyNackError::UnknownTarget,
                    ERR_UNKNOWN_TARGET,
                    message.clone(),
                ),
                PublishErrorCode::IdConflict => (
                    LegacyNackError::IdConflict,
                    ERR_ID_CONFLICT,
                    message.clone(),
                ),
                PublishErrorCode::Unavailable => (
                    LegacyNackError::Unavailable,
                    ERR_UNAVAILABLE,
                    message.clone(),
                ),
            },
            other => (
                LegacyNackError::Unavailable,
                ERR_INTERNAL_ERROR,
                other.to_string(),
            ),
        }
    }

    fn map_cloudevent_error(err: &CloudEventError) -> (LegacyNackError, i32, String) {
        match err {
            CloudEventError::InvalidEvent(msg) => (
                LegacyNackError::InvalidEvent,
                ERR_INVALID_EVENT,
                msg.clone(),
            ),
            CloudEventError::TooLarge(msg) => {
                (LegacyNackError::TooLarge, ERR_TOO_LARGE, msg.clone())
            }
        }
    }

    async fn handle_incoming_line(
        inner: &SupervisorInner,
        host: &Arc<dyn NodeAdapterHost>,
        out_tx: &mpsc::Sender<String>,
        detected_protocol: &Arc<AtomicU8>,
        pending_requests: &Arc<Mutex<PendingMap>>,
        line: String,
        truncated: bool,
    ) {
        if truncated {
            inner
                .oversized_frames_rejected
                .fetch_add(1, Ordering::Relaxed);
            let proto = detected_protocol.load(Ordering::Acquire);
            let msg = format!("frame exceeds {MAX_FRAME_BYTES} byte limit");
            if proto == PROTO_JSONRPC_V2 {
                send_frame(
                    out_tx,
                    &PluginFrame::JsonRpcResponse(JsonRpcResponse::err(
                        None,
                        ERR_TOO_LARGE,
                        msg,
                        Some(json!({ "limit": MAX_FRAME_BYTES })),
                    )),
                )
                .await;
            } else {
                send_frame(
                    out_tx,
                    &PluginFrame::LegacyV1(LegacyV1Frame::Nack {
                        id: None,
                        source: None,
                        error: LegacyNackError::TooLarge,
                        message: msg,
                    }),
                )
                .await;
            }
            return;
        }

        if line.trim().is_empty() {
            return;
        }

        let decoded = match decode_frame(&line) {
            Ok(frame) => frame,
            Err(err) => {
                let proto = detected_protocol.load(Ordering::Acquire);
                if proto == PROTO_JSONRPC_V2 {
                    let code = match err {
                        FrameError::FrameTooLarge { .. } => ERR_TOO_LARGE,
                        FrameError::InvalidJson(_) => ERR_PARSE_ERROR,
                        _ => ERR_INVALID_REQUEST,
                    };
                    send_frame(
                        out_tx,
                        &PluginFrame::JsonRpcResponse(JsonRpcResponse::err(
                            None,
                            code,
                            err.to_string(),
                            None,
                        )),
                    )
                    .await;
                } else {
                    let nack_err = match err {
                        FrameError::FrameTooLarge { .. } => LegacyNackError::TooLarge,
                        FrameError::UnsupportedLegacyType(_) => LegacyNackError::UnsupportedType,
                        _ => LegacyNackError::InvalidEvent,
                    };
                    send_frame(
                        out_tx,
                        &PluginFrame::LegacyV1(LegacyV1Frame::Nack {
                            id: None,
                            source: None,
                            error: nack_err,
                            message: err.to_string(),
                        }),
                    )
                    .await;
                }
                return;
            }
        };

        let frame_proto = if decoded.is_legacy_v1() {
            PROTO_LEGACY_V1
        } else {
            PROTO_JSONRPC_V2
        };
        detected_protocol.store(frame_proto, Ordering::Release);
        inner
            .last_detected_protocol
            .store(frame_proto, Ordering::Release);

        match decoded {
            PluginFrame::LegacyV1(legacy) => {
                handle_legacy_v1_frame(inner, host, out_tx, pending_requests, legacy).await;
            }
            PluginFrame::JsonRpcRequest(req) => {
                handle_jsonrpc_request(inner, host, out_tx, req).await;
            }
            PluginFrame::JsonRpcNotification(notif) => {
                handle_jsonrpc_notification(inner, host, notif).await;
            }
            PluginFrame::JsonRpcResponse(resp) => {
                handle_jsonrpc_response(pending_requests, resp).await;
            }
        }
    }

    async fn handle_legacy_v1_frame(
        inner: &SupervisorInner,
        host: &Arc<dyn NodeAdapterHost>,
        out_tx: &mpsc::Sender<String>,
        pending_requests: &Arc<Mutex<PendingMap>>,
        frame: LegacyV1Frame,
    ) {
        match frame {
            LegacyV1Frame::Hello { .. } => {
                send_frame(
                    out_tx,
                    &PluginFrame::LegacyV1(LegacyV1Frame::Hello {
                        protocol: 1,
                        plugin: inner.config.id.clone(),
                        targets: inner.config.targets.clone(),
                    }),
                )
                .await;
            }
            LegacyV1Frame::Event { to, event } => {
                let echo_id = truncate_echo(event.get("id"));
                let echo_source = truncate_echo(event.get("source"));

                if !inner.config.targets.is_empty() && !inner.config.targets.contains(&to) {
                    send_frame(
                        out_tx,
                        &PluginFrame::LegacyV1(LegacyV1Frame::Nack {
                            id: echo_id,
                            source: echo_source,
                            error: LegacyNackError::UnknownTarget,
                            message: format!("unknown target '{to}'"),
                        }),
                    )
                    .await;
                    return;
                }

                let parsed = match check_cloudevent_v2(&event) {
                    Ok((ev, _)) => ev,
                    Err(err) => {
                        let (nack_err, _, msg) = map_cloudevent_error(&err);
                        send_frame(
                            out_tx,
                            &PluginFrame::LegacyV1(LegacyV1Frame::Nack {
                                id: echo_id,
                                source: echo_source,
                                error: nack_err,
                                message: msg,
                            }),
                        )
                        .await;
                        return;
                    }
                };

                let ev_id = parsed.id.clone();
                let ev_source = parsed.source.clone();
                match host.publish_event(&to, parsed).await {
                    Ok(outcome) => {
                        let status = match outcome.status {
                            PublishStatus::Stored => LegacyAckStatus::Stored,
                            PublishStatus::Duplicate => LegacyAckStatus::Duplicate,
                        };
                        send_frame(
                            out_tx,
                            &PluginFrame::LegacyV1(LegacyV1Frame::Ack {
                                id: ev_id,
                                source: ev_source,
                                status,
                            }),
                        )
                        .await;
                    }
                    Err(err) => {
                        let (nack_err, _, msg) = map_publish_error(&err);
                        send_frame(
                            out_tx,
                            &PluginFrame::LegacyV1(LegacyV1Frame::Nack {
                                id: Some(ev_id),
                                source: Some(ev_source),
                                error: nack_err,
                                message: msg,
                            }),
                        )
                        .await;
                    }
                }
            }
            LegacyV1Frame::Response {
                id,
                ok,
                result,
                error,
            } => {
                if let Some(sender) = pending_requests.lock().await.remove(&id) {
                    let resolved = if ok {
                        Ok(result.unwrap_or(Value::Null))
                    } else {
                        Err(AdapterError::RequestFailed(
                            error.unwrap_or_else(|| "plugin_request_failed".to_string()),
                        ))
                    };
                    let _ = sender.send(resolved);
                }
            }
            LegacyV1Frame::Status {
                target,
                pending,
                oldest_age_seconds,
                t3_connected,
            } => {
                *inner.last_status.write().expect("status lock") = Some(StatusParams {
                    target,
                    pending,
                    oldest_age_seconds,
                    t3_connected,
                });
            }
            LegacyV1Frame::DeliveryFailed {
                target,
                events,
                reason,
            } => {
                host.report_delivery_failed(&inner.config.id, &target, events, &reason)
                    .await;
            }
            LegacyV1Frame::Ack { .. }
            | LegacyV1Frame::Nack { .. }
            | LegacyV1Frame::Request { .. } => {
                send_frame(
                    out_tx,
                    &PluginFrame::LegacyV1(LegacyV1Frame::Nack {
                        id: None,
                        source: None,
                        error: LegacyNackError::UnsupportedType,
                        message: "unexpected legacy frame direction from plugin".to_string(),
                    }),
                )
                .await;
            }
        }
    }

    async fn handle_jsonrpc_request(
        inner: &SupervisorInner,
        host: &Arc<dyn NodeAdapterHost>,
        out_tx: &mpsc::Sender<String>,
        req: JsonRpcRequest,
    ) {
        match req.method.as_str() {
            METHOD_HELLO => {
                let reply = json!({
                    "protocol": 2,
                    "plugin": inner.config.id,
                    "targets": inner.config.targets,
                });
                send_frame(
                    out_tx,
                    &PluginFrame::JsonRpcResponse(JsonRpcResponse::ok(req.id, reply)),
                )
                .await;
            }
            METHOD_PUBLISH => {
                let Some(raw_params) = req.params else {
                    send_frame(
                        out_tx,
                        &PluginFrame::JsonRpcResponse(JsonRpcResponse::err(
                            Some(req.id),
                            ERR_INVALID_PARAMS,
                            "hyphae/publish requires params",
                            None,
                        )),
                    )
                    .await;
                    return;
                };
                let params: PublishParams = match serde_json::from_value(raw_params) {
                    Ok(p) => p,
                    Err(e) => {
                        send_frame(
                            out_tx,
                            &PluginFrame::JsonRpcResponse(JsonRpcResponse::err(
                                Some(req.id),
                                ERR_INVALID_PARAMS,
                                format!("invalid publish params: {e}"),
                                None,
                            )),
                        )
                        .await;
                        return;
                    }
                };

                if !inner.config.targets.is_empty() && !inner.config.targets.contains(&params.to) {
                    send_frame(
                        out_tx,
                        &PluginFrame::JsonRpcResponse(JsonRpcResponse::err(
                            Some(req.id),
                            ERR_UNKNOWN_TARGET,
                            format!("unknown target '{}'", params.to),
                            None,
                        )),
                    )
                    .await;
                    return;
                }

                let parsed = match check_cloudevent_v2(&params.event) {
                    Ok((ev, _)) => ev,
                    Err(err) => {
                        let (_, code, msg) = map_cloudevent_error(&err);
                        send_frame(
                            out_tx,
                            &PluginFrame::JsonRpcResponse(JsonRpcResponse::err(
                                Some(req.id),
                                code,
                                msg,
                                None,
                            )),
                        )
                        .await;
                        return;
                    }
                };

                let ev_id = parsed.id.clone();
                let ev_source = parsed.source.clone();
                match host.publish_event(&params.to, parsed).await {
                    Ok(outcome) => {
                        let status_str = match outcome.status {
                            PublishStatus::Stored => "stored",
                            PublishStatus::Duplicate => "duplicate",
                        };
                        send_frame(
                            out_tx,
                            &PluginFrame::JsonRpcResponse(JsonRpcResponse::ok(
                                req.id,
                                json!({
                                    "id": ev_id,
                                    "source": ev_source,
                                    "status": status_str,
                                    "matched": outcome.matched,
                                }),
                            )),
                        )
                        .await;
                    }
                    Err(err) => {
                        let (_, code, msg) = map_publish_error(&err);
                        send_frame(
                            out_tx,
                            &PluginFrame::JsonRpcResponse(JsonRpcResponse::err(
                                Some(req.id),
                                code,
                                msg,
                                None,
                            )),
                        )
                        .await;
                    }
                }
            }
            METHOD_STATUS => {
                let parsed = req
                    .params
                    .and_then(|raw| serde_json::from_value::<StatusParams>(raw).ok());
                if let Some(status) = parsed {
                    *inner.last_status.write().expect("status lock") = Some(status);
                    send_frame(
                        out_tx,
                        &PluginFrame::JsonRpcResponse(JsonRpcResponse::ok(
                            req.id,
                            json!({ "ok": true }),
                        )),
                    )
                    .await;
                } else {
                    send_frame(
                        out_tx,
                        &PluginFrame::JsonRpcResponse(JsonRpcResponse::err(
                            Some(req.id),
                            ERR_INVALID_PARAMS,
                            "invalid status params",
                            None,
                        )),
                    )
                    .await;
                }
            }
            METHOD_DELIVERY_FAILED => {
                let parsed = req
                    .params
                    .and_then(|raw| serde_json::from_value::<DeliveryFailedParams>(raw).ok());
                if let Some(df) = parsed {
                    host.report_delivery_failed(
                        &inner.config.id,
                        &df.target,
                        df.events,
                        &df.reason,
                    )
                    .await;
                    send_frame(
                        out_tx,
                        &PluginFrame::JsonRpcResponse(JsonRpcResponse::ok(
                            req.id,
                            json!({ "ok": true }),
                        )),
                    )
                    .await;
                } else {
                    send_frame(
                        out_tx,
                        &PluginFrame::JsonRpcResponse(JsonRpcResponse::err(
                            Some(req.id),
                            ERR_INVALID_PARAMS,
                            "invalid deliveryFailed params",
                            None,
                        )),
                    )
                    .await;
                }
            }
            other => {
                send_frame(
                    out_tx,
                    &PluginFrame::JsonRpcResponse(JsonRpcResponse::err(
                        Some(req.id),
                        ERR_METHOD_NOT_FOUND,
                        format!("method not found: {other}"),
                        None,
                    )),
                )
                .await;
            }
        }
    }

    async fn handle_jsonrpc_notification(
        inner: &SupervisorInner,
        host: &Arc<dyn NodeAdapterHost>,
        notif: JsonRpcNotification,
    ) {
        match notif.method.as_str() {
            METHOD_HELLO => {}
            METHOD_PUBLISH => {
                if let Some(params) = notif
                    .params
                    .and_then(|raw| serde_json::from_value::<PublishParams>(raw).ok())
                {
                    if inner.config.targets.is_empty() || inner.config.targets.contains(&params.to)
                    {
                        if let Ok((ev, _)) = check_cloudevent_v2(&params.event) {
                            let _ = host.publish_event(&params.to, ev).await;
                        }
                    }
                }
            }
            METHOD_STATUS => {
                if let Some(status) = notif
                    .params
                    .and_then(|raw| serde_json::from_value::<StatusParams>(raw).ok())
                {
                    *inner.last_status.write().expect("status lock") = Some(status);
                }
            }
            METHOD_DELIVERY_FAILED => {
                if let Some(df) = notif
                    .params
                    .and_then(|raw| serde_json::from_value::<DeliveryFailedParams>(raw).ok())
                {
                    host.report_delivery_failed(
                        &inner.config.id,
                        &df.target,
                        df.events,
                        &df.reason,
                    )
                    .await;
                }
            }
            _ => {}
        }
    }

    async fn handle_jsonrpc_response(
        pending_requests: &Arc<Mutex<PendingMap>>,
        resp: JsonRpcResponse,
    ) {
        let Some(rpc_id) = resp.id else {
            return;
        };
        let key = match rpc_id {
            RpcId::String(s) => s,
            RpcId::Number(n) => n.to_string(),
        };
        if let Some(sender) = pending_requests.lock().await.remove(&key) {
            let resolved = match (resp.result, resp.error) {
                (Some(val), None) => Ok(val),
                (_, Some(err)) => Err(AdapterError::RequestFailed(format!(
                    "{} (code {})",
                    err.message, err.code
                ))),
                (None, None) => Ok(Value::Null),
            };
            let _ = sender.send(resolved);
        }
    }
}
