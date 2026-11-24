//! Single unified fd-3 `SubprocessSupervisor` replacing BOTH v1 `PluginProcess`
//! (`src/core/plugins/supervisor.ts`) AND `RouterStreamHost` (`src/streams.ts`).
//!
//! Key guarantees:
//! - Explicit private bidirectional Unix fd-3 IPC channel (`socketpair(AF_UNIX, SOCK_STREAM)`
//!   duped onto fd 3 with `FD_CLOEXEC` cleared in `pre_exec`, compatible with both Node's
//!   `createReadStream`/`createWriteStream({ fd: 3 })` and Python's `socket.socket(fileno=3)`).
//! - Clean environment allowlist (`PATH`, `HOME`, `TMPDIR`, `LANG`, `XDG_RUNTIME_DIR`,
//!   `DBUS_SESSION_BUS_ADDRESS`, `HYPHAE_PROTOCOL=2`, explicit plugin config env — never leaks
//!   arbitrary host secrets).
//! - Strictly bounded 64 KiB `hyp_proto::rpc::LineSplitter` on incoming fd-3 frames.
//! - Per-frame protocol auto-detection via `hyp_proto::rpc::decode_frame`, seamlessly supporting
//!   BOTH JSON-RPC 2.0 v2 (`hyphae/hello`, `hyphae/publish`, `hyphae/post`, `hyphae/status`,
//!   `hyphae/deliveryFailed`) AND legacy fd-3 v1 (`hello`, `event`, `ack`, `nack`, `request`,
//!   `response`, `status`, `delivery_failed`).
//! - Outbound `post()` request/response correlation with timeouts, exponential restart backoff on
//!   unexpected child exit, and clean `SIGTERM` -> `SIGKILL` shutdown.
//! - Clean cross-platform compilation: Unix fd-3 process management is gated behind `#[cfg(unix)]`,
//!   returning `AdapterError::UnsupportedPlatform` cleanly on non-Unix platforms (e.g. Windows).

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use hyp_proto::rpc::{
    DeliveryFailedParams, JsonRpcNotification, JsonRpcRequest, LegacyV1Frame,
    METHOD_DELIVERY_FAILED, METHOD_POST, METHOD_STATUS, PluginFrame, PostParams, RpcId,
    StatusParams, encode_frame,
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
];

const PROTO_UNKNOWN: u8 = 0;
const PROTO_LEGACY_V1: u8 = 1;
const PROTO_JSONRPC_V2: u8 = 2;

/// Detected or configured wire protocol on the child's fd-3 channel.
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

/// Configuration for a supervised fd-3 subprocess adapter.
#[derive(Debug, Clone)]
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
    /// Delay between `SIGTERM` and `SIGKILL` during shutdown.
    pub kill_timeout: Duration,
    /// Optional explicit parent env map (defaults to `std::env::vars()` when `None`).
    pub parent_env_override: Option<BTreeMap<String, String>>,
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
            hello_mode: HelloMode::Auto,
            auto_hello_grace: Duration::from_millis(50),
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(60),
            reset_after: Duration::from_secs(60),
            kill_timeout: Duration::from_secs(5),
            parent_env_override: None,
        }
    }
}

/// Builds the isolated child environment from [`ALLOWED_PARENT_ENV`], explicit plugin `config.env`,
/// and standard Hyphae protocol variables (`HYPHAE_PROTOCOL=2`, `HYPHAE_FD=3`, etc.).
pub fn build_isolated_env(
    config: &SubprocessConfig,
    parent_env: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for &key in ALLOWED_PARENT_ENV {
        if let Some(val) = parent_env.get(key) {
            env.insert(key.to_string(), val.clone());
        }
    }
    for (k, v) in &config.env {
        env.insert(k.clone(), v.clone());
    }
    env.insert("HYPHAE_FD".to_string(), "3".to_string());
    env.insert("HYPHAE_PLUGIN".to_string(), config.id.clone());
    env.insert("HYPHAE_PROTOCOL".to_string(), "2".to_string());
    env.insert("AGENTS_MESH_FD".to_string(), "3".to_string());
    env.insert("AGENTS_MESH_PLUGIN".to_string(), config.id.clone());
    env.insert("T3_MESH_FD".to_string(), "3".to_string());
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
            }),
        }
    }

    /// Returns the number of unexpected restarts performed by this supervisor.
    pub fn restart_count(&self) -> u64 {
        self.inner.restart_count.load(Ordering::Relaxed)
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
            (conn.tx.clone(), conn.detected_protocol.load(Ordering::Acquire))
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
            (conn.tx.clone(), conn.detected_protocol.load(Ordering::Acquire))
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
            #[cfg(not(unix))]
            {
                let _ = host;
                Err(AdapterError::UnsupportedPlatform(
                    "fd-3 subprocess plugins require Unix".to_string(),
                ))
            }

            #[cfg(unix)]
            {
                let mut handle_guard = self.inner.loop_handle.lock().await;
                if handle_guard.is_some() {
                    return Err(AdapterError::AlreadyStarted(self.inner.config.id.clone()));
                }

                self.inner.stopping.store(0, Ordering::Release);
                self.set_health(AdapterHealth::Starting);
                host.update_status(&self.inner.config.id, AdapterHealth::Starting)
                    .await;

                let inner = Arc::clone(&self.inner);
                let ready_notify = Arc::new(Notify::new());
                let ready_notify_bg = Arc::clone(&ready_notify);

                let task = tokio::spawn(async move {
                    unix_runtime::supervise_loop(inner, host, Some(ready_notify_bg)).await;
                });

                *handle_guard = Some(task);
                drop(handle_guard);

                let _ = tokio::time::timeout(Duration::from_secs(2), ready_notify.notified()).await;
                Ok(())
            }
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

#[cfg(unix)]
mod unix_runtime {
    use std::collections::HashMap;
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream as StdUnixStream;
    use std::process::Stdio;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU8, Ordering};
    use std::time::{Duration, Instant};

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
    use serde_json::{Value, json};
    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
    use tokio::net::UnixStream as TokioUnixStream;
    use tokio::process::{Child, Command};
    use tokio::sync::{Mutex, Notify, mpsc};
    use tokio::task::JoinHandle;

    use crate::adapters::trait_def::{
        AdapterError, AdapterHealth, NodeAdapterHost, PublishErrorCode, PublishStatus,
    };

    use super::{
        ActiveConnection, HelloMode, PROTO_JSONRPC_V2, PROTO_LEGACY_V1, PROTO_UNKNOWN, PendingMap,
        SubprocessConfig, SupervisorInner, build_isolated_env,
    };

    const MAX_OUTPUT_LINE_BYTES: usize = 2 * 1024;
    const MAX_ECHO_CHARS: usize = 256;
    const OUTBOUND_QUEUE_CAPACITY: usize = 256;

    const F_SETFD: i32 = 2;
    const SIGTERM: i32 = 15;

    unsafe extern "C" {
        fn dup2(oldfd: i32, newfd: i32) -> i32;
        fn fcntl(fd: i32, cmd: i32, ...) -> i32;
        fn kill(pid: i32, sig: i32) -> i32;
    }

    fn spawn_with_fd3(config: &SubprocessConfig) -> std::io::Result<(Child, TokioUnixStream)> {
        let (parent_sock, child_sock) = StdUnixStream::pair()?;
        parent_sock.set_nonblocking(true)?;
        child_sock.set_nonblocking(false)?;

        let parent_env = config
            .parent_env_override
            .clone()
            .unwrap_or_else(|| std::env::vars().collect());
        let env = build_isolated_env(config, &parent_env);

        let mut cmd = Command::new(&config.exec);
        cmd.args(&config.args)
            .env_clear()
            .envs(&env)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

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

    async fn terminate_child(child: &mut Child, kill_timeout: Duration) {
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

    pub(super) async fn supervise_loop(
        inner: Arc<SupervisorInner>,
        host: Arc<dyn NodeAdapterHost>,
        mut first_ready: Option<Arc<Notify>>,
    ) {
        let mut backoff = inner.config.initial_backoff;

        while inner.stopping.load(Ordering::Acquire) == 0 {
            let started_at = Instant::now();
            let spawned = spawn_with_fd3(&inner.config);

            let (mut child, stream) = match spawned {
                Ok(pair) => pair,
                Err(err) => {
                    let reason = format!("spawn failed: {err}");
                    *inner.health.write().expect("health lock") =
                        AdapterHealth::Degraded(reason.clone());
                    host.update_status(&inner.config.id, AdapterHealth::Degraded(reason))
                        .await;
                    if let Some(n) = first_ready.take() {
                        n.notify_waiters();
                    }
                    if !sleep_or_stop(&inner, backoff).await {
                        break;
                    }
                    backoff = (backoff * 2).min(inner.config.max_backoff);
                    inner.restart_count.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
            };

            let stdout_task = child.stdout.take().map(drain_output_stream);
            let stderr_task = child.stderr.take().map(drain_output_stream);

            let (mut read_half, mut write_half) = stream.into_split();
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
                    let last_proto_inner = Arc::clone(&inner);
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
                                        &inner,
                                        &host,
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

            if let Some(t) = stdout_task {
                let _ = t.await;
            }
            if let Some(t) = stderr_task {
                let _ = t.await;
            }

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
            let reason = format!("subprocess {exit_desc} unexpectedly");
            *inner.health.write().expect("health lock") = AdapterHealth::Degraded(reason.clone());
            host.update_status(&inner.config.id, AdapterHealth::Degraded(reason))
                .await;

            if !sleep_or_stop(&inner, backoff).await {
                *inner.health.write().expect("health lock") = AdapterHealth::Stopped;
                host.update_status(&inner.config.id, AdapterHealth::Stopped)
                    .await;
                break;
            }
            backoff = (backoff * 2).min(inner.config.max_backoff);
            inner.restart_count.fetch_add(1, Ordering::Relaxed);
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
                    host.report_delivery_failed(&inner.config.id, &df.target, df.events, &df.reason)
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
                    host.report_delivery_failed(&inner.config.id, &df.target, df.events, &df.reason)
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
