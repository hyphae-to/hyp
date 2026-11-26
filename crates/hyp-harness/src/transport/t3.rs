//! T3 Code (`statev2.sqlite` + authenticated WebSocket RPC) native wakeup transport.
//!
//! Pure-Rust parity implementation of Hyphae v1's `src/t3.ts`:
//! - Strict origin validation ([`normalize_t3_server_url`]): HTTPS origin or loopback HTTP origin only.
//! - Strictly read-only `statev2.sqlite` resolution ([`resolve_t3_thread_by_provider_session`],
//!   [`verify_t3_thread_exists`], [`resolve_t3_caller_by_call_id`]) across both orchestration v2 and
//!   legacy v1 projection tables, failing closed on deleted/archived/ambiguous threads.
//! - Zero-leak bearer token lookup via [`SecretStore`] (`"t3-auth-token"`, fallback `"t3-session-token"`).
//! - Server session probe ([`probe_t3_server`]) via `GET /api/auth/session`.
//! - Authenticated `POST /api/auth/websocket-ticket` + pure-Rust RFC 6455 WebSocket client
//!   (over loopback TCP `ws://` and `rustls` TLS `wss://`) speaking T3's orchestration protocol v2
//!   Effect RPC (`orchestration.getThreadProjection` + `orchestration.dispatchCommand`).

use std::collections::BTreeSet;
use std::fmt;
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use bytes::Bytes;
use http::{HeaderValue, Method, Request, StatusCode, Uri, Version, header};
use http_body_util::{BodyExt, Full};
use hyp_crypto::{CryptoError, SecretBackend, SecretStore};
use hyp_store::uuid_v4;
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::{TokioExecutor, TokioIo};
use ring::digest::{SHA1_FOR_LEGACY_USE_ONLY, digest};
use ring::rand::{SecureRandom, SystemRandom};
use rusqlite::{Connection, OpenFlags, OptionalExtension};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;

use crate::call_registry::CallerErrorCode;
use crate::protocol::normalize_mesh_tool_name;
use crate::transport::{InboxDigest, PushMode, PushOutcome, PushTransport, TransportFuture};

/// Default loopback T3 Code server origin.
pub const DEFAULT_T3_URL: &str = "http://127.0.0.1:3773";
/// Primary `SecretStore` key name holding the T3 Code bearer token.
pub const DEFAULT_T3_TOKEN_SECRET: &str = "t3-auth-token";
/// Fallback `SecretStore` key name checked when no custom secret name is configured.
pub const FALLBACK_T3_TOKEN_SECRET: &str = "t3-session-token";
/// T3 orchestration WebSocket RPC protocol version query parameter.
pub const T3_ORCHESTRATION_PROTOCOL: &str = "2";

/// Default timeout for `/api/auth/websocket-ticket` and WebSocket upgrade handshake.
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
/// Default timeout for `orchestration.getThreadProjection`.
pub const DEFAULT_PROJECTION_TIMEOUT: Duration = Duration::from_secs(12);
/// Default timeout for `orchestration.dispatchCommand`.
pub const DEFAULT_DISPATCH_TIMEOUT: Duration = Duration::from_secs(15);
/// Default timeout for `GET /api/auth/session` probe.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_millis(2_500);

/// Hard cap (2 MiB) on any single WebSocket frame or reassembled fragmented message.
pub const MAX_WS_FRAME_BYTES: usize = 2 * 1024 * 1024;
/// Hard cap (256 KiB) on HTTP JSON responses from `/api/auth/*`.
const MAX_HTTP_BODY_BYTES: usize = 256 * 1024;
/// RFC 6455 §1.3 static GUID concatenated to `Sec-WebSocket-Key`.
const WS_GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

// ============================================================================
// Public Types & Configuration
// ============================================================================

/// Target configuration for a T3 Code thread wakeup transport.
#[derive(Clone, PartialEq, Eq)]
pub struct T3Target {
    /// Owning T3 Code thread ID.
    pub thread_id: String,
    /// T3 Code server origin (must pass [`normalize_t3_server_url`]).
    pub server_url: String,
    /// Optional T3 Code base directory containing `userdata/statev2.sqlite`.
    pub base_dir: Option<PathBuf>,
    /// Optional explicit `SecretStore` key name (defaults to [`DEFAULT_T3_TOKEN_SECRET`]
    /// with fallback to [`FALLBACK_T3_TOKEN_SECRET`]).
    pub token_secret: Option<String>,
    /// Optional Hyphae state/config directory used to open [`SecretStore`].
    pub state_dir: Option<PathBuf>,
    /// Optional explicit [`SecretBackend`] override (e.g. `SecretBackend::File` in tests).
    pub secret_backend: Option<SecretBackend>,
    /// Optional direct bearer token override (programmatic/test helper; redacted in `Debug`
    /// and never persisted to disk).
    pub token_override: Option<String>,
}

impl T3Target {
    /// Creates a minimal target bound to `thread_id` and `server_url` using default secret lookup.
    pub fn new(thread_id: impl Into<String>, server_url: impl Into<String>) -> Self {
        Self {
            thread_id: thread_id.into(),
            server_url: server_url.into(),
            base_dir: None,
            token_secret: None,
            state_dir: None,
            secret_backend: None,
            token_override: None,
        }
    }
}

impl fmt::Debug for T3Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("T3Target")
            .field("thread_id", &self.thread_id)
            .field("server_url", &self.server_url)
            .field("base_dir", &self.base_dir)
            .field("token_secret", &self.token_secret)
            .field("state_dir", &self.state_dir)
            .field("secret_backend", &self.secret_backend)
            .field(
                "token_override",
                &self.token_override.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Fail-closed error returned by T3 `statev2.sqlite` thread/caller resolution helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum T3LookupError {
    /// No matching active (non-deleted, non-archived) T3 thread or DB was found.
    CallerNotFound(String),
    /// Multiple distinct active T3 threads matched the same session/call identifier.
    CallerAmbiguous(String),
    /// Tool name could not be verified as a known Hyphae mesh tool.
    CallerUnverifiable(String),
}

impl T3LookupError {
    /// Maps this error to its canonical [`CallerErrorCode`].
    pub const fn code(&self) -> CallerErrorCode {
        match self {
            Self::CallerNotFound(_) => CallerErrorCode::CallerNotFound,
            Self::CallerAmbiguous(_) => CallerErrorCode::CallerAmbiguous,
            Self::CallerUnverifiable(_) => CallerErrorCode::CallerUnverifiable,
        }
    }

    /// Human-readable error message.
    pub fn message(&self) -> &str {
        match self {
            Self::CallerNotFound(m) | Self::CallerAmbiguous(m) | Self::CallerUnverifiable(m) => m,
        }
    }
}

impl fmt::Display for T3LookupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code().as_str(), self.message())
    }
}

impl std::error::Error for T3LookupError {}

/// Outcome of resolving a T3 Code thread ID from read-only `statev2.sqlite` projections.
pub type T3ThreadLookupResult = Result<String, T3LookupError>;

/// Result of probing a T3 Code server's `GET /api/auth/session` endpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct T3ProbeResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authenticated: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl T3ProbeResult {
    /// Returns `true` ONLY when the T3 server responded 2xx AND confirmed authentication
    /// succeeded (`authenticated == Some(true)`). Unauthenticated 2xx responses MUST NOT be
    /// treated as live attachable transports because delivery fails with `t3_auth_missing` /
    /// `t3_auth_failed` and silently drops wakeups.
    pub fn is_authenticated(&self) -> bool {
        self.ok && self.authenticated == Some(true)
    }
}

/// Selected T3 orchestration v2 `message.dispatch` mode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum T3DispatchMode {
    StartImmediately,
    QueueAfterActive,
    SteerActive { target_run_id: String },
    RestartActive { target_run_id: String },
}

impl T3DispatchMode {
    fn to_json(&self) -> Value {
        match self {
            Self::StartImmediately => json!({ "type": "start_immediately" }),
            Self::QueueAfterActive => json!({ "type": "queue_after_active" }),
            Self::SteerActive { target_run_id } => json!({
                "type": "steer_active",
                "targetRunId": target_run_id,
            }),
            Self::RestartActive { target_run_id } => json!({
                "type": "restart_active",
                "targetRunId": target_run_id,
            }),
        }
    }
}

/// Rich delivery detail returned by [`T3Transport::deliver_detailed`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct T3DeliveryDetail {
    pub outcome: PushOutcome,
    pub interrupted: bool,
    pub dispatch_mode: Option<T3DispatchMode>,
}

// ============================================================================
// Path & URL Validation Helpers
// ============================================================================

/// Resolves the default T3 Code base directory (`$T3CODE_HOME` if non-empty, else `~/.t3`).
pub fn default_t3_base_dir() -> PathBuf {
    if let Ok(env_home) = std::env::var("T3CODE_HOME") {
        let trimmed = env_home.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    home_dir().join(".t3")
}

/// Returns `<base_dir>/userdata/statev2.sqlite`.
pub fn t3_state_db_path(base_dir: &Path) -> PathBuf {
    base_dir.join("userdata").join("statev2.sqlite")
}

fn home_dir() -> PathBuf {
    if let Ok(h) = std::env::var("HOME") {
        if !h.trim().is_empty() {
            return PathBuf::from(h);
        }
    }
    if let Ok(h) = std::env::var("USERPROFILE") {
        if !h.trim().is_empty() {
            return PathBuf::from(h);
        }
    }
    PathBuf::from(".")
}

fn default_hyphae_config_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("HYPHAE_CONFIG_DIR") {
        let trimmed = dir.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed);
        }
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        let trimmed = xdg.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed).join("hyphae");
        }
    }
    #[cfg(windows)]
    if let Ok(appdata) = std::env::var("APPDATA") {
        let trimmed = appdata.trim();
        if !trimmed.is_empty() {
            return PathBuf::from(trimmed).join("hyphae");
        }
    }
    home_dir().join(".config").join("hyphae")
}

const INVALID_URL_ERR: &str = "T3 Code server URL must be a loopback origin (e.g. http://127.0.0.1:3773) or an explicit HTTPS origin when remote access is enabled";

/// Returns `true` iff `name` is one of the two allowed T3 Code bearer token secret names
/// (`"t3-auth-token"` or `"t3-session-token"`). Arbitrary `tokenSecret` names from config
/// MUST fail closed so a config writer can never exfiltrate other Keychain/SecretStore entries.
pub fn is_allowed_t3_token_secret(name: &str) -> bool {
    matches!(
        name.trim(),
        DEFAULT_T3_TOKEN_SECRET | FALLBACK_T3_TOKEN_SECRET
    )
}

/// Validates and normalizes a T3 Code server URL to its canonical origin (`scheme://host[:port]`).
///
/// Security invariants (exact v1 `src/t3.ts` parity):
/// - Accepts ONLY `https://` origins or loopback `http://` origins (`localhost`, `127.0.0.1`, `[::1]`).
/// - Rejects credentials/userinfo (`user:pass@`), non-root paths, query strings, fragments,
///   backslashes, whitespace, and control characters.
/// - Omits default ports (`:80` for `http`, `:443` for `https`) and trailing `/`.
pub fn normalize_t3_server_url(raw: &str) -> Result<String, String> {
    normalize_t3_server_url_with_remote(raw, true)
}

/// Validates and normalizes a T3 Code server URL, enforcing loopback-only origins
/// (`127.0.0.1`, `localhost`, `[::1]`) unless `allow_remote == true` AND `scheme == "https"`.
pub fn normalize_t3_server_url_with_remote(
    raw: &str,
    allow_remote: bool,
) -> Result<String, String> {
    if raw.is_empty()
        || raw
            .bytes()
            .any(|b| b <= 0x20 || b == 0x7f || b == b'\\' || b == b'?' || b == b'#')
    {
        return Err(INVALID_URL_ERR.to_string());
    }

    let Some(scheme_end) = raw.find("://") else {
        return Err(INVALID_URL_ERR.to_string());
    };
    let scheme = raw[..scheme_end].to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return Err(INVALID_URL_ERR.to_string());
    }

    let after_scheme = &raw[scheme_end + 3..];
    if after_scheme.is_empty() {
        return Err(INVALID_URL_ERR.to_string());
    }

    let (authority, path) = match after_scheme.find('/') {
        Some(idx) => (&after_scheme[..idx], &after_scheme[idx..]),
        None => (after_scheme, ""),
    };

    // Only empty path or root "/" is permitted.
    if !path.is_empty() && path != "/" {
        return Err(INVALID_URL_ERR.to_string());
    }

    // Reject any userinfo / credentials (`@`).
    if authority.is_empty() || authority.contains('@') {
        return Err(INVALID_URL_ERR.to_string());
    }

    let (host_lower, port_opt) = if let Some(rest) = authority.strip_prefix('[') {
        let Some(close_bracket) = rest.find(']') else {
            return Err(INVALID_URL_ERR.to_string());
        };
        let ipv6_str = &rest[..close_bracket];
        let ipv6: Ipv6Addr = ipv6_str.parse().map_err(|_| INVALID_URL_ERR.to_string())?;
        let after_bracket = &rest[close_bracket + 1..];
        let port = parse_optional_port(after_bracket)?;
        (format!("[{ipv6}]"), port)
    } else {
        if authority.contains('[') || authority.contains(']') {
            return Err(INVALID_URL_ERR.to_string());
        }
        let (host, port_str) = match authority.rfind(':') {
            Some(colon) => (&authority[..colon], Some(&authority[colon..])),
            None => (authority, None),
        };
        if host.is_empty() || host.contains(':') {
            return Err(INVALID_URL_ERR.to_string());
        }
        if !is_valid_hostname(host) {
            return Err(INVALID_URL_ERR.to_string());
        }
        let port = match port_str {
            Some(p) => parse_optional_port(p)?,
            None => None,
        };
        (host.to_ascii_lowercase(), port)
    };

    let is_loopback = matches!(host_lower.as_str(), "localhost" | "127.0.0.1" | "[::1]");
    let allowed = is_loopback || (allow_remote && scheme == "https");
    if !allowed {
        return Err(INVALID_URL_ERR.to_string());
    }

    let default_port = if scheme == "https" { 443 } else { 80 };
    let origin = match port_opt {
        Some(port) if port != default_port => format!("{scheme}://{host_lower}:{port}"),
        _ => format!("{scheme}://{host_lower}"),
    };

    // Final cross-check with `http::Uri` so downstream hyper requests always accept this origin.
    origin
        .parse::<Uri>()
        .map_err(|_| INVALID_URL_ERR.to_string())?;

    Ok(origin)
}

fn parse_optional_port(suffix: &str) -> Result<Option<u16>, String> {
    if suffix.is_empty() {
        return Ok(None);
    }
    let Some(digits) = suffix.strip_prefix(':') else {
        return Err(INVALID_URL_ERR.to_string());
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return Err(INVALID_URL_ERR.to_string());
    }
    let port: u16 = digits.parse().map_err(|_| INVALID_URL_ERR.to_string())?;
    if port == 0 {
        return Err(INVALID_URL_ERR.to_string());
    }
    Ok(Some(port))
}

fn is_valid_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if host.starts_with('.') || host.contains("..") {
        return false;
    }
    let trimmed = host.strip_suffix('.').unwrap_or(host);
    if trimmed.is_empty() {
        return false;
    }
    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return false;
        }
    }
    true
}

// ============================================================================
// Read-Only `statev2.sqlite` Thread & Caller Resolution
// ============================================================================

fn open_t3_db_read_only(base_dir: &Path) -> Option<Connection> {
    let db_path = t3_state_db_path(base_dir);
    if !db_path.is_file() {
        return None;
    }
    let conn = Connection::open_with_flags(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .ok()?;
    let _ = conn.busy_timeout(Duration::from_millis(500));
    let _ = conn.pragma_update(None, "query_only", "ON");
    Some(conn)
}

fn table_exists(conn: &Connection, name: &str) -> bool {
    conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [name],
        |row| row.get::<_, i64>(0),
    )
    .optional()
    .ok()
    .flatten()
    .is_some()
}

/// Resolves a provider session/thread ID (e.g. Claude `session_id` or Codex `thread_id`)
/// to its owning active T3 Code `thread_id` via T3's read-only `statev2.sqlite` projections.
///
/// Checks both v2 (`orchestration_v2_projection_*`) and v1 (`projection_thread_*`) tables.
/// Ignores deleted/archived threads and fails closed with [`T3LookupError::CallerAmbiguous`]
/// if more than one active T3 thread matches.
pub fn resolve_t3_thread_by_provider_session(
    provider_session_id: &str,
    base_dir: &Path,
) -> T3ThreadLookupResult {
    if provider_session_id.is_empty() || provider_session_id.len() > 256 {
        return Err(T3LookupError::CallerNotFound(
            "Empty or invalid provider session ID".to_string(),
        ));
    }

    let Some(conn) = open_t3_db_read_only(base_dir) else {
        return Err(T3LookupError::CallerNotFound(format!(
            "T3 state DB not found under {}",
            base_dir.display()
        )));
    };

    let mut matched = BTreeSet::<String>::new();
    let has_v2_threads = table_exists(&conn, "orchestration_v2_projection_threads");

    let query_result: rusqlite::Result<()> = (|| {
        if has_v2_threads
            && table_exists(
                &conn,
                "orchestration_v2_projection_provider_session_bindings",
            )
        {
            let mut stmt = conn.prepare(
                "SELECT DISTINCT b.thread_id
                 FROM orchestration_v2_projection_provider_session_bindings b
                 JOIN orchestration_v2_projection_threads t ON t.thread_id = b.thread_id
                 WHERE b.provider_session_id = ?1
                   AND t.deleted_at IS NULL AND t.archived_at IS NULL",
            )?;
            let rows =
                stmt.query_map([provider_session_id], |row| row.get::<_, Option<String>>(0))?;
            for r in rows {
                if let Some(tid) = r? {
                    if !tid.is_empty() {
                        matched.insert(tid);
                    }
                }
            }
        }

        if has_v2_threads && table_exists(&conn, "orchestration_v2_projection_provider_threads") {
            let mut stmt = conn.prepare(
                "SELECT DISTINCT p.thread_id
                 FROM orchestration_v2_projection_provider_threads p
                 JOIN orchestration_v2_projection_threads t ON t.thread_id = p.thread_id
                 WHERE (p.provider_thread_id = ?1 OR p.provider_session_id = ?1)
                   AND t.deleted_at IS NULL AND t.archived_at IS NULL",
            )?;
            let rows =
                stmt.query_map([provider_session_id], |row| row.get::<_, Option<String>>(0))?;
            for r in rows {
                if let Some(tid) = r? {
                    if !tid.is_empty() {
                        matched.insert(tid);
                    }
                }
            }
        }

        if table_exists(&conn, "projection_thread_sessions")
            && table_exists(&conn, "projection_threads")
        {
            let mut stmt = conn.prepare(
                "SELECT DISTINCT s.thread_id
                 FROM projection_thread_sessions s
                 JOIN projection_threads t ON t.thread_id = s.thread_id
                 WHERE (s.provider_session_id = ?1 OR s.provider_thread_id = ?1)
                   AND t.deleted_at IS NULL AND t.archived_at IS NULL",
            )?;
            let rows =
                stmt.query_map([provider_session_id], |row| row.get::<_, Option<String>>(0))?;
            for r in rows {
                if let Some(tid) = r? {
                    if !tid.is_empty() {
                        matched.insert(tid);
                    }
                }
            }
        }

        Ok(())
    })();

    if query_result.is_err() {
        return Err(T3LookupError::CallerNotFound(
            "Failed to query T3 state database".to_string(),
        ));
    }

    match matched.len() {
        1 => Ok(matched.into_iter().next().expect("len == 1")),
        n if n > 1 => Err(T3LookupError::CallerAmbiguous(format!(
            "Provider session {provider_session_id} matched {n} active T3 threads"
        ))),
        _ => Err(T3LookupError::CallerNotFound(format!(
            "No active T3 thread bound to provider session {provider_session_id}"
        ))),
    }
}

/// Verifies that an explicit T3 thread ID exists and is neither deleted nor archived.
pub fn verify_t3_thread_exists(thread_id: &str, base_dir: &Path) -> bool {
    if thread_id.is_empty() || thread_id.len() > 200 {
        return false;
    }
    let Some(conn) = open_t3_db_read_only(base_dir) else {
        return false;
    };

    if table_exists(&conn, "orchestration_v2_projection_threads") {
        let found = conn
            .query_row(
                "SELECT 1 FROM orchestration_v2_projection_threads
                 WHERE thread_id = ?1 AND deleted_at IS NULL AND archived_at IS NULL",
                [thread_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .ok()
            .flatten()
            .is_some();
        if found {
            return true;
        }
    }

    if table_exists(&conn, "projection_threads") {
        let found = conn
            .query_row(
                "SELECT 1 FROM projection_threads
                 WHERE thread_id = ?1 AND deleted_at IS NULL AND archived_at IS NULL",
                [thread_id],
                |row| row.get::<_, i64>(0),
            )
            .optional()
            .ok()
            .flatten()
            .is_some();
        if found {
            return true;
        }
    }

    false
}

fn payload_matches_call(payload_json: &str, call_id: &str, normalized_tool: &str) -> bool {
    if !payload_json.contains(call_id) {
        return false;
    }
    let Ok(parsed) = serde_json::from_str::<Value>(payload_json) else {
        return false;
    };
    let mut stack = vec![&parsed];
    let mut saw_call_id = false;
    let mut saw_tool = false;
    while let Some(cur) = stack.pop() {
        match cur {
            Value::String(s) => {
                if s == call_id {
                    saw_call_id = true;
                }
                if normalize_mesh_tool_name(s) == Some(normalized_tool) {
                    saw_tool = true;
                }
            }
            Value::Array(items) => {
                for item in items {
                    stack.push(item);
                }
            }
            Value::Object(map) => {
                for v in map.values() {
                    stack.push(v);
                }
            }
            _ => {}
        }
        if saw_call_id && saw_tool {
            return true;
        }
    }
    saw_call_id && saw_tool
}

fn escape_sql_like(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('%');
    for ch in raw.chars() {
        if matches!(ch, '%' | '_' | '\\') {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('%');
    out
}

/// Single-shot read-only lookup for an in-flight T3 tool call matching both `call_id`
/// and the normalized Hyphae tool name in `orchestration_v2_projection_turn_items` or
/// `projection_thread_activities`.
pub fn lookup_t3_call_once(base_dir: &Path, call_id: &str, tool: &str) -> T3ThreadLookupResult {
    let Some(normalized_tool) = normalize_mesh_tool_name(tool) else {
        return Err(T3LookupError::CallerUnverifiable(format!(
            "Unknown mesh tool {tool}"
        )));
    };
    if call_id.is_empty() || call_id.len() > 256 {
        return Err(T3LookupError::CallerNotFound(
            "Empty or invalid call ID".to_string(),
        ));
    }

    let Some(conn) = open_t3_db_read_only(base_dir) else {
        return Err(T3LookupError::CallerNotFound(format!(
            "T3 state DB not found under {}",
            base_dir.display()
        )));
    };

    let like_pattern = escape_sql_like(call_id);
    let mut matched = BTreeSet::<String>::new();

    let query_result: rusqlite::Result<()> = (|| {
        if table_exists(&conn, "orchestration_v2_projection_turn_items")
            && table_exists(&conn, "orchestration_v2_projection_threads")
        {
            let mut stmt = conn.prepare(
                "SELECT i.thread_id, i.payload_json
                 FROM orchestration_v2_projection_turn_items i
                 JOIN orchestration_v2_projection_threads t ON t.thread_id = i.thread_id
                 WHERE i.payload_json LIKE ?1 ESCAPE '\\'
                   AND t.deleted_at IS NULL AND t.archived_at IS NULL
                   AND LOWER(i.status) NOT IN ('completed', 'succeeded', 'failed', 'cancelled', 'error')",
            )?;
            let rows = stmt.query_map([&like_pattern], |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            })?;
            for r in rows {
                let (tid_opt, payload_opt) = r?;
                if let (Some(tid), Some(payload)) = (tid_opt, payload_opt) {
                    if !tid.is_empty() && payload_matches_call(&payload, call_id, normalized_tool) {
                        matched.insert(tid);
                    }
                }
            }
        }

        if matched.is_empty()
            && table_exists(&conn, "projection_thread_activities")
            && table_exists(&conn, "projection_threads")
        {
            let mut stmt = conn.prepare(
                "SELECT a.thread_id, a.payload_json
                 FROM projection_thread_activities a
                 JOIN projection_threads t ON t.thread_id = a.thread_id
                 WHERE a.payload_json LIKE ?1 ESCAPE '\\'
                   AND t.deleted_at IS NULL AND t.archived_at IS NULL
                 ORDER BY a.created_at DESC
                 LIMIT 20",
            )?;
            let rows = stmt.query_map([&like_pattern], |row| {
                Ok((
                    row.get::<_, Option<String>>(0)?,
                    row.get::<_, Option<String>>(1)?,
                ))
            })?;
            for r in rows {
                let (tid_opt, payload_opt) = r?;
                if let (Some(tid), Some(payload)) = (tid_opt, payload_opt) {
                    if !tid.is_empty() && payload_matches_call(&payload, call_id, normalized_tool) {
                        matched.insert(tid);
                    }
                }
            }
        }

        Ok(())
    })();

    if query_result.is_err() {
        return Err(T3LookupError::CallerNotFound(
            "Failed to query T3 turn items".to_string(),
        ));
    }

    match matched.len() {
        1 => Ok(matched.into_iter().next().expect("len == 1")),
        n if n > 1 => Err(T3LookupError::CallerAmbiguous(format!(
            "T3 call {call_id} matched {n} active threads"
        ))),
        _ => Err(T3LookupError::CallerNotFound(format!(
            "No in-flight T3 call found for {normalized_tool} ({call_id})"
        ))),
    }
}

/// Authoritative per-call T3 Code caller verification directly against T3's read-only
/// `statev2.sqlite` projections with bounded exponential retry (matching `src/t3.ts`).
pub async fn resolve_t3_caller_by_call_id(
    call_id: &str,
    tool: &str,
    base_dir: &Path,
    timeout: Duration,
) -> T3ThreadLookupResult {
    if normalize_mesh_tool_name(tool).is_none() {
        return Err(T3LookupError::CallerUnverifiable(format!(
            "Unknown mesh tool {tool}"
        )));
    }
    let deadline = Instant::now() + timeout;
    let mut delay = Duration::from_millis(40);
    loop {
        let res = lookup_t3_call_once(base_dir, call_id, tool);
        match res {
            Ok(thread_id) => return Ok(thread_id),
            Err(err @ T3LookupError::CallerAmbiguous(_))
            | Err(err @ T3LookupError::CallerUnverifiable(_)) => return Err(err),
            Err(err) => {
                let now = Instant::now();
                if now + delay > deadline {
                    return Err(err);
                }
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_millis(200));
            }
        }
    }
}

// ============================================================================
// Secret Resolution & HTTP Helpers
// ============================================================================

fn resolve_bearer_token(target: &T3Target) -> Option<String> {
    if let Some(ref direct) = target.token_override {
        let trimmed = direct.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    let config_dir = target
        .state_dir
        .clone()
        .unwrap_or_else(default_hyphae_config_dir);
    let store = match target.secret_backend {
        Some(backend) => SecretStore::new(config_dir, backend),
        None => SecretStore::from_env(config_dir),
    };

    if let Some(custom_name) = target
        .token_secret
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if !is_allowed_t3_token_secret(custom_name) {
            return None;
        }
        return store
            .get(custom_name)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
    }

    // Default lookup: primary "t3-auth-token", fallback "t3-session-token".
    match store.get(DEFAULT_T3_TOKEN_SECRET) {
        Ok(val) => {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
        Err(CryptoError::SecretNotFound(_)) => {}
        Err(_) => return None,
    }

    store
        .get(FALLBACK_T3_TOKEN_SECRET)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn build_http1_client() -> Client<HttpsConnector<HttpConnector>, Full<Bytes>> {
    let connector = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_http1()
        .build();
    Client::builder(TokioExecutor::new())
        .pool_max_idle_per_host(0)
        .build(connector)
}

async fn read_bounded_http_body(
    mut body: hyper::body::Incoming,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    while let Some(frame_res) = body.frame().await {
        let frame = frame_res.map_err(|e| format!("HTTP body read error: {e}"))?;
        if let Ok(data) = frame.into_data() {
            if out.len().saturating_add(data.len()) > max_bytes {
                return Err(format!("HTTP response exceeded {max_bytes} byte cap"));
            }
            out.extend_from_slice(&data);
        }
    }
    Ok(out)
}

/// Probes a running T3 Code server's `GET /api/auth/session` endpoint (loopback-only by default).
pub async fn probe_t3_server(
    server_url: &str,
    token: Option<&str>,
    timeout: Duration,
) -> T3ProbeResult {
    probe_t3_server_with_remote(server_url, token, false, timeout).await
}

/// Probes a running T3 Code server's `GET /api/auth/session` endpoint, allowing remote `https://`
/// origins ONLY when `allow_remote == true`.
pub async fn probe_t3_server_with_remote(
    server_url: &str,
    token: Option<&str>,
    allow_remote: bool,
    timeout: Duration,
) -> T3ProbeResult {
    let origin = match normalize_t3_server_url_with_remote(server_url, allow_remote) {
        Ok(o) => o,
        Err(e) => {
            return T3ProbeResult {
                ok: false,
                authenticated: None,
                error: Some(e),
            };
        }
    };

    let uri: Uri = match format!("{origin}/api/auth/session").parse() {
        Ok(u) => u,
        Err(e) => {
            return T3ProbeResult {
                ok: false,
                authenticated: None,
                error: Some(format!("Invalid probe URI: {e}")),
            };
        }
    };

    let mut req_builder = Request::builder().method(Method::GET).uri(uri);
    if let Some(tok) = token.map(str::trim).filter(|s| !s.is_empty()) {
        let header_val = match HeaderValue::from_str(&format!("Bearer {tok}")) {
            Ok(v) => v,
            Err(_) => {
                return T3ProbeResult {
                    ok: false,
                    authenticated: None,
                    error: Some("Invalid bearer token header characters".to_string()),
                };
            }
        };
        req_builder = req_builder.header(header::AUTHORIZATION, header_val);
    }

    let req = match req_builder.body(Full::new(Bytes::new())) {
        Ok(r) => r,
        Err(e) => {
            return T3ProbeResult {
                ok: false,
                authenticated: None,
                error: Some(format!("Failed to build probe request: {e}")),
            };
        }
    };

    let client = build_http1_client();
    let resp = match tokio::time::timeout(timeout, client.request(req)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            return T3ProbeResult {
                ok: false,
                authenticated: None,
                error: Some(e.to_string()),
            };
        }
        Err(_) => {
            return T3ProbeResult {
                ok: false,
                authenticated: None,
                error: Some("T3 probe timed out".to_string()),
            };
        }
    };

    let status = resp.status();
    if !status.is_success() {
        return T3ProbeResult {
            ok: false,
            authenticated: None,
            error: Some(format!("HTTP {}", status.as_u16())),
        };
    }

    let bytes = match tokio::time::timeout(
        timeout,
        read_bounded_http_body(resp.into_body(), MAX_HTTP_BODY_BYTES),
    )
    .await
    {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => {
            return T3ProbeResult {
                ok: false,
                authenticated: None,
                error: Some(e),
            };
        }
        Err(_) => {
            return T3ProbeResult {
                ok: false,
                authenticated: None,
                error: Some("T3 probe body read timed out".to_string()),
            };
        }
    };

    let authenticated = serde_json::from_slice::<Value>(&bytes)
        .ok()
        .and_then(|v| {
            v.as_object()
                .and_then(|o| o.get("authenticated"))
                .and_then(Value::as_bool)
        })
        .unwrap_or(false);

    T3ProbeResult {
        ok: true,
        authenticated: Some(authenticated),
        error: None,
    }
}

// ============================================================================
// Pure-Rust RFC 6455 WebSocket Client (TCP + TLS via `hyper` Upgrade)
// ============================================================================

#[derive(Debug)]
enum WsError {
    Io(String),
    Protocol(String),
    FrameTooLarge(usize),
    Closed,
}

impl fmt::Display for WsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(m) => write!(f, "WebSocket I/O error: {m}"),
            Self::Protocol(m) => write!(f, "WebSocket protocol error: {m}"),
            Self::FrameTooLarge(n) => write!(f, "WebSocket frame exceeds cap ({n} bytes)"),
            Self::Closed => write!(f, "WebSocket closed"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WsMessage {
    Text(String),
    Binary(Vec<u8>),
}

/// Computes RFC 6455 `Sec-WebSocket-Accept` from `Sec-WebSocket-Key`.
fn compute_ws_accept(sec_websocket_key: &str) -> String {
    let mut input = Vec::with_capacity(sec_websocket_key.len() + WS_GUID.len());
    input.extend_from_slice(sec_websocket_key.as_bytes());
    input.extend_from_slice(WS_GUID.as_bytes());
    let sha1 = digest(&SHA1_FOR_LEGACY_USE_ONLY, &input);
    BASE64_STANDARD.encode(sha1.as_ref())
}

fn percent_encode_query_component(raw: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(raw.len());
    for &b in raw.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
    }
    out
}

fn header_has_token_ignore_case(
    headers: &http::HeaderMap,
    name: header::HeaderName,
    token: &str,
) -> bool {
    headers.get_all(name).iter().any(|val| {
        val.to_str().is_ok_and(|s| {
            s.split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(token))
        })
    })
}

/// Bounded pure-Rust RFC 6455 client framing over any `AsyncRead + AsyncWrite + Unpin` stream.
struct WsClientStream<S> {
    io: S,
    rng: SystemRandom,
    max_frame_bytes: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin> WsClientStream<S> {
    fn new(io: S, max_frame_bytes: usize) -> Self {
        Self {
            io,
            rng: SystemRandom::new(),
            max_frame_bytes,
        }
    }

    async fn send_text(&mut self, text: &str) -> Result<(), WsError> {
        self.write_masked_frame(0x1, text.as_bytes()).await
    }

    async fn send_pong(&mut self, payload: &[u8]) -> Result<(), WsError> {
        if payload.len() > 125 {
            return Err(WsError::Protocol("Pong payload exceeds 125 bytes".into()));
        }
        self.write_masked_frame(0xA, payload).await
    }

    async fn close(&mut self) {
        // Best-effort RFC 6455 Close frame (code 1000 = Normal Closure).
        let _ = self.write_masked_frame(0x8, &1000u16.to_be_bytes()).await;
        let _ = self.io.shutdown().await;
    }

    async fn write_masked_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<(), WsError> {
        if payload.len() > self.max_frame_bytes {
            return Err(WsError::FrameTooLarge(payload.len()));
        }

        let mut mask = [0u8; 4];
        self.rng
            .fill(&mut mask)
            .map_err(|_| WsError::Io("CSPRNG mask generation failed".into()))?;

        let mut frame = Vec::with_capacity(14 + payload.len());
        frame.push(0x80 | (opcode & 0x0f));
        let len = payload.len();
        if len < 126 {
            frame.push(0x80 | (len as u8));
        } else if len <= u16::MAX as usize {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(len as u64).to_be_bytes());
        }
        frame.extend_from_slice(&mask);
        for (i, &b) in payload.iter().enumerate() {
            frame.push(b ^ mask[i & 3]);
        }

        self.io
            .write_all(&frame)
            .await
            .map_err(|e| WsError::Io(e.to_string()))?;
        self.io
            .flush()
            .await
            .map_err(|e| WsError::Io(e.to_string()))?;
        Ok(())
    }

    async fn read_message(&mut self) -> Result<WsMessage, WsError> {
        let mut frag_opcode: Option<u8> = None;
        let mut frag_buf: Vec<u8> = Vec::new();

        loop {
            let mut hdr = [0u8; 2];
            self.io.read_exact(&mut hdr).await.map_err(|e| {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    WsError::Closed
                } else {
                    WsError::Io(e.to_string())
                }
            })?;

            let fin = (hdr[0] & 0x80) != 0;
            let rsv = hdr[0] & 0x70;
            let opcode = hdr[0] & 0x0f;
            let masked = (hdr[1] & 0x80) != 0;
            let len_code = hdr[1] & 0x7f;

            if rsv != 0 {
                return Err(WsError::Protocol(
                    "Non-zero RSV bits without extension".into(),
                ));
            }
            if masked {
                return Err(WsError::Protocol(
                    "RFC 6455 violation: server sent masked frame".into(),
                ));
            }

            let payload_len: usize = match len_code {
                0..=125 => len_code as usize,
                126 => {
                    let mut ext = [0u8; 2];
                    self.io
                        .read_exact(&mut ext)
                        .await
                        .map_err(|e| WsError::Io(e.to_string()))?;
                    u16::from_be_bytes(ext) as usize
                }
                127 => {
                    let mut ext = [0u8; 8];
                    self.io
                        .read_exact(&mut ext)
                        .await
                        .map_err(|e| WsError::Io(e.to_string()))?;
                    let raw_len = u64::from_be_bytes(ext);
                    if (raw_len & (1u64 << 63)) != 0 {
                        return Err(WsError::Protocol(
                            "Invalid 64-bit WebSocket length with MSB set".into(),
                        ));
                    }
                    usize::try_from(raw_len).map_err(|_| WsError::FrameTooLarge(usize::MAX))?
                }
                _ => unreachable!("7-bit mask"),
            };

            if payload_len > self.max_frame_bytes {
                return Err(WsError::FrameTooLarge(payload_len));
            }

            // Control frames (0x8..=0xF) MUST NOT be fragmented and MUST have length <= 125.
            if opcode >= 0x8 && (!fin || payload_len > 125) {
                return Err(WsError::Protocol(
                    "Invalid WebSocket control frame (fragmented or >125 bytes)".into(),
                ));
            }

            let mut payload = vec![0u8; payload_len];
            if payload_len > 0 {
                self.io
                    .read_exact(&mut payload)
                    .await
                    .map_err(|e| WsError::Io(e.to_string()))?;
            }

            match opcode {
                // Ping -> respond immediately with masked Pong echoing payload.
                0x9 => {
                    self.send_pong(&payload).await?;
                }
                // Pong -> unsolicited heartbeat; ignore.
                0xA => {}
                // Close -> echo close best-effort and signal closure.
                0x8 => {
                    let close_payload = if payload.len() >= 2 {
                        &payload[..2]
                    } else {
                        &1000u16.to_be_bytes()[..]
                    };
                    let _ = self.write_masked_frame(0x8, close_payload).await;
                    let _ = self.io.shutdown().await;
                    return Err(WsError::Closed);
                }
                // Text (0x1) or Binary (0x2)
                0x1 | 0x2 => {
                    if frag_opcode.is_some() {
                        return Err(WsError::Protocol(
                            "New data frame received before fragmented message completed".into(),
                        ));
                    }
                    if fin {
                        return decode_ws_data_message(opcode, payload);
                    }
                    frag_opcode = Some(opcode);
                    frag_buf = payload;
                }
                // Continuation (0x0)
                0x0 => {
                    let Some(active_op) = frag_opcode else {
                        return Err(WsError::Protocol(
                            "Unexpected continuation frame with no active fragmented message"
                                .into(),
                        ));
                    };
                    let total = frag_buf.len().saturating_add(payload.len());
                    if total > self.max_frame_bytes {
                        return Err(WsError::FrameTooLarge(total));
                    }
                    frag_buf.extend_from_slice(&payload);
                    if fin {
                        let assembled = std::mem::take(&mut frag_buf);
                        return decode_ws_data_message(active_op, assembled);
                    }
                }
                other => {
                    return Err(WsError::Protocol(format!(
                        "Unsupported WebSocket opcode 0x{other:x}"
                    )));
                }
            }
        }
    }
}

fn decode_ws_data_message(opcode: u8, payload: Vec<u8>) -> Result<WsMessage, WsError> {
    match opcode {
        0x1 => {
            let text = String::from_utf8(payload)
                .map_err(|_| WsError::Protocol("Invalid UTF-8 in WebSocket text frame".into()))?;
            Ok(WsMessage::Text(text))
        }
        0x2 => Ok(WsMessage::Binary(payload)),
        _ => Err(WsError::Protocol(format!(
            "Unexpected data opcode {opcode}"
        ))),
    }
}

// ============================================================================
// T3 Effect RPC Client (`websocket-ticket` + WebSocket Upgrade + Effect Exit)
// ============================================================================

#[derive(Debug, Clone)]
struct T3RpcResponse {
    ok: bool,
    value: Option<Value>,
    #[allow(dead_code)]
    error_tag: Option<String>,
    error_name: Option<String>,
    error_message: Option<String>,
}

fn parse_effect_exit(msg: &Map<String, Value>) -> T3RpcResponse {
    let exit = msg.get("exit").and_then(Value::as_object);
    if let Some(exit_obj) = exit {
        if exit_obj.get("_tag").and_then(Value::as_str) == Some("Success") {
            return T3RpcResponse {
                ok: true,
                value: exit_obj.get("value").cloned(),
                error_tag: None,
                error_name: None,
                error_message: None,
            };
        }

        if let Some(cause_val) = exit_obj.get("cause") {
            let entries: Vec<&Value> = match cause_val {
                Value::Array(arr) => arr.iter().collect(),
                Value::Object(_) => vec![cause_val],
                _ => Vec::new(),
            };
            for entry in entries {
                let Some(entry_obj) = entry.as_object() else {
                    continue;
                };
                match entry_obj.get("_tag").and_then(Value::as_str) {
                    Some("Fail") => {
                        if let Some(err_obj) = entry_obj.get("error").and_then(Value::as_object) {
                            let inner =
                                err_obj
                                    .get("cause")
                                    .and_then(Value::as_object)
                                    .and_then(|c| {
                                        c.get("cause").and_then(Value::as_object).or(Some(c))
                                    });
                            return T3RpcResponse {
                                ok: false,
                                value: None,
                                error_tag: err_obj
                                    .get("_tag")
                                    .and_then(Value::as_str)
                                    .map(str::to_string),
                                error_name: inner
                                    .and_then(|c| c.get("name"))
                                    .and_then(Value::as_str)
                                    .map(str::to_string),
                                error_message: err_obj
                                    .get("message")
                                    .and_then(Value::as_str)
                                    .map(str::to_string),
                            };
                        }
                    }
                    Some("Die") => {
                        let defect_msg = entry_obj.get("defect").map(|d| match d {
                            Value::String(s) => s.clone(),
                            other => other.to_string(),
                        });
                        return T3RpcResponse {
                            ok: false,
                            value: None,
                            error_tag: Some("Die".to_string()),
                            error_name: None,
                            error_message: defect_msg,
                        };
                    }
                    _ => {}
                }
            }
        }
    }

    T3RpcResponse {
        ok: false,
        value: None,
        error_tag: None,
        error_name: None,
        error_message: Some("Unknown T3 RPC error".to_string()),
    }
}

fn is_thread_not_found_error(res: &T3RpcResponse) -> bool {
    if res.error_name.as_deref() == Some("ProjectionStoreThreadNotFoundError") {
        return true;
    }
    if let Some(msg) = res.error_message.as_deref() {
        let lower = msg.to_ascii_lowercase();
        if lower.contains("no orchestration projection exists") {
            return true;
        }
        if let Some(idx) = lower.find("thread") {
            if lower[idx..].contains("not found") {
                return true;
            }
        }
    }
    false
}

struct T3WsRpcClient {
    ws: WsClientStream<TokioIo<hyper::upgrade::Upgraded>>,
}

impl T3WsRpcClient {
    async fn connect(origin: &str, token: &str, timeout: Duration) -> Result<Self, &'static str> {
        let deadline = Instant::now() + timeout;
        let client = build_http1_client();

        // 1. Exchange bearer token for single-use WebSocket ticket.
        let ticket_uri: Uri = format!("{origin}/api/auth/websocket-ticket")
            .parse()
            .map_err(|_| "t3_server_unreachable")?;
        let auth_header =
            HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| "t3_auth_failed")?;
        let ticket_req = Request::builder()
            .method(Method::POST)
            .uri(ticket_uri)
            .header(header::AUTHORIZATION, auth_header)
            .body(Full::new(Bytes::new()))
            .map_err(|_| "t3_server_unreachable")?;

        let ticket_resp = tokio::time::timeout_at(deadline, client.request(ticket_req))
            .await
            .map_err(|_| "t3_server_unreachable")?
            .map_err(|_| "t3_server_unreachable")?;

        let status = ticket_resp.status();
        if status == StatusCode::UNAUTHORIZED || status == StatusCode::FORBIDDEN {
            return Err("t3_auth_failed");
        }
        if !status.is_success() {
            return Err("t3_server_unreachable");
        }

        let ticket_body = tokio::time::timeout_at(
            deadline,
            read_bounded_http_body(ticket_resp.into_body(), MAX_HTTP_BODY_BYTES),
        )
        .await
        .map_err(|_| "t3_server_unreachable")?
        .map_err(|_| "t3_server_unreachable")?;

        let parsed_body: Value =
            serde_json::from_slice(&ticket_body).map_err(|_| "t3_server_unreachable")?;
        let ticket = parsed_body
            .as_object()
            .and_then(|o| o.get("ticket"))
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty())
            .ok_or("t3_auth_failed")?;

        // 2. Perform RFC 6455 WebSocket upgrade over HTTP/1.1 (TCP for http://, TLS for https://).
        let encoded_ticket = percent_encode_query_component(ticket);
        let ws_http_uri: Uri = format!(
            "{origin}/ws?wsTicket={encoded_ticket}&orchestrationProtocol={T3_ORCHESTRATION_PROTOCOL}"
        )
        .parse()
        .map_err(|_| "t3_server_unreachable")?;

        let rng = SystemRandom::new();
        let mut key_bytes = [0u8; 16];
        rng.fill(&mut key_bytes)
            .map_err(|_| "t3_server_unreachable")?;
        let ws_key = BASE64_STANDARD.encode(key_bytes);
        let expected_accept = compute_ws_accept(&ws_key);

        let ws_req = Request::builder()
            .method(Method::GET)
            .version(Version::HTTP_11)
            .uri(ws_http_uri)
            .header(header::CONNECTION, "Upgrade")
            .header(header::UPGRADE, "websocket")
            .header("sec-websocket-version", "13")
            .header("sec-websocket-key", ws_key)
            .body(Full::new(Bytes::new()))
            .map_err(|_| "t3_server_unreachable")?;

        let ws_resp = tokio::time::timeout_at(deadline, client.request(ws_req))
            .await
            .map_err(|_| "t3_server_unreachable")?
            .map_err(|_| "t3_server_unreachable")?;

        if ws_resp.status() != StatusCode::SWITCHING_PROTOCOLS {
            return Err("t3_server_unreachable");
        }
        if !header_has_token_ignore_case(ws_resp.headers(), header::UPGRADE, "websocket")
            || !header_has_token_ignore_case(ws_resp.headers(), header::CONNECTION, "upgrade")
        {
            return Err("t3_server_unreachable");
        }
        let actual_accept = ws_resp
            .headers()
            .get("sec-websocket-accept")
            .and_then(|v| v.to_str().ok())
            .map(str::trim);
        if actual_accept != Some(expected_accept.as_str()) {
            return Err("t3_server_unreachable");
        }

        let upgraded = tokio::time::timeout_at(deadline, hyper::upgrade::on(ws_resp))
            .await
            .map_err(|_| "t3_server_unreachable")?
            .map_err(|_| "t3_server_unreachable")?;

        Ok(Self {
            ws: WsClientStream::new(TokioIo::new(upgraded), MAX_WS_FRAME_BYTES),
        })
    }

    async fn request(
        &mut self,
        tag: &str,
        payload: Value,
        timeout: Duration,
    ) -> Result<T3RpcResponse, WsError> {
        let deadline = Instant::now() + timeout;
        let id = uuid_v4();
        let frame = json!({
            "_tag": "Request",
            "id": id,
            "tag": tag,
            "payload": payload,
            "headers": [],
        });
        let encoded = serde_json::to_string(&frame)
            .map_err(|e| WsError::Protocol(format!("JSON serialize error: {e}")))?;

        tokio::time::timeout_at(deadline, self.ws.send_text(&encoded))
            .await
            .map_err(|_| WsError::Io(format!("T3 RPC {tag} write timed out")))??;

        loop {
            let msg = tokio::time::timeout_at(deadline, self.ws.read_message())
                .await
                .map_err(|_| WsError::Io(format!("T3 RPC {tag} timed out")))??;

            let WsMessage::Text(raw) = msg else {
                continue;
            };
            let Ok(parsed) = serde_json::from_str::<Value>(&raw) else {
                continue;
            };
            let Some(obj) = parsed.as_object() else {
                continue;
            };
            if obj.get("_tag").and_then(Value::as_str) != Some("Exit") {
                continue;
            }
            if obj.get("requestId").and_then(Value::as_str) != Some(id.as_str()) {
                continue;
            }
            return Ok(parse_effect_exit(obj));
        }
    }

    async fn close(mut self) {
        self.ws.close().await;
    }
}

// ============================================================================
// `T3Transport` + `PushTransport` Implementation
// ============================================================================

/// Native T3 Code push wakeup transport implementing [`PushTransport`].
#[derive(Debug, Clone)]
pub struct T3Transport {
    target: T3Target,
    connect_timeout: Duration,
    projection_timeout: Duration,
    dispatch_timeout: Duration,
    allow_remote: bool,
}

impl T3Transport {
    /// Creates a `T3Transport` with default timeouts (8s connect, 12s projection, 15s dispatch)
    /// and loopback-only origin enforcement (`allow_remote = false`).
    pub fn new(target: T3Target) -> Self {
        Self {
            target,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            projection_timeout: DEFAULT_PROJECTION_TIMEOUT,
            dispatch_timeout: DEFAULT_DISPATCH_TIMEOUT,
            allow_remote: false,
        }
    }

    /// Creates a `T3Transport` with explicit RPC timeouts and loopback-only origin enforcement.
    pub fn with_timeouts(
        target: T3Target,
        connect_timeout: Duration,
        projection_timeout: Duration,
        dispatch_timeout: Duration,
    ) -> Self {
        Self {
            target,
            connect_timeout,
            projection_timeout,
            dispatch_timeout,
            allow_remote: false,
        }
    }

    /// Explicitly opts into remote `https://` T3 server origins (default `false`: loopback-only).
    pub fn with_allow_remote(mut self, allow_remote: bool) -> Self {
        self.allow_remote = allow_remote;
        self
    }

    /// Returns the bound [`T3Target`].
    pub fn target(&self) -> &T3Target {
        &self.target
    }

    /// Executes the full T3 orchestration v2 delivery flow (`getThreadProjection` +
    /// `dispatchCommand` `message.dispatch`), returning both the [`PushOutcome`] and
    /// detailed dispatch mode / interrupt metadata.
    pub async fn deliver_detailed(&self, digest: &InboxDigest, mode: PushMode) -> T3DeliveryDetail {
        let origin =
            match normalize_t3_server_url_with_remote(&self.target.server_url, self.allow_remote) {
                Ok(o) => o,
                Err(_) => {
                    return T3DeliveryDetail {
                        outcome: PushOutcome::reject("t3_invalid_server_url"),
                        interrupted: false,
                        dispatch_mode: None,
                    };
                }
            };

        let Some(token) = resolve_bearer_token(&self.target) else {
            return T3DeliveryDetail {
                outcome: PushOutcome::hold("t3_auth_missing"),
                interrupted: false,
                dispatch_mode: None,
            };
        };

        let mut client = match T3WsRpcClient::connect(&origin, &token, self.connect_timeout).await {
            Ok(c) => c,
            Err(reason) => {
                return T3DeliveryDetail {
                    outcome: PushOutcome::hold(reason),
                    interrupted: false,
                    dispatch_mode: None,
                };
            }
        };

        let detail = self
            .execute_rpc_delivery(&mut client, digest.as_str(), mode)
            .await;
        client.close().await;
        detail
    }

    async fn execute_rpc_delivery(
        &self,
        client: &mut T3WsRpcClient,
        text: &str,
        mode: PushMode,
    ) -> T3DeliveryDetail {
        let projection_res = match client
            .request(
                "orchestration.getThreadProjection",
                json!({ "threadId": self.target.thread_id }),
                self.projection_timeout,
            )
            .await
        {
            Ok(res) => res,
            Err(_) => {
                return T3DeliveryDetail {
                    outcome: PushOutcome::hold("t3_server_unreachable"),
                    interrupted: false,
                    dispatch_mode: None,
                };
            }
        };

        if !projection_res.ok {
            let outcome = if is_thread_not_found_error(&projection_res) {
                PushOutcome::reject("t3_thread_not_found")
            } else {
                PushOutcome::hold("t3_projection_unavailable")
            };
            return T3DeliveryDetail {
                outcome,
                interrupted: false,
                dispatch_mode: None,
            };
        }

        let empty_obj = Map::new();
        let projection = projection_res
            .value
            .as_ref()
            .and_then(Value::as_object)
            .unwrap_or(&empty_obj);

        if let Some(thread) = projection.get("thread").and_then(Value::as_object) {
            if thread.get("deletedAt").is_some_and(is_timestamp_field_set) {
                return T3DeliveryDetail {
                    outcome: PushOutcome::reject("t3_thread_deleted"),
                    interrupted: false,
                    dispatch_mode: None,
                };
            }
            if thread.get("archivedAt").is_some_and(is_timestamp_field_set) {
                return T3DeliveryDetail {
                    outcome: PushOutcome::reject("t3_thread_archived"),
                    interrupted: false,
                    dispatch_mode: None,
                };
            }
        }

        let (dispatch_mode, interrupted) = select_dispatch_mode(projection, mode);

        let dispatch_payload = json!({
            "type": "message.dispatch",
            "commandId": uuid_v4(),
            "createdBy": "system",
            "creationSource": "mcp",
            "threadId": self.target.thread_id,
            "messageId": uuid_v4(),
            "text": text,
            "attachments": [],
            "dispatchMode": dispatch_mode.to_json(),
        });

        let dispatch_res = match client
            .request(
                "orchestration.dispatchCommand",
                dispatch_payload,
                self.dispatch_timeout,
            )
            .await
        {
            Ok(res) => res,
            Err(_) => {
                return T3DeliveryDetail {
                    outcome: PushOutcome::hold("t3_server_unreachable"),
                    interrupted: false,
                    dispatch_mode: Some(dispatch_mode),
                };
            }
        };

        if dispatch_res.ok {
            return T3DeliveryDetail {
                outcome: PushOutcome::Delivered,
                interrupted,
                dispatch_mode: Some(dispatch_mode),
            };
        }

        let outcome = if is_thread_not_found_error(&dispatch_res) {
            PushOutcome::reject("t3_thread_not_found")
        } else {
            PushOutcome::reject("t3_dispatch_failed")
        };

        T3DeliveryDetail {
            outcome,
            interrupted: false,
            dispatch_mode: Some(dispatch_mode),
        }
    }
}

fn is_timestamp_field_set(val: &Value) -> bool {
    match val {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::String(s) => !s.trim().is_empty(),
        _ => true,
    }
}

fn select_dispatch_mode(projection: &Map<String, Value>, mode: PushMode) -> (T3DispatchMode, bool) {
    let active_run = projection
        .get("runs")
        .and_then(Value::as_array)
        .and_then(|runs| {
            runs.iter().rev().find_map(|entry| {
                let obj = entry.as_object()?;
                let status = obj.get("status").and_then(Value::as_str)?;
                let id = obj.get("id").and_then(Value::as_str)?;
                if matches!(status, "preparing" | "starting" | "running" | "waiting") {
                    Some((id, obj))
                } else {
                    None
                }
            })
        });

    let Some((active_run_id, active_run_obj)) = active_run else {
        return (T3DispatchMode::StartImmediately, false);
    };

    if mode == PushMode::Queue {
        return (T3DispatchMode::QueueAfterActive, false);
    }

    let supports_active_steering = active_run_obj
        .get("providerThreadId")
        .and_then(Value::as_str)
        .and_then(|pt_id| {
            let p_threads = projection.get("providerThreads")?.as_array()?;
            let pt = p_threads
                .iter()
                .filter_map(Value::as_object)
                .find(|t| t.get("id").and_then(Value::as_str) == Some(pt_id))?;
            let ps_id = pt.get("providerSessionId").and_then(Value::as_str)?;
            let p_sessions = projection.get("providerSessions")?.as_array()?;
            let ps = p_sessions
                .iter()
                .filter_map(Value::as_object)
                .find(|s| s.get("id").and_then(Value::as_str) == Some(ps_id))?;
            ps.get("capabilities")?
                .as_object()?
                .get("turns")?
                .as_object()?
                .get("supportsActiveSteering")?
                .as_bool()
        })
        .unwrap_or(false);

    if supports_active_steering {
        (
            T3DispatchMode::SteerActive {
                target_run_id: active_run_id.to_string(),
            },
            true,
        )
    } else {
        (
            T3DispatchMode::RestartActive {
                target_run_id: active_run_id.to_string(),
            },
            true,
        )
    }
}

impl PushTransport for T3Transport {
    fn kind(&self) -> &'static str {
        "t3"
    }

    fn supports_interrupt(&self) -> bool {
        true
    }

    fn target_metadata(&self) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "t3ThreadId".to_string(),
            serde_json::json!(self.target.thread_id),
        );
        obj.insert(
            "t3Url".to_string(),
            serde_json::json!(self.target.server_url),
        );
        if let Some(ref base_dir) = self.target.base_dir {
            if !base_dir.as_os_str().is_empty() {
                obj.insert(
                    "t3BaseDir".to_string(),
                    serde_json::json!(base_dir.to_string_lossy().as_ref()),
                );
            }
        }
        Value::Object(obj)
    }

    fn deliver<'a>(
        &'a self,
        digest: &'a InboxDigest,
        mode: PushMode,
    ) -> TransportFuture<'a, PushOutcome> {
        Box::pin(async move { self.deliver_detailed(digest, mode).await.outcome })
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_url_accepts_https_and_loopback_http_and_rejects_insecure_or_dirty_urls() {
        // Valid loopback HTTP + HTTPS origins
        assert_eq!(
            normalize_t3_server_url("http://127.0.0.1:3773").unwrap(),
            "http://127.0.0.1:3773"
        );
        assert_eq!(
            normalize_t3_server_url("http://127.0.0.1:3773/").unwrap(),
            "http://127.0.0.1:3773"
        );
        assert_eq!(
            normalize_t3_server_url("http://127.0.0.1:80").unwrap(),
            "http://127.0.0.1"
        );
        assert_eq!(
            normalize_t3_server_url("http://LOCALHOST:3773/").unwrap(),
            "http://localhost:3773"
        );
        assert_eq!(
            normalize_t3_server_url("http://[::1]:3773").unwrap(),
            "http://[::1]:3773"
        );
        assert_eq!(
            normalize_t3_server_url("http://[::1]:3773/").unwrap(),
            "http://[::1]:3773"
        );
        assert_eq!(
            normalize_t3_server_url("https://t3.example.com").unwrap(),
            "https://t3.example.com"
        );
        assert_eq!(
            normalize_t3_server_url("https://T3.Example.TS.Net:443/").unwrap(),
            "https://t3.example.ts.net"
        );
        assert_eq!(
            normalize_t3_server_url("https://t3.example.com:8443").unwrap(),
            "https://t3.example.com:8443"
        );

        // Rejected: non-loopback HTTP, wrong schemes, userinfo, non-root paths, query, fragment, dirty chars
        for bad in [
            "",
            "not-a-url",
            "ws://127.0.0.1:3773",
            "wss://t3.example.com",
            "http://10.0.0.1:3773",
            "http://192.168.1.50:3773",
            "http://0.0.0.0:3773",
            "http://127.0.0.2:3773",
            "http://example.com",
            "http://localhost.evil.com:3773",
            "http://[2001:db8::1]:3773",
            "https://u:p@example.com",
            "https://user@example.com",
            "http://user:pass@127.0.0.1:3773",
            "https://t3.example.com/api",
            "http://127.0.0.1:3773/ws",
            "http://127.0.0.1:3773//",
            "https://t3.example.com?foo=bar",
            "http://127.0.0.1:3773?",
            "https://t3.example.com#section",
            "http://127.0.0.1:3773/#frag",
            "http://localhost\\@evil.com",
            "https://t3.example.com:0",
            "https://t3.example.com:70000",
            "https://t3.example.com:",
            "http://127.0.0.1:3773\r\nX: 1",
        ] {
            assert!(
                normalize_t3_server_url(bad).is_err(),
                "expected URL to be rejected: {bad:?}"
            );
        }
    }

    #[test]
    fn rfc6455_accept_vector_matches_spec_example() {
        // RFC 6455 §1.3 canonical test vector
        assert_eq!(
            compute_ws_accept("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn target_debug_redacts_token_override() {
        let mut target = T3Target::new("thr-1", DEFAULT_T3_URL);
        target.token_override = Some("super-secret-t3-token-12345".into());
        let dbg = format!("{target:?}");
        assert!(!dbg.contains("super-secret-t3-token-12345"));
        assert!(dbg.contains("[REDACTED]"));
    }

    #[test]
    fn parse_effect_exit_handles_success_fail_and_die() {
        let ok_msg = json!({
            "_tag": "Exit",
            "requestId": "req-1",
            "exit": { "_tag": "Success", "value": { "sequence": 7 } }
        });
        let ok = parse_effect_exit(ok_msg.as_object().unwrap());
        assert!(ok.ok);
        assert_eq!(ok.value, Some(json!({ "sequence": 7 })));

        let not_found = json!({
            "_tag": "Exit",
            "requestId": "req-2",
            "exit": {
                "_tag": "Failure",
                "cause": [{
                    "_tag": "Fail",
                    "error": {
                        "_tag": "OrchestrationV2GetThreadProjectionError",
                        "message": "No orchestration projection exists for thread thr-missing.",
                        "cause": { "cause": { "name": "ProjectionStoreThreadNotFoundError" } }
                    }
                }]
            }
        });
        let nf = parse_effect_exit(not_found.as_object().unwrap());
        assert!(!nf.ok);
        assert_eq!(
            nf.error_name.as_deref(),
            Some("ProjectionStoreThreadNotFoundError")
        );
        assert!(is_thread_not_found_error(&nf));

        let die = json!({
            "_tag": "Exit",
            "requestId": "req-3",
            "exit": {
                "_tag": "Failure",
                "cause": [{ "_tag": "Die", "defect": "unexpected boom" }]
            }
        });
        let d = parse_effect_exit(die.as_object().unwrap());
        assert!(!d.ok);
        assert_eq!(d.error_tag.as_deref(), Some("Die"));
        assert_eq!(d.error_message.as_deref(), Some("unexpected boom"));
        assert!(!is_thread_not_found_error(&d));
    }

    #[tokio::test]
    async fn ws_client_framing_handles_7bit_16bit_64bit_fragmentation_ping_pong_and_cap() {
        let (client_io, mut server_io) = tokio::io::duplex(256 * 1024);

        // Spawn peer verifying client masking across 7-bit, 16-bit, and >65535 (64-bit) frames,
        // then sending fragmented text with an interleaved Ping frame, then an oversized frame header.
        let server_task = tokio::spawn(async move {
            async fn read_client_masked_frame(io: &mut tokio::io::DuplexStream) -> (u8, Vec<u8>) {
                let mut hdr = [0u8; 2];
                io.read_exact(&mut hdr).await.unwrap();
                let opcode = hdr[0] & 0x0f;
                assert_ne!(hdr[1] & 0x80, 0, "client frame MUST be masked");
                let len_code = hdr[1] & 0x7f;
                let len: usize = match len_code {
                    0..=125 => len_code as usize,
                    126 => {
                        let mut b = [0u8; 2];
                        io.read_exact(&mut b).await.unwrap();
                        u16::from_be_bytes(b) as usize
                    }
                    127 => {
                        let mut b = [0u8; 8];
                        io.read_exact(&mut b).await.unwrap();
                        u64::from_be_bytes(b) as usize
                    }
                    _ => unreachable!(),
                };
                let mut mask = [0u8; 4];
                io.read_exact(&mut mask).await.unwrap();
                let mut data = vec![0u8; len];
                io.read_exact(&mut data).await.unwrap();
                for (i, byte) in data.iter_mut().enumerate() {
                    *byte ^= mask[i & 3];
                }
                (opcode, data)
            }

            // 1. 7-bit payload (< 126)
            let (op1, p1) = read_client_masked_frame(&mut server_io).await;
            assert_eq!(op1, 0x1);
            assert_eq!(p1, b"small");

            // 2. 16-bit payload (1000 bytes)
            let (op2, p2) = read_client_masked_frame(&mut server_io).await;
            assert_eq!(op2, 0x1);
            assert_eq!(p2.len(), 1000);

            // 3. 64-bit payload (70000 bytes)
            let (op3, p3) = read_client_masked_frame(&mut server_io).await;
            assert_eq!(op3, 0x1);
            assert_eq!(p3.len(), 70_000);

            // 4. Send fragmented text frame + interleaved Ping + continuation final frame
            server_io.write_all(&[0x01, 5]).await.unwrap();
            server_io.write_all(b"hello").await.unwrap();
            // Interleaved Ping ("ping!")
            server_io.write_all(&[0x89, 5]).await.unwrap();
            server_io.write_all(b"ping!").await.unwrap();
            // Final continuation (" world")
            server_io.write_all(&[0x80, 6]).await.unwrap();
            server_io.write_all(b" world").await.unwrap();
            server_io.flush().await.unwrap();

            // Client must reply with masked Pong echoing "ping!"
            let (pong_op, pong_payload) = read_client_masked_frame(&mut server_io).await;
            assert_eq!(pong_op, 0xA);
            assert_eq!(pong_payload, b"ping!");

            // 5. Send a frame claiming > MAX_WS_FRAME_BYTES (3 MiB) in 64-bit header -> client must fail closed
            let huge: u64 = (MAX_WS_FRAME_BYTES as u64) + 1024;
            let mut huge_hdr = [0u8; 10];
            huge_hdr[0] = 0x81;
            huge_hdr[1] = 127;
            huge_hdr[2..10].copy_from_slice(&huge.to_be_bytes());
            server_io.write_all(&huge_hdr).await.unwrap();
            server_io.flush().await.unwrap();
        });

        let mut ws = WsClientStream::new(client_io, MAX_WS_FRAME_BYTES);
        ws.send_text("small").await.unwrap();
        ws.send_text(&"a".repeat(1000)).await.unwrap();
        ws.send_text(&"b".repeat(70_000)).await.unwrap();

        let reassembled = ws.read_message().await.unwrap();
        assert_eq!(reassembled, WsMessage::Text("hello world".into()));

        let err = ws.read_message().await.unwrap_err();
        assert!(matches!(err, WsError::FrameTooLarge(_)));

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn token_secret_lockdown_and_loopback_default_block_exfiltration() {
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::new(dir.path(), SecretBackend::File);
        store.set("t3-auth-token", "auth-ok").unwrap();
        store.set("t3-session-token", "session-ok").unwrap();
        store
            .set("node-sign-priv", "SENSITIVE_PRIVATE_KEY")
            .unwrap();

        assert!(is_allowed_t3_token_secret("t3-auth-token"));
        assert!(is_allowed_t3_token_secret("t3-session-token"));
        assert!(!is_allowed_t3_token_secret("node-sign-priv"));
        assert!(!is_allowed_t3_token_secret("custom-secret"));

        let mut ok_t = T3Target::new("thr-1", DEFAULT_T3_URL);
        ok_t.state_dir = Some(dir.path().to_path_buf());
        ok_t.secret_backend = Some(SecretBackend::File);
        ok_t.token_secret = Some("t3-session-token".into());
        assert_eq!(resolve_bearer_token(&ok_t).as_deref(), Some("session-ok"));

        let mut exfil_t = ok_t.clone();
        exfil_t.token_secret = Some("node-sign-priv".into());
        assert_eq!(
            resolve_bearer_token(&exfil_t),
            None,
            "arbitrary tokenSecret MUST fail closed and never read unrelated secrets"
        );

        // Loopback-only enforced by default on probe & T3Transport!
        assert!(normalize_t3_server_url_with_remote("https://evil.example.com", false).is_err());
        assert!(normalize_t3_server_url_with_remote("http://127.0.0.1:3773", false).is_ok());
        assert!(normalize_t3_server_url_with_remote("https://127.0.0.1:3773", false).is_ok());

        let remote_probe = probe_t3_server(
            "https://evil.example.com",
            Some("auth-ok"),
            Duration::from_millis(200),
        )
        .await;
        assert!(!remote_probe.ok);

        let mut remote_target = T3Target::new("thr-1", "https://evil.example.com");
        remote_target.token_override = Some("auth-ok".into());
        let outcome = T3Transport::new(remote_target)
            .deliver(&crate::transport::test_digest(), PushMode::Queue)
            .await;
        assert_eq!(outcome, PushOutcome::reject("t3_invalid_server_url"));
    }
}
