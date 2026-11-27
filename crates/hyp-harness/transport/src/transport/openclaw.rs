//! Native OpenClaw Gateway webhook push transport (`POST /hooks/wake` default, or opt-in
//! `POST /hooks/agent`).
//!
//! Security & reliability invariants:
//! - Strict origin validation ([`normalize_openclaw_base_url`]): loopback `http://`
//!   (`127.0.0.1`, `localhost`, `[::1]`) or `https://` only — rejects non-loopback `http://`,
//!   credentials/userinfo, query strings, fragments, and control characters fail-closed.
//! - Exact session targeting: defaults to `POST /hooks/wake` (`{ text, mode: "now", agentId,
//!   sessionKey? }`) so OpenClaw wakes the exact registered interactive session directly instead
//!   of spawning an isolated cron job (`POST /hooks/agent`). Validates `sessionKey` fail-closed.
//! - Zero-leak bearer authentication: hook token is read strictly from [`SecretStore`]
//!   (default secret name `"openclaw-hooks-token"`), sent solely via `Authorization: Bearer <token>`,
//!   NEVER logged, persisted in plaintext config, or placed in URL query parameters.
//! - Fail-closed probe ([`probe_openclaw_gateway`]): requires a non-empty secret token AND a
//!   reachable gateway `/hooks/*` endpoint before attaching, so OpenClaw sessions without hooks
//!   configured never falsely claim `hasLiveTransport == true`.
//! - Strictly metadata-only wake nudge: NEVER forwards raw untrusted mesh message bodies into
//!   OpenClaw's prompt! Instead sends a minimal count/handle nudge telling the gateway agent to
//!   call `hyp_inbox`, while `LocalDaemon` keeps the unread items intact in SQLite.
//! - Deterministic HTTP status mapping:
//!   - `200`/`202`/`204` -> [`PushOutcome::Delivered`]
//!   - `429` -> [`PushOutcome::Hold`] (`"openclaw_rate_limited"`, retryable)
//!   - `5xx` / connection refused / timeout -> [`PushOutcome::Hold`] (`"openclaw_gateway_unavailable"`, retryable)
//!   - `401`/`403` -> [`PushOutcome::Reject`] (`"openclaw_auth_failed"`, terminal — daemon detaches)
//!   - `404` -> [`PushOutcome::Reject`] (`"openclaw_hooks_disabled"`, terminal — daemon detaches)

use hyp_harness_ipc::paths::transport_config_dir as default_hyphae_config_dir;
use hyp_node::engine::http_util::{
    build_unpooled_http1_client as build_http1_client, consume_bounded_body,
};
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderName, HeaderValue, Method, Request, StatusCode, Uri, header};
use http_body_util::Full;
use hyp_crypto::{SecretBackend, SecretStore};
use hyp_store::uuid_v4;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::transport::{InboxDigest, PushMode, PushOutcome, PushTransport, TransportFuture};

/// Default loopback OpenClaw Gateway base URL.
pub const DEFAULT_OPENCLAW_URL: &str = "http://127.0.0.1:18789";
/// Default OpenClaw Gateway hooks path prefix.
pub const DEFAULT_OPENCLAW_HOOKS_PATH: &str = "/hooks";
/// Default OpenClaw target agent identifier for `/hooks/wake` and `/hooks/agent`.
pub const DEFAULT_OPENCLAW_AGENT_ID: &str = "main";
/// Default `SecretStore` key name holding the OpenClaw Gateway hooks bearer token.
pub const DEFAULT_OPENCLAW_TOKEN_SECRET: &str = "openclaw-hooks-token";

/// Default timeout for [`probe_openclaw_gateway`].
pub const DEFAULT_OPENCLAW_PROBE_TIMEOUT: Duration = Duration::from_millis(2_500);
/// Default timeout for a single OpenClaw webhook `POST` delivery.
pub const DEFAULT_OPENCLAW_DELIVER_TIMEOUT: Duration = Duration::from_secs(10);

/// Hard cap (256 KiB) when draining HTTP response bodies from OpenClaw Gateway.
const MAX_OPENCLAW_HTTP_BODY_BYTES: usize = 256 * 1024;
/// Maximum allowed length for `hooks_path`.
const MAX_HOOKS_PATH_LEN: usize = 256;

/// Reject reason when the configured OpenClaw hooks secret is missing or empty.
pub const REASON_OPENCLAW_TOKEN_MISSING: &str = "openclaw_token_missing";
/// Reject reason when the configured OpenClaw base URL or hooks path fails validation.
pub const REASON_OPENCLAW_INVALID_URL: &str = "openclaw_invalid_url";
/// Reject reason when the target OpenClaw `sessionKey` fails fail-closed validation.
pub const REASON_OPENCLAW_INVALID_SESSION_KEY: &str = "openclaw_invalid_session_key";
/// Terminal reject reason when the target OpenClaw session does not exist (`createIfMissing: false`).
pub const REASON_OPENCLAW_SESSION_MISSING: &str = "openclaw_session_missing";
/// Terminal reject reason on HTTP `401` / `403` (daemon detaches transport).
pub const REASON_OPENCLAW_AUTH_FAILED: &str = "openclaw_auth_failed";
/// Terminal reject reason on HTTP `404` (hooks disabled on gateway; daemon detaches transport).
pub const REASON_OPENCLAW_HOOKS_DISABLED: &str = "openclaw_hooks_disabled";
/// Retryable hold reason on HTTP `5xx`, connection refused, or network timeout.
pub const REASON_OPENCLAW_GATEWAY_UNAVAILABLE: &str = "openclaw_gateway_unavailable";
/// Retryable hold reason on HTTP `429 Too Many Requests`.
pub const REASON_OPENCLAW_RATE_LIMITED: &str = "openclaw_rate_limited";
/// Reject reason on unexpected non-auth 4xx responses.
pub const REASON_OPENCLAW_REQUEST_REJECTED: &str = "openclaw_request_rejected";

const INVALID_URL_ERR: &str = "OpenClaw Gateway URL must be a loopback origin (e.g. http://127.0.0.1:18789) unless allowRemote=true with https://";
const INVALID_HOOKS_PATH_ERR: &str = "OpenClaw hooks path must start with '/' and contain no traversal, query, or control characters";

/// Returns `true` iff `name` is the sole allowed OpenClaw Gateway hooks secret name
/// (`"openclaw-hooks-token"`). Arbitrary `tokenSecret` names from config MUST fail closed
/// so a config writer can never exfiltrate other Keychain/SecretStore entries.
pub fn is_allowed_openclaw_token_secret(name: &str) -> bool {
    name.trim() == DEFAULT_OPENCLAW_TOKEN_SECRET
}

use hyp_harness_ipc::hints::MAX_OPENCLAW_AGENT_ID_LEN;
pub use hyp_harness_ipc::hints::{
    canonical_openclaw_session_id, parse_openclaw_agent_id_from_session_key,
    validate_openclaw_session_key,
};

/// OpenClaw Gateway webhook endpoint mode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OpenClawEndpointMode {
    /// `POST <base><hooks_path>/wake` with `{ text, mode: "now", agentId, sessionKey? }`.
    /// Default mode: wakes the exact existing OpenClaw session directly without spawning an
    /// isolated cron job.
    #[default]
    Wake,
    /// Explicit legacy opt-in: `POST <base><hooks_path>/agent` with
    /// `{ message, name, agentId, wakeMode, deliver, sessionKey? }` (runs via isolated cron runner).
    Agent,
}

impl OpenClawEndpointMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Wake => "wake",
        }
    }
}

impl FromStr for OpenClawEndpointMode {
    type Err = String;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "agent" => Ok(Self::Agent),
            "wake" => Ok(Self::Wake),
            other => Err(format!(
                "Invalid OpenClaw endpoint mode '{other}' (expected 'agent' or 'wake')"
            )),
        }
    }
}

/// Target configuration for an OpenClaw Gateway push transport.
#[derive(Clone, PartialEq, Eq)]
pub struct OpenClawTarget {
    /// OpenClaw Gateway origin (default `http://127.0.0.1:18789`; must pass [`normalize_openclaw_base_url`]).
    pub base_url: String,
    /// Gateway hooks mount prefix (default `"/hooks"`).
    pub hooks_path: String,
    /// Endpoint mode (`"wake"` default -> `/hooks/wake`, or explicit opt-in `"agent"` -> `/hooks/agent`).
    pub endpoint_mode: OpenClawEndpointMode,
    /// Target OpenClaw agent ID sent in `/hooks/wake` and `/hooks/agent` payloads (default `"main"`).
    pub agent_id: String,
    /// Optional exact OpenClaw `sessionKey` (e.g. `"agent:main:explicit:thread-2"`) so wakeups
    /// target ONLY the registered interactive session and never cross sessions.
    pub session_key: Option<String>,
    /// Optional Hyphae handle used in the metadata-only wake nudge (`@<handle>`).
    pub handle: Option<String>,
    /// Optional `SecretStore` key name (locked strictly to [`DEFAULT_OPENCLAW_TOKEN_SECRET`]).
    pub token_secret: Option<String>,
    /// Explicitly allow non-loopback `https://` gateway origins (default `false`: loopback-only).
    pub allow_remote: bool,
    /// Optional Hyphae state/config directory used to open [`SecretStore`].
    pub state_dir: Option<PathBuf>,
    /// Optional explicit [`SecretBackend`] override (e.g. `SecretBackend::File` in tests).
    pub secret_backend: Option<SecretBackend>,
    /// Optional direct bearer token override (programmatic/test helper; redacted in `Debug`
    /// and never persisted to disk).
    pub token_override: Option<String>,
}

impl Default for OpenClawTarget {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenClawTarget {
    /// Creates a target with OpenClaw Gateway loopback defaults (`http://127.0.0.1:18789`,
    /// `/hooks`, mode `wake`, agentId `"main"`, secret `"openclaw-hooks-token"`).
    pub fn new() -> Self {
        Self {
            base_url: DEFAULT_OPENCLAW_URL.to_string(),
            hooks_path: DEFAULT_OPENCLAW_HOOKS_PATH.to_string(),
            endpoint_mode: OpenClawEndpointMode::Wake,
            agent_id: DEFAULT_OPENCLAW_AGENT_ID.to_string(),
            session_key: None,
            handle: None,
            token_secret: None,
            allow_remote: false,
            state_dir: None,
            secret_backend: None,
            token_override: None,
        }
    }

    pub fn with_base_url(mut self, base_url: impl Into<String>) -> Self {
        self.base_url = base_url.into();
        self
    }

    pub fn with_hooks_path(mut self, hooks_path: impl Into<String>) -> Self {
        self.hooks_path = hooks_path.into();
        self
    }

    pub fn with_endpoint_mode(mut self, endpoint_mode: OpenClawEndpointMode) -> Self {
        self.endpoint_mode = endpoint_mode;
        self
    }

    pub fn with_agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.agent_id = agent_id.into();
        self
    }

    pub fn with_session_key(mut self, session_key: impl Into<String>) -> Self {
        self.session_key = Some(session_key.into());
        self
    }

    pub fn with_handle(mut self, handle: impl Into<String>) -> Self {
        self.handle = Some(handle.into());
        self
    }

    pub fn with_token_secret(mut self, secret_name: impl Into<String>) -> Self {
        self.token_secret = Some(secret_name.into());
        self
    }

    pub fn with_allow_remote(mut self, allow_remote: bool) -> Self {
        self.allow_remote = allow_remote;
        self
    }

    pub fn with_state_dir(mut self, state_dir: impl Into<PathBuf>) -> Self {
        self.state_dir = Some(state_dir.into());
        self
    }

    pub fn with_secret_backend(mut self, backend: SecretBackend) -> Self {
        self.secret_backend = Some(backend);
        self
    }

    pub fn with_token_override(mut self, token: impl Into<String>) -> Self {
        self.token_override = Some(token.into());
        self
    }

    /// Resolves the validated full endpoint URI (`<origin><hooks_path>/<mode>`).
    pub fn endpoint_url(&self) -> Result<String, String> {
        let origin = normalize_openclaw_base_url_with_remote(&self.base_url, self.allow_remote)?;
        let hooks_path = normalize_openclaw_hooks_path(&self.hooks_path)?;
        Ok(format!(
            "{origin}{hooks_path}/{}",
            self.endpoint_mode.as_str()
        ))
    }
}

impl fmt::Debug for OpenClawTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenClawTarget")
            .field("base_url", &self.base_url)
            .field("hooks_path", &self.hooks_path)
            .field("endpoint_mode", &self.endpoint_mode)
            .field("agent_id", &self.agent_id)
            .field("session_key", &self.session_key)
            .field("handle", &self.handle)
            .field("token_secret", &self.token_secret)
            .field("allow_remote", &self.allow_remote)
            .field("state_dir", &self.state_dir)
            .field("secret_backend", &self.secret_backend)
            .field(
                "token_override",
                &self.token_override.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

/// Optional `"openclaw"` configuration block parsed from `node.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenClawNodeConfig {
    pub enabled: bool,
    pub delivery_mode: Option<String>,
    pub url: Option<String>,
    pub hooks_path: Option<String>,
    pub agent_id: Option<String>,
    pub mode: Option<OpenClawEndpointMode>,
    pub token_secret: Option<String>,
    pub allow_remote: bool,
}

impl Default for OpenClawNodeConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            delivery_mode: None,
            url: None,
            hooks_path: None,
            agent_id: None,
            mode: None,
            token_secret: None,
            allow_remote: false,
        }
    }
}

impl OpenClawNodeConfig {
    /// Applies transport defaults to the optional OpenClaw block from node.json.
    pub fn from_node_file(config: hyp_node::node_file::OpenClawFile) -> Self {
        Self {
            enabled: config.enabled.unwrap_or(true),
            delivery_mode: config.delivery_mode,
            url: config.url,
            hooks_path: config.hooks_path,
            agent_id: config.agent_id,
            mode: config.mode.and_then(|mode| mode.parse().ok()),
            token_secret: config.token_secret,
            allow_remote: config.allow_remote.unwrap_or(false),
        }
    }

    /// Returns `true` when OpenClaw Gateway webhook push wakeups are enabled (`enabled != false`
    /// and `deliveryMode != "inbox"`).
    pub fn gateway_push_enabled(&self) -> bool {
        self.enabled
            && !self
                .delivery_mode
                .as_deref()
                .is_some_and(|m| m.eq_ignore_ascii_case("inbox"))
    }

    /// Converts this config into an [`OpenClawTarget`] with defaults applied.
    pub fn to_target(&self) -> OpenClawTarget {
        let mut target = OpenClawTarget::new();
        if let Some(ref url) = self.url {
            target.base_url = url.clone();
        }
        if let Some(ref path) = self.hooks_path {
            target.hooks_path = path.clone();
        }
        if let Some(ref agent_id) = self.agent_id {
            target.agent_id = agent_id.clone();
        }
        if let Some(mode) = self.mode {
            target.endpoint_mode = mode;
        }
        if let Some(ref secret) = self.token_secret {
            target.token_secret = Some(secret.clone());
        }
        target.allow_remote = self.allow_remote;
        target
    }
}

/// Result of probing an OpenClaw Gateway via [`probe_openclaw_gateway`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenClawProbeResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

// ============================================================================
// URL, Path, Nudge & Secret Helpers
// ============================================================================

/// Validates and normalizes an OpenClaw Gateway base URL to its canonical loopback origin
/// (`scheme://host[:port]`).
///
/// Fails closed by default on any non-loopback host (`127.0.0.1`, `localhost`, `[::1]` only)
/// so a config writer cannot redirect bearer tokens to an arbitrary remote server.
pub fn normalize_openclaw_base_url(raw: &str) -> Result<String, String> {
    normalize_openclaw_base_url_with_remote(raw, false)
}

/// Validates and normalizes an OpenClaw Gateway base URL to its canonical origin
/// (`scheme://host[:port]`), permitting remote `https://` origins ONLY when `allow_remote == true`.
///
/// Fails closed on:
/// - Any non-loopback origin when `allow_remote == false`.
/// - Non-loopback `http://` origins even when `allow_remote == true`.
/// - Any scheme other than `http` or `https`.
/// - Userinfo/credentials (`@`), non-root paths, query strings (`?`), fragments (`#`),
///   backslashes, whitespace, or control characters.
pub fn normalize_openclaw_base_url_with_remote(
    raw: &str,
    allow_remote: bool,
) -> Result<String, String> {
    super::origin::normalize_origin(raw, allow_remote, INVALID_URL_ERR)
}

/// Validates and normalizes `hooks_path` (e.g. `"/hooks"` or `"/api/hooks"`).
///
/// Rejects paths that do not start with `'/'`, contain path traversal (`..`), query strings,
/// fragments, backslashes, whitespace, or control characters. Strips any trailing `'/'`.
pub fn normalize_openclaw_hooks_path(raw: &str) -> Result<String, String> {
    if raw.is_empty() || raw.len() > MAX_HOOKS_PATH_LEN || !raw.starts_with('/') {
        return Err(INVALID_HOOKS_PATH_ERR.to_string());
    }
    if raw
        .bytes()
        .any(|b| b <= 0x20 || b == 0x7f || b == b'\\' || b == b'?' || b == b'#')
    {
        return Err(INVALID_HOOKS_PATH_ERR.to_string());
    }
    for seg in raw.split('/') {
        if seg == ".." || seg == "." {
            return Err(INVALID_HOOKS_PATH_ERR.to_string());
        }
    }
    let trimmed = raw.trim_end_matches('/');
    Ok(trimmed.to_string())
}

fn sanitize_agent_id(raw: &str) -> &str {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_OPENCLAW_AGENT_ID_LEN
        || trimmed.chars().any(char::is_control)
    {
        DEFAULT_OPENCLAW_AGENT_ID
    } else {
        trimmed
    }
}

fn sanitize_idempotency_suffix(raw: &str) -> String {
    let cleaned: String = raw
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
        .take(96)
        .collect();
    if cleaned.is_empty() {
        uuid_v4()
    } else {
        cleaned
    }
}

fn is_valid_header_token(tok: &str) -> bool {
    !tok.is_empty() && !tok.bytes().any(|b| b < 0x20 || b == 0x7f)
}

/// Resolves the OpenClaw Gateway hooks bearer token strictly from `token_override` (tests)
/// or [`SecretStore`] under the locked key name `"openclaw-hooks-token"`.
///
/// Fails closed (`None`) if `target.token_secret` names any secret other than
/// `"openclaw-hooks-token"`, preventing config-driven exfiltration of arbitrary Keychain entries.
pub fn resolve_openclaw_token(target: &OpenClawTarget) -> Option<String> {
    if let Some(ref direct) = target.token_override {
        let trimmed = direct.trim();
        if is_valid_header_token(trimmed) {
            return Some(trimmed.to_string());
        }
        return None;
    }

    if let Some(raw_name) = target
        .token_secret
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if !is_allowed_openclaw_token_secret(raw_name) {
            return None;
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
    store
        .get(DEFAULT_OPENCLAW_TOKEN_SECRET)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| is_valid_header_token(s))
}

async fn drain_bounded_http_body(body: hyper::body::Incoming, max_bytes: usize) {
    let _ = consume_bounded_body(body, max_bytes, |_| {}).await;
}

// ============================================================================
// Gateway Probe & Transport Implementation
// ============================================================================

/// Fail-closed probe for an OpenClaw Gateway webhook endpoint.
///
/// Security & honesty invariants:
/// - Immediately returns `ok: false` (`openclaw_token_missing`) WITHOUT touching the network
///   when no valid `"openclaw-hooks-token"` exists in [`SecretStore`] (or if a disallowed
///   `tokenSecret` name was configured).
/// - NEVER sends the `Authorization: Bearer` token to an unverified listener during probing!
///   Sends an unauthenticated `POST <origin><hooks_path>/<mode>` with empty JSON `{}` so an
///   OpenClaw Gateway rejects with `401 Unauthorized` or `400 Bad Request` (or `200`/`204`
///   non-HTML) without executing a wake or exposing any credential.
/// - Rejects `405 Method Not Allowed` (random services), HTML responses (`text/html`),
///   `404 Not Found` (`openclaw_hooks_disabled`), `403 Forbidden`, `5xx`, connection refused,
///   and timeouts fail-closed.
pub async fn probe_openclaw_gateway(
    target: &OpenClawTarget,
    timeout: Duration,
) -> OpenClawProbeResult {
    let endpoint_url = match target.endpoint_url() {
        Ok(u) => u,
        Err(e) => {
            return OpenClawProbeResult {
                ok: false,
                status: None,
                error: Some(e),
            };
        }
    };

    if resolve_openclaw_token(target).is_none() {
        return OpenClawProbeResult {
            ok: false,
            status: None,
            error: Some(REASON_OPENCLAW_TOKEN_MISSING.to_string()),
        };
    }

    let uri: Uri = match endpoint_url.parse() {
        Ok(u) => u,
        Err(_) => {
            return OpenClawProbeResult {
                ok: false,
                status: None,
                error: Some(REASON_OPENCLAW_INVALID_URL.to_string()),
            };
        }
    };

    let req = match Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(Bytes::from_static(b"{}")))
    {
        Ok(r) => r,
        Err(e) => {
            return OpenClawProbeResult {
                ok: false,
                status: None,
                error: Some(format!("Failed to build OpenClaw probe request: {e}")),
            };
        }
    };

    let client = build_http1_client();
    let resp = match tokio::time::timeout(timeout, client.request(req)).await {
        Ok(Ok(r)) => r,
        Ok(Err(_)) | Err(_) => {
            return OpenClawProbeResult {
                ok: false,
                status: None,
                error: Some(REASON_OPENCLAW_GATEWAY_UNAVAILABLE.to_string()),
            };
        }
    };

    let status = resp.status();
    let code = status.as_u16();
    let is_html = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.to_ascii_lowercase().contains("text/html"));
    let _ = tokio::time::timeout(
        Duration::from_millis(250),
        drain_bounded_http_body(resp.into_body(), MAX_OPENCLAW_HTTP_BODY_BYTES),
    )
    .await;

    if is_html {
        return OpenClawProbeResult {
            ok: false,
            status: Some(code),
            error: Some(REASON_OPENCLAW_GATEWAY_UNAVAILABLE.to_string()),
        };
    }

    match status {
        StatusCode::OK
        | StatusCode::NO_CONTENT
        | StatusCode::BAD_REQUEST
        | StatusCode::UNAUTHORIZED => OpenClawProbeResult {
            ok: true,
            status: Some(code),
            error: None,
        },
        StatusCode::FORBIDDEN => OpenClawProbeResult {
            ok: false,
            status: Some(code),
            error: Some(REASON_OPENCLAW_AUTH_FAILED.to_string()),
        },
        StatusCode::NOT_FOUND => OpenClawProbeResult {
            ok: false,
            status: Some(code),
            error: Some(REASON_OPENCLAW_HOOKS_DISABLED.to_string()),
        },
        StatusCode::METHOD_NOT_ALLOWED => OpenClawProbeResult {
            ok: false,
            status: Some(code),
            error: Some(REASON_OPENCLAW_REQUEST_REJECTED.to_string()),
        },
        _ => OpenClawProbeResult {
            ok: false,
            status: Some(code),
            error: Some(REASON_OPENCLAW_GATEWAY_UNAVAILABLE.to_string()),
        },
    }
}

/// Native OpenClaw Gateway [`PushTransport`] delivering strictly metadata-only wake nudges.
#[derive(Debug, Clone)]
pub struct OpenClawTransport {
    target: OpenClawTarget,
    deliver_timeout: Duration,
}

impl OpenClawTransport {
    /// Creates a new transport with [`DEFAULT_OPENCLAW_DELIVER_TIMEOUT`] (10 seconds).
    pub fn new(target: OpenClawTarget) -> Self {
        Self {
            target,
            deliver_timeout: DEFAULT_OPENCLAW_DELIVER_TIMEOUT,
        }
    }

    /// Overrides the HTTP delivery timeout (useful for deterministic tests).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.deliver_timeout = timeout;
        self
    }

    /// Returns the configured [`OpenClawTarget`].
    pub fn target(&self) -> &OpenClawTarget {
        &self.target
    }

    async fn deliver_digest_inner(&self, digest: &InboxDigest, batch_id: &str) -> PushOutcome {
        let endpoint_url = match self.target.endpoint_url() {
            Ok(u) => u,
            Err(_) => return PushOutcome::reject(REASON_OPENCLAW_INVALID_URL),
        };
        let uri: Uri = match endpoint_url.parse() {
            Ok(u) => u,
            Err(_) => return PushOutcome::reject(REASON_OPENCLAW_INVALID_URL),
        };

        let validated_session_key = match self.target.session_key.as_deref() {
            Some(raw) => match validate_openclaw_session_key(raw) {
                Ok(key) => Some(key),
                Err(_) => return PushOutcome::reject(REASON_OPENCLAW_INVALID_SESSION_KEY),
            },
            None => None,
        };

        let Some(token) = resolve_openclaw_token(&self.target) else {
            return PushOutcome::reject(REASON_OPENCLAW_TOKEN_MISSING);
        };
        let auth_header = match HeaderValue::from_str(&format!("Bearer {token}")) {
            Ok(v) => v,
            Err(_) => return PushOutcome::reject(REASON_OPENCLAW_TOKEN_MISSING),
        };

        let effective_agent_id = sanitize_agent_id(&self.target.agent_id);
        let payload = match self.target.endpoint_mode {
            OpenClawEndpointMode::Wake => {
                let mut obj = Map::new();
                obj.insert("text".into(), json!(digest));
                obj.insert("mode".into(), json!("now"));
                obj.insert("agentId".into(), json!(effective_agent_id));
                if let Some(ref sk) = validated_session_key {
                    obj.insert("sessionKey".into(), json!(sk));
                }
                Value::Object(obj)
            }
            OpenClawEndpointMode::Agent => {
                let mut obj = Map::new();
                obj.insert("message".into(), json!(digest));
                obj.insert("name".into(), json!("Hyphae"));
                obj.insert("agentId".into(), json!(effective_agent_id));
                obj.insert("wakeMode".into(), json!("now"));
                obj.insert("deliver".into(), json!(false));
                if let Some(ref sk) = validated_session_key {
                    obj.insert("sessionKey".into(), json!(sk));
                }
                Value::Object(obj)
            }
        };

        let body_bytes = match serde_json::to_vec(&payload) {
            Ok(b) => b,
            Err(_) => return PushOutcome::reject(REASON_OPENCLAW_REQUEST_REJECTED),
        };

        let idem_value = format!("hyphae-{}", sanitize_idempotency_suffix(batch_id));
        let idem_header = match HeaderValue::from_str(&idem_value) {
            Ok(v) => v,
            Err(_) => return PushOutcome::reject(REASON_OPENCLAW_REQUEST_REJECTED),
        };
        let idem_name = HeaderName::from_static("idempotency-key");

        let req = match Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::AUTHORIZATION, auth_header)
            .header(header::CONTENT_TYPE, "application/json")
            .header(idem_name, idem_header)
            .body(Full::new(Bytes::from(body_bytes)))
        {
            Ok(r) => r,
            Err(_) => return PushOutcome::reject(REASON_OPENCLAW_REQUEST_REJECTED),
        };

        let client = build_http1_client();
        let resp = match tokio::time::timeout(self.deliver_timeout, client.request(req)).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) | Err(_) => return PushOutcome::hold(REASON_OPENCLAW_GATEWAY_UNAVAILABLE),
        };

        let status = resp.status();
        let _ = tokio::time::timeout(
            Duration::from_millis(250),
            drain_bounded_http_body(resp.into_body(), MAX_OPENCLAW_HTTP_BODY_BYTES),
        )
        .await;

        map_openclaw_http_status(status)
    }
}

/// Deterministic HTTP status -> [`PushOutcome`] mapper for OpenClaw Gateway webhooks.
pub fn map_openclaw_http_status(status: StatusCode) -> PushOutcome {
    match status {
        StatusCode::OK | StatusCode::ACCEPTED | StatusCode::NO_CONTENT => PushOutcome::delivered(),
        StatusCode::TOO_MANY_REQUESTS => PushOutcome::hold(REASON_OPENCLAW_RATE_LIMITED),
        s if s.is_server_error() => PushOutcome::hold(REASON_OPENCLAW_GATEWAY_UNAVAILABLE),
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            PushOutcome::reject(REASON_OPENCLAW_AUTH_FAILED)
        }
        StatusCode::NOT_FOUND => PushOutcome::reject(REASON_OPENCLAW_HOOKS_DISABLED),
        _ => PushOutcome::reject(REASON_OPENCLAW_REQUEST_REJECTED),
    }
}

impl PushTransport for OpenClawTransport {
    fn kind(&self) -> &'static str {
        "openclaw"
    }

    fn supports_interrupt(&self) -> bool {
        false
    }

    fn target_metadata(&self) -> Value {
        let mut obj = Map::new();
        obj.insert("openclawUrl".into(), json!(self.target.base_url));
        obj.insert("openclawHooksPath".into(), json!(self.target.hooks_path));
        obj.insert(
            "openclawMode".into(),
            json!(self.target.endpoint_mode.as_str()),
        );
        obj.insert(
            "openclawAgentId".into(),
            json!(sanitize_agent_id(&self.target.agent_id)),
        );
        if let Some(ref sk) = self.target.session_key {
            if let Ok(valid) = validate_openclaw_session_key(sk) {
                obj.insert("openclawSessionKey".into(), json!(valid));
            }
        }
        Value::Object(obj)
    }

    fn deliver<'a>(
        &'a self,
        digest: &'a InboxDigest,
        _mode: PushMode,
    ) -> TransportFuture<'a, PushOutcome> {
        let batch_id = uuid_v4();
        Box::pin(async move { self.deliver_digest_inner(digest, &batch_id).await })
    }

    fn deliver_digest<'a>(
        &'a self,
        digest: &'a InboxDigest,
        batch_id: &'a str,
        _mode: PushMode,
    ) -> TransportFuture<'a, PushOutcome> {
        Box::pin(async move { self.deliver_digest_inner(digest, batch_id).await })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_valid_origins_and_enforces_loopback_default_and_blocks_smuggling() {
        assert_eq!(
            normalize_openclaw_base_url("http://127.0.0.1:18789").unwrap(),
            "http://127.0.0.1:18789"
        );
        assert_eq!(
            normalize_openclaw_base_url("http://LOCALHOST:18789/").unwrap(),
            "http://localhost:18789"
        );
        assert_eq!(
            normalize_openclaw_base_url("http://[::1]:18789").unwrap(),
            "http://[::1]:18789"
        );
        assert_eq!(
            normalize_openclaw_base_url("https://127.0.0.1:18789").unwrap(),
            "https://127.0.0.1:18789"
        );
        // Remote HTTPS is rejected by default (loopback-only) and allowed only with explicit opt-in.
        assert!(normalize_openclaw_base_url("https://gw.example.com:443/").is_err());
        assert_eq!(
            normalize_openclaw_base_url_with_remote("https://gw.example.com:443/", true).unwrap(),
            "https://gw.example.com"
        );
        assert!(
            normalize_openclaw_base_url_with_remote("http://gw.example.com:18789", true).is_err()
        );

        for bad in [
            "",
            "https://evil.example.com",
            "http://192.168.1.50:18789",
            "http://openclaw.internal:18789",
            "http://user:pass@127.0.0.1:18789",
            "http://127.0.0.1:18789/hooks",
            "http://127.0.0.1:18789?token=leak",
            "http://127.0.0.1:18789#frag",
            "ftp://127.0.0.1:18789",
            "http://127.0.0.1:0",
            "http://127.0.0.1:18789\r\n",
        ] {
            assert!(
                normalize_openclaw_base_url(bad).is_err(),
                "expected base URL {bad:?} to fail closed"
            );
        }
    }

    #[test]
    fn token_secret_is_strictly_locked_to_openclaw_hooks_token() {
        let dir = tempfile::tempdir().unwrap();
        let store = SecretStore::new(dir.path(), SecretBackend::File);
        store.set("openclaw-hooks-token", "valid-oc-token").unwrap();
        store.set("aws-secret-key", "DO_NOT_EXFILTRATE").unwrap();

        let default_target = OpenClawTarget::new()
            .with_state_dir(dir.path())
            .with_secret_backend(SecretBackend::File);
        assert_eq!(
            resolve_openclaw_token(&default_target).as_deref(),
            Some("valid-oc-token")
        );

        let explicit_ok = OpenClawTarget::new()
            .with_token_secret("openclaw-hooks-token")
            .with_state_dir(dir.path())
            .with_secret_backend(SecretBackend::File);
        assert_eq!(
            resolve_openclaw_token(&explicit_ok).as_deref(),
            Some("valid-oc-token")
        );

        let exfil_attempt = OpenClawTarget::new()
            .with_token_secret("aws-secret-key")
            .with_state_dir(dir.path())
            .with_secret_backend(SecretBackend::File);
        assert_eq!(
            resolve_openclaw_token(&exfil_attempt),
            None,
            "arbitrary tokenSecret MUST fail closed and never read unrelated secrets"
        );
    }

    #[test]
    fn normalizes_hooks_path_and_rejects_traversal_and_queries() {
        assert_eq!(normalize_openclaw_hooks_path("/hooks").unwrap(), "/hooks");
        assert_eq!(normalize_openclaw_hooks_path("/hooks/").unwrap(), "/hooks");
        assert_eq!(
            normalize_openclaw_hooks_path("/api/v1/hooks").unwrap(),
            "/api/v1/hooks"
        );
        assert_eq!(normalize_openclaw_hooks_path("/").unwrap(), "");

        for bad in [
            "",
            "hooks",
            "/hooks/../admin",
            "/hooks?token=secret",
            "/hooks#frag",
            "/hooks\\evil",
            "/hooks\nX-Injected: 1",
        ] {
            assert!(
                normalize_openclaw_hooks_path(bad).is_err(),
                "expected hooks path {bad:?} to fail closed"
            );
        }
    }

    #[test]
    fn debug_redacts_token_override_and_metadata_never_contains_secret() {
        let target = OpenClawTarget::new()
            .with_token_override("super-secret-openclaw-tok-999")
            .with_handle("claw");
        let dbg = format!("{target:?}");
        assert!(!dbg.contains("super-secret-openclaw-tok-999"));
        assert!(dbg.contains("[REDACTED]"));

        let transport = OpenClawTransport::new(target);
        assert_eq!(transport.kind(), "openclaw");
        assert!(!transport.supports_interrupt());
        let meta = transport.target_metadata().to_string();
        assert!(!meta.contains("super-secret-openclaw-tok-999"));
    }

    #[test]
    fn http_status_mapping_matches_retryable_and_terminal_contract() {
        assert_eq!(
            map_openclaw_http_status(StatusCode::OK),
            PushOutcome::delivered()
        );
        assert_eq!(
            map_openclaw_http_status(StatusCode::ACCEPTED),
            PushOutcome::delivered()
        );
        assert_eq!(
            map_openclaw_http_status(StatusCode::NO_CONTENT),
            PushOutcome::delivered()
        );
        assert_eq!(
            map_openclaw_http_status(StatusCode::TOO_MANY_REQUESTS),
            PushOutcome::hold(REASON_OPENCLAW_RATE_LIMITED)
        );
        assert_eq!(
            map_openclaw_http_status(StatusCode::BAD_GATEWAY),
            PushOutcome::hold(REASON_OPENCLAW_GATEWAY_UNAVAILABLE)
        );
        assert_eq!(
            map_openclaw_http_status(StatusCode::SERVICE_UNAVAILABLE),
            PushOutcome::hold(REASON_OPENCLAW_GATEWAY_UNAVAILABLE)
        );
        assert_eq!(
            map_openclaw_http_status(StatusCode::UNAUTHORIZED),
            PushOutcome::reject(REASON_OPENCLAW_AUTH_FAILED)
        );
        assert_eq!(
            map_openclaw_http_status(StatusCode::FORBIDDEN),
            PushOutcome::reject(REASON_OPENCLAW_AUTH_FAILED)
        );
        assert_eq!(
            map_openclaw_http_status(StatusCode::NOT_FOUND),
            PushOutcome::reject(REASON_OPENCLAW_HOOKS_DISABLED)
        );
    }

    #[tokio::test]
    async fn probe_fails_closed_without_secret_token() {
        let dir = tempfile::tempdir().unwrap();
        let target = OpenClawTarget::new()
            .with_state_dir(dir.path())
            .with_secret_backend(SecretBackend::File);
        let res = probe_openclaw_gateway(&target, Duration::from_millis(200)).await;
        assert!(!res.ok);
        assert_eq!(res.error.as_deref(), Some(REASON_OPENCLAW_TOKEN_MISSING));
    }

    #[test]
    fn default_endpoint_mode_is_wake_and_session_key_helpers_fail_closed() {
        assert_eq!(OpenClawEndpointMode::default(), OpenClawEndpointMode::Wake);
        let target = OpenClawTarget::new()
            .with_agent_id("ops")
            .with_session_key("agent:ops:explicit:thread-7");
        assert_eq!(target.endpoint_mode, OpenClawEndpointMode::Wake);
        assert_eq!(
            target.endpoint_url().unwrap(),
            "http://127.0.0.1:18789/hooks/wake"
        );
        assert_eq!(
            parse_openclaw_agent_id_from_session_key("agent:ops:explicit:thread-7").as_deref(),
            Some("ops")
        );
        assert_eq!(
            parse_openclaw_agent_id_from_session_key("agent:main:main").as_deref(),
            Some("main")
        );
        assert_eq!(parse_openclaw_agent_id_from_session_key("main"), None);
        assert_eq!(
            parse_openclaw_agent_id_from_session_key("agent::main"),
            None
        );

        assert_eq!(
            canonical_openclaw_session_id("agent:main:explicit:thread-2").unwrap(),
            "openclaw:agent:main:explicit:thread-2"
        );
        assert_eq!(
            canonical_openclaw_session_id("openclaw:agent:main:main").unwrap(),
            "openclaw:agent:main:main"
        );
        // Special valid non-session-id chars (e.g. `/` or `@`) deterministically hash to `openclaw:sk_<32 hex>`
        let hashed = canonical_openclaw_session_id("agent:main:slack:team/chan@1").unwrap();
        assert!(hashed.starts_with("openclaw:sk_"), "hashed={hashed}");
        assert_eq!(hashed.len(), "openclaw:sk_".len() + 32);
        assert!(hyp_harness_ipc::caller::is_valid_session_id(&hashed));

        for bad in [
            "",
            "agent:main:has space",
            "agent:main:bad\nid",
            "agent:main:bad\rid",
            "agent:main:bad\x00id",
            &"a".repeat(257),
        ] {
            assert!(
                validate_openclaw_session_key(bad).is_err(),
                "expected invalid sessionKey {bad:?} to fail closed"
            );
            assert!(
                canonical_openclaw_session_id(bad).is_err(),
                "expected canonical_openclaw_session_id({bad:?}) to fail closed"
            );
        }

        let transport = OpenClawTransport::new(target);
        let meta = transport.target_metadata();
        assert_eq!(meta["openclawMode"], "wake");
        assert_eq!(meta["openclawAgentId"], "ops");
        assert_eq!(meta["openclawSessionKey"], "agent:ops:explicit:thread-7");
    }

    #[tokio::test]
    async fn invalid_session_key_rejects_fail_closed_before_network() {
        let target = OpenClawTarget::new()
            .with_token_override("valid-tok")
            .with_session_key("agent:main:bad\ninjection");
        let transport = OpenClawTransport::new(target);
        assert_eq!(
            transport
                .deliver_digest(&crate::transport::test_digest(), "b1", PushMode::Queue)
                .await,
            PushOutcome::reject(REASON_OPENCLAW_INVALID_SESSION_KEY)
        );
    }
}
