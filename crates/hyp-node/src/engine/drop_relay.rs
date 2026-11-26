//! RAM-only Blind Ephemeral Drop Relay (`DropRelay`).
//!
//! Implements the stateless-capability, zero-disk blind rendezvous relay for Verified Human Drops:
//! - **Zero disk / zero SQLite persistence**: every ciphertext payload lives exclusively in RAM
//!   inside a `Zeroizing<Vec<u8>>` buffer and is zeroized immediately on burn, TTL expiration, or
//!   process drop.
//! - **Zero sensitive logging**: never logs `drop_id`, client IPs, capability tokens, or payloads;
//!   `Debug` implementations redact secrets and payload bytes.
//! - **Stateless HMAC-SHA256 capabilities (`hdcap1_`)**: backed by an in-RAM 32-byte CSPRNG key
//!   with hourly rotation (current + previous key ring) so 15-minute drops never break across
//!   hour boundaries. Supports ~2 µs constant-time verification via [`DropRelay::verify_capability`]
//!   *before* reading HTTP request body bytes.
//! - **Anti-DoS & strict non-eviction**: sliding-window per-node and per-IP creation quotas
//!   (`429 Too Many Requests`), per-drop / per-IP / global SSE concurrency caps with RAII `Drop`
//!   guards, and sweep-before-reject global caps returning `503 Service Unavailable` (`Retry-After`)
//!   without ever evicting honest in-flight drops.
//! - **Atomic late-subscriber catch-up**: captures buffered items (`seq > Last-Event-ID`) and
//!   subscribes to the live `tokio::sync::broadcast` channel under the same mutex acquisition so
//!   zero items are lost or duplicated between backlog replay and live SSE streaming.
//! - **Fail-closed CORS & Chrome PNA**: strict explicit origin allowlist (never `"*"` or `"null"`)
//!   with optional `Access-Control-Allow-Private-Network: true` for direct LAN/Tailscale drops.

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::header::{ACCESS_CONTROL_ALLOW_ORIGIN, HeaderName, HeaderValue, VARY};
use http::{HeaderMap, StatusCode};
use hyp_proto::problem::ProblemDetails;
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::broadcast;
use zeroize::Zeroizing;

use crate::engine::http_util::SseEvent;

/// Prefix for stateless HMAC-SHA256 drop capability tokens (`postCap` / `subCap`).
pub const DROP_CAP_PREFIX: &str = "hdcap1_";

/// Domain separation prefix for drop capability HMACs.
pub const DROP_CAP_DOMAIN: &[u8] = b"hyphae/v2/human-drop-cap\n";

/// HTTP header carrying `postCap` or `subCap`.
pub const DROP_CAP_HEADER: &str = "X-Hyphae-Drop-Cap";

/// Number of CSPRNG bytes in a `drop_id` (128 bits -> 22 unpadded base64url chars).
pub const DROP_ID_BYTES: usize = 16;

/// Exact character length of an unpadded base64url 128-bit `drop_id`.
pub const DROP_ID_LEN: usize = 22;

/// Raw decoded byte length of an `hdcap1_` token (`role_byte[1] || exp_ms_be[8] || mac[32]`).
const DROP_CAP_RAW_LEN: usize = 1 + 8 + 32;

/// Exact base64url character length of `DROP_CAP_RAW_LEN` (41 bytes -> 55 chars).
const DROP_CAP_ENCODED_LEN: usize = 55;

/// Hourly HMAC key rotation interval (1 hour in milliseconds).
pub const KEY_ROTATION_INTERVAL_MS: i64 = 3_600_000;

/// Sliding window duration for per-node and per-IP creation rate limits (1 hour in milliseconds).
pub const CREATE_RATE_WINDOW_MS: i64 = 3_600_000;

/// Hard maximum TTL cap (15 minutes in seconds).
pub const HARD_MAX_TTL_SECONDS: u64 = 900;

/// Default drop TTL (10 minutes in seconds).
pub const DEFAULT_TTL_SECONDS: u64 = 600;

/// Default RAM budget for buffered ciphertexts (256 MiB).
pub const DEFAULT_MAX_MEMORY_MB: usize = 256;

/// Default maximum buffered items per drop slot.
pub const DEFAULT_MAX_ITEMS_PER_DROP: usize = 16;

/// Default maximum ciphertext payload size per POST (64 KiB).
pub const DEFAULT_MAX_PAYLOAD_BYTES: usize = 65_536;

/// Default maximum concurrent active drops across the relay.
pub const DEFAULT_MAX_ACTIVE_DROPS: usize = 4_096;

/// Default maximum concurrent active drops per creator node.
pub const DEFAULT_MAX_ACTIVE_DROPS_PER_NODE: usize = 3;

/// Default maximum drop creations per hour per creator node.
pub const DEFAULT_CREATES_PER_HOUR_PER_NODE: u32 = 10;

/// Default maximum drop creations per hour per client IP.
pub const DEFAULT_CREATES_PER_HOUR_PER_IP: u32 = 20;

/// Default maximum concurrent SSE subscriber streams globally.
pub const DEFAULT_MAX_SSE_STREAMS: usize = 4_096;

/// Default maximum concurrent SSE subscriber streams per `drop_id`.
pub const DEFAULT_MAX_SSE_STREAMS_PER_DROP: usize = 2;

/// Default maximum concurrent SSE subscriber streams per client IP.
pub const DEFAULT_MAX_SSE_STREAMS_PER_IP: usize = 16;

/// Default allowed CORS origin (`https://hyphae.to` — never `"*"`).
pub const DEFAULT_ALLOWED_ORIGIN: &str = "https://hyphae.to";

/// Recommended SSE keepalive cadence in seconds for HTTP servers mounting `DropRelay`.
pub const DROP_SSE_KEEPALIVE_SECONDS: u64 = 25;

/// Recommended SSE frame write timeout in seconds for HTTP servers mounting `DropRelay`.
pub const DROP_SSE_WRITE_TIMEOUT_SECONDS: u64 = 5;

const BYTES_PER_MIB: usize = 1024 * 1024;
const MAX_CREATOR_NODE_ID_LEN: usize = 256;
const RATE_TABLE_PRUNE_THRESHOLD: usize = 4_096;

/// Configuration for the RAM-only Blind Drop Relay (`node.json` -> `dropRelay`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DropRelayConfig {
    /// Opt-in gate; when `false`, all relay operations fail closed with `404`.
    pub enabled: bool,
    /// When `true` (Direct LAN/Tailscale nodes), accept only self-targeted drops.
    pub local_drops_only: bool,
    /// Maximum total buffered ciphertext RAM in MiB (default: `256` MiB).
    pub max_memory_mb: usize,
    /// Default drop TTL in seconds (default: `600` = 10 min).
    pub default_ttl_seconds: u64,
    /// Maximum allowed drop TTL in seconds (default & hard cap: `900` = 15 min).
    pub max_ttl_seconds: u64,
    /// Maximum number of ciphertext items accepted per drop slot (default: `16`).
    pub max_items_per_drop: usize,
    /// Maximum byte size of a single posted ciphertext payload (default: `65_536` = 64 KiB).
    pub max_payload_bytes: usize,
    /// Maximum concurrent active drops globally (default: `4_096`).
    pub max_active_drops: usize,
    /// Maximum concurrent active drops per creator node (default: `3`).
    pub max_active_drops_per_node: usize,
    /// Sliding-window drop creations per hour per creator node (default: `10`).
    pub creates_per_hour_per_node: u32,
    /// Sliding-window drop creations per hour per client IP (default: `20`).
    pub creates_per_hour_per_ip: u32,
    /// Maximum concurrent SSE subscriber streams globally (default: `4_096`).
    pub max_sse_streams: usize,
    /// Maximum concurrent SSE subscriber streams per `drop_id` (default: `2`).
    pub max_sse_streams_per_drop: usize,
    /// Maximum concurrent SSE subscriber streams per client IP (default: `16`).
    pub max_sse_streams_per_ip: usize,
    /// Explicit CORS origin allowlist (default: `["https://hyphae.to"]` — never `"*"`).
    pub allowed_origins: Vec<String>,
    /// Emit `Access-Control-Allow-Private-Network: true` for Chrome PNA direct LAN/Tailscale drops.
    pub allow_private_network: bool,
}

impl Default for DropRelayConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            local_drops_only: false,
            max_memory_mb: DEFAULT_MAX_MEMORY_MB,
            default_ttl_seconds: DEFAULT_TTL_SECONDS,
            max_ttl_seconds: HARD_MAX_TTL_SECONDS,
            max_items_per_drop: DEFAULT_MAX_ITEMS_PER_DROP,
            max_payload_bytes: DEFAULT_MAX_PAYLOAD_BYTES,
            max_active_drops: DEFAULT_MAX_ACTIVE_DROPS,
            max_active_drops_per_node: DEFAULT_MAX_ACTIVE_DROPS_PER_NODE,
            creates_per_hour_per_node: DEFAULT_CREATES_PER_HOUR_PER_NODE,
            creates_per_hour_per_ip: DEFAULT_CREATES_PER_HOUR_PER_IP,
            max_sse_streams: DEFAULT_MAX_SSE_STREAMS,
            max_sse_streams_per_drop: DEFAULT_MAX_SSE_STREAMS_PER_DROP,
            max_sse_streams_per_ip: DEFAULT_MAX_SSE_STREAMS_PER_IP,
            allowed_origins: vec![DEFAULT_ALLOWED_ORIGIN.to_string()],
            allow_private_network: true,
        }
    }
}

impl DropRelayConfig {
    /// Returns the configured RAM ceiling in bytes (`max_memory_mb * 1_048_576`).
    pub fn max_memory_bytes(&self) -> usize {
        self.max_memory_mb.saturating_mul(BYTES_PER_MIB)
    }

    /// Returns the effective maximum TTL clamped to `1..=900` seconds.
    pub fn effective_max_ttl_seconds(&self) -> u64 {
        self.max_ttl_seconds.clamp(1, HARD_MAX_TTL_SECONDS)
    }
}

/// Capability role encoded inside an `hdcap1_` token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DropCapRole {
    /// Allows posting opaque ciphertext payloads to `POST /v1/drops/{id}`.
    Post = 1,
    /// Allows subscribing (`GET /v1/drops/{id}/stream`) and acknowledging/burning (`POST /v1/drops/{id}/ack`).
    Sub = 2,
}

impl DropCapRole {
    fn from_byte(b: u8) -> Option<Self> {
        match b {
            1 => Some(Self::Post),
            2 => Some(Self::Sub),
            _ => None,
        }
    }

    fn as_mac_label(self) -> &'static str {
        match self {
            Self::Post => "post",
            Self::Sub => "sub",
        }
    }
}

/// Request payload for `POST /v1/drops`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CreateDropRequest {
    /// Requested TTL in seconds (clamped to `1..=max_ttl_seconds`; defaults to `default_ttl_seconds`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
    /// Optional per-drop item cap (clamped to `1..=max_items_per_drop`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_items: Option<usize>,
    /// Optional intended target node ID (enforced equal to creator when `local_drops_only` is set).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_node_id: Option<String>,
    /// When `true`, burning all buffered items via `ack_drop(..., burn: true)` immediately closes
    /// and deletes the drop slot from RAM.
    #[serde(default)]
    pub burn_after_read: bool,
}

/// Response returned from [`DropRelay::create_drop`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateDropResponse {
    pub drop_id: String,
    pub expires_at_ms: i64,
    pub post_cap: String,
    pub sub_cap: String,
    pub max_payload_bytes: usize,
    pub max_items: usize,
}

impl fmt::Debug for CreateDropResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateDropResponse")
            .field("drop_id", &"[REDACTED]")
            .field("expires_at_ms", &self.expires_at_ms)
            .field("post_cap", &"[REDACTED]")
            .field("sub_cap", &"[REDACTED]")
            .field("max_payload_bytes", &self.max_payload_bytes)
            .field("max_items", &self.max_items)
            .finish()
    }
}

/// Response returned from [`DropRelay::post_drop`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostDropResponse {
    pub seq: u64,
    pub expires_at_ms: i64,
}

/// Authentication credential for subscribing to or acknowledging a drop.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DropSubscriberAuth<'a> {
    /// Stateless HMAC subscriber capability (`X-Hyphae-Drop-Cap: <subCap>`).
    SubCap(&'a str),
    /// Verified `Hyphae-Ed25519` authenticated node ID of the drop's creator.
    CreatorNode(&'a str),
}

impl fmt::Debug for DropSubscriberAuth<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SubCap(_) => f.write_str("DropSubscriberAuth::SubCap([REDACTED])"),
            Self::CreatorNode(node_id) => f
                .debug_tuple("DropSubscriberAuth::CreatorNode")
                .field(node_id)
                .finish(),
        }
    }
}

/// Response returned from [`DropRelay::ack_drop`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AckDropResponse {
    pub acked_seq: u64,
    pub burned_items: usize,
    pub burned_bytes: usize,
    pub remaining_items: usize,
    pub slot_closed: bool,
}

/// Aggregate-only health and capacity telemetry for `GET /v1/health`.
///
/// Strictly contains zero per-drop, per-node, or per-IP identifiers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DropRelayHealth {
    pub enabled: bool,
    pub active_drops: usize,
    pub buffered_bytes: usize,
    pub max_memory_bytes: usize,
    pub active_sse_streams: usize,
    pub drops_created_total: u64,
    pub drops_delivered_total: u64,
}

/// Single opaque ciphertext item stored in RAM and streamed to SSE subscribers.
///
/// Underlying ciphertext bytes are stored inside `Arc<Zeroizing<Vec<u8>>>` so the buffer is
/// securely zeroized when the final reference is dropped.
#[derive(Clone)]
pub struct DropItem {
    /// Monotonically increasing sequence number (`1..=max_items`).
    pub seq: u64,
    /// Opaque ciphertext bytes (zeroized on drop).
    pub payload: Arc<Zeroizing<Vec<u8>>>,
    /// Arrival timestamp in milliseconds since Unix epoch.
    pub received_at_ms: i64,
}

impl DropItem {
    /// Returns a read-only slice of the opaque ciphertext payload bytes.
    pub fn payload_bytes(&self) -> &[u8] {
        self.payload.as_slice()
    }

    /// Formats this item as a WHATWG SSE event (`id: <seq>`, `event: drop`, `data: ...`).
    ///
    /// Valid UTF-8 payloads (such as canonical `HumanDropEnvelopeV1` JSON) are emitted directly;
    /// arbitrary non-UTF-8 binary payloads fall back to unpadded base64url.
    pub fn to_sse_event(&self) -> SseEvent {
        let data = match std::str::from_utf8(self.payload.as_slice()) {
            Ok(text) if !text.contains('\0') => text.to_string(),
            _ => URL_SAFE_NO_PAD.encode(self.payload.as_slice()),
        };
        SseEvent::new("drop", data).with_id(self.seq.to_string())
    }
}

impl fmt::Debug for DropItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DropItem")
            .field("seq", &self.seq)
            .field("payload_len", &self.payload.len())
            .field("received_at_ms", &self.received_at_ms)
            .finish()
    }
}

/// Fail-closed error variants produced by [`DropRelay`].
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DropRelayError {
    #[error("drop relay is disabled on this node")]
    Disabled,
    #[error("bad drop relay request: {0}")]
    BadRequest(String),
    #[error("unauthorized drop capability or caller: {0}")]
    Unauthorized(String),
    #[error("forbidden drop relay operation: {0}")]
    Forbidden(String),
    #[error("drop slot not found")]
    NotFound,
    #[error("drop slot or capability has expired")]
    Expired,
    #[error("drop payload ({size} bytes) exceeds limit of {max_bytes} bytes")]
    PayloadTooLarge { size: usize, max_bytes: usize },
    #[error("drop slot is full (max {max_items} items)")]
    DropFull { max_items: usize },
    #[error("drop relay rate limited ({reason}); retry after {retry_after_secs}s")]
    RateLimited {
        reason: String,
        retry_after_secs: u64,
    },
    #[error("drop relay capacity exceeded ({reason}); retry after {retry_after_secs}s")]
    CapacityExceeded {
        reason: String,
        retry_after_secs: u64,
    },
    #[error("internal drop relay error: {0}")]
    Internal(String),
}

impl DropRelayError {
    /// Returns the HTTP status code corresponding to this error.
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::Disabled | Self::NotFound => StatusCode::NOT_FOUND,
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::Expired => StatusCode::GONE,
            Self::PayloadTooLarge { .. } => StatusCode::PAYLOAD_TOO_LARGE,
            Self::DropFull { .. } => StatusCode::CONFLICT,
            Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::CapacityExceeded { .. } => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// Returns the RFC 9110 `Retry-After` delta-seconds hint when applicable.
    pub fn retry_after_secs(&self) -> Option<u64> {
        match self {
            Self::RateLimited {
                retry_after_secs, ..
            }
            | Self::CapacityExceeded {
                retry_after_secs, ..
            } => Some(*retry_after_secs),
            _ => None,
        }
    }

    /// Converts this error into an RFC 9457 `application/problem+json` payload.
    pub fn to_problem_details(&self) -> ProblemDetails {
        match self {
            Self::Disabled => ProblemDetails::new(
                "drop_relay_disabled",
                "drop-relay-disabled",
                "Drop Relay Disabled",
                404,
                self.to_string(),
            ),
            Self::BadRequest(msg) => ProblemDetails::new(
                "drop_bad_request",
                "drop-bad-request",
                "Bad Drop Request",
                400,
                msg.clone(),
            ),
            Self::Unauthorized(msg) => ProblemDetails::new(
                "drop_unauthorized",
                "drop-unauthorized",
                "Unauthorized Drop Request",
                401,
                msg.clone(),
            ),
            Self::Forbidden(msg) => ProblemDetails::new(
                "drop_forbidden",
                "drop-forbidden",
                "Forbidden Drop Request",
                403,
                msg.clone(),
            ),
            Self::NotFound => ProblemDetails::new(
                "drop_not_found",
                "drop-not-found",
                "Drop Not Found",
                404,
                self.to_string(),
            ),
            Self::Expired => ProblemDetails::new(
                "drop_expired",
                "drop-expired",
                "Drop Expired",
                410,
                self.to_string(),
            ),
            Self::PayloadTooLarge { size, max_bytes } => ProblemDetails::new(
                "drop_payload_too_large",
                "drop-payload-too-large",
                "Drop Payload Too Large",
                413,
                self.to_string(),
            )
            .with_extension("payloadBytes", serde_json::json!(size))
            .with_extension("maxPayloadBytes", serde_json::json!(max_bytes)),
            Self::DropFull { max_items } => ProblemDetails::new(
                "drop_full",
                "drop-full",
                "Drop Slot Full",
                409,
                self.to_string(),
            )
            .with_extension("maxItems", serde_json::json!(max_items)),
            Self::RateLimited {
                reason,
                retry_after_secs,
            } => ProblemDetails::new(
                "drop_rate_limited",
                "drop-rate-limited",
                "Drop Relay Rate Limited",
                429,
                reason.clone(),
            )
            .with_extension("retryAfterSeconds", serde_json::json!(retry_after_secs)),
            Self::CapacityExceeded {
                reason,
                retry_after_secs,
            } => ProblemDetails::new(
                "drop_capacity_exceeded",
                "drop-capacity-exceeded",
                "Drop Relay Capacity Exceeded",
                503,
                reason.clone(),
            )
            .with_extension("retryAfterSeconds", serde_json::json!(retry_after_secs)),
            Self::Internal(msg) => ProblemDetails::new(
                "drop_internal_error",
                "drop-internal-error",
                "Drop Relay Internal Error",
                500,
                msg.clone(),
            ),
        }
    }
}

/// Hourly-rotated in-RAM HMAC-SHA256 key ring (current + previous 32-byte CSPRNG secrets).
///
/// Keeping one previous hour's key guarantees 15-minute capabilities never break across an hour
/// boundary while automatically zeroizing retired keys in RAM.
struct RotatingHmacKeys {
    rng: SystemRandom,
    current_bucket: Option<i64>,
    current_secret: Zeroizing<[u8; 32]>,
    previous_bucket: Option<i64>,
    previous_secret: Option<Zeroizing<[u8; 32]>>,
}

impl RotatingHmacKeys {
    fn new() -> Self {
        let rng = SystemRandom::new();
        let current_secret = generate_secret_key(&rng).expect("OS CSPRNG unavailable");
        Self {
            rng,
            current_bucket: None,
            current_secret,
            previous_bucket: None,
            previous_secret: None,
        }
    }

    fn rotate_if_needed(&mut self, now_ms: i64) -> Result<(), DropRelayError> {
        let bucket = now_ms.div_euclid(KEY_ROTATION_INTERVAL_MS);
        match self.current_bucket {
            None => {
                self.current_bucket = Some(bucket);
                Ok(())
            }
            Some(cur) if bucket == cur => Ok(()),
            Some(cur) if bucket < cur => {
                // Tolerate slight backward clock adjustments without discarding valid keys.
                Ok(())
            }
            Some(cur) if bucket == cur + 1 => {
                let fresh = generate_secret_key(&self.rng)?;
                let old_current = std::mem::replace(&mut self.current_secret, fresh);
                self.previous_secret = Some(old_current);
                self.previous_bucket = Some(cur);
                self.current_bucket = Some(bucket);
                Ok(())
            }
            Some(_) => {
                // More than one hour elapsed: any capability minted under previous keys is strictly
                // expired (max TTL is 15 min), so zeroize & discard previous secret immediately.
                self.previous_secret = None;
                self.previous_bucket = None;
                self.current_secret = generate_secret_key(&self.rng)?;
                self.current_bucket = Some(bucket);
                Ok(())
            }
        }
    }

    fn mint(
        &mut self,
        drop_id: &str,
        role: DropCapRole,
        expires_at_ms: i64,
        now_ms: i64,
    ) -> Result<String, DropRelayError> {
        self.rotate_if_needed(now_ms)?;
        let exp_bytes = expires_at_ms.to_be_bytes();
        let mac_msg = build_cap_mac_input(role, drop_id, &exp_bytes);
        let key = hmac::Key::new(hmac::HMAC_SHA256, self.current_secret.as_slice());
        let tag = hmac::sign(&key, &mac_msg);

        let mut raw = Zeroizing::new([0u8; DROP_CAP_RAW_LEN]);
        raw[0] = role as u8;
        raw[1..9].copy_from_slice(&exp_bytes);
        raw[9..41].copy_from_slice(tag.as_ref());

        let mut token = String::with_capacity(DROP_CAP_PREFIX.len() + DROP_CAP_ENCODED_LEN);
        token.push_str(DROP_CAP_PREFIX);
        URL_SAFE_NO_PAD.encode_string(&raw[..], &mut token);
        Ok(token)
    }

    fn verify(
        &mut self,
        drop_id: &str,
        token: &str,
        expected_role: DropCapRole,
        now_ms: i64,
    ) -> Result<i64, DropRelayError> {
        self.rotate_if_needed(now_ms)?;

        let encoded = token
            .strip_prefix(DROP_CAP_PREFIX)
            .ok_or_else(|| DropRelayError::Unauthorized("missing hdcap1_ token prefix".into()))?;
        if encoded.len() != DROP_CAP_ENCODED_LEN {
            return Err(DropRelayError::Unauthorized(
                "invalid drop capability token length".into(),
            ));
        }

        let decoded = URL_SAFE_NO_PAD.decode(encoded.as_bytes()).map_err(|_| {
            DropRelayError::Unauthorized("malformed drop capability encoding".into())
        })?;
        let raw = Zeroizing::new(decoded);
        if raw.len() != DROP_CAP_RAW_LEN {
            return Err(DropRelayError::Unauthorized(
                "invalid drop capability payload size".into(),
            ));
        }

        let token_role = DropCapRole::from_byte(raw[0])
            .ok_or_else(|| DropRelayError::Unauthorized("unknown drop capability role".into()))?;
        if token_role != expected_role {
            return Err(DropRelayError::Unauthorized(
                "drop capability role mismatch".into(),
            ));
        }

        let mut exp_bytes = [0u8; 8];
        exp_bytes.copy_from_slice(&raw[1..9]);
        let exp_ms = i64::from_be_bytes(exp_bytes);
        let tag = &raw[9..41];

        let mac_msg = build_cap_mac_input(token_role, drop_id, &exp_bytes);

        let cur_key = hmac::Key::new(hmac::HMAC_SHA256, self.current_secret.as_slice());
        let mut verified = hmac::verify(&cur_key, &mac_msg, tag).is_ok();
        if !verified {
            if let Some(prev) = &self.previous_secret {
                let prev_key = hmac::Key::new(hmac::HMAC_SHA256, prev.as_slice());
                if hmac::verify(&prev_key, &mac_msg, tag).is_ok() {
                    verified = true;
                }
            }
        }

        if !verified {
            return Err(DropRelayError::Unauthorized(
                "invalid drop capability signature".into(),
            ));
        }

        if now_ms >= exp_ms {
            return Err(DropRelayError::Expired);
        }

        Ok(exp_ms)
    }

    fn random_drop_id(&self) -> Result<String, DropRelayError> {
        let mut bytes = [0u8; DROP_ID_BYTES];
        self.rng
            .fill(&mut bytes)
            .map_err(|_| DropRelayError::Internal("CSPRNG failure generating drop_id".into()))?;
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }
}

fn generate_secret_key(rng: &SystemRandom) -> Result<Zeroizing<[u8; 32]>, DropRelayError> {
    let mut secret = Zeroizing::new([0u8; 32]);
    rng.fill(&mut *secret)
        .map_err(|_| DropRelayError::Internal("CSPRNG failure generating HMAC key".into()))?;
    Ok(secret)
}

fn build_cap_mac_input(role: DropCapRole, drop_id: &str, exp_ms_be: &[u8; 8]) -> Vec<u8> {
    let role_label = role.as_mac_label();
    let mut msg =
        Vec::with_capacity(DROP_CAP_DOMAIN.len() + role_label.len() + 1 + drop_id.len() + 1 + 8);
    msg.extend_from_slice(DROP_CAP_DOMAIN);
    msg.extend_from_slice(role_label.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(drop_id.as_bytes());
    msg.push(b'\n');
    msg.extend_from_slice(exp_ms_be);
    msg
}

fn is_valid_drop_id(drop_id: &str) -> bool {
    drop_id.len() == DROP_ID_LEN
        && drop_id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

struct DropSlot {
    creator_node_id: String,
    expires_at_ms: i64,
    burn_after_read: bool,
    max_items: usize,
    next_seq: u64,
    highest_acked_seq: u64,
    items: VecDeque<DropItem>,
    buffered_bytes: usize,
    tx: broadcast::Sender<DropItem>,
}

impl Drop for DropSlot {
    fn drop(&mut self) {
        self.items.clear();
        self.buffered_bytes = 0;
    }
}

#[derive(Default)]
struct RelayState {
    slots: HashMap<String, DropSlot>,
    per_node_active_drops: HashMap<String, usize>,
    node_create_window: HashMap<String, VecDeque<i64>>,
    ip_create_window: HashMap<String, VecDeque<i64>>,
    total_buffered_bytes: usize,
    active_sse_streams: usize,
    per_drop_sse_streams: HashMap<String, usize>,
    per_ip_sse_streams: HashMap<String, usize>,
    drops_created_total: u64,
    drops_delivered_total: u64,
}

impl RelayState {
    fn remove_slot_locked(&mut self, drop_id: &str) -> Option<DropSlot> {
        let mut slot = self.slots.remove(drop_id)?;
        self.total_buffered_bytes = self
            .total_buffered_bytes
            .saturating_sub(slot.buffered_bytes);
        if let Some(count) = self.per_node_active_drops.get_mut(&slot.creator_node_id) {
            if *count <= 1 {
                self.per_node_active_drops.remove(&slot.creator_node_id);
            } else {
                *count -= 1;
            }
        }
        slot.items.clear();
        slot.buffered_bytes = 0;
        Some(slot)
    }

    fn sweep_expired_locked(&mut self, now_ms: i64) -> usize {
        let expired_ids: Vec<String> = self
            .slots
            .iter()
            .filter(|(_, slot)| now_ms >= slot.expires_at_ms)
            .map(|(id, _)| id.clone())
            .collect();
        let removed = expired_ids.len();
        for id in expired_ids {
            let _ = self.remove_slot_locked(&id);
        }

        // Prune expired sliding-window entries so transient nodes/IPs never grow RAM unboundedly.
        let cutoff = now_ms.saturating_sub(CREATE_RATE_WINDOW_MS);
        prune_rate_map(&mut self.node_create_window, cutoff);
        prune_rate_map(&mut self.ip_create_window, cutoff);

        removed
    }

    fn earliest_expiry_retry_after(&self, now_ms: i64, creator_filter: Option<&str>) -> u64 {
        let earliest = self
            .slots
            .values()
            .filter(|slot| match creator_filter {
                Some(node_id) => slot.creator_node_id == node_id,
                None => true,
            })
            .map(|slot| slot.expires_at_ms)
            .min();
        match earliest {
            Some(exp_ms) => ms_until_retry_secs(exp_ms, now_ms),
            None => 1,
        }
    }
}

fn prune_window(window: &mut VecDeque<i64>, cutoff_ms: i64) {
    while let Some(&front) = window.front() {
        if front <= cutoff_ms {
            window.pop_front();
        } else {
            break;
        }
    }
}

fn prune_rate_map(map: &mut HashMap<String, VecDeque<i64>>, cutoff_ms: i64) {
    map.retain(|_, window| {
        prune_window(window, cutoff_ms);
        !window.is_empty()
    });
}

fn ms_until_retry_secs(target_ms: i64, now_ms: i64) -> u64 {
    let delta = target_ms.saturating_sub(now_ms);
    if delta <= 0 {
        1
    } else {
        ((delta as u64).saturating_add(999) / 1_000).max(1)
    }
}

struct DropRelayInner {
    max_memory_bytes: usize,
    local_node_id: Option<String>,
    keys: Mutex<RotatingHmacKeys>,
    state: Mutex<RelayState>,
}

/// Self-contained, RAM-only Blind Drop Relay engine.
///
/// Cheaply `Clone`-able (backed by `Arc`); safe to share across concurrent `hyper` tasks.
#[derive(Clone)]
pub struct DropRelay {
    config: Arc<DropRelayConfig>,
    inner: Arc<DropRelayInner>,
}

impl fmt::Debug for DropRelay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DropRelay")
            .field("enabled", &self.config.enabled)
            .field("local_drops_only", &self.config.local_drops_only)
            .field("max_memory_bytes", &self.inner.max_memory_bytes)
            .finish()
    }
}

impl DropRelay {
    /// Creates a new RAM-only [`DropRelay`] with freshly generated in-RAM CSPRNG HMAC keys.
    pub fn new(config: DropRelayConfig) -> Self {
        let max_memory_bytes = config.max_memory_bytes();
        Self::with_memory_cap_bytes(config, max_memory_bytes)
    }

    /// Creates a new [`DropRelay`] with an explicit byte-level RAM cap (useful for tight quotas
    /// and deterministic boundary tests).
    pub fn with_memory_cap_bytes(config: DropRelayConfig, max_memory_bytes: usize) -> Self {
        Self {
            config: Arc::new(config),
            inner: Arc::new(DropRelayInner {
                max_memory_bytes,
                local_node_id: None,
                keys: Mutex::new(RotatingHmacKeys::new()),
                state: Mutex::new(RelayState::default()),
            }),
        }
    }

    /// Binds this relay to a local node ID for `local_drops_only` enforcement on Direct LAN /
    /// Tailscale nodes.
    pub fn with_local_node_id(mut self, node_id: impl Into<String>) -> Self {
        let node_id = node_id.into();
        if let Some(existing) = Arc::get_mut(&mut self.inner) {
            existing.local_node_id = Some(node_id);
            return self;
        }
        self.inner = Arc::new(DropRelayInner {
            max_memory_bytes: self.inner.max_memory_bytes,
            local_node_id: Some(node_id),
            keys: Mutex::new(RotatingHmacKeys::new()),
            state: Mutex::new(RelayState::default()),
        });
        self
    }

    /// Returns a reference to the immutable relay configuration.
    pub fn config(&self) -> &DropRelayConfig {
        &self.config
    }

    /// Returns `true` if the drop relay is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Returns `true` if `Access-Control-Allow-Private-Network: true` should be emitted.
    pub fn allow_private_network(&self) -> bool {
        self.config.allow_private_network
    }

    /// Returns the effective RAM ceiling in bytes.
    pub fn max_memory_bytes(&self) -> usize {
        self.inner.max_memory_bytes
    }

    /// Strict CORS origin allowlist check. Never returns `"*"` or `"null"`, even if misconfigured.
    pub fn cors_origin_for(&self, origin: Option<&str>) -> Option<&str> {
        let req_origin = origin?.trim();
        if req_origin.is_empty()
            || req_origin == "*"
            || req_origin.eq_ignore_ascii_case("null")
            || req_origin.bytes().any(|b| b <= 0x20 || b == 0x7f)
        {
            return None;
        }
        for allowed in &self.config.allowed_origins {
            let candidate = allowed.trim().trim_end_matches('/');
            if candidate.is_empty()
                || candidate == "*"
                || candidate.eq_ignore_ascii_case("null")
                || candidate.bytes().any(|b| b <= 0x20 || b == 0x7f)
                || (!candidate.starts_with("https://") && !candidate.starts_with("http://"))
            {
                continue;
            }
            if candidate == req_origin {
                return Some(candidate);
            }
        }
        None
    }

    /// Applies fail-closed CORS (and optional Chrome PNA) headers onto an HTTP response `HeaderMap`.
    ///
    /// Returns `true` if `origin` matched the allowlist and headers were added.
    pub fn apply_cors_headers(&self, origin: Option<&str>, headers: &mut HeaderMap) -> bool {
        headers.insert(VARY, HeaderValue::from_static("Origin"));
        let Some(allowed) = self.cors_origin_for(origin) else {
            return false;
        };
        if let Ok(val) = HeaderValue::from_str(allowed) {
            headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, val);
        }
        if self.config.allow_private_network {
            headers.insert(
                HeaderName::from_static("access-control-allow-private-network"),
                HeaderValue::from_static("true"),
            );
        }
        true
    }

    /// Performs fast constant-time stateless HMAC-SHA256 verification of `postCap` or `subCap`.
    ///
    /// Designed to be called **before** reading or allocating HTTP request body bytes (~2 µs
    /// rejection path). Returns the token's `expires_at_ms` on success.
    pub fn verify_capability(
        &self,
        drop_id: &str,
        token: &str,
        expected_role: DropCapRole,
        now_ms: i64,
    ) -> Result<i64, DropRelayError> {
        if !self.config.enabled {
            return Err(DropRelayError::Disabled);
        }
        if !is_valid_drop_id(drop_id) {
            return Err(DropRelayError::Unauthorized(
                "invalid drop_id format".into(),
            ));
        }
        let mut keys = self
            .inner
            .keys
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        keys.verify(drop_id, token, expected_role, now_ms)
    }

    /// Allocates a new ephemeral blind drop slot and returns stateless `postCap` & `subCap` tokens.
    pub fn create_drop(
        &self,
        creator_node_id: &str,
        client_ip: &str,
        req: CreateDropRequest,
        now_ms: i64,
    ) -> Result<CreateDropResponse, DropRelayError> {
        if !self.config.enabled {
            return Err(DropRelayError::Disabled);
        }

        let creator = creator_node_id.trim();
        if creator.is_empty() || creator.len() > MAX_CREATOR_NODE_ID_LEN {
            return Err(DropRelayError::BadRequest("invalid creator_node_id".into()));
        }

        let ip_key = normalize_ip(client_ip);

        if self.config.local_drops_only {
            if let Some(local_id) = self.inner.local_node_id.as_deref() {
                if creator != local_id {
                    return Err(DropRelayError::Forbidden(
                        "relay only accepts drops created by its local node".into(),
                    ));
                }
            }
            if let Some(target) = req.target_node_id.as_deref() {
                if target.trim() != creator {
                    return Err(DropRelayError::Forbidden(
                        "relay only accepts self-targeted drops".into(),
                    ));
                }
            }
        }

        let effective_max_ttl = self.config.effective_max_ttl_seconds();
        let ttl_secs = req
            .ttl_seconds
            .unwrap_or(self.config.default_ttl_seconds)
            .clamp(1, effective_max_ttl);
        let expires_at_ms = now_ms.saturating_add((ttl_secs as i64).saturating_mul(1_000));
        let configured_max_items = self.config.max_items_per_drop.max(1);
        let max_items = req
            .max_items
            .unwrap_or(configured_max_items)
            .clamp(1, configured_max_items);

        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // 1. Check per-node active drop cap (sweep expired slots first before rejecting).
        let max_per_node = self.config.max_active_drops_per_node;
        let current_node_active = state
            .per_node_active_drops
            .get(creator)
            .copied()
            .unwrap_or(0);
        if current_node_active >= max_per_node {
            state.sweep_expired_locked(now_ms);
            let after_sweep = state
                .per_node_active_drops
                .get(creator)
                .copied()
                .unwrap_or(0);
            if after_sweep >= max_per_node {
                let retry_after_secs = state.earliest_expiry_retry_after(now_ms, Some(creator));
                return Err(DropRelayError::RateLimited {
                    reason: format!("per-node active drop limit ({max_per_node}) reached"),
                    retry_after_secs,
                });
            }
        }

        // 2. Check per-node hourly sliding-window rate limit.
        let cutoff = now_ms.saturating_sub(CREATE_RATE_WINDOW_MS);
        let max_node_per_hr = self.config.creates_per_hour_per_node as usize;
        if let Some(window) = state.node_create_window.get_mut(creator) {
            prune_window(window, cutoff);
            if window.len() >= max_node_per_hr {
                let retry_after_secs = window
                    .front()
                    .map(|&oldest| {
                        ms_until_retry_secs(oldest.saturating_add(CREATE_RATE_WINDOW_MS), now_ms)
                    })
                    .unwrap_or(1);
                return Err(DropRelayError::RateLimited {
                    reason: format!(
                        "per-node hourly drop creation limit ({max_node_per_hr}/hr) exceeded"
                    ),
                    retry_after_secs,
                });
            }
        } else if max_node_per_hr == 0 {
            return Err(DropRelayError::RateLimited {
                reason: "per-node hourly drop creation limit (0/hr) exceeded".into(),
                retry_after_secs: 3600,
            });
        }

        // 3. Check per-IP hourly sliding-window rate limit.
        let max_ip_per_hr = self.config.creates_per_hour_per_ip as usize;
        if let Some(window) = state.ip_create_window.get_mut(&ip_key) {
            prune_window(window, cutoff);
            if window.len() >= max_ip_per_hr {
                let retry_after_secs = window
                    .front()
                    .map(|&oldest| {
                        ms_until_retry_secs(oldest.saturating_add(CREATE_RATE_WINDOW_MS), now_ms)
                    })
                    .unwrap_or(1);
                return Err(DropRelayError::RateLimited {
                    reason: format!(
                        "per-IP hourly drop creation limit ({max_ip_per_hr}/hr) exceeded"
                    ),
                    retry_after_secs,
                });
            }
        } else if max_ip_per_hr == 0 {
            return Err(DropRelayError::RateLimited {
                reason: "per-IP hourly drop creation limit (0/hr) exceeded".into(),
                retry_after_secs: 3600,
            });
        }

        // 4. Check global active drops cap: sweep expired first, NEVER evict honest live drops!
        let max_global = self.config.max_active_drops;
        if state.slots.len() >= max_global {
            state.sweep_expired_locked(now_ms);
            if state.slots.len() >= max_global {
                let retry_after_secs = state.earliest_expiry_retry_after(now_ms, None);
                return Err(DropRelayError::CapacityExceeded {
                    reason: format!("global active drop limit ({max_global}) reached"),
                    retry_after_secs,
                });
            }
        }

        // Opportunistically bound rate-limit map cardinality under churn.
        if state.ip_create_window.len() > RATE_TABLE_PRUNE_THRESHOLD {
            prune_rate_map(&mut state.ip_create_window, cutoff);
        }
        if state.node_create_window.len() > RATE_TABLE_PRUNE_THRESHOLD {
            prune_rate_map(&mut state.node_create_window, cutoff);
        }

        // 5. Generate CSPRNG 128-bit drop_id and mint stateless postCap + subCap.
        let (drop_id, post_cap, sub_cap) = {
            let mut keys = self
                .inner
                .keys
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut candidate = keys.random_drop_id()?;
            while state.slots.contains_key(&candidate) {
                candidate = keys.random_drop_id()?;
            }
            let post_cap = keys.mint(&candidate, DropCapRole::Post, expires_at_ms, now_ms)?;
            let sub_cap = keys.mint(&candidate, DropCapRole::Sub, expires_at_ms, now_ms)?;
            (candidate, post_cap, sub_cap)
        };

        // Broadcast channel sized strictly above `max_items` so subscribers never lag within a slot.
        let (tx, _rx) = broadcast::channel(max_items.saturating_add(4));
        let slot = DropSlot {
            creator_node_id: creator.to_string(),
            expires_at_ms,
            burn_after_read: req.burn_after_read,
            max_items,
            next_seq: 1,
            highest_acked_seq: 0,
            items: VecDeque::with_capacity(max_items.min(16)),
            buffered_bytes: 0,
            tx,
        };

        state.slots.insert(drop_id.clone(), slot);
        *state
            .per_node_active_drops
            .entry(creator.to_string())
            .or_insert(0) += 1;
        state
            .node_create_window
            .entry(creator.to_string())
            .or_default()
            .push_back(now_ms);
        state
            .ip_create_window
            .entry(ip_key)
            .or_default()
            .push_back(now_ms);
        state.drops_created_total = state.drops_created_total.saturating_add(1);

        Ok(CreateDropResponse {
            drop_id,
            expires_at_ms,
            post_cap,
            sub_cap,
            max_payload_bytes: self.config.max_payload_bytes,
            max_items,
        })
    }

    /// Appends an opaque ciphertext payload into an existing drop slot's RAM FIFO and wakes all
    /// live SSE subscribers.
    ///
    /// Wraps `payload` in `Zeroizing<Vec<u8>>` immediately so even rejected payloads are zeroized
    /// on drop.
    pub fn post_drop(
        &self,
        drop_id: &str,
        post_cap: &str,
        payload: Vec<u8>,
        now_ms: i64,
    ) -> Result<PostDropResponse, DropRelayError> {
        let payload = Zeroizing::new(payload);

        // Verify capability constant-time BEFORE checking slot state or accounting.
        self.verify_capability(drop_id, post_cap, DropCapRole::Post, now_ms)?;

        if payload.is_empty() {
            return Err(DropRelayError::BadRequest(
                "drop payload must not be empty".into(),
            ));
        }

        let payload_len = payload.len();
        if payload_len > self.config.max_payload_bytes {
            return Err(DropRelayError::PayloadTooLarge {
                size: payload_len,
                max_bytes: self.config.max_payload_bytes,
            });
        }

        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Verify slot exists and is not expired.
        let (slot_expired, slot_full, slot_max_items, slot_expires_at_ms) =
            match state.slots.get(drop_id) {
                None => return Err(DropRelayError::NotFound),
                Some(slot) => (
                    now_ms >= slot.expires_at_ms,
                    slot.next_seq > slot.max_items as u64 || slot.items.len() >= slot.max_items,
                    slot.max_items,
                    slot.expires_at_ms,
                ),
            };

        if slot_expired {
            let _ = state.remove_slot_locked(drop_id);
            return Err(DropRelayError::Expired);
        }

        if slot_full {
            return Err(DropRelayError::DropFull {
                max_items: slot_max_items,
            });
        }

        // Enforce global RAM ceiling: sweep expired slots first; NEVER evict honest live drops!
        if state.total_buffered_bytes.saturating_add(payload_len) > self.inner.max_memory_bytes {
            state.sweep_expired_locked(now_ms);
            if state.total_buffered_bytes.saturating_add(payload_len) > self.inner.max_memory_bytes
            {
                let retry_after_secs = state.earliest_expiry_retry_after(now_ms, None);
                return Err(DropRelayError::CapacityExceeded {
                    reason: format!(
                        "global RAM limit ({} bytes) reached",
                        self.inner.max_memory_bytes
                    ),
                    retry_after_secs,
                });
            }
        }

        let slot = state
            .slots
            .get_mut(drop_id)
            .ok_or(DropRelayError::NotFound)?;
        let seq = slot.next_seq;
        slot.next_seq = slot.next_seq.saturating_add(1);

        let item = DropItem {
            seq,
            payload: Arc::new(payload),
            received_at_ms: now_ms,
        };

        slot.items.push_back(item.clone());
        slot.buffered_bytes = slot.buffered_bytes.saturating_add(payload_len);
        let _ = slot.tx.send(item);

        state.total_buffered_bytes = state.total_buffered_bytes.saturating_add(payload_len);

        Ok(PostDropResponse {
            seq,
            expires_at_ms: slot_expires_at_ms,
        })
    }

    /// Subscribes to a drop slot with atomic late-subscriber catch-up (`seq > last_event_id`) and
    /// RAII SSE stream concurrency accounting.
    pub fn subscribe_drop(
        &self,
        drop_id: &str,
        sub_cap_or_creator: DropSubscriberAuth<'_>,
        client_ip: &str,
        last_event_id: Option<u64>,
        now_ms: i64,
    ) -> Result<DropSubscription, DropRelayError> {
        if !self.config.enabled {
            return Err(DropRelayError::Disabled);
        }
        if !is_valid_drop_id(drop_id) {
            return Err(DropRelayError::Unauthorized(
                "invalid drop_id format".into(),
            ));
        }

        // Verify stateless subCap BEFORE touching shared state.
        if let DropSubscriberAuth::SubCap(token) = sub_cap_or_creator {
            self.verify_capability(drop_id, token, DropCapRole::Sub, now_ms)?;
        }

        let ip_key = normalize_ip(client_ip);

        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let slot_expired = match state.slots.get(drop_id) {
            None => return Err(DropRelayError::NotFound),
            Some(slot) => {
                if let DropSubscriberAuth::CreatorNode(node_id) = sub_cap_or_creator {
                    if slot.creator_node_id != node_id.trim() {
                        return Err(DropRelayError::Unauthorized(
                            "caller node is not the creator of this drop".into(),
                        ));
                    }
                }
                now_ms >= slot.expires_at_ms
            }
        };

        if slot_expired {
            let _ = state.remove_slot_locked(drop_id);
            return Err(DropRelayError::Expired);
        }

        // Enforce SSE concurrency limits (per-drop, per-IP, global).
        let per_drop_count = state
            .per_drop_sse_streams
            .get(drop_id)
            .copied()
            .unwrap_or(0);
        if per_drop_count >= self.config.max_sse_streams_per_drop {
            return Err(DropRelayError::RateLimited {
                reason: format!(
                    "per-drop SSE stream limit ({}) reached",
                    self.config.max_sse_streams_per_drop
                ),
                retry_after_secs: 5,
            });
        }

        let per_ip_count = state.per_ip_sse_streams.get(&ip_key).copied().unwrap_or(0);
        if per_ip_count >= self.config.max_sse_streams_per_ip {
            return Err(DropRelayError::RateLimited {
                reason: format!(
                    "per-IP SSE stream limit ({}) reached",
                    self.config.max_sse_streams_per_ip
                ),
                retry_after_secs: 5,
            });
        }

        if state.active_sse_streams >= self.config.max_sse_streams {
            return Err(DropRelayError::CapacityExceeded {
                reason: format!(
                    "global SSE stream limit ({}) reached",
                    self.config.max_sse_streams
                ),
                retry_after_secs: 5,
            });
        }

        // Atomically snapshot catch-up backlog AND subscribe to live broadcast under the SAME lock!
        let min_seq = last_event_id.unwrap_or(0);
        let slot = state.slots.get(drop_id).ok_or(DropRelayError::NotFound)?;
        let backlog: VecDeque<DropItem> = slot
            .items
            .iter()
            .filter(|item| item.seq > min_seq)
            .cloned()
            .collect();
        let last_seq = backlog.back().map(|i| i.seq).unwrap_or(min_seq);
        let expires_at_ms = slot.expires_at_ms;
        let live_rx = slot.tx.subscribe();

        state.active_sse_streams = state.active_sse_streams.saturating_add(1);
        *state
            .per_drop_sse_streams
            .entry(drop_id.to_string())
            .or_insert(0) += 1;
        *state.per_ip_sse_streams.entry(ip_key.clone()).or_insert(0) += 1;

        Ok(DropSubscription {
            drop_id: drop_id.to_string(),
            expires_at_ms,
            backlog,
            last_seq,
            live_rx,
            _guard: DropStreamGuard {
                inner: Arc::clone(&self.inner),
                drop_id: drop_id.to_string(),
                client_ip: ip_key,
            },
        })
    }

    /// Acknowledges delivery of items up to `seq`.
    ///
    /// When `burn == true`, immediately removes and zeroizes all buffered items with `seq <= ack`,
    /// decrements `buffered_bytes`, and if the slot was created with `burn_after_read == true` and
    /// is now empty, closes and deletes the slot immediately.
    pub fn ack_drop(
        &self,
        drop_id: &str,
        auth: DropSubscriberAuth<'_>,
        seq: u64,
        burn: bool,
        now_ms: i64,
    ) -> Result<AckDropResponse, DropRelayError> {
        if !self.config.enabled {
            return Err(DropRelayError::Disabled);
        }
        if !is_valid_drop_id(drop_id) {
            return Err(DropRelayError::Unauthorized(
                "invalid drop_id format".into(),
            ));
        }

        if let DropSubscriberAuth::SubCap(token) = auth {
            self.verify_capability(drop_id, token, DropCapRole::Sub, now_ms)?;
        }

        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let slot_expired = match state.slots.get(drop_id) {
            None => return Err(DropRelayError::NotFound),
            Some(slot) => {
                if let DropSubscriberAuth::CreatorNode(node_id) = auth {
                    if slot.creator_node_id != node_id.trim() {
                        return Err(DropRelayError::Unauthorized(
                            "caller node is not the creator of this drop".into(),
                        ));
                    }
                }
                now_ms >= slot.expires_at_ms
            }
        };

        if slot_expired {
            let _ = state.remove_slot_locked(drop_id);
            return Err(DropRelayError::Expired);
        }

        let (acked_seq, burned_items, burned_bytes, remaining_items, should_close, newly_delivered) = {
            let slot = state
                .slots
                .get_mut(drop_id)
                .ok_or(DropRelayError::NotFound)?;

            let max_posted_seq = slot.next_seq.saturating_sub(1);
            let effective_seq = seq.min(max_posted_seq);
            let newly_delivered = effective_seq.saturating_sub(slot.highest_acked_seq);
            if effective_seq > slot.highest_acked_seq {
                slot.highest_acked_seq = effective_seq;
            }

            let mut burned_items = 0usize;
            let mut burned_bytes = 0usize;
            if burn && seq > 0 {
                while let Some(front) = slot.items.front() {
                    if front.seq <= seq {
                        if let Some(removed) = slot.items.pop_front() {
                            let len = removed.payload.len();
                            burned_items += 1;
                            burned_bytes = burned_bytes.saturating_add(len);
                            slot.buffered_bytes = slot.buffered_bytes.saturating_sub(len);
                            drop(removed);
                        }
                    } else {
                        break;
                    }
                }
            }

            let remaining_items = slot.items.len();
            let should_close =
                burn && slot.burn_after_read && remaining_items == 0 && effective_seq > 0;
            (
                effective_seq,
                burned_items,
                burned_bytes,
                remaining_items,
                should_close,
                newly_delivered,
            )
        };

        state.total_buffered_bytes = state.total_buffered_bytes.saturating_sub(burned_bytes);
        state.drops_delivered_total = state.drops_delivered_total.saturating_add(newly_delivered);

        let slot_closed = if should_close {
            state.remove_slot_locked(drop_id).is_some()
        } else {
            false
        };

        Ok(AckDropResponse {
            acked_seq,
            burned_items,
            burned_bytes,
            remaining_items,
            slot_closed,
        })
    }

    /// Sweeps all expired drop slots as of `now_ms`, zeroizing buffered payloads and reclaiming RAM
    /// and per-node slot counts. Returns the number of expired slots removed.
    pub fn sweep_expired(&self, now_ms: i64) -> usize {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.sweep_expired_locked(now_ms)
    }

    /// Returns aggregate-only relay health counters as of `now_ms` (after sweeping expired slots).
    pub fn health(&self, now_ms: i64) -> DropRelayHealth {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.sweep_expired_locked(now_ms);
        DropRelayHealth {
            enabled: self.config.enabled,
            active_drops: state.slots.len(),
            buffered_bytes: state.total_buffered_bytes,
            max_memory_bytes: self.inner.max_memory_bytes,
            active_sse_streams: state.active_sse_streams,
            drops_created_total: state.drops_created_total,
            drops_delivered_total: state.drops_delivered_total,
        }
    }
}

/// Active SSE subscription returned by [`DropRelay::subscribe_drop`].
///
/// Yields all buffered catch-up items (`seq > Last-Event-ID`) in exact sequence order before
/// streaming live arrivals, with zero gaps or duplicates. Dropping this subscription releases
/// global, per-drop, and per-IP SSE stream counters cleanly via RAII.
pub struct DropSubscription {
    drop_id: String,
    expires_at_ms: i64,
    backlog: VecDeque<DropItem>,
    last_seq: u64,
    live_rx: broadcast::Receiver<DropItem>,
    _guard: DropStreamGuard,
}

impl fmt::Debug for DropSubscription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DropSubscription")
            .field("drop_id", &"[REDACTED]")
            .field("expires_at_ms", &self.expires_at_ms)
            .field("backlog_len", &self.backlog.len())
            .field("last_seq", &self.last_seq)
            .finish()
    }
}

impl DropSubscription {
    /// Returns the subscribed `drop_id`.
    pub fn drop_id(&self) -> &str {
        &self.drop_id
    }

    /// Returns the drop's expiration timestamp in milliseconds since Unix epoch.
    pub fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }

    /// Returns the number of catch-up backlog items remaining to be yielded before live streaming.
    pub fn backlog_len(&self) -> usize {
        self.backlog.len()
    }

    /// Synchronously drains all pending catch-up backlog items in ascending `seq` order.
    pub fn drain_backlog(&mut self) -> Vec<DropItem> {
        let mut out = Vec::with_capacity(self.backlog.len());
        while let Some(item) = self.backlog.pop_front() {
            if item.seq > self.last_seq {
                self.last_seq = item.seq;
            }
            out.push(item);
        }
        out
    }

    /// Non-blocking receive: yields the next catch-up item or an already-queued live item if any.
    pub fn try_recv(&mut self) -> Option<DropItem> {
        if let Some(item) = self.backlog.pop_front() {
            if item.seq > self.last_seq {
                self.last_seq = item.seq;
            }
            return Some(item);
        }

        loop {
            match self.live_rx.try_recv() {
                Ok(item) => {
                    if item.seq <= self.last_seq {
                        continue;
                    }
                    self.last_seq = item.seq;
                    return Some(item);
                }
                Err(broadcast::error::TryRecvError::Lagged(_)) => {
                    self.refill_backlog_after_lag();
                    if let Some(item) = self.backlog.pop_front() {
                        if item.seq > self.last_seq {
                            self.last_seq = item.seq;
                        }
                        return Some(item);
                    }
                }
                Err(
                    broadcast::error::TryRecvError::Empty | broadcast::error::TryRecvError::Closed,
                ) => return None,
            }
        }
    }

    /// Asynchronously receives the next drop item (catch-up backlog first, then live arrivals).
    ///
    /// Returns `None` once the drop slot is closed (burned-after-read or swept on expiration) and
    /// all queued items have been drained.
    pub async fn recv(&mut self) -> Option<DropItem> {
        if let Some(item) = self.backlog.pop_front() {
            if item.seq > self.last_seq {
                self.last_seq = item.seq;
            }
            return Some(item);
        }

        loop {
            match self.live_rx.recv().await {
                Ok(item) => {
                    if item.seq <= self.last_seq {
                        continue;
                    }
                    self.last_seq = item.seq;
                    return Some(item);
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    self.refill_backlog_after_lag();
                    if let Some(item) = self.backlog.pop_front() {
                        if item.seq > self.last_seq {
                            self.last_seq = item.seq;
                        }
                        return Some(item);
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return None,
            }
        }
    }

    fn refill_backlog_after_lag(&mut self) {
        let state = self
            ._guard
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(slot) = state.slots.get(&self.drop_id) {
            for item in &slot.items {
                if item.seq > self.last_seq {
                    self.backlog.push_back(item.clone());
                }
            }
        }
    }
}

struct DropStreamGuard {
    inner: Arc<DropRelayInner>,
    drop_id: String,
    client_ip: String,
}

impl Drop for DropStreamGuard {
    fn drop(&mut self) {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.active_sse_streams = state.active_sse_streams.saturating_sub(1);

        if let Some(count) = state.per_drop_sse_streams.get_mut(&self.drop_id) {
            if *count <= 1 {
                state.per_drop_sse_streams.remove(&self.drop_id);
            } else {
                *count -= 1;
            }
        }

        if let Some(count) = state.per_ip_sse_streams.get_mut(&self.client_ip) {
            if *count <= 1 {
                state.per_ip_sse_streams.remove(&self.client_ip);
            } else {
                *count -= 1;
            }
        }
    }
}

fn normalize_ip(client_ip: &str) -> String {
    let trimmed = client_ip.trim();
    if trimmed.is_empty() {
        "unknown".to_string()
    } else {
        trimmed.to_string()
    }
}
