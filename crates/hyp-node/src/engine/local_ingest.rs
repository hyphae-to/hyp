//! Default-enabled socket-only local event ingestion route (`<state_dir>/ingest.sock` on Unix,
//! loopback TCP + `0600` `<state_dir>/ingest.addr` with constant-time bearer token on Windows).
//!
//! Architecture & security invariants:
//! - **Socket-only (NO FIFO pipe):** avoids blocking writers, framing corruption, and multi-writer
//!   interleaving.
//! - **Strict local-only permissions:** `0700` parent directory and `0600` socket / atomic `.addr`
//!   file; loopback TCP client and server strictly reject non-loopback IPs and validate the
//!   32-byte CSPRNG bearer token in constant time (length-hiding ephemeral-key HMAC-SHA256).
//! - **Bounded framing & DoS defense:** max 64 KiB NDJSON lines, 5 s read timeout per line,
//!   max 64 concurrent connections.
//! - **Composable route policy:** `allowed_types`, `allowed_topics`, CloudEvents Filter AST,
//!   `max_payload_bytes`, per-route `TokenBucket` (`Drop` or `Coalesce`), optional Ed25519
//!   `hyphaesig` verification against active `human_authorities` (always fail-closed when present;
//!   upgrades to `TrustTier::HumanVerified`), and `SecurityGatePipeline` screening before
//!   publishing onto `local.<topic>`.

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
#[cfg(unix)]
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hyp_crypto::human::verify_local_ingest_event;
use hyp_crypto::rfc3339::format_rfc3339_millis;
use hyp_crypto::{OkpJwk as CryptoOkpJwk, constant_time_eq};
use hyp_proto::address::is_valid_topic;
use hyp_proto::cloudevent::{
    CONTENT_TYPE_JSON, CloudEvent, CloudEventLimits, EXT_LOCAL_EVENT_SIG, MAX_ATTRIBUTE_CHARS,
    TYPE_SCHEDULED_MESSAGE_V1, check_cloudevent_v2_with_limits, is_extension_name,
    is_valid_rfc3339_strict,
};
use hyp_proto::jcs::to_jcs_string;
use hyp_store::{
    GateAuditInput, GateDecision as StoreGateDecision, GateDirection, HumanAuthorityRecord,
    MailboxKind, MailboxPutOptions, now_ms, sha256_hex, uuid_v4,
};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use thiserror::Error;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
#[cfg(unix)]
use tokio::net::UnixStream;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::delivery::{DeliveryUrgency, urgency_cap_gate_reason};
use crate::engine::config::NodeError;
pub use crate::engine::config::{
    DEFAULT_LOCAL_INGEST_BURST, DEFAULT_LOCAL_INGEST_MAX_PAYLOAD_BYTES,
    DEFAULT_LOCAL_INGEST_MAX_PER_MINUTE, DEFAULT_LOCAL_INGEST_ROUTE_ID, DEFAULT_LOCAL_INGEST_TOPIC,
    LocalIngestConfig, LocalIngestLimitAction, LocalIngestRoute,
};
use crate::engine::node::UnifiedNode;
use crate::gates::{
    GateDecision, InboundContext, RateLimitConfig, SecurityGatePipeline, TokenBucket, TrustTier,
    VerifiedHumanClaim,
};

/// Maximum NDJSON line size accepted on `ingest.sock` / loopback TCP (64 KiB).
pub const MAX_LOCAL_INGEST_LINE_BYTES: usize = 64 * 1024;

/// Strict per-line read timeout so hung local writers cannot stall the daemon.
pub const LOCAL_INGEST_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Maximum concurrent client connections accepted simultaneously by [`LocalIngestServer`].
pub const LOCAL_INGEST_MAX_CONCURRENT_CONNS: usize = 64;

/// Maximum accepted `ttlSeconds` hint (30 days) to prevent arithmetic overflow.
const MAX_TTL_SECONDS: u64 = 30 * 24 * 60 * 60;

/// Maximum `.addr` JSON descriptor file size read by the client (4 KiB).
const MAX_ADDR_FILE_BYTES: u64 = 4096;

/// Successful ingestion receipt returned by [`LocalIngestServer::ingest_local_event`] and
/// written as one compact NDJSON line per accepted request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalIngestOutcome {
    pub ok: bool,
    pub id: String,
    /// Qualified local topic (`"local.<topic>"`, e.g. `"local.schedule"`).
    pub topic: String,
    /// Matched [`LocalIngestRoute::id`].
    pub route: String,
    /// Effective trust tier (`"human-verified"` or `"external-webhook"`).
    pub trust_tier: String,
    /// Verified human authority `kid` when `hyphaesig` was verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_human_kid: Option<String>,
    /// Verified human authority `human_id` when `hyphaesig` was verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verified_human_id: Option<String>,
    /// Number of subscriptions matched in `EventStore`.
    pub matched_subscribers: usize,
    /// Number of local session mailboxes immediately woken/delivered.
    pub delivered_sessions: usize,
    /// Terminal decision (`"allow"`).
    pub decision: String,
    /// `true` when the route token bucket was saturated and `on_limit = Coalesce` collapsed this event.
    #[serde(default)]
    pub coalesced: bool,
    /// Effective mailbox coalesce key applied to delivered items, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coalesce_key: Option<String>,
    /// `true` if the Security Gate downgraded delivery urgency to `notify`.
    #[serde(default)]
    pub downgraded_to_notify: bool,
    /// `true` if the Security Gate capped delivery urgency at `queue` (RFC 0004 Stage 1 default).
    #[serde(default)]
    pub capped_to_queue: bool,
    /// Monotonic `gate_audit` sequence number, if an audit row was written.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_seq: Option<i64>,
    /// `true` if `EventStore` deduplicated an already-known event ID.
    #[serde(default)]
    pub deduplicated: bool,
}

impl LocalIngestOutcome {
    /// Serializes this receipt into a wire JSON value.
    pub fn to_json_receipt(&self) -> Value {
        serde_json::to_value(self).unwrap_or_else(|_| {
            json!({
                "ok": true,
                "id": self.id,
                "topic": self.topic,
                "route": self.route,
                "trustTier": self.trust_tier,
                "matchedSubscribers": self.matched_subscribers,
                "decision": self.decision,
            })
        })
    }
}

/// Fail-closed error returned by [`LocalIngestServer::ingest_local_event`] or
/// [`send_local_ingest_event`].
#[derive(Debug, Error)]
pub enum LocalIngestError {
    #[error("invalid_event: {0}")]
    InvalidEvent(String),

    #[error("invalid_topic: '{0}' is not a valid local topic")]
    InvalidTopic(String),

    #[error("route_denied: no local ingest route permits type '{event_type}' on topic '{topic}'")]
    RouteDenied { topic: String, event_type: String },

    #[error(
        "filter_rejected: event type '{event_type}' on topic '{topic}' did not match route filters"
    )]
    FilterRejected { topic: String, event_type: String },

    #[error("payload_too_large: {actual} bytes exceeds route limit {max} bytes")]
    PayloadTooLarge { actual: usize, max: usize },

    #[error("unauthorized: route '{route_id}' requires a valid hyphaesig Ed25519 signature")]
    SignatureRequired { route_id: String },

    #[error("invalid_signature: {0}")]
    InvalidSignature(String),

    #[error("rate_limited: route '{route_id}' saturated (retry after {retry_after_ms}ms)")]
    RateLimited {
        route_id: String,
        retry_after_ms: u64,
    },

    #[error("gate_blocked: {reason}")]
    GateBlocked {
        reason: String,
        stage: String,
        audit_seq: Option<i64>,
    },

    #[error("gate_quarantined: {reason}")]
    GateQuarantined {
        reason: String,
        stage: String,
        receipt: Option<String>,
        audit_seq: Option<i64>,
    },

    #[error("gate_hold: {reason} (retry after {retry_after_ms}ms)")]
    GateHold {
        reason: String,
        stage: String,
        retry_after_ms: u64,
    },

    #[error("gate_error: {0}")]
    GateError(String),

    #[error("node_error: {0}")]
    Node(#[from] NodeError),

    #[error("transport_error: {0}")]
    Transport(String),
}

impl LocalIngestError {
    /// Converts this error into a crisp, machine-readable JSON receipt line.
    pub fn to_json_receipt(&self) -> Value {
        match self {
            Self::InvalidEvent(msg) => json!({
                "ok": false,
                "error": "invalid_event",
                "message": msg,
            }),
            Self::InvalidTopic(topic) => json!({
                "ok": false,
                "error": "invalid_topic",
                "topic": topic,
                "message": self.to_string(),
            }),
            Self::RouteDenied { topic, event_type } => json!({
                "ok": false,
                "error": "route_denied",
                "topic": topic,
                "type": event_type,
                "message": self.to_string(),
            }),
            Self::FilterRejected { topic, event_type } => json!({
                "ok": false,
                "error": "filter_rejected",
                "topic": topic,
                "type": event_type,
                "message": self.to_string(),
            }),
            Self::PayloadTooLarge { actual, max } => json!({
                "ok": false,
                "error": "payload_too_large",
                "actualBytes": actual,
                "maxBytes": max,
                "message": self.to_string(),
            }),
            Self::SignatureRequired { route_id } => json!({
                "ok": false,
                "error": "signature_required",
                "code": "unauthorized",
                "route": route_id,
                "message": self.to_string(),
            }),
            Self::InvalidSignature(msg) => json!({
                "ok": false,
                "error": "invalid_signature",
                "code": "unauthorized",
                "message": msg,
            }),
            Self::RateLimited {
                route_id,
                retry_after_ms,
            } => json!({
                "ok": false,
                "error": "rate_limited",
                "action": "drop",
                "route": route_id,
                "retryAfterMs": retry_after_ms,
                "message": self.to_string(),
            }),
            Self::GateBlocked {
                reason,
                stage,
                audit_seq,
            } => json!({
                "ok": false,
                "error": "gate_blocked",
                "decision": "blocked",
                "reason": reason,
                "stage": stage,
                "auditSeq": audit_seq,
            }),
            Self::GateQuarantined {
                reason,
                stage,
                receipt,
                audit_seq,
            } => json!({
                "ok": false,
                "error": "gate_quarantined",
                "decision": "quarantined",
                "reason": reason,
                "stage": stage,
                "receipt": receipt,
                "auditSeq": audit_seq,
            }),
            Self::GateHold {
                reason,
                stage,
                retry_after_ms,
            } => json!({
                "ok": false,
                "error": "gate_hold",
                "decision": "hold",
                "reason": reason,
                "stage": stage,
                "retryAfterMs": retry_after_ms,
            }),
            Self::GateError(msg) => json!({
                "ok": false,
                "error": "gate_error",
                "decision": "blocked",
                "reason": msg,
            }),
            Self::Node(err) => json!({
                "ok": false,
                "error": "node_error",
                "message": err.to_string(),
            }),
            Self::Transport(msg) => json!({
                "ok": false,
                "error": "transport_error",
                "message": msg,
            }),
        }
    }
}

/// Builds the deterministic RFC 8785 JCS canonical JSON string of a CloudEvent WITHOUT its
/// `hyphaesig` extension attribute.
///
/// Exported publicly so `hyp emit --sign` and [`LocalIngestServer`] sign and verify bit-identical
/// bytes under `hyp_crypto::human::LOCAL_EVENT_SIG_DOMAIN`.
pub fn canonical_local_event_for_signing(event: &CloudEvent) -> Result<String, LocalIngestError> {
    let mut unsigned = event.clone();
    unsigned.extensions.remove(EXT_LOCAL_EVENT_SIG);
    let val = serde_json::to_value(&unsigned)
        .map_err(|e| LocalIngestError::InvalidEvent(format!("failed to serialize event: {e}")))?;
    to_jcs_string(&val)
        .map_err(|e| LocalIngestError::InvalidEvent(format!("failed to canonicalize event: {e}")))
}

#[derive(Debug, Deserialize, Serialize)]
struct LoopbackAddrFile {
    addr: String,
    token: String,
}

#[derive(Debug)]
struct NormalizedLocalEvent {
    topic: String,
    event: CloudEvent,
    payload_bytes: usize,
    coalesce_key: Option<String>,
    ttl_seconds: Option<u64>,
}

struct LocalIngestState {
    node: Arc<UnifiedNode>,
    gate: Arc<RwLock<Option<Arc<SecurityGatePipeline>>>>,
    config: LocalIngestConfig,
    routes: Vec<LocalIngestRoute>,
    buckets: Mutex<HashMap<usize, TokenBucket>>,
}

impl LocalIngestState {
    fn new(
        node: Arc<UnifiedNode>,
        gate: Arc<RwLock<Option<Arc<SecurityGatePipeline>>>>,
        config: LocalIngestConfig,
    ) -> Self {
        let routes = config.effective_routes();
        Self {
            node,
            gate,
            config,
            routes,
            buckets: Mutex::new(HashMap::new()),
        }
    }

    fn current_gate(&self) -> Option<Arc<SecurityGatePipeline>> {
        self.gate
            .read()
            .expect("local_ingest gate lock poisoned")
            .as_ref()
            .map(Arc::clone)
    }

    fn consume_route_bucket(
        &self,
        route_idx: usize,
        route: &LocalIngestRoute,
        now_ms: i64,
    ) -> Result<(), u64> {
        let Ok(mut map) = self.buckets.lock() else {
            return Err(5_000);
        };
        let bucket = map.entry(route_idx).or_insert_with(|| {
            TokenBucket::new(
                RateLimitConfig {
                    max_burst: route.burst,
                    refill_per_min: route.max_per_minute,
                },
                now_ms,
            )
        });
        bucket.try_consume(now_ms)
    }

    async fn ingest_local_event(
        &self,
        raw_json: &Value,
        gate: Option<&SecurityGatePipeline>,
        now_ms: i64,
    ) -> Result<LocalIngestOutcome, LocalIngestError> {
        // 1. Normalize into `(topic, CloudEvent)` + optional TTL / coalesce hints.
        let normalized =
            normalize_local_ingest_payload(raw_json, &self.config.default_topic, now_ms)?;
        let topic = normalized.topic;
        let event = normalized.event;

        // 2. Match first route whose `allowed_types`, `allowed_topics`, and `filters` ALL match.
        let mut type_and_topic_matched = false;
        let mut matched_route: Option<(usize, &LocalIngestRoute)> = None;
        for (idx, route) in self.routes.iter().enumerate() {
            if route.matches_type(&event.event_type) && route.matches_topic(&topic) {
                type_and_topic_matched = true;
                if route.matches_filters(&event) {
                    matched_route = Some((idx, route));
                    break;
                }
            }
        }
        let (route_idx, route) = match matched_route {
            Some(found) => found,
            None => {
                if type_and_topic_matched {
                    return Err(LocalIngestError::FilterRejected {
                        topic,
                        event_type: event.event_type,
                    });
                }
                return Err(LocalIngestError::RouteDenied {
                    topic,
                    event_type: event.event_type,
                });
            }
        };

        // 3. Enforce per-route payload byte ceiling fail-closed.
        if normalized.payload_bytes > route.max_payload_bytes {
            return Err(LocalIngestError::PayloadTooLarge {
                actual: normalized.payload_bytes,
                max: route.max_payload_bytes,
            });
        }

        // 4. Cryptographic signature verification (`hyphaesig`).
        //    ALWAYS verified fail-closed when present, even if `route.require_signature == false`.
        let (trust_tier, verified_authority) = self.verify_optional_signature(&event, route)?;

        // 5. Per-route frequency / burst token bucket (`Drop` vs `Coalesce`).
        let mut coalesced = false;
        if let Err(retry_after_ms) = self.consume_route_bucket(route_idx, route, now_ms) {
            match route.on_limit {
                LocalIngestLimitAction::Drop => {
                    return Err(LocalIngestError::RateLimited {
                        route_id: route.id.clone(),
                        retry_after_ms,
                    });
                }
                LocalIngestLimitAction::Coalesce => {
                    coalesced = true;
                }
            }
        }

        let effective_coalesce_key = normalized
            .coalesce_key
            .or_else(|| route.default_coalesce_key.clone())
            .or_else(|| {
                if route.on_limit == LocalIngestLimitAction::Coalesce || coalesced {
                    Some(format!("route:{}", route.id))
                } else {
                    None
                }
            });
        let effective_ttl_seconds = normalized.ttl_seconds.or(route.default_ttl_seconds);
        let expires_at = effective_ttl_seconds.map(|secs| {
            let clamped = secs.min(MAX_TTL_SECONDS) as i64;
            now_ms.saturating_add(clamped.saturating_mul(1_000))
        });

        let verified_claim = verified_authority.as_ref().map(|auth| VerifiedHumanClaim {
            human_id: auth.human_id.clone(),
            kid: auth.kid.clone(),
            role: auth.role.as_str().to_string(),
            claim_id: event.id.clone(),
            issued_at_ms: now_ms,
            expires_at_ms: expires_at.unwrap_or_else(|| now_ms.saturating_add(900_000)),
            kind: "local-ingest".to_string(),
        });

        // 6. Security Gate verification (`if route.gate` and `gate` is `Some(g)`).
        let mut audit_seq: Option<i64> = None;
        let mut gate_cap: Option<DeliveryUrgency> = None;
        let qualified_topic = format!("local.{topic}");

        if route.gate {
            if let Some(pipeline) = gate {
                let sender_label = match verified_authority.as_ref() {
                    Some(auth) => {
                        let kid8: String = auth.kid.chars().take(8).collect();
                        format!("human:{}:{}", auth.human_id, kid8)
                    }
                    None => event.source.clone(),
                };
                let ctx = InboundContext {
                    session_id: format!("local-ingest:{topic}"),
                    origin_node: self.node.node_id().to_string(),
                    sender: sender_label,
                    trust_tier,
                    e2ee_verified: trust_tier == TrustTier::HumanVerified,
                    identity_verified: trust_tier == TrustTier::HumanVerified,
                    kind: MailboxKind::Event,
                    channel: None,
                    topic: Some(topic.clone()),
                    bridge: None,
                    event: event.clone(),
                    transfer_paths: Vec::new(),
                    rendered_text: None,
                    human_auth: verified_claim.clone(),
                };
                let eval = pipeline
                    .screen_local_ingest(&ctx, now_ms)
                    .await
                    .map_err(|e| LocalIngestError::GateError(e.to_string()))?;
                audit_seq = eval.audit_seq;
                match eval.decision {
                    GateDecision::Allow { max_urgency } => gate_cap = max_urgency,
                    GateDecision::Block { reason } => {
                        return Err(LocalIngestError::GateBlocked {
                            reason,
                            stage: eval.stage,
                            audit_seq: eval.audit_seq,
                        });
                    }
                    GateDecision::Quarantine { reason, .. } => {
                        return Err(LocalIngestError::GateQuarantined {
                            reason,
                            stage: eval.stage,
                            receipt: eval.receipt,
                            audit_seq: eval.audit_seq,
                        });
                    }
                    GateDecision::Hold {
                        reason,
                        retry_after_ms,
                    } => {
                        return Err(LocalIngestError::GateHold {
                            reason,
                            stage: eval.stage,
                            retry_after_ms,
                        });
                    }
                }
            } else if let Some(ref auth) = verified_authority {
                // Even without an attached `SecurityGatePipeline`, record an immutable audit trail
                // whenever a human-verified signature upgraded trust on local ingest.
                let kid8: String = auth.kid.chars().take(8).collect();
                let payload_text = serde_json::to_string(&event).unwrap_or_default();
                let traceparent = event
                    .extensions
                    .get(hyp_proto::cloudevent::EXT_TRACEPARENT)
                    .and_then(Value::as_str)
                    .map(ToString::to_string);
                let seq = {
                    let db = self.node.db();
                    db.local()
                        .append_gate_audit(
                            &GateAuditInput {
                                direction: GateDirection::Inbound,
                                stage: "local_ingest".to_string(),
                                decision: StoreGateDecision::Allow,
                                origin_node: Some(self.node.node_id().to_string()),
                                source: Some(format!("human:{}:{}", auth.human_id, kid8)),
                                session_id: Some(format!("local-ingest:{topic}")),
                                receipt_id: None,
                                event_type: Some(event.event_type.clone()),
                                trust_tier: Some("human-verified".to_string()),
                                confidence: Some(1.0),
                                categories: vec![
                                    "gate.allowed".to_string(),
                                    "human.verified".to_string(),
                                    "local_ingest".to_string(),
                                ],
                                reason: None,
                                traceparent,
                                payload_sha256: sha256_hex(payload_text.as_bytes()),
                                reviewer: Some(format!("human:{}:{}", auth.human_id, kid8)),
                            },
                            now_ms,
                        )
                        .map_err(NodeError::from)?
                };
                audit_seq = Some(seq);
            }
        }

        // 7. Publish onto `UnifiedNode::publish_event` (`local.<topic>`) and flush matched local
        //    session subscribers immediately through the mailbox + `local_inbox_tx` wakeup path!
        let mut publish_event = event.clone();
        if coalesced {
            if let Some(Value::Object(ref mut data_map)) = publish_event.data {
                data_map.insert("coalesced".to_string(), Value::Bool(true));
                if let Some(ref key) = effective_coalesce_key {
                    data_map
                        .entry("coalesceKey".to_string())
                        .or_insert_with(|| Value::String(key.clone()));
                }
            }
        }

        let ingest_res = self
            .node
            .publish_event(&qualified_topic, publish_event)
            .await
            .map_err(|err| match err {
                NodeError::PayloadTooLarge(_)
                | NodeError::CloudEvent(hyp_proto::cloudevent::CloudEventError::TooLarge(_))
                | NodeError::Store(hyp_store::StoreError::TooLarge(_)) => {
                    LocalIngestError::PayloadTooLarge {
                        actual: normalized.payload_bytes,
                        max: route.max_payload_bytes,
                    }
                }
                other => LocalIngestError::Node(other),
            })?;

        let put_opts = MailboxPutOptions {
            coalesce_key: effective_coalesce_key.clone(),
            expires_at,
        };
        let delivered_sessions = self.node.deliver_local_topic_batches(
            &topic,
            &put_opts,
            verified_claim.as_ref(),
            urgency_cap_gate_reason(gate_cap),
            now_ms,
        )?;

        Ok(LocalIngestOutcome {
            ok: true,
            id: event.id,
            topic: qualified_topic,
            route: route.id.clone(),
            trust_tier: trust_tier.as_str().to_string(),
            verified_human_kid: verified_authority.as_ref().map(|a| a.kid.clone()),
            verified_human_id: verified_authority.as_ref().map(|a| a.human_id.clone()),
            matched_subscribers: ingest_res.matched,
            delivered_sessions,
            decision: "allow".to_string(),
            coalesced,
            coalesce_key: effective_coalesce_key,
            downgraded_to_notify: gate_cap == Some(DeliveryUrgency::Notify),
            capped_to_queue: gate_cap == Some(DeliveryUrgency::Queue),
            audit_seq,
            deduplicated: ingest_res.deduplicated,
        })
    }

    fn verify_optional_signature(
        &self,
        event: &CloudEvent,
        route: &LocalIngestRoute,
    ) -> Result<(TrustTier, Option<HumanAuthorityRecord>), LocalIngestError> {
        let Some(raw_sig) = event.extensions.get(EXT_LOCAL_EVENT_SIG) else {
            if route.require_signature {
                return Err(LocalIngestError::SignatureRequired {
                    route_id: route.id.clone(),
                });
            }
            return Ok((TrustTier::ExternalWebhook, None));
        };

        let Some(sig_str) = raw_sig.as_str() else {
            return Err(LocalIngestError::InvalidSignature(
                "hyphaesig extension must be a string".to_string(),
            ));
        };

        let canonical = canonical_local_event_for_signing(event)?;
        let mut matched_authority: Option<HumanAuthorityRecord> = None;

        let verified_kid = verify_local_ingest_event(sig_str, &canonical, |kid| {
            let db = self.node.db();
            let min_epoch = db.human().min_auth_epoch().ok()?;
            let rec = db.human().get_active_authority_by_kid(kid).ok()??;
            if rec.auth_epoch < min_epoch {
                return None;
            }
            let jwk: CryptoOkpJwk = serde_json::from_str(&rec.jwk_json).ok()?;
            let pk = jwk.to_ed25519().ok()?;
            matched_authority = Some(rec);
            Some(pk)
        })
        .map_err(|e| LocalIngestError::InvalidSignature(e.to_string()))?;

        let auth = matched_authority.ok_or_else(|| {
            LocalIngestError::InvalidSignature(format!(
                "verified kid '{verified_kid}' missing authority record"
            ))
        })?;
        Ok((TrustTier::HumanVerified, Some(auth)))
    }
}

/// Async NDJSON socket-only local event ingestion server.
///
/// - On Unix (`#[cfg(unix)]`): binds a `0600` Unix domain socket at `<state_dir>/ingest.sock`
///   (or loopback TCP + `0600` `.addr` file if the configured path has a `.addr` extension).
/// - On non-Unix (`#[cfg(not(unix))]`): binds a loopback `127.0.0.1:0` TCP listener and writes
///   an atomic `<state_dir>/ingest.addr` JSON file containing `{ "addr", "token" }`, enforcing
///   constant-time bearer token authentication on every connection.
pub struct LocalIngestServer {
    state: Arc<LocalIngestState>,
    endpoint_path: PathBuf,
    bound_tcp_addr: Option<SocketAddr>,
    shutdown_tx: watch::Sender<bool>,
    accept_handle: Option<JoinHandle<()>>,
    cleaned_up: Arc<AtomicBool>,
}

impl LocalIngestServer {
    /// Starts the local ingest server using `node.config().local_ingest`.
    pub async fn start_default(
        node: Arc<UnifiedNode>,
        gate: Option<Arc<SecurityGatePipeline>>,
    ) -> Result<Self, NodeError> {
        let cfg = node.config().local_ingest.clone();
        Self::start(node, gate, cfg).await
    }

    /// Starts the local ingest server with an explicit [`LocalIngestConfig`].
    pub async fn start(
        node: Arc<UnifiedNode>,
        gate: Option<Arc<SecurityGatePipeline>>,
        config: LocalIngestConfig,
    ) -> Result<Self, NodeError> {
        Self::start_with_shared_gate(node, Arc::new(RwLock::new(gate)), config).await
    }

    /// Starts the local ingest server sharing a live hot-reloadable [`SecurityGatePipeline`] slot.
    pub async fn start_with_shared_gate(
        node: Arc<UnifiedNode>,
        gate: Arc<RwLock<Option<Arc<SecurityGatePipeline>>>>,
        config: LocalIngestConfig,
    ) -> Result<Self, NodeError> {
        if !config.enabled {
            return Err(NodeError::BadRequest(
                "local ingest server is disabled in configuration".into(),
            ));
        }
        let endpoint_path = config.resolved_socket_path(&node.config().state_dir);
        ensure_private_parent_dir(&endpoint_path)?;

        let state = Arc::new(LocalIngestState::new(node, gate, config));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let cleaned_up = Arc::new(AtomicBool::new(false));

        #[cfg(unix)]
        {
            if is_addr_file_path(&endpoint_path) {
                return Self::start_loopback_tcp(
                    state,
                    endpoint_path,
                    shutdown_tx,
                    shutdown_rx,
                    cleaned_up,
                )
                .await;
            }
            Self::start_unix(state, endpoint_path, shutdown_tx, shutdown_rx, cleaned_up)
        }

        #[cfg(not(unix))]
        {
            Self::start_loopback_tcp(state, endpoint_path, shutdown_tx, shutdown_rx, cleaned_up)
                .await
        }
    }

    #[cfg(unix)]
    fn start_unix(
        state: Arc<LocalIngestState>,
        endpoint_path: PathBuf,
        shutdown_tx: watch::Sender<bool>,
        mut shutdown_rx: watch::Receiver<bool>,
        cleaned_up: Arc<AtomicBool>,
    ) -> Result<Self, NodeError> {
        prepare_unix_socket_path(&endpoint_path)?;
        let listener = crate::engine::private_socket::bind_private_unix_socket(&endpoint_path)?;

        let sem = Arc::new(Semaphore::new(LOCAL_INGEST_MAX_CONCURRENT_CONNS));
        let accept_state = Arc::clone(&state);
        let accept_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, _)) => {
                                spawn_connection_handler(
                                    stream,
                                    Arc::clone(&accept_state),
                                    None,
                                    Arc::clone(&sem),
                                );
                            }
                            Err(e) => {
                                if e.kind() == io::ErrorKind::Interrupted {
                                    continue;
                                }
                                tokio::time::sleep(Duration::from_millis(25)).await;
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            state,
            endpoint_path,
            bound_tcp_addr: None,
            shutdown_tx,
            accept_handle: Some(accept_handle),
            cleaned_up,
        })
    }

    async fn start_loopback_tcp(
        state: Arc<LocalIngestState>,
        endpoint_path: PathBuf,
        shutdown_tx: watch::Sender<bool>,
        mut shutdown_rx: watch::Receiver<bool>,
        cleaned_up: Arc<AtomicBool>,
    ) -> Result<Self, NodeError> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let bound_addr = listener.local_addr()?;
        let bearer_token = Arc::new(generate_bearer_token()?);

        write_atomic_addr_file(&endpoint_path, bound_addr, &bearer_token)?;

        let sem = Arc::new(Semaphore::new(LOCAL_INGEST_MAX_CONCURRENT_CONNS));
        let accept_state = Arc::clone(&state);
        let accept_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            break;
                        }
                    }
                    accepted = listener.accept() => {
                        match accepted {
                            Ok((stream, peer_addr)) => {
                                if !peer_addr.ip().is_loopback() {
                                    drop(stream);
                                    continue;
                                }
                                spawn_connection_handler(
                                    stream,
                                    Arc::clone(&accept_state),
                                    Some(Arc::clone(&bearer_token)),
                                    Arc::clone(&sem),
                                );
                            }
                            Err(e) => {
                                if e.kind() == io::ErrorKind::Interrupted {
                                    continue;
                                }
                                tokio::time::sleep(Duration::from_millis(25)).await;
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            state,
            endpoint_path,
            bound_tcp_addr: Some(bound_addr),
            shutdown_tx,
            accept_handle: Some(accept_handle),
            cleaned_up,
        })
    }

    /// Returns the filesystem path of the bound socket (`ingest.sock`) or loopback `.addr` file.
    pub fn endpoint_path(&self) -> &Path {
        &self.endpoint_path
    }

    /// Returns the bound loopback TCP socket address when running in `.addr` loopback mode.
    pub fn bound_tcp_addr(&self) -> Option<SocketAddr> {
        self.bound_tcp_addr
    }

    /// Evaluates, screens, and ingests a raw JSON local event payload through the full route
    /// evaluation pipeline (`normalize -> route match -> size -> hyphaesig -> token bucket ->
    /// SecurityGatePipeline -> UnifiedNode::publish_event -> local mailbox wakeups`).
    pub async fn ingest_local_event(
        &self,
        raw_json: &Value,
        gate: Option<&SecurityGatePipeline>,
        now_ms: i64,
    ) -> Result<LocalIngestOutcome, LocalIngestError> {
        self.state.ingest_local_event(raw_json, gate, now_ms).await
    }

    /// Gracefully stops the listener task and removes the socket / `.addr` file from disk.
    pub async fn stop(mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(handle) = self.accept_handle.take() {
            let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
        }
        self.cleanup_endpoint();
    }

    fn cleanup_endpoint(&self) {
        if !self.cleaned_up.swap(true, Ordering::SeqCst) {
            let _ = fs::remove_file(&self.endpoint_path);
        }
    }
}

impl Drop for LocalIngestServer {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(true);
        if let Some(handle) = self.accept_handle.take() {
            handle.abort();
        }
        self.cleanup_endpoint();
    }
}

// ============================================================================
// Cross-Platform Client Helper (`send_local_ingest_event`)
// ============================================================================

/// Sends a single local event payload (full CloudEvents v1.0 or compact shorthand JSON) over the
/// local ingest socket (`ingest.sock` on Unix) or loopback TCP descriptor (`ingest.addr` with
/// bearer token) and returns the parsed JSON receipt from the server.
pub async fn send_local_ingest_event(
    endpoint_path: &Path,
    payload: &Value,
) -> Result<Value, LocalIngestError> {
    tokio::time::timeout(
        LOCAL_INGEST_READ_TIMEOUT,
        send_local_ingest_event_inner(endpoint_path, payload),
    )
    .await
    .map_err(|_| LocalIngestError::Transport("local ingest request timed out".to_string()))?
}

async fn send_local_ingest_event_inner(
    endpoint_path: &Path,
    payload: &Value,
) -> Result<Value, LocalIngestError> {
    if let Some((addr, token)) = detect_loopback_addr_descriptor(endpoint_path)? {
        let stream = TcpStream::connect(addr).await.map_err(|e| {
            LocalIngestError::Transport(format!("failed to connect to {addr}: {e}"))
        })?;
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        if let Value::Object(mut obj) = payload.clone() {
            obj.insert("auth".to_string(), Value::String(token.to_string()));
            write_ndjson_line(&mut write_half, &Value::Object(obj)).await?;
        } else {
            let auth_line = json!({ "auth": token.as_str() });
            write_ndjson_line(&mut write_half, &auth_line).await?;
            let ack_line = read_bounded_line(&mut reader, MAX_LOCAL_INGEST_LINE_BYTES)
                .await?
                .ok_or_else(|| {
                    LocalIngestError::Transport("connection closed during bearer auth".to_string())
                })?;
            let ack: Value = serde_json::from_str(&ack_line).map_err(|e| {
                LocalIngestError::Transport(format!("invalid auth response JSON: {e}"))
            })?;
            if ack.get("ok").and_then(Value::as_bool) != Some(true) {
                return Ok(ack);
            }
            write_ndjson_line(&mut write_half, payload).await?;
        }

        let resp_line = read_bounded_line(&mut reader, MAX_LOCAL_INGEST_LINE_BYTES)
            .await?
            .ok_or_else(|| {
                LocalIngestError::Transport(
                    "local ingest server closed connection without receipt".to_string(),
                )
            })?;
        return serde_json::from_str(&resp_line).map_err(|e| {
            LocalIngestError::Transport(format!("invalid receipt JSON from local ingest: {e}"))
        });
    }

    #[cfg(unix)]
    {
        let stream = UnixStream::connect(endpoint_path).await.map_err(|e| {
            LocalIngestError::Transport(format!(
                "failed to connect to {}: {e}",
                endpoint_path.display()
            ))
        })?;
        let (read_half, mut write_half) = stream.into_split();
        write_ndjson_line(&mut write_half, payload).await?;
        let mut reader = BufReader::new(read_half);
        let resp_line = read_bounded_line(&mut reader, MAX_LOCAL_INGEST_LINE_BYTES)
            .await?
            .ok_or_else(|| {
                LocalIngestError::Transport(
                    "local ingest server closed connection without receipt".to_string(),
                )
            })?;
        serde_json::from_str(&resp_line).map_err(|e| {
            LocalIngestError::Transport(format!("invalid receipt JSON from local ingest: {e}"))
        })
    }

    #[cfg(not(unix))]
    {
        Err(LocalIngestError::Transport(format!(
            "no loopback ingest descriptor found at {}",
            endpoint_path.display()
        )))
    }
}

// ============================================================================
// Connection Handler & Bounded NDJSON Framing
// ============================================================================

fn spawn_connection_handler<S>(
    stream: S,
    state: Arc<LocalIngestState>,
    bearer_token: Option<Arc<Zeroizing<String>>>,
    sem: Arc<Semaphore>,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    match sem.try_acquire_owned() {
        Ok(permit) => {
            tokio::spawn(async move {
                let _permit = permit;
                handle_connection(stream, state, bearer_token).await;
            });
        }
        Err(_) => {
            tokio::spawn(async move {
                let mut stream = stream;
                let busy = json!({
                    "ok": false,
                    "error": "server_busy",
                    "retryAfterMs": 250,
                });
                let _ = write_ndjson_line(&mut stream, &busy).await;
            });
        }
    }
}

async fn handle_connection<S>(
    stream: S,
    state: Arc<LocalIngestState>,
    bearer_token: Option<Arc<Zeroizing<String>>>,
) where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut authenticated = bearer_token.is_none();

    loop {
        let line_res = tokio::time::timeout(
            LOCAL_INGEST_READ_TIMEOUT,
            read_bounded_line(&mut reader, MAX_LOCAL_INGEST_LINE_BYTES),
        )
        .await;

        let line = match line_res {
            Ok(Ok(Some(l))) => l,
            Ok(Ok(None)) => break,
            Ok(Err(err)) => {
                let _ = write_ndjson_line(&mut write_half, &err.to_json_receipt()).await;
                break;
            }
            Err(_) => {
                let resp = json!({
                    "ok": false,
                    "error": "read_timeout",
                    "message": "local ingest line read timed out",
                });
                let _ = write_ndjson_line(&mut write_half, &resp).await;
                break;
            }
        };

        if line.trim().is_empty() {
            continue;
        }

        let mut val: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let resp = json!({
                    "ok": false,
                    "error": "invalid_json",
                    "message": e.to_string(),
                });
                let _ = write_ndjson_line(&mut write_half, &resp).await;
                if !authenticated {
                    break;
                }
                continue;
            }
        };

        if let Some(ref expected) = bearer_token {
            let provided =
                val.as_object_mut()
                    .and_then(|obj| obj.remove("auth"))
                    .map(|v| match v {
                        Value::String(s) => s,
                        _ => String::new(),
                    });

            if let Some(candidate) = provided {
                if !constant_time_eq(expected.as_bytes(), candidate.as_bytes()) {
                    let resp = json!({
                        "ok": false,
                        "error": "unauthorized",
                        "message": "invalid local ingest bearer token",
                    });
                    let _ = write_ndjson_line(&mut write_half, &resp).await;
                    break;
                }
                authenticated = true;
                // Pure auth handshake line (`{ "auth": "<token>" }`) succeeds and awaits next line.
                if val.as_object().is_some_and(Map::is_empty) {
                    let ack = json!({ "ok": true, "authenticated": true });
                    if write_ndjson_line(&mut write_half, &ack).await.is_err() {
                        break;
                    }
                    continue;
                }
            } else if !authenticated {
                let resp = json!({
                    "ok": false,
                    "error": "unauthorized",
                    "message": "missing local ingest bearer token",
                });
                let _ = write_ndjson_line(&mut write_half, &resp).await;
                break;
            }
        }

        let current_gate = state.current_gate();
        let receipt = match state
            .ingest_local_event(&val, current_gate.as_deref(), now_ms())
            .await
        {
            Ok(outcome) => outcome.to_json_receipt(),
            Err(err) => err.to_json_receipt(),
        };

        if write_ndjson_line(&mut write_half, &receipt).await.is_err() {
            break;
        }
    }
}

async fn read_bounded_line(
    reader: &mut (impl AsyncBufRead + Unpin),
    max_bytes: usize,
) -> Result<Option<String>, LocalIngestError> {
    let mut buf = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|e| LocalIngestError::Transport(format!("read error: {e}")))?;
        if available.is_empty() {
            if buf.is_empty() {
                return Ok(None);
            }
            break;
        }
        if let Some(pos) = available.iter().position(|&b| b == b'\n') {
            if buf.len() + pos > max_bytes {
                return Err(LocalIngestError::PayloadTooLarge {
                    actual: buf.len() + pos,
                    max: max_bytes,
                });
            }
            buf.extend_from_slice(&available[..pos]);
            reader.consume(pos + 1);
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
            break;
        }
        let len = available.len();
        if buf.len() + len > max_bytes {
            return Err(LocalIngestError::PayloadTooLarge {
                actual: buf.len() + len,
                max: max_bytes,
            });
        }
        buf.extend_from_slice(available);
        reader.consume(len);
    }
    String::from_utf8(buf)
        .map(Some)
        .map_err(|_| LocalIngestError::InvalidEvent("invalid UTF-8 in NDJSON frame".to_string()))
}

async fn write_ndjson_line(
    writer: &mut (impl AsyncWrite + Unpin),
    packet: &Value,
) -> Result<(), LocalIngestError> {
    let mut bytes = serde_json::to_vec(packet)
        .map_err(|e| LocalIngestError::Transport(format!("json encode failed: {e}")))?;
    bytes.push(b'\n');
    writer
        .write_all(&bytes)
        .await
        .map_err(|e| LocalIngestError::Transport(format!("write failed: {e}")))?;
    writer
        .flush()
        .await
        .map_err(|e| LocalIngestError::Transport(format!("flush failed: {e}")))?;
    Ok(())
}

// ============================================================================
// Inbound Payload Normalization (Full CloudEvents v1.0 & Compact Shorthand)
// ============================================================================

fn normalize_local_ingest_payload(
    raw_json: &Value,
    default_topic: &str,
    now_ms: i64,
) -> Result<NormalizedLocalEvent, LocalIngestError> {
    let Value::Object(root_map) = raw_json else {
        return Err(LocalIngestError::InvalidEvent(
            "local ingest payload must be a JSON object".to_string(),
        ));
    };

    let raw_bytes = serde_json::to_vec(raw_json)
        .map_err(|e| LocalIngestError::InvalidEvent(e.to_string()))?
        .len();

    // Optional explicit envelope wrapper: `{ "topic"?: "...", "event": { ... } }`.
    let (outer_map, body_map) = if !root_map.contains_key("specversion") {
        if let Some(Value::Object(inner)) = root_map.get("event") {
            (Some(root_map), inner)
        } else {
            (None, root_map)
        }
    } else {
        (None, root_map)
    };

    let raw_topic = outer_map
        .and_then(|m| m.get("topic"))
        .or_else(|| body_map.get("topic"))
        .and_then(Value::as_str)
        .unwrap_or(default_topic)
        .trim();
    let topic = raw_topic
        .strip_prefix("local.")
        .unwrap_or(raw_topic)
        .to_string();
    if !is_valid_topic(&topic) {
        return Err(LocalIngestError::InvalidTopic(topic));
    }

    let coalesce_key = extract_optional_coalesce_key(outer_map, body_map)?;
    let ttl_seconds = extract_optional_ttl_seconds(outer_map, body_map)?;

    let parse_limits = CloudEventLimits {
        max_data_bytes: MAX_LOCAL_INGEST_LINE_BYTES,
        max_event_bytes: MAX_LOCAL_INGEST_LINE_BYTES,
        max_attribute_chars: MAX_ATTRIBUTE_CHARS,
    };

    let event = if body_map.get("specversion").and_then(Value::as_str) == Some("1.0") {
        // Full CloudEvents v1.0 envelope: preserve all signed CloudEvent fields verbatim!
        let mut ce_map = body_map.clone();
        ce_map.remove("auth");
        ce_map.remove("topic");
        ce_map.remove("coalesceKey");
        ce_map.remove("coalesce_key");
        ce_map.remove("ttlSeconds");
        ce_map.remove("ttl_seconds");

        // Fail closed cleanly if `hyphaesig` is present with a non-string type.
        if let Some(sig_val) = ce_map.get(EXT_LOCAL_EVENT_SIG) {
            if !sig_val.is_string() {
                return Err(LocalIngestError::InvalidSignature(
                    "hyphaesig must be a string".to_string(),
                ));
            }
        }

        let (ce, _) = check_cloudevent_v2_with_limits(&Value::Object(ce_map), parse_limits)
            .map_err(|e| LocalIngestError::InvalidEvent(e.to_string()))?;
        ce
    } else if body_map.contains_key("specversion") {
        return Err(LocalIngestError::InvalidEvent(
            "specversion must be \"1.0\"".to_string(),
        ));
    } else {
        // Compact Shorthand JSON -> normalize into valid CloudEvents v1.0!
        normalize_shorthand_to_cloudevent(body_map, now_ms, parse_limits)?
    };

    let serialized_event_bytes = serde_json::to_vec(&event)
        .map_err(|e| LocalIngestError::InvalidEvent(e.to_string()))?
        .len();
    let payload_bytes = raw_bytes.max(serialized_event_bytes);

    Ok(NormalizedLocalEvent {
        topic,
        event,
        payload_bytes,
        coalesce_key,
        ttl_seconds,
    })
}

fn normalize_shorthand_to_cloudevent(
    map: &Map<String, Value>,
    now_ms: i64,
    parse_limits: CloudEventLimits,
) -> Result<CloudEvent, LocalIngestError> {
    let event_type = match map.get("type") {
        None | Some(Value::Null) => TYPE_SCHEDULED_MESSAGE_V1.to_string(),
        Some(Value::String(s)) if !s.trim().is_empty() => s.trim().to_string(),
        _ => {
            return Err(LocalIngestError::InvalidEvent(
                "type must be a non-empty string".to_string(),
            ));
        }
    };

    let source = match map.get("source") {
        None | Some(Value::Null) => "local-ingest".to_string(),
        Some(Value::String(s)) if !s.trim().is_empty() => s.trim().to_string(),
        _ => {
            return Err(LocalIngestError::InvalidEvent(
                "source must be a non-empty string".to_string(),
            ));
        }
    };

    let id = match map.get("id") {
        None | Some(Value::Null) => format!("local-{}", uuid_v4()),
        Some(Value::String(s)) if !s.trim().is_empty() => s.trim().to_string(),
        _ => {
            return Err(LocalIngestError::InvalidEvent(
                "id must be a non-empty string".to_string(),
            ));
        }
    };

    let time = match map.get("time") {
        None | Some(Value::Null) => format_rfc3339_millis(now_ms),
        Some(Value::String(t)) => {
            if !is_valid_rfc3339_strict(t) {
                return Err(LocalIngestError::InvalidEvent(
                    "time must be an RFC 3339 timestamp".to_string(),
                ));
            }
            t.clone()
        }
        _ => {
            return Err(LocalIngestError::InvalidEvent(
                "time must be an RFC 3339 string".to_string(),
            ));
        }
    };

    let datacontenttype = match map.get("datacontenttype") {
        None | Some(Value::Null) => CONTENT_TYPE_JSON.to_string(),
        Some(Value::String(s)) if !s.trim().is_empty() => s.trim().to_string(),
        _ => {
            return Err(LocalIngestError::InvalidEvent(
                "datacontenttype must be a string".to_string(),
            ));
        }
    };

    let subject = match map.get("subject") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        _ => {
            return Err(LocalIngestError::InvalidEvent(
                "subject must be a string".to_string(),
            ));
        }
    };

    let label = match map.get("label") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        _ => {
            return Err(LocalIngestError::InvalidEvent(
                "label must be a string".to_string(),
            ));
        }
    };

    let note = match map.get("note") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        _ => {
            return Err(LocalIngestError::InvalidEvent(
                "note must be a string".to_string(),
            ));
        }
    };

    let text = match map.get("text") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.clone()),
        _ => {
            return Err(LocalIngestError::InvalidEvent(
                "text must be a string".to_string(),
            ));
        }
    };

    let mut data_obj = match map.get("data") {
        None | Some(Value::Null) => Map::new(),
        Some(Value::Object(obj)) => obj.clone(),
        Some(other) => {
            let mut m = Map::new();
            m.insert("value".to_string(), other.clone());
            m
        }
    };
    if let Some(ref lbl) = label {
        data_obj
            .entry("label".to_string())
            .or_insert_with(|| Value::String(lbl.clone()));
    }
    if let Some(ref n) = note {
        data_obj
            .entry("note".to_string())
            .or_insert_with(|| Value::String(n.clone()));
    }
    if let Some(ref t) = text {
        data_obj
            .entry("text".to_string())
            .or_insert_with(|| Value::String(t.clone()));
    }

    let mut extensions = BTreeMap::new();
    if let Some(ref lbl) = label {
        if lbl.encode_utf16().count() <= MAX_ATTRIBUTE_CHARS {
            extensions.insert("label".to_string(), Value::String(lbl.clone()));
        }
    }

    if let Some(sig_val) = map.get(EXT_LOCAL_EVENT_SIG) {
        let Some(sig_str) = sig_val.as_str() else {
            return Err(LocalIngestError::InvalidSignature(
                "hyphaesig must be a string".to_string(),
            ));
        };
        extensions.insert(
            EXT_LOCAL_EVENT_SIG.to_string(),
            Value::String(sig_str.to_string()),
        );
    }

    // Preserve any additional valid CloudEvents extension attributes passed at top level.
    for (k, v) in map {
        if matches!(
            k.as_str(),
            "specversion"
                | "id"
                | "source"
                | "type"
                | "datacontenttype"
                | "dataschema"
                | "subject"
                | "time"
                | "data"
                | "data_base64"
                | "topic"
                | "auth"
                | "label"
                | "note"
                | "text"
                | "coalesceKey"
                | "coalesce_key"
                | "ttlSeconds"
                | "ttl_seconds"
                | "hyphaesig"
        ) {
            continue;
        }
        if is_extension_name(k) {
            if let Value::String(s) = v {
                extensions.insert(k.clone(), Value::String(s.clone()));
            }
        }
    }

    let ce = CloudEvent {
        specversion: "1.0".to_string(),
        id,
        source,
        event_type,
        datacontenttype: Some(datacontenttype),
        dataschema: map
            .get("dataschema")
            .and_then(Value::as_str)
            .map(ToString::to_string),
        subject,
        time: Some(time),
        data: Some(Value::Object(data_obj)),
        data_base64: None,
        extensions,
    };

    let ce_val =
        serde_json::to_value(&ce).map_err(|e| LocalIngestError::InvalidEvent(e.to_string()))?;
    let (validated, _) = check_cloudevent_v2_with_limits(&ce_val, parse_limits)
        .map_err(|e| LocalIngestError::InvalidEvent(e.to_string()))?;
    Ok(validated)
}

fn extract_optional_coalesce_key(
    outer: Option<&Map<String, Value>>,
    body: &Map<String, Value>,
) -> Result<Option<String>, LocalIngestError> {
    let raw = outer
        .and_then(|m| m.get("coalesceKey").or_else(|| m.get("coalesce_key")))
        .or_else(|| body.get("coalesceKey").or_else(|| body.get("coalesce_key")))
        .or_else(|| {
            body.get("data")
                .and_then(Value::as_object)
                .and_then(|d| d.get("coalesceKey").or_else(|| d.get("coalesce_key")))
        });
    match raw {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => {
            let trimmed = s.trim();
            if trimmed.is_empty() || trimmed.len() > 256 {
                return Err(LocalIngestError::InvalidEvent(
                    "coalesceKey must be 1..=256 characters".to_string(),
                ));
            }
            Ok(Some(trimmed.to_string()))
        }
        _ => Err(LocalIngestError::InvalidEvent(
            "coalesceKey must be a string".to_string(),
        )),
    }
}

fn extract_optional_ttl_seconds(
    outer: Option<&Map<String, Value>>,
    body: &Map<String, Value>,
) -> Result<Option<u64>, LocalIngestError> {
    let raw = outer
        .and_then(|m| m.get("ttlSeconds").or_else(|| m.get("ttl_seconds")))
        .or_else(|| body.get("ttlSeconds").or_else(|| body.get("ttl_seconds")))
        .or_else(|| {
            body.get("data")
                .and_then(Value::as_object)
                .and_then(|d| d.get("ttlSeconds").or_else(|| d.get("ttl_seconds")))
        });
    match raw {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => {
            let secs = n.as_u64().ok_or_else(|| {
                LocalIngestError::InvalidEvent("ttlSeconds must be a positive integer".to_string())
            })?;
            if secs == 0 {
                return Err(LocalIngestError::InvalidEvent(
                    "ttlSeconds must be >= 1".to_string(),
                ));
            }
            Ok(Some(secs.min(MAX_TTL_SECONDS)))
        }
        _ => Err(LocalIngestError::InvalidEvent(
            "ttlSeconds must be a positive integer".to_string(),
        )),
    }
}

// ============================================================================
// Filesystem, Socket & Loopback `.addr` Helpers (Cross-OS Hygiene)
// ============================================================================

fn ensure_private_parent_dir(path: &Path) -> Result<(), NodeError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
            #[cfg(unix)]
            {
                fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn is_addr_file_path(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("addr"))
}

#[cfg(unix)]
fn prepare_unix_socket_path(path: &Path) -> Result<(), NodeError> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            let ft = meta.file_type();
            if ft.is_dir() || ft.is_symlink() {
                return Err(NodeError::Io(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("refusing to replace non-socket path at {}", path.display()),
                )));
            }
            if ft.is_socket() {
                // Fail closed if another live process is currently accepting connections here.
                if StdUnixStream::connect(path).is_ok() {
                    return Err(NodeError::Io(io::Error::new(
                        io::ErrorKind::AddrInUse,
                        format!("local ingest socket already active at {}", path.display()),
                    )));
                }
            }
            fs::remove_file(path)?;
            Ok(())
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(NodeError::Io(e)),
    }
}

fn generate_bearer_token() -> Result<Zeroizing<String>, NodeError> {
    let rng = SystemRandom::new();
    let mut raw = Zeroizing::new([0u8; 32]);
    rng.fill(&mut *raw)
        .map_err(|_| NodeError::Io(io::Error::other("OS CSPRNG failure")))?;
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(*raw)))
}

fn write_atomic_addr_file(
    endpoint_path: &Path,
    bound_addr: SocketAddr,
    token: &str,
) -> Result<(), NodeError> {
    let payload = serde_json::to_vec(&LoopbackAddrFile {
        addr: bound_addr.to_string(),
        token: token.to_string(),
    })?;

    let tmp_name = format!(
        ".{}.tmp.{}.{}",
        endpoint_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("ingest.addr"),
        std::process::id(),
        uuid_v4(),
    );
    let tmp_path = endpoint_path.with_file_name(tmp_name);

    let mut file = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp_path)?
        }
        #[cfg(not(unix))]
        {
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)?
        }
    };

    if let Err(err) = file
        .write_all(&payload)
        .and_then(|()| file.write_all(b"\n"))
        .and_then(|()| file.sync_all())
    {
        drop(file);
        let _ = fs::remove_file(&tmp_path);
        return Err(NodeError::Io(err));
    }
    drop(file);

    #[cfg(unix)]
    {
        let _ = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600));
    }

    if let Err(err) = fs::rename(&tmp_path, endpoint_path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(NodeError::Io(err));
    }
    Ok(())
}

fn parse_addr_descriptor_file(
    path: &Path,
) -> Result<(SocketAddr, Zeroizing<String>), LocalIngestError> {
    let file = fs::File::open(path).map_err(|e| {
        LocalIngestError::Transport(format!("failed to open {}: {e}", path.display()))
    })?;
    let mut raw = String::new();
    file.take(MAX_ADDR_FILE_BYTES)
        .read_to_string(&mut raw)
        .map_err(|e| {
            LocalIngestError::Transport(format!("failed to read {}: {e}", path.display()))
        })?;
    let parsed: LoopbackAddrFile = serde_json::from_str(raw.trim()).map_err(|e| {
        LocalIngestError::Transport(format!(
            "invalid ingest.addr JSON at {}: {e}",
            path.display()
        ))
    })?;
    let addr: SocketAddr = parsed.addr.trim().parse().map_err(|e| {
        LocalIngestError::Transport(format!("invalid loopback addr '{}': {e}", parsed.addr))
    })?;
    if !addr.ip().is_loopback() {
        return Err(LocalIngestError::Transport(format!(
            "refusing non-loopback local ingest address {addr}"
        )));
    }
    if parsed.token.trim().is_empty() {
        return Err(LocalIngestError::Transport(
            "ingest.addr missing bearer token".to_string(),
        ));
    }
    Ok((addr, Zeroizing::new(parsed.token)))
}

#[cfg(unix)]
fn detect_loopback_addr_descriptor(
    endpoint_path: &Path,
) -> Result<Option<(SocketAddr, Zeroizing<String>)>, LocalIngestError> {
    if is_addr_file_path(endpoint_path) {
        return parse_addr_descriptor_file(endpoint_path).map(Some);
    }
    if let Ok(meta) = fs::metadata(endpoint_path) {
        if meta.is_file() {
            return parse_addr_descriptor_file(endpoint_path).map(Some);
        }
        return Ok(None);
    }
    let sibling = endpoint_path.with_file_name("ingest.addr");
    if sibling != endpoint_path && sibling.is_file() {
        return parse_addr_descriptor_file(&sibling).map(Some);
    }
    Ok(None)
}

#[cfg(not(unix))]
fn detect_loopback_addr_descriptor(
    endpoint_path: &Path,
) -> Result<Option<(SocketAddr, Zeroizing<String>)>, LocalIngestError> {
    if endpoint_path.is_file() {
        return parse_addr_descriptor_file(endpoint_path).map(Some);
    }
    let sibling = endpoint_path.with_file_name("ingest.addr");
    if sibling != endpoint_path && sibling.is_file() {
        return parse_addr_descriptor_file(&sibling).map(Some);
    }
    Err(LocalIngestError::Transport(format!(
        "no local ingest descriptor found at {} or {}",
        endpoint_path.display(),
        sibling.display()
    )))
}
