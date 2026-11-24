//! Universal CloudEvents v1.0 envelope, strict validator, W3C Trace Context,
//! and multi-hop provenance & loop guard (§2.3, §6.1, `src/core/router/cloudevent.ts`).

use crate::address::{NodeId, is_valid_node_id};
use crate::jcs::{jcs_sha256_hex, to_jcs_string};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::sync::OnceLock;
use thiserror::Error;

// ---- Standard Hyphae v2 CloudEvent types (§6.1) ----

pub const TYPE_DM_V1: &str = "to.hyphae.dm.v1";
pub const TYPE_CHANNEL_V1: &str = "to.hyphae.channel.v1";
pub const TYPE_KV_SET: &str = "to.hyphae.kv.set";
pub const TYPE_KV_DELETED: &str = "to.hyphae.kv.deleted";
pub const TYPE_TRANSFER_V1: &str = "to.hyphae.transfer.v1";
pub const TYPE_NODE_MANIFEST: &str = "to.hyphae.node.manifest";
pub const TYPE_NODE_DIRECTORY: &str = "to.hyphae.node.directory";
pub const TYPE_WAKEUP_V1: &str = "to.hyphae.wakeup.v1";
pub const TYPE_HUMAN_DROP_V1: &str = "to.hyphae.human.drop.v1";
pub const TYPE_HUMAN_SECRET_STORED_V1: &str = "to.hyphae.human.secret.stored.v1";
pub const TYPE_HUMAN_REVOCATION_V1: &str = "to.hyphae.human.revocation.v1";

pub const CONTENT_TYPE_JSON: &str = "application/json";
pub const CONTENT_TYPE_E2EE_JSON: &str = "application/hyphae-e2ee+json";
pub const CONTENT_TYPE_TEXT_PLAIN: &str = "text/plain";

// ---- Standard CloudEvents extension attribute names ----

pub const EXT_TRACEPARENT: &str = "traceparent";
pub const EXT_TRACESTATE: &str = "tracestate";
pub const EXT_ORIGIN: &str = "hyphaeorigin";
pub const EXT_VIA: &str = "hyphaevia";
pub const EXT_HOPS: &str = "hyphaehops";

// ---- Size & multi-hop limits ----

pub const MAX_DATA_BYTES: usize = 8 * 1024;
pub const MAX_EVENT_BYTES: usize = 12 * 1024;
pub const MAX_ATTRIBUTE_CHARS: usize = 256;
pub const DEFAULT_MAX_HOPS: u8 = 2;
pub const HARD_MAX_HOPS: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloudEventLimits {
    pub max_data_bytes: usize,
    pub max_event_bytes: usize,
    pub max_attribute_chars: usize,
}

impl CloudEventLimits {
    /// v1 & default event-stream limits (8 KiB data, 12 KiB total event).
    pub const DEFAULT: Self = Self {
        max_data_bytes: MAX_DATA_BYTES,
        max_event_bytes: MAX_EVENT_BYTES,
        max_attribute_chars: MAX_ATTRIBUTE_CHARS,
    };

    /// Higher envelope limit for E2EE DM / channel ciphertext payloads (32 KiB data, 36 KiB event).
    pub const E2EE_ENVELOPE: Self = Self {
        max_data_bytes: 32 * 1024,
        max_event_bytes: 36 * 1024,
        max_attribute_chars: MAX_ATTRIBUTE_CHARS,
    };
}

impl Default for CloudEventLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CloudEventError {
    #[error("invalid_event: {0}")]
    InvalidEvent(String),
    #[error("too_large: {0}")]
    TooLarge(String),
}

impl CloudEventError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidEvent(_) => "invalid_event",
            Self::TooLarge(_) => "too_large",
        }
    }
}

/// W3C Trace Context `traceparent` header / CloudEvent extension attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TraceParent {
    pub version: u8,
    pub trace_id: [u8; 16],
    pub parent_id: [u8; 8],
    pub trace_flags: u8,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TraceContextError {
    #[error("invalid traceparent format: {0}")]
    InvalidFormat(String),
    #[error("forbidden traceparent version 0xff")]
    ForbiddenVersion,
    #[error("traceparent trace-id must not be all zeros")]
    ZeroTraceId,
    #[error("traceparent parent-id must not be all zeros")]
    ZeroParentId,
    #[error("invalid tracestate: {0}")]
    InvalidTraceState(String),
}

impl TraceParent {
    pub fn new(trace_id: [u8; 16], parent_id: [u8; 8], sampled: bool) -> Result<Self, TraceContextError> {
        if trace_id == [0u8; 16] {
            return Err(TraceContextError::ZeroTraceId);
        }
        if parent_id == [0u8; 8] {
            return Err(TraceContextError::ZeroParentId);
        }
        Ok(Self {
            version: 0,
            trace_id,
            parent_id,
            trace_flags: u8::from(sampled),
        })
    }

    /// Parses and strictly validates a W3C Trace Context `traceparent` value.
    pub fn parse(input: &str) -> Result<Self, TraceContextError> {
        let parts: Vec<&str> = input.split('-').collect();
        if parts.len() < 4 {
            return Err(TraceContextError::InvalidFormat(input.to_string()));
        }
        let version = parse_lower_hex_u8(parts[0])
            .ok_or_else(|| TraceContextError::InvalidFormat(input.to_string()))?;
        if version == 0xff {
            return Err(TraceContextError::ForbiddenVersion);
        }
        if version == 0 && parts.len() != 4 {
            return Err(TraceContextError::InvalidFormat(
                "version 00 traceparent must have exactly 4 dash-separated fields".to_string(),
            ));
        }

        let trace_id: [u8; 16] = parse_lower_hex_fixed(parts[1])
            .ok_or_else(|| TraceContextError::InvalidFormat(input.to_string()))?;
        let parent_id: [u8; 8] = parse_lower_hex_fixed(parts[2])
            .ok_or_else(|| TraceContextError::InvalidFormat(input.to_string()))?;
        let trace_flags = parse_lower_hex_u8(parts[3])
            .ok_or_else(|| TraceContextError::InvalidFormat(input.to_string()))?;

        if trace_id == [0u8; 16] {
            return Err(TraceContextError::ZeroTraceId);
        }
        if parent_id == [0u8; 8] {
            return Err(TraceContextError::ZeroParentId);
        }

        Ok(Self {
            version,
            trace_id,
            parent_id,
            trace_flags,
        })
    }

    pub fn is_sampled(&self) -> bool {
        (self.trace_flags & 0x01) != 0
    }

    pub fn child(&self, new_parent_id: [u8; 8]) -> Result<Self, TraceContextError> {
        if new_parent_id == [0u8; 8] {
            return Err(TraceContextError::ZeroParentId);
        }
        Ok(Self {
            version: 0,
            trace_id: self.trace_id,
            parent_id: new_parent_id,
            trace_flags: self.trace_flags,
        })
    }

    pub fn format(&self) -> String {
        format!(
            "{:02x}-{}-{}-{:02x}",
            self.version,
            hex::encode(self.trace_id),
            hex::encode(self.parent_id),
            self.trace_flags
        )
    }
}

impl std::fmt::Display for TraceParent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.format())
    }
}

/// Validates a W3C `tracestate` attribute value (non-control ASCII, comma-separated `key=val` pairs).
pub fn validate_tracestate(input: &str) -> Result<(), TraceContextError> {
    if input.len() > 512 {
        return Err(TraceContextError::InvalidTraceState(
            "tracestate exceeds 512 bytes".to_string(),
        ));
    }
    if input.bytes().any(|b| !(0x20..0x7f).contains(&b)) {
        return Err(TraceContextError::InvalidTraceState(
            "tracestate contains non-printable ASCII".to_string(),
        ));
    }
    if input.is_empty() {
        return Ok(());
    }
    for member in input.split(',') {
        let member = member.trim();
        if member.is_empty() {
            continue;
        }
        let Some((k, v)) = member.split_once('=') else {
            return Err(TraceContextError::InvalidTraceState(format!(
                "missing '=' in member {member:?}"
            )));
        };
        if k.is_empty() || v.contains('=') || v.contains(',') {
            return Err(TraceContextError::InvalidTraceState(format!(
                "malformed member {member:?}"
            )));
        }
    }
    Ok(())
}

/// Multi-hop provenance extracted from `hyphaeorigin`, `hyphaevia`, and `hyphaehops`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Provenance {
    pub origin: Option<NodeId>,
    pub via: Vec<NodeId>,
    pub hops: u8,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProvenanceError {
    #[error("routing_loop: node {node_id:?} already appears in forwarding path {via:?}")]
    RoutingLoop { node_id: String, via: Vec<String> },
    #[error("hop_limit_exceeded: hops {hops} reached max {max_hops}")]
    HopLimitExceeded { hops: u8, max_hops: u8 },
    #[error("invalid provenance attribute: {0}")]
    InvalidAttribute(String),
}

/// CloudEvents v1.0 structured-JSON envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CloudEvent {
    pub specversion: String,
    pub id: String,
    pub source: String,
    #[serde(rename = "type")]
    pub event_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub datacontenttype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dataschema: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_base64: Option<String>,
    #[serde(flatten)]
    pub extensions: BTreeMap<String, Value>,
}

impl CloudEvent {
    /// Creates a new CloudEvents v1.0 JSON envelope with required attributes.
    pub fn new(
        id: impl Into<String>,
        source: impl Into<String>,
        event_type: impl Into<String>,
        data: Value,
    ) -> Self {
        Self {
            specversion: "1.0".to_string(),
            id: id.into(),
            source: source.into(),
            event_type: event_type.into(),
            datacontenttype: Some(CONTENT_TYPE_JSON.to_string()),
            dataschema: None,
            subject: None,
            time: None,
            data: Some(data),
            data_base64: None,
            extensions: BTreeMap::new(),
        }
    }

    /// Looks up a top-level context or extension attribute value by name.
    pub fn get_attribute(&self, name: &str) -> Option<Value> {
        match name {
            "specversion" => Some(Value::String(self.specversion.clone())),
            "id" => Some(Value::String(self.id.clone())),
            "source" => Some(Value::String(self.source.clone())),
            "type" => Some(Value::String(self.event_type.clone())),
            "datacontenttype" => self.datacontenttype.clone().map(Value::String),
            "dataschema" => self.dataschema.clone().map(Value::String),
            "subject" => self.subject.clone().map(Value::String),
            "time" => self.time.clone().map(Value::String),
            "data" | "data_base64" => None,
            other => self.extensions.get(other).cloned(),
        }
    }

    /// Sets an extension attribute as a string value.
    pub fn set_extension(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.extensions.insert(key.into(), Value::String(value.into()));
    }

    /// Parses the W3C `traceparent` extension attribute, if present.
    pub fn traceparent(&self) -> Result<Option<TraceParent>, TraceContextError> {
        match self.extensions.get(EXT_TRACEPARENT) {
            None => Ok(None),
            Some(Value::String(s)) => TraceParent::parse(s).map(Some),
            Some(_) => Err(TraceContextError::InvalidFormat(
                "traceparent must be a string".to_string(),
            )),
        }
    }

    /// Attaches a W3C `traceparent` extension attribute.
    pub fn set_traceparent(&mut self, tp: &TraceParent) {
        self.set_extension(EXT_TRACEPARENT, tp.format());
    }

    /// Extracts multi-hop provenance (`hyphaeorigin`, `hyphaevia`, `hyphaehops`).
    pub fn provenance(&self) -> Result<Provenance, ProvenanceError> {
        let origin = match self.extensions.get(EXT_ORIGIN) {
            None => None,
            Some(Value::String(s)) => Some(
                NodeId::new(s.as_str()).map_err(|_| {
                    ProvenanceError::InvalidAttribute(format!("invalid hyphaeorigin {s:?}"))
                })?,
            ),
            Some(_) => {
                return Err(ProvenanceError::InvalidAttribute(
                    "hyphaeorigin must be a string".to_string(),
                ));
            }
        };

        let via = match self.extensions.get(EXT_VIA) {
            None => Vec::new(),
            Some(Value::String(s)) if s.is_empty() => Vec::new(),
            Some(Value::String(s)) => {
                if s.len() > MAX_ATTRIBUTE_CHARS {
                    return Err(ProvenanceError::InvalidAttribute(format!(
                        "hyphaevia exceeds {MAX_ATTRIBUTE_CHARS} chars"
                    )));
                }
                let mut list = Vec::new();
                for part in s.split(',') {
                    let id = NodeId::new(part).map_err(|_| {
                        ProvenanceError::InvalidAttribute(format!(
                            "invalid node id {part:?} in hyphaevia"
                        ))
                    })?;
                    list.push(id);
                }
                list
            }
            Some(_) => {
                return Err(ProvenanceError::InvalidAttribute(
                    "hyphaevia must be a string".to_string(),
                ));
            }
        };

        let hops = match self.extensions.get(EXT_HOPS) {
            None => via.len().try_into().unwrap_or(u8::MAX),
            Some(Value::String(s)) => s.parse::<u8>().map_err(|_| {
                ProvenanceError::InvalidAttribute(format!("invalid hyphaehops {s:?}"))
            })?,
            Some(_) => {
                return Err(ProvenanceError::InvalidAttribute(
                    "hyphaehops must be a decimal string".to_string(),
                ));
            }
        };

        Ok(Provenance { origin, via, hops })
    }

    /// Verifies that forwarding this event through `self_node_id` (optionally to `next_hop`)
    /// does not create a cycle or exceed the hop cap (§2.3).
    pub fn check_forwarding(
        &self,
        self_node_id: &NodeId,
        next_hop: Option<&NodeId>,
        max_hops: u8,
    ) -> Result<Provenance, ProvenanceError> {
        let effective_max = max_hops.min(HARD_MAX_HOPS);
        let prov = self.provenance()?;

        let via_strings = || prov.via.iter().map(|n| n.as_str().to_string()).collect();

        if prov.via.iter().any(|n| n == self_node_id) {
            return Err(ProvenanceError::RoutingLoop {
                node_id: self_node_id.to_string(),
                via: via_strings(),
            });
        }
        if let Some(next) = next_hop {
            if next == self_node_id
                || prov.via.iter().any(|n| n == next)
                || prov.origin.as_ref() == Some(next)
            {
                return Err(ProvenanceError::RoutingLoop {
                    node_id: next.to_string(),
                    via: via_strings(),
                });
            }
        }
        if prov.hops >= effective_max || prov.via.len() >= usize::from(effective_max) {
            return Err(ProvenanceError::HopLimitExceeded {
                hops: prov.hops.max(prov.via.len().try_into().unwrap_or(u8::MAX)),
                max_hops: effective_max,
            });
        }

        Ok(prov)
    }

    /// Validates forwarding invariants and stamps `hyphaeorigin`, `hyphaevia`, and `hyphaehops`.
    pub fn record_hop(
        &mut self,
        self_node_id: &NodeId,
        next_hop: Option<&NodeId>,
        max_hops: u8,
    ) -> Result<Provenance, ProvenanceError> {
        let mut prov = self.check_forwarding(self_node_id, next_hop, max_hops)?;
        if prov.origin.is_none() {
            prov.origin = Some(self_node_id.clone());
        }
        prov.via.push(self_node_id.clone());
        prov.hops = prov.hops.saturating_add(1);

        let via_str: String = prov
            .via
            .iter()
            .map(NodeId::as_str)
            .collect::<Vec<_>>()
            .join(",");
        if via_str.len() > MAX_ATTRIBUTE_CHARS {
            return Err(ProvenanceError::InvalidAttribute(format!(
                "hyphaevia would exceed {MAX_ATTRIBUTE_CHARS} chars"
            )));
        }

        if let Some(origin) = &prov.origin {
            self.set_extension(EXT_ORIGIN, origin.as_str());
        }
        self.set_extension(EXT_VIA, via_str);
        self.set_extension(EXT_HOPS, prov.hops.to_string());
        Ok(prov)
    }

    /// Idempotency digest: SHA-256 hex of RFC 8785 JCS over the event excluding `time`
    /// (matching `eventDigest` in `src/core/router/cloudevent.ts`).
    pub fn digest(&self) -> String {
        let mut value = serde_json::to_value(self).expect("CloudEvent serialization is infallible");
        if let Value::Object(ref mut map) = value {
            map.remove("time");
        }
        jcs_sha256_hex(&value).expect("validated CloudEvent has finite numbers")
    }
}

/// Computes the idempotency digest directly on a raw JSON CloudEvent object (excluding `time`).
pub fn event_digest_value(value: &Value) -> Result<String, CloudEventError> {
    let Value::Object(map) = value else {
        return Err(CloudEventError::InvalidEvent(
            "the body must be a CloudEvent JSON object".to_string(),
        ));
    };
    let mut without_time = map.clone();
    without_time.remove("time");
    jcs_sha256_hex(&Value::Object(without_time))
        .map_err(|e| CloudEventError::InvalidEvent(e.to_string()))
}

/// Strict Hyphae v1 CloudEvent validation matching `checkCloudEvent` in
/// `src/core/router/cloudevent.ts` 100% (including exact error class `invalid_event` vs `too_large`).
pub fn check_cloudevent_v1(value: &Value) -> Result<(CloudEvent, usize), CloudEventError> {
    let Value::Object(map) = value else {
        return Err(CloudEventError::InvalidEvent(
            "the body must be a CloudEvent JSON object".to_string(),
        ));
    };
    if map.get("specversion").and_then(Value::as_str) != Some("1.0") {
        return Err(CloudEventError::InvalidEvent(
            "specversion must be \"1.0\"".to_string(),
        ));
    }
    if map.get("datacontenttype").and_then(Value::as_str) != Some("application/json") {
        return Err(CloudEventError::InvalidEvent(
            "datacontenttype must be \"application/json\"".to_string(),
        ));
    }
    for name in ["id", "source", "type"] {
        match map.get(name).and_then(Value::as_str) {
            Some(s) if !s.is_empty() => {}
            _ => {
                return Err(CloudEventError::InvalidEvent(format!(
                    "{name} must be a non-empty string"
                )));
            }
        }
    }
    for name in ["subject", "time"] {
        if let Some(v) = map.get(name) {
            if !v.is_string() {
                return Err(CloudEventError::InvalidEvent(format!(
                    "{name} must be a string"
                )));
            }
        }
    }
    if let Some(Value::String(t)) = map.get("time") {
        if !is_valid_rfc3339_strict(t) {
            return Err(CloudEventError::InvalidEvent(
                "time must be an RFC 3339 timestamp".to_string(),
            ));
        }
    }
    let Some(data) = map.get("data") else {
        return Err(CloudEventError::InvalidEvent(
            "data must be a JSON object".to_string(),
        ));
    };
    if !data.is_object() {
        return Err(CloudEventError::InvalidEvent(
            "data must be a JSON object".to_string(),
        ));
    }

    for (name, attr) in map {
        if name == "data" {
            continue;
        }
        if !is_extension_name(name) {
            let preview: String = name.chars().take(64).collect();
            return Err(CloudEventError::InvalidEvent(format!(
                "attribute name {preview:?} is not lowercase alphanumeric"
            )));
        }
        let Some(s) = attr.as_str() else {
            return Err(CloudEventError::InvalidEvent(format!(
                "attribute {name} must be a string"
            )));
        };
        let char_len = s.encode_utf16().count();
        if char_len > MAX_ATTRIBUTE_CHARS {
            return Err(CloudEventError::TooLarge(format!(
                "attribute {name} is {char_len} characters; limit {MAX_ATTRIBUTE_CHARS}"
            )));
        }
    }

    let data_bytes = json_utf8_len(data)?;
    if data_bytes > MAX_DATA_BYTES {
        return Err(CloudEventError::TooLarge(format!(
            "data is {data_bytes} bytes; limit {MAX_DATA_BYTES}"
        )));
    }
    let bytes = json_utf8_len(value)?;
    if bytes > MAX_EVENT_BYTES {
        return Err(CloudEventError::TooLarge(format!(
            "event is {bytes} bytes; limit {MAX_EVENT_BYTES}"
        )));
    }

    let event: CloudEvent = serde_json::from_value(value.clone())
        .map_err(|e| CloudEventError::InvalidEvent(e.to_string()))?;
    Ok((event, bytes))
}

/// Validates a Hyphae v2 CloudEvents v1.0 envelope with default limits:
/// - Required: `specversion == "1.0"`, non-empty `id`, `source`, `type`.
/// - Optional: `subject`, `time` (RFC 3339), `datacontenttype` (RFC 2046 media type),
///   `dataschema`, mutually exclusive `data` vs `data_base64`, extension attributes.
/// - Validates W3C `traceparent`/`tracestate` and `hyphaeorigin`/`hyphaevia`/`hyphaehops` if present.
pub fn check_cloudevent_v2(value: &Value) -> Result<(CloudEvent, usize), CloudEventError> {
    check_cloudevent_v2_with_limits(value, CloudEventLimits::DEFAULT)
}

/// Validates a Hyphae v2 CloudEvents v1.0 envelope against custom byte/attribute limits.
pub fn check_cloudevent_v2_with_limits(
    value: &Value,
    limits: CloudEventLimits,
) -> Result<(CloudEvent, usize), CloudEventError> {
    let Value::Object(map) = value else {
        return Err(CloudEventError::InvalidEvent(
            "the body must be a CloudEvent JSON object".to_string(),
        ));
    };
    if map.get("specversion").and_then(Value::as_str) != Some("1.0") {
        return Err(CloudEventError::InvalidEvent(
            "specversion must be \"1.0\"".to_string(),
        ));
    }
    for name in ["id", "source", "type"] {
        match map.get(name).and_then(Value::as_str) {
            Some(s) if !s.is_empty() => {}
            _ => {
                return Err(CloudEventError::InvalidEvent(format!(
                    "{name} must be a non-empty string"
                )));
            }
        }
    }

    if map.contains_key("data") && map.contains_key("data_base64") {
        return Err(CloudEventError::InvalidEvent(
            "CloudEvent cannot contain both data and data_base64".to_string(),
        ));
    }

    if let Some(v) = map.get("datacontenttype") {
        let Some(ct) = v.as_str() else {
            return Err(CloudEventError::InvalidEvent(
                "datacontenttype must be a string".to_string(),
            ));
        };
        if !is_valid_rfc2046_media_type(ct) {
            return Err(CloudEventError::InvalidEvent(format!(
                "datacontenttype {ct:?} is not a valid RFC 2046 media type"
            )));
        }
    }

    if let Some(v) = map.get("dataschema") {
        match v.as_str() {
            Some(s) if !s.is_empty() && !s.chars().any(|c| c.is_control() || c.is_whitespace()) => {}
            _ => {
                return Err(CloudEventError::InvalidEvent(
                    "dataschema must be a non-empty URI string".to_string(),
                ));
            }
        }
    }

    for name in ["subject", "time"] {
        if let Some(v) = map.get(name) {
            if !v.is_string() {
                return Err(CloudEventError::InvalidEvent(format!(
                    "{name} must be a string"
                )));
            }
        }
    }

    if let Some(Value::String(t)) = map.get("time") {
        if !is_valid_rfc3339_strict(t) {
            return Err(CloudEventError::InvalidEvent(
                "time must be an RFC 3339 timestamp".to_string(),
            ));
        }
    }

    if let Some(v) = map.get("data_base64") {
        let Some(b64) = v.as_str() else {
            return Err(CloudEventError::InvalidEvent(
                "data_base64 must be a base64 string".to_string(),
            ));
        };
        let decoded = BASE64_STD.decode(b64).map_err(|_| {
            CloudEventError::InvalidEvent("data_base64 is not valid base64".to_string())
        })?;
        if decoded.len() > limits.max_data_bytes {
            return Err(CloudEventError::TooLarge(format!(
                "decoded data_base64 is {} bytes; limit {}",
                decoded.len(),
                limits.max_data_bytes
            )));
        }
    }

    if let Some(data) = map.get("data") {
        let data_bytes = json_utf8_len(data)?;
        if data_bytes > limits.max_data_bytes {
            return Err(CloudEventError::TooLarge(format!(
                "data is {data_bytes} bytes; limit {}",
                limits.max_data_bytes
            )));
        }
    }

    validate_v2_attributes(map, limits)?;

    let bytes = json_utf8_len(value)?;
    if bytes > limits.max_event_bytes {
        return Err(CloudEventError::TooLarge(format!(
            "event is {bytes} bytes; limit {}",
            limits.max_event_bytes
        )));
    }

    let event: CloudEvent = serde_json::from_value(value.clone())
        .map_err(|e| CloudEventError::InvalidEvent(e.to_string()))?;

    // Validate W3C Trace Context and Hyphae provenance attributes when present.
    if let Err(e) = event.traceparent() {
        return Err(CloudEventError::InvalidEvent(e.to_string()));
    }
    if let Some(Value::String(ts)) = event.extensions.get(EXT_TRACESTATE) {
        if let Err(e) = validate_tracestate(ts) {
            return Err(CloudEventError::InvalidEvent(e.to_string()));
        }
    }
    if let Err(e) = event.provenance() {
        return Err(CloudEventError::InvalidEvent(e.to_string()));
    }
    if let Some(Value::String(origin)) = event.extensions.get(EXT_ORIGIN) {
        if !is_valid_node_id(origin) {
            return Err(CloudEventError::InvalidEvent(format!(
                "invalid hyphaeorigin {origin:?}"
            )));
        }
    }

    Ok((event, bytes))
}

fn validate_v2_attributes(
    map: &Map<String, Value>,
    limits: CloudEventLimits,
) -> Result<(), CloudEventError> {
    for (name, attr) in map {
        if name == "data" || name == "data_base64" {
            continue;
        }
        if !is_extension_name(name) {
            let preview: String = name.chars().take(64).collect();
            return Err(CloudEventError::InvalidEvent(format!(
                "attribute name {preview:?} is not lowercase alphanumeric"
            )));
        }
        let Some(s) = attr.as_str() else {
            return Err(CloudEventError::InvalidEvent(format!(
                "attribute {name} must be a string"
            )));
        };
        let char_len = s.encode_utf16().count();
        if char_len > limits.max_attribute_chars {
            return Err(CloudEventError::TooLarge(format!(
                "attribute {name} is {char_len} characters; limit {}",
                limits.max_attribute_chars
            )));
        }
    }
    Ok(())
}

/// CloudEvents 1.0 attribute name rule: `/^[a-z0-9]{1,20}$/`.
pub fn is_extension_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 20
        && bytes
            .iter()
            .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// Validates RFC 2046 media type (`type/subtype` with optional `; param=value` parameters).
pub fn is_valid_rfc2046_media_type(value: &str) -> bool {
    static MEDIA_TYPE_RE: OnceLock<Regex> = OnceLock::new();
    let re = MEDIA_TYPE_RE.get_or_init(|| {
        Regex::new(
            r#"^[A-Za-z0-9!#$&^_.+-]{1,64}/[A-Za-z0-9!#$&^_.+-]{1,127}(?:\s*;\s*[A-Za-z0-9!#$&^_.+-]{1,64}=(?:[A-Za-z0-9!#$&^_.+-]{1,127}|"[^"\\]{0,127}"))*$"#,
        )
        .expect("valid media type regex")
    });
    !value.is_empty() && value.len() <= MAX_ATTRIBUTE_CHARS && re.is_match(value)
}

/// Strict RFC 3339 check matching `src/core/router/cloudevent.ts`:
/// uppercase `T`, `Z` or `±HH:MM`, and valid calendar date/time.
pub fn is_valid_rfc3339_strict(value: &str) -> bool {
    parse_rfc3339_utc_nanos(value).is_some()
}

/// Parses a strict RFC 3339 timestamp (`YYYY-MM-DDTHH:MM:SS(.frac)?(Z|±HH:MM)`) into
/// Unix epoch UTC nanoseconds (`i128`), validating leap years, month day counts, and offset bounds.
pub fn parse_rfc3339_utc_nanos(value: &str) -> Option<i128> {
    let bytes = value.as_bytes();
    if bytes.len() < 20 {
        return None;
    }
    if bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let year: i64 = parse_ascii_digits(&value[0..4])? as i64;
    let month: u32 = parse_ascii_digits(&value[5..7])?;
    let day: u32 = parse_ascii_digits(&value[8..10])?;
    let hour: u32 = parse_ascii_digits(&value[11..13])?;
    let minute: u32 = parse_ascii_digits(&value[14..16])?;
    let second: u32 = parse_ascii_digits(&value[17..19])?;

    if !(1..=12).contains(&month) {
        return None;
    }
    let max_day = days_in_month(year, month);
    if day < 1 || day > max_day {
        return None;
    }
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }

    let mut pos = 19;
    let mut nanos: i128 = 0;
    if pos < bytes.len() && bytes[pos] == b'.' {
        pos += 1;
        let frac_start = pos;
        while pos < bytes.len() && bytes[pos].is_ascii_digit() {
            pos += 1;
        }
        let frac_len = pos - frac_start;
        if frac_len == 0 {
            return None;
        }
        // Take up to 9 digits of fractional seconds (nanosecond precision).
        let take = frac_len.min(9);
        let mut scale: i128 = 100_000_000;
        for &b in &bytes[frac_start..frac_start + take] {
            nanos += i128::from(b - b'0') * scale;
            scale /= 10;
        }
    }

    let tz = &value[pos..];
    let offset_secs: i64 = if tz == "Z" {
        0
    } else if tz.len() == 6
        && (tz.as_bytes()[0] == b'+' || tz.as_bytes()[0] == b'-')
        && tz.as_bytes()[3] == b':'
    {
        let sign: i64 = if tz.as_bytes()[0] == b'+' { 1 } else { -1 };
        let tz_h: u32 = parse_ascii_digits(&tz[1..3])?;
        let tz_m: u32 = parse_ascii_digits(&tz[4..6])?;
        if tz_h > 23 || tz_m > 59 {
            return None;
        }
        sign * (i64::from(tz_h) * 3600 + i64::from(tz_m) * 60)
    } else {
        return None;
    };

    let days = days_from_civil(year, month, day);
    let total_secs: i128 = i128::from(days) * 86_400
        + i128::from(hour) * 3600
        + i128::from(minute) * 60
        + i128::from(second)
        - i128::from(offset_secs);
    Some(total_secs * 1_000_000_000 + nanos)
}

fn parse_ascii_digits(s: &str) -> Option<u32> {
    if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn is_leap_year(year: i64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if is_leap_year(year) {
                29
            } else {
                28
            }
        }
        _ => 0,
    }
}

/// Howard Hinnant's algorithm: days since 1970-01-01 from proleptic Gregorian civil date.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400; // [0, 399]
    let m = i64::from(month);
    let d = i64::from(day);
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

fn json_utf8_len(value: &Value) -> Result<usize, CloudEventError> {
    to_jcs_string(value)
        .map(|s| s.len())
        .map_err(|e| CloudEventError::InvalidEvent(e.to_string()))
}

fn parse_lower_hex_u8(s: &str) -> Option<u8> {
    if s.len() != 2 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return None;
    }
    u8::from_str_radix(s, 16).ok()
}

fn parse_lower_hex_fixed<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != N * 2
        || !s
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(s, &mut out).ok()?;
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn traceparent_validation_and_child() {
        let valid = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let tp = TraceParent::parse(valid).unwrap();
        assert_eq!(tp.version, 0);
        assert!(tp.is_sampled());
        assert_eq!(tp.format(), valid);

        let child = tp.child([1, 2, 3, 4, 5, 6, 7, 8]).unwrap();
        assert_eq!(child.trace_id, tp.trace_id);
        assert_eq!(child.parent_id, [1, 2, 3, 4, 5, 6, 7, 8]);

        // Forbidden version ff, zero trace_id, zero parent_id, uppercase hex.
        assert!(TraceParent::parse("ff-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01").is_err());
        assert!(TraceParent::parse("00-00000000000000000000000000000000-00f067aa0ba902b7-01").is_err());
        assert!(TraceParent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01").is_err());
        assert!(TraceParent::parse("00-4BF92F3577B34DA6A3CE929D0E0E4736-00f067aa0ba902b7-01").is_err());
        assert!(TraceParent::parse("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra").is_err());
    }

    #[test]
    fn multi_hop_loop_and_cap_guards() {
        let alice = NodeId::new("alice@macbook").unwrap();
        let hub = NodeId::new("acme-team").unwrap();
        let bob = NodeId::new("bob@laptop").unwrap();
        let carol = NodeId::new("carol@dev").unwrap();

        let mut ev = CloudEvent::new("ev-1", "alice@macbook/claude", TYPE_DM_V1, json!({"text": "hi"}));
        let p1 = ev.record_hop(&alice, Some(&hub), DEFAULT_MAX_HOPS).unwrap();
        assert_eq!(p1.hops, 1);
        assert_eq!(p1.origin.as_ref(), Some(&alice));
        assert_eq!(p1.via, vec![alice.clone()]);

        // Cycle back to alice is rejected!
        assert!(matches!(
            ev.check_forwarding(&hub, Some(&alice), DEFAULT_MAX_HOPS),
            Err(ProvenanceError::RoutingLoop { .. })
        ));

        // Second hop through hub -> bob succeeds.
        let p2 = ev.record_hop(&hub, Some(&bob), DEFAULT_MAX_HOPS).unwrap();
        assert_eq!(p2.hops, 2);

        // Third hop exceeds default max_hops = 2!
        assert!(matches!(
            ev.check_forwarding(&bob, Some(&carol), DEFAULT_MAX_HOPS),
            Err(ProvenanceError::HopLimitExceeded { hops: 2, max_hops: 2 })
        ));

        // Even if caller passes max_hops = 99, hard protocol cap 4 is enforced!
        ev.record_hop(&bob, Some(&carol), 99).unwrap();
        let dave = NodeId::new("dave@box").unwrap();
        ev.record_hop(&carol, Some(&dave), 99).unwrap();
        assert!(matches!(
            ev.check_forwarding(&dave, None, 99),
            Err(ProvenanceError::HopLimitExceeded { hops: 4, max_hops: 4 })
        ));
    }

    #[test]
    fn v2_accepts_rfc2046_media_types_and_data_base64() {
        let ev = json!({
            "specversion": "1.0",
            "id": "e1",
            "source": "alice@macbook/claude",
            "type": TYPE_DM_V1,
            "datacontenttype": CONTENT_TYPE_E2EE_JSON,
            "traceparent": "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            "data": { "ciphertext": "abc" }
        });
        assert!(check_cloudevent_v2(&ev).is_ok());

        let bin = json!({
            "specversion": "1.0",
            "id": "e2",
            "source": "alice@macbook/claude",
            "type": TYPE_TRANSFER_V1,
            "datacontenttype": "application/octet-stream",
            "data_base64": BASE64_STD.encode(b"hello")
        });
        assert!(check_cloudevent_v2(&bin).is_ok());

        // Both data and data_base64 -> fail closed!
        let both = json!({
            "specversion": "1.0",
            "id": "e3",
            "source": "s",
            "type": "t",
            "data": {},
            "data_base64": "YQ=="
        });
        assert!(check_cloudevent_v2(&both).is_err());
    }

    #[test]
    fn rfc3339_leap_years_and_timezone_ordering() {
        assert!(is_valid_rfc3339_strict("2024-02-29T23:59:59.999999999Z"));
        assert!(!is_valid_rfc3339_strict("2025-02-29T00:00:00Z"));
        assert!(is_valid_rfc3339_strict("2000-02-29T00:00:00Z"));
        assert!(!is_valid_rfc3339_strict("1900-02-29T00:00:00Z"));
        assert!(!is_valid_rfc3339_strict("2026-01-01T00:00:00+24:00"));
        assert!(!is_valid_rfc3339_strict("2026-01-01T00:00:00+00:60"));

        // Equivalent instants in different timezones produce identical UTC nanoseconds.
        let utc = parse_rfc3339_utc_nanos("2026-06-15T10:00:00Z").unwrap();
        let plus2 = parse_rfc3339_utc_nanos("2026-06-15T12:00:00+02:00").unwrap();
        let minus5 = parse_rfc3339_utc_nanos("2026-06-15T05:00:00-05:00").unwrap();
        assert_eq!(utc, plus2);
        assert_eq!(utc, minus5);
    }
}
