//! Self-contained domain types, CloudEvents v1.0 validation/digest, Subscriptions API v1.0
//! filter AST, canonical JSON, identifier validation, and RFC 3339 formatting.
//!
//! These types are intentionally self-contained for Wave 1 independent compilation and will
//! unify seamlessly with `hyp-proto` after Wave 1 merges.

use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::error::{StoreError, StoreResult};

/// Maximum UTF-8 byte length for CloudEvents `data` object (8 KiB).
pub const MAX_EVENT_DATA_BYTES: usize = 8 * 1024;
/// Maximum UTF-8 byte length for a serialized CloudEvent (12 KiB).
pub const MAX_EVENT_BYTES: usize = 12 * 1024;
/// Maximum character length for a CloudEvent string attribute.
pub const MAX_ATTRIBUTE_CHARS: usize = 256;
/// Maximum UTF-8 byte length for a subscription's serialized `filters` array (4 KiB).
pub const MAX_FILTERS_BYTES: usize = 4 * 1024;
/// Maximum nesting depth for a CloudEvents Subscriptions API filter AST.
pub const MAX_FILTER_DEPTH: usize = 8;

/// Returns current wall-clock time as epoch milliseconds.
pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Generates an RFC 4122 version 4 UUID string.
pub fn uuid_v4() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15],
    )
}

/// Computes lowercase hex SHA-256 of arbitrary bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Formats epoch milliseconds as an RFC 3339 UTC timestamp (`YYYY-MM-DDTHH:MM:SS.sssZ`).
pub fn epoch_ms_to_rfc3339(ms: i64) -> String {
    let secs = ms.div_euclid(1000);
    let millis = ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let sec_of_day = secs.rem_euclid(86_400);
    let hour = sec_of_day / 3600;
    let minute = (sec_of_day % 3600) / 60;
    let second = sec_of_day % 60;

    // Howard Hinnant's civil-from-days algorithm (proleptic Gregorian calendar).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z")
}

// ---- Identifier validation ----

fn is_lower_alnum(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit()
}

/// Validates a node / connector ID: `/^[a-z0-9][a-z0-9@._-]{0,63}$/`.
pub fn is_node_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    if !is_lower_alnum(bytes[0]) {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|&b| is_lower_alnum(b) || matches!(b, b'@' | b'.' | b'_' | b'-'))
}

/// Validates a session handle: `/^[a-z0-9][a-z0-9._-]{0,63}$/`.
pub fn is_handle(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    if !is_lower_alnum(bytes[0]) {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|&b| is_lower_alnum(b) || matches!(b, b'.' | b'_' | b'-'))
}

/// Validates an event topic: `/^[a-z0-9][a-z0-9._-]{0,63}$/`.
pub fn is_topic(value: &str) -> bool {
    is_handle(value)
}

/// Validates a channel name: `/^#[a-z0-9][a-z0-9._-]{0,62}$/`.
pub fn is_channel_name(value: &str) -> bool {
    let Some(rest) = value.strip_prefix('#') else {
        return false;
    };
    let bytes = rest.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    if !is_lower_alnum(bytes[0]) {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|&b| is_lower_alnum(b) || matches!(b, b'.' | b'_' | b'-'))
}

/// Validates a transfer ID against path traversal: ASCII `[A-Za-z0-9_-]{1,128}`.
pub fn is_safe_transfer_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() > 128 {
        return false;
    }
    bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

/// Validates a KV namespace: `/^[a-z0-9][a-z0-9._-]{0,63}$/`.
pub fn is_kv_namespace(value: &str) -> bool {
    is_handle(value)
}

/// Validates a KV key: non-empty, <= 256 UTF-8 bytes, no whitespace/control chars, no `..` segments.
pub fn is_kv_key(value: &str) -> bool {
    if value.is_empty() || value.len() > 256 {
        return false;
    }
    if value.starts_with('/') || value.ends_with('/') {
        return false;
    }
    if value
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == '\\')
    {
        return false;
    }
    !value.split('/').any(|seg| seg.is_empty() || seg == "..")
}

/// Parses `<node-id>/<handle>` into `(node_id, handle)`.
pub fn parse_address(value: &str) -> Option<(&str, &str)> {
    let idx = value.rfind('/')?;
    let node_id = &value[..idx];
    let handle = &value[idx + 1..];
    if is_node_id(node_id) && is_handle(handle) {
        Some((node_id, handle))
    } else {
        None
    }
}

/// Formats `<node-id>/<handle>`.
pub fn format_address(node_id: &str, handle: &str) -> String {
    format!("{node_id}/{handle}")
}

/// Validates a CloudEvents extension attribute name (`^[a-z0-9]{1,20}$`).
pub fn is_ce_attribute_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty() && bytes.len() <= 20 && bytes.iter().all(|&b| is_lower_alnum(b))
}

/// Validates a CloudEvents Subscriptions API filter key:
/// either an attribute name `^[a-z0-9]{1,20}$` or `data.<field>` (`[^\s]{1,128}`).
pub fn is_valid_filter_key(key: &str) -> bool {
    if let Some(field) = key.strip_prefix("data.") {
        !field.is_empty()
            && field.len() <= 128
            && !field.chars().any(|c| c.is_whitespace() || c.is_control())
    } else {
        is_ce_attribute_name(key)
    }
}

// ---- Canonical JSON & CloudEvents v1.0 ----

/// Serializes any JSON value deterministically with object keys sorted lexicographically.
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_canonical_json(value, &mut out);
    out
}

fn write_canonical_json(value: &Value, out: &mut String) {
    match value {
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical_json(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
            keys.sort_unstable();
            out.push('{');
            for (i, key) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                if let Ok(k) = serde_json::to_string(key) {
                    out.push_str(&k);
                }
                out.push(':');
                if let Some(v) = map.get(*key) {
                    write_canonical_json(v, out);
                }
            }
            out.push('}');
        }
        other => {
            if let Ok(s) = serde_json::to_string(other) {
                out.push_str(&s);
            }
        }
    }
}

/// CloudEvents v1.0 structured JSON envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CloudEvent {
    pub specversion: String,
    pub id: String,
    pub source: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub datacontenttype: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dataschema: Option<String>,
    pub data: Value,
    #[serde(flatten, default)]
    pub extensions: BTreeMap<String, String>,
}

impl CloudEvent {
    /// Constructs a new CloudEvents v1.0 event with `datacontenttype = "application/json"`.
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
            datacontenttype: "application/json".to_string(),
            subject: None,
            time: None,
            dataschema: None,
            data,
            extensions: BTreeMap::new(),
        }
    }

    /// Adds a CloudEvents string extension attribute.
    pub fn with_extension(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extensions.insert(key.into(), value.into());
        self
    }

    /// Sets the optional `subject` attribute.
    pub fn with_subject(mut self, subject: impl Into<String>) -> Self {
        self.subject = Some(subject.into());
        self
    }

    /// Sets the optional `time` attribute.
    pub fn with_time(mut self, time: impl Into<String>) -> Self {
        self.time = Some(time.into());
        self
    }

    /// Sets the `datacontenttype` media type.
    pub fn with_content_type(mut self, content_type: impl Into<String>) -> Self {
        self.datacontenttype = content_type.into();
        self
    }

    /// Validates this CloudEvent against v2 size and attribute invariants, returning total JSON bytes.
    pub fn validate(&self) -> StoreResult<usize> {
        if self.specversion != "1.0" {
            return Err(StoreError::InvalidInput(
                "specversion must be \"1.0\"".to_string(),
            ));
        }
        if self.id.is_empty() {
            return Err(StoreError::InvalidInput(
                "id must be a non-empty string".to_string(),
            ));
        }
        if self.source.is_empty() {
            return Err(StoreError::InvalidInput(
                "source must be a non-empty string".to_string(),
            ));
        }
        if self.event_type.is_empty() {
            return Err(StoreError::InvalidInput(
                "type must be a non-empty string".to_string(),
            ));
        }
        if self.datacontenttype.is_empty() || !self.datacontenttype.contains('/') {
            return Err(StoreError::InvalidInput(
                "datacontenttype must be a valid RFC 2046 media type".to_string(),
            ));
        }
        for (name, val) in [
            ("id", self.id.as_str()),
            ("source", self.source.as_str()),
            ("type", self.event_type.as_str()),
            ("datacontenttype", self.datacontenttype.as_str()),
        ] {
            if val.chars().count() > MAX_ATTRIBUTE_CHARS {
                return Err(StoreError::TooLarge(format!(
                    "attribute '{name}' exceeds {MAX_ATTRIBUTE_CHARS} chars"
                )));
            }
        }
        for (name, opt) in [
            ("subject", self.subject.as_deref()),
            ("time", self.time.as_deref()),
            ("dataschema", self.dataschema.as_deref()),
        ] {
            if let Some(val) = opt {
                if val.chars().count() > MAX_ATTRIBUTE_CHARS {
                    return Err(StoreError::TooLarge(format!(
                        "attribute '{name}' exceeds {MAX_ATTRIBUTE_CHARS} chars"
                    )));
                }
            }
        }
        for (name, val) in &self.extensions {
            if !is_ce_attribute_name(name) || name == "data" {
                return Err(StoreError::InvalidInput(format!(
                    "extension attribute name '{name}' must be lowercase alphanumeric (1..=20)"
                )));
            }
            if val.chars().count() > MAX_ATTRIBUTE_CHARS {
                return Err(StoreError::TooLarge(format!(
                    "extension attribute '{name}' exceeds {MAX_ATTRIBUTE_CHARS} chars"
                )));
            }
        }
        if !self.data.is_object() {
            return Err(StoreError::InvalidInput(
                "data must be a JSON object".to_string(),
            ));
        }
        let data_bytes = serde_json::to_string(&self.data)?.len();
        if data_bytes > MAX_EVENT_DATA_BYTES {
            return Err(StoreError::TooLarge(format!(
                "event data is {data_bytes} bytes; limit is {MAX_EVENT_DATA_BYTES}"
            )));
        }
        let total_bytes = serde_json::to_string(self)?.len();
        if total_bytes > MAX_EVENT_BYTES {
            return Err(StoreError::TooLarge(format!(
                "event is {total_bytes} bytes; limit is {MAX_EVENT_BYTES}"
            )));
        }
        Ok(total_bytes)
    }

    /// Computes the idempotency SHA-256 digest of the event excluding `time`
    /// (so redeliveries with updated receipt timestamps remain idempotent).
    pub fn digest(&self) -> String {
        let mut map = Map::new();
        map.insert("specversion".to_string(), Value::String(self.specversion.clone()));
        map.insert("id".to_string(), Value::String(self.id.clone()));
        map.insert("source".to_string(), Value::String(self.source.clone()));
        map.insert("type".to_string(), Value::String(self.event_type.clone()));
        map.insert(
            "datacontenttype".to_string(),
            Value::String(self.datacontenttype.clone()),
        );
        if let Some(s) = &self.subject {
            map.insert("subject".to_string(), Value::String(s.clone()));
        }
        if let Some(ds) = &self.dataschema {
            map.insert("dataschema".to_string(), Value::String(ds.clone()));
        }
        map.insert("data".to_string(), self.data.clone());
        for (k, v) in &self.extensions {
            map.insert(k.clone(), Value::String(v.clone()));
        }
        sha256_hex(canonical_json(&Value::Object(map)).as_bytes())
    }
}

// ---- CloudEvents Subscriptions API v1.0 Filter AST ----

/// CloudEvents Subscriptions API v1.0 filter AST node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Filter {
    Exact(BTreeMap<String, String>),
    Prefix(BTreeMap<String, String>),
    Suffix(BTreeMap<String, String>),
    All(Vec<Filter>),
    Any(Vec<Filter>),
    Not(Box<Filter>),
}

impl Filter {
    pub fn exact(key: impl Into<String>, value: impl Into<String>) -> Self {
        let mut map = BTreeMap::new();
        map.insert(key.into(), value.into());
        Self::Exact(map)
    }

    pub fn prefix(key: impl Into<String>, value: impl Into<String>) -> Self {
        let mut map = BTreeMap::new();
        map.insert(key.into(), value.into());
        Self::Prefix(map)
    }

    pub fn suffix(key: impl Into<String>, value: impl Into<String>) -> Self {
        let mut map = BTreeMap::new();
        map.insert(key.into(), value.into());
        Self::Suffix(map)
    }
}

/// Validates a slice of filters against byte size, nesting depth, and key grammar limits.
pub fn check_filters(filters: &[Filter]) -> StoreResult<()> {
    let serialized = serde_json::to_string(filters)?;
    if serialized.len() > MAX_FILTERS_BYTES {
        return Err(StoreError::InvalidFilter {
            path: "filters".to_string(),
            message: format!("filters exceed {MAX_FILTERS_BYTES} bytes"),
        });
    }
    for (idx, filter) in filters.iter().enumerate() {
        check_filter_node(filter, &format!("filters[{idx}]"), 1)?;
    }
    Ok(())
}

/// Parses and validates a JSON filters array string.
pub fn parse_and_check_filters(json: &str) -> StoreResult<Vec<Filter>> {
    if json.len() > MAX_FILTERS_BYTES {
        return Err(StoreError::InvalidFilter {
            path: "filters".to_string(),
            message: format!("filters exceed {MAX_FILTERS_BYTES} bytes"),
        });
    }
    let filters: Vec<Filter> =
        serde_json::from_str(json).map_err(|err| StoreError::InvalidFilter {
            path: "filters".to_string(),
            message: err.to_string(),
        })?;
    check_filters(&filters)?;
    Ok(filters)
}

fn check_filter_node(filter: &Filter, path: &str, depth: usize) -> StoreResult<()> {
    if depth > MAX_FILTER_DEPTH {
        return Err(StoreError::InvalidFilter {
            path: path.to_string(),
            message: format!("filters nest deeper than {MAX_FILTER_DEPTH}"),
        });
    }
    match filter {
        Filter::Exact(map) | Filter::Prefix(map) | Filter::Suffix(map) => {
            let dialect = match filter {
                Filter::Exact(_) => "exact",
                Filter::Prefix(_) => "prefix",
                Filter::Suffix(_) => "suffix",
                _ => unreachable!(),
            };
            let at = format!("{path}.{dialect}");
            if map.is_empty() {
                return Err(StoreError::InvalidFilter {
                    path: at,
                    message: "expected a non-empty attribute map".to_string(),
                });
            }
            for key in map.keys() {
                if !is_valid_filter_key(key) {
                    return Err(StoreError::InvalidFilter {
                        path: format!("{at}[{key:?}]"),
                        message: "keys must be attribute names or data.<field>".to_string(),
                    });
                }
            }
        }
        Filter::All(inner) | Filter::Any(inner) => {
            let dialect = if matches!(filter, Filter::All(_)) {
                "all"
            } else {
                "any"
            };
            let at = format!("{path}.{dialect}");
            if inner.is_empty() {
                return Err(StoreError::InvalidFilter {
                    path: at,
                    message: "expected a non-empty array of filters".to_string(),
                });
            }
            for (idx, child) in inner.iter().enumerate() {
                check_filter_node(child, &format!("{at}[{idx}]"), depth + 1)?;
            }
        }
        Filter::Not(child) => {
            check_filter_node(child, &format!("{path}.not"), depth + 1)?;
        }
    }
    Ok(())
}

fn value_texts(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => out.push(s.clone()),
        Value::Number(n) => out.push(n.to_string()),
        Value::Bool(b) => out.push(if *b { "true" } else { "false" }.to_string()),
        Value::Array(arr) => {
            for item in arr {
                if !item.is_array() {
                    value_texts(item, out);
                }
            }
        }
        Value::Null | Value::Object(_) => {}
    }
}

fn lookup_event_attribute(event: &CloudEvent, key: &str) -> Vec<String> {
    if let Some(field) = key.strip_prefix("data.") {
        let mut out = Vec::new();
        if let Some(obj) = event.data.as_object() {
            if let Some(val) = obj.get(field) {
                value_texts(val, &mut out);
            }
        }
        return out;
    }
    match key {
        "specversion" => vec![event.specversion.clone()],
        "id" => vec![event.id.clone()],
        "source" => vec![event.source.clone()],
        "type" => vec![event.event_type.clone()],
        "datacontenttype" => vec![event.datacontenttype.clone()],
        "subject" => event.subject.iter().cloned().collect(),
        "time" => event.time.iter().cloned().collect(),
        "dataschema" => event.dataschema.iter().cloned().collect(),
        "data" => Vec::new(),
        other => event.extensions.get(other).cloned().into_iter().collect(),
    }
}

fn compare_pairs(
    pairs: &BTreeMap<String, String>,
    event: &CloudEvent,
    pred: fn(&str, &str) -> bool,
) -> bool {
    pairs.iter().all(|(key, expected)| {
        lookup_event_attribute(event, key)
            .iter()
            .any(|actual| pred(actual, expected))
    })
}

/// Evaluates a single CloudEvents Subscriptions API filter node against an event.
pub fn matches_filter(filter: &Filter, event: &CloudEvent) -> bool {
    match filter {
        Filter::Exact(pairs) => compare_pairs(pairs, event, |a, e| a == e),
        Filter::Prefix(pairs) => compare_pairs(pairs, event, |a, e| a.starts_with(e)),
        Filter::Suffix(pairs) => compare_pairs(pairs, event, |a, e| a.ends_with(e)),
        Filter::All(inner) => inner.iter().all(|f| matches_filter(f, event)),
        Filter::Any(inner) => inner.iter().any(|f| matches_filter(f, event)),
        Filter::Not(inner) => !matches_filter(inner, event),
    }
}

/// Evaluates a top-level filter list (logical AND; empty slice matches every event).
pub fn matches_filters(filters: &[Filter], event: &CloudEvent) -> bool {
    filters.iter().all(|f| matches_filter(f, event))
}

// ---- Shared Enums ----

/// Outcome supplied by a recipient acknowledging a message, event batch, or transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum AckOutcome {
    Delivered,
    Hold {
        reason: String,
        #[serde(default)]
        retry_after_ms: Option<i64>,
    },
    Rejected {
        reason: String,
    },
}

/// Session & subscription delivery mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeliveryMode {
    Full,
    Notify,
}

impl DeliveryMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Notify => "notify",
        }
    }

    pub fn parse(s: &str) -> StoreResult<Self> {
        match s {
            "full" => Ok(Self::Full),
            "notify" => Ok(Self::Notify),
            other => Err(StoreError::InvalidInput(format!(
                "invalid delivery mode '{other}'"
            ))),
        }
    }
}

/// Local Security Gate state for a mailbox entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GateState {
    Pending,
    Delivered,
    Quarantined,
    Rejected,
}

impl GateState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Delivered => "delivered",
            Self::Quarantined => "quarantined",
            Self::Rejected => "rejected",
        }
    }

    pub fn parse(s: &str) -> StoreResult<Self> {
        match s {
            "pending" => Ok(Self::Pending),
            "delivered" => Ok(Self::Delivered),
            "quarantined" => Ok(Self::Quarantined),
            "rejected" => Ok(Self::Rejected),
            other => Err(StoreError::InvalidInput(format!(
                "invalid gate state '{other}'"
            ))),
        }
    }
}

/// Security Gate decision recorded in the immutable `gate_audit` log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GateDecision {
    Allow,
    Quarantine,
    Block,
    Error,
}

impl GateDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Quarantine => "quarantine",
            Self::Block => "block",
            Self::Error => "error",
        }
    }

    pub fn parse(s: &str) -> StoreResult<Self> {
        match s {
            "allow" => Ok(Self::Allow),
            "quarantine" => Ok(Self::Quarantine),
            "block" => Ok(Self::Block),
            "error" => Ok(Self::Error),
            other => Err(StoreError::InvalidInput(format!(
                "invalid gate decision '{other}'"
            ))),
        }
    }
}

/// Direction of a Security Gate audit event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GateDirection {
    Inbound,
    Outbound,
    Review,
}

impl GateDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
            Self::Review => "review",
        }
    }

    pub fn parse(s: &str) -> StoreResult<Self> {
        match s {
            "inbound" => Ok(Self::Inbound),
            "outbound" => Ok(Self::Outbound),
            "review" => Ok(Self::Review),
            other => Err(StoreError::InvalidInput(format!(
                "invalid gate direction '{other}'"
            ))),
        }
    }
}

/// Kind of item parked in a local session mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MailboxKind {
    Message,
    Event,
    Plugin,
    Transfer,
    Kv,
}

impl MailboxKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Message => "message",
            Self::Event => "event",
            Self::Plugin => "plugin",
            Self::Transfer => "transfer",
            Self::Kv => "kv",
        }
    }

    pub fn parse(s: &str) -> StoreResult<Self> {
        match s {
            "message" => Ok(Self::Message),
            "event" => Ok(Self::Event),
            "plugin" => Ok(Self::Plugin),
            "transfer" => Ok(Self::Transfer),
            "kv" => Ok(Self::Kv),
            other => Err(StoreError::InvalidInput(format!(
                "invalid mailbox kind '{other}'"
            ))),
        }
    }
}

/// Shared KV write concurrency/authorization model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WriteModel {
    Owner,
    Shared,
    Allowlist,
}

impl WriteModel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Owner => "owner",
            Self::Shared => "shared",
            Self::Allowlist => "allowlist",
        }
    }

    pub fn parse(s: &str) -> StoreResult<Self> {
        match s {
            "owner" => Ok(Self::Owner),
            "shared" => Ok(Self::Shared),
            "allowlist" => Ok(Self::Allowlist),
            other => Err(StoreError::InvalidInput(format!(
                "invalid kv write model '{other}'"
            ))),
        }
    }
}

/// Node configuration profile for a paired peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerProfile {
    Local,
    Router,
    P2p,
}

impl PeerProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Router => "router",
            Self::P2p => "p2p",
        }
    }

    pub fn parse(s: &str) -> StoreResult<Self> {
        match s {
            "local" => Ok(Self::Local),
            "router" => Ok(Self::Router),
            "p2p" => Ok(Self::P2p),
            other => Err(StoreError::InvalidInput(format!(
                "invalid peer profile '{other}'"
            ))),
        }
    }
}

/// Peer trust tier used for pairing scopes and Security Gate defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrustTier {
    #[serde(rename = "self")]
    SelfNode,
    Org,
    Peer,
    Guest,
}

impl TrustTier {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SelfNode => "self",
            Self::Org => "org",
            Self::Peer => "peer",
            Self::Guest => "guest",
        }
    }

    pub fn parse(s: &str) -> StoreResult<Self> {
        match s {
            "self" => Ok(Self::SelfNode),
            "org" => Ok(Self::Org),
            "peer" => Ok(Self::Peer),
            "guest" => Ok(Self::Guest),
            other => Err(StoreError::InvalidInput(format!(
                "invalid trust tier '{other}'"
            ))),
        }
    }
}

/// Lifecycle state of a paired peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PeerStatus {
    Pending,
    Active,
    Paused,
    Revoked,
}

impl PeerStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Revoked => "revoked",
        }
    }

    pub fn parse(s: &str) -> StoreResult<Self> {
        match s {
            "pending" => Ok(Self::Pending),
            "active" => Ok(Self::Active),
            "paused" => Ok(Self::Paused),
            "revoked" => Ok(Self::Revoked),
            other => Err(StoreError::InvalidInput(format!(
                "invalid peer status '{other}'"
            ))),
        }
    }
}

/// Direction of a stored grant relative to this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum GrantDirection {
    Inbound,
    Outbound,
}

impl GrantDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Inbound => "inbound",
            Self::Outbound => "outbound",
        }
    }

    pub fn parse(s: &str) -> StoreResult<Self> {
        match s {
            "inbound" => Ok(Self::Inbound),
            "outbound" => Ok(Self::Outbound),
            other => Err(StoreError::InvalidInput(format!(
                "invalid grant direction '{other}'"
            ))),
        }
    }
}

/// Key purpose in `peer_keys`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyUse {
    Signing,
    Encryption,
    Prekey,
    Admin,
}

impl KeyUse {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Signing => "signing",
            Self::Encryption => "encryption",
            Self::Prekey => "prekey",
            Self::Admin => "admin",
        }
    }

    pub fn parse(s: &str) -> StoreResult<Self> {
        match s {
            "signing" => Ok(Self::Signing),
            "encryption" => Ok(Self::Encryption),
            "prekey" => Ok(Self::Prekey),
            "admin" => Ok(Self::Admin),
            other => Err(StoreError::InvalidInput(format!(
                "invalid key use '{other}'"
            ))),
        }
    }
}

/// Lifecycle state of a peer JWK in `peer_keys`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KeyStatus {
    Active,
    Retired,
    Revoked,
}

impl KeyStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Retired => "retired",
            Self::Revoked => "revoked",
        }
    }

    pub fn parse(s: &str) -> StoreResult<Self> {
        match s {
            "active" => Ok(Self::Active),
            "retired" => Ok(Self::Retired),
            "revoked" => Ok(Self::Revoked),
            other => Err(StoreError::InvalidInput(format!(
                "invalid key status '{other}'"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn rfc3339_formatting_handles_epoch_and_leap_years() {
        assert_eq!(epoch_ms_to_rfc3339(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            epoch_ms_to_rfc3339(1_709_164_800_123),
            "2024-02-29T00:00:00.123Z"
        );
        assert_eq!(
            epoch_ms_to_rfc3339(1_700_000_000_000),
            "2023-11-14T22:13:20.000Z"
        );
    }

    #[test]
    fn canonical_json_and_event_digest_ignore_key_order_and_time() {
        let a = json!({ "b": 1, "a": { "y": true, "x": [3, 2, 1] } });
        let b = json!({ "a": { "x": [3, 2, 1], "y": true }, "b": 1 });
        assert_eq!(canonical_json(&a), canonical_json(&b));

        let ev1 = CloudEvent::new("1", "src", "t", a).with_time("2025-01-01T00:00:00.000Z");
        let ev2 = CloudEvent::new("1", "src", "t", b).with_time("2026-01-01T00:00:00.000Z");
        assert_eq!(ev1.digest(), ev2.digest());
    }

    #[test]
    fn identifier_validators_enforce_grammars() {
        assert!(is_node_id("alice@macbook"));
        assert!(is_node_id("public.hyphae.to"));
        assert!(!is_node_id("-bad"));
        assert!(!is_node_id("UPPER"));

        assert!(is_channel_name("#incidents"));
        assert!(!is_channel_name("incidents"));
        assert!(!is_channel_name("#"));

        assert!(is_safe_transfer_id("tx_123-ABC"));
        assert!(!is_safe_transfer_id("../etc/passwd"));
        assert!(!is_safe_transfer_id("a/b"));

        assert!(is_kv_key("plan/v1/step"));
        assert!(!is_kv_key("../escape"));
        assert!(!is_kv_key("/leading"));
        assert!(!is_kv_key("has space"));
    }

    #[test]
    fn filter_ast_dialects_all_any_not_prefix_suffix() {
        let ev = CloudEvent::new(
            "e1",
            "github.com/acme/checkout",
            "com.github.pull_request.opened",
            json!({ "labels": ["bug", "p1"] }),
        )
        .with_extension("repo", "acme/checkout");

        let filters = vec![
            Filter::All(vec![
                Filter::prefix("type", "com.github.pull_request."),
                Filter::suffix("source", "/checkout"),
            ]),
            Filter::Any(vec![
                Filter::exact("data.labels", "p0"),
                Filter::exact("data.labels", "p1"),
            ]),
            Filter::Not(Box::new(Filter::exact("repo", "acme/ignored"))),
        ];
        check_filters(&filters).unwrap();
        assert!(matches_filters(&filters, &ev));
    }
}
