//! JSON-RPC 2.0 over NDJSON plugin frame codec (`HYPHAE_PROTOCOL=2`),
//! bounded strictly at `MAX_FRAME_BYTES` (64 KiB).

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use thiserror::Error;

/// Hard frame cap matching `MAX_LINE_BYTES` in `src/core/plugins/protocol.ts` (64 KiB).
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
pub const JSONRPC_VERSION: &str = "2.0";

// ---- Standard Hyphae v2 JSON-RPC 2.0 plugin methods (§6.4) ----

pub const METHOD_HELLO: &str = "hyphae/hello";
pub const METHOD_PUBLISH: &str = "hyphae/publish";
pub const METHOD_POST: &str = "hyphae/post";
pub const METHOD_STATUS: &str = "hyphae/status";
pub const METHOD_DELIVERY_FAILED: &str = "hyphae/deliveryFailed";
pub const METHOD_SYSTEM_WAKE: &str = "system.wake";

// ---- Standard JSON-RPC 2.0 error codes + Hyphae server codes ----

pub const ERR_PARSE_ERROR: i32 = -32700;
pub const ERR_INVALID_REQUEST: i32 = -32600;
pub const ERR_METHOD_NOT_FOUND: i32 = -32601;
pub const ERR_INVALID_PARAMS: i32 = -32602;
pub const ERR_INTERNAL_ERROR: i32 = -32603;

pub const ERR_TOO_LARGE: i32 = -32001;
pub const ERR_INVALID_EVENT: i32 = -32002;
pub const ERR_UNKNOWN_TARGET: i32 = -32003;
pub const ERR_ID_CONFLICT: i32 = -32004;
pub const ERR_UNAVAILABLE: i32 = -32005;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FrameError {
    #[error("frame is {len} bytes; limit {limit} bytes")]
    FrameTooLarge { len: usize, limit: usize },
    #[error("NDJSON frame contains an embedded newline")]
    EmbeddedNewline,
    #[error("frame is not valid JSON: {0}")]
    InvalidJson(String),
    #[error("invalid plugin frame: {0}")]
    InvalidFrame(String),
}

/// JSON-RPC 2.0 request/response identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RpcId {
    String(String),
    Number(i64),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: RpcId,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcRequest {
    pub fn new(id: RpcId, method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            method: method.into(),
            params,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

impl JsonRpcNotification {
    pub fn new(method: impl Into<String>, params: Option<Value>) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            method: method.into(),
            params,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: Option<RpcId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(default, deserialize_with = "present_result")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

fn present_result<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}

impl JsonRpcResponse {
    pub fn ok(id: RpcId, result: Value) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id: Some(id),
            result: Some(result),
            error: None,
        }
    }

    pub fn err(
        id: Option<RpcId>,
        code: i32,
        message: impl Into<String>,
        data: Option<Value>,
    ) -> Self {
        Self {
            jsonrpc: JSONRPC_VERSION.to_string(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data,
            }),
        }
    }
}

// ---- Strongly-Typed Hyphae v2 Method Payloads ----

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventKeyRef {
    pub id: String,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloParams {
    pub protocol: u32,
    pub plugin: String,
    pub targets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublishParams {
    pub to: String,
    pub event: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PostParams {
    pub target: String,
    pub params: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatusParams {
    pub target: String,
    pub pending: u64,
    pub oldest_age_seconds: u64,
    pub t3_connected: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryFailedParams {
    pub target: String,
    pub events: Vec<EventKeyRef>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemWakeParams {
    pub slept_ms: u64,
}

/// JSON-RPC 2.0 plugin IPC frame. Protocol v1 is deliberately unsupported.
#[derive(Debug, Clone, PartialEq)]
pub enum PluginFrame {
    JsonRpcRequest(JsonRpcRequest),
    JsonRpcNotification(JsonRpcNotification),
    JsonRpcResponse(JsonRpcResponse),
}

/// Decodes one bounded JSON-RPC 2.0 NDJSON line. No legacy negotiation or fallback.
pub fn decode_frame(line: &str) -> Result<PluginFrame, FrameError> {
    let trimmed = line
        .strip_suffix('\n')
        .unwrap_or(line)
        .strip_suffix('\r')
        .unwrap_or_else(|| line.strip_suffix('\n').unwrap_or(line));

    if trimmed.len() > MAX_FRAME_BYTES {
        return Err(FrameError::FrameTooLarge {
            len: trimmed.len(),
            limit: MAX_FRAME_BYTES,
        });
    }
    if trimmed.contains('\n') {
        return Err(FrameError::EmbeddedNewline);
    }

    let val: Value =
        serde_json::from_str(trimmed).map_err(|e| FrameError::InvalidJson(e.to_string()))?;
    let Value::Object(ref map) = val else {
        return Err(FrameError::InvalidFrame(
            "frame must be a JSON object".to_string(),
        ));
    };

    // Detect JSON-RPC 2.0 first.
    if let Some(version) = map.get("jsonrpc") {
        if version.as_str() != Some(JSONRPC_VERSION) {
            return Err(FrameError::InvalidFrame(
                "jsonrpc field must be \"2.0\"".to_string(),
            ));
        }
        let has_method = map.contains_key("method");
        let has_id = map.contains_key("id");
        let has_result = map.contains_key("result");
        let has_error = map.contains_key("error");

        if has_method {
            if has_result || has_error {
                return Err(FrameError::InvalidFrame(
                    "JSON-RPC request/notification cannot contain result or error".to_string(),
                ));
            }
            if has_id {
                let req: JsonRpcRequest = serde_json::from_value(val)
                    .map_err(|e| FrameError::InvalidFrame(e.to_string()))?;
                return Ok(PluginFrame::JsonRpcRequest(req));
            }
            let notif: JsonRpcNotification =
                serde_json::from_value(val).map_err(|e| FrameError::InvalidFrame(e.to_string()))?;
            return Ok(PluginFrame::JsonRpcNotification(notif));
        }

        if has_result == has_error {
            return Err(FrameError::InvalidFrame(
                "JSON-RPC response must contain exactly one of result or error".to_string(),
            ));
        }
        if !has_id {
            return Err(FrameError::InvalidFrame(
                "JSON-RPC response must contain an id field".to_string(),
            ));
        }
        if has_error && !map.get("error").is_some_and(Value::is_object) {
            return Err(FrameError::InvalidFrame(
                "JSON-RPC error must be an object".into(),
            ));
        }
        let resp: JsonRpcResponse =
            serde_json::from_value(val).map_err(|e| FrameError::InvalidFrame(e.to_string()))?;
        return Ok(PluginFrame::JsonRpcResponse(resp));
    }

    Err(FrameError::InvalidFrame(
        "plugin frames require jsonrpc=\"2.0\"; protocol v1 is not supported".into(),
    ))
}

/// Encodes a `PluginFrame` as compact single-line NDJSON terminated by `\n`,
/// enforcing the 64 KiB frame cap.
pub fn encode_frame(frame: &PluginFrame) -> Result<String, FrameError> {
    let mut json = match frame {
        PluginFrame::JsonRpcRequest(r) => serde_json::to_string(r),
        PluginFrame::JsonRpcNotification(n) => serde_json::to_string(n),
        PluginFrame::JsonRpcResponse(r) => serde_json::to_string(r),
    }
    .map_err(|e| FrameError::InvalidFrame(e.to_string()))?;

    if json.len() > MAX_FRAME_BYTES {
        return Err(FrameError::FrameTooLarge {
            len: json.len(),
            limit: MAX_FRAME_BYTES,
        });
    }
    json.push('\n');
    Ok(json)
}

/// Bounded streaming NDJSON line splitter matching `LineSplitter` in `src/core/plugins/protocol.ts`.
///
/// Guarantees memory usage stays bounded at `max_bytes` even if a plugin streams gigabytes
/// without sending a newline.
#[derive(Debug, Clone)]
pub struct LineSplitter {
    max_bytes: usize,
    keep_prefix: bool,
    buf: Vec<u8>,
    overflow: bool,
}

impl LineSplitter {
    pub fn new(max_bytes: usize, keep_prefix: bool) -> Self {
        Self {
            max_bytes,
            keep_prefix,
            buf: Vec::new(),
            overflow: false,
        }
    }

    pub fn overflowing(&self) -> bool {
        self.overflow
    }

    /// Feeds a chunk of bytes and invokes `on_line(text, truncated)` for each completed line.
    pub fn push(&mut self, chunk: &[u8], mut on_line: impl FnMut(String, bool)) {
        let mut start = 0;
        while start <= chunk.len() {
            match chunk[start..].iter().position(|&b| b == b'\n') {
                Some(rel) => {
                    self.take(&chunk[start..start + rel]);
                    self.emit(&mut on_line);
                    start += rel + 1;
                    if start == chunk.len() {
                        break;
                    }
                }
                None => {
                    self.take(&chunk[start..]);
                    break;
                }
            }
        }
    }

    /// Emits any trailing unterminated line.
    pub fn flush(&mut self, mut on_line: impl FnMut(String, bool)) {
        if !self.buf.is_empty() || self.overflow {
            self.emit(&mut on_line);
        }
    }

    fn take(&mut self, part: &[u8]) {
        if self.overflow && !self.keep_prefix {
            return;
        }
        let room = self.max_bytes.saturating_sub(self.buf.len());
        if part.len() > room {
            self.overflow = true;
            if !self.keep_prefix {
                self.buf.clear();
                return;
            }
        }
        let take_len = room.min(part.len());
        if take_len > 0 {
            self.buf.extend_from_slice(&part[..take_len]);
        }
    }

    fn emit(&mut self, on_line: &mut impl FnMut(String, bool)) {
        let truncated = self.overflow;
        let mut text = String::from_utf8_lossy(&self.buf).into_owned();
        if text.ends_with('\r') {
            text.pop();
        }
        self.buf.clear();
        self.overflow = false;
        on_line(text, truncated);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn jsonrpc_v2_roundtrip_and_method_params() {
        let req = PluginFrame::JsonRpcRequest(JsonRpcRequest::new(
            RpcId::Number(1),
            METHOD_PUBLISH,
            Some(
                serde_json::to_value(PublishParams {
                    to: "ops".to_string(),
                    event: json!({"specversion":"1.0","id":"1","source":"slack","type":"to.hyphae.bridge.slack","data":{}}),
                })
                .unwrap(),
            ),
        ));
        let wire = encode_frame(&req).unwrap();
        assert!(wire.ends_with('\n'));
        let decoded = decode_frame(&wire).unwrap();
        assert_eq!(decoded, req);

        let notif = PluginFrame::JsonRpcNotification(JsonRpcNotification::new(
            METHOD_STATUS,
            Some(
                serde_json::to_value(StatusParams {
                    target: "ops".to_string(),
                    pending: 2,
                    oldest_age_seconds: 15,
                    t3_connected: true,
                })
                .unwrap(),
            ),
        ));
        assert_eq!(decode_frame(&encode_frame(&notif).unwrap()).unwrap(), notif);

        let resp = PluginFrame::JsonRpcResponse(JsonRpcResponse::ok(
            RpcId::String("req-9".to_string()),
            json!({"status": "stored"}),
        ));
        assert_eq!(decode_frame(&encode_frame(&resp).unwrap()).unwrap(), resp);

        let wake = PluginFrame::JsonRpcNotification(JsonRpcNotification::new(
            METHOD_SYSTEM_WAKE,
            Some(serde_json::to_value(SystemWakeParams { slept_ms: 600_000 }).unwrap()),
        ));
        let wake_wire = encode_frame(&wake).unwrap();
        assert_eq!(
            wake_wire,
            "{\"jsonrpc\":\"2.0\",\"method\":\"system.wake\",\"params\":{\"sleptMs\":600000}}\n"
        );
        assert_eq!(decode_frame(&wake_wire).unwrap(), wake);
    }

    #[test]
    fn retired_plugin_v1_frames_are_rejected() {
        let legacy_lines = [
            r#"{"type":"hello","protocol":1,"plugin":"slack","targets":["ops"]}"#,
            r#"{"type":"event","to":"ops","event":{"id":"1","source":"slack"}}"#,
            r#"{"type":"ack","id":"1","source":"slack","status":"stored"}"#,
            r#"{"type":"nack","id":null,"source":null,"error":"too_large","message":"over 64k"}"#,
            r#"{"type":"request","id":"r1","method":"post","target":"ops","params":{"text":"hi"}}"#,
            r#"{"type":"response","id":"r1","ok":true,"result":{"ts":"123"}}"#,
            r#"{"type":"status","target":"ops","pending":0,"oldestAgeSeconds":0,"t3Connected":true}"#,
            r#"{"type":"delivery_failed","target":"ops","events":[{"id":"1","source":"s"}],"reason":"expired"}"#,
        ];

        for line in legacy_lines {
            assert!(matches!(
                decode_frame(line),
                Err(FrameError::InvalidFrame(_))
            ));
        }
    }

    #[test]
    fn enforces_64kib_cap_and_bounded_line_splitter() {
        let huge = format!(
            r#"{{"jsonrpc":"2.0","id":"huge","method":"hyphae/publish","params":{{"to":"a","event":"{}"}}}}"#,
            "x".repeat(MAX_FRAME_BYTES)
        );
        assert!(matches!(
            decode_frame(&huge),
            Err(FrameError::FrameTooLarge { .. })
        ));

        // Invalid JSON-RPC response with both result and error fails closed.
        assert!(
            decode_frame(
                r#"{"jsonrpc":"2.0","id":1,"result":1,"error":{"code":-1,"message":"x"}}"#
            )
            .is_err()
        );

        let mut splitter = LineSplitter::new(16, false);
        let mut lines = Vec::new();
        splitter.push(b"short\r\n0123456789abcdefOVERFLOW\nnext", |l, trunc| {
            lines.push((l, trunc));
        });
        splitter.flush(|l, trunc| lines.push((l, trunc)));
        assert_eq!(
            lines,
            vec![
                ("short".to_string(), false),
                ("".to_string(), true),
                ("next".to_string(), false),
            ]
        );
    }
}
