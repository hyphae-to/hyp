//! Clean `hyper 1` + `hyper-util` + `hyper-rustls` HTTP/1.1+2 helpers:
//! - Bounded request body reading
//! - JSON & RFC 9457 `application/problem+json` response builders
//! - RFC 9110 `ETag` / `If-None-Match` / `If-Match` / `Retry-After` helpers
//! - WHATWG Server-Sent Events (SSE) encoder & incremental streaming parser
//! - Outbound `HttpClient` supporting both HTTPS (`webpki-roots` + `ring`) and loopback HTTP.

use std::collections::BTreeMap;
use std::io;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::{Bytes, BytesMut};
use http::header::{
    CACHE_CONTROL, CONNECTION, CONTENT_TYPE, ETAG, HOST, IF_MATCH, IF_NONE_MATCH, RETRY_AFTER,
};
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode};
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Body, Frame, Incoming};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tokio::process::{Child, ChildStdin, ChildStdout, Command};
use tokio::sync::{mpsc, oneshot, watch};

pub use hyp_crypto::pairing::{SshEndpoint, parse_ssh_endpoint};
use hyp_proto::problem::{CONTENT_TYPE_PROBLEM_JSON, ProblemDetails};

use crate::engine::config::NodeError;

/// Optional environment variable overriding the `ssh` binary path (primarily for isolated tests).
pub const ENV_SSH_BIN: &str = "HYPHAE_SSH_BIN";

const MAX_SSH_STDERR_BYTES: usize = 4096;

/// Unified boxed HTTP body type used across both `hyper 1` server and client.
pub type BoxedBody = BoxBody<Bytes, io::Error>;

/// Wraps an owned byte payload as a `BoxedBody`.
pub fn full_body(bytes: impl Into<Bytes>) -> BoxedBody {
    Full::new(bytes.into())
        .map_err(|never| match never {})
        .boxed()
}

/// Returns an empty `BoxedBody`.
pub fn empty_body() -> BoxedBody {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

/// Streaming `http_body::Body` fed by an `mpsc::Receiver` (used for WHATWG SSE responses).
struct ChannelBody {
    rx: mpsc::Receiver<Result<Frame<Bytes>, io::Error>>,
}

impl Body for ChannelBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.rx.poll_recv(cx)
    }
}

/// Wraps an `mpsc::Receiver` into a streaming `BoxedBody`.
pub fn stream_body(rx: mpsc::Receiver<Result<Frame<Bytes>, io::Error>>) -> BoxedBody {
    ChannelBody { rx }.boxed()
}

/// Builds a JSON HTTP response (`Content-Type: application/json`).
pub fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response<BoxedBody> {
    match serde_json::to_vec(value) {
        Ok(bytes) => Response::builder()
            .status(status)
            .header(CONTENT_TYPE, "application/json")
            .body(full_body(bytes))
            .expect("valid HTTP response"),
        Err(err) => problem_response(&ProblemDetails::new(
            "internal_error",
            "internal-error",
            "Serialization Failed",
            500,
            err.to_string(),
        )),
    }
}

/// Builds a JSON HTTP response with a strong RFC 9110 `ETag` header.
pub fn json_response_with_etag<T: Serialize>(
    status: StatusCode,
    value: &T,
    etag: &str,
) -> Response<BoxedBody> {
    let mut resp = json_response(status, value);
    if let Ok(val) = HeaderValue::from_str(etag) {
        resp.headers_mut().insert(ETAG, val);
    }
    resp
}

/// Builds a raw bytes HTTP response.
pub fn bytes_response(
    status: StatusCode,
    content_type: &str,
    bytes: impl Into<Bytes>,
) -> Response<BoxedBody> {
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, content_type)
        .body(full_body(bytes))
        .expect("valid HTTP response")
}

/// Builds an RFC 9457 `application/problem+json` response.
pub fn problem_response(problem: &ProblemDetails) -> Response<BoxedBody> {
    let status = StatusCode::from_u16(problem.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = serde_json::to_vec(problem).unwrap_or_else(|_| {
        b"{\"type\":\"https://hyphae.to/errors/internal-error\",\"title\":\"Internal Error\",\"status\":500,\"error\":\"internal_error\"}".to_vec()
    });
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, CONTENT_TYPE_PROBLEM_JSON)
        .body(full_body(body))
        .expect("valid problem response")
}

/// Builds a `304 Not Modified` response preserving the resource `ETag`.
pub fn not_modified_response(etag: &str) -> Response<BoxedBody> {
    let mut builder = Response::builder().status(StatusCode::NOT_MODIFIED);
    if let Ok(val) = HeaderValue::from_str(etag) {
        builder = builder.header(ETAG, val);
    }
    builder.body(empty_body()).expect("valid 304 response")
}

/// Builds a WHATWG `text/event-stream` response backed by `rx`.
pub fn sse_response(rx: mpsc::Receiver<Result<Frame<Bytes>, io::Error>>) -> Response<BoxedBody> {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/event-stream; charset=utf-8")
        .header(CACHE_CONTROL, "no-cache")
        .header(CONNECTION, "keep-alive")
        .body(stream_body(rx))
        .expect("valid SSE response")
}

/// Attaches an RFC 9110 `Retry-After` delta-seconds header to a response.
pub fn with_retry_after(mut resp: Response<BoxedBody>, seconds: u64) -> Response<BoxedBody> {
    if let Ok(val) = HeaderValue::from_str(&seconds.to_string()) {
        resp.headers_mut().insert(RETRY_AFTER, val);
    }
    resp
}

/// Reads an HTTP body up to `max_bytes`, failing closed with `PayloadTooLarge` if exceeded.
pub async fn read_body_bytes(mut body: Incoming, max_bytes: usize) -> Result<Bytes, NodeError> {
    let mut buf = BytesMut::new();
    while let Some(frame_res) = body.frame().await {
        let frame = frame_res.map_err(|e| NodeError::Http(format!("body read error: {e}")))?;
        if let Some(data) = frame.data_ref() {
            if buf.len().saturating_add(data.len()) > max_bytes {
                return Err(NodeError::PayloadTooLarge(format!(
                    "request body exceeds limit of {max_bytes} bytes"
                )));
            }
            buf.extend_from_slice(data);
        }
    }
    Ok(buf.freeze())
}

/// Reads and JSON-deserializes an HTTP body with a hard byte limit.
pub async fn read_json_body<T: DeserializeOwned>(
    body: Incoming,
    max_bytes: usize,
) -> Result<T, NodeError> {
    let bytes = read_body_bytes(body, max_bytes).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

// ============================================================================
// RFC 9110 ETag / If-None-Match / If-Match / Retry-After Helpers
// ============================================================================

/// Computes a strong RFC 9110 quoted ETag (`"sha256-<32hex>"`) from raw representation bytes.
pub fn compute_etag(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    format!("\"sha256-{}\"", hex::encode(&digest[..16]))
}

/// Formats a KV version as a strong RFC 9110 ETag (`"<version>"`).
pub fn format_version_etag(version: u64) -> String {
    format!("\"{version}\"")
}

fn strip_etag_quotes(tag: &str) -> &str {
    let trimmed = tag.trim();
    let without_weak = trimmed
        .strip_prefix("W/")
        .or_else(|| trimmed.strip_prefix("w/"))
        .unwrap_or(trimmed);
    without_weak
        .strip_prefix('"')
        .and_then(|s| s.strip_suffix('"'))
        .unwrap_or(without_weak)
}

/// Evaluates RFC 9110 §13.1.2 `If-None-Match` against the current `etag` (weak comparison).
pub fn etag_matches_if_none_match(headers: &HeaderMap, current_etag: &str) -> bool {
    let Some(raw) = headers.get(IF_NONE_MATCH).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let target = strip_etag_quotes(current_etag);
    for candidate in raw.split(',') {
        let c = candidate.trim();
        if c == "*" || strip_etag_quotes(c) == target {
            return true;
        }
    }
    false
}

/// Parses an RFC 9110 `If-Match` version header for Shared KV optimistic CAS (`"42"`, `42`, `W/"42"`).
pub fn parse_if_match_version(headers: &HeaderMap) -> Result<Option<u64>, NodeError> {
    let Some(val) = headers.get(IF_MATCH) else {
        return Ok(None);
    };
    let raw = val
        .to_str()
        .map_err(|_| NodeError::BadRequest("If-Match header is not valid ASCII".into()))?
        .trim();
    if raw.is_empty() || raw == "*" {
        return Ok(None);
    }
    let cleaned = strip_etag_quotes(raw);
    let version = cleaned.parse::<u64>().map_err(|_| {
        NodeError::BadRequest(format!(
            "If-Match header '{raw}' must be an integer version ETag (e.g. \"1\")"
        ))
    })?;
    Ok(Some(version))
}

/// Parses an RFC 9110 `Retry-After` delta-seconds header into milliseconds.
pub fn parse_retry_after_ms(headers: &HeaderMap) -> Option<u64> {
    let raw = headers.get(RETRY_AFTER)?.to_str().ok()?.trim();
    raw.parse::<u64>().ok().map(|secs| secs.saturating_mul(1000))
}

// ============================================================================
// WHATWG Server-Sent Events (SSE) Encoder & Incremental Streaming Line Parser
// ============================================================================

/// A single WHATWG Server-Sent Event frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub id: Option<String>,
    pub event: Option<String>,
    pub data: String,
    pub retry_ms: Option<u64>,
}

impl SseEvent {
    pub fn new(event: impl Into<String>, data: impl Into<String>) -> Self {
        Self {
            id: None,
            event: Some(event.into()),
            data: data.into(),
            retry_ms: None,
        }
    }

    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = Some(id.into());
        self
    }

    /// Encodes this event according to the WHATWG SSE specification.
    pub fn encode(&self) -> String {
        let mut out = String::new();
        if let Some(id) = &self.id {
            let clean: String = id.chars().filter(|&c| c != '\n' && c != '\r' && c != '\0').collect();
            out.push_str("id: ");
            out.push_str(&clean);
            out.push('\n');
        }
        if let Some(ev) = &self.event {
            let clean: String = ev.chars().filter(|&c| c != '\n' && c != '\r').collect();
            out.push_str("event: ");
            out.push_str(&clean);
            out.push('\n');
        }
        if let Some(retry) = self.retry_ms {
            out.push_str(&format!("retry: {retry}\n"));
        }
        if self.data.is_empty() {
            out.push_str("data:\n");
        } else {
            for line in self.data.split('\n') {
                let line = line.strip_suffix('\r').unwrap_or(line);
                out.push_str("data: ");
                out.push_str(line);
                out.push('\n');
            }
        }
        out.push('\n');
        out
    }
}

/// Returns a standard SSE comment keepalive frame (`: keepalive\n\n`).
pub fn sse_keepalive_frame() -> Bytes {
    Bytes::from_static(b": keepalive\n\n")
}

/// Incremental WHATWG SSE streaming line parser handling arbitrary TCP chunk boundaries.
#[derive(Debug, Default)]
pub struct SseParser {
    line_buf: Vec<u8>,
    cur_event: Option<String>,
    cur_id: Option<String>,
    cur_retry: Option<u64>,
    cur_data: Vec<String>,
    has_data: bool,
    last_event_id: Option<String>,
}

impl SseParser {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the most recently received `Last-Event-ID`.
    pub fn last_event_id(&self) -> Option<&str> {
        self.last_event_id.as_deref()
    }

    /// Feeds raw bytes from an HTTP chunk and returns all complete `SseEvent`s parsed so far.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<SseEvent> {
        let mut events = Vec::new();
        for &b in chunk {
            if b == b'\n' {
                if self.line_buf.last() == Some(&b'\r') {
                    self.line_buf.pop();
                }
                let line = String::from_utf8_lossy(&self.line_buf).into_owned();
                self.line_buf.clear();
                if let Some(ev) = self.process_line(&line) {
                    events.push(ev);
                }
            } else {
                self.line_buf.push(b);
            }
        }
        events
    }

    fn process_line(&mut self, line: &str) -> Option<SseEvent> {
        if line.is_empty() {
            if !self.has_data {
                self.cur_event = None;
                self.cur_retry = None;
                return None;
            }
            let data = self.cur_data.join("\n");
            self.cur_data.clear();
            self.has_data = false;
            let id = self.cur_id.take().or_else(|| self.last_event_id.clone());
            let event = self.cur_event.take();
            let retry_ms = self.cur_retry.take();
            return Some(SseEvent {
                id,
                event,
                data,
                retry_ms,
            });
        }

        // Comment line (`: ...`)
        if line.starts_with(':') {
            return None;
        }

        let (field, value) = match line.split_once(':') {
            Some((f, v)) => (f, v.strip_prefix(' ').unwrap_or(v)),
            None => (line, ""),
        };

        match field {
            "event" => self.cur_event = Some(value.to_string()),
            "data" => {
                self.cur_data.push(value.to_string());
                self.has_data = true;
            }
            "id" => {
                if !value.contains('\0') {
                    self.cur_id = Some(value.to_string());
                    self.last_event_id = Some(value.to_string());
                }
            }
            "retry" => {
                if let Ok(ms) = value.parse::<u64>() {
                    self.cur_retry = Some(ms);
                }
            }
            _ => {}
        }
        None
    }
}

// ============================================================================
// URL Query & Percent Encoding Helpers
// ============================================================================

/// Parses a URL query string (`a=1&b=hello%20world`) into a sorted map.
pub fn parse_query(query: Option<&str>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(q) = query else {
        return out;
    };
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(pair), String::new()),
        };
        out.insert(k, v);
    }
    out
}

/// Decodes RFC 3986 `%XX` escape sequences (plus `+` as space in query parameters).
pub fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(hi), Some(lo)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push((hi << 4) | lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Percent-encodes a single URL path segment or query value (RFC 3986 unreserved set).
pub fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

// ============================================================================
// Outbound HTTP/1.1+2 + rustls + Optional `ssh://` Client
// ============================================================================

/// AsyncRead + AsyncWrite wrapper over a spawned `ssh` child process's `stdout`/`stdin` pipes.
///
/// The underlying `Child` is spawned with `kill_on_drop(true)` and shared with the connection
/// driver task so dropping a connection or shutting down the node immediately kills and reaps
/// the child process without leaking zombies.
struct ChildStdioStream {
    stdin: ChildStdin,
    stdout: ChildStdout,
    _child: Arc<Mutex<Option<Child>>>,
}

impl AsyncRead for ChildStdioStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdout).poll_read(cx, buf)
    }
}

impl AsyncWrite for ChildStdioStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stdin).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdin).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdin).poll_shutdown(cx)
    }
}

/// Resolves the SSH executable (`HYPHAE_SSH_BIN` override when set, otherwise `ssh`).
pub fn resolve_ssh_binary() -> String {
    std::env::var(ENV_SSH_BIN)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "ssh".to_string())
}

fn format_ssh_stderr(buf: &Arc<Mutex<Vec<u8>>>) -> String {
    let guard = buf.lock().expect("ssh stderr buffer lock poisoned");
    if guard.is_empty() {
        return String::new();
    }
    let clean: String = String::from_utf8_lossy(&guard)
        .chars()
        .map(|c| if c.is_control() && c != '\n' { ' ' } else { c })
        .collect();
    let trimmed = clean.trim();
    if trimmed.is_empty() {
        String::new()
    } else {
        format!(" (ssh stderr: {trimmed})")
    }
}

/// Shared asynchronous HTTP/HTTPS/SSH client supporting HTTP/1.1, HTTP/2, streaming SSE,
/// and optional `ssh://` stdio-tunnelled HTTP/1.1 + SSE peers.
#[derive(Clone)]
pub struct HttpClient {
    inner: Client<HttpsConnector<HttpConnector>, BoxedBody>,
    ssh_shutdown: Arc<watch::Sender<bool>>,
}

impl HttpClient {
    /// Constructs a new `HttpClient` with `rustls` (`ring` + `webpki-roots`),
    /// permitting HTTPS, loopback HTTP, and strictly validated `ssh://` peer transports.
    pub fn new() -> Result<Self, NodeError> {
        let connector = HttpsConnectorBuilder::new()
            .with_provider_and_webpki_roots(rustls::crypto::ring::default_provider())
            .map_err(|e| NodeError::Http(format!("TLS connector init failed: {e}")))?
            .https_or_http()
            .enable_http1()
            .enable_http2()
            .build();
        let inner = Client::builder(TokioExecutor::new()).build(connector);
        let (ssh_shutdown, _) = watch::channel(false);
        Ok(Self {
            inner,
            ssh_shutdown: Arc::new(ssh_shutdown),
        })
    }

    /// Signals all active `ssh://` transport connections created by this client (or its clones)
    /// to terminate and reap their child processes immediately.
    pub fn shutdown_ssh(&self) {
        let _ = self.ssh_shutdown.send(true);
    }

    /// Sends an HTTP request and returns the raw streaming `hyper::Response<Incoming>`.
    ///
    /// Supports `https://`, loopback `http://`, and direct `ssh://[user@]host[:port]/path` URIs.
    /// For `ssh://` endpoints carrying query parameters (`?stateDir=...&bin=...`), prefer
    /// [`Self::request_for_endpoint`] with an origin-form request URI.
    pub async fn request(&self, req: Request<BoxedBody>) -> Result<Response<Incoming>, NodeError> {
        if req.uri().scheme_str() == Some("ssh") {
            let authority = req
                .uri()
                .authority()
                .map(|a| a.as_str())
                .ok_or_else(|| NodeError::Http("ssh:// request URI missing authority".into()))?;
            let base = format!("ssh://{authority}");
            let ssh = parse_ssh_endpoint(&base)?;
            return self.request_ssh_inner(&ssh, req, true, None).await;
        }
        self.inner
            .request(req)
            .await
            .map_err(|e| NodeError::Http(format!("HTTP request failed: {e}")))
    }

    /// Sends a one-shot request to `base_endpoint` (`https://`, loopback `http://`, or `ssh://`),
    /// combining `base_endpoint` with `req`'s origin-form `path_and_query`.
    pub async fn request_for_endpoint(
        &self,
        base_endpoint: &str,
        req: Request<BoxedBody>,
    ) -> Result<Response<Incoming>, NodeError> {
        self.request_for_endpoint_inner(base_endpoint, req, true, None)
            .await
    }

    /// Sends a long-lived streaming request (such as WHATWG SSE `GET /v1/inbox`) to
    /// `base_endpoint`, keeping the `ssh://` transport open until EOF, `cancel_rx`, or
    /// [`Self::shutdown_ssh`].
    pub async fn request_stream_for_endpoint(
        &self,
        base_endpoint: &str,
        req: Request<BoxedBody>,
        cancel_rx: Option<oneshot::Receiver<()>>,
    ) -> Result<Response<Incoming>, NodeError> {
        self.request_for_endpoint_inner(base_endpoint, req, false, cancel_rx)
            .await
    }

    async fn request_for_endpoint_inner(
        &self,
        base_endpoint: &str,
        mut req: Request<BoxedBody>,
        close_after_response: bool,
        cancel_rx: Option<oneshot::Receiver<()>>,
    ) -> Result<Response<Incoming>, NodeError> {
        let trimmed = base_endpoint.trim();
        if trimmed.starts_with("ssh://") {
            let ssh = parse_ssh_endpoint(trimmed)?;
            return self
                .request_ssh_inner(&ssh, req, close_after_response, cancel_rx)
                .await;
        }

        if req.uri().scheme().is_none() {
            let pq = req
                .uri()
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("/");
            let full = format!("{}{}", trimmed.trim_end_matches('/'), pq);
            let parsed_uri: http::Uri = full
                .parse()
                .map_err(|e| NodeError::Http(format!("invalid endpoint URI '{full}': {e}")))?;
            *req.uri_mut() = parsed_uri;
        }
        self.inner
            .request(req)
            .await
            .map_err(|e| NodeError::Http(format!("HTTP request failed: {e}")))
    }

    async fn request_ssh_inner(
        &self,
        ssh: &SshEndpoint,
        mut req: Request<BoxedBody>,
        close_after_response: bool,
        cancel_rx: Option<oneshot::Receiver<()>>,
    ) -> Result<Response<Incoming>, NodeError> {
        if *self.ssh_shutdown.borrow() {
            return Err(NodeError::Http(
                "SSH transport client has been shut down".into(),
            ));
        }

        let path_and_query = req
            .uri()
            .path_and_query()
            .map(|p| p.as_str().to_string())
            .unwrap_or_else(|| "/".to_string());
        let origin_uri: http::Uri = path_and_query.parse().map_err(|e| {
            NodeError::Http(format!("invalid HTTP/1.1 request target '{path_and_query}': {e}"))
        })?;
        *req.uri_mut() = origin_uri;

        if !req.headers().contains_key(HOST) {
            let host_val = HeaderValue::from_str(&ssh.http_host_header())
                .map_err(|e| NodeError::Http(format!("invalid SSH Host header: {e}")))?;
            req.headers_mut().insert(HOST, host_val);
        }
        if close_after_response {
            req.headers_mut()
                .insert(CONNECTION, HeaderValue::from_static("close"));
        }

        let ssh_bin = resolve_ssh_binary();
        let args = ssh.build_ssh_args();
        let mut cmd = Command::new(&ssh_bin);
        cmd.args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        let mut child = cmd.spawn().map_err(|e| {
            NodeError::Http(format!(
                "failed to spawn SSH transport '{ssh_bin}' for '{}': {e}",
                ssh.target()
            ))
        })?;

        let stdin = child.stdin.take().ok_or_else(|| {
            NodeError::Http("SSH child process missing stdin pipe".into())
        })?;
        let stdout = child.stdout.take().ok_or_else(|| {
            NodeError::Http("SSH child process missing stdout pipe".into())
        })?;
        let stderr_pipe = child.stderr.take();

        let stderr_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        if let Some(mut err_pipe) = stderr_pipe {
            let buf_clone = Arc::clone(&stderr_buf);
            tokio::spawn(async move {
                let mut tmp = [0u8; 512];
                loop {
                    match err_pipe.read(&mut tmp).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let mut guard =
                                buf_clone.lock().expect("ssh stderr buffer lock poisoned");
                            let remaining = MAX_SSH_STDERR_BYTES.saturating_sub(guard.len());
                            if remaining > 0 {
                                guard.extend_from_slice(&tmp[..n.min(remaining)]);
                            }
                        }
                    }
                }
            });
        }

        let child_slot: Arc<Mutex<Option<Child>>> = Arc::new(Mutex::new(Some(child)));
        let stdio_stream = ChildStdioStream {
            stdin,
            stdout,
            _child: Arc::clone(&child_slot),
        };

        let (mut sender, conn) =
            match hyper::client::conn::http1::handshake(TokioIo::new(stdio_stream)).await {
                Ok(pair) => pair,
                Err(e) => {
                    let child_opt = child_slot
                        .lock()
                        .expect("ssh child slot lock poisoned")
                        .take();
                    if let Some(mut c) = child_opt {
                        let _ = c.kill().await;
                    }
                    tokio::task::yield_now().await;
                    let stderr_note = format_ssh_stderr(&stderr_buf);
                    return Err(NodeError::Http(format!(
                        "SSH HTTP/1.1 handshake failed for '{}': {e}{stderr_note}",
                        ssh.target()
                    )));
                }
            };

        let mut client_shutdown_rx = self.ssh_shutdown.subscribe();
        let child_for_reap = Arc::clone(&child_slot);
        tokio::spawn(async move {
            {
                let shutdown_fut = async {
                    if *client_shutdown_rx.borrow() {
                        return;
                    }
                    let _ = client_shutdown_rx.changed().await;
                };
                match cancel_rx {
                    Some(cancel) => {
                        tokio::select! {
                            _ = conn => {}
                            _ = shutdown_fut => {}
                            _ = cancel => {}
                        }
                    }
                    None => {
                        tokio::select! {
                            _ = conn => {}
                            _ = shutdown_fut => {}
                        }
                    }
                }
            }
            // `conn` (and its `ChildStdioStream` stdin/stdout pipes) has now been dropped.
            // Kill and reap the child process deterministically so zero zombie PIDs remain.
            let child_opt = child_for_reap
                .lock()
                .expect("ssh child slot lock poisoned")
                .take();
            if let Some(mut c) = child_opt {
                let _ = c.kill().await;
            }
        });

        let resp_res = sender.send_request(req).await;
        drop(sender);
        match resp_res {
            Ok(resp) => Ok(resp),
            Err(e) => {
                tokio::task::yield_now().await;
                let stderr_note = format_ssh_stderr(&stderr_buf);
                Err(NodeError::Http(format!(
                    "SSH HTTP/1.1 request failed for '{}': {e}{stderr_note}",
                    ssh.target()
                )))
            }
        }
    }

    /// Collects a response's status, headers, and bounded body bytes.
    pub async fn collect(
        resp: Response<Incoming>,
        max_bytes: usize,
    ) -> Result<(StatusCode, HeaderMap, Bytes), NodeError> {
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = read_body_bytes(resp.into_body(), max_bytes).await?;
        Ok((status, headers, body))
    }

    /// Decodes a non-2xx peer response into `NodeError::RemoteProblem` (parsing RFC 9457
    /// `application/problem+json` whenever present).
    pub fn decode_error_response(status: StatusCode, body: &[u8]) -> NodeError {
        if let Ok(problem) = serde_json::from_slice::<ProblemDetails>(body) {
            return NodeError::RemoteProblem(Box::new(problem));
        }
        let text = String::from_utf8_lossy(body);
        let snippet: String = text.chars().take(256).collect();
        NodeError::RemoteProblem(Box::new(ProblemDetails::new(
            format!("http_{}", status.as_u16()),
            "remote-error",
            status.canonical_reason().unwrap_or("Remote Error"),
            status.as_u16(),
            if snippet.is_empty() {
                format!("Remote peer returned HTTP {}", status.as_u16())
            } else {
                snippet
            },
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sse_encode_and_incremental_parse_roundtrip() {
        let ev1 = SseEvent::new("message", "{\"hello\":\"world\"}").with_id("msg:1");
        let ev2 = SseEvent::new("batch", "line1\nline2").with_id("batch:2");
        let mut wire = String::new();
        wire.push_str(": keepalive\n\n");
        wire.push_str(&ev1.encode());
        wire.push_str(&ev2.encode());

        // Feed byte-by-byte to verify arbitrary chunk boundary resilience.
        let mut parser = SseParser::new();
        let mut parsed = Vec::new();
        for b in wire.as_bytes() {
            parsed.extend(parser.feed(&[*b]));
        }
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], ev1);
        assert_eq!(parsed[1], ev2);
        assert_eq!(parser.last_event_id(), Some("batch:2"));
    }

    #[test]
    fn etag_and_if_match_helpers() {
        let tag = compute_etag(b"manifest-payload");
        let mut headers = HeaderMap::new();
        headers.insert(IF_NONE_MATCH, HeaderValue::from_str(&tag).unwrap());
        assert!(etag_matches_if_none_match(&headers, &tag));
        assert!(!etag_matches_if_none_match(&headers, "\"other\""));

        let mut kv_headers = HeaderMap::new();
        kv_headers.insert(IF_MATCH, HeaderValue::from_str(&format_version_etag(7)).unwrap());
        assert_eq!(parse_if_match_version(&kv_headers).unwrap(), Some(7));

        kv_headers.insert(IF_MATCH, HeaderValue::from_static("W/\"12\""));
        assert_eq!(parse_if_match_version(&kv_headers).unwrap(), Some(12));

        kv_headers.insert(IF_MATCH, HeaderValue::from_static("not-a-number"));
        assert!(parse_if_match_version(&kv_headers).is_err());
    }
}
