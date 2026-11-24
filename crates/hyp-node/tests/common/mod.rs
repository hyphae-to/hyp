//! Shared integration test harness for `hyp-node` E2E & security test suites.
//!
//! 100% cross-platform (`127.0.0.1:0` loopback only, `SecretBackend::File`, zero live Keychain
//! or external network mutations). Annotated with `#![allow(dead_code)]` so every test binary
//! using a subset of helpers compiles cleanly with `-D warnings` on Unix and Windows.

#![allow(dead_code)]

use std::convert::Infallible;
use std::fs;
use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_TYPE, HeaderName};
use http::{HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinHandle;
use tokio::time::timeout;

use hyp_crypto::Ed25519KeyPair;
use hyp_node::adapters::{
    AdapterError, AdapterHealth, BoxFuture, NodeAdapterHost, PublishErrorCode, PublishOutcome,
    PublishStatus,
};
use hyp_node::engine::UnifiedNode;
use hyp_node::engine::http_util::{BoxedBody, empty_body, full_body};
use hyp_proto::cloudevent::CloudEvent;
use hyp_proto::rpc::EventKeyRef;
use hyp_store::{MailboxEntry, now_ms};

/// Ephemeral loopback bind address (`127.0.0.1:0`).
pub fn loopback_zero() -> SocketAddr {
    "127.0.0.1:0".parse().expect("valid loopback socket addr")
}

// ============================================================================
// MockHttpServer (ephemeral `127.0.0.1:0` hyper server with pluggable async handler)
// ============================================================================

/// Incoming HTTP request snapshot passed to a [`MockHttpServer`] async handler.
#[derive(Debug, Clone)]
pub struct MockRequest {
    pub method: Method,
    pub path: String,
    pub query: Option<String>,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl MockRequest {
    pub fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn header_str(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

/// Outgoing HTTP response returned from a [`MockHttpServer`] async handler.
#[derive(Debug, Clone)]
pub struct MockResponse {
    pub status: StatusCode,
    pub headers: Vec<(String, String)>,
    pub body: Bytes,
}

impl MockResponse {
    pub fn json<T: Serialize>(status: StatusCode, value: &T) -> Self {
        let body = serde_json::to_vec(value).expect("serialize mock json response");
        Self {
            status,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: Bytes::from(body),
        }
    }

    pub fn text(status: StatusCode, text: impl Into<String>) -> Self {
        Self {
            status,
            headers: vec![(
                "content-type".to_string(),
                "text/plain; charset=utf-8".to_string(),
            )],
            body: Bytes::from(text.into()),
        }
    }

    pub fn empty(status: StatusCode) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: Bytes::new(),
        }
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// Ephemeral `127.0.0.1:0` HTTP/1.1 mock server with pluggable async handler and `Drop` abort guard.
pub struct MockHttpServer {
    addr: SocketAddr,
    calls: Arc<AtomicUsize>,
    handle: JoinHandle<()>,
}

impl MockHttpServer {
    pub async fn start<F, Fut>(handler: F) -> Self
    where
        F: Fn(MockRequest) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = MockResponse> + Send + 'static,
    {
        let listener = TcpListener::bind(loopback_zero())
            .await
            .expect("bind loopback mock server");
        let addr = listener.local_addr().expect("mock server local addr");
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_srv = Arc::clone(&calls);
        let handler = Arc::new(handler);

        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let calls = Arc::clone(&calls_srv);
                let handler = Arc::clone(&handler);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let calls = Arc::clone(&calls);
                        let handler = Arc::clone(&handler);
                        async move {
                            calls.fetch_add(1, Ordering::SeqCst);
                            let method = req.method().clone();
                            let uri = req.uri().clone();
                            let path = uri.path().to_string();
                            let query = uri.query().map(ToOwned::to_owned);
                            let headers = req.headers().clone();
                            let body = req
                                .into_body()
                                .collect()
                                .await
                                .map(|b| b.to_bytes())
                                .unwrap_or_default();

                            let mock_resp = handler(MockRequest {
                                method,
                                path,
                                query,
                                headers,
                                body,
                            })
                            .await;

                            let mut builder = Response::builder().status(mock_resp.status);
                            for (k, v) in mock_resp.headers {
                                if let (Ok(name), Ok(val)) = (
                                    HeaderName::from_bytes(k.as_bytes()),
                                    HeaderValue::from_str(&v),
                                ) {
                                    builder = builder.header(name, val);
                                }
                            }
                            let resp = builder
                                .body(Full::new(mock_resp.body))
                                .expect("valid mock HTTP response");
                            Ok::<_, Infallible>(resp)
                        }
                    });
                    let _ = http1::Builder::new().serve_connection(io, svc).await;
                });
            }
        });

        Self {
            addr,
            calls,
            handle,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn url(&self, path: &str) -> String {
        if path.starts_with('/') {
            format!("http://{}{}", self.addr, path)
        } else {
            format!("http://{}/{}", self.addr, path)
        }
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Drop for MockHttpServer {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

// ============================================================================
// Ed25519AuthBuilder (signed Hyphae v2 Authorization + X-Hyphae-Timestamp + X-Hyphae-Nonce)
// ============================================================================

/// Builds signed Hyphae v2 `Authorization: Hyphae-Ed25519 ...`, `X-Hyphae-Timestamp`,
/// `X-Hyphae-Nonce`, and `X-Hyphae-Node` headers with explicit timestamp/nonce overrides
/// for boundary clock-skew and replay testing.
pub struct Ed25519AuthBuilder<'a> {
    node_id: String,
    signing_key: &'a Ed25519KeyPair,
    timestamp_ms: Option<i64>,
    nonce: Option<String>,
    seq: AtomicU64,
}

impl<'a> Ed25519AuthBuilder<'a> {
    pub fn new(node_id: impl Into<String>, signing_key: &'a Ed25519KeyPair) -> Self {
        Self {
            node_id: node_id.into(),
            signing_key,
            timestamp_ms: None,
            nonce: None,
            seq: AtomicU64::new(1),
        }
    }

    /// Overrides the signed request timestamp (Unix milliseconds).
    pub fn with_timestamp_ms(mut self, ts_ms: i64) -> Self {
        self.timestamp_ms = Some(ts_ms);
        self
    }

    /// Overrides the signed request nonce (fixes the nonce across calls for replay tests).
    pub fn with_nonce(mut self, nonce: impl Into<String>) -> Self {
        self.nonce = Some(nonce.into());
        self
    }

    fn resolve_ts_and_nonce(&self) -> (i64, String) {
        let ts = self.timestamp_ms.unwrap_or_else(now_ms);
        let nonce = match &self.nonce {
            Some(explicit) => explicit.clone(),
            None => {
                let n = self.seq.fetch_add(1, Ordering::Relaxed);
                format!("hyphae-test-nonce-{ts}-{n}")
            }
        };
        (ts, nonce)
    }

    /// Computes the signed `Authorization`, `X-Hyphae-Timestamp`, `X-Hyphae-Nonce`, and
    /// `X-Hyphae-Node` headers for `(method, path_and_query, body)`.
    pub fn build_headers(&self, method: &str, path_and_query: &str, body: &[u8]) -> HeaderMap {
        let (ts, nonce) = self.resolve_ts_and_nonce();
        let body_sha = hex::encode(Sha256::digest(body));
        let signing_input = format!("{method}\n{path_and_query}\n{ts}\n{nonce}\n{body_sha}");
        let sig = self
            .signing_key
            .sign_domain_b64("http-auth", signing_input.as_bytes());
        let auth_val = format!(
            "Hyphae-Ed25519 node=\"{}\",ts=\"{}\",nonce=\"{}\",sig=\"{}\"",
            self.node_id, ts, nonce, sig
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&auth_val).expect("valid Authorization header"),
        );
        headers.insert(
            HeaderName::from_static("x-hyphae-node"),
            HeaderValue::from_str(&self.node_id).expect("valid X-Hyphae-Node header"),
        );
        headers.insert(
            HeaderName::from_static("x-hyphae-timestamp"),
            HeaderValue::from_str(&ts.to_string()).expect("valid X-Hyphae-Timestamp header"),
        );
        headers.insert(
            HeaderName::from_static("x-hyphae-nonce"),
            HeaderValue::from_str(&nonce).expect("valid X-Hyphae-Nonce header"),
        );
        headers
    }

    /// Convenience helper returning just the `Authorization` header string.
    pub fn authorization_header(&self, method: &str, path_and_query: &str, body: &[u8]) -> String {
        self.build_headers(method, path_and_query, body)
            .get(AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .expect("Authorization header present")
            .to_string()
    }

    /// Builds a complete signed `http::Request<BoxedBody>` ready for `HttpClient::request`.
    pub fn sign_request(
        &self,
        method: Method,
        base_url: &str,
        path_and_query: &str,
        body: Option<Bytes>,
        content_type: Option<&str>,
    ) -> Request<BoxedBody> {
        let raw_slice = body.as_deref().unwrap_or(&[]);
        let auth_headers = self.build_headers(method.as_str(), path_and_query, raw_slice);
        let url = format!("{}{}", base_url.trim_end_matches('/'), path_and_query);
        let mut builder = Request::builder().method(method).uri(url);
        if let Some(ct) = content_type {
            builder = builder.header(CONTENT_TYPE, ct);
        }
        for (name, value) in &auth_headers {
            builder = builder.header(name, value);
        }
        let boxed = match body {
            Some(b) => full_body(b),
            None => empty_body(),
        };
        builder.body(boxed).expect("valid signed HTTP request")
    }
}

// ============================================================================
// SQLite Zero-Plaintext Leak Assertion
// ============================================================================

/// Scans physical `node.sqlite`, `node.sqlite-wal`, and `node.sqlite-shm` files on disk
/// to verify zero leaked plaintext substrings across every needle.
pub fn assert_zero_plaintext_in_sqlite(state_dir: &Path, needles: &[&str]) {
    for filename in ["node.sqlite", "node.sqlite-wal", "node.sqlite-shm"] {
        let p = state_dir.join(filename);
        if !p.exists() {
            continue;
        }
        let bytes = fs::read(&p).expect("read sqlite file");
        for &needle in needles {
            assert!(!needle.is_empty(), "plaintext audit needle must be non-empty");
            let needle_bytes = needle.as_bytes();
            assert!(
                !bytes.windows(needle_bytes.len()).any(|w| w == needle_bytes),
                "SECURITY VIOLATION: found plaintext substring {:?} in {}!",
                needle,
                p.display()
            );
        }
    }
}

// ============================================================================
// DeterministicRng (xorshift64* seeded from HYPHAE_TEST_SEED)
// ============================================================================

const DEFAULT_RNG_SEED: u64 = 0x9E37_79B9_7F4A_7C15;

/// Seeded `xorshift64*` PRNG for reproducible fuzz/differential testing.
#[derive(Debug, Clone)]
pub struct DeterministicRng {
    seed: u64,
    state: u64,
}

impl DeterministicRng {
    /// Reads `HYPHAE_TEST_SEED` (decimal or `0x`-hex), falling back to a deterministic constant.
    pub fn from_env() -> Self {
        let seed = std::env::var("HYPHAE_TEST_SEED")
            .ok()
            .and_then(|raw| {
                let s = raw.trim();
                if let Some(hex_str) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                    u64::from_str_radix(hex_str, 16).ok()
                } else {
                    s.parse::<u64>().ok()
                }
            })
            .unwrap_or(DEFAULT_RNG_SEED);
        Self::from_seed(seed)
    }

    pub fn from_seed(seed: u64) -> Self {
        let non_zero = if seed == 0 { DEFAULT_RNG_SEED } else { seed };
        Self {
            seed: non_zero,
            state: non_zero,
        }
    }

    /// Original seed for diagnostic panic messages (`HYPHAE_TEST_SEED=<seed>`).
    pub fn seed(&self) -> u64 {
        self.seed
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn next_usize(&mut self, bound: usize) -> usize {
        assert!(bound > 0, "bound must be > 0");
        (self.next_u64() as usize) % bound
    }

    pub fn fill_bytes(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let word = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&word[..chunk.len()]);
        }
    }
}

// ============================================================================
// Bounded Async Local Mailbox Waiter
// ============================================================================

/// Zero-polling bounded async helper waiting for a local mailbox item matching `predicate`
/// (and acknowledging it once matched).
pub async fn wait_for_mailbox_item<F>(
    node: &Arc<UnifiedNode>,
    session_id: &str,
    timeout_dur: Duration,
    predicate: F,
) -> MailboxEntry
where
    F: Fn(&MailboxEntry) -> bool,
{
    let mut rx = node.subscribe_local_inbox();
    let deadline = tokio::time::Instant::now() + timeout_dur;

    loop {
        let items = node.peek_local_inbox(session_id, 200).expect("peek inbox");
        if let Some(found) = items.into_iter().find(|e| predicate(e)) {
            let _ = node
                .db()
                .local()
                .acknowledge_inbox(session_id, &[found.receipt.as_str()], now_ms());
            return found;
        }
        let now = tokio::time::Instant::now();
        assert!(
            now < deadline,
            "timed out waiting for mailbox item on node '{}' session '{}'; pending={:?}",
            node.node_id(),
            session_id,
            node.peek_local_inbox(session_id, 50)
                .unwrap_or_default()
                .iter()
                .map(|m| (&m.kind, &m.text))
                .collect::<Vec<_>>()
        );
        let remaining = (deadline - now).min(Duration::from_millis(100));
        let _ = timeout(remaining, rx.recv()).await;
    }
}

// ============================================================================
// UnifiedNodeAdapterHost Bridge (wires any NodeAdapter into a live UnifiedNode)
// ============================================================================

/// Bridges a [`hyp_node::adapters::NodeAdapter`] into a live [`UnifiedNode`], capturing every
/// ingested `(topic, CloudEvent)` for exact differential assertions.
pub struct UnifiedNodeAdapterHost {
    node: Arc<UnifiedNode>,
    published: AsyncMutex<Vec<(String, CloudEvent)>>,
    health_updates: AsyncMutex<Vec<(String, AdapterHealth)>>,
}

impl UnifiedNodeAdapterHost {
    pub fn new(node: Arc<UnifiedNode>) -> Arc<Self> {
        Arc::new(Self {
            node,
            published: AsyncMutex::new(Vec::new()),
            health_updates: AsyncMutex::new(Vec::new()),
        })
    }

    pub async fn published_events(&self) -> Vec<(String, CloudEvent)> {
        self.published.lock().await.clone()
    }

    pub async fn health_updates(&self) -> Vec<(String, AdapterHealth)> {
        self.health_updates.lock().await.clone()
    }

    pub async fn wait_for_event_count(
        &self,
        expected: usize,
        timeout_dur: Duration,
    ) -> Vec<(String, CloudEvent)> {
        let deadline = tokio::time::Instant::now() + timeout_dur;
        loop {
            let cur = self.published.lock().await.clone();
            if cur.len() >= expected {
                return cur;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for {expected} published events; got {}",
                cur.len()
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    }
}

impl NodeAdapterHost for UnifiedNodeAdapterHost {
    fn publish_event<'a>(
        &'a self,
        topic: &'a str,
        event: CloudEvent,
    ) -> BoxFuture<'a, Result<PublishOutcome, AdapterError>> {
        Box::pin(async move {
            let caller = self.node.node_id().as_str().to_string();
            let res = self
                .node
                .ingest_inbound_event(&caller, topic, &event)
                .map_err(|e| AdapterError::PublishFailed {
                    code: PublishErrorCode::InvalidEvent,
                    message: e.to_string(),
                })?;
            let status = if res.deduplicated {
                PublishStatus::Duplicate
            } else {
                self.published
                    .lock()
                    .await
                    .push((topic.to_string(), event));
                PublishStatus::Stored
            };
            Ok(PublishOutcome {
                status,
                matched: res.matched,
            })
        })
    }

    fn update_status<'a>(
        &'a self,
        adapter_id: &'a str,
        health: AdapterHealth,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.health_updates
                .lock()
                .await
                .push((adapter_id.to_string(), health));
        })
    }

    fn report_delivery_failed<'a>(
        &'a self,
        _adapter_id: &'a str,
        _target: &'a str,
        _events: Vec<EventKeyRef>,
        _reason: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}
