//! `hyper 1` + `hyper-util` HTTP/1.1+2 & WHATWG SSE Peer Server (`UnifiedNode::serve`).
//!
//! Endpoints:
//! - `GET /v1/manifest` (RFC 9110 `ETag`/`If-None-Match`, public vs authenticated caller-scoped)
//! - `GET /.well-known/agent.json` (opt-in A2A Agent Card projection; `404` when disabled)
//! - `POST /v1/pair` (Org Admin-CA `am2_` single-use pairing claim)
//! - `POST /v1/p2p/pair/<offerId>` (Direct P2P `hp2p1_` mutual pairing handshake)
//! - `PUT/GET /v1/keys`
//! - `PUT/GET /v1/handles`
//! - `POST /v1/messages`
//! - `POST /v1/channels/join`, `DELETE /v1/channels/members`, `POST /v1/channels/post`, `GET /v1/channels`
//! - `POST/GET /v1/channel-epochs`
//! - `POST/GET /v1/kv-epochs`
//! - `POST /v1/events`
//! - `PUT/DELETE/GET /v1/subscriptions`
//! - `GET /v1/inbox` (WHATWG SSE push!), `POST /v1/inbox/ack`
//! - `PUT/GET /v1/transfers/<id>`
//! - `PUT/GET/DELETE /v1/kv/<namespace>/<key...>`, `GET /v1/kv/<namespace>`

use std::convert::Infallible;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use http::header::{
    ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS, ACCESS_CONTROL_MAX_AGE,
    AUTHORIZATION, CONNECTION, CONTENT_LENGTH, HeaderValue, ORIGIN,
};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use hyp_crypto::SignedPayload;
use hyp_crypto::pairing::P2pPairResponse;
use hyp_proto::address::Channel;
use hyp_proto::problem::ProblemDetails;
use hyp_store::{KvDeleteInput, KvSetInput, StoreError, now_ms};

use crate::adapters::{AdapterError, GitHubWebhookAdapter, WebhookIngestOutcome};
use crate::engine::config::{NodeError, ip_matches_trusted_proxies, normalize_ip_addr};
use crate::engine::drop_relay::{
    CreateDropRequest, DROP_CAP_HEADER, DROP_SSE_KEEPALIVE_SECONDS, DropCapRole, DropRelay,
    DropRelayError, DropSubscriberAuth, DropSubscription,
};
use crate::engine::http_util::{
    BoxedBody, SseEvent, bytes_response, empty_body, etag_matches_if_none_match,
    format_version_etag, json_response, json_response_with_etag, not_modified_response,
    parse_if_match_version, parse_query, percent_decode, problem_response, read_body_bytes,
    sse_keepalive_frame, sse_response, with_retry_after,
};
use crate::engine::node::{AuthenticatedPeer, UnifiedNode};
use crate::engine::peer_link::{
    AuthClaimRequest, ChannelEpochResponse, ChannelJoinRequest, ChannelJoinResponse,
    ChannelLeaveRequest, ChannelPostRequest, ChannelsResponse, DelegatedPairRequest,
    GuestPairRequest, HandlesResponse, InboxAckRequest, InboxAckResponse, KvDeleteBody,
    KvEpochResponse, KvListResponse, KvSetBody, PairRequestV2, PeerKeysResponse,
    PostMessageRequest, PostMessageResponse, PublishEventRequest, PutChannelEpochRequest,
    PutHandlesRequest, PutKeyRequest, PutKvEpochRequest, PutSubscriptionsRequest,
    PutSubscriptionsResponse, SubscriptionsResponse, TransferUploadResponse,
};

const MAX_JSON_BODY_BYTES: usize = 2 * 1024 * 1024;
const MAX_UNAUTH_CONTROL_BODY_BYTES: usize = 64 * 1024;
const MAX_DROP_CONTROL_BODY_BYTES: usize = 16 * 1024;
const SSE_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(25);
const MAX_CONCURRENT_LINGERING_CLOSES: usize = 64;
const LINGERING_CLOSE_TIMEOUT: Duration = Duration::from_millis(200);
const LINGERING_CLOSE_MAX_DISCARD_BYTES: usize = 512 * 1024;

/// Default Unix domain socket filename for local `hyp connect` / `ssh://` peer transport.
pub const DEFAULT_PEER_SOCKET_FILENAME: &str = "peer.sock";

static ACTIVE_LINGERING_CLOSES: AtomicUsize = AtomicUsize::new(0);

/// RFC 9112 §9.6 lingering-close `TcpStream` wrapper.
///
/// When an HTTP/1.1 handler rejects an oversized request early (e.g. `413 Payload Too Large`
/// from `Content-Length` before buffering any request body bytes), closing a `TcpStream` while
/// unread request bytes sit in the kernel receive buffer triggers a TCP `RST` on BSD/macOS/Linux,
/// wiping out the `413` response before the client can read it. Performing a bounded `SHUT_WR`
/// half-close + zero-allocation stack drain avoids the TCP reset problem without DoS risk.
struct LingeringTcpStream {
    stream: Option<TcpStream>,
    peer_eof: bool,
    wrote_bytes: bool,
}

impl LingeringTcpStream {
    fn new(stream: TcpStream) -> Self {
        Self {
            stream: Some(stream),
            peer_eof: false,
            wrote_bytes: false,
        }
    }
}

impl AsyncRead for LingeringTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let Some(ref mut stream) = self.stream else {
            return Poll::Ready(Ok(()));
        };
        let before = buf.filled().len();
        let res = Pin::new(stream).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            if buf.filled().len() == before {
                self.peer_eof = true;
            }
        }
        res
    }
}

impl AsyncWrite for LingeringTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let Some(ref mut stream) = self.stream else {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "connection closed",
            )));
        };
        let res = Pin::new(stream).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res {
            if *n > 0 {
                self.wrote_bytes = true;
            }
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(ref mut stream) = self.stream else {
            return Poll::Ready(Ok(()));
        };
        Pin::new(stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(ref mut stream) = self.stream else {
            return Poll::Ready(Ok(()));
        };
        Pin::new(stream).poll_shutdown(cx)
    }
}

impl Drop for LingeringTcpStream {
    fn drop(&mut self) {
        if !self.wrote_bytes || self.peer_eof {
            return;
        }
        let Some(mut stream) = self.stream.take() else {
            return;
        };
        let prev = ACTIVE_LINGERING_CLOSES.fetch_add(1, Ordering::AcqRel);
        if prev >= MAX_CONCURRENT_LINGERING_CLOSES {
            ACTIVE_LINGERING_CLOSES.fetch_sub(1, Ordering::AcqRel);
            return;
        }
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            ACTIVE_LINGERING_CLOSES.fetch_sub(1, Ordering::AcqRel);
            return;
        };
        handle.spawn(async move {
            let _ = stream.shutdown().await;
            let _ = tokio::time::timeout(LINGERING_CLOSE_TIMEOUT, async {
                let mut discard = [0u8; 4096];
                let mut total = 0usize;
                while total < LINGERING_CLOSE_MAX_DISCARD_BYTES {
                    match stream.read(&mut discard).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => total = total.saturating_add(n),
                    }
                }
            })
            .await;
            ACTIVE_LINGERING_CLOSES.fetch_sub(1, Ordering::AcqRel);
        });
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AckDropBody {
    seq: u64,
    #[serde(default = "default_true")]
    burn: bool,
}

/// Wire envelope for `POST /v1/pair` supporting both Hub-local grants and inline
/// offline Admin-CA-signed `GrantV2` (`signedGrant` / `signedGrantV2`).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdminPairRequestEnvelope {
    #[serde(flatten)]
    base: PairRequestV2,
    #[serde(default, alias = "signedGrantV2")]
    signed_grant: Option<SignedPayload>,
}

/// Wire envelope for `PUT /v1/keys` supporting both single-proof rotation (signed by the
/// currently pinned key or Admin-CA) and dual-proof rotation (`rotationProof` + `proof`).
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PutKeyRequestEnvelope {
    #[serde(flatten)]
    base: PutKeyRequest,
    #[serde(default, alias = "authorityProof")]
    rotation_proof: Option<SignedPayload>,
}

fn default_true() -> bool {
    true
}

impl UnifiedNode {
    /// Binds and serves this `UnifiedNode`'s HTTP/1.1+2 + WHATWG SSE peer server on `addr`
    /// (typically `127.0.0.1:0` in tests or loopback behind Tailscale/Caddy in production).
    pub async fn serve(
        self: Arc<Self>,
        addr: SocketAddr,
    ) -> Result<(SocketAddr, JoinHandle<()>), NodeError> {
        let listener = TcpListener::bind(addr).await?;
        let local_addr = listener.local_addr()?;
        self.set_bound_addr(local_addr);

        let mut shutdown_rx = self.shutdown_receiver();
        let node = Arc::clone(&self);
        let handle = tokio::spawn(async move {
            loop {
                let accept = tokio::select! {
                    res = listener.accept() => res,
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                        continue;
                    }
                };
                let (stream, peer_addr) = match accept {
                    Ok(pair) => pair,
                    Err(_) => continue,
                };
                let conn_node = Arc::clone(&node);
                let mut conn_shutdown = node.shutdown_receiver();
                tokio::spawn(async move {
                    if *conn_shutdown.borrow() {
                        return;
                    }
                    let io = TokioIo::new(LingeringTcpStream::new(stream));
                    let service = service_fn(move |req: Request<Incoming>| {
                        let n = Arc::clone(&conn_node);
                        async move { Ok::<_, Infallible>(handle_http_request(n, peer_addr, req).await) }
                    });
                    let builder = AutoServerBuilder::new(TokioExecutor::new());
                    let conn = builder.serve_connection(io, service);
                    tokio::pin!(conn);
                    tokio::select! {
                        _ = conn.as_mut() => {}
                        _ = conn_shutdown.changed() => {
                            if *conn_shutdown.borrow() {
                                conn.as_mut().graceful_shutdown();
                            }
                        }
                    }
                });
            }
        });

        Ok((local_addr, handle))
    }

    /// Binds and serves this `UnifiedNode`'s full Hyphae v2 HTTP/1.1+2 + WHATWG SSE peer router
    /// over a user-only (`0600`) Unix domain socket (typically `<state_dir>/peer.sock`), enabling
    /// zero-open-port `hyp connect` / `ssh://` peer transport.
    #[cfg(unix)]
    pub async fn serve_unix(
        self: Arc<Self>,
        path: std::path::PathBuf,
    ) -> Result<(std::path::PathBuf, JoinHandle<()>), NodeError> {
        use std::os::unix::fs::{FileTypeExt, PermissionsExt};

        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
                let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
            }
        }

        if let Ok(meta) = std::fs::symlink_metadata(&path) {
            if !meta.file_type().is_socket() {
                return Err(NodeError::Io(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    format!(
                        "refusing to bind peer.sock over non-socket path {}",
                        path.display()
                    ),
                )));
            }
            let alive = matches!(
                tokio::time::timeout(
                    Duration::from_millis(200),
                    tokio::net::UnixStream::connect(&path),
                )
                .await,
                Ok(Ok(_))
            );
            if alive {
                return Err(NodeError::Io(io::Error::new(
                    io::ErrorKind::AddrInUse,
                    format!(
                        "another live Hyphae peer server is already listening on {}",
                        path.display()
                    ),
                )));
            }
            std::fs::remove_file(&path)?;
        }

        let listener = tokio::net::UnixListener::bind(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        self.set_peer_socket_path(path.clone());

        let mut shutdown_rx = self.shutdown_receiver();
        let node = Arc::clone(&self);
        let cleanup_path = path.clone();
        let loopback_peer = SocketAddr::from(([127, 0, 0, 1], 0));
        let handle = tokio::spawn(async move {
            loop {
                let accept = tokio::select! {
                    res = listener.accept() => res,
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() {
                            break;
                        }
                        continue;
                    }
                };
                let (stream, _unix_addr) = match accept {
                    Ok(pair) => pair,
                    Err(_) => continue,
                };
                let conn_node = Arc::clone(&node);
                let mut conn_shutdown = node.shutdown_receiver();
                tokio::spawn(async move {
                    if *conn_shutdown.borrow() {
                        return;
                    }
                    let io = TokioIo::new(stream);
                    let service = service_fn(move |req: Request<Incoming>| {
                        let n = Arc::clone(&conn_node);
                        async move {
                            Ok::<_, Infallible>(handle_http_request(n, loopback_peer, req).await)
                        }
                    });
                    let builder = AutoServerBuilder::new(TokioExecutor::new());
                    let conn = builder.serve_connection(io, service);
                    tokio::pin!(conn);
                    tokio::select! {
                        _ = conn.as_mut() => {}
                        _ = conn_shutdown.changed() => {
                            if *conn_shutdown.borrow() {
                                conn.as_mut().graceful_shutdown();
                            }
                        }
                    }
                });
            }
            let _ = std::fs::remove_file(&cleanup_path);
        });

        Ok((path, handle))
    }
}

async fn handle_http_request(
    node: Arc<UnifiedNode>,
    peer_addr: SocketAddr,
    req: Request<Incoming>,
) -> Response<BoxedBody> {
    match route_request(node, peer_addr, req).await {
        Ok(resp) => resp,
        Err(err) => {
            let retry_after = match &err {
                NodeError::RateLimited {
                    retry_after_secs, ..
                } => *retry_after_secs,
                NodeError::Store(StoreError::RateLimited(_)) => Some(60),
                NodeError::DropRelay(e) => e.retry_after_secs(),
                _ => None,
            };
            let mut resp = problem_response(&err.to_problem_details());
            if resp.status() == StatusCode::PAYLOAD_TOO_LARGE {
                resp.headers_mut()
                    .insert(CONNECTION, HeaderValue::from_static("close"));
            }
            match retry_after {
                Some(secs) => with_retry_after(resp, secs),
                None => resp,
            }
        }
    }
}

#[derive(Clone, Copy)]
enum PublicControlRoute<'a> {
    Health,
    Manifest,
    AgentCard,
    Pair,
    GuestPair,
    AuthClaim,
    DelegatedPair,
    P2pPair(&'a str),
}

impl<'a> PublicControlRoute<'a> {
    fn classify(method: &Method, path: &'a str) -> Option<Self> {
        let route = match (method, path) {
            (&Method::GET, "/v1/health") => Self::Health,
            (&Method::GET, "/v1/manifest") => Self::Manifest,
            (&Method::GET, "/.well-known/agent.json") => Self::AgentCard,
            (&Method::POST, "/v1/pair") => Self::Pair,
            (&Method::POST, "/v1/guest/pair") => Self::GuestPair,
            (&Method::POST, "/v1/auth/claim") => Self::AuthClaim,
            (&Method::POST, "/v1/pair/delegated") => Self::DelegatedPair,
            (&Method::POST, _) => Self::P2pPair(path.strip_prefix("/v1/p2p/pair/")?),
            _ => return None,
        };
        Some(route)
    }

    fn check_enabled(self, node: &UnifiedNode) -> Result<(), NodeError> {
        match self {
            Self::AgentCard if !node.config().expose_a2a_card => Err(NodeError::NotFound(
                "A2A agent card projection is disabled on this node".into(),
            )),
            Self::GuestPair if !node.config().guest_pairing.enabled => Err(NodeError::NotFound(
                "guest pairing is disabled on this node".into(),
            )),
            _ => Ok(()),
        }
    }
}

#[derive(Clone, Copy)]
enum PeerRoute<'a> {
    Keys,
    Handles,
    Messages,
    Channels,
    ChannelJoin,
    ChannelLeave,
    ChannelPost,
    ChannelEpochs,
    KvEpochs,
    Events,
    Subscriptions,
    InboxAck,
    Transfer(&'a str),
    KvMetadata,
    Kv(&'a str),
}

impl<'a> PeerRoute<'a> {
    fn classify(method: &Method, path: &'a str) -> Option<Self> {
        let route = match (method, path) {
            (_, "/v1/keys") => Self::Keys,
            (_, "/v1/handles") => Self::Handles,
            (&Method::POST, "/v1/messages") => Self::Messages,
            (&Method::GET, "/v1/channels") => Self::Channels,
            (&Method::POST, "/v1/channels/join") => Self::ChannelJoin,
            (&Method::DELETE, "/v1/channels/members") => Self::ChannelLeave,
            (&Method::POST, "/v1/channels/post") => Self::ChannelPost,
            (_, "/v1/channel-epochs") => Self::ChannelEpochs,
            (_, p) if p.starts_with("/v1/channel-epochs/") => Self::ChannelEpochs,
            (_, "/v1/kv-epochs") => Self::KvEpochs,
            (_, p) if p.starts_with("/v1/kv-epochs/") => Self::KvEpochs,
            (&Method::POST, "/v1/events") => Self::Events,
            (_, "/v1/subscriptions") => Self::Subscriptions,
            (&Method::POST, "/v1/inbox/ack") => Self::InboxAck,
            (&Method::GET, "/v1/kv-metadata") => Self::KvMetadata,
            _ => {
                if let Some(id) = path.strip_prefix("/v1/transfers/") {
                    Self::Transfer(id)
                } else {
                    Self::Kv(path.strip_prefix("/v1/kv/")?)
                }
            }
        };
        Some(route)
    }
}

async fn route_request(
    node: Arc<UnifiedNode>,
    peer_addr: SocketAddr,
    req: Request<Incoming>,
) -> Result<Response<BoxedBody>, NodeError> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let path = uri.path().to_string();
    let path_and_query = uri
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_else(|| path.clone());
    let query = parse_query(uri.query());
    let headers = req.headers().clone();

    if let Some(receiver) = path.strip_prefix("/v1/webhooks/") {
        let github = receiver == "github" || receiver.starts_with("github/");
        if !github {
            return Err(NodeError::NotFound(
                "Webhook receiver is not configured on this node".into(),
            ));
        }
    }

    // Streaming SSE endpoint must NOT read a request body before upgrading.
    if method == Method::GET && path == "/v1/inbox" {
        let empty_sha = hex::encode(Sha256::digest(b""));
        let caller = require_auth(&node, &headers, "GET", &path_and_query, &empty_sha)?;
        return Ok(start_inbox_sse_stream(node, caller));
    }

    // RAM-only Blind Ephemeral Drop Relay endpoints MUST be handled BEFORE generic body reads
    // so capability tokens are verified before allocating body bytes and SSE streams do not read
    // request bodies.
    if path == "/v1/drops" || path.starts_with("/v1/drops/") {
        return handle_drop_relay_request(
            node,
            peer_addr,
            method,
            &path,
            &path_and_query,
            &query,
            &headers,
            req.into_body(),
        )
        .await;
    }

    // Pre-auth route-appropriate body size guard: check route limits & `Content-Length` BEFORE
    // buffering request body bytes (preventing pre-auth memory amplification).
    let public_control = PublicControlRoute::classify(&method, &path);
    let peer_route = PeerRoute::classify(&method, &path);
    let max_body =
        resolve_pre_read_body_limit(&node, &method, &path, &headers, public_control, peer_route)?;
    check_content_length(&headers, max_body)?;

    let body_bytes = read_body_bytes(req.into_body(), max_body).await?;
    let body_sha = hex::encode(Sha256::digest(&body_bytes));

    // ---- Unauthenticated or Optionally Authenticated Endpoints ----

    if let Some(route) = public_control {
        route.check_enabled(&node)?;
        return match route {
            PublicControlRoute::Health => {
                let gh_summary = match node.github_public_adapter() {
                    Some(adapter) => {
                        let stats = adapter.stats().await;
                        json!({
                            "enabled": true,
                            "activePollers": stats.active_pollers,
                            "pollsTotal": stats.polls_total,
                            "polls200": stats.polls_200,
                            "polls304": stats.polls_304,
                        })
                    }
                    None => json!({
                        "enabled": false,
                        "activePollers": 0,
                        "pollsTotal": 0,
                        "polls200": 0,
                        "polls304": 0,
                    }),
                };
                Ok(json_response(
                    StatusCode::OK,
                    &json!({
                        "ok": true,
                        "nodeId": node.node_id().as_str(),
                        "profile": node.config().profile,
                        "guestPairingEnabled": node.config().guest_pairing.enabled,
                        "githubPublic": gh_summary,
                        "dropRelay": node.drop_relay().health(now_ms()),
                    }),
                ))
            }
            PublicControlRoute::Manifest => {
                let caller =
                    node.authenticate_request(&headers, "GET", &path_and_query, &body_sha)?;
                let (signed, _payload, etag) = node.build_signed_manifest(caller.as_ref())?;
                if etag_matches_if_none_match(&headers, &etag) {
                    return Ok(not_modified_response(&etag));
                }
                Ok(json_response_with_etag(StatusCode::OK, &signed, &etag))
            }
            PublicControlRoute::AgentCard => {
                let caller =
                    node.authenticate_request(&headers, "GET", &path_and_query, &body_sha)?;
                let (_signed, payload, _etag) = node.build_signed_manifest(caller.as_ref())?;
                let card = payload.to_a2a_agent_card(&node.endpoint_url());
                Ok(json_response(StatusCode::OK, &card))
            }
            PublicControlRoute::Pair => {
                let pair_env: AdminPairRequestEnvelope = serde_json::from_slice(&body_bytes)?;
                let reply = node.handle_admin_pair_request_with_grant(
                    &pair_env.base,
                    pair_env.signed_grant.as_ref(),
                )?;
                Ok(json_response(StatusCode::OK, &reply))
            }
            PublicControlRoute::GuestPair => {
                let guest_req: GuestPairRequest = serde_json::from_slice(&body_bytes)?;
                let reply = node.handle_guest_pair_request(&guest_req)?;
                Ok(json_response(StatusCode::OK, &reply))
            }
            PublicControlRoute::AuthClaim => {
                let claim_req: AuthClaimRequest = serde_json::from_slice(&body_bytes)?;
                let reply = node.handle_auth_claim_request(&claim_req)?;
                Ok(json_response(StatusCode::OK, &reply))
            }
            PublicControlRoute::DelegatedPair => {
                let pair_req: DelegatedPairRequest = serde_json::from_slice(&body_bytes)?;
                let reply = node.handle_delegated_pair_request(&pair_req)?;
                Ok(json_response(StatusCode::OK, &reply))
            }
            PublicControlRoute::P2pPair(offer_id) => {
                let offer_id = percent_decode(offer_id);
                let pair_resp: P2pPairResponse = serde_json::from_slice(&body_bytes)?;
                let reply = node.handle_p2p_pair_request(&offer_id, &pair_resp)?;
                Ok(json_response(StatusCode::OK, &reply))
            }
        };
    }

    if let Some(adapter) = resolve_github_webhook_target(&node, &method, &path)? {
        let outcome = adapter.ingest_webhook(&headers, &body_bytes).await;
        return webhook_outcome_response(outcome);
    }

    // ---- Strictly Authenticated Peer Endpoints ----

    let caller = require_auth(&node, &headers, method.as_str(), &path_and_query, &body_sha)?;

    match peer_route {
        Some(PeerRoute::Keys) => match method {
            Method::PUT => {
                let put_env: PutKeyRequestEnvelope = serde_json::from_slice(&body_bytes)?;
                node.register_peer_key_proof_authorized(
                    &caller,
                    &put_env.base,
                    put_env.rotation_proof.as_ref(),
                )?;
                Ok(json_response(StatusCode::OK, &json!({ "ok": true })))
            }
            Method::GET => {
                let filter_node = query.get("nodeId").map(String::as_str);
                let kv_namespace = query.get("kvNamespace").map(String::as_str);
                let keys = match kv_namespace {
                    Some(ns) if filter_node.is_none() => {
                        node.list_kv_member_keys_for_caller(&caller, ns)?
                    }
                    _ => node.list_directory_keys_for_caller(&caller, filter_node)?,
                };
                Ok(json_response(StatusCode::OK, &PeerKeysResponse { keys }))
            }
            _ => Err(NodeError::BadRequest("method not allowed".into())),
        },
        Some(PeerRoute::Handles) => match method {
            Method::PUT => {
                let put_req: PutHandlesRequest = serde_json::from_slice(&body_bytes)?;
                let pairs: Vec<(&str, Option<&str>)> = put_req
                    .handles
                    .iter()
                    .map(|h| (h.as_str(), put_req.descriptions.get(h).map(String::as_str)))
                    .collect();
                let handles = {
                    let db = node.db();
                    db.messages().set_handles_with_descriptions(
                        &caller.peer_id,
                        &pairs,
                        now_ms(),
                    )?
                };
                Ok(json_response(StatusCode::OK, &HandlesResponse { handles }))
            }
            Method::GET => {
                let filter_node = query.get("nodeId").map(String::as_str);
                let handles = node.list_directory_handles_for_caller(&caller, filter_node)?;
                Ok(json_response(StatusCode::OK, &HandlesResponse { handles }))
            }
            _ => Err(NodeError::BadRequest("method not allowed".into())),
        },
        Some(PeerRoute::Messages) => {
            let msg_req: PostMessageRequest = serde_json::from_slice(&body_bytes)?;
            let (id, deduplicated) = node.handle_server_post_message(&caller, msg_req).await?;
            Ok(json_response(
                StatusCode::OK,
                &PostMessageResponse { id, deduplicated },
            ))
        }
        Some(PeerRoute::Channels) => {
            let filter_ch = query.get("channel").map(String::as_str);
            let channels = node.list_channels_for_caller(&caller, filter_ch)?;
            Ok(json_response(
                StatusCode::OK,
                &ChannelsResponse { channels },
            ))
        }
        Some(PeerRoute::ChannelJoin) => {
            let join_req: ChannelJoinRequest = serde_json::from_slice(&body_bytes)?;
            let channel = Channel::normalize(&join_req.channel)?.into_inner();
            node.require_scope(
                &caller,
                caller.scopes.may_channel_join(&channel),
                &format!("channel:join={channel}"),
            )?;
            let now = now_ms();
            let membership = {
                let db = node.db();
                let sender_addr = hyp_store::format_address(&caller.peer_id, &join_req.handle);
                if !db.messages().is_enrolled(&sender_addr)? {
                    db.messages()
                        .register_handle(&caller.peer_id, &join_req.handle, None, now)?;
                }
                db.channels().join(
                    node.node_id().as_str(),
                    &channel,
                    &caller.peer_id,
                    &join_req.handle,
                    now,
                )?
            };
            let policy = node.get_channel_policy(&channel);
            let can_post = caller.scopes.may_channel_post(&channel)
                && policy.is_authorized_writer(&caller.peer_id, Some(&membership.address));
            Ok(json_response(
                StatusCode::OK,
                &ChannelJoinResponse {
                    host_node: membership.host_node,
                    channel: membership.channel,
                    address: membership.address,
                    members: membership.members,
                    mode: policy.mode,
                    writers: policy.writers,
                    can_post,
                },
            ))
        }
        Some(PeerRoute::ChannelLeave) => {
            let leave_req: ChannelLeaveRequest = serde_json::from_slice(&body_bytes)?;
            let channel = Channel::normalize(&leave_req.channel)?.into_inner();
            let left = {
                let db = node.db();
                db.channels().leave(
                    node.node_id().as_str(),
                    &channel,
                    &caller.peer_id,
                    &leave_req.handle,
                )?
            };
            Ok(json_response(StatusCode::OK, &json!({ "left": left })))
        }
        Some(PeerRoute::ChannelPost) => {
            let post_req: ChannelPostRequest = serde_json::from_slice(&body_bytes)?;
            let res = node.handle_server_channel_post(&caller, post_req).await?;
            Ok(json_response(StatusCode::OK, &res))
        }
        Some(PeerRoute::ChannelEpochs) => match method {
            Method::POST => {
                let put_req: PutChannelEpochRequest = serde_json::from_slice(&body_bytes)?;
                let saved = node.handle_server_put_channel_epoch(&caller, put_req)?;
                Ok(json_response(StatusCode::OK, &saved))
            }
            Method::GET => {
                let raw_ch = path
                    .strip_prefix("/v1/channel-epochs/")
                    .filter(|s| !s.is_empty())
                    .map(percent_decode)
                    .or_else(|| query.get("channel").cloned())
                    .ok_or_else(|| NodeError::BadRequest("missing channel query param".into()))?;
                let channel = Channel::normalize(&raw_ch)?.into_inner();
                node.require_scope(
                    &caller,
                    caller.scopes.may_channel_join(&channel),
                    &format!("channel:join={channel}"),
                )?;
                let epoch = if let Some(ep_str) = query.get("epoch") {
                    let ep_num: u64 = ep_str
                        .parse()
                        .map_err(|_| NodeError::BadRequest("invalid epoch number".into()))?;
                    node.db()
                        .channels()
                        .get_epoch(node.node_id().as_str(), &channel, ep_num)?
                } else {
                    node.db()
                        .channels()
                        .latest_epoch(node.node_id().as_str(), &channel)?
                };
                Ok(json_response(
                    StatusCode::OK,
                    &ChannelEpochResponse { epoch },
                ))
            }
            _ => Err(NodeError::BadRequest("method not allowed".into())),
        },
        Some(PeerRoute::KvEpochs) => match method {
            Method::POST => {
                let put_req: PutKvEpochRequest = serde_json::from_slice(&body_bytes)?;
                let saved = node.handle_server_put_kv_epoch(&caller, put_req)?;
                Ok(json_response(StatusCode::OK, &saved))
            }
            Method::GET => {
                let ns = path
                    .strip_prefix("/v1/kv-epochs/")
                    .filter(|s| !s.is_empty())
                    .map(percent_decode)
                    .or_else(|| query.get("namespace").cloned())
                    .ok_or_else(|| NodeError::BadRequest("missing namespace param".into()))?;
                node.require_scope(
                    &caller,
                    caller.scopes.may_kv_read(&ns, "") || caller.scopes.may_kv_write(&ns, ""),
                    &format!("kv:read={ns}/*"),
                )?;
                let epoch = if let Some(ep_str) = query.get("epoch") {
                    let ep_num: u64 = ep_str
                        .parse()
                        .map_err(|_| NodeError::BadRequest("invalid epoch number".into()))?;
                    node.db()
                        .kv()
                        .get_epoch(node.node_id().as_str(), &ns, ep_num)?
                } else {
                    node.db().kv().latest_epoch(node.node_id().as_str(), &ns)?
                };
                Ok(json_response(StatusCode::OK, &KvEpochResponse { epoch }))
            }
            _ => Err(NodeError::BadRequest("method not allowed".into())),
        },
        Some(PeerRoute::Events) => {
            let pub_req: PublishEventRequest = serde_json::from_slice(&body_bytes)?;
            node.require_scope(
                &caller,
                caller.scopes.may_stream_publish(&pub_req.topic),
                &format!("stream:publish={}", pub_req.topic),
            )?;
            let res =
                node.ingest_inbound_event_for_caller(&caller, &pub_req.topic, &pub_req.event)?;
            Ok(json_response(StatusCode::OK, &res))
        }
        Some(PeerRoute::Subscriptions) => match method {
            Method::PUT => {
                let put_req: PutSubscriptionsRequest = serde_json::from_slice(&body_bytes)?;
                let (subscriptions, diagnostics) = node
                    .handle_server_put_subscriptions(&caller, put_req)
                    .await?;
                Ok(json_response(
                    StatusCode::OK,
                    &PutSubscriptionsResponse {
                        subscriptions,
                        diagnostics,
                    },
                ))
            }
            Method::GET => {
                let prefix = format!("{}::", caller.peer_id);
                let subscriptions: Vec<_> = node
                    .db()
                    .events()
                    .list_subscriptions(Some(&caller.peer_id))?
                    .into_iter()
                    .map(|mut s| {
                        if let Some(stripped) = s.id.strip_prefix(&prefix) {
                            s.id = stripped.to_string();
                        }
                        s
                    })
                    .collect();
                Ok(json_response(
                    StatusCode::OK,
                    &SubscriptionsResponse { subscriptions },
                ))
            }
            Method::DELETE => {
                let id = query
                    .get("id")
                    .ok_or_else(|| NodeError::BadRequest("missing id query param".into()))?;
                let deleted = node.handle_server_delete_subscription(&caller, id).await?;
                Ok(json_response(
                    StatusCode::OK,
                    &json!({ "deleted": deleted }),
                ))
            }
            _ => Err(NodeError::BadRequest("method not allowed".into())),
        },
        Some(PeerRoute::InboxAck) => {
            let ack_req: InboxAckRequest = serde_json::from_slice(&body_bytes)?;
            let now = now_ms();
            let acked = {
                let db = node.db();
                match ack_req.kind.as_str() {
                    "message" => {
                        db.messages()
                            .ack(&caller.peer_id, &ack_req.id, &ack_req.outcome, now)?
                    }
                    "batch" => db.events().ack_batch(
                        &caller.peer_id,
                        &ack_req.id,
                        &ack_req.outcome,
                        now,
                    )?,
                    "transfer" => {
                        db.transfers()
                            .ack(&caller.peer_id, &ack_req.id, &ack_req.outcome, now)?
                    }
                    other => {
                        return Err(NodeError::BadRequest(format!(
                            "unknown inbox ack kind '{other}'"
                        )));
                    }
                }
            };
            node.clear_in_flight(&caller.peer_id, &format!("{}:{}", ack_req.kind, ack_req.id));
            // Trigger immediate next-item push if more items are queued for this peer!
            node.notify_peer_inbox(&caller.peer_id);
            node.notify_scheduler();
            Ok(json_response(StatusCode::OK, &InboxAckResponse { acked }))
        }
        Some(PeerRoute::Transfer(raw_id)) => {
            let id = percent_decode(raw_id);
            match method {
                Method::PUT => {
                    let to_node = headers
                        .get("x-hyphae-transfer-to")
                        .and_then(|v| v.to_str().ok())
                        .ok_or_else(|| {
                            NodeError::BadRequest("missing X-Hyphae-Transfer-To header".into())
                        })?;
                    let transfer_type = headers
                        .get("x-hyphae-transfer-type")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("transfer.stream.v2");
                    let header_b64 = headers
                        .get("x-hyphae-transfer-header")
                        .and_then(|v| v.to_str().ok())
                        .ok_or_else(|| {
                            NodeError::BadRequest("missing X-Hyphae-Transfer-Header header".into())
                        })?;
                    let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).map_err(|_| {
                        NodeError::BadRequest("invalid transfer header base64url".into())
                    })?;
                    let header_json = String::from_utf8(header_bytes).map_err(|_| {
                        NodeError::BadRequest("transfer header is not valid UTF-8".into())
                    })?;
                    let expected_sha = headers
                        .get("x-hyphae-sha256")
                        .and_then(|v| v.to_str().ok())
                        .map(ToOwned::to_owned);
                    let to_handle = headers
                        .get("x-hyphae-transfer-to-handle")
                        .and_then(|v| v.to_str().ok());

                    let res = node
                        .handle_server_upload_transfer(
                            &caller,
                            &id,
                            to_node,
                            to_handle,
                            transfer_type,
                            &header_json,
                            expected_sha,
                            body_bytes,
                        )
                        .await?;
                    Ok(json_response(
                        StatusCode::OK,
                        &TransferUploadResponse {
                            id: res.id,
                            sha256: res.sha256,
                            size: res.size,
                            deduplicated: res.deduplicated,
                        },
                    ))
                }
                Method::GET => {
                    let rec = {
                        let db = node.db();
                        db.transfers().get(&id)?
                    }
                    .ok_or_else(|| NodeError::NotFound(format!("transfer '{id}' not found")))?;
                    if rec.to_node != caller.peer_id {
                        return Err(NodeError::Unauthorized(
                            "transfer is not addressed to caller".into(),
                        ));
                    }
                    node.require_scope(
                        &caller,
                        caller.scopes.may_receive_files(rec.size),
                        "files:receive",
                    )?;
                    let blob = {
                        let db = node.db();
                        db.transfers().read_blob(&caller.peer_id, &id)?
                    }
                    .ok_or_else(|| {
                        NodeError::NotFound(format!("transfer blob '{id}' not found"))
                    })?;
                    Ok(bytes_response(
                        StatusCode::OK,
                        "application/octet-stream",
                        blob,
                    ))
                }
                _ => Err(NodeError::BadRequest("method not allowed".into())),
            }
        }
        Some(PeerRoute::KvMetadata) => match (query.get("namespace"), query.get("key")) {
            (None, None) => Ok(json_response(
                StatusCode::OK,
                &node.inspect_hosted_kv_for_peer(&caller, now_ms())?,
            )),
            (Some(namespace), None) => Ok(json_response(
                StatusCode::OK,
                &node.inspect_hosted_kv_keys_for_peer(
                    &caller,
                    namespace,
                    query.get("after").map(String::as_str),
                )?,
            )),
            (Some(namespace), Some(key)) => Ok(json_response(
                StatusCode::OK,
                &node.read_hosted_kv_for_peer(&caller, namespace, key)?,
            )),
            _ => Err(NodeError::BadRequest(
                "KV preview requires a namespace and key".into(),
            )),
        },
        Some(PeerRoute::Kv(rest)) => {
            if let Some((ns_raw, key_raw)) = rest.split_once('/') {
                let namespace = percent_decode(ns_raw);
                let key = key_raw
                    .split('/')
                    .map(percent_decode)
                    .collect::<Vec<_>>()
                    .join("/");
                return match method {
                    Method::PUT => {
                        node.require_scope(
                            &caller,
                            caller.scopes.may_kv_write(&namespace, &key),
                            &format!("kv:write={namespace}/{key}"),
                        )?;
                        let body: KvSetBody = serde_json::from_slice(&body_bytes)?;
                        let if_match_ver = parse_if_match_version(&headers)?;
                        let expected_version = if_match_ver.or(body.expected_version);
                        let res = {
                            let db = node.db();
                            db.kv().set(
                                &KvSetInput {
                                    host_node: node.node_id().to_string(),
                                    namespace: namespace.clone(),
                                    key: key.clone(),
                                    value: body.value,
                                    content_type: body.content_type,
                                    write_model: body.write_model,
                                    owner_id: body.owner_id,
                                    allowlist: body.allowlist,
                                    writer_id: caller.peer_id.clone(),
                                    expected_version,
                                    e2ee_epoch: body.e2ee_epoch,
                                    signature: body.signature,
                                    ttl_ms: body.ttl_ms,
                                },
                                now_ms(),
                            )
                        };
                        match res {
                            Ok(set_res) => {
                                node.notify_kv_metadata_change();
                                node.notify_all_inbox_subscribers();
                                node.notify_scheduler();
                                let etag = format_version_etag(set_res.entry.version);
                                Ok(json_response_with_etag(
                                    StatusCode::OK,
                                    &set_res.entry,
                                    &etag,
                                ))
                            }
                            Err(StoreError::VersionConflict { current_version }) => {
                                let problem = ProblemDetails::version_conflict(
                                    expected_version.unwrap_or(0),
                                    current_version,
                                    Some(&namespace),
                                    Some(&key),
                                );
                                Ok(problem_response(&problem))
                            }
                            Err(err) => Err(NodeError::Store(err)),
                        }
                    }
                    Method::GET => {
                        node.require_scope(
                            &caller,
                            caller.scopes.may_kv_read(&namespace, &key),
                            &format!("kv:read={namespace}/{key}"),
                        )?;
                        let entry = {
                            let db = node.db();
                            db.kv()
                                .get(node.node_id().as_str(), &namespace, &key, now_ms())?
                        }
                        .ok_or_else(|| {
                            NodeError::NotFound(format!("kv entry '{namespace}/{key}' not found"))
                        })?;
                        let etag = format_version_etag(entry.version);
                        if etag_matches_if_none_match(&headers, &etag) {
                            return Ok(not_modified_response(&etag));
                        }
                        Ok(json_response_with_etag(StatusCode::OK, &entry, &etag))
                    }
                    Method::DELETE => {
                        node.require_scope(
                            &caller,
                            caller.scopes.may_kv_write(&namespace, &key),
                            &format!("kv:write={namespace}/{key}"),
                        )?;
                        let body: KvDeleteBody = if body_bytes.is_empty() {
                            KvDeleteBody::default()
                        } else {
                            serde_json::from_slice(&body_bytes)?
                        };
                        let if_match_ver = parse_if_match_version(&headers)?;
                        let expected_version = if_match_ver.or(body.expected_version);
                        let res = {
                            let db = node.db();
                            db.kv().delete(
                                &KvDeleteInput {
                                    host_node: node.node_id().to_string(),
                                    namespace: namespace.clone(),
                                    key: key.clone(),
                                    writer_id: caller.peer_id.clone(),
                                    expected_version,
                                },
                                now_ms(),
                            )
                        };
                        match res {
                            Ok(del_res) => {
                                if del_res.deleted {
                                    node.notify_kv_metadata_change();
                                }
                                node.notify_all_inbox_subscribers();
                                Ok(json_response(StatusCode::OK, &del_res))
                            }
                            Err(StoreError::VersionConflict { current_version }) => {
                                let problem = ProblemDetails::version_conflict(
                                    expected_version.unwrap_or(0),
                                    current_version,
                                    Some(&namespace),
                                    Some(&key),
                                );
                                Ok(problem_response(&problem))
                            }
                            Err(err) => Err(NodeError::Store(err)),
                        }
                    }
                    _ => Err(NodeError::BadRequest("method not allowed".into())),
                };
            } else if method == Method::GET {
                let namespace = percent_decode(rest);
                let prefix = query.get("prefix").map(String::as_str);
                let probe_key = prefix.unwrap_or("");
                node.require_scope(
                    &caller,
                    caller.scopes.may_kv_read(&namespace, probe_key),
                    &format!("kv:read={namespace}/{probe_key}*"),
                )?;
                let entries: Vec<_> = {
                    let db = node.db();
                    db.kv()
                        .list(node.node_id().as_str(), &namespace, prefix, now_ms())?
                }
                .into_iter()
                .filter(|e| caller.scopes.may_kv_read(&e.namespace, &e.key))
                .collect();
                return Ok(json_response(StatusCode::OK, &KvListResponse { entries }));
            }
            Err(NodeError::NotFound(format!(
                "route '{method} {path}' not found"
            )))
        }
        None => Err(NodeError::NotFound(format!(
            "route '{method} {path}' not found"
        ))),
    }
}

fn webhook_outcome_response(
    outcome: Result<WebhookIngestOutcome, AdapterError>,
) -> Result<Response<BoxedBody>, NodeError> {
    let outcome = outcome.map_err(|err| match err {
        AdapterError::Unauthorized(m) => NodeError::Unauthorized(m),
        AdapterError::InvalidInput(m) => NodeError::BadRequest(m),
        AdapterError::PayloadTooLarge(m) => NodeError::PayloadTooLarge(m),
        other => NodeError::Http(other.to_string()),
    })?;
    let payload = match outcome {
        WebhookIngestOutcome::Published { event_id, outcome } => json!({
            "ok": true,
            "status": "published",
            "eventId": event_id,
            "publishStatus": outcome.status,
            "matched": outcome.matched,
        }),
        WebhookIngestOutcome::Ignored { reason } => json!({
            "ok": true,
            "status": "ignored",
            "reason": reason,
        }),
    };
    Ok(json_response(StatusCode::OK, &payload))
}

fn require_auth(
    node: &UnifiedNode,
    headers: &HeaderMap,
    method: &str,
    path_and_query: &str,
    body_sha256: &str,
) -> Result<AuthenticatedPeer, NodeError> {
    node.authenticate_request(headers, method, path_and_query, body_sha256)?
        .ok_or_else(|| NodeError::Unauthorized("missing Authorization header".into()))
}

fn request_origin(headers: &HeaderMap) -> Option<&str> {
    headers.get(ORIGIN).and_then(|v| v.to_str().ok())
}

fn drop_cap_header(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(DROP_CAP_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn drop_relay_error_response(
    relay: &DropRelay,
    req_headers: &HeaderMap,
    err: &DropRelayError,
    with_cors: bool,
) -> Response<BoxedBody> {
    let mut resp = problem_response(&err.to_problem_details());
    if let Some(secs) = err.retry_after_secs() {
        resp = with_retry_after(resp, secs);
    }
    if with_cors {
        relay.apply_cors_headers(request_origin(req_headers), resp.headers_mut());
    }
    resp
}

fn check_content_length(headers: &HeaderMap, max_bytes: usize) -> Result<(), NodeError> {
    let Some(raw_val) = headers.get(CONTENT_LENGTH) else {
        return Ok(());
    };
    let raw_str = raw_val
        .to_str()
        .map_err(|_| NodeError::BadRequest("invalid Content-Length header".into()))?
        .trim();
    let declared: usize = raw_str
        .parse()
        .map_err(|_| NodeError::BadRequest("invalid Content-Length header".into()))?;
    if declared > max_bytes {
        return Err(NodeError::PayloadTooLarge(format!(
            "declared Content-Length {declared} exceeds limit of {max_bytes} bytes"
        )));
    }
    Ok(())
}

fn resolve_github_webhook_target(
    node: &UnifiedNode,
    method: &Method,
    path: &str,
) -> Result<Option<Arc<GitHubWebhookAdapter>>, NodeError> {
    if method != Method::POST {
        return Ok(None);
    }
    if path == "/v1/webhooks/github" {
        return node.github_webhook_adapter(None).map(Some).ok_or_else(|| {
            NodeError::NotFound("github webhook endpoint is disabled on this node".into())
        });
    }
    let Some(raw_id) = path
        .strip_prefix("/v1/webhooks/github/")
        .filter(|id| !id.is_empty() && !id.contains('/'))
    else {
        return Ok(None);
    };
    let id = percent_decode(raw_id);
    node.github_webhook_adapter(Some(&id))
        .map(Some)
        .ok_or_else(|| {
            NodeError::NotFound(format!(
                "github webhook '{id}' is not configured on this node"
            ))
        })
}

fn resolve_pre_read_body_limit(
    node: &UnifiedNode,
    method: &Method,
    path: &str,
    headers: &HeaderMap,
    public_control: Option<PublicControlRoute<'_>>,
    peer_route: Option<PeerRoute<'_>>,
) -> Result<usize, NodeError> {
    if let Some(route) = public_control {
        route.check_enabled(node)?;
        return Ok(MAX_UNAUTH_CONTROL_BODY_BYTES);
    }

    if let Some(adapter) = resolve_github_webhook_target(node, method, path)? {
        return Ok(adapter.config().max_body_bytes);
    }

    if method == Method::PUT && matches!(peer_route, Some(PeerRoute::Transfer(_))) {
        if !headers.contains_key(AUTHORIZATION) {
            return Err(NodeError::Unauthorized(
                "missing Authorization header".into(),
            ));
        }
        return Ok(node
            .config()
            .store_config
            .transfer_limits
            .max_bytes
            .min(usize::MAX as u64) as usize);
    }

    Ok(MAX_JSON_BODY_BYTES)
}

/// Extracts the effective client IP for Drop Relay per-IP rate limiting (`H7`).
///
/// Security invariant:
/// - ONLY inspects `X-Forwarded-For` when `trusted_proxies` is non-empty AND `peer_ip` matches a
///   configured CIDR/IP in `trusted_proxies`.
/// - Walks `X-Forwarded-For` from **right to left** and returns the **rightmost valid IP NOT
///   matching `trusted_proxies`** (preventing left-side client header spoofing and intermediate
///   trusted hop confusion).
/// - Never falls back to `X-Real-Ip` (dropped to prevent intermediate proxy header spoofing).
pub fn extract_drop_relay_client_ip(
    peer_ip: IpAddr,
    headers: &HeaderMap,
    trusted_proxies: &[String],
) -> String {
    let norm_peer = normalize_ip_addr(peer_ip);
    if trusted_proxies.is_empty() || !ip_matches_trusted_proxies(norm_peer, trusted_proxies) {
        return norm_peer.to_string();
    }

    let mut xff_ips: Vec<IpAddr> = Vec::new();
    for val in headers.get_all("x-forwarded-for") {
        if let Ok(raw) = val.to_str() {
            for part in raw.split(',') {
                let candidate = part.trim();
                if let Ok(parsed) = candidate.parse::<IpAddr>() {
                    xff_ips.push(normalize_ip_addr(parsed));
                }
            }
        }
    }
    if let Some(ip) = xff_ips
        .into_iter()
        .rev()
        .find(|ip| !ip_matches_trusted_proxies(*ip, trusted_proxies))
    {
        return ip.to_string();
    }

    norm_peer.to_string()
}

#[allow(clippy::too_many_arguments)]
async fn handle_drop_relay_request(
    node: Arc<UnifiedNode>,
    peer_addr: SocketAddr,
    method: Method,
    path: &str,
    path_and_query: &str,
    query: &std::collections::BTreeMap<String, String>,
    headers: &HeaderMap,
    body: Incoming,
) -> Result<Response<BoxedBody>, NodeError> {
    let relay = node.drop_relay();
    if !relay.is_enabled() {
        return Ok(drop_relay_error_response(
            &relay,
            headers,
            &DropRelayError::Disabled,
            false,
        ));
    }

    if method == Method::OPTIONS {
        let mut resp = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, OPTIONS")
            .header(
                ACCESS_CONTROL_ALLOW_HEADERS,
                "Content-Type, X-Hyphae-Drop-Cap, Last-Event-ID",
            )
            .header(ACCESS_CONTROL_MAX_AGE, "600")
            .body(empty_body())
            .expect("valid 204 preflight response");
        relay.apply_cors_headers(request_origin(headers), resp.headers_mut());
        return Ok(resp);
    }

    let client_ip =
        extract_drop_relay_client_ip(peer_addr.ip(), headers, &node.config().trusted_proxies);

    // POST /v1/drops
    if path == "/v1/drops" {
        if method != Method::POST {
            return Err(NodeError::BadRequest("method not allowed".into()));
        }
        check_content_length(headers, MAX_DROP_CONTROL_BODY_BYTES)?;
        let body_bytes = read_body_bytes(body, MAX_DROP_CONTROL_BODY_BYTES).await?;
        let body_sha = hex::encode(Sha256::digest(&body_bytes));
        let caller = require_auth(&node, headers, "POST", path_and_query, &body_sha)?;
        let allowed =
            caller.peer_id == node.node_id().as_str() || caller.scopes.allows_drop_create();
        node.require_scope(&caller, allowed, "drop:create")?;
        let create_req: CreateDropRequest = if body_bytes.is_empty() {
            CreateDropRequest::default()
        } else {
            serde_json::from_slice(&body_bytes)?
        };
        return match relay.create_drop(&caller.peer_id, &client_ip, create_req, now_ms()) {
            Ok(created) => Ok(json_response(StatusCode::CREATED, &created)),
            Err(err) => Ok(drop_relay_error_response(&relay, headers, &err, false)),
        };
    }

    let Some(rest) = path.strip_prefix("/v1/drops/") else {
        return Err(NodeError::NotFound(format!(
            "route '{method} {path}' not found"
        )));
    };

    // GET /v1/drops/{id}/stream
    if let Some(raw_id) = rest.strip_suffix("/stream") {
        if raw_id.is_empty() || raw_id.contains('/') {
            return Err(NodeError::NotFound(format!(
                "route '{method} {path}' not found"
            )));
        }
        if method != Method::GET {
            return Err(NodeError::BadRequest("method not allowed".into()));
        }
        let drop_id = percent_decode(raw_id);
        let cap_opt = drop_cap_header(headers);
        let creator_id = if cap_opt.is_none() {
            let empty_sha = hex::encode(Sha256::digest(b""));
            let caller = require_auth(&node, headers, "GET", path_and_query, &empty_sha)?;
            Some(caller.peer_id)
        } else {
            None
        };
        let sub_auth = match (cap_opt, creator_id.as_deref()) {
            (Some(cap), _) => DropSubscriberAuth::SubCap(cap),
            (None, Some(node_id)) => DropSubscriberAuth::CreatorNode(node_id),
            (None, None) => unreachable!(),
        };

        let raw_cursor = headers
            .get("last-event-id")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .or_else(|| {
                query
                    .get("after")
                    .map(String::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
            });
        let last_event_id = match raw_cursor {
            None => None,
            Some(raw) => match raw.parse::<u64>() {
                Ok(seq) => Some(seq),
                Err(_) => {
                    let err =
                        DropRelayError::BadRequest(format!("invalid Last-Event-ID cursor '{raw}'"));
                    return Ok(drop_relay_error_response(&relay, headers, &err, false));
                }
            },
        };

        return match relay.subscribe_drop(&drop_id, sub_auth, &client_ip, last_event_id, now_ms()) {
            Ok(sub) => Ok(start_drop_sse_stream(node, sub)),
            Err(err) => Ok(drop_relay_error_response(&relay, headers, &err, false)),
        };
    }

    // POST /v1/drops/{id}/ack
    if let Some(raw_id) = rest.strip_suffix("/ack") {
        if raw_id.is_empty() || raw_id.contains('/') {
            return Err(NodeError::NotFound(format!(
                "route '{method} {path}' not found"
            )));
        }
        if method != Method::POST {
            return Err(NodeError::BadRequest("method not allowed".into()));
        }
        let drop_id = percent_decode(raw_id);
        check_content_length(headers, MAX_DROP_CONTROL_BODY_BYTES)?;
        let body_bytes = read_body_bytes(body, MAX_DROP_CONTROL_BODY_BYTES).await?;
        let body_sha = hex::encode(Sha256::digest(&body_bytes));
        let cap_opt = drop_cap_header(headers);
        let creator_id = if cap_opt.is_none() {
            let caller = require_auth(&node, headers, "POST", path_and_query, &body_sha)?;
            Some(caller.peer_id)
        } else {
            None
        };
        let sub_auth = match (cap_opt, creator_id.as_deref()) {
            (Some(cap), _) => DropSubscriberAuth::SubCap(cap),
            (None, Some(node_id)) => DropSubscriberAuth::CreatorNode(node_id),
            (None, None) => unreachable!(),
        };
        let ack_body: AckDropBody = serde_json::from_slice(&body_bytes)?;
        return match relay.ack_drop(&drop_id, sub_auth, ack_body.seq, ack_body.burn, now_ms()) {
            Ok(resp) => Ok(json_response(StatusCode::OK, &resp)),
            Err(err) => Ok(drop_relay_error_response(&relay, headers, &err, false)),
        };
    }

    // POST /v1/drops/{id}
    if !rest.is_empty() && !rest.contains('/') {
        if method != Method::POST {
            return Err(NodeError::BadRequest("method not allowed".into()));
        }
        let drop_id = percent_decode(rest);
        let Some(cap) = drop_cap_header(headers) else {
            let err = DropRelayError::Unauthorized(format!("missing {DROP_CAP_HEADER} header"));
            return Ok(drop_relay_error_response(&relay, headers, &err, true));
        };

        // Constant-time stateless capability verification BEFORE reading request body bytes!
        if let Err(err) = relay.verify_capability(&drop_id, cap, DropCapRole::Post, now_ms()) {
            return Ok(drop_relay_error_response(&relay, headers, &err, true));
        }

        let max_payload = relay.config().max_payload_bytes;
        if let Err(err) = check_content_length(headers, max_payload) {
            return match err {
                NodeError::PayloadTooLarge(_) => {
                    let derr = DropRelayError::PayloadTooLarge {
                        size: max_payload.saturating_add(1),
                        max_bytes: max_payload,
                    };
                    Ok(drop_relay_error_response(&relay, headers, &derr, true))
                }
                other => {
                    let mut resp = problem_response(&other.to_problem_details());
                    relay.apply_cors_headers(request_origin(headers), resp.headers_mut());
                    Ok(resp)
                }
            };
        }
        let body_bytes = match read_body_bytes(body, max_payload).await {
            Ok(bytes) => bytes,
            Err(NodeError::PayloadTooLarge(_)) => {
                let err = DropRelayError::PayloadTooLarge {
                    size: max_payload.saturating_add(1),
                    max_bytes: max_payload,
                };
                return Ok(drop_relay_error_response(&relay, headers, &err, true));
            }
            Err(err) => {
                let mut resp = problem_response(&err.to_problem_details());
                relay.apply_cors_headers(request_origin(headers), resp.headers_mut());
                return Ok(resp);
            }
        };

        return match relay.post_drop(&drop_id, cap, body_bytes.to_vec(), now_ms()) {
            Ok(posted) => {
                let mut resp = json_response(StatusCode::CREATED, &posted);
                relay.apply_cors_headers(request_origin(headers), resp.headers_mut());
                Ok(resp)
            }
            Err(err) => Ok(drop_relay_error_response(&relay, headers, &err, true)),
        };
    }

    Err(NodeError::NotFound(format!(
        "route '{method} {path}' not found"
    )))
}

fn start_drop_sse_stream(node: Arc<UnifiedNode>, mut sub: DropSubscription) -> Response<BoxedBody> {
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, io::Error>>(64);

    tokio::spawn(async move {
        let mut shutdown_rx = node.shutdown_receiver();
        if *shutdown_rx.borrow() {
            return;
        }
        if tx
            .send(Ok(Frame::data(Bytes::from_static(b": connected\n\n"))))
            .await
            .is_err()
        {
            return;
        }

        for item in sub.drain_backlog() {
            let encoded = item.to_sse_event().encode();
            if tx
                .send(Ok(Frame::data(Bytes::from(encoded))))
                .await
                .is_err()
            {
                return;
            }
        }

        let mut keepalive = tokio::time::interval(Duration::from_secs(DROP_SSE_KEEPALIVE_SECONDS));
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        keepalive.tick().await;

        loop {
            if *shutdown_rx.borrow() {
                break;
            }
            let remaining_ms = sub.expires_at_ms().saturating_sub(now_ms());
            if remaining_ms <= 0 {
                break;
            }
            let expiry_sleep = tokio::time::sleep(Duration::from_millis(remaining_ms as u64));
            tokio::pin!(expiry_sleep);

            tokio::select! {
                item = sub.recv() => {
                    match item {
                        Some(item) => {
                            let encoded = item.to_sse_event().encode();
                            if tx.send(Ok(Frame::data(Bytes::from(encoded)))).await.is_err() {
                                break;
                            }
                        }
                        None => break,
                    }
                }
                _ = keepalive.tick() => {
                    if tx.send(Ok(Frame::data(sse_keepalive_frame()))).await.is_err() {
                        break;
                    }
                }
                _ = &mut expiry_sleep => {
                    break;
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = tx.closed() => {
                    break;
                }
            }
        }
    });

    sse_response(rx)
}

fn start_inbox_sse_stream(
    node: Arc<UnifiedNode>,
    caller: AuthenticatedPeer,
) -> Response<BoxedBody> {
    let (tx, rx) = mpsc::channel::<Result<Frame<Bytes>, io::Error>>(64);
    let peer_id = caller.peer_id.clone();

    tokio::spawn(async move {
        let mut wake_rx = node.subscribe_peer_inbox_wakeups();
        let mut shutdown_rx = node.shutdown_receiver();
        if *shutdown_rx.borrow() || !node.is_peer_still_active(&peer_id) {
            return;
        }

        // Reset stale in-flight entries when peer reconnects so unacked items redeliver cleanly!
        node.clear_all_in_flight_for_peer(&peer_id);

        if tx
            .send(Ok(Frame::data(Bytes::from_static(b": connected\n\n"))))
            .await
            .is_err()
        {
            return;
        }

        let mut keepalive = tokio::time::interval(SSE_KEEPALIVE_INTERVAL);
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        keepalive.tick().await; // consume immediate first tick

        loop {
            if *shutdown_rx.borrow() || !node.is_peer_still_active(&peer_id) {
                break;
            }
            if !push_due_items_to_sse(&node, &peer_id, &tx).await {
                break;
            }
            tokio::select! {
                msg = wake_rx.recv() => {
                    match msg {
                        Ok(target) if target == "*" || target == peer_id => {}
                        Ok(_) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                    }
                }
                _ = keepalive.tick() => {
                    // P1-4: Re-verify peer is still Active before every keepalive tick.
                    if !node.is_peer_still_active(&peer_id) {
                        break;
                    }
                    if tx.send(Ok(Frame::data(sse_keepalive_frame()))).await.is_err() {
                        break;
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
                _ = tx.closed() => {
                    break;
                }
            }
        }
        node.clear_all_in_flight_for_peer(&peer_id);
    });

    sse_response(rx)
}

async fn push_due_items_to_sse(
    node: &UnifiedNode,
    peer_id: &str,
    tx: &mpsc::Sender<Result<Frame<Bytes>, io::Error>>,
) -> bool {
    // P1-4: Fail closed before pulling or pushing any queued items for a revoked/inactive peer.
    if !node.is_peer_still_active(peer_id) {
        return false;
    }
    let now = now_ms();
    let (due_msgs, due_batches, due_transfer) = {
        let db = node.db();
        let _ = db.events().tick(now);
        let msgs = db
            .messages()
            .due_messages(
                peer_id,
                |id| node.is_in_flight(peer_id, &format!("message:{id}")),
                now,
            )
            .unwrap_or_default();
        let batches = db
            .events()
            .due_batches(
                peer_id,
                |id| node.is_in_flight(peer_id, &format!("batch:{id}")),
                now,
            )
            .unwrap_or_default();
        let transfer = db
            .transfers()
            .due_transfer(
                peer_id,
                |id| node.is_in_flight(peer_id, &format!("transfer:{id}")),
                now,
            )
            .ok()
            .flatten();
        (msgs, batches, transfer)
    };

    for msg in due_msgs {
        if !node.is_peer_still_active(peer_id) {
            return false;
        }
        let key = format!("message:{}", msg.id);
        if !node.mark_in_flight(peer_id, key.clone()) {
            continue;
        }
        if let Ok(json_str) = serde_json::to_string(&msg) {
            let sse = SseEvent::new("message", json_str).with_id(key).encode();
            if tx.send(Ok(Frame::data(Bytes::from(sse)))).await.is_err() {
                return false;
            }
        }
    }

    for batch in due_batches {
        if !node.is_peer_still_active(peer_id) {
            return false;
        }
        // Issue #25 (B6) defense-in-depth: never push local-only topic batches to remote peers
        // over SSE even if a stale subscription or pending batch existed from before `exposeTopic: false`.
        if batch.origin_node == node.node_id().as_str() && node.is_local_only_topic(&batch.topic) {
            continue;
        }
        let key = format!("batch:{}", batch.id);
        if !node.mark_in_flight(peer_id, key.clone()) {
            continue;
        }
        if let Ok(json_str) = serde_json::to_string(&batch) {
            let sse = SseEvent::new("batch", json_str).with_id(key).encode();
            if tx.send(Ok(Frame::data(Bytes::from(sse)))).await.is_err() {
                return false;
            }
        }
    }

    if let Some(transfer) = due_transfer {
        if !node.is_peer_still_active(peer_id) {
            return false;
        }
        let key = format!("transfer:{}", transfer.id);
        if node.mark_in_flight(peer_id, key.clone()) {
            if let Ok(json_str) = serde_json::to_string(&transfer) {
                let sse = SseEvent::new("transfer", json_str).with_id(key).encode();
                if tx.send(Ok(Frame::data(Bytes::from(sse)))).await.is_err() {
                    return false;
                }
            }
        }
    }

    true
}
