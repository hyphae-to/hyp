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
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode};
use hyper::body::{Frame, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use hyp_crypto::pairing::P2pPairResponse;
use hyp_proto::address::Channel;
use hyp_proto::problem::ProblemDetails;
use hyp_store::{KvDeleteInput, KvSetInput, StoreError, now_ms};

use crate::adapters::{AdapterError, WebhookIngestOutcome};
use crate::engine::config::NodeError;
use crate::engine::http_util::{
    BoxedBody, SseEvent, bytes_response, etag_matches_if_none_match, format_version_etag,
    json_response, json_response_with_etag, not_modified_response, parse_if_match_version,
    parse_query, percent_decode, problem_response, read_body_bytes, sse_keepalive_frame,
    sse_response, with_retry_after,
};
use crate::engine::node::{AuthenticatedPeer, UnifiedNode};
use crate::engine::peer_link::{
    ChannelEpochResponse, ChannelJoinRequest, ChannelJoinResponse, ChannelLeaveRequest,
    ChannelPostRequest, ChannelsResponse, GuestPairRequest, HandlesResponse, InboxAckRequest,
    InboxAckResponse, KvDeleteBody, KvEpochResponse, KvListResponse, KvSetBody, PairRequestV2,
    PeerKeysResponse, PostMessageRequest, PostMessageResponse, PublishEventRequest,
    PutChannelEpochRequest, PutHandlesRequest, PutKeyRequest, PutKvEpochRequest,
    PutSubscriptionsRequest, PutSubscriptionsResponse, SubscriptionsResponse,
    TransferUploadResponse,
};

const MAX_JSON_BODY_BYTES: usize = 2 * 1024 * 1024;
const SSE_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(25);

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
                let (stream, _peer_addr) = match accept {
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
                        async move { Ok::<_, Infallible>(handle_http_request(n, req).await) }
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
}

async fn handle_http_request(
    node: Arc<UnifiedNode>,
    req: Request<Incoming>,
) -> Response<BoxedBody> {
    match route_request(node, req).await {
        Ok(resp) => resp,
        Err(err) => {
            let retry_after = match &err {
                NodeError::RateLimited {
                    retry_after_secs, ..
                } => *retry_after_secs,
                NodeError::Store(StoreError::RateLimited(_)) => Some(60),
                _ => None,
            };
            let resp = problem_response(&err.to_problem_details());
            match retry_after {
                Some(secs) => with_retry_after(resp, secs),
                None => resp,
            }
        }
    }
}

async fn route_request(
    node: Arc<UnifiedNode>,
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

    // Streaming SSE endpoint must NOT read a request body before upgrading.
    if method == Method::GET && path == "/v1/inbox" {
        let empty_sha = hex::encode(Sha256::digest(b""));
        let caller = require_auth(&node, &headers, "GET", &path_and_query, &empty_sha)?;
        return Ok(start_inbox_sse_stream(node, caller));
    }

    // Determine max body cap (transfers permit up to configured `max_bytes`).
    let is_transfer_put = method == Method::PUT && path.starts_with("/v1/transfers/");
    let max_body = if is_transfer_put {
        node.config()
            .store_config
            .transfer_limits
            .max_bytes
            .min(usize::MAX as u64) as usize
    } else {
        MAX_JSON_BODY_BYTES
    };

    let body_bytes = read_body_bytes(req.into_body(), max_body).await?;
    let body_sha = hex::encode(Sha256::digest(&body_bytes));

    // ---- Unauthenticated or Optionally Authenticated Endpoints ----

    if method == Method::GET && path == "/v1/health" {
        let gh_summary = match node.github_public_adapter() {
            Some(adapter) => {
                let stats = adapter.stats().await;
                json!({
                    "enabled": true,
                    "activePollers": stats.active_pollers,
                    "pollsTotal": stats.polls_total,
                    "polls200": stats.polls_200,
                    "polls304": stats.polls_304,
                    "appWebhooksPublished": stats.app_webhooks_published,
                })
            }
            None => json!({
                "enabled": false,
                "activePollers": 0,
                "pollsTotal": 0,
                "polls200": 0,
                "polls304": 0,
                "appWebhooksPublished": 0,
            }),
        };
        return Ok(json_response(
            StatusCode::OK,
            &json!({
                "ok": true,
                "nodeId": node.node_id().as_str(),
                "profile": node.config().profile,
                "guestPairingEnabled": node.config().guest_pairing.enabled,
                "githubPublic": gh_summary,
            }),
        ));
    }

    if method == Method::GET && path == "/v1/manifest" {
        let caller = node.authenticate_request(&headers, "GET", &path_and_query, &body_sha)?;
        let (signed, _payload, etag) = node.build_signed_manifest(caller.as_ref())?;
        if etag_matches_if_none_match(&headers, &etag) {
            return Ok(not_modified_response(&etag));
        }
        return Ok(json_response_with_etag(StatusCode::OK, &signed, &etag));
    }

    if method == Method::GET && path == "/.well-known/agent.json" {
        if !node.config().expose_a2a_card {
            return Err(NodeError::NotFound(
                "A2A agent card projection is disabled on this node".into(),
            ));
        }
        let caller = node.authenticate_request(&headers, "GET", &path_and_query, &body_sha)?;
        let (_signed, payload, _etag) = node.build_signed_manifest(caller.as_ref())?;
        let card = payload.to_a2a_agent_card(&node.endpoint_url());
        return Ok(json_response(StatusCode::OK, &card));
    }

    if method == Method::POST && path == "/v1/pair" {
        let pair_req: PairRequestV2 = serde_json::from_slice(&body_bytes)?;
        let reply = node.handle_admin_pair_request(&pair_req)?;
        return Ok(json_response(StatusCode::OK, &reply));
    }

    if method == Method::POST && path == "/v1/guest/pair" {
        if !node.config().guest_pairing.enabled {
            return Err(NodeError::NotFound(
                "guest pairing is disabled on this node".into(),
            ));
        }
        let guest_req: GuestPairRequest = serde_json::from_slice(&body_bytes)?;
        let reply = node.handle_guest_pair_request(&guest_req)?;
        return Ok(json_response(StatusCode::OK, &reply));
    }

    if method == Method::POST && path == "/v1/webhooks/github-app" {
        let Some(adapter) = node
            .github_public_adapter()
            .filter(|a| a.has_app_webhook_secret())
        else {
            return Err(NodeError::NotFound(
                "github-app webhook endpoint is disabled on this node".into(),
            ));
        };
        let outcome = adapter
            .handle_app_webhook(&headers, &body_bytes)
            .await
            .map_err(|err| match err {
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
            WebhookIngestOutcome::PublishedMany {
                event_ids,
                stored,
                duplicates,
            } => json!({
                "ok": true,
                "status": "published_many",
                "eventIds": event_ids,
                "stored": stored,
                "duplicates": duplicates,
            }),
            WebhookIngestOutcome::Ignored { reason } => json!({
                "ok": true,
                "status": "ignored",
                "reason": reason,
            }),
        };
        return Ok(json_response(StatusCode::OK, &payload));
    }

    if method == Method::POST {
        if let Some(offer_id) = path.strip_prefix("/v1/p2p/pair/") {
            let offer_id = percent_decode(offer_id);
            let pair_resp: P2pPairResponse = serde_json::from_slice(&body_bytes)?;
            let reply = node.handle_p2p_pair_request(&offer_id, &pair_resp)?;
            return Ok(json_response(StatusCode::OK, &reply));
        }
    }

    // ---- Strictly Authenticated Peer Endpoints ----

    let caller = require_auth(&node, &headers, method.as_str(), &path_and_query, &body_sha)?;

    // /v1/keys
    if path == "/v1/keys" {
        return match method {
            Method::PUT => {
                let put_req: PutKeyRequest = serde_json::from_slice(&body_bytes)?;
                node.register_peer_key_proof(&caller.peer_id, &put_req)?;
                Ok(json_response(StatusCode::OK, &json!({ "ok": true })))
            }
            Method::GET => {
                let filter_node = query.get("nodeId").map(String::as_str);
                let keys = node.list_directory_keys(filter_node)?;
                Ok(json_response(StatusCode::OK, &PeerKeysResponse { keys }))
            }
            _ => Err(NodeError::BadRequest("method not allowed".into())),
        };
    }

    // /v1/handles
    if path == "/v1/handles" {
        return match method {
            Method::PUT => {
                let put_req: PutHandlesRequest = serde_json::from_slice(&body_bytes)?;
                let refs: Vec<&str> = put_req.handles.iter().map(String::as_str).collect();
                let handles = {
                    let db = node.db();
                    db.messages()
                        .set_handles(&caller.peer_id, &refs, now_ms())?
                };
                Ok(json_response(StatusCode::OK, &HandlesResponse { handles }))
            }
            Method::GET => {
                let filter_node = query.get("nodeId").map(String::as_str);
                let handles = {
                    let db = node.db();
                    db.messages().list_handles(filter_node)?
                };
                Ok(json_response(StatusCode::OK, &HandlesResponse { handles }))
            }
            _ => Err(NodeError::BadRequest("method not allowed".into())),
        };
    }

    // /v1/messages
    if method == Method::POST && path == "/v1/messages" {
        let msg_req: PostMessageRequest = serde_json::from_slice(&body_bytes)?;
        let (id, deduplicated) = node.handle_server_post_message(&caller, msg_req).await?;
        return Ok(json_response(
            StatusCode::OK,
            &PostMessageResponse { id, deduplicated },
        ));
    }

    // /v1/channels/*
    if method == Method::GET && path == "/v1/channels" {
        let filter_ch = query.get("channel").map(String::as_str);
        let channels = node.list_channels_for_caller(&caller, filter_ch)?;
        return Ok(json_response(StatusCode::OK, &ChannelsResponse { channels }));
    }

    if method == Method::POST && path == "/v1/channels/join" {
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
        return Ok(json_response(
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
        ));
    }

    if method == Method::DELETE && path == "/v1/channels/members" {
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
        return Ok(json_response(StatusCode::OK, &json!({ "left": left })));
    }

    if method == Method::POST && path == "/v1/channels/post" {
        let post_req: ChannelPostRequest = serde_json::from_slice(&body_bytes)?;
        let res = node.handle_server_channel_post(&caller, post_req).await?;
        return Ok(json_response(StatusCode::OK, &res));
    }

    // /v1/channel-epochs
    if path == "/v1/channel-epochs" || path.starts_with("/v1/channel-epochs/") {
        return match method {
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
        };
    }

    // /v1/kv-epochs
    if path == "/v1/kv-epochs" || path.starts_with("/v1/kv-epochs/") {
        return match method {
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
                    node.db()
                        .kv()
                        .latest_epoch(node.node_id().as_str(), &ns)?
                };
                Ok(json_response(StatusCode::OK, &KvEpochResponse { epoch }))
            }
            _ => Err(NodeError::BadRequest("method not allowed".into())),
        };
    }

    // /v1/events
    if method == Method::POST && path == "/v1/events" {
        let pub_req: PublishEventRequest = serde_json::from_slice(&body_bytes)?;
        node.require_scope(
            &caller,
            caller.scopes.may_stream_publish(&pub_req.topic),
            &format!("stream:publish={}", pub_req.topic),
        )?;
        let res = node.ingest_inbound_event(&caller.peer_id, &pub_req.topic, &pub_req.event)?;
        return Ok(json_response(StatusCode::OK, &res));
    }

    // /v1/subscriptions
    if path == "/v1/subscriptions" {
        return match method {
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
                Ok(json_response(StatusCode::OK, &json!({ "deleted": deleted })))
            }
            _ => Err(NodeError::BadRequest("method not allowed".into())),
        };
    }

    // /v1/inbox/ack
    if method == Method::POST && path == "/v1/inbox/ack" {
        let ack_req: InboxAckRequest = serde_json::from_slice(&body_bytes)?;
        let now = now_ms();
        let acked = {
            let db = node.db();
            match ack_req.kind.as_str() {
                "message" => {
                    db.messages()
                        .ack(&caller.peer_id, &ack_req.id, &ack_req.outcome, now)?
                }
                "batch" => {
                    db.events()
                        .ack_batch(&caller.peer_id, &ack_req.id, &ack_req.outcome, now)?
                }
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
        node.clear_in_flight(
            &caller.peer_id,
            &format!("{}:{}", ack_req.kind, ack_req.id),
        );
        // Trigger immediate next-item push if more items are queued for this peer!
        node.notify_peer_inbox(&caller.peer_id);
        node.notify_scheduler();
        return Ok(json_response(StatusCode::OK, &InboxAckResponse { acked }));
    }

    // /v1/transfers/<id>
    if let Some(raw_id) = path.strip_prefix("/v1/transfers/") {
        let id = percent_decode(raw_id);
        return match method {
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
                let header_bytes = URL_SAFE_NO_PAD
                    .decode(header_b64)
                    .map_err(|_| NodeError::BadRequest("invalid transfer header base64url".into()))?;
                let header_json = String::from_utf8(header_bytes)
                    .map_err(|_| NodeError::BadRequest("transfer header is not valid UTF-8".into()))?;
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
                .ok_or_else(|| NodeError::NotFound(format!("transfer blob '{id}' not found")))?;
                Ok(bytes_response(
                    StatusCode::OK,
                    "application/octet-stream",
                    blob,
                ))
            }
            _ => Err(NodeError::BadRequest("method not allowed".into())),
        };
    }

    // /v1/kv/<namespace>[/<key...>]
    if let Some(rest) = path.strip_prefix("/v1/kv/") {
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
                            node.notify_all_inbox_subscribers();
                            node.notify_scheduler();
                            let etag = format_version_etag(set_res.entry.version);
                            Ok(json_response_with_etag(StatusCode::OK, &set_res.entry, &etag))
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
    }

    Err(NodeError::NotFound(format!("route '{method} {path}' not found")))
}

fn require_auth(
    node: &UnifiedNode,
    headers: &http::HeaderMap,
    method: &str,
    path_and_query: &str,
    body_sha256: &str,
) -> Result<AuthenticatedPeer, NodeError> {
    node.authenticate_request(headers, method, path_and_query, body_sha256)?
        .ok_or_else(|| NodeError::Unauthorized("missing Authorization header".into()))
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
        if *shutdown_rx.borrow() {
            return;
        }

        // Reset stale in-flight entries when peer reconnects so unacked items redeliver cleanly!
        node.clear_all_in_flight_for_peer(&peer_id);

        let _ = tx.send(Ok(Frame::data(Bytes::from_static(b": connected\n\n")))).await;

        let mut keepalive = tokio::time::interval(SSE_KEEPALIVE_INTERVAL);
        keepalive.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        keepalive.tick().await; // consume immediate first tick

        loop {
            if *shutdown_rx.borrow() {
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
                    if tx.send(Ok(Frame::data(sse_keepalive_frame()))).await.is_err() {
                        break;
                    }
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
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
