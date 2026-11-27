//! Outbound `PeerLink` HTTP/SSE client, shared wire DTOs, authenticated request signing
//! (Bearer & Ed25519), and crash-safe commit-before-ack WHATWG SSE `/v1/inbox` consumer.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, ETAG, IF_MATCH, IF_NONE_MATCH};
use http::{HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use hyp_crypto::e2ee::SignedEpochKeyBundle;
use hyp_crypto::human::HumanInviteClaimV1;
use hyp_crypto::{NodeIdentityKeys, OkpJwk as CryptoOkpJwk, SignedPayload};
use hyp_proto::address::NodeId;
use hyp_proto::cloudevent::CloudEvent as ProtoCloudEvent;
use hyp_proto::filter::{Filter as ProtoFilter, SubscriptionDiagnostic};
use hyp_proto::manifest::{NegotiatedSession, SignedNodeManifest};
use hyp_store::{
    AckOutcome, ChannelEpoch, DeliveryMode, DueBatch, HandleRecord, IngestResult, KvDeleteResult,
    KvEntry, KvEpoch, MessageRecord, PostChannelResult, Subscription, TransferRecord, WriteModel,
    now_ms,
};

use crate::engine::config::{ChannelMode, NodeError};
use crate::engine::http_util::{
    BoxedBody, HttpClient, SseParser, empty_body, format_version_etag, full_body,
    parse_retry_after_ms, percent_encode,
};
use crate::engine::node::{KvInspection, KvKeyPage, UnifiedNode};

/// Default maximum response size for JSON control endpoints (4 MiB).
pub const MAX_JSON_RESPONSE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum transfer blob download size (256 MiB + 64 KiB framing headroom).
pub const MAX_TRANSFER_DOWNLOAD_BYTES: usize = 256 * 1024 * 1024 + 64 * 1024;

// ============================================================================
// Shared HTTP Wire DTOs (Client <-> Server)
// ============================================================================

/// Canonical v2 Admin-CA binding payload signed with both pairing key and node signing key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairBindingV2 {
    pub v: u8,
    pub grant_id: String,
    pub node_id: String,
    pub signing_jwk: CryptoOkpJwk,
    pub encryption_jwk: CryptoOkpJwk,
    pub bound_at: String,
}

/// Request sent to `POST /v1/pair` for Org Admin-CA (`am2_`) pairing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairRequestV2 {
    pub grant_id: String,
    /// RFC 8785 JCS canonical JSON of `PairBindingV2`.
    pub payload: String,
    /// Base64url Ed25519 signature by one-time pairing key over `"hyphae/v2/binding\n" || payload`.
    pub pairing_sig: String,
    /// Base64url Ed25519 signature by node signing key over `"hyphae/v2/binding-self\n" || payload`.
    pub self_sig: String,
}

/// Supports both Hub-local grants and inline offline Admin-CA grants.
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AdminPairRequestEnvelope {
    #[serde(flatten)]
    pub(crate) base: PairRequestV2,
    #[serde(
        default,
        alias = "signedGrantV2",
        skip_serializing_if = "Option::is_none"
    )]
    pub(crate) signed_grant: Option<SignedPayload>,
}

/// Server reply to `POST /v1/pair`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PairServerReply {
    pub node_id: String,
    pub grant: SignedPayload,
    pub auth_credential: String,
    pub signed_manifest: SignedNodeManifest,
}

/// Server reply to `POST /v1/p2p/pair/<offerId>` (§4.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct P2pPairServerReply {
    pub offer_id: String,
    pub alice_grant_to_bob: SignedPayload,
    pub auth_credential: String,
    pub signed_manifest: SignedNodeManifest,
}

/// Self-service guest-ro pairing request for `POST /v1/guest/pair`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuestPairRequest {
    pub node_id: String,
    pub ed25519_jwk: CryptoOkpJwk,
    pub x25519_jwk: CryptoOkpJwk,
    pub timestamp: String,
    pub proof_sig: String,
}

/// Canonical RFC 8785 JCS proof payload signed under domain `"guest-pair"` for `POST /v1/guest/pair`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GuestPairProofPayload<'a> {
    pub ed25519_jwk: &'a CryptoOkpJwk,
    pub hub_node_id: &'a str,
    pub node_id: &'a str,
    pub timestamp: &'a str,
    pub x25519_jwk: &'a CryptoOkpJwk,
}

/// Computes the canonical RFC 8785 JCS bytes signed under domain `"guest-pair"`.
pub fn guest_pair_proof_canonical(
    hub_node_id: &str,
    node_id: &str,
    ed25519_jwk: &CryptoOkpJwk,
    x25519_jwk: &CryptoOkpJwk,
    timestamp: &str,
) -> Result<String, hyp_crypto::CryptoError> {
    let payload = GuestPairProofPayload {
        ed25519_jwk,
        hub_node_id,
        node_id,
        timestamp,
        x25519_jwk,
    };
    hyp_crypto::jcs::to_canonical_json(&payload)
}

/// Server reply to `POST /v1/guest/pair`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GuestPairReply {
    pub ok: bool,
    pub node_id: String,
    pub peer_id: String,
    pub preset: String,
    pub scopes: Vec<String>,
    pub manifest: SignedNodeManifest,
}

/// Request sent to `POST /v1/auth/claim` to claim a single-use Admin-CA `hjoin1_` human invite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthClaimRequest {
    pub hjoin1: String,
    pub claim: HumanInviteClaimV1,
    pub claim_sig: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

/// Server reply to `POST /v1/auth/claim`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthClaimReply {
    pub ok: bool,
    pub hub_node_id: String,
    pub human_id: String,
    pub kid: String,
    pub fingerprint: String,
    pub node_prefix: String,
    pub scopes: Vec<String>,
    pub max_devices: u32,
}

/// Request sent to `POST /v1/pair/delegated` using a human-signed `hcert1_` NodeCert + live device proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegatedPairRequest {
    pub node_id: String,
    pub ed25519_jwk: CryptoOkpJwk,
    pub x25519_jwk: CryptoOkpJwk,
    pub node_cert: String,
    pub timestamp: String,
    pub proof_sig: String,
}

/// Server reply to `POST /v1/pair/delegated`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegatedPairReply {
    pub ok: bool,
    pub node_id: String,
    pub peer_id: String,
    pub human_id: String,
    pub auth_epoch: u64,
    pub scopes: Vec<String>,
    pub auth_credential: String,
    pub signed_manifest: SignedNodeManifest,
}

/// Entry in the `GET /v1/keys` peer key directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerKeyDirectoryEntry {
    pub node_id: String,
    pub signing_jwk: CryptoOkpJwk,
    pub encryption_jwk: CryptoOkpJwk,
    pub kid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerKeysResponse {
    pub keys: Vec<PeerKeyDirectoryEntry>,
}

/// Self-signed key registration payload for `PUT /v1/keys`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyRegPayloadV2 {
    pub v: u8,
    pub node_id: String,
    pub signing_jwk: CryptoOkpJwk,
    pub encryption_jwk: CryptoOkpJwk,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutKeyRequest {
    pub signing_jwk: CryptoOkpJwk,
    pub encryption_jwk: CryptoOkpJwk,
    pub proof: SignedPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutHandlesRequest {
    pub handles: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub descriptions: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HandlesResponse {
    pub handles: Vec<HandleRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostMessageRequest {
    pub id: String,
    pub from_handle: String,
    pub to: String,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e2ee_epoch: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostMessageResponse {
    pub id: String,
    pub deduplicated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelJoinRequest {
    pub channel: String,
    pub handle: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelLeaveRequest {
    pub channel: String,
    pub handle: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelPostRequest {
    pub id: String,
    pub channel: String,
    pub from_handle: String,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e2ee_epoch: Option<u64>,
}

/// Caller-scoped channel discovery entry returned by `GET /v1/channels`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelDirectoryEntry {
    pub host_node: String,
    pub channel: String,
    pub members: Vec<String>,
    pub mode: ChannelMode,
    #[serde(default)]
    pub writers: Vec<String>,
    pub can_post: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelsResponse {
    pub channels: Vec<ChannelDirectoryEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelJoinResponse {
    pub host_node: String,
    pub channel: String,
    pub address: String,
    pub members: Vec<String>,
    pub mode: ChannelMode,
    #[serde(default)]
    pub writers: Vec<String>,
    pub can_post: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutChannelEpochRequest {
    pub channel: String,
    pub epoch: u64,
    pub bundle: SignedEpochKeyBundle,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelEpochResponse {
    pub epoch: Option<ChannelEpoch>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutKvEpochRequest {
    pub namespace: String,
    pub epoch: u64,
    pub bundle: SignedEpochKeyBundle,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KvEpochResponse {
    pub epoch: Option<KvEpoch>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublishEventRequest {
    pub topic: String,
    pub event: ProtoCloudEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionInputWire {
    pub id: String,
    pub topic: String,
    pub filters: Vec<ProtoFilter>,
    pub coalesce_seconds: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_batch_age_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_wakes_per_hour: Option<usize>,
    pub mode: DeliveryMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutSubscriptionsRequest {
    pub subscriptions: Vec<SubscriptionInputWire>,
    /// If set, replaces all subscriptions for this caller on `replace_topic`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replace_topic: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PutSubscriptionsResponse {
    pub subscriptions: Vec<Subscription>,
    pub diagnostics: Vec<SubscriptionDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionsResponse {
    pub subscriptions: Vec<Subscription>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboxAckRequest {
    /// `"message"`, `"batch"`, or `"transfer"`.
    pub kind: String,
    pub id: String,
    pub outcome: AckOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboxAckResponse {
    pub acked: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KvSetBody {
    pub value: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    pub write_model: WriteModel,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowlist: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e2ee_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub clear_ttl: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KvDeleteBody {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KvListResponse {
    pub entries: Vec<KvEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferUploadResponse {
    pub id: String,
    pub sha256: String,
    pub size: u64,
    pub deduplicated: bool,
}

/// Outcome of fetching `GET /v1/manifest` from a peer.
#[derive(Debug, Clone)]
pub enum ManifestFetchOutcome {
    NotModified,
    Signed {
        manifest: SignedNodeManifest,
        etag: Option<String>,
    },
}

// ============================================================================
// Peer Authentication & Outbound `PeerLink` Client
// ============================================================================

/// Outbound authentication mechanism used by `PeerLink`.
#[derive(Clone)]
pub enum PeerAuth {
    /// Opaque 256-bit bearer token issued by peer during `am2_` or `hp2p1_` pairing.
    Bearer(Arc<Zeroizing<String>>),
    /// Per-request Ed25519 signature verified against our pinned signing JWK on the remote peer.
    Ed25519,
}

impl PeerAuth {
    /// Compares two authentication configurations without logging or exposing bearer secrets.
    pub fn matches(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Ed25519, Self::Ed25519) => true,
            (Self::Bearer(a), Self::Bearer(b)) => a.as_str() == b.as_str(),
            _ => false,
        }
    }
}

impl std::fmt::Debug for PeerAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bearer(_) => f.write_str("PeerAuth::Bearer([REDACTED])"),
            Self::Ed25519 => f.write_str("PeerAuth::Ed25519"),
        }
    }
}

/// Canonical HTTP authentication transcript, retained at its existing public path.
pub use hyp_crypto::http_auth::http_auth_signing_input;

/// Outbound HTTP/SSE link to a single remote Hyphae `Node` (Hub, Public Node, or Direct P2P peer).
pub struct PeerLink {
    peer_id: String,
    endpoint: String,
    self_node_id: NodeId,
    identity: Arc<NodeIdentityKeys>,
    auth: PeerAuth,
    client: HttpClient,
    negotiated: Mutex<Option<NegotiatedSession>>,
}

impl std::fmt::Debug for PeerLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerLink")
            .field("peer_id", &self.peer_id)
            .field("endpoint", &self.endpoint)
            .field("auth", &self.auth)
            .finish()
    }
}

impl PeerLink {
    pub fn new(
        peer_id: impl Into<String>,
        endpoint: impl Into<String>,
        self_node_id: NodeId,
        identity: Arc<NodeIdentityKeys>,
        auth: PeerAuth,
        client: HttpClient,
    ) -> Self {
        let ep = endpoint.into().trim_end_matches('/').to_string();
        Self {
            peer_id: peer_id.into(),
            endpoint: ep,
            self_node_id,
            identity,
            auth,
            client,
            negotiated: Mutex::new(None),
        }
    }

    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn auth(&self) -> &PeerAuth {
        &self.auth
    }

    pub fn set_negotiated(&self, session: NegotiatedSession) {
        *self.negotiated.lock().expect("negotiated lock poisoned") = Some(session);
    }

    pub fn negotiated(&self) -> Option<NegotiatedSession> {
        self.negotiated
            .lock()
            .expect("negotiated lock poisoned")
            .clone()
    }

    fn build_request(
        &self,
        method: Method,
        path_and_query: &str,
        body_bytes: Option<Bytes>,
        content_type: Option<&str>,
    ) -> Result<Request<BoxedBody>, NodeError> {
        let body_sha = match &body_bytes {
            Some(b) => hex::encode(Sha256::digest(b)),
            None => hex::encode(Sha256::digest(b"")),
        };

        let uri_str = if self.endpoint.starts_with("ssh://") {
            path_and_query.to_string()
        } else {
            format!("{}{}", self.endpoint, path_and_query)
        };

        let mut builder = Request::builder().method(method.clone()).uri(&uri_str);
        if let Some(ct) = content_type {
            builder = builder.header(CONTENT_TYPE, ct);
        }

        let auth_header = match &self.auth {
            PeerAuth::Bearer(tok) => format!("Bearer {}", tok.as_str()),
            PeerAuth::Ed25519 => {
                let ts = now_ms();
                let mut nonce_bytes = [0u8; 12];
                let rng = SystemRandom::new();
                rng.fill(&mut nonce_bytes)
                    .map_err(|_| NodeError::Http("CSPRNG failure generating auth nonce".into()))?;
                let nonce = hex::encode(nonce_bytes);
                hyp_crypto::http_auth::sign_http_auth(
                    self.self_node_id.as_str(),
                    &self.identity.signing,
                    method.as_str(),
                    path_and_query,
                    ts,
                    &nonce,
                    &body_sha,
                )
            }
        };
        builder = builder.header(AUTHORIZATION, auth_header);
        builder = builder.header("x-hyphae-node", self.self_node_id.as_str());

        let body = match body_bytes {
            Some(b) => full_body(b),
            None => empty_body(),
        };
        builder
            .body(body)
            .map_err(|e| NodeError::Http(format!("failed to build request: {e}")))
    }

    async fn send_json<Req: Serialize, Resp: serde::de::DeserializeOwned>(
        &self,
        method: Method,
        path_and_query: &str,
        body: Option<&Req>,
        extra_headers: &[(&str, &str)],
    ) -> Result<Resp, NodeError> {
        let payload = match body {
            Some(b) => Some(Bytes::from(serde_json::to_vec(b)?)),
            None => None,
        };
        let ct = if payload.is_some() {
            Some("application/json")
        } else {
            None
        };
        let mut req = self.build_request(method, path_and_query, payload, ct)?;
        for &(k, v) in extra_headers {
            let name = http::header::HeaderName::from_bytes(k.as_bytes())
                .map_err(|e| NodeError::Http(format!("invalid header name '{k}': {e}")))?;
            let val = HeaderValue::from_str(v)
                .map_err(|e| NodeError::Http(format!("invalid header value for '{k}': {e}")))?;
            req.headers_mut().insert(name, val);
        }

        let resp = self
            .client
            .request_for_endpoint(&self.endpoint, req)
            .await?;
        let (status, _headers, bytes) = HttpClient::collect(resp, MAX_JSON_RESPONSE_BYTES).await?;
        if !status.is_success() {
            return Err(HttpClient::decode_error_response(status, &bytes));
        }
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Fetches `GET /v1/manifest` (with optional RFC 9110 `If-None-Match` ETag),
    /// rejecting missing manifests through the ordinary HTTP error path.
    pub async fn fetch_manifest(
        &self,
        if_none_match: Option<&str>,
    ) -> Result<ManifestFetchOutcome, NodeError> {
        let mut req = self.build_request(Method::GET, "/v1/manifest", None, None)?;
        if let Some(etag) = if_none_match {
            if let Ok(val) = HeaderValue::from_str(etag) {
                req.headers_mut().insert(IF_NONE_MATCH, val);
            }
        }
        let resp = self
            .client
            .request_for_endpoint(&self.endpoint, req)
            .await?;
        let (status, headers, bytes) = HttpClient::collect(resp, MAX_JSON_RESPONSE_BYTES).await?;
        if status == StatusCode::NOT_MODIFIED {
            return Ok(ManifestFetchOutcome::NotModified);
        }
        if !status.is_success() {
            return Err(HttpClient::decode_error_response(status, &bytes));
        }
        let manifest: SignedNodeManifest = serde_json::from_slice(&bytes)?;
        let etag = headers
            .get(ETAG)
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);
        Ok(ManifestFetchOutcome::Signed { manifest, etag })
    }

    pub async fn get_keys(&self, node_id: Option<&str>) -> Result<PeerKeysResponse, NodeError> {
        let path = match node_id {
            Some(id) => format!("/v1/keys?nodeId={}", percent_encode(id)),
            None => "/v1/keys".to_string(),
        };
        self.send_json::<(), _>(Method::GET, &path, None, &[]).await
    }

    pub async fn get_kv_member_keys(&self, namespace: &str) -> Result<PeerKeysResponse, NodeError> {
        let path = format!("/v1/keys?kvNamespace={}", percent_encode(namespace));
        self.send_json::<(), _>(Method::GET, &path, None, &[]).await
    }

    pub async fn put_handles_with_descriptions(
        &self,
        handles: &[String],
        descriptions: &BTreeMap<String, String>,
    ) -> Result<HandlesResponse, NodeError> {
        let body = PutHandlesRequest {
            handles: handles.to_vec(),
            descriptions: descriptions.clone(),
        };
        self.send_json(Method::PUT, "/v1/handles", Some(&body), &[])
            .await
    }

    pub async fn get_handles(&self, node_id: Option<&str>) -> Result<HandlesResponse, NodeError> {
        let path = match node_id {
            Some(id) => format!("/v1/handles?nodeId={}", percent_encode(id)),
            None => "/v1/handles".to_string(),
        };
        self.send_json::<(), _>(Method::GET, &path, None, &[]).await
    }

    pub async fn post_message(
        &self,
        req: &PostMessageRequest,
    ) -> Result<PostMessageResponse, NodeError> {
        self.send_json(Method::POST, "/v1/messages", Some(req), &[])
            .await
    }

    pub async fn join_channel(
        &self,
        channel: &str,
        handle: &str,
    ) -> Result<ChannelJoinResponse, NodeError> {
        let body = ChannelJoinRequest {
            channel: channel.to_string(),
            handle: handle.to_string(),
        };
        self.send_json(Method::POST, "/v1/channels/join", Some(&body), &[])
            .await
    }

    pub async fn leave_channel(&self, channel: &str, handle: &str) -> Result<bool, NodeError> {
        let body = ChannelLeaveRequest {
            channel: channel.to_string(),
            handle: handle.to_string(),
        };
        let resp: serde_json::Value = self
            .send_json(Method::DELETE, "/v1/channels/members", Some(&body), &[])
            .await?;
        Ok(resp.get("left").and_then(|v| v.as_bool()).unwrap_or(false))
    }

    pub async fn list_channels(
        &self,
        channel: Option<&str>,
    ) -> Result<ChannelsResponse, NodeError> {
        let path = match channel {
            Some(ch) => format!("/v1/channels?channel={}", percent_encode(ch)),
            None => "/v1/channels".to_string(),
        };
        self.send_json::<(), _>(Method::GET, &path, None, &[]).await
    }

    pub async fn post_channel(
        &self,
        req: &ChannelPostRequest,
    ) -> Result<PostChannelResult, NodeError> {
        self.send_json(Method::POST, "/v1/channels/post", Some(req), &[])
            .await
    }

    pub async fn put_channel_epoch(
        &self,
        req: &PutChannelEpochRequest,
    ) -> Result<ChannelEpoch, NodeError> {
        self.send_json(Method::POST, "/v1/channel-epochs", Some(req), &[])
            .await
    }

    pub async fn get_channel_epoch(
        &self,
        channel: &str,
        epoch: Option<u64>,
    ) -> Result<Option<ChannelEpoch>, NodeError> {
        let mut path = format!("/v1/channel-epochs?channel={}", percent_encode(channel));
        if let Some(ep) = epoch {
            path.push_str(&format!("&epoch={ep}"));
        }
        let resp: ChannelEpochResponse = self
            .send_json::<(), _>(Method::GET, &path, None, &[])
            .await?;
        Ok(resp.epoch)
    }

    pub async fn put_kv_epoch(&self, req: &PutKvEpochRequest) -> Result<KvEpoch, NodeError> {
        self.send_json(Method::POST, "/v1/kv-epochs", Some(req), &[])
            .await
    }

    pub async fn get_kv_epoch(
        &self,
        namespace: &str,
        epoch: Option<u64>,
    ) -> Result<Option<KvEpoch>, NodeError> {
        let mut path = format!("/v1/kv-epochs?namespace={}", percent_encode(namespace));
        if let Some(ep) = epoch {
            path.push_str(&format!("&epoch={ep}"));
        }
        let resp: KvEpochResponse = self
            .send_json::<(), _>(Method::GET, &path, None, &[])
            .await?;
        Ok(resp.epoch)
    }

    pub async fn publish_event(
        &self,
        req: &PublishEventRequest,
    ) -> Result<IngestResult, NodeError> {
        self.send_json(Method::POST, "/v1/events", Some(req), &[])
            .await
    }

    pub async fn put_subscriptions(
        &self,
        req: &PutSubscriptionsRequest,
    ) -> Result<PutSubscriptionsResponse, NodeError> {
        self.send_json(Method::PUT, "/v1/subscriptions", Some(req), &[])
            .await
    }

    pub async fn delete_subscription(&self, id: &str) -> Result<bool, NodeError> {
        let path = format!("/v1/subscriptions?id={}", percent_encode(id));
        let resp: serde_json::Value = self
            .send_json::<(), _>(Method::DELETE, &path, None, &[])
            .await?;
        Ok(resp
            .get("deleted")
            .and_then(|v| v.as_bool())
            .unwrap_or(false))
    }

    pub async fn list_subscriptions(&self) -> Result<SubscriptionsResponse, NodeError> {
        self.send_json::<(), _>(Method::GET, "/v1/subscriptions", None, &[])
            .await
    }

    pub async fn kv_set(
        &self,
        namespace: &str,
        key: &str,
        body: &KvSetBody,
        if_match_version: Option<u64>,
    ) -> Result<KvEntry, NodeError> {
        let path = format!(
            "/v1/kv/{}/{}",
            percent_encode(namespace),
            encode_kv_key_path(key)
        );
        let etag_owned = if_match_version.map(format_version_etag);
        let mut headers = Vec::new();
        if let Some(ref etag) = etag_owned {
            headers.push((IF_MATCH.as_str(), etag.as_str()));
        }
        self.send_json(Method::PUT, &path, Some(body), &headers)
            .await
    }

    pub async fn kv_get(&self, namespace: &str, key: &str) -> Result<Option<KvEntry>, NodeError> {
        let path = format!(
            "/v1/kv/{}/{}",
            percent_encode(namespace),
            encode_kv_key_path(key)
        );
        match self
            .send_json::<(), KvEntry>(Method::GET, &path, None, &[])
            .await
        {
            Ok(entry) => Ok(Some(entry)),
            Err(NodeError::RemoteProblem(p)) if p.status == 404 => Ok(None),
            Err(err) => Err(err),
        }
    }

    pub async fn kv_delete(
        &self,
        namespace: &str,
        key: &str,
        expected_version: Option<u64>,
    ) -> Result<KvDeleteResult, NodeError> {
        let path = format!(
            "/v1/kv/{}/{}",
            percent_encode(namespace),
            encode_kv_key_path(key)
        );
        let body = KvDeleteBody { expected_version };
        let etag_owned = expected_version.map(format_version_etag);
        let mut headers = Vec::new();
        if let Some(ref etag) = etag_owned {
            headers.push((IF_MATCH.as_str(), etag.as_str()));
        }
        self.send_json(Method::DELETE, &path, Some(&body), &headers)
            .await
    }

    pub(crate) async fn kv_inspect(&self) -> Result<KvInspection, NodeError> {
        self.send_json::<(), _>(Method::GET, "/v1/kv-metadata", None, &[])
            .await
    }

    pub(crate) async fn kv_keys(
        &self,
        namespace: &str,
        after: Option<&str>,
    ) -> Result<KvKeyPage, NodeError> {
        let mut path = format!("/v1/kv-metadata?namespace={}", percent_encode(namespace));
        if let Some(after) = after {
            path.push_str("&after=");
            path.push_str(&percent_encode(after));
        }
        self.send_json::<(), _>(Method::GET, &path, None, &[]).await
    }

    pub(crate) async fn kv_preview(
        &self,
        namespace: &str,
        key: &str,
    ) -> Result<Option<KvEntry>, NodeError> {
        let path = format!(
            "/v1/kv-metadata?namespace={}&key={}",
            percent_encode(namespace),
            percent_encode(key),
        );
        self.send_json::<(), _>(Method::GET, &path, None, &[]).await
    }

    pub async fn kv_list(
        &self,
        namespace: &str,
        prefix: Option<&str>,
    ) -> Result<Vec<KvEntry>, NodeError> {
        let mut path = format!("/v1/kv/{}", percent_encode(namespace));
        if let Some(p) = prefix {
            path.push_str(&format!("?prefix={}", percent_encode(p)));
        }
        let resp: KvListResponse = self
            .send_json::<(), _>(Method::GET, &path, None, &[])
            .await?;
        Ok(resp.entries)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn upload_transfer(
        &self,
        id: &str,
        to_node: &str,
        to_handle: Option<&str>,
        transfer_type: &str,
        header_json: &str,
        sha256_hex: &str,
        ciphertext: Bytes,
    ) -> Result<TransferUploadResponse, NodeError> {
        let path = format!("/v1/transfers/{}", percent_encode(id));
        let mut req = self.build_request(
            Method::PUT,
            &path,
            Some(ciphertext),
            Some("application/octet-stream"),
        )?;
        let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
        req.headers_mut().insert(
            "x-hyphae-transfer-to",
            HeaderValue::from_str(to_node)
                .map_err(|e| NodeError::BadRequest(format!("invalid to_node header: {e}")))?,
        );
        req.headers_mut().insert(
            "x-hyphae-transfer-type",
            HeaderValue::from_str(transfer_type)
                .map_err(|e| NodeError::BadRequest(format!("invalid transfer_type header: {e}")))?,
        );
        req.headers_mut().insert(
            "x-hyphae-transfer-header",
            HeaderValue::from_str(&header_b64)
                .map_err(|e| NodeError::BadRequest(format!("invalid transfer header: {e}")))?,
        );
        req.headers_mut().insert(
            "x-hyphae-sha256",
            HeaderValue::from_str(sha256_hex)
                .map_err(|e| NodeError::BadRequest(format!("invalid sha256 header: {e}")))?,
        );
        if let Some(h) = to_handle {
            if let Ok(v) = HeaderValue::from_str(h) {
                req.headers_mut().insert("x-hyphae-transfer-to-handle", v);
            }
        }

        let resp = self
            .client
            .request_for_endpoint(&self.endpoint, req)
            .await?;
        let (status, _headers, bytes) = HttpClient::collect(resp, MAX_JSON_RESPONSE_BYTES).await?;
        if !status.is_success() {
            return Err(HttpClient::decode_error_response(status, &bytes));
        }
        Ok(serde_json::from_slice(&bytes)?)
    }

    pub async fn download_transfer(&self, id: &str) -> Result<Bytes, NodeError> {
        let path = format!("/v1/transfers/{}", percent_encode(id));
        let req = self.build_request(Method::GET, &path, None, None)?;
        let resp = self
            .client
            .request_for_endpoint(&self.endpoint, req)
            .await?;
        let (status, _headers, bytes) =
            HttpClient::collect(resp, MAX_TRANSFER_DOWNLOAD_BYTES).await?;
        if !status.is_success() {
            return Err(HttpClient::decode_error_response(status, &bytes));
        }
        Ok(bytes)
    }

    pub async fn ack_inbox(&self, req: &InboxAckRequest) -> Result<bool, NodeError> {
        let resp: InboxAckResponse = self
            .send_json(Method::POST, "/v1/inbox/ack", Some(req), &[])
            .await?;
        Ok(resp.acked)
    }

    pub async fn open_inbox_sse(
        &self,
        last_event_id: Option<&str>,
    ) -> Result<Response<Incoming>, NodeError> {
        self.open_inbox_sse_cancellable(last_event_id, None).await
    }

    pub(crate) async fn open_inbox_sse_cancellable(
        &self,
        last_event_id: Option<&str>,
        cancel_rx: Option<tokio::sync::oneshot::Receiver<()>>,
    ) -> Result<Response<Incoming>, NodeError> {
        let mut req = self.build_request(Method::GET, "/v1/inbox", None, None)?;
        req.headers_mut()
            .insert(ACCEPT, HeaderValue::from_static("text/event-stream"));
        if let Some(id) = last_event_id {
            if let Ok(val) = HeaderValue::from_str(id) {
                req.headers_mut().insert("last-event-id", val);
            }
        }
        self.client
            .request_stream_for_endpoint(&self.endpoint, req, cancel_rx)
            .await
    }
}

fn encode_kv_key_path(key: &str) -> String {
    key.split('/')
        .map(percent_encode)
        .collect::<Vec<_>>()
        .join("/")
}

const SSE_INITIAL_BACKOFF_MS: u64 = 50;
const SSE_MAX_BACKOFF_MS: u64 = 5_000;
const SSE_AUTH_INITIAL_BACKOFF_MS: u64 = 2_000;
const SSE_AUTH_MAX_BACKOFF_MS: u64 = 60_000;
const MAX_SSE_ERROR_BODY_BYTES: usize = 16 * 1024;

fn is_permanent_sse_auth_denial(status: StatusCode, body: &[u8]) -> bool {
    if status != StatusCode::FORBIDDEN {
        return false;
    }
    let text = String::from_utf8_lossy(body).to_ascii_lowercase();
    text.contains("revoked")
        || text.contains("not_granted")
        || text.contains("not-granted")
        || text.contains("scope_denied")
        || text.contains("not active")
        || text.contains("all grants for peer")
}

async fn wait_for_wake(wake_rx: &mut watch::Receiver<u64>) {
    if wake_rx.changed().await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// Spawns a background WHATWG SSE `/v1/inbox` worker for `link` with crash-safe
/// commit-before-ack semantics and exponential backoff reconnect.
///
/// Security / resilience (P1-20, Issue #29):
/// - On HTTP `403` with a permanent revocation or `not_granted` denial body, stops polling
///   until the next `reconcile_peers` or node restart.
/// - On HTTP `401` or other `403`, applies strong exponential backoff (`2s .. 60s`) instead of
///   tight-loop retrying.
/// - On host sleep/wake (`node.subscribe_wake_epoch()`), immediately aborts any active
///   half-open HTTP/SSE stream or backoff sleep, resets exponential backoff, and reconnects
///   right away to pull missed messages and flush pending outbox.
/// - On malformed SSE item JSON, logs and skips cleanly (best-effort reject-ack if an event ID
///   is available) without stalling the stream.
pub fn spawn_sse_worker(
    node: Arc<UnifiedNode>,
    link: Arc<PeerLink>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> JoinHandle<()> {
    let mut wake_rx = node.subscribe_wake_epoch();
    tokio::spawn(async move {
        let mut backoff_ms = SSE_INITIAL_BACKOFF_MS;
        let mut auth_backoff_ms = SSE_AUTH_INITIAL_BACKOFF_MS;
        let mut last_event_id: Option<String> = None;

        loop {
            if *shutdown_rx.borrow() {
                break;
            }

            let (stream_cancel_tx, stream_cancel_rx) = tokio::sync::oneshot::channel::<()>();
            let connect_res = tokio::select! {
                biased;
                _ = shutdown_rx.changed() => {
                    let _ = stream_cancel_tx.send(());
                    if *shutdown_rx.borrow() { break; }
                    continue;
                }
                _ = wait_for_wake(&mut wake_rx) => {
                    let _ = stream_cancel_tx.send(());
                    backoff_ms = SSE_INITIAL_BACKOFF_MS;
                    auth_backoff_ms = SSE_AUTH_INITIAL_BACKOFF_MS;
                    continue;
                }
                res = link.open_inbox_sse_cancellable(last_event_id.as_deref(), Some(stream_cancel_rx)) => res,
            };

            match connect_res {
                Ok(resp) if resp.status() == StatusCode::OK => {
                    backoff_ms = SSE_INITIAL_BACKOFF_MS;
                    auth_backoff_ms = SSE_AUTH_INITIAL_BACKOFF_MS;
                    // Promptly wake local peer inbox & scheduler on link connect/reconnect.
                    node.notify_peer_inbox(link.peer_id());
                    node.notify_scheduler();
                    let mut body = resp.into_body();
                    let mut parser = SseParser::new();

                    let mut wake_triggered = false;
                    loop {
                        let next_frame = tokio::select! {
                            biased;
                            _ = shutdown_rx.changed() => {
                                if *shutdown_rx.borrow() {
                                    let _ = stream_cancel_tx.send(());
                                    return;
                                }
                                continue;
                            }
                            _ = wait_for_wake(&mut wake_rx) => {
                                let _ = stream_cancel_tx.send(());
                                backoff_ms = SSE_INITIAL_BACKOFF_MS;
                                auth_backoff_ms = SSE_AUTH_INITIAL_BACKOFF_MS;
                                wake_triggered = true;
                                break;
                            }
                            frame = body.frame() => frame,
                        };

                        match next_frame {
                            Some(Ok(frame)) => {
                                if let Some(data) = frame.data_ref() {
                                    for ev in parser.feed(data) {
                                        if let Some(id) = ev.id.clone() {
                                            last_event_id = Some(id);
                                        }
                                        dispatch_sse_event(
                                            &node,
                                            &link,
                                            ev.event.as_deref(),
                                            ev.id.as_deref(),
                                            &ev.data,
                                        )
                                        .await;
                                    }
                                }
                            }
                            Some(Err(_)) | None => break,
                        }
                    }
                    drop(body);
                    if wake_triggered {
                        continue;
                    }
                }
                Ok(resp)
                    if resp.status() == StatusCode::UNAUTHORIZED
                        || resp.status() == StatusCode::FORBIDDEN =>
                {
                    let status = resp.status();
                    let retry_hdr = parse_retry_after_ms(resp.headers());
                    let body_bytes = match HttpClient::collect(resp, MAX_SSE_ERROR_BODY_BYTES).await
                    {
                        Ok((_st, _hdrs, bytes)) => bytes,
                        Err(_) => Bytes::new(),
                    };
                    if is_permanent_sse_auth_denial(status, &body_bytes) {
                        eprintln!(
                            "hyphae: stopping SSE worker for peer '{}' after permanent HTTP {} denial",
                            link.peer_id(),
                            status.as_u16()
                        );
                        break;
                    }
                    let wait_ms = retry_hdr
                        .unwrap_or(auth_backoff_ms)
                        .max(auth_backoff_ms)
                        .min(SSE_AUTH_MAX_BACKOFF_MS);
                    let wait = Duration::from_millis(wait_ms);
                    let mut woke = false;
                    tokio::select! {
                        biased;
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() { break; }
                        }
                        _ = wait_for_wake(&mut wake_rx) => {
                            backoff_ms = SSE_INITIAL_BACKOFF_MS;
                            auth_backoff_ms = SSE_AUTH_INITIAL_BACKOFF_MS;
                            woke = true;
                        }
                        _ = tokio::time::sleep(wait) => {}
                    }
                    if woke {
                        continue;
                    }
                    auth_backoff_ms =
                        (auth_backoff_ms.saturating_mul(2)).min(SSE_AUTH_MAX_BACKOFF_MS);
                }
                Ok(resp) => {
                    let retry_ms = parse_retry_after_ms(resp.headers()).unwrap_or(backoff_ms);
                    let wait = Duration::from_millis(retry_ms.min(SSE_MAX_BACKOFF_MS));
                    let mut woke = false;
                    tokio::select! {
                        biased;
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() { break; }
                        }
                        _ = wait_for_wake(&mut wake_rx) => {
                            backoff_ms = SSE_INITIAL_BACKOFF_MS;
                            auth_backoff_ms = SSE_AUTH_INITIAL_BACKOFF_MS;
                            woke = true;
                        }
                        _ = tokio::time::sleep(wait) => {}
                    }
                    if woke {
                        continue;
                    }
                    backoff_ms = (backoff_ms * 2).min(SSE_MAX_BACKOFF_MS);
                }
                Err(_) => {
                    let wait = Duration::from_millis(backoff_ms);
                    let mut woke = false;
                    tokio::select! {
                        biased;
                        _ = shutdown_rx.changed() => {
                            if *shutdown_rx.borrow() { break; }
                        }
                        _ = wait_for_wake(&mut wake_rx) => {
                            backoff_ms = SSE_INITIAL_BACKOFF_MS;
                            auth_backoff_ms = SSE_AUTH_INITIAL_BACKOFF_MS;
                            woke = true;
                        }
                        _ = tokio::time::sleep(wait) => {}
                    }
                    if woke {
                        continue;
                    }
                    backoff_ms = (backoff_ms * 2).min(SSE_MAX_BACKOFF_MS);
                }
            }
        }
    })
}

async fn reject_malformed_sse_item(
    link: &Arc<PeerLink>,
    kind: &str,
    event_id: Option<&str>,
    err: &serde_json::Error,
) {
    eprintln!(
        "hyphae: skipping malformed SSE '{kind}' item from peer '{}': {err}",
        link.peer_id()
    );
    let prefix = format!("{kind}:");
    if let Some(raw_id) = event_id {
        if let Some(item_id) = raw_id.strip_prefix(&prefix) {
            if !item_id.is_empty() {
                let _ = link
                    .ack_inbox(&InboxAckRequest {
                        kind: kind.to_string(),
                        id: item_id.to_string(),
                        outcome: AckOutcome::Rejected {
                            reason: format!("malformed_sse_payload: {err}"),
                        },
                    })
                    .await;
            }
        }
    }
}

async fn dispatch_sse_event(
    node: &Arc<UnifiedNode>,
    link: &Arc<PeerLink>,
    event_name: Option<&str>,
    event_id: Option<&str>,
    data: &str,
) {
    let peer_id = link.peer_id();
    match event_name {
        Some("message") => match serde_json::from_str::<MessageRecord>(data) {
            Ok(msg) => {
                let id = msg.id.clone();
                let outcome = match node.handle_inbound_peer_message(peer_id, msg).await {
                    Ok(()) => AckOutcome::Delivered,
                    Err(NodeError::Conflict(r)) if r == "local_inbox_full" => AckOutcome::Hold {
                        reason: "local_inbox_full".to_string(),
                        retry_after_ms: Some(5_000),
                    },
                    Err(err) => AckOutcome::Rejected {
                        reason: err.to_string(),
                    },
                };
                // Crash-safe invariant: ack upstream ONLY AFTER local DB commit succeeded (or failed permanently).
                let _ = link
                    .ack_inbox(&InboxAckRequest {
                        kind: "message".to_string(),
                        id,
                        outcome,
                    })
                    .await;
            }
            Err(err) => {
                reject_malformed_sse_item(link, "message", event_id, &err).await;
            }
        },
        Some("batch") => match serde_json::from_str::<DueBatch>(data) {
            Ok(batch) => {
                let id = batch.id.clone();
                let outcome = match node.handle_inbound_peer_batch(peer_id, batch).await {
                    Ok(()) => AckOutcome::Delivered,
                    Err(err) => AckOutcome::Rejected {
                        reason: err.to_string(),
                    },
                };
                let _ = link
                    .ack_inbox(&InboxAckRequest {
                        kind: "batch".to_string(),
                        id,
                        outcome,
                    })
                    .await;
            }
            Err(err) => {
                reject_malformed_sse_item(link, "batch", event_id, &err).await;
            }
        },
        Some("transfer") => match serde_json::from_str::<TransferRecord>(data) {
            Ok(transfer) => {
                let id = transfer.id.clone();
                let outcome = match node
                    .handle_inbound_peer_transfer(peer_id, link, transfer)
                    .await
                {
                    Ok(()) => AckOutcome::Delivered,
                    Err(err) => AckOutcome::Rejected {
                        reason: err.to_string(),
                    },
                };
                let _ = link
                    .ack_inbox(&InboxAckRequest {
                        kind: "transfer".to_string(),
                        id,
                        outcome,
                    })
                    .await;
            }
            Err(err) => {
                reject_malformed_sse_item(link, "transfer", event_id, &err).await;
            }
        },
        _ => {}
    }
}
