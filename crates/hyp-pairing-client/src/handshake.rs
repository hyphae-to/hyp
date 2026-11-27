use super::{MAX_MANIFEST_RESPONSE_BYTES, manifest::verify_signed_manifest_strict};
use http::{Method, Request, header};
use hyp_crypto::compat_v1::PairingCodeV1;
use hyp_crypto::keys::{Ed25519PublicKey, NodeIdentityKeys, SignedPayload, X25519PublicKey};
use hyp_crypto::pairing::{
    AdminInviteV2, GrantV2, P2pOfferToken, P2pPairResponse, create_p2p_response, sign_grant_v2,
};
use hyp_crypto::rfc3339::format_rfc3339_millis;
use hyp_node::engine::http_util::{
    BoundedBodyError, BoundedRequestError, HttpClient, full_body, percent_encode, request_bounded,
};
use hyp_node::engine::pairing_client::{
    AdminPairReplyError, AdminPairRequestError, build_admin_pair_request, p2p_counter_grant,
};
use hyp_node::engine::{P2pPairServerReply, PairServerReply};
use hyp_proto::address::{LOCAL_NODE_ID, is_valid_node_id};
use hyp_proto::jcs::sha256_hex;
use hyp_proto::manifest::{NodeManifestPayload, SignedNodeManifest};
use hyp_proto::problem::ProblemDetails;
use hyp_store::{TrustTier as StoreTrustTier, now_ms};
use std::time::Duration;

const PAIR_HTTP_TIMEOUT_SECS: u64 = 15;

#[derive(Debug)]
pub enum LiveHandshakeError {
    Unreachable(String),
    Rejected { code: &'static str, message: String },
}

pub struct LiveP2pHandshakeResult {
    pub bob_grant_id: String,
    pub bob_grant_signed: SignedPayload,
    pub alice_grant_verified: GrantV2,
    pub alice_grant_signed: SignedPayload,
    pub auth_credential: String,
    pub signed_manifest: SignedNodeManifest,
    pub manifest_payload: Box<NodeManifestPayload>,
    pub manifest_etag: String,
}

pub struct LiveAm2HandshakeResult {
    pub hub_node_id: String,
    pub verified_grant: GrantV2,
    pub signed_grant: SignedPayload,
    pub auth_credential: String,
    pub signed_manifest: SignedNodeManifest,
    pub manifest_payload: Box<NodeManifestPayload>,
    pub hub_signing_pk: Ed25519PublicKey,
    pub hub_encryption_pk: X25519PublicKey,
    pub manifest_etag: String,
}

fn compute_manifest_etag(manifest_json: &str) -> String {
    let digest = sha256_hex(manifest_json.as_bytes());
    format!("\"{}\"", &digest[..16])
}

fn post_json_handshake(
    base_endpoint: &str,
    path: &str,
    body_bytes: Vec<u8>,
) -> Result<(u16, Vec<u8>), LiveHandshakeError> {
    let display_url = format!("{}{path}", base_endpoint.trim_end_matches('/'));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| LiveHandshakeError::Rejected {
            code: "RUNTIME_ERROR",
            message: format!("Failed to start async runtime: {e}"),
        })?;

    rt.block_on(async {
        let client = HttpClient::new().map_err(|e| LiveHandshakeError::Rejected {
            code: "HTTP_ERROR",
            message: format!("Failed to initialize HTTP client: {e}"),
        })?;
        let req = Request::builder()
            .method(Method::POST)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .header(
                header::USER_AGENT,
                format!("hyp/{}", env!("CARGO_PKG_VERSION")),
            )
            .body(full_body(body_bytes))
            .map_err(|e| LiveHandshakeError::Rejected {
                code: "HTTP_ERROR",
                message: format!("Failed to build pairing HTTP request: {e}"),
            })?;

        let outcome = request_bounded(
            client.request_for_endpoint(base_endpoint, req),
            Duration::from_secs(PAIR_HTTP_TIMEOUT_SECS),
            MAX_MANIFEST_RESPONSE_BYTES,
            |response| Ok::<_, LiveHandshakeError>(response.status().as_u16()),
        )
        .await
        .map_err(|error| match error {
            BoundedRequestError::RequestTimeout => LiveHandshakeError::Unreachable(format!(
                "POST {display_url} timed out after {PAIR_HTTP_TIMEOUT_SECS}s"
            )),
            BoundedRequestError::Request(error) => {
                LiveHandshakeError::Unreachable(format!("POST {display_url} failed: {error}"))
            }
            BoundedRequestError::Policy(error) => error,
            BoundedRequestError::BodyTimeout { .. } => LiveHandshakeError::Unreachable(
                "Timed out reading pairing response body".to_string(),
            ),
            BoundedRequestError::Body {
                error: BoundedBodyError::Read(error),
                ..
            } => LiveHandshakeError::Unreachable(format!(
                "Pairing response body read error: {error}"
            )),
            BoundedRequestError::Body {
                error: BoundedBodyError::TooLarge,
                ..
            } => LiveHandshakeError::Rejected {
                code: "PAIR_HANDSHAKE_INVALID",
                message: format!(
                    "Pairing response exceeds {MAX_MANIFEST_RESPONSE_BYTES} byte safety cap"
                ),
            },
        });

        client.shutdown_ssh();
        outcome
    })
}

fn decode_handshake_http_error(
    url: &str,
    status: u16,
    body_bytes: &[u8],
    not_found_code: &'static str,
    conflict_code: &'static str,
) -> LiveHandshakeError {
    if let Ok(problem) = serde_json::from_slice::<ProblemDetails>(body_bytes) {
        let code = match (status, problem.error.as_str()) {
            (401, _) | (403, _) => "PAIR_REJECTED",
            (404, _) => not_found_code,
            (409, _) => conflict_code,
            (410, _) => "TOKEN_EXPIRED",
            (429, _) | (_, "rate_limited") => "RATE_LIMITED",
            _ => "PAIR_HANDSHAKE_FAILED",
        };
        let detail = problem
            .detail
            .unwrap_or_else(|| format!("{} (HTTP {status})", problem.title));
        return LiveHandshakeError::Rejected {
            code,
            message: format!("POST {url} rejected ({}): {detail}", problem.error),
        };
    }
    let snippet: String = String::from_utf8_lossy(body_bytes)
        .chars()
        .take(200)
        .collect();
    let code = match status {
        401 | 403 => "PAIR_REJECTED",
        404 => not_found_code,
        409 => conflict_code,
        410 => "TOKEN_EXPIRED",
        429 => "RATE_LIMITED",
        _ => "PAIR_HANDSHAKE_FAILED",
    };
    LiveHandshakeError::Rejected {
        code,
        message: format!("POST {url} returned HTTP {status}: {}", snippet.trim()),
    }
}

/// Exchanges a validated peer offer for signed grants, a pinned manifest and a credential.
pub fn execute_live_p2p_handshake(
    offer: &P2pOfferToken,
    alice_sign_pk: &Ed25519PublicKey,
    local_node_id: &str,
    local_endpoint: Option<&str>,
    local_keys: &NodeIdentityKeys,
    granted_scopes: &[String],
    trust_tier: StoreTrustTier,
) -> Result<LiveP2pHandshakeResult, LiveHandshakeError> {
    let now_db = now_ms();
    let bob_grant_id = format!("p2p-{}", offer.offer_id);
    let bob_grant = p2p_counter_grant(
        offer,
        bob_grant_id.clone(),
        granted_scopes.to_vec(),
        trust_tier.as_str(),
        format_rfc3339_millis(now_db),
        None,
    );
    let bob_grant_signed = sign_grant_v2(&bob_grant, &local_keys.signing).map_err(|e| {
        LiveHandshakeError::Rejected {
            code: "GRANT_ERROR",
            message: format!("Failed to sign local P2P counter-grant: {e}"),
        }
    })?;
    let resp_body: P2pPairResponse =
        create_p2p_response(offer, local_node_id, local_endpoint, local_keys, &bob_grant).map_err(
            |e| LiveHandshakeError::Rejected {
                code: "OFFER_ERROR",
                message: format!("Failed to construct P2P pairing response: {e}"),
            },
        )?;
    let req_bytes = serde_json::to_vec(&resp_body).map_err(|e| LiveHandshakeError::Rejected {
        code: "ENCODE_ERROR",
        message: format!("Failed to serialize P2P pairing response: {e}"),
    })?;

    let path = format!("/v1/p2p/pair/{}", percent_encode(&offer.offer_id));
    let url = format!("{}{path}", offer.endpoint.trim_end_matches('/'));
    let (status, body_bytes) = post_json_handshake(&offer.endpoint, &path, req_bytes)?;
    if status != 200 {
        return Err(decode_handshake_http_error(
            &url,
            status,
            &body_bytes,
            "OFFER_NOT_FOUND",
            "OFFER_ALREADY_CLAIMED",
        ));
    }

    let server_reply: P2pPairServerReply =
        serde_json::from_slice(&body_bytes).map_err(|e| LiveHandshakeError::Rejected {
            code: "PAIR_HANDSHAKE_INVALID",
            message: format!("Invalid P2pPairServerReply JSON from {url}: {e}"),
        })?;
    if server_reply.auth_credential.trim().is_empty() {
        return Err(LiveHandshakeError::Rejected {
            code: "PAIR_HANDSHAKE_INVALID",
            message: "Peer returned an empty authCredential in P2P pairing reply".to_string(),
        });
    }

    let alice_grant_verified = server_reply
        .verify_grant(offer, local_node_id)
        .map_err(|e| LiveHandshakeError::Rejected {
            code: "INVALID_SIGNATURE",
            message: format!(
                "Peer P2P confirmation failed zero-TOFU verification against out-of-band JWK: {e}"
            ),
        })?;

    let (manifest_payload, _sign_pk, _enc_pk) = verify_signed_manifest_strict(
        &server_reply.signed_manifest,
        Some(&offer.node_id),
        Some(alice_sign_pk),
        Some(&offer.encryption_jwk.x),
    )
    .map_err(|(code, message)| LiveHandshakeError::Rejected { code, message })?;

    let manifest_json = serde_json::to_string(&server_reply.signed_manifest).map_err(|e| {
        LiveHandshakeError::Rejected {
            code: "ENCODE_ERROR",
            message: e.to_string(),
        }
    })?;
    let manifest_etag = compute_manifest_etag(&manifest_json);

    Ok(LiveP2pHandshakeResult {
        bob_grant_id,
        bob_grant_signed,
        alice_grant_verified,
        alice_grant_signed: server_reply.alice_grant_to_bob,
        auth_credential: server_reply.auth_credential,
        signed_manifest: server_reply.signed_manifest,
        manifest_payload: Box::new(manifest_payload),
        manifest_etag,
    })
}

/// Redeems an admin invite and verifies the returned grant and hub identity.
pub fn execute_live_am2_handshake(
    invite: &AdminInviteV2,
    parsed_v1: &PairingCodeV1,
    admin_pk: &Ed25519PublicKey,
    expected_hub_id: Option<&str>,
    local_node_id: &str,
    local_keys: &NodeIdentityKeys,
    inline_signed_grant: Option<&SignedPayload>,
) -> Result<LiveAm2HandshakeResult, LiveHandshakeError> {
    let req_bytes = build_admin_pair_request(
        parsed_v1,
        local_node_id,
        local_keys,
        inline_signed_grant,
        || format_rfc3339_millis(now_ms()),
    )
    .map_err(|error| {
        let (code, message) = match error {
            AdminPairRequestError::PairingKey(error) => (
                "INVALID_TOKEN",
                format!("Failed to derive one-time pairing key from am2_ bundle: {error}"),
            ),
            AdminPairRequestError::Canonicalization(error) => (
                "ENCODE_ERROR",
                format!("Failed to canonicalize PairBindingV2: {error}"),
            ),
            AdminPairRequestError::Serialization(error) => (
                "ENCODE_ERROR",
                format!("Failed to serialize PairRequestV2: {error}"),
            ),
        };
        LiveHandshakeError::Rejected { code, message }
    })?;

    let url = format!("{}/v1/pair", invite.router.trim_end_matches('/'));
    let (status, body_bytes) = post_json_handshake(&invite.router, "/v1/pair", req_bytes)?;
    if status != 200 {
        return Err(decode_handshake_http_error(
            &url,
            status,
            &body_bytes,
            "GRANT_NOT_FOUND",
            "GRANT_ALREADY_CLAIMED",
        ));
    }

    let reply: PairServerReply =
        serde_json::from_slice(&body_bytes).map_err(|e| LiveHandshakeError::Rejected {
            code: "PAIR_HANDSHAKE_INVALID",
            message: format!("Invalid PairServerReply JSON from {url}: {e}"),
        })?;
    if reply.auth_credential.trim().is_empty() {
        return Err(LiveHandshakeError::Rejected {
            code: "PAIR_HANDSHAKE_INVALID",
            message: "Hub returned an empty authCredential in /v1/pair reply".to_string(),
        });
    }
    if reply.node_id == LOCAL_NODE_ID || !is_valid_node_id(&reply.node_id) {
        return Err(LiveHandshakeError::Rejected {
            code: "PAIR_HANDSHAKE_INVALID",
            message: format!(
                "Hub returned invalid nodeId '{}' in /v1/pair reply",
                reply.node_id
            ),
        });
    }
    if let Some(expected) = expected_hub_id {
        if reply.node_id != expected {
            return Err(LiveHandshakeError::Rejected {
                code: "NODE_ID_MISMATCH",
                message: format!(
                    "Hub /v1/pair returned nodeId '{}' which does not match expected '{expected}'",
                    reply.node_id
                ),
            });
        }
    }

    let verified_grant = reply.verify_grant(admin_pk, local_node_id).map_err(|error| {
        match error {
            AdminPairReplyError::Signature(error) => LiveHandshakeError::Rejected {
                code: "INVALID_SIGNATURE",
                message: format!("Hub /v1/pair returned grant that failed Admin-CA signature verification: {error}"),
            },
            AdminPairReplyError::WrongNode(actual) => LiveHandshakeError::Rejected {
                code: "PAIR_REJECTED",
                message: format!("Hub returned grant for nodeId '{actual}' which does not match local nodeId '{local_node_id}'"),
            },
        }
    })?;

    let (manifest_payload, hub_signing_pk, hub_encryption_pk) =
        verify_signed_manifest_strict(&reply.signed_manifest, Some(&reply.node_id), None, None)
            .map_err(|(code, message)| LiveHandshakeError::Rejected { code, message })?;

    let manifest_json = serde_json::to_string(&reply.signed_manifest).map_err(|e| {
        LiveHandshakeError::Rejected {
            code: "ENCODE_ERROR",
            message: e.to_string(),
        }
    })?;
    let manifest_etag = compute_manifest_etag(&manifest_json);

    Ok(LiveAm2HandshakeResult {
        hub_node_id: reply.node_id,
        verified_grant,
        signed_grant: reply.grant,
        auth_credential: reply.auth_credential,
        signed_manifest: reply.signed_manifest,
        manifest_payload: Box::new(manifest_payload),
        hub_signing_pk,
        hub_encryption_pk,
        manifest_etag,
    })
}
