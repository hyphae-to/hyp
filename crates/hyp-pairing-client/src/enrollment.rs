use super::{MANIFEST_FETCH_TIMEOUT_SECS, MAX_MANIFEST_RESPONSE_BYTES};
use http::{Method, Request, header};
use hyp_crypto::keys::{Ed25519PublicKey, NodeIdentityKeys, OkpJwk as CryptoOkpJwk};
use hyp_crypto::manifest::{
    ManifestVerificationError, decode_manifest_payload, verify_manifest_canonical,
    verify_manifest_expiry, verify_manifest_signature,
};
use hyp_crypto::pairing::validate_endpoint_origin;
use hyp_crypto::rfc3339::{format_rfc3339_millis, now_unix_ms};
use hyp_node::engine::http_util::{
    BoundedBodyError, BoundedRequestError, HttpClient, full_body, request_bounded,
};
use hyp_node::engine::pairing_client::build_delegated_pair_request;
use hyp_node::engine::{
    DelegatedPairReply, GuestPairReply, GuestPairRequest, guest_pair_proof_canonical,
};
use hyp_proto::manifest::{NodeManifestPayload, SignedNodeManifest};
use hyp_proto::problem::ProblemDetails;
use hyp_proto::scopes::expand_v2_scopes;
use std::time::Duration;

fn decode_enrollment_manifest(
    signed: &SignedNodeManifest,
    hub_node_id: &str,
    path: &str,
    label: &str,
) -> Result<NodeManifestPayload, (&'static str, String)> {
    let payload =
        decode_manifest_payload(signed, Some(hub_node_id)).map_err(|error| match error {
            ManifestVerificationError::Payload(error) => (
                "INVALID_MANIFEST",
                format!("Invalid NodeManifestPayload in {path} reply: {error}"),
            ),
            ManifestVerificationError::NodeIdMismatch { actual, expected } => (
                "NODE_ID_MISMATCH",
                format!("Manifest nodeId '{actual}' in {path} reply does not match '{expected}'"),
            ),
            error => ("INVALID_MANIFEST", error.to_string()),
        })?;
    verify_manifest_canonical(signed, &payload).map_err(|error| match error {
        ManifestVerificationError::Canonicalization(error) => (
            "INVALID_MANIFEST",
            format!("Failed to canonicalize {label} manifest payload: {error}"),
        ),
        ManifestVerificationError::NonCanonical => (
            "NON_CANONICAL_MANIFEST",
            format!("Manifest in {path} reply is not canonical RFC 8785 JCS (fail-closed)"),
        ),
        error => ("INVALID_MANIFEST", error.to_string()),
    })?;
    Ok(payload)
}

fn verify_enrollment_manifest_expiry(
    payload: &NodeManifestPayload,
    path: &str,
) -> Result<(), (&'static str, String)> {
    verify_manifest_expiry(payload, now_unix_ms).map_err(|error| match error {
        ManifestVerificationError::InvalidExpiry { source, .. } => (
            "INVALID_MANIFEST",
            format!("Invalid expiresAt in {path} manifest: {source}"),
        ),
        ManifestVerificationError::Expired { expires_at, .. } => (
            "MANIFEST_EXPIRED",
            format!("Hub manifest in {path} expired at {expires_at}"),
        ),
        error => ("INVALID_MANIFEST", error.to_string()),
    })
}

pub enum GuestEnrollOutcome {
    Enrolled {
        preset: String,
        scopes: Vec<String>,
        manifest: SignedNodeManifest,
        manifest_payload: Box<NodeManifestPayload>,
    },
    NotEnabled,
}

/// Requests guest access and verifies the response manifest with the supplied hub signing key.
pub fn attempt_guest_self_enroll(
    base_url: &str,
    hub_node_id: &str,
    hub_signing_pk: &Ed25519PublicKey,
    local_node_id: &str,
    local_keys: &NodeIdentityKeys,
) -> Result<GuestEnrollOutcome, (&'static str, String)> {
    let pair_url = format!("{}/v1/guest/pair", base_url.trim_end_matches('/'));

    let ed25519_jwk = local_keys.signing_jwk();
    let x25519_jwk = local_keys.encryption_jwk();
    let timestamp = format_rfc3339_millis(now_unix_ms());
    let canonical = guest_pair_proof_canonical(
        hub_node_id,
        local_node_id,
        &ed25519_jwk,
        &x25519_jwk,
        &timestamp,
    )
    .map_err(|e| {
        (
            "ENCODE_ERROR",
            format!("Failed to canonicalize guest-pair proof: {e}"),
        )
    })?;
    let proof_sig = local_keys
        .signing
        .sign_domain_b64("guest-pair", canonical.as_bytes());

    let req_body = GuestPairRequest {
        node_id: local_node_id.to_string(),
        ed25519_jwk,
        x25519_jwk,
        timestamp,
        proof_sig,
    };
    let req_bytes = serde_json::to_vec(&req_body).map_err(|e| {
        (
            "ENCODE_ERROR",
            format!("Failed to serialize guest-pair request: {e}"),
        )
    })?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            (
                "RUNTIME_ERROR",
                format!("Failed to start async runtime: {e}"),
            )
        })?;

    let (status, body_bytes) = rt.block_on(async {
        let client = HttpClient::new().map_err(|e| {
            (
                "HTTP_ERROR",
                format!("Failed to initialize HTTP client: {e}"),
            )
        })?;
        let req = Request::builder()
            .method(Method::POST)
            .uri("/v1/guest/pair")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .header(
                header::USER_AGENT,
                format!("hyp/{}", env!("CARGO_PKG_VERSION")),
            )
            .body(full_body(req_bytes))
            .map_err(|e| {
                (
                    "HTTP_ERROR",
                    format!("Failed to build guest-pair request: {e}"),
                )
            })?;

        let outcome = request_bounded(
            client.request_for_endpoint(base_url, req),
            Duration::from_secs(MANIFEST_FETCH_TIMEOUT_SECS),
            MAX_MANIFEST_RESPONSE_BYTES,
            |response| Ok::<_, (&'static str, String)>(response.status().as_u16()),
        )
        .await
        .map_err(|error| match error {
            BoundedRequestError::RequestTimeout => (
                "GUEST_PAIR_FAILED",
                format!("POST {pair_url} timed out after {MANIFEST_FETCH_TIMEOUT_SECS}s"),
            ),
            BoundedRequestError::Request(error) => (
                "GUEST_PAIR_FAILED",
                format!("POST {pair_url} failed: {error}"),
            ),
            BoundedRequestError::Policy(error) => error,
            BoundedRequestError::BodyTimeout { .. } => (
                "GUEST_PAIR_FAILED",
                "Timed out reading /v1/guest/pair response body".to_string(),
            ),
            BoundedRequestError::Body {
                error: BoundedBodyError::Read(error),
                ..
            } => (
                "GUEST_PAIR_FAILED",
                format!("Guest pair body read error: {error}"),
            ),
            BoundedRequestError::Body {
                error: BoundedBodyError::TooLarge,
                ..
            } => (
                "GUEST_PAIR_INVALID",
                format!("Guest pair response exceeds {MAX_MANIFEST_RESPONSE_BYTES} byte cap"),
            ),
        });

        client.shutdown_ssh();
        outcome
    })?;

    if status == 404 {
        return Ok(GuestEnrollOutcome::NotEnabled);
    }

    if status != 200 {
        let (code, detail) =
            if let Ok(problem) = serde_json::from_slice::<ProblemDetails>(&body_bytes) {
                let err_code = match (status, problem.error.as_str()) {
                    (_, "peer_key_mismatch") => "PEER_KEY_MISMATCH",
                    (429, _) | (_, "rate_limited") => "RATE_LIMITED",
                    (409, _) => "GUEST_PAIR_CONFLICT",
                    (403, _) | (401, _) => "GUEST_PAIR_REJECTED",
                    _ => "GUEST_PAIR_FAILED",
                };
                let msg = problem
                    .detail
                    .unwrap_or_else(|| format!("{} (HTTP {status})", problem.title));
                (
                    err_code,
                    format!("POST {pair_url} rejected ({}): {msg}", problem.error),
                )
            } else {
                let snippet: String = String::from_utf8_lossy(&body_bytes)
                    .chars()
                    .take(200)
                    .collect();
                let err_code = match status {
                    409 => "GUEST_PAIR_CONFLICT",
                    429 => "RATE_LIMITED",
                    401 | 403 => "GUEST_PAIR_REJECTED",
                    _ => "GUEST_PAIR_FAILED",
                };
                (
                    err_code,
                    format!("POST {pair_url} returned HTTP {status}: {snippet}"),
                )
            };
        return Err((code, detail));
    }

    let reply: GuestPairReply = serde_json::from_slice(&body_bytes).map_err(|e| {
        (
            "GUEST_PAIR_INVALID",
            format!("Invalid GuestPairReply JSON from {pair_url}: {e}"),
        )
    })?;
    if !reply.ok {
        return Err((
            "GUEST_PAIR_REJECTED",
            format!("Hub '{hub_node_id}' returned ok=false on /v1/guest/pair"),
        ));
    }
    if reply.node_id != hub_node_id {
        return Err((
            "NODE_ID_MISMATCH",
            format!(
                "Hub /v1/guest/pair nodeId '{}' does not match verified manifest nodeId '{hub_node_id}'",
                reply.node_id
            ),
        ));
    }
    if reply.peer_id != local_node_id {
        return Err((
            "GUEST_PAIR_INVALID",
            format!(
                "Hub /v1/guest/pair peerId '{}' does not match local nodeId '{local_node_id}'",
                reply.peer_id
            ),
        ));
    }
    if reply.scopes.is_empty() {
        return Err((
            "GUEST_PAIR_INVALID",
            "Hub /v1/guest/pair returned empty granted scopes".to_string(),
        ));
    }
    let validated_scopes = expand_v2_scopes(&reply.scopes).map_err(|e| {
        (
            "GUEST_PAIR_INVALID",
            format!("Hub /v1/guest/pair returned invalid scopes: {e}"),
        )
    })?;

    // Verify the authenticated manifest returned by `/v1/guest/pair` against the pinned hub signing key!
    let manifest_payload =
        decode_enrollment_manifest(&reply.manifest, hub_node_id, "/v1/guest/pair", "guest-pair")?;
    verify_manifest_signature(&reply.manifest, hub_signing_pk).map_err(|error| (
        "INVALID_SIGNATURE",
        format!("Manifest signature in /v1/guest/pair reply failed pinned hub key verification: {error}"),
    ))?;
    verify_enrollment_manifest_expiry(&manifest_payload, "/v1/guest/pair")?;

    Ok(GuestEnrollOutcome::Enrolled {
        preset: reply.preset,
        scopes: validated_scopes,
        manifest: reply.manifest,
        manifest_payload: Box::new(manifest_payload),
    })
}

pub struct DelegatedEnrollSuccess {
    pub hub_node_id: String,
    pub human_id: String,
    pub auth_epoch: u64,
    pub scopes: Vec<String>,
    pub auth_credential: String,
    pub manifest: SignedNodeManifest,
    pub manifest_payload: Box<NodeManifestPayload>,
}

/// Calls `POST <base_url>/v1/pair/delegated` using a human-signed `hcert1_` NodeCert and a live
/// device Ed25519 possession proof, verifying the returned `SignedNodeManifest` against the hub's
/// pinned signing key (or self-signed manifest + optional `expected_hub_fingerprint`).
pub fn attempt_delegated_pair_enroll(
    base_url: &str,
    hub_node_id: &str,
    expected_hub_signing_pk: Option<&Ed25519PublicKey>,
    expected_hub_fingerprint: Option<&str>,
    local_node_id: &str,
    local_keys: &NodeIdentityKeys,
    hcert1: &str,
) -> Result<DelegatedEnrollSuccess, (u16, &'static str, String)> {
    let pair_url = format!("{}/v1/pair/delegated", base_url.trim_end_matches('/'));
    validate_endpoint_origin(base_url).map_err(|e| {
        (
            0u16,
            "INVALID_ENDPOINT",
            format!("Invalid delegated pairing endpoint '{base_url}': {e}"),
        )
    })?;

    let req_body =
        build_delegated_pair_request(hub_node_id, local_node_id, local_keys, hcert1, || {
            format_rfc3339_millis(now_unix_ms())
        })
        .map_err(|e| {
            (
                0u16,
                "SIGN_ERROR",
                format!("Failed to sign DelegatedPairProofV1: {e}"),
            )
        })?;
    let req_bytes = serde_json::to_vec(&req_body).map_err(|e| {
        (
            0u16,
            "ENCODE_ERROR",
            format!("Failed to serialize delegated-pair request: {e}"),
        )
    })?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            (
                0u16,
                "RUNTIME_ERROR",
                format!("Failed to start async runtime: {e}"),
            )
        })?;

    let (status, body_bytes) = rt.block_on(async {
        let client = HttpClient::new().map_err(|e| {
            (
                0u16,
                "HTTP_ERROR",
                format!("Failed to initialize HTTP client: {e}"),
            )
        })?;
        let req = Request::builder()
            .method(Method::POST)
            .uri("/v1/pair/delegated")
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .header(
                header::USER_AGENT,
                format!("hyp/{}", env!("CARGO_PKG_VERSION")),
            )
            .body(full_body(req_bytes))
            .map_err(|e| {
                (
                    0u16,
                    "HTTP_ERROR",
                    format!("Failed to build delegated-pair request: {e}"),
                )
            })?;

        let outcome = request_bounded(
            client.request_for_endpoint(base_url, req),
            Duration::from_secs(MANIFEST_FETCH_TIMEOUT_SECS),
            MAX_MANIFEST_RESPONSE_BYTES,
            |response| Ok::<_, (u16, &'static str, String)>(response.status().as_u16()),
        )
        .await
        .map_err(|error| match error {
            BoundedRequestError::RequestTimeout => (
                0u16,
                "DELEGATED_PAIR_FAILED",
                format!("POST {pair_url} timed out after {MANIFEST_FETCH_TIMEOUT_SECS}s"),
            ),
            BoundedRequestError::Request(error) => (
                0u16,
                "DELEGATED_PAIR_FAILED",
                format!("POST {pair_url} failed: {error}"),
            ),
            BoundedRequestError::Policy(error) => error,
            BoundedRequestError::BodyTimeout { status } => (
                status,
                "DELEGATED_PAIR_FAILED",
                "Timed out reading /v1/pair/delegated response body".to_string(),
            ),
            BoundedRequestError::Body {
                status,
                error: BoundedBodyError::Read(error),
            } => (
                status,
                "DELEGATED_PAIR_FAILED",
                format!("Delegated pair body read error: {error}"),
            ),
            BoundedRequestError::Body {
                status,
                error: BoundedBodyError::TooLarge,
            } => (
                status,
                "DELEGATED_PAIR_INVALID",
                format!("Delegated pair response exceeds {MAX_MANIFEST_RESPONSE_BYTES} byte cap"),
            ),
        });

        client.shutdown_ssh();
        outcome
    })?;

    if status != 200 {
        let (code, detail) =
            if let Ok(problem) = serde_json::from_slice::<ProblemDetails>(&body_bytes) {
                let err_code = match (status, problem.error.as_str()) {
                    (_, "peer_key_mismatch") => "PEER_KEY_MISMATCH",
                    (_, "human_key_mismatch") => "HUMAN_KEY_MISMATCH",
                    (429, _) | (_, "quota_exceeded") | (_, "rate_limited") => "QUOTA_EXCEEDED",
                    (409, _) => "DELEGATED_PAIR_CONFLICT",
                    (401, _) | (403, _) => "DELEGATED_PAIR_REJECTED",
                    (404, _) => "DELEGATED_PAIR_NOT_SUPPORTED",
                    _ => "DELEGATED_PAIR_FAILED",
                };
                let msg = problem
                    .detail
                    .unwrap_or_else(|| format!("{} (HTTP {status})", problem.title));
                (
                    err_code,
                    format!("POST {pair_url} rejected ({}): {msg}", problem.error),
                )
            } else {
                let snippet: String = String::from_utf8_lossy(&body_bytes)
                    .chars()
                    .take(200)
                    .collect();
                let err_code = match status {
                    409 => "DELEGATED_PAIR_CONFLICT",
                    429 => "QUOTA_EXCEEDED",
                    401 | 403 => "DELEGATED_PAIR_REJECTED",
                    404 => "DELEGATED_PAIR_NOT_SUPPORTED",
                    _ => "DELEGATED_PAIR_FAILED",
                };
                (
                    err_code,
                    format!("POST {pair_url} returned HTTP {status}: {snippet}"),
                )
            };
        return Err((status, code, detail));
    }

    let reply: DelegatedPairReply = serde_json::from_slice(&body_bytes).map_err(|e| {
        (
            200,
            "DELEGATED_PAIR_INVALID",
            format!("Invalid DelegatedPairReply JSON from {pair_url}: {e}"),
        )
    })?;
    if !reply.ok || reply.auth_credential.trim().is_empty() {
        return Err((
            200,
            "DELEGATED_PAIR_INVALID",
            format!("Hub '{hub_node_id}' returned invalid delegated pair reply"),
        ));
    }
    if reply.node_id != hub_node_id {
        return Err((
            200,
            "NODE_ID_MISMATCH",
            format!(
                "Hub /v1/pair/delegated nodeId '{}' does not match expected '{hub_node_id}'",
                reply.node_id
            ),
        ));
    }
    if reply.peer_id != local_node_id {
        return Err((
            200,
            "DELEGATED_PAIR_INVALID",
            format!(
                "Hub /v1/pair/delegated peerId '{}' does not match local nodeId '{local_node_id}'",
                reply.peer_id
            ),
        ));
    }
    let validated_scopes = expand_v2_scopes(&reply.scopes).map_err(|e| {
        (
            200,
            "DELEGATED_PAIR_INVALID",
            format!("Hub /v1/pair/delegated returned invalid scopes: {e}"),
        )
    })?;

    let manifest_payload = decode_enrollment_manifest(
        &reply.signed_manifest,
        hub_node_id,
        "/v1/pair/delegated",
        "delegated-pair",
    )
    .map_err(|(code, message)| (200, code, message))?;
    let manifest_sign_pk = CryptoOkpJwk::from(&manifest_payload.identity.signing_jwk)
        .to_ed25519()
        .map_err(|e| {
            (
                200,
                "INVALID_KEY",
                format!("Invalid hub signingJwk in delegated-pair manifest: {e}"),
            )
        })?;
    let verify_pk = if let Some(pinned) = expected_hub_signing_pk {
        if *pinned != manifest_sign_pk {
            return Err((
                200,
                "HUB_KEY_MISMATCH",
                "Hub signing key in /v1/pair/delegated manifest does not match pinned manifest key"
                    .to_string(),
            ));
        }
        pinned
    } else {
        &manifest_sign_pk
    };
    if let Some(expected_fp) = expected_hub_fingerprint {
        let actual_fp = verify_pk.fingerprint();
        if !expected_fp.eq_ignore_ascii_case(&actual_fp) {
            return Err((
                200,
                "HUB_FINGERPRINT_MISMATCH",
                format!(
                    "Hub signing key fingerprint '{actual_fp}' does not match pinned '{expected_fp}'"
                ),
            ));
        }
    }
    verify_manifest_signature(&reply.signed_manifest, verify_pk).map_err(|error| {
        (
            200,
            "INVALID_SIGNATURE",
            format!("Manifest signature in /v1/pair/delegated reply failed verification: {error}"),
        )
    })?;
    verify_enrollment_manifest_expiry(&manifest_payload, "/v1/pair/delegated")
        .map_err(|(code, message)| (200, code, message))?;

    Ok(DelegatedEnrollSuccess {
        hub_node_id: reply.node_id,
        human_id: reply.human_id,
        auth_epoch: reply.auth_epoch,
        scopes: validated_scopes,
        auth_credential: reply.auth_credential,
        manifest: reply.signed_manifest,
        manifest_payload: Box::new(manifest_payload),
    })
}
