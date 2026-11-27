use super::{MANIFEST_FETCH_TIMEOUT_SECS, MAX_MANIFEST_RESPONSE_BYTES};
use http::{Method, Request, header};
use hyp_crypto::keys::{Ed25519PublicKey, X25519PublicKey};
use hyp_crypto::manifest::{
    ManifestPins, ManifestVerificationError, VerifiedManifest, verify_signed_manifest,
};
use hyp_crypto::rfc3339::now_unix_ms;
use hyp_node::engine::http_util::{
    BoundedBodyError, BoundedRequestError, HttpClient, empty_body, request_bounded,
};
use hyp_proto::manifest::{NodeManifestPayload, SignedNodeManifest};
use std::time::Duration;

#[derive(Clone, Copy)]
enum ManifestSource {
    PairingReply,
    Fetch,
}

fn manifest_verification_error(
    source: ManifestSource,
    error: ManifestVerificationError,
) -> (&'static str, String) {
    use ManifestSource::*;
    use ManifestVerificationError::*;
    let from_reply = matches!(source, PairingReply);
    let context = if from_reply {
        "pairing manifest"
    } else {
        "manifest"
    };
    match error {
        Payload(error) => (
            "INVALID_MANIFEST",
            match source {
                PairingReply => format!("Invalid NodeManifestPayload in pairing reply: {error}"),
                Fetch => format!("Invalid NodeManifestPayload in signed manifest: {error}"),
            },
        ),
        NodeIdMismatch { actual, expected } => (
            "NODE_ID_MISMATCH",
            format!("Pairing reply manifest nodeId '{actual}' does not match expected '{expected}'"),
        ),
        Canonicalization(error) => (
            "INVALID_MANIFEST",
            format!("Failed to canonicalize {context} payload: {error}"),
        ),
        NonCanonical => (
            "NON_CANONICAL_MANIFEST",
            match source {
                PairingReply => "Pairing reply manifest payload is not canonical RFC 8785 JCS (fail-closed)",
                Fetch => "Signed manifest payload is not canonical RFC 8785 JCS (fail-closed)",
            }.to_owned(),
        ),
        SigningKey(error) => ("INVALID_KEY", format!("Invalid signingJwk in {context}: {error}")),
        EncryptionKey(error) => ("INVALID_KEY", format!("Invalid encryptionJwk in {context}: {error}")),
        SigningPinMismatch => (
            "KEY_PIN_MISMATCH",
            "Pairing reply manifest signingJwk does not match out-of-band pinned key (fail-closed)".to_owned(),
        ),
        EncryptionPinMismatch => (
            "KEY_PIN_MISMATCH",
            "Pairing reply manifest encryptionJwk does not match out-of-band pinned key (fail-closed)".to_owned(),
        ),
        Signature(error) => (
            "INVALID_SIGNATURE",
            match source {
                PairingReply => format!("Pairing reply manifest Ed25519 signature verification failed (fail-closed): {error}"),
                Fetch => format!("Manifest Ed25519 signature verification failed (fail-closed): {error}"),
            },
        ),
        InvalidExpiry { expires_at, source: error } => (
            "INVALID_MANIFEST",
            match source {
                PairingReply => format!("Invalid expiresAt '{expires_at}' in pairing manifest: {error}"),
                Fetch => format!("Invalid manifest expiresAt '{expires_at}': {error}"),
            },
        ),
        Expired { node_id, expires_at } => (
            "MANIFEST_EXPIRED",
            match source {
                PairingReply => format!("Peer '{node_id}' manifest in pairing reply expired at {expires_at}"),
                Fetch => format!("Node '{node_id}' manifest expired at {expires_at}"),
            },
        ),
    }
}

pub(super) fn verify_signed_manifest_strict(
    signed: &SignedNodeManifest,
    expected_node_id: Option<&str>,
    expected_signing_pk: Option<&Ed25519PublicKey>,
    expected_enc_x: Option<&str>,
) -> Result<(NodeManifestPayload, Ed25519PublicKey, X25519PublicKey), (&'static str, String)> {
    let verified = verify_signed_manifest(
        signed,
        ManifestPins {
            node_id: expected_node_id,
            signing_key: expected_signing_pk,
            encryption_x: expected_enc_x,
        },
        now_unix_ms,
    )
    .map_err(|error| manifest_verification_error(ManifestSource::PairingReply, error))?;
    Ok((
        verified.payload,
        verified.signing_key,
        verified.encryption_key,
    ))
}

pub struct VerifiedLiveManifest {
    pub signed: SignedNodeManifest,
    pub payload: NodeManifestPayload,
    pub signing_pk: Ed25519PublicKey,
    pub encryption_pk: X25519PublicKey,
    pub etag: Option<String>,
}

/// Fetches a self-signed manifest. Callers check existing peer pins before trusting its identity.
pub fn fetch_and_verify_manifest(
    base_url: &str,
) -> Result<VerifiedLiveManifest, (&'static str, String)> {
    let manifest_url = format!("{}/v1/manifest", base_url.trim_end_matches('/'));

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            (
                "RUNTIME_ERROR",
                format!("Failed to start async runtime: {e}"),
            )
        })?;

    let (body_bytes, etag) = rt.block_on(async {
        let client = HttpClient::new().map_err(|e| {
            (
                "HTTP_ERROR",
                format!("Failed to initialize HTTP client: {e}"),
            )
        })?;

        let req = Request::builder()
            .method(Method::GET)
            .uri("/v1/manifest")
            .header(header::ACCEPT, "application/json")
            .header(
                header::USER_AGENT,
                format!("hyp/{}", env!("CARGO_PKG_VERSION")),
            )
            .body(empty_body())
            .map_err(|e| ("HTTP_ERROR", format!("Failed to build request: {e}")))?;

        let outcome = request_bounded(
            client.request_for_endpoint(base_url, req),
            Duration::from_secs(MANIFEST_FETCH_TIMEOUT_SECS),
            MAX_MANIFEST_RESPONSE_BYTES,
            |response| {
                let status = response.status().as_u16();
                if status != 200 {
                    return Err((
                        "MANIFEST_FETCH_FAILED",
                        format!("GET {manifest_url} returned HTTP {status} (expected 200)"),
                    ));
                }
                let etag = response
                    .headers()
                    .get(header::ETAG)
                    .and_then(|value| value.to_str().ok())
                    .map(ToOwned::to_owned);
                Ok::<_, (&'static str, String)>(etag)
            },
        )
        .await
        .map(|(etag, bytes)| (bytes, etag))
        .map_err(|error| match error {
            BoundedRequestError::RequestTimeout => (
                "MANIFEST_FETCH_FAILED",
                format!("GET {manifest_url} timed out after {MANIFEST_FETCH_TIMEOUT_SECS}s"),
            ),
            BoundedRequestError::Request(error) => (
                "MANIFEST_FETCH_FAILED",
                format!("GET {manifest_url} failed: {error}"),
            ),
            BoundedRequestError::Policy(error) => error,
            BoundedRequestError::BodyTimeout { .. } => (
                "MANIFEST_FETCH_FAILED",
                "Timed out reading /v1/manifest response body".to_string(),
            ),
            BoundedRequestError::Body {
                error: BoundedBodyError::Read(error),
                ..
            } => (
                "MANIFEST_FETCH_FAILED",
                format!("Manifest body read error: {error}"),
            ),
            BoundedRequestError::Body {
                error: BoundedBodyError::TooLarge,
                ..
            } => (
                "INVALID_MANIFEST",
                format!("Manifest response exceeds {MAX_MANIFEST_RESPONSE_BYTES} byte safety cap"),
            ),
        });

        client.shutdown_ssh();
        outcome
    })?;

    let signed: SignedNodeManifest = serde_json::from_slice(&body_bytes).map_err(|e| {
        (
            "INVALID_MANIFEST",
            format!("Response from {manifest_url} is not a valid SignedNodeManifest: {e}"),
        )
    })?;

    let VerifiedManifest {
        payload,
        signing_key: signing_pk,
        encryption_key: encryption_pk,
    } = verify_signed_manifest(&signed, ManifestPins::default(), now_unix_ms)
        .map_err(|error| manifest_verification_error(ManifestSource::Fetch, error))?;

    Ok(VerifiedLiveManifest {
        signed,
        payload,
        signing_pk,
        encryption_pk,
        etag,
    })
}
