//! Verification of signed node manifests and their out-of-band identity pins.

use hyp_proto::jcs::JcsError;
use hyp_proto::manifest::{ManifestError, NodeManifestPayload, SignedNodeManifest};
use thiserror::Error;

use crate::CryptoError;
use crate::keys::{Ed25519PublicKey, OkpJwk, X25519PublicKey};
use crate::rfc3339::parse_rfc3339_millis;

#[derive(Debug, Error)]
pub enum ManifestVerificationError {
    #[error("invalid manifest payload: {0}")]
    Payload(ManifestError),
    #[error("manifest nodeId '{actual}' does not match '{expected}'")]
    NodeIdMismatch { actual: String, expected: String },
    #[error("failed to canonicalize manifest payload: {0}")]
    Canonicalization(JcsError),
    #[error("manifest payload is not canonical RFC 8785 JCS")]
    NonCanonical,
    #[error("invalid signingJwk: {0}")]
    SigningKey(CryptoError),
    #[error("invalid encryptionJwk: {0}")]
    EncryptionKey(CryptoError),
    #[error("manifest signingJwk does not match the pinned signing key")]
    SigningPinMismatch,
    #[error("manifest encryptionJwk does not match the pinned encryption key")]
    EncryptionPinMismatch,
    #[error("invalid manifest signature: {0}")]
    Signature(CryptoError),
    #[error("invalid manifest expiresAt '{expires_at}': {source}")]
    InvalidExpiry {
        expires_at: String,
        source: CryptoError,
    },
    #[error("manifest for '{node_id}' expired at {expires_at}")]
    Expired { node_id: String, expires_at: String },
}

/// Pins obtained separately from the fetched manifest.
#[derive(Default)]
pub struct ManifestPins<'a> {
    pub node_id: Option<&'a str>,
    pub signing_key: Option<&'a Ed25519PublicKey>,
    pub encryption_x: Option<&'a str>,
}

pub struct VerifiedManifest {
    pub payload: NodeManifestPayload,
    pub signing_key: Ed25519PublicKey,
    pub encryption_key: X25519PublicKey,
}

/// Verifies only the signature. Diagnostics can use this to report signature and
/// schema/expiry checks independently. Pairing should use `verify_signed_manifest`.
pub fn verify_manifest_signature(
    signed: &SignedNodeManifest,
    signing_key: &Ed25519PublicKey,
) -> Result<(), CryptoError> {
    signing_key.verify_domain_b64("manifest", signed.payload.as_bytes(), &signed.sig)
}

/// Verifies an enrollment or pairing manifest against all supplied identity pins.
pub fn verify_signed_manifest(
    signed: &SignedNodeManifest,
    pins: ManifestPins<'_>,
    now_ms: impl FnOnce() -> i64,
) -> Result<VerifiedManifest, ManifestVerificationError> {
    let payload = decode_manifest_payload(signed, pins.node_id)?;
    let (signing_key, encryption_key) =
        verify_manifest_integrity(signed, &payload, pins.signing_key, pins.encryption_x)?;

    verify_manifest_expiry(&payload, now_ms)?;
    Ok(VerifiedManifest {
        payload,
        signing_key,
        encryption_key,
    })
}

/// Checks canonical bytes, key encoding, supplied key pins and signature for a
/// decoded manifest. Peer negotiation retains its own audience and expiry checks.
pub fn verify_manifest_integrity(
    signed: &SignedNodeManifest,
    payload: &NodeManifestPayload,
    signing_pin: Option<&Ed25519PublicKey>,
    encryption_pin: Option<&str>,
) -> Result<(Ed25519PublicKey, X25519PublicKey), ManifestVerificationError> {
    verify_manifest_canonical(signed, payload)?;

    let signing_key = OkpJwk::from(&payload.identity.signing_jwk)
        .to_ed25519()
        .map_err(ManifestVerificationError::SigningKey)?;
    let encryption_key = OkpJwk::from(&payload.identity.encryption_jwk)
        .to_x25519()
        .map_err(ManifestVerificationError::EncryptionKey)?;
    if signing_pin.is_some_and(|expected| expected != &signing_key) {
        return Err(ManifestVerificationError::SigningPinMismatch);
    }
    if encryption_pin.is_some_and(|expected| expected != payload.identity.encryption_jwk.x) {
        return Err(ManifestVerificationError::EncryptionPinMismatch);
    }
    verify_manifest_signature(signed, &signing_key)
        .map_err(ManifestVerificationError::Signature)?;

    Ok((signing_key, encryption_key))
}

/// Decodes the typed payload and checks an expected peer ID before key work.
pub fn decode_manifest_payload(
    signed: &SignedNodeManifest,
    expected_node_id: Option<&str>,
) -> Result<NodeManifestPayload, ManifestVerificationError> {
    let payload = signed
        .decode_payload()
        .map_err(ManifestVerificationError::Payload)?;
    if let Some(expected) = expected_node_id {
        if payload.node_id.as_str() != expected {
            return Err(ManifestVerificationError::NodeIdMismatch {
                actual: payload.node_id.as_str().to_owned(),
                expected: expected.to_owned(),
            });
        }
    }
    Ok(payload)
}

/// Checks that a decoded manifest matches the exact canonical bytes that were signed.
pub fn verify_manifest_canonical(
    signed: &SignedNodeManifest,
    payload: &NodeManifestPayload,
) -> Result<(), ManifestVerificationError> {
    let canonical = payload
        .to_canonical_payload()
        .map_err(ManifestVerificationError::Canonicalization)?;
    if canonical != signed.payload {
        return Err(ManifestVerificationError::NonCanonical);
    }

    Ok(())
}

/// Checks expiry at the pairing client's millisecond clock boundary.
pub fn verify_manifest_expiry(
    payload: &NodeManifestPayload,
    now_ms: impl FnOnce() -> i64,
) -> Result<(), ManifestVerificationError> {
    let exp_ms = parse_rfc3339_millis(&payload.expires_at).map_err(|source| {
        ManifestVerificationError::InvalidExpiry {
            expires_at: payload.expires_at.clone(),
            source,
        }
    })?;
    if now_ms() > exp_ms {
        return Err(ManifestVerificationError::Expired {
            node_id: payload.node_id.as_str().to_owned(),
            expires_at: payload.expires_at.clone(),
        });
    }
    Ok(())
}
