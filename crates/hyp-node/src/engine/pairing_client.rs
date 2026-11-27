//! Shared request and response mechanics for pairing and enrollment clients.

use std::future::Future;
use std::time::Duration;

use http::{Response, StatusCode};
use hyper::body::{Bytes, Incoming};

use hyp_crypto::Ed25519PublicKey;
use hyp_crypto::compat_v1::{PairingCodeV1, derive_pairing_key_v1};
use hyp_crypto::human::{DelegatedPairProofV1, node_cert_sha256, sign_delegated_pair_proof};
use hyp_crypto::jcs::to_canonical_json;
use hyp_crypto::pairing::{
    GrantV2, P2pOfferToken, P2pPairConfirmation, verify_grant_v2, verify_p2p_confirmation,
};
use hyp_crypto::{CryptoError, NodeIdentityKeys, SignedPayload};
use thiserror::Error;

use super::config::NodeError;
use super::http_util::read_body_bytes;
use super::peer_link::{
    AdminPairRequestEnvelope, DelegatedPairRequest, P2pPairServerReply, PairBindingV2,
    PairRequestV2, PairServerReply,
};

#[derive(Debug, Error)]
pub enum AdminPairRequestError {
    #[error("failed to derive one-time pairing key: {0}")]
    PairingKey(CryptoError),
    #[error("failed to canonicalize PairBindingV2: {0}")]
    Canonicalization(CryptoError),
    #[error("failed to serialize PairRequestV2: {0}")]
    Serialization(serde_json::Error),
}

/// Signs the same canonical binding with the one-time key and the device key.
/// The ordinary JSON request for the hub retains the existing wire field order.
pub fn build_admin_pair_request(
    code: &PairingCodeV1,
    node_id: &str,
    keys: &NodeIdentityKeys,
    signed_grant: Option<&SignedPayload>,
    bound_at: impl FnOnce() -> String,
) -> Result<Vec<u8>, AdminPairRequestError> {
    let pair_key = derive_pairing_key_v1(&code.secret, &code.grant_id)
        .map_err(AdminPairRequestError::PairingKey)?;
    let binding = PairBindingV2 {
        v: 2,
        grant_id: code.grant_id.clone(),
        node_id: node_id.to_owned(),
        signing_jwk: keys.signing_jwk(),
        encryption_jwk: keys.encryption_jwk(),
        bound_at: bound_at(),
    };
    let payload = to_canonical_json(&binding).map_err(AdminPairRequestError::Canonicalization)?;
    let pairing_sig = pair_key.sign_domain_b64("binding", payload.as_bytes());
    let self_sig = keys
        .signing
        .sign_domain_b64("binding-self", payload.as_bytes());
    let request = AdminPairRequestEnvelope {
        base: PairRequestV2 {
            grant_id: code.grant_id.clone(),
            payload,
            pairing_sig,
            self_sig,
        },
        signed_grant: signed_grant.cloned(),
    };
    serde_json::to_value(request)
        .and_then(|value| serde_json::to_vec(&value))
        .map_err(AdminPairRequestError::Serialization)
}

/// Builds the proof and wire request from the same local identity and certificate.
pub fn build_delegated_pair_request(
    hub_node_id: &str,
    node_id: &str,
    keys: &NodeIdentityKeys,
    node_cert: &str,
    timestamp: impl FnOnce() -> String,
) -> Result<DelegatedPairRequest, CryptoError> {
    let ed25519_jwk = keys.signing_jwk();
    let x25519_jwk = keys.encryption_jwk();
    let timestamp = timestamp();
    let proof = DelegatedPairProofV1 {
        hub_node_id: hub_node_id.to_owned(),
        node_id: node_id.to_owned(),
        ed25519_jwk: ed25519_jwk.clone(),
        x25519_jwk: x25519_jwk.clone(),
        node_cert_sha256: node_cert_sha256(node_cert),
        timestamp: timestamp.clone(),
    };
    let proof_sig = sign_delegated_pair_proof(&proof, &keys.signing)?;
    Ok(DelegatedPairRequest {
        node_id: node_id.to_owned(),
        ed25519_jwk,
        x25519_jwk,
        node_cert: node_cert.trim().to_owned(),
        timestamp,
        proof_sig,
    })
}

#[derive(Debug, Error)]
pub enum AuthClaimHttpError<E> {
    #[error("claim request timed out")]
    Timeout,
    #[error("claim request failed: {0}")]
    Request(E),
    #[error("failed to read claim response: {0}")]
    Body(NodeError),
}

/// Reads the same bounded reply for engine and CLI claim callers. The CLI
/// specifies a header timeout and both retain their response-status policy.
pub async fn collect_auth_claim_reply<E>(
    request: impl Future<Output = Result<Response<Incoming>, E>>,
    header_timeout: Option<Duration>,
    max_response_bytes: usize,
) -> Result<(StatusCode, Bytes), AuthClaimHttpError<E>> {
    let response = match header_timeout {
        Some(timeout) => tokio::time::timeout(timeout, request)
            .await
            .map_err(|_| AuthClaimHttpError::Timeout)?,
        None => request.await,
    }
    .map_err(AuthClaimHttpError::Request)?;
    let status = response.status();
    let bytes = read_body_bytes(response.into_body(), max_response_bytes)
        .await
        .map_err(AuthClaimHttpError::Body)?;
    Ok((status, bytes))
}

/// Creates the shared counter-grant shape used by the CLI and the live node.
pub fn p2p_counter_grant(
    offer: &P2pOfferToken,
    id: String,
    scopes: Vec<String>,
    trust_tier: &str,
    issued_at: String,
    pair_by: Option<String>,
) -> GrantV2 {
    GrantV2 {
        v: 2,
        id,
        node_id: offer.node_id.clone(),
        scopes,
        trust_tier: Some(trust_tier.to_owned()),
        pairing_key: None,
        subject_signing_jwk: Some(offer.signing_jwk.clone()),
        subject_encryption_jwk: Some(offer.encryption_jwk.clone()),
        issued_at,
        pair_by,
        expires_at: None,
    }
}

impl P2pPairServerReply {
    /// Verifies the reply's outbound grant against the out-of-band offer key.
    pub fn verify_grant(
        &self,
        offer: &P2pOfferToken,
        local_node_id: &str,
    ) -> Result<GrantV2, CryptoError> {
        verify_p2p_confirmation(
            offer,
            &P2pPairConfirmation {
                offer_id: self.offer_id.clone(),
                alice_grant_to_bob: self.alice_grant_to_bob.clone(),
            },
            local_node_id,
        )
    }
}

#[derive(Debug, Error)]
pub enum AdminPairReplyError {
    #[error("hub grant has invalid Admin-CA signature: {0}")]
    Signature(CryptoError),
    #[error("hub returned a grant for the wrong nodeId '{0}'")]
    WrongNode(String),
}

impl PairServerReply {
    /// Verifies the hub grant against the Admin-CA key and local node ID.
    pub fn verify_grant(
        &self,
        admin_pk: &Ed25519PublicKey,
        local_node_id: &str,
    ) -> Result<GrantV2, AdminPairReplyError> {
        let grant =
            verify_grant_v2(&self.grant, admin_pk).map_err(AdminPairReplyError::Signature)?;
        if grant.node_id != local_node_id {
            return Err(AdminPairReplyError::WrongNode(grant.node_id));
        }
        Ok(grant)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyp_crypto::Ed25519KeyPair;
    use hyp_crypto::compat_v1::{issue_grant_v1, parse_pairing_code_v1};

    #[test]
    fn admin_pair_request_matches_previous_signed_wire_bytes() {
        let admin_key = Ed25519KeyPair::from_seed([11; 32]).unwrap();
        let issued =
            issue_grant_v1(&admin_key, "test@local", &["*"], 10_000, 1_795_516_800_000).unwrap();
        let code = parse_pairing_code_v1(&issued.code).unwrap();
        let keys = NodeIdentityKeys::generate().unwrap();
        let timestamp = "2026-11-24T12:05:00Z";
        let binding = PairBindingV2 {
            v: 2,
            grant_id: code.grant_id.clone(),
            node_id: "test@local".into(),
            signing_jwk: keys.signing_jwk(),
            encryption_jwk: keys.encryption_jwk(),
            bound_at: timestamp.to_owned(),
        };
        let pairing_key = derive_pairing_key_v1(&code.secret, &code.grant_id).unwrap();
        let payload = to_canonical_json(&binding).unwrap();
        let expected = PairRequestV2 {
            grant_id: code.grant_id.clone(),
            pairing_sig: pairing_key.sign_domain_b64("binding", payload.as_bytes()),
            self_sig: keys
                .signing
                .sign_domain_b64("binding-self", payload.as_bytes()),
            payload,
        };
        let signed_grant = admin_key.sign_jcs("grant", &issued.grant).unwrap();
        for grant in [None, Some(&signed_grant)] {
            let mut previous = serde_json::to_value(&expected).unwrap();
            if let Some(grant) = grant {
                previous["signedGrant"] = serde_json::to_value(grant).unwrap();
            }
            let actual = build_admin_pair_request(&code, "test@local", &keys, grant, || {
                timestamp.to_owned()
            })
            .unwrap();
            assert!(
                actual == serde_json::to_vec(&previous).unwrap(),
                "admin pair request wire bytes drifted"
            );
        }
    }
}
