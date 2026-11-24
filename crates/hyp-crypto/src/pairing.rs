//! Hyphae v2 Pairing & Trust Primitives:
//! - v2 `GrantV2` & `RevocationV2` (RFC 8785 JCS + `"hyphae/v2/<kind>\n"` Ed25519)
//! - v2 Org Admin-CA Invite Bundle (`am2_`)
//! - v2 Direct P2P Mutual Pairing (`hp2p1_`) with 160-bit pairing secret,
//!   HKDF binding MAC, Ed25519 self-sig, and zero-TOFU embedded OKP JWKs.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::compat_v1::parse_pairing_code_v1;
use crate::error::CryptoError;
use crate::hpke::hkdf_sha256;
use crate::jcs::to_canonical_json;
use crate::keys::{Ed25519KeyPair, Ed25519PublicKey, NodeIdentityKeys, OkpJwk, SignedPayload};
use crate::rfc3339::parse_rfc3339_millis;

/// Prefix for v2 Org Admin-CA invite bundles (`am2_<base64url>`).
pub const AM2_PREFIX: &str = "am2_";

/// Prefix for v2 Direct P2P mutual pairing offers (`hp2p1_<base64url>`).
pub const HP2P1_PREFIX: &str = "hp2p1_";

/// Size of the out-of-band pairing secret in `hp2p1_` (160 bits = 20 bytes).
pub const P2P_SECRET_BYTES: usize = 20;

/// Validates canonical Hyphae `nodeId` / `connectorId`: `/^[a-z0-9][a-z0-9@._-]{0,63}$/`.
pub fn is_valid_node_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    if bytes.is_empty() || bytes.len() > 64 {
        return false;
    }
    if !(bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit()) {
        return false;
    }
    bytes.iter().all(|&b| {
        b.is_ascii_lowercase()
            || b.is_ascii_digit()
            || matches!(b, b'@' | b'.' | b'_' | b'-')
    })
}

/// Validates that `endpoint` is an HTTPS origin or a loopback HTTP origin (`127.0.0.1`, `localhost`, `[::1]`).
pub fn validate_endpoint_origin(endpoint: &str) -> Result<(), CryptoError> {
    let trimmed = endpoint.trim();
    if trimmed.contains(char::is_whitespace) || trimmed.contains('@') {
        return Err(CryptoError::InvalidPairing(format!(
            "invalid endpoint URL: {endpoint}"
        )));
    }
    if let Some(rest) = trimmed.strip_prefix("https://") {
        if rest.is_empty() || rest.starts_with('/') {
            return Err(CryptoError::InvalidPairing("empty https host".into()));
        }
        return Ok(());
    }
    if let Some(rest) = trimmed.strip_prefix("http://") {
        let host_port = rest.split('/').next().unwrap_or("");
        let is_loopback = host_port == "localhost"
            || host_port.starts_with("localhost:")
            || host_port == "127.0.0.1"
            || host_port.starts_with("127.0.0.1:")
            || host_port == "[::1]"
            || host_port.starts_with("[::1]:");
        if is_loopback {
            return Ok(());
        }
    }
    Err(CryptoError::InvalidPairing(format!(
        "endpoint must be https:// or loopback http:// (got {endpoint})"
    )))
}

fn parse_rfc3339(ts: &str) -> Result<i64, CryptoError> {
    parse_rfc3339_millis(ts)
}

// ============================================================================
// v2 Grants & Revocations
// ============================================================================

/// Hyphae v2 permissioned Grant payload (RFC 8785 JCS + `"hyphae/v2/grant\n"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantV2 {
    pub v: u8,
    pub id: String,
    #[serde(rename = "nodeId")]
    pub node_id: String,
    pub scopes: Vec<String>,
    #[serde(rename = "trustTier", skip_serializing_if = "Option::is_none")]
    pub trust_tier: Option<String>,
    #[serde(rename = "pairingKey", skip_serializing_if = "Option::is_none")]
    pub pairing_key: Option<OkpJwk>,
    #[serde(rename = "subjectSigningJwk", skip_serializing_if = "Option::is_none")]
    pub subject_signing_jwk: Option<OkpJwk>,
    #[serde(rename = "subjectEncryptionJwk", skip_serializing_if = "Option::is_none")]
    pub subject_encryption_jwk: Option<OkpJwk>,
    #[serde(rename = "issuedAt")]
    pub issued_at: String,
    #[serde(rename = "pairBy", skip_serializing_if = "Option::is_none")]
    pub pair_by: Option<String>,
    #[serde(rename = "expiresAt", skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
}

/// Hyphae v2 Grant Revocation payload (RFC 8785 JCS + `"hyphae/v2/revocation\n"`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationV2 {
    pub v: u8,
    #[serde(rename = "nodeId")]
    pub node_id: String,
    #[serde(rename = "grantId")]
    pub grant_id: String,
    #[serde(rename = "revokedAt")]
    pub revoked_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

fn validate_grant_v2(grant: &GrantV2) -> Result<(), CryptoError> {
    if grant.v != 2 {
        return Err(CryptoError::InvalidPairing(format!(
            "expected GrantV2 v=2, got {}",
            grant.v
        )));
    }
    if grant.id.trim().is_empty() {
        return Err(CryptoError::InvalidPairing("empty grant id".into()));
    }
    if !is_valid_node_id(&grant.node_id) {
        return Err(CryptoError::InvalidPairing(format!(
            "invalid nodeId '{}'",
            grant.node_id
        )));
    }
    if grant.scopes.is_empty() {
        return Err(CryptoError::InvalidPairing(
            "grant must contain at least one scope".into(),
        ));
    }
    if let Some(tier) = &grant.trust_tier {
        if !matches!(tier.as_str(), "org" | "peer" | "guest") {
            return Err(CryptoError::InvalidPairing(format!(
                "invalid trustTier '{tier}'"
            )));
        }
    }
    if let Some(pk) = &grant.pairing_key {
        let _ = pk.to_ed25519()?;
    }
    if let Some(sk) = &grant.subject_signing_jwk {
        let _ = sk.to_ed25519()?;
    }
    if let Some(ek) = &grant.subject_encryption_jwk {
        let _ = ek.to_x25519()?;
    }
    let issued = parse_rfc3339(&grant.issued_at)?;
    if let Some(pair_by) = &grant.pair_by {
        let pb = parse_rfc3339(pair_by)?;
        if pb <= issued {
            return Err(CryptoError::InvalidPairing(
                "grant pairBy must be after issuedAt".into(),
            ));
        }
    }
    if let Some(exp) = &grant.expires_at {
        let e = parse_rfc3339(exp)?;
        if e <= issued {
            return Err(CryptoError::InvalidPairing(
                "grant expiresAt must be after issuedAt".into(),
            ));
        }
    }
    Ok(())
}

/// Validates, canonicalizes with JCS, and signs a `GrantV2` under `"hyphae/v2/grant\n"`.
pub fn sign_grant_v2(
    grant: &GrantV2,
    issuer: &Ed25519KeyPair,
) -> Result<SignedPayload, CryptoError> {
    validate_grant_v2(grant)?;
    issuer.sign_jcs("grant", grant)
}

/// Strictly verifies a signed `GrantV2` against `issuer_pk`.
pub fn verify_grant_v2(
    signed: &SignedPayload,
    issuer_pk: &Ed25519PublicKey,
) -> Result<GrantV2, CryptoError> {
    let grant: GrantV2 = issuer_pk.verify_signed("grant", signed)?;
    validate_grant_v2(&grant)?;
    Ok(grant)
}

/// Validates, canonicalizes with JCS, and signs a `RevocationV2` under `"hyphae/v2/revocation\n"`.
pub fn sign_revocation_v2(
    rev: &RevocationV2,
    issuer: &Ed25519KeyPair,
) -> Result<SignedPayload, CryptoError> {
    if rev.v != 2 || !is_valid_node_id(&rev.node_id) || rev.grant_id.trim().is_empty() {
        return Err(CryptoError::InvalidPairing("invalid RevocationV2".into()));
    }
    let _ = parse_rfc3339(&rev.revoked_at)?;
    issuer.sign_jcs("revocation", rev)
}

/// Strictly verifies a signed `RevocationV2` against `issuer_pk`.
pub fn verify_revocation_v2(
    signed: &SignedPayload,
    issuer_pk: &Ed25519PublicKey,
) -> Result<RevocationV2, CryptoError> {
    let rev: RevocationV2 = issuer_pk.verify_signed("revocation", signed)?;
    if rev.v != 2 || !is_valid_node_id(&rev.node_id) || rev.grant_id.trim().is_empty() {
        return Err(CryptoError::InvalidPairing("invalid RevocationV2".into()));
    }
    let _ = parse_rfc3339(&rev.revoked_at)?;
    Ok(rev)
}

// ============================================================================
// v2 Org Admin-CA Invite Bundle (`am2_`)
// ============================================================================

/// Org Admin-CA paired onboarding invite bundle (`am2_<base64url>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdminInviteV2 {
    pub v: u8,
    pub router: String,
    #[serde(rename = "adminJwk")]
    pub admin_jwk: OkpJwk,
    #[serde(rename = "pairingCode")]
    pub pairing_code: String,
    #[serde(rename = "requireE2ee", skip_serializing_if = "Option::is_none")]
    pub require_e2ee: Option<bool>,
}

fn validate_admin_invite(invite: &AdminInviteV2) -> Result<(), CryptoError> {
    if invite.v != 2 {
        return Err(CryptoError::InvalidPairing(format!(
            "expected am2_ v=2, got {}",
            invite.v
        )));
    }
    validate_endpoint_origin(&invite.router)?;
    let admin_pk = invite.admin_jwk.to_ed25519()?;
    let code = invite.pairing_code.trim();
    if code.is_empty() {
        return Err(CryptoError::InvalidPairing("empty pairingCode".into()));
    }
    // If pairingCode is a t3mp1_ code, cross-check embedded admin fingerprint against adminJwk!
    if code.starts_with("t3mp1_") {
        let parsed = parse_pairing_code_v1(code)?;
        if parsed.admin_fingerprint != admin_pk.fingerprint() {
            return Err(CryptoError::InvalidPairing(
                "t3mp1_ admin fingerprint does not match adminJwk".into(),
            ));
        }
    }
    Ok(())
}

/// Encodes a validated `AdminInviteV2` into an `am2_<base64url>` invite string.
pub fn encode_am2(invite: &AdminInviteV2) -> Result<String, CryptoError> {
    validate_admin_invite(invite)?;
    let canon = to_canonical_json(invite)?;
    Ok(format!("{AM2_PREFIX}{}", URL_SAFE_NO_PAD.encode(canon.as_bytes())))
}

/// Decodes and strictly validates an `am2_<base64url>` invite string.
pub fn decode_am2(token: &str) -> Result<AdminInviteV2, CryptoError> {
    let trimmed = token.trim();
    let encoded = trimmed
        .strip_prefix(AM2_PREFIX)
        .ok_or_else(|| CryptoError::InvalidPairing("expected 'am2_' prefix".into()))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| CryptoError::InvalidPairing(format!("invalid am2_ base64url: {e}")))?;
    let invite: AdminInviteV2 = serde_json::from_slice(&bytes)?;
    validate_admin_invite(&invite)?;
    Ok(invite)
}

// ============================================================================
// v2 Direct P2P Mutual Pairing (`hp2p1_`)
// ============================================================================

/// Out-of-band direct P2P mutual pairing offer token (`hp2p1_<base64url>`).
/// Embeds Alice's OKP JWKs (zero-TOFU) and a 160-bit random pairing secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct P2pOfferToken {
    pub v: u8,
    #[serde(rename = "offerId")]
    pub offer_id: String,
    #[serde(rename = "nodeId")]
    pub node_id: String,
    pub endpoint: String,
    #[serde(rename = "signingJwk")]
    pub signing_jwk: OkpJwk,
    #[serde(rename = "encryptionJwk")]
    pub encryption_jwk: OkpJwk,
    /// Base64url-encoded 20-byte (160-bit) pairing secret.
    pub secret: String,
    #[serde(rename = "offeredScopes")]
    pub offered_scopes: Vec<String>,
    #[serde(rename = "requestedScopes")]
    pub requested_scopes: Vec<String>,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
}

/// Bob's pairing response payload sent to `POST /v1/p2p/pair/<offerId>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct P2pPairResponsePayload {
    pub v: u8,
    #[serde(rename = "offerId")]
    pub offer_id: String,
    #[serde(rename = "bobNodeId")]
    pub bob_node_id: String,
    #[serde(rename = "bobEndpoint", skip_serializing_if = "Option::is_none")]
    pub bob_endpoint: Option<String>,
    #[serde(rename = "bobSigningJwk")]
    pub bob_signing_jwk: OkpJwk,
    #[serde(rename = "bobEncryptionJwk")]
    pub bob_encryption_jwk: OkpJwk,
    #[serde(rename = "bobGrantToAlice")]
    pub bob_grant_to_alice: SignedPayload,
}

/// Signed + HKDF-MAC-bound P2P pairing response (proves possession of both the 160-bit OOB secret and Bob's Ed25519 key).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct P2pPairResponse {
    /// JCS-canonicalized `P2pPairResponsePayload`.
    pub payload: String,
    /// Base64url HMAC-SHA256(HKDF(secret, "hyphae/v2/p2p-pair", offerId), "hyphae/v2/p2p-bind\n" || payload).
    #[serde(rename = "bindingMac")]
    pub binding_mac: String,
    /// Base64url Ed25519(bobSigningKey, "hyphae/v2/p2p-self\n" || payload).
    #[serde(rename = "selfSig")]
    pub self_sig: String,
}

/// Alice's confirmation returned in `200 OK` after verifying Bob's `P2pPairResponse`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct P2pPairConfirmation {
    #[serde(rename = "offerId")]
    pub offer_id: String,
    #[serde(rename = "aliceGrantToBob")]
    pub alice_grant_to_bob: SignedPayload,
}

/// Verified outcome returned to Alice upon accepting Bob's `P2pPairResponse`.
#[derive(Debug, Clone)]
pub struct VerifiedP2pPeer {
    pub bob_node_id: String,
    pub bob_endpoint: Option<String>,
    pub bob_signing_pk: Ed25519PublicKey,
    pub bob_encryption_pk: crate::keys::X25519PublicKey,
    pub bob_grant_to_alice: GrantV2,
}

fn decode_p2p_secret(secret_b64: &str) -> Result<Zeroizing<[u8; P2P_SECRET_BYTES]>, CryptoError> {
    let raw = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(secret_b64)
            .map_err(|e| CryptoError::InvalidPairing(format!("invalid hp2p1_ secret: {e}")))?,
    );
    if raw.len() != P2P_SECRET_BYTES {
        return Err(CryptoError::InvalidPairing(format!(
            "hp2p1_ secret must be {P2P_SECRET_BYTES} bytes (160 bits), got {}",
            raw.len()
        )));
    }
    let mut out = Zeroizing::new([0u8; P2P_SECRET_BYTES]);
    out.copy_from_slice(&raw);
    Ok(out)
}

fn validate_p2p_offer(offer: &P2pOfferToken) -> Result<(), CryptoError> {
    if offer.v != 1 {
        return Err(CryptoError::InvalidPairing(format!(
            "expected hp2p1_ v=1, got {}",
            offer.v
        )));
    }
    if offer.offer_id.trim().is_empty() {
        return Err(CryptoError::InvalidPairing("empty offerId".into()));
    }
    if !is_valid_node_id(&offer.node_id) {
        return Err(CryptoError::InvalidPairing(format!(
            "invalid nodeId '{}'",
            offer.node_id
        )));
    }
    validate_endpoint_origin(&offer.endpoint)?;
    let _ = offer.signing_jwk.to_ed25519()?;
    let _ = offer.encryption_jwk.to_x25519()?;
    let _ = decode_p2p_secret(&offer.secret)?;
    let _ = parse_rfc3339(&offer.expires_at)?;
    Ok(())
}

fn derive_p2p_binding_key(
    secret: &[u8; P2P_SECRET_BYTES],
    offer_id: &str,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    hkdf_sha256(b"hyphae/v2/p2p-pair", secret, offer_id.as_bytes(), 32)
}

fn compute_p2p_binding_mac(
    secret: &[u8; P2P_SECRET_BYTES],
    offer_id: &str,
    payload: &str,
) -> Result<[u8; 32], CryptoError> {
    let key_bytes = derive_p2p_binding_key(secret, offer_id)?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
    let mut msg = Vec::with_capacity(20 + payload.len());
    msg.extend_from_slice(b"hyphae/v2/p2p-bind\n");
    msg.extend_from_slice(payload.as_bytes());
    let tag = hmac::sign(&key, &msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(tag.as_ref());
    Ok(out)
}

fn verify_p2p_binding_mac(
    secret: &[u8; P2P_SECRET_BYTES],
    offer_id: &str,
    payload: &str,
    provided_mac: &[u8],
) -> Result<(), CryptoError> {
    let key_bytes = derive_p2p_binding_key(secret, offer_id)?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, &key_bytes);
    let mut msg = Vec::with_capacity(20 + payload.len());
    msg.extend_from_slice(b"hyphae/v2/p2p-bind\n");
    msg.extend_from_slice(payload.as_bytes());
    hmac::verify(&key, &msg, provided_mac)
        .map_err(|_| CryptoError::InvalidSignature("P2P pairing binding MAC mismatch".into()))
}

/// Generates a fresh `P2pOfferToken` with a CSPRNG 160-bit pairing secret and Alice's OKP JWKs.
#[allow(clippy::too_many_arguments)]
pub fn create_p2p_offer(
    offer_id: &str,
    alice_node_id: &str,
    endpoint: &str,
    alice_keys: &NodeIdentityKeys,
    offered_scopes: Vec<String>,
    requested_scopes: Vec<String>,
    expires_at: &str,
) -> Result<P2pOfferToken, CryptoError> {
    let rng = SystemRandom::new();
    let mut secret = Zeroizing::new([0u8; P2P_SECRET_BYTES]);
    rng.fill(&mut *secret)
        .map_err(|_| CryptoError::Hpke("OS CSPRNG failure".into()))?;

    let offer = P2pOfferToken {
        v: 1,
        offer_id: offer_id.to_string(),
        node_id: alice_node_id.to_string(),
        endpoint: endpoint.to_string(),
        signing_jwk: alice_keys.signing_jwk(),
        encryption_jwk: alice_keys.encryption_jwk(),
        secret: URL_SAFE_NO_PAD.encode(*secret),
        offered_scopes,
        requested_scopes,
        expires_at: expires_at.to_string(),
    };
    validate_p2p_offer(&offer)?;
    Ok(offer)
}

/// Encodes a validated `P2pOfferToken` into an `hp2p1_<base64url>` string.
pub fn encode_hp2p1(offer: &P2pOfferToken) -> Result<String, CryptoError> {
    validate_p2p_offer(offer)?;
    let canon = to_canonical_json(offer)?;
    Ok(format!("{HP2P1_PREFIX}{}", URL_SAFE_NO_PAD.encode(canon.as_bytes())))
}

/// Decodes and strictly validates an `hp2p1_<base64url>` pairing offer token.
pub fn decode_hp2p1(token: &str) -> Result<P2pOfferToken, CryptoError> {
    let trimmed = token.trim();
    let encoded = trimmed
        .strip_prefix(HP2P1_PREFIX)
        .ok_or_else(|| CryptoError::InvalidPairing("expected 'hp2p1_' prefix".into()))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| CryptoError::InvalidPairing(format!("invalid hp2p1_ base64url: {e}")))?;
    let offer: P2pOfferToken = serde_json::from_slice(&bytes)?;
    validate_p2p_offer(&offer)?;
    Ok(offer)
}

/// Bob constructs a signed and HKDF-MAC-authenticated `P2pPairResponse` to Alice's `offer`.
pub fn create_p2p_response(
    offer: &P2pOfferToken,
    bob_node_id: &str,
    bob_endpoint: Option<&str>,
    bob_keys: &NodeIdentityKeys,
    bob_grant_to_alice: &GrantV2,
) -> Result<P2pPairResponse, CryptoError> {
    validate_p2p_offer(offer)?;
    if !is_valid_node_id(bob_node_id) {
        return Err(CryptoError::InvalidPairing(format!(
            "invalid bobNodeId '{bob_node_id}'"
        )));
    }
    if let Some(ep) = bob_endpoint {
        validate_endpoint_origin(ep)?;
    }
    if bob_grant_to_alice.node_id != offer.node_id {
        return Err(CryptoError::InvalidPairing(
            "bobGrantToAlice.nodeId must match offer.nodeId".into(),
        ));
    }

    let signed_grant = sign_grant_v2(bob_grant_to_alice, &bob_keys.signing)?;
    let body = P2pPairResponsePayload {
        v: 1,
        offer_id: offer.offer_id.clone(),
        bob_node_id: bob_node_id.to_string(),
        bob_endpoint: bob_endpoint.map(ToOwned::to_owned),
        bob_signing_jwk: bob_keys.signing_jwk(),
        bob_encryption_jwk: bob_keys.encryption_jwk(),
        bob_grant_to_alice: signed_grant,
    };
    let payload = to_canonical_json(&body)?;
    let secret = decode_p2p_secret(&offer.secret)?;
    let mac = compute_p2p_binding_mac(&secret, &offer.offer_id, &payload)?;
    let self_sig = bob_keys
        .signing
        .sign_domain_b64("p2p-self", payload.as_bytes());

    Ok(P2pPairResponse {
        payload,
        binding_mac: URL_SAFE_NO_PAD.encode(mac),
        self_sig,
    })
}

/// Alice verifies Bob's `P2pPairResponse` against her local `offer`:
/// checks expiry, constant-time HKDF-HMAC binding MAC, Bob's JWKs, Bob's Ed25519 self-sig,
/// and Bob's signed grant targeting Alice.
pub fn verify_p2p_response(
    offer: &P2pOfferToken,
    response: &P2pPairResponse,
    now_unix_ms: i64,
) -> Result<VerifiedP2pPeer, CryptoError> {
    validate_p2p_offer(offer)?;
    let expires_at = parse_rfc3339(&offer.expires_at)?;
    if now_unix_ms > expires_at {
        return Err(CryptoError::InvalidPairing("P2P offer has expired".into()));
    }

    // 1. Constant-time verification of HKDF binding MAC (proves possession of 160-bit OOB secret).
    let secret = decode_p2p_secret(&offer.secret)?;
    let provided_mac = URL_SAFE_NO_PAD
        .decode(&response.binding_mac)
        .map_err(|e| CryptoError::InvalidPairing(format!("invalid bindingMac base64url: {e}")))?;
    verify_p2p_binding_mac(&secret, &offer.offer_id, &response.payload, &provided_mac)?;

    // 2. Parse and validate Bob's payload and JWKs.
    let body: P2pPairResponsePayload = serde_json::from_str(&response.payload)?;
    if body.v != 1 || body.offer_id != offer.offer_id {
        return Err(CryptoError::InvalidPairing(
            "P2P response version or offerId mismatch".into(),
        ));
    }
    if !is_valid_node_id(&body.bob_node_id) {
        return Err(CryptoError::InvalidPairing(format!(
            "invalid bobNodeId '{}'",
            body.bob_node_id
        )));
    }
    if let Some(ep) = &body.bob_endpoint {
        validate_endpoint_origin(ep)?;
    }

    let bob_signing_pk = body.bob_signing_jwk.to_ed25519()?;
    let bob_encryption_pk = body.bob_encryption_jwk.to_x25519()?;

    // 3. Verify Bob's Ed25519 self-signature over the response payload.
    bob_signing_pk.verify_domain_b64("p2p-self", response.payload.as_bytes(), &response.self_sig)?;

    // 4. Verify Bob's grant to Alice was signed by Bob's signing key and targets Alice.
    let bob_grant_to_alice = verify_grant_v2(&body.bob_grant_to_alice, &bob_signing_pk)?;
    if bob_grant_to_alice.node_id != offer.node_id {
        return Err(CryptoError::InvalidPairing(
            "bobGrantToAlice targets wrong nodeId".into(),
        ));
    }

    Ok(VerifiedP2pPeer {
        bob_node_id: body.bob_node_id,
        bob_endpoint: body.bob_endpoint,
        bob_signing_pk,
        bob_encryption_pk,
        bob_grant_to_alice,
    })
}

/// Alice constructs her confirmation carrying her signed grant to Bob.
pub fn create_p2p_confirmation(
    offer_id: &str,
    alice_grant_to_bob: &GrantV2,
    alice_signing: &Ed25519KeyPair,
) -> Result<P2pPairConfirmation, CryptoError> {
    let signed_grant = sign_grant_v2(alice_grant_to_bob, alice_signing)?;
    Ok(P2pPairConfirmation {
        offer_id: offer_id.to_string(),
        alice_grant_to_bob: signed_grant,
    })
}

/// Bob verifies Alice's confirmation against Alice's zero-TOFU JWK pinned in the out-of-band `hp2p1_` offer.
pub fn verify_p2p_confirmation(
    offer: &P2pOfferToken,
    confirmation: &P2pPairConfirmation,
    expected_bob_node_id: &str,
) -> Result<GrantV2, CryptoError> {
    validate_p2p_offer(offer)?;
    if confirmation.offer_id != offer.offer_id {
        return Err(CryptoError::InvalidPairing(
            "confirmation offerId mismatch".into(),
        ));
    }
    let alice_pk = offer.signing_jwk.to_ed25519()?;
    let grant = verify_grant_v2(&confirmation.alice_grant_to_bob, &alice_pk)?;
    if grant.node_id != expected_bob_node_id {
        return Err(CryptoError::InvalidPairing(
            "aliceGrantToBob targets wrong nodeId".into(),
        ));
    }
    Ok(grant)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compat_v1::issue_grant_v1;
    use crate::rfc3339::now_unix_ms;

    #[test]
    fn am2_encode_decode_and_t3mp1_fingerprint_check() {
        let admin = Ed25519KeyPair::generate().unwrap();
        let issued = issue_grant_v1(&admin, "alice@macbook", &["*"], 60_000, now_unix_ms()).unwrap();

        let invite = AdminInviteV2 {
            v: 2,
            router: "https://mesh.acme.internal".into(),
            admin_jwk: admin.to_jwk(),
            pairing_code: issued.code,
            require_e2ee: Some(true),
        };
        let encoded = encode_am2(&invite).unwrap();
        assert!(encoded.starts_with("am2_"));
        let decoded = decode_am2(&encoded).unwrap();
        assert_eq!(decoded, invite);

        // Reject remote plaintext http://
        let bad_http = AdminInviteV2 {
            router: "http://mesh.acme.internal".into(),
            ..invite.clone()
        };
        assert!(encode_am2(&bad_http).is_err());

        // Reject mismatched admin key vs t3mp1_ fingerprint
        let wrong_admin = Ed25519KeyPair::generate().unwrap();
        let bad_fp = AdminInviteV2 {
            admin_jwk: wrong_admin.to_jwk(),
            ..invite
        };
        assert!(encode_am2(&bad_fp).is_err());
    }

    #[test]
    fn hp2p1_mutual_pairing_handshake_and_mutations() {
        let alice = NodeIdentityKeys::generate().unwrap();
        let bob = NodeIdentityKeys::generate().unwrap();
        let mallory = NodeIdentityKeys::generate().unwrap();

        let now = parse_rfc3339_millis("2026-11-24T12:00:00Z").unwrap();
        let offer = create_p2p_offer(
            "offer-42",
            "alice@macbook",
            "https://alice.tailnet.ts.net",
            &alice,
            vec!["dm:send".into(), "dm:receive".into()],
            vec!["dm:send".into(), "kv:read=pair/*".into()],
            "2026-11-24T13:00:00Z",
        )
        .unwrap();

        let token = encode_hp2p1(&offer).unwrap();
        assert!(token.starts_with("hp2p1_"));
        let bob_decoded = decode_hp2p1(&token).unwrap();
        assert_eq!(bob_decoded, offer);

        let bob_grant = GrantV2 {
            v: 2,
            id: "grant-bob-to-alice".into(),
            node_id: "alice@macbook".into(),
            scopes: vec!["dm:send".into(), "kv:read=pair/*".into()],
            trust_tier: Some("peer".into()),
            pairing_key: None,
            subject_signing_jwk: Some(bob_decoded.signing_jwk.clone()),
            subject_encryption_jwk: Some(bob_decoded.encryption_jwk.clone()),
            issued_at: "2026-11-24T12:05:00Z".into(),
            pair_by: None,
            expires_at: Some("2027-11-24T12:05:00Z".into()),
        };

        let resp = create_p2p_response(&bob_decoded, "bob@laptop", None, &bob, &bob_grant).unwrap();
        let verified = verify_p2p_response(&offer, &resp, now).unwrap();
        assert_eq!(verified.bob_node_id, "bob@laptop");
        assert_eq!(verified.bob_signing_pk, bob.signing.public_key());
        assert_eq!(verified.bob_encryption_pk, bob.encryption.public_key());

        // 1-bit flip in bindingMac fails
        let mut bad_mac = resp.clone();
        let mut mac_bytes = URL_SAFE_NO_PAD.decode(&bad_mac.binding_mac).unwrap();
        mac_bytes[0] ^= 0x01;
        bad_mac.binding_mac = URL_SAFE_NO_PAD.encode(mac_bytes);
        assert!(verify_p2p_response(&offer, &bad_mac, now).is_err());

        // Expired offer fails
        let after_exp = parse_rfc3339_millis("2026-11-24T14:00:00Z").unwrap();
        assert!(verify_p2p_response(&offer, &resp, after_exp).is_err());

        // Confirmation from Alice verified against pinned zero-TOFU JWK
        let alice_grant = GrantV2 {
            v: 2,
            id: "grant-alice-to-bob".into(),
            node_id: "bob@laptop".into(),
            scopes: vec!["dm:send".into(), "dm:receive".into()],
            trust_tier: Some("peer".into()),
            pairing_key: None,
            subject_signing_jwk: Some(bob.signing_jwk()),
            subject_encryption_jwk: Some(bob.encryption_jwk()),
            issued_at: "2026-11-24T12:05:01Z".into(),
            pair_by: None,
            expires_at: None,
        };
        let conf = create_p2p_confirmation(&offer.offer_id, &alice_grant, &alice.signing).unwrap();
        let verified_grant = verify_p2p_confirmation(&bob_decoded, &conf, "bob@laptop").unwrap();
        assert_eq!(verified_grant.id, "grant-alice-to-bob");

        // Mallory forging confirmation fails
        let forged_conf =
            create_p2p_confirmation(&offer.offer_id, &alice_grant, &mallory.signing).unwrap();
        assert!(verify_p2p_confirmation(&bob_decoded, &forged_conf, "bob@laptop").is_err());
    }

    #[test]
    fn v2_revocation_sign_and_verify() {
        let admin = Ed25519KeyPair::generate().unwrap();
        let rev = RevocationV2 {
            v: 2,
            node_id: "alice@lost-laptop".into(),
            grant_id: "grant-999".into(),
            revoked_at: "2026-11-24T15:00:00Z".into(),
            reason: Some("device_lost".into()),
        };
        let signed = sign_revocation_v2(&rev, &admin).unwrap();
        let verified = verify_revocation_v2(&signed, &admin.public_key()).unwrap();
        assert_eq!(verified, rev);
    }
}
