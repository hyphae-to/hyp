//! Hyphae v2 Human Authority & Zero-Knowledge Sealed Drops (`human.drop.v1`, `hdrop1_`, `hcert1_`).
//!
//! Tier 1 pure-Rust Ed25519 + RFC 9180 HPKE (`DHKEM(X25519, HKDF-SHA256)` + `HKDF-SHA256` +
//! `AES-256-GCM`) + power-of-2 bucket padding (`256 B .. 32 KiB`) + RFC 8785 JCS.
//!
//! Security invariants:
//! - Mode B Sign-then-Pad-then-HPKE hides `humanId`, `humanKid`, `nodeId`, `kind`, and payload
//!   bytes from blind relays; only an opaque `HumanDropEnvelopeV1` travels on the wire.
//! - Audience (`nodeId`, `nodeEncKid`, optional `handle`) and `dropId` are signed inside
//!   `HumanClaimV1` AND bound into HPKE `info` and AEAD `aad` (defeating surreptitious forwarding).
//! - Fail-closed verification enforces TTL (`<= 15 min`), clock skew (`60 s`), monotonic
//!   `authEpoch >= min_auth_epoch`, strict Ed25519 signature checks (rejecting small-order /
//!   non-canonical points), and the reserved system-secret name denylist.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::e2ee::{pad_bucket, unpad_bucket};
use crate::error::CryptoError;
use crate::hpke::{self, hkdf_sha256};
use crate::jcs::to_canonical_json;
use crate::keys::{
    decode_raw_key_32, Ed25519KeyPair, Ed25519PublicKey, OkpJwk, X25519KeyPair, X25519PublicKey,
};
use crate::keystore::validate_secret_name;
use crate::pairing::is_valid_node_id;
use crate::rfc3339::parse_rfc3339_millis;

/// Domain separation prefix for inner `HumanClaimV1` Ed25519 signatures.
pub const HUMAN_CLAIM_DOMAIN: &[u8] = b"hyphae/v2/human-claim\n";

/// Domain separation prefix for human-signed `NodeCertV1` (`hcert1_`) Ed25519 signatures.
pub const HUMAN_NODE_CERT_DOMAIN: &[u8] = b"hyphae/v2/human-node-cert\n";

/// Domain separation prefix for `HumanRevocationV1` Ed25519 signatures.
pub const HUMAN_REVOCATION_DOMAIN: &[u8] = b"hyphae/v2/human-revocation\n";

/// Wire cipher suite identifier for sealed human drops.
pub const HUMAN_DROP_SUITE_V1: &str = "human.drop.v1";

/// Prefix for RFC 9180 HPKE `info` binding (`HUMAN_DROP_HPKE_INFO_PREFIX || recipientEncKid || "\n" || dropId`).
pub const HUMAN_DROP_HPKE_INFO_PREFIX: &str = "hyphae/v2/human-drop\n1\n";

/// Prefix for RFC 9180 HPKE `aad` binding (`HUMAN_DROP_HPKE_AAD_PREFIX || recipientEncKid || "\n" || dropId`).
pub const HUMAN_DROP_HPKE_AAD_PREFIX: &str = "hyphae/v2/human-drop-aad\nhuman.drop.v1\n";

/// Prefix for WebAuthn Passkey `prf` SHA-256 input derivation.
pub const HUMAN_PRF_INPUT_PREFIX: &str = "hyphae/v2/human-prf-input\n";

/// Salt for HKDF-SHA256 derivation of a Passkey `prf` Ed25519 seed.
pub const HUMAN_PRF_HKDF_SALT: &[u8] = b"hyphae/v2/human-prf-ed25519";

/// Salt for HKDF-SHA256 derivation of a companion Passkey `prf` X25519 encryption key.
pub const HUMAN_PRF_X25519_SALT: &[u8] = b"hyphae/v2/human-prf-x25519";

/// Wire cipher suite identifier for encrypted directive drafts (`encDraft` in `#drop=`).
pub const HUMAN_DRAFT_SUITE: &str = "human.draft.v1";

/// Prefix for RFC 9180 HPKE `info` binding of encrypted human directive drafts.
pub const HUMAN_DRAFT_INFO_PREFIX: &[u8] = b"hyphae/v2/human-draft\n";

/// Maximum Unicode scalar value count for an encrypted directive draft body.
pub const MAX_HUMAN_DRAFT_CHARS: usize = 512;

/// Maximum Unicode scalar value count for an optional encrypted directive draft context label.
pub const MAX_HUMAN_DRAFT_CONTEXT_CHARS: usize = 160;

/// Domain separation prefix for attached Ed25519 signatures over local ingested events (`hyphaesig`).
pub const LOCAL_EVENT_SIG_DOMAIN: &[u8] = b"hyphae/v2/local-event\n";

/// Armored prefix for offline/copy-paste sealed drops (`hdrop1_<base64url(JCS)>`).
pub const HDROP1_PREFIX: &str = "hdrop1_";

/// Armored prefix for human-signed node certificates (`hcert1_<base64url(JCS)>`).
pub const HCERT1_PREFIX: &str = "hcert1_";

/// Hard upper bound on `expiresAt - issuedAt` for any `HumanClaimV1` (15 minutes).
pub const MAX_CLAIM_TTL_MS: i64 = 900_000;

/// Maximum tolerated forward clock skew on `issuedAt` (1 minute).
pub const CLOCK_SKEW_MS: i64 = 60_000;

const RESERVED_SECRET_PREFIXES: &[&str] = &[
    "node-sign-",
    "node-enc-",
    "id-sign-",
    "id-enc-",
    "admin-ca-",
    "gate-policy-",
    "human-admin-",
    "human-authority-",
    "auth-token-",
    "staged-join-token-",
    "pair-",
    "p2p-offer-",
];

const RESERVED_SECRET_EXACT: &[&str] = &[
    "admin-ca",
    "gate-policy",
    "gate-policy-hmac",
    "gate_policy_hmac",
    "gate-policy-hmac-key",
    "human-admin",
    "human-authority",
    "auth-token",
    "t3-auth-token",
    "t3-session-token",
    "staged-join-token",
    "openclaw-hooks-token",
    "hyphae-admin-pubkey",
    "daemon-session-token-key",
];

/// Supported MVP sealed drop kinds (`directive` or `secret`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HumanDropKind {
    Directive,
    Secret,
}

impl HumanDropKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Directive => "directive",
            Self::Secret => "secret",
        }
    }
}

/// Target audience bound inside `HumanClaimV1` (defeating surreptitious forwarding).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HumanAudience {
    pub node_id: String,
    pub node_enc_kid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
}

/// Target secret metadata carried when `HumanClaimV1::kind == HumanDropKind::Secret`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretDropSpec {
    pub name: String,
    pub overwrite: bool,
}

/// Canonical inner human claim signed under `HUMAN_CLAIM_DOMAIN` and sealed inside `HumanDropEnvelopeV1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HumanClaimV1 {
    pub v: u32,
    pub kind: HumanDropKind,
    pub claim_id: String,
    pub human_id: String,
    pub human_kid: String,
    pub auth_epoch: u64,
    pub issued_at: String,
    pub expires_at: String,
    pub drop_id: String,
    pub audience: HumanAudience,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_spec: Option<SecretDropSpec>,
    pub body: String,
}

impl Zeroize for HumanClaimV1 {
    fn zeroize(&mut self) {
        self.body.zeroize();
    }
}

/// Inner Ed25519-signed canonical JSON claim (`payload` is RFC 8785 JCS of `HumanClaimV1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedHumanClaimV1 {
    pub payload: String,
    pub sig: String,
}

impl Zeroize for SignedHumanClaimV1 {
    fn zeroize(&mut self) {
        self.payload.zeroize();
    }
}

/// Opaque wire envelope for a sealed human drop (zero `humanKid`, `nodeId`, or `kind` exposed!).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HumanDropEnvelopeV1 {
    pub v: u32,
    pub suite: String,
    pub drop_id: String,
    pub enc: String,
    pub ct: String,
}

/// Human-signed node key certificate payload (`NodeCertV1`, pins node signing & encryption JWKs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeCertPayloadV1 {
    pub v: u32,
    pub node_id: String,
    pub signing_jwk: OkpJwk,
    pub encryption_jwk: OkpJwk,
    pub human_id: String,
    pub human_kid: String,
    pub auth_epoch: u64,
    pub issued_at: String,
    pub expires_at: String,
}

/// Signed `NodeCertV1` envelope (armored as `hcert1_<base64url(JCS)>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedNodeCertV1 {
    pub payload: String,
    pub sig: String,
}

/// Human key revocation & monotonic `min_auth_epoch` bump payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HumanRevocationPayloadV1 {
    pub v: u32,
    pub human_id: String,
    pub revoked_kid: String,
    pub new_min_auth_epoch: u64,
    pub revoked_at: String,
    pub reason: String,
    pub issuer_kid: String,
}

/// Signed `HumanRevocationV1` envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedHumanRevocationV1 {
    pub payload: String,
    pub sig: String,
}

/// Plaintext payload sealed inside `EncryptedHumanDraftV1` (`encDraft` in `#drop=` links).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HumanDraftPayloadV1 {
    pub v: u8,
    pub node_id: String,
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
    pub created_at: String,
}

impl Zeroize for HumanDraftPayloadV1 {
    fn zeroize(&mut self) {
        self.text.zeroize();
        if let Some(ctx) = &mut self.context {
            ctx.zeroize();
        }
    }
}

/// HPKE-sealed directive draft prefill (`human.draft.v1`) encrypted to the human's Passkey-PRF X25519 key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedHumanDraftV1 {
    pub v: u8,
    pub suite: String,
    pub recipient_kid: String,
    pub enc: String,
    pub ct: String,
}

// ============================================================================
// Context Builders, PRF Derivation & Denylist Helpers
// ============================================================================

/// Builds the exact RFC 9180 HPKE `info` bytes for `human.drop.v1`:
/// `"hyphae/v2/human-drop\n1\n" || recipientEncKid || "\n" || dropId`.
pub fn human_drop_hpke_info(recipient_enc_kid: &str, drop_id: &str) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(HUMAN_DROP_HPKE_INFO_PREFIX.len() + recipient_enc_kid.len() + 1 + drop_id.len());
    out.extend_from_slice(HUMAN_DROP_HPKE_INFO_PREFIX.as_bytes());
    out.extend_from_slice(recipient_enc_kid.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(drop_id.as_bytes());
    out
}

/// Builds the exact RFC 9180 HPKE `aad` bytes for `human.drop.v1`:
/// `"hyphae/v2/human-drop-aad\nhuman.drop.v1\n" || recipientEncKid || "\n" || dropId`.
pub fn human_drop_hpke_aad(recipient_enc_kid: &str, drop_id: &str) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(HUMAN_DROP_HPKE_AAD_PREFIX.len() + recipient_enc_kid.len() + 1 + drop_id.len());
    out.extend_from_slice(HUMAN_DROP_HPKE_AAD_PREFIX.as_bytes());
    out.extend_from_slice(recipient_enc_kid.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(drop_id.as_bytes());
    out
}

/// Computes the deterministic 32-byte WebAuthn `prf.eval.first` input:
/// `SHA-256("hyphae/v2/human-prf-input\n" || humanId || "\n" || prfSalt)`.
pub fn human_prf_input(human_id: &str, prf_salt: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HUMAN_PRF_INPUT_PREFIX.as_bytes());
    hasher.update(human_id.as_bytes());
    hasher.update(b"\n");
    hasher.update(prf_salt.as_bytes());
    hasher.finalize().into()
}

fn build_prf_hkdf_info(human_id: &str, auth_epoch: u64) -> Result<Vec<u8>, CryptoError> {
    if !is_valid_human_id(human_id) {
        return Err(CryptoError::InvalidKey(format!(
            "invalid humanId '{human_id}'"
        )));
    }
    if auth_epoch == 0 {
        return Err(CryptoError::InvalidKey(
            "authEpoch must be >= 1 for PRF key derivation".into(),
        ));
    }

    let mut info = Vec::with_capacity(human_id.len() + 1 + 8);
    info.extend_from_slice(human_id.as_bytes());
    info.push(b'\n');
    info.extend_from_slice(&auth_epoch.to_be_bytes());
    Ok(info)
}

/// Deterministically derives an Ed25519 signing keypair from a 32-byte WebAuthn `prf` output:
/// ```text
/// ed25519_seed = HKDF-SHA256(
///     salt = "hyphae/v2/human-prf-ed25519",
///     ikm  = prf_output_32,
///     info = humanId || "\n" || authEpoch_u64_be,
///     L    = 32
/// )
/// ```
/// Matches `site/drop/crypto.js` byte-for-byte.
pub fn derive_prf_ed25519_keypair(
    prf_output_32: &[u8; 32],
    human_id: &str,
    auth_epoch: u64,
) -> Result<Ed25519KeyPair, CryptoError> {
    let info = build_prf_hkdf_info(human_id, auth_epoch)?;
    let derived = hkdf_sha256(HUMAN_PRF_HKDF_SALT, prf_output_32, &info, 32)?;
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&derived);
    Ed25519KeyPair::from_seed(*seed)
}

/// Deterministically derives a companion X25519 encryption keypair from a 32-byte WebAuthn `prf`
/// output:
/// ```text
/// x25519_seed = HKDF-SHA256(
///     salt = "hyphae/v2/human-prf-x25519",
///     ikm  = prf_output_32,
///     info = humanId || "\n" || authEpoch_u64_be,
///     L    = 32
/// )
/// ```
/// Uses the exact same HKDF `info` construction as [`derive_prf_ed25519_keypair`]; only the salt
/// distinguishes Ed25519 vs X25519, so rotating `auth_epoch` rotates both keys together.
/// Matches `site/drop/crypto.js` byte-for-byte.
pub fn derive_prf_x25519_keypair(
    prf_output_32: &[u8; 32],
    human_id: &str,
    auth_epoch: u64,
) -> Result<X25519KeyPair, CryptoError> {
    let info = build_prf_hkdf_info(human_id, auth_epoch)?;
    let derived = hkdf_sha256(HUMAN_PRF_X25519_SALT, prf_output_32, &info, 32)?;
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&derived);
    X25519KeyPair::from_bytes(*seed)
}

/// Fail-closed case-insensitive denylist rejecting Hyphae internal system secret names.
///
/// Rejects: `node-sign-*`, `node-enc-*`, `id-sign-*`, `id-enc-*`, `admin-ca-*`,
/// `gate-policy-*`, `human-admin-*`, `human-authority-*`, `auth-token-*`,
/// `t3-auth-token`, `t3-session-token`, `staged-join-token`, and `staged-join-token-*`.
pub fn is_reserved_secret_name(name: &str) -> bool {
    let lower = name.trim().to_ascii_lowercase();
    RESERVED_SECRET_EXACT.contains(&lower.as_str())
        || RESERVED_SECRET_PREFIXES
            .iter()
            .any(|prefix| lower.starts_with(prefix))
}

// ============================================================================
// Validation & Domain-Separated Ed25519 Signing Helpers
// ============================================================================

fn is_valid_human_id(id: &str) -> bool {
    is_valid_node_id(id)
}

fn is_valid_handle(handle: &str) -> bool {
    let b = handle.as_bytes();
    if b.is_empty() || b.len() > 64 {
        return false;
    }
    if !(b[0].is_ascii_lowercase() || b[0].is_ascii_digit()) {
        return false;
    }
    b.iter()
        .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-'))
}

fn is_valid_token_id(id: &str, allow_empty: bool) -> bool {
    if id.is_empty() {
        return allow_empty;
    }
    id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
}

fn sign_with_domain(signer: &Ed25519KeyPair, domain: &[u8], payload: &[u8]) -> String {
    let mut msg = Zeroizing::new(Vec::with_capacity(domain.len() + payload.len()));
    msg.extend_from_slice(domain);
    msg.extend_from_slice(payload);
    let sig = signer.sign_raw(&msg);
    URL_SAFE_NO_PAD.encode(sig)
}

fn verify_with_domain(
    pk: &Ed25519PublicKey,
    domain: &[u8],
    payload: &[u8],
    sig_b64: &str,
) -> Result<(), CryptoError> {
    let sig = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| CryptoError::InvalidSignature(format!("invalid base64url sig: {e}")))?;
    let mut msg = Zeroizing::new(Vec::with_capacity(domain.len() + payload.len()));
    msg.extend_from_slice(domain);
    msg.extend_from_slice(payload);
    pk.verify_raw(&msg, &sig)
}

fn validate_claim_fields(claim: &HumanClaimV1) -> Result<(i64, i64), CryptoError> {
    if claim.v != 1 {
        return Err(CryptoError::InvalidEnvelope(format!(
            "unsupported HumanClaimV1 version {} (expected 1)",
            claim.v
        )));
    }
    if !is_valid_token_id(&claim.claim_id, false) {
        return Err(CryptoError::InvalidEnvelope(
            "invalid claimId (must be 1..=128 base64url chars)".into(),
        ));
    }
    if !is_valid_human_id(&claim.human_id) {
        return Err(CryptoError::InvalidEnvelope(format!(
            "invalid humanId '{}'",
            claim.human_id
        )));
    }
    if !is_valid_token_id(&claim.human_kid, false) {
        return Err(CryptoError::InvalidEnvelope("invalid humanKid".into()));
    }
    if claim.auth_epoch == 0 {
        return Err(CryptoError::InvalidEnvelope(
            "human claim authEpoch must be >= 1".into(),
        ));
    }
    if !is_valid_token_id(&claim.drop_id, true) {
        return Err(CryptoError::InvalidEnvelope(
            "invalid dropId (must be empty or 1..=128 base64url chars)".into(),
        ));
    }
    if !is_valid_node_id(&claim.audience.node_id) {
        return Err(CryptoError::InvalidEnvelope(format!(
            "invalid audience.nodeId '{}'",
            claim.audience.node_id
        )));
    }
    if !is_valid_token_id(&claim.audience.node_enc_kid, false) {
        return Err(CryptoError::InvalidEnvelope(
            "invalid audience.nodeEncKid".into(),
        ));
    }
    if let Some(handle) = &claim.audience.handle {
        if !is_valid_handle(handle) {
            return Err(CryptoError::InvalidEnvelope(format!(
                "invalid audience.handle '{handle}'"
            )));
        }
    }

    let issued_ms = parse_rfc3339_millis(&claim.issued_at).map_err(|_| {
        CryptoError::InvalidEnvelope(format!("invalid issuedAt '{}'", claim.issued_at))
    })?;
    let expires_ms = parse_rfc3339_millis(&claim.expires_at).map_err(|_| {
        CryptoError::InvalidEnvelope(format!("invalid expiresAt '{}'", claim.expires_at))
    })?;
    if expires_ms <= issued_ms {
        return Err(CryptoError::InvalidEnvelope(
            "human claim expiresAt must be strictly after issuedAt".into(),
        ));
    }
    let ttl_ms = expires_ms.saturating_sub(issued_ms);
    if ttl_ms > MAX_CLAIM_TTL_MS {
        return Err(CryptoError::InvalidEnvelope(format!(
            "human claim TTL {ttl_ms}ms exceeds maximum {MAX_CLAIM_TTL_MS}ms"
        )));
    }

    match claim.kind {
        HumanDropKind::Directive => {
            if claim.secret_spec.is_some() {
                return Err(CryptoError::InvalidEnvelope(
                    "directive claim must not carry secretSpec".into(),
                ));
            }
        }
        HumanDropKind::Secret => {
            let spec = claim.secret_spec.as_ref().ok_or_else(|| {
                CryptoError::InvalidEnvelope("secret drop claim requires secretSpec".into())
            })?;
            if is_reserved_secret_name(&spec.name) {
                return Err(CryptoError::InvalidSecretName(format!(
                    "reserved system secret name '{}' cannot be targeted by human drops",
                    spec.name
                )));
            }
            validate_secret_name(&spec.name)?;
        }
    }

    if claim.body.is_empty() {
        return Err(CryptoError::InvalidEnvelope(
            "human claim body must not be empty".into(),
        ));
    }

    Ok((issued_ms, expires_ms))
}

fn validate_envelope_structure(envelope: &HumanDropEnvelopeV1) -> Result<([u8; 32], Vec<u8>), CryptoError> {
    if envelope.v != 1 || envelope.suite != HUMAN_DROP_SUITE_V1 {
        return Err(CryptoError::InvalidEnvelope(format!(
            "unsupported human drop envelope v={} suite={}",
            envelope.v, envelope.suite
        )));
    }
    if !is_valid_token_id(&envelope.drop_id, true) {
        return Err(CryptoError::InvalidEnvelope(
            "invalid envelope dropId".into(),
        ));
    }
    let enc_bytes = decode_raw_key_32(&envelope.enc)
        .map_err(|e| CryptoError::InvalidEnvelope(format!("invalid envelope enc: {e}")))?;
    let ct_bytes = URL_SAFE_NO_PAD
        .decode(&envelope.ct)
        .map_err(|e| CryptoError::InvalidEnvelope(format!("invalid envelope ct base64url: {e}")))?;
    if ct_bytes.is_empty() {
        return Err(CryptoError::InvalidEnvelope(
            "human drop ciphertext must not be empty".into(),
        ));
    }
    Ok((enc_bytes, ct_bytes))
}

// ============================================================================
// Mode B Sealed Human Drops (`human.drop.v1` / `hdrop1_`)
// ============================================================================

/// Validates, JCS-canonicalizes, and Ed25519-signs a `HumanClaimV1` under `HUMAN_CLAIM_DOMAIN`.
pub fn sign_human_claim(
    claim: &HumanClaimV1,
    signer: &Ed25519KeyPair,
) -> Result<SignedHumanClaimV1, CryptoError> {
    let _ = validate_claim_fields(claim)?;
    let expected_kid = signer.kid();
    if claim.human_kid != expected_kid {
        return Err(CryptoError::InvalidEnvelope(
            "claim humanKid does not match signer key".into(),
        ));
    }
    let payload = to_canonical_json(claim)?;
    let sig = sign_with_domain(signer, HUMAN_CLAIM_DOMAIN, payload.as_bytes());
    Ok(SignedHumanClaimV1 { payload, sig })
}

/// Seals a `HumanClaimV1` using Mode B (Sign -> Pad to 256B..32KiB bucket -> RFC 9180 HPKE):
///
/// 1. Validates claim fields, TTL (`<= 15m`), reserved secret-name denylist, and key bindings.
/// 2. Signs RFC 8785 JCS of `claim` under `HUMAN_CLAIM_DOMAIN`.
/// 3. Pads `JCS(SignedHumanClaimV1)` via `e2ee::pad_bucket`.
/// 4. Seals via `hpke::seal_base` to `recipient_enc_pk` with `info` & `aad` bound to
///    `recipient_enc_pk.kid()` and `claim.drop_id`.
pub fn seal_human_drop(
    claim: &HumanClaimV1,
    signer: &Ed25519KeyPair,
    recipient_enc_pk: &X25519PublicKey,
) -> Result<HumanDropEnvelopeV1, CryptoError> {
    let recipient_enc_kid = recipient_enc_pk.kid();
    if claim.audience.node_enc_kid != recipient_enc_kid {
        return Err(CryptoError::InvalidEnvelope(
            "claim audience.nodeEncKid does not match recipient encryption key".into(),
        ));
    }

    let signed = Zeroizing::new(sign_human_claim(claim, signer)?);
    let signed_json = Zeroizing::new(to_canonical_json(&*signed)?);
    let padded = pad_bucket(signed_json.as_bytes())?;

    let info = human_drop_hpke_info(&recipient_enc_kid, &claim.drop_id);
    let aad = human_drop_hpke_aad(&recipient_enc_kid, &claim.drop_id);
    let (enc_bytes, ct_bytes) = hpke::seal_base(recipient_enc_pk, &info, &aad, &padded)?;

    Ok(HumanDropEnvelopeV1 {
        v: 1,
        suite: HUMAN_DROP_SUITE_V1.to_string(),
        drop_id: claim.drop_id.clone(),
        enc: URL_SAFE_NO_PAD.encode(enc_bytes),
        ct: URL_SAFE_NO_PAD.encode(&ct_bytes),
    })
}

/// Opens and strictly verifies a `HumanDropEnvelopeV1` fail-closed:
///
/// - Enforces `v == 1`, `suite == "human.drop.v1"`, HPKE `open_base` + `unpad_bucket`.
/// - Resolves the active authority key and monotonic `min_auth_epoch` via `lookup_authority(human_id, human_kid)`.
/// - Verifies Ed25519 signature over `HUMAN_CLAIM_DOMAIN || payload`.
/// - Enforces outer/inner `dropId` match, `audience.nodeId == recipient_node_id`,
///   `audience.nodeEncKid == recipient_enc_kp.kid()`, `authEpoch >= min_auth_epoch`,
///   TTL `<= 15m`, `issuedAt <= now_ms + 60s`, `now_ms < expiresAt`, and reserved secret-name guard.
pub fn open_human_drop<F>(
    envelope: &HumanDropEnvelopeV1,
    recipient_enc_kp: &X25519KeyPair,
    recipient_node_id: &str,
    now_ms: i64,
    lookup_authority: F,
) -> Result<HumanClaimV1, CryptoError>
where
    F: FnOnce(&str, &str) -> Option<(Ed25519PublicKey, u64)>,
{
    let (enc_bytes, ct_bytes) = validate_envelope_structure(envelope)?;
    let recipient_enc_kid = recipient_enc_kp.kid();

    let info = human_drop_hpke_info(&recipient_enc_kid, &envelope.drop_id);
    let aad = human_drop_hpke_aad(&recipient_enc_kid, &envelope.drop_id);
    let padded = hpke::open_base(&enc_bytes, recipient_enc_kp, &info, &aad, &ct_bytes)?;
    let signed_bytes = unpad_bucket(&padded)?;

    let signed: Zeroizing<SignedHumanClaimV1> = Zeroizing::new(serde_json::from_slice(&signed_bytes)?);
    let claim: HumanClaimV1 = serde_json::from_str(&signed.payload)?;

    // Look up active authority and verify Ed25519 signature BEFORE accepting claim semantics.
    let (authority_pk, min_auth_epoch) = lookup_authority(&claim.human_id, &claim.human_kid)
        .ok_or_else(|| {
            CryptoError::InvalidSignature(format!(
                "unknown or revoked human authority '{}' kid '{}'",
                claim.human_id, claim.human_kid
            ))
        })?;

    if claim.human_kid != authority_pk.kid() {
        return Err(CryptoError::InvalidSignature(
            "claim humanKid does not match authority public key thumbprint".into(),
        ));
    }

    verify_with_domain(
        &authority_pk,
        HUMAN_CLAIM_DOMAIN,
        signed.payload.as_bytes(),
        &signed.sig,
    )?;

    // Structural, TTL, and reserved secret-name checks.
    let (issued_ms, expires_ms) = validate_claim_fields(&claim)?;

    // Audience, rendezvous, epoch anti-rollback, and wall-clock checks.
    if claim.drop_id != envelope.drop_id {
        return Err(CryptoError::InvalidEnvelope(
            "inner claim dropId does not match outer envelope dropId".into(),
        ));
    }
    if claim.audience.node_id != recipient_node_id {
        return Err(CryptoError::InvalidEnvelope(format!(
            "claim audience.nodeId '{}' does not match local node '{recipient_node_id}'",
            claim.audience.node_id
        )));
    }
    if claim.audience.node_enc_kid != recipient_enc_kid {
        return Err(CryptoError::InvalidEnvelope(
            "claim audience.nodeEncKid does not match local encryption key".into(),
        ));
    }
    if claim.auth_epoch < min_auth_epoch {
        return Err(CryptoError::ReplayOrRollback(format!(
            "human claim authEpoch {} is below minimum allowed epoch {min_auth_epoch}",
            claim.auth_epoch
        )));
    }
    if issued_ms > now_ms.saturating_add(CLOCK_SKEW_MS) {
        return Err(CryptoError::InvalidEnvelope(format!(
            "human claim issuedAt '{}' exceeds allowed clock skew",
            claim.issued_at
        )));
    }
    if now_ms >= expires_ms {
        return Err(CryptoError::InvalidEnvelope(format!(
            "human claim expired at '{}'",
            claim.expires_at
        )));
    }

    Ok(claim)
}

/// Encodes a validated `HumanDropEnvelopeV1` into an armored `hdrop1_<base64url(JCS)>` token.
pub fn encode_hdrop1(envelope: &HumanDropEnvelopeV1) -> Result<String, CryptoError> {
    let _ = validate_envelope_structure(envelope)?;
    let canon = to_canonical_json(envelope)?;
    Ok(format!(
        "{HDROP1_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(canon.as_bytes())
    ))
}

/// Decodes and structurally validates an armored `hdrop1_<base64url(JCS)>` token.
pub fn decode_hdrop1(armored: &str) -> Result<HumanDropEnvelopeV1, CryptoError> {
    let trimmed = armored.trim();
    let encoded = trimmed
        .strip_prefix(HDROP1_PREFIX)
        .ok_or_else(|| CryptoError::InvalidEnvelope("expected 'hdrop1_' prefix".into()))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| CryptoError::InvalidEnvelope(format!("invalid hdrop1_ base64url: {e}")))?;
    let envelope: HumanDropEnvelopeV1 = serde_json::from_slice(&bytes)?;
    let _ = validate_envelope_structure(&envelope)?;
    Ok(envelope)
}

// ============================================================================
// Human-Signed Node Certificates (`NodeCertV1` / `hcert1_`)
// ============================================================================

fn validate_node_cert_fields(cert: &NodeCertPayloadV1) -> Result<(i64, i64), CryptoError> {
    if cert.v != 1 {
        return Err(CryptoError::InvalidEnvelope(format!(
            "unsupported NodeCertPayloadV1 version {} (expected 1)",
            cert.v
        )));
    }
    if !is_valid_node_id(&cert.node_id) {
        return Err(CryptoError::InvalidEnvelope(format!(
            "invalid nodeId '{}' in NodeCertV1",
            cert.node_id
        )));
    }
    let _ = cert.signing_jwk.to_ed25519()?;
    let _ = cert.encryption_jwk.to_x25519()?;
    if !is_valid_human_id(&cert.human_id) {
        return Err(CryptoError::InvalidEnvelope(format!(
            "invalid humanId '{}' in NodeCertV1",
            cert.human_id
        )));
    }
    if !is_valid_token_id(&cert.human_kid, false) {
        return Err(CryptoError::InvalidEnvelope(
            "invalid humanKid in NodeCertV1".into(),
        ));
    }
    if cert.auth_epoch == 0 {
        return Err(CryptoError::InvalidEnvelope(
            "NodeCertV1 authEpoch must be >= 1".into(),
        ));
    }
    let issued_ms = parse_rfc3339_millis(&cert.issued_at).map_err(|_| {
        CryptoError::InvalidEnvelope(format!("invalid NodeCertV1 issuedAt '{}'", cert.issued_at))
    })?;
    let expires_ms = parse_rfc3339_millis(&cert.expires_at).map_err(|_| {
        CryptoError::InvalidEnvelope(format!(
            "invalid NodeCertV1 expiresAt '{}'",
            cert.expires_at
        ))
    })?;
    if expires_ms <= issued_ms {
        return Err(CryptoError::InvalidEnvelope(
            "NodeCertV1 expiresAt must be strictly after issuedAt".into(),
        ));
    }
    Ok((issued_ms, expires_ms))
}

/// Validates, JCS-canonicalizes, and signs a `NodeCertPayloadV1` under `HUMAN_NODE_CERT_DOMAIN`.
pub fn sign_node_cert(
    cert: &NodeCertPayloadV1,
    signer: &Ed25519KeyPair,
) -> Result<SignedNodeCertV1, CryptoError> {
    let _ = validate_node_cert_fields(cert)?;
    if cert.human_kid != signer.kid() {
        return Err(CryptoError::InvalidEnvelope(
            "NodeCertV1 humanKid does not match signer key".into(),
        ));
    }
    let payload = to_canonical_json(cert)?;
    let sig = sign_with_domain(signer, HUMAN_NODE_CERT_DOMAIN, payload.as_bytes());
    Ok(SignedNodeCertV1 { payload, sig })
}

/// Strictly verifies a `SignedNodeCertV1` against `issuer_pk`, `now_ms`, and `min_auth_epoch`.
pub fn verify_node_cert(
    signed: &SignedNodeCertV1,
    issuer_pk: &Ed25519PublicKey,
    now_ms: i64,
    min_auth_epoch: u64,
) -> Result<NodeCertPayloadV1, CryptoError> {
    verify_with_domain(
        issuer_pk,
        HUMAN_NODE_CERT_DOMAIN,
        signed.payload.as_bytes(),
        &signed.sig,
    )?;
    let cert: NodeCertPayloadV1 = serde_json::from_str(&signed.payload)?;
    let (issued_ms, expires_ms) = validate_node_cert_fields(&cert)?;
    if cert.human_kid != issuer_pk.kid() {
        return Err(CryptoError::InvalidSignature(
            "NodeCertV1 humanKid does not match issuer public key".into(),
        ));
    }
    if cert.auth_epoch < min_auth_epoch {
        return Err(CryptoError::ReplayOrRollback(format!(
            "NodeCertV1 authEpoch {} is below minimum allowed epoch {min_auth_epoch}",
            cert.auth_epoch
        )));
    }
    if issued_ms > now_ms.saturating_add(CLOCK_SKEW_MS) {
        return Err(CryptoError::InvalidEnvelope(format!(
            "NodeCertV1 issuedAt '{}' exceeds allowed clock skew",
            cert.issued_at
        )));
    }
    if now_ms >= expires_ms {
        return Err(CryptoError::InvalidEnvelope(format!(
            "NodeCertV1 expired at '{}'",
            cert.expires_at
        )));
    }
    Ok(cert)
}

/// Encodes a `SignedNodeCertV1` into an armored `hcert1_<base64url(JCS)>` string.
pub fn encode_hcert1(cert: &SignedNodeCertV1) -> Result<String, CryptoError> {
    if cert.payload.is_empty() || cert.sig.is_empty() {
        return Err(CryptoError::InvalidEnvelope(
            "SignedNodeCertV1 payload and sig must be non-empty".into(),
        ));
    }
    let canon = to_canonical_json(cert)?;
    Ok(format!(
        "{HCERT1_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(canon.as_bytes())
    ))
}

/// Decodes an armored `hcert1_<base64url(JCS)>` string into a `SignedNodeCertV1`.
pub fn decode_hcert1(armored: &str) -> Result<SignedNodeCertV1, CryptoError> {
    let trimmed = armored.trim();
    let encoded = trimmed
        .strip_prefix(HCERT1_PREFIX)
        .ok_or_else(|| CryptoError::InvalidEnvelope("expected 'hcert1_' prefix".into()))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| CryptoError::InvalidEnvelope(format!("invalid hcert1_ base64url: {e}")))?;
    let cert: SignedNodeCertV1 = serde_json::from_slice(&bytes)?;
    if cert.payload.is_empty() || cert.sig.is_empty() {
        return Err(CryptoError::InvalidEnvelope(
            "decoded hcert1_ has empty payload or sig".into(),
        ));
    }
    Ok(cert)
}

// ============================================================================
// Human Key Revocation (`HumanRevocationV1`)
// ============================================================================

fn validate_revocation_fields(rev: &HumanRevocationPayloadV1) -> Result<(), CryptoError> {
    if rev.v != 1 {
        return Err(CryptoError::InvalidEnvelope(format!(
            "unsupported HumanRevocationPayloadV1 version {} (expected 1)",
            rev.v
        )));
    }
    if !is_valid_human_id(&rev.human_id) {
        return Err(CryptoError::InvalidEnvelope(format!(
            "invalid humanId '{}' in HumanRevocationV1",
            rev.human_id
        )));
    }
    if !is_valid_token_id(&rev.revoked_kid, false) {
        return Err(CryptoError::InvalidEnvelope(
            "invalid revokedKid in HumanRevocationV1".into(),
        ));
    }
    if !is_valid_token_id(&rev.issuer_kid, false) {
        return Err(CryptoError::InvalidEnvelope(
            "invalid issuerKid in HumanRevocationV1".into(),
        ));
    }
    if rev.new_min_auth_epoch == 0 {
        return Err(CryptoError::InvalidEnvelope(
            "HumanRevocationV1 newMinAuthEpoch must be >= 1".into(),
        ));
    }
    let _ = parse_rfc3339_millis(&rev.revoked_at).map_err(|_| {
        CryptoError::InvalidEnvelope(format!(
            "invalid HumanRevocationV1 revokedAt '{}'",
            rev.revoked_at
        ))
    })?;
    if rev.reason.len() > 512 {
        return Err(CryptoError::InvalidEnvelope(
            "HumanRevocationV1 reason exceeds 512 bytes".into(),
        ));
    }
    Ok(())
}

/// Validates, JCS-canonicalizes, and signs a `HumanRevocationPayloadV1` under `HUMAN_REVOCATION_DOMAIN`.
pub fn sign_human_revocation(
    rev: &HumanRevocationPayloadV1,
    issuer: &Ed25519KeyPair,
) -> Result<SignedHumanRevocationV1, CryptoError> {
    validate_revocation_fields(rev)?;
    if rev.issuer_kid != issuer.kid() {
        return Err(CryptoError::InvalidEnvelope(
            "HumanRevocationV1 issuerKid does not match issuer key".into(),
        ));
    }
    let payload = to_canonical_json(rev)?;
    let sig = sign_with_domain(issuer, HUMAN_REVOCATION_DOMAIN, payload.as_bytes());
    Ok(SignedHumanRevocationV1 { payload, sig })
}

/// Strictly verifies a `SignedHumanRevocationV1` against `issuer_pk`.
pub fn verify_human_revocation(
    signed: &SignedHumanRevocationV1,
    issuer_pk: &Ed25519PublicKey,
) -> Result<HumanRevocationPayloadV1, CryptoError> {
    verify_with_domain(
        issuer_pk,
        HUMAN_REVOCATION_DOMAIN,
        signed.payload.as_bytes(),
        &signed.sig,
    )?;
    let rev: HumanRevocationPayloadV1 = serde_json::from_str(&signed.payload)?;
    validate_revocation_fields(&rev)?;
    if rev.issuer_kid != issuer_pk.kid() {
        return Err(CryptoError::InvalidSignature(
            "HumanRevocationV1 issuerKid does not match issuer public key".into(),
        ));
    }
    Ok(rev)
}

// ============================================================================
// Encrypted Directive Drafts (`human.draft.v1`) & Local Event Signatures (`hyphaesig`)
// ============================================================================

fn is_forbidden_draft_char(ch: char) -> bool {
    matches!(
        ch,
        '\u{0000}'..='\u{0008}'
            | '\u{000B}'..='\u{001F}'
            | '\u{007F}'..='\u{009F}'
            | '\u{061C}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202F}'
            | '\u{2060}'..='\u{206F}'
            | '\u{FEFF}'
    )
}

/// Strictly validates human directive draft text fail-closed:
/// - Non-empty after trimming.
/// - Unicode scalar count `<= MAX_HUMAN_DRAFT_CHARS` (512).
/// - Rejects C0/C1 control characters (other than `\n` and `\t`), `\r`, BiDi overrides/isolates,
///   and zero-width / invisible formatting characters.
pub fn validate_draft_text(text: &str) -> Result<(), CryptoError> {
    if text.trim().is_empty() {
        return Err(CryptoError::InvalidEnvelope(
            "human draft text must not be empty".into(),
        ));
    }
    let char_count = text.chars().count();
    if char_count > MAX_HUMAN_DRAFT_CHARS {
        return Err(CryptoError::InvalidEnvelope(format!(
            "human draft text length {char_count} exceeds maximum {MAX_HUMAN_DRAFT_CHARS} chars"
        )));
    }
    for ch in text.chars() {
        if is_forbidden_draft_char(ch) {
            return Err(CryptoError::InvalidEnvelope(format!(
                "human draft text contains forbidden control or invisible character U+{:04X}",
                ch as u32
            )));
        }
    }
    Ok(())
}

/// Builds the exact RFC 9180 HPKE `info` bytes for `human.draft.v1`:
/// `"hyphae/v2/human-draft\n" || nodeId || "\n" || recipientKid`.
pub fn human_draft_hpke_info(node_id: &str, recipient_kid: &str) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(HUMAN_DRAFT_INFO_PREFIX.len() + node_id.len() + 1 + recipient_kid.len());
    out.extend_from_slice(HUMAN_DRAFT_INFO_PREFIX);
    out.extend_from_slice(node_id.as_bytes());
    out.push(b'\n');
    out.extend_from_slice(recipient_kid.as_bytes());
    out
}

/// Builds the exact RFC 9180 HPKE `aad` bytes for `human.draft.v1`:
/// `JCS({ "v": 1, "suite": "human.draft.v1", "nodeId": nodeId, "recipientKid": recipientKid })`.
pub fn human_draft_hpke_aad(node_id: &str, recipient_kid: &str) -> Result<Vec<u8>, CryptoError> {
    let aad = to_canonical_json(&serde_json::json!({
        "v": 1,
        "suite": HUMAN_DRAFT_SUITE,
        "nodeId": node_id,
        "recipientKid": recipient_kid,
    }))?;
    Ok(aad.into_bytes())
}

fn validate_draft_payload(payload: &HumanDraftPayloadV1) -> Result<(), CryptoError> {
    if payload.v != 1 {
        return Err(CryptoError::InvalidEnvelope(format!(
            "unsupported HumanDraftPayloadV1 version {} (expected 1)",
            payload.v
        )));
    }
    if !is_valid_node_id(&payload.node_id) {
        return Err(CryptoError::InvalidEnvelope(format!(
            "invalid HumanDraftPayloadV1 nodeId '{}'",
            payload.node_id
        )));
    }
    validate_draft_text(&payload.text)?;
    if let Some(context) = &payload.context {
        validate_draft_text(context)?;
        let ctx_chars = context.chars().count();
        if ctx_chars > MAX_HUMAN_DRAFT_CONTEXT_CHARS {
            return Err(CryptoError::InvalidEnvelope(format!(
                "human draft context length {ctx_chars} exceeds maximum {MAX_HUMAN_DRAFT_CONTEXT_CHARS} chars"
            )));
        }
    }
    let _ = parse_rfc3339_millis(&payload.created_at).map_err(|_| {
        CryptoError::InvalidEnvelope(format!(
            "invalid HumanDraftPayloadV1 createdAt '{}'",
            payload.created_at
        ))
    })?;
    Ok(())
}

/// Validates, JCS-canonicalizes, bucket-pads, and HPKE-seals a `HumanDraftPayloadV1` to the
/// human's companion Passkey-PRF X25519 encryption key.
pub fn seal_human_draft(
    payload: &HumanDraftPayloadV1,
    recipient_enc_pk: &X25519PublicKey,
) -> Result<EncryptedHumanDraftV1, CryptoError> {
    validate_draft_payload(payload)?;

    let recipient_kid = recipient_enc_pk.kid();
    let info = human_draft_hpke_info(&payload.node_id, &recipient_kid);
    let aad = human_draft_hpke_aad(&payload.node_id, &recipient_kid)?;

    let jcs = Zeroizing::new(to_canonical_json(payload)?);
    let padded = pad_bucket(jcs.as_bytes())?;
    let (enc_bytes, ct_bytes) = hpke::seal_base(recipient_enc_pk, &info, &aad, &padded)?;

    Ok(EncryptedHumanDraftV1 {
        v: 1,
        suite: HUMAN_DRAFT_SUITE.to_string(),
        recipient_kid,
        enc: URL_SAFE_NO_PAD.encode(enc_bytes),
        ct: URL_SAFE_NO_PAD.encode(&ct_bytes),
    })
}

/// Opens and strictly validates an `EncryptedHumanDraftV1` fail-closed using the human's
/// Passkey-PRF X25519 keypair and expected `nodeId`.
pub fn open_human_draft(
    draft: &EncryptedHumanDraftV1,
    recipient_enc_kp: &X25519KeyPair,
    expected_node_id: &str,
) -> Result<HumanDraftPayloadV1, CryptoError> {
    if !is_valid_node_id(expected_node_id) {
        return Err(CryptoError::InvalidEnvelope(format!(
            "invalid expected_node_id '{expected_node_id}'"
        )));
    }
    if draft.v != 1 || draft.suite != HUMAN_DRAFT_SUITE {
        return Err(CryptoError::InvalidEnvelope(format!(
            "unsupported human draft envelope v={} suite={}",
            draft.v, draft.suite
        )));
    }

    let expected_kid = recipient_enc_kp.kid();
    if draft.recipient_kid != expected_kid {
        return Err(CryptoError::InvalidEnvelope(
            "encrypted draft recipientKid does not match recipient X25519 key".into(),
        ));
    }

    let enc_bytes = decode_raw_key_32(&draft.enc)
        .map_err(|e| CryptoError::InvalidEnvelope(format!("invalid draft enc: {e}")))?;
    let ct_bytes = URL_SAFE_NO_PAD
        .decode(&draft.ct)
        .map_err(|e| CryptoError::InvalidEnvelope(format!("invalid draft ct base64url: {e}")))?;
    if ct_bytes.is_empty() {
        return Err(CryptoError::InvalidEnvelope(
            "encrypted human draft ciphertext must not be empty".into(),
        ));
    }

    let info = human_draft_hpke_info(expected_node_id, &expected_kid);
    let aad = human_draft_hpke_aad(expected_node_id, &expected_kid)?;
    let padded = hpke::open_base(&enc_bytes, recipient_enc_kp, &info, &aad, &ct_bytes)?;
    let plain_bytes = unpad_bucket(&padded)?;

    let payload: HumanDraftPayloadV1 = serde_json::from_slice(&plain_bytes)?;
    validate_draft_payload(&payload)?;
    if payload.node_id != expected_node_id {
        return Err(CryptoError::InvalidEnvelope(format!(
            "draft payload nodeId '{}' does not match expected '{expected_node_id}'",
            payload.node_id
        )));
    }

    Ok(payload)
}

/// Signs canonical CloudEvent JSON under `LOCAL_EVENT_SIG_DOMAIN` and formats the RFC-clean
/// `hyphaesig` CloudEvents string extension attribute: `"ed25519:<kid>:<b64url>"`.
pub fn sign_local_ingest_event(signer: &Ed25519KeyPair, canonical_event_json: &str) -> String {
    format!(
        "ed25519:{}:{}",
        signer.kid(),
        sign_with_domain(signer, LOCAL_EVENT_SIG_DOMAIN, canonical_event_json.as_bytes())
    )
}

/// Strictly verifies a `hyphaesig` extension attribute (`"ed25519:<kid>:<b64url>"`) over
/// `canonical_event_json` under `LOCAL_EVENT_SIG_DOMAIN`, returning the verified signer `kid`.
pub fn verify_local_ingest_event(
    sig_attr: &str,
    canonical_event_json: &str,
    lookup_pk: impl FnOnce(&str) -> Option<Ed25519PublicKey>,
) -> Result<String, CryptoError> {
    let mut parts = sig_attr.split(':');
    let scheme = parts.next();
    let kid = parts.next();
    let sig_b64 = parts.next();
    let extra = parts.next();

    if scheme != Some("ed25519") || extra.is_some() {
        return Err(CryptoError::InvalidSignature(
            "invalid hyphaesig format (expected 'ed25519:<kid>:<b64url>')".into(),
        ));
    }
    let kid = kid.unwrap_or("");
    let sig_b64 = sig_b64.unwrap_or("");
    if !is_valid_token_id(kid, false) || sig_b64.is_empty() {
        return Err(CryptoError::InvalidSignature(
            "invalid kid or signature in hyphaesig attribute".into(),
        ));
    }

    let pk = lookup_pk(kid).ok_or_else(|| {
        CryptoError::InvalidSignature(format!(
            "unknown or revoked local event signer kid '{kid}'"
        ))
    })?;
    if pk.kid() != kid {
        return Err(CryptoError::InvalidSignature(
            "local event signer kid does not match public key thumbprint".into(),
        ));
    }

    verify_with_domain(
        &pk,
        LOCAL_EVENT_SIG_DOMAIN,
        canonical_event_json.as_bytes(),
        sig_b64,
    )?;
    Ok(kid.to_string())
}
