//! **100% Byte-Compatible v1 `t3-mesh` & `HYP1` Interoperability Layer**.
//!
//! Mirrors the exact wire contracts of:
//! - `src/core/identity/keys.ts` (`t3-mesh/v1/<kind>\n` Ed25519 signatures)
//! - `src/core/identity/grant.ts` (`Grant`, `Binding`, `SignedBinding`, `Entry`, `Revocation`, `t3mp1_` pairing codes)
//! - `src/identity.ts` (`createKeyRegistration`, `verifyKeyRegistration`)
//! - `src/core/transfer/seal.ts` (`seal` / `open` X25519 + HKDF-SHA256 + AES-256-GCM)
//! - `src/core/transfer/pack.ts` (`HYP1` gzipped file pack/unpack)
//!
//! Hardened with strict small-order Ed25519 & all-zero X25519 checks on every verification path.

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::hpke::hkdf_sha256;
use crate::keys::{
    decode_raw_key_32, is_raw_key, is_small_order_ed25519_point, Ed25519KeyPair, Ed25519PublicKey,
    X25519KeyPair, X25519PublicKey,
};
use crate::pairing::is_valid_node_id;
use crate::rfc3339::{format_rfc3339_millis, parse_rfc3339_millis};

/// Maximum TTL for v1 sealed transfers (24 hours, matching `seal.ts`).
pub const MAX_TRANSFER_TTL_MS_V1: i64 = 24 * 60 * 60 * 1000;

/// Magic header for v1 `HYP1` file packs.
pub const HYP1_MAGIC: &[u8; 4] = b"HYP1";
pub const HYP1_MAX_FILES: usize = 200;
pub const HYP1_MAX_RAW_BYTES: usize = 256 * 1024 * 1024;
const HYP1_MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const HYP1_MAX_FILENAME_LEN: usize = 200;
const T3MP1_PREFIX: &str = "t3mp1_";
const T3MP1_SECRET_BYTES: usize = 20;

/// v1 signed JSON payload (`src/core/identity/keys.ts`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedV1 {
    pub payload: String,
    pub sig: String,
}

/// Valid v1 `t3-mesh/v1/<kind>\n` signature kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureKindV1 {
    Grant,
    Binding,
    BindingSelf,
    Revocation,
    Transfer,
    Attestation,
    KeyReg,
}

impl SignatureKindV1 {
    pub const fn as_str(self) -> &'static str {
        match self {
            SignatureKindV1::Grant => "grant",
            SignatureKindV1::Binding => "binding",
            SignatureKindV1::BindingSelf => "binding-self",
            SignatureKindV1::Revocation => "revocation",
            SignatureKindV1::Transfer => "transfer",
            SignatureKindV1::Attestation => "attestation",
            SignatureKindV1::KeyReg => "key-reg",
        }
    }
}

fn signed_bytes_v1(kind: SignatureKindV1, payload: &[u8]) -> Vec<u8> {
    let prefix = format!("t3-mesh/v1/{}\n", kind.as_str());
    let mut buf = Vec::with_capacity(prefix.len() + payload.len());
    buf.extend_from_slice(prefix.as_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Signs UTF-8 `payload` under `"t3-mesh/v1/<kind>\n"` and returns base64url no-pad signature.
pub fn sign_payload_v1(kind: SignatureKindV1, payload: &str, key: &Ed25519KeyPair) -> String {
    let msg = signed_bytes_v1(kind, payload.as_bytes());
    URL_SAFE_NO_PAD.encode(key.sign_raw(&msg))
}

/// Serializes `value` with `serde_json::to_string` and signs under `"t3-mesh/v1/<kind>\n"`.
pub fn sign_value_v1<T: Serialize>(
    kind: SignatureKindV1,
    value: &T,
    key: &Ed25519KeyPair,
) -> Result<SignedV1, CryptoError> {
    let payload = serde_json::to_string(value)?;
    let sig = sign_payload_v1(kind, &payload, key);
    Ok(SignedV1 { payload, sig })
}

/// Verifies a v1 `"t3-mesh/v1/<kind>\n"` Ed25519 signature strictly.
pub fn verify_payload_v1(
    kind: SignatureKindV1,
    payload: &str,
    sig_b64: &str,
    key: &Ed25519PublicKey,
) -> bool {
    let Ok(sig) = URL_SAFE_NO_PAD.decode(sig_b64) else {
        return false;
    };
    let msg = signed_bytes_v1(kind, payload.as_bytes());
    key.verify_raw(&msg, &sig).is_ok()
}

fn is_uuid_v1(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 36 {
        return false;
    }
    for (i, &ch) in b.iter().enumerate() {
        if matches!(i, 8 | 13 | 18 | 23) {
            if ch != b'-' {
                return false;
            }
        } else if !(ch.is_ascii_digit() || (b'a'..=b'f').contains(&ch)) {
            return false;
        }
    }
    true
}

fn is_handle_v1(s: &str) -> bool {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 64 {
        return false;
    }
    if !(b[0].is_ascii_lowercase() || b[0].is_ascii_digit()) {
        return false;
    }
    b.iter()
        .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-'))
}

fn parse_time_v1(ts: &str) -> Option<i64> {
    parse_rfc3339_millis(ts).ok()
}

fn generate_uuid_v4() -> Result<String, CryptoError> {
    let rng = SystemRandom::new();
    let mut b = [0u8; 16];
    rng.fill(&mut b)
        .map_err(|_| CryptoError::Hpke("OS CSPRNG failure".into()))?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    Ok(uuid_from_bytes(&b))
}

fn uuid_to_bytes(id: &str) -> Result<[u8; 16], CryptoError> {
    if !is_uuid_v1(id) {
        return Err(CryptoError::InvalidPairing(format!("invalid UUID '{id}'")));
    }
    let clean: String = id.chars().filter(|&c| c != '-').collect();
    let decoded = hex::decode(clean)
        .map_err(|e| CryptoError::InvalidPairing(format!("invalid UUID hex: {e}")))?;
    decoded
        .try_into()
        .map_err(|_| CryptoError::InvalidPairing("UUID is not 16 bytes".into()))
}

fn uuid_from_bytes(b: &[u8; 16]) -> String {
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

// ============================================================================
// v1 Scopes expansion (`src/core/identity/scopes.ts`)
// ============================================================================

const V1_BASE_SCOPES: [&str; 7] = [
    "messages:send",
    "messages:receive",
    "events:subscribe",
    "files:send",
    "files:receive",
    "forks:send",
    "forks:receive",
];

const V1_RUNTIME_MODES: [&str; 4] = ["approval-required", "auto-accept-edits", "auto", "full-access"];

/// Expands v1 scope shorthands identically to `expandScopes()` in `src/core/identity/scopes.ts`.
pub fn expand_scopes_v1(input: &[&str]) -> Result<Vec<String>, CryptoError> {
    if input.is_empty() {
        return Err(CryptoError::InvalidPairing(
            "a grant needs at least one scope".into(),
        ));
    }
    let mut expanded_items: Vec<&str> = Vec::new();
    for &item in input {
        match item {
            "*" => expanded_items.extend_from_slice(&[
                "messages:send",
                "messages:receive",
                "events:subscribe",
                "files:send",
                "files:receive",
                "forks:send",
                "forks:receive/full-access",
            ]),
            "messages:*" => expanded_items.extend_from_slice(&["messages:send", "messages:receive"]),
            "events:*" => expanded_items.push("events:subscribe"),
            "files:*" => expanded_items.extend_from_slice(&["files:send", "files:receive"]),
            "forks:*" => expanded_items.extend_from_slice(&["forks:send", "forks:receive/full-access"]),
            other => expanded_items.push(other),
        }
    }

    let mut by_base: BTreeMap<&str, String> = BTreeMap::new();
    for scope in expanded_items {
        let (base, formatted) = if let Some(rest) = scope.strip_prefix("forks:receive") {
            let mode = rest
                .strip_prefix('/')
                .ok_or_else(|| CryptoError::InvalidPairing(format!("invalid scope '{scope}'")))?;
            if !V1_RUNTIME_MODES.contains(&mode) {
                return Err(CryptoError::InvalidPairing(format!(
                    "unknown runtime mode '{mode}'"
                )));
            }
            ("forks:receive", format!("forks:receive/{mode}"))
        } else if let Some((base, recips)) = scope.split_once('=') {
            if base != "files:send" && base != "forks:send" {
                return Err(CryptoError::InvalidPairing(format!(
                    "scope '{scope}' does not accept recipients"
                )));
            }
            let mut list: Vec<&str> = recips.split(',').collect();
            if list.is_empty() || list.iter().any(|id| !is_valid_node_id(id)) {
                return Err(CryptoError::InvalidPairing(format!(
                    "invalid recipient in scope '{scope}'"
                )));
            }
            list.sort_unstable();
            list.dedup();
            (base, format!("{base}={}", list.join(",")))
        } else {
            if !V1_BASE_SCOPES.contains(&scope) || scope == "forks:receive" {
                return Err(CryptoError::InvalidPairing(format!(
                    "unknown scope '{scope}'"
                )));
            }
            (scope, scope.to_string())
        };

        if let Some(existing) = by_base.get(base) {
            if existing != &formatted {
                return Err(CryptoError::InvalidPairing(format!(
                    "conflicting forms of scope '{base}': '{existing}' vs '{formatted}'"
                )));
            }
        } else {
            by_base.insert(base, formatted);
        }
    }

    let mut out = Vec::new();
    for base in V1_BASE_SCOPES {
        if let Some(val) = by_base.get(base) {
            out.push(val.clone());
        }
    }
    Ok(out)
}

// ============================================================================
// v1 Grants, Bindings, Entries, Revocations & `t3mp1_` Pairing Codes
// ============================================================================

/// Exact v1 `Grant` (`src/core/identity/grant.ts`). Field order matches TS `JSON.stringify`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantV1 {
    pub v: u8,
    pub id: String,
    #[serde(rename = "connectorId")]
    pub connector_id: String,
    pub scopes: Vec<String>,
    #[serde(rename = "pairingKey")]
    pub pairing_key: String,
    #[serde(rename = "issuedAt")]
    pub issued_at: String,
    #[serde(rename = "pairBy")]
    pub pair_by: String,
}

/// Exact v1 `Binding` (`src/core/identity/grant.ts`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingV1 {
    pub v: u8,
    #[serde(rename = "grantId")]
    pub grant_id: String,
    #[serde(rename = "connectorId")]
    pub connector_id: String,
    #[serde(rename = "signingKey")]
    pub signing_key: String,
    #[serde(rename = "encryptionKey")]
    pub encryption_key: String,
    #[serde(rename = "boundAt")]
    pub bound_at: String,
}

/// Exact v1 `Revocation` (`src/core/identity/grant.ts`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationV1 {
    pub v: u8,
    #[serde(rename = "connectorId")]
    pub connector_id: String,
    #[serde(rename = "grantId")]
    pub grant_id: String,
    #[serde(rename = "revokedAt")]
    pub revoked_at: String,
}

/// Exact v1 `SignedBinding` (`src/core/identity/grant.ts`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedBindingV1 {
    pub payload: String,
    #[serde(rename = "pairingSig")]
    pub pairing_sig: String,
    #[serde(rename = "selfSig")]
    pub self_sig: String,
}

/// Exact v1 `Entry` (`src/core/identity/grant.ts`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryV1 {
    pub grant: SignedV1,
    pub binding: SignedBindingV1,
}

/// Verified v1 connector identity (`src/core/identity/grant.ts`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityV1 {
    pub connector_id: String,
    pub grant_id: String,
    pub issued_at: String,
    pub scopes: Vec<String>,
    pub signing_key: String,
    pub encryption_key: String,
}

/// Parsed v1 `t3mp1_` pairing code.
#[derive(Clone)]
pub struct PairingCodeV1 {
    pub grant_id: String,
    pub secret: Zeroizing<[u8; T3MP1_SECRET_BYTES]>,
    pub admin_fingerprint: String,
}

impl std::fmt::Debug for PairingCodeV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairingCodeV1")
            .field("grant_id", &self.grant_id)
            .field("admin_fingerprint", &self.admin_fingerprint)
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

/// Result of `issue_grant_v1`.
#[derive(Debug, Clone)]
pub struct IssuedGrantV1 {
    pub grant: GrantV1,
    pub signed: SignedV1,
    pub code: String,
}

/// Formats a `t3mp1_` pairing code byte-identically to `formatPairingCode` in `grant.ts`.
pub fn format_pairing_code_v1(code: &PairingCodeV1) -> Result<String, CryptoError> {
    let uuid = uuid_to_bytes(&code.grant_id)?;
    let fp = hex::decode(&code.admin_fingerprint)
        .map_err(|e| CryptoError::InvalidPairing(format!("invalid admin fingerprint hex: {e}")))?;
    if fp.len() != 8 {
        return Err(CryptoError::InvalidPairing(
            "admin fingerprint must be 8 bytes (16 hex chars)".into(),
        ));
    }
    let mut raw = Zeroizing::new(Vec::with_capacity(16 + T3MP1_SECRET_BYTES + 8));
    raw.extend_from_slice(&uuid);
    raw.extend_from_slice(&*code.secret);
    raw.extend_from_slice(&fp);
    Ok(format!("{T3MP1_PREFIX}{}", URL_SAFE_NO_PAD.encode(&*raw)))
}

/// Parses a `t3mp1_` pairing code byte-identically to `parsePairingCode` in `grant.ts`.
pub fn parse_pairing_code_v1(text: &str) -> Result<PairingCodeV1, CryptoError> {
    let trimmed = text.trim();
    let encoded = trimmed
        .strip_prefix(T3MP1_PREFIX)
        .ok_or_else(|| CryptoError::InvalidPairing("expected 't3mp1_' prefix".into()))?;
    let bytes = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| CryptoError::InvalidPairing(format!("invalid t3mp1_ base64url: {e}")))?,
    );
    if bytes.len() != 16 + T3MP1_SECRET_BYTES + 8 {
        return Err(CryptoError::InvalidPairing(
            "t3mp1_ pairing code has invalid length".into(),
        ));
    }
    let uuid: [u8; 16] = bytes[0..16].try_into().unwrap();
    let mut secret = Zeroizing::new([0u8; T3MP1_SECRET_BYTES]);
    secret.copy_from_slice(&bytes[16..16 + T3MP1_SECRET_BYTES]);
    let admin_fingerprint = hex::encode(&bytes[16 + T3MP1_SECRET_BYTES..]);
    Ok(PairingCodeV1 {
        grant_id: uuid_from_bytes(&uuid),
        secret,
        admin_fingerprint,
    })
}

/// Derives the one-time Ed25519 pairing keypair from `(secret, grantId)` identically to `grant.ts:177`:
/// `HKDF-SHA256(ikm=secret, salt="t3-mesh pairing v1", info=grantId, len=32)`.
pub fn derive_pairing_key_v1(
    secret: &[u8; T3MP1_SECRET_BYTES],
    grant_id: &str,
) -> Result<Ed25519KeyPair, CryptoError> {
    let seed_vec = hkdf_sha256(b"t3-mesh pairing v1", secret, grant_id.as_bytes(), 32)?;
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(&seed_vec);
    Ed25519KeyPair::from_seed(*seed)
}

/// Issues a v1 admin-signed grant and `t3mp1_` pairing code.
pub fn issue_grant_v1(
    admin_key: &Ed25519KeyPair,
    connector_id: &str,
    scopes: &[&str],
    ttl_ms: i64,
    now_unix_ms: i64,
) -> Result<IssuedGrantV1, CryptoError> {
    if !is_valid_node_id(connector_id) {
        return Err(CryptoError::InvalidPairing(format!(
            "invalid connectorId '{connector_id}'"
        )));
    }
    let id = generate_uuid_v4()?;
    let rng = SystemRandom::new();
    let mut secret = Zeroizing::new([0u8; T3MP1_SECRET_BYTES]);
    rng.fill(&mut *secret)
        .map_err(|_| CryptoError::Hpke("OS CSPRNG failure".into()))?;
    let pair_kp = derive_pairing_key_v1(&secret, &id)?;
    let expanded = expand_scopes_v1(scopes)?;
    let grant = GrantV1 {
        v: 1,
        id: id.clone(),
        connector_id: connector_id.to_string(),
        scopes: expanded,
        pairing_key: pair_kp.public_key_b64(),
        issued_at: format_rfc3339_millis(now_unix_ms),
        pair_by: format_rfc3339_millis(now_unix_ms + ttl_ms),
    };
    let signed = sign_value_v1(SignatureKindV1::Grant, &grant, admin_key)?;
    let code = format_pairing_code_v1(&PairingCodeV1 {
        grant_id: id,
        secret,
        admin_fingerprint: admin_key.fingerprint(),
    })?;
    Ok(IssuedGrantV1 {
        grant,
        signed,
        code,
    })
}

/// Verifies and decodes a v1 admin-signed `GrantV1`.
pub fn open_grant_v1(signed: &SignedV1, admin_key: &Ed25519PublicKey) -> Result<GrantV1, CryptoError> {
    if !verify_payload_v1(SignatureKindV1::Grant, &signed.payload, &signed.sig, admin_key) {
        return Err(CryptoError::InvalidSignature(
            "grant signature does not check against admin key".into(),
        ));
    }
    let grant: GrantV1 = serde_json::from_str(&signed.payload)?;
    if grant.v != 1
        || !is_uuid_v1(&grant.id)
        || !is_valid_node_id(&grant.connector_id)
        || !is_raw_key(&grant.pairing_key)
        || parse_time_v1(&grant.issued_at).is_none()
        || parse_time_v1(&grant.pair_by).is_none()
    {
        return Err(CryptoError::InvalidPairing("malformed v1 grant payload".into()));
    }
    // Reject small-order pairingKey!
    let _ = Ed25519PublicKey::from_b64(&grant.pairing_key)?;
    Ok(grant)
}

/// Creates a dual-signed v1 `SignedBindingV1` (`pairingSig` + `selfSig`).
pub fn sign_binding_v1(
    grant: &GrantV1,
    code: &PairingCodeV1,
    signing_key: &Ed25519KeyPair,
    encryption_key: &X25519KeyPair,
    now_unix_ms: i64,
) -> Result<SignedBindingV1, CryptoError> {
    let binding = BindingV1 {
        v: 1,
        grant_id: grant.id.clone(),
        connector_id: grant.connector_id.clone(),
        signing_key: signing_key.public_key_b64(),
        encryption_key: encryption_key.public_key_b64(),
        bound_at: format_rfc3339_millis(now_unix_ms),
    };
    let pair_kp = derive_pairing_key_v1(&code.secret, &grant.id)?;
    let pairing = sign_value_v1(SignatureKindV1::Binding, &binding, &pair_kp)?;
    let self_sig = sign_payload_v1(SignatureKindV1::BindingSelf, &pairing.payload, signing_key);
    Ok(SignedBindingV1 {
        payload: pairing.payload,
        pairing_sig: pairing.sig,
        self_sig,
    })
}

/// Verifies a full v1 `EntryV1` (`grant` + `binding`) offline against `admin_key`.
pub fn verify_entry_v1(
    entry: &EntryV1,
    admin_key: &Ed25519PublicKey,
) -> Result<IdentityV1, CryptoError> {
    let grant = open_grant_v1(&entry.grant, admin_key)?;
    let binding: BindingV1 = serde_json::from_str(&entry.binding.payload)?;
    if binding.v != 1 || !is_raw_key(&binding.signing_key) || !is_raw_key(&binding.encryption_key) {
        return Err(CryptoError::InvalidPairing("binding is malformed".into()));
    }
    let bound_at = parse_time_v1(&binding.bound_at)
        .ok_or_else(|| CryptoError::InvalidPairing("invalid binding boundAt".into()))?;
    let pair_by = parse_time_v1(&grant.pair_by)
        .ok_or_else(|| CryptoError::InvalidPairing("invalid grant pairBy".into()))?;

    if binding.grant_id != grant.id || binding.connector_id != grant.connector_id {
        return Err(CryptoError::InvalidPairing(
            "binding is for another grant".into(),
        ));
    }

    let pairing_pk = Ed25519PublicKey::from_b64(&grant.pairing_key)?;
    let signing_pk = Ed25519PublicKey::from_b64(&binding.signing_key)?;
    // Validate X25519 encryptionKey is non-zero & non-low-order
    let _ = X25519PublicKey::from_b64(&binding.encryption_key)?;

    if !verify_payload_v1(
        SignatureKindV1::Binding,
        &entry.binding.payload,
        &entry.binding.pairing_sig,
        &pairing_pk,
    ) {
        return Err(CryptoError::InvalidSignature(
            "binding was not signed with the pairing key".into(),
        ));
    }
    if !verify_payload_v1(
        SignatureKindV1::BindingSelf,
        &entry.binding.payload,
        &entry.binding.self_sig,
        &signing_pk,
    ) {
        return Err(CryptoError::InvalidSignature(
            "binding was not signed with its own signing key".into(),
        ));
    }
    if bound_at > pair_by {
        return Err(CryptoError::InvalidPairing(
            "bound after the pairing window".into(),
        ));
    }

    Ok(IdentityV1 {
        connector_id: grant.connector_id,
        grant_id: grant.id,
        issued_at: grant.issued_at,
        scopes: grant.scopes,
        signing_key: binding.signing_key,
        encryption_key: binding.encryption_key,
    })
}

/// Signs a v1 `RevocationV1` with `admin_key`.
pub fn sign_revocation_v1(
    admin_key: &Ed25519KeyPair,
    connector_id: &str,
    grant_id: &str,
    now_unix_ms: i64,
) -> Result<SignedV1, CryptoError> {
    let rev = RevocationV1 {
        v: 1,
        connector_id: connector_id.to_string(),
        grant_id: grant_id.to_string(),
        revoked_at: format_rfc3339_millis(now_unix_ms),
    };
    sign_value_v1(SignatureKindV1::Revocation, &rev, admin_key)
}

/// Verifies and decodes a v1 admin-signed `RevocationV1`.
pub fn open_revocation_v1(
    signed: &SignedV1,
    admin_key: &Ed25519PublicKey,
) -> Result<RevocationV1, CryptoError> {
    if !verify_payload_v1(
        SignatureKindV1::Revocation,
        &signed.payload,
        &signed.sig,
        admin_key,
    ) {
        return Err(CryptoError::InvalidSignature(
            "revocation signature invalid".into(),
        ));
    }
    let rev: RevocationV1 = serde_json::from_str(&signed.payload)?;
    if rev.v != 1 || !is_valid_node_id(&rev.connector_id) || !is_uuid_v1(&rev.grant_id) {
        return Err(CryptoError::InvalidPairing(
            "malformed v1 revocation payload".into(),
        ));
    }
    Ok(rev)
}

// ============================================================================
// v1 Key Registration (`src/identity.ts`)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRegistrationPayloadV1 {
    pub v: u8,
    #[serde(rename = "connectorId")]
    pub connector_id: String,
    #[serde(rename = "signingKey")]
    pub signing_key: String,
    #[serde(rename = "encryptionKey")]
    pub encryption_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRegistrationV1 {
    #[serde(rename = "signingKey")]
    pub signing_key: String,
    #[serde(rename = "encryptionKey")]
    pub encryption_key: String,
    pub proof: SignedV1,
}

/// Creates a self-signed v1 key registration matching `createKeyRegistration` in `src/identity.ts`.
pub fn create_key_registration_v1(
    connector_id: &str,
    signing_key: &Ed25519KeyPair,
    encryption_key: &X25519KeyPair,
) -> Result<KeyRegistrationV1, CryptoError> {
    let signing_pub = signing_key.public_key_b64();
    let encryption_pub = encryption_key.public_key_b64();
    let payload = KeyRegistrationPayloadV1 {
        v: 1,
        connector_id: connector_id.to_string(),
        signing_key: signing_pub.clone(),
        encryption_key: encryption_pub.clone(),
    };
    let proof = sign_value_v1(SignatureKindV1::KeyReg, &payload, signing_key)?;
    Ok(KeyRegistrationV1 {
        signing_key: signing_pub,
        encryption_key: encryption_pub,
        proof,
    })
}

/// Verifies a v1 key registration matching `verifyKeyRegistration` in `src/identity.ts`.
pub fn verify_key_registration_v1(
    connector_id: &str,
    reg: &KeyRegistrationV1,
) -> Result<(Ed25519PublicKey, X25519PublicKey), CryptoError> {
    let signing_bytes = decode_raw_key_32(&reg.signing_key)?;
    if is_small_order_ed25519_point(&signing_bytes) {
        return Err(CryptoError::SmallOrderKey);
    }
    let signing_pk = Ed25519PublicKey::from_bytes(signing_bytes)?;
    let encryption_pk = X25519PublicKey::from_b64(&reg.encryption_key)?;

    if !verify_payload_v1(
        SignatureKindV1::KeyReg,
        &reg.proof.payload,
        &reg.proof.sig,
        &signing_pk,
    ) {
        return Err(CryptoError::InvalidSignature(
            "key registration signature is invalid".into(),
        ));
    }

    let parsed: KeyRegistrationPayloadV1 = serde_json::from_str(&reg.proof.payload)?;
    if parsed.v != 1
        || parsed.connector_id != connector_id
        || parsed.signing_key != reg.signing_key
        || parsed.encryption_key != reg.encryption_key
    {
        return Err(CryptoError::InvalidPairing(
            "key registration payload does not match connector and keys".into(),
        ));
    }
    Ok((signing_pk, encryption_pk))
}

// ============================================================================
// v1 Sealed Transfers (`src/core/transfer/seal.ts`)
// ============================================================================

/// Exact v1 `TransferHeader` (`src/core/transfer/seal.ts`). Field order matches TS `JSON.stringify`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferHeaderV1 {
    pub v: u8,
    pub id: String,
    #[serde(rename = "type")]
    pub transfer_type: String,
    pub from: String,
    pub to: String,
    #[serde(rename = "toHandle")]
    pub to_handle: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: String,
    pub size: usize,
    pub sha256: String,
    pub nonce: String,
    #[serde(rename = "ephemeralKey")]
    pub ephemeral_key: String,
}

#[derive(Debug, Clone)]
pub struct SealInputV1<'a> {
    pub id: &'a str,
    pub transfer_type: &'a str,
    pub from: &'a str,
    pub to: &'a str,
    pub to_handle: Option<&'a str>,
    pub ttl_ms: i64,
}

#[derive(Debug, Clone)]
pub struct SealedV1 {
    pub header: SignedV1,
    pub ciphertext: Vec<u8>,
}

fn transfer_aad_v1(id: &str, transfer_type: &str, from: &str, to: &str) -> Vec<u8> {
    format!("{id}\n{transfer_type}\n{from}\n{to}").into_bytes()
}

fn transfer_content_key_v1(
    shared: &[u8; 32],
    ephemeral_pub: &[u8; 32],
    recipient_pub: &[u8; 32],
    id: &str,
) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(ephemeral_pub);
    salt[32..].copy_from_slice(recipient_pub);
    let info = format!("t3-mesh/v1/transfer\n{id}");
    hkdf_sha256(&salt, shared, info.as_bytes(), 32)
}

/// Parses and validates a v1 `TransferHeaderV1` without checking the signature (`readHeader` in `seal.ts`).
pub fn read_header_v1(signed: &SignedV1) -> Result<TransferHeaderV1, CryptoError> {
    let header: TransferHeaderV1 = serde_json::from_str(&signed.payload)?;
    let created = parse_time_v1(&header.created_at)
        .ok_or_else(|| CryptoError::InvalidTransfer("invalid createdAt".into()))?;
    let expires = parse_time_v1(&header.expires_at)
        .ok_or_else(|| CryptoError::InvalidTransfer("invalid expiresAt".into()))?;
    let ttl = expires - created;
    let valid_type = matches!(header.transfer_type.as_str(), "files" | "fork" | "fork.result");
    let handle_ok = match &header.to_handle {
        None => true,
        Some(h) => is_handle_v1(h),
    };
    let type_handle_match = (header.transfer_type == "files") == header.to_handle.is_some();
    let sha_ok = header.sha256.len() == 64
        && header
            .sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    let nonce_ok = URL_SAFE_NO_PAD
        .decode(&header.nonce)
        .map(|n| n.len() == 12)
        .unwrap_or(false);

    if header.v != 1
        || !is_uuid_v1(&header.id)
        || !valid_type
        || !is_valid_node_id(&header.from)
        || !is_valid_node_id(&header.to)
        || !handle_ok
        || !type_handle_match
        || ttl <= 0
        || ttl > MAX_TRANSFER_TTL_MS_V1
        || header.size <= 16
        || !sha_ok
        || !nonce_ok
        || !is_raw_key(&header.ephemeral_key)
    {
        return Err(CryptoError::InvalidTransfer(
            "malformed v1 transfer header".into(),
        ));
    }
    Ok(header)
}

/// Seals a v1 transfer byte-identically to `seal()` in `src/core/transfer/seal.ts`.
pub fn seal_v1(
    input: &SealInputV1<'_>,
    plaintext: &[u8],
    sender_signing: &Ed25519KeyPair,
    recipient_enc_pk: &X25519PublicKey,
    now_unix_ms: i64,
) -> Result<SealedV1, CryptoError> {
    if plaintext.is_empty() {
        return Err(CryptoError::InvalidTransfer(
            "v1 sealed transfer plaintext must be non-empty (size > 16)".into(),
        ));
    }
    let ephemeral = X25519KeyPair::generate()?;
    let ephem_pub = ephemeral.public_key_bytes();
    let shared = ephemeral.diffie_hellman(recipient_enc_pk)?;
    let key = transfer_content_key_v1(&shared, &ephem_pub, recipient_enc_pk.as_bytes(), input.id)?;

    let rng = SystemRandom::new();
    let mut nonce_bytes = [0u8; 12];
    rng.fill(&mut nonce_bytes)
        .map_err(|_| CryptoError::Hpke("OS CSPRNG failure".into()))?;

    let unbound = UnboundKey::new(&aead::AES_256_GCM, &key)
        .map_err(|_| CryptoError::Hpke("failed to construct AES-256-GCM key".into()))?;
    let aead_key = LessSafeKey::new(unbound);
    let aad = transfer_aad_v1(input.id, input.transfer_type, input.from, input.to);

    let mut ciphertext = Vec::with_capacity(plaintext.len() + 16);
    ciphertext.extend_from_slice(plaintext);
    aead_key
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(&aad),
            &mut ciphertext,
        )
        .map_err(|_| CryptoError::Hpke("v1 seal AEAD failed".into()))?;

    let clamped_ttl = input.ttl_ms.min(MAX_TRANSFER_TTL_MS_V1);
    let header = TransferHeaderV1 {
        v: 1,
        id: input.id.to_string(),
        transfer_type: input.transfer_type.to_string(),
        from: input.from.to_string(),
        to: input.to.to_string(),
        to_handle: input.to_handle.map(ToOwned::to_owned),
        created_at: format_rfc3339_millis(now_unix_ms),
        expires_at: format_rfc3339_millis(now_unix_ms + clamped_ttl),
        size: ciphertext.len(),
        sha256: hex::encode(Sha256::digest(&ciphertext)),
        nonce: URL_SAFE_NO_PAD.encode(nonce_bytes),
        ephemeral_key: URL_SAFE_NO_PAD.encode(ephem_pub),
    };
    let signed = sign_value_v1(SignatureKindV1::Transfer, &header, sender_signing)?;
    Ok(SealedV1 {
        header: signed,
        ciphertext,
    })
}

/// Verifies signature + SHA-256 and opens a v1 sealed transfer (`open()` in `src/core/transfer/seal.ts`).
pub fn open_v1(
    signed: &SignedV1,
    ciphertext: &[u8],
    sender_signing_pk: &Ed25519PublicKey,
    recipient_enc_kp: &X25519KeyPair,
) -> Result<(TransferHeaderV1, Zeroizing<Vec<u8>>), CryptoError> {
    let header = read_header_v1(signed)?;
    if !verify_payload_v1(
        SignatureKindV1::Transfer,
        &signed.payload,
        &signed.sig,
        sender_signing_pk,
    ) {
        return Err(CryptoError::InvalidSignature(
            "v1 transfer header is not signed by sender's key".into(),
        ));
    }
    if ciphertext.len() != header.size
        || hex::encode(Sha256::digest(ciphertext)) != header.sha256
    {
        return Err(CryptoError::InvalidTransfer(
            "v1 ciphertext size or sha256 does not match header".into(),
        ));
    }

    let ephem_pk = X25519PublicKey::from_b64(&header.ephemeral_key)?;
    let shared = recipient_enc_kp.diffie_hellman(&ephem_pk)?;
    let key = transfer_content_key_v1(
        &shared,
        ephem_pk.as_bytes(),
        &recipient_enc_kp.public_key_bytes(),
        &header.id,
    )?;

    let nonce_vec = URL_SAFE_NO_PAD
        .decode(&header.nonce)
        .map_err(|_| CryptoError::InvalidTransfer("invalid v1 nonce".into()))?;
    let nonce_bytes: [u8; 12] = nonce_vec
        .try_into()
        .map_err(|_| CryptoError::InvalidTransfer("v1 nonce must be 12 bytes".into()))?;

    let unbound = UnboundKey::new(&aead::AES_256_GCM, &key)
        .map_err(|_| CryptoError::Hpke("failed to construct AES-256-GCM key".into()))?;
    let aead_key = LessSafeKey::new(unbound);
    let aad = transfer_aad_v1(&header.id, &header.transfer_type, &header.from, &header.to);

    let mut buf = Zeroizing::new(ciphertext.to_vec());
    let pt_len = aead_key
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_bytes),
            Aad::from(&aad),
            &mut buf,
        )
        .map_err(|_| {
            CryptoError::DecryptionFailed(
                "v1 transfer decryption failed (wrong key or altered)".into(),
            )
        })?
        .len();
    buf.truncate(pt_len);
    Ok((header, buf))
}

// ============================================================================
// v1 `HYP1` Gzipped File Pack (`src/core/transfer/pack.ts`)
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hyp1FileEntry {
    pub name: String,
    pub size: usize,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hyp1Manifest {
    pub v: u8,
    #[serde(rename = "fromHandle", skip_serializing_if = "Option::is_none")]
    pub from_handle: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    pub files: Vec<Hyp1FileEntry>,
}

#[derive(Debug, Clone)]
pub struct PackedHyp1 {
    pub payload: Vec<u8>,
    pub manifest: Hyp1Manifest,
    pub raw_bytes: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpackedHyp1File {
    pub name: String,
    pub path: PathBuf,
    pub size: usize,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnpackedHyp1 {
    pub dest_dir: PathBuf,
    pub from_handle: Option<String>,
    pub note: Option<String>,
    pub files: Vec<UnpackedHyp1File>,
}

/// Validates a flat `HYP1` filename identically to `isSafePackFilename` in `pack.ts`.
pub fn is_safe_hyp1_filename(name: &str) -> bool {
    if name.is_empty() || name.len() > HYP1_MAX_FILENAME_LEN {
        return false;
    }
    if name
        .bytes()
        .any(|b| b < 0x20 || b == 0x7f || b == b'/' || b == b'\\')
    {
        return false;
    }
    if name == "." || name == ".." || name.contains("..") || name.starts_with('.') {
        return false;
    }
    Path::new(name).file_name().and_then(|s| s.to_str()) == Some(name)
}

fn sanitize_hyp1_basename(path: &Path) -> String {
    let raw_base = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("file");
    let mut s: String = raw_base
        .chars()
        .map(|c| {
            let cp = c as u32;
            if cp < 0x20 || cp == 0x7f || c == '/' || c == '\\' {
                '_'
            } else {
                c
            }
        })
        .collect();
    while s.contains("..") {
        s = s.replace("..", "_");
    }
    let trimmed = s.trim_start_matches('.');
    let clean = if trimmed.is_empty() { "file" } else { trimmed };
    if clean.len() <= HYP1_MAX_FILENAME_LEN {
        return clean.to_string();
    }
    if let Some(ext) = Path::new(clean).extension().and_then(|e| e.to_str()) {
        let dot_ext_len = ext.len() + 1;
        if dot_ext_len > 1 && dot_ext_len < 32 {
            let prefix_len = HYP1_MAX_FILENAME_LEN - dot_ext_len;
            return format!("{}.{}", &clean[..prefix_len], ext);
        }
    }
    clean[..HYP1_MAX_FILENAME_LEN].to_string()
}

fn allocate_unique_hyp1_name(base: &str, seen_lower: &mut HashSet<String>) -> Result<String, CryptoError> {
    if seen_lower.insert(base.to_ascii_lowercase()) {
        return Ok(base.to_string());
    }
    let dot_ext = Path::new(base)
        .extension()
        .and_then(|e| e.to_str())
        .map(|e| format!(".{e}"))
        .filter(|e| e.len() < base.len() && e.len() <= 32)
        .unwrap_or_default();
    let stem = &base[..base.len() - dot_ext.len()];
    for n in 2..100_000usize {
        let tag = format!("-{n}");
        let max_stem = HYP1_MAX_FILENAME_LEN
            .saturating_sub(tag.len() + dot_ext.len())
            .max(1);
        let candidate = format!("{}{tag}{dot_ext}", &stem[..stem.len().min(max_stem)]);
        if seen_lower.insert(candidate.to_ascii_lowercase()) {
            return Ok(candidate);
        }
    }
    Err(CryptoError::InvalidTransfer(format!(
        "could not allocate unique HYP1 filename for '{base}'"
    )))
}

/// Packs regular files into a gzipped `HYP1` binary frame byte-compatible with `packFiles` in `pack.ts`.
pub fn pack_hyp1(
    file_paths: &[&Path],
    from_handle: Option<&str>,
    note: Option<&str>,
    max_raw_bytes: Option<usize>,
    max_files: Option<usize>,
) -> Result<PackedHyp1, CryptoError> {
    let max_raw = max_raw_bytes.unwrap_or(HYP1_MAX_RAW_BYTES);
    let max_cnt = max_files.unwrap_or(HYP1_MAX_FILES);

    if file_paths.is_empty() {
        return Err(CryptoError::InvalidTransfer(
            "expected at least one file path to pack".into(),
        ));
    }
    if file_paths.len() > max_cnt {
        return Err(CryptoError::ArchiveLimitExceeded(format!(
            "too many files ({}); limit is {max_cnt}",
            file_paths.len()
        )));
    }

    let mut seen_lower = HashSet::new();
    let mut entries = Vec::with_capacity(file_paths.len());
    let mut chunks = Vec::with_capacity(file_paths.len());
    let mut total_raw = 0usize;

    for &path in file_paths {
        let st = fs::metadata(path)?;
        if !st.is_file() {
            return Err(CryptoError::UnsafeArchiveEntry(format!(
                "path is not a regular file: {}",
                path.display()
            )));
        }
        let content = fs::read(path)?;
        total_raw = total_raw
            .checked_add(content.len())
            .ok_or_else(|| CryptoError::ArchiveLimitExceeded("raw size overflow".into()))?;
        if total_raw > max_raw {
            return Err(CryptoError::ArchiveLimitExceeded(format!(
                "total file bytes exceed limit of {max_raw}"
            )));
        }
        let sanitized = sanitize_hyp1_basename(path);
        let name = allocate_unique_hyp1_name(&sanitized, &mut seen_lower)?;
        if !is_safe_hyp1_filename(&name) {
            return Err(CryptoError::UnsafeArchiveEntry(format!(
                "could not derive safe filename from {}",
                path.display()
            )));
        }
        let sha256 = hex::encode(Sha256::digest(&content));
        entries.push(Hyp1FileEntry {
            name,
            size: content.len(),
            sha256,
        });
        chunks.push(content);
    }

    let manifest = Hyp1Manifest {
        v: 1,
        from_handle: from_handle.filter(|s| !s.is_empty()).map(ToOwned::to_owned),
        note: note.filter(|s| !s.is_empty()).map(ToOwned::to_owned),
        files: entries,
    };
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    if manifest_bytes.len() > HYP1_MAX_MANIFEST_BYTES {
        return Err(CryptoError::ArchiveLimitExceeded(
            "HYP1 manifest exceeds 1 MiB limit".into(),
        ));
    }

    let mut gz = GzEncoder::new(Vec::new(), Compression::default());
    gz.write_all(HYP1_MAGIC)?;
    gz.write_all(&(manifest_bytes.len() as u32).to_be_bytes())?;
    gz.write_all(&manifest_bytes)?;
    for c in &chunks {
        gz.write_all(c)?;
    }
    let payload = gz.finish()?;

    Ok(PackedHyp1 {
        payload,
        manifest,
        raw_bytes: total_raw,
    })
}

/// Safely inflates, verifies, and extracts a v1 `HYP1` gzipped file pack (`unpackFiles` in `pack.ts`).
pub fn unpack_hyp1(
    payload: &[u8],
    dest_dir: &Path,
    max_raw_bytes: Option<usize>,
    max_files: Option<usize>,
) -> Result<UnpackedHyp1, CryptoError> {
    let max_raw = max_raw_bytes.unwrap_or(HYP1_MAX_RAW_BYTES);
    let max_cnt = max_files.unwrap_or(HYP1_MAX_FILES);
    let max_inflated = max_raw.saturating_add(HYP1_MAX_MANIFEST_BYTES);

    // Bounded gunzip to defeat gzip bombs
    let mut gz = GzDecoder::new(payload);
    let mut raw = Vec::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = gz.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if raw.len().saturating_add(n) > max_inflated {
            return Err(CryptoError::ArchiveLimitExceeded(
                "HYP1 gzip output exceeds maximum allowed length".into(),
            ));
        }
        raw.extend_from_slice(&buf[..n]);
    }

    if raw.len() < 8 {
        return Err(CryptoError::InvalidTransfer(
            "corrupt HYP1 pack: truncated header".into(),
        ));
    }
    if &raw[..4] != HYP1_MAGIC {
        return Err(CryptoError::InvalidTransfer(
            "corrupt HYP1 pack: invalid magic".into(),
        ));
    }
    let manifest_len = u32::from_be_bytes(raw[4..8].try_into().unwrap()) as usize;
    if manifest_len == 0 || manifest_len > HYP1_MAX_MANIFEST_BYTES || 8 + manifest_len > raw.len() {
        return Err(CryptoError::InvalidTransfer(
            "corrupt HYP1 pack: invalid manifest length".into(),
        ));
    }

    let manifest: Hyp1Manifest = serde_json::from_slice(&raw[8..8 + manifest_len])?;
    if manifest.v != 1 || manifest.files.is_empty() || manifest.files.len() > max_cnt {
        return Err(CryptoError::InvalidTransfer(
            "corrupt HYP1 pack: invalid version or file count".into(),
        ));
    }

    // Verify ALL filenames, sizes, and SHA-256 hashes BEFORE touching disk!
    let mut seen_lower = HashSet::new();
    let mut verified: Vec<(&Hyp1FileEntry, &[u8])> = Vec::with_capacity(manifest.files.len());
    let mut offset = 8 + manifest_len;
    let mut total_raw = 0usize;

    for entry in &manifest.files {
        if !is_safe_hyp1_filename(&entry.name) {
            return Err(CryptoError::UnsafeArchiveEntry(format!(
                "unsafe HYP1 filename '{}'",
                entry.name
            )));
        }
        if !seen_lower.insert(entry.name.to_ascii_lowercase()) {
            return Err(CryptoError::UnsafeArchiveEntry(format!(
                "duplicate HYP1 filename '{}'",
                entry.name
            )));
        }
        if entry.sha256.len() != 64
            || !entry
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(CryptoError::InvalidTransfer(format!(
                "invalid sha256 for '{}'",
                entry.name
            )));
        }
        total_raw = total_raw
            .checked_add(entry.size)
            .ok_or_else(|| CryptoError::ArchiveLimitExceeded("raw size overflow".into()))?;
        if total_raw > max_raw {
            return Err(CryptoError::ArchiveLimitExceeded(format!(
                "HYP1 raw size exceeds limit of {max_raw}"
            )));
        }
        if offset.saturating_add(entry.size) > raw.len() {
            return Err(CryptoError::InvalidTransfer(format!(
                "truncated HYP1 data for '{}'",
                entry.name
            )));
        }
        let slice = &raw[offset..offset + entry.size];
        offset += entry.size;
        let actual_sha = hex::encode(Sha256::digest(slice));
        if actual_sha != entry.sha256 {
            return Err(CryptoError::InvalidTransfer(format!(
                "HYP1 sha256 mismatch for '{}'",
                entry.name
            )));
        }
        verified.push((entry, slice));
    }

    if offset != raw.len() {
        return Err(CryptoError::InvalidTransfer(
            "corrupt HYP1 pack: unexpected trailing bytes".into(),
        ));
    }

    fs::create_dir_all(dest_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dest_dir, fs::Permissions::from_mode(0o700))?;
    }
    let abs_dest = fs::canonicalize(dest_dir)?;

    let mut unpacked_files = Vec::with_capacity(verified.len());
    let write_res: Result<(), CryptoError> = (|| {
        for (entry, data) in verified {
            let file_path = abs_dest.join(&entry.name);
            if file_path.parent() != Some(abs_dest.as_path()) {
                return Err(CryptoError::UnsafeArchiveEntry(format!(
                    "HYP1 path escape for '{}'",
                    entry.name
                )));
            }
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut f = opts.open(&file_path)?;
            f.write_all(data)?;
            f.flush()?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600))?;
            }
            unpacked_files.push(UnpackedHyp1File {
                name: entry.name.clone(),
                path: file_path,
                size: entry.size,
                sha256: entry.sha256.clone(),
            });
        }
        Ok(())
    })();

    if let Err(err) = write_res {
        let _ = fs::remove_dir_all(&abs_dest);
        return Err(err);
    }

    Ok(UnpackedHyp1 {
        dest_dir: abs_dest,
        from_handle: manifest.from_handle.filter(|s| !s.is_empty()),
        note: manifest.note.filter(|s| !s.is_empty()),
        files: unpacked_files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rfc3339::now_unix_ms;
    use tempfile::TempDir;

    #[test]
    fn v1_grant_binding_entry_revocation_and_key_reg_roundtrip() {
        let admin = Ed25519KeyPair::generate().unwrap();
        let alice_sign = Ed25519KeyPair::generate().unwrap();
        let alice_enc = X25519KeyPair::generate().unwrap();
        let now = now_unix_ms();

        let issued = issue_grant_v1(&admin, "alice@macbook", &["*"], 300_000, now).unwrap();
        let parsed_code = parse_pairing_code_v1(&issued.code).unwrap();
        assert_eq!(parsed_code.grant_id, issued.grant.id);
        assert_eq!(parsed_code.admin_fingerprint, admin.fingerprint());

        let binding =
            sign_binding_v1(&issued.grant, &parsed_code, &alice_sign, &alice_enc, now).unwrap();
        let entry = EntryV1 {
            grant: issued.signed,
            binding,
        };
        let identity = verify_entry_v1(&entry, &admin.public_key()).unwrap();
        assert_eq!(identity.connector_id, "alice@macbook");
        assert_eq!(identity.signing_key, alice_sign.public_key_b64());
        assert_eq!(identity.encryption_key, alice_enc.public_key_b64());

        let rev = sign_revocation_v1(&admin, "alice@macbook", &issued.grant.id, now).unwrap();
        let opened_rev = open_revocation_v1(&rev, &admin.public_key()).unwrap();
        assert_eq!(opened_rev.grant_id, issued.grant.id);

        let reg = create_key_registration_v1("alice@macbook", &alice_sign, &alice_enc).unwrap();
        let (s_pk, e_pk) = verify_key_registration_v1("alice@macbook", &reg).unwrap();
        assert_eq!(s_pk, alice_sign.public_key());
        assert_eq!(e_pk, alice_enc.public_key());
    }

    #[test]
    fn v1_seal_open_and_hyp1_pack_unpack_roundtrip() {
        let sender_sign = Ed25519KeyPair::generate().unwrap();
        let recip_enc = X25519KeyPair::generate().unwrap();
        let now = now_unix_ms();

        let tmp = TempDir::new().unwrap();
        let f1 = tmp.path().join("notes.txt");
        fs::write(&f1, b"hello from v1 HYP1").unwrap();

        let packed = pack_hyp1(&[f1.as_path()], Some("claude"), Some("attached"), None, None).unwrap();
        let sealed = seal_v1(
            &SealInputV1 {
                id: "11111111-2222-4333-8444-555555555555",
                transfer_type: "files",
                from: "alice@macbook",
                to: "bob@laptop",
                to_handle: Some("codex"),
                ttl_ms: 60_000,
            },
            &packed.payload,
            &sender_sign,
            &recip_enc.public_key(),
            now,
        )
        .unwrap();

        let (hdr, opened_payload) =
            open_v1(&sealed.header, &sealed.ciphertext, &sender_sign.public_key(), &recip_enc)
                .unwrap();
        assert_eq!(hdr.from, "alice@macbook");
        let dest = tmp.path().join("out");
        let unpacked = unpack_hyp1(&opened_payload, &dest, None, None).unwrap();
        assert_eq!(unpacked.from_handle.as_deref(), Some("claude"));
        assert_eq!(unpacked.note.as_deref(), Some("attached"));
        assert_eq!(fs::read(&unpacked.files[0].path).unwrap(), b"hello from v1 HYP1");
    }
}
