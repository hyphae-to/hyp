//! Active v1 pairing-code, grant issuance, scope and signature compatibility.
//!
//! Retains the byte contracts used by am2 invites and `/v1/pair`.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::hpke::hkdf_sha256;
use crate::keys::{Ed25519KeyPair, Ed25519PublicKey};
use crate::pairing::is_valid_node_id;
use crate::rfc3339::format_rfc3339_millis;

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

fn generate_uuid_v4() -> Result<String, CryptoError> {
    let rng = SystemRandom::new();
    let mut b = [0u8; 16];
    rng.fill(&mut b)
        .map_err(|_| CryptoError::Hpke("OS CSPRNG failure".into()))?;
    Ok(hyp_proto::uuid::format_uuid_v4(b))
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

/// Expands v1 scope shorthands through the protocol owner, preserving crypto diagnostics.
pub fn expand_scopes_v1(input: &[&str]) -> Result<Vec<String>, CryptoError> {
    use hyp_proto::scopes::{ScopeError, expand_v1_scopes};

    expand_v1_scopes(input).map_err(|error| {
        let message = match error {
            ScopeError::EmptyScopes => "a grant needs at least one scope".to_owned(),
            ScopeError::DuplicateBase {
                first,
                second,
                base,
            } => format!("conflicting forms of scope '{base}': '{first}' vs '{second}'"),
            ScopeError::InvalidScope { scope, .. } => {
                if let Some(rest) = scope.strip_prefix("forks:receive") {
                    if let Some(mode) = rest.strip_prefix('/') {
                        format!("unknown runtime mode '{mode}'")
                    } else {
                        format!("invalid scope '{scope}'")
                    }
                } else if let Some((base, _)) = scope.split_once('=') {
                    if matches!(base, "files:send" | "forks:send") {
                        format!("invalid recipient in scope '{scope}'")
                    } else {
                        format!("scope '{scope}' does not accept recipients")
                    }
                } else {
                    format!("unknown scope '{scope}'")
                }
            }
        };
        CryptoError::InvalidPairing(message)
    })
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_errors_keep_crypto_diagnostics() {
        let cases: &[(&[&str], &str)] = &[
            (&[], "a grant needs at least one scope"),
            (&["forks:receive"], "invalid scope 'forks:receive'"),
            (&["forks:receive/fast"], "unknown runtime mode 'fast'"),
            (&["files:send="], "invalid recipient in scope 'files:send='"),
            (
                &["events:subscribe=alice"],
                "scope 'events:subscribe=alice' does not accept recipients",
            ),
            (&["unknown"], "unknown scope 'unknown'"),
            (
                &["files:send", "files:send=alice"],
                "conflicting forms of scope 'files:send': 'files:send' vs 'files:send=alice'",
            ),
        ];
        for (input, expected) in cases {
            let error = expand_scopes_v1(input).unwrap_err();
            assert!(
                matches!(error, CryptoError::InvalidPairing(ref message) if message == expected),
                "{input:?}: {error}"
            );
        }
    }

    #[test]
    fn issued_grant_retains_pairing_code_key_and_signature_contract() {
        let admin = Ed25519KeyPair::generate().unwrap();
        let now = 1_700_000_000_000;
        let issued = issue_grant_v1(&admin, "alice@macbook", &["*"], 300_000, now).unwrap();
        let code = parse_pairing_code_v1(&issued.code).unwrap();
        assert_eq!(code.grant_id, issued.grant.id);
        assert_eq!(code.admin_fingerprint, admin.fingerprint());
        assert_eq!(format_pairing_code_v1(&code).unwrap(), issued.code);
        assert_eq!(
            derive_pairing_key_v1(&code.secret, &code.grant_id)
                .unwrap()
                .public_key_b64(),
            issued.grant.pairing_key
        );
        assert_eq!(issued.grant.connector_id, "alice@macbook");
        assert_eq!(
            issued.grant.scopes,
            [
                "messages:send",
                "messages:receive",
                "events:subscribe",
                "files:send",
                "files:receive",
                "forks:send",
                "forks:receive/full-access",
            ]
        );
        assert_eq!(issued.grant.issued_at, format_rfc3339_millis(now));
        assert_eq!(issued.grant.pair_by, format_rfc3339_millis(now + 300_000));
        assert_eq!(
            serde_json::from_str::<GrantV1>(&issued.signed.payload).unwrap(),
            issued.grant
        );
        assert!(verify_payload_v1(
            SignatureKindV1::Grant,
            &issued.signed.payload,
            &issued.signed.sig,
            &admin.public_key()
        ));
    }
}
