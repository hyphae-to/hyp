//! Zeroized Ed25519 & X25519 keys, RFC 8410 PKCS#8/SPKI DER interop,
//! RFC 7517/8037 OKP JWKs, RFC 7638 JWK Thumbprints (`kid`), and
//! strict domain-separated Ed25519 signing/verification.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom, SystemRandom};
use ring::signature::{self, KeyPair as _};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::jcs::to_canonical_json;
use crate::x25519::{is_low_order_x25519_point, x25519_dh, x25519_public_from_private};

fn domain_message(domain: &[u8], payload: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut msg = Zeroizing::new(Vec::with_capacity(domain.len() + payload.len()));
    msg.extend_from_slice(domain);
    msg.extend_from_slice(payload);
    msg
}

pub(crate) fn sign_with_domain(signer: &Ed25519KeyPair, domain: &[u8], payload: &[u8]) -> String {
    let msg = domain_message(domain, payload);
    let sig = signer.sign_raw(&msg);
    URL_SAFE_NO_PAD.encode(sig)
}

pub(crate) fn verify_with_domain(
    pk: &Ed25519PublicKey,
    domain: &[u8],
    payload: &[u8],
    sig_b64: &str,
) -> Result<(), CryptoError> {
    let sig = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|e| CryptoError::InvalidSignature(format!("invalid base64url sig: {e}")))?;
    let msg = domain_message(domain, payload);
    pk.verify_raw(&msg, &sig)
}

/// RFC 8410 PKCS#8 v1 DER prefix for a raw 32-byte Ed25519 private seed (16 bytes).
/// Identical to Node `node:crypto` `export({ format: "der", type: "pkcs8" })`.
const ED25519_PKCS8_V1_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];

/// RFC 8410 PKCS#8 v1 DER prefix for a raw 32-byte X25519 private key (16 bytes).
/// Identical to Node `node:crypto` `export({ format: "der", type: "pkcs8" })`.
const X25519_PKCS8_V1_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
];

/// RFC 8410 SPKI DER prefix for a raw 32-byte Ed25519 public key (12 bytes).
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// RFC 8410 SPKI DER prefix for a raw 32-byte X25519 public key (12 bytes).
const X25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e, 0x03, 0x21, 0x00,
];

/// AlgorithmIdentifier DER bytes for Ed25519 (`OID 1.3.101.112`).
const ED25519_ALG_ID: [u8; 7] = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];

/// AlgorithmIdentifier DER bytes for X25519 (`OID 1.3.101.110`).
const X25519_ALG_ID: [u8; 7] = [0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x6e];

/// `p = 2^255 - 19` in little-endian bytes.
const ED25519_P_LE: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
];

/// Canonical little-endian y-coordinates (mod p) of the eight small-order Ed25519 points
/// (libsodium blocklist, matching `src/core/identity/keys.ts`).
const SMALL_ORDER_ED25519_Y_LE: [[u8; 32]; 5] = [
    // 0
    [0u8; 32],
    // 1
    [
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ],
    // p - 1
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // 0x05fc536d880238b13933c6d305acdfd5f098eff289f4c345b027b2c28f95e826 (little-endian)
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
    // 0x7a03ac9277fdc74ec6cc392cfa53202a0f67100d760b3cba4fd84d3d706a17c7 (little-endian)
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
];

/// Returns `true` if `bytes` encodes a small-order Ed25519 point (in any encoding,
/// including sign bit and non-canonical `y >= p`).
pub fn is_small_order_ed25519_point(bytes: &[u8]) -> bool {
    if bytes.len() != 32 {
        return true;
    }
    let mut y = [0u8; 32];
    y.copy_from_slice(bytes);
    y[31] &= 0x7f;

    // Reduce y mod (2^255 - 19): since y < 2^255, y >= p iff bytes[1..31] == 0xff,
    // bytes[31] == 0x7f, and bytes[0] >= 0xed.
    let ge_p = y[31] == 0x7f && y[1..31].iter().all(|&b| b == 0xff) && y[0] >= 0xed;
    if ge_p {
        let reduced = y[0] - 0xed;
        y = [0u8; 32];
        y[0] = reduced;
    }

    SMALL_ORDER_ED25519_Y_LE.contains(&y)
}

/// Returns `true` if the Ed25519 point uses a non-canonical `y >= 2^255 - 19`.
pub fn is_non_canonical_ed25519_y(bytes: &[u8; 32]) -> bool {
    let mut y = *bytes;
    y[31] &= 0x7f;
    // Compare little-endian against ED25519_P_LE
    for i in (0..32).rev() {
        if y[i] > ED25519_P_LE[i] {
            return true;
        }
        if y[i] < ED25519_P_LE[i] {
            return false;
        }
    }
    true // y == p is non-canonical
}

/// Validates and decodes a canonical 43-char base64url (no-pad) 32-byte raw key.
pub fn decode_raw_key_32(b64: &str) -> Result<[u8; 32], CryptoError> {
    if b64.len() != 43 {
        return Err(CryptoError::InvalidKey(
            "expected 43-character base64url 32-byte key".into(),
        ));
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(b64)
        .map_err(|e| CryptoError::InvalidKey(format!("invalid base64url key: {e}")))?;
    decoded
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("decoded key is not 32 bytes".into()))
}

/// Returns `true` if `value` is a valid 43-char base64url encoding of 32 raw key bytes.
pub fn is_raw_key(value: &str) -> bool {
    decode_raw_key_32(value).is_ok()
}

/// First 8 bytes of SHA-256 of raw 32-byte public key, lowercase hex (16 chars).
/// Byte-identical to `fingerprint()` in `src/core/identity/keys.ts`.
pub fn fingerprint_bytes(raw_pub: &[u8; 32]) -> String {
    let digest = Sha256::digest(raw_pub);
    hex::encode(&digest[..8])
}

/// Standard RFC 7517 / RFC 8037 Octet Key Pair (OKP) JSON Web Key.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(from = "hyp_proto::manifest::OkpJwk<String>")]
pub struct OkpJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
}

impl Serialize for OkpJwk {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        hyp_proto::manifest::OkpJwk {
            kty: self.kty.as_str(),
            crv: self.crv.as_str(),
            x: self.x.as_str(),
        }
        .serialize(serializer)
    }
}

impl From<hyp_proto::manifest::OkpJwk<String>> for OkpJwk {
    fn from(jwk: hyp_proto::manifest::OkpJwk<String>) -> Self {
        Self {
            kty: jwk.kty,
            crv: jwk.crv,
            x: jwk.x,
        }
    }
}

impl From<&hyp_proto::manifest::OkpJwk> for OkpJwk {
    fn from(jwk: &hyp_proto::manifest::OkpJwk) -> Self {
        Self {
            kty: jwk.kty.clone(),
            crv: jwk.crv.as_str().to_string(),
            x: jwk.x.clone(),
        }
    }
}

impl OkpJwk {
    /// Constructs an Ed25519 OKP JWK from raw 32-byte public key.
    pub fn ed25519(raw_pub: &[u8; 32]) -> Self {
        Self {
            kty: "OKP".to_string(),
            crv: "Ed25519".to_string(),
            x: URL_SAFE_NO_PAD.encode(raw_pub),
        }
    }

    /// Constructs an X25519 OKP JWK from raw 32-byte public key.
    pub fn x25519(raw_pub: &[u8; 32]) -> Self {
        Self {
            kty: "OKP".to_string(),
            crv: "X25519".to_string(),
            x: URL_SAFE_NO_PAD.encode(raw_pub),
        }
    }

    /// Computes the standard **RFC 7638 SHA-256 JWK Thumbprint** (`kid`), base64url no-pad.
    ///
    /// For OKP keys (RFC 8037 §2), the canonical JSON input is:
    /// `{"crv":"<crv>","kty":"OKP","x":"<x>"}`.
    pub fn thumbprint(&self) -> Result<String, CryptoError> {
        if self.kty != "OKP" {
            return Err(CryptoError::InvalidKey(format!(
                "expected JWK kty \"OKP\", got {:?}",
                self.kty
            )));
        }
        let curve = match self.crv.as_str() {
            "Ed25519" => hyp_proto::manifest::OkpCurve::Ed25519,
            "X25519" => hyp_proto::manifest::OkpCurve::X25519,
            _ => {
                return Err(CryptoError::InvalidKey(format!(
                    "unsupported OKP crv {:?}",
                    self.crv
                )));
            }
        };
        let raw = decode_raw_key_32(&self.x)?;
        Ok(hyp_proto::manifest::okp_key_thumbprint(curve, &raw))
    }

    /// Converts and strictly validates this JWK as an `Ed25519PublicKey`.
    pub fn to_ed25519(&self) -> Result<Ed25519PublicKey, CryptoError> {
        if self.kty != "OKP" || self.crv != "Ed25519" {
            return Err(CryptoError::InvalidKey(format!(
                "expected OKP/Ed25519 JWK, got {}/{}",
                self.kty, self.crv
            )));
        }
        Ed25519PublicKey::from_b64(&self.x)
    }

    /// Converts and strictly validates this JWK as an `X25519PublicKey`.
    pub fn to_x25519(&self) -> Result<X25519PublicKey, CryptoError> {
        if self.kty != "OKP" || self.crv != "X25519" {
            return Err(CryptoError::InvalidKey(format!(
                "expected OKP/X25519 JWK, got {}/{}",
                self.kty, self.crv
            )));
        }
        X25519PublicKey::from_b64(&self.x)
    }
}

/// A signed canonical payload (`payload` JSON string + base64url Ed25519 `sig`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedPayload {
    pub payload: String,
    pub sig: String,
}

type ParsedPkcs8 = (Zeroizing<[u8; 32]>, Option<[u8; 32]>);

/// Validates and parses an RFC 8410 PKCS#8 v1 or v2 DER private key for Ed25519 or X25519,
/// returning `(seed[32], optional_embedded_public_key[32])`.
fn parse_rfc8410_pkcs8(
    der: &[u8],
    expected_alg_id: &[u8; 7],
    alg_name: &str,
) -> Result<ParsedPkcs8, CryptoError> {
    // Fast path: exact 48-byte PKCS#8 v1 (Node `node:crypto` & OpenSSL default).
    if der.len() == 48 {
        let prefix = if expected_alg_id == &ED25519_ALG_ID {
            &ED25519_PKCS8_V1_PREFIX
        } else {
            &X25519_PKCS8_V1_PREFIX
        };
        if der[..16] == *prefix {
            let mut seed = Zeroizing::new([0u8; 32]);
            seed.copy_from_slice(&der[16..48]);
            return Ok((seed, None));
        }
    }

    // General strict DER parser for RFC 5958 / RFC 8410 OneAsymmetricKey (v1 or v2):
    // SEQUENCE {
    //   version INTEGER (0 or 1),
    //   privateKeyAlgorithm SEQUENCE { OBJECT IDENTIFIER <oid> },
    //   privateKey OCTET STRING (CONTAINING OCTET STRING [32B seed]),
    //   [optional publicKey [1] BIT STRING (0x00 || 32B pub) or legacy [1] { BIT STRING }]
    // }
    let (seq_body, rest) = read_der_tlv(der, 0x30)?;
    if !rest.is_empty() {
        return Err(CryptoError::InvalidKey(format!(
            "trailing bytes after {alg_name} PKCS#8 SEQUENCE"
        )));
    }
    let (ver_bytes, after_ver) = read_der_tlv(seq_body, 0x02)?;
    let version = match ver_bytes {
        [0x00] => 0u8,
        [0x01] => 1u8,
        _ => {
            return Err(CryptoError::InvalidKey(format!(
                "unsupported {alg_name} PKCS#8 version"
            )));
        }
    };

    if after_ver.len() < expected_alg_id.len()
        || &after_ver[..expected_alg_id.len()] != expected_alg_id
    {
        return Err(CryptoError::InvalidKey(format!(
            "PKCS#8 algorithm OID mismatch (expected {alg_name})"
        )));
    }
    let after_alg = &after_ver[expected_alg_id.len()..];

    let (outer_priv, after_priv) = read_der_tlv(after_alg, 0x04)?;
    let (inner_seed, inner_rest) = read_der_tlv(outer_priv, 0x04)?;
    if !inner_rest.is_empty() || inner_seed.len() != 32 {
        return Err(CryptoError::InvalidKey(format!(
            "{alg_name} PKCS#8 private key octet string must be 32 bytes"
        )));
    }
    let mut seed = Zeroizing::new([0u8; 32]);
    seed.copy_from_slice(inner_seed);

    if after_priv.is_empty() {
        return Ok((seed, None));
    }

    if version != 1 {
        return Err(CryptoError::InvalidKey(format!(
            "unexpected trailing fields in PKCS#8 v1 {alg_name} key"
        )));
    }

    // Optional PKCS#8 v2 publicKey: RFC 5958 implicit [1] (`0x81 0x21 0x00 || 32B`)
    // or legacy ring explicit [1] (`0xa1 0x23 0x03 0x21 0x00 || 32B`).
    let embedded_pub = if after_priv.first() == Some(&0x81) {
        let (bits, tail) = read_der_tlv(after_priv, 0x81)?;
        if !tail.is_empty() || bits.len() != 33 || bits[0] != 0x00 {
            return Err(CryptoError::InvalidKey(format!(
                "malformed PKCS#8 v2 public key in {alg_name}"
            )));
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&bits[1..33]);
        Some(pk)
    } else if after_priv.first() == Some(&0xa1) {
        let (wrapped, tail) = read_der_tlv(after_priv, 0xa1)?;
        if !tail.is_empty() {
            return Err(CryptoError::InvalidKey(format!(
                "trailing bytes after PKCS#8 v2 public key in {alg_name}"
            )));
        }
        let (bits, inner_tail) = read_der_tlv(wrapped, 0x03)?;
        if !inner_tail.is_empty() || bits.len() != 33 || bits[0] != 0x00 {
            return Err(CryptoError::InvalidKey(format!(
                "malformed legacy PKCS#8 v2 public key in {alg_name}"
            )));
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&bits[1..33]);
        Some(pk)
    } else {
        return Err(CryptoError::InvalidKey(format!(
            "unexpected tag in PKCS#8 v2 {alg_name} key"
        )));
    };

    Ok((seed, embedded_pub))
}

fn read_der_tlv(input: &[u8], expected_tag: u8) -> Result<(&[u8], &[u8]), CryptoError> {
    if input.len() < 2 || input[0] != expected_tag {
        return Err(CryptoError::InvalidKey(format!(
            "invalid DER tag (expected 0x{expected_tag:02x})"
        )));
    }
    let len_byte = input[1];
    let (len, header_len) = if len_byte < 0x80 {
        (len_byte as usize, 2usize)
    } else if len_byte == 0x81 {
        if input.len() < 3 {
            return Err(CryptoError::InvalidKey("truncated DER length".into()));
        }
        let l = input[2] as usize;
        if l < 0x80 {
            return Err(CryptoError::InvalidKey("non-canonical DER length".into()));
        }
        (l, 3usize)
    } else {
        return Err(CryptoError::InvalidKey("unsupported DER length".into()));
    };
    let end = header_len
        .checked_add(len)
        .ok_or_else(|| CryptoError::InvalidKey("DER length overflow".into()))?;
    if end > input.len() {
        return Err(CryptoError::InvalidKey("truncated DER value".into()));
    }
    Ok((&input[header_len..end], &input[end..]))
}

/// Zeroizing Ed25519 signing keypair backed by `ring::signature::Ed25519KeyPair`.
pub struct Ed25519KeyPair {
    seed: Zeroizing<[u8; 32]>,
    public_key: [u8; 32],
    inner: signature::Ed25519KeyPair,
}

impl fmt::Debug for Ed25519KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ed25519KeyPair")
            .field("public_key", &self.public_key_b64())
            .field("seed", &"[REDACTED]")
            .finish()
    }
}

impl Ed25519KeyPair {
    /// Generates a fresh Ed25519 signing keypair using the OS CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        let rng = SystemRandom::new();
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill(&mut *seed)
            .map_err(|_| CryptoError::InvalidKey("OS CSPRNG failure".into()))?;
        Self::from_seed(*seed)
    }

    /// Constructs an Ed25519 keypair from its 32-byte raw seed.
    pub fn from_seed(seed: [u8; 32]) -> Result<Self, CryptoError> {
        let seed = Zeroizing::new(seed);
        let inner = signature::Ed25519KeyPair::from_seed_unchecked(&*seed)
            .map_err(|_| CryptoError::InvalidKey("invalid Ed25519 seed".into()))?;
        let public_key: [u8; 32] =
            inner.public_key().as_ref().try_into().map_err(|_| {
                CryptoError::InvalidKey("unexpected Ed25519 public key length".into())
            })?;
        Ok(Self {
            seed,
            public_key,
            inner,
        })
    }

    /// Imports an Ed25519 private key from PKCS#8 DER (v1 or v2, RFC 8410).
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, CryptoError> {
        let (seed, embedded_pub) = parse_rfc8410_pkcs8(der, &ED25519_ALG_ID, "Ed25519")?;
        let kp = Self::from_seed(*seed)?;
        if let Some(expected_pub) = embedded_pub {
            if expected_pub != kp.public_key {
                return Err(CryptoError::InvalidKey(
                    "Ed25519 PKCS#8 v2 embedded public key does not match private seed".into(),
                ));
            }
        }
        Ok(kp)
    }

    /// Imports an Ed25519 private key from base64url-encoded PKCS#8 DER.
    pub fn from_pkcs8_b64(b64: &str) -> Result<Self, CryptoError> {
        let der = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(b64.trim())
                .map_err(|e| CryptoError::InvalidKey(format!("invalid base64url PKCS#8: {e}")))?,
        );
        Self::from_pkcs8_der(&der)
    }

    /// Exports the private key as canonical 48-byte RFC 8410 PKCS#8 v1 DER
    /// (byte-identical to Node `node:crypto`).
    pub fn export_pkcs8_der(&self) -> Zeroizing<Vec<u8>> {
        let mut der = Zeroizing::new(Vec::with_capacity(48));
        der.extend_from_slice(&ED25519_PKCS8_V1_PREFIX);
        der.extend_from_slice(&*self.seed);
        der
    }

    /// Exports the private key as base64url-encoded PKCS#8 v1 DER.
    pub fn export_pkcs8_b64(&self) -> Zeroizing<String> {
        let der = self.export_pkcs8_der();
        Zeroizing::new(URL_SAFE_NO_PAD.encode(&*der))
    }

    /// Returns the raw 32-byte private seed (caller should avoid copying out of zeroized memory).
    pub fn seed_bytes(&self) -> &[u8; 32] {
        &self.seed
    }

    /// Returns the validated `Ed25519PublicKey`.
    pub fn public_key(&self) -> Ed25519PublicKey {
        Ed25519PublicKey(self.public_key)
    }

    /// Returns the raw 32-byte public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key
    }

    /// Returns the 43-char base64url raw public key.
    pub fn public_key_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.public_key)
    }

    /// Returns the RFC 7517 / RFC 8037 OKP JWK for this signing key.
    pub fn to_jwk(&self) -> OkpJwk {
        OkpJwk::ed25519(&self.public_key)
    }

    /// Returns the RFC 7638 SHA-256 JWK Thumbprint (`kid`).
    pub fn kid(&self) -> String {
        self.to_jwk()
            .thumbprint()
            .expect("generated Ed25519 JWK is always valid")
    }

    /// Returns the 16-hex-char v1-compatible SHA-256 fingerprint.
    pub fn fingerprint(&self) -> String {
        fingerprint_bytes(&self.public_key)
    }

    /// Signs arbitrary raw message bytes using RFC 8032 Ed25519.
    pub fn sign_raw(&self, msg: &[u8]) -> [u8; 64] {
        let sig = self.inner.sign(msg);
        sig.as_ref()
            .try_into()
            .expect("Ed25519 signature is always 64 bytes")
    }

    /// Signs `payload` under Hyphae v2 domain separation: `"hyphae/v2/<kind>\n" || payload`.
    pub fn sign_domain(&self, kind: &str, payload: &[u8]) -> [u8; 64] {
        let buf = domain_message(format!("hyphae/v2/{kind}\n").as_bytes(), payload);
        self.sign_raw(&buf)
    }

    /// Signs `payload` under Hyphae v2 domain separation and encodes signature as base64url.
    pub fn sign_domain_b64(&self, kind: &str, payload: &[u8]) -> String {
        sign_with_domain(self, format!("hyphae/v2/{kind}\n").as_bytes(), payload)
    }

    /// Canonicalizes `value` with RFC 8785 JCS and signs under `"hyphae/v2/<kind>\n"`.
    pub fn sign_jcs<T: Serialize>(
        &self,
        kind: &str,
        value: &T,
    ) -> Result<SignedPayload, CryptoError> {
        let payload = to_canonical_json(value)?;
        let sig = self.sign_domain_b64(kind, payload.as_bytes());
        Ok(SignedPayload { payload, sig })
    }
}

/// Validated Ed25519 public key (rejects small-order and non-canonical points).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ed25519PublicKey([u8; 32]);

impl Ed25519PublicKey {
    /// Parses and validates a 32-byte Ed25519 public key, rejecting small-order and non-canonical encodings.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CryptoError> {
        if is_small_order_ed25519_point(&bytes) {
            return Err(CryptoError::SmallOrderKey);
        }
        if is_non_canonical_ed25519_y(&bytes) {
            return Err(CryptoError::InvalidKey(
                "non-canonical Ed25519 public key y-coordinate".into(),
            ));
        }
        Ok(Self(bytes))
    }

    /// Parses and validates a 43-char base64url raw Ed25519 public key.
    pub fn from_b64(b64: &str) -> Result<Self, CryptoError> {
        let bytes = decode_raw_key_32(b64)?;
        Self::from_bytes(bytes)
    }

    /// Parses and validates an RFC 8410 SPKI DER Ed25519 public key (44 bytes).
    pub fn from_spki_der(der: &[u8]) -> Result<Self, CryptoError> {
        if der.len() != 44 || der[..12] != ED25519_SPKI_PREFIX {
            return Err(CryptoError::InvalidKey(
                "invalid Ed25519 SPKI DER encoding".into(),
            ));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&der[12..44]);
        Self::from_bytes(bytes)
    }

    /// Exports this public key as RFC 8410 SPKI DER (44 bytes, interoperable with Node `spki`).
    pub fn export_spki_der(&self) -> Vec<u8> {
        let mut der = Vec::with_capacity(44);
        der.extend_from_slice(&ED25519_SPKI_PREFIX);
        der.extend_from_slice(&self.0);
        der
    }

    /// Returns the raw 32-byte public key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the 43-char base64url public key.
    pub fn to_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    /// Returns the RFC 7517 / RFC 8037 OKP JWK.
    pub fn to_jwk(&self) -> OkpJwk {
        OkpJwk::ed25519(&self.0)
    }

    /// Returns the RFC 7638 SHA-256 JWK Thumbprint (`kid`).
    pub fn kid(&self) -> String {
        self.to_jwk()
            .thumbprint()
            .expect("validated Ed25519 JWK is always valid")
    }

    /// Returns the 16-hex-char v1-compatible SHA-256 fingerprint.
    pub fn fingerprint(&self) -> String {
        fingerprint_bytes(&self.0)
    }

    /// Strictly verifies a raw Ed25519 signature, rejecting small-order public keys,
    /// small-order signature `R` components, non-canonical `R`, and non-canonical `s`.
    pub fn verify_raw(&self, msg: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        if sig.len() != 64 {
            return Err(CryptoError::InvalidSignature(
                "Ed25519 signature must be 64 bytes".into(),
            ));
        }
        if is_small_order_ed25519_point(&self.0) {
            return Err(CryptoError::SmallOrderKey);
        }
        let r_bytes: [u8; 32] = sig[..32].try_into().unwrap();
        if is_small_order_ed25519_point(&r_bytes) || is_non_canonical_ed25519_y(&r_bytes) {
            return Err(CryptoError::InvalidSignature(
                "signature R is small-order or non-canonical".into(),
            ));
        }
        let verifier = signature::UnparsedPublicKey::new(&signature::ED25519, &self.0);
        verifier
            .verify(msg, sig)
            .map_err(|_| CryptoError::InvalidSignature("Ed25519 verification failed".into()))
    }

    /// Strictly verifies a Hyphae v2 domain-separated signature (`"hyphae/v2/<kind>\n" || payload`).
    pub fn verify_domain(&self, kind: &str, payload: &[u8], sig: &[u8]) -> Result<(), CryptoError> {
        let buf = domain_message(format!("hyphae/v2/{kind}\n").as_bytes(), payload);
        self.verify_raw(&buf, sig)
    }

    /// Strictly verifies a base64url Hyphae v2 domain-separated signature.
    pub fn verify_domain_b64(
        &self,
        kind: &str,
        payload: &[u8],
        sig_b64: &str,
    ) -> Result<(), CryptoError> {
        verify_with_domain(
            self,
            format!("hyphae/v2/{kind}\n").as_bytes(),
            payload,
            sig_b64,
        )
    }

    /// Verifies a `SignedPayload` under `"hyphae/v2/<kind>\n"` and deserializes its JSON payload.
    pub fn verify_signed<T: DeserializeOwned>(
        &self,
        kind: &str,
        signed: &SignedPayload,
    ) -> Result<T, CryptoError> {
        self.verify_domain_b64(kind, signed.payload.as_bytes(), &signed.sig)?;
        Ok(serde_json::from_str(&signed.payload)?)
    }
}

/// Zeroizing X25519 key-agreement keypair.
pub struct X25519KeyPair {
    secret: Zeroizing<[u8; 32]>,
    public_key: [u8; 32],
}

impl fmt::Debug for X25519KeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("X25519KeyPair")
            .field("public_key", &self.public_key_b64())
            .field("secret", &"[REDACTED]")
            .finish()
    }
}

impl X25519KeyPair {
    /// Generates a fresh X25519 keypair using the OS CSPRNG.
    pub fn generate() -> Result<Self, CryptoError> {
        let rng = SystemRandom::new();
        let mut secret = Zeroizing::new([0u8; 32]);
        rng.fill(&mut *secret)
            .map_err(|_| CryptoError::InvalidKey("OS CSPRNG failure".into()))?;
        Self::from_bytes(*secret)
    }

    /// Constructs an X25519 keypair from its 32-byte private scalar.
    pub fn from_bytes(secret: [u8; 32]) -> Result<Self, CryptoError> {
        let secret = Zeroizing::new(secret);
        let public_key = x25519_public_from_private(&secret);
        if is_low_order_x25519_point(&public_key) {
            return Err(CryptoError::SmallOrderKey);
        }
        Ok(Self { secret, public_key })
    }

    /// Imports an X25519 private key from RFC 8410 PKCS#8 DER (v1 or v2).
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, CryptoError> {
        let (secret, embedded_pub) = parse_rfc8410_pkcs8(der, &X25519_ALG_ID, "X25519")?;
        let kp = Self::from_bytes(*secret)?;
        if let Some(expected_pub) = embedded_pub {
            if expected_pub != kp.public_key {
                return Err(CryptoError::InvalidKey(
                    "X25519 PKCS#8 v2 embedded public key does not match private key".into(),
                ));
            }
        }
        Ok(kp)
    }

    /// Imports an X25519 private key from base64url-encoded PKCS#8 DER.
    pub fn from_pkcs8_b64(b64: &str) -> Result<Self, CryptoError> {
        let der = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(b64.trim())
                .map_err(|e| CryptoError::InvalidKey(format!("invalid base64url PKCS#8: {e}")))?,
        );
        Self::from_pkcs8_der(&der)
    }

    /// Exports the private key as canonical 48-byte RFC 8410 PKCS#8 v1 DER
    /// (byte-identical to Node `node:crypto`).
    pub fn export_pkcs8_der(&self) -> Zeroizing<Vec<u8>> {
        let mut der = Zeroizing::new(Vec::with_capacity(48));
        der.extend_from_slice(&X25519_PKCS8_V1_PREFIX);
        der.extend_from_slice(&*self.secret);
        der
    }

    /// Exports the private key as base64url-encoded PKCS#8 v1 DER.
    pub fn export_pkcs8_b64(&self) -> Zeroizing<String> {
        let der = self.export_pkcs8_der();
        Zeroizing::new(URL_SAFE_NO_PAD.encode(&*der))
    }

    /// Returns the raw 32-byte private key bytes.
    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret
    }

    /// Returns the validated `X25519PublicKey`.
    pub fn public_key(&self) -> X25519PublicKey {
        X25519PublicKey(self.public_key)
    }

    /// Returns the raw 32-byte public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.public_key
    }

    /// Returns the 43-char base64url public key.
    pub fn public_key_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.public_key)
    }

    /// Returns the RFC 7517 / RFC 8037 OKP JWK for this encryption key.
    pub fn to_jwk(&self) -> OkpJwk {
        OkpJwk::x25519(&self.public_key)
    }

    /// Returns the RFC 7638 SHA-256 JWK Thumbprint (`kid`).
    pub fn kid(&self) -> String {
        self.to_jwk()
            .thumbprint()
            .expect("generated X25519 JWK is always valid")
    }

    /// Performs X25519 Diffie-Hellman key agreement, rejecting low-order peer keys and
    /// all-zero shared secrets.
    pub fn diffie_hellman(
        &self,
        peer: &X25519PublicKey,
    ) -> Result<Zeroizing<[u8; 32]>, CryptoError> {
        x25519_dh(&self.secret, &peer.0)
    }
}

/// Validated X25519 public key (rejects all-zero and small-order Curve25519 points).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct X25519PublicKey([u8; 32]);

impl X25519PublicKey {
    /// Parses and validates a 32-byte X25519 public key, rejecting all-zero and low-order points.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, CryptoError> {
        if is_low_order_x25519_point(&bytes) {
            return Err(CryptoError::SmallOrderKey);
        }
        Ok(Self(bytes))
    }

    /// Parses and validates a 43-char base64url raw X25519 public key.
    pub fn from_b64(b64: &str) -> Result<Self, CryptoError> {
        let bytes = decode_raw_key_32(b64)?;
        Self::from_bytes(bytes)
    }

    /// Parses and validates an RFC 8410 SPKI DER X25519 public key (44 bytes).
    pub fn from_spki_der(der: &[u8]) -> Result<Self, CryptoError> {
        if der.len() != 44 || der[..12] != X25519_SPKI_PREFIX {
            return Err(CryptoError::InvalidKey(
                "invalid X25519 SPKI DER encoding".into(),
            ));
        }
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&der[12..44]);
        Self::from_bytes(bytes)
    }

    /// Exports this public key as RFC 8410 SPKI DER (44 bytes).
    pub fn export_spki_der(&self) -> Vec<u8> {
        let mut der = Vec::with_capacity(44);
        der.extend_from_slice(&X25519_SPKI_PREFIX);
        der.extend_from_slice(&self.0);
        der
    }

    /// Returns the raw 32-byte public key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the 43-char base64url public key.
    pub fn to_b64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    /// Returns the RFC 7517 / RFC 8037 OKP JWK.
    pub fn to_jwk(&self) -> OkpJwk {
        OkpJwk::x25519(&self.0)
    }

    /// Returns the RFC 7638 SHA-256 JWK Thumbprint (`kid`).
    pub fn kid(&self) -> String {
        self.to_jwk()
            .thumbprint()
            .expect("validated X25519 JWK is always valid")
    }
}

/// Complete long-term cryptographic identity pair for a Hyphae v2 `Node`.
#[derive(Debug)]
pub struct NodeIdentityKeys {
    pub signing: Ed25519KeyPair,
    pub encryption: X25519KeyPair,
}

impl NodeIdentityKeys {
    /// Generates a fresh Ed25519 + X25519 node identity keypair.
    pub fn generate() -> Result<Self, CryptoError> {
        Ok(Self {
            signing: Ed25519KeyPair::generate()?,
            encryption: X25519KeyPair::generate()?,
        })
    }

    pub fn signing_jwk(&self) -> OkpJwk {
        self.signing.to_jwk()
    }

    pub fn encryption_jwk(&self) -> OkpJwk {
        self.encryption.to_jwk()
    }

    /// Primary node `kid` (RFC 7638 thumbprint of the signing JWK).
    pub fn kid(&self) -> String {
        self.signing.kid()
    }

    /// v1-compatible 16-hex-char fingerprint of the signing public key.
    pub fn fingerprint(&self) -> String {
        self.signing.fingerprint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_jwk_schema_keeps_crypto_curve_strings_and_proto_curve_validation() {
        let raw =
            r#"{"kty":"OKP","crv":"P-256","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}"#;
        let jwk: OkpJwk = serde_json::from_str(raw).unwrap();
        assert_eq!(serde_json::to_string(&jwk).unwrap(), raw);
        assert_eq!(jwk.crv, "P-256");
        assert!(
            matches!(jwk.thumbprint(), Err(CryptoError::InvalidKey(ref error)) if error == "unsupported OKP crv \"P-256\"")
        );
        assert!(serde_json::from_str::<hyp_proto::manifest::OkpJwk>(raw).is_err());

        let key = Ed25519KeyPair::from_seed([7; 32]).unwrap();
        let proto = hyp_proto::manifest::OkpJwk::new(
            hyp_proto::manifest::OkpCurve::Ed25519,
            &key.public_key().0,
        );
        let crypto = OkpJwk::from(&proto);
        assert_eq!(crypto.to_ed25519().unwrap(), key.public_key());
        assert_eq!(
            serde_json::to_string(&crypto).unwrap(),
            serde_json::to_string(&proto).unwrap()
        );
        assert_eq!(
            crypto.thumbprint().unwrap(),
            proto.thumbprint_sha256().unwrap()
        );
    }

    #[test]
    fn ed25519_pkcs8_spki_jwk_and_domain_signing_roundtrip() {
        let kp = Ed25519KeyPair::generate().unwrap();
        let pkcs8_b64 = kp.export_pkcs8_b64();
        let reimported = Ed25519KeyPair::from_pkcs8_b64(&pkcs8_b64).unwrap();
        assert_eq!(kp.public_key_bytes(), reimported.public_key_bytes());

        // Cross-algorithm import MUST fail closed
        assert!(X25519KeyPair::from_pkcs8_b64(&pkcs8_b64).is_err());

        // SPKI roundtrip
        let spki = kp.public_key().export_spki_der();
        let pk2 = Ed25519PublicKey::from_spki_der(&spki).unwrap();
        assert_eq!(pk2, kp.public_key());
        assert!(X25519PublicKey::from_spki_der(&spki).is_err());

        // JWK & RFC 7638 thumbprint
        let jwk = kp.to_jwk();
        assert_eq!(jwk.kty, "OKP");
        assert_eq!(jwk.crv, "Ed25519");
        assert_eq!(jwk.to_ed25519().unwrap(), kp.public_key());
        assert_eq!(jwk.thumbprint().unwrap().len(), 43);

        // Domain-separated signing & domain confusion resistance
        let sig = kp.sign_domain_b64("manifest", b"{\"v\":1}");
        kp.public_key()
            .verify_domain_b64("manifest", b"{\"v\":1}", &sig)
            .unwrap();
        assert!(
            kp.public_key()
                .verify_domain_b64("grant", b"{\"v\":1}", &sig)
                .is_err()
        );
    }

    #[test]
    fn rejects_small_order_ed25519_keys_and_signature_r() {
        for small_y in &SMALL_ORDER_ED25519_Y_LE {
            assert!(is_small_order_ed25519_point(small_y));
            assert!(matches!(
                Ed25519PublicKey::from_bytes(*small_y),
                Err(CryptoError::SmallOrderKey)
            ));
            let mut with_sign_bit = *small_y;
            with_sign_bit[31] |= 0x80;
            assert!(is_small_order_ed25519_point(&with_sign_bit));
            assert!(matches!(
                Ed25519PublicKey::from_bytes(with_sign_bit),
                Err(CryptoError::SmallOrderKey)
            ));
        }

        // Non-canonical y = p (= 0 mod p) and p + 1 (= 1 mod p)
        assert!(is_small_order_ed25519_point(&ED25519_P_LE));
        let mut p_plus_1 = ED25519_P_LE;
        p_plus_1[0] += 1;
        assert!(is_small_order_ed25519_point(&p_plus_1));

        // Signature with small-order R must be rejected
        let kp = Ed25519KeyPair::generate().unwrap();
        let mut forged = kp.sign_domain("test", b"hello");
        forged[..32].copy_from_slice(&SMALL_ORDER_ED25519_Y_LE[0]);
        assert!(
            kp.public_key()
                .verify_domain("test", b"hello", &forged)
                .is_err()
        );
    }

    #[test]
    fn x25519_pkcs8_spki_and_dh_roundtrip() {
        let a = X25519KeyPair::generate().unwrap();
        let b = X25519KeyPair::generate().unwrap();
        let a_pkcs8 = a.export_pkcs8_b64();
        let a2 = X25519KeyPair::from_pkcs8_b64(&a_pkcs8).unwrap();
        assert_eq!(a.public_key_bytes(), a2.public_key_bytes());
        assert!(Ed25519KeyPair::from_pkcs8_b64(&a_pkcs8).is_err());

        let s1 = a.diffie_hellman(&b.public_key()).unwrap();
        let s2 = b.diffie_hellman(&a.public_key()).unwrap();
        assert_eq!(*s1, *s2);

        // Reject all-zero X25519 public key
        assert!(matches!(
            X25519PublicKey::from_bytes([0u8; 32]),
            Err(CryptoError::SmallOrderKey)
        ));
    }

    #[test]
    fn ring_pkcs8_v2_ed25519_import_works() {
        let rng = SystemRandom::new();
        let doc = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let kp = Ed25519KeyPair::from_pkcs8_der(doc.as_ref()).unwrap();
        let ring_kp = signature::Ed25519KeyPair::from_pkcs8(doc.as_ref()).unwrap();
        assert_eq!(kp.public_key_bytes(), ring_kp.public_key().as_ref());
    }
}
