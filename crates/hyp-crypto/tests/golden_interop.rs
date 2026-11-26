//! Pure-Rust frozen golden interoperability & adversarial mutation suite for `hyp-crypto`
//! (ZERO Node.js runtime!).
//!
//! Embeds real TypeScript v1 & Node `node:crypto` golden vectors in
//! `fixtures/v1_crypto_vectors.json`:
//! - Ed25519 + X25519 PKCS#8 DER, SPKI DER, raw 32B keys, SHA-256 fingerprints,
//!   OKP JWKs, and RFC 7638 JWK Thumbprints
//! - Small-order Ed25519 curve point rejection table
//! - All 7 domain-separated `t3-mesh/v1/<kind>\n` Ed25519 signatures
//! - Signed `Grant`, `t3mp1_` pairing codes and derived pairing keys
//! - Independent Node `node:crypto` RFC 9180 HPKE `DHKEM(X25519, HKDF-SHA256) +
//!   HKDF-SHA256 + AES-256-GCM` ciphertexts
//!
//! For EVERY verified artifact, ALSO constructs nearby 1-bit / 1-byte mutated copies
//! (McKeeman nearby altered cases) and asserts every mutation fails closed!

use std::collections::HashMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hyp_crypto::compat_v1::{
    GrantV1, SignatureKindV1, SignedV1, derive_pairing_key_v1, format_pairing_code_v1,
    parse_pairing_code_v1, verify_payload_v1,
};
use hyp_crypto::hpke;
use hyp_crypto::keys::{
    Ed25519KeyPair, Ed25519PublicKey, OkpJwk, X25519KeyPair, X25519PublicKey,
    is_small_order_ed25519_point,
};
use serde::Deserialize;

const VECTORS_JSON: &str = include_str!("fixtures/v1_crypto_vectors.json");

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CryptoFixture {
    schema_version: u32,
    keys: Vec<KeyVector>,
    small_order_checks: Vec<SmallOrderVector>,
    domain_signatures: Vec<DomainSigVector>,
    grants_and_entries: Vec<GrantEntryVector>,
    hpke_vectors: Vec<HpkeVector>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyVector {
    name: String,
    key_type: String,
    seed_hex: String,
    pkcs8_b64: String,
    spki_der_hex: String,
    raw_pub_b64: String,
    fingerprint: String,
    jwk: OkpJwk,
    jwk_thumbprint: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SmallOrderVector {
    point_hex: String,
    is_small_order: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DomainSigVector {
    kind: String,
    signer: String,
    payload: String,
    sig: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrantEntryVector {
    name: String,
    connector_id: String,
    code: String,
    signed_grant: SignedV1,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct HpkeVector {
    name: String,
    recipient_key_name: String,
    enc_hex: String,
    info_hex: String,
    aad_hex: String,
    plaintext_b64: String,
    ciphertext_hex: String,
}

fn load_fixture() -> CryptoFixture {
    let f: CryptoFixture =
        serde_json::from_str(VECTORS_JSON).expect("parse v1_crypto_vectors.json");
    assert_eq!(f.schema_version, 1);
    f
}

fn load_key_maps(
    fixture: &CryptoFixture,
) -> (
    HashMap<String, Ed25519KeyPair>,
    HashMap<String, X25519KeyPair>,
) {
    let mut ed = HashMap::new();
    let mut x = HashMap::new();
    for k in &fixture.keys {
        match k.key_type.as_str() {
            "ed25519" => {
                let kp =
                    Ed25519KeyPair::from_pkcs8_b64(&k.pkcs8_b64).expect("import Ed25519 PKCS8");
                ed.insert(k.name.clone(), kp);
            }
            "x25519" => {
                let kp = X25519KeyPair::from_pkcs8_b64(&k.pkcs8_b64).expect("import X25519 PKCS8");
                x.insert(k.name.clone(), kp);
            }
            other => panic!("unexpected keyType: {other}"),
        }
    }
    (ed, x)
}

fn flip_b64url_byte(b64: &str, byte_idx: usize) -> String {
    let mut bytes = URL_SAFE_NO_PAD.decode(b64).expect("valid base64url");
    let len = bytes.len();
    bytes[byte_idx % len] ^= 0x01;
    URL_SAFE_NO_PAD.encode(bytes)
}

fn parse_sig_kind(s: &str) -> SignatureKindV1 {
    match s {
        "grant" => SignatureKindV1::Grant,
        "binding" => SignatureKindV1::Binding,
        "binding-self" => SignatureKindV1::BindingSelf,
        "revocation" => SignatureKindV1::Revocation,
        "transfer" => SignatureKindV1::Transfer,
        "attestation" => SignatureKindV1::Attestation,
        "key-reg" => SignatureKindV1::KeyReg,
        other => panic!("unknown signature kind: {other}"),
    }
}

#[test]
fn golden_v1_keys_pkcs8_spki_jwk_thumbprint_and_small_order_points() {
    let fixture = load_fixture();
    assert_eq!(fixture.keys.len(), 7);

    for k in &fixture.keys {
        let seed: [u8; 32] = hex::decode(&k.seed_hex)
            .expect("seed hex")
            .try_into()
            .expect("32-byte seed");
        let spki_der = hex::decode(&k.spki_der_hex).expect("spki hex");

        match k.key_type.as_str() {
            "ed25519" => {
                let kp = Ed25519KeyPair::from_pkcs8_b64(&k.pkcs8_b64).unwrap();
                let from_seed = Ed25519KeyPair::from_seed(seed).unwrap();
                assert_eq!(kp.public_key_b64(), k.raw_pub_b64, "key {}", k.name);
                assert_eq!(from_seed.public_key_b64(), k.raw_pub_b64, "seed {}", k.name);
                assert_eq!(kp.fingerprint(), k.fingerprint, "fp {}", k.name);
                assert_eq!(
                    kp.export_pkcs8_b64().as_str(),
                    k.pkcs8_b64,
                    "pkcs8 {}",
                    k.name
                );
                assert_eq!(
                    kp.public_key().export_spki_der(),
                    spki_der,
                    "spki {}",
                    k.name
                );
                assert_eq!(kp.to_jwk(), k.jwk, "jwk {}", k.name);
                assert_eq!(kp.kid(), k.jwk_thumbprint, "rfc7638 kid {}", k.name);
                assert_eq!(k.jwk.thumbprint().unwrap(), k.jwk_thumbprint);

                // SPKI import roundtrip & mutated SPKI fails closed.
                let spki_pk = Ed25519PublicKey::from_spki_der(&spki_der).unwrap();
                assert_eq!(spki_pk, kp.public_key());
                let mut bad_spki = spki_der.clone();
                bad_spki[0] ^= 0xff;
                assert!(Ed25519PublicKey::from_spki_der(&bad_spki).is_err());

                // Mutated PKCS#8 fails closed.
                let bad_pkcs8 = flip_b64url_byte(&k.pkcs8_b64, 0);
                assert!(Ed25519KeyPair::from_pkcs8_b64(&bad_pkcs8).is_err());
            }
            "x25519" => {
                let kp = X25519KeyPair::from_pkcs8_b64(&k.pkcs8_b64).unwrap();
                let from_seed = X25519KeyPair::from_bytes(seed).unwrap();
                assert_eq!(kp.public_key_b64(), k.raw_pub_b64, "key {}", k.name);
                assert_eq!(from_seed.public_key_b64(), k.raw_pub_b64, "seed {}", k.name);
                assert_eq!(
                    kp.export_pkcs8_b64().as_str(),
                    k.pkcs8_b64,
                    "pkcs8 {}",
                    k.name
                );
                assert_eq!(
                    kp.public_key().export_spki_der(),
                    spki_der,
                    "spki {}",
                    k.name
                );
                assert_eq!(kp.to_jwk(), k.jwk, "jwk {}", k.name);
                assert_eq!(kp.kid(), k.jwk_thumbprint, "rfc7638 kid {}", k.name);
                assert_eq!(k.jwk.thumbprint().unwrap(), k.jwk_thumbprint);

                let spki_pk = X25519PublicKey::from_spki_der(&spki_der).unwrap();
                assert_eq!(spki_pk, kp.public_key());
                let mut bad_spki = spki_der.clone();
                bad_spki[4] ^= 0x01;
                assert!(X25519PublicKey::from_spki_der(&bad_spki).is_err());

                let bad_pkcs8 = flip_b64url_byte(&k.pkcs8_b64, 0);
                assert!(X25519KeyPair::from_pkcs8_b64(&bad_pkcs8).is_err());
            }
            other => panic!("unexpected keyType {other}"),
        }
    }

    // Small-order point rejection oracle parity.
    assert!(fixture.small_order_checks.len() >= 10);
    for check in &fixture.small_order_checks {
        let bytes = hex::decode(&check.point_hex).unwrap();
        assert_eq!(
            is_small_order_ed25519_point(&bytes),
            check.is_small_order,
            "small-order mismatch for {}",
            check.point_hex
        );
    }
}

#[test]
fn golden_v1_domain_separated_signatures_and_mutations_fail_closed() {
    let fixture = load_fixture();
    let (ed_keys, _) = load_key_maps(&fixture);
    let wrong_pk = ed_keys["bob-sign"].public_key();
    let all_kinds = [
        SignatureKindV1::Grant,
        SignatureKindV1::Binding,
        SignatureKindV1::BindingSelf,
        SignatureKindV1::Revocation,
        SignatureKindV1::Transfer,
        SignatureKindV1::Attestation,
        SignatureKindV1::KeyReg,
    ];

    assert_eq!(fixture.domain_signatures.len(), 7);
    for vec in &fixture.domain_signatures {
        let kind = parse_sig_kind(&vec.kind);
        let pk = ed_keys[&vec.signer].public_key();

        // Exact TS signature verifies!
        assert!(
            verify_payload_v1(kind, &vec.payload, &vec.sig, &pk),
            "valid TS signature failed for kind {}",
            vec.kind
        );

        // Domain separation: every OTHER signature kind MUST fail closed!
        for other_kind in all_kinds {
            if other_kind != kind {
                assert!(
                    !verify_payload_v1(other_kind, &vec.payload, &vec.sig, &pk),
                    "domain confusion allowed {:?} signature under {:?}",
                    kind,
                    other_kind
                );
            }
        }

        // Wrong public key MUST fail closed.
        assert!(!verify_payload_v1(kind, &vec.payload, &vec.sig, &wrong_pk));

        // 1-bit flip in signature MUST fail closed.
        let bad_sig = flip_b64url_byte(&vec.sig, 0);
        assert!(!verify_payload_v1(kind, &vec.payload, &bad_sig, &pk));

        // 1-char mutation in payload MUST fail closed.
        let mut bad_payload = vec.payload.clone();
        bad_payload.push(' ');
        assert!(!verify_payload_v1(kind, &bad_payload, &vec.sig, &pk));
    }
}

#[test]
fn golden_v1_pairing_codes_keys_and_signed_grants() {
    let fixture = load_fixture();
    let (ed_keys, _) = load_key_maps(&fixture);
    let admin_pk = ed_keys["admin"].public_key();
    assert_eq!(fixture.grants_and_entries.len(), 4);
    for vector in &fixture.grants_and_entries {
        let code = parse_pairing_code_v1(&vector.code)
            .unwrap_or_else(|error| panic!("pairing vector {}: {error}", vector.name));
        let grant: GrantV1 = serde_json::from_str(&vector.signed_grant.payload).unwrap();
        assert_eq!(grant.connector_id, vector.connector_id);
        assert_eq!(code.grant_id, grant.id);
        assert_eq!(code.admin_fingerprint, admin_pk.fingerprint());
        assert_eq!(format_pairing_code_v1(&code).unwrap(), vector.code);
        assert_eq!(
            derive_pairing_key_v1(&code.secret, &code.grant_id)
                .unwrap()
                .public_key_b64(),
            grant.pairing_key
        );
        assert!(verify_payload_v1(
            SignatureKindV1::Grant,
            &vector.signed_grant.payload,
            &vector.signed_grant.sig,
            &admin_pk
        ));
        assert!(parse_pairing_code_v1(&vector.code.replacen("t3mp1_", "t3mp2_", 1)).is_err());
        assert!(parse_pairing_code_v1(&vector.code[..vector.code.len() - 4]).is_err());
    }
}

#[test]
fn golden_rfc9180_hpke_aes256gcm_vectors_and_mutations_fail_closed() {
    let fixture = load_fixture();
    let (_, x_keys) = load_key_maps(&fixture);

    assert_eq!(fixture.hpke_vectors.len(), 3);
    for vec in &fixture.hpke_vectors {
        let recipient = &x_keys[&vec.recipient_key_name];
        let wrong_recipient = if vec.recipient_key_name == "bob-enc" {
            &x_keys["alice-enc"]
        } else {
            &x_keys["bob-enc"]
        };

        let enc: [u8; 32] = hex::decode(&vec.enc_hex)
            .unwrap()
            .try_into()
            .expect("32-byte enc");
        let info = hex::decode(&vec.info_hex).unwrap();
        let aad = hex::decode(&vec.aad_hex).unwrap();
        let ct = hex::decode(&vec.ciphertext_hex).unwrap();
        let expected_pt = URL_SAFE_NO_PAD.decode(&vec.plaintext_b64).unwrap();

        // 1. Independent Node crypto RFC 9180 HPKE ciphertext decrypts cleanly in Rust!
        let got_pt = hpke::open_base(&enc, recipient, &info, &aad, &ct)
            .unwrap_or_else(|e| panic!("hpke::open_base failed on {}: {e}", vec.name));
        assert_eq!(
            &*got_pt,
            expected_pt.as_slice(),
            "HPKE plaintext mismatch on {}",
            vec.name
        );

        // 2. Every nearby mutation MUST fail closed!
        // 2a. Wrong recipient key
        assert!(hpke::open_base(&enc, wrong_recipient, &info, &aad, &ct).is_err());
        // 2b. Flip 1 bit in encapsulated key `enc`
        let mut bad_enc = enc;
        bad_enc[0] ^= 0x01;
        assert!(hpke::open_base(&bad_enc, recipient, &info, &aad, &ct).is_err());
        // 2c. Flip 1 bit in ciphertext/tag
        let mut bad_ct = ct.clone();
        bad_ct[0] ^= 0x01;
        assert!(hpke::open_base(&enc, recipient, &info, &aad, &bad_ct).is_err());
        let mut bad_tag = ct.clone();
        let last = bad_tag.len() - 1;
        bad_tag[last] ^= 0x01;
        assert!(hpke::open_base(&enc, recipient, &info, &aad, &bad_tag).is_err());
        // 2d. Mutated AAD
        let mut bad_aad = aad.clone();
        bad_aad.push(0x42);
        assert!(hpke::open_base(&enc, recipient, &info, &bad_aad, &ct).is_err());
        // 2e. Mutated info
        let mut bad_info = info.clone();
        bad_info.push(0x99);
        assert!(hpke::open_base(&enc, recipient, &bad_info, &aad, &ct).is_err());
    }
}
