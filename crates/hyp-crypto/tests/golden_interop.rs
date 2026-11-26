//! Pure-Rust frozen golden interoperability & adversarial mutation suite for `hyp-crypto`
//! (ZERO Node.js runtime!).
//!
//! Embeds real TypeScript v1 & Node `node:crypto` golden vectors in
//! `fixtures/v1_crypto_vectors.json`:
//! - Ed25519 + X25519 PKCS#8 DER, SPKI DER, raw 32B keys, SHA-256 fingerprints,
//!   OKP JWKs, and RFC 7638 JWK Thumbprints
//! - Small-order Ed25519 curve point rejection table
//! - All 7 domain-separated `t3-mesh/v1/<kind>\n` Ed25519 signatures
//! - Signed `Grant`, `t3mp1_` pairing codes, `SignedBinding`, `Entry`, `Revocation`,
//!   and `KeyRegistration`
//! - `seal_v1` X25519+HKDF-SHA256+AES-256-GCM ciphertexts & `HYP1` file packs
//!   (multi-file text, empty file, all-256-byte binary, UTF-8, 64 KiB binary)
//! - Independent Node `node:crypto` RFC 9180 HPKE `DHKEM(X25519, HKDF-SHA256) +
//!   HKDF-SHA256 + AES-256-GCM` ciphertexts
//!
//! For EVERY verified artifact, ALSO constructs nearby 1-bit / 1-byte mutated copies
//! (McKeeman nearby altered cases) and asserts every mutation fails closed!

use std::collections::HashMap;
use std::fs;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hyp_crypto::compat_v1::{
    EntryV1, KeyRegistrationV1, SignatureKindV1, SignedV1, open_grant_v1, open_revocation_v1,
    open_v1, parse_pairing_code_v1, unpack_hyp1, verify_entry_v1, verify_key_registration_v1,
    verify_payload_v1,
};
use hyp_crypto::hpke;
use hyp_crypto::keys::{
    Ed25519KeyPair, Ed25519PublicKey, OkpJwk, X25519KeyPair, X25519PublicKey,
    is_small_order_ed25519_point,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

const VECTORS_JSON: &str = include_str!("fixtures/v1_crypto_vectors.json");

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CryptoFixture {
    schema_version: u32,
    keys: Vec<KeyVector>,
    small_order_checks: Vec<SmallOrderVector>,
    domain_signatures: Vec<DomainSigVector>,
    grants_and_entries: Vec<GrantEntryVector>,
    key_registrations: Vec<KeyRegVector>,
    sealed_transfers: Vec<SealedTransferVector>,
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
    signer_key_name: String,
    enc_key_name: String,
    code: String,
    signed_grant: SignedV1,
    entry: EntryV1,
    revocation: SignedV1,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyRegVector {
    connector_id: String,
    signer_key_name: String,
    enc_key_name: String,
    registration: KeyRegistrationV1,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExpectedFile {
    name: String,
    content_b64: String,
    sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SealedTransferVector {
    name: String,
    sender_sign_key_name: String,
    recipient_enc_key_name: String,
    from: String,
    to: String,
    to_handle: Option<String>,
    from_handle: Option<String>,
    note: Option<String>,
    transfer_type: String,
    packed_payload_b64: String,
    sealed_header: SignedV1,
    sealed_ciphertext_b64: String,
    files: Vec<ExpectedFile>,
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
fn golden_v1_grants_t3mp1_bindings_entries_revocations_keyregs_and_mutations() {
    let fixture = load_fixture();
    let (ed_keys, x_keys) = load_key_maps(&fixture);
    let admin_pk = ed_keys["admin"].public_key();
    let wrong_admin_pk = ed_keys["bob-sign"].public_key();

    assert_eq!(fixture.grants_and_entries.len(), 4);
    for gvec in &fixture.grants_and_entries {
        let signer_kp = &ed_keys[&gvec.signer_key_name];
        let enc_kp = &x_keys[&gvec.enc_key_name];

        // 1. Grant verification + mutated copies fail closed.
        let grant = open_grant_v1(&gvec.signed_grant, &admin_pk)
            .unwrap_or_else(|e| panic!("open_grant_v1 failed on {}: {e}", gvec.name));
        assert_eq!(grant.connector_id, gvec.connector_id);
        assert!(open_grant_v1(&gvec.signed_grant, &wrong_admin_pk).is_err());

        let mut bad_grant_sig = gvec.signed_grant.clone();
        bad_grant_sig.sig = flip_b64url_byte(&bad_grant_sig.sig, 3);
        assert!(open_grant_v1(&bad_grant_sig, &admin_pk).is_err());

        let mut bad_grant_payload = gvec.signed_grant.clone();
        bad_grant_payload.payload = bad_grant_payload
            .payload
            .replace(&gvec.connector_id, "mallory@evil");
        assert!(open_grant_v1(&bad_grant_payload, &admin_pk).is_err());

        // 2. `t3mp1_` pairing code parsing + mutated copies fail closed.
        let code = parse_pairing_code_v1(&gvec.code)
            .unwrap_or_else(|e| panic!("parse_pairing_code_v1 failed on {}: {e}", gvec.name));
        assert_eq!(code.grant_id, grant.id);
        assert_eq!(code.admin_fingerprint, admin_pk.fingerprint());
        assert!(parse_pairing_code_v1(&gvec.code.replacen("t3mp1_", "t3mp2_", 1)).is_err());
        assert!(parse_pairing_code_v1(&gvec.code[..gvec.code.len() - 4]).is_err());

        // 3. Full Entry (Grant + SignedBinding) verification + mutated copies fail closed.
        let identity = verify_entry_v1(&gvec.entry, &admin_pk)
            .unwrap_or_else(|e| panic!("verify_entry_v1 failed on {}: {e}", gvec.name));
        assert_eq!(identity.connector_id, gvec.connector_id);
        assert_eq!(identity.signing_key, signer_kp.public_key_b64());
        assert_eq!(identity.encryption_key, enc_kp.public_key_b64());
        assert!(verify_entry_v1(&gvec.entry, &wrong_admin_pk).is_err());

        // Mutating binding pairing_sig, self_sig, or grant signature all fail closed!
        let mut bad_entry_sig = gvec.entry.clone();
        bad_entry_sig.binding.pairing_sig = flip_b64url_byte(&bad_entry_sig.binding.pairing_sig, 7);
        assert!(verify_entry_v1(&bad_entry_sig, &admin_pk).is_err());

        let mut bad_entry_self = gvec.entry.clone();
        bad_entry_self.binding.self_sig = flip_b64url_byte(&bad_entry_self.binding.self_sig, 9);
        assert!(verify_entry_v1(&bad_entry_self, &admin_pk).is_err());

        let mut bad_entry_grant = gvec.entry.clone();
        bad_entry_grant.grant.sig = flip_b64url_byte(&bad_entry_grant.grant.sig, 11);
        assert!(verify_entry_v1(&bad_entry_grant, &admin_pk).is_err());

        // 4. Revocation verification + mutations fail closed.
        let rev = open_revocation_v1(&gvec.revocation, &admin_pk)
            .unwrap_or_else(|e| panic!("open_revocation_v1 failed on {}: {e}", gvec.name));
        assert_eq!(rev.grant_id, grant.id);
        assert_eq!(rev.connector_id, gvec.connector_id);
        assert!(open_revocation_v1(&gvec.revocation, &wrong_admin_pk).is_err());

        let mut bad_rev = gvec.revocation.clone();
        bad_rev.sig = flip_b64url_byte(&bad_rev.sig, 5);
        assert!(open_revocation_v1(&bad_rev, &admin_pk).is_err());
    }

    // 5. KeyRegistrations + wrong connectorId + mutated sig fail closed.
    assert_eq!(fixture.key_registrations.len(), 2);
    for kr in &fixture.key_registrations {
        let expected_sign = ed_keys[&kr.signer_key_name].public_key();
        let expected_enc = x_keys[&kr.enc_key_name].public_key();
        let (got_sign, got_enc) =
            verify_key_registration_v1(&kr.connector_id, &kr.registration).unwrap();
        assert_eq!(got_sign, expected_sign);
        assert_eq!(got_enc, expected_enc);

        // Wrong connector_id binding MUST fail closed.
        assert!(verify_key_registration_v1("wrong@node", &kr.registration).is_err());

        // Flipped proof sig MUST fail closed.
        let mut bad_kr = kr.registration.clone();
        bad_kr.proof.sig = flip_b64url_byte(&bad_kr.proof.sig, 2);
        assert!(verify_key_registration_v1(&kr.connector_id, &bad_kr).is_err());
    }
}

#[test]
fn golden_v1_seal_ciphertexts_hyp1_file_packs_and_mutations() {
    let fixture = load_fixture();
    let (ed_keys, x_keys) = load_key_maps(&fixture);
    let tmp = TempDir::new().unwrap();

    assert_eq!(fixture.sealed_transfers.len(), 3);
    for tv in &fixture.sealed_transfers {
        let sender_pk = ed_keys[&tv.sender_sign_key_name].public_key();
        let recipient_kp = &x_keys[&tv.recipient_enc_key_name];
        let wrong_sender_pk = ed_keys["admin"].public_key();
        let wrong_recipient_kp = if tv.recipient_enc_key_name == "bob-enc" {
            &x_keys["carol-enc"]
        } else {
            &x_keys["bob-enc"]
        };

        let ct = URL_SAFE_NO_PAD
            .decode(&tv.sealed_ciphertext_b64)
            .expect("decode ciphertext");
        let expected_pack = URL_SAFE_NO_PAD
            .decode(&tv.packed_payload_b64)
            .expect("decode packed payload");

        // 1. Open TS-sealed transfer & assert byte-identical HYP1 plaintext.
        let (hdr, plaintext) = open_v1(&tv.sealed_header, &ct, &sender_pk, recipient_kp)
            .unwrap_or_else(|e| panic!("open_v1 failed on {}: {e}", tv.name));
        assert_eq!(hdr.from, tv.from);
        assert_eq!(hdr.to, tv.to);
        assert_eq!(hdr.to_handle, tv.to_handle);
        assert_eq!(hdr.transfer_type, tv.transfer_type);
        assert_eq!(&*plaintext, &expected_pack);

        // 2. Unpack TS HYP1 archive & verify metadata + exact file bytes + SHA-256!
        let unpack_dir = tmp.path().join(&tv.name);
        let unpacked = unpack_hyp1(&plaintext, &unpack_dir, None, None)
            .unwrap_or_else(|e| panic!("unpack_hyp1 failed on {}: {e}", tv.name));
        assert_eq!(unpacked.from_handle, tv.from_handle);
        assert_eq!(unpacked.note, tv.note);
        assert_eq!(unpacked.files.len(), tv.files.len());
        for (got_file, exp_file) in unpacked.files.iter().zip(tv.files.iter()) {
            assert_eq!(got_file.name, exp_file.name);
            let got_bytes = fs::read(&got_file.path).unwrap();
            let exp_bytes = URL_SAFE_NO_PAD.decode(&exp_file.content_b64).unwrap();
            assert_eq!(
                got_bytes, exp_bytes,
                "file content mismatch for {}",
                exp_file.name
            );
            assert_eq!(hex::encode(Sha256::digest(&got_bytes)), exp_file.sha256);
        }

        // 3. Mutated copies of `seal_v1` MUST ALL fail closed!
        // 3a. Wrong sender Ed25519 key
        assert!(open_v1(&tv.sealed_header, &ct, &wrong_sender_pk, recipient_kp).is_err());
        // 3b. Wrong recipient X25519 key
        assert!(open_v1(&tv.sealed_header, &ct, &sender_pk, wrong_recipient_kp).is_err());
        // 3c. Flipped header signature bit
        let mut bad_hdr = tv.sealed_header.clone();
        bad_hdr.sig = flip_b64url_byte(&bad_hdr.sig, 0);
        assert!(open_v1(&bad_hdr, &ct, &sender_pk, recipient_kp).is_err());
        // 3d. Flipped ciphertext body byte
        let mut bad_ct_body = ct.clone();
        bad_ct_body[0] ^= 0x80;
        assert!(open_v1(&tv.sealed_header, &bad_ct_body, &sender_pk, recipient_kp).is_err());
        // 3e. Flipped GCM auth tag byte (last byte)
        let mut bad_ct_tag = ct.clone();
        let last = bad_ct_tag.len() - 1;
        bad_ct_tag[last] ^= 0x01;
        assert!(open_v1(&tv.sealed_header, &bad_ct_tag, &sender_pk, recipient_kp).is_err());

        // 4. Mutated copies of `HYP1` pack MUST ALL fail closed!
        let mut bad_magic = plaintext.clone();
        bad_magic[3] = b'2';
        assert!(
            unpack_hyp1(
                &bad_magic,
                &tmp.path().join(format!("{}_bad_magic", tv.name)),
                None,
                None
            )
            .is_err()
        );

        let mut bad_gz = plaintext.clone();
        let mid = bad_gz.len() / 2;
        bad_gz[mid] ^= 0xff;
        assert!(
            unpack_hyp1(
                &bad_gz,
                &tmp.path().join(format!("{}_bad_gz", tv.name)),
                None,
                None
            )
            .is_err()
        );

        let truncated = &plaintext[..plaintext.len().saturating_sub(8)];
        assert!(
            unpack_hyp1(
                truncated,
                &tmp.path().join(format!("{}_trunc", tv.name)),
                None,
                None
            )
            .is_err()
        );
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
