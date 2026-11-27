//! Golden vectors, differential reference-oracle verification, and mutated-valid-input
//! fail-closed tests for `hyp_crypto::human` (Verified Human Drops MVP).

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hyp_crypto::e2ee::pad_bucket;
use hyp_crypto::human::{
    CLOCK_SKEW_MS, EncryptedHumanDraftV1, HCERT1_PREFIX, HDROP1_PREFIX, HUMAN_CLAIM_DOMAIN,
    HUMAN_DRAFT_SUITE, HUMAN_DROP_SUITE_V1, HUMAN_PRF_HKDF_SALT, HUMAN_PRF_X25519_SALT,
    HumanAudience, HumanClaimV1, HumanDraftPayloadV1, HumanDropEnvelopeV1, HumanDropKind,
    HumanRevocationPayloadV1, LOCAL_EVENT_SIG_DOMAIN, MAX_CLAIM_TTL_MS, MAX_HUMAN_DRAFT_CHARS,
    MAX_HUMAN_DRAFT_CONTEXT_CHARS, NodeCertPayloadV1, SecretDropSpec, SignedHumanClaimV1,
    decode_hcert1, decode_hdrop1, derive_prf_ed25519_keypair, derive_prf_x25519_keypair,
    encode_hcert1, encode_hdrop1, human_draft_hpke_aad, human_draft_hpke_info, human_drop_hpke_aad,
    human_drop_hpke_info, human_prf_input, is_reserved_drop_secret_name, is_reserved_secret_name,
    open_human_draft, open_human_drop, seal_human_draft, seal_human_drop, sign_human_claim,
    sign_human_revocation, sign_local_ingest_event, sign_node_cert, validate_draft_text,
    verify_human_revocation, verify_local_ingest_event, verify_node_cert,
};
use hyp_crypto::jcs::to_canonical_json;
use hyp_crypto::rfc3339::{format_rfc3339_millis, parse_rfc3339_millis};
use hyp_crypto::{CryptoError, Ed25519KeyPair, X25519KeyPair, hpke};
use ring::hmac;

const T0: i64 = 1_795_554_000_000; // 2026-11-24T21:00:00.000Z

/// Independent RFC 5869 HKDF-SHA256 reference oracle (differential verification against `hyp_crypto`).
fn reference_hkdf_sha256_32(salt: &[u8], ikm: &[u8], info: &[u8]) -> [u8; 32] {
    // Extract: PRK = HMAC-SHA256(salt, IKM)
    let salt_key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    let prk = hmac::sign(&salt_key, ikm);
    // Expand (L = 32 -> single block T(1) = HMAC-SHA256(PRK, info || 0x01))
    let prk_key = hmac::Key::new(hmac::HMAC_SHA256, prk.as_ref());
    let mut msg = Vec::with_capacity(info.len() + 1);
    msg.extend_from_slice(info);
    msg.push(0x01);
    let okm = hmac::sign(&prk_key, &msg);
    let mut out = [0u8; 32];
    out.copy_from_slice(okm.as_ref());
    out
}

fn flip_b64_bit(b64: &str, byte_idx: usize, bit_mask: u8) -> String {
    let mut raw = URL_SAFE_NO_PAD.decode(b64).expect("valid base64url");
    raw[byte_idx] ^= bit_mask;
    URL_SAFE_NO_PAD.encode(&raw)
}

fn sample_directive_claim(
    signer: &Ed25519KeyPair,
    node_enc: &X25519KeyPair,
    drop_id: &str,
) -> HumanClaimV1 {
    HumanClaimV1 {
        v: 1,
        kind: HumanDropKind::Directive,
        claim_id: "9f2aB7xQ_kL3mNpRsTuVwX".to_string(),
        human_id: "riley".to_string(),
        human_kid: signer.kid(),
        auth_epoch: 1,
        issued_at: format_rfc3339_millis(T0),
        expires_at: format_rfc3339_millis(T0 + 600_000),
        drop_id: drop_id.to_string(),
        audience: HumanAudience {
            node_id: "prod@eu-1".to_string(),
            node_enc_kid: node_enc.kid(),
            handle: Some("ops".to_string()),
        },
        secret_spec: None,
        body: "Deploy commit 8a9b1c2 to eu-1 after canary passes.".to_string(),
    }
}

fn sample_secret_claim(
    signer: &Ed25519KeyPair,
    node_enc: &X25519KeyPair,
    drop_id: &str,
    secret_name: &str,
) -> HumanClaimV1 {
    HumanClaimV1 {
        v: 1,
        kind: HumanDropKind::Secret,
        claim_id: "7c1dE4fG_hI2jKlMnOpQrS".to_string(),
        human_id: "riley".to_string(),
        human_kid: signer.kid(),
        auth_epoch: 1,
        issued_at: format_rfc3339_millis(T0),
        expires_at: format_rfc3339_millis(T0 + 600_000),
        drop_id: drop_id.to_string(),
        audience: HumanAudience {
            node_id: "prod@eu-1".to_string(),
            node_enc_kid: node_enc.kid(),
            handle: Some("ops".to_string()),
        },
        secret_spec: Some(SecretDropSpec {
            name: secret_name.to_string(),
            overwrite: false,
        }),
        body: "hyphae_zk_test_secret_value_001".to_string(),
    }
}

/// Manually seals a raw `SignedHumanClaimV1` into a valid HPKE `HumanDropEnvelopeV1`
/// (bypassing `seal_human_drop` sender-side validation so we can test receiver-side fail-closed guards!).
fn manual_hpke_seal(
    signed: &SignedHumanClaimV1,
    recipient_enc_pk: &hyp_crypto::X25519PublicKey,
    outer_drop_id: &str,
) -> HumanDropEnvelopeV1 {
    let signed_json = to_canonical_json(signed).unwrap();
    let padded = pad_bucket(signed_json.as_bytes()).unwrap();
    let kid = recipient_enc_pk.kid();
    let info = human_drop_hpke_info(&kid, outer_drop_id);
    let aad = human_drop_hpke_aad(&kid, outer_drop_id);
    let (enc, ct) = hpke::seal_base(recipient_enc_pk, &info, &aad, &padded).unwrap();
    HumanDropEnvelopeV1 {
        v: 1,
        suite: HUMAN_DROP_SUITE_V1.to_string(),
        drop_id: outer_drop_id.to_string(),
        enc: URL_SAFE_NO_PAD.encode(enc),
        ct: URL_SAFE_NO_PAD.encode(&ct),
    }
}

fn manual_sign_claim_unchecked(
    claim: &HumanClaimV1,
    signer: &Ed25519KeyPair,
) -> SignedHumanClaimV1 {
    let payload = to_canonical_json(claim).unwrap();
    let mut msg = Vec::with_capacity(HUMAN_CLAIM_DOMAIN.len() + payload.len());
    msg.extend_from_slice(HUMAN_CLAIM_DOMAIN);
    msg.extend_from_slice(payload.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(signer.sign_raw(&msg));
    SignedHumanClaimV1 { payload, sig }
}

// ============================================================================
// 1. Deterministic PRF + HKDF-SHA256 & HPKE Context Golden Vectors
// ============================================================================

#[test]
fn golden_prf_hkdf_derivation_and_hpke_context_vectors() {
    let prf_output: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let human_id = "riley";
    let prf_salt = "prf_salt_golden_v1";
    let auth_epoch = 1u64;

    // 1. PRF input SHA-256 vector
    let prf_in = human_prf_input(human_id, prf_salt);
    let prf_in_hex = hex::encode(prf_in);
    assert_eq!(prf_in.len(), 32);
    // Independent SHA-256 check
    use sha2::{Digest, Sha256};
    let expected_prf_in = hex::encode(Sha256::digest(
        b"hyphae/v2/human-prf-input\nriley\nprf_salt_golden_v1",
    ));
    assert_eq!(prf_in_hex, expected_prf_in);

    // 2. Differential RFC 5869 HKDF-SHA256 check for Ed25519 seed derivation
    let mut expected_info = Vec::new();
    expected_info.extend_from_slice(b"riley\n");
    expected_info.extend_from_slice(&1u64.to_be_bytes());
    let expected_seed = reference_hkdf_sha256_32(HUMAN_PRF_HKDF_SALT, &prf_output, &expected_info);

    let kp = derive_prf_ed25519_keypair(&prf_output, human_id, auth_epoch).unwrap();
    assert_eq!(kp.seed_bytes(), &expected_seed);

    // Deterministic across repeated calls and distinct across epochs / humanIds
    let kp_again = derive_prf_ed25519_keypair(&prf_output, human_id, auth_epoch).unwrap();
    assert_eq!(kp.public_key_bytes(), kp_again.public_key_bytes());
    assert_eq!(kp.kid(), kp_again.kid());

    let kp_epoch2 = derive_prf_ed25519_keypair(&prf_output, human_id, 2).unwrap();
    assert_ne!(kp.public_key_bytes(), kp_epoch2.public_key_bytes());
    assert_ne!(kp.kid(), kp_epoch2.kid());

    let kp_other_human = derive_prf_ed25519_keypair(&prf_output, "alice", auth_epoch).unwrap();
    assert_ne!(kp.public_key_bytes(), kp_other_human.public_key_bytes());

    // Fail closed on invalid PRF inputs
    assert!(derive_prf_ed25519_keypair(&prf_output, human_id, 0).is_err());
    assert!(derive_prf_ed25519_keypair(&prf_output, "", 1).is_err());
    assert!(derive_prf_ed25519_keypair(&prf_output, "bad\nhuman", 1).is_err());
    assert!(derive_prf_ed25519_keypair(&prf_output, "UPPER", 1).is_err());

    // 3. Exact HPKE info and AAD byte formatting (online relay & offline empty dropId)
    assert_eq!(
        human_drop_hpke_info("encKid123", "dropAbc"),
        b"hyphae/v2/human-drop\n1\nencKid123\ndropAbc"
    );
    assert_eq!(
        human_drop_hpke_aad("encKid123", "dropAbc"),
        b"hyphae/v2/human-drop-aad\nhuman.drop.v1\nencKid123\ndropAbc"
    );
    assert_eq!(
        human_drop_hpke_info("encKid123", ""),
        b"hyphae/v2/human-drop\n1\nencKid123\n"
    );
    assert_eq!(
        human_drop_hpke_aad("encKid123", ""),
        b"hyphae/v2/human-drop-aad\nhuman.drop.v1\nencKid123\n"
    );

    // Frozen golden vector assertions for bit-exact cross-language parity with site/drop/crypto.js
    assert_eq!(
        prf_in_hex,
        "3e33d281eb415de893fb84014f62c4f73089c6a0a246af486ef7a1b20ef62835"
    );
    assert_eq!(
        hex::encode(kp.seed_bytes()),
        "bf4ac0b286c37619dee23126a228416cfbba5c9c647a7087c8940b88c2e71400"
    );
    assert_eq!(
        kp.public_key_b64(),
        "K9V8yrpadyse_IxKHl1U3ZF3C1foO3X71UAInHriGx8"
    );
    assert_eq!(kp.kid(), "lGP0xwXhgK3CMB4qC8aWhJflZ-de5JGALgoM-5A19l8");
}

// ============================================================================
// 2. Roundtrip Sealed Drops (`directive` + `secret`, `hdrop1_`), `NodeCertV1` (`hcert1_`), `HumanRevocationV1`
// ============================================================================

#[test]
fn roundtrip_directive_and_secret_hdrop1_hides_all_metadata() {
    let human = Ed25519KeyPair::from_seed([0x11; 32]).unwrap();
    let node_enc = X25519KeyPair::from_bytes([0x22; 32]).unwrap();

    // 1. Relay directive drop
    let directive = sample_directive_claim(&human, &node_enc, "4d8eK2mN9pQ1rS5tU7vW0x");
    let env = seal_human_drop(&directive, &human, &node_enc.public_key()).unwrap();
    assert_eq!(env.v, 1);
    assert_eq!(env.suite, HUMAN_DROP_SUITE_V1);
    assert_eq!(env.drop_id, "4d8eK2mN9pQ1rS5tU7vW0x");

    // Outer wire JSON MUST NOT leak humanId, humanKid, nodeId, kind, secretSpec, or body!
    let wire_json = to_canonical_json(&env).unwrap();
    assert!(!wire_json.contains("riley"));
    assert!(!wire_json.contains(&human.kid()));
    assert!(!wire_json.contains("prod@eu-1"));
    assert!(!wire_json.contains(&node_enc.kid()));
    assert!(!wire_json.contains("directive"));
    assert!(!wire_json.contains("Deploy commit"));

    // Ciphertext length = power-of-2 padded bucket + 16-byte AES-256-GCM tag
    let raw_ct = URL_SAFE_NO_PAD.decode(&env.ct).unwrap();
    assert!((raw_ct.len() - 16).is_power_of_two());

    // Armored hdrop1_ roundtrip + open
    let armored = encode_hdrop1(&env).unwrap();
    assert!(armored.starts_with(HDROP1_PREFIX));
    let decoded_env = decode_hdrop1(&armored).unwrap();
    assert_eq!(decoded_env, env);

    let opened = open_human_drop(
        &decoded_env,
        &node_enc,
        "prod@eu-1",
        T0 + 1_000,
        |hid, kid| {
            assert_eq!(hid, "riley");
            assert_eq!(kid, human.kid());
            Some((human.public_key(), 1))
        },
    )
    .unwrap();
    assert_eq!(opened, directive);

    // 2. Offline secret drop (`drop_id = ""`)
    let secret = sample_secret_claim(&human, &node_enc, "", "stripe-prod-key");
    let sec_env = seal_human_drop(&secret, &human, &node_enc.public_key()).unwrap();
    let sec_wire = to_canonical_json(&sec_env).unwrap();
    assert!(!sec_wire.contains("stripe-prod-key"));
    assert!(!sec_wire.contains("hyphae_zk_test_secret"));

    let sec_armored = encode_hdrop1(&sec_env).unwrap();
    let sec_decoded = decode_hdrop1(&sec_armored).unwrap();
    let opened_sec = open_human_drop(&sec_decoded, &node_enc, "prod@eu-1", T0 + 5_000, |_, _| {
        Some((human.public_key(), 1))
    })
    .unwrap();
    assert_eq!(opened_sec, secret);
}

#[test]
fn roundtrip_node_cert_hcert1_and_mutations_fail_closed() {
    let admin = Ed25519KeyPair::from_seed([0x33; 32]).unwrap();
    let other_human = Ed25519KeyPair::from_seed([0x44; 32]).unwrap();
    let node_sign = Ed25519KeyPair::from_seed([0x55; 32]).unwrap();
    let node_enc = X25519KeyPair::from_bytes([0x66; 32]).unwrap();

    let cert = NodeCertPayloadV1 {
        v: 1,
        node_id: "prod@eu-1".to_string(),
        signing_jwk: node_sign.to_jwk(),
        encryption_jwk: node_enc.to_jwk(),
        human_id: "riley".to_string(),
        human_kid: admin.kid(),
        auth_epoch: 2,
        issued_at: format_rfc3339_millis(T0),
        expires_at: format_rfc3339_millis(T0 + 86_400_000),
    };

    let signed = sign_node_cert(&cert, &admin).unwrap();
    let armored = encode_hcert1(&signed).unwrap();
    assert!(armored.starts_with(HCERT1_PREFIX));
    let decoded = decode_hcert1(&armored).unwrap();
    assert_eq!(decoded, signed);

    let verified = verify_node_cert(&decoded, &admin.public_key(), T0 + 1_000, 2).unwrap();
    assert_eq!(verified, cert);

    // 1-bit flip in sig fails closed
    let mut bad_sig = decoded.clone();
    bad_sig.sig = flip_b64_bit(&bad_sig.sig, 0, 0x01);
    assert!(matches!(
        verify_node_cert(&bad_sig, &admin.public_key(), T0 + 1_000, 1),
        Err(CryptoError::InvalidSignature(_))
    ));

    // 1-bit flip in payload fails closed
    let mut bad_payload = decoded.clone();
    bad_payload.payload = bad_payload.payload.replace("prod@eu-1", "prod@eu-2");
    assert!(matches!(
        verify_node_cert(&bad_payload, &admin.public_key(), T0 + 1_000, 1),
        Err(CryptoError::InvalidSignature(_))
    ));

    // Wrong issuer fails closed
    assert!(matches!(
        verify_node_cert(&decoded, &other_human.public_key(), T0 + 1_000, 1),
        Err(CryptoError::InvalidSignature(_))
    ));

    // Expired cert fails closed (exact boundary and past)
    assert!(verify_node_cert(&decoded, &admin.public_key(), T0 + 86_400_000, 1).is_err());
    assert!(verify_node_cert(&decoded, &admin.public_key(), T0 + 86_400_001, 1).is_err());

    // Future issuedAt beyond CLOCK_SKEW_MS fails closed
    assert!(verify_node_cert(&decoded, &admin.public_key(), T0 - CLOCK_SKEW_MS - 1, 1).is_err());

    // Rolled-back authEpoch fails closed with ReplayOrRollback
    assert!(matches!(
        verify_node_cert(&decoded, &admin.public_key(), T0 + 1_000, 3),
        Err(CryptoError::ReplayOrRollback(_))
    ));

    // Bad armored prefix fails closed
    assert!(decode_hcert1("hdrop1_abc").is_err());
}

#[test]
fn roundtrip_human_revocation_and_cross_domain_rejection() {
    let admin = Ed25519KeyPair::from_seed([0x77; 32]).unwrap();
    let lost_phone = Ed25519KeyPair::from_seed([0x88; 32]).unwrap();
    let other = Ed25519KeyPair::from_seed([0x99; 32]).unwrap();

    let rev = HumanRevocationPayloadV1 {
        v: 1,
        human_id: "riley".to_string(),
        revoked_kid: lost_phone.kid(),
        new_min_auth_epoch: 3,
        revoked_at: format_rfc3339_millis(T0),
        reason: "Lost phone on train".to_string(),
        issuer_kid: admin.kid(),
    };

    let signed = sign_human_revocation(&rev, &admin).unwrap();
    let verified = verify_human_revocation(&signed, &admin.public_key()).unwrap();
    assert_eq!(verified, rev);

    // 1-bit flip in sig fails closed
    let mut bad_sig = signed.clone();
    bad_sig.sig = flip_b64_bit(&bad_sig.sig, 63, 0x80);
    assert!(matches!(
        verify_human_revocation(&bad_sig, &admin.public_key()),
        Err(CryptoError::InvalidSignature(_))
    ));

    // Wrong issuer fails closed
    assert!(matches!(
        verify_human_revocation(&signed, &other.public_key()),
        Err(CryptoError::InvalidSignature(_))
    ));

    // Cross-domain attack: sign the exact revocation payload bytes under HUMAN_CLAIM_DOMAIN -> MUST fail!
    let mut cross_domain_msg = Vec::new();
    cross_domain_msg.extend_from_slice(HUMAN_CLAIM_DOMAIN);
    cross_domain_msg.extend_from_slice(signed.payload.as_bytes());
    let wrong_domain_signed = hyp_crypto::human::SignedHumanRevocationV1 {
        payload: signed.payload.clone(),
        sig: URL_SAFE_NO_PAD.encode(admin.sign_raw(&cross_domain_msg)),
    };
    assert!(matches!(
        verify_human_revocation(&wrong_domain_signed, &admin.public_key()),
        Err(CryptoError::InvalidSignature(_))
    ));
}

// ============================================================================
// 3. Mutated-Valid-Input Fail-Closed Suite (McKeeman Nearby Altered Inputs)
// ============================================================================

#[test]
fn mutated_drop_envelopes_and_claims_all_fail_closed() {
    let human = Ed25519KeyPair::from_seed([0xA1; 32]).unwrap();
    let node_enc = X25519KeyPair::from_bytes([0xB2; 32]).unwrap();
    let wrong_enc = X25519KeyPair::from_bytes([0xC3; 32]).unwrap();

    let claim = sample_directive_claim(&human, &node_enc, "drop_valid_12345");
    let valid_env = seal_human_drop(&claim, &human, &node_enc.public_key()).unwrap();

    // 1. 1-bit flip in `enc` (first byte & last byte)
    for (idx, mask) in [(0, 0x01), (15, 0x10), (31, 0x80)] {
        let mut mutated = valid_env.clone();
        mutated.enc = flip_b64_bit(&mutated.enc, idx, mask);
        assert!(
            open_human_drop(&mutated, &node_enc, "prod@eu-1", T0 + 1_000, |_, _| {
                Some((human.public_key(), 1))
            })
            .is_err(),
            "1-bit flip in enc[{idx}] must fail closed"
        );
    }

    // 2. 1-bit flip in `ct` (body byte and trailing AEAD tag byte)
    let raw_ct_len = URL_SAFE_NO_PAD.decode(&valid_env.ct).unwrap().len();
    for idx in [0, 32, raw_ct_len - 17, raw_ct_len - 1] {
        let mut mutated = valid_env.clone();
        mutated.ct = flip_b64_bit(&mutated.ct, idx, 0x01);
        assert!(
            open_human_drop(&mutated, &node_enc, "prod@eu-1", T0 + 1_000, |_, _| {
                Some((human.public_key(), 1))
            })
            .is_err(),
            "1-bit flip in ct[{idx}] must fail closed"
        );
    }

    // 3. 1-bit flip in inner Ed25519 `sig` (re-sealed cleanly with valid HPKE!)
    let mut bad_inner_sig = sign_human_claim(&claim, &human).unwrap();
    bad_inner_sig.sig = flip_b64_bit(&bad_inner_sig.sig, 10, 0x04);
    let env_bad_sig = manual_hpke_seal(&bad_inner_sig, &node_enc.public_key(), &claim.drop_id);
    assert!(matches!(
        open_human_drop(&env_bad_sig, &node_enc, "prod@eu-1", T0 + 1_000, |_, _| {
            Some((human.public_key(), 1))
        }),
        Err(CryptoError::InvalidSignature(_))
    ));

    // 4. 1-bit flip in inner `payload` (re-sealed cleanly with valid HPKE!)
    let mut bad_inner_payload = sign_human_claim(&claim, &human).unwrap();
    bad_inner_payload.payload = bad_inner_payload.payload.replace("eu-1", "eu-2");
    let env_bad_payload =
        manual_hpke_seal(&bad_inner_payload, &node_enc.public_key(), &claim.drop_id);
    assert!(matches!(
        open_human_drop(
            &env_bad_payload,
            &node_enc,
            "prod@eu-1",
            T0 + 1_000,
            |_, _| { Some((human.public_key(), 1)) }
        ),
        Err(CryptoError::InvalidSignature(_))
    ));

    // 5. Wrong `recipient_node_id` -> fails closed
    assert!(matches!(
        open_human_drop(&valid_env, &node_enc, "staging@us-1", T0 + 1_000, |_, _| {
            Some((human.public_key(), 1))
        }),
        Err(CryptoError::InvalidEnvelope(_))
    ));

    // 6. Wrong `recipient_enc_kp` (wrong `nodeEncKid`) -> fails closed
    assert!(
        open_human_drop(&valid_env, &wrong_enc, "prod@eu-1", T0 + 1_000, |_, _| {
            Some((human.public_key(), 1))
        })
        .is_err()
    );

    // 7. Inner `audience.nodeEncKid` mismatch (signed for `wrong_enc`, manually HPKE-sealed to `node_enc`)
    let mut wrong_aud_kid = claim.clone();
    wrong_aud_kid.audience.node_enc_kid = wrong_enc.kid();
    let signed_wrong_kid = manual_sign_claim_unchecked(&wrong_aud_kid, &human);
    let env_wrong_kid = manual_hpke_seal(&signed_wrong_kid, &node_enc.public_key(), &claim.drop_id);
    assert!(matches!(
        open_human_drop(
            &env_wrong_kid,
            &node_enc,
            "prod@eu-1",
            T0 + 1_000,
            |_, _| { Some((human.public_key(), 1)) }
        ),
        Err(CryptoError::InvalidEnvelope(_))
    ));

    // 8. Outer `envelope.drop_id` tampered -> HPKE AAD/info fails closed
    let mut bad_outer_drop = valid_env.clone();
    bad_outer_drop.drop_id = "drop_different_99".to_string();
    assert!(
        open_human_drop(
            &bad_outer_drop,
            &node_enc,
            "prod@eu-1",
            T0 + 1_000,
            |_, _| { Some((human.public_key(), 1)) }
        )
        .is_err()
    );

    // 9. Inner `claim.drop_id` != outer `envelope.drop_id` (manually HPKE-sealed with outer id!)
    let signed_claim = sign_human_claim(&claim, &human).unwrap();
    let env_mismatch_drop =
        manual_hpke_seal(&signed_claim, &node_enc.public_key(), "different_outer");
    assert!(matches!(
        open_human_drop(
            &env_mismatch_drop,
            &node_enc,
            "prod@eu-1",
            T0 + 1_000,
            |_, _| { Some((human.public_key(), 1)) }
        ),
        Err(CryptoError::InvalidEnvelope(_))
    ));

    // 10. Expired `expiresAt` (exact expiry boundary & past)
    let exp_ms = parse_rfc3339_millis(&claim.expires_at).unwrap();
    assert!(matches!(
        open_human_drop(&valid_env, &node_enc, "prod@eu-1", exp_ms, |_, _| {
            Some((human.public_key(), 1))
        }),
        Err(CryptoError::InvalidEnvelope(_))
    ));
    assert!(matches!(
        open_human_drop(&valid_env, &node_enc, "prod@eu-1", exp_ms + 1, |_, _| {
            Some((human.public_key(), 1))
        }),
        Err(CryptoError::InvalidEnvelope(_))
    ));
    // 1 ms before expiry succeeds
    assert!(
        open_human_drop(&valid_env, &node_enc, "prod@eu-1", exp_ms - 1, |_, _| {
            Some((human.public_key(), 1))
        })
        .is_ok()
    );

    // 11. TTL > 15m (`MAX_CLAIM_TTL_MS + 1`) rejected on BOTH seal and open!
    let mut over_ttl = claim.clone();
    over_ttl.expires_at = format_rfc3339_millis(T0 + MAX_CLAIM_TTL_MS + 1);
    assert!(seal_human_drop(&over_ttl, &human, &node_enc.public_key()).is_err());
    let signed_over_ttl = manual_sign_claim_unchecked(&over_ttl, &human);
    let env_over_ttl =
        manual_hpke_seal(&signed_over_ttl, &node_enc.public_key(), &over_ttl.drop_id);
    assert!(matches!(
        open_human_drop(&env_over_ttl, &node_enc, "prod@eu-1", T0 + 1_000, |_, _| {
            Some((human.public_key(), 1))
        }),
        Err(CryptoError::InvalidEnvelope(_))
    ));

    // 12. Future `issuedAt` beyond `CLOCK_SKEW_MS` fails closed; exact `CLOCK_SKEW_MS` succeeds!
    assert!(
        open_human_drop(
            &valid_env,
            &node_enc,
            "prod@eu-1",
            T0 - CLOCK_SKEW_MS,
            |_, _| Some((human.public_key(), 1))
        )
        .is_ok()
    );
    assert!(matches!(
        open_human_drop(
            &valid_env,
            &node_enc,
            "prod@eu-1",
            T0 - CLOCK_SKEW_MS - 1,
            |_, _| Some((human.public_key(), 1))
        ),
        Err(CryptoError::InvalidEnvelope(_))
    ));

    // 13. Rolled-back `authEpoch < min_auth_epoch` fails closed with `ReplayOrRollback`!
    assert!(matches!(
        open_human_drop(&valid_env, &node_enc, "prod@eu-1", T0 + 1_000, |_, _| {
            Some((human.public_key(), 2))
        }),
        Err(CryptoError::ReplayOrRollback(_))
    ));

    // 14. Revoked / unknown authority fails closed!
    assert!(matches!(
        open_human_drop(&valid_env, &node_enc, "prod@eu-1", T0 + 1_000, |_, _| None),
        Err(CryptoError::InvalidSignature(_))
    ));

    // 15. Bad armored `hdrop1_` prefix / malformed base64 fails closed
    assert!(decode_hdrop1("hcert1_invalid").is_err());
    assert!(decode_hdrop1("hdrop1_!!!notbase64!!!").is_err());
}

#[test]
fn reserved_secret_names_fail_closed_case_insensitively_on_seal_and_open() {
    let human = Ed25519KeyPair::from_seed([0xD4; 32]).unwrap();
    let node_enc = X25519KeyPair::from_bytes([0xE5; 32]).unwrap();

    let reserved_names = [
        "node-sign-deadbeef1234",
        "NODE-SIGN-DEADBEEF1234",
        "node-enc-deadbeef1234",
        "Node-Enc-1234",
        "id-sign-abcdef012345",
        "id-enc-abcdef012345",
        "admin-ca-root",
        "ADMIN-CA-PRIMARY",
        "gate-policy-hmac-key",
        "Gate-Policy-Sig",
        "human-admin-1234567890ab",
        "human-authority-primary",
        "auth-token-prod",
        "AUTH-TOKEN-1",
    ];

    for name in reserved_names {
        assert!(
            is_reserved_secret_name(name),
            "'{name}' MUST be flagged as reserved"
        );

        assert!(is_reserved_drop_secret_name(name));

        // Seal rejects reserved name
        let claim = sample_secret_claim(&human, &node_enc, "", name);
        assert!(
            matches!(
                seal_human_drop(&claim, &human, &node_enc.public_key()),
                Err(CryptoError::InvalidSecretName(_))
            ),
            "seal_human_drop must reject reserved secret name '{name}'"
        );

        // Even if a malicious client manually signs & HPKE-seals it, `open_human_drop` fails closed!
        let signed = manual_sign_claim_unchecked(&claim, &human);
        let env = manual_hpke_seal(&signed, &node_enc.public_key(), "");
        assert!(
            matches!(
                open_human_drop(&env, &node_enc, "prod@eu-1", T0 + 1_000, |_, _| {
                    Some((human.public_key(), 1))
                }),
                Err(CryptoError::InvalidSecretName(_))
            ),
            "open_human_drop must reject reserved secret name '{name}'"
        );
    }

    // Drop ingestion keeps its stricter policy without changing the general crypto policy.
    for name in [
        "node-ed25519-legacy",
        " NODE-X25519-primary ",
        "Peer-Auth-router",
    ] {
        assert!(!is_reserved_secret_name(name));
        assert!(is_reserved_drop_secret_name(name));
    }

    // Legitimate application secret names are allowed
    for allowed in [
        "stripe-prod-key",
        "openai_api_key",
        "db.password-2",
        "my-node-sign-token",
    ] {
        assert!(
            !is_reserved_secret_name(allowed),
            "'{allowed}' must NOT be flagged as reserved"
        );
        assert!(!is_reserved_drop_secret_name(allowed));
        let claim = sample_secret_claim(&human, &node_enc, "", allowed);
        let env = seal_human_drop(&claim, &human, &node_enc.public_key()).unwrap();
        let opened = open_human_drop(&env, &node_enc, "prod@eu-1", T0 + 1_000, |_, _| {
            Some((human.public_key(), 1))
        })
        .unwrap();
        assert_eq!(opened.secret_spec.unwrap().name, allowed);
    }

    // Smuggling secretSpec in a directive or omitting secretSpec in a secret fails closed
    let mut bad_dir = sample_directive_claim(&human, &node_enc, "");
    bad_dir.secret_spec = Some(SecretDropSpec {
        name: "stripe-prod-key".to_string(),
        overwrite: false,
    });
    assert!(seal_human_drop(&bad_dir, &human, &node_enc.public_key()).is_err());

    let mut bad_sec = sample_secret_claim(&human, &node_enc, "", "stripe-prod-key");
    bad_sec.secret_spec = None;
    assert!(seal_human_drop(&bad_sec, &human, &node_enc.public_key()).is_err());
}

// ============================================================================
// 4. Companion Passkey-PRF X25519 Derivation, Encrypted Drafts (`human.draft.v1`),
//    BiDi/Control Guards, and Local Event Signatures (`hyphaesig`)
// ============================================================================

#[test]
fn golden_prf_x25519_derivation_differential_and_parity_vectors() {
    // 1. Existing golden PRF seed (`0x01..=0x20`, `human_id = "riley"`, `auth_epoch = 1`)
    let prf_output: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let mut info_riley = Vec::new();
    info_riley.extend_from_slice(b"riley\n");
    info_riley.extend_from_slice(&1u64.to_be_bytes());
    let expected_x25519_seed =
        reference_hkdf_sha256_32(HUMAN_PRF_X25519_SALT, &prf_output, &info_riley);

    let xkp = derive_prf_x25519_keypair(&prf_output, "riley", 1).unwrap();
    let edkp = derive_prf_ed25519_keypair(&prf_output, "riley", 1).unwrap();
    assert_eq!(xkp.secret_bytes(), &expected_x25519_seed);
    assert_ne!(
        xkp.secret_bytes(),
        edkp.seed_bytes(),
        "X25519 salt must domain-separate seed from Ed25519 seed"
    );
    assert_eq!(xkp.to_jwk().kty, "OKP");
    assert_eq!(xkp.to_jwk().crv, "X25519");

    // Deterministic, epoch-rotated, and humanId-separated
    let xkp_again = derive_prf_x25519_keypair(&prf_output, "riley", 1).unwrap();
    assert_eq!(xkp.public_key_bytes(), xkp_again.public_key_bytes());
    assert_eq!(xkp.kid(), xkp_again.kid());

    let xkp_epoch2 = derive_prf_x25519_keypair(&prf_output, "riley", 2).unwrap();
    assert_ne!(xkp.public_key_bytes(), xkp_epoch2.public_key_bytes());
    assert_ne!(xkp.kid(), xkp_epoch2.kid());

    let xkp_other = derive_prf_x25519_keypair(&prf_output, "alice", 1).unwrap();
    assert_ne!(xkp.public_key_bytes(), xkp_other.public_key_bytes());

    // Fail closed on invalid inputs (exact same guards as Ed25519 derivation)
    assert!(derive_prf_x25519_keypair(&prf_output, "riley", 0).is_err());
    assert!(derive_prf_x25519_keypair(&prf_output, "", 1).is_err());
    assert!(derive_prf_x25519_keypair(&prf_output, "bad\nhuman", 1).is_err());
    assert!(derive_prf_x25519_keypair(&prf_output, "UPPER", 1).is_err());

    // 2. Cross-language parity vector (`[0x42; 32]`, `"riley@laptop"`, `auth_epoch = 1`)
    let prf_42 = [0x42u8; 32];
    let mut info_laptop = Vec::new();
    info_laptop.extend_from_slice(b"riley@laptop\n");
    info_laptop.extend_from_slice(&1u64.to_be_bytes());
    let expected_seed_42 = reference_hkdf_sha256_32(HUMAN_PRF_X25519_SALT, &prf_42, &info_laptop);
    let xkp_42 = derive_prf_x25519_keypair(&prf_42, "riley@laptop", 1).unwrap();
    assert_eq!(xkp_42.secret_bytes(), &expected_seed_42);

    // Frozen golden vectors for bit-exact cross-language parity with site/drop/crypto.js
    assert_eq!(
        hex::encode(xkp.secret_bytes()),
        "6a11f21c76839118dd7b1a3398bf55e161f0e17ee55f4255a34e1739fde2c10a"
    );
    assert_eq!(
        xkp.public_key_b64(),
        "-r-JbVKpJ8b7Il0KEDoENapjf4573RBx91N-stbiyko"
    );
    assert_eq!(xkp.kid(), "X-Nb11_B-mkg8EhgSVDFqZGErzIGUtA5B9hw8ermw0Y");

    assert_eq!(
        hex::encode(xkp_42.secret_bytes()),
        "cff92086a9a86d5a5899dd7c954653507df69eccf32be25aefeaedffc95d9b78"
    );
    assert_eq!(
        xkp_42.public_key_b64(),
        "sCgHjkeXSeIo_WraHUREnLiKvaxGyUlNXC7g-_2Id1U"
    );
    assert_eq!(xkp_42.kid(), "UtmzLYU60s2Jj123YDj9-lyyavWFwXCEcWZ6nVFcTd4");
}

#[test]
fn encrypted_human_draft_roundtrip_and_mutated_inputs_fail_closed() {
    let prf_42 = [0x42u8; 32];
    let human_enc = derive_prf_x25519_keypair(&prf_42, "riley@laptop", 1).unwrap();
    let other_enc = derive_prf_x25519_keypair(&prf_42, "riley@laptop", 2).unwrap();

    // Exact HPKE info and AAD byte formatting
    let info = human_draft_hpke_info("prod@eu-1", &human_enc.kid());
    assert_eq!(
        info,
        format!("hyphae/v2/human-draft\nprod@eu-1\n{}", human_enc.kid()).into_bytes()
    );
    let aad = human_draft_hpke_aad("prod@eu-1", &human_enc.kid()).unwrap();
    assert_eq!(
        String::from_utf8(aad).unwrap(),
        format!(
            "{{\"nodeId\":\"prod@eu-1\",\"recipientKid\":\"{}\",\"suite\":\"human.draft.v1\",\"v\":1}}",
            human_enc.kid()
        )
    );

    // 1. Roundtrip with context, newline, tab, and Unicode
    let draft_payload = HumanDraftPayloadV1 {
        v: 1,
        node_id: "prod@eu-1".to_string(),
        text: "Approve deploy of release v0.5.0:\n\t- Verify canary metrics ✓".to_string(),
        context: Some("Deploy gate · eu-1".to_string()),
        created_at: format_rfc3339_millis(T0),
    };
    let sealed = seal_human_draft(&draft_payload, &human_enc.public_key()).unwrap();
    assert_eq!(sealed.v, 1);
    assert_eq!(sealed.suite, HUMAN_DRAFT_SUITE);
    assert_eq!(sealed.recipient_kid, human_enc.kid());

    // Wire JSON MUST NOT leak plaintext draft text, context, or nodeId!
    let wire_json = to_canonical_json(&sealed).unwrap();
    assert!(!wire_json.contains("Approve deploy"));
    assert!(!wire_json.contains("Deploy gate"));
    assert!(!wire_json.contains("prod@eu-1"));

    // Power-of-2 bucket padding + 16-byte AES-256-GCM tag
    let raw_ct = URL_SAFE_NO_PAD.decode(&sealed.ct).unwrap();
    assert!((raw_ct.len() - 16).is_power_of_two());

    let opened = open_human_draft(&sealed, &human_enc, "prod@eu-1").unwrap();
    assert_eq!(opened, draft_payload);

    // 2. Roundtrip without optional context
    let no_ctx = HumanDraftPayloadV1 {
        v: 1,
        node_id: "prod@eu-1".to_string(),
        text: "Rotate session tokens.".to_string(),
        context: None,
        created_at: format_rfc3339_millis(T0),
    };
    let sealed_no_ctx = seal_human_draft(&no_ctx, &human_enc.public_key()).unwrap();
    assert_eq!(
        open_human_draft(&sealed_no_ctx, &human_enc, "prod@eu-1").unwrap(),
        no_ctx
    );

    // 3. Mutated valid inputs ALL fail closed:
    // 3a. 1-bit flip in `enc`
    for (idx, mask) in [(0, 0x01), (16, 0x08), (31, 0x80)] {
        let mut mutated = sealed.clone();
        mutated.enc = flip_b64_bit(&mutated.enc, idx, mask);
        assert!(
            open_human_draft(&mutated, &human_enc, "prod@eu-1").is_err(),
            "1-bit flip in draft enc[{idx}] must fail closed"
        );
    }

    // 3b. 1-bit flip in `ct` (ciphertext & AEAD tag)
    for idx in [0, 32, raw_ct.len() - 17, raw_ct.len() - 1] {
        let mut mutated = sealed.clone();
        mutated.ct = flip_b64_bit(&mutated.ct, idx, 0x01);
        assert!(
            open_human_draft(&mutated, &human_enc, "prod@eu-1").is_err(),
            "1-bit flip in draft ct[{idx}] must fail closed"
        );
    }

    // 3c. Wrong expected `nodeId` fails HPKE info/AAD check
    assert!(open_human_draft(&sealed, &human_enc, "staging@us-1").is_err());

    // 3d. Wrong `recipientKid` or wrong recipient keypair fails closed
    let mut wrong_kid = sealed.clone();
    wrong_kid.recipient_kid = other_enc.kid();
    assert!(open_human_draft(&wrong_kid, &human_enc, "prod@eu-1").is_err());
    assert!(open_human_draft(&sealed, &other_enc, "prod@eu-1").is_err());

    // 3e. Wrong version or suite fails closed
    let mut bad_ver = sealed.clone();
    bad_ver.v = 2;
    assert!(open_human_draft(&bad_ver, &human_enc, "prod@eu-1").is_err());
    let mut bad_suite = sealed.clone();
    bad_suite.suite = "human.drop.v1".to_string();
    assert!(open_human_draft(&bad_suite, &human_enc, "prod@eu-1").is_err());

    // 3f. Malicious sender manually sealing mismatched inner `nodeId` or BiDi payload fails closed on open!
    let malicious_node = HumanDraftPayloadV1 {
        v: 1,
        node_id: "evil@node".to_string(),
        text: "Valid text".to_string(),
        context: None,
        created_at: format_rfc3339_millis(T0),
    };
    let padded_bad_node =
        pad_bucket(to_canonical_json(&malicious_node).unwrap().as_bytes()).unwrap();
    let (enc_m, ct_m) = hpke::seal_base(
        &human_enc.public_key(),
        &human_draft_hpke_info("prod@eu-1", &human_enc.kid()),
        &human_draft_hpke_aad("prod@eu-1", &human_enc.kid()).unwrap(),
        &padded_bad_node,
    )
    .unwrap();
    let crafted_bad_node = EncryptedHumanDraftV1 {
        v: 1,
        suite: HUMAN_DRAFT_SUITE.to_string(),
        recipient_kid: human_enc.kid(),
        enc: URL_SAFE_NO_PAD.encode(enc_m),
        ct: URL_SAFE_NO_PAD.encode(ct_m),
    };
    assert!(matches!(
        open_human_draft(&crafted_bad_node, &human_enc, "prod@eu-1"),
        Err(CryptoError::InvalidEnvelope(_))
    ));

    let malicious_bidi = HumanDraftPayloadV1 {
        v: 1,
        node_id: "prod@eu-1".to_string(),
        text: "Approve \u{202E}evil".to_string(),
        context: None,
        created_at: format_rfc3339_millis(T0),
    };
    let padded_bidi = pad_bucket(to_canonical_json(&malicious_bidi).unwrap().as_bytes()).unwrap();
    let (enc_b, ct_b) = hpke::seal_base(
        &human_enc.public_key(),
        &human_draft_hpke_info("prod@eu-1", &human_enc.kid()),
        &human_draft_hpke_aad("prod@eu-1", &human_enc.kid()).unwrap(),
        &padded_bidi,
    )
    .unwrap();
    let crafted_bidi = EncryptedHumanDraftV1 {
        v: 1,
        suite: HUMAN_DRAFT_SUITE.to_string(),
        recipient_kid: human_enc.kid(),
        enc: URL_SAFE_NO_PAD.encode(enc_b),
        ct: URL_SAFE_NO_PAD.encode(ct_b),
    };
    assert!(matches!(
        open_human_draft(&crafted_bidi, &human_enc, "prod@eu-1"),
        Err(CryptoError::InvalidEnvelope(_))
    ));
}

#[test]
fn validate_draft_text_enforces_length_bidi_invisible_and_control_guards() {
    let human_enc = X25519KeyPair::from_bytes([0x51; 32]).unwrap();

    // Valid edge cases: exact 512 ASCII chars, exact 512 multibyte chars, newline & tab
    let exact_512 = "a".repeat(MAX_HUMAN_DRAFT_CHARS);
    assert!(validate_draft_text(&exact_512).is_ok());
    let exact_512_unicode = "✓".repeat(MAX_HUMAN_DRAFT_CHARS);
    assert!(validate_draft_text(&exact_512_unicode).is_ok());
    assert!(validate_draft_text("line 1\n\tline 2").is_ok());

    // Overflow: 513 chars fails closed
    let over_513 = "a".repeat(MAX_HUMAN_DRAFT_CHARS + 1);
    assert!(validate_draft_text(&over_513).is_err());

    // Empty / whitespace-only fails closed
    assert!(validate_draft_text("").is_err());
    assert!(validate_draft_text("   \n\t  ").is_err());

    // Every forbidden BiDi, invisible, CR, and C0/C1 control char fails closed
    let forbidden_chars = [
        '\u{0000}', '\u{0007}', '\u{0008}', '\u{000B}', '\u{000C}', '\u{000D}', '\u{001B}',
        '\u{001F}', '\u{007F}', '\u{0080}', '\u{0085}', '\u{009F}', '\u{061C}', '\u{200B}',
        '\u{200C}', '\u{200D}', '\u{200E}', '\u{200F}', '\u{2028}', '\u{2029}', '\u{202A}',
        '\u{202D}', '\u{202E}', '\u{202F}', '\u{2060}', '\u{2066}', '\u{2069}', '\u{FEFF}',
    ];
    for ch in forbidden_chars {
        let bad = format!("hello{ch}world");
        assert!(
            validate_draft_text(&bad).is_err(),
            "forbidden char U+{:04X} must be rejected",
            ch as u32
        );
    }

    // Context length & BiDi enforcement on seal_human_draft
    let ok_ctx = HumanDraftPayloadV1 {
        v: 1,
        node_id: "prod@eu-1".to_string(),
        text: "Proceed".to_string(),
        context: Some("c".repeat(MAX_HUMAN_DRAFT_CONTEXT_CHARS)),
        created_at: format_rfc3339_millis(T0),
    };
    assert!(seal_human_draft(&ok_ctx, &human_enc.public_key()).is_ok());

    let over_ctx = HumanDraftPayloadV1 {
        context: Some("c".repeat(MAX_HUMAN_DRAFT_CONTEXT_CHARS + 1)),
        ..ok_ctx.clone()
    };
    assert!(seal_human_draft(&over_ctx, &human_enc.public_key()).is_err());

    let bidi_ctx = HumanDraftPayloadV1 {
        context: Some("ctx\u{200B}hidden".to_string()),
        ..ok_ctx
    };
    assert!(seal_human_draft(&bidi_ctx, &human_enc.public_key()).is_err());
}

#[test]
fn local_ingest_event_signature_roundtrip_and_tamper_rejection() {
    let signer = Ed25519KeyPair::from_seed([0x61; 32]).unwrap();
    let other = Ed25519KeyPair::from_seed([0x62; 32]).unwrap();

    let canonical_event = r#"{"data":{"text":"Run nightly check"},"datacontenttype":"application/json","id":"ev-local-1","source":"cron/nightly","specversion":"1.0","type":"to.hyphae.local.v1"}"#;

    let sig_attr = sign_local_ingest_event(&signer, canonical_event);
    assert!(sig_attr.starts_with(&format!("ed25519:{}:", signer.kid())));
    assert_eq!(sig_attr.len(), 8 + 43 + 1 + 86);

    // Valid verification returns verified kid
    let verified_kid = verify_local_ingest_event(&sig_attr, canonical_event, |kid| {
        assert_eq!(kid, signer.kid());
        Some(signer.public_key())
    })
    .unwrap();
    assert_eq!(verified_kid, signer.kid());

    // 1-bit flip in signature fails closed
    let parts: Vec<&str> = sig_attr.split(':').collect();
    let tampered_sig = format!("ed25519:{}:{}", parts[1], flip_b64_bit(parts[2], 0, 0x01));
    assert!(matches!(
        verify_local_ingest_event(&tampered_sig, canonical_event, |_| Some(
            signer.public_key()
        )),
        Err(CryptoError::InvalidSignature(_))
    ));

    // 1-byte mutation in canonical event JSON fails closed
    let tampered_event = canonical_event.replace("nightly", "nightlY");
    assert!(matches!(
        verify_local_ingest_event(&sig_attr, &tampered_event, |_| Some(signer.public_key())),
        Err(CryptoError::InvalidSignature(_))
    ));

    // Unknown / revoked key fails closed
    assert!(matches!(
        verify_local_ingest_event(&sig_attr, canonical_event, |_| None),
        Err(CryptoError::InvalidSignature(_))
    ));

    // Mismatched public key returned by lookup fails closed
    assert!(matches!(
        verify_local_ingest_event(&sig_attr, canonical_event, |_| Some(other.public_key())),
        Err(CryptoError::InvalidSignature(_))
    ));

    // Cross-domain attack: signature computed under HUMAN_CLAIM_DOMAIN instead of LOCAL_EVENT_SIG_DOMAIN fails closed!
    let mut wrong_domain_msg = Vec::new();
    wrong_domain_msg.extend_from_slice(HUMAN_CLAIM_DOMAIN);
    wrong_domain_msg.extend_from_slice(canonical_event.as_bytes());
    let wrong_domain_attr = format!(
        "ed25519:{}:{}",
        signer.kid(),
        URL_SAFE_NO_PAD.encode(signer.sign_raw(&wrong_domain_msg))
    );
    assert!(matches!(
        verify_local_ingest_event(&wrong_domain_attr, canonical_event, |_| Some(
            signer.public_key()
        )),
        Err(CryptoError::InvalidSignature(_))
    ));
    assert_eq!(LOCAL_EVENT_SIG_DOMAIN, b"hyphae/v2/local-event\n");

    // Malformed extension formats all fail closed
    for malformed in [
        "",
        "ed25519",
        "ed25519:onlytwo",
        "ed25519::sig",
        "ed25519:validkid:",
        "rsa:validkid:sig",
        "ed25519:bad kid:sig",
        &format!("{sig_attr}:extra"),
    ] {
        assert!(
            matches!(
                verify_local_ingest_event(malformed, canonical_event, |_| Some(
                    signer.public_key()
                )),
                Err(CryptoError::InvalidSignature(_))
            ),
            "malformed hyphaesig '{malformed}' must fail closed"
        );
    }
}
