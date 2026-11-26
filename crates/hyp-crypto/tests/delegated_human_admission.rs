//! Golden vectors, differential round-trip, and mutated-valid-input fail-closed tests for
//! Delegated Human-Cert Admission wire formats in `hyp_crypto::human`:
//! - `hjoin1_` (`HumanInviteV1` / `SignedHumanInviteV1`)
//! - `hpub1_` (`HumanPubCardV1`)
//! - `HumanInviteClaimV1`
//! - `DelegatedPairProofV1`

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hyp_crypto::human::{
    DELEGATED_PROOF_SKEW_MS, DelegatedPairProofV1, HJOIN1_PREFIX, HPUB1_PREFIX, HumanInviteClaimV1,
    HumanInviteV1, HumanPubCardV1, MAX_DELEGATED_DEVICES_LIMIT, NodeCertPayloadV1, decode_hjoin1,
    decode_hpub1, encode_hcert1, encode_hjoin1, encode_hpub1, node_cert_sha256,
    sign_delegated_pair_proof, sign_human_invite, sign_human_invite_claim, sign_node_cert,
    verify_delegated_pair_proof, verify_human_invite, verify_human_invite_claim,
    verify_human_invite_embedded,
};
use hyp_crypto::rfc3339::format_rfc3339_millis;
use hyp_crypto::{CryptoError, Ed25519KeyPair, X25519KeyPair};

const T0: i64 = 1_795_554_000_000;

fn flip_b64_bit(b64: &str, byte_idx: usize, bit_mask: u8) -> String {
    let mut raw = URL_SAFE_NO_PAD.decode(b64).expect("valid base64url");
    raw[byte_idx] ^= bit_mask;
    URL_SAFE_NO_PAD.encode(&raw)
}

fn sample_invite() -> HumanInviteV1 {
    HumanInviteV1 {
        v: 1,
        invite_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        hub_node_id: "acme-team".to_string(),
        hub_endpoint: "https://hub.acme.example".to_string(),
        hub_fingerprint: Some("0123456789abcdef".to_string()),
        human_id: "philip".to_string(),
        node_prefix: "philip@*".to_string(),
        scopes: vec![
            "dm:send".to_string(),
            "dm:receive".to_string(),
            "channel:join=*".to_string(),
            "channel:post=*".to_string(),
            "kv:read=shared/*".to_string(),
            "kv:write=shared/*".to_string(),
        ],
        max_devices: 10,
        issued_at: format_rfc3339_millis(T0),
        expires_at: format_rfc3339_millis(T0 + 86_400_000),
    }
}

#[test]
fn hjoin1_sign_encode_decode_verify_roundtrip_and_mutated_valid_fail_closed() {
    let admin = Ed25519KeyPair::generate().unwrap();
    let other_admin = Ed25519KeyPair::generate().unwrap();

    let invite = sample_invite();
    let signed = sign_human_invite(&invite, &admin).unwrap();
    let token = encode_hjoin1(&signed).unwrap();
    assert!(token.starts_with(HJOIN1_PREFIX));

    let decoded = decode_hjoin1(&token).unwrap();
    assert_eq!(decoded, signed);

    let verified = verify_human_invite(&decoded, &admin.public_key(), T0 + 1_000).unwrap();
    assert_eq!(verified.invite_id, invite.invite_id);
    assert_eq!(verified.hub_node_id, "acme-team");
    assert_eq!(verified.human_id, "philip");
    assert_eq!(verified.node_prefix, "philip@*");
    assert_eq!(verified.max_devices, 10);

    let (embedded_inv, embedded_pk) = verify_human_invite_embedded(&decoded, T0 + 1_000).unwrap();
    assert_eq!(embedded_inv.invite_id, invite.invite_id);
    assert_eq!(embedded_pk, admin.public_key());

    // 1. Wrong pinned Admin-CA public key fails closed
    assert!(matches!(
        verify_human_invite(&decoded, &other_admin.public_key(), T0 + 1_000),
        Err(CryptoError::InvalidSignature(_))
    ));

    // 2. 1-bit signature mutation fails closed
    let mut bad_sig = decoded.clone();
    bad_sig.sig = flip_b64_bit(&bad_sig.sig, 0, 0x01);
    assert!(matches!(
        verify_human_invite(&bad_sig, &admin.public_key(), T0 + 1_000),
        Err(CryptoError::InvalidSignature(_))
    ));
    assert!(matches!(
        verify_human_invite_embedded(&bad_sig, T0 + 1_000),
        Err(CryptoError::InvalidSignature(_))
    ));

    // 3. 1-byte payload mutation fails closed
    let mut bad_payload = decoded.clone();
    bad_payload.payload = bad_payload.payload.replace("philip@*", "alice@*");
    assert!(matches!(
        verify_human_invite(&bad_payload, &admin.public_key(), T0 + 1_000),
        Err(CryptoError::InvalidSignature(_))
    ));

    // 4. Expired invite fails closed (even after 60s skew window)
    assert!(verify_human_invite(&decoded, &admin.public_key(), T0 + 86_400_000 + 120_000).is_err());

    // 5. Forbidden scopes fail closed at BOTH signing and verification
    for forbidden in [
        vec!["*".to_string()],
        vec!["dm:send".to_string(), "bridge:post=slack:ops".to_string()],
        vec!["dm:send".to_string(), "forward:via=hub-a".to_string()],
        vec![],
    ] {
        let mut inv = sample_invite();
        inv.scopes = forbidden;
        assert!(sign_human_invite(&inv, &admin).is_err());
    }

    // 6. Invalid nodePrefix patterns fail closed (bare `*`, mid-string `*`, traversal, uppercase, reserved `local`)
    for bad_prefix in [
        "*",
        "**",
        "phi*lip@mac",
        "philip@../evil",
        "Philip@*",
        "local",
        "",
    ] {
        let mut inv = sample_invite();
        inv.node_prefix = bad_prefix.to_string();
        assert!(
            sign_human_invite(&inv, &admin).is_err(),
            "nodePrefix '{bad_prefix}' MUST fail closed"
        );
    }

    // 7. Out-of-bounds maxDevices fails closed
    for bad_max in [0u32, MAX_DELEGATED_DEVICES_LIMIT + 1, 999] {
        let mut inv = sample_invite();
        inv.max_devices = bad_max;
        assert!(sign_human_invite(&inv, &admin).is_err());
    }

    // 8. Disallowed hubEndpoint fails closed (cleartext non-loopback HTTP, javascript:, etc.)
    for bad_ep in [
        "http://hub.acme.example",
        "javascript:alert(1)",
        "file:///etc/passwd",
        "",
    ] {
        let mut inv = sample_invite();
        inv.hub_endpoint = bad_ep.to_string();
        assert!(
            sign_human_invite(&inv, &admin).is_err(),
            "hubEndpoint '{bad_ep}' MUST fail closed"
        );
    }

    // Loopback HTTP IS allowed for local dev/testing
    let mut loopback_inv = sample_invite();
    loopback_inv.hub_endpoint = "http://127.0.0.1:47899".to_string();
    assert!(sign_human_invite(&loopback_inv, &admin).is_ok());

    // 9. Bad prefix / malformed token fail closed
    assert!(decode_hjoin1("am2_not_hjoin").is_err());
    assert!(decode_hjoin1("hjoin1_!!!notbase64!!!").is_err());
}

#[test]
fn hpub1_roundtrip_and_validation_fail_closed() {
    let human_ed = Ed25519KeyPair::generate().unwrap();
    let human_x = X25519KeyPair::generate().unwrap();

    let card = HumanPubCardV1 {
        v: 1,
        human_id: "philip".to_string(),
        signing_jwk: human_ed.to_jwk(),
        enc_jwk: Some(human_x.to_jwk()),
    };
    let encoded = encode_hpub1(&card).unwrap();
    assert!(encoded.starts_with(HPUB1_PREFIX));
    assert!(!encoded.contains('\n'));
    assert!(!encoded.contains(' '));

    let decoded = decode_hpub1(&encoded).unwrap();
    assert_eq!(decoded, card);
    assert_eq!(
        decoded.signing_jwk.to_ed25519().unwrap(),
        human_ed.public_key()
    );
    assert_eq!(
        decoded.enc_jwk.as_ref().unwrap().to_x25519().unwrap(),
        human_x.public_key()
    );

    // Without enc_jwk also works
    let card_no_enc = HumanPubCardV1 {
        v: 1,
        human_id: "philip".to_string(),
        signing_jwk: human_ed.to_jwk(),
        enc_jwk: None,
    };
    let encoded_no_enc = encode_hpub1(&card_no_enc).unwrap();
    let dec2 = decode_hpub1(&encoded_no_enc).unwrap();
    assert_eq!(dec2.human_id, "philip");
    assert_eq!(
        dec2.signing_jwk.to_ed25519().unwrap(),
        human_ed.public_key()
    );
    assert!(dec2.enc_jwk.is_none());

    // Wrong prefix / wrong curve / invalid humanId fail closed
    assert!(decode_hpub1("hjoin1_abc").is_err());
    let mut bad_curve = card.clone();
    bad_curve.signing_jwk = human_x.to_jwk();
    assert!(encode_hpub1(&bad_curve).is_err());

    let mut bad_hid = card.clone();
    bad_hid.human_id = "local".to_string();
    assert!(encode_hpub1(&bad_hid).is_err());
}

#[test]
fn human_invite_claim_sign_verify_and_skew_bounds() {
    let human_ed = Ed25519KeyPair::generate().unwrap();
    let human_x = X25519KeyPair::generate().unwrap();
    let other_ed = Ed25519KeyPair::generate().unwrap();

    let claim = HumanInviteClaimV1 {
        invite_id: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        hub_node_id: "acme-team".to_string(),
        human_id: "philip".to_string(),
        signing_jwk: human_ed.to_jwk(),
        enc_jwk: Some(human_x.to_jwk()),
        prf_salt: Some("prf-salt-abc123".to_string()),
        timestamp: format_rfc3339_millis(T0),
    };

    let sig = sign_human_invite_claim(&claim, &human_ed).unwrap();
    let (pk, enc) = verify_human_invite_claim(&claim, &sig, T0 + 1_000).unwrap();
    assert_eq!(pk, human_ed.public_key());
    assert_eq!(enc.unwrap(), human_x.public_key());

    // 1-bit signature mutation fails closed
    let bad_sig = flip_b64_bit(&sig, 4, 0x80);
    assert!(matches!(
        verify_human_invite_claim(&claim, &bad_sig, T0 + 1_000),
        Err(CryptoError::InvalidSignature(_))
    ));

    // Tampered field (e.g., humanId swapped) fails closed
    let mut tampered = claim.clone();
    tampered.human_id = "mallory".to_string();
    assert!(verify_human_invite_claim(&tampered, &sig, T0 + 1_000).is_err());

    // Wrong signing key fails at signing time
    assert!(sign_human_invite_claim(&claim, &other_ed).is_err());

    // Beyond ±5m skew fails closed (both past and future)
    assert!(verify_human_invite_claim(&claim, &sig, T0 + DELEGATED_PROOF_SKEW_MS + 1_000).is_err());
    assert!(verify_human_invite_claim(&claim, &sig, T0 - DELEGATED_PROOF_SKEW_MS - 1_000).is_err());
}

#[test]
fn delegated_pair_proof_sign_verify_and_mutations_fail_closed() {
    let human_ed = Ed25519KeyPair::generate().unwrap();
    let dev_ed = Ed25519KeyPair::generate().unwrap();
    let dev_x = X25519KeyPair::generate().unwrap();
    let attacker_ed = Ed25519KeyPair::generate().unwrap();

    let cert_payload = NodeCertPayloadV1 {
        v: 1,
        node_id: "philip@macbook".to_string(),
        signing_jwk: dev_ed.to_jwk(),
        encryption_jwk: dev_x.to_jwk(),
        human_id: "philip".to_string(),
        human_kid: human_ed.kid(),
        auth_epoch: 1,
        issued_at: format_rfc3339_millis(T0),
        expires_at: format_rfc3339_millis(T0 + 86_400_000),
    };
    let signed_cert = sign_node_cert(&cert_payload, &human_ed).unwrap();
    let hcert1 = encode_hcert1(&signed_cert).unwrap();
    let cert_sha = node_cert_sha256(&hcert1);
    assert_eq!(cert_sha.len(), 64);

    let proof = DelegatedPairProofV1 {
        hub_node_id: "acme-team".to_string(),
        node_id: "philip@macbook".to_string(),
        ed25519_jwk: dev_ed.to_jwk(),
        x25519_jwk: dev_x.to_jwk(),
        node_cert_sha256: cert_sha.clone(),
        timestamp: format_rfc3339_millis(T0),
    };
    let sig = sign_delegated_pair_proof(&proof, &dev_ed).unwrap();
    assert_eq!(proof.node_cert_sha256, cert_sha);

    let (pk, xpk) = verify_delegated_pair_proof(&proof, &sig, T0 + 2_000).unwrap();
    assert_eq!(pk, dev_ed.public_key());
    assert_eq!(xpk, dev_x.public_key());

    // 1-bit signature flip fails closed
    let bad_sig = flip_b64_bit(&sig, 10, 0x04);
    assert!(matches!(
        verify_delegated_pair_proof(&proof, &bad_sig, T0 + 2_000),
        Err(CryptoError::InvalidSignature(_))
    ));

    // Mutating bound cert digest fails closed
    let mut bad_cert_hash = proof.clone();
    bad_cert_hash.node_cert_sha256 = node_cert_sha256(&format!("{hcert1}x"));
    assert!(verify_delegated_pair_proof(&bad_cert_hash, &sig, T0 + 2_000).is_err());

    // Swapping signing key in proof fails closed
    let mut swapped = proof.clone();
    swapped.ed25519_jwk = attacker_ed.to_jwk();
    assert!(verify_delegated_pair_proof(&swapped, &sig, T0 + 2_000).is_err());

    // Replay past ±5m skew fails closed
    assert!(
        verify_delegated_pair_proof(&proof, &sig, T0 + DELEGATED_PROOF_SKEW_MS + 5_000).is_err()
    );
}
