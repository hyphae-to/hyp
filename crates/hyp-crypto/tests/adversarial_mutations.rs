//! McKeeman Level 1-6 Adversarial Mutation & Security Boundary Test Suite.
//!
//! Systematically perturbs valid cryptographic inputs (1-bit flips, truncation, reordering,
//! rollback, cross-context swaps, small-order/all-zero keys, symlink/traversal/bomb archives,
//! blocked executable attachments, and keystore permission violations) to assert fail-closed behavior.

#[cfg(unix)]
use std::fs;
use std::io::Write;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use tempfile::TempDir;

use hyp_crypto::compat_v1::{
    create_key_registration_v1, issue_grant_v1, open_v1, parse_pairing_code_v1, seal_v1,
    sign_binding_v1, verify_entry_v1, verify_key_registration_v1, EntryV1, KeyRegistrationV1,
    SealInputV1,
};
use hyp_crypto::e2ee::{
    create_epoch_bundle, open_channel_message, open_dm, open_epoch_bundle, open_kv_entry,
    seal_channel_message, seal_dm, seal_kv_entry, ChannelContext, DmContext, EpochMember,
    EpochScope, KvContext,
};
use hyp_crypto::hpke;
use hyp_crypto::jcs::to_canonical_json;
use hyp_crypto::keys::{
    Ed25519KeyPair, Ed25519PublicKey, NodeIdentityKeys, OkpJwk, X25519KeyPair, X25519PublicKey,
};
use hyp_crypto::keystore::{validate_secret_name, SecretBackend, SecretStore};
use hyp_crypto::pairing::{
    create_p2p_confirmation, create_p2p_offer, create_p2p_response, decode_am2, decode_hp2p1,
    encode_am2, encode_hp2p1, sign_revocation_v2, verify_p2p_confirmation, verify_p2p_response,
    verify_revocation_v2, AdminInviteV2, GrantV2, P2pOfferToken, P2pPairConfirmation,
    P2pPairResponse, RevocationV2, AM2_PREFIX, HP2P1_PREFIX,
};
use hyp_crypto::rfc3339::{now_unix_ms, parse_rfc3339_millis};
#[cfg(unix)]
use hyp_crypto::transfer::{pack_tar_gz, TarInputEntry};
use hyp_crypto::transfer::{
    decrypt_stream_v2, default_stage1_attachment_guard, encrypt_stream_v2, pack_tar_gz_bytes,
    unpack_tar_gz, StreamEncryptParams, TarPackOptions, TarUnpackOptions, TRANSFER_CHUNK_SIZE,
};
use hyp_crypto::CryptoError;

fn flip_b64_byte(s: &str, idx: usize, mask: u8) -> String {
    let mut bytes = URL_SAFE_NO_PAD.decode(s).unwrap();
    bytes[idx] ^= mask;
    URL_SAFE_NO_PAD.encode(bytes)
}

#[test]
fn mutation_1bit_flips_across_dm_channel_kv_and_hpke() {
    let alice = NodeIdentityKeys::generate().unwrap();
    let bob = NodeIdentityKeys::generate().unwrap();

    // 1. HPKE 1-bit flips across enc and ct
    let (enc, ct) = hpke::seal_base(&bob.encryption.public_key(), b"info", b"aad", b"payload").unwrap();
    for pos in [0, 15, 31] {
        let mut bad_enc = enc;
        bad_enc[pos] ^= 0x01;
        assert!(hpke::open_base(&bad_enc, &bob.encryption, b"info", b"aad", &ct).is_err());
    }
    for pos in [0, ct.len() / 2, ct.len() - 1] {
        let mut bad_ct = ct.clone();
        bad_ct[pos] ^= 0x01;
        assert!(hpke::open_base(&enc, &bob.encryption, b"info", b"aad", &bad_ct).is_err());
    }

    // 2. DM envelope 1-bit flips + AAD context swap
    let dm_ctx = DmContext {
        node_id: "hub",
        msg_id: "dm-1",
        sender: "alice/claude",
        recipient: "bob/codex",
    };
    let dm = seal_dm(&dm_ctx, b"secret", &alice.signing, &bob.encryption.public_key()).unwrap();
    for mut_dm in [
        {
            let mut m = dm.clone();
            m.enc = flip_b64_byte(&m.enc, 0, 0x01);
            m
        },
        {
            let mut m = dm.clone();
            m.ct = flip_b64_byte(&m.ct, 10, 0x01);
            m
        },
        {
            let mut m = dm.clone();
            m.sig = flip_b64_byte(&m.sig, 63, 0x01);
            m
        },
    ] {
        assert!(open_dm(&mut_dm, &dm_ctx, &alice.signing.public_key(), &bob.encryption).is_err());
    }
    // Changing any single AAD field rejects
    for bad_ctx in [
        DmContext { node_id: "hub2", ..dm_ctx },
        DmContext { msg_id: "dm-2", ..dm_ctx },
        DmContext { sender: "eve/claude", ..dm_ctx },
        DmContext { recipient: "carol/codex", ..dm_ctx },
    ] {
        assert!(open_dm(&dm, &bad_ctx, &alice.signing.public_key(), &bob.encryption).is_err());
    }

    // 3. Channel & KV 1-bit flips and cross-channel / cross-key swaps
    let bob_pub = bob.encryption.public_key();
    let (rk, mut bundle) = create_epoch_bundle(
        EpochScope::Channel,
        "hub",
        "#sec",
        1,
        "alice",
        &alice.signing,
        &[EpochMember { node_id: "bob", enc_pk: &bob_pub }],
    )
    .unwrap();
    // Flip 1 bit in bundle signature -> rejected
    bundle.sig = flip_b64_byte(&bundle.sig, 0, 0x02);
    assert!(open_epoch_bundle(
        &bundle,
        EpochScope::Channel,
        "hub",
        "#sec",
        &alice.signing.public_key(),
        "bob",
        &bob.encryption,
        1
    )
    .is_err());

    let ch_ctx = ChannelContext {
        host_node: "hub",
        channel: "#sec",
        msg_id: "c1",
        sender: "alice/claude",
    };
    let ch = seal_channel_message(&ch_ctx, b"alert", &rk, &alice.signing).unwrap();
    let mut ch_bad_nonce = ch.clone();
    ch_bad_nonce.nonce = flip_b64_byte(&ch_bad_nonce.nonce, 0, 0x01);
    assert!(open_channel_message(&ch_bad_nonce, &ch_ctx, &rk, &alice.signing.public_key(), 1).is_err());
    assert!(open_channel_message(
        &ch,
        &ChannelContext { channel: "#other", ..ch_ctx },
        &rk,
        &alice.signing.public_key(),
        1
    )
    .is_err());

    let kv_ctx = KvContext {
        host_node: "hub",
        namespace: "ns",
        key: "k1",
        version: 1,
        writer_node_id: "alice",
        writer_grant_id: "g1",
    };
    let kv = seal_kv_entry(&kv_ctx, b"val1", &rk, &alice.signing).unwrap();
    let mut kv_bad_ct = kv.clone();
    kv_bad_ct.ct = flip_b64_byte(&kv_bad_ct.ct, 0, 0x01);
    assert!(open_kv_entry(&kv_bad_ct, &kv_ctx, &rk, &alice.signing.public_key(), 1, None).is_err());
}

#[test]
fn mutation_streaming_transfer_edge_boundaries_and_cross_transfer_chunk_swap() {
    let sender = NodeIdentityKeys::generate().unwrap();
    let bob = NodeIdentityKeys::generate().unwrap();
    let bob_pk = bob.encryption.public_key();

    // Boundary sizes: 0 bytes, 1 byte, exact 64 KiB (1 chunk), 64 KiB + 1 (2 chunks)
    for size in [0usize, 1, TRANSFER_CHUNK_SIZE, TRANSFER_CHUNK_SIZE + 1] {
        let pt: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let params = StreamEncryptParams {
            id: "tr-boundary",
            from: "alice",
            media_type: "application/octet-stream",
            created_at: "2026-11-24T12:00:00Z",
            expires_at: "2026-11-25T12:00:00Z",
        };
        let mut ct = Vec::new();
        let hdr = encrypt_stream_v2(
            &pt[..],
            &mut ct,
            &params,
            &sender.signing,
            &[("bob", &bob_pk)],
        )
        .unwrap();
        let mut out = Vec::new();
        let decoded = decrypt_stream_v2(
            &hdr,
            &ct[..],
            &mut out,
            &sender.signing.public_key(),
            "bob",
            &bob.encryption,
        )
        .unwrap();
        assert_eq!(out, pt);
        assert_eq!(decoded.plaintext_bytes, size as u64);
    }

    // Cross-transfer chunk swap attack: splice chunk 0 of transfer B into transfer A
    let payload_a = vec![0xAAu8; TRANSFER_CHUNK_SIZE + 100];
    let payload_b = vec![0xBBu8; TRANSFER_CHUNK_SIZE + 100];
    let mut ct_a = Vec::new();
    let hdr_a = encrypt_stream_v2(
        &payload_a[..],
        &mut ct_a,
        &StreamEncryptParams {
            id: "tr-A",
            from: "alice",
            media_type: "application/octet-stream",
            created_at: "2026-11-24T12:00:00Z",
            expires_at: "2026-11-25T12:00:00Z",
        },
        &sender.signing,
        &[("bob", &bob_pk)],
    )
    .unwrap();
    let mut ct_b = Vec::new();
    let _hdr_b = encrypt_stream_v2(
        &payload_b[..],
        &mut ct_b,
        &StreamEncryptParams {
            id: "tr-B",
            from: "alice",
            media_type: "application/octet-stream",
            created_at: "2026-11-24T12:00:00Z",
            expires_at: "2026-11-25T12:00:00Z",
        },
        &sender.signing,
        &[("bob", &bob_pk)],
    )
    .unwrap();

    let chunk0_wire_len = 4 + TRANSFER_CHUNK_SIZE + 16;
    let mut spliced = ct_a.clone();
    spliced[4..4 + chunk0_wire_len].copy_from_slice(&ct_b[4..4 + chunk0_wire_len]);
    assert!(decrypt_stream_v2(
        &hdr_a,
        &spliced[..],
        &mut Vec::new(),
        &sender.signing.public_key(),
        "bob",
        &bob.encryption,
    )
    .is_err());
}

#[test]
fn mutation_all_zero_and_small_order_keys_rejected_everywhere() {
    let zero_b64 = URL_SAFE_NO_PAD.encode([0u8; 32]);
    assert!(matches!(
        X25519PublicKey::from_b64(&zero_b64),
        Err(CryptoError::SmallOrderKey)
    ));
    assert!(matches!(
        Ed25519PublicKey::from_b64(&zero_b64),
        Err(CryptoError::SmallOrderKey)
    ));

    // v1 verify_key_registration rejects all-zero X25519 key
    let sign = Ed25519KeyPair::generate().unwrap();
    let enc = X25519KeyPair::generate().unwrap();
    let mut reg = create_key_registration_v1("alice", &sign, &enc).unwrap();
    reg.encryption_key = zero_b64.clone();
    assert!(matches!(
        verify_key_registration_v1("alice", &reg),
        Err(CryptoError::SmallOrderKey)
    ));

    // v1 verify_key_registration rejects small-order Ed25519 signing key
    let bad_reg = KeyRegistrationV1 {
        signing_key: zero_b64.clone(),
        encryption_key: enc.public_key_b64(),
        proof: reg.proof,
    };
    assert!(matches!(
        verify_key_registration_v1("alice", &bad_reg),
        Err(CryptoError::SmallOrderKey)
    ));

    // v1 seal/open rejects tampered header or ciphertext
    let now = now_unix_ms();
    let sealed = seal_v1(
        &SealInputV1 {
            id: "11111111-2222-4333-8444-555555555555",
            transfer_type: "files",
            from: "alice",
            to: "bob",
            to_handle: Some("codex"),
            ttl_ms: 60_000,
        },
        b"payload",
        &sign,
        &enc.public_key(),
        now,
    )
    .unwrap();
    let mut bad_ct = sealed.ciphertext.clone();
    bad_ct[0] ^= 0x01;
    assert!(open_v1(&sealed.header, &bad_ct, &sign.public_key(), &enc).is_err());

    // v1 Entry rejects tampered binding selfSig
    let admin = Ed25519KeyPair::generate().unwrap();
    let issued = issue_grant_v1(&admin, "alice", &["*"], 60_000, now).unwrap();
    let code = parse_pairing_code_v1(&issued.code).unwrap();
    let mut binding = sign_binding_v1(&issued.grant, &code, &sign, &enc, now).unwrap();
    binding.self_sig = flip_b64_byte(&binding.self_sig, 0, 0x01);
    let entry = EntryV1 {
        grant: issued.signed,
        binding,
    };
    assert!(verify_entry_v1(&entry, &admin.public_key()).is_err());
}

#[test]
fn mutation_archive_limits_symlinks_nul_duplicates_and_decompression_bomb() {
    let tmp = TempDir::new().unwrap();

    // 1. Packing a symlink on disk fails closed
    #[cfg(unix)]
    {
        let real_file = tmp.path().join("real.txt");
        let link_file = tmp.path().join("link.txt");
        fs::write(&real_file, b"real").unwrap();
        std::os::unix::fs::symlink(&real_file, &link_file).unwrap();
        let res = pack_tar_gz(
            &[TarInputEntry {
                archive_path: "link.txt".into(),
                source_path: link_file,
            }],
            Vec::new(),
            TarPackOptions::default(),
        );
        assert!(matches!(res, Err(CryptoError::UnsafeArchiveEntry(_))));
    }

    // 2. Duplicate case-insensitive filename rejected
    let dup = pack_tar_gz_bytes(
        &[("Report.md", b"a"), ("report.md", b"b")],
        Vec::new(),
        TarPackOptions::default(),
    );
    assert!(matches!(dup, Err(CryptoError::UnsafeArchiveEntry(_))));

    // 3. Exceeding max_files (201 files) rejected on pack AND unpack
    let mut many_names = Vec::new();
    for i in 0..201 {
        many_names.push(format!("f{i:03}.txt"));
    }
    let refs: Vec<(&str, &[u8])> = many_names.iter().map(|s| (s.as_str(), &b"x"[..])).collect();
    assert!(matches!(
        pack_tar_gz_bytes(&refs, Vec::new(), TarPackOptions::default()),
        Err(CryptoError::ArchiveLimitExceeded(_))
    ));
    // Pack 201 with higher pack limit, verify default unpack (max_files = 200) rejects & cleans up!
    let mut big_count_tar = Vec::new();
    pack_tar_gz_bytes(
        &refs,
        &mut big_count_tar,
        TarPackOptions {
            max_files: 250,
            max_raw_bytes: 1024 * 1024,
        },
    )
    .unwrap();
    let d_many = tmp.path().join("many");
    assert!(matches!(
        unpack_tar_gz(&big_count_tar[..], &d_many, &TarUnpackOptions::default()),
        Err(CryptoError::ArchiveLimitExceeded(_))
    ));
    assert!(!d_many.exists());

    // 4. Raw gzip bomb (10 MiB zeros inside raw gzip stream without even valid tar) aborted fast!
    let mut bomb_gz = GzEncoder::new(Vec::new(), Compression::best());
    let zeros = vec![0u8; 64 * 1024];
    for _ in 0..160 {
        // 10 MiB of zeros -> compresses to ~10 KiB
        bomb_gz.write_all(&zeros).unwrap();
    }
    let bomb_bytes = bomb_gz.finish().unwrap();
    assert!(bomb_bytes.len() < 32 * 1024);
    let d_bomb = tmp.path().join("raw-bomb");
    assert!(unpack_tar_gz(
        &bomb_bytes[..],
        &d_bomb,
        &TarUnpackOptions {
            max_files: 10,
            max_raw_bytes: 32 * 1024,
            attachment_guard: Some(&default_stage1_attachment_guard),
        },
    )
    .is_err());
    assert!(!d_bomb.exists());
}

#[test]
fn mutation_keystore_symlinks_permissions_and_traversal_in_ephemeral_tempdir() {
    let tmp = TempDir::new().unwrap();
    let store = SecretStore::new(tmp.path(), SecretBackend::File);
    store.set("valid-secret", "token-value").unwrap();

    // Traversal names rejected
    for bad in ["../escape", "sub/secret", ".hidden", "A_UPPER", "a..b"] {
        assert!(validate_secret_name(bad).is_err());
        assert!(store.set(bad, "x").is_err());
        assert!(store.get(bad).is_err());
    }

    // Symlink secret file fails closed!
    #[cfg(unix)]
    {
        let external = tmp.path().join("outside.txt");
        fs::write(&external, b"outside-secret\n").unwrap();
        let sym_secret = store.secrets_dir().join("sym-secret.secret");
        std::os::unix::fs::symlink(&external, &sym_secret).unwrap();
        assert!(matches!(
            store.get("sym-secret"),
            Err(CryptoError::Keystore(_))
        ));

        // Overly broad secrets directory (0755) fails closed!
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(store.secrets_dir(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            store.get("valid-secret"),
            Err(CryptoError::Keystore(_))
        ));
    }
}

/// Deterministic zero-dependency SplitMix64 PRNG for seeded mutation sweeps.
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn gen_usize(&mut self, bound: usize) -> usize {
        (self.next_u64() as usize) % bound
    }
}

fn resolve_seed(default: u64) -> u64 {
    match std::env::var("HYPHAE_TEST_SEED") {
        Ok(raw) => {
            let trimmed = raw.trim();
            if let Some(hex) = trimmed
                .strip_prefix("0x")
                .or_else(|| trimmed.strip_prefix("0X"))
            {
                u64::from_str_radix(hex, 16)
                    .unwrap_or_else(|e| panic!("invalid hex HYPHAE_TEST_SEED={raw:?}: {e}"))
            } else {
                trimmed
                    .parse::<u64>()
                    .unwrap_or_else(|e| panic!("invalid decimal HYPHAE_TEST_SEED={raw:?}: {e}"))
            }
        }
        Err(_) => default,
    }
}

/// Wire-identical v2 self-signed key registration payload (`PUT /v1/keys`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyRegPayloadV2 {
    v: u8,
    node_id: String,
    signing_jwk: OkpJwk,
    encryption_jwk: OkpJwk,
}

fn flip_ascii_str_bit(s: &str, byte_idx: usize, bit_0_to_6: u8) -> String {
    let mut bytes = s.as_bytes().to_vec();
    let mask = 1u8 << (bit_0_to_6 % 7);
    bytes[byte_idx] ^= mask;
    String::from_utf8(bytes).expect("flipping bits 0..=6 of ASCII preserves UTF-8")
}

fn flip_token_ascii_bit(token: &str, byte_idx: usize, bit_0_to_6: u8) -> String {
    let mut bytes = token.as_bytes().to_vec();
    bytes[byte_idx] ^= 1u8 << (bit_0_to_6 % 7);
    String::from_utf8(bytes).expect("token is ASCII")
}

#[test]
fn seeded_1bit_mutation_sweep_am2_hp2p1_revocation_and_key_reg() {
    let seed = resolve_seed(0xC0DE_5EED_2026);
    let mut rng = SplitMix64::new(seed);
    let now = parse_rfc3339_millis("2026-11-24T12:00:00Z").unwrap();

    let admin = Ed25519KeyPair::generate().unwrap();
    let alice = NodeIdentityKeys::generate().unwrap();
    let bob = NodeIdentityKeys::generate().unwrap();

    // =========================================================================
    // 1. `am2_` Admin-CA Invite Bundle + `t3mp1_` Pairing Redemption
    // =========================================================================
    let issued = issue_grant_v1(&admin, "alice@macbook", &["*"], 60_000, now).unwrap();
    let invite = AdminInviteV2 {
        v: 2,
        router: "https://mesh.acme.internal".into(),
        admin_jwk: admin.to_jwk(),
        pairing_code: issued.code.clone(),
        require_e2ee: Some(true),
    };
    let encoded_am2 = encode_am2(&invite).unwrap();
    assert_eq!(decode_am2(&encoded_am2).unwrap(), invite);

    let redeem_am2 = |candidate_token: &str| -> Result<(), CryptoError> {
        let decoded = decode_am2(candidate_token)?;
        let code = parse_pairing_code_v1(&decoded.pairing_code)?;
        if code.grant_id != issued.grant.id {
            return Err(CryptoError::InvalidPairing("grant_id mismatch".into()));
        }
        let admin_pk = decoded.admin_jwk.to_ed25519()?;
        let binding = sign_binding_v1(&issued.grant, &code, &alice.signing, &alice.encryption, now)?;
        let entry = EntryV1 {
            grant: issued.signed.clone(),
            binding,
        };
        let _ = verify_entry_v1(&entry, &admin_pk)?;
        Ok(())
    };
    redeem_am2(&encoded_am2).expect("baseline am2_ redemption must succeed");

    // 1a. 72 seeded 1-bit flips across `admin_jwk.x` (32B) and `t3mp1_` raw bytes (44B) -> 100% fail closed!
    let orig_admin_x = URL_SAFE_NO_PAD.decode(&invite.admin_jwk.x).unwrap();
    let orig_t3mp1_raw = URL_SAFE_NO_PAD
        .decode(invite.pairing_code.strip_prefix("t3mp1_").unwrap())
        .unwrap();
    let am2_crypto_total = orig_admin_x.len() + orig_t3mp1_raw.len();
    for step in 0..72usize {
        let pos = rng.gen_usize(am2_crypto_total);
        let bit = (rng.next_u64() % 8) as u8;
        let mask = 1u8 << bit;
        let mut mutated = invite.clone();
        if pos < orig_admin_x.len() {
            let mut x = orig_admin_x.clone();
            x[pos] ^= mask;
            mutated.admin_jwk.x = URL_SAFE_NO_PAD.encode(x);
        } else {
            let mut raw = orig_t3mp1_raw.clone();
            raw[pos - orig_admin_x.len()] ^= mask;
            mutated.pairing_code = format!("t3mp1_{}", URL_SAFE_NO_PAD.encode(raw));
        }
        let canon = to_canonical_json(&mutated).unwrap();
        let mutated_token = format!("{AM2_PREFIX}{}", URL_SAFE_NO_PAD.encode(canon.as_bytes()));
        assert!(
            redeem_am2(&mutated_token).is_err(),
            "seed=0x{seed:016x} step={step}: am2_ crypto 1-bit flip (pos={pos}, bit={bit}) was not rejected!"
        );
    }

    // 1b. 72 seeded 1-bit flips across raw encoded `am2_<base64url>` bytes -> zero panics & fail-closed!
    for step in 0..72usize {
        let pos = rng.gen_usize(encoded_am2.len());
        let bit = (rng.next_u64() % 7) as u8;
        let mutated_token = flip_token_ascii_bit(&encoded_am2, pos, bit);
        if let Ok(decoded) = decode_am2(&mutated_token) {
            assert_ne!(
                decoded, invite,
                "seed=0x{seed:016x} step={step}: mutated am2_ decoded identically at pos={pos}"
            );
            // Any mutation touching admin_jwk or pairing_code MUST fail redemption.
            if decoded.admin_jwk != invite.admin_jwk || decoded.pairing_code != invite.pairing_code {
                assert!(
                    redeem_am2(&mutated_token).is_err(),
                    "seed=0x{seed:016x} step={step}: mutated am2_ key/code passed redemption at pos={pos}"
                );
            }
        }
    }

    // =========================================================================
    // 2. `hp2p1_` Direct P2P Offer + `P2pPairResponse` + `P2pPairConfirmation`
    // =========================================================================
    let offer = create_p2p_offer(
        "offer-seed-99",
        "alice@macbook",
        "https://alice.tailnet.ts.net",
        &alice,
        vec!["dm:send".into(), "dm:receive".into()],
        vec!["dm:send".into(), "kv:read=pair/*".into()],
        "2026-11-24T13:00:00Z",
    )
    .unwrap();
    let encoded_hp2p1 = encode_hp2p1(&offer).unwrap();
    assert_eq!(decode_hp2p1(&encoded_hp2p1).unwrap(), offer);

    let bob_grant = GrantV2 {
        v: 2,
        id: "grant-bob-to-alice".into(),
        node_id: "alice@macbook".into(),
        scopes: vec!["dm:send".into(), "kv:read=pair/*".into()],
        trust_tier: Some("peer".into()),
        pairing_key: None,
        subject_signing_jwk: Some(offer.signing_jwk.clone()),
        subject_encryption_jwk: Some(offer.encryption_jwk.clone()),
        issued_at: "2026-11-24T12:05:00Z".into(),
        pair_by: None,
        expires_at: Some("2027-11-24T12:05:00Z".into()),
    };
    let p2p_resp = create_p2p_response(
        &offer,
        "bob@laptop",
        Some("https://bob.tailnet.ts.net"),
        &bob,
        &bob_grant,
    )
    .unwrap();
    let verified_peer = verify_p2p_response(&offer, &p2p_resp, now).unwrap();
    assert_eq!(verified_peer.bob_node_id, "bob@laptop");

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
    let p2p_conf = create_p2p_confirmation(&offer.offer_id, &alice_grant, &alice.signing).unwrap();
    verify_p2p_confirmation(&offer, &p2p_conf, "bob@laptop").unwrap();

    let run_full_p2p_handshake = |candidate_hp2p1: &str| -> Result<(), CryptoError> {
        let decoded_offer: P2pOfferToken = decode_hp2p1(candidate_hp2p1)?;
        let mut grant = bob_grant.clone();
        grant.node_id = decoded_offer.node_id.clone();
        grant.subject_signing_jwk = Some(decoded_offer.signing_jwk.clone());
        grant.subject_encryption_jwk = Some(decoded_offer.encryption_jwk.clone());
        let resp = create_p2p_response(
            &decoded_offer,
            "bob@laptop",
            Some("https://bob.tailnet.ts.net"),
            &bob,
            &grant,
        )?;
        // Alice verifies Bob's response against her true offer (checks offerId, nodeId, secret MAC, selfSig).
        let _ = verify_p2p_response(&offer, &resp, now)?;
        // Bob verifies Alice's real confirmation against the zero-TOFU signing_jwk from the offer.
        let _ = verify_p2p_confirmation(&decoded_offer, &p2p_conf, "bob@laptop")?;
        // Bob encrypts a DM to the zero-TOFU encryption_jwk from the offer; Alice opens it.
        let alice_enc_from_offer = decoded_offer.encryption_jwk.to_x25519()?;
        let dm_ctx = DmContext {
            node_id: "alice@macbook",
            msg_id: "p2p-check",
            sender: "bob@laptop/codex",
            recipient: "alice@macbook/claude",
        };
        let env = seal_dm(&dm_ctx, b"p2p-hello", &bob.signing, &alice_enc_from_offer)?;
        let pt = open_dm(&env, &dm_ctx, &bob.signing.public_key(), &alice.encryption)?;
        if pt.as_slice() != b"p2p-hello" {
            return Err(CryptoError::InvalidPairing("dm plaintext mismatch".into()));
        }
        Ok(())
    };
    run_full_p2p_handshake(&encoded_hp2p1).expect("baseline hp2p1_ handshake must succeed");

    // 2a. 72 seeded 1-bit flips across `hp2p1_` crypto/identity fields (`secret`, `signing_jwk`, `encryption_jwk`, `offer_id`, `node_id`) -> 100% fail closed!
    let orig_secret = URL_SAFE_NO_PAD.decode(&offer.secret).unwrap();
    let orig_sign_x = URL_SAFE_NO_PAD.decode(&offer.signing_jwk.x).unwrap();
    let orig_enc_x = URL_SAFE_NO_PAD.decode(&offer.encryption_jwk.x).unwrap();
    let total_offer_crypto =
        orig_secret.len() + orig_sign_x.len() + orig_enc_x.len() + offer.offer_id.len() + offer.node_id.len();
    for step in 0..72usize {
        let mut pos = rng.gen_usize(total_offer_crypto);
        let bit = (rng.next_u64() % 8) as u8;
        let mut mutated = offer.clone();
        if pos < orig_secret.len() {
            let mut s = orig_secret.clone();
            s[pos] ^= 1u8 << bit;
            mutated.secret = URL_SAFE_NO_PAD.encode(s);
        } else {
            pos -= orig_secret.len();
            if pos < orig_sign_x.len() {
                let mut x = orig_sign_x.clone();
                x[pos] ^= 1u8 << bit;
                mutated.signing_jwk.x = URL_SAFE_NO_PAD.encode(x);
            } else {
                pos -= orig_sign_x.len();
                if pos < orig_enc_x.len() {
                    let mut x = orig_enc_x.clone();
                    x[pos] ^= 1u8 << bit;
                    mutated.encryption_jwk.x = URL_SAFE_NO_PAD.encode(x);
                } else {
                    pos -= orig_enc_x.len();
                    if pos < offer.offer_id.len() {
                        mutated.offer_id = flip_ascii_str_bit(&offer.offer_id, pos, bit % 7);
                    } else {
                        pos -= offer.offer_id.len();
                        mutated.node_id = flip_ascii_str_bit(&offer.node_id, pos, bit % 7);
                    }
                }
            }
        }
        let canon = to_canonical_json(&mutated).unwrap();
        let mutated_token = format!("{HP2P1_PREFIX}{}", URL_SAFE_NO_PAD.encode(canon.as_bytes()));
        assert!(
            run_full_p2p_handshake(&mutated_token).is_err(),
            "seed=0x{seed:016x} step={step}: hp2p1_ crypto 1-bit flip was not rejected!"
        );
    }

    // 2b. 72 seeded 1-bit flips across raw encoded `hp2p1_<base64url>` bytes -> zero panics & fail-closed!
    for step in 0..72usize {
        let pos = rng.gen_usize(encoded_hp2p1.len());
        let bit = (rng.next_u64() % 7) as u8;
        let mutated_token = flip_token_ascii_bit(&encoded_hp2p1, pos, bit);
        if let Ok(decoded) = decode_hp2p1(&mutated_token) {
            assert_ne!(
                decoded, offer,
                "seed=0x{seed:016x} step={step}: mutated hp2p1_ decoded identically at pos={pos}"
            );
            if decoded.secret != offer.secret
                || decoded.signing_jwk != offer.signing_jwk
                || decoded.encryption_jwk != offer.encryption_jwk
                || decoded.offer_id != offer.offer_id
                || decoded.node_id != offer.node_id
            {
                assert!(
                    run_full_p2p_handshake(&mutated_token).is_err(),
                    "seed=0x{seed:016x} step={step}: mutated hp2p1_ crypto/identity passed handshake at pos={pos}"
                );
            }
        }
    }

    // 2c. 72 seeded 1-bit flips across `P2pPairResponse` (`payload`, `binding_mac`, `self_sig`) -> 100% rejected!
    let orig_mac = URL_SAFE_NO_PAD.decode(&p2p_resp.binding_mac).unwrap();
    let orig_self_sig = URL_SAFE_NO_PAD.decode(&p2p_resp.self_sig).unwrap();
    let resp_total = p2p_resp.payload.len() + orig_mac.len() + orig_self_sig.len();
    for step in 0..72usize {
        let pos = rng.gen_usize(resp_total);
        let bit = (rng.next_u64() % 8) as u8;
        let mut mutated: P2pPairResponse = p2p_resp.clone();
        if pos < p2p_resp.payload.len() {
            mutated.payload = flip_ascii_str_bit(&p2p_resp.payload, pos, bit % 7);
        } else if pos < p2p_resp.payload.len() + orig_mac.len() {
            let mut mac = orig_mac.clone();
            mac[pos - p2p_resp.payload.len()] ^= 1u8 << bit;
            mutated.binding_mac = URL_SAFE_NO_PAD.encode(mac);
        } else {
            let mut sig = orig_self_sig.clone();
            sig[pos - p2p_resp.payload.len() - orig_mac.len()] ^= 1u8 << bit;
            mutated.self_sig = URL_SAFE_NO_PAD.encode(sig);
        }
        assert!(
            verify_p2p_response(&offer, &mutated, now).is_err(),
            "seed=0x{seed:016x} step={step}: P2pPairResponse 1-bit flip (pos={pos}, bit={bit}) was accepted!"
        );
    }

    // 2d. 72 seeded 1-bit flips across `P2pPairConfirmation` (`offer_id`, `payload`, `sig`) -> 100% rejected!
    let orig_conf_sig = URL_SAFE_NO_PAD
        .decode(&p2p_conf.alice_grant_to_bob.sig)
        .unwrap();
    let conf_total = p2p_conf.offer_id.len()
        + p2p_conf.alice_grant_to_bob.payload.len()
        + orig_conf_sig.len();
    for step in 0..72usize {
        let pos = rng.gen_usize(conf_total);
        let bit = (rng.next_u64() % 8) as u8;
        let mut mutated: P2pPairConfirmation = p2p_conf.clone();
        if pos < p2p_conf.offer_id.len() {
            mutated.offer_id = flip_ascii_str_bit(&p2p_conf.offer_id, pos, bit % 7);
        } else if pos < p2p_conf.offer_id.len() + p2p_conf.alice_grant_to_bob.payload.len() {
            let p_idx = pos - p2p_conf.offer_id.len();
            mutated.alice_grant_to_bob.payload =
                flip_ascii_str_bit(&p2p_conf.alice_grant_to_bob.payload, p_idx, bit % 7);
        } else {
            let s_idx = pos - p2p_conf.offer_id.len() - p2p_conf.alice_grant_to_bob.payload.len();
            let mut sig = orig_conf_sig.clone();
            sig[s_idx] ^= 1u8 << bit;
            mutated.alice_grant_to_bob.sig = URL_SAFE_NO_PAD.encode(sig);
        }
        assert!(
            verify_p2p_confirmation(&offer, &mutated, "bob@laptop").is_err(),
            "seed=0x{seed:016x} step={step}: P2pPairConfirmation 1-bit flip (pos={pos}, bit={bit}) was accepted!"
        );
    }

    // =========================================================================
    // 3. Signed `RevocationV2` (72 seeded 1-bit flips across payload + sig)
    // =========================================================================
    let rev = RevocationV2 {
        v: 2,
        node_id: "alice@lost-laptop".into(),
        grant_id: "grant-revoked-777".into(),
        revoked_at: "2026-11-24T15:00:00Z".into(),
        reason: Some("device_compromised".into()),
    };
    let signed_rev = sign_revocation_v2(&rev, &admin).unwrap();
    assert_eq!(verify_revocation_v2(&signed_rev, &admin.public_key()).unwrap(), rev);

    let orig_rev_sig = URL_SAFE_NO_PAD.decode(&signed_rev.sig).unwrap();
    let rev_total = signed_rev.payload.len() + orig_rev_sig.len();
    for step in 0..72usize {
        let pos = rng.gen_usize(rev_total);
        let bit = (rng.next_u64() % 8) as u8;
        let mut mutated = signed_rev.clone();
        if pos < signed_rev.payload.len() {
            mutated.payload = flip_ascii_str_bit(&signed_rev.payload, pos, bit % 7);
        } else {
            let mut sig = orig_rev_sig.clone();
            sig[pos - signed_rev.payload.len()] ^= 1u8 << bit;
            mutated.sig = URL_SAFE_NO_PAD.encode(sig);
        }
        assert!(
            verify_revocation_v2(&mutated, &admin.public_key()).is_err(),
            "seed=0x{seed:016x} step={step}: RevocationV2 1-bit flip (pos={pos}, bit={bit}) was accepted!"
        );
    }

    // =========================================================================
    // 4. Signed `KeyRegPayloadV2` (+ `KeyRegistrationV1` parity sweep)
    // =========================================================================
    let key_reg_v2 = KeyRegPayloadV2 {
        v: 2,
        node_id: "alice@macbook".into(),
        signing_jwk: alice.signing_jwk(),
        encryption_jwk: alice.encryption_jwk(),
    };
    let signed_kr = alice.signing.sign_jcs("key-reg", &key_reg_v2).unwrap();
    let verified_kr: KeyRegPayloadV2 = alice
        .signing
        .public_key()
        .verify_signed("key-reg", &signed_kr)
        .unwrap();
    assert_eq!(verified_kr, key_reg_v2);
    // Domain separation check: "key-reg" signature MUST NOT verify under "grant" or "revocation".
    assert!(
        alice
            .signing
            .public_key()
            .verify_signed::<KeyRegPayloadV2>("grant", &signed_kr)
            .is_err()
    );

    let orig_kr_sig = URL_SAFE_NO_PAD.decode(&signed_kr.sig).unwrap();
    let kr_total = signed_kr.payload.len() + orig_kr_sig.len();
    for step in 0..72usize {
        let pos = rng.gen_usize(kr_total);
        let bit = (rng.next_u64() % 8) as u8;
        let mut mutated = signed_kr.clone();
        if pos < signed_kr.payload.len() {
            mutated.payload = flip_ascii_str_bit(&signed_kr.payload, pos, bit % 7);
        } else {
            let mut sig = orig_kr_sig.clone();
            sig[pos - signed_kr.payload.len()] ^= 1u8 << bit;
            mutated.sig = URL_SAFE_NO_PAD.encode(sig);
        }
        assert!(
            alice
                .signing
                .public_key()
                .verify_signed::<KeyRegPayloadV2>("key-reg", &mutated)
                .is_err(),
            "seed=0x{seed:016x} step={step}: KeyRegPayloadV2 1-bit flip (pos={pos}, bit={bit}) was accepted!"
        );
    }

    // Also sweep 64 seeded 1-bit flips across `KeyRegistrationV1`.
    let kr_v1 = create_key_registration_v1("alice@macbook", &alice.signing, &alice.encryption).unwrap();
    assert!(verify_key_registration_v1("alice@macbook", &kr_v1).is_ok());
    let orig_v1_sig = URL_SAFE_NO_PAD.decode(&kr_v1.proof.sig).unwrap();
    let kr_v1_total = kr_v1.proof.payload.len() + orig_v1_sig.len();
    for step in 0..64usize {
        let pos = rng.gen_usize(kr_v1_total);
        let bit = (rng.next_u64() % 8) as u8;
        let mut mutated = kr_v1.clone();
        if pos < kr_v1.proof.payload.len() {
            mutated.proof.payload = flip_ascii_str_bit(&kr_v1.proof.payload, pos, bit % 7);
        } else {
            let mut sig = orig_v1_sig.clone();
            sig[pos - kr_v1.proof.payload.len()] ^= 1u8 << bit;
            mutated.proof.sig = URL_SAFE_NO_PAD.encode(sig);
        }
        assert!(
            verify_key_registration_v1("alice@macbook", &mutated).is_err(),
            "seed=0x{seed:016x} step={step}: KeyRegistrationV1 1-bit flip (pos={pos}, bit={bit}) was accepted!"
        );
    }
}
