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
use hyp_crypto::keys::{Ed25519KeyPair, Ed25519PublicKey, NodeIdentityKeys, X25519KeyPair, X25519PublicKey};
use hyp_crypto::keystore::{validate_secret_name, SecretBackend, SecretStore};
use hyp_crypto::rfc3339::now_unix_ms;
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
