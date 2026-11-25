//! End-to-end Pairing Security, Key Rotation, Offline Admin-CA, and Anti-Recon Tests (`hyp-node`).
//!
//! Covers Issues #8 & #9 (`P1-1`, `P1-2`, `P1-3`, `P1-11`):
//! 1. `P1-1`: P2P peer-id takeover protection (rejects claiming existing Hub/Router peer ID,
//!    local `node_id`, `'local'`, or existing P2P peer without explicit targeted idempotent re-pair),
//!    preserving Hub's endpoint, pinned JWKs, and `peer-auth-*` secret 100% untouched; plus
//!    `PeerStore::upsert_peer_key` silent replacement rejection vs explicit `rotate_peer_key`.
//! 2. `P1-2`: `PUT /v1/keys` closes unauthenticated/self-signed key swaps (`403 Forbidden`),
//!    blocks Guest & unpinned callers (`403 Forbidden`), and supports authorized rotation signed
//!    by the currently pinned signing key (single-proof & dual-proof) or configured `admin_jwk`,
//!    atomically retiring old keys (`KeyStatus::Retired`) and clearing stale `peer-auth-*` secrets.
//! 3. `P1-3`: True Offline Admin-CA Team Hub pairing — Hub holds ONLY public `admin_jwk` (ZERO
//!    Admin-CA private key, ZERO pre-inserted grant rows in SQLite). Client redeems inline
//!    `signedGrant` over live `POST /v1/pair`, single-use replay returns `409 Conflict`, 1-bit
//!    tampering in `signedGrant` returns `401 Unauthorized`, expired grant returns `410 Gone`,
//!    and legacy Hub-DB-backed pairing remains 100% backwards compatible.
//! 4. `P1-11`: Anti-recon directory scope gate on `GET /v1/keys` and `GET /v1/handles` — guests
//!    and peers lacking directory/DM/channel scopes cannot enumerate private org/peer nodes,
//!    keys, or handles (`403 not_granted`).
//!
//! 100% isolated (`tempfile::TempDir`, `127.0.0.1:0`, `SecretBackend::File`, zero external calls).

mod common;

use std::sync::Arc;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{Method, Request, StatusCode};
use serde_json::{Value, json};
use tempfile::TempDir;
use zeroize::Zeroizing;

use common::{Ed25519AuthBuilder, loopback_zero};
use hyp_crypto::compat_v1::{
    PairingCodeV1, derive_pairing_key_v1, format_pairing_code_v1, parse_pairing_code_v1,
};
use hyp_crypto::jcs::to_canonical_json;
use hyp_crypto::keystore::SecretStore;
use hyp_crypto::pairing::{
    AdminInviteV2, GrantV2, create_p2p_response, decode_hp2p1, encode_am2_with_signed_grant,
    sign_grant_v2,
};
use hyp_crypto::rfc3339::format_rfc3339_millis;
use hyp_crypto::{Ed25519KeyPair, NodeIdentityKeys, SecretBackend};
use hyp_node::engine::http_util::{HttpClient, full_body};
use hyp_node::engine::peer_link::{KeyRegPayloadV2, PairBindingV2, PairRequestV2, PutKeyRequest};
use hyp_node::engine::{
    GuestPairRequest, GuestPairingConfig, NodeConfig, UnifiedNode, guest_pair_proof_canonical,
};
use hyp_proto::address::NodeId;
use hyp_proto::manifest::{OkpCurve, OkpJwk};
use hyp_proto::problem::ProblemDetails;
use hyp_proto::scopes::ScopePreset;
use hyp_store::{
    KeyStatus, KeyUse, PeerInput, PeerKeyInput, PeerProfile, PeerStatus, StoreError, TrustTier,
    now_ms, sha256_hex, uuid_v4,
};

fn peer_auth_secret_name(peer_id: &str) -> String {
    let hash = sha256_hex(peer_id.as_bytes());
    format!("peer-auth-{}", &hash[..12])
}

/// Mints a true offline Admin-CA `am2_` token WITHOUT touching any Hub database!
fn mint_offline_am2_invite(
    admin_ca: &Ed25519KeyPair,
    hub_endpoint: &str,
    target_node_id: &str,
    scopes: &[&str],
    trust_tier: &str,
    ttl_ms: i64,
    now: i64,
) -> (String, String, hyp_crypto::SignedPayload, PairingCodeV1) {
    let grant_id = uuid_v4();
    let mut secret = Zeroizing::new([0u8; 20]);
    for (i, b) in secret.iter_mut().enumerate() {
        *b = (i as u8).wrapping_mul(37).wrapping_add(11);
    }
    let pair_kp = derive_pairing_key_v1(&secret, &grant_id).unwrap();
    let grant = GrantV2 {
        v: 2,
        id: grant_id.clone(),
        node_id: target_node_id.to_string(),
        scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
        trust_tier: Some(trust_tier.to_string()),
        pairing_key: Some(pair_kp.to_jwk()),
        subject_signing_jwk: None,
        subject_encryption_jwk: None,
        issued_at: format_rfc3339_millis(now),
        pair_by: Some(format_rfc3339_millis(now + ttl_ms)),
        expires_at: Some(format_rfc3339_millis(now + ttl_ms)),
    };
    let signed_grant = sign_grant_v2(&grant, admin_ca).unwrap();
    let pairing_code_v1 = PairingCodeV1 {
        grant_id: grant_id.clone(),
        secret,
        admin_fingerprint: admin_ca.fingerprint(),
    };
    let pairing_code = format_pairing_code_v1(&pairing_code_v1).unwrap();
    let invite = AdminInviteV2 {
        v: 2,
        router: hub_endpoint.to_string(),
        admin_jwk: admin_ca.to_jwk(),
        pairing_code,
        require_e2ee: Some(true),
    };
    let am2 = encode_am2_with_signed_grant(&invite, &signed_grant).unwrap();
    let parsed = parse_pairing_code_v1(&invite.pairing_code).unwrap();
    (am2, grant_id, signed_grant, parsed)
}

async fn send_post_json(
    client: &HttpClient,
    url: &str,
    body: &Value,
) -> (StatusCode, Vec<u8>) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(url)
        .header(CONTENT_TYPE, "application/json")
        .body(full_body(serde_json::to_vec(body).unwrap()))
        .unwrap();
    let resp = client.request(req).await.unwrap();
    let (status, _, bytes) = HttpClient::collect(resp, 128 * 1024).await.unwrap();
    (status, bytes.to_vec())
}

// ============================================================================
// 1. P1-1 (P0): Close P2P peer-id takeover & store silent key replacement
// ============================================================================

#[tokio::test]
async fn p1_1_p2p_peer_id_takeover_blocked_and_store_key_pin_enforced() {
    let hub_dir = TempDir::new().unwrap();
    let alice_dir = TempDir::new().unwrap();
    let bob_dir = TempDir::new().unwrap();

    let admin_ca = Ed25519KeyPair::generate().unwrap();
    let admin_proto_jwk = OkpJwk::new(OkpCurve::Ed25519, &admin_ca.public_key_bytes());

    let mut hub_cfg = NodeConfig::router(NodeId::new("acme-hub").unwrap(), hub_dir.path());
    hub_cfg.secret_backend = Some(SecretBackend::File);
    hub_cfg.admin_jwk = Some(admin_proto_jwk);
    let hub = UnifiedNode::open(hub_cfg).unwrap();
    let (hub_addr, _hub_srv) = Arc::clone(&hub).serve(loopback_zero()).await.unwrap();
    let hub_url = format!("http://{hub_addr}");

    let mut alice_cfg = NodeConfig::p2p(NodeId::new("alice@macbook").unwrap(), alice_dir.path());
    alice_cfg.secret_backend = Some(SecretBackend::File);
    let alice = UnifiedNode::open(alice_cfg).unwrap();
    let (alice_addr, _alice_srv) = Arc::clone(&alice).serve(loopback_zero()).await.unwrap();
    let alice_url = format!("http://{alice_addr}");

    // Pair Alice with `acme-hub` so Alice has an active Router peer row, pinned JWKs, and
    // a stored `peer-auth-*` bearer credential for `acme-hub`.
    let member_scopes = ScopePreset::Member.expand();
    let member_refs: Vec<&str> = member_scopes.iter().map(String::as_str).collect();
    let (alice_am2, _) = hub
        .create_admin_invite(&admin_ca, "alice@macbook", &member_refs, TrustTier::Org, 300_000)
        .unwrap();
    alice.accept_am2_invite(&alice_am2).await.unwrap();

    // Snapshot `acme-hub`'s peer record, pinned JWKs, and bearer secret on Alice BEFORE attack.
    let hub_peer_before = alice.db().peers().get_peer("acme-hub").unwrap().unwrap();
    assert_eq!(hub_peer_before.profile, PeerProfile::Router);
    assert_eq!(hub_peer_before.endpoint.as_deref(), Some(hub_url.as_str()));
    let hub_sign_before = alice
        .db()
        .peers()
        .list_peer_keys("acme-hub", Some(KeyUse::Signing), true)
        .unwrap();
    let hub_enc_before = alice
        .db()
        .peers()
        .list_peer_keys("acme-hub", Some(KeyUse::Encryption), true)
        .unwrap();
    assert_eq!(hub_sign_before.len(), 1);
    assert_eq!(hub_enc_before.len(), 1);
    let alice_secrets = SecretStore::new(alice_dir.path(), SecretBackend::File);
    let hub_bearer_before = alice_secrets
        .get(&peer_auth_secret_name("acme-hub"))
        .expect("Alice must have Hub bearer token stored");

    // Alice mints a legitimate P2P offer and gives it to an attacker (`mallory`).
    let (p2p_token, offer) = alice
        .create_p2p_invite(vec!["dm:send".into(), "dm:receive".into()], vec![], 300_000)
        .unwrap();
    let decoded_offer = decode_hp2p1(&p2p_token).unwrap();
    let mallory_keys = NodeIdentityKeys::generate().unwrap();
    let client = HttpClient::new().unwrap();
    let pair_url = format!("{alice_url}/v1/p2p/pair/{}", offer.offer_id);

    let make_p2p_grant = || GrantV2 {
        v: 2,
        id: uuid_v4(),
        node_id: "alice@macbook".to_string(),
        scopes: vec!["dm:send".into(), "dm:receive".into()],
        trust_tier: Some("peer".to_string()),
        pairing_key: None,
        subject_signing_jwk: Some(decoded_offer.signing_jwk.clone()),
        subject_encryption_jwk: Some(decoded_offer.encryption_jwk.clone()),
        issued_at: format_rfc3339_millis(now_ms()),
        pair_by: None,
        expires_at: None,
    };

    // (a) ATTACK: Mallory tries to claim `acme-hub` with attacker's endpoint & keys -> 409 Conflict!
    let hijack_resp = create_p2p_response(
        &decoded_offer,
        "acme-hub",
        Some("http://127.0.0.1:19999"),
        &mallory_keys,
        &make_p2p_grant(),
    )
    .unwrap();
    let (st_hub, body_hub) =
        send_post_json(&client, &pair_url, &serde_json::to_value(&hijack_resp).unwrap()).await;
    assert_eq!(
        st_hub,
        StatusCode::CONFLICT,
        "Hub takeover via P2P MUST be rejected with 409; got {st_hub}: {}",
        String::from_utf8_lossy(&body_hub)
    );
    let prob_hub: ProblemDetails = serde_json::from_slice(&body_hub).unwrap();
    assert_eq!(prob_hub.error, "peer_key_mismatch");
    assert!(
        !String::from_utf8_lossy(&body_hub).contains("authCredential"),
        "rejected hijack must NEVER return an authCredential"
    );

    // Verify `acme-hub`'s peer row, endpoint, pinned keys, and bearer token are 100% UNTOUCHED!
    let hub_peer_after = alice.db().peers().get_peer("acme-hub").unwrap().unwrap();
    assert_eq!(hub_peer_after.endpoint, hub_peer_before.endpoint);
    assert_eq!(hub_peer_after.profile, PeerProfile::Router);
    assert_eq!(hub_peer_after.trust_tier, hub_peer_before.trust_tier);
    assert_eq!(hub_peer_after.scopes, hub_peer_before.scopes);
    assert_eq!(
        hub_peer_after.auth_credential_ref,
        hub_peer_before.auth_credential_ref
    );
    assert_eq!(
        alice
            .db()
            .peers()
            .list_peer_keys("acme-hub", Some(KeyUse::Signing), true)
            .unwrap(),
        hub_sign_before
    );
    assert_eq!(
        alice
            .db()
            .peers()
            .list_peer_keys("acme-hub", Some(KeyUse::Encryption), true)
            .unwrap(),
        hub_enc_before
    );
    assert_eq!(
        alice_secrets.get(&peer_auth_secret_name("acme-hub")).unwrap(),
        hub_bearer_before
    );

    // (b) ATTACK: Mallory tries to claim Alice's own node_id (`alice@macbook`) -> 409 Conflict!
    let self_claim = create_p2p_response(
        &decoded_offer,
        "alice@macbook",
        None,
        &mallory_keys,
        &make_p2p_grant(),
    )
    .unwrap();
    let (st_self, body_self) =
        send_post_json(&client, &pair_url, &serde_json::to_value(&self_claim).unwrap()).await;
    assert_eq!(
        st_self,
        StatusCode::CONFLICT,
        "claiming local node_id MUST return 409; got {st_self}: {}",
        String::from_utf8_lossy(&body_self)
    );
    assert!(
        String::from_utf8_lossy(&body_self).contains("PEER_ID_CONFLICT"),
        "expected PEER_ID_CONFLICT detail: {}",
        String::from_utf8_lossy(&body_self)
    );

    // (c) ATTACK: Mallory tries to claim reserved `'local'` -> 409 Conflict!
    let local_claim = create_p2p_response(
        &decoded_offer,
        "local",
        None,
        &mallory_keys,
        &make_p2p_grant(),
    )
    .unwrap();
    let (st_local, body_local) =
        send_post_json(&client, &pair_url, &serde_json::to_value(&local_claim).unwrap()).await;
    assert_eq!(
        st_local,
        StatusCode::CONFLICT,
        "claiming 'local' MUST return 409; got {st_local}: {}",
        String::from_utf8_lossy(&body_local)
    );

    // (d) Legitimate Bob pairs with the untouched offer -> 200 OK!
    let mut bob_cfg = NodeConfig::p2p(NodeId::new("bob@laptop").unwrap(), bob_dir.path());
    bob_cfg.secret_backend = Some(SecretBackend::File);
    let bob = UnifiedNode::open(bob_cfg).unwrap();
    bob.accept_p2p_invite(&p2p_token, vec!["dm:send".into(), "dm:receive".into()])
        .await
        .expect("legitimate Bob pairing must succeed after rejected takeovers");

    // (e) ATTACK: Untargeted offer cannot overwrite existing `bob@laptop` (neither with Mallory's
    //     keys -> 409 peer_key_mismatch, nor even with Bob's own keys -> 409 PEER_ALREADY_EXISTS)!
    let (offer2_tok, offer2) = alice
        .create_p2p_invite(vec!["dm:send".into()], vec![], 300_000)
        .unwrap();
    let offer2_dec = decode_hp2p1(&offer2_tok).unwrap();
    let pair_url2 = format!("{alice_url}/v1/p2p/pair/{}", offer2.offer_id);

    let bob_hijack = create_p2p_response(
        &offer2_dec,
        "bob@laptop",
        None,
        &mallory_keys,
        &make_p2p_grant(),
    )
    .unwrap();
    let (st_bh, _) =
        send_post_json(&client, &pair_url2, &serde_json::to_value(&bob_hijack).unwrap()).await;
    assert_eq!(st_bh, StatusCode::CONFLICT);

    let bob_untargeted_repair = create_p2p_response(
        &offer2_dec,
        "bob@laptop",
        None,
        bob.identity(),
        &make_p2p_grant(),
    )
    .unwrap();
    let (st_untargeted, body_untargeted) = send_post_json(
        &client,
        &pair_url2,
        &serde_json::to_value(&bob_untargeted_repair).unwrap(),
    )
    .await;
    assert_eq!(
        st_untargeted,
        StatusCode::CONFLICT,
        "untargeted re-pair of existing peer MUST be rejected 409: {}",
        String::from_utf8_lossy(&body_untargeted)
    );

    // (f) Explicitly targeted offer (`create_p2p_invite_for_peer(Some("bob@laptop"), ...)`)
    //     rejects Mallory (wrong peer_id -> 409), rejects Bob with wrong keys -> 409,
    //     and PERMITS idempotent re-pair with Bob's identical pinned JWKs -> 200 OK!
    let (targeted_tok, targeted_offer) = alice
        .create_p2p_invite_for_peer(
            Some("bob@laptop"),
            vec!["dm:send".into(), "dm:receive".into()],
            vec![],
            300_000,
        )
        .unwrap();
    let targeted_dec = decode_hp2p1(&targeted_tok).unwrap();
    let targeted_url = format!("{alice_url}/v1/p2p/pair/{}", targeted_offer.offer_id);

    let wrong_peer = create_p2p_response(
        &targeted_dec,
        "mallory@evil",
        None,
        &mallory_keys,
        &make_p2p_grant(),
    )
    .unwrap();
    let (st_wrong_peer, _) =
        send_post_json(&client, &targeted_url, &serde_json::to_value(&wrong_peer).unwrap()).await;
    assert_eq!(st_wrong_peer, StatusCode::CONFLICT);

    let valid_repair = create_p2p_response(
        &targeted_dec,
        "bob@laptop",
        None,
        bob.identity(),
        &make_p2p_grant(),
    )
    .unwrap();
    let (st_repair, body_repair) =
        send_post_json(&client, &targeted_url, &serde_json::to_value(&valid_repair).unwrap()).await;
    assert_eq!(
        st_repair,
        StatusCode::OK,
        "explicit targeted idempotent re-pair with identical keys must succeed: {}",
        String::from_utf8_lossy(&body_repair)
    );

    // (g) hyp-store invariant: `upsert_peer_key` refuses silently inserting a second active
    //     signing/encryption key with a different kid; `rotate_peer_key` retires the old key!
    {
        let db = alice.db();
        let err = db
            .peers()
            .upsert_peer_key(
                &PeerKeyInput {
                    peer_id: "acme-hub".into(),
                    kid: mallory_keys.signing.kid(),
                    key_use: KeyUse::Signing,
                    jwk_json: serde_json::to_string(&mallory_keys.signing_jwk()).unwrap(),
                    status: KeyStatus::Active,
                    expires_at: None,
                },
                now_ms(),
            )
            .expect_err("silent replacement of active signing key must fail closed");
        assert!(matches!(err, StoreError::IdConflict(_)), "got {err:?}");
        assert_eq!(
            db.peers()
                .list_peer_keys("acme-hub", Some(KeyUse::Signing), true)
                .unwrap()
                .len(),
            1
        );
    }

    bob.shutdown();
    alice.shutdown();
    hub.shutdown();
}

// ============================================================================
// 2. P1-2 (P0): Close `PUT /v1/keys` unauthenticated key swap
// ============================================================================

#[tokio::test]
async fn p1_2_put_keys_rejects_self_signed_guest_unpinned_and_allows_authorized_rotation() {
    let hub_dir = TempDir::new().unwrap();
    let alice_dir = TempDir::new().unwrap();

    let admin_ca = Ed25519KeyPair::generate().unwrap();
    let admin_proto_jwk = OkpJwk::new(OkpCurve::Ed25519, &admin_ca.public_key_bytes());

    let mut hub_cfg = NodeConfig::router(NodeId::new("acme-keys-hub").unwrap(), hub_dir.path());
    hub_cfg.secret_backend = Some(SecretBackend::File);
    hub_cfg.admin_jwk = Some(admin_proto_jwk);
    hub_cfg.guest_pairing = GuestPairingConfig {
        enabled: true,
        ..GuestPairingConfig::default()
    };
    let hub = UnifiedNode::open(hub_cfg).unwrap();
    let (hub_addr, _hub_srv) = Arc::clone(&hub).serve(loopback_zero()).await.unwrap();
    let hub_url = format!("http://{hub_addr}");

    let mut alice_cfg = NodeConfig::local(NodeId::new("alice@macbook").unwrap(), alice_dir.path());
    alice_cfg.secret_backend = Some(SecretBackend::File);
    let alice = UnifiedNode::open(alice_cfg).unwrap();

    let member_scopes = ScopePreset::Member.expand();
    let member_refs: Vec<&str> = member_scopes.iter().map(String::as_str).collect();
    let (alice_am2, _) = hub
        .create_admin_invite(&admin_ca, "alice@macbook", &member_refs, TrustTier::Org, 300_000)
        .unwrap();
    alice.accept_am2_invite(&alice_am2).await.unwrap();

    let alice_secrets = SecretStore::new(alice_dir.path(), SecretBackend::File);
    let alice_bearer = alice_secrets
        .get(&peer_auth_secret_name("acme-keys-hub"))
        .expect("alice bearer credential");
    let alice_orig_sign_kid = alice.identity().signing.kid();
    let alice_orig_enc_kid = alice.identity().encryption.kid();

    // Seed a synthetic stale `peer-auth-*` secret on the hub for `alice@macbook` to verify
    // authorized rotation clears it cleanly.
    let hub_secrets = SecretStore::new(hub_dir.path(), SecretBackend::File);
    hub_secrets
        .set(&peer_auth_secret_name("alice@macbook"), "stale-peer-token")
        .unwrap();

    let client = HttpClient::new().unwrap();

    // (a) ATTACK: Attacker steals Alice's Bearer token, creates `evil_keys`, signs proof with
    //     ONLY `evil_keys` -> MUST fail closed with 403 Forbidden!
    let evil_keys = NodeIdentityKeys::generate().unwrap();
    let evil_payload = KeyRegPayloadV2 {
        v: 2,
        node_id: "alice@macbook".to_string(),
        signing_jwk: evil_keys.signing_jwk(),
        encryption_jwk: evil_keys.encryption_jwk(),
    };
    let evil_put = PutKeyRequest {
        signing_jwk: evil_keys.signing_jwk(),
        encryption_jwk: evil_keys.encryption_jwk(),
        proof: evil_keys.signing.sign_jcs("key-reg", &evil_payload).unwrap(),
    };
    let req_bearer_attack = Request::builder()
        .method(Method::PUT)
        .uri(format!("{hub_url}/v1/keys"))
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Bearer {}", alice_bearer.as_str()))
        .body(full_body(serde_json::to_vec(&evil_put).unwrap()))
        .unwrap();
    let resp_bearer_attack = client.request(req_bearer_attack).await.unwrap();
    let (st_ba, _, body_ba) = HttpClient::collect(resp_bearer_attack, 64 * 1024)
        .await
        .unwrap();
    assert_eq!(
        st_ba,
        StatusCode::FORBIDDEN,
        "self-signed new-key PUT /v1/keys with Bearer token MUST return 403; got {st_ba}: {}",
        String::from_utf8_lossy(&body_ba)
    );

    // (b) ATTACK: Even with valid Ed25519 HTTP auth from Alice's old key, a `proof` signed ONLY
    //     by the new key MUST return 403 Forbidden!
    let alice_auth_v1 = Ed25519AuthBuilder::new("alice@macbook", &alice.identity().signing);
    let req_self_only = alice_auth_v1.sign_request(
        Method::PUT,
        &hub_url,
        "/v1/keys",
        Some(Bytes::from(serde_json::to_vec(&evil_put).unwrap())),
        Some("application/json"),
    );
    let resp_self_only = client.request(req_self_only).await.unwrap();
    assert_eq!(resp_self_only.status(), StatusCode::FORBIDDEN);

    // Confirm Alice's pinned keys on the hub are 100% untouched.
    assert_eq!(
        hub.lookup_peer_signing_key("alice@macbook")
            .unwrap()
            .unwrap()
            .kid(),
        alice_orig_sign_kid
    );

    // (c) ATTACK: Enrolled `TrustTier::Guest` calls `PUT /v1/keys` (even signed by guest's own
    //     pinned key!) -> MUST fail closed with 403 Forbidden!
    let guest_keys = NodeIdentityKeys::generate().unwrap();
    let ts = format_rfc3339_millis(now_ms());
    let g_canon = guest_pair_proof_canonical(
        "acme-keys-hub",
        "guest@pub",
        &guest_keys.signing_jwk(),
        &guest_keys.encryption_jwk(),
        &ts,
    )
    .unwrap();
    let guest_req = GuestPairRequest {
        node_id: "guest@pub".to_string(),
        ed25519_jwk: guest_keys.signing_jwk(),
        x25519_jwk: guest_keys.encryption_jwk(),
        timestamp: ts,
        proof_sig: guest_keys
            .signing
            .sign_domain_b64("guest-pair", g_canon.as_bytes()),
    };
    let (st_g, _) = send_post_json(
        &client,
        &format!("{hub_url}/v1/guest/pair"),
        &serde_json::to_value(&guest_req).unwrap(),
    )
    .await;
    assert_eq!(st_g, StatusCode::OK);

    let guest_keys_v2 = NodeIdentityKeys::generate().unwrap();
    let guest_rot_payload = KeyRegPayloadV2 {
        v: 2,
        node_id: "guest@pub".to_string(),
        signing_jwk: guest_keys_v2.signing_jwk(),
        encryption_jwk: guest_keys_v2.encryption_jwk(),
    };
    let guest_put = PutKeyRequest {
        signing_jwk: guest_keys_v2.signing_jwk(),
        encryption_jwk: guest_keys_v2.encryption_jwk(),
        proof: guest_keys
            .signing
            .sign_jcs("key-reg", &guest_rot_payload)
            .unwrap(),
    };
    let guest_auth = Ed25519AuthBuilder::new("guest@pub", &guest_keys.signing);
    let req_guest_put = guest_auth.sign_request(
        Method::PUT,
        &hub_url,
        "/v1/keys",
        Some(Bytes::from(serde_json::to_vec(&guest_put).unwrap())),
        Some("application/json"),
    );
    let resp_guest_put = client.request(req_guest_put).await.unwrap();
    assert_eq!(
        resp_guest_put.status(),
        StatusCode::FORBIDDEN,
        "Guest caller MUST NEVER rotate directory keys (403)"
    );

    // (d) ATTACK: Unpinned peer (peer row + bearer token, zero pinned signing keys) -> 403!
    let unpinned_bearer = "unpinned-test-bearer-secret-token";
    {
        let db = hub.db();
        db.peers()
            .upsert_peer(
                &PeerInput {
                    peer_id: "unpinned@box".into(),
                    endpoint: None,
                    profile: PeerProfile::Local,
                    trust_tier: TrustTier::Peer,
                    status: PeerStatus::Active,
                    scopes: ScopePreset::Member.expand(),
                    auth_credential_ref: None,
                },
                now_ms(),
            )
            .unwrap();
        db.local()
            .set_metadata(
                &format!("auth_token:{}", sha256_hex(unpinned_bearer.as_bytes())),
                "unpinned@box",
            )
            .unwrap();
    }
    let unpinned_keys = NodeIdentityKeys::generate().unwrap();
    let unpinned_payload = KeyRegPayloadV2 {
        v: 2,
        node_id: "unpinned@box".to_string(),
        signing_jwk: unpinned_keys.signing_jwk(),
        encryption_jwk: unpinned_keys.encryption_jwk(),
    };
    let unpinned_put = PutKeyRequest {
        signing_jwk: unpinned_keys.signing_jwk(),
        encryption_jwk: unpinned_keys.encryption_jwk(),
        proof: unpinned_keys
            .signing
            .sign_jcs("key-reg", &unpinned_payload)
            .unwrap(),
    };
    let req_unpinned = Request::builder()
        .method(Method::PUT)
        .uri(format!("{hub_url}/v1/keys"))
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Bearer {unpinned_bearer}"))
        .body(full_body(serde_json::to_vec(&unpinned_put).unwrap()))
        .unwrap();
    assert_eq!(
        client.request(req_unpinned).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );

    // (e) LEGITIMATE ROTATION #1: Signed by currently pinned key `K_v1` -> 200 OK,
    //     old key marked `Retired`, new key is sole `Active` key, stale `peer-auth-*` cleared!
    let alice_v2 = NodeIdentityKeys::generate().unwrap();
    let rot_v2_payload = KeyRegPayloadV2 {
        v: 2,
        node_id: "alice@macbook".to_string(),
        signing_jwk: alice_v2.signing_jwk(),
        encryption_jwk: alice_v2.encryption_jwk(),
    };
    let rot_v2_req = PutKeyRequest {
        signing_jwk: alice_v2.signing_jwk(),
        encryption_jwk: alice_v2.encryption_jwk(),
        proof: alice
            .identity()
            .signing
            .sign_jcs("key-reg", &rot_v2_payload)
            .unwrap(),
    };
    let req_v2 = alice_auth_v1.sign_request(
        Method::PUT,
        &hub_url,
        "/v1/keys",
        Some(Bytes::from(serde_json::to_vec(&rot_v2_req).unwrap())),
        Some("application/json"),
    );
    let resp_v2 = client.request(req_v2).await.unwrap();
    let (st_v2, _, body_v2) = HttpClient::collect(resp_v2, 64 * 1024).await.unwrap();
    assert_eq!(
        st_v2,
        StatusCode::OK,
        "valid rotation signed by pinned key must succeed: {}",
        String::from_utf8_lossy(&body_v2)
    );

    // Verify old key is Retired and ONLY new key is Active (no ambiguous duplicate active keys!).
    {
        let db = hub.db();
        let active_sign = db
            .peers()
            .list_peer_keys("alice@macbook", Some(KeyUse::Signing), true)
            .unwrap();
        assert_eq!(active_sign.len(), 1);
        assert_eq!(active_sign[0].kid, alice_v2.signing.kid());

        let old_sign = db
            .peers()
            .get_peer_key("alice@macbook", &alice_orig_sign_kid)
            .unwrap()
            .expect("old signing key record should remain for audit as Retired");
        assert_eq!(old_sign.status, KeyStatus::Retired);

        let active_enc = db
            .peers()
            .list_peer_keys("alice@macbook", Some(KeyUse::Encryption), true)
            .unwrap();
        assert_eq!(active_enc.len(), 1);
        assert_eq!(active_enc[0].kid, alice_v2.encryption.kid());

        let old_enc = db
            .peers()
            .get_peer_key("alice@macbook", &alice_orig_enc_kid)
            .unwrap()
            .unwrap();
        assert_eq!(old_enc.status, KeyStatus::Retired);
    }
    assert!(
        hub_secrets
            .get(&peer_auth_secret_name("alice@macbook"))
            .is_err(),
        "stale peer-auth-* secret must be cleared upon authorized key rotation"
    );

    // New key `alice_v2` authenticates cleanly; retired `alice_v1` is rejected with 401!
    let alice_auth_v2 = Ed25519AuthBuilder::new("alice@macbook", &alice_v2.signing);
    let ok_v2_req = alice_auth_v2.sign_request(Method::GET, &hub_url, "/v1/channels", None, None);
    assert_eq!(client.request(ok_v2_req).await.unwrap().status(), StatusCode::OK);
    let bad_v1_req = alice_auth_v1.sign_request(Method::GET, &hub_url, "/v1/channels", None, None);
    assert_eq!(
        client.request(bad_v1_req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );

    // (f) LEGITIMATE ROTATION #2: Dual-proof (`rotationProof` by `K_v2` + `proof` by `K_v3`)!
    let alice_v3 = NodeIdentityKeys::generate().unwrap();
    let rot_v3_payload = KeyRegPayloadV2 {
        v: 2,
        node_id: "alice@macbook".to_string(),
        signing_jwk: alice_v3.signing_jwk(),
        encryption_jwk: alice_v3.encryption_jwk(),
    };
    let dual_body = json!({
        "signingJwk": alice_v3.signing_jwk(),
        "encryptionJwk": alice_v3.encryption_jwk(),
        "proof": alice_v3.signing.sign_jcs("key-reg", &rot_v3_payload).unwrap(),
        "rotationProof": alice_v2.signing.sign_jcs("key-reg", &rot_v3_payload).unwrap(),
    });
    let req_v3 = alice_auth_v2.sign_request(
        Method::PUT,
        &hub_url,
        "/v1/keys",
        Some(Bytes::from(serde_json::to_vec(&dual_body).unwrap())),
        Some("application/json"),
    );
    assert_eq!(client.request(req_v3).await.unwrap().status(), StatusCode::OK);
    assert_eq!(
        hub.lookup_peer_signing_key("alice@macbook")
            .unwrap()
            .unwrap()
            .kid(),
        alice_v3.signing.kid()
    );

    // (g) N1 + LEGITIMATE ROTATION #3: Stale pre-rotation bearer token is now invalidated (401),
    //     while Admin-CA recovery rotation signed by `admin_ca` authenticated under active `K_v3` succeeds!
    let alice_v4 = NodeIdentityKeys::generate().unwrap();
    let rot_v4_payload = KeyRegPayloadV2 {
        v: 2,
        node_id: "alice@macbook".to_string(),
        signing_jwk: alice_v4.signing_jwk(),
        encryption_jwk: alice_v4.encryption_jwk(),
    };
    let admin_rot = PutKeyRequest {
        signing_jwk: alice_v4.signing_jwk(),
        encryption_jwk: alice_v4.encryption_jwk(),
        proof: admin_ca.sign_jcs("key-reg", &rot_v4_payload).unwrap(),
    };
    let admin_rot_bytes = serde_json::to_vec(&admin_rot).unwrap();
    let req_v4_stale_bearer = Request::builder()
        .method(Method::PUT)
        .uri(format!("{hub_url}/v1/keys"))
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, format!("Bearer {}", alice_bearer.as_str()))
        .body(full_body(admin_rot_bytes.clone()))
        .unwrap();
    assert_eq!(
        client
            .request(req_v4_stale_bearer)
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED,
        "N1: pre-rotation bearer token must be rejected with 401 after key rotation"
    );

    let alice_auth_v3 = Ed25519AuthBuilder::new("alice@macbook", &alice_v3.signing);
    let req_v4 = alice_auth_v3.sign_request(
        Method::PUT,
        &hub_url,
        "/v1/keys",
        Some(Bytes::from(admin_rot_bytes)),
        Some("application/json"),
    );
    assert_eq!(client.request(req_v4).await.unwrap().status(), StatusCode::OK);
    assert_eq!(
        hub.lookup_peer_signing_key("alice@macbook")
            .unwrap()
            .unwrap()
            .kid(),
        alice_v4.signing.kid()
    );

    alice.shutdown();
    hub.shutdown();
}

// ============================================================================
// 3. P1-3 (P0): True Offline Admin-CA E2E, Replay 409, Bit-Flip 401, Expiry 410
// ============================================================================

#[tokio::test]
async fn p1_3_true_offline_admin_ca_pairing_replay_and_tamper_mutations() {
    let hub_dir = TempDir::new().unwrap();
    let alice_dir = TempDir::new().unwrap();
    let bob_dir = TempDir::new().unwrap();

    // Admin-CA key lives STRICTLY offline (never written to Hub's TempDir!).
    // Hub ONLY receives the public `admin_proto_jwk`.
    let offline_admin_ca = Ed25519KeyPair::generate().unwrap();
    let rogue_admin_ca = Ed25519KeyPair::generate().unwrap();
    let admin_proto_jwk = OkpJwk::new(OkpCurve::Ed25519, &offline_admin_ca.public_key_bytes());

    let mut hub_cfg = NodeConfig::router(NodeId::new("acme-offline-hub").unwrap(), hub_dir.path());
    hub_cfg.secret_backend = Some(SecretBackend::File);
    hub_cfg.admin_jwk = Some(admin_proto_jwk);
    let hub = UnifiedNode::open(hub_cfg).unwrap();
    let (hub_addr, _hub_srv) = Arc::clone(&hub).serve(loopback_zero()).await.unwrap();
    let hub_url = format!("http://{hub_addr}");

    // Prove Hub SQLite has ZERO grants pre-inserted!
    assert!(
        hub.db().peers().list_grants(None).unwrap().is_empty(),
        "Hub DB must start with zero grants"
    );

    let member_scopes = ScopePreset::Member.expand();
    let member_refs: Vec<&str> = member_scopes.iter().map(String::as_str).collect();
    let now = now_ms();

    // 1. Mint offline `am2_` invite for `alice@macbook` completely outside the Hub.
    let (alice_am2, _alice_grant_id, _, _) = mint_offline_am2_invite(
        &offline_admin_ca,
        &hub_url,
        "alice@macbook",
        &member_refs,
        "org",
        300_000,
        now,
    );
    assert!(hub.db().peers().list_grants(None).unwrap().is_empty());

    // Alice redeems offline `am2_` via live `POST /v1/pair` -> succeeds!
    let mut alice_cfg = NodeConfig::local(NodeId::new("alice@macbook").unwrap(), alice_dir.path());
    alice_cfg.secret_backend = Some(SecretBackend::File);
    let alice = UnifiedNode::open(alice_cfg).unwrap();
    let link_info = alice
        .accept_am2_invite(&alice_am2)
        .await
        .expect("offline Admin-CA am2_ pairing MUST succeed without pre-inserted Hub DB row");
    assert_eq!(link_info.peer_id, "acme-offline-hub");

    // 2. REPLAY: Re-submitting the EXACT same offline `am2_` token MUST fail closed with 409!
    let replay_err = alice
        .accept_am2_invite(&alice_am2)
        .await
        .expect_err("replaying offline am2_ token MUST fail closed");
    match replay_err {
        hyp_node::engine::NodeError::RemoteProblem(prob) => {
            assert_eq!(prob.status, 409, "replay must return 409; got {prob:?}");
            assert_eq!(prob.error, "already_paired");
        }
        other => panic!("expected RemoteProblem(409 already_paired), got {other:?}"),
    }

    // 3. MUTATED-VALID: 1-bit flip in `signedGrant.sig` -> 401 Unauthorized!
    let (_, bob_grant_id, bob_signed_grant, bob_code) = mint_offline_am2_invite(
        &offline_admin_ca,
        &hub_url,
        "bob@laptop",
        &member_refs,
        "org",
        300_000,
        now,
    );
    let bob_keys = NodeIdentityKeys::generate().unwrap();
    let bob_pair_kp = derive_pairing_key_v1(&bob_code.secret, &bob_grant_id).unwrap();
    let bob_binding = PairBindingV2 {
        v: 2,
        grant_id: bob_grant_id.clone(),
        node_id: "bob@laptop".to_string(),
        signing_jwk: bob_keys.signing_jwk(),
        encryption_jwk: bob_keys.encryption_jwk(),
        bound_at: format_rfc3339_millis(now),
    };
    let bob_payload = to_canonical_json(&bob_binding).unwrap();
    let bob_pairing_sig = bob_pair_kp.sign_domain_b64("binding", bob_payload.as_bytes());
    let bob_self_sig = bob_keys
        .signing
        .sign_domain_b64("binding-self", bob_payload.as_bytes());

    let mut tampered_sg = bob_signed_grant.clone();
    let mut sig_bytes = URL_SAFE_NO_PAD.decode(&tampered_sg.sig).unwrap();
    sig_bytes[0] ^= 0x01; // 1-bit flip!
    tampered_sg.sig = URL_SAFE_NO_PAD.encode(sig_bytes);

    let client = HttpClient::new().unwrap();
    let pair_endpoint = format!("{hub_url}/v1/pair");
    let (st_tamper, body_tamper) = send_post_json(
        &client,
        &pair_endpoint,
        &json!({
            "grantId": bob_grant_id,
            "payload": bob_payload,
            "pairingSig": bob_pairing_sig,
            "selfSig": bob_self_sig,
            "signedGrant": tampered_sg,
        }),
    )
    .await;
    assert!(
        st_tamper == StatusCode::UNAUTHORIZED || st_tamper == StatusCode::FORBIDDEN,
        "1-bit flipped signedGrant MUST be rejected with 401/403; got {st_tamper}: {}",
        String::from_utf8_lossy(&body_tamper)
    );

    // 4. MUTATED-VALID: Grant signed by a rogue Admin-CA key -> 401 Unauthorized!
    let (_, rogue_gid, rogue_sg, rogue_code) = mint_offline_am2_invite(
        &rogue_admin_ca,
        &hub_url,
        "bob@laptop",
        &member_refs,
        "org",
        300_000,
        now,
    );
    let rogue_pair_kp = derive_pairing_key_v1(&rogue_code.secret, &rogue_gid).unwrap();
    let rogue_binding = PairBindingV2 {
        v: 2,
        grant_id: rogue_gid.clone(),
        node_id: "bob@laptop".to_string(),
        signing_jwk: bob_keys.signing_jwk(),
        encryption_jwk: bob_keys.encryption_jwk(),
        bound_at: format_rfc3339_millis(now),
    };
    let rogue_payload = to_canonical_json(&rogue_binding).unwrap();
    let (st_rogue, _) = send_post_json(
        &client,
        &pair_endpoint,
        &json!({
            "grantId": rogue_gid,
            "payload": rogue_payload,
            "pairingSig": rogue_pair_kp.sign_domain_b64("binding", rogue_payload.as_bytes()),
            "selfSig": bob_keys.signing.sign_domain_b64("binding-self", rogue_payload.as_bytes()),
            "signedGrant": rogue_sg,
        }),
    )
    .await;
    assert_eq!(st_rogue, StatusCode::UNAUTHORIZED);

    // 5. MUTATED-VALID: Expired offline `signedGrant` -> 410 Gone!
    let (_, exp_gid, exp_sg, exp_code) = mint_offline_am2_invite(
        &offline_admin_ca,
        &hub_url,
        "bob@laptop",
        &member_refs,
        "org",
        60_000,
        now - 120_000, // issued 2m ago, pair_by 1m ago!
    );
    let exp_pair_kp = derive_pairing_key_v1(&exp_code.secret, &exp_gid).unwrap();
    let exp_binding = PairBindingV2 {
        v: 2,
        grant_id: exp_gid.clone(),
        node_id: "bob@laptop".to_string(),
        signing_jwk: bob_keys.signing_jwk(),
        encryption_jwk: bob_keys.encryption_jwk(),
        bound_at: format_rfc3339_millis(now),
    };
    let exp_payload = to_canonical_json(&exp_binding).unwrap();
    let (st_exp, _) = send_post_json(
        &client,
        &pair_endpoint,
        &json!({
            "grantId": exp_gid,
            "payload": exp_payload,
            "pairingSig": exp_pair_kp.sign_domain_b64("binding", exp_payload.as_bytes()),
            "selfSig": bob_keys.signing.sign_domain_b64("binding-self", exp_payload.as_bytes()),
            "signedGrant": exp_sg,
        }),
    )
    .await;
    assert_eq!(st_exp, StatusCode::GONE);

    // 6. Backwards compatibility: Hub-DB-backed pairing WITHOUT inline `signedGrant` still works!
    let (_legacy_am2, legacy_rec) = hub
        .create_admin_invite(&offline_admin_ca, "bob@laptop", &member_refs, TrustTier::Org, 300_000)
        .unwrap();
    let legacy_decoded = hyp_crypto::pairing::decode_am2(&_legacy_am2).unwrap();
    let legacy_code = parse_pairing_code_v1(&legacy_decoded.pairing_code).unwrap();
    let legacy_pair_kp = derive_pairing_key_v1(&legacy_code.secret, &legacy_rec.id).unwrap();
    let mut bob_cfg = NodeConfig::local(NodeId::new("bob@laptop").unwrap(), bob_dir.path());
    bob_cfg.secret_backend = Some(SecretBackend::File);
    let bob = UnifiedNode::open(bob_cfg).unwrap();
    let legacy_binding = PairBindingV2 {
        v: 2,
        grant_id: legacy_rec.id.clone(),
        node_id: "bob@laptop".to_string(),
        signing_jwk: bob.identity().signing_jwk(),
        encryption_jwk: bob.identity().encryption_jwk(),
        bound_at: format_rfc3339_millis(now_ms()),
    };
    let legacy_payload = to_canonical_json(&legacy_binding).unwrap();
    let legacy_req = PairRequestV2 {
        grant_id: legacy_rec.id.clone(),
        payload: legacy_payload.clone(),
        pairing_sig: legacy_pair_kp.sign_domain_b64("binding", legacy_payload.as_bytes()),
        self_sig: bob
            .identity()
            .signing
            .sign_domain_b64("binding-self", legacy_payload.as_bytes()),
    };
    // Omit `signedGrant` completely -> Hub looks up its own SQLite row cleanly!
    let (st_legacy, body_legacy) = send_post_json(
        &client,
        &pair_endpoint,
        &serde_json::to_value(&legacy_req).unwrap(),
    )
    .await;
    assert_eq!(
        st_legacy,
        StatusCode::OK,
        "legacy DB-backed POST /v1/pair without inline signedGrant must succeed: {}",
        String::from_utf8_lossy(&body_legacy)
    );

    bob.shutdown();
    alice.shutdown();
    hub.shutdown();
}

// ============================================================================
// 4. P1-11 (P1): Anti-recon directory scope gate on `GET /v1/keys` & `/v1/handles`
// ============================================================================

#[tokio::test]
async fn p1_11_anti_recon_blocks_guests_and_underscoped_peers_from_enumerating_directory() {
    let hub_dir = TempDir::new().unwrap();
    let alice_dir = TempDir::new().unwrap();
    let stream_dir = TempDir::new().unwrap();

    let admin_ca = Ed25519KeyPair::generate().unwrap();
    let admin_proto_jwk = OkpJwk::new(OkpCurve::Ed25519, &admin_ca.public_key_bytes());

    let mut hub_cfg = NodeConfig::router(NodeId::new("acme-recon-hub").unwrap(), hub_dir.path());
    hub_cfg.secret_backend = Some(SecretBackend::File);
    hub_cfg.admin_jwk = Some(admin_proto_jwk);
    hub_cfg.guest_pairing = GuestPairingConfig {
        enabled: true,
        ..GuestPairingConfig::default()
    };
    let hub = UnifiedNode::open(hub_cfg).unwrap();
    let (hub_addr, _hub_srv) = Arc::clone(&hub).serve(loopback_zero()).await.unwrap();
    let hub_url = format!("http://{hub_addr}");

    // Pair private org member `alice@macbook` and register a private handle `claude-secret`.
    let member_scopes = ScopePreset::Member.expand();
    let member_refs: Vec<&str> = member_scopes.iter().map(String::as_str).collect();
    let (alice_am2, _) = hub
        .create_admin_invite(&admin_ca, "alice@macbook", &member_refs, TrustTier::Org, 300_000)
        .unwrap();
    let mut alice_cfg = NodeConfig::local(NodeId::new("alice@macbook").unwrap(), alice_dir.path());
    alice_cfg.secret_backend = Some(SecretBackend::File);
    let alice = UnifiedNode::open(alice_cfg).unwrap();
    alice.accept_am2_invite(&alice_am2).await.unwrap();
    alice.register_handle("sess-a", "claude-secret").await.unwrap();

    // Pair an under-scoped peer `streamonly@box` with ONLY `stream:subscribe=alerts`
    // (lacking dm:send / channel:join / directory:read / *).
    let (stream_am2, _) = hub
        .create_admin_invite(
            &admin_ca,
            "streamonly@box",
            &["stream:subscribe=alerts"],
            TrustTier::Peer,
            300_000,
        )
        .unwrap();
    let mut stream_cfg = NodeConfig::local(NodeId::new("streamonly@box").unwrap(), stream_dir.path());
    stream_cfg.secret_backend = Some(SecretBackend::File);
    let stream_peer = UnifiedNode::open(stream_cfg).unwrap();
    stream_peer.accept_am2_invite(&stream_am2).await.unwrap();

    // Enroll a public guest (`TrustTier::Guest`).
    let client = HttpClient::new().unwrap();
    let guest_keys = NodeIdentityKeys::generate().unwrap();
    let ts = format_rfc3339_millis(now_ms());
    let g_canon = guest_pair_proof_canonical(
        "acme-recon-hub",
        "guest@visitor",
        &guest_keys.signing_jwk(),
        &guest_keys.encryption_jwk(),
        &ts,
    )
    .unwrap();
    let guest_req = GuestPairRequest {
        node_id: "guest@visitor".to_string(),
        ed25519_jwk: guest_keys.signing_jwk(),
        x25519_jwk: guest_keys.encryption_jwk(),
        timestamp: ts,
        proof_sig: guest_keys
            .signing
            .sign_domain_b64("guest-pair", g_canon.as_bytes()),
    };
    let (st_gp, _) = send_post_json(
        &client,
        &format!("{hub_url}/v1/guest/pair"),
        &serde_json::to_value(&guest_req).unwrap(),
    )
    .await;
    assert_eq!(st_gp, StatusCode::OK);

    let guest_auth = Ed25519AuthBuilder::new("guest@visitor", &guest_keys.signing);
    let stream_auth = Ed25519AuthBuilder::new("streamonly@box", &stream_peer.identity().signing);
    let alice_auth = Ed25519AuthBuilder::new("alice@macbook", &alice.identity().signing);

    // (a) Guest MUST receive 403 on unfiltered & cross-peer `GET /v1/keys` and `GET /v1/handles`!
    for forbidden_path in [
        "/v1/keys",
        "/v1/keys?nodeId=alice%40macbook",
        "/v1/handles",
        "/v1/handles?nodeId=alice%40macbook",
        "/v1/handles?nodeId=acme-recon-hub",
    ] {
        let req = guest_auth.sign_request(Method::GET, &hub_url, forbidden_path, None, None);
        let resp = client.request(req).await.unwrap();
        let (st, _, body) = HttpClient::collect(resp, 64 * 1024).await.unwrap();
        assert_eq!(
            st,
            StatusCode::FORBIDDEN,
            "guest GET {forbidden_path} MUST return 403; got {st}: {}",
            String::from_utf8_lossy(&body)
        );
        assert!(
            !String::from_utf8_lossy(&body).contains("claude-secret"),
            "guest error response must not leak private handles"
        );
    }

    // Guest MAY fetch ONLY the hub's own public key or its own key.
    let self_key_req = guest_auth.sign_request(
        Method::GET,
        &hub_url,
        "/v1/keys?nodeId=acme-recon-hub",
        None,
        None,
    );
    let (st_hub_k, _, body_hub_k) =
        HttpClient::collect(client.request(self_key_req).await.unwrap(), 64 * 1024)
            .await
            .unwrap();
    assert_eq!(st_hub_k, StatusCode::OK);
    let hub_keys_json: Value = serde_json::from_slice(&body_hub_k).unwrap();
    assert_eq!(hub_keys_json["keys"].as_array().unwrap().len(), 1);
    assert_eq!(hub_keys_json["keys"][0]["nodeId"], "acme-recon-hub");

    // (b) Under-scoped `streamonly@box` MUST receive 403 on unfiltered & cross-peer directory!
    for forbidden_path in [
        "/v1/keys",
        "/v1/keys?nodeId=alice%40macbook",
        "/v1/handles",
        "/v1/handles?nodeId=alice%40macbook",
    ] {
        let req = stream_auth.sign_request(Method::GET, &hub_url, forbidden_path, None, None);
        let resp = client.request(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "underscoped peer GET {forbidden_path} MUST return 403"
        );
    }

    // (c) Authorized org member (`alice@macbook`) CAN list keys and handles cleanly!
    let ok_keys = alice_auth.sign_request(Method::GET, &hub_url, "/v1/keys", None, None);
    let (st_ok_k, _, body_ok_k) =
        HttpClient::collect(client.request(ok_keys).await.unwrap(), 64 * 1024)
            .await
            .unwrap();
    assert_eq!(st_ok_k, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body_ok_k).contains("alice@macbook"));

    let ok_handles = alice_auth.sign_request(Method::GET, &hub_url, "/v1/handles", None, None);
    let (st_ok_h, _, body_ok_h) =
        HttpClient::collect(client.request(ok_handles).await.unwrap(), 64 * 1024)
            .await
            .unwrap();
    assert_eq!(st_ok_h, StatusCode::OK);
    assert!(String::from_utf8_lossy(&body_ok_h).contains("claude-secret"));

    stream_peer.shutdown();
    alice.shutdown();
    hub.shutdown();
}
