//! Level 6–7 E2E verification suite for **Option A: Delegated Human-Cert Admission**:
//!
//! Full multi-node scenario against a real loopback Router Hub (`acme-team`):
//! 1. Admin mints signed `hjoin1_` invite (`nodePrefix: "philip@*"`, `maxDevices: 2`, `member` scopes).
//! 2. Philip claims via `POST /v1/auth/claim`:
//!    - First claim succeeds (`200 OK`), enrolling HumanAuthority + delegation policy.
//!    - Replay of the exact same `hjoin1_` fails closed (`409`).
//!    - Anti-hijack: claiming a second `hjoin1_` for `philip` with a DIFFERENT Ed25519 key fails closed (`409 human_key_mismatch`).
//!    - Re-claiming a second `hjoin1_` with Philip's SAME key is idempotent (`200 OK`).
//! 3. Philip's laptop #1 (`philip@macbook`) pairs via `POST /v1/pair/delegated` using `hcert1_` + live `DelegatedPairProofV1`:
//!    - Hub persists `admitted_by_human_id = "philip"`, `admitted_auth_epoch = 1`.
//!    - E2EE DM between `alice@macbook` and `philip@macbook` succeeds with ZERO plaintext in hub `node.sqlite`.
//!    - E2EE Shared KV written by `alice@macbook` (auto-wrapped to all active hub members!) is decrypted by `philip@macbook` with ZERO plaintext in hub `node.sqlite`.
//! 4. Philip's laptop #2 (`philip@devbox`) joins via `POST /v1/pair/delegated` with ZERO new admin invite!
//! 5. Security & quota invariants:
//!    - Idempotent re-pair of `philip@macbook` succeeds without counting as a 3rd device.
//!    - Wrong-prefix cert (`alice@rogue` signed by Philip) fails closed.
//!    - 3rd device (`philip@ipad`) fails closed on `maxDevices: 2` (`429 quota_exceeded`).
//!    - Anti-hijack: another key attempting to pair as `alice@macbook` or `philip@macbook` fails closed.
//! 6. Cascade revocation (`hub.revoke_human_authority_cascade("philip", ...)`):
//!    - Immediately revokes BOTH `philip@macbook` and `philip@devbox`!
//!    - Immediately closes live `/v1/inbox` SSE streams for BOTH devices!
//!    - Invalidates bearer tokens (subsequent API calls fail closed with `401`/`403`)!
//!    - Evicts BOTH revoked devices from the next E2EE Shared KV epoch!
//!    - Blocks any new device certified by revoked `philip` from joining (`401`)!

use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use http::StatusCode;
use http_body_util::BodyExt;
use serde_json::json;
use tempfile::TempDir;
use tokio::time::timeout;

use hyp_crypto::human::{
    HumanInviteClaimV1, HumanInviteV1, NodeCertPayloadV1, encode_hcert1, encode_hjoin1,
    sign_human_invite, sign_human_invite_claim, sign_node_cert,
};
use hyp_crypto::rfc3339::format_rfc3339_millis;
use hyp_crypto::{Ed25519KeyPair, SecretBackend, X25519KeyPair};
use hyp_node::engine::{
    AuthClaimRequest, E2eePolicy, KvNamespaceConfig, KvWriteRequest, NodeConfig, NodeError,
    UnifiedNode,
};
use hyp_proto::address::NodeId;
use hyp_proto::manifest::{KvMode, KvWriteModel, OkpCurve, OkpJwk};
use hyp_proto::scopes::ScopePreset;
use hyp_store::{MailboxEntry, PeerStatus, TrustTier, WriteModel, now_ms, uuid_v4};

fn loopback_zero() -> SocketAddr {
    "127.0.0.1:0".parse().expect("valid loopback addr")
}

fn assert_zero_plaintext_in_sqlite(state_dir: &Path, needle: &str) {
    let needle_bytes = needle.as_bytes();
    for filename in ["node.sqlite", "node.sqlite-wal", "node.sqlite-shm"] {
        let p = state_dir.join(filename);
        if p.exists() {
            let bytes = fs::read(&p).expect("read sqlite file");
            assert!(
                !bytes.windows(needle_bytes.len()).any(|w| w == needle_bytes),
                "SECURITY VIOLATION: found plaintext substring {:?} in {}!",
                needle,
                p.display()
            );
        }
    }
}

async fn wait_for_mailbox_item<F>(
    node: &Arc<UnifiedNode>,
    session_id: &str,
    predicate: F,
) -> MailboxEntry
where
    F: Fn(&MailboxEntry) -> bool,
{
    let mut rx = node.subscribe_local_inbox();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    loop {
        let items = node.peek_local_inbox(session_id, 50).expect("peek inbox");
        if let Some(found) = items.into_iter().find(|e| predicate(e)) {
            let _ = node.db().local().acknowledge_inbox(
                session_id,
                &[found.receipt.as_str()],
                now_ms(),
            );
            return found;
        }
        let now = tokio::time::Instant::now();
        assert!(
            now < deadline,
            "timed out waiting for mailbox item on node '{}' session '{}'",
            node.node_id(),
            session_id
        );
        let _ = timeout(deadline - now, rx.recv()).await;
    }
}

fn make_local_node(node_id: &str, dir: &TempDir) -> Arc<UnifiedNode> {
    let mut cfg = NodeConfig::local(NodeId::new(node_id).unwrap(), dir.path());
    cfg.secret_backend = Some(SecretBackend::File);
    cfg.e2ee_policy = E2eePolicy::Required;
    UnifiedNode::open(cfg).unwrap()
}

fn mint_hjoin1(
    admin_ca: &Ed25519KeyPair,
    hub_node_id: &str,
    hub_endpoint: &str,
    hub_fp: &str,
    human_id: &str,
    node_prefix: &str,
    max_devices: u32,
) -> (String, HumanInviteV1) {
    let now = now_ms();
    let scopes = ScopePreset::Member.expand();
    let invite = HumanInviteV1 {
        v: 1,
        invite_id: uuid_v4(),
        hub_node_id: hub_node_id.to_string(),
        hub_endpoint: hub_endpoint.to_string(),
        hub_fingerprint: Some(hub_fp.to_string()),
        human_id: human_id.to_string(),
        node_prefix: node_prefix.to_string(),
        scopes,
        max_devices,
        issued_at: format_rfc3339_millis(now),
        expires_at: format_rfc3339_millis(now + 3_600_000),
    };
    let signed = sign_human_invite(&invite, admin_ca).unwrap();
    (encode_hjoin1(&signed).unwrap(), invite)
}

fn sign_device_hcert1(
    human_kp: &Ed25519KeyPair,
    human_id: &str,
    auth_epoch: u64,
    device_node: &UnifiedNode,
) -> String {
    let now = now_ms();
    let payload = NodeCertPayloadV1 {
        v: 1,
        node_id: device_node.node_id().to_string(),
        signing_jwk: device_node.identity().signing_jwk(),
        encryption_jwk: device_node.identity().encryption_jwk(),
        human_id: human_id.to_string(),
        human_kid: human_kp.kid(),
        auth_epoch,
        issued_at: format_rfc3339_millis(now),
        expires_at: format_rfc3339_millis(now + 86_400_000),
    };
    let signed = sign_node_cert(&payload, human_kp).unwrap();
    encode_hcert1(&signed).unwrap()
}

#[tokio::test]
async fn delegated_human_admission_multi_device_e2ee_quota_hijack_and_cascade_revocation() {
    let hub_dir = TempDir::new().unwrap();
    let alice_dir = TempDir::new().unwrap();
    let philip1_dir = TempDir::new().unwrap();
    let philip2_dir = TempDir::new().unwrap();
    let philip3_dir = TempDir::new().unwrap();
    let rogue_dir = TempDir::new().unwrap();
    let hijack_dir = TempDir::new().unwrap();

    // 1. Boot `acme-team` Router Hub with Org Admin-CA public key + E2EE Shared KV namespace.
    let admin_ca = Ed25519KeyPair::generate().unwrap();
    let admin_proto_jwk = OkpJwk::new(OkpCurve::Ed25519, &admin_ca.public_key_bytes());

    let mut hub_cfg = NodeConfig::router(NodeId::new("acme-team").unwrap(), hub_dir.path());
    hub_cfg.secret_backend = Some(SecretBackend::File);
    hub_cfg.e2ee_policy = E2eePolicy::Required;
    hub_cfg.admin_jwk = Some(admin_proto_jwk);
    hub_cfg.kv_namespaces.push(KvNamespaceConfig {
        name: "shared".to_string(),
        mode: KvMode::E2ee,
        write_model: KvWriteModel::Shared,
    });

    let hub = UnifiedNode::open(hub_cfg).unwrap();
    let hub_fp = hub.identity().signing.public_key().fingerprint();
    let (hub_addr, _hub_srv) = Arc::clone(&hub).serve(loopback_zero()).await.unwrap();
    let hub_url = format!("http://{hub_addr}");

    // 2. Pair baseline team member `alice@macbook` via standard `am2_` invite.
    let alice = make_local_node("alice@macbook", &alice_dir);
    alice.register_handle("sess-alice", "claude").await.unwrap();
    let member_scopes = ScopePreset::Member.expand();
    let member_refs: Vec<&str> = member_scopes.iter().map(String::as_str).collect();
    let (alice_am2, _) = hub
        .create_admin_invite(&admin_ca, "alice@macbook", &member_refs, TrustTier::Org, 3_600_000)
        .unwrap();
    alice.accept_am2_invite(&alice_am2).await.unwrap();

    // 3. Mint `hjoin1_` for Philip (`philip@*`, `maxDevices: 2`) and claim via `POST /v1/auth/claim`.
    let philip_human = Ed25519KeyPair::generate().unwrap();
    let philip_human_enc = X25519KeyPair::generate().unwrap();
    let (hjoin1_1, inv_1) = mint_hjoin1(
        &admin_ca,
        "acme-team",
        &hub_url,
        &hub_fp,
        "philip",
        "philip@*",
        2,
    );

    let philip1 = make_local_node("philip@macbook", &philip1_dir);
    philip1.register_handle("sess-p1", "codex").await.unwrap();

    let claim_1 = HumanInviteClaimV1 {
        invite_id: inv_1.invite_id.clone(),
        hub_node_id: "acme-team".to_string(),
        human_id: "philip".to_string(),
        signing_jwk: philip_human.to_jwk(),
        enc_jwk: Some(philip_human_enc.to_jwk()),
        prf_salt: Some("prf-salt-philip-1".to_string()),
        timestamp: format_rfc3339_millis(now_ms()),
    };
    let claim_1_sig = sign_human_invite_claim(&claim_1, &philip_human).unwrap();
    let claim_req_1 = AuthClaimRequest {
        hjoin1: hjoin1_1.clone(),
        claim: claim_1,
        claim_sig: claim_1_sig,
        label: Some("passkey-iphone".to_string()),
    };

    let claim_reply = philip1
        .claim_human_invite_on_hub(&hub_url, &claim_req_1)
        .await
        .expect("POST /v1/auth/claim must succeed");
    assert!(claim_reply.ok);
    assert_eq!(claim_reply.hub_node_id, "acme-team");
    assert_eq!(claim_reply.human_id, "philip");
    assert_eq!(claim_reply.kid, philip_human.kid());
    assert_eq!(claim_reply.node_prefix, "philip@*");
    assert_eq!(claim_reply.max_devices, 2);

    // 3b. Replay of the exact same `hjoin1_` MUST fail closed (409)!
    let replay_err = philip1
        .claim_human_invite_on_hub(&hub_url, &claim_req_1)
        .await
        .expect_err("replaying consumed hjoin1_ MUST fail closed");
    match replay_err {
        NodeError::RemoteProblem(p) => assert_eq!(p.status, 409, "unexpected replay problem: {p:?}"),
        other => panic!("expected 409 on hjoin1_ replay, got {other:?}"),
    }

    // 3c. Anti-hijack: claiming a second `hjoin1_` for `philip` with a DIFFERENT key fails closed (`409 human_key_mismatch`)!
    let attacker_human = Ed25519KeyPair::generate().unwrap();
    let (hjoin1_hijack, inv_hijack) = mint_hjoin1(
        &admin_ca,
        "acme-team",
        &hub_url,
        &hub_fp,
        "philip",
        "philip@*",
        2,
    );
    let hijack_claim = HumanInviteClaimV1 {
        invite_id: inv_hijack.invite_id.clone(),
        hub_node_id: "acme-team".to_string(),
        human_id: "philip".to_string(),
        signing_jwk: attacker_human.to_jwk(),
        enc_jwk: None,
        prf_salt: None,
        timestamp: format_rfc3339_millis(now_ms()),
    };
    let hijack_sig = sign_human_invite_claim(&hijack_claim, &attacker_human).unwrap();
    let hijack_err = philip1
        .claim_human_invite_on_hub(
            &hub_url,
            &AuthClaimRequest {
                hjoin1: hjoin1_hijack,
                claim: hijack_claim,
                claim_sig: hijack_sig,
                label: None,
            },
        )
        .await
        .expect_err("hijacking enrolled humanId with different key MUST fail closed");
    match hijack_err {
        NodeError::RemoteProblem(p) => {
            assert_eq!(p.status, 409);
            assert_eq!(p.error, "human_key_mismatch");
        }
        other => panic!("expected 409 human_key_mismatch, got {other:?}"),
    }

    // 3d. Idempotent re-claim of a fresh invite with Philip's SAME key succeeds!
    let (hjoin1_idem, inv_idem) = mint_hjoin1(
        &admin_ca,
        "acme-team",
        &hub_url,
        &hub_fp,
        "philip",
        "philip@*",
        2,
    );
    let idem_claim = HumanInviteClaimV1 {
        invite_id: inv_idem.invite_id.clone(),
        hub_node_id: "acme-team".to_string(),
        human_id: "philip".to_string(),
        signing_jwk: philip_human.to_jwk(),
        enc_jwk: Some(philip_human_enc.to_jwk()),
        prf_salt: Some("prf-salt-philip-1".to_string()),
        timestamp: format_rfc3339_millis(now_ms()),
    };
    let idem_sig = sign_human_invite_claim(&idem_claim, &philip_human).unwrap();
    let idem_reply = philip1
        .claim_human_invite_on_hub(
            &hub_url,
            &AuthClaimRequest {
                hjoin1: hjoin1_idem,
                claim: idem_claim,
                claim_sig: idem_sig,
                label: Some("passkey-iphone".to_string()),
            },
        )
        .await
        .expect("idempotent re-claim with identical key should succeed");
    assert_eq!(idem_reply.kid, philip_human.kid());

    // 4. Philip's laptop #1 (`philip@macbook`) joins via `POST /v1/pair/delegated`.
    let cert_p1 = sign_device_hcert1(&philip_human, "philip", 1, &philip1);
    let (pair1_reply, _) = philip1
        .pair_delegated_with_hub(&hub_url, "acme-team", &cert_p1, Some(&hub_fp))
        .await
        .expect("philip@macbook delegated pair must succeed");
    assert!(pair1_reply.ok);
    assert_eq!(pair1_reply.node_id, "acme-team");
    assert_eq!(pair1_reply.peer_id, "philip@macbook");
    assert_eq!(pair1_reply.human_id, "philip");
    assert_eq!(pair1_reply.auth_epoch, 1);

    // Verify hub DB provenance fields!
    let p1_row = hub.db().peers().get_peer("philip@macbook").unwrap().unwrap();
    assert_eq!(p1_row.status, PeerStatus::Active);
    assert_eq!(p1_row.admitted_by_human_id.as_deref(), Some("philip"));
    assert_eq!(p1_row.admitted_auth_epoch, Some(1));

    // 5. E2EE DM (`alice@macbook` -> `philip@macbook`) succeeds with ZERO plaintext on hub!
    let dm_secret = "DELEGATED-E2EE-DM-SECRET-77123";
    alice
        .send_dm("claude", "philip@macbook/codex", dm_secret)
        .await
        .expect("E2EE DM to delegated peer must succeed");
    let got_dm = wait_for_mailbox_item(&philip1, "sess-p1", |m| m.text == dm_secret).await;
    assert_eq!(got_dm.source, "alice@macbook/claude");
    assert_zero_plaintext_in_sqlite(hub_dir.path(), dm_secret);

    // 6. E2EE Shared KV written by Alice (auto-wrapped to all active hub members!) is readable by Philip #1!
    let kv_secret_1 = "DELEGATED-SHARED-KV-SECRET-ALPHA-9901";
    let kv_w1 = alice
        .kv_set(KvWriteRequest {
            host_node: "acme-team".to_string(),
            namespace: "shared".to_string(),
            key: "release/token".to_string(),
            value: json!({ "token": kv_secret_1 }),
            write_model: WriteModel::Shared,
            owner_id: None,
            allowlist: None,
            expected_version: Some(0),
            ttl_ms: None,
            encrypt: true,
            e2ee_members: None, // auto-wrap for all active hub members!
        })
        .await
        .expect("E2EE shared KV write must succeed");
    assert_eq!(kv_w1.e2ee_epoch, Some(1));
    assert_zero_plaintext_in_sqlite(hub_dir.path(), kv_secret_1);

    let kv_r1 = philip1
        .kv_get("acme-team", "shared", "release/token")
        .await
        .expect("delegated peer philip@macbook must decrypt auto-wrapped E2EE shared KV")
        .expect("KV entry exists");
    assert_eq!(kv_r1.value["token"], kv_secret_1);

    // 7. Philip's laptop #2 (`philip@devbox`) joins with ZERO new admin invite!
    let philip2 = make_local_node("philip@devbox", &philip2_dir);
    philip2.register_handle("sess-p2", "claude").await.unwrap();
    let cert_p2 = sign_device_hcert1(&philip_human, "philip", 1, &philip2);
    let (pair2_reply, _) = philip2
        .pair_delegated_with_hub(&hub_url, "acme-team", &cert_p2, Some(&hub_fp))
        .await
        .expect("philip@devbox delegated pair must succeed with ZERO admin invite");
    assert_eq!(pair2_reply.peer_id, "philip@devbox");
    assert_eq!(pair2_reply.human_id, "philip");

    // 8. Idempotent re-pair of `philip@macbook` succeeds without counting as a 3rd device!
    let (re_pair_reply, _) = philip1
        .pair_delegated_with_hub(&hub_url, "acme-team", &cert_p1, Some(&hub_fp))
        .await
        .expect("idempotent re-pair of philip@macbook must not trip maxDevices=2");
    assert_eq!(re_pair_reply.peer_id, "philip@macbook");

    // 9. Wrong-prefix cert (`alice@rogue` certified by Philip) fails closed!
    let rogue = make_local_node("alice@rogue", &rogue_dir);
    let rogue_cert = sign_device_hcert1(&philip_human, "philip", 1, &rogue);
    let rogue_err = rogue
        .pair_delegated_with_hub(&hub_url, "acme-team", &rogue_cert, Some(&hub_fp))
        .await
        .expect_err("wrong nodePrefix alice@rogue MUST fail closed");
    match rogue_err {
        NodeError::RemoteProblem(p) => assert!(
            p.status == 401 || p.status == 403,
            "expected 401/403 for wrong nodePrefix, got {p:?}"
        ),
        other => panic!("expected RemoteProblem for wrong prefix, got {other:?}"),
    }

    // 10. Anti-hijack: another device holding different keys trying to pair as `philip@macbook` fails closed (`409 peer_key_mismatch`)!
    let hijacker = make_local_node("philip@macbook", &hijack_dir);
    let hijack_cert = sign_device_hcert1(&philip_human, "philip", 1, &hijacker);
    let peer_hijack_err = hijacker
        .pair_delegated_with_hub(&hub_url, "acme-team", &hijack_cert, Some(&hub_fp))
        .await
        .expect_err("hijacking existing active peer with different device key MUST fail closed");
    match peer_hijack_err {
        NodeError::RemoteProblem(p) => {
            assert_eq!(p.status, 409);
            assert_eq!(p.error, "peer_key_mismatch");
        }
        other => panic!("expected 409 peer_key_mismatch, got {other:?}"),
    }

    // 11. `maxDevices: 2` cap blocks 3rd device (`philip@ipad`) with `429 quota_exceeded`!
    let philip3 = make_local_node("philip@ipad", &philip3_dir);
    let cert_p3 = sign_device_hcert1(&philip_human, "philip", 1, &philip3);
    let cap_err = philip3
        .pair_delegated_with_hub(&hub_url, "acme-team", &cert_p3, Some(&hub_fp))
        .await
        .expect_err("3rd device exceeding maxDevices=2 MUST fail closed");
    match cap_err {
        NodeError::RemoteProblem(p) => {
            assert_eq!(p.status, 429);
            assert_eq!(p.error, "quota_exceeded");
        }
        other => panic!("expected 429 quota_exceeded, got {other:?}"),
    }

    // 12. Open live `/v1/inbox` SSE streams for BOTH `philip@macbook` and `philip@devbox`.
    let p1_link = philip1.peer_link("acme-team").await.unwrap();
    let p2_link = philip2.peer_link("acme-team").await.unwrap();
    let mut p1_sse = p1_link.open_inbox_sse(None).await.unwrap().into_body();
    let mut p2_sse = p2_link.open_inbox_sse(None).await.unwrap().into_body();
    let f1 = timeout(Duration::from_secs(3), p1_sse.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert!(std::str::from_utf8(&f1).unwrap().contains(": connected"));
    let f2 = timeout(Duration::from_secs(3), p2_sse.frame())
        .await
        .unwrap()
        .unwrap()
        .unwrap()
        .into_data()
        .unwrap();
    assert!(std::str::from_utf8(&f2).unwrap().contains(": connected"));

    // 13. Cascade-revoke Philip on the hub!
    let (new_min_epoch, revoked_peers) = hub
        .revoke_human_authority_cascade(
            "philip",
            None,
            true,
            r#"{"reason":"offboarding cascade test"}"#,
        )
        .await
        .expect("cascade revocation must succeed");
    assert_eq!(new_min_epoch, 2);
    assert_eq!(
        revoked_peers,
        vec!["philip@devbox".to_string(), "philip@macbook".to_string()]
    );

    // 13a. BOTH live SSE streams MUST terminate promptly!
    let wait_sse_closed = |mut body: hyper::body::Incoming| async move {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
        loop {
            let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
            assert!(!rem.is_zero(), "SSE stream did not close after cascade revocation");
            match timeout(rem, body.frame()).await {
                Ok(None) => return, // clean EOF!
                Ok(Some(Err(_))) => return, // dropped!
                Ok(Some(Ok(_))) => continue,
                Err(_) => panic!("timed out waiting for SSE close after cascade revocation"),
            }
        }
    };
    wait_sse_closed(p1_sse).await;
    wait_sse_closed(p2_sse).await;

    // 13b. Subsequent bearer-authenticated HTTP requests from BOTH revoked devices fail closed!
    let p1_after = p1_link.open_inbox_sse(None).await.unwrap();
    assert!(
        p1_after.status() == StatusCode::UNAUTHORIZED || p1_after.status() == StatusCode::FORBIDDEN,
        "revoked philip@macbook must get 401/403, got {}",
        p1_after.status()
    );
    let p2_after = p2_link.open_inbox_sse(None).await.unwrap();
    assert!(
        p2_after.status() == StatusCode::UNAUTHORIZED || p2_after.status() == StatusCode::FORBIDDEN,
        "revoked philip@devbox must get 401/403, got {}",
        p2_after.status()
    );

    // 13c. Next E2EE Shared KV epoch written by Alice evicts BOTH revoked Philip devices!
    let active_members = hub.db().peers().list_peers(Some(PeerStatus::Active)).unwrap();
    let active_ids: Vec<String> = active_members.into_iter().map(|p| p.peer_id).collect();
    assert_eq!(active_ids, vec!["alice@macbook".to_string()]);

    let post_revoke_secret = "POST-REVOKE-TOP-SECRET-EVICTED-9999";
    let kv_w2 = alice
        .kv_set(KvWriteRequest {
            host_node: "acme-team".to_string(),
            namespace: "shared".to_string(),
            key: "post-revoke/secret".to_string(),
            value: json!({ "secret": post_revoke_secret }),
            write_model: WriteModel::Shared,
            owner_id: None,
            allowlist: None,
            expected_version: Some(0),
            ttl_ms: None,
            encrypt: true,
            e2ee_members: None,
        })
        .await
        .expect("Alice's post-revoke KV write must succeed");
    assert_eq!(kv_w2.e2ee_epoch, Some(2), "KV epoch must rotate from 1 -> 2 after eviction");
    assert_zero_plaintext_in_sqlite(hub_dir.path(), post_revoke_secret);

    // Neither Philip device can read the new KV entry (bearer revoked + excluded from wrapped epoch)!
    assert!(
        philip1
            .kv_get("acme-team", "shared", "post-revoke/secret")
            .await
            .is_err()
    );
    assert!(
        philip2
            .kv_get("acme-team", "shared", "post-revoke/secret")
            .await
            .is_err()
    );

    // Verify on hub DB that epoch 2 wrapped ONLY for Alice (evicting BOTH revoked Philip devices)!
    let latest_epoch = hub
        .db()
        .kv()
        .latest_epoch("acme-team", "shared")
        .unwrap()
        .expect("latest kv epoch exists");
    assert_eq!(latest_epoch.epoch, 2);
    assert!(
        !latest_epoch.members.iter().any(|m| m.starts_with("philip@")),
        "revoked Philip devices MUST be evicted from KV epoch {} members: {:?}",
        latest_epoch.epoch,
        latest_epoch.members
    );
    assert!(
        !latest_epoch.key_envelope_json.contains("philip@macbook")
            && !latest_epoch.key_envelope_json.contains("philip@devbox"),
        "revoked Philip devices MUST NOT receive wrapped keys in KV epoch {}",
        latest_epoch.epoch
    );

    // 13d. Attempting to join a brand-new Philip device after revocation fails closed!
    let post_rev_err = philip3
        .pair_delegated_with_hub(&hub_url, "acme-team", &cert_p3, Some(&hub_fp))
        .await
        .expect_err("joining with revoked human authority MUST fail closed");
    match post_rev_err {
        NodeError::RemoteProblem(p) => assert!(
            p.status == 401 || p.status == 403,
            "expected 401/403 after authority revocation, got {p:?}"
        ),
        other => panic!("expected RemoteProblem after revocation, got {other:?}"),
    }
}
