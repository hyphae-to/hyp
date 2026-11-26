//! Level 5–7 E2E verification suite for Wave 2:
//! - `P1-4`: Live peer revocation drops outbound `PeerLink` via `reconcile_peers`, enforces
//!   active status in `require_peer_link`, and terminates active `/v1/inbox` SSE streams
//!   immediately without pushing further queued items.
//! - `P1-6`: Outbound-only SSE pulled messages, transfers, and batches enforce counter-grant
//!   scopes & active peer status fail-closed with `gate_audit` logging.
//! - `P1-10`: P2P and Guest peers cannot poison `peer_routes` or spoof third-party handles;
//!   Router peers cannot overwrite direct active peers in `peers`.
//! - `P1-18`: Expired grants (`grant.expires_at <= now_ms`) are rejected in `authorize_peer_action`
//!   and HTTP authentication.
//! - `P1-20`: SSE worker stops polling on permanent HTTP `403` revoked/`not_granted` denials
//!   (zero tight-loop retries) and skips/reject-acks malformed SSE items without stalling.
//! - `H4` / `N3` / `N4`: Inbound `to.hyphae.human.revocation.v1` events are handled per-event
//!   (invalid revocations are audited & skipped without poisoning the rest of the batch),
//!   automatically revoke keys and bump `min_auth_epoch` monotonically without bricking a locked
//!   `SecurityGatePipeline`.
//! - `H5`: Old-epoch authority key claiming a forged higher `claim.auth_epoch` fails closed.
//! - `H7`: `X-Forwarded-For` is honored ONLY when the TCP peer IP matches `trusted_proxies`
//!   CIDRs, walking right-to-left skipping trusted hops (`X-Real-Ip` is never trusted).
//! - `N1`: Peer bearer tokens are bound to peer/grant/signing-kid and immediately invalidated on
//!   revoke, re-pair, and `PUT /v1/keys` key rotation.
//! - `H11` & `H15`: Every rejected/expired/revoked/epoch-stale/replayed drop claim writes an
//!   immutable `gate_audit` (`gate.human_drop_rejected`) row with zero secret plaintext;
//!   local `overwrite_secret = true` NEVER overrides human-signed `spec.overwrite = false`.
//! - `H16`: `t3-auth-token`, `t3-session-token`, `staged-join-token`, and `staged-join-token-*`
//!   are blocked fail-closed by `is_reserved_secret_name` and `ingest_human_drop`.

use std::convert::Infallible;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use http::{HeaderMap, Method, Request, Response, StatusCode};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use serde_json::json;
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, watch};

use hyp_crypto::human::{
    HumanAudience, HumanClaimV1, HumanDropEnvelopeV1, HumanDropKind, HumanRevocationPayloadV1,
    SecretDropSpec, SignedHumanClaimV1, human_drop_hpke_aad, human_drop_hpke_info,
    is_reserved_secret_name, seal_human_drop, sign_human_revocation,
};
use hyp_crypto::jcs::to_canonical_json;
use hyp_crypto::rfc3339::format_rfc3339_millis;
use hyp_crypto::{Ed25519KeyPair, NodeIdentityKeys, SecretBackend, X25519PublicKey};
use hyp_node::engine::http_util::{BoxedBody, HttpClient, empty_body, full_body, sse_response};
use hyp_node::engine::node::PeerAction;
use hyp_node::engine::peer_link::{
    KeyRegPayloadV2, PeerAuth, PeerLink, PutKeyRequest, spawn_sse_worker,
};
use hyp_node::engine::server::extract_drop_relay_client_ip;
use hyp_node::engine::{
    DropRelayConfig, E2eePolicy, NodeConfig, NodeError, SubscribeRequest, UnifiedNode,
};
use hyp_node::gates::{SecurityGateConfig, SecurityGatePipeline, sign_gate_policy};
use hyp_proto::address::NodeId;
use hyp_proto::cloudevent::{CloudEvent as ProtoCloudEvent, TYPE_HUMAN_REVOCATION_V1};
use hyp_proto::scopes::ScopePreset;
use hyp_store::{
    CloudEvent as StoreCloudEvent, DeliveryMode, DueBatch, GateAuditQuery, GateDecision,
    GrantDirection, GrantInput, HumanAuthorityInput, HumanAuthorityRole, HumanAuthorityStatus,
    KeyStatus, KeyUse, MailboxEntry, MessageRecord, NodeDb, PeerInput, PeerKeyInput, PeerProfile,
    PeerStatus, RevocationInput, TransferRecord, TrustTier, now_ms, uuid_v4,
};

fn loopback_zero() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

fn make_p2p_config(node_id: &str, dir: &TempDir) -> NodeConfig {
    let mut cfg = NodeConfig::p2p(NodeId::new(node_id).unwrap(), dir.path());
    cfg.secret_backend = Some(SecretBackend::File);
    cfg.e2ee_policy = E2eePolicy::Required;
    cfg
}

fn make_router_config(node_id: &str, dir: &TempDir, admin_ca: &Ed25519KeyPair) -> NodeConfig {
    let mut cfg = NodeConfig::router(NodeId::new(node_id).unwrap(), dir.path());
    cfg.secret_backend = Some(SecretBackend::File);
    cfg.e2ee_policy = E2eePolicy::Required;
    let jwk = admin_ca.to_jwk();
    cfg.admin_jwk = Some(hyp_proto::manifest::OkpJwk {
        kty: jwk.kty,
        crv: hyp_proto::manifest::OkpCurve::Ed25519,
        x: jwk.x,
    });
    cfg
}

async fn wait_for_mailbox_item(
    node: &UnifiedNode,
    session_id: &str,
    predicate: impl Fn(&MailboxEntry) -> bool,
) -> MailboxEntry {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    loop {
        if let Ok(items) = node.peek_local_inbox(session_id, 50) {
            if let Some(found) = items.into_iter().find(&predicate) {
                return found;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for mailbox item on session '{session_id}'"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn enroll_human(
    node: &UnifiedNode,
    human_id: &str,
    kp: &Ed25519KeyPair,
    role: HumanAuthorityRole,
    epoch: u64,
) {
    let jwk_json = serde_json::to_string(&kp.to_jwk()).unwrap();
    node.db()
        .human()
        .upsert_authority(
            &HumanAuthorityInput {
                human_id: human_id.to_string(),
                kid: kp.kid(),
                label: format!("{human_id}-ep{epoch}"),
                role,
                jwk_json,
                enc_jwk_json: None,
                prf_salt: None,
                auth_epoch: epoch,
            },
            now_ms(),
        )
        .unwrap();
}

#[allow(clippy::too_many_arguments)]
fn build_directive_claim(
    human_id: &str,
    kp: &Ed25519KeyPair,
    auth_epoch: u64,
    node_id: &str,
    node_enc_pk: &X25519PublicKey,
    handle: Option<&str>,
    body: &str,
    issued_at_ms: i64,
    expires_at_ms: i64,
) -> HumanClaimV1 {
    HumanClaimV1 {
        v: 1,
        kind: HumanDropKind::Directive,
        claim_id: format!("clm_{}", uuid_v4().replace('-', "")),
        human_id: human_id.to_string(),
        human_kid: kp.kid(),
        auth_epoch,
        issued_at: format_rfc3339_millis(issued_at_ms),
        expires_at: format_rfc3339_millis(expires_at_ms),
        drop_id: String::new(),
        audience: HumanAudience {
            node_id: node_id.to_string(),
            node_enc_kid: node_enc_pk.kid(),
            handle: handle.map(ToOwned::to_owned),
        },
        secret_spec: None,
        body: body.to_string(),
    }
}

#[allow(clippy::too_many_arguments)]
fn build_secret_claim(
    human_id: &str,
    kp: &Ed25519KeyPair,
    auth_epoch: u64,
    node_id: &str,
    node_enc_pk: &X25519PublicKey,
    handle: Option<&str>,
    secret_name: &str,
    overwrite: bool,
    secret_val: &str,
) -> HumanClaimV1 {
    let now = now_ms();
    HumanClaimV1 {
        v: 1,
        kind: HumanDropKind::Secret,
        claim_id: format!("sec_{}", uuid_v4().replace('-', "")),
        human_id: human_id.to_string(),
        human_kid: kp.kid(),
        auth_epoch,
        issued_at: format_rfc3339_millis(now),
        expires_at: format_rfc3339_millis(now + 300_000),
        drop_id: String::new(),
        audience: HumanAudience {
            node_id: node_id.to_string(),
            node_enc_kid: node_enc_pk.kid(),
            handle: handle.map(ToOwned::to_owned),
        },
        secret_spec: Some(SecretDropSpec {
            name: secret_name.to_string(),
            overwrite,
        }),
        body: secret_val.to_string(),
    }
}

/// Seals a claim bypassing `seal_human_drop` sender-side validation (for testing receiver-side
/// fail-closed guards against reserved secret names, expired claims, etc.).
fn manual_seal_unchecked(
    claim: &HumanClaimV1,
    signer: &Ed25519KeyPair,
    recipient_enc_pk: &X25519PublicKey,
) -> HumanDropEnvelopeV1 {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let payload = to_canonical_json(claim).unwrap();
    let mut msg = Vec::new();
    msg.extend_from_slice(hyp_crypto::human::HUMAN_CLAIM_DOMAIN);
    msg.extend_from_slice(payload.as_bytes());
    let sig = URL_SAFE_NO_PAD.encode(signer.sign_raw(&msg));
    let signed = SignedHumanClaimV1 { payload, sig };
    let signed_json = to_canonical_json(&signed).unwrap();
    let padded = hyp_crypto::e2ee::pad_bucket(signed_json.as_bytes()).unwrap();
    let enc_kid = recipient_enc_pk.kid();
    let info = human_drop_hpke_info(&enc_kid, &claim.drop_id);
    let aad = human_drop_hpke_aad(&enc_kid, &claim.drop_id);
    let (enc, ct) = hyp_crypto::hpke::seal_base(recipient_enc_pk, &info, &aad, &padded).unwrap();
    HumanDropEnvelopeV1 {
        v: 1,
        suite: hyp_crypto::human::HUMAN_DROP_SUITE_V1.to_string(),
        drop_id: claim.drop_id.clone(),
        enc: URL_SAFE_NO_PAD.encode(enc),
        ct: URL_SAFE_NO_PAD.encode(ct),
    }
}

// ============================================================================
// 1. P1-4: Live Peer Revocation — Outbound Teardown & Immediate SSE Closure
// ============================================================================

#[tokio::test]
async fn p1_4_live_peer_revocation_drops_outbound_link_and_closes_active_sse_stream() {
    let alice_dir = TempDir::new().unwrap();
    let bob_dir = TempDir::new().unwrap();

    let alice = UnifiedNode::open(make_p2p_config("alice@macbook", &alice_dir)).unwrap();
    let (_alice_addr, _alice_srv) = Arc::clone(&alice).serve(loopback_zero()).await.unwrap();
    alice.register_handle("sess-alice", "claude").await.unwrap();

    let bob = UnifiedNode::open(make_p2p_config("bob@laptop", &bob_dir)).unwrap();
    bob.register_handle("sess-bob", "codex").await.unwrap();

    let (hp2p_tok, _) = alice
        .create_p2p_invite(vec!["dm:*".into()], vec!["dm:*".into()], 300_000)
        .unwrap();
    bob.accept_p2p_invite(&hp2p_tok, vec!["dm:*".into()])
        .await
        .unwrap();

    // Baseline: Alice -> Bob DM succeeds over SSE.
    let pre_msg = "PRE-REVOKE-LEGIT-DM-001";
    alice
        .send_dm("claude", "bob@laptop/codex", pre_msg)
        .await
        .unwrap();
    let got = wait_for_mailbox_item(&bob, "sess-bob", |m| m.text == pre_msg).await;
    assert_eq!(got.source, "alice@macbook/claude");

    // Open an explicit raw `/v1/inbox` SSE stream as Bob to observe immediate termination!
    let bob_link = bob.peer_link("alice@macbook").await.unwrap();
    let sse_resp = bob_link.open_inbox_sse(None).await.unwrap();
    assert_eq!(sse_resp.status(), StatusCode::OK);
    let mut sse_body = sse_resp.into_body();

    // Read the initial `: connected\n\n` frame.
    let first_frame = tokio::time::timeout(Duration::from_secs(3), sse_body.frame())
        .await
        .expect("connected frame timeout")
        .expect("stream open")
        .expect("valid frame");
    let first_bytes = first_frame.into_data().unwrap();
    assert!(
        std::str::from_utf8(&first_bytes)
            .unwrap()
            .contains(": connected")
    );

    // Revoke Bob on Alice AND enqueue a post-revocation DM (which MUST NEVER reach Bob's SSE!).
    let now = now_ms();
    {
        let db = alice.db();
        db.peers()
            .set_peer_status("bob@laptop", PeerStatus::Revoked, now)
            .unwrap();
        for g in db.peers().list_grants(Some("bob@laptop")).unwrap() {
            db.peers()
                .add_revocation(
                    &RevocationInput {
                        grant_id: g.id,
                        peer_id: "bob@laptop".to_string(),
                        signed_json: r#"{"reason":"compromised"}"#.to_string(),
                    },
                    now,
                )
                .unwrap();
        }
    }
    // Wake Alice's SSE handler via `reconcile_peers` (same call triggered by `peers.reload`!).
    let _ = alice.reconcile_peers(Duration::from_secs(2)).await;

    // Active `/v1/inbox` SSE stream MUST terminate cleanly (EOF) without sending any further data!
    let mut leaked_frames = Vec::new();
    let eof_res = tokio::time::timeout(Duration::from_secs(3), async {
        while let Some(frame_res) = sse_body.frame().await {
            if let Ok(frame) = frame_res {
                if let Some(data) = frame.data_ref() {
                    let s = String::from_utf8_lossy(data).to_string();
                    if s.contains("event: message") {
                        leaked_frames.push(s);
                    }
                }
            }
        }
    })
    .await;
    assert!(
        eof_res.is_ok(),
        "active /v1/inbox SSE stream MUST close immediately after peer revocation"
    );
    assert!(
        leaked_frames.is_empty(),
        "revoked SSE stream must never deliver queued messages: {leaked_frames:?}"
    );

    // Subsequent HTTP reconnect from revoked Bob MUST fail closed with 401 Unauthorized!
    let reconnect = bob_link.open_inbox_sse(None).await.unwrap();
    assert_eq!(reconnect.status(), StatusCode::UNAUTHORIZED);

    // Client-side: revoking Alice on Bob makes `require_peer_link` fail closed IMMEDIATELY
    // AND `reconcile_peers` drops the tracked outbound link!
    {
        let db = bob.db();
        db.peers()
            .set_peer_status("alice@macbook", PeerStatus::Revoked, now_ms())
            .unwrap();
    }
    assert!(
        bob.refresh_peer_manifest("alice@macbook").await.is_err(),
        "require_peer_link must fail closed once peer status is Revoked"
    );
    assert!(
        bob.peer_link("alice@macbook").await.is_none(),
        "stale PeerLink must be removed when require_peer_link detects Revoked status"
    );

    // Re-insert a stale link check: verify `reconcile_peers` drops revoked links cleanly.
    let rep = bob.reconcile_peers(Duration::from_secs(2)).await;
    assert!(rep.connected_peers.is_empty());

    bob.shutdown();
    alice.shutdown();
}

// ============================================================================
// 2. P1-6: Pulled Inbound SSE Items Enforce Counter-Grant Scopes Fail-Closed
// ============================================================================

#[tokio::test]
async fn p1_6_outbound_sse_enforces_counter_grant_scopes_fail_closed() {
    let alice_dir = TempDir::new().unwrap();
    let bob_dir = TempDir::new().unwrap();

    let alice = UnifiedNode::open(make_p2p_config("alice@macbook", &alice_dir)).unwrap();
    let (_alice_addr, _alice_srv) = Arc::clone(&alice).serve(loopback_zero()).await.unwrap();
    alice.register_handle("sess-alice", "claude").await.unwrap();

    let bob = UnifiedNode::open(make_p2p_config("bob@laptop", &bob_dir)).unwrap();
    bob.register_handle("sess-bob", "codex").await.unwrap();
    bob.register_handle("sess-other", "other").await.unwrap();

    // Bob ONLY grants Alice `dm:send=bob@laptop/codex` (NO `dm:send=bob@laptop/other`,
    // NO `files:send`, NO `channel:post`, NO `stream:publish`).
    let (hp2p_tok, _) = alice
        .create_p2p_invite(
            ScopePreset::Member.expand(),
            vec!["dm:send=bob@laptop/codex".into()],
            300_000,
        )
        .unwrap();
    bob.accept_p2p_invite(&hp2p_tok, vec!["dm:send=bob@laptop/codex".into()])
        .await
        .unwrap();

    // 1. Authorized DM to `bob@laptop/codex` via SSE succeeds!
    let ok_msg = "AUTHORIZED-SCOPED-DM-CODEX";
    alice
        .send_dm("claude", "bob@laptop/codex", ok_msg)
        .await
        .unwrap();
    let delivered = wait_for_mailbox_item(&bob, "sess-bob", |m| m.text == ok_msg).await;
    assert_eq!(delivered.source, "alice@macbook/claude");

    // 2. Unauthorized DM to `bob@laptop/other` via SSE is rejected fail-closed!
    let unauth_dm = MessageRecord {
        id: uuid_v4(),
        from_addr: "alice@macbook/claude".to_string(),
        to_addr: "bob@laptop/other".to_string(),
        channel: None,
        text: "unauthorized dm".to_string(),
        digest: "deadbeef".to_string(),
        sent_at: now_ms(),
        state: hyp_store::MessageState::Pending,
        reason: None,
        hold_until: 0,
        settled_at: None,
        origin_environment_id: None,
        origin_thread_id: None,
        e2ee_epoch: None,
    };
    let dm_err = bob
        .handle_inbound_peer_message("alice@macbook", unauth_dm)
        .await
        .unwrap_err();
    assert!(
        matches!(dm_err, NodeError::ScopeDenied { .. }),
        "expected ScopeDenied for unauthorized DM target, got {dm_err:?}"
    );
    assert!(bob.peek_local_inbox("sess-other", 10).unwrap().is_empty());

    // 3. Unauthorized `#channel` post via SSE is rejected fail-closed!
    let unauth_chan = MessageRecord {
        id: uuid_v4(),
        from_addr: "alice@macbook/claude".to_string(),
        to_addr: "bob@laptop/codex".to_string(),
        channel: Some("#ops".to_string()),
        text: "unauthorized channel post".to_string(),
        digest: "deadbeef".to_string(),
        sent_at: now_ms(),
        state: hyp_store::MessageState::Pending,
        reason: None,
        hold_until: 0,
        settled_at: None,
        origin_environment_id: None,
        origin_thread_id: None,
        e2ee_epoch: None,
    };
    let chan_err = bob
        .handle_inbound_peer_message("alice@macbook", unauth_chan)
        .await
        .unwrap_err();
    assert!(
        matches!(chan_err, NodeError::ScopeDenied { .. }),
        "expected ScopeDenied for unauthorized channel post, got {chan_err:?}"
    );

    // 4. Unauthorized file transfer via SSE is rejected BEFORE downloading blob!
    let bob_link = bob.peer_link("alice@macbook").await.unwrap();
    let unauth_xfer = TransferRecord {
        id: uuid_v4(),
        from_node: "alice@macbook".to_string(),
        to_node: "bob@laptop".to_string(),
        transfer_type: "transfer.stream.v2".to_string(),
        header_json: "{}".to_string(),
        sha256: "00".repeat(32),
        size: 1024,
        sent_at: now_ms(),
        expires_at: now_ms() + 60_000,
        state: hyp_store::TransferState::Pending,
        reason: None,
        hold_until: 0,
        settled_at: None,
    };
    let xfer_err = bob
        .handle_inbound_peer_transfer("alice@macbook", &bob_link, unauth_xfer)
        .await
        .unwrap_err();
    assert!(
        matches!(xfer_err, NodeError::ScopeDenied { .. }),
        "expected ScopeDenied for unauthorized SSE transfer, got {xfer_err:?}"
    );

    // 5. Unauthorized event batch via SSE is rejected fail-closed!
    let unauth_batch = DueBatch {
        id: uuid_v4(),
        subscription_id: "sub-fake".to_string(),
        origin_node: "alice@macbook".to_string(),
        subscriber: "bob@laptop".to_string(),
        topic: "alerts".to_string(),
        mode: DeliveryMode::Full,
        events: Vec::new(),
        opened_at: now_ms(),
        closed_at: now_ms(),
    };
    let batch_err = bob
        .handle_inbound_peer_batch("alice@macbook", unauth_batch)
        .await
        .unwrap_err();
    assert!(
        matches!(batch_err, NodeError::ScopeDenied { .. }),
        "expected ScopeDenied for unauthorized SSE batch, got {batch_err:?}"
    );

    // Verify immutable `gate_audit` logged `peer.scope_denied` rows for the rejected items!
    let audits = bob
        .db()
        .local()
        .query_gate_audit(&GateAuditQuery {
            decision: Some(GateDecision::Block),
            limit: Some(50),
            ..GateAuditQuery::default()
        })
        .unwrap();
    assert!(
        audits
            .iter()
            .filter(|a| {
                a.origin_node.as_deref() == Some("alice@macbook")
                    && a.categories.iter().any(|c| c == "peer.scope_denied")
            })
            .count()
            >= 4,
        "expected >= 4 peer.scope_denied audit rows, got {}",
        audits.len()
    );

    bob.shutdown();
    alice.shutdown();
}

// ============================================================================
// 3. P1-10: Stop Unverified Route Poisoning
// ============================================================================

#[tokio::test]
async fn p1_10_p2p_and_guest_cannot_poison_routes_or_overwrite_direct_peer() {
    let alice_dir = TempDir::new().unwrap();
    let mallory_dir = TempDir::new().unwrap();
    let victim_dir = TempDir::new().unwrap();
    let org_hub_dir = TempDir::new().unwrap();
    let guest_hub_dir = TempDir::new().unwrap();

    let org_ca = Ed25519KeyPair::generate().unwrap();
    let guest_ca = Ed25519KeyPair::generate().unwrap();

    let alice = UnifiedNode::open(make_p2p_config("alice@macbook", &alice_dir)).unwrap();
    alice.register_handle("sess-alice", "alice").await.unwrap();

    // Direct P2P peer `victim@direct`
    let victim = UnifiedNode::open(make_p2p_config("victim@direct", &victim_dir)).unwrap();
    let (_victim_addr, _victim_srv) = Arc::clone(&victim).serve(loopback_zero()).await.unwrap();
    victim
        .register_handle("sess-victim", "claude")
        .await
        .unwrap();
    let (victim_tok, _) = victim
        .create_p2p_invite(vec!["dm:*".into()], vec!["dm:*".into()], 300_000)
        .unwrap();
    alice
        .accept_p2p_invite(&victim_tok, vec!["dm:*".into()])
        .await
        .unwrap();

    // Malicious P2P peer `mallory@p2p` advertising bogus third-party handles!
    let mallory = UnifiedNode::open(make_p2p_config("mallory@p2p", &mallory_dir)).unwrap();
    let (_mallory_addr, _mallory_srv) = Arc::clone(&mallory).serve(loopback_zero()).await.unwrap();
    mallory
        .register_handle("sess-mallory", "mallory")
        .await
        .unwrap();
    {
        let db = mallory.db();
        db.messages()
            .register_handle("ghost@thirdparty", "agent", None, now_ms())
            .unwrap();
        db.messages()
            .register_handle("victim@direct", "claude", None, now_ms())
            .unwrap();
    }
    let (mallory_tok, _) = mallory
        .create_p2p_invite(vec!["dm:*".into()], vec!["dm:*".into()], 300_000)
        .unwrap();
    alice
        .accept_p2p_invite(&mallory_tok, vec!["dm:*".into()])
        .await
        .unwrap();

    // Guest-tier hub `public-guest-hub` advertising bogus third-party handles!
    let guest_hub = UnifiedNode::open(make_router_config(
        "public-guest-hub",
        &guest_hub_dir,
        &guest_ca,
    ))
    .unwrap();
    let (_guest_addr, _guest_srv) = Arc::clone(&guest_hub).serve(loopback_zero()).await.unwrap();
    {
        let db = guest_hub.db();
        db.messages()
            .register_handle("guest-poison@node", "bot", None, now_ms())
            .unwrap();
    }
    let (guest_am2, _) = guest_hub
        .create_admin_invite(
            &guest_ca,
            "alice@macbook",
            &["dm:*"],
            TrustTier::Guest,
            300_000,
        )
        .unwrap();
    alice.accept_am2_invite(&guest_am2).await.unwrap();
    // Explicitly ensure trust_tier is Guest on Alice's peer row for `public-guest-hub`.
    {
        let db = alice.db();
        let mut p = db.peers().get_peer("public-guest-hub").unwrap().unwrap();
        p.trust_tier = TrustTier::Guest;
        db.peers()
            .upsert_peer(
                &PeerInput {
                    peer_id: p.peer_id,
                    endpoint: p.endpoint,
                    profile: p.profile,
                    trust_tier: TrustTier::Guest,
                    status: p.status,
                    scopes: p.scopes,
                    auth_credential_ref: p.auth_credential_ref,
                },
                now_ms(),
            )
            .unwrap();
    }

    // Legitimate Org Router hub `acme-org-hub` advertising both `legit@teammate` and `victim@direct`.
    let org_hub =
        UnifiedNode::open(make_router_config("acme-org-hub", &org_hub_dir, &org_ca)).unwrap();
    let (_org_addr, _org_srv) = Arc::clone(&org_hub).serve(loopback_zero()).await.unwrap();
    {
        let db = org_hub.db();
        db.messages()
            .register_handle("legit@teammate", "codex", None, now_ms())
            .unwrap();
        db.messages()
            .register_handle("victim@direct", "claude", None, now_ms())
            .unwrap();
    }
    let (org_am2, _) = org_hub
        .create_admin_invite(&org_ca, "alice@macbook", &["dm:*"], TrustTier::Org, 300_000)
        .unwrap();
    alice.accept_am2_invite(&org_am2).await.unwrap();

    // Run full discovery across all connected peers!
    let discovered = alice.discover_peer_handles().await;

    // 1. Mallory (P2P) MUST NOT poison `peer_routes` or appear as `via` for `ghost@thirdparty`!
    assert!(
        alice
            .db()
            .peers()
            .get_peer_route("ghost@thirdparty")
            .unwrap()
            .is_none(),
        "P2P peer must NOT create indirect routes in peer_routes"
    );
    assert!(
        !discovered
            .iter()
            .any(|h| h.node_id == "ghost@thirdparty" && h.via.as_deref() == Some("mallory@p2p")),
        "P2P peer must NOT advertise third-party handles in discover_peer_handles"
    );

    // 2. Guest-tier Router MUST NOT create indirect routes!
    assert!(
        alice
            .db()
            .peers()
            .get_peer_route("guest-poison@node")
            .unwrap()
            .is_none(),
        "Guest-tier peer must NOT create indirect routes in peer_routes"
    );

    // 3. Direct active peer `victim@direct` MUST NEVER be overwritten with an indirect route!
    assert!(
        alice
            .db()
            .peers()
            .get_peer_route("victim@direct")
            .unwrap()
            .is_none(),
        "direct Active peer must NEVER get an indirect route entry"
    );

    // 4. Legitimate Org Router hub STILL learns indirect route for `legit@teammate`!
    let legit_route = alice
        .db()
        .peers()
        .get_peer_route("legit@teammate")
        .unwrap()
        .expect("Org Router hub should legitimately seed route for non-direct teammate");
    assert_eq!(legit_route.via_peer, "acme-org-hub");

    alice.shutdown();
    mallory.shutdown();
    victim.shutdown();
    org_hub.shutdown();
    guest_hub.shutdown();
}

// ============================================================================
// 4. P1-18: Expired Grant Enforced in `authorize_peer_action` & HTTP Auth
// ============================================================================

#[tokio::test]
async fn p1_18_expired_grant_is_rejected_in_authorize_peer_action() {
    let dir = TempDir::new().unwrap();
    let node = UnifiedNode::open(make_p2p_config("host@server", &dir)).unwrap();
    let now = now_ms();

    // Register peer with an already-expired Inbound grant (`expires_at <= now`).
    let expired_kp = Ed25519KeyPair::generate().unwrap();
    {
        let db = node.db();
        db.peers()
            .upsert_peer(
                &PeerInput {
                    peer_id: "expired@peer".to_string(),
                    endpoint: None,
                    profile: PeerProfile::P2p,
                    trust_tier: TrustTier::Peer,
                    status: PeerStatus::Active,
                    scopes: vec!["dm:send=*".to_string(), "dm:receive".to_string()],
                    auth_credential_ref: None,
                },
                now,
            )
            .unwrap();
        db.peers()
            .upsert_peer_key(
                &PeerKeyInput {
                    peer_id: "expired@peer".to_string(),
                    kid: expired_kp.kid(),
                    key_use: KeyUse::Signing,
                    jwk_json: serde_json::to_string(&expired_kp.to_jwk()).unwrap(),
                    status: KeyStatus::Active,
                    expires_at: None,
                },
                now,
            )
            .unwrap();
        db.peers()
            .add_grant(
                &GrantInput {
                    id: "grant-expired-1".to_string(),
                    peer_id: "expired@peer".to_string(),
                    direction: GrantDirection::Inbound,
                    signed_json: "{}".to_string(),
                    scopes: vec!["dm:send=*".to_string(), "dm:receive".to_string()],
                    trust_tier: TrustTier::Peer,
                    issued_at: now - 60_000,
                    pair_by: None,
                    expires_at: Some(now - 1_000),
                },
                now,
            )
            .unwrap();
    }

    let err = node
        .authorize_peer_action(
            "expired@peer",
            PeerAction::DmSend {
                to_addr: "host@server/claude",
            },
        )
        .unwrap_err();
    assert!(
        matches!(err, NodeError::Unauthorized(ref m) if m.contains("expired")),
        "expected Unauthorized(expired) for expired grant, got {err:?}"
    );

    // Adding a valid unexpired grant (`expires_at: None`) authorizes the peer cleanly!
    {
        let db = node.db();
        db.peers()
            .add_grant(
                &GrantInput {
                    id: "grant-valid-2".to_string(),
                    peer_id: "expired@peer".to_string(),
                    direction: GrantDirection::Inbound,
                    signed_json: r#"{"v":2}"#.to_string(),
                    scopes: vec!["dm:send=*".to_string(), "dm:receive".to_string()],
                    trust_tier: TrustTier::Peer,
                    issued_at: now,
                    pair_by: None,
                    expires_at: None,
                },
                now,
            )
            .unwrap();
    }
    let ok_peer = node
        .authorize_peer_action(
            "expired@peer",
            PeerAction::DmSend {
                to_addr: "host@server/claude",
            },
        )
        .unwrap();
    assert_eq!(ok_peer.peer_id, "expired@peer");

    node.shutdown();
}

// ============================================================================
// 5. P1-20: SSE Worker Stops on Permanent 403 & Skips Malformed Items Cleanly
// ============================================================================

#[tokio::test]
async fn p1_20_sse_worker_stops_on_permanent_403_and_skips_malformed_items() {
    // Part A: Permanent HTTP 403 `not_granted` / `revoked` stops polling immediately (1 hit).
    let hits_403 = Arc::new(AtomicUsize::new(0));
    let hits_403_srv = Arc::clone(&hits_403);
    let listener_403 = TcpListener::bind(loopback_zero()).await.unwrap();
    let addr_403 = listener_403.local_addr().unwrap();
    let srv_403 = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener_403.accept().await else {
                break;
            };
            let counter = Arc::clone(&hits_403_srv);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |_req: Request<Incoming>| {
                    let c = Arc::clone(&counter);
                    async move {
                        c.fetch_add(1, Ordering::SeqCst);
                        let body = json!({
                            "error": "not_granted",
                            "detail": "peer has been revoked"
                        })
                        .to_string();
                        Ok::<_, Infallible>(
                            Response::builder()
                                .status(StatusCode::FORBIDDEN)
                                .header(CONTENT_TYPE, "application/problem+json")
                                .body(full_body(body.into_bytes()))
                                .unwrap(),
                        )
                    }
                });
                let _ = AutoServerBuilder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    let dir = TempDir::new().unwrap();
    let node = UnifiedNode::open(make_p2p_config("client@box", &dir)).unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let link_403 = Arc::new(PeerLink::new(
        "revoking-hub",
        format!("http://{addr_403}"),
        node.node_id().clone(),
        Arc::new(
            node.secret_store()
                .load_or_create_node_keys(node.node_id().as_str())
                .unwrap(),
        ),
        PeerAuth::Ed25519,
        HttpClient::new().unwrap(),
    ));
    let worker = spawn_sse_worker(Arc::clone(&node), link_403, shutdown_rx);
    tokio::time::timeout(Duration::from_secs(3), worker)
        .await
        .expect("SSE worker must stop cleanly on permanent 403 revoked/not_granted")
        .unwrap();
    assert_eq!(
        hits_403.load(Ordering::SeqCst),
        1,
        "permanent 403 must stop after 1 request (zero tight-loop retries)"
    );
    let _ = shutdown_tx.send(true);
    srv_403.abort();

    // Part B: Malformed SSE item is skipped & reject-acked cleanly without stalling the stream!
    let acks_seen = Arc::new(AtomicUsize::new(0));
    let acks_srv = Arc::clone(&acks_seen);
    let listener_bad = TcpListener::bind(loopback_zero()).await.unwrap();
    let addr_bad = listener_bad.local_addr().unwrap();
    let srv_bad = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener_bad.accept().await else {
                break;
            };
            let acks = Arc::clone(&acks_srv);
            tokio::spawn(async move {
                let io = TokioIo::new(stream);
                let svc = service_fn(move |req: Request<Incoming>| {
                    let acks = Arc::clone(&acks);
                    async move {
                        if req.method() == Method::GET && req.uri().path() == "/v1/inbox" {
                            let (tx, rx) = mpsc::channel(8);
                            tokio::spawn(async move {
                                let payload = concat!(
                                    ": connected\n\n",
                                    "event: message\nid: message:bad-1\ndata: {broken-json\n\n",
                                    "event: batch\nid: batch:bad-2\ndata: not-valid-json\n\n"
                                );
                                let _ = tx
                                    .send(Ok(hyper::body::Frame::data(bytes::Bytes::from_static(
                                        payload.as_bytes(),
                                    ))))
                                    .await;
                                tokio::time::sleep(Duration::from_secs(10)).await;
                            });
                            Ok::<_, Infallible>(sse_response(rx))
                        } else if req.method() == Method::POST
                            && req.uri().path() == "/v1/inbox/ack"
                        {
                            let _ = req.into_body().collect().await;
                            acks.fetch_add(1, Ordering::SeqCst);
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header(CONTENT_TYPE, "application/json")
                                    .body(full_body(br#"{"acked":true}"#.to_vec()))
                                    .unwrap(),
                            )
                        } else {
                            Ok::<_, Infallible>(
                                Response::builder()
                                    .status(StatusCode::NOT_FOUND)
                                    .body(full_body(Vec::new()))
                                    .unwrap(),
                            )
                        }
                    }
                });
                let _ = AutoServerBuilder::new(TokioExecutor::new())
                    .serve_connection(io, svc)
                    .await;
            });
        }
    });

    let (shutdown_tx2, shutdown_rx2) = watch::channel(false);
    let link_bad = Arc::new(PeerLink::new(
        "malformed-hub",
        format!("http://{addr_bad}"),
        node.node_id().clone(),
        Arc::new(
            node.secret_store()
                .load_or_create_node_keys(node.node_id().as_str())
                .unwrap(),
        ),
        PeerAuth::Ed25519,
        HttpClient::new().unwrap(),
    ));
    let worker2 = spawn_sse_worker(Arc::clone(&node), link_bad, shutdown_rx2);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        if acks_seen.load(Ordering::SeqCst) >= 2 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "SSE worker must skip & reject-ack both malformed frames without stalling (got {})",
            acks_seen.load(Ordering::SeqCst)
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }

    let _ = shutdown_tx2.send(true);
    worker2.abort();
    srv_bad.abort();
    node.shutdown();
}

// ============================================================================
// 6. H4: Inbound `to.hyphae.human.revocation.v1` Auto-Revokes Key & Bumps Epoch
// ============================================================================

#[tokio::test]
async fn h4_inbound_revocation_event_revokes_key_and_bumps_min_epoch_automatically() {
    let hub_dir = TempDir::new().unwrap();
    let worker_dir = TempDir::new().unwrap();
    let admin_ca = Ed25519KeyPair::generate().unwrap();

    let hub = UnifiedNode::open(make_router_config("acme-hub", &hub_dir, &admin_ca)).unwrap();
    let (_hub_addr, _hub_srv) = Arc::clone(&hub).serve(loopback_zero()).await.unwrap();

    let worker = UnifiedNode::open(make_p2p_config("worker@box", &worker_dir)).unwrap();
    worker.register_handle("sess-worker", "ops").await.unwrap();

    let scopes = ScopePreset::Member.expand();
    let scope_refs: Vec<&str> = scopes.iter().map(String::as_str).collect();
    let (am2, _) = hub
        .create_admin_invite(
            &admin_ca,
            "worker@box",
            &scope_refs,
            TrustTier::Org,
            300_000,
        )
        .unwrap();
    worker.accept_am2_invite(&am2).await.unwrap();

    // Enroll human Admin (epoch 1) and Signer (epoch 1) on `worker@box`.
    let human_admin = Ed25519KeyPair::generate().unwrap();
    let lost_phone = Ed25519KeyPair::generate().unwrap();
    enroll_human(
        &worker,
        "bogdan",
        &human_admin,
        HumanAuthorityRole::Admin,
        1,
    );
    enroll_human(
        &worker,
        "bogdan",
        &lost_phone,
        HumanAuthorityRole::Signer,
        1,
    );
    assert_eq!(worker.db().human().min_auth_epoch().unwrap(), 1);

    // N3: Lock a signed SecurityGatePipeline on `worker@box` anchored to `authorities_digest`
    // BEFORE any revocation arrives.
    let initial_digest = worker.db().human().authorities_digest().unwrap();
    let mut gate_cfg = SecurityGateConfig {
        require_signed_policy: true,
        human_authorities_digest: Some(initial_digest),
        ..SecurityGateConfig::default()
    };
    gate_cfg.policy_signature = Some(sign_gate_policy(&gate_cfg, worker.secret_store()).unwrap());
    let gate_db = Arc::new(Mutex::new(
        NodeDb::open(worker_dir.path().join("node.sqlite")).unwrap(),
    ));
    let worker_gate = SecurityGatePipeline::new(
        gate_cfg,
        gate_db,
        Some(Arc::new(worker.secret_store().clone())),
    )
    .unwrap();
    assert!(!worker_gate.is_policy_tampered());

    // Subscribe `worker@box` to `acme-hub.security`.
    worker
        .subscribe_local_or_remote(SubscribeRequest {
            id: Some("sub-revocations".to_string()),
            subscriber_session: "sess-worker".to_string(),
            qualified_topic: "acme-hub.security".to_string(),
            filters: Vec::new(),
            coalesce_seconds: 0,
            mode: DeliveryMode::Full,
        })
        .await
        .unwrap();

    // 1. N4: Mixed batch containing a forged revocation (non-admin signer), a malformed
    //    revocation event, AND a valid normal event MUST handle revocations per-event:
    //    log + audit the bad revocation events and STILL deliver the valid normal event!
    let forged_rev = sign_human_revocation(
        &HumanRevocationPayloadV1 {
            v: 1,
            human_id: "bogdan".to_string(),
            revoked_kid: human_admin.kid(),
            new_min_auth_epoch: 9,
            revoked_at: format_rfc3339_millis(now_ms()),
            reason: "forged".to_string(),
            issuer_kid: lost_phone.kid(),
        },
        &lost_phone,
    )
    .unwrap();
    let mixed_batch = DueBatch {
        id: uuid_v4(),
        subscription_id: "sub-revocations".to_string(),
        origin_node: "acme-hub".to_string(),
        subscriber: "worker@box".to_string(),
        topic: "security".to_string(),
        mode: DeliveryMode::Full,
        events: vec![
            StoreCloudEvent {
                specversion: "1.0".to_string(),
                id: "forged-rev-1".to_string(),
                source: "acme-hub".to_string(),
                event_type: TYPE_HUMAN_REVOCATION_V1.to_string(),
                datacontenttype: "application/json".to_string(),
                subject: None,
                time: Some(format_rfc3339_millis(now_ms())),
                dataschema: None,
                data: serde_json::to_value(&forged_rev).unwrap(),
                extensions: Default::default(),
            },
            StoreCloudEvent {
                specversion: "1.0".to_string(),
                id: "malformed-rev-2".to_string(),
                source: "acme-hub".to_string(),
                event_type: TYPE_HUMAN_REVOCATION_V1.to_string(),
                datacontenttype: "application/json".to_string(),
                subject: None,
                time: Some(format_rfc3339_millis(now_ms())),
                dataschema: None,
                data: json!({"garbage": true}),
                extensions: Default::default(),
            },
            StoreCloudEvent {
                specversion: "1.0".to_string(),
                id: "good-security-ping".to_string(),
                source: "acme-hub".to_string(),
                event_type: "to.hyphae.security.notice".to_string(),
                datacontenttype: "application/json".to_string(),
                subject: None,
                time: Some(format_rfc3339_millis(now_ms())),
                dataschema: None,
                data: json!({"status": "batch-survived"}),
                extensions: Default::default(),
            },
        ],
        opened_at: now_ms(),
        closed_at: now_ms(),
    };
    worker
        .handle_inbound_peer_batch("acme-hub", mixed_batch)
        .await
        .expect("N4: junk revocation events must not poison valid siblings in the same batch");
    assert_eq!(worker.db().human().min_auth_epoch().unwrap(), 1);
    assert_eq!(
        worker
            .db()
            .human()
            .get_authority("bogdan", &human_admin.kid())
            .unwrap()
            .unwrap()
            .status,
        HumanAuthorityStatus::Active
    );
    // Both invalid revocations were audited as `human.revocation_rejected`.
    let rejected_rev_audits: Vec<_> = worker
        .db()
        .local()
        .query_gate_audit(&GateAuditQuery {
            decision: Some(GateDecision::Block),
            limit: Some(20),
            ..GateAuditQuery::default()
        })
        .unwrap()
        .into_iter()
        .filter(|a| {
            a.categories
                .iter()
                .any(|c| c == "human.revocation_rejected")
        })
        .collect();
    assert!(
        rejected_rev_audits.len() >= 2,
        "N4: expected >= 2 human.revocation_rejected audit rows, got {}",
        rejected_rev_audits.len()
    );
    // Valid sibling event in the same batch was delivered cleanly to `sess-worker`!
    let delivered = wait_for_mailbox_item(&worker, "sess-worker", |item| {
        let raw = serde_json::to_string(item).unwrap_or_default();
        raw.contains("good-security-ping") && raw.contains("batch-survived")
    })
    .await;
    let delivered_raw = serde_json::to_string(&delivered).unwrap();
    assert!(
        !delivered_raw.contains("forged-rev-1") && !delivered_raw.contains("malformed-rev-2"),
        "N4: rejected revocation events must not be delivered into mailbox"
    );

    // 2. Authentic Admin-signed `to.hyphae.human.revocation.v1` published on `acme-hub.security`
    //    flows over real SSE into `worker@box` and automatically revokes `lost_phone` + bumps epoch -> 3!
    let valid_rev = sign_human_revocation(
        &HumanRevocationPayloadV1 {
            v: 1,
            human_id: "bogdan".to_string(),
            revoked_kid: lost_phone.kid(),
            new_min_auth_epoch: 3,
            revoked_at: format_rfc3339_millis(now_ms()),
            reason: "lost phone".to_string(),
            issuer_kid: human_admin.kid(),
        },
        &human_admin,
    )
    .unwrap();
    let rev_ce = ProtoCloudEvent::new(
        format!("rev-{}", uuid_v4()),
        "human:bogdan",
        TYPE_HUMAN_REVOCATION_V1,
        serde_json::to_value(&valid_rev).unwrap(),
    );
    hub.publish_event("local.security", rev_ce).await.unwrap();

    let deadline = tokio::time::Instant::now() + Duration::from_secs(6);
    loop {
        let min_ep = worker.db().human().min_auth_epoch().unwrap();
        let rec = worker
            .db()
            .human()
            .get_authority("bogdan", &lost_phone.kid())
            .unwrap()
            .unwrap();
        if min_ep == 3 && rec.status == HumanAuthorityStatus::Revoked {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for inbound H4 revocation event (epoch={min_ep}, status={:?})",
            rec.status
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // N3: Applying a cryptographically verified mesh revocation MUST NOT brick the locked gate!
    assert!(
        !worker_gate.is_policy_tampered(),
        "N3: valid mesh revocation must not trigger gate_policy_tampered"
    );
    worker_gate
        .verify_policy_integrity()
        .expect("N3: locked gate policy integrity must stay valid after monotonic revocation");

    // Simultaneously, any claim signed by the revoked `lost_phone` key MUST immediately fail closed!
    let now = now_ms();
    let revoked_claim = build_directive_claim(
        "bogdan",
        &lost_phone,
        1,
        worker.node_id().as_str(),
        &worker.identity().encryption.public_key(),
        Some("ops"),
        "claim from revoked phone",
        now,
        now + 300_000,
    );
    let revoked_env = seal_human_drop(
        &revoked_claim,
        &lost_phone,
        &worker.identity().encryption.public_key(),
    )
    .unwrap();
    assert!(
        matches!(
            worker
                .ingest_human_drop(&revoked_env, Some(&worker_gate), false)
                .await,
            Err(NodeError::Unauthorized(_))
        ),
        "N3: revoked key must be rejected fail-closed immediately"
    );

    // 3. Re-delivering the exact same revocation batch is idempotent & monotonic!
    let replay_rev_batch = DueBatch {
        id: uuid_v4(),
        subscription_id: "sub-revocations".to_string(),
        origin_node: "acme-hub".to_string(),
        subscriber: "worker@box".to_string(),
        topic: "security".to_string(),
        mode: DeliveryMode::Full,
        events: vec![StoreCloudEvent {
            specversion: "1.0".to_string(),
            id: uuid_v4(),
            source: "acme-hub".to_string(),
            event_type: TYPE_HUMAN_REVOCATION_V1.to_string(),
            datacontenttype: "application/json".to_string(),
            subject: None,
            time: Some(format_rfc3339_millis(now_ms())),
            dataschema: None,
            data: serde_json::to_value(&valid_rev).unwrap(),
            extensions: Default::default(),
        }],
        opened_at: now_ms(),
        closed_at: now_ms(),
    };
    worker
        .handle_inbound_peer_batch("acme-hub", replay_rev_batch)
        .await
        .unwrap();
    assert_eq!(worker.db().human().min_auth_epoch().unwrap(), 3);
    assert!(!worker_gate.is_policy_tampered());

    // 4. N3 tamper check: enrolling an unauthorized new authority row directly in SQLite STILL
    //    flips the locked gate immediately to tampered!
    let rogue_authority = Ed25519KeyPair::generate().unwrap();
    enroll_human(
        &worker,
        "rogue",
        &rogue_authority,
        HumanAuthorityRole::Admin,
        3,
    );
    assert!(
        worker_gate.is_policy_tampered(),
        "N3: unauthorized human_authorities insertion must still trigger gate_policy_tampered"
    );

    worker.shutdown();
    hub.shutdown();
}

// ============================================================================
// 7. H5: Old-Epoch Key Claiming Fake Higher `claim.auth_epoch` Fails Closed
// ============================================================================

#[tokio::test]
async fn h5_old_epoch_key_spoofing_higher_claim_epoch_is_rejected() {
    let dir = TempDir::new().unwrap();
    let node = UnifiedNode::open(make_p2p_config("epoch@test", &dir)).unwrap();
    node.register_handle("sess-ops", "ops").await.unwrap();

    let admin_ep1 = Ed25519KeyPair::generate().unwrap();
    let signer_ep1 = Ed25519KeyPair::generate().unwrap();
    enroll_human(&node, "bogdan", &admin_ep1, HumanAuthorityRole::Admin, 1);
    enroll_human(&node, "bogdan", &signer_ep1, HumanAuthorityRole::Signer, 1);

    // Bump `min_auth_epoch` to 2 by revoking `signer_ep1`.
    let rev = sign_human_revocation(
        &HumanRevocationPayloadV1 {
            v: 1,
            human_id: "bogdan".to_string(),
            revoked_kid: signer_ep1.kid(),
            new_min_auth_epoch: 2,
            revoked_at: format_rfc3339_millis(now_ms()),
            reason: "rotate to epoch 2".to_string(),
            issuer_kid: admin_ep1.kid(),
        },
        &admin_ep1,
    )
    .unwrap();
    node.ingest_human_revocation(&rev).unwrap();
    assert_eq!(node.db().human().min_auth_epoch().unwrap(), 2);

    // ATTACK: Old epoch-1 key (`rec.auth_epoch == 1`) lies and sets `claim.auth_epoch = 2`!
    let now = now_ms();
    let spoofed_claim = build_directive_claim(
        "bogdan",
        &admin_ep1,
        2,
        node.node_id().as_str(),
        &node.identity().encryption.public_key(),
        Some("ops"),
        "Spoofed epoch 2 directive",
        now,
        now + 300_000,
    );
    let spoofed_env = seal_human_drop(
        &spoofed_claim,
        &admin_ep1,
        &node.identity().encryption.public_key(),
    )
    .unwrap();
    let err = node
        .ingest_human_drop(&spoofed_env, None, false)
        .await
        .unwrap_err();
    assert!(
        matches!(err, NodeError::Unauthorized(_)),
        "H5: old-epoch key lying about claim.auth_epoch must fail closed, got {err:?}"
    );

    // Enroll genuine epoch-2 key: claiming mismatched epoch 3 STILL fails closed!
    let admin_ep2 = Ed25519KeyPair::generate().unwrap();
    enroll_human(&node, "bogdan", &admin_ep2, HumanAuthorityRole::Admin, 2);

    let mismatched_claim = build_directive_claim(
        "bogdan",
        &admin_ep2,
        3,
        node.node_id().as_str(),
        &node.identity().encryption.public_key(),
        Some("ops"),
        "Mismatched epoch 3 claim from epoch-2 key",
        now,
        now + 300_000,
    );
    let mismatched_env = seal_human_drop(
        &mismatched_claim,
        &admin_ep2,
        &node.identity().encryption.public_key(),
    )
    .unwrap();
    assert!(matches!(
        node.ingest_human_drop(&mismatched_env, None, false).await,
        Err(NodeError::Unauthorized(_))
    ));

    // Genuine epoch-2 key with exact `claim.auth_epoch == 2` succeeds!
    let valid_claim = build_directive_claim(
        "bogdan",
        &admin_ep2,
        2,
        node.node_id().as_str(),
        &node.identity().encryption.public_key(),
        Some("ops"),
        "Legit epoch 2 directive",
        now,
        now + 300_000,
    );
    let valid_env = seal_human_drop(
        &valid_claim,
        &admin_ep2,
        &node.identity().encryption.public_key(),
    )
    .unwrap();
    let ok = node
        .ingest_human_drop(&valid_env, None, false)
        .await
        .unwrap();
    assert_eq!(ok.claim_id, valid_claim.claim_id);

    node.shutdown();
}

// ============================================================================
// 8. H7: Drop Relay `X-Forwarded-For` Trusted Reverse Proxy Enforcement
// ============================================================================

#[tokio::test]
async fn h7_drop_relay_xff_honored_only_when_behind_trusted_reverse_proxy() {
    // 1. Pure extraction matrix: empty list, loopback-only, explicit IPv4/IPv6 CIDRs,
    //    right-to-left skipping of trusted hops, and strict ignoring of `X-Real-Ip`.
    let mut xff_hdrs = HeaderMap::new();
    xff_hdrs.insert(
        "x-forwarded-for",
        HeaderValue::from_static("198.51.100.1, 203.0.113.9, 10.0.0.5, 127.0.0.1"),
    );

    let none_trusted: Vec<String> = Vec::new();
    let loopback_trusted = vec!["127.0.0.1/32".to_string(), "::1/128".to_string()];
    let vpc_and_loopback_trusted = vec![
        "127.0.0.1/32".to_string(),
        "10.0.0.0/24".to_string(),
        "fd00::/64".to_string(),
    ];

    // Empty trusted_proxies -> ALWAYS uses TCP peer IP (even from 127.0.0.1!)
    assert_eq!(
        extract_drop_relay_client_ip(IpAddr::V4(Ipv4Addr::LOCALHOST), &xff_hdrs, &none_trusted),
        "127.0.0.1"
    );
    // Public internet peer IP -> NEVER trusts X-Forwarded-For even when proxies are configured!
    assert_eq!(
        extract_drop_relay_client_ip(
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
            &xff_hdrs,
            &vpc_and_loopback_trusted
        ),
        "203.0.113.5"
    );
    // Loopback-only list MUST NOT trust an unconfigured RFC1918 VPC/Fly neighbor (10.0.0.5)!
    assert_eq!(
        extract_drop_relay_client_ip(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            &xff_hdrs,
            &loopback_trusted
        ),
        "10.0.0.5"
    );
    // Loopback proxy with loopback-only list stops at rightmost non-trusted entry (10.0.0.5).
    assert_eq!(
        extract_drop_relay_client_ip(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &xff_hdrs,
            &loopback_trusted
        ),
        "10.0.0.5"
    );
    // Explicit CIDR list walks right-to-left skipping BOTH 127.0.0.1 and 10.0.0.5 -> 203.0.113.9!
    assert_eq!(
        extract_drop_relay_client_ip(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &xff_hdrs,
            &vpc_and_loopback_trusted
        ),
        "203.0.113.9"
    );
    assert_eq!(
        extract_drop_relay_client_ip(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
            &xff_hdrs,
            &vpc_and_loopback_trusted
        ),
        "203.0.113.9"
    );
    assert_eq!(
        extract_drop_relay_client_ip(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
            &xff_hdrs,
            &vpc_and_loopback_trusted
        ),
        "203.0.113.9"
    );
    // H7: `X-Real-Ip` is NEVER trusted even from a trusted loopback proxy!
    let mut real_ip_hdrs = HeaderMap::new();
    real_ip_hdrs.insert("x-real-ip", HeaderValue::from_static("198.51.100.42"));
    assert_eq!(
        extract_drop_relay_client_ip(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &real_ip_hdrs,
            &loopback_trusted
        ),
        "127.0.0.1"
    );
    assert_eq!(
        extract_drop_relay_client_ip(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &real_ip_hdrs,
            &none_trusted
        ),
        "127.0.0.1"
    );

    // 2. Real HTTP E2E test proving per-IP rate limiting ignores XFF when `trusted_proxies` is
    //    empty and enforces rightmost non-trusted XFF when `trusted_proxies` matches the proxy!
    let relay_cfg = DropRelayConfig {
        enabled: true,
        creates_per_hour_per_ip: 1,
        creates_per_hour_per_node: 10,
        max_active_drops_per_node: 10,
        ..DropRelayConfig::default()
    };

    let make_signed_post_drop =
        |node: &UnifiedNode, addr: SocketAddr, xff: &str| -> Request<BoxedBody> {
            let path = "/v1/drops";
            let body_bytes = br#"{"ttlSeconds":60}"#;
            let body_sha = hyp_store::sha256_hex(body_bytes);
            let ts = now_ms();
            let nonce = uuid_v4();
            let signing_input = format!("POST\n{path}\n{ts}\n{nonce}\n{body_sha}");
            let sig = node
                .identity()
                .signing
                .sign_domain_b64("http-auth", signing_input.as_bytes());
            let auth = format!(
                "Hyphae-Ed25519 node=\"{}\",ts=\"{ts}\",nonce=\"{nonce}\",sig=\"{sig}\"",
                node.node_id().as_str()
            );
            Request::builder()
                .method(Method::POST)
                .uri(format!("http://{addr}{path}"))
                .header(AUTHORIZATION, auth)
                .header(CONTENT_TYPE, "application/json")
                .header("x-forwarded-for", xff)
                .body(full_body(body_bytes.to_vec()))
                .unwrap()
        };

    let client = HttpClient::new().unwrap();

    // Case A: empty `trusted_proxies` -> XFF ignored -> 2nd request rate-limited (429)!
    let dir_direct = TempDir::new().unwrap();
    let mut cfg_direct = make_p2p_config("relay-direct", &dir_direct);
    cfg_direct.drop_relay = relay_cfg.clone();
    cfg_direct.trusted_proxies = Vec::new();
    let node_direct = UnifiedNode::open(cfg_direct).unwrap();
    let (addr_direct, _srv_direct) = Arc::clone(&node_direct)
        .serve(loopback_zero())
        .await
        .unwrap();

    let r1 = client
        .request(make_signed_post_drop(
            &node_direct,
            addr_direct,
            "198.51.100.10",
        ))
        .await
        .unwrap();
    assert_eq!(r1.status(), StatusCode::CREATED);
    let r2 = client
        .request(make_signed_post_drop(
            &node_direct,
            addr_direct,
            "198.51.100.11",
        ))
        .await
        .unwrap();
    assert_eq!(
        r2.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "when trusted_proxies is empty, XFF must be ignored so 2nd loopback request hits 429"
    );
    node_direct.shutdown();

    // Case B: `trusted_proxies = ["127.0.0.1/32", "::1/128"]` -> honors rightmost non-trusted XFF!
    let dir_proxied = TempDir::new().unwrap();
    let mut cfg_proxied = make_p2p_config("relay-proxied", &dir_proxied);
    cfg_proxied.drop_relay = relay_cfg;
    cfg_proxied.trusted_proxies = loopback_trusted;
    let node_proxied = UnifiedNode::open(cfg_proxied).unwrap();
    let (addr_proxied, _srv_proxied) = Arc::clone(&node_proxied)
        .serve(loopback_zero())
        .await
        .unwrap();

    let p1 = client
        .request(make_signed_post_drop(
            &node_proxied,
            addr_proxied,
            "198.51.100.10",
        ))
        .await
        .unwrap();
    assert_eq!(p1.status(), StatusCode::CREATED);
    let p2 = client
        .request(make_signed_post_drop(
            &node_proxied,
            addr_proxied,
            "198.51.100.11",
        ))
        .await
        .unwrap();
    assert_eq!(
        p2.status(),
        StatusCode::CREATED,
        "distinct client IPs behind trusted reverse proxy must have separate rate-limit buckets"
    );
    // Spoofing left-side IP while rightmost non-trusted remains `198.51.100.10` MUST hit 429!
    let p3 = client
        .request(make_signed_post_drop(
            &node_proxied,
            addr_proxied,
            "1.2.3.4, 198.51.100.10, 127.0.0.1",
        ))
        .await
        .unwrap();
    assert_eq!(
        p3.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "rightmost non-trusted XFF entry must defeat left-side spoofing"
    );
    node_proxied.shutdown();
}

// ============================================================================
// 9. H11 & H15: Rejected/Replayed Drops Write Audit Rows; Signed `overwrite=false` Governs
// ============================================================================

#[tokio::test]
async fn h11_and_h15_rejected_drops_audit_without_secret_leak_and_signed_overwrite_governs() {
    let dir = TempDir::new().unwrap();
    let node = UnifiedNode::open(make_p2p_config("audit@test", &dir)).unwrap();
    node.register_handle("sess-ops", "ops").await.unwrap();

    let gate_db = Arc::new(Mutex::new(
        NodeDb::open(dir.path().join("node.sqlite")).unwrap(),
    ));
    let gate = SecurityGatePipeline::new(
        SecurityGateConfig::default(),
        gate_db,
        Some(Arc::new(node.secret_store().clone())),
    )
    .unwrap();

    let human_kp = Ed25519KeyPair::generate().unwrap();
    let rogue_kp = Ed25519KeyPair::generate().unwrap();
    enroll_human(&node, "bogdan", &human_kp, HumanAuthorityRole::Admin, 1);

    // 1. Store initial secret `api-secret`.
    let initial_secret = "CANARY_INITIAL_SECRET_999111";
    let c1 = build_secret_claim(
        "bogdan",
        &human_kp,
        1,
        node.node_id().as_str(),
        &node.identity().encryption.public_key(),
        Some("ops"),
        "api-secret",
        false,
        initial_secret,
    );
    let e1 = seal_human_drop(&c1, &human_kp, &node.identity().encryption.public_key()).unwrap();
    node.ingest_human_drop(&e1, Some(&gate), false)
        .await
        .unwrap();

    // 2. H15: Second secret claim with signed `overwrite: false` MUST fail with Conflict EVEN
    //    when caller passes `overwrite_secret = true`!
    let blocked_secret = "CANARY_NEVER_WRITTEN_888222";
    let c2 = build_secret_claim(
        "bogdan",
        &human_kp,
        1,
        node.node_id().as_str(),
        &node.identity().encryption.public_key(),
        Some("ops"),
        "api-secret",
        false,
        blocked_secret,
    );
    let e2 = seal_human_drop(&c2, &human_kp, &node.identity().encryption.public_key()).unwrap();
    let err_overwrite = node
        .ingest_human_drop(&e2, Some(&gate), true)
        .await
        .unwrap_err();
    assert!(matches!(err_overwrite, NodeError::Conflict(_)));
    assert_eq!(
        node.secret_store().get("api-secret").unwrap().as_str(),
        initial_secret
    );

    // 3. H15: Secret claim with human-signed `overwrite: true` succeeds even with `overwrite_secret = false`.
    let rotated_secret = "CANARY_ROTATED_SECRET_777333";
    let c3 = build_secret_claim(
        "bogdan",
        &human_kp,
        1,
        node.node_id().as_str(),
        &node.identity().encryption.public_key(),
        Some("ops"),
        "api-secret",
        true,
        rotated_secret,
    );
    let e3 = seal_human_drop(&c3, &human_kp, &node.identity().encryption.public_key()).unwrap();
    node.ingest_human_drop(&e3, Some(&gate), false)
        .await
        .unwrap();
    assert_eq!(
        node.secret_store().get("api-secret").unwrap().as_str(),
        rotated_secret
    );

    // 4. H11: Trigger replay, unknown authority, and expired claim rejections and verify every
    //    one writes an immutable `gate.human_drop_rejected` row with zero secret leakage!
    // (a) Replay of e3
    assert!(matches!(
        node.ingest_human_drop(&e3, Some(&gate), false).await,
        Err(NodeError::Unauthorized(_))
    ));
    // (b) Unknown authority key
    let now = now_ms();
    let c_rogue = build_directive_claim(
        "attacker",
        &rogue_kp,
        1,
        node.node_id().as_str(),
        &node.identity().encryption.public_key(),
        Some("ops"),
        "rogue directive",
        now,
        now + 300_000,
    );
    let e_rogue = seal_human_drop(
        &c_rogue,
        &rogue_kp,
        &node.identity().encryption.public_key(),
    )
    .unwrap();
    assert!(matches!(
        node.ingest_human_drop(&e_rogue, Some(&gate), false).await,
        Err(NodeError::Unauthorized(_))
    ));
    // (c) Expired claim
    let c_expired = build_directive_claim(
        "bogdan",
        &human_kp,
        1,
        node.node_id().as_str(),
        &node.identity().encryption.public_key(),
        Some("ops"),
        "expired directive",
        now - 120_000,
        now - 1_000,
    );
    let e_expired = manual_seal_unchecked(
        &c_expired,
        &human_kp,
        &node.identity().encryption.public_key(),
    );
    assert!(matches!(
        node.ingest_human_drop(&e_expired, Some(&gate), false).await,
        Err(NodeError::Unauthorized(_))
    ));

    let rejected_audits = node
        .db()
        .local()
        .query_gate_audit(&GateAuditQuery {
            decision: Some(GateDecision::Block),
            limit: Some(50),
            ..GateAuditQuery::default()
        })
        .unwrap();
    let drop_rejected: Vec<_> = rejected_audits
        .iter()
        .filter(|a| a.categories.iter().any(|c| c == "gate.human_drop_rejected"))
        .collect();
    // Expect at least 4: overwrite-conflict + replay + unknown-authority + expired!
    assert!(
        drop_rejected.len() >= 4,
        "H11: expected >= 4 gate.human_drop_rejected audit rows, got {}",
        drop_rejected.len()
    );
    for row in &drop_rejected {
        let serialized = serde_json::to_string(row).unwrap();
        assert!(!serialized.contains(initial_secret));
        assert!(!serialized.contains(blocked_secret));
        assert!(!serialized.contains(rotated_secret));
    }

    node.shutdown();
}

// ============================================================================
// 10. H16: Reserved System Secret Denylist (`t3-*`, `staged-join-token*`)
// ============================================================================

#[tokio::test]
async fn h16_reserved_secret_names_rejected_in_crypto_and_engine() {
    for reserved in [
        "t3-auth-token",
        "T3-AUTH-TOKEN",
        "  t3-auth-token  ",
        "t3-session-token",
        "T3-Session-Token",
        "staged-join-token",
        "staged-join-token-acme",
        "STAGED-JOIN-TOKEN-1234",
    ] {
        assert!(
            is_reserved_secret_name(reserved),
            "H16: '{reserved}' must be rejected by is_reserved_secret_name"
        );
    }

    for allowed in ["stripe-live-key", "github-pat", "my-t3-app-secret"] {
        assert!(
            !is_reserved_secret_name(allowed),
            "normal secret name '{allowed}' should not be reserved"
        );
    }

    // Verify end-to-end rejection in `ingest_human_drop` with `gate.human_drop_rejected` audit!
    let dir = TempDir::new().unwrap();
    let node = UnifiedNode::open(make_p2p_config("h16@test", &dir)).unwrap();
    node.register_handle("sess-ops", "ops").await.unwrap();
    let human_kp = Ed25519KeyPair::generate().unwrap();
    enroll_human(&node, "bogdan", &human_kp, HumanAuthorityRole::Admin, 1);

    for reserved in [
        "t3-auth-token",
        "t3-session-token",
        "staged-join-token",
        "staged-join-token-team",
    ] {
        let claim = build_secret_claim(
            "bogdan",
            &human_kp,
            1,
            node.node_id().as_str(),
            &node.identity().encryption.public_key(),
            Some("ops"),
            reserved,
            true,
            "evil-override-value",
        );
        let env =
            manual_seal_unchecked(&claim, &human_kp, &node.identity().encryption.public_key());
        let err = node.ingest_human_drop(&env, None, true).await.unwrap_err();
        assert!(
            matches!(err, NodeError::Unauthorized(_)),
            "H16: ingest_human_drop must reject reserved secret '{reserved}', got {err:?}"
        );
        assert!(node.secret_store().get(reserved).is_err());
    }

    let audits = node
        .db()
        .local()
        .query_gate_audit(&GateAuditQuery {
            decision: Some(GateDecision::Block),
            limit: Some(20),
            ..GateAuditQuery::default()
        })
        .unwrap();
    assert!(
        audits
            .iter()
            .filter(|a| a.categories.iter().any(|c| c == "gate.human_drop_rejected"))
            .count()
            >= 4
    );

    node.shutdown();
}

// ============================================================================
// 11. N1: Bearer Token Invalidation on Peer Revoke, Re-Pair & Key Rotation
// ============================================================================

#[tokio::test]
async fn n1_bearer_token_invalidated_on_revoke_repair_and_key_rotation() {
    let hub_dir = TempDir::new().unwrap();
    let alice_dir = TempDir::new().unwrap();
    let admin_ca = Ed25519KeyPair::generate().unwrap();

    let hub = UnifiedNode::open(make_router_config("acme-hub", &hub_dir, &admin_ca)).unwrap();
    let (hub_addr, _hub_srv) = Arc::clone(&hub).serve(loopback_zero()).await.unwrap();

    let alice = UnifiedNode::open(make_p2p_config("alice@laptop", &alice_dir)).unwrap();
    let scopes = ScopePreset::Member.expand();
    let scope_refs: Vec<&str> = scopes.iter().map(String::as_str).collect();

    // 1. Initial pairing issues Bearer token #1.
    let (am2_first, _) = hub
        .create_admin_invite(
            &admin_ca,
            "alice@laptop",
            &scope_refs,
            TrustTier::Org,
            300_000,
        )
        .unwrap();
    alice.accept_am2_invite(&am2_first).await.unwrap();

    let read_hub_bearer = |peer_node: &UnifiedNode| -> String {
        let rec = peer_node
            .db()
            .peers()
            .get_peer("acme-hub")
            .unwrap()
            .expect("alice should have acme-hub peer record");
        let secret_ref = rec
            .auth_credential_ref
            .expect("paired peer must store auth_credential_ref");
        peer_node
            .secret_store()
            .get(&secret_ref)
            .unwrap()
            .as_str()
            .to_string()
    };

    let bearer_1 = read_hub_bearer(&alice);
    let client = HttpClient::new().unwrap();
    let probe_bearer = |token: &str| {
        let req = Request::builder()
            .method(Method::GET)
            .uri(format!("http://{hub_addr}/v1/handles"))
            .header(AUTHORIZATION, format!("Bearer {token}"))
            .body(empty_body())
            .unwrap();
        client.request(req)
    };

    // Bearer #1 works while active.
    assert_eq!(
        probe_bearer(&bearer_1).await.unwrap().status(),
        StatusCode::OK
    );

    // 2. Revoke `alice@laptop` on `hub` -> Bearer #1 is immediately rejected (401).
    hub.db()
        .peers()
        .set_peer_status("alice@laptop", PeerStatus::Revoked, now_ms())
        .unwrap();
    hub.reconcile_peers(Duration::from_secs(5)).await;
    assert_eq!(
        probe_bearer(&bearer_1).await.unwrap().status(),
        StatusCode::UNAUTHORIZED,
        "N1: revoked peer bearer token must be rejected immediately"
    );

    // 3. Re-pair `alice@laptop` with a fresh invite -> Bearer #2 works, Bearer #1 stays dead!
    let (am2_second, _) = hub
        .create_admin_invite(
            &admin_ca,
            "alice@laptop",
            &scope_refs,
            TrustTier::Org,
            300_000,
        )
        .unwrap();
    alice.accept_am2_invite(&am2_second).await.unwrap();
    let bearer_2 = read_hub_bearer(&alice);
    assert_ne!(bearer_1, bearer_2);
    assert_eq!(
        probe_bearer(&bearer_1).await.unwrap().status(),
        StatusCode::UNAUTHORIZED,
        "N1: old bearer token must stay dead even after re-pairing the same peer_id"
    );
    assert_eq!(
        probe_bearer(&bearer_2).await.unwrap().status(),
        StatusCode::OK,
        "N1: newly issued bearer token after re-pair must succeed"
    );

    // 4. Rotate `alice@laptop`'s signing & encryption keys via `PUT /v1/keys` -> Bearer #2
    //    is immediately invalidated!
    let rotated_ids = NodeIdentityKeys::generate().unwrap();
    let new_sign_jwk = rotated_ids.signing.to_jwk();
    let new_enc_jwk = rotated_ids.encryption.to_jwk();
    let payload = KeyRegPayloadV2 {
        v: 2,
        node_id: "alice@laptop".to_string(),
        signing_jwk: new_sign_jwk.clone(),
        encryption_jwk: new_enc_jwk.clone(),
    };
    let proof = alice
        .identity()
        .signing
        .sign_jcs("key-reg", &payload)
        .unwrap();
    let put_req_body = serde_json::to_vec(&PutKeyRequest {
        signing_jwk: new_sign_jwk,
        encryption_jwk: new_enc_jwk,
        proof,
    })
    .unwrap();
    let put_req = Request::builder()
        .method(Method::PUT)
        .uri(format!("http://{hub_addr}/v1/keys"))
        .header(AUTHORIZATION, format!("Bearer {bearer_2}"))
        .header(CONTENT_TYPE, "application/json")
        .body(full_body(put_req_body))
        .unwrap();
    let put_resp = client.request(put_req).await.unwrap();
    assert_eq!(
        put_resp.status(),
        StatusCode::OK,
        "key rotation PUT /v1/keys signed by pinned key must succeed"
    );

    // Bearer #2 was bound to the pre-rotation signing kid and deleted on rotation -> 401!
    assert_eq!(
        probe_bearer(&bearer_2).await.unwrap().status(),
        StatusCode::UNAUTHORIZED,
        "N1: pre-rotation bearer token must be rejected immediately after PUT /v1/keys"
    );

    alice.shutdown();
    hub.shutdown();
}
