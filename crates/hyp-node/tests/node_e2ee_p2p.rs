//! End-to-end integration tests for the Hyphae v2 Unified Rust `Node` engine:
//! 1. 3-Node Hub Topology (`alice@macbook` <-> `acme-team` Hub <-> `bob@laptop`):
//!    - Admin-CA `am2_` pairing, signed manifest negotiation & RFC 9110 `ETag` `304`
//!    - E2EE DM (`dm.e2ee.v1`) with ZERO plaintext substrings in hub `node.sqlite`
//!    - E2EE `#channel` (`channel.e2ee.v1`) + epoch 1 -> epoch 2 rotation with ZERO plaintext in hub DB
//!    - Read-only announcement `#channel` (`ChannelMode::Announcement`) blocking `member` non-writers
//!      with RFC 9457 `403 channel_read_only` + `escalationNote`, while decrypting for readers
//!    - Shared KV (`WriteModel::Shared` CAS `If-Match` -> `409 version_conflict`) + `kv.e2ee.v1`
//!      + zero-polling pushdown subscription on `acme-team.kv`
//!    - Streaming E2EE file transfer (`transfer.stream.v2`) with OCI digest & unpacked content check
//! 2. Direct 2-Node P2P (`alice@macbook` <-> `bob@laptop`, ZERO central hub!):
//!    - Full `hp2p1_` mutual pairing handshake with asymmetric scopes & single-use replay protection
//!    - Direct E2EE DMs in both directions
//!    - `403 not_granted` with `escalationNote` on denied `kv:write=prod/secret`
//!    - Unauthenticated `GET /v1/manifest` returning strictly empty `advertised` & no `escalation`
//!    - Opt-in `GET /.well-known/agent.json` (`404` when disabled, A2A card when enabled)
//! 3. Adversarial & Security Invariants:
//!    - Routing loop (`hyphaevia` cycle -> `400 routing_loop`) & hop cap (`400 hop_limit_exceeded`)
//!    - Manifest rollback (`manifest_version` decrease) & E2EE downgrade (`dm.e2ee.v1` disappearing) fail closed
//!    - `E2eePolicy::Required` vs legacy non-E2EE peer fails closed (`501 capability_unsupported`).

use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use http::{Method, Request, StatusCode};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::time::timeout;

use hyp_crypto::rfc3339::format_rfc3339_millis;
use hyp_crypto::transfer::TarInputEntry;
use hyp_crypto::{Ed25519KeyPair, SecretBackend};
use hyp_node::engine::http_util::{HttpClient, empty_body};
use hyp_node::engine::{
    ChannelMode, ChannelPolicy, E2eePolicy, EscalationConfig, KvNamespaceConfig, KvWriteRequest,
    NodeConfig, NodeError, SubscribeRequest, TopicConfig, UnifiedNode,
};
use hyp_proto::address::NodeId;
use hyp_proto::cloudevent::{CloudEvent, EXT_HOPS, EXT_ORIGIN, EXT_VIA};
use hyp_proto::filter::Filter;
use hyp_proto::manifest::{
    CapabilityToken, KvMode, KvWriteModel, NegotiationError, OkpCurve, OkpJwk, SignedNodeManifest,
};
use hyp_proto::scopes::ScopePreset;
use hyp_store::{DeliveryMode, MailboxEntry, MailboxKind, TrustTier, WriteModel, now_ms};

fn loopback_zero() -> SocketAddr {
    "127.0.0.1:0".parse().expect("valid loopback addr")
}

/// Scans the physical SQLite database file + WAL + SHM sidecars on disk to prove
/// that `needle` does NOT appear anywhere in ANY table, index, or WAL frame!
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

/// Zero-polling waiter for a local session mailbox entry matching `predicate`.
async fn wait_for_mailbox_item<F>(
    node: &Arc<UnifiedNode>,
    session_id: &str,
    predicate: F,
) -> MailboxEntry
where
    F: Fn(&MailboxEntry) -> bool,
{
    let mut rx = node.subscribe_local_inbox();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);

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
        let remaining = deadline - now;
        let _ = timeout(remaining, rx.recv()).await;
    }
}

// ============================================================================
// Test 1: 3-Node Hub Topology (`alice@macbook` <-> `acme-team` <-> `bob@laptop`)
// ============================================================================

#[tokio::test]
async fn three_node_hub_e2ee_dm_channels_announcements_kv_and_transfers() {
    let hub_dir = TempDir::new().unwrap();
    let alice_dir = TempDir::new().unwrap();
    let bob_dir = TempDir::new().unwrap();

    // Org Admin-CA key (never stored on hub disk; hub only holds `admin_jwk` pubkey!).
    let admin_ca = Ed25519KeyPair::generate().unwrap();
    let admin_proto_jwk = OkpJwk::new(OkpCurve::Ed25519, &admin_ca.public_key_bytes());

    // Configure `acme-team` Router Hub with escalation notes, KV namespace, and `#announcements` policy.
    let mut hub_cfg = NodeConfig::router(NodeId::new("acme-team").unwrap(), hub_dir.path());
    hub_cfg.secret_backend = Some(SecretBackend::File);
    hub_cfg.admin_jwk = Some(admin_proto_jwk);
    hub_cfg.escalation = EscalationConfig {
        default: Some("Ask #it-help for additional hub permissions.".to_string()),
        by_scope: BTreeMap::from([(
            "channel:post=#announcements".to_string(),
            "Posting in #announcements is restricted to release managers; ask @alice.".to_string(),
        )]),
    };
    hub_cfg.kv_namespaces.push(KvNamespaceConfig {
        name: "deploys".to_string(),
        mode: KvMode::E2ee,
        write_model: KvWriteModel::Shared,
    });
    hub_cfg.channel_policies.insert(
        "#announcements".to_string(),
        ChannelPolicy::announcement(["alice@macbook"])
            .with_description("Company-wide read-only release announcements"),
    );

    let hub = UnifiedNode::open(hub_cfg).unwrap();
    let (hub_addr, _hub_srv) = Arc::clone(&hub).serve(loopback_zero()).await.unwrap();

    // Verify opt-in A2A Agent Card is 404 when disabled (`expose_a2a_card: false`).
    let client = HttpClient::new().unwrap();
    let a2a_req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{hub_addr}/.well-known/agent.json"))
        .body(empty_body())
        .unwrap();
    let a2a_resp = client.request(a2a_req).await.unwrap();
    assert_eq!(a2a_resp.status(), StatusCode::NOT_FOUND);

    // Boot Alice and Bob Local Nodes (strictly file-only keystore in temp dirs!).
    let mut alice_cfg = NodeConfig::local(NodeId::new("alice@macbook").unwrap(), alice_dir.path());
    alice_cfg.secret_backend = Some(SecretBackend::File);
    let alice = UnifiedNode::open(alice_cfg).unwrap();

    let mut bob_cfg = NodeConfig::local(NodeId::new("bob@laptop").unwrap(), bob_dir.path());
    bob_cfg.secret_backend = Some(SecretBackend::File);
    let bob = UnifiedNode::open(bob_cfg).unwrap();

    // Both Alice & Bob receive full `member` grants (including `channel:post=*` and `kv:write=deploys/*`).
    let mut member_scopes = ScopePreset::Member.expand();
    member_scopes.push("kv:read=deploys/*".to_string());
    member_scopes.push("kv:write=deploys/*".to_string());
    let member_refs: Vec<&str> = member_scopes.iter().map(String::as_str).collect();

    let (alice_am2, _) = hub
        .create_admin_invite(
            &admin_ca,
            "alice@macbook",
            &member_refs,
            TrustTier::Org,
            300_000,
        )
        .unwrap();
    let (bob_am2, _) = hub
        .create_admin_invite(
            &admin_ca,
            "bob@laptop",
            &member_refs,
            TrustTier::Org,
            300_000,
        )
        .unwrap();

    let alice_link_info = alice.accept_am2_invite(&alice_am2).await.unwrap();
    let bob_link_info = bob.accept_am2_invite(&bob_am2).await.unwrap();
    assert_eq!(alice_link_info.peer_id, "acme-team");
    assert_eq!(bob_link_info.peer_id, "acme-team");
    assert_eq!(alice_link_info.negotiated.agreed_protocol, 2);
    assert!(
        alice_link_info
            .negotiated
            .shared_capabilities
            .contains(&CapabilityToken::DmE2eeV1)
    );

    // Verify RFC 9110 ETag conditional fetch -> `304 Not Modified`!
    let (not_modified, updated) = alice.refresh_peer_manifest("acme-team").await.unwrap();
    assert!(
        not_modified,
        "expected 304 Not Modified on unchanged manifest"
    );
    assert!(updated.is_none());

    // Register local agent handles on Alice (`claude`) and Bob (`codex`).
    alice.register_handle("sess-alice", "claude").await.unwrap();
    bob.register_handle("sess-bob", "codex").await.unwrap();

    // ------------------------------------------------------------------------
    // 1A. E2EE DM (`dm.e2ee.v1`): Alice -> Bob, ZERO plaintext in hub DB!
    // ------------------------------------------------------------------------
    let dm_secret = "TOPSECRET-DM-DEPLOY-KEY-9a8b7c6d";
    let dm_res = alice
        .send_dm("claude", "bob@laptop/codex", dm_secret)
        .await
        .unwrap();
    assert!(dm_res.encrypted);
    assert_eq!(dm_res.routed_via, "acme-team");

    let bob_dm = wait_for_mailbox_item(&bob, "sess-bob", |m| m.text == dm_secret).await;
    assert_eq!(bob_dm.kind, MailboxKind::Message);
    assert_eq!(bob_dm.source, "alice@macbook/claude");

    // Directly check hub's `messages` table AND raw `node.sqlite` + `-wal` bytes!
    {
        let hub_db = hub.db();
        let hub_msg = hub_db.messages().get_message(&dm_res.id).unwrap().unwrap();
        assert!(
            hub_msg.text.contains("dm.e2ee.v1"),
            "hub must store opaque dm.e2ee.v1 envelope"
        );
        assert!(!hub_msg.text.contains(dm_secret));
    }
    assert_zero_plaintext_in_sqlite(hub_dir.path(), dm_secret);

    // ------------------------------------------------------------------------
    // 1B. E2EE `#incidents` (`channel.e2ee.v1`): epoch 1 -> rotate epoch 2 -> ZERO plaintext!
    // ------------------------------------------------------------------------
    alice
        .join_channel("acme-team/#incidents", "claude")
        .await
        .unwrap();
    bob.join_channel("acme-team/#incidents", "codex")
        .await
        .unwrap();

    let ep1 = alice
        .ensure_channel_epoch("acme-team", "#incidents")
        .await
        .unwrap();
    assert_eq!(ep1, 1);

    let ch_msg1 = "SECRET-INCIDENT-EPOCH1-checkout-p0";
    alice
        .post_channel("acme-team/#incidents", "claude", ch_msg1)
        .await
        .unwrap();
    let bob_ch1 = wait_for_mailbox_item(&bob, "sess-bob", |m| m.text == ch_msg1).await;
    assert!(bob_ch1.source.contains("#incidents"));

    // Rotate room key strictly to epoch 2, then Bob posts -> Alice decrypts!
    let ep2 = alice
        .rotate_channel_epoch("acme-team", "#incidents")
        .await
        .unwrap();
    assert_eq!(ep2, 2);

    let ch_msg2 = "SECRET-INCIDENT-EPOCH2-mitigated-now";
    bob.post_channel("acme-team/#incidents", "codex", ch_msg2)
        .await
        .unwrap();
    let alice_ch2 = wait_for_mailbox_item(&alice, "sess-alice", |m| m.text == ch_msg2).await;
    assert!(alice_ch2.source.contains("#incidents"));

    // Prove ZERO plaintext `#channel` substrings exist anywhere in `acme-team`'s `node.sqlite`!
    assert_zero_plaintext_in_sqlite(hub_dir.path(), ch_msg1);
    assert_zero_plaintext_in_sqlite(hub_dir.path(), ch_msg2);

    // ------------------------------------------------------------------------
    // 1C. Read-Only Announcement `#announcements` (`ChannelMode::Announcement`)
    // ------------------------------------------------------------------------
    alice
        .join_channel("acme-team/#announcements", "claude")
        .await
        .unwrap();
    bob.join_channel("acme-team/#announcements", "codex")
        .await
        .unwrap();

    // Discovery metadata: `GET /v1/channels` reports `mode: announcement` and caller-scoped `canPost`!
    let alice_chans = alice
        .list_channels("acme-team", Some("#announcements"))
        .await
        .unwrap();
    assert_eq!(alice_chans.len(), 1);
    assert_eq!(alice_chans[0].mode, ChannelMode::Announcement);
    assert!(alice_chans[0].can_post, "Alice is an authorized writer");

    let bob_chans = bob
        .list_channels("acme-team", Some("#announcements"))
        .await
        .unwrap();
    assert_eq!(bob_chans.len(), 1);
    assert_eq!(bob_chans[0].mode, ChannelMode::Announcement);
    assert!(
        !bob_chans[0].can_post,
        "Bob must see canPost=false even with member channel:post=*"
    );

    // Authorized writer Alice posts E2EE announcement -> Bob receives decrypted!
    let ann_text = "ANNOUNCEMENT-SECRET-RELEASE-v2.2.0-SHIPPED";
    alice
        .post_channel("acme-team/#announcements", "claude", ann_text)
        .await
        .unwrap();
    let bob_ann = wait_for_mailbox_item(&bob, "sess-bob", |m| m.text == ann_text).await;
    assert!(bob_ann.source.contains("#announcements"));
    assert_zero_plaintext_in_sqlite(hub_dir.path(), ann_text);

    // Non-writer Bob (despite holding `member` `channel:post=*`!) MUST fail closed with 403 `channel_read_only`!
    let pending_before = hub
        .db()
        .messages()
        .list_pending("alice@macbook/claude")
        .unwrap()
        .len();
    let bob_post_err = bob
        .post_channel("acme-team/#announcements", "codex", "unauthorized spam")
        .await
        .unwrap_err();
    match bob_post_err {
        NodeError::RemoteProblem(prob) => {
            assert_eq!(prob.status, 403);
            assert_eq!(prob.error, "channel_read_only");
            assert_eq!(prob.title, "Channel is read-only (announcement mode)");
            assert_eq!(
                prob.extensions.get("channel"),
                Some(&json!("#announcements"))
            );
            let note = prob
                .extensions
                .get("escalationNote")
                .and_then(Value::as_str)
                .expect("expected escalationNote on 403 channel_read_only");
            assert!(note.contains("release managers"));
        }
        other => panic!("expected RemoteProblem 403 channel_read_only, got {other:?}"),
    }
    // Zero message stored from Bob's rejected announcement post!
    let pending_after = hub
        .db()
        .messages()
        .list_pending("alice@macbook/claude")
        .unwrap()
        .len();
    assert_eq!(pending_before, pending_after);

    // Bob also CANNOT rotate epochs on an announcement channel!
    let bob_rot_err = bob
        .rotate_channel_epoch("acme-team", "#announcements")
        .await
        .unwrap_err();
    match bob_rot_err {
        NodeError::RemoteProblem(prob) => {
            assert_eq!(prob.status, 403);
            assert_eq!(prob.error, "channel_read_only");
        }
        other => panic!("expected 403 channel_read_only on epoch rotation, got {other:?}"),
    }

    // Defense-in-depth: even if a compromised hub bypassed its own policy and forged/forwarded
    // a validly Ed25519-signed E2EE post from non-writer Bob (`bob@laptop/codex`) on
    // `#announcements`, Alice's client-side inbound check MUST reject it fail-closed!
    {
        let ep_rec = hub
            .db()
            .channels()
            .latest_epoch("acme-team", "#announcements")
            .unwrap()
            .unwrap();
        let bundle: hyp_crypto::e2ee::SignedEpochKeyBundle =
            serde_json::from_str(&ep_rec.key_envelope_json).unwrap();
        let (bob_rk, _) = hyp_crypto::e2ee::open_epoch_bundle(
            &bundle,
            hyp_crypto::e2ee::EpochScope::Channel,
            "acme-team",
            "#announcements",
            &alice.identity().signing.public_key(),
            "bob@laptop",
            &bob.identity().encryption,
            1,
        )
        .unwrap();
        let spoof_ctx = hyp_crypto::e2ee::ChannelContext {
            host_node: "acme-team",
            channel: "#announcements",
            msg_id: "rogue-hub-inject-1",
            sender: "bob@laptop/codex",
        };
        let rogue_env = hyp_crypto::e2ee::seal_channel_message(
            &spoof_ctx,
            b"rogue hub injected announcement from bob",
            &bob_rk,
            &bob.identity().signing,
        )
        .unwrap();
        let rogue_record = hyp_store::MessageRecord {
            id: "rogue-hub-inject-1:alice@macbook/claude".to_string(),
            from_addr: "bob@laptop/codex".to_string(),
            to_addr: "alice@macbook/claude".to_string(),
            channel: Some("#announcements".to_string()),
            text: serde_json::to_string(&rogue_env).unwrap(),
            digest: "d".to_string(),
            sent_at: now_ms(),
            state: hyp_store::MessageState::Pending,
            reason: None,
            hold_until: 0,
            settled_at: None,
            origin_environment_id: None,
            origin_thread_id: None,
            e2ee_epoch: Some(ep_rec.epoch),
        };
        let reject_err = alice
            .handle_inbound_peer_message("acme-team", rogue_record)
            .await
            .unwrap_err();
        assert!(
            reject_err
                .to_string()
                .contains("unauthorized_announcement_writer"),
            "recipient must reject unauthorized announcement writer even if hub is compromised; got {reject_err:?}"
        );
    }

    // Runtime `set_channel_policy` persistence with exact `<node>/<handle>` writer allowlist:
    hub.set_channel_policy(
        "#releases",
        ChannelPolicy::announcement(["alice@macbook/claude"]),
    )
    .unwrap();
    alice
        .join_channel("acme-team/#releases", "claude")
        .await
        .unwrap();
    bob.join_channel("acme-team/#releases", "codex")
        .await
        .unwrap();
    alice
        .post_channel("acme-team/#releases", "claude", "RELEASE-HANDLE-EXACT-OK")
        .await
        .unwrap();
    let _ = wait_for_mailbox_item(&bob, "sess-bob", |m| m.text == "RELEASE-HANDLE-EXACT-OK").await;
    // Different handle on the SAME authorized node (`alice@macbook/other`) is still rejected!
    let other_handle_err = alice
        .post_channel(
            "acme-team/#releases",
            "other",
            "unauthorized handle on alice",
        )
        .await
        .unwrap_err();
    assert!(matches!(
        other_handle_err,
        NodeError::RemoteProblem(ref p) if p.status == 403 && p.error == "channel_read_only"
    ));
    let rel_err = bob
        .post_channel("acme-team/#releases", "codex", "bob blocked")
        .await
        .unwrap_err();
    assert!(
        matches!(rel_err, NodeError::RemoteProblem(ref p) if p.status == 403 && p.error == "channel_read_only")
    );

    // ------------------------------------------------------------------------
    // 1D. Shared KV (`shared` CAS `If-Match` -> `409 version_conflict`) + `kv.e2ee.v1`
    //     + Zero-Polling Pushdown Subscription on `acme-team.kv`
    // ------------------------------------------------------------------------
    let sub_res = bob
        .subscribe_local_or_remote(SubscribeRequest {
            id: Some("bob-kv-watch".to_string()),
            subscriber_session: "sess-bob".to_string(),
            qualified_topic: "acme-team.kv".to_string(),
            filters: vec![
                Filter::Exact(BTreeMap::from([("ns".to_string(), "deploys".to_string())])),
                Filter::Prefix(BTreeMap::from([(
                    "key".to_string(),
                    "checkout/".to_string(),
                )])),
            ],
            coalesce_seconds: 0,
            mode: DeliveryMode::Full,
        })
        .await
        .unwrap();
    assert_eq!(sub_res.pushdown_shards, 1);
    assert_eq!(sub_res.origin_node, "acme-team");

    // Plaintext Shared CAS write v1 on matching key `deploys/checkout/sha` -> wakes Bob!
    let v1 = alice
        .kv_set(KvWriteRequest {
            host_node: "acme-team".to_string(),
            namespace: "deploys".to_string(),
            key: "checkout/sha".to_string(),
            value: json!({ "sha": "abc123" }),
            write_model: WriteModel::Shared,
            owner_id: None,
            allowlist: None,
            expected_version: Some(0),
            ttl_ms: None,
            encrypt: false,
            e2ee_members: None,
        })
        .await
        .unwrap();
    assert_eq!(v1.version, 1);

    let bob_kv_wake = wait_for_mailbox_item(&bob, "sess-bob", |m| {
        m.kind == MailboxKind::Kv && m.text.contains("checkout/sha") && m.text.contains("abc123")
    })
    .await;
    assert_eq!(bob_kv_wake.source, "acme-team.kv");

    // Stale CAS write (If-Match: "0" when current is 1) -> RFC 9457 `409 version_conflict`!
    let stale_err = bob
        .kv_set(KvWriteRequest {
            host_node: "acme-team".to_string(),
            namespace: "deploys".to_string(),
            key: "checkout/sha".to_string(),
            value: json!({ "sha": "stale-race" }),
            write_model: WriteModel::Shared,
            owner_id: None,
            allowlist: None,
            expected_version: Some(0),
            ttl_ms: None,
            encrypt: false,
            e2ee_members: None,
        })
        .await
        .unwrap_err();
    match stale_err {
        NodeError::RemoteProblem(prob) => {
            assert_eq!(prob.status, 409);
            assert_eq!(prob.error, "version_conflict");
            assert_eq!(prob.extensions.get("currentVersion"), Some(&json!(1)));
        }
        other => panic!("expected 409 version_conflict, got {other:?}"),
    }

    // Non-matching key (`deploys/billing/ignored`) MUST NOT wake Bob (dropped upstream by pushdown)!
    alice
        .kv_set(KvWriteRequest {
            host_node: "acme-team".to_string(),
            namespace: "deploys".to_string(),
            key: "billing/ignored".to_string(),
            value: json!({ "ignored": true }),
            write_model: WriteModel::Shared,
            owner_id: None,
            allowlist: None,
            expected_version: Some(0),
            ttl_ms: None,
            encrypt: false,
            e2ee_members: None,
        })
        .await
        .unwrap();

    // E2EE KV write (`kv.e2ee.v1`) on matching key `deploys/checkout/secret_cfg`:
    let kv_secret = "TOPSECRET-KV-DATABASE-PASSWORD-8899";
    let enc_kv = alice
        .kv_set(KvWriteRequest {
            host_node: "acme-team".to_string(),
            namespace: "deploys".to_string(),
            key: "checkout/secret_cfg".to_string(),
            value: json!({ "dbPass": kv_secret }),
            write_model: WriteModel::Shared,
            owner_id: None,
            allowlist: None,
            expected_version: Some(0),
            ttl_ms: None,
            encrypt: true,
            e2ee_members: Some(vec!["alice@macbook".to_string(), "bob@laptop".to_string()]),
        })
        .await
        .unwrap();
    assert_eq!(enc_kv.version, 1);
    assert_eq!(enc_kv.e2ee_epoch, Some(1));

    // Bob receives decrypted KV watch event automatically AND decrypts via `kv_get`,
    // while `acme-team`'s `node.sqlite` holds ZERO KV plaintext!
    let bob_e2ee_kv_wake = wait_for_mailbox_item(&bob, "sess-bob", |m| {
        m.kind == MailboxKind::Kv && m.text.contains("checkout/secret_cfg")
    })
    .await;
    assert!(
        bob_e2ee_kv_wake.text.contains(kv_secret),
        "Bob's local KV watch event should carry decrypted payload"
    );

    // Ensure non-matching `billing/ignored` NEVER arrived in Bob's mailbox!
    let leftover = bob.peek_local_inbox("sess-bob", 50).unwrap();
    assert!(
        !leftover.iter().any(|m| m.text.contains("billing/ignored")),
        "non-matching KV key must never cross wire or wake Bob"
    );

    let bob_read_kv = bob
        .kv_get("acme-team", "deploys", "checkout/secret_cfg")
        .await
        .unwrap()
        .expect("encrypted KV entry exists");
    assert_eq!(bob_read_kv.value, json!({ "dbPass": kv_secret }));
    assert_zero_plaintext_in_sqlite(hub_dir.path(), kv_secret);

    // ------------------------------------------------------------------------
    // 1E. Streaming E2EE File Transfer (`transfer.stream.v2`): Alice -> Bob
    // ------------------------------------------------------------------------
    let file_secret = "CONFIDENTIAL-RELEASE-ARTIFACT-CONTENT-424242\nLine 2 of report.\n";
    let src_file_path = alice_dir.path().join("release-report.txt");
    fs::write(&src_file_path, file_secret).unwrap();

    let tx_res = alice
        .send_files(
            "bob@laptop",
            Some("codex"),
            &[TarInputEntry {
                archive_path: "reports/release-report.txt".to_string(),
                source_path: src_file_path,
            }],
            Some("acme-team"),
        )
        .await
        .unwrap();
    assert!(tx_res.plaintext_digest.starts_with("sha256:"));
    assert!(tx_res.ciphertext_digest.starts_with("sha256:"));

    let bob_tx_notice = wait_for_mailbox_item(&bob, "sess-bob", |m| {
        m.kind == MailboxKind::Transfer && m.text.contains(&tx_res.id)
    })
    .await;
    // Notice is path-only (does NOT dump raw file content into mailbox text!).
    assert!(!bob_tx_notice.text.contains(file_secret));
    let notice_json: Value = serde_json::from_str(&bob_tx_notice.text).unwrap();
    assert_eq!(notice_json["plaintextDigest"], tx_res.plaintext_digest);
    let extracted_path = notice_json["files"][0]["diskPath"]
        .as_str()
        .expect("extracted file diskPath");
    let extracted_content = fs::read_to_string(extracted_path).unwrap();
    assert_eq!(extracted_content, file_secret);
    assert_zero_plaintext_in_sqlite(hub_dir.path(), "CONFIDENTIAL-RELEASE-ARTIFACT-CONTENT");

    alice.shutdown();
    bob.shutdown();
    hub.shutdown();
}

// ============================================================================
// Test 2: Direct 2-Node P2P (`alice@macbook` <-> `bob@laptop`, ZERO central hub!)
// ============================================================================

#[tokio::test]
async fn direct_two_node_p2p_hp2p1_asymmetric_scopes_and_public_manifest_isolation() {
    let alice_dir = TempDir::new().unwrap();
    let bob_dir = TempDir::new().unwrap();

    let mut alice_cfg = NodeConfig::p2p(NodeId::new("alice@macbook").unwrap(), alice_dir.path());
    alice_cfg.secret_backend = Some(SecretBackend::File);
    alice_cfg.expose_a2a_card = true; // Verify opt-in A2A projection too!
    alice_cfg.topics.push(TopicConfig {
        topic: "internal-builds".to_string(),
        kind: Some("ci".to_string()),
        description: Some("Private build stream".to_string()),
        metadata: None,
        has_provisioned_publisher: true,
    });
    alice_cfg.kv_namespaces.push(KvNamespaceConfig {
        name: "pair".to_string(),
        mode: KvMode::Plaintext,
        write_model: KvWriteModel::Owner,
    });
    alice_cfg.escalation = EscalationConfig {
        default: Some("Message Alice on Signal to request more P2P scopes.".to_string()),
        by_scope: BTreeMap::from([(
            "kv:write=prod/*".to_string(),
            "Production writes require on-call approval from Alice.".to_string(),
        )]),
    };

    let alice = UnifiedNode::open(alice_cfg).unwrap();
    let (alice_addr, _alice_srv) = Arc::clone(&alice).serve(loopback_zero()).await.unwrap();

    // Seed a local KV entry on Alice inside `pair/plan` (readable by Bob once paired).
    alice
        .kv_set(KvWriteRequest {
            host_node: "local".to_string(),
            namespace: "pair".to_string(),
            key: "plan".to_string(),
            value: json!({ "step": "ship-v2" }),
            write_model: WriteModel::Owner,
            owner_id: None,
            allowlist: None,
            expected_version: None,
            ttl_ms: None,
            encrypt: false,
            e2ee_members: None,
        })
        .await
        .unwrap();

    // 2A. Unauthenticated `GET /v1/manifest` MUST return `audience: "public"` with
    //     STRICTLY EMPTY `advertised` arrays and NO `escalation` text!
    let client = HttpClient::new().unwrap();
    let pub_req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{alice_addr}/v1/manifest"))
        .body(empty_body())
        .unwrap();
    let pub_resp = client.request(pub_req).await.unwrap();
    let (status, _hdrs, bytes) = HttpClient::collect(pub_resp, 1024 * 1024).await.unwrap();
    assert_eq!(status, StatusCode::OK);
    let pub_signed: SignedNodeManifest = serde_json::from_slice(&bytes).unwrap();
    let pub_payload = pub_signed.decode_payload().unwrap();
    assert_eq!(pub_payload.audience, "public");
    assert!(pub_payload.advertised.is_empty());
    assert!(pub_payload.advertised.topics.is_empty());
    assert!(pub_payload.advertised.channels.is_empty());
    assert!(pub_payload.advertised.kv_namespaces.is_empty());
    assert!(pub_payload.advertised.rpc_commands.is_empty());
    assert!(pub_payload.escalation.is_none());

    // Opt-in `GET /.well-known/agent.json` returns public A2A card with zero private skills.
    let a2a_req = Request::builder()
        .method(Method::GET)
        .uri(format!("http://{alice_addr}/.well-known/agent.json"))
        .body(empty_body())
        .unwrap();
    let a2a_resp = client.request(a2a_req).await.unwrap();
    let (a2a_status, _, a2a_bytes) = HttpClient::collect(a2a_resp, 1024 * 1024).await.unwrap();
    assert_eq!(a2a_status, StatusCode::OK);
    let card: hyp_proto::manifest::AgentCard = serde_json::from_slice(&a2a_bytes).unwrap();
    assert_eq!(card.name, "alice@macbook");
    assert!(card.skills.is_empty());

    // 2B. Direct P2P Mutual Pairing (`hp2p1_`) with asymmetric scopes:
    //     Alice grants Bob `dm:*` + `kv:read=pair/*` (DENIES `kv:write=prod/*`!).
    let mut bob_cfg = NodeConfig::p2p(NodeId::new("bob@laptop").unwrap(), bob_dir.path());
    bob_cfg.secret_backend = Some(SecretBackend::File);
    let bob = UnifiedNode::open(bob_cfg).unwrap();

    alice.register_handle("sess-alice", "claude").await.unwrap();
    bob.register_handle("sess-bob", "codex").await.unwrap();

    let (hp2p_token, offer) = alice
        .create_p2p_invite(
            vec!["dm:*".to_string(), "kv:read=pair/*".to_string()],
            vec!["dm:*".to_string()],
            300_000,
        )
        .unwrap();
    assert!(hp2p_token.starts_with("hp2p1_"));

    // Mutated 1-bit flip in `bindingMac` MUST fail closed over HTTP `POST /v1/p2p/pair/<offerId>`
    // without consuming the single-use offer!
    {
        let dummy_grant = hyp_crypto::pairing::GrantV2 {
            v: 2,
            id: "bad-mac-grant".to_string(),
            node_id: "alice@macbook".to_string(),
            scopes: vec!["dm:send".to_string()],
            trust_tier: Some("peer".to_string()),
            pairing_key: None,
            subject_signing_jwk: Some(offer.signing_jwk.clone()),
            subject_encryption_jwk: Some(offer.encryption_jwk.clone()),
            issued_at: format_rfc3339_millis(now_ms()),
            pair_by: None,
            expires_at: None,
        };
        let mut forged = hyp_crypto::pairing::create_p2p_response(
            &offer,
            "bob@laptop",
            None,
            bob.identity(),
            &dummy_grant,
        )
        .unwrap();
        use base64::Engine as _;
        let mut mac_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&forged.binding_mac)
            .unwrap();
        mac_bytes[0] ^= 0x01;
        forged.binding_mac = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac_bytes);
        let bad_req = Request::builder()
            .method(Method::POST)
            .uri(format!(
                "http://{alice_addr}/v1/p2p/pair/{}",
                offer.offer_id
            ))
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(hyp_node::engine::http_util::full_body(
                serde_json::to_vec(&forged).unwrap(),
            ))
            .unwrap();
        let bad_resp = client.request(bad_req).await.unwrap();
        assert_eq!(bad_resp.status(), StatusCode::BAD_REQUEST);
    }

    let paired = bob
        .accept_p2p_invite(&hp2p_token, vec!["dm:*".to_string()])
        .await
        .unwrap();
    assert_eq!(paired.peer_id, "alice@macbook");
    assert_eq!(paired.negotiated.agreed_protocol, 2);

    // Single-use atomic offer enforcement: replaying `hp2p1_` token MUST fail closed!
    let replay_err = bob
        .accept_p2p_invite(&hp2p_token, vec!["dm:*".to_string()])
        .await
        .unwrap_err();
    assert!(matches!(replay_err, NodeError::RemoteProblem(_)));

    // 2C. Direct E2EE DM works in BOTH directions (Bob -> Alice direct HTTP, Alice -> Bob via SSE)!
    let p2p_secret_1 = "DIRECT-P2P-BOB-TO-ALICE-ZERO-HUB";
    let res1 = bob
        .send_dm("codex", "alice@macbook/claude", p2p_secret_1)
        .await
        .unwrap();
    assert!(res1.encrypted);
    assert_eq!(res1.routed_via, "alice@macbook");
    let alice_got = wait_for_mailbox_item(&alice, "sess-alice", |m| m.text == p2p_secret_1).await;
    assert_eq!(alice_got.source, "bob@laptop/codex");

    let p2p_secret_2 = "DIRECT-P2P-ALICE-TO-BOB-VIA-SSE";
    let res2 = alice
        .send_dm("claude", "bob@laptop/codex", p2p_secret_2)
        .await
        .unwrap();
    assert!(res2.encrypted);
    let bob_got = wait_for_mailbox_item(&bob, "sess-bob", |m| m.text == p2p_secret_2).await;
    assert_eq!(bob_got.source, "alice@macbook/claude");

    // 2D. Asymmetric scope enforcement:
    //     - `kv:read=pair/plan` SUCCEEDS
    //     - `kv:write=prod/secret` FAILS CLOSED with RFC 9457 `403 not_granted` + Alice's `escalationNote`!
    let pair_plan = bob
        .kv_get("alice@macbook", "pair", "plan")
        .await
        .unwrap()
        .expect("pair/plan readable");
    assert_eq!(pair_plan.value, json!({ "step": "ship-v2" }));

    let denied_err = bob
        .kv_set(KvWriteRequest {
            host_node: "alice@macbook".to_string(),
            namespace: "prod".to_string(),
            key: "secret".to_string(),
            value: json!({ "pwn": true }),
            write_model: WriteModel::Owner,
            owner_id: None,
            allowlist: None,
            expected_version: None,
            ttl_ms: None,
            encrypt: false,
            e2ee_members: None,
        })
        .await
        .unwrap_err();
    match denied_err {
        NodeError::RemoteProblem(prob) => {
            assert_eq!(prob.status, 403);
            assert_eq!(prob.error, "not_granted");
            assert_eq!(
                prob.extensions.get("missingScope"),
                Some(&json!("kv:write=prod/secret"))
            );
            assert!(prob.extensions.contains_key("currentScopes"));
            assert_eq!(
                prob.extensions.get("escalationNote"),
                Some(&json!(
                    "Production writes require on-call approval from Alice."
                ))
            );
        }
        other => panic!("expected RemoteProblem 403 not_granted, got {other:?}"),
    }

    alice.shutdown();
    bob.shutdown();
}

// ============================================================================
// Test 3: Adversarial & Security Invariants
// ============================================================================

#[tokio::test]
async fn adversarial_routing_loops_manifest_rollback_e2ee_downgrade_and_required_policy() {
    let hub_dir = TempDir::new().unwrap();
    let alice_dir = TempDir::new().unwrap();
    let legacy_dir = TempDir::new().unwrap();

    // 3A. Zero-polling idle check + Routing loop (`hyphaevia` cycle -> `400 routing_loop`)
    //     & hop cap (`400 hop_limit_exceeded`) both in-process and over HTTP `POST /v1/events`!
    let mut hub_cfg = NodeConfig::router(NodeId::new("hub-a").unwrap(), hub_dir.path());
    hub_cfg.secret_backend = Some(SecretBackend::File);
    let hub = UnifiedNode::open(hub_cfg).unwrap();
    assert_eq!(
        hub.db().next_deadline_ms(now_ms()).unwrap(),
        None,
        "idle node must have None next_deadline_ms (zero polling!)"
    );

    let mut cycle_ev = CloudEvent::new(
        "ev-cycle-1",
        "origin/src",
        "com.example.ping",
        json!({ "ok": true }),
    );
    cycle_ev.set_extension(EXT_ORIGIN, "node-x");
    cycle_ev.set_extension(EXT_VIA, "node-x,hub-a");
    cycle_ev.set_extension(EXT_HOPS, "1");

    let loop_err = hub
        .ingest_inbound_event("node-x", "alerts", &cycle_ev)
        .unwrap_err();
    assert_eq!(loop_err.status_code(), StatusCode::BAD_REQUEST);
    let loop_prob = loop_err.to_problem_details();
    assert_eq!(loop_prob.status, 400);
    assert_eq!(loop_prob.error, "routing_loop");

    let mut hops_ev = CloudEvent::new(
        "ev-hops-1",
        "origin/src",
        "com.example.ping",
        json!({ "ok": true }),
    );
    hops_ev.set_extension(EXT_ORIGIN, "node-x");
    hops_ev.set_extension(EXT_VIA, "node-x,hub-b");
    hops_ev.set_extension(EXT_HOPS, "2");

    let hops_err = hub
        .ingest_inbound_event("hub-b", "alerts", &hops_ev)
        .unwrap_err();
    assert_eq!(hops_err.status_code(), StatusCode::BAD_REQUEST);
    let hops_prob = hops_err.to_problem_details();
    assert_eq!(hops_prob.status, 400);
    assert_eq!(hops_prob.error, "hop_limit_exceeded");

    // Also verify HTTP `POST /v1/events` returns RFC 9457 `400 routing_loop` over the wire!
    let (hub_addr, _hub_srv) = Arc::clone(&hub).serve(loopback_zero()).await.unwrap();
    let (p2p_tok, _) = hub
        .create_p2p_invite(
            vec!["dm:*".to_string(), "stream:publish=alerts".to_string()],
            vec!["dm:*".to_string()],
            300_000,
        )
        .unwrap();
    let probe_dir = TempDir::new().unwrap();
    let mut probe_cfg = NodeConfig::local(NodeId::new("probe@dev").unwrap(), probe_dir.path());
    probe_cfg.secret_backend = Some(SecretBackend::File);
    let probe = UnifiedNode::open(probe_cfg).unwrap();
    let _ = probe
        .accept_p2p_invite(&p2p_tok, vec!["dm:*".to_string()])
        .await
        .unwrap();
    let probe_link = probe.peer_link("hub-a").await.unwrap();
    let http_loop_err = probe_link
        .publish_event(&hyp_node::engine::peer_link::PublishEventRequest {
            topic: "alerts".to_string(),
            event: cycle_ev.clone(),
        })
        .await
        .unwrap_err();
    match http_loop_err {
        NodeError::RemoteProblem(p) => {
            assert_eq!(p.status, 400);
            assert_eq!(p.error, "routing_loop");
        }
        other => panic!("expected HTTP 400 routing_loop, got {other:?}"),
    }
    let _ = hub_addr;
    probe.shutdown();

    // 3B. Manifest rollback (`manifest_version` decrease) & E2EE downgrade (`dm.e2ee.v1` disappearing)
    let mut alice_cfg = NodeConfig::local(NodeId::new("alice@macbook").unwrap(), alice_dir.path());
    alice_cfg.secret_backend = Some(SecretBackend::File);
    alice_cfg.e2ee_policy = E2eePolicy::Prefer; // Even under `Prefer`, anti-downgrade MUST fail closed!
    let alice = UnifiedNode::open(alice_cfg).unwrap();

    // Bump hub to manifest_version = 2 and build an authenticated manifest for Alice.
    let v2_ver = hub.bump_manifest_version().unwrap();
    assert_eq!(v2_ver, 2);
    let alice_auth = hyp_node::engine::AuthenticatedPeer {
        peer_id: "alice@macbook".to_string(),
        scopes: hyp_proto::scopes::ScopeSet::from_strings(&["dm:*"]),
        trust_tier: TrustTier::Peer,
    };
    let (manifest_v2, payload_v2, etag_v2) = hub.build_signed_manifest(Some(&alice_auth)).unwrap();
    assert_eq!(payload_v2.manifest_version, 2);

    // Cache v2 cleanly on Alice.
    let neg_v2 = alice
        .verify_and_cache_peer_manifest("hub-a", &manifest_v2, Some(etag_v2), false)
        .unwrap();
    assert!(
        neg_v2
            .shared_capabilities
            .contains(&CapabilityToken::DmE2eeV1)
    );

    // Rollback attack: sign a valid manifest with older `manifest_version = 1 < 2`!
    let mut rollback_payload = payload_v2.clone();
    rollback_payload.manifest_version = 1;
    let rb_canon = rollback_payload.to_canonical_payload().unwrap();
    let rb_sig = hub
        .identity()
        .signing
        .sign_domain_b64("manifest", rb_canon.as_bytes());
    let rollback_signed = SignedNodeManifest {
        payload: rb_canon,
        sig: rb_sig,
    };
    let rb_err = alice
        .verify_and_cache_peer_manifest("hub-a", &rollback_signed, None, false)
        .unwrap_err();
    assert!(
        matches!(
            rb_err,
            NodeError::Negotiation(NegotiationError::ManifestRollbackDetected { .. })
        ),
        "expected ManifestRollbackDetected, got {rb_err:?}"
    );
    assert_eq!(
        rb_err.to_problem_details().error,
        "manifest_rollback_detected"
    );

    // E2EE downgrade attack: sign manifest_version = 3 WITHOUT `dm.e2ee.v1`!
    let mut downgrade_payload = payload_v2.clone();
    downgrade_payload.manifest_version = 3;
    downgrade_payload.issued_at = format_rfc3339_millis(now_ms());
    downgrade_payload.expires_at = format_rfc3339_millis(now_ms() + 86_400_000);
    downgrade_payload
        .capabilities
        .retain(|c| *c != CapabilityToken::DmE2eeV1);
    let dg_canon = downgrade_payload.to_canonical_payload().unwrap();
    let dg_sig = hub
        .identity()
        .signing
        .sign_domain_b64("manifest", dg_canon.as_bytes());
    let downgrade_signed = SignedNodeManifest {
        payload: dg_canon,
        sig: dg_sig,
    };
    let dg_err = alice
        .verify_and_cache_peer_manifest("hub-a", &downgrade_signed, None, false)
        .unwrap_err();
    assert!(
        matches!(
            dg_err,
            NodeError::Negotiation(NegotiationError::CapabilityDowngradeDetected { .. })
        ),
        "expected CapabilityDowngradeDetected, got {dg_err:?}"
    );
    assert_eq!(
        dg_err.to_problem_details().error,
        "capability_downgrade_detected"
    );

    // 3C. `E2eePolicy::Required` vs a signed non-E2EE peer fails closed!
    let mut strict_dir = TempDir::new().unwrap();
    let mut strict_cfg =
        NodeConfig::local(NodeId::new("strict@laptop").unwrap(), strict_dir.path());
    strict_cfg.secret_backend = Some(SecretBackend::File);
    strict_cfg.e2ee_policy = E2eePolicy::Required;
    let strict_node = UnifiedNode::open(strict_cfg).unwrap();

    // Also test a live v2 peer whose manifest omits `dm.e2ee.v1`: fails closed on verification!
    let mut non_e2ee_cfg =
        NodeConfig::router(NodeId::new("legacy-v2-hub").unwrap(), legacy_dir.path());
    non_e2ee_cfg.secret_backend = Some(SecretBackend::File);
    non_e2ee_cfg.e2ee_policy = E2eePolicy::Disabled;
    non_e2ee_cfg.capabilities_override = Some(vec![
        CapabilityToken::ManifestV1,
        CapabilityToken::DmV1,
        CapabilityToken::ChannelV1,
        CapabilityToken::EventsV1,
    ]);
    let non_e2ee_hub = UnifiedNode::open(non_e2ee_cfg).unwrap();
    let strict_auth = hyp_node::engine::AuthenticatedPeer {
        peer_id: "strict@laptop".to_string(),
        scopes: hyp_proto::scopes::ScopeSet::from_strings(&["dm:*"]),
        trust_tier: TrustTier::Peer,
    };
    let (non_e2ee_manifest, _, _) = non_e2ee_hub
        .build_signed_manifest(Some(&strict_auth))
        .unwrap();
    let req_err = strict_node
        .verify_and_cache_peer_manifest("legacy-v2-hub", &non_e2ee_manifest, None, false)
        .unwrap_err();
    assert!(matches!(
        req_err,
        NodeError::Negotiation(NegotiationError::RequiredCapabilityUnsupported {
            capability: CapabilityToken::DmE2eeV1,
            ..
        })
    ));

    // Keep strict_dir alive until shutdown.
    let _ = &mut strict_dir;
    strict_node.shutdown();
    non_e2ee_hub.shutdown();
    alice.shutdown();
    hub.shutdown();
}

// ============================================================================
// 4. Shared KV E2EE Auto-Wrapping for Authorized Hub Members + Blindness + Rotation
// ============================================================================

#[tokio::test]
async fn kv_e2ee_auto_wraps_for_authorized_hub_members_excludes_blind_router_and_rotates_on_join_or_revoke()
 {
    let hub_dir = TempDir::new().unwrap();
    let alice_dir = TempDir::new().unwrap();
    let bob_dir = TempDir::new().unwrap();
    let carol_dir = TempDir::new().unwrap();
    let guest_dir = TempDir::new().unwrap();

    let admin_ca = Ed25519KeyPair::generate().unwrap();
    let admin_proto_jwk = OkpJwk::new(OkpCurve::Ed25519, &admin_ca.public_key_bytes());

    let mut hub_cfg = NodeConfig::router(NodeId::new("acme-kv-hub").unwrap(), hub_dir.path());
    hub_cfg.secret_backend = Some(SecretBackend::File);
    hub_cfg.admin_jwk = Some(admin_proto_jwk);
    hub_cfg.kv_namespaces.push(KvNamespaceConfig {
        name: "shared".to_string(),
        mode: KvMode::E2ee,
        write_model: KvWriteModel::Shared,
    });
    hub_cfg.kv_namespaces.push(KvNamespaceConfig {
        name: "limited".into(),
        mode: KvMode::Plaintext,
        write_model: KvWriteModel::Owner,
    });
    let hub = UnifiedNode::open(hub_cfg).unwrap();
    let (_hub_addr, _hub_srv) = Arc::clone(&hub).serve(loopback_zero()).await.unwrap();

    let mut alice_cfg = NodeConfig::local(NodeId::new("alice@macbook").unwrap(), alice_dir.path());
    alice_cfg.secret_backend = Some(SecretBackend::File);
    let alice = UnifiedNode::open(alice_cfg).unwrap();

    let mut bob_cfg = NodeConfig::local(NodeId::new("bob@laptop").unwrap(), bob_dir.path());
    bob_cfg.secret_backend = Some(SecretBackend::File);
    let bob = UnifiedNode::open(bob_cfg).unwrap();

    let mut carol_cfg =
        NodeConfig::local(NodeId::new("carol@workstation").unwrap(), carol_dir.path());
    carol_cfg.secret_backend = Some(SecretBackend::File);
    let carol = UnifiedNode::open(carol_cfg).unwrap();

    let mut guest_cfg = NodeConfig::local(NodeId::new("guest@public").unwrap(), guest_dir.path());
    guest_cfg.secret_backend = Some(SecretBackend::File);
    let guest = UnifiedNode::open(guest_cfg).unwrap();

    let member_scopes = [
        "dm:send=*",
        "dm:receive",
        "kv:read=shared/*",
        "kv:write=shared/*",
        "kv:read=limited/visible/*",
    ];
    let guest_scopes_owned = ScopePreset::GuestRo.expand();
    let guest_scopes: Vec<&str> = guest_scopes_owned.iter().map(String::as_str).collect();

    // Pair Alice, Bob, and a non-KV Guest against the hub.
    let (inv_a, _) = hub
        .create_admin_invite(
            &admin_ca,
            "alice@macbook",
            &member_scopes,
            TrustTier::Org,
            300_000,
        )
        .unwrap();
    alice.accept_am2_invite(&inv_a).await.unwrap();

    let (inv_b, _) = hub
        .create_admin_invite(
            &admin_ca,
            "bob@laptop",
            &member_scopes,
            TrustTier::Org,
            300_000,
        )
        .unwrap();
    bob.accept_am2_invite(&inv_b).await.unwrap();

    let (inv_g, _) = hub
        .create_admin_invite(
            &admin_ca,
            "guest@public",
            &guest_scopes,
            TrustTier::Guest,
            300_000,
        )
        .unwrap();
    guest.accept_am2_invite(&inv_g).await.unwrap();

    // 1. Alice writes encrypted Shared KV WITHOUT specifying `e2ee_members`!
    let secret_v1 = "AUTO-WRAPPED-SHARED-KV-SECRET-V1";
    let written_v1 = alice
        .kv_set(KvWriteRequest {
            host_node: "acme-kv-hub".to_string(),
            namespace: "shared".to_string(),
            key: "config".to_string(),
            value: json!({ "token": secret_v1 }),
            write_model: WriteModel::Shared,
            owner_id: None,
            allowlist: None,
            expected_version: Some(0),
            ttl_ms: None,
            encrypt: true,
            e2ee_members: None,
        })
        .await
        .unwrap();
    assert_eq!(written_v1.e2ee_epoch, Some(1));

    for key in ["visible/notes", "hidden/notes"] {
        hub.kv_set(KvWriteRequest {
            host_node: "local".into(),
            namespace: "limited".into(),
            key: key.into(),
            value: json!("plain fixture"),
            write_model: WriteModel::Owner,
            owner_id: None,
            allowlist: None,
            expected_version: None,
            ttl_ms: None,
            encrypt: false,
            e2ee_members: None,
        })
        .await
        .unwrap();
    }
    let inspection = bob.inspect_kv(now_ms()).await.unwrap();
    assert_eq!(inspection.namespaces.len(), 2);
    let limited = &inspection.namespaces[0];
    assert_eq!(limited.name, "limited");
    assert_eq!(limited.origin_node, "acme-kv-hub");
    assert_eq!(limited.entry_count, 1);
    assert_eq!(limited.entries[0].key, "visible/notes");
    assert!(
        !serde_json::to_string(&inspection)
            .unwrap()
            .contains("plain fixture")
    );
    assert_eq!(inspection.namespaces[1].name, "shared");
    assert_eq!(inspection.namespaces[1].epoch, Some(1));
    assert_eq!(inspection.namespaces[1].member_count, 2);
    assert!(
        !serde_json::to_string(&inspection)
            .unwrap()
            .contains(secret_v1)
    );
    assert!(
        bob.preview_kv("acme-kv-hub", "limited", "hidden/notes")
            .await
            .unwrap()
            .is_none()
    );
    let preview = bob
        .preview_kv("acme-kv-hub", "shared", "config")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&preview.text).unwrap()["token"],
        secret_v1
    );
    assert!(
        guest
            .inspect_kv(now_ms())
            .await
            .unwrap()
            .namespaces
            .is_empty()
    );

    // Bob MUST immediately decrypt it via `kv_get`!
    let bob_v1 = bob
        .kv_get("acme-kv-hub", "shared", "config")
        .await
        .unwrap()
        .expect("Bob sees encrypted shared/config");
    assert_eq!(bob_v1.value, json!({ "token": secret_v1 }));

    // Hub blindness + least-privilege epoch member assertions:
    // - Zero plaintext in hub SQLite
    // - Epoch 1 members MUST be exactly {alice, bob}: NEVER acme-kv-hub (blind router) and NEVER guest!
    assert_zero_plaintext_in_sqlite(hub_dir.path(), secret_v1);
    let ep1 = hub
        .db()
        .kv()
        .latest_epoch("acme-kv-hub", "shared")
        .unwrap()
        .expect("epoch 1 stored on hub");
    assert_eq!(ep1.epoch, 1);
    assert_eq!(
        ep1.members,
        vec!["alice@macbook".to_string(), "bob@laptop".to_string()],
        "blind router and unauthorized guest must NEVER receive E2EE KV epoch wraps"
    );

    // Guest attempting `GET /v1/keys?kvNamespace=shared` MUST fail closed (403 not_granted)!
    let guest_auth = hyp_node::engine::AuthenticatedPeer {
        peer_id: "guest@public".to_string(),
        scopes: hyp_proto::scopes::ScopeSet::from_preset(ScopePreset::GuestRo),
        trust_tier: TrustTier::Guest,
    };
    let guest_err = hub
        .list_kv_member_keys_for_caller(&guest_auth, "shared")
        .unwrap_err();
    assert_eq!(guest_err.to_problem_details().status, 403);

    // 2. Carol joins later; next encrypted write auto-rotates to epoch 2 covering {alice, bob, carol}!
    let (inv_c, _) = hub
        .create_admin_invite(
            &admin_ca,
            "carol@workstation",
            &member_scopes,
            TrustTier::Org,
            300_000,
        )
        .unwrap();
    carol.accept_am2_invite(&inv_c).await.unwrap();

    let secret_v2 = "AUTO-WRAPPED-SHARED-KV-SECRET-V2";
    let written_v2 = alice
        .kv_set(KvWriteRequest {
            host_node: "acme-kv-hub".to_string(),
            namespace: "shared".to_string(),
            key: "config2".to_string(),
            value: json!({ "token": secret_v2 }),
            write_model: WriteModel::Shared,
            owner_id: None,
            allowlist: None,
            expected_version: Some(0),
            ttl_ms: None,
            encrypt: true,
            e2ee_members: None,
        })
        .await
        .unwrap();
    assert_eq!(written_v2.e2ee_epoch, Some(2));
    let carol_v2 = carol
        .kv_get("acme-kv-hub", "shared", "config2")
        .await
        .unwrap()
        .expect("Carol decrypts newly rotated epoch 2 KV entry");
    assert_eq!(carol_v2.value, json!({ "token": secret_v2 }));
    assert_zero_plaintext_in_sqlite(hub_dir.path(), secret_v2);

    // 3. Revoke Bob on hub; next encrypted write auto-rotates to epoch 3 evicting Bob!
    hub.db()
        .peers()
        .set_peer_status("bob@laptop", hyp_store::PeerStatus::Revoked, now_ms())
        .unwrap();
    let secret_v3 = "AUTO-WRAPPED-SHARED-KV-SECRET-V3";
    let written_v3 = alice
        .kv_set(KvWriteRequest {
            host_node: "acme-kv-hub".to_string(),
            namespace: "shared".to_string(),
            key: "config3".to_string(),
            value: json!({ "token": secret_v3 }),
            write_model: WriteModel::Shared,
            owner_id: None,
            allowlist: None,
            expected_version: Some(0),
            ttl_ms: None,
            encrypt: true,
            e2ee_members: None,
        })
        .await
        .unwrap();
    assert_eq!(written_v3.e2ee_epoch, Some(3));
    let ep3 = hub
        .db()
        .kv()
        .latest_epoch("acme-kv-hub", "shared")
        .unwrap()
        .expect("epoch 3 stored on hub");
    assert_eq!(
        ep3.members,
        vec!["alice@macbook".to_string(), "carol@workstation".to_string()],
        "revoked peer bob@laptop must be evicted from new E2EE KV epoch"
    );
    let carol_v3 = carol
        .kv_get("acme-kv-hub", "shared", "config3")
        .await
        .unwrap()
        .expect("Carol decrypts post-revocation epoch 3 KV entry");
    assert_eq!(carol_v3.value, json!({ "token": secret_v3 }));
    assert_zero_plaintext_in_sqlite(hub_dir.path(), secret_v3);

    guest.shutdown();
    carol.shutdown();
    bob.shutdown();
    alice.shutdown();
    hub.shutdown();
}

// ============================================================================
// 5. Hub Restart Monotonic Manifest Version + Reconnect Regression Test
// ============================================================================

#[tokio::test]
async fn hub_restart_bumps_manifest_version_and_paired_client_reconnects_cleanly() {
    let hub_dir = TempDir::new().unwrap();
    let alice_dir = TempDir::new().unwrap();

    let admin_ca = Ed25519KeyPair::generate().unwrap();
    let admin_proto_jwk = OkpJwk::new(OkpCurve::Ed25519, &admin_ca.public_key_bytes());

    let build_hub_cfg = |dir: &std::path::Path| {
        let mut cfg = NodeConfig::router(NodeId::new("restart-hub").unwrap(), dir);
        cfg.secret_backend = Some(SecretBackend::File);
        cfg.admin_jwk = Some(admin_proto_jwk.clone());
        cfg
    };

    // 1. Start hub #1 (`manifest_version == 1`) and pair Alice.
    let hub1 = UnifiedNode::open(build_hub_cfg(hub_dir.path())).unwrap();
    assert_eq!(hub1.current_manifest_version().unwrap(), 1);
    let (hub_addr, hub1_srv) = Arc::clone(&hub1).serve(loopback_zero()).await.unwrap();

    let mut alice_cfg = NodeConfig::local(NodeId::new("alice@macbook").unwrap(), alice_dir.path());
    alice_cfg.secret_backend = Some(SecretBackend::File);
    let alice1 = UnifiedNode::open(alice_cfg.clone()).unwrap();

    let scopes = [
        "dm:send=*",
        "dm:receive",
        "kv:read=shared/*",
        "kv:write=shared/*",
    ];
    let (inv, _) = hub1
        .create_admin_invite(&admin_ca, "alice@macbook", &scopes, TrustTier::Org, 300_000)
        .unwrap();
    let paired = alice1.accept_am2_invite(&inv).await.unwrap();
    assert_eq!(paired.negotiated.updated_manifest_version, Some(1));

    // Save v1 signed manifest to verify anti-rollback still rejects v1 after v2 is observed.
    let alice_auth = hyp_node::engine::AuthenticatedPeer {
        peer_id: "alice@macbook".to_string(),
        scopes: hyp_proto::scopes::ScopeSet::from_strings(&scopes),
        trust_tier: TrustTier::Org,
    };
    let (v1_manifest, _, _) = hub1.build_signed_manifest(Some(&alice_auth)).unwrap();

    // 2. Shut down BOTH hub and Alice, then restart hub on the SAME address & state dir!
    alice1.shutdown();
    hub1.shutdown();
    hub1_srv.abort();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let hub2 = UnifiedNode::open(build_hub_cfg(hub_dir.path())).unwrap();
    assert_eq!(
        hub2.current_manifest_version().unwrap(),
        2,
        "restarted hub MUST monotonically bump manifest_version to avoid equivocation"
    );
    let (_hub2_addr, _hub2_srv) = Arc::clone(&hub2).serve(hub_addr).await.unwrap();

    // 3. Restart Alice and reconnect to restarted hub: MUST succeed cleanly (no ManifestRollback)!
    let alice2 = UnifiedNode::open(alice_cfg).unwrap();
    let link = alice2
        .connect_peer("restart-hub", &format!("http://{hub_addr}"))
        .await
        .expect("paired client MUST reconnect cleanly after hub restart");
    assert_eq!(link.peer_id(), "restart-hub");
    let rec = alice2
        .db()
        .peers()
        .get_peer("restart-hub")
        .unwrap()
        .unwrap();
    assert_eq!(rec.manifest_version, 2);

    // 4. Anti-rollback still fails closed if an attacker replays the stale v1 manifest!
    let replay_err = alice2
        .verify_and_cache_peer_manifest("restart-hub", &v1_manifest, None, false)
        .unwrap_err();
    assert!(
        matches!(
            replay_err,
            NodeError::Negotiation(NegotiationError::ManifestRollbackDetected { .. })
                | NodeError::Store(hyp_store::StoreError::ManifestRollback { .. })
        ),
        "stale v1 manifest replay after v2 must still fail closed, got {replay_err:?}"
    );

    alice2.shutdown();
    hub2.shutdown();
}
