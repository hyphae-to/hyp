//! End-to-end integration tests for Hyphae v0.3.0 Stage 2 (`hyp-node`):
//! 1. Backward-compatible handle `description` sync over `PUT /v1/handles` & `GET /v1/handles`,
//!    sanitization (multiline, control chars, multibyte UTF-8 truncation), v0.2.0 wire interop,
//!    update/clear semantics, and preservation across reconnects.
//! 2. Automatic multi-hub route learning (`peer_routes`), structured `discover_peer_handles()`,
//!    automatic E2EE DM & streaming file transfer routing across multiple hubs without explicit
//!    `<hub>!` prefixes, late-joiner lazy route refresh, direct P2P precedence (both outbound-link
//!    and outbound-only SSE directions), and clean route clearing when revoking a hub peer.
//! 3. Connect-time route seeding in `accept_am2_invite` and `connect_peer`.

use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{Method, Request, StatusCode};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::time::timeout;

use hyp_crypto::transfer::TarInputEntry;
use hyp_crypto::{Ed25519KeyPair, SecretBackend};
use hyp_node::engine::http_util::{HttpClient, full_body};
use hyp_node::engine::peer_link::{HandlesResponse, PutHandlesRequest};
use hyp_node::engine::{DiscoveredPeerHandle, NodeConfig, UnifiedNode};
use hyp_proto::address::NodeId;
use hyp_proto::manifest::{OkpCurve, OkpJwk};
use hyp_proto::scopes::ScopePreset;
use hyp_store::{
    MAX_HANDLE_DESCRIPTION_CHARS, MailboxEntry, MailboxKind, PeerStatus, TrustTier, now_ms,
};

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
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);

    loop {
        let items = node.peek_local_inbox(session_id, 50).expect("peek inbox");
        if let Some(found) = items.into_iter().find(|e| predicate(e)) {
            let _ = node
                .db()
                .local()
                .acknowledge_inbox(session_id, &[found.receipt.as_str()], now_ms());
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

async fn spawn_hub(
    node_id: &str,
    dir: &Path,
) -> (Arc<UnifiedNode>, Ed25519KeyPair, String, tokio::task::JoinHandle<()>) {
    let admin_ca = Ed25519KeyPair::generate().unwrap();
    let admin_proto_jwk = OkpJwk::new(OkpCurve::Ed25519, &admin_ca.public_key_bytes());
    let mut cfg = NodeConfig::router(NodeId::new(node_id).unwrap(), dir);
    cfg.secret_backend = Some(SecretBackend::File);
    cfg.admin_jwk = Some(admin_proto_jwk);
    let hub = UnifiedNode::open(cfg).unwrap();
    let (addr, srv) = Arc::clone(&hub).serve(loopback_zero()).await.unwrap();
    (hub, admin_ca, format!("http://{addr}"), srv)
}

fn open_local(node_id: &str, dir: &Path) -> Arc<UnifiedNode> {
    let mut cfg = NodeConfig::local(NodeId::new(node_id).unwrap(), dir);
    cfg.secret_backend = Some(SecretBackend::File);
    UnifiedNode::open(cfg).unwrap()
}

async fn pair_member_to_hub(
    hub: &Arc<UnifiedNode>,
    admin_ca: &Ed25519KeyPair,
    client: &Arc<UnifiedNode>,
) {
    let scopes = ScopePreset::Member.expand();
    let scope_refs: Vec<&str> = scopes.iter().map(String::as_str).collect();
    let (am2, _) = hub
        .create_admin_invite(
            admin_ca,
            client.node_id().as_str(),
            &scope_refs,
            TrustTier::Org,
            300_000,
        )
        .unwrap();
    client.accept_am2_invite(&am2).await.unwrap();
}

/// Sends a raw signed HTTP `PUT /v1/handles` payload to `hub_url` using `client`'s Ed25519 key
/// so tests can directly verify wire-level v0.2.0 and malformed/extra-key compatibility.
async fn raw_put_handles(
    client: &Arc<UnifiedNode>,
    hub_url: &str,
    raw_json: &str,
) -> (StatusCode, HandlesResponse) {
    let path_and_query = "/v1/handles";
    let body_bytes = raw_json.as_bytes().to_vec();
    let body_sha = hex::encode(Sha256::digest(&body_bytes));
    let ts = now_ms();
    let nonce = format!("test-nonce-{ts}-{}", body_bytes.len());
    let signing_input = format!("PUT\n{path_and_query}\n{ts}\n{nonce}\n{body_sha}");
    let sig = client
        .identity()
        .signing
        .sign_domain_b64("http-auth", signing_input.as_bytes());
    let auth_header = format!(
        "Hyphae-Ed25519 node=\"{}\",ts=\"{}\",nonce=\"{}\",sig=\"{}\"",
        client.node_id().as_str(),
        ts,
        nonce,
        sig
    );

    let http = HttpClient::new().unwrap();
    let req = Request::builder()
        .method(Method::PUT)
        .uri(format!("{hub_url}{path_and_query}"))
        .header(CONTENT_TYPE, "application/json")
        .header(AUTHORIZATION, auth_header)
        .header("x-hyphae-node", client.node_id().as_str())
        .body(full_body(body_bytes))
        .unwrap();
    let resp = http.request(req).await.unwrap();
    let (status, _headers, bytes) = HttpClient::collect(resp, 1024 * 1024).await.unwrap();
    let parsed: HandlesResponse = serde_json::from_slice(&bytes).expect("valid HandlesResponse");
    (status, parsed)
}

// ============================================================================
// Test 1: Handle Description Wire Roundtrip, Sanitization & v0.2.0 Interop
// ============================================================================

#[tokio::test]
async fn handle_description_wire_roundtrip_sanitization_and_v020_compat() {
    let hub_dir = TempDir::new().unwrap();
    let alice_dir = TempDir::new().unwrap();
    let bob_dir = TempDir::new().unwrap();

    let (hub, admin_ca, hub_url, _hub_srv) = spawn_hub("hub-desc", hub_dir.path()).await;
    let alice = open_local("alice@macbook", alice_dir.path());
    let bob = open_local("bob@laptop", bob_dir.path());

    pair_member_to_hub(&hub, &admin_ca, &alice).await;
    pair_member_to_hub(&hub, &admin_ca, &bob).await;

    // 1. Register handles with multiline, control chars, multibyte UTF-8, and >200-char payloads.
    let raw_multiline = "  PR reviewer\r\n\tfor \u{0000}Rust\u{0007} crates — café 🚀   ";
    let expected_sanitized = "PR reviewer for Rust crates — café 🚀";
    let rec = alice
        .register_handle_with_description("sess-alice-rev", "reviewer", Some(raw_multiline))
        .await
        .unwrap();
    assert_eq!(rec.description.as_deref(), Some(expected_sanitized));

    let overlong_utf8 = "λ".repeat(MAX_HANDLE_DESCRIPTION_CHARS + 50);
    let expected_truncated = "λ".repeat(MAX_HANDLE_DESCRIPTION_CHARS);
    let long_rec = alice
        .register_handle_with_description("sess-alice-long", "longdesc", Some(&overlong_utf8))
        .await
        .unwrap();
    assert_eq!(long_rec.description.as_deref(), Some(expected_truncated.as_str()));

    bob.register_handle_with_description(
        "sess-bob",
        "codex",
        Some("Backend API & SQLite migrations"),
    )
    .await
    .unwrap();

    // 2. Discover from Bob: receives sanitized descriptions, correct `via`, and deterministic sorting.
    let discovered = bob.discover_peer_handles().await;
    assert_eq!(
        discovered,
        vec![
            DiscoveredPeerHandle {
                address: "alice@macbook/longdesc".to_string(),
                node_id: "alice@macbook".to_string(),
                handle: "longdesc".to_string(),
                description: Some(expected_truncated.clone()),
                via: Some("hub-desc".to_string()),
            },
            DiscoveredPeerHandle {
                address: "alice@macbook/reviewer".to_string(),
                node_id: "alice@macbook".to_string(),
                handle: "reviewer".to_string(),
                description: Some(expected_sanitized.to_string()),
                via: Some("hub-desc".to_string()),
            },
            DiscoveredPeerHandle {
                address: "bob@laptop/codex".to_string(),
                node_id: "bob@laptop".to_string(),
                handle: "codex".to_string(),
                description: Some("Backend API & SQLite migrations".to_string()),
                via: None,
            },
        ]
    );

    // 3. Wire-level v0.2.0 backward & forward compatibility checks.
    // 3a. Empty `descriptions` map is omitted from JSON wire payload (`skip_serializing_if`).
    let empty_req = PutHandlesRequest {
        handles: vec!["legacy".to_string()],
        descriptions: BTreeMap::new(),
    };
    let empty_wire = serde_json::to_string(&empty_req).unwrap();
    assert_eq!(empty_wire, r#"{"handles":["legacy"]}"#);

    // 3b. A v0.2.0 server struct (only `handles`) cleanly ignores v0.3.0 `descriptions`.
    #[derive(Debug, Deserialize)]
    struct V020PutHandlesRequest {
        handles: Vec<String>,
    }
    let v030_req = PutHandlesRequest {
        handles: vec!["reviewer".to_string()],
        descriptions: BTreeMap::from([("reviewer".to_string(), "Security reviewer".to_string())]),
    };
    let v030_wire = serde_json::to_string(&v030_req).unwrap();
    let decoded_by_v020: V020PutHandlesRequest = serde_json::from_str(&v030_wire).unwrap();
    assert_eq!(decoded_by_v020.handles, vec!["reviewer".to_string()]);

    // 3c. Raw HTTP `PUT /v1/handles` sending exact v0.2.0 JSON `{"handles":["legacy"]}` succeeds cleanly.
    let (status, resp) = raw_put_handles(&alice, &hub_url, r#"{"handles":["legacy"]}"#).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp.handles.len(), 1);
    assert_eq!(resp.handles[0].handle, "legacy");
    assert_eq!(resp.handles[0].description, None);
    let resp_val = serde_json::to_value(&resp.handles[0]).unwrap();
    assert!(
        resp_val.get("description").is_none(),
        "None description must be omitted from JSON response"
    );

    // 3d. Stray key in `descriptions` not listed in `handles` is ignored (no ghost handle created).
    let (status, resp) = raw_put_handles(
        &alice,
        &hub_url,
        r#"{"handles":["legacy"],"descriptions":{"legacy":"Active\n\tagent","ghost":"Ignored"}}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(resp.handles.len(), 1);
    assert_eq!(resp.handles[0].handle, "legacy");
    assert_eq!(resp.handles[0].description.as_deref(), Some("Active agent"));

    // 4. Update, clear via `None` / `register_handle`, and preserve across `connect_peer` reconnect.
    alice
        .register_handle_with_description(
            "sess-alice-rev",
            "reviewer",
            Some("Updated security auditor"),
        )
        .await
        .unwrap();
    let discovered_after_update = bob.discover_peer_handles().await;
    let rev = discovered_after_update
        .iter()
        .find(|h| h.address == "alice@macbook/reviewer")
        .unwrap();
    assert_eq!(rev.description.as_deref(), Some("Updated security auditor"));
    let long = discovered_after_update
        .iter()
        .find(|h| h.address == "alice@macbook/longdesc")
        .unwrap();
    assert_eq!(long.description.as_deref(), Some(expected_truncated.as_str()));

    // Backward-compatible `register_handle` clears description to `None` while preserving sibling handles.
    alice
        .register_handle("sess-alice-rev", "reviewer")
        .await
        .unwrap();
    let discovered_after_clear = bob.discover_peer_handles().await;
    let rev = discovered_after_clear
        .iter()
        .find(|h| h.address == "alice@macbook/reviewer")
        .unwrap();
    assert_eq!(rev.description, None);
    let long = discovered_after_clear
        .iter()
        .find(|h| h.address == "alice@macbook/longdesc")
        .unwrap();
    assert_eq!(long.description.as_deref(), Some(expected_truncated.as_str()));

    // Set description again and force a full `connect_peer` reconnect: descriptions MUST survive!
    alice
        .register_handle_with_description(
            "sess-alice-rev",
            "reviewer",
            Some("Persists across reconnect"),
        )
        .await
        .unwrap();
    alice.connect_peer("hub-desc", &hub_url).await.unwrap();
    let discovered_after_reconnect = bob.discover_peer_handles().await;
    let rev = discovered_after_reconnect
        .iter()
        .find(|h| h.address == "alice@macbook/reviewer")
        .unwrap();
    assert_eq!(rev.description.as_deref(), Some("Persists across reconnect"));
    let long = discovered_after_reconnect
        .iter()
        .find(|h| h.address == "alice@macbook/longdesc")
        .unwrap();
    assert_eq!(long.description.as_deref(), Some(expected_truncated.as_str()));

    alice.shutdown();
    bob.shutdown();
    hub.shutdown();
}

// ============================================================================
// Test 2: Multi-Hub Automatic DM & File Transfer Routing, Lazy Refresh,
//         Direct P2P Precedence & Hub Revocation Route Cleanup
// ============================================================================

#[tokio::test]
async fn multi_hub_automatic_dm_and_file_transfer_routing_without_hub_prefix() {
    let hub_alpha_dir = TempDir::new().unwrap();
    let hub_beta_dir = TempDir::new().unwrap();
    let alice_dir = TempDir::new().unwrap();
    let bob_dir = TempDir::new().unwrap();
    let carol_dir = TempDir::new().unwrap();
    let dave_dir = TempDir::new().unwrap();
    let files_dir = TempDir::new().unwrap();

    let (hub_alpha, alpha_ca, _alpha_url, _alpha_srv) =
        spawn_hub("hub-alpha", hub_alpha_dir.path()).await;
    let (hub_beta, beta_ca, _beta_url, _beta_srv) =
        spawn_hub("hub-beta", hub_beta_dir.path()).await;

    let alice = open_local("alice@macbook", alice_dir.path());
    let bob = open_local("bob@laptop", bob_dir.path());
    let carol = open_local("carol@workstation", carol_dir.path());

    // Alice connects to BOTH `hub-alpha` and `hub-beta`.
    // Carol connects ONLY to `hub-alpha`. Bob connects ONLY to `hub-beta`.
    pair_member_to_hub(&hub_alpha, &alpha_ca, &alice).await;
    pair_member_to_hub(&hub_beta, &beta_ca, &alice).await;
    pair_member_to_hub(&hub_alpha, &alpha_ca, &carol).await;
    pair_member_to_hub(&hub_beta, &beta_ca, &bob).await;

    alice
        .register_handle_with_description("sess-alice", "alice", Some("Coordinator"))
        .await
        .unwrap();
    carol
        .register_handle_with_description("sess-carol", "claude", Some("Frontend & design systems"))
        .await
        .unwrap();
    bob.register_handle_with_description("sess-bob", "codex", Some("Distributed systems & Rust"))
        .await
        .unwrap();

    // 1. Structured discovery learns both hub routes & surfaces descriptions + `via`.
    let discovered = alice.discover_peer_handles().await;
    assert_eq!(
        discovered,
        vec![
            DiscoveredPeerHandle {
                address: "alice@macbook/alice".to_string(),
                node_id: "alice@macbook".to_string(),
                handle: "alice".to_string(),
                description: Some("Coordinator".to_string()),
                via: None,
            },
            DiscoveredPeerHandle {
                address: "bob@laptop/codex".to_string(),
                node_id: "bob@laptop".to_string(),
                handle: "codex".to_string(),
                description: Some("Distributed systems & Rust".to_string()),
                via: Some("hub-beta".to_string()),
            },
            DiscoveredPeerHandle {
                address: "carol@workstation/claude".to_string(),
                node_id: "carol@workstation".to_string(),
                handle: "claude".to_string(),
                description: Some("Frontend & design systems".to_string()),
                via: Some("hub-alpha".to_string()),
            },
        ]
    );
    assert_eq!(
        alice
            .db()
            .peers()
            .get_peer_route("bob@laptop")
            .unwrap()
            .unwrap()
            .via_peer,
        "hub-beta"
    );
    assert_eq!(
        alice
            .db()
            .peers()
            .get_peer_route("carol@workstation")
            .unwrap()
            .unwrap()
            .via_peer,
        "hub-alpha"
    );

    // 2. Automatic E2EE DM routing across both hubs WITHOUT any `<hub>!` prefix!
    let dm_bob_secret = "MULTIHUB-BETA-DM-SECRET-847291";
    let dm_bob_res = alice
        .send_dm("alice", "bob@laptop/codex", dm_bob_secret)
        .await
        .unwrap();
    assert!(dm_bob_res.encrypted);
    assert_eq!(dm_bob_res.routed_via, "hub-beta");
    let bob_got = wait_for_mailbox_item(&bob, "sess-bob", |m| m.text == dm_bob_secret).await;
    assert_eq!(bob_got.kind, MailboxKind::Message);
    assert_eq!(bob_got.source, "alice@macbook/alice");
    assert_zero_plaintext_in_sqlite(hub_alpha_dir.path(), dm_bob_secret);
    assert_zero_plaintext_in_sqlite(hub_beta_dir.path(), dm_bob_secret);

    let dm_carol_secret = "MULTIHUB-ALPHA-DM-SECRET-192837";
    let dm_carol_res = alice
        .send_dm("alice", "carol@workstation/claude", dm_carol_secret)
        .await
        .unwrap();
    assert!(dm_carol_res.encrypted);
    assert_eq!(dm_carol_res.routed_via, "hub-alpha");
    let carol_got = wait_for_mailbox_item(&carol, "sess-carol", |m| m.text == dm_carol_secret).await;
    assert_eq!(carol_got.kind, MailboxKind::Message);
    assert_eq!(carol_got.source, "alice@macbook/alice");
    assert_zero_plaintext_in_sqlite(hub_alpha_dir.path(), dm_carol_secret);
    assert_zero_plaintext_in_sqlite(hub_beta_dir.path(), dm_carol_secret);

    // 3. Late-joiner lazy route refresh: Dave joins `hub-beta` AFTER Alice connected & discovered.
    //    Alice sends directly to `dave@linux/ops` WITHOUT calling `discover_peer_handles()` first!
    let dave = open_local("dave@linux", dave_dir.path());
    pair_member_to_hub(&hub_beta, &beta_ca, &dave).await;
    dave.register_handle_with_description("sess-dave", "ops", Some("On-call SRE"))
        .await
        .unwrap();
    assert!(
        alice
            .db()
            .peers()
            .get_peer_route("dave@linux")
            .unwrap()
            .is_none(),
        "route to late-joining Dave must not exist prior to lazy refresh"
    );

    let dm_dave_secret = "LATE-JOINER-LAZY-REFRESH-SECRET-551199";
    let dm_dave_res = alice
        .send_dm("alice", "dave@linux/ops", dm_dave_secret)
        .await
        .unwrap();
    assert!(dm_dave_res.encrypted);
    assert_eq!(dm_dave_res.routed_via, "hub-beta");
    assert_eq!(
        alice
            .db()
            .peers()
            .get_peer_route("dave@linux")
            .unwrap()
            .unwrap()
            .via_peer,
        "hub-beta"
    );
    let dave_got = wait_for_mailbox_item(&dave, "sess-dave", |m| m.text == dm_dave_secret).await;
    assert_eq!(dave_got.source, "alice@macbook/alice");
    assert_zero_plaintext_in_sqlite(hub_alpha_dir.path(), dm_dave_secret);
    assert_zero_plaintext_in_sqlite(hub_beta_dir.path(), dm_dave_secret);

    // 4. Automatic multi-hub E2EE file transfer routing (`via_hub: None`).
    let beta_file_path = files_dir.path().join("beta_report.txt");
    let beta_file_secret = "TOPSECRET-BETA-TRANSFER-PAYLOAD-404992";
    fs::write(&beta_file_path, beta_file_secret).unwrap();
    let beta_xfer = alice
        .send_files(
            "bob@laptop",
            Some("codex"),
            &[TarInputEntry {
                archive_path: "beta_report.txt".to_string(),
                source_path: beta_file_path.clone(),
            }],
            None,
        )
        .await
        .unwrap();
    assert_eq!(beta_xfer.routed_via, "hub-beta");

    let bob_xfer_item = wait_for_mailbox_item(&bob, "sess-bob", |m| {
        m.kind == MailboxKind::Transfer && m.text.contains(&beta_xfer.id)
    })
    .await;
    let notice: Value = serde_json::from_str(&bob_xfer_item.text).unwrap();
    let disk_path = notice["files"][0]["diskPath"].as_str().unwrap();
    assert_eq!(fs::read_to_string(disk_path).unwrap(), beta_file_secret);
    assert_zero_plaintext_in_sqlite(hub_alpha_dir.path(), beta_file_secret);
    assert_zero_plaintext_in_sqlite(hub_beta_dir.path(), beta_file_secret);

    // Also verify `send_files` auto-routes to Carol via `hub-alpha`.
    let alpha_file_path = files_dir.path().join("alpha_spec.txt");
    let alpha_file_secret = "TOPSECRET-ALPHA-TRANSFER-PAYLOAD-331122";
    fs::write(&alpha_file_path, alpha_file_secret).unwrap();
    let alpha_xfer = alice
        .send_files(
            "carol@workstation",
            Some("claude"),
            &[TarInputEntry {
                archive_path: "alpha_spec.txt".to_string(),
                source_path: alpha_file_path.clone(),
            }],
            None,
        )
        .await
        .unwrap();
    assert_eq!(alpha_xfer.routed_via, "hub-alpha");
    let carol_xfer_item = wait_for_mailbox_item(&carol, "sess-carol", |m| {
        m.kind == MailboxKind::Transfer && m.text.contains(&alpha_xfer.id)
    })
    .await;
    let carol_notice: Value = serde_json::from_str(&carol_xfer_item.text).unwrap();
    let carol_disk = carol_notice["files"][0]["diskPath"].as_str().unwrap();
    assert_eq!(fs::read_to_string(carol_disk).unwrap(), alpha_file_secret);

    // 5. Direct P2P link MUST take precedence over learned hub route!
    // 5a. Outbound direct P2P `PeerLink`: Bob serves + invites Alice -> Alice connects directly to Bob.
    let (_bob_p2p_addr, _bob_srv) = Arc::clone(&bob).serve(loopback_zero()).await.unwrap();
    let p2p_scopes = ScopePreset::Member.expand();
    let (bob_p2p_invite, _) = bob
        .create_p2p_invite(p2p_scopes.clone(), p2p_scopes.clone(), 300_000)
        .unwrap();
    alice
        .accept_p2p_invite(&bob_p2p_invite, p2p_scopes.clone())
        .await
        .unwrap();

    // Discovery prefers direct `via: Some("bob@laptop")` over hub-relayed `via: Some("hub-beta")`!
    let discovered_with_p2p = alice.discover_peer_handles().await;
    let bob_disc = discovered_with_p2p
        .iter()
        .find(|h| h.address == "bob@laptop/codex")
        .unwrap();
    assert_eq!(bob_disc.via.as_deref(), Some("bob@laptop"));
    assert_eq!(
        bob_disc.description.as_deref(),
        Some("Distributed systems & Rust")
    );

    // DM & file transfer to Bob route directly via `bob@laptop` (NOT `hub-beta`!).
    let p2p_bob_dm = "DIRECT-P2P-BEATS-HUB-BETA-DM-998877";
    let p2p_dm_res = alice
        .send_dm("alice", "bob@laptop/codex", p2p_bob_dm)
        .await
        .unwrap();
    assert!(p2p_dm_res.encrypted);
    assert_eq!(p2p_dm_res.routed_via, "bob@laptop");
    let _ = wait_for_mailbox_item(&bob, "sess-bob", |m| m.text == p2p_bob_dm).await;
    assert!(
        hub_beta
            .db()
            .messages()
            .get_message(&p2p_dm_res.id)
            .unwrap()
            .is_none(),
        "direct P2P DM must bypass hub-beta completely"
    );

    let p2p_xfer = alice
        .send_files(
            "bob@laptop",
            Some("codex"),
            &[TarInputEntry {
                archive_path: "beta_report.txt".to_string(),
                source_path: beta_file_path,
            }],
            None,
        )
        .await
        .unwrap();
    assert_eq!(p2p_xfer.routed_via, "bob@laptop");
    let _ = wait_for_mailbox_item(&bob, "sess-bob", |m| {
        m.kind == MailboxKind::Transfer && m.text.contains(&p2p_xfer.id)
    })
    .await;
    assert!(
        hub_beta
            .db()
            .transfers()
            .get(&p2p_xfer.id)
            .unwrap()
            .is_none(),
        "direct P2P file transfer must bypass hub-beta completely"
    );

    // 5b. Outbound-only P2P peer: Alice serves + invites Carol -> Carol connects inbound via SSE.
    let (_alice_p2p_addr, _alice_srv) = Arc::clone(&alice).serve(loopback_zero()).await.unwrap();
    let (alice_p2p_invite, _) = alice
        .create_p2p_invite(p2p_scopes.clone(), p2p_scopes.clone(), 300_000)
        .unwrap();
    carol
        .accept_p2p_invite(&alice_p2p_invite, p2p_scopes)
        .await
        .unwrap();

    // Discovery prefers direct `via: Some("carol@workstation")` over `via: Some("hub-alpha")`.
    let discovered_with_both_p2p = alice.discover_peer_handles().await;
    let carol_disc = discovered_with_both_p2p
        .iter()
        .find(|h| h.address == "carol@workstation/claude")
        .unwrap();
    assert_eq!(carol_disc.via.as_deref(), Some("carol@workstation"));
    assert_eq!(
        carol_disc.description.as_deref(),
        Some("Frontend & design systems")
    );

    // DM & file transfer to outbound-only P2P Carol route via Alice's own SSE server (NOT `hub-alpha`!).
    let p2p_carol_dm = "DIRECT-SSE-P2P-BEATS-HUB-ALPHA-DM-665544";
    let p2p_carol_res = alice
        .send_dm("alice", "carol@workstation/claude", p2p_carol_dm)
        .await
        .unwrap();
    assert!(p2p_carol_res.encrypted);
    assert_eq!(p2p_carol_res.routed_via, "alice@macbook");
    let _ = wait_for_mailbox_item(&carol, "sess-carol", |m| m.text == p2p_carol_dm).await;
    assert!(
        hub_alpha
            .db()
            .messages()
            .get_message(&p2p_carol_res.id)
            .unwrap()
            .is_none(),
        "outbound-only P2P DM must bypass hub-alpha completely"
    );

    let p2p_carol_xfer = alice
        .send_files(
            "carol@workstation",
            Some("claude"),
            &[TarInputEntry {
                archive_path: "alpha_spec.txt".to_string(),
                source_path: alpha_file_path,
            }],
            None,
        )
        .await
        .unwrap();
    assert_eq!(p2p_carol_xfer.routed_via, "alice@macbook");
    let _ = wait_for_mailbox_item(&carol, "sess-carol", |m| {
        m.kind == MailboxKind::Transfer && m.text.contains(&p2p_carol_xfer.id)
    })
    .await;
    assert!(
        hub_alpha
            .db()
            .transfers()
            .get(&p2p_carol_xfer.id)
            .unwrap()
            .is_none(),
        "outbound-only P2P file transfer must bypass hub-alpha completely"
    );

    // 6. Revoking `hub-beta` clears all learned routes via `hub-beta` and stops re-learning from it!
    alice
        .db()
        .peers()
        .set_peer_status("hub-beta", PeerStatus::Revoked, now_ms())
        .unwrap();
    assert!(
        alice
            .db()
            .peers()
            .get_peer_route("bob@laptop")
            .unwrap()
            .is_none(),
        "revoking hub-beta must clear bob@laptop route"
    );
    assert!(
        alice
            .db()
            .peers()
            .get_peer_route("dave@linux")
            .unwrap()
            .is_none(),
        "revoking hub-beta must clear dave@linux route"
    );

    let discovered_after_revoke = alice.discover_peer_handles().await;
    assert!(
        !discovered_after_revoke
            .iter()
            .any(|h| h.node_id == "dave@linux"),
        "revoked hub-beta must not be queried during discovery"
    );
    assert!(
        discovered_after_revoke
            .iter()
            .any(|h| h.address == "bob@laptop/codex" && h.via.as_deref() == Some("bob@laptop")),
        "direct P2P peer Bob must remain discoverable after hub-beta revocation"
    );
    assert!(
        alice
            .db()
            .peers()
            .get_peer_route("dave@linux")
            .unwrap()
            .is_none(),
        "revoked hub-beta must not re-populate peer_routes"
    );

    alice.shutdown();
    bob.shutdown();
    carol.shutdown();
    dave.shutdown();
    hub_alpha.shutdown();
    hub_beta.shutdown();
}

// ============================================================================
// Test 3: Connect-Time Route Seeding (`accept_am2_invite` & `connect_peer`)
// ============================================================================

#[tokio::test]
async fn connect_peer_and_pair_seed_routes_immediately() {
    let hub_alpha_dir = TempDir::new().unwrap();
    let hub_beta_dir = TempDir::new().unwrap();
    let alice_dir = TempDir::new().unwrap();
    let bob_dir = TempDir::new().unwrap();
    let carol_dir = TempDir::new().unwrap();

    let (hub_alpha, alpha_ca, _alpha_url, _alpha_srv) =
        spawn_hub("hub-alpha", hub_alpha_dir.path()).await;
    let (hub_beta, beta_ca, beta_url, _beta_srv) =
        spawn_hub("hub-beta", hub_beta_dir.path()).await;

    // Carol and Bob join their hubs BEFORE Alice ever connects.
    let carol = open_local("carol@workstation", carol_dir.path());
    pair_member_to_hub(&hub_alpha, &alpha_ca, &carol).await;
    carol
        .register_handle_with_description("sess-carol", "claude", Some("Alpha worker"))
        .await
        .unwrap();

    let bob = open_local("bob@laptop", bob_dir.path());
    pair_member_to_hub(&hub_beta, &beta_ca, &bob).await;
    bob.register_handle_with_description("sess-bob", "codex", Some("Beta worker"))
        .await
        .unwrap();

    // Alice connects to both hubs; routes are seeded immediately without calling `discover_peer_handles()`.
    let alice = open_local("alice@macbook", alice_dir.path());
    pair_member_to_hub(&hub_alpha, &alpha_ca, &alice).await;
    pair_member_to_hub(&hub_beta, &beta_ca, &alice).await;

    assert_eq!(
        alice
            .db()
            .peers()
            .get_peer_route("carol@workstation")
            .unwrap()
            .unwrap()
            .via_peer,
        "hub-alpha"
    );
    assert_eq!(
        alice
            .db()
            .peers()
            .get_peer_route("bob@laptop")
            .unwrap()
            .unwrap()
            .via_peer,
        "hub-beta"
    );

    // Clear `peer_routes` manually and reconnect via `connect_peer` -> re-seeds immediately!
    alice.db().peers().delete_peer_routes_via("hub-beta").unwrap();
    assert!(
        alice
            .db()
            .peers()
            .get_peer_route("bob@laptop")
            .unwrap()
            .is_none()
    );
    alice.connect_peer("hub-beta", &beta_url).await.unwrap();
    assert_eq!(
        alice
            .db()
            .peers()
            .get_peer_route("bob@laptop")
            .unwrap()
            .unwrap()
            .via_peer,
        "hub-beta"
    );

    alice.shutdown();
    bob.shutdown();
    carol.shutdown();
    hub_alpha.shutdown();
    hub_beta.shutdown();
}
