//! E2E Security Wire, Rate-Limit, and HTTP Streaming E2EE Transfer Guard Tests (`hyp-node`).
//!
//! 100% pure Rust & cross-platform (`tempfile::TempDir`, `127.0.0.1:0`, `SecretBackend::File`,
//! zero live Keychain or external network access).
//!
//! Covers:
//! 1. Ed25519 HTTP-auth nonce replay protection & clock-skew boundary matrix (`±299s` vs `±301s`).
//! 2. HTTP `POST /v1/messages` rate limiting (`429` RFC 9457 Problem Details + numeric `Retry-After`).
//! 3. Real HTTP `PeerLink` streaming E2EE transfer (`transfer.stream.v2`) mutated-valid matrix:
//!    - (a) Benign file delivered & decrypted cleanly with zero hub plaintext.
//!    - (b) Malicious archives (`evil.sh`, `.git/hooks/pre-commit`) rejected fail-closed by
//!      recipient attachment guard with ZERO unpacked files and ZERO mailbox entry.
//!    - (c) 1-bit flipped ciphertext blob rejected fail-closed on BOTH hub-disk SHA-256 tamper
//!      AND matching-SHA-256 AEAD tag verification with ZERO extraction.
//!    - (d) Unauthorized 3rd peer (`carol`) calling `GET /v1/transfers/<id>` -> `401 unauthorized`.
//!    - (e) Transfer exceeding `files:send=<maxBytes>` scope cap -> `403 not_granted`.

mod common;

use std::fs::{self, File};
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_TYPE, RETRY_AFTER};
use http::{Method, Request, StatusCode};
use serde_json::{Value, json};
use tempfile::TempDir;

use common::{
    DeterministicRng, Ed25519AuthBuilder, assert_zero_plaintext_in_sqlite, loopback_zero,
    wait_for_mailbox_item,
};
use hyp_crypto::rfc3339::format_rfc3339_millis;
use hyp_crypto::transfer::{
    StreamEncryptParams, TarInputEntry, TarPackOptions, encrypt_stream_v2, pack_tar_gz,
};
use hyp_crypto::{Ed25519KeyPair, SecretBackend};
use hyp_node::engine::http_util::{HttpClient, full_body};
use hyp_node::engine::{NodeConfig, NodeError, UnifiedNode};
use hyp_proto::address::NodeId;
use hyp_proto::manifest::{OkpCurve, OkpJwk};
use hyp_proto::problem::{CONTENT_TYPE_PROBLEM_JSON, ProblemDetails};
use hyp_proto::scopes::ScopePreset;
use hyp_store::{MailboxKind, TransferRecord, TransferState, TrustTier, now_ms, sha256_hex};

/// Waits until `hub`'s transfer row for `transfer_id` transitions to `expected_state`.
async fn wait_for_transfer_state(
    hub: &Arc<UnifiedNode>,
    transfer_id: &str,
    expected_state: TransferState,
    timeout_dur: Duration,
) -> TransferRecord {
    let deadline = tokio::time::Instant::now() + timeout_dur;
    loop {
        if let Some(rec) = hub.db().transfers().get(transfer_id).expect("get transfer") {
            if rec.state == expected_state {
                return rec;
            }
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for transfer '{transfer_id}' to reach {expected_state:?}; current={:?}",
            hub.db().transfers().get(transfer_id)
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Writes `bytes` to a temporary source file under `stage_dir` and returns a `TarInputEntry`.
fn stage_tar_entry(
    stage_dir: &Path,
    local_name: &str,
    archive_path: &str,
    bytes: &[u8],
) -> TarInputEntry {
    let source_path = stage_dir.join(local_name);
    fs::write(&source_path, bytes).expect("write tar source file");
    TarInputEntry {
        archive_path: archive_path.to_string(),
        source_path,
    }
}

/// Scans every file under `dir` recursively to verify zero plaintext substring leakage.
fn assert_zero_plaintext_in_dir(dir: &Path, needle: &str) {
    if !dir.exists() {
        return;
    }
    let needle_bytes = needle.as_bytes();
    for entry in fs::read_dir(dir).expect("read dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            assert_zero_plaintext_in_dir(&path, needle);
        } else if path.is_file() {
            let bytes = fs::read(&path).expect("read file");
            assert!(
                !bytes.windows(needle_bytes.len()).any(|w| w == needle_bytes),
                "SECURITY VIOLATION: found plaintext {:?} in {}!",
                needle,
                path.display()
            );
        }
    }
}

// ============================================================================
// 1. Ed25519 Nonce Replay & Clock-Skew Boundary Matrix
// ============================================================================

#[tokio::test]
async fn ed25519_nonce_replay_and_clock_skew_boundary_matrix() {
    let hub_dir = TempDir::new().unwrap();
    let alice_dir = TempDir::new().unwrap();
    let bob_dir = TempDir::new().unwrap();

    let admin_ca = Ed25519KeyPair::generate().unwrap();
    let admin_jwk = OkpJwk::new(OkpCurve::Ed25519, &admin_ca.public_key_bytes());

    let mut hub_cfg = NodeConfig::router(NodeId::new("acme-hub").unwrap(), hub_dir.path());
    hub_cfg.secret_backend = Some(SecretBackend::File);
    hub_cfg.admin_jwk = Some(admin_jwk);
    let hub = UnifiedNode::open(hub_cfg).unwrap();
    let (hub_addr, _hub_srv) = Arc::clone(&hub).serve(loopback_zero()).await.unwrap();
    let hub_url = format!("http://{hub_addr}");

    let mut alice_cfg = NodeConfig::local(NodeId::new("alice@macbook").unwrap(), alice_dir.path());
    alice_cfg.secret_backend = Some(SecretBackend::File);
    let alice = UnifiedNode::open(alice_cfg).unwrap();

    let mut bob_cfg = NodeConfig::local(NodeId::new("bob@laptop").unwrap(), bob_dir.path());
    bob_cfg.secret_backend = Some(SecretBackend::File);
    let bob = UnifiedNode::open(bob_cfg).unwrap();

    let scopes = ScopePreset::Member.expand();
    let scope_refs: Vec<&str> = scopes.iter().map(String::as_str).collect();
    let (alice_am2, _) = hub
        .create_admin_invite(
            &admin_ca,
            "alice@macbook",
            &scope_refs,
            TrustTier::Org,
            300_000,
        )
        .unwrap();
    let (bob_am2, _) = hub
        .create_admin_invite(
            &admin_ca,
            "bob@laptop",
            &scope_refs,
            TrustTier::Org,
            300_000,
        )
        .unwrap();
    alice.accept_am2_invite(&alice_am2).await.unwrap();
    bob.accept_am2_invite(&bob_am2).await.unwrap();

    let client = HttpClient::new().unwrap();

    // (a) Identical signed request replayed within skew window -> 1st 200, 2nd 401 `unauthorized`!
    let replay_ts = now_ms();
    let replay_builder = Ed25519AuthBuilder::new("alice@macbook", &alice.identity().signing)
        .with_timestamp_ms(replay_ts)
        .with_nonce("fixed-replay-nonce-001");
    let headers_first = replay_builder.build_headers("GET", "/v1/channels", b"");
    let signed_auth = headers_first.get(AUTHORIZATION).unwrap().to_str().unwrap();
    assert!(signed_auth.contains(&format!("ts=\"{replay_ts}\"")));
    assert!(signed_auth.contains("nonce=\"fixed-replay-nonce-001\""));

    // A valid split tuple is no longer a credential and must not consume its nonce.
    // Supplying it alongside invalid Authorization cannot rescue that credential either.
    let mut split = headers_first.clone();
    split.remove(AUTHORIZATION);
    split.insert("x-hyphae-timestamp", replay_ts.to_string().parse().unwrap());
    split.insert("x-hyphae-nonce", "fixed-replay-nonce-001".parse().unwrap());
    let signature = signed_auth
        .split("sig=\"")
        .nth(1)
        .unwrap()
        .trim_end_matches('"');
    split.insert("x-hyphae-sig", signature.parse().unwrap());
    for authorization in [
        None,
        Some("Bearer unknown-test-credential"),
        Some("invalid"),
    ] {
        let mut request = Request::builder()
            .method(Method::GET)
            .uri(format!("{hub_url}/v1/channels"))
            .body(full_body(Bytes::new()))
            .unwrap();
        *request.headers_mut() = split.clone();
        if let Some(value) = authorization {
            request
                .headers_mut()
                .insert(AUTHORIZATION, value.parse().unwrap());
        }
        assert_eq!(
            client.request(request).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
    }

    // Bearer remains sufficient on its own; retired split fields are not a second factor.
    let bearer = "isolated-split-retirement-test-credential";
    hub.db()
        .local()
        .set_metadata(
            &format!("auth_token:{}", sha256_hex(bearer.as_bytes())),
            &json!({"peerId":"alice@macbook"}).to_string(),
        )
        .unwrap();
    let mut bearer_headers = split.clone();
    bearer_headers.insert(AUTHORIZATION, format!("Bearer {bearer}").parse().unwrap());
    bearer_headers.insert("x-hyphae-sig", "retired-and-invalid".parse().unwrap());
    let authenticated = hub
        .authenticate_request(&bearer_headers, "GET", "/v1/channels", &sha256_hex(b""))
        .unwrap()
        .unwrap();
    assert_eq!(authenticated.peer_id, "alice@macbook");

    let req1 = replay_builder.sign_request(Method::GET, &hub_url, "/v1/channels", None, None);
    let resp1 = client.request(req1).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);

    // Exact byte-for-byte replay of the same signed request -> 401 unauthorized!
    let req2 = replay_builder.sign_request(Method::GET, &hub_url, "/v1/channels", None, None);
    let resp2 = client.request(req2).await.unwrap();
    let (status2, resp2_headers, body2) = HttpClient::collect(resp2, 64 * 1024).await.unwrap();
    assert_eq!(status2, StatusCode::UNAUTHORIZED);
    assert_eq!(
        resp2_headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some(CONTENT_TYPE_PROBLEM_JSON)
    );
    let prob2: ProblemDetails = serde_json::from_slice(&body2).unwrap();
    assert_eq!(prob2.status, 401);
    assert_eq!(prob2.error, "unauthorized");
    assert!(
        prob2
            .detail
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase()
            .contains("replayed"),
        "expected replay detail, got {:?}",
        prob2.detail
    );

    // Same (peer_id, nonce) reused on a DIFFERENT path with fresh signature -> STILL 401!
    let req2_other_path =
        replay_builder.sign_request(Method::GET, &hub_url, "/v1/keys", None, None);
    let resp2_other = client.request(req2_other_path).await.unwrap();
    assert_eq!(resp2_other.status(), StatusCode::UNAUTHORIZED);

    // (b) Different peer (`bob@laptop`) using the same nonce string -> 200 OK (scoped per peer_id),
    //     then Bob replaying it -> 401!
    let bob_same_nonce = Ed25519AuthBuilder::new("bob@laptop", &bob.identity().signing)
        .with_timestamp_ms(now_ms())
        .with_nonce("fixed-replay-nonce-001");
    let bob_req1 = bob_same_nonce.sign_request(Method::GET, &hub_url, "/v1/channels", None, None);
    assert_eq!(
        client.request(bob_req1).await.unwrap().status(),
        StatusCode::OK
    );
    let bob_req2 = bob_same_nonce.sign_request(Method::GET, &hub_url, "/v1/channels", None, None);
    assert_eq!(
        client.request(bob_req2).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );

    // (c) Different nonces with valid timestamps -> both 200 OK!
    let fresh_builder = Ed25519AuthBuilder::new("alice@macbook", &alice.identity().signing);
    let req_a = fresh_builder.sign_request(Method::GET, &hub_url, "/v1/channels", None, None);
    let req_b = fresh_builder.sign_request(Method::GET, &hub_url, "/v1/channels", None, None);
    assert_eq!(
        client.request(req_a).await.unwrap().status(),
        StatusCode::OK
    );
    assert_eq!(
        client.request(req_b).await.unwrap().status(),
        StatusCode::OK
    );

    // (d) Forged/invalid signature does NOT poison the replay cache for that nonce!
    let unpoisoned = Ed25519AuthBuilder::new("alice@macbook", &alice.identity().signing)
        .with_timestamp_ms(now_ms())
        .with_nonce("unpoisoned-nonce-777");
    let valid_auth = unpoisoned.authorization_header("GET", "/v1/channels", b"");
    let (prefix, sig_quoted) = valid_auth.rsplit_once("sig=\"").unwrap();
    let sig_b64 = sig_quoted.trim_end_matches('"');
    let mut sig_bytes = URL_SAFE_NO_PAD.decode(sig_b64).unwrap();
    sig_bytes[0] ^= 0x01;
    let bad_auth = format!("{prefix}sig=\"{}\"", URL_SAFE_NO_PAD.encode(sig_bytes));
    let forged_req = Request::builder()
        .method(Method::GET)
        .uri(format!("{hub_url}/v1/channels"))
        .header(AUTHORIZATION, bad_auth)
        .body(full_body(Bytes::new()))
        .unwrap();
    assert_eq!(
        client.request(forged_req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    // Now the legitimate signed request with the same nonce MUST succeed!
    let legit_req = unpoisoned.sign_request(Method::GET, &hub_url, "/v1/channels", None, None);
    assert_eq!(
        client.request(legit_req).await.unwrap().status(),
        StatusCode::OK
    );

    // (e) Clock-skew boundary matrix (`HTTP_AUTH_SKEW_MS = 300_000` ms):
    //   now - 299_000 -> 200
    //   now + 299_000 -> 200 (and replay -> 401)
    //   now - 301_000 -> 401
    //   now + 301_000 -> 401
    let skew_cases: &[(&str, i64, StatusCode)] = &[
        ("skew-past-ok", -299_000, StatusCode::OK),
        ("skew-future-ok", 299_000, StatusCode::OK),
        ("skew-past-reject", -301_000, StatusCode::UNAUTHORIZED),
        ("skew-future-reject", 301_000, StatusCode::UNAUTHORIZED),
    ];
    for &(label, delta_ms, expected_status) in skew_cases {
        let ts = now_ms() + delta_ms;
        let b = Ed25519AuthBuilder::new("alice@macbook", &alice.identity().signing)
            .with_timestamp_ms(ts)
            .with_nonce(format!("nonce-{label}"));
        let req = b.sign_request(Method::GET, &hub_url, "/v1/channels", None, None);
        let resp = client.request(req).await.unwrap();
        let (status, _, body) = HttpClient::collect(resp, 64 * 1024).await.unwrap();
        assert_eq!(
            status,
            expected_status,
            "case={label} delta_ms={delta_ms}: body={}",
            String::from_utf8_lossy(&body)
        );
        if expected_status == StatusCode::UNAUTHORIZED {
            let prob: ProblemDetails = serde_json::from_slice(&body).unwrap();
            assert_eq!(prob.status, 401);
            assert_eq!(prob.error, "unauthorized");
        } else {
            // Replaying the valid boundary request (including future-skewed +299s) MUST fail!
            let replay_req = b.sign_request(Method::GET, &hub_url, "/v1/channels", None, None);
            assert_eq!(
                client.request(replay_req).await.unwrap().status(),
                StatusCode::UNAUTHORIZED,
                "case={label}: replay must fail closed with 401"
            );
        }
    }

    alice.shutdown();
    bob.shutdown();
    hub.shutdown();
}

// ============================================================================
// 2. HTTP `POST /v1/messages` Rate Limit (`429`) + Numeric `Retry-After`
// ============================================================================

#[tokio::test]
async fn http_post_messages_rate_limit_429_includes_retry_after_header() {
    let hub_dir = TempDir::new().unwrap();
    let alice_dir = TempDir::new().unwrap();
    let bob_dir = TempDir::new().unwrap();

    let admin_ca = Ed25519KeyPair::generate().unwrap();
    let admin_jwk = OkpJwk::new(OkpCurve::Ed25519, &admin_ca.public_key_bytes());

    let mut hub_cfg = NodeConfig::router(NodeId::new("acme-rl").unwrap(), hub_dir.path());
    hub_cfg.secret_backend = Some(SecretBackend::File);
    hub_cfg.admin_jwk = Some(admin_jwk);
    hub_cfg
        .store_config
        .message_limits
        .max_per_hour_per_recipient = 3;
    let hub = UnifiedNode::open(hub_cfg).unwrap();
    let (hub_addr, _hub_srv) = Arc::clone(&hub).serve(loopback_zero()).await.unwrap();
    let hub_url = format!("http://{hub_addr}");

    let mut alice_cfg = NodeConfig::local(NodeId::new("alice@macbook").unwrap(), alice_dir.path());
    alice_cfg.secret_backend = Some(SecretBackend::File);
    let alice = UnifiedNode::open(alice_cfg).unwrap();

    let mut bob_cfg = NodeConfig::local(NodeId::new("bob@laptop").unwrap(), bob_dir.path());
    bob_cfg.secret_backend = Some(SecretBackend::File);
    let bob = UnifiedNode::open(bob_cfg).unwrap();

    let scopes = ScopePreset::Member.expand();
    let scope_refs: Vec<&str> = scopes.iter().map(String::as_str).collect();
    let (alice_am2, _) = hub
        .create_admin_invite(
            &admin_ca,
            "alice@macbook",
            &scope_refs,
            TrustTier::Org,
            300_000,
        )
        .unwrap();
    let (bob_am2, _) = hub
        .create_admin_invite(
            &admin_ca,
            "bob@laptop",
            &scope_refs,
            TrustTier::Org,
            300_000,
        )
        .unwrap();
    alice.accept_am2_invite(&alice_am2).await.unwrap();
    bob.accept_am2_invite(&bob_am2).await.unwrap();

    alice.register_handle("sess-a", "claude").await.unwrap();
    bob.register_handle("sess-b", "codex").await.unwrap();
    // Shut down Bob's SSE consumer so raw plaintext wire messages remain queued on the hub
    // instead of being rejected by Bob's default `E2eePolicy::Required`.
    bob.shutdown();

    let client = HttpClient::new().unwrap();
    let auth = Ed25519AuthBuilder::new("alice@macbook", &alice.identity().signing);

    // First 3 messages within `max_per_hour_per_recipient = 3` -> 200 OK.
    for idx in 1..=3 {
        let payload = serde_json::to_vec(&json!({
            "id": format!("rl-msg-{idx}"),
            "fromHandle": "claude",
            "to": "bob@laptop/codex",
            "text": format!("message number {idx}"),
        }))
        .unwrap();
        let req = auth.sign_request(
            Method::POST,
            &hub_url,
            "/v1/messages",
            Some(Bytes::from(payload)),
            Some("application/json"),
        );
        let resp = client.request(req).await.unwrap();
        let (status, _, body) = HttpClient::collect(resp, 64 * 1024).await.unwrap();
        assert_eq!(
            status,
            StatusCode::OK,
            "message #{idx} should succeed, got {}: {}",
            status,
            String::from_utf8_lossy(&body)
        );
    }

    // 4th message exceeds per-hour recipient cap -> 429 RFC 9457 Problem Details + numeric Retry-After!
    let payload4 = serde_json::to_vec(&json!({
        "id": "rl-msg-4",
        "fromHandle": "claude",
        "to": "bob@laptop/codex",
        "text": "message number 4 should be rate limited",
    }))
    .unwrap();
    let req4 = auth.sign_request(
        Method::POST,
        &hub_url,
        "/v1/messages",
        Some(Bytes::from(payload4)),
        Some("application/json"),
    );
    let resp4 = client.request(req4).await.unwrap();
    let (status4, headers4, body4) = HttpClient::collect(resp4, 64 * 1024).await.unwrap();
    assert_eq!(status4, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        headers4.get(CONTENT_TYPE).and_then(|v| v.to_str().ok()),
        Some(CONTENT_TYPE_PROBLEM_JSON)
    );
    let retry_after_str = headers4
        .get(RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .expect("429 response MUST include Retry-After header");
    let retry_after_secs: u64 = retry_after_str
        .parse()
        .expect("Retry-After header must be numeric delta-seconds");
    assert!(
        retry_after_secs > 0,
        "Retry-After must be > 0, got {retry_after_secs}"
    );

    let prob4: ProblemDetails = serde_json::from_slice(&body4).expect("valid ProblemDetails");
    assert_eq!(prob4.status, 429);
    assert_eq!(prob4.error, "rate_limited");

    alice.shutdown();
    bob.shutdown();
    hub.shutdown();
}

// ============================================================================
// 3. Real HTTP `PeerLink` Streaming E2EE Transfer Mutated-Valid Matrix
// ============================================================================

#[tokio::test]
async fn http_peerlink_streaming_e2ee_transfer_mutated_valid_matrix() {
    let hub_dir = TempDir::new().unwrap();
    let alice_dir = TempDir::new().unwrap();
    let bob_dir = TempDir::new().unwrap();
    let carol_dir = TempDir::new().unwrap();
    let dave_dir = TempDir::new().unwrap();
    let eve_dir = TempDir::new().unwrap();

    let admin_ca = Ed25519KeyPair::generate().unwrap();
    let admin_jwk = OkpJwk::new(OkpCurve::Ed25519, &admin_ca.public_key_bytes());

    let mut hub_cfg = NodeConfig::router(NodeId::new("acme-xfer").unwrap(), hub_dir.path());
    hub_cfg.secret_backend = Some(SecretBackend::File);
    hub_cfg.admin_jwk = Some(admin_jwk);
    let hub = UnifiedNode::open(hub_cfg).unwrap();
    let (hub_addr, _hub_srv) = Arc::clone(&hub).serve(loopback_zero()).await.unwrap();
    let hub_url = format!("http://{hub_addr}");

    let open_local = |id: &str, dir: &Path| {
        let mut cfg = NodeConfig::local(NodeId::new(id).unwrap(), dir);
        cfg.secret_backend = Some(SecretBackend::File);
        UnifiedNode::open(cfg).unwrap()
    };

    let alice = open_local("alice@macbook", alice_dir.path());
    let bob = open_local("bob@laptop", bob_dir.path());
    let carol = open_local("carol@workstation", carol_dir.path());
    let dave = open_local("dave@capped", dave_dir.path());
    let eve = open_local("eve@offline", eve_dir.path());

    let member_scopes = ScopePreset::Member.expand();
    let member_refs: Vec<&str> = member_scopes.iter().map(String::as_str).collect();

    for (node_id, node) in [
        ("alice@macbook", &alice),
        ("bob@laptop", &bob),
        ("carol@workstation", &carol),
        ("eve@offline", &eve),
    ] {
        let (am2, _) = hub
            .create_admin_invite(&admin_ca, node_id, &member_refs, TrustTier::Org, 300_000)
            .unwrap();
        node.accept_am2_invite(&am2).await.unwrap();
    }

    // Pair `dave@capped` with a tight byte cap scope `files:send=1kb` (1024 bytes).
    let (dave_am2, _) = hub
        .create_admin_invite(
            &admin_ca,
            "dave@capped",
            &["dm:receive", "files:send=1kb"],
            TrustTier::Org,
            300_000,
        )
        .unwrap();
    dave.accept_am2_invite(&dave_am2).await.unwrap();

    alice.register_handle("sess-alice", "claude").await.unwrap();
    bob.register_handle("sess-bob", "codex").await.unwrap();
    carol.register_handle("sess-carol", "gemini").await.unwrap();
    eve.register_handle("sess-eve", "codex").await.unwrap();

    // ------------------------------------------------------------------------
    // (a) Benign file via `send_files` over real HTTP hub -> delivered & decrypted cleanly,
    //     ZERO hub plaintext in SQLite or transfer blobs!
    // ------------------------------------------------------------------------
    let src_stage = TempDir::new().unwrap();
    let benign_secret = "BENIGN_E2EE_TRANSFER_PLAINTEXT_CANARY_9f8a7b6c";
    let benign_entry_in = stage_tar_entry(
        src_stage.path(),
        "design.txt",
        "docs/design.txt",
        benign_secret.as_bytes(),
    );
    let benign_res = alice
        .send_files(
            "bob@laptop",
            Some("codex"),
            &[benign_entry_in],
            Some("acme-xfer"),
        )
        .await
        .expect("benign send_files must succeed");
    assert_eq!(benign_res.to_node, "bob@laptop");
    assert_eq!(benign_res.routed_via, "acme-xfer");

    let benign_entry = wait_for_mailbox_item(&bob, "sess-bob", Duration::from_secs(5), |m| {
        m.kind == MailboxKind::Transfer && m.text.contains(&benign_res.id)
    })
    .await;
    let notice: Value = serde_json::from_str(&benign_entry.text).unwrap();
    let files = notice["files"].as_array().expect("files array");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["archivePath"], "docs/design.txt");
    let disk_path = files[0]["diskPath"].as_str().expect("diskPath");
    let unpacked_bytes = fs::read(disk_path).expect("read unpacked benign file");
    assert_eq!(unpacked_bytes, benign_secret.as_bytes());

    assert_zero_plaintext_in_sqlite(hub_dir.path(), &[benign_secret]);
    assert_zero_plaintext_in_dir(&hub_dir.path().join("transfers"), benign_secret);

    // ------------------------------------------------------------------------
    // (b) Malicious `tar.gz` containing `evil.sh` and `.git/hooks/pre-commit` over real HTTP
    //     `send_files` -> recipient `decrypt_and_unpack_transfer` attachment guard rejects
    //     fail-closed with ZERO files written to unpack dir and ZERO mailbox entry delivered!
    // ------------------------------------------------------------------------
    let malicious_cases: Vec<(&str, Vec<TarInputEntry>)> = vec![
        (
            "evil-shell-script",
            vec![
                stage_tar_entry(
                    src_stage.path(),
                    "readme.txt",
                    "readme.txt",
                    b"innocent decoy",
                ),
                stage_tar_entry(
                    src_stage.path(),
                    "evil_src",
                    "evil.sh",
                    b"#!/bin/sh\nwhoami\n",
                ),
            ],
        ),
        (
            "git-hook-dropper",
            vec![
                stage_tar_entry(src_stage.path(), "notes.md", "notes.md", b"decoy"),
                stage_tar_entry(
                    src_stage.path(),
                    "hook_src",
                    ".git/hooks/pre-commit",
                    b"#!/bin/sh\necho pwned\n",
                ),
            ],
        ),
    ];
    for (label, malicious_entries) in malicious_cases {
        let send_res = alice
            .send_files(
                "bob@laptop",
                Some("codex"),
                &malicious_entries,
                Some("acme-xfer"),
            )
            .await
            .expect("hub is E2EE-blind so upload succeeds; recipient MUST reject");

        let rejected = wait_for_transfer_state(
            &hub,
            &send_res.id,
            TransferState::Rejected,
            Duration::from_secs(5),
        )
        .await;
        let reason = rejected.reason.as_deref().unwrap_or("");
        assert!(
            reason.to_ascii_lowercase().contains("blocked"),
            "case={label}: expected attachment guard rejection reason, got {reason:?}"
        );

        let unpack_dir = bob_dir.path().join("received_transfers").join(&send_res.id);
        assert!(
            !unpack_dir.exists(),
            "case={label}: unpack dir {} MUST NOT exist after attachment guard rejection!",
            unpack_dir.display()
        );
        let pending_bob = bob.peek_local_inbox("sess-bob", 100).unwrap();
        assert!(
            !pending_bob.iter().any(|m| m.text.contains(&send_res.id)),
            "case={label}: rejected transfer MUST NOT appear in Bob's mailbox!"
        );
    }

    // ------------------------------------------------------------------------
    // (c) & (d) Take `eve@offline` offline so transfers remain queued on hub:
    //   - (d) Unauthorized 3rd peer (`carol`) calling `GET /v1/transfers/<id>` -> 401 unauthorized!
    //   - (c1) 1-bit flipped ciphertext blob on hub disk -> fails closed on `sha256` verification
    //          with ZERO extraction & ZERO mailbox entry!
    //   - (c2) 1-bit flipped ciphertext blob uploaded with matching transport `X-Hyphae-Sha256`
    //          (simulating a malicious/tampering hub) -> fails closed on AEAD/signed-header
    //          verification with ZERO extraction & ZERO mailbox entry!
    // ------------------------------------------------------------------------
    eve.shutdown();
    drop(eve);

    let corrupt_disk_entry = stage_tar_entry(
        src_stage.path(),
        "corrupt_disk.txt",
        "secret.txt",
        b"DO_NOT_UNPACK_CORRUPT_DISK",
    );
    let xfer_corrupt_disk = alice
        .send_files(
            "eve@offline",
            Some("codex"),
            &[corrupt_disk_entry],
            Some("acme-xfer"),
        )
        .await
        .expect("upload to offline eve succeeds");

    // (d) Carol (valid authenticated peer, NOT the recipient!) tries `GET /v1/transfers/<id>` -> 401!
    let http_client = HttpClient::new().unwrap();
    let carol_auth = Ed25519AuthBuilder::new("carol@workstation", &carol.identity().signing);
    let steal_path = format!("/v1/transfers/{}", xfer_corrupt_disk.id);
    let steal_req = carol_auth.sign_request(Method::GET, &hub_url, &steal_path, None, None);
    let steal_resp = http_client.request(steal_req).await.unwrap();
    let (steal_status, steal_headers, steal_body) =
        HttpClient::collect(steal_resp, 64 * 1024).await.unwrap();
    assert_eq!(steal_status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        steal_headers
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok()),
        Some(CONTENT_TYPE_PROBLEM_JSON)
    );
    let steal_prob: ProblemDetails = serde_json::from_slice(&steal_body).unwrap();
    assert_eq!(steal_prob.status, 401);
    assert_eq!(steal_prob.error, "unauthorized");

    // (c1) Flip 1 bit in the hub's on-disk ciphertext blob for `xfer_corrupt_disk`.
    let hub_blob_path = hub_dir.path().join("transfers").join(&xfer_corrupt_disk.id);
    let mut disk_blob = fs::read(&hub_blob_path).expect("read hub transfer blob");
    assert!(!disk_blob.is_empty());
    let mid = disk_blob.len() / 2;
    disk_blob[mid] ^= 0x01;
    fs::write(&hub_blob_path, &disk_blob).expect("write 1-bit flipped hub blob");

    // (c2) Build a validly signed E2EE transfer for `eve@offline`, flip 1 bit in the ciphertext,
    //      and upload with the corrupted blob's matching transport `X-Hyphae-Sha256` so the
    //      hub accepts it and `eve` must catch it via AEAD/signed-header verification!
    let aead_xfer_id = "xfer-aead-bitflip-001";
    let (eve_enc_pk, aead_header_json, mut aead_ct) = {
        let eve_tmp = open_local("eve@offline", eve_dir.path());
        let enc_pk = eve_tmp.identity().encryption.public_key();
        eve_tmp.shutdown();

        let stage = TempDir::new().unwrap();
        let tar_path = stage.path().join("aead.tar.gz");
        let enc_path = stage.path().join("aead.enc");
        let aead_entry = stage_tar_entry(
            stage.path(),
            "aead_src.txt",
            "aead.txt",
            b"DO_NOT_UNPACK_AEAD_FLIP",
        );
        {
            let f = File::create(&tar_path).unwrap();
            pack_tar_gz(&[aead_entry], f, TarPackOptions::default()).unwrap();
        }
        let now = now_ms();
        let created_at = format_rfc3339_millis(now);
        let expires_at = format_rfc3339_millis(now + 600_000);
        let signed_hdr = encrypt_stream_v2(
            BufReader::new(File::open(&tar_path).unwrap()),
            File::create(&enc_path).unwrap(),
            &StreamEncryptParams {
                id: aead_xfer_id,
                from: "alice@macbook",
                media_type: "application/vnd.hyphae.tar+gzip",
                created_at: &created_at,
                expires_at: &expires_at,
            },
            &alice.identity().signing,
            &[("eve@offline", &enc_pk)],
        )
        .unwrap();
        let ct = fs::read(&enc_path).unwrap();
        let hdr_json = serde_json::to_string(&signed_hdr).unwrap();
        (enc_pk, hdr_json, ct)
    };
    let _ = eve_enc_pk;
    let last_idx = aead_ct.len() - 1;
    aead_ct[last_idx] ^= 0x01; // 1-bit flip in final AEAD ciphertext/tag byte
    let tampered_sha = sha256_hex(&aead_ct);

    let alice_auth = Ed25519AuthBuilder::new("alice@macbook", &alice.identity().signing);
    let put_path = format!("/v1/transfers/{aead_xfer_id}");
    let mut put_req = alice_auth.sign_request(
        Method::PUT,
        &hub_url,
        &put_path,
        Some(Bytes::from(aead_ct)),
        Some("application/octet-stream"),
    );
    put_req
        .headers_mut()
        .insert("x-hyphae-transfer-to", "eve@offline".parse().unwrap());
    put_req.headers_mut().insert(
        "x-hyphae-transfer-type",
        "transfer.stream.v2".parse().unwrap(),
    );
    put_req.headers_mut().insert(
        "x-hyphae-transfer-header",
        URL_SAFE_NO_PAD
            .encode(aead_header_json.as_bytes())
            .parse()
            .unwrap(),
    );
    put_req
        .headers_mut()
        .insert("x-hyphae-sha256", tampered_sha.parse().unwrap());
    let put_resp = http_client.request(put_req).await.unwrap();
    assert_eq!(put_resp.status(), StatusCode::OK);

    // Bring `eve@offline` back online and reconnect SSE to `acme-xfer`!
    let eve_reopened = open_local("eve@offline", eve_dir.path());
    eve_reopened
        .connect_peer("acme-xfer", &hub_url)
        .await
        .expect("reconnect eve to hub");

    let rec_c1 = wait_for_transfer_state(
        &hub,
        &xfer_corrupt_disk.id,
        TransferState::Rejected,
        Duration::from_secs(5),
    )
    .await;
    assert!(
        rec_c1
            .reason
            .as_deref()
            .unwrap_or("")
            .to_ascii_lowercase()
            .contains("sha256"),
        "expected sha256 mismatch rejection, got {:?}",
        rec_c1.reason
    );

    let rec_c2 = wait_for_transfer_state(
        &hub,
        aead_xfer_id,
        TransferState::Rejected,
        Duration::from_secs(5),
    )
    .await;
    assert!(
        rec_c2.reason.is_some(),
        "expected AEAD/digest failure rejection reason on tampered transfer"
    );

    for bad_id in [&xfer_corrupt_disk.id as &str, aead_xfer_id] {
        let dest = eve_dir.path().join("received_transfers").join(bad_id);
        assert!(
            !dest.exists(),
            "corrupted transfer '{bad_id}' MUST NOT leave any unpacked directory at {}",
            dest.display()
        );
    }
    let eve_inbox = eve_reopened.peek_local_inbox("sess-eve", 100).unwrap();
    assert!(
        eve_inbox.is_empty(),
        "corrupted transfers MUST NOT deliver any mailbox item; got {eve_inbox:?}"
    );

    // ------------------------------------------------------------------------
    // (e) Transfer exceeding `files:send=1kb` scope cap -> 403 `not_granted`!
    //     (Use deterministic incompressible bytes so gzip+AEAD ciphertext exceeds 1024 bytes.)
    // ------------------------------------------------------------------------
    let mut rng = DeterministicRng::from_env();
    let mut big_incompressible = vec![0u8; 4096];
    rng.fill_bytes(&mut big_incompressible);
    let big_entry = stage_tar_entry(src_stage.path(), "big.bin", "big.bin", &big_incompressible);

    let cap_err = dave
        .send_files("bob@laptop", Some("codex"), &[big_entry], Some("acme-xfer"))
        .await
        .expect_err(&format!(
            "transfer exceeding files:send=1kb MUST fail closed (HYPHAE_TEST_SEED={})",
            rng.seed()
        ));
    match cap_err {
        NodeError::RemoteProblem(prob) => {
            assert_eq!(prob.status, 403, "expected 403, got {prob:?}");
            assert_eq!(
                prob.error, "not_granted",
                "expected not_granted, got {prob:?}"
            );
        }
        other => panic!("expected RemoteProblem(403 not_granted), got {other:?}"),
    }

    // Conversely, a tiny transfer under the 1 KiB ciphertext cap from `dave` succeeds!
    let tiny_entry = stage_tar_entry(src_stage.path(), "tiny.txt", "tiny.txt", b"ok");
    let small_res = dave
        .send_files(
            "bob@laptop",
            Some("codex"),
            &[tiny_entry],
            Some("acme-xfer"),
        )
        .await
        .expect("tiny transfer within files:send=1kb cap must succeed");
    let small_entry = wait_for_mailbox_item(&bob, "sess-bob", Duration::from_secs(5), |m| {
        m.kind == MailboxKind::Transfer && m.text.contains(&small_res.id)
    })
    .await;
    assert!(small_entry.text.contains("tiny.txt"));

    alice.shutdown();
    bob.shutdown();
    carol.shutdown();
    dave.shutdown();
    eve_reopened.shutdown();
    hub.shutdown();
}
