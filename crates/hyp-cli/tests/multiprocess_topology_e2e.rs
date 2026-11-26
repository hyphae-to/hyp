//! True multi-process compiled-binary E2E topology suite for `hyp-cli`.
//!
//! Every node in these topologies runs as an independent OS process spawned from
//! the compiled `hyp` binary (`CARGO_BIN_EXE_hyp`) — zero in-process node shortcuts!
//!
//! Tests:
//! 1. `three_process_hub_alice_bob_e2ee_dm_and_channel_with_zero_hub_plaintext`
//! 2. `two_process_public_node_onboarding_to_live_hyp_wait_github_stream`
//! 3. `live_tampered_gate_policy_daemon_lockdown_and_human_approve_wakeup`
//! 4. `legacy_v1_connector_json_and_v1_keystore_upgrade_preserves_identity`
//! 5. `hyp_secret_and_hyp_kv_forgotten_inputs_and_adversarial_matrix`

mod common;

use common::{
    ManagedProcess, McpSubprocess, isolated_cmd, parse_json_stdout, wait_for_session_live,
};
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
#[cfg(unix)]
use hyp_crypto::e2ee::{DmContext, seal_dm};
use hyp_crypto::keys::{Ed25519KeyPair, NodeIdentityKeys, X25519KeyPair};
use hyp_crypto::keystore::{SecretBackend, SecretStore, legacy_connector_key_secret_names};
#[cfg(unix)]
use hyp_crypto::rfc3339::now_unix_ms;
use hyp_proto::scopes::ScopePreset;
use hyp_store::{
    KeyStatus, KeyUse, NodeDb, PeerInput, PeerKeyInput, PeerProfile, PeerStatus, TrustTier, now_ms,
};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};
#[cfg(unix)]
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{Value, json};
#[cfg(unix)]
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

const RPC_TIMEOUT: Duration = Duration::from_secs(12);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(12);

fn bytes_contain(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(unix)]
fn ed25519_auth_header(
    node_id: &str,
    keys: &NodeIdentityKeys,
    method: &str,
    path_and_query: &str,
    body: &[u8],
) -> String {
    let ts = now_unix_ms();
    let mut nonce_bytes = [0u8; 12];
    SystemRandom::new().fill(&mut nonce_bytes).unwrap();
    let nonce = hex::encode(nonce_bytes);
    let body_sha = hex::encode(Sha256::digest(body));
    let signing_input = format!("{method}\n{path_and_query}\n{ts}\n{nonce}\n{body_sha}");
    let sig = keys
        .signing
        .sign_domain_b64("http-auth", signing_input.as_bytes());
    format!("Hyphae-Ed25519 node=\"{node_id}\",ts=\"{ts}\",nonce=\"{nonce}\",sig=\"{sig}\"")
}

/// Registers an enrolled peer's public Ed25519 + X25519 keys and scopes in a hub/peer's
/// SQLite `PeerStore` (WAL-mode visible immediately to a running `hyp` process).
fn register_peer_in_sqlite(
    db_path: &Path,
    peer_id: &str,
    keys: &NodeIdentityKeys,
    profile: PeerProfile,
    trust_tier: TrustTier,
    scopes: Vec<String>,
) {
    let db = NodeDb::open(db_path).expect("open target node.sqlite");
    let now = now_ms();
    db.peers()
        .upsert_peer(
            &PeerInput {
                peer_id: peer_id.to_string(),
                endpoint: None,
                profile,
                trust_tier,
                status: PeerStatus::Active,
                scopes,
                auth_credential_ref: None,
            },
            now,
        )
        .expect("upsert peer");
    db.peers()
        .upsert_peer_key(
            &PeerKeyInput {
                peer_id: peer_id.to_string(),
                kid: keys.signing.kid(),
                key_use: KeyUse::Signing,
                jwk_json: serde_json::to_string(&keys.signing_jwk()).unwrap(),
                status: KeyStatus::Active,
                expires_at: None,
            },
            now,
        )
        .expect("upsert peer signing key");
    db.peers()
        .upsert_peer_key(
            &PeerKeyInput {
                peer_id: peer_id.to_string(),
                kid: keys.encryption.kid(),
                key_use: KeyUse::Encryption,
                jwk_json: serde_json::to_string(&keys.encryption_jwk()).unwrap(),
                status: KeyStatus::Active,
                expires_at: None,
            },
            now,
        )
        .expect("upsert peer encryption key");
}

// ============================================================================
// Mock GitHub REST API Server running on a dedicated background thread
// ============================================================================

struct MockGitHubState {
    events_200: AtomicU64,
    events_304: AtomicU64,
}

struct MockGitHubHandle {
    addr: SocketAddr,
    state: Arc<MockGitHubState>,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
    join: Option<thread::JoinHandle<()>>,
}

impl MockGitHubHandle {
    fn start() -> Self {
        let state = Arc::new(MockGitHubState {
            events_200: AtomicU64::new(0),
            events_304: AtomicU64::new(0),
        });
        let bg_state = Arc::clone(&state);
        let (addr_tx, addr_rx) = mpsc::channel::<SocketAddr>();
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        let join = thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build mock github tokio runtime");
            rt.block_on(async move {
                let listener = TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("bind mock github listener");
                let addr = listener.local_addr().unwrap();
                let _ = addr_tx.send(addr);

                loop {
                    tokio::select! {
                        _ = &mut shutdown_rx => break,
                        accept = listener.accept() => {
                            let Ok((stream, _)) = accept else { break };
                            let st = Arc::clone(&bg_state);
                            tokio::spawn(async move {
                                let io = TokioIo::new(stream);
                                let svc = service_fn(move |req| {
                                    let st_req = Arc::clone(&st);
                                    async move { handle_mock_github(st_req, req).await }
                                });
                                let _ = http1::Builder::new().serve_connection(io, svc).await;
                            });
                        }
                    }
                }
            });
        });

        let addr = addr_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("mock github server failed to bind");
        Self {
            addr,
            state,
            shutdown_tx: Some(shutdown_tx),
            join: Some(join),
        }
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

impl Drop for MockGitHubHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

async fn handle_mock_github(
    state: Arc<MockGitHubState>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path().to_string();
    let if_none_match = req
        .headers()
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .map(ToOwned::to_owned);

    if let Some(rest) = path.strip_prefix("/repos/") {
        if let Some(repo_raw) = rest.strip_suffix("/events") {
            let repo = repo_raw.to_ascii_lowercase();
            if repo == "acme/open" {
                if if_none_match.as_deref() == Some("\"gh-mp-e1\"") {
                    state.events_304.fetch_add(1, Ordering::SeqCst);
                    return Ok(Response::builder()
                        .status(StatusCode::NOT_MODIFIED)
                        .header(header::ETAG, "\"gh-mp-e1\"")
                        .header("x-poll-interval", "1")
                        .header("x-ratelimit-remaining", "59")
                        .body(Full::new(Bytes::new()))
                        .unwrap());
                }

                state.events_200.fetch_add(1, Ordering::SeqCst);
                let events = json!([
                    {
                        "id": "gh-mp-pr-9001",
                        "type": "PullRequestEvent",
                        "actor": { "login": "octocat", "type": "User" },
                        "repo": { "name": "acme/open" },
                        "payload": {
                            "action": "opened",
                            "number": 9001,
                            "pull_request": {
                                "number": 9001,
                                "title": "Multi-process live public.hyphae.to stream wakeup",
                                "html_url": "https://github.com/acme/open/pull/9001",
                                "state": "open",
                                "draft": false,
                                "user": { "login": "octocat", "type": "User" },
                                "head": { "ref": "feat/mp-stream" },
                                "base": { "ref": "main" },
                                "labels": [{ "name": "ci" }]
                            }
                        },
                        "created_at": "2026-11-24T17:10:00Z"
                    }
                ]);
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ETAG, "\"gh-mp-e1\"")
                    .header("x-poll-interval", "1")
                    .header("x-ratelimit-remaining", "59")
                    .body(Full::new(Bytes::from(events.to_string())))
                    .unwrap());
            }
            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(r#"{"message":"Not Found"}"#)))
                .unwrap());
        }

        let repo = rest.to_ascii_lowercase();
        if repo == "acme/open" {
            let body = json!({
                "full_name": "acme/open",
                "private": false,
                "visibility": "public"
            });
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(body.to_string())))
                .unwrap());
        }
    }

    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::new()))
        .unwrap())
}

// ============================================================================
// 1. Three-Process Topology: Hub (`acme-team`) + Alice + Bob (Auto-Connect,
//    E2EE DM, E2EE `#eng` Channel, ZERO Plaintext Bytes on Hub!)
// ============================================================================

#[test]
fn three_process_hub_alice_bob_e2ee_dm_and_channel_with_zero_hub_plaintext() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let hub_home = tmp.path().join("hub-home");
    let hub_state = tmp.path().join("hub-state");
    let alice_home = tmp.path().join("alice-home");
    let alice_state = tmp.path().join("alice-state");
    let bob_home = tmp.path().join("bob-home");
    let bob_state = tmp.path().join("bob-state");
    for d in [
        &hub_home,
        &hub_state,
        &alice_home,
        &alice_state,
        &bob_home,
        &bob_state,
    ] {
        fs::create_dir_all(d).unwrap();
    }

    // Process 1: Compiled `hyp node start --profile router` (`acme-team`)
    let mut hub_cmd = isolated_cmd(&hub_home);
    hub_cmd
        .args([
            "node",
            "start",
            "--profile",
            "router",
            "--node-id",
            "acme-team",
            "--bind",
            "127.0.0.1:0",
            "--no-local-socket",
            "--state-dir",
            hub_state.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null());
    let mut hub_proc = ManagedProcess::spawn("acme-team hub", &mut hub_cmd);
    let hub_startup = hub_proc.read_json_line(STARTUP_TIMEOUT);
    assert_eq!(hub_startup["ok"], true, "hub startup: {hub_startup}");
    let hub_endpoint = hub_startup["data"]["endpoint"]
        .as_str()
        .expect("hub endpoint")
        .to_string();

    // Issue real `am2_` Org Admin-CA invites via `hyp pair invite --mode team`
    // and accept them via stdin on Alice & Bob (`hyp pair accept`) so both persist
    // active peer rows pointing to `acme-team` + pinned Admin-CA keys & grants!
    for (peer_node_id, home, state) in [
        ("alice@macbook", &alice_home, &alice_state),
        ("bob@laptop", &bob_home, &bob_state),
    ] {
        let inv_out = isolated_cmd(&hub_home)
            .args([
                "pair",
                "invite",
                "--mode",
                "team",
                "--node-id",
                "acme-team",
                "--endpoint",
                &hub_endpoint,
                "--peer",
                peer_node_id,
                "--preset",
                "member",
                "--state-dir",
                hub_state.to_str().unwrap(),
                "--json",
            ])
            .output()
            .expect("run hyp pair invite --mode team");
        assert_eq!(inv_out.status.code(), Some(0));
        let inv_json = parse_json_stdout(&inv_out);
        let am2_token = inv_json["data"]["token"].as_str().expect("am2 token");
        assert!(am2_token.starts_with("am2_"));

        let mut acc_child = isolated_cmd(home)
            .args([
                "pair",
                "accept",
                "--offline",
                "--node-id",
                peer_node_id,
                "--state-dir",
                state.to_str().unwrap(),
                "--json",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn hyp pair accept");
        acc_child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("{am2_token}\n").as_bytes())
            .unwrap();
        let acc_out = acc_child.wait_with_output().unwrap();
        assert_eq!(
            acc_out.status.code(),
            Some(0),
            "pair accept failed for {peer_node_id}: stdout={} stderr={}",
            String::from_utf8_lossy(&acc_out.stdout),
            String::from_utf8_lossy(&acc_out.stderr)
        );
        let acc_json = parse_json_stdout(&acc_out);
        assert_eq!(acc_json["ok"], true);
        assert_eq!(acc_json["data"]["peerId"], "acme-team");

        // Register the peer's public Ed25519 + X25519 identity on `acme-team`'s WAL SQLite
        // directory so `acme-team` authenticates Ed25519 requests & serves `/v1/keys`.
        let peer_keys = SecretStore::new(state, SecretBackend::File)
            .load_or_create_node_keys(peer_node_id)
            .expect("load paired peer keys");
        register_peer_in_sqlite(
            &hub_state.join("node.sqlite"),
            peer_node_id,
            &peer_keys,
            PeerProfile::Local,
            TrustTier::Org,
            ScopePreset::Member.expand(),
        );
    }

    // Process 2: Compiled `hyp daemon` for Alice (`alice@macbook`) — MUST auto-connect `acme-team`!
    let mut alice_cmd = isolated_cmd(&alice_home);
    alice_cmd
        .args([
            "daemon",
            "--profile",
            "local",
            "--node-id",
            "alice@macbook",
            "--state-dir",
            alice_state.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null());
    let mut alice_proc = ManagedProcess::spawn("alice@macbook daemon", &mut alice_cmd);
    let alice_startup = alice_proc.read_json_line(STARTUP_TIMEOUT);
    assert_eq!(alice_startup["ok"], true, "alice startup: {alice_startup}");
    assert_eq!(
        alice_startup["data"]["connectedPeers"],
        json!(["acme-team"]),
        "Alice must auto-connect persisted active peer acme-team on boot: {alice_startup}"
    );
    let alice_sock = PathBuf::from(alice_startup["data"]["socketPath"].as_str().unwrap());

    // Process 3: Compiled `hyp daemon` for Bob (`bob@laptop`) — MUST auto-connect `acme-team`!
    let mut bob_cmd = isolated_cmd(&bob_home);
    bob_cmd
        .args([
            "daemon",
            "--profile",
            "local",
            "--node-id",
            "bob@laptop",
            "--state-dir",
            bob_state.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null());
    let mut bob_proc = ManagedProcess::spawn("bob@laptop daemon", &mut bob_cmd);
    let bob_startup = bob_proc.read_json_line(STARTUP_TIMEOUT);
    assert_eq!(bob_startup["ok"], true, "bob startup: {bob_startup}");
    assert_eq!(
        bob_startup["data"]["connectedPeers"],
        json!(["acme-team"]),
        "Bob must auto-connect persisted active peer acme-team on boot: {bob_startup}"
    );
    let bob_sock = PathBuf::from(bob_startup["data"]["socketPath"].as_str().unwrap());

    // Verify `node.status.json` also records `connectedPeers`
    let alice_status_file: Value =
        serde_json::from_str(&fs::read_to_string(alice_state.join("node.status.json")).unwrap())
            .unwrap();
    assert_eq!(alice_status_file["connectedPeers"], json!(["acme-team"]));

    // Spawn real `hyp mcp` subprocesses against BOTH Alice and Bob daemons!
    let mut alice_mcp = McpSubprocess::spawn(&alice_home, &alice_sock);
    let mut bob_mcp = McpSubprocess::spawn(&bob_home, &bob_sock);
    alice_mcp.initialize(RPC_TIMEOUT);
    bob_mcp.initialize(RPC_TIMEOUT);

    // Enroll Alice (`alice@macbook/alice`) and Bob (`bob@laptop/bob`) via real `hyp hook claude pre-tool-use`
    let (a_join, a_err) = alice_mcp.call_verified_claude(
        &alice_home,
        &alice_sock,
        "alice-s1",
        "hyp_mesh",
        json!({ "action": "join", "handle": "alice" }),
        RPC_TIMEOUT,
    );
    assert!(!a_err, "alice join failed: {a_join}");
    assert!(
        a_join.contains("alice@macbook/alice"),
        "alice join: {a_join}"
    );

    let (b_join, b_err) = bob_mcp.call_verified_claude(
        &bob_home,
        &bob_sock,
        "bob-s1",
        "hyp_mesh",
        json!({ "action": "join", "handle": "bob" }),
        RPC_TIMEOUT,
    );
    assert!(!b_err, "bob join failed: {b_join}");
    assert!(b_join.contains("bob@laptop/bob"), "bob join: {b_join}");

    // --- Part A: Cross-Process E2EE DM (Alice -> acme-team -> Bob's live `hyp wait`) ---
    let dm_secret = "E2EE_DM_SENTINEL_THREE_PROCESS_918273645";
    let mut bob_wait_dm_cmd = isolated_cmd(&bob_home);
    bob_wait_dm_cmd
        .args([
            "wait",
            "--session",
            "claude:bob-s1",
            "--socket",
            bob_sock.to_str().unwrap(),
            "--timeout",
            "15",
            "--json",
        ])
        .stdin(Stdio::null());
    let mut bob_wait_dm = ManagedProcess::spawn("bob hyp wait (DM)", &mut bob_wait_dm_cmd);
    wait_for_session_live(&bob_sock, "claude:bob-s1", Duration::from_secs(5));

    let (dm_res, dm_err) = alice_mcp.call_verified_claude(
        &alice_home,
        &alice_sock,
        "alice-s1",
        "hyp_send",
        json!({ "to": "bob@laptop/bob", "text": dm_secret }),
        RPC_TIMEOUT,
    );
    assert!(!dm_err, "alice E2EE DM failed: {dm_res}");
    let dm_res_val: Value = serde_json::from_str(&dm_res).expect("dm response JSON");
    assert_eq!(
        dm_res_val["encrypted"], true,
        "DM must be E2EE: {dm_res_val}"
    );
    assert_eq!(dm_res_val["routedVia"], "acme-team");

    let (dm_wait_status, dm_wait_json) = bob_wait_dm.wait_json_output(Duration::from_secs(15));
    assert_eq!(dm_wait_status.code(), Some(0));
    assert_eq!(dm_wait_json["ok"], true);
    let dm_items = dm_wait_json["data"]["items"].as_array().unwrap();
    let dm_wait_txt = dm_items[0]["text"].as_str().unwrap_or_default();
    assert!(
        dm_wait_txt.contains("<hyphae-inbox ")
            && dm_wait_txt.contains("<dm from=\"alice@macbook/alice\" count=\"1\"/>"),
        "Bob's live hyp wait must receive metadata-only XML digest: {dm_wait_json}"
    );
    assert!(
        !dm_wait_txt.contains(dm_secret),
        "RFC 0004: live hyp wait must NEVER expose raw E2EE DM plaintext: {dm_wait_json}"
    );
    let (bob_dm_inbox, bob_dm_err) = bob_mcp.call_verified_claude(
        &bob_home,
        &bob_sock,
        "bob-s1",
        "hyp_inbox",
        json!({}),
        RPC_TIMEOUT,
    );
    assert!(!bob_dm_err, "bob hyp_inbox failed: {bob_dm_inbox}");
    assert!(
        bob_dm_inbox.contains(dm_secret),
        "Bob's hyp_inbox must return decrypted DM plaintext: {bob_dm_inbox}"
    );

    // --- Part B: Cross-Process E2EE `#eng` Channel (Alice -> acme-team -> Bob's live `hyp wait`) ---
    let (a_ch, a_ch_err) = alice_mcp.call_verified_claude(
        &alice_home,
        &alice_sock,
        "alice-s1",
        "hyp_mesh",
        json!({ "action": "join", "channel": "acme-team/#eng" }),
        RPC_TIMEOUT,
    );
    assert!(!a_ch_err, "alice join #eng failed: {a_ch}");

    let (b_ch, b_ch_err) = bob_mcp.call_verified_claude(
        &bob_home,
        &bob_sock,
        "bob-s1",
        "hyp_mesh",
        json!({ "action": "join", "channel": "acme-team/#eng" }),
        RPC_TIMEOUT,
    );
    assert!(!b_ch_err, "bob join #eng failed: {b_ch}");

    let chan_secret = "E2EE_CHANNEL_ENG_SENTINEL_5566778899";
    let mut bob_wait_ch_cmd = isolated_cmd(&bob_home);
    bob_wait_ch_cmd
        .args([
            "wait",
            "--session",
            "claude:bob-s1",
            "--socket",
            bob_sock.to_str().unwrap(),
            "--timeout",
            "15",
            "--json",
        ])
        .stdin(Stdio::null());
    let mut bob_wait_ch = ManagedProcess::spawn("bob hyp wait (#eng)", &mut bob_wait_ch_cmd);
    wait_for_session_live(&bob_sock, "claude:bob-s1", Duration::from_secs(5));

    let (ch_post, ch_post_err) = alice_mcp.call_verified_claude(
        &alice_home,
        &alice_sock,
        "alice-s1",
        "hyp_send",
        json!({ "to": "acme-team/#eng", "text": chan_secret }),
        RPC_TIMEOUT,
    );
    assert!(!ch_post_err, "alice post #eng failed: {ch_post}");

    let (ch_wait_status, ch_wait_json) = bob_wait_ch.wait_json_output(Duration::from_secs(15));
    assert_eq!(ch_wait_status.code(), Some(0));
    assert_eq!(ch_wait_json["ok"], true);
    let ch_items = ch_wait_json["data"]["items"].as_array().unwrap();
    let ch_wait_txt = ch_items[0]["text"].as_str().unwrap_or_default();
    assert!(
        ch_wait_txt.contains("<hyphae-inbox ")
            && ch_wait_txt.contains("<channel name=\"#eng\" count=\"1\"/>"),
        "Bob's live hyp wait must receive metadata-only #eng XML digest: {ch_wait_json}"
    );
    assert!(
        !ch_wait_txt.contains(chan_secret),
        "RFC 0004: live hyp wait must NEVER expose raw #eng plaintext: {ch_wait_json}"
    );
    let (bob_ch_inbox, bob_ch_err) = bob_mcp.call_verified_claude(
        &bob_home,
        &bob_sock,
        "bob-s1",
        "hyp_inbox",
        json!({}),
        RPC_TIMEOUT,
    );
    assert!(!bob_ch_err, "bob #eng hyp_inbox failed: {bob_ch_inbox}");
    assert!(
        bob_ch_inbox.contains(chan_secret),
        "Bob's hyp_inbox must return decrypted #eng channel message: {bob_ch_inbox}"
    );

    // --- Part C: Cryptographic Zero-Knowledge Hub Verification ---
    // Scan `acme-team`'s `node.sqlite`, `node.sqlite-wal`, and `node.sqlite-shm` both live
    // AND after clean shutdown proving ZERO plaintext DM or `#eng` bytes ever touched the Hub!
    let scan_hub_files = |phase: &str| {
        for fname in ["node.sqlite", "node.sqlite-wal", "node.sqlite-shm"] {
            let p = hub_state.join(fname);
            if p.exists() {
                let raw = fs::read(&p).expect("read hub sqlite artifact");
                assert!(
                    !bytes_contain(&raw, dm_secret.as_bytes()),
                    "PLAINTEXT LEAK ({phase}): DM secret found in Hub {fname}!"
                );
                assert!(
                    !bytes_contain(&raw, chan_secret.as_bytes()),
                    "PLAINTEXT LEAK ({phase}): #eng secret found in Hub {fname}!"
                );
            }
        }
    };
    scan_hub_files("live");

    assert_eq!(alice_mcp.close(Duration::from_secs(5)), Some(0));
    assert_eq!(bob_mcp.close(Duration::from_secs(5)), Some(0));
    let _ = alice_proc.shutdown_gracefully();
    let _ = bob_proc.shutdown_gracefully();
    let _ = hub_proc.shutdown_gracefully();

    scan_hub_files("post-shutdown");
}

// ============================================================================
// 2. Two-Process Public Node Onboarding -> Live `hyp wait` GitHub Stream
// ============================================================================

#[test]
fn two_process_public_node_onboarding_to_live_hyp_wait_github_stream() {
    let mock_gh = MockGitHubHandle::start();
    let tmp = tempfile::tempdir().expect("tempdir");
    let hub_home = tmp.path().join("hub-home");
    let kit_dir = tmp.path().join("kit");
    let hub_state = tmp.path().join("hub-state");
    let laptop_home = tmp.path().join("laptop-home");
    let laptop_state = tmp.path().join("laptop-state");
    for d in [&hub_home, &hub_state, &laptop_home, &laptop_state] {
        fs::create_dir_all(d).unwrap();
    }

    // 1. Run `hyp deploy init public-node`
    let init_out = isolated_cmd(&hub_home)
        .args([
            "deploy",
            "init",
            "public-node",
            "--node-id",
            "public.hyphae.to",
            "--domain",
            "public.hyphae.to",
            "--out",
            kit_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run hyp deploy init public-node");
    assert_eq!(init_out.status.code(), Some(0));
    assert_eq!(parse_json_stdout(&init_out)["ok"], true);

    // Patch generated `node.json` for local mock GitHub REST API + 1s ETag polling
    let node_json_path = kit_dir.join("node.json");
    let mut cfg: Value =
        serde_json::from_str(&fs::read_to_string(&node_json_path).unwrap()).unwrap();
    cfg["stateDir"] = json!(hub_state.to_str().unwrap());
    cfg["sources"][0]["apiBaseUrl"] = json!(mock_gh.base_url());
    cfg["sources"][0]["minPollIntervalSeconds"] = json!(1);
    cfg["sources"][0]["graceWindowSeconds"] = json!(1);
    fs::write(&node_json_path, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();

    // 2. Process 1: Compiled `hyp node start` (`public.hyphae.to`)
    let mut hub_cmd = isolated_cmd(&hub_home);
    hub_cmd
        .args([
            "node",
            "start",
            "--config",
            node_json_path.to_str().unwrap(),
            "--bind",
            "127.0.0.1:0",
            "--no-local-socket",
            "--json",
        ])
        .stdin(Stdio::null());
    let mut hub_proc = ManagedProcess::spawn("public.hyphae.to node", &mut hub_cmd);
    let hub_startup = hub_proc.read_json_line(STARTUP_TIMEOUT);
    assert_eq!(
        hub_startup["ok"], true,
        "public node startup: {hub_startup}"
    );
    assert_eq!(hub_startup["data"]["guestPairingEnabled"], true);
    assert_eq!(hub_startup["data"]["githubPublicEnabled"], true);
    let hub_url = hub_startup["data"]["endpoint"]
        .as_str()
        .expect("public node endpoint")
        .to_string();

    // 3. Self-service `hyp pair join` from `dev@laptop`
    let join_out = isolated_cmd(&laptop_home)
        .args([
            "pair",
            "join",
            &hub_url,
            "--state-dir",
            laptop_state.to_str().unwrap(),
            "--node-id",
            "dev@laptop",
            "--json",
        ])
        .output()
        .expect("run hyp pair join");
    assert_eq!(
        join_out.status.code(),
        Some(0),
        "pair join stderr={}",
        String::from_utf8_lossy(&join_out.stderr)
    );
    let join_json = parse_json_stdout(&join_out);
    assert_eq!(join_json["ok"], true);
    assert_eq!(join_json["data"]["enrolled"], true);
    assert_eq!(join_json["data"]["peerId"], "public.hyphae.to");
    assert_eq!(join_json["data"]["preset"], "guest-ro");

    // 4. Process 2: Compiled `hyp daemon` for `dev@laptop` — auto-connects `public.hyphae.to`!
    let mut laptop_cmd = isolated_cmd(&laptop_home);
    laptop_cmd
        .args([
            "daemon",
            "--profile",
            "local",
            "--node-id",
            "dev@laptop",
            "--state-dir",
            laptop_state.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null());
    let mut laptop_proc = ManagedProcess::spawn("dev@laptop daemon", &mut laptop_cmd);
    let laptop_startup = laptop_proc.read_json_line(STARTUP_TIMEOUT);
    assert_eq!(
        laptop_startup["ok"], true,
        "laptop startup: {laptop_startup}"
    );
    assert_eq!(
        laptop_startup["data"]["connectedPeers"],
        json!(["public.hyphae.to"]),
        "dev@laptop must auto-connect public.hyphae.to on boot: {laptop_startup}"
    );
    let laptop_sock = PathBuf::from(laptop_startup["data"]["socketPath"].as_str().unwrap());

    // 5. Drive `hyp mcp` (`hyp_mesh(join)` + `hyp_stream(subscribe)`) + live `hyp wait`!
    let mut mcp = McpSubprocess::spawn(&laptop_home, &laptop_sock);
    mcp.initialize(RPC_TIMEOUT);

    let (j_txt, j_err) = mcp.call_verified_claude(
        &laptop_home,
        &laptop_sock,
        "dev-s1",
        "hyp_mesh",
        json!({ "action": "join", "handle": "dev" }),
        RPC_TIMEOUT,
    );
    assert!(!j_err, "dev join failed: {j_txt}");

    let mut wait_cmd = isolated_cmd(&laptop_home);
    wait_cmd
        .args([
            "wait",
            "--session",
            "claude:dev-s1",
            "--socket",
            laptop_sock.to_str().unwrap(),
            "--timeout",
            "15",
            "--json",
        ])
        .stdin(Stdio::null());
    let mut wait_proc = ManagedProcess::spawn("dev hyp wait (github stream)", &mut wait_cmd);
    wait_for_session_live(&laptop_sock, "claude:dev-s1", Duration::from_secs(5));

    let (sub_txt, sub_err) = mcp.call_verified_claude(
        &laptop_home,
        &laptop_sock,
        "dev-s1",
        "hyp_stream",
        json!({
            "action": "subscribe",
            "topic": "public.hyphae.to.github",
            "filters": [{ "exact": { "repo": "acme/open" } }],
            "coalesceSeconds": 0
        }),
        RPC_TIMEOUT,
    );
    assert!(!sub_err, "hyp_stream subscribe failed: {sub_txt}");
    let sub_val: Value = serde_json::from_str(&sub_txt).expect("subscribe JSON");
    assert_eq!(sub_val["originNode"], "public.hyphae.to");
    assert_eq!(sub_val["topic"], "github");

    // 6. Verify live GitHub PR CloudEvent flows Mock GitHub -> public.hyphae.to -> SSE -> dev@laptop -> hyp wait!
    // Because `public.hyphae.to` is a `Guest` trust-tier peer, Stage 1 security gate automatically
    // downgrades live push to a slim `notifyOnly: true` digest waking `hyp wait`, while keeping the
    // full CloudEvent durable in `hyp_inbox`.
    let (wait_status, wait_json) = wait_proc.wait_json_output(Duration::from_secs(15));
    assert_eq!(wait_status.code(), Some(0));
    assert_eq!(wait_json["ok"], true);
    let items = wait_json["data"]["items"].as_array().unwrap();
    assert!(
        !items.is_empty(),
        "expected GitHub PR CloudEvent to wake live hyp wait: {wait_json}"
    );
    let joined_text: String = items
        .iter()
        .filter_map(|i| i["text"].as_str())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(
        joined_text.contains("<hyphae-inbox ")
            && joined_text.contains("public.hyphae.to.github")
            && joined_text.contains("urgency=\"queue\""),
        "woken wait digest missing public.hyphae.to.github queue XML digest: {wait_json}"
    );
    assert!(
        !joined_text.contains("Multi-process live public.hyphae.to stream wakeup"),
        "RFC 0004: wait digest must NEVER contain raw event text: {wait_json}"
    );
    // RFC 0004: Guest trust tier enforces Stage 1 CapToQueue (wakes threads with a metadata-only
    // `<hyphae-inbox ... urgency="queue">` digest without injecting untrusted payload text!).
    assert_eq!(
        items[0]["notifyOnly"], false,
        "Guest trust tier stream should be Stage-1 capped to queue XML digest: {wait_json}"
    );

    // Drain the full durable GitHub PR CloudEvent via `hyp_inbox`!
    let (inbox_txt, inbox_err) = mcp.call_verified_claude(
        &laptop_home,
        &laptop_sock,
        "dev-s1",
        "hyp_inbox",
        json!({ "state": "unread", "ack": true }),
        RPC_TIMEOUT,
    );
    assert!(!inbox_err, "hyp_inbox drain failed: {inbox_txt}");
    assert!(
        inbox_txt.contains("acme/open")
            && (inbox_txt.contains("9001")
                || inbox_txt.contains("Multi-process live public.hyphae.to stream wakeup")),
        "drained hyp_inbox payload missing GitHub PR CloudEvent details: {inbox_txt}"
    );

    // 7. Confirm mock GitHub served initial 200 AND subsequent conditional 304 Not Modified!
    assert!(mock_gh.state.events_200.load(Ordering::SeqCst) >= 1);
    let deadline = Instant::now() + Duration::from_secs(6);
    while Instant::now() < deadline && mock_gh.state.events_304.load(Ordering::SeqCst) == 0 {
        thread::sleep(Duration::from_millis(100));
    }
    assert!(
        mock_gh.state.events_304.load(Ordering::SeqCst) >= 1,
        "expected conditional ETag 304 Not Modified poll after initial 200"
    );

    assert_eq!(mcp.close(Duration::from_secs(5)), Some(0));
    let _ = laptop_proc.shutdown_gracefully();
    let _ = hub_proc.shutdown_gracefully();
}

// ============================================================================
// 3. Live Tampered Gate Policy Daemon Lockdown & Human Approve Wakeup
// ============================================================================

#[cfg(unix)]
#[test]
fn live_tampered_gate_policy_daemon_lockdown_and_human_approve_wakeup() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let hub_home = tmp.path().join("hub-home");
    let hub_state = tmp.path().join("hub-state");
    let home = tmp.path().join("home");
    let state_dir = tmp.path().join("state");
    for d in [&hub_home, &hub_state, &home, &state_dir] {
        fs::create_dir_all(d).unwrap();
    }

    // 0. Start an external compiled router (`ext-hub`) so untrusted inbound messages arrive
    //    over a real remote SSE `/v1/inbox` link (`origin_node = "ext-hub"`, `TrustTier::Peer`).
    let mut hub_cmd = isolated_cmd(&hub_home);
    hub_cmd
        .args([
            "node",
            "start",
            "--profile",
            "router",
            "--node-id",
            "ext-hub",
            "--bind",
            "127.0.0.1:0",
            "--no-local-socket",
            "--state-dir",
            hub_state.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null());
    let mut hub_proc = ManagedProcess::spawn("ext-hub router", &mut hub_cmd);
    let hub_startup = hub_proc.read_json_line(STARTUP_TIMEOUT);
    assert_eq!(hub_startup["ok"], true, "ext-hub startup: {hub_startup}");
    let hub_endpoint = hub_startup["data"]["endpoint"]
        .as_str()
        .expect("ext-hub endpoint")
        .to_string();

    // 1. Run `hyp onboard` + `hyp gate init --lock` on `sec@box`
    let onb_out = isolated_cmd(&home)
        .args([
            "onboard",
            "--profile",
            "local",
            "--node-id",
            "sec@box",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--home",
            home.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run hyp onboard");
    assert_eq!(onb_out.status.code(), Some(0));

    let passkey = common::TestPasskeyAdmin::generate("sec-admin", "macbook-touchid");
    passkey.enroll_via_web(&home, &state_dir, None);

    let (gate_init_code, init_json, gate_init_stderr, _) = passkey.run_and_approve_json(
        &home,
        &[
            "gate",
            "init",
            "--adapter",
            "http-classifier",
            "--base-url",
            "http://127.0.0.1:1/classify",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--lock",
            "--local",
            "--no-open",
            "--json",
        ],
        None,
    );
    assert_eq!(gate_init_code, 0, "stderr={gate_init_stderr}");
    assert_eq!(init_json["data"]["locked"], true);
    assert_eq!(init_json["data"]["gatePolicySig"], "OK");

    // Persist `ext-hub` as an active peer on `sec@box` and register `sec@box` + `ext@peer` on `ext-hub`
    let sec_keys = SecretStore::new(&state_dir, SecretBackend::File)
        .load_or_create_node_keys("sec@box")
        .expect("load sec@box keys");
    let ext_keys = NodeIdentityKeys::generate().expect("generate ext@peer keys");

    {
        let sec_db = NodeDb::open(state_dir.join("node.sqlite")).expect("open sec@box db");
        let now = now_ms();
        sec_db
            .peers()
            .upsert_peer(
                &PeerInput {
                    peer_id: "ext-hub".to_string(),
                    endpoint: Some(hub_endpoint.clone()),
                    profile: PeerProfile::Router,
                    trust_tier: TrustTier::Peer,
                    status: PeerStatus::Active,
                    scopes: ScopePreset::Member.expand(),
                    auth_credential_ref: None,
                },
                now,
            )
            .expect("persist ext-hub on sec@box");
    }
    register_peer_in_sqlite(
        &hub_state.join("node.sqlite"),
        "sec@box",
        &sec_keys,
        PeerProfile::Local,
        TrustTier::Peer,
        ScopePreset::Member.expand(),
    );
    register_peer_in_sqlite(
        &hub_state.join("node.sqlite"),
        "ext@peer",
        &ext_keys,
        PeerProfile::Local,
        TrustTier::Peer,
        ScopePreset::Member.expand(),
    );

    // 2. Tamper `node.json` on disk without re-signing `gate_policy_sig`
    let node_json_path = state_dir.join("node.json");
    let mut tampered: Value =
        serde_json::from_str(&fs::read_to_string(&node_json_path).unwrap()).unwrap();
    tampered["gate"]["filters"][0]["enabled"] = Value::Bool(false);
    tampered["gate"]["filters"][0]["adapter"]["url"] =
        Value::String("http://127.0.0.1:9999/bypass".to_string());
    fs::write(
        &node_json_path,
        serde_json::to_string_pretty(&tampered).unwrap(),
    )
    .unwrap();

    // Verify `hyp doctor --json` reports fail-closed `gate_policy_tampered`
    let doc_out = isolated_cmd(&home)
        .args([
            "doctor",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--home",
            home.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(doc_out.status.code(), Some(1));
    let doc_json = parse_json_stdout(&doc_out);
    assert_eq!(doc_json["ok"], false);
    assert_eq!(doc_json["data"]["gate"]["tampered"], true);
    assert_eq!(doc_json["data"]["gate"]["gatePolicySig"], "FAIL");

    // 3. Boot real compiled `hyp daemon` (`sec@box`) — auto-connects `ext-hub` and enters tamper lockdown!
    let mut daemon_cmd = isolated_cmd(&home);
    daemon_cmd
        .args([
            "daemon",
            "--profile",
            "local",
            "--node-id",
            "sec@box",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null());
    let mut daemon = ManagedProcess::spawn("sec@box tampered daemon", &mut daemon_cmd);
    let startup = daemon.read_json_line(STARTUP_TIMEOUT);
    assert_eq!(startup["ok"], true, "sec@box startup: {startup}");
    assert_eq!(
        startup["data"]["connectedPeers"],
        json!(["ext-hub"]),
        "sec@box must auto-connect ext-hub: {startup}"
    );
    assert!(
        startup["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap_or("").contains("gate_policy_tampered")),
        "expected gate_policy_tampered startup warning: {startup}"
    );
    let sec_sock = PathBuf::from(startup["data"]["socketPath"].as_str().unwrap());

    // Enroll agent session `claude:sec-s1` as handle `sec`
    let mut mcp = McpSubprocess::spawn(&home, &sec_sock);
    mcp.initialize(RPC_TIMEOUT);
    let (j_txt, j_err) = mcp.call_verified_claude(
        &home,
        &sec_sock,
        "sec-s1",
        "hyp_mesh",
        json!({ "action": "join", "handle": "sec" }),
        RPC_TIMEOUT,
    );
    assert!(!j_err, "sec join failed: {j_txt}");

    // Arm live `hyp wait` (0.8s timeout — MUST NOT wake for quarantined message!)
    let mut blocked_wait_cmd = isolated_cmd(&home);
    blocked_wait_cmd
        .args([
            "wait",
            "--session",
            "claude:sec-s1",
            "--socket",
            sec_sock.to_str().unwrap(),
            "--timeout",
            "0.8",
            "--json",
        ])
        .stdin(Stdio::null());
    let mut blocked_wait =
        ManagedProcess::spawn("sec hyp wait (locked down)", &mut blocked_wait_cmd);
    wait_for_session_live(&sec_sock, "claude:sec-s1", Duration::from_secs(5));

    // Send real E2EE-sealed authenticated DM from `ext@peer/outsider` via `ext-hub` -> `sec@box/sec`
    let head_marker = "UNTRUSTED_LOCKDOWN_HEAD_5501";
    let tail_secret = "SENSITIVE_RAW_BODY_TAIL_SECRET_8829";
    let padding = "x".repeat(180);
    let untrusted_body = format!("{head_marker}:{padding}:{tail_secret}");

    let dm_id = "tampered-gate-dm-1";
    let dm_ctx = DmContext {
        node_id: "ext-hub",
        msg_id: dm_id,
        sender: "ext@peer/outsider",
        recipient: "sec@box/sec",
    };
    let sealed = seal_dm(
        &dm_ctx,
        untrusted_body.as_bytes(),
        &ext_keys.signing,
        &sec_keys.encryption.public_key(),
    )
    .expect("seal DM for sec@box via ext-hub");

    let req_body = serde_json::to_vec(&json!({
        "id": dm_id,
        "fromHandle": "outsider",
        "to": "sec@box/sec",
        "text": serde_json::to_string(&sealed).unwrap(),
        "contentType": "application/vnd.hyphae.e2ee+json"
    }))
    .unwrap();
    let auth_hdr = ed25519_auth_header("ext@peer", &ext_keys, "POST", "/v1/messages", &req_body);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let post_status = rt.block_on(async {
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
        let req = Request::builder()
            .method(Method::POST)
            .uri(format!("{hub_endpoint}/v1/messages"))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, auth_hdr)
            .body(Full::new(Bytes::from(req_body)))
            .unwrap();
        let resp = client
            .request(req)
            .await
            .expect("POST /v1/messages to ext-hub");
        resp.status()
    });
    assert!(
        post_status.is_success(),
        "POST /v1/messages returned unexpected status {post_status}"
    );

    // 4. Verify live `hyp wait` timed out cleanly with ZERO output / ZERO wakeup (100% hidden!)
    let (bw_status, bw_stdout) = blocked_wait.wait_stdout_output(Duration::from_secs(5));
    assert_eq!(bw_status.code(), Some(0));
    assert!(
        bw_stdout.trim().is_empty(),
        "quarantined item MUST NEVER wake hyp wait: stdout={bw_stdout:?}"
    );
    assert!(!bw_stdout.contains(head_marker));
    assert!(!bw_stdout.contains(tail_secret));

    // Verify `hyp_inbox` returns 0 unread items and ZERO bytes of the quarantined payload!
    let (inbox_txt, inbox_err) = mcp.call_verified_claude(
        &home,
        &sec_sock,
        "sec-s1",
        "hyp_inbox",
        json!({}),
        RPC_TIMEOUT,
    );
    assert!(!inbox_err, "hyp_inbox failed: {inbox_txt}");
    let inbox_val: Value = serde_json::from_str(&inbox_txt).unwrap();
    assert_eq!(inbox_val["unread"], 0);
    assert_eq!(inbox_val["items"].as_array().unwrap().len(), 0);
    assert!(!inbox_txt.contains(head_marker));
    assert!(!inbox_txt.contains(tail_secret));

    // 5. Poll briefly for SSE delivery + quarantine to commit, then verify `hyp gate review --json`
    //    surfaces quarantine metadata (`gate_policy_tampered`) without a raw `text` field or tail leak!
    let deadline = Instant::now() + Duration::from_secs(8);
    let (rev_stdout, rev_json) = loop {
        let rev_out = isolated_cmd(&home)
            .args([
                "gate",
                "review",
                "--state-dir",
                state_dir.to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(rev_out.status.code(), Some(0));
        let raw_stdout = String::from_utf8_lossy(&rev_out.stdout).to_string();
        let parsed = parse_json_stdout(&rev_out);
        if parsed["data"]["count"].as_u64().unwrap_or(0) >= 1 {
            break (raw_stdout, parsed);
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for tampered gate policy to quarantine inbound item: {parsed}"
        );
        thread::sleep(Duration::from_millis(50));
    };

    assert_eq!(rev_json["data"]["count"], 1, "review JSON: {rev_json}");
    let q_item = &rev_json["data"]["items"][0];
    assert_eq!(q_item["reason"], "gate_policy_tampered");
    // Verified sender node (`ext@peer`) is preserved instead of attributing the relaying hub (`ext-hub`).
    assert_eq!(q_item["originNode"], "ext@peer");
    assert_eq!(q_item["sessionId"], "claude:sec-s1");
    assert!(
        q_item.get("text").is_none(),
        "gate review must not emit raw text field"
    );
    assert!(
        !rev_stdout.contains(tail_secret),
        "gate review must NOT leak raw body tail beyond bounded preview"
    );
    assert!(
        q_item["payloadSha256"]
            .as_str()
            .is_some_and(|s| s.len() == 64),
        "expected SHA-256 digest in gate review metadata: {q_item}"
    );
    let receipt = q_item["receipt"]
        .as_str()
        .expect("quarantined receipt")
        .to_string();

    // Also verify `hyp gate log --json` recorded `gate_policy_tampered` with ZERO body bytes!
    let log_out = isolated_cmd(&home)
        .args([
            "gate",
            "log",
            "--decision",
            "quarantined",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(log_out.status.code(), Some(0));
    let log_stdout = String::from_utf8_lossy(&log_out.stdout);
    assert!(
        !log_stdout.contains(head_marker),
        "gate log must never store raw body"
    );
    assert!(
        !log_stdout.contains(tail_secret),
        "gate log must never store raw body"
    );
    let log_json = parse_json_stdout(&log_out);
    assert!(
        log_json["data"]["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["stage"] == "policy_integrity" && e["reason"] == "gate_policy_tampered"),
        "expected policy_integrity tamper audit row: {log_json}"
    );

    // 6. Operator inspects/re-locks policy (`hyp gate lock`), approves quarantined receipt
    //    (`hyp inbox approve <receipt> --json`), and restarts daemon -> approved message wakes `hyp wait`!
    assert_eq!(mcp.close(Duration::from_secs(5)), Some(0));
    let _ = daemon.shutdown_gracefully();

    let (relock_code, relock_json, relock_stderr, _) = passkey.run_and_approve_json(
        &home,
        &[
            "gate",
            "lock",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--local",
            "--no-open",
            "--json",
        ],
        None,
    );
    assert_eq!(relock_code, 0, "stderr={relock_stderr}");
    assert_eq!(relock_json["data"]["gatePolicySig"], "OK");

    let approve_out = common::run_hyp_in_pty(
        &home,
        &[
            "inbox",
            "approve",
            &receipt,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ],
        None,
        Some("y\n"),
    );
    assert_eq!(approve_out.code, 0, "tty={}", approve_out.tty);
    let approve_json = approve_out.parse_json();
    assert_eq!(approve_json["ok"], true);
    assert_eq!(approve_json["data"]["gateState"], "pending");

    let mut clean_daemon_cmd = isolated_cmd(&home);
    clean_daemon_cmd
        .args([
            "daemon",
            "--profile",
            "local",
            "--node-id",
            "sec@box",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null());
    let mut clean_daemon = ManagedProcess::spawn("sec@box re-locked daemon", &mut clean_daemon_cmd);
    let clean_startup = clean_daemon.read_json_line(STARTUP_TIMEOUT);
    assert_eq!(clean_startup["ok"], true);
    assert!(
        !clean_startup
            .get("warnings")
            .and_then(Value::as_array)
            .is_some_and(|arr| arr
                .iter()
                .any(|w| w.as_str().unwrap_or("").contains("gate_policy_tampered"))),
        "re-locked daemon should have zero tamper warnings: {clean_startup}"
    );
    let clean_sock = PathBuf::from(clean_startup["data"]["socketPath"].as_str().unwrap());

    // Live `hyp wait` immediately receives the full human-approved message!
    let mut approved_wait_cmd = isolated_cmd(&home);
    approved_wait_cmd
        .args([
            "wait",
            "--session",
            "claude:sec-s1",
            "--socket",
            clean_sock.to_str().unwrap(),
            "--timeout",
            "5",
            "--json",
        ])
        .stdin(Stdio::null());
    let mut approved_wait =
        ManagedProcess::spawn("sec hyp wait (approved)", &mut approved_wait_cmd);
    let (aw_status, aw_json) = approved_wait.wait_json_output(Duration::from_secs(6));
    assert_eq!(aw_status.code(), Some(0));
    assert_eq!(aw_json["ok"], true);
    let delivered_items = aw_json["data"]["items"].as_array().unwrap();
    let aw_txt = delivered_items[0]["text"].as_str().unwrap_or_default();
    assert!(
        aw_txt.contains("<hyphae-inbox ")
            && aw_txt.contains("<dm from=\"ext@peer/outsider\" count=\"1\"/>"),
        "approved message must wake with metadata-only XML digest: {aw_json}"
    );
    assert!(
        !aw_txt.contains(head_marker) && !aw_txt.contains(tail_secret),
        "RFC 0004: live hyp wait must NEVER include raw approved body: {aw_json}"
    );
    {
        let db = hyp_store::NodeDb::open(state_dir.join("node.sqlite")).unwrap();
        let inbox = db.local().peek_inbox("claude:sec-s1", 20).unwrap();
        assert!(
            inbox
                .iter()
                .any(|m| m.text.contains(head_marker) && m.text.contains(tail_secret)),
            "approved message must remain intact in full inside mailbox for hyp_inbox: {inbox:?}"
        );
    }

    let _ = clean_daemon.shutdown_gracefully();
    let _ = hub_proc.shutdown_gracefully();
}

// ============================================================================
// 4. Legacy v1 `connector.json` + v1 Keystore (`id-sign-*`, `id-enc-*`) Upgrade
//    Preserves Exact Identity (`kid` + `fingerprint`) Across Daemon, Status, Doctor & MCP
// ============================================================================

#[test]
fn legacy_v1_connector_json_and_v1_keystore_upgrade_preserves_identity() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("home");
    let cfg_dir = tmp.path().join("legacy-cfg");
    let state_dir = tmp.path().join("legacy-state");
    for d in [&home, &cfg_dir, &state_dir] {
        fs::create_dir_all(d).unwrap();
    }

    let node_id = "legacy@workstation";

    // Seed legacy v1 keystore entries (`id-sign-<hash12>`, `id-enc-<hash12>`)
    let legacy_sign = Ed25519KeyPair::generate().expect("generate legacy ed25519");
    let legacy_enc = X25519KeyPair::generate().expect("generate legacy x25519");
    let expected_kid = legacy_sign.kid();
    let expected_fingerprint = legacy_sign.fingerprint();

    let (v1_sign_name, v1_enc_name) = legacy_connector_key_secret_names(node_id);
    assert!(v1_sign_name.starts_with("id-sign-"));
    assert!(v1_enc_name.starts_with("id-enc-"));
    let store = SecretStore::new(&state_dir, SecretBackend::File);
    store
        .set(&v1_sign_name, &legacy_sign.export_pkcs8_b64())
        .expect("seed v1 signing key");
    store
        .set(&v1_enc_name, &legacy_enc.export_pkcs8_b64())
        .expect("seed v1 encryption key");

    // Seed legacy v1 `connector.json` pointing to `state_dir`
    let connector_json = cfg_dir.join("connector.json");
    fs::write(
        &connector_json,
        serde_json::to_string_pretty(&json!({
            "connectorId": node_id,
            "stateDir": state_dir.to_str().unwrap()
        }))
        .unwrap(),
    )
    .unwrap();

    // Boot compiled `hyp daemon --config <connector.json> --json`
    let mut daemon_cmd = isolated_cmd(&home);
    daemon_cmd
        .args([
            "daemon",
            "--config",
            connector_json.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null());
    let mut daemon = ManagedProcess::spawn("legacy v1 hyp daemon", &mut daemon_cmd);
    let startup = daemon.read_json_line(STARTUP_TIMEOUT);
    assert_eq!(startup["ok"], true, "legacy daemon startup: {startup}");
    assert_eq!(startup["data"]["nodeId"], node_id);
    assert_eq!(
        startup["data"]["kid"], expected_kid,
        "v2 daemon MUST preserve legacy v1 signing kid!"
    );
    assert_eq!(
        startup["data"]["fingerprint"], expected_fingerprint,
        "v2 daemon MUST preserve legacy v1 signing fingerprint!"
    );
    assert!(
        startup["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap_or("").contains("legacy v1")),
        "expected legacy v1 config warning on startup: {startup}"
    );

    let sock = PathBuf::from(
        startup["data"]["socketPath"]
            .as_str()
            .expect("legacy v1 local daemon must bind local IPC socket"),
    );
    assert!(
        sock.exists(),
        "local IPC socket must exist at {}",
        sock.display()
    );

    // Verify `hyp status --json` and `hyp doctor --json` preserve exact legacy identity
    for subcmd in ["status", "doctor"] {
        let out = isolated_cmd(&home)
            .args([
                subcmd,
                "--config",
                connector_json.to_str().unwrap(),
                "--home",
                home.to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(0),
            "{subcmd} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let env = parse_json_stdout(&out);
        assert_eq!(env["ok"], true);
        assert_eq!(env["data"]["node"]["nodeId"], node_id);
        assert_eq!(env["data"]["node"]["kid"], expected_kid);
        assert_eq!(env["data"]["node"]["fingerprint"], expected_fingerprint);
        assert_eq!(env["data"]["node"]["socketPath"], sock.to_str().unwrap());
    }

    // Serve live `hyp mcp` calls over the upgraded daemon's local IPC socket!
    let mut mcp = McpSubprocess::spawn(&home, &sock);
    let init = mcp.initialize(RPC_TIMEOUT);
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");

    let (join_txt, join_err) = mcp.call_verified_claude(
        &home,
        &sock,
        "legacy-s1",
        "hyp_mesh",
        json!({ "action": "join", "handle": "migrated" }),
        RPC_TIMEOUT,
    );
    assert!(!join_err, "legacy mcp join failed: {join_txt}");
    assert!(
        join_txt.contains("legacy@workstation/migrated"),
        "expected legacy nodeId in MCP join address: {join_txt}"
    );

    assert_eq!(mcp.close(Duration::from_secs(5)), Some(0));
    let _ = daemon.shutdown_gracefully();
}

// ============================================================================
// 5. `hyp secret` & `hyp kv` Forgotten Inputs & Adversarial Matrix
// ============================================================================

#[test]
fn hyp_secret_and_hyp_kv_forgotten_inputs_and_adversarial_matrix() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("home");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    let sd = state_dir.to_str().unwrap();

    // --- Part A: `hyp secret` adversarial & forgotten inputs ---

    // 1. Path traversal in secret name -> exit 2 (`INVALID_SECRET_NAME`)
    let trav = isolated_cmd(&home)
        .args(["secret", "set", "../escape", "--state-dir", sd, "--json"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(trav.status.code(), Some(2));
    assert_eq!(
        parse_json_stdout(&trav)["error"]["code"],
        "INVALID_SECRET_NAME"
    );

    // 2. Empty stdin -> fail closed (`EMPTY_SECRET`, exit 1)
    let mut empty_child = isolated_cmd(&home)
        .args(["secret", "set", "empty-key", "--state-dir", sd, "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    drop(empty_child.stdin.take());
    let empty_out = empty_child.wait_with_output().unwrap();
    assert_eq!(empty_out.status.code(), Some(1));
    assert_eq!(
        parse_json_stdout(&empty_out)["error"]["code"],
        "EMPTY_SECRET"
    );

    // 3. Oversized >64 KiB stdin -> fail closed (`SECRET_TOO_LARGE`, exit 1)
    let mut huge_child = isolated_cmd(&home)
        .args(["secret", "set", "huge-key", "--state-dir", sd, "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let huge_payload = vec![b'A'; 65 * 1024];
    let _ = huge_child.stdin.take().unwrap().write_all(&huge_payload);
    let huge_out = huge_child.wait_with_output().unwrap();
    assert_eq!(huge_out.status.code(), Some(1));
    assert_eq!(
        parse_json_stdout(&huge_out)["error"]["code"],
        "SECRET_TOO_LARGE"
    );

    // 4. `hyp secret set foo --web`: wrong path (404), wrong HTTP methods PUT/DELETE (405),
    //    bad CSRF (403), valid POST (200) -> stored in 0600 file backend with zero stdout leak!
    let mut web_cmd = isolated_cmd(&home);
    web_cmd
        .args([
            "secret",
            "set",
            "foo",
            "--web",
            "--no-open",
            "--timeout",
            "20",
            "--state-dir",
            sd,
            "--json",
        ])
        .stdin(Stdio::null());
    let mut web_proc = ManagedProcess::spawn("hyp secret set foo --web", &mut web_cmd);
    let stderr_line = web_proc
        .try_read_stderr_line(Duration::from_secs(10))
        .expect("read web capture URL from stderr");
    let url = stderr_line
        .split_whitespace()
        .find(|w| w.starts_with("http://127.0.0.1:"))
        .unwrap_or_else(|| panic!("missing loopback capture URL in stderr: {stderr_line}"))
        .to_string();
    let origin = url
        .split("/s/")
        .next()
        .expect("extract origin from /s/<token> URL")
        .to_string();

    let foo_secret = "adv-web-secret-foo-987654321";
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();

        // Wrong path -> 404 Not Found
        let wrong_path_req = Request::builder()
            .method(Method::GET)
            .uri(format!("{origin}/s/not-the-real-token"))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let wrong_path_resp = client.request(wrong_path_req).await.unwrap();
        assert_eq!(wrong_path_resp.status(), StatusCode::NOT_FOUND);

        // Wrong HTTP methods PUT & DELETE -> 405 Method Not Allowed
        for method in [Method::PUT, Method::DELETE] {
            let bad_method_req = Request::builder()
                .method(method.clone())
                .uri(&url)
                .body(Full::new(Bytes::new()))
                .unwrap();
            let bad_method_resp = client.request(bad_method_req).await.unwrap();
            assert_eq!(
                bad_method_resp.status(),
                StatusCode::METHOD_NOT_ALLOWED,
                "expected 405 for {method}"
            );
        }

        // Valid GET -> 200 OK & extract hidden CSRF token
        let get_req = Request::builder()
            .method(Method::GET)
            .uri(&url)
            .body(Full::new(Bytes::new()))
            .unwrap();
        let get_resp = client.request(get_req).await.unwrap();
        assert_eq!(get_resp.status(), StatusCode::OK);
        let html_bytes = get_resp.into_body().collect().await.unwrap().to_bytes();
        let html = String::from_utf8_lossy(&html_bytes);
        let marker = "name=\"csrf\" value=\"";
        let start = html.find(marker).expect("csrf input") + marker.len();
        let end = html[start..].find('"').unwrap() + start;
        let csrf = &html[start..end];

        // Bad CSRF -> 403 Forbidden
        let bad_csrf_req = Request::builder()
            .method(Method::POST)
            .uri(&url)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Full::new(Bytes::from(format!(
                "csrf=forged-csrf-nonce&value={foo_secret}"
            ))))
            .unwrap();
        let bad_csrf_resp = client.request(bad_csrf_req).await.unwrap();
        assert_eq!(bad_csrf_resp.status(), StatusCode::FORBIDDEN);

        // Valid POST -> 200 OK
        let ok_req = Request::builder()
            .method(Method::POST)
            .uri(&url)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Full::new(Bytes::from(format!(
                "csrf={csrf}&value={foo_secret}"
            ))))
            .unwrap();
        let ok_resp = client.request(ok_req).await.unwrap();
        assert_eq!(ok_resp.status(), StatusCode::OK);
    });

    let (web_status, web_json) = web_proc.wait_json_output(Duration::from_secs(10));
    assert_eq!(web_status.code(), Some(0));
    assert_eq!(web_json["ok"], true);
    assert_eq!(web_json["data"]["name"], "foo");
    assert_eq!(web_json["data"]["captureMode"], "web");
    assert!(
        !web_json.to_string().contains(foo_secret),
        "secret value must NEVER appear in CLI stdout JSON"
    );

    let store = SecretStore::new(&state_dir, SecretBackend::File);
    assert_eq!(
        &*store.get("foo").expect("read stored foo secret"),
        foo_secret
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let loc = web_json["data"]["location"]
            .as_str()
            .expect("secret file path");
        let mode = fs::metadata(loc)
            .expect("stat secret file")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "secret fallback file must be strictly 0600");
    }

    // --- Part B: `hyp kv` forgotten inputs & allowlist authorization matrix ---

    // 1. Malformed JSON `--value '{bad'` -> exit 2 (`INVALID_JSON_VALUE`)
    let bad_json = isolated_cmd(&home)
        .args([
            "kv",
            "set",
            "--ns",
            "ops",
            "--key",
            "bad-json",
            "--value",
            "{bad",
            "--state-dir",
            sd,
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(bad_json.status.code(), Some(2));
    assert_eq!(
        parse_json_stdout(&bad_json)["error"]["code"],
        "INVALID_JSON_VALUE"
    );

    // 2. `--ttl-seconds 0` and negative `--ttl-seconds=-5` -> exit 2 (`INVALID_TTL`)
    for bad_ttl in ["--ttl-seconds=0", "--ttl-seconds=-5"] {
        let ttl_out = isolated_cmd(&home)
            .args([
                "kv",
                "set",
                "--ns",
                "ops",
                "--key",
                "bad-ttl",
                "--value",
                r#"{"ok":true}"#,
                bad_ttl,
                "--state-dir",
                sd,
                "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(
            ttl_out.status.code(),
            Some(2),
            "expected exit 2 for {bad_ttl}"
        );
        assert_eq!(parse_json_stdout(&ttl_out)["error"]["code"], "INVALID_TTL");
    }

    // 3. `allowlist` write-model enforcement: authorized writers succeed, unauthorized fails closed (exit 1)!
    let create_allow = isolated_cmd(&home)
        .args([
            "kv",
            "set",
            "--ns",
            "deploys",
            "--key",
            "prod-sha",
            "--value",
            r#"{"sha":"aaa111"}"#,
            "--write-model",
            "allowlist",
            "--allowlist",
            "alice@macbook,bob@laptop",
            "--writer",
            "alice@macbook",
            "--state-dir",
            sd,
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(create_allow.status.code(), Some(0));
    assert_eq!(parse_json_stdout(&create_allow)["data"]["version"], 1);

    // Authorized second writer updates key -> v2
    let bob_update = isolated_cmd(&home)
        .args([
            "kv",
            "set",
            "--ns",
            "deploys",
            "--key",
            "prod-sha",
            "--value",
            r#"{"sha":"bbb222"}"#,
            "--write-model",
            "allowlist",
            "--writer",
            "bob@laptop",
            "--expected-version",
            "1",
            "--state-dir",
            sd,
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(bob_update.status.code(), Some(0));
    assert_eq!(parse_json_stdout(&bob_update)["data"]["version"], 2);

    // Unauthorized writer (`mallory@evil`) attempting write -> fail closed (exit 1, UNAUTHORIZED)
    let mallory_set = isolated_cmd(&home)
        .args([
            "kv",
            "set",
            "--ns",
            "deploys",
            "--key",
            "prod-sha",
            "--value",
            r#"{"sha":"pwned"}"#,
            "--write-model",
            "allowlist",
            "--writer",
            "mallory@evil",
            "--expected-version",
            "2",
            "--state-dir",
            sd,
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(mallory_set.status.code(), Some(1));
    let mallory_set_json = parse_json_stdout(&mallory_set);
    assert_eq!(mallory_set_json["ok"], false);
    assert_eq!(mallory_set_json["error"]["code"], "UNAUTHORIZED");

    // Unauthorized writer attempting delete -> fail closed (exit 1, UNAUTHORIZED)
    let mallory_del = isolated_cmd(&home)
        .args([
            "kv",
            "delete",
            "--ns",
            "deploys",
            "--key",
            "prod-sha",
            "--writer",
            "mallory@evil",
            "--state-dir",
            sd,
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(mallory_del.status.code(), Some(1));
    assert_eq!(
        parse_json_stdout(&mallory_del)["error"]["code"],
        "UNAUTHORIZED"
    );

    // Confirm KV entry stayed intact at v2 (`bbb222`)
    let get_after = isolated_cmd(&home)
        .args([
            "kv",
            "get",
            "--ns",
            "deploys",
            "--key",
            "prod-sha",
            "--state-dir",
            sd,
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(get_after.status.code(), Some(0));
    let get_json = parse_json_stdout(&get_after);
    assert_eq!(get_json["data"]["version"], 2);
    assert_eq!(get_json["data"]["value"]["sha"], "bbb222");
}

// ============================================================================
// 6. Four-Process Two-Hub Topology: Agent Descriptions & Automatic Multi-Hub
//    E2EE Routing Without `<hub>!` Prefix (Zero Plaintext on Either Hub)
// ============================================================================

#[test]
fn two_hub_agent_descriptions_and_auto_routing_without_hub_prefix() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let hub_a_home = tmp.path().join("hub-a-home");
    let hub_a_state = tmp.path().join("hub-a-state");
    let hub_b_home = tmp.path().join("hub-b-home");
    let hub_b_state = tmp.path().join("hub-b-state");
    let alice_home = tmp.path().join("alice-home");
    let alice_state = tmp.path().join("alice-state");
    let bob_home = tmp.path().join("bob-home");
    let bob_state = tmp.path().join("bob-state");
    for d in [
        &hub_a_home,
        &hub_a_state,
        &hub_b_home,
        &hub_b_state,
        &alice_home,
        &alice_state,
        &bob_home,
        &bob_state,
    ] {
        fs::create_dir_all(d).unwrap();
    }

    // Spawn Process 1 (`hub-alpha`) and Process 2 (`hub-beta`)
    let spawn_hub = |node_id: &str, home: &Path, state: &Path| {
        let mut cmd = isolated_cmd(home);
        cmd.args([
            "node",
            "start",
            "--profile",
            "router",
            "--node-id",
            node_id,
            "--bind",
            "127.0.0.1:0",
            "--no-local-socket",
            "--state-dir",
            state.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null());
        let proc = ManagedProcess::spawn(format!("{node_id} hub"), &mut cmd);
        let startup = proc.read_json_line(STARTUP_TIMEOUT);
        assert_eq!(startup["ok"], true, "{node_id} startup: {startup}");
        let endpoint = startup["data"]["endpoint"]
            .as_str()
            .expect("hub endpoint")
            .to_string();
        (proc, endpoint)
    };
    let (mut hub_a_proc, hub_a_ep) = spawn_hub("hub-alpha", &hub_a_home, &hub_a_state);
    let (mut hub_b_proc, hub_b_ep) = spawn_hub("hub-beta", &hub_b_home, &hub_b_state);

    let pair_node_to_hub = |hub_id: &str,
                            hub_home: &Path,
                            hub_state: &Path,
                            hub_ep: &str,
                            peer_id: &str,
                            peer_home: &Path,
                            peer_state: &Path| {
        let inv_out = isolated_cmd(hub_home)
            .args([
                "pair",
                "invite",
                "--mode",
                "team",
                "--node-id",
                hub_id,
                "--endpoint",
                hub_ep,
                "--peer",
                peer_id,
                "--preset",
                "member",
                "--state-dir",
                hub_state.to_str().unwrap(),
                "--json",
            ])
            .output()
            .expect("hyp pair invite");
        assert_eq!(inv_out.status.code(), Some(0));
        let am2_token = parse_json_stdout(&inv_out)["data"]["token"]
            .as_str()
            .expect("am2 token")
            .to_string();

        let mut acc_child = isolated_cmd(peer_home)
            .args([
                "pair",
                "accept",
                "--offline",
                "--node-id",
                peer_id,
                "--state-dir",
                peer_state.to_str().unwrap(),
                "--json",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn hyp pair accept");
        acc_child
            .stdin
            .take()
            .unwrap()
            .write_all(format!("{am2_token}\n").as_bytes())
            .unwrap();
        let acc_out = acc_child.wait_with_output().unwrap();
        assert_eq!(
            acc_out.status.code(),
            Some(0),
            "pair accept failed for {peer_id} -> {hub_id}: {}",
            String::from_utf8_lossy(&acc_out.stderr)
        );

        let peer_keys = SecretStore::new(peer_state, SecretBackend::File)
            .load_or_create_node_keys(peer_id)
            .expect("load paired peer keys");
        register_peer_in_sqlite(
            &hub_state.join("node.sqlite"),
            peer_id,
            &peer_keys,
            PeerProfile::Local,
            TrustTier::Org,
            ScopePreset::Member.expand(),
        );
    };

    // Alice connects to BOTH hubs (`hub-alpha` & `hub-beta`); Bob connects ONLY to `hub-beta`.
    pair_node_to_hub(
        "hub-alpha",
        &hub_a_home,
        &hub_a_state,
        &hub_a_ep,
        "alice@macbook",
        &alice_home,
        &alice_state,
    );
    pair_node_to_hub(
        "hub-beta",
        &hub_b_home,
        &hub_b_state,
        &hub_b_ep,
        "alice@macbook",
        &alice_home,
        &alice_state,
    );
    pair_node_to_hub(
        "hub-beta",
        &hub_b_home,
        &hub_b_state,
        &hub_b_ep,
        "bob@laptop",
        &bob_home,
        &bob_state,
    );

    // Process 3: Alice (`alice@macbook`) auto-connects BOTH hubs!
    let mut alice_cmd = isolated_cmd(&alice_home);
    alice_cmd
        .args([
            "daemon",
            "--profile",
            "local",
            "--node-id",
            "alice@macbook",
            "--state-dir",
            alice_state.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null());
    let mut alice_proc = ManagedProcess::spawn("alice@macbook daemon", &mut alice_cmd);
    let alice_startup = alice_proc.read_json_line(STARTUP_TIMEOUT);
    assert_eq!(alice_startup["ok"], true, "alice startup: {alice_startup}");
    let alice_connected: Vec<String> = alice_startup["data"]["connectedPeers"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert!(
        alice_connected.contains(&"hub-alpha".to_string())
            && alice_connected.contains(&"hub-beta".to_string()),
        "Alice must auto-connect both hubs on boot: {alice_startup}"
    );
    let alice_sock = PathBuf::from(alice_startup["data"]["socketPath"].as_str().unwrap());

    // Process 4: Bob (`bob@laptop`) auto-connects ONLY `hub-beta`!
    let mut bob_cmd = isolated_cmd(&bob_home);
    bob_cmd
        .args([
            "daemon",
            "--profile",
            "local",
            "--node-id",
            "bob@laptop",
            "--state-dir",
            bob_state.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null());
    let mut bob_proc = ManagedProcess::spawn("bob@laptop daemon", &mut bob_cmd);
    let bob_startup = bob_proc.read_json_line(STARTUP_TIMEOUT);
    assert_eq!(bob_startup["ok"], true, "bob startup: {bob_startup}");
    assert_eq!(bob_startup["data"]["connectedPeers"], json!(["hub-beta"]));
    let bob_sock = PathBuf::from(bob_startup["data"]["socketPath"].as_str().unwrap());

    let mut alice_mcp = McpSubprocess::spawn(&alice_home, &alice_sock);
    let mut bob_mcp = McpSubprocess::spawn(&bob_home, &bob_sock);
    alice_mcp.initialize(RPC_TIMEOUT);
    bob_mcp.initialize(RPC_TIMEOUT);

    // Bob joins `hub-beta` with an explicit role description!
    let (b_join, b_err) = bob_mcp.call_verified_claude(
        &bob_home,
        &bob_sock,
        "bob-s1",
        "hyp_mesh",
        json!({
            "action": "join",
            "handle": "bob",
            "description": "Rust release engineer"
        }),
        RPC_TIMEOUT,
    );
    assert!(!b_err, "bob join failed: {b_join}");
    let b_join_val: Value = serde_json::from_str(&b_join).unwrap();
    assert_eq!(b_join_val["description"], "Rust release engineer");

    let (a_join, a_err) = alice_mcp.call_verified_claude(
        &alice_home,
        &alice_sock,
        "alice-s1",
        "hyp_mesh",
        json!({
            "action": "join",
            "handle": "alice",
            "description": "Lead orchestrator"
        }),
        RPC_TIMEOUT,
    );
    assert!(!a_err, "alice join failed: {a_join}");

    // Alice queries `hyp_mesh({ action: "peers" })` -> discovers Bob's description & `via: "hub-beta"`!
    let (peers_txt, peers_err) = alice_mcp.call_verified_claude(
        &alice_home,
        &alice_sock,
        "alice-s1",
        "hyp_mesh",
        json!({ "action": "peers" }),
        RPC_TIMEOUT,
    );
    assert!(!peers_err, "alice peers failed: {peers_txt}");
    let peers_val: Value = serde_json::from_str(&peers_txt).unwrap();
    assert_eq!(peers_val["untrustedMetadata"], true);
    assert!(
        peers_val["peers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p == "bob@laptop/bob"),
        "expected bob@laptop/bob in peers: {peers_val}"
    );
    let bob_detail = peers_val["peerDetails"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["address"] == "bob@laptop/bob")
        .expect("bob@laptop/bob in peerDetails");
    assert_eq!(bob_detail["nodeId"], "bob@laptop");
    assert_eq!(bob_detail["handle"], "bob");
    assert_eq!(bob_detail["description"], "Rust release engineer");
    assert_eq!(bob_detail["via"], "hub-beta");

    // Arm Bob's live `hyp wait` and send DM from Alice WITHOUT any `hub-beta!` prefix!
    let dm_secret = "TWO_HUB_AUTO_ROUTE_E2EE_SECRET_44556677";
    let mut bob_wait_cmd = isolated_cmd(&bob_home);
    bob_wait_cmd
        .args([
            "wait",
            "--session",
            "claude:bob-s1",
            "--socket",
            bob_sock.to_str().unwrap(),
            "--timeout",
            "15",
            "--json",
        ])
        .stdin(Stdio::null());
    let mut bob_wait = ManagedProcess::spawn("bob hyp wait (multi-hub DM)", &mut bob_wait_cmd);
    wait_for_session_live(&bob_sock, "claude:bob-s1", Duration::from_secs(5));

    let (send_txt, send_err) = alice_mcp.call_verified_claude(
        &alice_home,
        &alice_sock,
        "alice-s1",
        "hyp_send",
        json!({ "to": "bob@laptop/bob", "text": dm_secret }),
        RPC_TIMEOUT,
    );
    assert!(!send_err, "alice auto-routed send failed: {send_txt}");
    let send_val: Value = serde_json::from_str(&send_txt).unwrap();
    assert_eq!(send_val["encrypted"], true, "DM must be E2EE: {send_val}");
    assert_eq!(
        send_val["routedVia"], "hub-beta",
        "DM without hub prefix must auto-route via learned hub-beta route: {send_val}"
    );

    let (wait_status, wait_json) = bob_wait.wait_json_output(Duration::from_secs(15));
    assert_eq!(wait_status.code(), Some(0));
    assert_eq!(wait_json["ok"], true);
    let items = wait_json["data"]["items"].as_array().unwrap();
    let wait_txt = items[0]["text"].as_str().unwrap_or_default();
    assert!(
        wait_txt.contains("<hyphae-inbox ")
            && wait_txt.contains("<dm from=\"alice@macbook/alice\" count=\"1\"/>"),
        "Bob's live hyp wait must receive metadata-only XML digest: {wait_json}"
    );
    assert!(
        !wait_txt.contains(dm_secret),
        "RFC 0004: live hyp wait must NEVER include raw E2EE DM plaintext: {wait_json}"
    );
    let (bob_inbox_txt, bob_inbox_err) = bob_mcp.call_verified_claude(
        &bob_home,
        &bob_sock,
        "bob-s1",
        "hyp_inbox",
        json!({}),
        RPC_TIMEOUT,
    );
    assert!(!bob_inbox_err, "bob hyp_inbox failed: {bob_inbox_txt}");
    assert!(
        bob_inbox_txt.contains(dm_secret),
        "Bob's hyp_inbox must return decrypted E2EE DM: {bob_inbox_txt}"
    );

    // Zero-knowledge verification on BOTH hubs (live + post-shutdown)!
    let scan_both_hubs = |phase: &str| {
        for (label, dir) in [("hub-alpha", &hub_a_state), ("hub-beta", &hub_b_state)] {
            for fname in ["node.sqlite", "node.sqlite-wal", "node.sqlite-shm"] {
                let p = dir.join(fname);
                if p.exists() {
                    let raw = fs::read(&p).expect("read hub sqlite");
                    assert!(
                        !bytes_contain(&raw, dm_secret.as_bytes()),
                        "PLAINTEXT LEAK ({phase}) on {label}/{fname}!"
                    );
                }
            }
        }
    };
    scan_both_hubs("live");

    assert_eq!(alice_mcp.close(Duration::from_secs(5)), Some(0));
    assert_eq!(bob_mcp.close(Duration::from_secs(5)), Some(0));
    let _ = alice_proc.shutdown_gracefully();
    let _ = bob_proc.shutdown_gracefully();
    let _ = hub_a_proc.shutdown_gracefully();
    let _ = hub_b_proc.shutdown_gracefully();

    scan_both_hubs("post-shutdown");
}

// ============================================================================
// 7. `node.json` `plugins[]` Boot Wiring, Secret Resolution & Full Bridge
//    Inbound/Outbound Roundtrip (Unix fd-3 SubprocessSupervisor)
// ============================================================================

#[cfg(unix)]
#[test]
fn node_json_plugins_boot_wiring_secret_resolution_and_bridge_roundtrip() {
    struct CapturedCallback {
        body: String,
        signature: Option<String>,
    }

    struct MockCallbackReceiver {
        addr: SocketAddr,
        rx: mpsc::Receiver<CapturedCallback>,
        shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
        join: Option<thread::JoinHandle<()>>,
    }

    impl MockCallbackReceiver {
        fn start() -> Self {
            let (addr_tx, addr_rx) = mpsc::channel::<SocketAddr>();
            let (cb_tx, cb_rx) = mpsc::channel::<CapturedCallback>();
            let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

            let join = thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("mock callback runtime");
                rt.block_on(async move {
                    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let addr = listener.local_addr().unwrap();
                    let _ = addr_tx.send(addr);

                    loop {
                        tokio::select! {
                            _ = &mut shutdown_rx => break,
                            accepted = listener.accept() => {
                                let Ok((stream, _)) = accepted else { break };
                                let tx = cb_tx.clone();
                                tokio::spawn(async move {
                                    let io = TokioIo::new(stream);
                                    let svc = service_fn(move |req: Request<Incoming>| {
                                        let tx_inner = tx.clone();
                                        async move {
                                            let sig = req
                                                .headers()
                                                .get("x-webhook-signature-256")
                                                .and_then(|v| v.to_str().ok())
                                                .map(ToOwned::to_owned);
                                            let bytes = req
                                                .into_body()
                                                .collect()
                                                .await
                                                .map(|b| b.to_bytes())
                                                .unwrap_or_default();
                                            let _ = tx_inner.send(CapturedCallback {
                                                body: String::from_utf8_lossy(&bytes).into_owned(),
                                                signature: sig,
                                            });
                                            Ok::<_, hyper::Error>(
                                                Response::builder()
                                                    .status(StatusCode::OK)
                                                    .header(header::CONTENT_TYPE, "application/json")
                                                    .body(Full::new(Bytes::from(r#"{"ok":true}"#)))
                                                    .unwrap(),
                                            )
                                        }
                                    });
                                    let _ = http1::Builder::new().serve_connection(io, svc).await;
                                });
                            }
                        }
                    }
                });
            });

            let addr = addr_rx
                .recv_timeout(Duration::from_secs(5))
                .expect("callback receiver bind");
            Self {
                addr,
                rx: cb_rx,
                shutdown_tx: Some(shutdown_tx),
                join: Some(join),
            }
        }
    }

    impl Drop for MockCallbackReceiver {
        fn drop(&mut self) {
            if let Some(tx) = self.shutdown_tx.take() {
                let _ = tx.send(());
            }
            if let Some(j) = self.join.take() {
                let _ = j.join();
            }
        }
    }

    fn hmac_sha256_header(secret: &str, body: &[u8]) -> String {
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
        let tag = ring::hmac::sign(&key, body);
        format!("sha256={}", hex::encode(tag.as_ref()))
    }

    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("home");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&state_dir).unwrap();

    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root");
    let webhook_script = repo_root.join("plugins").join("webhook").join("index.mjs");
    assert!(
        webhook_script.exists(),
        "expected webhook plugin at {}",
        webhook_script.display()
    );

    // Reserve an ephemeral loopback port for the webhook plugin HTTP listener.
    let webhook_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };

    let receiver = MockCallbackReceiver::start();
    let webhook_secret = "whsec-test-plugin-boot-99112233";

    // Fault-isolation test: missing secret reference in `plugins[].env` MUST warn and skip
    // only that plugin without aborting the entire `hyp daemon`!
    let bad_cfg_path = tmp.path().join("bad-node.json");
    fs::write(
        &bad_cfg_path,
        serde_json::to_string_pretty(&json!({
            "v": 2,
            "nodeId": "bridge@box",
            "profile": "local",
            "stateDir": state_dir.to_str().unwrap(),
            "plugins": [{
                "id": "webhook",
                "kind": "bridge",
                "exec": "node",
                "args": [webhook_script.to_str().unwrap()],
                "targets": ["ops"],
                "env": {
                    "WEBHOOK_SECRET": { "secret": "missing-webhook-secret" }
                }
            }]
        }))
        .unwrap(),
    )
    .unwrap();
    let mut isolated_daemon_cmd = isolated_cmd(&home);
    isolated_daemon_cmd.args([
        "daemon",
        "--config",
        bad_cfg_path.to_str().unwrap(),
        "--json",
    ]);
    let mut isolated_daemon =
        ManagedProcess::spawn("hyp daemon missing-secret plugin", &mut isolated_daemon_cmd);
    let bad_json = isolated_daemon.read_json_line(Duration::from_secs(10));
    assert_eq!(
        bad_json["ok"], true,
        "daemon must stay up when one plugin misses a secret: {bad_json}"
    );
    let warnings = bad_json["warnings"]
        .as_array()
        .expect("startup warnings array");
    assert!(
        warnings.iter().any(|w| {
            w.as_str()
                .is_some_and(|s| s.contains("missing-webhook-secret"))
        }),
        "expected missing secret reference in warnings: {bad_json}"
    );
    let plugins_arr = bad_json["data"]["plugins"]
        .as_array()
        .expect("plugins statuses");
    assert_eq!(plugins_arr.len(), 1);
    assert_eq!(plugins_arr[0]["id"], "webhook");
    assert_eq!(plugins_arr[0]["status"], "skipped");
    isolated_daemon.shutdown_gracefully();

    // Store real secret in `SecretStore` (file backend, 0600) and write valid `node.json`.
    let secrets = SecretStore::new(&state_dir, SecretBackend::File);
    secrets
        .set("webhook-test-secret", webhook_secret)
        .expect("store webhook-test-secret");

    let node_json_path = state_dir.join("node.json");
    fs::write(
        &node_json_path,
        serde_json::to_string_pretty(&json!({
            "v": 2,
            "nodeId": "bridge@box",
            "profile": "local",
            "stateDir": state_dir.to_str().unwrap(),
            "plugins": [{
                "id": "webhook",
                "kind": "bridge",
                "exec": "node",
                "args": [webhook_script.to_str().unwrap()],
                "targets": ["ops"],
                "env": {
                    "WEBHOOK_HOST": "127.0.0.1",
                    "WEBHOOK_PORT": webhook_port.to_string(),
                    "WEBHOOK_PATH": "/webhook",
                    "WEBHOOK_TARGET": "ops",
                    "WEBHOOK_SECRET": { "secret": "webhook-test-secret" },
                    "WEBHOOK_POST_URL": format!("http://{}/callback", receiver.addr)
                }
            }]
        }))
        .unwrap(),
    )
    .unwrap();

    // Boot compiled `hyp daemon --config <node.json> --json`!
    let mut daemon_cmd = isolated_cmd(&home);
    daemon_cmd
        .args([
            "daemon",
            "--config",
            node_json_path.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null());
    let mut daemon_proc = ManagedProcess::spawn("bridge@box daemon", &mut daemon_cmd);
    let startup = daemon_proc.read_json_line(STARTUP_TIMEOUT);
    assert_eq!(startup["ok"], true, "bridge daemon startup: {startup}");
    assert!(
        !startup.to_string().contains(webhook_secret),
        "secret value MUST NEVER appear in daemon startup JSON"
    );
    let status_file_raw = fs::read_to_string(state_dir.join("node.status.json")).unwrap();
    assert!(
        !status_file_raw.contains(webhook_secret),
        "secret value MUST NEVER appear in node.status.json"
    );
    assert_eq!(startup["data"]["plugins"][0]["id"], "webhook");
    assert_eq!(startup["data"]["plugins"][0]["kind"], "bridge");
    assert_eq!(startup["data"]["plugins"][0]["targets"], json!(["ops"]));
    assert_eq!(startup["data"]["plugins"][0]["status"], "running");
    let sock = PathBuf::from(startup["data"]["socketPath"].as_str().unwrap());

    // Spawn real `hyp mcp` and verify `hyp_bridge` tool + unlinked configured target advertising!
    let mut mcp = McpSubprocess::spawn(&home, &sock);
    mcp.initialize(RPC_TIMEOUT);

    let list_resp = mcp.rpc(
        json!({ "jsonrpc": "2.0", "id": 900, "method": "tools/list", "params": {} }),
        RPC_TIMEOUT,
    );
    let tool_names: Vec<String> = list_resp["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_string())
        .collect();
    assert!(
        tool_names.contains(&"hyp_bridge".to_string()),
        "tools/list must include hyp_bridge when plugins[] bridge is booted: {tool_names:?}"
    );

    // Join two sessions: `primary` and `reader`.
    for (sess, handle) in [("wh-primary", "primary"), ("wh-reader", "reader")] {
        let (j_txt, j_err) = mcp.call_verified_claude(
            &home,
            &sock,
            sess,
            "hyp_mesh",
            json!({ "action": "join", "handle": handle }),
            RPC_TIMEOUT,
        );
        assert!(!j_err, "join {handle} failed: {j_txt}");
    }

    // BEFORE linking: `hyp_bridge({ action: "targets" })` immediately advertises `webhook:ops` (`configured: true`)!
    let (pre_targets_txt, pre_targets_err) = mcp.call_verified_claude(
        &home,
        &sock,
        "wh-primary",
        "hyp_bridge",
        json!({ "action": "targets" }),
        RPC_TIMEOUT,
    );
    assert!(!pre_targets_err, "targets failed: {pre_targets_txt}");
    let pre_targets: Value = serde_json::from_str(&pre_targets_txt).unwrap();
    assert_eq!(pre_targets["plugins"], json!(["webhook"]));
    assert_eq!(pre_targets["targets"][0]["plugin"], "webhook");
    assert_eq!(pre_targets["targets"][0]["target"], "ops");
    assert_eq!(pre_targets["targets"][0]["configured"], true);
    assert_eq!(pre_targets["targets"][0]["readers"], json!([]));
    assert!(pre_targets["targets"][0]["primarySession"].is_null());

    // Claim primary (`handoff`) for `wh-primary`, and `link` (`reader`) for `wh-reader`!
    let (ho_txt, ho_err) = mcp.call_verified_claude(
        &home,
        &sock,
        "wh-primary",
        "hyp_bridge",
        json!({ "action": "handoff", "plugin": "webhook", "target": "ops" }),
        RPC_TIMEOUT,
    );
    assert!(!ho_err, "primary handoff failed: {ho_txt}");

    let (lk_txt, lk_err) = mcp.call_verified_claude(
        &home,
        &sock,
        "wh-reader",
        "hyp_bridge",
        json!({ "action": "link", "plugin": "webhook", "target": "ops" }),
        RPC_TIMEOUT,
    );
    assert!(!lk_err, "reader link failed: {lk_txt}");
    assert_eq!(
        serde_json::from_str::<Value>(&lk_txt).unwrap()["role"],
        "reader"
    );

    // Arm BOTH live `hyp wait` subprocesses (`primary` + `reader`)!
    let spawn_wait = |sess: &str| {
        let mut cmd = isolated_cmd(&home);
        cmd.args([
            "wait",
            "--session",
            sess,
            "--socket",
            sock.to_str().unwrap(),
            "--timeout",
            "15",
            "--json",
        ])
        .stdin(Stdio::null());
        ManagedProcess::spawn(format!("hyp wait ({sess})"), &mut cmd)
    };
    let wait_primary = spawn_wait("claude:wh-primary");
    let wait_reader = spawn_wait("claude:wh-reader");
    wait_for_session_live(&sock, "claude:wh-primary", Duration::from_secs(5));
    wait_for_session_live(&sock, "claude:wh-reader", Duration::from_secs(5));

    // Deliver inbound HTTP POST to the real `plugins/webhook/index.mjs` process!
    let webhook_url = format!("http://127.0.0.1:{webhook_port}/webhook");
    let inbound_marker = "WEBHOOK_INBOUND_ROUNDTRIP_SENTINEL_9090";
    let inbound_body = json!({
        "id": "wh-delivery-1",
        "from": "pagerduty",
        "text": inbound_marker
    })
    .to_string();
    let valid_sig = hmac_sha256_header(webhook_secret, inbound_body.as_bytes());

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
        // Wait for webhook plugin HTTP listener to accept connections (bounded retry).
        let deadline = Instant::now() + Duration::from_secs(20);
        let bad_resp = loop {
            let req = Request::builder()
                .method(Method::POST)
                .uri(&webhook_url)
                .header(header::CONTENT_TYPE, "application/json")
                .header("x-webhook-signature-256", "sha256=deadbeef")
                .body(Full::new(Bytes::from(inbound_body.clone())))
                .unwrap();
            match client.request(req).await {
                Ok(r) => break r,
                Err(_) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                Err(e) => panic!("webhook plugin never became reachable at {webhook_url}: {e}"),
            }
        };
        assert_eq!(
            bad_resp.status(),
            StatusCode::UNAUTHORIZED,
            "bad HMAC must fail closed 401 (proving WEBHOOK_SECRET was resolved from SecretStore)"
        );

        let good_req = Request::builder()
            .method(Method::POST)
            .uri(&webhook_url)
            .header(header::CONTENT_TYPE, "application/json")
            .header("x-webhook-signature-256", &valid_sig)
            .body(Full::new(Bytes::from(inbound_body.clone())))
            .unwrap();
        let good_resp = client.request(good_req).await.expect("signed webhook POST");
        assert_eq!(good_resp.status(), StatusCode::ACCEPTED);
    });

    // BOTH `primary` and `reader` live `hyp wait` processes MUST wake with the metadata-only XML digest!
    for (label, mut waiter) in [("primary", wait_primary), ("reader", wait_reader)] {
        let (st, out) = waiter.wait_json_output(Duration::from_secs(12));
        assert_eq!(st.code(), Some(0), "{label} wait status: {out}");
        assert_eq!(out["ok"], true);
        let items = out["data"]["items"].as_array().unwrap();
        let wait_txt = items[0]["text"].as_str().unwrap_or_default();
        assert!(
            wait_txt.contains("<hyphae-inbox ")
                && wait_txt.contains("<bridge target=\"webhook:ops\" count=\"1\"/>"),
            "{label} must receive metadata-only bridge XML digest: {out}"
        );
        assert!(
            !wait_txt.contains(inbound_marker),
            "RFC 0004: {label} wait must NEVER include raw webhook payload: {out}"
        );
    }
    let (wh_inbox_txt, wh_inbox_err) = mcp.call_verified_claude(
        &home,
        &sock,
        "wh-primary",
        "hyp_inbox",
        json!({}),
        RPC_TIMEOUT,
    );
    assert!(!wh_inbox_err, "primary hyp_inbox failed: {wh_inbox_txt}");
    assert!(
        wh_inbox_txt.contains(inbound_marker),
        "primary hyp_inbox must return full inbound webhook payload: {wh_inbox_txt}"
    );

    // Outbound: `reader` MUST be rejected `not_target_holder`!
    let (r_txt, r_err) = mcp.call_verified_claude(
        &home,
        &sock,
        "wh-reader",
        "hyp_send",
        json!({ "to": "webhook:ops", "text": "unauthorized reader post" }),
        RPC_TIMEOUT,
    );
    assert!(
        r_err && r_txt.contains("not_target_holder"),
        "reader outbound post must fail closed not_target_holder: {r_txt}"
    );

    // Outbound: Stage 1 Outbound DLP MUST block synthetic AWS secret (`AKIA...`)!
    let (dlp_txt, dlp_err) = mcp.call_verified_claude(
        &home,
        &sock,
        "wh-primary",
        "hyp_send",
        json!({ "to": "webhook:ops", "text": "leak AKIAIOSFODNN7EXAMPLE" }),
        RPC_TIMEOUT,
    );
    assert!(
        dlp_err && dlp_txt.contains("outbound_dlp_blocked"),
        "Outbound DLP must block synthetic AWS secret before plugin post: {dlp_txt}"
    );
    assert!(
        receiver.rx.try_recv().is_err(),
        "no callback may reach receiver for rejected/DLP-blocked posts"
    );

    // Outbound: `primary` clean reply hits mock HTTP receiver with valid HMAC-SHA256!
    let outbound_text = "Incident acknowledged by primary on-call agent";
    let (ok_txt, ok_err) = mcp.call_verified_claude(
        &home,
        &sock,
        "wh-primary",
        "hyp_send",
        json!({ "to": "webhook:ops", "text": outbound_text }),
        RPC_TIMEOUT,
    );
    assert!(!ok_err, "primary outbound bridge post failed: {ok_txt}");
    let ok_val: Value = serde_json::from_str(&ok_txt).unwrap();
    assert_eq!(ok_val["delivered"], true);

    let captured = receiver
        .rx
        .recv_timeout(Duration::from_secs(5))
        .expect("receive outbound webhook callback");
    let cb_json: Value = serde_json::from_str(&captured.body).expect("callback JSON");
    assert_eq!(cb_json["target"], "ops");
    assert_eq!(cb_json["text"], outbound_text);
    let expected_cb_sig = hmac_sha256_header(webhook_secret, captured.body.as_bytes());
    assert_eq!(
        captured.signature.as_deref(),
        Some(expected_cb_sig.as_str()),
        "outbound webhook callback MUST carry valid HMAC-SHA256 signature"
    );

    // Clean daemon shutdown MUST terminate child plugin cleanly (no orphaned listener!).
    assert_eq!(mcp.close(Duration::from_secs(5)), Some(0));
    let _ = daemon_proc.shutdown_gracefully();

    let close_deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if std::net::TcpStream::connect(("127.0.0.1", webhook_port)).is_err() {
            break;
        }
        assert!(
            Instant::now() < close_deadline,
            "child webhook plugin remained listening on port {webhook_port} after daemon shutdown (orphan leak!)"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

// ============================================================================
// 8. v1 -> v2 SQLite Upgrade via Compiled `hyp doctor` Creates `0600` Backup,
//    Preserves All v1 Data, and Blocks Newer-Schema Downgrades Fail-Closed
// ============================================================================

#[test]
fn v1_to_v2_sqlite_upgrade_via_compiled_hyp_doctor_creates_backup() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("v1-home");
    let state_dir = home.join(".config").join("hyphae");
    fs::create_dir_all(&state_dir).unwrap();
    let db_path = state_dir.join("node.sqlite");

    // 1. Seed a genuine v0.2.0 schema-v1 SQLite DB with sample peer, handle, and mailbox message.
    {
        let db = NodeDb::open(&db_path).expect("seed base sqlite");
        let now = now_ms();
        db.local()
            .set_metadata("node_id", "v1@workstation")
            .unwrap();
        db.local()
            .register_session("claude:v1-sess", r#"{"kind":"claude"}"#, now)
            .unwrap();
        db.local()
            .set_session_handle("claude:v1-sess", Some("legacy-agent"), now)
            .unwrap();
        db.messages()
            .register_handle(
                "v1@workstation",
                "legacy-agent",
                Some("claude:v1-sess"),
                now,
            )
            .unwrap();
        db.peers()
            .upsert_peer(
                &PeerInput {
                    peer_id: "acme-team".to_string(),
                    endpoint: Some("https://acme.example".to_string()),
                    profile: PeerProfile::Router,
                    trust_tier: TrustTier::Org,
                    status: PeerStatus::Active,
                    scopes: ScopePreset::Member.expand(),
                    auth_credential_ref: None,
                },
                now,
            )
            .unwrap();
        let peer_keys = NodeIdentityKeys::generate().unwrap();
        let manifest_payload = hyp_proto::manifest::NodeManifestPayload {
            v: 1,
            node_id: hyp_proto::address::NodeId::new("acme-team").unwrap(),
            profile: hyp_proto::manifest::NodeProfile::Router,
            hyphae_version: "2.2.0".to_string(),
            protocol_range: hyp_proto::manifest::ProtocolRange { min: 1, max: 2 },
            manifest_version: 1,
            issued_at: "2026-11-24T00:00:00Z".to_string(),
            expires_at: "2027-11-24T00:00:00Z".to_string(),
            audience: "v1@workstation".to_string(),
            identity: hyp_proto::manifest::ManifestIdentity {
                signing_jwk: hyp_proto::manifest::OkpJwk::new(
                    hyp_proto::manifest::OkpCurve::Ed25519,
                    &peer_keys.signing.public_key_bytes(),
                ),
                encryption_jwk: hyp_proto::manifest::OkpJwk::new(
                    hyp_proto::manifest::OkpCurve::X25519,
                    &peer_keys.encryption.public_key_bytes(),
                ),
                kid: peer_keys.kid(),
                admin_jwk: None,
            },
            capabilities: vec![
                hyp_proto::manifest::CapabilityToken::ManifestV1,
                hyp_proto::manifest::CapabilityToken::DmV1,
                hyp_proto::manifest::CapabilityToken::DmE2eeV1,
                hyp_proto::manifest::CapabilityToken::ChannelV1,
                hyp_proto::manifest::CapabilityToken::ChannelE2eeV1,
                hyp_proto::manifest::CapabilityToken::EventsV1,
                hyp_proto::manifest::CapabilityToken::SubPushdownV1,
                hyp_proto::manifest::CapabilityToken::KvV1,
                hyp_proto::manifest::CapabilityToken::KvE2eeV1,
                hyp_proto::manifest::CapabilityToken::TransferStreamV2,
            ],
            policy: hyp_proto::manifest::ManifestPolicy {
                require_pairing: true,
                require_e2ee: true,
                max_text_bytes: 32 * 1024,
                max_transfer_bytes: 50 * 1024 * 1024,
            },
            advertised: hyp_proto::manifest::AdvertisedResources::default(),
            escalation: None,
        };
        let caps: Vec<String> = manifest_payload
            .capabilities
            .iter()
            .map(|c| c.as_str().to_string())
            .collect();
        db.peers()
            .cache_manifest(
                "acme-team",
                &hyp_store::ManifestCacheUpdate {
                    manifest_version: 1,
                    manifest_json: serde_json::to_string(&manifest_payload).unwrap(),
                    etag: None,
                    capabilities: caps,
                    accept_downgrade: false,
                },
                now,
            )
            .unwrap();
        db.local()
            .put_in_mailbox(
                &hyp_store::MailboxInsert {
                    session_id: "claude:v1-sess".to_string(),
                    origin_node: "acme-team".to_string(),
                    item_id: "v1-msg-001".to_string(),
                    text: "PRESERVED_V1_MAILBOX_MESSAGE".to_string(),
                    kind: hyp_store::MailboxKind::Message,
                    source: "bob@laptop/bob".to_string(),
                    gate_state: hyp_store::GateState::Pending,
                    gate_reason: None,
                    traceparent: None,
                },
                now,
            )
            .unwrap();

        // Roll schema strictly back to frozen v0.2.0 schema v1 (`0001_initial_v2.sql` shape),
        // dropping v7 (`human_delegation_policies`, `peers.admitted_*`), v5 (`human_authorities.enc_jwk_json`),
        // v4 (`human_*`), v3 (`wakeups`), and v2.
        db.connection()
            .execute_batch(
                "DROP INDEX IF EXISTS peers_admitted_by_human;
                 DROP TABLE IF EXISTS human_delegation_policies;
                 ALTER TABLE peers DROP COLUMN admitted_by_human_id;
                 ALTER TABLE peers DROP COLUMN admitted_auth_epoch;
                 DROP INDEX IF EXISTS human_authorities_kid;
                 DROP INDEX IF EXISTS human_claim_nonces_expires;
                 DROP TABLE IF EXISTS human_authorities;
                 DROP TABLE IF EXISTS human_claim_nonces;
                 DROP TABLE IF EXISTS human_node_certs;
                 ALTER TABLE mailbox DROP COLUMN human_auth_json;
                 DROP INDEX IF EXISTS mailbox_coalesce_pending;
                 DROP INDEX IF EXISTS mailbox_expires_pending;
                 DROP INDEX IF EXISTS wakeups_next_fire;
                 DROP INDEX IF EXISTS wakeups_owner_active;
                 DROP INDEX IF EXISTS wakeups_target_session;
                 DROP TABLE IF EXISTS wakeups;
                 ALTER TABLE mailbox DROP COLUMN coalesce_key;
                 ALTER TABLE mailbox DROP COLUMN expires_at;
                 ALTER TABLE mailbox DROP COLUMN missed_count;
                 DROP INDEX IF EXISTS peer_routes_via;
                 DROP TABLE IF EXISTS peer_routes;
                 ALTER TABLE handles DROP COLUMN description;
                 DELETE FROM schema_version WHERE version > 1;
                 PRAGMA wal_checkpoint(TRUNCATE);",
            )
            .expect("downgrade seeded DB to exact v1 schema");
        assert_eq!(db.schema_version().unwrap(), 1);
    }
    assert!(
        !state_dir.join("backups").exists(),
        "backups/ must not exist before v1->vN migration"
    );

    let expected_ver = hyp_store::CURRENT_SCHEMA_VERSION;

    // 2. Run compiled `hyp doctor --home <home> --json` -> upgrades v1 -> latest & creates backup!
    let doc_out = isolated_cmd(&home)
        .args(["doctor", "--home", home.to_str().unwrap(), "--json"])
        .output()
        .expect("run hyp doctor --json");
    assert_eq!(
        doc_out.status.code(),
        Some(0),
        "doctor failed: stdout={} stderr={}",
        String::from_utf8_lossy(&doc_out.stdout),
        String::from_utf8_lossy(&doc_out.stderr)
    );
    let doc_json = parse_json_stdout(&doc_out);
    assert_eq!(doc_json["ok"], true, "doctor JSON: {doc_json}");

    let storage = &doc_json["data"]["storage"];
    assert_eq!(
        storage["schemaVersion"], expected_ver,
        "storage report: {storage}"
    );
    assert_eq!(storage["supportedSchemaVersion"], expected_ver);
    assert_eq!(storage["appliedMigrations"], expected_ver);
    assert_eq!(storage["migrationBackups"]["count"], 1);
    let latest_backup = storage["migrationBackups"]["latest"]
        .as_str()
        .expect("latest backup path");
    let backup_path = Path::new(latest_backup);
    assert!(
        backup_path.exists(),
        "backup file must exist on disk at {}",
        backup_path.display()
    );
    let backup_name = backup_path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    let expected_backup_prefix = format!("node.sqlite.v1-to-v{expected_ver}-");
    assert!(
        backup_name.starts_with(&expected_backup_prefix) && backup_name.ends_with(".bak"),
        "unexpected backup filename: {backup_name} (expected prefix {expected_backup_prefix})"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(backup_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "pre-migration backup must enforce strictly 0600 permissions, got {:o}",
            mode
        );
    }

    // Verify `store.sqlite` check line in JSON and TTY presentation.
    let sqlite_check = doc_json["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "store.sqlite")
        .expect("store.sqlite check");
    assert_eq!(sqlite_check["status"], "ok");
    let check_detail = sqlite_check["detail"].as_str().unwrap();
    let expected_schema_tag = format!("node.sqlite schema v{expected_ver}");
    assert!(
        check_detail.contains(&expected_schema_tag)
            && check_detail.contains("1 pre-migration backup in backups/"),
        "unexpected store.sqlite check detail: {check_detail}"
    );

    let tty_out = isolated_cmd(&home)
        .args(["doctor", "--home", home.to_str().unwrap()])
        .output()
        .expect("run hyp doctor TTY");
    assert_eq!(tty_out.status.code(), Some(0));
    let tty_stdout = String::from_utf8_lossy(&tty_out.stdout);
    let expected_tty_line =
        format!("node.sqlite schema v{expected_ver} (1 pre-migration backup in backups/)");
    assert!(
        tty_stdout.contains(&expected_tty_line),
        "TTY doctor output must display schema version and backup summary:\n{tty_stdout}"
    );

    // 3. Verify all seeded v1 data survived the v1 -> latest upgrade intact!
    {
        let db = NodeDb::open(&db_path).expect("reopen upgraded DB");
        assert_eq!(db.schema_version().unwrap(), expected_ver);
        let peer = db
            .peers()
            .get_peer("acme-team")
            .unwrap()
            .expect("v1 peer preserved");
        assert_eq!(peer.endpoint.as_deref(), Some("https://acme.example"));
        let handles = db.messages().list_handles(Some("v1@workstation")).unwrap();
        assert_eq!(handles.len(), 1);
        assert_eq!(handles[0].address, "v1@workstation/legacy-agent");
        assert_eq!(handles[0].description, None);
        let inbox = db.local().peek_inbox("claude:v1-sess", 10).unwrap();
        assert_eq!(inbox.len(), 1);
        assert_eq!(inbox[0].text, "PRESERVED_V1_MAILBOX_MESSAGE");
    }

    // 4. Verify newer-schema downgrade protection surfaces a FAIL check + actionable next step!
    let future_home = tmp.path().join("future-home");
    let future_state = future_home.join(".config").join("hyphae");
    fs::create_dir_all(&future_state).unwrap();
    {
        let db = NodeDb::open(future_state.join("node.sqlite")).unwrap();
        db.connection()
            .execute_batch(
                "INSERT INTO schema_version (version, applied_at) VALUES (99, 1700000000000);",
            )
            .unwrap();
    }
    let future_out = isolated_cmd(&future_home)
        .args(["doctor", "--home", future_home.to_str().unwrap(), "--json"])
        .output()
        .expect("run hyp doctor on future schema");
    assert_eq!(future_out.status.code(), Some(1));
    let future_json = parse_json_stdout(&future_out);
    assert_eq!(future_json["ok"], false);
    assert_eq!(future_json["error"]["code"], "SCHEMA_TOO_NEW");
    let fail_check = future_json["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "store.sqlite")
        .expect("store.sqlite FAIL check");
    assert_eq!(fail_check["status"], "fail");
    let fix_str = fail_check["fix"].as_str().unwrap_or_default();
    assert!(
        fix_str.contains("hyp update") && fix_str.contains("backups/"),
        "downgrade FAIL check must include actionable hyp update / backups/ next step: {fail_check}"
    );
}

// ============================================================================
// 9. Zero-Flag Default-HOME E2E Regression (`hyp onboard` -> `hyp daemon` ->
//    `hyp hook` -> `hyp mcp` -> `hyp wait`, ZERO `--socket` / `--state-dir`!)
// ============================================================================

#[test]
fn zero_flag_default_home_onboard_daemon_mcp_hook_wait_roundtrip() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("default-home");
    fs::create_dir_all(&home).unwrap();

    // 1. `hyp onboard --json` with ZERO `--state-dir` / `--config` / `--home` flags
    let onboard_out = isolated_cmd(&home)
        .args(["onboard", "--json"])
        .stdin(Stdio::null())
        .output()
        .expect("run hyp onboard --json");
    assert_eq!(
        onboard_out.status.code(),
        Some(0),
        "hyp onboard failed: stdout={} stderr={}",
        String::from_utf8_lossy(&onboard_out.stdout),
        String::from_utf8_lossy(&onboard_out.stderr)
    );
    let onboard_json = parse_json_stdout(&onboard_out);
    assert_eq!(onboard_json["ok"], true, "onboard JSON: {onboard_json}");
    let expected_cfg_dir = home.join(".config").join("hyphae");
    assert!(expected_cfg_dir.join("node.json").exists());
    assert!(expected_cfg_dir.join("node.sqlite").exists());

    // 2. Spawn `hyp daemon --json` with ZERO `--socket` / `--state-dir` / `--config` flags
    let mut daemon_cmd = isolated_cmd(&home);
    daemon_cmd.args(["daemon", "--json"]).stdin(Stdio::null());
    let mut daemon_proc = ManagedProcess::spawn("zero-flag hyp daemon", &mut daemon_cmd);
    let startup = daemon_proc.read_json_line(STARTUP_TIMEOUT);
    assert_eq!(startup["ok"], true, "zero-flag daemon startup: {startup}");
    let node_id = startup["data"]["nodeId"]
        .as_str()
        .expect("nodeId")
        .to_string();
    let expected_sock = expected_cfg_dir.join(hyp_harness::sock::DEFAULT_SOCKET_FILENAME);
    let actual_sock = PathBuf::from(startup["data"]["socketPath"].as_str().unwrap());
    assert_eq!(
        actual_sock,
        expected_sock,
        "hyp daemon default socket must live at ~/.config/hyphae/{}",
        hyp_harness::sock::DEFAULT_SOCKET_FILENAME
    );
    assert!(actual_sock.exists(), "default daemon socket must exist");

    // Helper: invoke `hyp hook claude <event>` with ZERO `--socket` flag!
    let run_zero_flag_hook = |event: &str, payload: Value| -> Value {
        let mut proc = isolated_cmd(&home)
            .args(["hook", "claude", event])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn zero-flag hyp hook");
        proc.stdin
            .take()
            .unwrap()
            .write_all(payload.to_string().as_bytes())
            .unwrap();
        let out = proc.wait_with_output().unwrap();
        assert_eq!(
            out.status.code(),
            Some(0),
            "zero-flag hyp hook claude {event} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        parse_json_stdout(&out)
    };

    // 3. `hyp hook claude session-start` (ZERO `--socket`)
    for sess in ["zero-a", "zero-b"] {
        let ss = run_zero_flag_hook("session-start", json!({ "session_id": sess }));
        assert_eq!(ss, json!({}));
    }

    // 4. Spawn `hyp mcp` with ZERO socket argument!
    let mut mcp_cmd = isolated_cmd(&home);
    mcp_cmd.args(["mcp"]).stdin(Stdio::piped());
    let mut mcp_proc = ManagedProcess::spawn("zero-flag hyp mcp", &mut mcp_cmd);
    let mut mcp_stdin = mcp_proc.take_stdin().expect("mcp stdin");
    let mut next_rpc_id = 0u64;

    next_rpc_id += 1;
    writeln!(
        mcp_stdin,
        "{}",
        json!({
            "jsonrpc": "2.0",
            "id": next_rpc_id,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": { "name": "zero-flag-e2e", "version": "1" }
            }
        })
    )
    .expect("write mcp initialize");
    mcp_stdin.flush().expect("flush mcp stdin");
    let init_resp = mcp_proc.read_json_line(RPC_TIMEOUT);
    assert_eq!(init_resp["result"]["protocolVersion"], "2025-06-18");
    writeln!(
        mcp_stdin,
        "{}",
        json!({ "jsonrpc": "2.0", "method": "notifications/initialized" })
    )
    .unwrap();
    mcp_stdin.flush().unwrap();

    // Helper: zero-flag `hyp hook claude pre-tool-use` + zero-flag `hyp mcp` `tools/call`!
    let mut call_verified =
        |session_raw: &str, tool_name: &str, arguments: Value| -> (String, bool) {
            next_rpc_id += 1;
            let id = next_rpc_id;
            let call_id = format!("toolu_zero_{session_raw}_{id}");
            let pre = run_zero_flag_hook(
                "pre-tool-use",
                json!({
                    "session_id": session_raw,
                    "tool_use_id": call_id,
                    "tool_name": format!("mcp__hyphae__{tool_name}"),
                    "tool_input": arguments
                }),
            );
            assert_eq!(pre, json!({}));
            writeln!(
                mcp_stdin,
                "{}",
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "method": "tools/call",
                    "params": {
                        "name": tool_name,
                        "arguments": arguments,
                        "_meta": { "claudecode/toolUseId": call_id }
                    }
                })
            )
            .expect("write mcp tools/call");
            mcp_stdin.flush().expect("flush mcp stdin");
            let resp = mcp_proc.read_json_line(RPC_TIMEOUT);
            let result = &resp["result"];
            let text = result["content"][0]["text"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            let is_error = result["isError"].as_bool() == Some(true);
            (text, is_error)
        };

    // Join `alpha` and `beta` via zero-flag `hyp mcp` + zero-flag `hyp hook`!
    let (ja_txt, ja_err) = call_verified(
        "zero-a",
        "hyp_mesh",
        json!({ "action": "join", "handle": "alpha", "description": "Zero-flag sender" }),
    );
    assert!(!ja_err, "zero-flag join alpha failed: {ja_txt}");
    assert!(ja_txt.contains(&format!("{node_id}/alpha")), "{ja_txt}");

    let (jb_txt, jb_err) = call_verified(
        "zero-b",
        "hyp_mesh",
        json!({ "action": "join", "handle": "beta", "description": "Zero-flag receiver" }),
    );
    assert!(!jb_err, "zero-flag join beta failed: {jb_txt}");
    assert!(jb_txt.contains(&format!("{node_id}/beta")), "{jb_txt}");

    // 5. Send DM #1 (`alpha` -> `beta`): `post-tool-use` holds Queue mid-turn cleanly,
    //    and zero-flag `user-prompt-submit` (TurnStart) drains DM #1 from default daemon socket!
    let dm1 = "ZERO_FLAG_HOOK_DELIVERY_SENTINEL_111";
    let (s1_txt, s1_err) = call_verified(
        "zero-a",
        "hyp_send",
        json!({ "to": format!("{node_id}/beta"), "text": dm1 }),
    );
    assert!(!s1_err, "zero-flag hyp_send #1 failed: {s1_txt}");

    let mid_out = run_zero_flag_hook(
        "post-tool-use",
        json!({
            "session_id": "zero-b",
            "tool_name": "Bash",
            "tool_use_id": "tu-zero-drain-1"
        }),
    );
    assert_eq!(
        mid_out,
        json!({}),
        "zero-flag post-tool-use must hold Queue DM until turn boundary: {mid_out}"
    );

    let pre_turn_out = run_zero_flag_hook("user-prompt-submit", json!({ "session_id": "zero-b" }));
    let drained_ctx = pre_turn_out["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap_or_default();
    assert!(
        drained_ctx.contains("<hyphae-inbox ")
            && drained_ctx.contains(&format!("<dm from=\"{node_id}/alpha\" count=\"1\"/>")),
        "zero-flag user-prompt-submit must emit metadata-only XML digest for DM #1: {pre_turn_out}"
    );
    assert!(
        !drained_ctx.contains(dm1),
        "RFC 0004: user-prompt-submit must NEVER expose raw DM #1 body: {pre_turn_out}"
    );
    let (inbox1_txt, inbox1_err) = call_verified("zero-b", "hyp_inbox", json!({}));
    assert!(!inbox1_err, "zero-flag hyp_inbox #1 failed: {inbox1_txt}");
    assert!(
        inbox1_txt.contains(dm1),
        "zero-flag hyp_inbox #1 must return and ack DM #1: {inbox1_txt}"
    );

    // 6. Spawn `hyp wait` with ZERO `--socket` flag and wake it via DM #2!
    let dm2 = "ZERO_FLAG_WAIT_WAKEUP_SENTINEL_222";
    let mut wait_cmd = isolated_cmd(&home);
    wait_cmd
        .args([
            "wait",
            "--session",
            "claude:zero-b",
            "--timeout",
            "15",
            "--json",
        ])
        .stdin(Stdio::null());
    let mut wait_proc = ManagedProcess::spawn("zero-flag hyp wait", &mut wait_cmd);
    wait_for_session_live(&actual_sock, "claude:zero-b", Duration::from_secs(5));

    let (s2_txt, s2_err) = call_verified(
        "zero-a",
        "hyp_send",
        json!({ "to": format!("{node_id}/beta"), "text": dm2 }),
    );
    assert!(!s2_err, "zero-flag hyp_send #2 failed: {s2_txt}");

    let (wait_status, wait_json) = wait_proc.wait_json_output(Duration::from_secs(12));
    assert_eq!(wait_status.code(), Some(0));
    assert_eq!(
        wait_json["ok"], true,
        "zero-flag hyp wait JSON: {wait_json}"
    );
    let wait_items = wait_json["data"]["items"].as_array().unwrap();
    let wait_txt = wait_items[0]["text"].as_str().unwrap_or_default();
    assert!(
        wait_txt.contains("<hyphae-inbox ")
            && wait_txt.contains(&format!("<dm from=\"{node_id}/alpha\" count=\"1\"/>")),
        "zero-flag hyp wait must emit metadata-only XML digest for DM #2: {wait_json}"
    );
    assert!(
        !wait_txt.contains(dm2),
        "RFC 0004: zero-flag hyp wait must NEVER expose raw DM #2 body: {wait_json}"
    );
    let (inbox2_txt, inbox2_err) = call_verified("zero-b", "hyp_inbox", json!({}));
    assert!(!inbox2_err, "zero-flag hyp_inbox #2 failed: {inbox2_txt}");
    assert!(
        inbox2_txt.contains(dm2),
        "zero-flag hyp_inbox #2 must return and ack DM #2: {inbox2_txt}"
    );

    drop(mcp_stdin);
    assert_eq!(
        mcp_proc
            .wait_timeout(Duration::from_secs(5))
            .and_then(|s| s.code()),
        Some(0)
    );
    let _ = daemon_proc.shutdown_gracefully();
}
