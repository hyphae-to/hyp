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
use hyp_crypto::e2ee::{DmContext, seal_dm};
use hyp_crypto::keys::{Ed25519KeyPair, NodeIdentityKeys, X25519KeyPair};
use hyp_crypto::keystore::{SecretBackend, SecretStore, legacy_connector_key_secret_names};
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
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{Value, json};
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
    let alice_status_file: Value = serde_json::from_str(
        &fs::read_to_string(alice_state.join("node.status.json")).unwrap(),
    )
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
    assert!(a_join.contains("alice@macbook/alice"), "alice join: {a_join}");

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
    assert_eq!(dm_res_val["encrypted"], true, "DM must be E2EE: {dm_res_val}");
    assert_eq!(dm_res_val["routedVia"], "acme-team");

    let (dm_wait_status, dm_wait_json) = bob_wait_dm.wait_json_output(Duration::from_secs(15));
    assert_eq!(dm_wait_status.code(), Some(0));
    assert_eq!(dm_wait_json["ok"], true);
    let dm_items = dm_wait_json["data"]["items"].as_array().unwrap();
    assert!(
        dm_items
            .iter()
            .any(|i| i["text"].as_str().unwrap_or_default().contains(dm_secret)),
        "Bob's live hyp wait must receive decrypted DM plaintext: {dm_wait_json}"
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
    assert!(
        ch_items
            .iter()
            .any(|i| i["text"].as_str().unwrap_or_default().contains(chan_secret)),
        "Bob's live hyp wait must receive decrypted #eng channel message: {ch_wait_json}"
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
    assert_eq!(hub_startup["ok"], true, "public node startup: {hub_startup}");
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
        joined_text.contains("public.hyphae.to.github"),
        "woken wait digest missing public.hyphae.to.github topic: {wait_json}"
    );
    assert_eq!(
        items[0]["notifyOnly"], true,
        "Guest trust tier stream should be Stage-1 downgraded to notifyOnly digest: {wait_json}"
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

    let gate_init = isolated_cmd(&home)
        .args([
            "gate",
            "init",
            "--adapter",
            "http-classifier",
            "--base-url",
            "http://127.0.0.1:1/classify",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--lock",
            "--json",
        ])
        .output()
        .expect("run hyp gate init --lock");
    assert_eq!(gate_init.status.code(), Some(0));
    let init_json = parse_json_stdout(&gate_init);
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
    let mut blocked_wait = ManagedProcess::spawn("sec hyp wait (locked down)", &mut blocked_wait_cmd);
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
        let resp = client.request(req).await.expect("POST /v1/messages to ext-hub");
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
    assert_eq!(q_item["originNode"], "ext-hub");
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

    let relock_out = isolated_cmd(&home)
        .args([
            "gate",
            "lock",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(relock_out.status.code(), Some(0));
    assert_eq!(parse_json_stdout(&relock_out)["data"]["gatePolicySig"], "OK");

    let approve_out = isolated_cmd(&home)
        .args([
            "inbox",
            "approve",
            &receipt,
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(approve_out.status.code(), Some(0));
    let approve_json = parse_json_stdout(&approve_out);
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
    assert!(
        delivered_items.iter().any(|i| {
            let txt = i["text"].as_str().unwrap_or_default();
            txt.contains(head_marker) && txt.contains(tail_secret)
        }),
        "approved message must deliver cleanly in full: {aw_json}"
    );

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
    assert!(sock.exists(), "local IPC socket must exist at {}", sock.display());

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
    assert_eq!(parse_json_stdout(&trav)["error"]["code"], "INVALID_SECRET_NAME");

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
    assert_eq!(parse_json_stdout(&empty_out)["error"]["code"], "EMPTY_SECRET");

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
    assert_eq!(&*store.get("foo").expect("read stored foo secret"), foo_secret);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let loc = web_json["data"]["location"].as_str().expect("secret file path");
        let mode = fs::metadata(loc).expect("stat secret file").permissions().mode() & 0o777;
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
        assert_eq!(ttl_out.status.code(), Some(2), "expected exit 2 for {bad_ttl}");
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
    assert_eq!(parse_json_stdout(&mallory_del)["error"]["code"], "UNAUTHORIZED");

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
