//! Full end-to-end tests for turnkey `public.hyphae.to` runtime:
//! - Compiled `hyp` binary (`hyp deploy init public-node` -> `hyp node start`)
//! - Self-service `hyp pair join <url>` (`POST /v1/guest/pair` -> `guest-ro` enrollment)
//! - Live demand-driven `GitHubPublicAdapter` ETag polling (`200` -> `304 Not Modified`),
//!   shared deduplicated poller across multiple enrolled laptops, live SSE `/v1/inbox` delivery,
//!   grace-window teardown to `activePollers == 0`, and clean `SIGTERM` shutdown
//! - Fail-closed security invariants: `403 not_granted` on DM/unconfined subscriptions,
//!   `422 subscription_rejected` on private/404 repos, `409 peer_key_mismatch` anti-hijack,
//!   `429 rate_limited` burst guard, `404` when disabled, and `POST /v1/webhooks/github-app`
//!   HMAC-SHA256 verification.
//!
//! 100% isolated (`HYPHAE_SECRET_BACKEND=file`, `tempfile::TempDir`, `127.0.0.1:0`, zero external calls).

use std::fs;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use http::header::{AUTHORIZATION, CONTENT_TYPE};
use http::{HeaderMap, Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyp_crypto::keys::NodeIdentityKeys;
use hyp_crypto::keystore::{SecretBackend, SecretStore};
use hyp_crypto::rfc3339::{format_rfc3339_millis, now_unix_ms};
use hyp_node::adapters::{
    GitHubPublicAdapter, GitHubPublicConfig, compute_hmac_sha256_header,
};
use hyp_node::engine::http_util::SseParser;
use hyp_node::engine::{
    GuestPairRequest, GuestPairingConfig, NodeConfig, UnifiedNode, guest_pair_proof_canonical,
};
use hyp_proto::address::NodeId;
use hyp_proto::manifest::SignedNodeManifest;
use hyp_store::{AckOutcome, DueBatch};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

fn hyp_bin() -> &'static str {
    env!("CARGO_BIN_EXE_hyp")
}

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }

    fn take(&mut self) -> Option<Child> {
        self.0.take()
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.0.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

// ============================================================================
// In-Process Mock GitHub REST API Server (`127.0.0.1:0`)
// ============================================================================

struct MockGitHubState {
    events_200: AtomicU64,
    events_304: AtomicU64,
}

struct MockGitHubServer {
    addr: SocketAddr,
    state: Arc<MockGitHubState>,
    shutdown_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

impl MockGitHubServer {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock github listener");
        let addr = listener.local_addr().expect("mock github local_addr");
        let state = Arc::new(MockGitHubState {
            events_200: AtomicU64::new(0),
            events_304: AtomicU64::new(0),
        });
        let bg_state = Arc::clone(&state);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
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

        Self {
            addr,
            state,
            shutdown_tx: Some(shutdown_tx),
        }
    }

    fn base_url(&self) -> String {
        format!("http://{}", self.addr)
    }
}

impl Drop for MockGitHubServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
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
            if repo == "acme/open" || repo.starts_with("acme/pub-") {
                if if_none_match.as_deref() == Some("\"gh-e1\"") {
                    state.events_304.fetch_add(1, Ordering::SeqCst);
                    return Ok(Response::builder()
                        .status(StatusCode::NOT_MODIFIED)
                        .header(header::ETAG, "\"gh-e1\"")
                        .header("x-poll-interval", "1")
                        .header("x-ratelimit-remaining", "59")
                        .body(Full::new(Bytes::new()))
                        .unwrap());
                }

                state.events_200.fetch_add(1, Ordering::SeqCst);
                let events = json!([
                    {
                        "id": "gh-evt-42001",
                        "type": "PullRequestEvent",
                        "actor": { "login": "octocat", "type": "User" },
                        "repo": { "name": repo },
                        "payload": {
                            "action": "opened",
                            "number": 42,
                            "pull_request": {
                                "number": 42,
                                "title": "Wire live public.hyphae.to runtime",
                                "html_url": format!("https://github.com/{repo}/pull/42"),
                                "state": "open",
                                "draft": false,
                                "user": { "login": "octocat", "type": "User" },
                                "head": { "ref": "feat/public-node" },
                                "base": { "ref": "main" },
                                "labels": [{ "name": "enhancement" }]
                            }
                        },
                        "created_at": "2026-11-24T16:50:00Z"
                    }
                ]);
                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "application/json")
                    .header(header::ETAG, "\"gh-e1\"")
                    .header("x-poll-interval", "1")
                    .header("x-ratelimit-remaining", "59")
                    .body(Full::new(Bytes::from(events.to_string())))
                    .unwrap());
            }

            return Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header(CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(r#"{"message":"Not Found"}"#)))
                .unwrap());
        }

        // Repo visibility endpoint: GET /repos/{owner}/{repo}
        let repo = rest.to_ascii_lowercase();
        let (status, body) = match repo.as_str() {
            "acme/open" | "acme/pub-1" | "acme/pub-2" | "acme/pub-3" => (
                StatusCode::OK,
                json!({
                    "full_name": repo,
                    "private": false,
                    "visibility": "public"
                }),
            ),
            "acme/private-repo" => (
                StatusCode::OK,
                json!({
                    "full_name": "acme/private-repo",
                    "private": true,
                    "visibility": "private"
                }),
            ),
            _ => (StatusCode::NOT_FOUND, json!({ "message": "Not Found" })),
        };
        return Ok(Response::builder()
            .status(status)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap());
    }

    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::new()))
        .unwrap())
}

// ============================================================================
// HTTP & Ed25519 Peer Auth Client Helpers
// ============================================================================

type FullClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Full<Bytes>>;
type EmptyClient = Client<hyper_rustls::HttpsConnector<HttpConnector>, Empty<Bytes>>;

fn make_full_client() -> FullClient {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let connector = HttpsConnectorBuilder::new()
        .with_provider_and_webpki_roots(rustls::crypto::ring::default_provider())
        .expect("tls provider")
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    Client::builder(TokioExecutor::new()).build(connector)
}

fn make_empty_client() -> EmptyClient {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let connector = HttpsConnectorBuilder::new()
        .with_provider_and_webpki_roots(rustls::crypto::ring::default_provider())
        .expect("tls provider")
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    Client::builder(TokioExecutor::new()).build(connector)
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

async fn send_json_request(
    client: &FullClient,
    base_url: &str,
    method: Method,
    path_and_query: &str,
    body: Option<Value>,
    auth: Option<(&str, &NodeIdentityKeys)>,
    extra_headers: &[(&str, &str)],
) -> (StatusCode, HeaderMap, Value) {
    let raw_bytes = match body {
        Some(v) => serde_json::to_vec(&v).unwrap(),
        None => Vec::new(),
    };
    let uri = format!("{base_url}{path_and_query}");
    let mut builder = Request::builder().method(method.clone()).uri(&uri);
    if !raw_bytes.is_empty() {
        builder = builder.header(CONTENT_TYPE, "application/json");
    }
    if let Some((node_id, keys)) = auth {
        let header_val = ed25519_auth_header(node_id, keys, method.as_str(), path_and_query, &raw_bytes);
        builder = builder.header(AUTHORIZATION, header_val);
    }
    for &(k, v) in extra_headers {
        builder = builder.header(k, v);
    }
    let req = builder.body(Full::new(Bytes::from(raw_bytes))).unwrap();
    let resp = client.request(req).await.expect("HTTP request failed");
    let status = resp.status();
    let headers = resp.headers().clone();
    let collected = resp.into_body().collect().await.unwrap().to_bytes();
    let json_val = if collected.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&collected)
            .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&collected) }))
    };
    (status, headers, json_val)
}

fn build_signed_guest_pair_request(
    hub_node_id: &str,
    guest_node_id: &str,
    keys: &NodeIdentityKeys,
    timestamp: String,
) -> GuestPairRequest {
    let ed25519_jwk = keys.signing_jwk();
    let x25519_jwk = keys.encryption_jwk();
    let canonical = guest_pair_proof_canonical(
        hub_node_id,
        guest_node_id,
        &ed25519_jwk,
        &x25519_jwk,
        &timestamp,
    )
    .unwrap();
    let proof_sig = keys
        .signing
        .sign_domain_b64("guest-pair", canonical.as_bytes());
    GuestPairRequest {
        node_id: guest_node_id.to_string(),
        ed25519_jwk,
        x25519_jwk,
        timestamp,
        proof_sig,
    }
}

// ============================================================================
// E2E Test 1: Full Turnkey `public.hyphae.to` Subprocess Flow
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn public_node_turnkey_deploy_join_live_github_stream_and_confinement() {
    let mock_gh = MockGitHubServer::start().await;
    let tmp = tempfile::tempdir().unwrap();
    let kit_dir = tmp.path().join("kit");
    let hub_state = tmp.path().join("hub-state");
    let laptop1_state = tmp.path().join("laptop1-state");
    let laptop2_state = tmp.path().join("laptop2-state");
    fs::create_dir_all(&hub_state).unwrap();

    // 1. Run `hyp deploy init public-node` to generate the real turnkey kit!
    let init_out = Command::new(hyp_bin())
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
        .env("HYPHAE_SECRET_BACKEND", "file")
        .output()
        .expect("run hyp deploy init public-node");
    assert_eq!(
        init_out.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&init_out.stdout),
        String::from_utf8_lossy(&init_out.stderr)
    );
    let init_env: Value = serde_json::from_slice(&init_out.stdout).unwrap();
    assert_eq!(init_env["ok"], true);

    // Adjust generated `node.json` for isolated loopback test runtime.
    let node_json_path = kit_dir.join("node.json");
    let mut node_cfg_json: Value =
        serde_json::from_str(&fs::read_to_string(&node_json_path).unwrap()).unwrap();
    node_cfg_json["stateDir"] = json!(hub_state.to_str().unwrap());
    node_cfg_json["sources"][0]["apiBaseUrl"] = json!(mock_gh.base_url());
    node_cfg_json["sources"][0]["minPollIntervalSeconds"] = json!(1);
    node_cfg_json["sources"][0]["graceWindowSeconds"] = json!(1);
    fs::write(
        &node_json_path,
        serde_json::to_string_pretty(&node_cfg_json).unwrap(),
    )
    .unwrap();

    // 2. Spawn the real compiled `hyp` binary serving `public.hyphae.to`!
    let mut child = Command::new(hyp_bin())
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
        .env("HYPHAE_SECRET_BACKEND", "file")
        .env("HOME", &hub_state)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn compiled hyp node start");

    let mut startup_line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut startup_line)
        .expect("read startup JSON line");
    let mut guard = ChildGuard::new(child);

    let startup_env: Value = serde_json::from_str(startup_line.trim())
        .unwrap_or_else(|e| panic!("invalid startup JSON '{startup_line}': {e}"));
    assert_eq!(startup_env["ok"], true);
    assert_eq!(startup_env["data"]["nodeId"], "public.hyphae.to");
    assert_eq!(startup_env["data"]["guestPairingEnabled"], true);
    assert_eq!(startup_env["data"]["githubPublicEnabled"], true);
    let hub_url = startup_env["data"]["endpoint"].as_str().unwrap().to_string();
    let hub_pid = startup_env["data"]["pid"].as_u64().unwrap();
    // Missing optional github-public-token emits a concise warning instead of failing startup!
    assert!(
        startup_env["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap_or("").contains("github-public-token")),
        "expected warning about optional github-public-token, got {:?}",
        startup_env["warnings"]
    );

    let client = make_full_client();

    // Verify unauthenticated GET /v1/health
    let (health_status, _, health_json) =
        send_json_request(&client, &hub_url, Method::GET, "/v1/health", None, None, &[]).await;
    assert_eq!(health_status, StatusCode::OK);
    assert_eq!(health_json["ok"], true);
    assert_eq!(health_json["nodeId"], "public.hyphae.to");
    assert_eq!(health_json["profile"], "router");
    assert_eq!(health_json["guestPairingEnabled"], true);
    assert_eq!(health_json["githubPublic"]["enabled"], true);
    assert_eq!(health_json["githubPublic"]["activePollers"], 0);

    // Verify `hyp deploy check --url` passes (unauthenticated /v1/manifest anti-recon + Ed25519 sig!)
    let check_out = Command::new(hyp_bin())
        .args([
            "deploy",
            "check",
            "--url",
            &hub_url,
            "--config",
            node_json_path.to_str().unwrap(),
            "--json",
        ])
        .env("HYPHAE_SECRET_BACKEND", "file")
        .output()
        .expect("run hyp deploy check");
    assert_eq!(
        check_out.status.code(),
        Some(0),
        "deploy check failed: {}",
        String::from_utf8_lossy(&check_out.stdout)
    );
    let check_env: Value = serde_json::from_slice(&check_out.stdout).unwrap();
    assert_eq!(check_env["ok"], true);
    assert_eq!(check_env["data"]["manifest"]["advertisedEmpty"], true);
    assert_eq!(check_env["data"]["manifest"]["signatureVerified"], true);

    // 3. Run `hyp pair join` from developer laptop 1 (`dev@laptop`)!
    let join1_out = Command::new(hyp_bin())
        .args([
            "pair",
            "join",
            &hub_url,
            "--state-dir",
            laptop1_state.to_str().unwrap(),
            "--node-id",
            "dev@laptop",
            "--json",
        ])
        .env("HYPHAE_SECRET_BACKEND", "file")
        .env("HOME", &laptop1_state)
        .output()
        .expect("run hyp pair join laptop 1");
    assert_eq!(
        join1_out.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&join1_out.stdout),
        String::from_utf8_lossy(&join1_out.stderr)
    );
    let join1_env: Value = serde_json::from_slice(&join1_out.stdout).unwrap();
    assert_eq!(join1_env["ok"], true);
    assert_eq!(join1_env["data"]["enrolled"], true);
    assert_eq!(join1_env["data"]["preset"], "guest-ro");
    assert_eq!(join1_env["data"]["peerId"], "public.hyphae.to");
    assert_eq!(join1_env["data"]["nodeId"], "dev@laptop");
    assert_eq!(join1_env["data"]["manifestVerified"], true);

    // Idempotent re-join with the SAME Ed25519 key succeeds!
    let rejoin1_out = Command::new(hyp_bin())
        .args([
            "pair",
            "join",
            &hub_url,
            "--state-dir",
            laptop1_state.to_str().unwrap(),
            "--node-id",
            "dev@laptop",
            "--json",
        ])
        .env("HYPHAE_SECRET_BACKEND", "file")
        .env("HOME", &laptop1_state)
        .output()
        .expect("re-run hyp pair join laptop 1");
    assert_eq!(rejoin1_out.status.code(), Some(0));
    let rejoin1_env: Value = serde_json::from_slice(&rejoin1_out.stdout).unwrap();
    assert_eq!(rejoin1_env["data"]["enrolled"], true);

    // Load laptop 1's persistent Ed25519/X25519 keys from SecretStore.
    let laptop1_keys = SecretStore::new(&laptop1_state, SecretBackend::File)
        .load_or_create_node_keys("dev@laptop")
        .expect("load laptop 1 keys");

    // Authenticated GET /v1/manifest as dev@laptop advertises the `github` topic!
    let (auth_man_status, _, auth_man_val) = send_json_request(
        &client,
        &hub_url,
        Method::GET,
        "/v1/manifest",
        None,
        Some(("dev@laptop", &laptop1_keys)),
        &[],
    )
    .await;
    assert_eq!(auth_man_status, StatusCode::OK);
    let signed_man: SignedNodeManifest = serde_json::from_value(auth_man_val).unwrap();
    let man_payload = signed_man.decode_payload().unwrap();
    assert_eq!(man_payload.audience, "dev@laptop");
    assert!(
        man_payload
            .advertised
            .topics
            .iter()
            .any(|t| t.topic == "github"),
        "expected authenticated manifest to advertise 'github' topic, got {:?}",
        man_payload.advertised.topics
    );

    // 4a. Fail-closed DM rejection: `POST /v1/messages` -> 403 not_granted!
    let (dm_status, _, dm_body) = send_json_request(
        &client,
        &hub_url,
        Method::POST,
        "/v1/messages",
        Some(json!({
            "id": "dm-blocked-1",
            "fromHandle": "dev",
            "to": "other@box/agent",
            "text": "should be denied"
        })),
        Some(("dev@laptop", &laptop1_keys)),
        &[],
    )
    .await;
    assert_eq!(dm_status, StatusCode::FORBIDDEN, "DM body: {dm_body}");
    assert_eq!(dm_body["error"], "not_granted");

    // 4b. Fail-closed missing `exact.repo` filter -> 403 not_granted!
    let (unconfined_status, _, unconfined_body) = send_json_request(
        &client,
        &hub_url,
        Method::PUT,
        "/v1/subscriptions",
        Some(json!({
            "subscriptions": [{
                "id": "sub-unconfined",
                "topic": "github",
                "filters": [],
                "coalesceSeconds": 0,
                "mode": "full"
            }]
        })),
        Some(("dev@laptop", &laptop1_keys)),
        &[],
    )
    .await;
    assert_eq!(
        unconfined_status,
        StatusCode::FORBIDDEN,
        "unconfined body: {unconfined_body}"
    );
    assert_eq!(unconfined_body["error"], "not_granted");

    // 4c. Fail-closed 404 / private GitHub repo rejection -> 422 subscription_rejected!
    for bad_repo in ["acme/secret", "acme/private-repo"] {
        let (sub_bad_status, _, sub_bad_body) = send_json_request(
            &client,
            &hub_url,
            Method::PUT,
            "/v1/subscriptions",
            Some(json!({
                "subscriptions": [{
                    "id": "sub-bad",
                    "topic": "github",
                    "filters": [{ "exact": { "repo": bad_repo } }],
                    "coalesceSeconds": 0,
                    "mode": "full"
                }]
            })),
            Some(("dev@laptop", &laptop1_keys)),
            &[],
        )
        .await;
        assert_eq!(
            sub_bad_status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "expected 422 for {bad_repo}, got {sub_bad_status}: {sub_bad_body}"
        );
        assert_eq!(
            sub_bad_body["type"],
            "https://hyphae.to/problems/subscription-rejected"
        );
        assert_eq!(sub_bad_body["code"], "subscription_rejected");
        assert_eq!(sub_bad_body["error"], "subscription_rejected");
        assert!(
            !sub_bad_body["diagnostics"].as_array().unwrap().is_empty(),
            "expected non-empty diagnostics for {bad_repo}"
        );
    }

    // Confirm no invalid subscriptions were persisted!
    let (list_status, _, list_body) = send_json_request(
        &client,
        &hub_url,
        Method::GET,
        "/v1/subscriptions",
        None,
        Some(("dev@laptop", &laptop1_keys)),
        &[],
    )
    .await;
    assert_eq!(list_status, StatusCode::OK);
    assert_eq!(list_body["subscriptions"].as_array().unwrap().len(), 0);

    // 4d. Open live `GET /v1/inbox` SSE stream as `dev@laptop`!
    let sse_client = make_empty_client();
    let sse_auth = ed25519_auth_header("dev@laptop", &laptop1_keys, "GET", "/v1/inbox", b"");
    let sse_req = Request::builder()
        .method(Method::GET)
        .uri(format!("{hub_url}/v1/inbox"))
        .header(AUTHORIZATION, sse_auth)
        .header(header::ACCEPT, "text/event-stream")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let sse_resp = sse_client
        .request(sse_req)
        .await
        .expect("connect SSE /v1/inbox");
    assert_eq!(sse_resp.status(), StatusCode::OK);
    let mut sse_body = sse_resp.into_body();

    // 4e. Subscribe `dev@laptop` to public `acme/open` (`coalesceSeconds: 0`) -> 200 OK!
    let (sub_ok_status, _, sub_ok_body) = send_json_request(
        &client,
        &hub_url,
        Method::PUT,
        "/v1/subscriptions",
        Some(json!({
            "subscriptions": [{
                "id": "sub-open",
                "topic": "github",
                "filters": [{ "exact": { "repo": "acme/open" } }],
                "coalesceSeconds": 0,
                "mode": "full"
            }]
        })),
        Some(("dev@laptop", &laptop1_keys)),
        &[],
    )
    .await;
    assert_eq!(sub_ok_status, StatusCode::OK, "sub body: {sub_ok_body}");
    assert_eq!(sub_ok_body["subscriptions"].as_array().unwrap().len(), 1);

    // Receive live `com.github.pull_request.opened` CloudEvent over SSE `/v1/inbox`!
    let delivered_batch: DueBatch = tokio::time::timeout(Duration::from_secs(8), async {
        let mut parser = SseParser::new();
        while let Some(frame_res) = sse_body.frame().await {
            let frame = frame_res.expect("SSE frame error");
            if let Some(data) = frame.data_ref() {
                for ev in parser.feed(data) {
                    if ev.event.as_deref() == Some("batch") {
                        return serde_json::from_str::<DueBatch>(&ev.data)
                            .expect("valid DueBatch JSON");
                    }
                }
            }
        }
        panic!("SSE stream closed before delivering GitHub batch");
    })
    .await
    .expect("timed out waiting for live GitHub CloudEvent batch on SSE /v1/inbox");

    assert_eq!(delivered_batch.topic, "github");
    assert_eq!(delivered_batch.events.len(), 1);
    let ce = &delivered_batch.events[0];
    assert_eq!(ce.event_type, "com.github.pull_request.opened");
    assert_eq!(ce.id, "gh-evt-42001");
    assert_eq!(
        ce.extensions.get("repo").map(String::as_str),
        Some("acme/open")
    );

    // Ack delivered batch cleanly.
    let (ack_status, _, ack_body) = send_json_request(
        &client,
        &hub_url,
        Method::POST,
        "/v1/inbox/ack",
        Some(json!({
            "kind": "batch",
            "id": delivered_batch.id,
            "outcome": AckOutcome::Delivered
        })),
        Some(("dev@laptop", &laptop1_keys)),
        &[],
    )
    .await;
    assert_eq!(ack_status, StatusCode::OK, "ack body: {ack_body}");
    assert_eq!(ack_body["acked"], true);

    // 4f. Verify subsequent polls hit `304 Not Modified` (`polls304 >= 1`) on `GET /v1/health`!
    let deadline = Instant::now() + Duration::from_secs(6);
    let mut observed_304 = false;
    while Instant::now() < deadline {
        let (_, _, h) =
            send_json_request(&client, &hub_url, Method::GET, "/v1/health", None, None, &[]).await;
        if h["githubPublic"]["polls304"].as_u64().unwrap_or(0) >= 1 {
            assert_eq!(h["githubPublic"]["activePollers"], 1);
            assert!(h["githubPublic"]["polls200"].as_u64().unwrap_or(0) >= 1);
            observed_304 = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        observed_304,
        "expected polls304 >= 1 on /v1/health (mock 200={}, 304={})",
        mock_gh.state.events_200.load(Ordering::SeqCst),
        mock_gh.state.events_304.load(Ordering::SeqCst)
    );

    // 4g. Enroll 2nd laptop (`dev2@laptop`) and subscribe to the SAME `acme/open` -> still 1 poller!
    let join2_out = Command::new(hyp_bin())
        .args([
            "pair",
            "join",
            &hub_url,
            "--state-dir",
            laptop2_state.to_str().unwrap(),
            "--node-id",
            "dev2@laptop",
            "--json",
        ])
        .env("HYPHAE_SECRET_BACKEND", "file")
        .env("HOME", &laptop2_state)
        .output()
        .expect("run hyp pair join laptop 2");
    assert_eq!(join2_out.status.code(), Some(0));
    let join2_env: Value = serde_json::from_slice(&join2_out.stdout).unwrap();
    assert_eq!(join2_env["data"]["enrolled"], true);
    assert_eq!(join2_env["data"]["preset"], "guest-ro");

    let laptop2_keys = SecretStore::new(&laptop2_state, SecretBackend::File)
        .load_or_create_node_keys("dev2@laptop")
        .expect("load laptop 2 keys");

    let (sub2_status, _, _) = send_json_request(
        &client,
        &hub_url,
        Method::PUT,
        "/v1/subscriptions",
        Some(json!({
            "subscriptions": [{
                "id": "sub-open-2",
                "topic": "github",
                "filters": [{ "exact": { "repo": "acme/open" } }],
                "coalesceSeconds": 0,
                "mode": "full"
            }]
        })),
        Some(("dev2@laptop", &laptop2_keys)),
        &[],
    )
    .await;
    assert_eq!(sub2_status, StatusCode::OK);

    let (_, _, health_shared) =
        send_json_request(&client, &hub_url, Method::GET, "/v1/health", None, None, &[]).await;
    assert_eq!(
        health_shared["githubPublic"]["activePollers"], 1,
        "2nd subscriber to same repo MUST share the exact same deduplicated ETag poller"
    );

    // 4h. Anti-hijack protection: different keypair trying to claim `dev@laptop` MUST fail closed!
    let attacker_keys = NodeIdentityKeys::generate().unwrap();
    let hijack_req = build_signed_guest_pair_request(
        "public.hyphae.to",
        "dev@laptop",
        &attacker_keys,
        format_rfc3339_millis(now_unix_ms()),
    );
    let (hijack_status, _, hijack_body) = send_json_request(
        &client,
        &hub_url,
        Method::POST,
        "/v1/guest/pair",
        Some(serde_json::to_value(&hijack_req).unwrap()),
        None,
        &[],
    )
    .await;
    assert!(
        hijack_status == StatusCode::CONFLICT || hijack_status == StatusCode::FORBIDDEN,
        "expected 409/403 on key hijack, got {hijack_status}: {hijack_body}"
    );
    assert_eq!(hijack_body["error"], "peer_key_mismatch");

    // Verify original `dev@laptop` key STILL authenticates cleanly (never overwritten!).
    let (verify_orig_status, _, verify_orig_body) = send_json_request(
        &client,
        &hub_url,
        Method::GET,
        "/v1/subscriptions",
        None,
        Some(("dev@laptop", &laptop1_keys)),
        &[],
    )
    .await;
    assert_eq!(verify_orig_status, StatusCode::OK);
    assert_eq!(verify_orig_body["subscriptions"].as_array().unwrap().len(), 1);

    // 4i. Unsubscribe BOTH laptops and verify clean teardown (`activePollers == 0`)!
    let (del1_status, _, del1_body) = send_json_request(
        &client,
        &hub_url,
        Method::DELETE,
        "/v1/subscriptions?id=sub-open",
        None,
        Some(("dev@laptop", &laptop1_keys)),
        &[],
    )
    .await;
    assert_eq!(del1_status, StatusCode::OK);
    assert_eq!(del1_body["deleted"], true);

    // Still 1 poller while laptop 2 remains subscribed!
    let (_, _, health_mid) =
        send_json_request(&client, &hub_url, Method::GET, "/v1/health", None, None, &[]).await;
    assert_eq!(health_mid["githubPublic"]["activePollers"], 1);

    let (del2_status, _, del2_body) = send_json_request(
        &client,
        &hub_url,
        Method::DELETE,
        "/v1/subscriptions?id=sub-open-2",
        None,
        Some(("dev2@laptop", &laptop2_keys)),
        &[],
    )
    .await;
    assert_eq!(del2_status, StatusCode::OK);
    assert_eq!(del2_body["deleted"], true);

    // Grace window is 1s; wait up to 4s for refcount==0 teardown!
    let teardown_deadline = Instant::now() + Duration::from_secs(4);
    let mut torn_down = false;
    while Instant::now() < teardown_deadline {
        let (_, _, h) =
            send_json_request(&client, &hub_url, Method::GET, "/v1/health", None, None, &[]).await;
        if h["githubPublic"]["activePollers"] == 0 {
            torn_down = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    assert!(torn_down, "expected activePollers == 0 after grace window teardown");

    // Drop SSE stream before shutdown.
    drop(sse_body);

    // 4j. Graceful `SIGTERM` shutdown of compiled `hyp` process!
    let mut child = guard.take().expect("child still running");
    #[cfg(unix)]
    {
        let kill_status = Command::new("kill")
            .args(["-TERM", &hub_pid.to_string()])
            .status()
            .expect("send SIGTERM");
        assert!(kill_status.success());
        let exit_status = child.wait().expect("wait for graceful exit");
        assert_eq!(exit_status.code(), Some(0), "expected clean exit code 0 on SIGTERM");
    }
    #[cfg(not(unix))]
    {
        let _ = hub_pid;
        let _ = child.kill();
        let _ = child.wait();
    }

    assert!(!hub_state.join("node.pid").exists(), "node.pid should be cleaned up");
    assert!(
        !hub_state.join("node.status.json").exists(),
        "node.status.json should be cleaned up"
    );
}

// ============================================================================
// E2E Test 2: Mutated-Valid Security Checks (404 Disabled, 429 Rate Limit,
//             Cumulative Guest Repo Cap, GitHub App Webhook 404/401/200)
// ============================================================================

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn guest_pair_disabled_rate_limit_cumulative_repo_cap_and_github_app_webhook() {
    let mock_gh = MockGitHubServer::start().await;
    let client = make_full_client();

    // 1. Default `UnifiedNode` has `guest_pairing.enabled == false` -> 404 on `/v1/guest/pair`
    //    and 404 on `/v1/webhooks/github-app`!
    let disabled_dir = tempfile::tempdir().unwrap();
    let mut disabled_cfg = NodeConfig::router(
        NodeId::new("private.local").unwrap(),
        disabled_dir.path(),
    );
    disabled_cfg.secret_backend = Some(SecretBackend::File);
    let disabled_node = UnifiedNode::open(disabled_cfg).unwrap();
    let (disabled_addr, disabled_srv) = Arc::clone(&disabled_node)
        .serve("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let disabled_url = format!("http://{disabled_addr}");

    let probe_keys = NodeIdentityKeys::generate().unwrap();
    let probe_req = build_signed_guest_pair_request(
        "private.local",
        "guest@box",
        &probe_keys,
        format_rfc3339_millis(now_unix_ms()),
    );
    let (st_404, _, _) = send_json_request(
        &client,
        &disabled_url,
        Method::POST,
        "/v1/guest/pair",
        Some(serde_json::to_value(&probe_req).unwrap()),
        None,
        &[],
    )
    .await;
    assert_eq!(st_404, StatusCode::NOT_FOUND);

    let (wh_404, _, _) = send_json_request(
        &client,
        &disabled_url,
        Method::POST,
        "/v1/webhooks/github-app",
        Some(json!({})),
        None,
        &[],
    )
    .await;
    assert_eq!(wh_404, StatusCode::NOT_FOUND);

    disabled_node.shutdown();
    disabled_srv.abort();

    // 2. Hardened public hub with `max_repos_per_guest: 2`, `max_joins_per_minute: 2`,
    //    and GitHub App webhook secret configured!
    let pub_dir = tempfile::tempdir().unwrap();
    let mut pub_cfg = NodeConfig::router(
        NodeId::new("pub-sec.local").unwrap(),
        pub_dir.path(),
    );
    pub_cfg.secret_backend = Some(SecretBackend::File);
    pub_cfg.guest_pairing = GuestPairingConfig {
        enabled: true,
        scopes: vec![
            "stream:subscribe=github[require=exact.repo;maxValues=2;maxBatchesPerHour=60]"
                .to_string(),
        ],
        max_repos_per_guest: 2,
        max_batches_per_hour: 60,
        max_joins_per_minute: 3,
    };
    let pub_node = UnifiedNode::open(pub_cfg).unwrap();
    let app_secret = "gh-app-super-secret-2026";
    let wh_store = SecretStore::new(pub_dir.path(), SecretBackend::File);
    wh_store
        .set("github-app-webhook-secret", app_secret)
        .unwrap();
    let app_secret_val = wh_store.get("github-app-webhook-secret").unwrap();
    let adapter = Arc::new(
        GitHubPublicAdapter::new(GitHubPublicConfig {
            api_base_url: mock_gh.base_url(),
            min_poll_interval: Duration::from_secs(60),
            base_poll_interval: Duration::from_secs(60),
            teardown_grace: Duration::ZERO,
            app_webhook_secret: Some(app_secret_val),
            ..GitHubPublicConfig::default()
        })
        .unwrap(),
    );
    adapter.register_app_installation("acme/open").await.unwrap();
    pub_node.attach_github_public(Arc::clone(&adapter)).await.unwrap();

    let (pub_addr, pub_srv) = Arc::clone(&pub_node)
        .serve("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();
    let pub_url = format!("http://{pub_addr}");

    // 2a. Valid guest enrollment -> 200 OK
    let guest_keys = NodeIdentityKeys::generate().unwrap();
    let good_req = build_signed_guest_pair_request(
        "pub-sec.local",
        "alice@guest",
        &guest_keys,
        format_rfc3339_millis(now_unix_ms()),
    );
    let (ok1, _, _) = send_json_request(
        &client,
        &pub_url,
        Method::POST,
        "/v1/guest/pair",
        Some(serde_json::to_value(&good_req).unwrap()),
        None,
        &[],
    )
    .await;
    assert_eq!(ok1, StatusCode::OK);

    // 2b. Mutated invalid proofSig -> 401
    let mut bad_sig_req = build_signed_guest_pair_request(
        "pub-sec.local",
        "badsig@guest",
        &NodeIdentityKeys::generate().unwrap(),
        format_rfc3339_millis(now_unix_ms()),
    );
    bad_sig_req.proof_sig = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
    let (st_badsig, _, _) = send_json_request(
        &client,
        &pub_url,
        Method::POST,
        "/v1/guest/pair",
        Some(serde_json::to_value(&bad_sig_req).unwrap()),
        None,
        &[],
    )
    .await;
    assert_eq!(st_badsig, StatusCode::UNAUTHORIZED);

    // 2c. Expired timestamp (>5 min skew) -> 401
    let expired_keys = NodeIdentityKeys::generate().unwrap();
    let expired_req = build_signed_guest_pair_request(
        "pub-sec.local",
        "stale@guest",
        &expired_keys,
        format_rfc3339_millis(now_unix_ms() - 10 * 60 * 1000),
    );
    let (st_expired, _, _) = send_json_request(
        &client,
        &pub_url,
        Method::POST,
        "/v1/guest/pair",
        Some(serde_json::to_value(&expired_req).unwrap()),
        None,
        &[],
    )
    .await;
    assert_eq!(st_expired, StatusCode::UNAUTHORIZED);

    // 2d. 4th request within the 1-minute window exceeds `max_joins_per_minute: 3` -> 429 rate_limited!
    let burst_keys = NodeIdentityKeys::generate().unwrap();
    let burst_req = build_signed_guest_pair_request(
        "pub-sec.local",
        "burst@guest",
        &burst_keys,
        format_rfc3339_millis(now_unix_ms()),
    );
    let (st_429, hdr_429, body_429) = send_json_request(
        &client,
        &pub_url,
        Method::POST,
        "/v1/guest/pair",
        Some(serde_json::to_value(&burst_req).unwrap()),
        None,
        &[],
    )
    .await;
    assert_eq!(st_429, StatusCode::TOO_MANY_REQUESTS, "body: {body_429}");
    assert_eq!(body_429["error"], "rate_limited");
    assert!(hdr_429.contains_key(header::RETRY_AFTER));

    // 2d. Cumulative `max_repos_per_guest: 2` across SEPARATE PUT calls!
    let (s1, _, _) = send_json_request(
        &client,
        &pub_url,
        Method::PUT,
        "/v1/subscriptions",
        Some(json!({
            "subscriptions": [{
                "id": "sub-1",
                "topic": "github",
                "filters": [{ "exact": { "repo": "acme/pub-1" } }],
                "coalesceSeconds": 0,
                "mode": "full"
            }]
        })),
        Some(("alice@guest", &guest_keys)),
        &[],
    )
    .await;
    assert_eq!(s1, StatusCode::OK);

    let (s2, _, _) = send_json_request(
        &client,
        &pub_url,
        Method::PUT,
        "/v1/subscriptions",
        Some(json!({
            "subscriptions": [{
                "id": "sub-2",
                "topic": "github",
                "filters": [{ "exact": { "repo": "acme/pub-2" } }],
                "coalesceSeconds": 0,
                "mode": "full"
            }]
        })),
        Some(("alice@guest", &guest_keys)),
        &[],
    )
    .await;
    assert_eq!(s2, StatusCode::OK);

    // 3rd distinct repo in a separate subscription ID MUST be denied fail-closed (`403 not_granted`)!
    let (s3, _, b3) = send_json_request(
        &client,
        &pub_url,
        Method::PUT,
        "/v1/subscriptions",
        Some(json!({
            "subscriptions": [{
                "id": "sub-3",
                "topic": "github",
                "filters": [{ "exact": { "repo": "acme/pub-3" } }],
                "coalesceSeconds": 0,
                "mode": "full"
            }]
        })),
        Some(("alice@guest", &guest_keys)),
        &[],
    )
    .await;
    assert_eq!(s3, StatusCode::FORBIDDEN, "expected 403 on 3rd repo: {b3}");
    assert_eq!(b3["error"], "not_granted");

    // 2e. `POST /v1/webhooks/github-app`: bad HMAC -> 401; valid HMAC -> 200 published!
    let wh_payload = json!({
        "action": "opened",
        "number": 77,
        "repository": { "full_name": "acme/open" },
        "sender": { "login": "octocat", "type": "User" },
        "issue": {
            "number": 77,
            "title": "Sub-second App push works",
            "html_url": "https://github.com/acme/open/issues/77",
            "state": "open",
            "user": { "login": "octocat", "type": "User" },
            "labels": []
        }
    });
    let wh_bytes = serde_json::to_vec(&wh_payload).unwrap();
    let valid_sig = compute_hmac_sha256_header(app_secret.as_bytes(), &wh_bytes);
    let mut bad_sig = valid_sig.clone();
    let last_ch = if bad_sig.ends_with('0') { '1' } else { '0' };
    bad_sig.pop();
    bad_sig.push(last_ch);

    let (bad_wh_status, _, _) = send_json_request(
        &client,
        &pub_url,
        Method::POST,
        "/v1/webhooks/github-app",
        Some(wh_payload.clone()),
        None,
        &[
            ("x-hub-signature-256", &bad_sig),
            ("x-github-event", "issues"),
            ("x-github-delivery", "app-deliv-1"),
        ],
    )
    .await;
    assert_eq!(bad_wh_status, StatusCode::UNAUTHORIZED);

    let (ok_wh_status, _, ok_wh_body) = send_json_request(
        &client,
        &pub_url,
        Method::POST,
        "/v1/webhooks/github-app",
        Some(wh_payload),
        None,
        &[
            ("x-hub-signature-256", &valid_sig),
            ("x-github-event", "issues"),
            ("x-github-delivery", "app-deliv-1"),
        ],
    )
    .await;
    assert_eq!(ok_wh_status, StatusCode::OK, "webhook body: {ok_wh_body}");
    assert_eq!(ok_wh_body["ok"], true);
    assert_eq!(ok_wh_body["status"], "published");

    let (_, _, h) =
        send_json_request(&client, &pub_url, Method::GET, "/v1/health", None, None, &[]).await;
    assert_eq!(h["githubPublic"]["appWebhooksPublished"], 1);

    pub_node.shutdown_adapters().await;
    pub_node.shutdown();
    pub_srv.abort();
}
