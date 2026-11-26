//! End-to-end tests for Hyphae v2 adapters (`public.hyphae.to` `github-public`,
//! unified fd-3 `SubprocessSupervisor` v1 + JSON-RPC 2.0 v2, and native Rust webhook
//! adapters with HMAC mutation and McKeeman differential schema parity checks).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Request, Response, StatusCode, header};
use http_body_util::Full;
use hyp_crypto::keystore::{SecretBackend, SecretStore};
use hyp_node::adapters::{
    AdapterError, AdapterHealth, AdapterKind, BoxFuture, CompiledSubscription,
    GitHubNormalizeOutcome, GitHubPublicAdapter, GitHubPublicConfig, GitHubWebhookAdapter,
    GitHubWebhookConfig, NodeAdapter, NodeAdapterHost, PublishOutcome, PublishStatus,
    WebhookIngestOutcome, compute_hmac_sha256_header, normalize_github_api_event,
    normalize_github_webhook,
};
use hyp_proto::cloudevent::CloudEvent;
use hyp_proto::filter::{DiagnosticCode, DiagnosticSeverity, Filter, matches_filters};
use hyp_proto::rpc::EventKeyRef;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use zeroize::Zeroizing;

// ============================================================================
// Shared Recording Host & Fanout Bus
// ============================================================================

#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Debug, Clone)]
struct DeliveryFailureRecord {
    adapter_id: String,
    target: String,
    events: Vec<EventKeyRef>,
    reason: String,
}

#[derive(Default)]
struct RecordingHost {
    events: Mutex<Vec<(String, CloudEvent)>>,
    statuses: Mutex<Vec<(String, AdapterHealth)>>,
    delivery_failures: Mutex<Vec<DeliveryFailureRecord>>,
    subscribers: Mutex<Vec<CompiledSubscription>>,
}

impl RecordingHost {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    async fn set_subscribers(&self, subs: Vec<CompiledSubscription>) {
        *self.subscribers.lock().await = subs;
    }

    async fn events(&self) -> Vec<(String, CloudEvent)> {
        self.events.lock().await.clone()
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    async fn delivery_failures(&self) -> Vec<DeliveryFailureRecord> {
        self.delivery_failures.lock().await.clone()
    }
}

impl NodeAdapterHost for RecordingHost {
    fn publish_event<'a>(
        &'a self,
        topic: &'a str,
        event: CloudEvent,
    ) -> BoxFuture<'a, Result<PublishOutcome, AdapterError>> {
        Box::pin(async move {
            let subs = self.subscribers.lock().await.clone();
            let matched = subs
                .iter()
                .filter(|s| s.topic == topic && matches_filters(&s.filters, &event))
                .count();

            let mut evs = self.events.lock().await;
            let is_dup = evs.iter().any(|(t, existing)| {
                t == topic && existing.id == event.id && existing.source == event.source
            });
            let status = if is_dup {
                PublishStatus::Duplicate
            } else {
                evs.push((topic.to_string(), event));
                PublishStatus::Stored
            };
            Ok(PublishOutcome { status, matched })
        })
    }

    fn update_status<'a>(
        &'a self,
        adapter_id: &'a str,
        health: AdapterHealth,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.statuses
                .lock()
                .await
                .push((adapter_id.to_string(), health));
        })
    }

    fn report_delivery_failed<'a>(
        &'a self,
        adapter_id: &'a str,
        target: &'a str,
        events: Vec<EventKeyRef>,
        reason: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            self.delivery_failures
                .lock()
                .await
                .push(DeliveryFailureRecord {
                    adapter_id: adapter_id.to_string(),
                    target: target.to_string(),
                    events,
                    reason: reason.to_string(),
                });
        })
    }
}

fn exact_repo_filter(repo: &str) -> Filter {
    Filter::Exact(BTreeMap::from([("repo".to_string(), repo.to_string())]))
}

// ============================================================================
// Local `hyper` Mock GitHub REST API Server (`127.0.0.1:0`)
// ============================================================================

#[derive(Debug, Clone)]
struct RecordedPoll {
    repo: String,
    if_none_match: Option<String>,
    status: u16,
}

#[derive(Default)]
struct MockGitHubState {
    repo_meta_hits: Mutex<BTreeMap<String, usize>>,
    last_auth_header: Mutex<Option<String>>,
    polls: Mutex<Vec<RecordedPoll>>,
    poll_counter: AtomicU64,
    quota_remaining: AtomicU64,
    /// When true, the next poll on `anthropics/claude-code` returns a fresh PullRequestEvent.
    emit_resumed_event: Mutex<bool>,
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
            .expect("bind loopback mock GitHub");
        let addr = listener.local_addr().expect("local addr");
        let state = Arc::new(MockGitHubState {
            quota_remaining: AtomicU64::new(60),
            ..MockGitHubState::default()
        });
        let state_bg = Arc::clone(&state);
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accept = listener.accept() => {
                        let Ok((stream, _)) = accept else { break };
                        let st = Arc::clone(&state_bg);
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
        .map(ToString::to_string);
    if let Some(auth) = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
    {
        *state.last_auth_header.lock().await = Some(auth.to_string());
    }

    // Repo visibility metadata endpoint: GET /repos/{owner}/{repo}
    if let Some(rest) = path.strip_prefix("/repos/") {
        if !rest.ends_with("/events") {
            let repo_key = rest.to_ascii_lowercase();
            *state
                .repo_meta_hits
                .lock()
                .await
                .entry(repo_key.clone())
                .or_insert(0) += 1;

            let (status, body) = match repo_key.as_str() {
                "anthropics/claude-code" => (
                    StatusCode::OK,
                    json!({
                        "full_name": "anthropics/claude-code",
                        "private": false,
                        "visibility": "public"
                    }),
                ),
                "acme/secret" => (
                    StatusCode::OK,
                    json!({
                        "full_name": "acme/secret",
                        "private": true,
                        "visibility": "private"
                    }),
                ),
                _ => (StatusCode::NOT_FOUND, json!({ "message": "Not Found" })),
            };

            return Ok(Response::builder()
                .status(status)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Full::new(Bytes::from(body.to_string())))
                .unwrap());
        }
    }

    // Repo events endpoint: GET /repos/{owner}/{repo}/events
    if let Some(rest) = path
        .strip_prefix("/repos/")
        .and_then(|s| s.strip_suffix("/events"))
    {
        let repo = rest.to_ascii_lowercase();
        let n = state.poll_counter.fetch_add(1, Ordering::SeqCst) + 1;

        // Check if test requested a post-App-fallback event.
        let mut emit_resumed = state.emit_resumed_event.lock().await;
        if *emit_resumed {
            *emit_resumed = false;
            drop(emit_resumed);
            let rem = state.quota_remaining.fetch_sub(1, Ordering::SeqCst) - 1;
            state.polls.lock().await.push(RecordedPoll {
                repo: repo.clone(),
                if_none_match,
                status: 200,
            });
            let payload = json!([{
                "id": "evt-resumed-99",
                "type": "IssuesEvent",
                "repo": { "name": "anthropics/claude-code" },
                "actor": { "login": "carol", "type": "User" },
                "created_at": "2026-11-24T12:10:00Z",
                "payload": {
                    "action": "opened",
                    "issue": {
                        "number": 99,
                        "title": "Polling resumed after App uninstall",
                        "html_url": "https://github.com/anthropics/claude-code/issues/99",
                        "state": "open",
                        "body": "ETag fallback works cleanly",
                        "labels": [{ "name": "ops" }],
                        "assignees": []
                    }
                }
            }]);
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ETAG, "\"etag-v3\"")
                .header("x-ratelimit-remaining", rem.to_string())
                .body(Full::new(Bytes::from(payload.to_string())))
                .unwrap());
        }
        drop(emit_resumed);

        // Deterministic ETag sequence:
        // Poll 1: 200 OK empty baseline with ETag "etag-v1" (consumes 1 quota: 60 -> 59)
        // Poll 2 (with If-None-Match: "etag-v1"): 304 Not Modified (0 quota consumed: stays 59!)
        // Poll 3 (with If-None-Match: "etag-v1"): 200 OK new PullRequestEvent with ETag "etag-v2" (59 -> 58)
        // Poll 4+ (with If-None-Match: "etag-v2"): 304 Not Modified (0 quota consumed: stays 58!)
        let resp = match n {
            1 => {
                let rem = state.quota_remaining.fetch_sub(1, Ordering::SeqCst) - 1;
                state.polls.lock().await.push(RecordedPoll {
                    repo,
                    if_none_match,
                    status: 200,
                });
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ETAG, "\"etag-v1\"")
                    .header("x-ratelimit-remaining", rem.to_string())
                    .body(Full::new(Bytes::from("[]")))
                    .unwrap()
            }
            2 if if_none_match.as_deref() == Some("\"etag-v1\"") => {
                // 304 Not Modified MUST consume 0 quota!
                let rem = state.quota_remaining.load(Ordering::SeqCst);
                state.polls.lock().await.push(RecordedPoll {
                    repo,
                    if_none_match,
                    status: 304,
                });
                Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .header(header::ETAG, "\"etag-v1\"")
                    .header("x-ratelimit-remaining", rem.to_string())
                    .body(Full::new(Bytes::new()))
                    .unwrap()
            }
            3 => {
                let rem = state.quota_remaining.fetch_sub(1, Ordering::SeqCst) - 1;
                state.polls.lock().await.push(RecordedPoll {
                    repo,
                    if_none_match,
                    status: 200,
                });
                let payload = json!([{
                    "id": "evt-pr-42",
                    "type": "PullRequestEvent",
                    "repo": { "name": "anthropics/claude-code" },
                    "actor": { "login": "alice", "type": "User" },
                    "created_at": "2026-11-24T12:00:00Z",
                    "payload": {
                        "action": "opened",
                        "number": 42,
                        "pull_request": {
                            "number": 42,
                            "title": "Add Rust v2 unified adapters",
                            "html_url": "https://github.com/anthropics/claude-code/pull/42",
                            "state": "open",
                            "draft": false,
                            "body": "Ping agent:reviewer for a quick check",
                            "labels": [{ "name": "rust" }, { "name": "v2" }],
                            "assignees": [{ "login": "bob" }],
                            "head": { "ref": "feat/adapters", "sha": "deadbeef1234" },
                            "base": { "ref": "main" }
                        }
                    }
                }]);
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .header(header::ETAG, "\"etag-v2\"")
                    .header("x-ratelimit-remaining", rem.to_string())
                    .body(Full::new(Bytes::from(payload.to_string())))
                    .unwrap()
            }
            _ => {
                let rem = state.quota_remaining.load(Ordering::SeqCst);
                state.polls.lock().await.push(RecordedPoll {
                    repo,
                    if_none_match,
                    status: 304,
                });
                Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .header(header::ETAG, "\"etag-v2\"")
                    .header("x-ratelimit-remaining", rem.to_string())
                    .body(Full::new(Bytes::new()))
                    .unwrap()
            }
        };

        return Ok(resp);
    }

    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::from("not found")))
        .unwrap())
}

// ============================================================================
// 1. `public.hyphae.to` End-to-End Test (50 Subscribers -> 1 Poller, ETag 304,
//    Private/404 Fail-Closed Lint, GitHub App <1s Upgrade & Fallback, Teardown)
// ============================================================================

#[tokio::test]
async fn public_hyphae_github_public_e2e_etag_50_subs_app_upgrade_and_teardown() {
    let mock = MockGitHubServer::start().await;
    let host = RecordingHost::new();
    let app_secret = "hyphae-public-app-webhook-secret";

    let cfg = GitHubPublicConfig {
        id: "github-public".to_string(),
        topic: "github".to_string(),
        api_base_url: mock.base_url(),
        github_token: None,
        allow_private_with_token: false,
        user_agent: "hyphae-test/2.0".to_string(),
        repo_cache_ttl: Duration::from_secs(300),
        base_poll_interval: Duration::from_millis(25),
        min_poll_interval: Duration::from_millis(10),
        teardown_grace: Duration::from_millis(100),
        app_webhook_secret: Some(Zeroizing::new(app_secret.to_string())),
        http_timeout: Duration::from_secs(5),
        ..GitHubPublicConfig::default()
    };

    let adapter = GitHubPublicAdapter::new(cfg).expect("build GitHubPublicAdapter");
    assert_eq!(adapter.id(), "github-public");
    assert_eq!(adapter.kind(), AdapterKind::Source);
    adapter.start(host.clone()).await.expect("start adapter");
    assert_eq!(adapter.health(), AdapterHealth::Healthy);

    // --- Subscribe-time fail-closed validation ---
    // Public repo passes and is cached (5m TTL).
    let diag_pub = adapter
        .validate_subscription("github", &[exact_repo_filter("anthropics/claude-code")])
        .await;
    assert!(diag_pub.is_empty(), "public repo should pass: {diag_pub:?}");
    let diag_pub_cached = adapter
        .validate_subscription("github", &[exact_repo_filter("anthropics/claude-code")])
        .await;
    assert!(diag_pub_cached.is_empty());
    assert_eq!(
        mock.state
            .repo_meta_hits
            .lock()
            .await
            .get("anthropics/claude-code")
            .copied(),
        Some(1),
        "second validation should hit 5-minute TTL cache"
    );

    // Private repo fails closed with `repo_not_found_or_private` + `local.github-public` hint.
    let diag_private = adapter
        .validate_subscription("github", &[exact_repo_filter("acme/secret")])
        .await;
    assert_eq!(diag_private.len(), 1);
    assert_eq!(diag_private[0].severity, DiagnosticSeverity::Error);
    assert_eq!(diag_private[0].code, DiagnosticCode::RepoNotFoundOrPrivate);
    assert!(
        diag_private[0]
            .remediation
            .as_deref()
            .unwrap_or("")
            .contains("local.github-public"),
        "missing local.github-public remediation hint: {:?}",
        diag_private[0]
    );

    // 404 repo fails closed identically.
    let diag_missing = adapter
        .validate_subscription("github", &[exact_repo_filter("nope/missing")])
        .await;
    assert_eq!(diag_missing.len(), 1);
    assert_eq!(diag_missing[0].severity, DiagnosticSeverity::Error);
    assert_eq!(diag_missing[0].code, DiagnosticCode::RepoNotFoundOrPrivate);
    assert!(
        diag_missing[0]
            .remediation
            .as_deref()
            .unwrap_or("")
            .contains("local.github-public")
    );

    // Missing exact.repo or malformed slug fails closed.
    let diag_empty = adapter.validate_subscription("github", &[]).await;
    assert_eq!(diag_empty[0].severity, DiagnosticSeverity::Error);
    let diag_url = adapter
        .validate_subscription(
            "github",
            &[exact_repo_filter(
                "https://github.com/anthropics/claude-code",
            )],
        )
        .await;
    assert_eq!(diag_url[0].severity, DiagnosticSeverity::Error);

    // --- Local mode with token from SecretStore allows private repos ---
    let tmp = tempfile::tempdir().expect("tempdir");
    let store = SecretStore::new(tmp.path(), SecretBackend::File);
    store
        .set("github-token", "ghp_local_test_token_12345")
        .unwrap();
    let local_cfg = GitHubPublicConfig {
        api_base_url: mock.base_url(),
        allow_private_with_token: true,
        ..GitHubPublicConfig::default()
    }
    .with_token_from_store(&store, "github-token")
    .expect("load token from SecretStore");
    let local_adapter = GitHubPublicAdapter::new(local_cfg).unwrap();
    let diag_local_priv = local_adapter
        .validate_subscription("github", &[exact_repo_filter("acme/secret")])
        .await;
    assert!(
        diag_local_priv.is_empty(),
        "local.github-public with token should allow private repo: {diag_local_priv:?}"
    );
    assert_eq!(
        mock.state.last_auth_header.lock().await.as_deref(),
        Some("Bearer ghp_local_test_token_12345")
    );
    // 404 still fails closed even in local mode.
    let diag_local_404 = local_adapter
        .validate_subscription("github", &[exact_repo_filter("nope/missing")])
        .await;
    assert_eq!(
        diag_local_404[0].code,
        DiagnosticCode::RepoNotFoundOrPrivate
    );

    // --- Register 50 subscribers on `anthropics/claude-code` -> EXACTLY 1 ETag poller ---
    let mut subs: Vec<CompiledSubscription> = (0..50)
        .map(|i| CompiledSubscription {
            id: format!("sub-{i:02}"),
            subscriber: format!("laptop-{i:02}"),
            topic: "github".to_string(),
            filters: vec![exact_repo_filter("anthropics/claude-code")],
            coalesce_seconds: 15,
        })
        .collect();
    host.set_subscribers(subs.clone()).await;
    adapter.on_subscriptions_changed("github", &subs).await;

    let stats_initial = adapter.stats().await;
    assert_eq!(
        stats_initial.active_pollers, 1,
        "50 subs MUST share 1 poller"
    );
    assert_eq!(
        stats_initial.refcounts.get("anthropics/claude-code"),
        Some(&50)
    );

    // Wait until Poll 3 publishes the PullRequestEvent (`evt-pr-42`).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(4);
    loop {
        if !host.events().await.is_empty() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for ETag poller to publish PullRequestEvent; stats={:?}",
            adapter.stats().await
        );
        tokio::time::sleep(Duration::from_millis(15)).await;
    }

    // Verify ETag flow & 0-quota 304 behavior.
    let polls = mock.state.polls.lock().await.clone();
    assert!(polls.len() >= 3, "expected at least 3 polls, got {polls:?}");
    assert_eq!(polls[0].repo, "anthropics/claude-code");
    assert_eq!(polls[0].if_none_match, None);
    assert_eq!(polls[0].status, 200);
    assert_eq!(polls[1].if_none_match.as_deref(), Some("\"etag-v1\""));
    assert_eq!(polls[1].status, 304, "poll 2 must receive 304 Not Modified");
    assert_eq!(polls[2].if_none_match.as_deref(), Some("\"etag-v1\""));
    assert_eq!(polls[2].status, 200);
    // Quota started at 60: 2 x 200 consumed 2, 304s consumed 0 -> quota remaining must be 58!
    assert_eq!(
        mock.state.quota_remaining.load(Ordering::SeqCst),
        58,
        "304 Not Modified responses must consume 0 quota"
    );

    // Verify normalized CloudEvent published ONCE and matches all 50 subscribers (and 0 unrelated).
    let published = host.events().await;
    assert_eq!(published.len(), 1, "event must be published exactly once");
    let (topic, ev) = &published[0];
    assert_eq!(topic, "github");
    assert_eq!(ev.specversion, "1.0");
    assert_eq!(ev.id, "evt-pr-42");
    assert_eq!(ev.event_type, "com.github.pull_request.opened");
    assert_eq!(ev.source, "github.com/anthropics/claude-code");
    assert_eq!(ev.subject.as_deref(), Some("pull/42"));
    assert_eq!(
        ev.extensions.get("repo").and_then(Value::as_str),
        Some("anthropics/claude-code")
    );
    assert_eq!(
        ev.extensions.get("action").and_then(Value::as_str),
        Some("opened")
    );
    assert_eq!(
        ev.extensions.get("actor").and_then(Value::as_str),
        Some("alice")
    );
    let data = ev.data.as_ref().unwrap();
    assert_eq!(data["number"], 42);
    assert_eq!(data["branch"], "feat/adapters");
    assert_eq!(data["base"], "main");
    assert_eq!(data["mentions"], json!(["agent:reviewer"]));
    let fanout_matches = subs
        .iter()
        .filter(|s| matches_filters(&s.filters, ev))
        .count();
    assert_eq!(fanout_matches, 50, "all 50 subscribers must match fanout");
    assert!(
        !matches_filters(&[exact_repo_filter("other/repo")], ev),
        "unrelated repo subscriber must not match"
    );

    // --- Seamless <1s GitHub App Push Upgrade & Fallback ---
    adapter
        .register_app_installation("anthropics/claude-code")
        .await
        .expect("register app installation");
    assert_eq!(
        adapter.stats().await.active_pollers,
        0,
        "ETag polling must pause immediately when App is installed"
    );

    // Allow any in-flight poll to settle, then snapshot poll count and verify polling is paused.
    tokio::time::sleep(Duration::from_millis(40)).await;
    let polls_while_paused_before = mock.state.polls.lock().await.len();
    tokio::time::sleep(Duration::from_millis(90)).await;
    let polls_while_paused_after = mock.state.polls.lock().await.len();
    assert_eq!(
        polls_while_paused_before, polls_while_paused_after,
        "no ETag HTTP polls should fire while GitHub App is installed"
    );

    // Build an App webhook delivery payload.
    let app_body = serde_json::to_vec(&json!({
        "action": "synchronize",
        "repository": { "full_name": "anthropics/claude-code" },
        "sender": { "login": "bob", "type": "User" },
        "pull_request": {
            "number": 42,
            "title": "Add Rust v2 unified adapters",
            "html_url": "https://github.com/anthropics/claude-code/pull/42",
            "state": "open",
            "draft": false,
            "labels": [],
            "assignees": [],
            "head": { "ref": "feat/adapters", "sha": "cafebabe5678" },
            "base": { "ref": "main" }
        }
    }))
    .unwrap();
    let valid_sig = compute_hmac_sha256_header(app_secret.as_bytes(), &app_body);

    // Invalid HMAC (single-byte flip) MUST fail closed!
    let mut flipped_sig = valid_sig.clone().into_bytes();
    let last_idx = flipped_sig.len() - 1;
    flipped_sig[last_idx] = if flipped_sig[last_idx] == b'0' {
        b'1'
    } else {
        b'0'
    };
    let flipped_sig_str = String::from_utf8(flipped_sig).unwrap();

    let mut bad_headers = HeaderMap::new();
    bad_headers.insert(
        "x-hub-signature-256",
        HeaderValue::from_str(&flipped_sig_str).unwrap(),
    );
    bad_headers.insert("x-github-event", HeaderValue::from_static("pull_request"));
    bad_headers.insert("x-github-delivery", HeaderValue::from_static("app-deliv-1"));
    assert!(
        matches!(
            adapter.ingest_app_webhook(&bad_headers, &app_body).await,
            Err(AdapterError::Unauthorized(_))
        ),
        "flipped HMAC on GitHub App webhook must fail closed"
    );

    // Valid HMAC App webhook delivers immediately onto the exact same `github` topic!
    let mut good_headers = HeaderMap::new();
    good_headers.insert(
        "x-hub-signature-256",
        HeaderValue::from_str(&valid_sig).unwrap(),
    );
    good_headers.insert("x-github-event", HeaderValue::from_static("pull_request"));
    good_headers.insert("x-github-delivery", HeaderValue::from_static("app-deliv-1"));
    let app_outcome = adapter
        .ingest_app_webhook(&good_headers, &app_body)
        .await
        .expect("valid App webhook must succeed");
    assert!(matches!(
        app_outcome,
        WebhookIngestOutcome::Published {
            ref event_id,
            outcome: PublishOutcome {
                status: PublishStatus::Stored,
                matched: 50,
            }
        } if event_id == "app-deliv-1"
    ));

    // Duplicate delivery ID is deduplicated cleanly.
    let dup_outcome = adapter
        .ingest_app_webhook(&good_headers, &app_body)
        .await
        .expect("duplicate delivery should return Ignored");
    assert!(matches!(
        dup_outcome,
        WebhookIngestOutcome::Ignored { ref reason } if reason == "duplicate_event_id"
    ));

    // Uninstalling the GitHub App transparently resumes ETag polling!
    *mock.state.emit_resumed_event.lock().await = true;
    adapter
        .unregister_app_installation("anthropics/claude-code")
        .await
        .expect("unregister app installation");
    assert_eq!(adapter.stats().await.active_pollers, 1);

    let resume_deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        if host
            .events()
            .await
            .iter()
            .any(|(_, e)| e.id == "evt-resumed-99")
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < resume_deadline,
            "timed out waiting for ETag poller to resume after App uninstall"
        );
        tokio::time::sleep(Duration::from_millis(15)).await;
    }

    // --- Unsubscribe all 50 subscribers -> poller tears down cleanly after grace window ---
    subs.clear();
    host.set_subscribers(Vec::new()).await;
    adapter.on_subscriptions_changed("github", &subs).await;

    // Wait past the 100ms teardown grace window.
    tokio::time::sleep(Duration::from_millis(180)).await;
    assert_eq!(
        adapter.stats().await.active_pollers,
        0,
        "poller must tear down after grace window when refcount hits 0"
    );

    let polls_after_teardown = mock.state.polls.lock().await.len();
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert_eq!(
        mock.state.polls.lock().await.len(),
        polls_after_teardown,
        "zero HTTP requests may fire after poller teardown"
    );

    adapter.stop().await.expect("stop adapter");
    assert_eq!(adapter.health(), AdapterHealth::Stopped);
}

#[test]
fn differential_github_webhook_and_events_api_produce_identical_cloudevents() {
    let ts = "2026-11-24T12:00:00Z";
    let pr_obj = json!({
        "number": 77,
        "title": "Differential schema parity test",
        "html_url": "https://github.com/acme/core/pull/77",
        "state": "open",
        "draft": false,
        "body": "Body text",
        "labels": [{ "name": "ci" }],
        "assignees": [{ "login": "dana" }],
        "head": { "ref": "fix/diff", "sha": "abc123" },
        "base": { "ref": "main" }
    });

    let webhook_payload = json!({
        "action": "opened",
        "number": 77,
        "repository": { "full_name": "acme/core" },
        "sender": { "login": "dana", "type": "User" },
        "pull_request": pr_obj
    });
    let api_event = json!({
        "id": "same-event-id",
        "type": "PullRequestEvent",
        "repo": { "name": "acme/core" },
        "actor": { "login": "dana", "type": "User" },
        "created_at": ts,
        "payload": {
            "action": "opened",
            "number": 77,
            "pull_request": pr_obj
        }
    });

    let from_webhook =
        match normalize_github_webhook("pull_request", "same-event-id", &webhook_payload, ts) {
            GitHubNormalizeOutcome::Publish(ev) => *ev,
            GitHubNormalizeOutcome::Ignore(r) => panic!("unexpected ignore: {r}"),
        };
    let from_api =
        normalize_github_api_event("acme/core", &api_event).expect("API event should normalize");

    assert_eq!(
        from_webhook, from_api,
        "GitHubWebhookAdapter and GitHubPublicAdapter must emit identical CloudEvents v1.0"
    );
}

// ============================================================================
// 2. Unified fd-3 `SubprocessSupervisor` Real Child Process Tests (Unix)
// ============================================================================

#[cfg(unix)]
mod unix_supervisor_tests {
    use super::*;
    use hyp_node::adapters::{
        HelloMode, SubprocessConfig, SubprocessSupervisor, WireProtocol, build_isolated_env,
    };
    use hyp_proto::rpc::StatusParams;

    fn python_bin() -> &'static str {
        "python3"
    }

    #[tokio::test]
    async fn supervisor_legacy_v1_real_child_event_post_status_oversized_and_env_isolation() {
        let host = RecordingHost::new();

        // Real Python child speaking LEGACY fd-3 v1 over fd 3 socketpair (just like plugins/sdk/client.py!).
        let script = r#"
import json, os, signal, socket, sys

sock = socket.socket(fileno=3)
reader = sock.makefile("rb")

def send(obj):
    sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))

def recv():
    line = reader.readline()
    if not line:
        sys.exit(0)
    return json.loads(line.decode("utf-8"))

# 1. Wait for legacy v1 hello from supervisor (HelloMode::Auto grace fallback)
hello = recv()
assert hello["type"] == "hello" and hello["protocol"] == 1, f"bad hello: {hello}"

# 2. Verify environment allowlist: secret NOT leaked, HYPHAE_PROTOCOL=2 & explicit config present
leaked = os.environ.get("TOP_SECRET_HOST_TOKEN")
explicit = os.environ.get("PLUGIN_CUSTOM_MODE")
proto = os.environ.get("HYPHAE_PROTOCOL")
assert leaked is None, f"secret leaked into child: {leaked}"
assert explicit == "bridge-test", f"missing explicit env: {explicit}"
assert proto == "2", f"expected HYPHAE_PROTOCOL=2, got {proto}"

# 3. Publish a valid CloudEvent via legacy v1 `event` -> expect `ack`
send({
    "type": "event",
    "to": "ops",
    "event": {
        "specversion": "1.0",
        "id": "v1-msg-1",
        "source": "local/slack/ops",
        "type": "to.hyphae.bridge.slack",
        "datacontenttype": "application/json",
        "data": {"text": "hello from legacy v1"}
    }
})
ack = recv()
assert ack["type"] == "ack" and ack["id"] == "v1-msg-1" and ack["status"] == "stored", f"bad ack: {ack}"

# 4. Send legacy v1 `status` frame
send({
    "type": "status",
    "target": "ops",
    "pending": 3,
    "oldestAgeSeconds": 12,
    "t3Connected": True
})

# 5. Send >64 KiB oversized frame -> expect legacy v1 `nack` with `too_large`
sock.sendall((json.dumps({"type": "event", "to": "ops", "pad": "A" * 70000}) + "\n").encode("utf-8"))
nack = recv()
assert nack["type"] == "nack" and nack["error"] == "too_large", f"expected too_large nack: {nack}"

# 6. Loop awaiting inbound `request` (post) and replying with `response`
while True:
    msg = recv()
    if msg.get("type") == "request" and msg.get("method") == "post":
        send({
            "type": "response",
            "id": msg["id"],
            "ok": True,
            "result": {"proto": "v1", "target": msg["target"], "echo": msg["params"].get("text")}
        })
"#;

        let mut parent_env = std::env::vars().collect::<BTreeMap<_, _>>();
        parent_env.insert(
            "TOP_SECRET_HOST_TOKEN".to_string(),
            "sk-live-do-not-leak".to_string(),
        );

        let mut cfg = SubprocessConfig::new(
            "slack-v1",
            AdapterKind::Bridge,
            python_bin(),
            vec!["-u".to_string(), "-c".to_string(), script.to_string()],
            vec!["ops".to_string()],
        );
        cfg.env
            .insert("PLUGIN_CUSTOM_MODE".to_string(), "bridge-test".to_string());
        cfg.auto_hello_grace = Duration::from_millis(30);
        cfg.kill_timeout = Duration::from_millis(500);
        cfg.parent_env_override = Some(parent_env.clone());

        // Unit check `build_isolated_env` directly too.
        let iso = build_isolated_env(&cfg, &parent_env);
        assert!(!iso.contains_key("TOP_SECRET_HOST_TOKEN"));
        assert_eq!(iso.get("HYPHAE_PROTOCOL").map(String::as_str), Some("2"));
        assert_eq!(
            iso.get("PLUGIN_CUSTOM_MODE").map(String::as_str),
            Some("bridge-test")
        );

        let sup = SubprocessSupervisor::new(cfg);
        sup.start(host.clone()).await.expect("start v1 supervisor");

        // Wait until child publishes event, reports status, and triggers oversized frame nack.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if !host.events().await.is_empty()
                && sup.last_status().is_some()
                && sup.oversized_frames_rejected() >= 1
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for v1 child handshake/events; events={:?} status={:?} oversized={}",
                host.events().await.len(),
                sup.last_status(),
                sup.oversized_frames_rejected()
            );
            tokio::time::sleep(Duration::from_millis(15)).await;
        }

        assert_eq!(sup.detected_protocol(), WireProtocol::LegacyV1);
        assert_eq!(sup.health(), AdapterHealth::Healthy);
        let evs = host.events().await;
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].0, "ops");
        assert_eq!(evs[0].1.id, "v1-msg-1");
        assert_eq!(
            sup.last_status(),
            Some(StatusParams {
                target: "ops".to_string(),
                pending: 3,
                oldest_age_seconds: 12,
                t3_connected: true,
            })
        );

        // Outbound correlated `post()` request over legacy v1!
        let mut params = BTreeMap::new();
        params.insert("text".to_string(), json!("deploy complete"));
        let reply = sup
            .post("ops", params, Duration::from_secs(3))
            .await
            .expect("v1 post request must succeed");
        assert_eq!(
            reply,
            json!({ "proto": "v1", "target": "ops", "echo": "deploy complete" })
        );

        // Clean SIGTERM shutdown.
        sup.stop().await.expect("stop v1 supervisor");
        assert_eq!(sup.health(), AdapterHealth::Stopped);
        assert!(!sup.is_connected().await);
    }

    #[tokio::test]
    async fn supervisor_jsonrpc_v2_real_child_hello_publish_post_status_and_oversized() {
        let host = RecordingHost::new();

        // Real Python child speaking JSON-RPC 2.0 v2 through the EXACT SAME `SubprocessSupervisor`!
        let script = r#"
import json, os, socket, sys

sock = socket.socket(fileno=3)
reader = sock.makefile("rb")

def send(obj):
    sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))

def recv():
    line = reader.readline()
    if not line:
        sys.exit(0)
    return json.loads(line.decode("utf-8"))

assert os.environ.get("HYPHAE_PROTOCOL") == "2"

# 1. Initiate JSON-RPC 2.0 `hyphae/hello` request immediately (auto-detected by HelloMode::Auto!)
send({
    "jsonrpc": "2.0",
    "id": "h1",
    "method": "hyphae/hello",
    "params": {"protocol": 2, "plugin": "telegram-v2", "targets": ["alerts"]}
})
hello_resp = recv()
assert hello_resp["jsonrpc"] == "2.0" and hello_resp["id"] == "h1", f"bad hello resp: {hello_resp}"
assert hello_resp["result"]["protocol"] == 2
assert hello_resp["result"]["targets"] == ["alerts"]

# 2. Publish CloudEvent via JSON-RPC 2.0 `hyphae/publish`
send({
    "jsonrpc": "2.0",
    "id": 2,
    "method": "hyphae/publish",
    "params": {
        "to": "alerts",
        "event": {
            "specversion": "1.0",
            "id": "v2-msg-1",
            "source": "local/telegram/alerts",
            "type": "to.hyphae.bridge.telegram",
            "datacontenttype": "application/json",
            "data": {"text": "hello from jsonrpc v2"}
        }
    }
})
pub_resp = recv()
assert pub_resp["jsonrpc"] == "2.0" and pub_resp["id"] == 2, f"bad pub resp: {pub_resp}"
assert pub_resp["result"]["status"] == "stored"

# 3. Send JSON-RPC 2.0 `hyphae/status` notification & `hyphae/deliveryFailed` notification
send({
    "jsonrpc": "2.0",
    "method": "hyphae/status",
    "params": {"target": "alerts", "pending": 1, "oldestAgeSeconds": 4, "t3Connected": True}
})
send({
    "jsonrpc": "2.0",
    "method": "hyphae/deliveryFailed",
    "params": {
        "target": "alerts",
        "events": [{"id": "old-1", "source": "local/telegram/alerts"}],
        "reason": "expired"
    }
})

# 4. Send >64 KiB oversized line -> expect JSON-RPC 2.0 ERR_TOO_LARGE (-32001)
sock.sendall((json.dumps({"jsonrpc": "2.0", "id": 99, "method": "hyphae/publish", "params": {"pad": "B" * 70000}}) + "\n").encode("utf-8"))
err_resp = recv()
assert err_resp["jsonrpc"] == "2.0" and err_resp["error"]["code"] == -32001, f"expected -32001: {err_resp}"

# 5. Handle inbound JSON-RPC 2.0 `hyphae/post` requests
while True:
    msg = recv()
    if msg.get("jsonrpc") == "2.0" and msg.get("method") == "hyphae/post":
        p = msg["params"]
        send({
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {"proto": "v2", "target": p["target"], "echo": p["params"].get("text")}
        })
"#;

        let mut cfg = SubprocessConfig::new(
            "telegram-v2",
            AdapterKind::Bridge,
            python_bin(),
            vec!["-u".to_string(), "-c".to_string(), script.to_string()],
            vec!["alerts".to_string()],
        );
        cfg.hello_mode = HelloMode::Auto;
        cfg.auto_hello_grace = Duration::from_millis(200);
        cfg.kill_timeout = Duration::from_millis(500);

        let sup = SubprocessSupervisor::new(cfg);
        sup.start(host.clone()).await.expect("start v2 supervisor");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if !host.events().await.is_empty()
                && sup.last_status().is_some()
                && !host.delivery_failures().await.is_empty()
                && sup.oversized_frames_rejected() >= 1
            {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for v2 child; events={} status={:?} failures={} oversized={}",
                host.events().await.len(),
                sup.last_status(),
                host.delivery_failures().await.len(),
                sup.oversized_frames_rejected()
            );
            tokio::time::sleep(Duration::from_millis(15)).await;
        }

        assert_eq!(sup.detected_protocol(), WireProtocol::JsonRpcV2);
        let evs = host.events().await;
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].0, "alerts");
        assert_eq!(evs[0].1.id, "v2-msg-1");
        let failures = host.delivery_failures().await;
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].adapter_id, "telegram-v2");
        assert_eq!(failures[0].target, "alerts");
        assert_eq!(failures[0].events.len(), 1);
        assert_eq!(failures[0].reason, "expired");

        // Outbound correlated JSON-RPC 2.0 `hyphae/post` request!
        let mut params = BTreeMap::new();
        params.insert("text".to_string(), json!("hello jsonrpc"));
        let reply = sup
            .post("alerts", params, Duration::from_secs(3))
            .await
            .expect("v2 post must succeed");
        assert_eq!(
            reply,
            json!({ "proto": "v2", "target": "alerts", "echo": "hello jsonrpc" })
        );

        sup.stop().await.expect("stop v2 supervisor");
        assert_eq!(sup.health(), AdapterHealth::Stopped);
    }

    #[tokio::test]
    async fn supervisor_restarts_unexpected_exit_with_backoff_and_sigkill_fallback() {
        let host = RecordingHost::new();
        let tmp = tempfile::tempdir().expect("tempdir");
        let marker = tmp.path().join("crash-once.flag");

        // First run crashes immediately (exit 1); second run ignores SIGTERM so we exercise
        // BOTH exponential restart AND SIGTERM -> SIGKILL shutdown!
        let script = r#"
import json, os, signal, socket, sys, time

marker = os.environ["MARKER_FILE"]
if not os.path.exists(marker):
    with open(marker, "w") as f:
        f.write("1")
    sys.exit(1)

signal.signal(signal.SIGTERM, signal.SIG_IGN)
sock = socket.socket(fileno=3)
sock.sendall((json.dumps({
    "jsonrpc": "2.0",
    "id": "hi",
    "method": "hyphae/hello",
    "params": {"protocol": 2, "plugin": "crasher", "targets": ["ops"]}
}) + "\n").encode("utf-8"))
while True:
    time.sleep(0.2)
"#;

        let mut cfg = SubprocessConfig::new(
            "crasher",
            AdapterKind::Source,
            python_bin(),
            vec!["-u".to_string(), "-c".to_string(), script.to_string()],
            vec!["ops".to_string()],
        );
        cfg.env.insert(
            "MARKER_FILE".to_string(),
            marker.to_string_lossy().into_owned(),
        );
        cfg.initial_backoff = Duration::from_millis(30);
        cfg.max_backoff = Duration::from_millis(120);
        cfg.kill_timeout = Duration::from_millis(120);

        let sup = SubprocessSupervisor::new(cfg);
        sup.start(host.clone()).await.expect("start crasher");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if sup.restart_count() >= 1 && sup.detected_protocol() == WireProtocol::JsonRpcV2 {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for supervisor restart; restarts={} proto={:?}",
                sup.restart_count(),
                sup.detected_protocol()
            );
            tokio::time::sleep(Duration::from_millis(15)).await;
        }

        // Stop must escalate SIGTERM -> SIGKILL cleanly within ~kill_timeout.
        let stop_started = tokio::time::Instant::now();
        sup.stop().await.expect("stop after SIGKILL escalation");
        assert!(
            stop_started.elapsed() < Duration::from_secs(2),
            "SIGKILL fallback should terminate promptly"
        );
        assert_eq!(sup.health(), AdapterHealth::Stopped);
    }

    #[tokio::test]
    async fn supervisor_node_fs_fd3_child_works_like_v1_js_sdk() {
        // Skip cleanly if `node` isn't installed in PATH on a minimal host.
        if std::process::Command::new("node")
            .arg("--version")
            .output()
            .is_err()
        {
            return;
        }
        let host = RecordingHost::new();
        // Matches `plugins/sdk/client.mjs`: uses `node:fs` createReadStream/createWriteStream on fd 3!
        let js_script = r#"
const fs = require("node:fs");
const rl = require("node:readline");
const out = fs.createWriteStream("", { fd: 3, autoClose: false });
const input = fs.createReadStream("", { fd: 3, autoClose: false });
const lines = rl.createInterface({ input });
const send = (obj) => out.write(JSON.stringify(obj) + "\n");
lines.on("line", (line) => {
  if (!line.trim()) return;
  const msg = JSON.parse(line);
  if (msg.type === "hello") {
    send({
      type: "event",
      to: "ops",
      event: {
        specversion: "1.0",
        id: "node-v1-1",
        source: "local/node-bridge/ops",
        type: "to.hyphae.bridge.node",
        datacontenttype: "application/json",
        data: { from: "node-fs-fd3" }
      }
    });
  } else if (msg.type === "request" && msg.method === "post") {
    send({ type: "response", id: msg.id, ok: true, result: { runtime: "node", echo: msg.params.text } });
  }
});
"#;
        let mut cfg = SubprocessConfig::new(
            "node-v1",
            AdapterKind::Bridge,
            "node",
            vec!["-e".to_string(), js_script.to_string()],
            vec!["ops".to_string()],
        );
        cfg.auto_hello_grace = Duration::from_millis(25);
        cfg.kill_timeout = Duration::from_millis(500);

        let sup = SubprocessSupervisor::new(cfg);
        sup.start(host.clone()).await.expect("start node child");

        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if !host.events().await.is_empty() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "timed out waiting for node fd-3 child event"
            );
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
        assert_eq!(host.events().await[0].1.id, "node-v1-1");
        assert_eq!(sup.detected_protocol(), WireProtocol::LegacyV1);

        let mut params = BTreeMap::new();
        params.insert("text".to_string(), json!("ping node"));
        let res = sup
            .post("ops", params, Duration::from_secs(3))
            .await
            .expect("node post must succeed");
        assert_eq!(res, json!({ "runtime": "node", "echo": "ping node" }));

        sup.stop().await.expect("stop node child");
        assert_eq!(sup.health(), AdapterHealth::Stopped);
    }
}

#[cfg(not(unix))]
#[tokio::test]
async fn supervisor_defaults_to_loopback_tcp_on_non_unix() {
    use hyp_node::adapters::{PluginTransportMode, SubprocessConfig};
    let cfg = SubprocessConfig::new(
        "win-test",
        AdapterKind::Bridge,
        "cmd.exe",
        vec![],
        vec!["ops".to_string()],
    );
    assert_eq!(cfg.transport_mode, PluginTransportMode::LoopbackTcp);
}

// ============================================================================
// 3. Webhook Mutation & Normalization Tests (GitHub, Prometheus, Generic)
// ============================================================================

#[tokio::test]
async fn github_webhook_hmac_mutations_and_event_types() {
    let host = RecordingHost::new();
    let secret = "super-secret-github-webhook-key";
    let mut cfg = GitHubWebhookConfig::new("github-webhook", "github", secret);
    cfg.allowed_repos = vec!["acme/checkout".to_string()];

    let adapter = GitHubWebhookAdapter::new(cfg);
    adapter
        .start(host.clone())
        .await
        .expect("start github webhook");

    let cases: &[(&str, &str, Value, &str, Option<&str>)] = &[
        (
            "pull_request",
            "deliv-pr",
            json!({
                "action": "opened",
                "repository": { "full_name": "acme/checkout" },
                "sender": { "login": "alice", "type": "User" },
                "pull_request": {
                    "number": 10,
                    "title": "Fix checkout",
                    "html_url": "https://github.com/acme/checkout/pull/10",
                    "state": "open",
                    "draft": false,
                    "body": "Fixes bug",
                    "labels": [{ "name": "bug" }],
                    "assignees": [],
                    "head": { "ref": "fix/10", "sha": "111aaa" },
                    "base": { "ref": "main" }
                }
            }),
            "com.github.pull_request.opened",
            Some("pull/10"),
        ),
        (
            "issues",
            "deliv-issue",
            json!({
                "action": "opened",
                "repository": { "full_name": "acme/checkout" },
                "sender": { "login": "bob", "type": "User" },
                "issue": {
                    "number": 5,
                    "title": "Cart crash",
                    "html_url": "https://github.com/acme/checkout/issues/5",
                    "state": "open",
                    "body": "Steps to repro",
                    "labels": [],
                    "assignees": []
                }
            }),
            "com.github.issues.opened",
            Some("issues/5"),
        ),
        (
            "issue_comment",
            "deliv-comment",
            json!({
                "action": "created",
                "repository": { "full_name": "acme/checkout" },
                "sender": { "login": "carol", "type": "User" },
                "issue": {
                    "number": 10,
                    "title": "Fix checkout",
                    "pull_request": { "url": "https://api.github.com/repos/acme/checkout/pulls/10" },
                    "labels": []
                },
                "comment": {
                    "html_url": "https://github.com/acme/checkout/pull/10#issuecomment-1",
                    "body": "LGTM agent:codex"
                }
            }),
            "com.github.issue_comment.created",
            Some("pull/10"),
        ),
        (
            "pull_request_review",
            "deliv-review",
            json!({
                "action": "submitted",
                "repository": { "full_name": "acme/checkout" },
                "sender": { "login": "dave", "type": "User" },
                "pull_request": { "number": 10, "title": "Fix checkout", "head": { "sha": "111aaa" } },
                "review": { "state": "approved", "body": "Ship it", "html_url": "https://github.com/acme/checkout/pull/10#pullrequestreview-1" }
            }),
            "com.github.pull_request_review.submitted",
            Some("pull/10"),
        ),
        (
            "push",
            "deliv-push",
            json!({
                "ref": "refs/heads/main",
                "after": "222bbb",
                "compare": "https://github.com/acme/checkout/compare/111...222",
                "repository": { "full_name": "acme/checkout", "default_branch": "main" },
                "sender": { "login": "alice", "type": "User" }
            }),
            "com.github.push",
            Some("refs/heads/main"),
        ),
        (
            "check_run",
            "deliv-check",
            json!({
                "action": "completed",
                "repository": { "full_name": "acme/checkout" },
                "sender": { "login": "github-actions[bot]", "type": "Bot" },
                "check_run": {
                    "id": 9001,
                    "name": "cargo test",
                    "status": "completed",
                    "conclusion": "success",
                    "head_sha": "222bbb",
                    "html_url": "https://github.com/acme/checkout/runs/9001",
                    "check_suite": { "head_branch": "main" },
                    "pull_requests": [{ "number": 10 }]
                }
            }),
            "com.github.check_run.completed",
            Some("actions/runs/9001"),
        ),
        (
            "workflow_run",
            "deliv-wf",
            json!({
                "action": "completed",
                "repository": { "full_name": "acme/checkout" },
                "sender": { "login": "github-actions[bot]", "type": "Bot" },
                "workflow_run": {
                    "id": 9002,
                    "name": "CI",
                    "conclusion": "success",
                    "head_branch": "main",
                    "head_sha": "222bbb",
                    "run_attempt": 1,
                    "path": ".github/workflows/ci.yml",
                    "html_url": "https://github.com/acme/checkout/actions/runs/9002",
                    "pull_requests": [{ "number": 10 }]
                }
            }),
            "com.github.workflow_run.completed",
            Some("actions/runs/9002"),
        ),
        (
            "release",
            "deliv-rel",
            json!({
                "action": "published",
                "repository": { "full_name": "acme/checkout" },
                "sender": { "login": "alice", "type": "User" },
                "release": {
                    "tag_name": "v2.0.0",
                    "name": "Release v2.0.0",
                    "html_url": "https://github.com/acme/checkout/releases/tag/v2.0.0",
                    "draft": false,
                    "prerelease": false,
                    "target_commitish": "main",
                    "body": "Unified Rust Node"
                }
            }),
            "com.github.release.published",
            Some("releases/v2.0.0"),
        ),
    ];

    for (ev_name, deliv_id, payload, expected_type, expected_subject) in cases {
        let body = serde_json::to_vec(payload).unwrap();
        let sig = compute_hmac_sha256_header(secret.as_bytes(), &body);

        // 1. Missing X-Hub-Signature-256 fails closed.
        let mut no_sig = HeaderMap::new();
        no_sig.insert("x-github-event", HeaderValue::from_str(ev_name).unwrap());
        no_sig.insert(
            "x-github-delivery",
            HeaderValue::from_str(deliv_id).unwrap(),
        );
        assert!(matches!(
            adapter.ingest_webhook(&no_sig, &body).await,
            Err(AdapterError::Unauthorized(_))
        ));

        // 2. Single-byte flip in X-Hub-Signature-256 fails closed.
        let mut flipped = sig.clone().into_bytes();
        flipped[10] = if flipped[10] == b'a' { b'b' } else { b'a' };
        let mut bad_sig = no_sig.clone();
        bad_sig.insert(
            "x-hub-signature-256",
            HeaderValue::from_str(&String::from_utf8(flipped).unwrap()).unwrap(),
        );
        assert!(matches!(
            adapter.ingest_webhook(&bad_sig, &body).await,
            Err(AdapterError::Unauthorized(_))
        ));

        // 3. Valid signature succeeds.
        let mut good = no_sig;
        good.insert("x-hub-signature-256", HeaderValue::from_str(&sig).unwrap());
        let outcome = adapter.ingest_webhook(&good, &body).await.unwrap();
        assert!(matches!(outcome, WebhookIngestOutcome::Published { .. }));

        let all = host.events().await;
        let last = &all.last().unwrap().1;
        assert_eq!(last.event_type, *expected_type);
        assert_eq!(last.source, "github.com/acme/checkout");
        assert_eq!(last.subject.as_deref(), *expected_subject);
        assert_eq!(
            last.extensions.get("repo").and_then(Value::as_str),
            Some("acme/checkout")
        );
    }

    // Disallowed repo is ignored cleanly even with a valid signature.
    let other_body = serde_json::to_vec(&json!({
        "action": "opened",
        "repository": { "full_name": "acme/unlisted" },
        "sender": { "login": "alice", "type": "User" },
        "issues": {},
        "issue": { "number": 1, "title": "ignored", "state": "open" }
    }))
    .unwrap();
    let other_sig = compute_hmac_sha256_header(secret.as_bytes(), &other_body);
    let mut other_headers = HeaderMap::new();
    other_headers.insert(
        "x-hub-signature-256",
        HeaderValue::from_str(&other_sig).unwrap(),
    );
    other_headers.insert("x-github-event", HeaderValue::from_static("issues"));
    other_headers.insert("x-github-delivery", HeaderValue::from_static("deliv-other"));
    assert!(matches!(
        adapter.ingest_webhook(&other_headers, &other_body).await.unwrap(),
        WebhookIngestOutcome::Ignored { ref reason } if reason == "repo_not_allowed"
    ));

    adapter.stop().await.unwrap();
}

// ============================================================================
// Multi-Owner `repoTokens` Isolation, Private+Public Coalescing & Poller Cap
// ============================================================================

#[derive(Default)]
struct MultiTokenMockState {
    requests: Mutex<Vec<(String, Option<String>)>>,
    rate_limit_once: Mutex<bool>,
}

async fn handle_multi_token_github(
    state: Arc<MultiTokenMockState>,
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path().to_string();
    let auth = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string);
    let if_none_match = req
        .headers()
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string);

    state
        .requests
        .lock()
        .await
        .push((path.clone(), auth.clone()));

    let required_auth_for = |repo: &str| -> Option<&'static str> {
        match repo {
            "bowd/personal-priv" => Some("Bearer hyphae_gh_tok_bowd_a"),
            "bayfold/org-priv" => Some("Bearer hyphae_gh_tok_bayfold_b"),
            "bayfold/special" => Some("Bearer hyphae_gh_tok_bayfold_special_c"),
            _ => None,
        }
    };

    if let Some(rest) = path.strip_prefix("/repos/") {
        if let Some(repo_raw) = rest.strip_suffix("/events") {
            let repo = repo_raw.to_ascii_lowercase();
            if let Some(expected) = required_auth_for(&repo) {
                if auth.as_deref() != Some(expected) {
                    return Ok(Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Full::new(Bytes::from(r#"{"message":"Not Found"}"#)))
                        .unwrap());
                }
            } else if repo != "oss/public-repo" {
                return Ok(Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from(r#"{"message":"Not Found"}"#)))
                    .unwrap());
            }

            if repo == "oss/public-repo" {
                let mut rl = state.rate_limit_once.lock().await;
                if *rl {
                    *rl = false;
                    return Ok(Response::builder()
                        .status(StatusCode::TOO_MANY_REQUESTS)
                        .header("retry-after", "1")
                        .header("x-ratelimit-remaining", "0")
                        .body(Full::new(Bytes::from(r#"{"message":"rate limited"}"#)))
                        .unwrap());
                }
            }

            if if_none_match.is_some() {
                return Ok(Response::builder()
                    .status(StatusCode::NOT_MODIFIED)
                    .header(header::ETAG, format!("\"etag-{repo}\""))
                    .header("x-ratelimit-remaining", "4999")
                    .body(Full::new(Bytes::new()))
                    .unwrap());
            }

            let evt_id = format!("evt-{}", repo.replace('/', "-"));
            let payload = json!([{
                "id": evt_id,
                "type": "IssuesEvent",
                "repo": { "name": repo },
                "actor": { "login": "octocat", "type": "User" },
                "created_at": "2026-11-25T08:00:00Z",
                "payload": {
                    "action": "opened",
                    "issue": {
                        "number": 7,
                        "title": format!("Event from {repo}"),
                        "html_url": format!("https://github.com/{repo}/issues/7"),
                        "state": "open",
                        "body": "scoped token test",
                        "labels": [],
                        "assignees": []
                    }
                }
            }]);
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, "application/json")
                .header(header::ETAG, format!("\"etag-{repo}\""))
                .header("x-ratelimit-remaining", "4999")
                .body(Full::new(Bytes::from(payload.to_string())))
                .unwrap());
        }

        // Repo visibility metadata: GET /repos/{owner}/{repo}
        let repo = rest.to_ascii_lowercase();
        let (status, body) = match repo.as_str() {
            "bowd/personal-priv" | "bayfold/org-priv" | "bayfold/special" => {
                let expected = required_auth_for(&repo).unwrap();
                if auth.as_deref() == Some(expected) {
                    (
                        StatusCode::OK,
                        json!({
                            "full_name": repo,
                            "private": true,
                            "visibility": "private"
                        }),
                    )
                } else {
                    (StatusCode::NOT_FOUND, json!({ "message": "Not Found" }))
                }
            }
            "oss/public-repo" => (
                StatusCode::OK,
                json!({
                    "full_name": "oss/public-repo",
                    "private": false,
                    "visibility": "public"
                }),
            ),
            "other-org/priv" => (
                // Even if metadata came back 200 private, adapter MUST still fail closed when
                // `token_for_repo("other-org/priv")` is None!
                StatusCode::OK,
                json!({
                    "full_name": "other-org/priv",
                    "private": true,
                    "visibility": "private"
                }),
            ),
            _ => (StatusCode::NOT_FOUND, json!({ "message": "Not Found" })),
        };
        return Ok(Response::builder()
            .status(status)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap());
    }

    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::new()))
        .unwrap())
}

#[tokio::test]
async fn multi_owner_repo_tokens_strict_isolation_coalescing_pattern_validation_and_poller_cap() {
    use hyp_node::adapters::github_public::normalize_repo_token_pattern;

    // 1. Pattern validation rejects `*`, `*/*`, `../bad`, empty fail-closed.
    for bad in [
        "*", "*/*", "*/repo", "../bad", "owner/..", "", "   ", "a/b/c",
    ] {
        assert!(
            normalize_repo_token_pattern(bad).is_err(),
            "pattern {bad:?} must fail closed"
        );
    }

    // Start local multi-token mock GitHub server.
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = Arc::new(MultiTokenMockState {
        requests: Mutex::new(Vec::new()),
        rate_limit_once: Mutex::new(true),
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
                            async move { handle_multi_token_github(st_req, req).await }
                        });
                        let _ = http1::Builder::new().serve_connection(io, svc).await;
                    });
                }
            }
        }
    });

    // Store 3 distinct owner/repo tokens in an isolated file SecretStore (ZERO default `github_token`!).
    let tmp = tempfile::tempdir().unwrap();
    let store = SecretStore::new(tmp.path(), SecretBackend::File);
    store.set("gh-bowd", "hyphae_gh_tok_bowd_a").unwrap();
    store.set("gh-bayfold", "hyphae_gh_tok_bayfold_b").unwrap();
    store
        .set("gh-bayfold-special", "hyphae_gh_tok_bayfold_special_c")
        .unwrap();

    let mut cfg = GitHubPublicConfig {
        api_base_url: format!("http://{addr}"),
        github_token: None, // intentionally omitted to assert ZERO auth on public/unmatched repos!
        allow_private_with_token: true,
        base_poll_interval: Duration::from_millis(25),
        min_poll_interval: Duration::from_millis(10),
        teardown_grace: Duration::ZERO,
        max_active_pollers: 10,
        ..GitHubPublicConfig::default()
    };
    cfg.with_repo_token_from_store("Bowd", &store, "gh-bowd")
        .unwrap()
        .with_repo_token_from_store("Bayfold/*", &store, "gh-bayfold")
        .unwrap()
        .with_repo_token_from_store("bayfold/Special", &store, "gh-bayfold-special")
        .unwrap();

    assert_eq!(
        cfg.configured_token_scopes(),
        vec![
            "bayfold/*".to_string(),
            "bayfold/special".to_string(),
            "bowd/*".to_string(),
        ]
    );

    let host = RecordingHost::new();
    let adapter = GitHubPublicAdapter::new(cfg).unwrap();
    adapter.start(host.clone()).await.unwrap();

    // 2. Visibility validation:
    //    - bowd/personal-priv, bayfold/org-priv, bayfold/special, oss/public-repo -> ALL pass!
    //    - other-org/priv -> FAILS CLOSED (no matching token -> even with allow_private_with_token: true)!
    for ok_repo in [
        "bowd/personal-priv",
        "bayfold/org-priv",
        "bayfold/special",
        "oss/public-repo",
    ] {
        let diags = adapter
            .validate_subscription("github", &[exact_repo_filter(ok_repo)])
            .await;
        assert!(
            diags.is_empty(),
            "expected {ok_repo} to validate cleanly, got {diags:?}"
        );
    }

    let diag_other = adapter
        .validate_subscription("github", &[exact_repo_filter("other-org/priv")])
        .await;
    assert_eq!(diag_other.len(), 1);
    assert_eq!(diag_other[0].severity, DiagnosticSeverity::Error);
    assert_eq!(diag_other[0].code, DiagnosticCode::RepoNotFoundOrPrivate);
    assert!(
        diag_other[0]
            .remediation
            .as_deref()
            .unwrap_or("")
            .contains("sources[].repoTokens"),
        "remediation should reference v2 repoTokens: {:?}",
        diag_other[0]
    );

    // 3. Coalesce all 4 accessible repos (3 private across 2 owners + 1 public) into ONE adapter!
    let subs: Vec<CompiledSubscription> = [
        "bowd/personal-priv",
        "bayfold/org-priv",
        "bayfold/special",
        "oss/public-repo",
    ]
    .iter()
    .enumerate()
    .map(|(idx, repo)| CompiledSubscription {
        id: format!("sub-multi-{idx}"),
        subscriber: "local".to_string(),
        topic: "github".to_string(),
        filters: vec![exact_repo_filter(repo)],
        coalesce_seconds: 0,
    })
    .collect();
    host.set_subscribers(subs.clone()).await;
    adapter.on_subscriptions_changed("github", &subs).await;
    assert_eq!(adapter.stats().await.active_pollers, 4);

    // Wait until all 4 repos publish their CloudEvent (including `oss/public-repo` recovering after HTTP 429!).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let evs = host.events().await;
        let ids: Vec<&str> = evs.iter().map(|(_, e)| e.id.as_str()).collect();
        if ids.contains(&"evt-bowd-personal-priv")
            && ids.contains(&"evt-bayfold-org-priv")
            && ids.contains(&"evt-bayfold-special")
            && ids.contains(&"evt-oss-public-repo")
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for multi-owner events; got {ids:?}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    // 4. STRICT SECURITY INVARIANT: inspect EVERY recorded HTTP request on the mock server!
    let recorded = state.requests.lock().await.clone();
    assert!(!recorded.is_empty());
    for (path, auth_hdr) in &recorded {
        if path.starts_with("/repos/bowd/personal-priv") {
            assert_eq!(
                auth_hdr.as_deref(),
                Some("Bearer hyphae_gh_tok_bowd_a"),
                "bowd/personal-priv got wrong auth header on {path}: {auth_hdr:?}"
            );
        } else if path.starts_with("/repos/bayfold/org-priv") {
            assert_eq!(
                auth_hdr.as_deref(),
                Some("Bearer hyphae_gh_tok_bayfold_b"),
                "bayfold/org-priv got wrong auth header on {path}: {auth_hdr:?}"
            );
        } else if path.starts_with("/repos/bayfold/special") {
            assert_eq!(
                auth_hdr.as_deref(),
                Some("Bearer hyphae_gh_tok_bayfold_special_c"),
                "bayfold/special must receive exact override token on {path}: {auth_hdr:?}"
            );
        } else if path.starts_with("/repos/oss/public-repo") {
            assert_eq!(
                *auth_hdr, None,
                "CRITICAL LEAK: public repo {path} must receive ZERO Authorization header, got {auth_hdr:?}"
            );
        } else if path.starts_with("/repos/other-org/priv") {
            assert_eq!(
                *auth_hdr, None,
                "CRITICAL LEAK: unmatched private repo {path} must receive ZERO Authorization header, got {auth_hdr:?}"
            );
        }
    }

    adapter.stop().await.unwrap();

    // 5. Verify `max_active_pollers` hard cap (cap = 2 prevents spawning 3rd poller & fails validation).
    let mut cap_cfg = GitHubPublicConfig {
        api_base_url: format!("http://{addr}"),
        allow_private_with_token: true,
        base_poll_interval: Duration::from_secs(60),
        min_poll_interval: Duration::from_secs(60),
        teardown_grace: Duration::ZERO,
        max_active_pollers: 2,
        ..GitHubPublicConfig::default()
    };
    cap_cfg
        .with_repo_token_from_store("bowd/*", &store, "gh-bowd")
        .unwrap()
        .with_repo_token_from_store("bayfold/*", &store, "gh-bayfold")
        .unwrap()
        .with_repo_token_from_store("bayfold/special", &store, "gh-bayfold-special")
        .unwrap();
    let cap_adapter = GitHubPublicAdapter::new(cap_cfg).unwrap();
    cap_adapter.start(host.clone()).await.unwrap();

    cap_adapter
        .on_subscriptions_changed("github", &subs[..3])
        .await;
    assert_eq!(
        cap_adapter.stats().await.active_pollers,
        2,
        "max_active_pollers=2 MUST cap spawned pollers at 2"
    );

    let diag_cap = cap_adapter
        .validate_subscription("github", &[exact_repo_filter("oss/public-repo")])
        .await;
    assert_eq!(diag_cap.len(), 1);
    assert_eq!(diag_cap[0].severity, DiagnosticSeverity::Error);
    assert_eq!(diag_cap[0].code, DiagnosticCode::UnmonitoredRepo);

    cap_adapter.stop().await.unwrap();
    let _ = shutdown_tx.send(());
}
