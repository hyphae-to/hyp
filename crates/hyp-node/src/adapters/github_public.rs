//! Demand-driven `github-public` Event Source Adapter powering BOTH `public.hyphae.to`
//! and local `local.github-public` (`docs/architecture-v2.md` §2.4).
//!
//! Architecture:
//! - Subscribe-time fail-closed reachability lint (`validate_subscription`): extracts required
//!   `exact.repo` values, verifies each repo exists and has `visibility == "public"` via
//!   `GET /repos/{owner}/{repo}` (cached with 5m TTL), unless `allow_private_with_token` is enabled
//!   for local mode with a GitHub token.
//! - Demand-driven refcounted ETag poller pool (`on_subscriptions_changed`): spawns EXACTLY ONE
//!   poller task per distinct active `owner/repo` globally regardless of subscriber count (1 or 5000).
//! - Conditional RFC 9110 polling (`If-None-Match: <etag>`): `304 Not Modified` consumes 0 quota,
//!   honors `X-Poll-Interval` and `X-RateLimit-Remaining`, backs off adaptively on idle `304`s
//!   (`base -> 2x -> 5x`), snaps back immediately to `base` on `200` new events, and tears down
//!   cleanly after a grace window once refcount drops to `0`.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use http::{HeaderMap, Method, Request, StatusCode, header};
use http_body_util::{BodyExt, Empty};
use hyp_crypto::keystore::SecretStore;
use hyp_crypto::rfc3339::{format_rfc3339_seconds, now_unix_ms};
use hyp_proto::cloudevent::{CloudEvent, check_cloudevent_v2, is_valid_rfc3339_strict};
use hyp_proto::filter::{DiagnosticCode, DiagnosticSeverity, Filter, SubscriptionDiagnostic};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use regex::Regex;
use serde_json::{Map, Value, json};
use tokio::sync::{Mutex, watch};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use crate::adapters::trait_def::{
    AdapterError, AdapterHealth, AdapterKind, BoxFuture, CompiledSubscription, NodeAdapter,
    NodeAdapterHost,
};
use crate::adapters::webhooks::{GitHubNormalizeOutcome, normalize_github_webhook};

const DEFAULT_API_BASE_URL: &str = "https://api.github.com";
const DEFAULT_USER_AGENT: &str = "hyphae-github-public/2.0";
const MAX_DEDUP_IDS_PER_REPO: usize = 512;
const MAX_HTTP_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
/// Default cap on concurrent active ETag pollers to prevent runaway subscriber DoS.
pub const DEFAULT_MAX_ACTIVE_POLLERS: usize = 100;
/// Upper bound (in seconds) for `Retry-After` / `X-RateLimit-Reset` rate-limit backoff.
const MAX_RATE_LIMIT_BACKOFF_SECS: u64 = 600;
const LOCAL_PRIVATE_REMEDIATION: &str = "Run local.github-public on your own Local Node: configure sources[].repoTokens + allowPrivateWithToken: true in ~/.config/hyphae/node.json.";

type HttpClient = Client<HttpsConnector<HttpConnector>, Empty<Bytes>>;

/// Configuration for [`GitHubPublicAdapter`].
#[derive(Debug, Clone)]
pub struct GitHubPublicConfig {
    pub id: String,
    pub topic: String,
    /// GitHub REST API base URL (defaults to `https://api.github.com`; overridable for tests).
    pub api_base_url: String,
    /// Optional default GitHub PAT/token (loaded from `SecretStore`; omitted on unauthenticated public mode).
    pub github_token: Option<Zeroizing<String>>,
    /// Optional per-owner (`"owner/*"`) or per-repo (`"owner/repo"`) GitHub PATs loaded from
    /// `SecretStore`. Strict precedence: exact `owner/repo` -> `owner/*` -> `github_token` -> `None`.
    pub repo_tokens: BTreeMap<String, Zeroizing<String>>,
    /// Allows subscribing to private repos when a matching token (`token_for_repo`) is present.
    pub allow_private_with_token: bool,
    pub user_agent: String,
    /// TTL for `GET /repos/{owner}/{repo}` visibility verification cache (default 5 minutes).
    pub repo_cache_ttl: Duration,
    /// Default base polling interval when `X-Poll-Interval` is not sent (default 60s).
    pub base_poll_interval: Duration,
    /// Minimum polling interval floor (default 60s in production; lower in tests).
    pub min_poll_interval: Duration,
    /// Grace window before tearing down a poller once its subscriber refcount hits 0 (default 5m).
    pub teardown_grace: Duration,
    /// Maximum concurrent active ETag pollers allowed (default `100`).
    pub max_active_pollers: usize,
    /// Per-request HTTP timeout.
    pub http_timeout: Duration,
}

impl Default for GitHubPublicConfig {
    fn default() -> Self {
        Self {
            id: "github-public".to_string(),
            topic: "github".to_string(),
            api_base_url: DEFAULT_API_BASE_URL.to_string(),
            github_token: None,
            repo_tokens: BTreeMap::new(),
            allow_private_with_token: false,
            user_agent: DEFAULT_USER_AGENT.to_string(),
            repo_cache_ttl: Duration::from_secs(300),
            base_poll_interval: Duration::from_secs(60),
            min_poll_interval: Duration::from_secs(60),
            teardown_grace: Duration::from_secs(300),
            max_active_pollers: DEFAULT_MAX_ACTIVE_POLLERS,
            http_timeout: Duration::from_secs(15),
        }
    }
}

impl GitHubPublicConfig {
    /// Loads an optional default GitHub token from a Hyphae [`SecretStore`] without touching CLI argv/env.
    pub fn with_token_from_store(
        mut self,
        store: &SecretStore,
        secret_name: &str,
    ) -> Result<Self, AdapterError> {
        let token = store.get(secret_name).map_err(|e| {
            AdapterError::Config(format!("failed to read secret '{secret_name}': {e}"))
        })?;
        self.github_token = Some(token);
        Ok(self)
    }

    /// Loads a scoped GitHub token (`owner/repo`, `owner/*`, or bare `owner` -> `owner/*`)
    /// from a Hyphae [`SecretStore`], validating and canonicalizing the pattern fail-closed.
    pub fn with_repo_token_from_store(
        &mut self,
        pattern: &str,
        store: &SecretStore,
        secret_name: &str,
    ) -> Result<&mut Self, AdapterError> {
        let canonical = normalize_repo_token_pattern(pattern)?;
        let token = store.get(secret_name).map_err(|e| {
            AdapterError::Config(format!("failed to read secret '{secret_name}': {e}"))
        })?;
        self.repo_tokens.insert(canonical, token);
        Ok(self)
    }

    /// Resolves the GitHub token to use for `repo` (`owner/repo`) with strict specificity:
    /// 1. Exact canonical `owner/repo` in `repo_tokens`,
    /// 2. Owner wildcard `owner/*` in `repo_tokens`,
    /// 3. Default `github_token`,
    /// 4. `None` (unauthenticated public mode).
    ///
    /// Security invariant: a token scoped to `org-a/*` is NEVER returned for `org-b/repo` or
    /// unrelated public repos.
    pub fn token_for_repo(&self, repo: &str) -> Option<&str> {
        let canonical = canonicalize_repo(repo)?;
        if let Some(tok) = self.repo_tokens.get(&canonical) {
            return Some(tok.as_str());
        }
        if let Some((owner, _)) = canonical.split_once('/') {
            let owner_wildcard = format!("{owner}/*");
            if let Some(tok) = self.repo_tokens.get(&owner_wildcard) {
                return Some(tok.as_str());
            }
        }
        self.github_token.as_deref().map(String::as_str)
    }

    /// Returns the sorted list of configured token scope patterns (e.g. `"bayfold/*"`,
    /// `"bayfold/special"`, plus `"*"` if a default `github_token` is set).
    /// NEVER exposes raw token values.
    pub fn configured_token_scopes(&self) -> Vec<String> {
        let mut scopes: BTreeSet<String> = self.repo_tokens.keys().cloned().collect();
        if self.github_token.is_some() {
            scopes.insert("*".to_string());
        }
        scopes.into_iter().collect()
    }
}

/// Runtime telemetry snapshot for [`GitHubPublicAdapter`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitHubPublicStats {
    pub active_pollers: usize,
    pub refcounts: BTreeMap<String, usize>,
    pub polls_total: u64,
    pub polls_200: u64,
    pub polls_304: u64,
}

#[derive(Debug, Clone)]
struct CachedRepoCheck {
    accessible: bool,
    reason: Option<String>,
    checked_at: Instant,
}

struct RepoDedupSet {
    order: VecDeque<String>,
    ids: HashSet<String>,
}

impl RepoDedupSet {
    fn new() -> Self {
        Self {
            order: VecDeque::new(),
            ids: HashSet::new(),
        }
    }

    /// Inserts `id`, returning `true` if it was newly seen (false if duplicate).
    fn insert(&mut self, id: String) -> bool {
        if !self.ids.insert(id.clone()) {
            return false;
        }
        self.order.push_back(id);
        while self.order.len() > MAX_DEDUP_IDS_PER_REPO {
            if let Some(evicted) = self.order.pop_front() {
                self.ids.remove(&evicted);
            }
        }
        true
    }
}

struct RepoDemandEntry {
    refcount: usize,
    poller_cancel: Option<watch::Sender<bool>>,
    poller_task: Option<JoinHandle<()>>,
    teardown_task: Option<JoinHandle<()>>,
}

struct TelemetryCounters {
    polls_total: AtomicU64,
    polls_200: AtomicU64,
    polls_304: AtomicU64,
}

impl TelemetryCounters {
    fn new() -> Self {
        Self {
            polls_total: AtomicU64::new(0),
            polls_200: AtomicU64::new(0),
            polls_304: AtomicU64::new(0),
        }
    }
}

struct Inner {
    config: GitHubPublicConfig,
    client: HttpClient,
    health: RwLock<AdapterHealth>,
    host: RwLock<Option<Arc<dyn NodeAdapterHost>>>,
    repo_cache: RwLock<HashMap<String, CachedRepoCheck>>,
    demand: Mutex<HashMap<String, RepoDemandEntry>>,
    dedup: Mutex<HashMap<String, RepoDedupSet>>,
    counters: TelemetryCounters,
}

/// Demand-driven `github-public` adapter (ETag poller pool).
#[derive(Clone)]
pub struct GitHubPublicAdapter {
    inner: Arc<Inner>,
}

impl GitHubPublicAdapter {
    pub fn new(mut config: GitHubPublicConfig) -> Result<Self, AdapterError> {
        let mut normalized_tokens = BTreeMap::new();
        for (raw_pat, token) in config.repo_tokens {
            let canonical = normalize_repo_token_pattern(&raw_pat)?;
            normalized_tokens.insert(canonical, token);
        }
        config.repo_tokens = normalized_tokens;
        let client = build_http_client()?;
        Ok(Self {
            inner: Arc::new(Inner {
                config,
                client,
                health: RwLock::new(AdapterHealth::Stopped),
                host: RwLock::new(None),
                repo_cache: RwLock::new(HashMap::new()),
                demand: Mutex::new(HashMap::new()),
                dedup: Mutex::new(HashMap::new()),
                counters: TelemetryCounters::new(),
            }),
        })
    }

    /// Returns the topic served by this `github-public` adapter (default `"github"`).
    pub fn topic(&self) -> &str {
        &self.inner.config.topic
    }

    /// Returns the sorted list of configured token scope patterns (NEVER raw tokens).
    pub fn configured_token_scopes(&self) -> Vec<String> {
        self.inner.config.configured_token_scopes()
    }

    /// Returns a point-in-time telemetry snapshot of active pollers, refcounts, and HTTP outcomes.
    pub async fn stats(&self) -> GitHubPublicStats {
        let demand = self.inner.demand.lock().await;
        let active_pollers = demand.values().filter(|e| e.poller_task.is_some()).count();
        let refcounts = demand
            .iter()
            .map(|(repo, e)| (repo.clone(), e.refcount))
            .collect();
        drop(demand);

        GitHubPublicStats {
            active_pollers,
            refcounts,
            polls_total: self.inner.counters.polls_total.load(Ordering::Relaxed),
            polls_200: self.inner.counters.polls_200.load(Ordering::Relaxed),
            polls_304: self.inner.counters.polls_304.load(Ordering::Relaxed),
        }
    }

    async fn check_repo_visibility(&self, repo: &str) -> (bool, Option<String>) {
        // 1. Check 5-minute TTL cache first.
        {
            let cache = self.inner.repo_cache.read().expect("repo cache lock");
            if let Some(entry) = cache.get(repo) {
                if entry.checked_at.elapsed() < self.inner.config.repo_cache_ttl {
                    return (entry.accessible, entry.reason.clone());
                }
            }
        }

        // 2. Call GET /repos/{owner}/{repo} using strictly scoped token_for_repo(repo).
        //    Fail closed on any non-200 or private repo without an explicit matching token.
        let url = format!(
            "{}/repos/{repo}",
            self.inner.config.api_base_url.trim_end_matches('/')
        );
        let repo_token = self.inner.config.token_for_repo(repo);
        let resp = match github_get(&self.inner, &url, repo_token, None).await {
            Ok(r) => r,
            Err(err) => {
                // Transient transport error: fail closed without poisoning the TTL cache.
                return (
                    false,
                    Some(format!(
                        "failed to verify GitHub repository '{repo}': {err}"
                    )),
                );
            }
        };

        let (accessible, reason, should_cache) = match resp.status {
            StatusCode::OK => match serde_json::from_slice::<Value>(&resp.body) {
                Ok(val) => {
                    let is_public = match val.get("visibility").and_then(Value::as_str) {
                        Some(v) => v.eq_ignore_ascii_case("public"),
                        None => val.get("private").and_then(Value::as_bool) == Some(false),
                    };
                    let allow_private =
                        self.inner.config.allow_private_with_token && repo_token.is_some();
                    if is_public || allow_private {
                        (true, None, true)
                    } else {
                        (
                            false,
                            Some(format!(
                                "Repository '{repo}' is private (visibility != \"public\") and no matching scoped token is configured."
                            )),
                            true,
                        )
                    }
                }
                Err(_) => (
                    false,
                    Some(format!(
                        "Repository '{repo}' metadata response was not valid JSON."
                    )),
                    false,
                ),
            },
            StatusCode::FORBIDDEN
                if parse_header_u64(&resp.headers, "x-ratelimit-remaining") == Some(0)
                    || resp.headers.contains_key("retry-after") =>
            {
                (
                    false,
                    Some(format!(
                        "GitHub API rate limit exceeded while verifying repository '{repo}' (HTTP 403)."
                    )),
                    false,
                )
            }
            StatusCode::TOO_MANY_REQUESTS => (
                false,
                Some(format!(
                    "GitHub API rate limit exceeded while verifying repository '{repo}' (HTTP 429)."
                )),
                false,
            ),
            StatusCode::NOT_FOUND | StatusCode::FORBIDDEN | StatusCode::UNAUTHORIZED => (
                false,
                Some(format!(
                    "Repository '{repo}' was not found or is private (HTTP {}).",
                    resp.status.as_u16()
                )),
                true,
            ),
            other => (
                false,
                Some(format!(
                    "Unable to verify repository '{repo}' (GitHub API HTTP {}).",
                    other.as_u16()
                )),
                false,
            ),
        };

        if should_cache {
            let mut cache = self.inner.repo_cache.write().expect("repo cache lock");
            cache.insert(
                repo.to_string(),
                CachedRepoCheck {
                    accessible,
                    reason: reason.clone(),
                    checked_at: Instant::now(),
                },
            );
        }

        (accessible, reason)
    }
}

impl NodeAdapter for GitHubPublicAdapter {
    fn id(&self) -> &str {
        &self.inner.config.id
    }

    fn kind(&self) -> AdapterKind {
        AdapterKind::Source
    }

    fn start<'a>(
        &'a self,
        host: Arc<dyn NodeAdapterHost>,
    ) -> BoxFuture<'a, Result<(), AdapterError>> {
        Box::pin(async move {
            *self.inner.host.write().expect("host lock") = Some(Arc::clone(&host));
            *self.inner.health.write().expect("health lock") = AdapterHealth::Healthy;
            host.update_status(&self.inner.config.id, AdapterHealth::Healthy)
                .await;

            // Start pollers for any subscriptions that arrived before `start()`,
            // enforcing `max_active_pollers` deterministically.
            let mut demand = self.inner.demand.lock().await;
            let cap = self.inner.config.max_active_pollers;
            let mut active_now = count_active_pollers(&demand);
            let mut repos: Vec<String> = demand.keys().cloned().collect();
            repos.sort();
            for repo in repos {
                if active_now >= cap {
                    break;
                }
                if let Some(entry) = demand.get_mut(&repo) {
                    if entry.refcount > 0 && entry.poller_task.is_none() {
                        spawn_poller_into_entry(
                            Arc::clone(&self.inner),
                            Arc::clone(&host),
                            &repo,
                            entry,
                        );
                        active_now += 1;
                    }
                }
            }
            Ok(())
        })
    }

    fn stop<'a>(&'a self) -> BoxFuture<'a, Result<(), AdapterError>> {
        Box::pin(async move {
            let host = self.inner.host.write().expect("host lock").take();
            let mut demand = self.inner.demand.lock().await;
            for (_, mut entry) in demand.drain() {
                if let Some(t) = entry.teardown_task.take() {
                    t.abort();
                }
                stop_poller_entry(&mut entry);
            }
            drop(demand);

            *self.inner.health.write().expect("health lock") = AdapterHealth::Stopped;
            if let Some(h) = host {
                h.update_status(&self.inner.config.id, AdapterHealth::Stopped)
                    .await;
            }
            Ok(())
        })
    }

    fn health(&self) -> AdapterHealth {
        self.inner.health.read().expect("health lock").clone()
    }

    fn on_subscriptions_changed<'a>(
        &'a self,
        topic: &'a str,
        active_subs: &'a [CompiledSubscription],
    ) -> BoxFuture<'a, ()> {
        Box::pin(async move {
            if topic != self.inner.config.topic {
                return;
            }

            // Compute deduplicated refcounts of active `exact.repo` values across all subscribers.
            let mut new_counts: BTreeMap<String, usize> = BTreeMap::new();
            for sub in active_subs {
                let mut sub_repos = BTreeSet::new();
                for raw in extract_exact_repos(&sub.filters) {
                    if let Some(canonical) = canonicalize_repo(&raw) {
                        sub_repos.insert(canonical);
                    }
                }
                for repo in sub_repos {
                    *new_counts.entry(repo).or_insert(0) += 1;
                }
            }

            let host = self.inner.host.read().expect("host lock").clone();
            let mut demand = self.inner.demand.lock().await;

            // Schedule grace-window teardown (or immediate teardown when grace == 0) FIRST so
            // freed slots are immediately reusable under `max_active_pollers`.
            let dropped_repos: Vec<String> = demand
                .keys()
                .filter(|r| !new_counts.contains_key(*r))
                .cloned()
                .collect();

            for repo in dropped_repos {
                if let Some(entry) = demand.get_mut(&repo) {
                    entry.refcount = 0;
                    if self.inner.config.teardown_grace.is_zero() {
                        if let Some(t) = entry.teardown_task.take() {
                            t.abort();
                        }
                        stop_poller_entry(entry);
                        demand.remove(&repo);
                    } else if entry.teardown_task.is_none() {
                        let inner_clone = Arc::clone(&self.inner);
                        let repo_clone = repo.clone();
                        let grace = self.inner.config.teardown_grace;
                        entry.teardown_task = Some(tokio::spawn(async move {
                            tokio::time::sleep(grace).await;
                            let mut guard = inner_clone.demand.lock().await;
                            if let Some(e) = guard.get_mut(&repo_clone) {
                                if e.refcount == 0 {
                                    stop_poller_entry(e);
                                    guard.remove(&repo_clone);
                                }
                            }
                        }));
                    }
                }
            }

            let cap = self.inner.config.max_active_pollers;
            let mut active_now = count_active_pollers(&demand);

            // Activate or increment active repos (deterministic BTreeMap order), enforcing cap.
            for (repo, count) in &new_counts {
                if let Some(entry) = demand.get_mut(repo) {
                    entry.refcount = *count;
                    if let Some(teardown) = entry.teardown_task.take() {
                        teardown.abort();
                    }
                    if entry.poller_task.is_none() && active_now < cap {
                        if let Some(ref h) = host {
                            spawn_poller_into_entry(
                                Arc::clone(&self.inner),
                                Arc::clone(h),
                                repo,
                                entry,
                            );
                            active_now += 1;
                        }
                    }
                } else {
                    let mut entry = RepoDemandEntry {
                        refcount: *count,
                        poller_cancel: None,
                        poller_task: None,
                        teardown_task: None,
                    };
                    if active_now < cap {
                        if let Some(ref h) = host {
                            spawn_poller_into_entry(
                                Arc::clone(&self.inner),
                                Arc::clone(h),
                                repo,
                                &mut entry,
                            );
                            active_now += 1;
                        }
                    }
                    demand.insert(repo.clone(), entry);
                }
            }
        })
    }

    fn validate_subscription<'a>(
        &'a self,
        topic: &'a str,
        filters: &'a [Filter],
    ) -> BoxFuture<'a, Vec<SubscriptionDiagnostic>> {
        Box::pin(async move {
            if topic != self.inner.config.topic {
                return Vec::new();
            }

            let raw_repos = extract_exact_repos(filters);
            if raw_repos.is_empty() {
                return vec![SubscriptionDiagnostic {
                    severity: DiagnosticSeverity::Error,
                    code: DiagnosticCode::InvalidGithubRepoFormat,
                    message: "Subscriptions to github-public require at least one exact.repo filter (\"owner/repo\").".to_string(),
                    remediation: Some(
                        r#"Add { exact: { repo: "owner/repo" } } to filters."#.to_string(),
                    ),
                    suggested_filter: Some(json!({ "exact": { "repo": "owner/repo" } })),
                }];
            }

            let (active_pollers, already_tracked) = {
                let demand = self.inner.demand.lock().await;
                let active = count_active_pollers(&demand);
                let tracked: BTreeSet<String> = demand
                    .iter()
                    .filter(|(_, e)| e.poller_task.is_some())
                    .map(|(k, _)| k.clone())
                    .collect();
                (active, tracked)
            };
            let cap = self.inner.config.max_active_pollers;
            let mut new_pollers_needed = 0usize;

            let mut diagnostics = Vec::new();
            let mut checked = BTreeSet::new();

            for raw in raw_repos {
                let Some(canonical) = canonicalize_repo(&raw) else {
                    diagnostics.push(SubscriptionDiagnostic {
                        severity: DiagnosticSeverity::Error,
                        code: DiagnosticCode::InvalidGithubRepoFormat,
                        message: format!(
                            "Filter exact.repo = {raw:?} is not a valid \"owner/repo\" repository slug."
                        ),
                        remediation: Some(
                            r#"Use { exact: { repo: "owner/repo" } } without a URL prefix or extra path segments."#.to_string(),
                        ),
                        suggested_filter: None,
                    });
                    continue;
                };

                if !checked.insert(canonical.clone()) {
                    continue;
                }

                if !already_tracked.contains(&canonical) {
                    if active_pollers.saturating_add(new_pollers_needed) >= cap {
                        diagnostics.push(SubscriptionDiagnostic {
                            severity: DiagnosticSeverity::Error,
                            code: DiagnosticCode::UnmonitoredRepo,
                            message: format!(
                                "Maximum active github-public pollers ({cap}) reached; cannot watch additional repository '{canonical}'."
                            ),
                            remediation: Some(
                                "Unsubscribe from unused repositories or raise sources[].maxActivePollers in ~/.config/hyphae/node.json."
                                    .to_string(),
                            ),
                            suggested_filter: None,
                        });
                        continue;
                    }
                    new_pollers_needed += 1;
                }

                let (accessible, reason) = self.check_repo_visibility(&canonical).await;
                if !accessible {
                    diagnostics.push(SubscriptionDiagnostic {
                        severity: DiagnosticSeverity::Error,
                        code: DiagnosticCode::RepoNotFoundOrPrivate,
                        message: reason.unwrap_or_else(|| {
                            format!("Repository '{canonical}' not found or is private.")
                        }),
                        remediation: Some(LOCAL_PRIVATE_REMEDIATION.to_string()),
                        suggested_filter: None,
                    });
                }
            }

            diagnostics
        })
    }
}

// ============================================================================
// ETag Poller Task & HTTP Client
// ============================================================================

struct RawHttpResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

fn build_http_client() -> Result<HttpClient, AdapterError> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| AdapterError::Http(format!("TLS protocol setup failed: {e}")))?
    .with_root_certificates(root_store)
    .with_no_client_auth();

    let connector = hyper_rustls::HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http()
        .enable_http1()
        .build();

    Ok(Client::builder(TokioExecutor::new()).build(connector))
}

async fn github_get(
    inner: &Inner,
    url: &str,
    token: Option<&str>,
    if_none_match: Option<&str>,
) -> Result<RawHttpResponse, AdapterError> {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(url)
        .header(header::ACCEPT, "application/vnd.github+json")
        .header(header::USER_AGENT, &inner.config.user_agent)
        .header("x-github-api-version", "2022-11-28");

    if let Some(etag) = if_none_match {
        builder = builder.header(header::IF_NONE_MATCH, etag);
    }
    if let Some(tok) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {tok}"));
    }

    let req = builder
        .body(Empty::<Bytes>::new())
        .map_err(|e| AdapterError::Http(format!("failed to build HTTP request: {e}")))?;

    let resp = tokio::time::timeout(inner.config.http_timeout, inner.client.request(req))
        .await
        .map_err(|_| AdapterError::Timeout(format!("GET {url} timed out")))?
        .map_err(|e| AdapterError::Http(format!("GET {url} failed: {e}")))?;

    let status = resp.status();
    let headers = resp.headers().clone();

    let mut collected = Vec::new();
    let mut body_stream = resp.into_body();
    while let Some(frame_res) = body_stream.frame().await {
        let frame = frame_res.map_err(|e| AdapterError::Http(format!("body read error: {e}")))?;
        if let Some(data) = frame.data_ref() {
            if collected.len() + data.len() > MAX_HTTP_RESPONSE_BYTES {
                return Err(AdapterError::PayloadTooLarge(format!(
                    "GitHub API response from {url} exceeded {MAX_HTTP_RESPONSE_BYTES} bytes"
                )));
            }
            collected.extend_from_slice(data);
        }
    }

    Ok(RawHttpResponse {
        status,
        headers,
        body: Bytes::from(collected),
    })
}

fn count_active_pollers(demand: &HashMap<String, RepoDemandEntry>) -> usize {
    demand.values().filter(|e| e.poller_task.is_some()).count()
}

fn stop_poller_entry(entry: &mut RepoDemandEntry) {
    if let Some(cancel) = entry.poller_cancel.take() {
        let _ = cancel.send(true);
    }
    if let Some(task) = entry.poller_task.take() {
        task.abort();
    }
}

fn spawn_poller_into_entry(
    inner: Arc<Inner>,
    host: Arc<dyn NodeAdapterHost>,
    repo: &str,
    entry: &mut RepoDemandEntry,
) {
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let repo_owned = repo.to_string();
    let task = tokio::spawn(async move {
        run_repo_etag_poller(inner, host, repo_owned, cancel_rx).await;
    });
    entry.poller_cancel = Some(cancel_tx);
    entry.poller_task = Some(task);
}

fn parse_header_u64(headers: &HeaderMap, name: &str) -> Option<u64> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
}

fn adaptive_backoff_multiplier(consecutive_304: u32) -> u32 {
    match consecutive_304 {
        0..=1 => 1,
        2..=3 => 2,
        _ => 5,
    }
}

/// Computes a clean, bounded rate-limit backoff from GitHub `Retry-After` or
/// `X-RateLimit-Remaining: 0` + `X-RateLimit-Reset` headers (capped at `MAX_RATE_LIMIT_BACKOFF_SECS`
/// and never below `min_poll_interval`).
fn compute_rate_limit_backoff(
    headers: &HeaderMap,
    poll_base: Duration,
    min_poll_interval: Duration,
    now_secs: u64,
) -> Duration {
    let max_cap = Duration::from_secs(MAX_RATE_LIMIT_BACKOFF_SECS).max(min_poll_interval);
    if let Some(retry_after) = parse_header_u64(headers, "retry-after") {
        let bounded_secs = retry_after.clamp(1, MAX_RATE_LIMIT_BACKOFF_SECS);
        return Duration::from_secs(bounded_secs)
            .max(min_poll_interval)
            .min(max_cap);
    }
    let remaining = parse_header_u64(headers, "x-ratelimit-remaining");
    let reset_epoch = parse_header_u64(headers, "x-ratelimit-reset");
    if remaining == Some(0) {
        if let Some(reset_secs) = reset_epoch {
            let wait_secs = reset_secs
                .saturating_sub(now_secs)
                .clamp(1, MAX_RATE_LIMIT_BACKOFF_SECS);
            return Duration::from_secs(wait_secs)
                .max(min_poll_interval)
                .min(max_cap);
        }
    }
    poll_base
        .saturating_mul(5)
        .max(min_poll_interval)
        .min(max_cap)
}

async fn run_repo_etag_poller(
    inner: Arc<Inner>,
    host: Arc<dyn NodeAdapterHost>,
    repo: String,
    mut cancel_rx: watch::Receiver<bool>,
) {
    let url = format!(
        "{}/repos/{repo}/events",
        inner.config.api_base_url.trim_end_matches('/')
    );
    let mut etag: Option<String> = None;
    let mut consecutive_304: u32 = 0;

    loop {
        if *cancel_rx.borrow() {
            break;
        }

        inner.counters.polls_total.fetch_add(1, Ordering::Relaxed);
        let repo_token = inner.config.token_for_repo(&repo);
        let resp = github_get(&inner, &url, repo_token, etag.as_deref()).await;

        let next_delay = match resp {
            Ok(raw) => {
                if let Some(new_etag) = raw
                    .headers
                    .get(header::ETAG)
                    .and_then(|v| v.to_str().ok())
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    etag = Some(new_etag.to_string());
                }

                let poll_base = match parse_header_u64(&raw.headers, "x-poll-interval") {
                    Some(secs) => Duration::from_secs(secs).max(inner.config.min_poll_interval),
                    None => inner
                        .config
                        .base_poll_interval
                        .max(inner.config.min_poll_interval),
                };

                let remaining = parse_header_u64(&raw.headers, "x-ratelimit-remaining");

                match raw.status {
                    StatusCode::NOT_MODIFIED => {
                        // 304 Not Modified consumes 0 GitHub API quota.
                        inner.counters.polls_304.fetch_add(1, Ordering::Relaxed);
                        consecutive_304 = consecutive_304.saturating_add(1);
                        let mult = adaptive_backoff_multiplier(consecutive_304);
                        poll_base.saturating_mul(mult)
                    }
                    StatusCode::OK => {
                        inner.counters.polls_200.fetch_add(1, Ordering::Relaxed);
                        // Snap back immediately to base interval on 200 activity.
                        consecutive_304 = 0;

                        if let Ok(Value::Array(items)) = serde_json::from_slice::<Value>(&raw.body)
                        {
                            // GitHub returns newest-first; publish oldest-first for clean ordering.
                            for item in items.iter().rev() {
                                if let Some(ev) = normalize_github_api_event(&repo, item) {
                                    let is_new = {
                                        let mut dedup = inner.dedup.lock().await;
                                        let set = dedup
                                            .entry(repo.clone())
                                            .or_insert_with(RepoDedupSet::new);
                                        set.insert(ev.id.clone())
                                    };
                                    if is_new {
                                        let _ = host.publish_event(&inner.config.topic, ev).await;
                                    }
                                }
                            }
                        }

                        if remaining == Some(0) {
                            let now_secs = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .map(|d| d.as_secs())
                                .unwrap_or(0);
                            compute_rate_limit_backoff(
                                &raw.headers,
                                poll_base,
                                inner.config.min_poll_interval,
                                now_secs,
                            )
                        } else if remaining.is_some_and(|r| r <= 5) {
                            poll_base.saturating_mul(2)
                        } else {
                            poll_base
                        }
                    }
                    StatusCode::FORBIDDEN | StatusCode::TOO_MANY_REQUESTS => {
                        let now_secs = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0);
                        compute_rate_limit_backoff(
                            &raw.headers,
                            poll_base,
                            inner.config.min_poll_interval,
                            now_secs,
                        )
                    }
                    StatusCode::NOT_FOUND | StatusCode::GONE => {
                        // Invalidate cache if repo vanished or turned private.
                        inner
                            .repo_cache
                            .write()
                            .expect("repo cache lock")
                            .remove(&repo);
                        poll_base.saturating_mul(5)
                    }
                    _ => poll_base.saturating_mul(2),
                }
            }
            Err(_) => inner
                .config
                .base_poll_interval
                .max(inner.config.min_poll_interval)
                .saturating_mul(2),
        };

        tokio::select! {
            _ = cancel_rx.changed() => {
                if *cancel_rx.borrow() {
                    break;
                }
            }
            () = tokio::time::sleep(next_delay) => {}
        }
    }
}

// ============================================================================
// GitHub Events API -> CloudEvents v1.0 Normalization
// ============================================================================

fn now_rfc3339_seconds() -> String {
    format_rfc3339_seconds(now_unix_ms())
}

/// Normalizes a single GitHub REST Events API object (`GET /repos/{owner}/{repo}/events`)
/// into the **exact same CloudEvents v1.0 schema** produced by [`crate::adapters::webhooks::GitHubWebhookAdapter`].
pub fn normalize_github_api_event(repo_fallback: &str, item: &Value) -> Option<CloudEvent> {
    let obj = item.as_object()?;
    let api_type = obj.get("type").and_then(Value::as_str)?;
    let event_id = obj.get("id").and_then(|v| match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    })?;

    let webhook_event = match api_type {
        "PullRequestEvent" => "pull_request",
        "IssuesEvent" => "issues",
        "IssueCommentEvent" => "issue_comment",
        "PullRequestReviewEvent" => "pull_request_review",
        "PullRequestReviewCommentEvent" => "pull_request_review_comment",
        "PushEvent" => "push",
        "ReleaseEvent" => "release",
        "CheckRunEvent" => "check_run",
        "WorkflowRunEvent" => "workflow_run",
        _ => return None,
    };

    let repo_name = obj
        .get("repo")
        .and_then(|r| r.get("name"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(repo_fallback);

    let mut synthetic: Map<String, Value> = obj
        .get("payload")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();

    // Align Events API quirks with webhook schema so downstream filters see identical CloudEvents.
    if webhook_event == "pull_request_review"
        && synthetic.get("action").and_then(Value::as_str) == Some("created")
    {
        synthetic.insert("action".to_string(), json!("submitted"));
    }
    if webhook_event == "push" && !synthetic.contains_key("after") {
        if let Some(head) = synthetic.get("head").cloned() {
            synthetic.insert("after".to_string(), head);
        }
    }

    synthetic
        .entry("repository".to_string())
        .or_insert_with(|| json!({ "full_name": repo_name }));

    if !synthetic.contains_key("sender") {
        if let Some(actor) = obj.get("actor").and_then(Value::as_object) {
            if let Some(login) = actor.get("login").and_then(Value::as_str) {
                let actor_type = actor.get("type").and_then(Value::as_str).unwrap_or("User");
                synthetic.insert(
                    "sender".to_string(),
                    json!({ "login": login, "type": actor_type }),
                );
            }
        }
    }

    let created_at = obj
        .get("created_at")
        .and_then(Value::as_str)
        .filter(|ts| is_valid_rfc3339_strict(ts))
        .map(ToString::to_string)
        .unwrap_or_else(now_rfc3339_seconds);

    match normalize_github_webhook(
        webhook_event,
        &event_id,
        &Value::Object(synthetic),
        &created_at,
    ) {
        GitHubNormalizeOutcome::Publish(ce) => {
            let val = serde_json::to_value(&*ce).ok()?;
            let (validated, _) = check_cloudevent_v2(&val).ok()?;
            Some(validated)
        }
        GitHubNormalizeOutcome::Ignore(_) => None,
    }
}

// ============================================================================
// Repo Slug Validation & Filter Extraction Helpers
// ============================================================================

/// Validates and canonicalizes a `repoTokens` scope pattern fail-closed.
///
/// Accepted forms:
/// - Exact `owner/repo` -> normalized lowercase `"owner/repo"`
/// - Owner wildcard `owner/*` -> normalized lowercase `"owner/*"`
/// - Bare `owner` -> normalized lowercase `"owner/*"`
///
/// Rejects `*`, `*/*`, `*/repo`, `..`, leading-dot owners, empty strings, extra path segments,
/// partial wildcards (`owner/foo*`), and invalid characters fail-closed.
pub fn normalize_repo_token_pattern(raw: &str) -> Result<String, AdapterError> {
    static OWNER_RE: OnceLock<Regex> = OnceLock::new();
    static REPO_SEG_RE: OnceLock<Regex> = OnceLock::new();
    let owner_re =
        OWNER_RE.get_or_init(|| Regex::new(r"^[A-Za-z0-9_.-]{1,39}$").expect("valid owner regex"));
    let repo_re = REPO_SEG_RE
        .get_or_init(|| Regex::new(r"^[A-Za-z0-9_.-]{1,100}$").expect("valid repo segment regex"));

    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.contains("..") {
        return Err(AdapterError::Config(format!(
            "invalid GitHub repoTokens pattern {raw:?}: expected \"owner/*\", \"owner/repo\", or \"owner\""
        )));
    }

    let is_valid_owner =
        |s: &str| owner_re.is_match(s) && s != "." && !s.starts_with('.') && !s.contains("..");
    let is_valid_repo = |s: &str| repo_re.is_match(s) && s != "." && !s.contains("..");

    let parts: Vec<&str> = trimmed.split('/').collect();
    match parts.as_slice() {
        [owner] if is_valid_owner(owner) => Ok(format!("{}/*", owner.to_ascii_lowercase())),
        [owner, "*"] if is_valid_owner(owner) => Ok(format!("{}/*", owner.to_ascii_lowercase())),
        [owner, repo] if is_valid_owner(owner) && is_valid_repo(repo) => Ok(format!(
            "{}/{}",
            owner.to_ascii_lowercase(),
            repo.to_ascii_lowercase()
        )),
        _ => Err(AdapterError::Config(format!(
            "invalid GitHub repoTokens pattern {raw:?}: expected \"owner/*\", \"owner/repo\", or \"owner\" (global wildcards '*'/'*/*' and traversal '..' are forbidden)"
        ))),
    }
}

/// Validates and canonicalizes an `owner/repo` slug (lowercase, strict GitHub slug regex).
pub fn canonicalize_repo(raw: &str) -> Option<String> {
    static REPO_RE: OnceLock<Regex> = OnceLock::new();
    let re = REPO_RE.get_or_init(|| {
        Regex::new(r"^[A-Za-z0-9_.-]{1,39}/[A-Za-z0-9_.-]{1,100}$").expect("valid repo regex")
    });
    let trimmed = raw.trim();
    if trimmed.contains("..") || !re.is_match(trimmed) {
        return None;
    }
    Some(trimmed.to_ascii_lowercase())
}

/// Extracts all positive `exact.repo` values from a CloudEvents Subscriptions API filter list,
/// traversing `all` and `any` while intentionally skipping `not` branches.
pub fn extract_exact_repos(filters: &[Filter]) -> Vec<String> {
    let mut out = Vec::new();
    collect_exact_repos(filters, &mut out);
    out
}

fn collect_exact_repos(filters: &[Filter], out: &mut Vec<String>) {
    for filter in filters {
        match filter {
            Filter::Exact(pairs) => {
                if let Some(repo) = pairs.get("repo") {
                    out.push(repo.clone());
                }
            }
            Filter::All(children) | Filter::Any(children) => {
                collect_exact_repos(children, out);
            }
            Filter::Prefix(_) | Filter::Suffix(_) | Filter::Not(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    #[test]
    fn canonicalize_repo_rejects_malformed_and_traversal_inputs() {
        assert_eq!(
            canonicalize_repo("Anthropics/Claude-Code"),
            Some("anthropics/claude-code".to_string())
        );
        assert_eq!(
            canonicalize_repo("owner/repo.rs"),
            Some("owner/repo.rs".to_string())
        );
        assert_eq!(canonicalize_repo("https://github.com/a/b"), None);
        assert_eq!(canonicalize_repo("a/b/c"), None);
        assert_eq!(canonicalize_repo("../secret"), None);
        assert_eq!(canonicalize_repo("owner/.."), None);
        assert_eq!(canonicalize_repo(""), None);
        assert_eq!(canonicalize_repo("onlyowner"), None);
    }

    #[test]
    fn normalize_repo_token_pattern_accepts_exact_wildcard_bare_and_rejects_invalid() {
        assert_eq!(
            normalize_repo_token_pattern("Bayfold/Special-Repo").unwrap(),
            "bayfold/special-repo"
        );
        assert_eq!(
            normalize_repo_token_pattern("Bayfold/*").unwrap(),
            "bayfold/*"
        );
        assert_eq!(normalize_repo_token_pattern("Bowd").unwrap(), "bowd/*");
        assert_eq!(
            normalize_repo_token_pattern("acme/.github").unwrap(),
            "acme/.github"
        );

        for bad in [
            "",
            "   ",
            "*",
            "*/*",
            "*/repo",
            "../bad",
            "owner/..",
            "owner/.",
            "./*",
            ".",
            "owner/",
            "/repo",
            "a/b/c",
            "owner/foo*",
            "owner/re po",
            "https://github.com/a/b",
        ] {
            assert!(
                normalize_repo_token_pattern(bad).is_err(),
                "expected pattern {bad:?} to fail closed"
            );
        }
    }

    #[test]
    fn token_for_repo_precedence_and_configured_scopes_never_leak_cross_owner() {
        let mut cfg = GitHubPublicConfig::default();
        cfg.repo_tokens.insert(
            "bayfold/*".to_string(),
            Zeroizing::new("hyphae_gh_tok_org_b".to_string()),
        );
        cfg.repo_tokens.insert(
            "bayfold/special".to_string(),
            Zeroizing::new("hyphae_gh_tok_exact_c".to_string()),
        );
        cfg.repo_tokens.insert(
            "bowd/*".to_string(),
            Zeroizing::new("hyphae_gh_tok_personal_a".to_string()),
        );

        assert_eq!(
            cfg.token_for_repo("Bayfold/Special"),
            Some("hyphae_gh_tok_exact_c")
        );
        assert_eq!(
            cfg.token_for_repo("bayfold/other"),
            Some("hyphae_gh_tok_org_b")
        );
        assert_eq!(
            cfg.token_for_repo("bowd/my-app"),
            Some("hyphae_gh_tok_personal_a")
        );
        assert_eq!(cfg.token_for_repo("oss/public-repo"), None);
        assert_eq!(cfg.token_for_repo("other-org/priv"), None);
        assert_eq!(cfg.token_for_repo("../bad"), None);
        assert_eq!(
            cfg.configured_token_scopes(),
            vec![
                "bayfold/*".to_string(),
                "bayfold/special".to_string(),
                "bowd/*".to_string(),
            ]
        );

        // When default github_token is configured, fallback applies and "*" appears in scopes.
        cfg.github_token = Some(Zeroizing::new("hyphae_gh_tok_default".to_string()));
        assert_eq!(
            cfg.token_for_repo("oss/public-repo"),
            Some("hyphae_gh_tok_default")
        );
        assert_eq!(
            cfg.token_for_repo("bayfold/special"),
            Some("hyphae_gh_tok_exact_c")
        );
        assert_eq!(
            cfg.token_for_repo("bayfold/other"),
            Some("hyphae_gh_tok_org_b")
        );
        assert_eq!(
            cfg.configured_token_scopes(),
            vec![
                "*".to_string(),
                "bayfold/*".to_string(),
                "bayfold/special".to_string(),
                "bowd/*".to_string(),
            ]
        );
    }

    #[test]
    fn compute_rate_limit_backoff_bounds_retry_after_and_reset_headers() {
        let min_poll = Duration::from_secs(60);
        let base = Duration::from_secs(60);

        // Retry-After huge value is capped at MAX_RATE_LIMIT_BACKOFF_SECS (600s).
        let mut hdr_huge = HeaderMap::new();
        hdr_huge.insert("retry-after", HeaderValue::from_static("99999999"));
        assert_eq!(
            compute_rate_limit_backoff(&hdr_huge, base, min_poll, 1_000),
            Duration::from_secs(MAX_RATE_LIMIT_BACKOFF_SECS)
        );

        // Retry-After smaller than min_poll_interval floors at min_poll_interval.
        let mut hdr_small = HeaderMap::new();
        hdr_small.insert("retry-after", HeaderValue::from_static("5"));
        assert_eq!(
            compute_rate_limit_backoff(&hdr_small, base, min_poll, 1_000),
            Duration::from_secs(60)
        );

        // Retry-After within bounds honored directly.
        let mut hdr_mid = HeaderMap::new();
        hdr_mid.insert("retry-after", HeaderValue::from_static("120"));
        assert_eq!(
            compute_rate_limit_backoff(&hdr_mid, base, min_poll, 1_000),
            Duration::from_secs(120)
        );

        // X-RateLimit-Remaining: 0 + X-RateLimit-Reset computes bounded delta.
        let mut hdr_reset = HeaderMap::new();
        hdr_reset.insert("x-ratelimit-remaining", HeaderValue::from_static("0"));
        hdr_reset.insert("x-ratelimit-reset", HeaderValue::from_static("1180"));
        assert_eq!(
            compute_rate_limit_backoff(&hdr_reset, base, min_poll, 1_000),
            Duration::from_secs(180)
        );

        // Far-future X-RateLimit-Reset is upper-bounded cleanly.
        let mut hdr_reset_huge = HeaderMap::new();
        hdr_reset_huge.insert("x-ratelimit-remaining", HeaderValue::from_static("0"));
        hdr_reset_huge.insert("x-ratelimit-reset", HeaderValue::from_static("9999999"));
        assert_eq!(
            compute_rate_limit_backoff(&hdr_reset_huge, base, min_poll, 1_000),
            Duration::from_secs(MAX_RATE_LIMIT_BACKOFF_SECS)
        );
    }

    #[test]
    fn adaptive_backoff_progression_matches_1x_2x_5x() {
        assert_eq!(adaptive_backoff_multiplier(0), 1);
        assert_eq!(adaptive_backoff_multiplier(1), 1);
        assert_eq!(adaptive_backoff_multiplier(2), 2);
        assert_eq!(adaptive_backoff_multiplier(3), 2);
        assert_eq!(adaptive_backoff_multiplier(4), 5);
        assert_eq!(adaptive_backoff_multiplier(20), 5);
    }

    #[test]
    fn extract_exact_repos_traverses_all_any_and_skips_not() {
        let filters = vec![
            Filter::All(vec![
                Filter::Exact(BTreeMap::from([("repo".to_string(), "acme/a".to_string())])),
                Filter::Any(vec![
                    Filter::Exact(BTreeMap::from([("repo".to_string(), "acme/b".to_string())])),
                    Filter::Prefix(BTreeMap::from([("repo".to_string(), "acme/".to_string())])),
                ]),
            ]),
            Filter::Not(Box::new(Filter::Exact(BTreeMap::from([(
                "repo".to_string(),
                "acme/excluded".to_string(),
            )])))),
        ];
        assert_eq!(
            extract_exact_repos(&filters),
            vec!["acme/a".to_string(), "acme/b".to_string()]
        );
    }
}
