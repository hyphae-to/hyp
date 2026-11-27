//! Native in-process Rust Event Source Adapters:
//! - [`GitHubWebhookAdapter`]: constant-time `ring::hmac` `X-Hub-Signature-256` verification +
//!   CloudEvents v1.0 normalization matching `src/core/github/normalize.ts` & `src/streams.ts`.

use std::collections::BTreeSet;
use std::sync::{Arc, RwLock};

use http::HeaderMap;
use hyp_crypto::rfc3339::{format_rfc3339_seconds, now_unix_ms};
use hyp_proto::cloudevent::{CloudEvent, MAX_ATTRIBUTE_CHARS, MAX_DATA_BYTES, check_cloudevent_v2};
use hyp_proto::filter::{
    Filter, ObservedTopicStats, SubscriptionDiagnostic, TopicCatalogEntry, TopicMetadata,
    TopicSchema, TopicScope, diagnose_subscription,
};
use regex::Regex;
use ring::hmac;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::sync::OnceLock;
use zeroize::Zeroizing;

use crate::adapters::trait_def::{
    AdapterError, AdapterHealth, AdapterKind, BoxFuture, NodeAdapter, NodeAdapterHost,
    PublishOutcome,
};

pub const MAX_TITLE_CHARS: usize = 200;
pub const MAX_TEXT_CHARS: usize = 1000;
/// CloudEvent extension attribute marking events emitted by external webhook adapters so
/// downstream receivers always cap their trust tier to `ExternalWebhook`.
pub const EXT_SOURCE_KIND: &str = "hyphaesourcekind";
/// Value stamped on [`EXT_SOURCE_KIND`] for all compiled-in webhook adapters.
pub const SOURCE_KIND_EXTERNAL_WEBHOOK: &str = "external-webhook";
const CUT_SUFFIX: &str = "[...]";
const MAX_MENTIONS: usize = 20;
const MAX_LIST_ITEMS: usize = 50;
const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;

/// Computes `sha256=<64 lowercase hex>` HMAC-SHA256 signature header using `ring::hmac`.
pub fn compute_hmac_sha256_header(secret: &[u8], body: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    let tag = hmac::sign(&key, body);
    format!("sha256={}", hex::encode(tag.as_ref()))
}

/// Verifies `sha256=<64 hex>` HMAC-SHA256 signature header in constant time via `ring::hmac`.
///
/// Fails closed if `secret` is empty, `header` is missing, prefix/length is invalid, hex is
/// malformed, or the MAC does not match `body`.
pub fn verify_hmac_sha256_header(
    secret: &[u8],
    body: &[u8],
    header: Option<&str>,
    strict_lowercase_hex: bool,
) -> bool {
    if secret.is_empty() {
        return false;
    }
    let Some(raw) = header else {
        return false;
    };
    let Some(hex_part) = raw.strip_prefix("sha256=") else {
        return false;
    };
    if hex_part.len() != 64 {
        return false;
    }
    if strict_lowercase_hex
        && !hex_part
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return false;
    }
    let Ok(sig_bytes) = hex::decode(hex_part) else {
        return false;
    };
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret);
    hmac::verify(&key, body, &sig_bytes).is_ok()
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

fn now_rfc3339_seconds() -> String {
    format_rfc3339_seconds(now_unix_ms())
}

/// Outcome of ingesting a webhook delivery into an adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookIngestOutcome {
    Published {
        event_id: String,
        outcome: PublishOutcome,
    },
    Ignored {
        reason: String,
    },
}

// ============================================================================
// GitHub Webhook Adapter & Normalizer
// ============================================================================

/// Outcome of normalizing a single GitHub webhook/event payload into a CloudEvent v1.0.
#[derive(Debug, Clone, PartialEq)]
pub enum GitHubNormalizeOutcome {
    Publish(Box<CloudEvent>),
    Ignore(String),
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct GitHubData {
    number: Option<i64>,
    title: Option<String>,
    url: Option<String>,
    state: Option<String>,
    draft: Option<bool>,
    author: Option<String>,
    author_type: Option<String>,
    labels: Vec<String>,
    assignees: Vec<String>,
    branch: Option<String>,
    base: Option<String>,
    head_sha: Option<String>,
    conclusion: Option<String>,
    text: Option<String>,
    mentions: Vec<String>,
    signed_by: Option<String>,
    pr_numbers: Vec<i64>,
    run_id: Option<i64>,
    run_attempt: Option<i64>,
    workflow_path: Option<String>,
}

fn github_published_actions(event: &str) -> Option<Option<&'static [&'static str]>> {
    match event {
        "pull_request" => Some(Some(&[
            "opened",
            "reopened",
            "closed",
            "synchronize",
            "ready_for_review",
            "converted_to_draft",
            "labeled",
            "unlabeled",
            "assigned",
        ])),
        "pull_request_review" => Some(Some(&["submitted", "dismissed"])),
        "pull_request_review_comment" => Some(Some(&["created"])),
        "issues" => Some(Some(&[
            "opened",
            "reopened",
            "closed",
            "labeled",
            "unlabeled",
            "assigned",
        ])),
        "issue_comment" => Some(Some(&["created"])),
        "workflow_run" => Some(Some(&["completed"])),
        "check_run" => Some(Some(&["created", "completed", "rerequested"])),
        "release" => Some(Some(&[
            "published",
            "created",
            "edited",
            "prereleased",
            "released",
        ])),
        "push" | "ping" => Some(None),
        _ => None,
    }
}

fn cut_chars(text: &str, max_chars: usize) -> String {
    let count = text.chars().count();
    if count <= max_chars {
        return text.to_string();
    }
    let keep = max_chars.saturating_sub(CUT_SUFFIX.len());
    let mut out: String = text.chars().take(keep).collect();
    out.push_str(CUT_SUFFIX);
    out
}

fn is_valid_subject(subject: &str) -> bool {
    static SUBJECT_RE: OnceLock<Regex> = OnceLock::new();
    let re = SUBJECT_RE
        .get_or_init(|| Regex::new(r"^[A-Za-z0-9._/-]{1,128}$").expect("valid subject regex"));
    re.is_match(subject)
}

fn is_valid_github_event_name(name: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    let re = RE.get_or_init(|| Regex::new(r"^[a-z_]{1,64}$").expect("valid event re"));
    re.is_match(name)
}

fn extract_signature(text: &str) -> Option<String> {
    static MARKER_RE: OnceLock<Regex> = OnceLock::new();
    let re = MARKER_RE.get_or_init(|| {
        Regex::new(r"<!--\s*agent:([a-z0-9][a-z0-9._-]{0,63})\s*-->").expect("valid marker regex")
    });
    let mut last = None;
    for cap in re.captures_iter(text) {
        if let Some(m) = cap.get(1) {
            last = Some(m.as_str().to_string());
        }
    }
    last
}

fn extract_mentions(text: &str) -> Vec<String> {
    static MARKER_RE: OnceLock<Regex> = OnceLock::new();
    static TOKEN_RE: OnceLock<Regex> = OnceLock::new();
    let marker_re = MARKER_RE.get_or_init(|| {
        Regex::new(r"<!--\s*agent:([a-z0-9][a-z0-9._-]{0,63})\s*-->").expect("valid marker regex")
    });
    let token_re = TOKEN_RE.get_or_init(|| {
        Regex::new(r"agent:([a-z0-9][a-z0-9._-]{0,63})[._-]*").expect("valid mention regex")
    });

    let stripped = marker_re.replace_all(text, " ");
    let bytes = stripped.as_bytes();
    let mut found = Vec::new();
    let mut seen = BTreeSet::new();

    for cap in token_re.captures_iter(&stripped) {
        let Some(full) = cap.get(0) else { continue };
        let Some(inner) = cap.get(1) else { continue };

        // Boundary check before `agent:` matching `(?<![A-Za-z0-9_:/.-])`
        if full.start() > 0 {
            let prev = bytes[full.start() - 1];
            if prev.is_ascii_alphanumeric() || matches!(prev, b'_' | b':' | b'/' | b'.' | b'-') {
                continue;
            }
        }
        // Boundary check after match matching `(?![A-Za-z0-9._-])`
        if full.end() < bytes.len() {
            let next = bytes[full.end()];
            if next.is_ascii_alphanumeric() || matches!(next, b'.' | b'_' | b'-') {
                continue;
            }
        }

        let name = inner.as_str().trim_end_matches(['.', '_', '-']);
        if name.is_empty() {
            continue;
        }
        let mention = format!("agent:{name}");
        if seen.insert(mention.clone()) {
            found.push(mention);
            if found.len() >= MAX_MENTIONS {
                break;
            }
        }
    }
    found
}

fn obj_get<'a>(val: Option<&'a Value>, key: &str) -> Option<&'a Value> {
    val.and_then(Value::as_object).and_then(|m| m.get(key))
}

fn get_str(val: Option<&Value>, key: &str) -> Option<String> {
    obj_get(val, key)
        .and_then(Value::as_str)
        .map(ToString::to_string)
}

fn get_i64(val: Option<&Value>, key: &str) -> Option<i64> {
    obj_get(val, key).and_then(Value::as_i64)
}

fn get_bool(val: Option<&Value>, key: &str) -> Option<bool> {
    obj_get(val, key).and_then(Value::as_bool)
}

fn get_names(val: Option<&Value>, list_key: &str, item_key: &str) -> Vec<String> {
    let Some(items) = obj_get(val, list_key).and_then(Value::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .filter_map(|item| get_str(Some(item), item_key))
        .collect()
}

fn pr_state(pr: Option<&Value>) -> Option<String> {
    let pr = pr?;
    if get_bool(Some(pr), "merged") == Some(true) || get_str(Some(pr), "merged_at").is_some() {
        return Some("merged".to_string());
    }
    get_str(Some(pr), "state")
}

fn fit_github_data(mut data: GitHubData) -> Value {
    data.labels.truncate(MAX_LIST_ITEMS);
    data.assignees.truncate(MAX_LIST_ITEMS);
    data.pr_numbers.truncate(MAX_LIST_ITEMS);

    loop {
        let serialized = serde_json::to_string(&data).unwrap_or_default();
        if serialized.len() <= MAX_DATA_BYTES {
            break;
        }
        let text_chars = data.text.as_ref().map(|t| t.chars().count()).unwrap_or(0);
        if text_chars > CUT_SUFFIX.len() + 50 {
            let next_len = text_chars / 2;
            data.text = data.text.as_deref().map(|t| cut_chars(t, next_len));
        } else if !data.labels.is_empty() {
            data.labels.pop();
        } else if !data.assignees.is_empty() {
            data.assignees.pop();
        } else if !data.mentions.is_empty() {
            data.mentions.pop();
        } else if !data.pr_numbers.is_empty() {
            data.pr_numbers.pop();
        } else if data.text.is_some() {
            data.text = None;
        } else if data
            .title
            .as_ref()
            .is_some_and(|t| t.chars().count() > CUT_SUFFIX.len() + 20)
        {
            if let Some(ref title) = data.title {
                let next_len = title.chars().count() / 2;
                data.title = Some(cut_chars(title, next_len));
            }
        } else {
            break;
        }
    }

    serde_json::to_value(data).expect("GitHubData serialization is infallible")
}

/// Normalizes a GitHub webhook payload into a CloudEvents v1.0 envelope matching `src/core/github/normalize.ts`.
pub fn normalize_github_webhook(
    event_name: &str,
    delivery_id: &str,
    payload: &Value,
    received_at_rfc3339: &str,
) -> GitHubNormalizeOutcome {
    if !payload.is_object() {
        return GitHubNormalizeOutcome::Ignore("payload is not an object".to_string());
    }
    let Some(allowed_actions) = github_published_actions(event_name) else {
        return GitHubNormalizeOutcome::Ignore(format!("event {event_name} is not published"));
    };

    let action = get_str(Some(payload), "action");
    if let Some(actions) = allowed_actions {
        match action.as_deref() {
            Some(act) if actions.contains(&act) => {}
            other => {
                return GitHubNormalizeOutcome::Ignore(format!(
                    "{event_name}.{} is not published",
                    other.unwrap_or("(none)")
                ));
            }
        }
    }

    let repository = obj_get(Some(payload), "repository");
    let repo = get_str(repository, "full_name");

    if event_name == "push" {
        if let Some(default_branch) = get_str(repository, "default_branch") {
            let expected_ref = format!("refs/heads/{default_branch}");
            if get_str(Some(payload), "ref").as_deref() != Some(expected_ref.as_str()) {
                return GitHubNormalizeOutcome::Ignore(
                    "push to a branch other than the default".to_string(),
                );
            }
        }
    }

    let mut data = GitHubData::default();
    let sender = obj_get(Some(payload), "sender");
    data.author = get_str(sender, "login");
    data.author_type = sender.map(|s| {
        if get_str(Some(s), "type").as_deref() == Some("Bot") {
            "Bot".to_string()
        } else {
            "User".to_string()
        }
    });

    let effective_action = if allowed_actions.is_some() {
        action.as_deref()
    } else {
        None
    };

    let subject: Option<String> = match event_name {
        "pull_request" => {
            let pr = obj_get(Some(payload), "pull_request");
            data.number = get_i64(pr, "number").or_else(|| get_i64(Some(payload), "number"));
            data.title = get_str(pr, "title");
            data.url = get_str(pr, "html_url");
            data.state = pr_state(pr);
            data.draft = get_bool(pr, "draft");
            data.labels = get_names(pr, "labels", "name");
            data.assignees = get_names(pr, "assignees", "login");
            data.branch = get_str(obj_get(pr, "head"), "ref");
            data.base = get_str(obj_get(pr, "base"), "ref");
            data.head_sha = get_str(obj_get(pr, "head"), "sha");
            if effective_action == Some("opened") {
                data.text = get_str(pr, "body");
            }
            if let Some(n) = data.number {
                data.pr_numbers = vec![n];
                Some(format!("pull/{n}"))
            } else {
                None
            }
        }
        "pull_request_review" => {
            let pr = obj_get(Some(payload), "pull_request");
            let review = obj_get(Some(payload), "review");
            data.number = get_i64(pr, "number");
            data.title = get_str(pr, "title");
            data.url = get_str(review, "html_url").or_else(|| get_str(pr, "html_url"));
            data.labels = get_names(pr, "labels", "name");
            data.state = get_str(review, "state");
            data.head_sha = get_str(obj_get(pr, "head"), "sha");
            data.text = get_str(review, "body");
            if let Some(n) = data.number {
                data.pr_numbers = vec![n];
                Some(format!("pull/{n}"))
            } else {
                None
            }
        }
        "pull_request_review_comment" => {
            let pr = obj_get(Some(payload), "pull_request");
            let comment = obj_get(Some(payload), "comment");
            data.number = get_i64(pr, "number");
            data.title = get_str(pr, "title");
            data.url = get_str(comment, "html_url").or_else(|| get_str(pr, "html_url"));
            data.labels = get_names(pr, "labels", "name");
            data.text = get_str(comment, "body");
            if let Some(n) = data.number {
                data.pr_numbers = vec![n];
                Some(format!("pull/{n}"))
            } else {
                None
            }
        }
        "issues" => {
            let issue = obj_get(Some(payload), "issue");
            data.number = get_i64(issue, "number");
            data.title = get_str(issue, "title");
            data.url = get_str(issue, "html_url");
            data.state = get_str(issue, "state");
            data.labels = get_names(issue, "labels", "name");
            data.assignees = get_names(issue, "assignees", "login");
            if effective_action == Some("opened") {
                data.text = get_str(issue, "body");
            }
            data.number.map(|n| format!("issues/{n}"))
        }
        "issue_comment" => {
            let issue = obj_get(Some(payload), "issue");
            let comment = obj_get(Some(payload), "comment");
            data.number = get_i64(issue, "number");
            data.title = get_str(issue, "title");
            data.url = get_str(comment, "html_url").or_else(|| get_str(issue, "html_url"));
            data.labels = get_names(issue, "labels", "name");
            data.text = get_str(comment, "body");
            let is_pr = obj_get(issue, "pull_request")
                .map(Value::is_object)
                .unwrap_or(false);
            if is_pr {
                if let Some(n) = data.number {
                    data.pr_numbers = vec![n];
                    Some(format!("pull/{n}"))
                } else {
                    None
                }
            } else {
                data.number.map(|n| format!("issues/{n}"))
            }
        }
        "workflow_run" => {
            let run = obj_get(Some(payload), "workflow_run");
            data.title = get_str(run, "name")
                .or_else(|| get_str(obj_get(Some(payload), "workflow"), "name"));
            data.url = get_str(run, "html_url");
            data.conclusion = get_str(run, "conclusion");
            data.branch = get_str(run, "head_branch");
            data.head_sha = get_str(run, "head_sha");
            let prs = obj_get(run, "pull_requests")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if prs.len() == 1 {
                data.number = get_i64(prs.first(), "number");
            }
            let mut seen_prs = BTreeSet::new();
            for pr in &prs {
                if let Some(n) = get_i64(Some(pr), "number") {
                    if n > 0 && seen_prs.insert(n) {
                        data.pr_numbers.push(n);
                    }
                }
            }
            data.run_id = get_i64(run, "id");
            data.run_attempt = get_i64(run, "run_attempt");
            data.workflow_path = get_str(run, "path");
            data.run_id.map(|id| format!("actions/runs/{id}"))
        }
        "check_run" => {
            let check_run = obj_get(Some(payload), "check_run");
            data.title = get_str(check_run, "name");
            data.url = get_str(check_run, "html_url");
            data.state = get_str(check_run, "status");
            data.conclusion = get_str(check_run, "conclusion");
            data.head_sha = get_str(check_run, "head_sha");
            data.branch = get_str(obj_get(check_run, "check_suite"), "head_branch");
            let prs = obj_get(check_run, "pull_requests")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if prs.len() == 1 {
                data.number = get_i64(prs.first(), "number");
            }
            let mut seen_prs = BTreeSet::new();
            for pr in &prs {
                if let Some(n) = get_i64(Some(pr), "number") {
                    if n > 0 && seen_prs.insert(n) {
                        data.pr_numbers.push(n);
                    }
                }
            }
            data.run_id = get_i64(check_run, "id");
            data.run_id.map(|id| format!("actions/runs/{id}"))
        }
        "release" => {
            let release = obj_get(Some(payload), "release");
            let tag = get_str(release, "tag_name");
            data.title = get_str(release, "name").or_else(|| tag.clone());
            data.url = get_str(release, "html_url");
            data.draft = get_bool(release, "draft");
            data.state = if get_bool(release, "prerelease") == Some(true) {
                Some("prerelease".to_string())
            } else {
                Some("published".to_string())
            };
            data.branch = get_str(release, "target_commitish");
            data.text = get_str(release, "body");
            tag.map(|t| format!("releases/{t}"))
        }
        "push" => {
            let git_ref = get_str(Some(payload), "ref").unwrap_or_default();
            data.branch = git_ref.strip_prefix("refs/heads/").map(ToString::to_string);
            data.head_sha =
                get_str(Some(payload), "after").or_else(|| get_str(Some(payload), "head"));
            data.url = get_str(Some(payload), "compare");
            if git_ref.starts_with("refs/heads/") {
                Some(git_ref)
            } else {
                None
            }
        }
        _ => None,
    };

    if let Some(full_text) = data.text.take() {
        data.mentions = extract_mentions(&full_text);
        data.signed_by = if data.author_type.as_deref() == Some("Bot") {
            extract_signature(&full_text)
        } else {
            None
        };
        data.text = Some(cut_chars(&full_text, MAX_TEXT_CHARS));
    }
    if let Some(title) = data.title.take() {
        data.title = Some(cut_chars(&title, MAX_TITLE_CHARS));
    }

    let org = get_str(obj_get(Some(payload), "organization"), "login");
    let source = if let Some(ref r) = repo {
        format!("github.com/{r}")
    } else if let Some(ref o) = org {
        format!("github.com/{o}")
    } else {
        "github.com".to_string()
    };

    let event_type = match effective_action {
        Some(act) => format!("com.github.{event_name}.{act}"),
        None => format!("com.github.{event_name}"),
    };

    let mut ce = CloudEvent::new(delivery_id, source, event_type, fit_github_data(data));
    ce.time = Some(received_at_rfc3339.to_string());

    if let Some(subj) = subject {
        if subj.len() <= MAX_ATTRIBUTE_CHARS && is_valid_subject(&subj) {
            ce.subject = Some(subj);
        }
    }
    if let Some(r) = repo {
        if !r.is_empty() && r.len() <= MAX_ATTRIBUTE_CHARS {
            ce.set_extension("repo", r);
        }
    }
    if let Some(act) = effective_action {
        if !act.is_empty() && act.len() <= MAX_ATTRIBUTE_CHARS {
            ce.set_extension("action", act);
        }
    }
    if let Some(actor) = ce
        .data
        .as_ref()
        .and_then(|d| d.get("author"))
        .and_then(Value::as_str)
        .map(ToString::to_string)
    {
        if !actor.is_empty() && actor.len() <= MAX_ATTRIBUTE_CHARS {
            ce.set_extension("actor", actor);
        }
    }
    ce.set_extension(EXT_SOURCE_KIND, SOURCE_KIND_EXTERNAL_WEBHOOK);

    GitHubNormalizeOutcome::Publish(Box::new(ce))
}

/// Configuration for [`GitHubWebhookAdapter`].
#[derive(Debug, Clone)]
pub struct GitHubWebhookConfig {
    pub id: String,
    pub topic: String,
    pub secret: Zeroizing<String>,
    pub allowed_repos: Vec<String>,
    pub allowed_orgs: Vec<String>,
    pub max_body_bytes: usize,
}

impl GitHubWebhookConfig {
    pub fn new(id: impl Into<String>, topic: impl Into<String>, secret: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            topic: topic.into(),
            secret: Zeroizing::new(secret.into()),
            allowed_repos: Vec::new(),
            allowed_orgs: Vec::new(),
            max_body_bytes: DEFAULT_MAX_BODY_BYTES,
        }
    }
}

/// In-process native Rust GitHub webhook Event Source Adapter.
pub struct GitHubWebhookAdapter {
    config: GitHubWebhookConfig,
    health: RwLock<AdapterHealth>,
    host: RwLock<Option<Arc<dyn NodeAdapterHost>>>,
}

impl GitHubWebhookAdapter {
    pub fn new(config: GitHubWebhookConfig) -> Self {
        Self {
            config,
            health: RwLock::new(AdapterHealth::Stopped),
            host: RwLock::new(None),
        }
    }

    pub fn topic(&self) -> &str {
        &self.config.topic
    }

    pub fn config(&self) -> &GitHubWebhookConfig {
        &self.config
    }

    /// Verifies `X-Hub-Signature-256`, normalizes the webhook delivery into a CloudEvent v1.0,
    /// enforces optional repo/org allowlists, and publishes it to the attached `NodeAdapterHost`.
    pub async fn ingest_webhook(
        &self,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<WebhookIngestOutcome, AdapterError> {
        if body.len() > self.config.max_body_bytes {
            return Err(AdapterError::PayloadTooLarge(format!(
                "webhook body {} bytes exceeds limit {}",
                body.len(),
                self.config.max_body_bytes
            )));
        }

        let sig_header = header_str(headers, "x-hub-signature-256");
        if !verify_hmac_sha256_header(self.config.secret.as_bytes(), body, sig_header, true) {
            return Err(AdapterError::Unauthorized(
                "invalid or missing X-Hub-Signature-256".to_string(),
            ));
        }

        let event_name = header_str(headers, "x-github-event")
            .ok_or_else(|| AdapterError::InvalidInput("missing X-GitHub-Event header".into()))?;

        if !is_valid_github_event_name(event_name) {
            return Err(AdapterError::InvalidInput(
                "malformed X-GitHub-Event header".into(),
            ));
        }

        // B8: ALWAYS derive deterministic event ID from SHA-256 of the raw HMAC-verified body
        // rather than trusting the unsigned `X-GitHub-Delivery` header.
        let deterministic_id = format!("gh-{}", hex::encode(Sha256::digest(body)));

        let payload: Value = serde_json::from_slice(body)
            .map_err(|e| AdapterError::InvalidInput(format!("invalid JSON body: {e}")))?;

        let ce = match normalize_github_webhook(
            event_name,
            &deterministic_id,
            &payload,
            &now_rfc3339_seconds(),
        ) {
            GitHubNormalizeOutcome::Publish(ev) => *ev,
            GitHubNormalizeOutcome::Ignore(reason) => {
                return Ok(WebhookIngestOutcome::Ignored { reason });
            }
        };

        if !self.config.allowed_repos.is_empty() || !self.config.allowed_orgs.is_empty() {
            let repo_lower = ce
                .extensions
                .get("repo")
                .and_then(Value::as_str)
                .map(str::to_ascii_lowercase)
                .unwrap_or_default();
            let owner = repo_lower.split('/').next().unwrap_or("");
            let repo_ok = !repo_lower.is_empty()
                && self
                    .config
                    .allowed_repos
                    .iter()
                    .any(|r| r.trim().eq_ignore_ascii_case(&repo_lower));
            let org_ok = !owner.is_empty()
                && self
                    .config
                    .allowed_orgs
                    .iter()
                    .any(|o| o.trim().eq_ignore_ascii_case(owner));
            if !repo_ok && !org_ok {
                return Ok(WebhookIngestOutcome::Ignored {
                    reason: "repo_not_allowed".to_string(),
                });
            }
        }

        let ce_val = serde_json::to_value(&ce)
            .map_err(|e| AdapterError::Internal(format!("CloudEvent serialization failed: {e}")))?;
        let (validated, _) =
            check_cloudevent_v2(&ce_val).map_err(|e| AdapterError::InvalidInput(e.to_string()))?;

        let host = self
            .host
            .read()
            .expect("host lock")
            .clone()
            .ok_or_else(|| AdapterError::NotRunning(self.config.id.clone()))?;

        let event_id = validated.id.clone();
        let outcome = host.publish_event(&self.config.topic, validated).await?;
        Ok(WebhookIngestOutcome::Published { event_id, outcome })
    }
}

impl NodeAdapter for GitHubWebhookAdapter {
    fn id(&self) -> &str {
        &self.config.id
    }

    fn kind(&self) -> AdapterKind {
        AdapterKind::Source
    }

    fn start<'a>(
        &'a self,
        host: Arc<dyn NodeAdapterHost>,
    ) -> BoxFuture<'a, Result<(), AdapterError>> {
        Box::pin(async move {
            if self.config.secret.is_empty() {
                return Err(AdapterError::Config(
                    "GitHub webhook secret must not be empty".to_string(),
                ));
            }
            *self.host.write().expect("host lock") = Some(Arc::clone(&host));
            *self.health.write().expect("health lock") = AdapterHealth::Healthy;
            host.update_status(&self.config.id, AdapterHealth::Healthy)
                .await;
            Ok(())
        })
    }

    fn stop<'a>(&'a self) -> BoxFuture<'a, Result<(), AdapterError>> {
        Box::pin(async move {
            let host = self.host.write().expect("host lock").take();
            *self.health.write().expect("health lock") = AdapterHealth::Stopped;
            if let Some(h) = host {
                h.update_status(&self.config.id, AdapterHealth::Stopped)
                    .await;
            }
            Ok(())
        })
    }

    fn health(&self) -> AdapterHealth {
        self.health.read().expect("health lock").clone()
    }

    fn validate_subscription<'a>(
        &'a self,
        topic: &'a str,
        filters: &'a [Filter],
    ) -> BoxFuture<'a, Vec<SubscriptionDiagnostic>> {
        Box::pin(async move {
            if topic != self.config.topic {
                return Vec::new();
            }
            let catalog = vec![TopicCatalogEntry {
                topic: self.config.topic.clone(),
                has_provisioned_publisher: true,
                metadata: Some(TopicMetadata {
                    kind: Some("github-webhook".to_string()),
                    description: Some("Normalized GitHub webhook CloudEvents".to_string()),
                    scope: if !self.config.allowed_repos.is_empty()
                        || !self.config.allowed_orgs.is_empty()
                    {
                        Some(TopicScope {
                            repos: self.config.allowed_repos.clone(),
                            orgs: self.config.allowed_orgs.clone(),
                            subjects: Vec::new(),
                        })
                    } else {
                        None
                    },
                    schema: Some(TopicSchema {
                        attributes: vec![
                            "repo".to_string(),
                            "action".to_string(),
                            "actor".to_string(),
                            "subject".to_string(),
                            "source".to_string(),
                            "type".to_string(),
                        ],
                        event_types: Vec::new(),
                        filter_examples: vec![r#"{ exact: { repo: "owner/repo" } }"#.to_string()],
                    }),
                    setup_guide: None,
                }),
                observed: ObservedTopicStats {
                    event_count: 1,
                    ..ObservedTopicStats::default()
                },
            }];
            diagnose_subscription(topic, filters, &catalog)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hmac_verification_edge_cases_and_mutations() {
        let secret = b"top-secret-key";
        let body = br#"{"hello":"world"}"#;
        let valid = compute_hmac_sha256_header(secret, body);

        assert!(verify_hmac_sha256_header(secret, body, Some(&valid), true));
        // Empty secret always fails closed.
        assert!(!verify_hmac_sha256_header(b"", body, Some(&valid), true));
        // Missing header fails closed.
        assert!(!verify_hmac_sha256_header(secret, body, None, true));
        // Wrong prefix fails closed.
        assert!(!verify_hmac_sha256_header(
            secret,
            body,
            Some(&valid.replacen("sha256=", "sha1=", 1)),
            true
        ));
        // Truncated hex fails closed.
        assert!(!verify_hmac_sha256_header(
            secret,
            body,
            Some(&valid[..valid.len() - 2]),
            true
        ));
        // Uppercase hex rejected in strict GitHub mode, accepted in lenient mode.
        let upper = format!("sha256={}", valid["sha256=".len()..].to_ascii_uppercase());
        assert!(!verify_hmac_sha256_header(secret, body, Some(&upper), true));
        assert!(verify_hmac_sha256_header(secret, body, Some(&upper), false));
        // Single-byte body mutation fails closed.
        let mut tampered_body = body.to_vec();
        tampered_body[2] ^= 0x01;
        assert!(!verify_hmac_sha256_header(
            secret,
            &tampered_body,
            Some(&valid),
            true
        ));
    }

    #[test]
    fn github_data_fits_under_8kib_limit_for_oversized_body_and_labels() {
        let huge_labels: Vec<Value> = (0..200)
            .map(|i| json!({ "name": format!("very-long-label-name-{i:04}-{}", "x".repeat(40)) }))
            .collect();
        let payload = json!({
            "action": "opened",
            "repository": { "full_name": "acme/big" },
            "sender": { "login": "bot-user", "type": "Bot" },
            "pull_request": {
                "number": 1,
                "title": "T".repeat(500),
                "html_url": "https://github.com/acme/big/pull/1",
                "state": "open",
                "body": format!("{} agent:reviewer <!-- agent:ci-bot -->", "B".repeat(20_000)),
                "labels": huge_labels,
                "assignees": []
            }
        });
        let ev = match normalize_github_webhook(
            "pull_request",
            "big-1",
            &payload,
            "2026-11-24T00:00:00Z",
        ) {
            GitHubNormalizeOutcome::Publish(ev) => *ev,
            GitHubNormalizeOutcome::Ignore(r) => panic!("unexpected ignore: {r}"),
        };
        let data_json = serde_json::to_string(ev.data.as_ref().unwrap()).unwrap();
        assert!(data_json.len() <= MAX_DATA_BYTES);
        assert_eq!(ev.data.as_ref().unwrap()["signed_by"], "ci-bot");
        assert_eq!(
            ev.data.as_ref().unwrap()["mentions"],
            json!(["agent:reviewer"])
        );
        let val = serde_json::to_value(&ev).unwrap();
        assert!(check_cloudevent_v2(&val).is_ok());
    }
}
