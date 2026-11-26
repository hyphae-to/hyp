//! Stage 1 Deterministic Policy Engine (0 ms, 0 tokens, fail-closed).
//!
//! Evaluates:
//! 1. **Inbound post-decrypt CloudEvents v1.0**:
//!    - Cryptographic identity & anti-downgrade E2EE verification.
//!    - Session/connector mute lookup against `NodeDb` `muted_sources`.
//!    - Global & per-session CloudEvents Subscriptions API Filter AST allow/denylists.
//!    - Per-trust-tier payload byte ceiling & per-sender token-bucket rate limit.
//!    - Deterministic inbound regex denylist.
//!    - Transfer attachment filename guard (reusing [`hyp_crypto::transfer::default_stage1_attachment_guard`]
//!      plus per-peer explicit allowlists).
//!    - Trust-tier delivery downgrade (`Guest` & `ExternalWebhook` -> `notify` or `quarantine`).
//! 2. **Outbound pre-encrypt payloads**:
//!    - Deterministic **Outbound DLP Secret Scanner** catching AWS keys, GitHub tokens, Slack
//!      tokens, Anthropic/OpenAI API keys, PEM private keys, JWTs, and custom operator patterns.
//!    - Returns `GateDecision::Block` with **redacted category names only** — NEVER echoes leaked
//!      secrets into errors, logs, or audit entries.

use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use hyp_crypto::transfer::{default_stage1_attachment_guard, validate_tar_archive_path};
use hyp_proto::filter::{matches_filter, matches_filters};
use hyp_store::NodeDb;
use regex::Regex;
use serde_json::Value;

use crate::gates::policy::{
    GateDecision, GateError, InboundContext, OutboundContext, RateLimitAction, Stage1Config,
    Stage1DenyAction, TierDeliveryAction, TokenBucket, TrustTier, format_quarantine_notice,
};

/// Upper bound on distinct sender rate-limit buckets retained in memory (anti-OOM).
const MAX_TRACKED_BUCKETS: usize = 8_192;

#[derive(Debug, Clone)]
struct CompiledDlpRule {
    category: String,
    regex: Regex,
}

/// Structured output of Stage 1 inbound or outbound evaluation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage1Outcome {
    pub decision: GateDecision,
    pub categories: Vec<String>,
}

impl Stage1Outcome {
    fn allow(downgraded_to_notify: bool) -> Self {
        let mut categories = Vec::new();
        if downgraded_to_notify {
            categories.push("downgraded_to_notify".to_string());
        }
        Self {
            decision: GateDecision::Allow {
                downgraded_to_notify,
            },
            categories,
        }
    }

    fn block(reason: impl Into<String>, category: impl Into<String>) -> Self {
        Self {
            decision: GateDecision::Block {
                reason: reason.into(),
            },
            categories: vec![category.into()],
        }
    }

    fn quarantine(reason: impl Into<String>, category: impl Into<String>) -> Self {
        let reason_str = reason.into();
        let notice = format_quarantine_notice(&reason_str);
        Self {
            decision: GateDecision::Quarantine {
                reason: reason_str,
                notice,
            },
            categories: vec![category.into()],
        }
    }

    fn hold(reason: impl Into<String>, retry_after_ms: u64, category: impl Into<String>) -> Self {
        Self {
            decision: GateDecision::Hold {
                reason: reason.into(),
                retry_after_ms,
            },
            categories: vec![category.into()],
        }
    }
}

/// Deterministic Stage 1 Policy & Outbound DLP Engine.
#[derive(Debug)]
pub struct Stage1Engine {
    config: Stage1Config,
    inbound_deny_regexes: Vec<Regex>,
    dlp_rules: Vec<CompiledDlpRule>,
    buckets: Mutex<HashMap<(TrustTier, String), TokenBucket>>,
}

impl Stage1Engine {
    /// Constructs a new [`Stage1Engine`], eagerly compiling and validating all regex rules
    /// so malformed patterns fail closed at startup rather than panicking at runtime.
    pub fn new(config: Stage1Config) -> Result<Self, GateError> {
        let mut inbound_deny_regexes = Vec::with_capacity(config.inbound_regex_denylist.len());
        for (idx, pattern) in config.inbound_regex_denylist.iter().enumerate() {
            let re = Regex::new(pattern).map_err(|e| {
                GateError::InvalidConfig(format!(
                    "invalid stage1.inbound_regex_denylist[{idx}]: {e}"
                ))
            })?;
            inbound_deny_regexes.push(re);
        }

        let mut dlp_rules = builtin_dlp_rules();
        for (idx, custom) in config.custom_dlp_patterns.iter().enumerate() {
            let cat = sanitize_category(&custom.category);
            if cat.is_empty() {
                return Err(GateError::InvalidConfig(format!(
                    "stage1.custom_dlp_patterns[{idx}].category must be non-empty"
                )));
            }
            let re = Regex::new(&custom.pattern).map_err(|e| {
                GateError::InvalidConfig(format!(
                    "invalid stage1.custom_dlp_patterns[{idx}] ({cat}): {e}"
                ))
            })?;
            dlp_rules.push(CompiledDlpRule {
                category: cat,
                regex: re,
            });
        }

        Ok(Self {
            config,
            inbound_deny_regexes,
            dlp_rules,
            buckets: Mutex::new(HashMap::new()),
        })
    }

    pub fn config(&self) -> &Stage1Config {
        &self.config
    }

    /// Evaluates an inbound post-decrypt CloudEvent through all deterministic Stage 1 rules.
    pub fn evaluate_inbound(
        &self,
        ctx: &InboundContext,
        db: Option<&NodeDb>,
        now_ms: i64,
    ) -> Stage1Outcome {
        // 1. Cryptographic identity & anti-downgrade E2EE verification.
        if ctx.trust_tier == TrustTier::HumanVerified {
            if ctx.human_auth.is_none() || !ctx.identity_verified || !ctx.e2ee_verified {
                return Stage1Outcome::block("human_auth_unverified", "human_auth_unverified");
            }
        } else if ctx.trust_tier.is_remote_peer() {
            if !ctx.identity_verified {
                return Stage1Outcome::block("unverified_identity", "identity_unverified");
            }
            if self.config.require_e2ee_for_peers && !ctx.e2ee_verified {
                return Stage1Outcome::block(
                    "e2ee_required_downgrade_rejected",
                    "e2ee_downgrade_rejected",
                );
            }
        }

        // 2. Session/connector mute check against `NodeDb` `muted_sources`
        // (bypassed for verified human operator directives).
        if ctx.trust_tier != TrustTier::HumanVerified {
            if let Some(node_db) = db {
                let mut candidates: Vec<&str> = Vec::with_capacity(6);
                if !ctx.sender.is_empty() {
                    candidates.push(ctx.sender.as_str());
                }
                if !ctx.origin_node.is_empty() {
                    candidates.push(ctx.origin_node.as_str());
                }
                if !ctx.event.source.is_empty() {
                    candidates.push(ctx.event.source.as_str());
                }
                if let Some(ch) = ctx.channel.as_deref() {
                    candidates.push(ch);
                }
                if let Some(topic) = ctx.topic.as_deref() {
                    candidates.push(topic);
                }
                if let Some(bridge) = ctx.bridge.as_deref() {
                    candidates.push(bridge);
                }
                match node_db.local().is_muted(&ctx.session_id, &candidates) {
                    Ok(Some(matched_pattern)) => {
                        return Stage1Outcome::block(
                            format!("muted_source:{matched_pattern}"),
                            "muted_source",
                        );
                    }
                    Ok(None) => {}
                    Err(_) => {
                        // Fail closed if mute lookup encounters a DB error.
                        return Stage1Outcome::block("mute_lookup_error", "mute_lookup_error");
                    }
                }
            }
        }

        // 3. Inbound CloudEvents Filter AST ACL checks (denylist, global allowlist, session allowlist).
        if ctx.trust_tier != TrustTier::HumanVerified
            && self
                .config
                .inbound_denylist
                .iter()
                .any(|filter| matches_filter(filter, &ctx.event))
        {
            return Stage1Outcome::block("inbound_acl_denied", "acl_denied");
        }
        if !self.config.inbound_allowlist.is_empty()
            && !matches_filters(&self.config.inbound_allowlist, &ctx.event)
        {
            return Stage1Outcome::block("inbound_acl_not_allowed", "acl_not_allowed");
        }
        if let Some(session_filters) = self.config.session_inbound_allowlists.get(&ctx.session_id) {
            if !session_filters.is_empty() && !matches_filters(session_filters, &ctx.event) {
                return Stage1Outcome::block("session_acl_not_allowed", "session_acl_not_allowed");
            }
        }

        // 4. Payload byte-size ceiling per trust tier.
        let tier_policy = self.config.policy_for(ctx.trust_tier);
        let payload_bytes = measure_inbound_payload_bytes(ctx);
        if payload_bytes > tier_policy.max_payload_bytes {
            return Stage1Outcome::block(
                format!(
                    "payload_too_large:{payload_bytes}>{}",
                    tier_policy.max_payload_bytes
                ),
                "payload_too_large",
            );
        }

        // 5. Per-sender token-bucket rate limit.
        let sender_key = rate_limit_sender_key(ctx);
        match self.consume_rate_limit(ctx.trust_tier, &sender_key, tier_policy.rate_limit, now_ms) {
            Ok(()) => {}
            Err(retry_after_ms) => {
                return match self.config.rate_limit_action {
                    RateLimitAction::Hold => {
                        Stage1Outcome::hold("rate_limited", retry_after_ms, "rate_limited")
                    }
                    RateLimitAction::Block => Stage1Outcome::block("rate_limited", "rate_limited"),
                };
            }
        }

        // 6. Deterministic inbound content regex denylist
        // (bypassed for verified human operator directives).
        if ctx.trust_tier != TrustTier::HumanVerified && !self.inbound_deny_regexes.is_empty() {
            let texts = collect_inbound_searchable_texts(ctx);
            for (idx, re) in self.inbound_deny_regexes.iter().enumerate() {
                if texts.iter().any(|t| re.is_match(t)) {
                    let reason = format!("inbound_regex_denied:rule_{idx}");
                    return match self.config.regex_deny_action {
                        Stage1DenyAction::Block => Stage1Outcome::block(reason, "regex_denied"),
                        Stage1DenyAction::Quarantine => {
                            Stage1Outcome::quarantine(reason, "regex_denied")
                        }
                    };
                }
            }
        }

        // 7. Transfer attachment filename guard (reuses `hyp_crypto::transfer::default_stage1_attachment_guard`).
        if self.config.enforce_transfer_attachment_guard && !ctx.transfer_paths.is_empty() {
            let peer_id = if !ctx.origin_node.is_empty() {
                ctx.origin_node.as_str()
            } else {
                ctx.sender.as_str()
            };
            for rel_path in &ctx.transfer_paths {
                if let Err(reason) =
                    self.check_transfer_attachment(peer_id, ctx.trust_tier, rel_path)
                {
                    return Stage1Outcome::block(
                        format!("blocked_attachment:{reason}"),
                        "blocked_attachment",
                    );
                }
            }
        }

        // 8. Automatic trust-tier delivery downgrade (never auto-interrupt live agents from untrusted tiers).
        match tier_policy.default_action {
            TierDeliveryAction::Allow => Stage1Outcome::allow(false),
            TierDeliveryAction::DowngradeToNotify => Stage1Outcome::allow(true),
            TierDeliveryAction::Quarantine => Stage1Outcome::quarantine(
                format!("trust_tier_quarantine:{}", ctx.trust_tier.as_str()),
                "trust_tier_quarantine",
            ),
        }
    }

    /// Evaluates an outbound pre-encrypt payload via the deterministic **Outbound DLP Secret Scanner**.
    ///
    /// **Zero-leak invariant:** If one or more secret patterns match, the returned `Block` reason
    /// and categories contain ONLY redacted category labels — NEVER any characters of the secret.
    pub fn evaluate_outbound(&self, ctx: &OutboundContext) -> Stage1Outcome {
        if !self.config.outbound_dlp_enabled {
            return Stage1Outcome::allow(false);
        }

        let mut matched_categories: BTreeSet<String> = BTreeSet::new();
        for rule in &self.dlp_rules {
            if rule.regex.is_match(&ctx.payload) {
                matched_categories.insert(rule.category.clone());
            }
        }

        if matched_categories.is_empty() {
            Stage1Outcome::allow(false)
        } else {
            let cats: Vec<String> = matched_categories.into_iter().collect();
            let reason = format!("outbound_dlp_blocked:{}", cats.join(","));
            Stage1Outcome {
                decision: GateDecision::Block { reason },
                categories: cats,
            }
        }
    }

    /// Evaluates a single transfer archive relative path against `hyp_crypto`'s fail-closed path
    /// validator, `default_stage1_attachment_guard`, and any explicit per-peer allowlist.
    ///
    /// Can be invoked directly inside `hyp_crypto::transfer::unpack_tar_gz` via `TarUnpackOptions::attachment_guard`.
    pub fn check_transfer_attachment(
        &self,
        peer_id: &str,
        trust_tier: TrustTier,
        rel_path: &str,
    ) -> Result<(), String> {
        // Always reject path traversal, absolute paths, NULs, backslashes, and control chars
        // — even for SelfHost or allowlisted peers!
        let clean = validate_tar_archive_path(rel_path, false).map_err(|e| e.to_string())?;

        if trust_tier == TrustTier::SelfHost || !self.config.enforce_transfer_attachment_guard {
            return Ok(());
        }

        match default_stage1_attachment_guard(&clean) {
            Ok(()) => Ok(()),
            Err(block_reason) => {
                if self.is_attachment_allowlisted(peer_id, &clean) {
                    Ok(())
                } else {
                    Err(block_reason)
                }
            }
        }
    }

    /// Checks whether `peer_id` has an explicit attachment allowlist entry matching `clean_path`.
    ///
    /// Security rule:
    /// - Bare extension allowlists (e.g. `".sh"`) permit scripts in normal paths, but NEVER bypass
    ///   sensitive `.git/hooks/*` or agent config dirs (`.claude/*`, `.agents/*`, `.codex/*`,
    ///   `.cursor/*`, `.vscode/*`) — those require an explicit exact path or prefix rule.
    fn is_attachment_allowlisted(&self, peer_id: &str, clean_path: &str) -> bool {
        let mut candidate_keys: Vec<&str> = vec![peer_id];
        if let Some((node_part, _)) = peer_id.split_once('/') {
            candidate_keys.push(node_part);
        }

        let lower_path = clean_path.to_ascii_lowercase();
        let is_sensitive_dir = is_sensitive_config_or_hook_path(&lower_path);

        for key in candidate_keys {
            let Some(entries) = self.config.transfer_attachment_allowlist.get(key) else {
                continue;
            };
            for raw_rule in entries {
                let rule = raw_rule.trim().to_ascii_lowercase();
                if rule.is_empty() {
                    continue;
                }
                // Exact relative path match (e.g. "scripts/deploy.sh" or ".git/hooks/pre-commit").
                if rule == lower_path {
                    return true;
                }
                // Directory prefix wildcard (e.g. "scripts/*" or ".git/hooks/*").
                if let Some(prefix) = rule.strip_suffix('*') {
                    if !prefix.is_empty() && lower_path.starts_with(prefix) {
                        return true;
                    }
                }
                // Extension allowlist (e.g. ".sh") — never bypasses sensitive hook/agent dirs.
                if rule.starts_with('.') && !rule.contains('/') && !is_sensitive_dir {
                    if let Some(file_name) = lower_path.rsplit('/').next() {
                        if file_name.ends_with(&rule) && file_name != rule {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    fn consume_rate_limit(
        &self,
        tier: TrustTier,
        sender_key: &str,
        limit: crate::gates::policy::RateLimitConfig,
        now_ms: i64,
    ) -> Result<(), u64> {
        let Ok(mut map) = self.buckets.lock() else {
            // Fail closed if mutex was poisoned.
            return Err(5_000);
        };
        let key = (tier, sender_key.to_string());
        if !map.contains_key(&key) && map.len() >= MAX_TRACKED_BUCKETS {
            // Evict the stalest bucket to stay strictly memory-bounded.
            if let Some(oldest_key) = map
                .iter()
                .min_by_key(|(_, b)| b.last_refill_ms())
                .map(|(k, _)| k.clone())
            {
                map.remove(&oldest_key);
            }
        }
        let bucket = map
            .entry(key)
            .or_insert_with(|| TokenBucket::new(limit, now_ms));
        bucket.try_consume(now_ms)
    }
}

fn is_sensitive_config_or_hook_path(lower_path: &str) -> bool {
    let segments: Vec<&str> = lower_path.split('/').collect();
    if segments.windows(2).any(|w| w == [".git", "hooks"]) {
        return true;
    }
    segments.iter().any(|&seg| {
        matches!(
            seg,
            ".claude" | ".agents" | ".codex" | ".cursor" | ".vscode"
        )
    })
}

fn rate_limit_sender_key(ctx: &InboundContext) -> String {
    let raw = if !ctx.sender.trim().is_empty() {
        ctx.sender.as_str()
    } else if !ctx.origin_node.trim().is_empty() {
        ctx.origin_node.as_str()
    } else {
        ctx.event.source.as_str()
    };
    raw.trim().to_ascii_lowercase()
}

fn measure_inbound_payload_bytes(ctx: &InboundContext) -> usize {
    let mut max_bytes = ctx.rendered_text.as_ref().map_or(0, String::len);
    if let Some(data) = &ctx.event.data {
        let serialized_len = serde_json::to_string(data).map_or(usize::MAX, |s| s.len());
        max_bytes = max_bytes.max(serialized_len);
    }
    if let Some(b64) = &ctx.event.data_base64 {
        let decoded_len = BASE64_STD
            .decode(b64)
            .map_or(b64.len(), |bytes| bytes.len());
        max_bytes = max_bytes.max(decoded_len);
    }
    max_bytes
}

fn collect_inbound_searchable_texts(ctx: &InboundContext) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(rendered) = &ctx.rendered_text {
        out.push(rendered.clone());
    }
    if let Some(subject) = &ctx.event.subject {
        out.push(subject.clone());
    }
    if let Some(data) = &ctx.event.data {
        collect_json_strings(data, &mut out);
    }
    out
}

fn collect_json_strings(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => out.push(s.clone()),
        Value::Array(items) => {
            for item in items {
                collect_json_strings(item, out);
            }
        }
        Value::Object(map) => {
            for v in map.values() {
                collect_json_strings(v, out);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn sanitize_category(raw: &str) -> String {
    raw.trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        .take(64)
        .collect()
}

/// Built-in high-precision outbound DLP secret detection rules (§5.2).
fn builtin_dlp_rules() -> Vec<CompiledDlpRule> {
    const BUILTINS: &[(&str, &str)] = &[
        // AWS IAM long-term (AKIA) and temporary STS (ASIA) access key IDs.
        ("aws_access_key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        // GitHub classic (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`) & fine-grained (`github_pat_`) tokens.
        (
            "github_token",
            r"\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b",
        ),
        // Slack bot, user, app, legacy, and refresh tokens.
        ("slack_token", r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
        // Anthropic API keys (`sk-ant-...`).
        ("anthropic_api_key", r"\bsk-ant-[A-Za-z0-9_-]{16,}\b"),
        // OpenAI API keys (`sk-...`, `sk-proj-...`, `sk-live-...`, `sk-test-...`).
        (
            "openai_api_key",
            r"\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}\b",
        ),
        // PEM-encoded private keys (RSA, EC, OPENSSH, PKCS8, DSA, PGP, etc.).
        ("pem_private_key", r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
        // JSON Web Tokens (`header.payload.signature` starting with base64url `{"...`).
        (
            "jwt_token",
            r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        ),
    ];

    BUILTINS
        .iter()
        .map(|&(category, pattern)| CompiledDlpRule {
            category: category.to_string(),
            regex: Regex::new(pattern).expect("built-in DLP regex must be valid"),
        })
        .collect()
}
