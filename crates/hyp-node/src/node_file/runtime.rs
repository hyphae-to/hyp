//! Runtime policy and native source configuration loaded from node.json.

use super::DeliveryRetryConfig;
use crate::adapters::github_public::normalize_repo_token_pattern;
use crate::adapters::{GitHubPublicConfig, GitHubWebhookConfig};
use crate::engine::config::{ForwardingPolicy, validate_trusted_proxy_cidr};
use crate::engine::{GuestPairingConfig, KvNamespaceConfig, NodeConfig, WakeRecoveryConfig};
use hyp_crypto::CryptoError;
use hyp_crypto::keys::OkpJwk as CryptoOkpJwk;
use hyp_crypto::keystore::validate_secret_name;
use hyp_proto::address::{is_valid_kv_namespace, is_valid_topic};
use hyp_proto::manifest::{KvMode, KvWriteModel, OkpCurve as ProtoOkpCurve, OkpJwk as ProtoOkpJwk};
use serde_json::Value;
use std::collections::HashSet;
use std::time::Duration;

impl super::GuestPairingFile {
    pub(super) fn to_runtime(
        &self,
        fallback_joins: Option<u64>,
    ) -> Result<GuestPairingConfig, String> {
        let mut cfg = GuestPairingConfig::default();
        cfg.enabled = self.enabled.unwrap_or(cfg.enabled);
        if let Some(max_repos) = self.max_repos_per_guest {
            if max_repos == 0 {
                return Err("guestPairing.maxReposPerGuest must be > 0".to_string());
            }
            cfg.max_repos_per_guest = max_repos as usize;
        }
        if let Some(max_batches) = self.max_batches_per_hour {
            if max_batches == 0 {
                return Err("guestPairing.maxBatchesPerHour must be > 0".to_string());
            }
            cfg.max_batches_per_hour = max_batches.min(u32::MAX as u64) as u32;
        }
        if let Some(max_joins) = self.max_joins_per_minute.or(fallback_joins) {
            cfg.max_joins_per_minute = max_joins.min(u32::MAX as u64) as u32;
        }
        if let Some(scopes) = &self.scopes {
            let arr = scopes.as_array().ok_or_else(|| {
                "guestPairing.scopes must be an array of scope strings".to_string()
            })?;
            let parsed =
                arr.iter()
                    .map(|value| {
                        value.as_str().map(str::to_owned).ok_or_else(|| {
                            "guestPairing.scopes entries must be strings".to_string()
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
            if !parsed.is_empty() {
                cfg.scopes = parsed;
            }
        } else if cfg.max_repos_per_guest != 10 || cfg.max_batches_per_hour != 60 {
            cfg.scopes = vec![format!(
                "stream:subscribe=github[require=exact.repo;maxValues={};maxBatchesPerHour={}]",
                cfg.max_repos_per_guest, cfg.max_batches_per_hour
            )];
        }
        Ok(cfg)
    }
}

fn parse_ed25519_jwk_str_or_b64(raw: &str, context: &str) -> Result<ProtoOkpJwk, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!("{context} cannot be empty"));
    }
    if trimmed.starts_with('{') {
        let val: Value =
            serde_json::from_str(trimmed).map_err(|e| format!("invalid JSON in {context}: {e}"))?;
        return parse_ed25519_jwk_object(&val, context);
    }
    if trimmed.len() != 43 {
        return Err(format!(
            "{context} string must be a 43-character unpadded base64url Ed25519 public key (got {} chars)",
            trimmed.len()
        ));
    }
    let crypto_jwk = CryptoOkpJwk {
        kty: "OKP".to_string(),
        crv: "Ed25519".to_string(),
        x: trimmed.to_string(),
    };
    crypto_jwk
        .to_ed25519()
        .map_err(|e| format!("invalid Ed25519 public key in {context}: {e}"))?;
    let proto_jwk = ProtoOkpJwk {
        kty: "OKP".to_string(),
        crv: ProtoOkpCurve::Ed25519,
        x: trimmed.to_string(),
    };
    proto_jwk
        .validate(Some(ProtoOkpCurve::Ed25519))
        .map_err(|e| format!("invalid Ed25519 public key in {context}: {e}"))?;
    Ok(proto_jwk)
}

fn parse_ed25519_jwk_object(val: &Value, context: &str) -> Result<ProtoOkpJwk, String> {
    let obj = val.as_object().ok_or_else(|| {
        format!("{context} must be an OKP Ed25519 JWK object or 43-char base64url string")
    })?;
    if obj.contains_key("d") {
        return Err(format!(
            "{context} must be a public OKP Ed25519 JWK (private key field 'd' is forbidden in node.json)"
        ));
    }
    let crypto_jwk: CryptoOkpJwk = serde_json::from_value(val.clone())
        .map_err(|e| format!("malformed OKP Ed25519 JWK in {context}: {e}"))?;
    if crypto_jwk.kty != "OKP" || crypto_jwk.crv != "Ed25519" {
        return Err(format!(
            "{context} must have kty=\"OKP\" and crv=\"Ed25519\", got kty={:?} crv={:?}",
            crypto_jwk.kty, crypto_jwk.crv
        ));
    }
    crypto_jwk
        .to_ed25519()
        .map_err(|e| format!("invalid Ed25519 public key in {context}: {e}"))?;
    let proto_jwk = ProtoOkpJwk {
        kty: "OKP".to_string(),
        crv: ProtoOkpCurve::Ed25519,
        x: crypto_jwk.x,
    };
    proto_jwk
        .validate(Some(ProtoOkpCurve::Ed25519))
        .map_err(|e| format!("invalid Ed25519 public key in {context}: {e}"))?;
    Ok(proto_jwk)
}

pub fn parse_pairing_admin_key(
    val: &Value,
    secrets: &hyp_crypto::SecretStore,
    warnings: &mut Vec<String>,
) -> Result<Option<ProtoOkpJwk>, String> {
    if val.is_null() {
        return Ok(None);
    }
    if let Some(s) = val.as_str() {
        return parse_ed25519_jwk_str_or_b64(s, "pairing.adminKey").map(Some);
    }
    if let Some(obj) = val.as_object() {
        if obj.len() == 1 && obj.contains_key("secret") {
            let secret_name = obj
                .get("secret")
                .and_then(Value::as_str)
                .ok_or_else(|| "pairing.adminKey.secret must be a string".to_string())?;
            validate_secret_name(secret_name).map_err(|e| {
                format!("invalid secret name '{secret_name}' in pairing.adminKey: {e}")
            })?;
            return match secrets.get(secret_name) {
                Ok(secret) => parse_ed25519_jwk_str_or_b64(
                    &secret,
                    &format!("pairing.adminKey (secret '{secret_name}')"),
                )
                .map(Some),
                Err(CryptoError::SecretNotFound(_)) => {
                    warnings.push(format!(
                        "Secret '{secret_name}' referenced by pairing.adminKey is not set; am2_ Admin-CA pairing disabled until `hyp secret set {secret_name}` is configured."
                    ));
                    Ok(None)
                }
                Err(e) => Err(format!(
                    "failed to load pairing.adminKey secret '{secret_name}': {e}"
                )),
            };
        }
        return parse_ed25519_jwk_object(val, "pairing.adminKey").map(Some);
    }
    Err("pairing.adminKey must be an OKP Ed25519 JWK object, a 43-char base64url public key string, or { \"secret\": \"<name>\" }".to_string())
}

pub fn parse_secret_ref_name(val: &Value, field_name: &str) -> Result<Option<String>, String> {
    if val.is_null() {
        return Ok(None);
    }
    if val.is_string() {
        return Err(format!(
            "'{field_name}' must use {{ \"secret\": \"<name>\" }} (plaintext credentials are forbidden in node.json)"
        ));
    }
    let obj = val
        .as_object()
        .ok_or_else(|| format!("'{field_name}' must be an object {{ \"secret\": \"<name>\" }}"))?;
    let name = obj
        .get("secret")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("'{field_name}' missing string 'secret' reference"))?;
    validate_secret_name(name)
        .map_err(|e| format!("invalid secret name '{name}' in '{field_name}': {e}"))?;
    Ok(Some(name.to_string()))
}

pub(super) fn parse_trusted_proxies_array(val: &Value, field: &str) -> Result<Vec<String>, String> {
    let arr = val
        .as_array()
        .ok_or_else(|| format!("{field} must be an array of IP/CIDR strings"))?;
    let mut out = Vec::with_capacity(arr.len());
    for item in arr {
        let s = item
            .as_str()
            .ok_or_else(|| format!("{field} entries must be IP/CIDR strings"))?
            .trim();
        let _ =
            validate_trusted_proxy_cidr(s).map_err(|e| format!("invalid entry in {field}: {e}"))?;
        out.push(s.to_string());
    }
    Ok(out)
}

pub(super) fn decode_forwarding(value: Value) -> Result<ForwardingPolicy, String> {
    const INVALID_HOPS: &str =
        "invalid forwarding policy: forwarding.maxHops must be >= 1 (default 2, max 4)";
    if value.get("maxHops").and_then(Value::as_u64) == Some(0) {
        return Err(INVALID_HOPS.to_owned());
    }
    let policy: ForwardingPolicy =
        serde_json::from_value(value).map_err(|e| format!("invalid forwarding policy: {e}"))?;
    if policy.max_hops == 0 {
        return Err(INVALID_HOPS.to_owned());
    }
    Ok(policy)
}

impl super::NodeFile {
    pub fn apply_runtime_policies(&self, node: &mut NodeConfig) -> Result<(), String> {
        if let Some(forwarding) = &self.forwarding {
            node.forwarding = forwarding.as_ref().map_err(Clone::clone)?.clone();
        }

        // Explicit CIDRs win over the legacy flag, which trusts loopback proxies only.
        let nested = self
            .listen
            .as_ref()
            .and_then(|listen| listen.trusted_proxies.as_ref());
        let nested = nested
            .map(|list| list.as_ref())
            .transpose()
            .map_err(Clone::clone)?;
        let top = self
            .trusted_proxies
            .as_ref()
            .map(|list| list.as_ref())
            .transpose()
            .map_err(Clone::clone)?;
        if let Some(cidrs) = top.or(nested) {
            node.trusted_proxies = cidrs.clone();
            return Ok(());
        }

        let nested = self
            .listen
            .as_ref()
            .and_then(|listen| listen.behind_reverse_proxy.as_ref())
            .map(|flag| flag.as_ref())
            .transpose()
            .map_err(|_| "listen.behindReverseProxy must be a boolean".to_string())?;
        let top = self
            .behind_reverse_proxy
            .as_ref()
            .map(|flag| flag.as_ref())
            .transpose()
            .map_err(|_| "behindReverseProxy must be a boolean".to_string())?;
        if let Some(flag) = top.or(nested) {
            node.trusted_proxies = if *flag {
                vec!["127.0.0.1/32".to_string(), "::1/128".to_string()]
            } else {
                Vec::new()
            };
        }
        Ok(())
    }
}

/// Parses `"kvNamespaces"` from `node.json` into [`KvNamespaceConfig`] entries.
///
/// Accepts both simple string entries (e.g. `["shared", "deploy-state"]`) and structured objects
/// (e.g. `{ "namespace": "shared", "mode": "e2ee", "writeModel": "shared" }` or `"name"`).
/// Validates every namespace name fail-closed with [`is_valid_kv_namespace`] and deduplicates
/// duplicate namespace names while emitting a startup warning.
pub(super) fn parse_kv_namespaces(
    val: &Value,
    warnings: &mut Vec<String>,
) -> Result<Vec<KvNamespaceConfig>, String> {
    if val.is_null() {
        return Ok(Vec::new());
    }
    let arr = val
        .as_array()
        .ok_or_else(|| "kvNamespaces must be an array".to_string())?;

    let mut out = Vec::with_capacity(arr.len());
    let mut seen = HashSet::new();

    for (idx, item) in arr.iter().enumerate() {
        let cfg = match item {
            Value::String(s) => {
                let name = s.trim();
                if !is_valid_kv_namespace(name) {
                    return Err(format!(
                        "kvNamespaces[{idx}] invalid namespace name '{name}': must match /^[a-z0-9][a-z0-9._-]{{0,63}}$/"
                    ));
                }
                KvNamespaceConfig {
                    name: name.to_string(),
                    mode: KvMode::E2ee,
                    write_model: KvWriteModel::Shared,
                }
            }
            Value::Object(obj) => {
                let name_field = match obj.get("name") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(s)) => Some(s.trim()),
                    Some(_) => {
                        return Err(format!("kvNamespaces[{idx}].name must be a string"));
                    }
                };
                let ns_field = match obj.get("namespace") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(s)) => Some(s.trim()),
                    Some(_) => {
                        return Err(format!("kvNamespaces[{idx}].namespace must be a string"));
                    }
                };
                let name = match (name_field, ns_field) {
                    (Some(a), Some(b)) if a != b => {
                        return Err(format!(
                            "kvNamespaces[{idx}] specifies conflicting 'name' ('{a}') and 'namespace' ('{b}')"
                        ));
                    }
                    (Some(a), _) => a,
                    (None, Some(b)) => b,
                    (None, None) => {
                        return Err(format!(
                            "kvNamespaces[{idx}] object must specify 'namespace' (or 'name')"
                        ));
                    }
                };
                if !is_valid_kv_namespace(name) {
                    return Err(format!(
                        "kvNamespaces[{idx}] invalid namespace name '{name}': must match /^[a-z0-9][a-z0-9._-]{{0,63}}$/"
                    ));
                }

                let mode = match obj.get("mode") {
                    None | Some(Value::Null) => KvMode::E2ee,
                    Some(Value::String(raw_mode)) => {
                        match raw_mode.trim().to_ascii_lowercase().as_str() {
                            "e2ee" => KvMode::E2ee,
                            "plaintext" => KvMode::Plaintext,
                            other => {
                                return Err(format!(
                                    "kvNamespaces[{idx}].mode invalid value '{other}': expected 'e2ee' or 'plaintext'"
                                ));
                            }
                        }
                    }
                    Some(_) => {
                        return Err(format!("kvNamespaces[{idx}].mode must be a string"));
                    }
                };

                let write_model_val = obj.get("writeModel").or_else(|| obj.get("write_model"));
                let write_model = match write_model_val {
                    None | Some(Value::Null) => KvWriteModel::Shared,
                    Some(Value::String(raw_wm)) => {
                        match raw_wm.trim().to_ascii_lowercase().as_str() {
                            "shared" | "cas" => KvWriteModel::Shared,
                            "owner" => KvWriteModel::Owner,
                            "allowlist" => KvWriteModel::Allowlist,
                            other => {
                                return Err(format!(
                                    "kvNamespaces[{idx}].writeModel invalid value '{other}': expected 'shared', 'owner', 'allowlist', or 'cas'"
                                ));
                            }
                        }
                    }
                    Some(_) => {
                        return Err(format!("kvNamespaces[{idx}].writeModel must be a string"));
                    }
                };

                KvNamespaceConfig {
                    name: name.to_string(),
                    mode,
                    write_model,
                }
            }
            _ => {
                return Err(format!(
                    "kvNamespaces[{idx}] must be a namespace string or object"
                ));
            }
        };

        if !seen.insert(cfg.name.clone()) {
            warnings.push(format!(
                "Duplicate kvNamespaces entry '{}' ignored (keeping first definition).",
                cfg.name
            ));
            continue;
        }
        out.push(cfg);
    }

    Ok(out)
}

fn parse_optional_string_vec(
    field: Option<&Result<Vec<Value>, String>>,
    label: &str,
) -> Result<Vec<String>, String> {
    let Some(field) = field else {
        return Ok(Vec::new());
    };
    let values = field
        .as_ref()
        .map_err(|_| format!("{label} must be an array of strings"))?;
    let mut out = Vec::new();
    for value in values {
        let text = value
            .as_str()
            .ok_or_else(|| format!("{label} entries must be strings"))?;
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            out.push(trimmed.to_string());
        }
    }
    Ok(out)
}

pub fn parse_github_public_source(
    sources: &[super::SourceFile],
    secrets: &hyp_crypto::SecretStore,
    public_read_only: bool,
    warnings: &mut Vec<String>,
) -> Result<Option<GitHubPublicConfig>, String> {
    let mut active_cfg: Option<GitHubPublicConfig> = None;
    let mut extra_enabled = 0usize;

    for source in sources {
        if source.kind.as_deref() != Some("github-public") || source.enabled == Some(false) {
            continue;
        }

        if active_cfg.is_some() {
            extra_enabled += 1;
            continue;
        }

        let mut cfg = GitHubPublicConfig::default();
        if let Some(id) = source
            .id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            cfg.id = id.to_owned();
        }
        if let Some(topic) = &source.topic {
            cfg.topic = topic.clone();
        }
        if let Some(base) = &source.api_base_url {
            cfg.api_base_url = base.clone();
        }
        if let Some(min_poll) = source.min_poll_interval_seconds {
            let duration = Duration::from_secs(min_poll);
            cfg.min_poll_interval = duration;
            cfg.base_poll_interval = cfg.base_poll_interval.min(duration);
        }
        if let Some(base_poll) = source.base_poll_interval_seconds {
            cfg.base_poll_interval = Duration::from_secs(base_poll);
        }
        if let Some(grace) = source.grace_window_seconds {
            cfg.teardown_grace = Duration::from_secs(grace);
        }
        if let Some(max_pollers) = &source.max_active_pollers {
            let max_pollers = *max_pollers
                .as_ref()
                .map_err(|_| "sources[].maxActivePollers must be a positive integer".to_string())?;
            if max_pollers == 0 {
                return Err("sources[].maxActivePollers must be >= 1".to_string());
            }
            cfg.max_active_pollers = usize::try_from(max_pollers).unwrap_or(usize::MAX);
        }
        if !public_read_only {
            if let Some(allow_private) = source.allow_private_with_token {
                cfg.allow_private_with_token = allow_private;
            }
        }

        if let Some(tok_val) = &source.github_token {
            if let Some(secret_name) = parse_secret_ref_name(tok_val, "sources[].githubToken")? {
                match secrets.get(&secret_name) {
                    Ok(secret) => cfg.github_token = Some(secret),
                    Err(CryptoError::SecretNotFound(_)) => {
                        warnings.push(format!(
                            "Secret '{secret_name}' is not set; starting github-public in unauthenticated public GitHub mode (60 req/hr). Run `hyp secret set {secret_name}` for 5,000 req/hr."
                        ));
                    }
                    Err(e) => {
                        return Err(format!(
                            "failed to load GitHub token secret '{secret_name}': {e}"
                        ));
                    }
                }
            }
        }

        if let Some(repo_tokens_val) = &source.repo_tokens {
            if !repo_tokens_val.is_null() {
                let repo_tokens_obj = repo_tokens_val.as_object().ok_or_else(|| {
                    "sources[].repoTokens must be a JSON object mapping \"owner/*\" or \"owner/repo\" to { \"secret\": \"<name>\" }".to_string()
                })?;
                let mut seen_patterns: HashSet<String> = HashSet::new();
                for (raw_pattern, secret_val) in repo_tokens_obj {
                    let canonical = normalize_repo_token_pattern(raw_pattern).map_err(|e| {
                        format!("invalid sources[].repoTokens pattern '{raw_pattern}': {e}")
                    })?;
                    if !seen_patterns.insert(canonical.clone()) {
                        return Err(format!(
                            "duplicate normalized sources[].repoTokens pattern '{canonical}' (from '{raw_pattern}')"
                        ));
                    }
                    let field_label = format!("sources[].repoTokens['{raw_pattern}']");
                    if let Some(secret_name) = parse_secret_ref_name(secret_val, &field_label)? {
                        match secrets.get(&secret_name) {
                            Ok(secret) => {
                                cfg.repo_tokens.insert(canonical, secret);
                            }
                            Err(CryptoError::SecretNotFound(_)) => {
                                warnings.push(format!(
                                    "Secret '{secret_name}' for github-public repoTokens['{canonical}'] is not set; repos matching '{canonical}' will fall back to default/unauthenticated mode until `hyp secret set {secret_name} --web` is configured."
                                ));
                            }
                            Err(e) => {
                                return Err(format!(
                                    "failed to load GitHub token secret '{secret_name}' for {field_label}: {e}"
                                ));
                            }
                        }
                    }
                }
            }
        }

        active_cfg = Some(cfg);
    }

    if extra_enabled > 0 {
        warnings.push(
            "Multiple enabled github-public sources found; only the first is active. Consolidate multiple GitHub tokens into sources[0].repoTokens (e.g. { \"owner/*\": { \"secret\": \"...\" } })."
                .to_string(),
        );
    }

    Ok(active_cfg)
}

pub(super) fn parse_wake_recovery(section: &Value) -> Result<WakeRecoveryConfig, String> {
    let mut cfg = WakeRecoveryConfig::default();
    let obj = section
        .as_object()
        .ok_or_else(|| "wakeRecovery must be a JSON object".to_string())?;
    if let Some(raw_enabled) = obj.get("enabled") {
        cfg.enabled = raw_enabled
            .as_bool()
            .ok_or_else(|| "wakeRecovery.enabled must be a boolean".to_string())?;
    }
    if let Some(raw_secs) = obj
        .get("minSleepSeconds")
        .or_else(|| obj.get("min_sleep_seconds"))
    {
        let secs = raw_secs
            .as_u64()
            .filter(|&v| v >= 1)
            .ok_or_else(|| "wakeRecovery.minSleepSeconds must be an integer >= 1".to_string())?;
        cfg.min_sleep_seconds = secs;
    }
    if let Some(raw_active) = obj
        .get("notifyInterruptedActive")
        .or_else(|| obj.get("notify_interrupted_active"))
    {
        cfg.notify_interrupted_active = raw_active
            .as_bool()
            .ok_or_else(|| "wakeRecovery.notifyInterruptedActive must be a boolean".to_string())?;
    }
    if let Some(raw_all) = obj
        .get("notifyAllEnrolled")
        .or_else(|| obj.get("notify_all_enrolled"))
    {
        cfg.notify_all_enrolled = raw_all
            .as_bool()
            .ok_or_else(|| "wakeRecovery.notifyAllEnrolled must be a boolean".to_string())?;
    }
    Ok(cfg)
}

fn parse_delivery_retry_fields(
    obj: &serde_json::Map<String, Value>,
    cfg: &mut DeliveryRetryConfig,
) -> Result<(), String> {
    if let Some(arr) = obj
        .get("holdRetryBackoffMs")
        .or_else(|| obj.get("hold_retry_backoff_ms"))
        .and_then(Value::as_array)
    {
        let mut backoff = Vec::with_capacity(arr.len());
        for item in arr {
            let ms = item.as_u64().ok_or_else(|| {
                "deliveryRetry.holdRetryBackoffMs entries must be non-negative integers".to_string()
            })?;
            backoff.push(ms);
        }
        if !backoff.is_empty() {
            cfg.hold_retry_backoff_ms = backoff;
        }
    }
    if let Some(max_att) = obj
        .get("holdRetryMaxAttempts")
        .or_else(|| obj.get("hold_retry_max_attempts"))
        .and_then(Value::as_u64)
    {
        cfg.hold_retry_max_attempts = max_att.min(u32::MAX as u64) as u32;
    }
    if let Some(resume) = obj
        .get("codexResume")
        .or_else(|| obj.get("codex_resume"))
        .and_then(Value::as_bool)
    {
        cfg.codex_resume = resume;
    }
    if let Some(arr) = obj
        .get("herdrSpawnAllowlist")
        .or_else(|| obj.get("herdr_spawn_allowlist"))
        .and_then(Value::as_array)
    {
        let mut allow = Vec::with_capacity(arr.len());
        for item in arr {
            let s = item.as_str().ok_or_else(|| {
                "deliveryRetry.herdrSpawnAllowlist entries must be strings".to_string()
            })?;
            allow.push(s.to_string());
        }
        cfg.herdr_spawn_allowlist = allow;
    }
    Ok(())
}

impl super::NodeFile {
    pub fn delivery_retry(&self) -> Result<DeliveryRetryConfig, String> {
        let mut config = DeliveryRetryConfig::default();

        // Old wakeup entries supply fallback values before root-level keys and deliveryRetry.
        if let Some(Ok(sources)) = &self.sources {
            for source in sources
                .iter()
                .filter(|source| source.kind.as_deref() == Some("wakeup"))
            {
                parse_delivery_retry_fields(&source.extra, &mut config)?;
            }
        }
        parse_delivery_retry_fields(&self.extra, &mut config)?;
        if let Some(section) = &self.delivery_retry {
            let fields = section
                .as_object()
                .ok_or_else(|| "deliveryRetry must be a JSON object".to_string())?;
            parse_delivery_retry_fields(fields, &mut config)?;
        }
        Ok(config)
    }
}

/// Guest topic collision guard: refuses (with a clear startup warning + skip) wiring any webhook
/// adapter onto topic `"github"` when `guestPairing.enabled == true` or onto any topic already
/// owned by a `github-public` source.
pub fn filter_colliding_webhook_sources(
    parsed: &mut Vec<GitHubWebhookConfig>,
    guest_pairing_enabled: bool,
    github_public_topic: Option<&str>,
    warnings: &mut Vec<String>,
) {
    let collision_reason = |topic: &str| -> Option<&'static str> {
        if topic == "github" && guest_pairing_enabled {
            return Some("guestPairing is enabled on topic 'github'");
        }
        if let Some(gh_pub_topic) = github_public_topic {
            if topic == gh_pub_topic {
                return Some("a github-public source already owns this topic");
            }
        }
        None
    };

    parsed.retain(|cfg| {
        if let Some(reason) = collision_reason(&cfg.topic) {
            warnings.push(format!(
                "Skipping github-webhook source '{}' on topic '{}': {reason}; configure a distinct private topic.",
                cfg.id, cfg.topic
            ));
            false
        } else {
            true
        }
    });
}

fn validate_webhook_source_id(id: &str, field: &str) -> Result<String, String> {
    let trimmed = id.trim();
    if trimmed.is_empty()
        || trimmed.len() > 64
        || trimmed.contains('/')
        || trimmed.contains('\\')
        || trimmed.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(format!("invalid {field} '{id}'"));
    }
    Ok(trimmed.to_string())
}

pub fn parse_webhook_sources(
    sources: &[super::SourceFile],
    secrets: &hyp_crypto::SecretStore,
    warnings: &mut Vec<String>,
) -> Result<Vec<GitHubWebhookConfig>, String> {
    let mut out = Vec::new();
    let mut gh_ids = HashSet::new();

    for source in sources {
        if source.enabled == Some(false) {
            continue;
        }
        let Some(kind) = source.kind.as_deref() else {
            continue;
        };

        match kind {
            "github-webhook" => {
                let raw_id = source.id.as_deref().unwrap_or("github");
                let id = validate_webhook_source_id(raw_id, "sources[github-webhook].id")?;
                if !gh_ids.insert(id.clone()) {
                    return Err(format!("duplicate github-webhook source id '{id}'"));
                }
                let topic = source.topic.as_deref().unwrap_or("github");
                if !is_valid_topic(topic) {
                    return Err(format!(
                        "invalid topic '{topic}' in github-webhook source '{id}'"
                    ));
                }
                let secret_val = source.secret.as_ref().or(source.webhook_secret.as_ref())
                    .ok_or_else(|| {
                        format!(
                            "sources[github-webhook:'{id}'] requires 'secret': {{ \"secret\": \"<name>\" }}"
                        )
                    })?;
                let secret_name = parse_secret_ref_name(
                    secret_val,
                    &format!("sources[github-webhook:'{id}'].secret"),
                )?
                .ok_or_else(|| {
                    format!(
                        "sources[github-webhook:'{id}'] requires non-null 'secret': {{ \"secret\": \"<name>\" }}"
                    )
                })?;
                let secret = secrets.get(&secret_name).map_err(|e| {
                    format!("failed to load secret '{secret_name}' for github-webhook '{id}': {e}")
                })?;
                if secret.is_empty() {
                    return Err(format!(
                        "secret '{secret_name}' for github-webhook '{id}' must not be empty"
                    ));
                }
                let mut cfg = GitHubWebhookConfig::new(id.clone(), topic, secret.as_str());
                cfg.allowed_repos = parse_optional_string_vec(
                    source.allowed_repos.as_ref(),
                    &format!("sources[github-webhook:'{id}'].allowedRepos"),
                )?;
                cfg.allowed_orgs = parse_optional_string_vec(
                    source.allowed_orgs.as_ref(),
                    &format!("sources[github-webhook:'{id}'].allowedOrgs"),
                )?;
                if let Some(max_b) = source.max_body_bytes {
                    if max_b == 0 {
                        return Err(format!(
                            "sources[github-webhook:'{id}'].maxBodyBytes must be >= 1"
                        ));
                    }
                    cfg.max_body_bytes = usize::try_from(max_b).unwrap_or(usize::MAX);
                }
                out.push(cfg);
            }
            "prometheus-webhook" | "webhook-stream" => {
                let plugin = if kind == "prometheus-webhook" {
                    "prometheus"
                } else {
                    "webhook"
                };
                warnings.push(format!(
                    "Skipping retired source kind '{kind}'. Run `hyp plugin install {plugin} --json` and migrate this source to plugins[]. See https://github.com/hyphae-to/hyp/blob/main/docs/plugins.md#webhook-plugin-migration."
                ));
            }
            _ => {}
        }
    }

    Ok(out)
}
