//! Generalized pluggable `FilterPlugin` trait and built-in guardrail adapters.
//!
//! Allows operators to compose any ordered chain of security filters on their Local Node:
//! 1. `anthropic` — Anthropic Messages API (`/v1/messages`) with immutable `DEFAULT_CORE_RUBRIC`
//! 2. `openai-compat` — OpenAI, Ollama, LM Studio, vLLM, OpenRouter, LiteLLM (`/v1/chat/completions`)
//! 3. `google` — Google Gemini (`:generateContent`)
//! 4. `lakera-guard` — Lakera Guard v2 (`POST /v2/guard`)
//! 5. `http-classifier` — Generic fast classifier sidecar (Meta Llama Prompt Guard 2 [22M/86M],
//!    LlamaFirewall, ProtectAI LLM Guard / DeBERTa-v3 ONNX, OpenShield)
//! 6. `subprocess` — Custom user-defined local script/binary speaking JSON-RPC 2.0 NDJSON
//!    `hyphae/filter` with strict timeout, clean env allowlist, kill-on-drop, and fail-closed `on_error`.

use std::future::Future;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{Method, Request, StatusCode};
use http_body_util::Full;
use hyp_crypto::SecretStore;
use hyp_proto::cloudevent::CloudEvent;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use crate::gates::policy::{
    AnthropicAuthHeader, FilterAdapterConfig, FilterPluginConfig, FilterPluginKind, GateDecision,
    GateError, InboundContext, LlmProvider, Stage2Config, Stage2ErrorAction, Stage2Matchers,
    format_quarantine_notice,
};
use crate::gates::stage2::{
    ClassifierVerdict, FilterOutcome, Stage2Guard, apply_verdict_with_threshold,
    build_gate_http_client, send_and_read_bounded, validate_classifier_endpoint_url,
    validate_verdict,
};

const DEFAULT_LAKERA_HOST: &str = "https://api.lakera.ai";
const MAX_SUBPROCESS_LINE_BYTES: usize = 64 * 1024;

/// Boxed `Send` future returned by [`FilterPlugin::evaluate`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Uniform trait for pluggable Local Security Gate filters.
pub trait FilterPlugin: Send + Sync {
    /// Stable identifier of this filter instance (recorded in `gate_audit.stage`).
    fn id(&self) -> &str;
    /// Adapter kind classification.
    fn kind(&self) -> FilterPluginKind;
    /// Optional opt-in matchers determining whether this filter runs for an inbound event.
    /// Returning `None` means the filter always runs when registered.
    fn matchers(&self) -> Option<&Stage2Matchers> {
        None
    }
    /// Evaluates an inbound post-decrypt CloudEvent and returns a fail-closed [`FilterOutcome`].
    fn evaluate<'a>(
        &'a self,
        ctx: &'a InboundContext,
        event: &'a CloudEvent,
        secrets: Option<&'a SecretStore>,
    ) -> BoxFuture<'a, FilterOutcome>;
}

/// Validates the configured HTTP classifier endpoint URL on a [`FilterPluginConfig`] fail-closed (`G17`).
pub fn validate_filter_plugin_endpoint_url(config: &FilterPluginConfig) -> Result<(), GateError> {
    match &config.adapter {
        FilterAdapterConfig::Anthropic {
            base_url: Some(u), ..
        }
        | FilterAdapterConfig::Google {
            base_url: Some(u), ..
        } => validate_classifier_endpoint_url(u).map_err(GateError::InvalidConfig),
        FilterAdapterConfig::OpenAiCompat { base_url, .. }
        | FilterAdapterConfig::LakeraGuard { base_url, .. } => {
            validate_classifier_endpoint_url(base_url).map_err(GateError::InvalidConfig)
        }
        FilterAdapterConfig::HttpClassifier { url, .. } => {
            validate_classifier_endpoint_url(url).map_err(GateError::InvalidConfig)
        }
        FilterAdapterConfig::Anthropic { base_url: None, .. }
        | FilterAdapterConfig::Google { base_url: None, .. }
        | FilterAdapterConfig::Subprocess { .. } => Ok(()),
    }
}

/// Instantiates a built-in [`FilterPlugin`] from a validated [`FilterPluginConfig`].
pub fn build_filter_plugin(
    config: &FilterPluginConfig,
) -> Result<Arc<dyn FilterPlugin>, GateError> {
    config.validate()?;
    validate_filter_plugin_endpoint_url(config)?;
    match &config.adapter {
        FilterAdapterConfig::Anthropic {
            model,
            temperature,
            max_output_tokens,
            timeout_ms,
            max_input_chars,
            min_allow_confidence,
            api_key_secret,
            base_url,
            auth_header,
            policy_notes,
        } => {
            let s2 = Stage2Config {
                enabled: config.enabled,
                matchers: config.matchers.clone(),
                provider: LlmProvider::Anthropic,
                base_url_override: base_url.clone(),
                auth_header: *auth_header,
                model: model.clone(),
                temperature: *temperature,
                api_key_secret: api_key_secret.clone(),
                policy_prompt: String::new(),
                policy_notes: policy_notes.clone(),
                max_input_chars: *max_input_chars,
                max_output_tokens: *max_output_tokens,
                timeout_ms: *timeout_ms,
                max_concurrent: config.max_concurrent,
                min_allow_confidence: *min_allow_confidence,
                on_error: config.on_error,
                busy_retry_after_ms: config.busy_retry_after_ms,
            };
            Ok(Arc::new(LlmGuardPlugin {
                id: config.id.clone(),
                kind: FilterPluginKind::Anthropic,
                matchers: config.matchers.clone(),
                guard: Stage2Guard::new(s2)?,
            }))
        }
        FilterAdapterConfig::OpenAiCompat {
            base_url,
            model,
            temperature,
            max_output_tokens,
            timeout_ms,
            max_input_chars,
            min_allow_confidence,
            api_key_secret,
            policy_notes,
        } => {
            let s2 = Stage2Config {
                enabled: config.enabled,
                matchers: config.matchers.clone(),
                provider: LlmProvider::OpenAiCompatible {
                    base_url: base_url.clone(),
                },
                base_url_override: None,
                auth_header: AnthropicAuthHeader::default(),
                model: model.clone(),
                temperature: *temperature,
                api_key_secret: api_key_secret.clone(),
                policy_prompt: String::new(),
                policy_notes: policy_notes.clone(),
                max_input_chars: *max_input_chars,
                max_output_tokens: *max_output_tokens,
                timeout_ms: *timeout_ms,
                max_concurrent: config.max_concurrent,
                min_allow_confidence: *min_allow_confidence,
                on_error: config.on_error,
                busy_retry_after_ms: config.busy_retry_after_ms,
            };
            Ok(Arc::new(LlmGuardPlugin {
                id: config.id.clone(),
                kind: FilterPluginKind::OpenAiCompat,
                matchers: config.matchers.clone(),
                guard: Stage2Guard::new(s2)?,
            }))
        }
        FilterAdapterConfig::Google {
            model,
            temperature,
            max_output_tokens,
            timeout_ms,
            max_input_chars,
            min_allow_confidence,
            api_key_secret,
            base_url,
            policy_notes,
        } => {
            let s2 = Stage2Config {
                enabled: config.enabled,
                matchers: config.matchers.clone(),
                provider: LlmProvider::Google,
                base_url_override: base_url.clone(),
                auth_header: AnthropicAuthHeader::default(),
                model: model.clone(),
                temperature: *temperature,
                api_key_secret: api_key_secret.clone(),
                policy_prompt: String::new(),
                policy_notes: policy_notes.clone(),
                max_input_chars: *max_input_chars,
                max_output_tokens: *max_output_tokens,
                timeout_ms: *timeout_ms,
                max_concurrent: config.max_concurrent,
                min_allow_confidence: *min_allow_confidence,
                on_error: config.on_error,
                busy_retry_after_ms: config.busy_retry_after_ms,
            };
            Ok(Arc::new(LlmGuardPlugin {
                id: config.id.clone(),
                kind: FilterPluginKind::Google,
                matchers: config.matchers.clone(),
                guard: Stage2Guard::new(s2)?,
            }))
        }
        FilterAdapterConfig::LakeraGuard {
            base_url,
            api_key_secret,
            project_id,
            timeout_ms,
            max_input_chars,
            on_flagged,
        } => Ok(Arc::new(LakeraGuardPlugin {
            id: config.id.clone(),
            matchers: config.matchers.clone(),
            base_url: base_url.clone(),
            api_key_secret: api_key_secret.clone(),
            project_id: project_id.clone(),
            timeout_ms: *timeout_ms,
            max_input_chars: *max_input_chars,
            on_flagged: *on_flagged,
            on_error: config.on_error,
            busy_retry_after_ms: config.busy_retry_after_ms,
            client: build_gate_http_client()?,
            semaphore: Arc::new(Semaphore::new(config.max_concurrent)),
        })),
        FilterAdapterConfig::HttpClassifier {
            url,
            api_key_secret,
            auth_header,
            score_field,
            label_field,
            flagged_labels,
            threshold,
            timeout_ms,
            max_input_chars,
            on_flagged,
        } => Ok(Arc::new(HttpClassifierPlugin {
            id: config.id.clone(),
            matchers: config.matchers.clone(),
            url: url.clone(),
            api_key_secret: api_key_secret.clone(),
            auth_header: auth_header.clone(),
            score_field: score_field.clone(),
            label_field: label_field.clone(),
            flagged_labels: flagged_labels.clone(),
            threshold: *threshold,
            timeout_ms: *timeout_ms,
            max_input_chars: *max_input_chars,
            on_flagged: *on_flagged,
            on_error: config.on_error,
            busy_retry_after_ms: config.busy_retry_after_ms,
            client: build_gate_http_client()?,
            semaphore: Arc::new(Semaphore::new(config.max_concurrent)),
        })),
        FilterAdapterConfig::Subprocess {
            command,
            args,
            env_allowlist,
            timeout_ms,
            max_input_chars,
            min_allow_confidence,
        } => Ok(Arc::new(SubprocessFilterPlugin {
            id: config.id.clone(),
            matchers: config.matchers.clone(),
            command: command.clone(),
            args: args.clone(),
            env_allowlist: env_allowlist.clone(),
            timeout_ms: *timeout_ms,
            max_input_chars: *max_input_chars,
            min_allow_confidence: *min_allow_confidence,
            on_error: config.on_error,
            busy_retry_after_ms: config.busy_retry_after_ms,
            semaphore: Arc::new(Semaphore::new(config.max_concurrent)),
        })),
    }
}

// ============================================================================
// 1-3. LLM Guard Plugin Adapter (Anthropic / OpenAI-Compat / Google)
// ============================================================================

struct LlmGuardPlugin {
    id: String,
    kind: FilterPluginKind,
    matchers: Stage2Matchers,
    guard: Stage2Guard,
}

impl FilterPlugin for LlmGuardPlugin {
    fn id(&self) -> &str {
        &self.id
    }

    fn kind(&self) -> FilterPluginKind {
        self.kind
    }

    fn matchers(&self) -> Option<&Stage2Matchers> {
        Some(&self.matchers)
    }

    fn evaluate<'a>(
        &'a self,
        ctx: &'a InboundContext,
        _event: &'a CloudEvent,
        secrets: Option<&'a SecretStore>,
    ) -> BoxFuture<'a, FilterOutcome> {
        Box::pin(async move {
            self.guard
                .evaluate(ctx, secrets)
                .await
                .with_plugin_id(self.id.clone())
        })
    }
}

// ============================================================================
// 4. Lakera Guard v2 Adapter (`POST /v2/guard`)
// ============================================================================

struct LakeraGuardPlugin {
    id: String,
    matchers: Stage2Matchers,
    base_url: String,
    api_key_secret: Option<String>,
    project_id: Option<String>,
    timeout_ms: u64,
    max_input_chars: usize,
    on_flagged: Stage2ErrorAction,
    on_error: Stage2ErrorAction,
    busy_retry_after_ms: u64,
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    semaphore: Arc<Semaphore>,
}

impl FilterPlugin for LakeraGuardPlugin {
    fn id(&self) -> &str {
        &self.id
    }

    fn kind(&self) -> FilterPluginKind {
        FilterPluginKind::LakeraGuard
    }

    fn matchers(&self) -> Option<&Stage2Matchers> {
        Some(&self.matchers)
    }

    fn evaluate<'a>(
        &'a self,
        ctx: &'a InboundContext,
        _event: &'a CloudEvent,
        secrets: Option<&'a SecretStore>,
    ) -> BoxFuture<'a, FilterOutcome> {
        Box::pin(async move {
            let outcome = self.evaluate_inner(ctx, secrets).await;
            outcome.with_plugin_id(self.id.clone())
        })
    }
}

impl LakeraGuardPlugin {
    async fn evaluate_inner(
        &self,
        ctx: &InboundContext,
        secrets: Option<&SecretStore>,
    ) -> FilterOutcome {
        let Ok(_permit) = self.semaphore.clone().try_acquire_owned() else {
            return FilterOutcome::hold("gate_busy", self.busy_retry_after_ms);
        };

        let raw_content = ctx.payload_text();
        let content_chars = raw_content.chars().count();
        if content_chars > self.max_input_chars {
            return FilterOutcome::over_budget(content_chars, self.max_input_chars);
        }

        let api_key = match resolve_optional_secret(
            &self.api_key_secret,
            secrets,
            self.base_url.trim_end_matches('/') == DEFAULT_LAKERA_HOST,
        ) {
            Ok(key) => key,
            Err(code) => return FilterOutcome::from_error(self.on_error, code),
        };

        let base = self.base_url.trim_end_matches('/');
        let url = if base.ends_with("/v2/guard") {
            base.to_string()
        } else {
            format!("{base}/v2/guard")
        };
        if validate_classifier_endpoint_url(&url).is_err() {
            return FilterOutcome::from_error(self.on_error, "gate_insecure_endpoint_url");
        }

        let mut payload = json!({
            "messages": [
                { "role": "user", "content": raw_content }
            ],
            "breakdown": true
        });
        if let Some(pid) = &self.project_id {
            if let Value::Object(ref mut map) = payload {
                map.insert("project_id".to_string(), Value::String(pid.clone()));
            }
        }

        let Ok(body_vec) = serde_json::to_vec(&payload) else {
            return FilterOutcome::from_error(self.on_error, "gate_request_serialize_error");
        };

        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(&url)
            .header("content-type", "application/json");
        if let Some(key) = api_key {
            builder = builder.header("authorization", format!("Bearer {}", &*key));
        }
        let Ok(req) = builder.body(Full::new(Bytes::from(body_vec))) else {
            return FilterOutcome::from_error(self.on_error, "gate_invalid_request");
        };

        let timeout = Duration::from_millis(self.timeout_ms);
        let (status, resp_bytes) =
            match tokio::time::timeout(timeout, send_and_read_bounded(&self.client, req)).await {
                Err(_) => return FilterOutcome::from_error(self.on_error, "gate_timeout"),
                Ok(Err(code)) => return FilterOutcome::from_error(self.on_error, code),
                Ok(Ok(pair)) => pair,
            };

        if status == StatusCode::TOO_MANY_REQUESTS {
            return FilterOutcome::from_error(self.on_error, "gate_rate_limited");
        }
        if !status.is_success() {
            let code = format!("gate_http_{}", status.as_u16());
            return FilterOutcome::from_error(self.on_error, &code);
        }

        let Ok(parsed) = serde_json::from_slice::<Value>(&resp_bytes) else {
            return FilterOutcome::from_error(self.on_error, "gate_malformed_response");
        };
        let Some(flagged) = parsed.get("flagged").and_then(Value::as_bool) else {
            return FilterOutcome::from_error(self.on_error, "gate_malformed_response");
        };

        let mut categories = Vec::new();
        if let Some(breakdown) = parsed.get("breakdown").and_then(Value::as_array) {
            for item in breakdown.iter().take(16) {
                if item.get("detected").and_then(Value::as_bool) == Some(true) {
                    if let Some(dt) = item.get("detector_type").and_then(Value::as_str) {
                        let clean = sanitize_tag(dt);
                        if !clean.is_empty() && !categories.contains(&clean) {
                            categories.push(clean);
                        }
                    }
                }
            }
        }

        if flagged {
            if !categories.iter().any(|c| c == "lakera_flagged") {
                categories.insert(0, "lakera_flagged".to_string());
            }
            let reason = if categories.len() > 1 {
                format!("lakera_flagged:{}", categories[1..].join(","))
            } else {
                "lakera_flagged".to_string()
            };
            let decision = match self.on_flagged {
                Stage2ErrorAction::Quarantine => GateDecision::Quarantine {
                    reason,
                    notice: format_quarantine_notice("lakera_flagged"),
                },
                Stage2ErrorAction::Block => GateDecision::Block { reason },
            };
            FilterOutcome {
                decision,
                confidence: Some(1.0),
                categories,
                had_error: false,
                plugin_id: None,
            }
        } else {
            FilterOutcome {
                decision: GateDecision::Allow {
                    downgraded_to_notify: false,
                },
                confidence: Some(1.0),
                categories: vec!["lakera_clean".to_string()],
                had_error: false,
                plugin_id: None,
            }
        }
    }
}

// ============================================================================
// 5. Generic Fast HTTP Classifier Adapter (Llama Prompt Guard 2 / DeBERTa / OpenShield)
// ============================================================================

struct HttpClassifierPlugin {
    id: String,
    matchers: Stage2Matchers,
    url: String,
    api_key_secret: Option<String>,
    auth_header: Option<String>,
    score_field: String,
    label_field: String,
    flagged_labels: Vec<String>,
    threshold: f64,
    timeout_ms: u64,
    max_input_chars: usize,
    on_flagged: Stage2ErrorAction,
    on_error: Stage2ErrorAction,
    busy_retry_after_ms: u64,
    client: Client<HttpsConnector<HttpConnector>, Full<Bytes>>,
    semaphore: Arc<Semaphore>,
}

impl FilterPlugin for HttpClassifierPlugin {
    fn id(&self) -> &str {
        &self.id
    }

    fn kind(&self) -> FilterPluginKind {
        FilterPluginKind::HttpClassifier
    }

    fn matchers(&self) -> Option<&Stage2Matchers> {
        Some(&self.matchers)
    }

    fn evaluate<'a>(
        &'a self,
        ctx: &'a InboundContext,
        _event: &'a CloudEvent,
        secrets: Option<&'a SecretStore>,
    ) -> BoxFuture<'a, FilterOutcome> {
        Box::pin(async move {
            let outcome = self.evaluate_inner(ctx, secrets).await;
            outcome.with_plugin_id(self.id.clone())
        })
    }
}

impl HttpClassifierPlugin {
    async fn evaluate_inner(
        &self,
        ctx: &InboundContext,
        secrets: Option<&SecretStore>,
    ) -> FilterOutcome {
        let Ok(_permit) = self.semaphore.clone().try_acquire_owned() else {
            return FilterOutcome::hold("gate_busy", self.busy_retry_after_ms);
        };

        let text = ctx.payload_text();
        let text_chars = text.chars().count();
        if text_chars > self.max_input_chars {
            return FilterOutcome::over_budget(text_chars, self.max_input_chars);
        }

        let api_key = match resolve_optional_secret(&self.api_key_secret, secrets, false) {
            Ok(key) => key,
            Err(code) => return FilterOutcome::from_error(self.on_error, code),
        };

        if validate_classifier_endpoint_url(&self.url).is_err() {
            return FilterOutcome::from_error(self.on_error, "gate_insecure_endpoint_url");
        }

        let Ok(body_vec) = serde_json::to_vec(&json!({ "text": text })) else {
            return FilterOutcome::from_error(self.on_error, "gate_request_serialize_error");
        };

        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(&self.url)
            .header("content-type", "application/json");
        if let Some(key) = api_key {
            match self.auth_header.as_deref() {
                Some(header) if !header.eq_ignore_ascii_case("authorization") => {
                    builder = builder.header(header, &*key);
                }
                _ => {
                    builder = builder.header("authorization", format!("Bearer {}", &*key));
                }
            }
        }
        let Ok(req) = builder.body(Full::new(Bytes::from(body_vec))) else {
            return FilterOutcome::from_error(self.on_error, "gate_invalid_request");
        };

        let timeout = Duration::from_millis(self.timeout_ms);
        let (status, resp_bytes) =
            match tokio::time::timeout(timeout, send_and_read_bounded(&self.client, req)).await {
                Err(_) => return FilterOutcome::from_error(self.on_error, "gate_timeout"),
                Ok(Err(code)) => return FilterOutcome::from_error(self.on_error, code),
                Ok(Ok(pair)) => pair,
            };

        if status == StatusCode::TOO_MANY_REQUESTS {
            return FilterOutcome::from_error(self.on_error, "gate_rate_limited");
        }
        if !status.is_success() {
            let code = format!("gate_http_{}", status.as_u16());
            return FilterOutcome::from_error(self.on_error, &code);
        }

        let Ok(parsed) = serde_json::from_slice::<Value>(&resp_bytes) else {
            return FilterOutcome::from_error(self.on_error, "gate_malformed_response");
        };

        let Some(score) = lookup_json_path(&parsed, &self.score_field).and_then(Value::as_f64)
        else {
            return FilterOutcome::from_error(self.on_error, "gate_invalid_score");
        };
        if !score.is_finite() || !(0.0..=1.0).contains(&score) {
            return FilterOutcome::from_error(self.on_error, "gate_invalid_score");
        }

        let label = if self.label_field.trim().is_empty() {
            None
        } else {
            lookup_json_path(&parsed, &self.label_field)
                .and_then(Value::as_str)
                .map(sanitize_tag)
                .filter(|s| !s.is_empty())
        };

        let is_flagged = if self.flagged_labels.is_empty() {
            score >= self.threshold
        } else {
            let Some(ref lbl) = label else {
                return FilterOutcome::from_error(self.on_error, "gate_malformed_response");
            };
            let label_matches = self
                .flagged_labels
                .iter()
                .any(|f| f.trim().eq_ignore_ascii_case(lbl));
            label_matches && score >= self.threshold
        };

        if is_flagged {
            let mut categories = vec!["classifier_flagged".to_string()];
            if let Some(lbl) = label {
                categories.push(lbl);
            }
            let reason = format!("classifier_flagged:{:.2}>={:.2}", score, self.threshold);
            let decision = match self.on_flagged {
                Stage2ErrorAction::Quarantine => GateDecision::Quarantine {
                    reason,
                    notice: format_quarantine_notice("classifier_flagged"),
                },
                Stage2ErrorAction::Block => GateDecision::Block { reason },
            };
            FilterOutcome {
                decision,
                confidence: Some(score),
                categories,
                had_error: false,
                plugin_id: None,
            }
        } else {
            let mut categories = vec!["classifier_clean".to_string()];
            if let Some(lbl) = label {
                categories.push(lbl);
            }
            FilterOutcome {
                decision: GateDecision::Allow {
                    downgraded_to_notify: false,
                },
                confidence: Some(score),
                categories,
                had_error: false,
                plugin_id: None,
            }
        }
    }
}

// ============================================================================
// 6. Custom Subprocess Filter Plugin (JSON-RPC 2.0 NDJSON `hyphae/filter`)
// ============================================================================

struct SubprocessFilterPlugin {
    id: String,
    matchers: Stage2Matchers,
    command: String,
    args: Vec<String>,
    env_allowlist: Vec<String>,
    timeout_ms: u64,
    max_input_chars: usize,
    min_allow_confidence: f64,
    on_error: Stage2ErrorAction,
    busy_retry_after_ms: u64,
    semaphore: Arc<Semaphore>,
}

impl FilterPlugin for SubprocessFilterPlugin {
    fn id(&self) -> &str {
        &self.id
    }

    fn kind(&self) -> FilterPluginKind {
        FilterPluginKind::Subprocess
    }

    fn matchers(&self) -> Option<&Stage2Matchers> {
        Some(&self.matchers)
    }

    fn evaluate<'a>(
        &'a self,
        ctx: &'a InboundContext,
        event: &'a CloudEvent,
        _secrets: Option<&'a SecretStore>,
    ) -> BoxFuture<'a, FilterOutcome> {
        Box::pin(async move {
            let outcome = self.evaluate_inner(ctx, event).await;
            outcome.with_plugin_id(self.id.clone())
        })
    }
}

impl SubprocessFilterPlugin {
    async fn evaluate_inner(&self, ctx: &InboundContext, event: &CloudEvent) -> FilterOutcome {
        let Ok(_permit) = self.semaphore.clone().try_acquire_owned() else {
            return FilterOutcome::hold("gate_busy", self.busy_retry_after_ms);
        };

        let body_text = ctx.payload_text();
        let body_chars = body_text.chars().count();
        if body_chars > self.max_input_chars {
            return FilterOutcome::over_budget(body_chars, self.max_input_chars);
        }
        let rpc_req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "hyphae/filter",
            "params": {
                "event": event,
                "trustTier": ctx.trust_tier.as_str(),
                "direction": "inbound",
                "originNode": ctx.origin_node,
                "sender": ctx.sender,
                "body": body_text,
            }
        });
        let Ok(mut line) = serde_json::to_string(&rpc_req) else {
            return FilterOutcome::from_error(self.on_error, "gate_request_serialize_error");
        };
        line.push('\n');

        let timeout = Duration::from_millis(self.timeout_ms);
        let run_res = tokio::time::timeout(timeout, self.invoke_child(line)).await;

        let resp_line = match run_res {
            Err(_) => return FilterOutcome::from_error(self.on_error, "gate_subprocess_timeout"),
            Ok(Err(code)) => return FilterOutcome::from_error(self.on_error, code),
            Ok(Ok(line)) => line,
        };

        let verdict = match parse_subprocess_rpc_response(&resp_line) {
            Ok(v) => v,
            Err(code) => return FilterOutcome::from_error(self.on_error, code),
        };

        apply_verdict_with_threshold(verdict, self.min_allow_confidence, self.on_error)
    }

    async fn invoke_child(&self, request_line: String) -> Result<String, &'static str> {
        let mut cmd = Command::new(&self.command);
        cmd.args(&self.args)
            .env_clear()
            .env("HYPHAE_PROTOCOL", "2")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);

        // Minimal safe baseline PATH + explicit operator env allowlist (zero ambient secrets leaked!).
        if let Ok(path) = std::env::var("PATH") {
            cmd.env("PATH", path);
        }
        for key in &self.env_allowlist {
            let trimmed = key.trim();
            if !trimmed.is_empty() {
                if let Ok(val) = std::env::var(trimmed) {
                    cmd.env(trimmed, val);
                }
            }
        }

        let mut child = cmd.spawn().map_err(|_| "gate_subprocess_spawn_failed")?;
        if let Some(mut stdin) = child.stdin.take() {
            if let Err(err) = stdin.write_all(request_line.as_bytes()).await {
                if err.kind() != std::io::ErrorKind::BrokenPipe {
                    return Err("gate_subprocess_io_error");
                }
            } else if let Err(err) = stdin.flush().await {
                if err.kind() != std::io::ErrorKind::BrokenPipe {
                    return Err("gate_subprocess_io_error");
                }
            }
            // Close stdin to signal EOF for single-shot filter scripts.
            drop(stdin);
        } else {
            return Err("gate_subprocess_io_error");
        }

        let Some(stdout) = child.stdout.take() else {
            return Err("gate_subprocess_io_error");
        };
        let mut reader = BufReader::new(stdout.take((MAX_SUBPROCESS_LINE_BYTES + 1) as u64));
        let mut line = String::new();
        let bytes_read = reader
            .read_line(&mut line)
            .await
            .map_err(|_| "gate_subprocess_io_error")?;

        if bytes_read == 0 {
            let _ = child.wait().await;
            return Err("gate_subprocess_crashed");
        }
        if bytes_read > MAX_SUBPROCESS_LINE_BYTES {
            let _ = child.kill().await;
            return Err("gate_subprocess_response_too_large");
        }

        // Wait cleanly for single-shot exit (if it stays alive as persistent, drop kills it cleanly).
        if let Ok(Some(status)) = child.try_wait() {
            if !status.success() {
                return Err("gate_subprocess_nonzero_exit");
            }
        }
        Ok(line)
    }
}

fn parse_subprocess_rpc_response(raw_line: &str) -> Result<ClassifierVerdict, &'static str> {
    let val: Value =
        serde_json::from_str(raw_line.trim()).map_err(|_| "gate_subprocess_invalid_json")?;
    let Some(obj) = val.as_object() else {
        return Err("gate_subprocess_invalid_json");
    };
    if obj.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err("gate_subprocess_invalid_rpc");
    }
    if obj.get("id").and_then(Value::as_i64) != Some(1) {
        return Err("gate_subprocess_invalid_rpc");
    }
    if obj.get("error").is_some() && !obj["error"].is_null() {
        return Err("gate_subprocess_rpc_error");
    }
    let Some(result) = obj.get("result").and_then(Value::as_object) else {
        return Err("gate_subprocess_invalid_rpc");
    };

    let decision = result
        .get("decision")
        .and_then(Value::as_str)
        .ok_or("gate_invalid_decision")?
        .to_string();

    let confidence = match result.get("confidence") {
        None | Some(Value::Null) => 1.0,
        Some(v) => v.as_f64().ok_or("gate_invalid_confidence")?,
    };

    let categories = match result.get("categories") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(arr)) => {
            let mut out = Vec::with_capacity(arr.len().min(16));
            for item in arr.iter().take(16) {
                let s = item.as_str().ok_or("gate_invalid_categories")?;
                let clean = sanitize_tag(s);
                if !clean.is_empty() {
                    out.push(clean);
                }
            }
            out
        }
        Some(_) => return Err("gate_invalid_categories"),
    };

    let reason = match result.get("reason") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(s)) => s.clone(),
        Some(_) => return Err("gate_invalid_reason"),
    };

    validate_verdict(ClassifierVerdict {
        decision,
        confidence,
        categories,
        reason,
    })
}

fn resolve_optional_secret(
    secret_name: &Option<String>,
    secrets: Option<&SecretStore>,
    required: bool,
) -> Result<Option<Zeroizing<String>>, &'static str> {
    match secret_name {
        Some(name) => {
            let Some(store) = secrets else {
                return Err("gate_secret_store_missing");
            };
            store
                .get(name)
                .map(Some)
                .map_err(|_| "gate_secret_unavailable")
        }
        None if required => Err("gate_api_key_missing"),
        None => Ok(None),
    }
}

/// Navigates dotted paths with optional array indices (e.g. `"score"`, `"results.0.score"`, `"0.score"`).
fn lookup_json_path<'a>(root: &'a Value, path: &str) -> Option<&'a Value> {
    let mut cur = root;
    for seg in path.split('.') {
        if seg.is_empty() {
            return None;
        }
        match cur {
            Value::Object(map) => {
                cur = map.get(seg)?;
            }
            Value::Array(arr) => {
                let idx: usize = seg.parse().ok()?;
                cur = arr.get(idx)?;
            }
            _ => return None,
        }
    }
    Some(cur)
}

fn sanitize_tag(raw: &str) -> String {
    raw.trim()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':' | '/'))
        .take(64)
        .collect()
}
