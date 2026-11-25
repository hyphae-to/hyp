//! `hyp gate` (`init`, `propose`, `lock`, `review`, `log`) & `hyp inbox` (`approve`, `reject`).
//!
//! Human-CLI-only Local Security Gate management:
//! - Never writes plaintext API keys (`{ "secret": "<name>" }` / `api_key_secret` references only!).
//! - Tamper-evident `gate_policy_sig` signing & verification via `hyp_node::gates::policy`.
//! - Human-only quarantine review, approval, rejection (+ atomic Stage 1 mute), and immutable
//!   `gate_audit` log inspection.

use crate::config_file::{
    default_node_id, ensure_v2_node_json_defaults, open_secret_store, read_json_object_or_empty,
    resolve_config_path_for_read, resolve_config_path_for_write, resolve_state_dir,
    write_atomic_json,
};
use crate::ui::{
    EXIT_ERROR, EXIT_OK, EXIT_USAGE, JsonEnvelope, emit_error, print_json, print_next_steps,
};
use clap::{Args, Subcommand, ValueEnum};
use hyp_crypto::keystore::{SecretStore, validate_secret_name};
use hyp_harness::sock::{DEFAULT_SOCKET_FILENAME, DaemonRpcResult, daemon_rpc_sync};
use hyp_node::engine::NodeProfile;
use hyp_node::gates::policy::{
    AnthropicAuthHeader, DEFAULT_HTTP_CLASSIFIER_THRESHOLD, DEFAULT_STAGE2_BUSY_RETRY_MS,
    DEFAULT_STAGE2_MAX_CONCURRENT, DEFAULT_STAGE2_MAX_INPUT_CHARS,
    DEFAULT_STAGE2_MAX_OUTPUT_TOKENS, DEFAULT_STAGE2_MIN_ALLOW_CONFIDENCE,
    DEFAULT_STAGE2_TIMEOUT_MS, FilterAdapterConfig, FilterPluginConfig, SecurityGateConfig,
    Stage2ErrorAction, Stage2Matchers, TrustTier, sign_gate_policy, verify_gate_policy_sig,
};
use hyp_store::{
    GateAuditQuery, GateDecision as StoreGateDecision, MuteRuleInput, NodeDb, StoreError, now_ms,
};
use serde::Serialize;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

const LIVE_DAEMON_RPC_TIMEOUT: Duration = Duration::from_millis(1_500);

fn resolve_daemon_socket_for_cli(
    explicit_state_dir: bool,
    explicit_config: bool,
    resolved_state_dir: &std::path::Path,
) -> PathBuf {
    if !explicit_state_dir && !explicit_config {
        for key in ["HYPHAE_SOCKET", "AGENTS_MESH_SOCKET"] {
            if let Ok(sock) = std::env::var(key) {
                let trimmed = sock.trim();
                if !trimmed.is_empty() {
                    return PathBuf::from(trimmed);
                }
            }
        }
    }
    resolved_state_dir.join(DEFAULT_SOCKET_FILENAME)
}

fn try_live_gate_reload(
    explicit_state_dir: bool,
    explicit_config: bool,
    resolved_state_dir: &std::path::Path,
) -> DaemonRpcResult {
    let sock =
        resolve_daemon_socket_for_cli(explicit_state_dir, explicit_config, resolved_state_dir);
    daemon_rpc_sync(&sock, &json!({ "type": "gate.reload" }), LIVE_DAEMON_RPC_TIMEOUT)
}

fn try_live_inbox_wake(
    explicit_state_dir: bool,
    resolved_state_dir: &std::path::Path,
    session_id: &str,
    receipt: &str,
) -> DaemonRpcResult {
    let sock = resolve_daemon_socket_for_cli(explicit_state_dir, false, resolved_state_dir);
    daemon_rpc_sync(
        &sock,
        &json!({
            "type": "inbox.wake",
            "sessionId": session_id,
            "receipt": receipt,
        }),
        LIVE_DAEMON_RPC_TIMEOUT,
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CliGateAdapter {
    Anthropic,
    #[value(name = "openai-compat")]
    OpenAiCompat,
    Google,
    #[value(name = "lakera-guard")]
    LakeraGuard,
    #[value(name = "http-classifier")]
    HttpClassifier,
    Subprocess,
}

impl CliGateAdapter {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Anthropic => "anthropic",
            Self::OpenAiCompat => "openai-compat",
            Self::Google => "google",
            Self::LakeraGuard => "lakera-guard",
            Self::HttpClassifier => "http-classifier",
            Self::Subprocess => "subprocess",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CliGateLogDecision {
    All,
    Quarantined,
    Quarantine,
    Blocked,
    Block,
    Allowed,
    Allow,
    Error,
}

impl CliGateLogDecision {
    pub const fn to_store_filter(self) -> Option<StoreGateDecision> {
        match self {
            Self::All => None,
            Self::Quarantined | Self::Quarantine => Some(StoreGateDecision::Quarantine),
            Self::Blocked | Self::Block => Some(StoreGateDecision::Block),
            Self::Allowed | Self::Allow => Some(StoreGateDecision::Allow),
            Self::Error => Some(StoreGateDecision::Error),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CliAnthropicAuthHeader {
    #[value(name = "x-api-key")]
    XApiKey,
    #[value(name = "bearer")]
    Bearer,
}

impl CliAnthropicAuthHeader {
    pub const fn to_policy(self) -> AnthropicAuthHeader {
        match self {
            Self::XApiKey => AnthropicAuthHeader::XApiKey,
            Self::Bearer => AnthropicAuthHeader::Bearer,
        }
    }
}

#[derive(Args)]
pub struct GateInitArgs {
    /// Guardrail / classifier adapter type
    #[arg(long, value_enum)]
    pub adapter: CliGateAdapter,
    /// Optional unique filter ID (defaults to "<adapter>-guard")
    #[arg(long)]
    pub id: Option<String>,
    /// Optional classifier/API base URL (required for http-classifier; defaults to Ollama for openai-compat)
    #[arg(long)]
    pub base_url: Option<String>,
    /// Anthropic authentication header format (x-api-key default, or bearer for custom proxies; --adapter anthropic only)
    #[arg(long, value_enum)]
    pub auth_header: Option<CliAnthropicAuthHeader>,
    /// Model identifier (e.g. claude-haiku-4-5, gemini-2.5-flash-lite, qwen2.5:3b)
    #[arg(long)]
    pub model: Option<String>,
    /// SecretStore key name holding the API key (NEVER pass a plaintext key!)
    #[arg(long)]
    pub secret: Option<String>,
    /// Subprocess executable command (required for --adapter subprocess)
    #[arg(long)]
    pub command: Option<String>,
    /// Optional subprocess arguments (repeatable)
    #[arg(long = "arg")]
    pub args: Vec<String>,
    /// Additive operator policy guidance appended after the immutable core rubric
    #[arg(long)]
    pub policy_notes: Option<String>,
    /// Explicit node.json path
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Explicit state directory for SecretStore and node.json
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    /// Immediately sign gate_policy_sig and enable tamper-evident require_signed_policy
    #[arg(long)]
    pub lock: bool,
    /// Output structured JSON envelope
    #[arg(long)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum GateCommand {
    /// Configure a Local Security Gate filter adapter in node.json (never plaintext API keys!)
    #[command(alias = "add")]
    Init(GateInitArgs),
    /// Stage an unsigned gate policy proposal for human inspection before `gate lock`
    Propose(GateInitArgs),
    /// Validate gate policy in node.json and sign tamper-evident gate_policy_sig via SecretStore
    Lock {
        /// Explicit node.json path
        #[arg(long)]
        config: Option<PathBuf>,
        /// Explicit state directory for SecretStore
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// List quarantined mailbox items awaiting human CLI disposition (human CLI only!)
    Review {
        /// Optional filter by session ID
        #[arg(long)]
        session: Option<String>,
        /// Maximum quarantined items to display
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Explicit state directory containing node.sqlite
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Query the immutable gate_audit trail
    Log {
        /// Filter by decision (quarantined, blocked, allowed, error, or all)
        #[arg(long, value_enum, default_value_t = CliGateLogDecision::All)]
        decision: CliGateLogDecision,
        /// Maximum audit rows to return
        #[arg(long, default_value_t = 50)]
        limit: usize,
        /// Optional filter by session ID
        #[arg(long)]
        session: Option<String>,
        /// Explicit state directory containing node.sqlite
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub enum InboxCommand {
    /// Human-CLI-only approval releasing a quarantined mailbox item into the target session inbox
    Approve {
        /// Quarantined mailbox receipt ID
        receipt: String,
        /// Reviewer identity recorded in immutable gate_audit
        #[arg(long, default_value = "human-cli")]
        reviewer: String,
        /// Explicit state directory containing node.sqlite
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Human-CLI-only rejection permanently dropping a quarantined item (optionally installing a global mute rule)
    Reject {
        /// Quarantined mailbox receipt ID
        receipt: String,
        /// Atomically install a Stage 1 global mute rule for the item's sender
        #[arg(long)]
        mute: bool,
        /// Rejection reason recorded in immutable gate_audit
        #[arg(long, default_value = "rejected by human reviewer")]
        reason: String,
        /// Reviewer identity recorded in immutable gate_audit
        #[arg(long, default_value = "human-cli")]
        reviewer: String,
        /// Explicit state directory containing node.sqlite
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GateFilterSummary {
    pub id: String,
    pub adapter_type: String,
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_header: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct GateStatusSummary {
    pub configured: bool,
    pub require_signed_policy: bool,
    /// `"OK"`, `"FAIL"`, or `"UNSIGNED"`
    pub gate_policy_sig: String,
    pub tampered: bool,
    pub detail: String,
    pub filters: Vec<GateFilterSummary>,
    pub quarantined_count: usize,
}

/// Evaluates Security Gate configuration, tamper-evident `gate_policy_sig` verification,
/// active `FilterPlugin` adapters, and quarantined item count for `status` & `doctor`.
pub fn inspect_gate_status(
    raw_config: Option<&Value>,
    secrets: &SecretStore,
    db: Option<&NodeDb>,
) -> GateStatusSummary {
    let quarantined_count = db
        .and_then(|d| d.local().list_quarantined(None, 10_000).ok())
        .map(|v| v.len())
        .unwrap_or(0);

    let Some(gate_val) = raw_config.and_then(|c| c.get("gate")) else {
        return GateStatusSummary {
            configured: false,
            require_signed_policy: false,
            gate_policy_sig: "UNSIGNED".to_string(),
            tampered: false,
            detail: "Stage 1 deterministic defaults active (no custom Stage 2 / filter plugins configured)".to_string(),
            filters: Vec::new(),
            quarantined_count,
        };
    };

    let gate_cfg: SecurityGateConfig = match serde_json::from_value(gate_val.clone()) {
        Ok(cfg) => cfg,
        Err(e) => {
            return GateStatusSummary {
                configured: true,
                require_signed_policy: true,
                gate_policy_sig: "FAIL".to_string(),
                tampered: true,
                detail: format!("gate_policy_tampered: malformed gate config ({e})"),
                filters: Vec::new(),
                quarantined_count,
            };
        }
    };

    let filters: Vec<GateFilterSummary> = gate_cfg
        .filters
        .iter()
        .map(summarize_filter_plugin)
        .collect();

    if gate_cfg.require_signed_policy || gate_cfg.policy_signature.is_some() {
        match gate_cfg.policy_signature.as_deref() {
            Some(sig) => match verify_gate_policy_sig(&gate_cfg, sig, secrets) {
                Ok(()) => {
                    if let Some(ref expected_digest) = gate_cfg.human_authorities_digest {
                        let actual_digest = db.and_then(|d| d.human().authorities_digest().ok());
                        if actual_digest.as_deref() != Some(expected_digest.as_str()) {
                            return GateStatusSummary {
                                configured: true,
                                require_signed_policy: gate_cfg.require_signed_policy,
                                gate_policy_sig: "FAIL".to_string(),
                                tampered: true,
                                detail: "gate_policy_tampered: human_authorities_digest mismatch with node.sqlite"
                                    .to_string(),
                                filters,
                                quarantined_count,
                            };
                        }
                    }
                    GateStatusSummary {
                        configured: true,
                        require_signed_policy: gate_cfg.require_signed_policy,
                        gate_policy_sig: "OK".to_string(),
                        tampered: false,
                        detail: format!(
                            "Signed gate policy verified ({} filter adapter(s), {} quarantined)",
                            filters.len(),
                            quarantined_count
                        ),
                        filters,
                        quarantined_count,
                    }
                }
                Err(e) => GateStatusSummary {
                    configured: true,
                    require_signed_policy: gate_cfg.require_signed_policy,
                    gate_policy_sig: "FAIL".to_string(),
                    tampered: true,
                    detail: format!("gate_policy_tampered: {e}"),
                    filters,
                    quarantined_count,
                },
            },
            None => GateStatusSummary {
                configured: true,
                require_signed_policy: true,
                gate_policy_sig: "FAIL".to_string(),
                tampered: true,
                detail: "gate_policy_tampered: require_signed_policy is true but policy_signature is missing"
                    .to_string(),
                filters,
                quarantined_count,
            },
        }
    } else {
        GateStatusSummary {
            configured: true,
            require_signed_policy: false,
            gate_policy_sig: "UNSIGNED".to_string(),
            tampered: false,
            detail: format!(
                "Unsigned gate policy ({} filter adapter(s)); run `hyp gate lock` to enforce tamper-evident signing",
                filters.len()
            ),
            filters,
            quarantined_count,
        }
    }
}

fn summarize_filter_plugin(cfg: &FilterPluginConfig) -> GateFilterSummary {
    match &cfg.adapter {
        FilterAdapterConfig::Anthropic {
            model,
            api_key_secret,
            auth_header,
            ..
        } => GateFilterSummary {
            id: cfg.id.clone(),
            adapter_type: "anthropic".to_string(),
            enabled: cfg.enabled,
            target: Some(model.clone()),
            api_key_secret: api_key_secret.clone(),
            auth_header: Some(auth_header.as_str().to_string()),
        },
        FilterAdapterConfig::OpenAiCompat {
            base_url,
            model,
            api_key_secret,
            ..
        } => GateFilterSummary {
            id: cfg.id.clone(),
            adapter_type: "openai-compat".to_string(),
            enabled: cfg.enabled,
            target: Some(format!("{model} @ {base_url}")),
            api_key_secret: api_key_secret.clone(),
            auth_header: None,
        },
        FilterAdapterConfig::Google {
            model,
            api_key_secret,
            ..
        } => GateFilterSummary {
            id: cfg.id.clone(),
            adapter_type: "google".to_string(),
            enabled: cfg.enabled,
            target: Some(model.clone()),
            api_key_secret: api_key_secret.clone(),
            auth_header: None,
        },
        FilterAdapterConfig::LakeraGuard {
            base_url,
            api_key_secret,
            ..
        } => GateFilterSummary {
            id: cfg.id.clone(),
            adapter_type: "lakera-guard".to_string(),
            enabled: cfg.enabled,
            target: Some(base_url.clone()),
            api_key_secret: api_key_secret.clone(),
            auth_header: None,
        },
        FilterAdapterConfig::HttpClassifier {
            url,
            api_key_secret,
            ..
        } => GateFilterSummary {
            id: cfg.id.clone(),
            adapter_type: "http-classifier".to_string(),
            enabled: cfg.enabled,
            target: Some(url.clone()),
            api_key_secret: api_key_secret.clone(),
            auth_header: None,
        },
        FilterAdapterConfig::Subprocess { command, .. } => GateFilterSummary {
            id: cfg.id.clone(),
            adapter_type: "subprocess".to_string(),
            enabled: cfg.enabled,
            target: Some(command.clone()),
            api_key_secret: None,
            auth_header: None,
        },
    }
}

pub fn run_gate(command: GateCommand) -> ExitCode {
    match command {
        GateCommand::Init(args) => run_gate_init_or_propose(args, false),
        GateCommand::Propose(args) => run_gate_init_or_propose(args, true),
        GateCommand::Lock {
            config,
            state_dir,
            json,
        } => run_gate_lock(config, state_dir, json),
        GateCommand::Review {
            session,
            limit,
            state_dir,
            json,
        } => run_gate_review(session, limit, state_dir, json),
        GateCommand::Log {
            decision,
            limit,
            session,
            state_dir,
            json,
        } => run_gate_log(decision, limit, session, state_dir, json),
    }
}

pub fn run_inbox(command: InboxCommand) -> ExitCode {
    match command {
        InboxCommand::Approve {
            receipt,
            reviewer,
            state_dir,
            json,
        } => run_inbox_approve(receipt, reviewer, state_dir, json),
        InboxCommand::Reject {
            receipt,
            mute,
            reason,
            reviewer,
            state_dir,
            json,
        } => run_inbox_reject(receipt, mute, reason, reviewer, state_dir, json),
    }
}

fn build_filter_plugin_from_args(args: &GateInitArgs) -> Result<FilterPluginConfig, String> {
    if args.auth_header.is_some() && args.adapter != CliGateAdapter::Anthropic {
        return Err(format!(
            "--auth-header is only supported for --adapter anthropic (got --adapter {})",
            args.adapter.as_str()
        ));
    }

    if let Some(ref secret_name) = args.secret {
        if looks_like_raw_api_key(secret_name) {
            return Err(
                "Refusing plaintext API key in --secret; pass a SecretStore name (e.g. --secret anthropic-api-key) and store the key via `hyp secret set <name>`."
                    .to_string(),
            );
        }
        validate_secret_name(secret_name)
            .map_err(|e| format!("Invalid --secret name '{secret_name}': {e}"))?;
    }

    let id = args
        .id
        .clone()
        .unwrap_or_else(|| format!("{}-guard", args.adapter.as_str()));
    let policy_notes = args.policy_notes.clone().unwrap_or_default();

    let adapter = match args.adapter {
        CliGateAdapter::Anthropic => FilterAdapterConfig::Anthropic {
            model: args
                .model
                .clone()
                .unwrap_or_else(|| "claude-haiku-4-5".to_string()),
            temperature: 0.0,
            max_output_tokens: DEFAULT_STAGE2_MAX_OUTPUT_TOKENS,
            timeout_ms: DEFAULT_STAGE2_TIMEOUT_MS,
            max_input_chars: DEFAULT_STAGE2_MAX_INPUT_CHARS,
            min_allow_confidence: DEFAULT_STAGE2_MIN_ALLOW_CONFIDENCE,
            api_key_secret: Some(
                args.secret
                    .clone()
                    .unwrap_or_else(|| "anthropic-api-key".to_string()),
            ),
            base_url: args.base_url.clone(),
            auth_header: args
                .auth_header
                .map(CliAnthropicAuthHeader::to_policy)
                .unwrap_or_default(),
            policy_notes,
        },
        CliGateAdapter::OpenAiCompat => FilterAdapterConfig::OpenAiCompat {
            base_url: args
                .base_url
                .clone()
                .unwrap_or_else(|| "http://127.0.0.1:11434/v1".to_string()),
            model: args
                .model
                .clone()
                .unwrap_or_else(|| "qwen2.5:3b".to_string()),
            temperature: 0.0,
            max_output_tokens: DEFAULT_STAGE2_MAX_OUTPUT_TOKENS,
            timeout_ms: DEFAULT_STAGE2_TIMEOUT_MS,
            max_input_chars: DEFAULT_STAGE2_MAX_INPUT_CHARS,
            min_allow_confidence: DEFAULT_STAGE2_MIN_ALLOW_CONFIDENCE,
            api_key_secret: args.secret.clone(),
            policy_notes,
        },
        CliGateAdapter::Google => FilterAdapterConfig::Google {
            model: args
                .model
                .clone()
                .unwrap_or_else(|| "gemini-2.5-flash-lite".to_string()),
            temperature: 0.0,
            max_output_tokens: DEFAULT_STAGE2_MAX_OUTPUT_TOKENS,
            timeout_ms: DEFAULT_STAGE2_TIMEOUT_MS,
            max_input_chars: DEFAULT_STAGE2_MAX_INPUT_CHARS,
            min_allow_confidence: DEFAULT_STAGE2_MIN_ALLOW_CONFIDENCE,
            api_key_secret: Some(
                args.secret
                    .clone()
                    .unwrap_or_else(|| "google-api-key".to_string()),
            ),
            base_url: args.base_url.clone(),
            policy_notes,
        },
        CliGateAdapter::LakeraGuard => FilterAdapterConfig::LakeraGuard {
            base_url: args
                .base_url
                .clone()
                .unwrap_or_else(|| "https://api.lakera.ai".to_string()),
            api_key_secret: Some(
                args.secret
                    .clone()
                    .unwrap_or_else(|| "lakera-api-key".to_string()),
            ),
            project_id: None,
            timeout_ms: DEFAULT_STAGE2_TIMEOUT_MS,
            max_input_chars: DEFAULT_STAGE2_MAX_INPUT_CHARS,
            on_flagged: Stage2ErrorAction::Quarantine,
        },
        CliGateAdapter::HttpClassifier => FilterAdapterConfig::HttpClassifier {
            url: args
                .base_url
                .clone()
                .unwrap_or_else(|| "http://127.0.0.1:8080/classify".to_string()),
            api_key_secret: args.secret.clone(),
            auth_header: None,
            score_field: "score".to_string(),
            label_field: "label".to_string(),
            flagged_labels: vec!["INJECTION".to_string(), "JAILBREAK".to_string()],
            threshold: DEFAULT_HTTP_CLASSIFIER_THRESHOLD,
            timeout_ms: DEFAULT_STAGE2_TIMEOUT_MS,
            max_input_chars: DEFAULT_STAGE2_MAX_INPUT_CHARS,
            on_flagged: Stage2ErrorAction::Quarantine,
        },
        CliGateAdapter::Subprocess => {
            let cmd_bin = args
                .command
                .clone()
                .or_else(|| args.base_url.clone())
                .ok_or_else(|| {
                    "--command <executable> is required for --adapter subprocess".to_string()
                })?;
            FilterAdapterConfig::Subprocess {
                command: cmd_bin,
                args: args.args.clone(),
                env_allowlist: Vec::new(),
                timeout_ms: DEFAULT_STAGE2_TIMEOUT_MS,
                max_input_chars: DEFAULT_STAGE2_MAX_INPUT_CHARS,
                min_allow_confidence: DEFAULT_STAGE2_MIN_ALLOW_CONFIDENCE,
            }
        }
    };

    let plugin = FilterPluginConfig {
        id,
        enabled: true,
        matchers: Stage2Matchers {
            peers: Vec::new(),
            channels: Vec::new(),
            topics: Vec::new(),
            bridges: Vec::new(),
            trust_tiers: vec![
                TrustTier::Guest,
                TrustTier::ExternalWebhook,
                TrustTier::Peer,
                TrustTier::Bridge,
            ],
        },
        on_error: Stage2ErrorAction::Quarantine,
        max_concurrent: DEFAULT_STAGE2_MAX_CONCURRENT,
        busy_retry_after_ms: DEFAULT_STAGE2_BUSY_RETRY_MS,
        adapter,
    };
    plugin.validate().map_err(|e| e.to_string())?;
    Ok(plugin)
}

fn looks_like_raw_api_key(s: &str) -> bool {
    let trimmed = s.trim();
    ["sk-", "AIza", "ghp_", "gho_", "xoxb-", "xoxp-", "AKIA"]
        .iter()
        .any(|p| trimmed.starts_with(p))
}

fn run_gate_init_or_propose(args: GateInitArgs, propose_only: bool) -> ExitCode {
    let cmd = if propose_only {
        "gate propose"
    } else {
        "gate init"
    };
    let as_json = args.json;

    let plugin = match build_filter_plugin_from_args(&args) {
        Ok(p) => p,
        Err(e) => {
            return emit_error(cmd, as_json, EXIT_USAGE, "INVALID_GATE_CONFIG", e, None);
        }
    };

    let state_dir = resolve_state_dir(args.state_dir.as_deref(), args.config.as_deref(), None);
    let config_path =
        resolve_config_path_for_write(args.config.as_deref(), args.state_dir.as_deref(), None);

    let mut cfg_map = match read_json_object_or_empty(&config_path) {
        Ok(m) => m,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "CONFIG_ERROR", e, None),
    };

    let mut gate_cfg: SecurityGateConfig = cfg_map
        .get("gate")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    // Upsert adapter by id so re-running `gate init` is idempotent.
    if let Some(existing) = gate_cfg.filters.iter_mut().find(|f| f.id == plugin.id) {
        *existing = plugin.clone();
    } else {
        gate_cfg.filters.push(plugin.clone());
    }

    if propose_only {
        // Proposal never mutates or locks live signed policy in node.json; writes sibling proposal file.
        gate_cfg.require_signed_policy = false;
        gate_cfg.policy_signature = None;
        let proposal_path = state_dir.join("gate.proposed.json");
        let proposal_val = match serde_json::to_value(&gate_cfg) {
            Ok(v) => v,
            Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "JSON_ERROR", e.to_string(), None),
        };
        if let Err(e) = write_atomic_json(&proposal_path, &proposal_val, true) {
            return emit_error(cmd, as_json, EXIT_ERROR, "IO_ERROR", e, None);
        }
        let next = vec![
            format!("Review proposed policy at {}", proposal_path.display()),
            format!(
                "Approve & lock as human: hyp gate lock --config {} --state-dir {}",
                config_path.display(),
                state_dir.display()
            ),
        ];
        if as_json {
            let envelope = JsonEnvelope {
                ok: true,
                command: cmd.to_string(),
                summary: Some(format!(
                    "Staged unsigned gate policy proposal ({}) at {}",
                    plugin.id,
                    proposal_path.display()
                )),
                data: Some(json!({
                    "proposalPath": proposal_path.display().to_string(),
                    "adapter": args.adapter.as_str(),
                    "filterId": plugin.id,
                    "locked": false,
                    "gate": proposal_val,
                })),
                warnings: Vec::new(),
                next,
                error: None,
            };
            print_json(&envelope);
        } else {
            println!("OK    Staged unsigned gate policy proposal '{}'", plugin.id);
            println!("      Proposal: {}", proposal_path.display());
            print_next_steps(&next);
        }
        return ExitCode::from(EXIT_OK);
    }

    let mut locked = false;
    if args.lock {
        let secrets = open_secret_store(&state_dir, args.state_dir.is_some());
        if let Err(e) = bind_human_authorities_digest_if_present(&state_dir, &mut gate_cfg) {
            return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e, None);
        }
        gate_cfg.require_signed_policy = true;
        gate_cfg.policy_signature = None;
        let sig = match sign_gate_policy(&gate_cfg, &secrets) {
            Ok(s) => s,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "POLICY_SIGN_FAILED",
                    format!("Failed to sign gate policy: {e}"),
                    None,
                );
            }
        };
        if let Err(e) = verify_gate_policy_sig(&gate_cfg, &sig, &secrets) {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "POLICY_VERIFY_FAILED",
                format!("Self-verification of signed gate policy failed: {e}"),
                None,
            );
        }
        gate_cfg.policy_signature = Some(sig);
        locked = true;
    } else {
        // Clear any stale signature because the policy was updated without `--lock`.
        gate_cfg.policy_signature = None;
        gate_cfg.require_signed_policy = false;
    }

    let node_id = cfg_map
        .get("nodeId")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(default_node_id);
    ensure_v2_node_json_defaults(&mut cfg_map, &node_id, NodeProfile::Local, &state_dir);

    let gate_val = match serde_json::to_value(&gate_cfg) {
        Ok(v) => v,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "JSON_ERROR", e.to_string(), None),
    };
    cfg_map.insert("gate".to_string(), gate_val);

    if let Err(e) = write_atomic_json(&config_path, &Value::Object(cfg_map), true) {
        return emit_error(cmd, as_json, EXIT_ERROR, "IO_ERROR", e, None);
    }

    let mut daemon_reloaded = false;
    let mut daemon_reload_error: Option<String> = None;
    let mut warnings: Vec<String> = Vec::new();
    if locked {
        let reload_res =
            try_live_gate_reload(args.state_dir.is_some(), args.config.is_some(), &state_dir);
        daemon_reloaded = reload_res.ok
            && reload_res
                .result
                .as_ref()
                .and_then(|r| r.get("reloaded"))
                .and_then(Value::as_bool)
                == Some(true);
        if !daemon_reloaded {
            if let Some(err) = reload_res.error {
                warnings.push(format!("Live daemon gate.reload failed: {err}"));
                daemon_reload_error = Some(err);
            }
        }
    }

    let summary_filter = summarize_filter_plugin(&plugin);
    let mut next = Vec::new();
    if let Some(ref secret_ref) = summary_filter.api_key_secret {
        next.push(format!(
            "Store API key out-of-band: hyp secret set {secret_ref} --web"
        ));
    }
    if !locked {
        next.push(format!(
            "Lock tamper-evident signature: hyp gate lock --config {} --state-dir {}",
            config_path.display(),
            state_dir.display()
        ));
    }
    next.push(format!(
        "hyp doctor --config {} --state-dir {}",
        config_path.display(),
        state_dir.display()
    ));

    if as_json {
        let mut data = json!({
            "configPath": config_path.display().to_string(),
            "stateDir": state_dir.display().to_string(),
            "filter": summary_filter,
            "locked": locked,
            "requireSignedPolicy": gate_cfg.require_signed_policy,
            "gatePolicySig": if locked { "OK" } else { "UNSIGNED" },
            "policySigningSecret": gate_cfg.policy_signing_secret,
            "daemonReloaded": daemon_reloaded,
        });
        if let Some(ref err) = daemon_reload_error {
            data["daemonReloadError"] = json!(err);
        }
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(format!(
                "Configured gate adapter '{}' ({}) in {}{}",
                plugin.id,
                args.adapter.as_str(),
                config_path.display(),
                if locked { " [LOCKED]" } else { "" }
            )),
            data: Some(data),
            warnings,
            next,
            error: None,
        };
        print_json(&envelope);
    } else {
        println!(
            "OK    Configured Security Gate adapter '{}' ({}){}",
            plugin.id,
            args.adapter.as_str(),
            if locked { " · gate_policy_sig LOCKED" } else { "" }
        );
        println!("      Config: {}", config_path.display());
        if let Some(ref sec) = summary_filter.api_key_secret {
            println!("      Secret: {{ \"secret\": \"{sec}\" }} (never plaintext)");
        }
        if locked {
            if daemon_reloaded {
                println!(
                    "      Live daemon reloaded — new Security Gate policy active immediately (no restart needed)."
                );
            } else if let Some(ref err) = daemon_reload_error {
                println!(
                    "WARN  Live daemon reload failed ({err}); run `hyp service restart` or `hyp node start` to apply."
                );
            } else {
                println!(
                    "      Daemon offline — run `hyp service restart` or `hyp node start` to apply."
                );
            }
        }
        print_next_steps(&next);
    }
    ExitCode::from(EXIT_OK)
}

fn bind_human_authorities_digest_if_present(
    state_dir: &std::path::Path,
    gate_cfg: &mut SecurityGateConfig,
) -> Result<(), String> {
    let db_path = state_dir.join("node.sqlite");
    if !db_path.exists() {
        return Ok(());
    }
    let db = NodeDb::open(&db_path)
        .map_err(|e| format!("failed to open {}: {e}", db_path.display()))?;
    let active = db
        .human()
        .list_authorities(false)
        .map_err(|e| format!("failed to query human_authorities: {e}"))?;
    if !active.is_empty() || gate_cfg.human_authorities_digest.is_some() {
        let digest = db
            .human()
            .authorities_digest()
            .map_err(|e| format!("failed to compute human_authorities_digest: {e}"))?;
        gate_cfg.human_authorities_digest = Some(digest);
    }
    Ok(())
}

fn run_gate_lock(
    config: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let cmd = "gate lock";
    let dir = resolve_state_dir(state_dir.as_deref(), config.as_deref(), None);
    let config_path = resolve_config_path_for_read(config.as_deref(), state_dir.as_deref(), None);
    let proposal_path = dir.join("gate.proposed.json");
    if !config_path.exists() && !proposal_path.exists() {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "CONFIG_NOT_FOUND",
            format!("Config file not found: {}", config_path.display()),
            Some("Run `hyp gate init --adapter ...` or `hyp onboard` first.".to_string()),
        );
    }

    let mut cfg_map = match read_json_object_or_empty(&config_path) {
        Ok(m) => m,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "CONFIG_ERROR", e, None),
    };
    if !config_path.exists() {
        let node_id = cfg_map
            .get("nodeId")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned)
            .unwrap_or_else(default_node_id);
        ensure_v2_node_json_defaults(&mut cfg_map, &node_id, NodeProfile::Local, &dir);
    }

    let mut gate_cfg: SecurityGateConfig = match cfg_map.get("gate") {
        Some(v) => match serde_json::from_value(v.clone()) {
            Ok(g) => g,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "INVALID_GATE_CONFIG",
                    format!("Malformed gate config in {}: {e}", config_path.display()),
                    None,
                );
            }
        },
        None => SecurityGateConfig::default(),
    };

    // Merge staged `gate.proposed.json` (from `hyp gate propose`) BEFORE binding
    // `human_authorities_digest` and signing `gate_policy_sig`, then delete the proposal file.
    let mut merged_proposal = false;
    if proposal_path.exists() {
        let raw_proposal = match std::fs::read_to_string(&proposal_path) {
            Ok(s) => s,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "IO_ERROR",
                    format!(
                        "Failed to read staged gate proposal {}: {e}",
                        proposal_path.display()
                    ),
                    None,
                );
            }
        };
        let mut proposed_cfg: SecurityGateConfig = match serde_json::from_str(&raw_proposal) {
            Ok(g) => g,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "INVALID_GATE_CONFIG",
                    format!("Malformed staged gate proposal {}: {e}", proposal_path.display()),
                    None,
                );
            }
        };
        // Preserve any already-configured filters not replaced by the proposal.
        for existing_filter in gate_cfg.filters {
            if !proposed_cfg
                .filters
                .iter()
                .any(|f| f.id == existing_filter.id)
            {
                proposed_cfg.filters.push(existing_filter);
            }
        }
        gate_cfg = proposed_cfg;
        merged_proposal = true;
    }

    if let Err(e) = gate_cfg.stage2.validate() {
        return emit_error(cmd, as_json, EXIT_ERROR, "INVALID_GATE_CONFIG", e.to_string(), None);
    }
    for f in &gate_cfg.filters {
        if let Err(e) = f.validate() {
            return emit_error(cmd, as_json, EXIT_ERROR, "INVALID_GATE_CONFIG", e.to_string(), None);
        }
    }

    let secrets = open_secret_store(&dir, state_dir.is_some());
    if let Err(e) = bind_human_authorities_digest_if_present(&dir, &mut gate_cfg) {
        return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e, None);
    }
    gate_cfg.require_signed_policy = true;
    gate_cfg.policy_signature = None;
    let sig = match sign_gate_policy(&gate_cfg, &secrets) {
        Ok(s) => s,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "POLICY_SIGN_FAILED",
                format!("Failed to sign gate policy: {e}"),
                None,
            );
        }
    };
    if let Err(e) = verify_gate_policy_sig(&gate_cfg, &sig, &secrets) {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "POLICY_VERIFY_FAILED",
            format!("Failed to verify signed gate policy: {e}"),
            None,
        );
    }
    gate_cfg.policy_signature = Some(sig);

    let gate_val = match serde_json::to_value(&gate_cfg) {
        Ok(v) => v,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "JSON_ERROR", e.to_string(), None),
    };
    cfg_map.insert("gate".to_string(), gate_val);
    if let Err(e) = write_atomic_json(&config_path, &Value::Object(cfg_map), true) {
        return emit_error(cmd, as_json, EXIT_ERROR, "IO_ERROR", e, None);
    }
    if merged_proposal {
        let _ = std::fs::remove_file(&proposal_path);
    }

    let reload_res = try_live_gate_reload(state_dir.is_some(), config.is_some(), &dir);
    let daemon_reloaded = reload_res.ok
        && reload_res
            .result
            .as_ref()
            .and_then(|r| r.get("reloaded"))
            .and_then(Value::as_bool)
            == Some(true);
    let mut warnings: Vec<String> = Vec::new();
    let daemon_reload_error = if !daemon_reloaded {
        if let Some(err) = reload_res.error {
            warnings.push(format!("Live daemon gate.reload failed: {err}"));
            Some(err)
        } else {
            None
        }
    } else {
        None
    };

    let mut next = Vec::new();
    if !daemon_reloaded {
        next.push("hyp service restart".to_string());
    }
    next.push(format!(
        "hyp doctor --config {} --state-dir {}",
        config_path.display(),
        dir.display()
    ));

    if as_json {
        let mut data = json!({
            "configPath": config_path.display().to_string(),
            "stateDir": dir.display().to_string(),
            "gatePolicySig": "OK",
            "requireSignedPolicy": true,
            "mergedProposal": merged_proposal,
            "filterCount": gate_cfg.filters.len(),
            "policySigningSecret": gate_cfg.policy_signing_secret,
            "humanAuthoritiesDigest": gate_cfg.human_authorities_digest,
            "daemonReloaded": daemon_reloaded,
        });
        if let Some(ref err) = daemon_reload_error {
            data["daemonReloadError"] = json!(err);
        }
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(format!(
                "Locked and signed gate_policy_sig for {} ({} filter(s){})",
                config_path.display(),
                gate_cfg.filters.len(),
                if merged_proposal {
                    ", merged gate.proposed.json"
                } else {
                    ""
                }
            )),
            data: Some(data),
            warnings,
            next,
            error: None,
        };
        print_json(&envelope);
    } else {
        println!(
            "OK    Locked gate policy in {} (gate_policy_sig verified via SecretStore '{}')",
            config_path.display(),
            gate_cfg.policy_signing_secret
        );
        if merged_proposal {
            println!("      Merged & removed staged proposal {}", proposal_path.display());
        }
        if daemon_reloaded {
            println!(
                "      Live daemon reloaded — new Security Gate policy active immediately (no restart needed)."
            );
        } else if let Some(ref err) = daemon_reload_error {
            println!(
                "WARN  Live daemon reload failed ({err}); run `hyp service restart` or `hyp node start` to apply."
            );
        } else {
            println!(
                "      Daemon offline — run `hyp service restart` or `hyp node start` to apply."
            );
        }
        print_next_steps(&next);
    }
    ExitCode::from(EXIT_OK)
}

fn run_gate_review(
    session: Option<String>,
    limit: usize,
    state_dir: Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let cmd = "gate review";
    let dir = resolve_state_dir(state_dir.as_deref(), None, None);
    let db_path = dir.join("node.sqlite");
    let db = match NodeDb::open(&db_path) {
        Ok(db) => db,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e.to_string(), None),
    };

    let items = match db.local().list_quarantined(session.as_deref(), limit) {
        Ok(v) => v,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e.to_string(), None),
    };

    let rows: Vec<Value> = items
        .iter()
        .map(|entry| {
            let preview: String = entry.text.chars().take(160).collect();
            json!({
                "receipt": entry.receipt,
                "sessionId": entry.session_id,
                "originNode": entry.origin_node,
                "sender": entry.source,
                "kind": entry.kind.as_str(),
                "reason": entry.gate_reason,
                "receivedAt": entry.received_at,
                "preview": preview,
                "payloadSha256": entry.payload_sha256,
            })
        })
        .collect();

    let next: Vec<String> = if let Some(first) = items.first() {
        vec![
            format!(
                "Approve: hyp inbox approve {} --state-dir {}",
                first.receipt,
                dir.display()
            ),
            format!(
                "Reject & mute sender: hyp inbox reject {} --mute --state-dir {}",
                first.receipt,
                dir.display()
            ),
        ]
    } else {
        Vec::new()
    };

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(format!("{} quarantined item(s) awaiting human review", rows.len())),
            data: Some(json!({
                "count": rows.len(),
                "items": rows,
            })),
            warnings: Vec::new(),
            next,
            error: None,
        };
        print_json(&envelope);
    } else {
        println!("Hyphae Quarantine Review ({} item(s))", items.len());
        if items.is_empty() {
            println!("  (no quarantined items)");
        } else {
            println!();
            for item in &items {
                let preview: String = item
                    .text
                    .chars()
                    .map(|c| if c.is_control() { ' ' } else { c })
                    .take(120)
                    .collect();
                println!("Receipt:  {}", item.receipt);
                println!("  Session:  {}", item.session_id);
                println!("  From:     {} (origin: {})", item.source, item.origin_node);
                println!(
                    "  Reason:   {}",
                    item.gate_reason.as_deref().unwrap_or("policy_quarantine")
                );
                println!("  Preview:  {preview}");
                println!();
            }
            print_next_steps(&next);
        }
    }
    ExitCode::from(EXIT_OK)
}

fn run_gate_log(
    decision: CliGateLogDecision,
    limit: usize,
    session: Option<String>,
    state_dir: Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let cmd = "gate log";
    let dir = resolve_state_dir(state_dir.as_deref(), None, None);
    let db_path = dir.join("node.sqlite");
    let db = match NodeDb::open(&db_path) {
        Ok(db) => db,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e.to_string(), None),
    };

    let entries = match db.local().query_gate_audit(&GateAuditQuery {
        decision: decision.to_store_filter(),
        direction: None,
        session_id: session,
        since_ms: None,
        until_ms: None,
        limit: Some(limit),
    }) {
        Ok(v) => v,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e.to_string(), None),
    };

    if as_json {
        let rows: Vec<Value> = entries
            .iter()
            .map(|e| {
                json!({
                    "seq": e.seq,
                    "createdAt": e.created_at,
                    "direction": e.direction.as_str(),
                    "stage": e.stage,
                    "decision": e.decision.as_str(),
                    "originNode": e.origin_node,
                    "source": e.source,
                    "sessionId": e.session_id,
                    "receiptId": e.receipt_id,
                    "trustTier": e.trust_tier,
                    "confidence": e.confidence,
                    "categories": e.categories,
                    "reason": e.reason,
                    "payloadSha256": e.payload_sha256,
                    "reviewer": e.reviewer,
                })
            })
            .collect();
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(format!("{} gate_audit record(s)", rows.len())),
            data: Some(json!({
                "count": rows.len(),
                "entries": rows,
            })),
            warnings: Vec::new(),
            next: Vec::new(),
            error: None,
        };
        print_json(&envelope);
    } else {
        println!("Hyphae Security Gate Audit Log ({} record(s))", entries.len());
        if entries.is_empty() {
            println!("  (no audit entries)");
        } else {
            println!();
            println!(
                "{:<6}  {:<10}  {:<16}  {:<10}  {:<22}  Reason",
                "Seq", "Direction", "Stage", "Decision", "Source"
            );
            println!("{}", "-".repeat(92));
            for e in &entries {
                println!(
                    "{:<6}  {:<10}  {:<16}  {:<10}  {:<22}  {}",
                    e.seq,
                    e.direction.as_str(),
                    e.stage,
                    e.decision.as_str(),
                    e.source.as_deref().unwrap_or("-"),
                    e.reason.as_deref().unwrap_or("-")
                );
            }
        }
    }
    ExitCode::from(EXIT_OK)
}

fn run_inbox_approve(
    receipt: String,
    reviewer: String,
    state_dir: Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let cmd = "inbox approve";
    let dir = resolve_state_dir(state_dir.as_deref(), None, None);
    let db_path = dir.join("node.sqlite");
    let db = match NodeDb::open(&db_path) {
        Ok(db) => db,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e.to_string(), None),
    };

    match db.local().approve_quarantined(&receipt, &reviewer, now_ms()) {
        Ok(entry) => {
            drop(db);
            let wake_res =
                try_live_inbox_wake(state_dir.is_some(), &dir, &entry.session_id, &entry.receipt);
            let daemon_notified = wake_res.ok;
            let daemon_woken = wake_res
                .result
                .as_ref()
                .and_then(|r| r.get("woken"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            let quarantined_remaining = wake_res
                .result
                .as_ref()
                .and_then(|r| r.get("quarantinedRemaining"))
                .and_then(Value::as_u64);

            if as_json {
                let mut data = json!({
                    "receipt": entry.receipt,
                    "sessionId": entry.session_id,
                    "gateState": entry.gate_state.as_str(),
                    "reviewer": reviewer,
                    "reviewedAt": entry.reviewed_at,
                    "daemonNotified": daemon_notified,
                    "daemonWoken": daemon_woken,
                });
                if let Some(rem) = quarantined_remaining {
                    data["quarantinedRemaining"] = json!(rem);
                }
                let envelope = JsonEnvelope {
                    ok: true,
                    command: cmd.to_string(),
                    summary: Some(format!(
                        "Approved quarantined receipt '{}' -> pending for session '{}'",
                        entry.receipt, entry.session_id
                    )),
                    data: Some(data),
                    warnings: Vec::new(),
                    next: Vec::new(),
                    error: None,
                };
                print_json(&envelope);
            } else {
                println!(
                    "OK    Approved receipt '{}' -> released to session '{}' (reviewer: {})",
                    entry.receipt, entry.session_id, reviewer
                );
                if daemon_notified && daemon_woken {
                    println!(
                        "      Live daemon notified — session '{}' woken immediately.",
                        entry.session_id
                    );
                } else if daemon_notified {
                    println!(
                        "      Live daemon notified — quarantine badge cleared (queued for session '{}').",
                        entry.session_id
                    );
                } else {
                    println!(
                        "      Daemon offline — released item will be delivered when `hyp node start` runs."
                    );
                }
            }
            ExitCode::from(EXIT_OK)
        }
        Err(StoreError::NotFound(m)) => {
            emit_error(cmd, as_json, EXIT_ERROR, "RECEIPT_NOT_FOUND", m, None)
        }
        Err(StoreError::InvalidState(m)) => {
            emit_error(cmd, as_json, EXIT_ERROR, "INVALID_RECEIPT_STATE", m, None)
        }
        Err(e) => emit_error(cmd, as_json, EXIT_ERROR, "APPROVE_FAILED", e.to_string(), None),
    }
}

fn run_inbox_reject(
    receipt: String,
    mute: bool,
    reason: String,
    reviewer: String,
    state_dir: Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let cmd = "inbox reject";
    let dir = resolve_state_dir(state_dir.as_deref(), None, None);
    let db_path = dir.join("node.sqlite");
    let db = match NodeDb::open(&db_path) {
        Ok(db) => db,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e.to_string(), None),
    };

    let mute_rule = if mute {
        match db.local().get_mailbox_entry(&receipt) {
            Ok(Some(entry)) => {
                let pattern = if !entry.source.trim().is_empty() {
                    entry.source
                } else {
                    entry.origin_node
                };
                (!pattern.trim().is_empty()).then_some(MuteRuleInput {
                    scope: "*".to_string(),
                    pattern,
                })
            }
            Ok(None) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "RECEIPT_NOT_FOUND",
                    format!("receipt '{receipt}' not found"),
                    None,
                );
            }
            Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e.to_string(), None),
        }
    } else {
        None
    };

    match db
        .local()
        .reject_quarantined(&receipt, &reviewer, &reason, mute_rule.as_ref(), now_ms())
    {
        Ok(entry) => {
            drop(db);
            let wake_res =
                try_live_inbox_wake(state_dir.is_some(), &dir, &entry.session_id, &entry.receipt);
            let daemon_notified = wake_res.ok;
            let quarantined_remaining = wake_res
                .result
                .as_ref()
                .and_then(|r| r.get("quarantinedRemaining"))
                .and_then(Value::as_u64);
            let muted_pattern = mute_rule.as_ref().map(|m| m.pattern.clone());
            if as_json {
                let mut data = json!({
                    "receipt": entry.receipt,
                    "sessionId": entry.session_id,
                    "gateState": entry.gate_state.as_str(),
                    "reason": reason,
                    "reviewer": reviewer,
                    "muted": muted_pattern.is_some(),
                    "mutedPattern": muted_pattern,
                    "reviewedAt": entry.reviewed_at,
                    "daemonNotified": daemon_notified,
                });
                if let Some(rem) = quarantined_remaining {
                    data["quarantinedRemaining"] = json!(rem);
                }
                let envelope = JsonEnvelope {
                    ok: true,
                    command: cmd.to_string(),
                    summary: Some(format!(
                        "Rejected quarantined receipt '{}'{}",
                        entry.receipt,
                        muted_pattern
                            .as_deref()
                            .map(|p| format!(" and muted '{p}'"))
                            .unwrap_or_default()
                    )),
                    data: Some(data),
                    warnings: Vec::new(),
                    next: Vec::new(),
                    error: None,
                };
                print_json(&envelope);
            } else {
                println!(
                    "OK    Rejected receipt '{}'{}",
                    entry.receipt,
                    muted_pattern
                        .as_deref()
                        .map(|p| format!(" + installed global mute rule for '{p}'"))
                        .unwrap_or_default()
                );
                if daemon_notified {
                    println!(
                        "      Live daemon notified — quarantine badge cleared immediately."
                    );
                } else {
                    println!("      Daemon offline — rejection recorded in SQLite.");
                }
            }
            ExitCode::from(EXIT_OK)
        }
        Err(StoreError::NotFound(m)) => {
            emit_error(cmd, as_json, EXIT_ERROR, "RECEIPT_NOT_FOUND", m, None)
        }
        Err(StoreError::InvalidState(m)) => {
            emit_error(cmd, as_json, EXIT_ERROR, "INVALID_RECEIPT_STATE", m, None)
        }
        Err(e) => emit_error(cmd, as_json, EXIT_ERROR, "REJECT_FAILED", e.to_string(), None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args(adapter: CliGateAdapter, auth_header: Option<CliAnthropicAuthHeader>) -> GateInitArgs {
        GateInitArgs {
            adapter,
            id: None,
            base_url: Some("https://ai-gateway.internal".to_string()),
            auth_header,
            model: Some("claude-haiku-4-5".to_string()),
            secret: Some("proxy-api-token".to_string()),
            command: None,
            args: Vec::new(),
            policy_notes: None,
            config: None,
            state_dir: None,
            lock: false,
            json: true,
        }
    }

    #[test]
    fn anthropic_auth_header_defaults_to_x_api_key_and_accepts_bearer() {
        let default_plugin =
            build_filter_plugin_from_args(&base_args(CliGateAdapter::Anthropic, None)).unwrap();
        match default_plugin.adapter {
            FilterAdapterConfig::Anthropic { auth_header, .. } => {
                assert_eq!(auth_header, AnthropicAuthHeader::XApiKey);
            }
            other => panic!("expected Anthropic adapter, got {other:?}"),
        }

        let bearer_plugin = build_filter_plugin_from_args(&base_args(
            CliGateAdapter::Anthropic,
            Some(CliAnthropicAuthHeader::Bearer),
        ))
        .unwrap();
        match &bearer_plugin.adapter {
            FilterAdapterConfig::Anthropic { auth_header, .. } => {
                assert_eq!(*auth_header, AnthropicAuthHeader::Bearer);
            }
            other => panic!("expected Anthropic adapter, got {other:?}"),
        }
        let summary = summarize_filter_plugin(&bearer_plugin);
        assert_eq!(summary.auth_header.as_deref(), Some("bearer"));
    }

    #[test]
    fn auth_header_rejects_non_anthropic_adapters_cleanly() {
        for adapter in [
            CliGateAdapter::Google,
            CliGateAdapter::OpenAiCompat,
            CliGateAdapter::LakeraGuard,
            CliGateAdapter::HttpClassifier,
            CliGateAdapter::Subprocess,
        ] {
            let err = build_filter_plugin_from_args(&base_args(
                adapter,
                Some(CliAnthropicAuthHeader::Bearer),
            ))
            .expect_err("non-anthropic adapter must reject --auth-header");
            assert!(
                err.contains("--auth-header is only supported for --adapter anthropic"),
                "unexpected error for {adapter:?}: {err}"
            );
        }
    }
}
