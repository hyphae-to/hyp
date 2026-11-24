//! Local Security Gates: Stage 1 deterministic policy/DLP/attachment guards, generalized
//! composable `FilterPlugin` chain (`anthropic`, `openai-compat`, `google`, `lakera-guard`,
//! `http-classifier`, `subprocess`), and tamper-evident human-signed policy verification.
//!
//! Architectural placement (`docs/architecture-v2.md` §5):
//! - **Inbound**: strictly **post-decrypt** (after HPKE/AEAD decrypt & Ed25519 verify), before any
//!   untrusted plaintext enters an agent's context window.
//! - **Outbound**: strictly **pre-encrypt** DLP secret scanning to prevent accidental credential leaks.
//! - **Anti-Tamper**: immutable `DEFAULT_CORE_RUBRIC` always prepended + optional HMAC-SHA256
//!   signed gate policy (`require_signed_policy`) failing closed with `gate_policy_tampered`.
//! - **Quarantine**: parked in `NodeDb` mailbox (`gate_state = "quarantined"`), hidden from agent
//!   `peek_inbox`/`drain_inbox`, and releasable **only** via human local CLI review.

pub mod pipeline;
pub mod plugins;
pub mod policy;
pub mod stage1;
pub mod stage2;

pub use pipeline::{InboundEvaluation, OutboundEvaluation, SecurityGatePipeline};
pub use plugins::{BoxFuture, FilterPlugin, build_filter_plugin};
pub use policy::{
    CustomDlpPattern, DEFAULT_HTTP_CLASSIFIER_THRESHOLD, DEFAULT_POLICY_SIGNING_SECRET,
    DEFAULT_STAGE2_BUSY_RETRY_MS, DEFAULT_STAGE2_MAX_CONCURRENT, DEFAULT_STAGE2_MAX_INPUT_CHARS,
    DEFAULT_STAGE2_MAX_OUTPUT_TOKENS, DEFAULT_STAGE2_MIN_ALLOW_CONFIDENCE,
    DEFAULT_STAGE2_TIMEOUT_MS, FilterAdapterConfig, FilterPluginConfig, FilterPluginKind,
    GateDecision, GateError, InboundContext, LlmProvider, MAX_POLICY_NOTES_CHARS,
    MAX_VERDICT_REASON_CHARS, OutboundContext, RateLimitAction, RateLimitConfig,
    SecurityGateConfig, Stage1Config, Stage1DenyAction, Stage2Config, Stage2ErrorAction,
    Stage2Matchers, TierDeliveryAction, TierPolicy, TokenBucket, TrustTier,
    default_stage2_policy_prompt, ensure_policy_signing_key, format_quarantine_notice,
    sign_gate_policy, verify_gate_policy_sig,
};
pub use stage1::{Stage1Engine, Stage1Outcome};
pub use stage2::{
    ClassifierVerdict, DEFAULT_CORE_RUBRIC, FilterOutcome, FramedPayload, Stage2Guard,
    Stage2Outcome, frame_untrusted_payload, neutralize_boundary_collisions,
    parse_and_validate_verdict_json, validate_verdict,
};
