//! Unified Local Security Gate Pipeline (`Anti-Tamper Policy Check -> Stage 1 -> FilterPlugin Chain -> NodeDb`).
//!
//! Orchestrates:
//! - Tamper-evident policy integrity verification (`require_signed_policy` -> fails closed with
//!   `Quarantine("gate_policy_tampered")` + `gate.tampered` audit row if on-disk config was mutated).
//! - Post-decrypt inbound screening (`Stage 1 deterministic -> legacy Stage 2 + ordered FilterPlugin chain`).
//! - Pre-encrypt outbound DLP secret scanning.
//! - Quarantine mailbox isolation (`gate_state = "quarantined"`), immutable `gate_audit` persistence,
//!   and **human-CLI-only** review/approval/rejection.
//!
//! Security invariants:
//! - Quarantined items are stored with `gate_state = "quarantined"` and are invisible to
//!   `peek_inbox` / `drain_inbox` until a human invokes [`SecurityGatePipeline::approve_quarantined`].
//! - Outbound DLP blocks never write leaked secret strings into errors or `gate_audit`.
//! - Stage 2 / filter plugins can NEVER undo a Stage 1 urgency ceiling or `Block`/`Quarantine`.
//! - The `NodeDb` mutex is NEVER held across `.await` points.

use std::sync::{Arc, Mutex};

use hyp_crypto::SecretStore;
use hyp_store::{
    GateAuditEntry, GateAuditInput, GateAuditQuery, GateDecision as StoreGateDecision,
    GateDirection, GateState, MailboxEntry, MailboxInsert, MailboxPutResult, MuteRuleInput, NodeDb,
};
use sha2::{Digest, Sha256};

use crate::delivery::{DeliveryUrgency, urgency_cap_gate_reason};
use crate::gates::plugins::{FilterPlugin, build_filter_plugin};
use crate::gates::policy::{
    GateDecision, GateError, InboundContext, OutboundContext, SecurityGateConfig, TrustTier,
    format_quarantine_notice, verify_gate_policy_integrity,
};
use crate::gates::stage1::Stage1Engine;
use crate::gates::stage2::{FilterOutcome, Stage2Guard};

/// Complete result of evaluating an inbound post-decrypt CloudEvent through the pipeline.
#[derive(Debug, Clone, PartialEq)]
pub struct InboundEvaluation {
    /// Final gate decision (`Allow`, `Quarantine`, `Block`, or `Hold`).
    pub decision: GateDecision,
    /// Stage or filter plugin that produced the decision (`"policy_integrity"`, `"stage1"`, `"stage2"`, `"filter:<id>"`, or `"mailbox"`).
    pub stage: String,
    /// Mailbox receipt ID if the item was parked in `mailbox` (`pending` or `quarantined`).
    pub receipt: Option<String>,
    /// True if an identical `(origin_node, item_id, session_id)` was already present in `mailbox`.
    pub duplicate: bool,
    /// SHA-256 hex digest of the evaluated plaintext payload.
    pub payload_sha256: String,
    /// Monotonic sequence number of the immutable `gate_audit` row (if recorded).
    pub audit_seq: Option<i64>,
    /// Classifier confidence (if a probabilistic filter ran and returned a valid score/confidence).
    pub confidence: Option<f64>,
    /// Categorized audit labels (`gate.allowed`, `gate.blocked`, `gate.quarantined`, `gate.error`, `gate.tampered`).
    pub categories: Vec<String>,
}

/// Complete result of evaluating an outbound pre-encrypt payload through Stage 1 DLP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundEvaluation {
    pub decision: GateDecision,
    pub payload_sha256: String,
    pub audit_seq: i64,
    /// Redacted secret categories detected (NEVER contains secret values).
    pub categories: Vec<String>,
}

/// Cached `gate_policy_sig` / Passkey `gate_lock_seal` verification state keyed by
/// `(config_hash, human_authorities_digest, lock_seal_fingerprint)`.
/// Avoids shelling out to OS Keychain / re-reading `SecretStore` on every inbound message while
/// immediately re-verifying fail-closed whenever `human_authorities` or `gate_lock_seal` changes
/// in SQLite.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PolicySigCacheEntry {
    config_hash: String,
    human_authorities_digest: String,
    seal_fingerprint: Option<String>,
}

/// Unified Local Security Gate pipeline backed by [`Stage1Engine`], [`Stage2Guard`],
/// composable [`FilterPlugin`] chain, [`NodeDb`], and an optional [`SecretStore`].
#[derive(Clone)]
pub struct SecurityGatePipeline {
    config: SecurityGateConfig,
    config_hash: String,
    stage1: Arc<Stage1Engine>,
    stage2: Option<Stage2Guard>,
    filters: Vec<Arc<dyn FilterPlugin>>,
    db: Arc<Mutex<NodeDb>>,
    secrets: Option<Arc<SecretStore>>,
    policy_sig_cache: Arc<Mutex<Option<PolicySigCacheEntry>>>,
}

impl std::fmt::Debug for SecurityGatePipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let filter_ids: Vec<&str> = self.filters.iter().map(|p| p.id()).collect();
        f.debug_struct("SecurityGatePipeline")
            .field("stage1", &self.stage1)
            .field("stage2", &self.stage2)
            .field("filters", &filter_ids)
            .field("require_signed_policy", &self.config.require_signed_policy)
            .finish()
    }
}

impl SecurityGatePipeline {
    /// Constructs a new [`SecurityGatePipeline`], validating constant signing key configuration,
    /// Stage 1 regexes, Stage 2 config, and all entries in `config.filters`.
    pub fn new(
        config: SecurityGateConfig,
        db: Arc<Mutex<NodeDb>>,
        secrets: Option<Arc<SecretStore>>,
    ) -> Result<Self, GateError> {
        config.validate()?;
        let stage1 = Arc::new(Stage1Engine::new(config.stage1.clone())?);
        let stage2 = if config.stage2.enabled {
            Some(Stage2Guard::new(config.stage2.clone())?)
        } else {
            None
        };
        let mut filters = Vec::with_capacity(config.filters.len());
        for fcfg in &config.filters {
            if fcfg.enabled {
                filters.push(build_filter_plugin(fcfg)?);
            } else {
                // Disabled filter configs still pass non-URL invariant validation (`G17` skipped).
                fcfg.validate()?;
            }
        }
        let config_bytes = serde_json::to_vec(&config).map_err(|e| {
            GateError::InvalidConfig(format!("failed to hash security gate config: {e}"))
        })?;
        let config_hash = sha256_hex(&config_bytes);
        Ok(Self {
            config,
            config_hash,
            stage1,
            stage2,
            filters,
            db,
            secrets,
            policy_sig_cache: Arc::new(Mutex::new(None)),
        })
    }

    /// Appends a custom in-process [`FilterPlugin`] to the ordered filter chain.
    pub fn with_custom_plugin(mut self, plugin: Arc<dyn FilterPlugin>) -> Self {
        self.filters.push(plugin);
        self
    }

    pub fn config(&self) -> &SecurityGateConfig {
        &self.config
    }

    /// Returns the number of active runtime filter plugins loaded in this pipeline.
    pub fn active_filter_count(&self) -> usize {
        self.filters.len()
    }

    pub fn db(&self) -> Arc<Mutex<NodeDb>> {
        Arc::clone(&self.db)
    }

    /// Verifies gate policy integrity fail-closed via [`verify_gate_policy_integrity`] (Passkey
    /// `gate_lock_seal` in `node.sqlite` first, then the legacy `node.json` signature).
    ///
    /// A successful result is cached per `(config_hash, human_authorities_digest, seal)` so
    /// inbound evaluation does not hit the `SecretStore` / OS Keychain on every message, while any
    /// change to `human_authorities` or `gate_lock_seal` re-verifies immediately.
    pub fn verify_policy_integrity(&self) -> Result<(), GateError> {
        let db = self
            .db
            .lock()
            .map_err(|_| GateError::LockPoisoned("node_db mutex poisoned".to_string()))?;
        let key = PolicySigCacheEntry {
            config_hash: self.config_hash.clone(),
            human_authorities_digest: db.human().authorities_digest()?,
            seal_fingerprint: db
                .human()
                .get_gate_lock_seal()?
                .map(|s| sha256_hex(format!("{}:{}", s.seal_seq, s.signed_claim_json).as_bytes())),
        };
        if let Ok(cache) = self.policy_sig_cache.lock() {
            if cache.as_ref() == Some(&key) {
                return Ok(());
            }
        }
        let result = verify_gate_policy_integrity(&self.config, &db, self.secrets.as_deref());
        if let Ok(mut cache) = self.policy_sig_cache.lock() {
            *cache = result.is_ok().then_some(key);
        }
        result.map(|_| ())
    }

    /// Whether this installation has entered live Passkey administration (including revoked
    /// enrollment history). This is not an unlocked/locked policy switch.
    pub fn requires_live_policy_approval(&self) -> Result<bool, GateError> {
        let db = self
            .db
            .lock()
            .map_err(|_| GateError::LockPoisoned("node_db mutex poisoned".into()))?;
        Ok(db.human().requires_live_approval()?)
    }

    /// Live replacement must have actual Passkey evidence on managed nodes. Legacy unsigned
    /// startup and HMAC evidence remain readable for migration, but cannot authorize a reload.
    pub fn verify_policy_change_approval(&self) -> Result<(), GateError> {
        let db = self
            .db
            .lock()
            .map_err(|_| GateError::LockPoisoned("node_db mutex poisoned".into()))?;
        let integrity = verify_gate_policy_integrity(&self.config, &db, self.secrets.as_deref())?;
        if db.human().requires_live_approval()? && !integrity.seal.is_some_and(|seal| seal.approved)
        {
            return Err(GateError::PolicySignature(
                "fresh Passkey approval required before replacing this policy".into(),
            ));
        }
        Ok(())
    }

    /// Returns `true` if either the external Passkey `gate_lock_seal` in `node.sqlite` OR the
    /// `node.json` policy signature / `human_authorities_digest` fails verification (`G1`).
    pub fn is_policy_tampered(&self) -> bool {
        self.verify_policy_integrity().is_err()
    }

    /// Evaluates a single transfer archive relative path against Stage 1 attachment safety rules.
    pub fn check_transfer_attachment(
        &self,
        peer_id: &str,
        trust_tier: TrustTier,
        rel_path: &str,
    ) -> Result<(), String> {
        self.stage1
            .check_transfer_attachment(peer_id, trust_tier, rel_path)
    }

    /// Evaluates an inbound post-decrypt CloudEvent (`Policy Integrity -> Stage 1 -> FilterPlugin Chain`),
    /// parks allowed/quarantined items in `NodeDb` mailbox, and writes an immutable `gate_audit` row.
    pub async fn evaluate_inbound(
        &self,
        ctx: &InboundContext,
        now_ms: i64,
    ) -> Result<InboundEvaluation, GateError> {
        self.evaluate_inbound_inner(None, ctx, now_ms).await
    }

    /// Evaluates an existing raw `Pending` mailbox entry in place (`Policy Integrity -> Stage 1 ->
    /// FilterPlugin Chain`), atomically transitioning `existing_receipt` on `Allow` (setting
    /// `reviewed_at`), `Quarantine` (`gate_state = 'quarantined'`), or `Block` (`gate_state =
    /// 'rejected'`), and retaining `existing_receipt` untouched on `Hold` while always writing an
    /// immutable `gate_audit` row.
    pub async fn evaluate_existing_mailbox_entry(
        &self,
        existing_receipt: &str,
        ctx: &InboundContext,
        now_ms: i64,
    ) -> Result<InboundEvaluation, GateError> {
        self.evaluate_inbound_inner(Some(existing_receipt), ctx, now_ms)
            .await
    }

    async fn evaluate_inbound_inner(
        &self,
        existing_receipt: Option<&str>,
        ctx: &InboundContext,
        now_ms: i64,
    ) -> Result<InboundEvaluation, GateError> {
        let payload_text = ctx.payload_text();
        let payload_sha256 = sha256_hex(payload_text.as_bytes());
        let traceparent = ctx.traceparent();

        // Step 0: Anti-tamper guard policy integrity verification.
        // If human-approved policy signing is required and on-disk config was modified (e.g. by a
        // prompt-injected coding agent editing `node.json`), fail closed on ALL non-`SelfHost` traffic!
        if ctx.trust_tier != TrustTier::SelfHost && self.is_policy_tampered() {
            let reason = "gate_policy_tampered".to_string();
            let notice = format_quarantine_notice(&reason);
            let cats = vec![
                "gate.tampered".to_string(),
                "gate_policy_tampered".to_string(),
            ];
            let (receipt, duplicate) = self.quarantine_or_store(
                existing_receipt,
                ctx,
                &payload_text,
                &reason,
                traceparent.clone(),
                now_ms,
            )?;
            let audit_seq = self.record_audit(
                &GateAuditInput {
                    direction: GateDirection::Inbound,
                    stage: "policy_integrity".to_string(),
                    decision: StoreGateDecision::Quarantine,
                    origin_node: Some(ctx.origin_node.clone()),
                    source: Some(ctx.sender.clone()),
                    session_id: Some(ctx.session_id.clone()),
                    receipt_id: receipt.clone(),
                    event_type: Some(ctx.event.event_type.clone()),
                    trust_tier: Some(ctx.trust_tier.as_str().to_string()),
                    confidence: Some(1.0),
                    categories: cats.clone(),
                    reason: Some(reason.clone()),
                    traceparent,
                    payload_sha256: payload_sha256.clone(),
                    reviewer: None,
                },
                now_ms,
            )?;
            return Ok(InboundEvaluation {
                decision: GateDecision::Quarantine { reason, notice },
                stage: "policy_integrity".to_string(),
                receipt,
                duplicate,
                payload_sha256,
                audit_seq: Some(audit_seq),
                confidence: Some(1.0),
                categories: cats,
            });
        }

        // Step 1: Deterministic Stage 1 (acquire DB lock briefly for mute lookup, drop before any await!).
        let stage1_out = {
            let db_guard = self
                .db
                .lock()
                .map_err(|_| GateError::LockPoisoned("node_db mutex poisoned".to_string()))?;
            self.stage1.evaluate_inbound(ctx, Some(&db_guard), now_ms)
        };

        let stage1_cap = match stage1_out.decision {
            GateDecision::Allow { max_urgency } => max_urgency,
            GateDecision::Hold {
                reason,
                retry_after_ms,
            } => {
                // G4 (P0): Retain held rows untouched and ALWAYS append an immutable `gate_audit` row.
                let (audit_seq, cats) = self.record_hold_audit(
                    ctx,
                    &payload_sha256,
                    traceparent,
                    "stage1",
                    existing_receipt.map(ToString::to_string),
                    &reason,
                    retry_after_ms,
                    &stage1_out.categories,
                    now_ms,
                )?;
                return Ok(InboundEvaluation {
                    decision: GateDecision::Hold {
                        reason,
                        retry_after_ms,
                    },
                    stage: "stage1".to_string(),
                    receipt: existing_receipt.map(ToString::to_string),
                    duplicate: false,
                    payload_sha256,
                    audit_seq: Some(audit_seq),
                    confidence: None,
                    categories: cats,
                });
            }
            GateDecision::Block { reason } => {
                let mut cats = vec!["gate.blocked".to_string()];
                cats.extend(stage1_out.categories);
                if let Some(r) = existing_receipt {
                    let _ = self.reject_existing_in_mailbox(r, ctx, &reason, now_ms)?;
                }
                let audit_seq = self.record_audit(
                    &GateAuditInput {
                        direction: GateDirection::Inbound,
                        stage: "stage1".to_string(),
                        decision: StoreGateDecision::Block,
                        origin_node: Some(ctx.origin_node.clone()),
                        source: Some(ctx.sender.clone()),
                        session_id: Some(ctx.session_id.clone()),
                        receipt_id: existing_receipt.map(ToString::to_string),
                        event_type: Some(ctx.event.event_type.clone()),
                        trust_tier: Some(ctx.trust_tier.as_str().to_string()),
                        confidence: Some(1.0),
                        categories: cats.clone(),
                        reason: Some(reason.clone()),
                        traceparent,
                        payload_sha256: payload_sha256.clone(),
                        reviewer: None,
                    },
                    now_ms,
                )?;
                return Ok(InboundEvaluation {
                    decision: GateDecision::Block { reason },
                    stage: "stage1".to_string(),
                    receipt: None,
                    duplicate: false,
                    payload_sha256,
                    audit_seq: Some(audit_seq),
                    confidence: Some(1.0),
                    categories: cats,
                });
            }
            GateDecision::Quarantine { reason, notice } => {
                let mut cats = vec!["gate.quarantined".to_string()];
                cats.extend(stage1_out.categories);
                let (receipt, duplicate) = self.quarantine_or_store(
                    existing_receipt,
                    ctx,
                    &payload_text,
                    &reason,
                    traceparent.clone(),
                    now_ms,
                )?;
                let audit_seq = self.record_audit(
                    &GateAuditInput {
                        direction: GateDirection::Inbound,
                        stage: "stage1".to_string(),
                        decision: StoreGateDecision::Quarantine,
                        origin_node: Some(ctx.origin_node.clone()),
                        source: Some(ctx.sender.clone()),
                        session_id: Some(ctx.session_id.clone()),
                        receipt_id: receipt.clone(),
                        event_type: Some(ctx.event.event_type.clone()),
                        trust_tier: Some(ctx.trust_tier.as_str().to_string()),
                        confidence: Some(1.0),
                        categories: cats.clone(),
                        reason: Some(reason.clone()),
                        traceparent,
                        payload_sha256: payload_sha256.clone(),
                        reviewer: None,
                    },
                    now_ms,
                )?;
                return Ok(InboundEvaluation {
                    decision: GateDecision::Quarantine { reason, notice },
                    stage: "stage1".to_string(),
                    receipt,
                    duplicate,
                    payload_sha256,
                    audit_seq: Some(audit_seq),
                    confidence: Some(1.0),
                    categories: cats,
                });
            }
        };

        // Step 1.5: Cryptographically verified human authority directives bypass Stage 2 and
        // `filters[]`, attach `human_auth_json` to the mailbox receipt, and write an immutable
        // `human_authority` audit record.
        if ctx.trust_tier == TrustTier::HumanVerified {
            let Some(ref auth) = ctx.human_auth else {
                if let Some(r) = existing_receipt {
                    let _ =
                        self.reject_existing_in_mailbox(r, ctx, "human_auth_unverified", now_ms)?;
                }
                return Ok(InboundEvaluation {
                    decision: GateDecision::Block {
                        reason: "human_auth_unverified".to_string(),
                    },
                    stage: "human_authority".to_string(),
                    receipt: None,
                    duplicate: false,
                    payload_sha256,
                    audit_seq: None,
                    confidence: Some(1.0),
                    categories: vec![
                        "gate.blocked".to_string(),
                        "human_auth_unverified".to_string(),
                    ],
                });
            };
            let (receipt, duplicate) = self.approve_existing_or_store_pending(
                existing_receipt,
                ctx,
                &payload_text,
                stage1_cap,
                traceparent.clone(),
                now_ms,
            )?;
            if receipt.is_none() && !duplicate {
                let extra = vec!["local_inbox_full".to_string()];
                let (audit_seq, cats) = self.record_hold_audit(
                    ctx,
                    &payload_sha256,
                    traceparent,
                    "mailbox",
                    None,
                    "local_inbox_full",
                    5_000,
                    &extra,
                    now_ms,
                )?;
                return Ok(InboundEvaluation {
                    decision: GateDecision::Hold {
                        reason: "local_inbox_full".to_string(),
                        retry_after_ms: 5_000,
                    },
                    stage: "mailbox".to_string(),
                    receipt: None,
                    duplicate: false,
                    payload_sha256,
                    audit_seq: Some(audit_seq),
                    confidence: Some(1.0),
                    categories: cats,
                });
            }
            if let Some(ref r) = receipt {
                let auth_json = serde_json::to_string(auth).map_err(|e| {
                    GateError::InvalidConfig(format!(
                        "failed to serialize verified human claim: {e}"
                    ))
                })?;
                let db_guard = self
                    .db
                    .lock()
                    .map_err(|_| GateError::LockPoisoned("node_db mutex poisoned".to_string()))?;
                let _ = db_guard.human().set_mailbox_human_auth(r, &auth_json)?;
            }
            let kid8: String = auth.kid.chars().take(8).collect();
            let mut cats = vec!["gate.allowed".to_string(), "human.verified".to_string()];
            cats.extend(stage1_out.categories);
            let audit_seq = self.record_audit(
                &GateAuditInput {
                    direction: GateDirection::Inbound,
                    stage: "human_authority".to_string(),
                    decision: StoreGateDecision::Allow,
                    origin_node: Some(ctx.origin_node.clone()),
                    source: Some(ctx.sender.clone()),
                    session_id: Some(ctx.session_id.clone()),
                    receipt_id: receipt.clone(),
                    event_type: Some(ctx.event.event_type.clone()),
                    trust_tier: Some("human-verified".to_string()),
                    confidence: Some(1.0),
                    categories: cats.clone(),
                    reason: urgency_cap_gate_reason(stage1_cap).map(str::to_string),
                    traceparent,
                    payload_sha256: payload_sha256.clone(),
                    reviewer: Some(format!("human:{}:{}", auth.human_id, kid8)),
                },
                now_ms,
            )?;
            return Ok(InboundEvaluation {
                decision: GateDecision::Allow {
                    max_urgency: stage1_cap,
                },
                stage: "human_authority".to_string(),
                receipt,
                duplicate,
                payload_sha256,
                audit_seq: Some(audit_seq),
                confidence: Some(1.0),
                categories: cats,
            });
        }

        // Step 2: Composable FilterPlugin chain (legacy `stage2` + ordered `filters[]`).
        // Short-circuits fail-closed on the first Hold / Quarantine / Block!
        let mut last_stage = "stage1".to_string();
        let mut last_confidence: Option<f64> = Some(1.0);
        let mut collected_categories = stage1_out.categories;

        if self.config.stage2.enabled && self.config.stage2.matchers.matches(ctx) {
            if let Some(ref stage2) = self.stage2 {
                let outcome = stage2.evaluate(ctx, self.secrets.as_deref()).await;
                if let Some(short_circuit) = self.handle_filter_outcome(
                    existing_receipt,
                    ctx,
                    &payload_text,
                    &payload_sha256,
                    traceparent.clone(),
                    "stage2",
                    outcome,
                    &mut last_stage,
                    &mut last_confidence,
                    &mut collected_categories,
                    now_ms,
                )? {
                    return Ok(short_circuit);
                }
            }
        }

        for plugin in &self.filters {
            if let Some(matchers) = plugin.matchers() {
                if !matchers.matches(ctx) {
                    continue;
                }
            }
            let stage_label = format!("filter:{}", plugin.id());
            let outcome = plugin
                .evaluate(ctx, &ctx.event, self.secrets.as_deref())
                .await;
            if let Some(short_circuit) = self.handle_filter_outcome(
                existing_receipt,
                ctx,
                &payload_text,
                &payload_sha256,
                traceparent.clone(),
                &stage_label,
                outcome,
                &mut last_stage,
                &mut last_confidence,
                &mut collected_categories,
                now_ms,
            )? {
                return Ok(short_circuit);
            }
        }

        let mut cats = vec!["gate.allowed".to_string()];
        cats.extend(collected_categories);
        self.finalize_allowed(
            existing_receipt,
            ctx,
            &payload_text,
            &payload_sha256,
            traceparent,
            &last_stage,
            stage1_cap,
            last_confidence,
            cats,
            now_ms,
        )
    }

    /// Evaluates an inbound local-ingest event (`Policy Integrity -> HumanVerified / Stage 1 ->
    /// FilterPlugin Chain`) and records an immutable `gate_audit` row WITHOUT writing a pending
    /// row into `mailbox` on `Allow` (the caller publishes allowed events onto `local.<topic>` so
    /// matched subscribers receive them cleanly).
    ///
    /// - Enforces `is_policy_tampered()` fail-closed for ALL trust tiers (including `HumanVerified`).
    /// - For `TrustTier::HumanVerified`: bypasses untrusted Stage 1 regexes and Stage 2 / `filters[]`,
    ///   and writes an immutable `gate_audit` row (`stage = "local_ingest"`,
    ///   `trust_tier = "human-verified"`, `reviewer = Some("human:<human_id>:<kid8>")`).
    /// - For unsigned events (`TrustTier::ExternalWebhook` etc.): runs full Stage 1 deterministic
    ///   checks and matched Stage 2 / `filters[]` plugins, parking `Quarantine` verdicts into
    ///   `GateState::Quarantined` and failing closed on `Block`/`Quarantine`/`Hold`.
    pub async fn screen_local_ingest(
        &self,
        ctx: &InboundContext,
        now_ms: i64,
    ) -> Result<InboundEvaluation, GateError> {
        let payload_text = ctx.payload_text();
        let payload_sha256 = sha256_hex(payload_text.as_bytes());
        let traceparent = ctx.traceparent();

        // Step 0: Anti-tamper guard policy integrity verification (fail-closed even for HumanVerified!).
        if self.is_policy_tampered() {
            let reason = "gate_policy_tampered".to_string();
            let notice = format_quarantine_notice(&reason);
            let cats = vec![
                "gate.tampered".to_string(),
                "gate_policy_tampered".to_string(),
            ];
            let (receipt, duplicate) = self.store_in_mailbox(
                ctx,
                &payload_text,
                GateState::Quarantined,
                Some(reason.clone()),
                traceparent.clone(),
                now_ms,
            )?;
            let audit_seq = self.record_audit(
                &GateAuditInput {
                    direction: GateDirection::Inbound,
                    stage: "policy_integrity".to_string(),
                    decision: StoreGateDecision::Quarantine,
                    origin_node: Some(ctx.origin_node.clone()),
                    source: Some(ctx.sender.clone()),
                    session_id: Some(ctx.session_id.clone()),
                    receipt_id: receipt.clone(),
                    event_type: Some(ctx.event.event_type.clone()),
                    trust_tier: Some(ctx.trust_tier.as_str().to_string()),
                    confidence: Some(1.0),
                    categories: cats.clone(),
                    reason: Some(reason.clone()),
                    traceparent,
                    payload_sha256: payload_sha256.clone(),
                    reviewer: None,
                },
                now_ms,
            )?;
            return Ok(InboundEvaluation {
                decision: GateDecision::Quarantine { reason, notice },
                stage: "policy_integrity".to_string(),
                receipt,
                duplicate,
                payload_sha256,
                audit_seq: Some(audit_seq),
                confidence: Some(1.0),
                categories: cats,
            });
        }

        // Step 1: Cryptographically verified human-signed local ingest event (`hyphaesig`).
        if ctx.trust_tier == TrustTier::HumanVerified {
            let Some(ref auth) = ctx.human_auth else {
                let reason = "human_auth_unverified".to_string();
                let cats = vec![
                    "gate.blocked".to_string(),
                    "human_auth_unverified".to_string(),
                ];
                let audit_seq = self.record_audit(
                    &GateAuditInput {
                        direction: GateDirection::Inbound,
                        stage: "local_ingest".to_string(),
                        decision: StoreGateDecision::Block,
                        origin_node: Some(ctx.origin_node.clone()),
                        source: Some(ctx.sender.clone()),
                        session_id: Some(ctx.session_id.clone()),
                        receipt_id: None,
                        event_type: Some(ctx.event.event_type.clone()),
                        trust_tier: Some("human-verified".to_string()),
                        confidence: Some(1.0),
                        categories: cats.clone(),
                        reason: Some(reason.clone()),
                        traceparent,
                        payload_sha256: payload_sha256.clone(),
                        reviewer: None,
                    },
                    now_ms,
                )?;
                return Ok(InboundEvaluation {
                    decision: GateDecision::Block { reason },
                    stage: "local_ingest".to_string(),
                    receipt: None,
                    duplicate: false,
                    payload_sha256,
                    audit_seq: Some(audit_seq),
                    confidence: Some(1.0),
                    categories: cats,
                });
            };
            let kid8: String = auth.kid.chars().take(8).collect();
            let cats = vec![
                "gate.allowed".to_string(),
                "human.verified".to_string(),
                "local_ingest".to_string(),
            ];
            let audit_seq = self.record_audit(
                &GateAuditInput {
                    direction: GateDirection::Inbound,
                    stage: "local_ingest".to_string(),
                    decision: StoreGateDecision::Allow,
                    origin_node: Some(ctx.origin_node.clone()),
                    source: Some(ctx.sender.clone()),
                    session_id: Some(ctx.session_id.clone()),
                    receipt_id: None,
                    event_type: Some(ctx.event.event_type.clone()),
                    trust_tier: Some("human-verified".to_string()),
                    confidence: Some(1.0),
                    categories: cats.clone(),
                    reason: None,
                    traceparent,
                    payload_sha256: payload_sha256.clone(),
                    reviewer: Some(format!("human:{}:{}", auth.human_id, kid8)),
                },
                now_ms,
            )?;
            return Ok(InboundEvaluation {
                decision: GateDecision::ALLOW,
                stage: "local_ingest".to_string(),
                receipt: None,
                duplicate: false,
                payload_sha256,
                audit_seq: Some(audit_seq),
                confidence: Some(1.0),
                categories: cats,
            });
        }

        // Step 2: Deterministic Stage 1 screening (mutex dropped before any .await!).
        let stage1_out = {
            let db_guard = self
                .db
                .lock()
                .map_err(|_| GateError::LockPoisoned("node_db mutex poisoned".to_string()))?;
            self.stage1.evaluate_inbound(ctx, Some(&db_guard), now_ms)
        };

        let stage1_cap = match stage1_out.decision {
            GateDecision::Allow { max_urgency } => max_urgency,
            GateDecision::Hold {
                reason,
                retry_after_ms,
            } => {
                let (audit_seq, cats) = self.record_hold_audit(
                    ctx,
                    &payload_sha256,
                    traceparent,
                    "stage1",
                    None,
                    &reason,
                    retry_after_ms,
                    &stage1_out.categories,
                    now_ms,
                )?;
                return Ok(InboundEvaluation {
                    decision: GateDecision::Hold {
                        reason,
                        retry_after_ms,
                    },
                    stage: "stage1".to_string(),
                    receipt: None,
                    duplicate: false,
                    payload_sha256,
                    audit_seq: Some(audit_seq),
                    confidence: None,
                    categories: cats,
                });
            }
            GateDecision::Block { reason } => {
                let mut cats = vec!["gate.blocked".to_string()];
                cats.extend(stage1_out.categories);
                let audit_seq = self.record_audit(
                    &GateAuditInput {
                        direction: GateDirection::Inbound,
                        stage: "stage1".to_string(),
                        decision: StoreGateDecision::Block,
                        origin_node: Some(ctx.origin_node.clone()),
                        source: Some(ctx.sender.clone()),
                        session_id: Some(ctx.session_id.clone()),
                        receipt_id: None,
                        event_type: Some(ctx.event.event_type.clone()),
                        trust_tier: Some(ctx.trust_tier.as_str().to_string()),
                        confidence: Some(1.0),
                        categories: cats.clone(),
                        reason: Some(reason.clone()),
                        traceparent,
                        payload_sha256: payload_sha256.clone(),
                        reviewer: None,
                    },
                    now_ms,
                )?;
                return Ok(InboundEvaluation {
                    decision: GateDecision::Block { reason },
                    stage: "stage1".to_string(),
                    receipt: None,
                    duplicate: false,
                    payload_sha256,
                    audit_seq: Some(audit_seq),
                    confidence: Some(1.0),
                    categories: cats,
                });
            }
            GateDecision::Quarantine { reason, notice } => {
                let mut cats = vec!["gate.quarantined".to_string()];
                cats.extend(stage1_out.categories);
                let (receipt, duplicate) = self.store_in_mailbox(
                    ctx,
                    &payload_text,
                    GateState::Quarantined,
                    Some(reason.clone()),
                    traceparent.clone(),
                    now_ms,
                )?;
                let audit_seq = self.record_audit(
                    &GateAuditInput {
                        direction: GateDirection::Inbound,
                        stage: "stage1".to_string(),
                        decision: StoreGateDecision::Quarantine,
                        origin_node: Some(ctx.origin_node.clone()),
                        source: Some(ctx.sender.clone()),
                        session_id: Some(ctx.session_id.clone()),
                        receipt_id: receipt.clone(),
                        event_type: Some(ctx.event.event_type.clone()),
                        trust_tier: Some(ctx.trust_tier.as_str().to_string()),
                        confidence: Some(1.0),
                        categories: cats.clone(),
                        reason: Some(reason.clone()),
                        traceparent,
                        payload_sha256: payload_sha256.clone(),
                        reviewer: None,
                    },
                    now_ms,
                )?;
                return Ok(InboundEvaluation {
                    decision: GateDecision::Quarantine { reason, notice },
                    stage: "stage1".to_string(),
                    receipt,
                    duplicate,
                    payload_sha256,
                    audit_seq: Some(audit_seq),
                    confidence: Some(1.0),
                    categories: cats,
                });
            }
        };

        // Step 3: Stage 2 + ordered FilterPlugin chain.
        let mut last_stage = "stage1".to_string();
        let mut last_confidence: Option<f64> = Some(1.0);
        let mut collected_categories = stage1_out.categories;

        if self.config.stage2.enabled && self.config.stage2.matchers.matches(ctx) {
            if let Some(ref stage2) = self.stage2 {
                let outcome = stage2.evaluate(ctx, self.secrets.as_deref()).await;
                if let Some(short_circuit) = self.handle_filter_outcome(
                    None,
                    ctx,
                    &payload_text,
                    &payload_sha256,
                    traceparent.clone(),
                    "stage2",
                    outcome,
                    &mut last_stage,
                    &mut last_confidence,
                    &mut collected_categories,
                    now_ms,
                )? {
                    return Ok(short_circuit);
                }
            }
        }

        for plugin in &self.filters {
            if let Some(matchers) = plugin.matchers() {
                if !matchers.matches(ctx) {
                    continue;
                }
            }
            let stage_label = format!("filter:{}", plugin.id());
            let outcome = plugin
                .evaluate(ctx, &ctx.event, self.secrets.as_deref())
                .await;
            if let Some(short_circuit) = self.handle_filter_outcome(
                None,
                ctx,
                &payload_text,
                &payload_sha256,
                traceparent.clone(),
                &stage_label,
                outcome,
                &mut last_stage,
                &mut last_confidence,
                &mut collected_categories,
                now_ms,
            )? {
                return Ok(short_circuit);
            }
        }

        // Step 4: Record immutable `gate_audit` allow entry without creating a stray pending mailbox row.
        let mut cats = vec!["gate.allowed".to_string(), "local_ingest".to_string()];
        cats.extend(collected_categories);
        let audit_seq = self.record_audit(
            &GateAuditInput {
                direction: GateDirection::Inbound,
                stage: last_stage.clone(),
                decision: StoreGateDecision::Allow,
                origin_node: Some(ctx.origin_node.clone()),
                source: Some(ctx.sender.clone()),
                session_id: Some(ctx.session_id.clone()),
                receipt_id: None,
                event_type: Some(ctx.event.event_type.clone()),
                trust_tier: Some(ctx.trust_tier.as_str().to_string()),
                confidence: last_confidence,
                categories: cats.clone(),
                reason: urgency_cap_gate_reason(stage1_cap).map(str::to_string),
                traceparent,
                payload_sha256: payload_sha256.clone(),
                reviewer: None,
            },
            now_ms,
        )?;

        Ok(InboundEvaluation {
            decision: GateDecision::Allow {
                max_urgency: stage1_cap,
            },
            stage: last_stage,
            receipt: None,
            duplicate: false,
            payload_sha256,
            audit_seq: Some(audit_seq),
            confidence: last_confidence,
            categories: cats,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_filter_outcome(
        &self,
        existing_receipt: Option<&str>,
        ctx: &InboundContext,
        payload_text: &str,
        payload_sha256: &str,
        traceparent: Option<String>,
        stage_label: &str,
        outcome: FilterOutcome,
        last_stage: &mut String,
        last_confidence: &mut Option<f64>,
        collected_categories: &mut Vec<String>,
        now_ms: i64,
    ) -> Result<Option<InboundEvaluation>, GateError> {
        match outcome.decision {
            GateDecision::Allow { .. } => {
                *last_stage = stage_label.to_string();
                *last_confidence = outcome.confidence;
                collected_categories.extend(outcome.categories);
                Ok(None)
            }
            GateDecision::Hold {
                reason,
                retry_after_ms,
            } => {
                // G4 (P0): Retain held rows untouched and ALWAYS write an immutable `gate_audit` row.
                let (audit_seq, cats) = self.record_hold_audit(
                    ctx,
                    payload_sha256,
                    traceparent,
                    stage_label,
                    existing_receipt.map(ToString::to_string),
                    &reason,
                    retry_after_ms,
                    &outcome.categories,
                    now_ms,
                )?;
                Ok(Some(InboundEvaluation {
                    decision: GateDecision::Hold {
                        reason,
                        retry_after_ms,
                    },
                    stage: stage_label.to_string(),
                    receipt: existing_receipt.map(ToString::to_string),
                    duplicate: false,
                    payload_sha256: payload_sha256.to_string(),
                    audit_seq: Some(audit_seq),
                    confidence: outcome.confidence,
                    categories: cats,
                }))
            }
            GateDecision::Quarantine { reason, notice } => {
                let (store_decision, tag) = if outcome.had_error {
                    (StoreGateDecision::Error, "gate.error")
                } else {
                    (StoreGateDecision::Quarantine, "gate.quarantined")
                };
                let mut cats = vec![tag.to_string()];
                cats.extend(outcome.categories);
                let (receipt, duplicate) = self.quarantine_or_store(
                    existing_receipt,
                    ctx,
                    payload_text,
                    &reason,
                    traceparent.clone(),
                    now_ms,
                )?;
                let audit_seq = self.record_audit(
                    &GateAuditInput {
                        direction: GateDirection::Inbound,
                        stage: stage_label.to_string(),
                        decision: store_decision,
                        origin_node: Some(ctx.origin_node.clone()),
                        source: Some(ctx.sender.clone()),
                        session_id: Some(ctx.session_id.clone()),
                        receipt_id: receipt.clone(),
                        event_type: Some(ctx.event.event_type.clone()),
                        trust_tier: Some(ctx.trust_tier.as_str().to_string()),
                        confidence: outcome.confidence,
                        categories: cats.clone(),
                        reason: Some(reason.clone()),
                        traceparent,
                        payload_sha256: payload_sha256.to_string(),
                        reviewer: None,
                    },
                    now_ms,
                )?;
                Ok(Some(InboundEvaluation {
                    decision: GateDecision::Quarantine { reason, notice },
                    stage: stage_label.to_string(),
                    receipt,
                    duplicate,
                    payload_sha256: payload_sha256.to_string(),
                    audit_seq: Some(audit_seq),
                    confidence: outcome.confidence,
                    categories: cats,
                }))
            }
            GateDecision::Block { reason } => {
                let (store_decision, tag) = if outcome.had_error {
                    (StoreGateDecision::Error, "gate.error")
                } else {
                    (StoreGateDecision::Block, "gate.blocked")
                };
                let mut cats = vec![tag.to_string()];
                cats.extend(outcome.categories);
                if let Some(r) = existing_receipt {
                    let _ = self.reject_existing_in_mailbox(r, ctx, &reason, now_ms)?;
                }
                let audit_seq = self.record_audit(
                    &GateAuditInput {
                        direction: GateDirection::Inbound,
                        stage: stage_label.to_string(),
                        decision: store_decision,
                        origin_node: Some(ctx.origin_node.clone()),
                        source: Some(ctx.sender.clone()),
                        session_id: Some(ctx.session_id.clone()),
                        receipt_id: existing_receipt.map(ToString::to_string),
                        event_type: Some(ctx.event.event_type.clone()),
                        trust_tier: Some(ctx.trust_tier.as_str().to_string()),
                        confidence: outcome.confidence,
                        categories: cats.clone(),
                        reason: Some(reason.clone()),
                        traceparent,
                        payload_sha256: payload_sha256.to_string(),
                        reviewer: None,
                    },
                    now_ms,
                )?;
                Ok(Some(InboundEvaluation {
                    decision: GateDecision::Block { reason },
                    stage: stage_label.to_string(),
                    receipt: None,
                    duplicate: false,
                    payload_sha256: payload_sha256.to_string(),
                    audit_seq: Some(audit_seq),
                    confidence: outcome.confidence,
                    categories: cats,
                }))
            }
        }
    }

    /// Evaluates an outbound pre-encrypt payload via Stage 1 Outbound DLP Secret Scanner and
    /// writes an immutable `gate_audit` row (NEVER storing leaked secrets).
    pub fn evaluate_outbound(
        &self,
        ctx: &OutboundContext,
        now_ms: i64,
    ) -> Result<OutboundEvaluation, GateError> {
        let payload_sha256 = sha256_hex(ctx.payload.as_bytes());
        let out = self.stage1.evaluate_outbound(ctx);

        let (store_decision, audit_tag, reason) = match &out.decision {
            GateDecision::Allow { .. } => (StoreGateDecision::Allow, "gate.allowed", None),
            GateDecision::Block { reason } => (
                StoreGateDecision::Block,
                "gate.blocked",
                Some(reason.clone()),
            ),
            GateDecision::Quarantine { reason, .. } => (
                StoreGateDecision::Quarantine,
                "gate.quarantined",
                Some(reason.clone()),
            ),
            GateDecision::Hold { reason, .. } => {
                (StoreGateDecision::Error, "gate.held", Some(reason.clone()))
            }
        };

        let mut audit_categories = vec![audit_tag.to_string()];
        audit_categories.extend(out.categories.iter().cloned());

        let audit_seq = self.record_audit(
            &GateAuditInput {
                direction: GateDirection::Outbound,
                stage: "stage1.dlp".to_string(),
                decision: store_decision,
                origin_node: ctx.destination_node.clone(),
                source: Some(ctx.destination.clone()),
                session_id: ctx.session_id.clone(),
                receipt_id: None,
                event_type: Some(ctx.event_type.clone()),
                trust_tier: Some(ctx.trust_tier.as_str().to_string()),
                confidence: Some(1.0),
                categories: audit_categories,
                reason,
                traceparent: ctx.traceparent.clone(),
                payload_sha256: payload_sha256.clone(),
                reviewer: None,
            },
            now_ms,
        )?;

        Ok(OutboundEvaluation {
            decision: out.decision,
            payload_sha256,
            audit_seq,
            categories: out.categories,
        })
    }

    // ---- Human-CLI-only Quarantine Review & Audit Log Operations (§5.1, §5.4) ----
    // Note: Intentionally NEVER exposed as MCP tools to agents!

    /// Lists quarantined mailbox items awaiting human CLI review (`hyp gate review`).
    pub fn review_quarantined(
        &self,
        session_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<MailboxEntry>, GateError> {
        let db = self
            .db
            .lock()
            .map_err(|_| GateError::LockPoisoned("node_db mutex poisoned".to_string()))?;
        Ok(db.local().list_quarantined(session_id, limit)?)
    }

    /// Human-CLI-only approval (`hyp inbox approve <receipt>`).
    /// Releases a quarantined item into the target session's `pending` inbox and writes a
    /// `human_review` audit entry.
    pub fn approve_quarantined(
        &self,
        receipt_id: &str,
        reviewer: &str,
        now_ms: i64,
    ) -> Result<MailboxEntry, GateError> {
        let db = self
            .db
            .lock()
            .map_err(|_| GateError::LockPoisoned("node_db mutex poisoned".to_string()))?;
        Ok(db
            .local()
            .approve_quarantined(receipt_id, reviewer, now_ms)?)
    }

    /// Human-CLI-only rejection (`hyp inbox reject <receipt> [--mute]`).
    /// Permanently rejects a quarantined item, writes a `human_review` audit entry, and when
    /// `mute == true`, atomically installs a global Stage 1 mute rule for the item's sender.
    pub fn reject_quarantined(
        &self,
        receipt_id: &str,
        reviewer: &str,
        reason: &str,
        mute: bool,
        now_ms: i64,
    ) -> Result<MailboxEntry, GateError> {
        let db = self
            .db
            .lock()
            .map_err(|_| GateError::LockPoisoned("node_db mutex poisoned".to_string()))?;
        let mute_rule = if mute {
            let entry = db.local().get_mailbox_entry(receipt_id)?.ok_or_else(|| {
                GateError::Store(hyp_store::StoreError::NotFound(format!(
                    "receipt '{receipt_id}' not found"
                )))
            })?;
            let pattern = if !entry.source.trim().is_empty() {
                entry.source
            } else {
                entry.origin_node
            };
            (!pattern.trim().is_empty()).then_some(MuteRuleInput {
                scope: "*".to_string(),
                pattern,
            })
        } else {
            None
        };
        Ok(db.local().reject_quarantined(
            receipt_id,
            reviewer,
            reason,
            mute_rule.as_ref(),
            now_ms,
        )?)
    }

    /// Queries the immutable `gate_audit` log (`hyp gate log`).
    pub fn query_audit_log(
        &self,
        query: &GateAuditQuery,
    ) -> Result<Vec<GateAuditEntry>, GateError> {
        let db = self
            .db
            .lock()
            .map_err(|_| GateError::LockPoisoned("node_db mutex poisoned".to_string()))?;
        Ok(db.local().query_gate_audit(query)?)
    }

    #[allow(clippy::too_many_arguments)]
    fn finalize_allowed(
        &self,
        existing_receipt: Option<&str>,
        ctx: &InboundContext,
        payload_text: &str,
        payload_sha256: &str,
        traceparent: Option<String>,
        stage: &str,
        max_urgency: Option<DeliveryUrgency>,
        confidence: Option<f64>,
        categories: Vec<String>,
        now_ms: i64,
    ) -> Result<InboundEvaluation, GateError> {
        let (receipt, duplicate) = self.approve_existing_or_store_pending(
            existing_receipt,
            ctx,
            payload_text,
            max_urgency,
            traceparent.clone(),
            now_ms,
        )?;
        if receipt.is_none() && !duplicate {
            let extra = vec!["local_inbox_full".to_string()];
            let (audit_seq, cats) = self.record_hold_audit(
                ctx,
                payload_sha256,
                traceparent,
                "mailbox",
                None,
                "local_inbox_full",
                5_000,
                &extra,
                now_ms,
            )?;
            return Ok(InboundEvaluation {
                decision: GateDecision::Hold {
                    reason: "local_inbox_full".to_string(),
                    retry_after_ms: 5_000,
                },
                stage: "mailbox".to_string(),
                receipt: None,
                duplicate: false,
                payload_sha256: payload_sha256.to_string(),
                audit_seq: Some(audit_seq),
                confidence,
                categories: cats,
            });
        }

        let audit_seq = self.record_audit(
            &GateAuditInput {
                direction: GateDirection::Inbound,
                stage: stage.to_string(),
                decision: StoreGateDecision::Allow,
                origin_node: Some(ctx.origin_node.clone()),
                source: Some(ctx.sender.clone()),
                session_id: Some(ctx.session_id.clone()),
                receipt_id: receipt.clone(),
                event_type: Some(ctx.event.event_type.clone()),
                trust_tier: Some(ctx.trust_tier.as_str().to_string()),
                confidence,
                categories: categories.clone(),
                reason: urgency_cap_gate_reason(max_urgency).map(str::to_string),
                traceparent,
                payload_sha256: payload_sha256.to_string(),
                reviewer: None,
            },
            now_ms,
        )?;

        Ok(InboundEvaluation {
            decision: GateDecision::Allow { max_urgency },
            stage: stage.to_string(),
            receipt,
            duplicate,
            payload_sha256: payload_sha256.to_string(),
            audit_seq: Some(audit_seq),
            confidence,
            categories,
        })
    }

    fn approve_existing_or_store_pending(
        &self,
        existing_receipt: Option<&str>,
        ctx: &InboundContext,
        payload_text: &str,
        max_urgency: Option<DeliveryUrgency>,
        traceparent: Option<String>,
        now_ms: i64,
    ) -> Result<(Option<String>, bool), GateError> {
        let gate_reason = urgency_cap_gate_reason(max_urgency);
        let db = self
            .db
            .lock()
            .map_err(|_| GateError::LockPoisoned("node_db mutex poisoned".to_string()))?;
        if let Some(r) = existing_receipt {
            if db
                .local()
                .mark_mailbox_gate_approved(&ctx.session_id, r, gate_reason, now_ms)?
            {
                return Ok((Some(r.to_string()), false));
            }
        }
        let res = db.local().put_in_mailbox(
            &MailboxInsert {
                session_id: ctx.session_id.clone(),
                origin_node: ctx.origin_node.clone(),
                item_id: ctx.event.id.clone(),
                text: payload_text.to_string(),
                kind: ctx.kind,
                source: ctx.sender.clone(),
                gate_state: GateState::Pending,
                gate_reason: gate_reason.map(str::to_string),
                traceparent,
            },
            now_ms,
        )?;
        match res {
            MailboxPutResult::Stored { receipt } => {
                let _ = db.local().mark_mailbox_gate_approved(
                    &ctx.session_id,
                    &receipt,
                    gate_reason,
                    now_ms,
                )?;
                Ok((Some(receipt), false))
            }
            MailboxPutResult::Duplicate => Ok((None, true)),
            MailboxPutResult::QueueFull => Ok((None, false)),
        }
    }

    fn quarantine_or_store(
        &self,
        existing_receipt: Option<&str>,
        ctx: &InboundContext,
        payload_text: &str,
        reason: &str,
        traceparent: Option<String>,
        now_ms: i64,
    ) -> Result<(Option<String>, bool), GateError> {
        if let Some(r) = existing_receipt {
            let transitioned = {
                let db = self
                    .db
                    .lock()
                    .map_err(|_| GateError::LockPoisoned("node_db mutex poisoned".to_string()))?;
                db.local().transition_mailbox_gate_state(
                    &ctx.session_id,
                    r,
                    GateState::Quarantined,
                    Some(reason),
                    now_ms,
                )?
            };
            if transitioned {
                return Ok((Some(r.to_string()), false));
            }
        }
        self.store_in_mailbox(
            ctx,
            payload_text,
            GateState::Quarantined,
            Some(reason.to_string()),
            traceparent,
            now_ms,
        )
    }

    fn reject_existing_in_mailbox(
        &self,
        existing_receipt: &str,
        ctx: &InboundContext,
        reason: &str,
        now_ms: i64,
    ) -> Result<bool, GateError> {
        let db = self
            .db
            .lock()
            .map_err(|_| GateError::LockPoisoned("node_db mutex poisoned".to_string()))?;
        Ok(db.local().transition_mailbox_gate_state(
            &ctx.session_id,
            existing_receipt,
            GateState::Rejected,
            Some(reason),
            now_ms,
        )?)
    }

    #[allow(clippy::too_many_arguments)]
    fn record_hold_audit(
        &self,
        ctx: &InboundContext,
        payload_sha256: &str,
        traceparent: Option<String>,
        stage: &str,
        receipt_id: Option<String>,
        reason: &str,
        retry_after_ms: u64,
        extra_categories: &[String],
        now_ms: i64,
    ) -> Result<(i64, Vec<String>), GateError> {
        let mut cats = vec!["gate.held".to_string()];
        for c in extra_categories {
            if !cats.iter().any(|existing| existing == c) {
                cats.push(c.clone());
            }
        }
        let audit_reason = format!("{reason} (retry_after_ms={retry_after_ms})");
        let seq = self.record_audit(
            &GateAuditInput {
                direction: GateDirection::Inbound,
                stage: stage.to_string(),
                decision: StoreGateDecision::Error,
                origin_node: Some(ctx.origin_node.clone()),
                source: Some(ctx.sender.clone()),
                session_id: Some(ctx.session_id.clone()),
                receipt_id,
                event_type: Some(ctx.event.event_type.clone()),
                trust_tier: Some(ctx.trust_tier.as_str().to_string()),
                confidence: None,
                categories: cats.clone(),
                reason: Some(audit_reason),
                traceparent,
                payload_sha256: payload_sha256.to_string(),
                reviewer: None,
            },
            now_ms,
        )?;
        Ok((seq, cats))
    }

    fn store_in_mailbox(
        &self,
        ctx: &InboundContext,
        payload_text: &str,
        gate_state: GateState,
        gate_reason: Option<String>,
        traceparent: Option<String>,
        now_ms: i64,
    ) -> Result<(Option<String>, bool), GateError> {
        let db = self
            .db
            .lock()
            .map_err(|_| GateError::LockPoisoned("node_db mutex poisoned".to_string()))?;
        let res = db.local().put_in_mailbox(
            &MailboxInsert {
                session_id: ctx.session_id.clone(),
                origin_node: ctx.origin_node.clone(),
                item_id: ctx.event.id.clone(),
                text: payload_text.to_string(),
                kind: ctx.kind,
                source: ctx.sender.clone(),
                gate_state,
                gate_reason,
                traceparent,
            },
            now_ms,
        )?;
        match res {
            MailboxPutResult::Stored { receipt } => Ok((Some(receipt), false)),
            MailboxPutResult::Duplicate => Ok((None, true)),
            MailboxPutResult::QueueFull => Ok((None, false)),
        }
    }

    fn record_audit(&self, input: &GateAuditInput, now_ms: i64) -> Result<i64, GateError> {
        let db = self
            .db
            .lock()
            .map_err(|_| GateError::LockPoisoned("node_db mutex poisoned".to_string()))?;
        Ok(db.local().append_gate_audit(input, now_ms)?)
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}
