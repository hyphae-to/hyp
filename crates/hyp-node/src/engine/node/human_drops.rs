use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

use hyp_crypto::OkpJwk as CryptoOkpJwk;
use hyp_crypto::human::{
    HumanDropEnvelopeV1, HumanDropKind, decode_hdrop1, is_reserved_drop_secret_name,
    open_human_drop,
};
use hyp_crypto::keystore::validate_secret_name;
use hyp_crypto::rfc3339::parse_rfc3339_millis;
use hyp_proto::address::LOCAL_NODE_ID;
use hyp_proto::cloudevent::{
    CloudEvent as ProtoCloudEvent, TYPE_HUMAN_DROP_V1, TYPE_HUMAN_SECRET_STORED_V1,
};
use hyp_store::{
    GateAuditInput, GateDecision as StoreGateDecision, GateDirection, GateState,
    HumanAuthorityRecord, HumanClaimKind, MailboxInsert, MailboxKind, MailboxPutResult, now_ms,
    sha256_hex,
};

use crate::delivery::DeliveryUrgency;
use crate::engine::config::NodeError;
use crate::gates::{
    GateDecision, InboundContext, SecurityGatePipeline, TrustTier as GateTrustTier,
    VerifiedHumanClaim,
};

use super::UnifiedNode;

#[derive(Clone, Copy)]
struct HumanDropAudit<'a> {
    source: Option<&'a str>,
    session_id: Option<&'a str>,
    payload_digest_input: &'a [u8],
    now: i64,
}

/// Metadata-only result returned by [`UnifiedNode::ingest_human_drop`].
///
/// **Zero-leak invariant:** Never contains secret payload bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IngestedHumanDrop {
    pub claim_id: String,
    pub human_id: String,
    pub kid: String,
    pub role: String,
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_session: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mailbox_receipt: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_seq: Option<i64>,
    pub downgraded_to_notify: bool,
}

impl UnifiedNode {
    /// Decodes an armored `hdrop1_` token and ingests it via [`UnifiedNode::ingest_human_drop`].
    pub async fn ingest_human_drop_token(
        &self,
        token: &str,
        gate: Option<&SecurityGatePipeline>,
        overwrite_secret: bool,
    ) -> Result<IngestedHumanDrop, NodeError> {
        let envelope = match decode_hdrop1(token) {
            Ok(env) => env,
            Err(e) => {
                let reason = format!("invalid hdrop1_ token: {e}");
                return self.reject_human_drop(
                    HumanDropAudit {
                        source: None,
                        session_id: None,
                        payload_digest_input: b"redacted-hdrop1",
                        now: now_ms(),
                    },
                    "human.invalid_token",
                    reason,
                    NodeError::Unauthorized,
                );
            }
        };
        self.ingest_human_drop(&envelope, gate, overwrite_secret)
            .await
    }

    fn record_human_drop_rejected_audit(
        &self,
        audit: HumanDropAudit<'_>,
        category: &str,
        reason: &str,
    ) {
        let categories = vec!["gate.human_drop_rejected".to_string(), category.to_string()];
        let db = self.db();
        let _ = db.local().append_gate_audit(
            &GateAuditInput {
                direction: GateDirection::Inbound,
                stage: "human_authority".to_string(),
                decision: StoreGateDecision::Block,
                origin_node: Some(self.node_id().to_string()),
                source: audit.source.map(str::to_owned),
                session_id: audit.session_id.map(str::to_owned),
                receipt_id: None,
                event_type: Some(TYPE_HUMAN_DROP_V1.to_string()),
                trust_tier: Some("unverified".to_string()),
                confidence: None,
                categories,
                reason: Some(reason.to_string()),
                traceparent: None,
                payload_sha256: sha256_hex(audit.payload_digest_input),
                reviewer: None,
            },
            audit.now,
        );
    }

    fn reject_human_drop(
        &self,
        audit: HumanDropAudit<'_>,
        category: &str,
        reason: impl Into<String>,
        error: fn(String) -> NodeError,
    ) -> Result<IngestedHumanDrop, NodeError> {
        let reason = reason.into();
        self.record_human_drop_rejected_audit(audit, category, &reason);
        Err(error(reason))
    }

    /// Strictly opens, verifies, replay-guards, and ingests a sealed [`HumanDropEnvelopeV1`]:
    ///
    /// - Fails closed if `gate` reports `is_policy_tampered() == true`.
    /// - Decrypts Mode B HPKE (`human.drop.v1`) with this node's X25519 key, verifies the inner
    ///   Ed25519 signature against an active authority in `human_authorities`, enforces audience
    ///   (`nodeId`, `nodeEncKid`), monotonic `min_auth_epoch` AND exact authority key epoch binding
    ///   (`rec.auth_epoch >= min_epoch && claim.auth_epoch == rec.auth_epoch`, H5), TTL (`<= 15m`),
    ///   clock skew (`60s`), and single-use atomic `claim_id` nonce consumption.
    /// - Writes an immutable `gate_audit` row (`gate.human_drop_rejected`) on every rejected,
    ///   expired, revoked, epoch-stale, or replayed drop claim before returning `Err` (H11).
    /// - **`HumanDropKind::Secret`**: writes directly to [`SecretStore`](hyp_crypto::SecretStore) after reserved-name and
    ///   human-signed overwrite checks (`spec.overwrite` governs fail-closed, H15); **zero** secret
    ///   bytes ever touch SQLite, logs, errors, or return values; delivers a metadata-only notice to
    ///   the target local session and records a `human_authority` audit row.
    /// - **`HumanDropKind::Directive`**: delivers with [`GateTrustTier::HumanVerified`] through
    ///   `gate` (bypassing Stage 2 / untrusted regexes while preserving anti-tamper & rate/size
    ///   limits) or directly into `mailbox` + `gate_audit` when `gate` is `None`.
    pub async fn ingest_human_drop(
        &self,
        envelope: &HumanDropEnvelopeV1,
        gate: Option<&SecurityGatePipeline>,
        overwrite_secret: bool,
    ) -> Result<IngestedHumanDrop, NodeError> {
        let now = now_ms();
        let audit = HumanDropAudit {
            source: None,
            session_id: None,
            payload_digest_input: envelope.ct.as_bytes(),
            now,
        };
        if let Some(g) = gate {
            if g.is_policy_tampered() {
                return self.reject_human_drop(
                    audit,
                    "gate.policy_tampered",
                    "gate_policy_tampered",
                    NodeError::Unauthorized,
                );
            }
        }

        let mut matched_authority: Option<HumanAuthorityRecord> = None;
        let mut rejected_stale_epoch_key = false;
        let claim = match open_human_drop(
            envelope,
            &self.identity.encryption,
            self.node_id().as_str(),
            now,
            |human_id, human_kid| {
                let db = self.db();
                let min_epoch = db.human().min_auth_epoch().ok()?;
                let rec = db.human().get_active_authority_by_kid(human_kid).ok()??;
                if rec.human_id != human_id {
                    return None;
                }
                // H5: Bumping `min_auth_epoch` MUST invalidate old-epoch keys even if the
                // signer lies about `claim.auth_epoch` inside the claim payload!
                if rec.auth_epoch < min_epoch {
                    rejected_stale_epoch_key = true;
                    return None;
                }
                let jwk: CryptoOkpJwk = serde_json::from_str(&rec.jwk_json).ok()?;
                let pk = jwk.to_ed25519().ok()?;
                matched_authority = Some(rec);
                Some((pk, min_epoch))
            },
        ) {
            Ok(c) => Zeroizing::new(c),
            Err(e) => {
                let err_msg = e.to_string();
                let lower = err_msg.to_ascii_lowercase();
                let extra_cat = if rejected_stale_epoch_key || lower.contains("authepoch") {
                    "human.epoch_stale"
                } else if lower.contains("expired") {
                    "human.expired"
                } else if lower.contains("unknown or revoked") {
                    "human.revoked_or_unknown"
                } else if lower.contains("reserved system secret") {
                    "human.reserved_secret"
                } else {
                    "human.verification_failed"
                };
                let reason = format!("human drop verification failed: {err_msg}");
                return self.reject_human_drop(audit, extra_cat, reason, NodeError::Unauthorized);
            }
        };

        let auth_rec = match matched_authority {
            Some(rec) => rec,
            None => {
                let reason = "verified human authority record unavailable";
                return self.reject_human_drop(
                    audit,
                    "human.revoked_or_unknown",
                    reason,
                    NodeError::Unauthorized,
                );
            }
        };

        let kid8: String = auth_rec.kid.chars().take(8).collect();
        let source = format!("human:{}:{}", auth_rec.human_id, kid8);
        let verified_audit = HumanDropAudit {
            source: Some(&source),
            ..audit
        };

        // H5: Enforce exact epoch binding (`claim.auth_epoch == rec.auth_epoch`), preventing an
        // old-epoch key from claiming a forged higher epoch.
        if claim.auth_epoch != auth_rec.auth_epoch {
            let reason = format!(
                "human claim authEpoch {} does not match enrolled authority key epoch {}",
                claim.auth_epoch, auth_rec.auth_epoch
            );
            return self.reject_human_drop(
                verified_audit,
                "human.epoch_mismatch",
                reason,
                NodeError::Unauthorized,
            );
        }

        let issued_at_ms = match parse_rfc3339_millis(&claim.issued_at) {
            Ok(ms) => ms,
            Err(e) => {
                let reason = format!("invalid claim issuedAt: {e}");
                return self.reject_human_drop(
                    verified_audit,
                    "human.invalid_timestamp",
                    reason,
                    NodeError::BadRequest,
                );
            }
        };
        let expires_at_ms = match parse_rfc3339_millis(&claim.expires_at) {
            Ok(ms) => ms,
            Err(e) => {
                let reason = format!("invalid claim expiresAt: {e}");
                return self.reject_human_drop(
                    verified_audit,
                    "human.invalid_timestamp",
                    reason,
                    NodeError::BadRequest,
                );
            }
        };

        let target_handle = claim.audience.handle.clone();
        let target_session = self.resolve_human_drop_target_session(target_handle.as_deref())?;
        let targeted_audit = HumanDropAudit {
            session_id: Some(&target_session),
            ..verified_audit
        };

        let verified_claim = VerifiedHumanClaim {
            human_id: auth_rec.human_id.clone(),
            kid: auth_rec.kid.clone(),
            role: auth_rec.role.as_str().to_string(),
            claim_id: claim.claim_id.clone(),
            issued_at_ms,
            expires_at_ms,
            kind: claim.kind.as_str().to_string(),
        };

        match claim.kind {
            HumanDropKind::Secret => {
                let secret_audit = HumanDropAudit {
                    payload_digest_input: b"redacted-secret",
                    ..targeted_audit
                };
                let spec = match claim.secret_spec.as_ref() {
                    Some(s) => s,
                    None => {
                        let reason = "secret drop claim missing secretSpec";
                        return self.reject_human_drop(
                            secret_audit,
                            "human.invalid_secret_spec",
                            reason,
                            NodeError::BadRequest,
                        );
                    }
                };
                let secret_name = spec.name.trim();
                if secret_name.is_empty() {
                    let reason = "secret drop name must not be empty";
                    return self.reject_human_drop(
                        secret_audit,
                        "human.invalid_secret_name",
                        reason,
                        NodeError::BadRequest,
                    );
                }
                if is_reserved_drop_secret_name(secret_name) {
                    let reason = format!(
                        "reserved system secret name '{secret_name}' cannot be written via human drop"
                    );
                    return self.reject_human_drop(
                        secret_audit,
                        "human.reserved_secret",
                        reason,
                        NodeError::Unauthorized,
                    );
                }
                if let Err(e) = validate_secret_name(secret_name) {
                    let reason = format!("invalid secret name: {e}");
                    return self.reject_human_drop(
                        secret_audit,
                        "human.invalid_secret_name",
                        reason,
                        NodeError::BadRequest,
                    );
                }

                // H15: Human-signed `spec.overwrite` governs fail-closed; a local
                // `overwrite_secret` flag MUST NEVER override a human's signed `overwrite: false`.
                let _ = overwrite_secret;
                let allow_overwrite = spec.overwrite;
                if !allow_overwrite && self.secrets.get(secret_name).is_ok() {
                    let reason = format!(
                        "secret '{secret_name}' already exists and signed claim specifies overwrite=false"
                    );
                    return self.reject_human_drop(
                        secret_audit,
                        "human.secret_exists",
                        reason,
                        NodeError::Conflict,
                    );
                }

                // Atomically consume single-use claim nonce before writing to SecretStore.
                let fresh = {
                    let db = self.db();
                    db.human().consume_claim_nonce(
                        &claim.claim_id,
                        &auth_rec.kid,
                        HumanClaimKind::Secret,
                        expires_at_ms,
                        now,
                    )?
                };
                if !fresh {
                    let reason = "human drop claim replay detected";
                    return self.reject_human_drop(
                        secret_audit,
                        "human.claim_replay",
                        reason,
                        NodeError::Unauthorized,
                    );
                }

                // Zero-knowledge secret sink: write directly to SecretStore; NEVER persist secret
                // bytes into SQLite (`mailbox`, `gate_audit`, `events`), logs, errors, or replies.
                let secret_val = Zeroizing::new(claim.body.clone());
                self.secrets.set(secret_name, &secret_val)?;

                let auth_json = serde_json::to_string(&verified_claim)?;
                let notice_body = format!(
                    "Secret '{secret_name}' stored in SecretStore by verified human '{}' (key {kid8}). Reference by name only.",
                    auth_rec.human_id
                );

                let (mailbox_receipt, audit_seq) = {
                    let db = self.db();
                    let put_res = db.local().put_in_mailbox(
                        &MailboxInsert {
                            session_id: target_session.clone(),
                            origin_node: self.node_id().to_string(),
                            item_id: format!("human-secret:{}", claim.claim_id),
                            text: notice_body,
                            kind: MailboxKind::Event,
                            source: source.clone(),
                            gate_state: GateState::Pending,
                            gate_reason: None,
                            traceparent: None,
                        },
                        now,
                    )?;
                    let receipt = match put_res {
                        MailboxPutResult::Stored { receipt } => {
                            let _ = db.human().set_mailbox_human_auth(&receipt, &auth_json)?;
                            Some(receipt)
                        }
                        MailboxPutResult::Duplicate | MailboxPutResult::QueueFull => None,
                    };
                    let seq = db.local().append_gate_audit(
                        &GateAuditInput {
                            direction: GateDirection::Inbound,
                            stage: "human_authority".to_string(),
                            decision: StoreGateDecision::Allow,
                            origin_node: Some(self.node_id().to_string()),
                            source: Some(source.clone()),
                            session_id: Some(target_session.clone()),
                            receipt_id: receipt.clone(),
                            event_type: Some(TYPE_HUMAN_SECRET_STORED_V1.to_string()),
                            trust_tier: Some("human-verified".to_string()),
                            confidence: Some(1.0),
                            categories: vec![
                                "gate.allowed".to_string(),
                                "human.verified".to_string(),
                                "human.secret_stored".to_string(),
                            ],
                            reason: None,
                            traceparent: None,
                            payload_sha256: sha256_hex(b"redacted-secret"),
                            reviewer: Some(source),
                        },
                        now,
                    )?;
                    (receipt, seq)
                };

                self.notify_local_session(&target_session);
                self.notify_scheduler();

                Ok(IngestedHumanDrop {
                    claim_id: claim.claim_id.clone(),
                    human_id: auth_rec.human_id,
                    kid: auth_rec.kid,
                    role: auth_rec.role.as_str().to_string(),
                    kind: claim.kind.as_str().to_string(),
                    target_handle,
                    target_session: Some(target_session),
                    secret_name: Some(secret_name.to_string()),
                    mailbox_receipt,
                    audit_seq: Some(audit_seq),
                    downgraded_to_notify: false,
                })
            }
            HumanDropKind::Directive => {
                // Atomically consume single-use claim nonce before routing directive.
                let fresh = {
                    let db = self.db();
                    db.human().consume_claim_nonce(
                        &claim.claim_id,
                        &auth_rec.kid,
                        HumanClaimKind::Directive,
                        expires_at_ms,
                        now,
                    )?
                };
                if !fresh {
                    let reason = "human drop claim replay detected";
                    return self.reject_human_drop(
                        targeted_audit,
                        "human.claim_replay",
                        reason,
                        NodeError::Unauthorized,
                    );
                }

                let body = claim.body.clone();
                let ce = ProtoCloudEvent::new(
                    format!("human-drop:{}", claim.claim_id),
                    source.clone(),
                    TYPE_HUMAN_DROP_V1,
                    json!({
                        "text": body,
                        "humanId": auth_rec.human_id,
                        "kid": auth_rec.kid,
                        "role": auth_rec.role.as_str(),
                        "claimId": claim.claim_id,
                    }),
                );

                if let Some(g) = gate {
                    let ctx = InboundContext {
                        session_id: target_session.clone(),
                        origin_node: self.node_id().to_string(),
                        sender: source,
                        trust_tier: GateTrustTier::HumanVerified,
                        e2ee_verified: true,
                        identity_verified: true,
                        kind: MailboxKind::Message,
                        channel: None,
                        topic: None,
                        bridge: None,
                        event: ce,
                        transfer_paths: Vec::new(),
                        rendered_text: Some(body),
                        human_auth: Some(verified_claim),
                    };
                    let eval = g.evaluate_inbound(&ctx, now).await.map_err(|e| {
                        NodeError::Unauthorized(format!("security gate error: {e}"))
                    })?;
                    match eval.decision {
                        GateDecision::Allow { max_urgency } => {
                            self.notify_local_session(&target_session);
                            self.notify_scheduler();
                            Ok(IngestedHumanDrop {
                                claim_id: claim.claim_id.clone(),
                                human_id: auth_rec.human_id,
                                kid: auth_rec.kid,
                                role: auth_rec.role.as_str().to_string(),
                                kind: claim.kind.as_str().to_string(),
                                target_handle,
                                target_session: Some(target_session),
                                secret_name: None,
                                mailbox_receipt: eval.receipt,
                                audit_seq: eval.audit_seq,
                                downgraded_to_notify: max_urgency == Some(DeliveryUrgency::Notify),
                            })
                        }
                        GateDecision::Hold {
                            reason,
                            retry_after_ms,
                        } => Err(NodeError::RateLimited {
                            detail: reason,
                            retry_after_secs: Some(
                                (retry_after_ms.saturating_add(999) / 1_000).max(1),
                            ),
                        }),
                        GateDecision::Block { reason }
                        | GateDecision::Quarantine { reason, .. } => {
                            Err(NodeError::Unauthorized(reason))
                        }
                    }
                } else {
                    let auth_json = serde_json::to_string(&verified_claim)?;
                    let (mailbox_receipt, audit_seq) = {
                        let db = self.db();
                        let put_res = db.local().put_in_mailbox(
                            &MailboxInsert {
                                session_id: target_session.clone(),
                                origin_node: self.node_id().to_string(),
                                item_id: format!("human-drop:{}", claim.claim_id),
                                text: body.clone(),
                                kind: MailboxKind::Message,
                                source: source.clone(),
                                gate_state: GateState::Pending,
                                gate_reason: None,
                                traceparent: None,
                            },
                            now,
                        )?;
                        let receipt = match put_res {
                            MailboxPutResult::Stored { receipt } => {
                                let _ = db.human().set_mailbox_human_auth(&receipt, &auth_json)?;
                                Some(receipt)
                            }
                            MailboxPutResult::Duplicate => None,
                            MailboxPutResult::QueueFull => {
                                return Err(NodeError::RateLimited {
                                    detail: "local_inbox_full".into(),
                                    retry_after_secs: Some(5),
                                });
                            }
                        };
                        let seq = db.local().append_gate_audit(
                            &GateAuditInput {
                                direction: GateDirection::Inbound,
                                stage: "human_authority".to_string(),
                                decision: StoreGateDecision::Allow,
                                origin_node: Some(self.node_id().to_string()),
                                source: Some(source.clone()),
                                session_id: Some(target_session.clone()),
                                receipt_id: receipt.clone(),
                                event_type: Some(TYPE_HUMAN_DROP_V1.to_string()),
                                trust_tier: Some("human-verified".to_string()),
                                confidence: Some(1.0),
                                categories: vec![
                                    "gate.allowed".to_string(),
                                    "human.verified".to_string(),
                                ],
                                reason: None,
                                traceparent: None,
                                payload_sha256: sha256_hex(body.as_bytes()),
                                reviewer: Some(source),
                            },
                            now,
                        )?;
                        (receipt, seq)
                    };

                    self.notify_local_session(&target_session);
                    self.notify_scheduler();

                    Ok(IngestedHumanDrop {
                        claim_id: claim.claim_id.clone(),
                        human_id: auth_rec.human_id,
                        kid: auth_rec.kid,
                        role: auth_rec.role.as_str().to_string(),
                        kind: claim.kind.as_str().to_string(),
                        target_handle,
                        target_session: Some(target_session),
                        secret_name: None,
                        mailbox_receipt,
                        audit_seq: Some(audit_seq),
                        downgraded_to_notify: false,
                    })
                }
            }
            HumanDropKind::Approval => {
                let approval_source = format!("human:{}:{}", auth_rec.human_id, auth_rec.kid);
                self.record_human_drop_rejected_audit(
                    HumanDropAudit {
                        source: Some(&approval_source),
                        payload_digest_input: claim.claim_id.as_bytes(),
                        ..audit
                    },
                    "human.approval_wrong_entrypoint",
                    "approval drops must be verified by the target ceremony command (not `hyp drop ingest`)",
                );
                Err(NodeError::BadRequest(
                    "approval drops cannot be ingested via `hyp drop ingest`; submit to the currently waiting live ceremony (e.g. `hyp gate apply`)"
                        .to_string(),
                ))
            }
        }
    }

    fn resolve_human_drop_target_session(
        &self,
        target_handle: Option<&str>,
    ) -> Result<String, NodeError> {
        let db = self.db();
        if let Some(handle) = target_handle {
            if let Some(sess) = db.local().session_by_handle(handle)? {
                return Ok(sess.id);
            }
            let handles = db.messages().list_handles(Some(self.node_id().as_str()))?;
            if let Some(rec) = handles.into_iter().find(|h| h.handle == handle) {
                if let Some(sid) = rec.session_id {
                    return Ok(sid);
                }
            }
            if let Some(sess) = db.local().get_session(handle)? {
                return Ok(sess.id);
            }
            return Ok(handle.to_string());
        }
        let sessions = db.local().list_sessions()?;
        if let Some(first) = sessions.first() {
            return Ok(first.id.clone());
        }
        Ok(LOCAL_NODE_ID.to_string())
    }
}
