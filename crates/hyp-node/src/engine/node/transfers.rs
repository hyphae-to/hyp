use std::fs::{self, File};
use std::io::BufReader;
use std::path::PathBuf;
use std::sync::Arc;

use bytes::Bytes;
use serde_json::{Value, json};

use hyp_crypto::rfc3339::{format_rfc3339_millis, parse_rfc3339_millis};
use hyp_crypto::transfer::{
    SignedTransferHeaderV2, StreamEncryptParams, TarInputEntry, TarPackOptions, TarUnpackOptions,
    decrypt_stream_v2, default_stage1_attachment_guard, encrypt_stream_v2, pack_tar_gz,
    unpack_tar_gz,
};
use hyp_proto::address::NodeId;
use hyp_proto::cloudevent::{CloudEvent as ProtoCloudEvent, TYPE_TRANSFER_V1};
use hyp_proto::manifest::CapabilityToken;
use hyp_proto::problem::ProblemDetails;
use hyp_store::{
    AckOutcome, GateAuditInput, GateDecision as StoreGateDecision, GateDirection, MailboxKind,
    PeerStatus, TransferRecord, TransferSubmit, now_ms, sha256_hex, uuid_v4,
};

use crate::engine::config::NodeError;
use crate::engine::peer_link::PeerLink;
use crate::gates::{GateDecision, InboundContext, TrustTier as GateTrustTier};

use super::{AuthenticatedPeer, PeerAction, UnifiedNode};

const DEFAULT_TRANSFER_TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// Result of `UnifiedNode::send_files`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferSendResult {
    pub id: String,
    pub to_node: String,
    pub routed_via: String,
    pub plaintext_digest: String,
    pub ciphertext_digest: String,
    pub ciphertext_bytes: u64,
}

impl UnifiedNode {
    // ========================================================================
    // Streaming File Transfers (`transfer.stream.v2`)
    // ========================================================================

    /// Packs `files` into a safe POSIX `tar.gz`, streams through 64 KiB chunked AES-256-GCM
    /// with HPKE DEK wrapping (`transfer.stream.v2`), and uploads to `target_node` (directly or
    /// via hub) with zero plaintext file bytes ever stored on the hub!
    pub async fn send_files(
        &self,
        target_node: &str,
        to_handle: Option<&str>,
        files: &[TarInputEntry],
        via_hub: Option<&str>,
    ) -> Result<TransferSendResult, NodeError> {
        let _ = NodeId::new(target_node)?;
        let explicit_hub = match via_hub {
            Some(h) => Some(NodeId::new(h)?),
            None => None,
        };
        let outbound_link = self
            .resolve_outbound_link_for_target(target_node, explicit_hub.as_ref())
            .await?;

        let route_peer = if let Some(ref link) = outbound_link {
            let pid = link.peer_id().to_string();
            if !self.peer_supports_cap(&pid, &CapabilityToken::TransferStreamV2, Some(link)) {
                return Err(NodeError::CapabilityUnsupported(Box::new(
                    ProblemDetails::capability_unsupported(
                        &CapabilityToken::TransferStreamV2,
                        &pid,
                        &self.config.hyphae_version,
                        "unknown",
                        Some("2.0.0"),
                        true,
                        None,
                    ),
                )));
            }
            pid
        } else {
            let peer_active = {
                let db = self.db();
                db.peers()
                    .get_peer(target_node)?
                    .is_some_and(|p| p.status == PeerStatus::Active)
            };
            if !peer_active {
                return Err(NodeError::NotFound(format!(
                    "no route to transfer target '{target_node}'"
                )));
            }
            self.config.node_id.to_string()
        };

        let (_, recipient_enc_pk) = self
            .resolve_peer_keys(target_node, outbound_link.as_ref())
            .await?;
        let transfer_id = uuid_v4();
        let now = now_ms();
        let created_at = format_rfc3339_millis(now);
        let expires_at = format_rfc3339_millis(now + DEFAULT_TRANSFER_TTL_MS);

        let stage_dir = self.config.state_dir.join("transfer_stage");
        fs::create_dir_all(&stage_dir)?;
        let tar_path = stage_dir.join(format!("{transfer_id}.tar.gz"));
        let enc_path = stage_dir.join(format!("{transfer_id}.enc"));

        // 1. Pack safe POSIX tar+gzip in O(64 KiB) RAM.
        let pack_res = (|| -> Result<SignedTransferHeaderV2, NodeError> {
            {
                let tar_file = File::create(&tar_path)?;
                let _packed = pack_tar_gz(files, tar_file, TarPackOptions::default())?;
            }
            let tar_reader = BufReader::new(File::open(&tar_path)?);
            let enc_writer = File::create(&enc_path)?;
            let signed_header = encrypt_stream_v2(
                tar_reader,
                enc_writer,
                &StreamEncryptParams {
                    id: &transfer_id,
                    from: self.config.node_id.as_str(),
                    media_type: "application/vnd.hyphae.tar+gzip",
                    created_at: &created_at,
                    expires_at: &expires_at,
                },
                &self.identity.signing,
                &[(target_node, &recipient_enc_pk)],
            )?;
            Ok(signed_header)
        })();
        let _ = fs::remove_file(&tar_path);

        let signed_header = match pack_res {
            Ok(h) => h,
            Err(err) => {
                let _ = fs::remove_file(&enc_path);
                return Err(err);
            }
        };

        let enc_bytes = match fs::read(&enc_path) {
            Ok(b) => {
                let _ = fs::remove_file(&enc_path);
                b
            }
            Err(e) => {
                let _ = fs::remove_file(&enc_path);
                return Err(e.into());
            }
        };

        let decoded_header: hyp_crypto::transfer::TransferStreamHeaderV2 =
            serde_json::from_str(&signed_header.payload)?;
        let header_json = serde_json::to_string(&signed_header)?;
        let sha = sha256_hex(&enc_bytes);

        if let Some(ref link) = outbound_link {
            link.upload_transfer(
                &transfer_id,
                target_node,
                to_handle,
                "transfer.stream.v2",
                &header_json,
                &sha,
                Bytes::from(enc_bytes),
            )
            .await?;
        } else {
            let expires_at_ms = now + DEFAULT_TRANSFER_TTL_MS;
            {
                let db = self.db();
                if let Some(h) = to_handle {
                    let _ = db
                        .local()
                        .set_metadata(&format!("transfer_handle:{transfer_id}"), h);
                }
                db.transfers().submit(
                    &TransferSubmit {
                        id: transfer_id.clone(),
                        from_node: self.config.node_id.to_string(),
                        to_node: target_node.to_string(),
                        transfer_type: "transfer.stream.v2".to_string(),
                        header_json,
                        expected_sha256: Some(sha),
                        expires_at: expires_at_ms,
                    },
                    &enc_bytes,
                    now,
                )?;
            }
            self.notify_peer_inbox(target_node);
            self.notify_scheduler();
        }

        Ok(TransferSendResult {
            id: transfer_id,
            to_node: target_node.to_string(),
            routed_via: route_peer,
            plaintext_digest: decoded_header.plaintext_digest,
            ciphertext_digest: decoded_header.ciphertext_digest,
            ciphertext_bytes: decoded_header.ciphertext_bytes,
        })
    }

    /// Server-side handler for `PUT /v1/transfers/<id>`.
    #[allow(clippy::too_many_arguments)]
    pub async fn handle_server_upload_transfer(
        &self,
        caller: &AuthenticatedPeer,
        id: &str,
        to_node: &str,
        to_handle: Option<&str>,
        transfer_type: &str,
        header_json: &str,
        expected_sha256: Option<String>,
        blob: Bytes,
    ) -> Result<hyp_store::TransferSubmitResult, NodeError> {
        self.require_scope(
            caller,
            caller
                .scopes
                .may_send_files(to_node, Some(blob.len() as u64)),
            &format!("files:send={to_node}"),
        )?;

        let signed_header: SignedTransferHeaderV2 = serde_json::from_str(header_json)?;
        let parsed: hyp_crypto::transfer::TransferStreamHeaderV2 =
            serde_json::from_str(&signed_header.payload)?;
        if parsed.id != id || parsed.from != caller.peer_id {
            return Err(NodeError::BadRequest(
                "transfer header id or from does not match request/caller".into(),
            ));
        }
        let expires_at = parse_rfc3339_millis(&parsed.expires_at)?;
        let now = now_ms();

        // Store optional `to_handle` hint alongside header in metadata so recipient delivers to that handle.
        let submit_res = {
            let db = self.db();
            if let Some(h) = to_handle {
                let _ = db.local().set_metadata(&format!("transfer_handle:{id}"), h);
            }
            db.transfers().submit(
                &TransferSubmit {
                    id: id.to_string(),
                    from_node: caller.peer_id.clone(),
                    to_node: to_node.to_string(),
                    transfer_type: transfer_type.to_string(),
                    header_json: header_json.to_string(),
                    expected_sha256,
                    expires_at,
                },
                &blob,
                now,
            )?
        };

        if to_node == self.config.node_id.as_str() {
            // Direct P2P transfer addressed to THIS node: decrypt & unpack immediately!
            let rec = {
                let db = self.db();
                db.transfers().get(id)?
            };
            if let Some(record) = rec {
                self.decrypt_and_unpack_transfer(
                    self.config.node_id.as_str(),
                    &record,
                    &blob,
                    None,
                )
                .await?;
                let db = self.db();
                let _ = db.transfers().ack(
                    self.config.node_id.as_str(),
                    id,
                    &AckOutcome::Delivered,
                    now_ms(),
                );
            }
        } else {
            self.notify_peer_inbox(to_node);
            self.notify_scheduler();
        }

        Ok(submit_res)
    }

    /// Processes an inbound transfer offer received via SSE `/v1/inbox`, downloading the
    /// encrypted blob, verifying signatures & OCI digests, safely unpacking to local disk,
    /// and writing a path-only reference into the local session mailbox.
    pub async fn handle_inbound_peer_transfer(
        &self,
        origin_node: &str,
        link: &Arc<PeerLink>,
        transfer: TransferRecord,
    ) -> Result<(), NodeError> {
        // P1-6: Verify active peer status & files scope BEFORE downloading the encrypted blob!
        if origin_node != self.config.node_id.as_str() {
            if let Err(err) = self.authorize_peer_action(
                origin_node,
                PeerAction::TransferSend {
                    to_node: self.config.node_id.as_str(),
                    bytes: Some(transfer.size),
                },
            ) {
                self.record_peer_scope_denied_audit(
                    origin_node,
                    TYPE_TRANSFER_V1,
                    &err.to_string(),
                    transfer.id.as_bytes(),
                );
                return Err(err);
            }
        }
        let blob = link.download_transfer(&transfer.id).await?;
        let actual_sha = sha256_hex(&blob);
        if actual_sha != transfer.sha256 {
            return Err(NodeError::BadRequest(
                "downloaded transfer blob sha256 mismatch".into(),
            ));
        }
        let _dest = self
            .decrypt_and_unpack_transfer(origin_node, &transfer, &blob, Some(link))
            .await?;
        Ok(())
    }

    async fn decrypt_and_unpack_transfer(
        &self,
        origin_node: &str,
        transfer: &TransferRecord,
        blob: &[u8],
        origin_link: Option<&Arc<PeerLink>>,
    ) -> Result<PathBuf, NodeError> {
        if transfer.id.is_empty()
            || transfer.id.len() > 128
            || transfer.id == "."
            || transfer.id == ".."
            || !transfer
                .id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            return Err(NodeError::BadRequest(format!(
                "invalid transfer id '{}'",
                transfer.id
            )));
        }

        let signed_header: SignedTransferHeaderV2 = serde_json::from_str(&transfer.header_json)?;
        let (sender_sign_pk, _) = self
            .resolve_peer_keys(&transfer.from_node, origin_link)
            .await?;

        // Always attribute the transfer to the verified `transfer.from_node` (NEVER the relaying
        // hub `origin_node` or `self.node_id`), so downstream Security Gates & allowlists resolve
        // the actual sender's trust tier.
        let _ = origin_node;
        let delivery_origin = transfer.from_node.as_str();

        let sender_trust_tier = if transfer.from_node == self.config.node_id.as_str() {
            GateTrustTier::SelfHost
        } else {
            let db = self.db();
            match db.peers().get_peer(&transfer.from_node)? {
                Some(peer) => GateTrustTier::from(peer.trust_tier),
                None => GateTrustTier::Peer,
            }
        };

        let gate = self.security_gate();

        let stage_dir = self.config.state_dir.join("transfer_stage");
        ensure_private_dir(&stage_dir)?;
        let dec_tar_path = stage_dir.join(format!("{}.dec.tar.gz", transfer.id));

        let received_root = self.config.state_dir.join("received_transfers");
        fs::create_dir_all(&received_root)?;
        let staging_root = received_root.join(".staging");
        ensure_private_dir(&staging_root)?;
        let staged_dir = staging_root.join(&transfer.id);
        if staged_dir.exists() {
            let _ = fs::remove_dir_all(&staged_dir);
        }
        ensure_private_dir(&staged_dir)?;
        let mut staging_guard = StagingCleanupGuard::new(staged_dir.clone());

        let quarantine_root = received_root.join(".quarantine");
        let quarantine_dir = quarantine_root.join(&transfer.id);
        let final_dir = received_root.join(&transfer.id);

        // G9 Stage-Before-Unpack: decrypt & extract strictly into private `0700` `.staging/<id>`
        // with Stage 1 / per-peer attachment allowlist checks BEFORE any file ever touches `final_dir`.
        let unpack_res = (|| -> Result<
            (
                hyp_crypto::transfer::TransferStreamHeaderV2,
                hyp_crypto::transfer::UnpackedTarGz,
            ),
            NodeError,
        > {
            let dec_file = File::create(&dec_tar_path)?;
            let header = decrypt_stream_v2(
                &signed_header,
                blob,
                dec_file,
                &sender_sign_pk,
                self.config.node_id.as_str(),
                &self.identity.encryption,
            )?;
            if header.from != transfer.from_node {
                return Err(NodeError::Unauthorized(format!(
                    "signed transfer header sender '{}' does not match transfer record sender '{}'",
                    header.from, transfer.from_node
                )));
            }
            let reader = BufReader::new(File::open(&dec_tar_path)?);
            let unpacked = if let Some(ref g) = gate {
                let guard = |rel_path: &str| {
                    g.check_transfer_attachment(&transfer.from_node, sender_trust_tier, rel_path)
                };
                let opts = TarUnpackOptions {
                    attachment_guard: Some(&guard),
                    ..TarUnpackOptions::default()
                };
                unpack_tar_gz(reader, &staged_dir, &opts)?
            } else {
                let opts = TarUnpackOptions {
                    attachment_guard: Some(&default_stage1_attachment_guard),
                    ..TarUnpackOptions::default()
                };
                unpack_tar_gz(reader, &staged_dir, &opts)?
            };
            if unpacked.compressed_digest != header.plaintext_digest {
                return Err(NodeError::BadRequest(
                    "unpacked tar.gz OCI digest does not match signed transfer header".into(),
                ));
            }
            Ok((header, unpacked))
        })();
        let _ = fs::remove_file(&dec_tar_path);

        let (header, unpacked) = match unpack_res {
            Ok(pair) => pair,
            Err(err) => {
                drop(staging_guard);
                if gate.is_some() {
                    let blocked_reason = match err {
                        NodeError::Crypto(hyp_crypto::CryptoError::AttachmentBlocked(ref msg))
                        | NodeError::Crypto(hyp_crypto::CryptoError::UnsafeArchiveEntry(ref msg))
                        | NodeError::Crypto(hyp_crypto::CryptoError::ArchiveLimitExceeded(
                            ref msg,
                        )) => Some(msg.clone()),
                        _ => None,
                    };
                    if let Some(msg) = blocked_reason {
                        let db = self.db();
                        let _ = db.local().append_gate_audit(
                            &GateAuditInput {
                                direction: GateDirection::Inbound,
                                stage: "stage1.attachment".to_string(),
                                decision: StoreGateDecision::Block,
                                origin_node: Some(delivery_origin.to_string()),
                                source: Some(transfer.from_node.clone()),
                                session_id: None,
                                receipt_id: None,
                                event_type: Some(TYPE_TRANSFER_V1.to_string()),
                                trust_tier: Some(sender_trust_tier.as_str().to_string()),
                                confidence: Some(1.0),
                                categories: vec![
                                    "gate.blocked".to_string(),
                                    "attachment_blocked".to_string(),
                                ],
                                reason: Some(msg),
                                traceparent: None,
                                payload_sha256: transfer.sha256.clone(),
                                reviewer: None,
                            },
                            now_ms(),
                        );
                    }
                }
                return Err(err);
            }
        };

        // Resolve target handle & local session BEFORE gate evaluation so `gate.evaluate_inbound`
        // records mailbox state (`pending` or `quarantined`) for the right recipient session.
        let (target_handle, target_session_id) = {
            let db = self.db();
            let now = now_ms();
            let hint = db
                .local()
                .get_metadata(&format!("transfer_handle:{}", transfer.id))?;
            let handle = match hint {
                Some(h) => h,
                None => db
                    .messages()
                    .list_handles(Some(self.config.node_id.as_str()))?
                    .into_iter()
                    .next()
                    .map(|h| h.handle)
                    .unwrap_or_else(|| "default".to_string()),
            };
            let sid = match db.local().session_by_handle(&handle)? {
                Some(s) => s.id,
                None => {
                    let sid = format!("handle:{handle}");
                    db.local().register_session(&sid, "{}", now)?;
                    let _ = db.local().set_session_handle(&sid, Some(&handle), now);
                    sid
                }
            };
            (handle, sid)
        };

        let transfer_paths: Vec<String> = unpacked
            .files
            .iter()
            .map(|f| f.archive_path.clone())
            .collect();

        // Build path-only reference pointing at `final_dir` (NEVER raw file bodies!).
        let file_refs: Vec<Value> = unpacked
            .files
            .iter()
            .map(|f| {
                json!({
                    "archivePath": f.archive_path,
                    "diskPath": final_dir.join(&f.archive_path).display().to_string(),
                    "size": f.size,
                    "digest": f.digest,
                })
            })
            .collect();
        let notice_value = json!({
            "transferId": transfer.id,
            "from": transfer.from_node,
            "destDir": final_dir.display().to_string(),
            "plaintextDigest": header.plaintext_digest,
            "files": file_refs,
        });
        let notice = serde_json::to_string(&notice_value)?;

        if let Some(ref g) = gate {
            let mut ce = ProtoCloudEvent::new(
                format!("transfer:{}", transfer.id),
                transfer.from_node.clone(),
                TYPE_TRANSFER_V1,
                notice_value,
            );
            ce.time = Some(format_rfc3339_millis(now_ms()));
            let ctx = InboundContext {
                session_id: target_session_id.clone(),
                origin_node: delivery_origin.to_string(),
                sender: transfer.from_node.clone(),
                trust_tier: sender_trust_tier,
                e2ee_verified: true,
                identity_verified: true,
                kind: MailboxKind::Transfer,
                channel: None,
                topic: None,
                bridge: None,
                event: ce,
                transfer_paths,
                rendered_text: Some(notice.clone()),
                human_auth: None,
            };

            let eval = match g.evaluate_inbound(&ctx, now_ms()).await {
                Ok(ev) => ev,
                Err(err) => {
                    drop(staging_guard);
                    return Err(NodeError::Unauthorized(format!(
                        "transfer security gate error: {err}"
                    )));
                }
            };

            match eval.decision {
                GateDecision::Allow { .. } => {
                    if final_dir.exists() {
                        let _ = fs::remove_dir_all(&final_dir);
                    }
                    fs::rename(&staged_dir, &final_dir)?;
                    staging_guard.disarm();
                    self.notify_local_session(&target_session_id);
                    return Ok(final_dir);
                }
                GateDecision::Quarantine { .. } => {
                    ensure_private_dir(&quarantine_root)?;
                    if quarantine_dir.exists() {
                        let _ = fs::remove_dir_all(&quarantine_dir);
                    }
                    fs::rename(&staged_dir, &quarantine_dir)?;
                    staging_guard.disarm();
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let _ =
                            fs::set_permissions(&quarantine_dir, fs::Permissions::from_mode(0o700));
                    }
                    return Ok(quarantine_dir);
                }
                GateDecision::Block { reason } => {
                    drop(staging_guard);
                    return Err(NodeError::Unauthorized(format!(
                        "transfer blocked by security gate: {reason}"
                    )));
                }
                GateDecision::Hold { reason, .. } => {
                    drop(staging_guard);
                    return Err(NodeError::Conflict(format!(
                        "transfer held by security gate: {reason}"
                    )));
                }
            }
        }

        // No custom SecurityGatePipeline attached: `staged_dir` already passed default Stage 1
        // attachment guard + OCI digest verification; promote atomically to `final_dir`.
        if final_dir.exists() {
            let _ = fs::remove_dir_all(&final_dir);
        }
        fs::rename(&staged_dir, &final_dir)?;
        staging_guard.disarm();

        self.deliver_plaintext_to_local_handle(
            delivery_origin,
            &format!("transfer:{}", transfer.id),
            &target_handle,
            &transfer.from_node,
            &notice,
            MailboxKind::Transfer,
        )?;
        Ok(final_dir)
    }
}

/// RAII cleanup guard ensuring `.staging/<id>` is always removed on error, block, or hold (`G9`).
struct StagingCleanupGuard {
    path: Option<PathBuf>,
}

impl StagingCleanupGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for StagingCleanupGuard {
    fn drop(&mut self) {
        if let Some(ref p) = self.path {
            let _ = fs::remove_dir_all(p);
        }
    }
}

/// Sweeps stale transfer staging leftovers from previous crashes on node startup (`G9`).
pub(super) fn sweep_stale_transfer_staging(state_dir: &std::path::Path) {
    let dirs = [
        state_dir.join("received_transfers").join(".staging"),
        state_dir.join("transfer_stage"),
    ];
    for dir in dirs {
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let _ = fs::remove_dir_all(&path);
                } else {
                    let _ = fs::remove_file(&path);
                }
            }
        }
    }
}

fn ensure_private_dir(path: &std::path::Path) -> Result<(), NodeError> {
    hyp_crypto::keystore::ensure_private_dir(path).map_err(|error| match error {
        hyp_crypto::CryptoError::Io(error) => NodeError::Io(error),
        error => NodeError::Crypto(error),
    })
}
