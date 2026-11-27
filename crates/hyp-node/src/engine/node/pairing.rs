use crate::engine::config::NodeError;
use crate::engine::http_util::{HttpClient, compute_etag, full_body};
use crate::engine::pairing_client::{
    AdminPairReplyError, AdminPairRequestError, AuthClaimHttpError, build_admin_pair_request,
    build_delegated_pair_request, collect_auth_claim_reply, p2p_counter_grant,
};
use crate::engine::peer_link::{
    AuthClaimReply, AuthClaimRequest, DelegatedPairReply, DelegatedPairRequest, GuestPairReply,
    GuestPairRequest, MAX_JSON_RESPONSE_BYTES, P2pPairServerReply, PairBindingV2, PairRequestV2,
    PairServerReply, guest_pair_proof_canonical,
};
use http::{Method, Request};
use hyp_crypto::compat_v1::{
    PairingCodeV1, derive_pairing_key_v1, format_pairing_code_v1, parse_pairing_code_v1,
};
use hyp_crypto::human::{
    DelegatedPairProofV1, NodeCertPayloadV1, decode_hcert1, decode_hjoin1, node_cert_sha256,
    verify_delegated_pair_proof, verify_human_invite, verify_human_invite_claim, verify_node_cert,
};
use hyp_crypto::jcs::to_canonical_json;
use hyp_crypto::manifest::{
    ManifestVerificationError, decode_manifest_payload, verify_manifest_integrity,
};
use hyp_crypto::pairing::{
    AdminInviteV2, GrantV2, P2pOfferToken, P2pPairResponse, create_p2p_confirmation,
    create_p2p_offer, create_p2p_response, decode_am2, decode_hp2p1, encode_am2_with_signed_grant,
    encode_hp2p1, extract_am2_signed_grant, sign_grant_v2, verify_grant_v2, verify_p2p_response,
};
use hyp_crypto::rfc3339::{format_rfc3339_millis, parse_rfc3339_millis};
use hyp_crypto::{
    Ed25519KeyPair, Ed25519PublicKey, OkpJwk as CryptoOkpJwk, SecretStore, SignedPayload,
};
use hyp_proto::address::{LOCAL_NODE_ID, NodeId};
use hyp_proto::manifest::{E2eePolicy, SignedNodeManifest};
use hyp_proto::scopes::{
    ScopePreset, ScopeSet, expand_v2_scopes, matches_node_prefix, validate_delegated_human_scopes,
};
use hyp_store::{
    GrantDirection, GrantInput, GrantRecord, HumanAuthorityInput, HumanAuthorityRole,
    HumanAuthorityStatus, HumanClaimKind, HumanDelegationPolicyInput, HumanNodeCertInput, KeyUse,
    NodeDb, PeerInput, PeerStatus, StoreError, TrustTier, now_ms, uuid_v4,
};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::json;
use std::sync::Arc;
use zeroize::Zeroizing;

use super::{
    AuthenticatedPeer, HTTP_AUTH_SKEW_MS, PeerKeyPersistence, PeerLinkInfo, UnifiedNode,
    expand_node_scopes, p2p_offer_secret_name, persist_peer_key_pair, persist_peer_with_keys,
};

/// Records the single-use claim row for a P2P offer. Its secret belongs in
/// SecretStore and can be stored after releasing the node database guard.
pub fn persist_p2p_offer_sentinel(
    db: &NodeDb,
    offer: &P2pOfferToken,
    issued_at: i64,
    pair_by: i64,
) -> Result<(), NodeError> {
    db.peers().add_grant(
        &GrantInput {
            id: format!("p2p-offer:{}", offer.offer_id),
            peer_id: offer.node_id.clone(),
            direction: GrantDirection::Inbound,
            signed_json: serde_json::to_string(&json!({
                "offerId": offer.offer_id,
                "peerId": offer.peer_id,
            }))?,
            scopes: offer.offered_scopes.clone(),
            trust_tier: TrustTier::Peer,
            issued_at,
            pair_by: Some(pair_by),
            expires_at: None,
        },
        issued_at,
    )?;
    Ok(())
}

/// Saves the private offer in the configured secret backend for daemon or reload use.
pub fn persist_p2p_offer_secret(
    secrets: &SecretStore,
    offer: &P2pOfferToken,
) -> Result<(), NodeError> {
    let name = p2p_offer_secret_name(&offer.offer_id);
    secrets.set(&name, &serde_json::to_string(offer)?)?;
    Ok(())
}

fn verify_pairing_reply_manifest(
    signed: &SignedNodeManifest,
    peer_id: &str,
    signing_pin: Option<&Ed25519PublicKey>,
    encryption_pin: Option<&str>,
) -> Result<Ed25519PublicKey, NodeError> {
    let map_error = |error| match error {
        ManifestVerificationError::Payload(error) => NodeError::Manifest(error),
        ManifestVerificationError::NodeIdMismatch { actual, expected } => NodeError::Unauthorized(
            format!("hub manifest nodeId '{actual}' does not match expected '{expected}'"),
        ),
        ManifestVerificationError::SigningPinMismatch
        | ManifestVerificationError::EncryptionPinMismatch => NodeError::Unauthorized(format!(
            "peer '{peer_id}' manifest key does not match pinned key"
        )),
        ManifestVerificationError::SigningKey(error)
        | ManifestVerificationError::EncryptionKey(error)
        | ManifestVerificationError::Signature(error) => NodeError::Crypto(error),
        error => NodeError::BadRequest(error.to_string()),
    };
    let payload = decode_manifest_payload(signed, Some(peer_id)).map_err(map_error)?;
    let (signing_key, _) = verify_manifest_integrity(signed, &payload, signing_pin, encryption_pin)
        .map_err(map_error)?;
    Ok(signing_key)
}

impl UnifiedNode {
    /// Creates an Org Admin-CA `am2_` invite bundle on this hub, persisting the single-use
    /// signed `GrantV2` in `PeerStore`.
    pub fn create_admin_invite(
        &self,
        admin_key: &Ed25519KeyPair,
        target_node_id: &str,
        scopes: &[&str],
        trust_tier: TrustTier,
        ttl_ms: i64,
    ) -> Result<(String, GrantRecord), NodeError> {
        let _ = NodeId::new(target_node_id)?;
        let expanded = expand_node_scopes(scopes)?;

        let now = now_ms();
        let grant_id = uuid_v4();
        let rng = SystemRandom::new();
        let mut secret = Zeroizing::new([0u8; 20]);
        rng.fill(&mut *secret)
            .map_err(|_| NodeError::Http("CSPRNG failure generating pairing secret".into()))?;
        let pair_kp = derive_pairing_key_v1(&secret, &grant_id)?;

        let tier_str = match trust_tier {
            TrustTier::Org | TrustTier::SelfNode => "org",
            TrustTier::Peer => "peer",
            TrustTier::Guest => "guest",
        };
        let grant = GrantV2 {
            v: 2,
            id: grant_id.clone(),
            node_id: target_node_id.to_string(),
            scopes: expanded.clone(),
            trust_tier: Some(tier_str.to_string()),
            pairing_key: Some(pair_kp.to_jwk()),
            subject_signing_jwk: None,
            subject_encryption_jwk: None,
            issued_at: format_rfc3339_millis(now),
            pair_by: Some(format_rfc3339_millis(now + ttl_ms)),
            expires_at: None,
        };
        let signed = sign_grant_v2(&grant, admin_key)?;
        let signed_json = serde_json::to_string(&signed)?;

        let record = {
            let db = self.db();
            db.peers().add_grant(
                &GrantInput {
                    id: grant_id.clone(),
                    peer_id: target_node_id.to_string(),
                    direction: GrantDirection::Inbound,
                    signed_json,
                    scopes: expanded,
                    trust_tier,
                    issued_at: now,
                    pair_by: Some(now + ttl_ms),
                    expires_at: None,
                },
                now,
            )?
        };

        let pairing_code = format_pairing_code_v1(&PairingCodeV1 {
            grant_id,
            secret,
            admin_fingerprint: admin_key.fingerprint(),
        })?;
        let invite = AdminInviteV2 {
            v: 2,
            router: self.endpoint_url(),
            admin_jwk: admin_key.to_jwk(),
            pairing_code,
            require_e2ee: Some(self.config.e2ee_policy == E2eePolicy::Required),
        };
        let token = encode_am2_with_signed_grant(&invite, &signed)?;
        Ok((token, record))
    }

    /// Server-side handler for `POST /v1/pair` (Org Admin-CA `am2_` single-use binding claim)
    /// when the signed grant is already persisted in Hub SQLite.
    pub fn handle_admin_pair_request(
        &self,
        req: &PairRequestV2,
    ) -> Result<PairServerReply, NodeError> {
        self.handle_admin_pair_request_with_grant(req, None)
    }

    /// Server-side handler for `POST /v1/pair` supporting BOTH:
    /// 1. True Offline Admin-CA pairing: client presents an inline `signed_grant` (`GrantV2`
    ///    signed by the offline Org Admin-CA key), verified purely against `config.admin_jwk`
    ///    and atomically recorded as claimed in `node.sqlite` (`claim_or_insert_grant`) so
    ///    zero Admin-CA private key or pre-inserted DB row is ever required on the Hub.
    /// 2. Legacy / Hub-local DB pairing: `inline_signed_grant` is `None` and the grant row
    ///    already exists in Hub SQLite (`claim_grant`).
    pub fn handle_admin_pair_request_with_grant(
        &self,
        req: &PairRequestV2,
        inline_signed_grant: Option<&SignedPayload>,
    ) -> Result<PairServerReply, NodeError> {
        let admin_proto_jwk = self.config.admin_jwk.as_ref().ok_or_else(|| {
            NodeError::BadRequest("this node has no configured adminJwk for am2_ pairing".into())
        })?;
        let admin_pk = hyp_crypto::OkpJwk::from(admin_proto_jwk).to_ed25519()?;

        let is_revoked = {
            let db = self.db();
            db.peers().is_grant_revoked(&req.grant_id)?
        };
        if is_revoked {
            return Err(NodeError::Unauthorized("grant has been revoked".into()));
        }

        let now = now_ms();
        let (signed_grant, grant, used_inline_grant) = match inline_signed_grant {
            Some(sg) => {
                let verified = verify_grant_v2(sg, &admin_pk).map_err(|e| {
                    NodeError::Unauthorized(format!(
                        "Admin-CA signature verification failed for signedGrant: {e}"
                    ))
                })?;
                if verified.id != req.grant_id {
                    return Err(NodeError::BadRequest(
                        "request grantId does not match signedGrant.id".into(),
                    ));
                }
                (sg.clone(), verified, true)
            }
            None => {
                let grant_rec = {
                    let db = self.db();
                    db.peers().get_grant(&req.grant_id)?
                }
                .ok_or_else(|| {
                    NodeError::NotFound(format!("grant '{}' not found", req.grant_id))
                })?;
                let sg: SignedPayload = serde_json::from_str(&grant_rec.signed_json)?;
                let verified = verify_grant_v2(&sg, &admin_pk).map_err(|e| {
                    NodeError::Unauthorized(format!(
                        "Admin-CA signature verification failed for stored grant: {e}"
                    ))
                })?;
                (sg, verified, false)
            }
        };

        let issued_at_ms = parse_rfc3339_millis(&grant.issued_at)?;
        let pair_by_ms = match grant.pair_by.as_deref() {
            Some(ts) => {
                let ms = parse_rfc3339_millis(ts)?;
                if now >= ms {
                    return Err(NodeError::Store(StoreError::Expired(format!(
                        "grant '{}' pairing window has ended",
                        grant.id
                    ))));
                }
                Some(ms)
            }
            None => None,
        };
        let expires_at_ms = match grant.expires_at.as_deref() {
            Some(ts) => {
                let ms = parse_rfc3339_millis(ts)?;
                if now >= ms {
                    return Err(NodeError::Store(StoreError::Expired(format!(
                        "grant '{}' has expired",
                        grant.id
                    ))));
                }
                Some(ms)
            }
            None => None,
        };

        let expanded_scopes = expand_node_scopes(&grant.scopes)?;

        let pairing_jwk = grant.pairing_key.as_ref().ok_or_else(|| {
            NodeError::BadRequest("grant does not carry a one-time pairingKey".into())
        })?;
        let pairing_pk = pairing_jwk.to_ed25519()?;

        // Verify pairingSig (possession of OOB secret) & selfSig (possession of node signing key).
        pairing_pk
            .verify_domain_b64("binding", req.payload.as_bytes(), &req.pairing_sig)
            .map_err(|_| NodeError::Unauthorized("invalid pairingSig proof".into()))?;
        let binding: PairBindingV2 = serde_json::from_str(&req.payload)?;
        if binding.v != 2 || binding.grant_id != grant.id || binding.node_id != grant.node_id {
            return Err(NodeError::BadRequest(
                "pairing binding grantId or nodeId mismatch".into(),
            ));
        }
        if binding.node_id == self.config.node_id.as_str() || binding.node_id == LOCAL_NODE_ID {
            return Err(NodeError::Conflict(format!(
                "PEER_ID_CONFLICT: peer nodeId '{}' conflicts with local hub identity",
                binding.node_id
            )));
        }
        let client_sign_pk = binding.signing_jwk.to_ed25519()?;
        let client_enc_pk = binding.encryption_jwk.to_x25519()?;
        client_sign_pk
            .verify_domain_b64("binding-self", req.payload.as_bytes(), &req.self_sig)
            .map_err(|_| NodeError::Unauthorized("invalid selfSig proof".into()))?;
        if let Some(ref pinned_subj_sign) = grant.subject_signing_jwk {
            if pinned_subj_sign.to_ed25519()? != client_sign_pk {
                return Err(NodeError::PeerKeyMismatch(
                    "binding signingJwk does not match grant subjectSigningJwk".into(),
                ));
            }
        }
        if let Some(ref pinned_subj_enc) = grant.subject_encryption_jwk {
            if pinned_subj_enc.to_x25519()? != client_enc_pk {
                return Err(NodeError::PeerKeyMismatch(
                    "binding encryptionJwk does not match grant subjectEncryptionJwk".into(),
                ));
            }
        }

        let entry_json = serde_json::to_string(req)?;
        let trust_tier = match grant.trust_tier.as_deref() {
            Some("org") => TrustTier::Org,
            Some("guest") => TrustTier::Guest,
            Some("peer") => TrustTier::Peer,
            _ => TrustTier::Org,
        };
        let signed_grant_json = serde_json::to_string(&signed_grant)?;
        let sign_kid = client_sign_pk.kid();
        let enc_kid = client_enc_pk.kid();

        // Atomically claim (or insert-as-claimed for offline Admin-CA) inside BEGIN IMMEDIATE!
        let keys_rotated = {
            let db = self.db();
            let prev_sign_kid = db
                .peers()
                .list_peer_keys(&binding.node_id, Some(KeyUse::Signing), true)?
                .into_iter()
                .next()
                .map(|k| k.kid);
            let prev_enc_kid = db
                .peers()
                .list_peer_keys(&binding.node_id, Some(KeyUse::Encryption), true)?
                .into_iter()
                .next()
                .map(|k| k.kid);

            if used_inline_grant {
                db.peers().claim_or_insert_grant(
                    &GrantInput {
                        id: grant.id.clone(),
                        peer_id: binding.node_id.clone(),
                        direction: GrantDirection::Inbound,
                        signed_json: signed_grant_json,
                        scopes: expanded_scopes.clone(),
                        trust_tier,
                        issued_at: issued_at_ms,
                        pair_by: pair_by_ms,
                        expires_at: expires_at_ms,
                    },
                    &entry_json,
                    now,
                )?;
            } else {
                db.peers().claim_grant(&grant.id, &entry_json, now)?;
            }
            persist_peer_with_keys(
                &db,
                &PeerInput {
                    peer_id: binding.node_id.clone(),
                    endpoint: None,
                    profile: hyp_store::PeerProfile::Local,
                    trust_tier,
                    status: PeerStatus::Active,
                    scopes: expanded_scopes.clone(),
                    auth_credential_ref: None,
                },
                PeerKeyPersistence::Rotate,
                [
                    (
                        sign_kid.clone(),
                        serde_json::to_string(&binding.signing_jwk),
                    ),
                    (
                        enc_kid.clone(),
                        serde_json::to_string(&binding.encryption_jwk),
                    ),
                ],
                now,
            )?;

            prev_sign_kid.is_some_and(|k| k != sign_kid)
                || prev_enc_kid.is_some_and(|k| k != enc_kid)
        };
        if keys_rotated {
            self.clear_peer_auth_credential(&binding.node_id);
        }

        // N1: Invalidate all previously issued bearer tokens for this peer on pair/re-pair.
        let _ = self.invalidate_peer_bearer_tokens(&binding.node_id)?;
        let auth_credential =
            self.issue_peer_bearer_token(&binding.node_id, Some(&grant.id), Some(&sign_kid))?;
        let caller = AuthenticatedPeer {
            peer_id: binding.node_id,
            scopes: ScopeSet::from_strings(&expanded_scopes),
            trust_tier,
        };
        let (signed_manifest, _, _) = self.build_signed_manifest(Some(&caller))?;

        Ok(PairServerReply {
            node_id: self.config.node_id.to_string(),
            grant: signed_grant,
            auth_credential,
            signed_manifest,
        })
    }

    /// Server-side handler for opt-in self-service `POST /v1/guest/pair` (`guest-ro` confinement).
    ///
    /// Security invariants:
    /// - Returns `404` when `!config.guest_pairing.enabled`.
    /// - Enforces sliding-window `max_joins_per_minute` (`429 rate_limited`).
    /// - Verifies Ed25519 possession proof under domain `"guest-pair"` over canonical RFC 8785 JCS
    ///   with a ±5 minute RFC 3339 timestamp skew bound.
    /// - Anti-hijack fail-closed: refuses (`409 peer_key_mismatch`) to overwrite any already
    ///   registered peer with a different Ed25519 signing key or non-Guest trust tier; re-enrolling
    ///   with the SAME Ed25519 key is idempotent.
    pub fn handle_guest_pair_request(
        &self,
        req: &GuestPairRequest,
    ) -> Result<GuestPairReply, NodeError> {
        if !self.config.guest_pairing.enabled {
            return Err(NodeError::NotFound(
                "guest pairing is disabled on this node".into(),
            ));
        }

        let now = now_ms();
        {
            let mut window = self
                .guest_join_timestamps
                .lock()
                .expect("guest_join_timestamps lock poisoned");
            let cutoff = now.saturating_sub(60_000);
            while window.front().is_some_and(|&ts| ts < cutoff) {
                window.pop_front();
            }
            let limit = self.config.guest_pairing.max_joins_per_minute as usize;
            if limit == 0 || window.len() >= limit {
                return Err(NodeError::RateLimited {
                    detail: format!("guest pairing rate limit exceeded ({limit} requests/minute)"),
                    retry_after_secs: Some(60),
                });
            }
            window.push_back(now);
        }

        if req.node_id == LOCAL_NODE_ID {
            return Err(NodeError::BadRequest(
                "guest nodeId cannot be reserved 'local'".into(),
            ));
        }
        let _ = NodeId::new(&req.node_id)?;
        if req.node_id == self.config.node_id.as_str() {
            return Err(NodeError::BadRequest(
                "guest nodeId cannot equal this hub's own nodeId".into(),
            ));
        }

        let signing_pk = req.ed25519_jwk.to_ed25519()?;
        let enc_pk = req.x25519_jwk.to_x25519()?;

        let ts_ms = parse_rfc3339_millis(&req.timestamp)?;
        if (now - ts_ms).abs() > HTTP_AUTH_SKEW_MS {
            return Err(NodeError::Unauthorized(
                "guest pairing timestamp outside allowed ±5 minute skew window".into(),
            ));
        }

        let canonical = guest_pair_proof_canonical(
            self.config.node_id.as_str(),
            &req.node_id,
            &req.ed25519_jwk,
            &req.x25519_jwk,
            &req.timestamp,
        )?;
        signing_pk
            .verify_domain_b64("guest-pair", canonical.as_bytes(), &req.proof_sig)
            .map_err(|_| NodeError::Unauthorized("invalid guest-pair proofSig".into()))?;

        let raw_scopes = if self.config.guest_pairing.scopes.is_empty() {
            ScopePreset::GuestRo.expand()
        } else {
            self.config.guest_pairing.scopes.clone()
        };
        let guest_scopes = expand_v2_scopes(&raw_scopes)
            .map_err(|e| NodeError::BadRequest(format!("invalid guest pairing scopes: {e}")))?;

        let signing_kid = signing_pk.kid();
        let enc_kid = enc_pk.kid();
        let sign_jwk_json = serde_json::to_string(&req.ed25519_jwk)?;
        let enc_jwk_json = serde_json::to_string(&req.x25519_jwk)?;

        // Anti-hijack check + atomic registration under the NodeDb mutex.
        {
            let db = self.db();
            let existing_peer = db.peers().get_peer(&req.node_id)?;
            let existing_sign_keys =
                db.peers()
                    .list_peer_keys(&req.node_id, Some(KeyUse::Signing), true)?;

            if let Some(peer) = existing_peer {
                if peer.status != PeerStatus::Active {
                    return Err(NodeError::Unauthorized(format!(
                        "peer '{}' is not active (status: {})",
                        req.node_id,
                        peer.status.as_str()
                    )));
                }
                if peer.trust_tier != TrustTier::Guest {
                    return Err(NodeError::PeerKeyMismatch(format!(
                        "peer '{}' is already registered as a non-guest peer",
                        req.node_id
                    )));
                }
                if existing_sign_keys.is_empty() {
                    return Err(NodeError::PeerKeyMismatch(format!(
                        "peer '{}' is already registered without a matching signing key",
                        req.node_id
                    )));
                }
            }

            if !existing_sign_keys.is_empty() {
                let all_match = existing_sign_keys.iter().all(|k| {
                    k.kid == signing_kid
                        && serde_json::from_str::<CryptoOkpJwk>(&k.jwk_json)
                            .ok()
                            .and_then(|j| j.to_ed25519().ok())
                            == Some(signing_pk)
                });
                if !all_match {
                    return Err(NodeError::PeerKeyMismatch(format!(
                        "peer '{}' is already registered with a different Ed25519 signing key",
                        req.node_id
                    )));
                }
            }

            persist_peer_with_keys(
                &db,
                &PeerInput {
                    peer_id: req.node_id.clone(),
                    endpoint: None,
                    profile: hyp_store::PeerProfile::Local,
                    trust_tier: TrustTier::Guest,
                    status: PeerStatus::Active,
                    scopes: guest_scopes.clone(),
                    auth_credential_ref: None,
                },
                PeerKeyPersistence::Upsert,
                [
                    (signing_kid, Ok(sign_jwk_json)),
                    (enc_kid, Ok(enc_jwk_json)),
                ],
                now,
            )?;
        }

        // N1: Invalidate any stale bearer tokens bound to this peer on guest pair/re-pair.
        let _ = self.invalidate_peer_bearer_tokens(&req.node_id)?;

        let caller = AuthenticatedPeer {
            peer_id: req.node_id.clone(),
            scopes: ScopeSet::from_strings(&guest_scopes),
            trust_tier: TrustTier::Guest,
        };
        let (manifest, _, _) = self.build_signed_manifest(Some(&caller))?;

        Ok(GuestPairReply {
            ok: true,
            node_id: self.config.node_id.to_string(),
            peer_id: req.node_id.clone(),
            preset: "guest-ro".to_string(),
            scopes: guest_scopes,
            manifest,
        })
    }

    // ========================================================================
    // Delegated Human-Cert Admission (`POST /v1/auth/claim`, `POST /v1/pair/delegated`, Cascade Revoke)
    // ========================================================================

    /// Server-side handler for `POST /v1/auth/claim` (unauthenticated — authenticated by the
    /// hub's pinned Org Admin-CA Ed25519 signature on `hjoin1_` + the human's Ed25519 `claimSig`).
    ///
    /// Security invariants (fail-closed):
    /// - Verifies `hjoin1_` against `config.admin_jwk`, `hubNodeId == self.node_id`, optional
    ///   `hubFingerprint`, disallowed scopes (`*`, `bridge:post`, `forward:via`), and expiry.
    /// - Verifies `claimSig` over `HumanInviteClaimV1` (±5m replay bound).
    /// - Anti-hijack: refuses (`409 human_key_mismatch`) if `humanId` already exists with a
    ///   different Ed25519 signing key or if the matching authority key was revoked.
    /// - Atomically consumes the single-use `inviteId` nonce in `human_claim_nonces`.
    pub fn handle_auth_claim_request(
        &self,
        req: &AuthClaimRequest,
    ) -> Result<AuthClaimReply, NodeError> {
        if self.db().human().requires_live_approval()? {
            return Err(NodeError::Unauthorized("Live Passkey approval required; use hyp auth admit on this node instead of an offline invite".into()));
        }
        let admin_proto_jwk = self.config.admin_jwk.as_ref().ok_or_else(|| {
            NodeError::BadRequest(
                "this hub has no configured adminJwk for delegated human invite claims".into(),
            )
        })?;
        let admin_pk = hyp_crypto::OkpJwk::from(admin_proto_jwk).to_ed25519()?;
        let now = now_ms();

        let signed_invite = decode_hjoin1(&req.hjoin1)
            .map_err(|e| NodeError::BadRequest(format!("invalid hjoin1_ invite token: {e}")))?;
        let invite = verify_human_invite(&signed_invite, &admin_pk, now).map_err(|e| {
            NodeError::Unauthorized(format!("hjoin1_ invite verification failed: {e}"))
        })?;

        if invite.hub_node_id != self.config.node_id.as_str() {
            return Err(NodeError::Unauthorized(format!(
                "hjoin1_ invite targets hub '{}', not '{}'",
                invite.hub_node_id,
                self.config.node_id.as_str()
            )));
        }
        if let Some(ref pinned_fp) = invite.hub_fingerprint {
            let local_fp = self.identity.signing.public_key().fingerprint();
            if !pinned_fp.eq_ignore_ascii_case(&local_fp) {
                return Err(NodeError::Unauthorized(format!(
                    "hjoin1_ hubFingerprint '{pinned_fp}' does not match this hub's signing key"
                )));
            }
        }

        if req.claim.invite_id != invite.invite_id {
            return Err(NodeError::BadRequest(
                "claim inviteId does not match hjoin1_ inviteId".into(),
            ));
        }
        if req.claim.hub_node_id != invite.hub_node_id {
            return Err(NodeError::BadRequest(
                "claim hubNodeId does not match hjoin1_ hubNodeId".into(),
            ));
        }
        if req.claim.human_id != invite.human_id {
            return Err(NodeError::BadRequest(
                "claim humanId does not match hjoin1_ humanId".into(),
            ));
        }

        let (human_pk, _human_enc_pk) = verify_human_invite_claim(&req.claim, &req.claim_sig, now)
            .map_err(|e| {
                NodeError::Unauthorized(format!("human invite claim signature invalid: {e}"))
            })?;

        let kid = human_pk.kid();
        let fingerprint = human_pk.fingerprint();
        let jwk_json = to_canonical_json(&req.claim.signing_jwk)?;
        let enc_jwk_json = match &req.claim.enc_jwk {
            Some(jwk) => Some(to_canonical_json(jwk)?),
            None => None,
        };
        let label = req
            .label
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control))
            .unwrap_or("passkey-delegated")
            .to_string();
        let invite_expires_ms = parse_rfc3339_millis(&invite.expires_at)?;
        let validated_scopes = validate_delegated_human_scopes(&invite.scopes)
            .map_err(|e| NodeError::BadRequest(format!("invalid delegated invite scopes: {e}")))?;

        {
            let db = self.db();

            // Anti-hijack fail-closed: refuse enrolling a different key or resurrecting a revoked key.
            let existing_for_human = db
                .human()
                .list_authorities_for_human(&invite.human_id, true)?;
            for existing in &existing_for_human {
                if existing.kid != kid {
                    return Err(NodeError::HumanKeyMismatch(format!(
                        "human '{}' is already enrolled with a different signing key (kid '{}')",
                        invite.human_id, existing.kid
                    )));
                }
                if existing.status == HumanAuthorityStatus::Revoked {
                    return Err(NodeError::HumanKeyMismatch(format!(
                        "human '{}' key '{}' has been revoked and cannot be re-claimed",
                        invite.human_id, existing.kid
                    )));
                }
                if existing.jwk_json != jwk_json {
                    return Err(NodeError::HumanKeyMismatch(format!(
                        "human '{}' key '{}' JWK mismatch",
                        invite.human_id, existing.kid
                    )));
                }
            }
            // Also verify `kid` is not already claimed by a different `human_id`.
            if let Some(other_owner) = db.human().get_active_authority_by_kid(&kid)? {
                if other_owner.human_id != invite.human_id {
                    return Err(NodeError::HumanKeyMismatch(format!(
                        "signing key kid '{kid}' is already enrolled under human '{}'",
                        other_owner.human_id
                    )));
                }
            }

            // Atomically consume single-use inviteId nonce (fail closed on replay!).
            let fresh = db.human().consume_claim_nonce(
                &invite.invite_id,
                &admin_pk.kid(),
                HumanClaimKind::HumanInvite,
                invite_expires_ms,
                now,
            )?;
            if !fresh {
                return Err(NodeError::Conflict(format!(
                    "human invite '{}' has already been claimed (replay rejected)",
                    invite.invite_id
                )));
            }

            let min_epoch = db.human().min_auth_epoch()?;
            let auth_epoch = existing_for_human
                .first()
                .map(|r| r.auth_epoch.max(min_epoch))
                .unwrap_or(min_epoch);

            db.human()
                .bootstrap_authority(
                    &HumanAuthorityInput {
                        human_id: invite.human_id.clone(),
                        kid: kid.clone(),
                        label,
                        role: HumanAuthorityRole::Signer,
                        jwk_json,
                        enc_jwk_json,
                        prf_salt: req.claim.prf_salt.clone(),
                        auth_epoch,
                    },
                    now,
                )
                .map_err(|e| match e {
                    StoreError::IdConflict(msg) => NodeError::HumanKeyMismatch(msg),
                    other => NodeError::Store(other),
                })?;

            db.human().upsert_delegation_policy(
                &HumanDelegationPolicyInput {
                    human_id: invite.human_id.clone(),
                    node_prefix: invite.node_prefix.clone(),
                    scopes: validated_scopes.clone(),
                    max_devices: invite.max_devices,
                    delegation_enabled: true,
                },
                now,
            )?;
        }

        Ok(AuthClaimReply {
            ok: true,
            hub_node_id: self.config.node_id.to_string(),
            human_id: invite.human_id,
            kid,
            fingerprint,
            node_prefix: invite.node_prefix,
            scopes: validated_scopes,
            max_devices: invite.max_devices,
        })
    }

    /// Server-side handler for `POST /v1/pair/delegated` (unauthenticated — authenticated by a
    /// human-signed `hcert1_` NodeCert from an active enrolled authority with `delegation_enabled`
    /// plus a live device Ed25519 possession proof `proofSig`).
    ///
    /// Security invariants (fail-closed):
    /// - Authority MUST be `Active` and have `delegation_enabled == true`.
    /// - Enforces `cert.auth_epoch >= max(min_auth_epoch, authority.auth_epoch)` and cert expiry.
    /// - Enforces `cert.node_id == req.node_id`, `matches_node_prefix(policy.node_prefix, req.node_id)`,
    ///   and exact JWK equality between `cert` and `req`.
    /// - Verifies live `DelegatedPairProofV1` Ed25519 signature (±5m skew) bound to `SHA-256(hcert1)`.
    /// - Anti-hijack: refuses (`409 peer_key_mismatch`) to overwrite any peer with a different
    ///   Ed25519 key or admitted under a different authority / non-delegated grant.
    /// - Enforces `policy.max_devices` across active peers admitted under `human_id` (counting
    ///   idempotent re-pair of the same `node_id` as 0 new devices).
    pub fn handle_delegated_pair_request(
        &self,
        req: &DelegatedPairRequest,
    ) -> Result<DelegatedPairReply, NodeError> {
        if req.node_id == LOCAL_NODE_ID {
            return Err(NodeError::BadRequest(
                "nodeId cannot be reserved 'local'".into(),
            ));
        }
        let _ = NodeId::new(&req.node_id)?;
        if req.node_id == self.config.node_id.as_str() {
            return Err(NodeError::Conflict(format!(
                "PEER_ID_CONFLICT: peer nodeId '{}' conflicts with local hub identity",
                req.node_id
            )));
        }

        let device_sign_pk = req.ed25519_jwk.to_ed25519()?;
        let device_enc_pk = req.x25519_jwk.to_x25519()?;
        let now = now_ms();

        let signed_cert = decode_hcert1(&req.node_cert)
            .map_err(|e| NodeError::BadRequest(format!("invalid hcert1_ nodeCert: {e}")))?;
        let unverified_cert: NodeCertPayloadV1 = serde_json::from_str(&signed_cert.payload)
            .map_err(|e| NodeError::BadRequest(format!("malformed nodeCert payload: {e}")))?;

        let (authority, policy, min_auth_epoch) = {
            let db = self.db();
            let auth = db
                .human()
                .get_active_authority_by_human_and_kid(
                    &unverified_cert.human_id,
                    &unverified_cert.human_kid,
                )?
                .ok_or_else(|| {
                    NodeError::Unauthorized(format!(
                        "human authority '{}' kid '{}' is unknown or revoked",
                        unverified_cert.human_id, unverified_cert.human_kid
                    ))
                })?;
            let pol = db
                .human()
                .get_delegation_policy(&auth.human_id)?
                .filter(|p| p.delegation_enabled)
                .ok_or_else(|| {
                    NodeError::Unauthorized(format!(
                        "delegated admission is disabled for human '{}'",
                        auth.human_id
                    ))
                })?;
            let min_ep = db.human().min_auth_epoch()?;
            (auth, pol, min_ep)
        };

        let authority_jwk: CryptoOkpJwk = serde_json::from_str(&authority.jwk_json)?;
        let authority_pk = authority_jwk.to_ed25519()?;
        let required_epoch = min_auth_epoch.max(authority.auth_epoch);

        let cert = verify_node_cert(&signed_cert, &authority_pk, now, required_epoch)
            .map_err(|e| NodeError::Unauthorized(format!("hcert1_ verification failed: {e}")))?;

        if cert.human_id != authority.human_id {
            return Err(NodeError::Unauthorized(
                "nodeCert humanId mismatch against enrolled authority".into(),
            ));
        }
        if cert.node_id != req.node_id {
            return Err(NodeError::Unauthorized(format!(
                "nodeCert nodeId '{}' does not match request nodeId '{}'",
                cert.node_id, req.node_id
            )));
        }
        if !matches_node_prefix(&policy.node_prefix, &req.node_id) {
            return Err(NodeError::Unauthorized(format!(
                "nodeId '{}' is outside allowed nodePrefix '{}' for human '{}'",
                req.node_id, policy.node_prefix, authority.human_id
            )));
        }
        if cert.signing_jwk.to_ed25519()? != device_sign_pk {
            return Err(NodeError::PeerKeyMismatch(
                "nodeCert signingJwk does not match request ed25519Jwk".into(),
            ));
        }
        if cert.encryption_jwk.to_x25519()? != device_enc_pk {
            return Err(NodeError::PeerKeyMismatch(
                "nodeCert encryptionJwk does not match request x25519Jwk".into(),
            ));
        }

        // Verify live device Ed25519 possession proof bound to this hub and SHA-256(hcert1_).
        let proof = DelegatedPairProofV1 {
            hub_node_id: self.config.node_id.to_string(),
            node_id: req.node_id.clone(),
            ed25519_jwk: req.ed25519_jwk.clone(),
            x25519_jwk: req.x25519_jwk.clone(),
            node_cert_sha256: node_cert_sha256(&req.node_cert),
            timestamp: req.timestamp.clone(),
        };
        let _ = verify_delegated_pair_proof(&proof, &req.proof_sig, now).map_err(|e| {
            NodeError::Unauthorized(format!("delegated pair proofSig invalid: {e}"))
        })?;

        // Defense-in-depth: validate policy scopes fail-closed before issuing any grant.
        let granted_scopes = validate_delegated_human_scopes(&policy.scopes).map_err(|e| {
            NodeError::Unauthorized(format!("delegation policy scopes invalid: {e}"))
        })?;

        let sign_kid = device_sign_pk.kid();
        let enc_kid = device_enc_pk.kid();
        let sign_jwk_json = to_canonical_json(&req.ed25519_jwk)?;
        let enc_jwk_json = to_canonical_json(&req.x25519_jwk)?;
        let cert_issued_ms = parse_rfc3339_millis(&cert.issued_at)?;
        let cert_expires_ms = parse_rfc3339_millis(&cert.expires_at)?;
        let signed_cert_json = to_canonical_json(&signed_cert)?;

        let keys_rotated = {
            let db = self.db();

            // Re-check authority & policy inside the DB lock to prevent TOCTOU race with revocation.
            let live_auth = db
                .human()
                .get_active_authority_by_human_and_kid(&authority.human_id, &authority.kid)?;
            let live_pol = db.human().get_delegation_policy(&authority.human_id)?;
            if live_auth.is_none() || !live_pol.as_ref().is_some_and(|p| p.delegation_enabled) {
                return Err(NodeError::Unauthorized(format!(
                    "human authority '{}' was revoked or delegation disabled",
                    authority.human_id
                )));
            }

            // Anti-hijack fail-closed check against existing peer state.
            let existing_peer = db.peers().get_peer(&req.node_id)?;
            let existing_sign_keys =
                db.peers()
                    .list_peer_keys(&req.node_id, Some(KeyUse::Signing), true)?;
            let prev_enc_kid = db
                .peers()
                .list_peer_keys(&req.node_id, Some(KeyUse::Encryption), true)?
                .into_iter()
                .next()
                .map(|k| k.kid);

            if let Some(ref peer) = existing_peer {
                if peer.status != PeerStatus::Active {
                    return Err(NodeError::Unauthorized(format!(
                        "peer '{}' is revoked or inactive and cannot re-pair",
                        req.node_id
                    )));
                }
                if peer.admitted_by_human_id.as_deref() != Some(authority.human_id.as_str()) {
                    return Err(NodeError::PeerKeyMismatch(format!(
                        "peer '{}' is already registered under a different authority or grant",
                        req.node_id
                    )));
                }
            }
            if !existing_sign_keys.is_empty() {
                let all_match = existing_sign_keys.iter().all(|k| {
                    k.kid == sign_kid
                        && serde_json::from_str::<CryptoOkpJwk>(&k.jwk_json)
                            .ok()
                            .and_then(|j| j.to_ed25519().ok())
                            == Some(device_sign_pk)
                });
                if !all_match {
                    return Err(NodeError::PeerKeyMismatch(format!(
                        "peer '{}' is already registered with a different Ed25519 signing key",
                        req.node_id
                    )));
                }
            }

            // Enforce `max_devices` cap (idempotent re-pair of same `node_id` counts as 0 new devices).
            let other_active = db
                .peers()
                .count_active_peers_admitted_by_human(&authority.human_id, Some(&req.node_id))?;
            if other_active >= policy.max_devices {
                return Err(NodeError::Store(StoreError::QuotaExceeded(format!(
                    "human '{}' reached delegated maxDevices limit ({})",
                    authority.human_id, policy.max_devices
                ))));
            }

            db.human().put_node_cert(&HumanNodeCertInput {
                node_id: req.node_id.clone(),
                human_kid: cert.human_kid.clone(),
                auth_epoch: cert.auth_epoch,
                signed_json: signed_cert_json,
                issued_at: cert_issued_ms,
                expires_at: cert_expires_ms,
            })?;

            db.peers().upsert_peer_with_admission(
                &PeerInput {
                    peer_id: req.node_id.clone(),
                    endpoint: None,
                    profile: hyp_store::PeerProfile::Local,
                    trust_tier: TrustTier::Org,
                    status: PeerStatus::Active,
                    scopes: granted_scopes.clone(),
                    auth_credential_ref: None,
                },
                Some(&authority.human_id),
                Some(cert.auth_epoch),
                now,
            )?;

            persist_peer_key_pair(
                &db,
                &req.node_id,
                PeerKeyPersistence::Rotate,
                [
                    (sign_kid.clone(), Ok(sign_jwk_json)),
                    (enc_kid.clone(), Ok(enc_jwk_json)),
                ],
                now,
            )?;

            existing_sign_keys.iter().any(|k| k.kid != sign_kid)
                || prev_enc_kid.is_some_and(|k| k != enc_kid)
        };

        if keys_rotated {
            self.clear_peer_auth_credential(&req.node_id);
        }

        // Invalidate stale bearer tokens and issue a fresh bearer credential.
        let _ = self.invalidate_peer_bearer_tokens(&req.node_id)?;
        let auth_credential = self.issue_peer_bearer_token(&req.node_id, None, Some(&sign_kid))?;

        let caller = AuthenticatedPeer {
            peer_id: req.node_id.clone(),
            scopes: ScopeSet::from_strings(&granted_scopes),
            trust_tier: TrustTier::Org,
        };
        let (signed_manifest, _, _) = self.build_signed_manifest(Some(&caller))?;

        Ok(DelegatedPairReply {
            ok: true,
            node_id: self.config.node_id.to_string(),
            peer_id: req.node_id.clone(),
            human_id: authority.human_id,
            auth_epoch: cert.auth_epoch,
            scopes: granted_scopes,
            auth_credential,
            signed_manifest,
        })
    }

    /// Cascade-revokes a `HumanAuthority` (a specific `kid` or all active keys for `human_id`),
    /// disables its delegation policy, marks every peer with `admitted_by_human_id == human_id` as
    /// `PeerStatus::Revoked`, invalidates all their bearer tokens, disconnects outbound links, and
    /// immediately wakes & drops all live inbound SSE `/v1/inbox` streams.
    ///
    /// Returns `(effective_min_auth_epoch, revoked_peer_ids)`.
    pub async fn revoke_human_authority_cascade(
        &self,
        human_id: &str,
        kid: Option<&str>,
        bump_epoch: bool,
        revocation_json: &str,
    ) -> Result<(u64, Vec<String>), NodeError> {
        if self.db().human().requires_live_approval()? {
            return Err(NodeError::Unauthorized(
                "Live Passkey approval required; use hyp auth revoke --cascade".into(),
            ));
        }
        let now = now_ms();
        let (effective_min, revoked_peers) = {
            let db = self.db();
            let current_min = db.human().min_auth_epoch()?;
            let target_min = if bump_epoch {
                current_min.saturating_add(1)
            } else {
                current_min
            };

            let target_kids: Vec<String> = if let Some(k) = kid {
                vec![k.to_string()]
            } else {
                let auths = db.human().list_authorities_for_human(human_id, true)?;
                if auths.is_empty() {
                    return Err(NodeError::NotFound(format!(
                        "human authority '{human_id}' not found"
                    )));
                }
                auths.into_iter().map(|a| a.kid).collect()
            };

            let mut eff_min = current_min;
            for target_kid in &target_kids {
                eff_min = db.human().revoke_authority_monotonic(
                    human_id,
                    target_kid,
                    target_min,
                    revocation_json,
                    now,
                )?;
            }

            let _ = db.human().set_delegation_enabled(human_id, false, now)?;
            let peers = db.peers().revoke_peers_admitted_by_human(human_id, now)?;
            (eff_min, peers)
        };

        for pid in &revoked_peers {
            let _ = self.invalidate_peer_bearer_tokens(pid);
            self.clear_peer_auth_credential(pid);
            let _ = self.disconnect_peer(pid).await;
            self.notify_peer_inbox(pid);
        }
        if !revoked_peers.is_empty() {
            self.notify_all_inbox_subscribers();
        }

        Ok((effective_min, revoked_peers))
    }

    /// Client-side helper calling `POST <hub_endpoint>/v1/auth/claim`.
    pub async fn claim_human_invite_on_hub(
        &self,
        hub_endpoint: &str,
        req: &AuthClaimRequest,
    ) -> Result<AuthClaimReply, NodeError> {
        let url = format!("{}/v1/auth/claim", hub_endpoint.trim_end_matches('/'));
        let http_req = Request::builder()
            .method(Method::POST)
            .uri(&url)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(full_body(serde_json::to_vec(req)?))
            .map_err(|e| NodeError::Http(e.to_string()))?;
        let (status, body) = collect_auth_claim_reply(
            self.http_client.request(http_req),
            None,
            MAX_JSON_RESPONSE_BYTES,
        )
        .await
        .map_err(|error| match error {
            AuthClaimHttpError::Request(error) | AuthClaimHttpError::Body(error) => error,
            AuthClaimHttpError::Timeout => NodeError::Http("claim request timed out".into()),
        })?;
        if !status.is_success() {
            return Err(HttpClient::decode_error_response(status, &body));
        }
        Ok(serde_json::from_slice(&body)?)
    }

    /// Client-side delegated pairing: signs a live `DelegatedPairProofV1` bound to `hcert1`, calls
    /// `POST <hub_endpoint>/v1/pair/delegated`, verifies & caches the hub's signed manifest, pins
    /// its keys, stores `authCredential` in `SecretStore`, and activates the live `PeerLink` + SSE!
    pub async fn pair_delegated_with_hub(
        self: &Arc<Self>,
        hub_endpoint: &str,
        hub_node_id: &str,
        hcert1: &str,
        expected_hub_fingerprint: Option<&str>,
    ) -> Result<(DelegatedPairReply, PeerLinkInfo), NodeError> {
        let req = build_delegated_pair_request(
            hub_node_id,
            self.config.node_id.as_str(),
            &self.identity,
            hcert1,
            || format_rfc3339_millis(now_ms()),
        )?;

        let base = hub_endpoint.trim_end_matches('/');
        let url = format!("{base}/v1/pair/delegated");
        let http_req = Request::builder()
            .method(Method::POST)
            .uri(&url)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(full_body(serde_json::to_vec(&req)?))
            .map_err(|e| NodeError::Http(e.to_string()))?;
        let resp = self.http_client.request(http_req).await?;
        let (status, _headers, body) = HttpClient::collect(resp, MAX_JSON_RESPONSE_BYTES).await?;
        if !status.is_success() {
            return Err(HttpClient::decode_error_response(status, &body));
        }
        let reply: DelegatedPairReply = serde_json::from_slice(&body)?;
        if reply.node_id != hub_node_id {
            return Err(NodeError::Unauthorized(format!(
                "hub returned unexpected nodeId '{}' (expected '{hub_node_id}')",
                reply.node_id
            )));
        }

        // Verify the signed identity before persisting credentials or peer state.
        let hub_pk =
            verify_pairing_reply_manifest(&reply.signed_manifest, hub_node_id, None, None)?;
        if let Some(expected_fp) = expected_hub_fingerprint {
            let actual_fp = hub_pk.fingerprint();
            if !expected_fp.eq_ignore_ascii_case(&actual_fp) {
                return Err(NodeError::Unauthorized(format!(
                    "hub signing key fingerprint '{actual_fp}' does not match pinned '{expected_fp}'"
                )));
            }
        }

        let cred_ref = self.save_peer_auth_credential(&reply.node_id, &reply.auth_credential)?;
        let now = now_ms();
        {
            let db = self.db();
            db.peers().upsert_peer(
                &PeerInput {
                    peer_id: reply.node_id.clone(),
                    endpoint: Some(base.to_string()),
                    profile: hyp_store::PeerProfile::Router,
                    trust_tier: TrustTier::Org,
                    status: PeerStatus::Active,
                    scopes: reply.scopes.clone(),
                    auth_credential_ref: Some(cred_ref),
                },
                now,
            )?;
        }

        let etag = compute_etag(&serde_json::to_vec(&reply.signed_manifest)?);
        let negotiated = self.verify_and_cache_peer_manifest(
            &reply.node_id,
            &reply.signed_manifest,
            Some(etag),
            false,
        )?;

        self.activate_peer_link(&reply.node_id, base, negotiated.clone())
            .await?;

        let info = PeerLinkInfo {
            peer_id: reply.node_id.clone(),
            endpoint: base.to_string(),
            negotiated,
        };
        Ok((reply, info))
    }

    /// Client-side Org Admin-CA (`am2_`) onboarding: decodes `am2_`, proves possession over
    /// `POST /v1/pair`, verifies the hub's signed manifest, pins JWKs, stores `authCredential`
    /// in `SecretStore`, activates `PeerLink` + background SSE `/v1/inbox`, and syncs handles!
    pub async fn accept_am2_invite(
        self: &Arc<Self>,
        am2_token: &str,
    ) -> Result<PeerLinkInfo, NodeError> {
        let invite = decode_am2(am2_token)?;
        let inline_signed_grant = extract_am2_signed_grant(am2_token)?;
        let parsed_code = parse_pairing_code_v1(&invite.pairing_code)?;
        let request_bytes = build_admin_pair_request(
            &parsed_code,
            self.config.node_id.as_str(),
            &self.identity,
            inline_signed_grant.as_ref(),
            || format_rfc3339_millis(now_ms()),
        )
        .map_err(|error| match error {
            AdminPairRequestError::PairingKey(error)
            | AdminPairRequestError::Canonicalization(error) => NodeError::Crypto(error),
            AdminPairRequestError::Serialization(error) => NodeError::from(error),
        })?;
        let http_req = Request::builder()
            .method(Method::POST)
            .uri("/v1/pair")
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(full_body(request_bytes))
            .map_err(|e| NodeError::Http(e.to_string()))?;
        let resp = self
            .http_client
            .request_for_endpoint(&invite.router, http_req)
            .await?;
        let (status, _headers, body) = HttpClient::collect(resp, MAX_JSON_RESPONSE_BYTES).await?;
        if !status.is_success() {
            return Err(HttpClient::decode_error_response(status, &body));
        }
        let reply: PairServerReply = serde_json::from_slice(&body)?;

        // Verify the returned grant against the out-of-band pinned adminJwk from `am2_`.
        let admin_pk = invite.admin_jwk.to_ed25519()?;
        let verified_grant = reply
            .verify_grant(&admin_pk, self.config.node_id.as_str())
            .map_err(|error| match error {
                AdminPairReplyError::Signature(error) => NodeError::Crypto(error),
                AdminPairReplyError::WrongNode(_) => {
                    NodeError::Unauthorized("hub returned grant for wrong nodeId".into())
                }
            })?;

        let pinned_hub_signing = self.lookup_peer_signing_key(&reply.node_id)?;
        verify_pairing_reply_manifest(
            &reply.signed_manifest,
            &reply.node_id,
            pinned_hub_signing.as_ref(),
            None,
        )?;

        // Persist authCredential in SecretStore (never plaintext in SQLite!).
        let cred_ref = self.save_peer_auth_credential(&reply.node_id, &reply.auth_credential)?;
        let now = now_ms();
        {
            let db = self.db();
            db.peers().upsert_peer(
                &PeerInput {
                    peer_id: reply.node_id.clone(),
                    endpoint: Some(invite.router.clone()),
                    profile: hyp_store::PeerProfile::Router,
                    trust_tier: TrustTier::Org,
                    status: PeerStatus::Active,
                    scopes: verified_grant.scopes.clone(),
                    auth_credential_ref: Some(cred_ref),
                },
                now,
            )?;
            let _ = db.peers().add_grant(
                &GrantInput {
                    id: verified_grant.id.clone(),
                    peer_id: reply.node_id.clone(),
                    direction: GrantDirection::Outbound,
                    signed_json: serde_json::to_string(&reply.grant)?,
                    scopes: verified_grant.scopes.clone(),
                    trust_tier: TrustTier::Org,
                    issued_at: now,
                    pair_by: None,
                    expires_at: None,
                },
                now,
            );
        }

        let etag = compute_etag(&serde_json::to_vec(&reply.signed_manifest)?);
        let negotiated = self.verify_and_cache_peer_manifest(
            &reply.node_id,
            &reply.signed_manifest,
            Some(etag),
            false,
        )?;

        self.activate_peer_link(&reply.node_id, &invite.router, negotiated.clone())
            .await?;

        Ok(PeerLinkInfo {
            peer_id: reply.node_id,
            endpoint: invite.router,
            negotiated,
        })
    }

    /// Creates a Direct P2P mutual pairing invite (`hp2p1_` token) carrying this node's
    /// zero-TOFU OKP JWKs and a CSPRNG 160-bit pairing secret (§4.3).
    pub fn create_p2p_invite(
        &self,
        offered_scopes: Vec<String>,
        requested_scopes: Vec<String>,
        ttl_ms: i64,
    ) -> Result<(String, P2pOfferToken), NodeError> {
        self.create_p2p_invite_for_peer(None, offered_scopes, requested_scopes, ttl_ms)
    }

    /// Creates a Direct P2P mutual pairing invite (`hp2p1_` token) optionally bound to a
    /// specific `target_peer_id` (required for idempotent re-pair with an already paired P2P peer).
    pub fn create_p2p_invite_for_peer(
        &self,
        target_peer_id: Option<&str>,
        offered_scopes: Vec<String>,
        requested_scopes: Vec<String>,
        ttl_ms: i64,
    ) -> Result<(String, P2pOfferToken), NodeError> {
        if let Some(pid) = target_peer_id {
            if pid == LOCAL_NODE_ID || pid == self.config.node_id.as_str() {
                return Err(NodeError::BadRequest(format!(
                    "target peer_id '{pid}' cannot be 'local' or self node_id"
                )));
            }
            let _ = NodeId::new(pid)?;
        }
        let expanded_offered = expand_node_scopes(&offered_scopes)?;
        let expanded_requested = if requested_scopes.is_empty() {
            Vec::new()
        } else {
            expand_node_scopes(&requested_scopes)?
        };

        let now = now_ms();
        let offer_id = uuid_v4();
        let expires_at = format_rfc3339_millis(now + ttl_ms);
        let mut offer = create_p2p_offer(
            &offer_id,
            self.config.node_id.as_str(),
            &self.endpoint_url(),
            &self.identity,
            expanded_offered.clone(),
            expanded_requested,
            &expires_at,
        )?;
        offer.peer_id = target_peer_id.map(ToOwned::to_owned);

        persist_p2p_offer_sentinel(&self.db(), &offer, now, now + ttl_ms)?;
        persist_p2p_offer_secret(&self.secrets, &offer)?;

        self.pending_p2p_offers
            .lock()
            .expect("pending_p2p_offers lock poisoned")
            .insert(offer_id, offer.clone());

        let token = encode_hp2p1(&offer)?;
        Ok((token, offer))
    }

    /// Server-side handler for `POST /v1/p2p/pair/<offerId>`: verifies 160-bit HKDF binding MAC,
    /// Bob's Ed25519 self-sig, Bob's signed grant, anti-takeover peer-id & key-pin checks,
    /// atomically claims the single-use offer, pins Bob's OKP JWKs, mints Bob's `authCredential`,
    /// and returns Alice's signed grant + manifest.
    pub fn handle_p2p_pair_request(
        &self,
        offer_id: &str,
        response: &P2pPairResponse,
    ) -> Result<P2pPairServerReply, NodeError> {
        let offer_secret_key = p2p_offer_secret_name(offer_id);
        let offer = match self
            .pending_p2p_offers
            .lock()
            .expect("pending_p2p_offers lock poisoned")
            .get(offer_id)
            .cloned()
        {
            Some(found) => found,
            None => {
                // Fall back to SecretStore for offers created out-of-process (`hyp pair invite`)
                // or prior to a daemon restart.
                let raw = match self.secrets.get(&offer_secret_key) {
                    Ok(v) => v,
                    Err(hyp_crypto::CryptoError::SecretNotFound(_)) => {
                        return Err(NodeError::NotFound(format!(
                            "P2P pairing offer '{offer_id}' not found"
                        )));
                    }
                    Err(e) => return Err(NodeError::Crypto(e)),
                };
                let parsed: P2pOfferToken = serde_json::from_str(&raw).map_err(|e| {
                    NodeError::BadRequest(format!("corrupt persisted P2P offer: {e}"))
                })?;
                if parsed.offer_id != offer_id {
                    return Err(NodeError::NotFound(format!(
                        "P2P pairing offer '{offer_id}' not found"
                    )));
                }
                parsed
            }
        };

        let now = now_ms();
        let verified = verify_p2p_response(&offer, response, now)?;

        // P1-1 anti-takeover check #1 (BEFORE claiming or upserting):
        // Refuse claiming our own node_id or reserved 'local'.
        if verified.bob_node_id == self.config.node_id.as_str()
            || verified.bob_node_id == LOCAL_NODE_ID
        {
            return Err(NodeError::Conflict(format!(
                "PEER_ID_CONFLICT: peer nodeId '{}' conflicts with local node identity",
                verified.bob_node_id
            )));
        }

        // If the offer explicitly bound a target `peerId`, reject mismatched claimants with 409.
        if let Some(ref expected_peer) = offer.peer_id {
            if verified.bob_node_id != *expected_peer {
                return Err(NodeError::Conflict(format!(
                    "PEER_ID_CONFLICT: P2P offer '{offer_id}' targets '{expected_peer}', not '{}'",
                    verified.bob_node_id
                )));
            }
        }

        // Atomically check existing peer/pins AND claim the single-use offer inside the DB lock!
        let grant_key = format!("p2p-offer:{offer_id}");
        let claim_entry = serde_json::to_string(response)?;
        let alice_grant_id = uuid_v4();
        let alice_grant = GrantV2 {
            v: 2,
            id: alice_grant_id.clone(),
            node_id: verified.bob_node_id.clone(),
            scopes: offer.offered_scopes.clone(),
            trust_tier: Some("peer".to_string()),
            pairing_key: None,
            subject_signing_jwk: Some(verified.bob_signing_pk.to_jwk()),
            subject_encryption_jwk: Some(verified.bob_encryption_pk.to_jwk()),
            issued_at: format_rfc3339_millis(now),
            pair_by: None,
            expires_at: None,
        };
        let conf = create_p2p_confirmation(&offer.offer_id, &alice_grant, &self.identity.signing)?;

        let bob_sign_kid = verified.bob_signing_pk.kid();
        let bob_enc_kid = verified.bob_encryption_pk.kid();

        {
            let db = self.db();

            // P1-1 anti-takeover check #2 (BEFORE claiming or upserting):
            // Never allow a P2P invitee to overwrite an existing peer (especially any Router/Hub
            // or peer with different pinned keys). Only permit idempotent re-pair when:
            //   1. The offer explicitly targeted this `peer_id`, AND
            //   2. Existing peer is an Active P2P peer, AND
            //   3. Existing pinned signing & encryption JWKs are identical to Bob's presented JWKs.
            let existing_peer = db.peers().get_peer(&verified.bob_node_id)?;
            let existing_sign_keys =
                db.peers()
                    .list_peer_keys(&verified.bob_node_id, Some(KeyUse::Signing), true)?;
            let existing_enc_keys =
                db.peers()
                    .list_peer_keys(&verified.bob_node_id, Some(KeyUse::Encryption), true)?;

            if existing_peer.is_some()
                || !existing_sign_keys.is_empty()
                || !existing_enc_keys.is_empty()
            {
                let sign_matches = !existing_sign_keys.is_empty()
                    && existing_sign_keys.iter().all(|k| {
                        k.kid == bob_sign_kid
                            && serde_json::from_str::<CryptoOkpJwk>(&k.jwk_json)
                                .ok()
                                .and_then(|j| j.to_ed25519().ok())
                                == Some(verified.bob_signing_pk)
                    });
                let enc_matches = !existing_enc_keys.is_empty()
                    && existing_enc_keys.iter().all(|k| {
                        k.kid == bob_enc_kid
                            && serde_json::from_str::<CryptoOkpJwk>(&k.jwk_json)
                                .ok()
                                .and_then(|j| j.to_x25519().ok())
                                == Some(verified.bob_encryption_pk)
                    });

                if let Some(ref peer_row) = existing_peer {
                    let profile_ok = peer_row.profile == hyp_store::PeerProfile::P2p
                        && peer_row.status == PeerStatus::Active;
                    let explicitly_targeted =
                        offer.peer_id.as_deref() == Some(verified.bob_node_id.as_str());

                    if !sign_matches || !enc_matches || !profile_ok {
                        return Err(NodeError::PeerKeyMismatch(format!(
                            "PEER_KEY_MISMATCH: peer '{}' already exists with different pinned keys or profile; refusing P2P takeover",
                            verified.bob_node_id
                        )));
                    }
                    if !explicitly_targeted {
                        return Err(NodeError::Conflict(format!(
                            "PEER_ALREADY_EXISTS: peer '{}' is already paired; explicit targeted --peer offer is required for idempotent re-pair",
                            verified.bob_node_id
                        )));
                    }
                } else {
                    // Peer is not paired yet, only has directory-cached keys in `peer_keys`:
                    // allow upgrading to a direct P2P peer ONLY if every cached key matches!
                    let sign_ok = existing_sign_keys.is_empty() || sign_matches;
                    let enc_ok = existing_enc_keys.is_empty() || enc_matches;
                    if !sign_ok || !enc_ok {
                        return Err(NodeError::PeerKeyMismatch(format!(
                            "PEER_KEY_MISMATCH: node '{}' already has different pinned keys cached; refusing P2P key takeover",
                            verified.bob_node_id
                        )));
                    }
                }
            }

            db.peers().claim_grant(&grant_key, &claim_entry, now)?;
            db.peers().upsert_peer(
                &PeerInput {
                    peer_id: verified.bob_node_id.clone(),
                    endpoint: verified.bob_endpoint.clone(),
                    profile: hyp_store::PeerProfile::P2p,
                    trust_tier: TrustTier::Peer,
                    status: PeerStatus::Active,
                    scopes: offer.offered_scopes.clone(),
                    auth_credential_ref: None,
                },
                now,
            )?;
            db.peers().add_grant(
                &GrantInput {
                    id: alice_grant_id.clone(),
                    peer_id: verified.bob_node_id.clone(),
                    direction: GrantDirection::Inbound,
                    signed_json: serde_json::to_string(&conf.alice_grant_to_bob)?,
                    scopes: offer.offered_scopes.clone(),
                    trust_tier: TrustTier::Peer,
                    issued_at: now,
                    pair_by: None,
                    expires_at: None,
                },
                now,
            )?;
            persist_peer_key_pair(
                &db,
                &verified.bob_node_id,
                PeerKeyPersistence::Upsert,
                [
                    (
                        bob_sign_kid.clone(),
                        serde_json::to_string(&verified.bob_signing_pk.to_jwk()),
                    ),
                    (
                        bob_enc_kid,
                        serde_json::to_string(&verified.bob_encryption_pk.to_jwk()),
                    ),
                ],
                now,
            )?;
        }

        // Remove offer from memory and SecretStore after single-use claim.
        self.pending_p2p_offers
            .lock()
            .expect("pending_p2p_offers lock poisoned")
            .remove(offer_id);
        let _ = self.secrets.delete(&offer_secret_key);

        // N1: Invalidate all previously issued bearer tokens for this peer on pair/re-pair.
        let _ = self.invalidate_peer_bearer_tokens(&verified.bob_node_id)?;
        let auth_credential = self.issue_peer_bearer_token(
            &verified.bob_node_id,
            Some(&alice_grant_id),
            Some(&bob_sign_kid),
        )?;
        let caller = AuthenticatedPeer {
            peer_id: verified.bob_node_id,
            scopes: ScopeSet::from_strings(&offer.offered_scopes),
            trust_tier: TrustTier::Peer,
        };
        let (signed_manifest, _, _) = self.build_signed_manifest(Some(&caller))?;

        Ok(P2pPairServerReply {
            offer_id: conf.offer_id,
            alice_grant_to_bob: conf.alice_grant_to_bob,
            auth_credential,
            signed_manifest,
        })
    }

    /// Client-side Direct P2P mutual pairing (`hp2p1_`): verifies Alice's OOB JWKs, builds
    /// Bob's signed grant + HKDF MAC response, POSTs `/v1/p2p/pair/<offerId>`, verifies
    /// Alice's confirmation & manifest against Alice's zero-TOFU JWK, pins keys, stores
    /// `authCredential` in `SecretStore`, and activates the bidirectional E2EE `PeerLink`!
    pub async fn accept_p2p_invite(
        self: &Arc<Self>,
        hp2p1_token: &str,
        bob_grants_to_alice: Vec<String>,
    ) -> Result<PeerLinkInfo, NodeError> {
        let offer = decode_hp2p1(hp2p1_token)?;
        if offer.node_id == self.config.node_id.as_str() || offer.node_id == LOCAL_NODE_ID {
            return Err(NodeError::Conflict(format!(
                "PEER_ID_CONFLICT: offer nodeId '{}' conflicts with local node identity",
                offer.node_id
            )));
        }
        let offer_sign_pk = offer.signing_jwk.to_ed25519()?;
        let offer_enc_pk = offer.encryption_jwk.to_x25519()?;
        {
            let db = self.db();
            let existing_peer = db.peers().get_peer(&offer.node_id)?;
            let existing_sign_keys =
                db.peers()
                    .list_peer_keys(&offer.node_id, Some(KeyUse::Signing), true)?;
            let existing_enc_keys =
                db.peers()
                    .list_peer_keys(&offer.node_id, Some(KeyUse::Encryption), true)?;
            if existing_peer.is_some()
                || !existing_sign_keys.is_empty()
                || !existing_enc_keys.is_empty()
            {
                let sign_matches = !existing_sign_keys.is_empty()
                    && existing_sign_keys.iter().all(|k| {
                        k.kid == offer_sign_pk.kid()
                            && serde_json::from_str::<CryptoOkpJwk>(&k.jwk_json)
                                .ok()
                                .and_then(|j| j.to_ed25519().ok())
                                == Some(offer_sign_pk)
                    });
                let enc_matches = !existing_enc_keys.is_empty()
                    && existing_enc_keys.iter().all(|k| {
                        k.kid == offer_enc_pk.kid()
                            && serde_json::from_str::<CryptoOkpJwk>(&k.jwk_json)
                                .ok()
                                .and_then(|j| j.to_x25519().ok())
                                == Some(offer_enc_pk)
                    });
                if let Some(ref peer_row) = existing_peer {
                    let profile_ok = peer_row.profile == hyp_store::PeerProfile::P2p
                        && peer_row.status == PeerStatus::Active;
                    if !sign_matches || !enc_matches || !profile_ok {
                        return Err(NodeError::PeerKeyMismatch(format!(
                            "PEER_KEY_MISMATCH: peer '{}' already exists with different pinned keys or profile; refusing P2P overwrite",
                            offer.node_id
                        )));
                    }
                } else {
                    let sign_ok = existing_sign_keys.is_empty() || sign_matches;
                    let enc_ok = existing_enc_keys.is_empty() || enc_matches;
                    if !sign_ok || !enc_ok {
                        return Err(NodeError::PeerKeyMismatch(format!(
                            "PEER_KEY_MISMATCH: node '{}' already has different pinned keys cached; refusing P2P overwrite",
                            offer.node_id
                        )));
                    }
                }
            }
        }
        let expanded_to_alice = expand_node_scopes(&bob_grants_to_alice)?;

        let now = now_ms();
        let bob_grant_id = uuid_v4();
        let bob_grant = p2p_counter_grant(
            &offer,
            bob_grant_id,
            expanded_to_alice.clone(),
            "peer",
            format_rfc3339_millis(now),
            None,
        );

        let my_endpoint = self
            .bound_addr
            .lock()
            .expect("bound_addr lock poisoned")
            .map(|a| format!("http://{a}"))
            .or_else(|| self.config.public_endpoint.clone());

        let resp_body = create_p2p_response(
            &offer,
            self.config.node_id.as_str(),
            my_endpoint.as_deref(),
            &self.identity,
            &bob_grant,
        )?;

        let path = format!(
            "/v1/p2p/pair/{}",
            crate::engine::http_util::percent_encode(&offer.offer_id)
        );
        let http_req = Request::builder()
            .method(Method::POST)
            .uri(&path)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(full_body(serde_json::to_vec(&resp_body)?))
            .map_err(|e| NodeError::Http(e.to_string()))?;
        let resp = self
            .http_client
            .request_for_endpoint(&offer.endpoint, http_req)
            .await?;
        let (status, _headers, body) = HttpClient::collect(resp, MAX_JSON_RESPONSE_BYTES).await?;
        if !status.is_success() {
            return Err(HttpClient::decode_error_response(status, &body));
        }
        let server_reply: P2pPairServerReply = serde_json::from_slice(&body)?;

        // Verify Alice's confirmation against Alice's zero-TOFU JWK embedded in `hp2p1_`!
        let verified_alice_grant =
            server_reply.verify_grant(&offer, self.config.node_id.as_str())?;

        // The reply manifest must match the keys received in the out-of-band offer.
        verify_pairing_reply_manifest(
            &server_reply.signed_manifest,
            &offer.node_id,
            Some(&offer_sign_pk),
            Some(&offer.encryption_jwk.x),
        )?;
        let alice_sign_pk = offer_sign_pk;
        let alice_enc_pk = offer_enc_pk;
        let cred_ref =
            self.save_peer_auth_credential(&offer.node_id, &server_reply.auth_credential)?;

        {
            let db = self.db();
            persist_peer_with_keys(
                &db,
                &PeerInput {
                    peer_id: offer.node_id.clone(),
                    endpoint: Some(offer.endpoint.clone()),
                    profile: hyp_store::PeerProfile::P2p,
                    trust_tier: TrustTier::Peer,
                    status: PeerStatus::Active,
                    // Inbound scopes Bob grants to Alice:
                    scopes: expanded_to_alice.clone(),
                    auth_credential_ref: Some(cred_ref),
                },
                PeerKeyPersistence::Upsert,
                [
                    (
                        alice_sign_pk.kid(),
                        serde_json::to_string(&offer.signing_jwk),
                    ),
                    (
                        alice_enc_pk.kid(),
                        serde_json::to_string(&offer.encryption_jwk),
                    ),
                ],
                now,
            )?;
            let _ = db.peers().add_grant(
                &GrantInput {
                    id: verified_alice_grant.id.clone(),
                    peer_id: offer.node_id.clone(),
                    direction: GrantDirection::Outbound,
                    signed_json: serde_json::to_string(&server_reply.alice_grant_to_bob)?,
                    scopes: verified_alice_grant.scopes,
                    trust_tier: TrustTier::Peer,
                    issued_at: now,
                    pair_by: None,
                    expires_at: None,
                },
                now,
            );
        }

        let etag = compute_etag(&serde_json::to_vec(&server_reply.signed_manifest)?);
        let negotiated = self.verify_and_cache_peer_manifest(
            &offer.node_id,
            &server_reply.signed_manifest,
            Some(etag),
            false,
        )?;

        self.activate_peer_link(&offer.node_id, &offer.endpoint, negotiated.clone())
            .await?;

        Ok(PeerLinkInfo {
            peer_id: offer.node_id,
            endpoint: offer.endpoint,
            negotiated,
        })
    }
}
