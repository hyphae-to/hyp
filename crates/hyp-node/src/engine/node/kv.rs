use crate::engine::config::NodeError;
use crate::engine::peer_link::{KvSetBody, PeerLink, PutKvEpochRequest};
use hyp_crypto::e2ee::{
    EpochScope, KvContext, KvEnvelopeV1, RoomEpochKey, open_kv_entry, seal_kv_entry,
};
use hyp_proto::address::LOCAL_NODE_ID;
use hyp_proto::cloudevent::{CONTENT_TYPE_E2EE_JSON, CONTENT_TYPE_JSON};
use hyp_proto::manifest::{CapabilityToken, NodeManifestPayload, SignedNodeManifest};
use hyp_proto::problem::ProblemDetails;
use hyp_proto::scopes::ScopeSet;
use hyp_store::{
    GrantDirection, KeyStatus, KeyUse, KvDeleteInput, KvDeleteResult, KvEntry, KvEpoch,
    KvEpochInput, KvSetInput, PeerKeyInput, PeerStatus, WriteModel, now_ms, parse_address,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::sync::watch;

use super::{AuthenticatedPeer, UnifiedNode};

/// Parameters for `UnifiedNode::kv_set`.
#[derive(Debug, Clone)]
pub struct KvWriteRequest {
    /// Target node (`"local"` or paired peer node ID).
    pub host_node: String,
    pub namespace: String,
    pub key: String,
    pub value: Value,
    pub write_model: WriteModel,
    pub owner_id: Option<String>,
    pub allowlist: Option<Vec<String>>,
    pub expected_version: Option<u64>,
    pub ttl_ms: Option<i64>,
    /// Encrypt value with `kv.e2ee.v1` namespace epoch key before storing/sending.
    pub encrypt: bool,
    /// Optional explicit member nodes when auto-bootstrapping an E2EE KV namespace epoch.
    pub e2ee_members: Option<Vec<String>>,
}

impl UnifiedNode {
    /// Ensures (or mints) an E2EE KV namespace epoch for `(host_node, namespace)`.
    pub async fn ensure_kv_epoch(
        &self,
        host_node: &str,
        namespace: &str,
        member_nodes: &[String],
    ) -> Result<u64, NodeError> {
        let resolved_host = if host_node == LOCAL_NODE_ID {
            self.config.node_id.as_str()
        } else {
            host_node
        };
        let link = if resolved_host == self.config.node_id.as_str() {
            None
        } else {
            Some(self.require_peer_link(resolved_host).await?)
        };

        let existing = if let Some(ref l) = link {
            l.get_kv_epoch(namespace, None).await?
        } else {
            self.db().kv().latest_epoch(resolved_host, namespace)?
        };

        if let Some(ep) = existing {
            let ep_members: BTreeSet<&str> = ep.members.iter().map(String::as_str).collect();
            let target_members: BTreeSet<&str> = member_nodes
                .iter()
                .map(String::as_str)
                .chain(std::iter::once(self.config.node_id.as_str()))
                .collect();
            if ep_members == target_members {
                let _ = self
                    .unwrap_and_cache_kv_epoch(resolved_host, namespace, &ep, link.as_ref())
                    .await?;
                return Ok(ep.epoch);
            }
            return self
                .create_or_rotate_kv_epoch(
                    resolved_host,
                    namespace,
                    Some(ep.epoch),
                    member_nodes,
                    link.as_ref(),
                )
                .await;
        }

        self.create_or_rotate_kv_epoch(resolved_host, namespace, None, member_nodes, link.as_ref())
            .await
    }

    /// Resolves the default set of E2EE KV epoch recipients when `KvWriteRequest.e2ee_members`
    /// is omitted on an encrypted write:
    /// - `WriteModel::Allowlist` (non-empty allowlist): `self` + allowlisted node IDs.
    /// - Remote host (`link.is_some()`): queries `GET /v1/keys?kvNamespace=<ns>` to wrap for all
    ///   active peers authorized to read `namespace`, caching their verified keys locally while
    ///   strictly excluding blind `Router` host nodes.
    /// - Local host (`link.is_none()`): wraps for `self` + active local peers authorized to read
    ///   `namespace` that have pinned signing + encryption keys.
    async fn resolve_default_kv_e2ee_members(
        &self,
        resolved_host: &str,
        namespace: &str,
        write_model: WriteModel,
        allowlist: Option<&[String]>,
        link: Option<&Arc<PeerLink>>,
    ) -> Vec<String> {
        let mut members: BTreeSet<String> = BTreeSet::new();
        members.insert(self.config.node_id.to_string());

        if write_model == WriteModel::Allowlist {
            if let Some(al) = allowlist.filter(|a| !a.is_empty()) {
                for raw in al {
                    let trimmed = raw.trim();
                    if trimmed.is_empty() {
                        continue;
                    }
                    let nid = parse_address(trimmed).map(|(n, _)| n).unwrap_or(trimmed);
                    members.insert(nid.to_string());
                }
                return members.into_iter().collect();
            }
        }

        if let Some(l) = link {
            let host_is_router = {
                let db = self.db();
                db.peers()
                    .get_peer(resolved_host)
                    .ok()
                    .flatten()
                    .is_some_and(|p| {
                        p.profile == hyp_store::PeerProfile::Router
                            || p.manifest_json
                                .as_deref()
                                .and_then(|raw| {
                                    serde_json::from_str::<SignedNodeManifest>(raw).ok()
                                })
                                .and_then(|s| {
                                    serde_json::from_str::<NodeManifestPayload>(&s.payload).ok()
                                })
                                .is_some_and(|m| {
                                    m.profile == hyp_proto::manifest::NodeProfile::Router
                                })
                    })
            };

            if let Ok(resp) = l.get_kv_member_keys(namespace).await {
                let now = now_ms();
                let db = self.db();
                for entry in resp.keys {
                    // Never wrap an E2EE KV epoch key for a blind router (defensive even against
                    // older hubs that ignore `?kvNamespace=` and include their own node_id).
                    if entry.node_id == resolved_host && host_is_router {
                        continue;
                    }
                    let Ok(sk) = entry.signing_jwk.to_ed25519() else {
                        continue;
                    };
                    let Ok(ek) = entry.encryption_jwk.to_x25519() else {
                        continue;
                    };
                    if entry.node_id != self.config.node_id.as_str() {
                        if let Ok(sj) = serde_json::to_string(&entry.signing_jwk) {
                            let _ = db.peers().upsert_peer_key(
                                &PeerKeyInput {
                                    peer_id: entry.node_id.clone(),
                                    kid: sk.kid(),
                                    key_use: KeyUse::Signing,
                                    jwk_json: sj,
                                    status: KeyStatus::Active,
                                    expires_at: None,
                                },
                                now,
                            );
                        }
                        if let Ok(ej) = serde_json::to_string(&entry.encryption_jwk) {
                            let _ = db.peers().upsert_peer_key(
                                &PeerKeyInput {
                                    peer_id: entry.node_id.clone(),
                                    kid: ek.kid(),
                                    key_use: KeyUse::Encryption,
                                    jwk_json: ej,
                                    status: KeyStatus::Active,
                                    expires_at: None,
                                },
                                now,
                            );
                        }
                    }
                    members.insert(entry.node_id);
                }
            }
        } else {
            let db = self.db();
            if let Ok(peers) = db.peers().list_peers(Some(PeerStatus::Active)) {
                for peer in peers {
                    let scopes = ScopeSet::from_strings(&peer.scopes);
                    if !scopes.may_kv_read_namespace(namespace)
                        && !scopes.may_kv_write_namespace(namespace)
                    {
                        continue;
                    }
                    let has_sign = db
                        .peers()
                        .list_peer_keys(&peer.peer_id, Some(KeyUse::Signing), true)
                        .is_ok_and(|k| !k.is_empty());
                    let has_enc = db
                        .peers()
                        .list_peer_keys(&peer.peer_id, Some(KeyUse::Encryption), true)
                        .is_ok_and(|k| !k.is_empty());
                    if has_sign && has_enc {
                        members.insert(peer.peer_id);
                    }
                }
            }
        }

        members.into_iter().collect()
    }

    async fn create_or_rotate_kv_epoch(
        &self,
        host_node: &str,
        namespace: &str,
        prev_epoch: Option<u64>,
        member_nodes: &[String],
        link: Option<&Arc<PeerLink>>,
    ) -> Result<u64, NodeError> {
        let mut unique: BTreeSet<String> = member_nodes.iter().cloned().collect();
        unique.insert(self.config.node_id.to_string());
        let all_members: Vec<String> = unique.into_iter().collect();

        let (room_key, signed_bundle) = self
            .build_room_epoch_bundle(
                EpochScope::Kv,
                host_node,
                namespace,
                prev_epoch,
                &all_members,
                link,
            )
            .await?;
        let new_epoch = room_key.epoch();

        if let Some(l) = link {
            l.put_kv_epoch(&PutKvEpochRequest {
                namespace: namespace.to_string(),
                epoch: new_epoch,
                bundle: signed_bundle.clone(),
                members: all_members.clone(),
            })
            .await?;
        }
        let stored = self.db().kv().put_epoch(
            &KvEpochInput {
                host_node: host_node.to_string(),
                namespace: namespace.to_string(),
                epoch: new_epoch,
                creator_node_id: self.config.node_id.to_string(),
                key_envelope_json: serde_json::to_string(&signed_bundle)?,
                members: all_members,
                signature: signed_bundle.sig.clone(),
            },
            now_ms(),
        );
        if stored.is_ok() && host_node == self.config.node_id.as_str() {
            self.notify_kv_metadata_change();
        }
        self.cache_room_key("kv", host_node, namespace, room_key);
        Ok(new_epoch)
    }

    pub(super) async fn get_or_fetch_kv_room_key(
        &self,
        host_node: &str,
        namespace: &str,
        epoch: u64,
        link: Option<&Arc<PeerLink>>,
    ) -> Result<RoomEpochKey, NodeError> {
        if let Some(k) = self.cached_room_key("kv", host_node, namespace, epoch) {
            return Ok(k);
        }
        let stored = if let Some(l) = link {
            l.get_kv_epoch(namespace, Some(epoch)).await?
        } else {
            self.db().kv().get_epoch(host_node, namespace, epoch)?
        }
        .ok_or_else(|| {
            NodeError::NotFound(format!(
                "kv epoch {epoch} not found for '{host_node}/{namespace}'"
            ))
        })?;
        self.unwrap_and_cache_kv_epoch(host_node, namespace, &stored, link)
            .await
    }

    async fn unwrap_and_cache_kv_epoch(
        &self,
        host_node: &str,
        namespace: &str,
        stored: &KvEpoch,
        link: Option<&Arc<PeerLink>>,
    ) -> Result<RoomEpochKey, NodeError> {
        let copy = self
            .open_and_cache_room_epoch(
                EpochScope::Kv,
                host_node,
                namespace,
                &stored.creator_node_id,
                &stored.key_envelope_json,
                link,
            )
            .await?;
        {
            let db = self.db();
            let _ = db.kv().put_epoch(
                &KvEpochInput {
                    host_node: host_node.to_string(),
                    namespace: namespace.to_string(),
                    epoch: stored.epoch,
                    creator_node_id: stored.creator_node_id.clone(),
                    key_envelope_json: stored.key_envelope_json.clone(),
                    members: stored.members.clone(),
                    signature: stored.signature.clone(),
                },
                now_ms(),
            );
        }
        Ok(copy)
    }

    pub fn handle_server_put_kv_epoch(
        &self,
        caller: &AuthenticatedPeer,
        req: PutKvEpochRequest,
    ) -> Result<KvEpoch, NodeError> {
        self.require_scope(
            caller,
            caller.scopes.may_kv_write(&req.namespace, ""),
            &format!("kv:write={}/*", req.namespace),
        )?;
        self.verify_uploaded_epoch_bundle(
            EpochScope::Kv,
            &caller.peer_id,
            &req.namespace,
            req.epoch,
            &req.bundle,
        )?;
        let epoch = self.db().kv().put_epoch(
            &KvEpochInput {
                host_node: self.config.node_id.to_string(),
                namespace: req.namespace,
                epoch: req.epoch,
                creator_node_id: caller.peer_id.clone(),
                key_envelope_json: serde_json::to_string(&req.bundle)?,
                members: req.members,
                signature: req.bundle.sig,
            },
            now_ms(),
        )?;
        self.notify_kv_metadata_change();
        Ok(epoch)
    }

    /// Writes a Shared KV entry locally or on a remote peer, supporting `owner` / `shared`
    /// (RFC 9110 `If-Match` CAS -> `409 version_conflict`) / `allowlist` AND transparent
    /// `kv.e2ee.v1` namespace encryption!
    pub async fn kv_set(&self, req: KvWriteRequest) -> Result<KvEntry, NodeError> {
        let resolved_host = if req.host_node == LOCAL_NODE_ID {
            self.config.node_id.to_string()
        } else {
            req.host_node.clone()
        };
        let is_local = resolved_host == self.config.node_id.as_str();
        let link = if is_local {
            None
        } else {
            Some(self.require_peer_link(&resolved_host).await?)
        };

        let (wire_value, content_type, e2ee_epoch, signature, cas_expected) = if req.encrypt {
            if let Some(ref l) = link {
                if !self.peer_supports_cap(&resolved_host, &CapabilityToken::KvE2eeV1, Some(l)) {
                    return Err(NodeError::CapabilityUnsupported(Box::new(
                        ProblemDetails::capability_unsupported(
                            &CapabilityToken::KvE2eeV1,
                            &resolved_host,
                            &self.config.hyphae_version,
                            "unknown",
                            Some("2.1.0"),
                            true,
                            None,
                        ),
                    )));
                }
            }

            // Determine exact expected version so AAD `version` matches atomic CAS write!
            let cur_version = match req.expected_version {
                Some(v) => v,
                None => {
                    let existing = if let Some(ref l) = link {
                        l.kv_get(&req.namespace, &req.key).await?
                    } else {
                        self.db()
                            .kv()
                            .get(&resolved_host, &req.namespace, &req.key, now_ms())?
                    };
                    existing.map(|e| e.version).unwrap_or(0)
                }
            };
            let next_version = cur_version.saturating_add(1);

            let members = match req.e2ee_members.clone().filter(|m| !m.is_empty()) {
                Some(explicit) => explicit,
                None => {
                    self.resolve_default_kv_e2ee_members(
                        &resolved_host,
                        &req.namespace,
                        req.write_model,
                        req.allowlist.as_deref(),
                        link.as_ref(),
                    )
                    .await
                }
            };
            let epoch_num = self
                .ensure_kv_epoch(&resolved_host, &req.namespace, &members)
                .await?;
            let room_key = self
                .get_or_fetch_kv_room_key(&resolved_host, &req.namespace, epoch_num, link.as_ref())
                .await?;

            let writer_grant_id = self.outbound_grant_id_for_peer(&resolved_host);
            let ctx = KvContext {
                host_node: &resolved_host,
                namespace: &req.namespace,
                key: &req.key,
                version: next_version,
                writer_node_id: self.config.node_id.as_str(),
                writer_grant_id: &writer_grant_id,
            };
            let plaintext_bytes = serde_json::to_vec(&req.value)?;
            let env = seal_kv_entry(&ctx, &plaintext_bytes, &room_key, &self.identity.signing)?;
            let sig = env.sig.clone();
            let mut env_val = serde_json::to_value(&env)?;
            if let Some(obj) = env_val.as_object_mut() {
                obj.insert("writerGrantId".to_string(), json!(writer_grant_id));
            }
            (
                env_val,
                Some(CONTENT_TYPE_E2EE_JSON.to_string()),
                Some(epoch_num),
                Some(sig),
                Some(cur_version),
            )
        } else {
            (
                req.value.clone(),
                Some(CONTENT_TYPE_JSON.to_string()),
                None,
                None,
                req.expected_version,
            )
        };

        let stored = if let Some(ref l) = link {
            let body = KvSetBody {
                value: wire_value,
                content_type,
                write_model: req.write_model,
                owner_id: req.owner_id,
                allowlist: req.allowlist,
                expected_version: cas_expected,
                e2ee_epoch,
                signature,
                ttl_ms: req.ttl_ms,
            };
            l.kv_set(&req.namespace, &req.key, &body, cas_expected)
                .await?
        } else {
            let res = {
                let db = self.db();
                db.kv().set(
                    &KvSetInput {
                        host_node: resolved_host.clone(),
                        namespace: req.namespace.clone(),
                        key: req.key.clone(),
                        value: wire_value,
                        content_type,
                        write_model: req.write_model,
                        owner_id: req.owner_id,
                        allowlist: req.allowlist,
                        writer_id: self.config.node_id.to_string(),
                        expected_version: cas_expected,
                        e2ee_epoch,
                        signature,
                        ttl_ms: req.ttl_ms,
                    },
                    now_ms(),
                )?
            };
            self.notify_local_kv_change();
            res.entry
        };

        self.record_kv_seen_version(&resolved_host, &req.namespace, &req.key, stored.version);
        Ok(KvEntry {
            value: req.value,
            ..stored
        })
    }

    /// Reads a KV entry locally or remotely, transparently verifying & decrypting `kv.e2ee.v1`
    /// envelopes and enforcing `maxSeenVersion` anti-rollback!
    pub async fn kv_get(
        &self,
        host_node: &str,
        namespace: &str,
        key: &str,
    ) -> Result<Option<KvEntry>, NodeError> {
        let resolved_host = if host_node == LOCAL_NODE_ID {
            self.config.node_id.to_string()
        } else {
            host_node.to_string()
        };
        let link = if resolved_host == self.config.node_id.as_str() {
            None
        } else {
            Some(self.require_peer_link(&resolved_host).await?)
        };

        let entry_opt = if let Some(ref l) = link {
            l.kv_get(namespace, key).await?
        } else {
            self.db()
                .kv()
                .get(&resolved_host, namespace, key, now_ms())?
        };
        let Some(entry) = entry_opt else {
            return Ok(None);
        };
        let decrypted = self
            .maybe_decrypt_kv_entry(&resolved_host, entry, link.as_ref())
            .await?;
        Ok(Some(decrypted))
    }

    pub async fn kv_delete(
        &self,
        host_node: &str,
        namespace: &str,
        key: &str,
        expected_version: Option<u64>,
    ) -> Result<KvDeleteResult, NodeError> {
        let resolved_host = if host_node == LOCAL_NODE_ID {
            self.config.node_id.to_string()
        } else {
            host_node.to_string()
        };
        if resolved_host == self.config.node_id.as_str() {
            let res = {
                let db = self.db();
                db.kv().delete(
                    &KvDeleteInput {
                        host_node: resolved_host,
                        namespace: namespace.to_string(),
                        key: key.to_string(),
                        writer_id: self.config.node_id.to_string(),
                        expected_version,
                    },
                    now_ms(),
                )?
            };
            if res.deleted {
                self.notify_local_kv_change();
            }
            return Ok(res);
        }
        let link = self.require_peer_link(&resolved_host).await?;
        link.kv_delete(namespace, key, expected_version).await
    }

    /// Watches changes to local KV metadata, including expiry and epoch rotations.
    pub fn subscribe_kv_metadata(&self) -> watch::Receiver<()> {
        self.kv_metadata_tx.subscribe()
    }

    pub(crate) fn notify_kv_metadata_change(&self) {
        self.kv_metadata_tx.send_replace(());
    }

    /// Materializes locally subscribed KV change batches after their write transaction commits.
    pub fn notify_local_kv_change(&self) {
        self.notify_kv_metadata_change();
        let _ = crate::adapters::deliver_source_topic_to_local_sessions(self, "kv");
        self.notify_all_inbox_subscribers();
        self.notify_scheduler();
    }

    pub async fn kv_list(
        &self,
        host_node: &str,
        namespace: &str,
        prefix: Option<&str>,
    ) -> Result<Vec<KvEntry>, NodeError> {
        let resolved_host = if host_node == LOCAL_NODE_ID {
            self.config.node_id.to_string()
        } else {
            host_node.to_string()
        };
        let link = if resolved_host == self.config.node_id.as_str() {
            None
        } else {
            Some(self.require_peer_link(&resolved_host).await?)
        };
        let entries = if let Some(ref l) = link {
            l.kv_list(namespace, prefix).await?
        } else {
            self.db()
                .kv()
                .list(&resolved_host, namespace, prefix, now_ms())?
        };
        let mut out = Vec::with_capacity(entries.len());
        for e in entries {
            out.push(
                self.maybe_decrypt_kv_entry(&resolved_host, e, link.as_ref())
                    .await?,
            );
        }
        Ok(out)
    }

    pub(super) async fn maybe_decrypt_kv_entry(
        &self,
        host_node: &str,
        mut entry: KvEntry,
        link: Option<&Arc<PeerLink>>,
    ) -> Result<KvEntry, NodeError> {
        if entry.content_type != CONTENT_TYPE_E2EE_JSON {
            return Ok(entry);
        }
        let env: KvEnvelopeV1 = serde_json::from_value(entry.value.clone())?;
        let writer_grant_id = entry
            .value
            .get("writerGrantId")
            .and_then(Value::as_str)
            .unwrap_or("self")
            .to_string();
        let (writer_pk, _) = self.resolve_peer_keys(&entry.writer_id, link).await?;
        let room_key = self
            .get_or_fetch_kv_room_key(host_node, &entry.namespace, env.epoch, link)
            .await?;
        let min_epoch = self.current_min_epoch("kv", host_node, &entry.namespace);
        let max_seen = self.get_kv_seen_version(host_node, &entry.namespace, &entry.key);
        let ctx = KvContext {
            host_node,
            namespace: &entry.namespace,
            key: &entry.key,
            version: entry.version,
            writer_node_id: &entry.writer_id,
            writer_grant_id: &writer_grant_id,
        };
        let pt_bytes = open_kv_entry(&env, &ctx, &room_key, &writer_pk, min_epoch, max_seen)?;
        let decrypted_val: Value = serde_json::from_slice(&pt_bytes)?;
        self.record_kv_seen_version(host_node, &entry.namespace, &entry.key, entry.version);
        entry.value = decrypted_val;
        Ok(entry)
    }

    fn outbound_grant_id_for_peer(&self, peer_id: &str) -> String {
        let db = self.db();
        if let Ok(grants) = db.peers().list_grants(Some(peer_id)) {
            if let Some(g) = grants
                .into_iter()
                .rev()
                .find(|g| g.direction == GrantDirection::Outbound)
            {
                return g.id;
            }
        }
        "self".to_string()
    }

    pub(super) fn get_kv_seen_version(&self, host_node: &str, ns: &str, key: &str) -> Option<u64> {
        self.kv_max_seen_version
            .lock()
            .expect("kv_max_seen_version lock poisoned")
            .get(&(host_node.to_string(), ns.to_string(), key.to_string()))
            .copied()
    }

    pub(super) fn record_kv_seen_version(
        &self,
        host_node: &str,
        ns: &str,
        key: &str,
        version: u64,
    ) {
        let mut map = self
            .kv_max_seen_version
            .lock()
            .expect("kv_max_seen_version lock poisoned");
        let entry = map
            .entry((host_node.to_string(), ns.to_string(), key.to_string()))
            .or_insert(0);
        if version > *entry {
            *entry = version;
        }
    }
}
