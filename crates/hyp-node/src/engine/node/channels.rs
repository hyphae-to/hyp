use crate::engine::config::{ChannelPolicy, NodeError};
use crate::engine::peer_link::{
    ChannelDirectoryEntry, ChannelJoinResponse, ChannelPostRequest, PeerLink,
    PutChannelEpochRequest,
};
use hyp_crypto::e2ee::{ChannelContext, EpochScope, RoomEpochKey, seal_channel_message};
use hyp_proto::address::{Channel, LOCAL_NODE_ID, NodeId, NodeScope, QualifiedChannel};
use hyp_proto::cloudevent::CONTENT_TYPE_E2EE_JSON;
use hyp_proto::manifest::{CapabilityToken, E2eePolicy};
use hyp_proto::problem::ProblemDetails;
use hyp_proto::scopes::ScopeSet;
use hyp_store::{
    AckOutcome, ChannelEpoch, ChannelEpochInput, PostChannelInput, PostChannelResult, TrustTier,
    format_address, now_ms, parse_address, uuid_v4,
};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::Arc;

use super::{AuthenticatedPeer, UnifiedNode};

impl UnifiedNode {
    async fn resolve_channel_coord(&self, qualified: &str) -> Result<(String, String), NodeError> {
        let default_scope = match self.default_remote_peer().await {
            Some(pid) => NodeScope::Remote(NodeId::new(pid)?),
            None => NodeScope::Local,
        };
        let qc = QualifiedChannel::resolve(qualified, &default_scope)?;
        let host = qc.node.concrete_node_id(&self.config.node_id).to_string();
        Ok((host, qc.channel.into_inner()))
    }

    /// Joins a `#channel` (local or remote hub) and caches its `ChannelPolicy` locally.
    pub async fn join_channel(
        &self,
        qualified_channel: &str,
        local_handle: &str,
    ) -> Result<ChannelJoinResponse, NodeError> {
        let (host_node, channel) = self.resolve_channel_coord(qualified_channel).await?;
        if host_node == self.config.node_id.as_str() {
            let now = now_ms();
            let membership = {
                let db = self.db();
                db.channels().join(
                    self.config.node_id.as_str(),
                    &channel,
                    self.config.node_id.as_str(),
                    local_handle,
                    now,
                )?
            };
            let policy = self.get_channel_policy(&channel);
            let can_post = policy
                .is_authorized_writer(self.config.node_id.as_str(), Some(&membership.address));
            return Ok(ChannelJoinResponse {
                host_node: membership.host_node,
                channel: membership.channel,
                address: membership.address,
                members: membership.members,
                mode: policy.mode,
                writers: policy.writers,
                can_post,
            });
        }

        let link = self.require_peer_link(&host_node).await?;
        let resp = link.join_channel(&channel, local_handle).await?;
        self.cache_remote_channel_policy(
            &host_node,
            &channel,
            ChannelPolicy {
                mode: resp.mode,
                writers: resp.writers.clone(),
                description: None,
            },
        );
        Ok(resp)
    }

    pub async fn leave_channel(
        &self,
        qualified_channel: &str,
        local_handle: &str,
    ) -> Result<bool, NodeError> {
        let (host_node, channel) = self.resolve_channel_coord(qualified_channel).await?;
        if host_node == self.config.node_id.as_str() {
            let db = self.db();
            return Ok(db.channels().leave(
                self.config.node_id.as_str(),
                &channel,
                self.config.node_id.as_str(),
                local_handle,
            )?);
        }
        let link = self.require_peer_link(&host_node).await?;
        link.leave_channel(&channel, local_handle).await
    }

    /// Lists channels on `host_node` (`"local"` or peer ID), including `mode` and caller-scoped `canPost`.
    pub async fn list_channels(
        &self,
        host_node: &str,
        channel: Option<&str>,
    ) -> Result<Vec<ChannelDirectoryEntry>, NodeError> {
        if host_node == LOCAL_NODE_ID || host_node == self.config.node_id.as_str() {
            let my_id = self.config.node_id.to_string();
            let self_auth = AuthenticatedPeer {
                peer_id: my_id,
                scopes: ScopeSet::from_strings(&["*"]),
                trust_tier: TrustTier::SelfNode,
            };
            return self.list_channels_for_caller(&self_auth, channel);
        }
        let link = self.require_peer_link(host_node).await?;
        let resp = link.list_channels(channel).await?;
        for entry in &resp.channels {
            self.cache_remote_channel_policy(
                host_node,
                &entry.channel,
                ChannelPolicy {
                    mode: entry.mode,
                    writers: entry.writers.clone(),
                    description: entry.description.clone(),
                },
            );
        }
        Ok(resp.channels)
    }

    /// Server-side caller-scoped channel directory listing (`GET /v1/channels`).
    pub fn list_channels_for_caller(
        &self,
        caller: &AuthenticatedPeer,
        filter_channel: Option<&str>,
    ) -> Result<Vec<ChannelDirectoryEntry>, NodeError> {
        let host = self.config.node_id.as_str();
        let policies = self.list_channel_policies();
        let (members_by_ch, caller_addrs) = {
            let db = self.db();
            let mut map: BTreeMap<String, Vec<String>> = BTreeMap::new();
            for info in db.channels().list_channels(Some(host))? {
                map.insert(info.channel, info.members);
            }
            let addrs: Vec<String> = db
                .messages()
                .list_handles(Some(&caller.peer_id))?
                .into_iter()
                .map(|h| h.address)
                .collect();
            (map, addrs)
        };

        let mut all_names: BTreeSet<String> = members_by_ch.keys().cloned().collect();
        for ch in policies.keys() {
            all_names.insert(ch.clone());
        }
        if let Some(target) = filter_channel {
            let norm = Channel::normalize(target)?.into_inner();
            all_names.retain(|c| c == &norm);
        }

        let mut out = Vec::new();
        for ch in all_names {
            if !caller.scopes.may_channel_join(&ch) {
                continue;
            }
            let policy = policies
                .get(&ch)
                .cloned()
                .unwrap_or_else(ChannelPolicy::open);
            let members = members_by_ch.get(&ch).cloned().unwrap_or_default();
            let can_post = caller.scopes.may_channel_post(&ch)
                && policy.node_can_post(&caller.peer_id, &caller_addrs);
            out.push(ChannelDirectoryEntry {
                host_node: host.to_string(),
                channel: ch,
                members,
                mode: policy.mode,
                writers: policy.writers,
                can_post,
                description: policy.description,
            });
        }
        Ok(out)
    }

    /// Ensures an active E2EE `channel.e2ee.v1` epoch exists for `(host_node, channel)` covering
    /// current member nodes (unwrapping an existing epoch or minting epoch 1 if absent).
    pub async fn ensure_channel_epoch(
        &self,
        host_node: &str,
        channel: &str,
    ) -> Result<u64, NodeError> {
        let link = if host_node == self.config.node_id.as_str() {
            None
        } else {
            Some(self.require_peer_link(host_node).await?)
        };

        let current_member_nodes = self
            .fetch_channel_member_nodes(host_node, channel, link.as_ref())
            .await?;

        let existing_epoch = if let Some(ref l) = link {
            l.get_channel_epoch(channel, None).await?
        } else {
            self.db().channels().latest_epoch(host_node, channel)?
        };

        if let Some(ep) = existing_epoch {
            // Check whether existing epoch covers all current members and is unwrap-able by us.
            let ep_members: BTreeSet<&str> = ep.members.iter().map(String::as_str).collect();
            let all_covered = current_member_nodes
                .iter()
                .all(|m| ep_members.contains(m.as_str()));
            if all_covered {
                let _ = self
                    .unwrap_and_cache_channel_epoch(host_node, channel, &ep, link.as_ref())
                    .await?;
                return Ok(ep.epoch);
            }
            // Membership changed -> rotate strictly to ep.epoch + 1!
            return self
                .create_or_rotate_channel_epoch(
                    host_node,
                    channel,
                    Some(ep.epoch),
                    &current_member_nodes,
                    link.as_ref(),
                )
                .await;
        }

        // No epoch yet -> mint epoch 1!
        self.create_or_rotate_channel_epoch(
            host_node,
            channel,
            None,
            &current_member_nodes,
            link.as_ref(),
        )
        .await
    }

    /// Explicitly rotates the E2EE room key for `(host_node, channel)` strictly to `latest + 1`
    /// for all current channel member nodes.
    pub async fn rotate_channel_epoch(
        &self,
        host_node: &str,
        channel: &str,
    ) -> Result<u64, NodeError> {
        let link = if host_node == self.config.node_id.as_str() {
            None
        } else {
            Some(self.require_peer_link(host_node).await?)
        };
        let members = self
            .fetch_channel_member_nodes(host_node, channel, link.as_ref())
            .await?;
        let prev_epoch = if let Some(ref l) = link {
            l.get_channel_epoch(channel, None).await?.map(|e| e.epoch)
        } else {
            self.db()
                .channels()
                .latest_epoch(host_node, channel)?
                .map(|e| e.epoch)
        };
        self.create_or_rotate_channel_epoch(host_node, channel, prev_epoch, &members, link.as_ref())
            .await
    }

    async fn fetch_channel_member_nodes(
        &self,
        host_node: &str,
        channel: &str,
        link: Option<&Arc<PeerLink>>,
    ) -> Result<Vec<String>, NodeError> {
        let addresses = if let Some(l) = link {
            let resp = l.list_channels(Some(channel)).await?;
            resp.channels
                .into_iter()
                .find(|c| c.channel == channel)
                .map(|c| c.members)
                .unwrap_or_default()
        } else {
            self.db().channels().members(host_node, channel)?
        };
        let mut nodes: BTreeSet<String> = BTreeSet::new();
        for addr in addresses {
            if let Some((nid, _)) = parse_address(&addr) {
                nodes.insert(nid.to_string());
            }
        }
        nodes.insert(self.config.node_id.to_string());
        Ok(nodes.into_iter().collect())
    }

    async fn create_or_rotate_channel_epoch(
        &self,
        host_node: &str,
        channel: &str,
        prev_epoch: Option<u64>,
        member_nodes: &[String],
        link: Option<&Arc<PeerLink>>,
    ) -> Result<u64, NodeError> {
        let (room_key, signed_bundle) = self
            .build_room_epoch_bundle(
                EpochScope::Channel,
                host_node,
                channel,
                prev_epoch,
                member_nodes,
                link,
            )
            .await?;
        let new_epoch = room_key.epoch();

        if let Some(l) = link {
            l.put_channel_epoch(&PutChannelEpochRequest {
                channel: channel.to_string(),
                epoch: new_epoch,
                bundle: signed_bundle.clone(),
                members: member_nodes.to_vec(),
            })
            .await?;
        }

        // Persist epoch locally & cache zeroized RoomEpochKey.
        let now = now_ms();
        {
            let db = self.db();
            let _ = db.channels().put_epoch(
                &ChannelEpochInput {
                    host_node: host_node.to_string(),
                    channel: channel.to_string(),
                    epoch: new_epoch,
                    creator_node_id: self.config.node_id.to_string(),
                    key_envelope_json: serde_json::to_string(&signed_bundle)?,
                    members: member_nodes.to_vec(),
                    signature: signed_bundle.sig.clone(),
                },
                now,
            );
        }
        self.cache_room_key("channel", host_node, channel, room_key);
        Ok(new_epoch)
    }

    pub(super) async fn get_or_fetch_channel_room_key(
        &self,
        host_node: &str,
        channel: &str,
        epoch: u64,
        link: Option<&Arc<PeerLink>>,
    ) -> Result<RoomEpochKey, NodeError> {
        if let Some(k) = self.cached_room_key("channel", host_node, channel, epoch) {
            return Ok(k);
        }
        let stored = if let Some(l) = link {
            l.get_channel_epoch(channel, Some(epoch)).await?
        } else {
            self.db().channels().get_epoch(host_node, channel, epoch)?
        }
        .ok_or_else(|| {
            NodeError::NotFound(format!(
                "channel epoch {epoch} not found for '{host_node}/{channel}'"
            ))
        })?;
        self.unwrap_and_cache_channel_epoch(host_node, channel, &stored, link)
            .await
    }

    async fn unwrap_and_cache_channel_epoch(
        &self,
        host_node: &str,
        channel: &str,
        stored: &ChannelEpoch,
        link: Option<&Arc<PeerLink>>,
    ) -> Result<RoomEpochKey, NodeError> {
        let copy = self
            .open_and_cache_room_epoch(
                EpochScope::Channel,
                host_node,
                channel,
                &stored.creator_node_id,
                &stored.key_envelope_json,
                link,
            )
            .await?;
        // Persist verified epoch locally as well.
        {
            let db = self.db();
            let _ = db.channels().put_epoch(
                &ChannelEpochInput {
                    host_node: host_node.to_string(),
                    channel: channel.to_string(),
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

    /// Posts a message to a `#channel`, transparently encrypting with `channel.e2ee.v1`
    /// under the latest Signed Epoch Room Key (zero `[#channel]` text mutation, zero plaintext
    /// in hub `node.sqlite`).
    pub async fn post_channel(
        &self,
        qualified_channel: &str,
        from_handle: &str,
        plaintext: &str,
    ) -> Result<PostChannelResult, NodeError> {
        let (host_node, channel) = self.resolve_channel_coord(qualified_channel).await?;
        let post_id = uuid_v4();
        let from_addr = format_address(self.config.node_id.as_str(), from_handle);

        if host_node == self.config.node_id.as_str() {
            self.enforce_channel_write_policy(
                &channel,
                self.config.node_id.as_str(),
                Some(&from_addr),
            )?;
            let res = {
                let db = self.db();
                db.channels().post(
                    &PostChannelInput {
                        id: post_id.clone(),
                        host_node: host_node.clone(),
                        channel: channel.clone(),
                        from_node: self.config.node_id.to_string(),
                        from_handle: from_handle.to_string(),
                        text: plaintext.to_string(),
                        e2ee_epoch: None,
                    },
                    now_ms(),
                )?
            };
            self.fanout_notify_channel_recipients(&res.delivered_to)
                .await;
            return Ok(res);
        }

        let link = self.require_peer_link(&host_node).await?;
        let supports_e2ee =
            self.peer_supports_cap(&host_node, &CapabilityToken::ChannelE2eeV1, Some(&link));
        let policy = self.effective_e2ee_policy_for_peer(&host_node);
        if policy == E2eePolicy::Required && !supports_e2ee {
            return Err(NodeError::CapabilityUnsupported(Box::new(
                ProblemDetails::capability_unsupported(
                    &CapabilityToken::ChannelE2eeV1,
                    &host_node,
                    &self.config.hyphae_version,
                    "unknown",
                    Some("2.0.0"),
                    true,
                    None,
                ),
            )));
        }
        let use_e2ee = policy != E2eePolicy::Disabled && supports_e2ee;

        let (wire_text, content_type, e2ee_epoch) = if use_e2ee {
            // Check latest epoch on hub: if one already exists and covers us, use it;
            // if none exists yet, attempt to mint epoch 1 (note: on an announcement channel,
            // a non-writer attempting to post will get 403 channel_read_only cleanly!).
            let epoch_num = match link.get_channel_epoch(&channel, None).await? {
                Some(ep) => {
                    let _ = self
                        .unwrap_and_cache_channel_epoch(&host_node, &channel, &ep, Some(&link))
                        .await?;
                    ep.epoch
                }
                None => self.ensure_channel_epoch(&host_node, &channel).await?,
            };
            let room_key = self
                .get_or_fetch_channel_room_key(&host_node, &channel, epoch_num, Some(&link))
                .await?;
            let ctx = ChannelContext {
                host_node: &host_node,
                channel: &channel,
                msg_id: &post_id,
                sender: &from_addr,
            };
            let env = seal_channel_message(
                &ctx,
                plaintext.as_bytes(),
                &room_key,
                &self.identity.signing,
            )?;
            (
                serde_json::to_string(&env)?,
                Some(CONTENT_TYPE_E2EE_JSON.to_string()),
                Some(epoch_num),
            )
        } else {
            (plaintext.to_string(), Some("text/plain".to_string()), None)
        };

        link.post_channel(&ChannelPostRequest {
            id: post_id,
            channel,
            from_handle: from_handle.to_string(),
            text: wire_text,
            content_type,
            e2ee_epoch,
        })
        .await
    }

    /// Server-side handler for `POST /v1/channels/post`: enforces BOTH `channel:post` scope AND
    /// `ChannelMode::Announcement` writer allowlist (`403 channel_read_only`) fail-closed!
    pub async fn handle_server_channel_post(
        &self,
        caller: &AuthenticatedPeer,
        req: ChannelPostRequest,
    ) -> Result<PostChannelResult, NodeError> {
        let channel = Channel::normalize(&req.channel)?.into_inner();
        self.require_scope(
            caller,
            caller.scopes.may_channel_post(&channel),
            &format!("channel:post={channel}"),
        )?;

        let sender_addr = format_address(&caller.peer_id, &req.from_handle);
        // CRITICAL SECURITY INVARIANT: Even a peer holding `channel:post=*` is blocked from
        // posting to a `ChannelMode::Announcement` room unless explicitly in `writers`!
        self.enforce_channel_write_policy(&channel, &caller.peer_id, Some(&sender_addr))?;

        let now = now_ms();
        let res = {
            let db = self.db();
            db.channels().post(
                &PostChannelInput {
                    id: req.id.clone(),
                    host_node: self.config.node_id.to_string(),
                    channel: channel.clone(),
                    from_node: caller.peer_id.clone(),
                    from_handle: req.from_handle.clone(),
                    text: req.text.clone(),
                    e2ee_epoch: req.e2ee_epoch,
                },
                now,
            )?
        };
        self.fanout_notify_channel_recipients(&res.delivered_to)
            .await;
        Ok(res)
    }

    async fn fanout_notify_channel_recipients(&self, delivered_to: &[String]) {
        let mut notified_nodes = HashSet::new();
        for addr in delivered_to {
            if let Some((nid, _)) = parse_address(addr) {
                if nid == self.config.node_id.as_str() {
                    // Direct local recipient on this node
                    let pending = {
                        let db = self.db();
                        db.messages().list_pending(addr).unwrap_or_default()
                    };
                    for msg in pending {
                        let msg_id = msg.id.clone();
                        if self
                            .handle_inbound_peer_message(self.config.node_id.as_str(), msg)
                            .await
                            .is_ok()
                        {
                            let db = self.db();
                            let _ = db.messages().ack(
                                self.config.node_id.as_str(),
                                &msg_id,
                                &AckOutcome::Delivered,
                                now_ms(),
                            );
                        }
                    }
                } else if notified_nodes.insert(nid.to_string()) {
                    self.notify_peer_inbox(nid);
                }
            }
        }
        self.notify_scheduler();
    }

    /// Server-side handler for `POST /v1/channel-epochs`: verifies writer policy (announcement
    /// rooms restrict epoch rotation to authorized writers), verifies creator Ed25519 signature,
    /// and stores monotonically in `channel_epochs`.
    pub fn handle_server_put_channel_epoch(
        &self,
        caller: &AuthenticatedPeer,
        req: PutChannelEpochRequest,
    ) -> Result<ChannelEpoch, NodeError> {
        let channel = Channel::normalize(&req.channel)?.into_inner();
        self.require_scope(
            caller,
            caller.scopes.may_channel_post(&channel),
            &format!("channel:post={channel}"),
        )?;
        self.enforce_channel_node_write_policy(&channel, &caller.peer_id)?;

        self.verify_uploaded_epoch_bundle(
            EpochScope::Channel,
            &caller.peer_id,
            &channel,
            req.epoch,
            &req.bundle,
        )?;
        let saved = {
            let db = self.db();
            db.channels().put_epoch(
                &ChannelEpochInput {
                    host_node: self.config.node_id.to_string(),
                    channel,
                    epoch: req.epoch,
                    creator_node_id: caller.peer_id.clone(),
                    key_envelope_json: serde_json::to_string(&req.bundle)?,
                    members: req.members,
                    signature: req.bundle.sig,
                },
                now_ms(),
            )?
        };
        Ok(saved)
    }
}
