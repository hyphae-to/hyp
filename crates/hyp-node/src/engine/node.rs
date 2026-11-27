//! Unified Rust `Node` engine (`UnifiedNode`):
//! - Persistent Ed25519 + X25519 identity via `SecretStore`
//! - Single WAL `node.sqlite` (`NodeDb`) + exact zero-polling `next_deadline_ms()` scheduler
//! - Transparent E2EE for DMs (`dm.e2ee.v1`), `#channels` (`channel.e2ee.v1`),
//!   Shared KV (`kv.e2ee.v1`), and streaming file transfers (`transfer.stream.v2`)
//! - Read-only announcement `#channels` (`ChannelMode::Announcement`) enforced fail-closed
//!   at both hub/server and E2EE recipient boundaries
//! - Subscription pushdown compilation, upstream sync, diagnostics, and loop/hop guards
//! - Signed capability manifests (public/authenticated scoping, ETag stability, anti-rollback,
//!   permanent E2EE anti-downgrade ratcheting)
//! - Direct P2P mutual pairing (`hp2p1_`) and Org Admin-CA pairing (`am2_`).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use http::header::AUTHORIZATION;
use http::{HeaderMap, Method, Request};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::{Notify, RwLock, broadcast, watch};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use hyp_crypto::compat_v1::{
    PairingCodeV1, derive_pairing_key_v1, format_pairing_code_v1, parse_pairing_code_v1,
};
use hyp_crypto::e2ee::{
    ChannelContext, ChannelEnvelopeV1, DmContext, DmEnvelopeV1, EpochMember, EpochScope,
    RoomEpochKey, SignedEpochKeyBundle, create_epoch_bundle, open_channel_message, open_dm,
    open_epoch_bundle, rotate_epoch_bundle, seal_dm,
};
use hyp_crypto::human::{
    DelegatedPairProofV1, HumanRevocationPayloadV1, NodeCertPayloadV1, SignedHumanRevocationV1,
    SignedNodeCertV1, decode_hcert1, decode_hjoin1, encode_hcert1, node_cert_sha256,
    sign_delegated_pair_proof, sign_node_cert, verify_delegated_pair_proof, verify_human_invite,
    verify_human_invite_claim, verify_human_revocation, verify_node_cert,
};
use hyp_crypto::jcs::to_canonical_json;
use hyp_crypto::pairing::{
    AdminInviteV2, GrantV2, P2P_SECRET_BYTES, P2pOfferToken, P2pPairConfirmation, P2pPairResponse,
    create_p2p_confirmation, create_p2p_offer, create_p2p_response, decode_am2, decode_hp2p1,
    encode_am2_with_signed_grant, encode_hp2p1, extract_am2_signed_grant, sign_grant_v2,
    verify_grant_v2, verify_p2p_confirmation, verify_p2p_response,
};
use hyp_crypto::rfc3339::{format_rfc3339_millis, parse_rfc3339_millis};
use hyp_crypto::{
    Ed25519KeyPair, Ed25519PublicKey, NodeIdentityKeys, OkpJwk as CryptoOkpJwk, SecretStore,
    SignedPayload, X25519PublicKey,
};
use hyp_proto::address::{Channel, Handle, LOCAL_NODE_ID, NodeId, PeerTarget};
use hyp_proto::cloudevent::{
    CONTENT_TYPE_E2EE_JSON, CloudEvent as ProtoCloudEvent, ProvenanceError, TYPE_CHANNEL_V1,
    TYPE_DM_V1,
};
use hyp_proto::manifest::{
    AdvertisedKvNamespace, AdvertisedResources, AdvertisedTopic, CapabilityToken, E2eePolicy,
    ManifestIdentity, ManifestPolicy, NegotiatedSession, NodeManifestPayload, PeerCapabilitiesView,
    PeerTrustHistory, SignedNodeManifest, negotiate_capabilities,
};
use hyp_proto::problem::ProblemDetails;
use hyp_proto::scopes::{
    ScopePreset, ScopeSet, expand_v2_scopes, matches_node_prefix, validate_delegated_human_scopes,
};
use hyp_store::{
    AckOutcome, EnqueueMessage, GateAuditInput, GateDecision as StoreGateDecision, GateDirection,
    GateState, GrantDirection, GrantInput, GrantRecord, HandleRecord, HumanAuthorityInput,
    HumanAuthorityRole, HumanAuthorityStatus, HumanClaimKind, HumanDelegationPolicyInput,
    HumanNodeCertInput, KeyStatus, KeyUse, MailboxEntry, MailboxInsert, MailboxKind,
    MailboxPutResult, ManifestCacheUpdate, MessageRecord, NodeDb, PeerInput, PeerKeyInput,
    PeerRecord, PeerStatus, Session, StoreError, TrustTier, format_address, now_ms, parse_address,
    sha256_hex, uuid_v4,
};

use crate::adapters::{
    AdapterError, AdapterHealth, BoxFuture, GitHubPublicAdapter, GitHubWebhookAdapter, NodeAdapter,
    NodeAdapterHost, PublishErrorCode, PublishOutcome, PublishStatus,
};
use crate::engine::config::{
    ChannelMode, ChannelPolicy, NodeConfig, NodeError, NodeProfile, crypto_jwk_to_proto,
    profile_to_store,
};
use crate::engine::drop_relay::DropRelay;
use crate::engine::http_util::{HttpClient, compute_etag, full_body};
use crate::engine::peer_link::{
    AuthClaimReply, AuthClaimRequest, DelegatedPairReply, DelegatedPairRequest, GuestPairReply,
    GuestPairRequest, KeyRegPayloadV2, MAX_JSON_RESPONSE_BYTES, ManifestFetchOutcome,
    P2pPairServerReply, PairBindingV2, PairRequestV2, PairServerReply, PeerAuth,
    PeerKeyDirectoryEntry, PeerLink, PostMessageRequest, PutKeyRequest, guest_pair_proof_canonical,
    http_auth_signing_input, spawn_sse_worker,
};
use crate::engine::wake::SystemWakeEvent;
use crate::gates::SecurityGatePipeline;

mod channels;
mod human_drops;
mod kv;
mod kv_inspect;
mod streams;
mod transfers;

pub use streams::{SubscribeRequest, SubscribeResult};
pub use transfers::TransferSendResult;
use transfers::sweep_stale_transfer_staging;

pub use human_drops::IngestedHumanDrop;

pub use kv::KvWriteRequest;

pub use kv_inspect::{
    KvInspection, KvKeyInspection, KvKeyPage, KvNamespaceInspection, KvValuePreview,
};

const MANIFEST_TTL_MS: i64 = 24 * 60 * 60 * 1000;
const MANIFEST_WINDOW_REFRESH_MS: i64 = 60 * 60 * 1000;
const HTTP_AUTH_SKEW_MS: i64 = 5 * 60 * 1000;
const MAX_HTTP_AUTH_NONCES: usize = 16_384;

/// Authenticated remote peer context attached to incoming HTTP requests.
#[derive(Debug, Clone)]
pub struct AuthenticatedPeer {
    pub peer_id: String,
    pub scopes: ScopeSet,
    pub trust_tier: TrustTier,
}

/// Action verified by [`UnifiedNode::authorize_peer_action`] across both inbound HTTP `POST`
/// handlers and pulled outbound-only SSE `/v1/inbox` delivery (`P1-6`, `P1-18`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerAction<'a> {
    DmSend {
        to_addr: &'a str,
    },
    ChannelPost {
        channel: &'a str,
    },
    TransferSend {
        to_node: &'a str,
        bytes: Option<u64>,
    },
    StreamPublish {
        topic: &'a str,
    },
    StreamDeliver {
        topic: &'a str,
    },
    KvRead {
        namespace: &'a str,
        key: &'a str,
    },
    KvWrite {
        namespace: &'a str,
        key: &'a str,
    },
}

/// Summary returned after pairing and activating a `PeerLink`.
#[derive(Debug, Clone)]
pub struct PeerLinkInfo {
    pub peer_id: String,
    pub endpoint: String,
    pub negotiated: NegotiatedSession,
}

/// Summary returned by [`UnifiedNode::reconcile_peers`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerReconcileReport {
    /// Total number of connected outbound `PeerLink`s after reconciliation.
    pub active_peers: usize,
    /// Number of newly connected or updated (reconnected) `PeerLink`s spawned in this pass.
    pub added: usize,
    /// Number of stale, revoked, or removed `PeerLink`s cancelled in this pass.
    pub removed: usize,
    /// Sorted list of peer IDs with active outbound `PeerLink`s after reconciliation.
    pub connected_peers: Vec<String>,
    /// Non-fatal per-peer warnings (e.g., temporarily unreachable endpoints).
    pub warnings: Vec<String>,
}

/// Structured agent handle entry returned by [`UnifiedNode::discover_peer_handles`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DiscoveredPeerHandle {
    pub address: String,
    pub node_id: String,
    pub handle: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Connected peer/hub through which this remote handle was discovered (`None` for local handles).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
}

/// Result of `UnifiedNode::send_dm`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendDmResult {
    pub id: String,
    pub to: String,
    pub routed_via: String,
    pub encrypted: bool,
}

#[derive(Debug, Clone, Default)]
struct ManifestWindow {
    version: u64,
    issued_at_ms: i64,
}

/// Deterministic `SecretStore` key for a pending single-use Direct P2P offer (`hp2p1_`).
///
/// Shared between `UnifiedNode` and `hyp pair invite --mode p2p` so out-of-process CLI invites
/// can be verified and atomically claimed by a running node daemon without writing pairing nonces
/// to plaintext files.
pub fn p2p_offer_secret_name(offer_id: &str) -> String {
    let hash = sha256_hex(offer_id.as_bytes());
    format!("p2p-offer-{}", &hash[..16])
}

/// Composable Hyphae v2 Unified Rust `Node` engine.
pub struct UnifiedNode {
    config: NodeConfig,
    identity: Arc<NodeIdentityKeys>,
    secrets: SecretStore,
    db: Mutex<NodeDb>,
    drop_relay: Arc<DropRelay>,
    http_client: HttpClient,
    bound_addr: Mutex<Option<SocketAddr>>,
    peer_socket_path: Mutex<Option<PathBuf>>,
    manifest_window: Mutex<ManifestWindow>,
    room_keys: Mutex<HashMap<(String, String, String, u64), RoomEpochKey>>,
    min_epochs: Mutex<HashMap<(String, String, String), u64>>,
    kv_max_seen_version: Mutex<HashMap<(String, String, String), u64>>,
    remote_channel_policies: Mutex<HashMap<(String, String), ChannelPolicy>>,
    pending_p2p_offers: Mutex<HashMap<String, P2pOfferToken>>,
    seen_http_nonces: Mutex<HashMap<(String, String), i64>>,
    guest_join_timestamps: Mutex<VecDeque<i64>>,
    github_public: Mutex<Option<Arc<GitHubPublicAdapter>>>,
    github_webhooks: Mutex<BTreeMap<String, Arc<GitHubWebhookAdapter>>>,
    security_gate: Mutex<Arc<std::sync::RwLock<Option<Arc<SecurityGatePipeline>>>>>,
    peer_links: RwLock<HashMap<String, Arc<PeerLink>>>,
    sse_tasks: Mutex<HashMap<String, JoinHandle<()>>>,
    peer_reconcile_lock: tokio::sync::Mutex<()>,
    inbox_tx: broadcast::Sender<String>,
    local_inbox_tx: broadcast::Sender<String>,
    kv_metadata_tx: watch::Sender<()>,
    in_flight_by_peer: Mutex<HashMap<String, HashSet<String>>>,
    scheduler_notify: Arc<Notify>,
    wake_epoch: watch::Sender<u64>,
    last_wake: Mutex<Option<SystemWakeEvent>>,
    shutdown_tx: watch::Sender<bool>,
    scheduler_handle: Mutex<Option<JoinHandle<()>>>,
}

impl UnifiedNode {
    /// Opens (or initializes) a Unified `Node` backed by `<state_dir>/node.sqlite` and
    /// `SecretStore`, sweeps orphaned transfer staging files, and starts the exact
    /// zero-polling deadline scheduler loop.
    pub fn open(config: NodeConfig) -> Result<Arc<Self>, NodeError> {
        fs::create_dir_all(&config.state_dir)?;
        sweep_stale_transfer_staging(&config.state_dir);
        let secrets = match config.secret_backend {
            Some(backend) => SecretStore::new(&config.state_dir, backend),
            None => SecretStore::from_env(&config.state_dir),
        };
        let identity = Arc::new(secrets.load_or_create_node_keys(config.node_id.as_str())?);
        let db_path = config.state_dir.join("node.sqlite");
        let db = NodeDb::open_with_config(&db_path, config.store_config.clone())?;
        let _ = db.transfers().sweep_orphans();

        db.local()
            .ensure_metadata("node_id", config.node_id.as_str())?;
        match db.local().get_metadata("manifest_version")? {
            None => {
                db.local().set_metadata("manifest_version", "1")?;
            }
            Some(raw) => {
                // Bump manifest_version monotonically across restarts so a newly signed
                // `issued_at`/`expires_at` window or reloaded config never triggers same-version
                // equivocation (`ManifestRollback`) on reconnecting peers.
                let next = raw.parse::<u64>().unwrap_or(1).max(1).saturating_add(1);
                db.local()
                    .set_metadata("manifest_version", &next.to_string())?;
            }
        }

        // Seed declarative channel policies from NodeConfig without clobbering existing persisted ones.
        if !config.channel_policies.is_empty() {
            let mut merged = load_channel_policies_from_db(&db);
            for (ch, policy) in &config.channel_policies {
                let norm = Channel::normalize(ch)?.into_inner();
                merged.entry(norm).or_insert_with(|| policy.clone());
            }
            let json_str = serde_json::to_string(&merged)?;
            db.local().set_metadata("channel_policies", &json_str)?;
        }

        // Issue #25 (B6): Prune any stale remote-peer subscriptions targeting local-only topics
        // (e.g. if an operator previously had `exposeTopic: true` and flipped it back to `false`),
        // preserving all same-node local session subscriptions.
        if !config.local_only_topics.is_empty() {
            let my_id = config.node_id.as_str();
            let remote_peers: HashSet<String> = db
                .peers()
                .list_peers(None)?
                .into_iter()
                .map(|p| p.peer_id)
                .filter(|pid| pid != my_id)
                .collect();
            if !remote_peers.is_empty() {
                for sub in db.events().list_subscriptions(None)? {
                    if sub.origin_node == my_id
                        && config.local_only_topics.contains(&sub.topic)
                        && remote_peers.contains(&sub.subscriber)
                    {
                        let _ = db.events().delete_subscription(&sub.id);
                    }
                }
            }
        }

        // Persist our own public keys in peer_keys so self-verification works uniformly.
        let now = now_ms();
        let self_sign_jwk = identity.signing_jwk();
        let self_enc_jwk = identity.encryption_jwk();
        let _ = db.peers().upsert_peer_key(
            &PeerKeyInput {
                peer_id: config.node_id.to_string(),
                kid: identity.signing.kid(),
                key_use: KeyUse::Signing,
                jwk_json: serde_json::to_string(&self_sign_jwk)?,
                status: KeyStatus::Active,
                expires_at: None,
            },
            now,
        );
        let _ = db.peers().upsert_peer_key(
            &PeerKeyInput {
                peer_id: config.node_id.to_string(),
                kid: identity.encryption.kid(),
                key_use: KeyUse::Encryption,
                jwk_json: serde_json::to_string(&self_enc_jwk)?,
                status: KeyStatus::Active,
                expires_at: None,
            },
            now,
        );

        let http_client = HttpClient::new()?;
        let drop_relay = Arc::new(
            DropRelay::new(config.drop_relay.clone()).with_local_node_id(config.node_id.as_str()),
        );
        let (inbox_tx, _) = broadcast::channel(256);
        let (local_inbox_tx, _) = broadcast::channel(256);
        let (wake_epoch, _) = watch::channel(0u64);
        let (shutdown_tx, _) = watch::channel(false);

        let node = Arc::new(Self {
            config,
            identity,
            secrets,
            db: Mutex::new(db),
            drop_relay,
            http_client,
            bound_addr: Mutex::new(None),
            peer_socket_path: Mutex::new(None),
            manifest_window: Mutex::new(ManifestWindow::default()),
            room_keys: Mutex::new(HashMap::new()),
            min_epochs: Mutex::new(HashMap::new()),
            kv_max_seen_version: Mutex::new(HashMap::new()),
            remote_channel_policies: Mutex::new(HashMap::new()),
            pending_p2p_offers: Mutex::new(HashMap::new()),
            seen_http_nonces: Mutex::new(HashMap::new()),
            guest_join_timestamps: Mutex::new(VecDeque::new()),
            github_public: Mutex::new(None),
            github_webhooks: Mutex::new(BTreeMap::new()),
            security_gate: Mutex::new(Arc::new(std::sync::RwLock::new(None))),
            peer_links: RwLock::new(HashMap::new()),
            sse_tasks: Mutex::new(HashMap::new()),
            peer_reconcile_lock: tokio::sync::Mutex::new(()),
            inbox_tx,
            local_inbox_tx,
            kv_metadata_tx: watch::channel(()).0,
            in_flight_by_peer: Mutex::new(HashMap::new()),
            scheduler_notify: Arc::new(Notify::new()),
            wake_epoch,
            last_wake: Mutex::new(None),
            shutdown_tx,
            scheduler_handle: Mutex::new(None),
        });

        node.start_scheduler();
        Ok(node)
    }

    /// Spawns the exact zero-polling `next_deadline_ms()` deadline scheduler task.
    fn start_scheduler(self: &Arc<Self>) {
        if tokio::runtime::Handle::try_current().is_err() {
            return;
        }
        let node = Arc::clone(self);
        let mut shutdown_rx = self.shutdown_tx.subscribe();
        let handle = tokio::spawn(async move {
            let mut first_tick = true;
            loop {
                if *shutdown_rx.borrow() {
                    break;
                }
                let now = now_ms();
                let step = {
                    let db = node.db();
                    let tick = db.tick(now);
                    let next = db.next_deadline_ms(now);
                    (tick, next)
                };

                let mut closed_batches = false;
                if let (Ok(report), _) = &step {
                    if report.kv_expired > 0 {
                        node.notify_kv_metadata_change();
                    }
                    if report.events.batches_closed > 0 {
                        closed_batches = true;
                        node.notify_all_inbox_subscribers();
                    }
                }
                if first_tick || closed_batches {
                    first_tick = false;
                    let _ = node.flush_pending_local_topic_batches_inner(false);
                }
                node.drop_relay.sweep_expired(now);

                let next_deadline = step.1.ok().flatten();
                match next_deadline {
                    None => {
                        // Completely idle: park indefinitely with zero polling wakeups!
                        tokio::select! {
                            _ = node.scheduler_notify.notified() => {}
                            _ = shutdown_rx.changed() => {
                                if *shutdown_rx.borrow() { break; }
                            }
                        }
                    }
                    Some(deadline_ms) => {
                        let wait_ms = (deadline_ms - now_ms()).max(0) as u64;
                        if wait_ms == 0 {
                            tokio::task::yield_now().await;
                            continue;
                        }
                        let sleep = tokio::time::sleep(Duration::from_millis(wait_ms));
                        tokio::pin!(sleep);
                        tokio::select! {
                            _ = &mut sleep => {}
                            _ = node.scheduler_notify.notified() => {}
                            _ = shutdown_rx.changed() => {
                                if *shutdown_rx.borrow() { break; }
                            }
                        }
                    }
                }
            }
        });
        *self
            .scheduler_handle
            .lock()
            .expect("scheduler_handle lock poisoned") = Some(handle);
    }

    /// Attaches and starts a live demand-driven [`GitHubPublicAdapter`] on this `UnifiedNode`,
    /// routing published CloudEvents straight into [`UnifiedNode::publish_event`], advertising its
    /// topic in authenticated manifests, and syncing any already-persisted subscriptions.
    pub async fn attach_github_public(
        self: &Arc<Self>,
        adapter: Arc<GitHubPublicAdapter>,
    ) -> Result<(), NodeError> {
        let host: Arc<dyn NodeAdapterHost> = Arc::new(UnifiedNodeAdapterHost {
            node: Arc::downgrade(self),
        });
        adapter.start(host).await.map_err(|e| {
            NodeError::BadRequest(format!("failed to start github-public adapter: {e}"))
        })?;
        *self
            .github_public
            .lock()
            .expect("github_public lock poisoned") = Some(Arc::clone(&adapter));
        self.sync_github_public_subscriptions(&adapter).await?;
        Ok(())
    }

    /// Returns the currently attached [`GitHubPublicAdapter`], if any.
    pub fn github_public_adapter(&self) -> Option<Arc<GitHubPublicAdapter>> {
        self.github_public
            .lock()
            .expect("github_public lock poisoned")
            .clone()
    }

    /// Attaches and starts a compiled-in pure-Rust [`GitHubWebhookAdapter`].
    pub async fn attach_github_webhook(
        self: &Arc<Self>,
        adapter: Arc<GitHubWebhookAdapter>,
    ) -> Result<(), NodeError> {
        let host: Arc<dyn NodeAdapterHost> = Arc::new(UnifiedNodeAdapterHost {
            node: Arc::downgrade(self),
        });
        adapter.start(host).await.map_err(|e| {
            NodeError::BadRequest(format!("failed to start github-webhook adapter: {e}"))
        })?;
        self.github_webhooks
            .lock()
            .expect("github_webhooks lock poisoned")
            .insert(adapter.id().to_string(), adapter);
        Ok(())
    }

    /// Looks up a registered [`GitHubWebhookAdapter`] by optional ID.
    pub fn github_webhook_adapter(&self, id: Option<&str>) -> Option<Arc<GitHubWebhookAdapter>> {
        let map = self
            .github_webhooks
            .lock()
            .expect("github_webhooks lock poisoned");
        match id {
            Some(k) => map.get(k).cloned(),
            None => {
                if map.len() == 1 {
                    map.values().next().cloned()
                } else {
                    map.get("github")
                        .or_else(|| map.get("github-webhook"))
                        .cloned()
                }
            }
        }
    }

    /// Attaches a standalone [`SecurityGatePipeline`] to this `UnifiedNode` (used for outbound
    /// bridge DLP checks and stage-before-unpack inbound transfer screening).
    pub fn set_security_gate(&self, gate: Option<Arc<SecurityGatePipeline>>) {
        let slot = self
            .security_gate
            .lock()
            .expect("security_gate lock poisoned")
            .clone();
        *slot.write().expect("security_gate rwlock poisoned") = gate;
    }

    /// Shares a live hot-reloadable [`SecurityGatePipeline`] slot (e.g. `LocalDaemon::gate_slot()`).
    pub fn set_shared_security_gate(
        &self,
        slot: Arc<std::sync::RwLock<Option<Arc<SecurityGatePipeline>>>>,
    ) {
        *self
            .security_gate
            .lock()
            .expect("security_gate lock poisoned") = slot;
    }

    /// Returns the currently active [`SecurityGatePipeline`], if any.
    pub fn security_gate(&self) -> Option<Arc<SecurityGatePipeline>> {
        let slot = self
            .security_gate
            .lock()
            .expect("security_gate lock poisoned")
            .clone();
        slot.read().expect("security_gate rwlock poisoned").clone()
    }

    /// Gracefully stops any attached live source adapters (e.g. `GitHubPublicAdapter` and
    /// compiled-in webhook adapters).
    pub async fn shutdown_adapters(&self) {
        let adapter = self
            .github_public
            .lock()
            .expect("github_public lock poisoned")
            .take();
        if let Some(gh) = adapter {
            let _ = gh.stop().await;
        }
        let gh_webhooks: Vec<Arc<GitHubWebhookAdapter>> = {
            let mut map = self
                .github_webhooks
                .lock()
                .expect("github_webhooks lock poisoned");
            std::mem::take(&mut *map).into_values().collect()
        };
        for a in gh_webhooks {
            let _ = a.stop().await;
        }
    }

    /// Gracefully stops the scheduler, attached source adapters, and all background SSE peer links.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        self.http_client.shutdown_ssh();
        self.scheduler_notify.notify_waiters();
        let gh_opt = self
            .github_public
            .lock()
            .expect("github_public lock poisoned")
            .take();
        let gh_webhooks: Vec<Arc<GitHubWebhookAdapter>> = {
            let mut map = self
                .github_webhooks
                .lock()
                .expect("github_webhooks lock poisoned");
            std::mem::take(&mut *map).into_values().collect()
        };
        if gh_opt.is_some() || !gh_webhooks.is_empty() {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    if let Some(gh) = gh_opt {
                        let _ = gh.stop().await;
                    }
                    for a in gh_webhooks {
                        let _ = a.stop().await;
                    }
                });
            }
        }
        if let Some(h) = self
            .scheduler_handle
            .lock()
            .expect("scheduler_handle lock poisoned")
            .take()
        {
            h.abort();
        }
        let tasks = self.sse_tasks.lock().expect("sse_tasks lock poisoned");
        for handle in tasks.values() {
            handle.abort();
        }
    }

    pub fn node_id(&self) -> &NodeId {
        &self.config.node_id
    }

    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// Returns `true` iff `topic` is marked local-only (`exposeTopic: false`), blocking
    /// remote peer advertisement in `/v1/manifest`, remote `PUT /v1/subscriptions` / `POST /v1/events`,
    /// and SSE batch fan-out to remote peers.
    pub fn is_local_only_topic(&self, topic: &str) -> bool {
        let bare = topic
            .strip_prefix(&format!("{LOCAL_NODE_ID}."))
            .unwrap_or(topic);
        self.config.local_only_topics.contains(bare)
    }

    pub fn identity(&self) -> &NodeIdentityKeys {
        &self.identity
    }

    pub fn secret_store(&self) -> &SecretStore {
        &self.secrets
    }

    pub fn drop_relay(&self) -> Arc<DropRelay> {
        Arc::clone(&self.drop_relay)
    }

    pub fn db(&self) -> MutexGuard<'_, NodeDb> {
        self.db.lock().expect("NodeDb mutex poisoned")
    }

    pub fn http_client(&self) -> &HttpClient {
        &self.http_client
    }

    pub(crate) fn set_bound_addr(&self, addr: SocketAddr) {
        *self.bound_addr.lock().expect("bound_addr lock poisoned") = Some(addr);
    }

    #[cfg(unix)]
    pub(crate) fn set_peer_socket_path(&self, path: PathBuf) {
        *self
            .peer_socket_path
            .lock()
            .expect("peer_socket_path lock poisoned") = Some(path);
    }

    /// Returns the bound Unix peer socket path (`peer.sock`) if [`UnifiedNode::serve_unix`] is active.
    pub fn peer_socket_path(&self) -> Option<PathBuf> {
        self.peer_socket_path
            .lock()
            .expect("peer_socket_path lock poisoned")
            .clone()
    }

    /// Returns this node's public HTTP(S) origin (explicit `public_endpoint` or bound loopback addr).
    pub fn endpoint_url(&self) -> String {
        if let Some(ref ep) = self.config.public_endpoint {
            return ep.trim_end_matches('/').to_string();
        }
        if let Some(addr) = *self.bound_addr.lock().expect("bound_addr lock poisoned") {
            return format!("http://{addr}");
        }
        if let Some(addr) = self.config.bind_addr {
            return format!("http://{addr}");
        }
        "http://127.0.0.1:0".to_string()
    }

    pub(crate) fn shutdown_receiver(&self) -> watch::Receiver<bool> {
        self.shutdown_tx.subscribe()
    }

    pub(crate) fn subscribe_peer_inbox_wakeups(&self) -> broadcast::Receiver<String> {
        self.inbox_tx.subscribe()
    }

    /// Subscribes to zero-polling wakeups when new items land in any local session mailbox.
    pub fn subscribe_local_inbox(&self) -> broadcast::Receiver<String> {
        self.local_inbox_tx.subscribe()
    }

    /// Subscribes to the shared monotonic system wake epoch incremented whenever the host
    /// resumes from sleep/suspend (`PeerLink` SSE workers and external Drop Relay watchers
    /// observe this channel to immediately abort half-open sockets and reset backoff).
    pub fn subscribe_wake_epoch(&self) -> watch::Receiver<u64> {
        self.wake_epoch.subscribe()
    }

    /// Returns the current monotonic system wake epoch (`0` until the first wake event).
    pub fn current_wake_epoch(&self) -> u64 {
        *self.wake_epoch.borrow()
    }

    /// Returns the most recent [`SystemWakeEvent`] observed by this node, if any.
    pub fn last_system_wake(&self) -> Option<SystemWakeEvent> {
        *self.last_wake.lock().expect("last_wake lock poisoned")
    }

    /// Signals a host sleep/wake recovery pass:
    /// 1. Increments `wake_epoch` so all `PeerLink` SSE workers and external Drop Relay SSE
    ///    watchers immediately abort half-open sockets, reset backoff, and reconnect.
    /// 2. Wakes any server-side peer inbox SSE streams.
    /// 3. Sweeps pending local topic batches whose coalesce windows elapsed during sleep.
    /// 4. Kicks the exact zero-polling deadline scheduler immediately.
    ///
    /// Returns the newly incremented `wake_epoch`.
    pub fn notify_system_wake(&self, slept_for: Duration) -> u64 {
        let ev = SystemWakeEvent {
            slept_for,
            woke_at_ms: now_ms(),
        };
        *self.last_wake.lock().expect("last_wake lock poisoned") = Some(ev);
        let mut next_epoch = 0u64;
        self.wake_epoch.send_modify(|epoch| {
            *epoch = epoch.saturating_add(1);
            next_epoch = *epoch;
        });
        self.notify_all_inbox_subscribers();
        let _ = self.flush_pending_local_topic_batches_inner(false);
        self.notify_scheduler();
        next_epoch
    }

    /// Immediately wakes the background zero-polling deadline scheduler loop.
    pub fn wake_scheduler(&self) {
        self.scheduler_notify.notify_one();
    }

    pub(crate) fn notify_scheduler(&self) {
        self.scheduler_notify.notify_one();
    }

    pub(crate) fn notify_peer_inbox(&self, peer_id: &str) {
        let _ = self.inbox_tx.send(peer_id.to_string());
    }

    pub(crate) fn notify_all_inbox_subscribers(&self) {
        let _ = self.inbox_tx.send("*".to_string());
    }

    pub(crate) fn notify_local_session(&self, session_id: &str) {
        let _ = self.local_inbox_tx.send(session_id.to_string());
    }

    pub(crate) fn mark_in_flight(&self, peer_id: &str, key: String) -> bool {
        let mut map = self
            .in_flight_by_peer
            .lock()
            .expect("in_flight_by_peer lock poisoned");
        map.entry(peer_id.to_string()).or_default().insert(key)
    }

    pub(crate) fn is_in_flight(&self, peer_id: &str, key: &str) -> bool {
        let map = self
            .in_flight_by_peer
            .lock()
            .expect("in_flight_by_peer lock poisoned");
        map.get(peer_id).is_some_and(|set| set.contains(key))
    }

    pub(crate) fn clear_in_flight(&self, peer_id: &str, key: &str) {
        let mut map = self
            .in_flight_by_peer
            .lock()
            .expect("in_flight_by_peer lock poisoned");
        if let Some(set) = map.get_mut(peer_id) {
            set.remove(key);
        }
    }

    pub(crate) fn clear_all_in_flight_for_peer(&self, peer_id: &str) {
        let mut map = self
            .in_flight_by_peer
            .lock()
            .expect("in_flight_by_peer lock poisoned");
        map.remove(peer_id);
    }

    // ========================================================================
    // Channel Policy (Open vs Read-Only Announcement Channels)
    // ========================================================================

    /// Sets and persists the access policy for `channel` (e.g. `ChannelPolicy::announcement(...)`)
    /// in `node.sqlite`, bumping the node's monotonic manifest version.
    pub fn set_channel_policy(
        &self,
        channel: &str,
        policy: ChannelPolicy,
    ) -> Result<(), NodeError> {
        let normalized = Channel::normalize(channel)?.into_inner();
        {
            let db = self.db();
            let mut policies = load_channel_policies_from_db(&db);
            policies.insert(normalized, policy);
            let encoded = serde_json::to_string(&policies)?;
            db.local().set_metadata("channel_policies", &encoded)?;
        }
        let _ = self.bump_manifest_version()?;
        Ok(())
    }

    /// Returns the effective `ChannelPolicy` for `channel` on this node (defaults to `Open`).
    pub fn get_channel_policy(&self, channel: &str) -> ChannelPolicy {
        let Ok(norm) = Channel::normalize(channel) else {
            return ChannelPolicy::open();
        };
        let key = norm.as_str();
        let persisted = {
            let db = self.db();
            load_channel_policies_from_db(&db)
        };
        if let Some(p) = persisted.get(key) {
            return p.clone();
        }
        if let Some(p) = self.config.channel_policies.get(key) {
            return p.clone();
        }
        ChannelPolicy::open()
    }

    /// Lists all configured channel policies on this node.
    pub fn list_channel_policies(&self) -> BTreeMap<String, ChannelPolicy> {
        let mut out = BTreeMap::new();
        for (ch, policy) in &self.config.channel_policies {
            if let Ok(norm) = Channel::normalize(ch) {
                out.insert(norm.into_inner(), policy.clone());
            }
        }
        let persisted = {
            let db = self.db();
            load_channel_policies_from_db(&db)
        };
        for (ch, policy) in persisted {
            out.insert(ch, policy);
        }
        out
    }

    fn cache_remote_channel_policy(&self, host_node: &str, channel: &str, policy: ChannelPolicy) {
        let mut map = self
            .remote_channel_policies
            .lock()
            .expect("remote_channel_policies lock poisoned");
        map.insert((host_node.to_string(), channel.to_string()), policy);
    }

    fn get_remote_channel_policy(&self, host_node: &str, channel: &str) -> Option<ChannelPolicy> {
        let map = self
            .remote_channel_policies
            .lock()
            .expect("remote_channel_policies lock poisoned");
        map.get(&(host_node.to_string(), channel.to_string()))
            .cloned()
    }

    /// Enforces `ChannelMode::Announcement` writer allowlist fail-closed, returning RFC 9457
    /// `403 channel_read_only` (with optional `escalationNote`) for unauthorized writers.
    pub fn enforce_channel_write_policy(
        &self,
        channel: &str,
        writer_node_id: &str,
        writer_address: Option<&str>,
    ) -> Result<(), NodeError> {
        let policy = self.get_channel_policy(channel);
        if policy.is_authorized_writer(writer_node_id, writer_address) {
            return Ok(());
        }
        let missing = format!("channel:post={channel}");
        let escalation_note = self
            .config
            .escalation
            .resolve(&missing)
            .map(|n| n.as_str().to_string());
        Err(NodeError::ChannelReadOnly {
            channel: channel.to_string(),
            escalation_note,
        })
    }

    /// Enforces `ChannelMode::Announcement` node-level write authorization (used for epoch
    /// creation/rotation where bundles are signed by the node identity), permitting a node
    /// only when `<node-id>` or one of its `<node-id>/<handle>` addresses is in `writers`.
    pub fn enforce_channel_node_write_policy(
        &self,
        channel: &str,
        writer_node_id: &str,
    ) -> Result<(), NodeError> {
        let policy = self.get_channel_policy(channel);
        let enrolled_addrs: Vec<String> = {
            let db = self.db();
            db.messages()
                .list_handles(Some(writer_node_id))?
                .into_iter()
                .map(|h| h.address)
                .collect()
        };
        if policy.node_can_post(writer_node_id, &enrolled_addrs) {
            return Ok(());
        }
        let missing = format!("channel:post={channel}");
        let escalation_note = self
            .config
            .escalation
            .resolve(&missing)
            .map(|n| n.as_str().to_string());
        Err(NodeError::ChannelReadOnly {
            channel: channel.to_string(),
            escalation_note,
        })
    }

    // ========================================================================
    // Local Sessions, Handles & Mailbox
    // ========================================================================

    pub fn register_session(
        &self,
        session_id: &str,
        backend_json: &str,
    ) -> Result<Session, NodeError> {
        let db = self.db();
        Ok(db
            .local()
            .register_session(session_id, backend_json, now_ms())?)
    }

    /// Enrolls a local handle for `session_id` and syncs local handles to every active `PeerLink`.
    pub async fn register_handle(
        &self,
        session_id: &str,
        handle: &str,
    ) -> Result<HandleRecord, NodeError> {
        self.register_handle_with_description(session_id, handle, None)
            .await
    }

    /// Enrolls (or refreshes) a local handle for `session_id` with an optional human-readable
    /// description (sanitized and capped at 200 Unicode characters by `hyp-store`) and syncs all
    /// local handles and their stored descriptions to every active `PeerLink`.
    pub async fn register_handle_with_description(
        &self,
        session_id: &str,
        handle: &str,
        description: Option<&str>,
    ) -> Result<HandleRecord, NodeError> {
        let _ = Handle::new(handle)?;
        let (record, all_handles, descriptions) = {
            let db = self.db();
            let now = now_ms();
            if db.local().get_session(session_id)?.is_none() {
                db.local().register_session(session_id, "{}", now)?;
            }
            db.local()
                .set_session_handle(session_id, Some(handle), now)?;
            let rec = db.messages().register_handle_with_description(
                self.config.node_id.as_str(),
                handle,
                Some(session_id),
                description,
                now,
            )?;
            let (all, descs) =
                collect_local_handles_and_descriptions(&db, self.config.node_id.as_str())?;
            (rec, all, descs)
        };

        let links: Vec<Arc<PeerLink>> = self.peer_links.read().await.values().cloned().collect();
        for link in links {
            let _ = link
                .put_handles_with_descriptions(&all_handles, &descriptions)
                .await;
        }

        Ok(record)
    }

    /// Discovers enrolled agent handles across this node and all active connected peers/hubs,
    /// returning structured entries sorted deterministically by `address` and learning multi-hub
    /// `peer_routes` in SQLite for hub-relayed remote nodes (never overriding directly paired
    /// `PeerProfile::P2p` peers).
    pub async fn discover_peer_handles(&self) -> Vec<DiscoveredPeerHandle> {
        let self_node = self.config.node_id.as_str();
        // Keyed by `address` -> (preference_rank, entry)
        // Rank: 0 = local, 1 = direct peer (`h.node_id == pid`), 2 = hub-relayed.
        let mut by_addr: BTreeMap<String, (u8, DiscoveredPeerHandle)> = BTreeMap::new();

        let (local_handles, active_peer_ids, indirect_allowed_peers) = {
            let db = self.db();
            let locals = db
                .messages()
                .list_handles(Some(self_node))
                .unwrap_or_default();
            let active_peers = db
                .peers()
                .list_peers(Some(PeerStatus::Active))
                .unwrap_or_default();
            let mut peer_ids: Vec<String> = Vec::with_capacity(active_peers.len());
            let mut indirect_allowed: HashSet<String> = HashSet::new();
            for p in active_peers {
                if peer_may_advertise_indirect_routes(&p) {
                    indirect_allowed.insert(p.peer_id.clone());
                }
                peer_ids.push(p.peer_id);
            }
            peer_ids.sort();
            (locals, peer_ids, indirect_allowed)
        };

        for h in local_handles {
            let entry = DiscoveredPeerHandle {
                address: h.address.clone(),
                node_id: h.node_id,
                handle: h.handle,
                description: h.description.filter(|d| !d.is_empty()),
                via: None,
            };
            by_addr.insert(h.address, (0, entry));
        }

        for pid in active_peer_ids {
            let remote_handles = if let Some(link) = self.peer_link(&pid).await {
                match link.get_handles(None).await {
                    Ok(resp) => {
                        self.learn_routes_from_handles(&pid, &resp.handles);
                        resp.handles
                    }
                    Err(_) => continue,
                }
            } else {
                // Outbound-only P2P peers connected inbound to our server may have already synced
                // their handles into our local `handles` table via `PUT /v1/handles`.
                let db = self.db();
                db.messages().list_handles(Some(&pid)).unwrap_or_default()
            };

            for h in remote_handles {
                if h.node_id == self_node {
                    continue;
                }
                // P1-10: P2P and Guest peers may only advertise handles for their own peer_id.
                if h.node_id != pid && !indirect_allowed_peers.contains(&pid) {
                    continue;
                }
                let rank = if h.node_id == pid { 1u8 } else { 2u8 };
                let incoming = DiscoveredPeerHandle {
                    address: h.address.clone(),
                    node_id: h.node_id,
                    handle: h.handle,
                    description: h.description.filter(|d| !d.is_empty()),
                    via: Some(pid.clone()),
                };
                match by_addr.entry(h.address) {
                    std::collections::btree_map::Entry::Vacant(v) => {
                        v.insert((rank, incoming));
                    }
                    std::collections::btree_map::Entry::Occupied(mut o) => {
                        let (cur_rank, cur_entry) = o.get_mut();
                        if rank < *cur_rank {
                            let preserved_desc = incoming
                                .description
                                .or_else(|| cur_entry.description.take());
                            *cur_rank = rank;
                            *cur_entry = DiscoveredPeerHandle {
                                description: preserved_desc,
                                ..incoming
                            };
                        } else if cur_entry.description.is_none() && incoming.description.is_some()
                        {
                            cur_entry.description = incoming.description;
                        }
                    }
                }
            }
        }

        by_addr.into_values().map(|(_, entry)| entry).collect()
    }

    pub fn drain_local_inbox(
        &self,
        session_id: &str,
        limit: usize,
    ) -> Result<Vec<MailboxEntry>, NodeError> {
        let db = self.db();
        Ok(db.local().drain_inbox(session_id, limit, now_ms())?)
    }

    pub fn peek_local_inbox(
        &self,
        session_id: &str,
        limit: usize,
    ) -> Result<Vec<MailboxEntry>, NodeError> {
        let db = self.db();
        Ok(db.local().peek_inbox(session_id, limit)?)
    }

    // ========================================================================
    // Signed Capability Manifest & Negotiation (§3.1 - §3.2)
    // ========================================================================

    pub fn current_manifest_version(&self) -> Result<u64, NodeError> {
        let db = self.db();
        let raw = db
            .local()
            .get_metadata("manifest_version")?
            .unwrap_or_else(|| "1".to_string());
        Ok(raw.parse::<u64>().unwrap_or(1).max(1))
    }

    pub fn bump_manifest_version(&self) -> Result<u64, NodeError> {
        let next = {
            let db = self.db();
            let cur = db
                .local()
                .get_metadata("manifest_version")?
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(1);
            let next = cur.saturating_add(1);
            db.local()
                .set_metadata("manifest_version", &next.to_string())?;
            next
        };
        self.notify_all_inbox_subscribers();
        Ok(next)
    }

    /// Builds and Ed25519-signs this node's `NodeManifestPayload` (strictly public/empty when
    /// `caller` is `None`; strictly scope-filtered + escalation-enabled when `caller` is `Some`).
    pub fn build_signed_manifest(
        &self,
        caller: Option<&AuthenticatedPeer>,
    ) -> Result<(SignedNodeManifest, NodeManifestPayload, String), NodeError> {
        let (manifest_version, issued_at_ms) = {
            let ver = self.current_manifest_version()?;
            let now = now_ms();
            let need_refresh = {
                let mut win = self
                    .manifest_window
                    .lock()
                    .expect("manifest_window lock poisoned");
                if win.issued_at_ms == 0 || win.version != ver {
                    win.version = ver;
                    win.issued_at_ms = now;
                    false
                } else {
                    now - win.issued_at_ms >= MANIFEST_WINDOW_REFRESH_MS
                }
            };
            if need_refresh {
                // Rolling to a fresh `issued_at`/`expires_at` window changes the signed manifest
                // JSON; bump `manifest_version` monotonically so peers never mistake a legitimate
                // TTL rollover for same-version equivocation.
                let next_ver = self.bump_manifest_version()?;
                let mut win = self
                    .manifest_window
                    .lock()
                    .expect("manifest_window lock poisoned");
                win.version = next_ver;
                win.issued_at_ms = now;
                (next_ver, win.issued_at_ms)
            } else {
                let win = self
                    .manifest_window
                    .lock()
                    .expect("manifest_window lock poisoned");
                (win.version, win.issued_at_ms)
            }
        };
        let expires_at_ms = issued_at_ms + MANIFEST_TTL_MS;

        let signing_jwk = crypto_jwk_to_proto(&self.identity.signing_jwk())?;
        let encryption_jwk = crypto_jwk_to_proto(&self.identity.encryption_jwk())?;
        let kid = signing_jwk.thumbprint_sha256()?;

        // Security invariant (§3.1): unauthenticated callers get `audience: "public"` with
        // strictly empty `advertised` arrays and NO `escalation` text!
        let (audience, advertised, escalation) = match caller {
            None => ("public".to_string(), AdvertisedResources::default(), None),
            Some(peer) => {
                let mut topics = Vec::new();
                for t in &self.config.topics {
                    if !self.is_local_only_topic(&t.topic)
                        && peer_may_see_topic(&peer.scopes, &t.topic)
                    {
                        topics.push(AdvertisedTopic {
                            topic: t.topic.clone(),
                            kind: t.kind.clone(),
                            description: t.description.clone(),
                        });
                    }
                }
                if let Some(gh) = self.github_public_adapter() {
                    let gh_topic = gh.topic();
                    if !topics.iter().any(|t| t.topic == gh_topic)
                        && peer_may_see_topic(&peer.scopes, gh_topic)
                    {
                        topics.push(AdvertisedTopic {
                            topic: gh_topic.to_string(),
                            kind: Some("github-public".to_string()),
                            description: Some(
                                "Public GitHub repository events (demand-driven ETag polling)"
                                    .to_string(),
                            ),
                        });
                    }
                }
                {
                    let map = self
                        .github_webhooks
                        .lock()
                        .expect("github_webhooks lock poisoned");
                    for adapter in map.values() {
                        let wh_topic = adapter.topic();
                        if !topics.iter().any(|t| t.topic == wh_topic)
                            && peer_may_see_topic(&peer.scopes, wh_topic)
                        {
                            topics.push(AdvertisedTopic {
                                topic: wh_topic.to_string(),
                                kind: Some("github-webhook".to_string()),
                                description: Some("GitHub webhook CloudEvents stream".to_string()),
                            });
                        }
                    }
                }
                if !topics.iter().any(|t| t.topic == "kv") && peer_may_see_topic(&peer.scopes, "kv")
                {
                    topics.push(AdvertisedTopic {
                        topic: "kv".to_string(),
                        kind: Some("kv".to_string()),
                        description: Some("Built-in Shared KV change stream".to_string()),
                    });
                }
                if self.config.local_ingest.enabled {
                    for ingest_topic in self.config.local_ingest.advertised_topics() {
                        if !self.is_local_only_topic(&ingest_topic)
                            && !topics.iter().any(|t| t.topic == ingest_topic)
                            && peer_may_see_topic(&peer.scopes, &ingest_topic)
                        {
                            topics.push(AdvertisedTopic {
                                topic: ingest_topic,
                                kind: Some("local-ingest".to_string()),
                                description: Some(
                                    "Local socket event ingestion stream (cron, scripts, triggers)"
                                        .to_string(),
                                ),
                            });
                        }
                    }
                }

                let mut channel_set: BTreeSet<String> = BTreeSet::new();
                {
                    let db = self.db();
                    if let Ok(list) = db
                        .channels()
                        .list_channels(Some(self.config.node_id.as_str()))
                    {
                        for c in list {
                            channel_set.insert(c.channel);
                        }
                    }
                }
                for ch in self.list_channel_policies().keys() {
                    channel_set.insert(ch.clone());
                }
                let channels: Vec<String> = channel_set
                    .into_iter()
                    .filter(|ch| peer.scopes.may_channel_join(ch))
                    .collect();

                let kv_namespaces: Vec<AdvertisedKvNamespace> = self
                    .config
                    .kv_namespaces
                    .iter()
                    .filter(|ns| {
                        peer.scopes.may_kv_read(&ns.name, "")
                            || peer.scopes.may_kv_write(&ns.name, "")
                    })
                    .map(|ns| AdvertisedKvNamespace {
                        name: ns.name.clone(),
                        mode: ns.mode,
                        write_model: ns.write_model,
                    })
                    .collect();

                let esc = if self.config.escalation.default.is_some()
                    || !self.config.escalation.by_scope.is_empty()
                {
                    Some(self.config.escalation.clone())
                } else {
                    None
                };

                (
                    peer.peer_id.clone(),
                    AdvertisedResources {
                        topics,
                        channels,
                        kv_namespaces,
                        rpc_commands: Vec::new(),
                    },
                    esc,
                )
            }
        };

        let payload = NodeManifestPayload {
            v: 1,
            node_id: self.config.node_id.clone(),
            profile: self.config.profile,
            hyphae_version: self.config.hyphae_version.clone(),
            protocol_range: self.config.protocol_range,
            manifest_version,
            issued_at: format_rfc3339_millis(issued_at_ms),
            expires_at: format_rfc3339_millis(expires_at_ms),
            audience,
            identity: ManifestIdentity {
                signing_jwk,
                encryption_jwk,
                kid,
                admin_jwk: self.config.admin_jwk.clone(),
            },
            capabilities: self.effective_capabilities(),
            policy: ManifestPolicy {
                require_pairing: self.config.require_pairing,
                require_e2ee: self.config.e2ee_policy == E2eePolicy::Required,
                max_text_bytes: self.config.store_config.message_limits.max_text_bytes as u64,
                max_transfer_bytes: self.config.store_config.transfer_limits.max_bytes,
            },
            advertised,
            escalation,
        };
        payload.validate()?;

        let canonical = payload
            .to_canonical_payload()
            .map_err(|e| NodeError::BadRequest(format!("manifest JCS error: {e}")))?;
        let sig = self
            .identity
            .signing
            .sign_domain_b64("manifest", canonical.as_bytes());
        let signed = SignedNodeManifest {
            payload: canonical,
            sig,
        };
        let wire_bytes = serde_json::to_vec(&signed)?;
        let etag = compute_etag(&wire_bytes);
        Ok((signed, payload, etag))
    }

    fn effective_capabilities(&self) -> Vec<CapabilityToken> {
        let mut caps = self.config.advertised_capabilities();
        if self.config.capabilities_override.is_none() {
            let has_human_authorities = {
                let db = self.db();
                db.human()
                    .list_authorities(false)
                    .map(|list| !list.is_empty())
                    .unwrap_or(false)
            };
            if has_human_authorities && !caps.contains(&CapabilityToken::HumanAuthV1) {
                caps.push(CapabilityToken::HumanAuthV1);
            }
            if self.config.drop_relay.enabled && !caps.contains(&CapabilityToken::DropRelayV1) {
                caps.push(CapabilityToken::DropRelayV1);
            }
        }
        caps
    }

    fn local_capabilities_view(&self) -> PeerCapabilitiesView {
        PeerCapabilitiesView {
            node_id: self.config.node_id.clone(),
            hyphae_version: self.config.hyphae_version.clone(),
            protocol_range: self.config.protocol_range,
            manifest_version: self.current_manifest_version().ok(),
            audience: None,
            expires_at: None,
            capabilities: self.effective_capabilities().into_iter().collect(),
            require_e2ee: self.config.e2ee_policy == E2eePolicy::Required,
        }
    }

    fn effective_e2ee_policy_for_peer(&self, peer_id: &str) -> E2eePolicy {
        self.config
            .peers
            .iter()
            .find(|p| p.peer_id == peer_id)
            .and_then(|p| p.e2ee_policy)
            .unwrap_or(self.config.e2ee_policy)
    }

    /// Strictly verifies a peer's `SignedNodeManifest` (signature against pinned signing JWK,
    /// audience, expiry, monotonic `manifestVersion` anti-rollback, permanent E2EE anti-downgrade,
    /// protocol intersection, and `E2eePolicy`), then caches it in `PeerStore`.
    pub fn verify_and_cache_peer_manifest(
        &self,
        peer_id: &str,
        signed: &SignedNodeManifest,
        etag: Option<String>,
        accept_downgrade: bool,
    ) -> Result<NegotiatedSession, NodeError> {
        let payload = signed.decode_payload()?;
        if payload.node_id.as_str() != peer_id {
            return Err(NodeError::BadRequest(format!(
                "manifest nodeId '{}' does not match expected peer '{peer_id}'",
                payload.node_id
            )));
        }

        // Verify signature against pinned Ed25519 key if already known (zero TOFU downgrade!),
        // otherwise verify against the JWK embedded in the manifest.
        let manifest_signing_jwk = hyp_crypto::OkpJwk::from(&payload.identity.signing_jwk);
        let manifest_enc_jwk = hyp_crypto::OkpJwk::from(&payload.identity.encryption_jwk);
        let pinned_signing = self.lookup_peer_signing_key(peer_id)?;
        let verify_pk = match pinned_signing {
            Some(pk) => {
                let candidate_pk = manifest_signing_jwk.to_ed25519()?;
                if pk != candidate_pk {
                    return Err(NodeError::Unauthorized(format!(
                        "peer '{peer_id}' manifest signing key does not match pinned key"
                    )));
                }
                pk
            }
            None => manifest_signing_jwk.to_ed25519()?,
        };

        verify_pk.verify_domain_b64("manifest", signed.payload.as_bytes(), &signed.sig)?;

        let history = self.build_trust_history(peer_id, accept_downgrade)?;
        let local_view = self.local_capabilities_view();
        let remote_view = PeerCapabilitiesView::from_manifest(&payload);
        let now = now_ms();
        let now_rfc = format_rfc3339_millis(now);
        let policy = self.effective_e2ee_policy_for_peer(peer_id);

        let negotiated = negotiate_capabilities(
            &local_view,
            &remote_view,
            self.config.node_id.as_str(),
            &now_rfc,
            policy,
            &history,
        )?;

        let cap_strings: Vec<String> = payload
            .capabilities
            .iter()
            .map(|c| c.as_str().to_string())
            .collect();
        let manifest_json = serde_json::to_string(signed)?;

        {
            let db = self.db();
            // Ensure peer record exists before caching manifest.
            if db.peers().get_peer(peer_id)?.is_none() {
                db.peers().upsert_peer(
                    &PeerInput {
                        peer_id: peer_id.to_string(),
                        endpoint: None,
                        profile: profile_to_store(payload.profile),
                        trust_tier: TrustTier::Peer,
                        status: PeerStatus::Active,
                        scopes: Vec::new(),
                        auth_credential_ref: None,
                    },
                    now,
                )?;
            }
            db.peers().cache_manifest(
                peer_id,
                &ManifestCacheUpdate {
                    manifest_version: payload.manifest_version as i64,
                    manifest_json,
                    etag,
                    capabilities: cap_strings,
                    accept_downgrade,
                },
                now,
            )?;

            // Pin verified JWKs in peer_keys.
            let _ = db.peers().upsert_peer_key(
                &PeerKeyInput {
                    peer_id: peer_id.to_string(),
                    kid: verify_pk.kid(),
                    key_use: KeyUse::Signing,
                    jwk_json: serde_json::to_string(&manifest_signing_jwk)?,
                    status: KeyStatus::Active,
                    expires_at: None,
                },
                now,
            );
            let enc_pk = manifest_enc_jwk.to_x25519()?;
            let _ = db.peers().upsert_peer_key(
                &PeerKeyInput {
                    peer_id: peer_id.to_string(),
                    kid: enc_pk.kid(),
                    key_use: KeyUse::Encryption,
                    jwk_json: serde_json::to_string(&manifest_enc_jwk)?,
                    status: KeyStatus::Active,
                    expires_at: None,
                },
                now,
            );
        }

        Ok(negotiated)
    }

    fn build_trust_history(
        &self,
        peer_id: &str,
        accept_downgrade: bool,
    ) -> Result<PeerTrustHistory, NodeError> {
        let db = self.db();
        let Some(rec) = db.peers().get_peer(peer_id)? else {
            return Ok(PeerTrustHistory {
                last_seen_manifest_version: None,
                previously_seen_capabilities: BTreeSet::new(),
                accept_downgrade,
            });
        };
        let mut seen = BTreeSet::new();
        for cap_str in &rec.observed_e2ee_caps {
            if let Ok(tok) = CapabilityToken::from_token_str(cap_str) {
                seen.insert(tok);
            }
        }
        if let Some(ref raw_manifest) = rec.manifest_json {
            if let Ok(signed) = serde_json::from_str::<SignedNodeManifest>(raw_manifest) {
                if let Ok(payload) = signed.decode_payload() {
                    for c in payload.capabilities {
                        seen.insert(c);
                    }
                }
            }
        }
        Ok(PeerTrustHistory {
            last_seen_manifest_version: (rec.manifest_version > 0)
                .then_some(rec.manifest_version as u64),
            previously_seen_capabilities: seen,
            accept_downgrade,
        })
    }

    // ========================================================================
    // Request Authentication & Scope Enforcement
    // ========================================================================

    /// Authenticates an incoming peer HTTP request via `Authorization: Bearer <token>`,
    /// or `Authorization: Hyphae-Ed25519 ...`.
    /// Returns `Ok(None)` if no authentication headers are present; fails closed with
    /// `NodeError::Unauthorized` on any invalid, malformed, replayed, or revoked credential.
    pub fn authenticate_request(
        &self,
        headers: &HeaderMap,
        method: &str,
        path_and_query: &str,
        body_sha256: &str,
    ) -> Result<Option<AuthenticatedPeer>, NodeError> {
        let Some(raw_auth) = headers.get(AUTHORIZATION) else {
            return Ok(None);
        };
        let auth_str = raw_auth
            .to_str()
            .map_err(|_| NodeError::Unauthorized("non-ASCII Authorization header".into()))?
            .trim();

        if let Some(token) = auth_str.strip_prefix("Bearer ") {
            let token = token.trim();
            if token.is_empty() {
                return Err(NodeError::Unauthorized("empty bearer token".into()));
            }
            let hash = sha256_hex(token.as_bytes());
            let peer = {
                let db = self.db();
                let Some(raw_binding) = db.local().get_metadata(&format!("auth_token:{hash}"))?
                else {
                    return Err(NodeError::Unauthorized("unknown bearer credential".into()));
                };
                let binding = parse_bearer_token_binding(&raw_binding)?;
                let active_peer = load_active_authenticated_peer(&db, &binding.peer_id)?;
                if let Some(ref gid) = binding.grant_id {
                    if db.peers().is_grant_revoked(gid)? {
                        return Err(NodeError::Unauthorized(
                            "bearer credential grant has been revoked".into(),
                        ));
                    }
                }
                if let Some(ref kid) = binding.sign_kid {
                    let key_active =
                        db.peers()
                            .get_peer_key(&binding.peer_id, kid)?
                            .is_some_and(|k| {
                                k.key_use == KeyUse::Signing && k.status == KeyStatus::Active
                            });
                    if !key_active {
                        return Err(NodeError::Unauthorized(
                            "bearer credential signing key is no longer active".into(),
                        ));
                    }
                }
                active_peer
            };
            return Ok(Some(peer));
        }

        if let Some(rest) = auth_str.strip_prefix("Hyphae-Ed25519 ") {
            let params = parse_auth_kv(rest);
            let peer_id = params
                .get("node")
                .ok_or_else(|| NodeError::Unauthorized("missing node in Ed25519 auth".into()))?;
            let ts_str = params
                .get("ts")
                .ok_or_else(|| NodeError::Unauthorized("missing ts in Ed25519 auth".into()))?;
            let nonce = params
                .get("nonce")
                .ok_or_else(|| NodeError::Unauthorized("missing nonce in Ed25519 auth".into()))?;
            let sig = params
                .get("sig")
                .ok_or_else(|| NodeError::Unauthorized("missing sig in Ed25519 auth".into()))?;
            let peer = self.verify_ed25519_http_auth(
                peer_id,
                ts_str,
                nonce,
                sig,
                method,
                path_and_query,
                body_sha256,
            )?;
            return Ok(Some(peer));
        }

        Err(NodeError::Unauthorized(
            "unsupported Authorization scheme".into(),
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_ed25519_http_auth(
        &self,
        peer_id: &str,
        ts_str: &str,
        nonce: &str,
        sig: &str,
        method: &str,
        path_and_query: &str,
        body_sha256: &str,
    ) -> Result<AuthenticatedPeer, NodeError> {
        if nonce.is_empty() {
            return Err(NodeError::Unauthorized(
                "empty nonce in Ed25519 auth".into(),
            ));
        }
        let ts: i64 = ts_str
            .parse()
            .map_err(|_| NodeError::Unauthorized("invalid ts in Ed25519 auth".into()))?;
        let now = now_ms();
        if (now - ts).abs() > HTTP_AUTH_SKEW_MS {
            return Err(NodeError::Unauthorized(
                "Ed25519 auth timestamp outside allowed skew window".into(),
            ));
        }

        let peer = {
            let db = self.db();
            let (peer, signing_pk) = if peer_id == self.config.node_id.as_str() {
                (
                    AuthenticatedPeer {
                        peer_id: self.config.node_id.to_string(),
                        scopes: ScopeSet::from_strings(&["*"]),
                        trust_tier: TrustTier::SelfNode,
                    },
                    self.identity.signing.public_key(),
                )
            } else {
                let peer = load_active_authenticated_peer(&db, peer_id)?;
                let signing_pk = lookup_peer_signing_key_in_db(&db, peer_id)?.ok_or_else(|| {
                    NodeError::Unauthorized(format!("no pinned signing key for peer '{peer_id}'"))
                })?;
                (peer, signing_pk)
            };
            let signing_input =
                http_auth_signing_input(method, path_and_query, ts, nonce, body_sha256);
            signing_pk
                .verify_domain_b64("http-auth", &signing_input, sig)
                .map_err(|_| NodeError::Unauthorized("Ed25519 auth signature invalid".into()))?;
            peer
        };

        // Bounded in-memory replay guard: reject any (peer_id, nonce) reuse while the
        // signed request could still be valid within the skew window.
        let expires_at = ts.saturating_add(HTTP_AUTH_SKEW_MS);
        let mut nonces = self
            .seen_http_nonces
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let key = (peer_id.to_string(), nonce.to_string());
        if let Some(&existing_exp) = nonces.get(&key) {
            if existing_exp >= now {
                return Err(NodeError::Unauthorized("replayed request nonce".into()));
            }
        }
        if nonces.len() >= MAX_HTTP_AUTH_NONCES {
            nonces.retain(|_, &mut exp| exp >= now);
            if nonces.len() >= MAX_HTTP_AUTH_NONCES {
                let evict_count = (MAX_HTTP_AUTH_NONCES / 8).max(1);
                let mut oldest: Vec<((String, String), i64)> =
                    nonces.iter().map(|(k, &v)| (k.clone(), v)).collect();
                oldest.sort_by_key(|(_, exp)| *exp);
                for (k, _) in oldest.into_iter().take(evict_count) {
                    nonces.remove(&k);
                }
            }
        }
        nonces.insert(key, expires_at);

        Ok(peer)
    }

    /// Enforces a boolean scope predicate fail-closed, resolving any matching `escalationNote`.
    pub fn require_scope(
        &self,
        peer: &AuthenticatedPeer,
        allowed: bool,
        missing_scope: &str,
    ) -> Result<(), NodeError> {
        if allowed {
            return Ok(());
        }
        let escalation_note = self
            .config
            .escalation
            .resolve(missing_scope)
            .map(|n| n.as_str().to_string());
        Err(NodeError::ScopeDenied {
            missing_scope: missing_scope.to_string(),
            current_scopes: peer.scopes.raw_scopes().to_vec(),
            escalation_note,
        })
    }

    /// Returns `true` iff `peer_id` is still active and has at least one non-revoked,
    /// non-expired inbound grant (when inbound grants exist). Used by live `/v1/inbox`
    /// SSE loops to terminate immediately upon revocation (`P1-4`).
    pub(crate) fn is_peer_still_active(&self, peer_id: &str) -> bool {
        if peer_id == self.config.node_id.as_str() {
            return true;
        }
        let db = self.db();
        load_active_authenticated_peer(&db, peer_id).is_ok()
    }

    /// Authorizes `action` for `peer_id` fail-closed against `PeerStore` status, grant
    /// revocations, grant `expires_at` (`P1-18`), and granted `ScopeSet` (`P1-6`).
    pub fn authorize_peer_action(
        &self,
        peer_id: &str,
        action: PeerAction<'_>,
    ) -> Result<AuthenticatedPeer, NodeError> {
        if peer_id == self.config.node_id.as_str() {
            return Ok(AuthenticatedPeer {
                peer_id: self.config.node_id.to_string(),
                scopes: ScopeSet::from_strings(&["*"]),
                trust_tier: TrustTier::SelfNode,
            });
        }

        let (auth_peer, profile, has_local_sub) = {
            let db = self.db();
            let (peer, profile) = load_active_authenticated_peer_with_profile(&db, peer_id)?;
            let sub = match action {
                PeerAction::StreamDeliver { topic }
                    if profile != hyp_store::PeerProfile::Router =>
                {
                    db.events()
                        .list_subscriptions(None)?
                        .into_iter()
                        .any(|s| s.origin_node == peer_id && s.topic == topic)
                }
                _ => false,
            };
            (peer, profile, sub)
        };

        let is_router = profile == hyp_store::PeerProfile::Router;
        let (allowed, missing_scope) = match action {
            PeerAction::DmSend { to_addr } => {
                let ok = if is_router {
                    auth_peer.scopes.may_dm_receive() || auth_peer.scopes.may_dm_send(to_addr)
                } else {
                    auth_peer.scopes.may_dm_send(to_addr)
                };
                (ok, format!("dm:send={to_addr}"))
            }
            PeerAction::ChannelPost { channel } => {
                let ok = if is_router {
                    auth_peer.scopes.may_channel_join(channel)
                        || auth_peer.scopes.may_channel_post(channel)
                } else {
                    auth_peer.scopes.may_channel_post(channel)
                };
                (ok, format!("channel:post={channel}"))
            }
            PeerAction::TransferSend { to_node, bytes } => {
                let ok = if is_router {
                    auth_peer.scopes.may_receive_files(bytes.unwrap_or(0))
                        || auth_peer.scopes.may_send_files(to_node, bytes)
                } else {
                    auth_peer.scopes.may_send_files(to_node, bytes)
                };
                (ok, format!("files:send={to_node}"))
            }
            PeerAction::StreamPublish { topic } => (
                auth_peer.scopes.may_stream_publish(topic),
                format!("stream:publish={topic}"),
            ),
            PeerAction::StreamDeliver { topic } => {
                let ok = if is_router {
                    peer_may_see_topic(&auth_peer.scopes, topic)
                        || auth_peer.scopes.may_stream_publish(topic)
                        || (topic == "kv" && peer_has_any_kv_read(&auth_peer.scopes))
                } else {
                    auth_peer.scopes.may_stream_publish(topic)
                        || (peer_may_see_topic(&auth_peer.scopes, topic) && has_local_sub)
                };
                (ok, format!("stream:publish={topic}"))
            }
            PeerAction::KvRead { namespace, key } => (
                auth_peer.scopes.may_kv_read(namespace, key),
                format!("kv:read={namespace}/{key}"),
            ),
            PeerAction::KvWrite { namespace, key } => (
                auth_peer.scopes.may_kv_write(namespace, key),
                format!("kv:write={namespace}/{key}"),
            ),
        };

        self.require_scope(&auth_peer, allowed, &missing_scope)?;
        Ok(auth_peer)
    }

    fn record_peer_scope_denied_audit(
        &self,
        origin_node: &str,
        event_type: &str,
        reason: &str,
        payload_digest_input: &[u8],
    ) {
        let now = now_ms();
        let db = self.db();
        let _ = db.local().append_gate_audit(
            &GateAuditInput {
                direction: GateDirection::Inbound,
                stage: "peer_scope".to_string(),
                decision: StoreGateDecision::Block,
                origin_node: Some(origin_node.to_string()),
                source: Some(origin_node.to_string()),
                session_id: None,
                receipt_id: None,
                event_type: Some(event_type.to_string()),
                trust_tier: Some("peer".to_string()),
                confidence: None,
                categories: vec!["peer.scope_denied".to_string()],
                reason: Some(reason.to_string()),
                traceparent: None,
                payload_sha256: sha256_hex(payload_digest_input),
                reviewer: None,
            },
            now,
        );
    }

    /// Deletes all stored bearer token records (`auth_token:*`) bound to `peer_id` (`N1`).
    pub fn invalidate_peer_bearer_tokens(&self, peer_id: &str) -> Result<usize, NodeError> {
        let db = self.db();
        Ok(db.peers().delete_bearer_tokens_for_peer(peer_id)?)
    }

    fn issue_peer_bearer_token(
        &self,
        peer_id: &str,
        grant_id: Option<&str>,
        sign_kid: Option<&str>,
    ) -> Result<String, NodeError> {
        let rng = SystemRandom::new();
        let mut raw = Zeroizing::new([0u8; 32]);
        rng.fill(&mut *raw)
            .map_err(|_| NodeError::Http("CSPRNG failure generating auth credential".into()))?;
        let token = URL_SAFE_NO_PAD.encode(*raw);
        let hash = sha256_hex(token.as_bytes());
        let binding = BearerTokenBinding {
            peer_id: peer_id.to_string(),
            grant_id: grant_id.map(ToOwned::to_owned),
            sign_kid: sign_kid.map(ToOwned::to_owned),
            issued_at: Some(now_ms()),
        };
        let encoded = serde_json::to_string(&binding)?;
        let db = self.db();
        db.local()
            .set_metadata(&format!("auth_token:{hash}"), &encoded)?;
        Ok(token)
    }

    fn peer_auth_secret_name(peer_id: &str) -> String {
        let hash = sha256_hex(peer_id.as_bytes());
        format!("peer-auth-{}", &hash[..12])
    }

    fn save_peer_auth_credential(&self, peer_id: &str, token: &str) -> Result<String, NodeError> {
        let name = Self::peer_auth_secret_name(peer_id);
        self.secrets.set(&name, token)?;
        Ok(name)
    }

    fn clear_peer_auth_credential(&self, peer_id: &str) {
        let name = Self::peer_auth_secret_name(peer_id);
        let _ = self.secrets.delete(&name);
    }

    fn load_peer_auth(&self, peer_id: &str) -> PeerAuth {
        let name = Self::peer_auth_secret_name(peer_id);
        match self.secrets.get(&name) {
            Ok(secret) => PeerAuth::Bearer(Arc::new(secret)),
            Err(_) => PeerAuth::Ed25519,
        }
    }

    // ========================================================================
    // Pairing: Org Admin-CA (`am2_`) & Direct P2P Mutual (`hp2p1_`)
    // ========================================================================

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
        let resp = self.http_client.request(http_req).await?;
        let (status, _headers, body) = HttpClient::collect(resp, MAX_JSON_RESPONSE_BYTES).await?;
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
        let ts = format_rfc3339_millis(now_ms());
        let ed_jwk = self.identity.signing_jwk();
        let x_jwk = self.identity.encryption_jwk();
        let proof = DelegatedPairProofV1 {
            hub_node_id: hub_node_id.to_string(),
            node_id: self.config.node_id.to_string(),
            ed25519_jwk: ed_jwk.clone(),
            x25519_jwk: x_jwk.clone(),
            node_cert_sha256: node_cert_sha256(hcert1),
            timestamp: ts.clone(),
        };
        let proof_sig = sign_delegated_pair_proof(&proof, &self.identity.signing)?;
        let req = DelegatedPairRequest {
            node_id: self.config.node_id.to_string(),
            ed25519_jwk: ed_jwk,
            x25519_jwk: x_jwk,
            node_cert: hcert1.trim().to_string(),
            timestamp: ts,
            proof_sig,
        };

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

        // Verify signed manifest BEFORE persisting credentials or peer state.
        let payload = reply.signed_manifest.decode_payload()?;
        if payload.node_id.as_str() != hub_node_id {
            return Err(NodeError::Unauthorized(format!(
                "hub manifest nodeId '{}' does not match expected '{hub_node_id}'",
                payload.node_id
            )));
        }
        let hub_pk = hyp_crypto::OkpJwk::from(&payload.identity.signing_jwk).to_ed25519()?;
        hub_pk.verify_domain_b64(
            "manifest",
            reply.signed_manifest.payload.as_bytes(),
            &reply.signed_manifest.sig,
        )?;
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
        let pair_kp = derive_pairing_key_v1(&parsed_code.secret, &parsed_code.grant_id)?;

        let binding = PairBindingV2 {
            v: 2,
            grant_id: parsed_code.grant_id.clone(),
            node_id: self.config.node_id.to_string(),
            signing_jwk: self.identity.signing_jwk(),
            encryption_jwk: self.identity.encryption_jwk(),
            bound_at: format_rfc3339_millis(now_ms()),
        };
        let payload = to_canonical_json(&binding)?;
        let pairing_sig = pair_kp.sign_domain_b64("binding", payload.as_bytes());
        let self_sig = self
            .identity
            .signing
            .sign_domain_b64("binding-self", payload.as_bytes());

        let pair_req = PairRequestV2 {
            grant_id: parsed_code.grant_id,
            payload,
            pairing_sig,
            self_sig,
        };
        let mut req_val = serde_json::to_value(&pair_req)?;
        if let Some(ref sg) = inline_signed_grant {
            if let Some(obj) = req_val.as_object_mut() {
                obj.insert("signedGrant".to_string(), serde_json::to_value(sg)?);
            }
        }
        let http_req = Request::builder()
            .method(Method::POST)
            .uri("/v1/pair")
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(full_body(serde_json::to_vec(&req_val)?))
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
        let verified_grant = verify_grant_v2(&reply.grant, &admin_pk)?;
        if verified_grant.node_id != self.config.node_id.as_str() {
            return Err(NodeError::Unauthorized(
                "hub returned grant for wrong nodeId".into(),
            ));
        }

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

        // Persist a single-use offer sentinel grant in `PeerStore` so `claim_grant` enforces
        // atomic single-use semantics across concurrent pairing requests!
        {
            let db = self.db();
            db.peers().add_grant(
                &GrantInput {
                    id: format!("p2p-offer:{offer_id}"),
                    peer_id: self.config.node_id.to_string(),
                    direction: GrantDirection::Inbound,
                    signed_json: serde_json::to_string(&json!({
                        "offerId": offer_id,
                        "peerId": target_peer_id,
                    }))?,
                    scopes: expanded_offered,
                    trust_tier: TrustTier::Peer,
                    issued_at: now,
                    pair_by: Some(now + ttl_ms),
                    expires_at: None,
                },
                now,
            )?;
        }

        // Persist the full offer in SecretStore (zero plaintext pairing nonce on disk!) so
        // `POST /v1/p2p/pair/<offerId>` also succeeds across daemon restarts or when the offer
        // was minted out-of-process by `hyp pair invite --mode p2p`.
        let offer_secret_key = p2p_offer_secret_name(&offer_id);
        let offer_json = serde_json::to_string(&offer)?;
        self.secrets.set(&offer_secret_key, &offer_json)?;

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
        let bob_grant = GrantV2 {
            v: 2,
            id: bob_grant_id.clone(),
            node_id: offer.node_id.clone(),
            scopes: expanded_to_alice.clone(),
            trust_tier: Some("peer".to_string()),
            pairing_key: None,
            subject_signing_jwk: Some(offer.signing_jwk.clone()),
            subject_encryption_jwk: Some(offer.encryption_jwk.clone()),
            issued_at: format_rfc3339_millis(now),
            pair_by: None,
            expires_at: None,
        };

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
        let confirmation = P2pPairConfirmation {
            offer_id: server_reply.offer_id.clone(),
            alice_grant_to_bob: server_reply.alice_grant_to_bob.clone(),
        };
        let verified_alice_grant =
            verify_p2p_confirmation(&offer, &confirmation, self.config.node_id.as_str())?;

        // Pin Alice's JWKs from the OOB `hp2p1_` offer BEFORE verifying Alice's manifest!
        let alice_sign_pk = offer.signing_jwk.to_ed25519()?;
        let alice_enc_pk = offer.encryption_jwk.to_x25519()?;
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

    /// Connects (or reconnects) to an already-paired peer endpoint, fetching & verifying its
    /// signed capability manifest and launching the background WHATWG SSE `/v1/inbox` worker.
    pub async fn connect_peer(
        self: &Arc<Self>,
        peer_id: &str,
        endpoint: &str,
    ) -> Result<Arc<PeerLink>, NodeError> {
        let auth = self.load_peer_auth(peer_id);
        let link = Arc::new(PeerLink::new(
            peer_id,
            endpoint,
            self.config.node_id.clone(),
            Arc::clone(&self.identity),
            auth,
            self.http_client.clone(),
        ));

        let negotiated = match link.fetch_manifest(None).await? {
            ManifestFetchOutcome::Signed { manifest, etag } => {
                self.verify_and_cache_peer_manifest(peer_id, &manifest, etag, false)?
            }
            ManifestFetchOutcome::NotModified => {
                return Err(NodeError::BadRequest(
                    "unexpected 304 Not Modified without If-None-Match".into(),
                ));
            }
        };

        self.activate_peer_link(peer_id, endpoint, negotiated).await
    }

    async fn activate_peer_link(
        self: &Arc<Self>,
        peer_id: &str,
        endpoint: &str,
        negotiated: NegotiatedSession,
    ) -> Result<Arc<PeerLink>, NodeError> {
        let auth = self.load_peer_auth(peer_id);
        let link = Arc::new(PeerLink::new(
            peer_id,
            endpoint,
            self.config.node_id.clone(),
            Arc::clone(&self.identity),
            auth,
            self.http_client.clone(),
        ));
        link.set_negotiated(negotiated);

        {
            let mut map = self.peer_links.write().await;
            map.insert(peer_id.to_string(), Arc::clone(&link));
        }

        // Sync existing local handles and their stored descriptions to the newly connected peer.
        let (local_handles, local_descriptions) = {
            let db = self.db();
            collect_local_handles_and_descriptions(&db, self.config.node_id.as_str())?
        };
        if !local_handles.is_empty() {
            let _ = link
                .put_handles_with_descriptions(&local_handles, &local_descriptions)
                .await;
        }

        // Best-effort route seeding at connect time (non-fatal if peer is offline or legacy).
        if let Ok(resp) = link.get_handles(None).await {
            self.learn_routes_from_handles(peer_id, &resp.handles);
        }

        // Spawn (or replace) background SSE `/v1/inbox` worker for this peer.
        let worker = spawn_sse_worker(
            Arc::clone(self),
            Arc::clone(&link),
            self.shutdown_tx.subscribe(),
        );
        {
            let mut tasks = self.sse_tasks.lock().expect("sse_tasks lock poisoned");
            if let Some(old) = tasks.insert(peer_id.to_string(), worker) {
                old.abort();
            }
        }

        // Promptly wake any server-side SSE inbox stream for this peer & the deadline scheduler.
        self.notify_peer_inbox(peer_id);
        self.notify_scheduler();

        Ok(link)
    }

    /// Re-fetches a peer's `GET /v1/manifest` using its cached RFC 9110 `ETag` (`If-None-Match`).
    /// Returns `(true, None)` on `304 Not Modified`, or `(false, Some(negotiated))` on update.
    pub async fn refresh_peer_manifest(
        &self,
        peer_id: &str,
    ) -> Result<(bool, Option<NegotiatedSession>), NodeError> {
        let link = self.require_peer_link(peer_id).await?;
        let cached_etag = {
            let db = self.db();
            db.peers().get_peer(peer_id)?.and_then(|p| p.manifest_etag)
        };
        match link.fetch_manifest(cached_etag.as_deref()).await? {
            ManifestFetchOutcome::NotModified => Ok((true, None)),
            ManifestFetchOutcome::Signed { manifest, etag } => {
                let negotiated =
                    self.verify_and_cache_peer_manifest(peer_id, &manifest, etag, false)?;
                link.set_negotiated(negotiated.clone());
                Ok((false, Some(negotiated)))
            }
        }
    }

    pub async fn peer_link(&self, peer_id: &str) -> Option<Arc<PeerLink>> {
        self.peer_links.read().await.get(peer_id).cloned()
    }

    /// Returns a sorted snapshot of all peer IDs with an active outbound `PeerLink`.
    pub async fn connected_peer_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self.peer_links.read().await.keys().cloned().collect();
        ids.sort();
        ids
    }

    /// Disconnects any active outbound `PeerLink` and aborts its background SSE `/v1/inbox`
    /// worker for `peer_id`. Returns `true` if a link or worker task was removed.
    pub async fn disconnect_peer(&self, peer_id: &str) -> bool {
        let removed_link = self.peer_links.write().await.remove(peer_id).is_some();
        let removed_sse = {
            let mut tasks = self.sse_tasks.lock().expect("sse_tasks lock poisoned");
            if let Some(handle) = tasks.remove(peer_id) {
                handle.abort();
                true
            } else {
                false
            }
        };
        removed_link || removed_sse
    }

    /// Reconciles live outbound `PeerLink` supervisors and SSE `/v1/inbox` workers against
    /// persisted `PeerStatus::Active` peers in `node.sqlite`.
    ///
    /// - Serialized across concurrent callers via `peer_reconcile_lock` so parallel reload
    ///   signals never spawn duplicate links.
    /// - Cancels and removes links for peers that were revoked, paused, deleted, or cleared.
    /// - Leaves unchanged, healthy existing links untouched (idempotent: `added == 0`).
    /// - Connects newly added or updated peers concurrently, bounded by `connect_timeout`.
    pub async fn reconcile_peers(
        self: &Arc<Self>,
        connect_timeout: Duration,
    ) -> PeerReconcileReport {
        let _guard = self.peer_reconcile_lock.lock().await;

        let (desired, inactive_peers) = {
            let db = self.db();
            let all_peers = db.peers().list_peers(None).unwrap_or_default();
            let mut map = BTreeMap::new();
            let mut inactive = Vec::new();
            for p in all_peers {
                if p.peer_id == self.config.node_id.as_str() {
                    continue;
                }
                if p.status != PeerStatus::Active {
                    inactive.push(p.peer_id);
                    continue;
                }
                if let Some(ep) = p
                    .endpoint
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                {
                    map.insert(p.peer_id, ep.to_string());
                }
            }
            (map, inactive)
        };
        let has_inactive_peers = !inactive_peers.is_empty();

        // N1: Invalidate stored bearer tokens for every revoked/inactive peer.
        for pid in &inactive_peers {
            let _ = self.invalidate_peer_bearer_tokens(pid);
        }

        // P1-4: Inspect ALL currently tracked outbound PeerLinks and SSE worker tasks and
        // immediately drop any peer whose row is no longer `PeerStatus::Active` or was deleted.
        let mut to_remove_set: BTreeSet<String> = {
            let links = self.peer_links.read().await;
            links
                .keys()
                .filter(|pid| !desired.contains_key(*pid))
                .cloned()
                .collect()
        };
        {
            let tasks = self.sse_tasks.lock().expect("sse_tasks lock poisoned");
            for pid in tasks.keys() {
                if !desired.contains_key(pid) {
                    to_remove_set.insert(pid.clone());
                }
            }
        }
        let to_remove: Vec<String> = to_remove_set.into_iter().collect();

        let mut removed = 0usize;
        for pid in to_remove {
            let _ = self.invalidate_peer_bearer_tokens(&pid);
            if self.disconnect_peer(&pid).await {
                removed += 1;
            }
            self.notify_peer_inbox(&pid);
        }
        if removed > 0 || has_inactive_peers {
            // Wake any live inbound `/v1/inbox` SSE loops so revoked/paused/deleted peers
            // immediately re-check `PeerStore` status and close their stream!
            self.notify_all_inbox_subscribers();
        }

        let existing_links: HashMap<String, Arc<PeerLink>> = {
            let links = self.peer_links.read().await;
            links.clone()
        };

        let mut to_connect: Vec<(String, String)> = Vec::new();
        for (pid, ep) in &desired {
            let desired_ep_norm = ep.trim_end_matches('/');
            let needs_connect = match existing_links.get(pid) {
                None => true,
                Some(existing) => {
                    let desired_auth = self.load_peer_auth(pid);
                    let sse_alive = {
                        let tasks = self.sse_tasks.lock().expect("sse_tasks lock poisoned");
                        tasks.get(pid).is_some_and(|h| !h.is_finished())
                    };
                    existing.endpoint() != desired_ep_norm
                        || !existing.auth().matches(&desired_auth)
                        || !sse_alive
                }
            };
            if needs_connect {
                to_connect.push((pid.clone(), ep.clone()));
            }
        }

        let mut added = 0usize;
        let mut warnings: Vec<String> = Vec::new();
        if !to_connect.is_empty() {
            let mut join_set = tokio::task::JoinSet::new();
            for (pid, ep) in to_connect {
                let node = Arc::clone(self);
                join_set.spawn(async move {
                    let outcome =
                        tokio::time::timeout(connect_timeout, node.connect_peer(&pid, &ep)).await;
                    (pid, ep, outcome)
                });
            }
            while let Some(joined) = join_set.join_next().await {
                match joined {
                    Ok((_pid, _ep, Ok(Ok(_)))) => {
                        added += 1;
                    }
                    Ok((pid, ep, Ok(Err(e)))) => {
                        warnings.push(format!(
                            "Peer '{pid}' ({ep}) could not be auto-connected: {e}"
                        ));
                    }
                    Ok((pid, ep, Err(_))) => {
                        warnings.push(format!("Peer '{pid}' ({ep}) timed out during auto-connect"));
                    }
                    Err(e) => {
                        warnings.push(format!("Peer auto-connect task failed: {e}"));
                    }
                }
            }
        }
        warnings.sort();

        let connected_peers = self.connected_peer_ids().await;
        PeerReconcileReport {
            active_peers: connected_peers.len(),
            added,
            removed,
            connected_peers,
            warnings,
        }
    }

    async fn require_peer_link(&self, peer_id: &str) -> Result<Arc<PeerLink>, NodeError> {
        let peer_status = {
            let db = self.db();
            db.peers().get_peer(peer_id)?.map(|p| p.status)
        };
        match peer_status {
            Some(PeerStatus::Active) => {}
            Some(status) => {
                let _ = self.disconnect_peer(peer_id).await;
                return Err(NodeError::Unauthorized(format!(
                    "peer '{peer_id}' is not active (status: {})",
                    status.as_str()
                )));
            }
            None => {
                let _ = self.disconnect_peer(peer_id).await;
                return Err(NodeError::NotFound(format!(
                    "no active PeerLink to '{peer_id}'"
                )));
            }
        }
        self.peer_link(peer_id)
            .await
            .ok_or_else(|| NodeError::NotFound(format!("no active PeerLink to '{peer_id}'")))
    }

    /// Finds the default hub (active Router-profile peer) if any, else the first active peer.
    async fn default_remote_peer(&self) -> Option<String> {
        let mut active_links: Vec<String> = self.peer_links.read().await.keys().cloned().collect();
        if active_links.is_empty() {
            return None;
        }
        active_links.sort();
        let db = self.db();
        let mut fallback = None;
        for pid in &active_links {
            match db.peers().get_peer(pid) {
                Ok(Some(rec)) => {
                    if rec.status != PeerStatus::Active {
                        continue;
                    }
                    if rec.profile == hyp_store::PeerProfile::Router {
                        return Some(pid.clone());
                    }
                    if fallback.is_none() {
                        fallback = Some(pid.clone());
                    }
                }
                _ => {
                    if fallback.is_none() {
                        fallback = Some(pid.clone());
                    }
                }
            }
        }
        fallback
    }

    fn learn_routes_from_handles(&self, via_peer: &str, handles: &[HandleRecord]) {
        let now = now_ms();
        let db = self.db();
        // P1-10 (#1): Only trust indirect routes (`handle.node_id != via_peer`) from an
        // active Router/Hub peer (`PeerProfile::Router` + `TrustTier::Org`). A P2P or Guest
        // peer may ONLY advertise handles for its own `peer_id`.
        let via_trusted_router = db
            .peers()
            .get_peer(via_peer)
            .ok()
            .flatten()
            .is_some_and(|p| peer_may_advertise_indirect_routes(&p));
        if !via_trusted_router {
            return;
        }
        let mut seen_nodes = HashSet::new();
        for h in handles {
            if h.node_id == self.config.node_id.as_str() || h.node_id == via_peer {
                continue;
            }
            if !seen_nodes.insert(h.node_id.as_str()) {
                continue;
            }
            // P1-10 (#2): NEVER overwrite an existing direct `Active` peer (any profile in
            // `peers` table) with an indirect route learned from another peer.
            let is_direct_active_peer = db
                .peers()
                .get_peer(&h.node_id)
                .ok()
                .flatten()
                .is_some_and(|p| p.status == PeerStatus::Active);
            if is_direct_active_peer {
                continue;
            }
            let _ = db.peers().upsert_peer_route(&h.node_id, via_peer, now);
        }
    }

    async fn refresh_routes_from_connected_peers(&self) {
        let active_peer_ids: Vec<String> = {
            let db = self.db();
            let mut ids: Vec<String> = db
                .peers()
                .list_peers(Some(PeerStatus::Active))
                .unwrap_or_default()
                .into_iter()
                .map(|p| p.peer_id)
                .collect();
            ids.sort();
            ids
        };

        for pid in active_peer_ids {
            if let Some(link) = self.peer_link(&pid).await {
                if let Ok(resp) = link.get_handles(None).await {
                    self.learn_routes_from_handles(&pid, &resp.handles);
                }
            }
        }
    }

    async fn active_peer_link(&self, peer_id: &str) -> Option<Arc<PeerLink>> {
        let link = self.peer_link(peer_id).await?;
        let is_inactive = {
            let db = self.db();
            db.peers()
                .get_peer(peer_id)
                .ok()
                .flatten()
                .is_some_and(|p| p.status != PeerStatus::Active)
        };
        if is_inactive {
            return None;
        }
        Some(link)
    }

    async fn active_connected_peer_count(&self) -> usize {
        let link_ids: Vec<String> = self.peer_links.read().await.keys().cloned().collect();
        if link_ids.is_empty() {
            return 0;
        }
        let db = self.db();
        link_ids
            .into_iter()
            .filter(|pid| {
                !db.peers()
                    .get_peer(pid)
                    .ok()
                    .flatten()
                    .is_some_and(|p| p.status != PeerStatus::Active)
            })
            .count()
    }

    /// Resolves the outbound `PeerLink` for sending a DM or file transfer to `target_node`.
    ///
    /// Route precedence:
    /// 1. Explicit hub (`explicit_hub: Some(hub)` -> `require_peer_link(hub)`).
    /// 2. Direct active `PeerLink` to `target_node`.
    /// 3. Directly paired active `PeerProfile::P2p` peer (outbound-only SSE peer -> `Ok(None)`).
    /// 4. Learned multi-hub route in `peer_routes` (with a single lazy route refresh across
    ///    connected active peers on miss when >= 2 active peers are connected).
    /// 5. Fallback to `default_remote_peer()`.
    async fn resolve_outbound_link_for_target(
        &self,
        target_node: &str,
        explicit_hub: Option<&NodeId>,
    ) -> Result<Option<Arc<PeerLink>>, NodeError> {
        if let Some(hub) = explicit_hub {
            return Ok(Some(self.require_peer_link(hub.as_str()).await?));
        }

        if let Some(direct) = self.active_peer_link(target_node).await {
            return Ok(Some(direct));
        }

        let is_direct_p2p = {
            let db = self.db();
            db.peers().get_peer(target_node)?.is_some_and(|p| {
                p.profile == hyp_store::PeerProfile::P2p && p.status == PeerStatus::Active
            })
        };
        if is_direct_p2p {
            return Ok(None);
        }

        let learned_via = {
            let db = self.db();
            db.peers().get_peer_route(target_node)?.map(|r| r.via_peer)
        };
        if let Some(via_peer) = learned_via {
            if let Some(via_link) = self.active_peer_link(&via_peer).await {
                return Ok(Some(via_link));
            }
        }

        if self.active_connected_peer_count().await >= 2 {
            self.refresh_routes_from_connected_peers().await;
            let refreshed_via = {
                let db = self.db();
                db.peers().get_peer_route(target_node)?.map(|r| r.via_peer)
            };
            if let Some(via_peer) = refreshed_via {
                if let Some(via_link) = self.active_peer_link(&via_peer).await {
                    return Ok(Some(via_link));
                }
            }
        }

        if let Some(hub_id) = self.default_remote_peer().await {
            return Ok(self.active_peer_link(&hub_id).await);
        }

        Ok(None)
    }

    // ========================================================================
    // Peer Key Lookup & Directory Sync
    // ========================================================================

    pub fn lookup_peer_signing_key(
        &self,
        peer_id: &str,
    ) -> Result<Option<Ed25519PublicKey>, NodeError> {
        let db = self.db();
        lookup_peer_signing_key_in_db(&db, peer_id)
    }

    pub fn lookup_peer_encryption_key(
        &self,
        peer_id: &str,
    ) -> Result<Option<X25519PublicKey>, NodeError> {
        let db = self.db();
        lookup_peer_encryption_key_in_db(&db, peer_id)
    }

    async fn resolve_peer_keys(
        &self,
        target_node: &str,
        via_link: Option<&Arc<PeerLink>>,
    ) -> Result<(Ed25519PublicKey, X25519PublicKey), NodeError> {
        if target_node == self.config.node_id.as_str() {
            return Ok((
                self.identity.signing.public_key(),
                self.identity.encryption.public_key(),
            ));
        }

        if let (Some(sk), Some(ek)) = (
            self.lookup_peer_signing_key(target_node)?,
            self.lookup_peer_encryption_key(target_node)?,
        ) {
            return Ok((sk, ek));
        }

        // Fetch from directory on `via_link` (or any active hub PeerLink) and validate OKP JWKs.
        let link = match via_link {
            Some(l) => Some(Arc::clone(l)),
            None => match self.default_remote_peer().await {
                Some(pid) => self.peer_link(&pid).await,
                None => None,
            },
        };
        if let Some(link) = link {
            let dir = link.get_keys(Some(target_node)).await?;
            if let Some(entry) = dir.keys.into_iter().find(|k| k.node_id == target_node) {
                let sk = entry.signing_jwk.to_ed25519()?;
                let ek = entry.encryption_jwk.to_x25519()?;
                let now = now_ms();
                let db = self.db();
                let _ = db.peers().upsert_peer_key(
                    &PeerKeyInput {
                        peer_id: target_node.to_string(),
                        kid: sk.kid(),
                        key_use: KeyUse::Signing,
                        jwk_json: serde_json::to_string(&entry.signing_jwk)?,
                        status: KeyStatus::Active,
                        expires_at: None,
                    },
                    now,
                );
                let _ = db.peers().upsert_peer_key(
                    &PeerKeyInput {
                        peer_id: target_node.to_string(),
                        kid: ek.kid(),
                        key_use: KeyUse::Encryption,
                        jwk_json: serde_json::to_string(&entry.encryption_jwk)?,
                        status: KeyStatus::Active,
                        expires_at: None,
                    },
                    now,
                );
                return Ok((sk, ek));
            }
        }

        Err(NodeError::NotFound(format!(
            "no active signing/encryption keys found for node '{target_node}'"
        )))
    }

    /// Lists active key directory entries stored on this node (optionally filtered by `node_id`).
    pub fn list_directory_keys(
        &self,
        filter_node: Option<&str>,
    ) -> Result<Vec<PeerKeyDirectoryEntry>, NodeError> {
        let db = self.db();
        let node_ids: Vec<String> = match filter_node {
            Some(nid) => vec![nid.to_string()],
            None => {
                let mut ids: BTreeSet<String> = db
                    .peers()
                    .list_peers(Some(PeerStatus::Active))?
                    .into_iter()
                    .map(|p| p.peer_id)
                    .collect();
                ids.insert(self.config.node_id.to_string());
                ids.into_iter().collect()
            }
        };

        let mut out = Vec::new();
        for nid in node_ids {
            let signing_recs = db
                .peers()
                .list_peer_keys(&nid, Some(KeyUse::Signing), true)?;
            let enc_recs = db
                .peers()
                .list_peer_keys(&nid, Some(KeyUse::Encryption), true)?;
            if let (Some(sr), Some(er)) = (signing_recs.last(), enc_recs.last()) {
                let signing_jwk: CryptoOkpJwk = serde_json::from_str(&sr.jwk_json)?;
                let encryption_jwk: CryptoOkpJwk = serde_json::from_str(&er.jwk_json)?;
                out.push(PeerKeyDirectoryEntry {
                    node_id: nid,
                    kid: sr.kid.clone(),
                    signing_jwk,
                    encryption_jwk,
                });
            }
        }
        Ok(out)
    }

    /// Lists active key directory entries visible to `caller` (P1-11 anti-recon scope gate).
    ///
    /// Guests (`TrustTier::Guest`) and peers lacking directory/DM/channel read scopes MUST NOT
    /// enumerate private org/peer nodes or keys; guests may only fetch this node's own public
    /// key (`?nodeId=<hub>`), their own key (`?nodeId=<self>`), or a co-member's key for a
    /// channel they are authorized to join and belong to (required for E2EE channel verification),
    /// and receive `403 not_granted` on unfiltered or unrelated peer enumeration.
    pub fn list_directory_keys_for_caller(
        &self,
        caller: &AuthenticatedPeer,
        filter_node: Option<&str>,
    ) -> Result<Vec<PeerKeyDirectoryEntry>, NodeError> {
        if caller_has_broad_directory_read(caller) {
            return self.list_directory_keys(filter_node);
        }
        if let Some(target) = filter_node {
            let is_self_or_hub = target == caller.peer_id || target == self.config.node_id.as_str();
            let scoped_peer_lookup = caller.trust_tier != TrustTier::Guest
                && (caller.scopes.may_dm_send(target)
                    || caller.scopes.may_send_files(target, None));
            let shared_channel_member = !is_self_or_hub
                && !scoped_peer_lookup
                && self.peers_share_authorized_channel(caller, target)?;
            if is_self_or_hub || scoped_peer_lookup || shared_channel_member {
                return self.list_directory_keys(Some(target));
            }
        }
        self.require_scope(caller, false, "directory:read")?;
        unreachable!()
    }

    /// Lists active key directory entries for peers authorized to read encrypted Shared KV
    /// entries in `namespace` (`GET /v1/keys?kvNamespace=<ns>`).
    ///
    /// Security invariants:
    /// - Fail-closed: `caller` must hold `kv:read` or `kv:write` covering `namespace`.
    /// - Anti-recon: `TrustTier::Guest` callers without `kv:write` for `namespace` cannot
    ///   enumerate org members (returns only `caller.peer_id`).
    /// - Hub blindness: a `NodeProfile::Router` NEVER includes its own keys in the returned
    ///   member list so blind routers never receive E2EE KV epoch key wrap slots.
    pub fn list_kv_member_keys_for_caller(
        &self,
        caller: &AuthenticatedPeer,
        namespace: &str,
    ) -> Result<Vec<PeerKeyDirectoryEntry>, NodeError> {
        if !hyp_proto::address::is_valid_kv_namespace(namespace) {
            return Err(NodeError::BadRequest(format!(
                "invalid KV namespace '{namespace}'"
            )));
        }
        let can_read = caller.scopes.may_kv_read_namespace(namespace);
        let can_write = caller.scopes.may_kv_write_namespace(namespace);
        self.require_scope(
            caller,
            can_read || can_write,
            &format!("kv:read={namespace}/*"),
        )?;

        let mut node_ids: BTreeSet<String> = BTreeSet::new();
        node_ids.insert(caller.peer_id.clone());

        let may_enumerate = caller.trust_tier != TrustTier::Guest || can_write;
        if may_enumerate {
            let db = self.db();
            for peer in db.peers().list_peers(Some(PeerStatus::Active))? {
                let peer_scopes = ScopeSet::from_strings(&peer.scopes);
                if peer_scopes.may_kv_read_namespace(namespace)
                    || peer_scopes.may_kv_write_namespace(namespace)
                {
                    node_ids.insert(peer.peer_id);
                }
            }
            // Non-router nodes (e.g., direct P2P hosts) participate as real endpoints and may
            // decrypt KV entries hosted on themselves; blind routers MUST NEVER be wrapped for.
            if self.config.profile != NodeProfile::Router {
                node_ids.insert(self.config.node_id.to_string());
            }
        }

        let db = self.db();
        let mut out = Vec::new();
        for nid in node_ids {
            if nid == self.config.node_id.as_str() {
                if self.config.profile != NodeProfile::Router {
                    out.push(PeerKeyDirectoryEntry {
                        node_id: nid,
                        kid: self.identity.signing.public_key().kid(),
                        signing_jwk: self.identity.signing_jwk(),
                        encryption_jwk: self.identity.encryption_jwk(),
                    });
                }
                continue;
            }
            let signing_recs = db
                .peers()
                .list_peer_keys(&nid, Some(KeyUse::Signing), true)?;
            let enc_recs = db
                .peers()
                .list_peer_keys(&nid, Some(KeyUse::Encryption), true)?;
            if let (Some(sr), Some(er)) = (signing_recs.last(), enc_recs.last()) {
                let signing_jwk: CryptoOkpJwk = serde_json::from_str(&sr.jwk_json)?;
                let encryption_jwk: CryptoOkpJwk = serde_json::from_str(&er.jwk_json)?;
                out.push(PeerKeyDirectoryEntry {
                    node_id: nid,
                    kid: sr.kid.clone(),
                    signing_jwk,
                    encryption_jwk,
                });
            }
        }
        Ok(out)
    }

    fn peers_share_authorized_channel(
        &self,
        caller: &AuthenticatedPeer,
        target_node: &str,
    ) -> Result<bool, NodeError> {
        let db = self.db();
        let channels = db
            .channels()
            .list_channels(Some(self.config.node_id.as_str()))?;
        for ch in channels {
            if !caller.scopes.may_channel_join(&ch.channel) {
                continue;
            }
            let has_caller = ch
                .members
                .iter()
                .any(|m| parse_address(m).is_some_and(|(nid, _)| nid == caller.peer_id));
            if !has_caller {
                continue;
            }
            let has_target = ch
                .members
                .iter()
                .any(|m| parse_address(m).is_some_and(|(nid, _)| nid == target_node));
            if has_target {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Lists handles visible to `caller` (P1-11 anti-recon scope gate).
    ///
    /// Guests (`TrustTier::Guest`) and peers lacking directory/DM/channel read scopes MUST NOT
    /// enumerate private org/peer handles; they may only inspect their own `?nodeId=<self>`
    /// handles (or DM-targeted peer handles for non-guests), and receive `403 not_granted`
    /// otherwise.
    pub fn list_directory_handles_for_caller(
        &self,
        caller: &AuthenticatedPeer,
        filter_node: Option<&str>,
    ) -> Result<Vec<HandleRecord>, NodeError> {
        if caller_has_broad_directory_read(caller) {
            let db = self.db();
            return Ok(db.messages().list_handles(filter_node)?);
        }
        if let Some(target) = filter_node {
            let is_self = target == caller.peer_id;
            let scoped_peer_lookup =
                caller.trust_tier != TrustTier::Guest && caller.scopes.may_dm_send(target);
            if is_self || scoped_peer_lookup {
                let db = self.db();
                return Ok(db.messages().list_handles(Some(target))?);
            }
        }
        self.require_scope(caller, false, "directory:read")?;
        unreachable!()
    }

    /// Registers an authorized key rotation for `caller_node` (`PUT /v1/keys`), loading
    /// the caller's peer record and enforcing P1-2 fail-closed authorization.
    pub fn register_peer_key_proof(
        &self,
        caller_node: &str,
        req: &PutKeyRequest,
    ) -> Result<(), NodeError> {
        let caller = if caller_node == self.config.node_id.as_str() {
            AuthenticatedPeer {
                peer_id: self.config.node_id.to_string(),
                scopes: ScopeSet::from_strings(&["*"]),
                trust_tier: TrustTier::SelfNode,
            }
        } else {
            let db = self.db();
            load_active_authenticated_peer(&db, caller_node).map_err(|_| {
                NodeError::Store(StoreError::Unauthorized(format!(
                    "peer '{caller_node}' is not an active authorized peer for key rotation"
                )))
            })?
        };
        self.register_peer_key_proof_authorized(&caller, req, None)
    }

    /// Registers an authorized key rotation (`PUT /v1/keys`) fail-closed (P1-2).
    ///
    /// Security invariants:
    /// - `TrustTier::Guest` callers are unconditionally rejected with `403 Forbidden`.
    /// - Unpinned callers (no currently pinned signing key) are rejected with `403 Forbidden`
    ///   unless presenting a valid proof signed by the configured `admin_jwk` Admin-CA key.
    /// - NEVER accepts a self-signed proof from a new attacker key alone: authorization proof
    ///   MUST verify under the currently pinned signing key OR the configured `admin_jwk`.
    /// - If `rotation_proof` is supplied, `rotation_proof` is verified under the pinned key or
    ///   `admin_jwk` AND `req.proof` is additionally verified under `req.signing_jwk` (dual PoP).
    /// - Clean rotation atomically marks prior active keys `KeyStatus::Retired` and clears any
    ///   stale `peer-auth-*` secret when keys change.
    pub fn register_peer_key_proof_authorized(
        &self,
        caller: &AuthenticatedPeer,
        req: &PutKeyRequest,
        rotation_proof: Option<&SignedPayload>,
    ) -> Result<(), NodeError> {
        if caller.trust_tier == TrustTier::Guest {
            return Err(NodeError::Store(StoreError::Unauthorized(
                "guest peers are not allowed to rotate directory keys".into(),
            )));
        }
        let caller_node = caller.peer_id.as_str();
        if caller_node != self.config.node_id.as_str() {
            let db = self.db();
            let peer_rec = db.peers().get_peer(caller_node)?.ok_or_else(|| {
                NodeError::Store(StoreError::Unauthorized(format!(
                    "unknown peer '{caller_node}' cannot rotate directory keys"
                )))
            })?;
            if peer_rec.status != PeerStatus::Active || peer_rec.trust_tier == TrustTier::Guest {
                return Err(NodeError::Store(StoreError::Unauthorized(format!(
                    "peer '{caller_node}' is not permitted to rotate directory keys"
                ))));
            }
        }

        let new_sign_pk = req.signing_jwk.to_ed25519()?;
        let new_enc_pk = req.encryption_jwk.to_x25519()?;

        let pinned_sign_pk = self.lookup_peer_signing_key(caller_node)?;
        let admin_pk = self
            .config
            .admin_jwk
            .as_ref()
            .map(|j| hyp_crypto::OkpJwk::from(j).to_ed25519())
            .transpose()?;

        if pinned_sign_pk.is_none() && admin_pk.is_none() {
            return Err(NodeError::Store(StoreError::Unauthorized(format!(
                "peer '{caller_node}' has no pinned signing key; refusing unpinned key registration"
            ))));
        }

        let verify_payload_matches = |payload: &KeyRegPayloadV2| -> Result<(), NodeError> {
            if payload.v != 2
                || payload.node_id != caller_node
                || payload.signing_jwk != req.signing_jwk
                || payload.encryption_jwk != req.encryption_jwk
            {
                return Err(NodeError::BadRequest(
                    "key registration proof does not match caller and keys".into(),
                ));
            }
            Ok(())
        };

        let verify_by_pinned_or_admin =
            |proof: &SignedPayload| -> Result<KeyRegPayloadV2, NodeError> {
                if let Some(ref cur_pk) = pinned_sign_pk {
                    if let Ok(payload) = cur_pk.verify_signed::<KeyRegPayloadV2>("key-reg", proof) {
                        return Ok(payload);
                    }
                }
                if let Some(ref apk) = admin_pk {
                    if let Ok(payload) = apk.verify_signed::<KeyRegPayloadV2>("key-reg", proof) {
                        return Ok(payload);
                    }
                }
                Err(NodeError::Store(StoreError::Unauthorized(
                    "key rotation requires a valid proof signed by the currently pinned signing key or configured Admin-CA key".into(),
                )))
            };

        if let Some(auth_proof) = rotation_proof {
            let auth_payload = verify_by_pinned_or_admin(auth_proof)?;
            verify_payload_matches(&auth_payload)?;
            // In dual-proof mode, also verify proof-of-possession of the new signing key.
            let new_payload: KeyRegPayloadV2 = new_sign_pk
                .verify_signed("key-reg", &req.proof)
                .map_err(|_| {
                    NodeError::Store(StoreError::Unauthorized(
                        "new signing key proof-of-possession failed".into(),
                    ))
                })?;
            verify_payload_matches(&new_payload)?;
        } else {
            let auth_payload = verify_by_pinned_or_admin(&req.proof)?;
            verify_payload_matches(&auth_payload)?;
        }

        let now = now_ms();
        let new_sign_kid = new_sign_pk.kid();
        let new_enc_kid = new_enc_pk.kid();
        let keys_changed = {
            let db = self.db();
            let prev_sign_kid = db
                .peers()
                .list_peer_keys(caller_node, Some(KeyUse::Signing), true)?
                .into_iter()
                .next()
                .map(|k| k.kid);
            let prev_enc_kid = db
                .peers()
                .list_peer_keys(caller_node, Some(KeyUse::Encryption), true)?
                .into_iter()
                .next()
                .map(|k| k.kid);

            persist_peer_key_pair(
                &db,
                caller_node,
                PeerKeyPersistence::Rotate,
                [
                    (
                        new_sign_kid.clone(),
                        serde_json::to_string(&req.signing_jwk),
                    ),
                    (
                        new_enc_kid.clone(),
                        serde_json::to_string(&req.encryption_jwk),
                    ),
                ],
                now,
            )?;

            prev_sign_kid.is_some_and(|k| k != new_sign_kid)
                || prev_enc_kid.is_some_and(|k| k != new_enc_kid)
        };
        if keys_changed {
            self.clear_peer_auth_credential(caller_node);
            // N1: Invalidate all previously issued bearer tokens for this peer upon key rotation.
            let _ = self.invalidate_peer_bearer_tokens(caller_node)?;
        }
        Ok(())
    }

    // ========================================================================
    // Transparent E2EE DMs (`dm.e2ee.v1`)
    // ========================================================================

    /// Sends a DM from `from_handle` to `target` (`<handle>`, `<node>/<handle>`, or
    /// `<hub>!<node>/<handle>`), automatically encrypting with `dm.e2ee.v1` (HPKE +
    /// power-of-2 bucket padding + Encrypt-then-Sign Ed25519) when supported, and failing
    /// closed if `E2eePolicy::Required` and the peer lacks `dm.e2ee.v1`.
    pub async fn send_dm(
        &self,
        from_handle: &str,
        target: &str,
        plaintext: &str,
    ) -> Result<SendDmResult, NodeError> {
        let parsed = PeerTarget::parse(target)?;
        let from_addr = format_address(self.config.node_id.as_str(), from_handle);
        let msg_id = uuid_v4();

        let (target_node, to_handle, explicit_hub) = match parsed {
            PeerTarget::Direct { node, handle } => (
                node.concrete_node_id(&self.config.node_id).clone(),
                handle,
                None,
            ),
            PeerTarget::ViaHub { hub, node, handle } => (node, handle, Some(hub)),
        };
        let to_addr = format_address(target_node.as_str(), to_handle.as_str());

        // Case 1: Local same-node delivery (zero network hop).
        if target_node == self.config.node_id {
            self.deliver_plaintext_to_local_handle(
                self.config.node_id.as_str(),
                &msg_id,
                to_handle.as_str(),
                &from_addr,
                plaintext,
                MailboxKind::Message,
            )?;
            return Ok(SendDmResult {
                id: msg_id,
                to: to_addr,
                routed_via: LOCAL_NODE_ID.to_string(),
                encrypted: false,
            });
        }

        // Case 2: Resolve outbound link (explicit hub -> direct P2P link -> outbound-only P2P ->
        // learned multi-hub route (+ lazy refresh) -> default hub).
        let outbound_link = self
            .resolve_outbound_link_for_target(target_node.as_str(), explicit_hub.as_ref())
            .await?;

        // Determine routing host node (context bound into HPKE info + AEAD AAD + Ed25519 sig)
        // and check E2EE capability requirement fail-closed!
        let (routing_host, use_e2ee) = if let Some(ref link) = outbound_link {
            let supports_e2ee =
                self.peer_supports_cap(link.peer_id(), &CapabilityToken::DmE2eeV1, Some(link));
            let policy = self.effective_e2ee_policy_for_peer(link.peer_id());
            if policy == E2eePolicy::Required && !supports_e2ee {
                return Err(NodeError::CapabilityUnsupported(Box::new(
                    ProblemDetails::capability_unsupported(
                        &CapabilityToken::DmE2eeV1,
                        link.peer_id(),
                        &self.config.hyphae_version,
                        "unknown",
                        Some("2.0.0"),
                        true,
                        Some(&format!(
                            "Upgrade peer '{}' to support dm.e2ee.v1",
                            link.peer_id()
                        )),
                    ),
                )));
            }
            let encrypt = policy != E2eePolicy::Disabled && supports_e2ee;
            (link.peer_id().to_string(), encrypt)
        } else {
            // Outbound-only P2P peer connected to our server via SSE `/v1/inbox`!
            let peer_exists = {
                let db = self.db();
                db.peers()
                    .get_peer(target_node.as_str())?
                    .is_some_and(|p| p.status == PeerStatus::Active)
            };
            if !peer_exists {
                return Err(NodeError::NotFound(format!(
                    "no route or paired peer found for '{target_node}'"
                )));
            }
            let policy = self.effective_e2ee_policy_for_peer(target_node.as_str());
            (
                self.config.node_id.to_string(),
                policy != E2eePolicy::Disabled,
            )
        };

        let (wire_text, content_type) = if use_e2ee {
            let (_, recipient_enc_pk) = self
                .resolve_peer_keys(target_node.as_str(), outbound_link.as_ref())
                .await?;
            let ctx = DmContext {
                node_id: &routing_host,
                msg_id: &msg_id,
                sender: &from_addr,
                recipient: &to_addr,
            };
            let env = seal_dm(
                &ctx,
                plaintext.as_bytes(),
                &self.identity.signing,
                &recipient_enc_pk,
            )?;
            (
                serde_json::to_string(&env)?,
                Some(CONTENT_TYPE_E2EE_JSON.to_string()),
            )
        } else {
            (plaintext.to_string(), Some("text/plain".to_string()))
        };

        if let Some(ref link) = outbound_link {
            link.post_message(&PostMessageRequest {
                id: msg_id.clone(),
                from_handle: from_handle.to_string(),
                to: to_addr.clone(),
                text: wire_text,
                content_type,
                e2ee_epoch: None,
            })
            .await?;
        } else {
            // Enqueue locally on our server so outbound-only P2P peer receives via SSE `/v1/inbox`!
            let now = now_ms();
            {
                let db = self.db();
                db.messages().enqueue(
                    &EnqueueMessage {
                        id: msg_id.clone(),
                        from_node: self.config.node_id.to_string(),
                        from_handle: from_handle.to_string(),
                        to_addr: to_addr.clone(),
                        channel: None,
                        text: wire_text,
                        origin_environment_id: None,
                        origin_thread_id: None,
                        e2ee_epoch: None,
                    },
                    now,
                )?;
            }
            self.notify_peer_inbox(target_node.as_str());
            self.notify_scheduler();
        }

        Ok(SendDmResult {
            id: msg_id,
            to: to_addr,
            routed_via: routing_host,
            encrypted: use_e2ee,
        })
    }

    fn peer_supports_cap(
        &self,
        peer_id: &str,
        cap: &CapabilityToken,
        link: Option<&Arc<PeerLink>>,
    ) -> bool {
        if let Some(l) = link {
            if let Some(neg) = l.negotiated() {
                return neg.shared_capabilities.contains(cap);
            }
        }
        let db = self.db();
        if let Ok(Some(rec)) = db.peers().get_peer(peer_id) {
            if rec.observed_e2ee_caps.iter().any(|c| c == cap.as_str()) {
                return true;
            }
            if let Some(ref raw) = rec.manifest_json {
                if let Ok(signed) = serde_json::from_str::<SignedNodeManifest>(raw) {
                    if let Ok(payload) = signed.decode_payload() {
                        return payload.capabilities.contains(cap);
                    }
                }
            }
        }
        false
    }

    /// Server-side handler for `POST /v1/messages`: enforces `dm:send`, `dm:receive` (for direct
    /// Router mailbox delivery), and `forward:via` + `forwarding` allowlist (for non-router or
    /// multi-hop transit relay), stores ciphertext verbatim, and delivers immediately if addressed
    /// to `self.node_id` (Direct P2P), else wakes SSE inbox.
    pub async fn handle_server_post_message(
        &self,
        caller: &AuthenticatedPeer,
        req: PostMessageRequest,
    ) -> Result<(String, bool), NodeError> {
        self.require_scope(
            caller,
            caller.scopes.may_dm_send(&req.to),
            &format!("dm:send={}", req.to),
        )?;
        let Some((to_node, _to_handle)) = parse_address(&req.to) else {
            return Err(NodeError::BadRequest(format!(
                "invalid recipient address '{}'",
                req.to
            )));
        };
        let to_node_owned = to_node.to_string();

        if to_node_owned != self.config.node_id.as_str() {
            let direct_router_peer = if self.config.profile == NodeProfile::Router {
                let db = self.db();
                match db.peers().get_peer(&to_node_owned)? {
                    Some(peer) if peer.status == PeerStatus::Active => Some(peer),
                    _ => None,
                }
            } else {
                None
            };

            if let Some(recipient_peer) = direct_router_peer {
                // Case A — Team Hub (`NodeProfile::Router`) delivering to a directly paired
                // `Active` member: zero `forward:via` required, but recipient MUST hold `dm:receive`.
                let recipient_scopes = ScopeSet::from_strings(&recipient_peer.scopes);
                if !recipient_scopes.may_dm_receive() {
                    return Err(NodeError::ScopeDenied {
                        missing_scope: "dm:receive".to_string(),
                        current_scopes: recipient_peer.scopes,
                        escalation_note: self
                            .config
                            .escalation
                            .resolve("dm:receive")
                            .map(|n| n.as_str().to_string()),
                    });
                }
            } else {
                // Case B — Non-router (`Local`/`P2p`) relaying to a 3rd node, OR Router transit-
                // forwarding to a non-direct 3rd node: require BOTH local `forwarding` allowlist
                // AND caller's explicit `forward:via=<target>` grant.
                let policy_ok =
                    self.config
                        .forwarding
                        .permits(&caller.peer_id, &to_node_owned, "dm");
                let scope_ok = caller.scopes.may_forward_via(&to_node_owned);
                self.require_scope(
                    caller,
                    policy_ok && scope_ok,
                    &format!("forward:via={to_node_owned}"),
                )?;
            }
        }

        let now = now_ms();

        let (enq, maybe_direct_record) = {
            let db = self.db();
            // Ensure caller's sender handle is registered on this node.
            let sender_addr = format_address(&caller.peer_id, &req.from_handle);
            if !db.messages().is_enrolled(&sender_addr)? {
                db.messages()
                    .register_handle(&caller.peer_id, &req.from_handle, None, now)?;
            }
            let enq = db.messages().enqueue(
                &EnqueueMessage {
                    id: req.id.clone(),
                    from_node: caller.peer_id.clone(),
                    from_handle: req.from_handle.clone(),
                    to_addr: req.to.clone(),
                    channel: None,
                    text: req.text.clone(),
                    origin_environment_id: None,
                    origin_thread_id: None,
                    e2ee_epoch: req.e2ee_epoch,
                },
                now,
            )?;
            let direct = if to_node_owned == self.config.node_id.as_str() {
                db.messages().get_message(&req.id)?
            } else {
                None
            };
            (enq, direct)
        };

        if let Some(msg) = maybe_direct_record {
            // Direct P2P message addressed to THIS node: decrypt & deliver immediately!
            let my_node = self.config.node_id.to_string();
            match self.handle_inbound_peer_message(&my_node, msg).await {
                Ok(()) => {
                    let db = self.db();
                    let _ = db
                        .messages()
                        .ack(&my_node, &req.id, &AckOutcome::Delivered, now_ms());
                }
                Err(err) => {
                    let db = self.db();
                    let _ = db.messages().ack(
                        &my_node,
                        &req.id,
                        &AckOutcome::Rejected {
                            reason: err.to_string(),
                        },
                        now_ms(),
                    );
                    return Err(err);
                }
            }
        } else {
            self.notify_peer_inbox(&to_node_owned);
            self.notify_scheduler();
        }

        Ok((enq.id, enq.deduplicated))
    }

    /// Processes an inbound DM or `#channel` message received from `origin_node` (either via
    /// remote hub/P2P SSE `/v1/inbox` or directly on our own P2P server), transparently verifying
    /// and decrypting `dm.e2ee.v1` / `channel.e2ee.v1` into the recipient local session mailbox!
    pub async fn handle_inbound_peer_message(
        &self,
        origin_node: &str,
        msg: MessageRecord,
    ) -> Result<(), NodeError> {
        let Some((sender_node, _sender_handle)) = parse_address(&msg.from_addr) else {
            return Err(NodeError::BadRequest(format!(
                "invalid sender address '{}'",
                msg.from_addr
            )));
        };
        let Some((to_node, to_handle)) = parse_address(&msg.to_addr) else {
            return Err(NodeError::BadRequest(format!(
                "invalid recipient address '{}'",
                msg.to_addr
            )));
        };
        if to_node != self.config.node_id.as_str() {
            return Err(NodeError::BadRequest(format!(
                "message addressed to '{to_node}', not '{}'",
                self.config.node_id
            )));
        }

        // P1-6: Enforce active peer status & counter-grant scopes fail-closed on pulled SSE items.
        if origin_node != self.config.node_id.as_str() {
            let action = match msg.channel.as_deref() {
                Some(ch) => PeerAction::ChannelPost { channel: ch },
                None => PeerAction::DmSend {
                    to_addr: &msg.to_addr,
                },
            };
            if let Err(err) = self.authorize_peer_action(origin_node, action) {
                let ev_type = if msg.channel.is_some() {
                    TYPE_CHANNEL_V1
                } else {
                    TYPE_DM_V1
                };
                self.record_peer_scope_denied_audit(
                    origin_node,
                    ev_type,
                    &err.to_string(),
                    msg.id.as_bytes(),
                );
                return Err(err);
            }
        }

        let origin_link = self.peer_link(origin_node).await;

        let (plaintext, source_label) = if let Some(ref channel) = msg.channel {
            // `#channel` post (`channel.e2ee.v1` or plaintext)
            if let Ok(env) = serde_json::from_str::<ChannelEnvelopeV1>(&msg.text) {
                if env.suite == "channel.e2ee.v1" {
                    let (sender_sign_pk, _) = self
                        .resolve_peer_keys(sender_node, origin_link.as_ref())
                        .await?;

                    // Defense-in-depth: on read-only announcement channels, verify the Ed25519
                    // sender is in the channel's authorized `writers` list!
                    if let Some(policy) = self
                        .resolve_channel_policy_for_inbound(
                            origin_node,
                            channel,
                            origin_link.as_ref(),
                        )
                        .await
                    {
                        if policy.mode == ChannelMode::Announcement
                            && !policy.is_authorized_writer(sender_node, Some(&msg.from_addr))
                        {
                            return Err(NodeError::Unauthorized(format!(
                                "unauthorized_announcement_writer: '{}' is not an authorized writer for '{channel}'",
                                msg.from_addr
                            )));
                        }
                    }

                    let room_key = self
                        .get_or_fetch_channel_room_key(
                            origin_node,
                            channel,
                            env.epoch,
                            origin_link.as_ref(),
                        )
                        .await?;
                    let min_epoch = self.current_min_epoch("channel", origin_node, channel);
                    // Strip hub fan-out suffix `:{to_addr}` to recover sender's logical `msg_id`!
                    let suffix = format!(":{}", msg.to_addr);
                    let logical_msg_id = msg.id.strip_suffix(&suffix).unwrap_or(&msg.id);
                    let ctx = ChannelContext {
                        host_node: origin_node,
                        channel,
                        msg_id: logical_msg_id,
                        sender: &msg.from_addr,
                    };
                    let pt_bytes =
                        open_channel_message(&env, &ctx, &room_key, &sender_sign_pk, min_epoch)?;
                    let pt = String::from_utf8(pt_bytes.to_vec()).map_err(|_| {
                        NodeError::BadRequest("decrypted channel message is not valid UTF-8".into())
                    })?;
                    (pt, format!("{origin_node}/{channel}:{}", msg.from_addr))
                } else {
                    return Err(NodeError::BadRequest(format!(
                        "unsupported channel suite '{}'",
                        env.suite
                    )));
                }
            } else {
                if self.config.e2ee_policy == E2eePolicy::Required {
                    return Err(NodeError::Unauthorized(
                        "e2ee_required: refusing plaintext channel message".into(),
                    ));
                }
                (
                    msg.text.clone(),
                    format!("{origin_node}/{channel}:{}", msg.from_addr),
                )
            }
        } else {
            // 1-to-1 DM (`dm.e2ee.v1` or plaintext)
            if let Ok(env) = serde_json::from_str::<DmEnvelopeV1>(&msg.text) {
                if env.suite == "dm.e2ee.v1" {
                    let (sender_sign_pk, _) = self
                        .resolve_peer_keys(sender_node, origin_link.as_ref())
                        .await?;
                    let ctx = DmContext {
                        node_id: origin_node,
                        msg_id: &msg.id,
                        sender: &msg.from_addr,
                        recipient: &msg.to_addr,
                    };
                    let pt_bytes = open_dm(&env, &ctx, &sender_sign_pk, &self.identity.encryption)?;
                    let pt = String::from_utf8(pt_bytes.to_vec()).map_err(|_| {
                        NodeError::BadRequest("decrypted DM is not valid UTF-8".into())
                    })?;
                    (pt, msg.from_addr.clone())
                } else {
                    return Err(NodeError::BadRequest(format!(
                        "unsupported DM suite '{}'",
                        env.suite
                    )));
                }
            } else {
                if self.config.e2ee_policy == E2eePolicy::Required {
                    return Err(NodeError::Unauthorized(
                        "e2ee_required: refusing plaintext DM".into(),
                    ));
                }
                (msg.text.clone(), msg.from_addr.clone())
            }
        };

        // Always attribute the mailbox entry to the verified `sender_node` (`msg.from_node`, NOT
        // the relaying hub `origin_node` or `self.node_id`), so downstream Security Gates resolve
        // the *sender's* actual trust tier instead of elevating relayed traffic to the hub's `Org`
        // tier or misclassifying direct P2P traffic as `SelfHost`.
        let delivery_origin = sender_node;

        self.deliver_plaintext_to_local_handle(
            delivery_origin,
            &msg.id,
            to_handle,
            &source_label,
            &plaintext,
            MailboxKind::Message,
        )
    }

    async fn resolve_channel_policy_for_inbound(
        &self,
        origin_node: &str,
        channel: &str,
        origin_link: Option<&Arc<PeerLink>>,
    ) -> Option<ChannelPolicy> {
        if origin_node == self.config.node_id.as_str() {
            return Some(self.get_channel_policy(channel));
        }
        if let Some(cached) = self.get_remote_channel_policy(origin_node, channel) {
            return Some(cached);
        }
        if let Some(link) = origin_link {
            if let Ok(resp) = link.list_channels(Some(channel)).await {
                if let Some(entry) = resp.channels.into_iter().find(|c| c.channel == channel) {
                    let policy = ChannelPolicy {
                        mode: entry.mode,
                        writers: entry.writers,
                        description: entry.description,
                    };
                    self.cache_remote_channel_policy(origin_node, channel, policy.clone());
                    return Some(policy);
                }
            }
        }
        None
    }

    fn deliver_plaintext_to_local_handle(
        &self,
        origin_node: &str,
        item_id: &str,
        to_handle: &str,
        source: &str,
        text: &str,
        kind: MailboxKind,
    ) -> Result<(), NodeError> {
        let now = now_ms();
        let session_id = {
            let db = self.db();
            let sid = match db.local().session_by_handle(to_handle)? {
                Some(s) => s.id,
                None => {
                    let sid = format!("handle:{to_handle}");
                    db.local().register_session(&sid, "{}", now)?;
                    let _ = db.local().set_session_handle(&sid, Some(to_handle), now);
                    sid
                }
            };
            match db.local().put_in_mailbox(
                &MailboxInsert {
                    session_id: sid.clone(),
                    origin_node: origin_node.to_string(),
                    item_id: item_id.to_string(),
                    text: text.to_string(),
                    kind,
                    source: source.to_string(),
                    gate_state: GateState::Pending,
                    gate_reason: None,
                    traceparent: None,
                },
                now,
            )? {
                MailboxPutResult::Stored { .. } | MailboxPutResult::Duplicate => sid,
                MailboxPutResult::QueueFull => {
                    return Err(NodeError::Conflict("local_inbox_full".into()));
                }
            }
        };
        self.notify_local_session(&session_id);
        Ok(())
    }

    async fn build_room_epoch_bundle(
        &self,
        scope: EpochScope,
        host_node: &str,
        resource: &str,
        previous_epoch: Option<u64>,
        member_nodes: &[String],
        link: Option<&Arc<PeerLink>>,
    ) -> Result<(RoomEpochKey, SignedEpochKeyBundle), NodeError> {
        let mut resolved = Vec::with_capacity(member_nodes.len());
        for node_id in member_nodes {
            let (_, enc_pk) = self.resolve_peer_keys(node_id, link).await?;
            resolved.push((node_id.as_str(), enc_pk));
        }
        let members: Vec<EpochMember<'_>> = resolved
            .iter()
            .map(|(node_id, enc_pk)| EpochMember { node_id, enc_pk })
            .collect();
        let creator = self.config.node_id.as_str();
        let signer = &self.identity.signing;
        let bundle = match previous_epoch {
            None => create_epoch_bundle(scope, host_node, resource, 1, creator, signer, &members)?,
            Some(previous) => rotate_epoch_bundle(
                scope, host_node, resource, previous, creator, signer, &members,
            )?,
        };
        Ok(bundle)
    }

    async fn open_and_cache_room_epoch(
        &self,
        scope: EpochScope,
        host_node: &str,
        resource: &str,
        creator_node_id: &str,
        key_envelope_json: &str,
        link: Option<&Arc<PeerLink>>,
    ) -> Result<RoomEpochKey, NodeError> {
        let bundle: SignedEpochKeyBundle = serde_json::from_str(key_envelope_json)?;
        let (creator_sign_pk, _) = self.resolve_peer_keys(creator_node_id, link).await?;
        let min_epoch = self.current_min_epoch(scope.as_str(), host_node, resource);
        let (key, _) = open_epoch_bundle(
            &bundle,
            scope,
            host_node,
            resource,
            &creator_sign_pk,
            self.config.node_id.as_str(),
            &self.identity.encryption,
            min_epoch,
        )?;
        let copy = RoomEpochKey::from_raw(key.epoch(), *key.key_bytes());
        self.cache_room_key(scope.as_str(), host_node, resource, key);
        Ok(copy)
    }

    fn cached_room_key(
        &self,
        scope: &str,
        host_node: &str,
        resource: &str,
        epoch: u64,
    ) -> Option<RoomEpochKey> {
        let map = self.room_keys.lock().expect("room_keys lock poisoned");
        map.get(&(
            scope.to_string(),
            host_node.to_string(),
            resource.to_string(),
            epoch,
        ))
        .map(|k| RoomEpochKey::from_raw(k.epoch(), *k.key_bytes()))
    }

    fn cache_room_key(&self, scope: &str, host_node: &str, resource: &str, key: RoomEpochKey) {
        let epoch = key.epoch();
        {
            let mut map = self.room_keys.lock().expect("room_keys lock poisoned");
            map.insert(
                (
                    scope.to_string(),
                    host_node.to_string(),
                    resource.to_string(),
                    epoch,
                ),
                key,
            );
        }
        let mut mins = self.min_epochs.lock().expect("min_epochs lock poisoned");
        let entry = mins
            .entry((
                scope.to_string(),
                host_node.to_string(),
                resource.to_string(),
            ))
            .or_insert(1);
        if epoch > *entry {
            *entry = epoch;
        }
    }

    fn current_min_epoch(&self, scope: &str, host_node: &str, resource: &str) -> u64 {
        let mins = self.min_epochs.lock().expect("min_epochs lock poisoned");
        mins.get(&(
            scope.to_string(),
            host_node.to_string(),
            resource.to_string(),
        ))
        .copied()
        .unwrap_or(1)
    }

    fn verify_uploaded_epoch_bundle(
        &self,
        scope: EpochScope,
        creator_node_id: &str,
        resource: &str,
        epoch: u64,
        bundle: &SignedEpochKeyBundle,
    ) -> Result<(), NodeError> {
        let creator_pk = self
            .lookup_peer_signing_key(creator_node_id)?
            .ok_or_else(|| {
                let label = match scope {
                    EpochScope::Channel => "epoch",
                    EpochScope::Kv => "kv epoch",
                };
                NodeError::Unauthorized(format!(
                    "no pinned signing key for {label} creator '{creator_node_id}'"
                ))
            })?;
        let payload: hyp_crypto::e2ee::EpochKeyBundlePayload =
            creator_pk.verify_signed("epoch-key", bundle)?;
        if payload.host_node != self.config.node_id.as_str()
            || payload.resource != resource
            || payload.epoch != epoch
            || payload.created_by != creator_node_id
        {
            return Err(NodeError::BadRequest(format!(
                "{} epoch bundle metadata mismatch",
                scope.as_str(),
            )));
        }
        Ok(())
    }

    // ========================================================================
    // Verified Human Drops (`human.drop.v1` / `hdrop1_`), Zero-Knowledge Secret
    // Sink, Human Key Revocation & Signed Node Certificates (`hcert1_`)
    // ========================================================================

    /// Verifies and applies a signed human authority key revocation, requiring an active `admin`
    /// issuer key and monotonically advancing `min_auth_epoch` in `NodeDb`.
    pub fn ingest_human_revocation(
        &self,
        signed: &SignedHumanRevocationV1,
    ) -> Result<(), NodeError> {
        self.apply_human_revocation(signed, false)
    }

    fn apply_human_revocation(
        &self,
        signed: &SignedHumanRevocationV1,
        local_publication: bool,
    ) -> Result<(), NodeError> {
        let preview: HumanRevocationPayloadV1 = serde_json::from_str(&signed.payload)?;
        let signed_json = serde_json::to_string(signed)?;
        let db = self.db();
        db.with_write_transaction(|| {
            let issuer = db.human().list_authorities(true)?.into_iter()
                .find(|record| record.kid == preview.issuer_kid)
                .ok_or_else(|| NodeError::Unauthorized("unknown human revocation issuer".into()))?;
            if issuer.role != HumanAuthorityRole::Admin {
                return Err(NodeError::Unauthorized("human revocation requires an admin issuer".into()));
            }
            let jwk: CryptoOkpJwk = serde_json::from_str(&issuer.jwk_json)?;
            let verified = verify_human_revocation(signed, &jwk.to_ed25519()?).map_err(|e| {
                NodeError::Unauthorized(format!("human revocation signature verification failed: {e}"))
            })?;
            let min_epoch = db.human().min_auth_epoch()?;
            let target = db.human().get_authority(&verified.human_id, &verified.revoked_kid)?;
            if target.as_ref().is_some_and(|record| {
                record.status == HumanAuthorityStatus::Revoked
                    && record.revocation_json.as_deref() == Some(signed_json.as_str())
                    && min_epoch >= verified.new_min_auth_epoch
            }) {
                return Ok(());
            }
            if local_publication && db.human().requires_live_approval()? {
                return Err(NodeError::Unauthorized(
                    "local authority revocation requires fresh live approval; only an already-applied revocation may be broadcast".into(),
                ));
            }
            if issuer.status != HumanAuthorityStatus::Active || issuer.auth_epoch < min_epoch {
                return Err(NodeError::Unauthorized("inactive or stale human revocation issuer".into()));
            }
            db.human().revoke_authority_monotonic(
                &verified.human_id,
                &verified.revoked_kid,
                verified.new_min_auth_epoch,
                &signed_json,
                now_ms(),
            )?;
            Ok(())
        })
    }

    /// Signs, persists, and armors (`hcert1_`) a [`SignedNodeCertV1`] binding this node's Ed25519
    /// and X25519 public keys under an active enrolled `admin` human authority key.
    pub fn issue_node_cert(
        &self,
        admin_kp: &Ed25519KeyPair,
        admin_kid: &str,
        ttl_days: u32,
    ) -> Result<(SignedNodeCertV1, String), NodeError> {
        if ttl_days == 0 {
            return Err(NodeError::BadRequest("ttl_days must be >= 1".into()));
        }
        if admin_kp.kid() != admin_kid {
            return Err(NodeError::Unauthorized(
                "admin keypair kid does not match admin_kid".into(),
            ));
        }

        let (admin, min_epoch) = {
            let db = self.db();
            let rec = db.human().get_active_authority_by_kid(admin_kid)?;
            let min_epoch = db.human().min_auth_epoch()?;
            (rec, min_epoch)
        };
        let admin = admin.ok_or_else(|| {
            NodeError::Unauthorized(format!(
                "unknown or inactive admin authority kid '{admin_kid}'"
            ))
        })?;
        if admin.role != HumanAuthorityRole::Admin {
            return Err(NodeError::Unauthorized(format!(
                "human authority '{}' kid '{admin_kid}' does not have admin role",
                admin.human_id
            )));
        }

        let now = now_ms();
        let ttl_ms = i64::from(ttl_days).saturating_mul(86_400_000);
        let expires_at_ms = now.saturating_add(ttl_ms);
        let auth_epoch = admin.auth_epoch.max(min_epoch);

        let payload = NodeCertPayloadV1 {
            v: 1,
            node_id: self.node_id().to_string(),
            signing_jwk: self.identity.signing_jwk(),
            encryption_jwk: self.identity.encryption_jwk(),
            human_id: admin.human_id,
            human_kid: admin_kid.to_string(),
            auth_epoch,
            issued_at: format_rfc3339_millis(now),
            expires_at: format_rfc3339_millis(expires_at_ms),
        };
        let signed = sign_node_cert(&payload, admin_kp)?;
        let armored = encode_hcert1(&signed)?;

        {
            let db = self.db();
            let signed_json = serde_json::to_string(&signed)?;
            let _ = db.human().put_node_cert(&HumanNodeCertInput {
                node_id: self.node_id().to_string(),
                human_kid: admin_kid.to_string(),
                auth_epoch,
                signed_json,
                issued_at: now,
                expires_at: expires_at_ms,
            })?;
        }

        Ok((signed, armored))
    }
}

// ============================================================================
// Internal helpers & NodeAdapterHost bridge
// ============================================================================

struct UnifiedNodeAdapterHost {
    node: Weak<UnifiedNode>,
}

impl NodeAdapterHost for UnifiedNodeAdapterHost {
    fn publish_event<'a>(
        &'a self,
        topic: &'a str,
        event: ProtoCloudEvent,
    ) -> BoxFuture<'a, Result<PublishOutcome, AdapterError>> {
        Box::pin(async move {
            let Some(node) = self.node.upgrade() else {
                return Err(AdapterError::NotRunning("unified-node".into()));
            };
            let qualified = format!("{LOCAL_NODE_ID}.{topic}");
            let res = node.publish_event(&qualified, event).await.map_err(|err| {
                let code = match &err {
                    NodeError::PayloadTooLarge(_) => PublishErrorCode::TooLarge,
                    NodeError::CloudEvent(_) | NodeError::BadRequest(_) => {
                        PublishErrorCode::InvalidEvent
                    }
                    NodeError::Conflict(_) => PublishErrorCode::IdConflict,
                    _ => PublishErrorCode::Unavailable,
                };
                AdapterError::PublishFailed {
                    code,
                    message: err.to_string(),
                }
            })?;
            let status = if res.deduplicated {
                PublishStatus::Duplicate
            } else {
                if res.matched > 0 {
                    let _ = crate::adapters::deliver_source_topic_to_local_sessions(&node, topic);
                }
                PublishStatus::Stored
            };
            Ok(PublishOutcome {
                status,
                matched: res.matched,
            })
        })
    }

    fn update_status<'a>(
        &'a self,
        _adapter_id: &'a str,
        _health: AdapterHealth,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }

    fn report_delivery_failed<'a>(
        &'a self,
        _adapter_id: &'a str,
        _target: &'a str,
        _events: Vec<hyp_proto::rpc::EventKeyRef>,
        _reason: &'a str,
    ) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

fn map_provenance_err(err: ProvenanceError) -> NodeError {
    match err {
        ProvenanceError::RoutingLoop { node_id, via } => NodeError::RoutingLoop { node_id, via },
        ProvenanceError::HopLimitExceeded { hops, max_hops } => {
            NodeError::HopLimitExceeded { hops, max_hops }
        }
        ProvenanceError::InvalidAttribute(msg) => NodeError::BadRequest(msg),
    }
}

fn caller_has_broad_directory_read(caller: &AuthenticatedPeer) -> bool {
    if caller.trust_tier == TrustTier::Guest {
        return false;
    }
    if caller.trust_tier == TrustTier::SelfNode {
        return true;
    }
    if caller.scopes.may_dm_send_any() {
        return true;
    }
    caller.scopes.raw_scopes().iter().any(|raw| {
        raw == "*"
            || raw == "directory:read"
            || raw == "dm:send"
            || raw == "dm:send=*"
            || raw == "dm:*"
            || raw == "messages:send"
            || raw == "messages:*"
            || raw == "channel:join"
            || raw.starts_with("channel:join=")
            || raw == "channel:*"
    })
}

fn peer_may_see_topic(scopes: &ScopeSet, topic: &str) -> bool {
    if scopes.check_stream_subscribe(topic, &[]).is_ok() {
        return true;
    }
    // Also surface constrained topics (e.g. `stream:subscribe=github[require=exact.repo]`)!
    scopes.raw_scopes().iter().any(|s| {
        s == "*"
            || s == "events:subscribe"
            || s == "stream:subscribe"
            || s == "stream:subscribe=*"
            || s == &format!("stream:subscribe={topic}")
            || s.starts_with(&format!("stream:subscribe={topic}["))
    })
}

fn collect_local_handles_and_descriptions(
    db: &NodeDb,
    node_id: &str,
) -> Result<(Vec<String>, BTreeMap<String, String>), NodeError> {
    let records = db.messages().list_handles(Some(node_id))?;
    let mut handles = Vec::with_capacity(records.len());
    let mut descriptions = BTreeMap::new();
    for rec in records {
        if let Some(desc) = rec.description {
            if !desc.is_empty() {
                descriptions.insert(rec.handle.clone(), desc);
            }
        }
        handles.push(rec.handle);
    }
    Ok((handles, descriptions))
}

fn load_channel_policies_from_db(db: &NodeDb) -> BTreeMap<String, ChannelPolicy> {
    let Ok(Some(raw)) = db.local().get_metadata("channel_policies") else {
        return BTreeMap::new();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

fn peer_may_advertise_indirect_routes(peer: &PeerRecord) -> bool {
    peer.status == PeerStatus::Active
        && peer.profile == hyp_store::PeerProfile::Router
        && peer.trust_tier == TrustTier::Org
}

fn peer_has_any_kv_read(scopes: &ScopeSet) -> bool {
    scopes
        .raw_scopes()
        .iter()
        .any(|s| s == "*" || s == "kv:*" || s == "kv:read" || s.starts_with("kv:read="))
}

fn extract_signed_human_revocation(data: &Value) -> Result<SignedHumanRevocationV1, NodeError> {
    let candidate = if data.get("payload").is_some() && data.get("sig").is_some() {
        data.clone()
    } else if let Some(inner) = data
        .get("revocation")
        .or_else(|| data.get("signedRevocation"))
    {
        inner.clone()
    } else {
        return Err(NodeError::BadRequest(
            "to.hyphae.human.revocation.v1 payload missing signed revocation object".into(),
        ));
    };
    let signed: SignedHumanRevocationV1 = serde_json::from_value(candidate).map_err(|e| {
        NodeError::BadRequest(format!(
            "invalid to.hyphae.human.revocation.v1 payload: {e}"
        ))
    })?;
    if signed.payload.is_empty() || signed.sig.is_empty() {
        return Err(NodeError::BadRequest(
            "to.hyphae.human.revocation.v1 payload and sig must be non-empty".into(),
        ));
    }
    Ok(signed)
}

fn load_active_authenticated_peer(
    db: &NodeDb,
    peer_id: &str,
) -> Result<AuthenticatedPeer, NodeError> {
    load_active_authenticated_peer_with_profile(db, peer_id).map(|(peer, _)| peer)
}

fn load_active_authenticated_peer_with_profile(
    db: &NodeDb,
    peer_id: &str,
) -> Result<(AuthenticatedPeer, hyp_store::PeerProfile), NodeError> {
    let peer: PeerRecord = db
        .peers()
        .get_peer(peer_id)?
        .ok_or_else(|| NodeError::Unauthorized(format!("unknown peer '{peer_id}'")))?;
    if peer.status != PeerStatus::Active {
        return Err(NodeError::Unauthorized(format!(
            "peer '{peer_id}' is not active (status: {})",
            peer.status.as_str()
        )));
    }
    let now = now_ms();
    // Fail closed if every inbound grant for this peer has been revoked or expired (P1-18).
    let inbound_grants: Vec<GrantRecord> = db
        .peers()
        .list_grants(Some(peer_id))?
        .into_iter()
        .filter(|g| g.direction == GrantDirection::Inbound)
        .collect();
    if !inbound_grants.is_empty() {
        let mut any_not_revoked = false;
        let mut any_valid = false;
        for g in &inbound_grants {
            if db.peers().is_grant_revoked(&g.id)? {
                continue;
            }
            any_not_revoked = true;
            if let Some(exp) = g.expires_at {
                if exp <= now {
                    continue;
                }
            }
            any_valid = true;
            break;
        }
        if !any_not_revoked {
            return Err(NodeError::Unauthorized(format!(
                "all grants for peer '{peer_id}' have been revoked"
            )));
        }
        if !any_valid {
            return Err(NodeError::Unauthorized(format!(
                "all grants for peer '{peer_id}' have expired"
            )));
        }
    }

    Ok((
        AuthenticatedPeer {
            peer_id: peer.peer_id,
            scopes: ScopeSet::from_strings(&peer.scopes),
            trust_tier: peer.trust_tier,
        },
        peer.profile,
    ))
}

fn lookup_peer_signing_key_in_db(
    db: &NodeDb,
    peer_id: &str,
) -> Result<Option<Ed25519PublicKey>, NodeError> {
    let keys = db
        .peers()
        .list_peer_keys(peer_id, Some(KeyUse::Signing), true)?;
    let Some(rec) = keys.last() else {
        return Ok(None);
    };
    let jwk: CryptoOkpJwk = serde_json::from_str(&rec.jwk_json)?;
    Ok(Some(jwk.to_ed25519()?))
}

fn lookup_peer_encryption_key_in_db(
    db: &NodeDb,
    peer_id: &str,
) -> Result<Option<X25519PublicKey>, NodeError> {
    let keys = db
        .peers()
        .list_peer_keys(peer_id, Some(KeyUse::Encryption), true)?;
    let Some(rec) = keys.last() else {
        return Ok(None);
    };
    let jwk: CryptoOkpJwk = serde_json::from_str(&rec.jwk_json)?;
    Ok(Some(jwk.to_x25519()?))
}

fn parse_auth_kv(input: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    for part in input.split(',') {
        let part = part.trim();
        if let Some((k, v)) = part.split_once('=') {
            let clean_v = v
                .trim()
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .unwrap_or(v.trim());
            out.insert(k.trim().to_string(), clean_v.to_string());
        }
    }
    out
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct BearerTokenBinding {
    peer_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    grant_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    sign_kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    issued_at: Option<i64>,
}

fn parse_bearer_token_binding(raw: &str) -> Result<BearerTokenBinding, NodeError> {
    let trimmed = raw.trim();
    if trimmed.starts_with('{') {
        serde_json::from_str::<BearerTokenBinding>(trimmed)
            .map_err(|_| NodeError::Unauthorized("corrupt bearer credential binding".into()))
    } else if !trimmed.is_empty() {
        Ok(BearerTokenBinding {
            peer_id: trimmed.to_string(),
            grant_id: None,
            sign_kid: None,
            issued_at: None,
        })
    } else {
        Err(NodeError::Unauthorized(
            "empty bearer credential binding".into(),
        ))
    }
}

#[derive(Clone, Copy)]
enum PeerKeyPersistence {
    Upsert,
    Rotate,
}

fn persist_peer_with_keys(
    db: &NodeDb,
    peer: &PeerInput,
    persistence: PeerKeyPersistence,
    keys: [(String, serde_json::Result<String>); 2],
    now: i64,
) -> Result<(), NodeError> {
    db.peers().upsert_peer(peer, now)?;
    persist_peer_key_pair(db, &peer.peer_id, persistence, keys, now)
}

fn persist_peer_key_pair(
    db: &NodeDb,
    peer_id: &str,
    persistence: PeerKeyPersistence,
    keys: [(String, serde_json::Result<String>); 2],
    now: i64,
) -> Result<(), NodeError> {
    let peers = db.peers();
    for ((kid, jwk_json), key_use) in keys.into_iter().zip([KeyUse::Signing, KeyUse::Encryption]) {
        let input = PeerKeyInput {
            peer_id: peer_id.to_owned(),
            kid,
            key_use,
            jwk_json: jwk_json?,
            status: KeyStatus::Active,
            expires_at: None,
        };
        match persistence {
            PeerKeyPersistence::Upsert => peers.upsert_peer_key(&input, now),
            PeerKeyPersistence::Rotate => peers.rotate_peer_key(&input, now),
        }?;
    }
    Ok(())
}

fn expand_node_scopes<S: AsRef<str>>(raw_scopes: &[S]) -> Result<Vec<String>, NodeError> {
    let normal: Vec<&str> = raw_scopes.iter().map(|s| s.as_ref().trim()).collect();
    expand_v2_scopes(&normal).map_err(|e| NodeError::BadRequest(format!("invalid scopes: {e}")))
}

/// Helper to generate a random 160-bit P2P secret (re-exported constant check).
#[allow(dead_code)]
const _P2P_SECRET_LEN_CHECK: usize = P2P_SECRET_BYTES;
