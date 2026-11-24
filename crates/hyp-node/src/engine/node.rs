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
use std::fs::{self, File};
use std::io::BufReader;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use http::header::AUTHORIZATION;
use http::{HeaderMap, Method, Request};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{Value, json};
use tokio::sync::{Notify, RwLock, broadcast, watch};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use hyp_crypto::compat_v1::{
    PairingCodeV1, derive_pairing_key_v1, format_pairing_code_v1, parse_pairing_code_v1,
};
use hyp_crypto::e2ee::{
    ChannelContext, ChannelEnvelopeV1, DmContext, DmEnvelopeV1, EpochMember, EpochScope,
    KvContext, KvEnvelopeV1, RoomEpochKey, SignedEpochKeyBundle, create_epoch_bundle,
    open_channel_message, open_dm, open_epoch_bundle, open_kv_entry, rotate_epoch_bundle,
    seal_channel_message, seal_dm, seal_kv_entry,
};
use hyp_crypto::jcs::to_canonical_json;
use hyp_crypto::pairing::{
    AdminInviteV2, GrantV2, P2P_SECRET_BYTES, P2pOfferToken, P2pPairConfirmation, P2pPairResponse,
    create_p2p_confirmation, create_p2p_offer, create_p2p_response, decode_am2, decode_hp2p1,
    encode_am2, encode_hp2p1, sign_grant_v2, verify_grant_v2, verify_p2p_confirmation,
    verify_p2p_response,
};
use hyp_crypto::rfc3339::{format_rfc3339_millis, parse_rfc3339_millis};
use hyp_crypto::transfer::{
    SignedTransferHeaderV2, StreamEncryptParams, TarInputEntry, TarPackOptions, TarUnpackOptions,
    decrypt_stream_v2, default_stage1_attachment_guard, encrypt_stream_v2, pack_tar_gz,
    unpack_tar_gz,
};
use hyp_crypto::{
    Ed25519KeyPair, Ed25519PublicKey, NodeIdentityKeys, OkpJwk as CryptoOkpJwk, SecretStore,
    SignedPayload, X25519PublicKey,
};
use hyp_proto::address::{
    Channel, Handle, LOCAL_NODE_ID, NodeId, NodeScope, PeerTarget, QualifiedChannel, resolve_topic,
};
use hyp_proto::cloudevent::{
    CONTENT_TYPE_E2EE_JSON, CONTENT_TYPE_JSON, CloudEvent as ProtoCloudEvent, ProvenanceError,
};
use hyp_proto::filter::{
    DiagnosticSeverity, Filter as ProtoFilter, LocalSubscription, ObservedTopicStats,
    SubscriptionDiagnostic, TopicCatalogEntry, compile_upstream_pushdown, diagnose_subscription,
};
use hyp_proto::manifest::{
    AdvertisedKvNamespace, AdvertisedResources, AdvertisedTopic, CapabilityToken, E2eePolicy,
    ManifestIdentity, ManifestPolicy, NegotiatedSession, NodeManifestPayload,
    PeerCapabilitiesView, PeerTrustHistory, SignedNodeManifest, negotiate_capabilities,
};
use hyp_proto::problem::ProblemDetails;
use hyp_proto::scopes::{ScopePreset, ScopeSet, expand_v2_scopes, extract_confined_values};
use hyp_store::{
    AckOutcome, ChannelEpoch, ChannelEpochInput, DeliveryMode, DueBatch,
    EnqueueMessage, GateState, GrantDirection, GrantInput, GrantRecord, HandleRecord, IngestResult,
    KeyStatus, KeyUse, KvDeleteInput, KvDeleteResult, KvEntry, KvEpoch, KvEpochInput, KvSetInput,
    MailboxEntry, MailboxInsert, MailboxKind, MailboxPutResult, ManifestCacheUpdate, MessageRecord,
    NodeDb, PeerInput, PeerKeyInput, PeerRecord, PeerStatus, PostChannelInput, PostChannelResult,
    Session, Subscription, SubscriptionSpec, TransferRecord, TransferSubmit, TrustTier,
    UpstreamPushdownInput, WriteModel, format_address, now_ms, parse_address, sha256_hex, uuid_v4,
};

use crate::adapters::github_public::canonicalize_repo;
use crate::adapters::{
    AdapterError, AdapterHealth, BoxFuture, CompiledSubscription, GitHubPublicAdapter, NodeAdapter,
    NodeAdapterHost, PublishErrorCode, PublishOutcome, PublishStatus,
};
use crate::engine::config::{
    ChannelMode, ChannelPolicy, NodeConfig, NodeError, crypto_jwk_to_proto, profile_to_store,
    proto_ce_to_store, proto_filter_to_store, proto_jwk_to_crypto, store_ce_to_proto,
    store_filter_to_proto,
};
use crate::engine::http_util::{
    HttpClient, compute_etag, full_body,
};
use crate::engine::peer_link::{
    ChannelDirectoryEntry, ChannelJoinResponse, ChannelPostRequest, GuestPairReply,
    GuestPairRequest, KeyRegPayloadV2, KvSetBody, MAX_JSON_RESPONSE_BYTES, ManifestFetchOutcome,
    P2pPairServerReply, PairBindingV2, PairRequestV2, PairServerReply, PeerAuth,
    PeerKeyDirectoryEntry, PeerLink, PostMessageRequest, PublishEventRequest,
    PutChannelEpochRequest, PutKeyRequest, PutKvEpochRequest, PutSubscriptionsRequest,
    SubscriptionInputWire, guest_pair_proof_canonical, http_auth_signing_input, spawn_sse_worker,
};

const MANIFEST_TTL_MS: i64 = 24 * 60 * 60 * 1000;
const MANIFEST_WINDOW_REFRESH_MS: i64 = 60 * 60 * 1000;
const HTTP_AUTH_SKEW_MS: i64 = 5 * 60 * 1000;
const MAX_HTTP_AUTH_NONCES: usize = 16_384;
const DEFAULT_TRANSFER_TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// Authenticated remote peer context attached to incoming HTTP requests.
#[derive(Debug, Clone)]
pub struct AuthenticatedPeer {
    pub peer_id: String,
    pub scopes: ScopeSet,
    pub trust_tier: TrustTier,
}

/// Summary returned after pairing and activating a `PeerLink`.
#[derive(Debug, Clone)]
pub struct PeerLinkInfo {
    pub peer_id: String,
    pub endpoint: String,
    pub negotiated: NegotiatedSession,
}

/// Result of `UnifiedNode::send_dm`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendDmResult {
    pub id: String,
    pub to: String,
    pub routed_via: String,
    pub encrypted: bool,
}

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

/// Request for `UnifiedNode::subscribe_local_or_remote`.
#[derive(Debug, Clone)]
pub struct SubscribeRequest {
    pub id: Option<String>,
    pub subscriber_session: String,
    /// Qualified topic (`local.<topic>`, `<node-id>.<topic>`, or shorthand `<topic>`).
    pub qualified_topic: String,
    pub filters: Vec<ProtoFilter>,
    pub coalesce_seconds: u32,
    pub mode: DeliveryMode,
}

/// Result of `UnifiedNode::subscribe_local_or_remote`.
#[derive(Debug, Clone)]
pub struct SubscribeResult {
    pub subscription: Subscription,
    pub origin_node: String,
    pub topic: String,
    pub diagnostics: Vec<SubscriptionDiagnostic>,
    pub pushdown_shards: usize,
}

#[derive(Debug, Clone, Default)]
struct ManifestWindow {
    version: u64,
    issued_at_ms: i64,
}

/// Composable Hyphae v2 Unified Rust `Node` engine.
pub struct UnifiedNode {
    config: NodeConfig,
    identity: Arc<NodeIdentityKeys>,
    secrets: SecretStore,
    db: Mutex<NodeDb>,
    http_client: HttpClient,
    bound_addr: Mutex<Option<SocketAddr>>,
    manifest_window: Mutex<ManifestWindow>,
    room_keys: Mutex<HashMap<(String, String, String, u64), RoomEpochKey>>,
    min_epochs: Mutex<HashMap<(String, String, String), u64>>,
    kv_max_seen_version: Mutex<HashMap<(String, String, String), u64>>,
    remote_channel_policies: Mutex<HashMap<(String, String), ChannelPolicy>>,
    pending_p2p_offers: Mutex<HashMap<String, P2pOfferToken>>,
    seen_http_nonces: Mutex<HashMap<(String, String), i64>>,
    guest_join_timestamps: Mutex<VecDeque<i64>>,
    github_public: Mutex<Option<Arc<GitHubPublicAdapter>>>,
    peer_links: RwLock<HashMap<String, Arc<PeerLink>>>,
    sse_tasks: Mutex<HashMap<String, JoinHandle<()>>>,
    inbox_tx: broadcast::Sender<String>,
    local_inbox_tx: broadcast::Sender<String>,
    in_flight_by_peer: Mutex<HashMap<String, HashSet<String>>>,
    scheduler_notify: Arc<Notify>,
    shutdown_tx: watch::Sender<bool>,
    scheduler_handle: Mutex<Option<JoinHandle<()>>>,
}

impl UnifiedNode {
    /// Opens (or initializes) a Unified `Node` backed by `<state_dir>/node.sqlite` and
    /// `SecretStore`, sweeps orphaned transfer staging files, and starts the exact
    /// zero-polling deadline scheduler loop.
    pub fn open(config: NodeConfig) -> Result<Arc<Self>, NodeError> {
        fs::create_dir_all(&config.state_dir)?;
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
        if db.local().get_metadata("manifest_version")?.is_none() {
            db.local().set_metadata("manifest_version", "1")?;
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
        let (inbox_tx, _) = broadcast::channel(256);
        let (local_inbox_tx, _) = broadcast::channel(256);
        let (shutdown_tx, _) = watch::channel(false);

        let node = Arc::new(Self {
            config,
            identity,
            secrets,
            db: Mutex::new(db),
            http_client,
            bound_addr: Mutex::new(None),
            manifest_window: Mutex::new(ManifestWindow::default()),
            room_keys: Mutex::new(HashMap::new()),
            min_epochs: Mutex::new(HashMap::new()),
            kv_max_seen_version: Mutex::new(HashMap::new()),
            remote_channel_policies: Mutex::new(HashMap::new()),
            pending_p2p_offers: Mutex::new(HashMap::new()),
            seen_http_nonces: Mutex::new(HashMap::new()),
            guest_join_timestamps: Mutex::new(VecDeque::new()),
            github_public: Mutex::new(None),
            peer_links: RwLock::new(HashMap::new()),
            sse_tasks: Mutex::new(HashMap::new()),
            inbox_tx,
            local_inbox_tx,
            in_flight_by_peer: Mutex::new(HashMap::new()),
            scheduler_notify: Arc::new(Notify::new()),
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

                if let (Ok(report), _) = &step {
                    if report.events.batches_closed > 0 {
                        node.notify_all_inbox_subscribers();
                    }
                }

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

    /// Gracefully stops any attached live source adapters (e.g. `GitHubPublicAdapter`).
    pub async fn shutdown_adapters(&self) {
        let adapter = self
            .github_public
            .lock()
            .expect("github_public lock poisoned")
            .take();
        if let Some(gh) = adapter {
            let _ = gh.stop().await;
        }
    }

    /// Gracefully stops the scheduler, attached source adapters, and all background SSE peer links.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
        self.scheduler_notify.notify_waiters();
        if let Some(gh) = self
            .github_public
            .lock()
            .expect("github_public lock poisoned")
            .take()
        {
            if let Ok(handle) = tokio::runtime::Handle::try_current() {
                handle.spawn(async move {
                    let _ = gh.stop().await;
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

    pub fn identity(&self) -> &NodeIdentityKeys {
        &self.identity
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
    pub fn set_channel_policy(&self, channel: &str, policy: ChannelPolicy) -> Result<(), NodeError> {
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
        Ok(db.local().register_session(session_id, backend_json, now_ms())?)
    }

    /// Enrolls a local handle for `session_id` and syncs local handles to every active `PeerLink`.
    pub async fn register_handle(
        &self,
        session_id: &str,
        handle: &str,
    ) -> Result<HandleRecord, NodeError> {
        let _ = Handle::new(handle)?;
        let (record, all_handles) = {
            let db = self.db();
            let now = now_ms();
            if db.local().get_session(session_id)?.is_none() {
                db.local().register_session(session_id, "{}", now)?;
            }
            db.local().set_session_handle(session_id, Some(handle), now)?;
            let rec = db.messages().register_handle(
                self.config.node_id.as_str(),
                handle,
                Some(session_id),
                now,
            )?;
            let all: Vec<String> = db
                .messages()
                .list_handles(Some(self.config.node_id.as_str()))?
                .into_iter()
                .map(|h| h.handle)
                .collect();
            (rec, all)
        };

        let links: Vec<Arc<PeerLink>> = self.peer_links.read().await.values().cloned().collect();
        for link in links {
            let _ = link.put_handles(all_handles.clone()).await;
        }

        Ok(record)
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
        let manifest_version = self.current_manifest_version()?;
        let issued_at_ms = {
            let mut win = self
                .manifest_window
                .lock()
                .expect("manifest_window lock poisoned");
            let now = now_ms();
            if win.version != manifest_version
                || win.issued_at_ms == 0
                || now - win.issued_at_ms >= MANIFEST_WINDOW_REFRESH_MS
            {
                win.version = manifest_version;
                win.issued_at_ms = now;
            }
            win.issued_at_ms
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
                    if peer_may_see_topic(&peer.scopes, &t.topic) {
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
                if !topics.iter().any(|t| t.topic == "kv") && peer_may_see_topic(&peer.scopes, "kv")
                {
                    topics.push(AdvertisedTopic {
                        topic: "kv".to_string(),
                        kind: Some("kv".to_string()),
                        description: Some("Built-in Shared KV change stream".to_string()),
                    });
                }

                let mut channel_set: BTreeSet<String> = BTreeSet::new();
                {
                    let db = self.db();
                    if let Ok(list) = db.channels().list_channels(Some(self.config.node_id.as_str()))
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
            capabilities: self.config.advertised_capabilities(),
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

    fn local_capabilities_view(&self) -> PeerCapabilitiesView {
        PeerCapabilitiesView {
            node_id: self.config.node_id.clone(),
            hyphae_version: self.config.hyphae_version.clone(),
            protocol_range: self.config.protocol_range,
            manifest_version: self.current_manifest_version().ok(),
            audience: None,
            expires_at: None,
            capabilities: self
                .config
                .advertised_capabilities()
                .into_iter()
                .collect(),
            require_e2ee: self.config.e2ee_policy == E2eePolicy::Required,
            is_legacy_v1: false,
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
        let manifest_signing_jwk = proto_jwk_to_crypto(&payload.identity.signing_jwk);
        let manifest_enc_jwk = proto_jwk_to_crypto(&payload.identity.encryption_jwk);
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

    /// Negotiates capabilities with a legacy v1 router (`GET /v1/manifest` -> `404`),
    /// failing closed under `E2eePolicy::Required` or after previous E2EE ratcheting.
    pub fn negotiate_legacy_v1_peer(
        &self,
        peer_id: &str,
        keys_endpoint_present: bool,
    ) -> Result<NegotiatedSession, NodeError> {
        let nid = NodeId::new(peer_id)?;
        let history = self.build_trust_history(peer_id, false)?;
        let local_view = self.local_capabilities_view();
        let remote_view = PeerCapabilitiesView::synthesize_legacy_v1(nid, keys_endpoint_present);
        let now_rfc = format_rfc3339_millis(now_ms());
        let policy = self.effective_e2ee_policy_for_peer(peer_id);

        Ok(negotiate_capabilities(
            &local_view,
            &remote_view,
            self.config.node_id.as_str(),
            &now_rfc,
            policy,
            &history,
        )?)
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

    /// Authenticates an incoming peer HTTP request via either `Authorization: Bearer <token>`
    /// or `Authorization: Hyphae-Ed25519 ...`. Returns `Ok(None)` if no Authorization header is
    /// present; fails closed with `NodeError::Unauthorized` on any invalid/revoked credential.
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
            let db = self.db();
            let Some(peer_id) = db.local().get_metadata(&format!("auth_token:{hash}"))? else {
                return Err(NodeError::Unauthorized("unknown bearer credential".into()));
            };
            let peer = load_active_authenticated_peer(&db, &peer_id)?;
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
            if nonce.is_empty() {
                return Err(NodeError::Unauthorized(
                    "empty nonce in Ed25519 auth".into(),
                ));
            }
            let sig = params
                .get("sig")
                .ok_or_else(|| NodeError::Unauthorized("missing sig in Ed25519 auth".into()))?;

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
                let peer = load_active_authenticated_peer(&db, peer_id)?;
                let signing_pk = lookup_peer_signing_key_in_db(&db, peer_id)?.ok_or_else(|| {
                    NodeError::Unauthorized(format!("no pinned signing key for peer '{peer_id}'"))
                })?;
                let signing_input =
                    http_auth_signing_input(method, path_and_query, ts, nonce, body_sha256);
                signing_pk
                    .verify_domain_b64("http-auth", &signing_input, sig)
                    .map_err(|_| {
                        NodeError::Unauthorized("Ed25519 auth signature invalid".into())
                    })?;
                peer
            };

            // Bounded in-memory replay guard: reject any (peer_id, nonce) reuse while the
            // signed request could still be valid within the skew window.
            let expires_at = ts.saturating_add(HTTP_AUTH_SKEW_MS);
            let mut nonces = self
                .seen_http_nonces
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let key = (peer_id.clone(), nonce.clone());
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

            return Ok(Some(peer));
        }

        Err(NodeError::Unauthorized(
            "unsupported Authorization scheme".into(),
        ))
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

    fn issue_peer_bearer_token(&self, peer_id: &str) -> Result<String, NodeError> {
        let rng = SystemRandom::new();
        let mut raw = Zeroizing::new([0u8; 32]);
        rng.fill(&mut *raw)
            .map_err(|_| NodeError::Http("CSPRNG failure generating auth credential".into()))?;
        let token = URL_SAFE_NO_PAD.encode(*raw);
        let hash = sha256_hex(token.as_bytes());
        let db = self.db();
        db.local()
            .set_metadata(&format!("auth_token:{hash}"), peer_id)?;
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
        let expanded = expand_v2_scopes(scopes)
            .map_err(|e| NodeError::BadRequest(format!("invalid scopes: {e}")))?;

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
        let token = encode_am2(&invite)?;
        Ok((token, record))
    }

    /// Server-side handler for `POST /v1/pair` (Org Admin-CA `am2_` single-use binding claim).
    pub fn handle_admin_pair_request(
        &self,
        req: &PairRequestV2,
    ) -> Result<PairServerReply, NodeError> {
        let admin_proto_jwk = self.config.admin_jwk.as_ref().ok_or_else(|| {
            NodeError::BadRequest("this node has no configured adminJwk for am2_ pairing".into())
        })?;
        let admin_pk = proto_jwk_to_crypto(admin_proto_jwk).to_ed25519()?;

        let grant_rec = {
            let db = self.db();
            db.peers().get_grant(&req.grant_id)?
        }
        .ok_or_else(|| NodeError::NotFound(format!("grant '{}' not found", req.grant_id)))?;

        let is_revoked = {
            let db = self.db();
            db.peers().is_grant_revoked(&req.grant_id)?
        };
        if is_revoked {
            return Err(NodeError::Unauthorized("grant has been revoked".into()));
        }

        let signed_grant: SignedPayload = serde_json::from_str(&grant_rec.signed_json)?;
        let grant = verify_grant_v2(&signed_grant, &admin_pk)?;
        let pairing_jwk = grant.pairing_key.as_ref().ok_or_else(|| {
            NodeError::BadRequest("grant does not carry a one-time pairingKey".into())
        })?;
        let pairing_pk = pairing_jwk.to_ed25519()?;

        // Verify pairingSig (possession of OOB secret) & selfSig (possession of node signing key).
        pairing_pk.verify_domain_b64("binding", req.payload.as_bytes(), &req.pairing_sig)?;
        let binding: PairBindingV2 = serde_json::from_str(&req.payload)?;
        if binding.v != 2 || binding.grant_id != grant.id || binding.node_id != grant.node_id {
            return Err(NodeError::BadRequest(
                "pairing binding grantId or nodeId mismatch".into(),
            ));
        }
        let client_sign_pk = binding.signing_jwk.to_ed25519()?;
        let client_enc_pk = binding.encryption_jwk.to_x25519()?;
        client_sign_pk.verify_domain_b64("binding-self", req.payload.as_bytes(), &req.self_sig)?;

        let now = now_ms();
        let entry_json = serde_json::to_string(req)?;
        let trust_tier = match grant.trust_tier.as_deref() {
            Some("org") => TrustTier::Org,
            Some("guest") => TrustTier::Guest,
            _ => TrustTier::Peer,
        };

        // Atomically claim the single-use grant inside BEGIN IMMEDIATE!
        {
            let db = self.db();
            db.peers().claim_grant(&grant.id, &entry_json, now)?;
            db.peers().upsert_peer(
                &PeerInput {
                    peer_id: binding.node_id.clone(),
                    endpoint: None,
                    profile: hyp_store::PeerProfile::Local,
                    trust_tier,
                    status: PeerStatus::Active,
                    scopes: grant.scopes.clone(),
                    auth_credential_ref: None,
                },
                now,
            )?;
            db.peers().upsert_peer_key(
                &PeerKeyInput {
                    peer_id: binding.node_id.clone(),
                    kid: client_sign_pk.kid(),
                    key_use: KeyUse::Signing,
                    jwk_json: serde_json::to_string(&binding.signing_jwk)?,
                    status: KeyStatus::Active,
                    expires_at: None,
                },
                now,
            )?;
            db.peers().upsert_peer_key(
                &PeerKeyInput {
                    peer_id: binding.node_id.clone(),
                    kid: client_enc_pk.kid(),
                    key_use: KeyUse::Encryption,
                    jwk_json: serde_json::to_string(&binding.encryption_jwk)?,
                    status: KeyStatus::Active,
                    expires_at: None,
                },
                now,
            )?;
        }

        let auth_credential = self.issue_peer_bearer_token(&binding.node_id)?;
        let caller = AuthenticatedPeer {
            peer_id: binding.node_id,
            scopes: ScopeSet::from_strings(&grant.scopes),
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

            db.peers().upsert_peer(
                &PeerInput {
                    peer_id: req.node_id.clone(),
                    endpoint: None,
                    profile: hyp_store::PeerProfile::Local,
                    trust_tier: TrustTier::Guest,
                    status: PeerStatus::Active,
                    scopes: guest_scopes.clone(),
                    auth_credential_ref: None,
                },
                now,
            )?;
            db.peers().upsert_peer_key(
                &PeerKeyInput {
                    peer_id: req.node_id.clone(),
                    kid: signing_kid,
                    key_use: KeyUse::Signing,
                    jwk_json: sign_jwk_json,
                    status: KeyStatus::Active,
                    expires_at: None,
                },
                now,
            )?;
            db.peers().upsert_peer_key(
                &PeerKeyInput {
                    peer_id: req.node_id.clone(),
                    kid: enc_kid,
                    key_use: KeyUse::Encryption,
                    jwk_json: enc_jwk_json,
                    status: KeyStatus::Active,
                    expires_at: None,
                },
                now,
            )?;
        }

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

    /// Client-side Org Admin-CA (`am2_`) onboarding: decodes `am2_`, proves possession over
    /// `POST /v1/pair`, verifies the hub's signed manifest, pins JWKs, stores `authCredential`
    /// in `SecretStore`, activates `PeerLink` + background SSE `/v1/inbox`, and syncs handles!
    pub async fn accept_am2_invite(
        self: &Arc<Self>,
        am2_token: &str,
    ) -> Result<PeerLinkInfo, NodeError> {
        let invite = decode_am2(am2_token)?;
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
        let url = format!("{}/v1/pair", invite.router.trim_end_matches('/'));
        let http_req = Request::builder()
            .method(Method::POST)
            .uri(&url)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(full_body(serde_json::to_vec(&pair_req)?))
            .map_err(|e| NodeError::Http(e.to_string()))?;
        let resp = self.http_client.request(http_req).await?;
        let (status, _headers, body) =
            HttpClient::collect(resp, MAX_JSON_RESPONSE_BYTES).await?;
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
        let expanded_offered = expand_v2_scopes(&offered_scopes)
            .map_err(|e| NodeError::BadRequest(format!("invalid offered scopes: {e}")))?;
        let expanded_requested = if requested_scopes.is_empty() {
            Vec::new()
        } else {
            expand_v2_scopes(&requested_scopes)
                .map_err(|e| NodeError::BadRequest(format!("invalid requested scopes: {e}")))?
        };

        let now = now_ms();
        let offer_id = uuid_v4();
        let expires_at = format_rfc3339_millis(now + ttl_ms);
        let offer = create_p2p_offer(
            &offer_id,
            self.config.node_id.as_str(),
            &self.endpoint_url(),
            &self.identity,
            expanded_offered.clone(),
            expanded_requested,
            &expires_at,
        )?;

        // Persist a single-use offer sentinel grant in `PeerStore` so `claim_grant` enforces
        // atomic single-use semantics across concurrent pairing requests!
        {
            let db = self.db();
            db.peers().add_grant(
                &GrantInput {
                    id: format!("p2p-offer:{offer_id}"),
                    peer_id: self.config.node_id.to_string(),
                    direction: GrantDirection::Inbound,
                    signed_json: serde_json::to_string(&json!({ "offerId": offer_id }))?,
                    scopes: expanded_offered,
                    trust_tier: TrustTier::Peer,
                    issued_at: now,
                    pair_by: Some(now + ttl_ms),
                    expires_at: None,
                },
                now,
            )?;
        }

        self.pending_p2p_offers
            .lock()
            .expect("pending_p2p_offers lock poisoned")
            .insert(offer_id, offer.clone());

        let token = encode_hp2p1(&offer)?;
        Ok((token, offer))
    }

    /// Server-side handler for `POST /v1/p2p/pair/<offerId>`: verifies 160-bit HKDF binding MAC,
    /// Bob's Ed25519 self-sig, Bob's signed grant, atomically claims the single-use offer, pins
    /// Bob's OKP JWKs, mints Bob's `authCredential`, and returns Alice's signed grant + manifest.
    pub fn handle_p2p_pair_request(
        &self,
        offer_id: &str,
        response: &P2pPairResponse,
    ) -> Result<P2pPairServerReply, NodeError> {
        let offer = self
            .pending_p2p_offers
            .lock()
            .expect("pending_p2p_offers lock poisoned")
            .get(offer_id)
            .cloned()
            .ok_or_else(|| {
                NodeError::NotFound(format!("P2P pairing offer '{offer_id}' not found"))
            })?;

        let now = now_ms();
        let verified = verify_p2p_response(&offer, response, now)?;

        // Atomically claim the single-use offer inside SQLite BEGIN IMMEDIATE!
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

        {
            let db = self.db();
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
                    id: alice_grant_id,
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
            db.peers().upsert_peer_key(
                &PeerKeyInput {
                    peer_id: verified.bob_node_id.clone(),
                    kid: verified.bob_signing_pk.kid(),
                    key_use: KeyUse::Signing,
                    jwk_json: serde_json::to_string(&verified.bob_signing_pk.to_jwk())?,
                    status: KeyStatus::Active,
                    expires_at: None,
                },
                now,
            )?;
            db.peers().upsert_peer_key(
                &PeerKeyInput {
                    peer_id: verified.bob_node_id.clone(),
                    kid: verified.bob_encryption_pk.kid(),
                    key_use: KeyUse::Encryption,
                    jwk_json: serde_json::to_string(&verified.bob_encryption_pk.to_jwk())?,
                    status: KeyStatus::Active,
                    expires_at: None,
                },
                now,
            )?;
        }

        // Remove offer from memory after single-use claim.
        self.pending_p2p_offers
            .lock()
            .expect("pending_p2p_offers lock poisoned")
            .remove(offer_id);

        let auth_credential = self.issue_peer_bearer_token(&verified.bob_node_id)?;
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
        let expanded_to_alice = expand_v2_scopes(&bob_grants_to_alice)
            .map_err(|e| NodeError::BadRequest(format!("invalid granted scopes: {e}")))?;

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

        let url = format!(
            "{}/v1/p2p/pair/{}",
            offer.endpoint.trim_end_matches('/'),
            offer.offer_id
        );
        let http_req = Request::builder()
            .method(Method::POST)
            .uri(&url)
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(full_body(serde_json::to_vec(&resp_body)?))
            .map_err(|e| NodeError::Http(e.to_string()))?;
        let resp = self.http_client.request(http_req).await?;
        let (status, _headers, body) =
            HttpClient::collect(resp, MAX_JSON_RESPONSE_BYTES).await?;
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
        let cred_ref = self.save_peer_auth_credential(&offer.node_id, &server_reply.auth_credential)?;

        {
            let db = self.db();
            db.peers().upsert_peer(
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
                now,
            )?;
            db.peers().upsert_peer_key(
                &PeerKeyInput {
                    peer_id: offer.node_id.clone(),
                    kid: alice_sign_pk.kid(),
                    key_use: KeyUse::Signing,
                    jwk_json: serde_json::to_string(&offer.signing_jwk)?,
                    status: KeyStatus::Active,
                    expires_at: None,
                },
                now,
            )?;
            db.peers().upsert_peer_key(
                &PeerKeyInput {
                    peer_id: offer.node_id.clone(),
                    kid: alice_enc_pk.kid(),
                    key_use: KeyUse::Encryption,
                    jwk_json: serde_json::to_string(&offer.encryption_jwk)?,
                    status: KeyStatus::Active,
                    expires_at: None,
                },
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
            ManifestFetchOutcome::LegacyV1 {
                keys_endpoint_present,
            } => self.negotiate_legacy_v1_peer(peer_id, keys_endpoint_present)?,
            ManifestFetchOutcome::NotModified => {
                return Err(NodeError::BadRequest(
                    "unexpected 304 Not Modified without If-None-Match".into(),
                ));
            }
        };

        self.activate_peer_link(peer_id, endpoint, negotiated)
            .await
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

        // Sync existing local handles to the newly connected peer.
        let local_handles: Vec<String> = {
            let db = self.db();
            db.messages()
                .list_handles(Some(self.config.node_id.as_str()))?
                .into_iter()
                .map(|h| h.handle)
                .collect()
        };
        if !local_handles.is_empty() {
            let _ = link.put_handles(local_handles).await;
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
            db.peers()
                .get_peer(peer_id)?
                .and_then(|p| p.manifest_etag)
        };
        match link.fetch_manifest(cached_etag.as_deref()).await? {
            ManifestFetchOutcome::NotModified => Ok((true, None)),
            ManifestFetchOutcome::Signed { manifest, etag } => {
                let negotiated =
                    self.verify_and_cache_peer_manifest(peer_id, &manifest, etag, false)?;
                link.set_negotiated(negotiated.clone());
                Ok((false, Some(negotiated)))
            }
            ManifestFetchOutcome::LegacyV1 {
                keys_endpoint_present,
            } => {
                let negotiated =
                    self.negotiate_legacy_v1_peer(peer_id, keys_endpoint_present)?;
                link.set_negotiated(negotiated.clone());
                Ok((false, Some(negotiated)))
            }
        }
    }

    pub async fn peer_link(&self, peer_id: &str) -> Option<Arc<PeerLink>> {
        self.peer_links.read().await.get(peer_id).cloned()
    }

    async fn require_peer_link(&self, peer_id: &str) -> Result<Arc<PeerLink>, NodeError> {
        self.peer_link(peer_id)
            .await
            .ok_or_else(|| NodeError::NotFound(format!("no active PeerLink to '{peer_id}'")))
    }

    /// Finds the default hub (Router-profile peer) if any, else the sole active peer.
    async fn default_remote_peer(&self) -> Option<String> {
        let active_links: Vec<String> = self.peer_links.read().await.keys().cloned().collect();
        if active_links.is_empty() {
            return None;
        }
        let db = self.db();
        for pid in &active_links {
            if let Ok(Some(rec)) = db.peers().get_peer(pid) {
                if rec.profile == hyp_store::PeerProfile::Router {
                    return Some(pid.clone());
                }
            }
        }
        active_links.into_iter().next()
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

    /// Registers a peer's self-signed `PutKeyRequest` (`PUT /v1/keys`).
    pub fn register_peer_key_proof(
        &self,
        caller_node: &str,
        req: &PutKeyRequest,
    ) -> Result<(), NodeError> {
        let sign_pk = req.signing_jwk.to_ed25519()?;
        let enc_pk = req.encryption_jwk.to_x25519()?;
        let payload: KeyRegPayloadV2 = sign_pk.verify_signed("key-reg", &req.proof)?;
        if payload.v != 2
            || payload.node_id != caller_node
            || payload.signing_jwk != req.signing_jwk
            || payload.encryption_jwk != req.encryption_jwk
        {
            return Err(NodeError::BadRequest(
                "key registration proof does not match caller and keys".into(),
            ));
        }

        let now = now_ms();
        let db = self.db();
        db.peers().upsert_peer_key(
            &PeerKeyInput {
                peer_id: caller_node.to_string(),
                kid: sign_pk.kid(),
                key_use: KeyUse::Signing,
                jwk_json: serde_json::to_string(&req.signing_jwk)?,
                status: KeyStatus::Active,
                expires_at: None,
            },
            now,
        )?;
        db.peers().upsert_peer_key(
            &PeerKeyInput {
                peer_id: caller_node.to_string(),
                kid: enc_pk.kid(),
                key_use: KeyUse::Encryption,
                jwk_json: serde_json::to_string(&req.encryption_jwk)?,
                status: KeyStatus::Active,
                expires_at: None,
            },
            now,
        )?;
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

        // Case 2: Resolve outbound link (explicit hub -> direct P2P link -> default hub -> outbound-only local queue).
        let outbound_link: Option<Arc<PeerLink>> = if let Some(ref hub) = explicit_hub {
            Some(self.require_peer_link(hub.as_str()).await?)
        } else if let Some(direct) = self.peer_link(target_node.as_str()).await {
            Some(direct)
        } else if let Some(hub_id) = self.default_remote_peer().await {
            // Check if target_node is a paired outbound-only P2P peer connected to US via SSE.
            let is_direct_paired = {
                let db = self.db();
                db.peers()
                    .get_peer(target_node.as_str())?
                    .is_some_and(|p| p.profile == hyp_store::PeerProfile::P2p)
            };
            if is_direct_paired {
                None
            } else {
                self.peer_link(&hub_id).await
            }
        } else {
            None
        };

        // Determine routing host node (context bound into HPKE info + AEAD AAD + Ed25519 sig)
        // and check E2EE capability requirement fail-closed!
        let (routing_host, use_e2ee) = if let Some(ref link) = outbound_link {
            let supports_e2ee = self.peer_supports_cap(link.peer_id(), &CapabilityToken::DmE2eeV1, Some(link));
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
                        Some(&format!("Upgrade peer '{}' to support dm.e2ee.v1", link.peer_id())),
                    ),
                )));
            }
            let encrypt = policy != E2eePolicy::Disabled && supports_e2ee;
            (link.peer_id().to_string(), encrypt)
        } else {
            // Outbound-only P2P peer connected to our server via SSE `/v1/inbox`!
            let peer_exists = {
                let db = self.db();
                db.peers().get_peer(target_node.as_str())?.is_some()
            };
            if !peer_exists {
                return Err(NodeError::NotFound(format!(
                    "no route or paired peer found for '{target_node}'"
                )));
            }
            let policy = self.effective_e2ee_policy_for_peer(target_node.as_str());
            (self.config.node_id.to_string(), policy != E2eePolicy::Disabled)
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

    /// Server-side handler for `POST /v1/messages`: enforces `dm:send`, stores ciphertext verbatim,
    /// and delivers immediately if addressed to `self.node_id` (Direct P2P), else wakes SSE inbox.
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
                    if let Some(policy) = self.resolve_channel_policy_for_inbound(
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
                    let pt_bytes = open_channel_message(
                        &env,
                        &ctx,
                        &room_key,
                        &sender_sign_pk,
                        min_epoch,
                    )?;
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
                    let pt_bytes =
                        open_dm(&env, &ctx, &sender_sign_pk, &self.identity.encryption)?;
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

        self.deliver_plaintext_to_local_handle(
            origin_node,
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

    // ========================================================================
    // E2EE `#channels` (`channel.e2ee.v1`), Epoch Rotation & Announcement Mode
    // ========================================================================

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
            let can_post = policy.is_authorized_writer(
                self.config.node_id.as_str(),
                Some(&membership.address),
            );
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
            let policy = policies.get(&ch).cloned().unwrap_or_else(ChannelPolicy::open);
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
            l.get_channel_epoch(channel, None)
                .await?
                .map(|e| e.epoch)
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
        let mut resolved: Vec<(String, X25519PublicKey)> = Vec::with_capacity(member_nodes.len());
        for nid in member_nodes {
            let (_, enc_pk) = self.resolve_peer_keys(nid, link).await?;
            resolved.push((nid.clone(), enc_pk));
        }
        let epoch_members: Vec<EpochMember<'_>> = resolved
            .iter()
            .map(|(nid, pk)| EpochMember {
                node_id: nid.as_str(),
                enc_pk: pk,
            })
            .collect();

        let (room_key, signed_bundle) = match prev_epoch {
            None => create_epoch_bundle(
                EpochScope::Channel,
                host_node,
                channel,
                1,
                self.config.node_id.as_str(),
                &self.identity.signing,
                &epoch_members,
            )?,
            Some(prev) => rotate_epoch_bundle(
                EpochScope::Channel,
                host_node,
                channel,
                prev,
                self.config.node_id.as_str(),
                &self.identity.signing,
                &epoch_members,
            )?,
        };
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

    async fn get_or_fetch_channel_room_key(
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
        let bundle: SignedEpochKeyBundle = serde_json::from_str(&stored.key_envelope_json)?;
        let (creator_sign_pk, _) = self
            .resolve_peer_keys(&stored.creator_node_id, link)
            .await?;
        let min_epoch = self.current_min_epoch("channel", host_node, channel);
        let (rk, _payload) = open_epoch_bundle(
            &bundle,
            EpochScope::Channel,
            host_node,
            channel,
            &creator_sign_pk,
            self.config.node_id.as_str(),
            &self.identity.encryption,
            min_epoch,
        )?;
        let copy = RoomEpochKey::from_raw(rk.epoch(), *rk.key_bytes());
        self.cache_room_key("channel", host_node, channel, rk);
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

        let creator_pk = self
            .lookup_peer_signing_key(&caller.peer_id)?
            .ok_or_else(|| {
                NodeError::Unauthorized(format!(
                    "no pinned signing key for epoch creator '{}'",
                    caller.peer_id
                ))
            })?;
        let payload: hyp_crypto::e2ee::EpochKeyBundlePayload =
            creator_pk.verify_signed("epoch-key", &req.bundle)?;
        if payload.host_node != self.config.node_id.as_str()
            || payload.resource != channel
            || payload.epoch != req.epoch
            || payload.created_by != caller.peer_id
        {
            return Err(NodeError::BadRequest(
                "channel epoch bundle metadata mismatch".into(),
            ));
        }

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

    // ========================================================================
    // Shared KV (`kv.v1` & `kv.e2ee.v1`) + Atomic CloudEvent Watches
    // ========================================================================

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
            let all_covered = member_nodes
                .iter()
                .all(|m| ep_members.contains(m.as_str()));
            if all_covered {
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

        let mut resolved: Vec<(String, X25519PublicKey)> = Vec::with_capacity(all_members.len());
        for nid in &all_members {
            let (_, enc_pk) = self.resolve_peer_keys(nid, link).await?;
            resolved.push((nid.clone(), enc_pk));
        }
        let epoch_members: Vec<EpochMember<'_>> = resolved
            .iter()
            .map(|(nid, pk)| EpochMember {
                node_id: nid.as_str(),
                enc_pk: pk,
            })
            .collect();

        let (room_key, signed_bundle) = match prev_epoch {
            None => create_epoch_bundle(
                EpochScope::Kv,
                host_node,
                namespace,
                1,
                self.config.node_id.as_str(),
                &self.identity.signing,
                &epoch_members,
            )?,
            Some(prev) => rotate_epoch_bundle(
                EpochScope::Kv,
                host_node,
                namespace,
                prev,
                self.config.node_id.as_str(),
                &self.identity.signing,
                &epoch_members,
            )?,
        };
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
        {
            let db = self.db();
            let _ = db.kv().put_epoch(
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
        }
        self.cache_room_key("kv", host_node, namespace, room_key);
        Ok(new_epoch)
    }

    async fn get_or_fetch_kv_room_key(
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
        let bundle: SignedEpochKeyBundle = serde_json::from_str(&stored.key_envelope_json)?;
        let (creator_sign_pk, _) = self
            .resolve_peer_keys(&stored.creator_node_id, link)
            .await?;
        let min_epoch = self.current_min_epoch("kv", host_node, namespace);
        let (rk, _payload) = open_epoch_bundle(
            &bundle,
            EpochScope::Kv,
            host_node,
            namespace,
            &creator_sign_pk,
            self.config.node_id.as_str(),
            &self.identity.encryption,
            min_epoch,
        )?;
        let copy = RoomEpochKey::from_raw(rk.epoch(), *rk.key_bytes());
        self.cache_room_key("kv", host_node, namespace, rk);
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
        let creator_pk = self
            .lookup_peer_signing_key(&caller.peer_id)?
            .ok_or_else(|| {
                NodeError::Unauthorized(format!(
                    "no pinned signing key for kv epoch creator '{}'",
                    caller.peer_id
                ))
            })?;
        let payload: hyp_crypto::e2ee::EpochKeyBundlePayload =
            creator_pk.verify_signed("epoch-key", &req.bundle)?;
        if payload.host_node != self.config.node_id.as_str()
            || payload.resource != req.namespace
            || payload.epoch != req.epoch
            || payload.created_by != caller.peer_id
        {
            return Err(NodeError::BadRequest(
                "kv epoch bundle metadata mismatch".into(),
            ));
        }
        let db = self.db();
        Ok(db.kv().put_epoch(
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
        )?)
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

            let members = req
                .e2ee_members
                .clone()
                .unwrap_or_else(|| vec![self.config.node_id.to_string()]);
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
            self.notify_all_inbox_subscribers();
            self.notify_scheduler();
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
            self.db().kv().get(&resolved_host, namespace, key, now_ms())?
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
            self.notify_all_inbox_subscribers();
            return Ok(res);
        }
        let link = self.require_peer_link(&resolved_host).await?;
        link.kv_delete(namespace, key, expected_version).await
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

    async fn maybe_decrypt_kv_entry(
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

    fn get_kv_seen_version(&self, host_node: &str, ns: &str, key: &str) -> Option<u64> {
        self.kv_max_seen_version
            .lock()
            .expect("kv_max_seen_version lock poisoned")
            .get(&(host_node.to_string(), ns.to_string(), key.to_string()))
            .copied()
    }

    fn record_kv_seen_version(&self, host_node: &str, ns: &str, key: &str, version: u64) {
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
        let route_peer = match via_hub {
            Some(h) => h.to_string(),
            None => {
                if self.peer_link(target_node).await.is_some() {
                    target_node.to_string()
                } else {
                    self.default_remote_peer().await.ok_or_else(|| {
                        NodeError::NotFound(format!("no route to transfer target '{target_node}'"))
                    })?
                }
            }
        };
        let link = self.require_peer_link(&route_peer).await?;
        if !self.peer_supports_cap(&route_peer, &CapabilityToken::TransferStreamV2, Some(&link)) {
            return Err(NodeError::CapabilityUnsupported(Box::new(
                ProblemDetails::capability_unsupported(
                    &CapabilityToken::TransferStreamV2,
                    &route_peer,
                    &self.config.hyphae_version,
                    "unknown",
                    Some("2.0.0"),
                    true,
                    None,
                ),
            )));
        }

        let (_, recipient_enc_pk) = self.resolve_peer_keys(target_node, Some(&link)).await?;
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
            caller.scopes.may_send_files(to_node, Some(blob.len() as u64)),
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
                let _ = db
                    .local()
                    .set_metadata(&format!("transfer_handle:{id}"), h);
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
        let signed_header: SignedTransferHeaderV2 = serde_json::from_str(&transfer.header_json)?;
        let (sender_sign_pk, _) = self
            .resolve_peer_keys(&transfer.from_node, origin_link)
            .await?;

        let stage_dir = self.config.state_dir.join("transfer_stage");
        fs::create_dir_all(&stage_dir)?;
        let dec_tar_path = stage_dir.join(format!("{}.dec.tar.gz", transfer.id));
        let dest_dir = self
            .config
            .state_dir
            .join("received_transfers")
            .join(&transfer.id);

        let unpack_res = (|| -> Result<(hyp_crypto::transfer::TransferStreamHeaderV2, hyp_crypto::transfer::UnpackedTarGz), NodeError> {
            let dec_file = File::create(&dec_tar_path)?;
            let header = decrypt_stream_v2(
                &signed_header,
                blob,
                dec_file,
                &sender_sign_pk,
                self.config.node_id.as_str(),
                &self.identity.encryption,
            )?;
            let reader = BufReader::new(File::open(&dec_tar_path)?);
            let opts = TarUnpackOptions {
                attachment_guard: Some(&default_stage1_attachment_guard),
                ..TarUnpackOptions::default()
            };
            let unpacked = unpack_tar_gz(reader, &dest_dir, &opts)?;
            if unpacked.compressed_digest != header.plaintext_digest {
                let _ = fs::remove_dir_all(&dest_dir);
                return Err(NodeError::BadRequest(
                    "unpacked tar.gz OCI digest does not match signed transfer header".into(),
                ));
            }
            Ok((header, unpacked))
        })();
        let _ = fs::remove_file(&dec_tar_path);

        let (header, unpacked) = unpack_res?;

        // Deliver path-only reference (NEVER raw file bodies!) into recipient local session mailbox.
        let file_refs: Vec<Value> = unpacked
            .files
            .iter()
            .map(|f| {
                json!({
                    "archivePath": f.archive_path,
                    "diskPath": f.disk_path.display().to_string(),
                    "size": f.size,
                    "digest": f.digest,
                })
            })
            .collect();
        let notice = serde_json::to_string(&json!({
            "transferId": transfer.id,
            "from": transfer.from_node,
            "destDir": dest_dir.display().to_string(),
            "plaintextDigest": header.plaintext_digest,
            "files": file_refs,
        }))?;

        let target_handle = {
            let db = self.db();
            let hint = db
                .local()
                .get_metadata(&format!("transfer_handle:{}", transfer.id))?;
            match hint {
                Some(h) => h,
                None => db
                    .messages()
                    .list_handles(Some(self.config.node_id.as_str()))?
                    .into_iter()
                    .next()
                    .map(|h| h.handle)
                    .unwrap_or_else(|| "default".to_string()),
            }
        };

        self.deliver_plaintext_to_local_handle(
            origin_node,
            &format!("transfer:{}", transfer.id),
            &target_handle,
            &transfer.from_node,
            &notice,
            MailboxKind::Transfer,
        )?;
        Ok(dest_dir)
    }

    // ========================================================================
    // Subscriptions, Pushdown Compilation, Diagnostics & Loop Prevention
    // ========================================================================

    /// Subscribes `subscriber_session` to a local (`local.<topic>`) or remote
    /// (`<node-id>.<topic>`) event stream: persists locally, compiles & syncs upstream
    /// pushdown shards (`compile_upstream_pushdown`) to remote peers, and surfaces reachability
    /// diagnostics back to the caller (§2.2).
    pub async fn subscribe_local_or_remote(
        &self,
        req: SubscribeRequest,
    ) -> Result<SubscribeResult, NodeError> {
        let known_peers: Vec<NodeId> = {
            let db = self.db();
            db.peers()
                .list_peers(None)?
                .into_iter()
                .filter_map(|p| NodeId::new(p.peer_id).ok())
                .collect()
        };
        let default_node = match self.default_remote_peer().await {
            Some(pid) => NodeScope::Remote(NodeId::new(pid)?),
            None => NodeScope::Local,
        };
        let resolved = resolve_topic(&req.qualified_topic, &known_peers, &default_node)?;
        let topic_str = resolved.topic.as_str().to_string();
        let origin_node_str = match &resolved.node {
            NodeScope::Local => self.config.node_id.to_string(),
            NodeScope::Remote(peer_id) => peer_id.to_string(),
        };

        let store_filters: Vec<hyp_store::Filter> =
            req.filters.iter().map(proto_filter_to_store).collect();
        let sub_id = req.id.unwrap_or_else(uuid_v4);
        let now = now_ms();

        // Fail-closed subscribe-time validation against attached `github-public` adapter for local topic.
        let local_gh_adapter = if resolved.node == NodeScope::Local {
            self.github_public_adapter()
                .filter(|a| a.topic() == topic_str)
        } else {
            None
        };
        let mut local_adapter_diags = Vec::new();
        if let Some(ref adapter) = local_gh_adapter {
            let diags = adapter.validate_subscription(&topic_str, &req.filters).await;
            if let Some(first_err) = diags
                .iter()
                .find(|d| d.severity == DiagnosticSeverity::Error)
            {
                return Err(NodeError::SubscriptionRejected {
                    detail: first_err.message.clone(),
                    diagnostics: diags,
                });
            }
            local_adapter_diags = diags;
        }

        let subscription = {
            let db = self.db();
            db.events().upsert_subscription(
                &SubscriptionSpec {
                    id: sub_id,
                    origin_node: origin_node_str.clone(),
                    topic: topic_str.clone(),
                    subscriber: req.subscriber_session.clone(),
                    filters: store_filters,
                    coalesce_seconds: i64::from(req.coalesce_seconds),
                    max_batch_age_ms: None,
                    max_wakes_per_hour: None,
                    mode: req.mode,
                },
                now,
            )?
        };

        if resolved.node == NodeScope::Local {
            if let Some(ref adapter) = local_gh_adapter {
                self.sync_github_public_subscriptions(adapter).await?;
            }
            let catalog = self.local_topic_catalog();
            let mut diagnostics = diagnose_subscription(&topic_str, &req.filters, &catalog);
            diagnostics.extend(local_adapter_diags);
            return Ok(SubscribeResult {
                subscription,
                origin_node: origin_node_str,
                topic: topic_str,
                diagnostics,
                pushdown_shards: 0,
            });
        }

        // Compile upstream pushdown plan across ALL local subscriptions on `(origin_node, topic)`.
        let local_subs_for_topic: Vec<LocalSubscription> = {
            let db = self.db();
            db.events()
                .list_subscriptions(None)?
                .into_iter()
                .filter(|s| s.origin_node == origin_node_str && s.topic == topic_str)
                .map(|s| LocalSubscription {
                    filters: s.filters.iter().map(store_filter_to_proto).collect(),
                    coalesce_seconds: s.coalesce_seconds.max(0) as u32,
                })
                .collect()
        };

        let plan = compile_upstream_pushdown(&topic_str, &local_subs_for_topic);
        let shard_count = plan.shards.len();

        // Persist upstream_pushdowns locally.
        {
            let db = self.db();
            for (idx, shard) in plan.shards.iter().enumerate() {
                let filters_json = serde_json::to_string(&shard.filters)?;
                db.events().upsert_upstream_pushdown(
                    &UpstreamPushdownInput {
                        id: shard.id.clone(),
                        peer_id: origin_node_str.clone(),
                        topic: topic_str.clone(),
                        shard_index: idx as i64,
                        filters_json,
                        coalesce_seconds: i64::from(shard.coalesce_seconds),
                        local_sub_count: local_subs_for_topic.len(),
                    },
                    now,
                )?;
            }
            // Remove stale shards if shard count shrank.
            for existing in db.events().list_upstream_pushdowns(Some(&origin_node_str))? {
                if existing.topic == topic_str && (existing.shard_index as usize) >= shard_count {
                    let _ = db.events().delete_upstream_pushdown(&existing.id);
                }
            }
        }

        // Sync compiled pushdown shards to remote peer via `PUT /v1/subscriptions`.
        let link = self.require_peer_link(&origin_node_str).await?;
        let wire_subs: Vec<SubscriptionInputWire> = plan
            .shards
            .iter()
            .map(|shard| SubscriptionInputWire {
                id: shard.id.clone(),
                topic: topic_str.clone(),
                filters: shard.filters.clone(),
                coalesce_seconds: i64::from(shard.coalesce_seconds),
                max_batch_age_ms: None,
                max_wakes_per_hour: None,
                mode: DeliveryMode::Full,
            })
            .collect();

        let sync_res = link
            .put_subscriptions(&PutSubscriptionsRequest {
                subscriptions: wire_subs,
                replace_topic: Some(topic_str.clone()),
            })
            .await;

        match sync_res {
            Ok(resp) => {
                let synced_at = now_ms();
                let db = self.db();
                for shard in &plan.shards {
                    let _ = db.events().mark_pushdown_synced(&shard.id, synced_at);
                }
                Ok(SubscribeResult {
                    subscription,
                    origin_node: origin_node_str,
                    topic: topic_str,
                    diagnostics: resp.diagnostics,
                    pushdown_shards: shard_count,
                })
            }
            Err(err) => {
                let err_at = now_ms();
                let err_msg = err.to_string();
                let db = self.db();
                for shard in &plan.shards {
                    let _ = db.events().mark_pushdown_error(&shard.id, &err_msg, err_at);
                }
                Err(err)
            }
        }
    }

    /// Builds the local `TopicCatalogEntry` snapshot for `diagnose_subscription`.
    pub fn local_topic_catalog(&self) -> Vec<TopicCatalogEntry> {
        let mut catalog: Vec<TopicCatalogEntry> = self
            .config
            .topics
            .iter()
            .map(|t| TopicCatalogEntry {
                topic: t.topic.clone(),
                has_provisioned_publisher: t.has_provisioned_publisher,
                metadata: t.metadata.clone(),
                observed: ObservedTopicStats::default(),
            })
            .collect();

        if let Some(gh) = self.github_public_adapter() {
            let gh_topic = gh.topic();
            if !catalog.iter().any(|c| c.topic == gh_topic) {
                catalog.push(TopicCatalogEntry {
                    topic: gh_topic.to_string(),
                    has_provisioned_publisher: true,
                    metadata: None,
                    observed: ObservedTopicStats::default(),
                });
            }
        }
        if !catalog.iter().any(|c| c.topic == "kv") {
            catalog.push(TopicCatalogEntry {
                topic: "kv".to_string(),
                has_provisioned_publisher: true,
                metadata: None,
                observed: ObservedTopicStats::default(),
            });
        }
        catalog
    }

    /// Recomputes all active compiled subscriptions for `adapter.topic()` from `EventStore`
    /// across all peers and notifies the demand-driven `GitHubPublicAdapter`.
    async fn sync_github_public_subscriptions(
        &self,
        adapter: &Arc<GitHubPublicAdapter>,
    ) -> Result<(), NodeError> {
        let target_topic = adapter.topic().to_string();
        let compiled: Vec<CompiledSubscription> = {
            let db = self.db();
            db.events()
                .list_subscriptions(None)?
                .into_iter()
                .filter(|s| s.topic == target_topic)
                .map(|s| CompiledSubscription {
                    id: s.id,
                    subscriber: s.subscriber,
                    topic: s.topic,
                    filters: s.filters.iter().map(store_filter_to_proto).collect(),
                    coalesce_seconds: s.coalesce_seconds.max(0) as u32,
                })
                .collect()
        };
        adapter
            .on_subscriptions_changed(&target_topic, &compiled)
            .await;
        Ok(())
    }

    /// Server-side handler for `PUT /v1/subscriptions`: checks `stream:subscribe` scope &
    /// dynamic `guest-ro` constraints, runs fail-closed `GitHubPublicAdapter::validate_subscription`
    /// BEFORE saving, persists in `EventStore`, and immediately syncs active subscriptions into
    /// `GitHubPublicAdapter::on_subscriptions_changed`.
    pub async fn handle_server_put_subscriptions(
        &self,
        caller: &AuthenticatedPeer,
        req: PutSubscriptionsRequest,
    ) -> Result<(Vec<Subscription>, Vec<SubscriptionDiagnostic>), NodeError> {
        let catalog = self.local_topic_catalog();
        let gh_adapter = self.github_public_adapter();
        let mut all_diagnostics = Vec::new();
        let mut specs = Vec::with_capacity(req.subscriptions.len());
        let mut incoming_guest_repos: BTreeSet<String> = BTreeSet::new();
        let incoming_namespaced_ids: HashSet<String> = req
            .subscriptions
            .iter()
            .map(|s| format!("{}::{}", caller.peer_id, s.id))
            .collect();

        for sub in &req.subscriptions {
            match caller.scopes.check_stream_subscribe(&sub.topic, &sub.filters) {
                Ok(approval) => {
                    if caller.trust_tier == TrustTier::Guest {
                        let Some(confined_repos) =
                            extract_confined_values(&sub.filters, "exact", "repo")
                        else {
                            self.require_scope(
                                caller,
                                false,
                                &format!("stream:subscribe={}[require=exact.repo]", sub.topic),
                            )?;
                            unreachable!();
                        };
                        if confined_repos.is_empty() {
                            self.require_scope(
                                caller,
                                false,
                                &format!("stream:subscribe={}[require=exact.repo]", sub.topic),
                            )?;
                        }
                        for raw_repo in confined_repos {
                            let canonical = canonicalize_repo(&raw_repo)
                                .unwrap_or_else(|| raw_repo.to_ascii_lowercase());
                            incoming_guest_repos.insert(canonical);
                        }
                    }

                    // Fail-closed subscribe-time validation against attached `github-public` adapter
                    // BEFORE writing anything to SQLite!
                    if let Some(ref adapter) = gh_adapter {
                        if sub.topic == adapter.topic() {
                            let adapter_diags = adapter
                                .validate_subscription(&sub.topic, &sub.filters)
                                .await;
                            if let Some(first_err) = adapter_diags
                                .iter()
                                .find(|d| d.severity == DiagnosticSeverity::Error)
                            {
                                return Err(NodeError::SubscriptionRejected {
                                    detail: first_err.message.clone(),
                                    diagnostics: adapter_diags,
                                });
                            }
                            all_diagnostics.extend(adapter_diags);
                        }
                    }

                    let diags = diagnose_subscription(&sub.topic, &sub.filters, &catalog);
                    all_diagnostics.extend(diags);
                    let store_filters: Vec<hyp_store::Filter> =
                        sub.filters.iter().map(proto_filter_to_store).collect();
                    let namespaced_id = format!("{}::{}", caller.peer_id, sub.id);
                    let mut effective_wakes =
                        match (sub.max_wakes_per_hour, approval.max_batches_per_hour) {
                            (Some(a), Some(b)) => Some(a.min(b as usize)),
                            (Some(a), None) => Some(a),
                            (None, Some(b)) => Some(b as usize),
                            (None, None) => None,
                        };
                    if caller.trust_tier == TrustTier::Guest {
                        let cap = self.config.guest_pairing.max_batches_per_hour as usize;
                        effective_wakes = Some(effective_wakes.map_or(cap, |w| w.min(cap)));
                    }
                    specs.push(SubscriptionSpec {
                        id: namespaced_id,
                        origin_node: self.config.node_id.to_string(),
                        topic: sub.topic.clone(),
                        subscriber: caller.peer_id.clone(),
                        filters: store_filters,
                        coalesce_seconds: sub.coalesce_seconds,
                        max_batch_age_ms: sub.max_batch_age_ms,
                        max_wakes_per_hour: effective_wakes,
                        mode: sub.mode,
                    });
                }
                Err(hyp_proto::scopes::ScopeDenial::Denied { missing_scope, .. }) => {
                    self.require_scope(caller, false, &missing_scope)?;
                }
            }
        }

        // Cumulative per-guest repo cap across ALL active subscriptions for this guest peer!
        if caller.trust_tier == TrustTier::Guest {
            let max_repos = self.config.guest_pairing.max_repos_per_guest;
            let mut total_repos = incoming_guest_repos;
            {
                let db = self.db();
                for existing in db.events().list_subscriptions(Some(&caller.peer_id))? {
                    if incoming_namespaced_ids.contains(&existing.id) {
                        continue;
                    }
                    if req.replace_topic.as_deref() == Some(existing.topic.as_str()) {
                        continue;
                    }
                    let proto_filters: Vec<ProtoFilter> =
                        existing.filters.iter().map(store_filter_to_proto).collect();
                    if let Some(existing_repos) =
                        extract_confined_values(&proto_filters, "exact", "repo")
                    {
                        for raw_repo in existing_repos {
                            let canonical = canonicalize_repo(&raw_repo)
                                .unwrap_or_else(|| raw_repo.to_ascii_lowercase());
                            total_repos.insert(canonical);
                        }
                    }
                }
            }
            if total_repos.len() > max_repos {
                self.require_scope(
                    caller,
                    false,
                    &format!("stream:subscribe=github[maxValues={max_repos}]"),
                )?;
            }
        }

        let now = now_ms();
        let saved = {
            let db = self.db();
            if let Some(ref replace_topic) = req.replace_topic {
                let keep_ids: HashSet<&str> = specs.iter().map(|s| s.id.as_str()).collect();
                for existing in db.events().list_subscriptions(Some(&caller.peer_id))? {
                    if existing.topic == *replace_topic && !keep_ids.contains(existing.id.as_str())
                    {
                        let _ = db.events().delete_subscription(&existing.id);
                    }
                }
            }
            let mut out = Vec::with_capacity(specs.len());
            for spec in &specs {
                let mut s = db.events().upsert_subscription(spec, now)?;
                let prefix = format!("{}::", caller.peer_id);
                if let Some(stripped) = s.id.strip_prefix(&prefix) {
                    s.id = stripped.to_string();
                }
                out.push(s);
            }
            out
        };

        if let Some(ref adapter) = gh_adapter {
            let gh_topic = adapter.topic();
            let touches_gh = req.replace_topic.as_deref() == Some(gh_topic)
                || req.subscriptions.iter().any(|s| s.topic == gh_topic);
            if touches_gh {
                self.sync_github_public_subscriptions(adapter).await?;
            }
        }

        Ok((saved, all_diagnostics))
    }

    /// Server-side handler for `DELETE /v1/subscriptions?id=...`: deletes only caller-owned
    /// subscriptions and notifies `GitHubPublicAdapter::on_subscriptions_changed` so pollers tear
    /// down cleanly when refcount drops to `0`.
    pub async fn handle_server_delete_subscription(
        &self,
        caller: &AuthenticatedPeer,
        id: &str,
    ) -> Result<bool, NodeError> {
        let namespaced = format!("{}::{id}", caller.peer_id);
        let deleted = {
            let db = self.db();
            let owned_ids: HashSet<String> = db
                .events()
                .list_subscriptions(Some(&caller.peer_id))?
                .into_iter()
                .map(|s| s.id)
                .collect();
            if owned_ids.contains(&namespaced) {
                db.events().delete_subscription(&namespaced)?
            } else if owned_ids.contains(id) {
                db.events().delete_subscription(id)?
            } else {
                false
            }
        };

        if deleted {
            if let Some(adapter) = self.github_public_adapter() {
                self.sync_github_public_subscriptions(&adapter).await?;
            }
        }
        Ok(deleted)
    }

    /// Publishes an event onto a local or remote topic, stamping provenance hop headers.
    pub async fn publish_event(
        &self,
        qualified_topic: &str,
        mut event: ProtoCloudEvent,
    ) -> Result<IngestResult, NodeError> {
        let known_peers: Vec<NodeId> = {
            let db = self.db();
            db.peers()
                .list_peers(None)?
                .into_iter()
                .filter_map(|p| NodeId::new(p.peer_id).ok())
                .collect()
        };
        let resolved = resolve_topic(qualified_topic, &known_peers, &NodeScope::Local)?;
        let topic = resolved.topic.as_str().to_string();

        match resolved.node {
            NodeScope::Local => {
                let my_id = self.config.node_id.to_string();
                self.ingest_inbound_event(&my_id, &topic, &event)
            }
            NodeScope::Remote(peer_id) => {
                let max_hops = self.config.forwarding.effective_max_hops();
                event
                    .record_hop(&self.config.node_id, Some(&peer_id), max_hops)
                    .map_err(map_provenance_err)?;
                let link = self.require_peer_link(peer_id.as_str()).await?;
                link.publish_event(&PublishEventRequest { topic, event })
                    .await
            }
        }
    }

    /// Validates routing loop & hop-limit guards (`hyphaevia`, `hyphaehops`) and forwarding
    /// policy, then ingests `event` into local `EventStore` inside `BEGIN IMMEDIATE`.
    pub fn ingest_inbound_event(
        &self,
        caller_node: &str,
        topic: &str,
        event: &ProtoCloudEvent,
    ) -> Result<IngestResult, NodeError> {
        let val = serde_json::to_value(event)?;
        let (mut validated, _) = hyp_proto::cloudevent::check_cloudevent_v2(&val)?;

        // Enforce strict cycle detection & hop limit cap (§2.3).
        let max_hops = self.config.forwarding.effective_max_hops();
        let prov = validated
            .check_forwarding(&self.config.node_id, None, max_hops)
            .map_err(map_provenance_err)?;

        // Enforce default-deny transit forwarding for foreign-origin events (§2.3).
        let is_foreign_transit = prov
            .origin
            .as_ref()
            .is_some_and(|orig| orig.as_str() != caller_node && orig != &self.config.node_id);
        if is_foreign_transit && !self.config.forwarding.permits(caller_node, "*", topic) {
            return Err(NodeError::Unauthorized(format!(
                "transit forwarding denied by default policy for origin from '{caller_node}' on topic '{topic}'"
            )));
        }

        // Record this node's hop in `hyphaeorigin`/`hyphaevia`/`hyphaehops` if cross-node.
        if caller_node != self.config.node_id.as_str() {
            validated
                .record_hop(&self.config.node_id, None, max_hops)
                .map_err(map_provenance_err)?;
        }

        let store_ev = proto_ce_to_store(&validated)?;
        let now = now_ms();
        let res = {
            let db = self.db();
            db.events().ingest(
                self.config.node_id.as_str(),
                topic,
                caller_node,
                &store_ev,
                now,
            )?
        };
        self.notify_all_inbox_subscribers();
        self.notify_scheduler();
        Ok(res)
    }

    /// Ingests an inbound `DueBatch` delivered from remote peer `origin_node` inside
    /// `BEGIN IMMEDIATE` BEFORE the caller acknowledges upstream, enforcing loop/hop guards,
    /// transparently decrypting `kv.e2ee.v1` events, and delivering matching events to local
    /// session mailboxes!
    pub async fn handle_inbound_peer_batch(
        &self,
        origin_node: &str,
        batch: DueBatch,
    ) -> Result<(), NodeError> {
        let max_hops = self.config.forwarding.effective_max_hops();
        let origin_link = self.peer_link(origin_node).await;

        // 1. Validate loop/hop provenance & optionally decrypt `kv.e2ee.v1` events.
        let mut prepared_events = Vec::with_capacity(batch.events.len());
        for mut ev in batch.events {
            let proto_ev = store_ce_to_proto(&ev);
            proto_ev
                .check_forwarding(&self.config.node_id, None, max_hops)
                .map_err(map_provenance_err)?;

            // Transparently decrypt E2EE KV delta CloudEvents!
            if ev.event_type == "to.hyphae.kv.set" && ev.datacontenttype == CONTENT_TYPE_E2EE_JSON {
                if let Some(val_obj) = ev.data.get("value").cloned() {
                    if let Ok(kv_env) = serde_json::from_value::<KvEnvelopeV1>(val_obj.clone()) {
                        let ns = ev.extensions.get("ns").cloned().unwrap_or_default();
                        let key = ev.extensions.get("key").cloned().unwrap_or_default();
                        let writer = ev.extensions.get("writer").cloned().unwrap_or_default();
                        let version: u64 = ev
                            .extensions
                            .get("version")
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(kv_env.version);
                        let writer_grant_id = val_obj
                            .get("writerGrantId")
                            .and_then(Value::as_str)
                            .unwrap_or("self")
                            .to_string();
                        if let Ok((writer_pk, _)) =
                            self.resolve_peer_keys(&writer, origin_link.as_ref()).await
                        {
                            if let Ok(rk) = self
                                .get_or_fetch_kv_room_key(
                                    origin_node,
                                    &ns,
                                    kv_env.epoch,
                                    origin_link.as_ref(),
                                )
                                .await
                            {
                                let min_epoch = self.current_min_epoch("kv", origin_node, &ns);
                                let max_seen = self.get_kv_seen_version(origin_node, &ns, &key);
                                let ctx = KvContext {
                                    host_node: origin_node,
                                    namespace: &ns,
                                    key: &key,
                                    version,
                                    writer_node_id: &writer,
                                    writer_grant_id: &writer_grant_id,
                                };
                                let pt_bytes = open_kv_entry(
                                    &kv_env, &ctx, &rk, &writer_pk, min_epoch, max_seen,
                                )?;
                                let pt_val: Value = serde_json::from_slice(&pt_bytes)?;
                                self.record_kv_seen_version(origin_node, &ns, &key, version);
                                if let Some(data_map) = ev.data.as_object_mut() {
                                    data_map.insert("value".to_string(), pt_val);
                                    data_map.insert("decrypted".to_string(), json!(true));
                                }
                                ev.datacontenttype = CONTENT_TYPE_JSON.to_string();
                            }
                        }
                    }
                }
            }
            prepared_events.push(ev);
        }

        // 2. Durable local ingest inside BEGIN IMMEDIATE per event + route to local session mailboxes.
        let now = now_ms();
        let mut sessions_to_wake = HashSet::new();
        {
            let db = self.db();
            for ev in &prepared_events {
                db.events()
                    .ingest(origin_node, &batch.topic, origin_node, ev, now)?;
            }
            // Tick immediately so coalesce_seconds == 0 batches are closed, and drain local subscribers!
            let _ = db.events().tick(now);

            let local_subscribers: BTreeSet<String> = db
                .events()
                .list_subscriptions(None)?
                .into_iter()
                .filter(|s| s.origin_node == origin_node && s.topic == batch.topic)
                .map(|s| s.subscriber)
                .collect();

            for subscriber in local_subscribers {
                let due = db.events().claim_due_batches(&subscriber, now)?;
                for local_batch in due {
                    let kind = if local_batch.topic == "kv" {
                        MailboxKind::Kv
                    } else {
                        MailboxKind::Event
                    };
                    let payload_text = serde_json::to_string(&json!({
                        "batchId": local_batch.id,
                        "originNode": local_batch.origin_node,
                        "topic": local_batch.topic,
                        "events": local_batch.events,
                    }))?;
                    let put = db.local().put_in_mailbox(
                        &MailboxInsert {
                            session_id: subscriber.clone(),
                            origin_node: origin_node.to_string(),
                            item_id: format!("batch:{}", local_batch.id),
                            text: payload_text,
                            kind,
                            source: format!("{origin_node}.{}", local_batch.topic),
                            gate_state: GateState::Pending,
                            gate_reason: None,
                            traceparent: None,
                        },
                        now,
                    )?;
                    if !matches!(put, MailboxPutResult::QueueFull) {
                        db.events().ack_batch(
                            &subscriber,
                            &local_batch.id,
                            &AckOutcome::Delivered,
                            now,
                        )?;
                        sessions_to_wake.insert(subscriber.clone());
                    }
                }
            }
        }

        for sid in sessions_to_wake {
            self.notify_local_session(&sid);
        }
        self.notify_scheduler();
        Ok(())
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

fn load_channel_policies_from_db(db: &NodeDb) -> BTreeMap<String, ChannelPolicy> {
    let Ok(Some(raw)) = db.local().get_metadata("channel_policies") else {
        return BTreeMap::new();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

fn load_active_authenticated_peer(
    db: &NodeDb,
    peer_id: &str,
) -> Result<AuthenticatedPeer, NodeError> {
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
    // Fail closed if every inbound grant for this peer has been revoked.
    let inbound_grants: Vec<GrantRecord> = db
        .peers()
        .list_grants(Some(peer_id))?
        .into_iter()
        .filter(|g| g.direction == GrantDirection::Inbound)
        .collect();
    if !inbound_grants.is_empty() {
        let mut any_valid = false;
        for g in &inbound_grants {
            if !db.peers().is_grant_revoked(&g.id)? {
                any_valid = true;
                break;
            }
        }
        if !any_valid {
            return Err(NodeError::Unauthorized(format!(
                "all grants for peer '{peer_id}' have been revoked"
            )));
        }
    }

    Ok(AuthenticatedPeer {
        peer_id: peer.peer_id,
        scopes: ScopeSet::from_strings(&peer.scopes),
        trust_tier: peer.trust_tier,
    })
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

/// Helper to generate a random 160-bit P2P secret (re-exported constant check).
#[allow(dead_code)]
const _P2P_SECRET_LEN_CHECK: usize = P2P_SECRET_BYTES;
