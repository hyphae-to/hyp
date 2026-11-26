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
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::{Notify, RwLock, broadcast, watch};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use hyp_crypto::compat_v1::{
    PairingCodeV1, derive_pairing_key_v1, format_pairing_code_v1, parse_pairing_code_v1,
};
use hyp_crypto::e2ee::{
    ChannelContext, ChannelEnvelopeV1, DmContext, DmEnvelopeV1, EpochMember, EpochScope, KvContext,
    KvEnvelopeV1, RoomEpochKey, SignedEpochKeyBundle, create_epoch_bundle, open_channel_message,
    open_dm, open_epoch_bundle, open_kv_entry, rotate_epoch_bundle, seal_channel_message, seal_dm,
    seal_kv_entry,
};
use hyp_crypto::human::{
    DelegatedPairProofV1, HumanDropEnvelopeV1, HumanDropKind, HumanRevocationPayloadV1,
    NodeCertPayloadV1, SignedHumanRevocationV1, SignedNodeCertV1, decode_hcert1, decode_hdrop1,
    decode_hjoin1, encode_hcert1, is_reserved_secret_name, node_cert_sha256, open_human_drop,
    sign_delegated_pair_proof, sign_node_cert, verify_delegated_pair_proof, verify_human_invite,
    verify_human_invite_claim, verify_human_revocation, verify_node_cert,
};
use hyp_crypto::jcs::to_canonical_json;
use hyp_crypto::keystore::validate_secret_name;
use hyp_crypto::pairing::{
    AdminInviteV2, GrantV2, P2P_SECRET_BYTES, P2pOfferToken, P2pPairConfirmation, P2pPairResponse,
    create_p2p_confirmation, create_p2p_offer, create_p2p_response, decode_am2, decode_hp2p1,
    encode_am2_with_signed_grant, encode_hp2p1, extract_am2_signed_grant, sign_grant_v2,
    verify_grant_v2, verify_p2p_confirmation, verify_p2p_response,
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
    TYPE_CHANNEL_V1, TYPE_DM_V1, TYPE_HUMAN_DROP_V1, TYPE_HUMAN_REVOCATION_V1,
    TYPE_HUMAN_SECRET_STORED_V1, TYPE_TRANSFER_V1,
};
use hyp_proto::filter::{
    DiagnosticSeverity, Filter as ProtoFilter, LocalSubscription, ObservedTopicStats,
    SubscriptionDiagnostic, TopicCatalogEntry, compile_upstream_pushdown, diagnose_subscription,
};
use hyp_proto::manifest::{
    AdvertisedKvNamespace, AdvertisedResources, AdvertisedTopic, CapabilityToken, E2eePolicy,
    ManifestIdentity, ManifestPolicy, NegotiatedSession, NodeManifestPayload, PeerCapabilitiesView,
    PeerTrustHistory, SignedNodeManifest, negotiate_capabilities,
};
use hyp_proto::problem::ProblemDetails;
use hyp_proto::scopes::{
    ScopePreset, ScopeSet, expand_v2_scopes, extract_confined_values, matches_node_prefix,
    validate_delegated_human_scopes,
};
use hyp_store::{
    AckOutcome, ChannelEpoch, ChannelEpochInput, DeliveryMode, DueBatch, EnqueueMessage,
    GateAuditInput, GateDecision as StoreGateDecision, GateDirection, GateState, GrantDirection,
    GrantInput, GrantRecord, HandleRecord, HumanAuthorityInput, HumanAuthorityRecord,
    HumanAuthorityRole, HumanAuthorityStatus, HumanClaimKind, HumanDelegationPolicyInput,
    HumanNodeCertInput, IngestResult, KeyStatus, KeyUse, KvDeleteInput, KvDeleteResult, KvEntry,
    KvEpoch, KvEpochInput, KvSetInput, MailboxEntry, MailboxInsert, MailboxKind, MailboxPutOptions,
    MailboxPutResult, ManifestCacheUpdate, MessageRecord, NodeDb, PeerInput, PeerKeyInput,
    PeerRecord, PeerStatus, PostChannelInput, PostChannelResult, Session, StoreError, Subscription,
    SubscriptionSpec, TransferRecord, TransferSubmit, TrustTier, UpstreamPushdownInput, WriteModel,
    format_address, now_ms, parse_address, sha256_hex, uuid_v4,
};

use crate::adapters::github_public::canonicalize_repo;
use crate::adapters::{
    AdapterError, AdapterHealth, BoxFuture, CompiledSubscription, GitHubPublicAdapter,
    GitHubWebhookAdapter, NodeAdapter, NodeAdapterHost, PublishErrorCode, PublishOutcome,
    PublishStatus,
};
use crate::delivery::DeliveryUrgency;
use crate::engine::config::{
    ChannelMode, ChannelPolicy, NodeConfig, NodeError, NodeProfile, crypto_jwk_to_proto,
    profile_to_store, proto_ce_to_store, proto_filter_to_store, proto_jwk_to_crypto,
    store_ce_to_proto, store_filter_to_proto,
};
use crate::engine::drop_relay::DropRelay;
use crate::engine::http_util::{HttpClient, compute_etag, full_body};
use crate::engine::peer_link::{
    AuthClaimReply, AuthClaimRequest, ChannelDirectoryEntry, ChannelJoinResponse,
    ChannelPostRequest, DelegatedPairReply, DelegatedPairRequest, GuestPairReply, GuestPairRequest,
    KeyRegPayloadV2, KvSetBody, MAX_JSON_RESPONSE_BYTES, ManifestFetchOutcome, P2pPairServerReply,
    PairBindingV2, PairRequestV2, PairServerReply, PeerAuth, PeerKeyDirectoryEntry, PeerLink,
    PostMessageRequest, PublishEventRequest, PutChannelEpochRequest, PutKeyRequest,
    PutKvEpochRequest, PutSubscriptionsRequest, SubscriptionInputWire, guest_pair_proof_canonical,
    http_auth_signing_input, spawn_sse_worker,
};
use crate::engine::wake::SystemWakeEvent;
use crate::gates::{
    GateDecision, InboundContext, SecurityGatePipeline, TrustTier as GateTrustTier,
    VerifiedHumanClaim,
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

    /// Authenticates an incoming peer HTTP request via `Authorization: Bearer <token>`,
    /// `Authorization: Hyphae-Ed25519 ...`, or standalone Ed25519 signature headers
    /// (`X-Hyphae-Node`, `X-Hyphae-Timestamp`, `X-Hyphae-Nonce`, `X-Hyphae-Sig`).
    /// Returns `Ok(None)` if no authentication headers are present; fails closed with
    /// `NodeError::Unauthorized` on any invalid, malformed, replayed, or revoked credential.
    pub fn authenticate_request(
        &self,
        headers: &HeaderMap,
        method: &str,
        path_and_query: &str,
        body_sha256: &str,
    ) -> Result<Option<AuthenticatedPeer>, NodeError> {
        let sig_hdr = headers
            .get("x-hyphae-sig")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let ts_hdr = headers
            .get("x-hyphae-timestamp")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let nonce_hdr = headers
            .get("x-hyphae-nonce")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let node_hdr = headers
            .get("x-hyphae-node")
            .and_then(|v| v.to_str().ok())
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let has_any_ed25519_hdr = sig_hdr.is_some() || ts_hdr.is_some() || nonce_hdr.is_some();

        let Some(raw_auth) = headers.get(AUTHORIZATION) else {
            if !has_any_ed25519_hdr {
                return Ok(None);
            }
            let peer_id = node_hdr.ok_or_else(|| {
                NodeError::Unauthorized("missing X-Hyphae-Node header for Ed25519 auth".into())
            })?;
            let ts_str = ts_hdr.ok_or_else(|| {
                NodeError::Unauthorized("missing X-Hyphae-Timestamp header for Ed25519 auth".into())
            })?;
            let nonce = nonce_hdr.ok_or_else(|| {
                NodeError::Unauthorized("missing X-Hyphae-Nonce header for Ed25519 auth".into())
            })?;
            let sig = sig_hdr.ok_or_else(|| {
                NodeError::Unauthorized("missing X-Hyphae-Sig header for Ed25519 auth".into())
            })?;
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
            // Defense-in-depth: if the caller also supplied X-Hyphae-Sig headers alongside Bearer,
            // verify the Ed25519 signature and confirm it binds to the same peer identity.
            if has_any_ed25519_hdr {
                let claimed_node = node_hdr.unwrap_or(&peer.peer_id);
                if claimed_node != peer.peer_id {
                    return Err(NodeError::Unauthorized(
                        "X-Hyphae-Node does not match Bearer credential peer".into(),
                    ));
                }
                let ts_str = ts_hdr.ok_or_else(|| {
                    NodeError::Unauthorized("missing X-Hyphae-Timestamp header".into())
                })?;
                let nonce = nonce_hdr.ok_or_else(|| {
                    NodeError::Unauthorized("missing X-Hyphae-Nonce header".into())
                })?;
                let sig = sig_hdr
                    .ok_or_else(|| NodeError::Unauthorized("missing X-Hyphae-Sig header".into()))?;
                let _ = self.verify_ed25519_http_auth(
                    claimed_node,
                    ts_str,
                    nonce,
                    sig,
                    method,
                    path_and_query,
                    body_sha256,
                )?;
            }
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
        let admin_pk = proto_jwk_to_crypto(admin_proto_jwk).to_ed25519()?;

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
            db.peers().upsert_peer(
                &PeerInput {
                    peer_id: binding.node_id.clone(),
                    endpoint: None,
                    profile: hyp_store::PeerProfile::Local,
                    trust_tier,
                    status: PeerStatus::Active,
                    scopes: expanded_scopes.clone(),
                    auth_credential_ref: None,
                },
                now,
            )?;
            db.peers().rotate_peer_key(
                &PeerKeyInput {
                    peer_id: binding.node_id.clone(),
                    kid: sign_kid.clone(),
                    key_use: KeyUse::Signing,
                    jwk_json: serde_json::to_string(&binding.signing_jwk)?,
                    status: KeyStatus::Active,
                    expires_at: None,
                },
                now,
            )?;
            db.peers().rotate_peer_key(
                &PeerKeyInput {
                    peer_id: binding.node_id.clone(),
                    kid: enc_kid.clone(),
                    key_use: KeyUse::Encryption,
                    jwk_json: serde_json::to_string(&binding.encryption_jwk)?,
                    status: KeyStatus::Active,
                    expires_at: None,
                },
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
        let admin_pk = proto_jwk_to_crypto(admin_proto_jwk).to_ed25519()?;
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

            db.peers().rotate_peer_key(
                &PeerKeyInput {
                    peer_id: req.node_id.clone(),
                    kid: sign_kid.clone(),
                    key_use: KeyUse::Signing,
                    jwk_json: sign_jwk_json,
                    status: KeyStatus::Active,
                    expires_at: None,
                },
                now,
            )?;
            db.peers().rotate_peer_key(
                &PeerKeyInput {
                    peer_id: req.node_id.clone(),
                    kid: enc_kid.clone(),
                    key_use: KeyUse::Encryption,
                    jwk_json: enc_jwk_json,
                    status: KeyStatus::Active,
                    expires_at: None,
                },
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
        let hub_pk = proto_jwk_to_crypto(&payload.identity.signing_jwk).to_ed25519()?;
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
            db.peers().upsert_peer_key(
                &PeerKeyInput {
                    peer_id: verified.bob_node_id.clone(),
                    kid: bob_sign_kid.clone(),
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
                    kid: bob_enc_kid,
                    key_use: KeyUse::Encryption,
                    jwk_json: serde_json::to_string(&verified.bob_encryption_pk.to_jwk())?,
                    status: KeyStatus::Active,
                    expires_at: None,
                },
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
            ManifestFetchOutcome::LegacyV1 {
                keys_endpoint_present,
            } => {
                let negotiated = self.negotiate_legacy_v1_peer(peer_id, keys_endpoint_present)?;
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
            .map(|j| proto_jwk_to_crypto(j).to_ed25519())
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

            db.peers().rotate_peer_key(
                &PeerKeyInput {
                    peer_id: caller_node.to_string(),
                    kid: new_sign_kid.clone(),
                    key_use: KeyUse::Signing,
                    jwk_json: serde_json::to_string(&req.signing_jwk)?,
                    status: KeyStatus::Active,
                    expires_at: None,
                },
                now,
            )?;
            db.peers().rotate_peer_key(
                &PeerKeyInput {
                    peer_id: caller_node.to_string(),
                    kid: new_enc_kid.clone(),
                    key_use: KeyUse::Encryption,
                    jwk_json: serde_json::to_string(&req.encryption_jwk)?,
                    status: KeyStatus::Active,
                    expires_at: None,
                },
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

    /// Materializes locally subscribed KV change batches after their write transaction commits.
    pub fn notify_local_kv_change(&self) {
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
            let diags = adapter
                .validate_subscription(&topic_str, &req.filters)
                .await;
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
            for existing in db
                .events()
                .list_upstream_pushdowns(Some(&origin_node_str))?
            {
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
        let mut observed_by_topic: BTreeMap<String, ObservedTopicStats> = {
            let db = self.db();
            db.events()
                .topic_event_stats(&[self.config.node_id.as_str(), LOCAL_NODE_ID])
                .unwrap_or_default()
                .into_iter()
                .map(|(topic, st)| {
                    (
                        topic,
                        ObservedTopicStats {
                            event_count: st.event_count,
                            last_event_at: st.last_received_at.map(format_rfc3339_millis),
                            sources: st.sources,
                            repos: st.repos,
                        },
                    )
                })
                .collect()
        };

        let mut catalog: Vec<TopicCatalogEntry> = self
            .config
            .topics
            .iter()
            .map(|t| {
                let bare = t.topic.strip_prefix("local.").unwrap_or(t.topic.as_str());
                let observed = observed_by_topic.remove(bare).unwrap_or_default();
                TopicCatalogEntry {
                    topic: t.topic.clone(),
                    has_provisioned_publisher: t.has_provisioned_publisher,
                    metadata: t.metadata.clone(),
                    observed,
                }
            })
            .collect();

        if let Some(gh) = self.github_public_adapter() {
            let gh_topic = gh.topic();
            if !catalog.iter().any(|c| c.topic == gh_topic) {
                let bare = gh_topic.strip_prefix("local.").unwrap_or(gh_topic);
                let observed = observed_by_topic.remove(bare).unwrap_or_default();
                catalog.push(TopicCatalogEntry {
                    topic: gh_topic.to_string(),
                    has_provisioned_publisher: true,
                    metadata: None,
                    observed,
                });
            }
        }
        if !catalog.iter().any(|c| c.topic == "kv") {
            let observed = observed_by_topic.remove("kv").unwrap_or_default();
            catalog.push(TopicCatalogEntry {
                topic: "kv".to_string(),
                has_provisioned_publisher: true,
                metadata: None,
                observed,
            });
        }
        if self.config.local_ingest.enabled {
            for ingest_topic in self.config.local_ingest.advertised_topics() {
                if !catalog.iter().any(|c| c.topic == ingest_topic) {
                    let bare = ingest_topic
                        .strip_prefix("local.")
                        .unwrap_or(ingest_topic.as_str());
                    let observed = observed_by_topic.remove(bare).unwrap_or_default();
                    catalog.push(TopicCatalogEntry {
                        topic: ingest_topic,
                        has_provisioned_publisher: true,
                        metadata: None,
                        observed,
                    });
                }
            }
        }

        // Include any local topics that already have stored events in SQLite even if not
        // statically declared in `config.topics` so diagnostics report accurate counts.
        for (topic, observed) in observed_by_topic {
            if observed.event_count > 0 && !catalog.iter().any(|c| c.topic == topic) {
                catalog.push(TopicCatalogEntry {
                    topic,
                    has_provisioned_publisher: true,
                    metadata: None,
                    observed,
                });
            }
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
        let mut catalog = self.local_topic_catalog();
        // Issue #25 (B6): Never expose local-only topic names in remote subscription diagnostics.
        if caller.peer_id != self.config.node_id.as_str() {
            catalog.retain(|entry| !self.is_local_only_topic(&entry.topic));
        }
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
            match caller
                .scopes
                .check_stream_subscribe(&sub.topic, &sub.filters)
            {
                Ok(approval) => {
                    // Issue #25 (B6): Local-only topics (`exposeTopic: false`, the default for
                    // subprocess `plugins[]` bridges & sources) MUST fail closed with 403 Forbidden
                    // for remote peers — EVEN IF the peer holds wildcard `stream:subscribe=*`
                    // (`member`, `observer`, `full` presets). Checked after scope verification so
                    // unprivileged peers cannot probe local-only topic names.
                    if caller.peer_id != self.config.node_id.as_str()
                        && self.is_local_only_topic(&sub.topic)
                    {
                        return Err(NodeError::TopicLocalOnly {
                            topic: sub.topic.clone(),
                        });
                    }
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
        self.ingest_inbound_event_inner(caller_node, None, topic, event)
    }

    /// Authenticated variant of [`Self::ingest_inbound_event`] used by `POST /v1/events`:
    /// enforces BOTH local `forwarding` allowlist policy AND caller's explicit `forward:via`
    /// scope when ingesting foreign-origin transit events (`P1-7`).
    pub fn ingest_inbound_event_for_caller(
        &self,
        caller: &AuthenticatedPeer,
        topic: &str,
        event: &ProtoCloudEvent,
    ) -> Result<IngestResult, NodeError> {
        self.ingest_inbound_event_inner(&caller.peer_id, Some(caller), topic, event)
    }

    /// Returns `true` iff `topic` is owned by an attached provisioned source/webhook adapter
    /// (preventing remote peers from spoofing adapter-owned webhook streams via `POST /v1/events`).
    fn is_adapter_owned_topic(&self, topic: &str) -> bool {
        if let Some(gh) = self.github_public_adapter() {
            if gh.topic() == topic {
                return true;
            }
        }
        if self
            .github_webhooks
            .lock()
            .expect("github_webhooks lock poisoned")
            .values()
            .any(|a| a.topic() == topic)
        {
            return true;
        }
        self.config.topics.iter().any(|t| {
            t.topic == topic
                && t.has_provisioned_publisher
                && matches!(
                    t.kind.as_deref(),
                    Some(
                        "github-public"
                            | "github-webhook"
                            | "prometheus-webhook"
                            | "webhook-stream"
                            | "source"
                    )
                )
        })
    }

    fn ingest_inbound_event_inner(
        &self,
        caller_node: &str,
        caller: Option<&AuthenticatedPeer>,
        topic: &str,
        event: &ProtoCloudEvent,
    ) -> Result<IngestResult, NodeError> {
        // Local-only topic protection (Issue #25 / B6): reject remote peers attempting
        // `POST /v1/events` onto a local-only topic with `403 topic_local_only`.
        if caller_node != self.config.node_id.as_str() && self.is_local_only_topic(topic) {
            return Err(NodeError::TopicLocalOnly {
                topic: topic.to_string(),
            });
        }
        // Adapter-owned topic protection: reject remote peers attempting `POST /v1/events` onto
        // an adapter-owned webhook/source topic with `403 not_granted`.
        if caller_node != self.config.node_id.as_str() && self.is_adapter_owned_topic(topic) {
            let missing = format!("stream:publish={topic}");
            if let Some(peer) = caller {
                return Err(NodeError::ScopeDenied {
                    missing_scope: missing.clone(),
                    current_scopes: peer.scopes.raw_scopes().to_vec(),
                    escalation_note: self
                        .config
                        .escalation
                        .resolve(&missing)
                        .map(|n| n.as_str().to_string()),
                });
            }
            return Err(NodeError::ScopeDenied {
                missing_scope: missing,
                current_scopes: Vec::new(),
                escalation_note: None,
            });
        }

        let val = serde_json::to_value(event)?;
        let (mut validated, _) = hyp_proto::cloudevent::check_cloudevent_v2(&val)?;

        // Enforce strict cycle detection & hop limit cap (§2.3).
        let max_hops = self.config.forwarding.effective_max_hops();
        let prov = validated
            .check_forwarding(&self.config.node_id, None, max_hops)
            .map_err(map_provenance_err)?;

        // Determine effective origin & detect foreign transit cleanly even when `hyphaeorigin`
        // is omitted (never bypassing foreign-origin checks when `hyphaevia` or `hyphaehops`
        // indicates transit!).
        let foreign_origin: Option<String> = if caller_node != self.config.node_id.as_str() {
            if let Some(orig) = prov.origin.as_ref() {
                if orig.as_str() != caller_node && orig != &self.config.node_id {
                    Some(orig.as_str().to_string())
                } else {
                    prov.via
                        .iter()
                        .find(|v| v.as_str() != caller_node && *v != &self.config.node_id)
                        .map(|v| v.as_str().to_string())
                }
            } else if !prov.via.is_empty() {
                let first_via = &prov.via[0];
                validated.set_extension(hyp_proto::cloudevent::EXT_ORIGIN, first_via.as_str());
                prov.via
                    .iter()
                    .find(|v| v.as_str() != caller_node && *v != &self.config.node_id)
                    .map(|v| v.as_str().to_string())
            } else if prov.hops > 0 {
                return Err(NodeError::BadRequest(
                    "hyphaehops > 0 requires hyphaeorigin or hyphaevia".into(),
                ));
            } else {
                // Direct event from remote peer with omitted `hyphaeorigin`: default origin to `caller_node`.
                validated.set_extension(hyp_proto::cloudevent::EXT_ORIGIN, caller_node);
                None
            }
        } else {
            prov.origin
                .as_ref()
                .filter(|orig| orig.as_str() != caller_node && *orig != &self.config.node_id)
                .map(|orig| orig.as_str().to_string())
        };

        // Enforce default-deny transit forwarding + explicit `forward:via` for foreign-origin events (§2.3).
        if let Some(orig) = foreign_origin {
            let policy_ok = self.config.forwarding.permits(caller_node, "*", topic);
            let scope_ok = match caller {
                Some(peer) => peer.scopes.may_forward_via(&orig),
                None => true,
            };
            if !policy_ok || !scope_ok {
                if let Some(peer) = caller {
                    let missing = format!("forward:via={orig}");
                    return Err(NodeError::ScopeDenied {
                        missing_scope: missing.clone(),
                        current_scopes: peer.scopes.raw_scopes().to_vec(),
                        escalation_note: self
                            .config
                            .escalation
                            .resolve(&missing)
                            .map(|n| n.as_str().to_string()),
                    });
                }
                return Err(NodeError::Unauthorized(format!(
                    "transit forwarding denied by default policy for origin '{orig}' from '{caller_node}' on topic '{topic}'"
                )));
            }
        }

        // Record this node's hop in `hyphaeorigin`/`hyphaevia`/`hyphaehops` if cross-node.
        if caller_node != self.config.node_id.as_str() {
            validated
                .record_hop(&self.config.node_id, None, max_hops)
                .map_err(map_provenance_err)?;
        }

        // H4: Auto-process signed `to.hyphae.human.revocation.v1` events fail-closed when this
        // node has enrolled human authorities (blind relay hubs without authorities still validate
        // structure before fanning out to downstream nodes).
        if validated.event_type == TYPE_HUMAN_REVOCATION_V1 {
            let data_val = validated.data.as_ref().ok_or_else(|| {
                NodeError::BadRequest(
                    "to.hyphae.human.revocation.v1 event missing data payload".into(),
                )
            })?;
            let signed_rev = extract_signed_human_revocation(data_val)?;
            let has_authorities = {
                let db = self.db();
                !db.human().list_authorities(true)?.is_empty()
            };
            if has_authorities {
                self.apply_human_revocation(
                    &signed_rev,
                    caller_node == self.config.node_id.as_str(),
                )?;
            }
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

    /// Sweeps ALL locally subscribed topics (`origin_node == self.node_id` and subscriber is not a
    /// remote peer), closes any due coalescing batches, materializes all ready `pending` batches
    /// into local session mailboxes (strictly at-most-once), wakes matched local sessions, and
    /// notifies the deadline scheduler.
    ///
    /// Returns the total number of batches materialized into local mailboxes.
    pub fn flush_pending_local_topic_batches(&self) -> usize {
        self.flush_pending_local_topic_batches_inner(true)
    }

    fn flush_pending_local_topic_batches_inner(&self, wake_scheduler: bool) -> usize {
        let now = now_ms();
        let my_id = self.config.node_id.to_string();
        let local_topics: Vec<String> = {
            let db = self.db();
            let _ = db.events().tick(now);
            let remote_peers: HashSet<String> = db
                .peers()
                .list_peers(None)
                .unwrap_or_default()
                .into_iter()
                .map(|p| p.peer_id)
                .filter(|pid| pid != &my_id)
                .collect();
            db.events()
                .list_subscriptions(None)
                .unwrap_or_default()
                .into_iter()
                .filter(|s| s.origin_node == my_id && !remote_peers.contains(&s.subscriber))
                .map(|s| s.topic)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect()
        };

        let mut total_batches = 0usize;
        let default_opts = MailboxPutOptions::default();
        for topic in local_topics {
            if let Ok((_, batches)) = self.deliver_local_topic_batches_inner(
                &topic,
                &default_opts,
                None,
                None,
                now,
                false,
            ) {
                total_batches += batches;
            }
        }

        if wake_scheduler {
            self.notify_scheduler();
        }
        total_batches
    }

    /// Like [`Self::deliver_local_topic_batches`], recording an explicit Stage 1 `gate_reason`
    /// (e.g. `"capped_to_queue"` or `"downgraded_to_notify"`).
    pub fn deliver_local_topic_batches(
        &self,
        topic: &str,
        put_opts: &MailboxPutOptions,
        human_auth: Option<&VerifiedHumanClaim>,
        gate_reason: Option<&str>,
        now_ms: i64,
    ) -> Result<usize, NodeError> {
        let bare_topic = topic
            .strip_prefix(&format!("{LOCAL_NODE_ID}."))
            .unwrap_or(topic);
        let (sessions_woken, _batches) = self.deliver_local_topic_batches_inner(
            bare_topic,
            put_opts,
            human_auth,
            gate_reason,
            now_ms,
            true,
        )?;
        Ok(sessions_woken)
    }

    fn deliver_local_topic_batches_inner(
        &self,
        topic: &str,
        put_opts: &MailboxPutOptions,
        human_auth: Option<&VerifiedHumanClaim>,
        gate_reason: Option<&str>,
        now_ms: i64,
        wake_scheduler: bool,
    ) -> Result<(usize, usize), NodeError> {
        let my_id = self.config.node_id.to_string();
        let auth_json = match human_auth {
            Some(claim) => Some(serde_json::to_string(claim)?),
            None => None,
        };
        let mut sessions_to_wake = BTreeSet::new();
        let mut batches_materialized = 0usize;

        {
            let db = self.db();
            let _ = db.events().tick(now_ms);

            let remote_peers: HashSet<String> = db
                .peers()
                .list_peers(None)?
                .into_iter()
                .map(|p| p.peer_id)
                .filter(|pid| pid != &my_id)
                .collect();

            let local_subscribers: BTreeSet<String> = db
                .events()
                .list_subscriptions(None)?
                .into_iter()
                .filter(|s| {
                    s.origin_node == my_id
                        && s.topic == topic
                        && !remote_peers.contains(&s.subscriber)
                })
                .map(|s| s.subscriber)
                .collect();

            for subscriber in local_subscribers {
                // `claim_due_batches` yields at most one pending batch per subscription per call,
                // so drain boundedly while making progress to flush batches queued across downtime.
                for _round in 0..64 {
                    let due = db.events().claim_due_batches(&subscriber, now_ms)?;
                    let mut progressed = false;
                    for local_batch in due {
                        if local_batch.origin_node != my_id || local_batch.topic != topic {
                            continue;
                        }
                        let kind = if local_batch.topic == "kv" {
                            MailboxKind::Kv
                        } else {
                            MailboxKind::Event
                        };
                        let traceparent = local_batch
                            .events
                            .first()
                            .and_then(|ev| {
                                ev.extensions.get(hyp_proto::cloudevent::EXT_TRACEPARENT)
                            })
                            .cloned();
                        let payload_text = serde_json::to_string(&json!({
                            "batchId": local_batch.id,
                            "originNode": local_batch.origin_node,
                            "topic": local_batch.topic,
                            "events": local_batch.events,
                        }))?;
                        let put = db.local().put_in_mailbox_ex(
                            &MailboxInsert {
                                session_id: subscriber.clone(),
                                origin_node: my_id.clone(),
                                item_id: format!("batch:{}", local_batch.id),
                                text: payload_text,
                                kind,
                                source: format!("local.{}", local_batch.topic),
                                gate_state: GateState::Pending,
                                gate_reason: gate_reason.map(str::to_string),
                                traceparent,
                            },
                            put_opts,
                            now_ms,
                        )?;
                        match put {
                            MailboxPutResult::Stored { receipt } => {
                                if let Some(ref json_str) = auth_json {
                                    let _ =
                                        db.human().set_mailbox_human_auth(&receipt, json_str)?;
                                }
                                db.events().ack_batch(
                                    &subscriber,
                                    &local_batch.id,
                                    &AckOutcome::Delivered,
                                    now_ms,
                                )?;
                                sessions_to_wake.insert(subscriber.clone());
                                batches_materialized += 1;
                                progressed = true;
                            }
                            MailboxPutResult::Duplicate => {
                                db.events().ack_batch(
                                    &subscriber,
                                    &local_batch.id,
                                    &AckOutcome::Delivered,
                                    now_ms,
                                )?;
                                progressed = true;
                            }
                            MailboxPutResult::QueueFull => {
                                let _ = db.events().ack_batch(
                                    &subscriber,
                                    &local_batch.id,
                                    &AckOutcome::Hold {
                                        reason: "local_inbox_full".to_string(),
                                        retry_after_ms: Some(5_000),
                                    },
                                    now_ms,
                                );
                            }
                        }
                    }
                    if !progressed {
                        break;
                    }
                }
            }
        }

        let delivered = sessions_to_wake.len();
        for sid in sessions_to_wake {
            self.notify_local_session(&sid);
        }
        if wake_scheduler {
            self.notify_scheduler();
        }
        Ok((delivered, batches_materialized))
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
        // P1-6: Verify active peer status & stream/KV scope fail-closed on pulled SSE batches.
        if origin_node != self.config.node_id.as_str() {
            let auth_peer = match self.authorize_peer_action(
                origin_node,
                PeerAction::StreamDeliver {
                    topic: &batch.topic,
                },
            ) {
                Ok(peer) => peer,
                Err(err) => {
                    self.record_peer_scope_denied_audit(
                        origin_node,
                        &format!("stream.{}", batch.topic),
                        &err.to_string(),
                        batch.id.as_bytes(),
                    );
                    return Err(err);
                }
            };
            if batch.topic == "kv"
                && !peer_may_see_topic(&auth_peer.scopes, "kv")
                && !auth_peer.scopes.may_stream_publish("kv")
            {
                for ev in &batch.events {
                    let ns = ev.extensions.get("ns").map(String::as_str).unwrap_or("");
                    let key = ev.extensions.get("key").map(String::as_str).unwrap_or("");
                    if let Err(err) = self.require_scope(
                        &auth_peer,
                        auth_peer.scopes.may_kv_read(ns, key),
                        &format!("kv:read={ns}/{key}"),
                    ) {
                        self.record_peer_scope_denied_audit(
                            origin_node,
                            "stream.kv",
                            &err.to_string(),
                            batch.id.as_bytes(),
                        );
                        return Err(err);
                    }
                }
            }
        }

        let max_hops = self.config.forwarding.effective_max_hops();
        let origin_link = self.peer_link(origin_node).await;

        // 1. Validate loop/hop provenance, apply H4 human revocations, and decrypt `kv.e2ee.v1`.
        let mut prepared_events = Vec::with_capacity(batch.events.len());
        for mut ev in batch.events {
            let proto_ev = store_ce_to_proto(&ev);
            proto_ev
                .check_forwarding(&self.config.node_id, None, max_hops)
                .map_err(map_provenance_err)?;

            // H4 / N4: Auto-apply signed `to.hyphae.human.revocation.v1` events fail-closed
            // per-event: log + audit any malformed/unauthorized revocation event and continue
            // processing the remaining events in the batch rather than poisoning the whole batch!
            if ev.event_type == TYPE_HUMAN_REVOCATION_V1 {
                let apply_res = extract_signed_human_revocation(&ev.data)
                    .and_then(|signed_rev| self.ingest_human_revocation(&signed_rev));
                if let Err(err) = apply_res {
                    eprintln!(
                        "hyphae: ignoring invalid to.hyphae.human.revocation.v1 event '{}' from '{}': {err}",
                        ev.id, origin_node
                    );
                    let now = now_ms();
                    let db = self.db();
                    let _ = db.local().append_gate_audit(
                        &GateAuditInput {
                            direction: GateDirection::Inbound,
                            stage: "human_revocation".to_string(),
                            decision: StoreGateDecision::Block,
                            origin_node: Some(origin_node.to_string()),
                            source: Some(ev.source.clone()),
                            session_id: None,
                            receipt_id: None,
                            event_type: Some(TYPE_HUMAN_REVOCATION_V1.to_string()),
                            trust_tier: Some("peer".to_string()),
                            confidence: None,
                            categories: vec!["human.revocation_rejected".to_string()],
                            reason: Some(err.to_string()),
                            traceparent: None,
                            payload_sha256: sha256_hex(ev.id.as_bytes()),
                            reviewer: None,
                        },
                        now,
                    );
                    continue;
                }
            }

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

    // ========================================================================
    // Verified Human Drops (`human.drop.v1` / `hdrop1_`), Zero-Knowledge Secret
    // Sink, Human Key Revocation & Signed Node Certificates (`hcert1_`)
    // ========================================================================

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
                self.record_human_drop_rejected_audit(
                    None,
                    None,
                    None,
                    Some("human.invalid_token"),
                    &reason,
                    b"redacted-hdrop1",
                    now_ms(),
                );
                return Err(NodeError::Unauthorized(reason));
            }
        };
        self.ingest_human_drop(&envelope, gate, overwrite_secret)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    fn record_human_drop_rejected_audit(
        &self,
        source: Option<String>,
        session_id: Option<String>,
        event_type: Option<&str>,
        extra_category: Option<&str>,
        reason: &str,
        payload_digest_input: &[u8],
        now: i64,
    ) {
        let mut categories = vec!["gate.human_drop_rejected".to_string()];
        if let Some(cat) = extra_category {
            categories.push(cat.to_string());
        }
        let db = self.db();
        let _ = db.local().append_gate_audit(
            &GateAuditInput {
                direction: GateDirection::Inbound,
                stage: "human_authority".to_string(),
                decision: StoreGateDecision::Block,
                origin_node: Some(self.node_id().to_string()),
                source,
                session_id,
                receipt_id: None,
                event_type: Some(event_type.unwrap_or(TYPE_HUMAN_DROP_V1).to_string()),
                trust_tier: Some("unverified".to_string()),
                confidence: None,
                categories,
                reason: Some(reason.to_string()),
                traceparent: None,
                payload_sha256: sha256_hex(payload_digest_input),
                reviewer: None,
            },
            now,
        );
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
    /// - **`HumanDropKind::Secret`**: writes directly to [`SecretStore`] after reserved-name and
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
        if let Some(g) = gate {
            if g.is_policy_tampered() {
                self.record_human_drop_rejected_audit(
                    None,
                    None,
                    None,
                    Some("gate.policy_tampered"),
                    "gate_policy_tampered",
                    envelope.ct.as_bytes(),
                    now,
                );
                return Err(NodeError::Unauthorized("gate_policy_tampered".into()));
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
                self.record_human_drop_rejected_audit(
                    None,
                    None,
                    None,
                    Some(extra_cat),
                    &reason,
                    envelope.ct.as_bytes(),
                    now,
                );
                return Err(NodeError::Unauthorized(reason));
            }
        };

        let auth_rec = match matched_authority {
            Some(rec) => rec,
            None => {
                let reason = "verified human authority record unavailable";
                self.record_human_drop_rejected_audit(
                    None,
                    None,
                    None,
                    Some("human.revoked_or_unknown"),
                    reason,
                    envelope.ct.as_bytes(),
                    now,
                );
                return Err(NodeError::Unauthorized(reason.into()));
            }
        };

        let kid8: String = auth_rec.kid.chars().take(8).collect();
        let source = format!("human:{}:{}", auth_rec.human_id, kid8);

        // H5: Enforce exact epoch binding (`claim.auth_epoch == rec.auth_epoch`), preventing an
        // old-epoch key from claiming a forged higher epoch.
        if claim.auth_epoch != auth_rec.auth_epoch {
            let reason = format!(
                "human claim authEpoch {} does not match enrolled authority key epoch {}",
                claim.auth_epoch, auth_rec.auth_epoch
            );
            self.record_human_drop_rejected_audit(
                Some(source),
                None,
                None,
                Some("human.epoch_mismatch"),
                &reason,
                envelope.ct.as_bytes(),
                now,
            );
            return Err(NodeError::Unauthorized(reason));
        }

        let issued_at_ms = match parse_rfc3339_millis(&claim.issued_at) {
            Ok(ms) => ms,
            Err(e) => {
                let reason = format!("invalid claim issuedAt: {e}");
                self.record_human_drop_rejected_audit(
                    Some(source),
                    None,
                    None,
                    Some("human.invalid_timestamp"),
                    &reason,
                    envelope.ct.as_bytes(),
                    now,
                );
                return Err(NodeError::BadRequest(reason));
            }
        };
        let expires_at_ms = match parse_rfc3339_millis(&claim.expires_at) {
            Ok(ms) => ms,
            Err(e) => {
                let reason = format!("invalid claim expiresAt: {e}");
                self.record_human_drop_rejected_audit(
                    Some(source),
                    None,
                    None,
                    Some("human.invalid_timestamp"),
                    &reason,
                    envelope.ct.as_bytes(),
                    now,
                );
                return Err(NodeError::BadRequest(reason));
            }
        };

        let target_handle = claim.audience.handle.clone();
        let target_session = self.resolve_human_drop_target_session(target_handle.as_deref())?;

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
                let spec = match claim.secret_spec.as_ref() {
                    Some(s) => s,
                    None => {
                        let reason = "secret drop claim missing secretSpec";
                        self.record_human_drop_rejected_audit(
                            Some(source),
                            Some(target_session),
                            Some(TYPE_HUMAN_DROP_V1),
                            Some("human.invalid_secret_spec"),
                            reason,
                            b"redacted-secret",
                            now,
                        );
                        return Err(NodeError::BadRequest(reason.into()));
                    }
                };
                let secret_name = spec.name.trim();
                if secret_name.is_empty() {
                    let reason = "secret drop name must not be empty";
                    self.record_human_drop_rejected_audit(
                        Some(source),
                        Some(target_session),
                        Some(TYPE_HUMAN_DROP_V1),
                        Some("human.invalid_secret_name"),
                        reason,
                        b"redacted-secret",
                        now,
                    );
                    return Err(NodeError::BadRequest(reason.into()));
                }
                if is_reserved_human_drop_secret_name(secret_name) {
                    let reason = format!(
                        "reserved system secret name '{secret_name}' cannot be written via human drop"
                    );
                    self.record_human_drop_rejected_audit(
                        Some(source),
                        Some(target_session),
                        Some(TYPE_HUMAN_DROP_V1),
                        Some("human.reserved_secret"),
                        &reason,
                        b"redacted-secret",
                        now,
                    );
                    return Err(NodeError::Unauthorized(reason));
                }
                if let Err(e) = validate_secret_name(secret_name) {
                    let reason = format!("invalid secret name: {e}");
                    self.record_human_drop_rejected_audit(
                        Some(source),
                        Some(target_session),
                        Some(TYPE_HUMAN_DROP_V1),
                        Some("human.invalid_secret_name"),
                        &reason,
                        b"redacted-secret",
                        now,
                    );
                    return Err(NodeError::BadRequest(reason));
                }

                // H15: Human-signed `spec.overwrite` governs fail-closed; a local
                // `overwrite_secret` flag MUST NEVER override a human's signed `overwrite: false`.
                let _ = overwrite_secret;
                let allow_overwrite = spec.overwrite;
                if !allow_overwrite && self.secrets.get(secret_name).is_ok() {
                    let reason = format!(
                        "secret '{secret_name}' already exists and signed claim specifies overwrite=false"
                    );
                    self.record_human_drop_rejected_audit(
                        Some(source),
                        Some(target_session),
                        Some(TYPE_HUMAN_DROP_V1),
                        Some("human.secret_exists"),
                        &reason,
                        b"redacted-secret",
                        now,
                    );
                    return Err(NodeError::Conflict(reason));
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
                    self.record_human_drop_rejected_audit(
                        Some(source),
                        Some(target_session),
                        Some(TYPE_HUMAN_DROP_V1),
                        Some("human.claim_replay"),
                        reason,
                        b"redacted-secret",
                        now,
                    );
                    return Err(NodeError::Unauthorized(reason.into()));
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
                    self.record_human_drop_rejected_audit(
                        Some(source),
                        Some(target_session),
                        Some(TYPE_HUMAN_DROP_V1),
                        Some("human.claim_replay"),
                        reason,
                        envelope.ct.as_bytes(),
                        now,
                    );
                    return Err(NodeError::Unauthorized(reason.into()));
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
                self.record_human_drop_rejected_audit(
                    Some(format!("human:{}:{}", auth_rec.human_id, auth_rec.kid)),
                    None,
                    Some(TYPE_HUMAN_DROP_V1),
                    Some("human.approval_wrong_entrypoint"),
                    "approval drops must be verified by the target ceremony command (not `hyp drop ingest`)",
                    claim.claim_id.as_bytes(),
                    now,
                );
                Err(NodeError::BadRequest(
                    "approval drops cannot be ingested via `hyp drop ingest`; submit to the currently waiting live ceremony (e.g. `hyp gate apply`)"
                        .to_string(),
                ))
            }
        }
    }

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

fn is_reserved_human_drop_secret_name(name: &str) -> bool {
    if is_reserved_secret_name(name) {
        return true;
    }
    let lower = name.trim().to_ascii_lowercase();
    lower.starts_with("node-ed25519-")
        || lower.starts_with("node-x25519-")
        || lower.starts_with("peer-auth-")
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
fn sweep_stale_transfer_staging(state_dir: &std::path::Path) {
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
    fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
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
