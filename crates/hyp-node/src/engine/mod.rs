//! Unified Rust `Node` engine: configuration profiles, `hyper 1` HTTP/SSE server,
//! `PeerLink` client, E2EE DMs (`dm.e2ee.v1`), E2EE `#channels` (`channel.e2ee.v1`,
//! including read-only `ChannelMode::Announcement` rooms), Shared KV (`kv.v1` / `kv.e2ee.v1`),
//! streaming file transfers (`transfer.stream.v2`), subscription pushdown & loop prevention,
//! signed manifests with anti-rollback/anti-downgrade, and `am2_` / `hp2p1_` pairing.

pub mod config;
pub mod drop_client;
pub mod drop_relay;
pub mod http_fetch;
pub mod http_util;
pub mod local_ingest;
pub mod node;
pub mod pairing_client;
pub mod peer_link;
#[cfg(unix)]
mod private_socket;
pub mod server;
pub mod wake;

pub use config::{
    ChannelMode, ChannelPolicy, DEFAULT_DROP_PORTAL_URL, DEFAULT_HYPHAE_VERSION,
    DEFAULT_LOCAL_INGEST_BURST, DEFAULT_LOCAL_INGEST_MAX_PAYLOAD_BYTES,
    DEFAULT_LOCAL_INGEST_MAX_PER_MINUTE, DEFAULT_LOCAL_INGEST_ROUTE_ID, DEFAULT_LOCAL_INGEST_TOPIC,
    E2eePolicy, ENV_DROP_PORTAL_URL, EscalationConfig, ForwardingMode, ForwardingPolicy,
    ForwardingRule, GuestPairingConfig, KvNamespaceConfig, LocalIngestConfig,
    LocalIngestLimitAction, LocalIngestRoute, NodeConfig, NodeError, NodeProfile, PeerConfig,
    TopicConfig, normalize_drop_portal_url, resolve_drop_portal_url,
};
pub use drop_relay::{
    AckDropResponse, CreateDropRequest, CreateDropResponse, DROP_CAP_HEADER, DropCapRole, DropItem,
    DropRelay, DropRelayConfig, DropRelayError, DropRelayHealth, DropSubscriberAuth,
    DropSubscription, PostDropResponse,
};
pub use http_util::{ENV_SSH_BIN, SshEndpoint, parse_ssh_endpoint, resolve_ssh_binary};
pub use local_ingest::{
    LOCAL_INGEST_MAX_CONCURRENT_CONNS, LOCAL_INGEST_READ_TIMEOUT, LocalIngestError,
    LocalIngestOutcome, LocalIngestServer, MAX_LOCAL_INGEST_LINE_BYTES,
    canonical_local_event_for_signing, send_local_ingest_event,
};
pub use node::{
    AuthenticatedPeer, DiscoveredPeerHandle, IngestedHumanDrop, KvWriteRequest, PeerLinkInfo,
    PeerReconcileReport, SendDmResult, SubscribeRequest, SubscribeResult, TransferSendResult,
    UnifiedNode, p2p_offer_secret_name,
};
pub use peer_link::{
    AuthClaimReply, AuthClaimRequest, ChannelDirectoryEntry, ChannelJoinResponse, ChannelsResponse,
    DelegatedPairReply, DelegatedPairRequest, GuestPairProofPayload, GuestPairReply,
    GuestPairRequest, HandlesResponse, ManifestFetchOutcome, P2pPairServerReply, PairServerReply,
    PeerAuth, PeerKeyDirectoryEntry, PeerKeysResponse, PeerLink, guest_pair_proof_canonical,
};
pub use server::DEFAULT_PEER_SOCKET_FILENAME;
pub use wake::{
    DEFAULT_WAKE_CHECK_INTERVAL_SECS, DEFAULT_WAKE_MIN_SLEEP_SECONDS, SleepWakeDetector,
    SystemWakeEvent, WakeRecoveryConfig, detect_sleep_gap, format_human_duration,
    spawn_wake_watcher,
};
