//! Unified Rust `Node` engine: configuration profiles, `hyper 1` HTTP/SSE server,
//! `PeerLink` client, E2EE DMs (`dm.e2ee.v1`), E2EE `#channels` (`channel.e2ee.v1`,
//! including read-only `ChannelMode::Announcement` rooms), Shared KV (`kv.v1` / `kv.e2ee.v1`),
//! streaming file transfers (`transfer.stream.v2`), subscription pushdown & loop prevention,
//! signed manifests with anti-rollback/anti-downgrade, and `am2_` / `hp2p1_` pairing.

pub mod config;
pub mod drop_relay;
pub mod http_util;
pub mod local_ingest;
pub mod node;
pub mod peer_link;
pub mod server;

pub use config::{
    ChannelMode, ChannelPolicy, DEFAULT_HYPHAE_VERSION, DEFAULT_LOCAL_INGEST_BURST,
    DEFAULT_LOCAL_INGEST_MAX_PAYLOAD_BYTES, DEFAULT_LOCAL_INGEST_MAX_PER_MINUTE,
    DEFAULT_LOCAL_INGEST_ROUTE_ID, DEFAULT_LOCAL_INGEST_TOPIC, E2eePolicy, EscalationConfig,
    ForwardingMode, ForwardingPolicy, ForwardingRule, GuestPairingConfig, KvNamespaceConfig,
    LocalIngestConfig, LocalIngestLimitAction, LocalIngestRoute, NodeConfig, NodeError,
    NodeProfile, PeerConfig, TopicConfig,
};
pub use drop_relay::{
    AckDropResponse, CreateDropRequest, CreateDropResponse, DROP_CAP_HEADER, DropCapRole, DropItem,
    DropRelay, DropRelayConfig, DropRelayError, DropRelayHealth, DropSubscriberAuth,
    DropSubscription, PostDropResponse,
};
pub use local_ingest::{
    LOCAL_INGEST_MAX_CONCURRENT_CONNS, LOCAL_INGEST_READ_TIMEOUT, LocalIngestError,
    LocalIngestOutcome, LocalIngestServer, MAX_LOCAL_INGEST_LINE_BYTES,
    canonical_local_event_for_signing, send_local_ingest_event,
};
pub use node::{
    AuthenticatedPeer, DiscoveredPeerHandle, IngestedHumanDrop, KvWriteRequest, PeerLinkInfo,
    SendDmResult, SubscribeRequest, SubscribeResult, TransferSendResult, UnifiedNode,
};
pub use peer_link::{
    ChannelDirectoryEntry, ChannelJoinResponse, ChannelsResponse, GuestPairProofPayload,
    GuestPairReply, GuestPairRequest, HandlesResponse, ManifestFetchOutcome, P2pPairServerReply,
    PairServerReply, PeerAuth, PeerKeyDirectoryEntry, PeerKeysResponse, PeerLink,
    guest_pair_proof_canonical,
};
