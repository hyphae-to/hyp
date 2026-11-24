//! Unified Rust `Node` engine: configuration profiles, `hyper 1` HTTP/SSE server,
//! `PeerLink` client, E2EE DMs (`dm.e2ee.v1`), E2EE `#channels` (`channel.e2ee.v1`,
//! including read-only `ChannelMode::Announcement` rooms), Shared KV (`kv.v1` / `kv.e2ee.v1`),
//! streaming file transfers (`transfer.stream.v2`), subscription pushdown & loop prevention,
//! signed manifests with anti-rollback/anti-downgrade, and `am2_` / `hp2p1_` pairing.

pub mod config;
pub mod http_util;
pub mod node;
pub mod peer_link;
pub mod server;

pub use config::{
    ChannelMode, ChannelPolicy, DEFAULT_HYPHAE_VERSION, E2eePolicy, EscalationConfig,
    ForwardingMode, ForwardingPolicy, ForwardingRule, KvNamespaceConfig, NodeConfig, NodeError,
    NodeProfile, PeerConfig, TopicConfig,
};
pub use node::{
    AuthenticatedPeer, KvWriteRequest, PeerLinkInfo, SendDmResult, SubscribeRequest,
    SubscribeResult, TransferSendResult, UnifiedNode,
};
pub use peer_link::{
    ChannelDirectoryEntry, ChannelJoinResponse, ChannelsResponse, HandlesResponse,
    ManifestFetchOutcome, P2pPairServerReply, PairServerReply, PeerAuth, PeerKeyDirectoryEntry,
    PeerKeysResponse, PeerLink,
};
