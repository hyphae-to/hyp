//! Hyphae v2 unified SQLite WAL storage engine and exact deadline scheduler.
//!
//! Collapses v1's split `router.sqlite` + `state.sqlite` databases into a single WAL-mode
//! `node.sqlite` driving DMs, E2EE `#channels`, CloudEvents pub/sub & pushdown coalescing,
//! encrypted file transfers, Shared KV with atomic CloudEvent emission, local sessions/mailbox
//! with Security Gate quarantine + immutable audit log, federation/manifest trust with
//! anti-rollback & anti-downgrade, and exact `next_deadline_ms()` scheduling.

pub use hyp_proto::PROTOCOL_VERSION;

pub mod db;
pub mod error;
pub mod events;
pub mod kv;
pub mod local;
pub mod messages;
pub mod peers;
pub mod scheduler;
pub mod transfers;
pub mod types;

pub use db::{CURRENT_SCHEMA_VERSION, NodeDb, StoreConfig};
pub use error::{StoreError, StoreResult};
pub use events::{
    BatchRecord, BatchState, DueBatch, EventCacheStats, EventLimits, EventStore, EventTickReport,
    IngestResult, Publisher, Subscription, SubscriptionSpec, UpstreamPushdown,
    UpstreamPushdownInput,
};
pub use kv::{
    KvDeleteInput, KvDeleteResult, KvEntry, KvEpoch, KvEpochInput, KvSetInput, KvSetResult,
    KvStore, MAX_KV_VALUE_BYTES,
};
pub use local::{
    BridgeLink, GateAuditEntry, GateAuditInput, GateAuditQuery, LocalStateStore, MailboxEntry,
    MailboxInsert, MailboxPutResult, MuteRule, MuteRuleInput, PluginTargetHandoff, PruneReport,
    Session, UnreadDigest,
};
pub use messages::{
    ChannelDeliveryFailure, ChannelEpoch, ChannelEpochInput, ChannelInfo, ChannelMembership,
    ChannelStore, EnqueueMessage, EnqueueResult, HandleRecord, MessageLimits, MessageRecord,
    MessageState, MessageStore, MessageTickReport, PostChannelInput, PostChannelResult,
};
pub use peers::{
    DirectoryCheckpoint, DirectoryCheckpointInput, GrantInput, GrantRecord, ManifestCacheUpdate,
    PeerInput, PeerKeyInput, PeerKeyRecord, PeerRecord, PeerStore, RevocationInput,
    RevocationRecord,
};
pub use scheduler::{DeadlineBreakdown, TickReport};
pub use transfers::{
    OrphanSweepReport, TransferLimits, TransferRecord, TransferState, TransferStore,
    TransferSubmit, TransferSubmitResult, TransferTickReport,
};
pub use types::{
    AckOutcome, CloudEvent, DeliveryMode, Filter, GateDecision, GateDirection, GateState,
    GrantDirection, KeyStatus, KeyUse, MailboxKind, PeerProfile, PeerStatus, TrustTier, WriteModel,
    canonical_json, check_filters, epoch_ms_to_rfc3339, format_address, is_channel_name, is_handle,
    is_kv_key, is_kv_namespace, is_node_id, is_safe_transfer_id, is_topic, matches_filter,
    matches_filters, now_ms, parse_address, parse_and_check_filters, sha256_hex, uuid_v4,
};
