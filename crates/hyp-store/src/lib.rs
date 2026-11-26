//! Hyphae v2 unified SQLite WAL storage engine and exact deadline scheduler.
//!
//! Collapses v1's split `router.sqlite` + `state.sqlite` databases into a single WAL-mode
//! `node.sqlite` driving DMs, E2EE `#channels`, CloudEvents pub/sub & pushdown coalescing,
//! encrypted file transfers, Shared KV with atomic CloudEvent emission, local sessions/mailbox
//! with Security Gate quarantine + immutable audit log, federation/manifest trust with
//! anti-rollback & anti-downgrade, and exact `next_deadline_ms()` scheduling.

pub use hyp_proto::PROTOCOL_VERSION;
pub use hyp_proto::cron::{CronError, CronExpr, CronTimezone, apply_cron_jitter};

pub mod db;
pub mod error;
pub mod events;
pub mod human;
pub mod kv;
pub mod local;
pub mod messages;
pub mod peers;
pub mod scheduler;
pub mod transfers;
pub mod types;
pub mod wakeups;

pub use db::{
    CURRENT_SCHEMA_VERSION, MAX_MIGRATION_BACKUPS, MIGRATIONS, Migration, MigrationKind, NodeDb,
    StoreConfig, run_migrations_with,
};
pub use error::{StoreError, StoreResult};
pub use events::{
    BatchRecord, BatchState, DueBatch, EventCacheStats, EventLimits, EventStore, EventTickReport,
    IngestResult, Publisher, SUBSCRIPTION_META_PREFIX, StoredTopicStats, Subscription,
    SubscriptionMeta, SubscriptionSpec, UpstreamPushdown, UpstreamPushdownInput,
};
pub use human::{
    GateLockSealRecord, HUMAN_MIN_AUTH_EPOCH_META_KEY, HumanAuthorityInput, HumanAuthorityRecord,
    HumanAuthorityRole, HumanAuthorityStatus, HumanAuthorityStore, HumanClaimKind,
    HumanDelegationPolicy, HumanDelegationPolicyInput, HumanNodeCertInput, HumanNodeCertRecord,
};
pub use kv::{
    KvDeleteInput, KvDeleteResult, KvEntry, KvEpoch, KvEpochInput, KvSetInput, KvSetResult,
    KvStore, MAX_KV_VALUE_BYTES,
};
pub use local::{
    BridgeLink, DaemonNoticeKind, GateAuditEntry, GateAuditInput, GateAuditQuery, LocalStateStore,
    MailboxEntry, MailboxEntryEx, MailboxInsert, MailboxItemMeta, MailboxPutOptions,
    MailboxPutResult, MuteRule, MuteRuleInput, PluginTargetHandoff, PruneReport, Session,
    UnreadDigest,
};
pub use messages::{
    ChannelDeliveryFailure, ChannelEpoch, ChannelEpochInput, ChannelInfo, ChannelMembership,
    ChannelStore, EnqueueMessage, EnqueueResult, HandleRecord, MAX_HANDLE_DESCRIPTION_CHARS,
    MessageLimits, MessageRecord, MessageState, MessageStore, MessageTickReport, PostChannelInput,
    PostChannelResult, sanitize_handle_description,
};
pub use peers::{
    DirectoryCheckpoint, DirectoryCheckpointInput, GrantInput, GrantRecord, ManifestCacheUpdate,
    PeerInput, PeerKeyInput, PeerKeyRecord, PeerRecord, PeerRoute, PeerStore, RevocationInput,
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
pub use wakeups::{
    DEFAULT_WAKEUP_TTL_MS, FiredWakeup, WakeupInsert, WakeupLimits, WakeupRecord, WakeupState,
    WakeupStore, WakeupTriggerKind, WakeupUrgency,
};
