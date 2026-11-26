//! Error types for the Hyphae v2 unified SQLite WAL store.

use thiserror::Error;

/// Unified error type returned by all `hyp-store` operations.
///
/// Security and integrity boundaries fail closed with structured error variants so callers
/// (HTTP handlers, MCP shims, CLI commands) can map them cleanly to RFC 9457 Problem Details.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("sqlite error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid argument: {0}")]
    InvalidInput(String),

    #[error("invalid filter at {path}: {message}")]
    InvalidFilter { path: String, message: String },

    #[error("not found: {0}")]
    NotFound(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("id conflict: {0}")]
    IdConflict(String),

    #[error("payload too large: {0}")]
    TooLarge(String),

    #[error("quota exceeded: {0}")]
    QuotaExceeded(String),

    #[error("rate limited: {0}")]
    RateLimited(String),

    #[error("version conflict: current version is {current_version}")]
    VersionConflict { current_version: u64 },

    #[error(
        "manifest rollback for peer '{peer_id}': expected version >= {expected_min}, received {received}"
    )]
    ManifestRollback {
        peer_id: String,
        expected_min: i64,
        received: i64,
    },

    #[error(
        "capability downgrade for peer '{peer_id}': missing previously observed E2EE capabilities {missing_capabilities:?}"
    )]
    CapabilityDowngrade {
        peer_id: String,
        missing_capabilities: Vec<String>,
    },

    #[error("epoch conflict for '{scope}': {message}")]
    EpochConflict { scope: String, message: String },

    #[error("invalid state transition: {0}")]
    InvalidState(String),

    #[error("expired: {0}")]
    Expired(String),

    #[error("already paired: {0}")]
    AlreadyPaired(String),
}

pub type StoreResult<T> = Result<T, StoreError>;
