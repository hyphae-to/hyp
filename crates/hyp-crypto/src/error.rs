//! Error types for `hyp-crypto`.

use thiserror::Error;

/// Unified fail-closed cryptographic, archive, pairing, and keystore error type.
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid key: {0}")]
    InvalidKey(String),

    #[error("rejected small-order or non-contributory curve point")]
    SmallOrderKey,

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("HPKE error: {0}")]
    Hpke(String),

    #[error("AEAD sequence number overflow")]
    SequenceOverflow,

    #[error("invalid E2EE envelope: {0}")]
    InvalidEnvelope(String),

    #[error("invalid pairing material: {0}")]
    InvalidPairing(String),

    #[error("replay or rollback detected: {0}")]
    ReplayOrRollback(String),

    #[error("invalid transfer: {0}")]
    InvalidTransfer(String),

    #[error("unsafe archive entry rejected: {0}")]
    UnsafeArchiveEntry(String),

    #[error("archive limit exceeded: {0}")]
    ArchiveLimitExceeded(String),

    #[error("attachment blocked by security guard: {0}")]
    AttachmentBlocked(String),

    #[error("keystore error: {0}")]
    Keystore(String),

    #[error("secret not found: {0}")]
    SecretNotFound(String),

    #[error("invalid secret name: {0}")]
    InvalidSecretName(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
