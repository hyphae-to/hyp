//! Unified `NodeAdapter` trait & host contract (`docs/architecture-v2.md` §1.2).
//!
//! Uses explicit `BoxFuture<'a, T>` instead of `async-trait` so every adapter
//! (`Harness`, `Source`, `Bridge`, `PeerLink`) is cleanly object-safe (`Arc<dyn NodeAdapter>`)
//! with zero proc-macro overhead.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use hyp_proto::cloudevent::CloudEvent;
use hyp_proto::filter::{Filter, SubscriptionDiagnostic};
use hyp_proto::rpc::EventKeyRef;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Boxed `Send` future alias used across the object-safe `NodeAdapter` and `NodeAdapterHost` traits.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Classification of an adapter attached to a unified Hyphae `Node`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterKind {
    Harness,
    Source,
    Bridge,
    PeerLink,
}

/// Lifecycle and operational health state of a `NodeAdapter`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdapterHealth {
    Starting,
    Healthy,
    Degraded(String),
    Stopped,
}

/// Result status of publishing a CloudEvent into the host bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PublishStatus {
    Stored,
    Duplicate,
}

/// Outcome returned by [`NodeAdapterHost::publish_event`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishOutcome {
    pub status: PublishStatus,
    pub matched: usize,
}

/// Structured error codes returned when the host rejects a published event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublishErrorCode {
    InvalidEvent,
    TooLarge,
    UnknownTarget,
    IdConflict,
    Unavailable,
}

/// Unified error type for `NodeAdapter` lifecycle, ingestion, and IPC operations.
#[derive(Debug, Error)]
pub enum AdapterError {
    #[error("adapter configuration error: {0}")]
    Config(String),
    #[error("adapter '{0}' is already started")]
    AlreadyStarted(String),
    #[error("adapter '{0}' is not running")]
    NotRunning(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("publish failed ({code:?}): {message}")]
    PublishFailed {
        code: PublishErrorCode,
        message: String,
    },
    #[error("request failed: {0}")]
    RequestFailed(String),
    #[error("operation timed out: {0}")]
    Timeout(String),
    #[error("unauthorized: {0}")]
    Unauthorized(String),
    #[error("invalid input: {0}")]
    InvalidInput(String),
    #[error("payload too large: {0}")]
    PayloadTooLarge(String),
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("unsupported platform: {0}")]
    UnsupportedPlatform(String),
    #[error("internal adapter error: {0}")]
    Internal(String),
}

/// Active subscription snapshot passed to [`NodeAdapter::on_subscriptions_changed`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledSubscription {
    pub id: String,
    pub subscriber: String,
    pub topic: String,
    pub filters: Vec<Filter>,
    pub coalesce_seconds: u32,
}

/// Narrow host interface exposed by `NodeCore` to attached `NodeAdapter`s.
pub trait NodeAdapterHost: Send + Sync {
    /// Publishes a validated CloudEvents v1.0 envelope onto `topic`.
    fn publish_event<'a>(
        &'a self,
        topic: &'a str,
        event: CloudEvent,
    ) -> BoxFuture<'a, Result<PublishOutcome, AdapterError>>;

    /// Reports a change in an adapter's health status.
    fn update_status<'a>(
        &'a self,
        adapter_id: &'a str,
        health: AdapterHealth,
    ) -> BoxFuture<'a, ()>;

    /// Reports that one or more events for `target` could not be delivered.
    fn report_delivery_failed<'a>(
        &'a self,
        adapter_id: &'a str,
        target: &'a str,
        events: Vec<EventKeyRef>,
        reason: &'a str,
    ) -> BoxFuture<'a, ()>;
}

/// Uniform composable adapter trait implemented by every Harness, Event Source,
/// Chat Bridge, and PeerLink attached to a Hyphae v2 `Node`.
pub trait NodeAdapter: Send + Sync {
    /// Unique adapter identifier within its Node (e.g. `"github-public"`, `"slack"`).
    fn id(&self) -> &str;

    /// Adapter class (`Harness`, `Source`, `Bridge`, `PeerLink`).
    fn kind(&self) -> AdapterKind;

    /// Starts the adapter and attaches it to `host`.
    fn start<'a>(
        &'a self,
        host: Arc<dyn NodeAdapterHost>,
    ) -> BoxFuture<'a, Result<(), AdapterError>>;

    /// Cleanly stops the adapter and releases all background tasks/resources.
    fn stop<'a>(&'a self) -> BoxFuture<'a, Result<(), AdapterError>>;

    /// Returns the adapter's current health state.
    fn health(&self) -> AdapterHealth;

    /// Optional hook invoked when active subscriptions on `topic` change
    /// (used by demand-driven sources such as `github-public`).
    fn on_subscriptions_changed<'a>(
        &'a self,
        _topic: &'a str,
        _active_subs: &'a [CompiledSubscription],
    ) -> BoxFuture<'a, ()> {
        Box::pin(async {})
    }

    /// Optional subscribe-time validation hook returning reachability diagnostics
    /// (used for fail-closed dynamic reachability checks such as `github-public`).
    fn validate_subscription<'a>(
        &'a self,
        _topic: &'a str,
        _filters: &'a [Filter],
    ) -> BoxFuture<'a, Vec<SubscriptionDiagnostic>> {
        Box::pin(async { Vec::new() })
    }
}
