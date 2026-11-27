//! Native external wakeup transports for idle agent sessions:
//! - [`herdr`] — Herdr (`hc`) terminal identity verification, interrupt & metadata-only wake nudge
//! - [`codex`] — Codex CLI (`codex queue --thread ... --message ...`) metadata-only wake nudge
//! - [`t3`] — T3 Code read-only `statev2.sqlite` thread resolution & metadata-only WebSocket RPC wake nudge
//! - [`openclaw`] — OpenClaw Gateway metadata-only webhook push (`POST /hooks/agent` or `/hooks/wake`)
//!
//! Security invariant (RFC 0004): every push transport carries only the daemon-rendered
//! metadata-only `<hyphae-inbox>` digest, so untrusted mesh/bridge/webhook bodies NEVER enter an
//! agent's `role: "user"` prompt. The woken agent reads content (with `humanVerified` /
//! `trustTier`) through `hyp_inbox`.

use std::future::Future;
use std::pin::Pin;

pub use hyp_node::delivery::InboxDigest;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod codex;
pub mod herdr;
pub mod openclaw;
mod origin;
mod process;
pub mod t3;

/// Boxed `Send` future alias used by [`PushTransport`].
pub type TransportFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Delivery urgency mode for an external push transport.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PushMode {
    /// Deliver when the target agent is idle / ready (never interrupt active work).
    Queue,
    /// May interrupt active work before delivering if supported by the transport.
    Interrupt,
}

/// Deterministic outcome of a single external push transport delivery attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "lowercase")]
pub enum PushOutcome {
    /// Message was accepted/delivered by the target transport.
    Delivered,
    /// Target is busy, offline, or temporarily unavailable; keep unread in durable mailbox.
    Hold {
        reason: String,
        #[serde(default, skip_serializing_if = "is_false")]
        interrupted: bool,
    },
    /// Delivery attempt failed with uncertain or terminal error; keep unread in mailbox for hook fallback.
    Reject {
        reason: String,
        #[serde(default, skip_serializing_if = "is_false")]
        interrupted: bool,
    },
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl PushOutcome {
    pub fn delivered() -> Self {
        Self::Delivered
    }

    pub fn hold(reason: impl Into<String>) -> Self {
        Self::Hold {
            reason: reason.into(),
            interrupted: false,
        }
    }

    pub fn hold_interrupted(reason: impl Into<String>) -> Self {
        Self::Hold {
            reason: reason.into(),
            interrupted: true,
        }
    }

    pub fn reject(reason: impl Into<String>) -> Self {
        Self::Reject {
            reason: reason.into(),
            interrupted: false,
        }
    }

    pub fn is_delivered(&self) -> bool {
        matches!(self, Self::Delivered)
    }
}

/// Trait implemented by Herdr, Codex Queue, T3 Code, and OpenClaw wakeup transports.
pub trait PushTransport: Send + Sync {
    /// Stable short transport name (`"herdr"`, `"codex_queue"`, `"t3"`).
    fn kind(&self) -> &'static str;

    /// Whether this transport supports [`PushMode::Interrupt`] in addition to [`PushMode::Queue`].
    fn supports_interrupt(&self) -> bool {
        false
    }

    /// Returns the bound Herdr terminal ID when this transport targets a Herdr terminal.
    fn herdr_terminal_id(&self) -> Option<&str> {
        None
    }

    /// Returns the pinned Herdr terminal creation timestamp (`created_ms`) when known.
    fn herdr_created_ms(&self) -> Option<i64> {
        None
    }

    /// Returns metadata-only JSON attributes describing the transport target
    /// (persisted into `sessions.backend_json`; MUST NEVER contain secrets).
    fn target_metadata(&self) -> Value {
        Value::Null
    }

    /// Attempts to wake the bound session with a metadata-only inbox digest.
    ///
    /// Even a string that looks like a digest cannot be sent through this API.
    /// ```compile_fail
    /// use hyp_harness::transport::{PushMode, PushTransport};
    ///
    /// fn send(transport: &dyn PushTransport) {
    ///     let _ = transport.deliver("<hyphae-inbox>message body</hyphae-inbox>", PushMode::Queue);
    /// }
    /// ```
    fn deliver<'a>(
        &'a self,
        digest: &'a InboxDigest,
        mode: PushMode,
    ) -> TransportFuture<'a, PushOutcome>;

    /// Delivers a unified RFC 0004 metadata-only `<hyphae-inbox ...>` XML digest with idempotency
    /// `batch_id`. Defaults to forwarding `digest` to [`Self::deliver`].
    fn deliver_digest<'a>(
        &'a self,
        digest: &'a InboxDigest,
        _batch_id: &'a str,
        mode: PushMode,
    ) -> TransportFuture<'a, PushOutcome> {
        self.deliver(digest, mode)
    }
}

#[cfg(test)]
fn test_digest() -> InboxDigest {
    InboxDigest::count_only(1, hyp_node::delivery::DeliveryUrgency::Queue).unwrap()
}
