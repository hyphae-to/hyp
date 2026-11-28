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

/// A wake transport failure reason serialized as the existing reason string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "String", into = "String")]
pub struct PushReason(PushReasonKind);

macro_rules! push_reasons {
    ($($variant:ident => $wire:expr),+ $(,)?) => {
        #[derive(Debug, Clone, PartialEq, Eq)]
        enum PushReasonKind {
            $($variant,)+
            Other(String),
        }

        impl PushReasonKind {
            fn known(value: &str) -> Option<Self> {
                match value {
                    $(candidate if candidate == $wire => Some(Self::$variant),)+
                    _ => None,
                }
            }

            fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $wire,)+
                    Self::Other(value) => value,
                }
            }
        }
    }
}

push_reasons! {
    HerdrWorking => "herdr_working",
    HerdrSendGuardRefused => "herdr_send_guard_refused",
    HerdrAgentNotReady => "herdr_agent_not_ready",
    T3ServerUnreachable => "t3_server_unreachable",
    CodexQueueUnavailable => "codex_queue_unavailable",
    OpenclawGatewayUnavailable => openclaw::REASON_OPENCLAW_GATEWAY_UNAVAILABLE,
    OpenclawRateLimited => openclaw::REASON_OPENCLAW_RATE_LIMITED,
    HerdrTargetUnavailable => "herdr_target_unavailable",
    T3ThreadDeleted => "t3_thread_deleted",
    T3ThreadArchived => "t3_thread_archived",
    T3ThreadNotFound => "t3_thread_not_found",
    T3AuthMissing => "t3_auth_missing",
    T3AuthFailed => "t3_auth_failed",
    T3InvalidServerUrl => "t3_invalid_server_url",
    OpenclawAuthFailed => openclaw::REASON_OPENCLAW_AUTH_FAILED,
    OpenclawHooksDisabled => openclaw::REASON_OPENCLAW_HOOKS_DISABLED,
    OpenclawInvalidUrl => openclaw::REASON_OPENCLAW_INVALID_URL,
    OpenclawInvalidSessionKey => openclaw::REASON_OPENCLAW_INVALID_SESSION_KEY,
    OpenclawSessionMissing => openclaw::REASON_OPENCLAW_SESSION_MISSING,
    OpenclawTokenMissing => openclaw::REASON_OPENCLAW_TOKEN_MISSING,
}

impl PushReason {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Whether Herdr is active or guards delivery, requiring a deferred retry.
    pub fn is_herdr_active_or_guarded(&self) -> bool {
        matches!(
            self.0,
            PushReasonKind::HerdrWorking
                | PushReasonKind::HerdrSendGuardRefused
                | PushReasonKind::HerdrAgentNotReady
        )
    }

    /// Whether transport availability may recover after a bounded retry.
    pub fn is_transiently_unavailable(&self) -> bool {
        matches!(
            self.0,
            PushReasonKind::T3ServerUnreachable
                | PushReasonKind::CodexQueueUnavailable
                | PushReasonKind::OpenclawGatewayUnavailable
                | PushReasonKind::OpenclawRateLimited
        )
    }

    /// Whether the target binding must be discarded before transport rediscovery.
    pub fn is_terminal_target_error(&self) -> bool {
        matches!(
            self.0,
            PushReasonKind::HerdrTargetUnavailable
                | PushReasonKind::T3ThreadDeleted
                | PushReasonKind::T3ThreadArchived
                | PushReasonKind::T3ThreadNotFound
                | PushReasonKind::T3AuthMissing
                | PushReasonKind::T3AuthFailed
                | PushReasonKind::T3InvalidServerUrl
                | PushReasonKind::OpenclawAuthFailed
                | PushReasonKind::OpenclawHooksDisabled
                | PushReasonKind::OpenclawInvalidUrl
                | PushReasonKind::OpenclawInvalidSessionKey
                | PushReasonKind::OpenclawSessionMissing
                | PushReasonKind::OpenclawTokenMissing
        )
    }
}

impl From<String> for PushReason {
    fn from(value: String) -> Self {
        Self(PushReasonKind::known(&value).unwrap_or(PushReasonKind::Other(value)))
    }
}

impl From<&str> for PushReason {
    fn from(value: &str) -> Self {
        Self(PushReasonKind::known(value).unwrap_or_else(|| PushReasonKind::Other(value.into())))
    }
}

impl From<PushReason> for String {
    fn from(value: PushReason) -> Self {
        match value.0 {
            PushReasonKind::Other(value) => value,
            reason => reason.as_str().into(),
        }
    }
}

/// Deterministic outcome of a single external push transport delivery attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "lowercase")]
pub enum PushOutcome {
    /// Message was accepted/delivered by the target transport.
    Delivered,
    /// Target is busy, offline, or temporarily unavailable; keep unread in durable mailbox.
    Hold {
        reason: PushReason,
        #[serde(default, skip_serializing_if = "is_false")]
        interrupted: bool,
    },
    /// Delivery attempt failed with uncertain or terminal error; keep unread in mailbox for hook fallback.
    Reject {
        reason: PushReason,
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

    pub fn hold(reason: impl Into<PushReason>) -> Self {
        Self::Hold {
            reason: reason.into(),
            interrupted: false,
        }
    }

    pub fn hold_interrupted(reason: impl Into<PushReason>) -> Self {
        Self::Hold {
            reason: reason.into(),
            interrupted: true,
        }
    }

    pub fn reject(reason: impl Into<PushReason>) -> Self {
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

    /// Whether hook activity determines when interrupt urgency needs an actual stop key.
    fn interrupt_requires_active_turn(&self) -> bool {
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
    /// use hyp_harness_transport::transport::{PushMode, PushTransport};
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_outcome_reason_wire_format_is_compatible() {
        for (reason, expected) in [
            ("herdr_working", PushReasonKind::HerdrWorking),
            (
                "unrecognized_reason",
                PushReasonKind::Other("unrecognized_reason".into()),
            ),
        ] {
            assert_eq!(PushReason::from(reason), PushReason(expected.clone()));
            assert_eq!(
                PushReason::from(reason.to_owned()),
                PushReason(expected.clone())
            );
            let packet = serde_json::json!({"outcome": "hold", "reason": reason});
            let outcome = serde_json::from_value::<PushOutcome>(packet.clone()).unwrap();
            assert_eq!(
                outcome,
                PushOutcome::Hold {
                    reason: PushReason(expected.clone()),
                    interrupted: false,
                }
            );
            assert_eq!(serde_json::to_value(outcome).unwrap(), packet);
        }
    }
}
