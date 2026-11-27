//! Shared delivery urgency and compatible validation errors.

use hyp_store::DeliveryMode;
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use thiserror::Error;

/// Errors returned by the Delivery Engine, policy validation, or filtered inbox queries.
#[derive(Debug, Error)]
pub enum DeliveryError {
    #[error("invalid delivery urgency: '{0}'")]
    InvalidUrgency(String),

    #[error("invalid delivery rule: {0}")]
    InvalidRule(String),

    #[error("invalid inbox state: '{0}' (expected unread | muted | delivered | all)")]
    InvalidState(String),

    #[error("forbidden inbox state '{0}': quarantined and rejected items are human-CLI-only")]
    ForbiddenState(String),

    #[error("invalid pagination cursor: {0}")]
    InvalidCursor(String),

    #[error("invalid filter: {0}")]
    InvalidFilter(String),

    #[error("storage error: {0}")]
    Store(#[from] hyp_store::StoreError),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Universal 3-tier delivery urgency plus silent `mute` archive (`docs/architecture-v2.md` §2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeliveryUrgency {
    /// Wakes an active or idle agent thread immediately.
    Interrupt,
    /// Held cleanly until the agent's next turn / idle boundary, coalesced into a batch.
    Queue,
    /// Full body stays in local inbox (`unread`); still emits a slim 1-line digest on next turn/idle.
    Notify,
    /// Silent durable archive (`state = 'muted'`). NEVER wakes or triggers a standalone digest;
    /// piggybacks `· N muted` onto other deliveries and stays inspectable via `hyp_inbox(state:"muted")`.
    Mute,
}

impl DeliveryUrgency {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Interrupt => "interrupt",
            Self::Queue => "queue",
            Self::Notify => "notify",
            Self::Mute => "mute",
        }
    }

    pub fn parse(s: &str) -> Result<Self, DeliveryError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "interrupt" => Ok(Self::Interrupt),
            "queue" | "full" => Ok(Self::Queue),
            "notify" => Ok(Self::Notify),
            "mute" | "muted" => Ok(Self::Mute),
            other => Err(DeliveryError::InvalidUrgency(other.to_string())),
        }
    }

    /// True when this urgency tier triggers an immediate live wake (active or idle).
    pub const fn is_immediate_interrupt(self) -> bool {
        matches!(self, Self::Interrupt)
    }

    /// True when this urgency tier is permitted to wake a waiter / emit a turn-boundary batch or digest.
    ///
    /// **Strict `mute` invariant:** `Mute` ALWAYS returns `false`.
    pub const fn triggers_delivery_or_digest(self) -> bool {
        !matches!(self, Self::Mute)
    }

    /// True when this item is silently archived (`state = 'muted'`).
    pub const fn is_muted(self) -> bool {
        matches!(self, Self::Mute)
    }

    /// Maps a legacy `hyp_store::DeliveryMode` (`full` | `notify`) to `DeliveryUrgency`.
    pub const fn from_store_mode(mode: DeliveryMode) -> Self {
        match mode {
            DeliveryMode::Full => Self::Queue,
            DeliveryMode::Notify => Self::Notify,
        }
    }

    /// Maps `DeliveryUrgency` down to the legacy 2-state `hyp_store::DeliveryMode`.
    pub const fn to_store_mode(self) -> DeliveryMode {
        match self {
            Self::Interrupt | Self::Queue => DeliveryMode::Full,
            Self::Notify | Self::Mute => DeliveryMode::Notify,
        }
    }

    /// Priority rank used for sorting items inside a batch (lower rank = higher priority).
    pub const fn rank(self) -> u8 {
        match self {
            Self::Interrupt => 0,
            Self::Queue => 1,
            Self::Notify => 2,
            Self::Mute => 3,
        }
    }
}

impl fmt::Display for DeliveryUrgency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DeliveryUrgency {
    type Err = DeliveryError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}
