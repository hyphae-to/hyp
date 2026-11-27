//! Session identifiers and caller verification codes used on the local socket.

use serde::{Deserialize, Serialize};

/// Fail-closed caller verification error codes (matching `src/caller.ts`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallerErrorCode {
    CallerUnverifiable,
    CallerNotFound,
    CallerAmbiguous,
}

impl CallerErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CallerUnverifiable => "caller_unverifiable",
            Self::CallerNotFound => "caller_not_found",
            Self::CallerAmbiguous => "caller_ambiguous",
        }
    }
}

/// Validates a session ID matching `src/protocol.ts:sessionIdPattern` (`^[a-z0-9][a-z0-9._:-]{1,255}$`).
pub fn is_valid_session_id(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() < 2 || bytes.len() > 256 {
        return false;
    }
    if !(bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit()) {
        return false;
    }
    bytes[1..]
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// Validates a per-session socket authentication token (`HYPHAE_SESSION_TOKEN`).
///
/// Strictly allows ASCII `[A-Za-z0-9._-]` (1..=256 bytes) with zero quotes, whitespace, or
/// control characters so it is safe both on wire JSON and in shell env files.
pub fn is_valid_session_token(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    if bytes.is_empty() || bytes.len() > 256 {
        return false;
    }
    bytes
        .iter()
        .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
