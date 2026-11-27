//! Pure harness identity hints shared by client shims and daemon transports.

use crate::caller::is_valid_session_id;

/// Maximum OpenClaw agent identifier length in bytes.
pub const MAX_OPENCLAW_AGENT_ID_LEN: usize = 128;
const MAX_SESSION_KEY_LEN: usize = 256;
const INVALID_SESSION_KEY_ERR: &str = "OpenClaw sessionKey must be a non-empty string (<=256 bytes) without whitespace or control characters";

/// Inspects `HC_TERMINAL_ID` from the current process environment.
///
/// Returns `None` when unset, blank, or not a safe terminal address.
pub fn detect_env_terminal_id() -> Option<String> {
    parse_env_terminal_id(crate::ambient_env_var("HC_TERMINAL_ID").as_deref())
}

fn parse_env_terminal_id(raw: Option<&str>) -> Option<String> {
    let trimmed = raw?.trim();
    if is_valid_terminal_id(trimmed) {
        Some(trimmed.to_string())
    } else {
        None
    }
}

/// Validates that a Herdr terminal identifier is non-empty, cannot be interpreted
/// as a CLI flag (does not start with `'-'`), and contains no whitespace or
/// control characters.
pub fn is_valid_terminal_id(terminal_id: &str) -> bool {
    !terminal_id.is_empty()
        && !terminal_id.starts_with('-')
        && !terminal_id
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
}

/// Strictly validates an OpenClaw `sessionKey` (e.g. `"agent:main:main"` or
/// `"agent:main:explicit:thread-2"`), rejecting empty strings, excessive length, whitespace,
/// or ASCII control characters fail-closed.
pub fn validate_openclaw_session_key(raw: &str) -> Result<String, String> {
    if raw.is_empty()
        || raw.len() > MAX_SESSION_KEY_LEN
        || raw.bytes().any(|b| b <= 0x20 || b == 0x7f)
    {
        return Err(INVALID_SESSION_KEY_ERR.to_string());
    }
    Ok(raw.to_string())
}

/// Extracts `<agentId>` from a canonical OpenClaw session key (`"agent:<agentId>:<rest>"`).
pub fn parse_openclaw_agent_id_from_session_key(session_key: &str) -> Option<String> {
    let rest = session_key.strip_prefix("agent:")?;
    let (aid, tail) = rest.split_once(':')?;
    if aid.is_empty()
        || tail.is_empty()
        || aid.len() > MAX_OPENCLAW_AGENT_ID_LEN
        || aid.bytes().any(|b| b <= 0x20 || b == 0x7f)
    {
        return None;
    }
    Some(aid.to_string())
}

/// Deterministically maps a validated OpenClaw `sessionKey` (or fallback OpenClaw ID) to its
/// canonical Hyphae `session_id` (`openclaw:<key>`, or `openclaw:sk_<sha256[..32]>` when the
/// key contains characters outside `[A-Za-z0-9._:-]` or exceeds 256 bytes with the prefix).
///
/// Matches `canonicalOpenClawSessionId()` in `plugins/openclaw/index.js` bit-for-bit.
pub fn canonical_openclaw_session_id(raw_key: &str) -> Result<String, String> {
    let stripped = raw_key.strip_prefix("openclaw:").unwrap_or(raw_key);
    let key = validate_openclaw_session_key(stripped)?;
    let direct = format!("openclaw:{key}");
    if is_valid_session_id(&direct) {
        Ok(direct)
    } else {
        let digest = hyp_proto::jcs::sha256_hex(key.as_bytes());
        Ok(format!("openclaw:sk_{}", &digest[..32]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_terminal_ids_and_env_parsing() {
        assert!(is_valid_terminal_id("t3"));
        assert!(is_valid_terminal_id("macbook:t12"));
        assert!(is_valid_terminal_id("dev-box.local:t1"));

        assert!(!is_valid_terminal_id(""));
        assert!(!is_valid_terminal_id("-t3"));
        assert!(!is_valid_terminal_id("--json"));
        assert!(!is_valid_terminal_id("t3 extra"));
        assert!(!is_valid_terminal_id("t3\n"));
        assert!(!is_valid_terminal_id("t3\0"));

        assert_eq!(parse_env_terminal_id(None), None);
        assert_eq!(parse_env_terminal_id(Some("")), None);
        assert_eq!(parse_env_terminal_id(Some("   ")), None);
        assert_eq!(parse_env_terminal_id(Some("--flag")), None);
        assert_eq!(parse_env_terminal_id(Some(" t9 \n")), Some("t9".into()));
    }
}
