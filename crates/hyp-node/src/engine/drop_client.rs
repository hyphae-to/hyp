//! Shared Drop Relay client URL policy and caller-specific diagnostics.
use http::Uri;

/// The two existing callers retain detailed and compact diagnostics for the same rejection.
#[derive(Debug)]
pub struct RelayUrlError {
    pub detailed: String,
    pub compact: String,
}

const SCHEME_MESSAGE: &str =
    "Drop Relay URL must use https:// (or loopback http://127.0.0.1 / http://localhost)";
const URI_MESSAGE: &str = "Drop Relay URL is not a valid URI";
const HOST_MESSAGE: &str = "Drop Relay URL is missing a valid host";
const USERINFO_MESSAGE: &str = "Drop Relay URL must not contain userinfo credentials";

/// Validates the strict intersection of the existing relay URL policies.
/// HTTP is limited to 127.0.0.1 or localhost; accepted spelling is otherwise retained.
pub fn validate_relay_url(raw: &str) -> Result<String, RelayUrlError> {
    let trimmed = raw.trim().trim_end_matches('/');
    let has_query_or_fragment = trimmed.contains('#') || trimmed.contains('?');
    let has_control = trimmed.bytes().any(|byte| byte <= 0x20 || byte == 0x7f);
    let parsed = trimmed.parse::<Uri>();
    // Presentation preserves the compact caller's original rejection precedence without
    // duplicating its acceptance decision or parsing the URI twice.
    let compact = if trimmed.is_empty() || has_control || has_query_or_fragment {
        SCHEME_MESSAGE
    } else {
        match parsed.as_ref() {
            Err(_) => URI_MESSAGE,
            Ok(uri) => match uri.authority() {
                None => HOST_MESSAGE,
                Some(authority) if authority.as_str().contains('@') => USERINFO_MESSAGE,
                Some(authority) if authority.host().is_empty() => HOST_MESSAGE,
                _ => SCHEME_MESSAGE,
            },
        }
    };
    let error = |detailed: String| RelayUrlError {
        detailed,
        compact: compact.to_string(),
    };
    if trimmed.is_empty() {
        return Err(error("Drop Relay URL cannot be empty".to_string()));
    }
    if has_query_or_fragment {
        return Err(error(
            "Drop Relay URL must not contain query parameters or fragments".to_string(),
        ));
    }
    let uri =
        parsed.map_err(|cause| error(format!("invalid Drop Relay URL '{trimmed}': {cause}")))?;
    let scheme = uri.scheme_str().ok_or_else(|| {
        error(format!(
            "Drop Relay URL '{trimmed}' must include https:// scheme"
        ))
    })?;
    let authority = uri
        .authority()
        .ok_or_else(|| error(format!("Drop Relay URL '{trimmed}' is missing a host")))?;
    if authority.as_str().contains('@') {
        return Err(error(
            "Drop Relay URL must not include embedded credentials".to_string(),
        ));
    }
    let host = authority.host().to_ascii_lowercase();
    if host.is_empty() {
        return Err(error("Drop Relay URL host cannot be empty".to_string()));
    }
    match scheme {
        "https" => {}
        "http" if matches!(host.as_str(), "127.0.0.1" | "localhost") => {}
        "http" => {
            return Err(error(format!(
                "refusing insecure http:// Drop Relay URL '{trimmed}'; use https:// (only loopback http://127.0.0.1 or http://localhost is permitted)"
            )));
        }
        other => {
            return Err(error(format!(
                "unsupported Drop Relay URL scheme '{other}' (expected https://)"
            )));
        }
    }
    if has_control {
        return Err(error(
            "Drop Relay URL must not contain whitespace or control characters".to_string(),
        ));
    }
    Ok(trimmed.to_string())
}
