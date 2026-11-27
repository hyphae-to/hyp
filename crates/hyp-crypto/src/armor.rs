//! Shared JCS/base64url token framing. Callers retain their type-specific validation.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Serialize, de::DeserializeOwned};

use crate::{error::CryptoError, jcs::to_canonical_json};

pub(crate) fn armor<T: Serialize>(prefix: &str, value: &T) -> Result<String, CryptoError> {
    let canonical = to_canonical_json(value)?;
    Ok(format!(
        "{prefix}{}",
        URL_SAFE_NO_PAD.encode(canonical.as_bytes())
    ))
}

pub(crate) fn dearmor<T: DeserializeOwned>(
    prefix: &str,
    token: &str,
    framing_error: fn(String) -> CryptoError,
) -> Result<T, CryptoError> {
    let encoded = token
        .trim()
        .strip_prefix(prefix)
        .ok_or_else(|| framing_error(format!("expected '{prefix}' prefix")))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|e| framing_error(format!("invalid {prefix} base64url: {e}")))?;
    Ok(serde_json::from_slice(&bytes)?)
}
