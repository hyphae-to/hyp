//! Canonical transcript and header for Hyphae Ed25519 HTTP authentication.
use crate::keys::Ed25519KeyPair;

/// Formats the canonical Ed25519 HTTP authentication signing input.
pub fn http_auth_signing_input(
    method: &str,
    path_and_query: &str,
    ts_ms: i64,
    nonce: &str,
    body_sha256: &str,
) -> Vec<u8> {
    format!("{method}\n{path_and_query}\n{ts_ms}\n{nonce}\n{body_sha256}").into_bytes()
}

/// Signs the exact caller-supplied transcript fields and formats its Authorization header.
/// Callers provide their own timestamp, nonce and body digest.
pub fn sign_http_auth(
    node_id: &str,
    signing: &Ed25519KeyPair,
    method: &str,
    path_and_query: &str,
    ts_ms: i64,
    nonce: &str,
    body_sha256: &str,
) -> String {
    let input = http_auth_signing_input(method, path_and_query, ts_ms, nonce, body_sha256);
    let signature = signing.sign_domain_b64("http-auth", &input);
    format!(
        "Hyphae-Ed25519 node=\"{node_id}\",ts=\"{ts_ms}\",nonce=\"{nonce}\",sig=\"{signature}\""
    )
}
