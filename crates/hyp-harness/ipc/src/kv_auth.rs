//! Mutual authentication of privileged local KV requests on loopback TCP.

use crate::sock::{MAX_SOCKET_LINE_BYTES, read_bounded_line_async, write_ndjson_line_async};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncRead, AsyncWrite, BufReader};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::{
    hmac::{self, HMAC_SHA256, Key},
    rand::{SecureRandom, SystemRandom},
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// Reserved `SecretStore` key name holding the daemon's 32-byte deterministic HMAC-SHA256
/// key used to derive per-session `sessionToken` values that survive daemon restarts & resume.
pub const DAEMON_SESSION_TOKEN_KEY_SECRET: &str = "daemon-session-token-key";

/// Reads an existing session key without generating or writing one.
pub fn read_session_token_key(store: &hyp_crypto::SecretStore) -> Option<[u8; 32]> {
    let existing = store.get(DAEMON_SESSION_TOKEN_KEY_SECRET).ok()?;
    let mut key = [0; 32];
    let written = URL_SAFE_NO_PAD
        .decode_slice(existing.trim(), &mut key)
        .ok()?;
    (written == key.len()).then_some(key)
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Challenge {
    pub server_nonce: String,
    pub server_proof: String,
}

pub(crate) fn key(session_key: &[u8; 32]) -> Key {
    let root = Key::new(HMAC_SHA256, session_key);
    let scoped = hmac::sign(&root, b"hyphae-local-kv-tcp-v1");
    Key::new(HMAC_SHA256, scoped.as_ref())
}

pub(crate) fn nonce() -> Option<String> {
    let mut bytes = [0u8; 16];
    SystemRandom::new().fill(&mut bytes).ok()?;
    Some(URL_SAFE_NO_PAD.encode(bytes))
}

fn transcript(
    endpoint: SocketAddr,
    client_nonce: &str,
    server_nonce: &str,
    request: Option<&Value>,
) -> Option<Vec<u8>> {
    for nonce in [client_nonce, server_nonce] {
        if nonce.len() != 22 || URL_SAFE_NO_PAD.decode(nonce).ok()?.len() != 16 {
            return None;
        }
    }
    // The typed tuple keeps the endpoint, nonces and request unambiguous.
    // The server proof signs null, and a client proof signs the request object.
    if request.is_some_and(|value| !value.is_object()) {
        return None;
    }
    serde_json::to_vec(&(endpoint, client_nonce, server_nonce, request)).ok()
}

pub(crate) fn sign(
    key: &Key,
    endpoint: SocketAddr,
    client_nonce: &str,
    server_nonce: &str,
    request: Option<&Value>,
) -> Option<String> {
    let transcript = transcript(endpoint, client_nonce, server_nonce, request)?;
    Some(URL_SAFE_NO_PAD.encode(hmac::sign(key, &transcript).as_ref()))
}

pub(crate) fn verify(
    key: &Key,
    endpoint: SocketAddr,
    client_nonce: &str,
    server_nonce: &str,
    request: Option<&Value>,
    proof: &str,
) -> bool {
    if proof.len() != 43 {
        return false;
    }
    let Some(transcript) = transcript(endpoint, client_nonce, server_nonce, request) else {
        return false;
    };
    URL_SAFE_NO_PAD
        .decode(proof)
        .is_ok_and(|bytes| hmac::verify(key, &transcript, &bytes).is_ok())
}

/// Returns the request only after verifying the response to a fresh, endpoint-bound challenge.
/// The daemon retains responsibility for the deadline and for executing the operation.
pub async fn authenticate_request<R, W>(
    session_token_key: &[u8; 32],
    packet: &Map<String, Value>,
    endpoint: SocketAddr,
    reader: &mut BufReader<R>,
    writer: &mut W,
) -> Option<Value>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let client_nonce = packet.get("clientNonce")?.as_str()?;
    let server_nonce = nonce()?;
    let key = key(session_token_key);
    let server_proof = sign(&key, endpoint, client_nonce, &server_nonce, None)?;
    let challenge = Challenge {
        server_nonce,
        server_proof,
    };
    write_ndjson_line_async(writer, &json!(challenge))
        .await
        .ok()?;
    let line = read_bounded_line_async(reader, MAX_SOCKET_LINE_BYTES)
        .await
        .ok()??;
    let mut response: Value = serde_json::from_str(&line).ok()?;
    let request = response.get("request")?;
    let client_proof = response.get("clientProof")?.as_str()?;
    if !verify(
        &key,
        endpoint,
        client_nonce,
        &challenge.server_nonce,
        Some(request),
        client_proof,
    ) {
        return None;
    }
    Some(response.get_mut("request")?.take())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_kv_proofs_bind_endpoint_nonces_request_and_direction() {
        let key = key(&[42; 32]);
        let endpoint = "127.0.0.1:12345".parse().unwrap();
        let wrong_endpoint = "127.0.0.1:12346".parse().unwrap();
        let client_nonce = nonce().unwrap();
        let first_challenge = nonce().unwrap();
        let next_challenge = nonce().unwrap();
        let request = json!({"action": "get", "key": "guarded"});
        let altered = json!({"action": "delete", "key": "guarded"});

        let server_proof = sign(&key, endpoint, &client_nonce, &first_challenge, None).unwrap();
        assert!(verify(
            &key,
            endpoint,
            &client_nonce,
            &first_challenge,
            None,
            &server_proof
        ));
        assert!(!verify(
            &key,
            wrong_endpoint,
            &client_nonce,
            &first_challenge,
            None,
            &server_proof
        ));

        let valid_proof = sign(
            &key,
            endpoint,
            &client_nonce,
            &first_challenge,
            Some(&request),
        )
        .unwrap();
        for (challenge, operation, proof, expected) in [
            (&first_challenge, &request, &valid_proof, true),
            (&first_challenge, &request, &server_proof, false),
            (&first_challenge, &altered, &valid_proof, false),
            (&next_challenge, &request, &valid_proof, false),
        ] {
            assert_eq!(
                verify(
                    &key,
                    endpoint,
                    &client_nonce,
                    challenge,
                    Some(operation),
                    proof
                ),
                expected
            );
        }
    }
}
