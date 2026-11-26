//! Local CLI KV operations shared by the daemon and offline SQLite access.

use hyp_proto::address::LOCAL_NODE_ID;
use hyp_store::{KvDeleteInput, KvEntry, KvSetInput, NodeDb, StoreError, WriteModel, now_ms};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalKvRequest {
    pub host_node: String,
    pub namespace: String,
    #[serde(flatten)]
    pub action: LocalKvAction,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(
    tag = "action",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub enum LocalKvAction {
    Get {
        key: String,
    },
    Set {
        key: String,
        value: Value,
        write_model: WriteModel,
        owner: Option<String>,
        allowlist: Option<Vec<String>>,
        writer: Option<String>,
        expected_version: Option<u64>,
        ttl_ms: Option<i64>,
    },
    Delete {
        key: String,
        writer: Option<String>,
        expected_version: Option<u64>,
    },
    List {
        prefix: Option<String>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LocalKvResponse {
    Get(Option<KvEntry>),
    Set(KvEntry),
    Delete {
        deleted: bool,
        previous_version: Option<u64>,
    },
    List {
        host_node: String,
        entries: Vec<KvEntry>,
    },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LocalKvError {
    VersionConflict(u64),
    Unauthorized(String),
    InvalidInput(String),
    ListTooLarge { state_dir: PathBuf, node_id: String },
    Other(String),
}

impl From<StoreError> for LocalKvError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::VersionConflict { current_version } => {
                Self::VersionConflict(current_version)
            }
            StoreError::Unauthorized(msg) => Self::Unauthorized(msg),
            StoreError::InvalidInput(msg) => Self::InvalidInput(msg),
            other => Self::Other(other.to_string()),
        }
    }
}

impl LocalKvRequest {
    pub fn execute(self, db: &NodeDb, local_node: &str) -> Result<LocalKvResponse, LocalKvError> {
        let host_node = if self.host_node == LOCAL_NODE_ID {
            local_node.to_owned()
        } else {
            self.host_node
        };
        let namespace = self.namespace;
        let kv = db.kv();
        let now = now_ms();
        Ok(match self.action {
            LocalKvAction::Get { key } => {
                LocalKvResponse::Get(kv.get(&host_node, &namespace, &key, now)?)
            }
            LocalKvAction::Set {
                key,
                value,
                write_model,
                owner,
                allowlist,
                writer,
                expected_version,
                ttl_ms,
            } => {
                let saved = kv.set(
                    &KvSetInput {
                        host_node,
                        namespace,
                        key,
                        value,
                        content_type: Some("application/json".into()),
                        write_model,
                        owner_id: owner,
                        allowlist,
                        writer_id: writer.unwrap_or_else(|| local_node.to_owned()),
                        expected_version,
                        e2ee_epoch: None,
                        signature: None,
                        ttl_ms,
                    },
                    now,
                )?;
                LocalKvResponse::Set(saved.entry)
            }
            LocalKvAction::Delete {
                key,
                writer,
                expected_version,
            } => {
                let removed = kv.delete(
                    &KvDeleteInput {
                        host_node,
                        namespace,
                        key,
                        writer_id: writer.unwrap_or_else(|| local_node.to_owned()),
                        expected_version,
                    },
                    now,
                )?;
                LocalKvResponse::Delete {
                    deleted: removed.deleted,
                    previous_version: removed.previous_version,
                }
            }
            LocalKvAction::List { prefix } => {
                let entries = kv.list(&host_node, &namespace, prefix.as_deref(), now)?;
                LocalKvResponse::List { host_node, entries }
            }
        })
    }
}

/// The TCP transport is reachable by other local users. Require proof of access to
/// the daemon's existing private keystore before accepting a privileged KV operation.
pub(crate) mod tcp_auth {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use ring::{
        hmac::{self, HMAC_SHA256, Key},
        rand::{SecureRandom, SystemRandom},
    };
    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use std::net::SocketAddr;

    #[derive(Deserialize, Serialize)]
    #[serde(rename_all = "camelCase")]
    pub struct Challenge {
        pub server_nonce: String,
        pub server_proof: String,
    }

    pub fn key(session_key: &[u8; 32]) -> Key {
        let root = Key::new(HMAC_SHA256, session_key);
        let scoped = hmac::sign(&root, b"hyphae-local-kv-tcp-v1");
        Key::new(HMAC_SHA256, scoped.as_ref())
    }

    pub fn nonce() -> Option<String> {
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

    pub fn sign(
        key: &Key,
        endpoint: SocketAddr,
        client_nonce: &str,
        server_nonce: &str,
        request: Option<&Value>,
    ) -> Option<String> {
        let transcript = transcript(endpoint, client_nonce, server_nonce, request)?;
        Some(URL_SAFE_NO_PAD.encode(hmac::sign(key, &transcript).as_ref()))
    }

    pub fn verify(
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

    #[cfg(test)]
    mod tests {
        use super::*;
        use serde_json::json;

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
}
