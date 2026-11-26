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
