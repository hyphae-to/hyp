use std::collections::{BTreeMap, BTreeSet};

use hyp_crypto::e2ee::{EpochScope, SignedEpochKeyBundle, verify_epoch_bundle};
use hyp_proto::cloudevent::CONTENT_TYPE_E2EE_JSON;
use hyp_proto::manifest::KvMode;
use hyp_store::kv::KvEntryMetadata;
use hyp_store::{Filter, KvEpoch, Subscription, is_kv_key, is_kv_namespace, now_ms};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{NodeError, UnifiedNode};

const MAX_NAMESPACES: usize = 32;
const MAX_SNAPSHOT_ENTRIES_PER_NAMESPACE: usize = 4;
const ENTRY_SCAN_PAGE: u32 = 128;
const MAX_KV_PREVIEW_BYTES: usize = 4096;

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KvValuePreview {
    pub text: String,
    pub version: u64,
    pub truncated: bool,
}

struct LocalNamespaceAccess {
    epoch: Option<u64>,
    member_count: usize,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KvInspection {
    pub namespaces: Vec<KvNamespaceInspection>,
    pub namespaces_truncated: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KvNamespaceInspection {
    pub name: String,
    pub origin_node: String,
    pub epoch: Option<u64>,
    pub member_count: usize,
    pub entry_count: usize,
    pub watch_count: usize,
    pub entries: Vec<KvKeyInspection>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KvKeyInspection {
    pub key: String,
    pub version: u64,
    pub updated_by: String,
    pub updated_at: i64,
    pub expires_at: Option<i64>,
    pub size_bytes: u64,
}

impl From<KvEntryMetadata> for KvKeyInspection {
    fn from(entry: KvEntryMetadata) -> Self {
        Self {
            key: entry.key,
            version: entry.version,
            updated_by: entry.writer_id,
            updated_at: entry.updated_at,
            expires_at: entry.expires_at,
            size_bytes: entry.stored_size_bytes,
        }
    }
}

impl UnifiedNode {
    /// Inspects hosted KV from the local node's point of view.
    pub fn inspect_local_kv(&self, now_ms: i64) -> Result<KvInspection, NodeError> {
        let host = self.config.node_id.as_str();
        let (names, watches) = {
            let db = self.db();
            (
                db.kv().list_namespaces(host, now_ms)?,
                db.events().list_subscriptions(None)?,
            )
        };
        let names: BTreeSet<_> = names
            .iter()
            .map(String::as_str)
            .chain(
                self.config
                    .kv_namespaces
                    .iter()
                    .map(|namespace| namespace.name.as_str()),
            )
            .collect();
        let mut namespaces = Vec::new();
        for name in names {
            let Some(access) = self.local_kv_namespace_access(name)? else {
                continue;
            };
            if namespaces.len() == MAX_NAMESPACES {
                return Ok(KvInspection {
                    namespaces,
                    namespaces_truncated: true,
                });
            }

            let mut epoch_access = BTreeMap::new();
            let mut entries = Vec::new();
            let mut entry_count = 0;
            let mut after = None;
            loop {
                let page = self.db().kv().list_entry_metadata(
                    host,
                    name,
                    after.as_deref(),
                    ENTRY_SCAN_PAGE,
                    now_ms,
                )?;
                let page_full = page.len() == ENTRY_SCAN_PAGE as usize;
                after = page.last().map(|entry| entry.key.clone());
                for entry in page {
                    let access_key = (
                        entry.content_type == CONTENT_TYPE_E2EE_JSON,
                        entry.e2ee_epoch,
                    );
                    let visible = if let Some(visible) = epoch_access.get(&access_key) {
                        *visible
                    } else {
                        let visible =
                            self.local_kv_entry_visible(name, &access, access_key.0, access_key.1)?;
                        epoch_access.insert(access_key, visible);
                        visible
                    };
                    if visible {
                        entry_count += 1;
                        if entries.len() < MAX_SNAPSHOT_ENTRIES_PER_NAMESPACE {
                            entries.push(entry.into());
                        }
                    }
                }
                if !page_full {
                    break;
                }
            }
            namespaces.push(KvNamespaceInspection {
                name: name.to_owned(),
                origin_node: host.to_owned(),
                epoch: access.epoch,
                member_count: access.member_count,
                entry_count,
                watch_count: watches
                    .iter()
                    .filter(|watch| watches_namespace(watch, host, name))
                    .count(),
                entries,
            });
        }
        Ok(KvInspection {
            namespaces,
            namespaces_truncated: false,
        })
    }

    /// Reads and decrypts one visible key after an explicit local request.
    pub async fn preview_local_kv(
        &self,
        namespace: &str,
        key: &str,
    ) -> Result<Option<KvValuePreview>, NodeError> {
        if !is_kv_namespace(namespace) || !is_kv_key(key) {
            return Err(NodeError::BadRequest("invalid KV namespace or key".into()));
        }
        let host = self.config.node_id.as_str();
        let Some(access) = self.local_kv_namespace_access(namespace)? else {
            return Ok(None);
        };
        let entry = self.db().kv().get(host, namespace, key, now_ms())?;
        let Some(entry) = entry else {
            return Ok(None);
        };
        if !self.local_kv_entry_visible(
            namespace,
            &access,
            entry.content_type == CONTENT_TYPE_E2EE_JSON,
            entry.e2ee_epoch,
        )? {
            return Ok(None);
        }
        let entry = self.maybe_decrypt_kv_entry(host, entry, None).await?;
        let mut text = match entry.value {
            Value::String(text) => text,
            value => serde_json::to_string_pretty(&value)?,
        };
        let truncated = text.len() > MAX_KV_PREVIEW_BYTES;
        if truncated {
            let mut end = MAX_KV_PREVIEW_BYTES;
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            text.truncate(end);
        }
        Ok(Some(KvValuePreview {
            text,
            version: entry.version,
            truncated,
        }))
    }

    fn local_kv_namespace_access(
        &self,
        namespace: &str,
    ) -> Result<Option<LocalNamespaceAccess>, NodeError> {
        let host = self.config.node_id.as_str();
        let latest = self.db().kv().latest_epoch(host, namespace)?;
        if let Some(epoch) = latest {
            return Ok(self
                .local_kv_epoch_member_count(&epoch)?
                .map(|member_count| LocalNamespaceAccess {
                    epoch: Some(epoch.epoch),
                    member_count,
                }));
        }
        let requires_encryption = self
            .config
            .kv_namespaces
            .iter()
            .any(|configured| configured.name == namespace && configured.mode == KvMode::E2ee);
        Ok((!requires_encryption).then_some(LocalNamespaceAccess {
            epoch: None,
            member_count: 0,
        }))
    }

    fn local_kv_entry_visible(
        &self,
        namespace: &str,
        access: &LocalNamespaceAccess,
        is_e2ee: bool,
        entry_epoch: Option<u64>,
    ) -> Result<bool, NodeError> {
        match (is_e2ee, entry_epoch, access.epoch) {
            (false, None, None) => Ok(true),
            (true, Some(epoch), Some(active)) if epoch == active => Ok(true),
            (true, Some(epoch), Some(active)) if epoch < active => {
                let stored =
                    self.db()
                        .kv()
                        .get_epoch(self.config.node_id.as_str(), namespace, epoch)?;
                match stored {
                    Some(stored) => Ok(self.local_kv_epoch_member_count(&stored)?.is_some()),
                    None => Ok(false),
                }
            }
            _ => Ok(false),
        }
    }

    fn local_kv_epoch_member_count(&self, epoch: &KvEpoch) -> Result<Option<usize>, NodeError> {
        let host = self.config.node_id.as_str();
        let signer = if epoch.creator_node_id == host {
            self.identity.signing.public_key()
        } else if let Some(key) = self.lookup_peer_signing_key(&epoch.creator_node_id)? {
            key
        } else {
            return Ok(None);
        };
        let Ok(bundle) = serde_json::from_str::<SignedEpochKeyBundle>(&epoch.key_envelope_json)
        else {
            return Ok(None);
        };
        let Ok(payload) = verify_epoch_bundle(
            &bundle,
            EpochScope::Kv,
            host,
            &epoch.namespace,
            &signer,
            self.current_min_epoch("kv", host, &epoch.namespace),
        ) else {
            return Ok(None);
        };
        if payload.epoch != epoch.epoch || payload.created_by != epoch.creator_node_id {
            return Ok(None);
        }
        let my_kid = self.identity.encryption.kid();
        if !payload
            .wraps
            .iter()
            .any(|wrap| wrap.node_id == host && wrap.recipient_kid == my_kid)
        {
            return Ok(None);
        }
        let members: BTreeSet<_> = payload
            .wraps
            .iter()
            .map(|wrap| wrap.node_id.as_str())
            .collect();
        Ok(Some(members.len()))
    }
}

fn watches_namespace(watch: &Subscription, host: &str, namespace: &str) -> bool {
    watch.topic == "kv"
        && (watch.origin_node == host || watch.origin_node == "local")
        && watch
            .filters
            .iter()
            .all(|filter| namespace_match(filter, namespace) != Some(false))
}

// Other event fields are unknown for a namespace summary. Count a watch if the
// known namespace does not rule it out, including through nested boolean filters.
fn namespace_match(filter: &Filter, namespace: &str) -> Option<bool> {
    let match_fields = |fields: &BTreeMap<String, String>, matches: fn(&str, &str) -> bool| {
        if let Some(value) = fields.get("ns") {
            if !matches(namespace, value) {
                return Some(false);
            }
            if fields.len() == 1 {
                return Some(true);
            }
        }
        fields.is_empty().then_some(true)
    };
    match filter {
        Filter::Exact(fields) => match_fields(fields, |a, b| a == b),
        Filter::Prefix(fields) => match_fields(fields, |a, b| a.starts_with(b)),
        Filter::Suffix(fields) => match_fields(fields, |a, b| a.ends_with(b)),
        Filter::Not(inner) => namespace_match(inner, namespace).map(|matched| !matched),
        Filter::All(filters) => {
            let mut result = Some(true);
            for filter in filters {
                match namespace_match(filter, namespace) {
                    Some(false) => return Some(false),
                    None => result = None,
                    Some(true) => {}
                }
            }
            result
        }
        Filter::Any(filters) => {
            let mut result = Some(false);
            for filter in filters {
                match namespace_match(filter, namespace) {
                    Some(true) => return Some(true),
                    None => result = None,
                    Some(false) => {}
                }
            }
            result
        }
    }
}
