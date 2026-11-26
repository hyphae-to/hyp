use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use hyp_crypto::e2ee::{EpochScope, SignedEpochKeyBundle, verify_epoch_bundle};
use hyp_proto::cloudevent::CONTENT_TYPE_E2EE_JSON;
use hyp_proto::manifest::KvMode;
use hyp_proto::scopes::ScopeSet;
use hyp_store::kv::KvEntryMetadata;
use hyp_store::{
    Filter, KvEntry, KvEpoch, PeerStatus, Subscription, is_kv_key, is_kv_namespace, now_ms,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{AuthenticatedPeer, NodeError, UnifiedNode};

const MAX_NAMESPACES: usize = 32;
const MAX_SNAPSHOT_ENTRIES_PER_NAMESPACE: usize = 4;
const ENTRY_SCAN_PAGE: u32 = 128;
const MAX_INSPECT_PEERS: usize = 8;
const PEER_INSPECT_TIMEOUT: Duration = Duration::from_millis(1200);

struct KvReader<'a> {
    node_id: &'a str,
    encryption_kid: Option<String>,
    scopes: Option<&'a ScopeSet>,
}

impl KvReader<'_> {
    fn may_read_namespace(&self, namespace: &str) -> bool {
        self.scopes
            .is_none_or(|scopes| scopes.may_kv_read_namespace(namespace))
    }

    fn may_read_key(&self, namespace: &str, key: &str) -> bool {
        self.scopes
            .is_none_or(|scopes| scopes.may_kv_read(namespace, key))
    }
}

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
        self.inspect_hosted_kv(&self.local_kv_reader(), now_ms)
    }

    pub(in crate::engine) fn inspect_hosted_kv_for_peer(
        &self,
        caller: &AuthenticatedPeer,
        now_ms: i64,
    ) -> Result<KvInspection, NodeError> {
        self.inspect_hosted_kv(&self.peer_kv_reader(caller)?, now_ms)
    }

    /// Fetches metadata from active peers for an explicit inspection request.
    pub async fn inspect_kv(&self, now_ms: i64) -> Result<KvInspection, NodeError> {
        let mut inspection = self.inspect_local_kv(now_ms)?;
        let links = self.peer_links.read().await;
        let peers: Vec<_> = self
            .db()
            .peers()
            .list_peers(Some(PeerStatus::Active))?
            .into_iter()
            .filter_map(|peer| links.get(&peer.peer_id).cloned())
            .collect();
        drop(links);
        inspection.namespaces_truncated |= peers.len() > MAX_INSPECT_PEERS;
        let mut tasks = tokio::task::JoinSet::new();
        for peer in peers.into_iter().take(MAX_INSPECT_PEERS) {
            tasks.spawn(async move {
                let result = tokio::time::timeout(PEER_INSPECT_TIMEOUT, peer.kv_inspect()).await;
                match result {
                    Ok(Ok(report)) => Some((peer.peer_id().to_owned(), report)),
                    _ => None,
                }
            });
        }
        let mut reports = BTreeMap::new();
        while let Some(result) = tasks.join_next().await {
            if let Ok(Some((peer_id, report))) = result {
                reports.insert(peer_id, report);
            }
        }
        for (peer_id, report) in reports {
            inspection.namespaces_truncated |= report.namespaces_truncated;
            let mut names = BTreeSet::new();
            for mut namespace in report.namespaces {
                if namespace.origin_node != peer_id
                    || !is_kv_namespace(&namespace.name)
                    || !names.insert(namespace.name.clone())
                {
                    continue;
                }
                if inspection.namespaces.len() >= MAX_NAMESPACES {
                    inspection.namespaces_truncated = true;
                    break;
                }
                namespace.entries.retain(|entry| is_kv_key(&entry.key));
                namespace
                    .entries
                    .truncate(MAX_SNAPSHOT_ENTRIES_PER_NAMESPACE);
                inspection.namespaces.push(namespace);
            }
        }
        Ok(inspection)
    }

    fn inspect_hosted_kv(
        &self,
        reader: &KvReader<'_>,
        now_ms: i64,
    ) -> Result<KvInspection, NodeError> {
        let host = self.config.node_id.as_str();
        let (names, watches) = {
            let db = self.db();
            let local = reader.scopes.is_none();
            let names = if local {
                db.kv().list_namespaces(host, now_ms)?
            } else {
                Vec::new()
            };
            let watches = db
                .events()
                .list_subscriptions((!local).then_some(reader.node_id))?;
            (names, watches)
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
            .filter(|namespace| reader.may_read_namespace(namespace))
            .collect();
        let mut namespaces = Vec::new();
        for name in names {
            let Some(access) = self.kv_namespace_access(reader, name)? else {
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
                    if !reader.may_read_key(name, &entry.key) {
                        continue;
                    }
                    let access_key = (
                        entry.content_type == CONTENT_TYPE_E2EE_JSON,
                        entry.e2ee_epoch,
                    );
                    let visible = if let Some(visible) = epoch_access.get(&access_key) {
                        *visible
                    } else {
                        let visible = self.kv_entry_visible(
                            reader,
                            name,
                            &access,
                            access_key.0,
                            access_key.1,
                        )?;
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
    pub async fn preview_kv(
        &self,
        origin: &str,
        namespace: &str,
        key: &str,
    ) -> Result<Option<KvValuePreview>, NodeError> {
        if !is_kv_namespace(namespace) || !is_kv_key(key) {
            return Err(NodeError::BadRequest("invalid KV namespace or key".into()));
        }
        let local = origin == self.config.node_id.as_str() || origin == "local";
        let link = if local {
            None
        } else {
            Some(self.require_peer_link(origin).await?)
        };
        let entry = if let Some(link) = &link {
            link.kv_preview(namespace, key).await?
        } else {
            self.read_hosted_kv(&self.local_kv_reader(), namespace, key)?
        };
        let Some(entry) = entry else {
            return Ok(None);
        };
        let host = if local {
            self.config.node_id.as_str()
        } else {
            origin
        };
        if entry.host_node != host || entry.namespace != namespace || entry.key != key {
            return Err(NodeError::BadRequest(
                "KV preview entry does not match its request".into(),
            ));
        }
        let entry = self
            .maybe_decrypt_kv_entry(host, entry, link.as_ref())
            .await?;
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

    pub(in crate::engine) fn read_hosted_kv_for_peer(
        &self,
        caller: &AuthenticatedPeer,
        namespace: &str,
        key: &str,
    ) -> Result<Option<KvEntry>, NodeError> {
        if !is_kv_namespace(namespace) || !is_kv_key(key) {
            return Err(NodeError::BadRequest("invalid KV namespace or key".into()));
        }
        self.read_hosted_kv(&self.peer_kv_reader(caller)?, namespace, key)
    }

    fn read_hosted_kv(
        &self,
        reader: &KvReader<'_>,
        namespace: &str,
        key: &str,
    ) -> Result<Option<KvEntry>, NodeError> {
        if !reader.may_read_key(namespace, key)
            || (reader.scopes.is_some()
                && !self
                    .config
                    .kv_namespaces
                    .iter()
                    .any(|cfg| cfg.name == namespace))
        {
            return Ok(None);
        }
        let Some(access) = self.kv_namespace_access(reader, namespace)? else {
            return Ok(None);
        };
        let entry = self
            .db()
            .kv()
            .get(self.config.node_id.as_str(), namespace, key, now_ms())?;
        let Some(entry) = entry else {
            return Ok(None);
        };
        Ok(self
            .kv_entry_visible(
                reader,
                namespace,
                &access,
                entry.content_type == CONTENT_TYPE_E2EE_JSON,
                entry.e2ee_epoch,
            )?
            .then_some(entry))
    }

    fn local_kv_reader(&self) -> KvReader<'_> {
        KvReader {
            node_id: self.config.node_id.as_str(),
            encryption_kid: Some(self.identity.encryption.kid()),
            scopes: None,
        }
    }

    fn peer_kv_reader<'a>(&self, caller: &'a AuthenticatedPeer) -> Result<KvReader<'a>, NodeError> {
        Ok(KvReader {
            node_id: &caller.peer_id,
            encryption_kid: self
                .lookup_peer_encryption_key(&caller.peer_id)?
                .map(|key| key.kid()),
            scopes: Some(&caller.scopes),
        })
    }

    fn kv_namespace_access(
        &self,
        reader: &KvReader<'_>,
        namespace: &str,
    ) -> Result<Option<LocalNamespaceAccess>, NodeError> {
        let host = self.config.node_id.as_str();
        let latest = self.db().kv().latest_epoch(host, namespace)?;
        if let Some(epoch) = latest {
            return Ok(self
                .kv_epoch_member_count(reader, &epoch)?
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

    fn kv_entry_visible(
        &self,
        reader: &KvReader<'_>,
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
                    Some(stored) => Ok(self.kv_epoch_member_count(reader, &stored)?.is_some()),
                    None => Ok(false),
                }
            }
            _ => Ok(false),
        }
    }

    fn kv_epoch_member_count(
        &self,
        reader: &KvReader<'_>,
        epoch: &KvEpoch,
    ) -> Result<Option<usize>, NodeError> {
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
        let Some(kid) = reader.encryption_kid.as_deref() else {
            return Ok(None);
        };
        if !payload
            .wraps
            .iter()
            .any(|wrap| wrap.node_id == reader.node_id && wrap.recipient_kid == kid)
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
