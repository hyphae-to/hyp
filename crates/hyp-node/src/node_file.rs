//! The operator's node.json and legacy connector.json on-disk configuration.

pub mod runtime;

use crate::engine::WakeRecoveryConfig;
use crate::engine::config::ForwardingPolicy;
use crate::engine::{
    DropRelayConfig, EscalationConfig, GuestPairingConfig, KvNamespaceConfig, LocalIngestConfig,
    NodeProfile,
};
use crate::gates::SecurityGateConfig;
use serde::{Deserialize, Deserializer, Serialize, de::DeserializeOwned};
use serde_json::{Map, Value};
use std::{
    collections::HashSet,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
};

/// Fields shared across node startup, CLI commands, and harness transport configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct NodeFile {
    #[serde(deserialize_with = "present_string")]
    node_id: Option<Option<String>>,
    #[serde(deserialize_with = "present_string")]
    connector_id: Option<Option<String>>,
    #[serde(deserialize_with = "lenient")]
    profile: Option<String>,
    #[serde(deserialize_with = "lenient_object")]
    listen: Option<Listen>,
    #[serde(deserialize_with = "lenient")]
    bind: Option<String>,
    #[serde(deserialize_with = "lenient_object")]
    local_router: Option<LegacyLocalRouter>,
    #[serde(deserialize_with = "lenient")]
    state_dir: Option<PathBuf>,
    #[serde(deserialize_with = "lenient_object")]
    policy: Option<Policy>,
    #[serde(deserialize_with = "lenient_object")]
    update: Option<Update>,
    #[serde(deserialize_with = "lenient_object")]
    pub t3: Option<T3File>,
    #[serde(deserialize_with = "lenient_object")]
    pub openclaw: Option<OpenClawFile>,
    // Section errors are deferred to consumers so one invalid optional block does not
    // prevent commands from inspecting or repairing the rest of the document.
    #[serde(deserialize_with = "checked_section")]
    pub local_ingest: Option<Result<LocalIngestConfig, String>>,
    #[serde(deserialize_with = "checked_section")]
    pub drop_relay: Option<Result<DropRelayConfig, String>>,
    #[serde(deserialize_with = "checked_section")]
    pub escalation: Option<Result<EscalationConfig, String>>,
    #[serde(deserialize_with = "checked_section")]
    pub gate: Option<Result<SecurityGateConfig, String>>,
    #[serde(deserialize_with = "decode_kv_setting")]
    kv: Option<Result<Option<bool>, &'static str>>,
    #[serde(deserialize_with = "decode_kv_namespaces")]
    kv_namespaces: Option<Result<KvNamespaces, String>>,
    #[serde(deserialize_with = "decode_guest_pairing")]
    guest_pairing: Option<Result<GuestPairingFile, String>>,
    #[serde(deserialize_with = "lenient_object")]
    rate_limits: Option<RateLimits>,
    #[serde(deserialize_with = "lenient_object")]
    delivery: Option<Delivery>,
    #[serde(deserialize_with = "lenient_object")]
    pub pairing: Option<Pairing>,
    #[serde(deserialize_with = "clean_string")]
    pub drop_relay_url: Option<String>,
    #[serde(deserialize_with = "decode_drop_portal")]
    pub drop_portal_url: Option<Result<String, &'static str>>,
    #[serde(deserialize_with = "decode_forwarding")]
    forwarding: Option<Result<ForwardingPolicy, String>>,
    #[serde(deserialize_with = "decode_top_proxies")]
    trusted_proxies: Option<Result<Vec<String>, String>>,
    #[serde(deserialize_with = "nullable_section")]
    behind_reverse_proxy: Option<Result<bool, String>>,
    #[serde(deserialize_with = "decode_wake_recovery")]
    wake_recovery: Option<Result<WakeRecoveryConfig, String>>,
    #[serde(deserialize_with = "decode_sources")]
    sources: Option<Result<Vec<SourceFile>, String>>,
    #[serde(deserialize_with = "lenient")]
    pub public_read_only: Option<bool>,
    #[serde(deserialize_with = "present_value")]
    delivery_retry: Option<Value>,
    #[serde(rename = "topics", deserialize_with = "decode_topic_names")]
    pub explicit_topics: HashSet<String>,
    #[serde(deserialize_with = "decode_plugins")]
    pub plugins: Option<PluginEntries>,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Listen {
    #[serde(deserialize_with = "lenient")]
    bind: Option<String>,
    #[serde(deserialize_with = "lenient")]
    public_url: Option<String>,
    #[serde(deserialize_with = "decode_listen_proxies")]
    trusted_proxies: Option<Result<Vec<String>, String>>,
    #[serde(deserialize_with = "nullable_section")]
    behind_reverse_proxy: Option<Result<bool, String>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct LegacyLocalRouter {
    #[serde(deserialize_with = "lenient")]
    host: Option<String>,
    #[serde(deserialize_with = "lenient")]
    port: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Policy {
    #[serde(deserialize_with = "lenient")]
    require_e2ee: Option<bool>,
    #[serde(deserialize_with = "lenient")]
    require_pairing: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
struct Update {
    #[serde(deserialize_with = "lenient")]
    channel: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct T3File {
    #[serde(deserialize_with = "clean_string")]
    pub url: Option<String>,
    #[serde(deserialize_with = "clean_string")]
    pub base_dir: Option<PathBuf>,
    #[serde(deserialize_with = "clean_string")]
    pub token_secret: Option<String>,
    #[serde(deserialize_with = "lenient")]
    pub allow_remote: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct OpenClawFile {
    #[serde(deserialize_with = "lenient")]
    pub enabled: Option<bool>,
    #[serde(deserialize_with = "clean_string")]
    pub delivery_mode: Option<String>,
    #[serde(deserialize_with = "clean_string")]
    pub url: Option<String>,
    #[serde(deserialize_with = "clean_string")]
    pub hooks_path: Option<String>,
    #[serde(deserialize_with = "clean_string")]
    pub agent_id: Option<String>,
    #[serde(deserialize_with = "clean_string")]
    pub mode: Option<String>,
    #[serde(deserialize_with = "clean_string")]
    pub token_secret: Option<String>,
    #[serde(deserialize_with = "lenient")]
    pub allow_remote: Option<bool>,
}

fn clean_string<'de, D: Deserializer<'de>, T: From<String>>(de: D) -> Result<Option<T>, D::Error> {
    let value: Option<String> = lenient(de)?;
    Ok(value
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| T::from(s.to_owned())))
}

/// Reads the explicit agent-facing KV tool setting. Missing values use capability discovery.
pub fn kv_tool_override(kv: Option<&Value>) -> Result<Option<bool>, &'static str> {
    match kv {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(enabled)) => Ok(Some(*enabled)),
        Some(Value::Object(kv)) => match kv.get("enabled") {
            None => Ok(None),
            Some(Value::Bool(enabled)) => Ok(Some(*enabled)),
            _ => Err("kv.enabled must be a boolean"),
        },
        _ => Err("kv must be a boolean or an object with an enabled boolean"),
    }
}

fn decode_kv_setting<'de, D: Deserializer<'de>>(
    de: D,
) -> Result<Option<Result<Option<bool>, &'static str>>, D::Error> {
    let value = Value::deserialize(de)?;
    Ok(Some(kv_tool_override(Some(&value))))
}

#[derive(Debug, Clone)]
struct KvNamespaces {
    entries: Vec<KvNamespaceConfig>,
    warnings: Vec<String>,
}

fn decode_kv_namespaces<'de, D: Deserializer<'de>>(
    de: D,
) -> Result<Option<Result<KvNamespaces, String>>, D::Error> {
    let value = Value::deserialize(de)?;
    let mut warnings = Vec::new();
    let namespaces = runtime::parse_kv_namespaces(&value, &mut warnings)
        .map(|entries| KvNamespaces { entries, warnings });
    Ok(Some(namespaces))
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct GuestPairingFile {
    #[serde(deserialize_with = "lenient")]
    enabled: Option<bool>,
    #[serde(deserialize_with = "lenient")]
    max_repos_per_guest: Option<u64>,
    #[serde(deserialize_with = "lenient")]
    max_batches_per_hour: Option<u64>,
    #[serde(deserialize_with = "lenient")]
    max_joins_per_minute: Option<u64>,
    #[serde(deserialize_with = "present_value")]
    scopes: Option<Value>,
}

fn decode_guest_pairing<'de, D: Deserializer<'de>>(
    de: D,
) -> Result<Option<Result<GuestPairingFile, String>>, D::Error> {
    let value = Value::deserialize(de)?;
    let config = if value.is_object() {
        GuestPairingFile::deserialize(value).map_err(|err| err.to_string())
    } else {
        Err("guestPairing must be a JSON object".to_owned())
    };
    Ok(Some(config))
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct RateLimits {
    #[serde(deserialize_with = "lenient")]
    guest_join_requests_per_minute: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Delivery {
    #[serde(deserialize_with = "checked_section")]
    midturn_queue_digest_seconds: Option<Result<u64, String>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct Pairing {
    pub admin_key: Option<Value>,
}

fn present_value<'de, D: Deserializer<'de>>(de: D) -> Result<Option<Value>, D::Error> {
    Value::deserialize(de).map(Some)
}

fn decode_drop_portal<'de, D: Deserializer<'de>>(
    de: D,
) -> Result<Option<Result<String, &'static str>>, D::Error> {
    let value = Value::deserialize(de)?;
    Ok(match value {
        Value::Null => None,
        Value::String(url) => Some(Ok(url)),
        _ => Some(Err("must be a string")),
    })
}

fn decode_forwarding<'de, D: Deserializer<'de>>(
    de: D,
) -> Result<Option<Result<ForwardingPolicy, String>>, D::Error> {
    let value = Value::deserialize(de)?;
    Ok((!value.is_null()).then(|| runtime::decode_forwarding(value)))
}

fn decode_top_proxies<'de, D: Deserializer<'de>>(
    de: D,
) -> Result<Option<Result<Vec<String>, String>>, D::Error> {
    decode_proxies(de, "trustedProxies")
}

fn decode_listen_proxies<'de, D: Deserializer<'de>>(
    de: D,
) -> Result<Option<Result<Vec<String>, String>>, D::Error> {
    decode_proxies(de, "listen.trustedProxies")
}

fn decode_proxies<'de, D: Deserializer<'de>>(
    de: D,
    field: &str,
) -> Result<Option<Result<Vec<String>, String>>, D::Error> {
    let value = Value::deserialize(de)?;
    Ok((!value.is_null()).then(|| runtime::parse_trusted_proxies_array(&value, field)))
}

fn nullable_section<'de, D: Deserializer<'de>, T: DeserializeOwned>(
    de: D,
) -> Result<Option<Result<T, String>>, D::Error> {
    let value = Value::deserialize(de)?;
    Ok((!value.is_null()).then(|| serde_json::from_value(value).map_err(|err| err.to_string())))
}

fn decode_wake_recovery<'de, D: Deserializer<'de>>(
    de: D,
) -> Result<Option<Result<WakeRecoveryConfig, String>>, D::Error> {
    let value = Value::deserialize(de)?;
    Ok(Some(runtime::parse_wake_recovery(&value)))
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct SourceFile {
    #[serde(deserialize_with = "lenient")]
    kind: Option<String>,
    #[serde(deserialize_with = "lenient")]
    enabled: Option<bool>,
    #[serde(deserialize_with = "lenient")]
    id: Option<String>,
    #[serde(deserialize_with = "clean_string")]
    topic: Option<String>,
    #[serde(deserialize_with = "present_value")]
    expose_topic: Option<Value>,
    #[serde(deserialize_with = "clean_string")]
    api_base_url: Option<String>,
    #[serde(deserialize_with = "lenient")]
    min_poll_interval_seconds: Option<u64>,
    #[serde(deserialize_with = "lenient")]
    base_poll_interval_seconds: Option<u64>,
    #[serde(deserialize_with = "lenient")]
    grace_window_seconds: Option<u64>,
    #[serde(deserialize_with = "nullable_section")]
    max_active_pollers: Option<Result<u64, String>>,
    #[serde(deserialize_with = "lenient")]
    allow_private_with_token: Option<bool>,
    github_token: Option<Value>,
    repo_tokens: Option<Value>,
    #[serde(deserialize_with = "present_value")]
    secret: Option<Value>,
    #[serde(deserialize_with = "present_value")]
    webhook_secret: Option<Value>,
    #[serde(deserialize_with = "nullable_section")]
    allowed_repos: Option<Result<Vec<Value>, String>>,
    #[serde(deserialize_with = "nullable_section")]
    allowed_orgs: Option<Result<Vec<Value>, String>>,
    #[serde(deserialize_with = "lenient")]
    max_body_bytes: Option<u64>,
    #[serde(flatten)]
    extra: Map<String, Value>,
}

fn decode_sources<'de, D: Deserializer<'de>>(
    de: D,
) -> Result<Option<Result<Vec<SourceFile>, String>>, D::Error> {
    let value = Value::deserialize(de)?;
    let entries = match value {
        Value::Array(entries) => entries
            .into_iter()
            .filter(Value::is_object)
            .map(|entry| SourceFile::deserialize(entry).map_err(|err| err.to_string()))
            .collect(),
        _ => Err("sources must be a JSON array".to_string()),
    };
    Ok(Some(entries))
}

// Invalid entries are retained so startup can report their original array index.
pub type PluginEntries = Result<Vec<Option<PluginFile>>, String>;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct PluginFile {
    #[serde(deserialize_with = "lenient")]
    pub enabled: Option<bool>,
    #[serde(deserialize_with = "clean_string")]
    pub id: Option<String>,
    pub kind: Option<Value>,
    #[serde(deserialize_with = "nullable_section")]
    pub exec: Option<Result<String, String>>,
    #[serde(deserialize_with = "nullable_section")]
    pub command: Option<Result<String, String>>,
    #[serde(deserialize_with = "nullable_section")]
    pub cwd: Option<Result<String, String>>,
    #[serde(deserialize_with = "nullable_section")]
    pub args: Option<Result<Vec<Value>, String>>,
    #[serde(deserialize_with = "nullable_section")]
    pub targets: Option<Result<Vec<Value>, String>>,
    #[serde(deserialize_with = "nullable_section")]
    pub env: Option<Result<Map<String, Value>, String>>,
    #[serde(deserialize_with = "nullable_section")]
    pub expose_topic: Option<Result<bool, String>>,
}

fn decode_plugins<'de, D: Deserializer<'de>>(de: D) -> Result<Option<PluginEntries>, D::Error> {
    let value = Value::deserialize(de)?;
    if value.is_null() {
        return Ok(None);
    }
    Ok(Some(match value {
        Value::Array(entries) => Ok(entries
            .into_iter()
            .map(|entry| {
                if !entry.is_object() {
                    return None;
                }
                PluginFile::deserialize(entry).ok()
            })
            .collect()),
        _ => Err("plugins must be a JSON array".to_string()),
    }))
}

fn decode_topic_names<'de, D: Deserializer<'de>>(de: D) -> Result<HashSet<String>, D::Error> {
    let value = Value::deserialize(de)?;
    Ok(value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            entry
                .as_str()
                .or_else(|| entry.get("topic").and_then(Value::as_str))
        })
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .map(str::to_ascii_lowercase)
        .collect())
}

fn checked_section<'de, D: Deserializer<'de>, T: DeserializeOwned>(
    de: D,
) -> Result<Option<Result<T, String>>, D::Error> {
    let value = Value::deserialize(de)?;
    Ok(Some(
        serde_json::from_value(value).map_err(|err| err.to_string()),
    ))
}

// Earlier versions ignore values of the wrong type for these fields.
fn lenient<'de, D: Deserializer<'de>, T: DeserializeOwned>(de: D) -> Result<Option<T>, D::Error> {
    Ok(serde_json::from_value(Value::deserialize(de)?).ok())
}

fn lenient_object<'de, D: Deserializer<'de>, T: DeserializeOwned>(
    de: D,
) -> Result<Option<T>, D::Error> {
    let value = Value::deserialize(de)?;
    Ok(value
        .is_object()
        .then(|| serde_json::from_value(value).ok())
        .flatten())
}

// A present nodeId suppresses connectorId fallback even if its value has the wrong type.
fn present_string<'de, D: Deserializer<'de>>(de: D) -> Result<Option<Option<String>>, D::Error> {
    lenient(de).map(Some)
}

/// Tier 3 bounded `Hold` retry backoff and opt-in Tier 4 cold-revival configuration
/// for the local daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryRetryConfig {
    pub hold_retry_backoff_ms: Vec<u64>,
    pub hold_retry_max_attempts: u32,
    pub codex_resume: bool,
    pub herdr_spawn_allowlist: Vec<String>,
}

impl Default for DeliveryRetryConfig {
    fn default() -> Self {
        Self {
            hold_retry_backoff_ms: vec![5_000, 15_000, 30_000, 60_000],
            hold_retry_max_attempts: 6,
            codex_resume: false,
            herdr_spawn_allowlist: Vec::new(),
        }
    }
}

/// Parsed fields normalized from either v2 `node.json` or legacy v1 `connector.json`.
#[derive(Debug, Clone)]
pub struct LoadedNodeFile {
    pub path: PathBuf,
    pub is_legacy_v1: bool,
    pub node_id: Option<String>,
    pub profile: Option<NodeProfile>,
    pub bind_addr: Option<SocketAddr>,
    pub public_url: Option<String>,
    pub state_dir: Option<PathBuf>,
    pub require_e2ee: bool,
    pub require_pairing: bool,
    pub update_channel: Option<String>,
    pub file: NodeFile,
    pub raw: Value,
}

impl NodeFile {
    /// Reads an object without applying startup validation so commands can inspect incomplete files.
    pub fn read(path: &Path) -> Result<(Self, Value), String> {
        let raw = Self::read_document(path)?;
        let file = Self::decode(path, &raw)?;
        Ok((file, raw))
    }

    fn decode(path: &Path, raw: &Value) -> Result<Self, String> {
        if !raw.is_object() {
            return Err(format!(
                "expected top-level JSON object in {}",
                path.display()
            ));
        }
        Self::deserialize(raw)
            .map_err(|e| format!("invalid node configuration in {}: {e}", path.display()))
    }

    /// Reads syntax for callers that inspect even malformed or incomplete configurations.
    pub fn read_document(path: &Path) -> Result<Value, String> {
        let contents = fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        serde_json::from_str(&contents)
            .map_err(|e| format!("invalid JSON in {}: {e}", path.display()))
    }

    /// Reads a document for editing, retaining even unrecognized fields and legacy spellings.
    pub fn read_document_or_empty(path: &Path) -> Result<Map<String, Value>, String> {
        if !path.exists() {
            return Ok(Map::new());
        }
        let (_, raw) = Self::read(path)?;
        match raw {
            Value::Object(map) => Ok(map),
            _ => Err(format!(
                "expected top-level JSON object in {}",
                path.display()
            )),
        }
    }

    /// Writes an edited document without applying validation specific to node startup.
    pub fn write_document(path: &Path, document: Map<String, Value>) -> Result<(), String> {
        let raw = Value::Object(document);
        Self::decode(path, &raw)?;
        crate::atomic_file::write_atomic_json(path, &raw, true)
    }

    pub fn kv_tool_override(&self) -> Result<Option<bool>, &'static str> {
        self.kv.unwrap_or(Ok(None))
    }

    pub fn kv_namespaces(
        &self,
        warnings: &mut Vec<String>,
    ) -> Result<Vec<KvNamespaceConfig>, String> {
        match &self.kv_namespaces {
            None => Ok(Vec::new()),
            Some(Ok(namespaces)) => {
                warnings.extend(namespaces.warnings.iter().cloned());
                Ok(namespaces.entries.clone())
            }
            Some(Err(error)) => Err(error.clone()),
        }
    }

    pub fn guest_pairing(&self) -> Result<GuestPairingConfig, String> {
        let Some(config) = self.guest_pairing.as_ref() else {
            return Ok(GuestPairingConfig::default());
        };
        let config = config.as_ref().map_err(Clone::clone)?;
        let fallback_joins = self
            .rate_limits
            .as_ref()
            .and_then(|limits| limits.guest_join_requests_per_minute);
        config.to_runtime(fallback_joins)
    }

    pub fn midturn_queue_digest_seconds(&self) -> Result<u64, &'static str> {
        match self
            .delivery
            .as_ref()
            .and_then(|d| d.midturn_queue_digest_seconds.as_ref())
        {
            None => Ok(crate::delivery::DEFAULT_MIDTURN_QUEUE_DIGEST_SECONDS),
            Some(Ok(seconds)) => Ok(*seconds),
            Some(Err(_)) => {
                Err("delivery.midturnQueueDigestSeconds must be a non-negative integer")
            }
        }
    }

    pub fn wake_recovery(&self) -> Result<WakeRecoveryConfig, String> {
        self.wake_recovery
            .clone()
            .unwrap_or_else(|| Ok(WakeRecoveryConfig::default()))
    }

    pub fn source_entries(&self) -> Result<Option<&[SourceFile]>, &str> {
        self.sources
            .as_ref()
            .map(|entries| entries.as_ref().map(Vec::as_slice))
            .transpose()
            .map_err(String::as_str)
    }

    /// Collect startup-only privacy rules before reconciling source or topic collisions.
    pub fn native_local_only_topics(&self) -> Result<impl Iterator<Item = &str>, String> {
        let mut topics = Vec::new();
        for source in self.source_entries()?.unwrap_or_default() {
            if source.enabled == Some(false)
                || !matches!(
                    source.kind.as_deref(),
                    Some("github-public" | "github-webhook")
                )
            {
                continue;
            }
            match source.expose_topic.as_ref() {
                None | Some(Value::Bool(true)) => {}
                Some(Value::Bool(false)) => {
                    let topic = source.topic.as_deref().unwrap_or("github");
                    if !hyp_proto::address::is_valid_topic(topic) {
                        return Err(format!("Invalid local-only source topic '{topic}'"));
                    }
                    topics.push(topic);
                    // Store both spellings. Native adapters preserve literal topic names
                    // while topic addressing and catalogs also recognize local.<topic>.
                    if let Some(bare) = topic.strip_prefix("local.") {
                        topics.push(bare);
                    }
                }
                _ => return Err("sources[].exposeTopic must be a boolean".to_string()),
            }
        }
        Ok(topics.into_iter())
    }

    pub fn state_dir(&self, path: &Path) -> Option<PathBuf> {
        let dir = self.state_dir.as_ref()?;
        Some(match path.parent() {
            Some(parent) if dir.is_relative() => parent.join(dir),
            _ => dir.clone(),
        })
    }

    pub fn validate(self, path: &Path, raw: Value) -> Result<LoadedNodeFile, String> {
        let is_legacy_v1 = self.node_id.is_none() && self.connector_id.is_some();
        let state_dir = self.state_dir(path);
        let node_id = self
            .node_id
            .as_ref()
            .or(self.connector_id.as_ref())
            .cloned()
            .flatten();
        let profile = match self.profile.as_deref() {
            Some("local") => Some(NodeProfile::Local),
            Some("router") => Some(NodeProfile::Router),
            Some("p2p") => Some(NodeProfile::P2p),
            Some(other) => {
                return Err(format!(
                    "invalid profile '{other}' in {} (expected local, router, or p2p)",
                    path.display()
                ));
            }
            None if is_legacy_v1 => Some(NodeProfile::Local),
            None => None,
        };
        let bind = self
            .listen
            .as_ref()
            .and_then(|listen| listen.bind.clone())
            .or_else(|| self.bind.clone())
            .or_else(|| {
                let legacy = self.local_router.as_ref()?;
                let host = legacy.host.as_deref().unwrap_or("127.0.0.1");
                let port = legacy.port?;
                Some(format!("{host}:{port}"))
            });
        let bind_addr = bind
            .map(|value| {
                value.parse::<SocketAddr>().map_err(|e| {
                    format!("invalid listen.bind '{value}' in {}: {e}", path.display())
                })
            })
            .transpose()?;
        let policy = self.policy.as_ref().cloned().unwrap_or_default();
        Ok(LoadedNodeFile {
            path: path.to_owned(),
            is_legacy_v1,
            node_id,
            profile,
            bind_addr,
            public_url: self
                .listen
                .as_ref()
                .and_then(|listen| listen.public_url.clone()),
            state_dir,
            require_e2ee: policy.require_e2ee.unwrap_or(true),
            require_pairing: policy.require_pairing.unwrap_or(true),
            update_channel: self
                .update
                .as_ref()
                .and_then(|update| update.channel.clone()),
            file: self,
            raw,
        })
    }
}

/// Loads either v2 node.json or the legacy connector.json format.
pub fn load_node_or_legacy_config(path: &Path) -> Result<LoadedNodeFile, String> {
    let (file, raw) = NodeFile::read(path)?;
    file.validate(path, raw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn native_source_visibility_defaults_to_exposed_and_requires_a_boolean() {
        let file: NodeFile = serde_json::from_value(json!({
            "sources": [
                {"kind": "github-public", "topic": "public-default"},
                {"kind": "github-webhook", "topic": "public-explicit", "exposeTopic": true},
                {"kind": "github-webhook", "exposeTopic": false},
                {"kind": "github-public", "topic": "local.private", "exposeTopic": false},
                {"kind": "github-webhook", "topic": "disabled", "enabled": false, "exposeTopic": false}
            ]
        })).unwrap();
        assert_eq!(
            file.native_local_only_topics().unwrap().collect::<Vec<_>>(),
            ["github", "local.private", "private"],
        );

        for invalid in [json!(null), json!("false"), json!(0)] {
            let file: NodeFile = serde_json::from_value(json!({
                "sources": [{"kind": "github-webhook", "exposeTopic": invalid}]
            }))
            .unwrap();
            assert!(file.native_local_only_topics().is_err());
        }
    }

    #[test]
    fn legacy_wakeup_retry_fields_preserve_precedence_across_spellings() {
        let file: NodeFile = serde_json::from_value(json!({
            "sources": [
                {"kind":"github-public", "holdRetryMaxAttempts":22},
                {"kind":"wakeup", "hold_retry_backoff_ms":[100, 200], "codexResume":true},
                {"kind":"wakeup", "herdr_spawn_allowlist":["old"]}
            ],
            "codex_resume": false,
            "holdRetryMaxAttempts": 8,
            "deliveryRetry": {
                "holdRetryMaxAttempts": 5,
                "hold_retry_max_attempts": 7,
                "holdRetryBackoffMs": [],
                "herdrSpawnAllowlist": ["current"]
            }
        }))
        .unwrap();
        let retry = file.delivery_retry().unwrap();
        assert_eq!(retry.hold_retry_backoff_ms, [100, 200]);
        assert_eq!(retry.hold_retry_max_attempts, 5);
        assert!(!retry.codex_resume);
        assert_eq!(retry.herdr_spawn_allowlist, ["current"]);
    }
}
