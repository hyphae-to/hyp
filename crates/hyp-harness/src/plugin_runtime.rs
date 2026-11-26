//! Supervision and local or federated delivery for configured subprocess plugins.

use crate::daemon::{BoxFuture as DaemonBoxFuture, BridgePoster, LocalDaemon};
use hyp_node::adapters::webhooks::{EXT_SOURCE_KIND, SOURCE_KIND_EXTERNAL_WEBHOOK};
use hyp_node::adapters::{
    AdapterError, AdapterHealth, AdapterKind, BoxFuture as AdapterBoxFuture, NodeAdapter,
    NodeAdapterHost, PublishErrorCode, PublishOutcome, PublishStatus, SubprocessConfig,
    SubprocessSupervisor,
};
use hyp_node::atomic_file::write_atomic_json;
use hyp_node::engine::{NodeConfig, NodeError, TopicConfig, UnifiedNode};
use hyp_proto::address::{LOCAL_NODE_ID, is_valid_topic};
use hyp_proto::cloudevent::CloudEvent as ProtoCloudEvent;
use hyp_proto::rpc::EventKeyRef;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

pub const fn plugin_kind_str(kind: AdapterKind) -> &'static str {
    match kind {
        AdapterKind::Bridge => "bridge",
        AdapterKind::Source => "source",
        AdapterKind::Harness => "harness",
        AdapterKind::PeerLink => "peer_link",
    }
}

pub struct ParsedPlugin {
    pub config: SubprocessConfig,
    pub expose_topic: bool,
    pub has_webhook_post_url: bool,
}

const DEFAULT_PLUGIN_POST_TIMEOUT: Duration = Duration::from_secs(15);
const LOCAL_BRIDGE_DEDUP_CAPACITY: usize = 4096;

/// Bounded local `(source, id)` deduplicator used for local-only bridge plugins so duplicate
/// inbound bridge deliveries return `PublishStatus::Duplicate` without publishing private
/// messages onto remote-subscribable `EventStore` topics.
struct LocalEventDedup {
    order: VecDeque<(String, String)>,
    seen: HashSet<(String, String)>,
}

impl LocalEventDedup {
    fn new() -> Self {
        Self {
            order: VecDeque::new(),
            seen: HashSet::new(),
        }
    }

    fn contains(&self, source: &str, id: &str) -> bool {
        self.seen.contains(&(source.to_string(), id.to_string()))
    }

    /// Returns `true` if `(source, id)` is newly inserted; `false` if already seen.
    fn insert(&mut self, source: String, id: String) -> bool {
        let key = (source, id);
        if !self.seen.insert(key.clone()) {
            return false;
        }
        self.order.push_back(key);
        while self.order.len() > LOCAL_BRIDGE_DEDUP_CAPACITY {
            if let Some(evicted) = self.order.pop_front() {
                self.seen.remove(&evicted);
            }
        }
        true
    }
}

/// Shared live plugin status registry wired into `NodePluginHost::update_status` so health
/// transitions, restart counts, crash loops, and redacted `lastError` values immediately
/// update `node.status.json` for `hyp status` and `hyp doctor`.
pub struct PluginStatusRegistry {
    entries: Mutex<Vec<Value>>,
    status_doc: Arc<Mutex<Option<(PathBuf, Value)>>>,
}

struct PluginHealthUpdate<'a> {
    plugin_id: &'a str,
    kind: AdapterKind,
    targets: &'a [String],
    health: &'a AdapterHealth,
    restarts: u64,
    crash_loop_backoff: bool,
    log_path: Option<&'a PathBuf>,
}

impl PluginStatusRegistry {
    fn new(initial_entries: Vec<Value>, status_doc: Arc<Mutex<Option<(PathBuf, Value)>>>) -> Self {
        Self {
            entries: Mutex::new(initial_entries),
            status_doc,
        }
    }

    pub fn snapshot(&self) -> Vec<Value> {
        self.entries
            .lock()
            .expect("plugin status registry lock poisoned")
            .clone()
    }

    pub fn flush_to_status_doc(&self) {
        let latest = self.snapshot();
        let mut guard = self.status_doc.lock().expect("status_doc lock poisoned");
        if let Some((ref path, ref mut doc)) = *guard {
            if let Some(obj) = doc.as_object_mut() {
                obj.insert("plugins".to_string(), Value::Array(latest));
            }
            let _ = write_atomic_json(path, doc, true);
        }
    }

    fn upsert_entry(&self, entry: Value) {
        let entry_id = entry
            .get("id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned);
        {
            let mut entries = self
                .entries
                .lock()
                .expect("plugin status registry lock poisoned");
            if let Some(ref id) = entry_id {
                if let Some(existing) = entries
                    .iter_mut()
                    .find(|e| e.get("id").and_then(Value::as_str) == Some(id.as_str()))
                {
                    *existing = entry;
                } else {
                    entries.push(entry);
                }
            } else {
                entries.push(entry);
            }
        }
        self.flush_to_status_doc();
    }

    fn update_health(&self, update: PluginHealthUpdate<'_>) {
        let (status_str, last_error) = match update.health {
            AdapterHealth::Starting => ("starting", None),
            AdapterHealth::Healthy => ("running", None),
            AdapterHealth::Degraded(reason) => (
                if update.crash_loop_backoff {
                    "crash_loop_backoff"
                } else {
                    "degraded"
                },
                Some(reason.as_str()),
            ),
            AdapterHealth::Stopped => ("stopped", None),
        };
        let mut map = serde_json::Map::new();
        map.insert("id".to_string(), json!(update.plugin_id));
        map.insert("kind".to_string(), json!(plugin_kind_str(update.kind)));
        map.insert("targets".to_string(), json!(update.targets));
        map.insert("status".to_string(), json!(status_str));
        map.insert("restarts".to_string(), json!(update.restarts));
        if let Some(err) = last_error {
            map.insert("lastError".to_string(), json!(err));
            map.insert("error".to_string(), json!(err));
        }
        if let Some(lp) = update.log_path {
            map.insert("logPath".to_string(), json!(lp.display().to_string()));
        }
        self.upsert_entry(Value::Object(map));
    }
}

struct NodePluginHost {
    plugin_id: String,
    kind: AdapterKind,
    targets: Vec<String>,
    expose_topic: bool,
    node: Weak<UnifiedNode>,
    daemon: Option<Weak<LocalDaemon>>,
    supervisor: Weak<SubprocessSupervisor>,
    registry: Arc<PluginStatusRegistry>,
    local_dedup: Mutex<LocalEventDedup>,
}

impl NodeAdapterHost for NodePluginHost {
    fn publish_event<'a>(
        &'a self,
        to: &'a str,
        event: ProtoCloudEvent,
    ) -> AdapterBoxFuture<'a, Result<PublishOutcome, AdapterError>> {
        Box::pin(async move {
            // Keep private local chat bridge messages strictly local-only unless the user
            // explicitly exposed the bridge topic in `node.json` (`topics[]` or `exposeTopic: true`).
            if self.kind == AdapterKind::Bridge && !self.expose_topic {
                let already_seen = self
                    .local_dedup
                    .lock()
                    .expect("local bridge dedup lock poisoned")
                    .contains(&event.source, &event.id);
                if already_seen {
                    return Ok(PublishOutcome {
                        status: PublishStatus::Duplicate,
                        matched: 0,
                    });
                }
                let Some(daemon) = self.daemon.as_ref().and_then(Weak::upgrade) else {
                    return Err(AdapterError::PublishFailed {
                        code: PublishErrorCode::Unavailable,
                        message: format!(
                            "local daemon unavailable for bridge '{}:{}'",
                            self.plugin_id, to
                        ),
                    });
                };
                let rendered = render_bridge_cloudevent(&event);
                let delivered = daemon
                    .deliver_bridge_inbound(&self.plugin_id, to, &event.id, &rendered)
                    .await
                    .map_err(|err| AdapterError::PublishFailed {
                        code: PublishErrorCode::Unavailable,
                        message: format!(
                            "bridge inbound delivery failed for '{}:{}': {err}",
                            self.plugin_id, to
                        ),
                    })?;
                if delivered == 0 {
                    return Err(AdapterError::PublishFailed {
                        code: PublishErrorCode::Unavailable,
                        message: format!(
                            "no local session is linked to bridge '{}:{}'; refusing to drop inbound message",
                            self.plugin_id, to
                        ),
                    });
                }
                self.local_dedup
                    .lock()
                    .expect("local bridge dedup lock poisoned")
                    .insert(event.source.clone(), event.id.clone());
                return Ok(PublishOutcome {
                    status: PublishStatus::Stored,
                    matched: delivered,
                });
            }

            let Some(node) = self.node.upgrade() else {
                return Err(AdapterError::NotRunning("unified-node".to_string()));
            };

            let mut event = event;
            if self.kind == AdapterKind::Source {
                // Issue #38: Enforce `hyphaesourcekind = "external-webhook"` server-side on
                // every CloudEvent emitted by a subprocess `kind: "source"` plugin (overwriting
                // any missing or forged value) so Security Gate ALWAYS caps trust tier to
                // `GateTrustTier::ExternalWebhook` (including across Hub fan-out).
                event.set_extension(EXT_SOURCE_KIND, SOURCE_KIND_EXTERNAL_WEBHOOK);
            }

            let topic = match self.kind {
                AdapterKind::Bridge => self.plugin_id.as_str(),
                _ => {
                    if is_valid_topic(to) {
                        to
                    } else {
                        self.plugin_id.as_str()
                    }
                }
            };
            let qualified = format!("{LOCAL_NODE_ID}.{topic}");
            let res = node
                .publish_event(&qualified, event.clone())
                .await
                .map_err(|err| {
                    let code = match &err {
                        NodeError::PayloadTooLarge(_) => PublishErrorCode::TooLarge,
                        NodeError::CloudEvent(_) | NodeError::BadRequest(_) => {
                            PublishErrorCode::InvalidEvent
                        }
                        NodeError::Conflict(_) => PublishErrorCode::IdConflict,
                        _ => PublishErrorCode::Unavailable,
                    };
                    AdapterError::PublishFailed {
                        code,
                        message: err.to_string(),
                    }
                })?;

            let mut matched = res.matched;
            // Issue #39 (B1): Hand freshly stored subprocess source events to matching
            // same-node session mailboxes immediately (`coalesceSeconds: 0` + backlog drain),
            // matching compiled-in adapters and `LocalIngestServer`.
            if !res.deduplicated && res.matched > 0 && self.kind == AdapterKind::Source {
                if let Err(err) =
                    hyp_node::adapters::deliver_source_topic_to_local_sessions(&node, topic)
                {
                    eprintln!(
                        "WARN  plugin '{}' event stored but local delivery on topic '{topic}' failed: {err}",
                        self.plugin_id
                    );
                }
            }
            if !res.deduplicated && self.kind == AdapterKind::Bridge {
                if let Some(daemon) = self.daemon.as_ref().and_then(Weak::upgrade) {
                    let rendered = render_bridge_cloudevent(&event);
                    if let Ok(delivered) = daemon
                        .deliver_bridge_inbound(&self.plugin_id, to, &event.id, &rendered)
                        .await
                    {
                        matched = matched.saturating_add(delivered);
                    }
                }
            }

            let status = if res.deduplicated {
                PublishStatus::Duplicate
            } else {
                PublishStatus::Stored
            };
            Ok(PublishOutcome { status, matched })
        })
    }

    fn update_status<'a>(
        &'a self,
        _adapter_id: &'a str,
        health: AdapterHealth,
    ) -> AdapterBoxFuture<'a, ()> {
        Box::pin(async move {
            let (restarts, crash_loop_backoff, log_path) = match self.supervisor.upgrade() {
                Some(sup) => (
                    sup.restart_count(),
                    sup.is_crash_loop_backoff(),
                    sup.stderr_log_path(),
                ),
                None => (0, false, None),
            };
            self.registry.update_health(PluginHealthUpdate {
                plugin_id: &self.plugin_id,
                kind: self.kind,
                targets: &self.targets,
                health: &health,
                restarts,
                crash_loop_backoff,
                log_path: log_path.as_ref(),
            });
        })
    }

    fn report_delivery_failed<'a>(
        &'a self,
        adapter_id: &'a str,
        target: &'a str,
        events: Vec<EventKeyRef>,
        reason: &'a str,
    ) -> AdapterBoxFuture<'a, ()> {
        Box::pin(async move {
            eprintln!(
                "WARN  plugin '{adapter_id}' delivery_failed target={target} count={} reason={reason}",
                events.len()
            );
        })
    }
}

struct SupervisorBridgePoster {
    supervisor: Arc<SubprocessSupervisor>,
}

impl BridgePoster for SupervisorBridgePoster {
    fn post<'a>(
        &'a self,
        _plugin: &'a str,
        target: &'a str,
        text: &'a str,
        meta: &'a Map<String, Value>,
    ) -> DaemonBoxFuture<'a, Result<Value, (String, String)>> {
        Box::pin(async move {
            let mut params: BTreeMap<String, Value> = BTreeMap::new();
            for (k, v) in meta {
                if k != "text" {
                    params.insert(k.clone(), v.clone());
                }
            }
            params.insert("text".to_string(), Value::String(text.to_string()));
            self.supervisor
                .post(target, params, DEFAULT_PLUGIN_POST_TIMEOUT)
                .await
                .map_err(|err| match err {
                    AdapterError::NotRunning(m) => ("plugin_not_running".to_string(), m),
                    AdapterError::Timeout(m) => ("plugin_timeout".to_string(), m),
                    AdapterError::RequestFailed(m) => ("plugin_post_failed".to_string(), m),
                    other => ("plugin_error".to_string(), other.to_string()),
                })
        })
    }
}

/// Renders an inbound bridge CloudEvent body without repeating `[plugin:target]`
/// (which the delivery packer already puts in the `[hyphae · plugin:target]` header).
fn render_bridge_cloudevent(event: &ProtoCloudEvent) -> String {
    let obj = event.data.as_ref().and_then(Value::as_object);
    let msg_ref = obj
        .and_then(|o| o.get("message_id"))
        .and_then(|v| match v {
            Value::Number(n) => Some(format!("#{n}")),
            Value::String(s) if !s.trim().is_empty() => Some(format!("#{}", s.trim())),
            _ => None,
        })
        .or_else(|| {
            event.subject.as_deref().and_then(|subj| {
                let trimmed = subj.trim();
                if trimmed.is_empty() {
                    return None;
                }
                match trimmed.rsplit_once('/') {
                    Some((_, tail)) if !tail.is_empty() => Some(format!("#{tail}")),
                    _ => Some(trimmed.to_string()),
                }
            })
        });

    if let Some(obj) = obj {
        if let Some(text) = obj.get("text").and_then(Value::as_str) {
            let sender = obj
                .get("from_username")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|u| format!("@{}", u.trim_start_matches('@')))
                .or_else(|| {
                    obj.get("from_name")
                        .or_else(|| obj.get("from"))
                        .or_else(|| obj.get("sender"))
                        .or_else(|| obj.get("author"))
                        .or_else(|| obj.get("user"))
                        .and_then(Value::as_str)
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(ToString::to_string)
                });

            return match (sender, msg_ref) {
                (Some(s), Some(m)) => format!("{s} ({m}): {text}"),
                (Some(s), None) => format!("{s}: {text}"),
                (None, Some(m)) => format!("({m}) {text}"),
                (None, None) => text.to_string(),
            };
        }
    }

    if let Some(ref data) = event.data {
        if let Some(s) = data.as_str() {
            return match msg_ref {
                Some(m) => format!("({m}) {s}"),
                None => s.to_string(),
            };
        }
        if let Ok(compact) = serde_json::to_string(data) {
            return match msg_ref {
                Some(m) => format!("({m}) {compact}"),
                None => compact,
            };
        }
    }
    match msg_ref {
        Some(m) => format!("({m}) {} ({})", event.event_type, event.source),
        None => format!("{} ({})", event.event_type, event.source),
    }
}

pub async fn start_plugins(
    plugins: Vec<ParsedPlugin>,
    skipped_statuses: Vec<Value>,
    status_doc: Arc<Mutex<Option<(PathBuf, Value)>>>,
    node: &Arc<UnifiedNode>,
    local_daemon: Option<&Arc<LocalDaemon>>,
    startup_warnings: &mut Vec<String>,
) -> (Vec<Arc<SubprocessSupervisor>>, Arc<PluginStatusRegistry>) {
    let registry = Arc::new(PluginStatusRegistry::new(skipped_statuses, status_doc));
    let mut started: Vec<Arc<SubprocessSupervisor>> = Vec::with_capacity(plugins.len());

    for parsed in plugins {
        let cfg = parsed.config;
        let plugin_id = cfg.id.clone();
        let kind = cfg.kind;
        let targets = cfg.targets.clone();
        let log_path = cfg.stderr_log_path.clone();
        let sup = Arc::new(SubprocessSupervisor::new(cfg));
        let host: Arc<dyn NodeAdapterHost> = Arc::new(NodePluginHost {
            plugin_id: plugin_id.clone(),
            kind,
            targets: targets.clone(),
            expose_topic: parsed.expose_topic,
            node: Arc::downgrade(node),
            daemon: local_daemon.map(Arc::downgrade),
            supervisor: Arc::downgrade(&sup),
            registry: Arc::clone(&registry),
            local_dedup: Mutex::new(LocalEventDedup::new()),
        });

        if let Err(err) = sup.start(host).await {
            startup_warnings.push(format!(
                "Plugin '{plugin_id}' failed to start and was skipped (daemon continuing): {err}"
            ));
            registry.upsert_entry(json!({
                "id": plugin_id,
                "kind": plugin_kind_str(kind),
                "targets": targets,
                "status": "failed",
                "restarts": 0,
                "error": err.to_string(),
                "lastError": err.to_string(),
                "logPath": log_path.map(|p| p.display().to_string()),
            }));
            continue;
        }

        let register_poster =
            kind == AdapterKind::Bridge || (plugin_id == "webhook" && parsed.has_webhook_post_url);
        if register_poster {
            if let Some(daemon) = local_daemon {
                daemon.register_bridge_poster_with_targets(
                    &plugin_id,
                    targets.clone(),
                    Arc::new(SupervisorBridgePoster {
                        supervisor: Arc::clone(&sup),
                    }),
                );
            } else {
                startup_warnings.push(format!(
                    "Bridge plugin '{plugin_id}' started without local IPC socket; local sessions require local socket."
                ));
            }
        }

        let live_health = sup.health();
        let live_log = sup.stderr_log_path();
        registry.update_health(PluginHealthUpdate {
            plugin_id: &plugin_id,
            kind,
            targets: &targets,
            health: &live_health,
            restarts: sup.restart_count(),
            crash_loop_backoff: sup.is_crash_loop_backoff(),
            log_path: live_log.as_ref(),
        });
        started.push(sup);
    }

    (started, registry)
}

pub async fn notify_plugins_wake(plugins: &[Arc<SubprocessSupervisor>], slept_for: Duration) {
    let mut join_set = tokio::task::JoinSet::new();
    for sup in plugins {
        let sup = Arc::clone(sup);
        join_set.spawn(async move {
            let _ = sup.send_system_wake(slept_for).await;
        });
    }
    while join_set.join_next().await.is_some() {}
}

pub async fn stop_plugins(plugins: Vec<Arc<SubprocessSupervisor>>) {
    for sup in plugins {
        let _ = sup.stop().await;
    }
}

/// Applies topic exposure and local-only policy for validated adapter configuration.
pub fn configure_plugin_topics(node_cfg: &mut NodeConfig, plugins: &[ParsedPlugin]) {
    for p in plugins {
        match p.config.kind {
            AdapterKind::Bridge => {
                if p.expose_topic {
                    if !node_cfg.topics.iter().any(|t| t.topic == p.config.id) {
                        node_cfg.topics.push(TopicConfig {
                            topic: p.config.id.clone(),
                            kind: Some("bridge".to_string()),
                            description: Some(format!("External bridge plugin '{}'", p.config.id)),
                            metadata: None,
                            has_provisioned_publisher: true,
                        });
                    }
                } else if is_valid_topic(&p.config.id) {
                    node_cfg.local_only_topics.insert(p.config.id.clone());
                }
            }
            AdapterKind::Source => {
                let mut has_invalid_target = false;
                for target in &p.config.targets {
                    if is_valid_topic(target) {
                        if !node_cfg.topics.iter().any(|t| t.topic == *target) {
                            node_cfg.topics.push(TopicConfig {
                                topic: target.clone(),
                                kind: Some("source".to_string()),
                                description: Some(format!(
                                    "External source plugin '{}'",
                                    p.config.id
                                )),
                                metadata: None,
                                has_provisioned_publisher: true,
                            });
                        }
                        if !p.expose_topic {
                            node_cfg.local_only_topics.insert(target.clone());
                        }
                    } else {
                        has_invalid_target = true;
                    }
                }
                if has_invalid_target && is_valid_topic(&p.config.id) {
                    if !node_cfg.topics.iter().any(|t| t.topic == p.config.id) {
                        node_cfg.topics.push(TopicConfig {
                            topic: p.config.id.clone(),
                            kind: Some("source".to_string()),
                            description: Some(format!("External source plugin '{}'", p.config.id)),
                            metadata: None,
                            has_provisioned_publisher: true,
                        });
                    }
                    if !p.expose_topic {
                        node_cfg.local_only_topics.insert(p.config.id.clone());
                    }
                }
            }
            _ => {}
        }
    }
}
