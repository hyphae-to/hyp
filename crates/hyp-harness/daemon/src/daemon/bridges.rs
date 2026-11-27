//! External chat bridge registration, target ownership, and inbound/outbound delivery.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::{Arc, Mutex};

use hyp_node::gates::TrustTier as GateTrustTier;
use hyp_store::{BridgeLink, MailboxKind, NodeDb, PluginTargetHandoff, parse_address, uuid_v4};
use serde_json::{Map, Value, json};

use super::{
    BoxFuture, DaemonStateLock, InboundItem, LocalDaemon, LocalDaemonInner, invalid_request,
    store_err_tuple,
};

/// Pluggable async outbound handler for local chat/webhook bridges (`<plugin>:<target>`).
///
/// Implemented by real external chat bridge supervisors as well as deterministic in-process
/// test bridges. Outbound DLP (`SecurityGatePipeline`) and primary target ownership
/// (`plugin_targets`) are ALWAYS enforced by [`LocalDaemon`] BEFORE invoking [`BridgePoster::post`].
pub trait BridgePoster: Send + Sync {
    fn post<'a>(
        &'a self,
        plugin: &'a str,
        target: &'a str,
        text: &'a str,
        meta: &'a Map<String, Value>,
    ) -> BoxFuture<'a, Result<Value, (String, String)>>;
}

struct RegisteredBridge {
    poster: Arc<dyn BridgePoster>,
    // None is a legacy poster without a configured allowlist. Some(empty) allows no targets.
    targets: Option<Vec<String>>,
}

#[derive(Default)]
pub(super) struct BridgeRegistry {
    plugins: Mutex<BTreeMap<String, RegisteredBridge>>,
}

impl BridgeRegistry {
    pub(super) fn has_plugins(&self) -> bool {
        !self
            .plugins
            .lock_state("bridge registry poisoned")
            .is_empty()
    }

    fn register(
        &self,
        plugin: String,
        targets: Option<Vec<String>>,
        poster: Arc<dyn BridgePoster>,
    ) {
        let key = plugin.trim().to_ascii_lowercase();
        if key.is_empty() {
            return;
        }
        let targets = targets.map(|raw_targets| {
            let mut clean_targets = Vec::new();
            for raw in raw_targets {
                let trimmed = raw.trim();
                if !trimmed.is_empty() && !clean_targets.iter().any(|t: &String| t == trimmed) {
                    clean_targets.push(trimmed.to_owned());
                }
            }
            clean_targets
        });
        let mut plugins = self.plugins.lock_state("bridge registry poisoned");
        // Replacing only the poster preserves any existing configured allowlist.
        let targets =
            targets.or_else(|| plugins.get_mut(&key).and_then(|entry| entry.targets.take()));
        plugins.insert(key, RegisteredBridge { poster, targets });
    }

    fn ensure_configured(&self, plugin: &str, target: &str) -> Result<(), (String, String)> {
        let plugins = self.plugins.lock_state("bridge registry poisoned");
        match plugins.get(plugin) {
            Some(entry) => entry.check_target(plugin, target),
            None if plugins.is_empty() => Ok(()),
            None => Err((
                "bridge_target_not_configured".into(),
                format!("Bridge target '{plugin}:{target}' is not configured"),
            )),
        }
    }

    fn poster_for(
        &self,
        plugin: &str,
        target: &str,
    ) -> Result<Arc<dyn BridgePoster>, (String, String)> {
        let plugins = self.plugins.lock_state("bridge registry poisoned");
        let entry = plugins.get(plugin).ok_or_else(|| {
            (
                "no_plugins".into(),
                format!("No local bridge plugin configured for '{plugin}:{target}'"),
            )
        })?;
        entry.check_target(plugin, target)?;
        Ok(Arc::clone(&entry.poster))
    }

    fn target_snapshot(&self) -> (Vec<String>, BTreeMap<String, Vec<String>>) {
        let entries = self.plugins.lock_state("bridge registry poisoned");
        let plugins = entries.keys().cloned().collect();
        let configured = entries
            .iter()
            .filter_map(|(plugin, entry)| Some((plugin.clone(), entry.targets.clone()?)))
            .collect();
        (plugins, configured)
    }
}

impl RegisteredBridge {
    fn check_target(&self, plugin: &str, target: &str) -> Result<(), (String, String)> {
        if self
            .targets
            .as_ref()
            .is_some_and(|allowed| !allowed.iter().any(|t| t == target || t == "*"))
        {
            return Err((
                "bridge_target_not_configured".into(),
                format!(
                    "Bridge target '{plugin}:{target}' is not configured for plugin '{plugin}'"
                ),
            ));
        }
        Ok(())
    }
}

impl LocalDaemon {
    /// Registers a pluggable outbound [`BridgePoster`] for `plugin` (case-insensitive slug).
    /// Also causes `mcp.caps` to advertise `hasPlugins: true` so `hyp_bridge` is surfaced in `tools/list`.
    pub fn register_bridge_poster(&self, plugin: impl Into<String>, poster: Arc<dyn BridgePoster>) {
        self.inner.bridges.register(plugin.into(), None, poster);
    }

    /// Registers a pluggable outbound [`BridgePoster`] together with its configured target list.
    ///
    /// Configured targets are immediately advertised by `hyp_bridge({ action: "targets" })` even
    /// before any session links or claims primary ownership, so agents can discover targets like
    /// `telegram:123456789` on boot.
    pub fn register_bridge_poster_with_targets(
        &self,
        plugin: impl Into<String>,
        targets: Vec<String>,
        poster: Arc<dyn BridgePoster>,
    ) {
        self.inner
            .bridges
            .register(plugin.into(), Some(targets), poster);
    }

    /// Fans out an inbound external chat/webhook bridge message to all sessions linked to
    /// `(plugin, target)` (plus any wildcard `(plugin, "*")` links).
    ///
    /// Every delivery runs through [`LocalDaemon::ingest_inbound`] (`GateTrustTier::Bridge`,
    /// `MailboxKind::Plugin`, `source = "{plugin}:{target}"`) so Local Security Gates and
    /// §2.5 Delivery Policy apply consistently and wake live sessions immediately.
    ///
    /// Returns the number of linked sessions for which ingestion was accepted.
    pub async fn deliver_bridge_inbound(
        &self,
        plugin: &str,
        target: &str,
        item_id: &str,
        text: &str,
    ) -> Result<usize, String> {
        let plugin_key = plugin.trim().to_ascii_lowercase();
        let target_trimmed = target.trim();
        if plugin_key.is_empty() || target_trimmed.is_empty() {
            return Err("plugin and target must be non-empty".to_string());
        }

        let session_ids = linked_sessions(&self.inner.node.db(), &plugin_key, target_trimmed)?;

        let origin_node = format!("bridge:{plugin_key}");
        let source = format!("{plugin_key}:{target_trimmed}");
        let effective_item_id = if item_id.trim().is_empty() {
            uuid_v4()
        } else {
            item_id.trim().to_string()
        };

        let mut delivered = 0usize;
        let mut last_err: Option<String> = None;
        for session_id in session_ids {
            match self
                .ingest_inbound(InboundItem {
                    session_id,
                    origin_node: origin_node.clone(),
                    item_id: effective_item_id.clone(),
                    source: source.clone(),
                    text: text.to_string(),
                    kind: MailboxKind::Plugin,
                    trust_tier: GateTrustTier::Bridge,
                })
                .await
            {
                Ok(Some(_)) => delivered += 1,
                Ok(None) => {}
                Err(e) => last_err = Some(e),
            }
        }

        if delivered == 0 {
            if let Some(err) = last_err {
                return Err(err);
            }
        }
        Ok(delivered)
    }
}

fn linked_sessions(db: &NodeDb, plugin: &str, target: &str) -> Result<Vec<String>, String> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for link in db
        .local()
        .bridge_links(plugin, target)
        .map_err(|e| e.to_string())?
    {
        if seen.insert(link.session_id.clone()) {
            out.push(link.session_id);
        }
    }
    if target != "*" {
        for link in db
            .local()
            .bridge_links(plugin, "*")
            .map_err(|e| e.to_string())?
        {
            if seen.insert(link.session_id.clone()) {
                out.push(link.session_id);
            }
        }
    }
    Ok(out)
}

impl LocalDaemonInner {
    pub(super) fn tool_bridge(
        &self,
        session_id: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        let result = match args.get("action").and_then(Value::as_str) {
            Some("targets") => {
                let (plugins, configured) = self.bridges.target_snapshot();
                return bridge_targets(&self.node.db(), session_id, plugins, configured);
            }
            Some("link") => {
                let (plugin, target) = parse_bridge_plugin_target(args)?;
                self.bridges.ensure_configured(&plugin, &target)?;
                link(
                    &self.node.db(),
                    session_id,
                    plugin,
                    target,
                    args,
                    self.current_time_ms(),
                )
            }
            Some("unlink") => unlink(&self.node.db(), session_id, args),
            Some("handoff") => {
                let (plugin, target) = parse_bridge_plugin_target(args)?;
                self.bridges.ensure_configured(&plugin, &target)?;
                handoff(
                    &self.node.db(),
                    session_id,
                    plugin,
                    target,
                    args,
                    self.current_time_ms(),
                )
            }
            _ => Err(invalid_request(
                "Expected hyp_bridge action: targets | link | unlink | handoff",
            )),
        }?;
        self.bump_ui_rev();
        Ok(result)
    }

    pub(super) async fn send_to_bridge(
        &self,
        session_id: &str,
        handle: &str,
        to: &str,
        args: &Map<String, Value>,
    ) -> Result<Value, (String, String)> {
        self.prepare_bridge_post(session_id, handle, to, args)?
            .send()
            .await
    }

    fn prepare_bridge_post<'a>(
        &self,
        session_id: &str,
        handle: &str,
        to: &'a str,
        args: &'a Map<String, Value>,
    ) -> Result<BridgePost<'a>, (String, String)> {
        let (raw_plugin, raw_target) = to
            .split_once(':')
            .ok_or_else(|| invalid_request(format!("Invalid bridge destination '{to}'")))?;
        let (text, reaction) = parse_bridge_text_and_reaction(args)?;
        let plugin = raw_plugin.trim().to_ascii_lowercase();
        let target = raw_target.trim();
        let full_dest = format!("{plugin}:{target}");
        let poster = self.bridges.poster_for(&plugin, target)?;

        let holder = self
            .node
            .db()
            .local()
            .get_plugin_target(&plugin, target)
            .map_err(store_err_tuple)?;
        match holder {
            Some(ref h) if h.session_id == session_id => {}
            Some(ref h) => {
                return Err((
                    "not_target_holder".into(),
                    format!(
                        "Session '{session_id}' is not the primary holder of '{full_dest}' (held by '{}')",
                        h.session_id
                    ),
                ));
            }
            None => {
                return Err((
                    "not_target_holder".into(),
                    format!(
                        "No primary holder assigned for '{full_dest}'; claim ownership via hyp_bridge(action:'handoff')"
                    ),
                ));
            }
        }

        // Enforce Stage 1 Outbound DLP BEFORE invoking any external chat bridge!
        if !text.is_empty() {
            self.check_outbound_gate(session_id, &full_dest, "to.hyphae.bridge.v1", text)?;
        }
        if let Some(rxn) = reaction {
            if !rxn.is_empty() {
                self.check_outbound_gate(session_id, &full_dest, "to.hyphae.bridge.v1", rxn)?;
            }
        }

        let mut meta = Map::new();
        meta.insert("sessionId".into(), json!(session_id));
        meta.insert("handle".into(), json!(handle));
        if let Some(reply_to) = args.get("replyTo") {
            meta.insert("replyTo".into(), reply_to.clone());
            if !args.contains_key("threadTs") && reply_to.is_string() {
                meta.insert("threadTs".into(), reply_to.clone());
            }
        }
        if let Some(thread_ts) = args.get("threadTs") {
            meta.insert("threadTs".into(), thread_ts.clone());
        }
        if let Some(chat_id) = args.get("chatId").filter(|v| !v.is_null()) {
            meta.insert("chatId".into(), chat_id.clone());
        }
        if let Some(rxn) = reaction {
            meta.insert("reaction".into(), json!(rxn));
        }
        if let Some(remove) = args.get("remove").and_then(Value::as_bool) {
            meta.insert("remove".into(), json!(remove));
        }

        Ok(BridgePost {
            poster,
            plugin,
            target,
            text,
            meta,
        })
    }
}

/// A single authorized send. The registry, DB and gate guards have all been released.
struct BridgePost<'a> {
    poster: Arc<dyn BridgePoster>,
    plugin: String,
    target: &'a str,
    text: &'a str,
    meta: Map<String, Value>,
}

impl BridgePost<'_> {
    async fn send(self) -> Result<Value, (String, String)> {
        let response = self
            .poster
            .post(&self.plugin, self.target, self.text, &self.meta)
            .await?;
        Ok(json!({
            "delivered": true,
            "plugin": self.plugin,
            "target": self.target,
            "to": format!("{}:{}", self.plugin, self.target),
            "response": response,
        }))
    }
}

fn bridge_targets(
    db: &NodeDb,
    session_id: &str,
    plugins: Vec<String>,
    configured_snapshot: BTreeMap<String, Vec<String>>,
) -> Result<Value, (String, String)> {
    let (links, targets) = {
        let caller_links = db
            .local()
            .bridge_links_for_session(session_id)
            .map_err(store_err_tuple)?;

        let sessions = db.local().list_sessions().map_err(store_err_tuple)?;
        let handle_by_session: HashMap<String, Option<String>> = sessions
            .iter()
            .map(|s| (s.id.clone(), s.handle.clone()))
            .collect();

        let mut configured_set: HashSet<(String, String)> = HashSet::new();
        let mut target_pairs: BTreeMap<(String, String), Vec<String>> = BTreeMap::new();
        for (plugin, targets_for_plugin) in &configured_snapshot {
            for target in targets_for_plugin {
                let pair = (plugin.clone(), target.clone());
                configured_set.insert(pair.clone());
                target_pairs.entry(pair).or_default();
            }
        }
        for s in &sessions {
            for l in db
                .local()
                .bridge_links_for_session(&s.id)
                .unwrap_or_default()
            {
                let readers = target_pairs.entry((l.plugin, l.target)).or_default();
                if !readers.contains(&l.session_id) {
                    readers.push(l.session_id);
                }
            }
        }

        let mut target_views = Vec::with_capacity(target_pairs.len());
        for ((plugin, target), readers) in target_pairs {
            let holder = db
                .local()
                .get_plugin_target(&plugin, &target)
                .map_err(store_err_tuple)?;
            let primary_session = holder.as_ref().map(|h| h.session_id.clone());
            let primary_handle = primary_session
                .as_deref()
                .and_then(|sid| handle_by_session.get(sid).cloned().flatten());
            let is_primary = primary_session.as_deref() == Some(session_id);
            let is_linked = readers.iter().any(|r| r == session_id);
            let is_configured = configured_set.contains(&(plugin.clone(), target.clone()));
            target_views.push(json!({
                "plugin": plugin,
                "target": target,
                "configured": is_configured,
                "primarySessionId": primary_session,
                "primarySession": primary_session,
                "primaryHandle": primary_handle,
                "isPrimary": is_primary,
                "callerIsPrimary": is_primary,
                "callerIsLinked": is_linked,
                "readers": readers,
            }));
        }

        (caller_links, target_views)
    };

    Ok(json!({
        "plugins": plugins,
        "links": links,
        "targets": targets,
    }))
}

fn link(
    db: &NodeDb,
    session_id: &str,
    plugin: String,
    target: String,
    args: &Map<String, Value>,
    now: i64,
) -> Result<Value, (String, String)> {
    let read_only = args.get("readOnly").and_then(Value::as_bool) == Some(true);
    let link = BridgeLink {
        plugin: plugin.clone(),
        target: target.clone(),
        session_id: session_id.to_string(),
        linked_at: now,
        linked_by: session_id.to_string(),
    };
    let (primary_session, claimed_primary) = {
        db.local().add_bridge_link(&link).map_err(store_err_tuple)?;
        let existing = db
            .local()
            .get_plugin_target(&plugin, &target)
            .map_err(store_err_tuple)?
            .map(|h| h.session_id);
        if existing.is_none() && !read_only {
            let handoff = PluginTargetHandoff {
                plugin: plugin.clone(),
                target: target.clone(),
                session_id: session_id.to_string(),
                set_at: now,
                set_by: session_id.to_string(),
            };
            db.local()
                .set_plugin_target(&handoff)
                .map_err(store_err_tuple)?;
            (Some(session_id.to_string()), true)
        } else {
            (existing, false)
        }
    };
    let role = if primary_session.as_deref() == Some(session_id) {
        "primary"
    } else {
        "reader"
    };
    Ok(json!({
        "linked": true,
        "plugin": plugin,
        "target": target,
        "role": role,
        "claimedPrimary": claimed_primary,
        "primarySessionId": primary_session,
    }))
}

fn unlink(
    db: &NodeDb,
    session_id: &str,
    args: &Map<String, Value>,
) -> Result<Value, (String, String)> {
    let (plugin, target) = parse_bridge_plugin_target(args)?;
    let all = args.get("all").and_then(Value::as_bool) == Some(true);

    let removed = {
        let holder = db
            .local()
            .get_plugin_target(&plugin, &target)
            .map_err(store_err_tuple)?;
        if all {
            match holder {
                Some(ref h) if h.session_id == session_id => {}
                Some(ref h) => {
                    return Err((
                        "not_target_holder".into(),
                        format!(
                            "Session '{session_id}' is not the primary holder of '{plugin}:{target}' (held by '{}')",
                            h.session_id
                        ),
                    ));
                }
                None => {
                    return Err((
                        "not_target_holder".into(),
                        format!(
                            "No primary holder assigned for '{plugin}:{target}'; cannot unlink all"
                        ),
                    ));
                }
            }
            let count = db
                .local()
                .remove_bridge_link(&plugin, &target, None)
                .map_err(store_err_tuple)?;
            let _ = db.local().remove_plugin_target(&plugin, &target);
            count
        } else {
            let count = db
                .local()
                .remove_bridge_link(&plugin, &target, Some(session_id))
                .map_err(store_err_tuple)?;
            if holder.as_ref().is_some_and(|h| h.session_id == session_id) {
                let _ = db.local().remove_plugin_target(&plugin, &target);
            }
            count
        }
    };

    Ok(json!({
        "removed": removed > 0,
        "removedCount": removed,
        "all": all,
        "plugin": plugin,
        "target": target,
    }))
}

fn handoff(
    db: &NodeDb,
    session_id: &str,
    plugin: String,
    target: String,
    args: &Map<String, Value>,
    now: i64,
) -> Result<Value, (String, String)> {
    let (target_session, previous_session) = {
        let current = db
            .local()
            .get_plugin_target(&plugin, &target)
            .map_err(store_err_tuple)?;

        if let Some(ref holder) = current {
            if holder.session_id != session_id {
                return Err((
                    "not_target_holder".into(),
                    format!(
                        "Session '{session_id}' is not the primary holder of '{plugin}:{target}' (held by '{}')",
                        holder.session_id
                    ),
                ));
            }
        }

        let target_session = if let Some(raw_handle) = args
            .get("handle")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            let h = raw_handle.strip_prefix('@').unwrap_or(raw_handle);
            let lookup = parse_address(h).map(|(_, h_part)| h_part).unwrap_or(h);
            db.local()
                .session_by_handle(lookup)
                .map_err(store_err_tuple)?
                .ok_or_else(|| ("not_found".into(), format!("Unknown handle '{raw_handle}'")))?
                .id
        } else {
            session_id.to_string()
        };

        let handoff = PluginTargetHandoff {
            plugin: plugin.clone(),
            target: target.clone(),
            session_id: target_session.clone(),
            set_at: now,
            set_by: session_id.to_string(),
        };
        db.local()
            .set_plugin_target(&handoff)
            .map_err(store_err_tuple)?;

        // Ensure the new primary writer is always also linked for inbound reads.
        let link = BridgeLink {
            plugin: plugin.clone(),
            target: target.clone(),
            session_id: target_session.clone(),
            linked_at: now,
            linked_by: session_id.to_string(),
        };
        db.local().add_bridge_link(&link).map_err(store_err_tuple)?;

        (target_session, current.map(|h| h.session_id))
    };

    Ok(json!({
        "handoff": true,
        "plugin": plugin,
        "target": target,
        "sessionId": target_session,
        "previousSessionId": previous_session,
    }))
}

fn parse_bridge_plugin_target(
    args: &Map<String, Value>,
) -> Result<(String, String), (String, String)> {
    let plugin_opt = args
        .get("plugin")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let target_raw = args
        .get("target")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| invalid_request("Expected target"))?;

    let (plugin, target) = if let Some(p) = plugin_opt {
        (p.to_ascii_lowercase(), target_raw.to_string())
    } else if let Some((p, t)) = target_raw.split_once(':') {
        let p_trim = p.trim().to_ascii_lowercase();
        let t_trim = t.trim();
        if p_trim.is_empty() || t_trim.is_empty() {
            return Err(invalid_request("Expected valid plugin and target"));
        }
        (p_trim, t_trim.to_string())
    } else {
        return Err(invalid_request("Expected plugin"));
    };

    Ok((plugin, target))
}

const MAX_BRIDGE_REACTION_CHARS: usize = 32;

fn validate_bridge_reaction(raw: &str) -> Result<&str, (String, String)> {
    if raw.chars().count() > MAX_BRIDGE_REACTION_CHARS {
        return Err(invalid_request(format!(
            "Reaction must be at most {MAX_BRIDGE_REACTION_CHARS} characters"
        )));
    }
    if raw.chars().any(char::is_control) {
        return Err(invalid_request(
            "Reaction must not contain control characters",
        ));
    }
    Ok(raw)
}

fn parse_bridge_text_and_reaction(
    args: &Map<String, Value>,
) -> Result<(&str, Option<&str>), (String, String)> {
    let text = match args.get("text") {
        None | Some(Value::Null) => "",
        Some(Value::String(s)) => s.as_str(),
        Some(_) => {
            return Err(invalid_request("Expected string 'text'"));
        }
    };
    let reaction = match args.get("reaction") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(validate_bridge_reaction(s.as_str())?),
        Some(_) => {
            return Err(invalid_request("Expected string 'reaction'"));
        }
    };
    if text.trim().is_empty() && reaction.is_none() {
        return Err(invalid_request("Expected non-empty 'text' or 'reaction'"));
    }
    Ok((text, reaction))
}
