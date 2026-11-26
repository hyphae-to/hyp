//! Configuration for the local daemon loaded from node.json.

use crate::plugin_runtime::{ParsedPlugin, plugin_kind_str};
use hyp_crypto::{CryptoError, keystore::validate_secret_name};
use hyp_node::adapters::supervisor::is_secret_like_env_key;
use hyp_node::adapters::telegram::{
    DEFAULT_TELEGRAM_TARGET, TelegramTargetResolution, resolve_telegram_default_target_with_token,
};
use hyp_node::adapters::{AdapterKind, SubprocessConfig};
use hyp_node::node_file::PluginEntries;
use hyp_proto::address::is_valid_handle;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Official event-source plugins whose `plugins[]` entry defaults to `kind: "source"` (1-to-many
/// `hyp_stream` topic) when `kind` is omitted. An explicit `kind` always wins.
const OFFICIAL_SOURCE_PLUGIN_IDS: &[&str] = &[
    "agentmail",
    "sentry",
    "gmail",
    "google-calendar",
    "vercel",
    "notion",
];

fn push_plugin_error(
    id: &str,
    kind: Option<AdapterKind>,
    targets: Option<&[String]>,
    reason: String,
    warnings: &mut Vec<String>,
    skipped_statuses: &mut Vec<Value>,
) {
    warnings.push(format!(
        "Skipping misconfigured plugin '{id}' (daemon continuing): {reason}"
    ));
    let mut entry = serde_json::Map::new();
    entry.insert("id".to_string(), json!(id));
    if let Some(k) = kind {
        entry.insert("kind".to_string(), json!(plugin_kind_str(k)));
    }
    if let Some(t) = targets {
        entry.insert("targets".to_string(), json!(t));
    }
    entry.insert("status".to_string(), json!("error"));
    entry.insert("error".to_string(), json!(reason));
    entry.insert("lastError".to_string(), json!(reason));
    skipped_statuses.push(Value::Object(entry));
}

/// Parses and validates `plugins[]` from `node.json`, accepting both `"exec"` and `"command"`,
/// resolving `{ "secret": "<name>" }` references via `SecretStore`, warning on plaintext
/// secret-like env values, and isolating individual malformed/misconfigured plugin entries into
/// startup warnings + error/skipped statuses so a single bad plugin never aborts `hyp node start`.
pub fn parse_plugins_config(
    plugins: &PluginEntries,
    config_dir: Option<&Path>,
    state_dir: &Path,
    explicit_topics: &HashSet<String>,
    secrets: &hyp_crypto::SecretStore,
    warnings: &mut Vec<String>,
    skipped_statuses: &mut Vec<Value>,
) -> Vec<ParsedPlugin> {
    let Ok(arr) = plugins else {
        let reason = "plugins must be a JSON array";
        warnings.push(format!(
            "Skipping 'plugins' configuration (daemon continuing): {reason}"
        ));
        skipped_statuses.push(json!({
            "id": "plugins",
            "status": "error",
            "error": reason,
            "lastError": reason,
        }));
        return Vec::new();
    };

    let mut seen_ids: HashSet<String> = HashSet::new();
    let mut configs: Vec<ParsedPlugin> = Vec::new();

    for (idx, entry) in arr.iter().enumerate() {
        let fallback_id = format!("plugins[{idx}]");
        let Some(entry) = entry else {
            push_plugin_error(
                &fallback_id,
                None,
                None,
                format!("plugins[{idx}] must be a JSON object"),
                warnings,
                skipped_statuses,
            );
            continue;
        };

        if entry.enabled == Some(false) {
            continue;
        }

        let Some(raw_id) = entry.id.as_deref() else {
            push_plugin_error(
                &fallback_id,
                None,
                None,
                format!("plugins[{idx}].id must be a non-empty string"),
                warnings,
                skipped_statuses,
            );
            continue;
        };
        let id = raw_id.to_ascii_lowercase();
        if !is_valid_handle(&id) {
            push_plugin_error(
                raw_id,
                None,
                None,
                format!(
                    "plugins[{idx}].id '{raw_id}' is not a valid identifier (expected /^[a-z0-9][a-z0-9._-]{{0,63}}$/)"
                ),
                warnings,
                skipped_statuses,
            );
            continue;
        }
        if !seen_ids.insert(id.clone()) {
            push_plugin_error(
                &id,
                None,
                None,
                format!("duplicate plugin id '{id}' in plugins[]"),
                warnings,
                skipped_statuses,
            );
            continue;
        }

        let explicit_kind = match &entry.kind {
            None => None,
            Some(Value::String(s)) if s == "bridge" => Some(AdapterKind::Bridge),
            Some(Value::String(s)) if s == "source" => Some(AdapterKind::Source),
            Some(other) => {
                push_plugin_error(
                    &id,
                    None,
                    None,
                    format!(
                        "plugins[{id}].kind {other} is invalid (expected 'bridge' or 'source')"
                    ),
                    warnings,
                    skipped_statuses,
                );
                continue;
            }
        };

        let command_field = |value: &Option<Result<String, String>>, field| match value {
            None => Ok(None),
            Some(Ok(value)) if !value.trim().is_empty() => Ok(Some(value.trim().to_owned())),
            Some(_) => Err(format!("plugins[{id}].{field} must be a non-empty string")),
        };
        let exec_opt = command_field(&entry.exec, "exec");
        let command_opt = command_field(&entry.command, "command");
        let exec = match (exec_opt, command_opt) {
            (Ok(Some(e)), Ok(Some(c))) => {
                if e != c {
                    warnings.push(format!(
                        "plugins[{id}] defines both 'exec' and 'command' with different values; preferring 'exec'."
                    ));
                }
                e
            }
            (Ok(Some(e)), Ok(None)) => e,
            (Ok(None), Ok(Some(c))) => c,
            (Err(e), _) | (_, Err(e)) => {
                push_plugin_error(&id, explicit_kind, None, e, warnings, skipped_statuses);
                continue;
            }
            (Ok(None), Ok(None)) => {
                push_plugin_error(
                    &id,
                    explicit_kind,
                    None,
                    format!("plugins[{id}] must specify a non-empty 'exec' or 'command' string"),
                    warnings,
                    skipped_statuses,
                );
                continue;
            }
        };

        let args = match &entry.args {
            None => Ok(Vec::new()),
            Some(Ok(values)) => values
                .iter()
                .enumerate()
                .map(|(index, value)| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| format!("plugins[{id}].args[{index}] must be a string"))
                })
                .collect(),
            Some(Err(_)) => Err(format!("plugins[{id}].args must be an array of strings")),
        };
        let args = match args {
            Ok(v) => v,
            Err(e) => {
                push_plugin_error(&id, explicit_kind, None, e, warnings, skipped_statuses);
                continue;
            }
        };

        let cwd = command_field(&entry.cwd, "cwd").map(|cwd| {
            cwd.map(|raw_cwd| {
                let path = PathBuf::from(raw_cwd);
                match config_dir {
                    Some(base) if path.is_relative() => base.join(path),
                    _ => path,
                }
            })
        });
        let cwd = match cwd {
            Ok(v) => v,
            Err(e) => {
                push_plugin_error(&id, explicit_kind, None, e, warnings, skipped_statuses);
                continue;
            }
        };

        let explicit_targets_res = match &entry.targets {
            None => {
                if id == "telegram" {
                    Ok(None)
                } else {
                    Err(format!(
                        "plugins[{id}].targets must be a non-empty array of strings"
                    ))
                }
            }
            Some(Ok(raw_targets)) => {
                let mut out = Vec::with_capacity(raw_targets.len());
                let mut err = None;
                for (tidx, item) in raw_targets.iter().enumerate() {
                    if let Some(s) = item.as_str().map(str::trim).filter(|t| !t.is_empty()) {
                        if !out.iter().any(|existing: &String| existing == s) {
                            out.push(s.to_string());
                        }
                    } else {
                        err = Some(format!(
                            "plugins[{id}].targets[{tidx}] must be a non-empty string"
                        ));
                        break;
                    }
                }
                match err {
                    Some(e) => Err(e),
                    None if out.is_empty() => {
                        if id == "telegram" {
                            Ok(None)
                        } else {
                            Err(format!(
                                "plugins[{id}].targets must contain at least one target"
                            ))
                        }
                    }
                    None => Ok(Some(out)),
                }
            }
            Some(Err(_)) => Err(format!(
                "plugins[{id}].targets must be a non-empty array of strings"
            )),
        };
        let explicit_targets = match explicit_targets_res {
            Ok(v) => v,
            Err(e) => {
                push_plugin_error(&id, explicit_kind, None, e, warnings, skipped_statuses);
                continue;
            }
        };

        let mut env_map: BTreeMap<String, String> = BTreeMap::new();
        let mut secret_env_refs: Vec<(String, String)> = Vec::new();
        let mut redacted_values: Vec<String> = Vec::new();
        let mut secret_skip_reason: Option<String> = None;
        let mut config_error_reason: Option<String> = None;
        let mut plaintext_warnings: Vec<String> = Vec::new();

        if let Some(env) = &entry.env {
            match env {
                Err(_) => {
                    config_error_reason = Some(format!("plugins[{id}].env must be a JSON object"));
                }
                Ok(env_obj) => {
                    for (env_key, val) in env_obj {
                        if env_key.trim().is_empty() {
                            config_error_reason =
                                Some(format!("plugins[{id}].env contains an empty variable name"));
                            break;
                        }
                        match val {
                            Value::String(s) => {
                                if !s.trim().is_empty() && is_secret_like_env_key(env_key) {
                                    plaintext_warnings.push(format!(
                                            "plugins[{id}].env.{env_key} uses a plaintext secret value in node.json; store it with `hyp secret set <name>` and reference {{ \"secret\": \"<name>\" }} instead."
                                        ));
                                    redacted_values.push(s.clone());
                                }
                                env_map.insert(env_key.clone(), s.clone());
                            }
                            Value::Object(ref_obj) => {
                                let Some(secret_name) = ref_obj
                                    .get("secret")
                                    .and_then(Value::as_str)
                                    .filter(|_| ref_obj.len() == 1)
                                else {
                                    config_error_reason = Some(format!(
                                        "plugins[{id}].env.{env_key} must be a string or {{ \"secret\": \"<name>\" }}"
                                    ));
                                    break;
                                };
                                if let Err(e) = validate_secret_name(secret_name) {
                                    config_error_reason = Some(format!(
                                        "invalid secret name '{secret_name}' in plugins[{id}].env.{env_key}: {e}"
                                    ));
                                    break;
                                }
                                match secrets.get(secret_name) {
                                    Ok(secret) => {
                                        redacted_values.push((*secret).clone());
                                        env_map.insert(env_key.clone(), (*secret).clone());
                                        secret_env_refs
                                            .push((env_key.clone(), secret_name.to_string()));
                                    }
                                    Err(CryptoError::SecretNotFound(_)) => {
                                        secret_skip_reason = Some(format!(
                                            "plugins[{id}].env.{env_key} references missing secret '{secret_name}'; run `hyp secret set {secret_name}`"
                                        ));
                                        break;
                                    }
                                    Err(e) => {
                                        secret_skip_reason = Some(format!(
                                            "failed to load secret '{secret_name}' for plugins[{id}].env.{env_key}: {e}"
                                        ));
                                        break;
                                    }
                                }
                            }
                            _ => {
                                config_error_reason = Some(format!(
                                    "plugins[{id}].env.{env_key} must be a string or {{ \"secret\": \"<name>\" }}"
                                ));
                                break;
                            }
                        }
                    }
                }
            }
        }

        let has_webhook_post_url = env_map
            .get("WEBHOOK_POST_URL")
            .is_some_and(|v| !v.trim().is_empty());
        let kind = match explicit_kind {
            Some(k) => k,
            None => {
                if id == "prometheus"
                    || OFFICIAL_SOURCE_PLUGIN_IDS.contains(&id.as_str())
                    || (id == "webhook" && !has_webhook_post_url)
                {
                    AdapterKind::Source
                } else {
                    AdapterKind::Bridge
                }
            }
        };

        let status_targets_fallback = [DEFAULT_TELEGRAM_TARGET.to_string()];
        let status_targets_slice = explicit_targets
            .as_deref()
            .unwrap_or(&status_targets_fallback);

        if let Some(reason) = config_error_reason {
            push_plugin_error(
                &id,
                Some(kind),
                Some(status_targets_slice),
                reason,
                warnings,
                skipped_statuses,
            );
            continue;
        }

        if let Some(reason) = secret_skip_reason {
            warnings.push(format!(
                "Skipping plugin '{id}' (daemon continuing): {reason}"
            ));
            skipped_statuses.push(json!({
                "id": id,
                "kind": plugin_kind_str(kind),
                "targets": status_targets_slice,
                "status": "skipped",
                "error": reason,
                "lastError": reason,
            }));
            continue;
        }

        let targets = match explicit_targets {
            Some(explicit) => explicit,
            None => {
                // Only `id == "telegram"` reaches here when `targets` is omitted/empty:
                // resolve bot username via Telegram `getMe` with fail-safe fallback to `"personal"`.
                let resolved = match env_map.get("TELEGRAM_BOT_TOKEN").map(String::as_str) {
                    Some(token) if !token.trim().is_empty() => {
                        let api_base = env_map
                            .get("TELEGRAM_API_BASE")
                            .map(String::as_str)
                            .map(str::trim)
                            .filter(|s| !s.is_empty());
                        resolve_telegram_default_target_with_token(token, api_base)
                    }
                    _ => TelegramTargetResolution {
                        target: DEFAULT_TELEGRAM_TARGET.to_string(),
                        source: "fallback",
                        warning: None,
                    },
                };
                if let Some(w) = resolved.warning {
                    warnings.push(w);
                }
                vec![resolved.target]
            }
        };

        warnings.extend(plaintext_warnings);

        // Issue #25 (B6): Default `exposeTopic` strictly to `false` for BOTH `bridge` and `source`
        // subprocess plugins unless the user explicitly opts in via `"exposeTopic": true`
        // (or lists a bridge's topic in top-level `topics[]`).
        let explicit_expose = match entry.expose_topic.as_ref() {
            None => None,
            Some(Ok(enabled)) => Some(*enabled),
            Some(Err(_)) => {
                warnings.push(format!(
                    "plugins[{id}].exposeTopic must be a boolean; defaulting to local-only (false)."
                ));
                Some(false)
            }
        };
        let expose_topic = match explicit_expose {
            Some(explicit) => explicit,
            None => match kind {
                AdapterKind::Bridge => explicit_topics.contains(&id),
                AdapterKind::Source => false,
                _ => false,
            },
        };

        let mut cfg = SubprocessConfig::new(id.clone(), kind, exec, args, targets);
        cfg.cwd = cwd;
        cfg.env = env_map;
        // Plugins keep small private cursors (polling offsets, dedupe sets) under the node's state
        // dir so a restart resumes instead of re-baselining. An explicit plugins[].env value wins.
        cfg.env
            .entry("HYPHAE_STATE_DIR".to_string())
            .or_insert_with(|| state_dir.display().to_string());
        if !secret_env_refs.is_empty() {
            let store_for_respawn = secrets.clone();
            let plugin_id_for_err = id.clone();
            cfg.env_resolver = Some(Arc::new(move || {
                let mut resolved = BTreeMap::new();
                for (env_key, secret_name) in &secret_env_refs {
                    let val = store_for_respawn.get(secret_name).map_err(|e| {
                        format!(
                            "plugins[{plugin_id_for_err}].env.{env_key} failed to load secret '{secret_name}': {e}"
                        )
                    })?;
                    resolved.insert(env_key.clone(), (*val).clone());
                }
                Ok(resolved)
            }));
        }

        cfg.stderr_log_path = Some(state_dir.join("logs").join(format!("plugin-{id}.log")));
        cfg.redacted_values = redacted_values;
        configs.push(ParsedPlugin {
            config: cfg,
            expose_topic,
            has_webhook_post_url,
        });
    }

    configs
}
