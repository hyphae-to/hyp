//! `hyp kv` — Shared KV via the local daemon, with offline SQLite access.
//!
//! Supports `get`, `set`, `delete`, and `list` across all three write models (`owner`, `shared`
//! optimistic CAS with clean exit `1` conflict reporting, and `allowlist`).

use crate::config_file::{
    load_node_or_legacy_config, open_secret_store, resolve_config_path_for_read,
    resolve_effective_node_id, resolve_state_dir,
};
use crate::statusline_cmd::sanitize_terminal_text;
use crate::ui::{CliError, EXIT_ERROR, EXIT_OK, EXIT_USAGE, JsonEnvelope, print_json};
use clap::{Subcommand, ValueEnum};
use hyp_daemon::local_kv::{LocalKvAction, LocalKvError, LocalKvRequest, LocalKvResponse};
use hyp_harness_ipc::sock::{DEFAULT_SOCKET_FILENAME, daemon_local_kv_rpc, default_socket_path};
use hyp_store::{NodeDb, WriteModel};
use serde_json::{Value, json};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CliWriteModel {
    Owner,
    Shared,
    Allowlist,
}

impl CliWriteModel {
    pub const fn to_store(self) -> WriteModel {
        match self {
            Self::Owner => WriteModel::Owner,
            Self::Shared => WriteModel::Shared,
            Self::Allowlist => WriteModel::Allowlist,
        }
    }
}

#[derive(Subcommand)]
pub enum KvCommand {
    /// Get a live Shared KV entry
    Get {
        /// KV namespace (e.g. shared, deploys)
        #[arg(long)]
        ns: String,
        /// Key within namespace (e.g. status, plan/step1)
        #[arg(long)]
        key: String,
        /// Host node ID (defaults to this node)
        #[arg(long, default_value = "local")]
        node: String,
        /// Explicit state directory containing node.sqlite
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// List metadata for a page of live Shared KV keys
    Keys {
        /// KV namespace
        #[arg(long)]
        ns: String,
        /// Cursor returned as nextAfter by the previous page
        #[arg(long)]
        after: Option<String>,
        /// Host node ID (defaults to this node)
        #[arg(long, default_value = "local")]
        node: String,
        /// Explicit daemon state directory
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Show a bounded preview of a live Shared KV value
    Preview {
        /// KV namespace
        #[arg(long)]
        ns: String,
        /// Key within namespace
        #[arg(long)]
        key: String,
        /// Host node ID (defaults to this node)
        #[arg(long, default_value = "local")]
        node: String,
        /// Explicit daemon state directory
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Create or update a Shared KV entry (supports CAS --expected-version and owner/shared/allowlist write models)
    Set {
        /// KV namespace (e.g. shared, deploys)
        #[arg(long)]
        ns: String,
        /// Key within namespace
        #[arg(long)]
        key: String,
        /// JSON value payload (e.g. '{"status":"green"}', '"hello"', '42')
        #[arg(long)]
        value: String,
        /// Expected current version for optimistic CAS concurrency
        #[arg(long)]
        expected_version: Option<u64>,
        /// Namespace key write model (owner, shared, or allowlist)
        #[arg(long, value_enum, default_value_t = CliWriteModel::Owner)]
        write_model: CliWriteModel,
        /// Explicit owner identity (for write-model=owner)
        #[arg(long)]
        owner: Option<String>,
        /// Comma-separated allowed writer IDs (for write-model=allowlist)
        #[arg(long, value_delimiter = ',')]
        allowlist: Option<Vec<String>>,
        /// Writer identity (defaults to nodeId or "local")
        #[arg(long)]
        writer: Option<String>,
        /// Renew expiry from now. Omit to preserve an existing expiry.
        #[arg(long)]
        ttl_seconds: Option<i64>,
        /// Remove the entry's expiry
        #[arg(long, conflicts_with = "ttl_seconds")]
        clear_ttl: bool,
        /// Host node ID (defaults to this node)
        #[arg(long, default_value = "local")]
        node: String,
        /// Explicit state directory containing node.sqlite
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Delete a Shared KV entry
    Delete {
        /// KV namespace
        #[arg(long)]
        ns: String,
        /// Key within namespace
        #[arg(long)]
        key: String,
        /// Expected current version for optimistic CAS concurrency
        #[arg(long)]
        expected_version: Option<u64>,
        /// Writer identity (defaults to nodeId or "local")
        #[arg(long)]
        writer: Option<String>,
        /// Host node ID (defaults to this node)
        #[arg(long, default_value = "local")]
        node: String,
        /// Explicit state directory containing node.sqlite
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// List live KV entries in a namespace (with optional key prefix filter)
    List {
        /// KV namespace
        #[arg(long)]
        ns: String,
        /// Optional key prefix filter
        #[arg(long)]
        prefix: Option<String>,
        /// Host node ID (defaults to this node)
        #[arg(long, default_value = "local")]
        node: String,
        /// Explicit state directory containing node.sqlite
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
}

pub fn run_kv(command: KvCommand) -> crate::ui::CommandResult {
    match command {
        KvCommand::Get {
            ns,
            key,
            node,
            state_dir,
            json,
        } => crate::ui::CommandResult::new(
            "kv get",
            json,
            run_kv_get(ns, key, node, state_dir, json),
        ),
        KvCommand::Keys {
            ns,
            after,
            node,
            state_dir,
            json,
        } => crate::ui::CommandResult::new(
            "kv keys",
            json,
            run_kv_keys(ns, after, node, state_dir, json),
        ),
        KvCommand::Preview {
            ns,
            key,
            node,
            state_dir,
            json,
        } => crate::ui::CommandResult::new(
            "kv preview",
            json,
            run_kv_preview(ns, key, node, state_dir, json),
        ),
        KvCommand::Set {
            ns,
            key,
            value,
            expected_version,
            write_model,
            owner,
            allowlist,
            writer,
            ttl_seconds,
            clear_ttl,
            node,
            state_dir,
            json,
        } => crate::ui::CommandResult::new(
            "kv set",
            json,
            run_kv_set(
                ns,
                key,
                value,
                expected_version,
                write_model,
                owner,
                allowlist,
                writer,
                ttl_seconds,
                clear_ttl,
                node,
                state_dir,
                json,
            ),
        ),
        KvCommand::Delete {
            ns,
            key,
            expected_version,
            writer,
            node,
            state_dir,
            json,
        } => crate::ui::CommandResult::new(
            "kv delete",
            json,
            run_kv_delete(ns, key, expected_version, writer, node, state_dir, json),
        ),
        KvCommand::List {
            ns,
            prefix,
            node,
            state_dir,
            json,
        } => crate::ui::CommandResult::new(
            "kv list",
            json,
            run_kv_list(ns, prefix, node, state_dir, json),
        ),
    }
}

#[derive(Debug)]
enum KvCommandError {
    Config(String),
    Db(String),
    Daemon(String),
    Operation(LocalKvError),
}

fn execute_kv(
    node: &str,
    namespace: &str,
    action: LocalKvAction,
    state_dir_arg: Option<&Path>,
) -> Result<LocalKvResponse, KvCommandError> {
    let config_path = resolve_config_path_for_read(None, state_dir_arg, None);
    let loaded = if config_path.exists() {
        Some(load_node_or_legacy_config(&config_path).map_err(KvCommandError::Config)?)
    } else {
        None
    };
    let mut dir = resolve_state_dir(
        state_dir_arg.or(loaded.as_ref().and_then(|cfg| cfg.state_dir.as_deref())),
        loaded.as_ref().map(|cfg| cfg.path.as_path()),
        None,
    );
    let explicit_socket = state_dir_arg.is_none()
        && ["HYPHAE_SOCKET", "AGENTS_MESH_SOCKET"]
            .iter()
            .any(|key| std::env::var_os(key).is_some_and(|value| !value.is_empty()));
    let socket = if explicit_socket {
        default_socket_path()
    } else {
        dir.join(DEFAULT_SOCKET_FILENAME)
    };
    let request = LocalKvRequest {
        host_node: node.to_owned(),
        namespace: namespace.to_owned(),
        action,
    };
    let keystore = open_secret_store(&dir, state_dir_arg.is_some());
    let daemon_node =
        match daemon_local_kv_rpc(&socket, &json!(request), &keystore, Duration::from_secs(10)) {
            Ok(rpc) => {
                let response = rpc
                    .result
                    .and_then(|mut result| result.remove("response"))
                    .ok_or_else(|| {
                        KvCommandError::Daemon(
                            rpc.error
                                .unwrap_or_else(|| "The daemon did not return a KV result.".into()),
                        )
                    })?;
                let response =
                    serde_json::from_value::<Result<LocalKvResponse, LocalKvError>>(response)
                        .map_err(|err| KvCommandError::Daemon(err.to_string()))?;
                // Large lists can exceed the RPC frame limit. This response permits a
                // read-only fall back to the specific daemon's database, including custom sockets.
                match (&request.action, response) {
                    (
                        LocalKvAction::List { .. },
                        Err(LocalKvError::ListTooLarge { state_dir, node_id }),
                    ) => {
                        dir = state_dir;
                        Some(node_id)
                    }
                    (_, response) => return response.map_err(KvCommandError::Operation),
                }
            }
            Err(err)
                if matches!(
                    err.kind(),
                    ErrorKind::NotFound | ErrorKind::ConnectionRefused
                ) =>
            {
                None
            }
            Err(err) => return Err(KvCommandError::Daemon(err.to_string())),
        };

    if matches!(
        request.action,
        LocalKvAction::Inspect | LocalKvAction::Keys { .. } | LocalKvAction::Preview { .. }
    ) {
        return Err(KvCommandError::Daemon(
            "KV inspection requires the local daemon.".into(),
        ));
    }
    let db_path = dir.join("node.sqlite");
    let db = NodeDb::open(&db_path).map_err(|err| {
        KvCommandError::Db(format!("failed to open {}: {err}", db_path.display()))
    })?;
    let local_node =
        daemon_node.unwrap_or_else(|| resolve_effective_node_id(loaded.as_ref(), Some(&db)));
    request
        .execute(&db, &local_node)
        .map_err(KvCommandError::Operation)
}

impl From<KvCommandError> for CliError {
    fn from(error: KvCommandError) -> Self {
        let (exit, code, message) = match error {
            KvCommandError::Config(msg) => (EXIT_ERROR, "CONFIG_ERROR", msg),
            KvCommandError::Db(msg) => (EXIT_ERROR, "DB_ERROR", msg),
            KvCommandError::Daemon(msg) => (EXIT_ERROR, "DAEMON_ERROR", msg),
            KvCommandError::Operation(LocalKvError::Unauthorized(msg)) => {
                (EXIT_ERROR, "UNAUTHORIZED", msg)
            }
            KvCommandError::Operation(LocalKvError::InvalidInput(msg)) => {
                (EXIT_USAGE, "INVALID_INPUT", msg)
            }
            KvCommandError::Operation(LocalKvError::Other(msg)) => (EXIT_ERROR, "KV_ERROR", msg),
            KvCommandError::Operation(other) => (EXIT_ERROR, "KV_ERROR", format!("{other:?}")),
        };
        Self::new(exit, code, message)
    }
}

fn unexpected_kv_response() -> CliError {
    CliError::error("DAEMON_ERROR", "Unexpected KV response")
}

fn version_conflict(
    ns: &str,
    key: &str,
    expected_version: Option<u64>,
    current_version: u64,
) -> CliError {
    let msg = format!(
        "CAS version conflict for '{ns}/{key}': expected {:?}, current version is {current_version}",
        expected_version
    );
    let fix = format!(
        "Re-read latest value (`hyp kv get --ns {ns} --key {key}`) and retry with `--expected-version {current_version}`."
    );
    CliError::error("VERSION_CONFLICT", msg)
        .with_fix(fix)
        .with_data(json!({
            "namespace": ns,
            "key": key,
            "expectedVersion": expected_version,
            "currentVersion": current_version,
        }))
}

fn run_kv_get(
    ns: String,
    key: String,
    node: String,
    state_dir: Option<PathBuf>,
    as_json: bool,
) -> Result<ExitCode, CliError> {
    let cmd = "kv get";
    let action = LocalKvAction::Get { key: key.clone() };
    match execute_kv(&node, &ns, action, state_dir.as_deref()) {
        Ok(LocalKvResponse::Get(Some(entry))) => {
            if as_json {
                let envelope = JsonEnvelope::ok(
                    cmd.to_string(),
                    format!("{ns}/{key} (v{})", entry.version),
                    json!({
                        "hostNode": entry.host_node,
                        "namespace": entry.namespace,
                        "key": entry.key,
                        "value": entry.value,
                        "version": entry.version,
                        "writeModel": entry.write_model.as_str(),
                        "ownerId": entry.owner_id,
                        "allowlist": entry.allowlist,
                        "writerId": entry.writer_id,
                        "createdAt": entry.created_at,
                        "updatedAt": entry.updated_at,
                        "expiresAt": entry.expires_at,
                    }),
                );
                print_json(&envelope);
            } else {
                println!(
                    "OK    {}/{} (v{}, model={}, writer={})",
                    entry.namespace,
                    entry.key,
                    entry.version,
                    entry.write_model.as_str(),
                    entry.writer_id
                );
                println!(
                    "{}",
                    serde_json::to_string_pretty(&entry.value).unwrap_or_default()
                );
            }
            Ok(ExitCode::from(EXIT_OK))
        }
        Ok(LocalKvResponse::Get(None)) => Err(CliError::error(
            "NOT_FOUND",
            format!("KV entry '{node}/{ns}/{key}' not found"),
        )
        .with_fix(format!("List keys with `hyp kv list --ns {ns}`."))),
        Err(err) => Err(err.into()),
        Ok(_) => Err(unexpected_kv_response()),
    }
}

fn run_kv_keys(
    namespace: String,
    after: Option<String>,
    node: String,
    state_dir: Option<PathBuf>,
    as_json: bool,
) -> Result<ExitCode, CliError> {
    let command = "kv keys";
    let action = LocalKvAction::Keys { after };
    match execute_kv(&node, &namespace, action, state_dir.as_deref()) {
        Ok(LocalKvResponse::Keys(page)) => {
            if as_json {
                print_json(&JsonEnvelope::ok(
                    command,
                    format!("{} live KV keys", page.entries.len()),
                    json!(page),
                ));
            } else {
                if page.entries.is_empty() {
                    println!("No visible keys.");
                }
                for entry in page.entries {
                    println!(
                        "{}  v{}  {}  {} B",
                        sanitize_terminal_text(&entry.key),
                        entry.version,
                        sanitize_terminal_text(&entry.updated_by),
                        entry.size_bytes,
                    );
                }
                if let Some(after) = page.next_after {
                    println!("More keys after {}", sanitize_terminal_text(&after));
                }
            }
            Ok(ExitCode::from(EXIT_OK))
        }
        Err(err) => Err(err.into()),
        Ok(_) => Err(unexpected_kv_response()),
    }
}

fn run_kv_preview(
    namespace: String,
    key: String,
    node: String,
    state_dir: Option<PathBuf>,
    as_json: bool,
) -> Result<ExitCode, CliError> {
    let command = "kv preview";
    let action = LocalKvAction::Preview { key };
    match execute_kv(&node, &namespace, action, state_dir.as_deref()) {
        Ok(LocalKvResponse::Preview(Some(preview))) => {
            if as_json {
                print_json(&JsonEnvelope::ok(
                    command,
                    format!("KV value preview (v{})", preview.version),
                    json!(preview),
                ));
            } else {
                for line in preview.text.lines() {
                    println!("{}", sanitize_terminal_text(line));
                }
                if preview.truncated {
                    println!("… (truncated)");
                }
            }
            Ok(ExitCode::from(EXIT_OK))
        }
        Ok(LocalKvResponse::Preview(None)) => Err(CliError::error(
            "NOT_FOUND",
            "No visible KV entry at this key.",
        )),
        Err(err) => Err(err.into()),
        Ok(_) => Err(unexpected_kv_response()),
    }
}

pub(crate) fn inspect_live_kv(socket: &Path) -> Option<Value> {
    let request = LocalKvRequest {
        host_node: "local".into(),
        namespace: String::new(),
        action: LocalKvAction::Inspect,
    };
    match request_live_kv(socket, &request)? {
        LocalKvResponse::Inspect(kv) => Some(json!(kv)),
        _ => None,
    }
}

pub(crate) fn request_live_kv(socket: &Path, request: &LocalKvRequest) -> Option<LocalKvResponse> {
    let hinted_state = socket
        .parent()
        .filter(|path| path.join("node.sqlite").is_file());
    let config_path = resolve_config_path_for_read(None, hinted_state, None);
    let loaded = load_node_or_legacy_config(&config_path).ok();
    let state_dir = resolve_state_dir(
        hinted_state.or(loaded.as_ref().and_then(|cfg| cfg.state_dir.as_deref())),
        loaded.as_ref().map(|cfg| cfg.path.as_path()),
        None,
    );
    let secret_store = open_secret_store(&state_dir, hinted_state.is_some());
    let response = daemon_local_kv_rpc(
        socket,
        &json!(request),
        &secret_store,
        Duration::from_secs(3),
    )
    .ok()?
    .result?
    .remove("response")?;
    serde_json::from_value::<Result<LocalKvResponse, LocalKvError>>(response)
        .ok()?
        .ok()
}

#[allow(clippy::too_many_arguments)]
fn run_kv_set(
    ns: String,
    key: String,
    raw_value: String,
    expected_version: Option<u64>,
    write_model: CliWriteModel,
    owner: Option<String>,
    allowlist: Option<Vec<String>>,
    writer: Option<String>,
    ttl_seconds: Option<i64>,
    clear_ttl: bool,
    node: String,
    state_dir: Option<PathBuf>,
    as_json: bool,
) -> Result<ExitCode, CliError> {
    let cmd = "kv set";
    let value: Value = match serde_json::from_str(&raw_value) {
        Ok(v) => v,
        Err(e) => {
            return Err(CliError::usage("INVALID_JSON_VALUE", format!("--value must be valid JSON: {e}")).with_fix("Quote strings as valid JSON, e.g. --value '\"ready\"' or --value '{\"ready\":true}'.".to_string()));
        }
    };
    let ttl_ms = match ttl_seconds {
        Some(s) if s <= 0 => {
            return Err(CliError::usage("INVALID_TTL", "--ttl-seconds must be > 0"));
        }
        Some(s) => Some(
            s.checked_mul(1000)
                .ok_or_else(|| CliError::usage("INVALID_TTL", "--ttl-seconds is too large"))?,
        ),
        None => None,
    };

    let action = LocalKvAction::Set {
        key: key.clone(),
        value,
        write_model: write_model.to_store(),
        owner,
        allowlist,
        writer,
        expected_version,
        ttl_ms,
        clear_ttl,
    };
    match execute_kv(&node, &ns, action, state_dir.as_deref()) {
        Ok(LocalKvResponse::Set(entry)) => {
            if as_json {
                let envelope = JsonEnvelope::ok(
                    cmd.to_string(),
                    format!(
                        "Set {}/{} -> v{} ({})",
                        entry.namespace,
                        entry.key,
                        entry.version,
                        entry.write_model.as_str()
                    ),
                    json!({
                        "hostNode": entry.host_node,
                        "namespace": entry.namespace,
                        "key": entry.key,
                        "value": entry.value,
                        "version": entry.version,
                        "writeModel": entry.write_model.as_str(),
                        "ownerId": entry.owner_id,
                        "allowlist": entry.allowlist,
                        "writerId": entry.writer_id,
                        "updatedAt": entry.updated_at,
                        "expiresAt": entry.expires_at,
                    }),
                );
                print_json(&envelope);
            } else {
                println!(
                    "OK    Set {}/{} -> v{} (model={}, writer={})",
                    entry.namespace,
                    entry.key,
                    entry.version,
                    entry.write_model.as_str(),
                    entry.writer_id
                );
            }
            Ok(ExitCode::from(EXIT_OK))
        }
        Err(KvCommandError::Operation(LocalKvError::VersionConflict(current_version))) => Err(
            version_conflict(&ns, &key, expected_version, current_version),
        ),
        Err(err) => Err(err.into()),
        Ok(_) => Err(unexpected_kv_response()),
    }
}

fn run_kv_delete(
    ns: String,
    key: String,
    expected_version: Option<u64>,
    writer: Option<String>,
    node: String,
    state_dir: Option<PathBuf>,
    as_json: bool,
) -> Result<ExitCode, CliError> {
    let cmd = "kv delete";
    let action = LocalKvAction::Delete {
        key: key.clone(),
        writer,
        expected_version,
    };
    match execute_kv(&node, &ns, action, state_dir.as_deref()) {
        Ok(LocalKvResponse::Delete {
            deleted,
            previous_version,
        }) => {
            if as_json {
                let envelope = JsonEnvelope::ok(
                    cmd.to_string(),
                    if deleted {
                        format!("Deleted {ns}/{key}")
                    } else {
                        format!("KV entry {ns}/{key} did not exist")
                    },
                    json!({
                        "namespace": ns,
                        "key": key,
                        "deleted": deleted,
                        "previousVersion": previous_version,
                    }),
                );
                print_json(&envelope);
            } else if deleted {
                println!(
                    "OK    Deleted {ns}/{key} (previous v{})",
                    previous_version.unwrap_or(0)
                );
            } else {
                println!("OK    KV entry {ns}/{key} was already absent");
            }
            Ok(ExitCode::from(EXIT_OK))
        }
        Err(KvCommandError::Operation(LocalKvError::VersionConflict(current_version))) => Err(
            version_conflict(&ns, &key, expected_version, current_version),
        ),
        Err(err) => Err(err.into()),
        Ok(_) => Err(unexpected_kv_response()),
    }
}

fn run_kv_list(
    ns: String,
    prefix: Option<String>,
    node: String,
    state_dir: Option<PathBuf>,
    as_json: bool,
) -> Result<ExitCode, CliError> {
    let cmd = "kv list";
    let action = LocalKvAction::List {
        prefix: prefix.clone(),
    };
    match execute_kv(&node, &ns, action, state_dir.as_deref()) {
        Ok(LocalKvResponse::List {
            host_node: node,
            entries,
        }) => {
            if as_json {
                let items: Vec<Value> = entries
                    .iter()
                    .map(|e| {
                        json!({
                            "hostNode": e.host_node,
                            "namespace": e.namespace,
                            "key": e.key,
                            "value": e.value,
                            "version": e.version,
                            "writeModel": e.write_model.as_str(),
                            "ownerId": e.owner_id,
                            "writerId": e.writer_id,
                            "updatedAt": e.updated_at,
                            "expiresAt": e.expires_at,
                        })
                    })
                    .collect();
                let envelope = JsonEnvelope::ok(
                    cmd.to_string(),
                    format!("{} key(s) in '{node}/{ns}'", items.len()),
                    json!({
                        "hostNode": node,
                        "namespace": ns,
                        "prefix": prefix,
                        "count": items.len(),
                        "entries": items,
                    }),
                );
                print_json(&envelope);
            } else {
                println!("KV Namespace '{node}/{ns}' ({} entries)", entries.len());
                if entries.is_empty() {
                    println!("  (empty)");
                } else {
                    println!();
                    println!("{:<28}  {:<6}  {:<10}  Value", "Key", "Ver", "Model");
                    println!("{}", "-".repeat(78));
                    for e in &entries {
                        let val_str = serde_json::to_string(&e.value).unwrap_or_default();
                        let preview: String = val_str.chars().take(48).collect();
                        println!(
                            "{:<28}  v{:<5}  {:<10}  {}",
                            e.key,
                            e.version,
                            e.write_model.as_str(),
                            preview
                        );
                    }
                }
            }
            Ok(ExitCode::from(EXIT_OK))
        }
        Err(err) => Err(err.into()),
        Ok(_) => Err(unexpected_kv_response()),
    }
}
