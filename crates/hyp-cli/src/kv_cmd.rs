//! `hyp-rs kv` — Direct CLI access to `NodeDb::kv()` (Shared KV / Blackboard).
//!
//! Supports `get`, `set`, `delete`, and `list` across all three write models (`owner`, `shared`
//! optimistic CAS with clean exit `1` conflict reporting, and `allowlist`).

use crate::config_file::{
    load_node_or_legacy_config, resolve_config_path_for_read, resolve_effective_node_id,
    resolve_state_dir,
};
use crate::ui::{
    CliError, EXIT_ERROR, EXIT_OK, EXIT_USAGE, JsonEnvelope, emit_error, print_json,
};
use clap::{Subcommand, ValueEnum};
use hyp_store::{KvDeleteInput, KvSetInput, NodeDb, StoreError, WriteModel, now_ms};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::ExitCode;

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
        /// Host node ID (defaults to "local")
        #[arg(long, default_value = "local")]
        node: String,
        /// Explicit state directory containing node.sqlite
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
        /// Optional TTL in seconds
        #[arg(long)]
        ttl_seconds: Option<i64>,
        /// Host node ID (defaults to "local")
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
        /// Host node ID (defaults to "local")
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
        /// Host node ID (defaults to "local")
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

pub fn run_kv(command: KvCommand) -> ExitCode {
    match command {
        KvCommand::Get {
            ns,
            key,
            node,
            state_dir,
            json,
        } => run_kv_get(ns, key, node, state_dir, json),
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
            node,
            state_dir,
            json,
        } => run_kv_set(
            ns,
            key,
            value,
            expected_version,
            write_model,
            owner,
            allowlist,
            writer,
            ttl_seconds,
            node,
            state_dir,
            json,
        ),
        KvCommand::Delete {
            ns,
            key,
            expected_version,
            writer,
            node,
            state_dir,
            json,
        } => run_kv_delete(ns, key, expected_version, writer, node, state_dir, json),
        KvCommand::List {
            ns,
            prefix,
            node,
            state_dir,
            json,
        } => run_kv_list(ns, prefix, node, state_dir, json),
    }
}

fn open_db(state_dir: Option<&PathBuf>) -> Result<(PathBuf, NodeDb), String> {
    let dir = resolve_state_dir(state_dir.map(PathBuf::as_path), None, None);
    let db_path = dir.join("node.sqlite");
    let db = NodeDb::open(&db_path)
        .map_err(|e| format!("failed to open {}: {e}", db_path.display()))?;
    Ok((dir, db))
}

fn default_writer_id(state_dir: Option<&PathBuf>, db: &NodeDb) -> String {
    let cfg_path = resolve_config_path_for_read(None, state_dir.map(PathBuf::as_path), None);
    let loaded = load_node_or_legacy_config(&cfg_path).ok();
    resolve_effective_node_id(loaded.as_ref(), Some(db))
}

fn emit_version_conflict(
    cmd: &str,
    as_json: bool,
    ns: &str,
    key: &str,
    expected_version: Option<u64>,
    current_version: u64,
) -> ExitCode {
    let msg = format!(
        "CAS version conflict for '{ns}/{key}': expected {:?}, current version is {current_version}",
        expected_version
    );
    let fix = format!(
        "Re-read latest value (`hyp-rs kv get --ns {ns} --key {key}`) and retry with `--expected-version {current_version}`."
    );
    if as_json {
        let envelope = JsonEnvelope {
            ok: false,
            command: cmd.to_string(),
            summary: Some(msg.clone()),
            data: Some(json!({
                "namespace": ns,
                "key": key,
                "expectedVersion": expected_version,
                "currentVersion": current_version,
            })),
            warnings: Vec::new(),
            next: vec![fix.clone()],
            error: Some(CliError {
                code: "VERSION_CONFLICT".to_string(),
                message: msg,
                fix: Some(fix),
            }),
        };
        print_json(&envelope);
    } else {
        eprintln!("FAIL [VERSION_CONFLICT] {msg}");
        eprintln!("Fix:  {fix}");
    }
    ExitCode::from(EXIT_ERROR)
}

fn run_kv_get(
    ns: String,
    key: String,
    node: String,
    state_dir: Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let cmd = "kv get";
    let (_dir, db) = match open_db(state_dir.as_ref()) {
        Ok(v) => v,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e, None),
    };

    match db.kv().get(&node, &ns, &key, now_ms()) {
        Ok(Some(entry)) => {
            if as_json {
                let envelope = JsonEnvelope {
                    ok: true,
                    command: cmd.to_string(),
                    summary: Some(format!("{ns}/{key} (v{})", entry.version)),
                    data: Some(json!({
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
                    })),
                    warnings: Vec::new(),
                    next: Vec::new(),
                    error: None,
                };
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
                println!("{}", serde_json::to_string_pretty(&entry.value).unwrap_or_default());
            }
            ExitCode::from(EXIT_OK)
        }
        Ok(None) => emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "NOT_FOUND",
            format!("KV entry '{node}/{ns}/{key}' not found"),
            Some(format!("List keys with `hyp-rs kv list --ns {ns}`.")),
        ),
        Err(e) => emit_error(cmd, as_json, EXIT_ERROR, "KV_ERROR", e.to_string(), None),
    }
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
    node: String,
    state_dir: Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let cmd = "kv set";
    let value: Value = match serde_json::from_str(&raw_value) {
        Ok(v) => v,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_JSON_VALUE",
                format!("--value must be valid JSON: {e}"),
                Some("Quote strings as valid JSON, e.g. --value '\"ready\"' or --value '{\"ready\":true}'.".to_string()),
            );
        }
    };
    let ttl_ms = match ttl_seconds {
        Some(s) if s <= 0 => {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_TTL",
                "--ttl-seconds must be > 0",
                None,
            );
        }
        Some(s) => Some(s.saturating_mul(1000)),
        None => None,
    };

    let (_dir, db) = match open_db(state_dir.as_ref()) {
        Ok(v) => v,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e, None),
    };
    let writer_id = writer.unwrap_or_else(|| default_writer_id(state_dir.as_ref(), &db));

    let res = db.kv().set(
        &KvSetInput {
            host_node: node,
            namespace: ns.clone(),
            key: key.clone(),
            value,
            content_type: Some("application/json".to_string()),
            write_model: write_model.to_store(),
            owner_id: owner,
            allowlist,
            writer_id,
            expected_version,
            e2ee_epoch: None,
            signature: None,
            ttl_ms,
        },
        now_ms(),
    );

    match res {
        Ok(saved) => {
            let entry = saved.entry;
            if as_json {
                let envelope = JsonEnvelope {
                    ok: true,
                    command: cmd.to_string(),
                    summary: Some(format!(
                        "Set {}/{} -> v{} ({})",
                        entry.namespace,
                        entry.key,
                        entry.version,
                        entry.write_model.as_str()
                    )),
                    data: Some(json!({
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
                    })),
                    warnings: Vec::new(),
                    next: Vec::new(),
                    error: None,
                };
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
            ExitCode::from(EXIT_OK)
        }
        Err(StoreError::VersionConflict { current_version }) => {
            emit_version_conflict(cmd, as_json, &ns, &key, expected_version, current_version)
        }
        Err(StoreError::Unauthorized(msg)) => {
            emit_error(cmd, as_json, EXIT_ERROR, "UNAUTHORIZED", msg, None)
        }
        Err(StoreError::InvalidInput(msg)) => {
            emit_error(cmd, as_json, EXIT_USAGE, "INVALID_INPUT", msg, None)
        }
        Err(e) => emit_error(cmd, as_json, EXIT_ERROR, "KV_ERROR", e.to_string(), None),
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
) -> ExitCode {
    let cmd = "kv delete";
    let (_dir, db) = match open_db(state_dir.as_ref()) {
        Ok(v) => v,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e, None),
    };
    let writer_id = writer.unwrap_or_else(|| default_writer_id(state_dir.as_ref(), &db));

    match db.kv().delete(
        &KvDeleteInput {
            host_node: node,
            namespace: ns.clone(),
            key: key.clone(),
            writer_id,
            expected_version,
        },
        now_ms(),
    ) {
        Ok(res) => {
            if as_json {
                let envelope = JsonEnvelope {
                    ok: true,
                    command: cmd.to_string(),
                    summary: Some(if res.deleted {
                        format!("Deleted {ns}/{key}")
                    } else {
                        format!("KV entry {ns}/{key} did not exist")
                    }),
                    data: Some(json!({
                        "namespace": ns,
                        "key": key,
                        "deleted": res.deleted,
                        "previousVersion": res.previous_version,
                    })),
                    warnings: Vec::new(),
                    next: Vec::new(),
                    error: None,
                };
                print_json(&envelope);
            } else if res.deleted {
                println!(
                    "OK    Deleted {ns}/{key} (previous v{})",
                    res.previous_version.unwrap_or(0)
                );
            } else {
                println!("OK    KV entry {ns}/{key} was already absent");
            }
            ExitCode::from(EXIT_OK)
        }
        Err(StoreError::VersionConflict { current_version }) => {
            emit_version_conflict(cmd, as_json, &ns, &key, expected_version, current_version)
        }
        Err(StoreError::Unauthorized(msg)) => {
            emit_error(cmd, as_json, EXIT_ERROR, "UNAUTHORIZED", msg, None)
        }
        Err(e) => emit_error(cmd, as_json, EXIT_ERROR, "KV_ERROR", e.to_string(), None),
    }
}

fn run_kv_list(
    ns: String,
    prefix: Option<String>,
    node: String,
    state_dir: Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let cmd = "kv list";
    let (_dir, db) = match open_db(state_dir.as_ref()) {
        Ok(v) => v,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e, None),
    };

    match db.kv().list(&node, &ns, prefix.as_deref(), now_ms()) {
        Ok(entries) => {
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
                let envelope = JsonEnvelope {
                    ok: true,
                    command: cmd.to_string(),
                    summary: Some(format!("{} key(s) in '{node}/{ns}'", items.len())),
                    data: Some(json!({
                        "hostNode": node,
                        "namespace": ns,
                        "prefix": prefix,
                        "count": items.len(),
                        "entries": items,
                    })),
                    warnings: Vec::new(),
                    next: Vec::new(),
                    error: None,
                };
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
            ExitCode::from(EXIT_OK)
        }
        Err(e) => emit_error(cmd, as_json, EXIT_ERROR, "KV_ERROR", e.to_string(), None),
    }
}
