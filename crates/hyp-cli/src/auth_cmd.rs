//! `hyp auth` — Tier 1 Ed25519 Human Authority management, node certification (`hcert1_`),
//! offline/CLI drop signing (`hdrop1_`), and one-shot loopback `--web` Passkey+PRF enrollment.
//!
//! Security invariants:
//! - NEVER accepts private keys, secrets, or drop bodies via CLI argv flags (stdin or `--web` only!).
//! - NEVER prints private key material or drop plaintext to stdout, stderr, logs, or `--json`.
//! - Automatically re-signs `gate.human_authorities_digest` + `gate.policy_signature` whenever
//!   `node.json` has `gate.require_signed_policy == true`.

use crate::config_file::{
    ct_eq, default_node_id, ensure_dir, load_node_or_legacy_config, open_secret_store,
    read_json_object_or_empty, resolve_config_path_for_read, resolve_config_path_for_write,
    resolve_effective_node_id, resolve_state_dir, write_atomic_json,
};
use crate::gate_cmd::{
    ConfirmError, emit_confirm_error, is_interactive_tty, require_controlling_tty_confirmation,
    require_interactive_tty_confirmation,
};
use crate::ui::{
    EXIT_ERROR, EXIT_OK, EXIT_USAGE, JsonEnvelope, emit_error, print_json, print_next_steps,
    print_warnings,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::{Subcommand, ValueEnum};
use http::{HeaderValue, Method, Request, Response, StatusCode, header};
use http_body_util::{BodyExt, Full};
use hyp_crypto::human::{
    HumanAudience, HumanClaimV1, HumanDropKind, HumanRevocationPayloadV1, NodeCertPayloadV1,
    SecretDropSpec, SignedHumanRevocationV1, SignedNodeCertV1, decode_hcert1, encode_hdrop1,
    is_reserved_secret_name, seal_human_drop, sign_human_revocation, sign_local_ingest_event,
    verify_node_cert,
};
use hyp_crypto::jcs::to_canonical_json;
use hyp_crypto::keys::{Ed25519KeyPair, Ed25519PublicKey, OkpJwk, X25519PublicKey};
use hyp_crypto::keystore::{SecretStore, validate_secret_name};
use hyp_crypto::rfc3339::{format_rfc3339_millis, now_unix_ms, parse_rfc3339_millis};
use hyp_harness::sock::{DEFAULT_SOCKET_FILENAME, daemon_rpc_sync};
use hyp_node::engine::{
    LocalIngestConfig, NodeConfig, NodeProfile, UnifiedNode, canonical_local_event_for_signing,
    resolve_drop_portal_url, send_local_ingest_event,
};
use hyp_node::gates::policy::{SecurityGateConfig, sign_gate_policy, verify_gate_policy_sig};
use hyp_proto::address::{LOCAL_NODE_ID, NodeId, is_valid_handle, is_valid_node_id};
use hyp_proto::cloudevent::{
    CONTENT_TYPE_JSON, CloudEvent as ProtoCloudEvent, EXT_LOCAL_EVENT_SIG, TYPE_HUMAN_REVOCATION_V1,
};
use hyp_store::{
    HumanAuthorityInput, HumanAuthorityRecord, HumanAuthorityRole, HumanAuthorityStatus,
    HumanNodeCertInput, KeyUse, NodeDb, now_ms, uuid_v4,
};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::io::{self, IsTerminal as _, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

const MAX_JWK_STDIN_BYTES: u64 = 16 * 1024;
const MAX_SIGN_BODY_BYTES: u64 = 32 * 1024;
const MAX_ENROLL_CALLBACK_BYTES: usize = 16 * 1024;
const DEFAULT_WEB_TIMEOUT_SECS: u64 = 300;
const MAX_DROP_TTL_SECS: u64 = 900;
const LIVE_DAEMON_RPC_TIMEOUT: Duration = Duration::from_secs(2);
const HUMAN_REVOCATIONS_TOPIC: &str = "human.revocations";

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CliHumanRole {
    Signer,
    Admin,
}

impl CliHumanRole {
    pub const fn to_store_role(self) -> HumanAuthorityRole {
        match self {
            Self::Signer => HumanAuthorityRole::Signer,
            Self::Admin => HumanAuthorityRole::Admin,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CliDropKind {
    Directive,
    Secret,
}

impl CliDropKind {
    pub const fn to_crypto_kind(self) -> HumanDropKind {
        match self {
            Self::Directive => HumanDropKind::Directive,
            Self::Secret => HumanDropKind::Secret,
        }
    }
}

#[derive(Subcommand)]
pub enum AuthCommand {
    /// Initialize a local Ed25519 human admin authority, certify this node (hcert1_), and optionally enroll a Passkey via --web
    Init {
        /// Canonical human identifier (defaults to current OS username)
        #[arg(long)]
        human_id: Option<String>,
        /// Human-readable label for the local admin key
        #[arg(long, default_value = "local-cli-admin")]
        label: String,
        /// Also launch a one-shot loopback enrollment callback for https://hyphae.to/drop Passkey+PRF
        #[arg(long)]
        web: bool,
        /// Optional loopback port override for --web (0 = ephemeral OS port)
        #[arg(long, default_value_t = 0)]
        port: u16,
        /// Timeout in seconds waiting for --web enrollment callback (default: 300)
        #[arg(long, default_value_t = DEFAULT_WEB_TIMEOUT_SECS)]
        timeout: u64,
        /// Do not auto-open a browser window when --web is set
        #[arg(long)]
        no_open: bool,
        /// Explicit state directory containing node.sqlite and secrets/
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Explicit node.json path
        #[arg(long)]
        config: Option<PathBuf>,
        /// Output structured JSON envelope (never includes private keys)
        #[arg(long)]
        json: bool,
    },
    /// Enroll an external OKP Ed25519 public JWK (or site/drop enrollment bundle) strictly from stdin
    Add {
        /// Canonical human identifier for this authority
        #[arg(long)]
        human_id: String,
        /// Human-readable label (e.g. iphone-passkey, yubikey-backup)
        #[arg(long)]
        label: String,
        /// Authority role (signer or admin)
        #[arg(long, value_enum, default_value_t = CliHumanRole::Signer)]
        role: CliHumanRole,
        /// Optional WebAuthn PRF salt to store as a public hint
        #[arg(long, allow_hyphen_values = true)]
        prf_salt: Option<String>,
        /// Optional starting authEpoch (defaults to current minAuthEpoch)
        #[arg(long)]
        auth_epoch: Option<u64>,
        /// Explicit state directory containing node.sqlite and secrets/
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Explicit node.json path
        #[arg(long)]
        config: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// List registered human authorities, monotonic minAuthEpoch, and authoritiesDigest
    List {
        /// Include revoked authorities
        #[arg(long)]
        all: bool,
        /// Explicit state directory containing node.sqlite
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Monotonically revoke a human authority key (optionally bumping minAuthEpoch)
    Revoke {
        /// Authority RFC 7638 kid (full kid or unambiguous >=8-char prefix)
        #[arg(allow_hyphen_values = true)]
        kid: String,
        /// Increment minAuthEpoch monotonically to invalidate older claims & certs
        #[arg(long)]
        bump_epoch: bool,
        /// Revocation reason recorded in audit metadata
        #[arg(long, default_value = "revoked via hyp auth revoke")]
        reason: String,
        /// Explicit admin kid to sign SignedHumanRevocationV1 (defaults to local admin key)
        #[arg(long, allow_hyphen_values = true)]
        issuer_kid: Option<String>,
        /// Publish the signed HumanRevocationV1 CloudEvent (`to.hyphae.human.revocation.v1`) on topic `human.revocations`
        #[arg(long)]
        broadcast: bool,
        /// Explicit state directory containing node.sqlite and secrets/
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Explicit node.json path
        #[arg(long)]
        config: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Issue & persist a human-signed NodeCertV1 (hcert1_) for this node's Ed25519 + X25519 keys
    CertifyNode {
        /// Certificate validity duration in days (default: 365)
        #[arg(long, default_value_t = 365)]
        ttl_days: u32,
        /// Explicit admin authority kid (defaults to active local admin key)
        #[arg(long, allow_hyphen_values = true)]
        kid: Option<String>,
        /// Explicit state directory containing node.sqlite and secrets/
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Explicit node.json path
        #[arg(long)]
        config: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Sign & HPKE-seal a Verified Human Drop (hdrop1_) reading plaintext body strictly from stdin (NEVER argv!)
    Sign {
        /// Drop kind (directive or secret)
        #[arg(long, value_enum)]
        kind: CliDropKind,
        /// Target nodeId (defaults to local nodeId)
        #[arg(long)]
        node_id: Option<String>,
        /// Optional target local agent handle
        #[arg(long)]
        handle: Option<String>,
        /// SecretStore name (required when --kind secret; reserved system keys are hard-blocked)
        #[arg(long)]
        secret_name: Option<String>,
        /// Allow overwriting an existing secret of the same name
        #[arg(long)]
        overwrite: bool,
        /// Claim TTL in seconds (1..=900, default: 600)
        #[arg(long, default_value_t = 600)]
        ttl: u64,
        /// Optional dropId rendezvous binding (empty for offline hdrop1_ tokens)
        #[arg(long, allow_hyphen_values = true)]
        drop_id: Option<String>,
        /// Explicit local authority kid to sign with (defaults to active local admin key)
        #[arg(long, allow_hyphen_values = true)]
        kid: Option<String>,
        /// Explicit state directory containing node.sqlite and secrets/
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Explicit node.json path
        #[arg(long)]
        config: Option<PathBuf>,
        /// Output structured JSON envelope (NEVER includes plaintext body!)
        #[arg(long)]
        json: bool,
    },
}

pub fn run_auth(command: AuthCommand) -> ExitCode {
    match command {
        AuthCommand::Init {
            human_id,
            label,
            web,
            port,
            timeout,
            no_open,
            state_dir,
            config,
            json,
        } => run_auth_init(
            human_id, label, web, port, timeout, no_open, state_dir, config, json,
        ),
        AuthCommand::Add {
            human_id,
            label,
            role,
            prf_salt,
            auth_epoch,
            state_dir,
            config,
            json,
        } => run_auth_add(
            human_id, label, role, prf_salt, auth_epoch, state_dir, config, json,
        ),
        AuthCommand::List {
            all,
            state_dir,
            json,
        } => run_auth_list(all, state_dir, json),
        AuthCommand::Revoke {
            kid,
            bump_epoch,
            reason,
            issuer_kid,
            broadcast,
            state_dir,
            config,
            json,
        } => run_auth_revoke(
            kid, bump_epoch, reason, issuer_kid, broadcast, state_dir, config, json,
        ),
        AuthCommand::CertifyNode {
            ttl_days,
            kid,
            state_dir,
            config,
            json,
        } => run_auth_certify_node(ttl_days, kid, state_dir, config, json),
        AuthCommand::Sign {
            kind,
            node_id,
            handle,
            secret_name,
            overwrite,
            ttl,
            drop_id,
            kid,
            state_dir,
            config,
            json,
        } => run_auth_sign(
            kind,
            node_id,
            handle,
            secret_name,
            overwrite,
            ttl,
            drop_id,
            kid,
            state_dir,
            config,
            json,
        ),
    }
}

/// Computes a valid, collision-free reserved SecretStore key name for a local human admin Ed25519 key.
/// Always starts with `human-admin-` (which is blocked by the remote secret-drop denylist) and
/// strictly matches `validate_secret_name` (`/^[a-z0-9][a-z0-9._-]{0,63}$/`).
pub fn admin_secret_name_for_kid(kid: &str) -> String {
    let prefix: String = kid
        .chars()
        .take(8)
        .map(|c| {
            let low = c.to_ascii_lowercase();
            if low.is_ascii_lowercase() || low.is_ascii_digit() || matches!(low, '_' | '-') {
                low
            } else {
                'x'
            }
        })
        .collect();
    let hash = hex::encode(&Sha256::digest(kid.as_bytes())[..4]);
    format!("human-admin-{prefix}-{hash}")
}

fn legacy_admin_secret_name_for_kid(kid: &str) -> String {
    let prefix: String = kid
        .chars()
        .take(8)
        .map(|c| {
            let low = c.to_ascii_lowercase();
            if low.is_ascii_lowercase() || low.is_ascii_digit() || matches!(low, '_' | '-') {
                low
            } else {
                'x'
            }
        })
        .collect();
    format!("human-admin-{prefix}")
}

/// Loads a local human authority Ed25519 keypair from `SecretStore` and verifies its `kid`.
fn load_local_authority_keypair(
    secrets: &SecretStore,
    kid: &str,
) -> Result<Ed25519KeyPair, String> {
    let primary = admin_secret_name_for_kid(kid);
    let raw = match secrets.get(&primary) {
        Ok(val) => val,
        Err(_) => {
            let fallback = legacy_admin_secret_name_for_kid(kid);
            secrets.get(&fallback).map_err(|_| {
                format!(
                    "local signing key for authority kid '{kid}' was not found in SecretStore (expected '{primary}')"
                )
            })?
        }
    };
    let kp = Ed25519KeyPair::from_pkcs8_b64(&raw)
        .map_err(|e| format!("stored signing key for '{kid}' is corrupt: {e}"))?;
    if kp.kid() != kid {
        return Err(format!(
            "stored signing key kid '{}' does not match expected authority kid '{kid}'",
            kp.kid()
        ));
    }
    Ok(kp)
}

fn is_gate_locked(config_path: &Path) -> bool {
    if !config_path.exists() {
        return false;
    }
    let Ok(cfg_map) = read_json_object_or_empty(config_path) else {
        return true;
    };
    let Some(gate_val) = cfg_map.get("gate") else {
        return false;
    };
    if gate_val
        .get("require_signed_policy")
        .and_then(Value::as_bool)
        == Some(true)
    {
        return true;
    }
    serde_json::from_value::<SecurityGateConfig>(gate_val.clone())
        .map(|g| g.require_signed_policy)
        .unwrap_or(true)
}

fn format_auth_init_confirm_summary(
    human_id: &str,
    label: &str,
    existing_authorities: usize,
    gate_locked: bool,
) -> Vec<String> {
    let mut lines = vec![
        "Human Admin Authority Initialization Summary".to_string(),
        format!("  Human ID:   {human_id}"),
        format!("  Role:       admin"),
        format!("  Label:      {label}"),
        format!("  Existing:   {existing_authorities} authority record(s) already present"),
    ];
    if gate_locked {
        lines.push(
            "  WARNING:    Security Gate is LOCKED; gate_policy_sig will be re-signed with the updated human_authorities_digest."
                .to_string(),
        );
    }
    lines
}

#[allow(clippy::too_many_arguments)]
fn format_auth_add_confirm_summary(
    human_id: &str,
    role: HumanAuthorityRole,
    label: &str,
    kid: &str,
    auth_epoch: u64,
    enc_kid: Option<&str>,
    has_node_cert: bool,
    gate_locked: bool,
) -> Vec<String> {
    let mut lines = vec![
        "Human Authority Enrollment Summary".to_string(),
        format!("  Human ID:   {human_id}"),
        format!("  Role:       {}", role.as_str()),
        format!("  Label:      {label}"),
        format!("  Key ID:     {kid}"),
        format!("  Auth Epoch: {auth_epoch}"),
    ];
    if let Some(ekid) = enc_kid {
        lines.push(format!("  Enc Key ID: {ekid}"));
    }
    if has_node_cert {
        lines.push("  Node Cert:  verified hcert1_ included".to_string());
    }
    if gate_locked {
        lines.push(
            "  WARNING:    Security Gate is LOCKED; gate_policy_sig will be re-signed with the updated human_authorities_digest."
                .to_string(),
        );
    }
    lines
}

#[allow(clippy::too_many_arguments)]
fn format_auth_revoke_confirm_summary(
    target: &HumanAuthorityRecord,
    bump_epoch: bool,
    current_min: u64,
    new_min: u64,
    broadcast: bool,
    reason: &str,
    gate_locked: bool,
) -> Vec<String> {
    let mut lines = vec![
        "Human Authority Revocation Summary".to_string(),
        format!("  Human ID:   {}", target.human_id),
        format!("  Role:       {}", target.role.as_str()),
        format!("  Label:      {}", target.label),
        format!("  Key ID:     {}", target.kid),
        format!(
            "  Bump Epoch: {}",
            if bump_epoch {
                format!("yes ({current_min} -> {new_min})")
            } else {
                format!("no (stays {current_min})")
            }
        ),
        format!(
            "  Broadcast:  {}",
            if broadcast {
                "yes (topic: human.revocations)"
            } else {
                "no (local only)"
            }
        ),
        format!("  Reason:     {reason}"),
    ];
    if gate_locked {
        lines.push(
            "  WARNING:    Security Gate is LOCKED; gate_policy_sig will be re-signed with the updated human_authorities_digest."
                .to_string(),
        );
    }
    lines
}

/// If `config_path` exists and `gate.require_signed_policy == true`, updates
/// `gate.human_authorities_digest = Some(db.human().authorities_digest()?)` and re-signs
/// `gate.policy_signature` via `sign_gate_policy`.
pub fn sync_gate_policy_digest_if_locked(
    config_path: &Path,
    _state_dir: &Path,
    db: &NodeDb,
    secrets: &SecretStore,
) -> Result<bool, String> {
    if !config_path.exists() {
        return Ok(false);
    }
    let mut cfg_map = read_json_object_or_empty(config_path)?;
    let Some(gate_val) = cfg_map.get("gate") else {
        return Ok(false);
    };
    let mut gate_cfg: SecurityGateConfig = serde_json::from_value(gate_val.clone())
        .map_err(|e| format!("malformed gate config in {}: {e}", config_path.display()))?;
    if !gate_cfg.require_signed_policy {
        return Ok(false);
    }

    let digest = db
        .human()
        .authorities_digest()
        .map_err(|e| format!("failed to compute human authorities digest: {e}"))?;
    gate_cfg.human_authorities_digest = Some(digest);
    gate_cfg.policy_signature = None;

    let sig = sign_gate_policy(&gate_cfg, secrets)
        .map_err(|e| format!("failed to re-sign gate policy: {e}"))?;
    verify_gate_policy_sig(&gate_cfg, &sig, secrets)
        .map_err(|e| format!("failed to verify re-signed gate policy: {e}"))?;
    gate_cfg.policy_signature = Some(sig);

    let updated_gate = serde_json::to_value(&gate_cfg)
        .map_err(|e| format!("failed to serialize updated gate config: {e}"))?;
    cfg_map.insert("gate".to_string(), updated_gate);
    write_atomic_json(config_path, &Value::Object(cfg_map), true)?;
    Ok(true)
}

fn resolve_daemon_socket_for_auth(
    explicit_state_dir: bool,
    explicit_config: bool,
    resolved_state_dir: &Path,
) -> PathBuf {
    if !explicit_state_dir && !explicit_config {
        for key in ["HYPHAE_SOCKET", "AGENTS_MESH_SOCKET"] {
            if let Ok(sock) = std::env::var(key) {
                let trimmed = sock.trim();
                if !trimmed.is_empty() {
                    return PathBuf::from(trimmed);
                }
            }
        }
    }
    resolved_state_dir.join(DEFAULT_SOCKET_FILENAME)
}

/// Attempts a live `gate.reload` IPC RPC against a running daemon after re-signing a locked gate
/// policy. Returns `(gate_reloaded, error_detail)` and appends actionable warnings + restart hint
/// whenever live reload did not confirm success.
fn reload_live_gate_after_resign(
    explicit_state_dir: bool,
    explicit_config: bool,
    state_dir: &Path,
    warnings: &mut Vec<String>,
    next: &mut Vec<String>,
) -> (bool, Option<String>) {
    let sock = resolve_daemon_socket_for_auth(explicit_state_dir, explicit_config, state_dir);
    let resp = daemon_rpc_sync(
        &sock,
        &json!({ "type": "gate.reload" }),
        LIVE_DAEMON_RPC_TIMEOUT,
    );
    let reloaded = resp.ok
        && resp
            .result
            .as_ref()
            .and_then(|r| r.get("reloaded"))
            .and_then(Value::as_bool)
            == Some(true);
    if reloaded {
        return (true, None);
    }
    let detail = resp
        .error
        .unwrap_or_else(|| "running daemon did not confirm gate reload".to_string());
    warnings.push(format!(
        "Locked Security Gate policy was re-signed on disk, but live daemon gate.reload did not complete ({detail}); restart the daemon so inbound traffic is not quarantined."
    ));
    let restart_cmd = "hyp service restart --json".to_string();
    if !next.contains(&restart_cmd) {
        next.insert(0, restart_cmd);
    }
    (false, Some(detail))
}

struct RevocationBroadcastOutcome {
    event_id: String,
    topic: String,
    via: &'static str,
    matched: usize,
}

fn broadcast_human_revocation(
    state_dir: &Path,
    config_read: &Path,
    secrets: &SecretStore,
    signed: &SignedHumanRevocationV1,
    issuer_kp: &Ed25519KeyPair,
    target: &HumanAuthorityRecord,
    revoked_at: &str,
) -> Result<RevocationBroadcastOutcome, String> {
    let loaded = if config_read.exists() {
        load_node_or_legacy_config(config_read).ok()
    } else {
        None
    };
    let local_node_id = {
        let db = NodeDb::open(state_dir.join("node.sqlite"))
            .map_err(|e| format!("failed to open node.sqlite: {e}"))?;
        resolve_effective_node_id(loaded.as_ref(), Some(&db))
    };

    let data_val = serde_json::to_value(signed)
        .map_err(|e| format!("failed to serialize SignedHumanRevocationV1: {e}"))?;
    let event_id = format!("human-rev-{}", uuid_v4());
    let mut ce = ProtoCloudEvent::new(
        event_id.clone(),
        format!("hyphae://{local_node_id}/auth"),
        TYPE_HUMAN_REVOCATION_V1,
        data_val,
    );
    ce.subject = Some(format!("{}:{}", target.human_id, target.kid));
    ce.time = Some(revoked_at.to_string());
    ce.datacontenttype = Some(CONTENT_TYPE_JSON.to_string());

    let local_ingest_cfg: LocalIngestConfig = loaded
        .as_ref()
        .and_then(|c| c.raw.get("localIngest"))
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();
    let ingest_socket = local_ingest_cfg.resolved_socket_path(state_dir);

    // 1. Prefer live local ingest socket when running and permitted by route policy so active
    //    SSE peer subscribers receive the event immediately.
    if ingest_socket.exists() {
        let mut signed_ce = ce.clone();
        if let Ok(canonical) = canonical_local_event_for_signing(&signed_ce) {
            let sig = sign_local_ingest_event(issuer_kp, &canonical);
            signed_ce.set_extension(EXT_LOCAL_EVENT_SIG, sig);
        }
        if let Ok(Value::Object(mut wire_obj)) = serde_json::to_value(&signed_ce) {
            wire_obj.insert(
                "topic".to_string(),
                Value::String(HUMAN_REVOCATIONS_TOPIC.to_string()),
            );
            let wire_json = Value::Object(wire_obj);
            if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                if let Ok(receipt) = rt.block_on(send_local_ingest_event(&ingest_socket, &wire_json))
                {
                    if receipt.get("ok").and_then(Value::as_bool) == Some(true) {
                        let receipt_id = receipt
                            .get("id")
                            .and_then(Value::as_str)
                            .unwrap_or(&event_id)
                            .to_string();
                        let matched = receipt
                            .get("matchedSubscribers")
                            .and_then(Value::as_u64)
                            .unwrap_or(0) as usize;
                        return Ok(RevocationBroadcastOutcome {
                            event_id: receipt_id,
                            topic: HUMAN_REVOCATIONS_TOPIC.to_string(),
                            via: "local_ingest",
                            matched,
                        });
                    }
                }
            }
        }
    }

    // 2. Fallback: durably ingest the CloudEvent into local EventStore on `human.revocations`
    //    via UnifiedNode so paired peers subscribed to `human.revocations` receive and apply it.
    let node = open_local_unified_node(state_dir, config_read, secrets)?;
    let ingest_res = node
        .ingest_inbound_event(&local_node_id, HUMAN_REVOCATIONS_TOPIC, &ce)
        .map_err(|e| format!("failed to publish human revocation event to EventStore: {e}"))?;
    Ok(RevocationBroadcastOutcome {
        event_id,
        topic: HUMAN_REVOCATIONS_TOPIC.to_string(),
        via: "event_store",
        matched: ingest_res.matched,
    })
}

fn default_human_id() -> String {
    if let Ok(u) = std::env::var("USER").or_else(|_| std::env::var("USERNAME")) {
        let cleaned = sanitize_human_id(&u);
        if !cleaned.is_empty() && cleaned != LOCAL_NODE_ID && is_valid_node_id(&cleaned) {
            return cleaned;
        }
    }
    let node = default_node_id();
    let prefix = node.split('@').next().unwrap_or("operator");
    let cleaned = sanitize_human_id(prefix);
    if !cleaned.is_empty() && cleaned != LOCAL_NODE_ID && is_valid_node_id(&cleaned) {
        cleaned
    } else {
        "operator".to_string()
    }
}

fn sanitize_human_id(raw: &str) -> String {
    let mut out = String::new();
    for ch in raw.chars() {
        let low = ch.to_ascii_lowercase();
        if low.is_ascii_alphanumeric() || matches!(low, '.' | '_' | '-' | '@') {
            out.push(low);
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches(|c: char| !c.is_ascii_alphanumeric())
        .chars()
        .take(64)
        .collect()
}

fn random_b64url(len: usize) -> Result<String, String> {
    let mut buf = vec![0u8; len];
    SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| "OS CSPRNG failure".to_string())?;
    Ok(URL_SAFE_NO_PAD.encode(&buf))
}

fn parse_optional_enc_jwk(val: Option<&Value>) -> Result<Option<(String, String)>, String> {
    let Some(raw) = val else {
        return Ok(None);
    };
    if raw.is_null() {
        return Ok(None);
    }
    let jwk: OkpJwk = serde_json::from_value(raw.clone())
        .map_err(|e| format!("malformed encJwk OKP object: {e}"))?;
    if jwk.kty != "OKP" || jwk.crv != "X25519" {
        return Err(format!(
            "encJwk must be OKP/X25519, got {}/{}",
            jwk.kty, jwk.crv
        ));
    }
    let pk = jwk
        .to_x25519()
        .map_err(|e| format!("invalid X25519 public key in encJwk: {e}"))?;
    let canonical =
        to_canonical_json(&jwk).map_err(|e| format!("failed to canonicalize encJwk: {e}"))?;
    Ok(Some((canonical, pk.kid())))
}

struct VerifiedEnrolledNodeCert {
    signed: SignedNodeCertV1,
    payload: NodeCertPayloadV1,
    issued_at_ms: i64,
    expires_at_ms: i64,
    armored: String,
}

fn validate_enrolled_node_cert(
    raw_hcert1: &str,
    authority_pk: &Ed25519PublicKey,
    expected_human_id: &str,
    expected_node_id: &str,
    expected_sign_x: &str,
    expected_enc_x: &str,
    min_auth_epoch: u64,
) -> Result<VerifiedEnrolledNodeCert, String> {
    let trimmed = raw_hcert1.trim();
    let signed = decode_hcert1(trimmed).map_err(|e| format!("invalid nodeCert hcert1_: {e}"))?;
    let payload = verify_node_cert(&signed, authority_pk, now_ms(), min_auth_epoch)
        .map_err(|e| format!("nodeCert verification failed: {e}"))?;
    if payload.node_id != expected_node_id {
        return Err(format!(
            "nodeCert nodeId '{}' does not match local node '{}'",
            payload.node_id, expected_node_id
        ));
    }
    if payload.signing_jwk.x != expected_sign_x {
        return Err("nodeCert signingJwk does not match local node Ed25519 key".to_string());
    }
    if payload.encryption_jwk.x != expected_enc_x {
        return Err("nodeCert encryptionJwk does not match local node X25519 key".to_string());
    }
    if payload.human_id != expected_human_id {
        return Err(format!(
            "nodeCert humanId '{}' does not match enrolled humanId '{expected_human_id}'",
            payload.human_id
        ));
    }
    let issued_at_ms = parse_rfc3339_millis(&payload.issued_at)
        .map_err(|e| format!("invalid nodeCert issuedAt: {e}"))?;
    let expires_at_ms = parse_rfc3339_millis(&payload.expires_at)
        .map_err(|e| format!("invalid nodeCert expiresAt: {e}"))?;
    Ok(VerifiedEnrolledNodeCert {
        signed,
        payload,
        issued_at_ms,
        expires_at_ms,
        armored: trimmed.to_string(),
    })
}

fn persist_verified_node_cert(
    db: &NodeDb,
    cert: &VerifiedEnrolledNodeCert,
) -> Result<(), String> {
    let signed_json = to_canonical_json(&cert.signed)
        .map_err(|e| format!("failed to serialize verified nodeCert: {e}"))?;
    db.human()
        .put_node_cert(&HumanNodeCertInput {
            node_id: cert.payload.node_id.clone(),
            human_kid: cert.payload.human_kid.clone(),
            auth_epoch: cert.payload.auth_epoch,
            signed_json,
            issued_at: cert.issued_at_ms,
            expires_at: cert.expires_at_ms,
        })
        .map_err(|e| format!("failed to persist verified nodeCert: {e}"))?;
    Ok(())
}

fn open_local_unified_node(
    state_dir: &Path,
    config_path: &Path,
    secrets: &SecretStore,
) -> Result<Arc<UnifiedNode>, String> {
    let loaded = if config_path.exists() {
        Some(load_node_or_legacy_config(config_path)?)
    } else {
        None
    };
    let node_id_str = {
        let db = NodeDb::open(state_dir.join("node.sqlite"))
            .map_err(|e| format!("failed to open node.sqlite: {e}"))?;
        resolve_effective_node_id(loaded.as_ref(), Some(&db))
    };
    let node_id = NodeId::new(&node_id_str)
        .map_err(|e| format!("invalid local nodeId '{node_id_str}': {e}"))?;
    let profile = loaded
        .as_ref()
        .and_then(|c| c.profile)
        .unwrap_or(NodeProfile::Local);
    let mut cfg = NodeConfig::new(node_id, profile, state_dir);
    cfg.secret_backend = Some(secrets.backend());
    UnifiedNode::open(cfg).map_err(|e| format!("failed to open UnifiedNode: {e}"))
}

#[allow(clippy::too_many_arguments)]
fn run_auth_init(
    human_id_arg: Option<String>,
    label: String,
    web: bool,
    port: u16,
    timeout_secs: u64,
    no_open: bool,
    state_dir_arg: Option<PathBuf>,
    config_arg: Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let cmd = "auth init";
    let human_id = human_id_arg
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(default_human_id);

    if human_id == LOCAL_NODE_ID || !is_valid_node_id(&human_id) {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "INVALID_HUMAN_ID",
            format!(
                "Invalid --human-id '{human_id}': must match /^[a-z0-9][a-z0-9@._-]{{0,63}}$/ and not be 'local'"
            ),
            Some("Example: hyp auth init --human-id alice".to_string()),
        );
    }

    let trimmed_label = label.trim();
    if trimmed_label.is_empty() || trimmed_label.len() > 128 {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "INVALID_LABEL",
            "--label must be 1..=128 printable characters",
            None,
        );
    }

    let state_dir = resolve_state_dir(state_dir_arg.as_deref(), config_arg.as_deref(), None);
    let config_read =
        resolve_config_path_for_read(config_arg.as_deref(), state_dir_arg.as_deref(), None);
    let config_write =
        resolve_config_path_for_write(config_arg.as_deref(), state_dir_arg.as_deref(), None);

    // Resolve and validate Drop Portal URL fail-closed BEFORE generating keys or opening callbacks.
    let resolved_drop_portal_url = if web {
        let configured_drop_portal_url: Option<String> = if config_read.exists() {
            match load_node_or_legacy_config(&config_read) {
                Ok(cfg) => match cfg.raw.get("dropPortalUrl") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(s)) => Some(s.clone()),
                    Some(_) => {
                        return emit_error(
                            cmd,
                            as_json,
                            EXIT_ERROR,
                            "CONFIG_ERROR",
                            format!(
                                "Invalid dropPortalUrl in {}: must be a string",
                                cfg.path.display()
                            ),
                            Some(
                                "Set dropPortalUrl to an https:// URL (e.g. \"https://hyphae.to/drop\") or loopback http://127.0.0.1."
                                    .to_string(),
                            ),
                        );
                    }
                },
                Err(_) => None,
            }
        } else {
            None
        };
        match resolve_drop_portal_url(configured_drop_portal_url.as_deref()) {
            Ok(u) => Some(u),
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "CONFIG_ERROR",
                    format!("Invalid Drop Portal URL: {e}"),
                    Some(
                        "Set HYPHAE_DROP_PORTAL_URL or node.json dropPortalUrl to an https:// URL (e.g. https://hyphae.to/drop) or loopback http://127.0.0.1."
                            .to_string(),
                    ),
                );
            }
        }
    } else {
        None
    };

    // Non-web `auth init` on a node that ALREADY has authorities or a locked Security Gate
    // requires unskippable interactive TTY confirmation (`#10` / `H1`).
    // Initial `auth init` on a brand-new unlocked node and `--web` (live Passkey ceremony)
    // continue seamlessly.
    if !web {
        let gate_locked = is_gate_locked(&config_read);
        let db_path = state_dir.join("node.sqlite");
        let existing_count = if db_path.exists() {
            match NodeDb::open(&db_path) {
                Ok(db) => db
                    .human()
                    .list_authorities(true)
                    .map(|v| v.len())
                    .unwrap_or(1),
                Err(_) => 1,
            }
        } else {
            0
        };
        if existing_count > 0 || gate_locked {
            let summary = format_auth_init_confirm_summary(
                &human_id,
                trimmed_label,
                existing_count,
                gate_locked,
            );
            let prompt = format!(
                "Initialize additional human admin authority '{human_id}' (label: {trimmed_label})? [y/N]: "
            );
            if let Err(err) = require_interactive_tty_confirmation(&summary, &prompt) {
                return emit_confirm_error(cmd, as_json, err);
            }
        }
    }

    if let Err(e) = ensure_dir(&state_dir, true) {
        return emit_error(cmd, as_json, EXIT_ERROR, "IO_ERROR", e, None);
    }

    let secrets = open_secret_store(&state_dir, state_dir_arg.is_some());
    let admin_kp = match Ed25519KeyPair::generate() {
        Ok(kp) => kp,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "KEYGEN_FAILED",
                format!("Failed to generate Ed25519 admin keypair: {e}"),
                None,
            );
        }
    };
    let kid = admin_kp.kid();
    let jwk = admin_kp.to_jwk();
    let jwk_json = match to_canonical_json(&jwk) {
        Ok(s) => s,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "JSON_ERROR", e.to_string(), None),
    };
    let secret_name = admin_secret_name_for_kid(&kid);
    let pkcs8_b64 = admin_kp.export_pkcs8_b64();
    if let Err(e) = secrets.set(&secret_name, &pkcs8_b64) {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "SECRET_STORE_ERROR",
            format!("Failed to persist admin signing key in SecretStore: {e}"),
            None,
        );
    }
    drop(pkcs8_b64);

    let node = match open_local_unified_node(&state_dir, &config_read, &secrets) {
        Ok(n) => n,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "NODE_OPEN_FAILED", e, None),
    };

    let min_epoch = {
        let db = node.db();
        match db.human().min_auth_epoch() {
            Ok(e) => e,
            Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e.to_string(), None),
        }
    };

    let inserted = {
        let db = node.db();
        match db.human().upsert_authority(
            &HumanAuthorityInput {
                human_id: human_id.clone(),
                kid: kid.clone(),
                label: trimmed_label.to_string(),
                role: HumanAuthorityRole::Admin,
                jwk_json: jwk_json.clone(),
                enc_jwk_json: None,
                prf_salt: None,
                auth_epoch: min_epoch,
            },
            now_ms(),
        ) {
            Ok(rec) => rec,
            Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e.to_string(), None),
        }
    };

    let mut web_enrolled: Option<Value> = None;
    let mut passkey_hcert1: Option<String> = None;
    if web {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "RUNTIME_ERROR",
                    format!("Failed to start async runtime: {e}"),
                    None,
                );
            }
        };
        let node_sign_jwk = node.identity().signing_jwk();
        let node_enc_jwk = node.identity().encryption_jwk();
        let drop_portal_url = resolved_drop_portal_url
            .as_deref()
            .expect("resolved_drop_portal_url set when web is true");
        let enrolled = match rt.block_on(enroll_passkey_via_web(
            drop_portal_url,
            &human_id,
            min_epoch,
            node.node_id().as_str(),
            &node_sign_jwk,
            &node_enc_jwk,
            port,
            timeout_secs,
            no_open,
            &secrets,
        )) {
            Ok(e) => e,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "WEB_ENROLL_FAILED",
                    e,
                    Some("Run `hyp auth add --human-id <id> --label <name>` and pipe the public JWK via stdin instead.".to_string()),
                );
            }
        };

        let signer_rec = {
            let db = node.db();
            match db.human().upsert_authority(
                &HumanAuthorityInput {
                    human_id: enrolled.human_id.clone(),
                    kid: enrolled.kid.clone(),
                    label: enrolled.label.clone(),
                    role: HumanAuthorityRole::Signer,
                    jwk_json: enrolled.jwk_json.clone(),
                    enc_jwk_json: enrolled.enc_jwk_json.clone(),
                    prf_salt: Some(enrolled.prf_salt.clone()),
                    auth_epoch: enrolled.auth_epoch,
                },
                now_ms(),
            ) {
                Ok(r) => r,
                Err(e) => {
                    return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e.to_string(), None);
                }
            }
        };
        if let Some(ref verified_cert) = enrolled.node_cert {
            let db = node.db();
            if let Err(e) = persist_verified_node_cert(&db, verified_cert) {
                return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e, None);
            }
            passkey_hcert1 = Some(verified_cert.armored.clone());
        }
        web_enrolled = Some(json!({
            "humanId": signer_rec.human_id,
            "kid": signer_rec.kid,
            "role": signer_rec.role.as_str(),
            "label": signer_rec.label,
            "encKey": signer_rec.enc_jwk_json.is_some(),
            "encKid": enrolled.enc_kid,
            "prfSalt": signer_rec.prf_salt,
            "authEpoch": signer_rec.auth_epoch,
            "credentialId": enrolled.credential_id,
            "nodeCertSigned": enrolled.node_cert.is_some(),
        }));
    }

    let hcert1 = if let Some(cert_token) = passkey_hcert1 {
        cert_token
    } else {
        match node.issue_node_cert(&admin_kp, &kid, 365) {
            Ok((_signed_cert, token)) => token,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "CERTIFY_FAILED",
                    format!("Failed to certify local node: {e}"),
                    None,
                );
            }
        }
    };

    let gate_resigned = {
        let db = node.db();
        match sync_gate_policy_digest_if_locked(&config_write, &state_dir, &db, &secrets) {
            Ok(b) => b,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "GATE_POLICY_SYNC_FAILED",
                    e,
                    None,
                );
            }
        }
    };

    let digest = {
        let db = node.db();
        db.human().authorities_digest().ok()
    };
    let node_id_str = node.node_id().as_str().to_string();
    drop(node);

    let mut warnings = Vec::new();
    let mut next = vec![
        format!("hyp auth list --state-dir {}", state_dir.display()),
        format!(
            "hyp drop create --kind directive --offline --state-dir {}",
            state_dir.display()
        ),
    ];
    let (gate_reloaded, gate_reload_error) = if gate_resigned {
        reload_live_gate_after_resign(
            state_dir_arg.is_some(),
            config_arg.is_some(),
            &state_dir,
            &mut warnings,
            &mut next,
        )
    } else {
        (false, None)
    };

    if as_json {
        let mut data = json!({
            "humanId": inserted.human_id,
            "kid": inserted.kid,
            "role": inserted.role.as_str(),
            "label": inserted.label,
            "authEpoch": inserted.auth_epoch,
            "publicJwk": jwk,
            "secretName": secret_name,
            "secretBackend": secrets.backend().as_str(),
            "nodeId": node_id_str,
            "nodeCert": hcert1,
            "authoritiesDigest": digest,
            "gatePolicyResigned": gate_resigned,
            "gateReloaded": gate_reloaded,
            "webEnrolled": web_enrolled,
            "stateDir": state_dir.display().to_string(),
        });
        if let Some(ref err) = gate_reload_error {
            data["gateReloadError"] = json!(err);
        }
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(format!(
                "Initialized human admin authority '{}' (kid {}) and certified node '{}'",
                inserted.human_id, inserted.kid, node_id_str
            )),
            data: Some(data),
            warnings,
            next,
            error: None,
        };
        print_json(&envelope);
    } else {
        println!(
            "OK    Initialized human admin authority '{}' (kid={})",
            inserted.human_id, inserted.kid
        );
        println!("      Label:     {}", inserted.label);
        println!("      Keystore:  {} ({})", secret_name, secrets.backend().as_str());
        println!("      Node Cert: issued 365d hcert1_ for '{node_id_str}'");
        if let Some(ref w) = web_enrolled {
            println!(
                "      Passkey:   enrolled signer kid={}",
                w.get("kid").and_then(Value::as_str).unwrap_or("-")
            );
        }
        if gate_resigned {
            println!("      Gate Sig:  re-signed with updated human_authorities_digest");
            if gate_reloaded {
                println!("      Gate Live: reloaded active daemon policy (no restart needed)");
            }
        }
        print_warnings(&warnings);
        print_next_steps(&next);
    }

    ExitCode::from(EXIT_OK)
}

#[allow(clippy::too_many_arguments)]
fn run_auth_add(
    human_id_raw: String,
    label: String,
    role: CliHumanRole,
    prf_salt_arg: Option<String>,
    auth_epoch_arg: Option<u64>,
    state_dir_arg: Option<PathBuf>,
    config_arg: Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let cmd = "auth add";
    let human_id = human_id_raw.trim().to_ascii_lowercase();
    if human_id == LOCAL_NODE_ID || !is_valid_node_id(&human_id) {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "INVALID_HUMAN_ID",
            format!("Invalid --human-id '{human_id_raw}'"),
            None,
        );
    }
    let trimmed_label = label.trim();
    if trimmed_label.is_empty() || trimmed_label.len() > 128 {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "INVALID_LABEL",
            "--label must be 1..=128 printable characters",
            None,
        );
    }

    // Fail closed immediately when not attached to an interactive human terminal (`#10` / `H1`).
    // Checking `stderr.is_terminal()` allows `hyp auth add < key.jwk` in a real human terminal
    // (confirming via `/dev/tty` / `CONIN$`) while blocking non-TTY agent subprocesses before I/O.
    if !io::stderr().is_terminal() {
        return emit_confirm_error(cmd, as_json, ConfirmError::NotInteractiveTty);
    }

    let mut raw = String::new();
    if let Err(e) = io::stdin()
        .lock()
        .take(MAX_JWK_STDIN_BYTES + 1)
        .read_to_string(&mut raw)
    {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "STDIN_ERROR",
            format!("Failed to read public JWK from stdin: {e}"),
            None,
        );
    }
    if raw.len() as u64 > MAX_JWK_STDIN_BYTES {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "PAYLOAD_TOO_LARGE",
            format!("Stdin JWK payload exceeds {MAX_JWK_STDIN_BYTES} byte safety cap"),
            None,
        );
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "EMPTY_STDIN",
            "Expected OKP Ed25519 public JWK JSON on stdin",
            Some("Pipe public JWK JSON: echo '{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"...\"}' | hyp auth add --human-id alice --label phone".to_string()),
        );
    }

    let parsed: Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_JSON",
                format!("Invalid JWK JSON on stdin: {e}"),
                None,
            );
        }
    };

    // Accept either a raw OKP JWK or a site/drop enrollment bundle
    // `{ jwk/publicJwk, encJwk?, nodeCert?, prfSalt?, authEpoch?, kid? }`.
    let (
        jwk_val,
        bundle_enc_jwk_val,
        bundle_node_cert,
        bundle_prf_salt,
        bundle_epoch,
        expected_kid,
    ) = if let Some(obj) = parsed.as_object() {
        if let Some(inner) = obj.get("jwk").or_else(|| obj.get("publicJwk")) {
            (
                inner.clone(),
                obj.get("encJwk").cloned(),
                obj.get("nodeCert")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(ToOwned::to_owned),
                obj.get("prfSalt").and_then(Value::as_str).map(ToOwned::to_owned),
                obj.get("authEpoch").and_then(Value::as_u64),
                obj.get("kid").and_then(Value::as_str).map(ToOwned::to_owned),
            )
        } else {
            (parsed, None, None, None, None, None)
        }
    } else {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "INVALID_JWK",
            "Expected a JSON object containing an OKP Ed25519 public JWK",
            None,
        );
    };

    let jwk: OkpJwk = match serde_json::from_value(jwk_val) {
        Ok(j) => j,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_JWK",
                format!("Malformed OKP JWK: {e}"),
                None,
            );
        }
    };
    let authority_ed_pk = match jwk.to_ed25519() {
        Ok(pk) => pk,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_JWK",
                format!("Public key must be a valid OKP Ed25519 JWK: {e}"),
                None,
            );
        }
    };
    let (enc_jwk_json, enc_kid) = match parse_optional_enc_jwk(bundle_enc_jwk_val.as_ref()) {
        Ok(Some((canon, ekid))) => (Some(canon), Some(ekid)),
        Ok(None) => (None, None),
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_ENC_JWK",
                e,
                None,
            );
        }
    };
    let kid = match jwk.thumbprint() {
        Ok(k) => k,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_JWK",
                format!("Failed to compute RFC 7638 kid: {e}"),
                None,
            );
        }
    };
    if let Some(ref exp) = expected_kid {
        if exp != &kid {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "KID_MISMATCH",
                format!("Bundle kid '{exp}' does not match JWK thumbprint '{kid}'"),
                None,
            );
        }
    }
    let canonical_jwk_json = match to_canonical_json(&jwk) {
        Ok(s) => s,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "JSON_ERROR", e.to_string(), None),
    };

    let state_dir = resolve_state_dir(state_dir_arg.as_deref(), config_arg.as_deref(), None);
    let config_read =
        resolve_config_path_for_read(config_arg.as_deref(), state_dir_arg.as_deref(), None);
    let config_write =
        resolve_config_path_for_write(config_arg.as_deref(), state_dir_arg.as_deref(), None);
    if let Err(e) = ensure_dir(&state_dir, true) {
        return emit_error(cmd, as_json, EXIT_ERROR, "IO_ERROR", e, None);
    }

    let db = match NodeDb::open(state_dir.join("node.sqlite")) {
        Ok(db) => db,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e.to_string(), None),
    };
    let min_epoch = db.human().min_auth_epoch().unwrap_or(1);
    let effective_epoch = auth_epoch_arg.or(bundle_epoch).unwrap_or(min_epoch).max(min_epoch);
    let effective_prf_salt = prf_salt_arg.or(bundle_prf_salt);
    let secrets = open_secret_store(&state_dir, state_dir_arg.is_some());

    // Validate optional Passkey-signed `nodeCert` (`hcert1_`) BEFORE mutating DB so invalid bundles
    // fail closed cleanly.
    let verified_bundle_cert = if let Some(ref raw_cert) = bundle_node_cert {
        let loaded = if config_read.exists() {
            load_node_or_legacy_config(&config_read).ok()
        } else {
            None
        };
        let local_node_id = resolve_effective_node_id(loaded.as_ref(), Some(&db));
        let local_identity = match secrets.load_or_create_node_keys(&local_node_id) {
            Ok(keys) => keys,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "NODE_KEY_ERROR",
                    format!("Failed to load local node identity keys: {e}"),
                    None,
                );
            }
        };
        match validate_enrolled_node_cert(
            raw_cert,
            &authority_ed_pk,
            &human_id,
            &local_node_id,
            &local_identity.signing_jwk().x,
            &local_identity.encryption_jwk().x,
            min_epoch,
        ) {
            Ok(cert) => Some(cert),
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_USAGE,
                    "INVALID_NODE_CERT",
                    e,
                    None,
                );
            }
        }
    } else {
        None
    };

    let gate_locked = is_gate_locked(&config_read);
    let summary = format_auth_add_confirm_summary(
        &human_id,
        role.to_store_role(),
        trimmed_label,
        &kid,
        effective_epoch,
        enc_kid.as_deref(),
        verified_bundle_cert.is_some(),
        gate_locked,
    );
    let kid8: String = kid.chars().take(8).collect();
    let prompt = format!(
        "Enroll human authority '{human_id}' (role: {}, kid: {kid8})? [y/N]: ",
        role.to_store_role().as_str()
    );
    if let Err(err) = require_controlling_tty_confirmation(&summary, &prompt) {
        return emit_confirm_error(cmd, as_json, err);
    }

    let rec = match db.human().upsert_authority(
        &HumanAuthorityInput {
            human_id: human_id.clone(),
            kid: kid.clone(),
            label: trimmed_label.to_string(),
            role: role.to_store_role(),
            jwk_json: canonical_jwk_json,
            enc_jwk_json,
            prf_salt: effective_prf_salt,
            auth_epoch: effective_epoch,
        },
        now_ms(),
    ) {
        Ok(r) => r,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e.to_string(), None),
    };

    let node_cert_stored = if let Some(ref cert) = verified_bundle_cert {
        if let Err(e) = persist_verified_node_cert(&db, cert) {
            return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e, None);
        }
        true
    } else {
        false
    };

    let gate_resigned = match sync_gate_policy_digest_if_locked(&config_write, &state_dir, &db, &secrets)
    {
        Ok(b) => b,
        Err(e) => {
            return emit_error(cmd, as_json, EXIT_ERROR, "GATE_POLICY_SYNC_FAILED", e, None);
        }
    };
    let digest = db.human().authorities_digest().ok();
    drop(db);

    let mut warnings = Vec::new();
    let mut next = vec![format!("hyp auth list --state-dir {}", state_dir.display())];
    let (gate_reloaded, gate_reload_error) = if gate_resigned {
        reload_live_gate_after_resign(
            state_dir_arg.is_some(),
            config_arg.is_some(),
            &state_dir,
            &mut warnings,
            &mut next,
        )
    } else {
        (false, None)
    };

    if as_json {
        let mut data = json!({
            "humanId": rec.human_id,
            "kid": rec.kid,
            "role": rec.role.as_str(),
            "label": rec.label,
            "authEpoch": rec.auth_epoch,
            "encKey": rec.enc_jwk_json.is_some(),
            "encKid": enc_kid,
            "nodeCertStored": node_cert_stored,
            "prfSalt": rec.prf_salt,
            "status": rec.status.as_str(),
            "authoritiesDigest": digest,
            "gatePolicyResigned": gate_resigned,
            "gateReloaded": gate_reloaded,
        });
        if let Some(ref err) = gate_reload_error {
            data["gateReloadError"] = json!(err);
        }
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(format!(
                "Enrolled human authority '{}' ({}) kid {}",
                rec.human_id,
                rec.role.as_str(),
                rec.kid
            )),
            data: Some(data),
            warnings,
            next,
            error: None,
        };
        print_json(&envelope);
    } else {
        println!(
            "OK    Enrolled human authority '{}' (role={}, kid={})",
            rec.human_id,
            rec.role.as_str(),
            rec.kid
        );
        println!("      Label:    {}", rec.label);
        if let Some(ref ekid) = enc_kid {
            println!("      Enc Key:  yes (encKid={ekid})");
        }
        if node_cert_stored {
            println!("      NodeCert: verified & stored Passkey-signed hcert1_");
        }
        if gate_resigned {
            println!("      Gate Sig: re-signed with updated human_authorities_digest");
            if gate_reloaded {
                println!("      Gate Live: reloaded active daemon policy (no restart needed)");
            }
        }
        print_warnings(&warnings);
        print_next_steps(&next);
    }
    ExitCode::from(EXIT_OK)
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuthListRow {
    kid: String,
    human_id: String,
    role: String,
    label: String,
    auth_epoch: u64,
    status: String,
    enc_key: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    enc_kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    prf_salt: Option<String>,
    created_at: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    revoked_at: Option<i64>,
}

impl From<HumanAuthorityRecord> for AuthListRow {
    fn from(r: HumanAuthorityRecord) -> Self {
        let enc_kid = r
            .enc_jwk_json
            .as_deref()
            .and_then(|raw| serde_json::from_str::<OkpJwk>(raw).ok())
            .and_then(|jwk| jwk.thumbprint().ok());
        Self {
            kid: r.kid,
            human_id: r.human_id,
            role: r.role.as_str().to_string(),
            label: r.label,
            auth_epoch: r.auth_epoch,
            status: r.status.as_str().to_string(),
            enc_key: r.enc_jwk_json.is_some(),
            enc_kid,
            prf_salt: r.prf_salt,
            created_at: r.created_at,
            revoked_at: r.revoked_at,
        }
    }
}

fn run_auth_list(all: bool, state_dir_arg: Option<PathBuf>, as_json: bool) -> ExitCode {
    let cmd = "auth list";
    let state_dir = resolve_state_dir(state_dir_arg.as_deref(), None, None);
    let db_path = state_dir.join("node.sqlite");

    let (rows, min_epoch, digest): (Vec<AuthListRow>, u64, Option<String>) = if db_path.exists() {
        let db = match NodeDb::open(&db_path) {
            Ok(db) => db,
            Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e.to_string(), None),
        };
        let list = match db.human().list_authorities(all) {
            Ok(v) => v.into_iter().map(AuthListRow::from).collect(),
            Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e.to_string(), None),
        };
        let min_ep = db.human().min_auth_epoch().unwrap_or(1);
        let dig = db.human().authorities_digest().ok();
        (list, min_ep, dig)
    } else {
        (Vec::new(), 1, None)
    };

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(format!(
                "{} human authority key(s) (minAuthEpoch={min_epoch})",
                rows.len()
            )),
            data: Some(json!({
                "count": rows.len(),
                "includeRevoked": all,
                "minAuthEpoch": min_epoch,
                "authoritiesDigest": digest,
                "authorities": rows,
                "stateDir": state_dir.display().to_string(),
            })),
            warnings: Vec::new(),
            next: if rows.is_empty() {
                vec![format!("hyp auth init --state-dir {}", state_dir.display())]
            } else {
                Vec::new()
            },
            error: None,
        };
        print_json(&envelope);
    } else {
        println!(
            "Hyphae Human Authorities (count={}, minAuthEpoch={min_epoch})",
            rows.len()
        );
        if let Some(ref d) = digest {
            println!("  Digest: {d}");
        }
        if rows.is_empty() {
            println!("  (none)");
        } else {
            println!();
            println!(
                "{:<16}  {:<18}  {:<8}  {:<6}  {:<8}  {:<6}  Label",
                "Kid", "Human ID", "Role", "Epoch", "Status", "EncKey"
            );
            println!("{}", "-".repeat(94));
            for r in &rows {
                let short_kid: String = r.kid.chars().take(16).collect();
                println!(
                    "{:<16}  {:<18}  {:<8}  {:<6}  {:<8}  {:<6}  {}",
                    short_kid,
                    r.human_id,
                    r.role,
                    r.auth_epoch,
                    r.status,
                    if r.enc_key { "yes" } else { "no" },
                    r.label
                );
            }
        }
    }
    ExitCode::from(EXIT_OK)
}

#[allow(clippy::too_many_arguments)]
fn run_auth_revoke(
    kid_arg: String,
    bump_epoch: bool,
    reason: String,
    issuer_kid_arg: Option<String>,
    broadcast: bool,
    state_dir_arg: Option<PathBuf>,
    config_arg: Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let cmd = "auth revoke";
    let query = kid_arg.trim();
    if query.is_empty() {
        return emit_error(cmd, as_json, EXIT_USAGE, "INVALID_KID", "kid cannot be empty", None);
    }
    if !is_interactive_tty() {
        return emit_confirm_error(cmd, as_json, ConfirmError::NotInteractiveTty);
    }

    let state_dir = resolve_state_dir(state_dir_arg.as_deref(), config_arg.as_deref(), None);
    let config_read =
        resolve_config_path_for_read(config_arg.as_deref(), state_dir_arg.as_deref(), None);
    let config_write =
        resolve_config_path_for_write(config_arg.as_deref(), state_dir_arg.as_deref(), None);
    let db_path = state_dir.join("node.sqlite");
    if !db_path.exists() {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "AUTHORITY_NOT_FOUND",
            format!("Authority '{query}' not found (database does not exist yet)"),
            None,
        );
    }

    let db = match NodeDb::open(&db_path) {
        Ok(db) => db,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e.to_string(), None),
    };
    let all = match db.human().list_authorities(true) {
        Ok(v) => v,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e.to_string(), None),
    };

    let target = match resolve_authority_by_kid_or_prefix(&all, query) {
        Ok(rec) => rec.clone(),
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "AUTHORITY_NOT_FOUND", e, None),
    };

    let current_min = db.human().min_auth_epoch().unwrap_or(1);
    let new_min = if bump_epoch {
        current_min.saturating_add(1)
    } else {
        current_min
    };
    let now = now_ms();
    let revoked_at = format_rfc3339_millis(now);

    let secrets = open_secret_store(&state_dir, state_dir_arg.is_some());
    let issuer_kp: Option<Ed25519KeyPair> = if let Some(ref ik) = issuer_kid_arg {
        all.iter()
            .find(|a| a.status == HumanAuthorityStatus::Active && a.kid == *ik)
            .and_then(|a| load_local_authority_keypair(&secrets, &a.kid).ok())
    } else {
        // Prefer another active admin key in SecretStore; fallback to target itself if it is a local admin key.
        all.iter()
            .filter(|a| {
                a.status == HumanAuthorityStatus::Active
                    && a.role == HumanAuthorityRole::Admin
                    && a.kid != target.kid
            })
            .find_map(|a| load_local_authority_keypair(&secrets, &a.kid).ok())
            .or_else(|| {
                if target.role == HumanAuthorityRole::Admin {
                    load_local_authority_keypair(&secrets, &target.kid).ok()
                } else {
                    None
                }
            })
    };

    let signed_revocation: Option<SignedHumanRevocationV1> = issuer_kp.as_ref().and_then(|kp| {
        let payload = HumanRevocationPayloadV1 {
            v: 1,
            human_id: target.human_id.clone(),
            revoked_kid: target.kid.clone(),
            new_min_auth_epoch: new_min,
            revoked_at: revoked_at.clone(),
            reason: reason.clone(),
            issuer_kid: kp.kid(),
        };
        sign_human_revocation(&payload, kp).ok()
    });

    if broadcast && signed_revocation.is_none() {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "SIGNER_KEY_UNAVAILABLE",
            "Cannot --broadcast revocation without an active local admin Ed25519 signing key to sign SignedHumanRevocationV1",
            Some("Pass --issuer-kid <active-admin-kid> or run `hyp auth init` on an admin node.".to_string()),
        );
    }

    let gate_locked = is_gate_locked(&config_read);
    let summary = format_auth_revoke_confirm_summary(
        &target,
        bump_epoch,
        current_min,
        new_min,
        broadcast,
        &reason,
        gate_locked,
    );
    let prompt = format!("Revoke human authority '{}'? [y/N]: ", target.kid);
    if let Err(err) = require_interactive_tty_confirmation(&summary, &prompt) {
        return emit_confirm_error(cmd, as_json, err);
    }

    let revocation_json = match &signed_revocation {
        Some(sr) => serde_json::to_string(sr).unwrap_or_else(|_| "{}".to_string()),
        None => json!({
            "v": 1,
            "humanId": target.human_id,
            "revokedKid": target.kid,
            "newMinAuthEpoch": new_min,
            "revokedAt": revoked_at,
            "reason": reason,
            "localCli": true,
        })
        .to_string(),
    };

    let effective_min = match db.human().revoke_authority_monotonic(
        &target.human_id,
        &target.kid,
        new_min,
        &revocation_json,
        now,
    ) {
        Ok(m) => m,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "REVOKE_FAILED", e.to_string(), None),
    };

    let gate_resigned = match sync_gate_policy_digest_if_locked(&config_write, &state_dir, &db, &secrets)
    {
        Ok(b) => b,
        Err(e) => {
            return emit_error(cmd, as_json, EXIT_ERROR, "GATE_POLICY_SYNC_FAILED", e, None);
        }
    };
    let digest = db.human().authorities_digest().ok();
    drop(db);

    let mut warnings = Vec::new();
    let mut next = Vec::new();
    let (gate_reloaded, gate_reload_error) = if gate_resigned {
        reload_live_gate_after_resign(
            state_dir_arg.is_some(),
            config_arg.is_some(),
            &state_dir,
            &mut warnings,
            &mut next,
        )
    } else {
        (false, None)
    };

    let broadcast_outcome = if broadcast {
        let sr = signed_revocation
            .as_ref()
            .expect("validated signed_revocation when broadcast=true");
        let kp = issuer_kp
            .as_ref()
            .expect("validated issuer_kp when broadcast=true");
        match broadcast_human_revocation(
            &state_dir,
            &config_read,
            &secrets,
            sr,
            kp,
            &target,
            &revoked_at,
        ) {
            Ok(outcome) => Some(outcome),
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "BROADCAST_FAILED",
                    format!("Authority revoked locally, but --broadcast failed: {e}"),
                    None,
                );
            }
        }
    } else {
        None
    };

    if as_json {
        let mut data = json!({
            "humanId": target.human_id,
            "kid": target.kid,
            "status": "revoked",
            "minAuthEpoch": effective_min,
            "epochBumped": bump_epoch,
            "authoritiesDigest": digest,
            "gatePolicyResigned": gate_resigned,
            "gateReloaded": gate_reloaded,
            "signedRevocation": signed_revocation,
            "broadcasted": broadcast_outcome.is_some(),
        });
        if let Some(ref err) = gate_reload_error {
            data["gateReloadError"] = json!(err);
        }
        if let Some(ref b) = broadcast_outcome {
            data["broadcastTopic"] = json!(b.topic);
            data["broadcastEventId"] = json!(b.event_id);
            data["broadcastEventType"] = json!(TYPE_HUMAN_REVOCATION_V1);
            data["broadcastVia"] = json!(b.via);
            data["broadcastMatched"] = json!(b.matched);
        }
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(format!(
                "Revoked human authority '{}' kid {} (minAuthEpoch={effective_min})",
                target.human_id, target.kid
            )),
            data: Some(data),
            warnings,
            next,
            error: None,
        };
        print_json(&envelope);
    } else {
        println!(
            "OK    Revoked authority '{}' (kid={}, minAuthEpoch={effective_min})",
            target.human_id, target.kid
        );
        if gate_resigned {
            println!("      Gate Sig:  re-signed with updated human_authorities_digest");
            if gate_reloaded {
                println!("      Gate Live: reloaded active daemon policy (no restart needed)");
            }
        }
        if let Some(ref b) = broadcast_outcome {
            println!(
                "      Broadcast: published {} to topic '{}' via {} (eventId={}, matched={})",
                TYPE_HUMAN_REVOCATION_V1, b.topic, b.via, b.event_id, b.matched
            );
        }
        print_warnings(&warnings);
        print_next_steps(&next);
    }
    ExitCode::from(EXIT_OK)
}

fn run_auth_certify_node(
    ttl_days: u32,
    kid_arg: Option<String>,
    state_dir_arg: Option<PathBuf>,
    config_arg: Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let cmd = "auth certify-node";
    if ttl_days == 0 {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "INVALID_TTL",
            "--ttl-days must be >= 1",
            None,
        );
    }

    let state_dir = resolve_state_dir(state_dir_arg.as_deref(), config_arg.as_deref(), None);
    let config_read =
        resolve_config_path_for_read(config_arg.as_deref(), state_dir_arg.as_deref(), None);
    let secrets = open_secret_store(&state_dir, state_dir_arg.is_some());

    let node = match open_local_unified_node(&state_dir, &config_read, &secrets) {
        Ok(n) => n,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "NODE_OPEN_FAILED", e, None),
    };

    let (admin_rec, admin_kp) = match select_local_signing_authority(
        &node.db(),
        &secrets,
        kid_arg.as_deref(),
        true,
    ) {
        Ok(pair) => pair,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "ADMIN_KEY_UNAVAILABLE",
                e,
                Some(format!("Run `hyp auth init --state-dir {}` first.", state_dir.display())),
            );
        }
    };

    let (signed, hcert1) = match node.issue_node_cert(&admin_kp, &admin_rec.kid, ttl_days) {
        Ok(res) => res,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "CERTIFY_FAILED",
                format!("Failed to issue NodeCertV1: {e}"),
                None,
            );
        }
    };

    let cert_payload: Value = serde_json::from_str(&signed.payload).unwrap_or(Value::Null);

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(format!(
                "Certified node '{}' for {ttl_days} day(s) under human authority '{}' ({})",
                node.node_id().as_str(),
                admin_rec.human_id,
                admin_rec.kid
            )),
            data: Some(json!({
                "nodeId": node.node_id().as_str(),
                "humanId": admin_rec.human_id,
                "humanKid": admin_rec.kid,
                "ttlDays": ttl_days,
                "token": hcert1,
                "cert": cert_payload,
            })),
            warnings: Vec::new(),
            next: Vec::new(),
            error: None,
        };
        print_json(&envelope);
    } else {
        println!(
            "OK    Certified node '{}' ({ttl_days}d) via '{}'",
            node.node_id().as_str(),
            admin_rec.human_id
        );
        println!("      Cert: {hcert1}");
    }
    ExitCode::from(EXIT_OK)
}

#[allow(clippy::too_many_arguments)]
fn run_auth_sign(
    kind: CliDropKind,
    node_id_arg: Option<String>,
    handle_arg: Option<String>,
    secret_name_arg: Option<String>,
    overwrite: bool,
    ttl_secs: u64,
    drop_id_arg: Option<String>,
    kid_arg: Option<String>,
    state_dir_arg: Option<PathBuf>,
    config_arg: Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let cmd = "auth sign";
    if ttl_secs == 0 || ttl_secs > MAX_DROP_TTL_SECS {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "INVALID_TTL",
            format!("--ttl must be in 1..={MAX_DROP_TTL_SECS} seconds"),
            None,
        );
    }

    if let Some(ref h) = handle_arg {
        if !is_valid_handle(h) {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_HANDLE",
                format!("Invalid --handle '{h}'"),
                None,
            );
        }
    }

    let secret_spec = match kind {
        CliDropKind::Secret => {
            let Some(ref raw_name) = secret_name_arg else {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_USAGE,
                    "MISSING_SECRET_NAME",
                    "--secret-name <name> is required when --kind secret",
                    None,
                );
            };
            let name = raw_name.trim();
            if is_reserved_secret_name(name) {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_USAGE,
                    "RESERVED_SECRET_NAME",
                    format!("Reserved system secret name '{name}' is permanently blocked for human drops"),
                    None,
                );
            }
            if let Err(e) = validate_secret_name(name) {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_USAGE,
                    "INVALID_SECRET_NAME",
                    format!("Invalid --secret-name '{name}': {e}"),
                    None,
                );
            }
            Some(SecretDropSpec {
                name: name.to_string(),
                overwrite,
            })
        }
        CliDropKind::Directive => {
            if secret_name_arg.is_some() {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_USAGE,
                    "UNEXPECTED_SECRET_NAME",
                    "--secret-name is only allowed when --kind secret",
                    None,
                );
            }
            None
        }
    };

    // Read body strictly from stdin (NEVER argv!) into a bounded buffer.
    let mut raw_body = String::new();
    if let Err(e) = io::stdin()
        .lock()
        .take(MAX_SIGN_BODY_BYTES + 1)
        .read_to_string(&mut raw_body)
    {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "STDIN_ERROR",
            format!("Failed to read body from stdin: {e}"),
            None,
        );
    }
    if raw_body.len() as u64 > MAX_SIGN_BODY_BYTES {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "BODY_TOO_LARGE",
            format!("Input exceeds {MAX_SIGN_BODY_BYTES} byte safety cap"),
            None,
        );
    }
    let body = raw_body.trim_end_matches(['\r', '\n']).to_string();
    drop(raw_body);
    if body.is_empty() {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "EMPTY_BODY",
            "No body received on stdin (body must be piped via stdin, never CLI argv)",
            None,
        );
    }

    let state_dir = resolve_state_dir(state_dir_arg.as_deref(), config_arg.as_deref(), None);
    let config_read =
        resolve_config_path_for_read(config_arg.as_deref(), state_dir_arg.as_deref(), None);
    let loaded = if config_read.exists() {
        load_node_or_legacy_config(&config_read).ok()
    } else {
        None
    };

    let db_path = state_dir.join("node.sqlite");
    if !db_path.exists() {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "NOT_INITIALIZED",
            format!("No node.sqlite found at {}", db_path.display()),
            Some(format!("Run `hyp auth init --state-dir {}` first.", state_dir.display())),
        );
    }
    let db = match NodeDb::open(&db_path) {
        Ok(db) => db,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "DB_ERROR", e.to_string(), None),
    };
    let secrets = open_secret_store(&state_dir, state_dir_arg.is_some());

    let (signer_rec, signer_kp) =
        match select_local_signing_authority(&db, &secrets, kid_arg.as_deref(), false) {
            Ok(pair) => pair,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "SIGNER_KEY_UNAVAILABLE",
                    e,
                    Some(format!("Run `hyp auth init --state-dir {}` first.", state_dir.display())),
                );
            }
        };

    let local_node_id = resolve_effective_node_id(loaded.as_ref(), Some(&db));
    let target_node_id = node_id_arg.unwrap_or_else(|| local_node_id.clone());
    if target_node_id == LOCAL_NODE_ID || !is_valid_node_id(&target_node_id) {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "INVALID_NODE_ID",
            format!("Invalid target --node-id '{target_node_id}'"),
            None,
        );
    }

    let recipient_enc_pk: X25519PublicKey = if target_node_id == local_node_id {
        match secrets.load_or_create_node_keys(&local_node_id) {
            Ok(keys) => keys.encryption.public_key(),
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "NODE_KEY_ERROR",
                    format!("Failed to load local node encryption key: {e}"),
                    None,
                );
            }
        }
    } else {
        match lookup_peer_encryption_key(&db, &target_node_id) {
            Ok(pk) => pk,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "PEER_KEY_NOT_FOUND",
                    e,
                    Some(format!(
                        "Ensure peer '{target_node_id}' is paired and has an active X25519 encryption key."
                    )),
                );
            }
        }
    };

    let claim_id = match random_b64url(16) {
        Ok(id) => id,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "RNG_ERROR", e, None),
    };
    let min_epoch = db.human().min_auth_epoch().unwrap_or(1);
    let auth_epoch = signer_rec.auth_epoch.max(min_epoch);
    let now = now_unix_ms();
    let expires_ms = now.saturating_add((ttl_secs as i64).saturating_mul(1_000));
    let issued_at = format_rfc3339_millis(now);
    let expires_at = format_rfc3339_millis(expires_ms);
    let drop_id = drop_id_arg.unwrap_or_default();

    let mut claim = HumanClaimV1 {
        v: 1,
        kind: kind.to_crypto_kind(),
        claim_id: claim_id.clone(),
        human_id: signer_rec.human_id.clone(),
        human_kid: signer_rec.kid.clone(),
        auth_epoch,
        issued_at,
        expires_at: expires_at.clone(),
        drop_id: drop_id.clone(),
        audience: HumanAudience {
            node_id: target_node_id.clone(),
            node_enc_kid: recipient_enc_pk.kid(),
            handle: handle_arg.clone(),
        },
        secret_spec: secret_spec.clone(),
        body,
    };

    let seal_res = seal_human_drop(&claim, &signer_kp, &recipient_enc_pk);
    // Wipe plaintext body bytes immediately after sealing.
    // SAFETY: `body` is valid UTF-8 and we immediately clear it after overwriting with zeroes.
    unsafe {
        for b in claim.body.as_bytes_mut() {
            std::ptr::write_volatile(b, 0);
        }
    }
    claim.body.clear();
    drop(claim);

    let envelope = match seal_res {
        Ok(env) => env,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "SEAL_FAILED",
                format!("Failed to seal human drop: {e}"),
                None,
            );
        }
    };

    let token = match encode_hdrop1(&envelope) {
        Ok(t) => t,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "ENCODE_FAILED",
                format!("Failed to encode hdrop1_ token: {e}"),
                None,
            );
        }
    };

    let next = vec![format!(
        "Pipe token into target node: printf '%s' \"$HDROP1\" | hyp drop ingest --state-dir {}",
        state_dir.display()
    )];

    if as_json {
        let env_out = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(format!(
                "Sealed {} drop (claimId={claim_id}) for node '{target_node_id}'",
                kind.to_crypto_kind().as_str()
            )),
            data: Some(json!({
                "token": token,
                "claimId": claim_id,
                "kind": kind.to_crypto_kind().as_str(),
                "humanId": signer_rec.human_id,
                "humanKid": signer_rec.kid,
                "authEpoch": auth_epoch,
                "targetNodeId": target_node_id,
                "targetHandle": handle_arg,
                "secretName": secret_spec.as_ref().map(|s| s.name.as_str()),
                "dropId": drop_id,
                "expiresAt": expires_at,
            })),
            warnings: Vec::new(),
            next,
            error: None,
        };
        print_json(&env_out);
    } else {
        println!("{token}");
    }
    ExitCode::from(EXIT_OK)
}

fn resolve_authority_by_kid_or_prefix<'a>(
    authorities: &'a [HumanAuthorityRecord],
    query: &str,
) -> Result<&'a HumanAuthorityRecord, String> {
    if let Some(exact) = authorities.iter().find(|a| a.kid == query) {
        return Ok(exact);
    }
    if query.len() >= 8 {
        let matches: Vec<&HumanAuthorityRecord> = authorities
            .iter()
            .filter(|a| a.kid.starts_with(query))
            .collect();
        if matches.len() == 1 {
            return Ok(matches[0]);
        }
        if matches.len() > 1 {
            return Err(format!(
                "ambiguous kid prefix '{query}' matches {} authorities; pass full kid",
                matches.len()
            ));
        }
    }
    Err(format!("human authority kid '{query}' not found"))
}

pub(crate) fn select_local_signing_authority(
    db: &NodeDb,
    secrets: &SecretStore,
    kid_arg: Option<&str>,
    require_admin: bool,
) -> Result<(HumanAuthorityRecord, Ed25519KeyPair), String> {
    let active = db
        .human()
        .list_authorities(false)
        .map_err(|e| format!("failed to list active authorities: {e}"))?;

    if let Some(requested) = kid_arg {
        let rec = resolve_authority_by_kid_or_prefix(&active, requested.trim())?.clone();
        if require_admin && rec.role != HumanAuthorityRole::Admin {
            return Err(format!(
                "authority '{}' kid '{}' does not have admin role",
                rec.human_id, rec.kid
            ));
        }
        let kp = load_local_authority_keypair(secrets, &rec.kid)?;
        return Ok((rec, kp));
    }

    for rec in &active {
        if require_admin && rec.role != HumanAuthorityRole::Admin {
            continue;
        }
        if let Ok(kp) = load_local_authority_keypair(secrets, &rec.kid) {
            return Ok((rec.clone(), kp));
        }
    }

    Err(if require_admin {
        "no active local admin authority key found in SecretStore".to_string()
    } else {
        "no active local human authority signing key found in SecretStore".to_string()
    })
}

fn lookup_peer_encryption_key(db: &NodeDb, peer_id: &str) -> Result<X25519PublicKey, String> {
    let keys = db
        .peers()
        .list_peer_keys(peer_id, Some(KeyUse::Encryption), true)
        .map_err(|e| format!("failed to query peer keys for '{peer_id}': {e}"))?;
    let active_enc = keys
        .into_iter()
        .next()
        .ok_or_else(|| format!("no active X25519 encryption key found for peer '{peer_id}'"))?;
    let jwk: OkpJwk = serde_json::from_str(&active_enc.jwk_json)
        .map_err(|e| format!("malformed peer encryption JWK for '{peer_id}': {e}"))?;
    jwk.to_x25519()
        .map_err(|e| format!("invalid peer X25519 key for '{peer_id}': {e}"))
}

// ============================================================================
// One-Shot Loopback `--web` Passkey+PRF Enrollment Callback Server
// ============================================================================

struct WebEnrolledAuthority {
    human_id: String,
    kid: String,
    label: String,
    jwk_json: String,
    enc_jwk_json: Option<String>,
    enc_kid: Option<String>,
    prf_salt: String,
    auth_epoch: u64,
    credential_id: Option<String>,
    node_cert: Option<VerifiedEnrolledNodeCert>,
}

struct WebEnrollState {
    allowed_origin: String,
    default_human_id: String,
    default_prf_salt: String,
    default_auth_epoch: u64,
    node_id: String,
    node_sign_jwk_x: String,
    node_enc_jwk_x: String,
    csrf_token: String,
    done_tx: Mutex<Option<oneshot::Sender<Result<WebEnrolledAuthority, String>>>>,
}

fn extract_portal_origin(portal_url: &str) -> Result<String, String> {
    let uri: http::Uri = portal_url
        .parse()
        .map_err(|e| format!("invalid Drop Portal URL '{portal_url}': {e}"))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| format!("Drop Portal URL '{portal_url}' is missing a scheme"))?;
    let authority = uri
        .authority()
        .ok_or_else(|| format!("Drop Portal URL '{portal_url}' is missing a host"))?;
    Ok(format!("{scheme}://{authority}"))
}

fn should_skip_browser_open(no_open: bool, store: &SecretStore) -> bool {
    if no_open {
        return true;
    }
    if std::env::var_os("HYPHAE_NO_OPEN").is_some() || std::env::var_os("CI").is_some() {
        return true;
    }
    let tmp = std::env::temp_dir();
    let canon_tmp = std::fs::canonicalize(&tmp).unwrap_or(tmp);
    let dir = store.config_dir();
    let canon_dir = std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf());
    canon_dir.starts_with(&canon_tmp)
        || dir.starts_with("/tmp")
        || dir.starts_with("/private/tmp")
        || dir.starts_with("/var/folders")
        || dir.starts_with("/private/var/folders")
}

fn try_open_browser(url: &str) {
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(url).spawn();
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("cmd")
        .args(["/c", "start", "", url])
        .spawn();
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    let _ = url;
}

fn apply_enroll_cors(origin: Option<&str>, allowed_origin: &str, resp: &mut Response<Full<Bytes>>) {
    if let Some(orig) = origin {
        if orig == allowed_origin {
            if let Ok(hdr_val) = HeaderValue::from_str(allowed_origin) {
                resp.headers_mut()
                    .insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, hdr_val);
                resp.headers_mut()
                    .insert(header::VARY, HeaderValue::from_static("Origin"));
                resp.headers_mut().insert(
                    header::HeaderName::from_static("access-control-allow-private-network"),
                    HeaderValue::from_static("true"),
                );
            }
        }
    }
}

fn json_enroll_response(
    status: StatusCode,
    origin: Option<&str>,
    allowed_origin: &str,
    body: Value,
) -> Response<Full<Bytes>> {
    let bytes = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    let mut resp = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONNECTION, "close")
        .body(Full::new(Bytes::from(bytes)))
        .expect("valid JSON response");
    apply_enroll_cors(origin, allowed_origin, &mut resp);
    resp
}

#[allow(clippy::too_many_arguments)]
async fn enroll_passkey_via_web(
    drop_portal_url: &str,
    human_id: &str,
    auth_epoch: u64,
    node_id: &str,
    node_sign_jwk: &OkpJwk,
    node_enc_jwk: &OkpJwk,
    port: u16,
    timeout_secs: u64,
    no_open: bool,
    secrets: &SecretStore,
) -> Result<WebEnrolledAuthority, String> {
    let allowed_origin = extract_portal_origin(drop_portal_url)?;
    let prf_salt = random_b64url(16)?;
    let csrf_token = random_b64url(24)?;

    let listener = TcpListener::bind(("127.0.0.1", port))
        .await
        .map_err(|e| format!("failed to bind 127.0.0.1:{port}: {e}"))?;
    let local_addr = listener
        .local_addr()
        .map_err(|e| format!("failed to query loopback address: {e}"))?;
    let callback_url = format!("http://127.0.0.1:{}/enroll", local_addr.port());

    let enroll_payload = json!({
        "v": 1,
        "humanId": human_id,
        "authEpoch": auth_epoch,
        "prfSalt": prf_salt,
        "callbackUrl": callback_url,
        "csrfToken": csrf_token,
        "nodeId": node_id,
        "nodeSignJwk": node_sign_jwk,
        "nodeEncJwk": node_enc_jwk,
    });
    let canon = to_canonical_json(&enroll_payload)
        .map_err(|e| format!("failed to encode enrollment fragment: {e}"))?;
    let enroll_url = format!(
        "{drop_portal_url}#enroll={}",
        URL_SAFE_NO_PAD.encode(canon.as_bytes())
    );

    let (done_tx, mut done_rx) = oneshot::channel::<Result<WebEnrolledAuthority, String>>();
    let state = Arc::new(WebEnrollState {
        allowed_origin,
        default_human_id: human_id.to_string(),
        default_prf_salt: prf_salt,
        default_auth_epoch: auth_epoch,
        node_id: node_id.to_string(),
        node_sign_jwk_x: node_sign_jwk.x.clone(),
        node_enc_jwk_x: node_enc_jwk.x.clone(),
        csrf_token,
        done_tx: Mutex::new(Some(done_tx)),
    });

    // Emit URL on stderr and flush so stdout stays clean for `--json`.
    eprintln!("Hyphae Passkey+PRF enrollment URL: {enroll_url}");
    let _ = io::stderr().flush();

    if !should_skip_browser_open(no_open, secrets) {
        try_open_browser(&enroll_url);
    }

    let timeout = tokio::time::sleep(Duration::from_secs(timeout_secs.max(1)));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            res = &mut done_rx => {
                tokio::time::sleep(Duration::from_millis(50)).await;
                return res.map_err(|_| "enrollment callback channel closed unexpectedly".to_string())?;
            }
            _ = &mut timeout => {
                return Err(format!("timed out after {timeout_secs}s waiting for Passkey enrollment callback"));
            }
            accept = listener.accept() => {
                let Ok((stream, _)) = accept else {
                    continue;
                };
                let st = Arc::clone(&state);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let st = Arc::clone(&st);
                        async move { Ok::<_, Infallible>(handle_enroll_callback(st, req).await) }
                    });
                    let _ = AutoServerBuilder::new(TokioExecutor::new())
                        .serve_connection(io, svc)
                        .await;
                });
            }
        }
    }
}

async fn handle_enroll_callback(
    state: Arc<WebEnrollState>,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let allowed = state.allowed_origin.as_str();
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    // Fail closed on untrusted browser Origin headers (allow strictly the configured portal origin or absent Origin).
    if let Some(ref orig) = origin {
        if orig != allowed {
            return json_enroll_response(
                StatusCode::FORBIDDEN,
                None,
                allowed,
                json!({ "ok": false, "error": "origin_not_allowed" }),
            );
        }
    }

    let path = req.uri().path().to_string();
    if path != "/enroll" {
        return json_enroll_response(
            StatusCode::NOT_FOUND,
            origin.as_deref(),
            allowed,
            json!({ "ok": false, "error": "not_found" }),
        );
    }

    if *req.method() == Method::OPTIONS {
        let mut resp = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(header::ACCESS_CONTROL_ALLOW_METHODS, "POST, OPTIONS")
            .header(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                "Content-Type, X-Hyphae-CSRF",
            )
            .header(header::ACCESS_CONTROL_MAX_AGE, "600")
            .header(header::CONNECTION, "close")
            .body(Full::new(Bytes::new()))
            .expect("valid preflight response");
        apply_enroll_cors(origin.as_deref(), allowed, &mut resp);
        return resp;
    }

    if *req.method() != Method::POST {
        return json_enroll_response(
            StatusCode::METHOD_NOT_ALLOWED,
            origin.as_deref(),
            allowed,
            json!({ "ok": false, "error": "method_not_allowed" }),
        );
    }

    let header_csrf = req
        .headers()
        .get("x-hyphae-csrf")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    let mut body_bytes = Vec::new();
    let mut body = req.into_body();
    while let Some(frame_res) = body.frame().await {
        let Ok(frame) = frame_res else {
            return json_enroll_response(
                StatusCode::BAD_REQUEST,
                origin.as_deref(),
                allowed,
                json!({ "ok": false, "error": "body_read_error" }),
            );
        };
        if let Some(chunk) = frame.data_ref() {
            if body_bytes.len() + chunk.len() > MAX_ENROLL_CALLBACK_BYTES {
                return json_enroll_response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    origin.as_deref(),
                    allowed,
                    json!({ "ok": false, "error": "payload_too_large" }),
                );
            }
            body_bytes.extend_from_slice(chunk);
        }
    }

    let parsed: Value = match serde_json::from_slice(&body_bytes) {
        Ok(v) => v,
        Err(_) => {
            return json_enroll_response(
                StatusCode::BAD_REQUEST,
                origin.as_deref(),
                allowed,
                json!({ "ok": false, "error": "invalid_json" }),
            );
        }
    };
    let Some(obj) = parsed.as_object() else {
        return json_enroll_response(
            StatusCode::BAD_REQUEST,
            origin.as_deref(),
            allowed,
            json!({ "ok": false, "error": "expected_json_object" }),
        );
    };

    // Constant-time CSRF/state verification (accepts `X-Hyphae-CSRF` header from site/drop/drop.js
    // OR `state` / `csrfToken` JSON field).
    let submitted_token = header_csrf.as_deref().or_else(|| {
        obj.get("state")
            .or_else(|| obj.get("csrfToken"))
            .and_then(Value::as_str)
    });
    let csrf_ok = submitted_token
        .is_some_and(|tok| ct_eq(tok.as_bytes(), state.csrf_token.as_bytes()));
    if !csrf_ok {
        return json_enroll_response(
            StatusCode::FORBIDDEN,
            origin.as_deref(),
            allowed,
            json!({ "ok": false, "error": "invalid_state_token" }),
        );
    }

    let Some(jwk_val) = obj.get("jwk").or_else(|| obj.get("publicJwk")) else {
        return json_enroll_response(
            StatusCode::BAD_REQUEST,
            origin.as_deref(),
            allowed,
            json!({ "ok": false, "error": "missing_jwk" }),
        );
    };
    let jwk: OkpJwk = match serde_json::from_value(jwk_val.clone()) {
        Ok(j) => j,
        Err(_) => {
            return json_enroll_response(
                StatusCode::BAD_REQUEST,
                origin.as_deref(),
                allowed,
                json!({ "ok": false, "error": "invalid_jwk" }),
            );
        }
    };
    let Ok(authority_ed_pk) = jwk.to_ed25519() else {
        return json_enroll_response(
            StatusCode::BAD_REQUEST,
            origin.as_deref(),
            allowed,
            json!({ "ok": false, "error": "invalid_ed25519_jwk" }),
        );
    };
    let (enc_jwk_json, enc_kid) = match parse_optional_enc_jwk(obj.get("encJwk")) {
        Ok(Some((canon, ekid))) => (Some(canon), Some(ekid)),
        Ok(None) => (None, None),
        Err(msg) => {
            return json_enroll_response(
                StatusCode::BAD_REQUEST,
                origin.as_deref(),
                allowed,
                json!({ "ok": false, "error": "invalid_enc_jwk", "message": msg }),
            );
        }
    };
    let Ok(kid) = jwk.thumbprint() else {
        return json_enroll_response(
            StatusCode::BAD_REQUEST,
            origin.as_deref(),
            allowed,
            json!({ "ok": false, "error": "invalid_jwk_thumbprint" }),
        );
    };
    if let Some(claimed_kid) = obj.get("kid").and_then(Value::as_str) {
        if claimed_kid != kid {
            return json_enroll_response(
                StatusCode::BAD_REQUEST,
                origin.as_deref(),
                allowed,
                json!({ "ok": false, "error": "kid_mismatch" }),
            );
        }
    }
    let Ok(jwk_json) = to_canonical_json(&jwk) else {
        return json_enroll_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            origin.as_deref(),
            allowed,
            json!({ "ok": false, "error": "serialization_failed" }),
        );
    };

    let human_id = obj
        .get("humanId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty() && is_valid_node_id(s))
        .unwrap_or(&state.default_human_id)
        .to_string();
    let label = obj
        .get("label")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control))
        .unwrap_or("passkey-signer")
        .to_string();
    let prf_salt = obj
        .get("prfSalt")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 128)
        .unwrap_or(&state.default_prf_salt)
        .to_string();
    let auth_epoch = obj
        .get("authEpoch")
        .and_then(Value::as_u64)
        .filter(|&e| e >= 1)
        .unwrap_or(state.default_auth_epoch);
    let credential_id = obj
        .get("credentialId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);

    let node_cert = match obj.get("nodeCert") {
        None | Some(Value::Null) => None,
        Some(Value::String(raw_cert)) if !raw_cert.trim().is_empty() => {
            match validate_enrolled_node_cert(
                raw_cert,
                &authority_ed_pk,
                &human_id,
                &state.node_id,
                &state.node_sign_jwk_x,
                &state.node_enc_jwk_x,
                state.default_auth_epoch,
            ) {
                Ok(cert) => Some(cert),
                Err(msg) => {
                    return json_enroll_response(
                        StatusCode::BAD_REQUEST,
                        origin.as_deref(),
                        allowed,
                        json!({ "ok": false, "error": "invalid_node_cert", "message": msg }),
                    );
                }
            }
        }
        Some(Value::String(_)) => None,
        Some(_) => {
            return json_enroll_response(
                StatusCode::BAD_REQUEST,
                origin.as_deref(),
                allowed,
                json!({ "ok": false, "error": "invalid_node_cert", "message": "nodeCert must be an hcert1_ string" }),
            );
        }
    };

    let enrolled = WebEnrolledAuthority {
        human_id,
        kid: kid.clone(),
        label,
        jwk_json,
        enc_jwk_json,
        enc_kid,
        prf_salt,
        auth_epoch,
        credential_id,
        node_cert,
    };

    if let Ok(mut guard) = state.done_tx.lock() {
        if let Some(tx) = guard.take() {
            let _ = tx.send(Ok(enrolled));
        }
    }

    json_enroll_response(
        StatusCode::OK,
        origin.as_deref(),
        allowed,
        json!({ "ok": true, "kid": kid }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate_cmd::confirm_interactive_with;

    #[test]
    fn auth_add_and_revoke_confirm_summaries_include_key_fields_and_locked_warning() {
        let add_summary = format_auth_add_confirm_summary(
            "bob",
            HumanAuthorityRole::Admin,
            "yubikey-backup",
            "kid_1234567890abcdef",
            3,
            Some("enc_kid_999"),
            true,
            true,
        )
        .join("\n");
        assert!(add_summary.contains("Human ID:   bob"));
        assert!(add_summary.contains("Role:       admin"));
        assert!(add_summary.contains("Key ID:     kid_1234567890abcdef"));
        assert!(add_summary.contains("Enc Key ID: enc_kid_999"));
        assert!(add_summary.contains("Security Gate is LOCKED"));

        let target = HumanAuthorityRecord {
            human_id: "bob".to_string(),
            kid: "kid_1234567890abcdef".to_string(),
            label: "phone".to_string(),
            role: HumanAuthorityRole::Signer,
            jwk_json: "{}".to_string(),
            enc_jwk_json: None,
            prf_salt: None,
            auth_epoch: 1,
            status: HumanAuthorityStatus::Active,
            created_at: 1,
            revoked_at: None,
            revocation_json: None,
        };
        let rev_summary = format_auth_revoke_confirm_summary(
            &target,
            true,
            1,
            2,
            true,
            "lost device",
            true,
        )
        .join("\n");
        assert!(rev_summary.contains("Human ID:   bob"));
        assert!(rev_summary.contains("Key ID:     kid_1234567890abcdef"));
        assert!(rev_summary.contains("Bump Epoch: yes (1 -> 2)"));
        assert!(rev_summary.contains("Broadcast:  yes (topic: human.revocations)"));
        assert!(rev_summary.contains("Security Gate is LOCKED"));

        // Verify injectable confirmation works cross-platform (including Windows!)
        let mut out = Vec::new();
        let mut yes_in = io::Cursor::new(b"yes\n".to_vec());
        assert_eq!(
            confirm_interactive_with(
                true,
                &format_auth_init_confirm_summary("alice", "laptop", 1, true),
                "Initialize additional human admin authority 'alice' (label: laptop)? [y/N]: ",
                &mut yes_in,
                &mut out
            ),
            Ok(())
        );
        let rendered = String::from_utf8(out).unwrap();
        assert!(rendered.contains("Security Gate is LOCKED"));
    }
}
