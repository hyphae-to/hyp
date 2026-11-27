//! `hyp auth` — Tier 1 Ed25519 Human Authority management, node certification (`hcert1_`),
//! offline/CLI drop signing (`hdrop1_`), and one-shot loopback `--web` Passkey+PRF enrollment.
//!
//! Security invariants (`#10` — H1, H2):
//! - NEVER accepts private keys, secrets, or drop bodies via CLI argv flags (stdin or `--web` only!).
//! - NEVER prints private key material or drop plaintext to stdout, stderr, logs, or `--json`.
//! - `hyp auth init --web` enrolls the browser Passkey directly as `role: admin` with ZERO
//!   plaintext PKCS#8 laptop key stored in `SecretStore` (`H2`).
//! - `hyp auth add`, `hyp auth admit`, and `hyp auth revoke` each require a fresh live
//!   Passkey-signed approval ceremony from an existing Passkey Admin
//!   and NEVER silently re-sign `gate_policy_sig` from a shell key (`H1`).

use crate::approval::{
    ApprovalCeremonyArgs, CeremonyOutcome, VerifiedApproval, base_approval_action,
    execute_approved_operation, has_passkey_history, inspect_policy_integrity, next_seal_seq,
    persist_passkey_gate_seal, run_passkey_approval_ceremony,
};
use crate::config_file::{
    SocketEnvPolicy, ct_eq, default_node_id, ensure_dir, load_node_or_legacy_config,
    open_secret_store, resolve_config_path_for_read, resolve_config_path_for_write,
    resolve_daemon_socket_path, resolve_effective_node_id, resolve_state_dir,
};
use crate::gate_cmd::{
    ConfirmError, require_controlling_tty_confirmation, require_interactive_tty_confirmation,
    sanitize_tty_display,
};
use crate::ui::{
    CliError, CommandResult, EXIT_OK, JsonEnvelope, print_json, print_next_steps, print_warnings,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::{Subcommand, ValueEnum};
use http::{HeaderValue, Method, Request, Response, StatusCode, header};
use http_body_util::Full;
use hyp_crypto::human::{
    DEFAULT_DELEGATED_MAX_DEVICES, HumanApprovalActionKind, HumanApprovalActionV1, HumanAudience,
    HumanClaimV1, HumanDropKind, HumanInviteV1, HumanPubCardV1, HumanRevocationPayloadV1,
    MAX_DELEGATED_DEVICES_LIMIT, NodeCertPayloadV1, SecretDropSpec, SignedHumanRevocationV1,
    SignedNodeCertV1, decode_hcert1, decode_hpub1, encode_hdrop1, encode_hjoin1, encode_hpub1,
    is_reserved_secret_name, seal_human_drop, sign_human_invite, sign_human_revocation,
    sign_local_ingest_event, verify_node_cert,
};
use hyp_crypto::jcs::to_canonical_json;
use hyp_crypto::keys::{Ed25519KeyPair, Ed25519PublicKey, OkpJwk, X25519PublicKey};
use hyp_crypto::keystore::{SecretStore, validate_secret_name};
use hyp_crypto::pairing::validate_endpoint_origin;
use hyp_crypto::rfc3339::{format_rfc3339_millis, now_unix_ms, parse_rfc3339_millis};
use hyp_harness::sock::daemon_rpc_sync;
use hyp_node::engine::http_util::{BoundedBodyError, consume_bounded_body};
use hyp_node::engine::{
    LocalIngestConfig, NodeConfig, NodeProfile, UnifiedNode, canonical_local_event_for_signing,
    resolve_drop_portal_url, send_local_ingest_event,
};
use hyp_node::gates::policy::{SecurityGateConfig, local_admin_secret_names_for_kid};
use hyp_node::node_file::NodeFile;
use hyp_proto::address::{LOCAL_NODE_ID, NodeId, is_valid_handle, is_valid_node_id};
use hyp_proto::cloudevent::{
    CONTENT_TYPE_JSON, CloudEvent as ProtoCloudEvent, EXT_LOCAL_EVENT_SIG, TYPE_HUMAN_REVOCATION_V1,
};
use hyp_proto::scopes::{ScopePreset, expand_delegated_human_scopes, validate_node_prefix_pattern};
use hyp_store::{
    HumanAuthorityInput, HumanAuthorityRecord, HumanAuthorityRole, HumanAuthorityStatus,
    HumanDelegationPolicyInput, HumanNodeCertInput, KeyUse, NodeDb, now_ms, uuid_v4,
};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use serde_json::{Value, json};
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
const DEFAULT_JOIN_PORTAL_URL: &str = "https://hyphae.to/join";
const MAX_INVITE_EXPIRES_HOURS: u64 = 24 * 365;
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
        #[command(flatten)]
        ceremony: ApprovalCeremonyArgs,
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
    /// Monotonically revoke a human authority key (optionally bumping minAuthEpoch and cascading to admitted devices)
    Revoke {
        /// Authority humanId, full RFC 7638 kid, or unambiguous >=8-char kid prefix
        #[arg(allow_hyphen_values = true)]
        kid: String,
        /// Increment minAuthEpoch monotonically to invalidate older claims & certs
        #[arg(long)]
        bump_epoch: bool,
        /// Revoke all peers admitted under this human authority, invalidate their bearer tokens, and reload the daemon
        #[arg(long)]
        cascade: bool,
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
        #[command(flatten)]
        ceremony: ApprovalCeremonyArgs,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Mint a single-use Org Admin-CA-signed `hjoin1_` human enrollment invite & https://hyphae.to/join link
    Invite {
        /// Canonical human identifier to invite (e.g. philip)
        human_id: String,
        /// Hub canonical nodeId (defaults to local nodeId)
        #[arg(long)]
        hub: Option<String>,
        /// Hub HTTPS endpoint (defaults to listen.publicUrl in node.json)
        #[arg(long)]
        endpoint: Option<String>,
        /// Optional 16-hex SHA-256 prefix of the hub's Ed25519 signing key
        #[arg(long)]
        hub_fingerprint: Option<String>,
        /// Allowed device nodeId glob pattern (default: <human-id>@*; bare '*' is forbidden)
        #[arg(long)]
        node_prefix: Option<String>,
        /// Built-in scope preset (default: member; never grants bridge:post, forward:via, or '*')
        #[arg(long, value_enum)]
        preset: Option<crate::pair::CliScopePreset>,
        /// Explicit v2 scopes to grant (repeatable or space-delimited; bridge:post, forward:via, and '*' are forbidden)
        #[arg(long, num_args = 1..)]
        grant: Vec<String>,
        /// Maximum simultaneous active devices this human may admit (1..=100, default: 10)
        #[arg(long, default_value_t = DEFAULT_DELEGATED_MAX_DEVICES)]
        max_devices: u32,
        /// Invite validity window in hours (1..=8760, default: 24)
        #[arg(long, default_value_t = 24)]
        expires_hours: u64,
        /// Join portal base URL (default: https://hyphae.to/join)
        #[arg(long, default_value = DEFAULT_JOIN_PORTAL_URL)]
        portal_url: String,
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
    /// Directly enroll a human authority and delegated admission policy on this hub (from hpub1_ or stdin JWK)
    Admit {
        /// Canonical human identifier to admit (e.g. philip)
        human_id: String,
        /// Compact public human identity card (`hpub1_...`, public keys only)
        #[arg(long)]
        id: Option<String>,
        /// Read `hpub1_...` or OKP Ed25519 public JWK JSON from stdin
        #[arg(long)]
        stdin: bool,
        /// Human-readable label for the enrolled authority
        #[arg(long, default_value = "delegated-human")]
        label: String,
        /// Allowed device nodeId glob pattern (default: <human-id>@*; bare '*' is forbidden)
        #[arg(long)]
        node_prefix: Option<String>,
        /// Built-in scope preset (default: member; never grants bridge:post, forward:via, or '*')
        #[arg(long, value_enum)]
        preset: Option<crate::pair::CliScopePreset>,
        /// Explicit v2 scopes to grant (repeatable or space-delimited; bridge:post, forward:via, and '*' are forbidden)
        #[arg(long, num_args = 1..)]
        grant: Vec<String>,
        /// Maximum simultaneous active devices this human may admit (1..=100, default: 10)
        #[arg(long, default_value_t = DEFAULT_DELEGATED_MAX_DEVICES)]
        max_devices: u32,
        /// Explicit state directory containing node.sqlite and secrets/
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Explicit node.json path
        #[arg(long)]
        config: Option<PathBuf>,
        #[command(flatten)]
        ceremony: ApprovalCeremonyArgs,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Print this node's enrolled Human Authority compact `hpub1_` public identity card and fingerprint
    Whoami {
        /// Optional humanId filter when multiple local authorities are enrolled
        #[arg(long)]
        human_id: Option<String>,
        /// Explicit state directory containing node.sqlite
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Explicit node.json path
        #[arg(long)]
        config: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Join a Team Hub via Passkey+PRF delegated human admission (alias for top-level `hyp join`)
    Join(crate::join_cmd::JoinArgs),
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

pub fn run_auth(command: AuthCommand) -> CommandResult {
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
        } => CommandResult::new(
            "auth init",
            json,
            run_auth_init(
                human_id, label, web, port, timeout, no_open, state_dir, config, json,
            ),
        ),
        AuthCommand::Add {
            human_id,
            label,
            role,
            prf_salt,
            auth_epoch,
            state_dir,
            config,
            ceremony,
            json,
        } => CommandResult::new(
            "auth add",
            json,
            run_auth_add(
                human_id, label, role, prf_salt, auth_epoch, state_dir, config, ceremony, json,
            ),
        ),
        AuthCommand::List {
            all,
            state_dir,
            json,
        } => CommandResult::new("auth list", json, run_auth_list(all, state_dir, json)),
        AuthCommand::Revoke {
            kid,
            bump_epoch,
            cascade,
            reason,
            issuer_kid,
            broadcast,
            state_dir,
            config,
            ceremony,
            json,
        } => CommandResult::new(
            "auth revoke",
            json,
            run_auth_revoke(
                kid, bump_epoch, cascade, reason, issuer_kid, broadcast, state_dir, config,
                ceremony, json,
            ),
        ),
        AuthCommand::Invite {
            human_id,
            hub,
            endpoint,
            hub_fingerprint,
            node_prefix,
            preset,
            grant,
            max_devices,
            expires_hours,
            portal_url,
            state_dir,
            config,
            json,
        } => CommandResult::new(
            "auth invite",
            json,
            run_auth_invite(
                human_id,
                hub,
                endpoint,
                hub_fingerprint,
                node_prefix,
                preset,
                grant,
                max_devices,
                expires_hours,
                portal_url,
                state_dir,
                config,
                json,
            ),
        ),
        AuthCommand::Admit {
            human_id,
            id,
            stdin,
            label,
            node_prefix,
            preset,
            grant,
            max_devices,
            state_dir,
            config,
            ceremony,
            json,
        } => CommandResult::new(
            "auth admit",
            json,
            run_auth_admit(
                human_id,
                id,
                stdin,
                label,
                node_prefix,
                preset,
                grant,
                max_devices,
                state_dir,
                config,
                ceremony,
                json,
            ),
        ),
        AuthCommand::Whoami {
            human_id,
            state_dir,
            config,
            json,
        } => CommandResult::new(
            "auth whoami",
            json,
            run_auth_whoami(human_id, state_dir, config, json),
        ),
        AuthCommand::Join(args) => crate::join_cmd::run_join(args),
        AuthCommand::CertifyNode {
            ttl_days,
            kid,
            state_dir,
            config,
            json,
        } => CommandResult::new(
            "auth certify-node",
            json,
            run_auth_certify_node(ttl_days, kid, state_dir, config, json),
        ),
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
        } => CommandResult::new(
            "auth sign",
            json,
            run_auth_sign(
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
        ),
    }
}

/// Computes a valid, collision-free reserved SecretStore key name for a local human admin Ed25519 key.
/// Always starts with `human-admin-` (which is blocked by the remote secret-drop denylist) and
/// strictly matches `validate_secret_name` (`/^[a-z0-9][a-z0-9._-]{0,63}$/`).
pub fn admin_secret_name_for_kid(kid: &str) -> String {
    local_admin_secret_names_for_kid(kid).0
}

fn legacy_admin_secret_name_for_kid(kid: &str) -> String {
    local_admin_secret_names_for_kid(kid).1
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

fn format_auth_init_confirm_summary(
    human_id: &str,
    label: &str,
    existing_authorities: usize,
    gate_locked: bool,
) -> Vec<String> {
    let mut lines = vec![
        "Human Admin Authority Initialization Summary".to_string(),
        format!("  Human ID:   {}", sanitize_tty_display(human_id)),
        "  Role:       admin".to_string(),
        format!("  Label:      {}", sanitize_tty_display(label)),
        format!("  Existing:   {existing_authorities} authority record(s) already present"),
    ];
    if gate_locked {
        lines.push(
            "  WARNING:    The approved policy will include the updated human_authorities_digest."
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
        format!("  Human ID:   {}", sanitize_tty_display(human_id)),
        format!("  Role:       {}", role.as_str()),
        format!("  Label:      {}", sanitize_tty_display(label)),
        format!("  Key ID:     {}", sanitize_tty_display(kid)),
        format!("  Auth Epoch: {auth_epoch}"),
    ];
    if let Some(ekid) = enc_kid {
        lines.push(format!("  Enc Key ID: {}", sanitize_tty_display(ekid)));
    }
    if has_node_cert {
        lines.push("  Node Cert:  verified hcert1_ included".to_string());
    }
    if gate_locked {
        lines.push(
            "  WARNING:    The approved policy will include the updated human_authorities_digest."
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
        format!("  Human ID:   {}", sanitize_tty_display(&target.human_id)),
        format!("  Role:       {}", target.role.as_str()),
        format!("  Label:      {}", sanitize_tty_display(&target.label)),
        format!("  Key ID:     {}", sanitize_tty_display(&target.kid)),
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
        format!("  Reason:     {}", sanitize_tty_display(reason)),
    ];
    if gate_locked {
        lines.push(
            "  WARNING:    The approved policy will include the updated human_authorities_digest."
                .to_string(),
        );
    }
    lines
}

#[allow(clippy::too_many_arguments)]
fn format_auth_sign_confirm_summary(
    kind: CliDropKind,
    human_id: &str,
    human_kid: &str,
    auth_epoch: u64,
    target_node_id: &str,
    target_handle: Option<&str>,
    secret_spec: Option<&SecretDropSpec>,
    drop_id: &str,
    ttl_secs: u64,
    body: &str,
) -> Vec<String> {
    let mut lines = vec![
        format!(
            "Sign & Seal Verified Human Drop ({})",
            kind.to_crypto_kind().as_str()
        ),
        format!(
            "  Authority:   {} (kid: {}, epoch: {auth_epoch})",
            sanitize_tty_display(human_id),
            sanitize_tty_display(human_kid)
        ),
        format!("  Target Node: {}", sanitize_tty_display(target_node_id)),
    ];
    if let Some(h) = target_handle {
        lines.push(format!("  Handle:      {}", sanitize_tty_display(h)));
    }
    if let Some(spec) = secret_spec {
        lines.push(format!(
            "  Secret Name: {} (overwrite: {})",
            sanitize_tty_display(&spec.name),
            spec.overwrite
        ));
    }
    lines.push(format!(
        "  Drop ID:     {}",
        if drop_id.is_empty() {
            "offline".to_string()
        } else {
            sanitize_tty_display(drop_id)
        }
    ));
    lines.push(format!("  TTL:         {ttl_secs}s"));
    match kind {
        CliDropKind::Secret => {
            lines.push(format!(
                "  Payload:     [REDACTED SECRET — {} byte(s)]",
                body.len()
            ));
        }
        CliDropKind::Directive => {
            let preview: String = sanitize_tty_display(body).chars().take(120).collect();
            let suffix = if body.chars().count() > 120 {
                "..."
            } else {
                ""
            };
            lines.push(format!("  Directive:   {preview}{suffix}"));
        }
    }
    lines
}

/// A locked gate's `node.json` rewritten for a changed `human_authorities` digest. It is prepared
/// before the Passkey ceremony so one tap binds the exact resulting `policySha256`, and nothing is
/// ever silently re-signed from a shell key.
struct ApprovedPolicyUpdate {
    cfg_map: serde_json::Map<String, Value>,
    gate_cfg: SecurityGateConfig,
    policy_sha: String,
    authorities_digest: String,
    seal_seq: u64,
}

impl ApprovedPolicyUpdate {
    fn prepare(config_path: &Path, db: &NodeDb, authorities_digest: &str) -> Result<Self, String> {
        let cfg_map = NodeFile::read_document_or_empty(config_path)?;
        let mut gate_cfg: SecurityGateConfig = match cfg_map.get("gate") {
            Some(v) => serde_json::from_value(v.clone())
                .map_err(|e| format!("malformed gate config in {}: {e}", config_path.display()))?,
            None => SecurityGateConfig::default(),
        };
        let policy_sha = gate_cfg
            .prepare_passkey_seal(authorities_digest)
            .map_err(|e| format!("failed to compute locked gate policy SHA-256: {e}"))?;
        Ok(Self {
            cfg_map,
            gate_cfg,
            policy_sha,
            authorities_digest: authorities_digest.to_string(),
            seal_seq: next_seal_seq(db)?,
        })
    }

    /// Stores the approved seal and writes the gate block whose hash the approval signed.
    fn apply(
        mut self,
        db: &NodeDb,
        config_write: &Path,
        verified: &VerifiedApproval,
    ) -> Result<u64, String> {
        persist_passkey_gate_seal(db, verified)?;
        self.cfg_map
            .entry("nodeId")
            .or_insert_with(|| json!(verified.action.node_id));
        let gate_val = serde_json::to_value(&self.gate_cfg).map_err(|e| e.to_string())?;
        self.cfg_map.insert("gate".to_string(), gate_val);
        NodeFile::write_document(config_write, self.cfg_map)?;
        Ok(self.seal_seq)
    }
}

/// Runs the Passkey ceremony for an `auth.add` / `auth.revoke` `action`, binding the re-seal of a
/// locked gate into the same approval.
#[allow(clippy::too_many_arguments)]
fn approve_authority_change(
    state_dir: &Path,
    config_read: &Path,
    db: &NodeDb,
    secrets: &SecretStore,
    mut action: HumanApprovalActionV1,
    reseal: Option<&ApprovedPolicyUpdate>,
    summary: &[String],
    ceremony: &ApprovalCeremonyArgs,
) -> Result<Box<VerifiedApproval>, CliError> {
    if let Some(reseal) = reseal {
        action.seal_seq = reseal.seal_seq;
        action.policy_sha256 = Some(reseal.policy_sha.clone());
        action.authorities_digest = Some(reseal.authorities_digest.clone());
    }
    match run_passkey_approval_ceremony(
        state_dir,
        config_read,
        db,
        secrets,
        action,
        summary,
        ceremony,
    ) {
        Ok(CeremonyOutcome::Approved(verified)) => Ok(verified),
        Err(err) => Err(err.into_cli_error()),
    }
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
    let sock = resolve_daemon_socket_path(
        state_dir,
        !explicit_state_dir && !explicit_config,
        SocketEnvPolicy::TrimmedUtf8,
    );
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
                if let Ok(receipt) =
                    rt.block_on(send_local_ingest_event(&ingest_socket, &wire_json))
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

pub(crate) fn random_b64url(len: usize) -> Result<String, String> {
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

fn persist_verified_node_cert(db: &NodeDb, cert: &VerifiedEnrolledNodeCert) -> Result<(), String> {
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
) -> Result<ExitCode, CliError> {
    let cmd = "auth init";
    let human_id = human_id_arg
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(default_human_id);

    if human_id == LOCAL_NODE_ID || !is_valid_node_id(&human_id) {
        return Err(CliError::usage("INVALID_HUMAN_ID", format!(
                "Invalid --human-id '{human_id}': must match /^[a-z0-9][a-z0-9@._-]{{0,63}}$/ and not be 'local'"
            )).with_fix("Example: hyp auth init --human-id alice".to_string()));
    }

    let trimmed_label = label.trim();
    if trimmed_label.is_empty() || trimmed_label.len() > 128 {
        return Err(CliError::usage(
            "INVALID_LABEL",
            "--label must be 1..=128 printable characters",
        ));
    }

    let state_dir = resolve_state_dir(state_dir_arg.as_deref(), config_arg.as_deref(), None);
    let config_read =
        resolve_config_path_for_read(config_arg.as_deref(), state_dir_arg.as_deref(), None);

    // Resolve and validate Drop Portal URL fail-closed BEFORE generating keys or opening callbacks.
    let resolved_drop_portal_url = if web {
        let configured_drop_portal_url: Option<String> = if config_read.exists() {
            match load_node_or_legacy_config(&config_read) {
                Ok(cfg) => match cfg.raw.get("dropPortalUrl") {
                    None | Some(Value::Null) => None,
                    Some(Value::String(s)) => Some(s.clone()),
                    Some(_) => {
                        return Err(CliError::error("CONFIG_ERROR", format!(
                                "Invalid dropPortalUrl in {}: must be a string",
                                cfg.path.display()
                            )).with_fix(
                                "Set dropPortalUrl to an https:// URL (e.g. \"https://hyphae.to/drop\") or loopback http://127.0.0.1."
                                    .to_string(),
                            ));
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
                return Err(CliError::error("CONFIG_ERROR", format!("Invalid Drop Portal URL: {e}")).with_fix(
                        "Set HYPHAE_DROP_PORTAL_URL or node.json dropPortalUrl to an https:// URL (e.g. https://hyphae.to/drop) or loopback http://127.0.0.1."
                            .to_string(),
                    ));
            }
        }
    } else {
        None
    };

    // P0 `#10` (H1 & H2): Once a Passkey Admin is enrolled OR the Security Gate is locked,
    // `hyp auth init` MUST fail closed and refuse to mint a shell-accessible key or silently
    // mutate authorities! Additional authorities must go through Passkey-approved `hyp auth add`.
    let secrets = open_secret_store(&state_dir, state_dir_arg.is_some());
    let lock_state = inspect_policy_integrity(&config_read, &state_dir, &secrets);
    let passkey_admin_present = has_passkey_history(&state_dir);
    if passkey_admin_present {
        return Err(CliError::error("PASSKEY_ADMIN_ENROLLED", "A Passkey Admin authority is already enrolled on this node; `hyp auth init` refuses to bypass the Passkey human boundary.").with_fix(format!(
                "Enroll additional authorities via Passkey-approved `hyp auth add --human-id <id> --label <name> --state-dir {}`.",
                state_dir.display()
            )));
    }
    if lock_state.approved && (!web || lock_state.tampered_reason.is_some()) {
        return Err(CliError::error("GATE_LOCKED", "An approved policy already exists; initialize cannot change authorities. Use live auth add.").with_fix(format!(
                "Enroll via Passkey-approved `hyp auth add --state-dir {}`.",
                state_dir.display()
            )));
    }

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
    // Upgrading a legacy non-Passkey node to its first Passkey Admin via `--web` or adding another
    // local key on a node with existing non-Passkey authorities still requires TTY confirmation.
    if existing_count > 0 {
        let summary =
            format_auth_init_confirm_summary(&human_id, trimmed_label, existing_count, false);
        let prompt = if web {
            format!(
                "Enroll Passkey Admin authority '{}' via browser (--web, label: {}) on a node with existing authorities? [y/N]: ",
                sanitize_tty_display(&human_id),
                sanitize_tty_display(trimmed_label)
            )
        } else {
            format!(
                "Initialize additional human admin authority '{}' (label: {})? [y/N]: ",
                sanitize_tty_display(&human_id),
                sanitize_tty_display(trimmed_label)
            )
        };
        require_interactive_tty_confirmation(&summary, &prompt)
            .map_err(|err| (err).into_cli_error(cmd))?;
    }

    ensure_dir(&state_dir, true).map_err(|e| CliError::error("IO_ERROR", e))?;

    let node = open_local_unified_node(&state_dir, &config_read, &secrets)
        .map_err(|e| CliError::error("NODE_OPEN_FAILED", e))?;

    let min_epoch = {
        let db = node.db();
        match db.human().min_auth_epoch() {
            Ok(e) => e,
            Err(e) => return Err(CliError::error("DB_ERROR", e.to_string())),
        }
    };

    // P0 `#10` (H2): `hyp auth init --web` enrolls the browser Passkey DIRECTLY as `role: admin`
    // WITHOUT generating or storing any plaintext PKCS#8 `human-admin-*` key in SecretStore!
    if web {
        let rt = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(rt) => rt,
            Err(e) => {
                return Err(CliError::error(
                    "RUNTIME_ERROR",
                    format!("Failed to start async runtime: {e}"),
                ));
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
                return Err(CliError::error("WEB_ENROLL_FAILED", e).with_fix("Run `hyp auth add --human-id <id> --label <name> --role admin` and pipe the Passkey enrollment bundle via stdin instead.".to_string()));
            }
        };

        let effective_label = if trimmed_label != "local-cli-admin" {
            trimmed_label.to_string()
        } else {
            enrolled.label.clone()
        };
        let inserted = {
            let db = node.db();
            match db.human().bootstrap_authority(
                &HumanAuthorityInput {
                    human_id: enrolled.human_id.clone(),
                    kid: enrolled.kid.clone(),
                    label: effective_label,
                    role: HumanAuthorityRole::Admin,
                    jwk_json: enrolled.jwk_json.clone(),
                    enc_jwk_json: enrolled.enc_jwk_json.clone(),
                    prf_salt: Some(enrolled.prf_salt.clone()),
                    auth_epoch: enrolled.auth_epoch,
                },
                now_ms(),
            ) {
                Ok(r) => r,
                Err(e) => {
                    return Err(CliError::error("DB_ERROR", e.to_string()));
                }
            }
        };
        let passkey_hcert1 = if let Some(ref verified_cert) = enrolled.node_cert {
            let db = node.db();
            persist_verified_node_cert(&db, verified_cert)
                .map_err(|e| CliError::error("DB_ERROR", e))?;
            Some(verified_cert.armored.clone())
        } else {
            None
        };

        let public_jwk: Value = serde_json::from_str(&inserted.jwk_json).unwrap_or(Value::Null);
        let digest = {
            let db = node.db();
            db.human().authorities_digest().ok()
        };
        let node_id_str = node.node_id().as_str().to_string();
        drop(node);

        let web_enrolled = json!({
            "humanId": inserted.human_id,
            "kid": inserted.kid,
            "role": inserted.role.as_str(),
            "label": inserted.label,
            "encKey": inserted.enc_jwk_json.is_some(),
            "encKid": enrolled.enc_kid,
            "prfSalt": inserted.prf_salt,
            "authEpoch": inserted.auth_epoch,
            "credentialId": enrolled.credential_id,
            "nodeCertSigned": enrolled.node_cert.is_some(),
        });
        let next = vec![
            format!("hyp gate apply --state-dir {}", state_dir.display()),
            format!("hyp auth list --state-dir {}", state_dir.display()),
        ];

        if as_json {
            let data = json!({
                "humanId": inserted.human_id,
                "kid": inserted.kid,
                "role": inserted.role.as_str(),
                "label": inserted.label,
                "authEpoch": inserted.auth_epoch,
                "publicJwk": public_jwk,
                "encKey": inserted.enc_jwk_json.is_some(),
                "encKid": enrolled.enc_kid,
                "prfSalt": inserted.prf_salt,
                "passkeyBacked": true,
                "secretName": Value::Null,
                "secretBackend": secrets.backend().as_str(),
                "nodeId": node_id_str,
                "nodeCert": passkey_hcert1,
                "authoritiesDigest": digest,
                "gatePolicyResigned": false,
                "gateReloaded": false,
                "webEnrolled": web_enrolled,
                "stateDir": state_dir.display().to_string(),
            });
            let envelope = JsonEnvelope::ok(cmd.to_string(), format!(
                    "Enrolled Passkey Admin authority '{}' (kid {}) with zero local private key on disk",
                    inserted.human_id, inserted.kid
                ), data).next(next);
            print_json(&envelope);
        } else {
            println!(
                "OK    Enrolled Passkey Admin authority '{}' (kid={})",
                inserted.human_id, inserted.kid
            );
            println!("      Label:     {}", inserted.label);
            println!(
                "      Boundary:  Hardware/browser Passkey+PRF (zero local private key stored)"
            );
            if passkey_hcert1.is_some() {
                println!("      Node Cert: verified Passkey-signed hcert1_ for '{node_id_str}'");
            }
            print_next_steps(&next);
        }
        return Ok(ExitCode::from(EXIT_OK));
    }

    // Local non-web CLI init (unlocked dev/hub node with 0 Passkey Admins).
    let admin_kp = match Ed25519KeyPair::generate() {
        Ok(kp) => kp,
        Err(e) => {
            return Err(CliError::error(
                "KEYGEN_FAILED",
                format!("Failed to generate Ed25519 admin keypair: {e}"),
            ));
        }
    };
    let kid = admin_kp.kid();
    let jwk = admin_kp.to_jwk();
    let jwk_json =
        to_canonical_json(&jwk).map_err(|e| CliError::error("JSON_ERROR", e.to_string()))?;
    let secret_name = admin_secret_name_for_kid(&kid);
    let pkcs8_b64 = admin_kp.export_pkcs8_b64();
    secrets.set(&secret_name, &pkcs8_b64).map_err(|e| {
        CliError::error(
            "SECRET_STORE_ERROR",
            format!("Failed to persist admin signing key in SecretStore: {e}"),
        )
    })?;
    drop(pkcs8_b64);

    let inserted = {
        let db = node.db();
        match db.human().bootstrap_authority(
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
            Err(e) => return Err(CliError::error("DB_ERROR", e.to_string())),
        }
    };

    let hcert1 = match node.issue_node_cert(&admin_kp, &kid, 365) {
        Ok((_signed_cert, token)) => token,
        Err(e) => {
            return Err(CliError::error(
                "CERTIFY_FAILED",
                format!("Failed to certify local node: {e}"),
            ));
        }
    };

    let digest = {
        let db = node.db();
        db.human().authorities_digest().ok()
    };
    let node_id_str = node.node_id().as_str().to_string();
    drop(node);

    let warnings = vec![
        "Local CLI key stored in SecretStore cannot approve Security Gate or authority changes; run `hyp auth init --web` to enroll a browser Passkey Admin."
            .to_string(),
    ];
    let next = vec![
        format!("hyp auth list --state-dir {}", state_dir.display()),
        format!(
            "hyp drop create --kind directive --offline --state-dir {}",
            state_dir.display()
        ),
    ];

    if as_json {
        let data = json!({
            "humanId": inserted.human_id,
            "kid": inserted.kid,
            "role": inserted.role.as_str(),
            "label": inserted.label,
            "authEpoch": inserted.auth_epoch,
            "publicJwk": jwk,
            "passkeyBacked": false,
            "secretName": secret_name,
            "secretBackend": secrets.backend().as_str(),
            "nodeId": node_id_str,
            "nodeCert": hcert1,
            "authoritiesDigest": digest,
            "gatePolicyResigned": false,
            "gateReloaded": false,
            "webEnrolled": Value::Null,
            "stateDir": state_dir.display().to_string(),
        });
        let envelope = JsonEnvelope::ok(
            cmd.to_string(),
            format!(
                "Initialized local human admin authority '{}' (kid {}) and certified node '{}'",
                inserted.human_id, inserted.kid, node_id_str
            ),
            data,
        )
        .warnings(warnings)
        .next(next);
        print_json(&envelope);
    } else {
        println!(
            "OK    Initialized local human admin authority '{}' (kid={})",
            inserted.human_id, inserted.kid
        );
        println!("      Label:     {}", inserted.label);
        println!(
            "      Keystore:  {} ({})",
            secret_name,
            secrets.backend().as_str()
        );
        println!("      Node Cert: issued 365d hcert1_ for '{node_id_str}'");
        print_warnings(&warnings);
        print_next_steps(&next);
    }

    Ok(ExitCode::from(EXIT_OK))
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
    ceremony: ApprovalCeremonyArgs,
    as_json: bool,
) -> Result<ExitCode, CliError> {
    let cmd = "auth add";
    let human_id = human_id_raw.trim().to_ascii_lowercase();
    if human_id == LOCAL_NODE_ID || !is_valid_node_id(&human_id) {
        return Err(CliError::usage(
            "INVALID_HUMAN_ID",
            format!("Invalid --human-id '{human_id_raw}'"),
        ));
    }
    let trimmed_label = label.trim();
    if trimmed_label.is_empty() || trimmed_label.len() > 128 {
        return Err(CliError::usage(
            "INVALID_LABEL",
            "--label must be 1..=128 printable characters",
        ));
    }

    let state_dir = resolve_state_dir(state_dir_arg.as_deref(), config_arg.as_deref(), None);
    let config_read =
        resolve_config_path_for_read(config_arg.as_deref(), state_dir_arg.as_deref(), None);
    let config_write =
        resolve_config_path_for_write(config_arg.as_deref(), state_dir_arg.as_deref(), None);
    let secrets = open_secret_store(&state_dir, state_dir_arg.is_some());
    let lock_state = inspect_policy_integrity(&config_read, &state_dir, &secrets);
    if let Some(reason) = lock_state.tampered_reason.as_deref() {
        return Err(CliError::error("GATE_POLICY_TAMPERED", format!(
                "Security Gate lock failed verification ({reason}); `hyp {cmd}` refuses to re-seal an unverified policy on disk."
            )).with_fix(format!(
                "Inspect and explicitly re-lock the policy via `hyp gate apply --state-dir {}` before mutating human authorities.",
                state_dir.display()
            )));
    }

    let mut raw = String::new();
    io::stdin()
        .lock()
        .take(MAX_JWK_STDIN_BYTES + 1)
        .read_to_string(&mut raw)
        .map_err(|e| {
            CliError::error(
                "STDIN_ERROR",
                format!("Failed to read public JWK from stdin: {e}"),
            )
        })?;
    if raw.len() as u64 > MAX_JWK_STDIN_BYTES {
        return Err(CliError::usage(
            "PAYLOAD_TOO_LARGE",
            format!("Stdin JWK payload exceeds {MAX_JWK_STDIN_BYTES} byte safety cap"),
        ));
    }
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CliError::usage("EMPTY_STDIN", "Expected OKP Ed25519 public JWK JSON on stdin").with_fix("Pipe public JWK JSON: echo '{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"...\"}' | hyp auth add --human-id alice --label phone".to_string()));
    }

    let parsed: Value = match serde_json::from_str(trimmed) {
        Ok(v) => v,
        Err(e) => {
            return Err(CliError::usage(
                "INVALID_JSON",
                format!("Invalid JWK JSON on stdin: {e}"),
            ));
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
                obj.get("prfSalt")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
                obj.get("authEpoch").and_then(Value::as_u64),
                obj.get("kid")
                    .and_then(Value::as_str)
                    .map(ToOwned::to_owned),
            )
        } else {
            (parsed, None, None, None, None, None)
        }
    } else {
        return Err(CliError::usage(
            "INVALID_JWK",
            "Expected a JSON object containing an OKP Ed25519 public JWK",
        ));
    };

    let jwk: OkpJwk = match serde_json::from_value(jwk_val) {
        Ok(j) => j,
        Err(e) => {
            return Err(CliError::usage(
                "INVALID_JWK",
                format!("Malformed OKP JWK: {e}"),
            ));
        }
    };
    let authority_ed_pk = match jwk.to_ed25519() {
        Ok(pk) => pk,
        Err(e) => {
            return Err(CliError::usage(
                "INVALID_JWK",
                format!("Public key must be a valid OKP Ed25519 JWK: {e}"),
            ));
        }
    };
    let (enc_jwk_json, enc_kid) = match parse_optional_enc_jwk(bundle_enc_jwk_val.as_ref()) {
        Ok(Some((canon, ekid))) => (Some(canon), Some(ekid)),
        Ok(None) => (None, None),
        Err(e) => {
            return Err(CliError::usage("INVALID_ENC_JWK", e));
        }
    };
    let kid = match jwk.thumbprint() {
        Ok(k) => k,
        Err(e) => {
            return Err(CliError::usage(
                "INVALID_JWK",
                format!("Failed to compute RFC 7638 kid: {e}"),
            ));
        }
    };
    if let Some(ref exp) = expected_kid {
        if exp != &kid {
            return Err(CliError::usage(
                "KID_MISMATCH",
                format!("Bundle kid '{exp}' does not match JWK thumbprint '{kid}'"),
            ));
        }
    }
    let canonical_jwk_json =
        to_canonical_json(&jwk).map_err(|e| CliError::error("JSON_ERROR", e.to_string()))?;

    ensure_dir(&state_dir, true).map_err(|e| CliError::error("IO_ERROR", e))?;

    let db = NodeDb::open(state_dir.join("node.sqlite"))
        .map_err(|e| CliError::error("DB_ERROR", e.to_string()))?;
    let min_epoch = db.human().min_auth_epoch().unwrap_or(1);
    let effective_epoch = auth_epoch_arg
        .or(bundle_epoch)
        .unwrap_or(min_epoch)
        .max(min_epoch);
    let effective_prf_salt = prf_salt_arg.or(bundle_prf_salt);

    let loaded = if config_read.exists() {
        load_node_or_legacy_config(&config_read).ok()
    } else {
        None
    };
    let local_node_id = resolve_effective_node_id(loaded.as_ref(), Some(&db));

    // Validate optional Passkey-signed `nodeCert` (`hcert1_`) BEFORE mutating DB so invalid bundles
    // fail closed cleanly.
    let verified_bundle_cert = if let Some(ref raw_cert) = bundle_node_cert {
        let local_identity = match secrets.load_or_create_node_keys(&local_node_id) {
            Ok(keys) => keys,
            Err(e) => {
                return Err(CliError::error(
                    "NODE_KEY_ERROR",
                    format!("Failed to load local node identity keys: {e}"),
                ));
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
                return Err(CliError::usage("INVALID_NODE_CERT", e));
            }
        }
    } else {
        None
    };

    let auth_input = HumanAuthorityInput {
        human_id: human_id.clone(),
        kid: kid.clone(),
        label: trimmed_label.to_string(),
        role: role.to_store_role(),
        jwk_json: canonical_jwk_json,
        enc_jwk_json,
        prf_salt: effective_prf_salt,
        auth_epoch: effective_epoch,
    };

    let mut summary = format_auth_add_confirm_summary(
        &human_id,
        role.to_store_role(),
        trimmed_label,
        &kid,
        effective_epoch,
        enc_kid.as_deref(),
        verified_bundle_cert.is_some(),
        lock_state.approved,
    );

    // Authorization: a Passkey Admin approval once one is enrolled (or the gate is locked),
    // otherwise interactive controlling-TTY confirmation.
    let approved: Option<Box<VerifiedApproval>>;
    let reseal: Option<ApprovedPolicyUpdate>;
    {
        {
            let prepared = db
                .human()
                .projected_authorities_digest_after_upsert(&auth_input)
                .map_err(|e| e.to_string())
                .and_then(|digest| ApprovedPolicyUpdate::prepare(&config_read, &db, &digest));
            match prepared {
                Ok(r) => reseal = Some(r),
                Err(e) => {
                    return Err(CliError::error("GATE_POLICY_SYNC_FAILED", e));
                }
            }
            summary.push(
                "Re-seals the locked Security Gate with the updated human_authorities_digest"
                    .to_string(),
            );
        }
        let mut action = base_approval_action(HumanApprovalActionKind::AuthAdd, local_node_id, 0);
        action.target_human_id = Some(human_id.clone());
        action.target_kid = Some(kid.clone());
        action.target_role = Some(role.to_store_role().as_str().to_string());
        action.parameters = Some(json!({"authority": auth_input}));
        match approve_authority_change(
            &state_dir,
            &config_read,
            &db,
            &secrets,
            action,
            reseal.as_ref(),
            &summary,
            &ceremony,
        ) {
            Ok(verified) => approved = Some(verified),
            Err(error) => return Err(error),
        }
    }

    let (Some(reseal), Some(verified)) = (reseal, approved.as_deref()) else {
        return Err(CliError::error(
            "PASSKEY_AUTHORITY_REQUIRED",
            "Live approval is required",
        ));
    };
    let approved_by_kid = Some(verified.kid.clone());
    let committed = execute_approved_operation(&config_read, &config_write, &db, verified, || {
        let rec = db
            .human()
            .upsert_authority(&auth_input, now_ms())
            .map_err(|e| e.to_string())?;
        let node_cert_stored = if let Some(ref cert) = verified_bundle_cert {
            persist_verified_node_cert(&db, cert)?;
            true
        } else {
            false
        };
        let seq = reseal.apply(&db, &config_write, verified)?;
        Ok((rec, node_cert_stored, Some(seq)))
    });
    let (rec, node_cert_stored, approved_seal_seq) =
        committed.map_err(|e| CliError::error("APPROVAL_COMMIT_FAILED", e))?;
    let gate_resigned = approved_seal_seq.is_some();
    let digest = db.human().authorities_digest().ok();
    drop(db);

    let mut warnings: Vec<String> = Vec::new();
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
    let via = if approved_by_kid.is_some() {
        " via Passkey Admin approval"
    } else {
        ""
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
            "approvedByKid": approved_by_kid,
            "sealSeq": approved_seal_seq,
            "gatePolicyResigned": gate_resigned,
            "gateReloaded": gate_reloaded,
        });
        if let Some(ref err) = gate_reload_error {
            data["gateReloadError"] = json!(err);
        }
        let envelope = JsonEnvelope::ok(
            cmd.to_string(),
            format!(
                "Enrolled human authority '{}' ({}) kid {}{via}",
                rec.human_id,
                rec.role.as_str(),
                rec.kid
            ),
            data,
        )
        .warnings(warnings)
        .next(next);
        print_json(&envelope);
    } else {
        println!(
            "OK    Enrolled human authority '{}' (role={}, kid={}){via}",
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
            println!("      Gate Seal: Passkey-sealed with updated human_authorities_digest");
            if gate_reloaded {
                println!("      Gate Live: reloaded active daemon policy (no restart needed)");
            }
        }
        print_warnings(&warnings);
        print_next_steps(&next);
    }
    Ok(ExitCode::from(EXIT_OK))
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

fn run_auth_list(
    all: bool,
    state_dir_arg: Option<PathBuf>,
    as_json: bool,
) -> Result<ExitCode, CliError> {
    let cmd = "auth list";
    let state_dir = resolve_state_dir(state_dir_arg.as_deref(), None, None);
    let db_path = state_dir.join("node.sqlite");

    let (rows, min_epoch, digest): (Vec<AuthListRow>, u64, Option<String>) = if db_path.exists() {
        let db = NodeDb::open(&db_path).map_err(|e| CliError::error("DB_ERROR", e.to_string()))?;
        let list = match db.human().list_authorities(all) {
            Ok(v) => v.into_iter().map(AuthListRow::from).collect(),
            Err(e) => return Err(CliError::error("DB_ERROR", e.to_string())),
        };
        let min_ep = db.human().min_auth_epoch().unwrap_or(1);
        let dig = db.human().authorities_digest().ok();
        (list, min_ep, dig)
    } else {
        (Vec::new(), 1, None)
    };

    if as_json {
        let envelope = JsonEnvelope::ok(
            cmd.to_string(),
            format!(
                "{} human authority key(s) (minAuthEpoch={min_epoch})",
                rows.len()
            ),
            json!({
                "count": rows.len(),
                "includeRevoked": all,
                "minAuthEpoch": min_epoch,
                "authoritiesDigest": digest,
                "authorities": rows,
                "stateDir": state_dir.display().to_string(),
            }),
        )
        .next(if rows.is_empty() {
            vec![format!("hyp auth init --state-dir {}", state_dir.display())]
        } else {
            Vec::new()
        });
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
    Ok(ExitCode::from(EXIT_OK))
}

#[allow(clippy::too_many_arguments)]
fn run_auth_revoke(
    kid_arg: String,
    bump_epoch: bool,
    cascade: bool,
    reason: String,
    issuer_kid_arg: Option<String>,
    broadcast: bool,
    state_dir_arg: Option<PathBuf>,
    config_arg: Option<PathBuf>,
    ceremony: ApprovalCeremonyArgs,
    as_json: bool,
) -> Result<ExitCode, CliError> {
    let cmd = "auth revoke";
    let query = kid_arg.trim();
    if query.is_empty() {
        return Err(CliError::usage(
            "INVALID_KID",
            "kid or humanId cannot be empty",
        ));
    }

    let explicit_state = state_dir_arg.is_some() || config_arg.is_some();
    let state_dir = resolve_state_dir(state_dir_arg.as_deref(), config_arg.as_deref(), None);
    let config_read =
        resolve_config_path_for_read(config_arg.as_deref(), state_dir_arg.as_deref(), None);
    let config_write =
        resolve_config_path_for_write(config_arg.as_deref(), state_dir_arg.as_deref(), None);
    let secrets = open_secret_store(&state_dir, state_dir_arg.is_some());
    let lock_state = inspect_policy_integrity(&config_read, &state_dir, &secrets);
    if let Some(reason) = lock_state.tampered_reason.as_deref() {
        return Err(CliError::error("GATE_POLICY_TAMPERED", format!(
                "Security Gate lock failed verification ({reason}); `hyp {cmd}` refuses to re-seal an unverified policy on disk."
            )).with_fix(format!(
                "Inspect and explicitly re-lock the policy via `hyp gate apply --state-dir {}` before mutating human authorities.",
                state_dir.display()
            )));
    }

    let db_path = state_dir.join("node.sqlite");
    if !db_path.exists() {
        return Err(CliError::error(
            "AUTHORITY_NOT_FOUND",
            format!("Authority '{query}' not found (database does not exist yet)"),
        ));
    }

    let db = NodeDb::open(&db_path).map_err(|e| CliError::error("DB_ERROR", e.to_string()))?;
    let all = db
        .human()
        .list_authorities(true)
        .map_err(|e| CliError::error("DB_ERROR", e.to_string()))?;

    let targets: Vec<HumanAuthorityRecord> =
        resolve_authorities_for_revoke(&all, query, cascade)
            .map_err(|e| CliError::error("AUTHORITY_NOT_FOUND", e))?;
    let target = targets[0].clone();

    let cascade_peer_ids: Vec<String> = if cascade {
        db.peers()
            .list_peers_admitted_by_human(&target.human_id, true)
            .unwrap_or_default()
            .into_iter()
            .map(|p| p.peer_id)
            .collect()
    } else {
        Vec::new()
    };

    let current_min = db.human().min_auth_epoch().unwrap_or(1);
    let new_min = if bump_epoch {
        current_min.saturating_add(1)
    } else {
        current_min
    };
    let survivor = db
        .human()
        .list_active_authorities()
        .ok()
        .is_some_and(|records| {
            records.iter().any(|a| {
                a.auth_epoch >= new_min
                    && !targets.iter().any(|t| t.kid == a.kid)
                    && hyp_node::gates::is_passkey_backed_admin(a, new_min, Some(&secrets))
            })
        });
    if !survivor {
        return Err(CliError::error(
            "PASSKEY_ADMIN_REQUIRED_AFTER_REVOKE",
            "Revocation would leave no active Passkey Admin. Enroll another Passkey Admin at the resulting epoch before revoking.",
        ));
    }

    let now = now_ms();
    let revoked_at = format_rfc3339_millis(now);

    let issuer_kp: Option<Ed25519KeyPair> = if let Some(ref ik) = issuer_kid_arg {
        all.iter()
            .find(|a| a.status == HumanAuthorityStatus::Active && a.kid == *ik)
            .and_then(|a| load_local_authority_keypair(&secrets, &a.kid).ok())
    } else {
        all.iter()
            .filter(|a| {
                a.status == HumanAuthorityStatus::Active
                    && a.role == HumanAuthorityRole::Admin
                    && !targets.iter().any(|t| t.kid == a.kid)
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
        return Err(CliError::error("SIGNER_KEY_UNAVAILABLE", "Cannot --broadcast revocation without an active local admin Ed25519 signing key to sign SignedHumanRevocationV1").with_fix(
                "Pass --issuer-kid <active-admin-kid> or run `hyp auth init` on an admin node."
                    .to_string(),
            ));
    }

    let mut summary = format_auth_revoke_confirm_summary(
        &target,
        bump_epoch,
        current_min,
        new_min,
        broadcast,
        &reason,
        lock_state.approved,
    );
    if cascade {
        summary.push(format!(
            "  Cascade:    yes (disables delegation & revokes {} active admitted peer(s))",
            cascade_peer_ids.len()
        ));
    }

    let approved: Option<Box<VerifiedApproval>>;
    let reseal: Option<ApprovedPolicyUpdate>;
    {
        let loaded = if config_read.exists() {
            load_node_or_legacy_config(&config_read).ok()
        } else {
            None
        };
        let local_node_id = resolve_effective_node_id(loaded.as_ref(), Some(&db));
        {
            // Revocation keeps the row, so the authorities digest is unchanged by it.
            let prepared = db
                .human()
                .authorities_digest()
                .map_err(|e| e.to_string())
                .and_then(|digest| ApprovedPolicyUpdate::prepare(&config_read, &db, &digest));
            match prepared {
                Ok(r) => reseal = Some(r),
                Err(e) => {
                    return Err(CliError::error("GATE_POLICY_SYNC_FAILED", e));
                }
            }
        }
        let mut action =
            base_approval_action(HumanApprovalActionKind::AuthRevoke, local_node_id, 0);
        action.target_human_id = Some(target.human_id.clone());
        action.target_kid = Some(target.kid.clone());
        action.bump_epoch = Some(bump_epoch);
        action.cascade = Some(cascade);
        action.parameters =
            Some(json!({"targets": targets, "reason": reason, "newMinAuthEpoch": new_min}));
        match approve_authority_change(
            &state_dir,
            &config_read,
            &db,
            &secrets,
            action,
            reseal.as_ref(),
            &summary,
            &ceremony,
        ) {
            Ok(verified) => approved = Some(verified),
            Err(error) => return Err(error),
        }
    }
    let approved_by_kid = approved.as_ref().map(|v| v.kid.clone());

    let (Some(reseal), Some(verified)) = (reseal, approved.as_deref()) else {
        return Err(CliError::error(
            "PASSKEY_AUTHORITY_REQUIRED",
            "Live approval is required",
        ));
    };
    let committed = execute_approved_operation(&config_read, &config_write, &db, verified, || {
        let mut effective_min = current_min;
        for t in &targets {
            let rev_json = if t.kid == target.kid {
                match &signed_revocation {
                    Some(sr) => serde_json::to_string(sr).unwrap_or_else(|_| "{}".to_string()),
                    None => json!({
                        "v": 1,
                        "humanId": t.human_id,
                        "revokedKid": t.kid,
                        "newMinAuthEpoch": new_min,
                        "revokedAt": revoked_at,
                        "reason": reason,
                        "approvedByKid": approved_by_kid,
                    })
                    .to_string(),
                }
            } else {
                json!({
                    "v": 1,
                    "humanId": t.human_id,
                    "revokedKid": t.kid,
                    "newMinAuthEpoch": new_min,
                    "revokedAt": revoked_at,
                    "reason": reason,
                    "approvedByKid": approved_by_kid,
                })
                .to_string()
            };
            effective_min = effective_min.max(
                db.human()
                    .revoke_authority_monotonic(&t.human_id, &t.kid, new_min, &rev_json, now)
                    .map_err(|e| e.to_string())?,
            );
        }
        require_revocation_survivor(&db, effective_min, &secrets)?;
        let revoked_peers = if cascade {
            db.human()
                .set_delegation_enabled(&target.human_id, false, now)
                .map_err(|e| e.to_string())?;
            db.peers()
                .revoke_peers_admitted_by_human(&target.human_id, now)
                .map_err(|e| e.to_string())?
        } else {
            Vec::new()
        };
        let seq = reseal.apply(&db, &config_write, verified)?;
        Ok((effective_min, revoked_peers, Some(seq)))
    });
    let (effective_min, revoked_peers, approved_seal_seq) =
        committed.map_err(|e| CliError::error("APPROVAL_COMMIT_FAILED", e))?;
    // External effects and live publication/reload happen only after the durable transaction.
    for pid in &revoked_peers {
        let cred = crate::pair::credential_secret_name("peer-auth", pid);
        let _ = secrets.delete(&cred);
    }
    let gate_resigned = approved_seal_seq.is_some();

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

    let peers_reloaded = if cascade {
        let reload = crate::pair::try_reload_live_daemon(&state_dir, explicit_state);
        warnings.extend(reload.warnings);
        reload.reloaded
    } else {
        false
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
                return Err(CliError::error(
                    "BROADCAST_FAILED",
                    format!("Authority revoked locally, but --broadcast failed: {e}"),
                ));
            }
        }
    } else {
        None
    };

    let revoked_kids: Vec<&str> = targets.iter().map(|t| t.kid.as_str()).collect();
    if as_json {
        let mut data = json!({
            "humanId": target.human_id,
            "kid": target.kid,
            "revokedKids": revoked_kids,
            "status": "revoked",
            "minAuthEpoch": effective_min,
            "epochBumped": bump_epoch,
            "cascade": cascade,
            "revokedPeers": revoked_peers,
            "peersReloaded": peers_reloaded,
            "authoritiesDigest": digest,
            "approvedByKid": approved_by_kid,
            "sealSeq": approved_seal_seq,
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
        let envelope = JsonEnvelope::ok(cmd.to_string(), if cascade {
                format!(
                    "Revoked human authority '{}' (minAuthEpoch={effective_min}) and cascaded revocation to {} admitted peer(s)",
                    target.human_id,
                    revoked_peers.len()
                )
            } else {
                format!(
                    "Revoked human authority '{}' kid {} (minAuthEpoch={effective_min})",
                    target.human_id, target.kid
                )
            }, data).warnings(warnings).next(next);
        print_json(&envelope);
    } else {
        println!(
            "OK    Revoked authority '{}' (kid={}, minAuthEpoch={effective_min})",
            target.human_id, target.kid
        );
        if cascade {
            println!(
                "      Cascade:   revoked {} admitted peer(s){}",
                revoked_peers.len(),
                if revoked_peers.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", revoked_peers.join(", "))
                }
            );
            if peers_reloaded {
                println!("      Daemon:    live daemon reloaded — SSE streams dropped immediately");
            }
        }
        if gate_resigned {
            println!("      Gate Seal: Passkey-sealed with updated human_authorities_digest");
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
    Ok(ExitCode::from(EXIT_OK))
}

fn run_auth_certify_node(
    ttl_days: u32,
    kid_arg: Option<String>,
    state_dir_arg: Option<PathBuf>,
    config_arg: Option<PathBuf>,
    as_json: bool,
) -> Result<ExitCode, CliError> {
    let cmd = "auth certify-node";
    if ttl_days == 0 {
        return Err(CliError::usage("INVALID_TTL", "--ttl-days must be >= 1"));
    }

    let state_dir = resolve_state_dir(state_dir_arg.as_deref(), config_arg.as_deref(), None);
    let config_read =
        resolve_config_path_for_read(config_arg.as_deref(), state_dir_arg.as_deref(), None);
    let secrets = open_secret_store(&state_dir, state_dir_arg.is_some());

    let node = open_local_unified_node(&state_dir, &config_read, &secrets)
        .map_err(|e| CliError::error("NODE_OPEN_FAILED", e))?;

    let (admin_rec, admin_kp) =
        match select_local_signing_authority(&node.db(), &secrets, kid_arg.as_deref(), true) {
            Ok(pair) => pair,
            Err(e) => {
                return Err(
                    CliError::error("ADMIN_KEY_UNAVAILABLE", e).with_fix(format!(
                        "Run `hyp auth init --state-dir {}` first.",
                        state_dir.display()
                    )),
                );
            }
        };

    let (signed, hcert1) = match node.issue_node_cert(&admin_kp, &admin_rec.kid, ttl_days) {
        Ok(res) => res,
        Err(e) => {
            return Err(CliError::error(
                "CERTIFY_FAILED",
                format!("Failed to issue NodeCertV1: {e}"),
            ));
        }
    };

    let cert_payload: Value = serde_json::from_str(&signed.payload).unwrap_or(Value::Null);

    if as_json {
        let envelope = JsonEnvelope::ok(
            cmd.to_string(),
            format!(
                "Certified node '{}' for {ttl_days} day(s) under human authority '{}' ({})",
                node.node_id().as_str(),
                admin_rec.human_id,
                admin_rec.kid
            ),
            json!({
                "nodeId": node.node_id().as_str(),
                "humanId": admin_rec.human_id,
                "humanKid": admin_rec.kid,
                "ttlDays": ttl_days,
                "token": hcert1,
                "cert": cert_payload,
            }),
        );
        print_json(&envelope);
    } else {
        println!(
            "OK    Certified node '{}' ({ttl_days}d) via '{}'",
            node.node_id().as_str(),
            admin_rec.human_id
        );
        println!("      Cert: {hcert1}");
    }
    Ok(ExitCode::from(EXIT_OK))
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
) -> Result<ExitCode, CliError> {
    let cmd = "auth sign";
    if ttl_secs == 0 || ttl_secs > MAX_DROP_TTL_SECS {
        return Err(CliError::usage(
            "INVALID_TTL",
            format!("--ttl must be in 1..={MAX_DROP_TTL_SECS} seconds"),
        ));
    }

    if let Some(ref h) = handle_arg {
        if !is_valid_handle(h) {
            return Err(CliError::usage(
                "INVALID_HANDLE",
                format!("Invalid --handle '{h}'"),
            ));
        }
    }

    let secret_spec = match kind {
        CliDropKind::Secret => {
            let Some(ref raw_name) = secret_name_arg else {
                return Err(CliError::usage(
                    "MISSING_SECRET_NAME",
                    "--secret-name <name> is required when --kind secret",
                ));
            };
            let name = raw_name.trim();
            if is_reserved_secret_name(name) {
                return Err(CliError::usage(
                    "RESERVED_SECRET_NAME",
                    format!(
                        "Reserved system secret name '{name}' is permanently blocked for human drops"
                    ),
                ));
            }
            validate_secret_name(name).map_err(|e| {
                CliError::usage(
                    "INVALID_SECRET_NAME",
                    format!("Invalid --secret-name '{name}': {e}"),
                )
            })?;
            Some(SecretDropSpec {
                name: name.to_string(),
                overwrite,
            })
        }
        CliDropKind::Directive => {
            if secret_name_arg.is_some() {
                return Err(CliError::usage(
                    "UNEXPECTED_SECRET_NAME",
                    "--secret-name is only allowed when --kind secret",
                ));
            }
            None
        }
    };

    // P0: `hyp auth sign` signs with the local admin key and MUST require an interactive human
    // controlling terminal (blocking non-TTY agent subprocesses before reading stdin or SecretStore).
    if !io::stderr().is_terminal() {
        return Err((ConfirmError::NotInteractiveTty).into_cli_error(cmd));
    }

    // Read body strictly from stdin (NEVER argv!) into a bounded buffer.
    let mut raw_body = String::new();
    io::stdin()
        .lock()
        .take(MAX_SIGN_BODY_BYTES + 1)
        .read_to_string(&mut raw_body)
        .map_err(|e| {
            CliError::error(
                "STDIN_ERROR",
                format!("Failed to read body from stdin: {e}"),
            )
        })?;
    if raw_body.len() as u64 > MAX_SIGN_BODY_BYTES {
        return Err(CliError::usage(
            "BODY_TOO_LARGE",
            format!("Input exceeds {MAX_SIGN_BODY_BYTES} byte safety cap"),
        ));
    }
    let body = raw_body.trim_end_matches(['\r', '\n']).to_string();
    drop(raw_body);
    if body.is_empty() {
        return Err(CliError::usage(
            "EMPTY_BODY",
            "No body received on stdin (body must be piped via stdin, never CLI argv)",
        ));
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
        return Err(CliError::error(
            "NOT_INITIALIZED",
            format!("No node.sqlite found at {}", db_path.display()),
        )
        .with_fix(format!(
            "Run `hyp auth init --state-dir {}` first.",
            state_dir.display()
        )));
    }
    let db = NodeDb::open(&db_path).map_err(|e| CliError::error("DB_ERROR", e.to_string()))?;
    let secrets = open_secret_store(&state_dir, state_dir_arg.is_some());

    let (signer_rec, signer_kp) =
        match select_local_signing_authority(&db, &secrets, kid_arg.as_deref(), false) {
            Ok(pair) => pair,
            Err(e) => {
                return Err(
                    CliError::error("SIGNER_KEY_UNAVAILABLE", e).with_fix(format!(
                        "Run `hyp auth init --state-dir {}` first.",
                        state_dir.display()
                    )),
                );
            }
        };

    let local_node_id = resolve_effective_node_id(loaded.as_ref(), Some(&db));
    let target_node_id = node_id_arg.unwrap_or_else(|| local_node_id.clone());
    if target_node_id == LOCAL_NODE_ID || !is_valid_node_id(&target_node_id) {
        return Err(CliError::usage(
            "INVALID_NODE_ID",
            format!("Invalid target --node-id '{target_node_id}'"),
        ));
    }

    let recipient_enc_pk: X25519PublicKey = if target_node_id == local_node_id {
        match secrets.load_or_create_node_keys(&local_node_id) {
            Ok(keys) => keys.encryption.public_key(),
            Err(e) => {
                return Err(CliError::error(
                    "NODE_KEY_ERROR",
                    format!("Failed to load local node encryption key: {e}"),
                ));
            }
        }
    } else {
        match lookup_peer_encryption_key(&db, &target_node_id) {
            Ok(pk) => pk,
            Err(e) => {
                return Err(CliError::error("PEER_KEY_NOT_FOUND", e).with_fix(format!(
                        "Ensure peer '{target_node_id}' is paired and has an active X25519 encryption key."
                    )));
            }
        }
    };

    let claim_id = random_b64url(16).map_err(|e| CliError::error("RNG_ERROR", e))?;
    let min_epoch = db.human().min_auth_epoch().unwrap_or(1);
    let auth_epoch = signer_rec.auth_epoch.max(min_epoch);
    let now = now_unix_ms();
    let expires_ms = now.saturating_add((ttl_secs as i64).saturating_mul(1_000));
    let issued_at = format_rfc3339_millis(now);
    let expires_at = format_rfc3339_millis(expires_ms);
    let drop_id = drop_id_arg.unwrap_or_default();

    let confirm_summary = format_auth_sign_confirm_summary(
        kind,
        &signer_rec.human_id,
        &signer_rec.kid,
        auth_epoch,
        &target_node_id,
        handle_arg.as_deref(),
        secret_spec.as_ref(),
        &drop_id,
        ttl_secs,
        &body,
    );
    let confirm_prompt = format!(
        "Sign & seal {} drop for node '{}'? [y/N]: ",
        kind.to_crypto_kind().as_str(),
        sanitize_tty_display(&target_node_id)
    );
    if let Err(err) = require_controlling_tty_confirmation(&confirm_summary, &confirm_prompt) {
        let mut body_wipe = body;
        // SAFETY: overwriting plaintext buffer with zeroes before immediately clearing/dropping.
        unsafe {
            for b in body_wipe.as_bytes_mut() {
                std::ptr::write_volatile(b, 0);
            }
        }
        body_wipe.clear();
        return Err((err).into_cli_error(cmd));
    }

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
            return Err(CliError::error(
                "SEAL_FAILED",
                format!("Failed to seal human drop: {e}"),
            ));
        }
    };

    let token = match encode_hdrop1(&envelope) {
        Ok(t) => t,
        Err(e) => {
            return Err(CliError::error(
                "ENCODE_FAILED",
                format!("Failed to encode hdrop1_ token: {e}"),
            ));
        }
    };

    let next = vec![format!(
        "Pipe token into target node: printf '%s' \"$HDROP1\" | hyp drop ingest --state-dir {}",
        state_dir.display()
    )];

    if as_json {
        let env_out = JsonEnvelope::ok(
            cmd.to_string(),
            format!(
                "Sealed {} drop (claimId={claim_id}) for node '{target_node_id}'",
                kind.to_crypto_kind().as_str()
            ),
            json!({
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
            }),
        )
        .next(next);
        print_json(&env_out);
    } else {
        println!("{token}");
    }
    Ok(ExitCode::from(EXIT_OK))
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

fn resolve_authorities_for_revoke(
    authorities: &[HumanAuthorityRecord],
    query: &str,
    cascade: bool,
) -> Result<Vec<HumanAuthorityRecord>, String> {
    if let Ok(rec) = resolve_authority_by_kid_or_prefix(authorities, query) {
        return Ok(vec![rec.clone()]);
    }
    let lower = query.to_ascii_lowercase();
    let by_human_active: Vec<HumanAuthorityRecord> = authorities
        .iter()
        .filter(|a| a.human_id == lower && a.status == HumanAuthorityStatus::Active)
        .cloned()
        .collect();
    if !by_human_active.is_empty() {
        if cascade || by_human_active.len() == 1 {
            return Ok(by_human_active);
        }
        return Err(format!(
            "human '{lower}' has {} active authority keys; pass a specific kid or --cascade",
            by_human_active.len()
        ));
    }
    let by_human_all: Vec<HumanAuthorityRecord> = authorities
        .iter()
        .filter(|a| a.human_id == lower)
        .cloned()
        .collect();
    if !by_human_all.is_empty() {
        if cascade || by_human_all.len() == 1 {
            return Ok(by_human_all);
        }
        return Ok(vec![by_human_all[0].clone()]);
    }
    Err(format!("human authority '{query}' not found"))
}

fn resolve_delegated_scopes(
    preset: Option<crate::pair::CliScopePreset>,
    grant: &[String],
) -> Result<Vec<String>, String> {
    let mut raw: Vec<String> = Vec::new();
    match (preset, grant.is_empty()) {
        (Some(p), true) => raw.extend(p.to_proto().expand()),
        (Some(p), false) => {
            raw.extend(p.to_proto().expand());
            raw.extend(crate::pair::tokenize_scope_args(grant));
        }
        (None, true) => raw.extend(ScopePreset::Member.expand()),
        (None, false) => raw.extend(crate::pair::tokenize_scope_args(grant)),
    }
    expand_delegated_human_scopes(&raw).map_err(|e| e.to_string())
}

#[allow(clippy::too_many_arguments)]
fn run_auth_invite(
    human_id_raw: String,
    hub_arg: Option<String>,
    endpoint_arg: Option<String>,
    hub_fingerprint_arg: Option<String>,
    node_prefix_arg: Option<String>,
    preset: Option<crate::pair::CliScopePreset>,
    grant: Vec<String>,
    max_devices: u32,
    expires_hours: u64,
    portal_url_raw: String,
    state_dir_arg: Option<PathBuf>,
    config_arg: Option<PathBuf>,
    as_json: bool,
) -> Result<ExitCode, CliError> {
    let cmd = "auth invite";
    let human_id = human_id_raw.trim().to_ascii_lowercase();
    if human_id == LOCAL_NODE_ID || !is_valid_node_id(&human_id) {
        return Err(CliError::usage(
            "INVALID_HUMAN_ID",
            format!("Invalid humanId '{human_id_raw}'"),
        )
        .with_fix(
            "Example: hyp auth invite philip --endpoint https://hub.example.com".to_string(),
        ));
    }
    if max_devices == 0 || max_devices > MAX_DELEGATED_DEVICES_LIMIT {
        return Err(CliError::usage(
            "INVALID_MAX_DEVICES",
            format!("--max-devices must be in 1..={MAX_DELEGATED_DEVICES_LIMIT}"),
        ));
    }
    if expires_hours == 0 || expires_hours > MAX_INVITE_EXPIRES_HOURS {
        return Err(CliError::usage(
            "INVALID_EXPIRES_HOURS",
            format!("--expires-hours must be in 1..={MAX_INVITE_EXPIRES_HOURS}"),
        ));
    }

    let portal_url = portal_url_raw.trim().trim_end_matches('/').to_string();
    validate_endpoint_origin(&portal_url).map_err(|e| {
        CliError::usage(
            "INVALID_PORTAL_URL",
            format!("Invalid --portal-url '{portal_url_raw}': {e}"),
        )
    })?;

    let node_prefix = node_prefix_arg
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("{human_id}@*"));
    validate_node_prefix_pattern(&node_prefix, false).map_err(|e| {
        CliError::usage(
            "INVALID_NODE_PREFIX",
            format!("Invalid --node-prefix '{node_prefix}': {e}"),
        )
        .with_fix(format!("Example: --node-prefix {human_id}@*"))
    })?;

    let scopes = match resolve_delegated_scopes(preset, &grant) {
        Ok(s) => s,
        Err(e) => {
            return Err(CliError::usage("INVALID_SCOPE", format!("Invalid delegated scopes: {e}")).with_fix("Use --preset member|observer|guest|full or concrete v2 scopes (never '*', bridge:post, or forward:via).".to_string()));
        }
    };

    let explicit_state = state_dir_arg.is_some() || config_arg.is_some();
    let state_dir = resolve_state_dir(state_dir_arg.as_deref(), config_arg.as_deref(), None);
    let config_read =
        resolve_config_path_for_read(config_arg.as_deref(), state_dir_arg.as_deref(), None);
    ensure_dir(&state_dir, true).map_err(|e| CliError::error("IO_ERROR", e))?;

    let loaded = if config_read.exists() {
        load_node_or_legacy_config(&config_read).ok()
    } else {
        None
    };
    let db_opt = if state_dir.join("node.sqlite").exists() {
        NodeDb::open(state_dir.join("node.sqlite")).ok()
    } else {
        None
    };
    let local_node_id = resolve_effective_node_id(loaded.as_ref(), db_opt.as_ref());
    let hub_node_id = hub_arg
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| local_node_id.clone());
    if hub_node_id == LOCAL_NODE_ID || !is_valid_node_id(&hub_node_id) {
        return Err(CliError::usage(
            "INVALID_HUB_NODE_ID",
            format!("Invalid --hub '{hub_node_id}'"),
        ));
    }

    let hub_endpoint = match endpoint_arg
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            loaded
                .as_ref()
                .and_then(|c| c.public_url.clone())
                .map(|s| s.trim().trim_end_matches('/').to_string())
        }) {
        Some(ep) => {
            validate_endpoint_origin(&ep).map_err(|e| {
                CliError::usage(
                    "INVALID_ENDPOINT",
                    format!("Invalid --endpoint '{ep}': {e}"),
                )
                .with_fix(
                    "Use https:// (or loopback http://127.0.0.1 for local testing).".to_string(),
                )
            })?;
            ep
        }
        None => {
            return Err(CliError::usage("MISSING_ENDPOINT", "Hub endpoint is required (pass --endpoint https://... or configure listen.publicUrl in node.json)").with_fix(format!(
                    "Example: hyp auth invite {human_id} --hub {hub_node_id} --endpoint https://hub.example.com"
                )));
        }
    };

    let secrets = open_secret_store(&state_dir, explicit_state);
    let hub_fingerprint = match hub_fingerprint_arg
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
    {
        Some(fp) => {
            if fp.len() != 16 || !fp.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(CliError::usage(
                    "INVALID_HUB_FINGERPRINT",
                    "--hub-fingerprint must be exactly 16 hex characters",
                ));
            }
            Some(fp)
        }
        None => {
            if hub_node_id == local_node_id {
                secrets
                    .load_or_create_node_keys(&hub_node_id)
                    .ok()
                    .map(|k| k.signing.public_key().fingerprint())
            } else {
                None
            }
        }
    };

    let admin_kp = match crate::pair::load_or_create_admin_key(&secrets, &hub_node_id) {
        Ok(kp) => kp,
        Err(e) => {
            return Err(CliError::error(
                "ADMIN_KEY_ERROR",
                format!("Failed to load hub Admin-CA key for '{hub_node_id}': {e}"),
            ));
        }
    };

    let now = now_unix_ms();
    let expires_ms = now + (expires_hours as i64) * 3_600_000;
    let invite_id = uuid_v4();
    let issued_at = format_rfc3339_millis(now);
    let expires_at = format_rfc3339_millis(expires_ms);

    let invite = HumanInviteV1 {
        v: 1,
        invite_id: invite_id.clone(),
        hub_node_id: hub_node_id.clone(),
        hub_endpoint: hub_endpoint.clone(),
        hub_fingerprint: hub_fingerprint.clone(),
        human_id: human_id.clone(),
        node_prefix: node_prefix.clone(),
        scopes: scopes.clone(),
        max_devices,
        issued_at: issued_at.clone(),
        expires_at: expires_at.clone(),
    };
    let signed = match sign_human_invite(&invite, &admin_kp) {
        Ok(s) => s,
        Err(e) => {
            return Err(CliError::error(
                "SIGN_FAILED",
                format!("Failed to sign HumanInviteV1: {e}"),
            ));
        }
    };
    let token = match encode_hjoin1(&signed) {
        Ok(t) => t,
        Err(e) => {
            return Err(CliError::error(
                "ENCODE_FAILED",
                format!("Failed to encode hjoin1_ token: {e}"),
            ));
        }
    };
    let join_url = format!("{portal_url}#{token}");
    let admin_kid = admin_kp.kid();
    let admin_fp = admin_kp.fingerprint();
    let admin_jwk = admin_kp.to_jwk();
    let next = vec![
        format!("Share the join URL privately with {human_id} (opens Touch ID / Passkey portal)"),
        "For headless CLI join: save token to a 0600 file and run `hyp join --token-file <path> --local-key`".to_string(),
    ];

    if as_json {
        let envelope = JsonEnvelope::ok(cmd.to_string(), format!(
                "Minted single-use hjoin1_ human invite for '{human_id}' on hub '{hub_node_id}' (prefix={node_prefix}, maxDevices={max_devices})"
            ), json!({
                "token": token,
                "joinUrl": join_url,
                "inviteId": invite_id,
                "humanId": human_id,
                "hubNodeId": hub_node_id,
                "hubEndpoint": hub_endpoint,
                "hubFingerprint": hub_fingerprint,
                "nodePrefix": node_prefix,
                "scopes": scopes,
                "maxDevices": max_devices,
                "issuedAt": issued_at,
                "expiresAt": expires_at,
                "adminKid": admin_kid,
                "adminFingerprint": admin_fp,
                "adminJwk": admin_jwk,
            })).next(next);
        print_json(&envelope);
    } else {
        println!("OK    Minted human enrollment invite for '{human_id}'");
        println!("      Hub:          {hub_node_id} ({hub_endpoint})");
        if let Some(ref fp) = hub_fingerprint {
            println!("      Hub FP:       {fp}");
        }
        println!("      Node Prefix:  {node_prefix} (max {max_devices} devices)");
        println!("      Scopes:       {}", scopes.join(" "));
        println!("      Expires:      {expires_at}");
        println!("      Admin-CA FP:  {admin_fp}");
        println!();
        println!("  Shareable Join Link (single-use, open in browser with Touch ID / Passkey):");
        println!("    {join_url}");
        println!();
        println!(
            "  Headless / CLI usage: save the token to a private 0600 file and run `hyp join --token-file <path> --local-key`."
        );
        print_next_steps(&next);
    }
    Ok(ExitCode::from(EXIT_OK))
}

#[allow(clippy::too_many_arguments)]
fn run_auth_admit(
    human_id_raw: String,
    id_arg: Option<String>,
    from_stdin: bool,
    label: String,
    node_prefix_arg: Option<String>,
    preset: Option<crate::pair::CliScopePreset>,
    grant: Vec<String>,
    max_devices: u32,
    state_dir_arg: Option<PathBuf>,
    config_arg: Option<PathBuf>,
    ceremony: ApprovalCeremonyArgs,
    as_json: bool,
) -> Result<ExitCode, CliError> {
    let cmd = "auth admit";
    let human_id = human_id_raw.trim().to_ascii_lowercase();
    if human_id == LOCAL_NODE_ID || !is_valid_node_id(&human_id) {
        return Err(CliError::usage(
            "INVALID_HUMAN_ID",
            format!("Invalid humanId '{human_id_raw}'"),
        ));
    }
    let trimmed_label = label.trim();
    if trimmed_label.is_empty()
        || trimmed_label.len() > 128
        || trimmed_label.chars().any(char::is_control)
    {
        return Err(CliError::usage(
            "INVALID_LABEL",
            "--label must be 1..=128 printable characters",
        ));
    }
    if max_devices == 0 || max_devices > MAX_DELEGATED_DEVICES_LIMIT {
        return Err(CliError::usage(
            "INVALID_MAX_DEVICES",
            format!("--max-devices must be in 1..={MAX_DELEGATED_DEVICES_LIMIT}"),
        ));
    }
    if id_arg.is_none() && !from_stdin {
        return Err(CliError::usage("MISSING_IDENTITY", "Provide either --id <hpub1_...> or --stdin (with hpub1_ or public OKP Ed25519 JWK JSON)").with_fix(format!("Example: hyp auth admit {human_id} --id hpub1_...")));
    }
    if id_arg.is_some() && from_stdin {
        return Err(CliError::usage(
            "CONFLICTING_FLAGS",
            "--id and --stdin are mutually exclusive",
        ));
    }

    let node_prefix = node_prefix_arg
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("{human_id}@*"));
    validate_node_prefix_pattern(&node_prefix, false).map_err(|e| {
        CliError::usage(
            "INVALID_NODE_PREFIX",
            format!("Invalid --node-prefix '{node_prefix}': {e}"),
        )
    })?;

    let scopes = match resolve_delegated_scopes(preset, &grant) {
        Ok(s) => s,
        Err(e) => {
            return Err(CliError::usage(
                "INVALID_SCOPE",
                format!("Invalid delegated scopes: {e}"),
            ));
        }
    };

    let raw_input = if let Some(id_val) = id_arg {
        id_val
    } else {
        let mut buf = String::new();
        io::stdin()
            .lock()
            .take(MAX_JWK_STDIN_BYTES + 1)
            .read_to_string(&mut buf)
            .map_err(|e| {
                CliError::error(
                    "STDIN_ERROR",
                    format!("Failed to read public identity from stdin: {e}"),
                )
            })?;
        if buf.len() as u64 > MAX_JWK_STDIN_BYTES {
            return Err(CliError::usage(
                "PAYLOAD_TOO_LARGE",
                format!("Stdin payload exceeds {MAX_JWK_STDIN_BYTES} byte safety cap"),
            ));
        }
        buf
    };

    let trimmed = raw_input.trim();
    if trimmed.is_empty() {
        return Err(CliError::usage(
            "EMPTY_INPUT",
            "Expected an hpub1_ identity card or OKP Ed25519 public JWK JSON",
        ));
    }

    let (signing_jwk, enc_jwk_opt, prf_salt_opt) = if trimmed.starts_with("hpub1_") {
        let card = match decode_hpub1(trimmed) {
            Ok(c) => c,
            Err(e) => {
                return Err(CliError::usage(
                    "INVALID_HPUB1",
                    format!("Invalid hpub1_ identity card: {e}"),
                ));
            }
        };
        if card.human_id != human_id {
            return Err(CliError::usage(
                "HUMAN_ID_MISMATCH",
                format!(
                    "hpub1_ card humanId '{}' does not match target '{human_id}'",
                    card.human_id
                ),
            ));
        }
        (card.signing_jwk, card.enc_jwk, None)
    } else {
        let parsed: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                return Err(CliError::usage(
                    "INVALID_JSON",
                    format!("Expected hpub1_ card or valid JSON JWK: {e}"),
                ));
            }
        };
        let Some(obj) = parsed.as_object() else {
            return Err(CliError::usage(
                "INVALID_JWK",
                "Expected a JSON object containing an OKP Ed25519 public JWK",
            ));
        };
        let jwk_val = obj
            .get("signingJwk")
            .or_else(|| obj.get("jwk"))
            .or_else(|| obj.get("publicJwk"))
            .cloned()
            .unwrap_or(parsed.clone());
        let jwk: OkpJwk = match serde_json::from_value(jwk_val) {
            Ok(j) => j,
            Err(e) => {
                return Err(CliError::usage(
                    "INVALID_JWK",
                    format!("Malformed OKP Ed25519 JWK: {e}"),
                ));
            }
        };
        let enc_jwk = match obj.get("encJwk") {
            None | Some(Value::Null) => None,
            Some(v) => match serde_json::from_value::<OkpJwk>(v.clone()) {
                Ok(ej) => Some(ej),
                Err(e) => {
                    return Err(CliError::usage(
                        "INVALID_ENC_JWK",
                        format!("Malformed OKP X25519 encJwk: {e}"),
                    ));
                }
            },
        };
        let prf_salt = obj
            .get("prfSalt")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ToOwned::to_owned);
        (jwk, enc_jwk, prf_salt)
    };

    let ed_pk = match signing_jwk.to_ed25519() {
        Ok(pk) => pk,
        Err(e) => {
            return Err(CliError::usage(
                "INVALID_JWK",
                format!("Invalid Ed25519 public JWK: {e}"),
            ));
        }
    };
    let enc_jwk_json = match enc_jwk_opt {
        Some(ref ej) => {
            ej.to_x25519().map_err(|e| {
                CliError::usage("INVALID_ENC_JWK", format!("Invalid X25519 encJwk: {e}"))
            })?;
            match to_canonical_json(ej) {
                Ok(s) => Some(s),
                Err(e) => {
                    return Err(CliError::error("JSON_ERROR", e.to_string()));
                }
            }
        }
        None => None,
    };
    let kid = ed_pk.kid();
    let fingerprint = ed_pk.fingerprint();
    let jwk_json = to_canonical_json(&signing_jwk)
        .map_err(|e| CliError::error("JSON_ERROR", e.to_string()))?;

    let explicit_state = state_dir_arg.is_some() || config_arg.is_some();
    let state_dir = resolve_state_dir(state_dir_arg.as_deref(), config_arg.as_deref(), None);
    let config_write =
        resolve_config_path_for_write(config_arg.as_deref(), state_dir_arg.as_deref(), None);
    ensure_dir(&state_dir, true).map_err(|e| CliError::error("IO_ERROR", e))?;

    let db = NodeDb::open(state_dir.join("node.sqlite"))
        .map_err(|e| CliError::error("DB_ERROR", e.to_string()))?;
    let secrets = open_secret_store(&state_dir, explicit_state);
    let integrity = inspect_policy_integrity(&config_write, &state_dir, &secrets);
    if let Some(reason) = integrity.tampered_reason {
        return Err(CliError::error("GATE_POLICY_TAMPERED", reason));
    }
    let min_epoch = db
        .human()
        .min_auth_epoch()
        .map_err(|e| CliError::error("DB_ERROR", e.to_string()))?;
    let input = HumanAuthorityInput {
        human_id: human_id.clone(),
        kid: kid.clone(),
        label: trimmed_label.to_string(),
        role: HumanAuthorityRole::Signer,
        jwk_json,
        enc_jwk_json,
        prf_salt: prf_salt_opt,
        auth_epoch: min_epoch,
    };
    let prepared = db
        .human()
        .projected_authorities_digest_after_upsert(&input)
        .map_err(|e| e.to_string())
        .and_then(|digest| ApprovedPolicyUpdate::prepare(&config_write, &db, &digest));
    let reseal = prepared.map_err(|e| CliError::error("GATE_POLICY_SYNC_FAILED", e))?;
    let loaded = load_node_or_legacy_config(&config_write).ok();
    let node_id = resolve_effective_node_id(loaded.as_ref(), Some(&db));
    let mut action =
        base_approval_action(HumanApprovalActionKind::AuthAdmit, node_id, reseal.seal_seq);
    action.target_human_id = Some(human_id.clone());
    action.target_kid = Some(kid.clone());
    action.target_role = Some("signer".to_string());
    action.parameters = Some(json!({"authority": input, "delegation": {
        "humanId": human_id, "nodePrefix": node_prefix, "scopes": scopes,
        "maxDevices": max_devices, "delegationEnabled": true,
    }}));
    let verified = approve_authority_change(
        &state_dir,
        &config_write,
        &db,
        &secrets,
        action,
        Some(&reseal),
        &[format!("Admit {human_id} with device prefix {node_prefix}")],
        &ceremony,
    )?;
    let now = now_ms();
    let committed =
        execute_approved_operation(&config_write, &config_write, &db, &verified, || {
            let authority = db
                .human()
                .upsert_authority(&input, now)
                .map_err(|e| e.to_string())?;
            let policy = db
                .human()
                .upsert_delegation_policy(
                    &HumanDelegationPolicyInput {
                        human_id: human_id.clone(),
                        node_prefix: node_prefix.clone(),
                        scopes: scopes.clone(),
                        max_devices,
                        delegation_enabled: true,
                    },
                    now,
                )
                .map_err(|e| e.to_string())?;
            reseal.apply(&db, &config_write, &verified)?;
            Ok((authority, policy))
        });
    let (auth_rec, policy) = committed.map_err(|e| CliError::error("APPROVAL_COMMIT_FAILED", e))?;
    let digest = db.human().authorities_digest().ok();
    drop(db);

    let mut warnings: Vec<String> = Vec::new();
    let mut next = vec![format!(
        "Device certified by '{human_id}' can now run `hyp pair join <hub-url>`"
    )];

    let (gate_reloaded, gate_reload_error) = reload_live_gate_after_resign(
        state_dir_arg.is_some(),
        config_arg.is_some(),
        &state_dir,
        &mut warnings,
        &mut next,
    );

    if as_json {
        let data = json!({
            "humanId": auth_rec.human_id,
            "kid": auth_rec.kid,
            "fingerprint": fingerprint,
            "role": auth_rec.role.as_str(),
            "label": auth_rec.label,
            "authEpoch": auth_rec.auth_epoch,
            "nodePrefix": policy.node_prefix,
            "scopes": policy.scopes,
            "maxDevices": policy.max_devices,
            "delegationEnabled": policy.delegation_enabled,
            "authoritiesDigest": digest,
            "gatePolicyResigned": true,
            "gateReloaded": gate_reloaded,
            "gateReloadError": gate_reload_error,
        });
        let envelope = JsonEnvelope::ok(
            cmd.to_string(),
            format!(
                "Admitted delegated human authority '{}' (prefix={}, maxDevices={})",
                auth_rec.human_id, policy.node_prefix, policy.max_devices
            ),
            data,
        )
        .warnings(warnings)
        .next(next);
        print_json(&envelope);
    } else {
        println!(
            "OK    Admitted human authority '{}' (kid={}, fp={fingerprint})",
            auth_rec.human_id, auth_rec.kid
        );
        println!(
            "      Delegation: enabled (prefix={}, maxDevices={})",
            policy.node_prefix, policy.max_devices
        );
        println!("      Scopes:     {}", policy.scopes.join(" "));
        print_warnings(&warnings);
        print_next_steps(&next);
    }
    Ok(ExitCode::from(EXIT_OK))
}

fn run_auth_whoami(
    human_id_filter: Option<String>,
    state_dir_arg: Option<PathBuf>,
    config_arg: Option<PathBuf>,
    as_json: bool,
) -> Result<ExitCode, CliError> {
    let cmd = "auth whoami";
    let state_dir = resolve_state_dir(state_dir_arg.as_deref(), config_arg.as_deref(), None);
    let db_path = state_dir.join("node.sqlite");
    if !db_path.exists() {
        return Err(CliError::error(
            "NO_HUMAN_AUTHORITY",
            "No human authority enrolled on this node yet",
        )
        .with_fix("Run `hyp join` or `hyp auth init` to enroll a human authority.".to_string()));
    }
    let db = NodeDb::open(&db_path).map_err(|e| CliError::error("DB_ERROR", e.to_string()))?;
    let active = db
        .human()
        .list_active_authorities()
        .map_err(|e| CliError::error("DB_ERROR", e.to_string()))?;
    let filter_norm = human_id_filter
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty());

    let selected = if let Some(ref hid) = filter_norm {
        active
            .iter()
            .filter(|a| a.human_id == *hid)
            .max_by_key(|a| (a.enc_jwk_json.is_some(), a.prf_salt.is_some(), a.created_at))
    } else {
        active
            .iter()
            .max_by_key(|a| (a.enc_jwk_json.is_some(), a.prf_salt.is_some(), a.created_at))
    };

    let Some(rec) = selected else {
        return Err(CliError::error(
            "NO_HUMAN_AUTHORITY",
            match filter_norm {
                Some(hid) => format!("No active human authority enrolled for '{hid}'"),
                None => "No active human authority enrolled on this node".to_string(),
            },
        )
        .with_fix("Run `hyp join` or `hyp auth init` to enroll a human authority.".to_string()));
    };

    let signing_jwk: OkpJwk = serde_json::from_str(&rec.jwk_json)
        .map_err(|e| CliError::error("CORRUPT_JWK", e.to_string()))?;
    let ed_pk = signing_jwk
        .to_ed25519()
        .map_err(|e| CliError::error("CORRUPT_JWK", e.to_string()))?;
    let enc_jwk: Option<OkpJwk> = rec
        .enc_jwk_json
        .as_deref()
        .and_then(|raw| serde_json::from_str::<OkpJwk>(raw).ok());
    let enc_kid = enc_jwk.as_ref().and_then(|j| j.thumbprint().ok());
    let fingerprint = ed_pk.fingerprint();

    let card = HumanPubCardV1 {
        v: 1,
        human_id: rec.human_id.clone(),
        signing_jwk: signing_jwk.clone(),
        enc_jwk: enc_jwk.clone(),
    };
    let hpub1 = match encode_hpub1(&card) {
        Ok(s) => s,
        Err(e) => {
            return Err(CliError::error("ENCODE_FAILED", e.to_string()));
        }
    };

    if as_json {
        let envelope = JsonEnvelope::ok(
            cmd.to_string(),
            format!("Human authority '{}' (fp={fingerprint})", rec.human_id),
            json!({
                "humanId": rec.human_id,
                "kid": rec.kid,
                "fingerprint": fingerprint,
                "role": rec.role.as_str(),
                "label": rec.label,
                "authEpoch": rec.auth_epoch,
                "encKid": enc_kid,
                "hpub1": hpub1,
                "signingJwk": signing_jwk,
                "encJwk": enc_jwk,
            }),
        )
        .next(vec![format!(
            "Hub admin can admit this identity directly: hyp auth admit {} --id {hpub1}",
            rec.human_id
        )]);
        print_json(&envelope);
    } else {
        println!("OK    Human Authority: {} ({})", rec.human_id, rec.label);
        println!("      Fingerprint: {fingerprint}");
        println!("      Key ID:      {}", rec.kid);
        if let Some(ref ek) = enc_kid {
            println!("      Enc Key ID:  {ek}");
        }
        println!("      Identity:    {hpub1}");
    }
    Ok(ExitCode::from(EXIT_OK))
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

pub(crate) fn extract_portal_origin(portal_url: &str) -> Result<String, String> {
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

pub(crate) fn should_skip_browser_open(no_open: bool, store: &SecretStore) -> bool {
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

pub(crate) fn try_open_browser(url: &str) {
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

pub(crate) fn apply_enroll_cors(
    origin: Option<&str>,
    allowed_origin: &str,
    resp: &mut Response<Full<Bytes>>,
) {
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

pub(crate) fn json_enroll_response(
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

    // P0 `#5`: Fail closed on missing OR mismatched Origin headers!
    // Require exact match with the configured Drop Portal origin so local scripts cannot POST
    // a spoofed JWK without an Origin header.
    if origin.as_deref() != Some(allowed) {
        return json_enroll_response(
            StatusCode::FORBIDDEN,
            None,
            allowed,
            json!({ "ok": false, "error": "origin_not_allowed" }),
        );
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
    if let Err(error) = consume_bounded_body(req.into_body(), MAX_ENROLL_CALLBACK_BYTES, |chunk| {
        body_bytes.extend_from_slice(chunk)
    })
    .await
    {
        let (status, message) = match error {
            BoundedBodyError::Read(_) => (StatusCode::BAD_REQUEST, "body_read_error"),
            BoundedBodyError::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
        };
        return json_enroll_response(
            status,
            origin.as_deref(),
            allowed,
            json!({ "ok": false, "error": message }),
        );
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
    let csrf_ok =
        submitted_token.is_some_and(|tok| ct_eq(tok.as_bytes(), state.csrf_token.as_bytes()));
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

fn require_revocation_survivor(
    db: &NodeDb,
    min_epoch: u64,
    secrets: &SecretStore,
) -> Result<(), String> {
    let survivor = db
        .human()
        .list_active_authorities()
        .map_err(|e| e.to_string())?
        .iter()
        .any(|record| hyp_node::gates::is_passkey_backed_admin(record, min_epoch, Some(secrets)));
    if survivor {
        Ok(())
    } else {
        Err("Revocation would leave no active Passkey Admin at commit".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gate_cmd::confirm_interactive_with;

    #[test]
    fn revocation_rechecks_survivor_after_status_changes_excluded_from_digest() {
        let tmp = tempfile::TempDir::new().unwrap();
        let db = NodeDb::open(tmp.path().join("node.sqlite")).unwrap();
        let secrets = SecretStore::new(tmp.path(), hyp_crypto::keystore::SecretBackend::File);
        for human in ["target", "survivor"] {
            let key = Ed25519KeyPair::generate().unwrap();
            db.human()
                .upsert_authority(
                    &HumanAuthorityInput {
                        human_id: human.into(),
                        kid: key.kid(),
                        label: human.into(),
                        role: HumanAuthorityRole::Admin,
                        jwk_json: serde_json::to_string(&key.to_jwk()).unwrap(),
                        enc_jwk_json: None,
                        prf_salt: Some("passkey-fixture".into()),
                        auth_epoch: 1,
                    },
                    now_ms(),
                )
                .unwrap();
        }
        let records = db.human().list_active_authorities().unwrap();
        let target = records.iter().find(|a| a.human_id == "target").unwrap();
        let survivor = records.iter().find(|a| a.human_id == "survivor").unwrap();
        let projected_digest = db.human().authorities_digest().unwrap();
        // The projected survivor disappears before the ceremony's snapshot. Status is
        // deliberately excluded from the signed identity digest, so digest checks cannot help.
        db.human()
            .revoke_authority_monotonic("survivor", &survivor.kid, 1, "{}", now_ms())
            .unwrap();
        assert_eq!(db.human().authorities_digest().unwrap(), projected_digest);
        let result = db.with_write_transaction(|| {
            db.human()
                .revoke_authority_monotonic("target", &target.kid, 1, "{}", now_ms())?;
            require_revocation_survivor(&db, 1, &secrets)
                .map_err(hyp_store::StoreError::InvalidState)
        });
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("no active Passkey Admin")
        );
        assert!(
            db.human()
                .get_active_authority_by_kid(&target.kid)
                .unwrap()
                .is_some()
        );
    }

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
        assert!(add_summary.contains("updated human_authorities_digest"));

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
        let rev_summary =
            format_auth_revoke_confirm_summary(&target, true, 1, 2, true, "lost device", true)
                .join("\n");
        assert!(rev_summary.contains("Human ID:   bob"));
        assert!(rev_summary.contains("Key ID:     kid_1234567890abcdef"));
        assert!(rev_summary.contains("Bump Epoch: yes (1 -> 2)"));
        assert!(rev_summary.contains("Broadcast:  yes (topic: human.revocations)"));
        assert!(rev_summary.contains("updated human_authorities_digest"));

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
        assert!(rendered.contains("updated human_authorities_digest"));
    }
}
