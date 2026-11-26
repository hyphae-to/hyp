//! Passkey approval ceremony for gate lock/unlock and authority changes (`#10` — G1, H1, H2).
//!
//! A guarded command builds the [`HumanApprovalActionV1`] it wants to apply, prints an approval
//! URL, and waits for a Passkey Admin to sign that exact action.
//!
//! Security invariants:
//! - Only an active **Passkey-backed `Admin`** (`prf_salt` present AND no shell-accessible PKCS#8
//!   secret in `SecretStore`) can approve.
//! - The signed action must equal the requested one field for field (`action`, `nodeId`, `nonce`,
//!   `exp`, `sealSeq`, `locked`, `policySha256`, `authoritiesDigest`, targets). The approval page
//!   shows those signed fields, never unsigned text.
//! - `claimId` and `nonce` are both consumed in `human_claim_nonces`, so an approval works once.
//!
//! The signed approval comes back over one of three transports: a Blind Drop Relay slot, a one-shot
//! loopback listener, or a file (`--no-wait` then `--approval-file`).

use crate::auth_cmd::{
    apply_enroll_cors as apply_cors, extract_portal_origin, json_enroll_response as json_response,
    random_b64url, should_skip_browser_open, try_open_browser,
};
use crate::config_file::{
    ensure_dir, load_node_or_legacy_config, read_json_object_or_empty, resolve_effective_node_id,
};
use crate::drop_cmd::{
    collect_bounded_body, create_relay_drop_slot, decode_drop_envelope, validate_relay_url,
    wait_for_relay_drop,
};
use crate::gate_cmd::sanitize_tty_display;
use crate::ui::{
    EXIT_ERROR, EXIT_OK, EXIT_USAGE, JsonEnvelope, emit_error, print_json, print_next_steps,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Args;
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::Full;
use hyp_crypto::human::{
    HumanApprovalActionKind, HumanApprovalActionV1, HumanDropEnvelopeV1, HumanDropKind,
    SignedNodeCertV1, encode_hcert1, open_human_drop_with_signed, validate_approval_action,
};
use hyp_crypto::jcs::to_canonical_json;
use hyp_crypto::keys::{NodeIdentityKeys, OkpJwk};
use hyp_crypto::keystore::SecretStore;
use hyp_crypto::rfc3339::{format_rfc3339_millis, now_unix_ms, parse_rfc3339_millis};
use hyp_node::engine::http_util::percent_encode;
use hyp_node::engine::{
    CreateDropRequest, DROP_CAP_HEADER, DropCapRole, DropRelay, DropRelayConfig,
    DropSubscriberAuth, resolve_drop_portal_url,
};
use hyp_node::gates::policy::{SecurityGateConfig, is_passkey_backed_admin, verify_gate_lock};
use hyp_store::{GateLockSealRecord, HumanAuthorityRecord, HumanClaimKind, NodeDb, now_ms};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use serde_json::{Map, Value, json};
use std::convert::Infallible;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

pub const DEFAULT_APPROVAL_TTL_SECS: u64 = 600;
const MAX_APPROVAL_TTL_SECS: u64 = 900;
const MAX_APPROVAL_BYTES: usize = 64 * 1024;

/// Shared CLI ceremony flags flattened onto Passkey-guarded `hyp gate` and `hyp auth` commands.
#[derive(Args, Debug, Clone)]
pub struct ApprovalCeremonyArgs {
    /// Explicit Blind Drop Relay base URL (overrides node.json dropRelayUrl)
    #[arg(long)]
    pub relay: Option<String>,
    /// Use a one-shot ephemeral loopback relay (127.0.0.1:0) instead of a remote Drop Relay
    #[arg(long)]
    pub local: bool,
    /// Approval link validity window in seconds (1..=900, default: 600)
    #[arg(long, default_value_t = DEFAULT_APPROVAL_TTL_SECS)]
    pub ttl: u64,
    /// Do not automatically open a browser tab for the Passkey approval URL
    #[arg(long)]
    pub no_open: bool,
    /// Print the Passkey approval URL and exit without waiting or mutating state
    #[arg(long)]
    pub no_wait: bool,
    /// Verify a Passkey-signed hdrop1_ token (or HumanDropEnvelopeV1 JSON) from a file instead of waiting
    #[arg(long)]
    pub approval_file: Option<PathBuf>,
}

impl Default for ApprovalCeremonyArgs {
    fn default() -> Self {
        Self {
            relay: None,
            local: false,
            ttl: DEFAULT_APPROVAL_TTL_SECS,
            no_open: false,
            no_wait: false,
            approval_file: None,
        }
    }
}

/// Lock state of the gate as the CLI sees it, from [`verify_gate_lock`].
#[derive(Debug, Clone)]
pub(crate) struct ExternalLockState {
    /// True if the gate is locked or its lock failed verification (fail closed).
    pub locked: bool,
    /// Why the existing seal or policy failed verification, if it did.
    pub tampered_reason: Option<String>,
}

/// A Passkey Admin approval that passed signature, binding and replay checks.
#[derive(Debug, Clone)]
pub(crate) struct VerifiedApproval {
    pub action: HumanApprovalActionV1,
    /// Canonical `SignedHumanClaimV1` JSON, stored as the `gate_lock_seal`.
    pub signed_claim_json: String,
    pub human_id: String,
    pub kid: String,
}

/// Returned when `--no-wait` is set so callers/agents can forward the URL out-of-band.
#[derive(Debug, Clone)]
pub(crate) struct PendingApproval {
    pub url: String,
    pub mode: &'static str,
    pub drop_id: Option<String>,
    pub relay: Option<String>,
    pub expires_at: String,
    pub authority_human_id: String,
    pub authority_kid: String,
    pub action: HumanApprovalActionV1,
    pub summary: Vec<String>,
}

#[derive(Debug, Clone)]
pub(crate) enum CeremonyOutcome {
    Approved(Box<VerifiedApproval>),
    Pending(Box<PendingApproval>),
}

#[derive(Debug, Clone)]
pub(crate) struct CeremonyError {
    pub exit_code: u8,
    pub code: &'static str,
    pub message: String,
    pub next: Option<String>,
}

impl CeremonyError {
    fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            exit_code: EXIT_ERROR,
            code,
            message: message.into(),
            next: None,
        }
    }

    fn usage(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            exit_code: EXIT_USAGE,
            ..Self::new(code, message)
        }
    }

    fn with_next(mut self, next: impl Into<String>) -> Self {
        self.next = Some(next.into());
        self
    }

    pub fn emit(self, cmd: &str, as_json: bool) -> ExitCode {
        emit_error(
            cmd,
            as_json,
            self.exit_code,
            self.code,
            self.message,
            self.next,
        )
    }
}

/// Lists all active Passkey-backed `Admin` authorities (strictly excluding shell-accessible PKCS#8 keys).
fn find_active_passkey_admins(
    db: &NodeDb,
    secrets: &SecretStore,
) -> Result<Vec<HumanAuthorityRecord>, String> {
    let min_epoch = db
        .human()
        .min_auth_epoch()
        .map_err(|e| format!("failed to read min_auth_epoch: {e}"))?;
    let active = db
        .human()
        .list_active_authorities()
        .map_err(|e| format!("failed to list active human authorities: {e}"))?;
    Ok(active
        .into_iter()
        .filter(|rec| is_passkey_backed_admin(rec, min_epoch, Some(secrets)))
        .collect())
}

/// Returns `true` if `state_dir/node.sqlite` has at least one active Passkey-backed `Admin`.
pub(crate) fn has_active_passkey_admin(state_dir: &Path, secrets: &SecretStore) -> bool {
    let db_path = state_dir.join("node.sqlite");
    db_path.exists()
        && NodeDb::open(&db_path)
            .ok()
            .and_then(|db| find_active_passkey_admins(&db, secrets).ok())
            .is_some_and(|admins| !admins.is_empty())
}

/// Picks the newest active Passkey Admin to address the approval link to. Fails closed with
/// `next: "hyp auth init --web"` if none is enrolled. `exclude_kid` (the key being revoked) is
/// avoided whenever another Passkey Admin exists.
pub(crate) fn select_passkey_admin(
    db: &NodeDb,
    secrets: &SecretStore,
    state_dir: &Path,
    exclude_kid: Option<&str>,
) -> Result<HumanAuthorityRecord, CeremonyError> {
    let admins =
        find_active_passkey_admins(db, secrets).map_err(|e| CeremonyError::new("DB_ERROR", e))?;
    admins
        .iter()
        .filter(|rec| Some(rec.kid.as_str()) != exclude_kid)
        .max_by_key(|rec| rec.created_at)
        .or_else(|| admins.iter().max_by_key(|rec| rec.created_at))
        .cloned()
        .ok_or_else(|| {
            CeremonyError::new(
                "PASSKEY_AUTHORITY_REQUIRED",
                "No enrolled Passkey Admin authority found. Locking/unlocking the Security Gate or mutating authorities requires a browser Passkey Admin (local CLI PKCS#8 keys in SecretStore cannot satisfy the human boundary).",
            )
            .with_next(format!(
                "hyp auth init --web --state-dir {}",
                state_dir.display()
            ))
        })
}

/// Reports whether the gate is locked, failing closed (`locked` + `tampered_reason`) when the
/// config, the database, or the lock itself cannot be read or verified.
pub(crate) fn inspect_external_lock_state(
    config_path: &Path,
    state_dir: &Path,
    secrets: &SecretStore,
) -> ExternalLockState {
    let verify = || -> Result<bool, String> {
        let gate_cfg = match read_json_object_or_empty(config_path)
            .map_err(|e| format!("failed to read node.json: {e}"))?
            .get("gate")
        {
            Some(val) => serde_json::from_value::<SecurityGateConfig>(val.clone())
                .map_err(|e| format!("malformed gate config in node.json: {e}"))?,
            None => SecurityGateConfig::default(),
        };
        let db_path = state_dir.join("node.sqlite");
        let db = if db_path.exists() {
            NodeDb::open(&db_path)
        } else {
            NodeDb::open_in_memory()
        }
        .map_err(|e| format!("failed to open node.sqlite: {e}"))?;
        verify_gate_lock(&gate_cfg, &db, Some(secrets))
            .map(|state| state.locked)
            .map_err(|e| e.to_string())
    };
    match verify() {
        Ok(locked) => ExternalLockState {
            locked,
            tampered_reason: None,
        },
        Err(reason) => ExternalLockState {
            locked: true,
            tampered_reason: Some(reason),
        },
    }
}

/// True if a Passkey `gate_lock_seal` exists, so the gate pipeline must load even when
/// `node.json` has no `gate` block.
pub(crate) fn has_gate_lock_seal(state_dir: &Path) -> bool {
    let db_path = state_dir.join("node.sqlite");
    db_path.exists()
        && NodeDb::open(&db_path)
            .ok()
            .and_then(|db| db.human().get_gate_lock_seal().ok().flatten())
            .is_some()
}

/// Returns the strictly next monotonic `seal_seq` for a new Passkey-signed `gate_lock_seal`.
pub(crate) fn next_seal_seq(db: &NodeDb) -> Result<u64, String> {
    let cur = db
        .human()
        .get_gate_lock_seal()
        .map_err(|e| format!("failed to read gate_lock_seal: {e}"))?
        .map_or(0, |s| s.seal_seq);
    Ok(cur.saturating_add(1))
}

/// Persists a verified Passkey approval as the `gate_lock_seal` row.
pub(crate) fn persist_passkey_gate_seal(
    db: &NodeDb,
    verified: &VerifiedApproval,
) -> Result<GateLockSealRecord, String> {
    db.human()
        .put_gate_lock_seal(
            verified.action.seal_seq,
            &verified.signed_claim_json,
            now_ms(),
        )
        .map_err(|e| format!("failed to persist Passkey gate_lock_seal: {e}"))
}

/// Builds a `HumanApprovalActionV1` for `action`; the ceremony fills in `nonce` and `exp`.
pub(crate) fn base_approval_action(
    action: HumanApprovalActionKind,
    node_id: String,
    seal_seq: u64,
    locked: bool,
) -> HumanApprovalActionV1 {
    HumanApprovalActionV1 {
        v: 1,
        action,
        node_id,
        nonce: String::new(),
        exp: String::new(),
        seal_seq,
        locked,
        policy_sha256: None,
        authorities_digest: None,
        target_human_id: None,
        target_kid: None,
        target_role: None,
        bump_epoch: None,
        cascade: None,
    }
}

/// Formats and prints `--no-wait` output consistently for both `--json` and human terminals.
pub(crate) fn emit_pending_approval(
    cmd: &str,
    as_json: bool,
    pending: &PendingApproval,
) -> ExitCode {
    let action = &pending.action;
    let action_name = action.action.as_str();
    let next = vec![if pending.mode == "relay" {
        "Forward the approval URL to the Passkey Admin device (or re-run without --no-wait to wait automatically).".to_string()
    } else {
        "Open the approval URL on the Passkey Admin device, copy the signed hdrop1_ token to a file, then re-run with --approval-file <path>.".to_string()
    }];

    if as_json {
        print_json(&JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(format!(
                "Generated Passkey approval URL for '{action_name}' on node '{}' (waiting skipped via --no-wait)",
                action.node_id
            )),
            data: Some(json!({
                "pending": true,
                "mode": pending.mode,
                "url": pending.url,
                "action": action_name,
                "nodeId": action.node_id,
                "nonce": action.nonce,
                "sealSeq": action.seal_seq,
                "locked": action.locked,
                "policySha256": action.policy_sha256,
                "authoritiesDigest": action.authorities_digest,
                "dropId": pending.drop_id,
                "relay": pending.relay,
                "authorityHumanId": pending.authority_human_id,
                "authorityKid": pending.authority_kid,
                "expiresAt": pending.expires_at,
                "diff": pending.summary,
            })),
            warnings: Vec::new(),
            next,
            error: None,
        });
    } else {
        println!(
            "OK    Passkey approval required for '{action_name}' on '{}'",
            action.node_id
        );
        println!("      URL:       {}", pending.url);
        println!(
            "      Authority: {} (kid={})",
            pending.authority_human_id, pending.authority_kid
        );
        println!("      Expires:   {}", pending.expires_at);
        println!("      Mode:      {}", pending.mode);
        if !pending.summary.is_empty() {
            println!("      Changes:");
            for line in &pending.summary {
                println!("        {}", sanitize_tty_display(line));
            }
        }
        print_next_steps(&next);
    }
    ExitCode::from(EXIT_OK)
}

/// Everything needed to print an approval URL for one ceremony.
struct ApprovalLink<'a> {
    drop_portal_url: String,
    identity: &'a NodeIdentityKeys,
    node_cert_hcert1: Option<String>,
    admin: &'a HumanAuthorityRecord,
    hint_auth_epoch: u64,
    action: &'a HumanApprovalActionV1,
}

/// Where the approval page posts the signed approval (`None` = offline copy/paste).
struct ApprovalSlot<'a> {
    drop_id: &'a str,
    relay_url: &'a str,
    post_cap: &'a str,
}

impl ApprovalLink<'_> {
    fn url(
        &self,
        expires_at: &str,
        slot: Option<&ApprovalSlot<'_>>,
    ) -> Result<String, CeremonyError> {
        let json_err = |e: hyp_crypto::CryptoError| CeremonyError::new("JSON_ERROR", e.to_string());
        let mut frag = Map::new();
        frag.insert("v".into(), json!(1));
        frag.insert("kind".into(), json!(HumanDropKind::Approval.as_str()));
        frag.insert("nodeId".into(), json!(self.action.node_id));
        frag.insert(
            "encJwk".into(),
            json!({ "kty": "OKP", "crv": "X25519", "x": self.identity.encryption_jwk().x }),
        );
        frag.insert("expiresAt".into(), json!(expires_at));
        if let Some(ref cert) = self.node_cert_hcert1 {
            frag.insert("nodeCert".into(), json!(cert));
        }
        if let Some(slot) = slot {
            frag.insert("dropId".into(), json!(slot.drop_id));
            frag.insert("relay".into(), json!(slot.relay_url));
            frag.insert("postCap".into(), json!(slot.post_cap));
        }
        frag.insert("humanId".into(), json!(self.admin.human_id));
        if let Some(ref salt) = self.admin.prf_salt {
            frag.insert("prfSalt".into(), json!(salt));
        }
        frag.insert("authEpoch".into(), json!(self.hint_auth_epoch));
        frag.insert(
            "approval".into(),
            serde_json::to_value(self.action)
                .map_err(|e| CeremonyError::new("JSON_ERROR", e.to_string()))?,
        );

        let canon = to_canonical_json(&Value::Object(frag)).map_err(json_err)?;
        Ok(format!(
            "{}#drop={}",
            self.drop_portal_url,
            URL_SAFE_NO_PAD.encode(canon.as_bytes())
        ))
    }

    /// Prints what is being approved and the URL to stderr, then opens a browser unless told not to.
    fn announce(&self, url: &str, expires_at: &str, summary: &[String], open_browser: bool) {
        let short_kid: String = self.admin.kid.chars().take(12).collect();
        eprintln!(
            "Hyphae Passkey Approval Required ({})",
            self.action.action.as_str()
        );
        eprintln!(
            "  Node:      {}",
            sanitize_tty_display(&self.action.node_id)
        );
        eprintln!(
            "  Authority: {} (Passkey admin, kid={short_kid}...)",
            sanitize_tty_display(&self.admin.human_id)
        );
        eprintln!("  Expires:   {expires_at}");
        if let Some(ref sha) = self.action.policy_sha256 {
            eprintln!("  Policy:    sha256 {sha}");
        }
        if !summary.is_empty() {
            eprintln!("  Summary:");
            for line in summary {
                eprintln!("    {}", sanitize_tty_display(line));
            }
        }
        eprintln!("Hyphae Passkey approval URL: {url}");
        eprintln!(
            "Waiting for Passkey signature... (open in browser or forward this URL to the admin's device)"
        );
        let _ = io::stderr().flush();
        if open_browser {
            try_open_browser(url);
        }
    }
}

/// Runs a complete Passkey approval ceremony for `action` and returns the verified approval, or
/// the pending URL when `--no-wait` is set. `summary` is shown on the local terminal only; it is
/// not part of what the Passkey signs.
pub(crate) fn run_passkey_approval_ceremony(
    state_dir: &Path,
    config_read: &Path,
    db: &NodeDb,
    secrets: &SecretStore,
    mut action: HumanApprovalActionV1,
    summary: &[String],
    ceremony: &ApprovalCeremonyArgs,
) -> Result<CeremonyOutcome, CeremonyError> {
    if ceremony.ttl == 0 || ceremony.ttl > MAX_APPROVAL_TTL_SECS {
        return Err(CeremonyError::usage(
            "INVALID_TTL",
            format!("--ttl must be in 1..={MAX_APPROVAL_TTL_SECS} seconds"),
        ));
    }
    ensure_dir(state_dir, true).map_err(|e| CeremonyError::new("IO_ERROR", e))?;

    let loaded = if config_read.exists() {
        load_node_or_legacy_config(config_read).ok()
    } else {
        None
    };
    if action.node_id.trim().is_empty() {
        action.node_id = resolve_effective_node_id(loaded.as_ref(), Some(db));
    }
    let node_id = action.node_id.clone();

    let exclude_kid = (action.action == HumanApprovalActionKind::AuthRevoke)
        .then_some(action.target_kid.as_deref())
        .flatten();
    let admin = select_passkey_admin(db, secrets, state_dir, exclude_kid)?;
    let identity = secrets.load_or_create_node_keys(&node_id).map_err(|e| {
        CeremonyError::new(
            "NODE_KEY_ERROR",
            format!("Failed to load node identity keys: {e}"),
        )
    })?;

    // `--approval-file <path>`: verify an approval collected earlier with `--no-wait`.
    if let Some(ref approval_path) = ceremony.approval_file {
        let envelope = read_approval_envelope_file(approval_path)?;
        let verified =
            verify_approval_envelope(&envelope, &identity, db, secrets, &action, None, false)?;
        return Ok(CeremonyOutcome::Approved(Box::new(verified)));
    }

    let config_err = |e: String| CeremonyError::new("CONFIG_ERROR", e);
    let raw_cfg = |key: &str| loaded.as_ref().and_then(|c| c.raw.get(key));
    let configured_portal = match raw_cfg("dropPortalUrl") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(s.as_str()),
        Some(_) => {
            return Err(config_err(format!(
                "Invalid dropPortalUrl in {}: must be a string",
                config_read.display()
            )));
        }
    };
    let drop_portal_url = resolve_drop_portal_url(configured_portal)
        .map_err(|e| config_err(format!("Invalid Drop Portal URL: {e}")))?;
    let portal_origin = extract_portal_origin(&drop_portal_url).map_err(config_err)?;

    // Remote Drop Relay: `--relay`, else node.json `dropRelayUrl`; `--local` forces loopback.
    let configured_relay = raw_cfg("dropRelayUrl")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let remote_relay_url = match (ceremony.local, &ceremony.relay, configured_relay) {
        (true, _, _) | (false, None, None) => None,
        (false, Some(explicit), _) => Some(
            validate_relay_url(explicit)
                .map_err(|e| CeremonyError::usage("INVALID_RELAY_URL", e))?,
        ),
        (false, None, Some(configured)) => Some(
            validate_relay_url(configured)
                .map_err(|e| CeremonyError::new("INVALID_RELAY_URL", e))?,
        ),
    };

    action.v = 1;
    action.nonce = random_b64url(16).map_err(|e| CeremonyError::new("RNG_ERROR", e))?;
    action.exp = format_rfc3339_millis(
        now_unix_ms().saturating_add((ceremony.ttl as i64).saturating_mul(1_000)),
    );
    validate_approval_action(&action).map_err(|e| {
        CeremonyError::new(
            "APPROVAL_INVALID_ACTION",
            format!("Invalid approval request: {e}"),
        )
    })?;

    let link = ApprovalLink {
        drop_portal_url,
        identity: &identity,
        node_cert_hcert1: db
            .human()
            .get_latest_node_cert(&node_id)
            .ok()
            .flatten()
            .and_then(|rec| serde_json::from_str::<SignedNodeCertV1>(&rec.signed_json).ok())
            .and_then(|signed| encode_hcert1(&signed).ok()),
        admin: &admin,
        hint_auth_epoch: admin
            .auth_epoch
            .max(db.human().min_auth_epoch().unwrap_or(1)),
        action: &action,
    };
    let pending = |url: String, mode, drop_id, relay, expires_at| {
        Ok(CeremonyOutcome::Pending(Box::new(PendingApproval {
            url,
            mode,
            drop_id,
            relay,
            expires_at,
            authority_human_id: admin.human_id.clone(),
            authority_kid: admin.kid.clone(),
            action: action.clone(),
            summary: summary.to_vec(),
        })))
    };
    let open_browser = !should_skip_browser_open(ceremony.no_open, secrets);

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            CeremonyError::new(
                "RUNTIME_ERROR",
                format!("Failed to start async runtime: {e}"),
            )
        })?;

    // Transport 1: remote Blind Drop Relay slot.
    if let Some(ref relay_base) = remote_relay_url {
        let created = rt
            .block_on(create_relay_drop_slot(
                relay_base,
                &node_id,
                &identity,
                ceremony.ttl,
            ))
            .map_err(|e| {
                CeremonyError::new("RELAY_CREATE_FAILED", e).with_next(
                    "Re-run with --local to use an ephemeral loopback approval listener.",
                )
            })?;
        let expires_at = format_rfc3339_millis(created.expires_at_ms);
        let url = link.url(
            &expires_at,
            Some(&ApprovalSlot {
                drop_id: &created.drop_id,
                relay_url: relay_base,
                post_cap: &created.post_cap,
            }),
        )?;
        if ceremony.no_wait {
            return pending(
                url,
                "relay",
                Some(created.drop_id),
                Some(relay_base.clone()),
                expires_at,
            );
        }
        link.announce(&url, &expires_at, summary, open_browser);
        let (verified, _ack, _warnings) = rt
            .block_on(wait_for_relay_drop(
                relay_base,
                &created.drop_id,
                Some(&created.sub_cap),
                &node_id,
                &identity,
                ceremony.ttl,
                async |envelope| {
                    verify_approval_envelope(
                        &envelope,
                        &identity,
                        db,
                        secrets,
                        &action,
                        Some(&created.drop_id),
                        true,
                    )
                    .map_err(|e| e.message)
                },
            ))
            .map_err(|e| {
                CeremonyError::new(
                    "APPROVAL_WAIT_FAILED",
                    format!("No valid Passkey approval received on relay '{relay_base}': {e}"),
                )
            })?;
        return Ok(CeremonyOutcome::Approved(Box::new(verified)));
    }

    // Transport 2: `--no-wait` without a relay prints an offline link for `--approval-file`.
    if ceremony.no_wait {
        let url = link.url(&action.exp, None)?;
        return pending(url, "offline", None, None, action.exp.clone());
    }

    // Transport 3: one-shot loopback listener on 127.0.0.1:0.
    let verified = rt.block_on(run_loopback_approval_ceremony(
        &link,
        &portal_origin,
        db,
        secrets,
        summary,
        ceremony.ttl,
        open_browser,
    ))?;
    Ok(CeremonyOutcome::Approved(Box::new(verified)))
}

fn read_approval_envelope_file(path: &Path) -> Result<HumanDropEnvelopeV1, CeremonyError> {
    let file_err = |what: &str, e: io::Error| {
        CeremonyError::new(
            "APPROVAL_FILE_ERROR",
            format!("Failed to {what} --approval-file {}: {e}", path.display()),
        )
    };
    let meta = std::fs::metadata(path).map_err(|e| file_err("stat", e))?;
    if meta.len() > MAX_APPROVAL_BYTES as u64 {
        return Err(CeremonyError::usage(
            "APPROVAL_TOO_LARGE",
            format!("--approval-file exceeds {MAX_APPROVAL_BYTES} byte safety cap"),
        ));
    }
    let raw = std::fs::read_to_string(path).map_err(|e| file_err("read", e))?;
    decode_drop_envelope(&raw).map_err(|e| CeremonyError::new("INVALID_APPROVAL_ENVELOPE", e))
}

/// Names the first field where the signed action differs from the requested one.
fn first_action_mismatch(
    expected: &HumanApprovalActionV1,
    actual: &HumanApprovalActionV1,
) -> Option<String> {
    let (Ok(Value::Object(exp)), Ok(Value::Object(act))) =
        (serde_json::to_value(expected), serde_json::to_value(actual))
    else {
        return Some("action".to_string());
    };
    exp.keys()
        .chain(act.keys())
        .find(|key| exp.get(*key) != act.get(*key))
        .cloned()
}

/// Strictly verifies a received Passkey-signed approval envelope fail-closed and consumes both
/// `claim.claim_id` and `action.nonce` in `human_claim_nonces`.
///
/// `live` is true when the envelope answers the URL this process just printed, so `nonce` and
/// `exp` must match too. With `--approval-file` the URL came from an earlier `--no-wait` run whose
/// nonce this process never saw; every other field is still bound.
fn verify_approval_envelope(
    envelope: &HumanDropEnvelopeV1,
    identity: &NodeIdentityKeys,
    db: &NodeDb,
    secrets: &SecretStore,
    expected_action: &HumanApprovalActionV1,
    expected_drop_id: Option<&str>,
    live: bool,
) -> Result<VerifiedApproval, CeremonyError> {
    let rejected = |code, msg: String| CeremonyError::new(code, msg);
    let db_err = |e: hyp_store::StoreError| CeremonyError::new("DB_ERROR", e.to_string());
    let now = now_unix_ms();
    let min_epoch = db.human().min_auth_epoch().map_err(db_err)?;

    let mut matched_authority: Option<HumanAuthorityRecord> = None;
    let mut reject_reason: Option<String> = None;
    let (claim, signed) = open_human_drop_with_signed(
        envelope,
        &identity.encryption,
        &expected_action.node_id,
        now,
        |claim_human_id, kid| {
            let rec = match db.human().get_active_authority_by_kid(kid) {
                Ok(Some(rec)) if rec.human_id == claim_human_id => rec,
                _ => {
                    reject_reason = Some(format!(
                        "signer '{claim_human_id}' (kid={kid}) is unknown or revoked"
                    ));
                    return None;
                }
            };
            if !is_passkey_backed_admin(&rec, min_epoch, Some(secrets)) {
                reject_reason = Some(format!(
                    "signer '{}' (kid={kid}, role={}) is not an active Passkey-backed admin authority",
                    rec.human_id,
                    rec.role.as_str()
                ));
                return None;
            }
            let Some(pk) = serde_json::from_str::<OkpJwk>(&rec.jwk_json)
                .ok()
                .and_then(|jwk| jwk.to_ed25519().ok())
            else {
                reject_reason = Some(format!("invalid Ed25519 key for authority kid '{kid}'"));
                return None;
            };
            matched_authority = Some(rec);
            Some((pk, min_epoch))
        },
    )
    .map_err(|e| {
        rejected(
            "APPROVAL_VERIFICATION_FAILED",
            match reject_reason {
                Some(ref r) => format!("Passkey approval rejected ({r}): {e}"),
                None => format!("Passkey approval cryptographic verification failed: {e}"),
            },
        )
    })?;
    let authority = matched_authority.ok_or_else(|| {
        rejected(
            "APPROVAL_VERIFICATION_FAILED",
            "Passkey approval signer authority could not be resolved".to_string(),
        )
    })?;

    if claim.kind != HumanDropKind::Approval {
        return Err(rejected(
            "APPROVAL_KIND_MISMATCH",
            format!(
                "Expected kind='approval' drop, got kind='{}'",
                claim.kind.as_str()
            ),
        ));
    }
    if claim.auth_epoch != authority.auth_epoch {
        return Err(rejected(
            "APPROVAL_SIGNER_MISMATCH",
            "Signed approval claim authEpoch does not match enrolled Passkey Admin".to_string(),
        ));
    }
    if expected_drop_id.is_some_and(|expected| claim.drop_id != expected) {
        return Err(rejected(
            "APPROVAL_DROP_ID_MISMATCH",
            format!(
                "Approval dropId '{}' does not match the active ceremony slot",
                claim.drop_id
            ),
        ));
    }

    let invalid = |msg: String| rejected("APPROVAL_INVALID_ACTION", msg);
    let signed_action: HumanApprovalActionV1 = serde_json::from_str(&claim.body)
        .map_err(|e| invalid(format!("Malformed signed approval action JSON: {e}")))?;
    let action_exp_ms = validate_approval_action(&signed_action)
        .map_err(|e| invalid(format!("Invalid signed approval action: {e}")))?;
    if now >= action_exp_ms {
        return Err(rejected(
            "APPROVAL_EXPIRED",
            format!("Signed approval action expired at {}", signed_action.exp),
        ));
    }

    let mut expected = expected_action.clone();
    if !live {
        expected.nonce.clone_from(&signed_action.nonce);
        expected.exp.clone_from(&signed_action.exp);
    }
    if let Some(field) = first_action_mismatch(&expected, &signed_action) {
        return Err(rejected(
            "APPROVAL_MISMATCH",
            format!(
                "Signed Passkey approval '{field}' does not match requested '{}' operation",
                expected.action.as_str()
            ),
        ));
    }

    // Consume BOTH the ceremony nonce AND the claim_id so neither can ever be replayed.
    let claim_exp_ms = parse_rfc3339_millis(&claim.expires_at)
        .map_err(|e| invalid(format!("Invalid claim expiresAt: {e}")))?;
    let replay_exp_ms = claim_exp_ms.max(action_exp_ms);
    for replay_key in [
        format!("an_{}", signed_action.nonce),
        claim.claim_id.clone(),
    ] {
        let fresh = db
            .human()
            .consume_claim_nonce(
                &replay_key,
                &authority.kid,
                HumanClaimKind::Approval,
                replay_exp_ms,
                now,
            )
            .map_err(db_err)?;
        if !fresh {
            return Err(rejected(
                "APPROVAL_REPLAYED",
                "Approval has already been used (replay rejected)".to_string(),
            ));
        }
    }

    let signed_claim_json = to_canonical_json(&signed).map_err(|e| {
        CeremonyError::new(
            "JSON_ERROR",
            format!("Failed to canonicalize signed approval claim: {e}"),
        )
    })?;
    Ok(VerifiedApproval {
        action: signed_action,
        signed_claim_json,
        human_id: authority.human_id,
        kid: authority.kid,
    })
}

// ============================================================================
// Loopback transport: one-shot local DropRelay on `127.0.0.1:0`
// ============================================================================

/// An approval the HTTP handler accepted into the slot, awaiting verification on the main task
/// (which owns the non-`Sync` `NodeDb`).
struct LoopbackSubmission {
    seq: u64,
    envelope: HumanDropEnvelopeV1,
    reply_tx: oneshot::Sender<Result<(String, String), String>>,
}

struct LoopbackRelayState {
    relay: DropRelay,
    drop_id: String,
    allowed_origin: String,
    submit_tx: mpsc::Sender<LoopbackSubmission>,
}

async fn run_loopback_approval_ceremony(
    link: &ApprovalLink<'_>,
    portal_origin: &str,
    db: &NodeDb,
    secrets: &SecretStore,
    summary: &[String],
    ttl_secs: u64,
    open_browser: bool,
) -> Result<VerifiedApproval, CeremonyError> {
    let node_id = link.action.node_id.as_str();
    let bind_err = |e: io::Error| {
        CeremonyError::new(
            "LOOPBACK_BIND_FAILED",
            format!("Failed to bind local loopback approval listener: {e}"),
        )
    };
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(bind_err)?;
    let relay_base = format!(
        "http://127.0.0.1:{}",
        listener.local_addr().map_err(bind_err)?.port()
    );

    let relay = DropRelay::new(DropRelayConfig {
        enabled: true,
        local_drops_only: true,
        max_items_per_drop: 8,
        allowed_origins: vec![portal_origin.to_string()],
        allow_private_network: true,
        ..Default::default()
    })
    .with_local_node_id(node_id);
    let created = relay
        .create_drop(
            node_id,
            "127.0.0.1",
            CreateDropRequest {
                ttl_seconds: Some(ttl_secs),
                max_items: Some(8),
                target_node_id: Some(node_id.to_string()),
                burn_after_read: true,
            },
            now_unix_ms(),
        )
        .map_err(|e| {
            CeremonyError::new(
                "RELAY_CREATE_FAILED",
                format!("Failed to create local approval slot: {e}"),
            )
        })?;

    let expires_at = format_rfc3339_millis(created.expires_at_ms);
    let url = link.url(
        &expires_at,
        Some(&ApprovalSlot {
            drop_id: &created.drop_id,
            relay_url: &relay_base,
            post_cap: &created.post_cap,
        }),
    )?;
    link.announce(&url, &expires_at, summary, open_browser);

    let (submit_tx, mut submit_rx) = mpsc::channel::<LoopbackSubmission>(8);
    let state = Arc::new(LoopbackRelayState {
        relay: relay.clone(),
        drop_id: created.drop_id.clone(),
        allowed_origin: portal_origin.to_string(),
        submit_tx,
    });

    let timeout = tokio::time::sleep(Duration::from_secs(ttl_secs.max(1)));
    tokio::pin!(timeout);
    loop {
        tokio::select! {
            _ = &mut timeout => {
                return Err(CeremonyError::new(
                    "APPROVAL_TIMEOUT",
                    format!("Timed out after {ttl_secs}s waiting for Passkey approval signature"),
                ));
            }
            Some(sub) = submit_rx.recv() => {
                match verify_approval_envelope(
                    &sub.envelope,
                    link.identity,
                    db,
                    secrets,
                    link.action,
                    Some(&created.drop_id),
                    true,
                ) {
                    Ok(verified) => {
                        let _ = sub.reply_tx.send(Ok((verified.human_id.clone(), verified.kid.clone())));
                        let _ = relay.ack_drop(
                            &created.drop_id,
                            DropSubscriberAuth::SubCap(&created.sub_cap),
                            sub.seq,
                            true,
                            now_unix_ms(),
                        );
                        // Give the HTTP 201 response time to flush to the browser before the listener closes.
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        return Ok(verified);
                    }
                    Err(err) => {
                        eprintln!("WARN  Rejected unverified Passkey approval: {}", err.message);
                        let _ = io::stderr().flush();
                        let _ = sub.reply_tx.send(Err(err.message));
                    }
                }
            }
            Ok((stream, _)) = listener.accept() => {
                let st = Arc::clone(&state);
                tokio::spawn(async move {
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let st = Arc::clone(&st);
                        async move { Ok::<_, Infallible>(handle_loopback_drop_req(st, req).await) }
                    });
                    let _ = AutoServerBuilder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        }
    }
}

/// Serves `POST /v1/drops/<dropId>` (plus its CORS preflight) for the one approval slot.
async fn handle_loopback_drop_req(
    state: Arc<LoopbackRelayState>,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let allowed = state.allowed_origin.as_str();
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);
    // Fail closed on a missing or mismatched Origin header (defeats CSRF / rogue local pages).
    if origin.as_deref() != Some(allowed) {
        return json_response(
            StatusCode::FORBIDDEN,
            None,
            allowed,
            json!({ "ok": false, "error": "forbidden origin" }),
        );
    }

    if req.method() == Method::OPTIONS {
        let mut resp = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(header::ACCESS_CONTROL_ALLOW_METHODS, "POST, OPTIONS")
            .header(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                format!("Content-Type, {DROP_CAP_HEADER}"),
            )
            .header(header::ACCESS_CONTROL_MAX_AGE, "600")
            .header(header::CACHE_CONTROL, "no-store")
            .body(Full::new(Bytes::new()))
            .expect("valid preflight response");
        apply_cors(origin.as_deref(), allowed, &mut resp);
        return resp;
    }

    let (status, body) = match accept_loopback_post(&state, req).await {
        Ok(body) => (StatusCode::CREATED, body),
        Err((status, error)) => (status, json!({ "ok": false, "error": error })),
    };
    json_response(status, origin.as_deref(), allowed, body)
}

async fn accept_loopback_post(
    state: &LoopbackRelayState,
    req: Request<Incoming>,
) -> Result<Value, (StatusCode, String)> {
    let drop_id = state.drop_id.as_str();
    let path = req.uri().path();
    if path != format!("/v1/drops/{}", percent_encode(drop_id))
        && path != format!("/v1/drops/{drop_id}")
    {
        return Err((StatusCode::NOT_FOUND, "unknown approval drop slot".into()));
    }
    if req.method() != Method::POST {
        return Err((StatusCode::METHOD_NOT_ALLOWED, "expected POST".into()));
    }
    let post_cap = req
        .headers()
        .get(DROP_CAP_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned)
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "missing X-Hyphae-Drop-Cap header".to_string(),
        ))?;

    // Constant-time capability check BEFORE reading body bytes.
    state
        .relay
        .verify_capability(drop_id, &post_cap, DropCapRole::Post, now_unix_ms())
        .map_err(|e| (e.status_code(), e.to_string()))?;
    let bytes = collect_bounded_body(req.into_body(), MAX_APPROVAL_BYTES)
        .await
        .map_err(|e| (StatusCode::PAYLOAD_TOO_LARGE, e))?;
    let posted = state
        .relay
        .post_drop(drop_id, &post_cap, bytes.clone(), now_unix_ms())
        .map_err(|e| (e.status_code(), e.to_string()))?;
    let envelope = std::str::from_utf8(&bytes)
        .map_err(|_| "approval payload must be valid UTF-8".to_string())
        .and_then(decode_drop_envelope)
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    let (reply_tx, reply_rx) = oneshot::channel();
    let closed = || {
        (
            StatusCode::GONE,
            "approval ceremony already completed or closed".to_string(),
        )
    };
    state
        .submit_tx
        .send(LoopbackSubmission {
            seq: posted.seq,
            envelope,
            reply_tx,
        })
        .await
        .map_err(|_| closed())?;
    let (human_id, kid) = reply_rx
        .await
        .map_err(|_| closed())?
        .map_err(|reason| (StatusCode::FORBIDDEN, reason))?;
    Ok(json!({
        "ok": true,
        "seq": posted.seq,
        "expiresAtMs": posted.expires_at_ms,
        "verified": true,
        "humanId": human_id,
        "kid": kid,
    }))
}
