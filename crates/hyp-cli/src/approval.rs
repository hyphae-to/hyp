//! Live per-operation Passkey approval for gate policy and authority changes (`#10` — G1, H1, H2).
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
//! The signed approval comes back over a live Blind Drop Relay slot or one-shot loopback listener.

use crate::auth_cmd::{
    apply_enroll_cors as apply_cors, extract_portal_origin, json_enroll_response as json_response,
    random_b64url, should_skip_browser_open, try_open_browser,
};
use crate::config_file::{
    ensure_dir, load_node_or_legacy_config, resolve_effective_node_id, write_atomic_file,
};
use crate::drop_cmd::{
    collect_bounded_body, create_relay_drop_slot, decode_drop_envelope, validate_relay_url,
    wait_for_relay_drop,
};
use crate::gate_cmd::sanitize_tty_display;
use crate::ui::{EXIT_ERROR, EXIT_USAGE};
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
use hyp_node::gates::policy::{
    SecurityGateConfig, is_passkey_backed_admin, verify_gate_policy_for_node,
};
use hyp_node::node_file::NodeFile;
use hyp_store::{
    GateLockSealRecord, HumanAuthorityRecord, HumanClaimKind, NodeDb, StoreError, now_ms,
};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use serde_json::{Map, Value, json};
use std::convert::Infallible;
use std::io::{self, Write as _};
use std::path::Path;
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
}

impl Default for ApprovalCeremonyArgs {
    fn default() -> Self {
        Self {
            relay: None,
            local: false,
            ttl: DEFAULT_APPROVAL_TTL_SECS,
            no_open: false,
        }
    }
}

/// Integrity of existing policy evidence. This never authorizes a mutation.
#[derive(Debug, Clone)]
pub(crate) struct PolicyIntegrityState {
    /// True when signed evidence exists or verification failed (fail closed).
    pub approved: bool,
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
    claim_id: String,
    replay_expires_at: i64,
    commit_expires_at: i64,
    expected_state: Value,
}

#[derive(Debug, Clone)]
pub(crate) enum CeremonyOutcome {
    Approved(Box<VerifiedApproval>),
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

    pub fn into_cli_error(self) -> crate::ui::CliError {
        crate::ui::CliError::new(self.exit_code, self.code, self.message)
            .with_optional_fix(self.next)
    }

    pub fn emit(self, cmd: &str, as_json: bool) -> ExitCode {
        crate::ui::print_command_error(cmd, as_json, self.into_cli_error())
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

/// Bootstrap is permitted only before any Passkey admin was enrolled. Revocation, expiry,
/// or a missing shell secret never turns an existing installation back into a new one.
/// Database errors are protected, not bootstrap permission.
pub(crate) fn has_passkey_history(state_dir: &Path) -> bool {
    let path = state_dir.join("node.sqlite");
    path.exists()
        && NodeDb::open(&path)
            .and_then(|db| db.human().requires_live_approval())
            .unwrap_or(true)
}

/// A revocation must be signed by an admin who remains eligible after that operation.
fn survives_operation(authority: &HumanAuthorityRecord, action: &HumanApprovalActionV1) -> bool {
    if matches!(
        action.action,
        HumanApprovalActionKind::AuthAdd | HumanApprovalActionKind::AuthAdmit
    ) {
        if action.target_kid.as_deref() != Some(&authority.kid) {
            return true;
        }
        let Some(input) = action.parameters.as_ref().and_then(|p| p.get("authority")) else {
            return false;
        };
        return input.get("role").and_then(Value::as_str) == Some("admin")
            && input.get("auth_epoch").and_then(Value::as_u64) == Some(authority.auth_epoch)
            && input.get("prf_salt").and_then(Value::as_str).is_some();
    }
    if action.action != HumanApprovalActionKind::AuthRevoke {
        return true;
    }
    let Some(parameters) = action.parameters.as_ref() else {
        return false;
    };
    let Some(epoch) = parameters.get("newMinAuthEpoch").and_then(Value::as_u64) else {
        return false;
    };
    let Some(targets) = parameters.get("targets").and_then(Value::as_array) else {
        return false;
    };
    authority.auth_epoch >= epoch
        && !targets
            .iter()
            .any(|target| target.get("kid").and_then(Value::as_str) == Some(authority.kid.as_str()))
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
            if db.human().requires_live_approval().unwrap_or(true) {
                return CeremonyError::new("PASSKEY_AUTHORITY_REQUIRED",
                    "No current Passkey Admin is eligible to approve new changes. Revocation or epoch reduction does not reopen bootstrap; current policy remains in effect.")
                    .with_next(format!("hyp auth list --state-dir {} --json", state_dir.display()));
            }
            CeremonyError::new(
                "PASSKEY_AUTHORITY_REQUIRED",
                "No enrolled Passkey Admin authority found. Changing the Security Gate or human authorities requires a browser Passkey Admin (local CLI PKCS#8 keys in SecretStore cannot satisfy the human boundary).",
            )
            .with_next(format!(
                "hyp auth init --web --state-dir {}",
                state_dir.display()
            ))
        })
}

/// Inspects existing policy integrity evidence, failing closed on unreadable or invalid state.
/// Mutation authorization always requires a separate live approval.
pub(crate) fn inspect_policy_integrity(
    config_path: &Path,
    state_dir: &Path,
    secrets: &SecretStore,
) -> PolicyIntegrityState {
    let verify = || -> Result<bool, String> {
        let gate_cfg = match NodeFile::read_document_or_empty(config_path)
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
        let loaded = load_node_or_legacy_config(config_path).ok();
        let node_id = resolve_effective_node_id(loaded.as_ref(), Some(&db));
        verify_gate_policy_for_node(&gate_cfg, &db, Some(secrets), Some(&node_id))
            .map(|state| state.approved)
            .map_err(|e| e.to_string())
    };
    match verify() {
        Ok(approved) => PolicyIntegrityState {
            approved,
            tampered_reason: None,
        },
        Err(reason) => PolicyIntegrityState {
            approved: true,
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
    db.local()
        .ensure_metadata("node_id", &verified.action.node_id)
        .map_err(|e| e.to_string())?;
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
) -> HumanApprovalActionV1 {
    HumanApprovalActionV1 {
        v: 1,
        action,
        node_id,
        nonce: String::new(),
        exp: String::new(),
        seal_seq,
        locked: true,
        policy_sha256: None,
        authorities_digest: None,
        target_human_id: None,
        target_kid: None,
        target_role: None,
        bump_epoch: None,
        cascade: None,
        parameters: None,
    }
}

/// Final compare, replay consumption, mutation and seal share one serialized SQLite writer.
/// A normal config-write failure rolls back authority/delegation/cascade changes, nonce and seal.
/// Config and SQLite are separate resources: a crash or SQLite commit failure can leave config
/// disagreeing with the old persisted seal, which remains fail closed rather than granting access.
pub(crate) fn execute_approved_operation<T>(
    config_read: &Path,
    config_write: &Path,
    db: &NodeDb,
    verified: &VerifiedApproval,
    operation: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    eprintln!("Applying approved operation...");
    db.with_write_transaction(|| {
        let fail = StoreError::InvalidState;
        if approval_snapshot(config_read, db).map_err(|e| fail(e.message))?
            != verified.expected_state
        {
            return Err(fail(
                "approval prestate changed before commit; request a fresh approval".into(),
            ));
        }
        let now = now_unix_ms();
        if now >= verified.commit_expires_at {
            return Err(fail("approval expired before commit".into()));
        }
        let original = match std::fs::read(config_write) {
            Ok(bytes) => Some(bytes),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => return Err(fail(e.to_string())),
        };
        for replay_key in [
            format!("an_{}", verified.action.nonce),
            verified.claim_id.clone(),
        ] {
            if !db.human().consume_claim_nonce(
                &replay_key,
                &verified.kid,
                HumanClaimKind::Approval,
                verified.replay_expires_at,
                now,
            )? {
                return Err(fail("approval already used (replay rejected)".into()));
            }
        }
        let result = operation().and_then(|value| {
            let raw = NodeFile::read_document_or_empty(config_write)?;
            let loaded = load_node_or_legacy_config(config_write).map_err(|e| e.to_string())?;
            if resolve_effective_node_id(Some(&loaded), Some(db)) != verified.action.node_id {
                return Err("resulting node identity differs from the signed approval".into());
            }
            let policy: SecurityGateConfig = serde_json::from_value(
                raw.get("gate")
                    .cloned()
                    .ok_or("resulting policy is missing")?,
            )
            .map_err(|e| e.to_string())?;
            if hyp_node::gates::gate_policy_sha256(&policy)
                .map_err(|e| e.to_string())?
                .as_str()
                != verified
                    .action
                    .policy_sha256
                    .as_deref()
                    .ok_or("signed policy hash missing")?
            {
                return Err("resulting policy differs from the signed approval".into());
            }
            if db
                .human()
                .authorities_digest()
                .map_err(|e| e.to_string())?
                .as_str()
                != verified
                    .action
                    .authorities_digest
                    .as_deref()
                    .ok_or("signed authority digest missing")?
            {
                return Err("resulting authority digest differs from the signed approval".into());
            }
            if let Some(epoch) = verified
                .action
                .parameters
                .as_ref()
                .and_then(|p| p.get("newMinAuthEpoch"))
                .and_then(Value::as_u64)
            {
                if db.human().min_auth_epoch().map_err(|e| e.to_string())? != epoch {
                    return Err("resulting minimum epoch differs from the signed approval".into());
                }
            }
            let seal = db
                .human()
                .get_gate_lock_seal()
                .map_err(|e| e.to_string())?
                .ok_or("approved policy evidence was not persisted")?;
            if seal.seal_seq != verified.action.seal_seq
                || seal.signed_claim_json != verified.signed_claim_json
            {
                return Err("persisted policy evidence differs from the approval".into());
            }
            Ok(value)
        });
        if let Err(error) = &result {
            let restored = match original {
                Some(bytes)
                    if std::fs::read(config_write).ok().as_deref() != Some(bytes.as_slice()) =>
                {
                    write_atomic_file(config_write, &bytes, true)
                }
                None if config_write.exists() => {
                    std::fs::remove_file(config_write).map_err(|e| e.to_string())
                }
                _ => Ok(()),
            };
            if let Err(restore_error) = restored {
                return Err(fail(format!(
                    "{error}; config restore failed: {restore_error}; policy remains fail closed"
                )));
            }
        }
        result.map_err(fail)
    })
    .map_err(|e| e.to_string())
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

fn approval_snapshot(config_read: &Path, db: &NodeDb) -> Result<Value, CeremonyError> {
    let config = match std::fs::read(config_read) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(CeremonyError::new("CONFIG_ERROR", e.to_string())),
    };
    let human = db.human();
    Ok(json!({
        "config": config,
        "authorities": human.list_authorities(true).map_err(|e| CeremonyError::new("DB_ERROR", e.to_string()))?,
        "epoch": human.min_auth_epoch().map_err(|e| CeremonyError::new("DB_ERROR", e.to_string()))?,
        "seal": human.get_gate_lock_seal().map_err(|e| CeremonyError::new("DB_ERROR", e.to_string()))?,
    }))
}

/// Runs a live Passkey approval ceremony for exactly one operation. `summary` is shown on the local terminal only; it is
/// not part of what the Passkey signs.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_passkey_approval_ceremony(
    state_dir: &Path,
    config_read: &Path,
    db: &NodeDb,
    secrets: &SecretStore,
    action: HumanApprovalActionV1,
    summary: &[String],
    ceremony: &ApprovalCeremonyArgs,
) -> Result<CeremonyOutcome, CeremonyError> {
    let before = approval_snapshot(config_read, db)?;
    let outcome = run_passkey_approval_ceremony_inner(
        state_dir,
        config_read,
        db,
        secrets,
        action,
        summary,
        ceremony,
    )?;
    if approval_snapshot(config_read, db)? != before {
        return Err(CeremonyError::new(
            "APPROVAL_STATE_CHANGED",
            "Policy or authorities changed during approval; request a fresh approval for the current state.",
        ));
    }
    let CeremonyOutcome::Approved(mut verified) = outcome;
    verified.expected_state = before;
    Ok(CeremonyOutcome::Approved(verified))
}

#[allow(clippy::too_many_arguments)]
fn run_passkey_approval_ceremony_inner(
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
    let admin = if matches!(
        action.action,
        HumanApprovalActionKind::AuthRevoke
            | HumanApprovalActionKind::AuthAdd
            | HumanApprovalActionKind::AuthAdmit
    ) {
        find_active_passkey_admins(db, secrets)
            .map_err(|e| CeremonyError::new("DB_ERROR", e))?
            .into_iter()
            .filter(|admin| survives_operation(admin, &action))
            .max_by_key(|admin| admin.created_at)
            .ok_or_else(|| {
                CeremonyError::new(
                    "PASSKEY_AUTHORITY_REQUIRED",
                    "No Passkey Admin can approve and remain active after this authority change",
                )
            })?
    } else {
        select_passkey_admin(db, secrets, state_dir, exclude_kid)?
    };
    let identity = secrets.load_or_create_node_keys(&node_id).map_err(|e| {
        CeremonyError::new(
            "NODE_KEY_ERROR",
            format!("Failed to load node identity keys: {e}"),
        )
    })?;

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
        .find(|key| {
            let canonical = |value: Option<&Value>| value.and_then(|v| to_canonical_json(v).ok());
            canonical(exp.get(*key)) != canonical(act.get(*key))
        })
        .cloned()
}

/// Strictly verifies a received Passkey-signed approval envelope fail closed. The final writer
/// transaction consumes `claim.claim_id` and `action.nonce` together with the approved mutation.
///
/// The nonce and expiry must match this live process. Offline approvals are never accepted.
fn verify_approval_envelope(
    envelope: &HumanDropEnvelopeV1,
    identity: &NodeIdentityKeys,
    db: &NodeDb,
    secrets: &SecretStore,
    expected_action: &HumanApprovalActionV1,
    expected_drop_id: Option<&str>,
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

    let expected = expected_action;
    if let Some(field) = first_action_mismatch(expected, &signed_action) {
        return Err(rejected(
            "APPROVAL_MISMATCH",
            format!(
                "Signed Passkey approval '{field}' does not match requested '{}' operation",
                expected.action.as_str()
            ),
        ));
    }

    if !survives_operation(&authority, &signed_action) {
        return Err(rejected(
            "APPROVAL_SIGNER_MISMATCH",
            "Approver must remain an active Passkey Admin after the operation".into(),
        ));
    }

    let claim_exp_ms = parse_rfc3339_millis(&claim.expires_at)
        .map_err(|e| invalid(format!("Invalid claim expiresAt: {e}")))?;
    let replay_exp_ms = claim_exp_ms.max(action_exp_ms);

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
        claim_id: claim.claim_id,
        replay_expires_at: replay_exp_ms,
        commit_expires_at: claim_exp_ms.min(action_exp_ms),
        expected_state: Value::Null,
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

#[cfg(test)]
mod commit_tests {
    use super::*;
    use hyp_store::{
        HumanAuthorityInput, HumanAuthorityRole, HumanAuthorityStatus, HumanDelegationPolicyInput,
    };
    use tempfile::TempDir;

    fn authority(id: &str) -> HumanAuthorityInput {
        HumanAuthorityInput {
            human_id: id.into(),
            kid: format!("{id}_key"),
            label: id.into(),
            role: HumanAuthorityRole::Signer,
            jwk_json: "{}".into(),
            enc_jwk_json: None,
            prf_salt: None,
            auth_epoch: 1,
        }
    }

    // These fixtures represent the output of verification. Real Passkey signatures and their
    // active-authority requirements are exercised by the live CLI/browser integration tests.
    fn approved(
        db: &NodeDb,
        config: &Path,
        digest: String,
    ) -> (VerifiedApproval, SecurityGateConfig) {
        let mut policy = SecurityGateConfig {
            require_signed_policy: true,
            human_authorities_digest: Some(digest.clone()),
            ..Default::default()
        };
        policy.policy_signature = None;
        let mut action =
            base_approval_action(HumanApprovalActionKind::AuthAdd, "commit@box".into(), 1);
        action.nonce = "commit_nonce".into();
        action.exp = format_rfc3339_millis(now_unix_ms() + 300_000);
        action.target_human_id = Some("member".into());
        action.target_kid = Some("member_key".into());
        action.target_role = Some("signer".into());
        action.policy_sha256 = Some(hyp_node::gates::gate_policy_sha256(&policy).unwrap());
        action.authorities_digest = Some(digest);
        (
            VerifiedApproval {
                action,
                signed_claim_json: "{}".into(),
                human_id: "admin".into(),
                kid: "admin_key".into(),
                claim_id: "commit_claim".into(),
                replay_expires_at: now_unix_ms() + 300_000,
                commit_expires_at: now_unix_ms() + 300_000,
                expected_state: approval_snapshot(config, db).unwrap(),
            },
            policy,
        )
    }

    fn replay_count(db: &NodeDb) -> i64 {
        db.connection()
            .query_row(
                "SELECT count(*) FROM human_claim_nonces WHERE kind='approval'",
                [],
                |r| r.get(0),
            )
            .unwrap()
    }

    #[test]
    fn shorter_claim_lifetime_is_rechecked_after_waiting_for_the_final_writer() {
        let tmp = TempDir::new().unwrap();
        let db = NodeDb::open_in_memory().unwrap();
        let config = tmp.path().join("node.json");
        std::fs::write(&config, b"{\"nodeId\":\"commit@box\"}").unwrap();
        let (mut verified, _) = approved(&db, &config, db.human().authorities_digest().unwrap());
        // The proof was verified while both lifetimes were live. Waiting for the writer
        // crosses the shorter claim expiry while action and replay retention remain live.
        verified.commit_expires_at = now_unix_ms() - 1;
        assert!(parse_rfc3339_millis(&verified.action.exp).unwrap() > now_unix_ms());
        assert!(verified.replay_expires_at > now_unix_ms());
        let error = execute_approved_operation::<()>(&config, &config, &db, &verified, || {
            panic!("expired proof must never reach the mutation")
        })
        .unwrap_err();
        assert!(error.contains("expired before commit"), "{error}");
        assert_eq!(replay_count(&db), 0);
        assert!(db.human().get_gate_lock_seal().unwrap().is_none());
    }

    #[test]
    fn ordinary_file_write_failure_rolls_back_authorities_reductions_delegation_replay_and_seal() {
        let tmp = TempDir::new().unwrap();
        let db = NodeDb::open(tmp.path().join("node.sqlite")).unwrap();
        let config = tmp.path().join("node.json");
        let original = b"{\"nodeId\":\"commit@box\"}\n";
        std::fs::write(&config, original).unwrap();
        let mut admin = authority("admin");
        admin.role = HumanAuthorityRole::Admin;
        db.human().upsert_authority(&admin, now_ms()).unwrap();
        let member = authority("member");
        let digest = db
            .human()
            .projected_authorities_digest_after_upsert(&member)
            .unwrap();
        let (verified, _) = approved(&db, &config, digest);
        let blocked = tmp.path().join("directory-is-not-a-file");
        std::fs::create_dir(&blocked).unwrap();
        let error = execute_approved_operation(&config, &config, &db, &verified, || {
            db.human()
                .upsert_authority(&member, now_ms())
                .map_err(|e| e.to_string())?;
            db.human()
                .upsert_delegation_policy(
                    &HumanDelegationPolicyInput {
                        human_id: "member".into(),
                        node_prefix: "member@*".into(),
                        scopes: vec!["dm:send".into()],
                        max_devices: 3,
                        delegation_enabled: true,
                    },
                    now_ms(),
                )
                .map_err(|e| e.to_string())?;
            db.human()
                .revoke_authority_monotonic("admin", "admin_key", 2, "{}", now_ms())
                .map_err(|e| e.to_string())?;
            persist_passkey_gate_seal(&db, &verified)?;
            write_atomic_file(&blocked, b"{}", true)
        })
        .unwrap_err();
        assert!(
            error.contains("rename"),
            "the actual filesystem write must be reached: {error}"
        );
        assert!(
            db.human()
                .get_active_authority_by_kid("member_key")
                .unwrap()
                .is_none()
        );
        assert_eq!(
            db.human()
                .get_authority("admin", "admin_key")
                .unwrap()
                .unwrap()
                .status,
            HumanAuthorityStatus::Active
        );
        assert_eq!(db.human().min_auth_epoch().unwrap(), 1);
        assert!(
            db.human()
                .get_delegation_policy("member")
                .unwrap()
                .is_none()
        );
        assert!(db.human().get_gate_lock_seal().unwrap().is_none());
        assert_eq!(replay_count(&db), 0);
        assert_eq!(std::fs::read(&config).unwrap(), original);
    }

    #[test]
    fn stale_projection_before_ceremony_snapshot_cannot_commit_under_the_signed_digest() {
        let tmp = TempDir::new().unwrap();
        let db = NodeDb::open(tmp.path().join("node.sqlite")).unwrap();
        let config = tmp.path().join("node.json");
        let original = b"{\"nodeId\":\"commit@box\"}\n";
        std::fs::write(&config, original).unwrap();
        let member = authority("member");
        let projected = db
            .human()
            .projected_authorities_digest_after_upsert(&member)
            .unwrap();
        // The operation was projected before a concurrent writer, but the ceremony snapshot
        // sees the later state. Only the signed-result check catches this particular window.
        db.human()
            .upsert_authority(&authority("concurrent"), now_ms())
            .unwrap();
        let (verified, policy) = approved(&db, &config, projected);
        let error = execute_approved_operation(&config, &config, &db, &verified, || {
            db.human()
                .upsert_authority(&member, now_ms())
                .map_err(|e| e.to_string())?;
            persist_passkey_gate_seal(&db, &verified)?;
            crate::config_file::write_atomic_json(
                &config,
                &json!({"nodeId":"commit@box", "gate":policy}),
                true,
            )
        })
        .unwrap_err();
        assert!(
            error.contains("resulting authority digest differs"),
            "{error}"
        );
        assert!(
            db.human()
                .get_active_authority_by_kid("member_key")
                .unwrap()
                .is_none()
        );
        assert!(
            db.human()
                .get_active_authority_by_kid("concurrent_key")
                .unwrap()
                .is_some()
        );
        assert!(db.human().get_gate_lock_seal().unwrap().is_none());
        assert_eq!(replay_count(&db), 0);
        assert_eq!(std::fs::read(&config).unwrap(), original);
    }
}
