//! `hyp join` — Zero-friction Delegated Human-Cert Admission CLI flow.
//!
//! Supports four modes:
//! 1. **Default one-shot loopback browser handoff (`hyp join`)**:
//!    Binds `127.0.0.1:47891` (falling back to OS-assigned port if busy, or `--port`), prints a
//!    CSPRNG 6-digit confirmation code (`NNN-NNN`), serves `/health`, `/device-info`, and
//!    `/complete` (both JSON and Safari form-POST) with strict Origin + Private Network Access
//!    headers and a 5-attempt constant-time code lockout, shuts down immediately upon handoff,
//!    auto-onboards if `node.json` doesn't exist yet, stores local Human Authority + `hcert1_`,
//!    executes `POST /v1/auth/claim` (if `hjoin1_` present) + `POST /v1/pair/delegated`, pins
//!    the hub manifest + bearer credential, and reloads the live daemon.
//! 2. **Signed handoff bundle via `--stdin` / `--token-file <path>`** (Safari / manual / remote VPS).
//! 3. **Headless CLI join (`--stdin --local-key` or `--token-file <path> --local-key`)** accepting
//!    a raw `hjoin1_` invite without a browser Passkey.
//! 4. **Remote machine card handoff (`hyp join --remote`)**: prints the remote machine's public
//!    device card JSON for signing on a laptop browser, then reads the signed handoff bundle from
//!    stdin to complete without the Passkey ever touching the remote host.

use crate::approval::inspect_policy_integrity;
use crate::auth_cmd::admin_secret_name_for_kid;
use crate::config_file::{
    build_http_client, ct_eq, default_node_id, ensure_dir, ensure_v2_node_json_defaults,
    load_node_or_legacy_config, open_secret_store, resolve_config_path_for_read,
    resolve_config_path_for_write, resolve_effective_node_id, resolve_home_dir, resolve_state_dir,
};
use crate::node_identity::short_hostname;
use crate::pair::{attempt_delegated_pair_enroll, credential_secret_name, try_reload_live_daemon};
use crate::setup::configure_detected_harnesses_for_join;
use crate::ui::{
    CliError, CommandResult, EXIT_OK, JsonEnvelope, print_json, print_next_steps, print_warnings,
};
use clap::Args;
use http::{HeaderValue, Method, Request, Response, StatusCode, header};
use http_body_util::Full;
use hyp_crypto::human::{
    HumanInviteClaimV1, NodeCertPayloadV1, SignedNodeCertV1, decode_hcert1, decode_hjoin1,
    encode_hcert1, sign_human_invite_claim, sign_node_cert, verify_human_invite_claim,
    verify_human_invite_embedded, verify_node_cert,
};
use hyp_crypto::jcs::to_canonical_json;
use hyp_crypto::keys::{Ed25519KeyPair, NodeIdentityKeys, OkpJwk};
use hyp_crypto::keystore::SecretStore;
use hyp_crypto::pairing::validate_endpoint_origin;
use hyp_crypto::rfc3339::{format_rfc3339_millis, now_unix_ms, parse_rfc3339_millis};
use hyp_node::engine::http_util::{BoundedBodyError, consume_bounded_body};
use hyp_node::engine::{AuthClaimReply, AuthClaimRequest};
use hyp_node::node_file::NodeFile;
use hyp_proto::address::{LOCAL_NODE_ID, is_valid_node_id};
use hyp_proto::manifest::NodeProfile;
use hyp_proto::problem::ProblemDetails;
use hyp_proto::scopes::matches_node_prefix;
use hyp_store::{
    HumanAuthorityInput, HumanAuthorityRole, HumanNodeCertInput, KeyStatus, KeyUse,
    ManifestCacheUpdate, NodeDb, PeerInput, PeerKeyInput, PeerProfile, PeerStatus,
    TrustTier as StoreTrustTier, now_ms,
};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::convert::Infallible;
use std::fs;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

pub const DEFAULT_JOIN_LOOPBACK_PORT: u16 = 47891;
const DEFAULT_JOIN_TIMEOUT_SECS: u64 = 300;
const MAX_JOIN_BODY_BYTES: usize = 64 * 1024;
const MAX_JOIN_CODE_ATTEMPTS: usize = 5;
const HTTP_TIMEOUT_SECS: u64 = 15;
const MAX_HTTP_RESP_BYTES: usize = 512 * 1024;

#[derive(Args, Debug, Clone)]
pub struct JoinArgs {
    /// Read a signed browser handoff bundle JSON (or raw hjoin1_ token with --local-key) from stdin
    #[arg(long)]
    pub stdin: bool,
    /// Read a signed browser handoff bundle JSON (or raw hjoin1_ token with --local-key) from a private file
    #[arg(long)]
    pub token_file: Option<PathBuf>,
    /// Headless CLI join: generate/use a local Ed25519 human key in SecretStore to claim a raw hjoin1_ invite without a browser Passkey
    #[arg(long)]
    pub local_key: bool,
    /// Print this remote machine's public device card JSON for signing in a laptop browser, then read the signed handoff bundle from stdin
    #[arg(long)]
    pub remote: bool,
    /// With --remote, print the public device card and exit immediately (pipe signed bundle later via `hyp join --stdin`)
    #[arg(long)]
    pub print_card: bool,
    /// Loopback HTTP port for browser handoff (default: 47891, auto-falls back to an ephemeral OS port if busy)
    #[arg(long)]
    pub port: Option<u16>,
    /// Timeout in seconds waiting for browser handoff confirmation (default: 300)
    #[arg(long, default_value_t = DEFAULT_JOIN_TIMEOUT_SECS)]
    pub timeout: u64,
    /// Override this device's canonical nodeId (e.g. philip@macbook)
    #[arg(long)]
    pub node_id: Option<String>,
    /// Explicit state directory containing node.sqlite and secrets/
    #[arg(long)]
    pub state_dir: Option<PathBuf>,
    /// Explicit node.json path
    #[arg(long)]
    pub config: Option<PathBuf>,
    /// Override home directory (ideal for isolated testing)
    #[arg(long)]
    pub home: Option<PathBuf>,
    /// Skip automatic coding-harness setup when auto-onboarding a new device
    #[arg(long)]
    pub no_setup: bool,
    /// Skip auto-starting/reloading the background daemon
    #[arg(long)]
    pub no_start: bool,
    /// Output structured JSON envelope (listening metadata emitted on stderr; final result on stdout)
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JoinHumanAuthorityMeta {
    human_id: String,
    signing_jwk: OkpJwk,
    #[serde(default)]
    enc_jwk: Option<OkpJwk>,
    #[serde(default)]
    prf_salt: Option<String>,
    #[serde(default)]
    auth_epoch: Option<u64>,
    #[serde(default)]
    label: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct JoinHandoffBundle {
    #[serde(default)]
    hjoin1: Option<String>,
    #[serde(default)]
    human_claim: Option<HumanInviteClaimV1>,
    #[serde(default)]
    human_claim_sig: Option<String>,
    human_authority: JoinHumanAuthorityMeta,
    node_cert: String,
    #[serde(default)]
    hub_endpoint: Option<String>,
    #[serde(default)]
    hub_node_id: Option<String>,
    #[serde(default)]
    hub_fingerprint: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoteDeviceCard {
    v: u32,
    node_id: String,
    hostname: String,
    ed25519_jwk: OkpJwk,
    x25519_jwk: OkpJwk,
    already_onboarded: bool,
}

struct ValidatedHandoff {
    node_id: String,
    already_onboarded: bool,
    human_id: String,
    human_kid: String,
    human_signing_jwk_json: String,
    human_enc_jwk_json: Option<String>,
    human_prf_salt: Option<String>,
    human_label: String,
    human_auth_epoch: u64,
    signed_cert: SignedNodeCertV1,
    cert_payload: NodeCertPayloadV1,
    cert_issued_ms: i64,
    cert_expires_ms: i64,
    hcert1: String,
    hub_node_id: String,
    hub_endpoint: String,
    hub_fingerprint: Option<String>,
    claim_request: Option<AuthClaimRequest>,
}

pub fn run_join(args: JoinArgs) -> CommandResult {
    let as_json = args.json;
    CommandResult::new("join", as_json, join(args))
}

fn join(args: JoinArgs) -> Result<ExitCode, CliError> {
    let cmd = "join";
    let as_json = args.json;

    if let Some(ref nid) = args.node_id {
        if nid == LOCAL_NODE_ID || !is_valid_node_id(nid) {
            return Err(CliError::usage("INVALID_NODE_ID", format!(
                    "Invalid --node-id '{nid}': must match /^[a-z0-9][a-z0-9@._-]{{0,63}}$/ and cannot be 'local'"
                )).with_fix("Example: --node-id philip@macbook".to_string()));
        }
    }
    if args.stdin && args.token_file.is_some() {
        return Err(CliError::usage(
            "CONFLICTING_FLAGS",
            "--stdin and --token-file are mutually exclusive",
        ));
    }

    let explicit_state = args.state_dir.is_some() || args.config.is_some() || args.home.is_some();
    let state_dir = resolve_state_dir(
        args.state_dir.as_deref(),
        args.config.as_deref(),
        args.home.as_deref(),
    );
    let config_read = resolve_config_path_for_read(
        args.config.as_deref(),
        args.state_dir.as_deref(),
        args.home.as_deref(),
    );
    let config_write = resolve_config_path_for_write(
        args.config.as_deref(),
        args.state_dir.as_deref(),
        args.home.as_deref(),
    );
    ensure_dir(&state_dir, true).map_err(|e| CliError::error("IO_ERROR", e))?;
    let secrets = open_secret_store(&state_dir, explicit_state);
    let already_onboarded = config_read.exists();
    let loaded = if already_onboarded {
        load_node_or_legacy_config(&config_read).ok()
    } else {
        None
    };

    // Mode 4: `--remote` (print public device card for laptop browser signing, then read bundle from stdin)
    if args.remote {
        let existing_db = if state_dir.join("node.sqlite").exists() {
            NodeDb::open(state_dir.join("node.sqlite")).ok()
        } else {
            None
        };
        let local_node_id = args
            .node_id
            .clone()
            .unwrap_or_else(|| resolve_effective_node_id(loaded.as_ref(), existing_db.as_ref()));
        drop(existing_db);
        let keys = match secrets.load_or_create_node_keys(&local_node_id) {
            Ok(k) => k,
            Err(e) => {
                return Err(CliError::error(
                    "KEYSTORE_ERROR",
                    format!("Failed to load/create device keys: {e}"),
                ));
            }
        };
        let card = RemoteDeviceCard {
            v: 1,
            node_id: local_node_id.clone(),
            hostname: short_hostname(),
            ed25519_jwk: keys.signing_jwk(),
            x25519_jwk: keys.encryption_jwk(),
            already_onboarded,
        };
        let card_json = match serde_json::to_string(&card) {
            Ok(s) => s,
            Err(e) => {
                return Err(CliError::error("ENCODE_ERROR", e.to_string()));
            }
        };
        if args.print_card {
            if as_json {
                let env = JsonEnvelope::ok(cmd.to_string(), format!("Public device card for '{local_node_id}'"), json!({ "deviceCard": card, "deviceCardJson": card_json })).next(vec![
                        "Paste deviceCardJson into https://hyphae.to/join (Safari / Remote VPS tab), sign with Passkey, then pipe the signed bundle into `hyp join --stdin`.".to_string(),
                    ]);
                print_json(&env);
            } else {
                println!("{card_json}");
            }
            return Ok(ExitCode::from(EXIT_OK));
        }

        // Emit card on stderr so user/agent can copy it, then read signed bundle on stdin.
        eprintln!(
            "Hyphae Remote Device Card (paste into https://hyphae.to/join -> Safari / Remote VPS):"
        );
        eprintln!("{card_json}");
        eprintln!("Waiting for signed handoff bundle JSON on stdin (paste then Ctrl-D)...");
        let _ = io::stderr().flush();

        let raw = read_bounded_stdin().map_err(|e| CliError::error("STDIN_ERROR", e))?;
        let bundle: JoinHandoffBundle = match serde_json::from_str(raw.trim()) {
            Ok(b) => b,
            Err(e) => {
                return Err(CliError::usage(
                    "INVALID_BUNDLE",
                    format!("Invalid signed handoff bundle JSON on stdin: {e}"),
                ));
            }
        };
        let validated = validate_handoff_bundle(&bundle, &local_node_id, &keys, already_onboarded)
            .map_err(|e| CliError::usage("INVALID_HANDOFF", e))?;
        return finalize_join(
            cmd,
            &args,
            &state_dir,
            &config_write,
            explicit_state,
            &secrets,
            &keys,
            validated,
        );
    }

    // Mode 2 & 3: `--stdin` or `--token-file <path>` (either signed handoff bundle OR raw hjoin1_ + --local-key)
    if args.stdin || args.token_file.is_some() {
        let raw = if let Some(ref path) = args.token_file {
            match read_bounded_file(path) {
                Ok(s) => s,
                Err(e) => return Err(CliError::error("IO_ERROR", e)),
            }
        } else {
            match read_bounded_stdin() {
                Ok(s) => s,
                Err(e) => return Err(CliError::error("STDIN_ERROR", e)),
            }
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(CliError::usage(
                "EMPTY_INPUT",
                "No invite token or signed handoff bundle received",
            ));
        }

        if trimmed.starts_with("hjoin1_") {
            if !args.local_key {
                return Err(CliError::usage("LOCAL_KEY_REQUIRED", "Raw hjoin1_ token requires --local-key for headless CLI join (or open the https://hyphae.to/join link in your browser and run `hyp join` for Passkey auth)").with_fix("Run `hyp join --token-file <path> --local-key` for headless servers/CI, or open the join URL in a browser and run `hyp join`.".to_string()));
            }
            return run_headless_local_key_join(
                cmd,
                &args,
                trimmed,
                &state_dir,
                &config_read,
                &config_write,
                explicit_state,
                already_onboarded,
                loaded.as_ref(),
                &secrets,
            );
        }

        let bundle: JoinHandoffBundle = match serde_json::from_str(trimmed) {
            Ok(b) => b,
            Err(e) => {
                return Err(CliError::usage(
                    "INVALID_BUNDLE",
                    format!(
                        "Input is neither an hjoin1_ token nor a valid signed handoff bundle JSON: {e}"
                    ),
                ));
            }
        };
        let existing_db = if state_dir.join("node.sqlite").exists() {
            NodeDb::open(state_dir.join("node.sqlite")).ok()
        } else {
            None
        };
        let local_node_id = resolve_join_node_id(
            args.node_id.as_deref(),
            loaded.as_ref(),
            existing_db.as_ref(),
            Some(&bundle.human_authority.human_id),
        );
        drop(existing_db);
        let keys = match secrets.load_or_create_node_keys(&local_node_id) {
            Ok(k) => k,
            Err(e) => {
                return Err(CliError::error(
                    "KEYSTORE_ERROR",
                    format!("Failed to load/create device keys: {e}"),
                ));
            }
        };
        let validated = validate_handoff_bundle(&bundle, &local_node_id, &keys, already_onboarded)
            .map_err(|e| CliError::usage("INVALID_HANDOFF", e))?;
        return finalize_join(
            cmd,
            &args,
            &state_dir,
            &config_write,
            explicit_state,
            &secrets,
            &keys,
            validated,
        );
    }

    // Mode 1: Default one-shot ephemeral loopback HTTP handoff server (`127.0.0.1:47891`)
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

    let existing_node_id = if already_onboarded {
        let db_opt = if state_dir.join("node.sqlite").exists() {
            NodeDb::open(state_dir.join("node.sqlite")).ok()
        } else {
            None
        };
        Some(resolve_effective_node_id(loaded.as_ref(), db_opt.as_ref()))
    } else {
        None
    };

    let (validated, device_keys) = match rt.block_on(run_loopback_join_server(
        &args,
        &state_dir,
        explicit_state,
        already_onboarded,
        existing_node_id,
    )) {
        Ok(pair) => pair,
        Err((code, msg)) => {
            return Err(CliError::error(code, msg).with_fix("Retry `hyp join`, or use the Safari / Remote VPS tab on https://hyphae.to/join with `hyp join --remote`.".to_string()));
        }
    };

    finalize_join(
        cmd,
        &args,
        &state_dir,
        &config_write,
        explicit_state,
        &secrets,
        &device_keys,
        validated,
    )
}

#[allow(clippy::too_many_arguments)]
fn run_headless_local_key_join(
    cmd: &str,
    args: &JoinArgs,
    hjoin1_raw: &str,
    state_dir: &Path,
    _config_read: &Path,
    config_write: &Path,
    explicit_state: bool,
    already_onboarded: bool,
    loaded: Option<&crate::config_file::LoadedNodeFile>,
    secrets: &SecretStore,
) -> Result<ExitCode, CliError> {
    let now = now_unix_ms();
    let signed_invite = match decode_hjoin1(hjoin1_raw) {
        Ok(s) => s,
        Err(e) => {
            return Err(CliError::usage(
                "INVALID_HJOIN1",
                format!("Invalid hjoin1_ token: {e}"),
            ));
        }
    };
    let (invite, _embedded_admin_pk) = match verify_human_invite_embedded(&signed_invite, now) {
        Ok(v) => v,
        Err(e) => {
            return Err(CliError::usage(
                "INVALID_HJOIN1",
                format!("hjoin1_ invite validation failed: {e}"),
            ));
        }
    };

    let existing_db = if state_dir.join("node.sqlite").exists() {
        NodeDb::open(state_dir.join("node.sqlite")).ok()
    } else {
        None
    };
    let local_node_id = resolve_join_node_id(
        args.node_id.as_deref(),
        loaded,
        existing_db.as_ref(),
        Some(&invite.human_id),
    );
    drop(existing_db);
    if !matches_node_prefix(&invite.node_prefix, &local_node_id) {
        return Err(CliError::usage(
            "NODE_PREFIX_MISMATCH",
            format!(
                "Local nodeId '{}' does not match invite allowed nodePrefix '{}'",
                local_node_id, invite.node_prefix
            ),
        )
        .with_fix(format!(
            "Pass --node-id {}@<device-name> matching '{}'",
            invite.human_id, invite.node_prefix
        )));
    }

    let device_keys = match secrets.load_or_create_node_keys(&local_node_id) {
        Ok(k) => k,
        Err(e) => {
            return Err(CliError::error(
                "KEYSTORE_ERROR",
                format!("Failed to load/create device keys: {e}"),
            ));
        }
    };

    // Load or create a local Ed25519 human keypair in SecretStore for headless CLI join.
    let human_kp = match Ed25519KeyPair::generate() {
        Ok(kp) => kp,
        Err(e) => {
            return Err(CliError::error(
                "KEYGEN_FAILED",
                format!("Failed to generate local Ed25519 human keypair: {e}"),
            ));
        }
    };
    let human_kid = human_kp.kid();
    let human_secret_name = admin_secret_name_for_kid(&human_kid);
    secrets
        .set(&human_secret_name, &human_kp.export_pkcs8_b64())
        .map_err(|e| {
            CliError::error(
                "KEYSTORE_ERROR",
                format!("Failed to persist local human key in SecretStore: {e}"),
            )
        })?;

    let claim = HumanInviteClaimV1 {
        invite_id: invite.invite_id.clone(),
        hub_node_id: invite.hub_node_id.clone(),
        human_id: invite.human_id.clone(),
        signing_jwk: human_kp.to_jwk(),
        enc_jwk: None,
        prf_salt: None,
        timestamp: format_rfc3339_millis(now),
    };
    let claim_sig = sign_human_invite_claim(&claim, &human_kp)
        .map_err(|e| CliError::error("SIGN_FAILED", e.to_string()))?;

    let cert_expires_ms = now + 365i64 * 86_400_000;
    let cert_payload = NodeCertPayloadV1 {
        v: 1,
        node_id: local_node_id.clone(),
        signing_jwk: device_keys.signing_jwk(),
        encryption_jwk: device_keys.encryption_jwk(),
        human_id: invite.human_id.clone(),
        human_kid: human_kid.clone(),
        auth_epoch: 1,
        issued_at: format_rfc3339_millis(now),
        expires_at: format_rfc3339_millis(cert_expires_ms),
    };
    let signed_cert = sign_node_cert(&cert_payload, &human_kp)
        .map_err(|e| CliError::error("SIGN_FAILED", e.to_string()))?;
    let hcert1 = match encode_hcert1(&signed_cert) {
        Ok(s) => s,
        Err(e) => {
            return Err(CliError::error("ENCODE_FAILED", e.to_string()));
        }
    };
    let human_jwk_json = match to_canonical_json(&human_kp.to_jwk()) {
        Ok(s) => s,
        Err(e) => {
            return Err(CliError::error("ENCODE_FAILED", e.to_string()));
        }
    };

    let validated = ValidatedHandoff {
        node_id: local_node_id,
        already_onboarded,
        human_id: invite.human_id.clone(),
        human_kid,
        human_signing_jwk_json: human_jwk_json,
        human_enc_jwk_json: None,
        human_prf_salt: None,
        human_label: "local-cli-delegated".to_string(),
        human_auth_epoch: 1,
        signed_cert,
        cert_payload,
        cert_issued_ms: now,
        cert_expires_ms,
        hcert1,
        hub_node_id: invite.hub_node_id,
        hub_endpoint: invite.hub_endpoint,
        hub_fingerprint: invite.hub_fingerprint,
        claim_request: Some(AuthClaimRequest {
            hjoin1: hjoin1_raw.to_string(),
            claim,
            claim_sig,
            label: Some("local-cli-delegated".to_string()),
        }),
    };

    finalize_join(
        cmd,
        args,
        state_dir,
        config_write,
        explicit_state,
        secrets,
        &device_keys,
        validated,
    )
}

// ============================================================================
// One-Shot Ephemeral Loopback Browser Handoff Server (`127.0.0.1:47891`)
// ============================================================================

type JoinHandoffResult = Result<(ValidatedHandoff, Arc<NodeIdentityKeys>), (&'static str, String)>;

struct LoopbackJoinState {
    code_digits: String,
    failed_attempts: AtomicUsize,
    state_dir: PathBuf,
    explicit_state: bool,
    already_onboarded: bool,
    explicit_node_id: Option<String>,
    existing_node_id: Option<String>,
    selected_device: Mutex<Option<(String, Arc<NodeIdentityKeys>)>>,
    done_tx: Mutex<Option<oneshot::Sender<JoinHandoffResult>>>,
}

fn generate_six_digit_code() -> Result<(String, String), String> {
    let mut bytes = [0u8; 4];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "OS CSPRNG failure".to_string())?;
    let val = u32::from_be_bytes(bytes) % 1_000_000;
    let digits = format!("{val:06}");
    let formatted = format!("{}-{}", &digits[0..3], &digits[3..6]);
    Ok((digits, formatted))
}

fn is_allowed_join_origin(origin: &str) -> bool {
    if origin == "https://hyphae.to" {
        return true;
    }
    if let Ok(extra) = std::env::var("HYPHAE_JOIN_PORTAL_ORIGIN") {
        let trimmed = extra.trim().trim_end_matches('/');
        if !trimmed.is_empty() && origin == trimmed {
            return true;
        }
    }
    if let Ok(uri) = origin.parse::<http::Uri>() {
        if uri.scheme_str() == Some("http") {
            if let Some(host) = uri.host() {
                if host == "127.0.0.1" || host == "localhost" {
                    return true;
                }
            }
        }
    }
    false
}

fn apply_join_cors(origin: Option<&str>, resp: &mut Response<Full<Bytes>>) {
    if let Some(orig) = origin {
        if is_allowed_join_origin(orig) {
            if let Ok(hdr_val) = HeaderValue::from_str(orig) {
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

fn json_join_response(
    status: StatusCode,
    origin: Option<&str>,
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
    apply_join_cors(origin, &mut resp);
    resp
}

fn html_join_response(status: StatusCode, html: String) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store")
        .header(header::CONNECTION, "close")
        .body(Full::new(Bytes::from(html.into_bytes())))
        .expect("valid HTML response")
}

async fn run_loopback_join_server(
    args: &JoinArgs,
    state_dir: &Path,
    explicit_state: bool,
    already_onboarded: bool,
    existing_node_id: Option<String>,
) -> Result<(ValidatedHandoff, Arc<NodeIdentityKeys>), (&'static str, String)> {
    let (code_digits, code_formatted) =
        generate_six_digit_code().map_err(|e| ("CSPRNG_ERROR", e))?;

    let listener = match args.port {
        Some(p) => TcpListener::bind(("127.0.0.1", p))
            .await
            .map_err(|e| ("BIND_FAILED", format!("Failed to bind 127.0.0.1:{p}: {e}")))?,
        None => match TcpListener::bind(("127.0.0.1", DEFAULT_JOIN_LOOPBACK_PORT)).await {
            Ok(l) => l,
            Err(_) => TcpListener::bind(("127.0.0.1", 0)).await.map_err(|e| {
                (
                    "BIND_FAILED",
                    format!("Failed to bind ephemeral loopback port: {e}"),
                )
            })?,
        },
    };
    let local_addr = listener.local_addr().map_err(|e| {
        (
            "BIND_FAILED",
            format!("Failed to inspect local address: {e}"),
        )
    })?;
    let listen_url = format!("http://127.0.0.1:{}", local_addr.port());

    let (done_tx, mut done_rx) = oneshot::channel::<
        Result<(ValidatedHandoff, Arc<NodeIdentityKeys>), (&'static str, String)>,
    >();
    let state = Arc::new(LoopbackJoinState {
        code_digits,
        failed_attempts: AtomicUsize::new(0),
        state_dir: state_dir.to_path_buf(),
        explicit_state,
        already_onboarded,
        explicit_node_id: args.node_id.clone(),
        existing_node_id,
        selected_device: Mutex::new(None),
        done_tx: Mutex::new(Some(done_tx)),
    });

    if args.json {
        // Emit machine-readable listening details immediately on stderr so agents/tests can
        // read the port + 6-digit code while keeping stdout strictly clean for the final JsonEnvelope!
        let listening_event = json!({
            "ok": true,
            "status": "listening",
            "listenUrl": listen_url,
            "port": local_addr.port(),
            "code": code_formatted,
            "timeoutSecs": args.timeout,
        });
        eprintln!("{listening_event}");
        let _ = io::stderr().flush();
    } else {
        println!();
        println!("  Hyphae Join — Waiting for Browser Passkey Approval");
        println!("  ──────────────────────────────────────────────────");
        println!("  Listen URL:         {listen_url}");
        println!("  Confirmation Code:  {code_formatted}");
        println!("  Timeout:            {}s", args.timeout);
        println!();
        println!("  Open your https://hyphae.to/join invite link in your browser,");
        println!("  authenticate with Touch ID / Passkey, and enter: {code_formatted}");
        if local_addr.port() != DEFAULT_JOIN_LOOPBACK_PORT {
            println!(
                "  (Note: default port {} was busy; enter custom port {} in the browser.)",
                DEFAULT_JOIN_LOOPBACK_PORT,
                local_addr.port()
            );
        }
        println!();
        let _ = io::stdout().flush();
    }

    let timeout = tokio::time::sleep(Duration::from_secs(args.timeout.max(1)));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            res = &mut done_rx => {
                // Brief grace period so the 200 OK / 429 response flushes to the browser cleanly.
                tokio::time::sleep(Duration::from_millis(40)).await;
                return res.map_err(|_| ("CHANNEL_CLOSED", "Join handoff channel closed unexpectedly".to_string()))?;
            }
            _ = &mut timeout => {
                return Err((
                    "JOIN_TIMEOUT",
                    format!("Timed out after {}s waiting for browser confirmation on {listen_url}", args.timeout),
                ));
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
                        async move { Ok::<_, Infallible>(handle_join_http_request(st, req).await) }
                    });
                    let _ = AutoServerBuilder::new(TokioExecutor::new())
                        .serve_connection(io, svc)
                        .await;
                });
            }
        }
    }
}

async fn handle_join_http_request(
    state: Arc<LoopbackJoinState>,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    // Fail closed on any explicitly supplied disallowed Origin header!
    if let Some(ref orig) = origin {
        if !is_allowed_join_origin(orig) {
            return json_join_response(
                StatusCode::FORBIDDEN,
                None,
                json!({ "ok": false, "error": "origin_not_allowed" }),
            );
        }
    }

    let path = req.uri().path().to_string();
    let method = req.method().clone();

    if method == Method::OPTIONS {
        let mut resp = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .header(header::ACCESS_CONTROL_ALLOW_METHODS, "GET, POST, OPTIONS")
            .header(
                header::ACCESS_CONTROL_ALLOW_HEADERS,
                "Content-Type, X-Hyphae-Join-Code",
            )
            .header(header::ACCESS_CONTROL_MAX_AGE, "600")
            .header(header::CONNECTION, "close")
            .body(Full::new(Bytes::new()))
            .expect("valid preflight response");
        apply_join_cors(origin.as_deref(), &mut resp);
        return resp;
    }

    // `GET /health` — zero sensitive info!
    if method == Method::GET && path == "/health" {
        return json_join_response(
            StatusCode::OK,
            origin.as_deref(),
            json!({
                "ok": true,
                "mode": "hyphae-join",
                "requiresCode": true,
            }),
        );
    }

    if method != Method::POST || (path != "/device-info" && path != "/complete") {
        return json_join_response(
            StatusCode::NOT_FOUND,
            origin.as_deref(),
            json!({ "ok": false, "error": "not_found" }),
        );
    }

    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_ascii_lowercase();
    let is_form = content_type.starts_with("application/x-www-form-urlencoded");
    let header_code = req
        .headers()
        .get("x-hyphae-join-code")
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);

    let body_bytes = match read_hyper_body_bounded(req.into_body(), MAX_JOIN_BODY_BYTES).await {
        Ok(b) => b,
        Err(status) => {
            return json_join_response(
                status,
                origin.as_deref(),
                json!({ "ok": false, "error": "body_error" }),
            );
        }
    };

    // Extract code + JSON body (supporting both JSON and Safari form-encoded POST on `/complete`).
    let (submitted_code, json_payload_bytes) = if is_form && path == "/complete" {
        let form = parse_form_urlencoded(&body_bytes);
        let code = header_code.or_else(|| form.get("code").cloned());
        let payload = form
            .get("payload")
            .map(|s| s.as_bytes().to_vec())
            .unwrap_or_default();
        (code, payload)
    } else {
        (header_code, body_bytes)
    };

    // Constant-time 6-digit code check with strict 5-attempt fail-closed lockout!
    if let Some(resp) = verify_join_code(
        &state,
        submitted_code.as_deref(),
        origin.as_deref(),
        is_form,
    ) {
        return resp;
    }

    if path == "/device-info" {
        let req_val: Value = if json_payload_bytes.is_empty() {
            json!({})
        } else {
            serde_json::from_slice(&json_payload_bytes).unwrap_or_else(|_| json!({}))
        };
        let requested_human = req_val
            .get("humanId")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty());

        let (node_id, keys) = match resolve_or_pin_loopback_device(&state, requested_human) {
            Ok(pair) => pair,
            Err(e) => {
                return json_join_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    origin.as_deref(),
                    json!({ "ok": false, "error": "device_key_error", "message": e }),
                );
            }
        };

        return json_join_response(
            StatusCode::OK,
            origin.as_deref(),
            json!({
                "ok": true,
                "nodeId": node_id,
                "hostname": short_hostname(),
                "ed25519Jwk": keys.signing_jwk(),
                "x25519Jwk": keys.encryption_jwk(),
                "alreadyOnboarded": state.already_onboarded,
            }),
        );
    }

    // `POST /complete`
    let bundle: JoinHandoffBundle = match serde_json::from_slice(&json_payload_bytes) {
        Ok(b) => b,
        Err(e) => {
            let msg = format!("Invalid handoff bundle JSON: {e}");
            return if is_form {
                html_join_response(
                    StatusCode::BAD_REQUEST,
                    format!(
                        "<!doctype html><html><body><h1>Join Failed</h1><p>{msg}</p></body></html>"
                    ),
                )
            } else {
                json_join_response(
                    StatusCode::BAD_REQUEST,
                    origin.as_deref(),
                    json!({ "ok": false, "error": "invalid_json", "message": msg }),
                )
            };
        }
    };

    let (node_id, keys) =
        match resolve_or_pin_loopback_device(&state, Some(&bundle.human_authority.human_id)) {
            Ok(pair) => pair,
            Err(e) => {
                return json_join_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    origin.as_deref(),
                    json!({ "ok": false, "error": "device_key_error", "message": e }),
                );
            }
        };

    let validated = match validate_handoff_bundle(&bundle, &node_id, &keys, state.already_onboarded)
    {
        Ok(v) => v,
        Err(e) => {
            return if is_form {
                html_join_response(
                    StatusCode::BAD_REQUEST,
                    format!(
                        "<!doctype html><html><body><h1>Verification Failed</h1><p>{e}</p></body></html>"
                    ),
                )
            } else {
                json_join_response(
                    StatusCode::BAD_REQUEST,
                    origin.as_deref(),
                    json!({ "ok": false, "error": "invalid_handoff", "message": e }),
                )
            };
        }
    };

    let resp_node_id = validated.node_id.clone();
    let resp_hub_id = validated.hub_node_id.clone();
    let resp_human_id = validated.human_id.clone();

    if let Ok(mut guard) = state.done_tx.lock() {
        if let Some(tx) = guard.take() {
            let _ = tx.send(Ok((validated, keys)));
        }
    }

    if is_form {
        html_join_response(
            StatusCode::OK,
            format!(
                "<!doctype html><html><body style=\"font-family:system-ui;background:#0f120d;color:#f4f1e8;padding:40px\"><h1>Approved!</h1><p>Device <code>{resp_node_id}</code> received your signed Passkey handoff for hub <code>{resp_hub_id}</code>. Return to your terminal — you can close this tab.</p></body></html>"
            ),
        )
    } else {
        json_join_response(
            StatusCode::OK,
            origin.as_deref(),
            json!({
                "ok": true,
                "nodeId": resp_node_id,
                "hubNodeId": resp_hub_id,
                "humanId": resp_human_id,
            }),
        )
    }
}

fn verify_join_code(
    state: &LoopbackJoinState,
    submitted: Option<&str>,
    origin: Option<&str>,
    is_form: bool,
) -> Option<Response<Full<Bytes>>> {
    let normalized: String = submitted
        .unwrap_or("")
        .chars()
        .filter(|c| c.is_ascii_digit())
        .collect();
    if normalized.len() == 6 && ct_eq(normalized.as_bytes(), state.code_digits.as_bytes()) {
        return None;
    }

    let attempts = state.failed_attempts.fetch_add(1, Ordering::AcqRel) + 1;
    if attempts >= MAX_JOIN_CODE_ATTEMPTS {
        if let Ok(mut guard) = state.done_tx.lock() {
            if let Some(tx) = guard.take() {
                let _ = tx.send(Err((
                    "CODE_LOCKED_OUT",
                    format!(
                        "Refused join after {MAX_JOIN_CODE_ATTEMPTS} invalid confirmation code attempts (fail-closed)"
                    ),
                )));
            }
        }
        return Some(if is_form {
            html_join_response(
                StatusCode::TOO_MANY_REQUESTS,
                "<!doctype html><html><body><h1>Locked Out</h1><p>Too many invalid confirmation code attempts. Restart <code>hyp join</code>.</p></body></html>".to_string(),
            )
        } else {
            json_join_response(
                StatusCode::TOO_MANY_REQUESTS,
                origin,
                json!({
                    "ok": false,
                    "error": "code_attempts_exceeded",
                    "attemptsRemaining": 0,
                }),
            )
        });
    }

    let remaining = MAX_JOIN_CODE_ATTEMPTS.saturating_sub(attempts);
    Some(if is_form {
        html_join_response(
            StatusCode::FORBIDDEN,
            format!(
                "<!doctype html><html><body><h1>Invalid Code</h1><p>Confirmation code did not match ({remaining} attempt(s) remaining).</p></body></html>"
            ),
        )
    } else {
        json_join_response(
            StatusCode::FORBIDDEN,
            origin,
            json!({
                "ok": false,
                "error": "invalid_code",
                "attemptsRemaining": remaining,
            }),
        )
    })
}

fn resolve_or_pin_loopback_device(
    state: &LoopbackJoinState,
    human_id_hint: Option<&str>,
) -> Result<(String, Arc<NodeIdentityKeys>), String> {
    let mut guard = state
        .selected_device
        .lock()
        .map_err(|_| "device state lock poisoned".to_string())?;
    if let Some((ref nid, ref keys)) = *guard {
        return Ok((nid.clone(), Arc::clone(keys)));
    }
    let node_id = if let Some(ref explicit) = state.explicit_node_id {
        explicit.clone()
    } else if let Some(ref existing) = state.existing_node_id {
        existing.clone()
    } else if let Some(hid) = human_id_hint {
        propose_node_id_for_human(hid)
    } else {
        default_node_id()
    };
    let secrets = open_secret_store(&state.state_dir, state.explicit_state);
    let keys = Arc::new(
        secrets
            .load_or_create_node_keys(&node_id)
            .map_err(|e| format!("failed to load/create device keys for '{node_id}': {e}"))?,
    );
    *guard = Some((node_id.clone(), Arc::clone(&keys)));
    Ok((node_id, keys))
}

fn validate_handoff_bundle(
    bundle: &JoinHandoffBundle,
    expected_node_id: &str,
    local_keys: &NodeIdentityKeys,
    already_onboarded: bool,
) -> Result<ValidatedHandoff, String> {
    let now = now_unix_ms();
    let human_id = bundle.human_authority.human_id.trim().to_ascii_lowercase();
    if human_id == LOCAL_NODE_ID || !is_valid_node_id(&human_id) {
        return Err(format!("invalid humanAuthority.humanId '{human_id}'"));
    }
    let human_pk = bundle
        .human_authority
        .signing_jwk
        .to_ed25519()
        .map_err(|e| format!("invalid humanAuthority.signingJwk: {e}"))?;
    let human_kid = human_pk.kid();
    let human_signing_jwk_json = to_canonical_json(&bundle.human_authority.signing_jwk)
        .map_err(|e| format!("failed to canonicalize human signingJwk: {e}"))?;
    let human_enc_jwk_json = match &bundle.human_authority.enc_jwk {
        Some(ej) => {
            let _ = ej
                .to_x25519()
                .map_err(|e| format!("invalid humanAuthority.encJwk: {e}"))?;
            Some(
                to_canonical_json(ej)
                    .map_err(|e| format!("failed to canonicalize human encJwk: {e}"))?,
            )
        }
        None => None,
    };
    let human_auth_epoch = bundle.human_authority.auth_epoch.unwrap_or(1).max(1);
    let human_label = bundle
        .human_authority
        .label
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 128 && !s.chars().any(char::is_control))
        .unwrap_or("passkey-delegated")
        .to_string();

    // Verify NodeCertV1 (`hcert1_`) against human's Ed25519 key AND local device keys!
    let hcert1 = bundle.node_cert.trim().to_string();
    let signed_cert =
        decode_hcert1(&hcert1).map_err(|e| format!("invalid hcert1_ nodeCert: {e}"))?;
    let cert_payload = verify_node_cert(&signed_cert, &human_pk, now, 1)
        .map_err(|e| format!("nodeCert signature/validity check failed: {e}"))?;
    if cert_payload.human_id != human_id {
        return Err(format!(
            "nodeCert humanId '{}' does not match humanAuthority '{}'",
            cert_payload.human_id, human_id
        ));
    }
    if cert_payload.node_id != expected_node_id {
        return Err(format!(
            "nodeCert nodeId '{}' does not match this device's nodeId '{expected_node_id}'",
            cert_payload.node_id
        ));
    }
    if cert_payload.signing_jwk.x != local_keys.signing_jwk().x {
        return Err("nodeCert signingJwk does not match this device's Ed25519 key".to_string());
    }
    if cert_payload.encryption_jwk.x != local_keys.encryption_jwk().x {
        return Err("nodeCert encryptionJwk does not match this device's X25519 key".to_string());
    }
    let cert_issued_ms = parse_rfc3339_millis(&cert_payload.issued_at)
        .map_err(|e| format!("invalid nodeCert issuedAt: {e}"))?;
    let cert_expires_ms = parse_rfc3339_millis(&cert_payload.expires_at)
        .map_err(|e| format!("invalid nodeCert expiresAt: {e}"))?;

    // If `hjoin1` is included, verify both the invite and the human's signed claim!
    let (hub_node_id, hub_endpoint, hub_fingerprint, claim_request) = if let Some(raw_hjoin1) =
        bundle
            .hjoin1
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
    {
        let signed_invite =
            decode_hjoin1(raw_hjoin1).map_err(|e| format!("invalid hjoin1_ token: {e}"))?;
        let (invite, _admin_pk) = verify_human_invite_embedded(&signed_invite, now)
            .map_err(|e| format!("hjoin1_ invite verification failed: {e}"))?;
        if invite.human_id != human_id {
            return Err(format!(
                "hjoin1_ humanId '{}' does not match humanAuthority '{human_id}'",
                invite.human_id
            ));
        }
        if !matches_node_prefix(&invite.node_prefix, expected_node_id) {
            return Err(format!(
                "device nodeId '{expected_node_id}' does not match invite nodePrefix '{}'",
                invite.node_prefix
            ));
        }
        let claim = bundle
            .human_claim
            .clone()
            .ok_or_else(|| "missing humanClaim for hjoin1_ invite".to_string())?;
        let claim_sig = bundle
            .human_claim_sig
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "missing humanClaimSig for hjoin1_ invite".to_string())?
            .to_string();
        let (claim_pk, _) = verify_human_invite_claim(&claim, &claim_sig, now)
            .map_err(|e| format!("humanClaimSig verification failed: {e}"))?;
        if claim_pk != human_pk {
            return Err(
                "humanClaim signingJwk does not match humanAuthority signingJwk".to_string(),
            );
        }
        if claim.invite_id != invite.invite_id
            || claim.hub_node_id != invite.hub_node_id
            || claim.human_id != invite.human_id
        {
            return Err("humanClaim fields do not match hjoin1_ invite".to_string());
        }
        (
            invite.hub_node_id,
            invite.hub_endpoint,
            invite.hub_fingerprint,
            Some(AuthClaimRequest {
                hjoin1: raw_hjoin1.to_string(),
                claim,
                claim_sig,
                label: Some(human_label.clone()),
            }),
        )
    } else {
        let ep = bundle
            .hub_endpoint
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| "bundle must provide hubEndpoint when hjoin1 is omitted".to_string())?
            .trim_end_matches('/')
            .to_string();
        validate_endpoint_origin(&ep).map_err(|e| format!("invalid hubEndpoint '{ep}': {e}"))?;
        let hub_id = bundle
            .hub_node_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty() && *s != LOCAL_NODE_ID && is_valid_node_id(s))
            .ok_or_else(|| {
                "bundle must provide valid hubNodeId when hjoin1 is omitted".to_string()
            })?
            .to_string();
        (hub_id, ep, bundle.hub_fingerprint.clone(), None)
    };

    Ok(ValidatedHandoff {
        node_id: expected_node_id.to_string(),
        already_onboarded,
        human_id,
        human_kid,
        human_signing_jwk_json,
        human_enc_jwk_json,
        human_prf_salt: bundle.human_authority.prf_salt.clone(),
        human_label,
        human_auth_epoch: cert_payload.auth_epoch.max(human_auth_epoch),
        signed_cert,
        cert_payload,
        cert_issued_ms,
        cert_expires_ms,
        hcert1,
        hub_node_id,
        hub_endpoint,
        hub_fingerprint,
        claim_request,
    })
}

#[allow(clippy::too_many_arguments)]
fn finalize_join(
    cmd: &str,
    args: &JoinArgs,
    state_dir: &Path,
    config_write: &Path,
    explicit_state: bool,
    secrets: &SecretStore,
    device_keys: &NodeIdentityKeys,
    validated: ValidatedHandoff,
) -> Result<ExitCode, CliError> {
    let as_json = args.json;
    let mut warnings: Vec<String> = Vec::new();
    let now_db = now_ms();

    // 1. Streamlined auto-onboarding when `node.json` does not exist yet.
    let mut configured_harnesses: Vec<String> = Vec::new();
    if !validated.already_onboarded {
        let mut cfg_map = NodeFile::read_document_or_empty(config_write).unwrap_or_default();
        cfg_map.insert("v".to_string(), json!(2));
        cfg_map.insert("nodeId".to_string(), json!(validated.node_id));
        cfg_map.insert("profile".to_string(), json!("local"));
        cfg_map.insert(
            "stateDir".to_string(),
            json!(state_dir.display().to_string()),
        );
        ensure_v2_node_json_defaults(
            &mut cfg_map,
            &validated.node_id,
            NodeProfile::Local,
            state_dir,
        );
        NodeFile::write_document(config_write, cfg_map).map_err(|e| {
            CliError::error(
                "CONFIG_WRITE_ERROR",
                format!("Failed to write {}: {e}", config_write.display()),
            )
        })?;
        if !args.no_setup {
            if let Some(home) = resolve_home_dir(args.home.as_deref()) {
                configured_harnesses = configure_detected_harnesses_for_join(
                    &home,
                    args.home.is_some(),
                    state_dir,
                    config_write,
                    &mut warnings,
                );
            }
        }
    }

    // 2. Persist local Human Authority + `hcert1_` NodeCert in local `node.sqlite`.
    let db_path = state_dir.join("node.sqlite");
    let db = match NodeDb::open(&db_path) {
        Ok(d) => d,
        Err(e) => {
            return Err(CliError::error(
                "DB_ERROR",
                format!("Failed to open {}: {e}", db_path.display()),
            ));
        }
    };
    let _ = db.local().ensure_metadata("node_id", &validated.node_id);

    match db.human().requires_live_approval() {
        Ok(false) => {}
        Ok(true) => {
            return Err(CliError::error(
                "PASSKEY_APPROVAL_REQUIRED",
                "Joining cannot mutate an existing Passkey-managed authority store; use live hyp auth add.",
            ));
        }
        Err(e) => return Err(CliError::error("DB_ERROR", e.to_string())),
    }
    if let Err(e) = db.human().bootstrap_authority(
        &HumanAuthorityInput {
            human_id: validated.human_id.clone(),
            kid: validated.human_kid.clone(),
            label: validated.human_label.clone(),
            role: HumanAuthorityRole::Signer,
            jwk_json: validated.human_signing_jwk_json.clone(),
            enc_jwk_json: validated.human_enc_jwk_json.clone(),
            prf_salt: validated.human_prf_salt.clone(),
            auth_epoch: validated.human_auth_epoch,
        },
        now_db,
    ) {
        return Err(CliError::error(
            "DB_ERROR",
            format!("Failed to persist local human authority: {e}"),
        ));
    }

    let signed_cert_json = match to_canonical_json(&validated.signed_cert) {
        Ok(s) => s,
        Err(e) => {
            return Err(CliError::error("ENCODE_ERROR", e.to_string()));
        }
    };
    if let Err(e) = db.human().put_node_cert(&HumanNodeCertInput {
        node_id: validated.node_id.clone(),
        human_kid: validated.cert_payload.human_kid.clone(),
        auth_epoch: validated.cert_payload.auth_epoch,
        signed_json: signed_cert_json,
        issued_at: validated.cert_issued_ms,
        expires_at: validated.cert_expires_ms,
    }) {
        return Err(CliError::error(
            "DB_ERROR",
            format!("Failed to persist local hcert1_ NodeCert: {e}"),
        ));
    }

    if inspect_policy_integrity(config_write, state_dir, secrets).approved {
        warnings.push(
            "Security Gate is Passkey-locked; run `hyp gate apply` to approve & re-seal the gate with the updated human_authorities_digest."
                .to_string(),
        );
    }

    // 3. Call `POST <hub>/v1/auth/claim` natively over HTTPS/Tailscale if `hjoin1_` was supplied.
    let mut claim_reply: Option<AuthClaimReply> = None;
    if let Some(ref claim_req) = validated.claim_request {
        match post_auth_claim(&validated.hub_endpoint, claim_req) {
            Ok(reply) => {
                claim_reply = Some(reply);
            }
            Err((code, msg)) => {
                return Err(CliError::error(code, msg).with_fix("Verify the hub is reachable and this single-use hjoin1_ invite has not expired or been claimed already.".to_string()));
            }
        }
    }

    // 4. Call `POST <hub>/v1/pair/delegated` with live device Ed25519 possession proof!
    let delegated = match attempt_delegated_pair_enroll(
        &validated.hub_endpoint,
        &validated.hub_node_id,
        None,
        validated.hub_fingerprint.as_deref(),
        &validated.node_id,
        device_keys,
        &validated.hcert1,
    ) {
        Ok(d) => d,
        Err((_status, code, msg)) => {
            return Err(CliError::error(code, msg).with_fix("Verify your nodeId matches the hub's allowed nodePrefix and your device limit has not been exceeded.".to_string()));
        }
    };

    // 5. Persist hub bearer credential in SecretStore, pin hub keys, and cache verified manifest!
    let cred_ref = credential_secret_name("peer-auth", &delegated.hub_node_id);
    secrets
        .set(&cred_ref, &delegated.auth_credential)
        .map_err(|e| {
            CliError::error(
                "KEYSTORE_ERROR",
                format!("Failed to store hub authCredential in SecretStore: {e}"),
            )
        })?;

    if let Err(e) = db.peers().upsert_peer(
        &PeerInput {
            peer_id: delegated.hub_node_id.clone(),
            endpoint: Some(validated.hub_endpoint.clone()),
            profile: PeerProfile::Router,
            trust_tier: StoreTrustTier::Org,
            status: PeerStatus::Active,
            scopes: delegated.scopes.clone(),
            auth_credential_ref: Some(cred_ref),
        },
        now_db,
    ) {
        return Err(CliError::error(
            "DB_ERROR",
            format!(
                "Failed to register hub peer '{}': {e}",
                delegated.hub_node_id
            ),
        ));
    }

    let hub_sign_jwk = OkpJwk::from(&delegated.manifest_payload.identity.signing_jwk);
    let hub_enc_jwk = OkpJwk::from(&delegated.manifest_payload.identity.encryption_jwk);
    let hub_sign_kid = hub_sign_jwk.thumbprint().unwrap_or_default();
    let hub_enc_kid = hub_enc_jwk.thumbprint().unwrap_or_default();
    if let (Ok(sign_json), Ok(enc_json)) = (
        serde_json::to_string(&hub_sign_jwk),
        serde_json::to_string(&hub_enc_jwk),
    ) {
        let _ = db.peers().rotate_peer_key(
            &PeerKeyInput {
                peer_id: delegated.hub_node_id.clone(),
                kid: hub_sign_kid,
                key_use: KeyUse::Signing,
                jwk_json: sign_json,
                status: KeyStatus::Active,
                expires_at: None,
            },
            now_db,
        );
        let _ = db.peers().rotate_peer_key(
            &PeerKeyInput {
                peer_id: delegated.hub_node_id.clone(),
                kid: hub_enc_kid,
                key_use: KeyUse::Encryption,
                jwk_json: enc_json,
                status: KeyStatus::Active,
                expires_at: None,
            },
            now_db,
        );
    }

    let caps: Vec<String> = delegated
        .manifest_payload
        .capabilities
        .iter()
        .map(|c| c.as_str().to_string())
        .collect();
    if let Ok(manifest_json) = serde_json::to_string(&delegated.manifest) {
        if let Err(e) = db.peers().cache_manifest(
            &delegated.hub_node_id,
            &ManifestCacheUpdate {
                manifest_version: delegated.manifest_payload.manifest_version as i64,
                manifest_json,
                etag: None,
                capabilities: caps,
                accept_downgrade: false,
            },
            now_db,
        ) {
            return Err(CliError::error(
                "MANIFEST_CACHE_ERROR",
                format!("Failed to cache hub manifest: {e}"),
            ));
        }
    }

    let peers: Vec<String> = db
        .peers()
        .list_peers(Some(PeerStatus::Active))
        .unwrap_or_default()
        .into_iter()
        .map(|p| p.peer_id)
        .collect();
    drop(db);

    // 6. Hot-reload local daemon if running.
    let daemon_reloaded = if args.no_start {
        false
    } else {
        let reload = try_reload_live_daemon(state_dir, explicit_state);
        warnings.extend(reload.warnings);
        reload.reloaded
    };

    let next = if daemon_reloaded {
        vec![format!("hyp status --state-dir {}", state_dir.display())]
    } else {
        vec![
            "hyp service start".to_string(),
            format!("hyp status --state-dir {}", state_dir.display()),
        ]
    };

    if as_json {
        let envelope = JsonEnvelope::ok(
            cmd.to_string(),
            format!(
                "Joined hub '{}' as '{}' via human:{} (ep {})",
                delegated.hub_node_id, validated.node_id, delegated.human_id, delegated.auth_epoch
            ),
            json!({
                "nodeId": validated.node_id,
                "hubNodeId": delegated.hub_node_id,
                "hubEndpoint": validated.hub_endpoint,
                "humanId": delegated.human_id,
                "humanKid": validated.human_kid,
                "authEpoch": delegated.auth_epoch,
                "scopes": delegated.scopes,
                "claimedInvite": claim_reply.is_some(),
                "peers": peers,
                "harnesses": configured_harnesses,
                "alreadyOnboarded": validated.already_onboarded,
                "daemonReloaded": daemon_reloaded,
                "stateDir": state_dir.display().to_string(),
            }),
        )
        .warnings(warnings)
        .next(next);
        print_json(&envelope);
    } else {
        println!(
            "OK    Joined hub '{}' as '{}'",
            delegated.hub_node_id, validated.node_id
        );
        println!("      Endpoint:   {}", validated.hub_endpoint);
        println!(
            "      Authority:  human:{} (ep {}, kid={})",
            delegated.human_id, delegated.auth_epoch, validated.human_kid
        );
        println!("      Scopes:     {}", delegated.scopes.join(" "));
        if !configured_harnesses.is_empty() {
            println!("      Harnesses:  {}", configured_harnesses.join(", "));
        }
        if daemon_reloaded {
            println!("      Daemon:     reloaded live daemon (connected immediately)");
        }
        print_warnings(&warnings);
        print_next_steps(&next);
    }
    Ok(ExitCode::from(EXIT_OK))
}

fn post_auth_claim(
    hub_endpoint: &str,
    claim_req: &AuthClaimRequest,
) -> Result<AuthClaimReply, (&'static str, String)> {
    let url = format!("{}/v1/auth/claim", hub_endpoint.trim_end_matches('/'));
    let uri: http::Uri = url.parse().map_err(|e| {
        (
            "INVALID_ENDPOINT",
            format!("Invalid auth claim URI '{url}': {e}"),
        )
    })?;
    let body_bytes = serde_json::to_vec(claim_req).map_err(|e| {
        (
            "ENCODE_ERROR",
            format!("Failed to serialize auth claim: {e}"),
        )
    })?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            (
                "RUNTIME_ERROR",
                format!("Failed to start async runtime: {e}"),
            )
        })?;

    let (status, resp_bytes) = rt.block_on(async {
        let client = build_http_client::<Full<Bytes>>().map_err(|e| {
            (
                "HTTP_ERROR",
                format!("Failed to initialize HTTP client: {e}"),
            )
        })?;
        let req = Request::builder()
            .method(Method::POST)
            .uri(&uri)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .header(
                header::USER_AGENT,
                format!("hyp/{}", env!("CARGO_PKG_VERSION")),
            )
            .body(Full::new(Bytes::from(body_bytes)))
            .map_err(|e| ("HTTP_ERROR", format!("Failed to build claim request: {e}")))?;

        let resp =
            tokio::time::timeout(Duration::from_secs(HTTP_TIMEOUT_SECS), client.request(req))
                .await
                .map_err(|_| {
                    (
                        "CLAIM_TIMEOUT",
                        format!("POST {url} timed out after {HTTP_TIMEOUT_SECS}s"),
                    )
                })?
                .map_err(|e| ("CLAIM_FAILED", format!("POST {url} failed: {e}")))?;

        let status = resp.status().as_u16();
        let bytes = read_hyper_body_bounded(resp.into_body(), MAX_HTTP_RESP_BYTES)
            .await
            .map_err(|_| {
                (
                    "CLAIM_FAILED",
                    format!("Failed to read response from {url}"),
                )
            })?;
        Ok::<(u16, Vec<u8>), (&'static str, String)>((status, bytes))
    })?;

    if status != 200 {
        if let Ok(problem) = serde_json::from_slice::<ProblemDetails>(&resp_bytes) {
            let code = match (status, problem.error.as_str()) {
                (_, "human_key_mismatch") => "HUMAN_KEY_MISMATCH",
                (409, _) => "INVITE_REPLAY_OR_CONFLICT",
                (401, _) | (403, _) => "CLAIM_UNAUTHORIZED",
                _ => "CLAIM_FAILED",
            };
            let detail = problem
                .detail
                .unwrap_or_else(|| format!("{} (HTTP {status})", problem.title));
            return Err((
                code,
                format!("POST {url} rejected ({}): {detail}", problem.error),
            ));
        }
        let snippet: String = String::from_utf8_lossy(&resp_bytes)
            .chars()
            .take(200)
            .collect();
        return Err((
            "CLAIM_FAILED",
            format!("POST {url} returned HTTP {status}: {snippet}"),
        ));
    }

    let reply: AuthClaimReply = serde_json::from_slice(&resp_bytes).map_err(|e| {
        (
            "CLAIM_INVALID",
            format!("Invalid AuthClaimReply JSON from {url}: {e}"),
        )
    })?;
    if !reply.ok {
        return Err(("CLAIM_REJECTED", format!("Hub returned ok=false on {url}")));
    }
    Ok(reply)
}

async fn read_hyper_body_bounded(body: Incoming, limit: usize) -> Result<Vec<u8>, StatusCode> {
    let mut out = Vec::new();
    consume_bounded_body(body, limit, |chunk| out.extend_from_slice(chunk))
        .await
        .map_err(|error| match error {
            BoundedBodyError::Read(_) => StatusCode::BAD_REQUEST,
            BoundedBodyError::TooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        })?;
    Ok(out)
}

fn parse_form_urlencoded(body: &[u8]) -> std::collections::HashMap<String, String> {
    let raw = String::from_utf8_lossy(body);
    let mut map = std::collections::HashMap::new();
    for pair in raw.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        map.insert(percent_decode_form(k), percent_decode_form(v));
    }
    map
}

fn percent_decode_form(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' if i + 2 < bytes.len() => {
                let hi = (bytes[i + 1] as char).to_digit(16);
                let lo = (bytes[i + 2] as char).to_digit(16);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push(((h << 4) | l) as u8);
                    i += 3;
                } else {
                    out.push(bytes[i]);
                    i += 1;
                }
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn read_bounded_stdin() -> Result<String, String> {
    let mut buf = String::new();
    io::stdin()
        .lock()
        .take((MAX_JOIN_BODY_BYTES + 1) as u64)
        .read_to_string(&mut buf)
        .map_err(|e| format!("failed to read stdin: {e}"))?;
    if buf.len() > MAX_JOIN_BODY_BYTES {
        return Err(format!(
            "stdin input exceeds {MAX_JOIN_BODY_BYTES} byte cap"
        ));
    }
    Ok(buf)
}

fn read_bounded_file(path: &Path) -> Result<String, String> {
    let meta = fs::metadata(path).map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
    if meta.len() > MAX_JOIN_BODY_BYTES as u64 {
        return Err(format!(
            "{} exceeds {MAX_JOIN_BODY_BYTES} byte cap",
            path.display()
        ));
    }
    fs::read_to_string(path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

fn propose_node_id_for_human(human_id: &str) -> String {
    let host = short_hostname();
    let candidate = format!("{}@{host}", human_id.trim().to_ascii_lowercase());
    if candidate != LOCAL_NODE_ID && is_valid_node_id(&candidate) {
        candidate
    } else {
        default_node_id()
    }
}

fn resolve_join_node_id(
    explicit: Option<&str>,
    loaded: Option<&crate::config_file::LoadedNodeFile>,
    db: Option<&NodeDb>,
    human_id_hint: Option<&str>,
) -> String {
    if let Some(nid) = explicit {
        return nid.to_string();
    }
    if let Some(cfg) = loaded {
        if let Some(ref nid) = cfg.node_id {
            if !nid.is_empty() {
                return nid.clone();
            }
        }
    }
    if let Some(d) = db {
        if let Ok(Some(nid)) = d.local().get_metadata("node_id") {
            if !nid.is_empty() {
                return nid;
            }
        }
    }
    if let Some(hid) = human_id_hint {
        return propose_node_id_for_human(hid);
    }
    default_node_id()
}
