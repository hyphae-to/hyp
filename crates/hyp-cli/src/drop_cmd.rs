//! `hyp drop` & `hyp relay` — Verified Human Drops (`hdrop1_`, `https://hyphae.to/drop#<fragment>`)
//! and Blind Ephemeral Drop Relay management.
//!
//! Security invariants:
//! - Drop URLs NEVER carry `proposedText` or `body` in the `#fragment`.
//! - `hyp drop ingest` reads `hdrop1_...` tokens strictly from stdin (NEVER CLI argv flags!).
//! - Secret values are NEVER printed to stdout, stderr, logs, or `--json`.
//! - Relay URLs MUST use `https://` (or loopback `http://127.0.0.1` / `http://localhost`).

use crate::auth_cmd::CliDropKind;
use crate::config_file::{
    build_http_client, default_node_id, ensure_dir, ensure_v2_node_json_defaults,
    load_node_or_legacy_config, open_secret_store, read_json_object_or_empty,
    resolve_config_path_for_read, resolve_config_path_for_write, resolve_effective_node_id,
    resolve_state_dir, write_atomic_json,
};
use crate::ui::{
    EXIT_ERROR, EXIT_OK, EXIT_USAGE, JsonEnvelope, emit_error, print_json, print_next_steps,
    print_warnings,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Subcommand;
use http::{Method, Request, header};
use http_body_util::{BodyExt, Full};
use hyp_crypto::human::{
    EncryptedHumanDraftV1, HumanDraftPayloadV1, HumanDropEnvelopeV1, MAX_HUMAN_DRAFT_CONTEXT_CHARS,
    SignedNodeCertV1, decode_hdrop1, encode_hcert1, is_reserved_secret_name, seal_human_draft,
    validate_draft_text,
};
use hyp_crypto::jcs::to_canonical_json;
use hyp_crypto::keys::{NodeIdentityKeys, OkpJwk};
use hyp_crypto::keystore::validate_secret_name;
use hyp_crypto::rfc3339::{format_rfc3339_millis, now_unix_ms};
use hyp_node::engine::http_util::{SseParser, percent_encode};
use hyp_node::engine::{
    AckDropResponse, CreateDropRequest, CreateDropResponse, DROP_CAP_HEADER, DropRelayConfig,
    IngestedHumanDrop, NodeConfig, NodeProfile, UnifiedNode, resolve_drop_portal_url,
};
use hyp_node::gates::{SecurityGateConfig, SecurityGatePipeline};
use hyp_proto::address::{NodeId, is_valid_handle};
use hyp_store::NodeDb;
use hyper::body::Bytes;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::io::{self, IsTerminal as _, Read as _};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const LAST_DROP_FILENAME: &str = "last_drop.json";
const MAX_HDROP1_STDIN_BYTES: u64 = 64 * 1024;
const MAX_DRAFT_STDIN_BYTES: u64 = 8 * 1024;
const MAX_SUBCAP_STDIN_BYTES: u64 = 4 * 1024;
const MAX_RELAY_JSON_BYTES: usize = 64 * 1024;
const MAX_DROP_TTL_SECS: u64 = 900;
const RELAY_HTTP_TIMEOUT_SECS: u64 = 15;
const RELAY_PROBE_TIMEOUT_SECS: u64 = 4;
const DROP_WAIT_BACKOFF_MS: &[u64] = &[500, 1_000, 2_000, 5_000];

#[derive(Subcommand)]
pub enum DropCommand {
    /// Allocate a blind drop slot (or offline invite) and emit a phone-ready https://hyphae.to/drop#drop=<fragment> URL
    Create {
        /// Drop kind (secret or directive)
        #[arg(long, value_enum)]
        kind: CliDropKind,
        /// Target SecretStore name (required when --kind secret; reserved system keys blocked)
        #[arg(long)]
        secret_name: Option<String>,
        /// Optional target local agent handle
        #[arg(long)]
        handle: Option<String>,
        /// Optional short directive draft prefill (HPKE-encrypted via encDraft; forbidden for --kind secret)
        #[arg(long)]
        draft: Option<String>,
        /// Read directive draft prefill from stdin (HPKE-encrypted via encDraft; forbidden for --kind secret)
        #[arg(long)]
        draft_stdin: bool,
        /// Optional context label (<= 160 chars) for encrypted directive draft (requires --draft or --draft-stdin)
        #[arg(long)]
        context: Option<String>,
        /// Explicit Drop Relay base URL (overrides node.json dropRelayUrl)
        #[arg(long)]
        relay: Option<String>,
        /// Drop slot TTL in seconds (1..=900, default: 600)
        #[arg(long, default_value_t = 600)]
        ttl: u64,
        /// Generate an offline https://hyphae.to/drop#drop=<fragment> invite (no Drop Relay contact)
        #[arg(long)]
        offline: bool,
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
    /// Stream a Drop Relay slot over SSE, verify & ingest the sealed drop, and burn it from relay RAM
    Wait {
        /// Drop Relay base URL (defaults to last_drop.json or node.json dropRelayUrl)
        #[arg(long)]
        relay: Option<String>,
        /// Drop slot ID to watch (defaults to most recent online `hyp drop create` saved in last_drop.json)
        #[arg(long, allow_hyphen_values = true)]
        drop_id: Option<String>,
        /// Allow overwriting an existing secret of the same name
        #[arg(long)]
        overwrite: bool,
        /// Maximum seconds to wait for a sealed drop (default: 600)
        #[arg(long, default_value_t = 600)]
        timeout: u64,
        /// Explicit state directory containing node.sqlite and secrets/
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Explicit node.json path
        #[arg(long)]
        config: Option<PathBuf>,
        /// Output structured JSON envelope (never includes secret values!)
        #[arg(long)]
        json: bool,
    },
    /// Verify & ingest an armored hdrop1_ token strictly from stdin (NEVER CLI argv!)
    Ingest {
        /// Allow overwriting an existing secret of the same name
        #[arg(long)]
        overwrite: bool,
        /// Explicit state directory containing node.sqlite and secrets/
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Explicit node.json path
        #[arg(long)]
        config: Option<PathBuf>,
        /// Output structured JSON envelope (never includes secret values!)
        #[arg(long)]
        json: bool,
    },
}

#[derive(Subcommand)]
pub enum RelayCommand {
    /// Save a validated Drop Relay HTTPS (or loopback HTTP) base URL into node.json
    Set {
        /// Drop Relay base URL (https://... or loopback http://127.0.0.1:...)
        url: String,
        /// Explicit node.json path
        #[arg(long)]
        config: Option<PathBuf>,
        /// Explicit state directory
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Show configured Drop Relay URL, local dropRelay config, and optional live /v1/health counters
    Status {
        /// Optional explicit Drop Relay URL to probe via GET /v1/health
        #[arg(long)]
        url: Option<String>,
        /// Probe configured remote dropRelayUrl via GET /v1/health even if non-loopback
        #[arg(long)]
        probe: bool,
        /// Explicit node.json path
        #[arg(long)]
        config: Option<PathBuf>,
        /// Explicit state directory
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
}

pub fn run_drop(command: DropCommand) -> ExitCode {
    match command {
        DropCommand::Create {
            kind,
            secret_name,
            handle,
            draft,
            draft_stdin,
            context,
            relay,
            ttl,
            offline,
            state_dir,
            config,
            json,
        } => run_drop_create(
            kind,
            secret_name,
            handle,
            draft,
            draft_stdin,
            context,
            relay,
            ttl,
            offline,
            state_dir,
            config,
            json,
        ),
        DropCommand::Wait {
            relay,
            drop_id,
            overwrite,
            timeout,
            state_dir,
            config,
            json,
        } => run_drop_wait(relay, drop_id, overwrite, timeout, state_dir, config, json),
        DropCommand::Ingest {
            overwrite,
            state_dir,
            config,
            json,
        } => run_drop_ingest(overwrite, state_dir, config, json),
    }
}

pub fn run_relay(command: RelayCommand) -> ExitCode {
    match command {
        RelayCommand::Set {
            url,
            config,
            state_dir,
            json,
        } => run_relay_set(url, config, state_dir, json),
        RelayCommand::Status {
            url,
            probe,
            config,
            state_dir,
            json,
        } => run_relay_status(url, probe, config, state_dir, json),
    }
}

/// Validates a Drop Relay base URL fail-closed: permits strictly `https://` or loopback
/// `http://127.0.0.1` / `http://localhost` / `http://[::1]`, with no userinfo, query, or fragment.
pub(crate) fn validate_relay_url(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return Err("Drop Relay URL cannot be empty".to_string());
    }
    if trimmed.contains('#') || trimmed.contains('?') {
        return Err("Drop Relay URL must not contain query parameters or fragments".to_string());
    }
    let uri: http::Uri = trimmed
        .parse()
        .map_err(|e| format!("invalid Drop Relay URL '{trimmed}': {e}"))?;
    let scheme = uri
        .scheme_str()
        .ok_or_else(|| format!("Drop Relay URL '{trimmed}' must include https:// scheme"))?;
    let auth = uri
        .authority()
        .ok_or_else(|| format!("Drop Relay URL '{trimmed}' is missing a host"))?;
    if auth.as_str().contains('@') {
        return Err("Drop Relay URL must not include embedded credentials".to_string());
    }
    let host = auth.host().to_ascii_lowercase();
    if host.is_empty() {
        return Err("Drop Relay URL host cannot be empty".to_string());
    }
    match scheme {
        "https" => Ok(trimmed.to_string()),
        "http" => {
            if is_loopback_host(&host) {
                Ok(trimmed.to_string())
            } else {
                Err(format!(
                    "refusing insecure http:// Drop Relay URL '{trimmed}'; use https:// (only loopback http://127.0.0.1 or http://localhost is permitted)"
                ))
            }
        }
        other => Err(format!(
            "unsupported Drop Relay URL scheme '{other}' (expected https://)"
        )),
    }
}

fn is_loopback_host(host: &str) -> bool {
    matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]")
}

fn is_loopback_url(url: &str) -> bool {
    url.parse::<http::Uri>()
        .ok()
        .and_then(|u| {
            u.authority()
                .map(|a| is_loopback_host(&a.host().to_ascii_lowercase()))
        })
        .unwrap_or(false)
}

pub(crate) fn build_ed25519_auth_header(
    node_id: &str,
    identity: &NodeIdentityKeys,
    method: &str,
    path_and_query: &str,
    body_bytes: &[u8],
) -> Result<String, String> {
    let body_sha = hex::encode(Sha256::digest(body_bytes));
    let ts = now_unix_ms();
    let mut nonce_bytes = [0u8; 12];
    SystemRandom::new()
        .fill(&mut nonce_bytes)
        .map_err(|_| "OS CSPRNG failure".to_string())?;
    let nonce = hex::encode(nonce_bytes);
    let signing_input = format!("{method}\n{path_and_query}\n{ts}\n{nonce}\n{body_sha}");
    let sig = identity
        .signing
        .sign_domain_b64("http-auth", signing_input.as_bytes());
    Ok(format!(
        "Hyphae-Ed25519 node=\"{node_id}\",ts=\"{ts}\",nonce=\"{nonce}\",sig=\"{sig}\""
    ))
}

fn open_node_and_optional_gate(
    state_dir: &Path,
    config_path: &Path,
    explicit_state: bool,
) -> Result<(Arc<UnifiedNode>, Option<SecurityGatePipeline>), String> {
    ensure_dir(state_dir, true)?;
    let loaded = if config_path.exists() {
        Some(load_node_or_legacy_config(config_path)?)
    } else {
        None
    };
    let secrets = open_secret_store(state_dir, explicit_state);
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
    let mut node_cfg = NodeConfig::new(node_id, profile, state_dir);
    node_cfg.secret_backend = Some(secrets.backend());

    let node =
        UnifiedNode::open(node_cfg).map_err(|e| format!("failed to open UnifiedNode: {e}"))?;

    let has_gate_seal = crate::approval::has_gate_lock_seal(state_dir);
    let gate = match loaded.as_ref().and_then(|c| c.raw.get("gate")) {
        Some(gate_val) => {
            let gate_cfg: SecurityGateConfig = serde_json::from_value(gate_val.clone())
                .map_err(|e| format!("invalid gate config in {}: {e}", config_path.display()))?;
            let gate_db = Arc::new(Mutex::new(
                NodeDb::open(state_dir.join("node.sqlite"))
                    .map_err(|e| format!("failed to open gate NodeDb: {e}"))?,
            ));
            let pipeline = SecurityGatePipeline::new(gate_cfg, gate_db, Some(Arc::new(secrets)))
                .map_err(|e| format!("failed to initialize SecurityGatePipeline: {e}"))?;
            Some(pipeline)
        }
        None if has_gate_seal => {
            let gate_db = Arc::new(Mutex::new(
                NodeDb::open(state_dir.join("node.sqlite"))
                    .map_err(|e| format!("failed to open gate NodeDb: {e}"))?,
            ));
            let pipeline = SecurityGatePipeline::new(
                SecurityGateConfig::default(),
                gate_db,
                Some(Arc::new(secrets)),
            )
            .map_err(|e| format!("failed to initialize SecurityGatePipeline: {e}"))?;
            Some(pipeline)
        }
        None => None,
    };

    Ok((node, gate))
}

#[allow(clippy::too_many_arguments)]
fn run_drop_create(
    kind: CliDropKind,
    secret_name_arg: Option<String>,
    handle_arg: Option<String>,
    draft_arg: Option<String>,
    draft_stdin: bool,
    context_arg: Option<String>,
    relay_arg: Option<String>,
    ttl_secs: u64,
    offline: bool,
    state_dir_arg: Option<PathBuf>,
    config_arg: Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let cmd = "drop create";
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

    if draft_arg.is_some() && draft_stdin {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "CONFLICTING_FLAGS",
            "Specify at most one of --draft or --draft-stdin",
            None,
        );
    }

    // Fail-closed security invariant #1: secrets MUST NEVER carry draft or context prefill.
    if kind == CliDropKind::Secret && (draft_arg.is_some() || draft_stdin || context_arg.is_some())
    {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "DRAFT_FORBIDDEN_FOR_SECRET",
            "Draft prefill is forbidden for secret drops; secrets must be entered fresh by the human",
            None,
        );
    }

    let draft_text: Option<String> = if draft_stdin {
        let mut raw = String::new();
        if let Err(e) = io::stdin()
            .lock()
            .take(MAX_DRAFT_STDIN_BYTES + 1)
            .read_to_string(&mut raw)
        {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "STDIN_ERROR",
                format!("Failed to read draft from stdin: {e}"),
                None,
            );
        }
        if raw.len() as u64 > MAX_DRAFT_STDIN_BYTES {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "DRAFT_TOO_LARGE",
                format!("Draft input exceeds {MAX_DRAFT_STDIN_BYTES} byte safety cap"),
                None,
            );
        }
        Some(raw.trim_end_matches(['\r', '\n']).to_string())
    } else {
        draft_arg
    };

    if draft_text.is_none() && context_arg.is_some() {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "CONTEXT_WITHOUT_DRAFT",
            "Optional --context requires --draft or --draft-stdin",
            None,
        );
    }

    if let Some(ref text) = draft_text {
        if let Err(e) = validate_draft_text(text) {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_DRAFT",
                e.to_string(),
                None,
            );
        }
        if let Some(ref ctx) = context_arg {
            if let Err(e) = validate_draft_text(ctx) {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_USAGE,
                    "INVALID_DRAFT_CONTEXT",
                    e.to_string(),
                    None,
                );
            }
            let ctx_chars = ctx.chars().count();
            if ctx_chars > MAX_HUMAN_DRAFT_CONTEXT_CHARS {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_USAGE,
                    "INVALID_DRAFT_CONTEXT",
                    format!(
                        "human draft context length {ctx_chars} exceeds maximum {MAX_HUMAN_DRAFT_CONTEXT_CHARS} chars"
                    ),
                    None,
                );
            }
        }
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

    let validated_secret_name = match kind {
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
                    format!(
                        "Reserved system secret name '{name}' is permanently blocked for human drops"
                    ),
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
            Some(name.to_string())
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

    let state_dir = resolve_state_dir(state_dir_arg.as_deref(), config_arg.as_deref(), None);
    let config_read =
        resolve_config_path_for_read(config_arg.as_deref(), state_dir_arg.as_deref(), None);
    let loaded = if config_read.exists() {
        load_node_or_legacy_config(&config_read).ok()
    } else {
        None
    };

    let configured_drop_portal_url: Option<String> = match loaded
        .as_ref()
        .and_then(|c| c.raw.get("dropPortalUrl"))
    {
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
                    config_read.display()
                ),
                Some(
                    "Set dropPortalUrl to an https:// URL (e.g. \"https://hyphae.to/drop\") or loopback http://127.0.0.1."
                        .to_string(),
                ),
            );
        }
    };
    let drop_portal_url = match resolve_drop_portal_url(configured_drop_portal_url.as_deref()) {
        Ok(u) => u,
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
    };

    let relay_url: Option<String> = if offline {
        None
    } else if let Some(ref explicit) = relay_arg {
        match validate_relay_url(explicit) {
            Ok(u) => Some(u),
            Err(e) => return emit_error(cmd, as_json, EXIT_USAGE, "INVALID_RELAY_URL", e, None),
        }
    } else if let Some(configured) = loaded
        .as_ref()
        .and_then(|c| c.raw.get("dropRelayUrl"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        match validate_relay_url(configured) {
            Ok(u) => Some(u),
            Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "INVALID_RELAY_URL", e, None),
        }
    } else {
        None
    };

    if let Err(e) = ensure_dir(&state_dir, true) {
        return emit_error(cmd, as_json, EXIT_ERROR, "IO_ERROR", e, None);
    }
    let db_path = state_dir.join("node.sqlite");
    let db = if db_path.exists() {
        NodeDb::open(&db_path).ok()
    } else {
        None
    };
    let node_id = resolve_effective_node_id(loaded.as_ref(), db.as_ref());
    let secrets = open_secret_store(&state_dir, state_dir_arg.is_some());
    // Non-authoritative UI cue ONLY (H15): strictly boolean existence check; NEVER expose secret bytes.
    let secret_exists = validated_secret_name
        .as_deref()
        .is_some_and(|sn| secrets.get(sn).is_ok());
    let identity = match secrets.load_or_create_node_keys(&node_id) {
        Ok(k) => k,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "NODE_KEY_ERROR",
                format!("Failed to load node identity keys: {e}"),
                None,
            );
        }
    };
    let enc_jwk = identity.encryption_jwk();

    let (node_cert_hcert1, mut hint_human_id, mut hint_prf_salt, mut hint_auth_epoch, min_ep) =
        if let Some(ref d) = db {
            let cert_token = d
                .human()
                .get_latest_node_cert(&node_id)
                .ok()
                .flatten()
                .and_then(|rec| serde_json::from_str::<SignedNodeCertV1>(&rec.signed_json).ok())
                .and_then(|signed| encode_hcert1(&signed).ok());
            let active_auths = d.human().list_authorities(false).unwrap_or_default();
            // Prefer an authority with a prf_salt (Passkey signer), else first active authority.
            let best_hint = active_auths
                .iter()
                .find(|a| a.prf_salt.is_some())
                .or_else(|| active_auths.first());
            let min_ep = d.human().min_auth_epoch().unwrap_or(1);
            (
                cert_token,
                best_hint.map(|a| a.human_id.clone()),
                best_hint.and_then(|a| a.prf_salt.clone()),
                best_hint.map(|a| a.auth_epoch.max(min_ep)),
                min_ep,
            )
        } else {
            (None, None, None, None, 1)
        };

    let now = now_unix_ms();

    // Fail-closed security invariant #2: encrypt directive draft to the human's Passkey X25519 key
    // (`encDraft` ONLY — NEVER downgrade to plaintext `draft` or `proposedText`!).
    let encrypted_draft: Option<EncryptedHumanDraftV1> = if let Some(ref text) = draft_text {
        let enc_authority = db
            .as_ref()
            .and_then(|d| d.human().get_preferred_human_enc_jwk(None).ok().flatten());
        let Some(auth_rec) = enc_authority else {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "NO_HUMAN_ENC_KEY",
                "No human X25519 encryption key enrolled for encrypted directive draft prefill; refusing plaintext downgrade",
                Some("hyp auth init --web".to_string()),
            );
        };
        let Some(ref raw_enc_jwk) = auth_rec.enc_jwk_json else {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "NO_HUMAN_ENC_KEY",
                "No human X25519 encryption key enrolled for encrypted directive draft prefill; refusing plaintext downgrade",
                Some("hyp auth init --web".to_string()),
            );
        };
        let parsed_enc_jwk: OkpJwk = match serde_json::from_str(raw_enc_jwk) {
            Ok(j) => j,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "INVALID_HUMAN_ENC_KEY",
                    format!("Stored human encryption JWK is invalid: {e}"),
                    Some("hyp auth init --web".to_string()),
                );
            }
        };
        let human_enc_pk = match parsed_enc_jwk.to_x25519() {
            Ok(pk) => pk,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "INVALID_HUMAN_ENC_KEY",
                    format!("Stored human encryption JWK is not a valid X25519 public key: {e}"),
                    Some("hyp auth init --web".to_string()),
                );
            }
        };

        // Keep Passkey PRF hints aligned with the authority whose X25519 key sealed `encDraft`.
        hint_human_id = Some(auth_rec.human_id.clone());
        if auth_rec.prf_salt.is_some() {
            hint_prf_salt = auth_rec.prf_salt.clone();
        }
        hint_auth_epoch = Some(auth_rec.auth_epoch.max(min_ep));

        let payload = HumanDraftPayloadV1 {
            v: 1,
            node_id: node_id.clone(),
            text: text.clone(),
            context: context_arg.clone(),
            created_at: format_rfc3339_millis(now),
        };
        match seal_human_draft(&payload, &human_enc_pk) {
            Ok(sealed) => Some(sealed),
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_USAGE,
                    "DRAFT_SEAL_FAILED",
                    format!("Failed to seal encrypted directive draft: {e}"),
                    None,
                );
            }
        }
    } else {
        None
    };

    let mut warnings = Vec::new();
    if node_cert_hcert1.is_none() {
        warnings.push(
            "No human-signed NodeCertV1 (hcert1_) found for this node; run `hyp auth init` or `hyp auth certify-node` (required by browser portal for kind=secret)."
                .to_string(),
        );
    }

    let (mode, drop_id, post_cap, expires_at_ms) = if let Some(ref base_url) = relay_url {
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
        let created = match rt.block_on(create_relay_drop_slot(
            base_url, &node_id, &identity, ttl_secs,
        )) {
            Ok(c) => c,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "RELAY_CREATE_FAILED",
                    e,
                    Some(
                        "Re-run with --offline to generate an offline hdrop1_ invite URL."
                            .to_string(),
                    ),
                );
            }
        };
        let last_drop_doc = json!({
            "dropId": created.drop_id,
            "relay": base_url,
            "subCap": created.sub_cap,
            "expiresAtMs": created.expires_at_ms,
        });
        let last_drop_path = state_dir.join(LAST_DROP_FILENAME);
        if let Err(e) = write_atomic_json(&last_drop_path, &last_drop_doc, true) {
            warnings.push(format!(
                "Could not save {} for zero-flag `hyp drop wait`: {e}",
                last_drop_path.display()
            ));
        }
        (
            "relay",
            Some(created.drop_id),
            Some(created.post_cap),
            created.expires_at_ms,
        )
    } else {
        (
            "offline",
            None,
            None,
            now.saturating_add((ttl_secs as i64).saturating_mul(1_000)),
        )
    };

    let expires_at = format_rfc3339_millis(expires_at_ms);

    // Construct exact `DropInviteFragmentV1` expected by `site/drop/drop.js` (`parseFragmentString`).
    // SECURITY: NEVER include plaintext `proposedText`, `draft`, or `body` — ONLY HPKE `encDraft`!
    let mut frag = Map::new();
    frag.insert("v".to_string(), json!(1));
    frag.insert("nodeId".to_string(), json!(node_id));
    frag.insert(
        "encJwk".to_string(),
        json!({
            "kty": "OKP",
            "crv": "X25519",
            "x": enc_jwk.x,
        }),
    );
    frag.insert("kind".to_string(), json!(kind.to_crypto_kind().as_str()));
    frag.insert("expiresAt".to_string(), json!(expires_at));
    if let Some(ref h) = handle_arg {
        frag.insert("handle".to_string(), json!(h));
    }
    if let Some(ref sn) = validated_secret_name {
        frag.insert("secretName".to_string(), json!(sn));
        if secret_exists {
            frag.insert("secretExists".to_string(), json!(true));
        }
    }
    if let Some(ref cert) = node_cert_hcert1 {
        frag.insert("nodeCert".to_string(), json!(cert));
    }
    if let Some(ref did) = drop_id {
        frag.insert("dropId".to_string(), json!(did));
    }
    if let Some(ref rurl) = relay_url {
        frag.insert("relay".to_string(), json!(rurl));
    }
    if let Some(ref pcap) = post_cap {
        frag.insert("postCap".to_string(), json!(pcap));
    }
    if let Some(ref hid) = hint_human_id {
        frag.insert("humanId".to_string(), json!(hid));
    }
    if let Some(ref salt) = hint_prf_salt {
        frag.insert("prfSalt".to_string(), json!(salt));
    }
    if let Some(ep) = hint_auth_epoch {
        frag.insert("authEpoch".to_string(), json!(ep));
    }
    if let Some(ref sealed_draft) = encrypted_draft {
        let draft_val = match serde_json::to_value(sealed_draft) {
            Ok(v) => v,
            Err(e) => {
                return emit_error(cmd, as_json, EXIT_ERROR, "JSON_ERROR", e.to_string(), None);
            }
        };
        frag.insert("encDraft".to_string(), draft_val);
    }

    let canon = match to_canonical_json(&Value::Object(frag)) {
        Ok(s) => s,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "JSON_ERROR", e.to_string(), None),
    };
    let drop_url = format!(
        "{drop_portal_url}#drop={}",
        URL_SAFE_NO_PAD.encode(canon.as_bytes())
    );

    let next = if relay_url.is_some() && drop_id.is_some() {
        vec![format!("hyp drop wait --state-dir {}", state_dir.display())]
    } else {
        vec![format!(
            "Paste the sealed hdrop1_ token from your phone into: hyp drop ingest --state-dir {}",
            state_dir.display()
        )]
    };

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(format!(
                "Created {mode} {} drop URL for node '{node_id}'",
                kind.to_crypto_kind().as_str()
            )),
            data: Some(json!({
                "mode": mode,
                "url": drop_url,
                "nodeId": node_id,
                "handle": handle_arg,
                "kind": kind.to_crypto_kind().as_str(),
                "secretName": validated_secret_name,
                "secretExists": secret_exists,
                "dropId": drop_id,
                "relay": relay_url,
                "nodeCert": node_cert_hcert1,
                "hasNodeCert": node_cert_hcert1.is_some(),
                "hasEncDraft": encrypted_draft.is_some(),
                "expiresAt": expires_at,
            })),
            warnings,
            next,
            error: None,
        };
        print_json(&envelope);
    } else {
        println!(
            "OK    Created {mode} {} drop invite for '{node_id}'",
            kind.to_crypto_kind().as_str()
        );
        println!("      URL:     {drop_url}");
        println!("      Expires: {expires_at}");
        if let Some(ref did) = drop_id {
            println!("      Drop ID: {did}");
        }
        if encrypted_draft.is_some() {
            println!("      Draft:   HPKE-encrypted (human.draft.v1; zero plaintext in URL)");
        }
        if secret_exists {
            if let Some(ref sn) = validated_secret_name {
                println!(
                    "      Note:    Secret '{sn}' already exists — check Overwrite on the drop page to replace it."
                );
            }
        }
        print_next_steps(&next);
    }
    ExitCode::from(EXIT_OK)
}

pub(crate) async fn create_relay_drop_slot(
    relay_base: &str,
    node_id: &str,
    identity: &NodeIdentityKeys,
    ttl_secs: u64,
) -> Result<CreateDropResponse, String> {
    let client = build_http_client::<Full<Bytes>>()?;
    let path = "/v1/drops";
    let url = format!("{relay_base}{path}");
    let body_req = CreateDropRequest {
        ttl_seconds: Some(ttl_secs),
        max_items: Some(1),
        target_node_id: Some(node_id.to_string()),
        burn_after_read: true,
    };
    let body_bytes = serde_json::to_vec(&body_req).map_err(|e| e.to_string())?;
    let auth = build_ed25519_auth_header(node_id, identity, "POST", path, &body_bytes)?;

    let req = Request::builder()
        .method(Method::POST)
        .uri(&url)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::AUTHORIZATION, auth)
        .header("x-hyphae-node", node_id)
        .header("X-Hyphae-Public-Key", identity.signing_jwk().x)
        .body(Full::new(Bytes::from(body_bytes)))
        .map_err(|e| format!("failed to build POST /v1/drops request: {e}"))?;

    let resp = tokio::time::timeout(
        Duration::from_secs(RELAY_HTTP_TIMEOUT_SECS),
        client.request(req),
    )
    .await
    .map_err(|_| format!("POST {url} timed out after {RELAY_HTTP_TIMEOUT_SECS}s"))?
    .map_err(|e| format!("POST {url} failed: {e}"))?;

    let status = resp.status();
    let bytes = collect_bounded_body(resp.into_body(), MAX_RELAY_JSON_BYTES).await?;
    if !status.is_success() {
        let snippet = String::from_utf8_lossy(&bytes);
        return Err(format!(
            "Drop Relay POST /v1/drops returned HTTP {}: {}",
            status.as_u16(),
            snippet.trim()
        ));
    }
    serde_json::from_slice::<CreateDropResponse>(&bytes)
        .map_err(|e| format!("invalid CreateDropResponse JSON from relay: {e}"))
}

struct SavedLastDrop {
    drop_id: String,
    relay: Option<String>,
    sub_cap: Option<String>,
    expires_at_ms: Option<i64>,
}

fn load_saved_last_drop(path: &Path) -> Option<SavedLastDrop> {
    let raw = std::fs::read_to_string(path).ok()?;
    let val: Value = serde_json::from_str(&raw).ok()?;
    let obj = val.as_object()?;
    let drop_id = obj
        .get("dropId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())?
        .to_string();
    let relay = obj
        .get("relay")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);
    let sub_cap = obj
        .get("subCap")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);
    let expires_at_ms = obj.get("expiresAtMs").and_then(Value::as_i64);
    Some(SavedLastDrop {
        drop_id,
        relay,
        sub_cap,
        expires_at_ms,
    })
}

#[allow(clippy::too_many_arguments)]
fn run_drop_wait(
    relay_arg: Option<String>,
    drop_id_arg: Option<String>,
    overwrite: bool,
    timeout_secs: u64,
    state_dir_arg: Option<PathBuf>,
    config_arg: Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let cmd = "drop wait";

    let state_dir = resolve_state_dir(state_dir_arg.as_deref(), config_arg.as_deref(), None);
    let config_read =
        resolve_config_path_for_read(config_arg.as_deref(), state_dir_arg.as_deref(), None);
    let loaded = if config_read.exists() {
        load_node_or_legacy_config(&config_read).ok()
    } else {
        None
    };

    let last_drop_path = state_dir.join(LAST_DROP_FILENAME);
    let saved_last = load_saved_last_drop(&last_drop_path);

    let (effective_drop_id, used_saved_last) = match drop_id_arg {
        Some(raw) => {
            let trimmed = raw.trim().to_string();
            if trimmed.is_empty() {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_USAGE,
                    "INVALID_DROP_ID",
                    "--drop-id cannot be empty",
                    None,
                );
            }
            let matched = saved_last.as_ref().is_some_and(|s| s.drop_id == trimmed);
            (trimmed, matched)
        }
        None => match saved_last {
            Some(ref saved) => {
                if let Some(exp) = saved.expires_at_ms {
                    if exp <= now_unix_ms() {
                        let _ = std::fs::remove_file(&last_drop_path);
                        return emit_error(
                            cmd,
                            as_json,
                            EXIT_ERROR,
                            "LAST_DROP_EXPIRED",
                            format!(
                                "Most recent drop slot '{}' in {} has expired; create a fresh drop link",
                                saved.drop_id,
                                last_drop_path.display()
                            ),
                            Some(format!(
                                "hyp drop create --kind directive --state-dir {}",
                                state_dir.display()
                            )),
                        );
                    }
                }
                (saved.drop_id.clone(), true)
            }
            None => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_USAGE,
                    "MISSING_DROP_ID",
                    format!(
                        "No --drop-id specified and no pending drop found in {}",
                        last_drop_path.display()
                    ),
                    Some(format!(
                        "Run `hyp drop create --kind directive --state-dir {}` first, or pass --drop-id <id>.",
                        state_dir.display()
                    )),
                );
            }
        },
    };

    let relay_raw = relay_arg
        .or_else(|| {
            if used_saved_last {
                saved_last.as_ref().and_then(|s| s.relay.clone())
            } else {
                None
            }
        })
        .or_else(|| {
            loaded
                .as_ref()
                .and_then(|c| c.raw.get("dropRelayUrl"))
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
        });
    let Some(relay_raw) = relay_raw else {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "MISSING_RELAY",
            "No --relay URL specified and no dropRelayUrl configured in node.json",
            Some(
                "Pass --relay https://<your-relay> or run `hyp relay set https://<your-relay>`."
                    .to_string(),
            ),
        );
    };
    let relay_url = match validate_relay_url(&relay_raw) {
        Ok(u) => u,
        Err(e) => return emit_error(cmd, as_json, EXIT_USAGE, "INVALID_RELAY_URL", e, None),
    };

    // Optionally read `subCap` from piped stdin (NEVER argv!), falling back to `last_drop.json`.
    let stdin_sub_cap: Option<String> = if !io::stdin().is_terminal() {
        let mut raw = String::new();
        if io::stdin()
            .lock()
            .take(MAX_SUBCAP_STDIN_BYTES + 1)
            .read_to_string(&mut raw)
            .is_ok()
            && (raw.len() as u64) <= MAX_SUBCAP_STDIN_BYTES
        {
            let t = raw.trim().to_string();
            if t.is_empty() { None } else { Some(t) }
        } else {
            None
        }
    } else {
        None
    };
    let sub_cap = stdin_sub_cap.or_else(|| {
        if used_saved_last {
            saved_last.as_ref().and_then(|s| s.sub_cap.clone())
        } else {
            None
        }
    });

    let (node, gate) =
        match open_node_and_optional_gate(&state_dir, &config_read, state_dir_arg.is_some()) {
            Ok(pair) => pair,
            Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "NODE_OPEN_FAILED", e, None),
        };

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

    match rt.block_on(wait_for_relay_drop(
        &relay_url,
        &effective_drop_id,
        sub_cap.as_deref(),
        node.node_id().as_str(),
        node.identity(),
        timeout_secs,
        async |envelope| {
            node.ingest_human_drop(&envelope, gate.as_ref(), overwrite)
                .await
                .map_err(|e| e.to_string())
        },
    )) {
        Ok((ingested, ack_resp, warnings)) => {
            if used_saved_last {
                let _ = std::fs::remove_file(&last_drop_path);
            }
            emit_ingested_drop_ok(
                cmd,
                as_json,
                &ingested,
                Some(&relay_url),
                Some(&effective_drop_id),
                ack_resp.as_ref(),
                warnings,
            )
        }
        Err(e) => emit_error(cmd, as_json, EXIT_ERROR, "DROP_WAIT_FAILED", e, None),
    }
}

/// Decodes a posted drop item: an armored `hdrop1_` token or `HumanDropEnvelopeV1` JSON.
pub(crate) fn decode_drop_envelope(raw: &str) -> Result<HumanDropEnvelopeV1, String> {
    let trimmed = raw.trim();
    if trimmed.starts_with("hdrop1_") {
        decode_hdrop1(trimmed).map_err(|e| format!("invalid hdrop1_ token: {e}"))
    } else {
        serde_json::from_str(trimmed).map_err(|e| format!("invalid HumanDropEnvelopeV1 JSON: {e}"))
    }
}

/// Streams a Drop Relay slot (SSE, reconnecting with backoff and `Last-Event-ID`) until `accept`
/// takes an item or `timeout_secs` passes, then burns the slot. Items that fail to decode or that
/// `accept` rejects are skipped with a warning, so junk posted to the slot cannot end the wait.
pub(crate) async fn wait_for_relay_drop<T>(
    relay_base: &str,
    drop_id: &str,
    sub_cap: Option<&str>,
    node_id: &str,
    identity: &NodeIdentityKeys,
    timeout_secs: u64,
    mut accept: impl AsyncFnMut(HumanDropEnvelopeV1) -> Result<T, String>,
) -> Result<(T, Option<AckDropResponse>, Vec<String>), String> {
    let client = build_http_client::<Full<Bytes>>()?;
    let encoded_id = percent_encode(drop_id);
    let stream_path = format!("/v1/drops/{encoded_id}/stream");
    let stream_url = format!("{relay_base}{stream_path}");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(timeout_secs.max(1));
    let mut last_event_id: Option<String> = None;
    let mut backoff_idx: usize = 0;
    let mut warnings: Vec<String> = Vec::new();
    let mut accepted: Option<(u64, T)> = None;

    while accepted.is_none() {
        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(format!(
                "timed out after {timeout_secs}s waiting for drop '{drop_id}'"
            ));
        }

        let mut req_builder = Request::builder()
            .method(Method::GET)
            .uri(&stream_url)
            .header(header::ACCEPT, "text/event-stream");
        if let Some(ref cursor) = last_event_id {
            req_builder = req_builder.header("Last-Event-ID", cursor.as_str());
        }
        if let Some(cap) = sub_cap {
            req_builder = req_builder.header(DROP_CAP_HEADER, cap);
        } else {
            let auth = build_ed25519_auth_header(node_id, identity, "GET", &stream_path, b"")?;
            req_builder = req_builder
                .header(header::AUTHORIZATION, auth)
                .header("x-hyphae-node", node_id)
                .header("X-Hyphae-Public-Key", identity.signing_jwk().x);
        }
        let req = req_builder
            .body(Full::new(Bytes::new()))
            .map_err(|e| format!("failed to build SSE stream request: {e}"))?;

        let resp = match tokio::time::timeout_at(deadline, client.request(req)).await {
            Err(_) => {
                return Err(format!(
                    "timed out after {timeout_secs}s waiting for drop '{drop_id}'"
                ));
            }
            Ok(Err(_transport_err)) => {
                let delay = Duration::from_millis(
                    DROP_WAIT_BACKOFF_MS[backoff_idx.min(DROP_WAIT_BACKOFF_MS.len() - 1)],
                );
                backoff_idx = backoff_idx.saturating_add(1);
                let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
                if rem.is_zero() {
                    return Err(format!(
                        "timed out after {timeout_secs}s waiting for drop '{drop_id}'"
                    ));
                }
                tokio::time::sleep(delay.min(rem)).await;
                continue;
            }
            Ok(Ok(resp)) => resp,
        };

        if !resp.status().is_success() {
            let status = resp.status();
            let err_bytes = collect_bounded_body(resp.into_body(), MAX_RELAY_JSON_BYTES)
                .await
                .unwrap_or_default();
            // Terminal client/slot errors (400/401/403/404/410) fail closed immediately;
            // transient server/rate-limit errors (429/5xx) reconnect with bounded backoff.
            if status.is_client_error() && status.as_u16() != 429 {
                return Err(format!(
                    "Drop Relay SSE stream returned HTTP {}: {}",
                    status.as_u16(),
                    String::from_utf8_lossy(&err_bytes).trim()
                ));
            }
            let delay = Duration::from_millis(
                DROP_WAIT_BACKOFF_MS[backoff_idx.min(DROP_WAIT_BACKOFF_MS.len() - 1)],
            );
            backoff_idx = backoff_idx.saturating_add(1);
            let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
            if rem.is_zero() {
                return Err(format!(
                    "timed out after {timeout_secs}s waiting for drop '{drop_id}'"
                ));
            }
            tokio::time::sleep(delay.min(rem)).await;
            continue;
        }

        let mut body = resp.into_body();
        let mut parser = SseParser::new();
        let mut received_any_event = false;

        loop {
            let frame_res = match tokio::time::timeout_at(deadline, body.frame()).await {
                Err(_) => {
                    return Err(format!(
                        "timed out after {timeout_secs}s waiting for drop '{drop_id}'"
                    ));
                }
                Ok(res) => res,
            };
            let Some(frame_res) = frame_res else {
                // Stream closed cleanly before a valid drop arrived -> reconnect with backoff.
                break;
            };
            let Ok(frame) = frame_res else {
                // Mid-stream transport error -> reconnect with backoff & Last-Event-ID.
                break;
            };
            if let Some(data) = frame.data_ref() {
                for ev in parser.feed(data) {
                    received_any_event = true;
                    if let Some(ref ev_id) = ev.id {
                        let trimmed_id = ev_id.trim();
                        if !trimmed_id.is_empty() {
                            last_event_id = Some(trimmed_id.to_string());
                        }
                    } else if let Some(parsed_id) = parser.last_event_id() {
                        let trimmed_id = parsed_id.trim();
                        if !trimmed_id.is_empty() {
                            last_event_id = Some(trimmed_id.to_string());
                        }
                    }

                    if ev.event.as_deref() == Some("drop") {
                        let seq = ev
                            .id
                            .as_deref()
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(1);
                        let envelope = match decode_drop_envelope(&ev.data) {
                            Ok(env) => env,
                            Err(err) => {
                                let msg = format!(
                                    "Ignored invalid drop item (seq={seq}) in slot '{drop_id}': {err}"
                                );
                                eprintln!("WARN  {msg}");
                                warnings.push(msg);
                                continue;
                            }
                        };

                        match accept(envelope).await {
                            Ok(ingested) => {
                                accepted = Some((seq, ingested));
                                break;
                            }
                            Err(err) => {
                                let msg = format!(
                                    "Ignored unverified drop item (seq={seq}) in slot '{drop_id}': {err}"
                                );
                                eprintln!("WARN  {msg}");
                                warnings.push(msg);
                                continue;
                            }
                        }
                    }
                }
                if accepted.is_some() {
                    break;
                }
            }
        }

        if accepted.is_some() {
            break;
        }

        if received_any_event {
            backoff_idx = 0;
        }
        let delay = Duration::from_millis(
            DROP_WAIT_BACKOFF_MS[backoff_idx.min(DROP_WAIT_BACKOFF_MS.len() - 1)],
        );
        backoff_idx = backoff_idx.saturating_add(1);
        let rem = deadline.saturating_duration_since(tokio::time::Instant::now());
        if rem.is_zero() {
            return Err(format!(
                "timed out after {timeout_secs}s waiting for drop '{drop_id}'"
            ));
        }
        tokio::time::sleep(delay.min(rem)).await;
    }

    let (seq, ingested) = accepted.ok_or_else(|| "no valid drop received".to_string())?;

    // Burn drop ciphertext from Drop Relay RAM immediately after verified ingestion.
    let ack_path = format!("/v1/drops/{encoded_id}/ack");
    let ack_url = format!("{relay_base}{ack_path}");
    let ack_body =
        serde_json::to_vec(&json!({ "seq": seq, "burn": true })).map_err(|e| e.to_string())?;
    let mut ack_builder = Request::builder()
        .method(Method::POST)
        .uri(&ack_url)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cap) = sub_cap {
        ack_builder = ack_builder.header(DROP_CAP_HEADER, cap);
    } else {
        let auth = build_ed25519_auth_header(node_id, identity, "POST", &ack_path, &ack_body)?;
        ack_builder = ack_builder
            .header(header::AUTHORIZATION, auth)
            .header("x-hyphae-node", node_id)
            .header("X-Hyphae-Public-Key", identity.signing_jwk().x);
    }
    let ack_resp = if let Ok(ack_req) = ack_builder.body(Full::new(Bytes::from(ack_body))) {
        match tokio::time::timeout(
            Duration::from_secs(RELAY_HTTP_TIMEOUT_SECS),
            client.request(ack_req),
        )
        .await
        {
            Ok(Ok(r)) if r.status().is_success() => {
                let bytes = collect_bounded_body(r.into_body(), MAX_RELAY_JSON_BYTES)
                    .await
                    .unwrap_or_default();
                serde_json::from_slice::<AckDropResponse>(&bytes).ok()
            }
            _ => None,
        }
    } else {
        None
    };

    Ok((ingested, ack_resp, warnings))
}

fn run_drop_ingest(
    overwrite: bool,
    state_dir_arg: Option<PathBuf>,
    config_arg: Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let cmd = "drop ingest";
    let mut raw = String::new();
    if let Err(e) = io::stdin()
        .lock()
        .take(MAX_HDROP1_STDIN_BYTES + 1)
        .read_to_string(&mut raw)
    {
        return emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "STDIN_ERROR",
            format!("Failed to read hdrop1_ token from stdin: {e}"),
            None,
        );
    }
    if raw.len() as u64 > MAX_HDROP1_STDIN_BYTES {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "TOKEN_TOO_LARGE",
            format!("Token input exceeds {MAX_HDROP1_STDIN_BYTES} byte safety cap"),
            None,
        );
    }
    let token = raw.trim().to_string();
    drop(raw);
    if token.is_empty() {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "EMPTY_STDIN",
            "Expected armored hdrop1_ token on stdin (never pass tokens as CLI arguments)",
            Some("Example: printf '%s' \"$HDROP1\" | hyp drop ingest".to_string()),
        );
    }

    let state_dir = resolve_state_dir(state_dir_arg.as_deref(), config_arg.as_deref(), None);
    let config_read =
        resolve_config_path_for_read(config_arg.as_deref(), state_dir_arg.as_deref(), None);

    let (node, gate) =
        match open_node_and_optional_gate(&state_dir, &config_read, state_dir_arg.is_some()) {
            Ok(pair) => pair,
            Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "NODE_OPEN_FAILED", e, None),
        };

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

    match rt.block_on(node.ingest_human_drop_token(&token, gate.as_ref(), overwrite)) {
        Ok(ingested) => {
            emit_ingested_drop_ok(cmd, as_json, &ingested, None, None, None, Vec::new())
        }
        Err(e) => emit_error(
            cmd,
            as_json,
            EXIT_ERROR,
            "DROP_INGEST_FAILED",
            e.to_string(),
            None,
        ),
    }
}

fn emit_ingested_drop_ok(
    cmd: &str,
    as_json: bool,
    ingested: &IngestedHumanDrop,
    relay_url: Option<&str>,
    drop_id: Option<&str>,
    ack: Option<&AckDropResponse>,
    warnings: Vec<String>,
) -> ExitCode {
    // SECURITY: NEVER print secret values — only metadata!
    let summary = if let Some(ref sec_name) = ingested.secret_name {
        format!(
            "Stored secret '{}' in SecretStore from verified human '{}' (claimId={})",
            sec_name, ingested.human_id, ingested.claim_id
        )
    } else {
        format!(
            "Ingested verified directive from human '{}' (claimId={})",
            ingested.human_id, ingested.claim_id
        )
    };

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(summary),
            data: Some(json!({
                "claimId": ingested.claim_id,
                "humanId": ingested.human_id,
                "kid": ingested.kid,
                "role": ingested.role,
                "kind": ingested.kind,
                "secretName": ingested.secret_name,
                "targetHandle": ingested.target_handle,
                "targetSession": ingested.target_session,
                "mailboxReceipt": ingested.mailbox_receipt,
                "auditSeq": ingested.audit_seq,
                "downgradedToNotify": ingested.downgraded_to_notify,
                "relay": relay_url,
                "dropId": drop_id,
                "relayAck": ack,
            })),
            warnings,
            next: Vec::new(),
            error: None,
        };
        print_json(&envelope);
    } else {
        println!("OK    {summary}");
        println!(
            "      Human:     {} (kid={}, role={})",
            ingested.human_id, ingested.kid, ingested.role
        );
        if let Some(ref s) = ingested.secret_name {
            println!("      Secret:    {s} (stored securely; value redacted)");
        }
        if let Some(ref sess) = ingested.target_session {
            println!("      Session:   {sess}");
        }
        if let Some(seq) = ingested.audit_seq {
            println!("      Audit Seq: #{seq}");
        }
        print_warnings(&warnings);
    }
    ExitCode::from(EXIT_OK)
}

fn run_relay_set(
    url: String,
    config_arg: Option<PathBuf>,
    state_dir_arg: Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let cmd = "relay set";
    let normalized = match validate_relay_url(&url) {
        Ok(u) => u,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_RELAY_URL",
                e,
                Some(
                    "Pass an https:// URL (e.g. hyp relay set https://drop.example.com)."
                        .to_string(),
                ),
            );
        }
    };

    let state_dir = resolve_state_dir(state_dir_arg.as_deref(), config_arg.as_deref(), None);
    let config_path =
        resolve_config_path_for_write(config_arg.as_deref(), state_dir_arg.as_deref(), None);

    let mut cfg_map = match read_json_object_or_empty(&config_path) {
        Ok(m) => m,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "CONFIG_ERROR", e, None),
    };
    let node_id = cfg_map
        .get("nodeId")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .unwrap_or_else(default_node_id);
    ensure_v2_node_json_defaults(&mut cfg_map, &node_id, NodeProfile::Local, &state_dir);
    cfg_map.insert(
        "dropRelayUrl".to_string(),
        Value::String(normalized.clone()),
    );

    if let Err(e) = write_atomic_json(&config_path, &Value::Object(cfg_map), true) {
        return emit_error(cmd, as_json, EXIT_ERROR, "IO_ERROR", e, None);
    }

    let warnings = vec![
        "If a Hyphae daemon is running, restart it (`hyp service restart --json`) so it picks up the updated dropRelayUrl."
            .to_string(),
    ];
    let next = vec![
        "hyp service restart --json".to_string(),
        format!("hyp relay status --config {}", config_path.display()),
        format!(
            "hyp drop create --kind directive --config {}",
            config_path.display()
        ),
    ];

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(format!(
                "Configured dropRelayUrl '{normalized}' in {}",
                config_path.display()
            )),
            data: Some(json!({
                "dropRelayUrl": normalized,
                "configPath": config_path.display().to_string(),
                "stateDir": state_dir.display().to_string(),
            })),
            warnings,
            next,
            error: None,
        };
        print_json(&envelope);
    } else {
        println!(
            "OK    Set dropRelayUrl = {normalized} in {}",
            config_path.display()
        );
        print_warnings(&warnings);
        print_next_steps(&next);
    }
    ExitCode::from(EXIT_OK)
}

fn run_relay_status(
    url_arg: Option<String>,
    probe_flag: bool,
    config_arg: Option<PathBuf>,
    state_dir_arg: Option<PathBuf>,
    as_json: bool,
) -> ExitCode {
    let cmd = "relay status";
    let config_path =
        resolve_config_path_for_read(config_arg.as_deref(), state_dir_arg.as_deref(), None);
    let loaded = if config_path.exists() {
        match load_node_or_legacy_config(&config_path) {
            Ok(cfg) => Some(cfg),
            Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "CONFIG_ERROR", e, None),
        }
    } else {
        None
    };

    let configured_url = loaded
        .as_ref()
        .and_then(|c| c.raw.get("dropRelayUrl"))
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);

    let local_relay: DropRelayConfig = loaded
        .as_ref()
        .and_then(|c| c.raw.get("dropRelay"))
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let explicit_probe_url = match url_arg {
        Some(ref raw) => match validate_relay_url(raw) {
            Ok(u) => Some(u),
            Err(e) => return emit_error(cmd, as_json, EXIT_USAGE, "INVALID_RELAY_URL", e, None),
        },
        None => None,
    };

    // Probe live `/v1/health` if `--url` or `--probe` was passed, OR if configured URL is loopback.
    let probe_target = explicit_probe_url.clone().or_else(|| {
        if let Some(ref cfg_u) = configured_url {
            if probe_flag || is_loopback_url(cfg_u) {
                return validate_relay_url(cfg_u).ok();
            }
        }
        None
    });

    let probe_result: Option<Value> = if let Some(ref target) = probe_target {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok();
        rt.map(|r| r.block_on(probe_relay_health(target)))
    } else {
        None
    };

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(match configured_url.as_deref() {
                Some(u) => format!(
                    "Drop Relay configured: {u} (local hosted={})",
                    local_relay.enabled
                ),
                None => format!(
                    "No remote dropRelayUrl configured (local hosted={})",
                    local_relay.enabled
                ),
            }),
            data: Some(json!({
                "configPath": config_path.display().to_string(),
                "dropRelayUrl": configured_url,
                "localDropRelay": {
                    "enabled": local_relay.enabled,
                    "localDropsOnly": local_relay.local_drops_only,
                    "maxMemoryMb": local_relay.max_memory_mb,
                    "defaultTtlSeconds": local_relay.default_ttl_seconds,
                    "maxTtlSeconds": local_relay.max_ttl_seconds,
                    "allowedOrigins": local_relay.allowed_origins,
                    "allowPrivateNetwork": local_relay.allow_private_network,
                },
                "probe": probe_result,
            })),
            warnings: Vec::new(),
            next: if configured_url.is_none() && !local_relay.enabled {
                vec![
                    "hyp relay set https://<your-drop-relay>".to_string(),
                    "hyp deploy init drop-relay --domain drop.example.com --out ./deploy-drop-relay".to_string(),
                ]
            } else {
                Vec::new()
            },
            error: None,
        };
        print_json(&envelope);
    } else {
        println!("Hyphae Drop Relay Status");
        println!(
            "  Remote URL:  {}",
            configured_url
                .as_deref()
                .unwrap_or("(not configured; offline mode)")
        );
        println!(
            "  Local Host:  {} (maxMemoryMb={}, ttl={}s..{}s)",
            if local_relay.enabled {
                "enabled"
            } else {
                "disabled"
            },
            local_relay.max_memory_mb,
            local_relay.default_ttl_seconds,
            local_relay.max_ttl_seconds
        );
        if let Some(ref p) = probe_result {
            let reachable = p.get("reachable").and_then(Value::as_bool).unwrap_or(false);
            let target = p.get("url").and_then(Value::as_str).unwrap_or("-");
            if reachable {
                println!("  Health:      OK ({target})");
                if let Some(dr) = p.get("dropRelay") {
                    println!(
                        "               activeDrops={}, bufferedBytes={}, activeSseStreams={}",
                        dr.get("activeDrops").and_then(Value::as_u64).unwrap_or(0),
                        dr.get("bufferedBytes").and_then(Value::as_u64).unwrap_or(0),
                        dr.get("activeSseStreams")
                            .and_then(Value::as_u64)
                            .unwrap_or(0),
                    );
                }
            } else {
                println!(
                    "  Health:      UNREACHABLE ({target}): {}",
                    p.get("error")
                        .and_then(Value::as_str)
                        .unwrap_or("request failed")
                );
            }
        }
    }
    ExitCode::from(EXIT_OK)
}

async fn probe_relay_health(base_url: &str) -> Value {
    let url = format!("{base_url}/v1/health");
    let client = match build_http_client::<Full<Bytes>>() {
        Ok(c) => c,
        Err(e) => return json!({ "url": url, "reachable": false, "error": e }),
    };
    let req = match Request::builder()
        .method(Method::GET)
        .uri(&url)
        .header(header::ACCEPT, "application/json")
        .body(Full::new(Bytes::new()))
    {
        Ok(r) => r,
        Err(e) => return json!({ "url": url, "reachable": false, "error": e.to_string() }),
    };
    match tokio::time::timeout(
        Duration::from_secs(RELAY_PROBE_TIMEOUT_SECS),
        client.request(req),
    )
    .await
    {
        Ok(Ok(resp)) => {
            let status = resp.status().as_u16();
            let bytes = collect_bounded_body(resp.into_body(), MAX_RELAY_JSON_BYTES)
                .await
                .unwrap_or_default();
            let parsed: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            json!({
                "url": url,
                "reachable": status == 200,
                "httpStatus": status,
                "dropRelay": parsed.get("dropRelay").cloned().unwrap_or(Value::Null),
            })
        }
        Ok(Err(e)) => json!({ "url": url, "reachable": false, "error": e.to_string() }),
        Err(_) => json!({
            "url": url,
            "reachable": false,
            "error": format!("timed out after {RELAY_PROBE_TIMEOUT_SECS}s"),
        }),
    }
}

pub(crate) async fn collect_bounded_body(
    mut body: hyper::body::Incoming,
    max_bytes: usize,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    while let Some(frame_res) = body.frame().await {
        let frame = frame_res.map_err(|e| format!("HTTP body read error: {e}"))?;
        if let Some(chunk) = frame.data_ref() {
            if out.len().saturating_add(chunk.len()) > max_bytes {
                return Err(format!(
                    "HTTP response exceeded {max_bytes} byte safety cap"
                ));
            }
            out.extend_from_slice(chunk);
        }
    }
    Ok(out)
}
