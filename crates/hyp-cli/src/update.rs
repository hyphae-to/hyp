//! `hyp update` — Cryptographically signed self-update, atomic binary swap with
//! smoke-check rollback, `--all` fleet orchestration (remote first, local last), and
//! 48h nightly / 168h stable agent notification cooldown.
//!
//! Security invariants:
//! - Every release manifest is RFC 8785 JCS canonicalized and Ed25519-signed under domain
//!   `"hyphae/v2/release\n"`. Bad signature -> FAIL CLOSED with 0 bytes written.
//! - Anti-rollback: refuses strict version downgrades and publishedAt regressions.
//! - Archive SHA-256 is verified in constant time BEFORE extracting or touching target binary.
//! - Smoke check (`<new_bin> version --json`) MUST pass BEFORE atomic swap (and is verified
//!   with automatic backup rollback via `hyp.prev` on Unix / `hyp.old.exe` on Windows).

use crate::config_file::{
    ct_eq, default_node_id, ensure_v2_node_json_defaults, load_node_or_legacy_config,
    resolve_config_path_for_read, resolve_config_path_for_write, resolve_state_dir,
};
use crate::ui::{
    CliError, CommandResult, EXIT_ERROR, EXIT_OK, JsonEnvelope, print_json, print_next_steps,
    print_warnings,
};
use clap::{Args, Subcommand, ValueEnum};
use hyp_crypto::jcs::to_canonical_json;
use hyp_crypto::keys::Ed25519PublicKey;
use hyp_crypto::pairing::validate_http_endpoint_origin;
use hyp_crypto::rfc3339::parse_rfc3339_millis;
use hyp_crypto::transfer::{TarUnpackOptions, unpack_tar_gz};
use hyp_node::engine::NodeProfile;
use hyp_node::engine::http_fetch::{FetchError, FetchOptions, fetch_bounded_https};
use hyp_node::node_file::NodeFile;
use hyp_store::{NodeDb, PeerRecord, now_ms};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};
use std::time::Duration;

/// Domain-separated prefix for Ed25519 release manifest signatures (`"hyphae/v2/release\n"`).
pub const RELEASE_SIGNING_DOMAIN: &str = "release";

/// Pinned release Ed25519 public key (43-char base64url; overridable via `--pubkey` or `HYPHAE_RELEASE_PUBKEY`).
pub const DEFAULT_RELEASE_PUBKEY_B64: &str = "UJMRGSIIT65-5w2IvGTt5bBsp9SsoCHFTyxMryxLf3U";

pub const DEFAULT_STABLE_MANIFEST_URL: &str =
    "https://github.com/hyphae-to/hyp/releases/latest/download/release-manifest.json";
pub const DEFAULT_NIGHTLY_MANIFEST_URL: &str =
    "https://github.com/hyphae-to/hyp/releases/download/nightly/release-manifest.json";

/// 48-hour cooldown for nightly update notifications.
pub const NIGHTLY_COOLDOWN_MS: i64 = 48 * 3_600 * 1_000;
/// 168-hour (7-day) cooldown for stable update notifications.
pub const STABLE_COOLDOWN_MS: i64 = 168 * 3_600 * 1_000;

pub const META_UPDATE_AVAILABLE_VERSION: &str = "update_available_version";
pub const META_UPDATE_NOTIFIED_VERSION: &str = "update_notified_version";
pub const META_UPDATE_NOTIFIED_AT: &str = "update_notified_at";
pub const META_UPDATE_DISMISSED_VERSION: &str = "update_dismissed_version";
pub const META_UPDATE_CHECKED_AT: &str = "update_checked_at";
pub const META_UPDATE_INSTALLED_PUBLISHED_AT: &str = "update_installed_published_at";

const MAX_MANIFEST_BYTES: usize = 512 * 1024;
const MAX_ARCHIVE_BYTES: usize = 128 * 1024 * 1024;
const HTTP_TIMEOUT_SECS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateChannel {
    Stable,
    Nightly,
}

impl UpdateChannel {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Nightly => "nightly",
        }
    }

    pub const fn default_manifest_url(self) -> &'static str {
        match self {
            Self::Stable => DEFAULT_STABLE_MANIFEST_URL,
            Self::Nightly => DEFAULT_NIGHTLY_MANIFEST_URL,
        }
    }

    pub const fn cooldown_ms(self) -> i64 {
        match self {
            Self::Stable => STABLE_COOLDOWN_MS,
            Self::Nightly => NIGHTLY_COOLDOWN_MS,
        }
    }

    pub fn parse_str(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "stable" => Some(Self::Stable),
            "nightly" => Some(Self::Nightly),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateChannelSetting {
    Stable,
    Nightly,
    Off,
}

impl UpdateChannelSetting {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Nightly => "nightly",
            Self::Off => "off",
        }
    }
}

#[derive(Args)]
pub struct UpdateArgs {
    #[command(subcommand)]
    pub action: Option<UpdateAction>,

    /// Release channel (stable or nightly)
    #[arg(long, value_enum)]
    pub channel: Option<UpdateChannel>,

    /// Require release manifest version to match this exact SemVer (fail-closed)
    #[arg(long)]
    pub version: Option<String>,

    /// Non-interactive confirmation (used by unattended / remote self-update workers)
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Plan and roll out updates across all eligible paired fleet peers (remote first, local last)
    #[arg(long)]
    pub all: bool,

    /// Verify manifest and compute fleet plan without replacing binaries or triggering remote updates
    #[arg(long)]
    pub dry_run: bool,

    /// Override signed release manifest URL (https:// or loopback http://127.0.0.1 for testing)
    #[arg(long)]
    pub manifest_url: Option<String>,

    /// Override pinned Ed25519 release signing public key (43-char base64url)
    #[arg(long, allow_hyphen_values = true)]
    pub pubkey: Option<String>,

    /// Explicit target binary path to atomically replace (defaults to current_exe)
    #[arg(long)]
    pub target_bin: Option<PathBuf>,

    /// Override target triple lookup in manifest artifacts
    #[arg(long)]
    pub target: Option<String>,

    /// Explicit state directory containing node.sqlite
    #[arg(long)]
    pub state_dir: Option<PathBuf>,

    /// Explicit node.json path
    #[arg(long)]
    pub config: Option<PathBuf>,

    /// Skip automatic post-upgrade sync of installed official plugins (`hyp plugin update --all`)
    #[arg(long)]
    pub no_plugins: bool,

    /// Skip automatic restart of an installed background daemon service after binary swap
    #[arg(long)]
    pub no_restart: bool,

    /// Output structured JSON envelope
    #[arg(long)]
    pub json: bool,
}

#[derive(Subcommand)]
pub enum UpdateAction {
    /// Get or persist the update channel (stable | nightly | off) in node.json
    Channel {
        /// New update channel (omit to inspect current channel)
        #[arg(value_enum)]
        value: Option<UpdateChannelSetting>,
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
    /// Fetch and verify a signed release manifest without installing
    Check {
        /// Release channel (stable or nightly)
        #[arg(long, value_enum)]
        channel: Option<UpdateChannel>,
        /// Override signed release manifest URL
        #[arg(long)]
        manifest_url: Option<String>,
        /// Override pinned Ed25519 release signing public key (43-char base64url)
        #[arg(long, allow_hyphen_values = true)]
        pubkey: Option<String>,
        /// Override target triple
        #[arg(long)]
        target: Option<String>,
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
    /// Dismiss agent update notifications for a specific release version
    Dismiss {
        /// Version string to dismiss (e.g. 0.2.0-nightly.20261124)
        version: String,
        /// Explicit state directory containing node.sqlite
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
}

/// Platform artifact descriptor inside a signed release manifest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseArtifact {
    pub url: String,
    pub sha256: String,
    pub size: u64,
}

/// Canonical RFC 8785 JCS payload signed under `"hyphae/v2/release\n"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseManifestPayload {
    pub channel: String,
    pub version: String,
    pub git_sha: String,
    pub published_at: String,
    pub min_protocol: u32,
    pub artifacts: BTreeMap<String, ReleaseArtifact>,
    pub changelog_summary: String,
}

/// Signed wire envelope for `release-manifest.json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedReleaseManifest {
    /// Strict RFC 8785 JCS canonical JSON of `ReleaseManifestPayload`.
    pub payload: String,
    /// Base64url Ed25519 signature over `"hyphae/v2/release\n" || payload`.
    pub sig: String,
}

/// Cached update state surfaced by `status` and `doctor`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CachedUpdateStatus {
    pub channel: String,
    pub current_version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub available_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dismissed_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notified_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notified_at: Option<i64>,
    pub should_notify: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum FleetEligibility {
    Skipped,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetPeerPlan {
    pub peer_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub eligibility: FleetEligibility,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
}

/// Returns the compile-time target triple matching `.github/workflows/release-rust.yml`
/// and `.github/workflows/nightly-rust.yml`.
pub const fn current_target_triple() -> &'static str {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    {
        "aarch64-apple-darwin"
    }
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    {
        "x86_64-apple-darwin"
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", target_env = "musl"))]
    {
        "x86_64-unknown-linux-musl"
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64", not(target_env = "musl")))]
    {
        "x86_64-unknown-linux-gnu"
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        "aarch64-unknown-linux-gnu"
    }
    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        "x86_64-pc-windows-msvc"
    }
    #[cfg(not(any(
        all(target_os = "macos", target_arch = "aarch64"),
        all(target_os = "macos", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "x86_64"),
        all(target_os = "linux", target_arch = "aarch64"),
        all(target_os = "windows", target_arch = "x86_64"),
    )))]
    {
        "unknown-target"
    }
}

/// Evaluates whether an agent should be notified of `available_version`, enforcing:
/// - `off` channel or identical/older version -> `false`
/// - explicitly dismissed version -> `false`
/// - 48h cooldown for `nightly` / 168h cooldown for `stable` since last notification!
pub fn should_notify_agent_of_update(
    channel: UpdateChannel,
    available_version: &str,
    current_version: &str,
    notified_version: Option<&str>,
    notified_at_ms: Option<i64>,
    dismissed_version: Option<&str>,
    now_unix_ms: i64,
) -> bool {
    if available_version.trim().is_empty() || available_version == current_version {
        return false;
    }
    if is_strict_version_downgrade(available_version, current_version) {
        return false;
    }
    if dismissed_version == Some(available_version) {
        return false;
    }
    if notified_version == Some(available_version) {
        if let Some(last_ms) = notified_at_ms {
            let elapsed = now_unix_ms.saturating_sub(last_ms);
            if elapsed < channel.cooldown_ms() {
                return false;
            }
        }
    }
    true
}

/// Reads persisted update notification metadata from `node.sqlite` for `status` & `doctor`.
pub fn read_cached_update_status(
    config_channel: Option<&str>,
    db: Option<&NodeDb>,
    now_unix_ms: i64,
) -> CachedUpdateStatus {
    let channel_str = config_channel
        .unwrap_or("stable")
        .trim()
        .to_ascii_lowercase();
    let current_version = env!("HYPHAE_BUILD_VERSION").to_string();

    let available_version = db.and_then(|d| {
        d.local()
            .get_metadata(META_UPDATE_AVAILABLE_VERSION)
            .ok()
            .flatten()
    });
    let dismissed_version = db.and_then(|d| {
        d.local()
            .get_metadata(META_UPDATE_DISMISSED_VERSION)
            .ok()
            .flatten()
    });
    let notified_version = db.and_then(|d| {
        d.local()
            .get_metadata(META_UPDATE_NOTIFIED_VERSION)
            .ok()
            .flatten()
    });
    let notified_at = db
        .and_then(|d| {
            d.local()
                .get_metadata(META_UPDATE_NOTIFIED_AT)
                .ok()
                .flatten()
        })
        .and_then(|s| s.parse::<i64>().ok());

    let should_notify = match (
        UpdateChannel::parse_str(&channel_str),
        available_version.as_deref(),
    ) {
        (Some(ch), Some(avail)) => should_notify_agent_of_update(
            ch,
            avail,
            &current_version,
            notified_version.as_deref(),
            notified_at,
            dismissed_version.as_deref(),
            now_unix_ms,
        ),
        _ => false,
    };

    CachedUpdateStatus {
        channel: channel_str,
        current_version,
        available_version,
        dismissed_version,
        notified_version,
        notified_at,
        should_notify,
    }
}

/// Strictly verifies a `SignedReleaseManifest` fail-closed:
/// 1. Validates Ed25519 public key (rejecting small-order / non-canonical keys)
/// 2. Verifies Ed25519 signature over `"hyphae/v2/release\n" || payload`
/// 3. Parses `ReleaseManifestPayload` AND verifies strict RFC 8785 JCS canonicalization
/// 4. Checks channel match, RFC 3339 `publishedAt`, anti-rollback (`version` & timestamp),
///    and valid artifact SHA-256 + safe origin URL for `target_triple`.
pub fn verify_release_manifest(
    signed: &SignedReleaseManifest,
    expected_pubkey_b64: &str,
    expected_channel: Option<UpdateChannel>,
    current_version: &str,
    min_published_at_ms: Option<i64>,
) -> Result<(ReleaseManifestPayload, i64), (&'static str, String)> {
    let pk = Ed25519PublicKey::from_b64(expected_pubkey_b64.trim()).map_err(|e| {
        (
            "INVALID_PUBKEY",
            format!("Invalid release Ed25519 public key: {e}"),
        )
    })?;

    pk.verify_domain_b64(
        RELEASE_SIGNING_DOMAIN,
        signed.payload.as_bytes(),
        &signed.sig,
    )
    .map_err(|e| {
        (
            "INVALID_SIGNATURE",
            format!("Release manifest Ed25519 signature verification failed (fail-closed): {e}"),
        )
    })?;

    let payload: ReleaseManifestPayload = serde_json::from_str(&signed.payload).map_err(|e| {
        (
            "INVALID_MANIFEST",
            format!("Malformed ReleaseManifestPayload JSON: {e}"),
        )
    })?;

    let canonical = to_canonical_json(&payload).map_err(|e| {
        (
            "INVALID_MANIFEST",
            format!("Failed to canonicalize release manifest payload: {e}"),
        )
    })?;
    if canonical != signed.payload {
        return Err((
            "NON_CANONICAL_MANIFEST",
            "Signed release manifest payload is not canonical RFC 8785 JCS".to_string(),
        ));
    }

    let manifest_channel = UpdateChannel::parse_str(&payload.channel).ok_or_else(|| {
        (
            "INVALID_MANIFEST",
            format!("Unsupported release channel '{}'", payload.channel),
        )
    })?;
    if let Some(expected) = expected_channel {
        if manifest_channel != expected {
            return Err((
                "CHANNEL_MISMATCH",
                format!(
                    "Release manifest channel '{}' does not match requested channel '{}'",
                    payload.channel,
                    expected.as_str()
                ),
            ));
        }
    }

    if payload.version.trim().is_empty() {
        return Err((
            "INVALID_MANIFEST",
            "Release manifest version is empty".to_string(),
        ));
    }

    let published_ms = parse_rfc3339_millis(&payload.published_at).map_err(|e| {
        (
            "INVALID_MANIFEST",
            format!(
                "Invalid publishedAt timestamp '{}': {e}",
                payload.published_at
            ),
        )
    })?;

    // Anti-rollback check: timestamp regression
    if let Some(min_ms) = min_published_at_ms {
        if published_ms < min_ms {
            return Err((
                "ROLLBACK_DETECTED",
                format!(
                    "Refusing release rollback: manifest publishedAt ({}) precedes previously installed timestamp",
                    payload.published_at
                ),
            ));
        }
    }

    // Anti-rollback check: strict version downgrade
    if is_strict_version_downgrade(&payload.version, current_version) {
        return Err((
            "ROLLBACK_DETECTED",
            format!(
                "Refusing version rollback: manifest version '{}' is older than current '{}'",
                payload.version, current_version
            ),
        ));
    }

    for (triple, art) in &payload.artifacts {
        validate_http_endpoint_origin(&art.url).map_err(|e| {
            (
                "UNSAFE_ARTIFACT_URL",
                format!("Artifact URL for '{triple}' rejected: {e}"),
            )
        })?;
        normalize_sha256_hex(&art.sha256).ok_or_else(|| {
            (
                "INVALID_MANIFEST",
                format!(
                    "Artifact for '{triple}' has invalid sha256 '{}'",
                    art.sha256
                ),
            )
        })?;
    }

    Ok((payload, published_ms))
}

fn normalize_sha256_hex(raw: &str) -> Option<String> {
    let trimmed = raw.trim().strip_prefix("sha256:").unwrap_or(raw.trim());
    if trimmed.len() == 64 && trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
        Some(trimmed.to_ascii_lowercase())
    } else {
        None
    }
}

/// Lightweight SemVer 2.0 comparison (`major.minor.patch[-pre]`) without extra crates.
fn parse_semver_key(v: &str) -> Option<(u64, u64, u64, bool, String)> {
    let stripped = v.trim().strip_prefix('v').unwrap_or(v.trim());
    let no_build = stripped.split('+').next().unwrap_or(stripped);
    let (core, pre) = match no_build.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (no_build, None),
    };
    let mut parts = core.split('.');
    let major: u64 = parts.next()?.parse().ok()?;
    let minor: u64 = parts.next()?.parse().ok()?;
    let patch: u64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    // Final releases (`is_final == true`) sort higher than prereleases of the same major.minor.patch.
    let (is_final, pre_str) = match pre {
        Some(p) => (false, p.to_string()),
        None => (true, String::new()),
    };
    Some((major, minor, patch, is_final, pre_str))
}

fn is_strict_version_downgrade(candidate: &str, current: &str) -> bool {
    let (Some(cand), Some(cur)) = (parse_semver_key(candidate), parse_semver_key(current)) else {
        return false;
    };
    cand < cur
}

pub fn run_update(args: UpdateArgs) -> CommandResult {
    match args.action {
        Some(UpdateAction::Channel {
            value,
            config,
            state_dir,
            json,
        }) => CommandResult::new(
            "update channel",
            json,
            run_update_channel(value, config, state_dir, json),
        ),
        Some(UpdateAction::Check {
            channel,
            manifest_url,
            pubkey,
            target,
            state_dir,
            config,
            json,
        }) => CommandResult::new(
            "update check",
            json,
            run_update_check(
                channel,
                manifest_url,
                pubkey,
                target,
                state_dir,
                config,
                json,
            ),
        ),
        Some(UpdateAction::Dismiss {
            version,
            state_dir,
            json,
        }) => CommandResult::new(
            "update dismiss",
            json,
            run_update_dismiss(version, state_dir, json),
        ),
        None => CommandResult::new("update", args.json, run_update_apply(args)),
    }
}

fn run_update_channel(
    value: Option<UpdateChannelSetting>,
    config: Option<PathBuf>,
    state_dir: Option<PathBuf>,
    as_json: bool,
) -> Result<ExitCode, CliError> {
    let cmd = "update channel";
    let dir = resolve_state_dir(state_dir.as_deref(), config.as_deref(), None);

    match value {
        None => {
            let cfg_path =
                resolve_config_path_for_read(config.as_deref(), state_dir.as_deref(), None);
            let channel = load_node_or_legacy_config(&cfg_path)
                .ok()
                .and_then(|c| c.update_channel)
                .unwrap_or_else(|| "stable".to_string());
            if as_json {
                let envelope = JsonEnvelope::ok(
                    cmd.to_string(),
                    format!("Update channel: {channel}"),
                    json!({
                        "channel": channel,
                        "configPath": cfg_path.display().to_string(),
                    }),
                );
                print_json(&envelope);
            } else {
                println!("OK    Update channel: {channel}");
            }
            Ok(ExitCode::from(EXIT_OK))
        }
        Some(setting) => {
            let cfg_path =
                resolve_config_path_for_write(config.as_deref(), state_dir.as_deref(), None);
            let mut map = NodeFile::read_document_or_empty(&cfg_path)
                .map_err(|e| CliError::error("CONFIG_ERROR", e))?;
            let node_id = map
                .get("nodeId")
                .and_then(Value::as_str)
                .map(ToOwned::to_owned)
                .unwrap_or_else(default_node_id);
            ensure_v2_node_json_defaults(&mut map, &node_id, NodeProfile::Local, &dir);
            let mut update_obj = map
                .get("update")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            update_obj.insert("channel".to_string(), json!(setting.as_str()));
            map.insert("update".to_string(), Value::Object(update_obj));

            NodeFile::write_document(&cfg_path, map).map_err(|e| CliError::error("IO_ERROR", e))?;
            if as_json {
                let envelope = JsonEnvelope::ok(
                    cmd.to_string(),
                    format!("Set update channel to '{}'", setting.as_str()),
                    json!({
                        "channel": setting.as_str(),
                        "configPath": cfg_path.display().to_string(),
                    }),
                )
                .next(vec![format!(
                    "hyp update check --channel {}",
                    setting.as_str()
                )]);
                print_json(&envelope);
            } else {
                println!(
                    "OK    Update channel set to '{}' in {}",
                    setting.as_str(),
                    cfg_path.display()
                );
            }
            Ok(ExitCode::from(EXIT_OK))
        }
    }
}

fn run_update_dismiss(
    version: String,
    state_dir: Option<PathBuf>,
    as_json: bool,
) -> Result<ExitCode, CliError> {
    let cmd = "update dismiss";
    let trimmed = version.trim();
    if trimmed.is_empty() {
        return Err(CliError::usage(
            "INVALID_VERSION",
            "Version to dismiss cannot be empty",
        ));
    }

    let dir = resolve_state_dir(state_dir.as_deref(), None, None);
    let db = NodeDb::open(dir.join("node.sqlite"))
        .map_err(|e| CliError::error("DB_ERROR", e.to_string()))?;
    db.local()
        .set_metadata(META_UPDATE_DISMISSED_VERSION, trimmed)
        .map_err(|e| CliError::error("DB_ERROR", e.to_string()))?;

    if as_json {
        let envelope = JsonEnvelope::ok(
            cmd.to_string(),
            format!("Dismissed update notification for version '{trimmed}'"),
            json!({
                "dismissedVersion": trimmed,
                "stateDir": dir.display().to_string(),
            }),
        );
        print_json(&envelope);
    } else {
        println!("OK    Dismissed update notifications for version '{trimmed}'");
    }
    Ok(ExitCode::from(EXIT_OK))
}

fn resolve_channel(
    explicit: Option<UpdateChannel>,
    config_arg: Option<&Path>,
    state_dir_arg: Option<&Path>,
) -> Result<UpdateChannel, String> {
    if let Some(ch) = explicit {
        return Ok(ch);
    }
    let cfg_path = resolve_config_path_for_read(config_arg, state_dir_arg, None);
    if let Ok(cfg) = load_node_or_legacy_config(&cfg_path) {
        if let Some(ref raw) = cfg.update_channel {
            if raw.eq_ignore_ascii_case("off") {
                return Err(
                    "Automatic updates are disabled (update.channel = 'off'); pass --channel stable|nightly to override."
                        .to_string(),
                );
            }
            if let Some(ch) = UpdateChannel::parse_str(raw) {
                return Ok(ch);
            }
        }
    }
    Ok(UpdateChannel::Stable)
}

fn resolve_pubkey(explicit: Option<&str>) -> String {
    if let Some(k) = explicit {
        return k.trim().to_string();
    }
    if let Ok(env_k) = std::env::var("HYPHAE_RELEASE_PUBKEY") {
        if !env_k.trim().is_empty() {
            return env_k.trim().to_string();
        }
    }
    DEFAULT_RELEASE_PUBKEY_B64.to_string()
}

fn run_update_check(
    channel_arg: Option<UpdateChannel>,
    manifest_url_arg: Option<String>,
    pubkey_arg: Option<String>,
    target_arg: Option<String>,
    state_dir_arg: Option<PathBuf>,
    config_arg: Option<PathBuf>,
    as_json: bool,
) -> Result<ExitCode, CliError> {
    let cmd = "update check";
    let channel = resolve_channel(channel_arg, config_arg.as_deref(), state_dir_arg.as_deref())
        .map_err(|e| CliError::error("UPDATES_DISABLED", e))?;
    let manifest_url =
        manifest_url_arg.unwrap_or_else(|| channel.default_manifest_url().to_string());
    let pubkey = resolve_pubkey(pubkey_arg.as_deref());
    let target_triple = target_arg.unwrap_or_else(|| current_target_triple().to_string());
    let dir = resolve_state_dir(state_dir_arg.as_deref(), config_arg.as_deref(), None);

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            return Err(CliError::error("RUNTIME_ERROR", e.to_string()));
        }
    };

    let signed = match rt.block_on(fetch_signed_manifest(&manifest_url)) {
        Ok(m) => m,
        Err((code, msg)) => return Err(CliError::error(code, msg)),
    };

    let db = NodeDb::open(dir.join("node.sqlite")).ok();
    let min_published = db
        .as_ref()
        .and_then(|d| {
            d.local()
                .get_metadata(META_UPDATE_INSTALLED_PUBLISHED_AT)
                .ok()
                .flatten()
        })
        .and_then(|s| s.parse::<i64>().ok());

    let current_version = env!("HYPHAE_BUILD_VERSION");
    let (manifest, _published_ms) = match verify_release_manifest(
        &signed,
        &pubkey,
        Some(channel),
        current_version,
        min_published,
    ) {
        Ok(v) => v,
        Err((code, msg)) => return Err(CliError::error(code, msg)),
    };

    let artifact = manifest.artifacts.get(&target_triple);
    let update_available = manifest.version != current_version;
    let now = now_ms();

    let mut should_notify = false;
    if let Some(ref db) = db {
        let notified_ver = db
            .local()
            .get_metadata(META_UPDATE_NOTIFIED_VERSION)
            .ok()
            .flatten();
        let notified_at = db
            .local()
            .get_metadata(META_UPDATE_NOTIFIED_AT)
            .ok()
            .flatten()
            .and_then(|s| s.parse::<i64>().ok());
        let dismissed_ver = db
            .local()
            .get_metadata(META_UPDATE_DISMISSED_VERSION)
            .ok()
            .flatten();

        should_notify = should_notify_agent_of_update(
            channel,
            &manifest.version,
            current_version,
            notified_ver.as_deref(),
            notified_at,
            dismissed_ver.as_deref(),
            now,
        );

        let _ = db
            .local()
            .set_metadata(META_UPDATE_AVAILABLE_VERSION, &manifest.version);
        let _ = db
            .local()
            .set_metadata(META_UPDATE_CHECKED_AT, &now.to_string());
        if should_notify {
            let _ = db
                .local()
                .set_metadata(META_UPDATE_NOTIFIED_VERSION, &manifest.version);
            let _ = db
                .local()
                .set_metadata(META_UPDATE_NOTIFIED_AT, &now.to_string());
        }
    }

    let mut next = Vec::new();
    if update_available {
        next.push(format!("hyp update --channel {}", channel.as_str()));
        next.push(format!("hyp update dismiss {}", manifest.version));
    }

    if as_json {
        let envelope = JsonEnvelope::ok(
            cmd.to_string(),
            format!(
                "Verified {} manifest {} (current: {}, updateAvailable: {})",
                manifest.channel, manifest.version, current_version, update_available
            ),
            json!({
                "channel": manifest.channel,
                "currentVersion": current_version,
                "latestVersion": manifest.version,
                "gitSha": manifest.git_sha,
                "publishedAt": manifest.published_at,
                "minProtocol": manifest.min_protocol,
                "changelogSummary": manifest.changelog_summary,
                "target": target_triple,
                "artifactPresent": artifact.is_some(),
                "artifact": artifact,
                "signatureVerified": true,
                "updateAvailable": update_available,
                "shouldNotify": should_notify,
            }),
        )
        .next(next);
        print_json(&envelope);
    } else {
        println!(
            "OK    Verified signed {} manifest: {} (current: {})",
            manifest.channel, manifest.version, current_version
        );
        println!("      Published: {}", manifest.published_at);
        println!("      Git SHA:   {}", manifest.git_sha);
        println!("      Target:    {}", target_triple);
        println!("      Summary:   {}", manifest.changelog_summary);
        println!("      Notify:    {should_notify}");
        print_next_steps(&next);
    }
    Ok(ExitCode::from(EXIT_OK))
}

fn run_update_apply(args: UpdateArgs) -> Result<ExitCode, CliError> {
    let cmd = "update";
    let as_json = args.json;
    let channel = resolve_channel(
        args.channel,
        args.config.as_deref(),
        args.state_dir.as_deref(),
    )
    .map_err(|e| CliError::error("UPDATES_DISABLED", e))?;
    let manifest_url = args
        .manifest_url
        .clone()
        .unwrap_or_else(|| channel.default_manifest_url().to_string());
    let pubkey = resolve_pubkey(args.pubkey.as_deref());
    let target_triple = args
        .target
        .clone()
        .unwrap_or_else(|| current_target_triple().to_string());
    let dir = resolve_state_dir(args.state_dir.as_deref(), args.config.as_deref(), None);

    let target_bin = match args.target_bin.clone() {
        Some(p) => p,
        None => match std::env::current_exe() {
            Ok(p) => p,
            Err(e) => {
                return Err(CliError::error(
                    "BIN_PATH_ERROR",
                    format!("Failed to locate current executable: {e}"),
                ));
            }
        },
    };

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            return Err(CliError::error("RUNTIME_ERROR", e.to_string()));
        }
    };

    // 1. Fetch & cryptographically verify signed release manifest (FAIL CLOSED!).
    let signed = match rt.block_on(fetch_signed_manifest(&manifest_url)) {
        Ok(m) => m,
        Err((code, msg)) => return Err(CliError::error(code, msg)),
    };

    let db = NodeDb::open(dir.join("node.sqlite")).ok();
    let min_published = db
        .as_ref()
        .and_then(|d| {
            d.local()
                .get_metadata(META_UPDATE_INSTALLED_PUBLISHED_AT)
                .ok()
                .flatten()
        })
        .and_then(|s| s.parse::<i64>().ok());

    let current_version = env!("HYPHAE_BUILD_VERSION");
    let (manifest, published_ms) = match verify_release_manifest(
        &signed,
        &pubkey,
        Some(channel),
        current_version,
        min_published,
    ) {
        Ok(v) => v,
        Err((code, msg)) => return Err(CliError::error(code, msg)),
    };

    if let Some(ref requested_version) = args.version {
        let req_ver = requested_version.trim();
        if manifest.version != req_ver {
            return Err(CliError::error(
                "VERSION_MISMATCH",
                format!(
                    "Requested version '{req_ver}' does not match verified release manifest version '{}'",
                    manifest.version
                ),
            ));
        }
    }

    let Some(artifact) = manifest.artifacts.get(&target_triple) else {
        return Err(CliError::error(
            "TARGET_NOT_FOUND",
            format!("Release manifest has no artifact for target '{target_triple}'"),
        ));
    };
    let expected_sha256 = normalize_sha256_hex(&artifact.sha256).expect("validated above");

    // 2. Build `--all` fleet plan (remote eligible peers FIRST, local LAST!).
    let mut fleet_plan: Vec<FleetPeerPlan> = Vec::new();
    let mut rollout_order: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    if args.all {
        if let Some(ref db) = db {
            if let Ok(peers) = db.peers().list_peers(None) {
                for peer in &peers {
                    let mut entry = classify_fleet_peer(peer);
                    entry.outcome = Some("SKIPPED".to_string());
                    fleet_plan.push(entry);
                }
            }
        }
        if !fleet_plan.is_empty() {
            warnings.push(format!(
                "Remote fleet self-update is planned for a future release; skipped {} remote peer(s) and updating local node only.",
                fleet_plan.len()
            ));
        }
    }

    if args.dry_run {
        rollout_order.push("local".to_string());
        if as_json {
            let envelope = JsonEnvelope::ok(
                cmd.to_string(),
                format!(
                    "Dry-run verified {} {} (target {})",
                    manifest.channel, manifest.version, target_triple
                ),
                json!({
                    "dryRun": true,
                    "channel": manifest.channel,
                    "version": manifest.version,
                    "target": target_triple,
                    "targetBin": target_bin.display().to_string(),
                    "signatureVerified": true,
                    "fleetAll": args.all,
                    "fleetPlan": fleet_plan,
                    "rolloutOrder": rollout_order,
                }),
            )
            .warnings(warnings)
            .next(vec![format!(
                "Re-run without --dry-run to apply {}",
                manifest.version
            )]);
            print_json(&envelope);
        } else {
            println!(
                "PLAN  Verified {} {} (target={}, dry-run)",
                manifest.channel, manifest.version, target_triple
            );
            print_fleet_table(&fleet_plan);
        }
        return Ok(ExitCode::from(EXIT_OK));
    }

    // 3. Download archive bytes & verify SHA-256 fail-closed BEFORE touching target binary!
    let archive_bytes = match rt.block_on(download_bytes(&artifact.url, MAX_ARCHIVE_BYTES)) {
        Ok(b) => b,
        Err((code, msg)) => return Err(CliError::error(code, msg)),
    };

    let actual_sha256 = hex::encode(Sha256::digest(&archive_bytes));
    if !ct_eq(actual_sha256.as_bytes(), expected_sha256.as_bytes()) {
        return Err(CliError::error("CHECKSUM_MISMATCH", format!(
                "Archive SHA-256 mismatch (fail-closed, 0 bytes written): expected {expected_sha256}, got {actual_sha256}"
            )).with_fix("Aborting update; verify release artifact integrity.".to_string()));
    }
    if artifact.size > 0 && archive_bytes.len() as u64 != artifact.size {
        return Err(CliError::error(
            "SIZE_MISMATCH",
            format!(
                "Archive byte length mismatch (fail-closed, 0 bytes written): expected {}, got {}",
                artifact.size,
                archive_bytes.len()
            ),
        ));
    }

    // 4. Stage, unpack, smoke-check (`version --json`), atomically swap with backup & rollback!
    let swap_res = match stage_smoke_check_and_swap(&target_bin, &artifact.url, &archive_bytes) {
        Ok(r) => r,
        Err(swap_err) => {
            if as_json {
                let envelope = JsonEnvelope::ok(cmd, swap_err.message.clone(), json!({
                        "targetBin": target_bin.display().to_string(),
                        "rolledBack": swap_err.rolled_back,
                        "originalPreserved": swap_err.original_preserved,
                        "smokeCheckPassed": false,
                        "fleetPlan": fleet_plan,
                    })).warnings(warnings).error(Some(CliError::error(swap_err.code.to_string(), swap_err.message).with_fix("Original binary remains intact; inspect the release artifact before retrying.".to_string())));
                print_json(&envelope);
            } else {
                eprintln!("FAIL [{}] {}", swap_err.code, swap_err.message);
                if swap_err.original_preserved {
                    eprintln!(
                        "OK    Original binary preserved intact at {}",
                        target_bin.display()
                    );
                }
            }
            return Ok(ExitCode::from(EXIT_ERROR));
        }
    };

    rollout_order.push("local".to_string());

    // Persist installed metadata for future anti-rollback & cooldown checks.
    if let Some(ref db) = db {
        let now = now_ms();
        let _ = db
            .local()
            .set_metadata(META_UPDATE_AVAILABLE_VERSION, &manifest.version);
        let _ = db.local().set_metadata(
            META_UPDATE_INSTALLED_PUBLISHED_AT,
            &published_ms.to_string(),
        );
        let _ = db
            .local()
            .set_metadata(META_UPDATE_CHECKED_AT, &now.to_string());
    }

    let mut next = vec!["hyp version --json".to_string()];

    // 5. Post-upgrade selective plugin sync (best-effort, non-fatal if offline, skippable via `--no-plugins`).
    let plugins_artifact_url = manifest.artifacts.get("plugins").map(|a| a.url.as_str());
    let plugins_sync = run_post_upgrade_plugin_sync(
        &target_bin,
        &dir,
        args.config.as_deref(),
        plugins_artifact_url,
        args.no_plugins,
        &mut warnings,
        &mut next,
    );

    // 6. Auto-restart managed background daemon service unless `--no-restart` or `HYPHAE_NO_SERVICE_RESTART=1`.
    let service_restart = run_post_upgrade_service_restart(
        args.state_dir.as_deref(),
        args.no_restart,
        &mut warnings,
        &mut next,
    );
    let service_restarted = service_restart.restarted;

    let remote_failed = fleet_plan.iter().any(|p| {
        p.outcome
            .as_deref()
            .is_some_and(|o| o.starts_with("FAILED"))
    });
    let ok = !remote_failed;

    if as_json {
        let envelope = JsonEnvelope::ok(
            cmd,
            format!(
                "Updated local binary {} to {} ({})",
                target_bin.display(),
                manifest.version,
                manifest.channel
            ),
            json!({
                "channel": manifest.channel,
                "version": manifest.version,
                "gitSha": manifest.git_sha,
                "publishedAt": manifest.published_at,
                "target": target_triple,
                "targetBin": target_bin.display().to_string(),
                "backupBin": swap_res.backup_path.as_ref().map(|p| p.display().to_string()),
                "sha256": actual_sha256,
                "signatureVerified": true,
                "smokeCheckPassed": true,
                "smokeVersion": swap_res.smoke_version,
                "pluginsSync": plugins_sync,
                "serviceRestarted": service_restarted,
                "serviceRestart": service_restart,
                "fleetAll": args.all,
                "fleetPlan": fleet_plan,
                "rolloutOrder": rollout_order,
            }),
        )
        .warnings(warnings)
        .next(next)
        .error(if ok {
            None
        } else {
            Some(CliError::error(
                "FLEET_PARTIAL_FAILURE".to_string(),
                "Local node updated, but one or more remote peers failed to update".to_string(),
            ))
        });
        print_json(&envelope);
    } else {
        println!(
            "OK    Updated {} -> {} ({})",
            target_bin.display(),
            manifest.version,
            manifest.channel
        );
        println!("      SHA-256: {}", actual_sha256);
        println!("      Smoke:   OK ({})", swap_res.smoke_version);
        if let Some(ref b) = swap_res.backup_path {
            println!("      Backup:  {}", b.display());
        }
        if let Some(summary_str) = plugins_sync.get("summary").and_then(Value::as_str) {
            println!("      Plugins: {summary_str}");
        }
        println!("      Service: {}", service_restart.detail);
        if args.all {
            print_fleet_table(&fleet_plan);
        }
        print_warnings(&warnings);
        print_next_steps(&next);
    }

    if ok {
        Ok(ExitCode::from(EXIT_OK))
    } else {
        Ok(ExitCode::from(EXIT_ERROR))
    }
}

fn env_disables_service_restart() -> bool {
    std::env::var("HYPHAE_NO_SERVICE_RESTART")
        .ok()
        .is_some_and(|raw| {
            matches!(
                raw.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            )
        })
}

fn run_post_upgrade_service_restart(
    state_dir_arg: Option<&Path>,
    no_restart: bool,
    warnings: &mut Vec<String>,
    next: &mut Vec<String>,
) -> crate::service::ServiceRestartOutcome {
    let restart_cmd = "hyp service restart --json".to_string();
    if no_restart || env_disables_service_restart() {
        let reason = if no_restart {
            "no_restart_flag"
        } else {
            "env_disabled"
        };
        if !next.contains(&restart_cmd) {
            next.push(restart_cmd);
        }
        return crate::service::ServiceRestartOutcome {
            attempted: false,
            installed: false,
            restarted: false,
            skipped: true,
            skip_reason: Some(reason.to_string()),
            error: None,
            detail: format!("skipped ({reason})"),
        };
    }

    let outcome = crate::service::restart_if_installed(None, state_dir_arg);
    if let Some(ref err) = outcome.error {
        warnings.push(format!(
            "Binary updated, but automatic background service restart failed ({err}); run `hyp service restart --json`."
        ));
        if !next.contains(&restart_cmd) {
            next.push(restart_cmd);
        }
    } else if outcome.skipped {
        warnings.push(outcome.detail.clone());
        if !next.contains(&restart_cmd) {
            next.push(restart_cmd);
        }
    }
    outcome
}

fn build_post_upgrade_plugin_sync_command(
    new_bin: &Path,
    state_dir: &Path,
    config_path: Option<&Path>,
    plugins_artifact_url: Option<&str>,
    caller_plugins_url_env: Option<&str>,
) -> Command {
    let mut cmd = Command::new(new_bin);
    cmd.args(["plugin", "update", "--all", "--state-dir"])
        .arg(state_dir);
    if let Some(cfg) = config_path {
        cmd.arg("--config").arg(cfg);
    }
    let has_caller_override = caller_plugins_url_env
        .map(str::trim)
        .is_some_and(|v| !v.is_empty());
    if !has_caller_override {
        if let Some(url) = plugins_artifact_url
            .map(str::trim)
            .filter(|v| !v.is_empty())
        {
            cmd.env("HYPHAE_PLUGINS_URL", url);
        }
    }
    cmd.arg("--json");
    cmd
}

/// Invokes `<new_hyp> plugin update --all --json` after a successful binary swap so installed
/// bridges and harness UI mods stay selectively synced. Strictly best-effort & non-fatal (offline
/// or modified plugins produce clear warnings and actionable `next` commands without failing the
/// binary upgrade).
fn run_post_upgrade_plugin_sync(
    new_bin: &Path,
    state_dir: &Path,
    config_path: Option<&Path>,
    plugins_artifact_url: Option<&str>,
    no_plugins: bool,
    warnings: &mut Vec<String>,
    next: &mut Vec<String>,
) -> Value {
    if no_plugins {
        let has_receipts = crate::plugin_cmd::receipts_file_path(state_dir).is_file();
        if has_receipts {
            next.push("hyp plugin update --all".to_string());
        }
        return json!({
            "skipped": true,
            "reason": "no_plugins_flag",
            "summary": "skipped (--no-plugins)",
            "updated": [],
            "upToDate": [],
            "modified": [],
        });
    }

    let caller_plugins_url_env = std::env::var("HYPHAE_PLUGINS_URL").ok();
    let mut cmd = build_post_upgrade_plugin_sync_command(
        new_bin,
        state_dir,
        config_path,
        plugins_artifact_url,
        caller_plugins_url_env.as_deref(),
    );

    match cmd.output() {
        Ok(out) => {
            if let Ok(parsed) = serde_json::from_slice::<Value>(&out.stdout) {
                if parsed.get("ok") == Some(&Value::Bool(true)) {
                    let data = parsed.get("data");
                    let updated: Vec<String> = data
                        .and_then(|d| d.get("updated"))
                        .and_then(Value::as_array)
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                                .collect()
                        })
                        .unwrap_or_default();
                    let up_to_date: Vec<String> = data
                        .and_then(|d| d.get("upToDate"))
                        .and_then(Value::as_array)
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                                .collect()
                        })
                        .unwrap_or_default();
                    let modified: Vec<String> = data
                        .and_then(|d| d.get("modified"))
                        .and_then(Value::as_array)
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                                .collect()
                        })
                        .unwrap_or_default();
                    let corrupt: Vec<String> = data
                        .and_then(|d| d.get("corrupt"))
                        .and_then(Value::as_array)
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(ToOwned::to_owned))
                                .collect()
                        })
                        .unwrap_or_default();
                    if let Some(plugin_warnings) = parsed.get("warnings").and_then(Value::as_array)
                    {
                        for w in plugin_warnings {
                            if let Some(s) = w.as_str() {
                                warnings.push(format!("plugin sync: {s}"));
                            }
                        }
                    }
                    if let Some(hints) = data
                        .and_then(|d| d.get("reloadHints"))
                        .and_then(Value::as_array)
                    {
                        for h in hints {
                            if let Some(s) = h.as_str() {
                                let owned = s.to_string();
                                if !next.contains(&owned) {
                                    next.push(owned);
                                }
                            }
                        }
                    }
                    let summary = if updated.is_empty() && modified.is_empty() && corrupt.is_empty()
                    {
                        if up_to_date.is_empty() {
                            "none installed (0 downloads)".to_string()
                        } else {
                            format!("{} up to date (0 downloads)", up_to_date.len())
                        }
                    } else {
                        format!(
                            "{} updated, {} up to date, {} modified skipped",
                            updated.len(),
                            up_to_date.len(),
                            modified.len()
                        )
                    };
                    return json!({
                        "skipped": false,
                        "ok": true,
                        "summary": summary,
                        "updated": updated,
                        "upToDate": up_to_date,
                        "modified": modified,
                        "corrupt": corrupt,
                    });
                }
                let err_msg = parsed
                    .get("error")
                    .and_then(|e| e.get("message"))
                    .and_then(Value::as_str)
                    .unwrap_or("plugin sync returned non-ok status");
                warnings.push(format!(
                    "Post-upgrade plugin sync did not complete ({err_msg}); run `hyp plugin update --all` manually."
                ));
                next.push("hyp plugin update --all".to_string());
                json!({
                    "skipped": false,
                    "ok": false,
                    "summary": format!("deferred ({err_msg})"),
                    "error": err_msg,
                })
            } else {
                let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
                let detail = if stderr.is_empty() {
                    format!("exit status {:?}", out.status.code())
                } else {
                    stderr
                };
                warnings.push(format!(
                    "Post-upgrade plugin sync skipped ({detail}); run `hyp plugin update --all` manually."
                ));
                next.push("hyp plugin update --all".to_string());
                json!({
                    "skipped": false,
                    "ok": false,
                    "summary": format!("deferred ({detail})"),
                    "error": detail,
                })
            }
        }
        Err(e) => {
            warnings.push(format!(
                "Failed to invoke post-upgrade plugin sync ({e}); run `hyp plugin update --all` manually."
            ));
            next.push("hyp plugin update --all".to_string());
            json!({
                "skipped": false,
                "ok": false,
                "summary": format!("deferred ({e})"),
                "error": e.to_string(),
            })
        }
    }
}

fn print_fleet_table(plan: &[FleetPeerPlan]) {
    if plan.is_empty() {
        return;
    }
    println!();
    println!("Fleet Update Plan (remote first, local last)");
    println!(
        "{:<10}  {:<22}  {:<10}  Reason",
        "Eligible", "Peer", "Outcome"
    );
    println!("{}", "-".repeat(86));
    for p in plan {
        println!(
            "{:<10}  {:<22}  {:<10}  {}",
            match p.eligibility {
                FleetEligibility::Skipped => "SKIPPED",
            },
            p.peer_id,
            p.outcome.as_deref().unwrap_or("-"),
            p.reason
        );
    }
}

/// Classifies a paired peer for `hyp update --all`.
///
/// Remote fleet self-update (`POST /v1/node/update`) is not shipped in `v0.7.0`, so every remote
/// peer is cleanly classified as `SKIPPED` without issuing any remote HTTP request.
pub fn classify_fleet_peer(peer: &PeerRecord) -> FleetPeerPlan {
    FleetPeerPlan {
        peer_id: peer.peer_id.clone(),
        endpoint: peer.endpoint.clone(),
        eligibility: FleetEligibility::Skipped,
        reason: "remote fleet self-update is planned for a future release".to_string(),
        outcome: None,
    }
}

async fn fetch_signed_manifest(url: &str) -> Result<SignedReleaseManifest, (&'static str, String)> {
    let bytes = download_bytes(url, MAX_MANIFEST_BYTES).await?;
    serde_json::from_slice::<SignedReleaseManifest>(&bytes).map_err(|e| {
        (
            "INVALID_MANIFEST",
            format!("Release manifest at {url} is not a valid SignedReleaseManifest: {e}"),
        )
    })
}

const MAX_REDIRECTS: usize = 5;

fn resolve_redirect_url(
    current_uri: &http::Uri,
    location: &str,
) -> Result<http::Uri, (&'static str, String)> {
    hyp_node::engine::http_fetch::resolve_redirect_url(current_uri, location, true, |url| {
        validate_http_endpoint_origin(url).map_err(|e| {
            FetchError::new(
                "UNSAFE_REDIRECT",
                format!("Refusing unsafe redirect '{url}': {e}"),
            )
        })?;
        url.parse().map_err(|e| {
            FetchError::new(
                "UNSAFE_REDIRECT",
                format!("Invalid redirect URL '{url}': {e}"),
            )
        })
    })
    .map(|(uri, _)| uri)
    .map_err(|error| (error.code, error.message))
}

async fn download_bytes(url: &str, max_bytes: usize) -> Result<Vec<u8>, (&'static str, String)> {
    fetch_bounded_https(
        url,
        FetchOptions {
            max_bytes,
            max_redirects: MAX_REDIRECTS,
            request_timeout: Duration::from_secs(HTTP_TIMEOUT_SECS),
            user_agent: format!("hyp/{}", env!("HYPHAE_BUILD_VERSION")),
            display_url: |url| url.to_string(),
        },
        |url| {
            validate_http_endpoint_origin(url).map_err(|e| {
                FetchError::new("UNSAFE_URL", format!("Refusing unsafe URL '{url}': {e}"))
            })?;
            url.parse()
                .map_err(|e| FetchError::new("INVALID_URL", format!("Invalid URL '{url}': {e}")))
        },
        |current, location| {
            let uri = resolve_redirect_url(current, location)
                .map_err(|(code, message)| FetchError::new(code, message))?;
            let source = uri.to_string();
            Ok((uri, source))
        },
    )
    .await
    .map(|(bytes, _)| bytes)
    .map_err(|error| (error.code, error.message))
}

struct SwapSuccess {
    backup_path: Option<PathBuf>,
    smoke_version: String,
}

struct SwapFailure {
    code: &'static str,
    message: String,
    rolled_back: bool,
    original_preserved: bool,
}

fn backup_binary_path(target_bin: &Path) -> PathBuf {
    let parent = target_bin.parent().unwrap_or_else(|| Path::new("."));
    #[cfg(windows)]
    {
        let stem = target_bin
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("hyp");
        parent.join(format!("{stem}.old.exe"))
    }
    #[cfg(not(windows))]
    {
        let name = target_bin
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("hyp");
        parent.join(format!("{name}.prev"))
    }
}

fn random_suffix_hex() -> Result<String, String> {
    let rng = SystemRandom::new();
    let mut b = [0u8; 8];
    rng.fill(&mut b)
        .map_err(|_| "OS CSPRNG failure".to_string())?;
    Ok(hex::encode(b))
}

fn stage_smoke_check_and_swap(
    target_bin: &Path,
    artifact_url: &str,
    archive_bytes: &[u8],
) -> Result<SwapSuccess, SwapFailure> {
    let parent = target_bin
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|e| SwapFailure {
        code: "IO_ERROR",
        message: format!(
            "Failed to prepare target directory {}: {e}",
            parent.display()
        ),
        rolled_back: false,
        original_preserved: true,
    })?;

    let suffix = random_suffix_hex().map_err(|e| SwapFailure {
        code: "RNG_ERROR",
        message: e,
        rolled_back: false,
        original_preserved: true,
    })?;
    let stage_dir = parent.join(format!(".hyp-update-stage-{suffix}"));
    fs::create_dir_all(&stage_dir).map_err(|e| SwapFailure {
        code: "IO_ERROR",
        message: format!("Failed to create staging dir {}: {e}", stage_dir.display()),
        rolled_back: false,
        original_preserved: true,
    })?;

    let result = (|| -> Result<SwapSuccess, SwapFailure> {
        let staged_bin = extract_binary_into_stage(&stage_dir, artifact_url, archive_bytes)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&staged_bin, fs::Permissions::from_mode(0o755)).map_err(|e| {
                SwapFailure {
                    code: "IO_ERROR",
                    message: format!("Failed to mark staged binary executable: {e}"),
                    rolled_back: false,
                    original_preserved: true,
                }
            })?;
        }

        // Pre-swap smoke check: `<new_bin> version --json` MUST succeed before touching target_bin!
        let smoke_version = run_binary_smoke_check(&staged_bin).map_err(|e| SwapFailure {
            code: "SMOKE_CHECK_FAILED",
            message: format!(
                "New binary failed pre-swap smoke check (`version --json`); rolled back without replacing original: {e}"
            ),
            rolled_back: true,
            original_preserved: true,
        })?;

        let had_original = target_bin.exists();
        let backup_path = had_original.then(|| backup_binary_path(target_bin));

        // Perform atomic swap with backup + post-swap verification + automatic rollback.
        if let Some(ref backup) = backup_path {
            #[cfg(windows)]
            {
                let _ = fs::remove_file(backup);
                fs::rename(target_bin, backup).map_err(|e| SwapFailure {
                    code: "SWAP_FAILED",
                    message: format!(
                        "Failed to rename current binary to {}: {e}",
                        backup.display()
                    ),
                    rolled_back: false,
                    original_preserved: true,
                })?;
            }
            #[cfg(not(windows))]
            {
                fs::copy(target_bin, backup).map_err(|e| SwapFailure {
                    code: "BACKUP_FAILED",
                    message: format!(
                        "Failed to back up current binary to {}: {e}",
                        backup.display()
                    ),
                    rolled_back: false,
                    original_preserved: true,
                })?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(backup, fs::Permissions::from_mode(0o755));
                }
            }
        }

        if let Err(e) = fs::rename(&staged_bin, target_bin) {
            if let Some(ref backup) = backup_path {
                let _ = fs::rename(backup, target_bin);
            }
            return Err(SwapFailure {
                code: "SWAP_FAILED",
                message: format!(
                    "Failed atomic binary swap into {}: {e}",
                    target_bin.display()
                ),
                rolled_back: true,
                original_preserved: true,
            });
        }

        // Post-swap smoke verification — auto-rollback from backup if anything went wrong!
        if let Err(e) = run_binary_smoke_check(target_bin) {
            if let Some(ref backup) = backup_path {
                if fs::copy(backup, target_bin).is_err() {
                    let _ = fs::rename(backup, target_bin);
                }
            }
            return Err(SwapFailure {
                code: "POST_SWAP_SMOKE_FAILED",
                message: format!("Post-swap smoke check failed; restored backup: {e}"),
                rolled_back: true,
                original_preserved: true,
            });
        }

        Ok(SwapSuccess {
            backup_path,
            smoke_version,
        })
    })();

    let _ = fs::remove_dir_all(&stage_dir);
    result
}

fn extract_binary_into_stage(
    stage_dir: &Path,
    artifact_url: &str,
    archive_bytes: &[u8],
) -> Result<PathBuf, SwapFailure> {
    let is_gzip = archive_bytes.len() >= 2 && archive_bytes[0] == 0x1f && archive_bytes[1] == 0x8b;
    let is_zip = archive_bytes.len() >= 4 && &archive_bytes[..4] == b"PK\x03\x04";

    if is_gzip || artifact_url.ends_with(".tar.gz") || artifact_url.ends_with(".tgz") {
        let unpacked = unpack_tar_gz(
            Cursor::new(archive_bytes),
            stage_dir,
            &TarUnpackOptions {
                max_files: 32,
                max_raw_bytes: MAX_ARCHIVE_BYTES as u64,
                attachment_guard: None,
            },
        )
        .map_err(|e| SwapFailure {
            code: "EXTRACT_FAILED",
            message: format!("Failed to safely unpack tar.gz release archive: {e}"),
            rolled_back: false,
            original_preserved: true,
        })?;

        let candidate = unpacked
            .files
            .iter()
            .find(|f| {
                let name = Path::new(&f.archive_path)
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("");
                matches!(name, "hyp" | "hyp-rs" | "hyp.exe" | "hyp-rs.exe")
            })
            .or_else(|| {
                if unpacked.files.len() == 1 {
                    unpacked.files.first()
                } else {
                    None
                }
            })
            .ok_or_else(|| SwapFailure {
                code: "EXTRACT_FAILED",
                message: "Release tar.gz archive did not contain a 'hyp' executable".to_string(),
                rolled_back: false,
                original_preserved: true,
            })?;
        return Ok(candidate.disk_path.clone());
    }

    if is_zip || artifact_url.ends_with(".zip") {
        let zip_path = stage_dir.join("release.zip");
        fs::write(&zip_path, archive_bytes).map_err(|e| SwapFailure {
            code: "IO_ERROR",
            message: format!("Failed writing staged zip archive: {e}"),
            rolled_back: false,
            original_preserved: true,
        })?;
        let out_dir = stage_dir.join("unzipped");
        fs::create_dir_all(&out_dir).map_err(|e| SwapFailure {
            code: "IO_ERROR",
            message: format!("Failed creating unzip dir: {e}"),
            rolled_back: false,
            original_preserved: true,
        })?;
        #[cfg(windows)]
        let status = Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                &format!(
                    "Expand-Archive -LiteralPath '{}' -DestinationPath '{}' -Force",
                    zip_path.display(),
                    out_dir.display()
                ),
            ])
            .status();
        #[cfg(not(windows))]
        let status = Command::new("unzip")
            .args(["-o", "-q"])
            .arg(&zip_path)
            .arg("-d")
            .arg(&out_dir)
            .status();

        match status {
            Ok(s) if s.success() => {
                for name in ["hyp.exe", "hyp-rs.exe", "hyp", "hyp-rs"] {
                    let cand = out_dir.join(name);
                    if cand.is_file() {
                        return Ok(cand);
                    }
                }
                return Err(SwapFailure {
                    code: "EXTRACT_FAILED",
                    message: "Zip release archive did not contain hyp executable".to_string(),
                    rolled_back: false,
                    original_preserved: true,
                });
            }
            Ok(s) => {
                return Err(SwapFailure {
                    code: "EXTRACT_FAILED",
                    message: format!("Zip extraction exited with status {:?}", s.code()),
                    rolled_back: false,
                    original_preserved: true,
                });
            }
            Err(e) => {
                return Err(SwapFailure {
                    code: "EXTRACT_FAILED",
                    message: format!("Failed to extract zip release archive: {e}"),
                    rolled_back: false,
                    original_preserved: true,
                });
            }
        }
    }

    // Raw executable payload
    let bin_name = if cfg!(windows) { "hyp.exe" } else { "hyp" };
    let staged_bin = stage_dir.join(bin_name);
    fs::write(&staged_bin, archive_bytes).map_err(|e| SwapFailure {
        code: "IO_ERROR",
        message: format!("Failed writing staged binary: {e}"),
        rolled_back: false,
        original_preserved: true,
    })?;
    Ok(staged_bin)
}

fn run_binary_smoke_check(bin_path: &Path) -> Result<String, String> {
    let output = Command::new(bin_path)
        .args(["version", "--json"])
        .output()
        .map_err(|e| format!("failed to execute {}: {e}", bin_path.display()))?;
    if !output.status.success() {
        return Err(format!(
            "exited with {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let parsed: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| format!("invalid JSON from `version --json`: {e}"))?;
    if parsed.get("ok") != Some(&Value::Bool(true))
        || parsed.get("command").and_then(Value::as_str) != Some("version")
    {
        return Err(
            "`version --json` envelope did not report ok=true, command='version'".to_string(),
        );
    }
    let ver = parsed
        .get("data")
        .and_then(|d| d.get("version"))
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    Ok(ver)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyp_crypto::keys::Ed25519KeyPair;

    #[test]
    fn cooldown_48h_nightly_168h_stable_and_dismiss() {
        let t0 = 1_700_000_000_000i64;
        // First notice -> true
        assert!(should_notify_agent_of_update(
            UpdateChannel::Nightly,
            "0.2.0-nightly.20261124",
            "0.2.0-alpha.0",
            None,
            None,
            None,
            t0
        ));
        // Within 48h nightly cooldown -> false
        assert!(!should_notify_agent_of_update(
            UpdateChannel::Nightly,
            "0.2.0-nightly.20261124",
            "0.2.0-alpha.0",
            Some("0.2.0-nightly.20261124"),
            Some(t0),
            None,
            t0 + NIGHTLY_COOLDOWN_MS - 1_000
        ));
        // After 48h nightly cooldown -> true
        assert!(should_notify_agent_of_update(
            UpdateChannel::Nightly,
            "0.2.0-nightly.20261124",
            "0.2.0-alpha.0",
            Some("0.2.0-nightly.20261124"),
            Some(t0),
            None,
            t0 + NIGHTLY_COOLDOWN_MS
        ));
        // Stable within 168h -> false; after 168h -> true
        assert!(!should_notify_agent_of_update(
            UpdateChannel::Stable,
            "0.3.0",
            "0.2.0-alpha.0",
            Some("0.3.0"),
            Some(t0),
            None,
            t0 + NIGHTLY_COOLDOWN_MS
        ));
        assert!(should_notify_agent_of_update(
            UpdateChannel::Stable,
            "0.3.0",
            "0.2.0-alpha.0",
            Some("0.3.0"),
            Some(t0),
            None,
            t0 + STABLE_COOLDOWN_MS
        ));
        // Dismissed version -> never notifies again even after cooldown
        assert!(!should_notify_agent_of_update(
            UpdateChannel::Nightly,
            "0.2.0-nightly.20261124",
            "0.2.0-alpha.0",
            Some("0.2.0-nightly.20261124"),
            Some(t0),
            Some("0.2.0-nightly.20261124"),
            t0 + STABLE_COOLDOWN_MS * 10
        ));
    }

    #[test]
    fn numbered_nightlies_are_ordered_by_date_and_run() {
        let versions = [
            "0.8.0",
            "0.8.1-nightly.20261128.dec46ff",
            "0.8.1-nightly.20261128.fffffff",
            "0.8.1-nightly.20261128.run.r00000000000000000099.gfffffff",
            "0.8.1-nightly.20261128.run.r00000000000000000100.g0000001",
            "0.8.1-nightly.20261129.run.r00000000000000000101.g0000000",
            "0.8.1",
        ];
        for (position, newer) in versions.iter().enumerate() {
            for older in &versions[..position] {
                assert!(
                    is_strict_version_downgrade(older, newer),
                    "{older} < {newer}"
                );
                assert!(
                    !is_strict_version_downgrade(newer, older),
                    "{newer} > {older}"
                );
            }
        }
    }

    #[test]
    fn verify_release_manifest_rejects_bad_sig_and_rollback() {
        let kp = Ed25519KeyPair::generate().unwrap();
        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            current_target_triple().to_string(),
            ReleaseArtifact {
                url: "http://127.0.0.1:9999/hyp.tar.gz".to_string(),
                sha256: "a".repeat(64),
                size: 123,
            },
        );
        let payload = ReleaseManifestPayload {
            channel: "nightly".to_string(),
            version: "0.2.0-nightly.20261124".to_string(),
            git_sha: "deadbeef".to_string(),
            published_at: "2026-11-24T03:00:00Z".to_string(),
            min_protocol: 1,
            artifacts,
            changelog_summary: "Nightly build".to_string(),
        };
        let signed_payload = kp.sign_jcs(RELEASE_SIGNING_DOMAIN, &payload).unwrap();
        let signed = SignedReleaseManifest {
            payload: signed_payload.payload,
            sig: signed_payload.sig,
        };

        // Valid verification
        let (verified, ts) = verify_release_manifest(
            &signed,
            &kp.public_key_b64(),
            Some(UpdateChannel::Nightly),
            "0.2.0-alpha.0",
            None,
        )
        .unwrap();
        assert_eq!(verified.version, "0.2.0-nightly.20261124");

        // Tampered signature -> fail closed
        let mut bad_sig = signed.clone();
        let replacement = if signed.sig.starts_with('A') {
            'B'
        } else {
            'A'
        };
        bad_sig.sig = format!("{replacement}{}", &signed.sig[1..]);
        assert!(
            verify_release_manifest(
                &bad_sig,
                &kp.public_key_b64(),
                Some(UpdateChannel::Nightly),
                "0.2.0-alpha.0",
                None
            )
            .is_err()
        );

        // Timestamp rollback -> fail closed
        assert_eq!(
            verify_release_manifest(
                &signed,
                &kp.public_key_b64(),
                Some(UpdateChannel::Nightly),
                "0.2.0-alpha.0",
                Some(ts + 1000)
            )
            .unwrap_err()
            .0,
            "ROLLBACK_DETECTED"
        );
    }

    #[test]
    fn no_plugins_flag_skips_post_upgrade_sync_and_hints_when_receipts_exist() {
        use clap::Parser;
        use tempfile::TempDir;

        #[derive(Parser)]
        struct Wrapper {
            #[command(flatten)]
            args: UpdateArgs,
        }

        let parsed = Wrapper::try_parse_from(["update", "--no-plugins", "--json"])
            .expect("parse --no-plugins");
        assert!(parsed.args.no_plugins);

        let tmp = TempDir::new().unwrap();
        let state_dir = tmp.path().join("state");
        let receipts_path = crate::plugin_cmd::receipts_file_path(&state_dir);
        fs::create_dir_all(receipts_path.parent().unwrap()).unwrap();
        fs::write(&receipts_path, "{\"schemaVersion\":1,\"installed\":{}}\n").unwrap();

        let mut warnings = Vec::new();
        let mut next = Vec::new();
        let sync = run_post_upgrade_plugin_sync(
            Path::new("/nonexistent/hyp"),
            &state_dir,
            None,
            Some(
                "https://github.com/hyphae-to/hyp/releases/download/nightly/hyp-nightly-plugins.tar.gz",
            ),
            true,
            &mut warnings,
            &mut next,
        );
        assert_eq!(sync["skipped"], true);
        assert!(warnings.is_empty());
        assert!(next.iter().any(|s| s == "hyp plugin update --all"));
    }

    #[test]
    fn post_upgrade_plugin_sync_command_forwards_manifest_plugins_url_without_clobbering_override()
    {
        let nightly_url =
            "https://github.com/hyphae-to/hyp/releases/download/nightly/hyp-nightly-plugins.tar.gz";
        let state = Path::new("/tmp/hyphae-state");
        let cfg = Path::new("/tmp/hyphae-state/node.json");

        // 1. When caller did not set HYPHAE_PLUGINS_URL, manifest's plugins artifact URL is forwarded!
        let cmd = build_post_upgrade_plugin_sync_command(
            Path::new("/usr/local/bin/hyp"),
            state,
            Some(cfg),
            Some(nightly_url),
            None,
        );
        let envs: BTreeMap<String, Option<String>> = cmd
            .get_envs()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.map(|val| val.to_string_lossy().into_owned()),
                )
            })
            .collect();
        assert_eq!(
            envs.get("HYPHAE_PLUGINS_URL").and_then(|v| v.as_deref()),
            Some(nightly_url)
        );
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            args,
            vec![
                "plugin",
                "update",
                "--all",
                "--state-dir",
                "/tmp/hyphae-state",
                "--config",
                "/tmp/hyphae-state/node.json",
                "--json"
            ]
        );

        // 2. When caller explicitly set HYPHAE_PLUGINS_URL, preserve caller override!
        let cmd_override = build_post_upgrade_plugin_sync_command(
            Path::new("/usr/local/bin/hyp"),
            state,
            None,
            Some(nightly_url),
            Some("https://mirror.example.com/custom.tar.gz"),
        );
        assert!(
            !cmd_override
                .get_envs()
                .any(|(k, _)| k == "HYPHAE_PLUGINS_URL"),
            "explicit caller HYPHAE_PLUGINS_URL must not be overwritten"
        );
    }

    #[test]
    fn resolve_redirect_url_allows_https_assets_and_blocks_downgrade_or_unsafe_targets() {
        let gh: http::Uri =
            "https://github.com/hyphae-to/hyp/releases/download/nightly/release-manifest.json"
                .parse()
                .unwrap();

        let ok_abs = resolve_redirect_url(
            &gh,
            "https://release-assets.githubusercontent.com/github-production-release-asset/123/manifest.json",
        )
        .expect("https -> https redirect allowed");
        assert_eq!(ok_abs.scheme_str(), Some("https"));

        let ok_rel = resolve_redirect_url(&gh, "/other/path/manifest.json")
            .expect("root-relative https redirect allowed");
        assert_eq!(
            ok_rel.to_string(),
            "https://github.com/other/path/manifest.json"
        );

        assert_eq!(
            resolve_redirect_url(&gh, "http://127.0.0.1:8080/manifest.json")
                .unwrap_err()
                .0,
            "UNSAFE_REDIRECT",
            "HTTPS -> HTTP downgrade must fail closed even to loopback"
        );
        assert_eq!(
            resolve_redirect_url(&gh, "http://evil.example.com/manifest.json")
                .unwrap_err()
                .0,
            "UNSAFE_REDIRECT"
        );
        assert_eq!(
            resolve_redirect_url(&gh, "file:///etc/passwd")
                .unwrap_err()
                .0,
            "UNSAFE_REDIRECT"
        );
    }
}
