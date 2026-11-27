//! `hyp plugin` — Unified Release-Artifact Verified Non-Rust Plugin & Harness Mod Manager.
//!
//! Security invariants:
//! - `hyp` stays a pure-Rust static binary (zero embedded JS/TS/TSX/SVG/PNG assets); `build.rs`
//!   pins ONLY per-file SHA-256 digests (LF-normalized for text, raw bytes for binary `.png`)
//!   and per-plugin deterministic `tree_sha256` digests for every official non-Rust plugin & mod:
//!   - Bridges (`kind = "bridge"`): `sdk`, `telegram`, `slack`, `whatsapp`, `webhook`, `prometheus`,
//!     and the event sources `agentmail`, `sentry`, `gmail`, `google-calendar`, `vercel`, `notion`
//!   - Harness mods (`kind = "harness"`): `claude-panel`, `claude-code`, `herdr-mod`
//! - Source precedence (ALL verified in constant time via `ct_eq` BEFORE writing a single byte):
//!   1. `--archive <path>` / `HYPHAE_PLUGINS_ARCHIVE`
//!   2. `--from-dir <path>` / `HYPHAE_PLUGINS_DIR`
//!   3. Local verified cache `<state_dir>/plugins-cache/hyp-v<ver>-plugins.tar.gz` (`0600`)
//!   4. HTTPS release asset `https://github.com/hyphae-to/hyp/releases/download/<tag>/hyp-<tag>-plugins.tar.gz`
//!      (where `<tag>` is `nightly` on nightly builds and `v<ver>` on stable builds;
//!      enforcing `https://` or loopback `http://127.0.0.1` / `http://[::1]` for local tests,
//!      <= 4 MiB, 30s timeout, <= 5 redirects with zero HTTPS->HTTP downgrade).
//! - Three-way hash state machine (`<state_dir>/plugins/installed.json`, `0600` atomic write):
//!   - `up_to_date` (`disk == pinned`): skipped with 0 network calls & 0 disk writes.
//!   - `outdated` (`receipt && disk == receipt && disk != pinned`): fetches tarball at most once,
//!     verifies SHA-256 in constant time, updates only changed plugins atomically.
//!   - `modified` (`disk != pinned && (!receipt || disk != receipt)`): refuses to clobber by
//!     default (fail-closed for local edits & legacy pre-receipt installs), requires `--force`.
//!   - `corrupt` (missing file / symlink / invalid target): fails closed in `verify` & `doctor`.

use crate::config_file::{
    build_http_client, ct_eq, ensure_dir, open_secret_store, resolve_config_path_for_read,
    resolve_home_dir, resolve_state_dir, write_atomic_file, write_atomic_json,
};
use crate::herdr_mod::detect_herdr_app_dir;
use crate::setup::{
    CLAUDE_SLASH_COMMANDS, ClaudeConfigProfile, canonical_dedup_key, resolve_claude_profiles,
};
use crate::ui::{
    CheckStatus, CliCheck, CliError, EXIT_ERROR, EXIT_OK, EXIT_USAGE, JsonEnvelope, emit_error,
    print_checks, print_json, print_next_steps, print_warnings,
};
use clap::Subcommand;
use http::{Method, Request, Uri, header};
use http_body_util::{BodyExt, Empty};
use hyp_crypto::keystore::validate_secret_name;
use hyp_crypto::transfer::{TarUnpackOptions, unpack_tar_gz};
use hyp_node::adapters::telegram::{
    DEFAULT_TELEGRAM_SECRET_NAME, resolve_telegram_default_target_from_store,
};
use hyp_node::node_file::NodeFile;
use hyp_store::now_ms;
use hyper::body::Bytes;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Cursor};
use std::path::{Component, Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

include!(concat!(env!("OUT_DIR"), "/plugin_checksums.rs"));

/// Maximum compressed and uncompressed byte size allowed for official plugin archives (4 MiB).
pub const MAX_ARCHIVE_BYTES: usize = 4 * 1024 * 1024;
const MAX_ARCHIVE_FILES: usize = 64;
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REDIRECTS: usize = 5;

pub const RECEIPT_SCHEMA_VERSION: u32 = 1;
const SDK_PLUGIN_ID: &str = "sdk";
const CLAUDE_PANEL_ID: &str = "claude-panel";
const CLAUDE_CODE_ID: &str = "claude-code";
const HERDR_MOD_ID: &str = "herdr-mod";

const BRIDGE_CONSUMER_IDS: &[&str] = &[
    "telegram",
    "slack",
    "whatsapp",
    "webhook",
    "prometheus",
    "agentmail",
    "sentry",
    "gmail",
    "google-calendar",
    "vercel",
    "notion",
];

/// File name of the structured onboarding tree (`hyphae.onboarding/v1`) an official plugin may ship
/// next to its script. Surfaced as `onboardingPath` so setup agents can walk it without guessing paths.
const ONBOARDING_TREE_FILE: &str = "onboarding.json";

const CLAUDE_PANEL_MANIFEST_JSON: &str = concat!(
    "{\n  \"name\": \"hyp-panel\",\n  \"version\": \"",
    env!("CARGO_PKG_VERSION"),
    "\",\n  \"description\": \"Native Hyphae live mesh side-panel mod (/hyp-panel) for Claude Code.\",\n  \"author\": { \"name\": \"Hyphae\" },\n  \"license\": \"MIT\",\n  \"repository\": \"https://github.com/hyphae-to/hyp\"\n}\n"
);
const CLAUDE_PANEL_HOOKS_JSON: &str = "{\n  \"modules\": [\"./register.tsx\"]\n}\n";

#[derive(Debug, Clone, Subcommand)]
pub enum PluginCommand {
    /// List official non-Rust plugins & harness mods, install state, and three-way status
    List {
        /// Explicit Hyphae state directory (defaults to ~/.config/hyphae)
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Explicit node.json path
        #[arg(long)]
        config: Option<PathBuf>,
        /// Override HOME directory
        #[arg(long)]
        home: Option<PathBuf>,
        /// Explicit Claude Code config profile directory (overrides $CLAUDE_CONFIG_DIR)
        #[arg(long, value_name = "DIR")]
        claude_config_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Download, SHA-256 verify, and atomically install an official plugin or harness mod (or `all`)
    Install {
        /// Plugin name: sdk, telegram, slack, whatsapp, webhook, prometheus, agentmail, sentry, gmail, google-calendar, vercel, notion, claude-panel, claude-code, herdr-mod, or all
        #[arg(value_name = "PLUGIN")]
        plugin: String,
        /// Explicit Hyphae state directory (defaults to ~/.config/hyphae)
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Explicit node.json path
        #[arg(long)]
        config: Option<PathBuf>,
        /// Override HOME directory
        #[arg(long)]
        home: Option<PathBuf>,
        /// Explicit Claude Code config profile directory (overrides $CLAUDE_CONFIG_DIR)
        #[arg(long, value_name = "DIR")]
        claude_config_dir: Option<PathBuf>,
        /// Override release tarball URL (https:// or loopback http://127.0.0.1 / http://[::1])
        #[arg(long)]
        url: Option<String>,
        /// Install and verify from a local .tar.gz plugin archive
        #[arg(long)]
        archive: Option<PathBuf>,
        /// Install and verify directly from a local plugins directory
        #[arg(long)]
        from_dir: Option<PathBuf>,
        /// Overwrite locally modified files or replace symlinks
        #[arg(long)]
        force: bool,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Selectively update outdated installed plugins & harness mods (0 downloads if up to date)
    Update {
        /// Optional plugin name (omit or pass --all to check all installed plugins)
        #[arg(value_name = "PLUGIN")]
        plugin: Option<String>,
        /// Check and update all installed official plugins & harness mods
        #[arg(long)]
        all: bool,
        /// Show planned updates without downloading or modifying files on disk
        #[arg(long)]
        dry_run: bool,
        /// Overwrite locally modified or pre-receipt legacy installs
        #[arg(long)]
        force: bool,
        /// Explicit Hyphae state directory (defaults to ~/.config/hyphae)
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Explicit node.json path
        #[arg(long)]
        config: Option<PathBuf>,
        /// Override HOME directory
        #[arg(long)]
        home: Option<PathBuf>,
        /// Explicit Claude Code config profile directory (overrides $CLAUDE_CONFIG_DIR)
        #[arg(long, value_name = "DIR")]
        claude_config_dir: Option<PathBuf>,
        /// Override release tarball URL (https:// or loopback http://127.0.0.1 / http://[::1])
        #[arg(long)]
        url: Option<String>,
        /// Update and verify from a local .tar.gz plugin archive
        #[arg(long)]
        archive: Option<PathBuf>,
        /// Update and verify directly from a local plugins directory
        #[arg(long)]
        from_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Remove an installed official plugin or harness mod (or `all`)
    Remove {
        /// Plugin name: sdk, telegram, slack, whatsapp, webhook, prometheus, agentmail, sentry, gmail, google-calendar, vercel, notion, claude-panel, claude-code, herdr-mod, or all
        #[arg(value_name = "PLUGIN")]
        plugin: String,
        /// Keep matching `plugins[]` entries in node.json instead of removing them
        #[arg(long)]
        keep_config: bool,
        /// Explicit Hyphae state directory (defaults to ~/.config/hyphae)
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Explicit node.json path
        #[arg(long)]
        config: Option<PathBuf>,
        /// Override HOME directory
        #[arg(long)]
        home: Option<PathBuf>,
        /// Explicit Claude Code config profile directory (overrides $CLAUDE_CONFIG_DIR)
        #[arg(long, value_name = "DIR")]
        claude_config_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Verify SHA-256 integrity of installed official plugins & harness mods against compile-time digests
    Verify {
        /// Optional single plugin name to verify (omit to verify all installed plugins)
        #[arg(value_name = "PLUGIN")]
        plugin: Option<String>,
        /// Explicit Hyphae state directory (defaults to ~/.config/hyphae)
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Explicit node.json path
        #[arg(long)]
        config: Option<PathBuf>,
        /// Override HOME directory
        #[arg(long)]
        home: Option<PathBuf>,
        /// Explicit Claude Code config profile directory (overrides $CLAUDE_CONFIG_DIR)
        #[arg(long, value_name = "DIR")]
        claude_config_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
}

/// Three-way install & drift status comparing disk, local receipt (`installed.json`), and
/// binary compile-time pinned digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginStatus {
    UpToDate,
    Outdated,
    Modified,
    Corrupt,
    NotInstalled,
}

impl PluginStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UpToDate => "up_to_date",
            Self::Outdated => "outdated",
            Self::Modified => "modified",
            Self::Corrupt => "corrupt",
            Self::NotInstalled => "not_installed",
        }
    }
}

/// Persisted receipt store at `<state_dir>/plugins/installed.json` (`0600`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginReceiptsFile {
    pub schema_version: u32,
    #[serde(default)]
    pub installed: BTreeMap<String, PluginInstallReceipt>,
}

impl Default for PluginReceiptsFile {
    fn default() -> Self {
        Self {
            schema_version: RECEIPT_SCHEMA_VERSION,
            installed: BTreeMap::new(),
        }
    }
}

/// Per-plugin install receipt stored inside `installed.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PluginInstallReceipt {
    pub kind: String,
    pub tree_sha256: String,
    pub installed_at: i64,
    #[serde(default)]
    pub target_paths: Vec<String>,
}

/// Explicit source overrides passed from CLI flags (take priority over env vars, cache, and HTTPS).
#[derive(Debug, Clone, Copy, Default)]
pub struct PluginSourceOverrides<'a> {
    pub archive: Option<&'a Path>,
    pub from_dir: Option<&'a Path>,
    pub url: Option<&'a str>,
}

/// Structured error returned by internal verified plugin installer helpers used by `setup.rs`
/// and `herdr_mod.rs`.
#[derive(Debug, Clone)]
pub struct PluginInstallError {
    pub code: &'static str,
    pub message: String,
}

impl PluginInstallError {
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    /// Returns `true` when the failure is an offline / remote-download unavailability error
    /// (safe for `hyp setup` to warn & continue on pure-Rust config), and `false` for security,
    /// checksum mismatch, symlink tamper, or explicit local source errors (MUST fail closed!).
    pub fn is_offline_download_error(&self) -> bool {
        matches!(
            self.code,
            "HTTP_ERROR"
                | "HTTP_TIMEOUT"
                | "HTTP_STATUS"
                | "HTTP_INIT_ERROR"
                | "TOO_MANY_REDIRECTS"
                | "RUNTIME_ERROR"
        )
    }
}

impl std::fmt::Display for PluginInstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

/// Summary returned by internal harness UI plugin install helpers (`setup.rs` / `herdr_mod.rs`).
#[derive(Debug, Clone)]
pub struct HarnessPluginInstallReport {
    pub files: Vec<String>,
    pub target_paths: Vec<PathBuf>,
}

/// Per-plugin health entry surfaced in `hyp doctor` & `hyp status`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorPluginSummary {
    pub name: String,
    pub kind: String,
    pub status: PluginStatus,
    pub pinned_tree_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub installed_tree_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_tree_sha256: Option<String>,
    pub target_paths: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Aggregate plugin health report for `hyp status` / `hyp doctor`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DoctorPluginsReport {
    pub plugins_dir: String,
    pub receipts_path: String,
    pub cache_path: String,
    pub cache_exists: bool,
    pub installed_count: usize,
    pub up_to_date_count: usize,
    pub outdated_count: usize,
    pub modified_count: usize,
    pub corrupt_count: usize,
    pub plugins: Vec<DoctorPluginSummary>,
    #[serde(skip_serializing)]
    pub checks: Vec<CliCheck>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PluginListEntry {
    name: String,
    kind: String,
    status: PluginStatus,
    installed: bool,
    verified: bool,
    script_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    onboarding_path: Option<String>,
    target_paths: Vec<String>,
    pinned_sha256: String,
    tree_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    installed_tree_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    disk_tree_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    node_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct InstalledPluginRecord {
    name: String,
    kind: String,
    script_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    onboarding_path: Option<String>,
    target_paths: Vec<String>,
    sha256: String,
    tree_sha256: String,
    verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    default_target_source: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifiedFileRecord {
    plugin: String,
    rel_path: String,
    path: String,
    pinned_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    actual_sha256: Option<String>,
    verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InstallSourceKind {
    Release,
    Cache,
    Archive,
    Dir,
}

impl InstallSourceKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Cache => "cache",
            Self::Archive => "archive",
            Self::Dir => "dir",
        }
    }
}

#[derive(Debug, Clone)]
struct PluginInspection {
    spec: &'static PinnedPluginSpec,
    status: PluginStatus,
    target_paths: Vec<PathBuf>,
    disk_tree_sha256: Option<String>,
    receipt_tree_sha256: Option<String>,
    files: Vec<VerifiedFileRecord>,
    detail: Option<String>,
}

/// Entrypoint wired from `main.rs` (`Commands::Plugin { command }`).
pub fn run_plugin(command: PluginCommand) -> ExitCode {
    match command {
        PluginCommand::List {
            state_dir,
            config,
            home,
            claude_config_dir,
            json,
        } => run_plugin_list(
            state_dir.as_deref(),
            config.as_deref(),
            home.as_deref(),
            claude_config_dir.as_deref(),
            json,
        ),
        PluginCommand::Install {
            plugin,
            state_dir,
            config,
            home,
            claude_config_dir,
            url,
            archive,
            from_dir,
            force,
            json,
        } => run_plugin_install(
            &plugin,
            state_dir.as_deref(),
            config.as_deref(),
            home.as_deref(),
            claude_config_dir.as_deref(),
            PluginSourceOverrides {
                archive: archive.as_deref(),
                from_dir: from_dir.as_deref(),
                url: url.as_deref(),
            },
            force,
            json,
        ),
        PluginCommand::Update {
            plugin,
            all,
            dry_run,
            force,
            state_dir,
            config,
            home,
            claude_config_dir,
            url,
            archive,
            from_dir,
            json,
        } => run_plugin_update(
            plugin.as_deref(),
            all,
            dry_run,
            force,
            state_dir.as_deref(),
            config.as_deref(),
            home.as_deref(),
            claude_config_dir.as_deref(),
            PluginSourceOverrides {
                archive: archive.as_deref(),
                from_dir: from_dir.as_deref(),
                url: url.as_deref(),
            },
            json,
        ),
        PluginCommand::Remove {
            plugin,
            keep_config,
            state_dir,
            config,
            home,
            claude_config_dir,
            json,
        } => run_plugin_remove(
            &plugin,
            keep_config,
            state_dir.as_deref(),
            config.as_deref(),
            home.as_deref(),
            claude_config_dir.as_deref(),
            json,
        ),
        PluginCommand::Verify {
            plugin,
            state_dir,
            config,
            home,
            claude_config_dir,
            json,
        } => run_plugin_verify(
            plugin.as_deref(),
            state_dir.as_deref(),
            config.as_deref(),
            home.as_deref(),
            claude_config_dir.as_deref(),
            json,
        ),
    }
}

/// Returns `true` when `version` carries a `nightly` SemVer prerelease identifier
/// (e.g. `0.7.1-nightly.20261126.bd3a90b`).
pub fn is_nightly_build_version(version: &str) -> bool {
    let trimmed = version.trim();
    let no_build = trimmed.split('+').next().unwrap_or(trimmed);
    let Some((_, prerelease)) = no_build.split_once('-') else {
        return false;
    };
    prerelease
        .split('.')
        .any(|ident| ident.eq_ignore_ascii_case("nightly"))
}

/// Resolves the GitHub Release URL for the official plugins tarball given build metadata.
///
/// Precedence:
/// 1. Explicit non-empty `release_tag` (e.g. `"nightly"` or `"v0.7.0"`).
/// 2. Nightly channel (`channel == Some("nightly")`) or `-nightly` prerelease `version`
///    -> rolling `nightly` GitHub Release asset (`.../releases/download/nightly/hyp-nightly-plugins.tar.gz`).
/// 3. Stable / tagged SemVer `version` (e.g. `"0.7.0"` or `"0.8.0-rc.1"`)
///    -> `.../releases/download/v<ver>/hyp-v<ver>-plugins.tar.gz`.
pub fn resolve_release_plugins_url(
    version: &str,
    channel: Option<&str>,
    release_tag: Option<&str>,
) -> String {
    let tag = if let Some(explicit_tag) = release_tag.map(str::trim).filter(|s| !s.is_empty()) {
        explicit_tag.to_string()
    } else if channel
        .map(str::trim)
        .is_some_and(|c| c.eq_ignore_ascii_case("nightly"))
        || is_nightly_build_version(version)
    {
        "nightly".to_string()
    } else {
        let ver = version.trim().trim_start_matches('v');
        format!("v{ver}")
    };
    format!("https://github.com/hyphae-to/hyp/releases/download/{tag}/hyp-{tag}-plugins.tar.gz")
}

/// Resolves the effective plugins archive download URL applying CLI `--url` and
/// `HYPHAE_PLUGINS_URL` overrides ahead of `default_url`.
pub fn resolve_effective_plugins_download_url(
    explicit_url: Option<&str>,
    env_url: Option<&str>,
    default_url: &str,
) -> String {
    if let Some(u) = explicit_url.map(str::trim).filter(|s| !s.is_empty()) {
        return u.to_string();
    }
    if let Some(u) = env_url.map(str::trim).filter(|s| !s.is_empty()) {
        return u.to_string();
    }
    default_url.to_string()
}

/// Default GitHub Release URL for the official plugins tarball matching this binary's build metadata.
pub fn default_release_plugins_url() -> String {
    resolve_release_plugins_url(
        env!("HYPHAE_BUILD_VERSION"),
        Some(env!("HYPHAE_BUILD_CHANNEL")),
        option_env!("HYPHAE_RELEASE_TAG"),
    )
}

/// Path to `<state_dir>/plugins/installed.json`.
pub fn receipts_file_path(state_dir: &Path) -> PathBuf {
    state_dir.join("plugins").join("installed.json")
}

/// Computes the local verified archive cache path for a given build version and channel,
/// isolating nightly builds from stable release caches.
pub fn cached_plugins_archive_path_for(
    state_dir: &Path,
    version: &str,
    channel: Option<&str>,
) -> PathBuf {
    let ver = version.trim().trim_start_matches('v');
    let filename = if is_nightly_build_version(ver) {
        format!("hyp-v{ver}-plugins.tar.gz")
    } else if channel
        .map(str::trim)
        .is_some_and(|c| c.eq_ignore_ascii_case("nightly"))
    {
        "hyp-nightly-plugins.tar.gz".to_string()
    } else {
        format!("hyp-v{ver}-plugins.tar.gz")
    };
    state_dir.join("plugins-cache").join(filename)
}

/// Path to `<state_dir>/plugins-cache/hyp-v<ver>-plugins.tar.gz` (isolated per build version/channel).
pub fn cached_plugins_archive_path(state_dir: &Path) -> PathBuf {
    cached_plugins_archive_path_for(
        state_dir,
        env!("HYPHAE_BUILD_VERSION"),
        Some(env!("HYPHAE_BUILD_CHANNEL")),
    )
}

/// Normalizes `\r\n` -> `\n` so Windows and Unix produce identical SHA-256 digests.
pub fn normalize_crlf(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\r' && i + 1 < bytes.len() && bytes[i + 1] == b'\n' {
            out.push(b'\n');
            i += 2;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

/// Computes lowercase hex SHA-256 over LF-normalized text bytes or raw binary bytes.
pub fn sha256_file_hex(bytes: &[u8], is_binary: bool) -> String {
    if is_binary {
        hex::encode(Sha256::digest(bytes))
    } else {
        let normalized = normalize_crlf(bytes);
        hex::encode(Sha256::digest(&normalized))
    }
}

/// Computes deterministic per-plugin `tree_sha256` over lexicographically sorted
/// `"{rel_path}\0{file_sha256}\n"` lines (identical to `crates/hyp-cli/build.rs`).
pub fn compute_tree_sha256(entries: &[(&str, &str)]) -> String {
    let mut sorted: Vec<(&str, &str)> = entries.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    let mut buf = Vec::new();
    for (rel_path, digest) in sorted {
        buf.extend_from_slice(rel_path.as_bytes());
        buf.push(0x00);
        buf.extend_from_slice(digest.as_bytes());
        buf.push(b'\n');
    }
    hex::encode(Sha256::digest(&buf))
}

/// Looks up a compile-time `PinnedPluginSpec` by canonical plugin ID.
pub fn pinned_spec_for(plugin_id: &str) -> Option<&'static PinnedPluginSpec> {
    PINNED_PLUGINS.iter().find(|p| p.id == plugin_id)
}

/// Resolves a user plugin selector (`sdk|telegram|slack|whatsapp|webhook|prometheus|agentmail|sentry|gmail|google-calendar|vercel|notion|claude-panel|claude-code|herdr-mod|all`).
pub fn resolve_plugin_targets(selector: &str) -> Result<Vec<&'static PinnedPluginSpec>, String> {
    let normalized = selector.trim().to_ascii_lowercase();
    if normalized == "all" {
        return Ok(PINNED_PLUGINS.iter().collect());
    }
    if let Some(spec) = pinned_spec_for(&normalized) {
        return Ok(vec![spec]);
    }
    let valid: Vec<&str> = PINNED_PLUGINS.iter().map(|p| p.id).collect();
    Err(format!(
        "Unknown official plugin '{selector}'. Expected one of: {}, or all.",
        valid.join(", ")
    ))
}

fn is_bridge_consumer(plugin_id: &str) -> bool {
    BRIDGE_CONSUMER_IDS.contains(&plugin_id)
}

/// Loads `<state_dir>/plugins/installed.json`, returning an empty store when absent.
pub fn load_receipts(state_dir: &Path) -> Result<PluginReceiptsFile, String> {
    let path = receipts_file_path(state_dir);
    let meta = match fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(PluginReceiptsFile::default());
        }
        Err(e) => return Err(format!("failed to stat {}: {e}", path.display())),
    };
    if meta.file_type().is_symlink() || !meta.file_type().is_file() {
        return Err(format!(
            "refusing non-regular receipt file at {}",
            path.display()
        ));
    }
    let raw =
        fs::read_to_string(&path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    let parsed: PluginReceiptsFile = serde_json::from_str(&raw)
        .map_err(|e| format!("invalid JSON in {}: {e}", path.display()))?;
    Ok(parsed)
}

/// Atomically persists `<state_dir>/plugins/installed.json` (`0600` under `0700`).
pub fn save_receipts(state_dir: &Path, receipts: &PluginReceiptsFile) -> Result<(), String> {
    let path = receipts_file_path(state_dir);
    if receipts.installed.is_empty() {
        if fs::symlink_metadata(&path).is_ok() {
            let _ = fs::remove_file(&path);
        }
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        ensure_dir(parent, true)?;
    }
    if let Ok(meta) = fs::symlink_metadata(&path) {
        if meta.file_type().is_symlink() {
            return Err(format!(
                "refusing symlink at receipt path {}",
                path.display()
            ));
        }
    }
    let val = serde_json::to_value(receipts)
        .map_err(|e| format!("failed to serialize plugin receipts: {e}"))?;
    write_atomic_json(&path, &val, true)
}

/// Maps a pinned archive `rel_path` onto its installed location inside `target_root`.
fn rel_path_to_disk_path(plugin_id: &str, target_root: &Path, rel_path: &str) -> PathBuf {
    let sub = match plugin_id {
        CLAUDE_PANEL_ID | CLAUDE_CODE_ID => {
            rel_path.strip_prefix("claude-code/").unwrap_or(rel_path)
        }
        HERDR_MOD_ID => rel_path.strip_prefix("herdr-mod/mods/").unwrap_or(rel_path),
        other => {
            let prefix = format!("{other}/");
            rel_path.strip_prefix(&prefix).unwrap_or(rel_path)
        }
    };
    target_root.join(sub)
}

fn default_claude_panel_targets(
    home: Option<&Path>,
    explicit_home: bool,
    claude_config_dir: Option<&Path>,
) -> Vec<PathBuf> {
    let Some(h) = home else {
        return Vec::new();
    };
    let profiles = resolve_claude_profiles(h, explicit_home, claude_config_dir);
    dedup_claude_panel_dirs(&profiles)
}

fn dedup_claude_panel_dirs(profiles: &[ClaudeConfigProfile]) -> Vec<PathBuf> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for profile in profiles {
        let panel_dir = profile.panel_dir();
        if seen.insert(canonical_dedup_key(&panel_dir)) {
            out.push(panel_dir);
        }
    }
    out
}

fn default_herdr_mods_dir(home: Option<&Path>, explicit_home: bool) -> Option<PathBuf> {
    let h = home?;
    let herdr_home = if !explicit_home {
        detect_herdr_app_dir(h).unwrap_or_else(|| h.join(".config").join("herdr-app"))
    } else {
        h.join(".config").join("herdr-app")
    };
    Some(herdr_home.join("mods"))
}

fn resolve_target_roots(
    plugin_id: &str,
    state_dir: &Path,
    home: Option<&Path>,
    explicit_home: bool,
    claude_config_dir: Option<&Path>,
    receipt: Option<&PluginInstallReceipt>,
) -> Vec<PathBuf> {
    if let Some(r) = receipt {
        if !r.target_paths.is_empty() && claude_config_dir.is_none() {
            return r.target_paths.iter().map(PathBuf::from).collect();
        }
    }
    match plugin_id {
        CLAUDE_PANEL_ID => default_claude_panel_targets(home, explicit_home, claude_config_dir),
        HERDR_MOD_ID => default_herdr_mods_dir(home, explicit_home)
            .into_iter()
            .collect(),
        other => vec![state_dir.join("plugins").join(other)],
    }
}

fn primary_script_display(plugin_id: &str, target_roots: &[PathBuf]) -> String {
    let Some(first) = target_roots.first() else {
        return String::new();
    };
    match plugin_id {
        SDK_PLUGIN_ID => first.join("client.mjs").display().to_string(),
        CLAUDE_PANEL_ID => first
            .join("hooks")
            .join("register.tsx")
            .display()
            .to_string(),
        CLAUDE_CODE_ID | HERDR_MOD_ID => first.display().to_string(),
        _ => first.join("index.mjs").display().to_string(),
    }
}

/// Absolute display path of the plugin's onboarding tree, when its pinned spec ships one.
fn onboarding_tree_display(spec: &PinnedPluginSpec, target_roots: &[PathBuf]) -> Option<String> {
    let first = target_roots.first()?;
    spec.files
        .iter()
        .any(|f| f.rel_path.rsplit('/').next() == Some(ONBOARDING_TREE_FILE))
        .then(|| first.join(ONBOARDING_TREE_FILE).display().to_string())
}

fn is_private_plugin_target(plugin_id: &str) -> bool {
    !matches!(plugin_id, CLAUDE_PANEL_ID | HERDR_MOD_ID)
}

/// Inspects a single plugin file at `path` against `expected_sha256` (rejecting symlinks & checking
/// intermediate components beneath `target_root`).
fn inspect_plugin_file(
    target_root: &Path,
    path: &Path,
    expected_sha256: &str,
    is_binary: bool,
) -> (bool, bool, Option<String>, Option<String>) {
    // Reject symlinks on any component at or beneath target_root (while allowing symlinks ABOVE
    // target_root such as `gateway/skills -> ~/.claude/skills`).
    if let Ok(rel) = path.strip_prefix(target_root) {
        if let Ok(meta) = fs::symlink_metadata(target_root) {
            if meta.file_type().is_symlink() {
                return (
                    true,
                    false,
                    None,
                    Some("plugin target root is a symlink (real directory required)".to_string()),
                );
            }
        }
        let mut cursor = target_root.to_path_buf();
        for comp in rel.components() {
            cursor.push(comp);
            if cursor == path {
                break;
            }
            if let Ok(meta) = fs::symlink_metadata(&cursor) {
                if meta.file_type().is_symlink() {
                    return (
                        true,
                        false,
                        None,
                        Some(format!(
                            "symlink directory rejected at {} (real directory required)",
                            cursor.display()
                        )),
                    );
                }
            }
        }
    }

    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => (false, false, None, None),
        Err(e) => (true, false, None, Some(format!("stat failed: {e}"))),
        Ok(meta) => {
            if meta.file_type().is_symlink() {
                return (
                    true,
                    false,
                    None,
                    Some("symlink rejected (regular file required)".to_string()),
                );
            }
            if !meta.file_type().is_file() {
                return (true, false, None, Some("not a regular file".to_string()));
            }
            match read_regular_file_checked(path) {
                Ok(bytes) => {
                    let actual = sha256_file_hex(&bytes, is_binary);
                    if ct_eq(actual.as_bytes(), expected_sha256.as_bytes()) {
                        (true, true, Some(actual), None)
                    } else {
                        (
                            true,
                            false,
                            Some(actual.clone()),
                            Some(format!(
                                "SHA-256 mismatch (expected {expected_sha256}, got {actual})"
                            )),
                        )
                    }
                }
                Err(e) => (true, false, None, Some(e)),
            }
        }
    }
}

/// Checks non-pinned wrapper files for `claude-panel` (`plugin.json`, `hooks.json`) to make sure
/// they exist as regular non-symlink files when `claude-panel` is installed.
fn check_claude_panel_wrappers(target_root: &Path) -> Option<String> {
    for rel in [".claude-plugin/plugin.json", "hooks/hooks.json"] {
        let p = target_root.join(rel);
        match fs::symlink_metadata(&p) {
            Err(_) => {
                return Some(format!("missing claude-panel wrapper file {}", p.display()));
            }
            Ok(meta) => {
                if meta.file_type().is_symlink() || !meta.file_type().is_file() {
                    return Some(format!(
                        "invalid claude-panel wrapper file {} (regular file required)",
                        p.display()
                    ));
                }
            }
        }
    }
    None
}

fn legacy_claude_code_tree_matches(
    spec: &PinnedPluginSpec,
    root: &Path,
    receipt_tree: &str,
) -> bool {
    let mut entries = Vec::with_capacity(spec.files.len());
    for entry in spec.files {
        let current = rel_path_to_disk_path(spec.id, root, entry.rel_path);
        let rel = if fs::symlink_metadata(&current).is_ok() {
            entry.rel_path.to_owned()
        } else if entry.rel_path == "claude-code/skills/hyp-mesh/SKILL.md" {
            "claude-code/skills/hyphae/SKILL.md".to_owned()
        } else if let Some(command) = entry
            .rel_path
            .strip_prefix("claude-code/commands/")
            .and_then(|filename| {
                CLAUDE_SLASH_COMMANDS
                    .iter()
                    .find(|command| command.filename == filename)
            })
        {
            format!("claude-code/commands/{}", command.legacy_name)
        } else {
            entry.rel_path.to_owned()
        };
        let path = rel_path_to_disk_path(spec.id, root, &rel);
        let (_, _, actual, _) = inspect_plugin_file(root, &path, entry.sha256, entry.is_binary);
        let Some(actual) = actual else { return false };
        entries.push((rel, actual));
    }
    let pairs: Vec<_> = entries
        .iter()
        .map(|(rel, sha)| (rel.as_str(), sha.as_str()))
        .collect();
    compute_tree_sha256(&pairs) == receipt_tree
}

fn legacy_panel_root(path: &Path) -> bool {
    path.file_name().is_some_and(|name| name == "hyphae-panel")
}

fn install_target_roots(plugin_id: &str, roots: Vec<PathBuf>) -> Vec<PathBuf> {
    roots
        .into_iter()
        .map(|root| {
            if plugin_id == CLAUDE_PANEL_ID && legacy_panel_root(&root) {
                root.with_file_name("hyp-panel")
            } else {
                root
            }
        })
        .collect()
}

fn check_panel_rename_targets(
    spec: &PinnedPluginSpec,
    roots: &[PathBuf],
) -> Result<(), PluginInstallError> {
    if spec.id != CLAUDE_PANEL_ID {
        return Ok(());
    }
    for old in roots.iter().filter(|path| legacy_panel_root(path)) {
        let new = old.with_file_name("hyp-panel");
        let status = fs::symlink_metadata(&new);
        if matches!(&status, Err(err) if err.kind() == io::ErrorKind::NotFound) {
            continue;
        }
        if status.is_ok_and(|meta| meta.is_dir())
            && check_claude_panel_wrappers(&new).is_none()
            && crate::config_file::read_json_value(&new.join(".claude-plugin/plugin.json")).ok()
                == serde_json::from_str::<Value>(CLAUDE_PANEL_MANIFEST_JSON).ok()
            && crate::config_file::read_json_value(&new.join("hooks/hooks.json")).ok()
                == serde_json::from_str::<Value>(CLAUDE_PANEL_HOOKS_JSON).ok()
            && spec.files.iter().all(|entry| {
                let path = rel_path_to_disk_path(spec.id, &new, entry.rel_path);
                inspect_plugin_file(&new, &path, entry.sha256, entry.is_binary).1
            })
        {
            continue;
        }
        return Err(PluginInstallError::new(
            "PLUGIN_MODIFIED",
            format!("{} already exists (pass --force to replace)", new.display()),
        ));
    }
    Ok(())
}

/// Retire the managed legacy panel files and keep any files users added.
fn retire_legacy_claude_panel(
    spec: &PinnedPluginSpec,
    root: &Path,
    previous: Option<&PluginInstallReceipt>,
) -> Result<(), String> {
    const LEGACY_TREES: &[&str] = &[
        "63620469bad933435dfa3850f3ef49b8bf728a5efb584484cbb53e062c44bdf6",
        "d8d361b10aebd295df11789d31205de1dae46aaccf59d9e8218b52fdde206e9b",
        "277e55ec2cdf1be944d44f505d4f7c31423546ae8466b97b9f1bd29d995a9f79",
        "930b74f28f54ecb82695f875516e288f3dece74f6f85806db4b6e77879e0436e",
        "e59fc404a19828e99d32b37955e87303dd586419f45d5cf7e6b33437f52ad7df",
    ];
    if root.file_name().is_none_or(|name| name != "hyp-panel") {
        return Ok(());
    }
    let old = root.with_file_name("hyphae-panel");
    let manifest = old.join(".claude-plugin/plugin.json");
    let hooks = old.join("hooks/hooks.json");
    let legacy_dirs = [old.clone(), old.join(".claude-plugin"), old.join("hooks")];
    if !legacy_dirs
        .iter()
        .all(|dir| fs::symlink_metadata(dir).is_ok_and(|m| m.is_dir()))
        || check_claude_panel_wrappers(&old).is_some()
    {
        return Ok(());
    }

    let Ok(manifest_json) = crate::config_file::read_json_value(&manifest) else {
        return Ok(());
    };
    let version = manifest_json["version"].as_str();
    let expected = serde_json::json!({
        "name": "hyphae-panel",
        "version": version,
        "description": "Native Hyphae live mesh side-panel mod (/hyphae-panel) for Claude Code.",
        "author": {"name": "Hyphae"},
        "license": "MIT",
        "repository": "https://github.com/hyphae-to/hyp",
    });
    if version.is_none()
        || manifest_json != expected
        || crate::config_file::read_json_value(&hooks).ok()
            != serde_json::from_str::<Value>(CLAUDE_PANEL_HOOKS_JSON).ok()
    {
        return Ok(());
    }
    let mut entries = Vec::with_capacity(spec.files.len());
    let mut paths = Vec::with_capacity(spec.files.len());
    for entry in spec.files {
        let path = rel_path_to_disk_path(spec.id, &old, entry.rel_path);
        let (_, _, actual, _) = inspect_plugin_file(&old, &path, entry.sha256, entry.is_binary);
        let Some(actual) = actual else { return Ok(()) };
        entries.push((entry.rel_path, actual));
        paths.push(path);
    }
    let pairs: Vec<_> = entries
        .iter()
        .map(|(rel, sha)| (*rel, sha.as_str()))
        .collect();
    let digest = compute_tree_sha256(&pairs);
    if !LEGACY_TREES.contains(&digest.as_str())
        && !previous.is_some_and(|receipt| {
            receipt.tree_sha256 == digest
                && receipt
                    .target_paths
                    .iter()
                    .any(|path| Path::new(path) == old)
        })
    {
        return Ok(());
    }
    for path in std::iter::once(manifest)
        .chain(std::iter::once(hooks))
        .chain(paths)
    {
        fs::remove_file(&path)
            .map_err(|err| format!("could not retire {}: {err}", path.display()))?;
    }
    for dir in legacy_dirs.into_iter().rev() {
        match fs::remove_dir(&dir) {
            Ok(()) => {}
            Err(err) if err.kind() == io::ErrorKind::DirectoryNotEmpty => {}
            Err(err) => return Err(format!("could not retire {}: {err}", dir.display())),
        }
    }
    Ok(())
}

fn migrate_standalone_claude_commands(panel: &Path) -> Result<(), String> {
    let Some(config_dir) = panel
        .parent()
        .filter(|dir| dir.file_name().is_some_and(|name| name == "skills"))
        .and_then(Path::parent)
    else {
        return Ok(());
    };
    let directory = config_dir.join("commands");
    if !fs::symlink_metadata(&directory).is_ok_and(|metadata| metadata.is_dir()) {
        return Ok(());
    }
    for command in CLAUDE_SLASH_COMMANDS {
        if command.matches_legacy(&directory)? {
            let path = directory.join(command.filename);
            match fs::symlink_metadata(&path) {
                Ok(meta) if meta.is_file() => {}
                Ok(_) => continue,
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    write_atomic_file(&path, command.content.as_bytes(), false)?;
                }
                Err(err) => return Err(format!("could not inspect {}: {err}", path.display())),
            }
            command.retire_legacy(&directory, false)?;
        }
    }
    Ok(())
}

fn complete_harness_rename(
    spec: &PinnedPluginSpec,
    roots: &[PathBuf],
    previous: Option<&PluginInstallReceipt>,
) -> Result<(), PluginInstallError> {
    for root in roots {
        let outcome = match spec.id {
            CLAUDE_PANEL_ID => retire_legacy_claude_panel(spec, root, previous)
                .and_then(|()| migrate_standalone_claude_commands(root)),
            CLAUDE_CODE_ID => CLAUDE_SLASH_COMMANDS
                .iter()
                .try_for_each(|command| command.retire_legacy(&root.join("commands"), false))
                .and_then(|()| {
                    let installed = root.join("skills/hyp-mesh/SKILL.md");
                    let legacy = crate::skill_render::legacy_skill_path(&installed, "hyphae");
                    crate::skill_render::retire_legacy_skill(&legacy, |text| {
                        const LEGACY_DIGESTS: &[&str] = &[
                            "866d50fa55e5c0a6c9f7814ba4400cd8f4de69e96ac7fa1f960ea7f53a14d597",
                            "78242d6f1d0fda4ad91547137353beb874e40cb06643d967f19ac6450fe275e4",
                        ];
                        LEGACY_DIGESTS.contains(&hyp_store::sha256_hex(text.as_bytes()).as_str())
                    })
                }),
            _ => Ok(()),
        };
        outcome.map_err(|err| PluginInstallError::new("IO_ERROR", err))?;
    }
    Ok(())
}

/// Evaluates three-way status (`up_to_date`, `outdated`, `modified`, `corrupt`, `not_installed`)
/// for one official plugin across all its target roots.
fn inspect_plugin(
    spec: &'static PinnedPluginSpec,
    state_dir: &Path,
    home: Option<&Path>,
    explicit_home: bool,
    claude_config_dir: Option<&Path>,
    receipts: &PluginReceiptsFile,
) -> PluginInspection {
    let receipt = receipts.installed.get(spec.id);
    let target_paths = resolve_target_roots(
        spec.id,
        state_dir,
        home,
        explicit_home,
        claude_config_dir,
        receipt,
    );
    let receipt_tree = receipt.map(|r| r.tree_sha256.clone());

    if target_paths.is_empty() {
        return PluginInspection {
            spec,
            status: if receipt.is_some() {
                PluginStatus::Corrupt
            } else {
                PluginStatus::NotInstalled
            },
            target_paths,
            disk_tree_sha256: None,
            receipt_tree_sha256: receipt_tree,
            files: Vec::new(),
            detail: if receipt.is_some() {
                Some("could not resolve target path for installed plugin".to_string())
            } else {
                None
            },
        };
    }

    let mut all_file_records: Vec<VerifiedFileRecord> = Vec::new();
    let mut overall_status: Option<PluginStatus> = None;
    let mut any_present = false;
    let mut representative_disk_tree: Option<String> = None;
    let mut first_detail: Option<String> = None;

    for root in &target_paths {
        let mut present_in_root = 0usize;
        let mut missing_in_root = 0usize;
        let mut symlink_or_io_error = false;
        let mut tree_entries: Vec<(&str, String)> = Vec::with_capacity(spec.files.len());
        let mut root_records: Vec<VerifiedFileRecord> = Vec::with_capacity(spec.files.len());

        // Check root itself for symlink tampering (e.g. dev-link on `mods/hyphae-pane`).
        if spec.id == HERDR_MOD_ID {
            for mod_sub in ["hyphae-pane", "hyphae-panel"] {
                let mod_dir = root.join(mod_sub);
                if let Ok(meta) = fs::symlink_metadata(&mod_dir) {
                    if meta.file_type().is_symlink() {
                        symlink_or_io_error = true;
                        any_present = true;
                        if first_detail.is_none() {
                            first_detail = Some(format!(
                                "symlink rejected at {} (real directory required for FSEvents)",
                                mod_dir.display()
                            ));
                        }
                    }
                }
            }
        }

        for entry in spec.files {
            let disk_path = rel_path_to_disk_path(spec.id, root, entry.rel_path);
            let (present, ok, actual_sha, reason) =
                inspect_plugin_file(root, &disk_path, entry.sha256, entry.is_binary);
            if present {
                present_in_root += 1;
                any_present = true;
                if let Some(ref sha) = actual_sha {
                    tree_entries.push((entry.rel_path, sha.clone()));
                } else {
                    symlink_or_io_error = true;
                    if first_detail.is_none() {
                        first_detail = reason.clone();
                    }
                }
            } else {
                missing_in_root += 1;
            }
            root_records.push(VerifiedFileRecord {
                plugin: spec.id.to_string(),
                rel_path: entry.rel_path.to_string(),
                path: disk_path.display().to_string(),
                pinned_sha256: entry.sha256.to_string(),
                actual_sha256: actual_sha,
                verified: present && ok,
                reason: if !present {
                    Some("missing file".to_string())
                } else {
                    reason
                },
            });
        }

        let root_status = if present_in_root == 0 && !symlink_or_io_error {
            if receipt.is_some() {
                if first_detail.is_none() {
                    first_detail = Some(format!(
                        "recorded in installed.json but missing on disk under {}",
                        root.display()
                    ));
                }
                PluginStatus::Corrupt
            } else {
                PluginStatus::NotInstalled
            }
        } else if spec.id == CLAUDE_CODE_ID
            && !symlink_or_io_error
            && missing_in_root > 0
            && receipt_tree
                .as_deref()
                .is_some_and(|tree| legacy_claude_code_tree_matches(spec, root, tree))
        {
            if first_detail.is_none() {
                first_detail = Some("outdated (legacy command or skill paths)".into());
            }
            PluginStatus::Outdated
        } else if symlink_or_io_error || missing_in_root > 0 {
            if first_detail.is_none() {
                first_detail = Some(format!(
                    "{missing_in_root} missing file(s) under {}",
                    root.display()
                ));
            }
            PluginStatus::Corrupt
        } else {
            if spec.id == CLAUDE_PANEL_ID {
                if let Some(wrapper_err) = check_claude_panel_wrappers(root) {
                    if first_detail.is_none() {
                        first_detail = Some(wrapper_err);
                    }
                    all_file_records.extend(root_records);
                    overall_status =
                        Some(merge_plugin_status(overall_status, PluginStatus::Corrupt));
                    continue;
                }
            }

            let pairs: Vec<(&str, &str)> = tree_entries
                .iter()
                .map(|(rel, sha)| (*rel, sha.as_str()))
                .collect();
            let disk_tree = compute_tree_sha256(&pairs);
            representative_disk_tree = Some(disk_tree.clone());

            if ct_eq(disk_tree.as_bytes(), spec.tree_sha256.as_bytes()) {
                if spec.id == CLAUDE_PANEL_ID && legacy_panel_root(root) {
                    PluginStatus::Outdated
                } else {
                    PluginStatus::UpToDate
                }
            } else if let Some(ref r_tree) = receipt_tree {
                if ct_eq(disk_tree.as_bytes(), r_tree.as_bytes()) {
                    if first_detail.is_none() {
                        first_detail = Some(format!(
                            "outdated (installed {}, binary expects {})",
                            &r_tree[..12.min(r_tree.len())],
                            &spec.tree_sha256[..12]
                        ));
                    }
                    PluginStatus::Outdated
                } else {
                    if first_detail.is_none() {
                        first_detail = Some(
                            "locally modified on disk (differs from receipt and pinned digest)"
                                .to_string(),
                        );
                    }
                    PluginStatus::Modified
                }
            } else {
                // Fail-closed for legacy pre-receipt installs whose on-disk hash differs from pinned:
                // refuse to overwrite without `--force` so user custom edits are never clobbered.
                if first_detail.is_none() {
                    first_detail = Some(
                        "modified or pre-receipt legacy install (no receipt in installed.json; pass --force to overwrite)"
                            .to_string(),
                    );
                }
                PluginStatus::Modified
            }
        };

        if root_status != PluginStatus::NotInstalled {
            all_file_records.extend(root_records);
        }
        overall_status = Some(merge_plugin_status(overall_status, root_status));
    }

    let final_status = match overall_status {
        Some(st) => st,
        None => {
            if any_present || receipt.is_some() {
                PluginStatus::Corrupt
            } else {
                PluginStatus::NotInstalled
            }
        }
    };

    PluginInspection {
        spec,
        status: final_status,
        target_paths,
        disk_tree_sha256: representative_disk_tree,
        receipt_tree_sha256: receipt_tree,
        files: all_file_records,
        detail: first_detail,
    }
}

fn merge_plugin_status(acc: Option<PluginStatus>, next: PluginStatus) -> PluginStatus {
    let Some(cur) = acc else {
        return next;
    };
    // Priority: Corrupt > Modified > Outdated > UpToDate > NotInstalled.
    let rank = |s: PluginStatus| -> u8 {
        match s {
            PluginStatus::NotInstalled => 0,
            PluginStatus::UpToDate => 1,
            PluginStatus::Outdated => 2,
            PluginStatus::Modified => 3,
            PluginStatus::Corrupt => 4,
        }
    };
    if rank(next) > rank(cur) { next } else { cur }
}

/// Validates a plugin archive download URL fail-closed:
/// - Requires `https://` with a non-empty host and no embedded userinfo/credentials
/// - Permits `http://` ONLY for local loopback (`127.0.0.1` or `[::1]`) for local testing.
pub fn validate_plugin_download_url(raw: &str) -> Result<Uri, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("plugin archive URL must not be empty".to_string());
    }
    if trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(
            "plugin archive URL must not contain whitespace or control characters".to_string(),
        );
    }

    let uri: Uri = trimmed
        .parse()
        .map_err(|e| format!("invalid plugin archive URL '{trimmed}': {e}"))?;

    let scheme = uri
        .scheme_str()
        .ok_or_else(|| format!("missing URL scheme in '{trimmed}' (expected https://)"))?;

    let authority = uri
        .authority()
        .ok_or_else(|| format!("missing host in URL '{trimmed}'"))?;
    if authority.as_str().contains('@') {
        return Err(format!(
            "refusing URL with embedded credentials/userinfo: '{trimmed}'"
        ));
    }

    let host = uri
        .host()
        .ok_or_else(|| format!("missing host in URL '{trimmed}'"))?;
    if host.is_empty() {
        return Err(format!("empty host in URL '{trimmed}'"));
    }

    match scheme {
        "https" => Ok(uri),
        "http" => {
            if matches!(host, "127.0.0.1" | "[::1]" | "::1") {
                Ok(uri)
            } else {
                Err(format!(
                    "refusing insecure http:// URL '{trimmed}': https:// is required (http:// is allowed only for 127.0.0.1 / [::1])"
                ))
            }
        }
        other => Err(format!(
            "unsupported URL scheme '{other}' in '{trimmed}': https:// is required"
        )),
    }
}

fn detect_telegram_secret_name_from_config(config_path: &Path) -> String {
    let Ok(map) = NodeFile::read_document_or_empty(config_path) else {
        return DEFAULT_TELEGRAM_SECRET_NAME.to_string();
    };
    let Some(plugins) = map.get("plugins").and_then(Value::as_array) else {
        return DEFAULT_TELEGRAM_SECRET_NAME.to_string();
    };
    for entry in plugins {
        let Some(obj) = entry.as_object() else {
            continue;
        };
        if obj.get("id").and_then(Value::as_str).map(str::trim) != Some("telegram") {
            continue;
        }
        if let Some(secret_name) = obj
            .get("env")
            .and_then(Value::as_object)
            .and_then(|env| env.get("TELEGRAM_BOT_TOKEN"))
            .and_then(Value::as_object)
            .filter(|s| s.len() == 1)
            .and_then(|s| s.get("secret"))
            .and_then(Value::as_str)
            .filter(|name| validate_secret_name(name).is_ok())
        {
            return secret_name.to_string();
        }
    }
    DEFAULT_TELEGRAM_SECRET_NAME.to_string()
}

/// Resolves an absolute path to the `node` runtime binary from `PATH` or common version-manager
/// / Homebrew locations without failing if Node.js is not yet installed.
pub fn detect_node_path(home_override: Option<&Path>) -> Option<String> {
    let bin_name = if cfg!(windows) { "node.exe" } else { "node" };

    if let Some(path_os) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_os) {
            if dir.as_os_str().is_empty() {
                continue;
            }
            let cand = dir.join(bin_name);
            if is_executable_file(&cand) {
                let abs = fs::canonicalize(&cand).unwrap_or(cand);
                return Some(abs.display().to_string());
            }
        }
    }

    let mut fallback_candidates: Vec<PathBuf> = Vec::new();
    #[cfg(unix)]
    {
        fallback_candidates.push(PathBuf::from("/opt/homebrew/bin/node"));
        fallback_candidates.push(PathBuf::from("/usr/local/bin/node"));
        fallback_candidates.push(PathBuf::from("/usr/bin/node"));
    }
    #[cfg(windows)]
    {
        if let Ok(pf) = std::env::var("ProgramFiles") {
            fallback_candidates.push(PathBuf::from(pf).join("nodejs").join("node.exe"));
        }
    }

    if let Some(home) = resolve_home_dir(home_override) {
        fallback_candidates.push(home.join(".volta").join("bin").join(bin_name));
        fallback_candidates.push(
            home.join(".local")
                .join("share")
                .join("mise")
                .join("shims")
                .join(bin_name),
        );
        fallback_candidates.push(home.join(".asdf").join("shims").join(bin_name));
        fallback_candidates.push(home.join(".fnm").join("current").join("bin").join(bin_name));

        let nvm_dir = home.join(".nvm").join("versions").join("node");
        if let Ok(entries) = fs::read_dir(&nvm_dir) {
            let mut nvm_bins: Vec<(String, PathBuf)> = entries
                .filter_map(Result::ok)
                .map(|e| {
                    let name = e.file_name().to_string_lossy().into_owned();
                    let bin = e.path().join("bin").join(bin_name);
                    (name, bin)
                })
                .filter(|(_, bin)| is_executable_file(bin))
                .collect();
            nvm_bins.sort_by(|(a, _), (b, _)| compare_nvm_versions(b, a));
            for (_, bin) in nvm_bins {
                fallback_candidates.push(bin);
            }
        }
    }

    for cand in fallback_candidates {
        if is_executable_file(&cand) {
            let abs = fs::canonicalize(&cand).unwrap_or(cand);
            return Some(abs.display().to_string());
        }
    }

    None
}

fn compare_nvm_versions(a: &str, b: &str) -> std::cmp::Ordering {
    let parse = |s: &str| -> (u64, u64, u64) {
        let stripped = s.strip_prefix('v').unwrap_or(s);
        let mut it = stripped.split('.');
        let maj = it.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        let min = it.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        let pat = it.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        (maj, min, pat)
    };
    parse(a).cmp(&parse(b)).then_with(|| a.cmp(b))
}

fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        (meta.permissions().mode() & 0o111) != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

/// RAII private temporary staging directory (`0700` on Unix) cleaned up unconditionally on `Drop`.
struct TempStageDir {
    path: PathBuf,
}

impl TempStageDir {
    fn create(prefix: &str) -> Result<Self, String> {
        let rng = SystemRandom::new();
        let mut suffix = [0u8; 8];
        rng.fill(&mut suffix)
            .map_err(|_| "OS CSPRNG failure".to_string())?;
        let path = std::env::temp_dir().join(format!("{prefix}-{}", hex::encode(suffix)));
        fs::create_dir(&path)
            .map_err(|e| format!("failed to create staging dir {}: {e}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if let Err(e) = fs::set_permissions(&path, fs::Permissions::from_mode(0o700)) {
                let _ = fs::remove_dir_all(&path);
                return Err(format!(
                    "failed to chmod 0700 staging dir {}: {e}",
                    path.display()
                ));
            }
        }
        Ok(Self { path })
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempStageDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn read_regular_file_checked(path: &Path) -> Result<Vec<u8>, String> {
    let meta = fs::symlink_metadata(path)
        .map_err(|e| format!("failed to stat {}: {e}", path.display()))?;
    if meta.file_type().is_symlink() {
        return Err(format!(
            "refusing symlink at {} (regular file required)",
            path.display()
        ));
    }
    if !meta.file_type().is_file() {
        return Err(format!("expected regular file at {}", path.display()));
    }
    if meta.len() as usize > MAX_ARCHIVE_BYTES {
        return Err(format!(
            "file {} exceeds {} byte safety limit",
            path.display(),
            MAX_ARCHIVE_BYTES
        ));
    }
    fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))
}

fn resolve_redirect_url(current_uri: &Uri, location: &str) -> Result<Uri, PluginInstallError> {
    let next_url = if location.starts_with("http://") || location.starts_with("https://") {
        location.to_string()
    } else if location.starts_with('/') {
        let scheme = current_uri.scheme_str().unwrap_or("https");
        let authority = current_uri
            .authority()
            .map(|a| a.as_str())
            .unwrap_or_default();
        format!("{scheme}://{authority}{location}")
    } else {
        return Err(PluginInstallError::new(
            "UNSAFE_REDIRECT",
            format!("Refusing unsupported redirect Location '{location}'"),
        ));
    };

    let next_uri = validate_plugin_download_url(&next_url)
        .map_err(|e| PluginInstallError::new("UNSAFE_REDIRECT", e))?;
    if current_uri.scheme_str() == Some("https") && next_uri.scheme_str() != Some("https") {
        return Err(PluginInstallError::new(
            "UNSAFE_REDIRECT",
            format!("Refusing HTTPS-to-HTTP downgrade redirect to '{next_url}'"),
        ));
    }
    Ok(next_uri)
}

async fn download_plugin_archive(
    initial_url: &str,
) -> Result<(Vec<u8>, String), PluginInstallError> {
    let mut current_url = initial_url.trim().to_string();
    let mut current_uri = validate_plugin_download_url(&current_url)
        .map_err(|e| PluginInstallError::new("UNSAFE_URL", e))?;
    let client = build_http_client::<Empty<Bytes>>()
        .map_err(|e| PluginInstallError::new("HTTP_INIT_ERROR", e))?;

    for redirect_count in 0..=MAX_REDIRECTS {
        let req = Request::builder()
            .method(Method::GET)
            .uri(&current_uri)
            .header(
                header::USER_AGENT,
                format!("hyp/{}", env!("CARGO_PKG_VERSION")),
            )
            .body(Empty::new())
            .map_err(|e| {
                PluginInstallError::new("HTTP_ERROR", format!("Failed to build request: {e}"))
            })?;

        let resp = tokio::time::timeout(HTTP_TIMEOUT, client.request(req))
            .await
            .map_err(|_| {
                PluginInstallError::new(
                    "HTTP_TIMEOUT",
                    format!(
                        "GET {} timed out after {}s",
                        redact_source_location(&current_url),
                        HTTP_TIMEOUT.as_secs()
                    ),
                )
            })?
            .map_err(|e| {
                PluginInstallError::new(
                    "HTTP_ERROR",
                    format!("GET {} failed: {e}", redact_source_location(&current_url)),
                )
            })?;

        let status = resp.status();
        if status.is_redirection() {
            if redirect_count >= MAX_REDIRECTS {
                return Err(PluginInstallError::new(
                    "TOO_MANY_REDIRECTS",
                    format!(
                        "GET {} exceeded {MAX_REDIRECTS} redirects",
                        redact_source_location(&current_url)
                    ),
                ));
            }
            let location = resp
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    PluginInstallError::new(
                        "HTTP_ERROR",
                        format!(
                            "GET {} returned redirect HTTP {} without Location header",
                            redact_source_location(&current_url),
                            status.as_u16()
                        ),
                    )
                })?;
            let next_uri = resolve_redirect_url(&current_uri, location)?;
            current_url = next_uri.to_string();
            current_uri = next_uri;
            continue;
        }

        if !status.is_success() {
            return Err(PluginInstallError::new(
                "HTTP_STATUS",
                format!(
                    "GET {} returned HTTP {}",
                    redact_source_location(&current_url),
                    status.as_u16()
                ),
            ));
        }

        let mut body = resp.into_body();
        let mut out = Vec::new();
        while let Some(frame_res) = body.frame().await {
            let frame = frame_res.map_err(|e| {
                PluginInstallError::new("HTTP_ERROR", format!("body read error: {e}"))
            })?;
            if let Some(chunk) = frame.data_ref() {
                if out.len().saturating_add(chunk.len()) > MAX_ARCHIVE_BYTES {
                    return Err(PluginInstallError::new(
                        "RESPONSE_TOO_LARGE",
                        format!(
                            "Download from {} exceeds {MAX_ARCHIVE_BYTES} byte limit",
                            redact_source_location(&current_url)
                        ),
                    ));
                }
                out.extend_from_slice(chunk);
            }
        }
        return Ok((out, redact_source_location(&current_url)));
    }

    Err(PluginInstallError::new(
        "TOO_MANY_REDIRECTS",
        format!(
            "GET {} exceeded redirect limit",
            redact_source_location(initial_url)
        ),
    ))
}

/// Strips any URL query string (`?sig=...`, `?sv=...`) or fragment (`#...`) from HTTP(S)
/// `sourceLocation` values so short-lived CDN / Azure blob SAS signatures are never echoed into
/// JSON envelopes, terminal logs, or error messages. Local filesystem paths pass through unchanged.
pub fn redact_source_location(raw: &str) -> String {
    let lower = raw.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        let cut = raw.find('?').into_iter().chain(raw.find('#')).min();
        match cut {
            Some(idx) => raw[..idx].to_string(),
            None => raw.to_string(),
        }
    } else {
        raw.to_string()
    }
}

fn normalize_archive_rel_path(archive_path: &str) -> &str {
    let without_dot = archive_path.strip_prefix("./").unwrap_or(archive_path);
    without_dot.strip_prefix("plugins/").unwrap_or(without_dot)
}

/// Unpacks `archive_bytes` into an ephemeral private staging directory and verifies EVERY
/// required file in constant time against its compile-time pinned SHA-256 BEFORE returning bytes.
fn extract_and_verify_archive(
    archive_bytes: &[u8],
    required_entries: &[&'static PinnedPluginFile],
) -> Result<BTreeMap<&'static str, Vec<u8>>, PluginInstallError> {
    if archive_bytes.is_empty() {
        return Err(PluginInstallError::new(
            "INVALID_ARCHIVE",
            "Plugin archive is empty",
        ));
    }
    if archive_bytes.len() > MAX_ARCHIVE_BYTES {
        return Err(PluginInstallError::new(
            "ARCHIVE_TOO_LARGE",
            format!("Plugin archive exceeds {MAX_ARCHIVE_BYTES} byte limit"),
        ));
    }

    let stage = TempStageDir::create("hyp-plugin-stage")
        .map_err(|e| PluginInstallError::new("IO_ERROR", e))?;
    let unpack_dir = stage.path().join("unpacked");
    let unpacked = unpack_tar_gz(
        Cursor::new(archive_bytes),
        &unpack_dir,
        &TarUnpackOptions {
            max_files: MAX_ARCHIVE_FILES,
            max_raw_bytes: MAX_ARCHIVE_BYTES as u64,
            attachment_guard: None,
        },
    )
    .map_err(|e| {
        PluginInstallError::new(
            "EXTRACT_FAILED",
            format!("Failed to safely unpack plugin archive (fail-closed): {e}"),
        )
    })?;

    let mut extracted_by_rel: BTreeMap<String, PathBuf> = BTreeMap::new();
    for file in &unpacked.files {
        let rel = normalize_archive_rel_path(&file.archive_path).to_string();
        if extracted_by_rel
            .insert(rel.clone(), file.disk_path.clone())
            .is_some()
        {
            return Err(PluginInstallError::new(
                "INVALID_ARCHIVE",
                format!("Archive contains duplicate normalized plugin entry '{rel}'"),
            ));
        }
    }

    let mut verified_files: BTreeMap<&'static str, Vec<u8>> = BTreeMap::new();
    for &entry in required_entries {
        if verified_files.contains_key(entry.rel_path) {
            continue;
        }
        let Some(disk_path) = extracted_by_rel.get(entry.rel_path) else {
            return Err(PluginInstallError::new(
                "MISSING_PLUGIN_FILE",
                format!(
                    "Plugin archive is missing required file '{}' (fail-closed, 0 bytes installed)",
                    entry.rel_path
                ),
            ));
        };
        let raw = read_regular_file_checked(disk_path)
            .map_err(|e| PluginInstallError::new("IO_ERROR", e))?;
        let payload = if entry.is_binary {
            raw
        } else {
            normalize_crlf(&raw)
        };
        let actual_sha = hex::encode(Sha256::digest(&payload));
        if !ct_eq(actual_sha.as_bytes(), entry.sha256.as_bytes()) {
            return Err(PluginInstallError::new(
                "CHECKSUM_MISMATCH",
                format!(
                    "SHA-256 verification failed for '{}' (fail-closed, 0 bytes installed): expected {}, got {}",
                    entry.rel_path, entry.sha256, actual_sha
                ),
            ));
        }
        verified_files.insert(entry.rel_path, payload);
    }

    Ok(verified_files)
}

/// Reads and verifies all required plugin files directly from a local directory (`--from-dir` /
/// `HYPHAE_PLUGINS_DIR`), supporting both `<dir>/<rel_path>` and `<dir>/plugins/<rel_path>`.
fn read_and_verify_from_dir(
    dir: &Path,
    required_entries: &[&'static PinnedPluginFile],
) -> Result<BTreeMap<&'static str, Vec<u8>>, PluginInstallError> {
    if !dir.is_dir() {
        return Err(PluginInstallError::new(
            "INVALID_SOURCE_DIR",
            format!("Plugin source directory does not exist: {}", dir.display()),
        ));
    }

    let probe_rel = required_entries
        .first()
        .map(|e| e.rel_path)
        .unwrap_or("sdk/client.mjs");
    let base_dir = if dir.join(probe_rel).exists() || dir.join("sdk").join("client.mjs").exists() {
        dir.to_path_buf()
    } else if dir.join("plugins").join(probe_rel).exists()
        || dir.join("plugins").join("sdk").join("client.mjs").exists()
    {
        dir.join("plugins")
    } else {
        dir.to_path_buf()
    };

    let mut verified_files: BTreeMap<&'static str, Vec<u8>> = BTreeMap::new();
    for &entry in required_entries {
        if verified_files.contains_key(entry.rel_path) {
            continue;
        }
        let full_path = base_dir.join(entry.rel_path);
        if !full_path.exists() && fs::symlink_metadata(&full_path).is_err() {
            return Err(PluginInstallError::new(
                "MISSING_PLUGIN_FILE",
                format!(
                    "Required plugin file '{}' not found under {} (fail-closed, 0 bytes installed)",
                    entry.rel_path,
                    base_dir.display()
                ),
            ));
        }
        let raw = read_regular_file_checked(&full_path)
            .map_err(|e| PluginInstallError::new("INVALID_SOURCE_FILE", e))?;
        let payload = if entry.is_binary {
            raw
        } else {
            normalize_crlf(&raw)
        };
        let actual_sha = hex::encode(Sha256::digest(&payload));
        if !ct_eq(actual_sha.as_bytes(), entry.sha256.as_bytes()) {
            return Err(PluginInstallError::new(
                "CHECKSUM_MISMATCH",
                format!(
                    "SHA-256 verification failed for '{}' (fail-closed, 0 bytes installed): expected {}, got {}",
                    entry.rel_path, entry.sha256, actual_sha
                ),
            ));
        }
        verified_files.insert(entry.rel_path, payload);
    }

    Ok(verified_files)
}

fn non_empty_env_path(var: &str) -> Option<PathBuf> {
    let raw = std::env::var_os(var)?;
    if raw.is_empty() {
        return None;
    }
    if let Some(s) = raw.to_str() {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return None;
        }
        return Some(PathBuf::from(trimmed));
    }
    Some(PathBuf::from(raw))
}

fn non_empty_env_str(var: &str) -> Option<String> {
    let val = std::env::var(var).ok()?;
    let trimmed = val.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn write_verified_cache(state_dir: &Path, archive_bytes: &[u8]) {
    let cache_path = cached_plugins_archive_path(state_dir);
    if let Some(parent) = cache_path.parent() {
        if ensure_dir(parent, true).is_err() {
            return;
        }
    }
    if let Ok(meta) = fs::symlink_metadata(&cache_path) {
        if meta.file_type().is_symlink() {
            return;
        }
    }
    let _ = write_atomic_file(&cache_path, archive_bytes, true);
}

type VerifiedPluginSource = (InstallSourceKind, String, BTreeMap<&'static str, Vec<u8>>);

/// Resolves and verifies all `required_entries` using strict precedence:
/// 1. Explicit CLI `--archive` / `--from-dir` / `--url`
/// 2. `HYPHAE_PLUGINS_ARCHIVE`
/// 3. `HYPHAE_PLUGINS_DIR`
/// 4. Local verified cache `<state_dir>/plugins-cache/hyp-v<ver>-plugins.tar.gz`
/// 5. HTTPS release download (or `HYPHAE_PLUGINS_URL`), saving verified tarball into cache.
fn resolve_and_verify_files(
    state_dir: &Path,
    required_entries: &[&'static PinnedPluginFile],
    source: PluginSourceOverrides<'_>,
) -> Result<VerifiedPluginSource, PluginInstallError> {
    // 1a. Explicit CLI --archive
    if let Some(archive_path) = source.archive {
        let bytes = read_regular_file_checked(archive_path)
            .map_err(|e| PluginInstallError::new("ARCHIVE_READ_ERROR", e))?;
        let files = extract_and_verify_archive(&bytes, required_entries)?;
        return Ok((
            InstallSourceKind::Archive,
            archive_path.display().to_string(),
            files,
        ));
    }

    // 1b. Explicit CLI --from-dir
    if let Some(dir) = source.from_dir {
        let files = read_and_verify_from_dir(dir, required_entries)?;
        return Ok((InstallSourceKind::Dir, dir.display().to_string(), files));
    }

    // 1c. Explicit CLI --url (always fetches directly, bypassing cache so overrides work deterministically)
    if let Some(explicit_url) = source.url {
        let (archive_bytes, final_url) = block_on_download(explicit_url)?;
        let files = extract_and_verify_archive(&archive_bytes, required_entries)?;
        write_verified_cache(state_dir, &archive_bytes);
        return Ok((InstallSourceKind::Release, final_url, files));
    }

    // 2. Environment HYPHAE_PLUGINS_ARCHIVE
    if let Some(env_archive) = non_empty_env_path("HYPHAE_PLUGINS_ARCHIVE") {
        let bytes = read_regular_file_checked(&env_archive)
            .map_err(|e| PluginInstallError::new("ARCHIVE_READ_ERROR", e))?;
        let files = extract_and_verify_archive(&bytes, required_entries)?;
        return Ok((
            InstallSourceKind::Archive,
            env_archive.display().to_string(),
            files,
        ));
    }

    // 3. Environment HYPHAE_PLUGINS_DIR
    if let Some(env_dir) = non_empty_env_path("HYPHAE_PLUGINS_DIR") {
        let files = read_and_verify_from_dir(&env_dir, required_entries)?;
        return Ok((InstallSourceKind::Dir, env_dir.display().to_string(), files));
    }

    // 4. Local verified cache `<state_dir>/plugins-cache/hyp-v<ver>-plugins.tar.gz`
    let cache_path = cached_plugins_archive_path(state_dir);
    if cache_path.is_file() {
        if let Ok(cached_bytes) = read_regular_file_checked(&cache_path) {
            if let Ok(files) = extract_and_verify_archive(&cached_bytes, required_entries) {
                return Ok((
                    InstallSourceKind::Cache,
                    cache_path.display().to_string(),
                    files,
                ));
            }
        }
    }

    // 5. HTTPS release download (`HYPHAE_PLUGINS_URL` override or GitHub Releases default)
    let env_url = non_empty_env_str("HYPHAE_PLUGINS_URL");
    let default_url = default_release_plugins_url();
    let download_url =
        resolve_effective_plugins_download_url(None, env_url.as_deref(), &default_url);
    let (archive_bytes, final_url) = block_on_download(&download_url)?;
    let files = extract_and_verify_archive(&archive_bytes, required_entries)?;
    write_verified_cache(state_dir, &archive_bytes);
    Ok((InstallSourceKind::Release, final_url, files))
}

fn block_on_download(url: &str) -> Result<(Vec<u8>, String), PluginInstallError> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            PluginInstallError::new(
                "RUNTIME_ERROR",
                format!("Failed to initialize async runtime: {e}"),
            )
        })?;
    rt.block_on(download_plugin_archive(url))
}

/// Safely writes a single verified plugin file under `target_root`, guaranteeing we NEVER follow
/// symlinks at or below `target_root` (while preserving parent symlinks above `target_root` such
/// as `gateway/skills -> ~/.claude/skills`).
fn write_verified_plugin_file(
    target_root: &Path,
    dest: &Path,
    bytes: &[u8],
    private: bool,
    replace_symlinks: bool,
) -> Result<(), PluginInstallError> {
    // Ensure target_root itself is not a symlink.
    if let Ok(meta) = fs::symlink_metadata(target_root) {
        if meta.file_type().is_symlink() {
            if replace_symlinks {
                fs::remove_file(target_root).map_err(|e| {
                    PluginInstallError::new(
                        "IO_ERROR",
                        format!("failed to remove symlink {}: {e}", target_root.display()),
                    )
                })?;
            } else {
                return Err(PluginInstallError::new(
                    "SYMLINK_REJECTED",
                    format!(
                        "refusing symlink at plugin directory {} (pass --force to replace)",
                        target_root.display()
                    ),
                ));
            }
        }
    }

    // Check every intermediate directory component under target_root and the leaf file itself.
    let rel = dest.strip_prefix(target_root).map_err(|_| {
        PluginInstallError::new(
            "IO_ERROR",
            format!(
                "destination {} escapes plugin target root {}",
                dest.display(),
                target_root.display()
            ),
        )
    })?;

    let mut cur = target_root.to_path_buf();
    let comps: Vec<Component<'_>> = rel.components().collect();
    for (idx, comp) in comps.iter().enumerate() {
        let is_leaf = idx + 1 == comps.len();
        match comp {
            Component::Normal(seg) => cur.push(seg),
            _ => {
                return Err(PluginInstallError::new(
                    "IO_ERROR",
                    format!("unsafe path component in {}", dest.display()),
                ));
            }
        }
        if let Ok(meta) = fs::symlink_metadata(&cur) {
            if meta.file_type().is_symlink() {
                if replace_symlinks {
                    fs::remove_file(&cur).map_err(|e| {
                        PluginInstallError::new(
                            "IO_ERROR",
                            format!("failed to unlink symlink {}: {e}", cur.display()),
                        )
                    })?;
                } else {
                    return Err(PluginInstallError::new(
                        "SYMLINK_REJECTED",
                        format!(
                            "refusing symlink at {} (pass --force to replace)",
                            cur.display()
                        ),
                    ));
                }
            } else if !is_leaf && !meta.file_type().is_dir() {
                return Err(PluginInstallError::new(
                    "IO_ERROR",
                    format!("expected directory at {}", cur.display()),
                ));
            }
        }
    }

    ensure_dir(target_root, private).map_err(|e| PluginInstallError::new("IO_ERROR", e))?;
    write_atomic_file(dest, bytes, private).map_err(|e| PluginInstallError::new("IO_ERROR", e))
}

/// Writes all verified files for a single plugin spec across its `target_roots`, plus any
/// minimal UI-only wrapper files for `claude-panel`.
fn write_plugin_to_targets(
    spec: &'static PinnedPluginSpec,
    target_roots: &[PathBuf],
    verified_files: &BTreeMap<&'static str, Vec<u8>>,
    replace_symlinks: bool,
) -> Result<Vec<String>, PluginInstallError> {
    let private = is_private_plugin_target(spec.id);
    let mut written_paths = Vec::new();

    for root in target_roots {
        // For herdr-mod, replace any legacy dev-link symlink on `mods/hyphae-pane` / `mods/hyphae-panel`
        // with a real directory so macOS FSEvents hot-reload works immediately.
        if spec.id == HERDR_MOD_ID {
            for mod_sub in ["hyphae-pane", "hyphae-panel"] {
                let mod_dir = root.join(mod_sub);
                if let Ok(meta) = fs::symlink_metadata(&mod_dir) {
                    if meta.file_type().is_symlink() {
                        if replace_symlinks {
                            fs::remove_file(&mod_dir).map_err(|e| {
                                PluginInstallError::new(
                                    "IO_ERROR",
                                    format!("failed to remove symlink {}: {e}", mod_dir.display()),
                                )
                            })?;
                        } else {
                            return Err(PluginInstallError::new(
                                "SYMLINK_REJECTED",
                                format!(
                                    "refusing symlink at {} (pass --force to replace)",
                                    mod_dir.display()
                                ),
                            ));
                        }
                    }
                }
            }
        }

        if spec.id == CLAUDE_PANEL_ID {
            let manifest_dest = root.join(".claude-plugin").join("plugin.json");
            let hooks_dest = root.join("hooks").join("hooks.json");
            write_verified_plugin_file(
                root,
                &manifest_dest,
                CLAUDE_PANEL_MANIFEST_JSON.as_bytes(),
                false,
                replace_symlinks,
            )?;
            write_verified_plugin_file(
                root,
                &hooks_dest,
                CLAUDE_PANEL_HOOKS_JSON.as_bytes(),
                false,
                replace_symlinks,
            )?;
            written_paths.push(manifest_dest.display().to_string());
            written_paths.push(hooks_dest.display().to_string());
        }

        for entry in spec.files {
            let dest = rel_path_to_disk_path(spec.id, root, entry.rel_path);
            let bytes = verified_files
                .get(entry.rel_path)
                .expect("verified entry present");
            write_verified_plugin_file(root, &dest, bytes, private, replace_symlinks)?;
            written_paths.push(dest.display().to_string());
        }
    }

    Ok(written_paths)
}

fn record_receipt(
    receipts: &mut PluginReceiptsFile,
    spec: &'static PinnedPluginSpec,
    target_roots: &[PathBuf],
) {
    receipts.schema_version = RECEIPT_SCHEMA_VERSION;
    receipts.installed.insert(
        spec.id.to_string(),
        PluginInstallReceipt {
            kind: spec.kind.as_str().to_string(),
            tree_sha256: spec.tree_sha256.to_string(),
            installed_at: now_ms(),
            target_paths: target_roots
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
        },
    );
}

fn reload_hint_for_plugin(plugin_id: &str) -> &'static str {
    match plugin_id {
        CLAUDE_PANEL_ID | CLAUDE_CODE_ID => {
            "Restart Claude Code so it loads the updated Hyphae plugin/panel."
        }
        HERDR_MOD_ID => {
            "Herdr hot-reloads updated hyphae-pane/hyphae-panel mods automatically via FSEvents."
        }
        _ => {
            "Run `hyp service restart --json` so running bridge subprocesses load updated scripts."
        }
    }
}

// ============================================================================
// Public Helpers Used by `setup.rs`, `herdr_mod.rs`, and `status_doctor.rs`
// ============================================================================

/// Installs (or verifies already up-to-date) `claude-panel` across deduplicated Claude profiles.
/// Never touches the network if all target profiles are already up to date on disk!
pub fn install_claude_panel_for_profiles(
    state_dir: &Path,
    profiles: &[ClaudeConfigProfile],
    source: PluginSourceOverrides<'_>,
    dry_run: bool,
) -> Result<HarnessPluginInstallReport, PluginInstallError> {
    let spec = pinned_spec_for(CLAUDE_PANEL_ID).expect("claude-panel pinned spec");
    let target_roots = dedup_claude_panel_dirs(profiles);

    if dry_run {
        let mut planned = Vec::new();
        for root in &target_roots {
            planned.push(
                root.join(".claude-plugin")
                    .join("plugin.json")
                    .display()
                    .to_string(),
            );
            planned.push(root.join("hooks").join("hooks.json").display().to_string());
            for entry in spec.files {
                planned.push(
                    rel_path_to_disk_path(spec.id, root, entry.rel_path)
                        .display()
                        .to_string(),
                );
            }
        }
        return Ok(HarnessPluginInstallReport {
            files: planned,
            target_paths: target_roots,
        });
    }

    // Fast path: if every target root ALREADY matches compile-time pinned digests on disk
    // (with valid wrappers), skip downloading entirely and ensure receipt is recorded!
    let all_up_to_date = !target_roots.is_empty()
        && target_roots.iter().all(|root| {
            check_claude_panel_wrappers(root).is_none()
                && spec.files.iter().all(|entry| {
                    let disk_path = rel_path_to_disk_path(spec.id, root, entry.rel_path);
                    let (present, ok, _, _) =
                        inspect_plugin_file(root, &disk_path, entry.sha256, entry.is_binary);
                    present && ok
                })
        });

    if all_up_to_date {
        let mut files = Vec::new();
        for root in &target_roots {
            files.push(
                root.join(".claude-plugin")
                    .join("plugin.json")
                    .display()
                    .to_string(),
            );
            files.push(root.join("hooks").join("hooks.json").display().to_string());
            for entry in spec.files {
                files.push(
                    rel_path_to_disk_path(spec.id, root, entry.rel_path)
                        .display()
                        .to_string(),
                );
            }
        }
        let mut receipts = load_receipts(state_dir).unwrap_or_default();
        complete_harness_rename(spec, &target_roots, receipts.installed.get(spec.id))?;
        record_receipt(&mut receipts, spec, &target_roots);
        let _ = save_receipts(state_dir, &receipts);
        return Ok(HarnessPluginInstallReport {
            files,
            target_paths: target_roots,
        });
    }

    let required: Vec<&'static PinnedPluginFile> = spec.files.iter().collect();
    let (_source_kind, _loc, verified_files) =
        resolve_and_verify_files(state_dir, &required, source)?;
    let files = write_plugin_to_targets(spec, &target_roots, &verified_files, true)?;

    let mut receipts =
        load_receipts(state_dir).map_err(|e| PluginInstallError::new("RECEIPT_ERROR", e))?;
    complete_harness_rename(spec, &target_roots, receipts.installed.get(spec.id))?;
    record_receipt(&mut receipts, spec, &target_roots);
    save_receipts(state_dir, &receipts).map_err(|e| PluginInstallError::new("RECEIPT_ERROR", e))?;

    Ok(HarnessPluginInstallReport {
        files,
        target_paths: target_roots,
    })
}

/// Installs (or verifies already up-to-date) `herdr-mod` (`hyphae-pane` + `hyphae-panel`) into
/// `<herdr_home>/mods/` using real directories (never symlinks) and records the receipt.
pub fn install_herdr_mod_files(
    state_dir: &Path,
    herdr_home: &Path,
    source: PluginSourceOverrides<'_>,
    dry_run: bool,
) -> Result<HarnessPluginInstallReport, PluginInstallError> {
    let spec = pinned_spec_for(HERDR_MOD_ID).expect("herdr-mod pinned spec");
    let mods_root = herdr_home.join("mods");
    let target_roots = vec![mods_root.clone()];

    if dry_run {
        let planned: Vec<String> = spec
            .files
            .iter()
            .map(|entry| {
                rel_path_to_disk_path(spec.id, &mods_root, entry.rel_path)
                    .display()
                    .to_string()
            })
            .collect();
        return Ok(HarnessPluginInstallReport {
            files: planned,
            target_paths: target_roots,
        });
    }

    // Fast path: if all 9 mod files are already real regular files matching pinned digests, skip download!
    let dir_symlinks_clean = ["hyphae-pane", "hyphae-panel"].iter().all(|sub| {
        fs::symlink_metadata(mods_root.join(sub))
            .map(|m| !m.file_type().is_symlink() && m.file_type().is_dir())
            .unwrap_or(false)
    });
    let all_up_to_date = dir_symlinks_clean
        && spec.files.iter().all(|entry| {
            let disk_path = rel_path_to_disk_path(spec.id, &mods_root, entry.rel_path);
            let (present, ok, _, _) =
                inspect_plugin_file(&mods_root, &disk_path, entry.sha256, entry.is_binary);
            present && ok
        });

    if all_up_to_date {
        let files: Vec<String> = spec
            .files
            .iter()
            .map(|entry| {
                rel_path_to_disk_path(spec.id, &mods_root, entry.rel_path)
                    .display()
                    .to_string()
            })
            .collect();
        let mut receipts = load_receipts(state_dir).unwrap_or_default();
        record_receipt(&mut receipts, spec, &target_roots);
        let _ = save_receipts(state_dir, &receipts);
        return Ok(HarnessPluginInstallReport {
            files,
            target_paths: target_roots,
        });
    }

    let required: Vec<&'static PinnedPluginFile> = spec.files.iter().collect();
    let (_source_kind, _loc, verified_files) =
        resolve_and_verify_files(state_dir, &required, source)?;
    let files = write_plugin_to_targets(spec, &target_roots, &verified_files, true)?;

    let mut receipts =
        load_receipts(state_dir).map_err(|e| PluginInstallError::new("RECEIPT_ERROR", e))?;
    record_receipt(&mut receipts, spec, &target_roots);
    save_receipts(state_dir, &receipts).map_err(|e| PluginInstallError::new("RECEIPT_ERROR", e))?;

    Ok(HarnessPluginInstallReport {
        files,
        target_paths: target_roots,
    })
}

/// Inspects all installed official plugins & harness mods for `hyp doctor` and `hyp status`.
pub fn inspect_plugins_for_doctor(
    state_dir: &Path,
    home: Option<&Path>,
    explicit_home: bool,
    claude_config_dir: Option<&Path>,
) -> DoctorPluginsReport {
    let plugins_dir = state_dir.join("plugins");
    let receipts_path = receipts_file_path(state_dir);
    let cache_path = cached_plugins_archive_path(state_dir);
    let cache_exists = cache_path.is_file();

    let mut checks = Vec::new();
    let receipts = match load_receipts(state_dir) {
        Ok(r) => r,
        Err(e) => {
            checks.push(CliCheck::fail(
                "plugins.receipts",
                format!("Failed to read plugin receipts: {e}"),
                Some("Run `hyp plugin verify` to inspect installed plugins.".to_string()),
            ));
            PluginReceiptsFile::default()
        }
    };

    let mut summaries = Vec::new();
    let mut up_to_date_count = 0usize;
    let mut outdated_count = 0usize;
    let mut modified_count = 0usize;
    let mut corrupt_count = 0usize;

    let mut any_bridge_installed = false;
    for spec in PINNED_PLUGINS {
        let insp = inspect_plugin(
            spec,
            state_dir,
            home,
            explicit_home,
            claude_config_dir,
            &receipts,
        );
        if insp.status == PluginStatus::NotInstalled {
            continue;
        }
        if is_bridge_consumer(spec.id) {
            any_bridge_installed = true;
        }
        let check_name = format!("plugin:{}", spec.id);
        match insp.status {
            PluginStatus::UpToDate => {
                up_to_date_count += 1;
                checks.push(CliCheck::ok(
                    check_name,
                    format!(
                        "{} verified (tree {})",
                        spec.kind.as_str(),
                        &spec.tree_sha256[..12]
                    ),
                ));
            }
            PluginStatus::Outdated => {
                outdated_count += 1;
                checks.push(CliCheck::warn(
                    check_name,
                    insp.detail
                        .clone()
                        .unwrap_or_else(|| "outdated plugin/mod on disk".to_string()),
                    Some("hyp plugin update --all".to_string()),
                ));
            }
            PluginStatus::Modified => {
                modified_count += 1;
                checks.push(CliCheck::warn(
                    check_name,
                    insp.detail
                        .clone()
                        .unwrap_or_else(|| "locally modified on disk".to_string()),
                    Some(format!(
                        "hyp plugin verify {} (or hyp plugin update {} --force)",
                        spec.id, spec.id
                    )),
                ));
            }
            PluginStatus::Corrupt => {
                corrupt_count += 1;
                checks.push(CliCheck::fail(
                    check_name,
                    insp.detail
                        .clone()
                        .unwrap_or_else(|| "corrupt or tampered plugin installation".to_string()),
                    Some(format!(
                        "hyp plugin verify {} && hyp plugin install {} --force",
                        spec.id, spec.id
                    )),
                ));
            }
            PluginStatus::NotInstalled => {}
        }

        summaries.push(DoctorPluginSummary {
            name: spec.id.to_string(),
            kind: spec.kind.as_str().to_string(),
            status: insp.status,
            pinned_tree_sha256: spec.tree_sha256.to_string(),
            installed_tree_sha256: insp.receipt_tree_sha256,
            disk_tree_sha256: insp.disk_tree_sha256,
            target_paths: insp
                .target_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            detail: insp.detail,
        });
    }

    // If any bridge consumer is installed but `sdk` is completely missing, surface a FAIL check.
    if any_bridge_installed && !summaries.iter().any(|s| s.name == SDK_PLUGIN_ID) {
        corrupt_count += 1;
        checks.push(CliCheck::fail(
            "plugin:sdk",
            "required shared SDK (sdk/client.mjs) is missing while bridge plugins are installed",
            Some("hyp plugin install sdk --force".to_string()),
        ));
    }

    DoctorPluginsReport {
        plugins_dir: plugins_dir.display().to_string(),
        receipts_path: receipts_path.display().to_string(),
        cache_path: cache_path.display().to_string(),
        cache_exists,
        installed_count: summaries.len(),
        up_to_date_count,
        outdated_count,
        modified_count,
        corrupt_count,
        plugins: summaries,
        checks,
    }
}

// ============================================================================
// Subcommand Implementations: list, install, update, verify, remove
// ============================================================================

fn run_plugin_list(
    state_dir_arg: Option<&Path>,
    config_arg: Option<&Path>,
    home_arg: Option<&Path>,
    claude_config_dir_arg: Option<&Path>,
    as_json: bool,
) -> ExitCode {
    let cmd = "plugin list";
    let state_dir = resolve_state_dir(state_dir_arg, config_arg, home_arg);
    let plugins_dir = state_dir.join("plugins");
    let resolved_home = resolve_home_dir(home_arg);
    let explicit_home = home_arg.is_some();
    let node_path = detect_node_path(home_arg);

    let receipts = match load_receipts(&state_dir) {
        Ok(r) => r,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "RECEIPT_ERROR", e, None),
    };

    let mut entries = Vec::with_capacity(PINNED_PLUGINS.len());
    let mut warnings = Vec::new();
    let mut installed_count = 0usize;
    let mut verified_count = 0usize;
    let mut outdated_count = 0usize;
    let mut modified_count = 0usize;
    let mut corrupt_count = 0usize;

    let sdk_spec = pinned_spec_for(SDK_PLUGIN_ID).expect("sdk spec");
    let sdk_insp = inspect_plugin(
        sdk_spec,
        &state_dir,
        resolved_home.as_deref(),
        explicit_home,
        claude_config_dir_arg,
        &receipts,
    );
    let sdk_installed = sdk_insp.status != PluginStatus::NotInstalled;
    let sdk_verified = sdk_insp.status == PluginStatus::UpToDate;
    let sdk_path = plugins_dir.join("sdk").join("client.mjs");

    for spec in PINNED_PLUGINS {
        let insp = inspect_plugin(
            spec,
            &state_dir,
            resolved_home.as_deref(),
            explicit_home,
            claude_config_dir_arg,
            &receipts,
        );
        let installed = insp.status != PluginStatus::NotInstalled;
        let verified =
            insp.status == PluginStatus::UpToDate && (!is_bridge_consumer(spec.id) || sdk_verified);
        if installed {
            installed_count += 1;
            match insp.status {
                PluginStatus::UpToDate => {
                    if verified {
                        verified_count += 1;
                    } else {
                        warnings.push(format!(
                            "{}: shared sdk/client.mjs is missing or unverified",
                            spec.id
                        ));
                    }
                }
                PluginStatus::Outdated => {
                    outdated_count += 1;
                    warnings.push(format!(
                        "{}: {}",
                        spec.id,
                        insp.detail.as_deref().unwrap_or("outdated")
                    ));
                }
                PluginStatus::Modified => {
                    modified_count += 1;
                    warnings.push(format!(
                        "{}: {}",
                        spec.id,
                        insp.detail.as_deref().unwrap_or("locally modified")
                    ));
                }
                PluginStatus::Corrupt => {
                    corrupt_count += 1;
                    warnings.push(format!(
                        "{}: {}",
                        spec.id,
                        insp.detail.as_deref().unwrap_or("corrupt")
                    ));
                }
                PluginStatus::NotInstalled => {}
            }
        }

        let pinned_primary_sha = spec
            .files
            .first()
            .map(|f| f.sha256)
            .unwrap_or(spec.tree_sha256);

        entries.push(PluginListEntry {
            name: spec.id.to_string(),
            kind: spec.kind.as_str().to_string(),
            status: insp.status,
            installed,
            verified,
            script_path: primary_script_display(spec.id, &insp.target_paths),
            onboarding_path: onboarding_tree_display(spec, &insp.target_paths),
            target_paths: insp
                .target_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            pinned_sha256: pinned_primary_sha.to_string(),
            tree_sha256: spec.tree_sha256.to_string(),
            installed_tree_sha256: insp.receipt_tree_sha256,
            disk_tree_sha256: insp.disk_tree_sha256,
            node_path: if spec.kind == PluginKind::Bridge {
                node_path.clone()
            } else {
                None
            },
            detail: insp.detail,
        });
    }

    if node_path.is_none() {
        warnings.push(
            "Node.js (24+) not found in PATH; install Node.js 24+ before running external bridge plugins."
                .to_string(),
        );
    }

    let mut next = Vec::new();
    if installed_count == 0 {
        next.push("hyp plugin install <telegram|slack|claude-panel|herdr-mod> --json".to_string());
    } else {
        if outdated_count > 0 {
            next.push("hyp plugin update --all --json".to_string());
        }
        if modified_count > 0 || corrupt_count > 0 || verified_count < installed_count {
            next.push("hyp plugin verify --json".to_string());
        }
    }

    let summary = format!(
        "{installed_count}/{} official plugins & harness mods installed ({verified_count} up_to_date, {outdated_count} outdated, {modified_count} modified, {corrupt_count} corrupt)",
        PINNED_PLUGINS.len(),
    );

    let cache_path = cached_plugins_archive_path(&state_dir);
    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(summary),
            data: Some(json!({
                "pluginsDir": plugins_dir.display().to_string(),
                "receiptsPath": receipts_file_path(&state_dir).display().to_string(),
                "cachePath": cache_path.display().to_string(),
                "cacheExists": cache_path.is_file(),
                "sdkPath": sdk_path.display().to_string(),
                "sdkInstalled": sdk_installed,
                "sdkVerified": sdk_verified,
                "nodePath": node_path,
                "plugins": entries,
            })),
            warnings,
            next,
            error: None,
        };
        print_json(&envelope);
    } else {
        println!("Plugins directory: {}", plugins_dir.display());
        println!(
            "Archive cache:     {} ({})",
            cache_path.display(),
            if cache_path.is_file() {
                "cached"
            } else {
                "empty"
            }
        );
        println!(
            "Node.js binary:    {}",
            node_path.as_deref().unwrap_or("(not detected)")
        );
        println!();
        println!(
            "{:<14}  {:<8}  {:<13}  {:<12}  Target",
            "Plugin", "Kind", "Status", "Tree SHA"
        );
        println!("{}", "-".repeat(86));
        for e in &entries {
            println!(
                "{:<14}  {:<8}  {:<13}  {:<12}  {}",
                e.name,
                e.kind,
                e.status.as_str(),
                &e.tree_sha256[..12],
                e.script_path
            );
        }
        print_warnings(&warnings);
        print_next_steps(&next);
    }

    ExitCode::from(EXIT_OK)
}

#[allow(clippy::too_many_arguments)]
fn run_plugin_install(
    plugin_arg: &str,
    state_dir_arg: Option<&Path>,
    config_arg: Option<&Path>,
    home_arg: Option<&Path>,
    claude_config_dir_arg: Option<&Path>,
    source: PluginSourceOverrides<'_>,
    force: bool,
    as_json: bool,
) -> ExitCode {
    let cmd = "plugin install";

    let source_flags = usize::from(source.url.is_some())
        + usize::from(source.archive.is_some())
        + usize::from(source.from_dir.is_some());
    if source_flags > 1 {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "CONFLICTING_FLAGS",
            "Specify at most one of --url, --archive, or --from-dir",
            None,
        );
    }

    let requested_targets = match resolve_plugin_targets(plugin_arg) {
        Ok(t) => t,
        Err(msg) => return emit_error(cmd, as_json, EXIT_USAGE, "UNKNOWN_PLUGIN", msg, None),
    };

    let state_dir = resolve_state_dir(state_dir_arg, config_arg, home_arg);
    let plugins_dir = state_dir.join("plugins");
    let resolved_home = resolve_home_dir(home_arg);
    let explicit_home = home_arg.is_some();

    let mut receipts = match load_receipts(&state_dir) {
        Ok(r) => r,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "RECEIPT_ERROR", e, None),
    };

    // Expand bridge installs to also ensure `sdk` is installed & verified alongside them.
    let needs_sdk = requested_targets.iter().any(|s| is_bridge_consumer(s.id));
    let mut install_specs: Vec<&'static PinnedPluginSpec> = Vec::new();
    let mut seen_ids: BTreeSet<&'static str> = BTreeSet::new();
    if needs_sdk && seen_ids.insert(SDK_PLUGIN_ID) {
        install_specs.push(pinned_spec_for(SDK_PLUGIN_ID).expect("sdk spec"));
    }
    for spec in &requested_targets {
        if seen_ids.insert(spec.id) {
            install_specs.push(*spec);
        }
    }

    // Refuse overwriting locally modified plugins unless `--force` is specified.
    if !force {
        for spec in &install_specs {
            let insp = inspect_plugin(
                spec,
                &state_dir,
                resolved_home.as_deref(),
                explicit_home,
                claude_config_dir_arg,
                &receipts,
            );
            if insp.status == PluginStatus::Modified {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "PLUGIN_MODIFIED",
                    format!(
                        "Plugin '{}' has local modifications on disk ({}); refusing to overwrite without --force",
                        spec.id,
                        insp.detail.as_deref().unwrap_or("modified")
                    ),
                    Some(format!(
                        "Re-run with: hyp plugin install {} --force",
                        spec.id
                    )),
                );
            }
        }
    }

    // Resolve target roots for every plugin BEFORE verifying/writing.
    let mut target_roots_by_id: BTreeMap<&'static str, Vec<PathBuf>> = BTreeMap::new();
    for spec in &install_specs {
        let roots = resolve_target_roots(
            spec.id,
            &state_dir,
            resolved_home.as_deref(),
            explicit_home,
            claude_config_dir_arg,
            receipts.installed.get(spec.id),
        );
        if roots.is_empty() {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "MISSING_HOME",
                format!(
                    "Could not determine target directory for '{}' (set HOME or pass --home)",
                    spec.id
                ),
                None,
            );
        }
        if !force {
            if let Err(err) = check_panel_rename_targets(spec, &roots) {
                return emit_error(cmd, as_json, EXIT_ERROR, err.code, err.message, None);
            }
        }
        target_roots_by_id.insert(spec.id, install_target_roots(spec.id, roots));
    }

    // Collect deduplicated required files across all target specs.
    let mut required_entries: Vec<&'static PinnedPluginFile> = Vec::new();
    let mut seen_rel: BTreeSet<&'static str> = BTreeSet::new();
    for spec in &install_specs {
        for f in spec.files {
            if seen_rel.insert(f.rel_path) {
                required_entries.push(f);
            }
        }
    }

    let (source_kind, source_detail, verified_files) = match resolve_and_verify_files(
        &state_dir,
        &required_entries,
        source,
    ) {
        Ok(res) => res,
        Err(err) => {
            let fix = if err.is_offline_download_error() {
                Some(
                        "Check network access or pass --archive <path-to-plugins.tar.gz> / --from-dir <plugins-dir>."
                            .to_string(),
                    )
            } else {
                None
            };
            return emit_error(cmd, as_json, EXIT_ERROR, err.code, err.message, fix);
        }
    };

    // ALL required files passed constant-time SHA-256 verification. Now write atomically!
    for spec in &install_specs {
        let roots = target_roots_by_id
            .get(spec.id)
            .expect("resolved target roots");
        if let Err(err) = write_plugin_to_targets(spec, roots, &verified_files, true) {
            return emit_error(cmd, as_json, EXIT_ERROR, err.code, err.message, None);
        }
        if let Err(err) = complete_harness_rename(spec, roots, receipts.installed.get(spec.id)) {
            return emit_error(cmd, as_json, EXIT_ERROR, err.code, err.message, None);
        }
        record_receipt(&mut receipts, spec, roots);
    }

    if let Err(e) = save_receipts(&state_dir, &receipts) {
        return emit_error(cmd, as_json, EXIT_ERROR, "RECEIPT_ERROR", e, None);
    }

    let sdk_spec = pinned_spec_for(SDK_PLUGIN_ID).expect("sdk spec");
    let sdk_dest = plugins_dir.join("sdk").join("client.mjs");
    let sdk_mjs_sha = sdk_spec
        .files
        .iter()
        .find(|f| f.rel_path == "sdk/client.mjs")
        .map(|f| f.sha256)
        .unwrap_or(sdk_spec.tree_sha256);
    let node_path = detect_node_path(home_arg);
    let mut warnings = Vec::new();

    let telegram_target_res = if requested_targets.iter().any(|s| s.id == "telegram") {
        let cfg_path = resolve_config_path_for_read(config_arg, state_dir_arg, home_arg);
        let secret_name = detect_telegram_secret_name_from_config(&cfg_path);
        let explicit_dir = state_dir_arg.is_some() || config_arg.is_some() || home_arg.is_some();
        let secrets = open_secret_store(&state_dir, explicit_dir);
        let res = resolve_telegram_default_target_from_store(&secrets, &secret_name, None);
        if let Some(ref w) = res.warning {
            warnings.push(w.clone());
        }
        Some(res)
    } else {
        None
    };

    let mut installed_records = Vec::with_capacity(requested_targets.len());
    for spec in &requested_targets {
        let roots = target_roots_by_id
            .get(spec.id)
            .expect("resolved target roots");
        let primary_sha = spec
            .files
            .first()
            .map(|f| f.sha256)
            .unwrap_or(spec.tree_sha256);
        let (default_target, default_target_source) = if spec.id == "telegram" {
            telegram_target_res
                .as_ref()
                .map(|r| (Some(r.target.clone()), Some(r.source)))
                .unwrap_or((None, None))
        } else {
            (None, None)
        };
        installed_records.push(InstalledPluginRecord {
            name: spec.id.to_string(),
            kind: spec.kind.as_str().to_string(),
            script_path: primary_script_display(spec.id, roots),
            onboarding_path: onboarding_tree_display(spec, roots),
            target_paths: roots.iter().map(|p| p.display().to_string()).collect(),
            sha256: primary_sha.to_string(),
            tree_sha256: spec.tree_sha256.to_string(),
            verified: true,
            default_target,
            default_target_source,
        });
    }

    let has_bridge = requested_targets
        .iter()
        .any(|s| s.kind == PluginKind::Bridge);
    if has_bridge && node_path.is_none() {
        warnings.push(
            "Node.js (24+) was not detected in PATH; install Node.js 24+ before enabling external bridge plugins in node.json."
                .to_string(),
        );
    }

    let node_cmd_hint = node_path.as_deref().unwrap_or("node");
    let mut next = Vec::new();
    if let Some(first_bridge) = installed_records
        .iter()
        .find(|r| r.kind == "bridge" && r.name != SDK_PLUGIN_ID)
    {
        if let Some(ref default_target) = first_bridge.default_target {
            next.push(format!(
                "Wire in ~/.config/hyphae/node.json plugins[]: command = \"{node_cmd_hint}\", args = [\"{}\"], targets = [\"{default_target}\"]",
                first_bridge.script_path
            ));
        } else {
            next.push(format!(
                "Wire in ~/.config/hyphae/node.json plugins[]: command = \"{node_cmd_hint}\", args = [\"{}\"]",
                first_bridge.script_path
            ));
        }
        next.push("hyp service restart --json".to_string());
    }
    for spec in &requested_targets {
        if spec.kind == PluginKind::Harness {
            let hint = reload_hint_for_plugin(spec.id).to_string();
            if !next.contains(&hint) {
                next.push(hint);
            }
        }
    }

    let names_joined: Vec<&str> = installed_records.iter().map(|r| r.name.as_str()).collect();
    let summary = format!(
        "Installed and verified {} ({})",
        names_joined.join(", "),
        source_kind.as_str(),
    );

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(summary),
            data: Some(json!({
                "plugins": installed_records,
                "sdkPath": sdk_dest.display().to_string(),
                "sdkSha256": sdk_mjs_sha,
                "pluginsDir": plugins_dir.display().to_string(),
                "receiptsPath": receipts_file_path(&state_dir).display().to_string(),
                "cachePath": cached_plugins_archive_path(&state_dir).display().to_string(),
                "nodePath": node_path,
                "source": source_kind.as_str(),
                "sourceLocation": redact_source_location(&source_detail),
            })),
            warnings,
            next,
            error: None,
        };
        print_json(&envelope);
    } else {
        println!("OK    {summary}");
        if needs_sdk {
            println!(
                "      SDK:   {} ({})",
                sdk_dest.display(),
                &sdk_mjs_sha[..16]
            );
        }
        for rec in &installed_records {
            println!(
                "      {:<13} {} (tree {})",
                rec.name,
                rec.script_path,
                &rec.tree_sha256[..12]
            );
            if let Some(ref target) = rec.default_target {
                println!(
                    "      Target: {} ({})",
                    target,
                    rec.default_target_source.unwrap_or("fallback")
                );
            }
        }
        if has_bridge {
            println!(
                "      Node:  {}",
                node_path.as_deref().unwrap_or("(not detected)")
            );
        }
        print_warnings(&warnings);
        print_next_steps(&next);
    }

    ExitCode::from(EXIT_OK)
}

#[allow(clippy::too_many_arguments)]
fn run_plugin_update(
    plugin_arg: Option<&str>,
    all_flag: bool,
    dry_run: bool,
    force: bool,
    state_dir_arg: Option<&Path>,
    config_arg: Option<&Path>,
    home_arg: Option<&Path>,
    claude_config_dir_arg: Option<&Path>,
    source: PluginSourceOverrides<'_>,
    as_json: bool,
) -> ExitCode {
    let cmd = "plugin update";

    let source_flags = usize::from(source.url.is_some())
        + usize::from(source.archive.is_some())
        + usize::from(source.from_dir.is_some());
    if source_flags > 1 {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "CONFLICTING_FLAGS",
            "Specify at most one of --url, --archive, or --from-dir",
            None,
        );
    }

    if plugin_arg.is_some() && all_flag {
        return emit_error(
            cmd,
            as_json,
            EXIT_USAGE,
            "CONFLICTING_FLAGS",
            "Specify either a plugin name or `--all`, not both",
            None,
        );
    }

    let explicit_single = plugin_arg
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("all"));
    let target_specs: Vec<&'static PinnedPluginSpec> = match explicit_single {
        Some(name) => match resolve_plugin_targets(name) {
            Ok(t) => t,
            Err(msg) => return emit_error(cmd, as_json, EXIT_USAGE, "UNKNOWN_PLUGIN", msg, None),
        },
        None => PINNED_PLUGINS.iter().collect(),
    };

    let state_dir = resolve_state_dir(state_dir_arg, config_arg, home_arg);
    let resolved_home = resolve_home_dir(home_arg);
    let explicit_home = home_arg.is_some();

    let mut receipts = match load_receipts(&state_dir) {
        Ok(r) => r,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "RECEIPT_ERROR", e, None),
    };

    let mut to_update: Vec<PluginInspection> = Vec::new();
    let mut up_to_date: Vec<String> = Vec::new();
    let mut modified_skipped: Vec<String> = Vec::new();
    let mut corrupt_skipped: Vec<String> = Vec::new();
    let mut not_installed: Vec<String> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();
    let mut next: Vec<String> = Vec::new();

    // Older updaters call this command on the new binary after a successful swap.
    if all_flag && !dry_run {
        if let Some(home) = resolved_home.as_deref() {
            crate::setup::migrate_installed_harness_skills(
                home,
                explicit_home,
                claude_config_dir_arg,
                &mut warnings,
            );
        }
    }

    for spec in &target_specs {
        let insp = inspect_plugin(
            spec,
            &state_dir,
            resolved_home.as_deref(),
            explicit_home,
            claude_config_dir_arg,
            &receipts,
        );
        match insp.status {
            PluginStatus::NotInstalled => {
                not_installed.push(spec.id.to_string());
            }
            PluginStatus::UpToDate => {
                up_to_date.push(spec.id.to_string());
            }
            PluginStatus::Outdated => {
                to_update.push(insp);
            }
            PluginStatus::Modified => {
                if force {
                    to_update.push(insp);
                } else {
                    warnings.push(format!(
                        "Refused to overwrite locally modified plugin '{}' ({}); pass --force to overwrite.",
                        spec.id,
                        insp.detail.as_deref().unwrap_or("modified on disk")
                    ));
                    next.push(format!("hyp plugin update {} --force", spec.id));
                    modified_skipped.push(spec.id.to_string());
                }
            }
            PluginStatus::Corrupt => {
                if force {
                    to_update.push(insp);
                } else {
                    warnings.push(format!(
                        "Skipped corrupt plugin '{}' ({}); run `hyp plugin install {} --force` to repair.",
                        spec.id,
                        insp.detail.as_deref().unwrap_or("corrupt on disk"),
                        spec.id
                    ));
                    next.push(format!("hyp plugin install {} --force", spec.id));
                    corrupt_skipped.push(spec.id.to_string());
                }
            }
        }
    }

    // Explicit single-plugin refusal cases (fail closed with exit 1).
    if let Some(single_name) = explicit_single {
        if !not_installed.is_empty() {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "NOT_INSTALLED",
                format!("Plugin '{single_name}' is not installed"),
                Some(format!("hyp plugin install {single_name}")),
            );
        }
        if !modified_skipped.is_empty() {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "PLUGIN_MODIFIED",
                format!(
                    "Plugin '{single_name}' has local modifications on disk; refusing to overwrite without --force"
                ),
                Some(format!("hyp plugin update {single_name} --force")),
            );
        }
        if !corrupt_skipped.is_empty() {
            return emit_error(
                cmd,
                as_json,
                EXIT_ERROR,
                "PLUGIN_CORRUPT",
                format!(
                    "Plugin '{single_name}' installation is corrupt on disk; repair with `hyp plugin install {single_name} --force` or `hyp plugin update {single_name} --force`"
                ),
                Some(format!("hyp plugin install {single_name} --force")),
            );
        }
    }

    // If a bridge plugin is being updated and `sdk` is outdated or missing, include `sdk` too.
    let updating_bridge = to_update.iter().any(|i| is_bridge_consumer(i.spec.id));
    if updating_bridge && !to_update.iter().any(|i| i.spec.id == SDK_PLUGIN_ID) {
        let sdk_spec = pinned_spec_for(SDK_PLUGIN_ID).expect("sdk spec");
        let sdk_insp = inspect_plugin(
            sdk_spec,
            &state_dir,
            resolved_home.as_deref(),
            explicit_home,
            claude_config_dir_arg,
            &receipts,
        );
        if sdk_insp.status != PluginStatus::UpToDate {
            to_update.insert(0, sdk_insp);
        }
    }

    // No plugin downloads when queued changes are absent or this is a dry run.
    if to_update.is_empty() || dry_run {
        let planned: Vec<String> = to_update.iter().map(|i| i.spec.id.to_string()).collect();
        let summary = if dry_run && !planned.is_empty() {
            format!(
                "Dry-run: would update {} plugin(s) ({}), {} up to date, {} modified",
                planned.len(),
                planned.join(", "),
                up_to_date.len(),
                modified_skipped.len()
            )
        } else if up_to_date.is_empty() && modified_skipped.is_empty() && corrupt_skipped.is_empty()
        {
            "No installed official plugins found to update (0 downloads, 0 writes)".to_string()
        } else {
            format!(
                "No plugins updated ({} up_to_date, {} modified, {} corrupt; 0 downloads, 0 writes)",
                up_to_date.len(),
                modified_skipped.len(),
                corrupt_skipped.len()
            )
        };

        if dry_run && !planned.is_empty() {
            next.insert(
                0,
                "Re-run without --dry-run to apply plugin updates.".to_string(),
            );
        }

        if as_json {
            let envelope = JsonEnvelope {
                ok: true,
                command: cmd.to_string(),
                summary: Some(summary),
                data: Some(json!({
                    "dryRun": dry_run,
                    "downloaded": false,
                    "updated": Vec::<String>::new(),
                    "planned": planned,
                    "upToDate": up_to_date,
                    "modified": modified_skipped,
                    "corrupt": corrupt_skipped,
                    "reloadHints": Vec::<String>::new(),
                })),
                warnings,
                next,
                error: None,
            };
            print_json(&envelope);
        } else {
            println!("{}  {summary}", if dry_run { "PLAN" } else { "OK  " });
            print_warnings(&warnings);
            print_next_steps(&next);
        }
        return ExitCode::from(EXIT_OK);
    }

    // Fetch/verify the release archive AT MOST ONCE for ALL plugins needing update.
    let mut required_entries: Vec<&'static PinnedPluginFile> = Vec::new();
    let mut seen_rel: BTreeSet<&'static str> = BTreeSet::new();
    for insp in &to_update {
        for f in insp.spec.files {
            if seen_rel.insert(f.rel_path) {
                required_entries.push(f);
            }
        }
    }

    let (source_kind, source_detail, verified_files) =
        match resolve_and_verify_files(&state_dir, &required_entries, source) {
            Ok(res) => res,
            Err(err) => {
                let fix = if err.is_offline_download_error() {
                    Some(
                        "Retry when online or pass --archive <path> / --from-dir <dir>."
                            .to_string(),
                    )
                } else {
                    None
                };
                return emit_error(cmd, as_json, EXIT_ERROR, err.code, err.message, fix);
            }
        };

    // Atomically write ONLY the changed plugins and update their receipts.
    if !force {
        for insp in &to_update {
            if let Err(err) = check_panel_rename_targets(insp.spec, &insp.target_paths) {
                return emit_error(cmd, as_json, EXIT_ERROR, err.code, err.message, None);
            }
        }
    }

    let mut updated_names: Vec<String> = Vec::new();
    let mut reload_hints: Vec<String> = Vec::new();
    for insp in &to_update {
        let roots = install_target_roots(insp.spec.id, insp.target_paths.clone());
        if let Err(err) = write_plugin_to_targets(insp.spec, &roots, &verified_files, force) {
            return emit_error(cmd, as_json, EXIT_ERROR, err.code, err.message, None);
        }
        if let Err(err) =
            complete_harness_rename(insp.spec, &roots, receipts.installed.get(insp.spec.id))
        {
            return emit_error(cmd, as_json, EXIT_ERROR, err.code, err.message, None);
        }
        record_receipt(&mut receipts, insp.spec, &roots);
        updated_names.push(insp.spec.id.to_string());
        let hint = reload_hint_for_plugin(insp.spec.id).to_string();
        if !reload_hints.contains(&hint) {
            reload_hints.push(hint);
        }
    }

    if let Err(e) = save_receipts(&state_dir, &receipts) {
        return emit_error(cmd, as_json, EXIT_ERROR, "RECEIPT_ERROR", e, None);
    }

    for hint in &reload_hints {
        if !next.contains(hint) {
            next.push(hint.clone());
        }
    }

    let summary = format!(
        "Updated {} plugin(s) ({}) via {} ({} already up to date, {} modified skipped)",
        updated_names.len(),
        updated_names.join(", "),
        source_kind.as_str(),
        up_to_date.len(),
        modified_skipped.len()
    );

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(summary),
            data: Some(json!({
                "dryRun": false,
                "downloaded": source_kind == InstallSourceKind::Release,
                "source": source_kind.as_str(),
                "sourceLocation": redact_source_location(&source_detail),
                "updated": updated_names,
                "upToDate": up_to_date,
                "modified": modified_skipped,
                "corrupt": corrupt_skipped,
                "reloadHints": reload_hints,
            })),
            warnings,
            next,
            error: None,
        };
        print_json(&envelope);
    } else {
        println!("OK    {summary}");
        for name in &updated_names {
            if let Some(spec) = pinned_spec_for(name) {
                println!(
                    "      updated  {:<13} tree {}",
                    name,
                    &spec.tree_sha256[..12]
                );
            }
        }
        print_warnings(&warnings);
        print_next_steps(&next);
    }

    ExitCode::from(EXIT_OK)
}

fn remove_plugin_on_disk(plugin_id: &str, target_roots: &[PathBuf]) -> Result<bool, String> {
    let mut removed_any = false;
    for root in target_roots {
        if plugin_id == HERDR_MOD_ID {
            for sub in ["hyphae-pane", "hyphae-panel"] {
                let mod_dir = root.join(sub);
                if let Ok(meta) = fs::symlink_metadata(&mod_dir) {
                    if meta.file_type().is_symlink() {
                        fs::remove_file(&mod_dir)
                            .map_err(|e| format!("Failed to remove {}: {e}", mod_dir.display()))?;
                    } else {
                        fs::remove_dir_all(&mod_dir)
                            .map_err(|e| format!("Failed to remove {}: {e}", mod_dir.display()))?;
                    }
                    removed_any = true;
                }
            }
        } else if let Ok(meta) = fs::symlink_metadata(root) {
            if meta.file_type().is_symlink() {
                fs::remove_file(root)
                    .map_err(|e| format!("Failed to remove {}: {e}", root.display()))?;
            } else {
                fs::remove_dir_all(root)
                    .map_err(|e| format!("Failed to remove {}: {e}", root.display()))?;
            }
            removed_any = true;
        }
    }
    Ok(removed_any)
}

fn arg_points_into_plugin_dir(
    arg: &str,
    plugin_dir: &Path,
    canon_plugin_dir: Option<&Path>,
    home: Option<&Path>,
) -> bool {
    let trimmed = arg.trim();
    if trimmed.is_empty() {
        return false;
    }
    let expanded = if let Some(rest) = trimmed.strip_prefix("~/") {
        match home {
            Some(h) => h.join(rest),
            None => PathBuf::from(trimmed),
        }
    } else {
        PathBuf::from(trimmed)
    };
    if expanded.starts_with(plugin_dir) {
        return true;
    }
    if let Some(canon_dir) = canon_plugin_dir {
        if expanded.starts_with(canon_dir) {
            return true;
        }
        if let Ok(canon_arg) = fs::canonicalize(&expanded) {
            if canon_arg.starts_with(canon_dir) {
                return true;
            }
        }
    }
    false
}

fn plugin_config_entry_matches(
    entry: &Value,
    target_ids: &[&str],
    plugins_dir: &Path,
    canon_plugins_dir: Option<&Path>,
    home: Option<&Path>,
) -> Option<String> {
    let obj = entry.as_object()?;
    let entry_id = obj
        .get("id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());

    for &target_id in target_ids {
        if entry_id.is_some_and(|id| id.eq_ignore_ascii_case(target_id)) {
            return Some(entry_id.unwrap_or(target_id).to_string());
        }
        let target_dir = plugins_dir.join(target_id);
        let canon_target_dir = canon_plugins_dir.map(|p| p.join(target_id));
        if let Some(args) = obj.get("args").and_then(Value::as_array) {
            for arg in args {
                if let Some(s) = arg.as_str() {
                    if arg_points_into_plugin_dir(s, &target_dir, canon_target_dir.as_deref(), home)
                    {
                        return Some(entry_id.unwrap_or(target_id).to_string());
                    }
                }
            }
        }
    }
    None
}

fn remove_plugins_from_node_json(
    config_path: &Path,
    plugins_dir: &Path,
    home: Option<&Path>,
    target_ids: &[&str],
) -> Result<Vec<String>, String> {
    if !config_path.exists() {
        return Ok(Vec::new());
    }
    let mut cfg_map = NodeFile::read_document_or_empty(config_path)?;
    let Some(plugins_val) = cfg_map.get("plugins") else {
        return Ok(Vec::new());
    };
    let Some(arr) = plugins_val.as_array() else {
        return Ok(Vec::new());
    };

    let canon_plugins_dir = fs::canonicalize(plugins_dir).ok();
    let mut kept = Vec::with_capacity(arr.len());
    let mut removed_ids = Vec::new();
    for item in arr {
        if let Some(matched_id) = plugin_config_entry_matches(
            item,
            target_ids,
            plugins_dir,
            canon_plugins_dir.as_deref(),
            home,
        ) {
            removed_ids.push(matched_id);
        } else {
            kept.push(item.clone());
        }
    }

    if !removed_ids.is_empty() {
        cfg_map.insert("plugins".to_string(), Value::Array(kept));
        NodeFile::write_document(config_path, cfg_map)?;
    }
    Ok(removed_ids)
}

#[allow(clippy::too_many_arguments)]
fn run_plugin_remove(
    plugin_arg: &str,
    keep_config: bool,
    state_dir_arg: Option<&Path>,
    config_arg: Option<&Path>,
    home_arg: Option<&Path>,
    claude_config_dir_arg: Option<&Path>,
    as_json: bool,
) -> ExitCode {
    let cmd = "plugin remove";
    let is_all = plugin_arg.trim().eq_ignore_ascii_case("all");
    let targets = match resolve_plugin_targets(plugin_arg) {
        Ok(t) => t,
        Err(msg) => return emit_error(cmd, as_json, EXIT_USAGE, "UNKNOWN_PLUGIN", msg, None),
    };

    let state_dir = resolve_state_dir(state_dir_arg, config_arg, home_arg);
    let config_path = resolve_config_path_for_read(config_arg, state_dir_arg, home_arg);
    let plugins_dir = state_dir.join("plugins");
    let resolved_home = resolve_home_dir(home_arg);
    let explicit_home = home_arg.is_some();

    let mut receipts = load_receipts(&state_dir).unwrap_or_default();
    let mut removed: Vec<String> = Vec::new();
    let mut sdk_removed = false;

    for spec in &targets {
        if is_all && spec.id == SDK_PLUGIN_ID {
            continue;
        }
        let roots = resolve_target_roots(
            spec.id,
            &state_dir,
            resolved_home.as_deref(),
            explicit_home,
            claude_config_dir_arg,
            receipts.installed.get(spec.id),
        );
        match remove_plugin_on_disk(spec.id, &roots) {
            Ok(true) => {
                if spec.id == SDK_PLUGIN_ID {
                    sdk_removed = true;
                } else {
                    removed.push(spec.id.to_string());
                }
            }
            Ok(false) => {}
            Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "IO_ERROR", e, None),
        }
        receipts.installed.remove(spec.id);
    }

    // If `all` or no bridge consumers remain installed, clean up `sdk/` as well.
    let any_bridge_remaining = BRIDGE_CONSUMER_IDS
        .iter()
        .any(|id| fs::symlink_metadata(plugins_dir.join(id)).is_ok());
    if is_all || !any_bridge_remaining {
        let sdk_dir = plugins_dir.join(SDK_PLUGIN_ID);
        if fs::symlink_metadata(&sdk_dir).is_ok() {
            if let Err(e) = fs::remove_dir_all(&sdk_dir) {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "IO_ERROR",
                    format!("Failed to remove {}: {e}", sdk_dir.display()),
                    None,
                );
            }
            sdk_removed = true;
        }
        receipts.installed.remove(SDK_PLUGIN_ID);
    }

    if let Err(e) = save_receipts(&state_dir, &receipts) {
        return emit_error(cmd, as_json, EXIT_ERROR, "RECEIPT_ERROR", e, None);
    }

    if is_all {
        if plugins_dir.exists() {
            let _ = fs::remove_dir_all(&plugins_dir);
        }
    } else if plugins_dir.exists() {
        // Remove empty plugins/ directory when nothing remains inside it.
        let _ = fs::remove_dir(&plugins_dir);
    }

    // Remove matching `plugins[]` entries from `node.json` unless `--keep-config` is passed.
    let target_ids: Vec<&str> = targets.iter().map(|s| s.id).collect();
    let mut warnings = Vec::new();
    let removed_config_entries = if keep_config {
        Vec::new()
    } else {
        match remove_plugins_from_node_json(
            &config_path,
            &plugins_dir,
            resolved_home.as_deref(),
            &target_ids,
        ) {
            Ok(entries) => entries,
            Err(e) => {
                warnings.push(format!(
                    "Could not clean matching plugins[] entries from {}: {e}",
                    config_path.display()
                ));
                Vec::new()
            }
        }
    };

    let mut next = Vec::new();
    if !removed_config_entries.is_empty() {
        next.push("hyp service restart --json".to_string());
    }

    let summary = if removed.is_empty() && !sdk_removed && removed_config_entries.is_empty() {
        format!(
            "Nothing to remove for '{plugin_arg}' under {}",
            plugins_dir.display()
        )
    } else if removed.is_empty() && !sdk_removed {
        format!(
            "Removed node.json plugins[] entry(ies): {}",
            removed_config_entries.join(", ")
        )
    } else {
        format!(
            "Removed {}",
            if removed.is_empty() {
                "sdk".to_string()
            } else {
                removed.join(", ")
            }
        )
    };

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(summary),
            data: Some(json!({
                "pluginsDir": plugins_dir.display().to_string(),
                "configPath": config_path.display().to_string(),
                "removed": removed,
                "sdkRemoved": sdk_removed,
                "keepConfig": keep_config,
                "removedConfigEntries": removed_config_entries,
            })),
            warnings,
            next,
            error: None,
        };
        print_json(&envelope);
    } else {
        println!("OK    {summary}");
        if !removed_config_entries.is_empty() {
            println!(
                "      Config: removed plugins[] entry(ies) ({}) from {}",
                removed_config_entries.join(", "),
                config_path.display()
            );
        }
        print_warnings(&warnings);
        print_next_steps(&next);
    }

    ExitCode::from(EXIT_OK)
}

fn run_plugin_verify(
    plugin_arg: Option<&str>,
    state_dir_arg: Option<&Path>,
    config_arg: Option<&Path>,
    home_arg: Option<&Path>,
    claude_config_dir_arg: Option<&Path>,
    as_json: bool,
) -> ExitCode {
    let cmd = "plugin verify";
    let explicit_single = plugin_arg
        .map(|s| s.trim())
        .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("all"));
    let specs_to_check: Vec<&'static PinnedPluginSpec> = match explicit_single {
        Some(name) => match resolve_plugin_targets(name) {
            Ok(t) => t,
            Err(msg) => return emit_error(cmd, as_json, EXIT_USAGE, "UNKNOWN_PLUGIN", msg, None),
        },
        None => PINNED_PLUGINS.iter().collect(),
    };

    let state_dir = resolve_state_dir(state_dir_arg, config_arg, home_arg);
    let plugins_dir = state_dir.join("plugins");
    let resolved_home = resolve_home_dir(home_arg);
    let explicit_home = home_arg.is_some();

    let receipts = match load_receipts(&state_dir) {
        Ok(r) => r,
        Err(e) => return emit_error(cmd, as_json, EXIT_ERROR, "RECEIPT_ERROR", e, None),
    };

    let mut records: Vec<VerifiedFileRecord> = Vec::new();
    let mut plugin_reports: Vec<DoctorPluginSummary> = Vec::new();
    let mut checks: Vec<CliCheck> = Vec::new();
    let mut any_bridge_installed = false;
    let mut sdk_checked = false;

    for spec in &specs_to_check {
        let insp = inspect_plugin(
            spec,
            &state_dir,
            resolved_home.as_deref(),
            explicit_home,
            claude_config_dir_arg,
            &receipts,
        );
        if insp.status == PluginStatus::NotInstalled {
            if explicit_single.is_some() {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "NOT_INSTALLED",
                    format!("Plugin '{}' is not installed", spec.id),
                    Some(format!("hyp plugin install {}", spec.id)),
                );
            }
            continue;
        }
        if is_bridge_consumer(spec.id) {
            any_bridge_installed = true;
        }
        if spec.id == SDK_PLUGIN_ID {
            sdk_checked = true;
        }

        for f in &insp.files {
            if f.verified {
                checks.push(CliCheck::ok(
                    &f.rel_path,
                    format!("verified ({})", &f.pinned_sha256[..16]),
                ));
            } else {
                checks.push(CliCheck::fail(
                    &f.rel_path,
                    f.reason
                        .clone()
                        .unwrap_or_else(|| "SHA-256 verification failed".to_string()),
                    Some(format!(
                        "Reinstall with: hyp plugin install {} --force",
                        spec.id
                    )),
                ));
            }
        }
        if insp.status != PluginStatus::UpToDate && insp.files.iter().all(|f| f.verified) {
            // E.g. corrupt wrapper file or symlinked mod directory.
            checks.push(CliCheck::fail(
                format!("plugin:{}", spec.id),
                insp.detail
                    .clone()
                    .unwrap_or_else(|| "plugin integrity check failed".to_string()),
                Some(format!(
                    "Reinstall with: hyp plugin install {} --force",
                    spec.id
                )),
            ));
        }

        records.extend(insp.files);
        plugin_reports.push(DoctorPluginSummary {
            name: spec.id.to_string(),
            kind: spec.kind.as_str().to_string(),
            status: insp.status,
            pinned_tree_sha256: spec.tree_sha256.to_string(),
            installed_tree_sha256: insp.receipt_tree_sha256,
            disk_tree_sha256: insp.disk_tree_sha256,
            target_paths: insp
                .target_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect(),
            detail: insp.detail,
        });
    }

    // If a bridge plugin is installed (either explicitly verified or via all), ALWAYS verify `sdk`!
    if any_bridge_installed && !sdk_checked {
        let sdk_spec = pinned_spec_for(SDK_PLUGIN_ID).expect("sdk spec");
        let sdk_insp = inspect_plugin(
            sdk_spec,
            &state_dir,
            resolved_home.as_deref(),
            explicit_home,
            claude_config_dir_arg,
            &receipts,
        );
        if sdk_insp.status == PluginStatus::NotInstalled {
            for f in sdk_spec.files {
                let p = plugins_dir.join(f.rel_path);
                let reason = Some("required shared SDK file is missing".to_string());
                checks.push(CliCheck::fail(
                    f.rel_path,
                    "required shared SDK file is missing",
                    Some("Reinstall affected plugin(s) with: hyp plugin install sdk".to_string()),
                ));
                records.insert(
                    0,
                    VerifiedFileRecord {
                        plugin: SDK_PLUGIN_ID.to_string(),
                        rel_path: f.rel_path.to_string(),
                        path: p.display().to_string(),
                        pinned_sha256: f.sha256.to_string(),
                        actual_sha256: None,
                        verified: false,
                        reason,
                    },
                );
            }
            plugin_reports.push(DoctorPluginSummary {
                name: SDK_PLUGIN_ID.to_string(),
                kind: PluginKind::Bridge.as_str().to_string(),
                status: PluginStatus::Corrupt,
                pinned_tree_sha256: sdk_spec.tree_sha256.to_string(),
                installed_tree_sha256: None,
                disk_tree_sha256: None,
                target_paths: vec![plugins_dir.join(SDK_PLUGIN_ID).display().to_string()],
                detail: Some("required shared SDK is missing".to_string()),
            });
        } else {
            for f in &sdk_insp.files {
                if f.verified {
                    checks.push(CliCheck::ok(
                        &f.rel_path,
                        format!("verified ({})", &f.pinned_sha256[..16]),
                    ));
                } else {
                    checks.push(CliCheck::fail(
                        &f.rel_path,
                        f.reason
                            .clone()
                            .unwrap_or_else(|| "SHA-256 verification failed".to_string()),
                        Some("Reinstall with: hyp plugin install sdk --force".to_string()),
                    ));
                }
            }
            records.extend(sdk_insp.files);
            plugin_reports.push(DoctorPluginSummary {
                name: SDK_PLUGIN_ID.to_string(),
                kind: PluginKind::Bridge.as_str().to_string(),
                status: sdk_insp.status,
                pinned_tree_sha256: sdk_spec.tree_sha256.to_string(),
                installed_tree_sha256: sdk_insp.receipt_tree_sha256,
                disk_tree_sha256: sdk_insp.disk_tree_sha256,
                target_paths: sdk_insp
                    .target_paths
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect(),
                detail: sdk_insp.detail,
            });
        }
    }

    let failed_files = records.iter().filter(|r| !r.verified).count();
    let failed_checks = checks
        .iter()
        .filter(|c| c.status == CheckStatus::Fail)
        .count();
    let all_ok = failed_files == 0 && failed_checks == 0;

    let summary = if plugin_reports.is_empty() {
        format!(
            "No official plugins installed under {}",
            plugins_dir.display()
        )
    } else if all_ok {
        format!(
            "All {} installed plugin file(s) across {} plugin(s) verified against compile-time SHA-256 digests",
            records.len(),
            plugin_reports.len()
        )
    } else {
        format!(
            "{} of {} installed plugin file(s) failed SHA-256 / integrity verification",
            failed_files.max(failed_checks),
            records.len()
        )
    };

    let mut next = Vec::new();
    if !all_ok {
        if plugin_reports
            .iter()
            .any(|p| p.status == PluginStatus::Outdated)
        {
            next.push("hyp plugin update --all --json".to_string());
        } else {
            next.push("hyp plugin install all --force --json".to_string());
        }
    }

    if as_json {
        let envelope = JsonEnvelope {
            ok: all_ok,
            command: cmd.to_string(),
            summary: Some(summary.clone()),
            data: Some(json!({
                "pluginsDir": plugins_dir.display().to_string(),
                "checked": records.len(),
                "failed": failed_files.max(failed_checks),
                "plugins": plugin_reports,
                "files": records,
            })),
            warnings: Vec::new(),
            next,
            error: if all_ok {
                None
            } else {
                Some(CliError {
                    exit: EXIT_ERROR,
                    code: "PLUGIN_VERIFY_FAILED".to_string(),
                    message: summary,
                    fix: Some(
                        "Update outdated plugins via `hyp plugin update --all` or reinstall tampered ones via `hyp plugin install <name> --force`."
                            .to_string(),
                    ),
                })
            },
        };
        print_json(&envelope);
    } else if plugin_reports.is_empty() {
        println!("OK    {summary}");
    } else {
        print_checks(&checks);
        print_next_steps(&next);
    }

    if all_ok {
        ExitCode::from(EXIT_OK)
    } else {
        ExitCode::from(EXIT_ERROR)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyp_crypto::transfer::{TarInputEntry, TarPackOptions, pack_tar_gz, pack_tar_gz_bytes};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::TempDir;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn repo_plugins_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("plugins")
    }

    fn build_official_plugins_tarball(prefix: &str, tamper_rel: Option<&str>) -> Vec<u8> {
        let root = repo_plugins_dir();
        let mut owned: Vec<(String, Vec<u8>)> = Vec::with_capacity(PINNED_PLUGIN_FILES.len());
        for entry in PINNED_PLUGIN_FILES {
            let mut bytes = fs::read(root.join(entry.rel_path)).expect("read repo plugin file");
            if tamper_rel == Some(entry.rel_path) {
                bytes[0] ^= 0x01; // 1-bit flip!
            }
            let archive_path = if prefix.is_empty() {
                entry.rel_path.to_string()
            } else {
                format!("{prefix}{}", entry.rel_path)
            };
            owned.push((archive_path, bytes));
        }
        let slices: Vec<(&str, &[u8])> = owned
            .iter()
            .map(|(p, b)| (p.as_str(), b.as_slice()))
            .collect();
        let mut out = Vec::new();
        pack_tar_gz_bytes(&slices, &mut out, TarPackOptions::default())
            .expect("pack plugin tarball");
        out
    }

    #[test]
    fn differential_build_rs_sha256_and_tree_digests_match_sha2_crate_for_all_plugins() {
        assert_eq!(PINNED_PLUGINS.len(), 15);
        assert_eq!(PINNED_PLUGIN_FILES.len(), 45);
        let root = repo_plugins_dir();

        for entry in PINNED_PLUGIN_FILES {
            let raw = fs::read(root.join(entry.rel_path))
                .unwrap_or_else(|e| panic!("failed reading {}: {e}", entry.rel_path));
            let expected = sha256_file_hex(&raw, entry.is_binary);
            assert_eq!(
                entry.sha256, expected,
                "build.rs SHA-256 diverged from sha2::Sha256 for {}",
                entry.rel_path
            );

            if !entry.is_binary {
                let lf = normalize_crlf(&raw);
                let mut crlf = Vec::with_capacity(lf.len() + 64);
                for &b in &lf {
                    if b == b'\n' {
                        crlf.push(b'\r');
                    }
                    crlf.push(b);
                }
                assert_eq!(
                    sha256_file_hex(&crlf, false),
                    entry.sha256,
                    "CRLF normalization must preserve exact digest for {}",
                    entry.rel_path
                );
            } else {
                assert!(
                    entry.rel_path.ends_with(".png"),
                    "unexpected binary asset {}",
                    entry.rel_path
                );
            }
        }

        // Verify per-plugin tree_sha256 deterministically.
        for spec in PINNED_PLUGINS {
            let pairs: Vec<(&str, &str)> =
                spec.files.iter().map(|f| (f.rel_path, f.sha256)).collect();
            let recomputed = compute_tree_sha256(&pairs);
            assert_eq!(
                spec.tree_sha256, recomputed,
                "tree_sha256 mismatch for {}",
                spec.id
            );
        }
    }

    #[test]
    fn url_validation_enforces_https_and_loopback_only() {
        assert!(validate_plugin_download_url(&default_release_plugins_url()).is_ok());
        assert!(
            validate_plugin_download_url(
                "https://github.com/hyphae-to/hyp/releases/download/v0.6.2/hyp-v0.6.2-plugins.tar.gz"
            )
            .is_ok()
        );
        assert!(validate_plugin_download_url("http://127.0.0.1:8080/plugins.tar.gz").is_ok());
        assert!(validate_plugin_download_url("http://[::1]:8080/plugins.tar.gz").is_ok());

        for bad in [
            "",
            "   ",
            "http://evil.com/plugins.tar.gz",
            "http://github.com/hyphae-to/hyp/releases/download/v0.6.2/hyp-v0.6.2-plugins.tar.gz",
            "http://127.0.0.1.evil.com/plugins.tar.gz",
            "http://localhost:8080/plugins.tar.gz",
            "file:///etc/passwd",
            "ftp://github.com/plugins.tar.gz",
            "https://user:pass@github.com/plugins.tar.gz",
            "https://github.com/plugins.tar.gz\n--inject",
        ] {
            assert!(
                validate_plugin_download_url(bad).is_err(),
                "expected URL '{bad}' to be rejected"
            );
        }

        let https_uri: Uri = "https://github.com/hyphae-to/hyp/releases/latest"
            .parse()
            .unwrap();
        let err = resolve_redirect_url(&https_uri, "http://127.0.0.1:8080/plugins.tar.gz")
            .expect_err("HTTPS->HTTP downgrade redirect must fail closed");
        assert_eq!(err.code, "UNSAFE_REDIRECT");
    }

    #[test]
    fn loopback_http_install_cache_update_three_way_and_tamper_lifecycle() {
        let valid_tarball = build_official_plugins_tarball("", None);
        let prefixed_tarball = build_official_plugins_tarball("plugins/", None);
        let tampered_tarball = build_official_plugins_tarball("", Some("telegram/index.mjs"));
        let tampered_png_tarball =
            build_official_plugins_tarball("", Some("claude-code/.claude-plugin/icon.png"));

        let hits = Arc::new(AtomicUsize::new(0));
        let hits_srv = Arc::clone(&hits);

        let (addr, stop_tx, server_thread) = {
            let (addr_tx, addr_rx) = std::sync::mpsc::channel();
            let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
            let valid_body = valid_tarball.clone();
            let prefixed_body = prefixed_tarball.clone();
            let tampered_body = tampered_tarball.clone();
            let tampered_png_body = tampered_png_tarball.clone();

            let handle = std::thread::spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("server tokio runtime");
                rt.block_on(async move {
                    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
                    let addr = listener.local_addr().expect("local addr");
                    addr_tx.send(addr).expect("send addr");
                    let mut stop_rx = stop_rx;
                    loop {
                        let accept_res = tokio::select! {
                            _ = &mut stop_rx => break,
                            res = listener.accept() => res,
                        };
                        let Ok((mut sock, _)) = accept_res else {
                            break;
                        };
                        hits_srv.fetch_add(1, Ordering::SeqCst);
                        let mut buf = [0u8; 2048];
                        let n = sock.read(&mut buf).await.unwrap_or(0);
                        let req = String::from_utf8_lossy(&buf[..n]);
                        let first_line = req.lines().next().unwrap_or("");

                        if first_line.starts_with("GET /redirect.tar.gz ") {
                            let resp = format!(
                                "HTTP/1.1 302 Found\r\nLocation: http://{addr}/valid.tar.gz\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                            );
                            let _ = sock.write_all(resp.as_bytes()).await;
                        } else if first_line.starts_with("GET /valid.tar.gz ") {
                            let hdr = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                valid_body.len()
                            );
                            let _ = sock.write_all(hdr.as_bytes()).await;
                            let _ = sock.write_all(&valid_body).await;
                        } else if first_line.starts_with("GET /prefixed.tar.gz ") {
                            let hdr = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                prefixed_body.len()
                            );
                            let _ = sock.write_all(hdr.as_bytes()).await;
                            let _ = sock.write_all(&prefixed_body).await;
                        } else if first_line.starts_with("GET /tampered.tar.gz ") {
                            let hdr = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                tampered_body.len()
                            );
                            let _ = sock.write_all(hdr.as_bytes()).await;
                            let _ = sock.write_all(&tampered_body).await;
                        } else if first_line.starts_with("GET /tampered-png.tar.gz ") {
                            let hdr = format!(
                                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                tampered_png_body.len()
                            );
                            let _ = sock.write_all(hdr.as_bytes()).await;
                            let _ = sock.write_all(&tampered_png_body).await;
                        } else {
                            let _ = sock
                                .write_all(
                                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                                )
                                .await;
                        }
                        let _ = sock.shutdown().await;
                    }
                });
            });
            let addr = addr_rx.recv().expect("recv server addr");
            (addr, stop_tx, handle)
        };

        // 1. Happy path over loopback HTTP with 302 redirect -> installs sdk + telegram + receipt + cache!
        let tmp_ok = TempDir::new().expect("temp dir");
        let state_ok = tmp_ok.path().join("state");
        let redirect_url = format!("http://{addr}/redirect.tar.gz");
        let code = run_plugin(PluginCommand::Install {
            plugin: "telegram".to_string(),
            state_dir: Some(state_ok.clone()),
            config: None,
            home: Some(tmp_ok.path().to_path_buf()),
            claude_config_dir: None,
            url: Some(redirect_url),
            archive: None,
            from_dir: None,
            force: false,
            json: true,
        });
        assert_eq!(code, ExitCode::from(EXIT_OK));
        let tg_path = state_ok.join("plugins/telegram/index.mjs");
        let sdk_path = state_ok.join("plugins/sdk/client.mjs");
        assert!(tg_path.is_file());
        assert!(sdk_path.is_file());
        assert!(receipts_file_path(&state_ok).is_file());
        assert!(
            cached_plugins_archive_path(&state_ok).is_file(),
            "verified release tarball must be cached locally"
        );

        // 2. Subsequent `hyp plugin update --all` when `up_to_date` makes ZERO HTTP requests!
        let hits_before_noop = hits.load(Ordering::SeqCst);
        let noop_update = run_plugin(PluginCommand::Update {
            plugin: None,
            all: true,
            dry_run: false,
            force: false,
            state_dir: Some(state_ok.clone()),
            config: None,
            home: Some(tmp_ok.path().to_path_buf()),
            claude_config_dir: None,
            url: Some(format!("http://{addr}/valid.tar.gz")),
            archive: None,
            from_dir: None,
            json: true,
        });
        assert_eq!(noop_update, ExitCode::from(EXIT_OK));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            hits_before_noop,
            "up_to_date `hyp plugin update --all` MUST make 0 network requests"
        );

        // 3. Simulate an OUTDATED install (`disk == receipt && disk != pinned`):
        //    update downloads ONCE and upgrades telegram cleanly!
        let old_tg = b"// older v0.6.1 telegram script\n";
        fs::write(&tg_path, old_tg).unwrap();
        let old_sha = sha256_file_hex(old_tg, false);
        let old_tree = compute_tree_sha256(&[("telegram/index.mjs", &old_sha)]);
        let mut rec = load_receipts(&state_ok).unwrap();
        rec.installed.get_mut("telegram").unwrap().tree_sha256 = old_tree;
        save_receipts(&state_ok, &rec).unwrap();

        let hits_before_outdated = hits.load(Ordering::SeqCst);
        let upd_ok = run_plugin(PluginCommand::Update {
            plugin: None,
            all: true,
            dry_run: false,
            force: false,
            state_dir: Some(state_ok.clone()),
            config: None,
            home: Some(tmp_ok.path().to_path_buf()),
            claude_config_dir: None,
            url: Some(format!("http://{addr}/valid.tar.gz")),
            archive: None,
            from_dir: None,
            json: true,
        });
        assert_eq!(upd_ok, ExitCode::from(EXIT_OK));
        assert_eq!(
            hits.load(Ordering::SeqCst),
            hits_before_outdated + 1,
            "outdated update must fetch release archive exactly once"
        );
        let verify_ok = run_plugin(PluginCommand::Verify {
            plugin: None,
            state_dir: Some(state_ok.clone()),
            config: None,
            home: Some(tmp_ok.path().to_path_buf()),
            claude_config_dir: None,
            json: true,
        });
        assert_eq!(verify_ok, ExitCode::from(EXIT_OK));

        // 4. Local user edit -> MODIFIED (`disk != receipt && disk != pinned`):
        //    - `verify` MUST fail closed (exit 1)
        //    - `update telegram` MUST refuse without --force (exit 1, 0 network calls, preserves edit)
        //    - `update --all` MUST skip without overwriting (0 network calls, preserves edit)
        //    - `update telegram --force` overwrites and restores verified state!
        let custom_edit = b"// user custom telegram tweak\n";
        fs::write(&tg_path, custom_edit).unwrap();
        assert_eq!(
            run_plugin(PluginCommand::Verify {
                plugin: Some("telegram".to_string()),
                state_dir: Some(state_ok.clone()),
                config: None,
                home: Some(tmp_ok.path().to_path_buf()),
                claude_config_dir: None,
                json: true,
            }),
            ExitCode::from(EXIT_ERROR)
        );
        let hits_before_mod = hits.load(Ordering::SeqCst);
        assert_eq!(
            run_plugin(PluginCommand::Update {
                plugin: Some("telegram".to_string()),
                all: false,
                dry_run: false,
                force: false,
                state_dir: Some(state_ok.clone()),
                config: None,
                home: Some(tmp_ok.path().to_path_buf()),
                claude_config_dir: None,
                url: Some(format!("http://{addr}/valid.tar.gz")),
                archive: None,
                from_dir: None,
                json: true,
            }),
            ExitCode::from(EXIT_ERROR)
        );
        assert_eq!(fs::read(&tg_path).unwrap(), custom_edit);
        assert_eq!(hits.load(Ordering::SeqCst), hits_before_mod);

        assert_eq!(
            run_plugin(PluginCommand::Update {
                plugin: None,
                all: true,
                dry_run: false,
                force: false,
                state_dir: Some(state_ok.clone()),
                config: None,
                home: Some(tmp_ok.path().to_path_buf()),
                claude_config_dir: None,
                url: Some(format!("http://{addr}/valid.tar.gz")),
                archive: None,
                from_dir: None,
                json: true,
            }),
            ExitCode::from(EXIT_OK)
        );
        assert_eq!(
            fs::read(&tg_path).unwrap(),
            custom_edit,
            "`update --all` without --force must NOT overwrite modified plugin"
        );
        assert_eq!(hits.load(Ordering::SeqCst), hits_before_mod);

        assert_eq!(
            run_plugin(PluginCommand::Update {
                plugin: Some("telegram".to_string()),
                all: false,
                dry_run: false,
                force: true,
                state_dir: Some(state_ok.clone()),
                config: None,
                home: Some(tmp_ok.path().to_path_buf()),
                claude_config_dir: None,
                url: Some(format!("http://{addr}/valid.tar.gz")),
                archive: None,
                from_dir: None,
                json: true,
            }),
            ExitCode::from(EXIT_OK)
        );
        assert_eq!(
            run_plugin(PluginCommand::Verify {
                plugin: None,
                state_dir: Some(state_ok.clone()),
                config: None,
                home: Some(tmp_ok.path().to_path_buf()),
                claude_config_dir: None,
                json: true,
            }),
            ExitCode::from(EXIT_OK)
        );

        // 5. Remove telegram -> cleans up telegram/ AND sdk/ (no bridges remain)!
        let remove_code = run_plugin(PluginCommand::Remove {
            plugin: "telegram".to_string(),
            keep_config: false,
            state_dir: Some(state_ok.clone()),
            config: None,
            home: Some(tmp_ok.path().to_path_buf()),
            claude_config_dir: None,
            json: true,
        });
        assert_eq!(remove_code, ExitCode::from(EXIT_OK));
        assert!(!tg_path.exists());
        assert!(!sdk_path.exists());

        // 6. Prefixed `plugins/<rel>` tarball layout works cleanly too!
        let prefixed_url = format!("http://{addr}/prefixed.tar.gz");
        let code_prefixed = run_plugin(PluginCommand::Install {
            plugin: "slack".to_string(),
            state_dir: Some(state_ok.clone()),
            config: None,
            home: Some(tmp_ok.path().to_path_buf()),
            claude_config_dir: None,
            url: Some(prefixed_url),
            archive: None,
            from_dir: None,
            force: false,
            json: true,
        });
        assert_eq!(code_prefixed, ExitCode::from(EXIT_OK));
        assert!(state_ok.join("plugins/slack/index.mjs").is_file());

        // 7. 1-bit flip in text file (telegram) AND in binary file (icon.png) -> FAIL CLOSED, 0 bytes written!
        let tmp_bad = TempDir::new().expect("temp dir");
        let state_bad = tmp_bad.path().join("state");
        assert_eq!(
            run_plugin(PluginCommand::Install {
                plugin: "telegram".to_string(),
                state_dir: Some(state_bad.clone()),
                config: None,
                home: Some(tmp_bad.path().to_path_buf()),
                claude_config_dir: None,
                url: Some(format!("http://{addr}/tampered.tar.gz")),
                archive: None,
                from_dir: None,
                force: false,
                json: true,
            }),
            ExitCode::from(EXIT_ERROR)
        );
        assert!(
            !state_bad.join("plugins").exists(),
            "fail-closed text tamper rejection must write ZERO files"
        );
        assert!(
            !cached_plugins_archive_path(&state_bad).exists(),
            "tampered archive must NEVER be cached"
        );

        assert_eq!(
            run_plugin(PluginCommand::Install {
                plugin: "claude-code".to_string(),
                state_dir: Some(state_bad.clone()),
                config: None,
                home: Some(tmp_bad.path().to_path_buf()),
                claude_config_dir: None,
                url: Some(format!("http://{addr}/tampered-png.tar.gz")),
                archive: None,
                from_dir: None,
                force: false,
                json: true,
            }),
            ExitCode::from(EXIT_ERROR)
        );
        assert!(
            !state_bad.join("plugins").exists(),
            "fail-closed binary icon.png tamper rejection must write ZERO files"
        );

        let _ = stop_tx.send(());
        server_thread.join().expect("join server thread");
    }

    #[test]
    fn from_dir_and_archive_happy_path_harness_mods_and_1bit_tamper_fail_closed() {
        let tmp = TempDir::new().expect("temp dir");
        let state_dir = tmp.path().join("state");
        let home = tmp.path().join("home");
        fs::create_dir_all(&home).unwrap();

        // 1. --from-dir `all` installs bridges + sdk + claude-panel + claude-code + herdr-mod!
        let code_ok = run_plugin(PluginCommand::Install {
            plugin: "all".to_string(),
            state_dir: Some(state_dir.clone()),
            config: None,
            home: Some(home.clone()),
            claude_config_dir: None,
            url: None,
            archive: None,
            from_dir: Some(repo_plugins_dir()),
            force: false,
            json: true,
        });
        assert_eq!(code_ok, ExitCode::from(EXIT_OK));
        assert!(state_dir.join("plugins/telegram/index.mjs").is_file());
        assert!(state_dir.join("plugins/sdk/client.mjs").is_file());
        assert!(state_dir.join("plugins/sdk/client.py").is_file());
        assert!(
            state_dir
                .join("plugins/claude-code/.claude-plugin/icon.png")
                .is_file()
        );
        assert!(
            home.join(".claude/skills/hyp-panel/hooks/register.tsx")
                .is_file()
        );
        assert!(
            home.join(".claude/skills/hyp-panel/.claude-plugin/plugin.json")
                .is_file()
        );
        assert!(
            home.join(".config/herdr-app/mods/hyphae-pane/pill.js")
                .is_file()
        );
        assert!(
            home.join(".config/herdr-app/mods/hyphae-panel/main.js")
                .is_file()
        );

        // Verify passes across ALL 9 plugins!
        assert_eq!(
            run_plugin(PluginCommand::Verify {
                plugin: None,
                state_dir: Some(state_dir.clone()),
                config: None,
                home: Some(home.clone()),
                claude_config_dir: None,
                json: true,
            }),
            ExitCode::from(EXIT_OK)
        );

        // Removing one bridge keeps sdk/ intact because 4 other bridges remain!
        let rm_one = run_plugin(PluginCommand::Remove {
            plugin: "webhook".to_string(),
            keep_config: false,
            state_dir: Some(state_dir.clone()),
            config: None,
            home: Some(home.clone()),
            claude_config_dir: None,
            json: true,
        });
        assert_eq!(rm_one, ExitCode::from(EXIT_OK));
        assert!(!state_dir.join("plugins/webhook").exists());
        assert!(state_dir.join("plugins/sdk/client.mjs").is_file());

        // Removing `all` cleans up plugins/ AND harness mods!
        let rm_all = run_plugin(PluginCommand::Remove {
            plugin: "all".to_string(),
            keep_config: false,
            state_dir: Some(state_dir.clone()),
            config: None,
            home: Some(home.clone()),
            claude_config_dir: None,
            json: true,
        });
        assert_eq!(rm_all, ExitCode::from(EXIT_OK));
        assert!(!state_dir.join("plugins").exists());
        assert!(!home.join(".claude/skills/hyp-panel").exists());
        assert!(!home.join(".config/herdr-app/mods/hyphae-pane").exists());
        assert!(!home.join(".config/herdr-app/mods/hyphae-panel").exists());

        // 2. --from-dir 1-bit tamper -> FAIL CLOSED, 0 files written!
        let tampered_dir = tmp.path().join("tampered-src");
        for entry in PINNED_PLUGIN_FILES {
            let dst = tampered_dir.join(entry.rel_path);
            fs::create_dir_all(dst.parent().unwrap()).unwrap();
            let mut bytes = fs::read(repo_plugins_dir().join(entry.rel_path)).unwrap();
            if entry.rel_path == "sdk/client.mjs" {
                bytes[0] ^= 0x01;
            }
            fs::write(&dst, &bytes).unwrap();
        }
        let code_tampered_dir = run_plugin(PluginCommand::Install {
            plugin: "telegram".to_string(),
            state_dir: Some(state_dir.clone()),
            config: None,
            home: Some(home.clone()),
            claude_config_dir: None,
            url: None,
            archive: None,
            from_dir: Some(tampered_dir),
            force: false,
            json: true,
        });
        assert_eq!(code_tampered_dir, ExitCode::from(EXIT_ERROR));
        assert!(
            !state_dir.join("plugins").exists(),
            "tampered --from-dir must write ZERO files"
        );

        // 3. --archive happy path using pack_tar_gz on ALL 28 real repo files
        let archive_path = tmp.path().join("plugins.tar.gz");
        let entries: Vec<TarInputEntry> = PINNED_PLUGIN_FILES
            .iter()
            .map(|e| TarInputEntry {
                archive_path: e.rel_path.to_string(),
                source_path: repo_plugins_dir().join(e.rel_path),
            })
            .collect();
        let file = fs::File::create(&archive_path).unwrap();
        pack_tar_gz(&entries, file, TarPackOptions::default()).unwrap();

        let code_archive = run_plugin(PluginCommand::Install {
            plugin: "prometheus".to_string(),
            state_dir: Some(state_dir.clone()),
            config: None,
            home: Some(home.clone()),
            claude_config_dir: None,
            url: None,
            archive: Some(archive_path),
            from_dir: None,
            force: false,
            json: true,
        });
        assert_eq!(code_archive, ExitCode::from(EXIT_OK));
        assert!(state_dir.join("plugins/prometheus/index.mjs").is_file());
        assert!(state_dir.join("plugins/sdk/client.mjs").is_file());

        // 4. Unknown plugin name -> EXIT_USAGE (2)
        assert_eq!(
            run_plugin(PluginCommand::Install {
                plugin: "discord".to_string(),
                state_dir: Some(state_dir.clone()),
                config: None,
                home: Some(home.clone()),
                claude_config_dir: None,
                url: None,
                archive: None,
                from_dir: None,
                force: false,
                json: true,
            }),
            ExitCode::from(EXIT_USAGE)
        );

        // 5. Conflicting source flags (--url + --from-dir) -> EXIT_USAGE (2)
        assert_eq!(
            run_plugin(PluginCommand::Install {
                plugin: "telegram".to_string(),
                state_dir: Some(state_dir.clone()),
                config: None,
                home: Some(home.clone()),
                claude_config_dir: None,
                url: Some("https://example.com/plugins.tar.gz".to_string()),
                archive: None,
                from_dir: Some(repo_plugins_dir()),
                force: false,
                json: true,
            }),
            ExitCode::from(EXIT_USAGE)
        );

        // 6. List + permissions check + missing SDK fail-closed
        assert_eq!(
            run_plugin(PluginCommand::List {
                state_dir: Some(state_dir.clone()),
                config: None,
                home: Some(home.clone()),
                claude_config_dir: None,
                json: true,
            }),
            ExitCode::from(EXIT_OK)
        );
        assert_eq!(
            run_plugin(PluginCommand::List {
                state_dir: Some(state_dir.clone()),
                config: None,
                home: Some(home.clone()),
                claude_config_dir: None,
                json: false,
            }),
            ExitCode::from(EXIT_OK)
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_mode = fs::metadata(state_dir.join("plugins"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            let file_mode = fs::metadata(state_dir.join("plugins/prometheus/index.mjs"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            let receipt_mode = fs::metadata(receipts_file_path(&state_dir))
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700, "plugins dir must be 0700");
            assert_eq!(file_mode, 0o600, "installed plugin script must be 0600");
            assert_eq!(receipt_mode, 0o600, "installed.json must be 0600");
        }

        // Deleting sdk/client.mjs while prometheus is installed -> verify MUST fail closed!
        fs::remove_file(state_dir.join("plugins/sdk/client.mjs")).unwrap();
        assert_eq!(
            run_plugin(PluginCommand::Verify {
                plugin: None,
                state_dir: Some(state_dir),
                config: None,
                home: Some(home),
                claude_config_dir: None,
                json: true,
            }),
            ExitCode::from(EXIT_ERROR)
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlink_tampering_on_installed_plugin_fails_verify_and_doctor_closed() {
        use std::os::unix::fs::symlink;

        let tmp = TempDir::new().unwrap();
        let state_dir = tmp.path().join("state");
        let home = tmp.path().join("home");
        fs::create_dir_all(&home).unwrap();

        assert_eq!(
            run_plugin(PluginCommand::Install {
                plugin: "herdr-mod".to_string(),
                state_dir: Some(state_dir.clone()),
                config: None,
                home: Some(home.clone()),
                claude_config_dir: None,
                url: None,
                archive: None,
                from_dir: Some(repo_plugins_dir()),
                force: false,
                json: true,
            }),
            ExitCode::from(EXIT_OK)
        );

        // Replace main.js with a symlink to a decoy file -> verify & doctor MUST flag corrupt!
        let decoy = tmp.path().join("decoy.js");
        fs::write(&decoy, b"console.log('decoy');\n").unwrap();
        let target_main = home.join(".config/herdr-app/mods/hyphae-pane/main.js");
        fs::remove_file(&target_main).unwrap();
        symlink(&decoy, &target_main).unwrap();

        assert_eq!(
            run_plugin(PluginCommand::Verify {
                plugin: Some("herdr-mod".to_string()),
                state_dir: Some(state_dir.clone()),
                config: None,
                home: Some(home.clone()),
                claude_config_dir: None,
                json: true,
            }),
            ExitCode::from(EXIT_ERROR)
        );
        let doctor = inspect_plugins_for_doctor(&state_dir, Some(&home), true, None);
        assert_eq!(doctor.corrupt_count, 1);

        // Reinstall with --force MUST unlink the symlink (leaving decoy untouched!) and restore real file!
        assert_eq!(
            run_plugin(PluginCommand::Install {
                plugin: "herdr-mod".to_string(),
                state_dir: Some(state_dir.clone()),
                config: None,
                home: Some(home.clone()),
                claude_config_dir: None,
                url: None,
                archive: None,
                from_dir: Some(repo_plugins_dir()),
                force: true,
                json: true,
            }),
            ExitCode::from(EXIT_OK)
        );
        assert!(
            !fs::symlink_metadata(&target_main)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&decoy).unwrap(), b"console.log('decoy');\n");
    }

    #[test]
    fn clap_subcommand_definition_and_nvm_version_ordering_are_valid() {
        use clap::{CommandFactory, Parser};

        #[derive(Parser)]
        struct TestCli {
            #[command(subcommand)]
            cmd: PluginCommand,
        }

        TestCli::command().debug_assert();

        let parsed = TestCli::try_parse_from([
            "plugin",
            "update",
            "--all",
            "--dry-run",
            "--state-dir",
            "/tmp/s",
            "--json",
        ])
        .expect("parse `plugin update --all --dry-run --state-dir /tmp/s --json`");
        match parsed.cmd {
            PluginCommand::Update {
                all, dry_run, json, ..
            } => {
                assert!(all);
                assert!(dry_run);
                assert!(json);
            }
            _ => panic!("expected Update variant"),
        }

        assert_eq!(
            compare_nvm_versions("v24.1.0", "v22.12.0"),
            std::cmp::Ordering::Greater
        );
        assert_eq!(
            compare_nvm_versions("v24.10.0", "v24.2.0"),
            std::cmp::Ordering::Greater
        );
    }

    #[test]
    fn release_plugins_url_and_cache_path_resolve_stable_nightly_and_overrides() {
        // Stable SemVer -> vX.Y.Z release asset
        assert_eq!(
            resolve_release_plugins_url("0.7.0", None, None),
            "https://github.com/hyphae-to/hyp/releases/download/v0.7.0/hyp-v0.7.0-plugins.tar.gz"
        );
        assert_eq!(
            resolve_release_plugins_url("0.7.0", Some("stable"), None),
            "https://github.com/hyphae-to/hyp/releases/download/v0.7.0/hyp-v0.7.0-plugins.tar.gz"
        );
        assert_eq!(
            resolve_release_plugins_url("v0.7.0", Some("stable"), Some("v0.7.0")),
            "https://github.com/hyphae-to/hyp/releases/download/v0.7.0/hyp-v0.7.0-plugins.tar.gz"
        );

        // Non-nightly tagged prerelease -> vX.Y.Z-rc.N release asset
        assert!(!is_nightly_build_version("0.8.0-rc.1"));
        assert_eq!(
            resolve_release_plugins_url("0.8.0-rc.1", Some("stable"), None),
            "https://github.com/hyphae-to/hyp/releases/download/v0.8.0-rc.1/hyp-v0.8.0-rc.1-plugins.tar.gz"
        );

        // Nightly prerelease version -> rolling `nightly` GitHub Release asset
        assert!(is_nightly_build_version("0.7.1-nightly.20261126.bd3a90b"));
        assert!(is_nightly_build_version(
            "0.7.1-nightly.20261126.bd3a90b+ci"
        ));
        assert!(is_nightly_build_version("0.7.1-nightly"));
        assert!(!is_nightly_build_version("0.7.0"));
        assert!(!is_nightly_build_version("0.7.0+nightly"));
        assert_eq!(
            resolve_release_plugins_url("0.7.1-nightly.20261126.bd3a90b", None, None),
            "https://github.com/hyphae-to/hyp/releases/download/nightly/hyp-nightly-plugins.tar.gz"
        );
        assert_eq!(
            resolve_release_plugins_url(
                "0.7.1-nightly.20261126.bd3a90b",
                Some("nightly"),
                Some("nightly")
            ),
            "https://github.com/hyphae-to/hyp/releases/download/nightly/hyp-nightly-plugins.tar.gz"
        );

        // Nightly channel or explicit `nightly` release tag on a Cargo.toml base version (e.g. 0.7.0)
        assert_eq!(
            resolve_release_plugins_url("0.7.0", Some("nightly"), None),
            "https://github.com/hyphae-to/hyp/releases/download/nightly/hyp-nightly-plugins.tar.gz"
        );
        assert_eq!(
            resolve_release_plugins_url("0.7.0", Some("stable"), Some("nightly")),
            "https://github.com/hyphae-to/hyp/releases/download/nightly/hyp-nightly-plugins.tar.gz"
        );

        // Explicit CLI `--url` > `HYPHAE_PLUGINS_URL` env > build metadata default
        let nightly_default = resolve_release_plugins_url(
            "0.7.1-nightly.20261126.bd3a90b",
            Some("nightly"),
            Some("nightly"),
        );
        let stable_default = resolve_release_plugins_url("0.7.0", Some("stable"), None);
        assert_eq!(
            resolve_effective_plugins_download_url(
                Some("https://mirror.example.com/cli.tar.gz"),
                Some("https://mirror.example.com/env.tar.gz"),
                &nightly_default,
            ),
            "https://mirror.example.com/cli.tar.gz"
        );
        assert_eq!(
            resolve_effective_plugins_download_url(
                None,
                Some("  https://mirror.example.com/custom-nightly.tar.gz  "),
                &nightly_default,
            ),
            "https://mirror.example.com/custom-nightly.tar.gz"
        );
        assert_eq!(
            resolve_effective_plugins_download_url(Some("   "), Some("   "), &nightly_default),
            "https://github.com/hyphae-to/hyp/releases/download/nightly/hyp-nightly-plugins.tar.gz"
        );
        assert_eq!(
            resolve_effective_plugins_download_url(None, None, &stable_default),
            "https://github.com/hyphae-to/hyp/releases/download/v0.7.0/hyp-v0.7.0-plugins.tar.gz"
        );

        // All resolved URLs pass strict URL validator
        for url in [
            resolve_release_plugins_url("0.7.0", Some("stable"), None),
            resolve_release_plugins_url("0.7.1-nightly.20261126.bd3a90b", Some("nightly"), None),
            resolve_release_plugins_url("0.8.0-rc.1", Some("stable"), None),
            default_release_plugins_url(),
        ] {
            assert!(
                validate_plugin_download_url(&url).is_ok(),
                "resolved URL must pass validation: {url}"
            );
        }

        // Cache archive path isolates nightly builds from stable v0.7.0 caches
        let state = Path::new("/tmp/hyphae-state");
        let stable_cache = cached_plugins_archive_path_for(state, "0.7.0", Some("stable"));
        let nightly_ver_cache = cached_plugins_archive_path_for(
            state,
            "0.7.1-nightly.20261126.bd3a90b",
            Some("nightly"),
        );
        let nightly_ch_cache = cached_plugins_archive_path_for(state, "0.7.0", Some("nightly"));
        assert_eq!(
            stable_cache,
            state.join("plugins-cache/hyp-v0.7.0-plugins.tar.gz")
        );
        assert_eq!(
            nightly_ver_cache,
            state.join("plugins-cache/hyp-v0.7.1-nightly.20261126.bd3a90b-plugins.tar.gz")
        );
        assert_eq!(
            nightly_ch_cache,
            state.join("plugins-cache/hyp-nightly-plugins.tar.gz")
        );
        assert_ne!(stable_cache, nightly_ver_cache);
        assert_ne!(stable_cache, nightly_ch_cache);

        // Local `--from-dir` precedence beats URL/cache cleanly via `resolve_and_verify_files`
        let tmp = TempDir::new().unwrap();
        let spec = pinned_spec_for("telegram").expect("telegram spec");
        let required: Vec<&'static PinnedPluginFile> = spec.files.iter().collect();
        let (kind, loc, files) = resolve_and_verify_files(
            tmp.path(),
            &required,
            PluginSourceOverrides {
                archive: None,
                from_dir: Some(&repo_plugins_dir()),
                url: Some("http://127.0.0.1:1/unreachable.tar.gz"),
            },
        )
        .expect("--from-dir must take precedence over unreachable URL");
        assert_eq!(kind, InstallSourceKind::Dir);
        assert_eq!(loc, repo_plugins_dir().display().to_string());
        assert!(files.contains_key("telegram/index.mjs"));
    }
}
