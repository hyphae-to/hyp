//! `hyp plugin` — Release-Artifact Verified Official External Plugin Manager.
//!
//! Security invariants:
//! - `hyp` never embeds external plugin source code in the binary; `build.rs` pins ONLY the
//!   LF-normalized FIPS 180-4 SHA-256 digest of each of the 6 official runtime files
//!   (`sdk/client.mjs`, `telegram/index.mjs`, `slack/index.mjs`, `whatsapp/index.mjs`,
//!   `webhook/index.mjs`, `prometheus/index.mjs`).
//! - Remote downloads enforce `https://` (allowing `http://127.0.0.1` / `http://[::1]` ONLY for
//!   local loopback tests), bounded `<= 4 MiB` size, 30s timeout, and at most 5 safe redirects
//!   with zero HTTPS->HTTP downgrade.
//! - Archives unpack into an ephemeral private `0700` temp directory via
//!   `hyp_crypto::transfer::unpack_tar_gz` (rejecting symlinks, hardlinks, `..` traversal,
//!   absolute paths, and decompression bombs > 4 MiB).
//! - EVERY requested file (+ `sdk/client.mjs`) is verified in constant time against its
//!   compile-time pinned SHA-256 BEFORE a single byte is written to `<state_dir>/plugins/`.
//! - Installed files are written atomically (`write_atomic_file(..., true)`, `0600` under `0700`).

use crate::config_file::{
    build_http_client, ct_eq, ensure_dir, resolve_home_dir, resolve_state_dir, write_atomic_file,
};
use crate::ui::{
    CliCheck, CliError, EXIT_ERROR, EXIT_OK, EXIT_USAGE, JsonEnvelope, emit_error, print_checks,
    print_json, print_next_steps, print_warnings,
};
use clap::Subcommand;
use http::{Method, Request, Uri, header};
use http_body_util::{BodyExt, Empty};
use hyp_crypto::transfer::{TarUnpackOptions, unpack_tar_gz};
use hyper::body::Bytes;
use ring::rand::{SecureRandom, SystemRandom};
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

include!(concat!(env!("OUT_DIR"), "/plugin_checksums.rs"));

/// Maximum compressed and uncompressed byte size allowed for official plugin archives (4 MiB).
pub const MAX_ARCHIVE_BYTES: usize = 4 * 1024 * 1024;
const MAX_ARCHIVE_FILES: usize = 32;
const HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REDIRECTS: usize = 5;

const SDK_PLUGIN_KEY: &str = "sdk";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OfficialPluginSpec {
    pub name: &'static str,
    pub kind: &'static str,
    pub rel_path: &'static str,
}

/// All 5 installable official external plugins (each requires `sdk/client.mjs`).
pub const OFFICIAL_PLUGINS: &[OfficialPluginSpec] = &[
    OfficialPluginSpec {
        name: "telegram",
        kind: "bridge",
        rel_path: "telegram/index.mjs",
    },
    OfficialPluginSpec {
        name: "slack",
        kind: "bridge",
        rel_path: "slack/index.mjs",
    },
    OfficialPluginSpec {
        name: "whatsapp",
        kind: "bridge",
        rel_path: "whatsapp/index.mjs",
    },
    OfficialPluginSpec {
        name: "webhook",
        kind: "source",
        rel_path: "webhook/index.mjs",
    },
    OfficialPluginSpec {
        name: "prometheus",
        kind: "source",
        rel_path: "prometheus/index.mjs",
    },
];

#[derive(Debug, Clone, Subcommand)]
pub enum PluginCommand {
    /// List official external plugins, install status, and compile-time SHA-256 verification
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
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Download, SHA-256 verify, and atomically install an official external plugin (or `all`)
    Install {
        /// Plugin name: telegram, slack, whatsapp, webhook, prometheus, or all
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
        /// Override release tarball URL (https:// or loopback http://127.0.0.1 / http://[::1])
        #[arg(long)]
        url: Option<String>,
        /// Install and verify from a local .tar.gz plugin archive
        #[arg(long)]
        archive: Option<PathBuf>,
        /// Install and verify directly from a local plugins directory
        #[arg(long)]
        from_dir: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Remove an installed official plugin (or `all`) from <state_dir>/plugins/
    Remove {
        /// Plugin name: telegram, slack, whatsapp, webhook, prometheus, or all
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
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
    /// Verify SHA-256 integrity of every installed official plugin against compile-time digests
    Verify {
        /// Explicit Hyphae state directory (defaults to ~/.config/hyphae)
        #[arg(long)]
        state_dir: Option<PathBuf>,
        /// Explicit node.json path
        #[arg(long)]
        config: Option<PathBuf>,
        /// Override HOME directory
        #[arg(long)]
        home: Option<PathBuf>,
        /// Output structured JSON envelope
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct PluginListEntry {
    name: String,
    kind: String,
    installed: bool,
    verified: bool,
    script_path: String,
    pinned_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    node_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct InstalledPluginRecord {
    name: String,
    kind: String,
    script_path: String,
    sha256: String,
    verified: bool,
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
    Archive,
    Dir,
}

impl InstallSourceKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Release => "release",
            Self::Archive => "archive",
            Self::Dir => "dir",
        }
    }
}

/// Entrypoint wired from `main.rs` (`Commands::Plugin { command }`).
pub fn run_plugin(command: PluginCommand) -> ExitCode {
    match command {
        PluginCommand::List {
            state_dir,
            config,
            home,
            json,
        } => run_plugin_list(
            state_dir.as_deref(),
            config.as_deref(),
            home.as_deref(),
            json,
        ),
        PluginCommand::Install {
            plugin,
            state_dir,
            config,
            home,
            url,
            archive,
            from_dir,
            json,
        } => run_plugin_install(
            &plugin,
            state_dir.as_deref(),
            config.as_deref(),
            home.as_deref(),
            url.as_deref(),
            archive.as_deref(),
            from_dir.as_deref(),
            json,
        ),
        PluginCommand::Remove {
            plugin,
            state_dir,
            config,
            home,
            json,
        } => run_plugin_remove(
            &plugin,
            state_dir.as_deref(),
            config.as_deref(),
            home.as_deref(),
            json,
        ),
        PluginCommand::Verify {
            state_dir,
            config,
            home,
            json,
        } => run_plugin_verify(
            state_dir.as_deref(),
            config.as_deref(),
            home.as_deref(),
            json,
        ),
    }
}

/// Default GitHub Release URL for the official plugins tarball matching this binary's version.
pub fn default_release_plugins_url() -> String {
    let version = env!("CARGO_PKG_VERSION");
    format!(
        "https://github.com/hyphae-to/hyp/releases/download/v{version}/hyp-v{version}-plugins.tar.gz"
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

/// Computes lowercase hex SHA-256 over LF-normalized bytes.
pub fn sha256_lf_hex(bytes: &[u8]) -> String {
    let normalized = normalize_crlf(bytes);
    hex::encode(Sha256::digest(&normalized))
}

/// Looks up the compile-time pinned digest entry for `"sdk"` or any official plugin name.
pub fn pinned_entry_for(plugin: &str) -> Option<&'static PinnedPluginFile> {
    PINNED_PLUGIN_FILES.iter().find(|p| p.plugin == plugin)
}

/// Resolves a user plugin selector (`telegram|slack|whatsapp|webhook|prometheus|all`).
pub fn resolve_plugin_targets(selector: &str) -> Result<Vec<OfficialPluginSpec>, String> {
    let normalized = selector.trim().to_ascii_lowercase();
    if normalized == "all" {
        return Ok(OFFICIAL_PLUGINS.to_vec());
    }
    if let Some(spec) = OFFICIAL_PLUGINS.iter().find(|p| p.name == normalized) {
        return Ok(vec![*spec]);
    }
    let valid: Vec<&str> = OFFICIAL_PLUGINS.iter().map(|p| p.name).collect();
    Err(format!(
        "Unknown official plugin '{selector}'. Expected one of: {}, or all.",
        valid.join(", ")
    ))
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
        return Err("plugin archive URL must not contain whitespace or control characters".to_string());
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
        fallback_candidates.push(home.join(".local").join("share").join("mise").join("shims").join(bin_name));
        fallback_candidates.push(home.join(".asdf").join("shims").join(bin_name));
        fallback_candidates.push(home.join(".fnm").join("current").join("bin").join(bin_name));

        // Scan ~/.nvm/versions/node/v*/bin/node and pick the highest installed version.
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
        return Err(format!(
            "expected regular file at {}",
            path.display()
        ));
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

fn inspect_installed_file(path: &Path, expected_sha256: &str) -> (bool, bool, Option<String>, Option<String>) {
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
                return (
                    true,
                    false,
                    None,
                    Some("not a regular file".to_string()),
                );
            }
            match read_regular_file_checked(path) {
                Ok(bytes) => {
                    let actual = sha256_lf_hex(&bytes);
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

fn resolve_redirect_url(current_uri: &Uri, location: &str) -> Result<Uri, (&'static str, String)> {
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
        return Err((
            "UNSAFE_REDIRECT",
            format!("Refusing unsupported redirect Location '{location}'"),
        ));
    };

    let next_uri =
        validate_plugin_download_url(&next_url).map_err(|e| ("UNSAFE_REDIRECT", e))?;
    if current_uri.scheme_str() == Some("https") && next_uri.scheme_str() != Some("https") {
        return Err((
            "UNSAFE_REDIRECT",
            format!("Refusing HTTPS-to-HTTP downgrade redirect to '{next_url}'"),
        ));
    }
    Ok(next_uri)
}

async fn download_plugin_archive(initial_url: &str) -> Result<(Vec<u8>, String), (&'static str, String)> {
    let mut current_url = initial_url.trim().to_string();
    let mut current_uri =
        validate_plugin_download_url(&current_url).map_err(|e| ("UNSAFE_URL", e))?;
    let client = build_http_client::<Empty<Bytes>>().map_err(|e| ("HTTP_INIT_ERROR", e))?;

    for redirect_count in 0..=MAX_REDIRECTS {
        let req = Request::builder()
            .method(Method::GET)
            .uri(&current_uri)
            .header(
                header::USER_AGENT,
                format!("hyp/{}", env!("CARGO_PKG_VERSION")),
            )
            .body(Empty::new())
            .map_err(|e| ("HTTP_ERROR", format!("Failed to build request: {e}")))?;

        let resp = tokio::time::timeout(HTTP_TIMEOUT, client.request(req))
            .await
            .map_err(|_| {
                (
                    "HTTP_TIMEOUT",
                    format!(
                        "GET {current_url} timed out after {}s",
                        HTTP_TIMEOUT.as_secs()
                    ),
                )
            })?
            .map_err(|e| ("HTTP_ERROR", format!("GET {current_url} failed: {e}")))?;

        let status = resp.status();
        if status.is_redirection() {
            if redirect_count >= MAX_REDIRECTS {
                return Err((
                    "TOO_MANY_REDIRECTS",
                    format!("GET {current_url} exceeded {MAX_REDIRECTS} redirects"),
                ));
            }
            let location = resp
                .headers()
                .get(header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .ok_or_else(|| {
                    (
                        "HTTP_ERROR",
                        format!(
                            "GET {current_url} returned redirect HTTP {} without Location header",
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
            return Err((
                "HTTP_STATUS",
                format!("GET {current_url} returned HTTP {}", status.as_u16()),
            ));
        }

        let mut body = resp.into_body();
        let mut out = Vec::new();
        while let Some(frame_res) = body.frame().await {
            let frame = frame_res.map_err(|e| ("HTTP_ERROR", format!("body read error: {e}")))?;
            if let Some(chunk) = frame.data_ref() {
                if out.len().saturating_add(chunk.len()) > MAX_ARCHIVE_BYTES {
                    return Err((
                        "RESPONSE_TOO_LARGE",
                        format!(
                            "Download from {current_url} exceeds {MAX_ARCHIVE_BYTES} byte limit"
                        ),
                    ));
                }
                out.extend_from_slice(chunk);
            }
        }
        return Ok((out, current_url));
    }

    Err((
        "TOO_MANY_REDIRECTS",
        format!("GET {initial_url} exceeded redirect limit"),
    ))
}

fn normalize_archive_rel_path(archive_path: &str) -> &str {
    let without_dot = archive_path.strip_prefix("./").unwrap_or(archive_path);
    without_dot.strip_prefix("plugins/").unwrap_or(without_dot)
}

/// Unpacks `archive_bytes` into an ephemeral private staging directory and verifies EVERY
/// required file (`sdk/client.mjs` + each target plugin's `<name>/index.mjs`) against the
/// compile-time pinned SHA-256 digests BEFORE returning the verified LF-normalized bytes.
fn extract_and_verify_archive(
    archive_bytes: &[u8],
    required_entries: &[&'static PinnedPluginFile],
) -> Result<BTreeMap<&'static str, Vec<u8>>, (&'static str, String)> {
    if archive_bytes.is_empty() {
        return Err((
            "INVALID_ARCHIVE",
            "Plugin archive is empty".to_string(),
        ));
    }
    if archive_bytes.len() > MAX_ARCHIVE_BYTES {
        return Err((
            "ARCHIVE_TOO_LARGE",
            format!("Plugin archive exceeds {MAX_ARCHIVE_BYTES} byte limit"),
        ));
    }

    let stage = TempStageDir::create("hyp-plugin-stage")
        .map_err(|e| ("IO_ERROR", e))?;
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
        (
            "EXTRACT_FAILED",
            format!("Failed to safely unpack plugin archive (fail-closed): {e}"),
        )
    })?;

    let mut extracted_by_rel: BTreeMap<String, PathBuf> = BTreeMap::new();
    for file in &unpacked.files {
        let rel = normalize_archive_rel_path(&file.archive_path).to_string();
        if extracted_by_rel.insert(rel.clone(), file.disk_path.clone()).is_some() {
            return Err((
                "INVALID_ARCHIVE",
                format!("Archive contains duplicate normalized plugin entry '{rel}'"),
            ));
        }
    }

    let mut verified_files: BTreeMap<&'static str, Vec<u8>> = BTreeMap::new();
    for &entry in required_entries {
        let Some(disk_path) = extracted_by_rel.get(entry.rel_path) else {
            return Err((
                "MISSING_PLUGIN_FILE",
                format!(
                    "Plugin archive is missing required file '{}' (fail-closed, 0 bytes installed)",
                    entry.rel_path
                ),
            ));
        };
        let raw = read_regular_file_checked(disk_path)
            .map_err(|e| ("IO_ERROR", e))?;
        let normalized = normalize_crlf(&raw);
        let actual_sha = hex::encode(Sha256::digest(&normalized));
        if !ct_eq(actual_sha.as_bytes(), entry.sha256.as_bytes()) {
            return Err((
                "CHECKSUM_MISMATCH",
                format!(
                    "SHA-256 verification failed for '{}' (fail-closed, 0 bytes installed): expected {}, got {}",
                    entry.rel_path, entry.sha256, actual_sha
                ),
            ));
        }
        verified_files.insert(entry.rel_path, normalized);
    }

    Ok(verified_files)
}

/// Reads and verifies all required plugin files directly from a local directory (`--from-dir`),
/// supporting both `<dir>/sdk/client.mjs` and `<dir>/plugins/sdk/client.mjs`.
fn read_and_verify_from_dir(
    dir: &Path,
    required_entries: &[&'static PinnedPluginFile],
) -> Result<BTreeMap<&'static str, Vec<u8>>, (&'static str, String)> {
    if !dir.is_dir() {
        return Err((
            "INVALID_SOURCE_DIR",
            format!("Plugin source directory does not exist: {}", dir.display()),
        ));
    }

    let base_dir = if dir.join("sdk").join("client.mjs").exists() {
        dir.to_path_buf()
    } else if dir.join("plugins").join("sdk").join("client.mjs").exists() {
        dir.join("plugins")
    } else {
        dir.to_path_buf()
    };

    let mut verified_files: BTreeMap<&'static str, Vec<u8>> = BTreeMap::new();
    for &entry in required_entries {
        let full_path = base_dir.join(entry.rel_path);
        if !full_path.exists() && fs::symlink_metadata(&full_path).is_err() {
            return Err((
                "MISSING_PLUGIN_FILE",
                format!(
                    "Required plugin file '{}' not found under {} (fail-closed, 0 bytes installed)",
                    entry.rel_path,
                    base_dir.display()
                ),
            ));
        }
        let raw = read_regular_file_checked(&full_path)
            .map_err(|e| ("INVALID_SOURCE_FILE", e))?;
        let normalized = normalize_crlf(&raw);
        let actual_sha = hex::encode(Sha256::digest(&normalized));
        if !ct_eq(actual_sha.as_bytes(), entry.sha256.as_bytes()) {
            return Err((
                "CHECKSUM_MISMATCH",
                format!(
                    "SHA-256 verification failed for '{}' (fail-closed, 0 bytes installed): expected {}, got {}",
                    entry.rel_path, entry.sha256, actual_sha
                ),
            ));
        }
        verified_files.insert(entry.rel_path, normalized);
    }

    Ok(verified_files)
}

fn run_plugin_list(
    state_dir_arg: Option<&Path>,
    config_arg: Option<&Path>,
    home_arg: Option<&Path>,
    as_json: bool,
) -> ExitCode {
    let cmd = "plugin list";
    let state_dir = resolve_state_dir(state_dir_arg, config_arg, home_arg);
    let plugins_dir = state_dir.join("plugins");
    let node_path = detect_node_path(home_arg);

    let sdk_pinned = pinned_entry_for(SDK_PLUGIN_KEY).expect("sdk pinned entry exists");
    let sdk_path = plugins_dir.join(sdk_pinned.rel_path);
    let (sdk_installed, sdk_verified, _, sdk_reason) =
        inspect_installed_file(&sdk_path, sdk_pinned.sha256);

    let mut entries = Vec::with_capacity(OFFICIAL_PLUGINS.len());
    let mut warnings = Vec::new();
    let mut installed_count = 0usize;
    let mut verified_count = 0usize;

    for spec in OFFICIAL_PLUGINS {
        let pinned = pinned_entry_for(spec.name).expect("official plugin pinned entry exists");
        let script_path = plugins_dir.join(spec.rel_path);
        let (installed, file_verified, _, reason) =
            inspect_installed_file(&script_path, pinned.sha256);
        let verified = installed && file_verified && sdk_verified;
        if installed {
            installed_count += 1;
            if verified {
                verified_count += 1;
            } else if let Some(r) = reason {
                warnings.push(format!("{}: {r}", spec.name));
            } else if !sdk_verified {
                warnings.push(format!(
                    "{}: shared sdk/client.mjs is {}",
                    spec.name,
                    sdk_reason.as_deref().unwrap_or("missing or unverified")
                ));
            }
        }
        entries.push(PluginListEntry {
            name: spec.name.to_string(),
            kind: spec.kind.to_string(),
            installed,
            verified,
            script_path: script_path.display().to_string(),
            pinned_sha256: pinned.sha256.to_string(),
            node_path: node_path.clone(),
        });
    }

    if node_path.is_none() {
        warnings.push(
            "Node.js (24+) not found in PATH; install Node.js 24+ before running external bridge plugins."
                .to_string(),
        );
    }

    let next = if installed_count == 0 {
        vec!["hyp plugin install <telegram|slack|whatsapp|webhook|prometheus> --json".to_string()]
    } else if verified_count < installed_count {
        vec!["hyp plugin verify --json".to_string()]
    } else {
        Vec::new()
    };

    let summary = format!(
        "{installed_count}/{} official plugins installed ({verified_count} verified) in {}",
        OFFICIAL_PLUGINS.len(),
        plugins_dir.display()
    );

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(summary),
            data: Some(json!({
                "pluginsDir": plugins_dir.display().to_string(),
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
            "Node.js binary:    {}",
            node_path.as_deref().unwrap_or("(not detected)")
        );
        println!();
        println!(
            "{:<12}  {:<8}  {:<10}  {:<10}  Path",
            "Plugin", "Kind", "Installed", "Verified"
        );
        println!("{}", "-".repeat(78));
        for e in &entries {
            println!(
                "{:<12}  {:<8}  {:<10}  {:<10}  {}",
                e.name,
                e.kind,
                if e.installed { "yes" } else { "no" },
                if !e.installed {
                    "-"
                } else if e.verified {
                    "OK"
                } else {
                    "FAIL"
                },
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
    url_arg: Option<&str>,
    archive_arg: Option<&Path>,
    from_dir_arg: Option<&Path>,
    as_json: bool,
) -> ExitCode {
    let cmd = "plugin install";

    let source_flags = usize::from(url_arg.is_some())
        + usize::from(archive_arg.is_some())
        + usize::from(from_dir_arg.is_some());
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

    let targets = match resolve_plugin_targets(plugin_arg) {
        Ok(t) => t,
        Err(msg) => return emit_error(cmd, as_json, EXIT_USAGE, "UNKNOWN_PLUGIN", msg, None),
    };

    let sdk_pinned = pinned_entry_for(SDK_PLUGIN_KEY).expect("sdk pinned entry exists");
    let mut required_entries: Vec<&'static PinnedPluginFile> = Vec::with_capacity(targets.len() + 1);
    required_entries.push(sdk_pinned);
    for spec in &targets {
        required_entries.push(pinned_entry_for(spec.name).expect("official plugin pinned entry"));
    }

    let (source_kind, source_detail, verified_files) = if let Some(dir) = from_dir_arg {
        match read_and_verify_from_dir(dir, &required_entries) {
            Ok(files) => (
                InstallSourceKind::Dir,
                dir.display().to_string(),
                files,
            ),
            Err((code, msg)) => return emit_error(cmd, as_json, EXIT_ERROR, code, msg, None),
        }
    } else if let Some(archive_path) = archive_arg {
        let bytes = match read_regular_file_checked(archive_path) {
            Ok(b) => b,
            Err(e) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "ARCHIVE_READ_ERROR",
                    e,
                    None,
                );
            }
        };
        match extract_and_verify_archive(&bytes, &required_entries) {
            Ok(files) => (
                InstallSourceKind::Archive,
                archive_path.display().to_string(),
                files,
            ),
            Err((code, msg)) => return emit_error(cmd, as_json, EXIT_ERROR, code, msg, None),
        }
    } else {
        let download_url = url_arg
            .map(ToOwned::to_owned)
            .unwrap_or_else(default_release_plugins_url);
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
                    format!("Failed to initialize async runtime: {e}"),
                    None,
                );
            }
        };
        let (archive_bytes, final_url) = match rt.block_on(download_plugin_archive(&download_url)) {
            Ok(res) => res,
            Err((code, msg)) => {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    code,
                    msg,
                    Some(
                        "Check network access or pass --archive <path-to-plugins.tar.gz> / --from-dir <plugins-dir>."
                            .to_string(),
                    ),
                );
            }
        };
        match extract_and_verify_archive(&archive_bytes, &required_entries) {
            Ok(files) => (InstallSourceKind::Release, final_url, files),
            Err((code, msg)) => return emit_error(cmd, as_json, EXIT_ERROR, code, msg, None),
        }
    };

    // ALL files have passed constant-time SHA-256 verification. Now atomically install them.
    let state_dir = resolve_state_dir(state_dir_arg, config_arg, home_arg);
    let plugins_dir = state_dir.join("plugins");
    if let Err(e) = ensure_dir(&plugins_dir, true) {
        return emit_error(cmd, as_json, EXIT_ERROR, "IO_ERROR", e, None);
    }

    for &entry in &required_entries {
        let dest = plugins_dir.join(entry.rel_path);
        let bytes = verified_files
            .get(entry.rel_path)
            .expect("verified entry present");
        if let Err(e) = write_atomic_file(&dest, bytes, true) {
            return emit_error(cmd, as_json, EXIT_ERROR, "IO_ERROR", e, None);
        }
    }

    let sdk_dest = plugins_dir.join(sdk_pinned.rel_path);
    let node_path = detect_node_path(home_arg);

    let mut installed_records = Vec::with_capacity(targets.len());
    for spec in &targets {
        let pinned = pinned_entry_for(spec.name).expect("official plugin pinned entry");
        installed_records.push(InstalledPluginRecord {
            name: spec.name.to_string(),
            kind: spec.kind.to_string(),
            script_path: plugins_dir.join(spec.rel_path).display().to_string(),
            sha256: pinned.sha256.to_string(),
            verified: true,
        });
    }

    let mut warnings = Vec::new();
    if node_path.is_none() {
        warnings.push(
            "Node.js (24+) was not detected in PATH; install Node.js 24+ before enabling external plugins in node.json."
                .to_string(),
        );
    }

    let node_cmd_hint = node_path.as_deref().unwrap_or("node");
    let mut next = Vec::new();
    if let Some(first) = installed_records.first() {
        next.push(format!(
            "Wire in ~/.config/hyphae/node.json plugins[]: command = \"{node_cmd_hint}\", args = [\"{}\"]",
            first.script_path
        ));
    }
    next.push("hyp service restart --json".to_string());

    let names_joined: Vec<&str> = installed_records.iter().map(|r| r.name.as_str()).collect();
    let summary = format!(
        "Installed and verified {} ({}) into {}",
        names_joined.join(", "),
        source_kind.as_str(),
        plugins_dir.display()
    );

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(summary),
            data: Some(json!({
                "plugins": installed_records,
                "sdkPath": sdk_dest.display().to_string(),
                "sdkSha256": sdk_pinned.sha256,
                "pluginsDir": plugins_dir.display().to_string(),
                "nodePath": node_path,
                "source": source_kind.as_str(),
                "sourceLocation": source_detail,
            })),
            warnings,
            next,
            error: None,
        };
        print_json(&envelope);
    } else {
        println!("OK    {summary}");
        println!("      SDK:   {} ({})", sdk_dest.display(), &sdk_pinned.sha256[..16]);
        for rec in &installed_records {
            println!(
                "      {:<10} {} ({})",
                rec.name,
                rec.script_path,
                &rec.sha256[..16]
            );
        }
        println!(
            "      Node:  {}",
            node_path.as_deref().unwrap_or("(not detected)")
        );
        print_warnings(&warnings);
        print_next_steps(&next);
    }

    ExitCode::from(EXIT_OK)
}

fn run_plugin_remove(
    plugin_arg: &str,
    state_dir_arg: Option<&Path>,
    config_arg: Option<&Path>,
    home_arg: Option<&Path>,
    as_json: bool,
) -> ExitCode {
    let cmd = "plugin remove";
    let is_all = plugin_arg.trim().eq_ignore_ascii_case("all");
    let targets = match resolve_plugin_targets(plugin_arg) {
        Ok(t) => t,
        Err(msg) => return emit_error(cmd, as_json, EXIT_USAGE, "UNKNOWN_PLUGIN", msg, None),
    };

    let state_dir = resolve_state_dir(state_dir_arg, config_arg, home_arg);
    let plugins_dir = state_dir.join("plugins");

    let mut removed: Vec<String> = Vec::new();
    let mut sdk_removed = false;

    if is_all {
        if plugins_dir.exists() {
            for spec in OFFICIAL_PLUGINS {
                if plugins_dir.join(spec.name).exists() {
                    removed.push(spec.name.to_string());
                }
            }
            sdk_removed = plugins_dir.join(SDK_PLUGIN_KEY).exists();
            if let Err(e) = fs::remove_dir_all(&plugins_dir) {
                return emit_error(
                    cmd,
                    as_json,
                    EXIT_ERROR,
                    "IO_ERROR",
                    format!("Failed to remove {}: {e}", plugins_dir.display()),
                    None,
                );
            }
        }
    } else {
        for spec in &targets {
            let plugin_subdir = plugins_dir.join(spec.name);
            if fs::symlink_metadata(&plugin_subdir).is_ok() {
                if let Err(e) = fs::remove_dir_all(&plugin_subdir) {
                    return emit_error(
                        cmd,
                        as_json,
                        EXIT_ERROR,
                        "IO_ERROR",
                        format!("Failed to remove {}: {e}", plugin_subdir.display()),
                        None,
                    );
                }
                removed.push(spec.name.to_string());
            }
        }

        // If no official plugins remain installed, clean up sdk/ and empty plugins/ directory.
        let any_remaining = OFFICIAL_PLUGINS
            .iter()
            .any(|spec| fs::symlink_metadata(plugins_dir.join(spec.name)).is_ok());
        if !any_remaining {
            let sdk_dir = plugins_dir.join(SDK_PLUGIN_KEY);
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
            if plugins_dir.exists() {
                let _ = fs::remove_dir(&plugins_dir);
            }
        }
    }

    let summary = if removed.is_empty() && !sdk_removed {
        format!("Nothing to remove for '{plugin_arg}' under {}", plugins_dir.display())
    } else {
        format!(
            "Removed {} from {}",
            if removed.is_empty() {
                "sdk".to_string()
            } else {
                removed.join(", ")
            },
            plugins_dir.display()
        )
    };

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(summary),
            data: Some(json!({
                "pluginsDir": plugins_dir.display().to_string(),
                "removed": removed,
                "sdkRemoved": sdk_removed,
            })),
            warnings: Vec::new(),
            next: Vec::new(),
            error: None,
        };
        print_json(&envelope);
    } else {
        println!("OK    {summary}");
    }

    ExitCode::from(EXIT_OK)
}

fn run_plugin_verify(
    state_dir_arg: Option<&Path>,
    config_arg: Option<&Path>,
    home_arg: Option<&Path>,
    as_json: bool,
) -> ExitCode {
    let cmd = "plugin verify";
    let state_dir = resolve_state_dir(state_dir_arg, config_arg, home_arg);
    let plugins_dir = state_dir.join("plugins");

    let mut records: Vec<VerifiedFileRecord> = Vec::new();
    let mut checks: Vec<CliCheck> = Vec::new();
    let mut any_plugin_installed = false;

    for spec in OFFICIAL_PLUGINS {
        let pinned = pinned_entry_for(spec.name).expect("official plugin pinned entry");
        let path = plugins_dir.join(pinned.rel_path);
        let (present, ok, actual, reason) = inspect_installed_file(&path, pinned.sha256);
        if present {
            any_plugin_installed = true;
            if ok {
                checks.push(CliCheck::ok(
                    pinned.rel_path,
                    format!("verified ({})", &pinned.sha256[..16]),
                ));
            } else {
                checks.push(CliCheck::fail(
                    pinned.rel_path,
                    reason
                        .clone()
                        .unwrap_or_else(|| "SHA-256 verification failed".to_string()),
                    Some(format!("Reinstall with: hyp plugin install {}", spec.name)),
                ));
            }
            records.push(VerifiedFileRecord {
                plugin: pinned.plugin.to_string(),
                rel_path: pinned.rel_path.to_string(),
                path: path.display().to_string(),
                pinned_sha256: pinned.sha256.to_string(),
                actual_sha256: actual,
                verified: ok,
                reason,
            });
        }
    }

    let sdk_pinned = pinned_entry_for(SDK_PLUGIN_KEY).expect("sdk pinned entry");
    let sdk_path = plugins_dir.join(sdk_pinned.rel_path);
    let (sdk_present, sdk_ok, sdk_actual, sdk_reason) =
        inspect_installed_file(&sdk_path, sdk_pinned.sha256);
    if sdk_present || any_plugin_installed {
        let reason = if !sdk_present {
            Some("required shared SDK file is missing".to_string())
        } else {
            sdk_reason
        };
        if sdk_ok {
            checks.push(CliCheck::ok(
                sdk_pinned.rel_path,
                format!("verified ({})", &sdk_pinned.sha256[..16]),
            ));
        } else {
            checks.push(CliCheck::fail(
                sdk_pinned.rel_path,
                reason
                    .clone()
                    .unwrap_or_else(|| "SHA-256 verification failed".to_string()),
                Some("Reinstall affected plugin(s) with: hyp plugin install <plugin>".to_string()),
            ));
        }
        records.insert(
            0,
            VerifiedFileRecord {
                plugin: sdk_pinned.plugin.to_string(),
                rel_path: sdk_pinned.rel_path.to_string(),
                path: sdk_path.display().to_string(),
                pinned_sha256: sdk_pinned.sha256.to_string(),
                actual_sha256: sdk_actual,
                verified: sdk_ok,
                reason,
            },
        );
    }

    let failed_count = records.iter().filter(|r| !r.verified).count();
    let all_ok = failed_count == 0;

    let summary = if records.is_empty() {
        format!("No official plugins installed under {}", plugins_dir.display())
    } else if all_ok {
        format!(
            "All {} installed plugin file(s) verified against compile-time SHA-256 digests",
            records.len()
        )
    } else {
        format!(
            "{failed_count} of {} installed plugin file(s) failed SHA-256 verification",
            records.len()
        )
    };

    let next = if all_ok {
        Vec::new()
    } else {
        vec!["hyp plugin install all --json".to_string()]
    };

    if as_json {
        let envelope = JsonEnvelope {
            ok: all_ok,
            command: cmd.to_string(),
            summary: Some(summary.clone()),
            data: Some(json!({
                "pluginsDir": plugins_dir.display().to_string(),
                "checked": records.len(),
                "failed": failed_count,
                "files": records,
            })),
            warnings: Vec::new(),
            next,
            error: if all_ok {
                None
            } else {
                Some(CliError {
                    code: "PLUGIN_VERIFY_FAILED".to_string(),
                    message: summary,
                    fix: Some("Reinstall tampered or corrupted plugins via `hyp plugin install <name>`.".to_string()),
                })
            },
        };
        print_json(&envelope);
    } else if records.is_empty() {
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
    fn differential_build_rs_sha256_matches_sha2_crate_for_all_6_files() {
        assert_eq!(PINNED_PLUGIN_FILES.len(), 6);
        let root = repo_plugins_dir();
        for entry in PINNED_PLUGIN_FILES {
            let raw = fs::read(root.join(entry.rel_path))
                .unwrap_or_else(|e| panic!("failed reading {}: {e}", entry.rel_path));
            let expected = sha256_lf_hex(&raw);
            assert_eq!(
                entry.sha256, expected,
                "build.rs SHA-256 diverged from sha2::Sha256 for {}",
                entry.rel_path
            );

            // Synthetic CRLF version MUST hash to the exact same pinned digest.
            let lf = normalize_crlf(&raw);
            let mut crlf = Vec::with_capacity(lf.len() + 64);
            for &b in &lf {
                if b == b'\n' {
                    crlf.push(b'\r');
                }
                crlf.push(b);
            }
            assert_eq!(
                sha256_lf_hex(&crlf),
                entry.sha256,
                "CRLF normalization must preserve exact digest for {}",
                entry.rel_path
            );
        }
    }

    #[test]
    fn url_validation_enforces_https_and_loopback_only() {
        assert!(validate_plugin_download_url(&default_release_plugins_url()).is_ok());
        assert!(validate_plugin_download_url("https://github.com/hyphae-to/hyp/releases/download/v0.6.1/hyp-v0.6.1-plugins.tar.gz").is_ok());
        assert!(validate_plugin_download_url("http://127.0.0.1:8080/plugins.tar.gz").is_ok());
        assert!(validate_plugin_download_url("http://[::1]:8080/plugins.tar.gz").is_ok());

        for bad in [
            "",
            "   ",
            "http://evil.com/plugins.tar.gz",
            "http://github.com/hyphae-to/hyp/releases/download/v0.6.1/hyp-v0.6.1-plugins.tar.gz",
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

        // Redirect downgrade from https -> http loopback must be rejected!
        let https_uri: Uri = "https://github.com/hyphae-to/hyp/releases/latest".parse().unwrap();
        let err = resolve_redirect_url(&https_uri, "http://127.0.0.1:8080/plugins.tar.gz")
            .expect_err("HTTPS->HTTP downgrade redirect must fail closed");
        assert_eq!(err.0, "UNSAFE_REDIRECT");
    }

    #[test]
    fn loopback_http_install_verify_tamper_and_remove_lifecycle() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        let valid_tarball = build_official_plugins_tarball("", None);
        let prefixed_tarball = build_official_plugins_tarball("plugins/", None);
        let tampered_tarball = build_official_plugins_tarball("", Some("telegram/index.mjs"));

        let (addr, server_handle) = rt.block_on(async {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
            let addr = listener.local_addr().expect("local addr");

            let valid_body = valid_tarball.clone();
            let prefixed_body = prefixed_tarball.clone();
            let tampered_body = tampered_tarball.clone();

            let handle = tokio::spawn(async move {
                for _ in 0..4 {
                    let (mut sock, _) = listener.accept().await.expect("accept");
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
                    } else {
                        let _ = sock
                            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                            .await;
                    }
                    let _ = sock.shutdown().await;
                }
            });
            (addr, handle)
        });

        // Move server runtime to a background thread so synchronous `run_plugin_install` can build its own runtime.
        let server_thread = std::thread::spawn(move || {
            rt.block_on(server_handle).expect("server task");
        });

        // 1. Happy path over loopback HTTP with 302 redirect -> installs sdk + telegram, verify passes!
        let tmp_ok = TempDir::new().expect("temp dir");
        let state_ok = tmp_ok.path().join("state");
        let redirect_url = format!("http://{addr}/redirect.tar.gz");
        let code = run_plugin(PluginCommand::Install {
            plugin: "telegram".to_string(),
            state_dir: Some(state_ok.clone()),
            config: None,
            home: Some(tmp_ok.path().to_path_buf()),
            url: Some(redirect_url),
            archive: None,
            from_dir: None,
            json: true,
        });
        assert_eq!(code, ExitCode::from(EXIT_OK));
        let tg_path = state_ok.join("plugins/telegram/index.mjs");
        let sdk_path = state_ok.join("plugins/sdk/client.mjs");
        assert!(tg_path.is_file(), "telegram/index.mjs must be installed");
        assert!(sdk_path.is_file(), "sdk/client.mjs must be installed");

        let verify_ok = run_plugin(PluginCommand::Verify {
            state_dir: Some(state_ok.clone()),
            config: None,
            home: Some(tmp_ok.path().to_path_buf()),
            json: true,
        });
        assert_eq!(verify_ok, ExitCode::from(EXIT_OK));

        // 2. Post-install 1-byte tamper on disk -> verify MUST fail closed with exit code 1!
        let mut on_disk = fs::read(&tg_path).expect("read installed telegram");
        on_disk.push(b' ');
        fs::write(&tg_path, &on_disk).expect("tamper installed telegram");
        let verify_tampered = run_plugin(PluginCommand::Verify {
            state_dir: Some(state_ok.clone()),
            config: None,
            home: Some(tmp_ok.path().to_path_buf()),
            json: true,
        });
        assert_eq!(verify_tampered, ExitCode::from(EXIT_ERROR));

        // 3. Remove telegram -> cleans up telegram/ AND sdk/ (no plugins remain)!
        let remove_code = run_plugin(PluginCommand::Remove {
            plugin: "telegram".to_string(),
            state_dir: Some(state_ok.clone()),
            config: None,
            home: Some(tmp_ok.path().to_path_buf()),
            json: true,
        });
        assert_eq!(remove_code, ExitCode::from(EXIT_OK));
        assert!(!tg_path.exists());
        assert!(!sdk_path.exists(), "sdk/ must be removed when no plugins remain");

        // 4. Prefixed `plugins/<rel>` tarball layout works cleanly too!
        let prefixed_url = format!("http://{addr}/prefixed.tar.gz");
        let code_prefixed = run_plugin(PluginCommand::Install {
            plugin: "slack".to_string(),
            state_dir: Some(state_ok.clone()),
            config: None,
            home: Some(tmp_ok.path().to_path_buf()),
            url: Some(prefixed_url),
            archive: None,
            from_dir: None,
            json: true,
        });
        assert_eq!(code_prefixed, ExitCode::from(EXIT_OK));
        assert!(state_ok.join("plugins/slack/index.mjs").is_file());

        // 5. Mutated valid input: 1-bit flip in telegram/index.mjs inside tarball -> FAIL CLOSED with 0 files written!
        let tmp_bad = TempDir::new().expect("temp dir");
        let state_bad = tmp_bad.path().join("state");
        let tampered_url = format!("http://{addr}/tampered.tar.gz");
        let bad_code = run_plugin(PluginCommand::Install {
            plugin: "telegram".to_string(),
            state_dir: Some(state_bad.clone()),
            config: None,
            home: Some(tmp_bad.path().to_path_buf()),
            url: Some(tampered_url),
            archive: None,
            from_dir: None,
            json: true,
        });
        assert_eq!(bad_code, ExitCode::from(EXIT_ERROR));
        assert!(
            !state_bad.join("plugins").exists(),
            "fail-closed tamper rejection must write ZERO files to <state_dir>/plugins/"
        );

        server_thread.join().expect("join server thread");
    }

    #[test]
    fn from_dir_and_archive_happy_path_and_1bit_tamper_fail_closed() {
        let tmp = TempDir::new().expect("temp dir");
        let state_dir = tmp.path().join("state");

        // 1. --from-dir happy path from real repo plugins/ directory
        let code_ok = run_plugin(PluginCommand::Install {
            plugin: "all".to_string(),
            state_dir: Some(state_dir.clone()),
            config: None,
            home: Some(tmp.path().to_path_buf()),
            url: None,
            archive: None,
            from_dir: Some(repo_plugins_dir()),
            json: true,
        });
        assert_eq!(code_ok, ExitCode::from(EXIT_OK));
        for entry in PINNED_PLUGIN_FILES {
            assert!(
                state_dir.join("plugins").join(entry.rel_path).is_file(),
                "missing installed {}",
                entry.rel_path
            );
        }

        // Removing one plugin keeps sdk/ intact because 4 other plugins remain!
        let rm_one = run_plugin(PluginCommand::Remove {
            plugin: "webhook".to_string(),
            state_dir: Some(state_dir.clone()),
            config: None,
            home: Some(tmp.path().to_path_buf()),
            json: true,
        });
        assert_eq!(rm_one, ExitCode::from(EXIT_OK));
        assert!(!state_dir.join("plugins/webhook").exists());
        assert!(state_dir.join("plugins/sdk/client.mjs").is_file());

        // Removing `all` removes the entire plugins/ directory.
        let rm_all = run_plugin(PluginCommand::Remove {
            plugin: "all".to_string(),
            state_dir: Some(state_dir.clone()),
            config: None,
            home: Some(tmp.path().to_path_buf()),
            json: true,
        });
        assert_eq!(rm_all, ExitCode::from(EXIT_OK));
        assert!(!state_dir.join("plugins").exists());

        // 2. --from-dir 1-bit tamper -> FAIL CLOSED, 0 files written!
        let tampered_dir = tmp.path().join("tampered-src");
        for entry in PINNED_PLUGIN_FILES {
            let dst = tampered_dir.join(entry.rel_path);
            fs::create_dir_all(dst.parent().unwrap()).unwrap();
            let mut bytes = fs::read(repo_plugins_dir().join(entry.rel_path)).unwrap();
            if entry.plugin == "sdk" {
                bytes[0] ^= 0x01; // Tamper shared SDK by 1 bit!
            }
            fs::write(&dst, &bytes).unwrap();
        }
        let code_tampered_dir = run_plugin(PluginCommand::Install {
            plugin: "telegram".to_string(),
            state_dir: Some(state_dir.clone()),
            config: None,
            home: Some(tmp.path().to_path_buf()),
            url: None,
            archive: None,
            from_dir: Some(tampered_dir),
            json: true,
        });
        assert_eq!(code_tampered_dir, ExitCode::from(EXIT_ERROR));
        assert!(
            !state_dir.join("plugins").exists(),
            "tampered --from-dir must write ZERO files"
        );

        // 3. --archive happy path using pack_tar_gz on real repo files
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
            home: Some(tmp.path().to_path_buf()),
            url: None,
            archive: Some(archive_path),
            from_dir: None,
            json: true,
        });
        assert_eq!(code_archive, ExitCode::from(EXIT_OK));
        assert!(state_dir.join("plugins/prometheus/index.mjs").is_file());
        assert!(state_dir.join("plugins/sdk/client.mjs").is_file());

        // 4. Unknown plugin name -> EXIT_USAGE (2)
        let bad_name = run_plugin(PluginCommand::Install {
            plugin: "discord".to_string(),
            state_dir: Some(state_dir.clone()),
            config: None,
            home: Some(tmp.path().to_path_buf()),
            url: None,
            archive: None,
            from_dir: None,
            json: true,
        });
        assert_eq!(bad_name, ExitCode::from(EXIT_USAGE));

        // 5. Conflicting source flags (--url + --from-dir) -> EXIT_USAGE (2)
        let conflicting = run_plugin(PluginCommand::Install {
            plugin: "telegram".to_string(),
            state_dir: Some(state_dir.clone()),
            config: None,
            home: Some(tmp.path().to_path_buf()),
            url: Some("https://example.com/plugins.tar.gz".to_string()),
            archive: None,
            from_dir: Some(repo_plugins_dir()),
            json: true,
        });
        assert_eq!(conflicting, ExitCode::from(EXIT_USAGE));

        // 6. List + Verify (both TTY and JSON) + permissions check + missing SDK fail-closed
        assert_eq!(
            run_plugin(PluginCommand::List {
                state_dir: Some(state_dir.clone()),
                config: None,
                home: Some(tmp.path().to_path_buf()),
                json: true,
            }),
            ExitCode::from(EXIT_OK)
        );
        assert_eq!(
            run_plugin(PluginCommand::List {
                state_dir: Some(state_dir.clone()),
                config: None,
                home: Some(tmp.path().to_path_buf()),
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
            assert_eq!(dir_mode, 0o700, "plugins dir must be 0700");
            assert_eq!(file_mode, 0o600, "installed plugin script must be 0600");
        }

        // Deleting sdk/client.mjs while prometheus is installed -> verify MUST fail closed!
        fs::remove_file(state_dir.join("plugins/sdk/client.mjs")).unwrap();
        assert_eq!(
            run_plugin(PluginCommand::Verify {
                state_dir: Some(state_dir),
                config: None,
                home: Some(tmp.path().to_path_buf()),
                json: true,
            }),
            ExitCode::from(EXIT_ERROR)
        );
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
            "install",
            "telegram",
            "--state-dir",
            "/tmp/s",
            "--json",
        ])
        .expect("parse `plugin install telegram --state-dir /tmp/s --json`");
        match parsed.cmd {
            PluginCommand::Install { plugin, json, .. } => {
                assert_eq!(plugin, "telegram");
                assert!(json);
            }
            _ => panic!("expected Install variant"),
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
}
