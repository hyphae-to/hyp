//! Zero-leak `SecretStore` supporting:
//! - Private user-only file backend (`HYPHAE_SECRET_BACKEND=file`, `0700` dir, atomic `0600` temp-file + rename)
//! - macOS Keychain (`/usr/bin/security -i` over stdin `-X <hex>`, zero secrets in argv, lossless `hyphae-b64v1:`)
//! - Linux Freedesktop Secret Service (`secret-tool` over stdin, zero secrets in argv)
//! - 1Password CLI (`HYPHAE_SECRET_BACKEND=1password`, `op` JSON over stdin, zero secrets in argv, lossless `hyphae-b64v1:`)
//! - LastPass CLI (`HYPHAE_SECRET_BACKEND=lastpass`, `lpass` over stdin with `LPASS_DISABLE_PINENTRY=1`, zero secrets in argv)
//! - Linux `pass` (`HYPHAE_SECRET_BACKEND=pass`, `pass insert -m -f` over stdin with non-interactive GPG opts, zero secrets in argv)
//!
//! Mirrors `src/secrets.ts` and `src/identity.ts` naming & safety invariants, including
//! automatic `File` backend selection for ephemeral temp directories so tests NEVER touch live OS keyrings.

mod backend;

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::CryptoError;
use crate::keys::{Ed25519KeyPair, NodeIdentityKeys, X25519KeyPair};

#[cfg(target_os = "macos")]
const MACOS_SECURITY_BIN: &str = "/usr/bin/security";
const KEYCHAIN_B64_PREFIX: &str = "hyphae-b64v1:";
const DEFAULT_OP_BIN: &str = "op";
const DEFAULT_OP_VAULT: &str = "Hyphae";
const DEFAULT_LPASS_BIN: &str = "lpass";
const DEFAULT_LPASS_PREFIX: &str = "hyphae";
const DEFAULT_PASS_BIN: &str = "pass";
const DEFAULT_PASS_PREFIX: &str = "hyphae";

/// Active secret storage backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretBackend {
    Keychain,
    SecretService,
    #[serde(rename = "1password")]
    OnePassword,
    #[serde(rename = "lastpass")]
    LastPass,
    #[serde(rename = "pass")]
    Pass,
    File,
}

impl SecretBackend {
    pub const fn as_str(self) -> &'static str {
        match self {
            SecretBackend::Keychain => "keychain",
            SecretBackend::SecretService => "secret-service",
            SecretBackend::OnePassword => "1password",
            SecretBackend::LastPass => "lastpass",
            SecretBackend::Pass => "pass",
            SecretBackend::File => "file",
        }
    }
}

/// Metadata returned when saving a secret (never includes secret contents).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedSecret {
    pub name: String,
    pub backend: SecretBackend,
    pub location: String,
}

/// Metadata returned when listing secrets (never reads or exposes secret contents).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretMetadata {
    pub name: String,
    pub backend: SecretBackend,
    pub location: String,
    pub mode_ok: bool,
    pub bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecretIndexEntry {
    backend: SecretBackend,
    #[serde(rename = "updatedAt")]
    updated_at: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecretIndexFile {
    version: u8,
    secrets: BTreeMap<String, SecretIndexEntry>,
}

impl Default for SecretIndexFile {
    fn default() -> Self {
        Self {
            version: 1,
            secrets: BTreeMap::new(),
        }
    }
}

/// Validates a Hyphae secret name: `/^[a-z0-9][a-z0-9._-]{0,63}$/` (path-traversal-proof).
pub fn validate_secret_name(name: &str) -> Result<(), CryptoError> {
    let b = name.as_bytes();
    if b.is_empty() || b.len() > 64 {
        return Err(CryptoError::InvalidSecretName(format!(
            "secret name '{name}' must be 1..=64 chars"
        )));
    }
    if !(b[0].is_ascii_lowercase() || b[0].is_ascii_digit()) {
        return Err(CryptoError::InvalidSecretName(format!(
            "secret name '{name}' must start with [a-z0-9]"
        )));
    }
    if !b
        .iter()
        .all(|&c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'.' | b'_' | b'-'))
    {
        return Err(CryptoError::InvalidSecretName(format!(
            "secret name '{name}' contains disallowed characters"
        )));
    }
    if name.contains("..") {
        return Err(CryptoError::InvalidSecretName(format!(
            "secret name '{name}' must not contain '..'"
        )));
    }
    Ok(())
}

/// Deterministic secret names for a v2 Node's identity keys (`node-sign-<hash12>`, `node-enc-<hash12>`),
/// alongside legacy v1 names (`id-sign-<hash12>`, `id-enc-<hash12>`).
pub fn node_key_secret_names(node_id: &str) -> (String, String) {
    let hash = hex::encode(Sha256::digest(node_id.as_bytes()));
    let short = &hash[..12];
    (format!("node-sign-{short}"), format!("node-enc-{short}"))
}

/// Legacy v1 connector key secret names (`id-sign-<hash12>`, `id-enc-<hash12>`).
pub fn legacy_connector_key_secret_names(connector_id: &str) -> (String, String) {
    let hash = hex::encode(Sha256::digest(connector_id.as_bytes()));
    let short = &hash[..12];
    (format!("id-sign-{short}"), format!("id-enc-{short}"))
}

fn is_valid_service_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn is_inside_temp_dir(config_dir: &Path) -> bool {
    let sys_tmp = std::env::temp_dir();
    let canon_tmp = fs::canonicalize(&sys_tmp).unwrap_or_else(|_| sys_tmp.clone());
    let abs = fs::canonicalize(config_dir).unwrap_or_else(|_| config_dir.to_path_buf());
    #[cfg(unix)]
    let candidates = [
        sys_tmp,
        canon_tmp,
        PathBuf::from("/tmp"),
        PathBuf::from("/private/tmp"),
        PathBuf::from("/var/folders"),
        PathBuf::from("/private/var/folders"),
    ];
    #[cfg(not(unix))]
    let candidates = [sys_tmp, canon_tmp];
    candidates
        .iter()
        .any(|base| abs.starts_with(base) || config_dir.starts_with(base))
}

/// Parses a `HYPHAE_SECRET_BACKEND` name into a [`SecretBackend`].
pub fn parse_backend(raw: &str) -> Option<SecretBackend> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "keychain" => Some(SecretBackend::Keychain),
        "secret-service" => Some(SecretBackend::SecretService),
        "1password" => Some(SecretBackend::OnePassword),
        "lastpass" => Some(SecretBackend::LastPass),
        "pass" => Some(SecretBackend::Pass),
        "file" => Some(SecretBackend::File),
        _ => None,
    }
}

/// Validates a 1Password vault name (`HYPHAE_1PASSWORD_VAULT`): non-empty, <= 128 bytes,
/// no control chars/newlines, and no leading `-` (prevents CLI flag injection).
pub fn validate_onepassword_vault(vault: &str) -> Result<(), CryptoError> {
    if vault.is_empty() || vault.trim().is_empty() {
        return Err(CryptoError::Keystore(
            "invalid 1Password vault name: cannot be empty".into(),
        ));
    }
    if vault.len() > 128 {
        return Err(CryptoError::Keystore(
            "invalid 1Password vault name: exceeds 128 bytes".into(),
        ));
    }
    if vault.starts_with('-') {
        return Err(CryptoError::Keystore(
            "invalid 1Password vault name: must not start with '-'".into(),
        ));
    }
    if vault.chars().any(char::is_control) {
        return Err(CryptoError::Keystore(
            "invalid 1Password vault name: contains disallowed control characters".into(),
        ));
    }
    if vault.trim() != vault {
        return Err(CryptoError::Keystore(
            "invalid 1Password vault name: must not have leading or trailing whitespace".into(),
        ));
    }
    Ok(())
}

/// Validates a LastPass entry prefix (`HYPHAE_LASTPASS_PREFIX`): non-empty, <= 128 bytes,
/// path-traversal-proof (rejects `..`, `.` segments, leading/trailing `/`, `//`, `\`,
/// control chars, and leading `-`).
pub fn validate_lastpass_prefix(prefix: &str) -> Result<(), CryptoError> {
    if prefix.is_empty() || prefix.trim().is_empty() {
        return Err(CryptoError::Keystore(
            "invalid LastPass prefix: cannot be empty".into(),
        ));
    }
    if prefix.len() > 128 {
        return Err(CryptoError::Keystore(
            "invalid LastPass prefix: exceeds 128 bytes".into(),
        ));
    }
    if prefix.trim() != prefix {
        return Err(CryptoError::Keystore(
            "invalid LastPass prefix: must not have leading or trailing whitespace".into(),
        ));
    }
    if prefix.starts_with('-') {
        return Err(CryptoError::Keystore(
            "invalid LastPass prefix: must not start with '-'".into(),
        ));
    }
    if prefix.starts_with('/') || prefix.ends_with('/') {
        return Err(CryptoError::Keystore(
            "invalid LastPass prefix: must not start or end with '/'".into(),
        ));
    }
    if prefix.contains('\\') || prefix.contains("..") {
        return Err(CryptoError::Keystore(
            "invalid LastPass prefix: path traversal characters ('..', '\\\\') are disallowed"
                .into(),
        ));
    }
    if prefix.chars().any(char::is_control) {
        return Err(CryptoError::Keystore(
            "invalid LastPass prefix: contains disallowed control characters".into(),
        ));
    }
    for seg in prefix.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." || seg.starts_with('.') {
            return Err(CryptoError::Keystore(
                "invalid LastPass prefix: contains invalid path segment".into(),
            ));
        }
    }
    Ok(())
}

/// Validates a Linux `pass` store prefix (`HYPHAE_PASS_PREFIX`): strictly path-traversal-proof
/// (`[A-Za-z0-9][A-Za-z0-9._-]*` segments separated by `/`, rejecting `..`, leading/trailing `/`,
/// hidden `.`-prefixed segments like `.git`/`.gpg-id`, backslashes, control chars, and leading `-`).
pub fn validate_pass_prefix(prefix: &str) -> Result<(), CryptoError> {
    if prefix.is_empty() || prefix.len() > 128 {
        return Err(CryptoError::Keystore(
            "invalid pass prefix: must be 1..=128 bytes".into(),
        ));
    }
    if prefix.starts_with('-') {
        return Err(CryptoError::Keystore(
            "invalid pass prefix: must not start with '-'".into(),
        ));
    }
    if prefix.starts_with('/') || prefix.ends_with('/') {
        return Err(CryptoError::Keystore(
            "invalid pass prefix: must not start or end with '/'".into(),
        ));
    }
    if prefix.contains('\\') || prefix.contains("..") {
        return Err(CryptoError::Keystore(
            "invalid pass prefix: path traversal characters ('..', '\\\\') are disallowed".into(),
        ));
    }
    if prefix.chars().any(char::is_control) {
        return Err(CryptoError::Keystore(
            "invalid pass prefix: contains disallowed control characters".into(),
        ));
    }
    for seg in prefix.split('/') {
        let b = seg.as_bytes();
        if b.is_empty() || !(b[0].is_ascii_alphanumeric()) {
            return Err(CryptoError::Keystore(
                "invalid pass prefix: each path segment must start with [A-Za-z0-9]".into(),
            ));
        }
        if !b
            .iter()
            .all(|&c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
        {
            return Err(CryptoError::Keystore(
                "invalid pass prefix: contains disallowed characters".into(),
            ));
        }
    }
    Ok(())
}

fn validate_cli_bin_path(bin: &Path, label: &str) -> Result<(), CryptoError> {
    let raw = bin.to_string_lossy();
    if raw.trim().is_empty() {
        return Err(CryptoError::Keystore(format!(
            "invalid {label} CLI path: cannot be empty"
        )));
    }
    if raw.chars().any(char::is_control) {
        return Err(CryptoError::Keystore(format!(
            "invalid {label} CLI path: contains disallowed control characters"
        )));
    }
    Ok(())
}

/// Pure backend resolution helper matching `detectSecretBackend` in `src/secrets.ts`.
pub fn detect_backend_with(config_dir: &Path, explicit_override: Option<&str>) -> SecretBackend {
    if let Some(raw) = explicit_override {
        if let Some(backend) = parse_backend(raw) {
            return backend;
        }
    }
    if is_inside_temp_dir(config_dir) {
        return SecretBackend::File;
    }
    #[cfg(target_os = "macos")]
    {
        if Path::new(MACOS_SECURITY_BIN).exists() {
            return SecretBackend::Keychain;
        }
    }
    #[cfg(target_os = "linux")]
    {
        if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some() {
            return SecretBackend::SecretService;
        }
    }
    SecretBackend::File
}

/// Always encodes a secret payload losslessly with the `hyphae-b64v1:` prefix so arbitrary
/// multiline, binary-safe UTF-8, quotes, and special characters survive external password managers.
pub fn encode_lossless_payload(value: &str) -> Zeroizing<String> {
    Zeroizing::new(format!(
        "{KEYCHAIN_B64_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(value.as_bytes())
    ))
}

/// Lossless ASCII encoding for macOS Keychain `-X` matching `src/secrets.ts:138-147`.
pub fn encode_keychain_payload(value: &str) -> Zeroizing<String> {
    let needs_b64 = value.starts_with(KEYCHAIN_B64_PREFIX)
        || value.bytes().any(|b| !(0x20..=0x7e).contains(&b));
    if needs_b64 {
        encode_lossless_payload(value)
    } else {
        Zeroizing::new(value.to_string())
    }
}

/// Decodes a macOS Keychain value written by `encode_keychain_payload` or `src/secrets.ts`.
pub fn decode_keychain_payload(raw: &str) -> Result<Zeroizing<String>, CryptoError> {
    if let Some(encoded) = raw.strip_prefix(KEYCHAIN_B64_PREFIX) {
        let bytes = Zeroizing::new(
            URL_SAFE_NO_PAD
                .decode(encoded)
                .map_err(|e| CryptoError::Keystore(format!("corrupt keychain payload: {e}")))?,
        );
        let s = String::from_utf8(bytes.to_vec())
            .map_err(|e| CryptoError::Keystore(format!("non-UTF8 keychain payload: {e}")))?;
        Ok(Zeroizing::new(s))
    } else {
        Ok(Zeroizing::new(raw.to_string()))
    }
}

/// Formats the `/usr/bin/security -i` stdin command line (zero secrets in argv!).
pub fn format_security_add_stdin(
    service: &str,
    name: &str,
    value: &str,
) -> Result<Zeroizing<String>, CryptoError> {
    validate_secret_name(name)?;
    if !is_valid_service_name(service) {
        return Err(CryptoError::Keystore(format!(
            "invalid keychain service name '{service}'"
        )));
    }
    let payload = encode_keychain_payload(value);
    let hex_val = Zeroizing::new(hex::encode(payload.as_bytes()));
    Ok(Zeroizing::new(format!(
        "add-generic-password -U -s {service} -a {name} -X {}\n",
        &*hex_val
    )))
}

#[cfg(unix)]
fn current_euid() -> u32 {
    unsafe extern "C" {
        fn geteuid() -> u32;
    }
    // SAFETY: POSIX `geteuid()` is always safe to call and has no preconditions.
    unsafe { geteuid() }
}

#[cfg(unix)]
fn check_private_path(
    path: &Path,
    expect_dir: bool,
    private_mode: bool,
) -> Result<u64, CryptoError> {
    use std::os::unix::fs::MetadataExt;
    let st = fs::symlink_metadata(path)?;
    if st.file_type().is_symlink() {
        return Err(CryptoError::Keystore(format!(
            "refusing symlink at {}",
            path.display()
        )));
    }
    if expect_dir && !st.is_dir() {
        return Err(CryptoError::Keystore(format!(
            "expected directory at {}",
            path.display()
        )));
    }
    if !expect_dir && !st.is_file() {
        return Err(CryptoError::Keystore(format!(
            "expected regular file at {}",
            path.display()
        )));
    }
    if st.uid() != current_euid() {
        return Err(CryptoError::Keystore(format!(
            "{} is not owned by current user",
            path.display()
        )));
    }
    if private_mode && (st.mode() & 0o077) != 0 {
        return Err(CryptoError::Keystore(format!(
            "{} has overly broad permissions ({:o}); expected 0600/0700",
            path.display(),
            st.mode() & 0o777
        )));
    }
    Ok(st.size())
}

#[cfg(not(unix))]
fn check_private_path(
    path: &Path,
    expect_dir: bool,
    _private_mode: bool,
) -> Result<u64, CryptoError> {
    let st = fs::symlink_metadata(path)?;
    if st.file_type().is_symlink() {
        return Err(CryptoError::Keystore(format!(
            "refusing symlink at {}",
            path.display()
        )));
    }
    if expect_dir && !st.is_dir() {
        return Err(CryptoError::Keystore(format!(
            "expected directory at {}",
            path.display()
        )));
    }
    if !expect_dir && !st.is_file() {
        return Err(CryptoError::Keystore(format!(
            "expected regular file at {}",
            path.display()
        )));
    }
    Ok(st.len())
}

fn check_private_owner_and_mode(path: &Path, expect_dir: bool) -> Result<u64, CryptoError> {
    check_private_path(path, expect_dir, true)
}

#[cfg(unix)]
fn open_private_directory(dir: &Path) -> Result<fs::File, CryptoError> {
    use std::os::unix::fs::OpenOptionsExt;
    let normalized: PathBuf = dir.components().collect();
    Ok(OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(normalized)?)
}

#[cfg(unix)]
fn tighten_private_directory(directory: &fs::File, path: &Path) -> Result<(), CryptoError> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = directory.metadata()?;
    if !metadata.is_dir() || metadata.uid() != current_euid() {
        return Err(CryptoError::Keystore(format!(
            "{} is not a directory owned by current user",
            path.display()
        )));
    }
    directory.set_permissions(fs::Permissions::from_mode(0o700))?;
    let metadata = directory.metadata()?;
    if metadata.mode() & 0o077 != 0 {
        return Err(CryptoError::Keystore(format!(
            "{} has overly broad permissions after chmod",
            path.display()
        )));
    }
    let normalized: PathBuf = path.components().collect();
    let visible = fs::symlink_metadata(&normalized)?;
    if visible.file_type().is_symlink()
        || visible.dev() != metadata.dev()
        || visible.ino() != metadata.ino()
    {
        return Err(CryptoError::Keystore(format!(
            "{} was replaced while setting directory permissions",
            path.display()
        )));
    }
    Ok(())
}

/// Creates or tightens a user-owned real directory to mode 0700, rejecting links before chmod.
pub fn ensure_private_dir(dir: &Path) -> Result<(), CryptoError> {
    // A trailing separator or `/.` must not turn a leaf symlink into a followed directory.
    let normalized: PathBuf = dir.components().collect();
    let dir = normalized.as_path();
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }
    let _ = check_private_path(dir, true, false)?;
    #[cfg(unix)]
    tighten_private_directory(&open_private_directory(dir)?, dir)?;
    #[cfg(not(unix))]
    let _ = check_private_owner_and_mode(dir, true)?;
    Ok(())
}

/// Atomically writes `contents` to `dest` inside `dir` using a fresh `0600` temp file + `sync_all` + `rename`.
fn atomic_write_private_file(dir: &Path, dest: &Path, contents: &[u8]) -> Result<(), CryptoError> {
    ensure_private_dir(dir)?;
    let rng = SystemRandom::new();
    let mut suffix = [0u8; 8];
    rng.fill(&mut suffix)
        .map_err(|_| CryptoError::Keystore("OS CSPRNG failure".into()))?;
    let tmp_name = format!(".tmp-{}", hex::encode(suffix));
    let tmp_path = dir.join(tmp_name);

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }

    let write_res: Result<(), CryptoError> = (|| {
        let mut f = opts.open(&tmp_path)?;
        f.write_all(contents)?;
        f.sync_all()?;
        drop(f);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))?;
        }
        fs::rename(&tmp_path, dest)?;
        Ok(())
    })();

    if write_res.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    write_res
}

/// Hyphae v2 `SecretStore` managing private keys & API secrets across OS keyrings,
/// external password managers (`1password`, `lastpass`, `pass`), and `0600` local files.
#[derive(Debug, Clone)]
pub struct SecretStore {
    config_dir: PathBuf,
    backend: SecretBackend,
    service: String,
    op_bin: Option<PathBuf>,
    op_vault: Option<String>,
    lpass_bin: Option<PathBuf>,
    lpass_prefix: Option<String>,
    pass_bin: Option<PathBuf>,
    pass_prefix: Option<String>,
    password_store_dir: Option<PathBuf>,
    gnupg_home: Option<PathBuf>,
}

impl SecretStore {
    /// Creates a `SecretStore` with an explicit backend (recommended in tests with `SecretBackend::File`).
    pub fn new(config_dir: impl Into<PathBuf>, backend: SecretBackend) -> Self {
        Self {
            config_dir: config_dir.into(),
            backend,
            service: "hyphae".to_string(),
            op_bin: None,
            op_vault: None,
            lpass_bin: None,
            lpass_prefix: None,
            pass_bin: None,
            pass_prefix: None,
            password_store_dir: None,
            gnupg_home: None,
        }
    }

    /// Creates a `SecretStore` pinned to the private local file backend (portable across Unix & Windows).
    pub fn file_only(config_dir: impl Into<PathBuf>) -> Self {
        Self::new(config_dir, SecretBackend::File)
    }

    /// Creates a `SecretStore` resolving backend from `HYPHAE_SECRET_BACKEND`, temp-dir safety guard,
    /// and OS platform defaults.
    pub fn from_env(config_dir: impl Into<PathBuf>) -> Self {
        let config_dir = config_dir.into();
        let override_val = std::env::var("HYPHAE_SECRET_BACKEND").ok();
        let backend = detect_backend_with(&config_dir, override_val.as_deref());
        let service = std::env::var("HYPHAE_KEYCHAIN_SERVICE")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| is_valid_service_name(s))
            .unwrap_or_else(|| "hyphae".to_string());
        let non_empty_env = |key: &str| std::env::var(key).ok().filter(|v| !v.is_empty());
        Self {
            config_dir,
            backend,
            service,
            op_bin: non_empty_env("HYPHAE_OP_BIN").map(PathBuf::from),
            op_vault: non_empty_env("HYPHAE_1PASSWORD_VAULT"),
            lpass_bin: non_empty_env("HYPHAE_LPASS_BIN").map(PathBuf::from),
            lpass_prefix: non_empty_env("HYPHAE_LASTPASS_PREFIX"),
            pass_bin: non_empty_env("HYPHAE_PASS_BIN").map(PathBuf::from),
            pass_prefix: non_empty_env("HYPHAE_PASS_PREFIX"),
            password_store_dir: non_empty_env("PASSWORD_STORE_DIR").map(PathBuf::from),
            gnupg_home: non_empty_env("GNUPGHOME").map(PathBuf::from),
        }
    }

    /// Overrides the 1Password CLI binary path (alternative to `HYPHAE_OP_BIN`, ideal for isolated tests).
    pub fn with_op_bin(mut self, bin: impl Into<PathBuf>) -> Self {
        self.op_bin = Some(bin.into());
        self
    }

    /// Overrides the 1Password vault name (alternative to `HYPHAE_1PASSWORD_VAULT`).
    pub fn with_op_vault(mut self, vault: impl Into<String>) -> Self {
        self.op_vault = Some(vault.into());
        self
    }

    /// Overrides the LastPass CLI binary path (alternative to `HYPHAE_LPASS_BIN`, ideal for isolated tests).
    pub fn with_lpass_bin(mut self, bin: impl Into<PathBuf>) -> Self {
        self.lpass_bin = Some(bin.into());
        self
    }

    /// Overrides the LastPass entry prefix (alternative to `HYPHAE_LASTPASS_PREFIX`).
    pub fn with_lpass_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.lpass_prefix = Some(prefix.into());
        self
    }

    /// Overrides the `pass` CLI binary path (alternative to `HYPHAE_PASS_BIN`, ideal for isolated tests).
    pub fn with_pass_bin(mut self, bin: impl Into<PathBuf>) -> Self {
        self.pass_bin = Some(bin.into());
        self
    }

    /// Overrides the `pass` entry prefix (alternative to `HYPHAE_PASS_PREFIX`).
    pub fn with_pass_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.pass_prefix = Some(prefix.into());
        self
    }

    /// Overrides `PASSWORD_STORE_DIR` for the `pass` backend.
    pub fn with_password_store_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.password_store_dir = Some(dir.into());
        self
    }

    /// Overrides `GNUPGHOME` for the `pass` backend.
    pub fn with_gnupg_home(mut self, dir: impl Into<PathBuf>) -> Self {
        self.gnupg_home = Some(dir.into());
        self
    }

    /// Resolves and validates the 1Password CLI executable path (`HYPHAE_OP_BIN` or `"op"`).
    pub fn resolved_op_bin(&self) -> Result<PathBuf, CryptoError> {
        let bin = match self.op_bin {
            Some(ref p) => p.clone(),
            None => std::env::var("HYPHAE_OP_BIN")
                .ok()
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_OP_BIN)),
        };
        validate_cli_bin_path(&bin, "1Password")?;
        Ok(bin)
    }

    /// Resolves and validates the 1Password vault name (`HYPHAE_1PASSWORD_VAULT` or `"Hyphae"`).
    pub fn resolved_op_vault(&self) -> Result<String, CryptoError> {
        let vault = match self.op_vault {
            Some(ref v) => v.clone(),
            None => std::env::var("HYPHAE_1PASSWORD_VAULT")
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| DEFAULT_OP_VAULT.to_string()),
        };
        validate_onepassword_vault(&vault)?;
        Ok(vault)
    }

    /// Resolves and validates the LastPass CLI executable path (`HYPHAE_LPASS_BIN` or `"lpass"`).
    pub fn resolved_lpass_bin(&self) -> Result<PathBuf, CryptoError> {
        let bin = match self.lpass_bin {
            Some(ref p) => p.clone(),
            None => std::env::var("HYPHAE_LPASS_BIN")
                .ok()
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_LPASS_BIN)),
        };
        validate_cli_bin_path(&bin, "LastPass")?;
        Ok(bin)
    }

    /// Resolves and validates the LastPass entry prefix (`HYPHAE_LASTPASS_PREFIX` or `"hyphae"`).
    pub fn resolved_lpass_prefix(&self) -> Result<String, CryptoError> {
        let prefix = match self.lpass_prefix {
            Some(ref p) => p.clone(),
            None => std::env::var("HYPHAE_LASTPASS_PREFIX")
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| DEFAULT_LPASS_PREFIX.to_string()),
        };
        validate_lastpass_prefix(&prefix)?;
        Ok(prefix)
    }

    /// Resolves and validates the `pass` CLI executable path (`HYPHAE_PASS_BIN` or `"pass"`).
    pub fn resolved_pass_bin(&self) -> Result<PathBuf, CryptoError> {
        let bin = match self.pass_bin {
            Some(ref p) => p.clone(),
            None => std::env::var("HYPHAE_PASS_BIN")
                .ok()
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(DEFAULT_PASS_BIN)),
        };
        validate_cli_bin_path(&bin, "pass")?;
        Ok(bin)
    }

    /// Resolves and validates the `pass` prefix (`HYPHAE_PASS_PREFIX` or `"hyphae"`).
    pub fn resolved_pass_prefix(&self) -> Result<String, CryptoError> {
        let prefix = match self.pass_prefix {
            Some(ref p) => p.clone(),
            None => std::env::var("HYPHAE_PASS_PREFIX")
                .ok()
                .filter(|v| !v.is_empty())
                .unwrap_or_else(|| DEFAULT_PASS_PREFIX.to_string()),
        };
        validate_pass_prefix(&prefix)?;
        Ok(prefix)
    }

    /// Resolves `PASSWORD_STORE_DIR` (or `~/.password-store`) for metadata-only `pass` listing.
    pub fn resolved_password_store_dir(&self) -> Option<PathBuf> {
        if let Some(ref dir) = self.password_store_dir {
            return Some(dir.clone());
        }
        if let Ok(env_dir) = std::env::var("PASSWORD_STORE_DIR") {
            let trimmed = env_dir.trim();
            if !trimmed.is_empty() {
                return Some(PathBuf::from(trimmed));
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            let trimmed = home.trim();
            if !trimmed.is_empty() {
                return Some(PathBuf::from(trimmed).join(".password-store"));
            }
        }
        if let Ok(profile) = std::env::var("USERPROFILE") {
            let trimmed = profile.trim();
            if !trimmed.is_empty() {
                return Some(PathBuf::from(trimmed).join(".password-store"));
            }
        }
        None
    }

    pub fn backend(&self) -> SecretBackend {
        self.backend
    }

    pub fn config_dir(&self) -> &Path {
        &self.config_dir
    }

    pub fn secrets_dir(&self) -> PathBuf {
        self.config_dir.join("secrets")
    }

    pub fn secret_file_path(&self, name: &str) -> Result<PathBuf, CryptoError> {
        validate_secret_name(name)?;
        Ok(self.secrets_dir().join(format!("{name}.secret")))
    }

    fn index_path(&self) -> PathBuf {
        self.secrets_dir().join("index.json")
    }

    fn read_index(&self) -> SecretIndexFile {
        let path = self.index_path();
        let Ok(raw) = fs::read_to_string(path) else {
            return SecretIndexFile::default();
        };
        serde_json::from_str(&raw).unwrap_or_default()
    }

    fn read_index_strict(&self) -> Result<SecretIndexFile, CryptoError> {
        let path = self.index_path();
        if !path.exists() {
            return Ok(SecretIndexFile::default());
        }
        let _ = check_private_owner_and_mode(&path, false)?;
        let raw = fs::read_to_string(&path)?;
        serde_json::from_str(&raw)
            .map_err(|e| CryptoError::Keystore(format!("failed to parse {}: {e}", path.display())))
    }

    fn write_index(&self, index: &SecretIndexFile) -> Result<(), CryptoError> {
        let mut json = serde_json::to_string_pretty(index)?;
        json.push('\n');
        atomic_write_private_file(&self.secrets_dir(), &self.index_path(), json.as_bytes())
    }

    /// Stores a secret value in the configured backend (atomic `0600` file, macOS Keychain via stdin,
    /// Linux Secret Service via stdin, 1Password `op` via stdin JSON, LastPass `lpass` via stdin,
    /// or Linux `pass` via stdin).
    pub fn set(&self, name: &str, value: &str) -> Result<SavedSecret, CryptoError> {
        validate_secret_name(name)?;
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(CryptoError::Keystore(format!(
                "secret '{name}' cannot be empty"
            )));
        }

        let (location, recorded_service) =
            backend::for_kind(self.backend).write(self, name, trimmed)?;

        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let mut index = self.read_index();
        index.secrets.insert(
            name.to_string(),
            SecretIndexEntry {
                backend: self.backend,
                updated_at: now_ms,
                service: recorded_service,
            },
        );
        self.write_index(&index)?;

        Ok(SavedSecret {
            name: name.to_string(),
            backend: self.backend,
            location,
        })
    }

    /// Reads a secret into a `Zeroizing<String>`.
    pub fn get(&self, name: &str) -> Result<Zeroizing<String>, CryptoError> {
        validate_secret_name(name)?;
        let index = self.read_index();
        let entry = index.secrets.get(name);
        let backend = entry.map(|e| e.backend).unwrap_or(self.backend);
        backend::for_kind(backend).read(
            self,
            name,
            entry.and_then(|entry| entry.service.as_deref()),
        )
    }

    /// Deletes a secret from the configured backend and index. Returns `true` if anything was removed.
    pub fn delete(&self, name: &str) -> Result<bool, CryptoError> {
        validate_secret_name(name)?;
        let mut index = self.read_index();
        let entry = index.secrets.get(name).cloned();
        let mut removed = false;

        if let Some(e) = &entry {
            removed |= backend::for_kind(e.backend).delete(self, name, e.service.as_deref())?;
        }

        let file_path = self.secret_file_path(name)?;
        if file_path.exists() {
            fs::remove_file(&file_path)?;
            removed = true;
        }

        if entry.is_some() {
            index.secrets.remove(name);
            self.write_index(&index)?;
            removed = true;
        } else if !removed {
            removed = backend::for_kind(self.backend).delete(self, name, None)?;
        }
        Ok(removed)
    }

    /// Lists secret metadata without ever reading or returning secret contents.
    pub fn list(&self) -> Result<Vec<SecretMetadata>, CryptoError> {
        let mut by_name: BTreeMap<String, SecretMetadata> = BTreeMap::new();
        let index = self.read_index();
        for (name, entry) in &index.secrets {
            if validate_secret_name(name).is_err() {
                continue;
            }
            if let Some(metadata) = backend::for_kind(entry.backend).indexed_metadata(
                self,
                name,
                entry.service.as_deref(),
            )? {
                by_name.insert(name.clone(), metadata);
            }
        }

        let dir = self.secrets_dir();
        if dir.is_dir() {
            for ent in fs::read_dir(&dir)? {
                let ent = ent?;
                let fname = ent.file_name();
                let Some(s) = fname.to_str() else { continue };
                let Some(name) = s.strip_suffix(".secret") else {
                    continue;
                };
                if validate_secret_name(name).is_err() || by_name.contains_key(name) {
                    continue;
                }
                let path = ent.path();
                let (mode_ok, bytes) = match check_private_owner_and_mode(&path, false) {
                    Ok(sz) => (true, Some(sz)),
                    Err(_) => (false, fs::symlink_metadata(&path).ok().map(|m| m.len())),
                };
                by_name.insert(
                    name.to_string(),
                    SecretMetadata {
                        name: name.to_string(),
                        backend: SecretBackend::File,
                        location: path.display().to_string(),
                        mode_ok,
                        bytes,
                    },
                );
            }
        }

        backend::for_kind(self.backend).discover(self, &mut by_name)?;

        Ok(by_name.into_values().collect())
    }

    /// Loads or creates a Node's persistent Ed25519 + X25519 identity keypair.
    /// Transparently reads legacy v1 `id-sign-<hash12>` / `id-enc-<hash12>` keys if present so
    /// upgraded machines keep their cryptographic fingerprints.
    ///
    /// Security invariant (`D10`): ONLY generates fresh keys when BOTH keys are genuinely absent
    /// (`CryptoError::SecretNotFound`) AND neither is recorded in `secrets/index.json` (and no
    /// sibling key exists). Backend errors (locked Keychain, D-Bus unavailable, permission errors,
    /// corrupt key/index) ALWAYS fail closed without silently regenerating a brand-new identity.
    pub fn load_or_create_node_keys(&self, node_id: &str) -> Result<NodeIdentityKeys, CryptoError> {
        let (v2_sign, v2_enc) = node_key_secret_names(node_id);
        let (v1_sign, v1_enc) = legacy_connector_key_secret_names(node_id);
        let index = self.read_index_strict()?;

        let existing_signing: Option<Ed25519KeyPair> = match self.get(&v2_sign) {
            Ok(b64) => Some(Ed25519KeyPair::from_pkcs8_b64(&b64)?),
            Err(CryptoError::SecretNotFound(_)) => {
                if index.secrets.contains_key(&v2_sign) {
                    return Err(CryptoError::Keystore(format!(
                        "node signing key '{v2_sign}' is recorded in secrets/index.json but missing from keystore; refusing to silently regenerate identity for '{node_id}'"
                    )));
                }
                match self.get(&v1_sign) {
                    Ok(b64) => Some(Ed25519KeyPair::from_pkcs8_b64(&b64)?),
                    Err(CryptoError::SecretNotFound(_)) => {
                        if index.secrets.contains_key(&v1_sign) {
                            return Err(CryptoError::Keystore(format!(
                                "legacy node signing key '{v1_sign}' is recorded in secrets/index.json but missing from keystore; refusing to silently regenerate identity for '{node_id}'"
                            )));
                        }
                        None
                    }
                    Err(e) => return Err(e),
                }
            }
            Err(e) => return Err(e),
        };

        let existing_encryption: Option<X25519KeyPair> = match self.get(&v2_enc) {
            Ok(b64) => Some(X25519KeyPair::from_pkcs8_b64(&b64)?),
            Err(CryptoError::SecretNotFound(_)) => {
                if index.secrets.contains_key(&v2_enc) {
                    return Err(CryptoError::Keystore(format!(
                        "node encryption key '{v2_enc}' is recorded in secrets/index.json but missing from keystore; refusing to silently regenerate identity for '{node_id}'"
                    )));
                }
                match self.get(&v1_enc) {
                    Ok(b64) => Some(X25519KeyPair::from_pkcs8_b64(&b64)?),
                    Err(CryptoError::SecretNotFound(_)) => {
                        if index.secrets.contains_key(&v1_enc) {
                            return Err(CryptoError::Keystore(format!(
                                "legacy node encryption key '{v1_enc}' is recorded in secrets/index.json but missing from keystore; refusing to silently regenerate identity for '{node_id}'"
                            )));
                        }
                        None
                    }
                    Err(e) => return Err(e),
                }
            }
            Err(e) => return Err(e),
        };

        match (existing_signing, existing_encryption) {
            (Some(signing), Some(encryption)) => Ok(NodeIdentityKeys {
                signing,
                encryption,
            }),
            (Some(_), None) => Err(CryptoError::Keystore(format!(
                "node encryption key '{v2_enc}' is missing while signing key exists for '{node_id}'; refusing to silently regenerate partial node identity"
            ))),
            (None, Some(_)) => Err(CryptoError::Keystore(format!(
                "node signing key '{v2_sign}' is missing while encryption key exists for '{node_id}'; refusing to silently regenerate partial node identity"
            ))),
            (None, None) => {
                let signing = Ed25519KeyPair::generate()?;
                let encryption = X25519KeyPair::generate()?;
                let sign_exported = signing.export_pkcs8_b64();
                let enc_exported = encryption.export_pkcs8_b64();
                self.set(&v2_sign, &sign_exported)?;
                self.set(&v2_enc, &enc_exported)?;
                Ok(NodeIdentityKeys {
                    signing,
                    encryption,
                })
            }
        }
    }

    // ---- File backend ----

    fn write_file_secret(&self, name: &str, value: &str) -> Result<String, CryptoError> {
        let dir = self.secrets_dir();
        let path = self.secret_file_path(name)?;
        let content = Zeroizing::new(format!("{value}\n"));
        atomic_write_private_file(&dir, &path, content.as_bytes())?;
        Ok(path.display().to_string())
    }

    fn read_file_secret(&self, name: &str) -> Result<Zeroizing<String>, CryptoError> {
        let dir = self.secrets_dir();
        if !dir.exists() {
            return Err(CryptoError::SecretNotFound(name.to_string()));
        }
        let _ = check_private_owner_and_mode(&dir, true)?;

        let path = self.secret_file_path(name)?;
        let canon_dir = fs::canonicalize(&dir)?;
        if !path.exists() {
            return Err(CryptoError::SecretNotFound(name.to_string()));
        }
        let _ = check_private_owner_and_mode(&path, false)?;
        let canon_file = fs::canonicalize(&path)?;
        if !canon_file.starts_with(&canon_dir) {
            return Err(CryptoError::Keystore(
                "secret path escapes secrets directory".into(),
            ));
        }

        let raw = Zeroizing::new(fs::read_to_string(&path)?);
        let trimmed = raw.trim().to_string();
        if trimmed.is_empty() {
            return Err(CryptoError::Keystore(format!("secret '{name}' is empty")));
        }
        Ok(Zeroizing::new(trimmed))
    }

    // ---- macOS Keychain backend (`/usr/bin/security -i` via stdin, zero secrets in argv) ----

    #[cfg(target_os = "macos")]
    fn write_mac_keychain(&self, name: &str, value: &str) -> Result<String, CryptoError> {
        let cmd_line = format_security_add_stdin(&self.service, name, value)?;
        let mut child = Command::new(MACOS_SECURITY_BIN)
            .arg("-i")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| CryptoError::Keystore(format!("failed to spawn security: {e}")))?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(cmd_line.as_bytes())?;
        }
        let output = child.wait_with_output()?;
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if !output.status.success()
            || stderr.contains("security:")
            || stderr.contains("SecKeychain")
            || stderr.to_ascii_lowercase().contains("error:")
        {
            return Err(CryptoError::Keystore(if stderr.is_empty() {
                format!(
                    "macOS Keychain write failed (exit {:?})",
                    output.status.code()
                )
            } else {
                stderr
            }));
        }
        Ok(format!("keychain:{}/{name}", self.service))
    }

    #[cfg(not(target_os = "macos"))]
    fn write_mac_keychain(&self, _name: &str, _value: &str) -> Result<String, CryptoError> {
        Err(CryptoError::Keystore(
            "macOS Keychain backend is only supported on macOS".into(),
        ))
    }

    #[cfg(target_os = "macos")]
    fn read_mac_keychain(
        &self,
        name: &str,
        service: &str,
    ) -> Result<Option<Zeroizing<String>>, CryptoError> {
        if !is_valid_service_name(service) {
            return Err(CryptoError::Keystore(
                "invalid keychain service name".into(),
            ));
        }
        let output = Command::new(MACOS_SECURITY_BIN)
            .args(["find-generic-password", "-s", service, "-a", name, "-w"])
            .stdin(Stdio::null())
            .output()
            .map_err(|e| CryptoError::Keystore(format!("failed to run security: {e}")))?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        classify_mac_keychain_output(name, output.status.code(), &output.stdout, &stderr)
    }

    #[cfg(not(target_os = "macos"))]
    fn read_mac_keychain(
        &self,
        _name: &str,
        _service: &str,
    ) -> Result<Option<Zeroizing<String>>, CryptoError> {
        Err(CryptoError::Keystore(
            "macOS Keychain backend is only supported on macOS".into(),
        ))
    }

    #[cfg(target_os = "macos")]
    fn delete_mac_keychain(&self, name: &str, service: &str) -> bool {
        if !is_valid_service_name(service) {
            return false;
        }
        Command::new(MACOS_SECURITY_BIN)
            .args(["delete-generic-password", "-s", service, "-a", name])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[cfg(not(target_os = "macos"))]
    fn delete_mac_keychain(&self, _name: &str, _service: &str) -> bool {
        false
    }

    // ---- Linux Secret Service backend (`secret-tool`, secret over stdin) ----

    #[cfg(target_os = "linux")]
    fn write_linux_secret_service(&self, name: &str, value: &str) -> Result<String, CryptoError> {
        let mut child = Command::new("secret-tool")
            .args([
                "store",
                &format!("--label=Hyphae: {name}"),
                "service",
                &self.service,
                "account",
                name,
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| CryptoError::Keystore(format!("failed to spawn secret-tool: {e}")))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(value.as_bytes())?;
        }
        let output = child.wait_with_output()?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            return Err(CryptoError::Keystore(if stderr.is_empty() {
                format!("secret-tool store failed (exit {:?})", output.status.code())
            } else {
                stderr
            }));
        }
        Ok(format!("secret-service:{}/{name}", self.service))
    }

    #[cfg(not(target_os = "linux"))]
    fn write_linux_secret_service(&self, _name: &str, _value: &str) -> Result<String, CryptoError> {
        Err(CryptoError::Keystore(
            "Linux Secret Service backend is only supported on Linux".into(),
        ))
    }

    #[cfg(target_os = "linux")]
    fn read_linux_secret_service(
        &self,
        name: &str,
        service: &str,
    ) -> Result<Option<Zeroizing<String>>, CryptoError> {
        let output = Command::new("secret-tool")
            .args(["lookup", "service", service, "account", name])
            .stdin(Stdio::null())
            .output()
            .map_err(|e| CryptoError::Keystore(format!("failed to run secret-tool: {e}")))?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        classify_linux_secret_service_output(name, output.status.code(), &output.stdout, &stderr)
    }

    #[cfg(not(target_os = "linux"))]
    fn read_linux_secret_service(
        &self,
        _name: &str,
        _service: &str,
    ) -> Result<Option<Zeroizing<String>>, CryptoError> {
        Err(CryptoError::Keystore(
            "Linux Secret Service backend is only supported on Linux".into(),
        ))
    }

    #[cfg(target_os = "linux")]
    fn delete_linux_secret_service(&self, name: &str, service: &str) -> bool {
        Command::new("secret-tool")
            .args(["clear", "service", service, "account", name])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    #[cfg(not(target_os = "linux"))]
    fn delete_linux_secret_service(&self, _name: &str, _service: &str) -> bool {
        false
    }

    // ---- 1Password CLI backend (`op`, stdin JSON template, zero secrets in argv) ----

    fn write_onepassword(
        &self,
        name: &str,
        value: &str,
        vault: &str,
    ) -> Result<String, CryptoError> {
        validate_secret_name(name)?;
        validate_onepassword_vault(vault)?;
        let bin = self.resolved_op_bin()?;
        let title = format!("hyphae/{name}");
        let encoded = encode_lossless_payload(value);

        // Check whether the item already exists (zero secrets in argv, closed stdin).
        let probe = Command::new(&bin)
            .args(["item", "get", &title, "--vault", vault, "--format", "json"])
            .stdin(Stdio::null())
            .output()
            .map_err(|e| map_cli_spawn_error("1Password", &bin, "op", e))?;

        let probe_stderr = String::from_utf8_lossy(&probe.stderr);
        if probe.status.success() {
            let (target_ref, edit_json) =
                build_onepassword_edit_json(&probe.stdout, &title, &encoded);
            let mut child = Command::new(&bin)
                .args([
                    "item",
                    "edit",
                    &target_ref,
                    "--vault",
                    vault,
                    "--format",
                    "json",
                ])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| map_cli_spawn_error("1Password", &bin, "op", e))?;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(edit_json.as_bytes())?;
            }
            let output = child.wait_with_output()?;
            if !output.status.success() {
                let raw_err = String::from_utf8_lossy(&output.stderr);
                let safe_err = redact_backend_stderr(&raw_err, value, &encoded);
                return Err(CryptoError::Keystore(format_onepassword_error(
                    "write",
                    name,
                    output.status.code(),
                    &safe_err,
                )));
            }
        } else {
            let probe_lower = probe_stderr.to_ascii_lowercase();
            if !is_onepassword_item_not_found(&probe_lower) {
                let safe_err = redact_backend_stderr(&probe_stderr, value, &encoded);
                return Err(CryptoError::Keystore(format_onepassword_error(
                    "write",
                    name,
                    probe.status.code(),
                    &safe_err,
                )));
            }
            let create_json = build_onepassword_create_json(&title, &encoded);
            let mut child = Command::new(&bin)
                .args(["item", "create", "--vault", vault, "--format", "json", "-"])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| map_cli_spawn_error("1Password", &bin, "op", e))?;
            if let Some(mut stdin) = child.stdin.take() {
                stdin.write_all(create_json.as_bytes())?;
            }
            let output = child.wait_with_output()?;
            if !output.status.success() {
                let raw_err = String::from_utf8_lossy(&output.stderr);
                let safe_err = redact_backend_stderr(&raw_err, value, &encoded);
                return Err(CryptoError::Keystore(format_onepassword_error(
                    "write",
                    name,
                    output.status.code(),
                    &safe_err,
                )));
            }
        }

        Ok(format!("1password:{vault}/{title}"))
    }

    fn read_onepassword(
        &self,
        name: &str,
        vault: &str,
    ) -> Result<Option<Zeroizing<String>>, CryptoError> {
        validate_secret_name(name)?;
        validate_onepassword_vault(vault)?;
        let bin = self.resolved_op_bin()?;
        let title = format!("hyphae/{name}");
        let output = Command::new(&bin)
            .args([
                "item", "get", &title, "--vault", vault, "--format", "json", "--reveal",
            ])
            .stdin(Stdio::null())
            .output()
            .map_err(|e| map_cli_spawn_error("1Password", &bin, "op", e))?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        classify_onepassword_get_output(name, output.status.code(), &output.stdout, &stderr)
    }

    fn delete_onepassword(&self, name: &str, vault: &str) -> Result<bool, CryptoError> {
        validate_secret_name(name)?;
        validate_onepassword_vault(vault)?;
        let bin = self.resolved_op_bin()?;
        let title = format!("hyphae/{name}");
        let output = Command::new(&bin)
            .args(["item", "delete", &title, "--vault", vault])
            .stdin(Stdio::null())
            .output()
            .map_err(|e| map_cli_spawn_error("1Password", &bin, "op", e))?;
        if output.status.success() {
            return Ok(true);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let lower = stderr.to_ascii_lowercase();
        if is_onepassword_item_not_found(&lower) {
            return Ok(false);
        }
        Err(CryptoError::Keystore(format_onepassword_error(
            "delete",
            name,
            output.status.code(),
            stderr.trim(),
        )))
    }

    fn list_onepassword(&self, vault: &str) -> Result<Vec<String>, CryptoError> {
        validate_onepassword_vault(vault)?;
        let bin = self.resolved_op_bin()?;
        let output = Command::new(&bin)
            .args(["item", "list", "--vault", vault, "--format", "json"])
            .stdin(Stdio::null())
            .output()
            .map_err(|e| map_cli_spawn_error("1Password", &bin, "op", e))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(CryptoError::Keystore(format_onepassword_error(
                "list",
                vault,
                output.status.code(),
                stderr.trim(),
            )));
        }
        parse_onepassword_list_json(&output.stdout)
    }

    // ---- LastPass CLI backend (`lpass`, stdin notes, LPASS_DISABLE_PINENTRY=1, zero secrets in argv) ----

    fn ensure_lastpass_authenticated(&self, bin: &Path) -> Result<(), CryptoError> {
        let output = Command::new(bin)
            .args(["status", "-q"])
            .env("LPASS_DISABLE_PINENTRY", "1")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| map_cli_spawn_error("LastPass", bin, "lpass", e))?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        Err(CryptoError::Keystore(if stderr.is_empty() {
            format!(
                "LastPass CLI is locked or unauthenticated (exit {:?}); run `lpass login <email>` or set HYPHAE_SECRET_BACKEND=file",
                output.status.code()
            )
        } else {
            format!(
                "LastPass CLI is locked or unauthenticated (exit {:?}): {stderr}; run `lpass login <email>` or set HYPHAE_SECRET_BACKEND=file",
                output.status.code()
            )
        }))
    }

    fn write_lastpass(&self, name: &str, value: &str, prefix: &str) -> Result<String, CryptoError> {
        validate_secret_name(name)?;
        validate_lastpass_prefix(prefix)?;
        let bin = self.resolved_lpass_bin()?;
        self.ensure_lastpass_authenticated(&bin)?;

        let entry = format!("{prefix}/{name}");
        let encoded = encode_lossless_payload(value);
        let stdin_payload = Zeroizing::new(format!("{}\n", &*encoded));

        // Try in-place edit first so overwrites never create duplicate LastPass entries.
        let mut edit_child = Command::new(&bin)
            .args(["edit", "--non-interactive", "--notes", &entry])
            .env("LPASS_DISABLE_PINENTRY", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| map_cli_spawn_error("LastPass", &bin, "lpass", e))?;
        if let Some(mut stdin) = edit_child.stdin.take() {
            stdin.write_all(stdin_payload.as_bytes())?;
        }
        let edit_out = edit_child.wait_with_output()?;
        if !edit_out.status.success() {
            let edit_err = String::from_utf8_lossy(&edit_out.stderr);
            if !is_lastpass_not_found(&edit_err.to_ascii_lowercase()) {
                let safe_err = redact_backend_stderr(&edit_err, value, &encoded);
                return Err(CryptoError::Keystore(format_lastpass_error(
                    "write",
                    name,
                    edit_out.status.code(),
                    &safe_err,
                )));
            }

            let mut add_child = Command::new(&bin)
                .args(["add", "--non-interactive", "--notes", &entry])
                .env("LPASS_DISABLE_PINENTRY", "1")
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .map_err(|e| map_cli_spawn_error("LastPass", &bin, "lpass", e))?;
            if let Some(mut stdin) = add_child.stdin.take() {
                stdin.write_all(stdin_payload.as_bytes())?;
            }
            let add_out = add_child.wait_with_output()?;
            if !add_out.status.success() {
                let add_err = String::from_utf8_lossy(&add_out.stderr);
                let safe_err = redact_backend_stderr(&add_err, value, &encoded);
                return Err(CryptoError::Keystore(format_lastpass_error(
                    "write",
                    name,
                    add_out.status.code(),
                    &safe_err,
                )));
            }
        }

        Ok(format!("lastpass:{entry}"))
    }

    fn read_lastpass(
        &self,
        name: &str,
        prefix: &str,
    ) -> Result<Option<Zeroizing<String>>, CryptoError> {
        validate_secret_name(name)?;
        validate_lastpass_prefix(prefix)?;
        let bin = self.resolved_lpass_bin()?;
        self.ensure_lastpass_authenticated(&bin)?;

        let entry = format!("{prefix}/{name}");
        let output = Command::new(&bin)
            .args(["show", "--notes", &entry])
            .env("LPASS_DISABLE_PINENTRY", "1")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| map_cli_spawn_error("LastPass", &bin, "lpass", e))?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        classify_lastpass_show_output(name, output.status.code(), &output.stdout, &stderr)
    }

    fn delete_lastpass(&self, name: &str, prefix: &str) -> Result<bool, CryptoError> {
        validate_secret_name(name)?;
        validate_lastpass_prefix(prefix)?;
        let bin = self.resolved_lpass_bin()?;
        self.ensure_lastpass_authenticated(&bin)?;

        let entry = format!("{prefix}/{name}");
        let output = Command::new(&bin)
            .args(["rm", &entry])
            .env("LPASS_DISABLE_PINENTRY", "1")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| map_cli_spawn_error("LastPass", &bin, "lpass", e))?;
        if output.status.success() {
            return Ok(true);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if is_lastpass_not_found(&stderr.to_ascii_lowercase()) {
            return Ok(false);
        }
        Err(CryptoError::Keystore(format_lastpass_error(
            "delete",
            name,
            output.status.code(),
            stderr.trim(),
        )))
    }

    fn list_lastpass(&self, prefix: &str) -> Result<Vec<String>, CryptoError> {
        validate_lastpass_prefix(prefix)?;
        let bin = self.resolved_lpass_bin()?;
        self.ensure_lastpass_authenticated(&bin)?;

        let output = Command::new(&bin)
            .args(["ls", prefix])
            .env("LPASS_DISABLE_PINENTRY", "1")
            .stdin(Stdio::null())
            .output()
            .map_err(|e| map_cli_spawn_error("LastPass", &bin, "lpass", e))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let lower = stderr.to_ascii_lowercase();
            let stdout_empty = output.stdout.iter().all(|b| b.is_ascii_whitespace());
            if stdout_empty && (is_lastpass_not_found(&lower) || stderr.trim().is_empty()) {
                return Ok(Vec::new());
            }
            return Err(CryptoError::Keystore(format_lastpass_error(
                "list",
                prefix,
                output.status.code(),
                stderr.trim(),
            )));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(parse_lastpass_ls_output(prefix, &stdout))
    }

    // ---- Linux `pass` backend (`password-store`, stdin insert, non-interactive GPG, zero secrets in argv) ----

    fn configure_pass_command(&self, cmd: &mut Command) {
        if let Some(ref dir) = self.password_store_dir {
            cmd.env("PASSWORD_STORE_DIR", dir);
        }
        if let Some(ref gnupg) = self.gnupg_home {
            cmd.env("GNUPGHOME", gnupg);
        }
        // Fail closed cleanly if gpg-agent is locked instead of hanging a headless daemon on pinentry.
        let existing_opts = std::env::var("PASSWORD_STORE_GPG_OPTS").unwrap_or_default();
        let mut opts = existing_opts.trim().to_string();
        for required in ["--batch", "--no-tty"] {
            if !opts.split_whitespace().any(|tok| tok == required) {
                if !opts.is_empty() {
                    opts.push(' ');
                }
                opts.push_str(required);
            }
        }
        cmd.env("PASSWORD_STORE_GPG_OPTS", opts);
        if std::env::var_os("PINENTRY_USER_DATA").is_none() {
            cmd.env("PINENTRY_USER_DATA", "hyphae-noninteractive");
        }
        cmd.env_remove("GPG_TTY");
    }

    fn write_pass(&self, name: &str, value: &str, prefix: &str) -> Result<String, CryptoError> {
        validate_secret_name(name)?;
        validate_pass_prefix(prefix)?;
        let bin = self.resolved_pass_bin()?;
        let entry = format!("{prefix}/{name}");
        let encoded = encode_lossless_payload(value);
        let stdin_payload = Zeroizing::new(format!("{}\n", &*encoded));

        let mut cmd = Command::new(&bin);
        cmd.args(["insert", "-m", "-f", &entry])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        self.configure_pass_command(&mut cmd);

        let mut child = cmd
            .spawn()
            .map_err(|e| map_cli_spawn_error("pass", &bin, "pass", e))?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(stdin_payload.as_bytes())?;
        }
        let output = child.wait_with_output()?;
        if !output.status.success() {
            let raw_err = String::from_utf8_lossy(&output.stderr);
            let safe_err = redact_backend_stderr(&raw_err, value, &encoded);
            return Err(CryptoError::Keystore(format_pass_error(
                "write",
                name,
                output.status.code(),
                &safe_err,
            )));
        }

        Ok(format!("pass:{entry}"))
    }

    fn read_pass(
        &self,
        name: &str,
        prefix: &str,
    ) -> Result<Option<Zeroizing<String>>, CryptoError> {
        validate_secret_name(name)?;
        validate_pass_prefix(prefix)?;
        let bin = self.resolved_pass_bin()?;
        let entry = format!("{prefix}/{name}");

        let mut cmd = Command::new(&bin);
        cmd.args(["show", &entry]).stdin(Stdio::null());
        self.configure_pass_command(&mut cmd);

        let output = cmd
            .output()
            .map_err(|e| map_cli_spawn_error("pass", &bin, "pass", e))?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        classify_pass_show_output(name, output.status.code(), &output.stdout, &stderr)
    }

    fn delete_pass(&self, name: &str, prefix: &str) -> Result<bool, CryptoError> {
        validate_secret_name(name)?;
        validate_pass_prefix(prefix)?;
        let bin = self.resolved_pass_bin()?;
        let entry = format!("{prefix}/{name}");

        let mut cmd = Command::new(&bin);
        cmd.args(["rm", "-f", &entry]).stdin(Stdio::null());
        self.configure_pass_command(&mut cmd);

        let output = cmd
            .output()
            .map_err(|e| map_cli_spawn_error("pass", &bin, "pass", e))?;
        if output.status.success() {
            return Ok(true);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if is_pass_not_found(&stderr.to_ascii_lowercase()) {
            return Ok(false);
        }
        Err(CryptoError::Keystore(format_pass_error(
            "delete",
            name,
            output.status.code(),
            stderr.trim(),
        )))
    }

    /// Scans `<PASSWORD_STORE_DIR>/<prefix>/*.gpg` metadata on disk without invoking `pass show` or GPG.
    fn list_pass_metadata(&self, prefix: &str) -> Result<Vec<String>, CryptoError> {
        validate_pass_prefix(prefix)?;
        let Some(store_dir) = self.resolved_password_store_dir() else {
            return Ok(Vec::new());
        };
        if !store_dir.is_dir() {
            return Ok(Vec::new());
        }
        let target_dir = store_dir.join(prefix);
        if !target_dir.exists() {
            return Ok(Vec::new());
        }
        let st = fs::symlink_metadata(&target_dir)?;
        if st.file_type().is_symlink() || !st.is_dir() {
            return Err(CryptoError::Keystore(format!(
                "refusing non-directory or symlink pass prefix path at {}",
                target_dir.display()
            )));
        }
        let canon_store = fs::canonicalize(&store_dir)?;
        let canon_target = fs::canonicalize(&target_dir)?;
        if !canon_target.starts_with(&canon_store) {
            return Err(CryptoError::Keystore(
                "pass prefix path escapes PASSWORD_STORE_DIR".into(),
            ));
        }

        let mut names = Vec::new();
        for ent in fs::read_dir(&canon_target)? {
            let ent = ent?;
            let path = ent.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                continue;
            };
            if meta.file_type().is_symlink() || !meta.is_file() {
                continue;
            }
            let fname = ent.file_name();
            let Some(s) = fname.to_str() else { continue };
            let Some(name) = s.strip_suffix(".gpg") else {
                continue;
            };
            if validate_secret_name(name).is_ok() {
                names.push(name.to_string());
            }
        }
        names.sort();
        names.dedup();
        Ok(names)
    }
}

/// Classifies the exit status, stdout, and stderr of macOS `/usr/bin/security find-generic-password`.
///
/// Only genuine `errSecItemNotFound` (exit code `44` or explicit not-found stderr without
/// interaction/lock/auth errors) maps to `Ok(None)`. Locked keychains (`errSecInteractionNotAllowed`,
/// exit `36`), denied access, or any other non-zero exit fail closed with `Err(CryptoError::Keystore)`.
pub fn classify_mac_keychain_output(
    name: &str,
    exit_code: Option<i32>,
    stdout: &[u8],
    stderr: &str,
) -> Result<Option<Zeroizing<String>>, CryptoError> {
    if exit_code != Some(0) {
        let stderr_trimmed = stderr.trim();
        let lower = stderr_trimmed.to_ascii_lowercase();
        let is_backend_denied = lower.contains("interaction is not allowed")
            || lower.contains("errsecinteractionnotallowed")
            || lower.contains("locked")
            || lower.contains("authfailed")
            || lower.contains("denied");
        let is_not_found = !is_backend_denied
            && (exit_code == Some(44)
                || stderr_trimmed.contains("errSecItemNotFound")
                || lower.contains("could not be found in the keychain"));
        if is_not_found {
            return Ok(None);
        }
        return Err(CryptoError::Keystore(if stderr_trimmed.is_empty() {
            format!(
                "macOS Keychain read failed for '{name}' (exit {exit_code:?}); unlock your login Keychain or set HYPHAE_SECRET_BACKEND=file"
            )
        } else {
            format!(
                "macOS Keychain read failed for '{name}' (exit {exit_code:?}): {stderr_trimmed}"
            )
        }));
    }

    let raw = Zeroizing::new(
        String::from_utf8(stdout.to_vec())
            .map_err(|e| CryptoError::Keystore(format!("non-UTF8 keychain output: {e}")))?,
    );
    let stripped = raw.trim_end_matches(['\r', '\n']);
    if stripped.is_empty() {
        return Err(CryptoError::Keystore(format!(
            "macOS Keychain secret '{name}' is empty"
        )));
    }
    let decoded = decode_keychain_payload(stripped)?;
    let trimmed = decoded.trim().to_string();
    if trimmed.is_empty() {
        Err(CryptoError::Keystore(format!(
            "macOS Keychain secret '{name}' is empty"
        )))
    } else {
        Ok(Some(Zeroizing::new(trimmed)))
    }
}

/// Classifies the exit status, stdout, and stderr of Linux `secret-tool lookup`.
///
/// On Linux, `secret-tool lookup` legitimately exits with status `1` and empty stderr (and empty
/// stdout) when the requested item does not exist in GNOME Keyring / KWallet (`OR1`). That case,
/// empty stdout with exit `0`, or exit `1` with explicit item-not-found stderr (without D-Bus,
/// lock, auth, or permission errors) maps to `Ok(None)` (`CryptoError::SecretNotFound`).
/// Any D-Bus error, locked keyring, permission/auth failure, non-empty unexpected stderr, or exit
/// code other than `0`/`1` fails closed with `Err(CryptoError::Keystore)`.
pub fn classify_linux_secret_service_output(
    name: &str,
    exit_code: Option<i32>,
    stdout: &[u8],
    stderr: &str,
) -> Result<Option<Zeroizing<String>>, CryptoError> {
    if exit_code != Some(0) {
        let stderr_trimmed = stderr.trim();
        let stdout_empty = stdout.iter().all(|b| b.is_ascii_whitespace());
        if exit_code == Some(1) {
            if stderr_trimmed.is_empty() && stdout_empty {
                return Ok(None);
            }
            let lower = stderr_trimmed.to_ascii_lowercase();
            let is_backend_err = lower.contains("dbus")
                || lower.contains("d-bus")
                || lower.contains("cannot autolaunch")
                || lower.contains("locked")
                || lower.contains("permission")
                || lower.contains("denied")
                || lower.contains("auth failed")
                || lower.contains("authentication")
                || lower.contains("unavailable")
                || lower.contains("org.freedesktop.secrets");
            let is_explicit_not_found = !is_backend_err
                && stdout_empty
                && (lower.contains("no matching")
                    || lower.contains("not found")
                    || lower.contains("no such item")
                    || lower.contains("no such secret"));
            if is_explicit_not_found {
                return Ok(None);
            }
        }
        return Err(CryptoError::Keystore(if stderr_trimmed.is_empty() {
            format!(
                "Linux Secret Service read failed for '{name}' (exit {exit_code:?}); ensure a Secret Service daemon is unlocked or set HYPHAE_SECRET_BACKEND=file"
            )
        } else {
            format!(
                "Linux Secret Service read failed for '{name}' (exit {exit_code:?}): {stderr_trimmed}"
            )
        }));
    }

    let raw = Zeroizing::new(
        String::from_utf8(stdout.to_vec())
            .map_err(|e| CryptoError::Keystore(format!("non-UTF8 secret-tool output: {e}")))?,
    );
    let trimmed = raw.trim().to_string();
    if trimmed.is_empty() {
        Ok(None)
    } else {
        Ok(Some(Zeroizing::new(trimmed)))
    }
}

fn map_cli_spawn_error(
    label: &str,
    bin: &Path,
    default_cmd: &str,
    err: std::io::Error,
) -> CryptoError {
    if err.kind() == std::io::ErrorKind::NotFound {
        CryptoError::Keystore(format!(
            "{label} CLI ('{}') not found; install `{default_cmd}`, set the binary override env var, or switch to HYPHAE_SECRET_BACKEND=file",
            bin.display()
        ))
    } else {
        CryptoError::Keystore(format!(
            "failed to spawn {label} CLI ('{}'): {err}",
            bin.display()
        ))
    }
}

/// Scrubs secret bytes (both lossless `hyphae-b64v1:` encoding and raw value) from child stderr
/// before returning an error message, preventing accidental secret leaks.
fn redact_backend_stderr(stderr: &str, raw_value: &str, encoded_value: &str) -> String {
    let mut out = stderr.trim().to_string();
    if !encoded_value.is_empty() && out.contains(encoded_value) {
        out = out.replace(encoded_value, "[REDACTED]");
    }
    if raw_value.len() >= 4 && out.contains(raw_value) {
        out = out.replace(raw_value, "[REDACTED]");
    }
    if out.len() > 512 {
        let mut end = 512;
        while end > 0 && !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
        out.push_str("...");
    }
    out
}

fn build_onepassword_create_json(title: &str, encoded_payload: &str) -> Zeroizing<String> {
    let doc = serde_json::json!({
        "title": title,
        "category": "SECURE_NOTE",
        "tags": ["hyphae"],
        "fields": [
            {
                "id": "notesPlain",
                "type": "STRING",
                "purpose": "NOTES",
                "label": "notesPlain",
                "value": encoded_payload,
            }
        ]
    });
    Zeroizing::new(doc.to_string())
}

fn build_onepassword_edit_json(
    existing_stdout: &[u8],
    title: &str,
    encoded_payload: &str,
) -> (String, Zeroizing<String>) {
    let mut target_ref = title.to_string();
    if let Ok(mut doc) = serde_json::from_slice::<serde_json::Value>(existing_stdout) {
        if let Some(obj) = doc.as_object_mut() {
            if let Some(id) = obj
                .get("id")
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|s| {
                    !s.is_empty() && !s.starts_with('-') && !s.chars().any(char::is_control)
                })
            {
                target_ref = id.to_string();
            }
            obj.insert(
                "title".to_string(),
                serde_json::Value::String(title.to_string()),
            );
            let fields = obj
                .entry("fields".to_string())
                .or_insert_with(|| serde_json::Value::Array(Vec::new()));
            if let Some(arr) = fields.as_array_mut() {
                let mut updated = false;
                for field in arr.iter_mut() {
                    let is_notes = field.get("id").and_then(serde_json::Value::as_str)
                        == Some("notesPlain")
                        || field.get("label").and_then(serde_json::Value::as_str)
                            == Some("notesPlain")
                        || field.get("purpose").and_then(serde_json::Value::as_str)
                            == Some("NOTES");
                    if is_notes {
                        if let Some(fobj) = field.as_object_mut() {
                            fobj.insert(
                                "value".to_string(),
                                serde_json::Value::String(encoded_payload.to_string()),
                            );
                            updated = true;
                            break;
                        }
                    }
                }
                if !updated {
                    arr.push(serde_json::json!({
                        "id": "notesPlain",
                        "type": "STRING",
                        "purpose": "NOTES",
                        "label": "notesPlain",
                        "value": encoded_payload,
                    }));
                }
                return (target_ref, Zeroizing::new(doc.to_string()));
            }
        }
    }
    (
        target_ref,
        build_onepassword_create_json(title, encoded_payload),
    )
}

fn is_onepassword_auth_or_vault_error(stderr_lower: &str) -> bool {
    stderr_lower.contains("not currently signed in")
        || stderr_lower.contains("not signed in")
        || stderr_lower.contains("signin")
        || stderr_lower.contains("sign in")
        || stderr_lower.contains("session expired")
        || stderr_lower.contains("session")
        || stderr_lower.contains("unauthorized")
        || stderr_lower.contains("authentication")
        || stderr_lower.contains("auth failed")
        || stderr_lower.contains("locked")
        || stderr_lower.contains("unlock")
        || stderr_lower.contains("biometric")
        || stderr_lower.contains("service account")
        || stderr_lower.contains("op_service_account_token")
        || stderr_lower.contains("permission")
        || stderr_lower.contains("denied")
        || stderr_lower.contains("forbidden")
        || stderr_lower.contains("isn't a vault")
        || stderr_lower.contains("vault not found")
        || stderr_lower.contains("no vault")
        || stderr_lower.contains("more than one item")
        || stderr_lower.contains("multiple items")
        || stderr_lower.contains("connect")
        || stderr_lower.contains("timeout")
        || stderr_lower.contains("timed out")
}

fn is_onepassword_item_not_found(stderr_lower: &str) -> bool {
    !is_onepassword_auth_or_vault_error(stderr_lower)
        && (stderr_lower.contains("isn't an item")
            || stderr_lower.contains("no item found")
            || stderr_lower.contains("item not found")
            || (stderr_lower.contains("not found") && !stderr_lower.contains("vault")))
}

fn format_onepassword_error(
    op_action: &str,
    target: &str,
    exit_code: Option<i32>,
    stderr: &str,
) -> String {
    let hint = "sign in with `op signin` or configure OP_SERVICE_ACCOUNT_TOKEN (or set HYPHAE_SECRET_BACKEND=file)";
    if stderr.is_empty() {
        format!("1Password {op_action} failed for '{target}' (exit {exit_code:?}); {hint}")
    } else {
        format!(
            "1Password {op_action} failed for '{target}' (exit {exit_code:?}): {stderr}; {hint}"
        )
    }
}

/// Classifies the exit status, stdout, and stderr of `op item get`.
///
/// Only genuine item-not-found (without auth/lock/vault/session errors) maps to `Ok(None)`.
/// Accepts full `op` item JSON (`fields[].value`), single-field JSON (`{"value": ...}`),
/// or raw field text, and decodes `hyphae-b64v1:` payloads losslessly.
pub fn classify_onepassword_get_output(
    name: &str,
    exit_code: Option<i32>,
    stdout: &[u8],
    stderr: &str,
) -> Result<Option<Zeroizing<String>>, CryptoError> {
    if exit_code != Some(0) {
        let stderr_trimmed = stderr.trim();
        let lower = stderr_trimmed.to_ascii_lowercase();
        let stdout_empty = stdout.iter().all(|b| b.is_ascii_whitespace());
        if stdout_empty && is_onepassword_item_not_found(&lower) {
            return Ok(None);
        }
        return Err(CryptoError::Keystore(format_onepassword_error(
            "read",
            name,
            exit_code,
            stderr_trimmed,
        )));
    }

    let raw_text = Zeroizing::new(
        String::from_utf8(stdout.to_vec())
            .map_err(|e| CryptoError::Keystore(format!("non-UTF8 1Password output: {e}")))?,
    );
    let trimmed_outer = raw_text.trim();
    if trimmed_outer.is_empty() {
        return Err(CryptoError::Keystore(format!(
            "1Password secret '{name}' is empty"
        )));
    }

    let extracted: Zeroizing<String> = if trimmed_outer.starts_with('{') {
        let parsed: serde_json::Value = serde_json::from_str(trimmed_outer).map_err(|e| {
            CryptoError::Keystore(format!("invalid 1Password JSON for '{name}': {e}"))
        })?;
        let val = parsed
            .get("fields")
            .and_then(serde_json::Value::as_array)
            .and_then(|fields| {
                fields.iter().find_map(|f| {
                    let is_notes = f.get("id").and_then(serde_json::Value::as_str)
                        == Some("notesPlain")
                        || f.get("label").and_then(serde_json::Value::as_str) == Some("notesPlain")
                        || f.get("purpose").and_then(serde_json::Value::as_str) == Some("NOTES");
                    if is_notes {
                        f.get("value").and_then(serde_json::Value::as_str)
                    } else {
                        None
                    }
                })
            })
            .or_else(|| parsed.get("value").and_then(serde_json::Value::as_str))
            .ok_or_else(|| {
                CryptoError::Keystore(format!(
                    "1Password item for '{name}' is missing notesPlain value"
                ))
            })?;
        Zeroizing::new(val.to_string())
    } else {
        Zeroizing::new(raw_text.trim_end_matches(['\r', '\n']).to_string())
    };

    if extracted.is_empty() {
        return Err(CryptoError::Keystore(format!(
            "1Password secret '{name}' is empty"
        )));
    }
    let decoded = decode_keychain_payload(&extracted)?;
    let final_val = decoded.trim().to_string();
    if final_val.is_empty() {
        Err(CryptoError::Keystore(format!(
            "1Password secret '{name}' is empty"
        )))
    } else {
        Ok(Some(Zeroizing::new(final_val)))
    }
}

/// Parses `op item list --vault <vault> --format json` metadata into Hyphae secret names
/// (`hyphae/<name>` -> `<name>`), never inspecting or returning secret values.
pub fn parse_onepassword_list_json(raw: &[u8]) -> Result<Vec<String>, CryptoError> {
    let trimmed = std::str::from_utf8(raw)
        .map_err(|e| CryptoError::Keystore(format!("non-UTF8 1Password list output: {e}")))?
        .trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    let items: serde_json::Value = serde_json::from_str(trimmed)
        .map_err(|e| CryptoError::Keystore(format!("invalid 1Password item list JSON: {e}")))?;
    let Some(arr) = items.as_array() else {
        return Err(CryptoError::Keystore(
            "unexpected 1Password item list JSON (expected array)".into(),
        ));
    };
    let mut names = Vec::new();
    for item in arr {
        let Some(title) = item.get("title").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let Some(name) = title.strip_prefix("hyphae/") else {
            continue;
        };
        if validate_secret_name(name).is_ok() {
            names.push(name.to_string());
        }
    }
    names.sort();
    names.dedup();
    Ok(names)
}

fn is_lastpass_auth_or_backend_error(stderr_lower: &str) -> bool {
    stderr_lower.contains("not logged in")
        || stderr_lower.contains("logged out")
        || stderr_lower.contains("login")
        || stderr_lower.contains("pinentry")
        || stderr_lower.contains("locked")
        || stderr_lower.contains("unlock")
        || stderr_lower.contains("decryption")
        || stderr_lower.contains("decrypt")
        || stderr_lower.contains("permission")
        || stderr_lower.contains("denied")
        || stderr_lower.contains("unauthorized")
        || stderr_lower.contains("authentication")
        || stderr_lower.contains("network")
        || stderr_lower.contains("could not connect")
        || stderr_lower.contains("curl")
        || stderr_lower.contains("timeout")
        || stderr_lower.contains("multiple matches")
}

fn is_lastpass_not_found(stderr_lower: &str) -> bool {
    !is_lastpass_auth_or_backend_error(stderr_lower)
        && (stderr_lower.contains("could not find")
            || stderr_lower.contains("not found")
            || stderr_lower.contains("no such")
            || stderr_lower.contains("unable to find"))
}

fn format_lastpass_error(
    op_action: &str,
    target: &str,
    exit_code: Option<i32>,
    stderr: &str,
) -> String {
    let hint = "run `lpass login <email>` (or set HYPHAE_SECRET_BACKEND=file)";
    if stderr.is_empty() {
        format!("LastPass {op_action} failed for '{target}' (exit {exit_code:?}); {hint}")
    } else {
        format!("LastPass {op_action} failed for '{target}' (exit {exit_code:?}): {stderr}; {hint}")
    }
}

/// Classifies the exit status, stdout, and stderr of `lpass show --notes`.
pub fn classify_lastpass_show_output(
    name: &str,
    exit_code: Option<i32>,
    stdout: &[u8],
    stderr: &str,
) -> Result<Option<Zeroizing<String>>, CryptoError> {
    if exit_code != Some(0) {
        let stderr_trimmed = stderr.trim();
        let lower = stderr_trimmed.to_ascii_lowercase();
        let stdout_empty = stdout.iter().all(|b| b.is_ascii_whitespace());
        if stdout_empty && is_lastpass_not_found(&lower) {
            return Ok(None);
        }
        return Err(CryptoError::Keystore(format_lastpass_error(
            "read",
            name,
            exit_code,
            stderr_trimmed,
        )));
    }

    let raw = Zeroizing::new(
        String::from_utf8(stdout.to_vec())
            .map_err(|e| CryptoError::Keystore(format!("non-UTF8 LastPass output: {e}")))?,
    );
    let stripped = raw.trim_end_matches(['\r', '\n']);
    if stripped.is_empty() {
        return Err(CryptoError::Keystore(format!(
            "LastPass secret '{name}' is empty"
        )));
    }
    let decoded = decode_keychain_payload(stripped)?;
    let trimmed = decoded.trim().to_string();
    if trimmed.is_empty() {
        Err(CryptoError::Keystore(format!(
            "LastPass secret '{name}' is empty"
        )))
    } else {
        Ok(Some(Zeroizing::new(trimmed)))
    }
}

/// Parses `lpass ls <prefix>` metadata lines into validated Hyphae secret names without reading values.
pub fn parse_lastpass_ls_output(prefix: &str, stdout: &str) -> Vec<String> {
    let needle = format!("{prefix}/");
    let mut names = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let without_id = trimmed
            .rsplit_once(" [id:")
            .map(|(head, _)| head.trim())
            .unwrap_or(trimmed);
        let candidate = if let Some(rest) = without_id.strip_prefix(&needle) {
            rest
        } else if let Some((_, rest)) = without_id.split_once(&format!(" {needle}")) {
            rest
        } else {
            continue;
        };
        let clean = candidate.trim();
        if validate_secret_name(clean).is_ok() {
            names.push(clean.to_string());
        }
    }
    names.sort();
    names.dedup();
    names
}

fn is_pass_gpg_or_backend_error(stderr_lower: &str) -> bool {
    stderr_lower.contains("gpg:")
        || stderr_lower.contains("gpg2:")
        || stderr_lower.contains("decryption")
        || stderr_lower.contains("decrypt")
        || stderr_lower.contains("no secret key")
        || stderr_lower.contains("secret key not available")
        || stderr_lower.contains("pinentry")
        || stderr_lower.contains("passphrase")
        || stderr_lower.contains("gpg-agent")
        || stderr_lower.contains("agent")
        || stderr_lower.contains("locked")
        || stderr_lower.contains("operation cancelled")
        || stderr_lower.contains("inappropriate ioctl")
        || stderr_lower.contains("permission denied")
        || stderr_lower.contains("denied")
        || stderr_lower.contains("pass init")
        || stderr_lower.contains("password store is empty")
}

fn is_pass_not_found(stderr_lower: &str) -> bool {
    !is_pass_gpg_or_backend_error(stderr_lower)
        && (stderr_lower.contains("is not in the password store")
            || stderr_lower.contains("not found"))
}

fn format_pass_error(
    op_action: &str,
    target: &str,
    exit_code: Option<i32>,
    stderr: &str,
) -> String {
    let hint =
        "unlock gpg-agent and ensure `pass init` has been run (or set HYPHAE_SECRET_BACKEND=file)";
    if stderr.is_empty() {
        format!("pass {op_action} failed for '{target}' (exit {exit_code:?}); {hint}")
    } else {
        format!("pass {op_action} failed for '{target}' (exit {exit_code:?}): {stderr}; {hint}")
    }
}

/// Classifies the exit status, stdout, and stderr of `pass show`.
pub fn classify_pass_show_output(
    name: &str,
    exit_code: Option<i32>,
    stdout: &[u8],
    stderr: &str,
) -> Result<Option<Zeroizing<String>>, CryptoError> {
    if exit_code != Some(0) {
        let stderr_trimmed = stderr.trim();
        let lower = stderr_trimmed.to_ascii_lowercase();
        let stdout_empty = stdout.iter().all(|b| b.is_ascii_whitespace());
        if stdout_empty && is_pass_not_found(&lower) {
            return Ok(None);
        }
        return Err(CryptoError::Keystore(format_pass_error(
            "read",
            name,
            exit_code,
            stderr_trimmed,
        )));
    }

    let raw = Zeroizing::new(
        String::from_utf8(stdout.to_vec())
            .map_err(|e| CryptoError::Keystore(format!("non-UTF8 pass output: {e}")))?,
    );
    let stripped = raw.trim_end_matches(['\r', '\n']);
    if stripped.is_empty() {
        return Err(CryptoError::Keystore(format!(
            "pass secret '{name}' is empty"
        )));
    }
    let decoded = decode_keychain_payload(stripped)?;
    let trimmed = decoded.trim().to_string();
    if trimmed.is_empty() {
        Err(CryptoError::Keystore(format!(
            "pass secret '{name}' is empty"
        )))
    } else {
        Ok(Some(Zeroizing::new(trimmed)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[cfg(unix)]
    #[test]
    fn private_directory_rejects_symlink_without_changing_target_permissions() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temp = TempDir::new().unwrap();
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o755)).unwrap();
        let link = temp.path().join("link");
        symlink(&target, &link).unwrap();
        for spelling in [&link, &link.join(""), &link.join(".")] {
            let error = ensure_private_dir(spelling).unwrap_err();
            assert!(
                matches!(error, CryptoError::Keystore(ref reason) if reason.contains("symlink"))
            );
            assert!(open_private_directory(spelling).is_err());
        }
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        ensure_private_dir(&target).unwrap();
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[cfg(unix)]
    #[test]
    fn private_directory_permissions_stay_on_opened_inode_after_path_swap() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let temp = TempDir::new().unwrap();
        let path = temp.path().join("directory");
        let moved = temp.path().join("moved");
        let target = temp.path().join("unrelated-target");
        for directory in [&path, &target] {
            fs::create_dir(directory).unwrap();
            fs::set_permissions(directory, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let opened = open_private_directory(&path).unwrap();
        fs::rename(&path, &moved).unwrap();
        symlink(&target, &path).unwrap();
        assert!(open_private_directory(&path).is_err());
        let error = tighten_private_directory(&opened, &path).unwrap_err();
        assert!(matches!(error, CryptoError::Keystore(ref reason) if reason.contains("replaced")));
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o755
        );
        assert_eq!(
            fs::metadata(&moved).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn secret_name_validation_blocks_path_traversal() {
        for ok in [
            "github-token",
            "identity.ed25519",
            "node-sign-abcdef012345",
            "a",
            "0_1.2-3",
        ] {
            assert!(validate_secret_name(ok).is_ok(), "expected '{ok}' valid");
        }
        for bad in [
            "",
            ".hidden",
            "../etc/passwd",
            "a/../b",
            "foo/bar",
            "foo\\bar",
            "UPPER",
            "with space",
            "a..b",
            "null\0byte",
            &"a".repeat(65),
        ] {
            assert!(
                matches!(
                    validate_secret_name(bad),
                    Err(CryptoError::InvalidSecretName(_))
                ),
                "expected '{bad}' rejected"
            );
        }
    }

    #[test]
    fn file_backend_atomic_roundtrip_permissions_and_fail_closed_checks() {
        let tmp = TempDir::new().unwrap();
        // Temp dir (and not-yet-created nested subdir) automatically resolves to File backend
        // across macOS, Linux, and Windows (never touches live OS keyrings!).
        assert_eq!(detect_backend_with(tmp.path(), None), SecretBackend::File);
        assert_eq!(
            detect_backend_with(&tmp.path().join("not-created-yet"), None),
            SecretBackend::File
        );
        assert_eq!(
            detect_backend_with(tmp.path(), Some("file")),
            SecretBackend::File
        );

        let store = SecretStore::file_only(tmp.path());
        let saved = store.set("api-token", "super-secret-value-123").unwrap();
        assert_eq!(saved.backend, SecretBackend::File);
        assert_eq!(&*store.get("api-token").unwrap(), "super-secret-value-123");

        // Verify 0700 dir and 0600 file permissions
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let dir_mode = fs::metadata(store.secrets_dir())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            let file_path = store.secret_file_path("api-token").unwrap();
            let file_mode = fs::metadata(&file_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(dir_mode, 0o700);
            assert_eq!(file_mode, 0o600);

            // Fail closed if permissions become world-readable!
            fs::set_permissions(&file_path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(matches!(
                store.get("api-token"),
                Err(CryptoError::Keystore(_))
            ));

            // Restore 0600 -> succeeds again
            fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(&*store.get("api-token").unwrap(), "super-secret-value-123");
        }

        // List never returns values
        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "api-token");
        assert!(listed[0].mode_ok);

        // Delete works
        assert!(store.delete("api-token").unwrap());
        assert!(matches!(
            store.get("api-token"),
            Err(CryptoError::SecretNotFound(_))
        ));
    }

    #[test]
    fn load_or_create_node_keys_and_legacy_v1_fallback() {
        let tmp = TempDir::new().unwrap();
        let store = SecretStore::new(tmp.path(), SecretBackend::File);

        // Fresh node creates persistent keys
        let k1 = store.load_or_create_node_keys("alice@macbook").unwrap();
        let k2 = store.load_or_create_node_keys("alice@macbook").unwrap();
        assert_eq!(k1.signing.public_key_bytes(), k2.signing.public_key_bytes());
        assert_eq!(
            k1.encryption.public_key_bytes(),
            k2.encryption.public_key_bytes()
        );

        // Legacy v1 id-sign-*/id-enc-* keys are read transparently without changing fingerprints
        let legacy_sign = Ed25519KeyPair::generate().unwrap();
        let legacy_enc = X25519KeyPair::generate().unwrap();
        let (v1_s, v1_e) = legacy_connector_key_secret_names("legacy@host");
        store.set(&v1_s, &legacy_sign.export_pkcs8_b64()).unwrap();
        store.set(&v1_e, &legacy_enc.export_pkcs8_b64()).unwrap();

        let loaded = store.load_or_create_node_keys("legacy@host").unwrap();
        assert_eq!(
            loaded.signing.public_key_bytes(),
            legacy_sign.public_key_bytes()
        );
        assert_eq!(
            loaded.encryption.public_key_bytes(),
            legacy_enc.public_key_bytes()
        );
    }

    #[test]
    fn macos_keychain_stdin_framing_and_lossless_encoding() {
        let plain = "ghp_normalAsciiToken123";
        assert_eq!(&*encode_keychain_payload(plain), plain);
        assert_eq!(&*decode_keychain_payload(plain).unwrap(), plain);

        let multiline = "line1\nline2\t🚀";
        let enc = encode_keychain_payload(multiline);
        assert!(enc.starts_with(KEYCHAIN_B64_PREFIX));
        assert_eq!(&*decode_keychain_payload(&enc).unwrap(), multiline);

        let stdin_cmd = format_security_add_stdin("hyphae", "node-sign-abc", plain).unwrap();
        assert!(stdin_cmd.starts_with("add-generic-password -U -s hyphae -a node-sign-abc -X "));
        assert!(stdin_cmd.ends_with('\n'));
        assert!(!stdin_cmd.contains(plain)); // hex-encoded in stdin, never plaintext argv
    }

    #[test]
    fn d10_keychain_and_secret_service_error_classification_fails_closed() {
        // macOS Keychain: exit 44 / errSecItemNotFound -> genuine None
        assert!(
            classify_mac_keychain_output(
                "node-sign-1",
                Some(44),
                b"",
                "security: SecKeychainSearchCopyNext: The specified item could not be found in the keychain."
            )
            .unwrap()
            .is_none()
        );
        // macOS Keychain: exit 36 errSecInteractionNotAllowed / locked -> Err(Keystore), NEVER None!
        assert!(matches!(
            classify_mac_keychain_output(
                "node-sign-1",
                Some(36),
                b"",
                "security: SecKeychainSearchCopyNext: User interaction is not allowed."
            ),
            Err(CryptoError::Keystore(_))
        ));
        assert!(matches!(
            classify_mac_keychain_output("node-sign-1", Some(51), b"", "errSecAuthFailed"),
            Err(CryptoError::Keystore(_))
        ));
        assert!(matches!(
            classify_mac_keychain_output("node-sign-1", Some(1), b"", ""),
            Err(CryptoError::Keystore(_))
        ));
        // Valid macOS read
        assert_eq!(
            &*classify_mac_keychain_output("node-sign-1", Some(0), b"secret-abc\n", "")
                .unwrap()
                .unwrap(),
            "secret-abc"
        );

        // Linux secret-tool: exit 0 with empty stdout -> genuine None
        assert!(
            classify_linux_secret_service_output("node-sign-1", Some(0), b"", "")
                .unwrap()
                .is_none()
        );
        // OR1: Linux secret-tool legitimately exits 1 with empty stdout & empty stderr on not-found!
        assert!(
            classify_linux_secret_service_output("node-sign-1", Some(1), b"", "")
                .unwrap()
                .is_none()
        );
        // Linux secret-tool: explicit not-found without D-Bus error -> genuine None
        assert!(
            classify_linux_secret_service_output(
                "node-sign-1",
                Some(1),
                b"",
                "secret-tool: no matching secret found"
            )
            .unwrap()
            .is_none()
        );
        // Linux secret-tool: exit 1 with non-empty stdout fails closed (never silently NotFound)
        assert!(matches!(
            classify_linux_secret_service_output("node-sign-1", Some(1), b"partial-output", ""),
            Err(CryptoError::Keystore(_))
        ));
        // Linux secret-tool: D-Bus unavailable / locked / permission denied / auth failed / exit 2+ -> Err(Keystore)
        for (code, stderr) in [
            (
                Some(1),
                "secret-tool: Cannot autolaunch D-Bus without X11 $DISPLAY",
            ),
            (Some(1), "secret-tool: Keyring is locked"),
            (Some(1), "secret-tool: Permission denied"),
            (Some(1), "secret-tool: auth failed"),
            (Some(1), "secret-tool: authentication cancelled"),
            (
                Some(1),
                "secret-tool: org.freedesktop.secrets service unavailable",
            ),
            (Some(2), ""),
            (Some(2), "org.freedesktop.secrets unavailable"),
            (Some(2), "secret-tool: no matching secret found"),
            (Some(127), ""),
            (None, ""),
        ] {
            assert!(
                matches!(
                    classify_linux_secret_service_output("node-sign-1", code, b"", stderr),
                    Err(CryptoError::Keystore(_))
                ),
                "expected Keystore error for code={code:?} stderr={stderr:?}"
            );
        }
        // Valid Linux read
        assert_eq!(
            &*classify_linux_secret_service_output("node-sign-1", Some(0), b"secret-xyz\n", "")
                .unwrap()
                .unwrap(),
            "secret-xyz"
        );
    }

    #[test]
    fn d10_load_or_create_node_keys_fails_closed_on_missing_indexed_or_sibling_key() {
        let tmp = TempDir::new().unwrap();
        let store = SecretStore::file_only(tmp.path());

        let orig = store.load_or_create_node_keys("node-d10@host").unwrap();
        let (v2_sign, v2_enc) = node_key_secret_names("node-d10@host");
        let sign_path = store.secret_file_path(&v2_sign).unwrap();
        let enc_path = store.secret_file_path(&v2_enc).unwrap();

        // 1. Delete signing secret file on disk while index.json still records it -> MUST fail closed!
        let saved_sign_bytes = fs::read(&sign_path).unwrap();
        fs::remove_file(&sign_path).unwrap();
        let err = store
            .load_or_create_node_keys("node-d10@host")
            .expect_err("must not regenerate when key is recorded in index.json");
        assert!(
            matches!(err, CryptoError::Keystore(_)),
            "unexpected err: {err}"
        );
        assert!(
            !sign_path.exists(),
            "must not write a newly generated signing key"
        );

        // Restore signing file -> loads original keys again!
        fs::write(&sign_path, &saved_sign_bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&sign_path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let reloaded = store.load_or_create_node_keys("node-d10@host").unwrap();
        assert_eq!(reloaded.kid(), orig.kid());

        // 2. Delete encryption key cleanly (removes from both disk & index) while signing sibling exists -> MUST fail closed!
        assert!(store.delete(&v2_enc).unwrap());
        let err2 = store
            .load_or_create_node_keys("node-d10@host")
            .expect_err("must not regenerate partial identity when sibling key exists");
        assert!(
            matches!(err2, CryptoError::Keystore(_)),
            "unexpected err: {err2}"
        );
        assert!(
            !enc_path.exists(),
            "must not silently regenerate missing sibling key"
        );
    }
}
