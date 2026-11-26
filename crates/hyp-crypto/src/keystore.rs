//! Zero-leak `SecretStore` supporting:
//! - Private user-only file backend (`HYPHAE_SECRET_BACKEND=file`, `0700` dir, atomic `0600` temp-file + rename)
//! - macOS Keychain (`/usr/bin/security -i` over stdin `-X <hex>`, zero secrets in argv, lossless `hyphae-b64v1:`)
//! - Linux Freedesktop Secret Service (`secret-tool` over stdin, zero secrets in argv)
//!
//! Mirrors `src/secrets.ts` and `src/identity.ts` naming & safety invariants, including
//! automatic `File` backend selection for ephemeral temp directories so tests NEVER touch live OS keyrings.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
#[cfg(any(target_os = "macos", target_os = "linux"))]
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

/// Active secret storage backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecretBackend {
    Keychain,
    SecretService,
    File,
}

impl SecretBackend {
    pub const fn as_str(self) -> &'static str {
        match self {
            SecretBackend::Keychain => "keychain",
            SecretBackend::SecretService => "secret-service",
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

/// Pure backend resolution helper matching `detectSecretBackend` in `src/secrets.ts`.
pub fn detect_backend_with(config_dir: &Path, explicit_override: Option<&str>) -> SecretBackend {
    if let Some(raw) = explicit_override {
        match raw.trim().to_ascii_lowercase().as_str() {
            "keychain" => return SecretBackend::Keychain,
            "secret-service" => return SecretBackend::SecretService,
            "file" => return SecretBackend::File,
            _ => {}
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

/// Lossless ASCII encoding for macOS Keychain `-X` matching `src/secrets.ts:138-147`.
pub fn encode_keychain_payload(value: &str) -> Zeroizing<String> {
    let needs_b64 = value.starts_with(KEYCHAIN_B64_PREFIX)
        || value.bytes().any(|b| !(0x20..=0x7e).contains(&b));
    if needs_b64 {
        Zeroizing::new(format!(
            "{KEYCHAIN_B64_PREFIX}{}",
            URL_SAFE_NO_PAD.encode(value.as_bytes())
        ))
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
fn check_private_owner_and_mode(path: &Path, expect_dir: bool) -> Result<u64, CryptoError> {
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
    if (st.mode() & 0o077) != 0 {
        return Err(CryptoError::Keystore(format!(
            "{} has overly broad permissions ({:o}); expected 0600/0700",
            path.display(),
            st.mode() & 0o777
        )));
    }
    Ok(st.size())
}

#[cfg(not(unix))]
fn check_private_owner_and_mode(path: &Path, expect_dir: bool) -> Result<u64, CryptoError> {
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

fn ensure_private_dir(dir: &Path) -> Result<(), CryptoError> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    }
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

/// Hyphae v2 `SecretStore` managing private keys & API secrets across OS keyrings and `0600` local files.
#[derive(Debug, Clone)]
pub struct SecretStore {
    config_dir: PathBuf,
    backend: SecretBackend,
    service: String,
}

impl SecretStore {
    /// Creates a `SecretStore` with an explicit backend (recommended in tests with `SecretBackend::File`).
    pub fn new(config_dir: impl Into<PathBuf>, backend: SecretBackend) -> Self {
        Self {
            config_dir: config_dir.into(),
            backend,
            service: "hyphae".to_string(),
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
        Self {
            config_dir,
            backend,
            service,
        }
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
    /// or Linux Secret Service via stdin).
    pub fn set(&self, name: &str, value: &str) -> Result<SavedSecret, CryptoError> {
        validate_secret_name(name)?;
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(CryptoError::Keystore(format!(
                "secret '{name}' cannot be empty"
            )));
        }

        let location = match self.backend {
            SecretBackend::File => self.write_file_secret(name, trimmed)?,
            SecretBackend::Keychain => {
                let loc = self.write_mac_keychain(name, trimmed)?;
                let _ = fs::remove_file(self.secret_file_path(name)?);
                loc
            }
            SecretBackend::SecretService => {
                let loc = self.write_linux_secret_service(name, trimmed)?;
                let _ = fs::remove_file(self.secret_file_path(name)?);
                loc
            }
        };

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
                service: (self.backend != SecretBackend::File).then(|| self.service.clone()),
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
        let service = entry
            .and_then(|e| e.service.as_deref())
            .unwrap_or(&self.service);

        match backend {
            SecretBackend::File => self.read_file_secret(name),
            SecretBackend::Keychain => self
                .read_mac_keychain(name, service)?
                .ok_or_else(|| CryptoError::SecretNotFound(name.to_string())),
            SecretBackend::SecretService => self
                .read_linux_secret_service(name, service)?
                .ok_or_else(|| CryptoError::SecretNotFound(name.to_string())),
        }
    }

    /// Deletes a secret from the configured backend and index. Returns `true` if anything was removed.
    pub fn delete(&self, name: &str) -> Result<bool, CryptoError> {
        validate_secret_name(name)?;
        let mut index = self.read_index();
        let entry = index.secrets.remove(name);
        let service = entry
            .as_ref()
            .and_then(|e| e.service.as_deref())
            .unwrap_or(&self.service);
        let mut removed = false;

        if let Some(e) = &entry {
            match e.backend {
                SecretBackend::Keychain => {
                    removed |= self.delete_mac_keychain(name, service);
                }
                SecretBackend::SecretService => {
                    removed |= self.delete_linux_secret_service(name, service);
                }
                SecretBackend::File => {}
            }
        }

        let file_path = self.secret_file_path(name)?;
        if file_path.exists() {
            fs::remove_file(&file_path)?;
            removed = true;
        }

        if entry.is_some() {
            self.write_index(&index)?;
            removed = true;
        } else if !removed {
            match self.backend {
                SecretBackend::Keychain => removed = self.delete_mac_keychain(name, service),
                SecretBackend::SecretService => {
                    removed = self.delete_linux_secret_service(name, service);
                }
                SecretBackend::File => {}
            }
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
            let service = entry.service.as_deref().unwrap_or(&self.service);
            match entry.backend {
                SecretBackend::Keychain | SecretBackend::SecretService => {
                    by_name.insert(
                        name.clone(),
                        SecretMetadata {
                            name: name.clone(),
                            backend: entry.backend,
                            location: format!("{}:{service}/{name}", entry.backend.as_str()),
                            mode_ok: true,
                            bytes: None,
                        },
                    );
                }
                SecretBackend::File => {
                    let path = self.secret_file_path(name)?;
                    if path.exists() {
                        let (mode_ok, bytes) = match check_private_owner_and_mode(&path, false) {
                            Ok(sz) => (true, Some(sz)),
                            Err(_) => (false, fs::symlink_metadata(&path).ok().map(|m| m.len())),
                        };
                        by_name.insert(
                            name.clone(),
                            SecretMetadata {
                                name: name.clone(),
                                backend: SecretBackend::File,
                                location: path.display().to_string(),
                                mode_ok,
                                bytes,
                            },
                        );
                    }
                }
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

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
