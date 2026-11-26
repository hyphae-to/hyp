//! Shared config, state-dir, secret-store, and atomic private file helpers for `hyp`.
//!
//! Supports both Hyphae v2 `node.json` and transparent legacy v1 `connector.json` auto-reading,
//! with portable `#[cfg(unix)]` / `#[cfg(not(unix))]` permissions enforcement.

use hyp_crypto::keystore::{SecretBackend, SecretStore};
use hyp_node::engine::NodeProfile;
use hyp_proto::address::{LOCAL_NODE_ID, is_valid_node_id};
use hyp_store::NodeDb;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::{Map, Value, json};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

/// Returns the default Hyphae config directory, honoring `--home`, `HYPHAE_CONFIG_DIR`,
/// `XDG_CONFIG_HOME`, `HOME`, and `USERPROFILE` (Windows).
pub fn default_config_dir(home_override: Option<&Path>) -> PathBuf {
    if let Some(home) = home_override {
        return home.join(".config").join("hyphae");
    }
    if let Ok(explicit) = std::env::var("HYPHAE_CONFIG_DIR") {
        if !explicit.trim().is_empty() {
            return PathBuf::from(explicit);
        }
    }
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        if !xdg.trim().is_empty() {
            return PathBuf::from(xdg).join("hyphae");
        }
    }
    if let Some(home) = resolve_home_dir(None) {
        return home.join(".config").join("hyphae");
    }
    PathBuf::from(".hyphae")
}

/// Resolves the user home directory from an explicit `--home`, `HOME`, or `USERPROFILE`.
pub fn resolve_home_dir(home_override: Option<&Path>) -> Option<PathBuf> {
    if let Some(home) = home_override {
        return Some(home.to_path_buf());
    }
    if let Ok(home) = std::env::var("HOME") {
        if !home.trim().is_empty() {
            return Some(PathBuf::from(home));
        }
    }
    if let Ok(profile) = std::env::var("USERPROFILE") {
        if !profile.trim().is_empty() {
            return Some(PathBuf::from(profile));
        }
    }
    None
}

/// Resolves the effective state directory holding `node.sqlite`, `secrets/`, and `node.pid`.
pub fn resolve_state_dir(
    state_dir_arg: Option<&Path>,
    config_path: Option<&Path>,
    home_override: Option<&Path>,
) -> PathBuf {
    if let Some(dir) = state_dir_arg {
        return dir.to_path_buf();
    }
    if let Ok(env_dir) = std::env::var("HYPHAE_STATE_DIR") {
        if !env_dir.trim().is_empty() {
            return PathBuf::from(env_dir);
        }
    }
    if let Some(cfg) = config_path {
        if let Ok(loaded) = read_json_value(cfg) {
            if let Some(sd) = loaded.get("stateDir").and_then(Value::as_str) {
                let p = PathBuf::from(sd);
                if p.is_absolute() {
                    return p;
                }
                if let Some(parent) = cfg.parent() {
                    return parent.join(p);
                }
                return p;
            }
        }
        if let Some(parent) = cfg.parent() {
            if !parent.as_os_str().is_empty() {
                return parent.to_path_buf();
            }
        }
    }
    default_config_dir(home_override)
}

/// Resolves the effective `node.json` path for reading (falls back cleanly to legacy v1
/// `connector.json` if `node.json` does not exist yet).
pub fn resolve_config_path_for_read(
    config_arg: Option<&Path>,
    state_dir_arg: Option<&Path>,
    home_override: Option<&Path>,
) -> PathBuf {
    if let Some(p) = config_arg {
        return p.to_path_buf();
    }
    if let Some(dir) = state_dir_arg {
        let v2 = dir.join("node.json");
        if v2.exists() {
            return v2;
        }
        let v1 = dir.join("connector.json");
        if v1.exists() {
            return v1;
        }
        return v2;
    }
    if let Ok(env_cfg) = std::env::var("HYPHAE_CONFIG") {
        if !env_cfg.trim().is_empty() {
            return PathBuf::from(env_cfg);
        }
    }
    let cfg_dir = default_config_dir(home_override);
    let v2 = cfg_dir.join("node.json");
    if v2.exists() {
        return v2;
    }
    let v1 = cfg_dir.join("connector.json");
    if v1.exists() {
        return v1;
    }
    v2
}

/// Resolves the target `node.json` path for writes (never overwrites legacy `connector.json`
/// unless explicitly passed via `--config`).
pub fn resolve_config_path_for_write(
    config_arg: Option<&Path>,
    state_dir_arg: Option<&Path>,
    home_override: Option<&Path>,
) -> PathBuf {
    if let Some(p) = config_arg {
        return p.to_path_buf();
    }
    if let Some(dir) = state_dir_arg {
        return dir.join("node.json");
    }
    if let Ok(env_cfg) = std::env::var("HYPHAE_CONFIG") {
        if !env_cfg.trim().is_empty() {
            return PathBuf::from(env_cfg);
        }
    }
    default_config_dir(home_override).join("node.json")
}

/// Opens a `SecretStore` pinned to `state_dir`. When `explicit_dir` is `true` and
/// `HYPHAE_SECRET_BACKEND` is unset (or unrecognized), defaults to `SecretBackend::File` so
/// isolated tests and explicit `--state-dir` calls never mutate live OS Keychain entries.
pub fn open_secret_store(state_dir: &Path, explicit_dir: bool) -> SecretStore {
    let override_val = std::env::var("HYPHAE_SECRET_BACKEND").ok();
    open_secret_store_with(state_dir, explicit_dir, override_val.as_deref())
}

/// Pure testable helper for [`open_secret_store`] supporting all `HYPHAE_SECRET_BACKEND` values
/// (`file`, `keychain`, `secret-service`, `1password`, `lastpass`, `pass`).
pub(crate) fn open_secret_store_with(
    state_dir: &Path,
    explicit_dir: bool,
    explicit_backend_override: Option<&str>,
) -> SecretStore {
    if let Some(backend) = explicit_backend_override.and_then(hyp_crypto::keystore::parse_backend) {
        let mut store = SecretStore::from_env(state_dir);
        if store.backend() != backend {
            store = SecretStore::new(state_dir, backend);
        }
        store
    } else if explicit_dir {
        SecretStore::new(state_dir, SecretBackend::File)
    } else {
        SecretStore::from_env(state_dir)
    }
}

/// Generates a deterministic, valid fallback `nodeId` from current user and hostname.
pub fn default_node_id() -> String {
    let raw_user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "user".to_string());
    let raw_host = std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "local-host".to_string());
    let user = sanitize_id_segment(&raw_user, "user");
    let host = sanitize_id_segment(raw_host.split('.').next().unwrap_or("local-host"), "host");
    let candidate = format!("{user}@{host}");
    if candidate != LOCAL_NODE_ID && is_valid_node_id(&candidate) {
        candidate
    } else {
        "user@local-host".to_string()
    }
}

fn sanitize_id_segment(raw: &str, fallback: &str) -> String {
    let mut out = String::new();
    for ch in raw.chars() {
        let low = ch.to_ascii_lowercase();
        if low.is_ascii_alphanumeric() || matches!(low, '.' | '_' | '-') {
            out.push(low);
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches(|c: char| !c.is_ascii_alphanumeric());
    if trimmed.is_empty() {
        fallback.to_string()
    } else {
        trimmed.chars().take(28).collect()
    }
}

/// Parsed fields normalized from either v2 `node.json` or legacy v1 `connector.json`.
#[derive(Debug, Clone)]
pub struct LoadedNodeFile {
    pub path: PathBuf,
    pub is_legacy_v1: bool,
    pub node_id: Option<String>,
    pub profile: Option<NodeProfile>,
    pub bind_addr: Option<SocketAddr>,
    pub public_url: Option<String>,
    pub state_dir: Option<PathBuf>,
    pub require_e2ee: bool,
    pub require_pairing: bool,
    pub update_channel: Option<String>,
    pub raw: Value,
}

/// Reads a JSON file into `serde_json::Value`.
pub fn read_json_value(path: &Path) -> Result<Value, String> {
    let raw =
        fs::read_to_string(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    serde_json::from_str(&raw).map_err(|e| format!("invalid JSON in {}: {e}", path.display()))
}

/// Reads an existing JSON object file or returns an empty JSON object if the file does not exist.
pub fn read_json_object_or_empty(path: &Path) -> Result<Map<String, Value>, String> {
    if !path.exists() {
        return Ok(Map::new());
    }
    match read_json_value(path)? {
        Value::Object(map) => Ok(map),
        _ => Err(format!(
            "expected top-level JSON object in {}",
            path.display()
        )),
    }
}

/// Reads the explicit agent-facing KV tool setting. Missing values use capability discovery.
pub fn kv_tool_override(kv: Option<&Value>) -> Result<Option<bool>, &'static str> {
    match kv {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Bool(enabled)) => Ok(Some(*enabled)),
        Some(Value::Object(kv)) => match kv.get("enabled") {
            None => Ok(None),
            Some(Value::Bool(enabled)) => Ok(Some(*enabled)),
            _ => Err("kv.enabled must be a boolean"),
        },
        _ => Err("kv must be a boolean or an object with an enabled boolean"),
    }
}

/// Loads either v2 `node.json` or legacy v1 `connector.json` transparently.
pub fn load_node_or_legacy_config(path: &Path) -> Result<LoadedNodeFile, String> {
    let raw = read_json_value(path)?;
    let obj = raw
        .as_object()
        .ok_or_else(|| format!("expected top-level JSON object in {}", path.display()))?;

    let is_legacy_v1 = obj.contains_key("connectorId") && !obj.contains_key("nodeId");

    let node_id = obj
        .get("nodeId")
        .or_else(|| obj.get("connectorId"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);

    let profile = match obj.get("profile").and_then(Value::as_str) {
        Some("local") => Some(NodeProfile::Local),
        Some("router") => Some(NodeProfile::Router),
        Some("p2p") => Some(NodeProfile::P2p),
        Some(other) => {
            return Err(format!(
                "invalid profile '{other}' in {} (expected local, router, or p2p)",
                path.display()
            ));
        }
        None => {
            if is_legacy_v1 {
                Some(NodeProfile::Local)
            } else {
                None
            }
        }
    };

    let bind_str = obj
        .get("listen")
        .and_then(|l| l.get("bind"))
        .and_then(Value::as_str)
        .or_else(|| obj.get("bind").and_then(Value::as_str))
        .map(ToOwned::to_owned)
        .or_else(|| {
            // Legacy v1 `localRouter: { host, port }`
            let lr = obj.get("localRouter")?;
            let host = lr
                .get("host")
                .and_then(Value::as_str)
                .unwrap_or("127.0.0.1");
            let port = lr.get("port").and_then(Value::as_u64)?;
            Some(format!("{host}:{port}"))
        });

    let bind_addr = match bind_str {
        Some(ref s) => Some(
            s.parse::<SocketAddr>()
                .map_err(|e| format!("invalid listen.bind '{s}' in {}: {e}", path.display()))?,
        ),
        None => None,
    };

    let public_url = obj
        .get("listen")
        .and_then(|l| l.get("publicUrl"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);

    let state_dir = obj.get("stateDir").and_then(Value::as_str).map(|s| {
        let p = PathBuf::from(s);
        if p.is_absolute() {
            p
        } else if let Some(parent) = path.parent() {
            parent.join(p)
        } else {
            p
        }
    });

    let policy = obj.get("policy");
    let require_e2ee = policy
        .and_then(|p| p.get("requireE2ee"))
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let require_pairing = policy
        .and_then(|p| p.get("requirePairing"))
        .and_then(Value::as_bool)
        .unwrap_or(true);

    let update_channel = obj
        .get("update")
        .and_then(|u| u.get("channel"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);

    Ok(LoadedNodeFile {
        path: path.to_path_buf(),
        is_legacy_v1,
        node_id,
        profile,
        bind_addr,
        public_url,
        state_dir,
        require_e2ee,
        require_pairing,
        update_channel,
        raw,
    })
}

/// Resolves the canonical node ID from config, `node.sqlite` metadata, or fallback default.
pub fn resolve_effective_node_id(loaded: Option<&LoadedNodeFile>, db: Option<&NodeDb>) -> String {
    if let Some(cfg) = loaded {
        if let Some(ref id) = cfg.node_id {
            if !id.is_empty() {
                return id.clone();
            }
        }
    }
    if let Some(db) = db {
        if let Ok(Some(id)) = db.local().get_metadata("node_id") {
            if !id.is_empty() {
                return id;
            }
        }
    }
    default_node_id()
}

/// Ensures directory exists with `0700` permissions on Unix when `private == true`.
pub fn ensure_dir(dir: &Path, private: bool) -> Result<(), String> {
    fs::create_dir_all(dir)
        .map_err(|e| format!("failed to create directory {}: {e}", dir.display()))?;
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("failed to chmod 0700 {}: {e}", dir.display()))?;
    }
    #[cfg(not(unix))]
    let _ = private;
    Ok(())
}

/// Resolves the final filesystem write target for `dest` so atomic renames through an existing
/// symlink update the symlink's target in place instead of clobbering the symlink itself.
///
/// Fails closed on symlink loops or multi-hop broken chains: only resolves either an existing
/// target via `fs::canonicalize` or a single-hop dangling relative/absolute symlink whose direct
/// target does not yet exist.
fn resolve_symlink_write_target(dest: &Path) -> Result<PathBuf, String> {
    let Ok(meta) = fs::symlink_metadata(dest) else {
        return Ok(dest.to_path_buf());
    };
    if !meta.file_type().is_symlink() {
        return Ok(dest.to_path_buf());
    }

    match fs::canonicalize(dest) {
        Ok(resolved) => Ok(resolved),
        Err(canon_err) => {
            let raw_target = fs::read_link(dest)
                .map_err(|e| format!("failed to read symlink {}: {e}", dest.display()))?;
            let candidate = if raw_target.is_absolute() {
                raw_target
            } else {
                dest.parent()
                    .filter(|p| !p.as_os_str().is_empty())
                    .unwrap_or_else(|| Path::new("."))
                    .join(raw_target)
            };
            // Only allow a single-hop dangling link whose direct target does not exist yet.
            // If `symlink_metadata(&candidate)` succeeds (e.g. symlink loop / multi-hop broken
            // chain) or errors with anything other than NotFound (e.g. ELOOP / EACCES), fail closed.
            match fs::symlink_metadata(&candidate) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    if candidate.file_name().is_none() {
                        return Err(format!(
                            "refusing to write through invalid symlink target {} (from {})",
                            candidate.display(),
                            dest.display()
                        ));
                    }
                    Ok(candidate)
                }
                _ => Err(format!(
                    "failed to resolve symlink {} (possible symlink loop or broken chain): {canon_err}",
                    dest.display()
                )),
            }
        }
    }
}

/// Atomically writes bytes to `dest` via sibling temporary file + `sync_all` + `rename`.
/// Enforces `0600` permissions on Unix when `private == true`.
///
/// If `dest` is an existing symlink, writes into the target's parent directory and atomically
/// renames over the resolved target path so the symlink at `dest` remains intact.
pub fn write_atomic_file(dest: &Path, bytes: &[u8], private: bool) -> Result<(), String> {
    let target = resolve_symlink_write_target(dest)?;
    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_dir(parent, private)?;

    let rng = SystemRandom::new();
    let mut suffix = [0u8; 8];
    rng.fill(&mut suffix)
        .map_err(|_| "OS CSPRNG failure".to_string())?;
    let tmp_path = parent.join(format!(".tmp-hyp-{}", hex::encode(suffix)));

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(if private { 0o600 } else { 0o644 });
    }

    let res: Result<(), String> = (|| {
        let mut f = opts
            .open(&tmp_path)
            .map_err(|e| format!("failed to create temp file {}: {e}", tmp_path.display()))?;
        f.write_all(bytes)
            .map_err(|e| format!("failed to write {}: {e}", tmp_path.display()))?;
        f.sync_all()
            .map_err(|e| format!("failed to sync {}: {e}", tmp_path.display()))?;
        drop(f);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = if private { 0o600 } else { 0o644 };
            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(mode))
                .map_err(|e| format!("failed to set permissions on {}: {e}", tmp_path.display()))?;
        }
        fs::rename(&tmp_path, &target).map_err(|e| {
            format!(
                "failed to atomically rename {} -> {}: {e}",
                tmp_path.display(),
                target.display()
            )
        })?;
        Ok(())
    })();

    if res.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    res
}

/// Atomically writes pretty-printed JSON with a trailing newline.
pub fn write_atomic_json(dest: &Path, value: &Value, private: bool) -> Result<(), String> {
    let mut text = serde_json::to_string_pretty(value)
        .map_err(|e| format!("failed to serialize JSON for {}: {e}", dest.display()))?;
    text.push('\n');
    write_atomic_file(dest, text.as_bytes(), private)
}

/// Ensures a baseline v2 `node.json` object has required top-level fields without clobbering
/// existing user configuration.
pub fn ensure_v2_node_json_defaults(
    map: &mut Map<String, Value>,
    node_id: &str,
    profile: NodeProfile,
    state_dir: &Path,
) {
    map.entry("v".to_string()).or_insert_with(|| json!(2));
    map.entry("nodeId".to_string())
        .or_insert_with(|| Value::String(node_id.to_string()));
    map.entry("profile".to_string())
        .or_insert_with(|| Value::String(profile_as_str(profile).to_string()));
    map.entry("stateDir".to_string())
        .or_insert_with(|| Value::String(state_dir.display().to_string()));
    map.entry("policy".to_string()).or_insert_with(|| {
        json!({
            "requirePairing": true,
            "requireE2ee": true,
            "maxTextBytes": 32768,
            "maxTransferBytes": 52428800
        })
    });
    map.entry("forwarding".to_string()).or_insert_with(|| {
        json!({
            "mode": "deny",
            "rules": []
        })
    });
    map.entry("update".to_string()).or_insert_with(|| {
        json!({
            "channel": "stable"
        })
    });
}

pub const fn profile_as_str(p: NodeProfile) -> &'static str {
    match p {
        NodeProfile::Local => "local",
        NodeProfile::Router => "router",
        NodeProfile::P2p => "p2p",
    }
}

/// Constant-time byte-slice equality comparison (avoids deprecated `ring::constant_time`).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (&x, &y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    std::hint::black_box(diff) == 0
}

/// Builds a shared `hyper 1` + `hyper-rustls` client (ring + webpki-roots, HTTPS + loopback HTTP).
pub fn build_http_client<B>()
-> Result<Client<hyper_rustls::HttpsConnector<HttpConnector>, B>, String>
where
    B: hyper::body::Body + Send + 'static + Unpin,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    let _ = rustls::crypto::ring::default_provider().install_default();
    let connector = HttpsConnectorBuilder::new()
        .with_provider_and_webpki_roots(rustls::crypto::ring::default_provider())
        .map_err(|e| format!("TLS connector initialization failed: {e}"))?
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();
    Ok(Client::builder(TokioExecutor::new()).build(connector))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_atomic_file_creates_and_updates_regular_file() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dest = tmp.path().join("nested").join("config.json");
        write_atomic_file(&dest, b"{\"v\":1}\n", true).expect("initial write");
        assert_eq!(fs::read_to_string(&dest).unwrap(), "{\"v\":1}\n");

        write_atomic_file(&dest, b"{\"v\":2}\n", false).expect("overwrite");
        assert_eq!(fs::read_to_string(&dest).unwrap(), "{\"v\":2}\n");
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_file_preserves_symlink_and_updates_target() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().expect("tempdir");
        let real_dir = tmp.path().join("real");
        let profile_dir = tmp.path().join("profile");
        fs::create_dir_all(&real_dir).unwrap();
        fs::create_dir_all(&profile_dir).unwrap();

        let target = real_dir.join("settings.json");
        fs::write(&target, "{\"v\":1}\n").unwrap();
        let link = profile_dir.join("settings.json");
        symlink(&target, &link).unwrap();

        write_atomic_file(&link, b"{\"v\":2}\n", false).expect("atomic write through symlink");

        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "symlink at dest must remain a symlink after write_atomic_file"
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "{\"v\":2}\n");
        assert_eq!(fs::read_to_string(&link).unwrap(), "{\"v\":2}\n");

        // Relative symlink in a sibling directory also stays intact.
        let rel_link = profile_dir.join("rel-settings.json");
        symlink(Path::new("../real/settings.json"), &rel_link).unwrap();
        write_atomic_file(&rel_link, b"{\"v\":3}\n", false).expect("atomic write via rel symlink");
        assert!(
            fs::symlink_metadata(&rel_link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read_to_string(&target).unwrap(), "{\"v\":3}\n");
    }

    #[cfg(unix)]
    #[test]
    fn write_atomic_file_handles_dangling_symlink_and_rejects_loops() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().expect("tempdir");
        let real_dir = tmp.path().join("real");
        let profile_dir = tmp.path().join("profile");
        fs::create_dir_all(&profile_dir).unwrap();

        // Single-hop dangling symlink pointing to a non-existent target file.
        let dangling_target = real_dir.join("future.json");
        let dangling_link = profile_dir.join("future.json");
        symlink(&dangling_target, &dangling_link).unwrap();

        write_atomic_file(&dangling_link, b"{\"created\":true}\n", false)
            .expect("single-hop dangling symlink should write target and stay symlink");
        assert!(
            fs::symlink_metadata(&dangling_link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(
            fs::read_to_string(&dangling_target).unwrap(),
            "{\"created\":true}\n"
        );

        // Symlink loop must fail closed and leave symlinks untouched.
        let loop_a = profile_dir.join("loop-a.json");
        let loop_b = profile_dir.join("loop-b.json");
        symlink(&loop_b, &loop_a).unwrap();
        symlink(&loop_a, &loop_b).unwrap();

        let err = write_atomic_file(&loop_a, b"oops", false).unwrap_err();
        assert!(
            err.contains("symlink"),
            "expected symlink resolution error, got: {err}"
        );
        assert!(
            fs::symlink_metadata(&loop_a)
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[test]
    fn open_secret_store_with_supports_1password_lastpass_pass_and_preserves_explicit_dir_safety() {
        let tmp = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            open_secret_store_with(tmp.path(), true, None).backend(),
            SecretBackend::File
        );
        assert_eq!(
            open_secret_store_with(tmp.path(), true, Some("unknown")).backend(),
            SecretBackend::File
        );
        assert_eq!(
            open_secret_store_with(tmp.path(), true, Some("1password")).backend(),
            SecretBackend::OnePassword
        );
        assert_eq!(
            open_secret_store_with(tmp.path(), true, Some("lastpass")).backend(),
            SecretBackend::LastPass
        );
        assert_eq!(
            open_secret_store_with(tmp.path(), true, Some("pass")).backend(),
            SecretBackend::Pass
        );
    }
}
