//! Shared config, state-dir, secret-store, and atomic private file helpers for `hyp-rs`.
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
/// `HYPHAE_SECRET_BACKEND` is unset, defaults to `SecretBackend::File` so isolated tests
/// and explicit `--state-dir` calls never mutate live OS Keychain entries.
pub fn open_secret_store(state_dir: &Path, explicit_dir: bool) -> SecretStore {
    if std::env::var_os("HYPHAE_SECRET_BACKEND").is_some() {
        SecretStore::from_env(state_dir)
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
    let raw = fs::read_to_string(path)
        .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    serde_json::from_str(&raw).map_err(|e| format!("invalid JSON in {}: {e}", path.display()))
}

/// Reads an existing JSON object file or returns an empty JSON object if the file does not exist.
pub fn read_json_object_or_empty(path: &Path) -> Result<Map<String, Value>, String> {
    if !path.exists() {
        return Ok(Map::new());
    }
    match read_json_value(path)? {
        Value::Object(map) => Ok(map),
        _ => Err(format!("expected top-level JSON object in {}", path.display())),
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
        Some(ref s) => Some(s.parse::<SocketAddr>().map_err(|e| {
            format!("invalid listen.bind '{s}' in {}: {e}", path.display())
        })?),
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
pub fn resolve_effective_node_id(
    loaded: Option<&LoadedNodeFile>,
    db: Option<&NodeDb>,
) -> String {
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

/// Atomically writes bytes to `dest` via sibling temporary file + `sync_all` + `rename`.
/// Enforces `0600` permissions on Unix when `private == true`.
pub fn write_atomic_file(dest: &Path, bytes: &[u8], private: bool) -> Result<(), String> {
    let parent = dest
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
        fs::rename(&tmp_path, dest).map_err(|e| {
            format!(
                "failed to atomically rename {} -> {}: {e}",
                tmp_path.display(),
                dest.display()
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
