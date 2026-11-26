//! Shared config, state-dir, secret-store, and atomic private file helpers for `hyp`.
//!
//! Supports both Hyphae v2 `node.json` and transparent legacy v1 `connector.json` auto-reading,
//! with portable `#[cfg(unix)]` / `#[cfg(not(unix))]` permissions enforcement.

use hyp_crypto::keystore::{SecretBackend, SecretStore};
use hyp_node::engine::NodeProfile;
use hyp_proto::address::{LOCAL_NODE_ID, is_valid_node_id};
use hyp_store::NodeDb;
use serde_json::{Map, Value, json};
use std::fs;
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
        if let Ok((file, _)) = hyp_node::node_file::NodeFile::read(cfg) {
            if let Some(dir) = file.state_dir(cfg) {
                return dir;
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

pub use hyp_node::node_file::kv_tool_override;

pub use hyp_node::node_file::{LoadedNodeFile, load_node_or_legacy_config};

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

pub use hyp_node::atomic_file::{ensure_dir, write_atomic_file, write_atomic_json};

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

pub use hyp_node::engine::http_util::build_http_client;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_file_compatibility_preserves_precedence_defaults_and_extensions() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("node.json");
        let legacy = json!({
            "connectorId": "legacy@host",
            "localRouter": {"port": 9071},
            "stateDir": "home/state",
            "extension": {"anything": [true, null]}
        });
        fs::write(&path, legacy.to_string()).unwrap();
        let loaded = load_node_or_legacy_config(&path).unwrap();
        assert!(loaded.is_legacy_v1);
        assert_eq!(loaded.node_id.as_deref(), Some("legacy@host"));
        assert_eq!(loaded.profile, Some(NodeProfile::Local));
        assert_eq!(loaded.bind_addr, Some("127.0.0.1:9071".parse().unwrap()));
        assert_eq!(loaded.state_dir, Some(tmp.path().join("home/state")));
        assert!(loaded.require_e2ee);
        assert!(loaded.require_pairing);
        assert_eq!(loaded.raw, legacy);
        assert_eq!(loaded.file.extra["extension"], legacy["extension"]);
        let mut original = hyp_node::node_file::NodeFile::read_document_or_empty(&path).unwrap();
        original.insert("update".into(), json!({"channel": "beta"}));
        hyp_node::node_file::NodeFile::write_document(&path, original).unwrap();
        let saved = load_node_or_legacy_config(&path).unwrap();
        assert_eq!(saved.raw["extension"], legacy["extension"]);
        assert_eq!(saved.update_channel.as_deref(), Some("beta"));

        let v2 = json!({
            "nodeId": null,
            "connectorId": "legacy@host",
            "profile": "p2p",
            "listen": {"bind": "[::1]:9081", "publicUrl": "https://node.example"},
            "bind": "127.0.0.1:9082",
            "localRouter": {"port": 9083},
            "policy": {"requireE2ee": false, "requirePairing": "false"},
            "update": {"channel": "beta"}
        });
        fs::write(&path, v2.to_string()).unwrap();
        let loaded = load_node_or_legacy_config(&path).unwrap();
        assert!(!loaded.is_legacy_v1);
        assert_eq!(loaded.node_id, None);
        assert_eq!(loaded.profile, Some(NodeProfile::P2p));
        assert_eq!(loaded.bind_addr, Some("[::1]:9081".parse().unwrap()));
        assert_eq!(loaded.public_url.as_deref(), Some("https://node.example"));
        assert!(!loaded.require_e2ee);
        assert!(loaded.require_pairing);
        assert_eq!(loaded.update_channel.as_deref(), Some("beta"));

        let mut fallback = v2;
        fallback["listen"]["bind"] = json!(123);
        fs::write(&path, fallback.to_string()).unwrap();
        let loaded = load_node_or_legacy_config(&path).unwrap();
        assert_eq!(loaded.bind_addr, Some("127.0.0.1:9082".parse().unwrap()));

        fallback["profile"] = json!("invalid");
        fs::write(&path, fallback.to_string()).unwrap();
        assert!(
            load_node_or_legacy_config(&path)
                .unwrap_err()
                .contains("invalid profile")
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
