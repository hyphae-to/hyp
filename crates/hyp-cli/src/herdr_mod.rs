//! Verified native Herdr mod (`hyphae-pane` + `hyphae-panel`) installer for `hyp`.
//!
//! Resolves and constant-time SHA-256 verifies the pure-JS GPUI mod assets through the
//! unified `hyp plugin` manager (`herdr-mod` in `hyp-vX.Y.Z-plugins.tar.gz` — ZERO embedded
//! JS/SVG inside the static `hyp` binary!) and wires them safely into `~/.config/herdr-app`:
//! - Copies mod folders as real directories (never symlinks by default) so macOS
//!   FSEvents hot-reload picks up updates immediately.
//! - Merges `cmd-shift-h -> mod.open:hyphae-panel` into `keys.json` only if unbound.
//! - Strictly respects symlinked layouts (e.g. git-managed `herdr-custom-ui`),
//!   customized `pane.header.content.mod`, and Herdr's read-only shipped layouts
//!   (`main`, `terminals`, `win98`).

use crate::config_file::resolve_state_dir;
use crate::plugin_cmd::{PluginSourceOverrides, install_herdr_mod_files};
use hyp_harness_transport::executable::{
    PathSearchPolicy, WindowsSuffixes, find_in_path as search_path,
};
use serde::Serialize;
use serde_json::{Map, Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

const SHIPPED_LAYOUTS: &[&str] = &["main", "terminals", "win98"];
const DEFAULT_SHORTCUT_KEY: &str = "cmd-shift-h";
const DEFAULT_SHORTCUT_ACTION: &str = "mod.open:hyphae-panel";

/// Typed error distinguishing offline/network unavailability (safe warning fallback in `hyp setup`)
/// from tamper, validation, or filesystem errors (always fail closed).
#[derive(Debug, Clone)]
pub struct HerdrModInstallError {
    pub message: String,
    pub is_offline_download: bool,
}

impl HerdrModInstallError {
    fn fatal(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            is_offline_download: false,
        }
    }
}

impl std::fmt::Display for HerdrModInstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

/// Options controlling how `install_herdr_mod` writes mods, keys, and layout wiring.
#[derive(Debug, Clone, Default)]
pub struct HerdrModInstallOptions {
    /// Explicit opt-in to edit an active symlinked layout JSON in place.
    pub patch_layout: bool,
    /// Explicit opt-in to replace a customized `pane.header.content.mod` (not `"pane"` / `"hyphae-pane"`).
    pub force: bool,
    /// Clone shipped `main.json` to `<name>.json`, patch `hyphae-pane` + `hyphae-panel`, and activate it.
    pub clone_layout: Option<String>,
    /// Skip running `herdr-app check` on the installed mods.
    pub skip_check: bool,
    /// Plan actions without modifying files on disk.
    pub dry_run: bool,
    /// Optional explicit override for the Herdr app config directory (`~/.config/herdr-app`).
    pub herdr_home_override: Option<PathBuf>,
    /// Optional explicit Hyphae state directory for plugin receipt & verified tarball cache.
    pub state_dir: Option<PathBuf>,
    /// Optional local plugins directory (`--plugins-dir`).
    pub plugins_dir: Option<PathBuf>,
    /// Optional local plugins archive (`--plugins-archive`).
    pub plugins_archive: Option<PathBuf>,
}

/// Outcome of the layout wiring step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LayoutAction {
    Patched,
    AlreadyConfigured,
    Cloned,
    SkippedShipped,
    SkippedSymlink,
    SkippedCustomHeader,
    SkippedMissing,
    DryRun,
}

/// Result of running `herdr-app check <mod_dir>` after installation.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModCheckResult {
    pub mod_name: String,
    pub ran: bool,
    pub passed: bool,
    pub output: String,
}

/// Structured result suitable for both TTY summaries and `--json` envelopes.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HerdrModInstallOutcome {
    pub herdr_home: PathBuf,
    pub dry_run: bool,
    pub installed_mods: Vec<String>,
    pub files: Vec<String>,
    pub keys_action: String,
    pub active_layout: String,
    pub layout_action: LayoutAction,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backup_path: Option<PathBuf>,
    pub checks: Vec<ModCheckResult>,
    pub warnings: Vec<String>,
    pub notes: Vec<String>,
    pub next: Vec<String>,
}

/// Detects an existing Herdr desktop app directory (`$HERDR_APP_HOME` or `<home>/.config/herdr-app`).
pub fn detect_herdr_app_dir(home: &Path) -> Option<PathBuf> {
    if let Ok(env_dir) = std::env::var("HERDR_APP_HOME") {
        let trimmed = env_dir.trim();
        if !trimmed.is_empty() {
            let path = PathBuf::from(trimmed);
            if path.is_dir() {
                return Some(path);
            }
        }
    }
    let default_dir = home.join(".config").join("herdr-app");
    if default_dir.is_dir() {
        Some(default_dir)
    } else {
        None
    }
}

/// Installs the SHA-256 verified `hyphae-pane` and `hyphae-panel` mods into Herdr safely.
pub fn install_herdr_mod(
    home: &Path,
    opts: HerdrModInstallOptions,
) -> Result<HerdrModInstallOutcome, HerdrModInstallError> {
    let herdr_home = opts
        .herdr_home_override
        .clone()
        .unwrap_or_else(|| home.join(".config").join("herdr-app"));
    let state_dir = opts
        .state_dir
        .clone()
        .unwrap_or_else(|| resolve_state_dir(None, None, Some(home)));

    if let Some(ref clone_name) = opts.clone_layout {
        validate_clone_layout_name(clone_name).map_err(HerdrModInstallError::fatal)?;
    }

    let mut files = Vec::new();
    let mut warnings = Vec::new();
    let mut notes = Vec::new();
    let mut next = Vec::new();

    // 1. Resolve, SHA-256 verify, and write `hyphae-pane` + `hyphae-panel` as real directories
    //    via the unified plugin manager (never embedded JS/SVG in `hyp`, never symlinks).
    let mods_root = herdr_home.join("mods");
    let mod_report = install_herdr_mod_files(
        &state_dir,
        &herdr_home,
        PluginSourceOverrides {
            archive: opts.plugins_archive.as_deref(),
            from_dir: opts.plugins_dir.as_deref(),
            url: None,
        },
        opts.dry_run,
    )
    .map_err(|err| HerdrModInstallError {
        is_offline_download: err.is_offline_download_error(),
        message: err.message,
    })?;
    files.extend(mod_report.files);

    // 2. Merge `cmd-shift-h -> mod.open:hyphae-panel` into `keys.json` only if unbound.
    let keys_path = herdr_home.join("keys.json");
    let keys_action = merge_keys_json(&keys_path, opts.dry_run, &mut files, &mut notes)
        .map_err(HerdrModInstallError::fatal)?;

    // 3. Read active layout from `shared.json` and wire layout safely.
    let shared_path = herdr_home.join("shared.json");
    let active_layout = read_active_layout_name(&shared_path);
    let mut backup_path = None;

    let layout_action = if let Some(ref clone_name) = opts.clone_layout {
        clone_and_activate_layout(
            &herdr_home,
            &shared_path,
            clone_name,
            opts.dry_run,
            &mut files,
            &mut notes,
        )
        .map_err(HerdrModInstallError::fatal)?
    } else {
        wire_active_layout(
            &herdr_home,
            &active_layout,
            &opts,
            &mut backup_path,
            &mut files,
            &mut warnings,
            &mut notes,
            &mut next,
        )
        .map_err(HerdrModInstallError::fatal)?
    };

    // 4. Validate installed mods via `herdr-app check` when available.
    let mut checks = Vec::new();
    if !opts.skip_check && !opts.dry_run {
        if let Some(herdr_bin) = find_herdr_app_binary(home) {
            for mod_name in ["hyphae-pane", "hyphae-panel"] {
                let target_dir = mods_root.join(mod_name);
                let check = run_herdr_check(&herdr_bin, mod_name, &target_dir);
                if check.ran && !check.passed {
                    warnings.push(format!(
                        "herdr-app check failed for {mod_name}: {}",
                        check.output.trim()
                    ));
                }
                checks.push(check);
            }
        } else {
            notes.push(
                "herdr-app binary not found on PATH; skipped `herdr-app check` verification."
                    .to_string(),
            );
        }
    }

    Ok(HerdrModInstallOutcome {
        herdr_home,
        dry_run: opts.dry_run,
        installed_mods: vec!["hyphae-pane".to_string(), "hyphae-panel".to_string()],
        files,
        keys_action,
        active_layout,
        layout_action,
        backup_path,
        checks,
        warnings,
        notes,
        next,
    })
}

fn validate_clone_layout_name(name: &str) -> Result<(), String> {
    let trimmed = name.trim();
    if trimmed.is_empty()
        || !trimmed
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
        || !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_'))
    {
        return Err(format!(
            "invalid --clone-layout name '{name}': use ASCII letters, digits, '-' or '_'"
        ));
    }
    if SHIPPED_LAYOUTS.contains(&trimmed) {
        return Err(format!(
            "cannot use shipped Herdr layout name '{trimmed}' as --clone-layout target"
        ));
    }
    Ok(())
}

fn merge_keys_json(
    keys_path: &Path,
    dry_run: bool,
    files: &mut Vec<String>,
    notes: &mut Vec<String>,
) -> Result<String, String> {
    let mut root_map = read_json_object_or_empty(keys_path)?;
    let global_val = root_map
        .entry("global".to_string())
        .or_insert_with(|| Value::Object(Map::new()));
    let global_map = global_val
        .as_object_mut()
        .ok_or_else(|| format!("expected 'global' object in {}", keys_path.display()))?;

    if let Some(existing) = global_map.get(DEFAULT_SHORTCUT_KEY) {
        notes.push(format!(
            "Preserved existing keys.json binding for {DEFAULT_SHORTCUT_KEY} ({existing})."
        ));
        return Ok("preserved".to_string());
    }

    global_map.insert(
        DEFAULT_SHORTCUT_KEY.to_string(),
        Value::String(DEFAULT_SHORTCUT_ACTION.to_string()),
    );
    files.push(keys_path.display().to_string());

    if dry_run {
        notes.push(format!(
            "Would add global shortcut {DEFAULT_SHORTCUT_KEY} -> {DEFAULT_SHORTCUT_ACTION} to {}.",
            keys_path.display()
        ));
        return Ok("dry_run".to_string());
    }

    write_json_pretty_atomic(keys_path, &Value::Object(root_map))?;
    notes.push(format!(
        "Added global shortcut {DEFAULT_SHORTCUT_KEY} -> {DEFAULT_SHORTCUT_ACTION} in keys.json."
    ));
    Ok("added".to_string())
}

fn read_active_layout_name(shared_path: &Path) -> String {
    let Ok(raw) = fs::read_to_string(shared_path) else {
        return "main".to_string();
    };
    let Ok(val) = serde_json::from_str::<Value>(&raw) else {
        return "main".to_string();
    };
    val.get("layout")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("main")
        .to_string()
}

fn clone_and_activate_layout(
    herdr_home: &Path,
    shared_path: &Path,
    clone_name: &str,
    dry_run: bool,
    files: &mut Vec<String>,
    notes: &mut Vec<String>,
) -> Result<LayoutAction, String> {
    let layouts_dir = herdr_home.join("layouts");
    let main_path = layouts_dir.join("main.json");
    let raw_main = fs::read_to_string(&main_path).map_err(|e| {
        format!(
            "failed to read shipped Herdr layout {} for cloning: {e}",
            main_path.display()
        )
    })?;
    let mut tree: Value = serde_json::from_str(&raw_main)
        .map_err(|e| format!("invalid JSON in {}: {e}", main_path.display()))?;

    let _ = patch_layout_tree(&mut tree, true)?;

    let dst_path = layouts_dir.join(format!("{clone_name}.json"));
    files.push(dst_path.display().to_string());
    files.push(shared_path.display().to_string());

    if dry_run {
        notes.push(format!(
            "Would clone {} -> {} and activate layout '{clone_name}'.",
            main_path.display(),
            dst_path.display()
        ));
        return Ok(LayoutAction::DryRun);
    }

    write_json_pretty_atomic(&dst_path, &tree)?;

    let mut shared_map = read_json_object_or_empty(shared_path)?;
    shared_map.insert("layout".to_string(), Value::String(clone_name.to_string()));
    write_json_pretty_atomic(shared_path, &Value::Object(shared_map))?;

    notes.push(format!(
        "Cloned shipped main.json -> {} (with hyphae-pane + hyphae-panel) and activated '{clone_name}'.",
        dst_path.display()
    ));
    Ok(LayoutAction::Cloned)
}

#[allow(clippy::too_many_arguments)]
fn wire_active_layout(
    herdr_home: &Path,
    active_layout: &str,
    opts: &HerdrModInstallOptions,
    backup_path: &mut Option<PathBuf>,
    files: &mut Vec<String>,
    warnings: &mut Vec<String>,
    notes: &mut Vec<String>,
    next: &mut Vec<String>,
) -> Result<LayoutAction, String> {
    if SHIPPED_LAYOUTS.contains(&active_layout) {
        notes.push(format!(
            "Active layout '{active_layout}' is a shipped Herdr layout and was left untouched; press {DEFAULT_SHORTCUT_KEY} to open the Hyphae floating inspector."
        ));
        next.push(
            "For per-pane top-bar pills and the right dock panel, run with `--clone-layout herdr-hyphae`."
                .to_string(),
        );
        return Ok(LayoutAction::SkippedShipped);
    }

    let layout_path = herdr_home
        .join("layouts")
        .join(format!("{active_layout}.json"));

    let meta = match fs::symlink_metadata(&layout_path) {
        Ok(m) => m,
        Err(_) => {
            notes.push(format!(
                "Active layout file {} does not exist; press {DEFAULT_SHORTCUT_KEY} to open the Hyphae floating inspector.",
                layout_path.display()
            ));
            return Ok(LayoutAction::SkippedMissing);
        }
    };

    // Strict L490 symlink safety: never mutate a symlinked (git-tracked) layout without `--patch-layout`.
    if meta.file_type().is_symlink() && !opts.patch_layout {
        let target_display = fs::read_link(&layout_path)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| layout_path.display().to_string());
        if let Some(custom_mod) = detect_custom_pane_header_mod(&layout_path) {
            warnings.push(format!(
                "Active layout '{}' is a symlink (-> {target_display}) using custom pane header mod '{custom_mod}'; skipped editing it.",
                layout_path.display()
            ));
            notes.push(format!(
                "Keep `{custom_mod}` intact via `pill.js`: copy `mods/hyphae-pane/{{pill.js,shared-client.js,kv-view.js,ui-snapshot.js,hyphae.svg}}` into `mods/{custom_mod}/`, add `import {{ renderHyphaePill }} from \"./pill.js\"` + `renderHyphaePill(...)`, and add `{{ \"id\": \"hyphae\", \"type\": \"block\", \"content\": {{ \"mod\": \"hyphae-panel\" }} }}` to `panel-body.children`."
            ));
            next.push(format!(
                "Compose pill.js inside mods/{custom_mod}/ and add hyphae-panel to panel-body.children in your custom UI repo (or press {DEFAULT_SHORTCUT_KEY} for the floating inspector)."
            ));
        } else {
            warnings.push(format!(
                "Active layout '{}' is a symlink (-> {target_display}); skipped editing it.",
                layout_path.display()
            ));
            notes.push(
                "Layout JSON snippet (2 lines): set `pane.header.content.mod = \"hyphae-pane\"` and add `{ \"id\": \"hyphae\", \"type\": \"block\", \"content\": { \"mod\": \"hyphae-panel\" } }` to `panel-body.children`."
                    .to_string(),
            );
            notes.push(
                "Custom pane header composition: copy `mods/hyphae-pane/{pill.js,shared-client.js,kv-view.js,ui-snapshot.js,hyphae.svg}` into your pane mod folder and use `import { renderHyphaePill } from \"./pill.js\"` (Herdr sandboxes JS module imports per mod folder)."
                    .to_string(),
            );
            next.push(
                "Re-run with `--patch-layout` to edit the symlinked layout in place, or apply the 2-line snippet in your custom UI repo."
                    .to_string(),
            );
        }
        return Ok(LayoutAction::SkippedSymlink);
    }

    let raw = fs::read_to_string(&layout_path)
        .map_err(|e| format!("failed to read {}: {e}", layout_path.display()))?;
    let mut tree: Value = serde_json::from_str(&raw)
        .map_err(|e| format!("invalid JSON in {}: {e}", layout_path.display()))?;

    match patch_layout_tree(&mut tree, opts.force)? {
        PatchTreeResult::SkippedCustomHeader(custom_mod) => {
            warnings.push(format!(
                "Active layout '{}' uses customized pane header mod '{custom_mod}'; skipped clobbering it.",
                layout_path.display()
            ));
            notes.push(format!(
                "Compose Hyphae inside `mods/{custom_mod}/`: copy `mods/hyphae-pane/{{pill.js,shared-client.js,kv-view.js,ui-snapshot.js,hyphae.svg}}` into `mods/{custom_mod}/` and call `renderHyphaePill(...)` via `import {{ renderHyphaePill }} from \"./pill.js\"`."
            ));
            next.push(
                "Re-run with `--force-layout` to replace the custom pane header with `hyphae-pane`."
                    .to_string(),
            );
            Ok(LayoutAction::SkippedCustomHeader)
        }
        PatchTreeResult::AlreadyConfigured => {
            notes.push(format!(
                "Layout {} already configures hyphae-pane and hyphae-panel.",
                layout_path.display()
            ));
            Ok(LayoutAction::AlreadyConfigured)
        }
        PatchTreeResult::Patched => {
            if opts.dry_run {
                files.push(layout_path.display().to_string());
                notes.push(format!(
                    "Would back up and patch {} with hyphae-pane and hyphae-panel.",
                    layout_path.display()
                ));
                return Ok(LayoutAction::DryRun);
            }

            let write_target = if meta.file_type().is_symlink() {
                fs::canonicalize(&layout_path).map_err(|e| {
                    format!(
                        "failed to resolve symlinked layout {}: {e}",
                        layout_path.display()
                    )
                })?
            } else {
                layout_path.clone()
            };
            let backup_file = create_layout_backup(herdr_home, active_layout, &write_target)?;
            *backup_path = Some(backup_file.clone());
            write_json_pretty_atomic(&write_target, &tree)?;
            files.push(layout_path.display().to_string());
            notes.push(format!(
                "Backed up {} -> {} and enabled hyphae-pane + hyphae-panel.",
                layout_path.display(),
                backup_file.display()
            ));
            Ok(LayoutAction::Patched)
        }
    }
}

fn find_pane_header_mod(node: &Value) -> Option<&str> {
    let obj = node.as_object()?;
    if let Some(content) = obj.get("content").and_then(Value::as_object) {
        if content.contains_key("tab") {
            if let Some(mod_name) = content
                .get("pane")
                .and_then(Value::as_object)
                .and_then(|p| p.get("header"))
                .and_then(Value::as_object)
                .and_then(|h| h.get("content"))
                .and_then(Value::as_object)
                .and_then(|c| c.get("mod"))
                .and_then(Value::as_str)
            {
                return Some(mod_name);
            }
        }
    }
    if let Some(children) = obj.get("children").and_then(Value::as_array) {
        for child in children {
            if let Some(found) = find_pane_header_mod(child) {
                return Some(found);
            }
        }
    }
    None
}

fn detect_custom_pane_header_mod(layout_path: &Path) -> Option<String> {
    let raw = fs::read_to_string(layout_path).ok()?;
    let tree: Value = serde_json::from_str(&raw).ok()?;
    let mod_name = find_pane_header_mod(&tree)?;
    if mod_name != "pane" && mod_name != "hyphae-pane" {
        Some(mod_name.to_string())
    } else {
        None
    }
}

enum PatchTreeResult {
    Patched,
    AlreadyConfigured,
    SkippedCustomHeader(String),
}

fn patch_layout_tree(tree: &mut Value, force: bool) -> Result<PatchTreeResult, String> {
    let mut changed = false;

    if let Some(header_content) = find_pane_header_content_mut(tree) {
        if let Some(existing_mod) = header_content
            .get("mod")
            .and_then(Value::as_str)
            .map(str::to_string)
        {
            if existing_mod != "pane" && existing_mod != "hyphae-pane" && !force {
                return Ok(PatchTreeResult::SkippedCustomHeader(existing_mod));
            }
            if existing_mod != "hyphae-pane" {
                header_content.insert("mod".to_string(), Value::String("hyphae-pane".to_string()));
                changed = true;
            }
        }
    }

    if let Some(panel_body) = find_node_mut(tree, "panel-body") {
        if let Some(children) = panel_body.get_mut("children").and_then(Value::as_array_mut) {
            let has_hyphae = children
                .iter()
                .any(|c| c.get("id").and_then(Value::as_str) == Some("hyphae"));
            if !has_hyphae {
                children.push(json!({
                    "id": "hyphae",
                    "type": "block",
                    "content": {
                        "mod": "hyphae-panel"
                    }
                }));
                changed = true;
            }
        }
    }

    if changed {
        Ok(PatchTreeResult::Patched)
    } else {
        Ok(PatchTreeResult::AlreadyConfigured)
    }
}

fn find_pane_header_content_mut(node: &mut Value) -> Option<&mut Map<String, Value>> {
    let obj = node.as_object_mut()?;
    let has_tab_pane_header = obj
        .get("content")
        .and_then(Value::as_object)
        .is_some_and(|c| {
            c.contains_key("tab")
                && c.get("pane")
                    .and_then(Value::as_object)
                    .and_then(|p| p.get("header"))
                    .and_then(Value::as_object)
                    .and_then(|h| h.get("content"))
                    .and_then(Value::as_object)
                    .is_some()
        });
    if has_tab_pane_header {
        return obj
            .get_mut("content")?
            .as_object_mut()?
            .get_mut("pane")?
            .as_object_mut()?
            .get_mut("header")?
            .as_object_mut()?
            .get_mut("content")?
            .as_object_mut();
    }
    if let Some(children) = obj.get_mut("children").and_then(Value::as_array_mut) {
        for child in children {
            if let Some(found) = find_pane_header_content_mut(child) {
                return Some(found);
            }
        }
    }
    None
}

fn find_node_mut<'a>(node: &'a mut Value, target_id: &str) -> Option<&'a mut Map<String, Value>> {
    let is_match = node.get("id").and_then(Value::as_str) == Some(target_id);
    if is_match {
        return node.as_object_mut();
    }
    if let Some(children) = node.get_mut("children").and_then(Value::as_array_mut) {
        for child in children {
            if let Some(found) = find_node_mut(child, target_id) {
                return Some(found);
            }
        }
    }
    None
}

fn create_layout_backup(
    herdr_home: &Path,
    active_layout: &str,
    layout_path: &Path,
) -> Result<PathBuf, String> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let backup_dir = herdr_home.join(".backups").join(format!("{ts}"));
    fs::create_dir_all(&backup_dir)
        .map_err(|e| format!("failed to create backup dir {}: {e}", backup_dir.display()))?;
    let backup_file = backup_dir.join(format!("{active_layout}.json"));
    fs::copy(layout_path, &backup_file).map_err(|e| {
        format!(
            "failed to back up {} to {}: {e}",
            layout_path.display(),
            backup_file.display()
        )
    })?;
    Ok(backup_file)
}

fn read_json_object_or_empty(path: &Path) -> Result<Map<String, Value>, String> {
    if !path.exists() {
        return Ok(Map::new());
    }
    let raw =
        fs::read_to_string(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    match serde_json::from_str::<Value>(&raw)
        .map_err(|e| format!("invalid JSON in {}: {e}", path.display()))?
    {
        Value::Object(map) => Ok(map),
        _ => Err(format!("expected JSON object in {}", path.display())),
    }
}

fn write_json_pretty_atomic(path: &Path, value: &Value) -> Result<(), String> {
    let mut rendered = serde_json::to_string_pretty(value)
        .map_err(|e| format!("failed to serialize JSON for {}: {e}", path.display()))?;
    rendered.push('\n');
    write_file_atomic(path, rendered.as_bytes())
}

fn write_file_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    crate::config_file::write_atomic_file(path, bytes, false)
}

fn find_herdr_app_binary(home: &Path) -> Option<PathBuf> {
    if let Some(paths) = std::env::var_os("PATH") {
        if let Some(found) = search_path(
            Path::new("herdr-app"),
            &paths,
            PathSearchPolicy {
                include_empty: true,
                executable: false,
                windows_suffixes: WindowsSuffixes::None,
            },
        ) {
            return Some(found);
        }
    }
    let local_bin = home.join(".local").join("bin").join("herdr-app");
    if local_bin.is_file() {
        return Some(local_bin);
    }
    None
}

fn run_herdr_check(bin: &Path, mod_name: &str, mod_dir: &Path) -> ModCheckResult {
    match Command::new(bin).arg("check").arg(mod_dir).output() {
        Ok(out) => {
            let combined = format!(
                "{}{}",
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr)
            );
            ModCheckResult {
                mod_name: mod_name.to_string(),
                ran: true,
                passed: out.status.success(),
                output: combined.trim().to_string(),
            }
        }
        Err(e) => ModCheckResult {
            mod_name: mod_name.to_string(),
            ran: false,
            passed: false,
            output: format!("failed to invoke {}: {e}", bin.display()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_layout(pane_mod: &str) -> Value {
        json!({
            "id": "root",
            "type": "row",
            "children": [
                {
                    "id": "work",
                    "type": "column",
                    "children": [
                        {
                            "id": "main",
                            "type": "block",
                            "content": {
                                "tab": "active",
                                "pane": {
                                    "header": {
                                        "content": { "mod": pane_mod },
                                        "height": 30,
                                        "position": "top",
                                        "reveal": "always"
                                    }
                                }
                            }
                        },
                        {
                            "id": "panel",
                            "type": "column",
                            "hidden": true,
                            "children": [
                                {
                                    "id": "panel-body",
                                    "type": "stack",
                                    "active": "files",
                                    "children": [
                                        { "id": "files", "type": "block", "content": { "mod": "files" } },
                                        { "id": "changes", "type": "block", "content": { "mod": "changes" } }
                                    ]
                                }
                            ]
                        }
                    ]
                }
            ]
        })
    }

    fn repo_plugins_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("..")
            .join("plugins")
    }

    fn test_opts(tmp: &TempDir) -> HerdrModInstallOptions {
        HerdrModInstallOptions {
            skip_check: true,
            state_dir: Some(tmp.path().join("state")),
            plugins_dir: Some(repo_plugins_dir()),
            ..Default::default()
        }
    }

    fn setup_herdr_fixture(tmp: &TempDir, active_layout: &str) -> PathBuf {
        let herdr_home = tmp.path().join(".config").join("herdr-app");
        fs::create_dir_all(herdr_home.join("layouts")).unwrap();
        fs::write(
            herdr_home.join("shared.json"),
            serde_json::to_string(&json!({ "layout": active_layout, "sidebar.width": 280 }))
                .unwrap(),
        )
        .unwrap();
        fs::write(
            herdr_home.join("layouts").join("main.json"),
            serde_json::to_string_pretty(&sample_layout("pane")).unwrap(),
        )
        .unwrap();
        herdr_home
    }

    #[cfg(unix)]
    #[test]
    fn install_refuses_to_edit_symlinked_layout_by_default() {
        use std::os::unix::fs::symlink;

        let tmp = TempDir::new().unwrap();
        let herdr_home = setup_herdr_fixture(&tmp, "herdr-folders");

        // Create external git-tracked layout and symlink it into layouts/
        let external_repo = tmp.path().join("herdr-custom-ui");
        fs::create_dir_all(&external_repo).unwrap();
        let external_layout = external_repo.join("herdr-folders.json");
        let original = serde_json::to_string_pretty(&sample_layout("pane")).unwrap();
        fs::write(&external_layout, &original).unwrap();
        symlink(
            &external_layout,
            herdr_home.join("layouts").join("herdr-folders.json"),
        )
        .unwrap();

        let outcome = install_herdr_mod(tmp.path(), test_opts(&tmp)).unwrap();

        assert_eq!(outcome.layout_action, LayoutAction::SkippedSymlink);
        assert_eq!(fs::read_to_string(&external_layout).unwrap(), original);
        assert!(outcome.notes.iter().any(|n| n.contains("renderHyphaePill")));
        assert!(outcome.notes.iter().any(|n| n.contains("hyphae-pane")));
        assert!(herdr_home.join("mods/hyphae-pane/pill.js").is_file());
        assert!(herdr_home.join("mods/hyphae-panel/main.js").is_file());
        assert!(
            !fs::symlink_metadata(herdr_home.join("mods/hyphae-pane"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_custom_header_advises_pill_js_and_patch_layout_preserves_symlink() {
        use std::os::unix::fs::symlink;

        // 1. Symlinked layout using custom header `folder-pane`: must advise pill.js composition
        //    WITHOUT suggesting overwriting `pane.header.content.mod = "hyphae-pane"`.
        let tmp = TempDir::new().unwrap();
        let herdr_home = setup_herdr_fixture(&tmp, "herdr-folders");
        let external_repo = tmp.path().join("herdr-custom-ui");
        fs::create_dir_all(&external_repo).unwrap();
        let external_custom = external_repo.join("herdr-folders.json");
        let original_custom = serde_json::to_string_pretty(&sample_layout("folder-pane")).unwrap();
        fs::write(&external_custom, &original_custom).unwrap();
        let custom_link = herdr_home.join("layouts").join("herdr-folders.json");
        symlink(&external_custom, &custom_link).unwrap();

        let skipped = install_herdr_mod(tmp.path(), test_opts(&tmp)).unwrap();

        assert_eq!(skipped.layout_action, LayoutAction::SkippedSymlink);
        assert_eq!(
            fs::read_to_string(&external_custom).unwrap(),
            original_custom
        );
        assert!(
            skipped
                .warnings
                .iter()
                .any(|w| w.contains("folder-pane") && w.contains("symlink")),
            "warning must name custom header mod and symlink: {:?}",
            skipped.warnings
        );
        assert!(
            skipped.notes.iter().any(|n| n.contains("pill.js")
                && n.contains("renderHyphaePill")
                && n.contains("mods/folder-pane/")
                && n.contains("hyphae-panel")),
            "note must guide pill.js composition + hyphae-panel: {:?}",
            skipped.notes
        );
        assert!(
            skipped
                .next
                .iter()
                .any(|n| n.contains("mods/folder-pane/") && n.contains("panel-body.children")),
            "next must mention mods/folder-pane/ + panel-body.children: {:?}",
            skipped.next
        );
        for msg in skipped
            .warnings
            .iter()
            .chain(skipped.notes.iter())
            .chain(skipped.next.iter())
        {
            assert!(
                !msg.contains("pane.header.content.mod = \"hyphae-pane\""),
                "must NOT recommend replacing custom pane header mod: {msg}"
            );
        }

        // 2. `--patch-layout` on a symlinked default-header layout updates target atomically
        //    while preserving the symlink itself 100% intact.
        let tmp2 = TempDir::new().unwrap();
        let herdr_home2 = setup_herdr_fixture(&tmp2, "git-layout");
        let ext_repo2 = tmp2.path().join("herdr-dotfiles");
        fs::create_dir_all(&ext_repo2).unwrap();
        let ext_default = ext_repo2.join("git-layout.json");
        fs::write(
            &ext_default,
            serde_json::to_string_pretty(&sample_layout("pane")).unwrap(),
        )
        .unwrap();
        let link2 = herdr_home2.join("layouts").join("git-layout.json");
        symlink(&ext_default, &link2).unwrap();

        let patched = install_herdr_mod(
            tmp2.path(),
            HerdrModInstallOptions {
                patch_layout: true,
                ..test_opts(&tmp2)
            },
        )
        .unwrap();
        assert_eq!(patched.layout_action, LayoutAction::Patched);
        assert!(patched.backup_path.as_ref().is_some_and(|p| p.is_file()));
        assert!(
            fs::symlink_metadata(&link2)
                .unwrap()
                .file_type()
                .is_symlink(),
            "--patch-layout must preserve the layout symlink intact"
        );
        let updated: Value =
            serde_json::from_str(&fs::read_to_string(&ext_default).unwrap()).unwrap();
        assert_eq!(
            updated["children"][0]["children"][0]["content"]["pane"]["header"]["content"]["mod"],
            "hyphae-pane"
        );
    }

    #[test]
    fn install_refuses_to_clobber_custom_pane_header_without_force() {
        let tmp = TempDir::new().unwrap();
        let herdr_home = setup_herdr_fixture(&tmp, "my-custom");
        let layout_path = herdr_home.join("layouts/my-custom.json");
        let original = serde_json::to_string_pretty(&sample_layout("fancy-pane")).unwrap();
        fs::write(&layout_path, &original).unwrap();

        let first = install_herdr_mod(tmp.path(), test_opts(&tmp)).unwrap();
        assert_eq!(first.layout_action, LayoutAction::SkippedCustomHeader);
        assert_eq!(fs::read_to_string(&layout_path).unwrap(), original);
        assert!(first.notes.iter().any(|n| n.contains("fancy-pane")));
        assert!(first.notes.iter().any(|n| n.contains("renderHyphaePill")));

        // With force=true, it backs up and patches cleanly.
        let forced = install_herdr_mod(
            tmp.path(),
            HerdrModInstallOptions {
                force: true,
                ..test_opts(&tmp)
            },
        )
        .unwrap();
        assert_eq!(forced.layout_action, LayoutAction::Patched);
        assert!(forced.backup_path.as_ref().is_some_and(|p| p.is_file()));
        let patched: Value =
            serde_json::from_str(&fs::read_to_string(&layout_path).unwrap()).unwrap();
        assert_eq!(
            patched["children"][0]["children"][0]["content"]["pane"]["header"]["content"]["mod"],
            "hyphae-pane"
        );
    }

    #[test]
    fn install_backs_up_and_patches_personal_layout_idempotently() {
        let tmp = TempDir::new().unwrap();
        let herdr_home = setup_herdr_fixture(&tmp, "personal");
        let layout_path = herdr_home.join("layouts/personal.json");
        fs::write(
            &layout_path,
            serde_json::to_string_pretty(&sample_layout("pane")).unwrap(),
        )
        .unwrap();

        let first = install_herdr_mod(tmp.path(), test_opts(&tmp)).unwrap();
        assert_eq!(first.layout_action, LayoutAction::Patched);
        assert!(first.backup_path.as_ref().is_some_and(|p| p.is_file()));

        let patched: Value =
            serde_json::from_str(&fs::read_to_string(&layout_path).unwrap()).unwrap();
        assert_eq!(
            patched["children"][0]["children"][0]["content"]["pane"]["header"]["content"]["mod"],
            "hyphae-pane"
        );
        let children = patched["children"][0]["children"][1]["children"][0]["children"]
            .as_array()
            .unwrap();
        assert_eq!(
            children
                .iter()
                .filter(|c| c.get("id").and_then(Value::as_str) == Some("hyphae"))
                .count(),
            1
        );

        // Second run must be idempotent and report AlreadyConfigured without duplicating nodes.
        let second = install_herdr_mod(tmp.path(), test_opts(&tmp)).unwrap();
        assert_eq!(second.layout_action, LayoutAction::AlreadyConfigured);
        assert!(second.backup_path.is_none());
        let after_second: Value =
            serde_json::from_str(&fs::read_to_string(&layout_path).unwrap()).unwrap();
        let children2 = after_second["children"][0]["children"][1]["children"][0]["children"]
            .as_array()
            .unwrap();
        assert_eq!(
            children2
                .iter()
                .filter(|c| c.get("id").and_then(Value::as_str) == Some("hyphae"))
                .count(),
            1
        );
    }

    #[test]
    fn install_preserves_shipped_main_and_supports_clone_layout() {
        let tmp = TempDir::new().unwrap();
        let herdr_home = setup_herdr_fixture(&tmp, "main");
        let main_before = fs::read_to_string(herdr_home.join("layouts/main.json")).unwrap();

        let default_run = install_herdr_mod(tmp.path(), test_opts(&tmp)).unwrap();
        assert_eq!(default_run.layout_action, LayoutAction::SkippedShipped);
        assert_eq!(
            fs::read_to_string(herdr_home.join("layouts/main.json")).unwrap(),
            main_before
        );

        // Reject invalid or shipped clone names.
        assert!(
            install_herdr_mod(
                tmp.path(),
                HerdrModInstallOptions {
                    clone_layout: Some("main".to_string()),
                    ..test_opts(&tmp)
                }
            )
            .is_err()
        );
        assert!(
            install_herdr_mod(
                tmp.path(),
                HerdrModInstallOptions {
                    clone_layout: Some("../evil".to_string()),
                    ..test_opts(&tmp)
                }
            )
            .is_err()
        );

        // Valid clone creates layouts/herdr-hyphae.json and updates shared.json cleanly.
        let cloned = install_herdr_mod(
            tmp.path(),
            HerdrModInstallOptions {
                clone_layout: Some("herdr-hyphae".to_string()),
                ..test_opts(&tmp)
            },
        )
        .unwrap();
        assert_eq!(cloned.layout_action, LayoutAction::Cloned);
        assert_eq!(
            fs::read_to_string(herdr_home.join("layouts/main.json")).unwrap(),
            main_before
        );
        let cloned_doc: Value = serde_json::from_str(
            &fs::read_to_string(herdr_home.join("layouts/herdr-hyphae.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            cloned_doc["children"][0]["children"][0]["content"]["pane"]["header"]["content"]["mod"],
            "hyphae-pane"
        );
        let shared_doc: Value =
            serde_json::from_str(&fs::read_to_string(herdr_home.join("shared.json")).unwrap())
                .unwrap();
        assert_eq!(shared_doc["layout"], "herdr-hyphae");
        assert_eq!(shared_doc["sidebar.width"], 280);
    }

    #[test]
    fn install_merges_keys_json_without_clobbering_existing_binding() {
        let tmp = TempDir::new().unwrap();
        let herdr_home = setup_herdr_fixture(&tmp, "main");
        let keys_path = herdr_home.join("keys.json");

        // Initial keys.json without cmd-shift-h -> adds cmd-shift-h and preserves other sections.
        fs::write(
            &keys_path,
            serde_json::to_string_pretty(&json!({
                "global": { "cmd-t": "tab.new" },
                "terminal": { "cmd-c": "terminal.copy" }
            }))
            .unwrap(),
        )
        .unwrap();

        let added = install_herdr_mod(tmp.path(), test_opts(&tmp)).unwrap();
        assert_eq!(added.keys_action, "added");
        let keys_after: Value =
            serde_json::from_str(&fs::read_to_string(&keys_path).unwrap()).unwrap();
        assert_eq!(keys_after["global"]["cmd-shift-h"], "mod.open:hyphae-panel");
        assert_eq!(keys_after["global"]["cmd-t"], "tab.new");
        assert_eq!(keys_after["terminal"]["cmd-c"], "terminal.copy");

        // Existing custom cmd-shift-h binding -> MUST NOT be overwritten!
        fs::write(
            &keys_path,
            serde_json::to_string_pretty(&json!({
                "global": { "cmd-shift-h": "mod.open:my-history" }
            }))
            .unwrap(),
        )
        .unwrap();
        let preserved = install_herdr_mod(tmp.path(), test_opts(&tmp)).unwrap();
        assert_eq!(preserved.keys_action, "preserved");
        let keys_final: Value =
            serde_json::from_str(&fs::read_to_string(&keys_path).unwrap()).unwrap();
        assert_eq!(keys_final["global"]["cmd-shift-h"], "mod.open:my-history");
    }

    #[test]
    fn dry_run_does_not_mutate_disk_and_pinned_herdr_assets_are_present() {
        let spec = crate::plugin_cmd::pinned_spec_for("herdr-mod").expect("herdr-mod pinned spec");
        assert_eq!(spec.files.len(), 13);
        assert_eq!(spec.tree_sha256.len(), 64);

        let tmp = TempDir::new().unwrap();
        let herdr_home = tmp.path().join(".config").join("herdr-app");
        let outcome = install_herdr_mod(
            tmp.path(),
            HerdrModInstallOptions {
                dry_run: true,
                ..test_opts(&tmp)
            },
        )
        .unwrap();
        assert_eq!(outcome.keys_action, "dry_run");
        assert!(!herdr_home.exists());
    }
}
