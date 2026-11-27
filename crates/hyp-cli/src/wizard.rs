//! Interactive Fullscreen Mycelium Onboarding Wizard & `hyp-setup` Agent Concierge.
//!
//! Pure Rust (zero external TUI crates):
//! - Fullscreen alternate-screen (`\x1b[?1049h` / `\x1b[?1049l`) RAII guard and Unix `/dev/tty`
//!   raw-mode arrow-key navigation guard (`stty -g` -> `stty raw -echo` -> unconditional restore).
//! - Responsive 24-bit ANSI truecolor (with 256-color / plain fallback) dot-matrix organic
//!   mycelium canvas that scales to fill the detected terminal viewport.
//! - Zero-typing highlighted menus showing only harnesses detected on this machine, including a
//!   native Herdr (`hc templates --json`) launch-template picker sub-screen.
//! - Clean two-path handoff: Path A auto-launches interactive CLIs / Herdr templates after
//!   installing `hyp-setup/SKILL.md`; Path B installs the skill and presents an interactive
//!   copy-paste guide screen (with clipboard support) for OpenClaw, T3 Code, and config-only CLIs.

use crate::config_file::{
    load_node_or_legacy_config, resolve_config_path_for_read, write_atomic_file,
};
use crate::setup::{
    CodexMcpConfig, HarnessDiagnostic, OnboardArgs, OpenClawDeliveryMode, apply_openclaw_config,
    canonical_dedup_key, codex_mcp_config_path, default_node_id, detect_harness_statuses,
    read_openclaw_hyphae_preferences, resolve_claude_profiles,
};
use crate::term::AltScreenGuard;
#[cfg(unix)]
use crate::term::RawTtyGuard;
use crate::ui::{
    CliError, EXIT_ERROR, EXIT_OK, JsonEnvelope, print_json, print_next_steps, print_warnings,
};
use hyp_harness_ipc::protocol::HarnessKind;
use hyp_harness_transport::executable::{
    PathSearchPolicy, WindowsSuffixes, find_in_path as search_path,
};
use hyp_mycelium::{ColorMode, render_frame, rgb_to_ansi256};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs;
#[cfg(unix)]
use std::io::BufReader;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

/// Embedded pure-Rust v2 `hyp-setup` concierge skill (zero network access needed).
pub const HYPHAE_SETUP_SKILL_MD: &str = include_str!("../../../skills/hyp-setup/SKILL.md");

pub const DEFAULT_CANVAS_WIDTH: usize = 54;
pub const DEFAULT_CANVAS_HEIGHT: usize = 18;
pub const DEFAULT_TOTAL_FRAMES: usize = 32;
const FRAME_DELAY_MS: u64 = 62;

// Shared botanical chrome accents used by menu, confirm, and guide renderers.
const RGB_HYPHAE_SAGE: (u8, u8, u8) = (176, 214, 178);
const RGB_PULSE_IVORY: (u8, u8, u8) = (240, 246, 238);
const RGB_NODE_AMBER: (u8, u8, u8) = (236, 206, 132);

// Fullscreen TUI botanical chrome palette.
const RGB_UI_MUTED: (u8, u8, u8) = (128, 148, 138);
#[cfg_attr(not(unix), allow(dead_code))]
const RGB_UI_BORDER: (u8, u8, u8) = (84, 116, 98);
#[cfg_attr(not(unix), allow(dead_code))]
const RGB_UI_HIGHLIGHT_BG: (u8, u8, u8) = (36, 56, 46);
#[cfg_attr(not(unix), allow(dead_code))]
const RGB_UI_TAG_LAUNCH: (u8, u8, u8) = (158, 214, 168);
#[cfg_attr(not(unix), allow(dead_code))]
const RGB_UI_TAG_GUIDE: (u8, u8, u8) = (236, 206, 132);
#[cfg_attr(not(unix), allow(dead_code))]
const RGB_UI_TAG_LOCAL: (u8, u8, u8) = (146, 176, 164);

/// Interactive agent CLIs that `hyp onboard` can hand off to directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LaunchableHarness {
    Claude,
    Codex,
    Antigravity,
    Opencode,
    Cursor,
    Gemini,
}

impl LaunchableHarness {
    pub const ALL: [Self; 6] = [
        Self::Claude,
        Self::Codex,
        Self::Antigravity,
        Self::Opencode,
        Self::Cursor,
        Self::Gemini,
    ];

    pub const fn kind(self) -> HarnessKind {
        match self {
            Self::Claude => HarnessKind::Claude,
            Self::Codex => HarnessKind::Codex,
            Self::Antigravity => HarnessKind::Antigravity,
            Self::Opencode => HarnessKind::Opencode,
            Self::Cursor => HarnessKind::Cursor,
            Self::Gemini => HarnessKind::Gemini,
        }
    }

    pub const fn id(self) -> &'static str {
        self.kind().as_str()
    }

    pub fn display_name(self) -> &'static str {
        &crate::harness_spec::spec(self.kind()).label
    }

    pub fn binary_name(self) -> &'static str {
        crate::harness_spec::spec(self.kind())
            .cli
            .as_deref()
            .expect("launchable CLI")
    }

    pub fn parse_alias(raw: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|harness| crate::harness_spec::spec(harness.kind()).matches_alias(raw.trim()))
    }

    /// Profile-aware primary skill path for `hyp-setup/SKILL.md` (honors `$CLAUDE_CONFIG_DIR`
    /// and `--claude-config-dir` for Claude Code).
    pub fn primary_skill_path_for(
        self,
        home: &Path,
        explicit_home: bool,
        claude_config_dir: Option<&Path>,
    ) -> PathBuf {
        if self == Self::Claude {
            if let Some(profile) = resolve_claude_profiles(home, explicit_home, claude_config_dir)
                .into_iter()
                .next()
            {
                return profile.setup_skill_path();
            }
        }
        crate::harness_spec::spec(self.kind())
            .setup_skill(home)
            .expect("launchable setup skill")
    }

    /// Additional cross-tool skill paths to populate alongside `primary_skill_path`.
    #[allow(dead_code)]
    pub fn extra_skill_paths(self, home: &Path) -> Vec<PathBuf> {
        self.extra_skill_paths_for(home, true, None)
    }

    /// Profile-aware additional skill paths to populate alongside `primary_skill_path_for`.
    pub fn extra_skill_paths_for(
        self,
        home: &Path,
        explicit_home: bool,
        claude_config_dir: Option<&Path>,
    ) -> Vec<PathBuf> {
        match self {
            Self::Claude => {
                let profiles = resolve_claude_profiles(home, explicit_home, claude_config_dir);
                let mut seen = BTreeSet::new();
                let mut extras = Vec::new();
                for (idx, profile) in profiles.into_iter().enumerate() {
                    let path = profile.setup_skill_path();
                    if seen.insert(canonical_dedup_key(&path)) && idx > 0 {
                        extras.push(path);
                    }
                }
                extras
            }
            _ => Vec::new(),
        }
    }

    /// Exact verified interactive CLI command & arguments for launching this harness.
    pub fn build_launch_spec(self, prompt: &str) -> LaunchSpec {
        let args = match self {
            Self::Claude => vec![prompt.to_string()],
            Self::Codex => vec![prompt.to_string()],
            // CRITICAL: `--prompt` is print mode; `--prompt-interactive` keeps an interactive session!
            Self::Antigravity => vec!["--prompt-interactive".to_string(), prompt.to_string()],
            Self::Opencode => vec!["--prompt".to_string(), prompt.to_string()],
            Self::Cursor => vec![prompt.to_string()],
            Self::Gemini => vec!["-i".to_string(), prompt.to_string()],
        };
        LaunchSpec {
            program: self.binary_name(),
            args,
        }
    }
}

/// Non-launchable Desktop/IDE/GUI/daemon harnesses (or CLI harnesses whose binary is not on PATH)
/// handled cleanly via Path B (install `hyp-setup` skill + interactive copy-paste / deep-link guide).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ManualGuideHarness {
    ClaudeDesktop,
    CodexDesktop,
    OpenCodeDesktop,
    CursorIde,
    Openclaw,
    T3,
    ConfigOnlyCli(LaunchableHarness),
}

impl ManualGuideHarness {
    pub const fn kind(self) -> HarnessKind {
        match self {
            Self::ClaudeDesktop => HarnessKind::Claude,
            Self::CodexDesktop => HarnessKind::Codex,
            Self::OpenCodeDesktop => HarnessKind::Opencode,
            Self::CursorIde => HarnessKind::Cursor,
            Self::Openclaw => HarnessKind::Openclaw,
            Self::T3 => HarnessKind::T3,
            Self::ConfigOnlyCli(lh) => lh.kind(),
        }
    }

    pub const fn id(self) -> &'static str {
        match self {
            Self::ClaudeDesktop => "claude-desktop",
            Self::CodexDesktop => "codex-desktop",
            Self::OpenCodeDesktop => "opencode-desktop",
            Self::CursorIde => "cursor",
            Self::Openclaw => "openclaw",
            Self::T3 => "t3",
            Self::ConfigOnlyCli(lh) => lh.id(),
        }
    }

    pub fn display_name(self) -> &'static str {
        match self {
            Self::ClaudeDesktop => "Claude Desktop",
            Self::CodexDesktop => "Codex Desktop",
            Self::OpenCodeDesktop => "OpenCode Desktop",
            Self::CursorIde => "Cursor (IDE)",
            Self::Openclaw => "OpenClaw",
            Self::T3 => "T3 Code",
            Self::ConfigOnlyCli(lh) => lh.display_name(),
        }
    }

    pub fn parse_alias(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "claude-desktop" | "claude_desktop" => Some(Self::ClaudeDesktop),
            "codex-desktop" | "codex_desktop" => Some(Self::CodexDesktop),
            "opencode-desktop" | "opencode_desktop" => Some(Self::OpenCodeDesktop),
            "cursor-ide" | "cursor_ide" => Some(Self::CursorIde),
            "openclaw" => Some(Self::Openclaw),
            "t3" | "t3-code" | "t3code" => Some(Self::T3),
            _ => None,
        }
    }

    #[allow(dead_code)]
    pub fn primary_skill_path(self, home: &Path) -> PathBuf {
        self.primary_skill_path_for(home, true, None)
    }

    pub fn primary_skill_path_for(
        self,
        home: &Path,
        explicit_home: bool,
        claude_config_dir: Option<&Path>,
    ) -> PathBuf {
        if self.kind() == HarnessKind::Claude {
            return LaunchableHarness::Claude.primary_skill_path_for(
                home,
                explicit_home,
                claude_config_dir,
            );
        }
        crate::harness_spec::spec(self.kind())
            .setup_skill(home)
            .expect("manual guide setup skill")
    }

    #[allow(dead_code)]
    pub fn extra_skill_paths(self, home: &Path) -> Vec<PathBuf> {
        self.extra_skill_paths_for(home, true, None)
    }

    pub fn extra_skill_paths_for(
        self,
        home: &Path,
        explicit_home: bool,
        claude_config_dir: Option<&Path>,
    ) -> Vec<PathBuf> {
        match self {
            Self::ClaudeDesktop => LaunchableHarness::Claude.extra_skill_paths_for(
                home,
                explicit_home,
                claude_config_dir,
            ),
            Self::CodexDesktop => LaunchableHarness::Codex.extra_skill_paths(home),
            Self::OpenCodeDesktop => vec![shared_setup_skill_path(home)],
            Self::CursorIde => Vec::new(),
            Self::Openclaw => Vec::new(),
            // Claude children discover the skill through their active Claude profiles.
            Self::T3 => {
                let mut seen = BTreeSet::new();
                let mut out = Vec::new();
                for profile in resolve_claude_profiles(home, explicit_home, claude_config_dir) {
                    let path = profile.setup_skill_path();
                    if seen.insert(canonical_dedup_key(&path)) {
                        out.push(path);
                    }
                }
                out
            }
            Self::ConfigOnlyCli(lh) => {
                lh.extra_skill_paths_for(home, explicit_home, claude_config_dir)
            }
        }
    }

    /// Human-friendly step 1 instruction tailored to this Desktop/IDE/GUI harness.
    pub fn open_instruction(self) -> String {
        match self {
            Self::ClaudeDesktop => "Open Claude Desktop and start a new chat.".to_string(),
            Self::CodexDesktop => "Open Codex Desktop and start a new thread.".to_string(),
            Self::OpenCodeDesktop => "Open OpenCode Desktop and start a new session.".to_string(),
            Self::CursorIde => "Open Cursor and start a new Cursor Agent thread.".to_string(),
            Self::Openclaw => "Open OpenClaw and start a new thread/session.".to_string(),
            Self::T3 => "Open T3 Code and start a new thread/session.".to_string(),
            Self::ConfigOnlyCli(lh) => {
                format!("Open {} and start a new thread/session.", lh.display_name())
            }
        }
    }

    /// Step 1 instruction shown immediately after updating a Desktop app's MCP configuration.
    pub fn restart_instruction(self) -> String {
        match self {
            Self::ClaudeDesktop => {
                "Restart Claude Desktop so it loads the hyphae MCP server.".to_string()
            }
            Self::CodexDesktop => {
                "Restart Codex Desktop so it loads the hyphae MCP server.".to_string()
            }
            Self::Openclaw => {
                "Reload or restart OpenClaw so it loads the Hyphae plugin & MCP server.".to_string()
            }
            other => other.open_instruction(),
        }
    }

    /// Optional MCP config hint & snippet (used for Claude Desktop & Codex Desktop).
    pub fn mcp_config_note(self, home: &Path, cli_bin: &str) -> Option<(PathBuf, String)> {
        match self {
            Self::ClaudeDesktop => {
                let path = claude_desktop_config_path(home);
                let snippet = r#"{ "mcpServers": { "hyphae": { "command": "hyp", "args": ["mcp", "--ephemeral"] } } }"#;
                Some((path, snippet.to_owned()))
            }
            Self::CodexDesktop => {
                let path = codex_mcp_config_path(home);
                let snippet = CodexMcpConfig::read(&path, cli_bin, None).ok()?.block;
                Some((path, snippet))
            }
            _ => None,
        }
    }
}

/// Platform-appropriate `claude_desktop_config.json` path under `home` (or `%APPDATA%` on Windows
/// when `%APPDATA%` lives inside `home`, keeping isolated `--home <tmp>` tests hermetic).
pub fn claude_desktop_config_path(home: &Path) -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        home.join("Library")
            .join("Application Support")
            .join("Claude")
            .join("claude_desktop_config.json")
    }
    #[cfg(windows)]
    {
        if let Some(appdata) = std::env::var_os("APPDATA") {
            let appdata_path = PathBuf::from(appdata);
            if appdata_path.starts_with(home) {
                return appdata_path
                    .join("Claude")
                    .join("claude_desktop_config.json");
            }
        }
        home.join("AppData")
            .join("Roaming")
            .join("Claude")
            .join("claude_desktop_config.json")
    }
    #[cfg(not(any(target_os = "macos", windows)))]
    {
        home.join(".config")
            .join("Claude")
            .join("claude_desktop_config.json")
    }
}

/// Preview plan for an interactive confirm-before-write Desktop MCP configuration update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopMcpPlan {
    pub harness: ManualGuideHarness,
    pub config_path: PathBuf,
    pub already_configured: bool,
    pub preview_lines: Vec<String>,
}

/// Outcome of applying a Desktop MCP configuration update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesktopMcpApplyResult {
    pub config_path: PathBuf,
    pub created: bool,
    pub already_configured: bool,
}

/// MCP config status displayed on the `ManualGuide` handoff screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesktopMcpStatus {
    NotApplicable,
    Applied(PathBuf),
    AlreadyConfigured(PathBuf),
    Skipped,
}

fn command_points_to_hyp(cmd: &str, cli_bin: &str) -> bool {
    let trimmed = cmd.trim();
    if trimmed.is_empty() {
        return false;
    }
    if trimmed == cli_bin.trim() {
        return true;
    }
    let basename = trimmed
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(trimmed)
        .to_ascii_lowercase();
    basename == "hyp" || basename == "hyp.exe"
}

fn claude_mcp_servers_has_hyphae(
    servers: &serde_json::Map<String, serde_json::Value>,
    cli_bin: &str,
) -> bool {
    let Some(entry) = servers.get("hyphae").and_then(serde_json::Value::as_object) else {
        return false;
    };
    let cmd_ok = entry
        .get("command")
        .and_then(serde_json::Value::as_str)
        .is_some_and(|cmd| command_points_to_hyp(cmd, cli_bin));
    if !cmd_ok {
        return false;
    }
    entry
        .get("args")
        .and_then(serde_json::Value::as_array)
        .is_some_and(|args| {
            args.first()
                .and_then(serde_json::Value::as_str)
                .is_some_and(|a| a == "mcp")
        })
}

/// Inspects the target Desktop app MCP configuration file and builds a safe confirm-before-write
/// preview plan for Claude Desktop (`claude_desktop_config.json`) and Codex Desktop (`~/.codex/config.toml`).
pub fn inspect_desktop_mcp_plan(
    harness: ManualGuideHarness,
    home: &Path,
    cli_bin: &str,
) -> Option<DesktopMcpPlan> {
    match harness {
        ManualGuideHarness::ClaudeDesktop => {
            let config_path = claude_desktop_config_path(home);
            let already_configured = if config_path.exists() {
                fs::read_to_string(&config_path)
                    .ok()
                    .and_then(|raw| serde_json::from_str::<serde_json::Value>(&raw).ok())
                    .and_then(|val| {
                        val.get("mcpServers")
                            .and_then(serde_json::Value::as_object)
                            .map(|servers| claude_mcp_servers_has_hyphae(servers, cli_bin))
                    })
                    .unwrap_or(false)
            } else {
                false
            };
            let cmd_json = serde_json::to_string(cli_bin).unwrap_or_else(|_| "\"hyp\"".to_string());
            let preview_lines = vec![
                "Merge mcpServers.hyphae (preserves existing servers):".to_string(),
                "{".to_string(),
                "  \"mcpServers\": {".to_string(),
                format!(
                    "    \"hyphae\": {{ \"command\": {cmd_json}, \"args\": [\"mcp\", \"--ephemeral\"] }}"
                ),
                "  }".to_string(),
                "}".to_string(),
            ];
            Some(DesktopMcpPlan {
                harness,
                config_path,
                already_configured,
                preview_lines,
            })
        }
        ManualGuideHarness::CodexDesktop => {
            let config_path = codex_mcp_config_path(home);
            let config = CodexMcpConfig::read(&config_path, cli_bin, None);
            let already_configured = config
                .as_ref()
                .is_ok_and(|config| config.already_configured);
            let preview_lines = match config {
                Ok(config) => std::iter::once(
                    "Configure [mcp_servers.hyphae] (preserves existing Codex settings):"
                        .to_string(),
                )
                .chain(config.block.lines().map(ToOwned::to_owned))
                .collect(),
                Err(err) => vec![err],
            };
            Some(DesktopMcpPlan {
                harness,
                config_path,
                already_configured,
                preview_lines,
            })
        }
        _ => None,
    }
}

/// Atomically merges the Hyphae MCP server entry into Claude Desktop's `claude_desktop_config.json`
/// or Codex Desktop's `~/.codex/config.toml`, preserving all existing user settings and failing
/// closed on malformed JSON.
pub fn apply_desktop_mcp_config(
    harness: ManualGuideHarness,
    home: &Path,
    cli_bin: &str,
) -> Result<DesktopMcpApplyResult, String> {
    match harness {
        ManualGuideHarness::ClaudeDesktop => {
            let config_path = claude_desktop_config_path(home);
            let existed = config_path.exists();
            if let Some(manager) = crate::skillshare::Skillshare::detect(home) {
                let already_configured = inspect_desktop_mcp_plan(harness, home, cli_bin)
                    .is_some_and(|plan| plan.already_configured);
                manager.for_claude_desktop().configure_mcp(
                    HarnessKind::Claude,
                    &config_path,
                    cli_bin,
                    None,
                    false,
                )?;
                return Ok(DesktopMcpApplyResult {
                    config_path,
                    created: !existed,
                    already_configured,
                });
            }
            let mut doc: serde_json::Map<String, serde_json::Value> = if existed {
                let raw = fs::read_to_string(&config_path)
                    .map_err(|e| format!("failed to read {}: {e}", config_path.display()))?;
                match serde_json::from_str::<serde_json::Value>(&raw) {
                    Ok(serde_json::Value::Object(map)) => map,
                    Ok(_) => {
                        return Err(format!(
                            "refusing to overwrite {}: expected top-level JSON object",
                            config_path.display()
                        ));
                    }
                    Err(e) => {
                        return Err(format!(
                            "refusing to overwrite malformed JSON in {}: {e}",
                            config_path.display()
                        ));
                    }
                }
            } else {
                serde_json::Map::new()
            };

            let mut servers = match doc.get("mcpServers") {
                None | Some(serde_json::Value::Null) => serde_json::Map::new(),
                Some(serde_json::Value::Object(map)) => map.clone(),
                Some(_) => {
                    return Err(format!(
                        "refusing to modify {}: 'mcpServers' must be a JSON object",
                        config_path.display()
                    ));
                }
            };

            let already_configured = claude_mcp_servers_has_hyphae(&servers, cli_bin);
            servers.insert(
                "hyphae".to_string(),
                json!({
                    "command": cli_bin,
                    "args": ["mcp", "--ephemeral"]
                }),
            );
            doc.insert("mcpServers".to_string(), serde_json::Value::Object(servers));

            let mut text = serde_json::to_string_pretty(&serde_json::Value::Object(doc))
                .map_err(|e| format!("failed to serialize {}: {e}", config_path.display()))?;
            text.push('\n');
            write_atomic_file(&config_path, text.as_bytes(), false)?;

            Ok(DesktopMcpApplyResult {
                config_path,
                created: !existed,
                already_configured,
            })
        }
        ManualGuideHarness::CodexDesktop => {
            let config_path = codex_mcp_config_path(home);
            let config = CodexMcpConfig::read(&config_path, cli_bin, None)?;
            config.write(&config_path, false)?;
            Ok(DesktopMcpApplyResult {
                config_path,
                created: config.created,
                already_configured: config.already_configured,
            })
        }
        other => Err(format!(
            "automatic MCP config update is not supported for {}",
            other.display_name()
        )),
    }
}

/// RFC 3986 percent-encoding for URI query parameters (encodes everything except unreserved
/// `ALPHA / DIGIT / "-" / "." / "_" / "~"`).
pub fn percent_encode_uri_component(input: &str) -> String {
    hyp_node::engine::http_util::percent_encode(input)
}

fn percent_encode_uri_path(path: &Path) -> String {
    let raw = path.to_string_lossy();
    let normalized = raw.replace('\\', "/");
    normalized
        .split('/')
        .filter(|seg| !seg.is_empty())
        .map(percent_encode_uri_component)
        .collect::<Vec<String>>()
        .join("/")
}

fn sanitize_http_url(raw: Option<&str>) -> Option<String> {
    let candidate = raw?.trim();
    if candidate.is_empty()
        || candidate.chars().any(char::is_whitespace)
        || candidate.chars().any(char::is_control)
    {
        return None;
    }
    let low = candidate.to_ascii_lowercase();
    if low.starts_with("http://") || low.starts_with("https://") {
        Some(candidate.to_string())
    } else {
        None
    }
}

/// Builds a Desktop / IDE deep-link URL for one-key `[o] Open in App` handoff.
pub fn build_manual_guide_deeplink(
    harness: ManualGuideHarness,
    prompt: &str,
    cwd: Option<&Path>,
    opencode_server_url: Option<&str>,
    t3_url: Option<&str>,
) -> Option<String> {
    match harness {
        ManualGuideHarness::ClaudeDesktop => Some(format!(
            "claude://claude.ai/new?q={}",
            percent_encode_uri_component(prompt)
        )),
        ManualGuideHarness::CodexDesktop => Some(format!(
            "codex://threads/new?prompt={}",
            percent_encode_uri_component(prompt)
        )),
        ManualGuideHarness::OpenCodeDesktop => {
            if let Some(url) = sanitize_http_url(opencode_server_url) {
                return Some(url);
            }
            let encoded_prompt = percent_encode_uri_component(prompt);
            if let Some(dir) = cwd.filter(|p| !p.as_os_str().is_empty()) {
                let dir_str = dir.to_string_lossy();
                Some(format!(
                    "opencode://new-session?directory={}&prompt={encoded_prompt}",
                    percent_encode_uri_component(&dir_str)
                ))
            } else {
                Some(format!("opencode://new-session?prompt={encoded_prompt}"))
            }
        }
        ManualGuideHarness::T3 => {
            if let Some(url) = sanitize_http_url(t3_url) {
                Some(url)
            } else {
                Some("t3code://".to_string())
            }
        }
        ManualGuideHarness::CursorIde => {
            if let Some(dir) = cwd.filter(|p| !p.as_os_str().is_empty()) {
                let encoded_path = percent_encode_uri_path(dir);
                if encoded_path.is_empty() {
                    Some("cursor://".to_string())
                } else {
                    Some(format!("cursor://file/{encoded_path}"))
                }
            } else {
                Some("cursor://".to_string())
            }
        }
        ManualGuideHarness::Openclaw | ManualGuideHarness::ConfigOnlyCli(_) => None,
    }
}

/// Hermetically detected Desktop / IDE applications on the host.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DetectedDesktopApps {
    pub claude_desktop: bool,
    pub codex_desktop: bool,
    pub opencode_desktop: bool,
    pub cursor_ide: bool,
}

/// Pure, hermetic Desktop/IDE detector accepting explicit `home`, optional macOS `apps_dir`,
/// optional Windows `appdata_dir` / `local_appdata_dir`, and optional `opencode_server_url`.
pub fn detect_desktop_apps_in_with_env(
    home: &Path,
    apps_dir: Option<&Path>,
    appdata_dir: Option<&Path>,
    local_appdata_dir: Option<&Path>,
    opencode_server_url: Option<&str>,
) -> DetectedDesktopApps {
    let claude_desktop = home
        .join("Library")
        .join("Application Support")
        .join("Claude")
        .exists()
        || home.join(".config").join("Claude").exists()
        || home.join("Applications").join("Claude.app").exists()
        || appdata_dir.is_some_and(|a| a.join("Claude").exists())
        || apps_dir.is_some_and(|a| a.join("Claude.app").exists());

    let codex_desktop = home.join("Applications").join("Codex.app").exists()
        || apps_dir.is_some_and(|a| a.join("Codex.app").exists());

    let opencode_desktop = home.join("Applications").join("OpenCode.app").exists()
        || apps_dir.is_some_and(|a| a.join("OpenCode.app").exists())
        || appdata_dir.is_some_and(|a| a.join("OpenCode").exists())
        || local_appdata_dir.is_some_and(|a| a.join("OpenCode").exists())
        || home.join("AppData").join("Local").join("OpenCode").exists()
        || sanitize_http_url(opencode_server_url).is_some();

    let cursor_ide = home.join(".cursor").exists()
        || home.join("Applications").join("Cursor.app").exists()
        || apps_dir.is_some_and(|a| a.join("Cursor.app").exists());

    DetectedDesktopApps {
        claude_desktop,
        codex_desktop,
        opencode_desktop,
        cursor_ide,
    }
}

/// Pure, hermetic Desktop/IDE detector accepting explicit `home`, optional macOS `apps_dir`
/// (e.g. `Some("/Applications")` in live runs, `None` or a tempdir in tests), and optional
/// Windows `appdata_dir` (e.g. `Some("%APPDATA%")`).
#[cfg(test)]
pub fn detect_desktop_apps_in(
    home: &Path,
    apps_dir: Option<&Path>,
    appdata_dir: Option<&Path>,
) -> DetectedDesktopApps {
    detect_desktop_apps_in_with_env(home, apps_dir, appdata_dir, None, None)
}

struct HostDesktopProbe {
    apps_dir: Option<PathBuf>,
    appdata_dir: Option<PathBuf>,
    local_appdata_dir: Option<PathBuf>,
    opencode_server_url: Option<String>,
}

fn host_desktop_probe(explicit_home: bool) -> HostDesktopProbe {
    if explicit_home {
        // Hermetic mode: never inspect host `/Applications`, `%APPDATA%`, or ambient env when `--home` is overridden.
        return HostDesktopProbe {
            apps_dir: None,
            appdata_dir: None,
            local_appdata_dir: None,
            opencode_server_url: None,
        };
    }

    #[cfg(target_os = "macos")]
    let apps_dir = Some(PathBuf::from("/Applications"));
    #[cfg(not(target_os = "macos"))]
    let apps_dir: Option<PathBuf> = None;

    #[cfg(windows)]
    let appdata_dir = std::env::var_os("APPDATA").map(PathBuf::from);
    #[cfg(not(windows))]
    let appdata_dir: Option<PathBuf> = None;

    #[cfg(windows)]
    let local_appdata_dir = std::env::var_os("LOCALAPPDATA").map(PathBuf::from);
    #[cfg(not(windows))]
    let local_appdata_dir: Option<PathBuf> = None;

    let opencode_server_url = std::env::var("OPENCODE_SERVER_URL").ok();

    HostDesktopProbe {
        apps_dir,
        appdata_dir,
        local_appdata_dir,
        opencode_server_url,
    }
}

/// Herdr launch template discovered via `hc templates --json`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HerdrTemplate {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub command: String,
}

impl HerdrTemplate {
    pub fn display_title(&self) -> &str {
        if self.description.trim().is_empty() {
            &self.name
        } else {
            self.description.trim()
        }
    }

    pub fn display_subtitle(&self) -> String {
        let cmd = self.command.trim();
        if cmd.is_empty() || cmd == self.name {
            self.name.clone()
        } else if cmd.starts_with(&self.name)
            && cmd
                .as_bytes()
                .get(self.name.len())
                .is_some_and(|b| b.is_ascii_whitespace())
        {
            cmd.to_string()
        } else {
            format!("{} · {}", self.name, cmd)
        }
    }
}

/// Resolved executable + argv for launching an interactive agent harness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchSpec {
    pub program: &'static str,
    pub args: Vec<String>,
}

/// Outcome returned by the interactive wizard so `setup::run_onboard` can fall through to local setup.
pub enum WizardOutcome {
    Finished(Result<ExitCode, CliError>),
    #[allow(dead_code)]
    RunLocalCliSetup,
    RunLocalCliSetupWithSelection(SetupSelection),
}

/// User-confirmed harness and optional component selections from the interactive toggle screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupSelection {
    pub harnesses: Vec<HarnessKind>,
    pub install_skills: bool,
    pub install_statusline: bool,
    pub install_claude_commands: bool,
    pub install_herdr_mod: bool,
    pub openclaw_delivery: OpenClawDeliveryMode,
    pub openclaw_prompt_injection: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InstalledSkillEntry {
    pub harness: String,
    pub path: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub extra_paths: Vec<String>,
}

#[derive(Debug, Clone)]
struct ExistingNodeInfo {
    node_id: String,
    config_path: PathBuf,
    is_legacy_v1: bool,
}

/// Parsed terminal key event for arrow-key navigation.
#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyEvent {
    Up,
    Down,
    Left,
    Right,
    Enter,
    Back,
    Cancel,
    Char(char),
    Other,
}

/// Action attached to each option in the main onboarding menu.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MainMenuAction {
    HerdrTemplates {
        hc_bin: PathBuf,
        templates: Vec<HerdrTemplate>,
    },
    LaunchHerdrTemplate {
        hc_bin: PathBuf,
        template: HerdrTemplate,
    },
    LaunchCli(LaunchableHarness),
    ManualGuide(ManualGuideHarness),
    QuickLocalSetup,
}

#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TagTone {
    Launch,
    Guide,
    Local,
}

/// Single highlighted row in the main onboarding menu (only detected/available options).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainMenuItem {
    pub label: String,
    pub tag: &'static str,
    pub subtitle: String,
    pub action: MainMenuAction,
}

#[cfg_attr(not(unix), allow(dead_code))]
impl MainMenuItem {
    fn tag_tone(&self) -> TagTone {
        match self.action {
            MainMenuAction::HerdrTemplates { .. }
            | MainMenuAction::LaunchHerdrTemplate { .. }
            | MainMenuAction::LaunchCli(_) => TagTone::Launch,
            MainMenuAction::ManualGuide(_) => TagTone::Guide,
            MainMenuAction::QuickLocalSetup => TagTone::Local,
        }
    }
}

// ============================================================================
// Color Mode, Terminal Size & RAII Screen / Raw-TTY Guards
// ============================================================================

/// Pure color-mode resolver for unit tests and runtime detection.
pub fn detect_color_mode_from_env(
    no_color: Option<&str>,
    clicolor: Option<&str>,
    colorterm: Option<&str>,
    term_program: Option<&str>,
    term: Option<&str>,
    wt_session: Option<&str>,
    is_tty: bool,
) -> ColorMode {
    if no_color.is_some_and(|v| !v.is_empty()) {
        return ColorMode::Plain;
    }
    if clicolor == Some("0") {
        return ColorMode::Plain;
    }
    if term.is_some_and(|t| t.eq_ignore_ascii_case("dumb")) {
        return ColorMode::Plain;
    }
    if let Some(ct) = colorterm {
        let low = ct.to_ascii_lowercase();
        if low.contains("truecolor") || low.contains("24bit") {
            return ColorMode::TrueColor;
        }
    }
    if let Some(tp) = term_program {
        let low = tp.to_ascii_lowercase();
        if low == "apple_terminal" {
            return ColorMode::Ansi256;
        }
        if matches!(
            low.as_str(),
            "iterm.app"
                | "wezterm"
                | "ghostty"
                | "vscode"
                | "alacritty"
                | "kitty"
                | "warpterminal"
                | "hyper"
                | "rio"
        ) {
            return ColorMode::TrueColor;
        }
    }
    if wt_session.is_some() {
        return ColorMode::TrueColor;
    }
    if let Some(t) = term {
        let low = t.to_ascii_lowercase();
        if low.contains("truecolor")
            || low.contains("direct")
            || low.contains("kitty")
            || low.contains("alacritty")
            || low.contains("wezterm")
            || low.contains("ghostty")
        {
            return ColorMode::TrueColor;
        }
        if low == "vt100" || low == "ansi" {
            return ColorMode::Ansi256;
        }
    }
    if is_tty {
        ColorMode::TrueColor
    } else {
        ColorMode::Plain
    }
}

pub fn detect_color_mode() -> ColorMode {
    let no_color = std::env::var("NO_COLOR").ok();
    let clicolor = std::env::var("CLICOLOR").ok();
    let colorterm = std::env::var("COLORTERM").ok();
    let term_program = std::env::var("TERM_PROGRAM").ok();
    let term = std::env::var("TERM").ok();
    let wt_session = std::env::var("WT_SESSION").ok();
    detect_color_mode_from_env(
        no_color.as_deref(),
        clicolor.as_deref(),
        colorterm.as_deref(),
        term_program.as_deref(),
        term.as_deref(),
        wt_session.as_deref(),
        io::stdout().is_terminal(),
    )
}

fn no_color_enabled() -> bool {
    std::env::var("NO_COLOR")
        .ok()
        .is_some_and(|v| !v.is_empty())
}

fn wizard_anim_disabled(no_anim_flag: bool) -> bool {
    no_anim_flag
        || no_color_enabled()
        || std::env::var("HYPHAE_WIZARD_NO_ANIM")
            .ok()
            .is_some_and(|v| {
                let t = v.trim();
                !t.is_empty() && t != "0" && !t.eq_ignore_ascii_case("false")
            })
}

/// Parses `stty size` output (`"rows cols"`) into `Some((rows, cols))`, rejecting zero/malformed values.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn parse_stty_size(raw: &str) -> Option<(usize, usize)> {
    let mut parts = raw.split_whitespace();
    let rows = parts.next()?.parse::<usize>().ok()?;
    let cols = parts.next()?.parse::<usize>().ok()?;
    if parts.next().is_some() || rows == 0 || cols == 0 {
        return None;
    }
    Some((rows, cols))
}

/// Resolves `(rows, cols)` from `$LINES` / `$COLUMNS`, falling back to `(24, 80)`.
pub fn detect_terminal_size_from_env(lines: Option<&str>, columns: Option<&str>) -> (usize, usize) {
    let rows = lines
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(24);
    let cols = columns
        .and_then(|v| v.trim().parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(80);
    (rows, cols)
}

/// Detects real terminal dimensions `(rows, cols)` cleanly with zero external crates:
/// - Unix: `stty size </dev/tty` when connected to a TTY, falling back to `$LINES`/`$COLUMNS`, then `24 × 80`.
/// - Non-Unix: `$LINES`/`$COLUMNS` or `24 × 80`.
pub fn detect_terminal_size() -> (usize, usize) {
    #[cfg(unix)]
    {
        if io::stdout().is_terminal() {
            if let Ok(tty) = fs::File::open("/dev/tty") {
                if let Ok(out) = Command::new("stty")
                    .arg("size")
                    .stdin(Stdio::from(tty))
                    .stdout(Stdio::piped())
                    .stderr(Stdio::null())
                    .output()
                {
                    if out.status.success() {
                        if let Some(size) = parse_stty_size(&String::from_utf8_lossy(&out.stdout)) {
                            return size;
                        }
                    }
                }
            }
        }
    }

    let lines = std::env::var("LINES").ok();
    let columns = std::env::var("COLUMNS").ok();
    detect_terminal_size_from_env(lines.as_deref(), columns.as_deref())
}

/// Scales the fullscreen animated mycelium canvas `(width, height)` cleanly for a `(rows, cols)` viewport.
pub fn compute_fullscreen_canvas_size(rows: usize, cols: usize) -> (usize, usize) {
    let width = if cols >= 34 {
        (cols - 6).min(132)
    } else {
        cols.saturating_sub(2).max(16)
    };
    let height = if rows >= 22 {
        (rows - 6).clamp(16, 44)
    } else {
        rows.saturating_sub(4).clamp(10, 16)
    };
    (width, height)
}

/// Parses raw terminal bytes (including VT100/xterm arrow escape sequences) into a [`KeyEvent`].
#[cfg_attr(not(unix), allow(dead_code))]
pub fn parse_key_bytes(bytes: &[u8]) -> KeyEvent {
    if bytes.is_empty() {
        return KeyEvent::Other;
    }
    match bytes {
        [0x1b, b'[', b'A', ..] | [0x1b, b'O', b'A', ..] => KeyEvent::Up,
        [0x1b, b'[', b'B', ..] | [0x1b, b'O', b'B', ..] => KeyEvent::Down,
        [0x1b, b'[', b'C', ..] | [0x1b, b'O', b'C', ..] => KeyEvent::Right,
        [0x1b, b'[', b'D', ..] | [0x1b, b'O', b'D', ..] => KeyEvent::Left,
        [0x1b] => KeyEvent::Back,
        [0x03, ..] => KeyEvent::Cancel,
        [b'\r', ..] | [b'\n', ..] => KeyEvent::Enter,
        [0x7f, ..] | [0x08, ..] => KeyEvent::Left,
        [b'k'] | [b'K'] => KeyEvent::Up,
        [b'j'] | [b'J'] => KeyEvent::Down,
        [b'h'] | [b'H'] => KeyEvent::Left,
        [b'l'] | [b'L'] => KeyEvent::Right,
        [b'q'] | [b'Q'] => KeyEvent::Cancel,
        [b] if b.is_ascii_graphic() || *b == b' ' => KeyEvent::Char(*b as char),
        _ => KeyEvent::Other,
    }
}

fn resolve_preview_canvas_dimensions() -> Option<(usize, usize)> {
    if let Some(cols) = std::env::var("COLUMNS")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
    {
        if cols < 30 {
            return None;
        }
        if cols < DEFAULT_CANVAS_WIDTH {
            let w = cols.saturating_sub(2);
            let h = (w / 3).clamp(10, DEFAULT_CANVAS_HEIGHT);
            return Some((w, h));
        }
    }
    Some((DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT))
}

fn fg_color(mode: ColorMode, rgb: (u8, u8, u8)) -> String {
    match mode {
        ColorMode::Plain => String::new(),
        ColorMode::TrueColor => format!("\x1b[38;2;{};{};{}m", rgb.0, rgb.1, rgb.2),
        ColorMode::Ansi256 => format!("\x1b[38;5;{}m", rgb_to_ansi256(rgb.0, rgb.1, rgb.2)),
    }
}

#[cfg_attr(not(unix), allow(dead_code))]
fn style_reset(mode: ColorMode) -> &'static str {
    match mode {
        ColorMode::Plain => "",
        ColorMode::TrueColor | ColorMode::Ansi256 => "\x1b[0m",
    }
}

fn paint_styled_text(mode: ColorMode, rgb: (u8, u8, u8), bold: bool, text: &str) -> String {
    if mode == ColorMode::Plain {
        return text.to_string();
    }
    let bold_code = if bold { "\x1b[1m" } else { "" };
    format!("{bold_code}{}{text}\x1b[0m", fg_color(mode, rgb))
}

fn truncate_chars(text: &str, max_chars: usize) -> String {
    if max_chars == 0 {
        return String::new();
    }
    let count = text.chars().count();
    if count <= max_chars {
        return text.to_string();
    }
    if max_chars == 1 {
        return "…".to_string();
    }
    let mut out: String = text.chars().take(max_chars - 1).collect();
    out.push('…');
    out
}

#[cfg_attr(not(unix), allow(dead_code))]
fn wrap_words(text: &str, max_width: usize) -> Vec<String> {
    if max_width == 0 {
        return vec![text.to_string()];
    }
    let mut lines = Vec::new();
    let mut current = String::new();
    let mut current_len = 0usize;

    for word in text.split_whitespace() {
        let wlen = word.chars().count();
        if current.is_empty() {
            if wlen <= max_width {
                current.push_str(word);
                current_len = wlen;
            } else {
                let mut chunk = String::new();
                for ch in word.chars() {
                    if chunk.chars().count() >= max_width {
                        lines.push(std::mem::take(&mut chunk));
                    }
                    chunk.push(ch);
                }
                current_len = chunk.chars().count();
                current = chunk;
            }
        } else if current_len + 1 + wlen <= max_width {
            current.push(' ');
            current.push_str(word);
            current_len += 1 + wlen;
        } else {
            lines.push(std::mem::take(&mut current));
            current.push_str(word);
            current_len = wlen;
        }
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// Renders a single centered fullscreen mycelium animation frame with minimalist footer.
fn compose_fullscreen_anim_frame(
    frame_idx: usize,
    total_frames: usize,
    term_size: (usize, usize),
    canvas_size: (usize, usize),
    color_mode: ColorMode,
    show_skip_hint: bool,
) -> String {
    let (term_rows, term_cols) = term_size;
    let (canvas_w, canvas_h) = canvas_size;
    let art = render_frame(frame_idx, total_frames, 0, canvas_w, canvas_h, color_mode);
    let version = env!("CARGO_PKG_VERSION");
    let footer_main = format!("hyphae v{version} · growing local mesh...");
    let footer_hint = if show_skip_hint {
        "press any key to skip"
    } else {
        ""
    };

    let footer_lines = if show_skip_hint { 3 } else { 2 };
    let total_block_h = canvas_h + footer_lines;
    let top_pad = term_rows.saturating_sub(total_block_h) / 2;
    let left_pad = term_cols.saturating_sub(canvas_w) / 2;
    let pad_str = " ".repeat(left_pad);

    let mut buf = String::with_capacity(term_rows * (term_cols + 12) + 32);
    buf.push_str("\x1b[?2026h\x1b[H");
    let mut row = 1usize;

    while row <= top_pad && row <= term_rows {
        use std::fmt::Write as _;
        let _ = write!(buf, "\x1b[{row};1H\x1b[K");
        row += 1;
    }

    for line in art.lines() {
        if row > term_rows {
            break;
        }
        use std::fmt::Write as _;
        let _ = write!(buf, "\x1b[{row};1H{pad_str}{line}\x1b[K");
        row += 1;
    }

    if row <= term_rows {
        use std::fmt::Write as _;
        let _ = write!(buf, "\x1b[{row};1H\x1b[K");
        row += 1;
    }

    if row <= term_rows {
        let trimmed = truncate_chars(&footer_main, term_cols.saturating_sub(2));
        let fpad = " ".repeat(term_cols.saturating_sub(trimmed.chars().count()) / 2);
        let styled = paint_styled_text(color_mode, RGB_HYPHAE_SAGE, false, &trimmed);
        use std::fmt::Write as _;
        let _ = write!(buf, "\x1b[{row};1H{fpad}{styled}\x1b[K");
        row += 1;
    }

    if show_skip_hint && row <= term_rows {
        let trimmed = truncate_chars(footer_hint, term_cols.saturating_sub(2));
        let hpad = " ".repeat(term_cols.saturating_sub(trimmed.chars().count()) / 2);
        let styled = paint_styled_text(color_mode, RGB_UI_MUTED, false, &trimmed);
        use std::fmt::Write as _;
        let _ = write!(buf, "\x1b[{row};1H{hpad}{styled}\x1b[K");
        row += 1;
    }

    while row <= term_rows {
        use std::fmt::Write as _;
        let _ = write!(buf, "\x1b[{row};1H\x1b[K");
        row += 1;
    }

    buf.push_str("\x1b[?2026l");
    buf
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AnimOutcome {
    Completed,
    Skipped,
    Cancelled,
}

/// Plays the fullscreen centered mycelium animation inside an already-entered alt-screen.
#[cfg(unix)]
fn play_fullscreen_intro_on_alt_screen(
    raw_tty: &mut RawTtyGuard,
    term_rows: usize,
    term_cols: usize,
    color_mode: ColorMode,
    hold_final_ms: u64,
) -> AnimOutcome {
    let (canvas_w, canvas_h) = compute_fullscreen_canvas_size(term_rows, term_cols);
    let _ = raw_tty.set_mode(true);
    let mut out = io::stdout().lock();

    for frame_idx in 0..DEFAULT_TOTAL_FRAMES {
        let rendered = compose_fullscreen_anim_frame(
            frame_idx,
            DEFAULT_TOTAL_FRAMES,
            (term_rows, term_cols),
            (canvas_w, canvas_h),
            color_mode,
            true,
        );
        let _ = out.write_all(rendered.as_bytes());
        let _ = out.flush();

        let wait_ms = if frame_idx + 1 < DEFAULT_TOTAL_FRAMES {
            FRAME_DELAY_MS
        } else {
            hold_final_ms
        };
        if wait_ms > 0 {
            let deadline = Instant::now() + Duration::from_millis(wait_ms);
            while Instant::now() < deadline {
                if let Some(key) = raw_tty.poll_any_key(parse_key_bytes) {
                    raw_tty.drain_pending();
                    return if key == KeyEvent::Cancel {
                        AnimOutcome::Cancelled
                    } else {
                        AnimOutcome::Skipped
                    };
                }
                let rem = deadline.saturating_duration_since(Instant::now());
                thread::sleep(rem.min(Duration::from_millis(15)));
            }
        }
    }
    AnimOutcome::Completed
}

/// Plays the fullscreen mycelium intro animation cleanly (entering & leaving alt-screen).
pub fn play_mycelium_animation(no_anim: bool) {
    if wizard_anim_disabled(no_anim) || !io::stdout().is_terminal() {
        return;
    }
    let (term_rows, term_cols) = detect_terminal_size();
    let color_mode = detect_color_mode();
    let mut alt = AltScreenGuard::wizard(true);

    #[cfg(unix)]
    if let Ok(mut raw) = RawTtyGuard::enter(true) {
        let _ =
            play_fullscreen_intro_on_alt_screen(&mut raw, term_rows, term_cols, color_mode, 220);
        raw.restore();
        alt.leave();
        return;
    }

    let (canvas_w, canvas_h) = compute_fullscreen_canvas_size(term_rows, term_cols);
    let mut out = io::stdout().lock();
    for frame_idx in 0..DEFAULT_TOTAL_FRAMES {
        let rendered = compose_fullscreen_anim_frame(
            frame_idx,
            DEFAULT_TOTAL_FRAMES,
            (term_rows, term_cols),
            (canvas_w, canvas_h),
            color_mode,
            false,
        );
        let _ = out.write_all(rendered.as_bytes());
        let _ = out.flush();
        if frame_idx + 1 < DEFAULT_TOTAL_FRAMES {
            thread::sleep(Duration::from_millis(FRAME_DELAY_MS));
        }
    }
    thread::sleep(Duration::from_millis(220));
    drop(out);
    alt.leave();
}

/// Entrypoint for `hyp onboard --preview-anim`.
pub fn run_preview_animation(no_anim: bool) -> ExitCode {
    let color_mode = detect_color_mode();
    let is_tty = io::stdout().is_terminal();

    // Non-TTY or `--no-anim`: emit exact settled dot-matrix canvas directly for tests & piping.
    if no_anim || !is_tty {
        let Some((width, height)) = resolve_preview_canvas_dimensions() else {
            return ExitCode::from(EXIT_OK);
        };
        let settled = render_frame(
            DEFAULT_TOTAL_FRAMES - 1,
            DEFAULT_TOTAL_FRAMES,
            0,
            width,
            height,
            color_mode,
        );
        println!("{settled}");
        return ExitCode::from(EXIT_OK);
    }

    // Live interactive TTY: play the full-screen alternate-screen animation.
    let (term_rows, term_cols) = detect_terminal_size();
    let mut alt = AltScreenGuard::wizard(true);

    #[cfg(unix)]
    if let Ok(mut raw) = RawTtyGuard::enter(true) {
        let _ =
            play_fullscreen_intro_on_alt_screen(&mut raw, term_rows, term_cols, color_mode, 450);
        raw.restore();
        alt.leave();
        return ExitCode::from(EXIT_OK);
    }

    let (canvas_w, canvas_h) = compute_fullscreen_canvas_size(term_rows, term_cols);
    let mut out = io::stdout().lock();
    for frame_idx in 0..DEFAULT_TOTAL_FRAMES {
        let rendered = compose_fullscreen_anim_frame(
            frame_idx,
            DEFAULT_TOTAL_FRAMES,
            (term_rows, term_cols),
            (canvas_w, canvas_h),
            color_mode,
            false,
        );
        let _ = out.write_all(rendered.as_bytes());
        let _ = out.flush();
        if frame_idx + 1 < DEFAULT_TOTAL_FRAMES {
            thread::sleep(Duration::from_millis(FRAME_DELAY_MS));
        }
    }
    thread::sleep(Duration::from_millis(450));
    drop(out);
    alt.leave();
    ExitCode::from(EXIT_OK)
}

// ============================================================================
// PATH Executable, Herdr Templates & Harness Detection
// ============================================================================

/// Cross-platform executable lookup using an explicit `PATH` value (unit-testable).
pub fn find_executable_in_path_env(bin_name: &str, path_var: Option<&OsStr>) -> Option<PathBuf> {
    search_path(
        Path::new(bin_name),
        path_var?,
        PathSearchPolicy {
            include_empty: false,
            executable: true,
            windows_suffixes: WindowsSuffixes::PathExt,
        },
    )
}

pub fn find_executable_in_path(bin_name: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH");
    find_executable_in_path_env(bin_name, path_var.as_deref())
}

fn detect_launchable_harnesses_on_path() -> Vec<(LaunchableHarness, PathBuf)> {
    LaunchableHarness::ALL
        .iter()
        .filter_map(|&h| find_executable_in_path(h.binary_name()).map(|p| (h, p)))
        .collect()
}

/// Parses `hc templates --json` output (`{"templates":[{"name","description","command"}]}`).
/// Never panics on invalid JSON, missing keys, or empty output.
pub fn parse_herdr_templates_json(raw: &str) -> Vec<HerdrTemplate> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }
    #[derive(Deserialize)]
    struct TemplatesEnvelope {
        #[serde(default)]
        templates: Vec<HerdrTemplate>,
    }

    let parsed = serde_json::from_str::<TemplatesEnvelope>(trimmed)
        .map(|env| env.templates)
        .or_else(|_| serde_json::from_str::<Vec<HerdrTemplate>>(trimmed))
        .unwrap_or_default();

    parsed
        .into_iter()
        .filter(|t| !t.name.trim().is_empty())
        .collect()
}

fn output_retrying_busy(cmd: &mut Command) -> io::Result<std::process::Output> {
    for attempt in 0..5 {
        match cmd.output() {
            Err(e) if e.kind() == io::ErrorKind::ExecutableFileBusy && attempt < 4 => {
                thread::sleep(Duration::from_millis(15));
            }
            other => return other,
        }
    }
    cmd.output()
}

fn status_retrying_busy(cmd: &mut Command) -> io::Result<std::process::ExitStatus> {
    for attempt in 0..5 {
        match cmd.status() {
            Err(e) if e.kind() == io::ErrorKind::ExecutableFileBusy && attempt < 4 => {
                thread::sleep(Duration::from_millis(15));
            }
            other => return other,
        }
    }
    cmd.status()
}

/// Discovers Herdr launch templates by invoking `hc templates --json`.
/// Returns an empty list on any error, offline Herdr, or malformed JSON (never panics).
pub fn discover_herdr_templates(hc_bin: &Path) -> Vec<HerdrTemplate> {
    let mut cmd = Command::new(hc_bin);
    cmd.args(["templates", "--json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let Ok(out) = output_retrying_busy(&mut cmd) else {
        return Vec::new();
    };
    if !out.status.success() {
        return Vec::new();
    }
    parse_herdr_templates_json(&String::from_utf8_lossy(&out.stdout))
}

fn detect_herdr_terminal_from_values(
    hc_terminal_id: Option<&str>,
    herdr_terminal_id: Option<&str>,
) -> Option<String> {
    let pick = |raw: Option<&str>| -> Option<String> {
        let trimmed = raw?.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    };
    pick(hc_terminal_id).or_else(|| pick(herdr_terminal_id))
}

/// Detects whether the current terminal session is running inside a Herdr terminal
/// (`HC_TERMINAL_ID`, then `HERDR_TERMINAL_ID`).
pub fn detect_herdr_terminal_from_env() -> Option<String> {
    let hc_id = std::env::var("HC_TERMINAL_ID").ok();
    let herdr_id = std::env::var("HERDR_TERMINAL_ID").ok();
    detect_herdr_terminal_from_values(hc_id.as_deref(), herdr_id.as_deref())
}

fn validate_herdr_terminal_address(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.starts_with('-')
        || trimmed.chars().any(char::is_whitespace)
        || trimmed.chars().any(char::is_control)
    {
        return None;
    }
    Some(trimmed.to_string())
}

/// Parses `hc run --bg --json` output (`RunResult { address: "t4h", ... }`), ignoring any leading
/// non-JSON log lines and rejecting empty, flag-like (`-bad`), or whitespace-containing addresses.
pub fn parse_herdr_run_address_json(raw: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct HerdrRunResult {
        address: Option<String>,
    }

    let try_parse = |candidate: &str| -> Option<String> {
        let parsed = serde_json::from_str::<HerdrRunResult>(candidate.trim()).ok()?;
        let addr = parsed.address?;
        validate_herdr_terminal_address(&addr)
    };

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(addr) = try_parse(trimmed) {
        return Some(addr);
    }

    let mut offset = 0usize;
    for line in raw.split_inclusive('\n') {
        let candidate = line.trim();
        if candidate.starts_with('{') {
            if let Some(addr) = try_parse(candidate) {
                return Some(addr);
            }
            if let Some(addr) = try_parse(&raw[offset..]) {
                return Some(addr);
            }
        }
        offset += line.len();
    }
    None
}

/// Infers which coding harness a Herdr template runs from its `name` and `command`
/// so `hyp-setup/SKILL.md` is installed into the right global skill directory before launch.
pub fn infer_harness_from_herdr_template(
    template_name: &str,
    template_command: &str,
) -> Option<LaunchableHarness> {
    let combined = format!(
        "{} {}",
        template_name.to_ascii_lowercase(),
        template_command.to_ascii_lowercase()
    );
    if combined.contains("claude") {
        Some(LaunchableHarness::Claude)
    } else if combined.contains("codex") {
        Some(LaunchableHarness::Codex)
    } else if combined.contains("opencode") {
        Some(LaunchableHarness::Opencode)
    } else if combined.contains("antigravity")
        || combined
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|tok| tok == "agy")
    {
        Some(LaunchableHarness::Antigravity)
    } else if combined.contains("cursor") {
        Some(LaunchableHarness::Cursor)
    } else if combined.contains("gemini") {
        Some(LaunchableHarness::Gemini)
    } else {
        None
    }
}

/// Builds the exact `hc run --bg --outlive-parent --label app=hyphae --json <template> <prompt>`
/// command for launching an agent via Herdr without blocking on headless input prompts.
pub fn build_herdr_template_launch_command(
    hc_bin: &Path,
    template_name: &str,
    prompt: &str,
) -> Command {
    let mut cmd = Command::new(hc_bin);
    cmd.args([
        "run",
        "--bg",
        "--outlive-parent",
        "--label",
        "app=hyphae",
        "--json",
        template_name,
        prompt,
    ]);
    cmd
}

/// Builds the interactive `hc attach <terminal_address>` command with inherited TTY stdio.
pub fn build_herdr_attach_command(hc_bin: &Path, terminal_address: &str) -> Command {
    let mut cmd = Command::new(hc_bin);
    cmd.args(["attach", terminal_address]);
    attach_interactive_stdio(&mut cmd);
    cmd
}

/// Builds `herdr-app do terminal.keep --terminal <address> --place tab` so a newly spawned `hc`
/// terminal opens directly as a real focused tab inside a running Herdr desktop app window.
pub fn build_herdr_app_keep_command(herdr_app_bin: &Path, terminal_address: &str) -> Command {
    let mut cmd = Command::new(herdr_app_bin);
    cmd.args([
        "do",
        "terminal.keep",
        "--terminal",
        terminal_address,
        "--place",
        "tab",
    ]);
    cmd.stdin(Stdio::null());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd
}

fn try_open_in_herdr_app_tab(terminal_address: &str, raise_window: bool) -> bool {
    let Some(herdr_app_bin) = find_executable_in_path("herdr-app") else {
        return false;
    };
    let mut cmd = build_herdr_app_keep_command(&herdr_app_bin, terminal_address);
    let kept = matches!(output_retrying_busy(&mut cmd), Ok(out) if out.status.success());
    if kept && raise_window {
        // Bare `herdr-app` raises/focuses the running Herdr window without blocking our CLI.
        let _ = Command::new(&herdr_app_bin)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
    }
    kept
}

/// Builds the filtered main menu containing ONLY options actually detected/available on this machine.
#[cfg(test)]
pub fn build_main_menu_items(
    diagnostics: &[HarnessDiagnostic],
    launchables: &[(LaunchableHarness, PathBuf)],
    hc_bin: Option<&Path>,
    herdr_templates: &[HerdrTemplate],
    desktop_apps: DetectedDesktopApps,
    existing_node_id: Option<&str>,
) -> Vec<MainMenuItem> {
    build_main_menu_items_with_env(
        diagnostics,
        launchables,
        hc_bin,
        herdr_templates,
        desktop_apps,
        existing_node_id,
        None,
    )
}

/// Herdr-environment-aware main menu builder:
/// - When `in_herdr_env.is_some()` (already inside a Herdr terminal) and templates exist, each
///   discovered Herdr template is surfaced directly at the top (`LaunchHerdrTemplate`) with zero
///   extra submenu hop.
/// - When `in_herdr_env.is_none()` (standard terminal), templates stay cleanly grouped under `Herdr`.
pub fn build_main_menu_items_with_env(
    diagnostics: &[HarnessDiagnostic],
    launchables: &[(LaunchableHarness, PathBuf)],
    hc_bin: Option<&Path>,
    herdr_templates: &[HerdrTemplate],
    desktop_apps: DetectedDesktopApps,
    existing_node_id: Option<&str>,
    in_herdr_env: Option<&str>,
) -> Vec<MainMenuItem> {
    let mut items = Vec::new();
    let find_diag = |name: &str| diagnostics.iter().find(|d| d.harness == name);
    let cli_on_path = |lh: LaunchableHarness| launchables.iter().any(|(h, _)| *h == lh);

    // 1. Herdr prominently at the top when `hc` is present and has >= 1 template.
    if let Some(hc_path) = hc_bin.filter(|_| !herdr_templates.is_empty()) {
        if in_herdr_env.is_some() {
            for tmpl in herdr_templates {
                items.push(MainMenuItem {
                    label: tmpl.display_title().to_string(),
                    tag: "via herdr",
                    subtitle: tmpl.display_subtitle(),
                    action: MainMenuAction::LaunchHerdrTemplate {
                        hc_bin: hc_path.to_path_buf(),
                        template: tmpl.clone(),
                    },
                });
            }
        } else {
            items.push(MainMenuItem {
                label: "Herdr".to_string(),
                tag: "via herdr",
                subtitle: format!("{} templates · native tab wakeup", herdr_templates.len()),
                action: MainMenuAction::HerdrTemplates {
                    hc_bin: hc_path.to_path_buf(),
                    templates: herdr_templates.to_vec(),
                },
            });
        }
    }

    // 2. Detected launchable CLI harnesses on PATH (`in terminal`).
    for &(lh, _) in launchables {
        let configured = find_diag(lh.id()).is_some_and(|d| d.configured);
        let subtitle = if configured {
            format!("{} · configured", lh.binary_name())
        } else {
            lh.binary_name().to_string()
        };
        items.push(MainMenuItem {
            label: lh.display_name().to_string(),
            tag: "in terminal",
            subtitle,
            action: MainMenuAction::LaunchCli(lh),
        });
    }

    // 3. Detected Desktop / IDE / GUI / daemon harnesses (only real runnable apps; skip uninstalled CLIs).
    if desktop_apps.claude_desktop {
        items.push(MainMenuItem {
            label: ManualGuideHarness::ClaudeDesktop.display_name().to_string(),
            tag: "desktop app",
            subtitle: "open in Claude Desktop".to_string(),
            action: MainMenuAction::ManualGuide(ManualGuideHarness::ClaudeDesktop),
        });
    }

    if desktop_apps.codex_desktop {
        items.push(MainMenuItem {
            label: ManualGuideHarness::CodexDesktop.display_name().to_string(),
            tag: "desktop app",
            subtitle: "open in Codex Desktop".to_string(),
            action: MainMenuAction::ManualGuide(ManualGuideHarness::CodexDesktop),
        });
    }

    if desktop_apps.opencode_desktop {
        items.push(MainMenuItem {
            label: ManualGuideHarness::OpenCodeDesktop
                .display_name()
                .to_string(),
            tag: "desktop app",
            subtitle: "open in OpenCode Desktop".to_string(),
            action: MainMenuAction::ManualGuide(ManualGuideHarness::OpenCodeDesktop),
        });
    }

    if !cli_on_path(LaunchableHarness::Cursor) && desktop_apps.cursor_ide {
        let configured = find_diag("cursor").is_some_and(|d| d.configured);
        let suffix = if configured { " · configured" } else { "" };
        items.push(MainMenuItem {
            label: ManualGuideHarness::CursorIde.display_name().to_string(),
            tag: "desktop app",
            subtitle: format!("open in Cursor{suffix}"),
            action: MainMenuAction::ManualGuide(ManualGuideHarness::CursorIde),
        });
    }

    for (guide_harness, tag, default_sub) in [
        (
            ManualGuideHarness::Openclaw,
            "copy prompt",
            "paste prompt in OpenClaw",
        ),
        (ManualGuideHarness::T3, "desktop app", "open in T3 Code"),
    ] {
        if let Some(diag) = find_diag(guide_harness.id()).filter(|d| d.detected || d.configured) {
            let subtitle = if diag.configured {
                format!("{default_sub} · configured")
            } else {
                default_sub.to_string()
            };
            items.push(MainMenuItem {
                label: guide_harness.display_name().to_string(),
                tag,
                subtitle,
                action: MainMenuAction::ManualGuide(guide_harness),
            });
        }
    }

    // 4. Deterministic local CLI setup + background service install right here.
    let local_subtitle = if existing_node_id.is_some() {
        "refresh node, harnesses & daemon here"
    } else {
        "configure node, keys & harnesses here"
    };
    items.push(MainMenuItem {
        label: "Local CLI setup".to_string(),
        tag: "local cli",
        subtitle: local_subtitle.to_string(),
        action: MainMenuAction::QuickLocalSetup,
    });

    items
}

/// Hermetic candidate detector taking explicit `home`, optional `config_path`, `PATH`,
/// optional macOS `apps_dir`, and optional Windows `appdata_dir` so unit tests never leak
/// host `/Applications`, `%APPDATA%`, or ambient `PATH`.
#[cfg(test)]
pub fn detect_candidates_in(
    home: &Path,
    config_path: Option<&Path>,
    path_var: Option<&OsStr>,
    apps_dir: Option<&Path>,
    appdata_dir: Option<&Path>,
    existing_node_id: Option<&str>,
) -> Vec<MainMenuItem> {
    detect_candidates_in_with_env(
        home,
        config_path,
        path_var,
        apps_dir,
        appdata_dir,
        None,
        None,
        existing_node_id,
        None,
    )
}

#[cfg(test)]
#[allow(clippy::too_many_arguments)]
pub fn detect_candidates_in_with_env(
    home: &Path,
    config_path: Option<&Path>,
    path_var: Option<&OsStr>,
    apps_dir: Option<&Path>,
    appdata_dir: Option<&Path>,
    local_appdata_dir: Option<&Path>,
    opencode_server_url: Option<&str>,
    existing_node_id: Option<&str>,
    in_herdr_env: Option<&str>,
) -> Vec<MainMenuItem> {
    detect_candidates_in_with_claude(
        home,
        true,
        None,
        config_path,
        path_var,
        apps_dir,
        appdata_dir,
        local_appdata_dir,
        opencode_server_url,
        existing_node_id,
        in_herdr_env,
    )
}

#[allow(clippy::too_many_arguments)]
fn detect_candidates_in_with_claude(
    home: &Path,
    explicit_home: bool,
    claude_config_dir: Option<&Path>,
    config_path: Option<&Path>,
    path_var: Option<&OsStr>,
    apps_dir: Option<&Path>,
    appdata_dir: Option<&Path>,
    local_appdata_dir: Option<&Path>,
    opencode_server_url: Option<&str>,
    existing_node_id: Option<&str>,
    in_herdr_env: Option<&str>,
) -> Vec<MainMenuItem> {
    let diagnostics = detect_harness_statuses(home, explicit_home, claude_config_dir, config_path);
    let launchables: Vec<(LaunchableHarness, PathBuf)> = LaunchableHarness::ALL
        .iter()
        .filter_map(|&h| find_executable_in_path_env(h.binary_name(), path_var).map(|p| (h, p)))
        .collect();
    let hc_bin = find_executable_in_path_env("hc", path_var);
    let herdr_templates = hc_bin
        .as_deref()
        .map(discover_herdr_templates)
        .unwrap_or_default();
    let desktop_apps = detect_desktop_apps_in_with_env(
        home,
        apps_dir,
        appdata_dir,
        local_appdata_dir,
        opencode_server_url,
    );

    build_main_menu_items_with_env(
        &diagnostics,
        &launchables,
        hc_bin.as_deref(),
        &herdr_templates,
        desktop_apps,
        existing_node_id,
        in_herdr_env,
    )
}

fn is_skill_harness_detected(
    kind: HarnessKind,
    home: &Path,
    include_path_scan: bool,
    explicit_home: bool,
    claude_config_dir: Option<&Path>,
) -> bool {
    let profiles = if kind == HarnessKind::Claude {
        resolve_claude_profiles(home, explicit_home, claude_config_dir)
    } else {
        Vec::new()
    };
    let dir_detected = crate::harness_spec::spec(kind).detected(home, &profiles);
    if dir_detected {
        return true;
    }
    if include_path_scan {
        if let Some(launchable) = launchable_from_kind(kind) {
            return find_executable_in_path(launchable.binary_name()).is_some();
        }
    }
    false
}

fn launchable_from_kind(kind: HarnessKind) -> Option<LaunchableHarness> {
    match kind {
        HarnessKind::Claude => Some(LaunchableHarness::Claude),
        HarnessKind::Codex => Some(LaunchableHarness::Codex),
        HarnessKind::Antigravity => Some(LaunchableHarness::Antigravity),
        HarnessKind::Opencode => Some(LaunchableHarness::Opencode),
        HarnessKind::Cursor => Some(LaunchableHarness::Cursor),
        HarnessKind::Gemini => Some(LaunchableHarness::Gemini),
        HarnessKind::Openclaw | HarnessKind::Herdr | HarnessKind::T3 => None,
    }
}

fn skill_paths_for_kind(
    kind: HarnessKind,
    home: &Path,
    explicit_home: bool,
    claude_config_dir: Option<&Path>,
) -> Option<(PathBuf, Vec<PathBuf>)> {
    if let Some(lh) = launchable_from_kind(kind) {
        return Some((
            lh.primary_skill_path_for(home, explicit_home, claude_config_dir),
            lh.extra_skill_paths_for(home, explicit_home, claude_config_dir),
        ));
    }
    match kind {
        HarnessKind::Openclaw => Some((
            ManualGuideHarness::Openclaw.primary_skill_path_for(
                home,
                explicit_home,
                claude_config_dir,
            ),
            ManualGuideHarness::Openclaw.extra_skill_paths_for(
                home,
                explicit_home,
                claude_config_dir,
            ),
        )),
        HarnessKind::T3 => Some((
            ManualGuideHarness::T3.primary_skill_path_for(home, explicit_home, claude_config_dir),
            ManualGuideHarness::T3.extra_skill_paths_for(home, explicit_home, claude_config_dir),
        )),
        HarnessKind::Herdr => None,
        _ => None,
    }
}

fn parse_skill_harness_selection(
    raw: Option<&str>,
    home: &Path,
    include_path_scan: bool,
    explicit_home: bool,
    claude_config_dir: Option<&Path>,
) -> Result<Vec<HarnessKind>, String> {
    let spec = raw.unwrap_or("auto").trim().to_ascii_lowercase();
    if spec.is_empty() || spec == "auto" {
        let mut found = Vec::new();
        for kind in HarnessKind::ALL {
            if skill_paths_for_kind(kind, home, explicit_home, claude_config_dir).is_some()
                && is_skill_harness_detected(
                    kind,
                    home,
                    include_path_scan,
                    explicit_home,
                    claude_config_dir,
                )
            {
                found.push(kind);
            }
        }
        return Ok(found);
    }
    if spec == "all" {
        return Ok(HarnessKind::ALL
            .iter()
            .copied()
            .filter(|&k| skill_paths_for_kind(k, home, explicit_home, claude_config_dir).is_some())
            .collect());
    }
    let mut selected = Vec::new();
    for piece in spec.split(',') {
        let item = piece.trim();
        if item.is_empty() {
            continue;
        }
        let kind = if let Some(lh) = LaunchableHarness::parse_alias(item) {
            lh.kind()
        } else if let Some(mh) = ManualGuideHarness::parse_alias(item) {
            mh.kind()
        } else {
            item.parse::<HarnessKind>()?
        };
        if !selected.contains(&kind) {
            selected.push(kind);
        }
    }
    if selected.is_empty() {
        return Err("no valid harnesses specified".to_string());
    }
    Ok(selected)
}

/// Profile-aware installer for `hyp-setup/SKILL.md` that deduplicates symlinked `skills/`
/// directories by canonical path while populating distinct `$CLAUDE_CONFIG_DIR` skill dirs.
pub fn install_setup_skill_for_harnesses_with_claude(
    home: &Path,
    explicit_home: bool,
    claude_config_dir: Option<&Path>,
    harnesses: &[HarnessKind],
) -> Result<Vec<InstalledSkillEntry>, String> {
    let mut entries = Vec::new();
    let mut written_paths = BTreeSet::new();

    for &kind in harnesses {
        let Some((primary, extras)) =
            skill_paths_for_kind(kind, home, explicit_home, claude_config_dir)
        else {
            continue;
        };
        let installed_primary = if written_paths.insert(canonical_dedup_key(&primary)) {
            write_setup_skill(home, &primary)?
        } else {
            resolved_setup_skill(home, &primary)?
        };
        let mut written_extras = Vec::new();
        for extra in extras {
            let installed_extra = if written_paths.insert(canonical_dedup_key(&extra)) {
                write_setup_skill(home, &extra)?
            } else {
                resolved_setup_skill(home, &extra)?
            };
            written_extras.push(installed_extra.display().to_string());
        }
        entries.push(InstalledSkillEntry {
            harness: kind.as_str().to_string(),
            path: installed_primary.display().to_string(),
            extra_paths: written_extras,
        });
    }

    // If `<home>/.agents` already exists and wasn't populated yet (e.g., Codex/T3 not detected),
    // also populate `<home>/.agents/skills/hyp-setup/SKILL.md` for cross-tool discovery.
    let agents_skill = shared_setup_skill_path(home);
    if home.join(".agents").is_dir() && written_paths.insert(canonical_dedup_key(&agents_skill)) {
        let agents_skill = write_setup_skill(home, &agents_skill)?;
        entries.push(InstalledSkillEntry {
            harness: "agents".to_string(),
            path: agents_skill.display().to_string(),
            extra_paths: Vec::new(),
        });
    }

    Ok(entries)
}

fn shared_setup_skill_path(home: &Path) -> PathBuf {
    crate::harness_spec::spec(HarnessKind::Codex)
        .setup_skill(home)
        .expect("shared setup skill")
}

fn is_stock_legacy_setup_skill(text: &str) -> bool {
    // The stock setup skill predates the managed runtime marker.
    const LEGACY_DIGESTS: &[&str] = &[
        "ed7a67f7478312e4b015ef58cb84fbe1ec77f1552d879070e2b88be1c3d76e7c",
        "6b2060da1c820016c22d3e6217dfe87d2866074c82b00a3c50f4552d57dd078e",
        "4a336e5b76253e513b4f57edae22cc9fbb2640080294c5cf0622912c1fb02186",
        "c86649c74bbca523f0cb5a2408fc5fd3080812f8aba1b28a921c0de8af16a547",
        "d34e2926a7f1d801b875efe526cc9e6044cd59201aad3b9bb3b3c4ff20ca7d48",
        "934bc876321ad2abf31c8bb918bc21d44e1257b70699a478a51cf80b659632d7",
        "d78d6f7cd123e39442fbe13158d0a15827e8d076a9d1b6e3fc54b872d6928e23",
        "e4ea5f1fff56c729f448c35d687e7c422d98cf3405d28ac9f5eaba11a4ce2351",
        "86e8bd12f2489abb4eca3be6c7d474d6cdb944d0db29cde6d8e5c50358c1e1bc",
        "e1b75a2e02e7b7835459460034c75839f9fd137b6ab4c93be1ba014f8d4b228e",
        "7945d93e4909b8e422ee18e18beca0555497a5c945634f9938acf7ab2aefe767",
        "ad2850fc1eff8fe439e8772156539b090ca2b81f3edcd2ffb31863b088d22959",
        "5eb5ad185bb59180311acdbf88e8db27bd98c8e86cb73250279e292c1f37a297",
    ];
    LEGACY_DIGESTS.contains(&hyp_store::sha256_hex(text.as_bytes()).as_str())
}

fn legacy_setup_skills(home: &Path, path: &Path) -> Vec<PathBuf> {
    let local = crate::skill_render::legacy_skill_path(path, "hyphae-setup");
    if path == shared_setup_skill_path(home) {
        let mut paths = vec![local];
        paths.extend(
            crate::harness_spec::spec(HarnessKind::Codex).legacy_skills(home, "hyphae-setup"),
        );
        paths
    } else {
        vec![local]
    }
}

fn resolved_setup_skill(home: &Path, path: &Path) -> Result<PathBuf, String> {
    if let Some(manager) = crate::skillshare::Skillshare::detect(home) {
        return manager.resolve_skill_path(path);
    }
    Ok(path.into())
}

fn write_setup_skill(home: &Path, path: &Path) -> Result<PathBuf, String> {
    if let Some(manager) = crate::skillshare::Skillshare::detect(home) {
        let installed = manager.install_skill(path, HYPHAE_SETUP_SKILL_MD, false, false)?;
        for old in legacy_setup_skills(home, path) {
            crate::skill_render::retire_legacy_skill(&old, is_stock_legacy_setup_skill)?;
        }
        return Ok(installed);
    }
    crate::skill_render::write_managed_skill(path, HYPHAE_SETUP_SKILL_MD, true)?;
    for old in legacy_setup_skills(home, path) {
        crate::skill_render::retire_legacy_skill(&old, is_stock_legacy_setup_skill)?;
    }
    Ok(path.into())
}

pub(crate) fn migrate_installed_setup_skills(
    home: &Path,
    explicit_home: bool,
    claude_config_dir: Option<&Path>,
    warnings: &mut Vec<String>,
) {
    let mut seen = BTreeSet::new();
    for kind in HarnessKind::ALL {
        if let Some((primary, extras)) =
            skill_paths_for_kind(kind, home, explicit_home, claude_config_dir)
        {
            for installed in std::iter::once(primary).chain(extras) {
                if seen.insert(canonical_dedup_key(&installed)) {
                    crate::skill_render::migrate_installed_skill(
                        &installed,
                        &legacy_setup_skills(home, &installed),
                        is_stock_legacy_setup_skill,
                        |_| HYPHAE_SETUP_SKILL_MD.to_owned(),
                        warnings,
                    );
                }
            }
        }
    }
}

/// Entrypoint for `hyp onboard --install-skill`.
pub fn run_install_skill(
    home: &Path,
    explicit_home: bool,
    claude_config_dir: Option<&Path>,
    harness_spec: Option<&str>,
    as_json: bool,
) -> Result<ExitCode, CliError> {
    let cmd = "onboard";
    let include_path_scan = !explicit_home;
    let targets = match parse_skill_harness_selection(
        harness_spec,
        home,
        include_path_scan,
        explicit_home,
        claude_config_dir,
    ) {
        Ok(t) => t,
        Err(e) => {
            return Err(CliError::usage("INVALID_HARNESS", e).with_fix(
                    "Use --harness all, auto, or one of: claude, codex, antigravity (agy), opencode, cursor, gemini, openclaw, t3."
                        .to_string(),
                ));
        }
    };

    let installed = match install_setup_skill_for_harnesses_with_claude(
        home,
        explicit_home,
        claude_config_dir,
        &targets,
    ) {
        Ok(v) => v,
        Err(e) => {
            return Err(CliError::error("SKILL_INSTALL_FAILED", e));
        }
    };

    let mut warnings = Vec::new();
    if installed.is_empty() {
        warnings.push(format!(
            "No supported harness directories detected under {}. Pass `--harness all` to install for all harnesses.",
            home.display()
        ));
    }

    let summary = format!(
        "Installed 'hyp-setup' skill for {} harness target(s)",
        installed.len()
    );
    let next = if installed.is_empty() {
        vec![format!(
            "hyp onboard --install-skill --harness all --home {}",
            home.display()
        )]
    } else {
        vec![
            "Open any configured agent harness and invoke the 'hyp-setup' skill.".to_string(),
            "Or run `hyp onboard --assist` to launch guided setup directly.".to_string(),
        ]
    };

    if as_json {
        let envelope = JsonEnvelope::ok(
            cmd.to_string(),
            summary,
            json!({
                "mode": "install-skill",
                "skill": "hyp-setup",
                "home": home.display().to_string(),
                "installedCount": installed.len(),
                "installed": installed,
            }),
        )
        .warnings(warnings)
        .next(next);
        print_json(&envelope);
    } else {
        println!("OK    {summary}");
        for item in &installed {
            println!("  [{:<11}] {}", item.harness, item.path);
            for extra in &item.extra_paths {
                println!("  [{:<11}] {} (cross-tool)", item.harness, extra);
            }
        }
        print_warnings(&warnings);
        print_next_steps(&next);
    }

    Ok(ExitCode::from(EXIT_OK))
}

// ============================================================================
// Existing Node Detection, Prompt Construction, Clipboard & Launchers
// ============================================================================

fn detect_existing_node(args: &OnboardArgs, home: &Path) -> Option<ExistingNodeInfo> {
    let config_path = resolve_config_path_for_read(None, args.state_dir.as_deref(), Some(home));
    if !config_path.exists() {
        return None;
    }
    match load_node_or_legacy_config(&config_path) {
        Ok(loaded) => Some(ExistingNodeInfo {
            node_id: loaded.node_id.unwrap_or_else(default_node_id),
            config_path: loaded.path,
            is_legacy_v1: loaded.is_legacy_v1,
        }),
        Err(_) => Some(ExistingNodeInfo {
            node_id: default_node_id(),
            config_path,
            is_legacy_v1: false,
        }),
    }
}

pub fn build_onboarding_prompt(skill_path: &Path, existing_node_id: Option<&str>) -> String {
    let path_str = skill_path.display();
    if let Some(node_id) = existing_node_id {
        format!(
            "Load and follow the hyp-setup skill (installed at {path_str}) to inspect my existing Hyphae node ({node_id}) and help me update my harnesses, peers, hubs, streams, bridges, or security gates."
        )
    } else {
        format!(
            "Load and follow the hyp-setup skill (installed at {path_str}) to onboard me to Hyphae and configure my local node, harnesses, and any peers, hubs, streams, bridges, or security gates I want."
        )
    }
}

/// Crisp copy-pasteable onboarding prompt for Path B (Desktop/IDE/GUI harnesses & config-only CLIs).
pub fn build_manual_guide_prompt(
    harness: ManualGuideHarness,
    existing_node_id: Option<&str>,
) -> String {
    if let Some(node_id) = existing_node_id {
        return format!(
            "Load and follow the hyp-setup skill to inspect my existing Hyphae node ({node_id}) and configure my harnesses, peers, and transports."
        );
    }
    match harness {
        ManualGuideHarness::ClaudeDesktop
        | ManualGuideHarness::CodexDesktop
        | ManualGuideHarness::OpenCodeDesktop
        | ManualGuideHarness::CursorIde => {
            "Set up Hyphae on this machine using the hyp-setup skill".to_string()
        }
        ManualGuideHarness::Openclaw
        | ManualGuideHarness::T3
        | ManualGuideHarness::ConfigOnlyCli(_) => {
            "Load and follow the hyp-setup skill to onboard me to Hyphae and configure my local node, harnesses, and transports."
                .to_string()
        }
    }
}

fn pipe_to_clipboard_command(program: &str, args: &[&str], text: &str) -> bool {
    let Ok(mut child) = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    else {
        return false;
    };
    if let Some(mut stdin) = child.stdin.take() {
        if stdin.write_all(text.as_bytes()).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            return false;
        }
    }
    child.wait().is_ok_and(|s| s.success())
}

/// Copies `text` to the OS clipboard using native platform tools (zero external crates).
fn copy_text_to_clipboard(text: &str) -> Result<&'static str, String> {
    #[cfg(target_os = "macos")]
    {
        if pipe_to_clipboard_command("pbcopy", &[], text) {
            return Ok("pbcopy");
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if std::env::var_os("WAYLAND_DISPLAY").is_some()
            && pipe_to_clipboard_command("wl-copy", &[], text)
        {
            return Ok("wl-copy");
        }
        if pipe_to_clipboard_command("xclip", &["-selection", "clipboard"], text) {
            return Ok("xclip");
        }
        if pipe_to_clipboard_command("xsel", &["--clipboard", "--input"], text) {
            return Ok("xsel");
        }
        if pipe_to_clipboard_command("wl-copy", &[], text) {
            return Ok("wl-copy");
        }
    }
    #[cfg(windows)]
    {
        if pipe_to_clipboard_command("clip", &[], text) {
            return Ok("clip");
        }
    }
    Err("No clipboard utility found (copy the prompt above manually).".to_string())
}

/// Launches a desktop deep link or HTTP URL using the native OS opener without shell interpolation.
fn open_url_in_os(url: &str) -> Result<&'static str, String> {
    let trimmed = url.trim();
    if trimmed.is_empty()
        || trimmed.chars().any(char::is_control)
        || trimmed.chars().any(char::is_whitespace)
    {
        return Err("refusing to open invalid URL".to_string());
    }
    if std::env::var("HYPHAE_NO_OPEN").ok().as_deref() == Some("1") {
        return Ok("noop");
    }

    #[cfg(target_os = "macos")]
    {
        let status = Command::new("open")
            .arg(trimmed)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| format!("failed launching 'open': {e}"))?;
        if status.success() {
            Ok("open")
        } else {
            Err(format!("'open' exited with status {status}"))
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let status = Command::new("xdg-open")
            .arg(trimmed)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| format!("failed launching 'xdg-open': {e}"))?;
        if status.success() {
            Ok("xdg-open")
        } else {
            Err(format!("'xdg-open' exited with status {status}"))
        }
    }
    #[cfg(windows)]
    {
        let status = Command::new("cmd")
            .args(["/C", "start", ""])
            .arg(trimmed)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| format!("failed launching 'cmd /C start': {e}"))?;
        if status.success() {
            Ok("cmd")
        } else {
            Err(format!("'cmd /C start' exited with status {status}"))
        }
    }
    #[cfg(not(any(unix, windows)))]
    {
        Err("URL opening is unsupported on this platform".to_string())
    }
}

/// Copies the onboarding prompt to clipboard first (cold-start fallback) and opens the app deep link.
fn trigger_open_in_app(harness: ManualGuideHarness, prompt: &str, deeplink: &str) -> String {
    let copied = copy_text_to_clipboard(prompt).is_ok();
    match open_url_in_os(deeplink) {
        Ok(_) if copied => format!(
            "✓ Opened {} (prompt also copied to clipboard!)",
            harness.display_name()
        ),
        Ok(_) => format!(
            "✓ Opened {} (copy prompt above if needed)",
            harness.display_name()
        ),
        Err(err) if copied => format!(
            "✓ Copied prompt · could not launch {} ({err})",
            harness.display_name()
        ),
        Err(err) => format!(
            "Could not launch {} ({err}); copy prompt above manually.",
            harness.display_name()
        ),
    }
}

fn resolve_wizard_cli_bin(explicit_bin: Option<&Path>) -> String {
    if let Some(p) = explicit_bin {
        return p.display().to_string();
    }
    std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "hyp".to_string())
}

fn resolve_t3_url_from_home(
    home: &Path,
    existing_node: Option<&ExistingNodeInfo>,
) -> Option<String> {
    let config_path = existing_node
        .map(|node| node.config_path.clone())
        .unwrap_or_else(|| home.join(".config").join("hyphae").join("node.json"));
    let (file, _) = hyp_node::node_file::NodeFile::read(&config_path).ok()?;
    let t3 = file.t3?;
    sanitize_http_url(t3.url.as_deref())
}

fn resolve_manual_guide_deeplink(
    harness: ManualGuideHarness,
    prompt: &str,
    home: &Path,
    explicit_home: bool,
    existing_node: Option<&ExistingNodeInfo>,
) -> Option<String> {
    let cwd = std::env::current_dir().ok();
    let opencode_url = if explicit_home {
        None
    } else {
        std::env::var("OPENCODE_SERVER_URL").ok()
    };
    let t3_url = if harness == ManualGuideHarness::T3 {
        resolve_t3_url_from_home(home, existing_node)
    } else {
        None
    };
    build_manual_guide_deeplink(
        harness,
        prompt,
        cwd.as_deref(),
        opencode_url.as_deref(),
        t3_url.as_deref(),
    )
}

fn attach_interactive_stdio(cmd: &mut Command) {
    cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
    // Attach `/dev/tty` for stdin when launched from a piped script like `curl | sh` in a TTY.
    // Never touch `/dev/tty` if stdout isn't a TTY (keeps automated E2E tests 100% isolated).
    #[cfg(unix)]
    {
        if io::stdout().is_terminal() && !io::stdin().is_terminal() {
            if let Ok(tty_file) = fs::File::open("/dev/tty") {
                cmd.stdin(Stdio::from(tty_file));
                return;
            }
        }
    }
    cmd.stdin(Stdio::inherit());
}

fn spawn_interactive_harness(
    harness: LaunchableHarness,
    exe_path: &Path,
    prompt: &str,
) -> Result<ExitCode, CliError> {
    let spec = harness.build_launch_spec(prompt);
    let mut cmd = Command::new(exe_path);
    cmd.args(&spec.args);
    attach_interactive_stdio(&mut cmd);

    match status_retrying_busy(&mut cmd) {
        Ok(status) => match status.code() {
            Some(code) => Ok(ExitCode::from((code.clamp(0, 255)) as u8)),
            None => Ok(ExitCode::from(EXIT_ERROR)),
        },
        Err(e) => Err(CliError::error(
            "LAUNCH_FAILED",
            format!(
                "Failed to launch {} ({}): {e}",
                harness.display_name(),
                exe_path.display()
            ),
        )
        .with_fix("Run `hyp onboard --yes` for quick local CLI setup.".to_string())),
    }
}

fn spawn_herdr_template(
    hc_bin: &Path,
    template_name: &str,
    prompt: &str,
    as_json: bool,
) -> Result<ExitCode, CliError> {
    let mut cmd = build_herdr_template_launch_command(hc_bin, template_name, prompt);
    cmd.stdin(Stdio::null());

    let output = match output_retrying_busy(&mut cmd) {
        Ok(out) => out,
        Err(e) => {
            return Err(CliError::error(
                "HERDR_LAUNCH_FAILED",
                format!(
                    "Failed to launch Herdr template '{template_name}' via {}: {e}",
                    hc_bin.display()
                ),
            )
            .with_fix(
                "Run `hc templates` to verify Herdr, or `hyp onboard --yes` for local CLI setup."
                    .to_string(),
            ));
        }
    };

    if !output.status.success() {
        let stderr_raw = String::from_utf8_lossy(&output.stderr);
        let stderr_snippet = truncate_chars(stderr_raw.trim(), 240);
        let detail = if stderr_snippet.is_empty() {
            let stdout_raw = String::from_utf8_lossy(&output.stdout);
            let stdout_snippet = truncate_chars(stdout_raw.trim(), 240);
            if stdout_snippet.is_empty() {
                format!(
                    "Herdr exited with status {} while launching template '{template_name}'",
                    output
                        .status
                        .code()
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "signal".to_string())
                )
            } else {
                format!("Herdr failed launching template '{template_name}': {stdout_snippet}")
            }
        } else {
            format!("Herdr failed launching template '{template_name}': {stderr_snippet}")
        };
        return Err(CliError::error("HERDR_LAUNCH_FAILED", detail).with_fix(
            "Run `hc templates` to verify Herdr, or `hyp onboard --yes` for local CLI setup."
                .to_string(),
        ));
    }

    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let Some(address) = parse_herdr_run_address_json(&stdout_raw) else {
        let snippet = truncate_chars(stdout_raw.trim(), 200);
        return Err(CliError::error("HERDR_LAUNCH_FAILED", format!(
                "Herdr launched template '{template_name}' but returned no valid terminal address (stdout: {snippet})"
            )).with_fix("Run `hc list` to inspect running Herdr terminals.".to_string()));
    };

    let raise_window = !as_json && io::stdout().is_terminal();
    let opened_in_herdr_app = try_open_in_herdr_app_tab(&address, raise_window);
    let next = if opened_in_herdr_app {
        Vec::new()
    } else {
        vec![format!("hc attach {address}")]
    };
    let summary = if opened_in_herdr_app {
        format!("Opened Herdr template '{template_name}' in a new Herdr app tab ({address})")
    } else {
        format!("Launched Herdr template '{template_name}' in terminal {address}")
    };

    if as_json {
        let envelope = JsonEnvelope::ok(
            "onboard".to_string(),
            summary,
            json!({
                "mode": "herdr_launch",
                "template": template_name,
                "terminal": address,
                "openedInHerdrApp": opened_in_herdr_app,
            }),
        )
        .next(next);
        print_json(&envelope);
        return Ok(ExitCode::from(EXIT_OK));
    }

    if opened_in_herdr_app || !io::stdout().is_terminal() {
        println!("OK    {summary}");
        println!("      Template: {template_name}");
        println!("      Terminal: {address}");
        if opened_in_herdr_app {
            println!("      Window:   Herdr app (focused tab)");
        }
        print_next_steps(&next);
        return Ok(ExitCode::from(EXIT_OK));
    }

    println!("Launched Herdr terminal {address} — attaching (Ctrl+\\ to detach)...");
    let mut attach_cmd = build_herdr_attach_command(hc_bin, &address);
    match status_retrying_busy(&mut attach_cmd) {
        Ok(status) => match status.code() {
            Some(code) => Ok(ExitCode::from((code.clamp(0, 255)) as u8)),
            None => Ok(ExitCode::from(EXIT_ERROR)),
        },
        Err(e) => Err(CliError::error(
            "HERDR_LAUNCH_FAILED",
            format!(
                "Launched Herdr terminal '{address}', but failed to attach via {}: {e}",
                hc_bin.display()
            ),
        )
        .with_fix(format!("Attach manually with: hc attach {address}"))),
    }
}

fn collect_skill_targets_with_primary(
    primary: Option<HarnessKind>,
    home: &Path,
    explicit_home: bool,
    claude_config_dir: Option<&Path>,
) -> Vec<HarnessKind> {
    let mut targets = Vec::new();
    if let Some(kind) = primary {
        targets.push(kind);
    }
    let include_path_scan = !explicit_home;
    for kind in HarnessKind::ALL {
        if !targets.contains(&kind)
            && skill_paths_for_kind(kind, home, explicit_home, claude_config_dir).is_some()
            && is_skill_harness_detected(
                kind,
                home,
                include_path_scan,
                explicit_home,
                claude_config_dir,
            )
        {
            targets.push(kind);
        }
    }
    targets
}

fn print_installed_skills_banner(installed: &[InstalledSkillEntry]) {
    println!();
    println!("Installed 'hyp-setup' skill:");
    for item in installed {
        println!("  • [{}] {}", item.harness, item.path);
        for extra in &item.extra_paths {
            println!("  • [{}] {} (cross-tool)", item.harness, extra);
        }
    }
}

fn install_and_handoff_cli(
    chosen: LaunchableHarness,
    home: &Path,
    explicit_home: bool,
    claude_config_dir: Option<&Path>,
    existing_node: Option<&ExistingNodeInfo>,
    cli_bin: &str,
    as_json: bool,
) -> Result<ExitCode, CliError> {
    // If the CLI binary is not on PATH, seamlessly fall back to Path B (install skill + guide)
    // instead of failing with a broken exec error.
    let Some(exe_path) = find_executable_in_path(chosen.binary_name()) else {
        let guide = match chosen {
            LaunchableHarness::Cursor => ManualGuideHarness::CursorIde,
            LaunchableHarness::Codex => ManualGuideHarness::CodexDesktop,
            other => ManualGuideHarness::ConfigOnlyCli(other),
        };
        return install_and_emit_manual_guide(
            guide,
            home,
            explicit_home,
            claude_config_dir,
            existing_node,
            cli_bin,
            as_json,
        );
    };

    let targets = collect_skill_targets_with_primary(
        Some(chosen.kind()),
        home,
        explicit_home,
        claude_config_dir,
    );
    let installed = match install_setup_skill_for_harnesses_with_claude(
        home,
        explicit_home,
        claude_config_dir,
        &targets,
    ) {
        Ok(v) => v,
        Err(e) => {
            return Err(CliError::error("SKILL_INSTALL_FAILED", e));
        }
    };

    let primary_skill = resolved_setup_skill(
        home,
        &chosen.primary_skill_path_for(home, explicit_home, claude_config_dir),
    )
    .map_err(|e| CliError::error("SKILL_INSTALL_FAILED", e))?;
    if !as_json {
        print_installed_skills_banner(&installed);
        println!();
        println!(
            "Launching {} ({})...",
            chosen.display_name(),
            chosen.binary_name()
        );
    }

    let prompt = build_onboarding_prompt(&primary_skill, existing_node.map(|n| n.node_id.as_str()));
    spawn_interactive_harness(chosen, &exe_path, &prompt)
}

fn install_and_handoff_herdr(
    hc_bin: &Path,
    template: &HerdrTemplate,
    home: &Path,
    explicit_home: bool,
    claude_config_dir: Option<&Path>,
    existing_node: Option<&ExistingNodeInfo>,
    as_json: bool,
) -> Result<ExitCode, CliError> {
    let inferred = infer_harness_from_herdr_template(&template.name, &template.command);
    let targets = collect_skill_targets_with_primary(
        inferred.map(LaunchableHarness::kind),
        home,
        explicit_home,
        claude_config_dir,
    );

    let mut installed = match install_setup_skill_for_harnesses_with_claude(
        home,
        explicit_home,
        claude_config_dir,
        &targets,
    ) {
        Ok(v) => v,
        Err(e) => {
            return Err(CliError::error("SKILL_INSTALL_FAILED", e));
        }
    };

    let primary_skill = if let Some(lh) = inferred {
        resolved_setup_skill(
            home,
            &lh.primary_skill_path_for(home, explicit_home, claude_config_dir),
        )
        .map_err(|e| CliError::error("SKILL_INSTALL_FAILED", e))?
    } else if let Some(first) = installed.first() {
        PathBuf::from(&first.path)
    } else {
        // Fallback cross-tool location when template name doesn't name a known harness and no
        // harness dirs exist under `home` yet.
        let fallback = shared_setup_skill_path(home);
        let fallback = write_setup_skill(home, &fallback)
            .map_err(|e| CliError::error("SKILL_INSTALL_FAILED", e))?;
        installed.push(InstalledSkillEntry {
            harness: "agents".to_string(),
            path: fallback.display().to_string(),
            extra_paths: Vec::new(),
        });
        fallback
    };

    if !as_json {
        print_installed_skills_banner(&installed);
        println!();
        println!(
            "Launching Herdr template '{}' ({} run --bg --outlive-parent {})...",
            template.display_title(),
            hc_bin.display(),
            template.name
        );
    }

    let prompt = build_onboarding_prompt(&primary_skill, existing_node.map(|n| n.node_id.as_str()));
    spawn_herdr_template(hc_bin, &template.name, &prompt, as_json)
}

fn install_manual_guide_skills(
    harness: ManualGuideHarness,
    home: &Path,
    explicit_home: bool,
    claude_config_dir: Option<&Path>,
) -> Result<(PathBuf, Vec<InstalledSkillEntry>), String> {
    let targets = collect_skill_targets_with_primary(
        Some(harness.kind()),
        home,
        explicit_home,
        claude_config_dir,
    );
    let mut installed = install_setup_skill_for_harnesses_with_claude(
        home,
        explicit_home,
        claude_config_dir,
        &targets,
    )?;

    // Ensure harness-specific extra cross-tool skill paths (e.g. OpenCode Desktop `~/.agents`)
    // are also written and recorded cleanly without duplicates.
    let mut already_recorded: BTreeSet<PathBuf> = BTreeSet::new();
    for item in &installed {
        already_recorded.insert(canonical_dedup_key(Path::new(&item.path)));
        for extra in &item.extra_paths {
            already_recorded.insert(canonical_dedup_key(Path::new(extra)));
        }
    }
    for extra in harness.extra_skill_paths_for(home, explicit_home, claude_config_dir) {
        let resolved = resolved_setup_skill(home, &extra)?;
        if already_recorded.insert(canonical_dedup_key(&resolved)) {
            let extra = write_setup_skill(home, &extra)?;
            already_recorded.insert(canonical_dedup_key(&extra));
            let extra_str = extra.display().to_string();
            if let Some(first) = installed.first_mut() {
                first.extra_paths.push(extra_str);
            } else {
                installed.push(InstalledSkillEntry {
                    harness: harness.id().to_string(),
                    path: extra_str,
                    extra_paths: Vec::new(),
                });
            }
        }
    }

    Ok((
        resolved_setup_skill(
            home,
            &harness.primary_skill_path_for(home, explicit_home, claude_config_dir),
        )?,
        installed,
    ))
}

#[allow(clippy::too_many_arguments)]
fn print_manual_guide_plain(
    harness: ManualGuideHarness,
    home: &Path,
    cli_bin: &str,
    primary_skill: &Path,
    installed: &[InstalledSkillEntry],
    prompt: &str,
    mcp_status: &DesktopMcpStatus,
    deeplink: Option<&str>,
) {
    println!();
    println!(
        "OK    Installed 'hyp-setup' skill to {}",
        primary_skill.display()
    );
    for item in installed {
        for extra in &item.extra_paths {
            println!("      + {extra}");
        }
    }
    match mcp_status {
        DesktopMcpStatus::Applied(cfg_path) => {
            println!("OK    Updated MCP config at {}", cfg_path.display());
        }
        DesktopMcpStatus::AlreadyConfigured(cfg_path) => {
            println!(
                "OK    MCP config already configured at {}",
                cfg_path.display()
            );
        }
        DesktopMcpStatus::Skipped | DesktopMcpStatus::NotApplicable => {
            if let Some((cfg_path, snippet)) = harness.mcp_config_note(home, cli_bin) {
                println!();
                println!("MCP config ({}):", cfg_path.display());
                for line in snippet.lines() {
                    println!("  {line}");
                }
            }
        }
    }
    println!();
    println!("Next steps for {}:", harness.display_name());
    let step1 = match mcp_status {
        DesktopMcpStatus::Applied(_) => harness.restart_instruction(),
        _ => harness.open_instruction(),
    };
    println!("  1. {step1}");
    if matches!(mcp_status, DesktopMcpStatus::Applied(_)) && deeplink.is_some() {
        println!("  2. Paste this prompt into a new chat (or press [o] to open prefilled):");
    } else {
        println!("  2. Paste this prompt:");
    }
    println!();
    println!("     {prompt}");
    if let Some(url) = deeplink {
        println!();
        println!("  Deep link: {url}");
    }
    println!();
}

fn install_and_emit_manual_guide(
    harness: ManualGuideHarness,
    home: &Path,
    explicit_home: bool,
    claude_config_dir: Option<&Path>,
    existing_node: Option<&ExistingNodeInfo>,
    cli_bin: &str,
    as_json: bool,
) -> Result<ExitCode, CliError> {
    let (primary_skill, installed) =
        match install_manual_guide_skills(harness, home, explicit_home, claude_config_dir) {
            Ok(res) => res,
            Err(e) => {
                return Err(CliError::error("SKILL_INSTALL_FAILED", e));
            }
        };

    let prompt = build_manual_guide_prompt(harness, existing_node.map(|n| n.node_id.as_str()));
    let deeplink =
        resolve_manual_guide_deeplink(harness, &prompt, home, explicit_home, existing_node);
    let mcp_plan = inspect_desktop_mcp_plan(harness, home, cli_bin);
    let mcp_status = match &mcp_plan {
        Some(plan) if plan.already_configured => {
            DesktopMcpStatus::AlreadyConfigured(plan.config_path.clone())
        }
        Some(_) => DesktopMcpStatus::Skipped,
        None => DesktopMcpStatus::NotApplicable,
    };
    let mcp_note = harness.mcp_config_note(home, cli_bin);
    let mut steps = vec![harness.open_instruction()];
    if !matches!(mcp_status, DesktopMcpStatus::AlreadyConfigured(_)) {
        if let Some((ref cfg_path, _)) = mcp_note {
            steps.push(format!(
                "Add the Hyphae MCP server entry to {} (or run `hyp setup` for CLI hooks).",
                cfg_path.display()
            ));
        }
    }
    steps.push(format!("Paste this prompt: {prompt}"));

    if as_json {
        let mut data = json!({
            "mode": "manual_guide",
            "harness": harness.id(),
            "displayName": harness.display_name(),
            "skill": "hyp-setup",
            "primarySkillPath": primary_skill.display().to_string(),
            "installedCount": installed.len(),
            "installed": installed,
            "prompt": prompt,
            "steps": steps,
        });
        if let Some(obj) = data.as_object_mut() {
            if let Some((cfg_path, snippet)) = mcp_note {
                obj.insert(
                    "mcpConfigPath".to_string(),
                    json!(cfg_path.display().to_string()),
                );
                obj.insert("mcpSnippet".to_string(), json!(snippet));
            }
            if let Some(ref plan) = mcp_plan {
                obj.insert(
                    "mcpAlreadyConfigured".to_string(),
                    json!(plan.already_configured),
                );
            }
            if let Some(ref url) = deeplink {
                obj.insert("deeplink".to_string(), json!(url));
            }
        }
        let envelope = JsonEnvelope::ok(
            "onboard".to_string(),
            format!(
                "Installed 'hyp-setup' skill for {} (manual handoff guide)",
                harness.display_name()
            ),
            data,
        )
        .next(steps);
        print_json(&envelope);
        return Ok(ExitCode::from(EXIT_OK));
    }

    print_manual_guide_plain(
        harness,
        home,
        cli_bin,
        &primary_skill,
        &installed,
        &prompt,
        &mcp_status,
        deeplink.as_deref(),
    );
    Ok(ExitCode::from(EXIT_OK))
}

// ============================================================================
// Fullscreen Arrow-Key TUI Renderer, Viewport Scrolling & State Machine
// ============================================================================

/// Computed visible viewport slice for scrollable TUI lists (`start..end` plus hidden counts).
#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScrollWindow {
    pub start: usize,
    pub end: usize,
    pub above: usize,
    pub below: usize,
}

/// Computes a bounded visible slice of `0..total` inside `max_rows` (including room for
/// `↑ N more` / `↓ M more` scroll hints) while ALWAYS keeping `selected` visible.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn compute_scroll_window(total: usize, selected: usize, max_rows: usize) -> ScrollWindow {
    if total == 0 || max_rows == 0 {
        return ScrollWindow {
            start: 0,
            end: 0,
            above: 0,
            below: 0,
        };
    }
    let sel = selected.min(total - 1);
    if total <= max_rows {
        return ScrollWindow {
            start: 0,
            end: total,
            above: 0,
            below: 0,
        };
    }
    if max_rows == 1 {
        return ScrollWindow {
            start: sel,
            end: sel + 1,
            above: 0,
            below: 0,
        };
    }
    if max_rows == 2 {
        if sel == 0 {
            return ScrollWindow {
                start: 0,
                end: 1,
                above: 0,
                below: total - 1,
            };
        }
        return ScrollWindow {
            start: sel,
            end: sel + 1,
            above: sel,
            below: 0,
        };
    }

    let edge_visible = max_rows - 1;
    let mid_visible = max_rows - 2;
    let half = mid_visible / 2;

    if sel <= half {
        let end = edge_visible.min(total);
        return ScrollWindow {
            start: 0,
            end,
            above: 0,
            below: total.saturating_sub(end),
        };
    }
    let bottom_threshold = total.saturating_sub(edge_visible - half);
    if sel >= bottom_threshold {
        let start = total.saturating_sub(edge_visible);
        return ScrollWindow {
            start,
            end: total,
            above: start,
            below: 0,
        };
    }

    let max_start = total.saturating_sub(mid_visible + 1).max(1);
    let start = sel.saturating_sub(half).clamp(1, max_start);
    let end = (start + mid_visible).min(total.saturating_sub(1));
    ScrollWindow {
        start,
        end,
        above: start,
        below: total.saturating_sub(end),
    }
}

#[cfg_attr(not(unix), allow(dead_code))]
fn safe_content_width(term_cols: usize, max_w: usize) -> usize {
    let available = term_cols.saturating_sub(2).max(1);
    let preferred = term_cols.saturating_sub(4).min(max_w);
    preferred.min(available).max(1)
}

#[cfg(unix)]
enum WizardScreen {
    Main {
        selected: usize,
    },
    LocalSetupConfig {
        state: SetupToggleState,
        main_selected: usize,
    },
    OpenClawLocalSetup {
        state: OpenClawConfigState,
        toggle_state: SetupToggleState,
        main_selected: usize,
    },
    OpenClawAssistConfig {
        state: OpenClawConfigState,
        primary_skill: PathBuf,
        installed: Vec<InstalledSkillEntry>,
        prompt: String,
        deeplink: Option<String>,
        error_status: Option<String>,
        main_selected: usize,
        allow_back: bool,
    },
    HerdrTemplates {
        hc_bin: PathBuf,
        templates: Vec<HerdrTemplate>,
        selected: usize,
        main_selected: usize,
        allow_back: bool,
    },
    DesktopMcpConfirm {
        harness: ManualGuideHarness,
        plan: DesktopMcpPlan,
        primary_skill: PathBuf,
        installed: Vec<InstalledSkillEntry>,
        prompt: String,
        deeplink: Option<String>,
        selected_option: usize,
        error_status: Option<String>,
        main_selected: usize,
        allow_back: bool,
    },
    ManualGuide {
        harness: ManualGuideHarness,
        primary_skill: PathBuf,
        installed: Vec<InstalledSkillEntry>,
        prompt: String,
        mcp_status: DesktopMcpStatus,
        deeplink: Option<String>,
        selected_action: usize,
        copied_status: Option<String>,
        main_selected: usize,
        allow_back: bool,
    },
}

enum WizardAction {
    Cancel,
    RunLocalCliSetupWithSelection(SetupSelection),
    LaunchCli(LaunchableHarness),
    LaunchHerdr {
        hc_bin: PathBuf,
        template: HerdrTemplate,
    },
    ManualGuide(ManualGuideHarness),
    #[cfg(unix)]
    ManualGuideDone {
        harness: ManualGuideHarness,
        primary_skill: PathBuf,
        installed: Vec<InstalledSkillEntry>,
        prompt: String,
        mcp_status: DesktopMcpStatus,
        deeplink: Option<String>,
    },
    #[cfg(unix)]
    Error(String),
}

/// Composes a borderless high-resolution 2×4 Unicode Braille mycelium & `HYPHAE` banner
/// floating cleanly above the fullscreen menu.
#[cfg_attr(not(unix), allow(dead_code))]
fn build_banner_lines_at_tick(
    term_rows: usize,
    term_cols: usize,
    content_w: usize,
    color_mode: ColorMode,
    anim_tick: usize,
) -> Vec<String> {
    if term_rows < 20 || term_cols < 32 || content_w < 24 {
        return Vec::new();
    }
    let art_h = if term_rows >= 34 {
        11
    } else if term_rows >= 28 {
        9
    } else {
        8
    };
    let banner_w = term_cols.saturating_sub(4).min(92);
    if banner_w < 24 {
        return Vec::new();
    }
    let art = render_frame(
        DEFAULT_TOTAL_FRAMES - 1,
        DEFAULT_TOTAL_FRAMES,
        anim_tick,
        banner_w,
        art_h,
        color_mode,
    );

    let left_pad = " ".repeat(term_cols.saturating_sub(banner_w) / 2);
    let mut lines = Vec::with_capacity(art_h + 1);
    for art_row in art.lines() {
        lines.push(format!("{left_pad}{art_row}"));
    }

    // Dimmed plain-text version centered directly underneath the animated HYPHAE wordmark.
    let ver_label = format!("v{}", env!("CARGO_PKG_VERSION"));
    let ver_pad = " ".repeat(term_cols.saturating_sub(ver_label.chars().count()) / 2);
    let ver_styled = match color_mode {
        ColorMode::Plain => ver_label,
        _ => format!(
            "\x1b[2m{}\x1b[0m",
            paint_styled_text(color_mode, RGB_UI_MUTED, false, &ver_label)
        ),
    };
    lines.push(format!("{ver_pad}{ver_styled}"));
    lines
}

#[cfg_attr(not(unix), allow(dead_code))]
#[allow(clippy::too_many_arguments)]
fn format_menu_row(
    selected: bool,
    label: &str,
    tag: Option<(&str, TagTone)>,
    subtitle: &str,
    label_col_w: usize,
    tag_col_w: usize,
    box_width: usize,
    left_pad: &str,
    color_mode: ColorMode,
) -> String {
    let inner_w = box_width.saturating_sub(2).max(16);
    let prefix = if selected { " ❯ " } else { "   " };
    let prefix_len = 3usize;

    let raw_tag = tag.map(|(t, _)| t).unwrap_or("");
    let show_tag = tag_col_w > 0 && inner_w >= prefix_len + 12 + 2 + tag_col_w;
    let effective_tag_w = if show_tag { tag_col_w } else { 0 };
    let label_max = if show_tag {
        label_col_w
            .min(
                inner_w
                    .saturating_sub(prefix_len + effective_tag_w + 4)
                    .max(8),
            )
            .max(1)
    } else {
        let sub_reserve = if subtitle.is_empty() {
            0
        } else {
            subtitle.chars().count().min(22) + 4
        };
        label_col_w
            .min(
                inner_w
                    .saturating_sub(prefix_len + sub_reserve + 1)
                    .max((inner_w / 2).min(inner_w.saturating_sub(prefix_len).max(1))),
            )
            .max(1)
    };
    let label_str = truncate_chars(label, label_max);
    let label_len = label_str.chars().count();
    let label_pad = " ".repeat(label_max.saturating_sub(label_len));

    let tag_str = if show_tag {
        truncate_chars(raw_tag, effective_tag_w)
    } else {
        String::new()
    };
    let tag_len = tag_str.chars().count();
    let tag_pad = if show_tag {
        " ".repeat(effective_tag_w.saturating_sub(tag_len))
    } else {
        String::new()
    };

    let used = prefix_len + label_max + if show_tag { 2 + effective_tag_w } else { 0 };
    let rem_for_sub = inner_w.saturating_sub(used + 2);
    let sub_str = if rem_for_sub >= 6 && !subtitle.is_empty() {
        truncate_chars(subtitle, rem_for_sub)
    } else {
        String::new()
    };
    let sub_len = sub_str.chars().count();
    let total_visible = used + if sub_len > 0 { 2 + sub_len } else { 0 };
    let trailing = " ".repeat(inner_w.saturating_sub(total_visible));

    if selected {
        match color_mode {
            ColorMode::Plain => {
                let mut line = format!("{prefix}{label_str}{label_pad}");
                if show_tag {
                    line.push_str("  ");
                    line.push_str(&tag_str);
                    line.push_str(&tag_pad);
                }
                if !sub_str.is_empty() {
                    line.push_str("  ");
                    line.push_str(&sub_str);
                }
                format!("{left_pad}\x1b[7m{line}{trailing}\x1b[0m")
            }
            ColorMode::Ansi256 => {
                let mut line = format!("{prefix}{label_str}{label_pad}");
                if show_tag {
                    line.push_str("  ");
                    line.push_str(&tag_str);
                    line.push_str(&tag_pad);
                }
                if !sub_str.is_empty() {
                    line.push_str("  ");
                    line.push_str(&sub_str);
                }
                format!("{left_pad}\x1b[7m\x1b[1m{line}{trailing}\x1b[0m")
            }
            ColorMode::TrueColor => {
                let bg = format!(
                    "\x1b[48;2;{};{};{}m",
                    RGB_UI_HIGHLIGHT_BG.0, RGB_UI_HIGHLIGHT_BG.1, RGB_UI_HIGHLIGHT_BG.2
                );
                let ivory = fg_color(color_mode, RGB_PULSE_IVORY);
                let amber = fg_color(color_mode, RGB_NODE_AMBER);
                let sage = fg_color(color_mode, RGB_HYPHAE_SAGE);
                let tag_rgb = match tag.map(|(_, tone)| tone) {
                    Some(TagTone::Launch) => RGB_UI_TAG_LAUNCH,
                    Some(TagTone::Guide) => RGB_UI_TAG_GUIDE,
                    Some(TagTone::Local) | None => RGB_UI_TAG_LOCAL,
                };
                let tag_fg = fg_color(color_mode, tag_rgb);

                let mut row = format!(
                    "{left_pad}{bg}{amber}\x1b[1m{prefix}{ivory}{label_str}{label_pad}\x1b[22m"
                );
                if show_tag {
                    row.push_str(&format!("  {tag_fg}{tag_str}{tag_pad}"));
                }
                if !sub_str.is_empty() {
                    row.push_str(&format!("  {sage}{sub_str}"));
                }
                row.push_str(&format!("{trailing}\x1b[0m"));
                row
            }
        }
    } else {
        let label_styled = paint_styled_text(color_mode, RGB_PULSE_IVORY, false, &label_str);
        let tag_styled = if !show_tag || tag_str.is_empty() {
            String::new()
        } else {
            match tag {
                Some((_, TagTone::Launch)) => {
                    paint_styled_text(color_mode, RGB_UI_TAG_LAUNCH, false, &tag_str)
                }
                Some((_, TagTone::Guide)) => {
                    paint_styled_text(color_mode, RGB_UI_TAG_GUIDE, false, &tag_str)
                }
                Some((_, TagTone::Local)) => {
                    paint_styled_text(color_mode, RGB_UI_TAG_LOCAL, false, &tag_str)
                }
                None => String::new(),
            }
        };
        let sub_styled = paint_styled_text(color_mode, RGB_UI_MUTED, false, &sub_str);

        let mut row = format!("{left_pad}{prefix}{label_styled}{label_pad}");
        if show_tag {
            row.push_str("  ");
            row.push_str(&tag_styled);
            row.push_str(&tag_pad);
        }
        if !sub_str.is_empty() {
            row.push_str("  ");
            row.push_str(&sub_styled);
        }
        row
    }
}

#[cfg(unix)]
fn flush_screen_lines(lines: &[String], term_rows: usize) {
    let mut frame = String::with_capacity(term_rows * 96 + 32);
    frame.push_str("\x1b[?2026h\x1b[H");
    for row_idx in 0..term_rows {
        let row_num = row_idx + 1;
        use std::fmt::Write as _;
        if let Some(line) = lines.get(row_idx) {
            let _ = write!(frame, "\x1b[{row_num};1H{line}\x1b[K");
        } else {
            let _ = write!(frame, "\x1b[{row_num};1H\x1b[K");
        }
    }
    frame.push_str("\x1b[J\x1b[?2026l");
    let mut out = io::stdout().lock();
    let _ = out.write_all(frame.as_bytes());
    let _ = out.flush();
}

/// Pure, cross-platform main menu frame composer with bounded viewport scrolling (`↑ N more` /
/// `↓ M more`), safe left-margin clamping, Herdr-environment header context, and living pulse tick.
#[cfg_attr(not(unix), allow(dead_code))]
#[allow(clippy::too_many_arguments)]
pub fn render_main_menu(
    items: &[MainMenuItem],
    selected: usize,
    existing_node_id: Option<&str>,
    is_legacy_v1: bool,
    _in_herdr_env: Option<&str>,
    term_rows: usize,
    term_cols: usize,
    color_mode: ColorMode,
    anim_tick: usize,
) -> Vec<String> {
    if term_rows == 0 {
        return Vec::new();
    }
    let content_w = safe_content_width(term_cols, 76);
    let left_pad = " ".repeat(term_cols.saturating_sub(content_w) / 2);
    let mut lines = Vec::new();

    let banner = build_banner_lines_at_tick(term_rows, term_cols, content_w, color_mode, anim_tick);
    lines.extend(banner);
    if !lines.is_empty() {
        lines.push(String::new());
    }

    let prompt_line = if let Some(node_id) = existing_node_id {
        let legacy = if is_legacy_v1 { " · legacy v1" } else { "" };
        format!("Who should guide setup? ({node_id}{legacy})")
    } else {
        "Who should guide setup?".to_string()
    };
    lines.push(format!(
        "{left_pad}{}",
        paint_styled_text(
            color_mode,
            RGB_HYPHAE_SAGE,
            false,
            &truncate_chars(&prompt_line, content_w)
        )
    ));
    lines.push(String::new());

    // Compute aligned column widths across all menu items so columns stay crisp while scrolling.
    let label_col_w = items
        .iter()
        .map(|i| i.label.chars().count())
        .max()
        .unwrap_or(14)
        .clamp(12, 24);
    let tag_col_w = items
        .iter()
        .map(|i| i.tag.chars().count())
        .max()
        .unwrap_or(0)
        .min(14);

    // Reserve exact footer height (blank line + keybinding line) so total never overflows `term_rows`.
    let footer_lines = 2usize;
    let avail_rows = term_rows.saturating_sub(lines.len() + footer_lines).max(1);
    let win = compute_scroll_window(items.len(), selected, avail_rows);

    if win.above > 0 {
        let hint = format!("   ↑ {} more", win.above);
        lines.push(format!(
            "{left_pad}{}",
            paint_styled_text(
                color_mode,
                RGB_UI_MUTED,
                false,
                &truncate_chars(&hint, content_w)
            )
        ));
    }

    for (idx, item) in items.iter().enumerate().take(win.end).skip(win.start) {
        lines.push(format_menu_row(
            idx == selected,
            &item.label,
            Some((item.tag, item.tag_tone())),
            &item.subtitle,
            label_col_w,
            tag_col_w,
            content_w,
            &left_pad,
            color_mode,
        ));
    }

    if win.below > 0 {
        let hint = format!("   ↓ {} more", win.below);
        lines.push(format!(
            "{left_pad}{}",
            paint_styled_text(
                color_mode,
                RGB_UI_MUTED,
                false,
                &truncate_chars(&hint, content_w)
            )
        ));
    }

    lines.push(String::new());
    let footer = truncate_chars("↑/↓ move · Enter select · q quit", content_w);
    lines.push(format!(
        "{left_pad}{}",
        paint_styled_text(color_mode, RGB_UI_MUTED, false, &footer)
    ));

    if lines.len() > term_rows {
        lines.truncate(term_rows);
    }

    // Vertically center only if there is comfortable extra space.
    let top_pad = term_rows.saturating_sub(lines.len()) / 3;
    let mut padded = vec![String::new(); top_pad];
    padded.extend(lines);
    padded
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn render_main_screen(
    items: &[MainMenuItem],
    selected: usize,
    existing_node: Option<&ExistingNodeInfo>,
    in_herdr_env: Option<&str>,
    term_rows: usize,
    term_cols: usize,
    color_mode: ColorMode,
    anim_tick: usize,
) {
    let lines = render_main_menu(
        items,
        selected,
        existing_node.map(|n| n.node_id.as_str()),
        existing_node.is_some_and(|n| n.is_legacy_v1),
        in_herdr_env,
        term_rows,
        term_cols,
        color_mode,
        anim_tick,
    );
    flush_screen_lines(&lines, term_rows);
}

/// Pure, cross-platform Herdr template picker frame composer with bounded viewport scrolling.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn render_herdr_templates(
    templates: &[HerdrTemplate],
    selected: usize,
    allow_back: bool,
    term_rows: usize,
    term_cols: usize,
    color_mode: ColorMode,
    anim_tick: usize,
) -> Vec<String> {
    if term_rows == 0 {
        return Vec::new();
    }
    let content_w = safe_content_width(term_cols, 76);
    let left_pad = " ".repeat(term_cols.saturating_sub(content_w) / 2);
    let mut lines = Vec::new();

    if term_rows >= 26 {
        lines.extend(build_banner_lines_at_tick(
            term_rows.min(27),
            term_cols,
            content_w,
            color_mode,
            anim_tick,
        ));
        if !lines.is_empty() {
            lines.push(String::new());
        }
    }

    lines.push(format!(
        "{left_pad}{}",
        paint_styled_text(
            color_mode,
            RGB_PULSE_IVORY,
            true,
            &truncate_chars("Herdr · Pick a Launch Template", content_w)
        )
    ));
    let sub = format!(
        "{} template(s) from `hc templates --json` · Enter launches & attaches via `hc run --bg`",
        templates.len()
    );
    lines.push(format!(
        "{left_pad}{}",
        paint_styled_text(
            color_mode,
            RGB_HYPHAE_SAGE,
            false,
            &truncate_chars(&sub, content_w)
        )
    ));
    lines.push(String::new());

    let total_entries = templates.len() + usize::from(allow_back);
    let footer_lines = 2usize;
    let avail_rows = term_rows.saturating_sub(lines.len() + footer_lines).max(1);
    let win = compute_scroll_window(total_entries, selected, avail_rows);

    if win.above > 0 {
        let hint = format!("   ↑ {} more", win.above);
        lines.push(format!(
            "{left_pad}{}",
            paint_styled_text(
                color_mode,
                RGB_UI_MUTED,
                false,
                &truncate_chars(&hint, content_w)
            )
        ));
    }

    let tmpl_label_w = templates
        .iter()
        .map(|t| t.display_title().chars().count())
        .max()
        .unwrap_or(14)
        .clamp(12, 26);

    for idx in win.start..win.end {
        if let Some(tmpl) = templates.get(idx) {
            lines.push(format_menu_row(
                idx == selected,
                tmpl.display_title(),
                None,
                &tmpl.display_subtitle(),
                tmpl_label_w,
                0,
                content_w,
                &left_pad,
                color_mode,
            ));
        } else {
            lines.push(format_menu_row(
                idx == selected,
                "← Back",
                None,
                "Return to harness list",
                tmpl_label_w,
                0,
                content_w,
                &left_pad,
                color_mode,
            ));
        }
    }

    if win.below > 0 {
        let hint = format!("   ↓ {} more", win.below);
        lines.push(format!(
            "{left_pad}{}",
            paint_styled_text(
                color_mode,
                RGB_UI_MUTED,
                false,
                &truncate_chars(&hint, content_w)
            )
        ));
    }

    lines.push(String::new());
    let hint = if allow_back {
        "↑/↓ move · Enter launch · ←/Esc back · q quit"
    } else {
        "↑/↓ move · Enter launch · q quit"
    };
    lines.push(format!(
        "{left_pad}{}",
        paint_styled_text(
            color_mode,
            RGB_UI_MUTED,
            false,
            &truncate_chars(hint, content_w)
        )
    ));

    if lines.len() > term_rows {
        lines.truncate(term_rows);
    }

    let top_pad = term_rows.saturating_sub(lines.len()) / 3;
    let mut padded = vec![String::new(); top_pad];
    padded.extend(lines);
    padded
}

#[cfg(unix)]
fn render_herdr_screen(
    templates: &[HerdrTemplate],
    selected: usize,
    allow_back: bool,
    term_rows: usize,
    term_cols: usize,
    color_mode: ColorMode,
    anim_tick: usize,
) {
    let lines = render_herdr_templates(
        templates, selected, allow_back, term_rows, term_cols, color_mode, anim_tick,
    );
    flush_screen_lines(&lines, term_rows);
}

#[cfg_attr(not(unix), allow(dead_code))]
fn display_compact_path(path: &Path, home: &Path) -> String {
    if let Ok(rel) = path.strip_prefix(home) {
        return format!("~/{}", rel.display());
    }
    path.display().to_string()
}

const DESKTOP_MCP_CHOICES: [(&str, &str); 2] = [
    ("Apply MCP config & continue", "merge safely"),
    ("Skip config write (I'll edit manually)", "show snippet"),
];

/// Pure, cross-platform Desktop MCP confirmation screen composer (Claude Desktop & Codex Desktop).
#[cfg_attr(not(unix), allow(dead_code))]
#[allow(clippy::too_many_arguments)]
pub fn render_desktop_mcp_confirm(
    harness: ManualGuideHarness,
    home: &Path,
    plan: &DesktopMcpPlan,
    primary_skill: &Path,
    selected_option: usize,
    error_status: Option<&str>,
    allow_back: bool,
    term_rows: usize,
    term_cols: usize,
    color_mode: ColorMode,
) -> Vec<String> {
    if term_rows == 0 {
        return Vec::new();
    }
    let content_w = safe_content_width(term_cols, 78);
    let left_pad = " ".repeat(term_cols.saturating_sub(content_w) / 2);
    let inner_card_w = content_w.saturating_sub(4).max(20);
    let border_fg = fg_color(color_mode, RGB_UI_BORDER);
    let reset = style_reset(color_mode);
    let horiz = "─".repeat(inner_card_w + 2);

    let mut lines = Vec::new();

    let title = format!("{} · Confirm MCP Config Update", harness.display_name());
    lines.push(format!(
        "{left_pad}{}",
        paint_styled_text(
            color_mode,
            RGB_PULSE_IVORY,
            true,
            &truncate_chars(&title, content_w)
        )
    ));
    let skill_ok = format!(
        "✓ Installed hyp-setup skill to {}",
        display_compact_path(primary_skill, home)
    );
    lines.push(format!(
        "{left_pad}{}",
        paint_styled_text(
            color_mode,
            RGB_UI_TAG_LAUNCH,
            false,
            &truncate_chars(&skill_ok, content_w)
        )
    ));
    lines.push(String::new());

    lines.push(format!("{left_pad}{border_fg}╭{horiz}╮{reset}"));

    let card_row = |plain_text: &str, rgb: (u8, u8, u8), bold: bool| -> String {
        let clipped = truncate_chars(plain_text, inner_card_w);
        let pad_r = " ".repeat(inner_card_w.saturating_sub(clipped.chars().count()));
        let styled = paint_styled_text(color_mode, rgb, bold, &clipped);
        format!("{left_pad}{border_fg}│{reset} {styled}{pad_r} {border_fg}│{reset}")
    };

    let target_label = format!("File: {}", display_compact_path(&plan.config_path, home));
    for wrapped in wrap_words(&target_label, inner_card_w) {
        lines.push(card_row(&wrapped, RGB_NODE_AMBER, true));
    }
    lines.push(card_row(
        "Existing servers & settings are preserved.",
        RGB_HYPHAE_SAGE,
        false,
    ));
    lines.push(card_row("", RGB_UI_MUTED, false));

    for (idx, preview) in plan.preview_lines.iter().enumerate() {
        let rgb = if idx == 0 {
            RGB_UI_MUTED
        } else {
            RGB_PULSE_IVORY
        };
        lines.push(card_row(preview, rgb, false));
    }

    lines.push(format!("{left_pad}{border_fg}╰{horiz}╯{reset}"));

    if let Some(err) = error_status {
        lines.push(format!(
            "{left_pad}{}",
            paint_styled_text(
                color_mode,
                RGB_NODE_AMBER,
                true,
                &truncate_chars(&format!("WARN  {err}"), content_w)
            )
        ));
    } else {
        lines.push(String::new());
    }

    let options = DESKTOP_MCP_CHOICES;
    let opt_label_w = options
        .iter()
        .map(|(l, _)| l.chars().count())
        .max()
        .unwrap_or(28);
    for (idx, (label, sub)) in options.iter().enumerate() {
        lines.push(format_menu_row(
            idx == selected_option,
            label,
            None,
            sub,
            opt_label_w,
            0,
            content_w,
            &left_pad,
            color_mode,
        ));
    }

    lines.push(String::new());
    let footer = if allow_back {
        "↑/↓ move · Enter select · ←/Esc back · q quit"
    } else {
        "↑/↓ move · Enter select · q quit"
    };
    lines.push(format!(
        "{left_pad}{}",
        paint_styled_text(
            color_mode,
            RGB_UI_MUTED,
            false,
            &truncate_chars(footer, content_w)
        )
    ));

    if lines.len() > term_rows {
        lines.truncate(term_rows);
    }

    let top_pad = term_rows.saturating_sub(lines.len()) / 3;
    let mut padded = vec![String::new(); top_pad];
    padded.extend(lines);
    padded
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn render_desktop_mcp_confirm_screen(
    harness: ManualGuideHarness,
    home: &Path,
    plan: &DesktopMcpPlan,
    primary_skill: &Path,
    selected_option: usize,
    error_status: Option<&str>,
    allow_back: bool,
    term_rows: usize,
    term_cols: usize,
    color_mode: ColorMode,
) {
    let lines = render_desktop_mcp_confirm(
        harness,
        home,
        plan,
        primary_skill,
        selected_option,
        error_status,
        allow_back,
        term_rows,
        term_cols,
        color_mode,
    );
    flush_screen_lines(&lines, term_rows);
}

#[cfg_attr(not(unix), allow(dead_code))]
#[allow(clippy::too_many_arguments)]
pub fn render_manual_guide(
    harness: ManualGuideHarness,
    home: &Path,
    cli_bin: &str,
    primary_skill: &Path,
    installed: &[InstalledSkillEntry],
    prompt: &str,
    mcp_status: &DesktopMcpStatus,
    deeplink: Option<&str>,
    selected_action: usize,
    copied_status: Option<&str>,
    allow_back: bool,
    term_rows: usize,
    term_cols: usize,
    color_mode: ColorMode,
) -> Vec<String> {
    if term_rows == 0 {
        return Vec::new();
    }
    let content_w = safe_content_width(term_cols, 78);
    let left_pad = " ".repeat(term_cols.saturating_sub(content_w) / 2);
    let inner_card_w = content_w.saturating_sub(4).max(20);
    let border_fg = fg_color(color_mode, RGB_UI_BORDER);
    let reset = style_reset(color_mode);
    let horiz = "─".repeat(inner_card_w + 2);

    let mut lines = Vec::new();

    let title = format!(
        "{} · Skill Installed & Handoff Guide",
        harness.display_name()
    );
    lines.push(format!(
        "{left_pad}{}",
        paint_styled_text(
            color_mode,
            RGB_PULSE_IVORY,
            true,
            &truncate_chars(&title, content_w)
        )
    ));
    lines.push(String::new());

    let confirm = format!(
        "✓ Installed hyp-setup skill to {}",
        display_compact_path(primary_skill, home)
    );
    lines.push(format!(
        "{left_pad}{}",
        paint_styled_text(
            color_mode,
            RGB_UI_TAG_LAUNCH,
            true,
            &truncate_chars(&confirm, content_w)
        )
    ));

    match mcp_status {
        DesktopMcpStatus::Applied(cfg_path) => {
            let msg = format!("✓ Updated {}", display_compact_path(cfg_path, home));
            lines.push(format!(
                "{left_pad}{}",
                paint_styled_text(
                    color_mode,
                    RGB_UI_TAG_LAUNCH,
                    true,
                    &truncate_chars(&msg, content_w)
                )
            ));
        }
        DesktopMcpStatus::AlreadyConfigured(cfg_path) => {
            let msg = format!(
                "✓ MCP config already configured at {}",
                display_compact_path(cfg_path, home)
            );
            lines.push(format!(
                "{left_pad}{}",
                paint_styled_text(
                    color_mode,
                    RGB_UI_TAG_LAUNCH,
                    false,
                    &truncate_chars(&msg, content_w)
                )
            ));
        }
        DesktopMcpStatus::Skipped | DesktopMcpStatus::NotApplicable => {}
    }

    // Show any additional cross-tool paths (e.g. Claude + Codex for T3 Code).
    let mut extras_shown = 0usize;
    for item in installed {
        for extra in &item.extra_paths {
            if extras_shown >= 2 {
                break;
            }
            let extra_line = format!("  + {}", display_compact_path(Path::new(extra), home));
            lines.push(format!(
                "{left_pad}{}",
                paint_styled_text(
                    color_mode,
                    RGB_UI_MUTED,
                    false,
                    &truncate_chars(&extra_line, content_w)
                )
            ));
            extras_shown += 1;
        }
    }
    lines.push(String::new());

    // Clean instruction card.
    lines.push(format!("{left_pad}{border_fg}╭{horiz}╮{reset}"));

    let card_row = |plain_text: &str, rgb: (u8, u8, u8), bold: bool| -> String {
        let clipped = truncate_chars(plain_text, inner_card_w);
        let pad_r = " ".repeat(inner_card_w.saturating_sub(clipped.chars().count()));
        let styled = paint_styled_text(color_mode, rgb, bold, &clipped);
        format!("{left_pad}{border_fg}│{reset} {styled}{pad_r} {border_fg}│{reset}")
    };

    let step1 = match mcp_status {
        DesktopMcpStatus::Applied(_) => format!("1. {}", harness.restart_instruction()),
        _ => format!("1. {}", harness.open_instruction()),
    };
    for wrapped in wrap_words(&step1, inner_card_w) {
        lines.push(card_row(&wrapped, RGB_HYPHAE_SAGE, false));
    }
    let step2 = if matches!(mcp_status, DesktopMcpStatus::Applied(_)) && deeplink.is_some() {
        "2. Then press [o] to open prefilled chat (or [c] to copy):"
    } else if deeplink.is_some() {
        "2. Press [o] to open in app, or paste this prompt:"
    } else {
        "2. Paste this prompt:"
    };
    lines.push(card_row(step2, RGB_HYPHAE_SAGE, false));
    lines.push(card_row("", RGB_UI_MUTED, false));

    for wrapped in wrap_words(prompt, inner_card_w.saturating_sub(2)) {
        let indented = format!("  {wrapped}");
        lines.push(card_row(&indented, RGB_PULSE_IVORY, true));
    }

    if matches!(
        mcp_status,
        DesktopMcpStatus::Skipped | DesktopMcpStatus::NotApplicable
    ) {
        if let Some((cfg_path, snippet)) = harness.mcp_config_note(home, cli_bin) {
            lines.push(card_row("", RGB_UI_MUTED, false));
            let cfg_hdr = format!("MCP config ({}):", display_compact_path(&cfg_path, home));
            for wrapped in wrap_words(&cfg_hdr, inner_card_w) {
                lines.push(card_row(&wrapped, RGB_NODE_AMBER, false));
            }
            for snippet_line in snippet.lines() {
                for wrapped in wrap_words(snippet_line, inner_card_w.saturating_sub(2)) {
                    let indented = format!("  {wrapped}");
                    lines.push(card_row(&indented, RGB_UI_MUTED, false));
                }
            }
        }
    }

    lines.push(format!("{left_pad}{border_fg}╰{horiz}╯{reset}"));

    if let Some(status) = copied_status {
        lines.push(format!(
            "{left_pad}{}",
            paint_styled_text(
                color_mode,
                RGB_NODE_AMBER,
                true,
                &truncate_chars(status, content_w)
            )
        ));
    } else {
        lines.push(String::new());
    }

    let mut actions: Vec<(String, &'static str)> = Vec::new();
    if deeplink.is_some() {
        actions.push((
            format!("[o] Open in {}", harness.display_name()),
            "copy prompt + launch app",
        ));
    }
    actions.push(("[c] Copy prompt to clipboard".to_string(), "copy"));
    if allow_back {
        actions.push(("[←] Back to harness list".to_string(), "return"));
    }
    actions.push(("[Enter / q] Done".to_string(), "exit wizard"));

    let act_label_w = actions
        .iter()
        .map(|(l, _)| l.chars().count())
        .max()
        .unwrap_or(28);
    for (idx, (label, sub)) in actions.iter().enumerate() {
        lines.push(format_menu_row(
            idx == selected_action,
            label,
            None,
            sub,
            act_label_w,
            0,
            content_w,
            &left_pad,
            color_mode,
        ));
    }

    lines.push(String::new());
    let footer = match (deeplink.is_some(), allow_back) {
        (true, true) => "o open · c copy · ↑/↓ move · ←/Esc back · Enter/q done",
        (true, false) => "o open · c copy · ↑/↓ move · Enter/q done",
        (false, true) => "c copy · ↑/↓ move · ←/Esc back · Enter/q done",
        (false, false) => "c copy · ↑/↓ move · Enter/q done",
    };
    lines.push(format!(
        "{left_pad}{}",
        paint_styled_text(
            color_mode,
            RGB_UI_MUTED,
            false,
            &truncate_chars(footer, content_w)
        )
    ));

    if lines.len() > term_rows {
        lines.truncate(term_rows);
    }

    let top_pad = term_rows.saturating_sub(lines.len()) / 3;
    let mut padded = vec![String::new(); top_pad];
    padded.extend(lines);
    padded
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn render_manual_guide_screen(
    harness: ManualGuideHarness,
    home: &Path,
    cli_bin: &str,
    primary_skill: &Path,
    installed: &[InstalledSkillEntry],
    prompt: &str,
    mcp_status: &DesktopMcpStatus,
    deeplink: Option<&str>,
    selected_action: usize,
    copied_status: Option<&str>,
    allow_back: bool,
    term_rows: usize,
    term_cols: usize,
    color_mode: ColorMode,
) {
    let lines = render_manual_guide(
        harness,
        home,
        cli_bin,
        primary_skill,
        installed,
        prompt,
        mcp_status,
        deeplink,
        selected_action,
        copied_status,
        allow_back,
        term_rows,
        term_cols,
        color_mode,
    );
    flush_screen_lines(&lines, term_rows);
}

// ============================================================================
// Pure-Rust Interactive Harness & Component Toggle Screen
// ============================================================================

/// Mutable state for the pure-Rust interactive harness & component toggle checklist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetupToggleState {
    pub detected_harnesses: Vec<HarnessKind>,
    pub selected_harnesses: [bool; 9],
    pub install_skills: bool,
    pub install_statusline: bool,
    pub install_claude_commands: bool,
    pub install_herdr_mod: bool,
    pub herdr_app_detected: bool,
    pub openclaw_delivery: OpenClawDeliveryMode,
    pub openclaw_prompt_injection: bool,
    pub cursor: usize,
    pub show_dry_run_preview: bool,
}

/// Pure result of processing a single keyboard or text command on [`SetupToggleState`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetupToggleAction {
    Continue,
    Apply(SetupSelection),
    Back,
    Cancel,
}

impl SetupToggleState {
    pub const HARNESS_COUNT: usize = 9;
    pub const COMPONENT_COUNT: usize = 4;
    pub const TOTAL_ITEMS: usize = Self::HARNESS_COUNT + Self::COMPONENT_COUNT;

    /// Builds default toggle state from explicit detection results (pure & unit-testable).
    pub fn from_detection(detected: &[HarnessKind], herdr_app_detected: bool) -> Self {
        let mut selected_harnesses = [false; 9];
        let mut normalized_detected = Vec::new();
        for (idx, &kind) in HarnessKind::ALL.iter().enumerate() {
            if detected.contains(&kind) {
                selected_harnesses[idx] = true;
                normalized_detected.push(kind);
            }
        }
        let herdr_checked = normalized_detected.contains(&HarnessKind::Herdr);
        Self {
            detected_harnesses: normalized_detected,
            selected_harnesses,
            install_skills: true,
            install_statusline: true,
            install_claude_commands: true,
            install_herdr_mod: herdr_app_detected && herdr_checked,
            herdr_app_detected,
            openclaw_delivery: OpenClawDeliveryMode::Gateway,
            openclaw_prompt_injection: false,
            cursor: 0,
            show_dry_run_preview: false,
        }
    }

    /// Detects installed harnesses and `~/.config/herdr-app` under `home` to build default state.
    #[allow(dead_code)]
    pub fn from_home(home: &Path, explicit_home: bool) -> Self {
        Self::from_home_with_claude(home, explicit_home, None)
    }

    /// Profile-aware harness & Herdr app detection under `home` (honors `$CLAUDE_CONFIG_DIR` /
    /// `--claude-config-dir`).
    pub fn from_home_with_claude(
        home: &Path,
        explicit_home: bool,
        claude_config_dir: Option<&Path>,
    ) -> Self {
        let diagnostics = detect_harness_statuses(home, explicit_home, claude_config_dir, None);
        let mut detected = Vec::new();
        for kind in HarnessKind::ALL {
            if diagnostics
                .iter()
                .any(|d| d.harness == kind.as_str() && (d.detected || d.configured))
            {
                detected.push(kind);
            }
        }
        let herdr_app_detected = if explicit_home {
            home.join(".config").join("herdr-app").is_dir()
        } else {
            crate::herdr_mod::detect_herdr_app_dir(home).is_some()
        };
        let mut state = Self::from_detection(&detected, herdr_app_detected);
        let (oc_delivery, oc_pi) = read_openclaw_hyphae_preferences(home);
        state.openclaw_delivery = oc_delivery;
        state.openclaw_prompt_injection = oc_pi;
        state
    }

    /// Overrides the checked harness checkboxes (e.g. from `--harness` pre-selection in `hyp setup -i`).
    pub fn set_selected_harnesses(&mut self, harnesses: &[HarnessKind]) {
        for (idx, &kind) in HarnessKind::ALL.iter().enumerate() {
            self.selected_harnesses[idx] = harnesses.contains(&kind);
        }
        let herdr_checked = self.is_harness_selected(HarnessKind::Herdr);
        self.install_herdr_mod = self.herdr_app_detected && herdr_checked;
    }

    pub fn is_harness_detected(&self, kind: HarnessKind) -> bool {
        self.detected_harnesses.contains(&kind)
    }

    pub fn is_harness_selected(&self, kind: HarnessKind) -> bool {
        HarnessKind::ALL
            .iter()
            .position(|&k| k == kind)
            .is_some_and(|idx| self.selected_harnesses[idx])
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    pub fn selected_harness_count(&self) -> usize {
        self.selected_harnesses.iter().filter(|&&b| b).count()
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    pub fn move_up(&mut self) {
        self.cursor = (self.cursor + Self::TOTAL_ITEMS - 1) % Self::TOTAL_ITEMS;
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    pub fn move_down(&mut self) {
        self.cursor = (self.cursor + 1) % Self::TOTAL_ITEMS;
    }

    pub fn toggle_index(&mut self, idx: usize) {
        if idx < Self::HARNESS_COUNT {
            self.selected_harnesses[idx] = !self.selected_harnesses[idx];
        } else {
            match idx {
                9 => self.install_skills = !self.install_skills,
                10 => self.install_statusline = !self.install_statusline,
                11 => self.install_claude_commands = !self.install_claude_commands,
                12 => self.install_herdr_mod = !self.install_herdr_mod,
                _ => {}
            }
        }
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    pub fn toggle_current(&mut self) {
        self.toggle_index(self.cursor);
    }

    /// Cycles harness checkboxes cleanly: all detected -> all 9 -> none -> all detected.
    pub fn cycle_harness_selection(&mut self) {
        let all_selected = self.selected_harnesses.iter().all(|&b| b);
        let has_partial_detected = !self.detected_harnesses.is_empty()
            && self.detected_harnesses.len() < Self::HARNESS_COUNT;
        let matches_detected = HarnessKind::ALL
            .iter()
            .enumerate()
            .all(|(i, &k)| self.selected_harnesses[i] == self.detected_harnesses.contains(&k));

        if has_partial_detected {
            if matches_detected {
                self.selected_harnesses = [true; 9];
            } else if all_selected {
                self.selected_harnesses = [false; 9];
            } else {
                for (i, &k) in HarnessKind::ALL.iter().enumerate() {
                    self.selected_harnesses[i] = self.detected_harnesses.contains(&k);
                }
            }
        } else if all_selected {
            self.selected_harnesses = [false; 9];
        } else {
            self.selected_harnesses = [true; 9];
        }
    }

    pub fn toggle_dry_run_preview(&mut self) {
        self.show_dry_run_preview = !self.show_dry_run_preview;
    }

    pub fn to_selection(&self) -> SetupSelection {
        let harnesses = HarnessKind::ALL
            .iter()
            .enumerate()
            .filter_map(|(idx, &kind)| self.selected_harnesses[idx].then_some(kind))
            .collect();
        SetupSelection {
            harnesses,
            install_skills: self.install_skills,
            install_statusline: self.install_statusline,
            install_claude_commands: self.install_claude_commands,
            install_herdr_mod: self.install_herdr_mod,
            openclaw_delivery: self.openclaw_delivery,
            openclaw_prompt_injection: self.openclaw_prompt_injection,
        }
    }

    /// Generates an exact dry-run preview of files & actions for the current selection.
    pub fn build_dry_run_preview(&self, home: &Path, include_node_bootstrap: bool) -> Vec<String> {
        let mut preview = Vec::new();
        if include_node_bootstrap {
            let cfg_dir = display_compact_path(&home.join(".config").join("hyphae"), home);
            preview.push(format!(
                "Node: {cfg_dir}/{{node.json, state/node.sqlite}} + Ed25519/X25519 keys"
            ));
        }

        let sel = self.to_selection();
        if sel.harnesses.is_empty() {
            if include_node_bootstrap {
                preview.push("Harnesses: none selected (only node bootstrap will run)".to_string());
            } else {
                preview.push("Harnesses: none selected (no files will be written)".to_string());
            }
            return preview;
        }

        for &kind in &sel.harnesses {
            let skill = || {
                format!(
                    "  + skill: {}",
                    display_compact_path(
                        &crate::harness_spec::spec(kind).runtime_skill(home),
                        home,
                    )
                )
            };
            match kind {
                HarnessKind::Antigravity => {
                    preview.push(
                        "antigravity: ~/.gemini/config/plugins/hyphae/{plugin,mcp_config,hooks}.json + sidecar + rules"
                            .to_string(),
                    );
                    if sel.install_skills {
                        preview.push(skill());
                    }
                    if sel.install_statusline {
                        preview.push(
                            "  + statusLine: ~/.gemini/antigravity-cli/settings.json (chains existing)"
                                .to_string(),
                        );
                    }
                }
                HarnessKind::Claude => {
                    let sl = if sel.install_statusline {
                        " + statusLine (chains existing)"
                    } else {
                        ""
                    };
                    preview.push(format!(
                        "claude: ~/.claude.json, ~/.claude/settings.json (hooks{sl})"
                    ));
                    if sel.install_claude_commands {
                        preview.push(
                            "  + commands: ~/.claude/commands/hyp{,-subs,-focus,-mute}.md"
                                .to_string(),
                        );
                    }
                    if sel.install_skills {
                        preview.push(skill());
                    }
                }
                HarnessKind::Codex => {
                    preview.push("codex: ~/.codex/{config.toml,hooks.json}".to_string());
                    if sel.install_skills {
                        preview.push(skill());
                    }
                }
                HarnessKind::Cursor => {
                    preview.push("cursor: ~/.cursor/{mcp.json,hooks.json}".to_string());
                    if sel.install_skills {
                        preview.push(skill());
                    }
                }
                HarnessKind::Opencode => {
                    preview.push(
                        "opencode: ~/.config/opencode/{opencode.json,plugins/hyphae.ts}"
                            .to_string(),
                    );
                    if sel.install_skills {
                        preview.push(skill());
                    }
                }
                HarnessKind::Gemini => {
                    preview.push("gemini: ~/.gemini/settings.json (MCP + hooks)".to_string());
                    if sel.install_skills {
                        preview.push(skill());
                    }
                }
                HarnessKind::Openclaw => {
                    preview.push(
                        "openclaw: ~/.openclaw/{openclaw.json, extensions/hyphae/{openclaw.plugin.json, index.js}}"
                            .to_string(),
                    );
                    preview.push(format!(
                        "  + mode: delivery={}, prompt-injection={} (messages still received via nudges/hyp_inbox when off)",
                        sel.openclaw_delivery.as_str(),
                        if sel.openclaw_prompt_injection { "on" } else { "off" }
                    ));
                    if sel.install_skills {
                        preview.push(skill());
                    }
                }
                HarnessKind::Herdr => {
                    preview.push(
                        "herdr: auto-detected via HC_TERMINAL_ID (no config file needed)"
                            .to_string(),
                    );
                    if sel.install_skills {
                        preview.push(skill());
                    }
                    if sel.install_herdr_mod {
                        preview.push(
                            "  + herdr-mod: ~/.config/herdr-app/{mods/hyphae-pane,mods/hyphae-panel,keys.json} (symlink-safe)"
                                .to_string(),
                        );
                    }
                }
                HarnessKind::T3 => {
                    preview.push("t3: ~/.config/hyphae/node.json (\"t3\" block)".to_string());
                    if sel.install_skills {
                        preview.push(skill());
                    }
                }
            }
        }
        preview
    }
}

/// Pure key event dispatcher for the interactive harness & component toggle screen.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn handle_setup_toggle_key(
    state: &mut SetupToggleState,
    key: KeyEvent,
    allow_back: bool,
) -> SetupToggleAction {
    match key {
        KeyEvent::Up => {
            state.move_up();
            SetupToggleAction::Continue
        }
        KeyEvent::Down => {
            state.move_down();
            SetupToggleAction::Continue
        }
        KeyEvent::Char(' ') => {
            state.toggle_current();
            SetupToggleAction::Continue
        }
        KeyEvent::Char('a') | KeyEvent::Char('A') => {
            state.cycle_harness_selection();
            SetupToggleAction::Continue
        }
        KeyEvent::Char('d') | KeyEvent::Char('D') => {
            state.toggle_dry_run_preview();
            SetupToggleAction::Continue
        }
        KeyEvent::Enter => SetupToggleAction::Apply(state.to_selection()),
        KeyEvent::Back | KeyEvent::Left | KeyEvent::Char('b') | KeyEvent::Char('B') => {
            if allow_back {
                SetupToggleAction::Back
            } else {
                SetupToggleAction::Cancel
            }
        }
        KeyEvent::Cancel => SetupToggleAction::Cancel,
        _ => SetupToggleAction::Continue,
    }
}

/// Pure parser for the numbered/text fallback prompt (non-Unix and non-raw terminals).
pub fn apply_setup_toggle_text_input(
    state: &mut SetupToggleState,
    raw_input: &str,
    allow_back: bool,
) -> Result<SetupToggleAction, String> {
    let trimmed = raw_input.trim();
    if trimmed.is_empty() {
        return Ok(SetupToggleAction::Apply(state.to_selection()));
    }
    let low = trimmed.to_ascii_lowercase();
    if matches!(low.as_str(), "q" | "quit" | "cancel") {
        return Ok(SetupToggleAction::Cancel);
    }
    if matches!(low.as_str(), "b" | "back") {
        return Ok(if allow_back {
            SetupToggleAction::Back
        } else {
            SetupToggleAction::Cancel
        });
    }
    if matches!(low.as_str(), "a" | "all") {
        state.cycle_harness_selection();
        return Ok(SetupToggleAction::Continue);
    }
    if matches!(low.as_str(), "d" | "dry-run" | "preview") {
        state.toggle_dry_run_preview();
        return Ok(SetupToggleAction::Continue);
    }

    let mut toggled = Vec::new();
    for token in trimmed.split(|c: char| c == ',' || c.is_whitespace()) {
        if token.is_empty() {
            continue;
        }
        let Ok(num) = token.parse::<usize>() else {
            return Err(format!(
                "Invalid input '{token}'. Enter 1-{}, 'a', 'd', 'b', 'q', or Enter to apply.",
                SetupToggleState::TOTAL_ITEMS
            ));
        };
        if !(1..=SetupToggleState::TOTAL_ITEMS).contains(&num) {
            return Err(format!(
                "Choice '{num}' out of range (1-{}).",
                SetupToggleState::TOTAL_ITEMS
            ));
        }
        toggled.push(num - 1);
    }
    if toggled.is_empty() {
        return Ok(SetupToggleAction::Apply(state.to_selection()));
    }
    for idx in toggled {
        state.toggle_index(idx);
    }
    Ok(SetupToggleAction::Continue)
}

// ============================================================================
// OpenClaw Delivery Mode & Prompt Injection Onboarding Step
// ============================================================================

/// Explicit reassurance shown in all OpenClaw onboarding screens & prompts.
pub const OPENCLAW_PROMPT_INJECTION_REASSURANCE: &str = "Even with prompt injection OFF, you will still receive all Hyphae messages (via Gateway wake nudges and hyp_inbox).";

/// Mutable state for the dedicated OpenClaw delivery mode & prompt-injection step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenClawConfigState {
    pub delivery: OpenClawDeliveryMode,
    pub prompt_injection: bool,
    pub cursor: usize,
}

/// Pure result of processing a keyboard or text input on [`OpenClawConfigState`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenClawConfigAction {
    Continue,
    Apply {
        delivery: OpenClawDeliveryMode,
        prompt_injection: bool,
    },
    Back,
    Cancel,
}

impl OpenClawConfigState {
    pub const OPTION_COUNT: usize = 2;

    pub fn new(delivery: OpenClawDeliveryMode, prompt_injection: bool) -> Self {
        Self {
            delivery,
            prompt_injection,
            cursor: 0,
        }
    }

    pub fn from_home(home: &Path) -> Self {
        let (delivery, prompt_injection) = read_openclaw_hyphae_preferences(home);
        Self::new(delivery, prompt_injection)
    }

    pub fn move_up(&mut self) {
        self.cursor = (self.cursor + Self::OPTION_COUNT - 1) % Self::OPTION_COUNT;
    }

    pub fn move_down(&mut self) {
        self.cursor = (self.cursor + 1) % Self::OPTION_COUNT;
    }

    pub fn toggle_delivery(&mut self) {
        self.delivery = match self.delivery {
            OpenClawDeliveryMode::Gateway => OpenClawDeliveryMode::Inbox,
            OpenClawDeliveryMode::Inbox => OpenClawDeliveryMode::Gateway,
        };
    }

    pub fn toggle_prompt_injection(&mut self) {
        self.prompt_injection = !self.prompt_injection;
    }

    pub fn toggle_current(&mut self) {
        match self.cursor {
            0 => self.toggle_delivery(),
            _ => self.toggle_prompt_injection(),
        }
    }
}

/// Pure keyboard dispatcher for the OpenClaw Delivery & Prompt Injection onboarding screen.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn handle_openclaw_config_key(
    state: &mut OpenClawConfigState,
    key: KeyEvent,
    allow_back: bool,
) -> OpenClawConfigAction {
    match key {
        KeyEvent::Up => {
            state.move_up();
            OpenClawConfigAction::Continue
        }
        KeyEvent::Down => {
            state.move_down();
            OpenClawConfigAction::Continue
        }
        KeyEvent::Char(' ') | KeyEvent::Right => {
            state.toggle_current();
            OpenClawConfigAction::Continue
        }
        KeyEvent::Char('1') => {
            state.cursor = 0;
            state.toggle_delivery();
            OpenClawConfigAction::Continue
        }
        KeyEvent::Char('2') => {
            state.cursor = 1;
            state.toggle_prompt_injection();
            OpenClawConfigAction::Continue
        }
        KeyEvent::Enter => OpenClawConfigAction::Apply {
            delivery: state.delivery,
            prompt_injection: state.prompt_injection,
        },
        KeyEvent::Back | KeyEvent::Left | KeyEvent::Char('b') | KeyEvent::Char('B') => {
            if allow_back {
                OpenClawConfigAction::Back
            } else {
                OpenClawConfigAction::Cancel
            }
        }
        KeyEvent::Cancel | KeyEvent::Char('q') | KeyEvent::Char('Q') => {
            OpenClawConfigAction::Cancel
        }
        _ => OpenClawConfigAction::Continue,
    }
}

/// Pure parser for the numbered/text OpenClaw configuration fallback prompt.
pub fn apply_openclaw_config_text_input(
    state: &mut OpenClawConfigState,
    raw_input: &str,
    allow_back: bool,
) -> Result<OpenClawConfigAction, String> {
    let trimmed = raw_input.trim();
    if trimmed.is_empty() {
        return Ok(OpenClawConfigAction::Apply {
            delivery: state.delivery,
            prompt_injection: state.prompt_injection,
        });
    }
    let low = trimmed.to_ascii_lowercase();
    match low.as_str() {
        "q" | "quit" | "cancel" => Ok(OpenClawConfigAction::Cancel),
        "b" | "back" => Ok(if allow_back {
            OpenClawConfigAction::Back
        } else {
            OpenClawConfigAction::Cancel
        }),
        "1" => {
            state.toggle_delivery();
            Ok(OpenClawConfigAction::Continue)
        }
        "gateway" => {
            state.delivery = OpenClawDeliveryMode::Gateway;
            Ok(OpenClawConfigAction::Continue)
        }
        "inbox" => {
            state.delivery = OpenClawDeliveryMode::Inbox;
            Ok(OpenClawConfigAction::Continue)
        }
        "2" => {
            state.toggle_prompt_injection();
            Ok(OpenClawConfigAction::Continue)
        }
        "on" | "yes" | "true" => {
            state.prompt_injection = true;
            Ok(OpenClawConfigAction::Continue)
        }
        "off" | "no" | "false" => {
            state.prompt_injection = false;
            Ok(OpenClawConfigAction::Continue)
        }
        _ => Err(format!(
            "Invalid choice '{trimmed}'. Enter 1 (toggle delivery), 2 (toggle prompt injection), 'gateway', 'inbox', 'on', 'off', 'b', 'q', or Enter to apply."
        )),
    }
}

const OPENCLAW_CONFIG_TITLE: &str = "OpenClaw · Delivery Mode & Prompt Injection";

#[cfg_attr(not(unix), allow(dead_code))]
#[allow(clippy::too_many_arguments)]
pub fn render_openclaw_config_screen(
    state: &OpenClawConfigState,
    home: &Path,
    error_status: Option<&str>,
    allow_back: bool,
    term_rows: usize,
    term_cols: usize,
    color_mode: ColorMode,
) -> Vec<String> {
    if term_rows == 0 {
        return Vec::new();
    }
    let content_w = safe_content_width(term_cols, 78);
    let left_pad = " ".repeat(term_cols.saturating_sub(content_w) / 2);
    let inner_card_w = content_w.saturating_sub(4).max(16);
    let border_fg = fg_color(color_mode, RGB_UI_BORDER);
    let reset = style_reset(color_mode);
    let horiz = "─".repeat(inner_card_w + 2);

    let mut lines = Vec::new();
    lines.push(format!(
        "{left_pad}{}",
        paint_styled_text(
            color_mode,
            RGB_PULSE_IVORY,
            true,
            &truncate_chars(OPENCLAW_CONFIG_TITLE, content_w)
        )
    ));
    let sub = format!(
        "Plugin: {}",
        display_compact_path(
            &home.join(".openclaw").join("extensions").join("hyphae"),
            home
        )
    );
    lines.push(format!(
        "{left_pad}{}",
        paint_styled_text(
            color_mode,
            RGB_UI_MUTED,
            false,
            &truncate_chars(&sub, content_w)
        )
    ));
    lines.push(String::new());

    let card_row = |plain_text: &str, rgb: (u8, u8, u8), bold: bool| -> String {
        let clipped = truncate_chars(plain_text, inner_card_w);
        let pad_r = " ".repeat(inner_card_w.saturating_sub(clipped.chars().count()));
        let styled = paint_styled_text(color_mode, rgb, bold, &clipped);
        format!("{left_pad}{border_fg}│{reset} {styled}{pad_r} {border_fg}│{reset}")
    };

    lines.push(format!("{left_pad}{border_fg}╭{horiz}╮{reset}"));
    let delivery_summary = format!("Delivery: {}", state.delivery.display_label());
    for wrapped in wrap_words(&delivery_summary, inner_card_w) {
        lines.push(card_row(&wrapped, RGB_PULSE_IVORY, true));
    }
    let pi_summary = if state.prompt_injection {
        "Prompt injection: ON (allowPromptModification + allowConversationAccess)"
    } else {
        "Prompt injection: OFF (zero prompt mutation)"
    };
    for wrapped in wrap_words(pi_summary, inner_card_w) {
        lines.push(card_row(&wrapped, RGB_HYPHAE_SAGE, false));
    }
    lines.push(card_row("", RGB_UI_MUTED, false));
    for wrapped in wrap_words(OPENCLAW_PROMPT_INJECTION_REASSURANCE, inner_card_w) {
        lines.push(card_row(&wrapped, RGB_NODE_AMBER, true));
    }
    lines.push(format!("{left_pad}{border_fg}╰{horiz}╯{reset}"));

    if let Some(err) = error_status {
        lines.push(format!(
            "{left_pad}{}",
            paint_styled_text(
                color_mode,
                RGB_NODE_AMBER,
                true,
                &truncate_chars(&format!("WARN  {err}"), content_w)
            )
        ));
    } else {
        lines.push(String::new());
    }

    let delivery_tag = state.delivery.as_str();
    let delivery_desc = match state.delivery {
        OpenClawDeliveryMode::Gateway => "wakes exact OpenClaw session (plugin / /hooks/wake)",
        OpenClawDeliveryMode::Inbox => "turn-start / hyp_inbox only",
    };
    let pi_desc = if state.prompt_injection {
        "ON — injects unread Hyphae messages via before_prompt_build"
    } else {
        "OFF — zero prompt mutation (nudges + hyp_inbox active)"
    };

    lines.push(format_toggle_row(
        state.cursor == 0,
        state.delivery == OpenClawDeliveryMode::Gateway,
        "Delivery mode",
        Some(delivery_tag),
        delivery_desc,
        16,
        8,
        content_w,
        &left_pad,
        color_mode,
    ));
    lines.push(format_toggle_row(
        state.cursor == 1,
        state.prompt_injection,
        "Prompt injection",
        Some(if state.prompt_injection { "ON" } else { "OFF" }),
        pi_desc,
        16,
        8,
        content_w,
        &left_pad,
        color_mode,
    ));

    lines.push(String::new());
    let back_hint = if allow_back {
        "Esc/b back · q quit"
    } else {
        "Esc/q cancel"
    };
    let footer = format!("↑/↓ move · Space toggle · Enter apply · {back_hint}");
    lines.push(format!(
        "{left_pad}{}",
        paint_styled_text(
            color_mode,
            RGB_UI_MUTED,
            false,
            &truncate_chars(&footer, content_w)
        )
    ));

    if lines.len() > term_rows {
        lines.truncate(term_rows);
    }
    let top_pad = term_rows.saturating_sub(lines.len()) / 3;
    let mut padded = vec![String::new(); top_pad];
    padded.extend(lines);
    padded
}

#[cfg(unix)]
fn render_openclaw_config_fullscreen(
    state: &OpenClawConfigState,
    home: &Path,
    error_status: Option<&str>,
    allow_back: bool,
    term_rows: usize,
    term_cols: usize,
    color_mode: ColorMode,
) {
    let lines = render_openclaw_config_screen(
        state,
        home,
        error_status,
        allow_back,
        term_rows,
        term_cols,
        color_mode,
    );
    flush_screen_lines(&lines, term_rows);
}

fn run_plain_tty_openclaw_config(
    state: &mut OpenClawConfigState,
    allow_back: bool,
) -> Result<OpenClawConfigAction, String> {
    loop {
        println!();
        println!("{OPENCLAW_CONFIG_TITLE}");
        println!("  [1] Delivery mode: {}", state.delivery.display_label());
        println!(
            "  [2] Prompt injection (before_prompt_build): [{}] {}",
            if state.prompt_injection { "x" } else { " " },
            if state.prompt_injection {
                "ON (automatically injects unread Hyphae messages at turn start)"
            } else {
                "OFF (zero prompt mutation)"
            }
        );
        println!();
        println!("  Note: {OPENCLAW_PROMPT_INJECTION_REASSURANCE}");
        println!();
        let back_str = if allow_back {
            "[b] back, [q] quit"
        } else {
            "[q] cancel"
        };
        println!(
            "Commands: [1] toggle delivery, [2] toggle prompt injection, [Enter] apply, {back_str}"
        );
        let reply = match read_tty_line("Choice or Enter to apply: ") {
            Ok(Some(line)) => line,
            Ok(None) => return Ok(OpenClawConfigAction::Cancel),
            Err(e) => return Err(format!("Failed reading interactive selection: {e}")),
        };
        match apply_openclaw_config_text_input(state, &reply, allow_back) {
            Ok(OpenClawConfigAction::Continue) => {}
            Ok(action) => return Ok(action),
            Err(msg) => println!("{msg}"),
        }
    }
}

fn component_toggle_display(idx: usize) -> (&'static str, &'static str) {
    match idx {
        9 => ("Runtime skills", "(hyp-mesh/SKILL.md)"),
        10 => (
            "Live statusLine",
            "(Claude Code / Antigravity — chains existing)",
        ),
        11 => (
            "Claude slash commands",
            "(/hyphae, /hyp-subs, /hyp-focus, /hyp-mute)",
        ),
        _ => (
            "Native Herdr mod",
            "(hyphae-pane + hyphae-panel, symlink-safe)",
        ),
    }
}

#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(unix), allow(dead_code))]
fn format_toggle_row(
    selected: bool,
    checked: bool,
    label: &str,
    badge: Option<&str>,
    detail: &str,
    label_col_w: usize,
    badge_col_w: usize,
    content_w: usize,
    left_pad: &str,
    color_mode: ColorMode,
) -> String {
    let inner_w = content_w.max(1);
    let prefix = if selected { " ❯ " } else { "   " };
    let check_str = if checked { "[x] " } else { "[ ] " };
    let lead_w = 7usize; // " ❯ " (3) + "[x] " (4)

    if inner_w <= lead_w {
        let clipped = truncate_chars(&format!("{prefix}{check_str}{label}"), inner_w);
        return if selected {
            match color_mode {
                ColorMode::Plain => format!("{left_pad}\x1b[7m{clipped}\x1b[0m"),
                ColorMode::Ansi256 => format!("{left_pad}\x1b[7m\x1b[1m{clipped}\x1b[0m"),
                ColorMode::TrueColor => {
                    let bg = format!(
                        "\x1b[48;2;{};{};{}m",
                        RGB_UI_HIGHLIGHT_BG.0, RGB_UI_HIGHLIGHT_BG.1, RGB_UI_HIGHLIGHT_BG.2
                    );
                    let ivory = fg_color(color_mode, RGB_PULSE_IVORY);
                    format!("{left_pad}{bg}{ivory}{clipped}\x1b[0m")
                }
            }
        } else {
            format!("{left_pad}{clipped}")
        };
    }

    let show_badge = badge_col_w > 0 && inner_w >= lead_w + 10 + 1 + badge_col_w;
    let effective_badge_w = if show_badge { badge_col_w } else { 0 };
    let label_budget = if show_badge {
        label_col_w
            .min(
                inner_w
                    .saturating_sub(lead_w + effective_badge_w + 1)
                    .max(1),
            )
            .max(1)
    } else {
        inner_w.saturating_sub(lead_w).max(1)
    };

    let label_clip = truncate_chars(label, label_budget);
    let label_len = label_clip.chars().count();
    let label_pad_len = if show_badge {
        label_budget.saturating_sub(label_len)
    } else {
        0
    };
    let label_pad = " ".repeat(label_pad_len);

    let badge_raw = badge.unwrap_or("");
    let badge_clip = if show_badge {
        truncate_chars(badge_raw, effective_badge_w)
    } else {
        String::new()
    };
    let badge_len = badge_clip.chars().count();
    let badge_pad_len = if show_badge {
        effective_badge_w.saturating_sub(badge_len)
    } else {
        0
    };
    let badge_pad = " ".repeat(badge_pad_len);

    let used =
        lead_w + label_len + label_pad_len + if show_badge { 1 + effective_badge_w } else { 0 };
    let rem_for_detail = inner_w.saturating_sub(used + 1);
    let detail_clip = if rem_for_detail >= 4 && !detail.is_empty() {
        truncate_chars(detail, rem_for_detail)
    } else {
        String::new()
    };
    let detail_len = detail_clip.chars().count();
    let total_visible = used + if detail_len > 0 { 1 + detail_len } else { 0 };
    let trailing = " ".repeat(inner_w.saturating_sub(total_visible));

    if selected {
        match color_mode {
            ColorMode::Plain => {
                let mut line = format!("{prefix}{check_str}{label_clip}{label_pad}");
                if show_badge {
                    line.push(' ');
                    line.push_str(&badge_clip);
                    line.push_str(&badge_pad);
                }
                if !detail_clip.is_empty() {
                    line.push(' ');
                    line.push_str(&detail_clip);
                }
                format!("{left_pad}\x1b[7m{line}{trailing}\x1b[0m")
            }
            ColorMode::Ansi256 => {
                let mut line = format!("{prefix}{check_str}{label_clip}{label_pad}");
                if show_badge {
                    line.push(' ');
                    line.push_str(&badge_clip);
                    line.push_str(&badge_pad);
                }
                if !detail_clip.is_empty() {
                    line.push(' ');
                    line.push_str(&detail_clip);
                }
                format!("{left_pad}\x1b[7m\x1b[1m{line}{trailing}\x1b[0m")
            }
            ColorMode::TrueColor => {
                let bg = format!(
                    "\x1b[48;2;{};{};{}m",
                    RGB_UI_HIGHLIGHT_BG.0, RGB_UI_HIGHLIGHT_BG.1, RGB_UI_HIGHLIGHT_BG.2
                );
                let amber = fg_color(color_mode, RGB_NODE_AMBER);
                let ivory = fg_color(color_mode, RGB_PULSE_IVORY);
                let check_fg = fg_color(
                    color_mode,
                    if checked {
                        RGB_UI_TAG_LAUNCH
                    } else {
                        RGB_UI_MUTED
                    },
                );
                let badge_fg = fg_color(color_mode, RGB_UI_TAG_LAUNCH);
                let detail_fg = fg_color(color_mode, RGB_HYPHAE_SAGE);
                let mut row = format!(
                    "{left_pad}{bg}{amber}\x1b[1m{prefix}{check_fg}{check_str}{ivory}{label_clip}{label_pad}\x1b[22m"
                );
                if show_badge {
                    row.push_str(&format!(" {badge_fg}{badge_clip}{badge_pad}"));
                }
                if !detail_clip.is_empty() {
                    row.push_str(&format!(" {detail_fg}{detail_clip}"));
                }
                row.push_str(&format!("{trailing}\x1b[0m"));
                row
            }
        }
    } else {
        let check_styled = paint_styled_text(
            color_mode,
            if checked {
                RGB_UI_TAG_LAUNCH
            } else {
                RGB_UI_MUTED
            },
            checked,
            check_str,
        );
        let label_styled = paint_styled_text(
            color_mode,
            if checked {
                RGB_PULSE_IVORY
            } else {
                RGB_UI_MUTED
            },
            false,
            &label_clip,
        );
        let badge_styled = if show_badge && !badge_clip.is_empty() {
            paint_styled_text(color_mode, RGB_UI_TAG_LAUNCH, false, &badge_clip)
        } else {
            String::new()
        };
        let detail_styled = if !detail_clip.is_empty() {
            paint_styled_text(color_mode, RGB_UI_MUTED, false, &detail_clip)
        } else {
            String::new()
        };
        let mut row = format!("{left_pad}{prefix}{check_styled}{label_styled}{label_pad}");
        if show_badge {
            row.push(' ');
            row.push_str(&badge_styled);
            row.push_str(&badge_pad);
        }
        if !detail_clip.is_empty() {
            row.push(' ');
            row.push_str(&detail_styled);
        }
        row
    }
}

struct ChecklistItem {
    index: usize,
    label: &'static str,
    checked: bool,
    badge: Option<&'static str>,
    detail: &'static str,
    component: bool,
}

enum ChecklistRow {
    Section(&'static str),
    Spacer,
    Item(ChecklistItem),
}

fn setup_checklist(state: &SetupToggleState) -> Vec<ChecklistRow> {
    let mut rows = vec![ChecklistRow::Section("Harnesses")];
    for (index, kind) in HarnessKind::ALL.into_iter().enumerate() {
        let spec = crate::harness_spec::spec(kind);
        rows.push(ChecklistRow::Item(ChecklistItem {
            index,
            label: spec.setup_label(),
            checked: state.selected_harnesses[index],
            badge: state.is_harness_detected(kind).then_some("(detected)"),
            detail: &spec.setup_location,
            component: false,
        }));
    }
    rows.push(ChecklistRow::Spacer);
    rows.push(ChecklistRow::Section("Components & UI Plugins"));
    let checked = [
        state.install_skills,
        state.install_statusline,
        state.install_claude_commands,
        state.install_herdr_mod,
    ];
    for (component_index, checked) in checked.into_iter().enumerate() {
        let index = SetupToggleState::HARNESS_COUNT + component_index;
        let (label, detail) = component_toggle_display(index);
        rows.push(ChecklistRow::Item(ChecklistItem {
            index,
            label,
            checked,
            badge: None,
            detail,
            component: true,
        }));
    }
    rows
}

/// Pure, cross-platform renderer for the interactive harness & component toggle checklist.
///
/// Guarantees `lines.len() <= term_rows` and every visible line fits cleanly within `term_cols`,
/// with optional inline dry-run preview (`d`) and bounded viewport scrolling on narrow terminals.
#[allow(clippy::too_many_arguments)]
#[cfg_attr(not(unix), allow(dead_code))]
pub fn render_setup_toggle_screen(
    state: &SetupToggleState,
    home: &Path,
    include_node_bootstrap: bool,
    allow_back: bool,
    term_rows: usize,
    term_cols: usize,
    color_mode: ColorMode,
    anim_tick: usize,
) -> Vec<String> {
    if term_rows == 0 {
        return Vec::new();
    }
    let content_w = safe_content_width(term_cols, 84);
    let left_pad = " ".repeat(term_cols.saturating_sub(content_w) / 2);
    let mut lines = Vec::new();

    if term_rows >= 33 && !state.show_dry_run_preview {
        lines.extend(build_banner_lines_at_tick(
            term_rows.min(27),
            term_cols,
            content_w,
            color_mode,
            anim_tick,
        ));
        if !lines.is_empty() {
            lines.push(String::new());
        }
    }

    let version = env!("CARGO_PKG_VERSION");
    let title = if include_node_bootstrap {
        format!("hyphae v{version} · local CLI setup — choose harnesses & components")
    } else {
        format!("hyphae v{version} · interactive setup — choose harnesses & components")
    };
    lines.push(format!(
        "{left_pad}{}",
        paint_styled_text(
            color_mode,
            RGB_PULSE_IVORY,
            true,
            &truncate_chars(&title, content_w)
        )
    ));

    let yn = |b: bool| if b { "on" } else { "off" };
    let summary = format!(
        "{}/9 harnesses · skills {} · statusLine {} · commands {} · herdr-mod {}",
        state.selected_harness_count(),
        yn(state.install_skills),
        yn(state.install_statusline),
        yn(state.install_claude_commands),
        yn(state.install_herdr_mod),
    );
    lines.push(format!(
        "{left_pad}{}",
        paint_styled_text(
            color_mode,
            RGB_HYPHAE_SAGE,
            false,
            &truncate_chars(&summary, content_w)
        )
    ));
    if term_rows >= 14 {
        lines.push(String::new());
    }

    let display_rows = setup_checklist(state);
    let selected_display_row = display_rows
        .iter()
        .position(|row| matches!(row, ChecklistRow::Item(item) if item.index == state.cursor))
        .unwrap_or(0);

    let footer_rows = if term_rows >= 10 { 2usize } else { 1usize };
    let body_budget = term_rows.saturating_sub(lines.len() + footer_rows).max(1);

    let (toggle_budget, preview_budget) = if state.show_dry_run_preview {
        if body_budget >= 22 {
            let t_rows = display_rows.len();
            let p_rows = body_budget.saturating_sub(t_rows + 1);
            (t_rows, p_rows)
        } else if body_budget >= 10 {
            let t_rows = (body_budget / 2).max(4);
            let p_rows = body_budget.saturating_sub(t_rows + 1);
            (t_rows, p_rows)
        } else {
            (body_budget.saturating_sub(4).max(1), body_budget.min(4))
        }
    } else {
        (body_budget, 0)
    };

    let win = compute_scroll_window(display_rows.len(), selected_display_row, toggle_budget);
    if win.above > 0 {
        let hint = format!("   ↑ {} more", win.above);
        lines.push(format!(
            "{left_pad}{}",
            paint_styled_text(
                color_mode,
                RGB_UI_MUTED,
                false,
                &truncate_chars(&hint, content_w)
            )
        ));
    }

    let harness_label_w = 12usize;
    let badge_w = 10usize; // "(detected)"
    for row in display_rows.iter().take(win.end).skip(win.start) {
        match row {
            ChecklistRow::Section(hdr) => {
                lines.push(format!(
                    "{left_pad}{}",
                    paint_styled_text(
                        color_mode,
                        RGB_NODE_AMBER,
                        true,
                        &truncate_chars(hdr, content_w)
                    )
                ));
            }
            ChecklistRow::Spacer => {
                lines.push(String::new());
            }
            ChecklistRow::Item(item) => {
                let (label_width, badge_width) = if item.component {
                    (item.label.chars().count(), 0)
                } else {
                    (harness_label_w, badge_w)
                };
                lines.push(format_toggle_row(
                    state.cursor == item.index,
                    item.checked,
                    item.label,
                    item.badge,
                    item.detail,
                    label_width,
                    badge_width,
                    content_w,
                    &left_pad,
                    color_mode,
                ));
            }
        }
    }

    if win.below > 0 {
        let hint = format!("   ↓ {} more", win.below);
        lines.push(format!(
            "{left_pad}{}",
            paint_styled_text(
                color_mode,
                RGB_UI_MUTED,
                false,
                &truncate_chars(&hint, content_w)
            )
        ));
    }

    if state.show_dry_run_preview && preview_budget >= 3 && content_w >= 8 {
        if lines.len() + preview_budget + footer_rows < term_rows {
            lines.push(String::new());
        }
        let inner_card_w = content_w.saturating_sub(4).max(4);
        let border_fg = fg_color(color_mode, RGB_UI_BORDER);
        let reset = style_reset(color_mode);
        let hdr_text = " Dry-Run Preview (zero files written) ";
        let hdr_clipped = truncate_chars(hdr_text, inner_card_w);
        let dash_fill = (inner_card_w + 2).saturating_sub(hdr_clipped.chars().count() + 1);
        let top_border = format!(
            "{left_pad}{border_fg}╭─{}{reset}{border_fg}{}╮{reset}",
            paint_styled_text(color_mode, RGB_NODE_AMBER, true, &hdr_clipped),
            "─".repeat(dash_fill)
        );
        lines.push(top_border);

        let preview_items = state.build_dry_run_preview(home, include_node_bootstrap);
        let max_preview_rows = preview_budget.saturating_sub(2).max(1);
        let card_row = |plain_text: &str, rgb: (u8, u8, u8)| -> String {
            let clipped = truncate_chars(plain_text, inner_card_w);
            let pad_r = " ".repeat(inner_card_w.saturating_sub(clipped.chars().count()));
            let styled = paint_styled_text(color_mode, rgb, false, &clipped);
            format!("{left_pad}{border_fg}│{reset} {styled}{pad_r} {border_fg}│{reset}")
        };

        if preview_items.len() <= max_preview_rows {
            for item in &preview_items {
                lines.push(card_row(item, RGB_PULSE_IVORY));
            }
        } else {
            let visible = max_preview_rows.saturating_sub(1);
            for item in preview_items.iter().take(visible) {
                lines.push(card_row(item, RGB_PULSE_IVORY));
            }
            let remaining = preview_items.len().saturating_sub(visible);
            lines.push(card_row(
                &format!("… +{remaining} more action(s)"),
                RGB_UI_MUTED,
            ));
        }
        let horiz = "─".repeat(inner_card_w + 2);
        lines.push(format!("{left_pad}{border_fg}╰{horiz}╯{reset}"));
    }

    if footer_rows >= 2 {
        lines.push(String::new());
    }
    let preview_hint = if state.show_dry_run_preview {
        "d hide preview"
    } else {
        "d preview"
    };
    let back_hint = if allow_back {
        "Esc/b back · q quit"
    } else {
        "Esc/b/q cancel"
    };
    let footer = format!(
        "↑/↓ move · Space toggle · a all/det/none · {preview_hint} · Enter apply · {back_hint}"
    );
    lines.push(format!(
        "{left_pad}{}",
        paint_styled_text(
            color_mode,
            RGB_UI_MUTED,
            false,
            &truncate_chars(&footer, content_w)
        )
    ));

    if lines.len() > term_rows {
        lines.truncate(term_rows);
    }

    let top_pad = term_rows.saturating_sub(lines.len()) / 3;
    let mut padded = vec![String::new(); top_pad];
    padded.extend(lines);
    padded
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn render_setup_toggle_fullscreen(
    state: &SetupToggleState,
    home: &Path,
    include_node_bootstrap: bool,
    allow_back: bool,
    term_rows: usize,
    term_cols: usize,
    color_mode: ColorMode,
    anim_tick: usize,
) {
    let lines = render_setup_toggle_screen(
        state,
        home,
        include_node_bootstrap,
        allow_back,
        term_rows,
        term_cols,
        color_mode,
        anim_tick,
    );
    flush_screen_lines(&lines, term_rows);
}

fn run_plain_tty_setup_toggle(
    state: &mut SetupToggleState,
    home: &Path,
    include_node_bootstrap: bool,
    allow_back: bool,
) -> Result<SetupToggleAction, String> {
    loop {
        println!();
        if include_node_bootstrap {
            println!("Local CLI Setup · Choose Harnesses & Components");
        } else {
            println!("hyp setup --interactive · Choose Harnesses & Components");
        }
        println!();
        for row in setup_checklist(state) {
            match row {
                ChecklistRow::Section(title) => println!("{title}:"),
                ChecklistRow::Spacer => println!(),
                ChecklistRow::Item(item) => {
                    let mark = if item.checked { "x" } else { " " };
                    let extra = if item.component {
                        Some(item.detail)
                    } else {
                        item.badge
                    }
                    .map_or_else(String::new, |detail| format!(" {detail}"));
                    println!("  [{:>2}] [{mark}] {}{extra}", item.index + 1, item.label);
                }
            }
        }
        if state.show_dry_run_preview {
            println!();
            println!("Dry-Run Preview (zero files written):");
            for line in state.build_dry_run_preview(home, include_node_bootstrap) {
                println!("  • {line}");
            }
        }
        println!();
        let back_str = if allow_back {
            "[b] back, [q] quit"
        } else {
            "[b/q] cancel"
        };
        println!(
            "Commands: number(s) to toggle (e.g. 1,11), [a] all/det/none, [d] preview, [Enter] apply, {back_str}"
        );

        let reply = match read_tty_line("Toggle or Enter to apply: ") {
            Ok(Some(line)) => line,
            Ok(None) => return Ok(SetupToggleAction::Cancel),
            Err(e) => return Err(format!("Failed reading interactive selection: {e}")),
        };
        match apply_setup_toggle_text_input(state, &reply, allow_back) {
            Ok(SetupToggleAction::Continue) => {}
            Ok(action) => return Ok(action),
            Err(msg) => println!("{msg}"),
        }
    }
}

/// Standalone interactive harness & component toggle screen entrypoint for `hyp setup --interactive`.
///
/// When OpenClaw is selected, advances to the dedicated OpenClaw Delivery Mode & Prompt Injection
/// step before returning `Ok(Some(selection))`.
///
/// Returns `Ok(Some(selection))` when confirmed with `Enter`, or `Ok(None)` when cancelled with
/// `Esc`/`b`/`q` (guaranteed zero files written).
pub fn run_setup_toggle_interactive(
    mut state: SetupToggleState,
    home: &Path,
) -> Result<Option<SetupSelection>, String> {
    #[cfg(unix)]
    {
        if io::stdout().is_terminal() {
            let color_mode = detect_color_mode();
            let mut alt = AltScreenGuard::wizard(true);
            if let Ok(mut raw) = RawTtyGuard::enter(false) {
                let live_anim = !wizard_anim_disabled(false) && color_mode != ColorMode::Plain;
                let mut anim_tick: usize = 0;
                let mut in_openclaw_step = false;
                let mut oc_state = OpenClawConfigState::new(
                    state.openclaw_delivery,
                    state.openclaw_prompt_injection,
                );
                let outcome = loop {
                    let (term_rows, term_cols) = detect_terminal_size();
                    if in_openclaw_step {
                        render_openclaw_config_fullscreen(
                            &oc_state, home, None, true, term_rows, term_cols, color_mode,
                        );
                        let key = match raw.read_key(parse_key_bytes) {
                            Ok(k) => k,
                            Err(e) => break Err(format!("Failed reading TTY input: {e}")),
                        };
                        match handle_openclaw_config_key(&mut oc_state, key, true) {
                            OpenClawConfigAction::Continue => {}
                            OpenClawConfigAction::Apply {
                                delivery,
                                prompt_injection,
                            } => {
                                state.openclaw_delivery = delivery;
                                state.openclaw_prompt_injection = prompt_injection;
                                break Ok(Some(state.to_selection()));
                            }
                            OpenClawConfigAction::Back => {
                                state.openclaw_delivery = oc_state.delivery;
                                state.openclaw_prompt_injection = oc_state.prompt_injection;
                                in_openclaw_step = false;
                            }
                            OpenClawConfigAction::Cancel => break Ok(None),
                        }
                        continue;
                    }

                    let has_live_banner = term_rows >= 33 && !state.show_dry_run_preview;
                    render_setup_toggle_fullscreen(
                        &state, home, false, false, term_rows, term_cols, color_mode, anim_tick,
                    );
                    let key = if live_anim && has_live_banner {
                        match raw.read_key_timeout(parse_key_bytes) {
                            Ok(Some(k)) => k,
                            Ok(None) => {
                                anim_tick = anim_tick.wrapping_add(1);
                                continue;
                            }
                            Err(e) => break Err(format!("Failed reading TTY input: {e}")),
                        }
                    } else {
                        match raw.read_key(parse_key_bytes) {
                            Ok(k) => k,
                            Err(e) => break Err(format!("Failed reading TTY input: {e}")),
                        }
                    };
                    match handle_setup_toggle_key(&mut state, key, false) {
                        SetupToggleAction::Continue => {}
                        SetupToggleAction::Apply(sel) => {
                            if sel.harnesses.contains(&HarnessKind::Openclaw) {
                                oc_state = OpenClawConfigState::new(
                                    state.openclaw_delivery,
                                    state.openclaw_prompt_injection,
                                );
                                in_openclaw_step = true;
                            } else {
                                break Ok(Some(sel));
                            }
                        }
                        SetupToggleAction::Back | SetupToggleAction::Cancel => break Ok(None),
                    }
                };
                raw.restore();
                alt.leave();
                return outcome;
            }
            alt.leave();
        }
    }

    loop {
        match run_plain_tty_setup_toggle(&mut state, home, false, false)? {
            SetupToggleAction::Apply(mut sel) => {
                if sel.harnesses.contains(&HarnessKind::Openclaw) {
                    let mut oc_state = OpenClawConfigState::new(
                        state.openclaw_delivery,
                        state.openclaw_prompt_injection,
                    );
                    match run_plain_tty_openclaw_config(&mut oc_state, true)? {
                        OpenClawConfigAction::Apply {
                            delivery,
                            prompt_injection,
                        } => {
                            state.openclaw_delivery = delivery;
                            state.openclaw_prompt_injection = prompt_injection;
                            sel.openclaw_delivery = delivery;
                            sel.openclaw_prompt_injection = prompt_injection;
                            return Ok(Some(sel));
                        }
                        OpenClawConfigAction::Back => {
                            state.openclaw_delivery = oc_state.delivery;
                            state.openclaw_prompt_injection = oc_state.prompt_injection;
                            continue;
                        }
                        OpenClawConfigAction::Cancel | OpenClawConfigAction::Continue => {
                            return Ok(None);
                        }
                    }
                }
                return Ok(Some(sel));
            }
            SetupToggleAction::Back | SetupToggleAction::Cancel | SetupToggleAction::Continue => {
                return Ok(None);
            }
        }
    }
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn build_initial_manual_guide_screen(
    harness: ManualGuideHarness,
    home: &Path,
    explicit_home: bool,
    existing_node: Option<&ExistingNodeInfo>,
    cli_bin: &str,
    primary_skill: PathBuf,
    installed: Vec<InstalledSkillEntry>,
    main_selected: usize,
    allow_back: bool,
) -> WizardScreen {
    let prompt = build_manual_guide_prompt(harness, existing_node.map(|n| n.node_id.as_str()));
    let deeplink =
        resolve_manual_guide_deeplink(harness, &prompt, home, explicit_home, existing_node);

    if harness == ManualGuideHarness::Openclaw {
        return WizardScreen::OpenClawAssistConfig {
            state: OpenClawConfigState::from_home(home),
            primary_skill,
            installed,
            prompt,
            deeplink,
            error_status: None,
            main_selected,
            allow_back,
        };
    }

    if let Some(plan) = inspect_desktop_mcp_plan(harness, home, cli_bin) {
        if !plan.already_configured {
            return WizardScreen::DesktopMcpConfirm {
                harness,
                plan,
                primary_skill,
                installed,
                prompt,
                deeplink,
                selected_option: 0,
                error_status: None,
                main_selected,
                allow_back,
            };
        }
        return WizardScreen::ManualGuide {
            harness,
            primary_skill,
            installed,
            prompt,
            mcp_status: DesktopMcpStatus::AlreadyConfigured(plan.config_path),
            deeplink,
            selected_action: 0,
            copied_status: None,
            main_selected,
            allow_back,
        };
    }

    WizardScreen::ManualGuide {
        harness,
        primary_skill,
        installed,
        prompt,
        mcp_status: DesktopMcpStatus::NotApplicable,
        deeplink,
        selected_action: 0,
        copied_status: None,
        main_selected,
        allow_back,
    }
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
fn run_fullscreen_tui_loop(
    initial_screen: WizardScreen,
    main_items: &[MainMenuItem],
    home: &Path,
    explicit_home: bool,
    claude_config_dir: Option<&Path>,
    existing_node: Option<&ExistingNodeInfo>,
    in_herdr_env: Option<&str>,
    cli_bin: &str,
    play_intro: bool,
    animate_banner: bool,
) -> Option<WizardAction> {
    let color_mode = detect_color_mode();
    let (mut term_rows, mut term_cols) = detect_terminal_size();

    let mut alt = AltScreenGuard::wizard(true);
    let Ok(mut raw) = RawTtyGuard::enter(play_intro) else {
        alt.leave();
        return None;
    };

    if play_intro
        && play_fullscreen_intro_on_alt_screen(&mut raw, term_rows, term_cols, color_mode, 140)
            == AnimOutcome::Cancelled
    {
        raw.restore();
        alt.leave();
        return Some(WizardAction::Cancel);
    }

    if raw.set_mode(false).is_err() {
        raw.restore();
        alt.leave();
        return None;
    }

    let live_anim = animate_banner && color_mode != ColorMode::Plain;
    let mut anim_tick: usize = 0;
    let mut screen = initial_screen;
    let resolution = loop {
        let (r, c) = detect_terminal_size();
        term_rows = r;
        term_cols = c;

        let has_live_banner = match &screen {
            WizardScreen::Main { selected } => {
                render_main_screen(
                    main_items,
                    *selected,
                    existing_node,
                    in_herdr_env,
                    term_rows,
                    term_cols,
                    color_mode,
                    anim_tick,
                );
                true
            }
            WizardScreen::LocalSetupConfig { state, .. } => {
                render_setup_toggle_fullscreen(
                    state, home, true, true, term_rows, term_cols, color_mode, anim_tick,
                );
                term_rows >= 33 && !state.show_dry_run_preview
            }
            WizardScreen::OpenClawLocalSetup { state, .. } => {
                render_openclaw_config_fullscreen(
                    state, home, None, true, term_rows, term_cols, color_mode,
                );
                false
            }
            WizardScreen::OpenClawAssistConfig {
                state,
                error_status,
                allow_back,
                ..
            } => {
                render_openclaw_config_fullscreen(
                    state,
                    home,
                    error_status.as_deref(),
                    *allow_back,
                    term_rows,
                    term_cols,
                    color_mode,
                );
                false
            }
            WizardScreen::HerdrTemplates {
                templates,
                selected,
                allow_back,
                ..
            } => {
                render_herdr_screen(
                    templates,
                    *selected,
                    *allow_back,
                    term_rows,
                    term_cols,
                    color_mode,
                    anim_tick,
                );
                term_rows >= 26
            }
            WizardScreen::DesktopMcpConfirm {
                harness,
                plan,
                primary_skill,
                selected_option,
                error_status,
                allow_back,
                ..
            } => {
                render_desktop_mcp_confirm_screen(
                    *harness,
                    home,
                    plan,
                    primary_skill,
                    *selected_option,
                    error_status.as_deref(),
                    *allow_back,
                    term_rows,
                    term_cols,
                    color_mode,
                );
                false
            }
            WizardScreen::ManualGuide {
                harness,
                primary_skill,
                installed,
                prompt,
                mcp_status,
                deeplink,
                selected_action,
                copied_status,
                allow_back,
                ..
            } => {
                render_manual_guide_screen(
                    *harness,
                    home,
                    cli_bin,
                    primary_skill,
                    installed,
                    prompt,
                    mcp_status,
                    deeplink.as_deref(),
                    *selected_action,
                    copied_status.as_deref(),
                    *allow_back,
                    term_rows,
                    term_cols,
                    color_mode,
                );
                false
            }
        };

        let key = if live_anim && has_live_banner {
            match raw.read_key_timeout(parse_key_bytes) {
                Ok(Some(k)) => k,
                Ok(None) => {
                    anim_tick = anim_tick.wrapping_add(1);
                    continue;
                }
                Err(e) => break WizardAction::Error(format!("Failed reading TTY input: {e}")),
            }
        } else {
            match raw.read_key(parse_key_bytes) {
                Ok(k) => k,
                Err(e) => break WizardAction::Error(format!("Failed reading TTY input: {e}")),
            }
        };

        match &mut screen {
            WizardScreen::Main { selected } => {
                let len = main_items.len();
                match key {
                    KeyEvent::Up => {
                        if len > 0 {
                            *selected = (*selected + len - 1) % len;
                        }
                    }
                    KeyEvent::Down => {
                        if len > 0 {
                            *selected = (*selected + 1) % len;
                        }
                    }
                    KeyEvent::Back | KeyEvent::Cancel => {
                        break WizardAction::Cancel;
                    }
                    KeyEvent::Enter => {
                        let idx = *selected;
                        let Some(item) = main_items.get(idx) else {
                            break WizardAction::Cancel;
                        };
                        match &item.action {
                            MainMenuAction::HerdrTemplates { hc_bin, templates } => {
                                screen = WizardScreen::HerdrTemplates {
                                    hc_bin: hc_bin.clone(),
                                    templates: templates.clone(),
                                    selected: 0,
                                    main_selected: idx,
                                    allow_back: true,
                                };
                            }
                            MainMenuAction::LaunchHerdrTemplate { hc_bin, template } => {
                                break WizardAction::LaunchHerdr {
                                    hc_bin: hc_bin.clone(),
                                    template: template.clone(),
                                };
                            }
                            MainMenuAction::LaunchCli(lh) => {
                                break WizardAction::LaunchCli(*lh);
                            }
                            MainMenuAction::ManualGuide(mh) => {
                                match install_manual_guide_skills(
                                    *mh,
                                    home,
                                    explicit_home,
                                    claude_config_dir,
                                ) {
                                    Ok((primary_skill, installed)) => {
                                        screen = build_initial_manual_guide_screen(
                                            *mh,
                                            home,
                                            explicit_home,
                                            existing_node,
                                            cli_bin,
                                            primary_skill,
                                            installed,
                                            idx,
                                            true,
                                        );
                                    }
                                    Err(e) => break WizardAction::Error(e),
                                }
                            }
                            MainMenuAction::QuickLocalSetup => {
                                let state = SetupToggleState::from_home_with_claude(
                                    home,
                                    explicit_home,
                                    claude_config_dir,
                                );
                                screen = WizardScreen::LocalSetupConfig {
                                    state,
                                    main_selected: idx,
                                };
                            }
                        }
                    }
                    _ => {}
                }
            }
            WizardScreen::LocalSetupConfig {
                state,
                main_selected,
            } => match handle_setup_toggle_key(state, key, true) {
                SetupToggleAction::Continue => {}
                SetupToggleAction::Apply(selection) => {
                    if selection.harnesses.contains(&HarnessKind::Openclaw) {
                        let oc_state = OpenClawConfigState::new(
                            state.openclaw_delivery,
                            state.openclaw_prompt_injection,
                        );
                        let saved_toggle = state.clone();
                        let saved_main = *main_selected;
                        screen = WizardScreen::OpenClawLocalSetup {
                            state: oc_state,
                            toggle_state: saved_toggle,
                            main_selected: saved_main,
                        };
                    } else {
                        break WizardAction::RunLocalCliSetupWithSelection(selection);
                    }
                }
                SetupToggleAction::Back => {
                    let prev = *main_selected;
                    screen = WizardScreen::Main { selected: prev };
                }
                SetupToggleAction::Cancel => {
                    break WizardAction::Cancel;
                }
            },
            WizardScreen::OpenClawLocalSetup {
                state,
                toggle_state,
                main_selected,
            } => match handle_openclaw_config_key(state, key, true) {
                OpenClawConfigAction::Continue => {}
                OpenClawConfigAction::Apply {
                    delivery,
                    prompt_injection,
                } => {
                    let mut next_toggle = toggle_state.clone();
                    next_toggle.openclaw_delivery = delivery;
                    next_toggle.openclaw_prompt_injection = prompt_injection;
                    break WizardAction::RunLocalCliSetupWithSelection(next_toggle.to_selection());
                }
                OpenClawConfigAction::Back => {
                    let mut prev_toggle = toggle_state.clone();
                    prev_toggle.openclaw_delivery = state.delivery;
                    prev_toggle.openclaw_prompt_injection = state.prompt_injection;
                    let prev_main = *main_selected;
                    screen = WizardScreen::LocalSetupConfig {
                        state: prev_toggle,
                        main_selected: prev_main,
                    };
                }
                OpenClawConfigAction::Cancel => {
                    break WizardAction::Cancel;
                }
            },
            WizardScreen::OpenClawAssistConfig {
                state,
                primary_skill,
                installed,
                prompt,
                deeplink,
                error_status,
                main_selected,
                allow_back,
            } => match handle_openclaw_config_key(state, key, *allow_back) {
                OpenClawConfigAction::Continue => {}
                OpenClawConfigAction::Apply {
                    delivery,
                    prompt_injection,
                } => {
                    let node_cfg_opt = existing_node.map(|n| n.config_path.as_path());
                    match apply_openclaw_config(
                        home,
                        cli_bin,
                        None,
                        node_cfg_opt,
                        delivery,
                        prompt_injection,
                        false,
                    ) {
                        Ok(_) => {
                            let next_skill = primary_skill.clone();
                            let next_installed = installed.clone();
                            let next_prompt = prompt.clone();
                            let next_deeplink = deeplink.clone();
                            let next_main = *main_selected;
                            let next_back = *allow_back;
                            screen = WizardScreen::ManualGuide {
                                harness: ManualGuideHarness::Openclaw,
                                primary_skill: next_skill,
                                installed: next_installed,
                                prompt: next_prompt,
                                mcp_status: DesktopMcpStatus::Applied(
                                    home.join(".openclaw").join("openclaw.json"),
                                ),
                                deeplink: next_deeplink,
                                selected_action: 0,
                                copied_status: None,
                                main_selected: next_main,
                                allow_back: next_back,
                            };
                        }
                        Err(err) => {
                            *error_status = Some(err);
                        }
                    }
                }
                OpenClawConfigAction::Back => {
                    let prev = *main_selected;
                    screen = WizardScreen::Main { selected: prev };
                }
                OpenClawConfigAction::Cancel => {
                    break WizardAction::Cancel;
                }
            },
            WizardScreen::HerdrTemplates {
                hc_bin,
                templates,
                selected,
                main_selected,
                allow_back,
            } => {
                let total = templates.len() + usize::from(*allow_back);
                match key {
                    KeyEvent::Up => {
                        if total > 0 {
                            *selected = (*selected + total - 1) % total;
                        }
                    }
                    KeyEvent::Down => {
                        if total > 0 {
                            *selected = (*selected + 1) % total;
                        }
                    }
                    KeyEvent::Left | KeyEvent::Back => {
                        if *allow_back {
                            let prev = *main_selected;
                            screen = WizardScreen::Main { selected: prev };
                        } else {
                            break WizardAction::Cancel;
                        }
                    }
                    KeyEvent::Cancel => {
                        break WizardAction::Cancel;
                    }
                    KeyEvent::Enter => {
                        if let Some(tmpl) = templates.get(*selected).cloned() {
                            break WizardAction::LaunchHerdr {
                                hc_bin: hc_bin.clone(),
                                template: tmpl,
                            };
                        } else if *allow_back {
                            let prev = *main_selected;
                            screen = WizardScreen::Main { selected: prev };
                        } else {
                            break WizardAction::Cancel;
                        }
                    }
                    _ => {}
                }
            }
            WizardScreen::DesktopMcpConfirm {
                harness,
                primary_skill,
                installed,
                prompt,
                deeplink,
                selected_option,
                error_status,
                main_selected,
                allow_back,
                ..
            } => match key {
                KeyEvent::Up | KeyEvent::Down => {
                    *selected_option = 1 - (*selected_option % 2);
                }
                KeyEvent::Left | KeyEvent::Back => {
                    if *allow_back {
                        let prev = *main_selected;
                        screen = WizardScreen::Main { selected: prev };
                    } else {
                        break WizardAction::Cancel;
                    }
                }
                KeyEvent::Cancel => {
                    break WizardAction::Cancel;
                }
                KeyEvent::Enter => {
                    if *selected_option == 0 {
                        match apply_desktop_mcp_config(*harness, home, cli_bin) {
                            Ok(applied) => {
                                let next_harness = *harness;
                                let next_skill = primary_skill.clone();
                                let next_installed = installed.clone();
                                let next_prompt = prompt.clone();
                                let next_deeplink = deeplink.clone();
                                let next_main = *main_selected;
                                let next_back = *allow_back;
                                screen = WizardScreen::ManualGuide {
                                    harness: next_harness,
                                    primary_skill: next_skill,
                                    installed: next_installed,
                                    prompt: next_prompt,
                                    mcp_status: DesktopMcpStatus::Applied(applied.config_path),
                                    deeplink: next_deeplink,
                                    selected_action: 0,
                                    copied_status: None,
                                    main_selected: next_main,
                                    allow_back: next_back,
                                };
                            }
                            Err(err) => {
                                *error_status = Some(err);
                                *selected_option = 1;
                            }
                        }
                    } else {
                        let next_harness = *harness;
                        let next_skill = primary_skill.clone();
                        let next_installed = installed.clone();
                        let next_prompt = prompt.clone();
                        let next_deeplink = deeplink.clone();
                        let next_main = *main_selected;
                        let next_back = *allow_back;
                        screen = WizardScreen::ManualGuide {
                            harness: next_harness,
                            primary_skill: next_skill,
                            installed: next_installed,
                            prompt: next_prompt,
                            mcp_status: DesktopMcpStatus::Skipped,
                            deeplink: next_deeplink,
                            selected_action: 0,
                            copied_status: None,
                            main_selected: next_main,
                            allow_back: next_back,
                        };
                    }
                }
                _ => {}
            },
            WizardScreen::ManualGuide {
                harness,
                primary_skill,
                installed,
                prompt,
                mcp_status,
                deeplink,
                selected_action,
                copied_status,
                main_selected,
                allow_back,
            } => {
                let has_open = deeplink.is_some();
                let open_idx = if has_open { Some(0usize) } else { None };
                let copy_idx = usize::from(has_open);
                let back_idx = if *allow_back {
                    Some(copy_idx + 1)
                } else {
                    None
                };
                let done_idx = copy_idx + 1 + usize::from(*allow_back);
                let action_count = done_idx + 1;

                match key {
                    KeyEvent::Up => {
                        *selected_action = (*selected_action + action_count - 1) % action_count;
                    }
                    KeyEvent::Down => {
                        *selected_action = (*selected_action + 1) % action_count;
                    }
                    KeyEvent::Char('o') | KeyEvent::Char('O') => {
                        if let Some(url) = deeplink.as_deref() {
                            *copied_status = Some(trigger_open_in_app(*harness, prompt, url));
                        }
                    }
                    KeyEvent::Char('c') | KeyEvent::Char('C') => {
                        *copied_status = match copy_text_to_clipboard(prompt) {
                            Ok(_) => Some("✓ Copied to clipboard!".to_string()),
                            Err(msg) => Some(msg),
                        };
                    }
                    KeyEvent::Left | KeyEvent::Back => {
                        if *allow_back {
                            let prev = *main_selected;
                            screen = WizardScreen::Main { selected: prev };
                        } else {
                            break WizardAction::ManualGuideDone {
                                harness: *harness,
                                primary_skill: primary_skill.clone(),
                                installed: installed.clone(),
                                prompt: prompt.clone(),
                                mcp_status: mcp_status.clone(),
                                deeplink: deeplink.clone(),
                            };
                        }
                    }
                    KeyEvent::Cancel => {
                        break WizardAction::ManualGuideDone {
                            harness: *harness,
                            primary_skill: primary_skill.clone(),
                            installed: installed.clone(),
                            prompt: prompt.clone(),
                            mcp_status: mcp_status.clone(),
                            deeplink: deeplink.clone(),
                        };
                    }
                    KeyEvent::Enter => {
                        if Some(*selected_action) == open_idx {
                            if let Some(url) = deeplink.as_deref() {
                                *copied_status = Some(trigger_open_in_app(*harness, prompt, url));
                            }
                        } else if *selected_action == copy_idx {
                            *copied_status = match copy_text_to_clipboard(prompt) {
                                Ok(_) => Some("✓ Copied to clipboard!".to_string()),
                                Err(msg) => Some(msg),
                            };
                        } else if Some(*selected_action) == back_idx {
                            let prev = *main_selected;
                            screen = WizardScreen::Main { selected: prev };
                        } else if *selected_action == done_idx {
                            break WizardAction::ManualGuideDone {
                                harness: *harness,
                                primary_skill: primary_skill.clone(),
                                installed: installed.clone(),
                                prompt: prompt.clone(),
                                mcp_status: mcp_status.clone(),
                                deeplink: deeplink.clone(),
                            };
                        }
                    }
                    _ => {}
                }
            }
        }
    };

    // CRITICAL: Always restore cooked TTY mode and leave alt-screen BEFORE returning / launching!
    raw.restore();
    alt.leave();
    Some(resolution)
}

#[derive(Clone, Copy)]
struct WizardDispatch<'a> {
    home: &'a Path,
    explicit_home: bool,
    claude_config_dir: Option<&'a Path>,
    existing_node: Option<&'a ExistingNodeInfo>,
    cli_bin: &'a str,
    json: bool,
}

impl<'a> WizardDispatch<'a> {
    fn new(
        args: &'a OnboardArgs,
        home: &'a Path,
        node: Option<&'a ExistingNodeInfo>,
        cli_bin: &'a str,
    ) -> Self {
        Self {
            home,
            explicit_home: args.home.is_some(),
            claude_config_dir: args.claude_config_dir.as_deref(),
            existing_node: node,
            cli_bin,
            json: args.json,
        }
    }

    fn dispatch(self, action: WizardAction) -> WizardOutcome {
        let Self {
            home,
            explicit_home,
            claude_config_dir,
            existing_node,
            cli_bin,
            json,
        } = self;
        match action {
            WizardAction::Cancel => WizardOutcome::Finished(Ok(ExitCode::from(EXIT_OK))),
            WizardAction::RunLocalCliSetupWithSelection(selection) => {
                WizardOutcome::RunLocalCliSetupWithSelection(selection)
            }
            WizardAction::LaunchCli(lh) => {
                let code = install_and_handoff_cli(
                    lh,
                    home,
                    explicit_home,
                    claude_config_dir,
                    existing_node,
                    cli_bin,
                    json,
                );
                WizardOutcome::Finished(code)
            }
            WizardAction::LaunchHerdr { hc_bin, template } => {
                let code = install_and_handoff_herdr(
                    &hc_bin,
                    &template,
                    home,
                    explicit_home,
                    claude_config_dir,
                    existing_node,
                    json,
                );
                WizardOutcome::Finished(code)
            }
            WizardAction::ManualGuide(harness) => {
                WizardOutcome::Finished(install_and_emit_manual_guide(
                    harness,
                    home,
                    explicit_home,
                    claude_config_dir,
                    existing_node,
                    cli_bin,
                    json,
                ))
            }
            #[cfg(unix)]
            WizardAction::ManualGuideDone {
                harness,
                primary_skill,
                installed,
                prompt,
                mcp_status,
                deeplink,
            } => {
                print_manual_guide_plain(
                    harness,
                    home,
                    cli_bin,
                    &primary_skill,
                    &installed,
                    &prompt,
                    &mcp_status,
                    deeplink.as_deref(),
                );
                WizardOutcome::Finished(Ok(ExitCode::from(EXIT_OK)))
            }
            #[cfg(unix)]
            WizardAction::Error(msg) => {
                WizardOutcome::Finished(Err(CliError::error("WIZARD_ERROR", msg)
                    .with_fix("Re-run with `hyp onboard --yes` for local CLI setup.".to_string())))
            }
        }
    }
}

// ============================================================================
// Cross-Platform Numbered Line Fallback (Windows & Non-Raw Terminals)
// ============================================================================

pub(crate) fn read_tty_line(prompt: &str) -> io::Result<Option<String>> {
    {
        let mut out = io::stdout().lock();
        out.write_all(prompt.as_bytes())?;
        out.flush()?;
    }

    #[cfg(unix)]
    {
        if !io::stdin().is_terminal() {
            if let Ok(tty) = fs::File::open("/dev/tty") {
                let mut reader = BufReader::new(tty);
                let mut line = String::new();
                let n = reader.read_line(&mut line)?;
                return if n == 0 { Ok(None) } else { Ok(Some(line)) };
            }
        }
    }

    let stdin = io::stdin();
    let mut line = String::new();
    let n = stdin.lock().read_line(&mut line)?;
    if n == 0 { Ok(None) } else { Ok(Some(line)) }
}

fn run_numbered_herdr_fallback(
    hc_bin: &Path,
    templates: &[HerdrTemplate],
    dispatch: WizardDispatch<'_>,
) -> Option<WizardOutcome> {
    println!();
    println!("Herdr · Pick a Launch Template:");
    for (idx, tmpl) in templates.iter().enumerate() {
        println!(
            "  [{}] {} ({})",
            idx + 1,
            tmpl.display_title(),
            tmpl.display_subtitle()
        );
    }
    println!("  [b] Back");
    println!("  [q] Quit");
    println!();

    loop {
        let reply = match read_tty_line("Choose template [1]: ") {
            Ok(Some(line)) => line.trim().to_ascii_lowercase(),
            Ok(None) => return Some(WizardOutcome::Finished(Ok(ExitCode::from(EXIT_OK)))),
            Err(_) => return None,
        };
        if reply.is_empty() {
            return Some(dispatch.dispatch(WizardAction::LaunchHerdr {
                hc_bin: hc_bin.to_owned(),
                template: templates[0].clone(),
            }));
        }
        if matches!(reply.as_str(), "b" | "back") {
            return None;
        }
        if matches!(reply.as_str(), "q" | "quit") {
            return Some(WizardOutcome::Finished(Ok(ExitCode::from(EXIT_OK))));
        }
        if let Some(n) = reply
            .parse::<usize>()
            .ok()
            .filter(|n| (1..=templates.len()).contains(n))
        {
            return Some(dispatch.dispatch(WizardAction::LaunchHerdr {
                hc_bin: hc_bin.to_owned(),
                template: templates[n - 1].clone(),
            }));
        }
        println!(
            "Invalid choice '{reply}'. Enter 1-{}, 'b' to go back, or 'q' to quit.",
            templates.len()
        );
    }
}

enum PlainMcpConfirmOutcome {
    Status(DesktopMcpStatus),
    Back,
    Quit,
}

fn run_plain_tty_desktop_mcp_confirm(
    harness: ManualGuideHarness,
    home: &Path,
    cli_bin: &str,
    allow_back: bool,
) -> PlainMcpConfirmOutcome {
    let Some(plan) = inspect_desktop_mcp_plan(harness, home, cli_bin) else {
        return PlainMcpConfirmOutcome::Status(DesktopMcpStatus::NotApplicable);
    };
    if plan.already_configured {
        return PlainMcpConfirmOutcome::Status(DesktopMcpStatus::AlreadyConfigured(
            plan.config_path,
        ));
    }

    println!();
    println!("{} · Confirm MCP Config Update", harness.display_name());
    println!("  File: {}", plan.config_path.display());
    println!("  Existing servers & settings are preserved.");
    println!();
    for line in &plan.preview_lines {
        println!("    {line}");
    }
    println!();
    for (index, (label, _)) in DESKTOP_MCP_CHOICES.iter().enumerate() {
        println!("  [{}] {label}", index + 1);
    }
    if allow_back {
        println!("  [b] Back");
    }
    println!("  [q] Quit");
    println!();

    loop {
        let reply = match read_tty_line("Selection [1]: ") {
            Ok(Some(line)) => line.trim().to_ascii_lowercase(),
            Ok(None) => return PlainMcpConfirmOutcome::Quit,
            Err(_) => return PlainMcpConfirmOutcome::Status(DesktopMcpStatus::Skipped),
        };
        if reply.is_empty() || matches!(reply.as_str(), "1" | "y" | "yes" | "apply") {
            match apply_desktop_mcp_config(harness, home, cli_bin) {
                Ok(res) => {
                    return PlainMcpConfirmOutcome::Status(DesktopMcpStatus::Applied(
                        res.config_path,
                    ));
                }
                Err(err) => {
                    println!("WARN  {err}");
                    return PlainMcpConfirmOutcome::Status(DesktopMcpStatus::Skipped);
                }
            }
        }
        if matches!(reply.as_str(), "2" | "n" | "no" | "skip") {
            return PlainMcpConfirmOutcome::Status(DesktopMcpStatus::Skipped);
        }
        if allow_back && matches!(reply.as_str(), "b" | "back") {
            return PlainMcpConfirmOutcome::Back;
        }
        if matches!(reply.as_str(), "q" | "quit") {
            return PlainMcpConfirmOutcome::Quit;
        }
        println!("Invalid choice '{reply}'. Enter 1, 2, or 'q' to quit.");
    }
}

fn run_plain_tty_manual_guide(
    harness: ManualGuideHarness,
    home: &Path,
    explicit_home: bool,
    claude_config_dir: Option<&Path>,
    existing_node: Option<&ExistingNodeInfo>,
    cli_bin: &str,
    allow_back: bool,
) -> Option<WizardOutcome> {
    let (primary_skill, installed) =
        match install_manual_guide_skills(harness, home, explicit_home, claude_config_dir) {
            Ok(res) => res,
            Err(e) => {
                return Some(WizardOutcome::Finished(Err(CliError::error(
                    "SKILL_INSTALL_FAILED",
                    e,
                ))));
            }
        };

    let mcp_status = if harness == ManualGuideHarness::Openclaw {
        let mut oc_state = OpenClawConfigState::from_home(home);
        match run_plain_tty_openclaw_config(&mut oc_state, allow_back) {
            Ok(OpenClawConfigAction::Apply {
                delivery,
                prompt_injection,
            }) => match apply_openclaw_config(
                home,
                cli_bin,
                None,
                existing_node.map(|n| n.config_path.as_path()),
                delivery,
                prompt_injection,
                false,
            ) {
                Ok(_) => DesktopMcpStatus::Applied(home.join(".openclaw").join("openclaw.json")),
                Err(err) => {
                    println!("WARN  {err}");
                    DesktopMcpStatus::Skipped
                }
            },
            Ok(OpenClawConfigAction::Back) => return None,
            Ok(OpenClawConfigAction::Cancel | OpenClawConfigAction::Continue) => {
                return Some(WizardOutcome::Finished(Ok(ExitCode::from(EXIT_OK))));
            }
            Err(_) => DesktopMcpStatus::Skipped,
        }
    } else {
        match run_plain_tty_desktop_mcp_confirm(harness, home, cli_bin, allow_back) {
            PlainMcpConfirmOutcome::Status(st) => st,
            PlainMcpConfirmOutcome::Back => return None,
            PlainMcpConfirmOutcome::Quit => {
                return Some(WizardOutcome::Finished(Ok(ExitCode::from(EXIT_OK))));
            }
        }
    };

    let prompt = build_manual_guide_prompt(harness, existing_node.map(|n| n.node_id.as_str()));
    let deeplink =
        resolve_manual_guide_deeplink(harness, &prompt, home, explicit_home, existing_node);
    print_manual_guide_plain(
        harness,
        home,
        cli_bin,
        &primary_skill,
        &installed,
        &prompt,
        &mcp_status,
        deeplink.as_deref(),
    );

    let action_prompt = match (deeplink.is_some(), allow_back) {
        (true, true) => {
            "Press [o] to open app, [c] to copy prompt, [b] to go back, or Enter to finish: "
        }
        (true, false) => "Press [o] to open app, [c] to copy prompt, or Enter to finish: ",
        (false, true) => "Press [c] to copy prompt, [b] to go back, or Enter to finish: ",
        (false, false) => "Press [c] to copy prompt, or Enter to finish: ",
    };
    if let Ok(Some(ans)) = read_tty_line(action_prompt) {
        let low = ans.trim().to_ascii_lowercase();
        if low == "o" {
            if let Some(url) = deeplink.as_deref() {
                println!("{}", trigger_open_in_app(harness, &prompt, url));
            }
        } else if low == "c" {
            match copy_text_to_clipboard(&prompt) {
                Ok(_) => println!("OK    Copied prompt to clipboard."),
                Err(msg) => println!("WARN  {msg}"),
            }
        } else if allow_back && (low == "b" || low == "back") {
            return None;
        }
    }
    Some(WizardOutcome::Finished(Ok(ExitCode::from(EXIT_OK))))
}

fn run_numbered_fallback_wizard(
    args: &OnboardArgs,
    home: &Path,
    main_items: &[MainMenuItem],
    existing_node: Option<&ExistingNodeInfo>,
    in_herdr_env: Option<&str>,
    cli_bin: &str,
) -> WizardOutcome {
    let dispatch = WizardDispatch::new(args, home, existing_node, cli_bin);
    play_mycelium_animation(args.no_anim);

    let version = env!("CARGO_PKG_VERSION");
    println!();
    if let Some(existing) = existing_node {
        let legacy_tag = if existing.is_legacy_v1 {
            " · legacy v1"
        } else {
            ""
        };
        println!(
            "hyphae v{version} · interactive setup (existing node: {}{legacy_tag})",
            existing.node_id
        );
        println!("  Config: {}", existing.config_path.display());
    } else {
        println!("hyphae v{version}");
    }
    let _ = in_herdr_env;

    let label_w = main_items
        .iter()
        .map(|i| i.label.chars().count())
        .max()
        .unwrap_or(14);
    let tag_w = main_items
        .iter()
        .map(|i| i.tag.chars().count())
        .max()
        .unwrap_or(9);

    loop {
        println!();
        println!("Who should guide setup?");
        for (idx, item) in main_items.iter().enumerate() {
            println!(
                "  {:>2}) {:label_w$}  {:tag_w$}  {}",
                idx + 1,
                item.label,
                item.tag,
                item.subtitle
            );
        }
        println!("   q) Quit");
        println!();

        let reply = match read_tty_line("Selection [1]: ") {
            Ok(Some(line)) => line.trim().to_ascii_lowercase(),
            Ok(None) => return WizardOutcome::Finished(Ok(ExitCode::from(EXIT_OK))),
            Err(e) => {
                return WizardOutcome::Finished(Err(CliError::error(
                    "TTY_READ_ERROR",
                    format!("Failed reading interactive selection: {e}"),
                )
                .with_fix(
                    "Re-run with `hyp onboard --yes` for non-interactive setup.".to_string(),
                )));
            }
        };

        if matches!(reply.as_str(), "q" | "quit") {
            println!("Cancelled.");
            return dispatch.dispatch(WizardAction::Cancel);
        }

        let picked_idx = if reply.is_empty() {
            Some(0)
        } else {
            reply
                .parse::<usize>()
                .ok()
                .filter(|n| (1..=main_items.len()).contains(n))
                .map(|n| n - 1)
        };

        let Some(idx) = picked_idx else {
            println!(
                "Invalid choice '{reply}'. Enter 1-{} or 'q' to quit.",
                main_items.len()
            );
            continue;
        };

        match &main_items[idx].action {
            MainMenuAction::HerdrTemplates { hc_bin, templates } => {
                if let Some(outcome) = run_numbered_herdr_fallback(hc_bin, templates, dispatch) {
                    return outcome;
                }
            }
            MainMenuAction::LaunchHerdrTemplate { hc_bin, template } => {
                return dispatch.dispatch(WizardAction::LaunchHerdr {
                    hc_bin: hc_bin.clone(),
                    template: template.clone(),
                });
            }
            MainMenuAction::LaunchCli(harness) => {
                return dispatch.dispatch(WizardAction::LaunchCli(*harness));
            }
            MainMenuAction::ManualGuide(mh) => {
                if let Some(outcome) = run_plain_tty_manual_guide(
                    *mh,
                    home,
                    args.home.is_some(),
                    args.claude_config_dir.as_deref(),
                    existing_node,
                    cli_bin,
                    true,
                ) {
                    return outcome;
                }
            }
            MainMenuAction::QuickLocalSetup => {
                let mut toggle_state = SetupToggleState::from_home_with_claude(
                    home,
                    args.home.is_some(),
                    args.claude_config_dir.as_deref(),
                );
                loop {
                    match run_plain_tty_setup_toggle(&mut toggle_state, home, true, true) {
                        Ok(SetupToggleAction::Apply(mut selection)) => {
                            if selection.harnesses.contains(&HarnessKind::Openclaw) {
                                let mut oc_state = OpenClawConfigState::new(
                                    toggle_state.openclaw_delivery,
                                    toggle_state.openclaw_prompt_injection,
                                );
                                match run_plain_tty_openclaw_config(&mut oc_state, true) {
                                    Ok(OpenClawConfigAction::Apply {
                                        delivery,
                                        prompt_injection,
                                    }) => {
                                        selection.openclaw_delivery = delivery;
                                        selection.openclaw_prompt_injection = prompt_injection;
                                        return dispatch.dispatch(
                                            WizardAction::RunLocalCliSetupWithSelection(selection),
                                        );
                                    }
                                    Ok(OpenClawConfigAction::Back) => {
                                        toggle_state.openclaw_delivery = oc_state.delivery;
                                        toggle_state.openclaw_prompt_injection =
                                            oc_state.prompt_injection;
                                        continue;
                                    }
                                    Ok(
                                        OpenClawConfigAction::Cancel
                                        | OpenClawConfigAction::Continue,
                                    ) => {
                                        println!("Cancelled.");
                                        return dispatch.dispatch(WizardAction::Cancel);
                                    }
                                    Err(e) => {
                                        return WizardOutcome::Finished(Err(CliError::error("TTY_READ_ERROR", e).with_fix(
                                                "Re-run with `hyp onboard --yes` for non-interactive setup."
                                                    .to_string(),
                                            )));
                                    }
                                }
                            }
                            return dispatch
                                .dispatch(WizardAction::RunLocalCliSetupWithSelection(selection));
                        }
                        Ok(SetupToggleAction::Back) => break,
                        Ok(SetupToggleAction::Cancel) | Ok(SetupToggleAction::Continue) => {
                            println!("Cancelled.");
                            return dispatch.dispatch(WizardAction::Cancel);
                        }
                        Err(e) => {
                            return WizardOutcome::Finished(Err(CliError::error(
                                "TTY_READ_ERROR",
                                e,
                            )
                            .with_fix(
                                "Re-run with `hyp onboard --yes` for non-interactive setup."
                                    .to_string(),
                            )));
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// Wizard & `--assist` Entrypoints
// ============================================================================

/// Determines whether `hyp onboard` should automatically launch the interactive wizard.
pub fn should_launch_interactive_wizard(args: &OnboardArgs, stdout_is_tty: bool) -> bool {
    if !stdout_is_tty {
        return false;
    }
    if args.json
        || args.yes
        || args.no_start
        || args.install_skill
        || args.preview_anim
        || args.join.is_some()
        || args.node_id.is_some()
        || args.state_dir.is_some()
        || args.home.is_some()
        || args.claude_config_dir.is_some()
        || args.bin.is_some()
        || args.harness.is_some()
        || args.statusline
        || args.install_mod
        || args.no_skills
        || args.no_commands
        || args.kv
        || args.no_kv
        || args.openclaw_delivery.is_some()
        || args.openclaw_prompt_injection
        || args.no_openclaw_prompt_injection
        || args.profile != crate::node_cmd::CliNodeProfile::Local
    {
        return false;
    }
    true
}

/// Runs the interactive fullscreen Mycelium onboarding wizard on a TTY.
pub fn run_interactive_wizard(args: &OnboardArgs, home: &Path) -> WizardOutcome {
    let existing_node = detect_existing_node(args, home);
    let config_opt = existing_node.as_ref().map(|n| n.config_path.as_path());
    let path_var = std::env::var_os("PATH");
    let probe = host_desktop_probe(args.home.is_some());
    let herdr_env = detect_herdr_terminal_from_env();
    let cli_bin = resolve_wizard_cli_bin(args.bin.as_deref());

    let main_items = detect_candidates_in_with_claude(
        home,
        args.home.is_some(),
        args.claude_config_dir.as_deref(),
        config_opt,
        path_var.as_deref(),
        probe.apps_dir.as_deref(),
        probe.appdata_dir.as_deref(),
        probe.local_appdata_dir.as_deref(),
        probe.opencode_server_url.as_deref(),
        existing_node.as_ref().map(|n| n.node_id.as_str()),
        herdr_env.as_deref(),
    );

    #[cfg(unix)]
    {
        let animate = !wizard_anim_disabled(args.no_anim) && io::stdout().is_terminal();
        if let Some(resolution) = run_fullscreen_tui_loop(
            WizardScreen::Main { selected: 0 },
            &main_items,
            home,
            args.home.is_some(),
            args.claude_config_dir.as_deref(),
            existing_node.as_ref(),
            herdr_env.as_deref(),
            &cli_bin,
            animate,
            animate,
        ) {
            return WizardDispatch::new(args, home, existing_node.as_ref(), &cli_bin)
                .dispatch(resolution);
        }
    }

    run_numbered_fallback_wizard(
        args,
        home,
        &main_items,
        existing_node.as_ref(),
        herdr_env.as_deref(),
        &cli_bin,
    )
}

/// Entrypoint for `hyp onboard --assist [HARNESS]`.
pub fn run_assist(args: &OnboardArgs, home: &Path, assist_target: &str) -> WizardOutcome {
    let cli_bin = resolve_wizard_cli_bin(args.bin.as_deref());
    let trimmed = assist_target.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("auto") {
        if io::stdout().is_terminal() && !args.json {
            return run_interactive_wizard(args, home);
        }
        let launchables = detect_launchable_harnesses_on_path();
        if let Some(&(chosen, _)) = launchables.first() {
            let existing_node = detect_existing_node(args, home);
            return WizardDispatch::new(args, home, existing_node.as_ref(), &cli_bin)
                .dispatch(WizardAction::LaunchCli(chosen));
        }
        // Check detected non-launchable harnesses (OpenClaw / T3) before failing.
        let existing_node = detect_existing_node(args, home);
        let diagnostics = detect_harness_statuses(
            home,
            args.home.is_some(),
            args.claude_config_dir.as_deref(),
            existing_node.as_ref().map(|n| n.config_path.as_path()),
        );
        for guide in [ManualGuideHarness::Openclaw, ManualGuideHarness::T3] {
            if diagnostics
                .iter()
                .any(|d| d.harness == guide.id() && (d.detected || d.configured))
            {
                return WizardDispatch::new(args, home, existing_node.as_ref(), &cli_bin)
                    .dispatch(WizardAction::ManualGuide(guide));
            }
        }
        return WizardOutcome::Finished(Err(CliError::error("NO_LAUNCHABLE_HARNESS", "No interactive agent CLI (claude, codex, agy, opencode, cursor-agent, gemini) found on PATH").with_fix(
                "Run `hyp onboard --yes` for local CLI onboarding, or install an agent CLI."
                    .to_string(),
            )));
    }

    // 1. Direct Herdr template handoff: `--assist herdr:<template>` or interactive `--assist herdr`.
    let lower = trimmed.to_ascii_lowercase();
    if lower == "herdr" || lower.starts_with("herdr:") {
        let Some(hc_bin) = find_executable_in_path("hc") else {
            return WizardOutcome::Finished(Err(CliError::error(
                "HERDR_CLI_NOT_FOUND",
                "Could not find 'hc' on PATH for Herdr launch templates",
            )
            .with_fix(
                "Install Herdr (`hc`) or run `hyp onboard --yes` for local CLI setup.".to_string(),
            )));
        };

        let existing_node = detect_existing_node(args, home);
        let discovered = discover_herdr_templates(&hc_bin);

        if lower == "herdr" {
            if discovered.is_empty() {
                return WizardOutcome::Finished(Err(CliError::error("HERDR_NO_TEMPLATES", "Herdr (`hc templates --json`) returned no launch templates").with_fix("Create a template under ~/.config/herdr-core/templates or pass `--assist <harness>`.".to_string())));
            }
            #[cfg(unix)]
            if io::stdout().is_terminal() && !args.json {
                let animate = !wizard_anim_disabled(args.no_anim);
                if let Some(resolution) = run_fullscreen_tui_loop(
                    WizardScreen::HerdrTemplates {
                        hc_bin: hc_bin.clone(),
                        templates: discovered.clone(),
                        selected: 0,
                        main_selected: 0,
                        allow_back: false,
                    },
                    &[],
                    home,
                    args.home.is_some(),
                    args.claude_config_dir.as_deref(),
                    existing_node.as_ref(),
                    None,
                    &cli_bin,
                    animate,
                    animate,
                ) {
                    return WizardDispatch::new(args, home, existing_node.as_ref(), &cli_bin)
                        .dispatch(resolution);
                }
            }
            if io::stdout().is_terminal() && !args.json {
                if let Some(outcome) = run_numbered_herdr_fallback(
                    &hc_bin,
                    &discovered,
                    WizardDispatch::new(args, home, existing_node.as_ref(), &cli_bin),
                ) {
                    return outcome;
                }
                return WizardOutcome::Finished(Ok(ExitCode::from(EXIT_OK)));
            }
            let names: Vec<&str> = discovered.iter().map(|t| t.name.as_str()).collect();
            return WizardOutcome::Finished(Err(CliError::usage("HERDR_TEMPLATE_REQUIRED", "Specify a Herdr launch template in non-interactive mode: `--assist herdr:<template>`").with_fix(format!("Available templates: {}", names.join(", ")))));
        }

        let tmpl_name = trimmed[6..].trim();
        if tmpl_name.is_empty() {
            return WizardOutcome::Finished(Err(CliError::usage(
                "INVALID_ASSIST_HARNESS",
                "Empty Herdr template name in `--assist herdr:`",
            )
            .with_fix("Example: hyp onboard --assist herdr:claude-gateway".to_string())));
        }

        let template = discovered
            .into_iter()
            .find(|t| t.name.eq_ignore_ascii_case(tmpl_name))
            .unwrap_or_else(|| HerdrTemplate {
                name: tmpl_name.to_string(),
                description: tmpl_name.to_string(),
                command: tmpl_name.to_string(),
            });

        if !args.json {
            play_mycelium_animation(args.no_anim);
        }
        return WizardDispatch::new(args, home, existing_node.as_ref(), &cli_bin)
            .dispatch(WizardAction::LaunchHerdr { hc_bin, template });
    }

    // 2. Non-launchable manual guide harnesses:
    //    `--assist claude-desktop|codex-desktop|opencode-desktop|cursor-ide|openclaw|t3`.
    if let Some(guide_harness) = ManualGuideHarness::parse_alias(trimmed) {
        let existing_node = detect_existing_node(args, home);

        #[cfg(unix)]
        if io::stdout().is_terminal() && !args.json {
            match install_manual_guide_skills(
                guide_harness,
                home,
                args.home.is_some(),
                args.claude_config_dir.as_deref(),
            ) {
                Ok((primary_skill, installed)) => {
                    let initial = build_initial_manual_guide_screen(
                        guide_harness,
                        home,
                        args.home.is_some(),
                        existing_node.as_ref(),
                        &cli_bin,
                        primary_skill,
                        installed,
                        0,
                        false,
                    );
                    let animate = !wizard_anim_disabled(args.no_anim);
                    if let Some(resolution) = run_fullscreen_tui_loop(
                        initial,
                        &[],
                        home,
                        args.home.is_some(),
                        args.claude_config_dir.as_deref(),
                        existing_node.as_ref(),
                        None,
                        &cli_bin,
                        animate,
                        animate,
                    ) {
                        return WizardDispatch::new(args, home, existing_node.as_ref(), &cli_bin)
                            .dispatch(resolution);
                    }
                }
                Err(e) => {
                    return WizardOutcome::Finished(Err(CliError::error(
                        "SKILL_INSTALL_FAILED",
                        e,
                    )));
                }
            }
        }

        if io::stdout().is_terminal() && !args.json {
            if let Some(outcome) = run_plain_tty_manual_guide(
                guide_harness,
                home,
                args.home.is_some(),
                args.claude_config_dir.as_deref(),
                existing_node.as_ref(),
                &cli_bin,
                false,
            ) {
                return outcome;
            }
            return WizardOutcome::Finished(Ok(ExitCode::from(EXIT_OK)));
        }

        return WizardDispatch::new(args, home, existing_node.as_ref(), &cli_bin)
            .dispatch(WizardAction::ManualGuide(guide_harness));
    }

    // 3. Verified interactive CLI harnesses.
    let Some(chosen) = LaunchableHarness::parse_alias(trimmed) else {
        return WizardOutcome::Finished(Err(CliError::usage("INVALID_ASSIST_HARNESS", format!(
                "Unsupported --assist harness '{trimmed}' (expected auto, herdr:<template>, claude, claude-desktop, codex, codex-desktop, opencode-desktop, agy/antigravity, opencode, cursor/cursor-agent, gemini, openclaw, or t3)"
            )).with_fix("Example: hyp onboard --assist claude".to_string())));
    };

    if !args.json {
        play_mycelium_animation(args.no_anim);
    }
    let existing_node = detect_existing_node(args, home);
    WizardDispatch::new(args, home, existing_node.as_ref(), &cli_bin)
        .dispatch(WizardAction::LaunchCli(chosen))
}

// ============================================================================
// Deterministic Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn strip_ansi(input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        let mut chars = input.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                if chars.peek() == Some(&'[') {
                    let _ = chars.next();
                    for ch in chars.by_ref() {
                        if ch.is_ascii_alphabetic() {
                            break;
                        }
                    }
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    fn is_braille_char(c: char) -> bool {
        ('\u{2800}'..='\u{28FF}').contains(&c)
    }

    #[test]
    fn borderless_menu_banner_centers_the_version_below_the_wordmark() {
        // Borderless fullscreen menu header banner must have zero outer box chrome and
        // include the plain-text version centered directly under the HYPHAE wordmark.
        let banner = build_banner_lines_at_tick(30, 80, 76, ColorMode::Plain, 0);
        assert_eq!(banner.len(), 10);
        assert_eq!(
            banner.last().map(|s| s.trim()),
            Some(format!("v{}", env!("CARGO_PKG_VERSION")).as_str())
        );
        let banner_text = banner.join("\n");
        assert!(banner_text.chars().any(is_braille_char));
        assert!(
            !banner_text.contains('╭') && !banner_text.contains('╰') && !banner_text.contains('│'),
            "menu banner must be borderless:\n{banner_text}"
        );
        for (idx, line) in banner.iter().enumerate() {
            assert!(
                line.chars().count() <= 80,
                "banner row {idx} exceeded 80 cols"
            );
        }
    }

    #[test]
    fn parse_stty_size_and_fullscreen_canvas_scaling() {
        assert_eq!(parse_stty_size("40 120\n"), Some((40, 120)));
        assert_eq!(parse_stty_size("  24   80  "), Some((24, 80)));
        assert_eq!(parse_stty_size("0 80"), None);
        assert_eq!(parse_stty_size("24 0"), None);
        assert_eq!(parse_stty_size("0 0"), None);
        assert_eq!(parse_stty_size("not a size"), None);
        assert_eq!(parse_stty_size("24 80 99"), None);
        assert_eq!(parse_stty_size(""), None);

        assert_eq!(
            detect_terminal_size_from_env(Some("38"), Some("106")),
            (38, 106)
        );
        assert_eq!(detect_terminal_size_from_env(None, None), (24, 80));
        assert_eq!(
            detect_terminal_size_from_env(Some("0"), Some("bad")),
            (24, 80)
        );

        assert_eq!(compute_fullscreen_canvas_size(24, 80), (74, 18));
        assert_eq!(compute_fullscreen_canvas_size(38, 106), (100, 32));
        assert_eq!(compute_fullscreen_canvas_size(60, 200), (132, 44));
        assert_eq!(compute_fullscreen_canvas_size(16, 40), (34, 12));
    }

    #[test]
    fn key_parser_recognizes_arrows_vim_enter_esc_q_and_ctrl_c() {
        assert_eq!(parse_key_bytes(b"\x1b[A"), KeyEvent::Up);
        assert_eq!(parse_key_bytes(b"\x1bOA"), KeyEvent::Up);
        assert_eq!(parse_key_bytes(b"k"), KeyEvent::Up);
        assert_eq!(parse_key_bytes(b"K"), KeyEvent::Up);

        assert_eq!(parse_key_bytes(b"\x1b[B"), KeyEvent::Down);
        assert_eq!(parse_key_bytes(b"\x1bOB"), KeyEvent::Down);
        assert_eq!(parse_key_bytes(b"j"), KeyEvent::Down);
        assert_eq!(parse_key_bytes(b"J"), KeyEvent::Down);

        assert_eq!(parse_key_bytes(b"\x1b[D"), KeyEvent::Left);
        assert_eq!(parse_key_bytes(b"\x1b[C"), KeyEvent::Right);

        assert_eq!(parse_key_bytes(b"\r"), KeyEvent::Enter);
        assert_eq!(parse_key_bytes(b"\n"), KeyEvent::Enter);
        assert_eq!(parse_key_bytes(b"\x1b"), KeyEvent::Back);
        assert_eq!(parse_key_bytes(b"q"), KeyEvent::Cancel);
        assert_eq!(parse_key_bytes(b"Q"), KeyEvent::Cancel);
        assert_eq!(parse_key_bytes(b"\x03"), KeyEvent::Cancel);
        assert_eq!(parse_key_bytes(b"c"), KeyEvent::Char('c'));
        assert_eq!(parse_key_bytes(b""), KeyEvent::Other);
    }

    #[test]
    fn herdr_template_parsing_inference_and_launch_command_builder() {
        let sample = r#"{"templates":[
            {"command":"claude-gateway","description":"Claude (Gateway)","name":"claude-gateway"},
            {"command":"codex-gateway --no-daemon","description":"Codex (Gateway)","name":"codex-gateway"},
            {"command":"opencode-direct","description":"OpenCode Direct","name":"opencode-direct"},
            {"command":"ignored","description":"Empty name","name":"   "}
        ]}"#;

        let parsed = parse_herdr_templates_json(sample);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[0].name, "claude-gateway");
        assert_eq!(parsed[0].description, "Claude (Gateway)");
        assert_eq!(parsed[1].command, "codex-gateway --no-daemon");
        assert_eq!(parsed[2].name, "opencode-direct");

        // Invalid / malformed payloads never panic.
        assert!(parse_herdr_templates_json("").is_empty());
        assert!(parse_herdr_templates_json("{bad json").is_empty());
        assert!(parse_herdr_templates_json(r#"{"templates": "oops"}"#).is_empty());

        // Harness inference.
        assert_eq!(
            infer_harness_from_herdr_template("claude-gateway", "claude-gateway"),
            Some(LaunchableHarness::Claude)
        );
        assert_eq!(
            infer_harness_from_herdr_template("codex-qwen", "codex-qwen --no-daemon"),
            Some(LaunchableHarness::Codex)
        );
        assert_eq!(
            infer_harness_from_herdr_template("opencode-direct", "opencode-direct"),
            Some(LaunchableHarness::Opencode)
        );
        assert_eq!(
            infer_harness_from_herdr_template("agy-dev", "agy --workspace ."),
            Some(LaunchableHarness::Antigravity)
        );
        assert_eq!(
            infer_harness_from_herdr_template("custom-shell", "bash"),
            None
        );

        // Launch command builder (`hc run --bg --outlive-parent --label app=hyphae --json`).
        let hc_path = Path::new("/usr/local/bin/hc");
        let prompt = "Load and follow hyp-setup";
        let cmd = build_herdr_template_launch_command(hc_path, "claude-gateway", prompt);
        assert_eq!(cmd.get_program(), OsStr::new("/usr/local/bin/hc"));
        let args: Vec<&OsStr> = cmd.get_args().collect();
        assert_eq!(
            args,
            vec![
                OsStr::new("run"),
                OsStr::new("--bg"),
                OsStr::new("--outlive-parent"),
                OsStr::new("--label"),
                OsStr::new("app=hyphae"),
                OsStr::new("--json"),
                OsStr::new("claude-gateway"),
                OsStr::new(prompt),
            ]
        );

        // Attach command builder (`hc attach <address>`).
        let attach_cmd = build_herdr_attach_command(hc_path, "t4h");
        assert_eq!(attach_cmd.get_program(), OsStr::new("/usr/local/bin/hc"));
        let attach_args: Vec<&OsStr> = attach_cmd.get_args().collect();
        assert_eq!(attach_args, vec![OsStr::new("attach"), OsStr::new("t4h")]);

        // Herdr desktop app tab-promotion builder (`herdr-app do terminal.keep ...`).
        let app_path = Path::new("/usr/local/bin/herdr-app");
        let keep_cmd = build_herdr_app_keep_command(app_path, "t4h");
        assert_eq!(
            keep_cmd.get_program(),
            OsStr::new("/usr/local/bin/herdr-app")
        );
        let keep_args: Vec<&OsStr> = keep_cmd.get_args().collect();
        assert_eq!(
            keep_args,
            vec![
                OsStr::new("do"),
                OsStr::new("terminal.keep"),
                OsStr::new("--terminal"),
                OsStr::new("t4h"),
                OsStr::new("--place"),
                OsStr::new("tab"),
            ]
        );
    }

    #[test]
    fn herdr_run_address_json_parser_handles_logs_and_rejects_flag_injection() {
        assert_eq!(
            parse_herdr_run_address_json(r#"{"address":"t4h","template":"claude-gateway"}"#),
            Some("t4h".to_string())
        );
        assert_eq!(
            parse_herdr_run_address_json(r#"{"address":"  t9x  "}"#),
            Some("t9x".to_string())
        );
        // Leading non-JSON log lines followed by single-line JSON.
        assert_eq!(
            parse_herdr_run_address_json(
                "[hc] starting daemon...\n[hc] ready\n{\"address\":\"t4h\"}\n"
            ),
            Some("t4h".to_string())
        );
        // Leading non-JSON log line followed by multi-line pretty JSON.
        assert_eq!(
            parse_herdr_run_address_json(
                "[hc] warning: slow start\n{\n  \"address\": \"t7b\"\n}\n"
            ),
            Some("t7b".to_string())
        );

        // Malformed, missing, empty, flag-injection, or whitespace-injected addresses MUST fail closed.
        assert_eq!(parse_herdr_run_address_json(""), None);
        assert_eq!(parse_herdr_run_address_json("{bad json"), None);
        assert_eq!(parse_herdr_run_address_json(r#"{"id":"t4h"}"#), None);
        assert_eq!(parse_herdr_run_address_json(r#"{"address":""}"#), None);
        assert_eq!(parse_herdr_run_address_json(r#"{"address":"   "}"#), None);
        assert_eq!(parse_herdr_run_address_json(r#"{"address":"-bad"}"#), None);
        assert_eq!(
            parse_herdr_run_address_json(r#"{"address":"--exec"}"#),
            None
        );
        assert_eq!(
            parse_herdr_run_address_json(r#"{"address":"t4h --bad"}"#),
            None
        );
        assert_eq!(
            parse_herdr_run_address_json("{\"address\":\"t4h\\nbad\"}"),
            None
        );
    }

    #[test]
    fn main_menu_only_lists_detected_harnesses_and_places_herdr_first() {
        let diagnostics = vec![
            HarnessDiagnostic {
                harness: "claude".to_string(),
                detected: true,
                configured: true,
                detail: String::new(),
                fix: None,
            },
            HarnessDiagnostic {
                harness: "codex".to_string(),
                detected: false,
                configured: false,
                detail: String::new(),
                fix: None,
            },
            HarnessDiagnostic {
                harness: "cursor".to_string(),
                detected: true,
                configured: false,
                detail: String::new(),
                fix: None,
            },
            HarnessDiagnostic {
                harness: "openclaw".to_string(),
                detected: true,
                configured: false,
                detail: String::new(),
                fix: None,
            },
            HarnessDiagnostic {
                harness: "t3".to_string(),
                detected: true,
                configured: false,
                detail: String::new(),
                fix: None,
            },
            HarnessDiagnostic {
                harness: "gemini".to_string(),
                detected: false,
                configured: false,
                detail: String::new(),
                fix: None,
            },
        ];
        let launchables = vec![(LaunchableHarness::Claude, PathBuf::from("/usr/bin/claude"))];
        let templates = vec![HerdrTemplate {
            name: "claude-gateway".to_string(),
            description: "Claude (Gateway)".to_string(),
            command: "claude-gateway".to_string(),
        }];

        let items = build_main_menu_items(
            &diagnostics,
            &launchables,
            Some(Path::new("/usr/local/bin/hc")),
            &templates,
            DetectedDesktopApps {
                claude_desktop: true,
                codex_desktop: true,
                opencode_desktop: false,
                cursor_ide: true,
            },
            None,
        );

        let labels: Vec<&str> = items.iter().map(|i| i.label.as_str()).collect();
        assert_eq!(
            labels,
            vec![
                "Herdr",
                "Claude Code",
                "Claude Desktop",
                "Codex Desktop",
                "Cursor (IDE)",
                "OpenClaw",
                "T3 Code",
                "Local CLI setup",
            ]
        );
        // Undetected harnesses (Codex CLI, Gemini, OpenCode, Antigravity) must NOT clutter the menu.
        assert!(!labels.contains(&"Codex"));
        assert!(!labels.contains(&"Gemini CLI"));

        // When Herdr has zero templates, Herdr must NOT appear in the menu.
        let without_herdr = build_main_menu_items(
            &diagnostics,
            &launchables,
            Some(Path::new("/usr/local/bin/hc")),
            &[],
            DetectedDesktopApps::default(),
            None,
        );
        assert!(without_herdr.iter().all(|i| i.label != "Herdr"));
    }

    #[test]
    fn main_menu_surfaces_herdr_templates_directly_when_inside_herdr_env() {
        assert_eq!(
            detect_herdr_terminal_from_values(Some(" t1b "), Some("t9z")),
            Some("t1b".to_string())
        );
        assert_eq!(
            detect_herdr_terminal_from_values(Some("   "), Some("t9z")),
            Some("t9z".to_string())
        );
        assert_eq!(detect_herdr_terminal_from_values(None, None), None);

        let launchables = vec![
            (LaunchableHarness::Claude, PathBuf::from("/usr/bin/claude")),
            (LaunchableHarness::Codex, PathBuf::from("/usr/bin/codex")),
        ];
        let templates = vec![
            HerdrTemplate {
                name: "claude-gateway".to_string(),
                description: "Claude (Gateway)".to_string(),
                command: "claude-gateway".to_string(),
            },
            HerdrTemplate {
                name: "codex-gateway".to_string(),
                description: "Codex (Gateway)".to_string(),
                command: "codex-gateway --no-daemon".to_string(),
            },
        ];

        // Inside Herdr (`Some("t1b")`): templates surfaced directly at the top with tag `"via herdr"`.
        let inside = build_main_menu_items_with_env(
            &[],
            &launchables,
            Some(Path::new("/usr/local/bin/hc")),
            &templates,
            DetectedDesktopApps::default(),
            None,
            Some("t1b"),
        );
        assert_eq!(inside[0].label, "Claude (Gateway)");
        assert_eq!(inside[0].tag, "via herdr");
        assert!(matches!(
            inside[0].action,
            MainMenuAction::LaunchHerdrTemplate { ref template, .. } if template.name == "claude-gateway"
        ));
        assert_eq!(inside[1].label, "Codex (Gateway)");
        assert_eq!(inside[1].tag, "via herdr");
        assert_eq!(inside[1].subtitle, "codex-gateway --no-daemon");
        assert!(matches!(
            inside[1].action,
            MainMenuAction::LaunchHerdrTemplate { ref template, .. } if template.name == "codex-gateway"
        ));
        assert_eq!(inside[2].label, "Claude Code");
        assert_eq!(inside[2].tag, "in terminal");
        assert_eq!(inside[3].label, "Codex");
        assert_eq!(inside[3].tag, "in terminal");
        assert!(
            inside
                .iter()
                .all(|i| !matches!(i.action, MainMenuAction::HerdrTemplates { .. }))
        );

        // Outside Herdr (`None`): templates stay cleanly grouped under single `"Herdr"` entry.
        let outside = build_main_menu_items_with_env(
            &[],
            &launchables,
            Some(Path::new("/usr/local/bin/hc")),
            &templates,
            DetectedDesktopApps::default(),
            None,
            None,
        );
        assert_eq!(outside[0].label, "Herdr");
        assert!(matches!(
            outside[0].action,
            MainMenuAction::HerdrTemplates { ref templates, .. } if templates.len() == 2
        ));
        assert_eq!(outside[1].label, "Claude Code");
    }

    #[test]
    fn viewport_windowing_bounds_frame_height_and_keeps_selected_visible() {
        let mut items = Vec::new();
        for idx in 1..=8 {
            items.push(MainMenuItem {
                label: format!("Template {idx:02}"),
                tag: "via herdr",
                subtitle: format!("tmpl-{idx:02}"),
                action: MainMenuAction::LaunchHerdrTemplate {
                    hc_bin: PathBuf::from("/usr/local/bin/hc"),
                    template: HerdrTemplate {
                        name: format!("tmpl-{idx:02}"),
                        description: format!("Template {idx:02}"),
                        command: "claude".to_string(),
                    },
                },
            });
        }
        for lh in [
            LaunchableHarness::Claude,
            LaunchableHarness::Codex,
            LaunchableHarness::Opencode,
            LaunchableHarness::Gemini,
        ] {
            items.push(MainMenuItem {
                label: lh.display_name().to_string(),
                tag: "in terminal",
                subtitle: lh.binary_name().to_string(),
                action: MainMenuAction::LaunchCli(lh),
            });
        }
        items.push(MainMenuItem {
            label: "Claude Desktop".to_string(),
            tag: "desktop app",
            subtitle: "open in Claude Desktop".to_string(),
            action: MainMenuAction::ManualGuide(ManualGuideHarness::ClaudeDesktop),
        });
        items.push(MainMenuItem {
            label: "Local CLI setup".to_string(),
            tag: "local cli",
            subtitle: "configure node, keys & harnesses here".to_string(),
            action: MainMenuAction::QuickLocalSetup,
        });
        assert_eq!(items.len(), 14);

        for selected in 0..items.len() {
            let lines = render_main_menu(
                &items,
                selected,
                Some("alice@workstation"),
                false,
                Some("t1b"),
                24,
                80,
                ColorMode::Plain,
                0,
            );
            assert!(
                lines.len() <= 24,
                "selected={selected}: frame overflowed 24 rows (got {})",
                lines.len()
            );
            let stripped: Vec<String> = lines.iter().map(|l| strip_ansi(l)).collect();
            for (row_idx, row) in stripped.iter().enumerate() {
                assert!(
                    row.chars().count() <= 80,
                    "selected={selected} row {row_idx} exceeded 80 cols: {row:?}"
                );
            }
            let joined = stripped.join("\n");
            assert!(
                joined.contains("Who should guide setup?"),
                "expected clean setup prompt in main menu:\n{joined}"
            );
            assert!(
                joined.contains(&format!("v{}", env!("CARGO_PKG_VERSION"))),
                "expected version directly under animated banner:\n{joined}"
            );
            assert!(
                !joined.contains("Herdr (t1b)") && !joined.contains("interactive onboarding"),
                "header must stay minimal without extra Herdr/onboarding banner lines:\n{joined}"
            );
            let expected_label = &items[selected].label;
            assert!(
                stripped
                    .iter()
                    .any(|row| row.contains('❯') && row.contains(expected_label.as_str())),
                "selected={selected} ('{expected_label}') must be highlighted and visible:\n{joined}"
            );
            let has_up_hint = stripped
                .iter()
                .any(|row| row.contains("↑ ") && row.contains(" more"));
            let has_down_hint = stripped
                .iter()
                .any(|row| row.contains("↓ ") && row.contains(" more"));
            if selected == 0 {
                assert!(has_down_hint, "missing ↓ hint at top:\n{joined}");
                assert!(!has_up_hint, "unexpected ↑ hint at top:\n{joined}");
            } else if selected == 7 {
                assert!(
                    has_up_hint && has_down_hint,
                    "expected both ↑ and ↓ hints in middle:\n{joined}"
                );
            } else if selected == items.len() - 1 {
                assert!(has_up_hint, "missing ↑ hint at bottom:\n{joined}");
                assert!(!has_down_hint, "unexpected ↓ hint at bottom:\n{joined}");
            }
        }

        // Narrow terminal left/right clamping check: header must NEVER overflow narrow width.
        let narrow = render_main_menu(
            &items,
            0,
            Some("alice@very-long-workstation-hostname"),
            true,
            Some("t1b"),
            18,
            34,
            ColorMode::Plain,
            0,
        );
        assert!(narrow.len() <= 18);
        for (row_idx, line) in narrow.iter().enumerate() {
            let plain = strip_ansi(line);
            assert!(
                plain.chars().count() <= 34,
                "narrow row {row_idx} exceeded 34 cols: {plain:?}"
            );
        }

        // Herdr template picker viewport scrolling check on 24 rows.
        let templates: Vec<HerdrTemplate> = (1..=12)
            .map(|i| HerdrTemplate {
                name: format!("tmpl-{i:02}"),
                description: format!("Herdr Agent {i:02}"),
                command: "claude".to_string(),
            })
            .collect();
        let herdr_mid = render_herdr_templates(&templates, 6, true, 24, 80, ColorMode::Plain, 0);
        assert!(herdr_mid.len() <= 24);
        let herdr_text = herdr_mid
            .iter()
            .map(|l| strip_ansi(l))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(herdr_text.contains("❯") && herdr_text.contains("Herdr Agent 07"));

        assert_ne!(
            build_banner_lines_at_tick(28, 64, 60, ColorMode::TrueColor, 0),
            build_banner_lines_at_tick(28, 64, 60, ColorMode::TrueColor, 6),
            "menu banner should pass its pulse tick to the renderer"
        );
    }

    #[test]
    fn desktop_mcp_config_claude_desktop_merges_preserves_and_fails_closed() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path();
        let cli_bin = "/usr/local/bin/hyp";

        // 1. Missing file: plan reports not yet configured.
        let plan0 = inspect_desktop_mcp_plan(ManualGuideHarness::ClaudeDesktop, home, cli_bin)
            .expect("claude desktop plan");
        assert!(!plan0.already_configured);
        assert_eq!(plan0.config_path, claude_desktop_config_path(home));
        assert!(
            plan0
                .preview_lines
                .iter()
                .any(|l| l.contains("mcpServers") && l.contains("preserves existing"))
        );

        // 2. Pre-existing config with another MCP server + top-level user keys.
        fs::create_dir_all(plan0.config_path.parent().unwrap()).unwrap();
        fs::write(
            &plan0.config_path,
            r#"{
  "globalShortcut": "Cmd+Space",
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
    }
  }
}
"#,
        )
        .unwrap();

        let applied = apply_desktop_mcp_config(ManualGuideHarness::ClaudeDesktop, home, cli_bin)
            .expect("apply claude desktop mcp");
        assert!(!applied.created);
        assert!(!applied.already_configured);
        assert_eq!(applied.config_path, plan0.config_path);

        let updated: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&plan0.config_path).unwrap()).unwrap();
        assert_eq!(updated["globalShortcut"], "Cmd+Space");
        assert_eq!(updated["mcpServers"]["filesystem"]["command"], "npx");
        assert_eq!(updated["mcpServers"]["hyphae"]["command"], cli_bin);
        assert_eq!(
            updated["mcpServers"]["hyphae"]["args"],
            json!(["mcp", "--ephemeral"])
        );

        // 3. Second inspection detects `already_configured == true`.
        let plan1 = inspect_desktop_mcp_plan(ManualGuideHarness::ClaudeDesktop, home, cli_bin)
            .expect("claude desktop plan 2");
        assert!(plan1.already_configured);

        // 4. Malformed JSON MUST fail closed without clobbering user's file!
        let corrupt = "{ \"mcpServers\": BROKEN_JSON";
        fs::write(&plan0.config_path, corrupt).unwrap();
        let err = apply_desktop_mcp_config(ManualGuideHarness::ClaudeDesktop, home, cli_bin)
            .expect_err("malformed JSON must fail closed");
        assert!(err.contains("malformed JSON"), "unexpected error: {err}");
        assert_eq!(
            fs::read_to_string(&plan0.config_path).unwrap(),
            corrupt,
            "corrupt user file must remain untouched"
        );

        // 5. Non-object `mcpServers` field also fails closed without clobbering.
        let bad_field = r#"{ "mcpServers": ["not-an-object"] }"#;
        fs::write(&plan0.config_path, bad_field).unwrap();
        let err2 = apply_desktop_mcp_config(ManualGuideHarness::ClaudeDesktop, home, cli_bin)
            .expect_err("non-object mcpServers must fail closed");
        assert!(err2.contains("mcpServers"), "unexpected error: {err2}");
        assert_eq!(fs::read_to_string(&plan0.config_path).unwrap(), bad_field);
    }

    #[test]
    fn desktop_mcp_config_codex_desktop_preserves_toml_and_is_idempotent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path();
        let cli_bin = "/opt/homebrew/bin/hyp";

        let plan0 = inspect_desktop_mcp_plan(ManualGuideHarness::CodexDesktop, home, cli_bin)
            .expect("codex desktop plan");
        assert!(!plan0.already_configured);
        assert_eq!(plan0.config_path, codex_mcp_config_path(home));
        assert!(
            plan0
                .preview_lines
                .iter()
                .any(|l| l.contains("[mcp_servers.hyphae]"))
        );

        // Commented-out header must NOT falsely report already_configured.
        fs::create_dir_all(plan0.config_path.parent().unwrap()).unwrap();
        let initial_toml = "model = \"gpt-5\"\n# [mcp_servers.hyphae]\n\n[mcp_servers.context7]\ncommand = \"npx\"\nargs = [\"-y\", \"@upstash/context7-mcp\"]\n";
        fs::write(&plan0.config_path, initial_toml).unwrap();
        assert!(
            !inspect_desktop_mcp_plan(ManualGuideHarness::CodexDesktop, home, cli_bin)
                .unwrap()
                .already_configured
        );

        let res1 = apply_desktop_mcp_config(ManualGuideHarness::CodexDesktop, home, cli_bin)
            .expect("apply codex mcp");
        assert!(!res1.created);
        assert!(!res1.already_configured);

        let written = fs::read_to_string(&plan0.config_path)
            .unwrap()
            .replace("\r\n", "\n");
        assert!(written.contains("model = \"gpt-5\""));
        assert!(written.contains("[mcp_servers.context7]"));
        assert!(written.contains("# >>> hyphae >>>"));
        assert!(written.contains("[mcp_servers.hyphae]"));
        assert!(written.contains("command = \"/opt/homebrew/bin/hyp\""));
        assert!(written.contains("args = [\"mcp\"]"));
        assert!(written.contains("env_vars = [\"CODEX_HOME\", \"HYPHAE_SOCKET\"]"));
        assert!(written.contains("# <<< hyphae <<<"));

        // Second inspection detects `already_configured == true`, second apply stays idempotent.
        let plan1 = inspect_desktop_mcp_plan(ManualGuideHarness::CodexDesktop, home, cli_bin)
            .expect("codex desktop plan 2");
        assert!(plan1.already_configured);
        let res2 = apply_desktop_mcp_config(ManualGuideHarness::CodexDesktop, home, cli_bin)
            .expect("apply codex mcp 2");
        assert!(res2.already_configured);
        let written2 = fs::read_to_string(&plan0.config_path)
            .unwrap()
            .replace("\r\n", "\n");
        assert_eq!(
            written2.matches("[mcp_servers.hyphae]").count(),
            2, // 1 commented line + 1 active managed header (no duplicate active sections!)
            "unexpected duplicate headers:\n{written2}"
        );
        assert_eq!(
            written2
                .lines()
                .filter(|l| l.trim() == "[mcp_servers.hyphae]")
                .count(),
            1
        );

        // An old unmarked table keeps its socket and neighboring settings.
        let unmarked = r#"model = "o3"

[mcp_servers.hyphae]
command = "old-hyp"
args = [
    'mcp',
    '/tmp/custom connector.sock',
]
startup_timeout_sec = 25 # Keep this.
env_vars = ['CUSTOM']

[mcp_servers.other]
command = "other"
"#;
        fs::write(&plan0.config_path, unmarked).unwrap();
        assert!(
            !inspect_desktop_mcp_plan(ManualGuideHarness::CodexDesktop, home, cli_bin)
                .unwrap()
                .already_configured
        );
        apply_desktop_mcp_config(ManualGuideHarness::CodexDesktop, home, cli_bin).unwrap();
        let replaced = fs::read_to_string(&plan0.config_path)
            .unwrap()
            .replace("\r\n", "\n");
        assert!(replaced.contains("model = \"o3\""));
        assert!(replaced.contains("[mcp_servers.other]"));
        assert!(replaced.contains("command = \"/opt/homebrew/bin/hyp\""));
        assert!(!replaced.contains("old-hyp"));
        let parsed = replaced.parse::<toml_edit::DocumentMut>().unwrap();
        let args: Vec<_> = parsed["mcp_servers"]["hyphae"]["args"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert_eq!(args, ["mcp", "/tmp/custom connector.sock"]);
        assert!(replaced.contains("startup_timeout_sec = 25 # Keep this."));
        assert!(replaced.contains("env_vars = [\"CUSTOM\", \"CODEX_HOME\", \"HYPHAE_SOCKET\"]"));
        assert_eq!(
            replaced
                .lines()
                .filter(|l| l.trim() == "[mcp_servers.hyphae]")
                .count(),
            1
        );
    }

    #[test]
    fn codex_cli_and_desktop_setup_share_one_idempotent_config_with_custom_socket() {
        use clap::Parser;
        use std::fs::{FileTimes, OpenOptions};
        use std::time::{Duration, UNIX_EPOCH};

        let tmp = tempfile::tempdir().unwrap();
        let bin = "/opt/hyphae/bin/hyp";
        let socket = "/tmp/Hyphae Dev/connector.sock";
        let desktop = ManualGuideHarness::CodexDesktop;
        let original = concat!(
            "# Keep the model and neighboring MCP server.\n",
            "model = 'o3'\n\n",
            "[mcp_servers.other]\n",
            "command = 'other'\n"
        );
        let mut configs = Vec::new();
        for cli_first in [true, false] {
            let home = tmp.path().join(if cli_first {
                "cli-first"
            } else {
                "desktop-first"
            });
            let path = codex_mcp_config_path(&home);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(&path, original).unwrap();

            let run_cli_setup = |socket: Option<&str>| {
                let state = home.join("state");
                let mut argv = vec![
                    "hyp",
                    "setup",
                    "--harness",
                    "codex",
                    "--home",
                    home.to_str().unwrap(),
                    "--state-dir",
                    state.to_str().unwrap(),
                    "--bin",
                    bin,
                    "--no-skills",
                    "--no-commands",
                    "--json",
                ];
                if let Some(socket) = socket {
                    argv.extend(["--socket", socket]);
                }
                let crate::Commands::Setup(args) =
                    crate::Cli::try_parse_from(argv).unwrap().command
                else {
                    panic!("expected setup command");
                };
                assert_eq!(
                    crate::finish_command(crate::setup::run_setup(args)),
                    ExitCode::SUCCESS
                );
            };

            if !cli_first {
                let applied = apply_desktop_mcp_config(desktop, &home, bin).unwrap();
                assert!(!applied.already_configured);
            }
            run_cli_setup(Some(socket));

            let plan = inspect_desktop_mcp_plan(desktop, &home, bin).unwrap();
            assert!(plan.already_configured);
            assert!(plan.preview_lines.iter().any(|line| line.contains(socket)));

            let stamp = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
            OpenOptions::new()
                .write(true)
                .open(&path)
                .unwrap()
                .set_times(FileTimes::new().set_modified(stamp))
                .unwrap();
            let applied = apply_desktop_mcp_config(desktop, &home, bin).unwrap();
            assert!(applied.already_configured);
            run_cli_setup(None);
            assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), stamp);

            let content = fs::read_to_string(&path).unwrap();
            assert!(content.starts_with(original));
            let parsed = content.parse::<toml_edit::DocumentMut>().unwrap();
            let args = parsed["mcp_servers"]["hyphae"]["args"].as_array().unwrap();
            assert_eq!(
                args.iter()
                    .map(|value| value.as_str().unwrap())
                    .collect::<Vec<_>>(),
                ["mcp", socket]
            );
            assert!(
                fs::read_to_string(path.with_file_name("hooks.json"))
                    .unwrap()
                    .contains(socket)
            );
            configs.push(content);
        }
        assert_eq!(configs[0], configs[1]);
    }

    #[test]
    fn manual_guide_deeplinks_rfc3986_and_opencode_desktop_detection() {
        let prompt = "Set up Hyphae? yes & check /home/a b=1#top";
        let encoded = percent_encode_uri_component(prompt);
        assert_eq!(
            encoded,
            "Set%20up%20Hyphae%3F%20yes%20%26%20check%20%2Fhome%2Fa%20b%3D1%23top"
        );

        let cwd = Path::new("/Users/alice/my project?v=1&ok=2");

        // 1. Claude Desktop
        assert_eq!(
            build_manual_guide_deeplink(
                ManualGuideHarness::ClaudeDesktop,
                prompt,
                Some(cwd),
                None,
                None
            ),
            Some(format!("claude://claude.ai/new?q={encoded}"))
        );

        // 2. Codex Desktop
        assert_eq!(
            build_manual_guide_deeplink(
                ManualGuideHarness::CodexDesktop,
                prompt,
                Some(cwd),
                None,
                None
            ),
            Some(format!("codex://threads/new?prompt={encoded}"))
        );

        // 3. OpenCode Desktop (with cwd, without cwd, with OPENCODE_SERVER_URL, and unsafe scheme rejected)
        assert_eq!(
            build_manual_guide_deeplink(
                ManualGuideHarness::OpenCodeDesktop,
                prompt,
                Some(cwd),
                Some("http://127.0.0.1:4096"),
                None,
            ),
            Some("http://127.0.0.1:4096".to_string())
        );
        let expected_dir = percent_encode_uri_component(&cwd.to_string_lossy());
        assert_eq!(
            build_manual_guide_deeplink(
                ManualGuideHarness::OpenCodeDesktop,
                prompt,
                Some(cwd),
                Some("javascript:alert(1)"),
                None,
            ),
            Some(format!(
                "opencode://new-session?directory={expected_dir}&prompt={encoded}"
            ))
        );
        assert_eq!(
            build_manual_guide_deeplink(
                ManualGuideHarness::OpenCodeDesktop,
                prompt,
                None,
                None,
                None,
            ),
            Some(format!("opencode://new-session?prompt={encoded}"))
        );

        // 4. T3 Code
        assert_eq!(
            build_manual_guide_deeplink(
                ManualGuideHarness::T3,
                prompt,
                Some(cwd),
                None,
                Some("http://127.0.0.1:3773"),
            ),
            Some("http://127.0.0.1:3773".to_string())
        );
        assert_eq!(
            build_manual_guide_deeplink(ManualGuideHarness::T3, prompt, Some(cwd), None, None),
            Some("t3code://".to_string())
        );

        // 5. Cursor IDE
        assert_eq!(
            build_manual_guide_deeplink(
                ManualGuideHarness::CursorIde,
                prompt,
                Some(cwd),
                None,
                None
            ),
            Some("cursor://file/Users/alice/my%20project%3Fv%3D1%26ok%3D2".to_string())
        );
        assert_eq!(
            build_manual_guide_deeplink(ManualGuideHarness::CursorIde, prompt, None, None, None),
            Some("cursor://".to_string())
        );

        // 6. OpenClaw -> None (clipboard copy only)
        assert_eq!(
            build_manual_guide_deeplink(
                ManualGuideHarness::Openclaw,
                prompt,
                Some(cwd),
                None,
                None
            ),
            None
        );

        // OpenCodeDesktop detection (macOS Applications, Windows LOCALAPPDATA, OPENCODE_SERVER_URL)
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path().join("home");
        let apps = tmp.path().join("Applications");
        let local_appdata = tmp.path().join("LocalAppData");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&apps).unwrap();
        fs::create_dir_all(&local_appdata).unwrap();

        assert!(!detect_desktop_apps_in(&home, Some(&apps), None).opencode_desktop);
        assert!(
            detect_desktop_apps_in_with_env(
                &home,
                Some(&apps),
                None,
                Some(&local_appdata),
                Some("http://127.0.0.1:4096")
            )
            .opencode_desktop
        );
        fs::create_dir_all(apps.join("OpenCode.app")).unwrap();
        assert!(detect_desktop_apps_in(&home, Some(&apps), None).opencode_desktop);

        let menu = detect_candidates_in(&home, None, Some(OsStr::new("")), Some(&apps), None, None);
        assert!(menu.iter().any(|m| {
            m.label == "OpenCode Desktop"
                && matches!(
                    m.action,
                    MainMenuAction::ManualGuide(ManualGuideHarness::OpenCodeDesktop)
                )
        }));

        // Confirm & ManualGuide renderers fit cleanly inside 24 rows and display key guidance.
        let plan = inspect_desktop_mcp_plan(
            ManualGuideHarness::ClaudeDesktop,
            &home,
            "/usr/local/bin/hyp",
        )
        .unwrap();
        let confirm_lines = render_desktop_mcp_confirm(
            ManualGuideHarness::ClaudeDesktop,
            &home,
            &plan,
            &ManualGuideHarness::ClaudeDesktop.primary_skill_path(&home),
            0,
            None,
            true,
            24,
            80,
            ColorMode::Plain,
        );
        assert!(confirm_lines.len() <= 24);
        let confirm_text = confirm_lines
            .iter()
            .map(|l| strip_ansi(l))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(confirm_text.contains("Existing servers & settings are preserved."));
        assert!(confirm_text.contains("Apply MCP config & continue"));
        assert!(confirm_text.contains("Skip config write"));

        let guide_lines = render_manual_guide(
            ManualGuideHarness::ClaudeDesktop,
            &home,
            "/opt/hyp",
            &ManualGuideHarness::ClaudeDesktop.primary_skill_path(&home),
            &[],
            "Set up Hyphae on this machine using the hyp-setup skill",
            &DesktopMcpStatus::Applied(plan.config_path.clone()),
            Some("claude://claude.ai/new?q=test"),
            0,
            None,
            true,
            24,
            80,
            ColorMode::Plain,
        );
        assert!(guide_lines.len() <= 24);
        let guide_text = guide_lines
            .iter()
            .map(|l| strip_ansi(l))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(guide_text.contains("✓ Updated"));
        assert!(guide_text.contains("Restart Claude Desktop"));
        assert!(guide_text.contains("[o] Open in Claude Desktop"));
    }

    #[test]
    fn desktop_and_ide_detection_is_hermetic_and_handles_all_platforms() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path().join("home");
        let apps = tmp.path().join("Applications");
        let appdata = tmp.path().join("AppData");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&apps).unwrap();
        std::fs::create_dir_all(&appdata).unwrap();

        // Empty temp dirs must detect ZERO Desktop/IDE apps (never leaking host /Applications!).
        let empty = detect_desktop_apps_in(&home, Some(&apps), Some(&appdata));
        assert_eq!(empty, DetectedDesktopApps::default());
        let empty_menu = detect_candidates_in(
            &home,
            None,
            Some(OsStr::new("")),
            Some(&apps),
            Some(&appdata),
            None,
        );
        assert_eq!(empty_menu.len(), 1);
        assert_eq!(empty_menu[0].label, "Local CLI setup");

        // Create fake macOS Claude.app, Codex.app, and Cursor.app under isolated temp apps_dir.
        std::fs::create_dir_all(apps.join("Claude.app")).unwrap();
        std::fs::create_dir_all(apps.join("Codex.app")).unwrap();
        std::fs::create_dir_all(apps.join("Cursor.app")).unwrap();

        let detected = detect_desktop_apps_in(&home, Some(&apps), Some(&appdata));
        assert!(detected.claude_desktop);
        assert!(detected.codex_desktop);
        assert!(detected.cursor_ide);

        let menu = detect_candidates_in(
            &home,
            None,
            Some(OsStr::new("")),
            Some(&apps),
            Some(&appdata),
            None,
        );
        let labels: Vec<&str> = menu.iter().map(|m| m.label.as_str()).collect();
        assert_eq!(
            labels,
            vec![
                "Claude Desktop",
                "Codex Desktop",
                "Cursor (IDE)",
                "Local CLI setup",
            ]
        );

        // Also verify Windows `%APPDATA%\Claude` and Linux `~/.config/Claude` detection paths.
        let tmp_win = tempfile::tempdir().expect("tempdir");
        let home_win = tmp_win.path().join("home");
        let appdata_win = tmp_win.path().join("Roaming");
        std::fs::create_dir_all(&home_win).unwrap();
        std::fs::create_dir_all(appdata_win.join("Claude")).unwrap();
        assert!(detect_desktop_apps_in(&home_win, None, Some(&appdata_win)).claude_desktop);

        let tmp_lin = tempfile::tempdir().expect("tempdir");
        let home_lin = tmp_lin.path().join("home");
        std::fs::create_dir_all(home_lin.join(".config").join("Claude")).unwrap();
        assert!(detect_desktop_apps_in(&home_lin, None, None).claude_desktop);
    }

    #[test]
    fn launch_command_builders_match_all_six_verified_clis() {
        let prompt = "Load and follow hyp-setup";

        let claude = LaunchableHarness::Claude.build_launch_spec(prompt);
        assert_eq!(claude.program, "claude");
        assert_eq!(claude.args, vec![prompt]);

        let codex = LaunchableHarness::Codex.build_launch_spec(prompt);
        assert_eq!(codex.program, "codex");
        assert_eq!(codex.args, vec![prompt]);

        let agy = LaunchableHarness::Antigravity.build_launch_spec(prompt);
        assert_eq!(agy.program, "agy");
        assert_eq!(agy.args, vec!["--prompt-interactive", prompt]);

        let opencode = LaunchableHarness::Opencode.build_launch_spec(prompt);
        assert_eq!(opencode.program, "opencode");
        assert_eq!(opencode.args, vec!["--prompt", prompt]);

        let cursor = LaunchableHarness::Cursor.build_launch_spec(prompt);
        assert_eq!(cursor.program, "cursor-agent");
        assert_eq!(cursor.args, vec![prompt]);

        let gemini = LaunchableHarness::Gemini.build_launch_spec(prompt);
        assert_eq!(gemini.program, "gemini");
        assert_eq!(gemini.args, vec!["-i", prompt]);
    }

    #[test]
    fn color_mode_detection_respects_no_color_and_apple_terminal() {
        assert_eq!(
            detect_color_mode_from_env(Some("1"), None, Some("truecolor"), None, None, None, true),
            ColorMode::Plain
        );
        assert_eq!(
            detect_color_mode_from_env(
                None,
                None,
                None,
                Some("Apple_Terminal"),
                Some("xterm-256color"),
                None,
                true
            ),
            ColorMode::Ansi256
        );
        assert_eq!(
            detect_color_mode_from_env(
                None,
                None,
                None,
                Some("WezTerm"),
                Some("xterm-256color"),
                None,
                true
            ),
            ColorMode::TrueColor
        );
        assert_eq!(
            detect_color_mode_from_env(None, None, Some("24bit"), None, None, None, false),
            ColorMode::TrueColor
        );
        assert_eq!(
            detect_color_mode_from_env(None, None, None, None, Some("dumb"), None, true),
            ColorMode::Plain
        );
    }

    #[test]
    fn embedded_skill_matches_frontmatter_and_security_invariants() {
        let normalized = HYPHAE_SETUP_SKILL_MD.replace("\r\n", "\n");
        assert!(normalized.starts_with("---\nname: hyp-setup\n"));
        assert!(!HYPHAE_SETUP_SKILL_MD.contains("hyp share"));
        assert!(!HYPHAE_SETUP_SKILL_MD.contains("npm install"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("hyp pair ssh"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("hyp connect"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("ssh://"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("hyp secret set"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("--web"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("hyp gate propose"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("hyp gate apply"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("Herdr"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("Codex Queue"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("Claude Code channels"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("T3 Code"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("OpenClaw"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("--no-skills"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("--no-commands"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("--statusline"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("--restore-statusline"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("--interactive"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("hyp uninstall"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("pill.js"));
    }

    #[test]
    fn setup_toggle_defaults_respect_detected_harnesses_and_herdr_app_dir() {
        // 1. Detected claude + codex, NO herdr-app -> herdr mod unchecked.
        let s1 =
            SetupToggleState::from_detection(&[HarnessKind::Claude, HarnessKind::Codex], false);
        assert!(s1.is_harness_selected(HarnessKind::Claude));
        assert!(s1.is_harness_selected(HarnessKind::Codex));
        assert!(!s1.is_harness_selected(HarnessKind::Herdr));
        assert!(!s1.is_harness_selected(HarnessKind::Cursor));
        assert!(s1.install_skills);
        assert!(s1.install_statusline);
        assert!(s1.install_claude_commands);
        assert!(!s1.install_herdr_mod);

        // 2. herdr-app exists, but Herdr harness NOT detected -> herdr mod stays unchecked.
        let s2 = SetupToggleState::from_detection(&[HarnessKind::Claude], true);
        assert!(!s2.install_herdr_mod);

        // 3. BOTH Herdr detected AND ~/.config/herdr-app exists -> herdr mod pre-checked!
        let s3 = SetupToggleState::from_detection(&[HarnessKind::Claude, HarnessKind::Herdr], true);
        assert!(s3.is_harness_selected(HarnessKind::Herdr));
        assert!(s3.install_herdr_mod);

        // 4. Hermetic from_home detection reads temp dir without touching host config.
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path().join("home");
        fs::create_dir_all(home.join(".claude")).unwrap();
        fs::create_dir_all(home.join(".config/herdr")).unwrap();
        fs::create_dir_all(home.join(".config/herdr-app")).unwrap();

        let from_fs = SetupToggleState::from_home(&home, true);
        assert_eq!(
            from_fs.detected_harnesses,
            vec![HarnessKind::Claude, HarnessKind::Herdr]
        );
        assert!(from_fs.install_herdr_mod);
        assert_eq!(
            from_fs.to_selection(),
            SetupSelection {
                harnesses: vec![HarnessKind::Claude, HarnessKind::Herdr],
                install_skills: true,
                install_statusline: true,
                install_claude_commands: true,
                install_herdr_mod: true,
                openclaw_delivery: OpenClawDeliveryMode::Gateway,
                openclaw_prompt_injection: false,
            }
        );
    }

    #[test]
    fn setup_toggle_keys_toggle_items_cycle_all_preview_and_cancel_cleanly() {
        let mut state = SetupToggleState::from_detection(&[HarnessKind::Claude], false);
        assert_eq!(state.cursor, 0);

        // Move down to Claude (index 1 in HarnessKind::ALL) and uncheck it with Space.
        assert_eq!(
            handle_setup_toggle_key(&mut state, KeyEvent::Down, true),
            SetupToggleAction::Continue
        );
        assert_eq!(state.cursor, 1);
        assert!(state.is_harness_selected(HarnessKind::Claude));
        handle_setup_toggle_key(&mut state, KeyEvent::Char(' '), true);
        assert!(!state.is_harness_selected(HarnessKind::Claude));

        // Toggle back on with Space.
        handle_setup_toggle_key(&mut state, KeyEvent::Char(' '), true);
        assert!(state.is_harness_selected(HarnessKind::Claude));

        // Press `a`: matches_detected (Claude only) -> all 9 -> none -> back to detected (Claude only).
        handle_setup_toggle_key(&mut state, KeyEvent::Char('a'), true);
        assert_eq!(state.selected_harness_count(), 9);
        handle_setup_toggle_key(&mut state, KeyEvent::Char('a'), true);
        assert_eq!(state.selected_harness_count(), 0);
        handle_setup_toggle_key(&mut state, KeyEvent::Char('a'), true);
        assert_eq!(state.selected_harness_count(), 1);
        assert!(state.is_harness_selected(HarnessKind::Claude));

        // Jump up from cursor 1 -> 0 -> wraps to 12 (Native Herdr mod), then toggle components.
        handle_setup_toggle_key(&mut state, KeyEvent::Up, true);
        assert_eq!(state.cursor, 0);
        handle_setup_toggle_key(&mut state, KeyEvent::Up, true);
        assert_eq!(state.cursor, 12);
        assert!(!state.install_herdr_mod);
        handle_setup_toggle_key(&mut state, KeyEvent::Char(' '), true);
        assert!(state.install_herdr_mod);

        // Toggle Runtime skills (index 9) off.
        state.cursor = 9;
        handle_setup_toggle_key(&mut state, KeyEvent::Char(' '), true);
        assert!(!state.install_skills);

        // Toggle dry-run preview on & off with `d`.
        assert!(!state.show_dry_run_preview);
        handle_setup_toggle_key(&mut state, KeyEvent::Char('d'), true);
        assert!(state.show_dry_run_preview);
        handle_setup_toggle_key(&mut state, KeyEvent::Char('D'), true);
        assert!(!state.show_dry_run_preview);

        // Esc & b return Back when allow_back=true, and Cancel when allow_back=false.
        assert_eq!(
            handle_setup_toggle_key(&mut state, KeyEvent::Back, true),
            SetupToggleAction::Back
        );
        assert_eq!(
            handle_setup_toggle_key(&mut state, KeyEvent::Char('b'), true),
            SetupToggleAction::Back
        );
        assert_eq!(
            handle_setup_toggle_key(&mut state, KeyEvent::Back, false),
            SetupToggleAction::Cancel
        );
        assert_eq!(
            handle_setup_toggle_key(&mut state, KeyEvent::Char('b'), false),
            SetupToggleAction::Cancel
        );
        assert_eq!(
            handle_setup_toggle_key(&mut state, KeyEvent::Cancel, true),
            SetupToggleAction::Cancel
        );

        // Enter applies exact checked selection.
        assert_eq!(
            handle_setup_toggle_key(&mut state, KeyEvent::Enter, true),
            SetupToggleAction::Apply(SetupSelection {
                harnesses: vec![HarnessKind::Claude],
                install_skills: false,
                install_statusline: true,
                install_claude_commands: true,
                install_herdr_mod: true,
                openclaw_delivery: OpenClawDeliveryMode::Gateway,
                openclaw_prompt_injection: false,
            })
        );
    }

    #[test]
    fn render_setup_toggle_screen_fits_narrow_tiny_and_wide_viewports_with_ansi_parity() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path().join("home");
        let mut state = SetupToggleState::from_detection(
            &[
                HarnessKind::Claude,
                HarnessKind::Antigravity,
                HarnessKind::Herdr,
            ],
            true,
        );
        state.cursor = 1; // Claude Code

        for (rows, cols) in [(24usize, 80usize), (18, 60), (40, 120)] {
            for preview in [false, true] {
                state.show_dry_run_preview = preview;
                let plain = render_setup_toggle_screen(
                    &state,
                    &home,
                    true,
                    true,
                    rows,
                    cols,
                    ColorMode::Plain,
                    0,
                );
                let ansi256 = render_setup_toggle_screen(
                    &state,
                    &home,
                    true,
                    true,
                    rows,
                    cols,
                    ColorMode::Ansi256,
                    0,
                );
                let tc = render_setup_toggle_screen(
                    &state,
                    &home,
                    true,
                    true,
                    rows,
                    cols,
                    ColorMode::TrueColor,
                    0,
                );

                assert!(
                    plain.len() <= rows,
                    "overflowed {rows} rows (preview={preview}): got {}",
                    plain.len()
                );
                assert_eq!(plain.len(), ansi256.len());
                assert_eq!(plain.len(), tc.len());

                for (idx, ((p, a), t)) in
                    plain.iter().zip(ansi256.iter()).zip(tc.iter()).enumerate()
                {
                    let sp = strip_ansi(p);
                    let sa = strip_ansi(a);
                    let st = strip_ansi(t);
                    assert_eq!(
                        sp, sa,
                        "Plain vs Ansi256 mismatch at row {idx} ({cols}x{rows}, preview={preview})"
                    );
                    assert_eq!(
                        sp, st,
                        "Plain vs TrueColor mismatch at row {idx} ({cols}x{rows}, preview={preview})"
                    );
                    assert!(
                        sp.chars().count() <= cols,
                        "row {idx} overflowed {cols} cols (preview={preview}): len={} text={sp:?}",
                        sp.chars().count()
                    );
                }

                let text = plain
                    .iter()
                    .map(|l| strip_ansi(l))
                    .collect::<Vec<_>>()
                    .join("\n");
                if !preview && rows >= 24 {
                    assert!(text.contains("Harnesses"));
                    assert!(text.contains("Components & UI Plugins"));
                    assert!(text.contains("[x] Claude Code"));
                    assert!(text.contains("(detected)"));
                    assert!(text.contains("[ ] Codex"));
                    assert!(text.contains("[x] Runtime skills"));
                    assert!(text.contains("[x] Live statusLine"));
                    assert!(text.contains("[x] Claude slash commands"));
                    assert!(text.contains("[x] Native Herdr mod"));
                }
                if preview {
                    assert!(
                        text.contains("Dry-Run Preview"),
                        "expected Dry-Run Preview box at {cols}x{rows}:\n{text}"
                    );
                }
            }
        }
    }

    #[test]
    fn setup_toggle_text_fallback_handles_multi_toggles_preview_back_and_apply() {
        let mut state = SetupToggleState::from_detection(&[HarnessKind::Claude], false);
        assert_eq!(
            apply_setup_toggle_text_input(&mut state, "2,10,11", true).unwrap(),
            SetupToggleAction::Continue
        );
        // 2 -> index 1 (Claude toggled off), 10 -> index 9 (skills off), 11 -> index 10 (statusline off).
        assert!(!state.is_harness_selected(HarnessKind::Claude));
        assert!(!state.install_skills);
        assert!(!state.install_statusline);

        assert_eq!(
            apply_setup_toggle_text_input(&mut state, "d", true).unwrap(),
            SetupToggleAction::Continue
        );
        assert!(state.show_dry_run_preview);

        assert_eq!(
            apply_setup_toggle_text_input(&mut state, "b", true).unwrap(),
            SetupToggleAction::Back
        );
        assert_eq!(
            apply_setup_toggle_text_input(&mut state, "b", false).unwrap(),
            SetupToggleAction::Cancel
        );
        assert_eq!(
            apply_setup_toggle_text_input(&mut state, "q", true).unwrap(),
            SetupToggleAction::Cancel
        );
        assert!(apply_setup_toggle_text_input(&mut state, "99", true).is_err());

        // Empty input applies.
        assert!(matches!(
            apply_setup_toggle_text_input(&mut state, "", true).unwrap(),
            SetupToggleAction::Apply(_)
        ));
    }

    #[test]
    fn x9_wizard_ignores_dead_t3_hyphae_json_and_omits_dead_preview_paths() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path();

        // Plant a dead/stale `~/.t3/hyphae.json` AND a real `node.json` `"t3"` block.
        fs::create_dir_all(home.join(".t3")).unwrap();
        fs::write(
            home.join(".t3").join("hyphae.json"),
            r#"{"hyphae":{"url":"http://127.0.0.1:9999"}}"#,
        )
        .unwrap();
        let node_cfg_path = home.join(".config").join("hyphae").join("node.json");
        fs::create_dir_all(node_cfg_path.parent().unwrap()).unwrap();
        fs::write(
            &node_cfg_path,
            r#"{"v":2,"nodeId":"alice@mac","t3":{"url":"http://127.0.0.1:3773"}}"#,
        )
        .unwrap();

        // Must resolve from `node.json` `"t3"` block, NEVER the removed `~/.t3/hyphae.json`!
        assert_eq!(
            resolve_t3_url_from_home(home, None).as_deref(),
            Some("http://127.0.0.1:3773")
        );

        // Even when `node.json` is absent, dead `~/.t3/hyphae.json` must NOT be used.
        fs::remove_file(&node_cfg_path).unwrap();
        assert_eq!(resolve_t3_url_from_home(home, None), None);

        // Dry-run preview for Herdr and T3 must NEVER list dead `~/.config/herdr/hyphae.json`
        // or `~/.t3/hyphae.json`.
        let state = SetupToggleState::from_detection(&[HarnessKind::Herdr, HarnessKind::T3], true);
        let lines = state.build_dry_run_preview(home, false);
        let joined = lines.join("\n");
        assert!(
            !joined.contains(".config/herdr/hyphae.json"),
            "Herdr preview must not reference dead ~/.config/herdr/hyphae.json:\n{joined}"
        );
        assert!(
            !joined.contains(".t3/hyphae.json"),
            "T3 preview must not reference dead ~/.t3/hyphae.json:\n{joined}"
        );
        assert!(
            joined.contains("HC_TERMINAL_ID"),
            "Herdr preview should note HC_TERMINAL_ID auto-detection:\n{joined}"
        );
        assert!(
            joined.contains("node.json"),
            "T3 preview should reference node.json t3 block:\n{joined}"
        );
    }

    #[test]
    fn openclaw_config_step_state_machine_text_fallback_and_viewport_ansi_parity() {
        let mut st = OpenClawConfigState::new(OpenClawDeliveryMode::Gateway, false);
        assert_eq!(st.cursor, 0);

        // Space on row 0 toggles Gateway -> Inbox -> Gateway.
        assert_eq!(
            handle_openclaw_config_key(&mut st, KeyEvent::Char(' '), true),
            OpenClawConfigAction::Continue
        );
        assert_eq!(st.delivery, OpenClawDeliveryMode::Inbox);
        assert_eq!(
            handle_openclaw_config_key(&mut st, KeyEvent::Char(' '), true),
            OpenClawConfigAction::Continue
        );
        assert_eq!(st.delivery, OpenClawDeliveryMode::Gateway);

        // Down moves to row 1 (Prompt injection); Space toggles OFF -> ON.
        assert_eq!(
            handle_openclaw_config_key(&mut st, KeyEvent::Down, true),
            OpenClawConfigAction::Continue
        );
        assert_eq!(st.cursor, 1);
        assert_eq!(
            handle_openclaw_config_key(&mut st, KeyEvent::Char(' '), true),
            OpenClawConfigAction::Continue
        );
        assert!(st.prompt_injection);

        // Number shortcuts 1 / 2 toggle directly.
        handle_openclaw_config_key(&mut st, KeyEvent::Char('1'), true);
        assert_eq!(st.delivery, OpenClawDeliveryMode::Inbox);
        handle_openclaw_config_key(&mut st, KeyEvent::Char('2'), true);
        assert!(!st.prompt_injection);

        // Enter applies chosen values.
        assert_eq!(
            handle_openclaw_config_key(&mut st, KeyEvent::Enter, true),
            OpenClawConfigAction::Apply {
                delivery: OpenClawDeliveryMode::Inbox,
                prompt_injection: false,
            }
        );

        // Back / Cancel respect allow_back.
        assert_eq!(
            handle_openclaw_config_key(&mut st, KeyEvent::Back, true),
            OpenClawConfigAction::Back
        );
        assert_eq!(
            handle_openclaw_config_key(&mut st, KeyEvent::Back, false),
            OpenClawConfigAction::Cancel
        );
        assert_eq!(
            handle_openclaw_config_key(&mut st, KeyEvent::Cancel, true),
            OpenClawConfigAction::Cancel
        );

        // Plain TTY text fallback parser.
        let mut txt_st = OpenClawConfigState::new(OpenClawDeliveryMode::Gateway, false);
        assert_eq!(
            apply_openclaw_config_text_input(&mut txt_st, "inbox", true).unwrap(),
            OpenClawConfigAction::Continue
        );
        assert_eq!(txt_st.delivery, OpenClawDeliveryMode::Inbox);
        assert_eq!(
            apply_openclaw_config_text_input(&mut txt_st, "on", true).unwrap(),
            OpenClawConfigAction::Continue
        );
        assert!(txt_st.prompt_injection);
        assert_eq!(
            apply_openclaw_config_text_input(&mut txt_st, "", true).unwrap(),
            OpenClawConfigAction::Apply {
                delivery: OpenClawDeliveryMode::Inbox,
                prompt_injection: true,
            }
        );
        assert_eq!(
            apply_openclaw_config_text_input(&mut txt_st, "b", true).unwrap(),
            OpenClawConfigAction::Back
        );
        assert_eq!(
            apply_openclaw_config_text_input(&mut txt_st, "q", true).unwrap(),
            OpenClawConfigAction::Cancel
        );
        assert!(apply_openclaw_config_text_input(&mut txt_st, "invalid-opt", true).is_err());

        // Differential viewport rendering: Plain == Ansi256 == TrueColor stripped text,
        // zero column overflow, and explicit reassurance copy always rendered.
        let tmp = tempfile::tempdir().expect("tempdir");
        let home = tmp.path();
        for (rows, cols) in [(24usize, 80usize), (20, 64), (36, 110)] {
            for pi in [false, true] {
                let render_st = OpenClawConfigState::new(OpenClawDeliveryMode::Gateway, pi);
                let plain = render_openclaw_config_screen(
                    &render_st,
                    home,
                    None,
                    true,
                    rows,
                    cols,
                    ColorMode::Plain,
                );
                let ansi256 = render_openclaw_config_screen(
                    &render_st,
                    home,
                    None,
                    true,
                    rows,
                    cols,
                    ColorMode::Ansi256,
                );
                let tc = render_openclaw_config_screen(
                    &render_st,
                    home,
                    None,
                    true,
                    rows,
                    cols,
                    ColorMode::TrueColor,
                );
                assert!(plain.len() <= rows);
                assert_eq!(plain.len(), ansi256.len());
                assert_eq!(plain.len(), tc.len());
                for (idx, ((p, a), t)) in
                    plain.iter().zip(ansi256.iter()).zip(tc.iter()).enumerate()
                {
                    let sp = strip_ansi(p);
                    let sa = strip_ansi(a);
                    let st_line = strip_ansi(t);
                    assert_eq!(sp, sa, "Plain vs Ansi256 mismatch row {idx}");
                    assert_eq!(sp, st_line, "Plain vs TrueColor mismatch row {idx}");
                    assert!(
                        sp.chars().count() <= cols,
                        "row {idx} overflowed {cols} cols: {sp:?}"
                    );
                }
                let full_text = plain
                    .iter()
                    .map(|l| strip_ansi(l))
                    .collect::<Vec<_>>()
                    .join(" ");
                let collapsed = full_text.split_whitespace().collect::<Vec<_>>().join(" ");
                assert!(
                    collapsed.contains("Even with prompt injection OFF")
                        && collapsed.contains("hyp_inbox"),
                    "expected explicit reassurance copy in rendered screen ({cols}x{rows}):\n{collapsed}"
                );
            }
        }

        // Dry-run preview includes OpenClaw extension files + delivery/prompt-injection mode.
        let toggle = SetupToggleState::from_detection(&[HarnessKind::Openclaw], false);
        let preview = toggle.build_dry_run_preview(home, false).join("\n");
        assert!(preview.contains("extensions/hyphae"), "preview={preview}");
        assert!(preview.contains("delivery=gateway"), "preview={preview}");
        assert!(
            preview.contains("prompt-injection=off"),
            "preview={preview}"
        );
    }
}
