//! Interactive Fullscreen Mycelium Onboarding Wizard & `hyphae-setup` Agent Concierge.
//!
//! Pure Rust (zero external TUI crates):
//! - Fullscreen alternate-screen (`\x1b[?1049h` / `\x1b[?1049l`) RAII guard and Unix `/dev/tty`
//!   raw-mode arrow-key navigation guard (`stty -g` -> `stty raw -echo` -> unconditional restore).
//! - Responsive 24-bit ANSI truecolor (with 256-color / plain fallback) dot-matrix organic
//!   mycelium canvas that scales to fill the detected terminal viewport.
//! - Zero-typing highlighted menus showing only harnesses detected on this machine, including a
//!   native Herdr (`hc templates --json`) launch-template picker sub-screen.
//! - Clean two-path handoff: Path A auto-launches interactive CLIs / Herdr templates after
//!   installing `hyphae-setup/SKILL.md`; Path B installs the skill and presents an interactive
//!   copy-paste guide screen (with clipboard support) for OpenClaw, T3 Code, and config-only CLIs.

use crate::config_file::{
    load_node_or_legacy_config, resolve_config_path_for_read, write_atomic_file,
};
use crate::setup::{HarnessDiagnostic, OnboardArgs, default_node_id, detect_harness_statuses};
use crate::ui::{
    EXIT_ERROR, EXIT_OK, EXIT_USAGE, JsonEnvelope, emit_error, print_json, print_next_steps,
    print_warnings,
};
use hyp_harness::protocol::HarnessKind;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeSet;
use std::f64::consts::PI;
use std::ffi::OsStr;
use std::fs;
#[cfg(unix)]
use std::io::{BufReader, Read};
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

/// Embedded pure-Rust v2 `hyphae-setup` concierge skill (zero network access needed).
pub const HYPHAE_SETUP_SKILL_MD: &str = include_str!("../../../skills/hyphae-setup/SKILL.md");

pub const DEFAULT_CANVAS_WIDTH: usize = 54;
pub const DEFAULT_CANVAS_HEIGHT: usize = 18;
pub const DEFAULT_TOTAL_FRAMES: usize = 32;
const FRAME_DELAY_MS: u64 = 62;

// Truecolor dot-matrix botanical mycelium palette.
const RGB_AMBIENT_DIM: (u8, u8, u8) = (56, 72, 68);
const RGB_HYPHAE_MOSS: (u8, u8, u8) = (102, 138, 118);
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

/// Terminal color rendering capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    TrueColor,
    Ansi256,
    Plain,
}

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

    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Claude => "Claude Code",
            Self::Codex => "Codex",
            Self::Antigravity => "Antigravity",
            Self::Opencode => "OpenCode",
            Self::Cursor => "Cursor Agent",
            Self::Gemini => "Gemini CLI",
        }
    }

    pub const fn binary_name(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Antigravity => "agy",
            Self::Opencode => "opencode",
            Self::Cursor => "cursor-agent",
            Self::Gemini => "gemini",
        }
    }

    pub fn parse_alias(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "claude" | "claude-code" => Some(Self::Claude),
            "codex" => Some(Self::Codex),
            "antigravity" | "agy" => Some(Self::Antigravity),
            "opencode" => Some(Self::Opencode),
            "cursor" | "cursor-agent" => Some(Self::Cursor),
            "gemini" | "gemini-cli" => Some(Self::Gemini),
            _ => None,
        }
    }

    /// Primary global skill file path for `hyphae-setup/SKILL.md`.
    pub fn primary_skill_path(self, home: &Path) -> PathBuf {
        match self {
            Self::Claude => home
                .join(".claude")
                .join("skills")
                .join("hyphae-setup")
                .join("SKILL.md"),
            Self::Codex => home
                .join(".codex")
                .join("skills")
                .join("hyphae-setup")
                .join("SKILL.md"),
            Self::Antigravity => home
                .join(".gemini")
                .join("config")
                .join("skills")
                .join("hyphae-setup")
                .join("SKILL.md"),
            Self::Opencode => home
                .join(".config")
                .join("opencode")
                .join("skills")
                .join("hyphae-setup")
                .join("SKILL.md"),
            Self::Cursor => home
                .join(".cursor")
                .join("skills")
                .join("hyphae-setup")
                .join("SKILL.md"),
            Self::Gemini => home
                .join(".gemini")
                .join("skills")
                .join("hyphae-setup")
                .join("SKILL.md"),
        }
    }

    /// Additional cross-tool skill paths to populate alongside `primary_skill_path`.
    pub fn extra_skill_paths(self, home: &Path) -> Vec<PathBuf> {
        match self {
            Self::Codex => vec![
                home.join(".agents")
                    .join("skills")
                    .join("hyphae-setup")
                    .join("SKILL.md"),
            ],
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
/// handled cleanly via Path B (install `hyphae-setup` skill + interactive copy-paste / deep-link guide).
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

    pub const fn display_name(self) -> &'static str {
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

    pub fn primary_skill_path(self, home: &Path) -> PathBuf {
        match self {
            Self::ClaudeDesktop => LaunchableHarness::Claude.primary_skill_path(home),
            Self::CodexDesktop => LaunchableHarness::Codex.primary_skill_path(home),
            Self::OpenCodeDesktop => LaunchableHarness::Opencode.primary_skill_path(home),
            Self::CursorIde => LaunchableHarness::Cursor.primary_skill_path(home),
            Self::Openclaw => home
                .join(".openclaw")
                .join("skills")
                .join("hyphae-setup")
                .join("SKILL.md"),
            Self::T3 => home
                .join(".agents")
                .join("skills")
                .join("hyphae-setup")
                .join("SKILL.md"),
            Self::ConfigOnlyCli(lh) => lh.primary_skill_path(home),
        }
    }

    pub fn extra_skill_paths(self, home: &Path) -> Vec<PathBuf> {
        match self {
            Self::ClaudeDesktop => Vec::new(),
            Self::CodexDesktop => LaunchableHarness::Codex.extra_skill_paths(home),
            Self::OpenCodeDesktop => vec![
                home.join(".agents")
                    .join("skills")
                    .join("hyphae-setup")
                    .join("SKILL.md"),
            ],
            Self::CursorIde => Vec::new(),
            Self::Openclaw => Vec::new(),
            // T3 Code spawns Claude and Codex sessions; install into all 3 skill locations.
            Self::T3 => vec![
                home.join(".claude")
                    .join("skills")
                    .join("hyphae-setup")
                    .join("SKILL.md"),
                home.join(".codex")
                    .join("skills")
                    .join("hyphae-setup")
                    .join("SKILL.md"),
            ],
            Self::ConfigOnlyCli(lh) => lh.extra_skill_paths(home),
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
            other => other.open_instruction(),
        }
    }

    /// Optional MCP config hint & snippet (used for Claude Desktop & Codex Desktop).
    pub fn mcp_config_note(self, home: &Path) -> Option<(PathBuf, &'static str)> {
        match self {
            Self::ClaudeDesktop => {
                let path = claude_desktop_config_path(home);
                let snippet =
                    r#"{ "mcpServers": { "hyphae": { "command": "hyp", "args": ["mcp"] } } }"#;
                Some((path, snippet))
            }
            Self::CodexDesktop => {
                let path = codex_desktop_config_path(home);
                let snippet = "[mcp_servers.hyphae]\ncommand = \"hyp\"\nargs = [\"mcp\"]";
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

/// Codex Desktop / CLI TOML config path (`~/.codex/config.toml`).
pub fn codex_desktop_config_path(home: &Path) -> PathBuf {
    home.join(".codex").join("config.toml")
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

fn codex_toml_is_hyphae_table_header(line: &str) -> bool {
    let trimmed = line.trim();
    if !trimmed.starts_with('[') || trimmed.starts_with("[[") {
        return false;
    }
    let Some(close_idx) = trimmed.find(']') else {
        return false;
    };
    let trailing = trimmed[close_idx + 1..].trim();
    if !trailing.is_empty() && !trailing.starts_with('#') {
        return false;
    }
    let inner: String = trimmed[1..close_idx]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    matches!(
        inner.as_str(),
        "mcp_servers.hyphae" | "mcp_servers.\"hyphae\"" | "mcp_servers.'hyphae'"
    )
}

fn codex_toml_has_hyphae_mcp(raw: &str) -> bool {
    raw.lines().any(codex_toml_is_hyphae_table_header)
}

fn upsert_toml_block_local(source: &str, marker: &str, block: &str) -> String {
    let begin = format!("# >>> {marker} >>>");
    let end = format!("# <<< {marker} <<<");
    let wrapped = format!("{begin}\n{}\n{end}\n", block.trim());
    if let (Some(start_idx), Some(end_idx)) = (source.find(&begin), source.find(&end)) {
        if end_idx > start_idx {
            let after_end = &source[end_idx + end.len()..];
            let after = after_end
                .strip_prefix("\r\n")
                .or_else(|| after_end.strip_prefix('\n'))
                .unwrap_or(after_end);
            return format!("{}{}{}", &source[..start_idx], wrapped, after);
        }
    }
    let sep = if source.is_empty() || source.ends_with('\n') {
        ""
    } else {
        "\n"
    };
    let blank = if source.trim().is_empty() { "" } else { "\n" };
    format!("{source}{sep}{blank}{wrapped}")
}

fn upsert_codex_hyphae_toml(source: &str, cli_bin: &str) -> String {
    let cmd_toml = serde_json::to_string(cli_bin).unwrap_or_else(|_| "\"hyp\"".to_string());
    let toml_block = format!(
        "[mcp_servers.hyphae]\ncommand = {cmd_toml}\nargs = [\"mcp\"]\nenv_vars = [\"CODEX_HOME\", \"HYPHAE_SOCKET\"]"
    );

    let begin = "# >>> hyphae >>>";
    let end = "# <<< hyphae <<<";
    if let (Some(start_idx), Some(end_idx)) = (source.find(begin), source.find(end)) {
        if end_idx > start_idx {
            return upsert_toml_block_local(source, "hyphae", &toml_block);
        }
    }

    // If an unmarked `[mcp_servers.hyphae]` table already exists, replace it cleanly in place
    // so we never write duplicate TOML table headers.
    let lines: Vec<&str> = source.lines().collect();
    if let Some(start_line) = lines
        .iter()
        .position(|line| codex_toml_is_hyphae_table_header(line))
    {
        let mut end_line = lines.len();
        for (idx, line) in lines.iter().enumerate().skip(start_line + 1) {
            if line.trim_start().starts_with('[') {
                end_line = idx;
                break;
            }
        }
        let mut before = lines[..start_line].to_vec();
        while before.last().is_some_and(|l| l.trim().is_empty()) {
            before.pop();
        }
        let mut after = lines[end_line..].to_vec();
        while after.first().is_some_and(|l| l.trim().is_empty()) {
            after.remove(0);
        }

        let mut out = String::new();
        if !before.is_empty() {
            out.push_str(&before.join("\n"));
            out.push_str("\n\n");
        }
        out.push_str(&format!("{begin}\n{toml_block}\n{end}\n"));
        if !after.is_empty() {
            out.push('\n');
            out.push_str(&after.join("\n"));
            out.push('\n');
        }
        return out;
    }

    upsert_toml_block_local(source, "hyphae", &toml_block)
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
                format!("    \"hyphae\": {{ \"command\": {cmd_json}, \"args\": [\"mcp\"] }}"),
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
            let config_path = codex_desktop_config_path(home);
            let already_configured = if config_path.exists() {
                fs::read_to_string(&config_path)
                    .ok()
                    .is_some_and(|raw| codex_toml_has_hyphae_mcp(&raw))
            } else {
                false
            };
            let cmd_toml = serde_json::to_string(cli_bin).unwrap_or_else(|_| "\"hyp\"".to_string());
            let preview_lines = vec![
                "Add [mcp_servers.hyphae] section (preserves existing Codex settings):".to_string(),
                "[mcp_servers.hyphae]".to_string(),
                format!("command = {cmd_toml}"),
                "args = [\"mcp\"]".to_string(),
                "env_vars = [\"CODEX_HOME\", \"HYPHAE_SOCKET\"]".to_string(),
            ];
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
                    "args": ["mcp"]
                }),
            );
            doc.insert(
                "mcpServers".to_string(),
                serde_json::Value::Object(servers),
            );

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
            let config_path = codex_desktop_config_path(home);
            let existed = config_path.exists();
            let existing_toml = if existed {
                fs::read_to_string(&config_path)
                    .map_err(|e| format!("failed to read {}: {e}", config_path.display()))?
            } else {
                String::new()
            };
            let already_configured = codex_toml_has_hyphae_mcp(&existing_toml);
            let next_toml = upsert_codex_hyphae_toml(&existing_toml, cli_bin);
            write_atomic_file(&config_path, next_toml.as_bytes(), false)?;

            Ok(DesktopMcpApplyResult {
                config_path,
                created: !existed,
                already_configured,
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
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(input.len() + input.len() / 4);
    for &b in input.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 0x0f) as usize] as char);
        }
    }
    out
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
        || home
            .join("AppData")
            .join("Local")
            .join("OpenCode")
            .exists()
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
#[allow(dead_code)]
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
    Finished(ExitCode),
    RunLocalCliSetup,
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

/// RAII alternate-screen + hidden-cursor guard.
///
/// Enters `\x1b[?1049h\x1b[2J\x1b[H\x1b[?25l` on creation and unconditionally restores
/// `\x1b[?25h\x1b[0m\x1b[?1049l` on `leave()` or `Drop` (including early returns / panic unwinds).
struct AltScreenGuard {
    active: bool,
}

impl AltScreenGuard {
    fn enter_if(enabled: bool) -> Self {
        if enabled {
            let mut out = io::stdout().lock();
            let _ = out.write_all(b"\x1b[?1049h\x1b[2J\x1b[H\x1b[?25l");
            let _ = out.flush();
        }
        Self { active: enabled }
    }

    fn leave(&mut self) {
        if self.active {
            self.active = false;
            let mut out = io::stdout().lock();
            let _ = out.write_all(b"\x1b[?25h\x1b[0m\x1b[?1049l");
            let _ = out.flush();
        }
    }
}

impl Drop for AltScreenGuard {
    fn drop(&mut self) {
        self.leave();
    }
}

/// Pure-Rust Unix `/dev/tty` raw-mode guard backed by `stty -g` / `stty raw -echo`.
/// Unconditionally restores the exact saved `stty` state in `Drop`.
#[cfg(unix)]
struct RawTtyGuard {
    saved_state: String,
    tty: fs::File,
    active: bool,
}

#[cfg(unix)]
impl RawTtyGuard {
    fn run_stty(tty: &fs::File, args: &[&str]) -> io::Result<std::process::Output> {
        let stdin_file = tty.try_clone()?;
        Command::new("stty")
            .args(args)
            .stdin(Stdio::from(stdin_file))
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
    }

    fn enter(nonblocking: bool) -> io::Result<Self> {
        let tty = fs::File::open("/dev/tty")?;
        let saved_out = Self::run_stty(&tty, &["-g"])?;
        if !saved_out.status.success() {
            return Err(io::Error::other("stty -g failed on /dev/tty"));
        }
        let saved_state = String::from_utf8_lossy(&saved_out.stdout)
            .trim()
            .to_string();
        if saved_state.is_empty() {
            return Err(io::Error::other("stty -g returned empty state"));
        }

        let mut guard = Self {
            saved_state,
            tty,
            active: true,
        };
        if let Err(e) = guard.set_mode(nonblocking) {
            guard.restore();
            return Err(e);
        }
        Ok(guard)
    }

    fn set_mode(&self, nonblocking: bool) -> io::Result<()> {
        let args: &[&str] = if nonblocking {
            &["raw", "-echo", "min", "0", "time", "0"]
        } else {
            &["raw", "-echo", "min", "0", "time", "1"]
        };
        let out = Self::run_stty(&self.tty, args)?;
        if out.status.success() {
            Ok(())
        } else {
            Err(io::Error::other("stty raw -echo failed on /dev/tty"))
        }
    }

    fn poll_any_key(&mut self) -> Option<KeyEvent> {
        let mut buf = [0u8; 8];
        match self.tty.read(&mut buf) {
            Ok(n) if n > 0 => Some(parse_key_bytes(&buf[..n])),
            _ => None,
        }
    }

    fn drain_pending(&mut self) {
        let mut buf = [0u8; 32];
        for _ in 0..4 {
            match self.tty.read(&mut buf) {
                Ok(n) if n > 0 => continue,
                _ => break,
            }
        }
    }

    /// Reads one key event with a ~100ms POSIX `stty raw -echo min 0 time 1` timeout.
    /// Returns `Ok(None)` on idle tick so the live banner can advance pulses with zero `unsafe`.
    fn read_key_timeout(&mut self) -> io::Result<Option<KeyEvent>> {
        let mut buf = [0u8; 8];
        match self.tty.read(&mut buf) {
            Ok(0) => Ok(None),
            Ok(n) => {
                let mut total = n;
                // If a lone ESC arrived, give the terminal one VTIME=1 (100ms) window
                // to deliver the remainder of an arrow-key escape sequence (`[A`/`OA`).
                if total == 1 && buf[0] == 0x1b {
                    if let Ok(extra) = self.tty.read(&mut buf[1..]) {
                        total += extra;
                    }
                }
                Ok(Some(parse_key_bytes(&buf[..total])))
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn read_key(&mut self) -> io::Result<KeyEvent> {
        loop {
            if let Some(key) = self.read_key_timeout()? {
                return Ok(key);
            }
        }
    }

    fn restore(&mut self) {
        if self.active {
            self.active = false;
            let _ = Self::run_stty(&self.tty, &[self.saved_state.as_str()]);
        }
    }
}

#[cfg(unix)]
impl Drop for RawTtyGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

// ============================================================================
// Dot-Matrix Procedural Mycelium Animation
// ============================================================================

#[derive(Clone, Copy, Default)]
struct Cell {
    hypha: f64,
    halo: f64,
    pulse: f64,
    node: f64,
    node_core: bool,
}

fn lerp_f64(a: f64, b: f64, t: f64) -> f64 {
    a + (b - a) * t.clamp(0.0, 1.0)
}

fn lerp_rgb(a: (u8, u8, u8), b: (u8, u8, u8), t: f64) -> (u8, u8, u8) {
    let t = t.clamp(0.0, 1.0);
    (
        (a.0 as f64 + (b.0 as f64 - a.0 as f64) * t).round() as u8,
        (a.1 as f64 + (b.1 as f64 - a.1 as f64) * t).round() as u8,
        (a.2 as f64 + (b.2 as f64 - a.2 as f64) * t).round() as u8,
    )
}

fn smoothstep(edge0: f64, edge1: f64, x: f64) -> f64 {
    if edge1 <= edge0 {
        return if x >= edge1 { 1.0 } else { 0.0 };
    }
    let t = ((x - edge0) / (edge1 - edge0)).clamp(0.0, 1.0);
    t * t * (3.0 - 2.0 * t)
}

fn gaussian(dist: f64, sigma: f64) -> f64 {
    let ratio = dist / sigma.max(1e-6);
    (-0.5 * ratio * ratio).exp()
}

/// Converts 24-bit RGB to the nearest xterm-256 palette index (6x6x6 cube vs 24-step grayscale).
pub fn rgb_to_ansi256(r: u8, g: u8, b: u8) -> u8 {
    const CUBE_LEVELS: [u8; 6] = [0, 95, 135, 175, 215, 255];

    fn nearest_cube(v: u8) -> usize {
        let mut best_idx = 0usize;
        let mut best_dist = i32::MAX;
        for (idx, &lvl) in CUBE_LEVELS.iter().enumerate() {
            let d = (v as i32 - lvl as i32).abs();
            if d < best_dist {
                best_dist = d;
                best_idx = idx;
            }
        }
        best_idx
    }

    let ri = nearest_cube(r);
    let gi = nearest_cube(g);
    let bi = nearest_cube(b);
    let cube_code = (16 + 36 * ri + 6 * gi + bi) as u8;
    let cube_dist = (r as i32 - CUBE_LEVELS[ri] as i32).pow(2)
        + (g as i32 - CUBE_LEVELS[gi] as i32).pow(2)
        + (b as i32 - CUBE_LEVELS[bi] as i32).pow(2);

    let avg = ((r as u32 + g as u32 + b as u32) / 3) as i32;
    let gray_idx = ((avg - 8 + 5) / 10).clamp(0, 23);
    let gray_lvl = 8 + 10 * gray_idx;
    let gray_code = (232 + gray_idx) as u8;
    let gray_dist = (r as i32 - gray_lvl).pow(2)
        + (g as i32 - gray_lvl).pow(2)
        + (b as i32 - gray_lvl).pow(2);

    if gray_dist < cube_dist {
        gray_code
    } else {
        cube_code
    }
}

fn quad_bezier(p0: (f64, f64), p1: (f64, f64), p2: (f64, f64), t: f64) -> (f64, f64) {
    let inv = 1.0 - t;
    let x = inv * inv * p0.0 + 2.0 * inv * t * p1.0 + t * t * p2.0;
    let y = inv * inv * p0.1 + 2.0 * inv * t * p1.1 + t * t * p2.1;
    (x, y)
}

struct Splat {
    x: f64,
    y: f64,
    hypha: f64,
    halo: f64,
    pulse: f64,
    node: f64,
    sigma_core: f64,
    sigma_halo: f64,
}

fn splat_point(grid: &mut [Cell], width: usize, height: usize, s: Splat) {
    let radius_x = (s.sigma_halo * 2.6).ceil().clamp(3.0, 6.0) as isize;
    let radius_y = ((radius_x as f64) * 0.65).ceil().max(2.0) as isize;
    let min_x = (s.x.floor() as isize - radius_x).max(0) as usize;
    let max_x = ((s.x.ceil() as isize + radius_x).min(width as isize - 1)).max(0) as usize;
    let min_y = (s.y.floor() as isize - radius_y).max(0) as usize;
    let max_y = ((s.y.ceil() as isize + radius_y).min(height as isize - 1)).max(0) as usize;
    let cutoff = s.sigma_halo * 2.85;

    for y in min_y..=max_y {
        let dy_vis = (y as f64 - s.y) * 2.0;
        let row_offset = y * width;
        for x in min_x..=max_x {
            let dx = x as f64 - s.x;
            let dist = dx.hypot(dy_vis);
            if dist > cutoff {
                continue;
            }
            let cell = &mut grid[row_offset + x];
            if s.hypha > 0.0 {
                let v = s.hypha * gaussian(dist, s.sigma_core);
                if v > cell.hypha {
                    cell.hypha = v;
                }
            }
            if s.halo > 0.0 {
                let v = s.halo * gaussian(dist, s.sigma_halo);
                if v > cell.halo {
                    cell.halo = v;
                }
            }
            if s.pulse > 0.0 {
                let v = s.pulse * gaussian(dist, s.sigma_core * 1.18);
                if v > cell.pulse {
                    cell.pulse = v;
                }
            }
            if s.node > 0.0 {
                let v = s.node * gaussian(dist, s.sigma_halo * 0.82);
                if v > cell.node {
                    cell.node = v;
                }
            }
        }
    }
}

/// Renders a single deterministic frame of the dot-matrix organic mycelium network.
///
/// Scales seamlessly from compact banner sizes (`54×18`, `48×8`) up to fullscreen canvases
/// (`100×32`, `132×44`) with 8 sinuous primary hyphae, interconnecting outer rings, inner
/// cross-linked anastomoses, fine branching root tendrils, glowing gold-amber nodes, and
/// traveling bioluminescent pulses.
pub fn render_mycelium_frame(
    frame_idx: usize,
    total_frames: usize,
    width: usize,
    height: usize,
    color_mode: ColorMode,
) -> String {
    render_mycelium_frame_at_phase(frame_idx, total_frames, 0, width, height, color_mode)
}

/// Renders a dot-matrix mycelium frame at an additional continuous pulse `phase_tick` (for live
/// ~10 FPS menu banner animation without advancing intro growth).
pub fn render_mycelium_frame_at_phase(
    frame_idx: usize,
    total_frames: usize,
    phase_tick: usize,
    width: usize,
    height: usize,
    color_mode: ColorMode,
) -> String {
    if width == 0 || height == 0 {
        return String::new();
    }

    let denom = total_frames.saturating_sub(1).max(1) as f64;
    let p = (frame_idx.min(total_frames.saturating_sub(1)) as f64) / denom;
    let phase_shift = (phase_tick as f64) * 0.045;

    let mut grid = vec![Cell::default(); width * height];

    let cx = (width as f64 - 1.0) * 0.5;
    let cy = (height as f64 - 1.0) * 0.5;
    let rx = (width as f64) * 0.41;
    let ry = (height as f64) * 0.39;
    let sway_scale = (width as f64) / (DEFAULT_CANVAS_WIDTH as f64);
    let diag_scale = ((width as f64).hypot(height as f64 * 2.0)) / (54.0_f64).hypot(36.0);
    let sigma_scale = ((width as f64 / DEFAULT_CANVAS_WIDTH as f64)
        .min(height as f64 / DEFAULT_CANVAS_HEIGHT as f64))
    .clamp(0.88, 1.38);

    // 8 organically spaced outer agent nodes around a living botanical ellipse.
    const NODE_COUNT: usize = 8;
    const NODE_ANGLES: [f64; NODE_COUNT] = [0.06, 0.84, 1.61, 2.39, 3.18, 3.96, 4.74, 5.52];
    const NODE_RADII: [f64; NODE_COUNT] = [1.00, 0.94, 0.98, 1.03, 0.97, 1.02, 0.95, 0.99];
    const SWAYS: [f64; NODE_COUNT] = [2.35, -2.05, 2.50, -2.15, 2.30, -2.40, 2.10, -2.35];

    let outer_nodes: [(f64, f64); NODE_COUNT] = std::array::from_fn(|i| {
        (
            cx + rx * NODE_RADII[i] * NODE_ANGLES[i].cos(),
            cy + ry * NODE_RADII[i] * NODE_ANGLES[i].sin(),
        )
    });

    let primary_point = |branch: usize, u: f64| -> (f64, f64) {
        let (nx, ny) = outer_nodes[branch];
        let dx = nx - cx;
        let dy = ny - cy;
        let vis_len = dx.hypot(dy * 2.0).max(1e-6);
        let px = -(dy * 2.0) / vis_len;
        let py = (dx / vis_len) * 0.5;
        let sway = SWAYS[branch] * sway_scale;
        let bend = (PI * u).sin() * sway + (2.0 * PI * u).sin() * (sway * 0.28);
        (cx + dx * u + px * bend, cy + dy * u + py * bend)
    };

    // 1. Central spore cluster — ignites at frame 0 and stays as a warm living core.
    let spore_bloom = smoothstep(0.0, 0.14, p);
    let spore_pulse =
        (1.0 - smoothstep(0.02, 0.24, p)) * 0.85 + 0.24 * smoothstep(0.74, 1.0, p);
    splat_point(
        &mut grid,
        width,
        height,
        Splat {
            x: cx,
            y: cy,
            hypha: 0.58 + 0.30 * spore_bloom,
            halo: 0.48 + 0.30 * spore_bloom,
            pulse: spore_pulse,
            node: 0.52 + 0.36 * spore_bloom,
            sigma_core: 0.85 * sigma_scale,
            sigma_halo: 1.85 * sigma_scale,
        },
    );
    let center_x = (cx.round() as isize).clamp(0, width as isize - 1) as usize;
    let center_y = (cy.round() as isize).clamp(0, height as isize - 1) as usize;
    grid[center_y * width + center_x].node_core = true;

    let primary_steps = (46.0 * diag_scale).round().clamp(34.0, 116.0) as usize;
    let ring_steps = (30.0 * diag_scale).round().clamp(22.0, 76.0) as usize;
    let root_steps = (18.0 * diag_scale).round().clamp(14.0, 44.0) as usize;
    let chord_steps = (26.0 * diag_scale).round().clamp(20.0, 64.0) as usize;

    // 2. Primary hyphae filaments growing outward from center to each outer agent node.
    for i in 0..NODE_COUNT {
        let delay = (i as f64) * 0.018;
        let growth = smoothstep(0.03 + delay, 0.54 + delay, p);
        if growth <= 0.005 {
            continue;
        }
        let max_step = ((primary_steps as f64) * growth).ceil() as usize;
        let pulse_phase = if p > 0.65 {
            let speed = 1.75;
            let raw = (p - 0.65) * speed + phase_shift + (i as f64) * 0.19;
            Some(raw.fract())
        } else {
            None
        };

        for s in 0..=max_step.min(primary_steps) {
            let u = (s as f64) / (primary_steps as f64);
            if u > growth {
                break;
            }
            let (sx, sy) = primary_point(i, u);
            let dist_to_tip = (growth - u).abs();
            let active_tip = if growth < 0.995 {
                gaussian(dist_to_tip, 0.075) * 0.95
            } else {
                0.0
            };
            let traveling = pulse_phase
                .map(|pu| {
                    let fade = smoothstep(0.65, 0.78, p);
                    gaussian((u - pu).abs(), 0.068) * 0.90 * fade
                })
                .unwrap_or(0.0);

            let body_strength = lerp_f64(0.86, 0.64, u * 0.55);
            let halo_strength = lerp_f64(0.56, 0.36, u * 0.50);
            splat_point(
                &mut grid,
                width,
                height,
                Splat {
                    x: sx,
                    y: sy,
                    hypha: body_strength,
                    halo: halo_strength,
                    pulse: active_tip.max(traveling),
                    node: 0.0,
                    sigma_core: 0.75 * sigma_scale,
                    sigma_halo: 1.52 * sigma_scale,
                },
            );
        }

        // 3. Outer interconnecting mesh-ring tendrils bridging branch i -> branch (i + 1) % 8.
        let ring_growth = smoothstep(0.30 + delay, 0.72 + delay, p);
        if ring_growth > 0.005 {
            let next_i = (i + 1) % NODE_COUNT;
            let start = primary_point(i, 0.56);
            let end = primary_point(next_i, 0.76);
            let mid_raw = ((start.0 + end.0) * 0.5, (start.1 + end.1) * 0.5);
            let ctrl = (
                cx + (mid_raw.0 - cx) * 1.24,
                cy + (mid_raw.1 - cy) * 1.24,
            );
            let ring_pulse_u = if p > 0.74 {
                Some(((p - 0.74) * 2.15 + phase_shift * 1.15 + (i as f64) * 0.27).fract())
            } else {
                None
            };
            let max_rs = ((ring_steps as f64) * ring_growth).ceil() as usize;
            for s in 0..=max_rs.min(ring_steps) {
                let u = (s as f64) / (ring_steps as f64);
                if u > ring_growth {
                    break;
                }
                let (sx, sy) = quad_bezier(start, ctrl, end, u);
                let tip = if ring_growth < 0.995 {
                    gaussian((ring_growth - u).abs(), 0.09) * 0.82
                } else {
                    0.0
                };
                let signal = ring_pulse_u
                    .map(|pu| gaussian((u - pu).abs(), 0.085) * 0.80 * smoothstep(0.74, 0.86, p))
                    .unwrap_or(0.0);
                splat_point(
                    &mut grid,
                    width,
                    height,
                    Splat {
                        x: sx,
                        y: sy,
                        hypha: 0.54,
                        halo: 0.34,
                        pulse: tip.max(signal),
                        node: 0.0,
                        sigma_core: 0.65 * sigma_scale,
                        sigma_halo: 1.32 * sigma_scale,
                    },
                );
            }
        }

        // 4. Inner cross-link anastomoses bridging alternating primary branches i -> (i + 2) % 8.
        if i % 2 == 0 {
            let chord_growth = smoothstep(0.36 + delay, 0.78 + delay, p);
            if chord_growth > 0.005 {
                let target_i = (i + 2) % NODE_COUNT;
                let start = primary_point(i, 0.36);
                let end = primary_point(target_i, 0.44);
                let mid_raw = ((start.0 + end.0) * 0.5, (start.1 + end.1) * 0.5);
                let ctrl = (
                    cx + (mid_raw.0 - cx) * 1.38,
                    cy + (mid_raw.1 - cy) * 1.38,
                );
                let chord_pulse_u = if p > 0.78 {
                    Some(((p - 0.78) * 1.9 + phase_shift * 0.95 + (i as f64) * 0.33).fract())
                } else {
                    None
                };
                let max_cs = ((chord_steps as f64) * chord_growth).ceil() as usize;
                for s in 0..=max_cs.min(chord_steps) {
                    let u = (s as f64) / (chord_steps as f64);
                    if u > chord_growth {
                        break;
                    }
                    let (sx, sy) = quad_bezier(start, ctrl, end, u);
                    let tip = if chord_growth < 0.995 {
                        gaussian((chord_growth - u).abs(), 0.10) * 0.70
                    } else {
                        0.0
                    };
                    let signal = chord_pulse_u
                        .map(|pu| gaussian((u - pu).abs(), 0.09) * 0.72 * smoothstep(0.78, 0.90, p))
                        .unwrap_or(0.0);
                    splat_point(
                        &mut grid,
                        width,
                        height,
                        Splat {
                            x: sx,
                            y: sy,
                            hypha: 0.44,
                            halo: 0.28,
                            pulse: tip.max(signal),
                            node: 0.0,
                            sigma_core: 0.58 * sigma_scale,
                            sigma_halo: 1.18 * sigma_scale,
                        },
                    );
                }
            }
        }

        // 5. Fine botanical side-tendrils branching softly outward from each primary hypha.
        let root_growth = smoothstep(0.26 + delay, 0.66 + delay, p);
        if root_growth > 0.005 {
            let start = primary_point(i, 0.36);
            let side_angle = NODE_ANGLES[i] - 0.42;
            let end = (
                cx + rx * 0.80 * side_angle.cos(),
                cy + ry * 0.80 * side_angle.sin(),
            );
            let ctrl = (
                start.0 + (end.0 - start.0) * 0.52 + (start.1 - cy) * 0.16,
                start.1 + (end.1 - start.1) * 0.52 - (start.0 - cx) * 0.08,
            );
            let max_ts = ((root_steps as f64) * root_growth).ceil() as usize;
            for s in 0..=max_ts.min(root_steps) {
                let u = (s as f64) / (root_steps as f64);
                if u > root_growth {
                    break;
                }
                let (sx, sy) = quad_bezier(start, ctrl, end, u);
                let taper = 1.0 - u * 0.45;
                let tip = if root_growth < 0.995 {
                    gaussian((root_growth - u).abs(), 0.12) * 0.65
                } else {
                    0.0
                };
                splat_point(
                    &mut grid,
                    width,
                    height,
                    Splat {
                        x: sx,
                        y: sy,
                        hypha: 0.45 * taper,
                        halo: 0.30 * taper,
                        pulse: tip,
                        node: 0.0,
                        sigma_core: 0.58 * sigma_scale,
                        sigma_halo: 1.18 * sigma_scale,
                    },
                );
            }
        }

        // 5b. Secondary outer fork on larger viewports for lush fullscreen organic density.
        if width >= 70 && height >= 22 {
            let fork_growth = smoothstep(0.42 + delay, 0.80 + delay, p);
            if fork_growth > 0.005 {
                let start = primary_point(i, 0.68);
                let fork_angle = NODE_ANGLES[i] + 0.30;
                let end = (
                    cx + rx * 1.08 * fork_angle.cos(),
                    cy + ry * 1.06 * fork_angle.sin(),
                );
                let ctrl = (
                    start.0 + (end.0 - start.0) * 0.55 - (start.1 - cy) * 0.12,
                    start.1 + (end.1 - start.1) * 0.55 + (start.0 - cx) * 0.06,
                );
                let max_fs = ((root_steps as f64) * fork_growth).ceil() as usize;
                for s in 0..=max_fs.min(root_steps) {
                    let u = (s as f64) / (root_steps as f64);
                    if u > fork_growth {
                        break;
                    }
                    let (sx, sy) = quad_bezier(start, ctrl, end, u);
                    let taper = 1.0 - u * 0.55;
                    splat_point(
                        &mut grid,
                        width,
                        height,
                        Splat {
                            x: sx,
                            y: sy,
                            hypha: 0.38 * taper,
                            halo: 0.28 * taper,
                            pulse: 0.0,
                            node: 0.0,
                            sigma_core: 0.55 * sigma_scale,
                            sigma_halo: 1.15 * sigma_scale,
                        },
                    );
                }
            }
        }

        // 6. Outer agent nodes ignite in warm bioluminescent gold-amber upon arrival.
        let arrive = smoothstep(0.48 + delay, 0.66 + delay, p);
        if arrive > 0.01 {
            let burst = gaussian(p - (0.58 + delay), 0.085) * 0.45;
            let steady_breathe =
                0.08 * ((p * 2.0 * PI) + phase_shift * 2.0 * PI + (i as f64)).sin();
            let node_intensity = (arrive * 0.92 + burst + steady_breathe).clamp(0.0, 1.15);
            let (nx, ny) = outer_nodes[i];
            splat_point(
                &mut grid,
                width,
                height,
                Splat {
                    x: nx,
                    y: ny,
                    hypha: 0.35 * arrive,
                    halo: 0.48 * arrive,
                    pulse: burst * 1.35,
                    node: node_intensity,
                    sigma_core: 0.78 * sigma_scale,
                    sigma_halo: 1.82 * sigma_scale,
                },
            );
            if arrive >= 0.35 {
                let ix = (nx.round() as isize).clamp(0, width as isize - 1) as usize;
                let iy = (ny.round() as isize).clamp(0, height as isize - 1) as usize;
                grid[iy * width + ix].node_core = true;
            }
        }
    }

    // 7. Compose dot-matrix rows with minimal ANSI escapes.
    let mut out = String::with_capacity(width * height * 6);
    for y in 0..height {
        if y > 0 {
            out.push('\n');
        }
        let mut last_color: Option<(u8, u8, u8)> = None;
        let row_offset = y * width;
        for x in 0..width {
            let cell = grid[row_offset + x];
            let (ch, color) = classify_cell(cell);
            match color {
                None => {
                    if color_mode != ColorMode::Plain && last_color.is_some() {
                        out.push_str("\x1b[0m");
                        last_color = None;
                    }
                    out.push(ch);
                }
                Some(rgb) => {
                    match color_mode {
                        ColorMode::Plain => {}
                        ColorMode::TrueColor => {
                            if last_color != Some(rgb) {
                                use std::fmt::Write as _;
                                let _ = write!(out, "\x1b[38;2;{};{};{}m", rgb.0, rgb.1, rgb.2);
                                last_color = Some(rgb);
                            }
                        }
                        ColorMode::Ansi256 => {
                            let code = rgb_to_ansi256(rgb.0, rgb.1, rgb.2);
                            let quantized = (code, 0, 0);
                            if last_color != Some(quantized) {
                                use std::fmt::Write as _;
                                let _ = write!(out, "\x1b[38;5;{code}m");
                                last_color = Some(quantized);
                            }
                        }
                    }
                    out.push(ch);
                }
            }
        }
        if color_mode != ColorMode::Plain && last_color.is_some() {
            out.push_str("\x1b[0m");
        }
    }
    out
}

fn classify_cell(cell: Cell) -> (char, Option<(u8, u8, u8)>) {
    if cell.node_core && cell.node >= 0.45 {
        let rgb = lerp_rgb(RGB_NODE_AMBER, RGB_PULSE_IVORY, (cell.pulse * 0.45).min(0.45));
        return ('●', Some(rgb));
    }
    if cell.pulse >= 0.48 {
        let t = ((cell.pulse - 0.48) / 0.52).clamp(0.0, 1.0);
        let rgb = lerp_rgb(RGB_HYPHAE_SAGE, RGB_PULSE_IVORY, t);
        return ('▪', Some(rgb));
    }
    if cell.node >= 0.34 && cell.node >= cell.hypha * 0.85 {
        let t = ((cell.node - 0.34) / 0.66).clamp(0.0, 1.0);
        let rgb = lerp_rgb(RGB_HYPHAE_SAGE, RGB_NODE_AMBER, t);
        let ch = if cell.node >= 0.56 { '▪' } else { '·' };
        return (ch, Some(rgb));
    }
    if cell.hypha >= 0.28 {
        let t = ((cell.hypha - 0.28) / 0.72).clamp(0.0, 1.0);
        let rgb = lerp_rgb(RGB_HYPHAE_MOSS, RGB_HYPHAE_SAGE, t);
        return ('▪', Some(rgb));
    }
    if cell.halo >= 0.14 {
        let t = ((cell.halo - 0.14) / 0.55).clamp(0.0, 1.0);
        let rgb = lerp_rgb(RGB_AMBIENT_DIM, RGB_HYPHAE_MOSS, t);
        return ('·', Some(rgb));
    }
    (' ', None)
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
    let art = render_mycelium_frame(frame_idx, total_frames, canvas_w, canvas_h, color_mode);
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
                if let Some(key) = raw_tty.poll_any_key() {
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
    let mut alt = AltScreenGuard::enter_if(true);

    #[cfg(unix)]
    if let Ok(mut raw) = RawTtyGuard::enter(true) {
        let _ = play_fullscreen_intro_on_alt_screen(&mut raw, term_rows, term_cols, color_mode, 220);
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
        let settled = render_mycelium_frame(
            DEFAULT_TOTAL_FRAMES - 1,
            DEFAULT_TOTAL_FRAMES,
            width,
            height,
            color_mode,
        );
        println!("{settled}");
        return ExitCode::from(EXIT_OK);
    }

    // Live interactive TTY: play the full-screen alternate-screen animation.
    let (term_rows, term_cols) = detect_terminal_size();
    let mut alt = AltScreenGuard::enter_if(true);

    #[cfg(unix)]
    if let Ok(mut raw) = RawTtyGuard::enter(true) {
        let _ = play_fullscreen_intro_on_alt_screen(&mut raw, term_rows, term_cols, color_mode, 450);
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
    let path_var = path_var?;
    for dir in std::env::split_paths(path_var) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        #[cfg(windows)]
        {
            let exts: Vec<String> = std::env::var("PATHEXT")
                .unwrap_or_else(|_| ".EXE;.CMD;.BAT;.COM".to_string())
                .split(';')
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().to_string())
                .collect();
            let direct = dir.join(bin_name);
            if direct.is_file() {
                return Some(direct);
            }
            for ext in &exts {
                let candidate = dir.join(format!("{bin_name}{ext}"));
                if candidate.is_file() {
                    return Some(candidate);
                }
                let lower_candidate = dir.join(format!("{bin_name}{}", ext.to_ascii_lowercase()));
                if lower_candidate.is_file() {
                    return Some(lower_candidate);
                }
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let candidate = dir.join(bin_name);
            let is_exec = fs::metadata(&candidate)
                .map(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0)
                .unwrap_or(false);
            if is_exec {
                return Some(candidate);
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            let candidate = dir.join(bin_name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
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
/// so `hyphae-setup/SKILL.md` is installed into the right global skill directory before launch.
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

/// Builds the filtered main menu containing ONLY options actually detected/available on this machine.
#[allow(dead_code)]
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
                    tag: "herdr",
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
                tag: "templates",
                subtitle: format!(
                    "Launch via Herdr templates ({} available) · native tab wakeup",
                    herdr_templates.len()
                ),
                action: MainMenuAction::HerdrTemplates {
                    hc_bin: hc_path.to_path_buf(),
                    templates: herdr_templates.to_vec(),
                },
            });
        }
    }

    // 2. Detected launchable CLI harnesses on PATH (`auto-launch`).
    for &(lh, _) in launchables {
        let configured = find_diag(lh.id()).is_some_and(|d| d.configured);
        let subtitle = if configured {
            format!("{} · configured", lh.binary_name())
        } else {
            lh.binary_name().to_string()
        };
        items.push(MainMenuItem {
            label: lh.display_name().to_string(),
            tag: "auto-launch",
            subtitle,
            action: MainMenuAction::LaunchCli(lh),
        });
    }

    // 3. Detected Desktop / IDE / GUI / daemon harnesses (`install skill + guide`).
    if desktop_apps.claude_desktop {
        items.push(MainMenuItem {
            label: ManualGuideHarness::ClaudeDesktop.display_name().to_string(),
            tag: "install skill + guide",
            subtitle: "Install skill + configure Claude Desktop MCP".to_string(),
            action: MainMenuAction::ManualGuide(ManualGuideHarness::ClaudeDesktop),
        });
    }

    let codex_diag_detected =
        find_diag("codex").is_some_and(|d| d.detected || d.configured);
    let show_codex_desktop =
        desktop_apps.codex_desktop || (!cli_on_path(LaunchableHarness::Codex) && codex_diag_detected);
    if show_codex_desktop {
        let subtitle = if desktop_apps.codex_desktop {
            "Install skill + configure Codex Desktop MCP".to_string()
        } else {
            "CLI 'codex' not on PATH · install skill + configure Codex MCP".to_string()
        };
        items.push(MainMenuItem {
            label: ManualGuideHarness::CodexDesktop.display_name().to_string(),
            tag: "install skill + guide",
            subtitle,
            action: MainMenuAction::ManualGuide(ManualGuideHarness::CodexDesktop),
        });
    }

    if desktop_apps.opencode_desktop {
        items.push(MainMenuItem {
            label: ManualGuideHarness::OpenCodeDesktop
                .display_name()
                .to_string(),
            tag: "install skill + guide",
            subtitle: "Install skill + open in OpenCode Desktop".to_string(),
            action: MainMenuAction::ManualGuide(ManualGuideHarness::OpenCodeDesktop),
        });
    }

    let cursor_diag_detected =
        find_diag("cursor").is_some_and(|d| d.detected || d.configured);
    let show_cursor_ide =
        !cli_on_path(LaunchableHarness::Cursor) && (desktop_apps.cursor_ide || cursor_diag_detected);
    if show_cursor_ide {
        let configured = find_diag("cursor").is_some_and(|d| d.configured);
        let suffix = if configured { " · configured" } else { "" };
        items.push(MainMenuItem {
            label: ManualGuideHarness::CursorIde.display_name().to_string(),
            tag: "install skill + guide",
            subtitle: format!("Install skill + open in Cursor Agent{suffix}"),
            action: MainMenuAction::ManualGuide(ManualGuideHarness::CursorIde),
        });
    }

    for (guide_harness, default_sub) in [
        (
            ManualGuideHarness::Openclaw,
            "Install skill + paste prompt in OpenClaw",
        ),
        (
            ManualGuideHarness::T3,
            "Install skill for Claude/Codex threads + paste prompt",
        ),
    ] {
        if let Some(diag) =
            find_diag(guide_harness.id()).filter(|d| d.detected || d.configured)
        {
            let subtitle = if diag.configured {
                format!("{default_sub} · configured")
            } else {
                default_sub.to_string()
            };
            items.push(MainMenuItem {
                label: guide_harness.display_name().to_string(),
                tag: "install skill + guide",
                subtitle,
                action: MainMenuAction::ManualGuide(guide_harness),
            });
        }
    }

    for lh in LaunchableHarness::ALL {
        if cli_on_path(lh) {
            continue;
        }
        // Codex, Cursor, and OpenCode Desktop cases are surfaced as dedicated Desktop/IDE entries.
        if matches!(lh, LaunchableHarness::Codex | LaunchableHarness::Cursor)
            || (lh == LaunchableHarness::Opencode && desktop_apps.opencode_desktop)
        {
            continue;
        }
        if let Some(diag) = find_diag(lh.id()).filter(|d| d.detected || d.configured) {
            let suffix = if diag.configured { " · configured" } else { "" };
            items.push(MainMenuItem {
                label: lh.display_name().to_string(),
                tag: "install skill + guide",
                subtitle: format!("CLI '{}' not on PATH{suffix}", lh.binary_name()),
                action: MainMenuAction::ManualGuide(ManualGuideHarness::ConfigOnlyCli(lh)),
            });
        }
    }

    // 4. Deterministic local CLI setup + background service install right here.
    let local_subtitle = if existing_node_id.is_some() {
        "Refresh local node, harnesses & background daemon here"
    } else {
        "Local node, keys, detected harnesses & background service"
    };
    items.push(MainMenuItem {
        label: "Quick local setup here".to_string(),
        tag: "local cli",
        subtitle: local_subtitle.to_string(),
        action: MainMenuAction::QuickLocalSetup,
    });

    items
}

/// Hermetic candidate detector taking explicit `home`, optional `config_path`, `PATH`,
/// optional macOS `apps_dir`, and optional Windows `appdata_dir` so unit tests never leak
/// host `/Applications`, `%APPDATA%`, or ambient `PATH`.
#[allow(dead_code)]
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
    let diagnostics = detect_harness_statuses(home, config_path);
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

fn is_skill_harness_detected(kind: HarnessKind, home: &Path, include_path_scan: bool) -> bool {
    let dir_detected = match kind {
        HarnessKind::Antigravity => {
            let gemini_dir = home.join(".gemini");
            gemini_dir.join("antigravity-cli").exists()
                || gemini_dir.join("config").exists()
                || (gemini_dir.is_dir() && !gemini_dir.join("settings.json").exists())
        }
        HarnessKind::Claude => home.join(".claude").exists() || home.join(".claude.json").exists(),
        HarnessKind::Codex => home.join(".codex").exists(),
        HarnessKind::Cursor => home.join(".cursor").exists(),
        HarnessKind::Opencode => home.join(".config").join("opencode").exists(),
        HarnessKind::Gemini => home.join(".gemini").join("settings.json").exists(),
        HarnessKind::Openclaw => home.join(".openclaw").exists(),
        HarnessKind::Herdr => {
            home.join(".config").join("herdr").exists()
                || home.join(".config").join("herdr-core").exists()
                || home.join(".herdr").exists()
        }
        HarnessKind::T3 => home.join(".t3").exists(),
    };
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

fn skill_paths_for_kind(kind: HarnessKind, home: &Path) -> Option<(PathBuf, Vec<PathBuf>)> {
    if let Some(lh) = launchable_from_kind(kind) {
        return Some((lh.primary_skill_path(home), lh.extra_skill_paths(home)));
    }
    match kind {
        HarnessKind::Openclaw => Some((
            ManualGuideHarness::Openclaw.primary_skill_path(home),
            ManualGuideHarness::Openclaw.extra_skill_paths(home),
        )),
        HarnessKind::T3 => Some((
            ManualGuideHarness::T3.primary_skill_path(home),
            ManualGuideHarness::T3.extra_skill_paths(home),
        )),
        HarnessKind::Herdr => None,
        _ => None,
    }
}

fn parse_skill_harness_selection(
    raw: Option<&str>,
    home: &Path,
    include_path_scan: bool,
) -> Result<Vec<HarnessKind>, String> {
    let spec = raw.unwrap_or("auto").trim().to_ascii_lowercase();
    if spec.is_empty() || spec == "auto" {
        let mut found = Vec::new();
        for kind in HarnessKind::ALL {
            if skill_paths_for_kind(kind, home).is_some()
                && is_skill_harness_detected(kind, home, include_path_scan)
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
            .filter(|&k| skill_paths_for_kind(k, home).is_some())
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

/// Installs the embedded `hyphae-setup/SKILL.md` for all specified harnesses (deduplicating paths).
pub fn install_setup_skill_for_harnesses(
    home: &Path,
    harnesses: &[HarnessKind],
) -> Result<Vec<InstalledSkillEntry>, String> {
    let mut entries = Vec::new();
    let mut written_paths = BTreeSet::new();

    for &kind in harnesses {
        let Some((primary, extras)) = skill_paths_for_kind(kind, home) else {
            continue;
        };
        if written_paths.insert(primary.clone()) {
            write_atomic_file(&primary, HYPHAE_SETUP_SKILL_MD.as_bytes(), false)?;
        }
        let mut written_extras = Vec::new();
        for extra in extras {
            if written_paths.insert(extra.clone()) {
                write_atomic_file(&extra, HYPHAE_SETUP_SKILL_MD.as_bytes(), false)?;
            }
            written_extras.push(extra.display().to_string());
        }
        entries.push(InstalledSkillEntry {
            harness: kind.as_str().to_string(),
            path: primary.display().to_string(),
            extra_paths: written_extras,
        });
    }

    // If `<home>/.agents` already exists and wasn't populated yet (e.g., Codex/T3 not detected),
    // also populate `<home>/.agents/skills/hyphae-setup/SKILL.md` for cross-tool discovery.
    let agents_skill = home
        .join(".agents")
        .join("skills")
        .join("hyphae-setup")
        .join("SKILL.md");
    if home.join(".agents").is_dir() && written_paths.insert(agents_skill.clone()) {
        write_atomic_file(&agents_skill, HYPHAE_SETUP_SKILL_MD.as_bytes(), false)?;
        entries.push(InstalledSkillEntry {
            harness: "agents".to_string(),
            path: agents_skill.display().to_string(),
            extra_paths: Vec::new(),
        });
    }

    Ok(entries)
}

/// Entrypoint for `hyp onboard --install-skill`.
pub fn run_install_skill(
    home: &Path,
    explicit_home: bool,
    harness_spec: Option<&str>,
    as_json: bool,
) -> ExitCode {
    let cmd = "onboard";
    let include_path_scan = !explicit_home;
    let targets = match parse_skill_harness_selection(harness_spec, home, include_path_scan) {
        Ok(t) => t,
        Err(e) => {
            return emit_error(
                cmd,
                as_json,
                EXIT_USAGE,
                "INVALID_HARNESS",
                e,
                Some(
                    "Use --harness all, auto, or one of: claude, codex, antigravity (agy), opencode, cursor, gemini, openclaw, t3."
                        .to_string(),
                ),
            );
        }
    };

    let installed = match install_setup_skill_for_harnesses(home, &targets) {
        Ok(v) => v,
        Err(e) => {
            return emit_error(cmd, as_json, EXIT_ERROR, "SKILL_INSTALL_FAILED", e, None);
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
        "Installed 'hyphae-setup' skill for {} harness target(s)",
        installed.len()
    );
    let next = if installed.is_empty() {
        vec![format!(
            "hyp onboard --install-skill --harness all --home {}",
            home.display()
        )]
    } else {
        vec![
            "Open any configured agent harness and invoke the 'hyphae-setup' skill.".to_string(),
            "Or run `hyp onboard --assist` to launch guided setup directly.".to_string(),
        ]
    };

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: cmd.to_string(),
            summary: Some(summary),
            data: Some(json!({
                "mode": "install-skill",
                "skill": "hyphae-setup",
                "home": home.display().to_string(),
                "installedCount": installed.len(),
                "installed": installed,
            })),
            warnings,
            next,
            error: None,
        };
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

    ExitCode::from(EXIT_OK)
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
            "Load and follow the hyphae-setup skill (installed at {path_str}) to inspect my existing Hyphae node ({node_id}) and help me update my harnesses, peers, hubs, streams, bridges, or security gates."
        )
    } else {
        format!(
            "Load and follow the hyphae-setup skill (installed at {path_str}) to onboard me to Hyphae and configure my local node, harnesses, and any peers, hubs, streams, bridges, or security gates I want."
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
            "Load and follow the hyphae-setup skill to inspect my existing Hyphae node ({node_id}) and configure my harnesses, peers, and transports."
        );
    }
    match harness {
        ManualGuideHarness::ClaudeDesktop
        | ManualGuideHarness::CodexDesktop
        | ManualGuideHarness::OpenCodeDesktop
        | ManualGuideHarness::CursorIde => {
            "Set up Hyphae on this machine using the hyphae-setup skill".to_string()
        }
        ManualGuideHarness::Openclaw
        | ManualGuideHarness::T3
        | ManualGuideHarness::ConfigOnlyCli(_) => {
            "Load and follow the hyphae-setup skill to onboard me to Hyphae and configure my local node, harnesses, and transports."
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

fn resolve_t3_url_from_home(home: &Path, existing_node: Option<&ExistingNodeInfo>) -> Option<String> {
    let t3_file = home.join(".t3").join("hyphae.json");
    if let Ok(raw) = fs::read_to_string(&t3_file) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
            if let Some(url) = val
                .get("hyphae")
                .and_then(|h| h.get("url"))
                .and_then(serde_json::Value::as_str)
            {
                if let Some(clean) = sanitize_http_url(Some(url)) {
                    return Some(clean);
                }
            }
        }
    }
    if let Some(node) = existing_node {
        if let Ok(raw) = fs::read_to_string(&node.config_path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
                if let Some(url) = val
                    .get("t3")
                    .and_then(|t| t.get("url"))
                    .and_then(serde_json::Value::as_str)
                {
                    if let Some(clean) = sanitize_http_url(Some(url)) {
                        return Some(clean);
                    }
                }
            }
        }
    }
    None
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
    as_json: bool,
) -> ExitCode {
    let spec = harness.build_launch_spec(prompt);
    let mut cmd = Command::new(exe_path);
    cmd.args(&spec.args);
    attach_interactive_stdio(&mut cmd);

    match status_retrying_busy(&mut cmd) {
        Ok(status) => match status.code() {
            Some(code) => ExitCode::from((code.clamp(0, 255)) as u8),
            None => ExitCode::from(EXIT_ERROR),
        },
        Err(e) => emit_error(
            "onboard",
            as_json,
            EXIT_ERROR,
            "LAUNCH_FAILED",
            format!(
                "Failed to launch {} ({}): {e}",
                harness.display_name(),
                exe_path.display()
            ),
            Some("Run `hyp onboard --yes` for quick local CLI setup.".to_string()),
        ),
    }
}

fn spawn_herdr_template(
    hc_bin: &Path,
    template_name: &str,
    prompt: &str,
    as_json: bool,
) -> ExitCode {
    let mut cmd = build_herdr_template_launch_command(hc_bin, template_name, prompt);
    cmd.stdin(Stdio::null());

    let output = match output_retrying_busy(&mut cmd) {
        Ok(out) => out,
        Err(e) => {
            return emit_error(
                "onboard",
                as_json,
                EXIT_ERROR,
                "HERDR_LAUNCH_FAILED",
                format!(
                    "Failed to launch Herdr template '{template_name}' via {}: {e}",
                    hc_bin.display()
                ),
                Some(
                    "Run `hc templates` to verify Herdr, or `hyp onboard --yes` for local CLI setup."
                        .to_string(),
                ),
            );
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
        return emit_error(
            "onboard",
            as_json,
            EXIT_ERROR,
            "HERDR_LAUNCH_FAILED",
            detail,
            Some(
                "Run `hc templates` to verify Herdr, or `hyp onboard --yes` for local CLI setup."
                    .to_string(),
            ),
        );
    }

    let stdout_raw = String::from_utf8_lossy(&output.stdout);
    let Some(address) = parse_herdr_run_address_json(&stdout_raw) else {
        let snippet = truncate_chars(stdout_raw.trim(), 200);
        return emit_error(
            "onboard",
            as_json,
            EXIT_ERROR,
            "HERDR_LAUNCH_FAILED",
            format!(
                "Herdr launched template '{template_name}' but returned no valid terminal address (stdout: {snippet})"
            ),
            Some("Run `hc list` to inspect running Herdr terminals.".to_string()),
        );
    };

    let next = vec![format!("hc attach {address}")];
    let summary = format!(
        "Launched Herdr template '{template_name}' in terminal {address}"
    );

    if as_json {
        let envelope = JsonEnvelope {
            ok: true,
            command: "onboard".to_string(),
            summary: Some(summary),
            data: Some(json!({
                "mode": "herdr_launch",
                "template": template_name,
                "terminal": address,
            })),
            warnings: Vec::new(),
            next,
            error: None,
        };
        print_json(&envelope);
        return ExitCode::from(EXIT_OK);
    }

    if !io::stdout().is_terminal() {
        println!("OK    {summary}");
        println!("      Template: {template_name}");
        println!("      Terminal: {address}");
        print_next_steps(&next);
        return ExitCode::from(EXIT_OK);
    }

    println!("Launched Herdr terminal {address} — attaching (Ctrl+\\ to detach)...");
    let mut attach_cmd = build_herdr_attach_command(hc_bin, &address);
    match status_retrying_busy(&mut attach_cmd) {
        Ok(status) => match status.code() {
            Some(code) => ExitCode::from((code.clamp(0, 255)) as u8),
            None => ExitCode::from(EXIT_ERROR),
        },
        Err(e) => emit_error(
            "onboard",
            false,
            EXIT_ERROR,
            "HERDR_LAUNCH_FAILED",
            format!(
                "Launched Herdr terminal '{address}', but failed to attach via {}: {e}",
                hc_bin.display()
            ),
            Some(format!("Attach manually with: hc attach {address}")),
        ),
    }
}

fn collect_skill_targets_with_primary(
    primary: Option<HarnessKind>,
    home: &Path,
    explicit_home: bool,
) -> Vec<HarnessKind> {
    let mut targets = Vec::new();
    if let Some(kind) = primary {
        targets.push(kind);
    }
    let include_path_scan = !explicit_home;
    for kind in HarnessKind::ALL {
        if !targets.contains(&kind)
            && skill_paths_for_kind(kind, home).is_some()
            && is_skill_harness_detected(kind, home, include_path_scan)
        {
            targets.push(kind);
        }
    }
    targets
}

fn print_installed_skills_banner(installed: &[InstalledSkillEntry]) {
    println!();
    println!("Installed 'hyphae-setup' skill:");
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
    existing_node: Option<&ExistingNodeInfo>,
    cli_bin: &str,
    as_json: bool,
) -> ExitCode {
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
            existing_node,
            cli_bin,
            as_json,
        );
    };

    let targets = collect_skill_targets_with_primary(Some(chosen.kind()), home, explicit_home);
    let installed = match install_setup_skill_for_harnesses(home, &targets) {
        Ok(v) => v,
        Err(e) => {
            return emit_error("onboard", as_json, EXIT_ERROR, "SKILL_INSTALL_FAILED", e, None);
        }
    };

    let primary_skill = chosen.primary_skill_path(home);
    if !as_json {
        print_installed_skills_banner(&installed);
        println!();
        println!(
            "Launching {} ({})...",
            chosen.display_name(),
            chosen.binary_name()
        );
    }

    let prompt = build_onboarding_prompt(
        &primary_skill,
        existing_node.map(|n| n.node_id.as_str()),
    );
    spawn_interactive_harness(chosen, &exe_path, &prompt, as_json)
}

fn install_and_handoff_herdr(
    hc_bin: &Path,
    template: &HerdrTemplate,
    home: &Path,
    explicit_home: bool,
    existing_node: Option<&ExistingNodeInfo>,
    as_json: bool,
) -> ExitCode {
    let inferred = infer_harness_from_herdr_template(&template.name, &template.command);
    let targets = collect_skill_targets_with_primary(
        inferred.map(LaunchableHarness::kind),
        home,
        explicit_home,
    );

    let mut installed = match install_setup_skill_for_harnesses(home, &targets) {
        Ok(v) => v,
        Err(e) => {
            return emit_error("onboard", as_json, EXIT_ERROR, "SKILL_INSTALL_FAILED", e, None);
        }
    };

    let primary_skill = if let Some(lh) = inferred {
        lh.primary_skill_path(home)
    } else if let Some(first) = installed.first() {
        PathBuf::from(&first.path)
    } else {
        // Fallback cross-tool location when template name doesn't name a known harness and no
        // harness dirs exist under `home` yet.
        let fallback = home
            .join(".agents")
            .join("skills")
            .join("hyphae-setup")
            .join("SKILL.md");
        if let Err(e) = write_atomic_file(&fallback, HYPHAE_SETUP_SKILL_MD.as_bytes(), false) {
            return emit_error("onboard", as_json, EXIT_ERROR, "SKILL_INSTALL_FAILED", e, None);
        }
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

    let prompt = build_onboarding_prompt(
        &primary_skill,
        existing_node.map(|n| n.node_id.as_str()),
    );
    spawn_herdr_template(hc_bin, &template.name, &prompt, as_json)
}

fn install_manual_guide_skills(
    harness: ManualGuideHarness,
    home: &Path,
    explicit_home: bool,
) -> Result<(PathBuf, Vec<InstalledSkillEntry>), String> {
    let targets = collect_skill_targets_with_primary(Some(harness.kind()), home, explicit_home);
    let mut installed = install_setup_skill_for_harnesses(home, &targets)?;

    // Ensure harness-specific extra cross-tool skill paths (e.g. OpenCode Desktop `~/.agents`)
    // are also written and recorded cleanly without duplicates.
    let mut already_recorded: BTreeSet<String> = BTreeSet::new();
    for item in &installed {
        already_recorded.insert(item.path.clone());
        for extra in &item.extra_paths {
            already_recorded.insert(extra.clone());
        }
    }
    for extra in harness.extra_skill_paths(home) {
        let extra_str = extra.display().to_string();
        if already_recorded.insert(extra_str.clone()) {
            write_atomic_file(&extra, HYPHAE_SETUP_SKILL_MD.as_bytes(), false)?;
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

    Ok((harness.primary_skill_path(home), installed))
}

fn print_manual_guide_plain(
    harness: ManualGuideHarness,
    home: &Path,
    primary_skill: &Path,
    installed: &[InstalledSkillEntry],
    prompt: &str,
    mcp_status: &DesktopMcpStatus,
    deeplink: Option<&str>,
) {
    println!();
    println!(
        "OK    Installed 'hyphae-setup' skill to {}",
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
            println!("OK    MCP config already configured at {}", cfg_path.display());
        }
        DesktopMcpStatus::Skipped | DesktopMcpStatus::NotApplicable => {
            if let Some((cfg_path, snippet)) = harness.mcp_config_note(home) {
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
    existing_node: Option<&ExistingNodeInfo>,
    cli_bin: &str,
    as_json: bool,
) -> ExitCode {
    let (primary_skill, installed) = match install_manual_guide_skills(harness, home, explicit_home)
    {
        Ok(res) => res,
        Err(e) => {
            return emit_error("onboard", as_json, EXIT_ERROR, "SKILL_INSTALL_FAILED", e, None);
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
    let mcp_note = harness.mcp_config_note(home);
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
            "skill": "hyphae-setup",
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
        let envelope = JsonEnvelope {
            ok: true,
            command: "onboard".to_string(),
            summary: Some(format!(
                "Installed 'hyphae-setup' skill for {} (manual handoff guide)",
                harness.display_name()
            )),
            data: Some(data),
            warnings: Vec::new(),
            next: steps,
            error: None,
        };
        print_json(&envelope);
        return ExitCode::from(EXIT_OK);
    }

    print_manual_guide_plain(
        harness,
        home,
        &primary_skill,
        &installed,
        &prompt,
        &mcp_status,
        deeplink.as_deref(),
    );
    ExitCode::from(EXIT_OK)
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

#[cfg(unix)]
enum TuiResolution {
    Cancel,
    RunLocalCliSetup,
    LaunchCli(LaunchableHarness),
    LaunchHerdr {
        hc_bin: PathBuf,
        template: HerdrTemplate,
    },
    ManualGuideDone {
        harness: ManualGuideHarness,
        primary_skill: PathBuf,
        installed: Vec<InstalledSkillEntry>,
        prompt: String,
        mcp_status: DesktopMcpStatus,
        deeplink: Option<String>,
    },
    Error(String),
}

/// Composes a bordered compact dot-matrix mycelium banner for the top of the fullscreen menu.
#[cfg_attr(not(unix), allow(dead_code))]
fn build_banner_lines_at_tick(
    term_rows: usize,
    term_cols: usize,
    content_w: usize,
    color_mode: ColorMode,
    anim_tick: usize,
) -> Vec<String> {
    if term_rows < 20 || term_cols < 44 || content_w < 30 {
        return Vec::new();
    }
    let banner_h = if term_rows >= 34 {
        11
    } else if term_rows >= 28 {
        9
    } else {
        7
    };
    let max_banner_w = content_w.saturating_sub(4).min(66);
    if max_banner_w < 24 {
        return Vec::new();
    }
    let banner_w = max_banner_w;
    let art = render_mycelium_frame_at_phase(
        DEFAULT_TOTAL_FRAMES - 1,
        DEFAULT_TOTAL_FRAMES,
        anim_tick,
        banner_w,
        banner_h,
        color_mode,
    );

    let border_fg = fg_color(color_mode, RGB_UI_BORDER);
    let reset = style_reset(color_mode);
    let horiz = "─".repeat(banner_w + 2);
    let box_outer_w = banner_w + 4;
    let left_pad = " ".repeat(term_cols.saturating_sub(box_outer_w) / 2);

    let mut lines = Vec::with_capacity(banner_h + 2);
    lines.push(format!("{left_pad}{border_fg}╭{horiz}╮{reset}"));
    for art_row in art.lines() {
        lines.push(format!(
            "{left_pad}{border_fg}│{reset} {art_row} {border_fg}│{reset}"
        ));
    }
    lines.push(format!("{left_pad}{border_fg}╰{horiz}╯{reset}"));
    lines
}

#[cfg_attr(not(unix), allow(dead_code))]
fn format_menu_row(
    selected: bool,
    label: &str,
    tag: Option<(&str, TagTone)>,
    subtitle: &str,
    box_width: usize,
    left_pad: &str,
    color_mode: ColorMode,
) -> String {
    let inner_w = box_width.saturating_sub(2).max(16);
    let prefix = if selected { " ❯ " } else { "   " };
    let tag_text = tag.map(|(t, _)| format!("[{t}]")).unwrap_or_default();

    let prefix_len = 3usize;
    let label_max = if tag.is_some() {
        (inner_w / 2)
            .clamp(12, 28)
            .min(inner_w.saturating_sub(4).max(1))
    } else {
        let sub_reserve = if subtitle.is_empty() {
            0
        } else {
            subtitle.chars().count().min(22) + 4
        };
        inner_w
            .saturating_sub(prefix_len + sub_reserve + 1)
            .max((inner_w / 2).min(inner_w.saturating_sub(prefix_len).max(1)))
    };
    let label_str = truncate_chars(label, label_max);
    let label_len = label_str.chars().count();
    let tag_len = tag_text.chars().count();
    let used = prefix_len + label_len + if tag_len > 0 { 2 + tag_len } else { 0 };
    let rem_for_sub = inner_w.saturating_sub(used + 3);
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
                let mut line = format!("{prefix}{label_str}");
                if !tag_text.is_empty() {
                    line.push_str("  ");
                    line.push_str(&tag_text);
                }
                if !sub_str.is_empty() {
                    line.push_str("  ");
                    line.push_str(&sub_str);
                }
                format!("{left_pad}\x1b[7m{line}{trailing}\x1b[0m")
            }
            ColorMode::Ansi256 => {
                let mut line = format!("{prefix}{label_str}");
                if !tag_text.is_empty() {
                    line.push_str("  ");
                    line.push_str(&tag_text);
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

                let mut row = format!("{left_pad}{bg}{amber}\x1b[1m{prefix}{ivory}{label_str}\x1b[22m");
                if !tag_text.is_empty() {
                    row.push_str(&format!("  {tag_fg}{tag_text}"));
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
        let tag_styled = match tag {
            Some((_, TagTone::Launch)) => {
                paint_styled_text(color_mode, RGB_UI_TAG_LAUNCH, false, &tag_text)
            }
            Some((_, TagTone::Guide)) => {
                paint_styled_text(color_mode, RGB_UI_TAG_GUIDE, false, &tag_text)
            }
            Some((_, TagTone::Local)) => {
                paint_styled_text(color_mode, RGB_UI_TAG_LOCAL, false, &tag_text)
            }
            None => String::new(),
        };
        let sub_styled = paint_styled_text(color_mode, RGB_UI_MUTED, false, &sub_str);

        let mut row = format!("{left_pad}{prefix}{label_styled}");
        if !tag_text.is_empty() {
            row.push_str("  ");
            row.push_str(&tag_styled);
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
    in_herdr_env: Option<&str>,
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

    let version = env!("CARGO_PKG_VERSION");
    let header_title = if let Some(node_id) = existing_node_id {
        let legacy = if is_legacy_v1 { " · legacy v1" } else { "" };
        format!("hyphae v{version} · configure existing node ({node_id}{legacy})")
    } else {
        format!("hyphae v{version} · interactive onboarding")
    };
    lines.push(format!(
        "{left_pad}{}",
        paint_styled_text(
            color_mode,
            RGB_PULSE_IVORY,
            true,
            &truncate_chars(&header_title, content_w)
        )
    ));
    if let Some(herdr_id) = in_herdr_env.filter(|s| !s.trim().is_empty()) {
        let note = format!("Herdr ({}) · templates launch & attach directly", herdr_id.trim());
        lines.push(format!(
            "{left_pad}{}",
            paint_styled_text(
                color_mode,
                RGB_NODE_AMBER,
                false,
                &truncate_chars(&note, content_w)
            )
        ));
    }
    lines.push(format!(
        "{left_pad}{}",
        paint_styled_text(
            color_mode,
            RGB_HYPHAE_SAGE,
            false,
            &truncate_chars(
                "Select a detected agent harness or run local CLI setup:",
                content_w
            )
        )
    ));
    lines.push(String::new());

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

    for idx in win.start..win.end {
        if let Some(tmpl) = templates.get(idx) {
            lines.push(format_menu_row(
                idx == selected,
                tmpl.display_title(),
                None,
                &tmpl.display_subtitle(),
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
        templates,
        selected,
        allow_back,
        term_rows,
        term_cols,
        color_mode,
        anim_tick,
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
        "✓ Installed hyphae-setup skill to {}",
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

    let options = [
        ("Apply MCP config & continue", "merge safely"),
        ("Skip config write (I'll edit manually)", "show snippet"),
    ];
    for (idx, (label, sub)) in options.iter().enumerate() {
        lines.push(format_menu_row(
            idx == selected_option,
            label,
            None,
            sub,
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

    let title = format!("{} · Skill Installed & Handoff Guide", harness.display_name());
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
        "✓ Installed hyphae-setup skill to {}",
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
        if let Some((cfg_path, snippet)) = harness.mcp_config_note(home) {
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

    for (idx, (label, sub)) in actions.iter().enumerate() {
        lines.push(format_menu_row(
            idx == selected_action,
            label,
            None,
            sub,
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
    existing_node: Option<&ExistingNodeInfo>,
    in_herdr_env: Option<&str>,
    cli_bin: &str,
    play_intro: bool,
    animate_banner: bool,
) -> Option<TuiResolution> {
    let color_mode = detect_color_mode();
    let (mut term_rows, mut term_cols) = detect_terminal_size();

    let mut alt = AltScreenGuard::enter_if(true);
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
        return Some(TuiResolution::Cancel);
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
            match raw.read_key_timeout() {
                Ok(Some(k)) => k,
                Ok(None) => {
                    anim_tick = anim_tick.wrapping_add(1);
                    continue;
                }
                Err(e) => break TuiResolution::Error(format!("Failed reading TTY input: {e}")),
            }
        } else {
            match raw.read_key() {
                Ok(k) => k,
                Err(e) => break TuiResolution::Error(format!("Failed reading TTY input: {e}")),
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
                        break TuiResolution::Cancel;
                    }
                    KeyEvent::Enter => {
                        let idx = *selected;
                        let Some(item) = main_items.get(idx) else {
                            break TuiResolution::Cancel;
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
                                break TuiResolution::LaunchHerdr {
                                    hc_bin: hc_bin.clone(),
                                    template: template.clone(),
                                };
                            }
                            MainMenuAction::LaunchCli(lh) => {
                                break TuiResolution::LaunchCli(*lh);
                            }
                            MainMenuAction::ManualGuide(mh) => {
                                match install_manual_guide_skills(*mh, home, explicit_home) {
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
                                    Err(e) => break TuiResolution::Error(e),
                                }
                            }
                            MainMenuAction::QuickLocalSetup => {
                                break TuiResolution::RunLocalCliSetup;
                            }
                        }
                    }
                    _ => {}
                }
            }
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
                            break TuiResolution::Cancel;
                        }
                    }
                    KeyEvent::Cancel => {
                        break TuiResolution::Cancel;
                    }
                    KeyEvent::Enter => {
                        if let Some(tmpl) = templates.get(*selected).cloned() {
                            break TuiResolution::LaunchHerdr {
                                hc_bin: hc_bin.clone(),
                                template: tmpl,
                            };
                        } else if *allow_back {
                            let prev = *main_selected;
                            screen = WizardScreen::Main { selected: prev };
                        } else {
                            break TuiResolution::Cancel;
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
                        break TuiResolution::Cancel;
                    }
                }
                KeyEvent::Cancel => {
                    break TuiResolution::Cancel;
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
                            break TuiResolution::ManualGuideDone {
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
                        break TuiResolution::ManualGuideDone {
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
                            break TuiResolution::ManualGuideDone {
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

#[cfg(unix)]
fn execute_tui_resolution(
    resolution: TuiResolution,
    home: &Path,
    explicit_home: bool,
    existing_node: Option<&ExistingNodeInfo>,
    cli_bin: &str,
) -> WizardOutcome {
    match resolution {
        TuiResolution::Cancel => WizardOutcome::Finished(ExitCode::from(EXIT_OK)),
        TuiResolution::RunLocalCliSetup => WizardOutcome::RunLocalCliSetup,
        TuiResolution::LaunchCli(lh) => {
            let code =
                install_and_handoff_cli(lh, home, explicit_home, existing_node, cli_bin, false);
            WizardOutcome::Finished(code)
        }
        TuiResolution::LaunchHerdr { hc_bin, template } => {
            let code = install_and_handoff_herdr(
                &hc_bin,
                &template,
                home,
                explicit_home,
                existing_node,
                false,
            );
            WizardOutcome::Finished(code)
        }
        TuiResolution::ManualGuideDone {
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
                &primary_skill,
                &installed,
                &prompt,
                &mcp_status,
                deeplink.as_deref(),
            );
            WizardOutcome::Finished(ExitCode::from(EXIT_OK))
        }
        TuiResolution::Error(msg) => WizardOutcome::Finished(emit_error(
            "onboard",
            false,
            EXIT_ERROR,
            "WIZARD_ERROR",
            msg,
            Some("Re-run with `hyp onboard --yes` for local CLI setup.".to_string()),
        )),
    }
}

// ============================================================================
// Cross-Platform Numbered Line Fallback (Windows & Non-Raw Terminals)
// ============================================================================

fn read_tty_line(prompt: &str) -> io::Result<Option<String>> {
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
    home: &Path,
    explicit_home: bool,
    existing_node: Option<&ExistingNodeInfo>,
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
            Ok(None) => return Some(WizardOutcome::Finished(ExitCode::from(EXIT_OK))),
            Err(_) => return None,
        };
        if reply.is_empty() {
            let code = install_and_handoff_herdr(
                hc_bin,
                &templates[0],
                home,
                explicit_home,
                existing_node,
                false,
            );
            return Some(WizardOutcome::Finished(code));
        }
        if matches!(reply.as_str(), "b" | "back") {
            return None;
        }
        if matches!(reply.as_str(), "q" | "quit") {
            return Some(WizardOutcome::Finished(ExitCode::from(EXIT_OK)));
        }
        if let Some(n) = reply
            .parse::<usize>()
            .ok()
            .filter(|n| (1..=templates.len()).contains(n))
        {
            let code = install_and_handoff_herdr(
                hc_bin,
                &templates[n - 1],
                home,
                explicit_home,
                existing_node,
                false,
            );
            return Some(WizardOutcome::Finished(code));
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
    println!("  [1] Apply MCP config & continue");
    println!("  [2] Skip config write (I'll edit manually)");
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
    existing_node: Option<&ExistingNodeInfo>,
    cli_bin: &str,
    allow_back: bool,
) -> Option<WizardOutcome> {
    let (primary_skill, installed) = match install_manual_guide_skills(harness, home, explicit_home)
    {
        Ok(res) => res,
        Err(e) => {
            return Some(WizardOutcome::Finished(emit_error(
                "onboard",
                false,
                EXIT_ERROR,
                "SKILL_INSTALL_FAILED",
                e,
                None,
            )));
        }
    };

    let mcp_status = match run_plain_tty_desktop_mcp_confirm(harness, home, cli_bin, allow_back) {
        PlainMcpConfirmOutcome::Status(st) => st,
        PlainMcpConfirmOutcome::Back => return None,
        PlainMcpConfirmOutcome::Quit => {
            return Some(WizardOutcome::Finished(ExitCode::from(EXIT_OK)));
        }
    };

    let prompt = build_manual_guide_prompt(harness, existing_node.map(|n| n.node_id.as_str()));
    let deeplink =
        resolve_manual_guide_deeplink(harness, &prompt, home, explicit_home, existing_node);
    print_manual_guide_plain(
        harness,
        home,
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
    Some(WizardOutcome::Finished(ExitCode::from(EXIT_OK)))
}

fn run_numbered_fallback_wizard(
    args: &OnboardArgs,
    home: &Path,
    main_items: &[MainMenuItem],
    existing_node: Option<&ExistingNodeInfo>,
    in_herdr_env: Option<&str>,
    cli_bin: &str,
) -> WizardOutcome {
    play_mycelium_animation(args.no_anim);

    let version = env!("CARGO_PKG_VERSION");
    println!();
    if let Some(existing) = existing_node {
        let legacy_tag = if existing.is_legacy_v1 { " · legacy v1" } else { "" };
        println!(
            "hyphae v{version} · interactive setup (existing node: {}{legacy_tag})",
            existing.node_id
        );
        println!("  Config: {}", existing.config_path.display());
    } else {
        println!("hyphae v{version} · interactive setup");
    }
    if let Some(herdr_id) = in_herdr_env.filter(|s| !s.trim().is_empty()) {
        println!(
            "  Herdr ({}) · templates launch & attach directly",
            herdr_id.trim()
        );
    }

    loop {
        println!();
        println!("Choose how to set up Hyphae:");
        for (idx, item) in main_items.iter().enumerate() {
            println!(
                "  [{}] {} [{}] — {}",
                idx + 1,
                item.label,
                item.tag,
                item.subtitle
            );
        }
        println!("  [q] Quit");
        println!();

        let reply = match read_tty_line("Selection [1]: ") {
            Ok(Some(line)) => line.trim().to_ascii_lowercase(),
            Ok(None) => return WizardOutcome::Finished(ExitCode::from(EXIT_OK)),
            Err(e) => {
                return WizardOutcome::Finished(emit_error(
                    "onboard",
                    false,
                    EXIT_ERROR,
                    "TTY_READ_ERROR",
                    format!("Failed reading interactive selection: {e}"),
                    Some("Re-run with `hyp onboard --yes` for non-interactive setup.".to_string()),
                ));
            }
        };

        if matches!(reply.as_str(), "q" | "quit") {
            println!("Cancelled.");
            return WizardOutcome::Finished(ExitCode::from(EXIT_OK));
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
                if let Some(outcome) = run_numbered_herdr_fallback(
                    hc_bin,
                    templates,
                    home,
                    args.home.is_some(),
                    existing_node,
                ) {
                    return outcome;
                }
            }
            MainMenuAction::LaunchHerdrTemplate { hc_bin, template } => {
                let code = install_and_handoff_herdr(
                    hc_bin,
                    template,
                    home,
                    args.home.is_some(),
                    existing_node,
                    false,
                );
                return WizardOutcome::Finished(code);
            }
            MainMenuAction::LaunchCli(lh) => {
                let code = install_and_handoff_cli(
                    *lh,
                    home,
                    args.home.is_some(),
                    existing_node,
                    cli_bin,
                    false,
                );
                return WizardOutcome::Finished(code);
            }
            MainMenuAction::ManualGuide(mh) => {
                if let Some(outcome) = run_plain_tty_manual_guide(
                    *mh,
                    home,
                    args.home.is_some(),
                    existing_node,
                    cli_bin,
                    true,
                ) {
                    return outcome;
                }
            }
            MainMenuAction::QuickLocalSetup => return WizardOutcome::RunLocalCliSetup,
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
        || args.bin.is_some()
        || args.harness.is_some()
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

    let main_items = detect_candidates_in_with_env(
        home,
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
            existing_node.as_ref(),
            herdr_env.as_deref(),
            &cli_bin,
            animate,
            animate,
        ) {
            return execute_tui_resolution(
                resolution,
                home,
                args.home.is_some(),
                existing_node.as_ref(),
                &cli_bin,
            );
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
            let code = install_and_handoff_cli(
                chosen,
                home,
                args.home.is_some(),
                existing_node.as_ref(),
                &cli_bin,
                args.json,
            );
            return WizardOutcome::Finished(code);
        }
        // Check detected non-launchable harnesses (OpenClaw / T3) before failing.
        let existing_node = detect_existing_node(args, home);
        let diagnostics = detect_harness_statuses(
            home,
            existing_node.as_ref().map(|n| n.config_path.as_path()),
        );
        for guide in [ManualGuideHarness::Openclaw, ManualGuideHarness::T3] {
            if diagnostics
                .iter()
                .any(|d| d.harness == guide.id() && (d.detected || d.configured))
            {
                let code = install_and_emit_manual_guide(
                    guide,
                    home,
                    args.home.is_some(),
                    existing_node.as_ref(),
                    &cli_bin,
                    args.json,
                );
                return WizardOutcome::Finished(code);
            }
        }
        return WizardOutcome::Finished(emit_error(
            "onboard",
            args.json,
            EXIT_ERROR,
            "NO_LAUNCHABLE_HARNESS",
            "No interactive agent CLI (claude, codex, agy, opencode, cursor-agent, gemini) found on PATH",
            Some(
                "Run `hyp onboard --yes` for local CLI onboarding, or install an agent CLI."
                    .to_string(),
            ),
        ));
    }

    // 1. Direct Herdr template handoff: `--assist herdr:<template>` or interactive `--assist herdr`.
    let lower = trimmed.to_ascii_lowercase();
    if lower == "herdr" || lower.starts_with("herdr:") {
        let Some(hc_bin) = find_executable_in_path("hc") else {
            return WizardOutcome::Finished(emit_error(
                "onboard",
                args.json,
                EXIT_ERROR,
                "HERDR_CLI_NOT_FOUND",
                "Could not find 'hc' on PATH for Herdr launch templates",
                Some("Install Herdr (`hc`) or run `hyp onboard --yes` for local CLI setup.".to_string()),
            ));
        };

        let existing_node = detect_existing_node(args, home);
        let discovered = discover_herdr_templates(&hc_bin);

        if lower == "herdr" {
            if discovered.is_empty() {
                return WizardOutcome::Finished(emit_error(
                    "onboard",
                    args.json,
                    EXIT_ERROR,
                    "HERDR_NO_TEMPLATES",
                    "Herdr (`hc templates --json`) returned no launch templates",
                    Some("Create a template under ~/.config/herdr-core/templates or pass `--assist <harness>`.".to_string()),
                ));
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
                    existing_node.as_ref(),
                    None,
                    &cli_bin,
                    animate,
                    animate,
                ) {
                    return execute_tui_resolution(
                        resolution,
                        home,
                        args.home.is_some(),
                        existing_node.as_ref(),
                        &cli_bin,
                    );
                }
            }
            if io::stdout().is_terminal() && !args.json {
                if let Some(outcome) = run_numbered_herdr_fallback(
                    &hc_bin,
                    &discovered,
                    home,
                    args.home.is_some(),
                    existing_node.as_ref(),
                ) {
                    return outcome;
                }
                return WizardOutcome::Finished(ExitCode::from(EXIT_OK));
            }
            let names: Vec<&str> = discovered.iter().map(|t| t.name.as_str()).collect();
            return WizardOutcome::Finished(emit_error(
                "onboard",
                args.json,
                EXIT_USAGE,
                "HERDR_TEMPLATE_REQUIRED",
                "Specify a Herdr launch template in non-interactive mode: `--assist herdr:<template>`",
                Some(format!("Available templates: {}", names.join(", "))),
            ));
        }

        let tmpl_name = trimmed[6..].trim();
        if tmpl_name.is_empty() {
            return WizardOutcome::Finished(emit_error(
                "onboard",
                args.json,
                EXIT_USAGE,
                "INVALID_ASSIST_HARNESS",
                "Empty Herdr template name in `--assist herdr:`",
                Some("Example: hyp onboard --assist herdr:claude-gateway".to_string()),
            ));
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
        let code = install_and_handoff_herdr(
            &hc_bin,
            &template,
            home,
            args.home.is_some(),
            existing_node.as_ref(),
            args.json,
        );
        return WizardOutcome::Finished(code);
    }

    // 2. Non-launchable manual guide harnesses:
    //    `--assist claude-desktop|codex-desktop|opencode-desktop|cursor-ide|openclaw|t3`.
    if let Some(guide_harness) = ManualGuideHarness::parse_alias(trimmed) {
        let existing_node = detect_existing_node(args, home);

        #[cfg(unix)]
        if io::stdout().is_terminal() && !args.json {
            match install_manual_guide_skills(guide_harness, home, args.home.is_some()) {
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
                        existing_node.as_ref(),
                        None,
                        &cli_bin,
                        animate,
                        animate,
                    ) {
                        return execute_tui_resolution(
                            resolution,
                            home,
                            args.home.is_some(),
                            existing_node.as_ref(),
                            &cli_bin,
                        );
                    }
                }
                Err(e) => {
                    return WizardOutcome::Finished(emit_error(
                        "onboard",
                        false,
                        EXIT_ERROR,
                        "SKILL_INSTALL_FAILED",
                        e,
                        None,
                    ));
                }
            }
        }

        if io::stdout().is_terminal() && !args.json {
            if let Some(outcome) = run_plain_tty_manual_guide(
                guide_harness,
                home,
                args.home.is_some(),
                existing_node.as_ref(),
                &cli_bin,
                false,
            ) {
                return outcome;
            }
            return WizardOutcome::Finished(ExitCode::from(EXIT_OK));
        }

        let code = install_and_emit_manual_guide(
            guide_harness,
            home,
            args.home.is_some(),
            existing_node.as_ref(),
            &cli_bin,
            args.json,
        );
        return WizardOutcome::Finished(code);
    }

    // 3. Verified interactive CLI harnesses.
    let Some(chosen) = LaunchableHarness::parse_alias(trimmed) else {
        return WizardOutcome::Finished(emit_error(
            "onboard",
            args.json,
            EXIT_USAGE,
            "INVALID_ASSIST_HARNESS",
            format!(
                "Unsupported --assist harness '{trimmed}' (expected auto, herdr:<template>, claude, claude-desktop, codex, codex-desktop, opencode-desktop, agy/antigravity, opencode, cursor/cursor-agent, gemini, openclaw, or t3)"
            ),
            Some("Example: hyp onboard --assist claude".to_string()),
        ));
    };

    if !args.json {
        play_mycelium_animation(args.no_anim);
    }
    let existing_node = detect_existing_node(args, home);
    let code = install_and_handoff_cli(
        chosen,
        home,
        args.home.is_some(),
        existing_node.as_ref(),
        &cli_bin,
        args.json,
    );
    WizardOutcome::Finished(code)
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

    fn count_lit_dots(plain_frame: &str) -> usize {
        plain_frame
            .chars()
            .filter(|&c| matches!(c, '·' | '▪' | '●'))
            .count()
    }

    #[test]
    fn mycelium_frame_renderer_scales_across_compact_and_fullscreen_dimensions() {
        for (width, height, total) in [
            (DEFAULT_CANVAS_WIDTH, DEFAULT_CANVAS_HEIGHT, 29usize),
            (100usize, 32usize, DEFAULT_TOTAL_FRAMES),
        ] {
            let mut early_lit = 0usize;
            let mut final_lit = 0usize;

            for frame_idx in [0, total / 3, (total * 2) / 3, total - 1] {
                let tc = render_mycelium_frame(frame_idx, total, width, height, ColorMode::TrueColor);
                let ansi256 =
                    render_mycelium_frame(frame_idx, total, width, height, ColorMode::Ansi256);
                let plain = render_mycelium_frame(frame_idx, total, width, height, ColorMode::Plain);

                assert!(!tc.is_empty(), "{width}x{height} frame {frame_idx} empty");
                assert!(
                    tc.contains("\x1b[38;2;"),
                    "{width}x{height} frame {frame_idx} missing truecolor ANSI sequence"
                );
                assert!(
                    ansi256.contains("\x1b[38;5;"),
                    "{width}x{height} frame {frame_idx} missing 256-color ANSI sequence"
                );
                assert!(
                    !plain.contains('\x1b'),
                    "{width}x{height} frame {frame_idx} plain mode must contain zero ANSI escapes"
                );
                assert_eq!(strip_ansi(&tc), plain);
                assert_eq!(strip_ansi(&ansi256), plain);

                let lines: Vec<&str> = plain.lines().collect();
                assert_eq!(
                    lines.len(),
                    height,
                    "{width}x{height} frame {frame_idx} height mismatch"
                );
                for (row_idx, line) in lines.iter().enumerate() {
                    assert_eq!(
                        line.chars().count(),
                        width,
                        "{width}x{height} frame {frame_idx} row {row_idx} width mismatch"
                    );
                }

                let lit = count_lit_dots(&plain);
                assert!(lit > 0, "{width}x{height} frame {frame_idx} should have lit dots");
                if frame_idx == 0 {
                    early_lit = lit;
                }
                if frame_idx == total - 1 {
                    final_lit = lit;
                    assert!(
                        plain.contains('●') && plain.contains('▪') && plain.contains('·'),
                        "{width}x{height} settled frame must include ●, ▪, and ·"
                    );
                }
            }

            assert!(
                final_lit >= early_lit * 3,
                "{width}x{height}: expected substantial network growth from spore ({early_lit}) to settled web ({final_lit})"
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

        assert_eq!(detect_terminal_size_from_env(Some("38"), Some("106")), (38, 106));
        assert_eq!(detect_terminal_size_from_env(None, None), (24, 80));
        assert_eq!(detect_terminal_size_from_env(Some("0"), Some("bad")), (24, 80));

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
        let prompt = "Load and follow hyphae-setup";
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
            parse_herdr_run_address_json("[hc] warning: slow start\n{\n  \"address\": \"t7b\"\n}\n"),
            Some("t7b".to_string())
        );

        // Malformed, missing, empty, flag-injection, or whitespace-injected addresses MUST fail closed.
        assert_eq!(parse_herdr_run_address_json(""), None);
        assert_eq!(parse_herdr_run_address_json("{bad json"), None);
        assert_eq!(parse_herdr_run_address_json(r#"{"id":"t4h"}"#), None);
        assert_eq!(parse_herdr_run_address_json(r#"{"address":""}"#), None);
        assert_eq!(parse_herdr_run_address_json(r#"{"address":"   "}"#), None);
        assert_eq!(parse_herdr_run_address_json(r#"{"address":"-bad"}"#), None);
        assert_eq!(parse_herdr_run_address_json(r#"{"address":"--exec"}"#), None);
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
                "Quick local setup here",
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

        // Inside Herdr (`Some("t1b")`): templates surfaced directly at the top with tag `"herdr"`.
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
        assert_eq!(inside[0].tag, "herdr");
        assert!(matches!(
            inside[0].action,
            MainMenuAction::LaunchHerdrTemplate { ref template, .. } if template.name == "claude-gateway"
        ));
        assert_eq!(inside[1].label, "Codex (Gateway)");
        assert_eq!(inside[1].tag, "herdr");
        assert!(matches!(
            inside[1].action,
            MainMenuAction::LaunchHerdrTemplate { ref template, .. } if template.name == "codex-gateway"
        ));
        assert_eq!(inside[2].label, "Claude Code");
        assert_eq!(inside[3].label, "Codex");
        assert!(inside.iter().all(|i| !matches!(i.action, MainMenuAction::HerdrTemplates { .. })));

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
                tag: "herdr",
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
                tag: "auto-launch",
                subtitle: lh.binary_name().to_string(),
                action: MainMenuAction::LaunchCli(lh),
            });
        }
        items.push(MainMenuItem {
            label: "Claude Desktop".to_string(),
            tag: "install skill + guide",
            subtitle: "Install skill + configure Claude Desktop MCP".to_string(),
            action: MainMenuAction::ManualGuide(ManualGuideHarness::ClaudeDesktop),
        });
        items.push(MainMenuItem {
            label: "Quick local setup here".to_string(),
            tag: "local cli",
            subtitle: "Local node, keys, detected harnesses & background service".to_string(),
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
                joined.contains("Herdr (t1b)"),
                "expected Herdr header note when inside Herdr env"
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

        // Living pulse phase produces distinct settled frames across advancing ticks.
        let f0 = render_mycelium_frame_at_phase(
            DEFAULT_TOTAL_FRAMES - 1,
            DEFAULT_TOTAL_FRAMES,
            0,
            60,
            9,
            ColorMode::TrueColor,
        );
        let f6 = render_mycelium_frame_at_phase(
            DEFAULT_TOTAL_FRAMES - 1,
            DEFAULT_TOTAL_FRAMES,
            6,
            60,
            9,
            ColorMode::TrueColor,
        );
        assert_ne!(f0, f6, "advancing phase ticks must animate bioluminescent pulses");
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
        assert_eq!(updated["mcpServers"]["hyphae"]["args"], json!(["mcp"]));

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
        assert_eq!(plan0.config_path, codex_desktop_config_path(home));
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
                .filter(|l| codex_toml_is_hyphae_table_header(l))
                .count(),
            1
        );

        // Replacing an unmarked existing `[mcp_servers.hyphae]` section preserves neighbors without duplicates.
        let unmarked = "model = \"o3\"\n\n[mcp_servers.hyphae]\ncommand = \"old-hyp\"\nargs = [\"mcp\"]\n\n[mcp_servers.other]\ncommand = \"other\"\n";
        fs::write(&plan0.config_path, unmarked).unwrap();
        assert!(
            inspect_desktop_mcp_plan(ManualGuideHarness::CodexDesktop, home, cli_bin)
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
        assert_eq!(
            replaced
                .lines()
                .filter(|l| codex_toml_is_hyphae_table_header(l))
                .count(),
            1
        );
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
            build_manual_guide_deeplink(ManualGuideHarness::ClaudeDesktop, prompt, Some(cwd), None, None),
            Some(format!("claude://claude.ai/new?q={encoded}"))
        );

        // 2. Codex Desktop
        assert_eq!(
            build_manual_guide_deeplink(ManualGuideHarness::CodexDesktop, prompt, Some(cwd), None, None),
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
            build_manual_guide_deeplink(ManualGuideHarness::CursorIde, prompt, Some(cwd), None, None),
            Some("cursor://file/Users/alice/my%20project%3Fv%3D1%26ok%3D2".to_string())
        );
        assert_eq!(
            build_manual_guide_deeplink(ManualGuideHarness::CursorIde, prompt, None, None, None),
            Some("cursor://".to_string())
        );

        // 6. OpenClaw -> None (clipboard copy only)
        assert_eq!(
            build_manual_guide_deeplink(ManualGuideHarness::Openclaw, prompt, Some(cwd), None, None),
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
                && matches!(m.action, MainMenuAction::ManualGuide(ManualGuideHarness::OpenCodeDesktop))
        }));

        // Confirm & ManualGuide renderers fit cleanly inside 24 rows and display key guidance.
        let plan = inspect_desktop_mcp_plan(ManualGuideHarness::ClaudeDesktop, &home, "/usr/local/bin/hyp")
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
            &ManualGuideHarness::ClaudeDesktop.primary_skill_path(&home),
            &[],
            "Set up Hyphae on this machine using the hyphae-setup skill",
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
        assert_eq!(empty_menu[0].label, "Quick local setup here");

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
                "Quick local setup here",
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
        let prompt = "Load and follow hyphae-setup";

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
        assert!(normalized.starts_with("---\nname: hyphae-setup\n"));
        assert!(!HYPHAE_SETUP_SKILL_MD.contains("hyp share"));
        assert!(!HYPHAE_SETUP_SKILL_MD.contains("hyp connect"));
        assert!(!HYPHAE_SETUP_SKILL_MD.contains("npm install"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("hyp secret set"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("--web"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("hyp gate propose"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("hyp gate lock"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("Herdr"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("Codex Queue"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("--claude-channel"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("T3 Code"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("OpenClaw"));
    }
}
