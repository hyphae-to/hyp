//! Interactive Mycelium Onboarding Wizard & `hyphae-setup` Agent Concierge.
//!
//! Pure Rust (zero external TUI crates):
//! - 24-bit ANSI truecolor (with automatic 256-color / plain fallback) dot-matrix mycelium network
//!   intro animation and RAII cursor visibility guard.
//! - `/dev/tty`-safe interactive prompting so `curl -fsSL https://hyphae.to/install.sh | sh`
//!   transitions cleanly into interactive setup.
//! - Embedded `hyphae-setup` concierge skill (`include_str!`), zero network required.
//! - Verified interactive CLI launchers for Claude Code (`claude`), Codex (`codex`),
//!   Antigravity (`agy --prompt-interactive`), OpenCode (`opencode --prompt`),
//!   Cursor Agent (`cursor-agent`), and Gemini CLI (`gemini -i`).

use crate::config_file::{
    load_node_or_legacy_config, resolve_config_path_for_read, write_atomic_file,
};
use crate::setup::{HarnessDiagnostic, OnboardArgs, default_node_id, detect_harness_statuses};
use crate::ui::{
    EXIT_ERROR, EXIT_OK, EXIT_USAGE, JsonEnvelope, emit_error, print_json, print_next_steps,
    print_warnings,
};
use hyp_harness::protocol::HarnessKind;
use serde::Serialize;
use serde_json::json;
use std::collections::BTreeSet;
use std::f64::consts::PI;
use std::ffi::OsStr;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io::BufReader;
use std::io::{self, BufRead, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::Duration;

/// Embedded pure-Rust v2 `hyphae-setup` concierge skill (zero network access needed).
pub const HYPHAE_SETUP_SKILL_MD: &str = include_str!("../../../skills/hyphae-setup/SKILL.md");

pub const DEFAULT_CANVAS_WIDTH: usize = 54;
pub const DEFAULT_CANVAS_HEIGHT: usize = 18;
pub const DEFAULT_TOTAL_FRAMES: usize = 30;
const FRAME_DELAY_MS: u64 = 60;

// Truecolor dot-matrix botanical mycelium palette.
const RGB_AMBIENT_DIM: (u8, u8, u8) = (56, 72, 68);
const RGB_HYPHAE_MOSS: (u8, u8, u8) = (102, 138, 118);
const RGB_HYPHAE_SAGE: (u8, u8, u8) = (176, 214, 178);
const RGB_PULSE_IVORY: (u8, u8, u8) = (240, 246, 238);
const RGB_NODE_AMBER: (u8, u8, u8) = (236, 206, 132);

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
struct DetectedDisplayRow {
    harness_name: &'static str,
    tag: &'static str,
    detail: String,
}

#[derive(Debug, Clone)]
struct ExistingNodeInfo {
    node_id: String,
    config_path: PathBuf,
    is_legacy_v1: bool,
}

// ============================================================================
// Color Mode & Cursor Guard
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

/// RAII cursor-hide guard: writes `\x1b[?25l` on creation and ALWAYS restores `\x1b[?25h\x1b[0m`
/// on drop (including early return or panic unwind).
struct CursorGuard {
    active: bool,
}

impl CursorGuard {
    fn hide_if(enabled: bool) -> Self {
        if enabled {
            let mut out = io::stdout().lock();
            let _ = out.write_all(b"\x1b[?25l");
            let _ = out.flush();
        }
        Self { active: enabled }
    }
}

impl Drop for CursorGuard {
    fn drop(&mut self) {
        if self.active {
            let mut out = io::stdout().lock();
            let _ = out.write_all(b"\x1b[?25h\x1b[0m");
            let _ = out.flush();
        }
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
    let min_x = (s.x.floor() as isize - 3).max(0) as usize;
    let max_x = ((s.x.ceil() as isize + 3).min(width as isize - 1)).max(0) as usize;
    let min_y = (s.y.floor() as isize - 2).max(0) as usize;
    let max_y = ((s.y.ceil() as isize + 2).min(height as isize - 1)).max(0) as usize;

    for y in min_y..=max_y {
        let dy_vis = (y as f64 - s.y) * 2.0;
        let row_offset = y * width;
        for x in min_x..=max_x {
            let dx = x as f64 - s.x;
            let dist = dx.hypot(dy_vis);
            if dist > 4.2 {
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
                let v = s.pulse * gaussian(dist, 0.92);
                if v > cell.pulse {
                    cell.pulse = v;
                }
            }
            if s.node > 0.0 {
                let v = s.node * gaussian(dist, 1.38);
                if v > cell.node {
                    cell.node = v;
                }
            }
        }
    }
}

/// Renders a single deterministic frame of the dot-matrix organic mycelium network.
///
/// Pure function (no sleeping, no TTY checks) so tests can verify frame dimensions,
/// progressive growth, truecolor/256-color/plain escaping, and settled state deterministically.
pub fn render_mycelium_frame(
    frame_idx: usize,
    total_frames: usize,
    width: usize,
    height: usize,
    color_mode: ColorMode,
) -> String {
    if width == 0 || height == 0 {
        return String::new();
    }

    let denom = total_frames.saturating_sub(1).max(1) as f64;
    let p = (frame_idx.min(total_frames.saturating_sub(1)) as f64) / denom;

    let mut grid = vec![Cell::default(); width * height];

    let cx = (width as f64 - 1.0) * 0.5;
    let cy = (height as f64 - 1.0) * 0.5;
    let rx = (width as f64) * 0.39;
    let ry = (height as f64) * 0.38;
    let sway_scale = (width as f64) / (DEFAULT_CANVAS_WIDTH as f64);

    // 6 organically spaced outer agent nodes around a living botanical ellipse.
    const NODE_ANGLES: [f64; 6] = [0.06, 1.09, 2.08, 3.17, 4.20, 5.22];
    const NODE_RADII: [f64; 6] = [1.00, 0.95, 1.03, 0.97, 1.02, 0.96];
    const SWAYS: [f64; 6] = [2.35, -2.05, 2.55, -2.25, 2.15, -2.45];

    let outer_nodes: [(f64, f64); 6] = std::array::from_fn(|i| {
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
        let bend = (PI * u).sin() * sway + (2.0 * PI * u).sin() * (sway * 0.30);
        (cx + dx * u + px * bend, cy + dy * u + py * bend)
    };

    // 1. Central spore cluster — ignites at frame 0 and stays as a warm living core.
    let spore_bloom = smoothstep(0.0, 0.14, p);
    let spore_pulse = (1.0 - smoothstep(0.02, 0.24, p)) * 0.85
        + 0.22 * smoothstep(0.75, 1.0, p);
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
            node: 0.52 + 0.34 * spore_bloom,
            sigma_core: 0.85,
            sigma_halo: 1.85,
        },
    );
    let center_x = (cx.round() as isize).clamp(0, width as isize - 1) as usize;
    let center_y = (cy.round() as isize).clamp(0, height as isize - 1) as usize;
    grid[center_y * width + center_x].node_core = true;

    // 2. Primary hyphae filaments growing from center to each outer agent node.
    const PRIMARY_STEPS: usize = 44;
    for i in 0..6 {
        let delay = (i as f64) * 0.024;
        let growth = smoothstep(0.04 + delay, 0.56 + delay, p);
        if growth <= 0.005 {
            continue;
        }
        let max_step = ((PRIMARY_STEPS as f64) * growth).ceil() as usize;
        // Traveling signal pulse after filament connects.
        let pulse_phase = if p > 0.68 {
            let speed = 1.65;
            let raw = (p - 0.68) * speed + (i as f64) * 0.23;
            Some(raw.fract())
        } else {
            None
        };

        for s in 0..=max_step.min(PRIMARY_STEPS) {
            let u = (s as f64) / (PRIMARY_STEPS as f64);
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
                    let fade = smoothstep(0.68, 0.80, p);
                    gaussian((u - pu).abs(), 0.07) * 0.88 * fade
                })
                .unwrap_or(0.0);

            let body_strength = lerp_f64(0.86, 0.66, u * 0.55);
            let halo_strength = lerp_f64(0.56, 0.36, u * 0.5);
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
                    sigma_core: 0.76,
                    sigma_halo: 1.55,
                },
            );
        }

        // 3. Secondary interconnecting mesh-ring tendrils bridging branch i -> branch (i + 1) % 6.
        let ring_growth = smoothstep(0.32 + delay, 0.74 + delay, p);
        if ring_growth > 0.005 {
            let next_i = (i + 1) % 6;
            let start = primary_point(i, 0.54);
            let end = primary_point(next_i, 0.74);
            let mid_raw = ((start.0 + end.0) * 0.5, (start.1 + end.1) * 0.5);
            let ctrl = (
                cx + (mid_raw.0 - cx) * 1.24,
                cy + (mid_raw.1 - cy) * 1.24,
            );
            const RING_STEPS: usize = 30;
            let ring_pulse_u = if p > 0.76 {
                Some(((p - 0.76) * 2.1 + (i as f64) * 0.31).fract())
            } else {
                None
            };
            let max_rs = ((RING_STEPS as f64) * ring_growth).ceil() as usize;
            for s in 0..=max_rs.min(RING_STEPS) {
                let u = (s as f64) / (RING_STEPS as f64);
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
                    .map(|pu| gaussian((u - pu).abs(), 0.085) * 0.78 * smoothstep(0.76, 0.88, p))
                    .unwrap_or(0.0);
                splat_point(
                    &mut grid,
                    width,
                    height,
                    Splat {
                        x: sx,
                        y: sy,
                        hypha: 0.56,
                        halo: 0.34,
                        pulse: tip.max(signal),
                        node: 0.0,
                        sigma_core: 0.66,
                        sigma_halo: 1.35,
                    },
                );
            }
        }

        // 4. Fine botanical side-tendrils branching softly outward from each primary hypha.
        let root_growth = smoothstep(0.28 + delay, 0.68 + delay, p);
        if root_growth > 0.005 {
            let start = primary_point(i, 0.36);
            let side_angle = NODE_ANGLES[i] - 0.52;
            let end = (
                cx + rx * 0.78 * side_angle.cos(),
                cy + ry * 0.78 * side_angle.sin(),
            );
            let ctrl = (
                start.0 + (end.0 - start.0) * 0.52 + (start.1 - cy) * 0.16,
                start.1 + (end.1 - start.1) * 0.52 - (start.0 - cx) * 0.08,
            );
            const ROOT_STEPS: usize = 16;
            let max_ts = ((ROOT_STEPS as f64) * root_growth).ceil() as usize;
            for s in 0..=max_ts.min(ROOT_STEPS) {
                let u = (s as f64) / (ROOT_STEPS as f64);
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
                        hypha: 0.46 * taper,
                        halo: 0.30 * taper,
                        pulse: tip,
                        node: 0.0,
                        sigma_core: 0.60,
                        sigma_halo: 1.20,
                    },
                );
            }
        }

        // 5. Outer agent nodes ignite in warm bioluminescent gold-amber upon arrival.
        let arrive = smoothstep(0.50 + delay, 0.68 + delay, p);
        if arrive > 0.01 {
            let burst = gaussian(p - (0.60 + delay), 0.085) * 0.45;
            let steady_breathe = 0.08 * ((p * 2.0 * PI) + (i as f64)).sin();
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
                    sigma_core: 0.78,
                    sigma_halo: 1.85,
                },
            );
            if arrive >= 0.35 {
                let ix = (nx.round() as isize).clamp(0, width as isize - 1) as usize;
                let iy = (ny.round() as isize).clamp(0, height as isize - 1) as usize;
                grid[iy * width + ix].node_core = true;
            }
        }
    }

    // 6. Compose dot-matrix rows with minimal ANSI escapes.
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

fn resolve_canvas_dimensions() -> Option<(usize, usize)> {
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

/// Plays the dot-matrix mycelium intro animation in-place without clearing scrollback.
pub fn play_mycelium_animation(no_anim: bool) {
    if no_anim || no_color_enabled() || !io::stdout().is_terminal() {
        return;
    }
    let Some((width, height)) = resolve_canvas_dimensions() else {
        return;
    };
    let color_mode = detect_color_mode();
    let _cursor = CursorGuard::hide_if(true);
    let mut out = io::stdout().lock();

    for frame_idx in 0..DEFAULT_TOTAL_FRAMES {
        let frame = render_mycelium_frame(frame_idx, DEFAULT_TOTAL_FRAMES, width, height, color_mode);
        if frame_idx == 0 {
            let _ = writeln!(out, "{frame}");
        } else {
            let _ = writeln!(out, "\x1b[{height}A\r{frame}");
        }
        let _ = out.flush();
        if frame_idx + 1 < DEFAULT_TOTAL_FRAMES {
            thread::sleep(Duration::from_millis(FRAME_DELAY_MS));
        }
    }
}

/// Entrypoint for `hyp onboard --preview-anim`.
pub fn run_preview_animation(no_anim: bool) -> ExitCode {
    let Some((width, height)) = resolve_canvas_dimensions() else {
        return ExitCode::from(EXIT_OK);
    };
    let color_mode = detect_color_mode();
    let is_tty = io::stdout().is_terminal();

    if no_anim || !is_tty {
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

    let _cursor = CursorGuard::hide_if(true);
    let mut out = io::stdout().lock();
    for frame_idx in 0..DEFAULT_TOTAL_FRAMES {
        let frame = render_mycelium_frame(frame_idx, DEFAULT_TOTAL_FRAMES, width, height, color_mode);
        if frame_idx == 0 {
            let _ = writeln!(out, "{frame}");
        } else {
            let _ = writeln!(out, "\x1b[{height}A\r{frame}");
        }
        let _ = out.flush();
        if frame_idx + 1 < DEFAULT_TOTAL_FRAMES {
            thread::sleep(Duration::from_millis(FRAME_DELAY_MS));
        }
    }
    ExitCode::from(EXIT_OK)
}

// ============================================================================
// PATH Executable & Harness Detection
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
            home.join(".config").join("herdr").exists() || home.join(".herdr").exists()
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
            home.join(".openclaw")
                .join("skills")
                .join("hyphae-setup")
                .join("SKILL.md"),
            Vec::new(),
        )),
        HarnessKind::Herdr | HarnessKind::T3 => None,
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

    // If `<home>/.agents` already exists and wasn't populated yet (e.g., Codex not detected),
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
    // When `--home` is explicitly provided (e.g. isolated testing), restrict auto-detection to
    // config directories under `home` so ambient host binaries on PATH never leak into tests.
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
                    "Use --harness all, auto, or one of: claude, codex, antigravity (agy), opencode, cursor, gemini, openclaw."
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
// Existing Node Detection, Prompt Construction & Agent Launcher
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

fn spawn_interactive_harness(
    harness: LaunchableHarness,
    prompt: &str,
    as_json: bool,
) -> ExitCode {
    let Some(exe_path) = find_executable_in_path(harness.binary_name()) else {
        return emit_error(
            "onboard",
            as_json,
            EXIT_ERROR,
            "HARNESS_CLI_NOT_FOUND",
            format!(
                "Could not find '{}' on PATH for {}",
                harness.binary_name(),
                harness.display_name()
            ),
            Some(
                "Install the CLI or run `hyp onboard --yes` for quick local CLI setup.".to_string(),
            ),
        );
    };

    let spec = harness.build_launch_spec(prompt);
    let mut cmd = Command::new(&exe_path);
    cmd.args(&spec.args)
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    // Attach `/dev/tty` for stdin when launched from a piped script like `curl | sh` in a TTY.
    // Never touch `/dev/tty` if stdout isn't a TTY (keeps automated E2E tests 100% isolated).
    #[cfg(unix)]
    {
        if io::stdout().is_terminal() && !io::stdin().is_terminal() {
            if let Ok(tty_file) = fs::File::open("/dev/tty") {
                cmd.stdin(Stdio::from(tty_file));
            } else {
                cmd.stdin(Stdio::inherit());
            }
        } else {
            cmd.stdin(Stdio::inherit());
        }
    }
    #[cfg(not(unix))]
    {
        cmd.stdin(Stdio::inherit());
    }

    match cmd.status() {
        Ok(status) => match status.code() {
            Some(code) => ExitCode::from((code.clamp(0, 255)) as u8),
            None => ExitCode::from(EXIT_ERROR),
        },
        Err(e) => emit_error(
            "onboard",
            as_json,
            EXIT_ERROR,
            "LAUNCH_FAILED",
            format!("Failed to launch {} ({}): {e}", harness.display_name(), exe_path.display()),
            Some("Run `hyp onboard --yes` for quick local CLI setup.".to_string()),
        ),
    }
}

fn install_and_handoff(
    chosen: LaunchableHarness,
    home: &Path,
    explicit_home: bool,
    existing_node: Option<&ExistingNodeInfo>,
    as_json: bool,
) -> ExitCode {
    let mut targets = vec![chosen.kind()];
    let include_path_scan = !explicit_home;
    for kind in HarnessKind::ALL {
        if !targets.contains(&kind)
            && skill_paths_for_kind(kind, home).is_some()
            && is_skill_harness_detected(kind, home, include_path_scan)
        {
            targets.push(kind);
        }
    }

    let installed = match install_setup_skill_for_harnesses(home, &targets) {
        Ok(v) => v,
        Err(e) => {
            return emit_error("onboard", as_json, EXIT_ERROR, "SKILL_INSTALL_FAILED", e, None);
        }
    };

    let primary_skill = chosen.primary_skill_path(home);
    if !as_json {
        println!();
        println!("Installed 'hyphae-setup' skill:");
        for item in &installed {
            println!("  • [{}] {}", item.harness, item.path);
            for extra in &item.extra_paths {
                println!("  • [{}] {} (cross-tool)", item.harness, extra);
            }
        }
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
    spawn_interactive_harness(chosen, &prompt, as_json)
}

// ============================================================================
// Interactive TTY Prompting & Wizard UI
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

fn collect_detected_rows(
    home: &Path,
    diagnostics: &[HarnessDiagnostic],
    launchables: &[(LaunchableHarness, PathBuf)],
) -> Vec<DetectedDisplayRow> {
    let mut rows = Vec::new();
    let find_diag = |name: &str| diagnostics.iter().find(|d| d.harness == name);

    for lh in LaunchableHarness::ALL {
        let on_path = launchables.iter().find(|(h, _)| *h == lh);
        let diag = find_diag(lh.id());
        let configured = diag.is_some_and(|d| d.configured);
        let detected = diag.is_some_and(|d| d.detected);

        if let Some((_, exe_path)) = on_path {
            let suffix = if configured { " · configured" } else { "" };
            rows.push(DetectedDisplayRow {
                harness_name: lh.display_name(),
                tag: "READY",
                detail: format!("{} ({}){suffix}", lh.binary_name(), exe_path.display()),
            });
        } else if detected {
            let suffix = if configured { " · configured" } else { "" };
            rows.push(DetectedDisplayRow {
                harness_name: lh.display_name(),
                tag: "DETECTED",
                detail: format!("config under {} (CLI '{}' not on PATH){suffix}", home.display(), lh.binary_name()),
            });
        }
    }

    let non_cli = [
        (HarnessKind::Openclaw, "OpenClaw"),
        (HarnessKind::T3, "T3 Code"),
        (HarnessKind::Herdr, "Herdr"),
    ];
    for (kind, display) in non_cli {
        if let Some(diag) = find_diag(kind.as_str()).filter(|d| d.detected || d.configured) {
            let state = if diag.configured {
                "configured"
            } else {
                "config detected"
            };
            rows.push(DetectedDisplayRow {
                harness_name: display,
                tag: "DETECTED",
                detail: state.to_string(),
            });
        }
    }

    rows
}

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

/// Runs the interactive Mycelium onboarding wizard on a TTY.
pub fn run_interactive_wizard(args: &OnboardArgs, home: &Path) -> WizardOutcome {
    let existing_node = detect_existing_node(args, home);

    play_mycelium_animation(args.no_anim);

    let version = env!("CARGO_PKG_VERSION");
    println!();
    if let Some(ref existing) = existing_node {
        let legacy_tag = if existing.is_legacy_v1 { " · legacy v1" } else { "" };
        println!(
            "hyphae v{version} · interactive setup (existing node: {}{legacy_tag})",
            existing.node_id
        );
        println!("  Config: {}", existing.config_path.display());
    } else {
        println!("hyphae v{version} · interactive setup");
    }

    let config_opt = existing_node.as_ref().map(|n| n.config_path.as_path());
    let diagnostics = detect_harness_statuses(home, config_opt);
    let launchables = detect_launchable_harnesses_on_path();
    let rows = collect_detected_rows(home, &diagnostics, &launchables);

    println!();
    println!("Detected harnesses:");
    if rows.is_empty() {
        println!("  (none detected on PATH or under {})", home.display());
    } else {
        for row in &rows {
            println!("  {:<8}  {:<14}  {}", row.tag, row.harness_name, row.detail);
        }
    }
    println!();

    if launchables.is_empty() {
        println!(
            "No interactive agent CLI (claude, codex, agy, opencode, cursor-agent, gemini) was found on PATH."
        );
        println!("  [Enter] Run quick local CLI setup");
        println!("  [q]     Cancel");
        println!();
        let prompt = if let Some(ref existing) = existing_node {
            format!(
                "Existing node detected ({}) — refresh local CLI setup right here? [Y/q]: ",
                existing.node_id
            )
        } else {
            "Run quick local CLI setup right here? [Y/q]: ".to_string()
        };
        let reply = match read_tty_line(&prompt) {
            Ok(Some(line)) => line.trim().to_ascii_lowercase(),
            Ok(None) => return WizardOutcome::Finished(ExitCode::from(EXIT_OK)),
            Err(_) => return WizardOutcome::RunLocalCliSetup,
        };
        if reply.is_empty() || matches!(reply.as_str(), "y" | "yes" | "m") {
            return WizardOutcome::RunLocalCliSetup;
        }
        println!("Cancelled.");
        return WizardOutcome::Finished(ExitCode::from(EXIT_OK));
    }

    println!("Choose how to set up Hyphae:");
    for (idx, (lh, _)) in launchables.iter().enumerate() {
        println!(
            "  [{}] {} ({})",
            idx + 1,
            lh.display_name(),
            lh.binary_name()
        );
    }
    if existing_node.is_some() {
        println!("  [m] Refresh local node & harness wiring right here");
    } else {
        println!("  [m] Quick local CLI setup right here");
    }
    println!("  [q] Cancel");
    println!();

    let prompt = if let Some(ref existing) = existing_node {
        format!(
            "Existing node detected ({}) — install/refresh the 'hyphae-setup' skill and hand off configuration changes to an agent? [1]: ",
            existing.node_id
        )
    } else {
        "Install the 'hyphae-setup' skill and start guided onboarding with an agent? [1]: "
            .to_string()
    };

    loop {
        let reply = match read_tty_line(&prompt) {
            Ok(Some(line)) => line.trim().to_ascii_lowercase(),
            Ok(None) => {
                println!();
                println!("Cancelled.");
                return WizardOutcome::Finished(ExitCode::from(EXIT_OK));
            }
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

        if reply.is_empty() {
            let chosen = launchables[0].0;
            let code = install_and_handoff(
                chosen,
                home,
                args.home.is_some(),
                existing_node.as_ref(),
                false,
            );
            return WizardOutcome::Finished(code);
        }
        if matches!(reply.as_str(), "q" | "quit" | "n" | "no") {
            println!("Cancelled.");
            return WizardOutcome::Finished(ExitCode::from(EXIT_OK));
        }
        if matches!(reply.as_str(), "m" | "manual" | "local" | "cli") {
            return WizardOutcome::RunLocalCliSetup;
        }
        if let Some(num) = reply
            .parse::<usize>()
            .ok()
            .filter(|n| (1..=launchables.len()).contains(n))
        {
            let chosen = launchables[num - 1].0;
            let code = install_and_handoff(
                chosen,
                home,
                args.home.is_some(),
                existing_node.as_ref(),
                false,
            );
            return WizardOutcome::Finished(code);
        }
        if let Some(parsed) = LaunchableHarness::parse_alias(&reply)
            .filter(|p| launchables.iter().any(|(h, _)| h == p))
        {
            let code = install_and_handoff(
                parsed,
                home,
                args.home.is_some(),
                existing_node.as_ref(),
                false,
            );
            return WizardOutcome::Finished(code);
        }
        println!(
            "Invalid choice '{reply}'. Enter 1-{}, 'm' for local CLI setup, or 'q' to cancel.",
            launchables.len()
        );
    }
}

/// Entrypoint for `hyp onboard --assist [HARNESS]`.
pub fn run_assist(args: &OnboardArgs, home: &Path, assist_target: &str) -> WizardOutcome {
    let trimmed = assist_target.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("auto") {
        if io::stdout().is_terminal() && !args.json {
            return run_interactive_wizard(args, home);
        }
        let launchables = detect_launchable_harnesses_on_path();
        let Some(&(chosen, _)) = launchables.first() else {
            return WizardOutcome::Finished(emit_error(
                "onboard",
                args.json,
                EXIT_ERROR,
                "NO_LAUNCHABLE_HARNESS",
                "No interactive agent CLI (claude, codex, agy, opencode, cursor-agent, gemini) found on PATH",
                Some("Run `hyp onboard --yes` for local CLI onboarding, or install an agent CLI.".to_string()),
            ));
        };
        let existing_node = detect_existing_node(args, home);
        let code = install_and_handoff(
            chosen,
            home,
            args.home.is_some(),
            existing_node.as_ref(),
            args.json,
        );
        return WizardOutcome::Finished(code);
    }

    let Some(chosen) = LaunchableHarness::parse_alias(trimmed) else {
        return WizardOutcome::Finished(emit_error(
            "onboard",
            args.json,
            EXIT_USAGE,
            "INVALID_ASSIST_HARNESS",
            format!(
                "Unsupported --assist harness '{trimmed}' (expected auto, claude, codex, agy/antigravity, opencode, cursor/cursor-agent, or gemini)"
            ),
            Some("Example: hyp onboard --assist claude".to_string()),
        ));
    };

    if !args.json {
        play_mycelium_animation(args.no_anim);
    }
    let existing_node = detect_existing_node(args, home);
    let code = install_and_handoff(
        chosen,
        home,
        args.home.is_some(),
        existing_node.as_ref(),
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
    fn mycelium_frame_renderer_dimensions_ansi_and_growth() {
        let total = 29;
        let width = DEFAULT_CANVAS_WIDTH;
        let height = DEFAULT_CANVAS_HEIGHT;

        let mut early_lit = 0usize;
        let mut final_lit = 0usize;

        for frame_idx in 0..total {
            let tc = render_mycelium_frame(frame_idx, total, width, height, ColorMode::TrueColor);
            let ansi256 = render_mycelium_frame(frame_idx, total, width, height, ColorMode::Ansi256);
            let plain = render_mycelium_frame(frame_idx, total, width, height, ColorMode::Plain);

            assert!(!tc.is_empty(), "frame {frame_idx} truecolor empty");
            assert!(
                tc.contains("\x1b[38;2;"),
                "frame {frame_idx} missing truecolor ANSI sequence"
            );
            assert!(
                ansi256.contains("\x1b[38;5;"),
                "frame {frame_idx} missing 256-color ANSI sequence"
            );
            assert!(
                !plain.contains('\x1b'),
                "frame {frame_idx} plain mode must contain zero ANSI escapes"
            );

            let plain_from_tc = strip_ansi(&tc);
            assert_eq!(
                plain_from_tc, plain,
                "frame {frame_idx} visible glyphs must match between TrueColor and Plain"
            );
            assert_eq!(
                strip_ansi(&ansi256),
                plain,
                "frame {frame_idx} visible glyphs must match between Ansi256 and Plain"
            );

            let lines: Vec<&str> = plain.lines().collect();
            assert_eq!(
                lines.len(),
                height,
                "frame {frame_idx} must have exact height {height}"
            );
            for (row_idx, line) in lines.iter().enumerate() {
                assert_eq!(
                    line.chars().count(),
                    width,
                    "frame {frame_idx} row {row_idx} must have exact width {width}"
                );
            }

            let lit = count_lit_dots(&plain);
            assert!(lit > 0, "frame {frame_idx} should have at least central spore lit");
            if frame_idx == 0 {
                early_lit = lit;
            }
            if frame_idx == total - 1 {
                final_lit = lit;
                assert!(
                    plain.contains('●') && plain.contains('▪') && plain.contains('·'),
                    "settled frame must include nodes (●), hyphae (▪), and ambient halo (·)"
                );
            }
        }

        assert!(
            early_lit < final_lit,
            "expected progressive mycelium growth: early_lit={early_lit} should be < final_lit={final_lit}"
        );
        assert!(
            final_lit >= early_lit * 3,
            "expected substantial network growth from spore ({early_lit}) to settled web ({final_lit})"
        );
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
        assert!(HYPHAE_SETUP_SKILL_MD.starts_with("---\nname: hyphae-setup\n"));
        assert!(!HYPHAE_SETUP_SKILL_MD.contains("hyp share"));
        assert!(!HYPHAE_SETUP_SKILL_MD.contains("hyp connect"));
        assert!(!HYPHAE_SETUP_SKILL_MD.contains("npm install"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("hyp secret set"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("--web"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("hyp gate propose"));
        assert!(HYPHAE_SETUP_SKILL_MD.contains("hyp gate lock"));
    }
}
