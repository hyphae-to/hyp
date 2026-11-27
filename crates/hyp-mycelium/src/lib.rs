//! Deterministic Unicode Braille frames for the Hyphae intro, preview and menu banner.

use std::f64::consts::PI;

/// Terminal color rendering capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColorMode {
    TrueColor,
    Ansi256,
    Plain,
}

// Truecolor high-res Braille botanical mycelium & HYPHAE bioluminescent palette.
const RGB_TENDRIL_TWILIGHT: (u8, u8, u8) = (40, 62, 50);
const RGB_TENDRIL_DEEP: (u8, u8, u8) = (68, 114, 84);
const RGB_TENDRIL_SAGE: (u8, u8, u8) = (118, 174, 118);
const RGB_WORD_EMERALD: (u8, u8, u8) = (82, 146, 98);
const RGB_WORD_MOSS: (u8, u8, u8) = (132, 188, 96);
const RGB_WORD_CHARTREUSE: (u8, u8, u8) = (183, 217, 86);
const RGB_WORD_GOLD: (u8, u8, u8) = (238, 200, 112);
const RGB_SPORE_AMBER: (u8, u8, u8) = (232, 163, 49);
const RGB_SPORE_GLOW: (u8, u8, u8) = (252, 226, 154);

/// Standard Unicode Braille (`U+2800..U+28FF`) bit mapping for sub-pixel `(dx, dy)`
/// within a `2 × 4` character cell:
/// - `(0,0)->0x01`, `(0,1)->0x02`, `(0,2)->0x04`, `(0,3)->0x40`
/// - `(1,0)->0x08`, `(1,1)->0x10`, `(1,2)->0x20`, `(1,3)->0x80`
const BRAILLE_BITS: [[u8; 4]; 2] = [[0x01, 0x02, 0x04, 0x40], [0x08, 0x10, 0x20, 0x80]];

// Master 16-sub-pixel-tall (4 exact Braille rows) botanical-serif `HYPHAE` bitmaps.
// Vertical pillars land on even 2-px Braille cell boundaries for razor-sharp terminal rendering.
const GLYPH_H_16: [&str; 16] = [
    ".####..####.",
    "..##....##..",
    "..##....##..",
    "..##....##..",
    "..##....##..",
    "..##....##..",
    "..##....##..",
    "..########..",
    "..########..",
    "..##....##..",
    "..##....##..",
    "..##....##..",
    "..##....##..",
    "..##....##..",
    "..##....##..",
    ".####..####.",
];

const GLYPH_Y_16: [&str; 16] = [
    "####..####",
    ".##....##.",
    ".##....##.",
    "..##..##..",
    "..##..##..",
    "..##..##..",
    "...####...",
    "...####...",
    "....##....",
    "....##....",
    "....##....",
    "....##....",
    "....##....",
    "....##....",
    "....##....",
    "...####...",
];

const GLYPH_P_16: [&str; 16] = [
    ".#######..",
    "..#######.",
    "..##....##",
    "..##....##",
    "..##....##",
    "..##....##",
    "..##....##",
    "..##....##",
    "..#######.",
    "..######..",
    "..##......",
    "..##......",
    "..##......",
    "..##......",
    "..##......",
    ".####.....",
];

const GLYPH_A_16: [&str; 16] = [
    ".....##.....",
    "....####....",
    "....####....",
    "...##..##...",
    "...##..##...",
    "...##..##...",
    "..##....##..",
    "..##....##..",
    "..##....##..",
    "..########..",
    "..########..",
    ".##......##.",
    ".##......##.",
    ".##......##.",
    ".##......##.",
    "####....####",
];

const GLYPH_E_16: [&str; 16] = [
    ".#########",
    "..########",
    "..##.....#",
    "..##......",
    "..##......",
    "..##......",
    "..##......",
    "..######..",
    "..######..",
    "..##......",
    "..##......",
    "..##......",
    "..##......",
    "..##.....#",
    "..########",
    ".#########",
];

// Compact 12-sub-pixel-tall (3 exact Braille rows) botanical-serif `HYPHAE` bitmaps
// for shorter headers (`height` in `6..=8`, `width >= 46`).
const GLYPH_H_12: [&str; 12] = [
    ".####..####.",
    "..##....##..",
    "..##....##..",
    "..##....##..",
    "..##....##..",
    "..########..",
    "..########..",
    "..##....##..",
    "..##....##..",
    "..##....##..",
    "..##....##..",
    ".####..####.",
];

const GLYPH_Y_12: [&str; 12] = [
    "####..####",
    ".##....##.",
    "..##..##..",
    "..##..##..",
    "...####...",
    "...####...",
    "....##....",
    "....##....",
    "....##....",
    "....##....",
    "....##....",
    "...####...",
];

const GLYPH_P_12: [&str; 12] = [
    ".#######..",
    "..#######.",
    "..##....##",
    "..##....##",
    "..##....##",
    "..#######.",
    "..######..",
    "..##......",
    "..##......",
    "..##......",
    "..##......",
    ".####.....",
];

const GLYPH_A_12: [&str; 12] = [
    ".....##.....",
    "....####....",
    "...##..##...",
    "...##..##...",
    "..##....##..",
    "..##....##..",
    "..########..",
    "..########..",
    ".##......##.",
    ".##......##.",
    ".##......##.",
    "####....####",
];

const GLYPH_E_12: [&str; 12] = [
    ".#########",
    "..########",
    "..##......",
    "..##......",
    "..##......",
    "..######..",
    "..######..",
    "..##......",
    "..##......",
    "..##......",
    "..########",
    ".#########",
];

#[derive(Clone, Copy, Default)]
struct BrailleCell {
    bits: u8,
    override_ch: Option<char>,
    wordmark_energy: f64,
    wordmark_shimmer: f64,
    tendril_energy: f64,
    pulse_energy: f64,
    spore_energy: f64,
}

struct BrailleCanvas {
    width: usize,
    height: usize,
    px_w: usize,
    px_h: usize,
    cells: Vec<BrailleCell>,
    /// Per-sub-pixel negative-space mask protecting `HYPHAE` (`0` open, `1` halo, `2` glyph stroke).
    mask: Vec<u8>,
}

impl BrailleCanvas {
    fn new(width: usize, height: usize) -> Self {
        let px_w = width * 2;
        let px_h = height * 4;
        Self {
            width,
            height,
            px_w,
            px_h,
            cells: vec![BrailleCell::default(); width * height],
            mask: vec![0u8; px_w * px_h],
        }
    }

    fn edge_fade(&self, px: f64, py: f64) -> f64 {
        let cx = (self.px_w as f64 - 1.0) * 0.5;
        let cy = (self.px_h as f64 - 1.0) * 0.5;
        let rx = (self.px_w as f64 * 0.485).max(1.0);
        let ry = (self.px_h as f64 * 0.475).max(1.0);
        let nx = ((px - cx) / rx).abs();
        let ny = ((py - cy) / ry).abs();
        // Smooth superellipse vignette so borderless tendrils dissolve organically into the void.
        let r = (nx.powf(2.6) + ny.powf(2.6)).powf(1.0 / 2.6);
        1.0 - smoothstep(0.76, 1.01, r)
    }

    fn is_masked(&self, px: isize, py: isize) -> bool {
        if px < 0 || py < 0 || px >= self.px_w as isize || py >= self.px_h as isize {
            return true;
        }
        self.mask[(py as usize) * self.px_w + (px as usize)] != 0
    }

    fn mark_halo_rect(&mut self, x0: isize, y0: isize, x1: isize, y1: isize) {
        let min_x = x0.max(0).min(self.px_w as isize) as usize;
        let max_x = x1.max(0).min(self.px_w as isize) as usize;
        let min_y = y0.max(0).min(self.px_h as isize) as usize;
        let max_y = y1.max(0).min(self.px_h as isize) as usize;
        for py in min_y..max_y {
            let row = py * self.px_w;
            for px in min_x..max_x {
                if self.mask[row + px] == 0 {
                    self.mask[row + px] = 1;
                }
            }
        }
    }

    fn mark_wordmark_pixel(&mut self, px: isize, py: isize, halo_radius: isize) {
        if px < 0 || py < 0 || px >= self.px_w as isize || py >= self.px_h as isize {
            return;
        }
        let idx = (py as usize) * self.px_w + (px as usize);
        self.mask[idx] = 2;

        let r2 = halo_radius * halo_radius + 1;
        for dy in -halo_radius..=halo_radius {
            let ny = py + dy;
            if ny < 0 || ny >= self.px_h as isize {
                continue;
            }
            let row = (ny as usize) * self.px_w;
            for dx in -halo_radius..=halo_radius {
                if dx * dx + dy * dy > r2 {
                    continue;
                }
                let nx = px + dx;
                if nx < 0 || nx >= self.px_w as isize {
                    continue;
                }
                let nidx = row + (nx as usize);
                if self.mask[nidx] == 0 {
                    self.mask[nidx] = 1;
                }
            }
        }
    }

    fn set_bit_at(&mut self, px: isize, py: isize) -> Option<&mut BrailleCell> {
        if px < 0 || py < 0 || px >= self.px_w as isize || py >= self.px_h as isize {
            return None;
        }
        let ux = px as usize;
        let uy = py as usize;
        let cx = ux / 2;
        let cy = uy / 4;
        let dx = ux % 2;
        let dy = uy % 4;
        let cell = &mut self.cells[cy * self.width + cx];
        cell.bits |= BRAILLE_BITS[dx][dy];
        Some(cell)
    }

    fn plot_wordmark_pixel(&mut self, px: isize, py: isize, energy: f64, shimmer: f64) {
        if let Some(cell) = self.set_bit_at(px, py) {
            if energy >= cell.wordmark_energy {
                cell.wordmark_energy = energy;
                cell.wordmark_shimmer = shimmer;
            } else if shimmer > cell.wordmark_shimmer {
                cell.wordmark_shimmer = shimmer;
            }
        }
    }

    fn plot_tendril_pixel(
        &mut self,
        px: isize,
        py: isize,
        energy: f64,
        pulse: f64,
        respect_halo: bool,
    ) {
        if px < 0 || py < 0 || px >= self.px_w as isize || py >= self.px_h as isize {
            return;
        }
        if respect_halo && self.is_masked(px, py) {
            return;
        }
        let fade = self.edge_fade(px as f64, py as f64);
        if fade <= 0.04 {
            return;
        }
        if fade < 0.44 && stipple_hash(px, py) > (fade / 0.44) {
            return;
        }
        if let Some(cell) = self.set_bit_at(px, py) {
            let te = energy * (0.28 + 0.72 * fade);
            if te > cell.tendril_energy {
                cell.tendril_energy = te;
            }
            let pe = pulse * (0.35 + 0.65 * fade);
            if pe > cell.pulse_energy {
                cell.pulse_energy = pe;
            }
        }
    }

    fn plot_spore_hub(
        &mut self,
        cx: f64,
        cy: f64,
        radius: f64,
        energy: f64,
        glow: f64,
        respect_halo: bool,
    ) {
        let fade = self.edge_fade(cx, cy);
        if fade <= 0.06 {
            return;
        }
        let r_eff = radius.max(0.55);
        let bound = r_eff.ceil() as isize;
        let icx = cx.round() as isize;
        let icy = cy.round() as isize;
        for dy in -bound..=bound {
            for dx in -bound..=bound {
                let px = icx + dx;
                let py = icy + dy;
                let dist = ((px as f64 - cx).hypot(py as f64 - cy)) / r_eff;
                if dist > 1.05 {
                    continue;
                }
                if respect_halo && self.is_masked(px, py) {
                    continue;
                }
                if let Some(cell) = self.set_bit_at(px, py) {
                    let falloff = (1.0 - dist * 0.45).clamp(0.45, 1.0);
                    let se = energy * falloff * (0.35 + 0.65 * fade);
                    if se > cell.spore_energy {
                        cell.spore_energy = se;
                    }
                    let pe = glow * falloff * (0.40 + 0.60 * fade);
                    if pe > cell.pulse_energy {
                        cell.pulse_energy = pe;
                    }
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn plot_cubic_bezier(
        &mut self,
        p0: (f64, f64),
        p1: (f64, f64),
        p2: (f64, f64),
        p3: (f64, f64),
        growth: f64,
        base_energy: f64,
        pulse_u: Option<f64>,
        pulse_strength: f64,
        bold: bool,
        respect_halo: bool,
    ) {
        if growth <= 0.004 {
            return;
        }
        let poly_len = (p1.0 - p0.0).hypot(p1.1 - p0.1)
            + (p2.0 - p1.0).hypot(p2.1 - p1.1)
            + (p3.0 - p2.0).hypot(p3.1 - p2.1);
        let steps = (poly_len * 2.2).ceil().clamp(24.0, 260.0) as usize;
        let max_step = ((steps as f64) * growth.clamp(0.0, 1.0)).ceil() as usize;

        for s in 0..=max_step.min(steps) {
            let u = (s as f64) / (steps as f64);
            if u > growth {
                break;
            }
            let (sx, sy) = cubic_bezier(p0, p1, p2, p3, u);
            let px = sx.round() as isize;
            let py = sy.round() as isize;

            let taper = lerp_f64(1.0, 0.56, u * 0.85);
            let active_tip = if growth < 0.995 {
                gaussian((growth - u).abs(), 0.075) * 0.98
            } else {
                0.0
            };
            let traveling = pulse_u
                .map(|pu| {
                    let d = wrapped_unit_dist(u, pu);
                    gaussian(d, 0.078) * pulse_strength
                })
                .unwrap_or(0.0);
            let pulse = active_tip.max(traveling);

            self.plot_tendril_pixel(px, py, base_energy * taper, pulse, respect_halo);

            // Primary hyphae subtly thicken near their base and right at passing pulse crests.
            if (bold && u < 0.18 && base_energy > 0.78) || pulse > 0.74 {
                let (tx, ty) = cubic_bezier_tangent(p0, p1, p2, p3, u);
                let tlen = tx.hypot(ty).max(1e-6);
                let nx = (-ty / tlen).round() as isize;
                let ny = (tx / tlen).round() as isize;
                if nx != 0 || ny != 0 {
                    self.plot_tendril_pixel(
                        px + nx,
                        py + ny,
                        base_energy * taper * 0.74,
                        pulse * 0.90,
                        respect_halo,
                    );
                }
            }
        }
    }

    fn set_override_cell(&mut self, cx: usize, cy: usize, cell: BrailleCell) {
        if cx >= self.width || cy >= self.height {
            return;
        }
        self.cells[cy * self.width + cx] = cell;
    }

    fn render(&self, color_mode: ColorMode) -> String {
        let mut out = String::with_capacity(self.width * self.height * 6);
        for y in 0..self.height {
            if y > 0 {
                out.push('\n');
            }
            let mut last_color: Option<(u8, u8, u8)> = None;
            let row_offset = y * self.width;
            for x in 0..self.width {
                let cell = self.cells[row_offset + x];
                let ch = match cell.override_ch {
                    Some(c) => c,
                    None if cell.bits == 0 => ' ',
                    None => char::from_u32(0x2800 | (cell.bits as u32)).unwrap_or(' '),
                };
                let color = if ch == ' ' {
                    None
                } else {
                    resolve_braille_cell_rgb(cell)
                };
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
}

fn resolve_braille_cell_rgb(cell: BrailleCell) -> Option<(u8, u8, u8)> {
    if cell.wordmark_energy > 0.05 {
        let s = cell.wordmark_shimmer.clamp(0.0, 1.0);
        let lit = if s < 0.36 {
            lerp_rgb(RGB_WORD_EMERALD, RGB_WORD_MOSS, s / 0.36)
        } else if s < 0.76 {
            lerp_rgb(RGB_WORD_MOSS, RGB_WORD_CHARTREUSE, (s - 0.36) / 0.40)
        } else {
            lerp_rgb(RGB_WORD_CHARTREUSE, RGB_WORD_GOLD, (s - 0.76) / 0.24)
        };
        let intensity = cell.wordmark_energy.clamp(0.0, 1.0);
        return Some(lerp_rgb(RGB_TENDRIL_TWILIGHT, lit, intensity));
    }
    if cell.spore_energy > 0.30 && cell.spore_energy >= cell.tendril_energy * 0.70 {
        let boost =
            (cell.pulse_energy * 0.85 + (cell.spore_energy - 0.75).max(0.0)).clamp(0.0, 1.0);
        let base = lerp_rgb(
            RGB_TENDRIL_SAGE,
            RGB_SPORE_AMBER,
            (cell.spore_energy * 1.15).clamp(0.0, 1.0),
        );
        return Some(lerp_rgb(base, RGB_SPORE_GLOW, boost));
    }
    if cell.pulse_energy > 0.22 {
        let p = ((cell.pulse_energy - 0.22) / 0.78).clamp(0.0, 1.0);
        if p < 0.58 {
            return Some(lerp_rgb(RGB_TENDRIL_SAGE, RGB_WORD_CHARTREUSE, p / 0.58));
        }
        return Some(lerp_rgb(
            RGB_WORD_CHARTREUSE,
            RGB_SPORE_GLOW,
            (p - 0.58) / 0.42,
        ));
    }
    if cell.tendril_energy > 0.0 {
        let t = cell.tendril_energy.clamp(0.0, 1.0);
        if t < 0.48 {
            return Some(lerp_rgb(RGB_TENDRIL_TWILIGHT, RGB_TENDRIL_DEEP, t / 0.48));
        }
        return Some(lerp_rgb(
            RGB_TENDRIL_DEEP,
            RGB_TENDRIL_SAGE,
            (t - 0.48) / 0.52,
        ));
    }
    None
}

fn stipple_hash(px: isize, py: isize) -> f64 {
    let mut h = (px as u64)
        .wrapping_mul(0x9E37_79B9_7F4A_7C15)
        .wrapping_add((py as u64).wrapping_mul(0xBF58_476D_1CE4_E5B9));
    h ^= h >> 30;
    h = h.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    h ^= h >> 27;
    h = h.wrapping_mul(0x94D0_49BB_1331_11EB);
    h ^= h >> 31;
    ((h >> 40) as f64) / ((1u64 << 24) as f64)
}

fn wrapped_unit_dist(a: f64, b: f64) -> f64 {
    let d = (a - b).abs();
    d.min(1.0 - d)
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
    let gray_dist =
        (r as i32 - gray_lvl).pow(2) + (g as i32 - gray_lvl).pow(2) + (b as i32 - gray_lvl).pow(2);

    if gray_dist < cube_dist {
        gray_code
    } else {
        cube_code
    }
}

fn cubic_bezier(
    p0: (f64, f64),
    p1: (f64, f64),
    p2: (f64, f64),
    p3: (f64, f64),
    t: f64,
) -> (f64, f64) {
    let inv = 1.0 - t;
    let inv2 = inv * inv;
    let t2 = t * t;
    let x = inv2 * inv * p0.0 + 3.0 * inv2 * t * p1.0 + 3.0 * inv * t2 * p2.0 + t2 * t * p3.0;
    let y = inv2 * inv * p0.1 + 3.0 * inv2 * t * p1.1 + 3.0 * inv * t2 * p2.1 + t2 * t * p3.1;
    (x, y)
}

fn cubic_bezier_tangent(
    p0: (f64, f64),
    p1: (f64, f64),
    p2: (f64, f64),
    p3: (f64, f64),
    t: f64,
) -> (f64, f64) {
    let inv = 1.0 - t;
    let dx = 3.0 * inv * inv * (p1.0 - p0.0)
        + 6.0 * inv * t * (p2.0 - p1.0)
        + 3.0 * t * t * (p3.0 - p2.0);
    let dy = 3.0 * inv * inv * (p1.1 - p0.1)
        + 6.0 * inv * t * (p2.1 - p1.1)
        + 3.0 * t * t * (p3.1 - p2.1);
    (dx, dy)
}

struct MyceliumStrand {
    p0: (f64, f64),
    p1: (f64, f64),
    p2: (f64, f64),
    p3: (f64, f64),
    start_p: f64,
    end_p: f64,
    energy: f64,
    pulse_speed: f64,
    pulse_offset: f64,
    bold: bool,
    respect_halo: bool,
}

struct SporeHub {
    x: f64,
    y: f64,
    radius: f64,
    appear_p: f64,
    pulse_speed: f64,
    pulse_offset: f64,
    pulse_u: f64,
    respect_halo: bool,
}

struct WordmarkBox {
    x0: f64,
    y0: f64,
    x1: f64,
    y1: f64,
}

fn wordmark_shimmer_value(u_x: f64, u_y: f64, phase: f64) -> f64 {
    let wave1 = 0.5 + 0.5 * (u_x * 4.4 - u_y * 1.15 - phase * 2.0 * PI).sin();
    let wave2 = 0.5 + 0.5 * (u_x * 2.1 + phase * 1.25 * PI + 0.7).cos();
    (0.72 * wave1 + 0.28 * wave2).clamp(0.0, 1.0)
}

fn draw_braille_wordmark(canvas: &mut BrailleCanvas, p: f64, phase: f64) -> WordmarkBox {
    let px_w = canvas.px_w;
    let px_h = canvas.px_h;
    let use_compact_12 = canvas.height <= 8;
    let hero_scale = canvas.width >= 98 && canvas.height >= 14;

    let glyphs: [&[&str]; 6] = if use_compact_12 {
        [
            &GLYPH_H_12,
            &GLYPH_Y_12,
            &GLYPH_P_12,
            &GLYPH_H_12,
            &GLYPH_A_12,
            &GLYPH_E_12,
        ]
    } else {
        [
            &GLYPH_H_16,
            &GLYPH_Y_16,
            &GLYPH_P_16,
            &GLYPH_H_16,
            &GLYPH_A_16,
            &GLYPH_E_16,
        ]
    };

    let base_h = glyphs[0].len();
    let base_gap = if canvas.width >= 66 { 4usize } else { 2usize };
    let scale_num = if hero_scale { 3usize } else { 1usize };
    let scale_den = if hero_scale { 2usize } else { 1usize };

    let scaled_len = |v: usize| -> usize { (v * scale_num) / scale_den };
    let gap = scaled_len(base_gap).max(2);
    let total_w: usize =
        glyphs.iter().map(|g| scaled_len(g[0].len())).sum::<usize>() + gap * (glyphs.len() - 1);
    let total_h = scaled_len(base_h);

    // Snap origin to even X and multiple-of-4 Y for crisp Braille cell pillar alignment.
    let raw_x0 = px_w.saturating_sub(total_w) / 2;
    let origin_x = (raw_x0 & !1) as isize;
    let raw_y0 = px_h.saturating_sub(total_h) / 2;
    let origin_y = ((raw_y0 + 2) & !3).min(px_h.saturating_sub(total_h)) as isize;

    let cx = origin_x as f64 + (total_w as f64) * 0.5;
    let cy = origin_y as f64 + (total_h as f64) * 0.5;
    let halo_r: isize = if hero_scale { 4 } else { 3 };

    let mut cursor_x = origin_x;
    for glyph in &glyphs {
        let gw_base = glyph[0].len();
        let gh_base = glyph.len();
        let gw = scaled_len(gw_base);

        for (by, row_str) in glyph.iter().enumerate() {
            let sy0 = (by * scale_num) / scale_den;
            let sy1 = (((by + 1) * scale_num) / scale_den).max(sy0 + 1);
            for (bx, ch) in row_str.bytes().enumerate() {
                if ch != b'#' {
                    continue;
                }
                let sx0 = (bx * scale_num) / scale_den;
                let sx1 = (((bx + 1) * scale_num) / scale_den).max(sx0 + 1);

                for dy in sy0..sy1 {
                    for dx in sx0..sx1 {
                        let px = cursor_x + dx as isize;
                        let py = origin_y + dy as isize;
                        let rx = ((px as f64 - cx) / ((total_w as f64) * 0.54).max(1.0)).abs();
                        let ry = ((py as f64 - cy) / ((total_h as f64) * 0.72).max(1.0)).abs();
                        let radial = rx.hypot(ry * 0.55).clamp(0.0, 1.25);

                        let reveal = if p >= 0.99 {
                            1.0
                        } else {
                            smoothstep(0.24 + radial * 0.30, 0.44 + radial * 0.30, p)
                        };
                        if reveal <= 0.14 {
                            continue;
                        }

                        canvas.mark_wordmark_pixel(px, py, halo_r);

                        let u_x =
                            ((px - origin_x) as f64 / (total_w as f64).max(1.0)).clamp(0.0, 1.0);
                        let u_y = ((py - origin_y) as f64
                            / (gh_base as f64 * scale_num as f64 / scale_den as f64).max(1.0))
                        .clamp(0.0, 1.0);
                        let base_shimmer = wordmark_shimmer_value(u_x, u_y, phase);
                        // Brief warm-gold ignition rim as letters crystallize during intro growth.
                        let ignite_rim = if p < 0.99 {
                            gaussian((reveal - 0.52).abs(), 0.24) * 0.55
                        } else {
                            0.0
                        };
                        let shimmer = (base_shimmer + ignite_rim).clamp(0.0, 1.0);
                        canvas.plot_wordmark_pixel(px, py, reveal, shimmer);
                    }
                }
            }
        }
        cursor_x += (gw + gap) as isize;
    }

    WordmarkBox {
        x0: origin_x as f64,
        y0: origin_y as f64,
        x1: (origin_x as usize + total_w) as f64,
        y1: (origin_y as usize + total_h) as f64,
    }
}

fn draw_narrow_wordmark(canvas: &mut BrailleCanvas, p: f64, phase: f64) -> WordmarkBox {
    let width = canvas.width;
    let height = canvas.height;
    let cy_row = height / 2;

    let banner = if width >= 25 {
        "· ✦  H Y P H A E  ✦ ·"
    } else if width >= 13 {
        "H Y P H A E"
    } else {
        "HYPHAE"
    };
    let banner_chars: Vec<char> = banner.chars().take(width).collect();
    let len = banner_chars.len();
    let start_col = width.saturating_sub(len) / 2;

    let wm_x0 = (start_col * 2) as f64;
    let wm_x1 = ((start_col + len) * 2) as f64;
    let wm_y0 = (cy_row * 4) as f64;
    let wm_y1 = ((cy_row + 1) * 4) as f64;

    if p >= 0.22 {
        // Reserve a clean 1-cell vertical & 2-sub-pixel horizontal cushion around narrow wordmark.
        canvas.mark_halo_rect(
            (wm_x0 as isize) - 2,
            (wm_y0 as isize) - 2,
            (wm_x1 as isize) + 2,
            (wm_y1 as isize) + 2,
        );
    }

    let mid = (len as f64 - 1.0) * 0.5;
    for (idx, &ch) in banner_chars.iter().enumerate() {
        let dist = ((idx as f64 - mid).abs() / mid.max(1.0)).clamp(0.0, 1.0);
        let reveal = if p >= 0.99 {
            1.0
        } else {
            smoothstep(0.22 + dist * 0.34, 0.42 + dist * 0.34, p)
        };
        if reveal <= 0.15 || ch == ' ' {
            continue;
        }
        let u_x = (idx as f64) / (len.saturating_sub(1).max(1) as f64);
        let shimmer = wordmark_shimmer_value(u_x, 0.5, phase);
        let cx = start_col + idx;
        if ch == '✦' {
            let pulse = 0.45 + 0.55 * (phase * 2.4 * PI + idx as f64).sin().abs();
            canvas.set_override_cell(
                cx,
                cy_row,
                BrailleCell {
                    override_ch: Some(ch),
                    spore_energy: 0.95 * reveal,
                    pulse_energy: pulse * reveal,
                    ..BrailleCell::default()
                },
            );
        } else if ch == '·' {
            canvas.set_override_cell(
                cx,
                cy_row,
                BrailleCell {
                    override_ch: Some(ch),
                    tendril_energy: 0.72 * reveal,
                    ..BrailleCell::default()
                },
            );
        } else {
            canvas.set_override_cell(
                cx,
                cy_row,
                BrailleCell {
                    override_ch: Some(ch),
                    wordmark_energy: reveal,
                    wordmark_shimmer: shimmer,
                    ..BrailleCell::default()
                },
            );
        }
    }

    WordmarkBox {
        x0: wm_x0,
        y0: wm_y0,
        x1: wm_x1,
        y1: wm_y1,
    }
}

fn build_botanical_topology(
    px_w: f64,
    px_h: f64,
    wm: &WordmarkBox,
    tall_mode: bool,
) -> (Vec<MyceliumStrand>, Vec<SporeHub>) {
    let cy = (px_h - 1.0) * 0.5;
    let wm_w = (wm.x1 - wm.x0).max(8.0);
    let wm_h = (wm.y1 - wm.y0).max(4.0);
    let left_span = wm.x0.max(6.0);
    let right_span = (px_w - wm.x1).max(6.0);
    let top_span = wm.y0.max(4.0);
    let bot_span = (px_h - wm.y1).max(4.0);
    let flank_pad = if px_w >= 130.0 { 4.0 } else { 2.5 };

    let mut strands = Vec::with_capacity(32);
    let mut hubs = Vec::with_capacity(24);

    let mut add_strand_with_hubs = |s: MyceliumStrand, hub_specs: &[(f64, f64)]| {
        for &(u, radius) in hub_specs {
            let (hx, hy) = cubic_bezier(s.p0, s.p1, s.p2, s.p3, u);
            let appear_p = lerp_f64(s.start_p, s.end_p, u);
            hubs.push(SporeHub {
                x: hx,
                y: hy,
                radius,
                appear_p,
                pulse_speed: s.pulse_speed,
                pulse_offset: s.pulse_offset,
                pulse_u: u,
                respect_halo: s.respect_halo,
            });
        }
        strands.push(s);
    };

    // 1. Left Botanical Flank Flourishes (airy asymmetric fronds radiating outside H's halo)
    let l_up = (wm.x0 - flank_pad, wm.y0 + wm_h * 0.14);
    let l_mid = (wm.x0 - flank_pad - 0.5, cy + wm_h * 0.06);
    let l_lo = (wm.x0 - flank_pad, wm.y1 - wm_h * 0.14);

    // Left upper S-sweep arcing gracefully up & outward into the upper-left void
    let lu_p0 = l_up;
    let lu_p1 = (wm.x0 - left_span * 0.34, wm.y0 - top_span * 0.05);
    let lu_p2 = (wm.x0 - left_span * 0.52, wm.y0 - top_span * 0.68);
    let lu_p3 = (px_w * 0.06, px_h * 0.12);
    let lu_fork_a = cubic_bezier(lu_p0, lu_p1, lu_p2, lu_p3, 0.42);
    let lu_fork_b = cubic_bezier(lu_p0, lu_p1, lu_p2, lu_p3, 0.68);
    add_strand_with_hubs(
        MyceliumStrand {
            p0: lu_p0,
            p1: lu_p1,
            p2: lu_p2,
            p3: lu_p3,
            start_p: 0.08,
            end_p: 0.56,
            energy: 0.92,
            pulse_speed: 0.95,
            pulse_offset: 0.04,
            bold: true,
            respect_halo: true,
        },
        &[(0.42, 1.08), (0.85, 0.90)],
    );

    // Left upper botanical sprig curving inward above `H Y` and terminating in an amber bud
    add_strand_with_hubs(
        MyceliumStrand {
            p0: lu_fork_a,
            p1: (wm.x0 - left_span * 0.08, wm.y0 - top_span * 0.78),
            p2: (wm.x0 + wm_w * 0.14, wm.y0 - top_span * 0.72),
            p3: (wm.x0 + wm_w * 0.27, wm.y0 - top_span * 0.34),
            start_p: 0.28,
            end_p: 0.72,
            energy: 0.78,
            pulse_speed: 1.12,
            pulse_offset: 0.22,
            bold: false,
            respect_halo: true,
        },
        &[(0.96, 1.02)],
    );

    // Left outer filigree capillary curling softly down-left into open margin
    add_strand_with_hubs(
        MyceliumStrand {
            p0: lu_fork_b,
            p1: (px_w * 0.09, px_h * 0.28),
            p2: (px_w * 0.05, px_h * 0.36),
            p3: (px_w * 0.03, px_h * 0.46),
            start_p: 0.38,
            end_p: 0.80,
            energy: 0.60,
            pulse_speed: 1.28,
            pulse_offset: 0.55,
            bold: false,
            respect_halo: true,
        },
        &[],
    );

    // Left mid-flank sinuous tendril
    add_strand_with_hubs(
        MyceliumStrand {
            p0: l_mid,
            p1: (wm.x0 - left_span * 0.34, cy + wm_h * 0.24),
            p2: (wm.x0 - left_span * 0.68, cy - wm_h * 0.22),
            p3: (px_w * 0.045, cy - px_h * 0.06),
            start_p: 0.12,
            end_p: 0.60,
            energy: 0.80,
            pulse_speed: -1.04,
            pulse_offset: 0.31,
            bold: false,
            respect_halo: true,
        },
        &[(0.58, 0.96)],
    );

    // Left lower root sweep curving sinuously down-left
    let ll_p0 = l_lo;
    let ll_p1 = (wm.x0 - left_span * 0.30, wm.y1 + bot_span * 0.06);
    let ll_p2 = (wm.x0 - left_span * 0.56, wm.y1 + bot_span * 0.72);
    let ll_p3 = (px_w * 0.08, px_h * 0.88);
    let ll_fork_a = cubic_bezier(ll_p0, ll_p1, ll_p2, ll_p3, 0.44);
    let ll_fork_b = cubic_bezier(ll_p0, ll_p1, ll_p2, ll_p3, 0.70);
    add_strand_with_hubs(
        MyceliumStrand {
            p0: ll_p0,
            p1: ll_p1,
            p2: ll_p2,
            p3: ll_p3,
            start_p: 0.10,
            end_p: 0.58,
            energy: 0.90,
            pulse_speed: 0.90,
            pulse_offset: 0.48,
            bold: true,
            respect_halo: true,
        },
        &[(0.44, 1.08), (0.85, 0.90)],
    );

    // Left lower botanical rootlet curling gently under `H Y` toward a glowing spore node
    add_strand_with_hubs(
        MyceliumStrand {
            p0: ll_fork_a,
            p1: (wm.x0 - left_span * 0.04, wm.y1 + bot_span * 0.78),
            p2: (wm.x0 + wm_w * 0.18, wm.y1 + bot_span * 0.72),
            p3: (wm.x0 + wm_w * 0.33, wm.y1 + bot_span * 0.36),
            start_p: 0.32,
            end_p: 0.76,
            energy: 0.76,
            pulse_speed: 1.08,
            pulse_offset: 0.71,
            bold: false,
            respect_halo: true,
        },
        &[(0.96, 1.00)],
    );

    // Left lower outer capillary
    add_strand_with_hubs(
        MyceliumStrand {
            p0: ll_fork_b,
            p1: (px_w * 0.11, px_h * 0.74),
            p2: (px_w * 0.06, px_h * 0.68),
            p3: (px_w * 0.035, px_h * 0.58),
            start_p: 0.42,
            end_p: 0.84,
            energy: 0.58,
            pulse_speed: -1.24,
            pulse_offset: 0.16,
            bold: false,
            respect_halo: true,
        },
        &[],
    );

    // 2. Right Botanical Flank Flourishes (organic asymmetric counterpart outside E's halo)
    let r_up = (wm.x1 + flank_pad, wm.y0 + wm_h * 0.16);
    let r_mid = (wm.x1 + flank_pad + 0.5, cy - wm_h * 0.06);
    let r_lo = (wm.x1 + flank_pad, wm.y1 - wm_h * 0.16);

    // Right upper S-sweep
    let ru_p0 = r_up;
    let ru_p1 = (wm.x1 + right_span * 0.32, wm.y0 - top_span * 0.06);
    let ru_p2 = (wm.x1 + right_span * 0.56, wm.y0 - top_span * 0.74);
    let ru_p3 = (px_w * 0.94, px_h * 0.12);
    let ru_fork_a = cubic_bezier(ru_p0, ru_p1, ru_p2, ru_p3, 0.40);
    let ru_fork_b = cubic_bezier(ru_p0, ru_p1, ru_p2, ru_p3, 0.66);
    add_strand_with_hubs(
        MyceliumStrand {
            p0: ru_p0,
            p1: ru_p1,
            p2: ru_p2,
            p3: ru_p3,
            start_p: 0.09,
            end_p: 0.57,
            energy: 0.92,
            pulse_speed: 1.00,
            pulse_offset: 0.52,
            bold: true,
            respect_halo: true,
        },
        &[(0.40, 1.08), (0.85, 0.90)],
    );

    // Right upper botanical sprig arching over `A E` into a glowing amber bud
    add_strand_with_hubs(
        MyceliumStrand {
            p0: ru_fork_a,
            p1: (wm.x1 + right_span * 0.06, wm.y0 - top_span * 0.80),
            p2: (wm.x0 + wm_w * 0.84, wm.y0 - top_span * 0.68),
            p3: (wm.x0 + wm_w * 0.69, wm.y0 - top_span * 0.36),
            start_p: 0.30,
            end_p: 0.74,
            energy: 0.78,
            pulse_speed: -1.10,
            pulse_offset: 0.68,
            bold: false,
            respect_halo: true,
        },
        &[(0.96, 1.02)],
    );

    // Right outer filigree capillary
    add_strand_with_hubs(
        MyceliumStrand {
            p0: ru_fork_b,
            p1: (px_w * 0.91, px_h * 0.28),
            p2: (px_w * 0.95, px_h * 0.35),
            p3: (px_w * 0.97, px_h * 0.44),
            start_p: 0.40,
            end_p: 0.82,
            energy: 0.60,
            pulse_speed: 1.26,
            pulse_offset: 0.87,
            bold: false,
            respect_halo: true,
        },
        &[],
    );

    // Right mid-flank sinuous tendril
    add_strand_with_hubs(
        MyceliumStrand {
            p0: r_mid,
            p1: (wm.x1 + right_span * 0.34, cy - wm_h * 0.20),
            p2: (wm.x1 + right_span * 0.68, cy + wm_h * 0.24),
            p3: (px_w * 0.955, cy + px_h * 0.06),
            start_p: 0.14,
            end_p: 0.62,
            energy: 0.80,
            pulse_speed: 1.06,
            pulse_offset: 0.79,
            bold: false,
            respect_halo: true,
        },
        &[(0.60, 0.96)],
    );

    // Right lower root sweep
    let rl_p0 = r_lo;
    let rl_p1 = (wm.x1 + right_span * 0.32, wm.y1 + bot_span * 0.10);
    let rl_p2 = (wm.x1 + right_span * 0.58, wm.y1 + bot_span * 0.70);
    let rl_p3 = (px_w * 0.92, px_h * 0.86);
    let rl_fork_a = cubic_bezier(rl_p0, rl_p1, rl_p2, rl_p3, 0.44);
    let rl_fork_b = cubic_bezier(rl_p0, rl_p1, rl_p2, rl_p3, 0.70);
    add_strand_with_hubs(
        MyceliumStrand {
            p0: rl_p0,
            p1: rl_p1,
            p2: rl_p2,
            p3: rl_p3,
            start_p: 0.11,
            end_p: 0.59,
            energy: 0.90,
            pulse_speed: 0.92,
            pulse_offset: 0.19,
            bold: true,
            respect_halo: true,
        },
        &[(0.44, 1.08), (0.86, 0.90)],
    );

    // Right lower botanical rootlet curving gently under `A E` into a glowing spore node
    add_strand_with_hubs(
        MyceliumStrand {
            p0: rl_fork_a,
            p1: (wm.x1 + right_span * 0.04, wm.y1 + bot_span * 0.78),
            p2: (wm.x0 + wm_w * 0.82, wm.y1 + bot_span * 0.70),
            p3: (wm.x0 + wm_w * 0.68, wm.y1 + bot_span * 0.38),
            start_p: 0.34,
            end_p: 0.78,
            energy: 0.76,
            pulse_speed: -1.06,
            pulse_offset: 0.38,
            bold: false,
            respect_halo: true,
        },
        &[(0.96, 1.00)],
    );

    // Right lower outer capillary
    add_strand_with_hubs(
        MyceliumStrand {
            p0: rl_fork_b,
            p1: (px_w * 0.89, px_h * 0.72),
            p2: (px_w * 0.94, px_h * 0.66),
            p3: (px_w * 0.965, px_h * 0.56),
            start_p: 0.44,
            end_p: 0.86,
            energy: 0.58,
            pulse_speed: 1.22,
            pulse_offset: 0.63,
            bold: false,
            respect_halo: true,
        },
        &[],
    );

    // 3. Airy Central Crown Sprout (delicate rising S-wisp above `P H`, leaving open breathing sky!)
    let crown_p0 = (wm.x0 + wm_w * 0.45, wm.y0 - top_span * 0.22);
    let crown_p1 = (wm.x0 + wm_w * 0.47, wm.y0 - top_span * 0.62);
    let crown_p2 = (wm.x0 + wm_w * 0.55, wm.y0 - top_span * 0.86);
    let crown_p3 = (wm.x0 + wm_w * 0.63, px_h * 0.04);
    let crown_fork = cubic_bezier(crown_p0, crown_p1, crown_p2, crown_p3, 0.46);
    add_strand_with_hubs(
        MyceliumStrand {
            p0: crown_p0,
            p1: crown_p1,
            p2: crown_p2,
            p3: crown_p3,
            start_p: 0.24,
            end_p: 0.70,
            energy: 0.76,
            pulse_speed: 0.88,
            pulse_offset: 0.14,
            bold: false,
            respect_halo: true,
        },
        &[(0.46, 1.02)],
    );
    // Tiny left-curling branch off the central crown
    add_strand_with_hubs(
        MyceliumStrand {
            p0: crown_fork,
            p1: (wm.x0 + wm_w * 0.44, wm.y0 - top_span * 0.76),
            p2: (wm.x0 + wm_w * 0.39, wm.y0 - top_span * 0.88),
            p3: (wm.x0 + wm_w * 0.34, px_h * 0.05),
            start_p: 0.40,
            end_p: 0.84,
            energy: 0.62,
            pulse_speed: 1.18,
            pulse_offset: 0.46,
            bold: false,
            respect_halo: true,
        },
        &[],
    );

    // 4. Airy Central Root Sprout (delicate descending S-root below `P H`)
    let root_p0 = (wm.x0 + wm_w * 0.53, wm.y1 + bot_span * 0.22);
    let root_p1 = (wm.x0 + wm_w * 0.51, wm.y1 + bot_span * 0.62);
    let root_p2 = (wm.x0 + wm_w * 0.44, wm.y1 + bot_span * 0.86);
    let root_p3 = (wm.x0 + wm_w * 0.36, px_h * 0.96);
    let root_fork = cubic_bezier(root_p0, root_p1, root_p2, root_p3, 0.48);
    add_strand_with_hubs(
        MyceliumStrand {
            p0: root_p0,
            p1: root_p1,
            p2: root_p2,
            p3: root_p3,
            start_p: 0.26,
            end_p: 0.72,
            energy: 0.76,
            pulse_speed: -0.90,
            pulse_offset: 0.61,
            bold: false,
            respect_halo: true,
        },
        &[(0.48, 1.02)],
    );
    // Tiny right-curling branch off the central root
    add_strand_with_hubs(
        MyceliumStrand {
            p0: root_fork,
            p1: (wm.x0 + wm_w * 0.54, wm.y1 + bot_span * 0.78),
            p2: (wm.x0 + wm_w * 0.60, wm.y1 + bot_span * 0.88),
            p3: (wm.x0 + wm_w * 0.65, px_h * 0.95),
            start_p: 0.42,
            end_p: 0.86,
            energy: 0.62,
            pulse_speed: 1.16,
            pulse_offset: 0.84,
            bold: false,
            respect_halo: true,
        },
        &[],
    );

    // 5. Expanded Organic Mycelium Canopy & Root Web for Tall Fullscreen Canvases
    // (activated only when vertical margins are genuinely spacious: `top_span >= 22px`, e.g. `54×18`, `100×32`)
    if tall_mode && top_span >= 20.0 && bot_span >= 20.0 {
        // Upper-left rising botanical bough arcing gracefully into the high sky
        let ul_p0 = (wm.x0 + wm_w * 0.20, wm.y0 - top_span * 0.26);
        let ul_p1 = (wm.x0 + wm_w * 0.14, wm.y0 - top_span * 0.56);
        let ul_p2 = (px_w * 0.24, px_h * 0.16);
        let ul_p3 = (px_w * 0.12, px_h * 0.06);
        let ul_node = cubic_bezier(ul_p0, ul_p1, ul_p2, ul_p3, 0.52);
        add_strand_with_hubs(
            MyceliumStrand {
                p0: ul_p0,
                p1: ul_p1,
                p2: ul_p2,
                p3: ul_p3,
                start_p: 0.24,
                end_p: 0.76,
                energy: 0.78,
                pulse_speed: 0.84,
                pulse_offset: 0.27,
                bold: false,
                respect_halo: true,
            },
            &[(0.52, 1.12)],
        );

        // Upper-right rising botanical bough
        let ur_p0 = (wm.x0 + wm_w * 0.78, wm.y0 - top_span * 0.28);
        let ur_p1 = (wm.x0 + wm_w * 0.84, wm.y0 - top_span * 0.58);
        let ur_p2 = (px_w * 0.74, px_h * 0.14);
        let ur_p3 = (px_w * 0.86, px_h * 0.05);
        let ur_node = cubic_bezier(ur_p0, ur_p1, ur_p2, ur_p3, 0.50);
        add_strand_with_hubs(
            MyceliumStrand {
                p0: ur_p0,
                p1: ur_p1,
                p2: ur_p2,
                p3: ur_p3,
                start_p: 0.26,
                end_p: 0.78,
                energy: 0.78,
                pulse_speed: -0.86,
                pulse_offset: 0.74,
                bold: false,
                respect_halo: true,
            },
            &[(0.50, 1.12)],
        );

        // High sinuous anastomosis bridging ul_node -> ur_node through open upper sky
        add_strand_with_hubs(
            MyceliumStrand {
                p0: ul_node,
                p1: (px_w * 0.40, px_h * 0.06),
                p2: (px_w * 0.58, wm.y0 - top_span * 0.48),
                p3: ur_node,
                start_p: 0.40,
                end_p: 0.86,
                energy: 0.66,
                pulse_speed: 0.94,
                pulse_offset: 0.08,
                bold: false,
                respect_halo: true,
            },
            &[(0.52, 0.98)],
        );

        // Lower-left descending root bough
        let dl_p0 = (wm.x0 + wm_w * 0.22, wm.y1 + bot_span * 0.28);
        let dl_p1 = (wm.x0 + wm_w * 0.16, wm.y1 + bot_span * 0.58);
        let dl_p2 = (px_w * 0.26, px_h * 0.84);
        let dl_p3 = (px_w * 0.14, px_h * 0.94);
        let dl_node = cubic_bezier(dl_p0, dl_p1, dl_p2, dl_p3, 0.50);
        add_strand_with_hubs(
            MyceliumStrand {
                p0: dl_p0,
                p1: dl_p1,
                p2: dl_p2,
                p3: dl_p3,
                start_p: 0.25,
                end_p: 0.77,
                energy: 0.78,
                pulse_speed: -0.82,
                pulse_offset: 0.39,
                bold: false,
                respect_halo: true,
            },
            &[(0.50, 1.12)],
        );

        // Lower-right descending root bough
        let dr_p0 = (wm.x0 + wm_w * 0.76, wm.y1 + bot_span * 0.26);
        let dr_p1 = (wm.x0 + wm_w * 0.82, wm.y1 + bot_span * 0.56);
        let dr_p2 = (px_w * 0.72, px_h * 0.86);
        let dr_p3 = (px_w * 0.84, px_h * 0.95);
        let dr_node = cubic_bezier(dr_p0, dr_p1, dr_p2, dr_p3, 0.52);
        add_strand_with_hubs(
            MyceliumStrand {
                p0: dr_p0,
                p1: dr_p1,
                p2: dr_p2,
                p3: dr_p3,
                start_p: 0.27,
                end_p: 0.79,
                energy: 0.78,
                pulse_speed: 0.85,
                pulse_offset: 0.88,
                bold: false,
                respect_halo: true,
            },
            &[(0.52, 1.12)],
        );

        // Deep sinuous anastomosis bridging dl_node -> dr_node through lower root space
        add_strand_with_hubs(
            MyceliumStrand {
                p0: dl_node,
                p1: (px_w * 0.42, wm.y1 + bot_span * 0.46),
                p2: (px_w * 0.60, px_h * 0.94),
                p3: dr_node,
                start_p: 0.42,
                end_p: 0.88,
                energy: 0.66,
                pulse_speed: -0.96,
                pulse_offset: 0.51,
                bold: false,
                respect_halo: true,
            },
            &[(0.48, 0.98)],
        );
    }

    (strands, hubs)
}

/// Render one frame of the HYPHAE wordmark and its growing mycelium network.
/// Width and height are measured in terminal cells. The zero-based frame index
/// controls growth. Advance the pulse tick to animate a fully grown network.
pub fn render_frame(
    frame_idx: usize,
    total_frames: usize,
    pulse_tick: usize,
    width: usize,
    height: usize,
    color_mode: ColorMode,
) -> String {
    let phase = (pulse_tick as f64) * 0.045;
    if width == 0 || height == 0 {
        return String::new();
    }

    let denom = total_frames.saturating_sub(1).max(1) as f64;
    let p = (frame_idx.min(total_frames.saturating_sub(1)) as f64) / denom;
    let effective_phase = phase + p * 0.60;

    let mut canvas = BrailleCanvas::new(width, height);
    let px_w = canvas.px_w as f64;
    let px_h = canvas.px_h as f64;
    let cx = (px_w - 1.0) * 0.5;
    let cy = (px_h - 1.0) * 0.5;

    // 1. Render the `HYPHAE` wordmark first so its negative-space halo protects letter legibility.
    let wm = if width < 46 || height < 6 {
        draw_narrow_wordmark(&mut canvas, p, effective_phase)
    } else {
        draw_braille_wordmark(&mut canvas, p, effective_phase)
    };

    // 2. Early intro central spore seed & nascent germinating filaments (fades cleanly once HYPHAE emerges).
    let seed_vis = 1.0 - smoothstep(0.20, 0.44, p);
    if seed_vis > 0.02 {
        let seed_r = lerp_f64(1.65, 2.35, smoothstep(0.0, 0.16, p));
        canvas.plot_spore_hub(cx, cy, seed_r, 0.98 * seed_vis, 0.88 * seed_vis, false);
        let sprout_growth = smoothstep(0.0, 0.34, p);
        if sprout_growth > 0.01 {
            let sprout_targets = [
                (wm.x0 - 1.5, wm.y0 + (wm.y1 - wm.y0) * 0.20),
                (wm.x0 - 1.5, wm.y1 - (wm.y1 - wm.y0) * 0.20),
                (wm.x1 + 1.5, wm.y0 + (wm.y1 - wm.y0) * 0.18),
                (wm.x1 + 1.5, wm.y1 - (wm.y1 - wm.y0) * 0.18),
                (cx - px_w * 0.14, wm.y0 - 3.0),
                (cx + px_w * 0.14, wm.y1 + 3.0),
            ];
            for (idx, &(tx, ty)) in sprout_targets.iter().enumerate() {
                let sign = if idx % 2 == 0 { 1.0 } else { -1.0 };
                let dx = tx - cx;
                let dy = ty - cy;
                let c1 = (
                    cx + dx * 0.35 - dy * 0.18 * sign,
                    cy + dy * 0.35 + dx * 0.12 * sign,
                );
                let c2 = (
                    cx + dx * 0.72 + dy * 0.14 * sign,
                    cy + dy * 0.72 - dx * 0.10 * sign,
                );
                canvas.plot_cubic_bezier(
                    (cx, cy),
                    c1,
                    c2,
                    (tx, ty),
                    sprout_growth,
                    0.86 * seed_vis,
                    None,
                    0.0,
                    true,
                    true,
                );
            }
        }
    }

    // 3. Organic curved Braille hyphae, branching capillaries, and anastomoses.
    let tall_mode = height >= 14;
    let (strands, hubs) = build_botanical_topology(px_w, px_h, &wm, tall_mode);

    let pulse_fade = if p >= 0.99 {
        1.0
    } else {
        smoothstep(0.55, 0.80, p)
    };

    for s in &strands {
        let growth = if p >= 0.99 {
            1.0
        } else {
            smoothstep(s.start_p, s.end_p, p)
        };
        if growth <= 0.005 {
            continue;
        }
        let pulse_u = if pulse_fade > 0.01 {
            Some((effective_phase * s.pulse_speed + s.pulse_offset).rem_euclid(1.0))
        } else {
            None
        };
        canvas.plot_cubic_bezier(
            s.p0,
            s.p1,
            s.p2,
            s.p3,
            growth,
            s.energy,
            pulse_u,
            0.94 * pulse_fade,
            s.bold,
            s.respect_halo,
        );
    }

    // 4. Warm-amber bioluminescent spore hubs that flare brightly as traveling pulses pass through.
    for hub in &hubs {
        let arrive = if p >= 0.99 {
            1.0
        } else {
            smoothstep(hub.appear_p - 0.05, hub.appear_p + 0.10, p)
        };
        if arrive <= 0.02 {
            continue;
        }
        let pulse_hit = if pulse_fade > 0.01 {
            let pu = (effective_phase * hub.pulse_speed + hub.pulse_offset).rem_euclid(1.0);
            gaussian(wrapped_unit_dist(hub.pulse_u, pu), 0.11) * pulse_fade
        } else {
            0.0
        };
        let arrive_burst = if p < 0.99 {
            gaussian((p - hub.appear_p).abs(), 0.07) * 0.75
        } else {
            0.0
        };
        let glow = pulse_hit.max(arrive_burst);
        let radius = hub.radius + glow * 0.30;
        canvas.plot_spore_hub(
            hub.x,
            hub.y,
            radius,
            (0.86 * arrive + 0.14 * glow).clamp(0.0, 1.0),
            glow,
            hub.respect_halo,
        );
    }

    canvas.render(color_mode)
}

#[cfg(test)]
mod tests;
