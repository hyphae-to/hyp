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

fn count_lit_dots(plain_frame: &str) -> usize {
    plain_frame
        .chars()
        .filter(|&c| is_braille_char(c) || (!c.is_whitespace() && !c.is_control()))
        .count()
}

#[test]
fn mycelium_frame_renderer_scales_across_compact_and_fullscreen_dimensions() {
    for (width, height, total) in [
        (40, 8, 32),
        (72, 10, 32),
        (54, 18, 29),
        (110, 14, 32),
        (100, 32, 32),
    ] {
        let mut early_lit = 0;
        let mut final_lit = 0;

        for frame_idx in [0, total / 3, (total * 2) / 3, total - 1] {
            let tc = render_frame(frame_idx, total, 0, width, height, ColorMode::TrueColor);
            let ansi256 = render_frame(frame_idx, total, 0, width, height, ColorMode::Ansi256);
            let plain = render_frame(frame_idx, total, 0, width, height, ColorMode::Plain);

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
            assert!(
                !plain.contains('╭') && !plain.contains('╰') && !plain.contains('│'),
                "{width}x{height} frame {frame_idx} must be borderless (no outer box frame)"
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
            assert!(
                lit > 0,
                "{width}x{height} frame {frame_idx} should have lit cells"
            );
            if frame_idx == 0 {
                early_lit = lit;
            }
            if frame_idx == total - 1 {
                final_lit = lit;
                assert!(
                    plain.chars().any(is_braille_char),
                    "{width}x{height} settled frame must contain Unicode Braille characters"
                );
                if width < 46 {
                    assert!(
                        plain.contains("H Y P H A E"),
                        "{width}x{height} narrow settled frame must show compact HYPHAE banner"
                    );
                }
            }
        }

        assert!(
            final_lit >= early_lit * 3,
            "{width}x{height}: expected substantial network growth from spore ({early_lit}) to settled web ({final_lit})"
        );
    }
}

#[test]
fn pulse_ticks_change_frames_across_canvas_sizes() {
    // Sample the same growth frame at three different pulse ticks.
    for (width, height) in [(40, 8), (72, 10), (110, 14)] {
        let tick0 = render_frame(31, 32, 0, width, height, ColorMode::TrueColor);
        let tick8 = render_frame(31, 32, 8, width, height, ColorMode::TrueColor);
        let tick16 = render_frame(31, 32, 16, width, height, ColorMode::TrueColor);
        assert_ne!(tick0, tick8, "{width}x{height}: ticks 0 and 8 must differ");
        assert_ne!(
            tick8, tick16,
            "{width}x{height}: ticks 8 and 16 must differ"
        );
        assert_ne!(
            tick0, tick16,
            "{width}x{height}: ticks 0 and 16 must differ"
        );

        let plain = render_frame(31, 32, 8, width, height, ColorMode::Plain);
        assert!(!plain.contains('\x1b'));
        assert!(!plain.contains('╭') && !plain.contains('╰'));
        assert!(plain.chars().any(is_braille_char));
        assert_eq!(strip_ansi(&tick8), plain);
    }

    if std::env::var("HYPHAE_PRINT_CANVAS").ok().as_deref() == Some("1") {
        for (label, w, h, f) in [
            ("72x10 settled", 72, 10, 31),
            ("54x18 settled", 54, 18, 31),
            ("40x8 narrow settled", 40, 8, 31),
            ("110x14 wide settled", 110, 14, 31),
            ("72x10 growth step 0", 72, 10, 0),
            ("72x10 growth step 12", 72, 10, 12),
        ] {
            let frame = render_frame(f, 32, 0, w, h, ColorMode::Plain);
            eprintln!("\n=== {label} ({w}x{h}) ===\n{frame}\n");
        }
    }
}
