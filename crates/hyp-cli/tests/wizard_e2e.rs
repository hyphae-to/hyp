//! End-to-end deterministic tests for the Interactive Mycelium Onboarding Wizard
//! and `hyphae-setup` Agent Concierge (`crates/hyp-cli/src/wizard.rs`, `setup.rs`).
//!
//! Covers:
//! 1. Dot-matrix animation frame rendering via `--preview-anim --no-anim` in Plain (`NO_COLOR=1`)
//!    and 24-bit TrueColor (`COLORTERM=truecolor`) modes with exact canvas dimensions.
//! 2. `hyp onboard --install-skill --home <tmp> --json`: detects fake harness config dirs
//!    (`.claude`, `.codex`, `.gemini`, `.config/opencode`, `.cursor`), installs
//!    `hyphae-setup/SKILL.md` into the exact global skill paths, and matches
//!    `skills/hyphae-setup/SKILL.md` byte-for-byte with clean v2 security invariants.
//! 3. `hyp onboard --assist <harness> --home <tmp>` with isolated fake CLI shims for ALL 6
//!    launchable CLIs (`claude`, `codex`, `agy --prompt-interactive`, `opencode --prompt`,
//!    `cursor-agent`, `gemini -i`), verifying pre-launch skill install, exact argv, existing-node
//!    prompt adaptation, and exit-code propagation.
//! 4. Backward compatibility for non-interactive `hyp onboard --home <tmp> --json`, `--yes`, and
//!    piped non-TTY invocations (never hangs waiting for TTY).

mod common;

use common::{isolated_cmd, parse_json_stdout};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tempfile::TempDir;

fn repo_setup_skill_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("skills")
        .join("hyphae-setup")
        .join("SKILL.md")
}

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

#[test]
fn preview_anim_renders_settled_dot_matrix_in_plain_and_truecolor_modes() {
    let tmp = TempDir::new().expect("tempdir");

    let plain_out = isolated_cmd(tmp.path())
        .env("NO_COLOR", "1")
        .env_remove("COLUMNS")
        .args(["onboard", "--preview-anim", "--no-anim"])
        .stdin(Stdio::null())
        .output()
        .expect("run preview-anim plain");
    assert_eq!(
        plain_out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&plain_out.stderr)
    );
    let plain_text = String::from_utf8(plain_out.stdout).expect("utf8");
    assert!(
        !plain_text.contains('\x1b'),
        "NO_COLOR=1 output must contain zero ANSI escapes"
    );
    let plain_lines: Vec<&str> = plain_text.lines().collect();
    assert_eq!(plain_lines.len(), 18, "expected 18 canvas rows");
    for (idx, line) in plain_lines.iter().enumerate() {
        assert_eq!(
            line.chars().count(),
            54,
            "row {idx} must be exactly 54 columns wide"
        );
    }
    assert!(plain_text.contains('●'), "missing agent node glyphs");
    assert!(plain_text.contains('▪'), "missing hyphae dot glyphs");
    assert!(plain_text.contains('·'), "missing ambient halo dot glyphs");

    let tc_out = isolated_cmd(tmp.path())
        .env_remove("NO_COLOR")
        .env_remove("CLICOLOR")
        .env_remove("COLUMNS")
        .env_remove("TERM_PROGRAM")
        .env("TERM", "xterm-256color")
        .env("COLORTERM", "truecolor")
        .args(["onboard", "--preview-anim", "--no-anim"])
        .stdin(Stdio::null())
        .output()
        .expect("run preview-anim truecolor");
    assert_eq!(tc_out.status.code(), Some(0));
    let tc_text = String::from_utf8(tc_out.stdout).expect("utf8");
    assert!(
        tc_text.contains("\x1b[38;2;"),
        "COLORTERM=truecolor output must contain 24-bit RGB escapes"
    );
    assert_eq!(
        strip_ansi(&tc_text),
        plain_text,
        "stripped TrueColor frame must match Plain frame identically"
    );
}

#[test]
fn install_skill_detects_fake_harnesses_and_writes_exact_skill_files() {
    let tmp = TempDir::new().expect("tempdir");
    let home = tmp.path();

    // Fake harness config directories matching real user environments.
    fs::create_dir_all(home.join(".claude")).unwrap();
    fs::create_dir_all(home.join(".codex")).unwrap();
    fs::create_dir_all(home.join(".gemini").join("config")).unwrap();
    fs::write(home.join(".gemini").join("settings.json"), "{}\n").unwrap();
    fs::create_dir_all(home.join(".config").join("opencode")).unwrap();
    fs::create_dir_all(home.join(".cursor")).unwrap();

    let out = isolated_cmd(home)
        .args([
            "onboard",
            "--install-skill",
            "--home",
            home.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run onboard --install-skill");

    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let payload = parse_json_stdout(&out);
    assert_eq!(payload["ok"], true);
    assert_eq!(payload["command"], "onboard");
    assert_eq!(payload["data"]["mode"], "install-skill");
    assert_eq!(payload["data"]["skill"], "hyphae-setup");
    assert_eq!(payload["data"]["installedCount"], 6);

    let canonical = fs::read_to_string(repo_setup_skill_path()).expect("read repo SKILL.md");
    assert!(canonical.starts_with("---\nname: hyphae-setup\n"));
    assert!(!canonical.contains("hyp share"));
    assert!(!canonical.contains("hyp connect"));
    assert!(!canonical.contains("npm install"));
    assert!(!canonical.contains("--value"));

    let expected_paths = [
        home.join(".claude/skills/hyphae-setup/SKILL.md"),
        home.join(".codex/skills/hyphae-setup/SKILL.md"),
        home.join(".agents/skills/hyphae-setup/SKILL.md"),
        home.join(".gemini/config/skills/hyphae-setup/SKILL.md"),
        home.join(".gemini/skills/hyphae-setup/SKILL.md"),
        home.join(".config/opencode/skills/hyphae-setup/SKILL.md"),
        home.join(".cursor/skills/hyphae-setup/SKILL.md"),
    ];

    for path in &expected_paths {
        assert!(path.is_file(), "expected installed skill at {}", path.display());
        let written = fs::read_to_string(path).expect("read installed skill");
        assert_eq!(
            written,
            canonical,
            "installed skill at {} must match skills/hyphae-setup/SKILL.md byte-for-byte",
            path.display()
        );
    }
}

#[test]
fn install_skill_handles_bare_gemini_directory_for_antigravity() {
    let tmp = TempDir::new().expect("tempdir");
    let home = tmp.path();

    fs::create_dir_all(home.join(".claude")).unwrap();
    fs::create_dir_all(home.join(".codex")).unwrap();
    fs::create_dir_all(home.join(".gemini")).unwrap();
    fs::create_dir_all(home.join(".config").join("opencode")).unwrap();
    fs::create_dir_all(home.join(".cursor")).unwrap();

    let out = isolated_cmd(home)
        .args([
            "onboard",
            "--install-skill",
            "--home",
            home.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run onboard --install-skill");

    assert_eq!(out.status.code(), Some(0));
    let payload = parse_json_stdout(&out);
    assert_eq!(payload["ok"], true);
    assert_eq!(payload["data"]["installedCount"], 5);

    let canonical = fs::read_to_string(repo_setup_skill_path()).expect("read repo SKILL.md");
    for rel in [
        ".claude/skills/hyphae-setup/SKILL.md",
        ".codex/skills/hyphae-setup/SKILL.md",
        ".gemini/config/skills/hyphae-setup/SKILL.md",
        ".config/opencode/skills/hyphae-setup/SKILL.md",
        ".cursor/skills/hyphae-setup/SKILL.md",
    ] {
        let p = home.join(rel);
        assert!(p.is_file(), "missing {}", p.display());
        assert_eq!(fs::read_to_string(&p).unwrap(), canonical);
    }
}

#[cfg(unix)]
fn write_executable_shim(bin_dir: &Path, name: &str, expected_skill: &Path, capture_file: &Path, exit_code: i32) {
    use std::os::unix::fs::PermissionsExt;

    let script_path = bin_dir.join(name);
    let script = format!(
        "#!/bin/sh\n\
         set -eu\n\
         if [ -f '{skill}' ]; then\n\
           echo 'SKILL_PREEXISTED=1' > '{cap}'\n\
         else\n\
           echo 'SKILL_PREEXISTED=0' > '{cap}'\n\
         fi\n\
         echo \"ARGC=$#\" >> '{cap}'\n\
         for arg in \"$@\"; do\n\
           printf 'ARG=%s\\n' \"$arg\" >> '{cap}'\n\
         done\n\
         exit {exit_code}\n",
        skill = expected_skill.display(),
        cap = capture_file.display(),
    );
    fs::write(&script_path, script).expect("write shim script");
    fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755)).expect("chmod shim");
}

#[cfg(unix)]
#[test]
fn assist_installs_skill_before_launch_and_invokes_all_six_verified_clis() {
    let cases: &[(&str, &str, &str, Option<&str>, i32)] = &[
        ("claude", "claude", ".claude/skills/hyphae-setup/SKILL.md", None, 0),
        ("codex", "codex", ".codex/skills/hyphae-setup/SKILL.md", None, 0),
        (
            "agy",
            "agy",
            ".gemini/config/skills/hyphae-setup/SKILL.md",
            Some("--prompt-interactive"),
            0,
        ),
        (
            "opencode",
            "opencode",
            ".config/opencode/skills/hyphae-setup/SKILL.md",
            Some("--prompt"),
            0,
        ),
        ("cursor", "cursor-agent", ".cursor/skills/hyphae-setup/SKILL.md", None, 0),
        ("gemini", "gemini", ".gemini/skills/hyphae-setup/SKILL.md", Some("-i"), 7),
    ];

    let canonical = fs::read_to_string(repo_setup_skill_path()).expect("read repo SKILL.md");

    for &(assist_arg, bin_name, skill_rel, expected_flag, shim_exit) in cases {
        let tmp = TempDir::new().expect("tempdir");
        let home = tmp.path().join("home");
        let bin_dir = tmp.path().join("bin");
        let capture = tmp.path().join("capture.txt");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&bin_dir).unwrap();

        let expected_skill = home.join(skill_rel);
        write_executable_shim(&bin_dir, bin_name, &expected_skill, &capture, shim_exit);

        let isolated_path = format!("{}:/usr/bin:/bin", bin_dir.display());
        let out = isolated_cmd(&home)
            .env("PATH", &isolated_path)
            .args([
                "onboard",
                "--assist",
                assist_arg,
                "--home",
                home.to_str().unwrap(),
                "--no-anim",
            ])
            .stdin(Stdio::null())
            .output()
            .unwrap_or_else(|e| panic!("failed running --assist {assist_arg}: {e}"));

        assert_eq!(
            out.status.code(),
            Some(shim_exit),
            "--assist {assist_arg} exit mismatch; stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            fs::read_to_string(&expected_skill).expect("skill installed"),
            canonical
        );

        let captured = fs::read_to_string(&capture).expect("read shim capture");
        let lines: Vec<&str> = captured.lines().collect();
        assert_eq!(
            lines.first().copied(),
            Some("SKILL_PREEXISTED=1"),
            "hyphae-setup/SKILL.md must be installed BEFORE launching {bin_name}"
        );

        if let Some(flag) = expected_flag {
            assert_eq!(lines.get(1).copied(), Some("ARGC=2"), "case {assist_arg}: {captured}");
            assert_eq!(
                lines.get(2).copied(),
                Some(format!("ARG={flag}").as_str()),
                "case {assist_arg} must pass exact flag {flag}"
            );
            let prompt_line = lines.get(3).copied().unwrap_or("");
            assert!(
                prompt_line.contains("hyphae-setup")
                    && prompt_line.contains(&expected_skill.display().to_string()),
                "case {assist_arg} prompt missing skill reference: {prompt_line}"
            );
        } else {
            assert_eq!(lines.get(1).copied(), Some("ARGC=1"), "case {assist_arg}: {captured}");
            let prompt_line = lines.get(2).copied().unwrap_or("");
            assert!(
                prompt_line.contains("hyphae-setup")
                    && prompt_line.contains(&expected_skill.display().to_string()),
                "case {assist_arg} prompt missing skill reference: {prompt_line}"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn assist_on_existing_node_adapts_prompt_for_ongoing_configuration() {
    let tmp = TempDir::new().expect("tempdir");
    let home = tmp.path().join("home");
    let bin_dir = tmp.path().join("bin");
    let capture = tmp.path().join("capture.txt");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&bin_dir).unwrap();

    // First bootstrap a real node under `home`.
    let bootstrap = isolated_cmd(&home)
        .args([
            "onboard",
            "--yes",
            "--home",
            home.to_str().unwrap(),
            "--node-id",
            "alice@workstation",
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("bootstrap node");
    assert_eq!(bootstrap.status.code(), Some(0));

    let expected_skill = home.join(".claude/skills/hyphae-setup/SKILL.md");
    write_executable_shim(&bin_dir, "claude", &expected_skill, &capture, 0);

    let isolated_path = format!("{}:/usr/bin:/bin", bin_dir.display());
    let assist_out = isolated_cmd(&home)
        .env("PATH", &isolated_path)
        .args([
            "onboard",
            "--assist",
            "claude",
            "--home",
            home.to_str().unwrap(),
            "--no-anim",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run assist on existing node");
    assert_eq!(assist_out.status.code(), Some(0));

    let captured = fs::read_to_string(&capture).expect("read capture");
    assert!(
        captured.contains("existing Hyphae node (alice@workstation)"),
        "expected existing-node prompt adaptation, got:\n{captured}"
    );
}

#[test]
fn non_interactive_onboard_preserves_backward_compatibility_and_never_hangs() {
    let tmp = TempDir::new().expect("tempdir");
    let home = tmp.path().join("home1");
    fs::create_dir_all(&home).unwrap();

    // 1. `--home <tmp> --json` behaves identically to before.
    let json_out = isolated_cmd(&home)
        .args(["onboard", "--home", home.to_str().unwrap(), "--json"])
        .stdin(Stdio::null())
        .output()
        .expect("onboard --json");
    assert_eq!(json_out.status.code(), Some(0));
    let payload = parse_json_stdout(&json_out);
    assert_eq!(payload["ok"], true);
    assert_eq!(payload["command"], "onboard");
    assert!(payload["data"]["kid"].as_str().unwrap().len() >= 32);
    assert!(home.join(".config/hyphae/node.json").is_file());
    assert!(home.join(".config/hyphae/node.sqlite").is_file());

    // 2. Non-TTY plain `hyp onboard` (with no flags at all) runs deterministically without waiting for TTY.
    let home2 = tmp.path().join("home2");
    fs::create_dir_all(&home2).unwrap();
    let plain_out = isolated_cmd(&home2)
        .env("HYPHAE_NO_SERVICE", "1")
        .args(["onboard"])
        .stdin(Stdio::null())
        .output()
        .expect("non-tty onboard");
    assert_eq!(
        plain_out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&plain_out.stderr)
    );
    let stdout = String::from_utf8_lossy(&plain_out.stdout);
    assert!(stdout.contains("Onboarded Hyphae v2 Node"), "stdout={stdout}");
    // Concise default Next steps (no redundant --config / --state-dir flags when using default paths).
    assert!(stdout.contains("hyp status\n") || stdout.contains("hyp status\r\n"), "stdout={stdout}");
    assert!(
        !stdout.contains("hyp status --state-dir"),
        "default onboard should emit concise Next steps without redundant --state-dir: {stdout}"
    );
    assert!(home2.join(".config/hyphae/node.json").is_file());

    // 3. Invalid `--assist` value fails cleanly with usage exit code 2.
    let bad_out = isolated_cmd(&home2)
        .args(["onboard", "--assist", "not-a-real-harness", "--json"])
        .stdin(Stdio::null())
        .output()
        .expect("invalid assist");
    assert_eq!(bad_out.status.code(), Some(2));
    let bad_json = parse_json_stdout(&bad_out);
    assert_eq!(bad_json["ok"], false);
    assert_eq!(bad_json["error"]["code"], "INVALID_ASSIST_HARNESS");
}

#[test]
fn setup_codex_and_claude_write_descriptive_status_messages_and_replace_unnamed_hooks() {
    let tmp = TempDir::new().expect("tempdir");
    let home = tmp.path();
    fs::create_dir_all(home.join(".codex")).unwrap();
    fs::create_dir_all(home.join(".claude")).unwrap();

    // Pre-populate legacy unnamed Hyphae hooks to ensure idempotent replacement (no duplicates!).
    fs::write(
        home.join(".codex/hooks.json"),
        r#"{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": ".*hyp_.*",
        "hooks": [{ "type": "command", "command": "/old/bin/hyp hook codex pre-tool-use", "timeout": 10 }]
      },
      {
        "matcher": "custom",
        "hooks": [{ "type": "command", "command": "echo keep-me", "timeout": 5 }]
      }
    ]
  }
}
"#,
    )
    .unwrap();

    let out = isolated_cmd(home)
        .args([
            "setup",
            "--harness",
            "codex,claude",
            "--home",
            home.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run setup codex,claude");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );

    let codex_hooks: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(home.join(".codex/hooks.json")).unwrap()).unwrap();
    let claude_settings: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(home.join(".claude/settings.json")).unwrap())
            .unwrap();

    // Unrelated user hook preserved, old unnamed Hyphae hook replaced (exact count == 2: custom + new Hyphae).
    assert_eq!(codex_hooks["hooks"]["PreToolUse"].as_array().unwrap().len(), 2);

    for (event, expected_msg) in [
        ("SessionStart", "Hyphae · Register session"),
        ("PreToolUse", "Hyphae · Verify MCP caller"),
        ("PostToolUse", "Hyphae · Deliver inbox messages"),
        ("Stop", "Hyphae · Check inbox on turn end"),
    ] {
        let codex_arr = codex_hooks["hooks"][event].as_array().unwrap();
        assert!(
            codex_arr.iter().any(|group| {
                group["hooks"]
                    .as_array()
                    .is_some_and(|arr| arr.iter().any(|h| h["statusMessage"] == expected_msg))
            }),
            "codex {event} missing statusMessage '{expected_msg}': {codex_hooks}"
        );

        let claude_arr = claude_settings["hooks"][event].as_array().unwrap();
        assert!(
            claude_arr.iter().any(|group| {
                group["hooks"]
                    .as_array()
                    .is_some_and(|arr| arr.iter().any(|h| h["statusMessage"] == expected_msg))
            }),
            "claude {event} missing statusMessage '{expected_msg}': {claude_settings}"
        );
    }
}

#[test]
fn service_status_json_reports_cleanly_in_isolated_home() {
    let tmp = TempDir::new().expect("tempdir");
    let home = tmp.path();

    let out = isolated_cmd(home)
        .args([
            "service",
            "status",
            "--home",
            home.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run hyp service status --json");
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let payload = parse_json_stdout(&out);
    assert_eq!(payload["ok"], true);
    assert_eq!(payload["command"], "service status");
    assert_eq!(payload["data"]["installed"], false);
    assert_eq!(payload["data"]["daemon"]["alive"], false);
}
