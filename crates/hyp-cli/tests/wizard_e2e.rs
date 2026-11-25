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
#[cfg(unix)]
use std::io;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::{Command, Output};
use std::process::Stdio;
#[cfg(unix)]
use std::thread;
#[cfg(unix)]
use std::time::Duration;
use tempfile::TempDir;

#[cfg(unix)]
fn output_retrying_busy(cmd: &mut Command) -> Output {
    for attempt in 0..5 {
        match cmd.output() {
            Ok(out) => return out,
            Err(e) if e.kind() == io::ErrorKind::ExecutableFileBusy && attempt < 4 => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("failed running test command: {e}"),
        }
    }
    cmd.output().expect("run test command")
}

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
    assert!(
        plain_text
            .chars()
            .any(|c| ('\u{2800}'..='\u{28FF}').contains(&c)),
        "expected Unicode Braille characters in settled canvas"
    );
    assert!(
        !plain_text.contains('╭') && !plain_text.contains('╰'),
        "borderless Braille canvas must not draw an outer box border"
    );

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
    let canonical_lf = canonical.replace("\r\n", "\n");
    assert!(canonical_lf.starts_with("---\nname: hyphae-setup\n"));
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
        let mut cmd = isolated_cmd(&home);
        cmd.env("PATH", &isolated_path)
            .args([
                "onboard",
                "--assist",
                assist_arg,
                "--home",
                home.to_str().unwrap(),
                "--no-anim",
            ])
            .stdin(Stdio::null());
        let out = output_retrying_busy(&mut cmd);

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
    let mut assist_cmd = isolated_cmd(&home);
    assist_cmd
        .env("PATH", &isolated_path)
        .args([
            "onboard",
            "--assist",
            "claude",
            "--home",
            home.to_str().unwrap(),
            "--no-anim",
        ])
        .stdin(Stdio::null());
    let assist_out = output_retrying_busy(&mut assist_cmd);
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

#[cfg(unix)]
#[test]
fn assist_herdr_template_installs_skill_and_invokes_hc_run() {
    use std::os::unix::fs::PermissionsExt;

    let canonical = fs::read_to_string(repo_setup_skill_path()).expect("read repo SKILL.md");

    // 1. `--assist herdr:claude-gateway --json`: invokes `hc run --bg --outlive-parent --label app=hyphae --json`
    //    and returns parsed terminal address `t4h` + `next: ["hc attach t4h"]` without hanging.
    {
        let tmp = TempDir::new().expect("tempdir");
        let home = tmp.path().join("home");
        let bin_dir = tmp.path().join("bin");
        let capture = tmp.path().join("hc_capture.txt");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&bin_dir).unwrap();

        let primary_skill = home.join(".claude/skills/hyphae-setup/SKILL.md");
        let hc_script = bin_dir.join("hc");
        let script = format!(
            "#!/bin/sh\n\
             set -eu\n\
             if [ \"$1\" = 'templates' ]; then\n\
               printf '%s\\n' '{{\"templates\":[{{\"name\":\"claude-gateway\",\"description\":\"Claude (Gateway)\",\"command\":\"claude-gateway\"}},{{\"name\":\"codex-gateway\",\"description\":\"Codex (Gateway)\",\"command\":\"codex-gateway --no-daemon\"}}]}}'\n\
               exit 0\n\
             fi\n\
             if [ -f '{skill}' ]; then\n\
               echo 'SKILL_PREEXISTED=1' > '{cap}'\n\
             else\n\
               echo 'SKILL_PREEXISTED=0' > '{cap}'\n\
             fi\n\
             echo \"ARGC=$#\" >> '{cap}'\n\
             for arg in \"$@\"; do\n\
               printf 'ARG=%s\\n' \"$arg\" >> '{cap}'\n\
             done\n\
             printf '%s\\n' '[hc] launching background terminal'\n\
             printf '%s\\n' '{{\"address\":\"t4h\",\"template\":\"claude-gateway\"}}'\n\
             exit 0\n",
            skill = primary_skill.display(),
            cap = capture.display(),
        );
        fs::write(&hc_script, script).expect("write fake hc");
        fs::set_permissions(&hc_script, fs::Permissions::from_mode(0o755)).expect("chmod hc");

        let isolated_path = format!("{}:/usr/bin:/bin", bin_dir.display());
        let mut cmd = isolated_cmd(&home);
        cmd.env("PATH", &isolated_path)
            .args([
                "onboard",
                "--assist",
                "herdr:claude-gateway",
                "--home",
                home.to_str().unwrap(),
                "--json",
            ])
            .stdin(Stdio::null());
        let out = output_retrying_busy(&mut cmd);

        assert_eq!(
            out.status.code(),
            Some(0),
            "stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            fs::read_to_string(&primary_skill).expect("primary skill installed"),
            canonical
        );

        let payload = parse_json_stdout(&out);
        assert_eq!(payload["ok"], true);
        assert_eq!(payload["command"], "onboard");
        assert_eq!(payload["data"]["mode"], "herdr_launch");
        assert_eq!(payload["data"]["template"], "claude-gateway");
        assert_eq!(payload["data"]["terminal"], "t4h");
        assert_eq!(payload["next"], serde_json::json!(["hc attach t4h"]));

        let captured = fs::read_to_string(&capture).expect("read fake hc capture");
        let lines: Vec<&str> = captured.lines().collect();
        assert_eq!(
            lines.first().copied(),
            Some("SKILL_PREEXISTED=1"),
            "hyphae-setup/SKILL.md must be installed BEFORE `hc run` executes"
        );
        assert_eq!(lines.get(1).copied(), Some("ARGC=8"), "captured:\n{captured}");
        assert_eq!(lines.get(2).copied(), Some("ARG=run"), "captured:\n{captured}");
        assert_eq!(lines.get(3).copied(), Some("ARG=--bg"), "captured:\n{captured}");
        assert_eq!(
            lines.get(4).copied(),
            Some("ARG=--outlive-parent"),
            "captured:\n{captured}"
        );
        assert_eq!(
            lines.get(5).copied(),
            Some("ARG=--label"),
            "captured:\n{captured}"
        );
        assert_eq!(
            lines.get(6).copied(),
            Some("ARG=app=hyphae"),
            "captured:\n{captured}"
        );
        assert_eq!(
            lines.get(7).copied(),
            Some("ARG=--json"),
            "captured:\n{captured}"
        );
        assert_eq!(
            lines.get(8).copied(),
            Some("ARG=claude-gateway"),
            "captured:\n{captured}"
        );
        let prompt_line = lines.get(9).copied().unwrap_or("");
        assert!(
            prompt_line.contains("hyphae-setup")
                && prompt_line.contains(&primary_skill.display().to_string()),
            "prompt missing skill reference: {prompt_line}"
        );
    }

    // 2. Plain non-TTY `--assist herdr:codex-gateway`: installs primary + `.agents` skill and
    //    prints attach instructions cleanly without hanging.
    {
        let tmp = TempDir::new().expect("tempdir");
        let home = tmp.path().join("home");
        let bin_dir = tmp.path().join("bin");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&bin_dir).unwrap();

        let hc_script = bin_dir.join("hc");
        let script = "#!/bin/sh\n\
             set -eu\n\
             if [ \"$1\" = 'templates' ]; then\n\
               printf '%s\\n' '{\"templates\":[{\"name\":\"codex-gateway\",\"description\":\"Codex (Gateway)\",\"command\":\"codex-gateway --no-daemon\"}]}'\n\
               exit 0\n\
             fi\n\
             printf '%s\\n' '{\"address\":\"t9m\"}'\n\
             exit 0\n";
        fs::write(&hc_script, script).expect("write fake hc");
        fs::set_permissions(&hc_script, fs::Permissions::from_mode(0o755)).expect("chmod hc");

        let isolated_path = format!("{}:/usr/bin:/bin", bin_dir.display());
        let mut cmd = isolated_cmd(&home);
        cmd.env("PATH", &isolated_path)
            .args([
                "onboard",
                "--assist",
                "herdr:codex-gateway",
                "--home",
                home.to_str().unwrap(),
                "--no-anim",
            ])
            .stdin(Stdio::null());
        let out = output_retrying_busy(&mut cmd);
        assert_eq!(
            out.status.code(),
            Some(0),
            "stderr={}",
            String::from_utf8_lossy(&out.stderr)
        );
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(stdout.contains("t9m"), "stdout={stdout}");
        assert!(stdout.contains("hc attach t9m"), "stdout={stdout}");

        for rel in [
            ".codex/skills/hyphae-setup/SKILL.md",
            ".agents/skills/hyphae-setup/SKILL.md",
        ] {
            let p = home.join(rel);
            assert!(p.is_file(), "missing {}", p.display());
            assert_eq!(fs::read_to_string(&p).unwrap(), canonical);
        }
    }

    // 3. Failing `hc run` emits structured `HERDR_LAUNCH_FAILED` including stderr snippet.
    {
        let tmp = TempDir::new().expect("tempdir");
        let home = tmp.path().join("home");
        let bin_dir = tmp.path().join("bin");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&bin_dir).unwrap();

        let hc_script = bin_dir.join("hc");
        let script = "#!/bin/sh\n\
             if [ \"$1\" = 'templates' ]; then\n\
               printf '%s\\n' '{\"templates\":[{\"name\":\"claude-gateway\",\"description\":\"Claude (Gateway)\",\"command\":\"claude-gateway\"}]}'\n\
               exit 0\n\
             fi\n\
             echo 'herdr daemon offline' >&2\n\
             exit 5\n";
        fs::write(&hc_script, script).expect("write fake hc fail");
        fs::set_permissions(&hc_script, fs::Permissions::from_mode(0o755)).expect("chmod hc");

        let isolated_path = format!("{}:/usr/bin:/bin", bin_dir.display());
        let mut cmd = isolated_cmd(&home);
        cmd.env("PATH", &isolated_path)
            .args([
                "onboard",
                "--assist",
                "herdr:claude-gateway",
                "--home",
                home.to_str().unwrap(),
                "--json",
            ])
            .stdin(Stdio::null());
        let out = output_retrying_busy(&mut cmd);
        assert_eq!(out.status.code(), Some(1));
        let err_json = parse_json_stdout(&out);
        assert_eq!(err_json["ok"], false);
        assert_eq!(err_json["error"]["code"], "HERDR_LAUNCH_FAILED");
        assert!(
            err_json["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("herdr daemon offline")),
            "expected stderr snippet in error: {err_json}"
        );
    }
}

#[test]
fn assist_openclaw_and_t3_install_skill_and_emit_structured_manual_guide() {
    let canonical = fs::read_to_string(repo_setup_skill_path()).expect("read repo SKILL.md");

    // 1. OpenClaw `--json` manual guide flow.
    let tmp_oc = TempDir::new().expect("tempdir");
    let home_oc = tmp_oc.path();
    let oc_out = isolated_cmd(home_oc)
        .args([
            "onboard",
            "--assist",
            "openclaw",
            "--home",
            home_oc.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run onboard --assist openclaw --json");
    assert_eq!(
        oc_out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&oc_out.stderr)
    );
    let oc_json = parse_json_stdout(&oc_out);
    assert_eq!(oc_json["ok"], true);
    assert_eq!(oc_json["command"], "onboard");
    assert_eq!(oc_json["data"]["mode"], "manual_guide");
    assert_eq!(oc_json["data"]["harness"], "openclaw");
    assert_eq!(oc_json["data"]["displayName"], "OpenClaw");
    assert!(
        oc_json["data"]["prompt"]
            .as_str()
            .is_some_and(|p| p.contains("hyphae-setup")),
        "missing prompt in JSON: {oc_json}"
    );
    let oc_skill = home_oc.join(".openclaw/skills/hyphae-setup/SKILL.md");
    assert!(oc_skill.is_file(), "expected OpenClaw skill at {}", oc_skill.display());
    assert_eq!(fs::read_to_string(&oc_skill).unwrap(), canonical);

    // 1b. OpenClaw plain non-TTY flow also exits 0 and prints the 2-step guide.
    let oc_plain = isolated_cmd(home_oc)
        .args([
            "onboard",
            "--assist",
            "openclaw",
            "--home",
            home_oc.to_str().unwrap(),
            "--no-anim",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run onboard --assist openclaw plain");
    assert_eq!(oc_plain.status.code(), Some(0));
    let oc_stdout = String::from_utf8_lossy(&oc_plain.stdout);
    assert!(oc_stdout.contains("Open OpenClaw"), "stdout={oc_stdout}");
    assert!(oc_stdout.contains("hyphae-setup"), "stdout={oc_stdout}");

    // 2. T3 Code `--json` manual guide flow (installs into .agents, .claude, and .codex!).
    let tmp_t3 = TempDir::new().expect("tempdir");
    let home_t3 = tmp_t3.path();
    let t3_out = isolated_cmd(home_t3)
        .args([
            "onboard",
            "--assist",
            "t3",
            "--home",
            home_t3.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run onboard --assist t3 --json");
    assert_eq!(
        t3_out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&t3_out.stderr)
    );
    let t3_json = parse_json_stdout(&t3_out);
    assert_eq!(t3_json["ok"], true);
    assert_eq!(t3_json["command"], "onboard");
    assert_eq!(t3_json["data"]["mode"], "manual_guide");
    assert_eq!(t3_json["data"]["harness"], "t3");
    assert_eq!(t3_json["data"]["displayName"], "T3 Code");
    assert!(
        t3_json["data"]["prompt"]
            .as_str()
            .is_some_and(|p| p.contains("hyphae-setup")),
        "missing prompt in JSON: {t3_json}"
    );

    for rel in [
        ".agents/skills/hyphae-setup/SKILL.md",
        ".claude/skills/hyphae-setup/SKILL.md",
        ".codex/skills/hyphae-setup/SKILL.md",
    ] {
        let path = home_t3.join(rel);
        assert!(path.is_file(), "expected T3 skill at {}", path.display());
        assert_eq!(fs::read_to_string(&path).unwrap(), canonical);
    }
}

#[test]
fn assist_claude_desktop_codex_desktop_and_cursor_ide_emit_manual_guides() {
    let canonical = fs::read_to_string(repo_setup_skill_path()).expect("read repo SKILL.md");

    // 1. Claude Desktop (`--assist claude-desktop --json`): installs ~/.claude/skills + emits MCP snippet.
    let tmp_cd = TempDir::new().expect("tempdir");
    let home_cd = tmp_cd.path();
    let cd_out = isolated_cmd(home_cd)
        .args([
            "onboard",
            "--assist",
            "claude-desktop",
            "--home",
            home_cd.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run onboard --assist claude-desktop --json");
    assert_eq!(
        cd_out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&cd_out.stderr)
    );
    let cd_json = parse_json_stdout(&cd_out);
    assert_eq!(cd_json["ok"], true);
    assert_eq!(cd_json["data"]["mode"], "manual_guide");
    assert_eq!(cd_json["data"]["harness"], "claude-desktop");
    assert_eq!(cd_json["data"]["displayName"], "Claude Desktop");
    assert_eq!(
        cd_json["data"]["prompt"],
        "Set up Hyphae on this machine using the hyphae-setup skill"
    );
    assert!(
        cd_json["data"]["mcpSnippet"]
            .as_str()
            .is_some_and(|s| s.contains("mcpServers") && s.contains("hyphae")),
        "expected claude_desktop_config.json MCP snippet: {cd_json}"
    );
    let cd_skill = home_cd.join(".claude/skills/hyphae-setup/SKILL.md");
    assert!(cd_skill.is_file());
    assert_eq!(fs::read_to_string(&cd_skill).unwrap(), canonical);

    // 2. Codex Desktop (`--assist codex-desktop --json`): installs ~/.codex/skills + ~/.agents/skills.
    let tmp_cx = TempDir::new().expect("tempdir");
    let home_cx = tmp_cx.path();
    let cx_out = isolated_cmd(home_cx)
        .args([
            "onboard",
            "--assist",
            "codex-desktop",
            "--home",
            home_cx.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run onboard --assist codex-desktop --json");
    assert_eq!(cx_out.status.code(), Some(0));
    let cx_json = parse_json_stdout(&cx_out);
    assert_eq!(cx_json["ok"], true);
    assert_eq!(cx_json["data"]["mode"], "manual_guide");
    assert_eq!(cx_json["data"]["harness"], "codex-desktop");
    assert_eq!(cx_json["data"]["displayName"], "Codex Desktop");
    assert_eq!(
        cx_json["data"]["prompt"],
        "Set up Hyphae on this machine using the hyphae-setup skill"
    );
    for rel in [
        ".codex/skills/hyphae-setup/SKILL.md",
        ".agents/skills/hyphae-setup/SKILL.md",
    ] {
        let p = home_cx.join(rel);
        assert!(p.is_file(), "missing {}", p.display());
        assert_eq!(fs::read_to_string(&p).unwrap(), canonical);
    }

    // 3. Cursor IDE fallback when `cursor-agent` CLI is NOT on PATH (`--assist cursor --json`).
    let tmp_cu = TempDir::new().expect("tempdir");
    let home_cu = tmp_cu.path();
    let cu_out = isolated_cmd(home_cu)
        .env("PATH", "")
        .args([
            "onboard",
            "--assist",
            "cursor",
            "--home",
            home_cu.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run onboard --assist cursor without cursor-agent on PATH");
    assert_eq!(cu_out.status.code(), Some(0));
    let cu_json = parse_json_stdout(&cu_out);
    assert_eq!(cu_json["ok"], true);
    assert_eq!(cu_json["data"]["mode"], "manual_guide");
    assert_eq!(cu_json["data"]["harness"], "cursor");
    assert_eq!(cu_json["data"]["displayName"], "Cursor (IDE)");
    assert_eq!(
        cu_json["data"]["prompt"],
        "Set up Hyphae on this machine using the hyphae-setup skill"
    );
    let cu_skill = home_cu.join(".cursor/skills/hyphae-setup/SKILL.md");
    assert!(cu_skill.is_file());
    assert_eq!(fs::read_to_string(&cu_skill).unwrap(), canonical);
    assert!(
        cu_json["data"]["deeplink"]
            .as_str()
            .is_some_and(|u| u.starts_with("cursor://")),
        "expected cursor deeplink: {cu_json}"
    );

    // 4. OpenCode Desktop (`--assist opencode-desktop --json`): installs both `.config/opencode`
    //    and `.agents` skill paths and emits an `opencode://new-session` deep link.
    let tmp_ocd = TempDir::new().expect("tempdir");
    let home_ocd = tmp_ocd.path();
    let ocd_out = isolated_cmd(home_ocd)
        .args([
            "onboard",
            "--assist",
            "opencode-desktop",
            "--home",
            home_ocd.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run onboard --assist opencode-desktop --json");
    assert_eq!(
        ocd_out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&ocd_out.stderr)
    );
    let ocd_json = parse_json_stdout(&ocd_out);
    assert_eq!(ocd_json["ok"], true);
    assert_eq!(ocd_json["data"]["mode"], "manual_guide");
    assert_eq!(ocd_json["data"]["harness"], "opencode-desktop");
    assert_eq!(ocd_json["data"]["displayName"], "OpenCode Desktop");
    assert!(
        ocd_json["data"]["deeplink"]
            .as_str()
            .is_some_and(|u| u.starts_with("opencode://new-session?")),
        "expected opencode deeplink: {ocd_json}"
    );
    for rel in [
        ".config/opencode/skills/hyphae-setup/SKILL.md",
        ".agents/skills/hyphae-setup/SKILL.md",
    ] {
        let p = home_ocd.join(rel);
        assert!(p.is_file(), "missing {}", p.display());
        assert_eq!(fs::read_to_string(&p).unwrap(), canonical);
    }

    // 5. Desktop MCP confirm-before-write E2E check:
    //    Non-TTY `--assist claude-desktop --json` NEVER silently writes `claude_desktop_config.json`,
    //    reports `mcpAlreadyConfigured: false` before config exists, and `true` once configured
    //    (and same for Codex Desktop `~/.codex/config.toml`).
    assert_eq!(cd_json["data"]["mcpAlreadyConfigured"], false);
    assert!(
        cd_json["data"]["deeplink"]
            .as_str()
            .is_some_and(|u| u.starts_with("claude://claude.ai/new?q=")),
        "expected claude desktop deeplink: {cd_json}"
    );
    let cd_cfg_path = PathBuf::from(cd_json["data"]["mcpConfigPath"].as_str().unwrap());
    assert!(
        !cd_cfg_path.exists(),
        "non-TTY --assist claude-desktop must never silently write config without confirmation"
    );
    fs::create_dir_all(cd_cfg_path.parent().unwrap()).unwrap();
    fs::write(
        &cd_cfg_path,
        r#"{"mcpServers":{"hyphae":{"command":"/usr/local/bin/hyp","args":["mcp"]}}}"#,
    )
    .unwrap();
    let cd_out2 = isolated_cmd(home_cd)
        .args([
            "onboard",
            "--assist",
            "claude-desktop",
            "--home",
            home_cd.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("re-run assist claude-desktop --json");
    assert_eq!(cd_out2.status.code(), Some(0));
    let cd_json2 = parse_json_stdout(&cd_out2);
    assert_eq!(cd_json2["data"]["mcpAlreadyConfigured"], true);

    assert_eq!(cx_json["data"]["mcpAlreadyConfigured"], false);
    assert!(
        cx_json["data"]["deeplink"]
            .as_str()
            .is_some_and(|u| u.starts_with("codex://threads/new?prompt=")),
        "expected codex desktop deeplink: {cx_json}"
    );
    let cx_cfg_path = home_cx.join(".codex/config.toml");
    assert!(!cx_cfg_path.exists());
    fs::create_dir_all(cx_cfg_path.parent().unwrap()).unwrap();
    fs::write(
        &cx_cfg_path,
        "model = \"gpt-5\"\n\n[mcp_servers.hyphae]\ncommand = \"hyp\"\nargs = [\"mcp\"]\n",
    )
    .unwrap();
    let cx_out2 = isolated_cmd(home_cx)
        .args([
            "onboard",
            "--assist",
            "codex-desktop",
            "--home",
            home_cx.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("re-run assist codex-desktop --json");
    assert_eq!(cx_out2.status.code(), Some(0));
    let cx_json2 = parse_json_stdout(&cx_out2);
    assert_eq!(cx_json2["data"]["mcpAlreadyConfigured"], true);
}
