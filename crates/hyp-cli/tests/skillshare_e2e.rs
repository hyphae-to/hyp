//! Run explicitly against a real Skillshare CLI; no user config or network sources.
//! cargo test -p hyp-cli --test skillshare_e2e -- --ignored --test-threads=1
#![cfg(unix)]
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};
use tempfile::TempDir;

fn manager() -> PathBuf {
    let output = Command::new("which")
        .arg("skillshare")
        .output()
        .expect("which");
    assert!(
        output.status.success(),
        "install Skillshare v0.33+ before this contract test"
    );
    PathBuf::from(String::from_utf8(output.stdout).unwrap().trim())
}

struct Fixture {
    root: TempDir,
    home: PathBuf,
    tools: PathBuf,
}
impl Fixture {
    fn new(with_manager: bool) -> Self {
        let root = TempDir::new().unwrap();
        let home = root.path().join("home");
        let tools = root.path().join("tools");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&tools).unwrap();
        if with_manager {
            std::os::unix::fs::symlink(manager(), tools.join("skillshare")).unwrap();
        }
        Self { root, home, tools }
    }
    fn run(&self, command: &str, harness: &str, extra: &[&str]) -> (bool, Value) {
        let output = Command::new(env!("CARGO_BIN_EXE_hyp"))
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", &self.tools)
            .env("HYPHAE_SECRET_BACKEND", "file")
            .env("TMPDIR", self.root.path())
            .args([command, "--harness", harness, "--home"])
            .arg(&self.home)
            .args(extra)
            .arg("--json")
            .output()
            .unwrap();
        let value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
            panic!("invalid JSON: {}", String::from_utf8_lossy(&output.stdout))
        });
        (output.status.success(), value)
    }
    fn json(&self, path: &str) -> Value {
        serde_json::from_slice(&fs::read(self.home.join(path)).unwrap()).unwrap()
    }
    fn write(&self, path: &str, contents: &str) {
        let path = self.home.join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
}

#[test]
#[ignore = "requires real Skillshare v0.33+ on PATH"]
fn fresh_repeat_setup_and_setup_skill_are_skillshare_owned() {
    let f = Fixture::new(true);
    f.write(
        ".claude.json",
        &json!({"theme":"preserved", "mcpServers":{"other":{"command":"other"}}}).to_string(),
    );
    for _ in 0..2 {
        let (ok, result) = f.run(
            "setup",
            "claude,codex,cursor,opencode,gemini",
            &["--no-commands"],
        );
        assert!(ok, "{result:#}");
        assert_eq!(result["data"]["configuredCount"], 5);
        let claude = f.json(".claude.json");
        assert_eq!(claude["theme"], "preserved");
        assert_eq!(claude["mcpServers"].as_object().unwrap().len(), 2);
        assert!(claude["mcpServers"]["hyphae"].is_object());
        let codex = fs::read_to_string(f.home.join(".codex/config.toml")).unwrap();
        assert!(codex.contains("mcp_servers.hyphae"));
        assert!(!codex.contains("hyphae-codex"));
        assert!(!codex.contains("--backend"));
        assert_eq!(
            f.json(".cursor/mcp.json")["mcpServers"]
                .as_object()
                .unwrap()
                .len(),
            1
        );
    }
    let (ok, result) = f.run("onboard", "claude", &["--install-skill"]);
    assert!(ok, "{result:#}");
    let skills = f.home.join(".claude/skills");
    let entries: Vec<_> = fs::read_dir(skills)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    for name in ["hyp-mesh", "hyp-setup"] {
        let selected: Vec<_> = entries
            .iter()
            .filter(|p| p.file_name().unwrap().to_string_lossy().ends_with(name))
            .collect();
        assert_eq!(selected.len(), 1);
        assert!(
            fs::symlink_metadata(selected[0])
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(
            fs::canonicalize(selected[0])
                .unwrap()
                .starts_with(fs::canonicalize(f.home.join(".config/skillshare/skills")).unwrap())
        );
    }
    for entry in result["data"]["installed"].as_array().into_iter().flatten() {
        if let Some(path) = entry["path"].as_str() {
            assert!(Path::new(path).is_file());
        }
    }
}

#[test]
#[ignore = "requires real Skillshare v0.33+ on PATH"]
fn migrate_direct_codex_preserves_server_overrides_and_unrelated_config() {
    let f = Fixture::new(false);
    assert!(f.run("setup", "codex", &["--no-commands"]).0);
    let config = f.home.join(".codex/config.toml");
    let original = fs::read_to_string(&config).unwrap();
    fs::write(&config, format!("model = 'preserved'\n{original}\nstartup_timeout_sec = 42\ndefault_tools_approval_mode = 'approve'\nenabled_tools = ['hyp_send']\n\n[mcp_servers.other]\ncommand = 'other'\n")).unwrap();
    std::os::unix::fs::symlink(manager(), f.tools.join("skillshare")).unwrap();
    for _ in 0..2 {
        let (ok, result) = f.run("setup", "codex", &["--no-commands"]);
        assert!(ok, "{result:#}");
        let migrated = fs::read_to_string(&config).unwrap();
        for expected in [
            "model = 'preserved'",
            "mcp_servers.other",
            "startup_timeout_sec",
            "42",
            "default_tools_approval_mode",
            "enabled_tools",
            "hyp_send",
            "mcp_servers.hyphae",
        ] {
            assert!(
                migrated.contains(expected),
                "missing {expected}: {migrated}"
            );
        }
        assert!(!migrated.contains("hyphae-codex"));
        assert!(!f.home.join(".agents/skills/hyp-mesh/SKILL.md").exists());
    }
}

#[test]
#[ignore = "requires real Skillshare v0.33+ on PATH"]
fn customized_skills_and_external_tool_references_are_preserved() {
    let f = Fixture::new(true);
    let source = "[mcp_servers.hyphae]\ncommand = 'hyp'\nargs = ['mcp','--backend','codex']\n\n[custom]\ntool = 'mcp__hyphae__hyp_send'\n";
    f.write(".codex/config.toml", source);
    let (ok, result) = f.run("setup", "codex", &["--no-commands"]);
    assert!(ok, "{result:#}");
    assert!(
        fs::read_to_string(f.home.join(".codex/config.toml"))
            .unwrap()
            .contains("mcp__hyphae__hyp_send")
    );
    f.write(
        ".cursor/skills/hyp-mesh/SKILL.md",
        "---\nname: hyp-mesh\n---\n<!-- hyphae:unmanaged -->\nKeep me\n",
    );
    let (ok, result) = f.run("setup", "cursor", &["--no-commands"]);
    assert!(!ok, "{result:#}");
    let entries: Vec<_> = fs::read_dir(f.home.join(".cursor/skills"))
        .unwrap()
        .collect();
    assert_eq!(entries.len(), 1);
}

#[test]
fn unavailable_manager_retains_direct_setup_and_dry_run_writes_nothing() {
    let f = Fixture::new(false);
    assert!(f.run("setup", "codex", &["--dry-run", "--no-commands"]).0);
    assert_eq!(fs::read_dir(&f.home).unwrap().count(), 0);
    assert!(f.run("setup", "codex", &["--no-commands"]).0);
    assert!(f.home.join(".agents/skills/hyp-mesh/SKILL.md").is_file());
    assert!(
        fs::read_to_string(f.home.join(".codex/config.toml"))
            .unwrap()
            .contains("[mcp_servers.hyphae]")
    );
    assert!(!f.home.join(".config/skillshare").exists());
}

#[test]
#[ignore = "requires real Skillshare v0.33+ on PATH"]
fn existing_standard_naming_and_filters_are_respected() {
    let f = Fixture::new(false);
    assert!(f.run("setup", "claude", &["--no-commands"]).0);
    let source = f.home.join(".config/skillshare/skills");
    fs::create_dir_all(&source).unwrap();
    f.write(".config/skillshare/config.yaml", &json!({
        "source": source, "mode": "merge", "target_naming": "standard",
        "targets": {"claude":{"path":f.home.join(".claude/skills"), "include":["hyphae-*__hyp-mesh"]}}
    }).to_string());
    std::os::unix::fs::symlink(manager(), f.tools.join("skillshare")).unwrap();
    for _ in 0..2 {
        let (ok, result) = f.run("setup", "claude", &["--no-commands"]);
        assert!(ok, "{result:#}");
        assert!(
            fs::symlink_metadata(f.home.join(".claude/skills/hyp-mesh"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
    }
    let cfg = fs::read_to_string(f.home.join(".config/skillshare/config.yaml")).unwrap();
    assert!(cfg.contains("standard"));
    assert!(cfg.contains("hyphae-*__hyp-mesh"));
    let (ok, result) = f.run("onboard", "claude", &["--install-skill"]);
    assert!(!ok, "a user include filter excludes hyp-setup: {result:#}");
    assert!(!f.home.join(".claude/skills/hyp-setup/SKILL.md").exists());
}

#[test]
fn failing_manager_never_falls_back_to_direct_registration() {
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new(false);
    f.write(".claude.json", "{\"keep\":true}\n");
    let executable = f.tools.join("skillshare");
    fs::write(&executable, "#!/bin/sh\nexit 17\n").unwrap();
    fs::set_permissions(executable, fs::Permissions::from_mode(0o755)).unwrap();
    let (ok, result) = f.run("setup", "claude", &["--no-commands"]);
    assert!(!ok, "{result:#}");
    assert_eq!(f.json(".claude.json"), json!({"keep":true}));
    assert!(!f.home.join(".claude/settings.json").exists());
    assert!(!f.home.join(".claude/skills/hyp-mesh/SKILL.md").exists());
}

#[test]
#[ignore = "requires real Skillshare v0.33+ on PATH"]
fn skillshare_exposed_opt_out_survives_repeat_setup() {
    let f = Fixture::new(true);
    assert!(f.run("setup", "cursor", &["--no-commands"]).0);
    let skill = fs::read_dir(f.home.join(".cursor/skills"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .ends_with("hyp-mesh")
        })
        .unwrap()
        .join("SKILL.md");
    let original = fs::read_to_string(&skill).unwrap();
    let edited = format!("{original}\n<!-- hyphae:unmanaged -->\nKeep this customization\n");
    fs::write(&skill, &edited).unwrap();
    let (ok, result) = f.run("setup", "cursor", &["--no-commands"]);
    assert!(!ok, "{result:#}");
    assert_eq!(fs::read_to_string(&skill).unwrap(), edited);
}

#[test]
#[ignore = "requires real Skillshare v0.33+ on PATH"]
fn existing_direct_clients_are_adopted_without_duplicate_servers() {
    let f = Fixture::new(false);
    assert!(
        f.run("setup", "claude,cursor,opencode,gemini", &["--no-commands"])
            .0
    );
    std::os::unix::fs::symlink(manager(), f.tools.join("skillshare")).unwrap();
    for _ in 0..2 {
        let (ok, result) = f.run("setup", "claude,cursor,opencode,gemini", &["--no-commands"]);
        assert!(ok, "{result:#}");
        assert_eq!(result["data"]["configuredCount"], 4, "{result:#}");
        assert_eq!(
            f.json(".claude.json")["mcpServers"]
                .as_object()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            f.json(".cursor/mcp.json")["mcpServers"]
                .as_object()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            f.json(".config/opencode/opencode.json")["mcp"]
                .as_object()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            f.json(".gemini/settings.json")["mcpServers"]
                .as_object()
                .unwrap()
                .len(),
            1
        );
    }
}

#[test]
#[ignore = "requires real Skillshare v0.33+ on PATH"]
fn claude_channel_opt_in_is_preserved_and_incompatible_shared_launch_is_rejected() {
    let f = Fixture::new(true);
    f.write(
        ".claude.json",
        &json!({"mcpServers":{"hyphae":{"command":"hyp","args":["mcp","--claude-channel"]}}})
            .to_string(),
    );
    for _ in 0..2 {
        let (ok, result) = f.run("setup", "claude", &["--no-commands", "--no-skills"]);
        assert!(ok, "{result:#}");
        assert_eq!(
            f.json(".claude.json")["mcpServers"]["hyphae"]["args"],
            json!(["mcp", "--claude-channel"])
        );
    }
    let (ok, result) = f.run("setup", "cursor", &["--no-commands", "--no-skills"]);
    assert!(!ok, "{result:#}");
    assert!(!f.home.join(".cursor/mcp.json").exists());
    assert_eq!(
        f.json(".claude.json")["mcpServers"]["hyphae"]["args"],
        json!(["mcp", "--claude-channel"])
    );
}

#[test]
#[ignore = "requires real Skillshare v0.33+ on PATH"]
fn matching_existing_skillshare_registration_is_reused_without_local_receipt() {
    let f = Fixture::new(true);
    assert!(f.run("setup", "cursor", &["--no-commands"]).0);
    fs::remove_file(f.home.join(".config/hyphae/skillshare/mcp/hyphae.json")).unwrap();
    let (ok, result) = f.run("setup", "cursor", &["--no-commands"]);
    assert!(ok, "{result:#}");
    assert_eq!(
        f.json(".cursor/mcp.json")["mcpServers"]
            .as_object()
            .unwrap()
            .len(),
        1
    );
}

#[test]
#[ignore = "requires real Skillshare v0.33+ on PATH"]
fn missing_receipt_cannot_change_other_clients_launch_arguments() {
    let f = Fixture::new(true);
    assert!(
        f.run("setup", "claude,cursor", &["--no-commands", "--no-skills"])
            .0
    );
    fs::remove_file(f.home.join(".config/hyphae/skillshare/mcp/hyphae.json")).unwrap();
    let claude = f.json(".claude.json");
    let cursor = f.json(".cursor/mcp.json");
    let (ok, result) = f.run(
        "setup",
        "claude",
        &[
            "--no-commands",
            "--no-skills",
            "--socket",
            "/tmp/proposed-other.sock",
        ],
    );
    assert!(!ok, "{result:#}");
    assert_eq!(f.json(".claude.json"), claude);
    assert_eq!(f.json(".cursor/mcp.json"), cursor);
}
