//! End-to-end tests for first-class `CLAUDE_CONFIG_DIR` / `--claude-config-dir` support,
//! symlink-preserving atomic writes, per-profile Claude `statusLine` chain backups, and
//! custom-header-aware Herdr symlink diagnostics (`--patch-layout` symlink safety).
//!
//! Strict isolation invariant: every test uses ephemeral `tempfile::TempDir`, isolated
//! `--home` / `--state-dir`, `HYPHAE_SECRET_BACKEND=file`, and scrubbed `CLAUDE_CONFIG_DIR` —
//! zero live user config or OS Keychain mutations!

mod common;

use common::{isolated_cmd, parse_json_stdout};
use serde_json::{Value, json};
use std::fs;
use std::path::Path;

fn clean_cmd(home: &Path) -> std::process::Command {
    let mut cmd = isolated_cmd(home);
    cmd.env_remove("CLAUDE_CONFIG_DIR")
        .env_remove("HERDR_APP_HOME");
    cmd
}

#[cfg(unix)]
#[test]
fn claude_gateway_symlinked_profile_cli_override_env_and_hermetic_isolation() {
    use std::os::unix::fs::symlink;

    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let state_dir = tmp.path().join("state");
    let gateway = home.join("profiles").join("claude-gateway");
    let outside_profile = tmp.path().join("ambient-outside-claude-profile");

    fs::create_dir_all(home.join(".claude").join("skills")).unwrap();
    fs::create_dir_all(&gateway).unwrap();

    let original_bar = json!({
        "type": "command",
        "command": "my-starship-bar --git",
        "padding": 1
    });
    fs::write(
        home.join(".claude").join("settings.json"),
        serde_json::to_string_pretty(&json!({
            "theme": "dark",
            "statusLine": original_bar
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        home.join(".claude.json"),
        serde_json::to_string_pretty(&json!({
            "mcpServers": {
                "existing-home": { "command": "npx", "args": ["home-server"] }
            }
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        gateway.join(".claude.json"),
        serde_json::to_string_pretty(&json!({
            "mcpServers": {
                "gateway-mcp": { "command": "npx", "args": ["gateway-server"] }
            }
        }))
        .unwrap(),
    )
    .unwrap();

    // Real-world Herdr `claude-gateway` symlinks:
    //   claude-gateway/settings.json -> ~/.claude/settings.json
    //   claude-gateway/skills        -> ~/.claude/skills
    //   claude-gateway/commands/     is separate (NOT symlinked)
    let gw_settings_link = gateway.join("settings.json");
    let gw_skills_link = gateway.join("skills");
    symlink(
        home.join(".claude").join("settings.json"),
        &gw_settings_link,
    )
    .unwrap();
    symlink(home.join(".claude").join("skills"), &gw_skills_link).unwrap();

    let fake_bin = "/opt/hyphae/bin/hyp";

    // ------------------------------------------------------------------------
    // Phase A: Explicit `--claude-config-dir <gateway>`
    // ------------------------------------------------------------------------
    let out_a = clean_cmd(&home)
        .args([
            "setup",
            "--harness",
            "claude",
            "--statusline",
            "--bin",
            fake_bin,
            "--home",
            home.to_str().unwrap(),
            "--claude-config-dir",
            gateway.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(out_a.status.code(), Some(0));
    let json_a = parse_json_stdout(&out_a);
    assert_eq!(json_a["ok"], true);

    // 1. Gateway `.claude.json` gets `mcpServers.hyphae` while preserving `gateway-mcp`.
    let gw_mcp: Value =
        serde_json::from_str(&fs::read_to_string(gateway.join(".claude.json")).unwrap()).unwrap();
    assert_eq!(gw_mcp["mcpServers"]["gateway-mcp"]["command"], "npx");
    assert_eq!(gw_mcp["mcpServers"]["hyphae"]["command"], fake_bin);

    // 2. `gateway/settings.json` MUST remain a symlink and its target gets hooks + chained statusLine.
    assert!(
        fs::symlink_metadata(&gw_settings_link)
            .unwrap()
            .file_type()
            .is_symlink(),
        "gateway/settings.json symlink must NEVER be clobbered by atomic write"
    );
    let real_settings: Value = serde_json::from_str(
        &fs::read_to_string(home.join(".claude").join("settings.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(real_settings["theme"], "dark");
    assert!(real_settings["hooks"]["SessionStart"].is_array());
    assert!(real_settings["hooks"]["PreToolUse"].is_array());
    assert!(real_settings["hooks"]["PostToolUse"].is_array());
    assert!(real_settings["hooks"]["Stop"].is_array());
    let sl_cmd = real_settings["statusLine"]["command"].as_str().unwrap();
    assert!(sl_cmd.contains("statusline --harness claude"));
    assert!(sl_cmd.contains("--chain-file"));
    // Because gateway/settings.json symlinks to ~/.claude/settings.json, it reuses the canonical chain file!
    assert!(
        state_dir.join("claude-statusline-chain.json").is_file(),
        "symlinked settings.json should reuse canonical claude-statusline-chain.json"
    );

    // 3. Separate `gateway/commands/hyphae*.md` installed cleanly.
    for cmd_file in [
        "hyphae.md",
        "hyphae-subs.md",
        "hyphae-focus.md",
        "hyphae-mute.md",
    ] {
        let content = fs::read_to_string(gateway.join("commands").join(cmd_file))
            .unwrap_or_else(|e| panic!("missing gateway command {cmd_file}: {e}"))
            .replace("\r\n", "\n");
        assert!(content.starts_with("---\n"));
    }

    // 4. `gateway/skills` symlink preserved AND both side-panel mod & runtime SKILL.md written through it.
    assert!(
        fs::symlink_metadata(&gw_skills_link)
            .unwrap()
            .file_type()
            .is_symlink(),
        "gateway/skills symlink must stay intact"
    );
    assert!(
        gateway
            .join("skills")
            .join("hyphae-panel")
            .join("hooks")
            .join("register.tsx")
            .is_file()
    );
    let runtime_skill = fs::read_to_string(gateway.join("skills").join("hyphae").join("SKILL.md"))
        .unwrap()
        .replace("\r\n", "\n");
    assert!(runtime_skill.starts_with("---\nname: hyphae\n"));

    // 5. `hyp doctor --claude-config-dir <gateway>` sees claude configured + statusLine chained OK.
    let doc_a = clean_cmd(&home)
        .args([
            "doctor",
            "--home",
            home.to_str().unwrap(),
            "--claude-config-dir",
            gateway.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(doc_a.status.code(), Some(0));
    let doc_a_json = parse_json_stdout(&doc_a);
    let claude_diag = doc_a_json["data"]["harnesses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["harness"] == "claude")
        .unwrap();
    assert_eq!(claude_diag["detected"], true);
    assert_eq!(claude_diag["configured"], true);
    let claude_sl = doc_a_json["data"]["statusLines"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["harness"] == "claude")
        .unwrap();
    assert_eq!(claude_sl["configured"], true);
    assert_eq!(claude_sl["chained"], true);
    assert_eq!(claude_sl["chainFileExists"], true);

    // 6. `--restore-statusline` restores original `statusLine` verbatim AND preserves symlink.
    let restore_a = clean_cmd(&home)
        .args([
            "setup",
            "--harness",
            "claude",
            "--restore-statusline",
            "--home",
            home.to_str().unwrap(),
            "--claude-config-dir",
            gateway.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(restore_a.status.code(), Some(0));
    assert!(
        fs::symlink_metadata(&gw_settings_link)
            .unwrap()
            .file_type()
            .is_symlink(),
        "--restore-statusline must preserve gateway/settings.json symlink"
    );
    let restored_settings: Value = serde_json::from_str(
        &fs::read_to_string(home.join(".claude").join("settings.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(restored_settings["statusLine"], original_bar);
    assert!(!state_dir.join("claude-statusline-chain.json").exists());

    // ------------------------------------------------------------------------
    // Phase B: Env `CLAUDE_CONFIG_DIR=<gateway>` inside `<home>` configures BOTH profiles!
    // ------------------------------------------------------------------------
    let out_b = clean_cmd(&home)
        .env("CLAUDE_CONFIG_DIR", &gateway)
        .args([
            "setup",
            "--harness",
            "claude",
            "--statusline",
            "--bin",
            fake_bin,
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(out_b.status.code(), Some(0));

    // BOTH gateway/.claude.json AND ~/.claude.json get mcpServers.hyphae while keeping existing MCP servers!
    let gw_mcp_b: Value =
        serde_json::from_str(&fs::read_to_string(gateway.join(".claude.json")).unwrap()).unwrap();
    let home_mcp_b: Value =
        serde_json::from_str(&fs::read_to_string(home.join(".claude.json")).unwrap()).unwrap();
    assert_eq!(gw_mcp_b["mcpServers"]["gateway-mcp"]["command"], "npx");
    assert_eq!(gw_mcp_b["mcpServers"]["hyphae"]["command"], fake_bin);
    assert_eq!(home_mcp_b["mcpServers"]["existing-home"]["command"], "npx");
    assert_eq!(home_mcp_b["mcpServers"]["hyphae"]["command"], fake_bin);

    // Both distinct commands dirs populated; symlinks still intact!
    assert!(gateway.join("commands").join("hyphae.md").is_file());
    assert!(
        home.join(".claude")
            .join("commands")
            .join("hyphae.md")
            .is_file()
    );
    assert!(
        fs::symlink_metadata(&gw_settings_link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(
        fs::symlink_metadata(&gw_skills_link)
            .unwrap()
            .file_type()
            .is_symlink()
    );

    // Doctor with CLAUDE_CONFIG_DIR sees single deduplicated Claude statusLine entry (symlinked settings.json).
    let doc_b = clean_cmd(&home)
        .env("CLAUDE_CONFIG_DIR", &gateway)
        .args([
            "doctor",
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(doc_b.status.code(), Some(0));
    let doc_b_json = parse_json_stdout(&doc_b);
    let claude_sl_entries: Vec<&Value> = doc_b_json["data"]["statusLines"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["harness"] == "claude")
        .collect();
    assert_eq!(
        claude_sl_entries.len(),
        1,
        "symlinked settings.json should deduplicate to 1 Claude statusLine entry: {claude_sl_entries:?}"
    );
    assert_eq!(claude_sl_entries[0]["configured"], true);
    assert_eq!(claude_sl_entries[0]["chained"], true);

    // Restore via env CLAUDE_CONFIG_DIR restores verbatim and keeps symlink intact.
    let restore_b = clean_cmd(&home)
        .env("CLAUDE_CONFIG_DIR", &gateway)
        .args([
            "setup",
            "--harness",
            "claude",
            "--restore-statusline",
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(restore_b.status.code(), Some(0));
    let restored_b: Value = serde_json::from_str(
        &fs::read_to_string(home.join(".claude").join("settings.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(restored_b["statusLine"], original_bar);
    assert!(
        fs::symlink_metadata(&gw_settings_link)
            .unwrap()
            .file_type()
            .is_symlink()
    );

    // `hyp onboard --install-skill --harness claude` with symlinked `gateway/skills -> ~/.claude/skills`
    // installs once without breaking the `skills` symlink or emitting duplicate extraPaths.
    let install_skill_gw = clean_cmd(&home)
        .env("CLAUDE_CONFIG_DIR", &gateway)
        .args([
            "onboard",
            "--install-skill",
            "--harness",
            "claude",
            "--home",
            home.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(install_skill_gw.status.code(), Some(0));
    let skill_gw_json = parse_json_stdout(&install_skill_gw);
    let claude_skill_entry = skill_gw_json["data"]["installed"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["harness"] == "claude")
        .unwrap();
    assert_eq!(
        claude_skill_entry
            .get("extraPaths")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0),
        0,
        "symlinked skills/ must deduplicate so extraPaths is empty: {claude_skill_entry}"
    );
    assert!(
        fs::symlink_metadata(&gw_skills_link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    assert!(
        gateway
            .join("skills")
            .join("hyphae-setup")
            .join("SKILL.md")
            .is_file()
    );

    // ------------------------------------------------------------------------
    // Phase C: Hermetic `--home` MUST NEVER touch ambient CLAUDE_CONFIG_DIR outside `<home>`
    // ------------------------------------------------------------------------
    let out_c = clean_cmd(&home)
        .env("CLAUDE_CONFIG_DIR", &outside_profile)
        .args([
            "setup",
            "--harness",
            "claude",
            "--bin",
            fake_bin,
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(out_c.status.code(), Some(0));
    assert!(
        !outside_profile.exists(),
        "isolated --home must never write to an ambient CLAUDE_CONFIG_DIR outside --home"
    );
}

#[test]
fn independent_claude_config_dir_statusline_chain_onboard_and_doctor_all_os() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let state_dir = tmp.path().join("state");
    let work_profile = home.join("profiles").join("work-claude");

    fs::create_dir_all(home.join(".claude")).unwrap();
    fs::create_dir_all(&work_profile).unwrap();

    let home_bar = json!({
        "type": "command",
        "command": "home-bar --short"
    });
    let work_bar = json!({
        "type": "command",
        "command": "work-bar --detailed"
    });

    fs::write(
        home.join(".claude").join("settings.json"),
        serde_json::to_string_pretty(&json!({ "statusLine": home_bar })).unwrap(),
    )
    .unwrap();
    fs::write(
        home.join(".claude.json"),
        serde_json::to_string_pretty(&json!({
            "mcpServers": { "home-mcp": { "command": "echo", "args": ["home"] } }
        }))
        .unwrap(),
    )
    .unwrap();

    // Independent non-symlinked settings.json + .claude.json inside CLAUDE_CONFIG_DIR.
    fs::write(
        work_profile.join("settings.json"),
        serde_json::to_string_pretty(&json!({ "statusLine": work_bar })).unwrap(),
    )
    .unwrap();
    fs::write(
        work_profile.join(".claude.json"),
        serde_json::to_string_pretty(&json!({
            "mcpServers": { "work-mcp": { "command": "echo", "args": ["work"] } }
        }))
        .unwrap(),
    )
    .unwrap();

    let fake_bin = "/opt/hyphae/bin/hyp";

    // 1. Setup with env CLAUDE_CONFIG_DIR inside `<home>`: chains BOTH bars into distinct files!
    let setup = clean_cmd(&home)
        .env("CLAUDE_CONFIG_DIR", &work_profile)
        .args([
            "setup",
            "--harness",
            "claude",
            "--statusline",
            "--bin",
            fake_bin,
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(setup.status.code(), Some(0));

    let home_mcp: Value =
        serde_json::from_str(&fs::read_to_string(home.join(".claude.json")).unwrap()).unwrap();
    let work_mcp: Value =
        serde_json::from_str(&fs::read_to_string(work_profile.join(".claude.json")).unwrap())
            .unwrap();
    assert_eq!(home_mcp["mcpServers"]["home-mcp"]["command"], "echo");
    assert_eq!(home_mcp["mcpServers"]["hyphae"]["command"], fake_bin);
    assert_eq!(work_mcp["mcpServers"]["work-mcp"]["command"], "echo");
    assert_eq!(work_mcp["mcpServers"]["hyphae"]["command"], fake_bin);

    // Distinct per-profile chain backup files (zero collision!).
    let chain_files: Vec<_> = fs::read_dir(&state_dir)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("claude") && n.ends_with("-statusline-chain.json"))
        })
        .collect();
    assert_eq!(
        chain_files.len(),
        2,
        "expected canonical + per-profile chain backup files, got: {chain_files:?}"
    );
    let canonical_chain = state_dir.join("claude-statusline-chain.json");
    assert!(canonical_chain.is_file());
    let saved_home_bar: Value =
        serde_json::from_str(&fs::read_to_string(&canonical_chain).unwrap()).unwrap();
    assert_eq!(saved_home_bar, home_bar);

    let per_profile_chain = chain_files
        .iter()
        .find(|p| **p != canonical_chain)
        .expect("per-profile hashed chain file");
    let saved_work_bar: Value =
        serde_json::from_str(&fs::read_to_string(per_profile_chain).unwrap()).unwrap();
    assert_eq!(saved_work_bar, work_bar);

    // Both independent skills/ directories received runtime hyphae/SKILL.md.
    for skill_path in [
        work_profile.join("skills").join("hyphae").join("SKILL.md"),
        home.join(".claude")
            .join("skills")
            .join("hyphae")
            .join("SKILL.md"),
    ] {
        let text = fs::read_to_string(&skill_path)
            .unwrap_or_else(|e| panic!("missing {}: {e}", skill_path.display()))
            .replace("\r\n", "\n");
        assert!(text.starts_with("---\nname: hyphae\n"));
    }

    // 2. Doctor detects both distinct Claude statusLine profiles cleanly.
    let doc = clean_cmd(&home)
        .env("CLAUDE_CONFIG_DIR", &work_profile)
        .args([
            "doctor",
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(doc.status.code(), Some(0));
    let doc_json = parse_json_stdout(&doc);
    let claude_sl_entries: Vec<&Value> = doc_json["data"]["statusLines"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["harness"] == "claude")
        .collect();
    assert_eq!(claude_sl_entries.len(), 2);
    for entry in &claude_sl_entries {
        assert_eq!(entry["configured"], true);
        assert_eq!(entry["chained"], true);
        assert_eq!(entry["chainFileExists"], true);
    }

    // 3. Restore both statusLines verbatim and delete both chain backups.
    let restore = clean_cmd(&home)
        .env("CLAUDE_CONFIG_DIR", &work_profile)
        .args([
            "setup",
            "--harness",
            "claude",
            "--restore-statusline",
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(restore.status.code(), Some(0));
    let restored_home: Value = serde_json::from_str(
        &fs::read_to_string(home.join(".claude").join("settings.json")).unwrap(),
    )
    .unwrap();
    let restored_work: Value =
        serde_json::from_str(&fs::read_to_string(work_profile.join("settings.json")).unwrap())
            .unwrap();
    assert_eq!(restored_home["statusLine"], home_bar);
    assert_eq!(restored_work["statusLine"], work_bar);
    assert!(!canonical_chain.exists());
    assert!(!per_profile_chain.exists());

    // 4. `hyp onboard --install-skill --harness claude` installs hyphae-setup/SKILL.md into BOTH profiles!
    let install_skill = clean_cmd(&home)
        .env("CLAUDE_CONFIG_DIR", &work_profile)
        .args([
            "onboard",
            "--install-skill",
            "--harness",
            "claude",
            "--home",
            home.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(install_skill.status.code(), Some(0));
    assert!(
        work_profile
            .join("skills")
            .join("hyphae-setup")
            .join("SKILL.md")
            .is_file()
    );
    assert!(
        home.join(".claude")
            .join("skills")
            .join("hyphae-setup")
            .join("SKILL.md")
            .is_file()
    );

    // 5. Simulate missing mcpServers.hyphae in work-profile/.claude.json while hooks exist ->
    //    `hyp doctor --claude-config-dir <work_profile>` must flag it clearly!
    fs::write(
        work_profile.join(".claude.json"),
        serde_json::to_string_pretty(&json!({ "mcpServers": {} })).unwrap(),
    )
    .unwrap();
    let doc_missing = clean_cmd(&home)
        .args([
            "doctor",
            "--home",
            home.to_str().unwrap(),
            "--claude-config-dir",
            work_profile.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(doc_missing.status.code(), Some(0));
    let doc_missing_json = parse_json_stdout(&doc_missing);
    let claude_diag = doc_missing_json["data"]["harnesses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|h| h["harness"] == "claude")
        .unwrap();
    assert_eq!(claude_diag["detected"], true);
    assert_eq!(claude_diag["configured"], false);
    assert!(
        claude_diag["detail"]
            .as_str()
            .unwrap()
            .contains("missing mcpServers.hyphae")
    );
    assert!(
        claude_diag["fix"]
            .as_str()
            .unwrap()
            .contains("--claude-config-dir")
    );

    // 6. `hyp onboard --assist claude` (with empty PATH so it never spawns host `claude`)
    //    installs `hyphae-setup/SKILL.md` into `$CLAUDE_CONFIG_DIR/skills/hyphae-setup/SKILL.md`
    //    and sets `primarySkillPath` accordingly!
    let assist_work = home.join("profiles").join("assist-claude");
    fs::create_dir_all(&assist_work).unwrap();
    let assist = clean_cmd(&home)
        .env("PATH", "")
        .args([
            "onboard",
            "--assist",
            "claude",
            "--home",
            home.to_str().unwrap(),
            "--claude-config-dir",
            assist_work.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(assist.status.code(), Some(0));
    let assist_json = parse_json_stdout(&assist);
    assert_eq!(assist_json["ok"], true);
    let expected_assist_skill = assist_work
        .join("skills")
        .join("hyphae-setup")
        .join("SKILL.md");
    assert!(expected_assist_skill.is_file());
    assert_eq!(
        assist_json["data"]["primarySkillPath"],
        expected_assist_skill.display().to_string()
    );

    // 7. `hyp onboard --yes --claude-config-dir <work_profile>` wires it back cleanly!
    let onboard = clean_cmd(&home)
        .args([
            "onboard",
            "--yes",
            "--node-id",
            "alice@work-profile",
            "--harness",
            "claude",
            "--bin",
            fake_bin,
            "--home",
            home.to_str().unwrap(),
            "--claude-config-dir",
            work_profile.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--no-start",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(onboard.status.code(), Some(0));
    let work_mcp_after: Value =
        serde_json::from_str(&fs::read_to_string(work_profile.join(".claude.json")).unwrap())
            .unwrap();
    assert_eq!(work_mcp_after["mcpServers"]["hyphae"]["command"], fake_bin);
}

#[cfg(unix)]
#[test]
fn herdr_symlinked_custom_header_pill_js_and_patch_layout_symlink_safety_e2e() {
    use std::os::unix::fs::symlink;

    fn sample_layout(pane_mod: &str) -> Value {
        json!({
            "id": "root",
            "type": "row",
            "children": [{
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
                        "children": [{
                            "id": "panel-body",
                            "type": "stack",
                            "active": "files",
                            "children": [
                                { "id": "files", "type": "block", "content": { "mod": "files" } }
                            ]
                        }]
                    }
                ]
            }]
        })
    }

    // 1. Symlinked layout with custom pane header (`folder-pane`): warns with pill.js guidance,
    //    NEVER recommends replacing `pane.header.content.mod = "hyphae-pane"`, and leaves target untouched.
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let state_dir = tmp.path().join("state");
    let herdr_app = home.join(".config").join("herdr-app");
    fs::create_dir_all(herdr_app.join("layouts")).unwrap();
    fs::write(
        herdr_app.join("shared.json"),
        serde_json::to_string(&json!({ "layout": "herdr-folders" })).unwrap(),
    )
    .unwrap();

    let custom_repo = tmp.path().join("herdr-custom-ui");
    fs::create_dir_all(&custom_repo).unwrap();
    let external_custom = custom_repo.join("herdr-folders.json");
    let original_custom = serde_json::to_string_pretty(&sample_layout("folder-pane")).unwrap();
    fs::write(&external_custom, &original_custom).unwrap();
    symlink(
        &external_custom,
        herdr_app.join("layouts").join("herdr-folders.json"),
    )
    .unwrap();

    let out_custom = clean_cmd(&home)
        .args([
            "setup",
            "--harness",
            "herdr",
            "--mod",
            "--bin",
            "/opt/hyphae/bin/hyp",
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(out_custom.status.code(), Some(0));
    let json_custom = parse_json_stdout(&out_custom);
    assert_eq!(json_custom["ok"], true);
    assert_eq!(
        json_custom["data"]["herdrMod"]["layoutAction"],
        "skipped_symlink"
    );
    assert_eq!(
        fs::read_to_string(&external_custom).unwrap(),
        original_custom,
        "external custom-header layout must remain byte-for-byte untouched"
    );

    let warnings: Vec<String> = json_custom["warnings"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(ToOwned::to_owned))
        .collect();
    let notes: Vec<String> = json_custom["data"]["herdrMod"]["notes"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(ToOwned::to_owned))
        .collect();
    let next: Vec<String> = json_custom["next"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str().map(ToOwned::to_owned))
        .collect();

    assert!(
        warnings
            .iter()
            .any(|w| w.contains("folder-pane") && w.contains("symlink")),
        "expected custom-header symlink warning: {warnings:?}"
    );
    assert!(
        notes.iter().any(|n| n.contains("pill.js")
            && n.contains("mods/folder-pane/")
            && n.contains("hyphae-panel")),
        "expected pill.js + hyphae-panel composition note: {notes:?}"
    );
    for msg in warnings.iter().chain(notes.iter()).chain(next.iter()) {
        assert!(
            !msg.contains("pane.header.content.mod = \"hyphae-pane\""),
            "must NOT advise overwriting custom pane header mod: {msg}"
        );
    }

    // 2. `--patch-layout` on a symlinked default-header layout updates target atomically AND preserves symlink.
    let tmp2 = tempfile::tempdir().unwrap();
    let home2 = tmp2.path().join("home");
    let state2 = tmp2.path().join("state");
    let herdr_app2 = home2.join(".config").join("herdr-app");
    fs::create_dir_all(herdr_app2.join("layouts")).unwrap();
    fs::write(
        herdr_app2.join("shared.json"),
        serde_json::to_string(&json!({ "layout": "my-git-layout" })).unwrap(),
    )
    .unwrap();
    let dotfiles = tmp2.path().join("dotfiles");
    fs::create_dir_all(&dotfiles).unwrap();
    let external_default = dotfiles.join("my-git-layout.json");
    fs::write(
        &external_default,
        serde_json::to_string_pretty(&sample_layout("pane")).unwrap(),
    )
    .unwrap();
    let layout_link = herdr_app2.join("layouts").join("my-git-layout.json");
    symlink(&external_default, &layout_link).unwrap();

    let out_patch = clean_cmd(&home2)
        .args([
            "setup",
            "--harness",
            "herdr",
            "--mod",
            "--patch-layout",
            "--bin",
            "/opt/hyphae/bin/hyp",
            "--home",
            home2.to_str().unwrap(),
            "--state-dir",
            state2.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(out_patch.status.code(), Some(0));
    let json_patch = parse_json_stdout(&out_patch);
    assert_eq!(json_patch["ok"], true);
    assert_eq!(json_patch["data"]["herdrMod"]["layoutAction"], "patched");
    assert!(
        fs::symlink_metadata(&layout_link)
            .unwrap()
            .file_type()
            .is_symlink(),
        "--patch-layout must preserve the layout symlink intact"
    );
    let patched_doc: Value =
        serde_json::from_str(&fs::read_to_string(&external_default).unwrap()).unwrap();
    assert_eq!(
        patched_doc["children"][0]["children"][0]["content"]["pane"]["header"]["content"]["mod"],
        "hyphae-pane"
    );
}
