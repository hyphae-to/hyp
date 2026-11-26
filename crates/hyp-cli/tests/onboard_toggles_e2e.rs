//! End-to-end tests for granular `hyp setup` & `hyp onboard` component opt-in/opt-out flags
//! (`--no-skills`, `--no-commands`, `--statusline`, `--mod`, `--interactive` TTY/JSON guards).
//!
//! Strict isolation invariant: every test uses ephemeral `tempfile::TempDir`, isolated
//! `HOME` / `--home` / `--state-dir`, and `HYPHAE_SECRET_BACKEND=file` — zero live user
//! config or OS Keychain mutations!

mod common;

use common::{isolated_cmd, parse_json_stdout};
use serde_json::{Value, json};
use std::fs;
use std::process::Stdio;

#[test]
fn setup_claude_no_skills_and_no_commands_writes_only_mcp_and_hooks() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(home.join(".claude")).unwrap();
    fs::write(
        home.join(".claude/settings.json"),
        serde_json::to_string_pretty(&json!({ "theme": "forest" })).unwrap(),
    )
    .unwrap();

    let fake_bin = "/opt/hyphae/bin/hyp";
    let out = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "claude",
            "--no-skills",
            "--no-commands",
            "--bin",
            fake_bin,
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let payload = parse_json_stdout(&out);
    assert_eq!(payload["ok"], true);
    assert_eq!(payload["data"]["configuredCount"], 1);

    // MCP & hooks MUST be written while preserving unrelated user settings.
    let mcp: Value =
        serde_json::from_str(&fs::read_to_string(home.join(".claude.json")).unwrap()).unwrap();
    assert_eq!(mcp["mcpServers"]["hyphae"]["command"], fake_bin);

    let settings: Value =
        serde_json::from_str(&fs::read_to_string(home.join(".claude/settings.json")).unwrap())
            .unwrap();
    assert_eq!(settings["theme"], "forest");
    assert!(settings["hooks"]["PreToolUse"].is_array());
    assert!(settings["hooks"]["PostToolUse"].is_array());
    assert!(settings["hooks"]["Stop"].is_array());
    assert!(settings.get("statusLine").is_none());

    // Runtime skill and ALL 4 slash commands MUST NOT exist.
    assert!(
        !home.join(".claude/skills/hyphae/SKILL.md").exists(),
        "runtime skill must be skipped when --no-skills is passed"
    );
    for cmd_file in [
        "hyphae.md",
        "hyphae-subs.md",
        "hyphae-focus.md",
        "hyphae-mute.md",
    ] {
        assert!(
            !home.join(".claude/commands").join(cmd_file).exists(),
            "slash command {cmd_file} must be skipped when --no-commands is passed"
        );
    }

    assert!(
        !home.join(".claude/skills/hyphae-panel").exists(),
        "native side-panel mod must be skipped when --no-commands is passed"
    );

    let notes = payload["data"]["harnesses"][0]["notes"]
        .as_array()
        .expect("notes array");
    assert!(
        notes
            .iter()
            .any(|n| n.as_str() == Some("Skipped runtime skills (--no-skills).")),
        "expected explicit --no-skills skip note in {notes:?}"
    );
    assert!(
        notes.iter().any(|n| n
            .as_str()
            .is_some_and(|s| s.contains("--no-commands") && s.contains("Claude slash commands"))),
        "expected explicit --no-commands skip note in {notes:?}"
    );
}

#[test]
fn setup_claude_and_antigravity_statusline_without_skills() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(home.join(".claude")).unwrap();
    fs::create_dir_all(home.join(".gemini/antigravity-cli")).unwrap();

    // Seed an existing custom Claude statusLine to verify non-destructive chaining works with --no-skills.
    fs::write(
        home.join(".claude/settings.json"),
        serde_json::to_string_pretty(&json!({
            "statusLine": { "type": "command", "command": "my-custom-bar" }
        }))
        .unwrap(),
    )
    .unwrap();

    let fake_bin = "/opt/hyphae/bin/hyp";
    let out = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "claude,antigravity",
            "--statusline",
            "--no-skills",
            "--bin",
            fake_bin,
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let payload = parse_json_stdout(&out);
    assert_eq!(payload["ok"], true);
    assert_eq!(payload["data"]["configuredCount"], 2);

    // Claude statusLine chained safely, slash commands installed, runtime skill skipped.
    let claude_settings: Value =
        serde_json::from_str(&fs::read_to_string(home.join(".claude/settings.json")).unwrap())
            .unwrap();
    let claude_sl_cmd = claude_settings["statusLine"]["command"]
        .as_str()
        .expect("claude statusLine.command");
    assert!(claude_sl_cmd.contains("statusline --harness claude"));
    assert!(claude_sl_cmd.contains("--chain-file"));
    assert!(state_dir.join("claude-statusline-chain.json").is_file());
    assert!(
        home.join(".claude/commands/hyphae.md").is_file(),
        "Claude slash commands should still install when --no-commands is not passed"
    );
    assert!(
        !home.join(".claude/skills/hyphae/SKILL.md").exists(),
        "Claude runtime skill must not be written when --no-skills is passed"
    );

    // Antigravity statusLine configured, plugin written, runtime skill skipped.
    assert!(
        home.join(".gemini/config/plugins/hyphae/hooks.json")
            .is_file()
    );
    let agy_settings: Value = serde_json::from_str(
        &fs::read_to_string(home.join(".gemini/antigravity-cli/settings.json")).unwrap(),
    )
    .unwrap();
    let agy_sl_cmd = agy_settings["statusLine"]["command"]
        .as_str()
        .expect("antigravity statusLine.command");
    assert!(agy_sl_cmd.contains("statusline --harness antigravity"));
    assert_eq!(agy_settings["statusLine"]["stack_with_default"], true);
    assert!(
        !home
            .join(".gemini/config/plugins/hyphae/skills/hyphae/SKILL.md")
            .exists(),
        "Antigravity runtime skill must not be written when --no-skills is passed"
    );
}

#[test]
fn setup_all_no_skills_skips_runtime_skills_across_all_nine_harnesses() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&home).unwrap();

    let out = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "all",
            "--no-skills",
            "--bin",
            "/opt/hyphae/bin/hyp",
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let payload = parse_json_stdout(&out);
    assert_eq!(payload["ok"], true);
    assert_eq!(payload["data"]["configuredCount"], 9);

    for skill_rel in [
        ".gemini/config/plugins/hyphae/skills/hyphae/SKILL.md",
        ".claude/skills/hyphae/SKILL.md",
        ".codex/skills/hyphae/SKILL.md",
        ".agents/skills/hyphae/SKILL.md",
        ".cursor/skills/hyphae/SKILL.md",
        ".config/opencode/skills/hyphae/SKILL.md",
        ".gemini/skills/hyphae/SKILL.md",
        ".openclaw/skills/hyphae/SKILL.md",
        ".config/herdr/skills/hyphae/SKILL.md",
    ] {
        assert!(
            !home.join(skill_rel).exists(),
            "expected no runtime skill at {skill_rel} when --no-skills is passed"
        );
    }
}

#[test]
fn onboard_yes_selected_harnesses_with_statusline_mod_and_no_skills() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let state_dir = tmp.path().join("state");

    // Seed BOTH selected harnesses (claude, herdr + herdr-app) AND unselected detected harnesses (codex, cursor).
    fs::create_dir_all(home.join(".claude")).unwrap();
    fs::create_dir_all(home.join(".config/herdr")).unwrap();
    fs::create_dir_all(home.join(".config/herdr-app/layouts")).unwrap();
    fs::write(
        home.join(".config/herdr-app/shared.json"),
        serde_json::to_string_pretty(&json!({ "layout": "main" })).unwrap(),
    )
    .unwrap();
    // Unselected harnesses present under home — MUST NOT be touched!
    fs::create_dir_all(home.join(".codex")).unwrap();
    fs::create_dir_all(home.join(".cursor")).unwrap();

    let fake_bin = "/opt/hyphae/bin/hyp";
    let out = isolated_cmd(&home)
        .args([
            "onboard",
            "--yes",
            "--node-id",
            "alice@workstation",
            "--harness",
            "claude,herdr",
            "--statusline",
            "--mod",
            "--no-skills",
            "--bin",
            fake_bin,
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--no-start",
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();

    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr)
    );
    let payload = parse_json_stdout(&out);
    assert_eq!(payload["ok"], true);
    assert_eq!(payload["command"], "onboard");

    // Verify ONLY claude & herdr were configured.
    let harnesses = payload["data"]["harnesses"]
        .as_array()
        .expect("harnesses array");
    let names: Vec<&str> = harnesses
        .iter()
        .filter_map(|h| h["harness"].as_str())
        .collect();
    assert_eq!(names, vec!["claude", "herdr"]);

    // Unselected detected harnesses must remain completely untouched.
    assert!(!home.join(".codex/config.toml").exists());
    assert!(!home.join(".codex/hooks.json").exists());
    assert!(!home.join(".cursor/mcp.json").exists());
    assert!(!home.join(".cursor/hooks.json").exists());

    // Claude statusLine enabled, hooks/MCP written, runtime skills skipped.
    let claude_settings: Value =
        serde_json::from_str(&fs::read_to_string(home.join(".claude/settings.json")).unwrap())
            .unwrap();
    assert!(
        claude_settings["statusLine"]["command"]
            .as_str()
            .is_some_and(|c| c.contains("statusline --harness claude"))
    );
    assert!(home.join(".claude/commands/hyphae.md").is_file());
    assert!(!home.join(".claude/skills/hyphae/SKILL.md").exists());

    // Native Herdr mod installed safely, runtime skills skipped, no dead ~/.config/herdr/hyphae.json written (X9).
    assert!(!home.join(".config/herdr/hyphae.json").exists());
    assert!(!home.join(".config/herdr/skills/hyphae/SKILL.md").exists());
    assert!(
        home.join(".config/herdr-app/mods/hyphae-pane/mod.json")
            .is_file()
    );
    assert!(
        home.join(".config/herdr-app/mods/hyphae-pane/pill.js")
            .is_file()
    );
    assert!(
        home.join(".config/herdr-app/mods/hyphae-panel/mod.json")
            .is_file()
    );
    assert!(home.join(".config/herdr-app/keys.json").is_file());
    assert_eq!(
        payload["data"]["herdrMod"]["installedMods"],
        json!(["hyphae-pane", "hyphae-panel"])
    );
}

#[test]
fn onboard_yes_no_commands_skips_claude_slash_commands_and_default_yes_preserves_backcompat() {
    // 1. Explicit `--no-commands` skips slash commands while keeping runtime skills.
    let tmp1 = tempfile::tempdir().unwrap();
    let home1 = tmp1.path().join("home");
    let state1 = tmp1.path().join("state");
    fs::create_dir_all(home1.join(".claude")).unwrap();

    let out1 = isolated_cmd(&home1)
        .args([
            "onboard",
            "--yes",
            "--node-id",
            "bob@laptop",
            "--harness",
            "claude",
            "--no-commands",
            "--home",
            home1.to_str().unwrap(),
            "--state-dir",
            state1.to_str().unwrap(),
            "--no-start",
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out1.status.code(), Some(0));
    assert!(home1.join(".claude/skills/hyphae/SKILL.md").is_file());
    assert!(!home1.join(".claude/commands/hyphae.md").exists());

    // 2. Default `hyp onboard --yes` (no new flags): skills enabled, statusLine off, Herdr mod off.
    let tmp2 = tempfile::tempdir().unwrap();
    let home2 = tmp2.path().join("home");
    let state2 = tmp2.path().join("state");
    fs::create_dir_all(home2.join(".claude")).unwrap();
    fs::create_dir_all(home2.join(".config/herdr")).unwrap();
    fs::create_dir_all(home2.join(".config/herdr-app")).unwrap();

    let out2 = isolated_cmd(&home2)
        .args([
            "onboard",
            "--yes",
            "--node-id",
            "carol@laptop",
            "--home",
            home2.to_str().unwrap(),
            "--state-dir",
            state2.to_str().unwrap(),
            "--no-start",
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out2.status.code(), Some(0));
    let payload2 = parse_json_stdout(&out2);
    assert_eq!(payload2["ok"], true);
    assert!(payload2["data"].get("herdrMod").is_none());
    assert!(home2.join(".claude/skills/hyphae/SKILL.md").is_file());
    assert!(home2.join(".claude/commands/hyphae.md").is_file());
    let claude_settings2: Value =
        serde_json::from_str(&fs::read_to_string(home2.join(".claude/settings.json")).unwrap())
            .unwrap();
    assert!(claude_settings2.get("statusLine").is_none());
    assert!(!home2.join(".config/herdr-app/mods/hyphae-pane").exists());
}

#[test]
fn setup_interactive_rejects_json_and_non_tty_with_exit_usage_and_zero_writes() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(home.join(".claude")).unwrap();

    // 1. `--interactive --json` must exit 2 (`EXIT_USAGE`) with structured error envelope.
    let out_json = isolated_cmd(&home)
        .args([
            "setup",
            "--interactive",
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(
        out_json.status.code(),
        Some(2),
        "expected EXIT_USAGE (2) for `hyp setup --interactive --json`, stderr={}",
        String::from_utf8_lossy(&out_json.stderr)
    );
    let err_json = parse_json_stdout(&out_json);
    assert_eq!(err_json["ok"], false);
    assert_eq!(err_json["error"]["code"], "INTERACTIVE_WITH_JSON");

    // 2. `--interactive` on non-TTY must also exit 2 (`EXIT_USAGE`).
    let out_non_tty = isolated_cmd(&home)
        .args([
            "setup",
            "--interactive",
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(
        out_non_tty.status.code(),
        Some(2),
        "expected EXIT_USAGE (2) for non-TTY `hyp setup --interactive`, stderr={}",
        String::from_utf8_lossy(&out_non_tty.stderr)
    );

    // 3. Conflicting `--no-skills --refresh-skills` exits 2 (`EXIT_USAGE`).
    let out_conflict = isolated_cmd(&home)
        .args([
            "setup",
            "--no-skills",
            "--refresh-skills",
            "--home",
            home.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out_conflict.status.code(), Some(2));

    // Zero files written under home or state_dir!
    assert!(!home.join(".claude.json").exists());
    assert!(!home.join(".claude/settings.json").exists());
    assert!(!state_dir.exists());
}

#[test]
fn setup_openclaw_installs_plugin_persists_delivery_and_prompt_injection_and_rejects_conflicts() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(home.join(".openclaw")).unwrap();
    fs::create_dir_all(&state_dir).unwrap();
    // Seed an existing openclaw.json with unrelated provider & MCP server to verify non-destructive merge.
    fs::write(
        home.join(".openclaw/openclaw.json"),
        serde_json::to_string_pretty(&json!({
            "agents": { "defaults": { "workspace": "/tmp/ws" } },
            "mcp": { "servers": { "weather": { "command": "weather-mcp", "args": [] } } }
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        state_dir.join("node.json"),
        serde_json::to_string_pretty(&json!({ "v": 2, "nodeId": "oc-test@box" })).unwrap(),
    )
    .unwrap();

    // 1. Conflicting `--openclaw-prompt-injection` + `--no-openclaw-prompt-injection` -> EXIT_USAGE (2).
    let conflict = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "openclaw",
            "--openclaw-prompt-injection",
            "--no-openclaw-prompt-injection",
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(conflict.status.code(), Some(2));
    assert_eq!(
        parse_json_stdout(&conflict)["error"]["code"],
        "CONFLICTING_FLAGS"
    );

    // 2. Default install -> conservative prompt injection OFF, delivery=gateway, plugin files installed.
    let fake_bin = "/opt/hyphae/bin/hyp";
    let out_default = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "openclaw",
            "--bin",
            fake_bin,
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(
        out_default.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out_default.stderr)
    );
    let payload_default = parse_json_stdout(&out_default);
    let notes_str =
        serde_json::to_string(&payload_default["data"]["harnesses"][0]["notes"]).unwrap();
    assert!(
        notes_str.contains("Even with prompt injection OFF") && notes_str.contains("hyp_inbox"),
        "expected reassurance note: {notes_str}"
    );
    assert!(
        home.join(".openclaw/extensions/hyphae/openclaw.plugin.json")
            .is_file()
    );
    assert!(home.join(".openclaw/extensions/hyphae/index.js").is_file());

    let oc_cfg: Value =
        serde_json::from_str(&fs::read_to_string(home.join(".openclaw/openclaw.json")).unwrap())
            .unwrap();
    assert_eq!(oc_cfg["agents"]["defaults"]["workspace"], "/tmp/ws");
    assert!(oc_cfg["mcp"]["servers"]["weather"].is_object());
    assert_eq!(oc_cfg["mcp"]["servers"]["hyphae"]["command"], fake_bin);
    assert_eq!(oc_cfg["plugins"]["allow"], json!(["hyphae"]));
    assert_eq!(oc_cfg["plugins"]["entries"]["hyphae"]["enabled"], true);
    assert_eq!(
        oc_cfg["plugins"]["entries"]["hyphae"]["hooks"]["allowPromptModification"],
        false
    );
    assert_eq!(
        oc_cfg["plugins"]["entries"]["hyphae"]["hooks"]["allowConversationAccess"],
        false
    );
    assert!(
        oc_cfg["plugins"]["entries"]["hyphae"]["hooks"]
            .get("allowPromptInjection")
            .is_none(),
        "must NEVER emit deprecated allowPromptInjection key"
    );
    assert_eq!(
        oc_cfg["plugins"]["entries"]["hyphae"]["config"]["deliveryMode"],
        "gateway"
    );
    assert_eq!(
        oc_cfg["plugins"]["entries"]["hyphae"]["config"]["promptInjection"],
        false
    );

    // 3. Explicit `--openclaw-delivery inbox --openclaw-prompt-injection` updates openclaw.json + node.json!
    let out_on = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "openclaw",
            "--openclaw-delivery",
            "inbox",
            "--openclaw-prompt-injection",
            "--bin",
            fake_bin,
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out_on.status.code(), Some(0));
    let oc_cfg_on: Value =
        serde_json::from_str(&fs::read_to_string(home.join(".openclaw/openclaw.json")).unwrap())
            .unwrap();
    assert_eq!(
        oc_cfg_on["plugins"]["entries"]["hyphae"]["hooks"]["allowPromptModification"],
        true
    );
    assert_eq!(
        oc_cfg_on["plugins"]["entries"]["hyphae"]["hooks"]["allowConversationAccess"],
        true
    );
    assert_eq!(
        oc_cfg_on["plugins"]["entries"]["hyphae"]["config"]["deliveryMode"],
        "inbox"
    );
    assert_eq!(
        oc_cfg_on["plugins"]["entries"]["hyphae"]["config"]["promptInjection"],
        true
    );
    let node_cfg: Value =
        serde_json::from_str(&fs::read_to_string(state_dir.join("node.json")).unwrap()).unwrap();
    assert_eq!(node_cfg["openclaw"]["deliveryMode"], "inbox");

    // 4. Re-running `hyp setup --harness openclaw` WITHOUT OpenClaw flags preserves prior choices!
    let out_rerun = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "openclaw",
            "--bin",
            fake_bin,
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out_rerun.status.code(), Some(0));
    let oc_cfg_rerun: Value =
        serde_json::from_str(&fs::read_to_string(home.join(".openclaw/openclaw.json")).unwrap())
            .unwrap();
    assert_eq!(
        oc_cfg_rerun["plugins"]["entries"]["hyphae"]["config"]["deliveryMode"],
        "inbox"
    );
    assert_eq!(
        oc_cfg_rerun["plugins"]["entries"]["hyphae"]["config"]["promptInjection"],
        true
    );
}
