//! End-to-end tests for the v0.6.0 Claude Code plugin bundle (`plugins/claude-code/`)
//! and non-destructive Claude Code / Antigravity CLI `statusLine` setup, chaining,
//! restoration, and `hyp doctor` diagnostics.
//!
//! Strict isolation invariant: every test uses ephemeral `tempfile::TempDir`, isolated
//! `HOME` / `--home` / `--state-dir`, and `HYPHAE_SECRET_BACKEND=file` — zero live user
//! config or OS Keychain mutations!

mod common;

use common::{isolated_cmd, parse_json_stdout};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn claude_plugin_dir() -> PathBuf {
    repo_root().join("plugins").join("claude-code")
}

// ============================================================================
// 1. Claude Code Plugin Bundle Schema, Security Invariants & `claude plugin validate`
// ============================================================================

#[test]
fn claude_code_plugin_bundle_conforms_to_schema_and_security_invariants() {
    let plugin_dir = claude_plugin_dir();

    // 1. `.claude-plugin/plugin.json`
    let manifest_raw = fs::read_to_string(plugin_dir.join(".claude-plugin/plugin.json"))
        .expect("read plugin.json");
    let manifest: Value = serde_json::from_str(&manifest_raw).expect("valid plugin.json");
    assert_eq!(manifest["name"], "hyphae");
    assert_eq!(manifest["version"], "0.6.0");
    assert_eq!(manifest["license"], "MIT");
    assert!(
        manifest["description"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "description must be non-empty"
    );
    assert!(manifest["author"].is_object() || manifest["author"].is_string());
    assert_eq!(manifest["repository"], "https://github.com/hyphae-to/hyp");

    // 2. `.mcp.json`
    let mcp_raw = fs::read_to_string(plugin_dir.join(".mcp.json")).expect("read .mcp.json");
    let mcp: Value = serde_json::from_str(&mcp_raw).expect("valid .mcp.json");
    assert_eq!(mcp["mcpServers"]["hyphae"]["command"], "hyp");
    assert_eq!(
        mcp["mcpServers"]["hyphae"]["args"],
        json!(["mcp", "--backend", "claude"])
    );

    // 3. `hooks/hooks.json`
    let hooks_raw =
        fs::read_to_string(plugin_dir.join("hooks/hooks.json")).expect("read hooks/hooks.json");
    let hooks_doc: Value = serde_json::from_str(&hooks_raw).expect("valid hooks/hooks.json");
    let hooks = hooks_doc["hooks"]
        .as_object()
        .expect("hooks.json must contain top-level hooks object");
    for (event, expected_subcmd) in [
        ("SessionStart", "hyp hook claude session-start"),
        ("PreToolUse", "hyp hook claude pre-tool-use"),
        ("PostToolUse", "hyp hook claude post-tool-use"),
        ("Stop", "hyp hook claude stop"),
    ] {
        let groups = hooks
            .get(event)
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("missing hook event {event}"));
        assert!(
            groups.iter().any(|g| {
                g["hooks"].as_array().is_some_and(|arr| {
                    arr.iter()
                        .any(|h| h["type"] == "command" && h["command"] == expected_subcmd)
                })
            }),
            "hook event {event} must invoke '{expected_subcmd}': {hooks_doc}"
        );
    }

    // 4. All 4 slash commands + README + SKILL.md
    let expected_commands = [
        ("hyphae.md", "hyp inspect --json", "!hyp ui"),
        ("hyphae-subs.md", "hyp session unsubscribe", "hyp session rule"),
        ("hyphae-focus.md", "hyp session focus", "focusMode"),
        ("hyphae-mute.md", "hyp session mute", "hyp session unmute"),
    ];
    for (file, needle_a, needle_b) in expected_commands {
        let path = plugin_dir.join("commands").join(file);
        let content = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("missing command {}: {e}", path.display()));
        assert!(
            content.starts_with("---\n"),
            "{file} must start with YAML frontmatter"
        );
        assert!(
            content.contains("description:"),
            "{file} frontmatter must define description"
        );
        assert!(
            content.contains(needle_a) && content.contains(needle_b),
            "{file} must reference '{needle_a}' and '{needle_b}'"
        );
        let lower = content.to_ascii_lowercase();
        assert!(
            lower.contains("untrusted"),
            "{file} must frame mesh metadata as untrusted data"
        );
        // Security invariants: never pass secrets/tokens via CLI flags!
        assert!(
            !content.contains("--value"),
            "{file} must never reference --value"
        );
        assert!(
            !content.contains("hp2p1_")
                && !content.contains("am2_")
                && !content.contains("t3mp1_"),
            "{file} must never embed raw pairing token prefixes"
        );
    }

    let readme =
        fs::read_to_string(plugin_dir.join("README.md")).expect("read plugins/claude-code/README.md");
    assert!(readme.contains("hyp setup --harness claude --statusline"));
    assert!(readme.contains("hyp setup --harness claude --restore-statusline"));
    assert!(readme.contains("!hyp ui"));
    assert!(readme.contains("--chain-file"));

    let skill = fs::read_to_string(plugin_dir.join("skills/hyphae/SKILL.md"))
        .expect("read plugin SKILL.md");
    assert!(skill.starts_with("---\nname: hyphae\n"));
    assert!(skill.to_ascii_lowercase().contains("untrusted"));

    // 5. Run `claude plugin validate --strict` if `claude` binary is present on PATH.
    if let Ok(output) = Command::new("claude")
        .args(["plugin", "validate", "--strict", "--json"])
        .arg(&plugin_dir)
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "claude plugin validate --strict failed (code={:?}):\nstdout={stdout}\nstderr={stderr}",
            output.status.code()
        );
        let report: Value = serde_json::from_str(&stdout)
            .unwrap_or_else(|e| panic!("invalid JSON from claude plugin validate ({e}): {stdout}"));
        assert_eq!(report["success"], true);
        let cmds = report["provides"]["commands"]
            .as_array()
            .expect("provides.commands array");
        for expected in [
            "hyphae:hyphae",
            "hyphae:hyphae-subs",
            "hyphae:hyphae-focus",
            "hyphae:hyphae-mute",
        ] {
            assert!(
                cmds.iter().any(|c| c.as_str() == Some(expected)),
                "claude plugin validate missing command '{expected}' in {cmds:?}"
            );
        }
    }
}

// ============================================================================
// 2. Claude Code `--statusline`: Fresh Install, Idempotency, Custom Chaining & Restore
// ============================================================================

#[test]
fn claude_statusline_fresh_idempotent_and_slash_commands() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(home.join(".claude")).unwrap();
    fs::write(
        home.join(".claude/settings.json"),
        serde_json::to_string_pretty(&json!({
            "theme": "dark",
            "permissions": { "allow": ["Read"] }
        }))
        .unwrap(),
    )
    .unwrap();

    let fake_bin = "/opt/hyphae/bin/hyp";
    let fake_sock = tmp.path().join("connector.sock");

    // Dry-run must NOT mutate settings.json or write slash commands.
    let dry = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "claude",
            "--statusline",
            "--bin",
            fake_bin,
            "--socket",
            fake_sock.to_str().unwrap(),
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--dry-run",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(dry.status.code(), Some(0));
    let before_settings: Value =
        serde_json::from_str(&fs::read_to_string(home.join(".claude/settings.json")).unwrap())
            .unwrap();
    assert!(before_settings.get("statusLine").is_none());
    assert!(!home.join(".claude/commands").exists());

    // First real run: writes statusLine with refreshInterval: 5 and installs 4 slash commands.
    let run1 = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "claude",
            "--statusline",
            "--bin",
            fake_bin,
            "--socket",
            fake_sock.to_str().unwrap(),
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(run1.status.code(), Some(0));
    let run1_json = parse_json_stdout(&run1);
    assert_eq!(run1_json["ok"], true);

    let settings_text_1 = fs::read_to_string(home.join(".claude/settings.json")).unwrap();
    let settings_1: Value = serde_json::from_str(&settings_text_1).unwrap();
    assert_eq!(settings_1["theme"], "dark");
    assert_eq!(settings_1["permissions"]["allow"], json!(["Read"]));
    assert_eq!(settings_1["statusLine"]["type"], "command");
    assert_eq!(settings_1["statusLine"]["refreshInterval"], 5);
    let expected_cmd = format!(
        "{fake_bin} statusline --harness claude --socket {}",
        fake_sock.display()
    );
    assert_eq!(settings_1["statusLine"]["command"], expected_cmd);
    assert!(
        !state_dir.join("claude-statusline-chain.json").exists(),
        "no chain file should be created when no pre-existing statusLine existed"
    );

    // All 4 slash commands installed under ~/.claude/commands/
    for file in [
        "hyphae.md",
        "hyphae-subs.md",
        "hyphae-focus.md",
        "hyphae-mute.md",
    ] {
        let installed = fs::read_to_string(home.join(".claude/commands").join(file))
            .unwrap_or_else(|e| panic!("missing ~/.claude/commands/{file}: {e}"));
        let canonical = fs::read_to_string(claude_plugin_dir().join("commands").join(file))
            .unwrap();
        assert_eq!(installed, canonical);
    }

    // Second run: strictly idempotent (byte-for-byte identical, no self-chaining!).
    let run2 = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "claude",
            "--statusline",
            "--bin",
            fake_bin,
            "--socket",
            fake_sock.to_str().unwrap(),
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(run2.status.code(), Some(0));
    let settings_text_2 = fs::read_to_string(home.join(".claude/settings.json")).unwrap();
    assert_eq!(settings_text_1, settings_text_2);
    assert!(!state_dir.join("claude-statusline-chain.json").exists());

    // Restore when unchained removes statusLine while keeping all other settings.
    let restore = isolated_cmd(&home)
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
    let restored: Value =
        serde_json::from_str(&fs::read_to_string(home.join(".claude/settings.json")).unwrap())
            .unwrap();
    assert!(restored.get("statusLine").is_none());
    assert_eq!(restored["theme"], "dark");
    assert!(restored["hooks"].is_object());
}

#[test]
fn claude_statusline_chains_existing_custom_bar_and_restores_verbatim() {
    let tmp = tempfile::tempdir().unwrap();
    // Include a space in state_dir path to verify POSIX quoting/unquoting round-trip!
    let home = tmp.path().join("home");
    let state_dir = tmp.path().join("hyphae state");
    fs::create_dir_all(home.join(".claude")).unwrap();

    let original_bar = json!({
        "type": "command",
        "command": "my-custom-bar --git --cost",
        "padding": 1
    });
    fs::write(
        home.join(".claude/settings.json"),
        serde_json::to_string_pretty(&json!({
            "theme": "solarized",
            "statusLine": original_bar
        }))
        .unwrap(),
    )
    .unwrap();

    let fake_bin = "/opt/hyphae/bin/hyp";
    let chain_file = state_dir.join("claude-statusline-chain.json");

    // 1. Setup with --statusline: preserves original in 0600 chain file and wraps via --chain-file.
    let run1 = isolated_cmd(&home)
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
    assert_eq!(run1.status.code(), Some(0));
    let run1_json = parse_json_stdout(&run1);
    assert_eq!(run1_json["ok"], true);
    let notes = run1_json["data"]["harnesses"][0]["notes"]
        .as_array()
        .unwrap();
    assert!(
        notes
            .iter()
            .any(|n| n.as_str().is_some_and(|s| s.contains("--chain-file"))),
        "setup notes should mention --chain-file chaining: {notes:?}"
    );

    assert!(chain_file.exists(), "chain file must be created");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&chain_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "chain file must have 0600 permissions");
    }
    let saved_chain: Value =
        serde_json::from_str(&fs::read_to_string(&chain_file).unwrap()).unwrap();
    assert_eq!(saved_chain, original_bar);

    let settings_1_text = fs::read_to_string(home.join(".claude/settings.json")).unwrap();
    let settings_1: Value = serde_json::from_str(&settings_1_text).unwrap();
    assert_eq!(settings_1["theme"], "solarized");
    assert_eq!(settings_1["statusLine"]["type"], "command");
    assert_eq!(settings_1["statusLine"]["refreshInterval"], 5);
    let cmd_str = settings_1["statusLine"]["command"].as_str().unwrap();
    assert!(cmd_str.contains("statusline --harness claude"));
    assert!(cmd_str.contains("--chain-file"));
    assert!(cmd_str.contains("claude-statusline-chain.json"));

    // 2. Re-run --statusline: strictly idempotent, NEVER double-chains or overwrites chain file!
    let run2 = isolated_cmd(&home)
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
    assert_eq!(run2.status.code(), Some(0));
    assert_eq!(
        fs::read_to_string(home.join(".claude/settings.json")).unwrap(),
        settings_1_text
    );
    let saved_chain_2: Value =
        serde_json::from_str(&fs::read_to_string(&chain_file).unwrap()).unwrap();
    assert_eq!(
        saved_chain_2, original_bar,
        "2nd run must never clobber claude-statusline-chain.json"
    );

    // 3. Doctor reports configured=true, chained=true, chainFileExists=true, status=ok.
    let doc_ok = isolated_cmd(&home)
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
    assert_eq!(doc_ok.status.code(), Some(0));
    let doc_ok_json = parse_json_stdout(&doc_ok);
    let claude_sl = doc_ok_json["data"]["statusLines"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["harness"] == "claude")
        .expect("claude statusLine diagnostic");
    assert_eq!(claude_sl["configured"], true);
    assert_eq!(claude_sl["chained"], true);
    assert_eq!(claude_sl["chainFileExists"], true);
    let claude_check = doc_ok_json["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "statusline:claude")
        .expect("statusline:claude check");
    assert_eq!(claude_check["status"], "ok");

    // 4. --restore-statusline restores original_bar identically and deletes chain file!
    let restore = isolated_cmd(&home)
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
    let restored: Value =
        serde_json::from_str(&fs::read_to_string(home.join(".claude/settings.json")).unwrap())
            .unwrap();
    assert_eq!(restored["statusLine"], original_bar);
    assert_eq!(restored["theme"], "solarized");
    assert!(!chain_file.exists(), "chain file must be deleted on restore");

    // 5. Re-running --restore-statusline when user has non-Hyphae statusLine leaves it untouched!
    let restore_again = isolated_cmd(&home)
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
    assert_eq!(restore_again.status.code(), Some(0));
    let after_second_restore: Value =
        serde_json::from_str(&fs::read_to_string(home.join(".claude/settings.json")).unwrap())
            .unwrap();
    assert_eq!(after_second_restore["statusLine"], original_bar);
}

// ============================================================================
// 3. Antigravity CLI `--statusline` (`stack_with_default: true`), Chaining & Restore
// ============================================================================

#[test]
fn antigravity_statusline_stacks_with_default_preserves_settings_and_restores() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let state_dir = tmp.path().join("state");
    let agy_dir = home.join(".gemini").join("antigravity-cli");
    fs::create_dir_all(&agy_dir).unwrap();
    fs::write(
        agy_dir.join("settings.json"),
        serde_json::to_string_pretty(&json!({
            "theme": "midnight",
            "editor": { "tabSize": 2 }
        }))
        .unwrap(),
    )
    .unwrap();

    let fake_bin = "/opt/hyphae/bin/hyp";

    // 1. Fresh Antigravity statusLine install
    let run1 = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "antigravity",
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
    assert_eq!(run1.status.code(), Some(0));
    let agy_settings_1_text = fs::read_to_string(agy_dir.join("settings.json")).unwrap();
    let agy_settings_1: Value = serde_json::from_str(&agy_settings_1_text).unwrap();
    assert_eq!(agy_settings_1["theme"], "midnight");
    assert_eq!(agy_settings_1["editor"]["tabSize"], 2);
    assert_eq!(
        agy_settings_1["statusLine"]["command"],
        format!("{fake_bin} statusline --harness antigravity")
    );
    assert_eq!(agy_settings_1["statusLine"]["stack_with_default"], true);

    // 2. Idempotent 2nd run
    let run2 = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "antigravity",
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
    assert_eq!(run2.status.code(), Some(0));
    assert_eq!(
        fs::read_to_string(agy_dir.join("settings.json")).unwrap(),
        agy_settings_1_text
    );

    // 3. Restore removes statusLine while keeping existing keys
    let restore1 = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "antigravity",
            "--restore-statusline",
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(restore1.status.code(), Some(0));
    let restored1: Value =
        serde_json::from_str(&fs::read_to_string(agy_dir.join("settings.json")).unwrap()).unwrap();
    assert!(restored1.get("statusLine").is_none());
    assert_eq!(restored1["theme"], "midnight");
    assert_eq!(restored1["editor"]["tabSize"], 2);

    // 4. Pre-existing custom Antigravity statusLine chains into 0600 file and restores verbatim!
    let custom_agy_bar = json!({
        "command": "custom-agy-status",
        "stack_with_default": false
    });
    fs::write(
        agy_dir.join("settings.json"),
        serde_json::to_string_pretty(&json!({
            "theme": "midnight",
            "statusLine": custom_agy_bar
        }))
        .unwrap(),
    )
    .unwrap();

    let chain_run = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "antigravity",
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
    assert_eq!(chain_run.status.code(), Some(0));

    let chain_file = state_dir.join("antigravity-statusline-chain.json");
    assert!(chain_file.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&chain_file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }
    let agy_chained: Value =
        serde_json::from_str(&fs::read_to_string(agy_dir.join("settings.json")).unwrap()).unwrap();
    assert_eq!(agy_chained["statusLine"]["stack_with_default"], true);
    assert!(
        agy_chained["statusLine"]["command"]
            .as_str()
            .unwrap()
            .contains("--chain-file")
    );

    let restore2 = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "antigravity",
            "--restore-statusline",
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(restore2.status.code(), Some(0));
    let restored2: Value =
        serde_json::from_str(&fs::read_to_string(agy_dir.join("settings.json")).unwrap()).unwrap();
    assert_eq!(restored2["statusLine"], custom_agy_bar);
    assert_eq!(restored2["theme"], "midnight");
    assert!(!chain_file.exists());
}

// ============================================================================
// 4. `hyp doctor` Missing `--chain-file` Warning & Conflicting Flag Fail-Closed
// ============================================================================

#[test]
fn doctor_warns_on_missing_chain_file_and_setup_rejects_conflicting_flags() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(home.join(".claude")).unwrap();
    fs::create_dir_all(home.join(".gemini/antigravity-cli")).unwrap();

    // Mutually exclusive --statusline and --restore-statusline must fail closed with exit code 2.
    let conflict = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "claude",
            "--statusline",
            "--restore-statusline",
            "--home",
            home.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(conflict.status.code(), Some(2));
    let conflict_json = parse_json_stdout(&conflict);
    assert_eq!(conflict_json["ok"], false);
    assert_eq!(conflict_json["error"]["code"], "CONFLICTING_FLAGS");

    // Seed custom statusLines for both Claude and Antigravity, chain them, then delete Claude's chain file.
    fs::write(
        home.join(".claude/settings.json"),
        r#"{"statusLine":{"type":"command","command":"my-bar"}}"#,
    )
    .unwrap();
    fs::write(
        home.join(".gemini/antigravity-cli/settings.json"),
        r#"{"statusLine":{"command":"my-agy-bar"}}"#,
    )
    .unwrap();

    let setup = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "claude,antigravity",
            "--statusline",
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
    assert_eq!(setup.status.code(), Some(0));

    // Delete Claude's chain file to simulate a missing --chain-file target!
    let claude_chain = state_dir.join("claude-statusline-chain.json");
    assert!(claude_chain.exists());
    fs::remove_file(&claude_chain).unwrap();

    // Doctor must still exit 0 (warning, NOT fatal fail), report claude chainFileExists=false,
    // emit a `warn` check for `statusline:claude`, and `ok` for `statusline:antigravity`.
    let doc = isolated_cmd(&home)
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
    assert_eq!(doc_json["ok"], true);

    let status_lines = doc_json["data"]["statusLines"].as_array().unwrap();
    let claude_sl = status_lines
        .iter()
        .find(|s| s["harness"] == "claude")
        .unwrap();
    assert_eq!(claude_sl["configured"], true);
    assert_eq!(claude_sl["chained"], true);
    assert_eq!(claude_sl["chainFileExists"], false);

    let agy_sl = status_lines
        .iter()
        .find(|s| s["harness"] == "antigravity")
        .unwrap();
    assert_eq!(agy_sl["configured"], true);
    assert_eq!(agy_sl["chained"], true);
    assert_eq!(agy_sl["chainFileExists"], true);

    let checks = doc_json["data"]["checks"].as_array().unwrap();
    let claude_check = checks
        .iter()
        .find(|c| c["name"] == "statusline:claude")
        .expect("statusline:claude check");
    assert_eq!(claude_check["status"], "warn");
    assert!(
        claude_check["detail"]
            .as_str()
            .unwrap()
            .contains("missing")
    );
    assert!(
        claude_check["fix"]
            .as_str()
            .unwrap()
            .contains("--restore-statusline")
    );

    let agy_check = checks
        .iter()
        .find(|c| c["name"] == "statusline:antigravity")
        .expect("statusline:antigravity check");
    assert_eq!(agy_check["status"], "ok");

    // Restoring Claude when chain file is missing removes the broken Hyphae wrapper cleanly.
    let cleanup = isolated_cmd(&home)
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
    assert_eq!(cleanup.status.code(), Some(0));
    let claude_after: Value =
        serde_json::from_str(&fs::read_to_string(home.join(".claude/settings.json")).unwrap())
            .unwrap();
    assert!(claude_after.get("statusLine").is_none());
}

// ============================================================================
// 6. Native Herdr Mod (`hyp setup --harness herdr --mod`) & Doctor Detection
// ============================================================================

#[test]
fn herdr_mod_setup_respects_symlinks_supports_clone_layout_and_doctor_detection() {
    let tmp = tempfile::TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let state_dir = tmp.path().join("state");
    let herdr_app = home.join(".config").join("herdr-app");
    let layouts_dir = herdr_app.join("layouts");
    fs::create_dir_all(&layouts_dir).unwrap();
    fs::create_dir_all(&state_dir).unwrap();

    // Seed shipped `main.json` so `--clone-layout` works cleanly on every OS.
    let shipped_main = json!({
        "pane": {
            "header": {
                "content": { "mod": "pane" }
            }
        },
        "panel": {
            "tabs": ["files", "changes"]
        }
    });
    fs::write(
        layouts_dir.join("main.json"),
        serde_json::to_string_pretty(&shipped_main).unwrap(),
    )
    .unwrap();

    // On Unix, also exercise strict symlink refusal on a git-backed custom layout.
    #[cfg(unix)]
    {
        let external_repo = tmp.path().join("herdr-custom-ui");
        fs::create_dir_all(&external_repo).unwrap();
        let target_layout = external_repo.join("herdr-folders.json");
        let original_custom = serde_json::to_string_pretty(&json!({
            "pane": { "header": { "content": { "mod": "folder-pane" } } },
            "panel": { "tabs": ["files"] }
        }))
        .unwrap();
        fs::write(&target_layout, &original_custom).unwrap();
        std::os::unix::fs::symlink(&target_layout, layouts_dir.join("herdr-folders.json"))
            .unwrap();
        fs::write(
            herdr_app.join("shared.json"),
            serde_json::to_string_pretty(&json!({ "layout": "herdr-folders" })).unwrap(),
        )
        .unwrap();

        let sym_out = isolated_cmd(&home)
            .args([
                "setup",
                "--harness",
                "herdr",
                "--mod",
                "--home",
                home.to_str().unwrap(),
                "--state-dir",
                state_dir.to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(
            sym_out.status.code(),
            Some(0),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&sym_out.stdout),
            String::from_utf8_lossy(&sym_out.stderr)
        );
        let sym_json = parse_json_stdout(&sym_out);
        assert_eq!(sym_json["ok"], true);
        assert_eq!(sym_json["data"]["herdrMod"]["layoutAction"], "skipped_symlink");
        assert!(
            !sym_json["warnings"].as_array().unwrap().is_empty(),
            "symlink refusal should emit an actionable warning"
        );
        // External symlink target MUST remain byte-identical!
        assert_eq!(fs::read_to_string(&target_layout).unwrap(), original_custom);
        assert!(herdr_app.join("mods/hyphae-pane/mod.json").is_file());
        assert!(herdr_app.join("mods/hyphae-panel/mod.json").is_file());
    }

    // Exercise `--clone-layout herdr-hyphae` (cross-platform: Linux, macOS, Windows).
    fs::write(
        herdr_app.join("shared.json"),
        serde_json::to_string_pretty(&json!({ "layout": "main" })).unwrap(),
    )
    .unwrap();
    let clone_out = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "herdr",
            "--mod",
            "--clone-layout",
            "herdr-hyphae",
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        clone_out.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&clone_out.stdout),
        String::from_utf8_lossy(&clone_out.stderr)
    );
    let clone_json = parse_json_stdout(&clone_out);
    assert_eq!(clone_json["ok"], true);
    assert_eq!(clone_json["data"]["herdrMod"]["layoutAction"], "cloned");
    assert!(layouts_dir.join("herdr-hyphae.json").is_file());
    let shared_after: Value =
        serde_json::from_str(&fs::read_to_string(herdr_app.join("shared.json")).unwrap()).unwrap();
    assert_eq!(shared_after["layout"], "herdr-hyphae");
    let keys_after: Value =
        serde_json::from_str(&fs::read_to_string(herdr_app.join("keys.json")).unwrap()).unwrap();
    assert_eq!(keys_after["global"]["cmd-shift-h"], "mod.open:hyphae-panel");

    // `hyp doctor --json` should detect and report `herdrMod.installed == true`.
    let doc_out = isolated_cmd(&home)
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
    let doc_json = parse_json_stdout(&doc_out);
    assert_eq!(doc_json["data"]["herdrMod"]["detected"], true);
    assert_eq!(doc_json["data"]["herdrMod"]["installed"], true);
    let checks = doc_json["data"]["checks"].as_array().unwrap();
    assert!(
        checks
            .iter()
            .any(|c| c["name"] == "herdr:mod" && c["status"] == "ok"),
        "expected ok herdr:mod check in {checks:?}"
    );
}
