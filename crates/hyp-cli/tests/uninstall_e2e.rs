//! End-to-end tests for `scripts/uninstall.sh` and the backwards-compatible
//! `scripts/reset-local.sh` wrapper.
//!
//! Strict isolation invariant: every test executes inside an ephemeral
//! `tempfile::TempDir` with isolated `HOME`, `XDG_CONFIG_HOME`, `XDG_STATE_HOME`,
//! `HYPHAE_INSTALL_DIR`, `HERDR_APP_HOME`, and `HYPHAE_SECRET_BACKEND=file` — zero
//! mutations to live `$HOME`, running daemons, LaunchAgents, or OS Keychain!

#[path = "../../test-support/node_runtime.rs"]
mod node_runtime;

mod common;

use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn uninstall_script_and_raw_mirror_are_byte_identical_and_non_empty() {
    let root = repo_root();
    let canonical = fs::read(root.join("scripts/uninstall.sh")).expect("read scripts/uninstall.sh");

    let raw_mirror = fs::read(root.join("uninstall.sh")).expect("read uninstall.sh");

    assert_eq!(canonical, raw_mirror, "root uninstall.sh must match");
    assert!(
        !canonical.is_empty(),
        "scripts/uninstall.sh must not be empty"
    );
    assert!(
        canonical.starts_with(b"#!/usr/bin/env bash\n")
            || canonical.starts_with(b"#!/usr/bin/env bash\r\n"),
        "scripts/uninstall.sh must start with #!/usr/bin/env bash"
    );
}

#[cfg(unix)]
mod unix_e2e {
    use super::common::isolated_cmd;
    use super::repo_root;
    use serde_json::{Value, json};
    use std::fs;
    use std::io::Write as _;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Output, Stdio};
    use tempfile::TempDir;

    fn write_file(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dirs");
        }
        fs::write(path, content).expect("write fixture file");
    }

    fn write_json(path: &Path, val: &Value) {
        let mut rendered = serde_json::to_string_pretty(val).expect("serialize JSON");
        rendered.push('\n');
        write_file(path, &rendered);
    }

    fn read_json(path: &Path) -> Value {
        let raw = fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("failed reading {}: {e}", path.display()));
        serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("invalid JSON in {}: {e}\n{raw}", path.display()))
    }

    fn run_script(script: &Path, home: &Path, args: &[&str]) -> Output {
        run_script_with_claude_dir(script, home, None, args)
    }

    fn run_script_with_claude_dir(
        script: &Path,
        home: &Path,
        claude_config_dir: Option<&Path>,
        args: &[&str],
    ) -> Output {
        let mut cmd = Command::new("/bin/bash");
        cmd.arg(script)
            .args(args)
            .env("HOME", home)
            .env("XDG_CONFIG_HOME", home.join(".config"))
            .env("XDG_STATE_HOME", home.join(".local/state"))
            .env("HYPHAE_INSTALL_DIR", home.join(".local/bin"))
            .env("HERDR_APP_HOME", home.join(".config/herdr-app"))
            .env("HYPHAE_SECRET_BACKEND", "file")
            .env("CI", "1")
            .stdin(Stdio::null());
        match claude_config_dir {
            Some(dir) => {
                cmd.env("CLAUDE_CONFIG_DIR", dir);
            }
            None => {
                cmd.env_remove("CLAUDE_CONFIG_DIR");
            }
        }
        cmd.output()
            .unwrap_or_else(|e| panic!("failed executing {}: {e}", script.display()))
    }

    struct PopulatedFixture {
        home: TempDir,
        external_layout_dir: TempDir,
        external_layout_target: PathBuf,
        external_layout_original: String,
        claude_original_statusline: Value,
        agy_original_statusline: Value,
    }

    fn build_populated_home() -> PopulatedFixture {
        let home = TempDir::new().expect("temp home");
        let h = home.path();
        let config_hyphae = h.join(".config/hyphae");

        // Original user custom statusLines backed up in ~/.config/hyphae/*-statusline-chain.json
        let claude_original_statusline = json!({
            "type": "command",
            "command": "/usr/local/bin/my-claude-bar --git --branch",
            "refreshInterval": 10
        });
        let agy_original_statusline = json!({
            "command": "/usr/local/bin/my-agy-bar --compact",
            "stack_with_default": false
        });

        let claude_chain = config_hyphae.join("claude-statusline-chain.json");
        let agy_chain = config_hyphae.join("antigravity-statusline-chain.json");
        write_json(&claude_chain, &claude_original_statusline);
        write_json(&agy_chain, &agy_original_statusline);
        write_json(
            &config_hyphae.join("node.json"),
            &json!({ "v": 2, "nodeId": "alice@testbox" }),
        );
        write_file(&h.join(".local/state/hyphae/daemon.log"), "ok\n");
        write_file(&h.join(".local/share/hyphae/cache.txt"), "cached\n");
        write_file(&h.join(".config/agents-mesh/legacy.json"), "{}\n");

        // OS service definition file inside isolated HOME (never touches live host services)
        if cfg!(target_os = "macos") {
            write_file(
                &h.join("Library/LaunchAgents/to.hyphae.daemon.plist"),
                "<plist></plist>\n",
            );
        } else {
            write_file(
                &h.join(".config/systemd/user/hyphae-daemon.service"),
                "[Unit]\nDescription=Hyphae\n",
            );
        }

        // Claude Code settings.json: custom keys + custom hooks + Hyphae hooks + chained statusLine
        let claude_settings = h.join(".claude/settings.json");
        write_json(
            &claude_settings,
            &json!({
                "theme": "dark",
                "permissions": { "allow": ["Bash(git status)"] },
                "statusLine": {
                    "type": "command",
                    "command": format!(
                        "{} statusline --harness claude --chain-file {}",
                        h.join(".local/bin/hyp").display(),
                        claude_chain.display()
                    ),
                    "refreshInterval": 5
                },
                "hooks": {
                    "SessionStart": [
                        {
                            "hooks": [{
                                "type": "command",
                                "command": format!("{} hook claude session-start", h.join(".local/bin/hyp").display()),
                                "timeout": 10
                            }]
                        }
                    ],
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{
                                "type": "command",
                                "command": "/usr/local/bin/my-audit-hook"
                            }]
                        },
                        {
                            "matcher": "mcp__hyphae__.*",
                            "hooks": [{
                                "type": "command",
                                "command": format!("{} hook claude pre-tool-use", h.join(".local/bin/hyp").display()),
                                "timeout": 10
                            }]
                        }
                    ],
                    "PostToolUse": [
                        {
                            "matcher": ".*",
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "/usr/local/bin/my-post-hook"
                                },
                                {
                                    "type": "command",
                                    "command": format!("{} hook claude post-tool-use", h.join(".local/bin/hyp").display()),
                                    "timeout": 10
                                }
                            ]
                        }
                    ],
                    "Stop": [
                        {
                            "hooks": [{
                                "type": "command",
                                "command": format!("{} hook claude stop", h.join(".local/bin/hyp").display()),
                                "timeout": 10
                            }]
                        }
                    ]
                }
            }),
        );
        fs::set_permissions(&claude_settings, fs::Permissions::from_mode(0o600))
            .expect("chmod claude settings");

        // ~/.claude.json + Claude Desktop config
        write_json(
            &h.join(".claude.json"),
            &json!({
                "numStartups": 42,
                "mcpServers": {
                    "github": { "command": "npx", "args": ["@modelcontextprotocol/server-github"] },
                    "hyphae": { "command": h.join(".local/bin/hyp").display().to_string(), "args": ["mcp"] }
                }
            }),
        );
        let desktop_cfg = if cfg!(target_os = "macos") {
            h.join("Library/Application Support/Claude/claude_desktop_config.json")
        } else {
            h.join(".config/Claude/claude_desktop_config.json")
        };
        write_json(
            &desktop_cfg,
            &json!({
                "mcpServers": {
                    "filesystem": { "command": "mcp-fs", "args": [] },
                    "hyphae": { "command": "hyp", "args": ["mcp", "--backend", "claude", "--ephemeral"] }
                }
            }),
        );

        // Claude slash commands (4 Hyphae + 1 custom user command)
        for cmd in [
            "hyphae.md",
            "hyphae-subs.md",
            "hyphae-focus.md",
            "hyphae-mute.md",
        ] {
            write_file(&h.join(".claude/commands").join(cmd), "# hyphae cmd\n");
        }
        write_file(
            &h.join(".claude/commands/my-cmd.md"),
            "# user custom command\n",
        );

        // Skills across all 10 harness roots (hyphae + hyphae-setup + hyphae-schedule + custom my-skill)
        for root in [
            ".claude/skills",
            ".codex/skills",
            ".agents/skills",
            ".gemini/config/skills",
            ".gemini/skills",
            ".config/opencode/skills",
            ".cursor/skills",
            ".openclaw/skills",
            ".config/herdr/skills",
            ".t3/skills",
        ] {
            write_file(&h.join(root).join("hyphae/SKILL.md"), "# hyphae\n");
            write_file(
                &h.join(root).join("hyphae-setup/SKILL.md"),
                "# hyphae-setup\n",
            );
            write_file(
                &h.join(root).join("hyphae-schedule/SKILL.md"),
                "# hyphae-schedule\n",
            );
        }
        write_file(
            &h.join(".claude/skills/my-skill/SKILL.md"),
            "# custom user skill\n",
        );

        // Antigravity CLI settings.json (chained statusLine + custom user keys) & plugin dir
        write_json(
            &h.join(".gemini/antigravity-cli/settings.json"),
            &json!({
                "model": "gemini-2.5-pro",
                "statusLine": {
                    "command": format!(
                        "{} statusline --harness antigravity --chain-file {}",
                        h.join(".local/bin/hyp").display(),
                        agy_chain.display()
                    ),
                    "stack_with_default": true
                }
            }),
        );
        write_file(&h.join(".gemini/config/plugins/hyphae/plugin.json"), "{}\n");
        write_file(&h.join(".gemini/config/plugins/hyphae/hooks.json"), "{}\n");

        // Gemini CLI settings.json (custom MCP + hyphae MCP + custom hook + hyphae hooks)
        write_json(
            &h.join(".gemini/settings.json"),
            &json!({
                "tools": { "enableHooks": true },
                "mcpServers": {
                    "custom-gemini": { "command": "my-gemini-mcp", "args": [] },
                    "hyphae": { "command": "hyp", "args": ["mcp"] }
                },
                "hooks": {
                    "BeforeTool": [
                        {
                            "matcher": ".*",
                            "hooks": [{
                                "name": "user-guard",
                                "type": "command",
                                "command": "/usr/local/bin/user-guard"
                            }]
                        },
                        {
                            "matcher": ".*hyp_.*",
                            "hooks": [{
                                "name": "hyphae-before-tool",
                                "type": "command",
                                "command": "hyp hook gemini pre-tool-use"
                            }]
                        }
                    ],
                    "AfterTool": [
                        {
                            "matcher": ".*",
                            "hooks": [{
                                "name": "hyphae-after-tool",
                                "type": "command",
                                "command": "hyp hook gemini post-tool-use"
                            }]
                        }
                    ]
                }
            }),
        );

        // Codex config.toml & hooks.json
        write_file(
            &h.join(".codex/config.toml"),
            r#"[model]
name = "o3"

[mcp_servers.other]
command = "other-mcp"
args = ["--stdio"]

# >>> hyphae >>>
[mcp_servers.hyphae]
command = "/tmp/hyp"
args = ["mcp"]
env_vars = ["CODEX_HOME", "HYPHAE_SOCKET"]
# <<< hyphae <<<

[features]
fast_mode = true
"#,
        );
        write_json(
            &h.join(".codex/hooks.json"),
            &json!({
                "hooks": {
                    "SessionStart": [
                        { "hooks": [{ "type": "command", "command": "/usr/local/bin/codex-custom" }] },
                        { "hooks": [{ "type": "command", "command": "hyp hook codex session-start" }] }
                    ],
                    "Stop": [
                        { "hooks": [{ "type": "command", "command": "hyp hook codex stop" }] }
                    ]
                }
            }),
        );

        // Cursor mcp.json & hooks.json
        write_json(
            &h.join(".cursor/mcp.json"),
            &json!({
                "mcpServers": {
                    "docs": { "command": "docs-mcp", "args": [] },
                    "hyphae": { "command": "hyp", "args": ["mcp"] }
                }
            }),
        );
        write_json(
            &h.join(".cursor/hooks.json"),
            &json!({
                "version": 1,
                "hooks": {
                    "beforeMCPExecution": [
                        { "command": "/usr/local/bin/cursor-user-hook", "timeout": 5 },
                        { "command": "hyp hook cursor pre-tool-use", "timeout": 10 }
                    ],
                    "stop": [
                        { "command": "hyp hook cursor stop", "timeout": 10 }
                    ]
                }
            }),
        );

        // OpenCode opencode.json & plugins/hyphae.ts
        write_json(
            &h.join(".config/opencode/opencode.json"),
            &json!({
                "$schema": "https://opencode.ai/config.json",
                "mcp": {
                    "user-tool": { "type": "local", "command": ["my-tool"], "enabled": true },
                    "hyphae": { "type": "local", "command": ["hyp", "mcp"], "enabled": true }
                }
            }),
        );
        write_file(
            &h.join(".config/opencode/plugins/hyphae.ts"),
            "export default {};\n",
        );

        // OpenClaw openclaw.json + official plugin directory
        write_json(
            &h.join(".openclaw/openclaw.json"),
            &json!({
                "profile": "default",
                "mcp": {
                    "servers": {
                        "weather": { "command": "weather-mcp", "args": [] },
                        "hyphae": { "command": "hyp", "args": ["mcp", "--backend", "openclaw", "--ephemeral"] }
                    }
                },
                "plugins": {
                    "allow": ["weather-ext", "hyphae"],
                    "entries": {
                        "weather-ext": { "enabled": true },
                        "hyphae": {
                            "enabled": true,
                            "hooks": {
                                "allowPromptModification": true,
                                "allowConversationAccess": true
                            },
                            "config": { "hypBin": "hyp", "deliveryMode": "gateway", "promptInjection": true }
                        }
                    }
                }
            }),
        );
        write_file(
            &h.join(".openclaw/extensions/hyphae/openclaw.plugin.json"),
            "{\"id\":\"hyphae\"}\n",
        );
        write_file(
            &h.join(".openclaw/extensions/hyphae/index.js"),
            "export default { id: 'hyphae' };\n",
        );

        // Herdr & T3 standalone adapter configs
        write_json(
            &h.join(".config/herdr/hyphae.json"),
            &json!({ "hyphae": {} }),
        );
        write_json(&h.join(".t3/hyphae.json"), &json!({ "hyphae": {} }));

        // Native Herdr app mods, keys.json, and symlinked custom layout
        let herdr_app = h.join(".config/herdr-app");
        write_file(&herdr_app.join("mods/hyphae-pane/mod.json"), "{}\n");
        write_file(&herdr_app.join("mods/hyphae-panel/mod.json"), "{}\n");
        write_file(&herdr_app.join("mods/user-custom-mod/mod.json"), "{}\n");
        write_json(
            &herdr_app.join("keys.json"),
            &json!({
                "global": {
                    "cmd-k": "palette.open",
                    "cmd-shift-h": "mod.open:hyphae-panel"
                }
            }),
        );

        let external_layout_dir = TempDir::new().expect("external layout dir");
        let external_layout_target = external_layout_dir.path().join("custom.json");
        let external_layout_original = "{\n  \"name\": \"custom\",\n  \"pane\": { \"header\": { \"content\": { \"mod\": \"hyphae-pane\" } } }\n}\n".to_string();
        write_file(&external_layout_target, &external_layout_original);
        fs::create_dir_all(herdr_app.join("layouts")).expect("create herdr layouts dir");
        symlink(
            &external_layout_target,
            herdr_app.join("layouts/custom.json"),
        )
        .expect("symlink custom layout");

        // Installed binaries
        let hyp_bin = h.join(".local/bin/hyp");
        write_file(&hyp_bin, "#!/bin/sh\necho hyp-fake\n");
        fs::set_permissions(&hyp_bin, fs::Permissions::from_mode(0o755)).expect("chmod hyp");
        write_file(&h.join(".local/bin/hyp.prev"), "#!/bin/sh\necho prev\n");

        PopulatedFixture {
            home,
            external_layout_dir,
            external_layout_target,
            external_layout_original,
            claude_original_statusline,
            agy_original_statusline,
        }
    }

    #[test]
    fn bash_and_sh_syntax_checks_pass_for_uninstall_and_reset_scripts() {
        let root = repo_root();
        for rel in [
            "scripts/uninstall.sh",
            "uninstall.sh",
            "scripts/reset-local.sh",
        ] {
            let path = root.join(rel);
            let bash_out = Command::new("/bin/bash")
                .args(["-n"])
                .arg(&path)
                .output()
                .expect("run /bin/bash -n");
            assert!(
                bash_out.status.success(),
                "/bin/bash -n failed on {rel}: {}",
                String::from_utf8_lossy(&bash_out.stderr)
            );

            let sh_out = Command::new("/bin/sh")
                .args(["-n"])
                .arg(&path)
                .output()
                .expect("run /bin/sh -n");
            assert!(
                sh_out.status.success(),
                "/bin/sh -n failed on {rel}: {}",
                String::from_utf8_lossy(&sh_out.stderr)
            );
        }
    }

    #[test]
    fn uninstall_dry_run_modifies_zero_files_and_prints_complete_plan() {
        let fx = build_populated_home();
        let h = fx.home.path();
        let script = repo_root().join("scripts/uninstall.sh");

        let claude_before = fs::read(h.join(".claude/settings.json")).unwrap();
        let codex_before = fs::read(h.join(".codex/config.toml")).unwrap();
        let keys_before = fs::read(h.join(".config/herdr-app/keys.json")).unwrap();

        let out = run_script(&script, h, &["--dry-run"]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(0),
            "dry-run failed: stdout={stdout}\nstderr={stderr}"
        );
        assert!(stdout.contains(
            "[dry-run] No files, processes, configs, or keychain entries were modified."
        ));
        assert!(stdout.contains("StatusLines to restore/remove"));
        assert!(stdout.contains("Shared harness configs to edit surgically"));
        assert!(stdout.contains("Herdr layout notes (will NOT be modified)"));

        // Every single file & binary must remain byte-identical!
        assert_eq!(
            fs::read(h.join(".claude/settings.json")).unwrap(),
            claude_before
        );
        assert_eq!(
            fs::read(h.join(".codex/config.toml")).unwrap(),
            codex_before
        );
        assert_eq!(
            fs::read(h.join(".config/herdr-app/keys.json")).unwrap(),
            keys_before
        );
        assert!(h.join(".config/hyphae/node.json").exists());
        assert!(h.join(".local/bin/hyp").exists());
        assert!(h.join(".config/herdr-app/mods/hyphae-pane").exists());
        assert_eq!(
            fs::read_to_string(&fx.external_layout_target).unwrap(),
            fx.external_layout_original
        );
        let _keep_alive = &fx.external_layout_dir;
    }

    #[test]
    fn uninstall_non_interactive_without_yes_exits_2_and_modifies_nothing() {
        let fx = build_populated_home();
        let h = fx.home.path();
        let script = repo_root().join("scripts/uninstall.sh");

        let out = run_script(&script, h, &[]);
        assert_eq!(
            out.status.code(),
            Some(2),
            "expected exit 2 on non-interactive stdin without --yes; stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(h.join(".config/hyphae/node.json").exists());
        assert!(h.join(".local/bin/hyp").exists());
    }

    #[test]
    fn full_uninstall_restores_statuslines_surgically_cleans_harnesses_and_preserves_user_data() {
        let fx = build_populated_home();
        let h = fx.home.path();
        let script = repo_root().join("scripts/uninstall.sh");

        let out = run_script(&script, h, &["--yes"]);
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            out.status.code(),
            Some(0),
            "full uninstall failed: stdout={stdout}\nstderr={stderr}"
        );
        assert!(stdout.contains("Hyphae uninstall complete!"));
        assert!(stdout.contains("custom.json"));

        // 0. Service plist / unit inside isolated HOME removed
        if cfg!(target_os = "macos") {
            assert!(
                !h.join("Library/LaunchAgents/to.hyphae.daemon.plist")
                    .exists()
            );
        } else {
            assert!(
                !h.join(".config/systemd/user/hyphae-daemon.service")
                    .exists()
            );
        }

        // 1. Both Claude & Antigravity statusLines restored VERBATIM!
        let claude_settings = read_json(&h.join(".claude/settings.json"));
        assert_eq!(claude_settings["statusLine"], fx.claude_original_statusline);
        assert_eq!(claude_settings["theme"], "dark");
        assert_eq!(
            claude_settings["permissions"]["allow"],
            json!(["Bash(git status)"])
        );
        let claude_mode = fs::metadata(h.join(".claude/settings.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            claude_mode, 0o600,
            "permissions on settings.json must be preserved"
        );

        // Hyphae hooks removed, custom user hooks preserved (including mixed PostToolUse matcher group!)
        assert!(claude_settings["hooks"].get("SessionStart").is_none());
        assert!(claude_settings["hooks"].get("Stop").is_none());
        let pre_groups = claude_settings["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre_groups.len(), 1);
        assert_eq!(
            pre_groups[0]["hooks"][0]["command"],
            "/usr/local/bin/my-audit-hook"
        );
        let post_groups = claude_settings["hooks"]["PostToolUse"].as_array().unwrap();
        assert_eq!(post_groups.len(), 1);
        assert_eq!(post_groups[0]["hooks"].as_array().unwrap().len(), 1);
        assert_eq!(
            post_groups[0]["hooks"][0]["command"],
            "/usr/local/bin/my-post-hook"
        );

        let agy_settings = read_json(&h.join(".gemini/antigravity-cli/settings.json"));
        assert_eq!(agy_settings["statusLine"], fx.agy_original_statusline);
        assert_eq!(agy_settings["model"], "gemini-2.5-pro");

        // 2. Claude MCP, Desktop MCP, Gemini, Cursor, OpenCode, OpenClaw surgically cleaned
        let claude_json = read_json(&h.join(".claude.json"));
        assert_eq!(claude_json["numStartups"], 42);
        assert!(claude_json["mcpServers"].get("hyphae").is_none());
        assert!(claude_json["mcpServers"].get("github").is_some());

        let desktop_cfg = if cfg!(target_os = "macos") {
            h.join("Library/Application Support/Claude/claude_desktop_config.json")
        } else {
            h.join(".config/Claude/claude_desktop_config.json")
        };
        let desktop_json = read_json(&desktop_cfg);
        assert!(desktop_json["mcpServers"].get("hyphae").is_none());
        assert!(desktop_json["mcpServers"].get("filesystem").is_some());

        let gemini_json = read_json(&h.join(".gemini/settings.json"));
        assert!(gemini_json["mcpServers"].get("hyphae").is_none());
        assert!(gemini_json["mcpServers"].get("custom-gemini").is_some());
        assert!(gemini_json["hooks"].get("AfterTool").is_none());
        let gemini_before = gemini_json["hooks"]["BeforeTool"].as_array().unwrap();
        assert_eq!(gemini_before.len(), 1);
        assert_eq!(gemini_before[0]["hooks"][0]["name"], "user-guard");

        let cursor_mcp = read_json(&h.join(".cursor/mcp.json"));
        assert!(cursor_mcp["mcpServers"].get("hyphae").is_none());
        assert!(cursor_mcp["mcpServers"].get("docs").is_some());
        let cursor_hooks = read_json(&h.join(".cursor/hooks.json"));
        assert_eq!(cursor_hooks["version"], 1);
        assert!(cursor_hooks["hooks"].get("stop").is_none());
        assert_eq!(
            cursor_hooks["hooks"]["beforeMCPExecution"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            cursor_hooks["hooks"]["beforeMCPExecution"][0]["command"],
            "/usr/local/bin/cursor-user-hook"
        );

        let opencode_json = read_json(&h.join(".config/opencode/opencode.json"));
        assert!(opencode_json["mcp"].get("hyphae").is_none());
        assert!(opencode_json["mcp"].get("user-tool").is_some());

        let openclaw_json = read_json(&h.join(".openclaw/openclaw.json"));
        assert_eq!(openclaw_json["profile"], "default");
        assert!(openclaw_json["mcp"]["servers"].get("hyphae").is_none());
        assert!(openclaw_json["mcp"]["servers"].get("weather").is_some());
        assert!(openclaw_json["plugins"]["entries"].get("hyphae").is_none());
        assert!(
            openclaw_json["plugins"]["entries"]
                .get("weather-ext")
                .is_some()
        );
        assert_eq!(openclaw_json["plugins"]["allow"], json!(["weather-ext"]));

        // 3. Codex config.toml & hooks.json
        let codex_toml = fs::read_to_string(h.join(".codex/config.toml")).unwrap();
        assert!(!codex_toml.contains("mcp_servers.hyphae"));
        assert!(!codex_toml.contains(">>> hyphae >>>"));
        assert!(codex_toml.contains("[model]\nname = \"o3\""));
        assert!(codex_toml.contains("[mcp_servers.other]\ncommand = \"other-mcp\""));
        assert!(codex_toml.contains("[features]\nfast_mode = true"));

        let codex_hooks = read_json(&h.join(".codex/hooks.json"));
        assert!(codex_hooks["hooks"].get("Stop").is_none());
        let codex_start = codex_hooks["hooks"]["SessionStart"].as_array().unwrap();
        assert_eq!(codex_start.len(), 1);
        assert_eq!(
            codex_start[0]["hooks"][0]["command"],
            "/usr/local/bin/codex-custom"
        );

        // 4. Standalone Hyphae files removed; custom user files preserved!
        for gone in [
            ".claude/commands/hyphae.md",
            ".claude/commands/hyphae-subs.md",
            ".claude/commands/hyphae-focus.md",
            ".claude/commands/hyphae-mute.md",
            ".gemini/config/plugins/hyphae",
            ".config/opencode/plugins/hyphae.ts",
            ".openclaw/extensions/hyphae",
            ".config/herdr/hyphae.json",
            ".t3/hyphae.json",
            ".config/herdr-app/mods/hyphae-pane",
            ".config/herdr-app/mods/hyphae-panel",
            ".claude/skills/hyphae",
            ".claude/skills/hyphae-setup",
            ".claude/skills/hyphae-schedule",
            ".codex/skills/hyphae",
            ".agents/skills/hyphae",
            ".gemini/config/skills/hyphae",
            ".gemini/skills/hyphae",
            ".config/opencode/skills/hyphae",
            ".cursor/skills/hyphae",
            ".openclaw/skills/hyphae",
            ".config/herdr/skills/hyphae",
            ".t3/skills/hyphae",
        ] {
            assert!(!h.join(gone).exists(), "expected {gone} to be removed");
        }
        assert!(h.join(".claude/commands/my-cmd.md").exists());
        assert!(h.join(".claude/skills/my-skill/SKILL.md").exists());
        assert!(
            h.join(".config/herdr-app/mods/user-custom-mod/mod.json")
                .exists()
        );

        // 5. Herdr keys.json & symlinked layout
        let herdr_keys = read_json(&h.join(".config/herdr-app/keys.json"));
        assert!(herdr_keys["global"].get("cmd-shift-h").is_none());
        assert_eq!(herdr_keys["global"]["cmd-k"], "palette.open");
        assert!(
            fs::symlink_metadata(h.join(".config/herdr-app/layouts/custom.json"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "symlinked Herdr layout must stay a symlink"
        );
        assert_eq!(
            fs::read_to_string(&fx.external_layout_target).unwrap(),
            fx.external_layout_original,
            "symlinked Herdr layout target must be untouched byte-for-byte"
        );

        // 6. State directories & binaries removed
        assert!(!h.join(".config/hyphae").exists());
        assert!(!h.join(".config/agents-mesh").exists());
        assert!(!h.join(".local/state/hyphae").exists());
        assert!(!h.join(".local/share/hyphae").exists());
        assert!(!h.join(".local/bin/hyp").exists());
        assert!(!h.join(".local/bin/hyp.prev").exists());

        // 7. Re-running uninstall is cleanly idempotent ("Already clean")
        let out2 = run_script(&script, h, &["--yes"]);
        assert_eq!(out2.status.code(), Some(0));
        assert!(String::from_utf8_lossy(&out2.stdout).contains("Already clean"));
        let _keep_alive = &fx.external_layout_dir;
    }

    #[test]
    fn real_hyp_setup_all_then_uninstall_round_trip_restores_cleanly() {
        let tmp = TempDir::new().expect("temp home");
        let h = tmp.path();

        // Seed pre-existing user custom statusLines & settings BEFORE `hyp setup`!
        let user_claude_sl = json!({
            "type": "command",
            "command": "/usr/local/bin/starship-claude --short",
            "refreshInterval": 15
        });
        let user_agy_sl = json!({
            "command": "/usr/local/bin/agy-custom-bar",
            "stack_with_default": false
        });
        write_json(
            &h.join(".claude/settings.json"),
            &json!({ "customSetting": true, "statusLine": user_claude_sl }),
        );
        write_json(
            &h.join(".gemini/antigravity-cli/settings.json"),
            &json!({ "customAgy": "keep", "statusLine": user_agy_sl }),
        );
        write_file(
            &h.join(".codex/config.toml"),
            "model = \"gpt-5\"\n\n[mcp_servers.mine]\ncommand = \"my-mcp\"\n",
        );

        // Run REAL compiled `hyp setup --harness all --statusline --home <tmp>`
        let setup_out = isolated_cmd(h)
            .args(["setup", "--harness", "all", "--statusline", "--home"])
            .arg(h)
            .output()
            .expect("run real hyp setup");
        assert!(
            setup_out.status.success(),
            "hyp setup failed: stdout={} stderr={}",
            String::from_utf8_lossy(&setup_out.stdout),
            String::from_utf8_lossy(&setup_out.stderr)
        );
        // Verify setup actually chained both statusLines & wrote configs
        assert!(
            h.join(".config/hyphae/claude-statusline-chain.json")
                .exists()
        );
        assert!(
            h.join(".config/hyphae/antigravity-statusline-chain.json")
                .exists()
        );
        assert!(h.join(".claude/commands/hyp.md").exists());
        assert!(h.join(".gemini/config/plugins/hyphae/hooks.json").exists());
        assert!(h.join(".config/opencode/plugins/hyphae.ts").exists());
        assert!(!h.join(".config/herdr/hyphae.json").exists());
        assert!(!h.join(".t3/hyphae.json").exists());
        assert!(h.join(".config/herdr/skills/hyp-mesh/SKILL.md").exists());
        assert!(h.join(".agents/skills/hyp-mesh/SKILL.md").exists());

        // Now run `scripts/uninstall.sh --yes`!
        let script = repo_root().join("scripts/uninstall.sh");
        let out = run_script(&script, h, &["--yes"]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "uninstall after real setup failed: stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );

        // Verify original statusLines & user settings restored verbatim across ALL 9 harnesses!
        let claude_after = read_json(&h.join(".claude/settings.json"));
        assert_eq!(claude_after["statusLine"], user_claude_sl);
        assert_eq!(claude_after["customSetting"], json!(true));
        assert!(claude_after.get("hooks").is_none());

        let agy_after = read_json(&h.join(".gemini/antigravity-cli/settings.json"));
        assert_eq!(agy_after["statusLine"], user_agy_sl);
        assert_eq!(agy_after["customAgy"], "keep");

        let codex_after = fs::read_to_string(h.join(".codex/config.toml")).unwrap();
        assert!(!codex_after.contains("hyphae"));
        assert!(codex_after.contains("model = \"gpt-5\""));
        assert!(codex_after.contains("[mcp_servers.mine]"));

        assert!(
            read_json(&h.join(".claude.json"))
                .get("mcpServers")
                .is_none()
        );
        assert!(
            read_json(&h.join(".cursor/mcp.json"))
                .get("mcpServers")
                .is_none()
        );
        assert!(
            read_json(&h.join(".cursor/hooks.json"))
                .get("hooks")
                .is_none()
        );
        assert!(
            read_json(&h.join(".codex/hooks.json"))
                .get("hooks")
                .is_none()
        );
        assert!(
            read_json(&h.join(".gemini/settings.json"))
                .get("mcpServers")
                .is_none()
        );
        assert!(
            read_json(&h.join(".gemini/settings.json"))
                .get("hooks")
                .is_none()
        );
        assert!(
            read_json(&h.join(".config/opencode/opencode.json"))
                .get("mcp")
                .is_none()
        );
        assert!(
            read_json(&h.join(".openclaw/openclaw.json"))
                .get("mcp")
                .is_none()
        );
        assert!(!h.join(".config/hyphae").exists());
        assert!(!h.join(".gemini/config/plugins/hyphae").exists());
        assert!(!h.join(".config/opencode/plugins/hyphae.ts").exists());
        assert!(!h.join(".config/herdr/hyphae.json").exists());
        assert!(!h.join(".t3/hyphae.json").exists());
    }

    #[test]
    fn piped_posix_sh_execution_matches_curl_pipe_sh_workflow() {
        let fx = build_populated_home();
        let h = fx.home.path();
        let script_bytes =
            fs::read(repo_root().join("scripts/uninstall.sh")).expect("read scripts/uninstall.sh");

        let mut child = Command::new("/bin/sh")
            .args(["-s", "--", "--yes"])
            .env("HOME", h)
            .env("XDG_CONFIG_HOME", h.join(".config"))
            .env("XDG_STATE_HOME", h.join(".local/state"))
            .env("HYPHAE_INSTALL_DIR", h.join(".local/bin"))
            .env("HERDR_APP_HOME", h.join(".config/herdr-app"))
            .env("HYPHAE_SECRET_BACKEND", "file")
            .env("CI", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn /bin/sh -s");

        child
            .stdin
            .take()
            .unwrap()
            .write_all(&script_bytes)
            .expect("pipe scripts/uninstall.sh to /bin/sh");
        let out = child.wait_with_output().expect("wait /bin/sh");
        assert_eq!(
            out.status.code(),
            Some(0),
            "curl|sh simulation failed: stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            read_json(&h.join(".claude/settings.json"))["statusLine"],
            fx.claude_original_statusline
        );
        assert!(!h.join(".config/hyphae").exists());
        assert!(!h.join(".local/bin/hyp").exists());
        let _keep_alive = &fx.external_layout_dir;
    }

    #[test]
    fn differential_python3_and_node_cleaners_produce_identical_results() {
        // Locate `node` on host; skip only if node is unavailable.
        let Ok(which_node) = Command::new("/usr/bin/which").arg("node").output() else {
            return;
        };
        if !which_node.status.success() {
            return;
        }
        let node_path = PathBuf::from(String::from_utf8_lossy(&which_node.stdout).trim());
        if !node_path.is_file() {
            return;
        }

        assert!(crate::node_runtime::node_available_at(
            node_path.as_os_str()
        ));

        // Build a shim bin dir exposing `node` + standard POSIX utils, WITHOUT `python3`.
        let no_py_bin = TempDir::new().expect("no-python bin dir");
        symlink(&node_path, no_py_bin.path().join("node")).expect("symlink node");
        for util in [
            "awk", "basename", "find", "grep", "id", "rm", "sort", "uname", "wc", "cat",
        ] {
            for dir in ["/usr/bin", "/bin"] {
                let cand = Path::new(dir).join(util);
                if cand.is_file() {
                    let _ = symlink(&cand, no_py_bin.path().join(util));
                    break;
                }
            }
        }

        let fx_py = build_populated_home();
        let fx_js = build_populated_home();
        let script = repo_root().join("scripts/uninstall.sh");

        let out_py = run_script(&script, fx_py.home.path(), &["--yes"]);
        assert_eq!(out_py.status.code(), Some(0));

        let out_js = Command::new("/bin/bash")
            .arg(&script)
            .args(["--yes"])
            .env("PATH", no_py_bin.path())
            .env("HOME", fx_js.home.path())
            .env("XDG_CONFIG_HOME", fx_js.home.path().join(".config"))
            .env("XDG_STATE_HOME", fx_js.home.path().join(".local/state"))
            .env("HYPHAE_INSTALL_DIR", fx_js.home.path().join(".local/bin"))
            .env(
                "HERDR_APP_HOME",
                fx_js.home.path().join(".config/herdr-app"),
            )
            .env("HYPHAE_SECRET_BACKEND", "file")
            .env("CI", "1")
            .stdin(Stdio::null())
            .output()
            .expect("run uninstall.sh with node fallback");
        assert_eq!(
            out_js.status.code(),
            Some(0),
            "node fallback failed: stdout={} stderr={}",
            String::from_utf8_lossy(&out_js.stdout),
            String::from_utf8_lossy(&out_js.stderr)
        );

        // Compare semantic JSON & TOML post-states across Python 3 vs Node.js!
        for rel_json in [
            ".claude/settings.json",
            ".claude.json",
            ".gemini/antigravity-cli/settings.json",
            ".gemini/settings.json",
            ".codex/hooks.json",
            ".cursor/mcp.json",
            ".cursor/hooks.json",
            ".config/opencode/opencode.json",
            ".openclaw/openclaw.json",
            ".config/herdr-app/keys.json",
        ] {
            assert_eq!(
                read_json(&fx_py.home.path().join(rel_json)),
                read_json(&fx_js.home.path().join(rel_json)),
                "Python 3 vs Node.js cleaner diverged on {rel_json}"
            );
        }
        assert_eq!(
            fs::read_to_string(fx_py.home.path().join(".codex/config.toml")).unwrap(),
            fs::read_to_string(fx_js.home.path().join(".codex/config.toml")).unwrap(),
            "Python 3 vs Node.js cleaner diverged on .codex/config.toml"
        );
        let _keep = (&fx_py.external_layout_dir, &fx_js.external_layout_dir);
    }

    #[test]
    fn edge_cases_unmarked_toml_unchained_statusline_malformed_json_and_keep_harnesses() {
        let tmp = TempDir::new().expect("temp home");
        let h = tmp.path();
        let script = repo_root().join("scripts/uninstall.sh");

        // 1. Unmarked [mcp_servers.hyphae] + subtable [mcp_servers.hyphae.env]
        write_file(
            &h.join(".codex/config.toml"),
            "model = \"o3\"\n\n[mcp_servers.hyphae]\ncommand = \"hyp\"\nargs = [\"mcp\"]\n\n[mcp_servers.hyphae.env]\nFOO = \"bar\"\n\n[mcp_servers.keep]\ncommand = \"keep-mcp\"\n",
        );
        // 2. Unchained Hyphae statusLine in Claude (no backup -> key removed), custom non-Hyphae in Antigravity (untouched)
        write_json(
            &h.join(".claude/settings.json"),
            &json!({
                "theme": "light",
                "statusLine": { "type": "command", "command": "hyp statusline --harness claude" }
            }),
        );
        let non_hyphae_sl = json!({ "command": "/opt/custom/bar" });
        write_json(
            &h.join(".gemini/antigravity-cli/settings.json"),
            &json!({ "statusLine": non_hyphae_sl }),
        );
        // 3. Malformed JSON in ~/.cursor/mcp.json -> must NOT crash or clobber user file!
        let broken_json = "{ broken json,,,\n";
        write_file(&h.join(".cursor/mcp.json"), broken_json);

        let out = run_script(&script, h, &["--yes"]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "edge cases failed: stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        let codex_after = fs::read_to_string(h.join(".codex/config.toml")).unwrap();
        assert!(!codex_after.contains("mcp_servers.hyphae"));
        assert!(!codex_after.contains("FOO = \"bar\""));
        assert!(codex_after.contains("model = \"o3\""));
        assert!(codex_after.contains("[mcp_servers.keep]\ncommand = \"keep-mcp\""));

        let claude_after = read_json(&h.join(".claude/settings.json"));
        assert!(claude_after.get("statusLine").is_none());
        assert_eq!(claude_after["theme"], "light");

        let agy_after = read_json(&h.join(".gemini/antigravity-cli/settings.json"));
        assert_eq!(agy_after["statusLine"], non_hyphae_sl);

        assert_eq!(
            fs::read_to_string(h.join(".cursor/mcp.json")).unwrap(),
            broken_json,
            "malformed JSON must never be clobbered"
        );

        // 4. --keep-harnesses leaves harness files untouched while removing state & binary
        let fx_kh = build_populated_home();
        let h_kh = fx_kh.home.path();
        let claude_before = fs::read(h_kh.join(".claude/settings.json")).unwrap();
        let out_kh = run_script(&script, h_kh, &["--yes", "--keep-harnesses"]);
        assert_eq!(out_kh.status.code(), Some(0));
        assert_eq!(
            fs::read(h_kh.join(".claude/settings.json")).unwrap(),
            claude_before
        );
        assert!(h_kh.join(".claude/skills/hyphae/SKILL.md").exists());
        assert!(h_kh.join(".config/herdr-app/mods/hyphae-pane").exists());
        assert!(!h_kh.join(".config/hyphae").exists());
        assert!(!h_kh.join(".local/bin/hyp").exists());
    }

    #[test]
    fn reset_local_keeps_binary_by_default_and_removes_with_all() {
        let reset_script = repo_root().join("scripts/reset-local.sh");

        // Case 1: `scripts/reset-local.sh --yes` keeps ~/.local/bin/hyp
        let fx1 = build_populated_home();
        let h1 = fx1.home.path();
        let out1 = run_script(&reset_script, h1, &["--yes"]);
        assert_eq!(
            out1.status.code(),
            Some(0),
            "reset-local --yes failed: stdout={} stderr={}",
            String::from_utf8_lossy(&out1.stdout),
            String::from_utf8_lossy(&out1.stderr)
        );
        assert!(
            h1.join(".local/bin/hyp").exists(),
            "reset-local.sh without --all MUST keep ~/.local/bin/hyp"
        );
        assert!(!h1.join(".config/hyphae").exists());
        assert!(!h1.join(".claude/skills/hyphae-setup").exists());

        // Case 2: `scripts/reset-local.sh --all --yes` removes ~/.local/bin/hyp too
        let fx2 = build_populated_home();
        let h2 = fx2.home.path();
        let out2 = run_script(&reset_script, h2, &["--all", "--yes"]);
        assert_eq!(
            out2.status.code(),
            Some(0),
            "reset-local --all --yes failed: stdout={} stderr={}",
            String::from_utf8_lossy(&out2.stdout),
            String::from_utf8_lossy(&out2.stderr)
        );
        assert!(
            !h2.join(".local/bin/hyp").exists(),
            "reset-local.sh --all MUST remove ~/.local/bin/hyp"
        );
        assert!(!h2.join(".config/hyphae").exists());
    }

    #[test]
    fn keep_flags_preserve_selected_components_and_custom_herdr_keybinding() {
        let fx = build_populated_home();
        let h = fx.home.path();
        let script = repo_root().join("scripts/uninstall.sh");

        // Replace cmd-shift-h with a user-customized binding to ensure it is NOT removed.
        write_json(
            &h.join(".config/herdr-app/keys.json"),
            &json!({
                "global": {
                    "cmd-shift-h": "my.custom.action"
                }
            }),
        );

        let out = run_script(
            &script,
            h,
            &["--yes", "--keep-binary", "--keep-state", "--keep-keychain"],
        );
        assert_eq!(
            out.status.code(),
            Some(0),
            "keep-flags uninstall failed: stdout={} stderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            h.join(".local/bin/hyp").exists(),
            "--keep-binary must preserve binary"
        );
        assert!(
            h.join(".config/hyphae/node.json").exists(),
            "--keep-state must preserve state"
        );
        // Harnesses were cleaned while custom cmd-shift-h binding was preserved!
        assert!(!h.join(".claude/skills/hyphae").exists());
        let keys = read_json(&h.join(".config/herdr-app/keys.json"));
        assert_eq!(keys["global"]["cmd-shift-h"], "my.custom.action");
    }

    #[test]
    fn hyp_uninstall_cli_dry_run_and_embedded_full_cleanup_work_in_isolated_home() {
        let fx = build_populated_home();
        let h = fx.home.path();
        let bin = env!("CARGO_BIN_EXE_hyp");

        // Also seed the native Claude Code side-panel mod dir (`~/.claude/skills/hyphae-panel`).
        let panel_dir = h.join(".claude/skills/hyphae-panel/hooks");
        fs::create_dir_all(&panel_dir).unwrap();
        fs::write(panel_dir.join("register.tsx"), "// panel mod").unwrap();

        let renamed_assets = [
            ".claude/commands/hyp.md",
            ".claude/commands/hyp-focus.md",
            ".claude/skills/hyp-panel/hooks/register.tsx",
            ".claude/skills/hyp-mesh/SKILL.md",
            ".claude/skills/hyp-setup/SKILL.md",
            ".claude/skills/hyp-onboard/SKILL.md",
            ".claude/skills/hyp-schedule/SKILL.md",
            ".config/opencode/commands/hyp.md",
            ".config/opencode/commands/hyphae.md",
        ];
        for rel in renamed_assets {
            write_file(&h.join(rel), "# fixture\n");
        }

        // 1. `hyp uninstall --dry-run --home <tmp>` leaves everything intact.
        let dry = Command::new(bin)
            .args(["uninstall", "--dry-run", "--home", h.to_str().unwrap()])
            .env("HOME", h)
            .env("XDG_CONFIG_HOME", h.join(".config"))
            .env("XDG_STATE_HOME", h.join(".local/state"))
            .env("HYPHAE_INSTALL_DIR", h.join(".local/bin"))
            .env("HYPHAE_SECRET_BACKEND", "file")
            .env("HYPHAE_NO_SERVICE", "1")
            .env_remove("CLAUDE_CONFIG_DIR")
            .output()
            .expect("run hyp uninstall --dry-run");
        assert_eq!(
            dry.status.code(),
            Some(0),
            "hyp uninstall --dry-run failed: stdout={} stderr={}",
            String::from_utf8_lossy(&dry.stdout),
            String::from_utf8_lossy(&dry.stderr)
        );
        assert!(
            h.join(".claude/skills/hyphae-panel/hooks/register.tsx")
                .exists()
        );
        assert!(h.join(".config/hyphae/node.json").exists());

        for rel in renamed_assets {
            assert!(h.join(rel).exists(), "dry run removed {rel}");
        }

        // 2. `hyp uninstall --yes --home <tmp>` runs the embedded script and removes everything cleanly.
        let run = Command::new(bin)
            .args(["uninstall", "--yes", "--home", h.to_str().unwrap()])
            .env("HOME", h)
            .env("XDG_CONFIG_HOME", h.join(".config"))
            .env("XDG_STATE_HOME", h.join(".local/state"))
            .env("HYPHAE_INSTALL_DIR", h.join(".local/bin"))
            .env("HYPHAE_SECRET_BACKEND", "file")
            .env("HYPHAE_NO_SERVICE", "1")
            .env_remove("CLAUDE_CONFIG_DIR")
            .output()
            .expect("run hyp uninstall --yes");
        assert_eq!(
            run.status.code(),
            Some(0),
            "hyp uninstall --yes failed: stdout={} stderr={}",
            String::from_utf8_lossy(&run.stdout),
            String::from_utf8_lossy(&run.stderr)
        );
        assert!(!h.join(".claude/skills/hyphae-panel").exists());
        for rel in renamed_assets {
            assert!(!h.join(rel).exists(), "uninstall left {rel}");
        }

        assert!(!h.join(".config/hyphae").exists());
        assert!(!h.join(".local/bin/hyp").exists());
        // Original custom Claude statusLine was restored verbatim!
        let claude_settings = read_json(&h.join(".claude/settings.json"));
        assert_eq!(
            claude_settings["statusLine"]["command"],
            "/usr/local/bin/my-claude-bar --git --branch"
        );
    }

    #[test]
    fn claude_config_dir_profile_symlinks_preserved_and_hermetic_guard_holds() {
        let script = repo_root().join("scripts/uninstall.sh");
        let tmp = TempDir::new().expect("temp home");
        let h = tmp.path();
        let profile = h.join(".claude-work");
        let config_hyphae = h.join(".config/hyphae");

        // Seed original custom statusLine backup & default ~/.claude state.
        let orig_sl = json!({
            "type": "command",
            "command": "/usr/local/bin/my-starship-claude --git",
            "refreshInterval": 10
        });
        let chain_path = config_hyphae.join("claude-statusline-chain.json");
        write_json(&chain_path, &orig_sl);
        write_json(
            &config_hyphae.join("node.json"),
            &json!({ "v": 2, "nodeId": "riley@demo-laptop" }),
        );

        let default_settings = h.join(".claude/settings.json");
        write_json(
            &default_settings,
            &json!({
                "theme": "dark",
                "statusLine": {
                    "type": "command",
                    "command": format!(
                        "{} statusline --harness claude --chain-file {}",
                        h.join(".local/bin/hyp").display(),
                        chain_path.display()
                    ),
                    "refreshInterval": 5
                },
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{ "type": "command", "command": "/usr/local/bin/keep-hook" }]
                        },
                        {
                            "matcher": "mcp__hyphae__.*",
                            "hooks": [{ "type": "command", "command": "hyp hook claude pre-tool-use" }]
                        }
                    ],
                    "Stop": [
                        {
                            "hooks": [{ "type": "command", "command": "hyp hook claude stop" }]
                        }
                    ]
                }
            }),
        );
        fs::set_permissions(&default_settings, fs::Permissions::from_mode(0o600))
            .expect("chmod settings.json");

        // Default ~/.claude.json + default commands & skills (including hyphae-panel + custom user files)
        write_json(
            &h.join(".claude.json"),
            &json!({
                "numStartups": 11,
                "mcpServers": {
                    "github": { "command": "npx", "args": ["github-mcp"] },
                    "hyphae": { "command": "hyp", "args": ["mcp"] }
                }
            }),
        );
        for cmd in [
            "hyphae.md",
            "hyphae-subs.md",
            "hyphae-focus.md",
            "hyphae-mute.md",
        ] {
            write_file(
                &h.join(".claude/commands").join(cmd),
                "# default hyphae cmd\n",
            );
        }
        write_file(
            &h.join(".claude/commands/default-custom.md"),
            "# keep default cmd\n",
        );
        for skill in ["hyphae", "hyphae-setup", "hyphae-schedule", "hyphae-panel"] {
            write_file(
                &h.join(".claude/skills").join(skill).join("SKILL.md"),
                "# hyphae skill\n",
            );
        }
        write_file(
            &h.join(".claude/skills/my-shared-skill/SKILL.md"),
            "# keep shared skill\n",
        );

        // Profile $CLAUDE_CONFIG_DIR:
        // - real .claude.json (profile-specific MCP servers)
        // - symlinked settings.json -> ~/.claude/settings.json
        // - symlinked skills -> ~/.claude/skills
        // - profile-local commands/ directory with hyphae*.md + custom command
        fs::create_dir_all(&profile).expect("create CLAUDE_CONFIG_DIR");
        write_json(
            &profile.join(".claude.json"),
            &json!({
                "profileName": "work",
                "mcpServers": {
                    "linear": { "command": "linear-mcp", "args": [] },
                    "hyphae": { "command": "hyp", "args": ["mcp"] }
                }
            }),
        );
        symlink(&default_settings, profile.join("settings.json"))
            .expect("symlink profile settings.json");
        symlink(h.join(".claude/skills"), profile.join("skills"))
            .expect("symlink profile skills dir");
        for cmd in [
            "hyphae.md",
            "hyphae-subs.md",
            "hyphae-focus.md",
            "hyphae-mute.md",
        ] {
            write_file(
                &profile.join("commands").join(cmd),
                "# profile hyphae cmd\n",
            );
        }
        write_file(
            &profile.join("commands/work-custom.md"),
            "# keep profile cmd\n",
        );

        // 1. Dry-run reports profile .claude.json & profile commands without duplicating symlinked
        //    settings.json or symlinked skills, and modifies zero files.
        let dry = run_script_with_claude_dir(&script, h, Some(&profile), &["--dry-run"]);
        let dry_stdout = String::from_utf8_lossy(&dry.stdout);
        assert_eq!(
            dry.status.code(),
            Some(0),
            "dry-run failed: stdout={dry_stdout}\nstderr={}",
            String::from_utf8_lossy(&dry.stderr)
        );
        assert!(dry_stdout.contains(&profile.join(".claude.json").display().to_string()));
        assert!(dry_stdout.contains(&profile.join("commands/hyphae.md").display().to_string()));
        assert!(
            !dry_stdout.contains(&profile.join("skills/hyphae").display().to_string()),
            "canonical dedup must avoid listing symlinked profile skills twice:\n{dry_stdout}"
        );
        assert!(
            read_json(&profile.join(".claude.json"))["mcpServers"]
                .get("hyphae")
                .is_some()
        );

        // 2. Full uninstall cleans BOTH profiles, restores statusLine verbatim, preserves BOTH symlinks.
        let out = run_script_with_claude_dir(&script, h, Some(&profile), &["--yes"]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "uninstall with CLAUDE_CONFIG_DIR failed: stdout={}\nstderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );

        let default_mcp = read_json(&h.join(".claude.json"));
        assert_eq!(default_mcp["numStartups"], 11);
        assert!(default_mcp["mcpServers"].get("hyphae").is_none());
        assert!(default_mcp["mcpServers"].get("github").is_some());

        let profile_mcp = read_json(&profile.join(".claude.json"));
        assert_eq!(profile_mcp["profileName"], "work");
        assert!(profile_mcp["mcpServers"].get("hyphae").is_none());
        assert!(profile_mcp["mcpServers"].get("linear").is_some());

        // Symlinks remain symlinks pointing to the exact original targets!
        assert!(
            fs::symlink_metadata(profile.join("settings.json"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "CLAUDE_CONFIG_DIR/settings.json symlink must NEVER be replaced with a regular file"
        );
        assert_eq!(
            fs::read_link(profile.join("settings.json")).unwrap(),
            default_settings
        );
        assert!(
            fs::symlink_metadata(profile.join("skills"))
                .unwrap()
                .file_type()
                .is_symlink(),
            "CLAUDE_CONFIG_DIR/skills symlink must NEVER be unlinked"
        );
        assert_eq!(
            fs::read_link(profile.join("skills")).unwrap(),
            h.join(".claude/skills")
        );

        // Chained statusLine restored verbatim, Hyphae hooks removed, custom hooks & 0600 preserved.
        let settings_after = read_json(&default_settings);
        assert_eq!(settings_after["statusLine"], orig_sl);
        assert_eq!(settings_after["theme"], "dark");
        assert!(settings_after["hooks"].get("Stop").is_none());
        let pre = settings_after["hooks"]["PreToolUse"].as_array().unwrap();
        assert_eq!(pre.len(), 1);
        assert_eq!(pre[0]["hooks"][0]["command"], "/usr/local/bin/keep-hook");
        assert_eq!(
            fs::metadata(&default_settings)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );

        // Commands & skills cleaned in both places; user custom commands & skills preserved!
        for cmd in [
            "hyphae.md",
            "hyphae-subs.md",
            "hyphae-focus.md",
            "hyphae-mute.md",
        ] {
            assert!(!h.join(".claude/commands").join(cmd).exists());
            assert!(!profile.join("commands").join(cmd).exists());
        }
        assert!(h.join(".claude/commands/default-custom.md").exists());
        assert!(profile.join("commands/work-custom.md").exists());

        for skill in ["hyphae", "hyphae-setup", "hyphae-schedule", "hyphae-panel"] {
            assert!(!h.join(".claude/skills").join(skill).exists());
            assert!(!profile.join("skills").join(skill).exists());
        }
        assert!(h.join(".claude/skills/my-shared-skill/SKILL.md").exists());
        assert!(profile.join("skills/my-shared-skill/SKILL.md").exists());

        // 3. Re-running with CLAUDE_CONFIG_DIR set is cleanly idempotent.
        let out2 = run_script_with_claude_dir(&script, h, Some(&profile), &["--yes"]);
        assert_eq!(out2.status.code(), Some(0));
        assert!(String::from_utf8_lossy(&out2.stdout).contains("Already clean"));

        // 4. Direct symlink to external dotfiles inside isolated HOME (no ~/.claude/settings.json)
        //    is cleaned through os.path.realpath / fs.realpathSync without replacing the symlink,
        //    differentially verified across BOTH Python 3 and Node.js cleaners!
        let setup_symlink_only_profile = |base: &Path| {
            let prof = base.join(".claude-dot");
            let df = base.join("dotfiles/claude-work-settings.json");
            let chain = base.join(".config/hyphae/claude-statusline-chain.json");
            write_json(&chain, &orig_sl);
            write_json(
                &df,
                &json!({
                    "owner": "dotfiles",
                    "statusLine": {
                        "type": "command",
                        "command": format!("hyp statusline --harness claude --chain-file {}", chain.display())
                    },
                    "hooks": {
                        "Stop": [{ "hooks": [{ "type": "command", "command": "hyp hook claude stop" }] }]
                    }
                }),
            );
            fs::create_dir_all(&prof).unwrap();
            symlink(&df, prof.join("settings.json")).unwrap();
            write_json(
                &prof.join(".claude.json"),
                &json!({ "mcpServers": { "hyphae": { "command": "hyp", "args": ["mcp"] }, "keep": { "command": "k" } } }),
            );
            (prof, df)
        };

        let tmp_py = TempDir::new().expect("temp home py");
        let (prof_py, df_py) = setup_symlink_only_profile(tmp_py.path());
        let out_py = run_script_with_claude_dir(&script, tmp_py.path(), Some(&prof_py), &["--yes"]);
        assert_eq!(out_py.status.code(), Some(0));
        assert!(
            fs::symlink_metadata(prof_py.join("settings.json"))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(read_json(&df_py)["statusLine"], orig_sl);
        assert!(read_json(&df_py).get("hooks").is_none());
        assert!(
            read_json(&prof_py.join(".claude.json"))["mcpServers"]
                .get("hyphae")
                .is_none()
        );
        assert!(
            read_json(&prof_py.join(".claude.json"))["mcpServers"]
                .get("keep")
                .is_some()
        );

        if let Ok(which_node) = Command::new("/usr/bin/which").arg("node").output() {
            let node_path = PathBuf::from(String::from_utf8_lossy(&which_node.stdout).trim());
            if which_node.status.success() && node_path.is_file() {
                assert!(crate::node_runtime::node_available_at(
                    node_path.as_os_str()
                ));
                let no_py_bin = TempDir::new().expect("no-python bin dir");
                symlink(&node_path, no_py_bin.path().join("node")).expect("symlink node");
                for util in [
                    "awk", "basename", "find", "grep", "id", "rm", "sort", "uname", "wc", "cat",
                ] {
                    for dir in ["/usr/bin", "/bin"] {
                        let cand = Path::new(dir).join(util);
                        if cand.is_file() {
                            let _ = symlink(&cand, no_py_bin.path().join(util));
                            break;
                        }
                    }
                }
                let tmp_js = TempDir::new().expect("temp home js");
                let (prof_js, df_js) = setup_symlink_only_profile(tmp_js.path());
                let out_js = Command::new("/bin/bash")
                    .arg(&script)
                    .args(["--yes"])
                    .env("PATH", no_py_bin.path())
                    .env("HOME", tmp_js.path())
                    .env("XDG_CONFIG_HOME", tmp_js.path().join(".config"))
                    .env("XDG_STATE_HOME", tmp_js.path().join(".local/state"))
                    .env("HYPHAE_INSTALL_DIR", tmp_js.path().join(".local/bin"))
                    .env("HERDR_APP_HOME", tmp_js.path().join(".config/herdr-app"))
                    .env("CLAUDE_CONFIG_DIR", &prof_js)
                    .env("HYPHAE_SECRET_BACKEND", "file")
                    .env("CI", "1")
                    .stdin(Stdio::null())
                    .output()
                    .expect("run node fallback with CLAUDE_CONFIG_DIR");
                assert_eq!(
                    out_js.status.code(),
                    Some(0),
                    "node fallback with CLAUDE_CONFIG_DIR failed: stdout={}\nstderr={}",
                    String::from_utf8_lossy(&out_js.stdout),
                    String::from_utf8_lossy(&out_js.stderr)
                );
                assert!(
                    fs::symlink_metadata(prof_js.join("settings.json"))
                        .unwrap()
                        .file_type()
                        .is_symlink()
                );
                assert_eq!(read_json(&df_py), read_json(&df_js));
                assert_eq!(
                    read_json(&prof_py.join(".claude.json")),
                    read_json(&prof_js.join(".claude.json"))
                );
            }
        }

        // 5. Hermetic guard: when HOME is isolated, an external CLAUDE_CONFIG_DIR outside HOME
        //    (e.g. inherited from host shell during tests) MUST NOT be mutated!
        let outside_dir = TempDir::new().expect("outside CLAUDE_CONFIG_DIR");
        let outside_mcp = outside_dir.path().join(".claude.json");
        let outside_cmd = outside_dir.path().join("commands/hyphae.md");
        write_json(
            &outside_mcp,
            &json!({ "mcpServers": { "hyphae": { "command": "hyp", "args": ["mcp"] } } }),
        );
        write_file(&outside_cmd, "# untouched outside home\n");

        let isolated_home = TempDir::new().expect("isolated home for hermetic guard");
        let guard_out = run_script_with_claude_dir(
            &script,
            isolated_home.path(),
            Some(outside_dir.path()),
            &["--yes"],
        );
        assert_eq!(guard_out.status.code(), Some(0));
        assert!(
            read_json(&outside_mcp)["mcpServers"]
                .get("hyphae")
                .is_some(),
            "hermetic guard must protect external CLAUDE_CONFIG_DIR outside isolated HOME"
        );
        assert!(
            outside_cmd.exists(),
            "hermetic guard must protect external CLAUDE_CONFIG_DIR commands outside isolated HOME"
        );
    }

    #[test]
    fn uninstall_preserves_t3_mesh_launch_agent_while_removing_hyphae_plists() {
        let root = repo_root();
        let script = root.join("scripts/uninstall.sh");
        let script_src = fs::read_to_string(&script).expect("read scripts/uninstall.sh");
        assert!(
            !script_src.contains("t3-mesh"),
            "scripts/uninstall.sh must NOT contain t3-mesh LaunchAgent globs (D13)"
        );

        let tmp = TempDir::new().expect("temp home");
        let h = tmp.path();

        let launch_agents = h.join("Library/LaunchAgents");
        let t3_plist = launch_agents.join("com.t3.t3-mesh.plist");
        let hyphae_plist = launch_agents.join("to.hyphae.daemon.plist");
        let legacy_hyphae_plist = launch_agents.join("com.hyphae.legacy.plist");
        let t3_content = "<?xml version=\"1.0\"?><plist><dict><key>Label</key><string>com.t3.t3-mesh</string></dict></plist>\n";

        write_file(&t3_plist, t3_content);
        write_file(
            &hyphae_plist,
            "<plist><dict><key>Label</key><string>to.hyphae.daemon</string></dict></plist>\n",
        );
        write_file(
            &legacy_hyphae_plist,
            "<plist><dict><key>Label</key><string>com.hyphae.legacy</string></dict></plist>\n",
        );

        // Dry-run must NEVER list com.t3.t3-mesh.plist!
        let dry = run_script(&script, h, &["--dry-run"]);
        let dry_stdout = String::from_utf8_lossy(&dry.stdout);
        assert_eq!(
            dry.status.code(),
            Some(0),
            "dry-run failed: stdout={dry_stdout}\nstderr={}",
            String::from_utf8_lossy(&dry.stderr)
        );
        assert!(
            !dry_stdout.contains("t3-mesh"),
            "dry-run plan must never target com.t3.t3-mesh.plist:\n{dry_stdout}"
        );
        if cfg!(target_os = "macos") {
            assert!(dry_stdout.contains("to.hyphae.daemon.plist"));
            assert!(dry_stdout.contains("com.hyphae.legacy.plist"));
        }

        // Full uninstall removes Hyphae plists while leaving com.t3.t3-mesh.plist untouched byte-for-byte!
        let out = run_script(&script, h, &["--yes"]);
        assert_eq!(
            out.status.code(),
            Some(0),
            "uninstall failed: stdout={}\nstderr={}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );

        assert!(
            t3_plist.is_file(),
            "com.t3.t3-mesh.plist MUST remain untouched after Hyphae uninstall"
        );
        assert_eq!(
            fs::read_to_string(&t3_plist).expect("read t3-mesh plist"),
            t3_content
        );
        if cfg!(target_os = "macos") {
            assert!(
                !hyphae_plist.exists(),
                "to.hyphae.daemon.plist must be removed"
            );
            assert!(
                !legacy_hyphae_plist.exists(),
                "com.hyphae.legacy.plist must be removed"
            );
        }
    }
}
