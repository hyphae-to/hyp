//! End-to-end differential tests for the Composable 4-Layer Runtime Skill Assembler,
//! `hyp setup` tailored skill installation, `<!-- hyphae:unmanaged -->` preservation,
//! `node.json` capability detection, and dynamic transport-aware MCP `initialize.instructions`.
//!
//! Strict isolation invariant: every test uses ephemeral `tempfile::TempDir`, isolated
//! `--home` / `--state-dir`, and `HYPHAE_SECRET_BACKEND=file` — zero live user config mutations!

mod common;

use common::{ManagedProcess, isolated_cmd, parse_json_stdout};
use serde_json::{Value, json};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tempfile::TempDir;

const MAX_TOKENS: usize = 450;

fn estimated_tokens(s: &str) -> usize {
    s.chars().count().div_ceil(4)
}

fn read_lf(path: &Path) -> String {
    fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed reading {}: {e}", path.display()))
        .replace("\r\n", "\n")
}

fn assert_common_skill_invariants(path: &Path, text: &str, expected_profile: &str) {
    let tokens = estimated_tokens(text);
    assert!(
        tokens <= MAX_TOKENS,
        "{} exceeded token budget ({tokens} > {MAX_TOKENS}):\n{text}",
        path.display()
    );
    assert!(
        text.starts_with("---\nname: hyp-mesh\ndescription: "),
        "{} missing Agent Skills frontmatter:\n{text}",
        path.display()
    );
    assert!(
        text.contains(&format!("<!-- hyphae:managed profile={expected_profile} ")),
        "{} missing managed profile={expected_profile} marker:\n{text}",
        path.display()
    );
    for req in [
        "`hyp_mesh`",
        "`hyp_send`",
        "`hyp_stream`",
        "`hyp_inbox`",
        "untrusted",
        "Never poll `hyp_inbox`",
        "CLI argv",
        "hp2p1_",
    ] {
        assert!(
            text.contains(req),
            "{} missing core/security invariant '{req}':\n{text}",
            path.display()
        );
    }
}

#[test]
fn setup_all_harnesses_installs_tailored_skills_idempotently_and_honors_dry_run() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&state_dir).unwrap();

    let legacy_claude = home.join(".claude/skills/hyphae/SKILL.md");
    let legacy_cursor = home.join(".cursor/skills/hyphae/SKILL.md");
    let legacy =
        "---\nname: hyphae\ndescription: Mesh\n---\n<!-- hyphae:managed profile=claude -->\n";
    let legacy_shared_copies =
        [".codex", ".agents", ".t3"].map(|root| home.join(root).join("skills/hyphae/SKILL.md"));
    for path in [&legacy_claude, &legacy_cursor]
        .into_iter()
        .chain(&legacy_shared_copies)
    {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, legacy).unwrap();
    }
    fs::write(
        &legacy_cursor,
        format!("{legacy}<!-- hyphae:unmanaged -->\n"),
    )
    .unwrap();

    // 1. `--dry-run` plans all 9 harnesses + skill paths without writing anything.
    let dry_out = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "all",
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--dry-run",
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(dry_out.status.code(), Some(0));
    let dry_json = parse_json_stdout(&dry_out);
    assert_eq!(dry_json["ok"], true);
    assert_eq!(dry_json["data"]["configuredCount"], 9);
    assert!(legacy_claude.exists());
    for rel in [
        ".gemini/config/plugins/hyphae/skills/hyp-mesh/SKILL.md",
        ".claude/skills/hyp-mesh/SKILL.md",
        ".agents/skills/hyp-mesh/SKILL.md",
        ".cursor/skills/hyp-mesh/SKILL.md",
        ".config/opencode/skills/hyp-mesh/SKILL.md",
        ".gemini/skills/hyp-mesh/SKILL.md",
        ".openclaw/skills/hyp-mesh/SKILL.md",
        ".config/herdr/skills/hyp-mesh/SKILL.md",
    ] {
        assert!(
            !home.join(rel).exists(),
            "--dry-run must not create {}",
            rel
        );
    }

    // 2. First real `hyp setup --harness all` writes tailored runtime skills for all 9 harnesses.
    let run1 = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "all",
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
        run1.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&run1.stderr)
    );
    let run1_json = parse_json_stdout(&run1);
    assert_eq!(run1_json["ok"], true);
    assert_eq!(run1_json["data"]["configuredCount"], 9);
    assert!(!legacy_claude.exists(), "retired the managed runtime skill");
    for old in &legacy_shared_copies {
        assert!(!old.exists(), "unretired managed skill: {}", old.display());
    }
    assert!(!home.join(".codex/skills/hyp-mesh/SKILL.md").exists());
    assert!(!home.join(".t3/skills/hyp-mesh/SKILL.md").exists());
    assert!(
        fs::read_to_string(legacy_cursor)
            .unwrap()
            .contains("<!-- hyphae:unmanaged -->")
    );

    let skill_cases: &[(&str, &str)] = &[
        (
            ".gemini/config/plugins/hyphae/skills/hyp-mesh/SKILL.md",
            "antigravity",
        ),
        (".claude/skills/hyp-mesh/SKILL.md", "claude"),
        (".agents/skills/hyp-mesh/SKILL.md", "codex"),
        (".cursor/skills/hyp-mesh/SKILL.md", "cursor"),
        (".config/opencode/skills/hyp-mesh/SKILL.md", "opencode"),
        (".gemini/skills/hyp-mesh/SKILL.md", "gemini"),
        (".openclaw/skills/hyp-mesh/SKILL.md", "openclaw"),
        (".config/herdr/skills/hyp-mesh/SKILL.md", "herdr"),
    ];

    let mut first_snapshots: Vec<(PathBuf, String)> = Vec::new();
    for &(rel, expected_profile) in skill_cases {
        let p = home.join(rel);
        let text = read_lf(&p);
        assert_common_skill_invariants(&p, &text, expected_profile);

        // Zero cross-harness leaks
        if expected_profile != "claude" {
            assert!(
                !text.contains("Monitor"),
                "Monitor leaked into {rel}:\n{text}"
            );
        }
        if expected_profile != "antigravity" {
            assert!(
                !text.contains("WaitMsBeforeAsync"),
                "WaitMsBeforeAsync leaked into {rel}:\n{text}"
            );
        }
        if matches!(expected_profile, "herdr" | "t3" | "openclaw") {
            assert!(
                !text.contains("hyp wait") && !text.contains("hyp watch"),
                "waiter command leaked into {rel}:\n{text}"
            );
        }

        // Default node.json has no bridge/kv -> 0 optional tool mentions, never removed hyp_wakeup
        assert!(!text.contains("`hyp_bridge`"));
        assert!(!text.contains("`hyp_kv`"));
        assert!(!text.contains("hyp_wakeup"));
        assert!(!text.contains("hyp wakeup"));

        // Local schedule tip appears ONLY on the 7 CLI harnesses without native scheduling
        let expect_local_sched = matches!(
            expected_profile,
            "herdr" | "codex" | "claude" | "t3" | "cursor" | "opencode" | "gemini"
        );
        assert_eq!(
            text.contains("local.schedule"),
            expect_local_sched,
            "local.schedule mismatch in {rel}:\n{text}"
        );
        assert_eq!(
            text.contains("hyp emit"),
            expect_local_sched,
            "hyp emit mismatch in {rel}:\n{text}"
        );
        assert_eq!(
            text.contains("ingest.sock"),
            expect_local_sched,
            "ingest.sock mismatch in {rel}:\n{text}"
        );

        first_snapshots.push((p, text));
    }

    // Specific orchestrator assertions when `all` includes Herdr & T3:
    let claude_txt = read_lf(&home.join(".claude/skills/hyp-mesh/SKILL.md"));
    assert!(claude_txt.contains("transport=claude-or-push"));
    assert!(claude_txt.contains("HC_TERMINAL_ID"));
    assert!(claude_txt.contains("Monitor"));

    let codex_txt = read_lf(&home.join(".agents/skills/hyp-mesh/SKILL.md"));
    assert!(codex_txt.contains("transport=codex-or-push"));
    assert!(codex_txt.contains("codex queue"));
    assert!(!codex_txt.contains("Monitor"));

    let ag_txt = read_lf(&home.join(".gemini/config/plugins/hyphae/skills/hyp-mesh/SKILL.md"));
    assert!(ag_txt.contains("WaitMsBeforeAsync: 500, IsDaemon: false"));
    assert!(ag_txt.contains("PreInvocation"));
    assert!(ag_txt.contains("`schedule`"));

    let oc_txt = read_lf(&home.join(".openclaw/skills/hyp-mesh/SKILL.md"));
    assert!(oc_txt.contains("HEARTBEAT.md"));
    assert!(oc_txt.contains("sessions_send"));
    assert!(!oc_txt.contains("hyp wait"));

    // 3. Re-run `hyp setup --harness all` and verify strict byte-for-byte idempotency!
    let run2 = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "all",
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(run2.status.code(), Some(0));

    for (path, before) in &first_snapshots {
        let after = read_lf(path);
        assert_eq!(
            before,
            &after,
            "runtime skill at {} was not idempotent across repeated hyp setup",
            path.display()
        );
    }
}

#[test]
fn setup_adapts_transport_to_host_orchestrators_and_node_json_capabilities() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&state_dir).unwrap();

    // 1. Standalone Claude & Codex (no Herdr, no T3, no capabilities).
    let out_standalone = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "claude,codex",
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out_standalone.status.code(), Some(0));

    let claude_solo = read_lf(&home.join(".claude/skills/hyp-mesh/SKILL.md"));
    assert!(
        claude_solo.contains("transport=claude-monitor"),
        "expected claude-monitor when Herdr/T3 absent:\n{claude_solo}"
    );
    assert!(claude_solo.contains("Monitor"));

    let codex_solo = read_lf(&home.join(".agents/skills/hyp-mesh/SKILL.md"));
    assert!(
        codex_solo.contains("transport=background-wait"),
        "expected background-wait when Herdr/T3 absent:\n{codex_solo}"
    );
    assert!(codex_solo.contains("hyp wait --session codex:<id>"));
    assert!(!codex_solo.contains("Monitor"));

    // 2. Enable Herdr dir + plugins[] + kvNamespaces[] in node.json!
    fs::create_dir_all(home.join(".config/herdr")).unwrap();
    fs::write(
        state_dir.join("node.json"),
        serde_json::to_string_pretty(&json!({
            "v": 2,
            "nodeId": "alice@testbox",
            "plugins": [
                { "id": "slack", "kind": "bridge", "exec": "/bin/true", "targets": ["ops"] }
            ],
            "kvNamespaces": ["shared"]
        }))
        .unwrap(),
    )
    .unwrap();

    // Refresh skills across claude, codex, openclaw, antigravity, herdr, t3
    let out_caps = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "claude,codex,openclaw,antigravity,herdr,t3",
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--refresh-skills",
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out_caps.status.code(), Some(0));

    // Claude & Codex switched to dual-with-push AND received bridge + kv + local.schedule tip!
    let claude_dual = read_lf(&home.join(".claude/skills/hyp-mesh/SKILL.md"));
    assert!(claude_dual.contains("transport=claude-or-push"));
    assert!(claude_dual.contains("caps=bridge,kv"));
    assert!(claude_dual.contains("`hyp_bridge`"));
    assert!(claude_dual.contains("`hyp_kv`"));
    assert!(claude_dual.contains("local.schedule"));
    assert!(claude_dual.contains("hyp emit"));
    assert!(!claude_dual.contains("hyp_wakeup"));
    assert!(estimated_tokens(&claude_dual) <= MAX_TOKENS);

    let codex_dual = read_lf(&home.join(".agents/skills/hyp-mesh/SKILL.md"));
    assert!(codex_dual.contains("transport=codex-or-push"));
    assert!(codex_dual.contains("caps=bridge,kv"));
    assert!(codex_dual.contains("`hyp_bridge`"));
    assert!(codex_dual.contains("`hyp_kv`"));
    assert!(codex_dual.contains("local.schedule"));
    assert!(codex_dual.contains("hyp emit"));
    assert!(!codex_dual.contains("hyp_wakeup"));
    assert!(!codex_dual.contains("Monitor"));
    assert!(estimated_tokens(&codex_dual) <= MAX_TOKENS);

    // OpenClaw & Antigravity receive bridge + kv, and MUST stay free of local OS schedule clutter!
    for (rel, profile) in [
        (".openclaw/skills/hyp-mesh/SKILL.md", "openclaw"),
        (
            ".gemini/config/plugins/hyphae/skills/hyp-mesh/SKILL.md",
            "antigravity",
        ),
    ] {
        let txt = read_lf(&home.join(rel));
        assert_common_skill_invariants(&home.join(rel), &txt, profile);
        assert!(txt.contains("caps=bridge,kv"), "{rel}:\n{txt}");
        assert!(txt.contains("`hyp_bridge`"), "{rel}:\n{txt}");
        assert!(txt.contains("`hyp_kv`"), "{rel}:\n{txt}");
        assert!(
            !txt.contains("hyp_wakeup")
                && !txt.contains("local.schedule")
                && !txt.contains("hyp emit"),
            "{profile} must suppress local schedule clutter:\n{txt}"
        );
    }

    // `--refresh-skills` did NOT create `.openclaw/openclaw.json` or `.t3/hyphae.json`!
    assert!(!home.join(".openclaw/openclaw.json").exists());
    assert!(!home.join(".t3/hyphae.json").exists());
}

#[test]
fn setup_preserves_unmanaged_skill_unless_force_skills_is_passed() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir_all(&home).unwrap();

    let claude_skill = home.join(".claude/skills/hyp-mesh/SKILL.md");
    fs::create_dir_all(claude_skill.parent().unwrap()).unwrap();
    let custom_skill = "---\nname: hyp-mesh\ndescription: Custom user skill\n---\n<!-- hyphae:unmanaged -->\n# My Custom Rules\n";
    fs::write(&claude_skill, custom_skill).unwrap();

    // 1. Normal `hyp setup --harness claude` preserves the unmanaged skill untouched.
    let out1 = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "claude",
            "--home",
            home.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out1.status.code(), Some(0));
    let json1 = parse_json_stdout(&out1);
    assert_eq!(read_lf(&claude_skill), custom_skill);
    let notes = json1["data"]["harnesses"][0]["notes"].as_array().unwrap();
    assert!(
        notes.iter().any(|n| n
            .as_str()
            .is_some_and(|s| s.contains("Preserved unmanaged skill"))),
        "expected unmanaged preservation note: {json1}"
    );

    // 2. `hyp setup --harness claude --refresh-skills` ALSO preserves unmanaged skill.
    let out2 = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "claude",
            "--home",
            home.to_str().unwrap(),
            "--refresh-skills",
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out2.status.code(), Some(0));
    assert_eq!(read_lf(&claude_skill), custom_skill);

    // 3. `hyp setup --harness claude --refresh-skills --force-skills` overwrites explicitly.
    let out3 = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "claude",
            "--home",
            home.to_str().unwrap(),
            "--refresh-skills",
            "--force-skills",
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(out3.status.code(), Some(0));
    let overwritten = read_lf(&claude_skill);
    assert_common_skill_invariants(&claude_skill, &overwritten, "claude");
}

#[test]
fn static_repo_skill_is_cross_orchestrator_accurate() {
    let repo_skill = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("skills")
        .join("hyp-mesh")
        .join("SKILL.md");
    let text = read_lf(&repo_skill);
    assert!(text.starts_with("---\nname: hyp-mesh\n"));
    assert!(text.contains("Herdr"));
    assert!(text.contains("T3 Code"));
    assert!(text.contains("Claude Code channel notices are best effort"));
    assert!(text.contains("codex queue"));
    assert!(text.contains("do **not** start a background waiter"));
    assert!(text.contains("WaitMsBeforeAsync: 500, IsDaemon: false"));
}

#[test]
fn live_mcp_subprocess_emits_transport_aware_initialize_instructions() {
    struct McpInstrCase<'a> {
        label: &'a str,
        args: Vec<&'a str>,
        envs: Vec<(&'a str, &'a str)>,
        client_name: Option<&'a str>,
        expected_substr: &'a str,
        expect_monitor: bool,
    }

    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let fake_sock = tmp.path().join("unused.sock");
    let sock_str = fake_sock.to_str().unwrap();

    let cases = vec![
        McpInstrCase {
            label: "herdr-backend",
            args: vec!["mcp", sock_str, "--backend", "herdr"],
            envs: vec![],
            client_name: None,
            expected_substr: "Herdr detected: check join hasLiveTransport",
            expect_monitor: false,
        },
        McpInstrCase {
            label: "herdr-env",
            args: vec!["mcp", sock_str],
            envs: vec![("HC_TERMINAL_ID", "t9a")],
            client_name: None,
            expected_substr: "Herdr detected: check join hasLiveTransport",
            expect_monitor: false,
        },
        McpInstrCase {
            label: "t3-backend",
            args: vec!["mcp", sock_str, "--backend", "t3"],
            envs: vec![],
            client_name: None,
            expected_substr: "T3 Code detected: check join hasLiveTransport",
            expect_monitor: false,
        },
        McpInstrCase {
            label: "t3-env",
            args: vec!["mcp", sock_str],
            envs: vec![("T3CODE_URL", "http://127.0.0.1:3773")],
            client_name: None,
            expected_substr: "T3 Code detected: check join hasLiveTransport",
            expect_monitor: false,
        },
        McpInstrCase {
            label: "claude-code-inferred",
            args: vec!["mcp", sock_str],
            envs: vec![],
            client_name: Some("claude-code"),
            expected_substr: "Claude channels are best effort when selected at launch",
            expect_monitor: true,
        },
        McpInstrCase {
            label: "claude-channel",
            args: vec!["mcp", sock_str, "--claude-channel"],
            envs: vec![],
            client_name: None,
            expected_substr: "Claude channels are best effort when selected at launch",
            expect_monitor: true,
        },
        McpInstrCase {
            label: "openclaw",
            args: vec!["mcp", sock_str, "--backend", "openclaw", "--ephemeral"],
            envs: vec![],
            client_name: None,
            expected_substr: "OpenClaw cron/sessions_send",
            expect_monitor: false,
        },
        McpInstrCase {
            label: "antigravity",
            args: vec!["mcp", sock_str, "--backend", "antigravity"],
            envs: vec![],
            client_name: None,
            expected_substr: "WaitMsBeforeAsync: 500",
            expect_monitor: false,
        },
        McpInstrCase {
            label: "claude-standalone",
            args: vec!["mcp", sock_str, "--backend", "claude"],
            envs: vec![],
            client_name: None,
            expected_substr: "Monitor hyp watch",
            expect_monitor: true,
        },
        McpInstrCase {
            label: "default-standalone",
            args: vec!["mcp", sock_str],
            envs: vec![],
            client_name: None,
            expected_substr: "Never poll hyp_inbox",
            expect_monitor: false,
        },
    ];

    for case in cases {
        let McpInstrCase {
            label,
            args,
            envs,
            client_name,
            expected_substr,
            expect_monitor,
        } = case;
        let mut cmd = isolated_cmd(home);
        cmd.env_remove("HC_TERMINAL_ID")
            .env_remove("HERDR_TERMINAL_ID")
            .env_remove("T3CODE_URL")
            .env_remove("T3_URL")
            .env_remove("T3CODE_HOME")
            .args(&args)
            .stdin(Stdio::piped());
        for (k, v) in envs {
            cmd.env(k, v);
        }

        let mut proc = ManagedProcess::spawn(format!("hyp mcp ({label})"), &mut cmd);
        let mut stdin = proc.take_stdin().unwrap();
        let mut params = json!({"protocolVersion": "2025-06-18"});
        if let Some(name) = client_name {
            params["clientInfo"] = json!({"name": name, "version": "fixture"});
        }
        let req = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": params
        });
        writeln!(stdin, "{req}").unwrap();
        stdin.flush().unwrap();

        let resp: Value = proc.read_json_line(Duration::from_secs(5));
        drop(stdin);
        let _ = proc.wait_timeout(Duration::from_secs(3));

        assert_eq!(
            resp["result"]["capabilities"]["experimental"]["claude/channel"].is_object(),
            client_name == Some("claude-code") || args.contains(&"--claude-channel"),
            "{label}: unexpected Claude channel capability",
        );
        let instr = resp["result"]["instructions"]
            .as_str()
            .unwrap_or_else(|| panic!("case {label} missing instructions: {resp}"));
        assert!(
            instr.contains(expected_substr),
            "case {label}: expected '{expected_substr}' in instructions: {instr}"
        );
        assert_eq!(
            instr.contains("Monitor"),
            expect_monitor,
            "case {label}: unexpected Monitor presence in: {instr}"
        );
        assert!(
            instr.contains("untrusted"),
            "case {label}: missing untrusted invariant in: {instr}"
        );
    }
}
