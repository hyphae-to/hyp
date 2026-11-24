//! 100% Pure-Rust end-to-end CLI binary tests for `hyp` (`daemon`, `node start`, `version`,
//! `hook`, `mcp`, `wait`, `watch`, `status`) — ZERO Node.js!
//!
//! Strict isolation invariant: every test runs against ephemeral `tempfile::TempDir`,
//! `HYPHAE_SECRET_BACKEND=file`, isolated `HOME`/`XDG_CONFIG_HOME`, full `HYPHAE_*` env
//! scrubbing, bounded-timeout process I/O, and deterministic transport readiness polling.

mod common;

use common::{
    ManagedProcess, McpSubprocess, hyp_bin, isolated_cmd, run_claude_pre_tool_use_hook,
    wait_for_session_live,
};
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

const RPC_TIMEOUT: Duration = Duration::from_secs(10);

struct NativeRustDaemon {
    tmp: tempfile::TempDir,
    state_dir: PathBuf,
    proc: ManagedProcess,
    socket_path: Option<PathBuf>,
    startup_envelope: Value,
}

impl NativeRustDaemon {
    #[cfg_attr(not(unix), allow(dead_code))]
    fn shutdown_gracefully(&mut self) -> Option<i32> {
        self.proc.shutdown_gracefully()
    }
}

fn start_native_rust_daemon_with_args(extra_args: &[&str]) -> NativeRustDaemon {
    let tmp = tempfile::tempdir().expect("tempdir");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap();

    let mut cmd = isolated_cmd(tmp.path());
    cmd.args([
        "daemon",
        "--profile",
        "local",
        "--node-id",
        "cli@local",
        "--state-dir",
        state_dir.to_str().unwrap(),
        "--json",
    ])
    .args(extra_args)
    .stdin(Stdio::null());

    let proc = ManagedProcess::spawn("hyp daemon", &mut cmd);
    let startup_envelope = proc.read_json_line(Duration::from_secs(10));
    assert_eq!(
        startup_envelope["ok"], true,
        "startup failed: {startup_envelope}"
    );
    assert_eq!(startup_envelope["command"], "node start");

    let socket_path = startup_envelope["data"]["socketPath"]
        .as_str()
        .map(PathBuf::from);

    NativeRustDaemon {
        tmp,
        state_dir,
        proc,
        socket_path,
        startup_envelope,
    }
}

fn start_native_rust_daemon() -> NativeRustDaemon {
    start_native_rust_daemon_with_args(&[])
}

#[test]
fn version_plain_and_json_envelope() {
    let plain = Command::new(hyp_bin())
        .arg("version")
        .output()
        .expect("run hyp version");
    assert_eq!(plain.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&plain.stdout).starts_with("hyphae "),
        "stdout: {}",
        String::from_utf8_lossy(&plain.stdout)
    );

    let json_out = Command::new(hyp_bin())
        .args(["version", "--json"])
        .output()
        .expect("run hyp version --json");
    assert_eq!(json_out.status.code(), Some(0));
    let env: Value = serde_json::from_slice(&json_out.stdout).expect("valid JSON envelope");
    assert_eq!(env["ok"], true);
    assert_eq!(env["command"], "version");
    assert_eq!(env["data"]["name"], "hyphae");
    assert_eq!(env["data"]["protocol"], 2);
}

#[test]
fn hook_fast_path_fails_safe_and_validates_usage() {
    let dir = tempfile::tempdir().unwrap();
    let missing_sock = dir.path().join("missing.sock");

    // Claude PostToolUse (PascalCase alias) with offline daemon -> fail-safe `{}` and exit 0
    let mut child = isolated_cmd(dir.path())
        .args([
            "hook",
            "claude",
            "PostToolUse",
            "--socket",
            missing_sock.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn hyp hook");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(br#"{"session_id":"s1","tool_use_id":"u1","tool_name":"hyp_send"}"#)
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "{}");

    // Antigravity PreToolUse with malformed stdin -> fail-safe `{"decision":"allow"}` and exit 0
    let mut ag_child = isolated_cmd(dir.path())
        .args([
            "hook",
            "antigravity",
            "PreToolUse",
            "--socket",
            missing_sock.to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn hyp hook antigravity");
    ag_child
        .stdin
        .take()
        .unwrap()
        .write_all(b"{not-json")
        .unwrap();
    let ag_out = ag_child.wait_with_output().unwrap();
    assert_eq!(ag_out.status.code(), Some(0));
    let ag_json: Value = serde_json::from_slice(&ag_out.stdout).unwrap();
    assert_eq!(ag_json, json!({"decision": "allow"}));

    // Invalid harness -> exit code 2
    let bad = isolated_cmd(dir.path())
        .args(["hook", "nonexistent", "PostToolUse"])
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(2));
}

#[test]
fn cli_subprocesses_mcp_hook_and_wait_interop() {
    #[cfg_attr(not(unix), allow(unused_mut))]
    let mut daemon = start_native_rust_daemon();
    let socket_path = daemon
        .socket_path
        .clone()
        .expect("local profile must start LocalDaemon and report socketPath");
    assert!(
        socket_path.exists(),
        "local daemon socket must exist at {}",
        socket_path.display()
    );
    let sock_str = socket_path.to_str().unwrap();

    // Verify `node.status.json` and `hyp status --json` expose `socketPath`.
    let status_file: Value = serde_json::from_str(
        &fs::read_to_string(daemon.state_dir.join("node.status.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(status_file["socketPath"], sock_str);
    assert_eq!(daemon.startup_envelope["data"]["socketPath"], sock_str);

    let status_out = isolated_cmd(daemon.tmp.path())
        .args([
            "status",
            "--state-dir",
            daemon.state_dir.to_str().unwrap(),
            "--home",
            daemon.tmp.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(status_out.status.code(), Some(0));
    let status_json: Value = serde_json::from_slice(&status_out.stdout).unwrap();
    assert_eq!(status_json["ok"], true);
    assert_eq!(status_json["data"]["node"]["socketPath"], sock_str);

    // 1. Spawn `hyp mcp <socket>` subprocess with bounded-timeout RPCs
    let mut mcp = McpSubprocess::spawn(daemon.tmp.path(), &socket_path);
    let init = mcp.initialize(RPC_TIMEOUT);
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");

    // Verify `tools/list` returns exactly the 4 core tools
    let list = mcp.rpc(
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
        RPC_TIMEOUT,
    );
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["hyp_send", "hyp_inbox", "hyp_mesh", "hyp_stream"]);

    // Verify unverified tool call fails closed with `caller_unverifiable`
    let unverified = mcp.rpc(
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "hyp_mesh",
                "arguments": {"action": "join", "handle": "spoof"}
            }
        }),
        RPC_TIMEOUT,
    );
    assert_eq!(unverified["result"]["isError"], true);
    assert!(
        unverified["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("caller_unverifiable")
    );

    // 2. Run real `hyp hook claude pre-tool-use` binary to register Alice's join call
    run_claude_pre_tool_use_hook(
        daemon.tmp.path(),
        &socket_path,
        "cli-s1",
        "toolu_cli_1",
        "hyp_mesh",
        json!({"action": "join", "handle": "alice"}),
    );

    let joined_alice = mcp.rpc(
        json!({
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "hyp_mesh",
                "arguments": {"action": "join", "handle": "alice"},
                "_meta": {"claudecode/toolUseId": "toolu_cli_1"}
            }
        }),
        RPC_TIMEOUT,
    );
    assert!(joined_alice["result"].get("isError").is_none());
    assert!(
        joined_alice["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("cli@local/alice")
    );

    // 3. Run real `hyp wait --session claude:cli-s1 --timeout 0.1` -> exits 0 cleanly on timeout
    let wait_timeout = isolated_cmd(daemon.tmp.path())
        .args([
            "wait",
            "--session",
            "claude:cli-s1",
            "--socket",
            sock_str,
            "--timeout",
            "0.1",
        ])
        .output()
        .unwrap();
    assert_eq!(wait_timeout.status.code(), Some(0));

    // 4. End-to-end delivery through the compiled Rust daemon: Bob joins, sends DM waking Alice's live `hyp wait`!
    run_claude_pre_tool_use_hook(
        daemon.tmp.path(),
        &socket_path,
        "cli-s2",
        "toolu_cli_bob_join",
        "hyp_mesh",
        json!({"action": "join", "handle": "bob"}),
    );
    let joined_bob = mcp.rpc(
        json!({
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "hyp_mesh",
                "arguments": {"action": "join", "handle": "bob"},
                "_meta": {"claudecode/toolUseId": "toolu_cli_bob_join"}
            }
        }),
        RPC_TIMEOUT,
    );
    assert!(joined_bob["result"].get("isError").is_none());
    assert!(
        joined_bob["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("cli@local/bob")
    );

    // Arm Alice's zero-polling `hyp wait --json` before Bob sends and wait deterministically for live transport!
    let mut wait_cmd = isolated_cmd(daemon.tmp.path());
    wait_cmd
        .args([
            "wait",
            "--session",
            "claude:cli-s1",
            "--socket",
            sock_str,
            "--timeout",
            "5",
            "--json",
        ])
        .stdin(Stdio::null());
    let mut wait_live = ManagedProcess::spawn("hyp wait (alice)", &mut wait_cmd);

    wait_for_session_live(&socket_path, "claude:cli-s1", Duration::from_secs(5));

    let dm_text = "hello from native rust daemon subprocess";
    run_claude_pre_tool_use_hook(
        daemon.tmp.path(),
        &socket_path,
        "cli-s2",
        "toolu_cli_bob_dm1",
        "hyp_send",
        json!({"to": "cli@local/alice", "text": dm_text}),
    );
    let sent1 = mcp.rpc(
        json!({
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "hyp_send",
                "arguments": {"to": "cli@local/alice", "text": dm_text},
                "_meta": {"claudecode/toolUseId": "toolu_cli_bob_dm1"}
            }
        }),
        RPC_TIMEOUT,
    );
    assert!(
        sent1["result"].get("isError").is_none(),
        "hyp_send failed: {sent1}"
    );

    let (wait_status, wait_json) = wait_live.wait_json_output(Duration::from_secs(6));
    assert_eq!(wait_status.code(), Some(0));
    assert_eq!(wait_json["ok"], true);
    assert_eq!(wait_json["command"], "wait");
    let items = wait_json["data"]["items"].as_array().unwrap();
    assert!(!items.is_empty(), "expected woken wait items: {wait_json}");
    assert!(
        items
            .iter()
            .any(|i| i["text"].as_str().unwrap_or_default().contains(dm_text)),
        "wait output missing DM text: {wait_json}"
    );

    // 5. Bob sends a second DM; Alice drains it through `hyp_inbox`!
    let dm_text_2 = "second native inbox message";
    run_claude_pre_tool_use_hook(
        daemon.tmp.path(),
        &socket_path,
        "cli-s2",
        "toolu_cli_bob_dm2",
        "hyp_send",
        json!({"to": "cli@local/alice", "text": dm_text_2}),
    );
    let sent2 = mcp.rpc(
        json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "hyp_send",
                "arguments": {"to": "cli@local/alice", "text": dm_text_2},
                "_meta": {"claudecode/toolUseId": "toolu_cli_bob_dm2"}
            }
        }),
        RPC_TIMEOUT,
    );
    assert!(sent2["result"].get("isError").is_none());

    run_claude_pre_tool_use_hook(
        daemon.tmp.path(),
        &socket_path,
        "cli-s1",
        "toolu_cli_alice_inbox",
        "hyp_inbox",
        json!({}),
    );
    let inbox = mcp.rpc(
        json!({
            "jsonrpc": "2.0",
            "id": 8,
            "method": "tools/call",
            "params": {
                "name": "hyp_inbox",
                "arguments": {},
                "_meta": {"claudecode/toolUseId": "toolu_cli_alice_inbox"}
            }
        }),
        RPC_TIMEOUT,
    );
    assert!(inbox["result"].get("isError").is_none());
    assert!(
        inbox["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains(dm_text_2),
        "hyp_inbox response missing second DM: {inbox}"
    );

    // 6. Verify piped one-shot stdin EOF drains in-flight `tools/list` cleanly before exiting
    let mut oneshot = isolated_cmd(daemon.tmp.path())
        .args(["mcp", sock_str])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    oneshot
        .stdin
        .take()
        .unwrap()
        .write_all(b"{\"jsonrpc\":\"2.0\",\"id\":42,\"method\":\"tools/list\",\"params\":{}}\n")
        .unwrap();
    let oneshot_out = oneshot.wait_with_output().unwrap();
    assert_eq!(oneshot_out.status.code(), Some(0));
    let oneshot_json: Value =
        serde_json::from_slice(&oneshot_out.stdout).expect("piped tools/list JSON");
    assert_eq!(oneshot_json["id"], 42);
    assert_eq!(oneshot_json["result"]["tools"].as_array().unwrap().len(), 4);

    assert_eq!(mcp.close(Duration::from_secs(5)), Some(0));

    // 7. Verify graceful shutdown removes socket, node.pid, and node.status.json cleanly on Unix
    #[cfg(unix)]
    {
        let exit_code = daemon.shutdown_gracefully();
        assert_eq!(exit_code, Some(0));
        assert!(
            !socket_path.exists(),
            "connector.sock must be removed on graceful shutdown"
        );
        assert!(
            !daemon.state_dir.join("node.pid").exists(),
            "node.pid must be removed on graceful shutdown"
        );
        assert!(
            !daemon.state_dir.join("node.status.json").exists(),
            "node.status.json must be removed on graceful shutdown"
        );
    }
}

#[test]
fn daemon_socket_and_no_local_socket_flags() {
    // 1. Explicit `--socket <custom>` overrides default location
    let custom_dir = tempfile::tempdir().unwrap();
    let custom_sock = custom_dir.path().join("custom.sock");
    let daemon = start_native_rust_daemon_with_args(&["--socket", custom_sock.to_str().unwrap()]);
    assert_eq!(daemon.socket_path.as_deref(), Some(custom_sock.as_path()));
    assert!(custom_sock.exists());
    drop(daemon);

    // 2. `--no-local-socket` disables local IPC listener completely (`socketPath: null`)
    let headless = start_native_rust_daemon_with_args(&["--no-local-socket"]);
    assert!(headless.socket_path.is_none());
    assert!(headless.startup_envelope["data"]["socketPath"].is_null());
    assert!(!headless.state_dir.join("connector.sock").exists());
    assert!(!headless.state_dir.join("connector.addr").exists());
}
