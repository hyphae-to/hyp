//! 100% Pure-Rust end-to-end CLI binary tests for `hyp` (`daemon`, `node start`, `version`,
//! `hook`, `mcp`, `wait`, `watch`, `status`) — ZERO Node.js!
//!
//! Strict isolation invariant: every test runs against ephemeral `tempfile::TempDir`,
//! `HYPHAE_SECRET_BACKEND=file`, isolated `HOME`/`XDG_CONFIG_HOME`, and loopback `127.0.0.1:0`.

use serde_json::{Value, json};
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn hyp_rs_bin() -> &'static str {
    env!("CARGO_BIN_EXE_hyp")
}

fn isolated_cmd(base_dir: &Path) -> Command {
    let mut cmd = Command::new(hyp_rs_bin());
    cmd.env("HYPHAE_SECRET_BACKEND", "file")
        .env("HOME", base_dir)
        .env("USERPROFILE", base_dir)
        .env("XDG_CONFIG_HOME", base_dir.join("xdg"))
        .env_remove("HYPHAE_CONFIG")
        .env_remove("HYPHAE_STATE_DIR")
        .env_remove("HYPHAE_CONFIG_DIR")
        .env_remove("HYPHAE_SOCKET");
    cmd
}

struct NativeRustDaemon {
    tmp: tempfile::TempDir,
    state_dir: PathBuf,
    child: Option<Child>,
    socket_path: Option<PathBuf>,
    startup_envelope: Value,
}

impl NativeRustDaemon {
    #[cfg_attr(not(unix), allow(dead_code))]
    fn shutdown_gracefully(&mut self) -> Option<i32> {
        let mut child = self.child.take()?;
        #[cfg(unix)]
        {
            let pid = child.id().to_string();
            let _ = Command::new("kill").args(["-TERM", &pid]).status();
            let deadline = std::time::Instant::now() + Duration::from_secs(5);
            while std::time::Instant::now() < deadline {
                if let Ok(Some(status)) = child.try_wait() {
                    return status.code();
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
        let _ = child.kill();
        child.wait().ok().and_then(|s| s.code())
    }
}

impl Drop for NativeRustDaemon {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            #[cfg(unix)]
            {
                let pid = child.id().to_string();
                let _ = Command::new("kill").args(["-TERM", &pid]).status();
                let deadline = std::time::Instant::now() + Duration::from_secs(2);
                while std::time::Instant::now() < deadline {
                    if let Ok(Some(_)) = child.try_wait() {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
            let _ = child.kill();
            let _ = child.wait();
        }
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
    .stdin(Stdio::null())
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn native Rust hyp daemon");
    let stdout = child.stdout.take().expect("daemon stdout");
    let mut line = String::new();
    BufReader::new(stdout)
        .read_line(&mut line)
        .expect("read startup JSON envelope line from native Rust daemon");

    let startup_envelope: Value = match serde_json::from_str(line.trim()) {
        Ok(v) => v,
        Err(e) => {
            let _ = child.kill();
            let _ = child.wait();
            let stderr = child
                .stderr
                .take()
                .and_then(|mut s| {
                    let mut buf = String::new();
                    std::io::Read::read_to_string(&mut s, &mut buf).ok()?;
                    Some(buf)
                })
                .unwrap_or_default();
            panic!("invalid startup JSON envelope ({e}): line={line:?}, stderr={stderr}");
        }
    };
    assert_eq!(startup_envelope["ok"], true, "startup failed: {startup_envelope}");
    assert_eq!(startup_envelope["command"], "node start");

    let socket_path = startup_envelope["data"]["socketPath"]
        .as_str()
        .map(PathBuf::from);

    NativeRustDaemon {
        tmp,
        state_dir,
        child: Some(child),
        socket_path,
        startup_envelope,
    }
}

fn start_native_rust_daemon() -> NativeRustDaemon {
    start_native_rust_daemon_with_args(&[])
}

fn run_claude_pre_tool_use_hook(
    base_dir: &Path,
    sock_str: &str,
    session_id: &str,
    tool_use_id: &str,
    tool_name: &str,
    tool_input: Value,
) {
    let mut hook_proc = isolated_cmd(base_dir)
        .args(["hook", "claude", "pre-tool-use", "--socket", sock_str])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hyp hook");
    hook_proc
        .stdin
        .take()
        .unwrap()
        .write_all(
            json!({
                "session_id": session_id,
                "tool_use_id": tool_use_id,
                "tool_name": format!("mcp__hyphae__{tool_name}"),
                "tool_input": tool_input
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
    let out = hook_proc.wait_with_output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(0),
        "hook stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn mcp_rpc(
    mcp_in: &mut std::process::ChildStdin,
    mcp_out: &mut BufReader<std::process::ChildStdout>,
    msg: Value,
) -> Value {
    writeln!(mcp_in, "{msg}").unwrap();
    mcp_in.flush().unwrap();
    let mut line = String::new();
    mcp_out.read_line(&mut line).unwrap();
    serde_json::from_str(line.trim())
        .unwrap_or_else(|e| panic!("invalid JSON-RPC response ({e}): line={line:?}"))
}

#[test]
fn version_plain_and_json_envelope() {
    let plain = Command::new(hyp_rs_bin())
        .arg("version")
        .output()
        .expect("run hyp version");
    assert_eq!(plain.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&plain.stdout).starts_with("hyphae "),
        "stdout: {}",
        String::from_utf8_lossy(&plain.stdout)
    );

    let json_out = Command::new(hyp_rs_bin())
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
    let mut child = Command::new(hyp_rs_bin())
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
    let mut ag_child = Command::new(hyp_rs_bin())
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
    let bad = Command::new(hyp_rs_bin())
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

    // 1. Spawn `hyp mcp <socket>` subprocess
    let mut mcp = isolated_cmd(daemon.tmp.path())
        .args(["mcp", sock_str])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hyp mcp");

    let mut mcp_in = mcp.stdin.take().unwrap();
    let mut mcp_out = BufReader::new(mcp.stdout.take().unwrap());

    let init = mcp_rpc(
        &mut mcp_in,
        &mut mcp_out,
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2025-06-18"}
        }),
    );
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
    writeln!(
        mcp_in,
        "{}",
        json!({"jsonrpc": "2.0", "method": "notifications/initialized"})
    )
    .unwrap();
    mcp_in.flush().unwrap();

    // Verify `tools/list` returns exactly the 4 core tools
    let list = mcp_rpc(
        &mut mcp_in,
        &mut mcp_out,
        json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}),
    );
    let names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["hyp_send", "hyp_inbox", "hyp_mesh", "hyp_stream"]);

    // Verify unverified tool call fails closed with `caller_unverifiable`
    let unverified = mcp_rpc(
        &mut mcp_in,
        &mut mcp_out,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "hyp_mesh",
                "arguments": {"action": "join", "handle": "spoof"}
            }
        }),
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
        sock_str,
        "cli-s1",
        "toolu_cli_1",
        "hyp_mesh",
        json!({"action": "join", "handle": "alice"}),
    );

    let joined_alice = mcp_rpc(
        &mut mcp_in,
        &mut mcp_out,
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
        sock_str,
        "cli-s2",
        "toolu_cli_bob_join",
        "hyp_mesh",
        json!({"action": "join", "handle": "bob"}),
    );
    let joined_bob = mcp_rpc(
        &mut mcp_in,
        &mut mcp_out,
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
    );
    assert!(joined_bob["result"].get("isError").is_none());
    assert!(
        joined_bob["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("cli@local/bob")
    );

    // Arm Alice's zero-polling `hyp wait --json` before Bob sends!
    let wait_live = isolated_cmd(daemon.tmp.path())
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
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn live hyp wait");

    std::thread::sleep(Duration::from_millis(120));

    let dm_text = "hello from native rust daemon subprocess";
    run_claude_pre_tool_use_hook(
        daemon.tmp.path(),
        sock_str,
        "cli-s2",
        "toolu_cli_bob_dm1",
        "hyp_send",
        json!({"to": "cli@local/alice", "text": dm_text}),
    );
    let sent1 = mcp_rpc(
        &mut mcp_in,
        &mut mcp_out,
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
    );
    assert!(
        sent1["result"].get("isError").is_none(),
        "hyp_send failed: {sent1}"
    );

    let wait_out = wait_live.wait_with_output().unwrap();
    assert_eq!(
        wait_out.status.code(),
        Some(0),
        "wait stderr: {}",
        String::from_utf8_lossy(&wait_out.stderr)
    );
    let wait_json: Value = serde_json::from_slice(&wait_out.stdout).unwrap_or_else(|e| {
        panic!(
            "expected valid wait --json output ({e}): stdout={}",
            String::from_utf8_lossy(&wait_out.stdout)
        )
    });
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
        sock_str,
        "cli-s2",
        "toolu_cli_bob_dm2",
        "hyp_send",
        json!({"to": "cli@local/alice", "text": dm_text_2}),
    );
    let sent2 = mcp_rpc(
        &mut mcp_in,
        &mut mcp_out,
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
    );
    assert!(sent2["result"].get("isError").is_none());

    run_claude_pre_tool_use_hook(
        daemon.tmp.path(),
        sock_str,
        "cli-s1",
        "toolu_cli_alice_inbox",
        "hyp_inbox",
        json!({}),
    );
    let inbox = mcp_rpc(
        &mut mcp_in,
        &mut mcp_out,
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

    drop(mcp_in);
    assert_eq!(mcp.wait().unwrap().code(), Some(0));

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
