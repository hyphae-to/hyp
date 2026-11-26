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
    assert_eq!(
        names,
        vec!["hyp_send", "hyp_inbox", "hyp_mesh", "hyp_stream"]
    );

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
    let wait_txt = items[0]["text"].as_str().unwrap_or_default();
    assert!(
        wait_txt.contains("<hyphae-inbox ")
            && wait_txt.contains("<dm from=\"cli@local/bob\" count=\"1\"/>"),
        "wait output missing metadata-only XML digest: {wait_json}"
    );
    assert!(
        !wait_txt.contains(dm_text),
        "RFC 0004: wait output must NEVER include raw DM plaintext: {wait_json}"
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

#[test]
fn node_start_parses_kv_namespaces_advertises_manifest_and_mcp_hyp_kv() {
    let tmp = tempfile::tempdir().unwrap();
    let hub_home = tmp.path().join("hub-home");
    let hub_state = tmp.path().join("hub-state");
    let peer_home = tmp.path().join("peer-home");
    let peer_state = tmp.path().join("peer-state");
    fs::create_dir_all(&hub_home).unwrap();
    fs::create_dir_all(&hub_state).unwrap();
    fs::create_dir_all(&peer_home).unwrap();
    fs::create_dir_all(&peer_state).unwrap();

    // 1. Write `node.json` containing both simple string and structured object `kvNamespaces`
    //    (plus a duplicate entry to verify deduplication).
    let config_path = hub_home.join("node.json");
    let node_json = json!({
        "nodeId": "kv-hub",
        "profile": "p2p",
        "kvNamespaces": [
            "shared",
            { "namespace": "deploy-state", "mode": "plaintext", "writeModel": "owner" },
            { "namespace": "ops", "mode": "e2ee", "writeModel": "cas" },
            "shared"
        ]
    });
    fs::write(
        &config_path,
        serde_json::to_string_pretty(&node_json).unwrap(),
    )
    .unwrap();

    // 2. Start compiled `hyp node start --config node.json --bind 127.0.0.1:0`
    let mut hub_cmd = isolated_cmd(&hub_home);
    hub_cmd
        .args([
            "node",
            "start",
            "--config",
            config_path.to_str().unwrap(),
            "--bind",
            "127.0.0.1:0",
            "--state-dir",
            hub_state.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null());
    let mut hub_proc = ManagedProcess::spawn("kv-hub", &mut hub_cmd);
    let hub_startup = hub_proc.read_json_line(Duration::from_secs(10));
    assert_eq!(hub_startup["ok"], true, "hub startup failed: {hub_startup}");
    let hub_socket = PathBuf::from(
        hub_startup["data"]["socketPath"]
            .as_str()
            .expect("p2p node must expose socketPath"),
    );
    let hub_endpoint = hub_startup["data"]["endpoint"]
        .as_str()
        .expect("p2p node must expose HTTP endpoint")
        .to_string();

    // 3. Verify `hyp mcp <socket>` `tools/list` on the node directly advertises `hyp_kv`!
    let mut mcp = McpSubprocess::spawn(&hub_home, &hub_socket);
    let init = mcp.initialize(RPC_TIMEOUT);
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");
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
    assert_eq!(
        names,
        vec!["hyp_send", "hyp_inbox", "hyp_mesh", "hyp_stream", "hyp_kv"],
        "node.json kvNamespaces must advertise hyp_kv in MCP tools/list: {list}"
    );
    assert_eq!(mcp.close(Duration::from_secs(5)), Some(0));

    // 4. Pair a real remote peer (`alice@laptop`) via `hyp pair invite --mode p2p` + live
    //    online `hyp pair accept` and verify the authenticated `/v1/manifest` advertises all 3
    //    parsed KV namespaces!
    let inv_out = isolated_cmd(&hub_home)
        .args([
            "pair",
            "invite",
            "--mode",
            "p2p",
            "--node-id",
            "kv-hub",
            "--endpoint",
            &hub_endpoint,
            "--peer",
            "alice@laptop",
            "--preset",
            "full",
            "--state-dir",
            hub_state.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run hyp pair invite");
    assert_eq!(
        inv_out.status.code(),
        Some(0),
        "pair invite failed: stdout={} stderr={}",
        String::from_utf8_lossy(&inv_out.stdout),
        String::from_utf8_lossy(&inv_out.stderr)
    );
    let inv_json: Value = serde_json::from_slice(&inv_out.stdout).expect("invite JSON");
    let pair_token = inv_json["data"]["token"].as_str().expect("pair token");

    let mut acc_child = isolated_cmd(&peer_home)
        .args([
            "pair",
            "accept",
            "--node-id",
            "alice@laptop",
            "--state-dir",
            peer_state.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hyp pair accept");
    acc_child
        .stdin
        .take()
        .unwrap()
        .write_all(format!("{pair_token}\n").as_bytes())
        .unwrap();
    let acc_out = acc_child.wait_with_output().unwrap();
    assert_eq!(
        acc_out.status.code(),
        Some(0),
        "pair accept failed: stdout={} stderr={}",
        String::from_utf8_lossy(&acc_out.stdout),
        String::from_utf8_lossy(&acc_out.stderr)
    );

    // Inspect cached signed manifest stored on `alice@laptop` after authenticated pairing!
    let peer_db = hyp_store::NodeDb::open(peer_state.join("node.sqlite")).unwrap();
    let hub_peer = peer_db
        .peers()
        .get_peer("kv-hub")
        .unwrap()
        .expect("kv-hub peer persisted");
    let manifest_raw = hub_peer
        .manifest_json
        .expect("authenticated manifest fetched during pairing");
    let signed: hyp_proto::manifest::SignedNodeManifest =
        serde_json::from_str(&manifest_raw).expect("valid signed manifest");
    let payload = signed.decode_payload().expect("valid manifest payload");
    let adv_kv: Vec<(
        &str,
        hyp_proto::manifest::KvMode,
        hyp_proto::manifest::KvWriteModel,
    )> = payload
        .advertised
        .kv_namespaces
        .iter()
        .map(|ns| (ns.name.as_str(), ns.mode, ns.write_model))
        .collect();
    assert_eq!(
        adv_kv,
        vec![
            (
                "shared",
                hyp_proto::manifest::KvMode::E2ee,
                hyp_proto::manifest::KvWriteModel::Shared,
            ),
            (
                "deploy-state",
                hyp_proto::manifest::KvMode::Plaintext,
                hyp_proto::manifest::KvWriteModel::Owner,
            ),
            (
                "ops",
                hyp_proto::manifest::KvMode::E2ee,
                hyp_proto::manifest::KvWriteModel::Shared,
            ),
        ],
        "/v1/manifest advertised.kvNamespaces must match parsed node.json entries"
    );

    // 5. Start a local daemon for `alice@laptop` (no local kvNamespaces!) and prove that the
    //    Hub's advertised manifest automatically causes `alice@laptop`'s `hyp mcp` `tools/list`
    //    to advertise `hyp_kv` as well!
    let mut peer_cmd = isolated_cmd(&peer_home);
    peer_cmd
        .args([
            "node",
            "start",
            "--profile",
            "local",
            "--node-id",
            "alice@laptop",
            "--state-dir",
            peer_state.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null());
    let mut peer_proc = ManagedProcess::spawn("alice-local", &mut peer_cmd);
    let peer_startup = peer_proc.read_json_line(Duration::from_secs(10));
    assert_eq!(peer_startup["ok"], true, "peer startup: {peer_startup}");
    let peer_socket = PathBuf::from(peer_startup["data"]["socketPath"].as_str().unwrap());

    let mut peer_mcp = McpSubprocess::spawn(&peer_home, &peer_socket);
    peer_mcp.initialize(RPC_TIMEOUT);
    let peer_list = peer_mcp.rpc(
        json!({"jsonrpc": "2.0", "id": 3, "method": "tools/list", "params": {}}),
        RPC_TIMEOUT,
    );
    let peer_names: Vec<&str> = peer_list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        peer_names,
        vec!["hyp_send", "hyp_inbox", "hyp_mesh", "hyp_stream", "hyp_kv"],
        "paired peer must inherit hyp_kv tool advertisement from Hub /v1/manifest: {peer_list}"
    );
    assert_eq!(peer_mcp.close(Duration::from_secs(5)), Some(0));

    // 6. Verify invalid `kvNamespaces` entry fails closed with CONFIG_ERROR on `hyp node start`.
    let bad_cfg_path = tmp.path().join("bad-node.json");
    let bad_state = tmp.path().join("bad-state");
    fs::create_dir_all(&bad_state).unwrap();
    fs::write(
        &bad_cfg_path,
        serde_json::to_string(&json!({
            "nodeId": "bad-kv",
            "profile": "local",
            "kvNamespaces": ["INVALID/NAMESPACE"]
        }))
        .unwrap(),
    )
    .unwrap();
    let bad_out = isolated_cmd(tmp.path())
        .args([
            "node",
            "start",
            "--config",
            bad_cfg_path.to_str().unwrap(),
            "--state-dir",
            bad_state.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(bad_out.status.code(), Some(1));
    let bad_env: Value = serde_json::from_slice(&bad_out.stdout).expect("bad error JSON");
    assert_eq!(bad_env["ok"], false);
    assert_eq!(bad_env["error"]["code"], "CONFIG_ERROR");

    peer_proc.shutdown_gracefully();
    hub_proc.shutdown_gracefully();
}

#[test]
fn kv_cli_and_mcp_wake_two_subscribers_under_the_real_node_id() {
    use common::parse_json_stdout;

    let mut daemon = start_native_rust_daemon();
    let home = daemon.tmp.path();
    let state = daemon.state_dir.to_str().unwrap();
    let socket = daemon.socket_path.as_deref().unwrap();
    let sessions = ["kv-first", "kv-coalesced"];
    let mut mcp = McpSubprocess::spawn(home, socket);
    mcp.initialize(RPC_TIMEOUT);

    let call = |mcp: &mut McpSubprocess, session: &str, tool, args: Value| {
        let (text, is_error) =
            mcp.call_verified_claude(home, socket, session, tool, args, RPC_TIMEOUT);
        assert!(!is_error, "{tool}: {text}");
        serde_json::from_str::<Value>(&text).unwrap()
    };
    for (session, coalesce_seconds) in [(sessions[0], 0), (sessions[1], 1)] {
        call(
            &mut mcp,
            session,
            "hyp_mesh",
            json!({"action":"join", "handle": session}),
        );
        let subscription = call(
            &mut mcp,
            session,
            "hyp_stream",
            json!({"action":"subscribe", "topic":"local.kv", "coalesceSeconds":coalesce_seconds}),
        );
        assert_eq!(subscription["topic"], "kv");
    }

    let kv = |args: &[&str]| {
        let output = isolated_cmd(home)
            .arg("kv")
            .args(args)
            .args(["--ns", "shared", "--state-dir", state, "--json"])
            .output()
            .unwrap();
        (output.status.code(), parse_json_stdout(&output))
    };
    let arm_waiters = || {
        sessions.map(|session| {
            let full_id = format!("claude:{session}");
            let mut cmd = isolated_cmd(home);
            cmd.args([
                "wait",
                "--session",
                &full_id,
                "--socket",
                socket.to_str().unwrap(),
                "--timeout",
                "8",
                "--json",
            ])
            .stdin(Stdio::null());
            let waiter = ManagedProcess::spawn("hyp wait (KV subscription)", &mut cmd);
            wait_for_session_live(socket, &full_id, Duration::from_secs(5));
            waiter
        })
    };
    let assert_wakes =
        |mcp: &mut McpSubprocess, waiters: [ManagedProcess; 2], key: &str, event_type| {
            for (session, mut waiter) in sessions.into_iter().zip(waiters) {
                let (status, wake) = waiter.wait_json_output(RPC_TIMEOUT);
                assert!(status.success(), "{session} missed the wake: {wake}");
                let digest = wake["data"]["items"][0]["text"].as_str().unwrap();
                assert!(
                    digest.contains("<hyphae-inbox") && digest.contains("topic=\"local.kv\""),
                    "{wake}"
                );
                assert!(!digest.contains(key), "{wake}");
                let inbox = call(mcp, session, "hyp_inbox", json!({}));
                let payload: Value =
                    serde_json::from_str(inbox["items"][0]["text"].as_str().unwrap()).unwrap();
                assert_eq!(payload["originNode"], "cli@local");
                assert_eq!(payload["topic"], "kv");
                assert_eq!(payload["events"].as_array().unwrap().len(), 1);
                assert_eq!(payload["events"][0]["type"], event_type);
                assert_eq!(payload["events"][0]["key"], key);
            }
        };

    let waiters = arm_waiters();
    let (status, set) = kv(&[
        "set",
        "--key",
        "cli-key",
        "--value",
        "42",
        "--write-model",
        "shared",
        "--ttl-seconds",
        "120",
    ]);
    assert_eq!(status, Some(0), "{set}");
    assert_eq!(set["data"]["hostNode"], "cli@local");
    assert_eq!(
        set["data"]["expiresAt"].as_i64().unwrap() - set["data"]["updatedAt"].as_i64().unwrap(),
        120_000
    );
    assert_wakes(&mut mcp, waiters, "cli-key", "to.hyphae.kv.set");

    let (status, conflict) = kv(&[
        "set",
        "--key",
        "cli-key",
        "--value",
        "0",
        "--expected-version",
        "0",
    ]);
    assert_eq!(status, Some(1));
    assert_eq!(conflict["error"]["code"], "VERSION_CONFLICT");
    assert_eq!(conflict["data"]["currentVersion"], 1);
    let (status, get) = kv(&["get", "--key", "cli-key", "--node", "local"]);
    assert_eq!(status, Some(0), "{get}");
    assert_eq!(get["data"]["hostNode"], "cli@local");
    assert_eq!(get["data"]["value"], 42);
    let (status, list) = kv(&["list", "--prefix", "cli-"]);
    assert_eq!(status, Some(0), "{list}");
    assert_eq!(list["data"]["entries"][0]["key"], "cli-key");

    let waiters = arm_waiters();
    let (status, delete) = kv(&["delete", "--key", "cli-key", "--expected-version", "1"]);
    assert_eq!(status, Some(0), "{delete}");
    assert_eq!(delete["data"]["deleted"], true);
    assert_wakes(&mut mcp, waiters, "cli-key", "to.hyphae.kv.deleted");

    let waiters = arm_waiters();
    let set = call(
        &mut mcp,
        sessions[0],
        "hyp_kv",
        json!({"action":"set","node":"local","namespace":"shared","key":"mcp-key","value":true,"writeModel":"shared"}),
    );
    assert_eq!(set["entry"]["host_node"], "cli@local");
    assert_wakes(&mut mcp, waiters, "mcp-key", "to.hyphae.kv.set");

    let waiters = arm_waiters();
    call(
        &mut mcp,
        sessions[1],
        "hyp_kv",
        json!({"action":"delete","node":"local","namespace":"shared","key":"mcp-key","expectedVersion":1}),
    );
    assert_wakes(&mut mcp, waiters, "mcp-key", "to.hyphae.kv.deleted");

    assert_eq!(mcp.close(RPC_TIMEOUT), Some(0));
    daemon.proc.shutdown_gracefully();
    let (status, offline) = kv(&["set", "--key", "offline-key", "--value", "1"]);
    assert_eq!(status, Some(0), "{offline}");
    assert_eq!(offline["data"]["hostNode"], "cli@local");
    let (status, offline) = kv(&["get", "--key", "offline-key"]);
    assert_eq!(status, Some(0), "{offline}");
    assert_eq!(offline["data"]["value"], 1);

    {
        use hyp_store::{KvSetInput, NodeDb, WriteModel, now_ms};

        let db = NodeDb::open(daemon.state_dir.join("node.sqlite")).unwrap();
        db.kv()
            .set(
                &KvSetInput {
                    host_node: "local".into(),
                    namespace: "legacy".into(),
                    key: "old-key".into(),
                    value: json!(0),
                    content_type: None,
                    write_model: WriteModel::Owner,
                    owner_id: None,
                    allowlist: None,
                    writer_id: "cli@local".into(),
                    expected_version: None,
                    e2ee_epoch: None,
                    signature: None,
                    ttl_ms: None,
                },
                now_ms(),
            )
            .unwrap();
    }
    let status = isolated_cmd(home)
        .args(["status", "--state-dir", state, "--json"])
        .output()
        .unwrap();
    let status = parse_json_stdout(&status);
    assert_eq!(
        status["data"]["node"]["kvNamespaces"],
        json!(["legacy", "shared"])
    );

    // A bogus TCP endpoint must receive only the nonce, and the CLI must
    // surface the failed exchange without retrying the mutation in SQLite.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr_file = daemon.state_dir.join("connector.addr");
    fs::write(&addr_file, listener.local_addr().unwrap().to_string()).unwrap();
    listener.set_nonblocking(true).unwrap();
    let fake_daemon = std::thread::spawn(move || {
        use std::io::{BufRead, BufReader, ErrorKind};
        use std::time::Instant;

        let deadline = Instant::now() + RPC_TIMEOUT;
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(err) if err.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(err) => panic!("failed to accept KV request: {err}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream.set_read_timeout(Some(RPC_TIMEOUT)).unwrap();
        let mut request = String::new();
        BufReader::new(stream).read_line(&mut request).unwrap();
        let packet: Value = serde_json::from_str(&request).unwrap();
        assert_eq!(packet["type"], "kv.local.challenge");
        assert!(packet.get("request").is_none());
        assert!(!request.contains("ambiguous-key"));
    });
    let (status, error) = kv(&["set", "--key", "ambiguous-key", "--value", "1"]);
    assert_eq!(status, Some(1), "{error}");
    assert_eq!(error["error"]["code"], "DAEMON_ERROR");
    fake_daemon.join().unwrap();
    fs::remove_file(addr_file).unwrap();
    let (status, missing) = kv(&["get", "--key", "ambiguous-key"]);
    assert_eq!(status, Some(1), "{missing}");
    assert_eq!(missing["error"]["code"], "NOT_FOUND");
}

#[tokio::test(flavor = "multi_thread")]
async fn kv_cli_authenticates_over_loopback_tcp() {
    use hyp_crypto::X25519KeyPair;
    use hyp_crypto::e2ee::{EpochMember, EpochScope, create_epoch_bundle};
    use hyp_crypto::keystore::SecretBackend;
    use hyp_harness::daemon::{LocalDaemon, LocalDaemonConfig};
    use hyp_harness::sock::daemon_rpc_async;
    use hyp_node::engine::{KvWriteRequest, NodeConfig, UnifiedNode};
    use hyp_proto::address::NodeId;
    use std::sync::Arc;

    let home = tempfile::tempdir().expect("tempdir");
    let state = home.path().join("state");
    let socket = state.join("connector.addr");
    let mut config = NodeConfig::local(NodeId::new("owner@local").unwrap(), &state);
    config.secret_backend = Some(SecretBackend::File);
    let node = UnifiedNode::open(config).unwrap();
    let daemon = LocalDaemon::start_tcp(
        Arc::clone(&node),
        None,
        LocalDaemonConfig::default(),
        socket.clone(),
    )
    .await
    .unwrap();

    let cli = |args: &[&str]| {
        let out = isolated_cmd(home.path())
            .args(["kv"])
            .args(args)
            .args(["--state-dir", state.to_str().unwrap(), "--json"])
            .output()
            .unwrap();
        let envelope: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(out.status.code(), Some(0), "{envelope}");
        envelope
    };
    let inspect = || {
        let out = isolated_cmd(home.path())
            .args([
                "inspect",
                "--all",
                "--socket",
                socket.to_str().unwrap(),
                "--json",
            ])
            .output()
            .unwrap();
        assert!(out.status.success());
        serde_json::from_slice::<Value>(&out.stdout).unwrap()
    };
    assert_eq!(inspect()["data"]["kv"]["namespaces"], json!([]));
    cli(&[
        "set",
        "--ns",
        "test",
        "--key",
        "guarded",
        "--value",
        "1",
        "--writer",
        "owner@local",
    ]);

    for request in [
        json!({ "action": "get", "key": "guarded" }),
        json!({ "action": "list" }),
        json!({ "action": "inspect" }),
        json!({ "action": "preview", "key": "guarded" }),
        json!({ "action": "set", "key": "guarded", "writeModel": "owner", "writer": "owner@local", "value": 2 }),
        json!({ "action": "delete", "key": "guarded", "writer": "owner@local" }),
    ] {
        let mut request = request.as_object().unwrap().clone();
        request.insert("hostNode".into(), json!("local"));
        request.insert("namespace".into(), json!("test"));
        let result = daemon_rpc_async(
            &socket,
            &json!({ "type": "kv.local", "request": request }),
            RPC_TIMEOUT,
        )
        .await;
        assert_eq!(
            result.error.as_deref(),
            Some("Local KV authentication failed.")
        );
    }
    let payload = "🔐".repeat(1200);
    node.kv_set(KvWriteRequest {
        host_node: "local".into(),
        namespace: "sealed".into(),
        key: "note".into(),
        value: json!(payload),
        write_model: hyp_store::WriteModel::Owner,
        owner_id: None,
        allowlist: None,
        expected_version: None,
        ttl_ms: None,
        encrypt: true,
        e2ee_members: None,
    })
    .await
    .unwrap();

    let filters = [
        hyp_store::Filter::All(vec![hyp_store::Filter::exact("ns", "sealed")]),
        hyp_store::Filter::Not(Box::new(hyp_store::Filter::exact("ns", "test"))),
        hyp_store::Filter::Any(vec![
            hyp_store::Filter::exact("ns", "other"),
            hyp_store::Filter::prefix("key", "watch/"),
        ]),
    ];
    for (index, filter) in filters.into_iter().enumerate() {
        node.db()
            .events()
            .upsert_subscription(
                &hyp_store::SubscriptionSpec {
                    id: format!("watch-{index}"),
                    origin_node: "owner@local".into(),
                    topic: "kv".into(),
                    subscriber: "claude:kv-inspect".into(),
                    filters: vec![filter],
                    coalesce_seconds: 0,
                    max_batch_age_ms: None,
                    max_wakes_per_hour: None,
                    mode: hyp_store::DeliveryMode::Full,
                },
                hyp_store::now_ms(),
            )
            .unwrap();
    }

    let unsecured =
        daemon_rpc_async(&socket, &json!({ "type": "sessions.summary" }), RPC_TIMEOUT).await;
    assert!(unsecured.ok);
    assert!(!unsecured.result.unwrap().contains_key("kv"));
    let inspection = inspect();
    let namespaces = inspection["data"]["kv"]["namespaces"].as_array().unwrap();
    assert_eq!(namespaces.len(), 2);
    assert_eq!(namespaces[0]["name"], "sealed");
    assert_eq!(namespaces[0]["epoch"], 1);
    assert_eq!(namespaces[0]["memberCount"], 1);
    assert_eq!(namespaces[0]["entryCount"], 1);
    assert_eq!(namespaces[0]["watchCount"], 3);
    assert_eq!(namespaces[1]["watchCount"], 1);
    assert_eq!(namespaces[0]["entries"][0]["key"], "note");
    assert_eq!(namespaces[0]["entries"][0]["version"], 1);
    assert!(!inspection.to_string().contains("🔐"));

    let preview = cli(&["preview", "--ns", "sealed", "--key", "note"]);
    assert_eq!(preview["data"]["text"], "🔐".repeat(1024));
    assert_eq!(preview["data"]["truncated"], true);

    // The database's separate members list is not an authorization source.
    let other = X25519KeyPair::generate().unwrap().public_key();
    let (_, next_epoch) = create_epoch_bundle(
        EpochScope::Kv,
        "owner@local",
        "sealed",
        2,
        "owner@local",
        &node.identity().signing,
        &[EpochMember {
            node_id: "other@local",
            enc_pk: &other,
        }],
    )
    .unwrap();
    node.db()
        .kv()
        .put_epoch(
            &hyp_store::KvEpochInput {
                host_node: "owner@local".into(),
                namespace: "sealed".into(),
                epoch: 2,
                creator_node_id: "owner@local".into(),
                key_envelope_json: serde_json::to_string(&next_epoch).unwrap(),
                members: vec!["owner@local".into()],
                signature: next_epoch.sig,
            },
            hyp_store::now_ms(),
        )
        .unwrap();
    assert_eq!(
        inspect()["data"]["kv"]["namespaces"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(
        node.preview_kv("local", "sealed", "note")
            .await
            .unwrap()
            .is_none()
    );
    node.db()
        .kv()
        .set(
            &hyp_store::KvSetInput {
                host_node: "owner@local".into(),
                namespace: "sealed".into(),
                key: "hidden".into(),
                value: json!({"encrypted": "opaque"}),
                content_type: Some(hyp_proto::cloudevent::CONTENT_TYPE_E2EE_JSON.into()),
                write_model: hyp_store::WriteModel::Owner,
                owner_id: None,
                allowlist: None,
                writer_id: "owner@local".into(),
                expected_version: None,
                e2ee_epoch: Some(2),
                signature: None,
                ttl_ms: None,
            },
            hyp_store::now_ms(),
        )
        .unwrap();
    let self_key = node.identity().encryption.public_key();
    let (_, own_epoch) = create_epoch_bundle(
        EpochScope::Kv,
        "owner@local",
        "sealed",
        3,
        "owner@local",
        &node.identity().signing,
        &[EpochMember {
            node_id: "owner@local",
            enc_pk: &self_key,
        }],
    )
    .unwrap();
    node.db()
        .kv()
        .put_epoch(
            &hyp_store::KvEpochInput {
                host_node: "owner@local".into(),
                namespace: "sealed".into(),
                epoch: 3,
                creator_node_id: "owner@local".into(),
                key_envelope_json: serde_json::to_string(&own_epoch).unwrap(),
                members: vec!["owner@local".into()],
                signature: own_epoch.sig,
            },
            hyp_store::now_ms(),
        )
        .unwrap();
    let own_inspection = inspect();
    let sealed = &own_inspection["data"]["kv"]["namespaces"][0];
    assert_eq!(sealed["name"], "sealed");
    assert_eq!(sealed["epoch"], 3);
    assert_eq!(sealed["entryCount"], 1);
    assert_eq!(sealed["entries"][0]["key"], "note");
    assert!(
        node.preview_local_kv("sealed", "hidden")
            .await
            .unwrap()
            .is_none()
    );

    let read = cli(&["get", "--ns", "test", "--key", "guarded"]);
    assert_eq!(read["data"]["value"], 1, "{read}");
    let deleted = cli(&["delete", "--ns", "test", "--key", "guarded"]);
    assert_eq!(deleted["data"]["deleted"], true, "{deleted}");

    daemon.stop().await;
    node.shutdown();
}

#[cfg(unix)]
#[test]
fn kv_cli_does_not_retry_a_mutation_when_daemon_reply_is_lost() {
    use hyp_store::NodeDb;
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixListener;

    let home = tempfile::tempdir().expect("tempdir");
    let state = home.path().join("state");
    fs::create_dir(&state).unwrap();
    let db_path = state.join("node.sqlite");
    let db = NodeDb::open(&db_path).unwrap();
    let listener = UnixListener::bind(state.join("connector.sock")).unwrap();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(RPC_TIMEOUT)).unwrap();
        let mut line = String::new();
        BufReader::new(stream).read_line(&mut line).unwrap();
        let packet: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(packet["type"], "kv.local");
        let request: hyp_harness::local_kv::LocalKvRequest =
            serde_json::from_value(packet["request"].clone()).unwrap();
        request.execute(&db, "owner@local").unwrap();
    });

    let out = isolated_cmd(home.path())
        .args([
            "kv",
            "set",
            "--ns",
            "test",
            "--key",
            "guarded",
            "--value",
            "1",
            "--node",
            "owner@local",
            "--state-dir",
            state.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    server.join().unwrap();
    let envelope: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(out.status.code(), Some(1), "{envelope}");
    assert_eq!(envelope["error"]["code"], "DAEMON_ERROR");
    let entry = NodeDb::open(&db_path)
        .unwrap()
        .kv()
        .get("owner@local", "test", "guarded", hyp_store::now_ms())
        .unwrap()
        .unwrap();
    assert_eq!(entry.version, 1);
}
