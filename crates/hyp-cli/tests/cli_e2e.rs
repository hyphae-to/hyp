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

    #[cfg(unix)]
    {
        let _ = peer_proc.shutdown_gracefully();
        let _ = hub_proc.shutdown_gracefully();
    }
    drop(peer_proc);
    drop(hub_proc);
}
