//! End-to-end CLI binary tests for `hyp-rs` (`version`, `hook`, `mcp`, `wait`, `watch`).

use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

fn hyp_rs_bin() -> &'static str {
    env!("CARGO_BIN_EXE_hyp-rs")
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

struct LiveTsDaemon {
    _tmp: tempfile::TempDir,
    child: Child,
    socket_path: PathBuf,
}

impl Drop for LiveTsDaemon {
    fn drop(&mut self) {
        let _ = self.child.stdin.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_live_ts_daemon() -> LiveTsDaemon {
    let tmp = tempfile::tempdir().expect("tempdir");
    let root = repo_root();
    let dir_str = tmp.path().to_str().unwrap();

    let bootstrap_js = r#"
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { RouterCore } from "./src/core/router/core.ts";
import { serveRouter } from "./src/core/router/server.ts";
import { startDaemon } from "./src/daemon.ts";

const dir = process.env.HYPHAE_TEST_DIR;
const routerCore = new RouterCore({ dbPath: join(dir, "router.sqlite") });
const token = routerCore.addConnector("cli@local");
const router = await serveRouter({ core: routerCore, host: "127.0.0.1", port: 0 });
const stateDir = join(dir, "state");
mkdirSync(stateDir, { mode: 0o700, recursive: true });
const daemon = await startDaemon({
  connectorId: "cli@local",
  directory: stateDir,
  routers: [{ name: "primary", url: router.url, token }],
}, { quiet: true });

process.stdout.write(JSON.stringify({ socketPath: daemon.socketPath }) + "\n");

const shutdown = async () => {
  try { await daemon.stop(); } catch {}
  try { await router.close(); } catch {}
  try { routerCore.close(); } catch {}
  process.exit(0);
};
process.stdin.resume();
process.stdin.on("end", () => { void shutdown(); });
process.on("SIGTERM", () => { void shutdown(); });
"#;

    let mut child = Command::new("node")
        .arg("--experimental-strip-types")
        .arg("--input-type=module")
        .arg("-e")
        .arg(bootstrap_js)
        .current_dir(&root)
        .env("HYPHAE_TEST_DIR", dir_str)
        .env("HYPHAE_SECRET_BACKEND", "file")
        .env("HOME", dir_str)
        .env("XDG_CONFIG_HOME", tmp.path().join("xdg"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn TS daemon");

    let stdout = child.stdout.take().expect("stdout");
    let mut line = String::new();
    BufReader::new(stdout).read_line(&mut line).unwrap();
    let ready: Value = serde_json::from_str(line.trim()).expect("valid ready JSON");
    let socket_path = PathBuf::from(ready["socketPath"].as_str().unwrap());

    LiveTsDaemon {
        _tmp: tmp,
        child,
        socket_path,
    }
}

#[test]
fn version_plain_and_json_envelope() {
    let plain = Command::new(hyp_rs_bin())
        .arg("version")
        .output()
        .expect("run hyp-rs version");
    assert_eq!(plain.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&plain.stdout).starts_with("hyphae "),
        "stdout: {}",
        String::from_utf8_lossy(&plain.stdout)
    );

    let json_out = Command::new(hyp_rs_bin())
        .args(["version", "--json"])
        .output()
        .expect("run hyp-rs version --json");
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
        .expect("spawn hyp-rs hook");
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
        .expect("spawn hyp-rs hook antigravity");
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
fn cli_subprocesses_mcp_hook_and_wait_interop_against_live_ts_daemon() {
    let daemon = start_live_ts_daemon();
    let sock_str = daemon.socket_path.to_str().unwrap();

    // 1. Spawn `hyp-rs mcp <socket>` subprocess
    let mut mcp = Command::new(hyp_rs_bin())
        .args(["mcp", sock_str])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hyp-rs mcp");

    let mut mcp_in = mcp.stdin.take().unwrap();
    let mut mcp_out = BufReader::new(mcp.stdout.take().unwrap());

    fn rpc(
        mcp_in: &mut std::process::ChildStdin,
        mcp_out: &mut BufReader<std::process::ChildStdout>,
        msg: Value,
    ) -> Value {
        writeln!(mcp_in, "{msg}").unwrap();
        mcp_in.flush().unwrap();
        let mut line = String::new();
        mcp_out.read_line(&mut line).unwrap();
        serde_json::from_str(line.trim()).expect("valid JSON-RPC response")
    }

    let init = rpc(
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
    let list = rpc(
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

    // 2. Run real `hyp-rs hook claude pre-tool-use` binary to register a join call
    let mut hook_proc = Command::new(hyp_rs_bin())
        .args(["hook", "claude", "pre-tool-use", "--socket", sock_str])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    hook_proc
        .stdin
        .take()
        .unwrap()
        .write_all(
            json!({
                "session_id": "cli-s1",
                "tool_use_id": "toolu_cli_1",
                "tool_name": "mcp__hyphae__hyp_mesh",
                "tool_input": {"action": "join", "handle": "alice"}
            })
            .to_string()
            .as_bytes(),
        )
        .unwrap();
    assert_eq!(hook_proc.wait().unwrap().code(), Some(0));

    let joined = rpc(
        &mut mcp_in,
        &mut mcp_out,
        json!({
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "hyp_mesh",
                "arguments": {"action": "join", "handle": "alice"},
                "_meta": {"claudecode/toolUseId": "toolu_cli_1"}
            }
        }),
    );
    assert!(joined["result"].get("isError").is_none());
    assert!(
        joined["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("cli@local/alice")
    );

    // 3. Run real `hyp-rs wait --session claude:cli-s1 --timeout 0.1` binary -> exits 0 cleanly on timeout
    let wait_timeout = Command::new(hyp_rs_bin())
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

    // 4. Verify piped one-shot stdin EOF drains in-flight `tools/list` cleanly before exiting
    let mut oneshot = Command::new(hyp_rs_bin())
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
    let oneshot_json: Value = serde_json::from_slice(&oneshot_out.stdout).expect("piped tools/list JSON");
    assert_eq!(oneshot_json["id"], 42);
    assert_eq!(oneshot_json["result"]["tools"].as_array().unwrap().len(), 4);

    drop(mcp_in);
    assert_eq!(mcp.wait().unwrap().code(), Some(0));
}
