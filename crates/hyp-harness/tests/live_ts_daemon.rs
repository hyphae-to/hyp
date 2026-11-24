//! Live end-to-end interoperability tests between the Rust `hyp-harness` shims
//! (`hooks`, `mcp`, `wait`/`watch`, `sock`) and our actual TypeScript v1 `hyp daemon`
//! launched via `node --experimental-strip-types` in an isolated TempDir (Unix), plus
//! loopback TCP end-to-end shim verification on Windows.

#![cfg_attr(not(unix), allow(dead_code))]

use hyp_harness::hooks::{HandleHookOptions, HookEvent, handle_hook_payload};
#[cfg(unix)]
use hyp_harness::mcp::select_tools_for_list;
use hyp_harness::mcp::{McpOptions, run_mcp_io};
use hyp_harness::protocol::HarnessKind;
use hyp_harness::wait::{WaitMode, WaitOptions, run_wait_to_writer};
use serde_json::{Value, json};
#[cfg(unix)]
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::process::{Child, Command, Stdio};
use std::time::Duration;
#[cfg(unix)]
use tempfile::TempDir;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, DuplexStream};

#[cfg(unix)]
struct LiveTsDaemon {
    _tmp: TempDir,
    child: Child,
    socket_path: PathBuf,
}

#[cfg(unix)]
impl Drop for LiveTsDaemon {
    fn drop(&mut self) {
        let _ = self.child.stdin.take();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(unix)]
fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

#[cfg(unix)]
fn start_live_ts_daemon() -> LiveTsDaemon {
    let tmp = tempfile::tempdir().expect("create tempdir");
    let root = repo_root();
    let dir_str = tmp.path().to_str().unwrap();

    // Isolated TypeScript v1 RouterCore + serveRouter(port: 0) + startDaemon(connector.sock).
    let bootstrap_js = r#"
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { RouterCore } from "./src/core/router/core.ts";
import { serveRouter } from "./src/core/router/server.ts";
import { startDaemon } from "./src/daemon.ts";

const dir = process.env.HYPHAE_TEST_DIR;
const routerCore = new RouterCore({
  dbPath: join(dir, "router.sqlite"),
  topics: new Map([["github", ["gh"]]]),
});
routerCore.events.setTopicMetadata("github", {
  kind: "github-webhook",
  scope: { repos: ["hyphae-to/hyp"] },
  schema: { attributes: ["repo", "action"] },
});
const token = routerCore.addConnector("rusttest@local");
const router = await serveRouter({ core: routerCore, host: "127.0.0.1", port: 0 });
const stateDir = join(dir, "state");
mkdirSync(stateDir, { mode: 0o700, recursive: true });
const daemon = await startDaemon({
  connectorId: "rusttest@local",
  directory: stateDir,
  routers: [{ name: "primary", url: router.url, token }],
}, { quiet: true });

process.stdout.write(JSON.stringify({ socketPath: daemon.socketPath, routerUrl: router.url }) + "\n");

const shutdown = async () => {
  try { await daemon.stop(); } catch {}
  try { await router.close(); } catch {}
  try { routerCore.close(); } catch {}
  process.exit(0);
};
process.stdin.resume();
process.stdin.on("end", () => { void shutdown(); });
process.on("SIGTERM", () => { void shutdown(); });
process.on("SIGINT", () => { void shutdown(); });
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
        .expect("spawn node TS daemon (ensure Node 24 is in PATH)");

    let stdout = child.stdout.take().expect("daemon stdout");
    let mut reader = BufReader::new(stdout);
    let mut ready_line = String::new();
    let bytes = reader
        .read_line(&mut ready_line)
        .expect("read daemon ready line");
    if bytes == 0 {
        let mut stderr_buf = String::new();
        if let Some(mut se) = child.stderr.take() {
            let _ = std::io::Read::read_to_string(&mut se, &mut stderr_buf);
        }
        panic!("TS daemon exited before ready. stderr:\n{stderr_buf}");
    }

    let ready: Value = serde_json::from_str(ready_line.trim()).unwrap_or_else(|e| {
        panic!("Invalid ready JSON from TS daemon: {e}; raw={ready_line:?}");
    });
    let socket_path = PathBuf::from(ready["socketPath"].as_str().expect("socketPath"));

    LiveTsDaemon {
        _tmp: tmp,
        child,
        socket_path,
    }
}

struct TestMcpClient {
    writer: DuplexStream,
    reader: tokio::io::Lines<tokio::io::BufReader<DuplexStream>>,
    next_id: u64,
    task: tokio::task::JoinHandle<()>,
}

impl TestMcpClient {
    fn spawn(options: McpOptions) -> Self {
        let (client_w, server_r) = tokio::io::duplex(65_536);
        let (server_w, client_r) = tokio::io::duplex(65_536);
        let task = tokio::spawn(async move {
            let _ = run_mcp_io(tokio::io::BufReader::new(server_r), server_w, options).await;
        });
        Self {
            writer: client_w,
            reader: tokio::io::BufReader::new(client_r).lines(),
            next_id: 0,
            task,
        }
    }

    async fn send_json(&mut self, msg: &Value) {
        let line = format!("{msg}\n");
        self.writer.write_all(line.as_bytes()).await.unwrap();
        self.writer.flush().await.unwrap();
    }

    async fn next_message(&mut self) -> Value {
        let line = tokio::time::timeout(Duration::from_secs(10), self.reader.next_line())
            .await
            .expect("MCP read timed out")
            .expect("MCP read I/O error")
            .expect("MCP stream closed unexpectedly");
        serde_json::from_str(&line).expect("valid JSON-RPC line")
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send_json(&json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params
        }))
        .await;
        loop {
            let msg = self.next_message().await;
            if msg.get("id").and_then(Value::as_u64) == Some(id) {
                return msg;
            }
        }
    }

    async fn initialize(&mut self) -> Value {
        let res = self
            .request(
                "initialize",
                json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "rust-live-test", "version": "1"}
                }),
            )
            .await;
        self.send_json(&json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
        res
    }

    async fn call_tool(
        &mut self,
        name: &str,
        arguments: Value,
        meta: Option<Value>,
    ) -> (String, bool) {
        let mut params = json!({ "name": name, "arguments": arguments });
        if let Some(m) = meta {
            params["_meta"] = m;
        }
        let res = self.request("tools/call", params).await;
        let result = &res["result"];
        let text = result["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        let is_error = result["isError"].as_bool() == Some(true);
        (text, is_error)
    }

    async fn close(self) {
        drop(self.writer);
        let _ = tokio::time::timeout(Duration::from_secs(3), self.task).await;
    }
}

fn hook_opts(harness: HarnessKind, event: HookEvent, sock: &Path) -> HandleHookOptions {
    HandleHookOptions {
        harness,
        event,
        socket_path: sock.to_path_buf(),
        cli_path: Some("hyp-rs".into()),
        explicit_socket: None,
    }
}

#[cfg(unix)]
#[tokio::test]
async fn live_ts_daemon_end_to_end_rust_shims() {
    let daemon = start_live_ts_daemon();
    let sock = daemon.socket_path.clone();

    let mut mcp = TestMcpClient::spawn(McpOptions::new(sock.clone()));
    let init = mcp.initialize().await;
    assert_eq!(init["result"]["protocolVersion"], "2025-06-18");

    // 1. tools/list advertises the exact 4 core tools (0 tokens for unused hyp_bridge)
    let list = mcp.request("tools/list", json!({})).await;
    let tool_names: Vec<&str> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        tool_names,
        vec!["hyp_send", "hyp_inbox", "hyp_mesh", "hyp_stream"]
    );

    // 2. Unverified tool call fails closed!
    let (unverified_txt, unverified_err) = mcp
        .call_tool(
            "hyp_mesh",
            json!({"action": "join", "handle": "spoof"}),
            None,
        )
        .await;
    assert!(unverified_err);
    assert!(
        unverified_txt.contains("caller_unverifiable"),
        "expected caller_unverifiable, got {unverified_txt}"
    );

    // 3. Antigravity joins via synchronous Rust PreToolUse hook -> overwrite._meshCall -> Rust MCP hyp_mesh
    let ag_pre = handle_hook_payload(
        json!({
            "conversationId": "ag-conv-1",
            "toolCall": {
                "id": "ag-call-1",
                "name": "hyp_mesh",
                "args": {"action": "join", "handle": "ag-alice", "include": ["peers", "topics"]}
            }
        })
        .as_object()
        .unwrap(),
        &hook_opts(HarnessKind::Antigravity, HookEvent::PreToolUse, &sock),
    );
    assert_eq!(ag_pre["decision"], "allow");
    let ag_token = ag_pre["overwrite"]["_meshCall"]
        .as_str()
        .expect("overwrite _meshCall token");

    let (ag_join_txt, ag_join_err) = mcp
        .call_tool(
            "hyp_mesh",
            json!({
                "action": "join",
                "handle": "ag-alice",
                "include": ["peers", "topics"],
                "_meshCall": ag_token
            }),
            None,
        )
        .await;
    assert!(!ag_join_err, "ag join failed: {ag_join_txt}");
    let ag_join_json: Value = serde_json::from_str(&ag_join_txt).unwrap();
    assert_eq!(ag_join_json["address"], "rusttest@local/ag-alice");
    assert!(ag_join_json["topics"].is_array());

    // 4. Claude joins on the SAME shared Rust MCP process via PreToolUse + _meta["claudecode/toolUseId"]
    handle_hook_payload(
        json!({
            "session_id": "claude-sess-2",
            "tool_use_id": "toolu_join_2",
            "tool_name": "mcp__hyphae__hyp_mesh",
            "tool_input": {"action": "join", "handle": "claude-bob"}
        })
        .as_object()
        .unwrap(),
        &hook_opts(HarnessKind::Claude, HookEvent::PreToolUse, &sock),
    );
    let (cl_join_txt, cl_join_err) = mcp
        .call_tool(
            "hyp_mesh",
            json!({"action": "join", "handle": "claude-bob"}),
            Some(json!({"claudecode/toolUseId": "toolu_join_2"})),
        )
        .await;
    assert!(!cl_join_err, "claude join failed: {cl_join_txt}");
    let cl_join_json: Value = serde_json::from_str(&cl_join_txt).unwrap();
    assert_eq!(cl_join_json["address"], "rusttest@local/claude-bob");

    // 5. Claude checks peers via hyp_mesh(action:"peers")
    handle_hook_payload(
        json!({
            "session_id": "claude-sess-2",
            "tool_use_id": "toolu_peers_3",
            "tool_name": "mcp__hyphae__hyp_mesh",
            "tool_input": {"action": "peers"}
        })
        .as_object()
        .unwrap(),
        &hook_opts(HarnessKind::Claude, HookEvent::PreToolUse, &sock),
    );
    let (peers_txt, peers_err) = mcp
        .call_tool(
            "hyp_mesh",
            json!({"action": "peers"}),
            Some(json!({"claudecode/toolUseId": "toolu_peers_3"})),
        )
        .await;
    assert!(!peers_err, "peers failed: {peers_txt}");
    assert!(peers_txt.contains("rusttest@local/ag-alice"));
    assert!(peers_txt.contains("rusttest@local/claude-bob"));

    // 6. Both join #ops via hyp_mesh(action:"join", channel:"#ops")
    let ag_ch_pre = handle_hook_payload(
        json!({
            "conversationId": "ag-conv-1",
            "toolCall": {
                "id": "ag-ch-1",
                "name": "hyp_mesh",
                "args": {"action": "join", "channel": "#ops"}
            }
        })
        .as_object()
        .unwrap(),
        &hook_opts(HarnessKind::Antigravity, HookEvent::PreToolUse, &sock),
    );
    let (ag_ch_txt, ag_ch_err) = mcp
        .call_tool(
            "hyp_mesh",
            json!({
                "action": "join",
                "channel": "#ops",
                "_meshCall": ag_ch_pre["overwrite"]["_meshCall"]
            }),
            None,
        )
        .await;
    assert!(!ag_ch_err, "ag channel join failed: {ag_ch_txt}");

    handle_hook_payload(
        json!({
            "session_id": "claude-sess-2",
            "tool_use_id": "toolu_ch_2",
            "tool_name": "mcp__hyphae__hyp_mesh",
            "tool_input": {"action": "join", "channel": "#ops"}
        })
        .as_object()
        .unwrap(),
        &hook_opts(HarnessKind::Claude, HookEvent::PreToolUse, &sock),
    );
    let (cl_ch_txt, cl_ch_err) = mcp
        .call_tool(
            "hyp_mesh",
            json!({"action": "join", "channel": "#ops"}),
            Some(json!({"claudecode/toolUseId": "toolu_ch_2"})),
        )
        .await;
    assert!(!cl_ch_err, "claude channel join failed: {cl_ch_txt}");

    // 7. Zero-polling Rust `wait` wakeup for Antigravity!
    let wait_sock = sock.clone();
    let wait_handle = tokio::spawn(async move {
        let mut buf: Vec<u8> = Vec::new();
        let code = run_wait_to_writer(
            WaitOptions {
                socket_path: wait_sock,
                mode: WaitMode::Once,
                session_id: Some("antigravity:ag-conv-1".into()),
                handle: None,
                timeout_seconds: Some(10.0),
                json: false,
            },
            &mut buf,
        )
        .await
        .expect("run_wait_to_writer failed");
        (code, String::from_utf8(buf).unwrap())
    });

    // Wait briefly until daemon sees live waiter (Stop hook returns `{}` once armed!)
    let mut armed = false;
    for _ in 0..40 {
        let st = handle_hook_payload(
            json!({
                "conversationId": "ag-conv-1",
                "continuationActive": false,
                "terminationReason": "NO_TOOL_CALL"
            })
            .as_object()
            .unwrap(),
            &hook_opts(HarnessKind::Antigravity, HookEvent::Stop, &sock),
        );
        if st.as_object().is_some_and(|m| m.is_empty()) {
            armed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(armed, "Stop hook should observe live Rust waiter transport");

    // Claude sends DM to Antigravity through live TS router -> wakes Rust `wait` immediately!
    handle_hook_payload(
        json!({
            "session_id": "claude-sess-2",
            "tool_use_id": "toolu_send_4",
            "tool_name": "mcp__hyphae__hyp_send",
            "tool_input": {"to": "rusttest@local/ag-alice", "text": "wake up from rust shim!"}
        })
        .as_object()
        .unwrap(),
        &hook_opts(HarnessKind::Claude, HookEvent::PreToolUse, &sock),
    );
    let (send_txt, send_err) = mcp
        .call_tool(
            "hyp_send",
            json!({"to": "rusttest@local/ag-alice", "text": "wake up from rust shim!"}),
            Some(json!({"claudecode/toolUseId": "toolu_send_4"})),
        )
        .await;
    assert!(!send_err, "send failed: {send_txt}");

    let (wait_code, wait_out) = tokio::time::timeout(Duration::from_secs(5), wait_handle)
        .await
        .expect("wait timed out")
        .expect("wait task panicked");
    assert_eq!(wait_code, 0);
    assert!(
        wait_out.contains("hyphae from rusttest@local/claude-bob"),
        "unexpected wait output: {wait_out}"
    );
    assert!(
        wait_out.contains("wake up from rust shim!"),
        "unexpected wait output: {wait_out}"
    );

    // 8. Antigravity posts to #ops -> Claude drains via synchronous Rust PostToolUse hook!
    let ag_post_pre = handle_hook_payload(
        json!({
            "conversationId": "ag-conv-1",
            "toolCall": {
                "id": "ag-post-2",
                "name": "hyp_send",
                "args": {"to": "#ops", "text": "ops channel broadcast!"}
            }
        })
        .as_object()
        .unwrap(),
        &hook_opts(HarnessKind::Antigravity, HookEvent::PreToolUse, &sock),
    );
    let (post_txt, post_err) = mcp
        .call_tool(
            "hyp_send",
            json!({
                "to": "#ops",
                "text": "ops channel broadcast!",
                "_meshCall": ag_post_pre["overwrite"]["_meshCall"]
            }),
            None,
        )
        .await;
    assert!(!post_err, "channel post failed: {post_txt}");

    // Poll briefly for SSE delivery into Claude's SQLite mailbox, then drain via PostToolUse hook
    let mut post_hook_out = json!({});
    for _ in 0..40 {
        post_hook_out = handle_hook_payload(
            json!({"session_id": "claude-sess-2", "tool_use_id": "toolu_send_4"})
                .as_object()
                .unwrap(),
            &hook_opts(HarnessKind::Claude, HookEvent::PostToolUse, &sock),
        );
        if post_hook_out.get("hookSpecificOutput").is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(
        post_hook_out["hookSpecificOutput"]["hookEventName"],
        "PostToolUse"
    );
    assert!(
        post_hook_out["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .unwrap()
            .contains("ops channel broadcast!"),
        "unexpected PostToolUse hook output: {post_hook_out}"
    );

    // 9. Delivery mode (`notify`) + `hyp_inbox(ack: true, summary: true)` + mute/unmute
    handle_hook_payload(
        json!({
            "session_id": "claude-sess-2",
            "tool_use_id": "toolu_mode_5",
            "tool_name": "mcp__hyphae__hyp_inbox",
            "tool_input": {"mode": "notify"}
        })
        .as_object()
        .unwrap(),
        &hook_opts(HarnessKind::Claude, HookEvent::PreToolUse, &sock),
    );
    let (mode_txt, mode_err) = mcp
        .call_tool(
            "hyp_inbox",
            json!({"mode": "notify"}),
            Some(json!({"claudecode/toolUseId": "toolu_mode_5"})),
        )
        .await;
    assert!(!mode_err, "mode switch failed: {mode_txt}");
    assert!(mode_txt.contains("\"deliveryMode\":\"notify\""));

    let ag_notify_pre = handle_hook_payload(
        json!({
            "conversationId": "ag-conv-1",
            "toolCall": {
                "id": "ag-send-3",
                "name": "hyp_send",
                "args": {"to": "rusttest@local/claude-bob", "text": "durable inbox item"}
            }
        })
        .as_object()
        .unwrap(),
        &hook_opts(HarnessKind::Antigravity, HookEvent::PreToolUse, &sock),
    );
    let (_, notify_send_err) = mcp
        .call_tool(
            "hyp_send",
            json!({
                "to": "rusttest@local/claude-bob",
                "text": "durable inbox item",
                "_meshCall": ag_notify_pre["overwrite"]["_meshCall"]
            }),
            None,
        )
        .await;
    assert!(!notify_send_err);

    // Wait briefly for SSE delivery then read+ack with summary:true via hyp_inbox
    let mut inbox_json = json!({});
    for _ in 0..40 {
        let call_id = format!("toolu_inbox_{}", mcp.next_id);
        handle_hook_payload(
            json!({
                "session_id": "claude-sess-2",
                "tool_use_id": call_id,
                "tool_name": "mcp__hyphae__hyp_inbox",
                "tool_input": {"ack": true, "summary": true}
            })
            .as_object()
            .unwrap(),
            &hook_opts(HarnessKind::Claude, HookEvent::PreToolUse, &sock),
        );
        let (txt, err) = mcp
            .call_tool(
                "hyp_inbox",
                json!({"ack": true, "summary": true}),
                Some(json!({"claudecode/toolUseId": call_id})),
            )
            .await;
        assert!(!err, "hyp_inbox failed: {txt}");
        inbox_json = serde_json::from_str(&txt).unwrap();
        if !inbox_json["items"].as_array().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(inbox_json["items"].as_array().unwrap().len(), 1);
    assert!(inbox_json["items"][0]["preview"].is_string());
    assert_eq!(inbox_json["unread"], 0);

    // 9b. Mute & unmute via `hyp_inbox(mute/unmute)` (routed to v1 `hyp_session`!)
    handle_hook_payload(
        json!({
            "session_id": "claude-sess-2",
            "tool_use_id": "toolu_mute_5b",
            "tool_name": "mcp__hyphae__hyp_inbox",
            "tool_input": {"mute": "#noisy", "scope": "session"}
        })
        .as_object()
        .unwrap(),
        &hook_opts(HarnessKind::Claude, HookEvent::PreToolUse, &sock),
    );
    let (mute_txt, mute_err) = mcp
        .call_tool(
            "hyp_inbox",
            json!({"mute": "#noisy", "scope": "session"}),
            Some(json!({"claudecode/toolUseId": "toolu_mute_5b"})),
        )
        .await;
    assert!(!mute_err, "mute failed: {mute_txt}");
    assert!(mute_txt.contains("\"#noisy\""));

    handle_hook_payload(
        json!({
            "session_id": "claude-sess-2",
            "tool_use_id": "toolu_unmute_5c",
            "tool_name": "mcp__hyphae__hyp_inbox",
            "tool_input": {"unmute": "#noisy", "scope": "session"}
        })
        .as_object()
        .unwrap(),
        &hook_opts(HarnessKind::Claude, HookEvent::PreToolUse, &sock),
    );
    let (unmute_txt, unmute_err) = mcp
        .call_tool(
            "hyp_inbox",
            json!({"unmute": "#noisy", "scope": "session"}),
            Some(json!({"claudecode/toolUseId": "toolu_unmute_5c"})),
        )
        .await;
    assert!(!unmute_err, "unmute failed: {unmute_txt}");
    assert_eq!(
        serde_json::from_str::<Value>(&unmute_txt).unwrap()["removed"],
        true
    );

    // Switch back to full mode and verify streaming `watch` (`WaitMode::Stream`)!
    handle_hook_payload(
        json!({
            "session_id": "claude-sess-2",
            "tool_use_id": "toolu_mode_full",
            "tool_name": "mcp__hyphae__hyp_inbox",
            "tool_input": {"mode": "full"}
        })
        .as_object()
        .unwrap(),
        &hook_opts(HarnessKind::Claude, HookEvent::PreToolUse, &sock),
    );
    let (_, mode_full_err) = mcp
        .call_tool(
            "hyp_inbox",
            json!({"mode": "full"}),
            Some(json!({"claudecode/toolUseId": "toolu_mode_full"})),
        )
        .await;
    assert!(!mode_full_err);

    let watch_sock = sock.clone();
    let watch_handle = tokio::spawn(async move {
        let mut buf: Vec<u8> = Vec::new();
        let code = run_wait_to_writer(
            WaitOptions {
                socket_path: watch_sock,
                mode: WaitMode::Stream,
                session_id: Some("claude:claude-sess-2".into()),
                handle: None,
                timeout_seconds: Some(0.45),
                json: false,
            },
            &mut buf,
        )
        .await
        .expect("watch failed");
        (code, String::from_utf8(buf).unwrap())
    });
    tokio::time::sleep(Duration::from_millis(80)).await;

    let ag_watch_pre = handle_hook_payload(
        json!({
            "conversationId": "ag-conv-1",
            "toolCall": {
                "id": "ag-send-watch",
                "name": "hyp_send",
                "args": {"to": "rusttest@local/claude-bob", "text": "stream watch ping!"}
            }
        })
        .as_object()
        .unwrap(),
        &hook_opts(HarnessKind::Antigravity, HookEvent::PreToolUse, &sock),
    );
    let (_, watch_send_err) = mcp
        .call_tool(
            "hyp_send",
            json!({
                "to": "rusttest@local/claude-bob",
                "text": "stream watch ping!",
                "_meshCall": ag_watch_pre["overwrite"]["_meshCall"]
            }),
            None,
        )
        .await;
    assert!(!watch_send_err);

    let (watch_code, watch_out) = tokio::time::timeout(Duration::from_secs(5), watch_handle)
        .await
        .expect("watch timed out")
        .expect("watch panicked");
    assert_eq!(watch_code, 0);
    let first_line = watch_out.lines().next().expect("watch NDJSON line");
    let watch_item: Value = serde_json::from_str(first_line).expect("valid watch NDJSON");
    assert!(
        watch_item["text"]
            .as_str()
            .unwrap()
            .contains("stream watch ping!"),
        "unexpected watch item: {watch_item}"
    );

    // 10. hyp_stream topics -> subscribe (`primary.github`) -> list -> unsubscribe
    handle_hook_payload(
        json!({
            "session_id": "claude-sess-2",
            "tool_use_id": "toolu_sub_6",
            "tool_name": "mcp__hyphae__hyp_stream",
            "tool_input": {"action": "subscribe", "topic": "primary.github", "key": "gh:pr-watch"}
        })
        .as_object()
        .unwrap(),
        &hook_opts(HarnessKind::Claude, HookEvent::PreToolUse, &sock),
    );
    let (sub_txt, sub_err) = mcp
        .call_tool(
            "hyp_stream",
            json!({
                "action": "subscribe",
                "topic": "primary.github",
                "key": "gh:pr-watch",
                "filters": [{"exact": {"repo": "hyphae-to/hyp"}}]
            }),
            Some(json!({"claudecode/toolUseId": "toolu_sub_6"})),
        )
        .await;
    assert!(!sub_err, "subscribe failed: {sub_txt}");
    let sub_json: Value = serde_json::from_str(&sub_txt).unwrap();
    assert_eq!(sub_json["outcome"], "created");
    assert_eq!(sub_json["reachable"], true);

    handle_hook_payload(
        json!({
            "session_id": "claude-sess-2",
            "tool_use_id": "toolu_unsub_7",
            "tool_name": "mcp__hyphae__hyp_stream",
            "tool_input": {"action": "unsubscribe", "key": "gh:pr-watch"}
        })
        .as_object()
        .unwrap(),
        &hook_opts(HarnessKind::Claude, HookEvent::PreToolUse, &sock),
    );
    let (unsub_txt, unsub_err) = mcp
        .call_tool(
            "hyp_stream",
            json!({"action": "unsubscribe", "key": "gh:pr-watch"}),
            Some(json!({"claudecode/toolUseId": "toolu_unsub_7"})),
        )
        .await;
    assert!(!unsub_err, "unsubscribe failed: {unsub_txt}");
    assert_eq!(
        serde_json::from_str::<Value>(&unsub_txt).unwrap()["removed"],
        true
    );

    // 11. Live `--claude-channel` native push notification against real TS daemon!
    let mut chan_opts = McpOptions::new(sock.clone());
    chan_opts.channel = true;
    chan_opts.ephemeral = true;
    chan_opts.backend = Some(HarnessKind::Claude);
    let mut chan_mcp = TestMcpClient::spawn(chan_opts);
    let chan_init = chan_mcp.initialize().await;
    assert!(chan_init["result"]["capabilities"]["experimental"]["claude/channel"].is_object());

    let (chan_join_txt, chan_join_err) = chan_mcp
        .call_tool(
            "hyp_mesh",
            json!({"action": "join", "handle": "claude-chan"}),
            None,
        )
        .await;
    assert!(!chan_join_err, "channel join failed: {chan_join_txt}");

    let ag_chan_pre = handle_hook_payload(
        json!({
            "conversationId": "ag-conv-1",
            "toolCall": {
                "id": "ag-send-chan",
                "name": "hyp_send",
                "args": {"to": "rusttest@local/claude-chan", "text": "live claude channel push!"}
            }
        })
        .as_object()
        .unwrap(),
        &hook_opts(HarnessKind::Antigravity, HookEvent::PreToolUse, &sock),
    );
    let (_, chan_send_err) = mcp
        .call_tool(
            "hyp_send",
            json!({
                "to": "rusttest@local/claude-chan",
                "text": "live claude channel push!",
                "_meshCall": ag_chan_pre["overwrite"]["_meshCall"]
            }),
            None,
        )
        .await;
    assert!(!chan_send_err);

    let notif = chan_mcp.next_message().await;
    assert_eq!(notif["method"], "notifications/claude/channel");
    assert!(
        notif["params"]["content"]
            .as_str()
            .unwrap()
            .contains("live claude channel push!"),
        "unexpected channel notification: {notif}"
    );

    chan_mcp.close().await;
    mcp.close().await;

    // Emit compaction summary in test stdout for visibility (`cargo test -- --nocapture`).
    let core_bytes = serde_json::to_string(&select_tools_for_list(false))
        .unwrap()
        .len();
    let bridge_bytes = serde_json::to_string(&select_tools_for_list(true))
        .unwrap()
        .len();
    let _ = writeln!(
        std::io::stdout(),
        "v2 MCP tools/list size: 4-core={} B (~{} tok), 4+1 bridge={} B (~{} tok)",
        core_bytes,
        core_bytes / 4,
        bridge_bytes,
        bridge_bytes / 4
    );
}

#[cfg(not(unix))]
#[tokio::test]
async fn windows_tcp_loopback_end_to_end_hook_mcp_and_wait() {
    use hyp_harness::sock::{MAX_SOCKET_LINE_BYTES, read_bounded_line_async, write_ndjson_line_async};

    let tmp = tempfile::tempdir().unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let addr_file = tmp.path().join("connector.addr");
    std::fs::write(&addr_file, format!("{addr}\n")).unwrap();

    // Minimal mock daemon over 127.0.0.1 handling hook `call.start`, MCP `mcp.caps`/`tool.call`,
    // and `wait.subscribe`.
    let server = tokio::spawn(async move {
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let (r, mut w) = stream.split();
                let mut reader = tokio::io::BufReader::new(r);
                while let Ok(Some(line)) =
                    read_bounded_line_async(&mut reader, MAX_SOCKET_LINE_BYTES).await
                {
                    let Ok(pkt) = serde_json::from_str::<Value>(&line) else {
                        break;
                    };
                    match pkt.get("type").and_then(Value::as_str) {
                        Some("call.start") => {
                            let _ = write_ndjson_line_async(
                                &mut w,
                                &json!({"ok": true, "result": {"callToken": "win_tok_1"}}),
                            )
                            .await;
                            break;
                        }
                        Some("mcp.hello") => {}
                        Some("mcp.caps") => {
                            let _ = write_ndjson_line_async(
                                &mut w,
                                &json!({"id": pkt["id"], "result": {"hasPlugins": false}}),
                            )
                            .await;
                        }
                        Some("tool.call") => {
                            let _ = write_ndjson_line_async(
                                &mut w,
                                &json!({
                                    "id": pkt["id"],
                                    "result": {
                                        "address": "win@local/alice",
                                        "callToken": pkt["callToken"]
                                    }
                                }),
                            )
                            .await;
                        }
                        Some("wait.subscribe") => {
                            let _ = write_ndjson_line_async(
                                &mut w,
                                &json!({
                                    "type": "wait.items",
                                    "items": [{"router": "primary", "received": 1, "text": "windows wakeup!"}]
                                }),
                            )
                            .await;
                            break;
                        }
                        _ => break,
                    }
                }
            });
        }
    });

    // 1. Synchronous hook over connector.addr
    let hook_addr = addr_file.clone();
    let pre = tokio::task::spawn_blocking(move || {
        handle_hook_payload(
            json!({
                "conversationId": "win-conv-1",
                "toolCall": {
                    "id": "tc-1",
                    "name": "hyp_mesh",
                    "args": {"action": "join", "handle": "alice"}
                }
            })
            .as_object()
            .unwrap(),
            &hook_opts(HarnessKind::Antigravity, HookEvent::PreToolUse, &hook_addr),
        )
    })
    .await
    .unwrap();
    assert_eq!(pre["decision"], "allow");
    assert_eq!(pre["overwrite"]["_meshCall"], "win_tok_1");

    // 2. Async MCP over connector.addr
    let mut mcp = TestMcpClient::spawn(McpOptions::new(addr_file.clone()));
    let _ = mcp.initialize().await;
    let list = mcp.request("tools/list", json!({})).await;
    assert_eq!(list["result"]["tools"].as_array().unwrap().len(), 4);
    let (txt, is_err) = mcp
        .call_tool(
            "hyp_mesh",
            json!({"action": "join", "handle": "alice", "_meshCall": "win_tok_1"}),
            None,
        )
        .await;
    assert!(!is_err, "mcp join failed: {txt}");
    assert!(txt.contains("win@local/alice"));
    mcp.close().await;

    // 3. Async wait over connector.addr
    let mut out = Vec::new();
    let code = run_wait_to_writer(
        WaitOptions {
            socket_path: addr_file,
            mode: WaitMode::Once,
            session_id: Some("antigravity:win-conv-1".into()),
            handle: None,
            timeout_seconds: Some(3.0),
            json: false,
        },
        &mut out,
    )
    .await
    .unwrap();
    assert_eq!(code, 0);
    assert_eq!(String::from_utf8(out).unwrap(), "windows wakeup!\n");

    let _ = tokio::time::timeout(Duration::from_secs(2), server).await;
}
