#![allow(dead_code)]
//! Shared test helpers for `hyp-harness` integration & E2E suites.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use hyp_harness::hooks::{HandleHookOptions, HookEvent, HookTransportHints, handle_hook_payload};
use hyp_harness::mcp::{McpOptions, run_mcp_io};
use hyp_harness::protocol::HarnessKind;
use hyp_harness::sock::daemon_rpc_async;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};

pub fn loopback_zero() -> SocketAddr {
    "127.0.0.1:0".parse().expect("valid loopback address")
}

pub fn hook_opts(harness: HarnessKind, event: HookEvent, sock: &Path) -> HandleHookOptions {
    HandleHookOptions {
        harness,
        event,
        socket_path: sock.to_path_buf(),
        cli_path: Some("hyp".into()),
        explicit_socket: None,
        transport_hints: HookTransportHints::default(),
    }
}

/// Runs synchronous `handle_hook_payload` on a blocking thread so the Tokio runtime is never stalled.
pub async fn run_hook(
    sock: &Path,
    harness: HarnessKind,
    event: HookEvent,
    payload: Value,
) -> Value {
    run_hook_with_hints(sock, harness, event, payload, HookTransportHints::default()).await
}

/// Runs synchronous `handle_hook_payload` with explicit [`HookTransportHints`].
pub async fn run_hook_with_hints(
    sock: &Path,
    harness: HarnessKind,
    event: HookEvent,
    payload: Value,
    transport_hints: HookTransportHints,
) -> Value {
    let sock_owned = sock.to_path_buf();
    tokio::task::spawn_blocking(move || {
        let map = payload
            .as_object()
            .expect("hook payload must be a JSON object");
        let mut opts = hook_opts(harness, event, &sock_owned);
        opts.transport_hints = transport_hints;
        handle_hook_payload(map, &opts)
    })
    .await
    .expect("hook blocking task panicked")
}

/// Queries `session.status` on `sock` for `session_id`.
pub async fn session_status(sock: &Path, session_id: &str) -> Value {
    let res = daemon_rpc_async(
        sock,
        &json!({ "type": "session.status", "sessionId": session_id }),
        Duration::from_secs(2),
    )
    .await;
    assert!(
        res.ok,
        "session.status RPC failed for {session_id}: {:?}",
        res.error
    );
    Value::Object(res.result.expect("session.status missing result"))
}

/// Polls `session.status` until `hasLiveTransport == true` (deterministic alternative to blind sleeps).
pub async fn wait_for_live_transport(sock: &Path, session_id: &str) {
    for _ in 0..200 {
        let st = session_status(sock, session_id).await;
        if st["hasLiveTransport"].as_bool() == Some(true) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    panic!("timed out waiting for hasLiveTransport == true on {session_id}");
}

/// Polls `session.status` until `hasLiveTransport == false`.
pub async fn wait_for_no_live_transport(sock: &Path, session_id: &str) {
    for _ in 0..200 {
        let st = session_status(sock, session_id).await;
        if st["hasLiveTransport"].as_bool() == Some(false) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    panic!("timed out waiting for hasLiveTransport == false on {session_id}");
}

/// Polls `session.status` until `pending >= min_pending`.
pub async fn wait_for_pending_count(sock: &Path, session_id: &str, min_pending: u64) {
    for _ in 0..200 {
        let st = session_status(sock, session_id).await;
        if st["pending"].as_u64().unwrap_or(0) >= min_pending {
            return;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    let final_st = session_status(sock, session_id).await;
    panic!(
        "timed out waiting for pending >= {min_pending} on {session_id}; last status: {final_st}"
    );
}

/// In-process JSON-RPC 2.0 MCP client driving `run_mcp_io` over `tokio::io::duplex`.
pub struct TestMcpClient {
    writer: DuplexStream,
    reader: tokio::io::Lines<BufReader<DuplexStream>>,
    next_id: u64,
    task: tokio::task::JoinHandle<()>,
}

impl TestMcpClient {
    pub fn spawn(options: McpOptions) -> Self {
        let (client_w, server_r) = tokio::io::duplex(65_536);
        let (server_w, client_r) = tokio::io::duplex(65_536);
        let task = tokio::spawn(async move {
            let _ = run_mcp_io(BufReader::new(server_r), server_w, options).await;
        });
        Self {
            writer: client_w,
            reader: BufReader::new(client_r).lines(),
            next_id: 0,
            task,
        }
    }

    pub async fn send_json(&mut self, msg: &Value) {
        let line = format!("{msg}\n");
        self.writer.write_all(line.as_bytes()).await.unwrap();
        self.writer.flush().await.unwrap();
    }

    pub async fn next_message(&mut self) -> Value {
        let line = tokio::time::timeout(Duration::from_secs(10), self.reader.next_line())
            .await
            .expect("MCP read timed out")
            .expect("MCP read I/O error")
            .expect("MCP stream closed unexpectedly");
        serde_json::from_str(&line).expect("valid JSON-RPC line")
    }

    pub async fn request(&mut self, method: &str, params: Value) -> Value {
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

    pub async fn initialize(&mut self) -> Value {
        let res = self
            .request(
                "initialize",
                json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": { "name": "hyp-harness-test", "version": "1" }
                }),
            )
            .await;
        self.send_json(&json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }))
            .await;
        res
    }

    pub async fn list_tools(&mut self) -> Vec<String> {
        let res = self.request("tools/list", json!({})).await;
        res["result"]["tools"]
            .as_array()
            .expect("tools/list must return tools array")
            .iter()
            .map(|t| t["name"].as_str().expect("tool name string").to_string())
            .collect()
    }

    pub async fn call_tool(
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

    pub async fn call_verified_claude(
        &mut self,
        sock: &Path,
        session_raw: &str,
        tool_name: &str,
        arguments: Value,
    ) -> (String, bool) {
        let call_id = format!("toolu_{}_{}", session_raw, self.next_id + 1);
        let pre = run_hook(
            sock,
            HarnessKind::Claude,
            HookEvent::PreToolUse,
            json!({
                "session_id": session_raw,
                "tool_use_id": call_id,
                "tool_name": format!("mcp__hyphae__{tool_name}"),
                "tool_input": arguments
            }),
        )
        .await;
        assert_eq!(pre, json!({}));

        self.call_tool(
            tool_name,
            arguments,
            Some(json!({ "claudecode/toolUseId": call_id })),
        )
        .await
    }

    pub async fn call_verified_antigravity(
        &mut self,
        sock: &Path,
        conv_id: &str,
        tool_name: &str,
        mut arguments: Value,
    ) -> (String, bool) {
        let call_id = format!("ag_{}_{}", conv_id, self.next_id + 1);
        let pre = run_hook(
            sock,
            HarnessKind::Antigravity,
            HookEvent::PreToolUse,
            json!({
                "conversationId": conv_id,
                "toolCall": {
                    "id": call_id,
                    "name": tool_name,
                    "args": arguments
                }
            }),
        )
        .await;
        assert_eq!(pre["decision"], "allow");
        let tok = pre["overwrite"]["_meshCall"]
            .as_str()
            .expect("Antigravity PreToolUse must inject _meshCall");
        arguments
            .as_object_mut()
            .expect("arguments object")
            .insert("_meshCall".into(), json!(tok));

        self.call_tool(tool_name, arguments, None).await
    }

    pub async fn call_verified_antigravity_lazy(
        &mut self,
        sock: &Path,
        conv_id: &str,
        tool_name: &str,
        arguments: Value,
    ) -> (String, bool) {
        let call_id = format!("ag_lazy_{}_{}", conv_id, self.next_id + 1);
        let pre = run_hook(
            sock,
            HarnessKind::Antigravity,
            HookEvent::PreToolUse,
            json!({
                "conversationId": conv_id,
                "toolCall": {
                    "id": call_id,
                    "name": "call_mcp_tool",
                    "args": {
                        "ServerName": "hyphae_hyphae",
                        "ToolName": tool_name,
                        "Arguments": arguments
                    }
                }
            }),
        )
        .await;
        assert_eq!(pre["decision"], "allow");
        let overwritten_args = pre["overwrite"]["Arguments"].clone();
        assert!(
            overwritten_args["_meshCall"].as_str().is_some(),
            "Antigravity lazy PreToolUse must inject overwrite.Arguments._meshCall"
        );
        self.call_tool(tool_name, overwritten_args, None).await
    }

    /// Executes the authentic PreToolUse + MCP `tools/call` verification flow for any of the 9 harnesses.
    pub async fn call_verified_for_harness(
        &mut self,
        sock: &Path,
        harness: HarnessKind,
        raw_session_id: &str,
        tool_name: &str,
        mut arguments: Value,
    ) -> (String, bool) {
        let call_id = format!("{}_{}_{}", harness.as_str(), raw_session_id, self.next_id + 1);
        match harness {
            HarnessKind::Antigravity => {
                self.call_verified_antigravity(sock, raw_session_id, tool_name, arguments)
                    .await
            }
            HarnessKind::Claude => {
                self.call_verified_claude(sock, raw_session_id, tool_name, arguments)
                    .await
            }
            HarnessKind::Codex => {
                let pre = run_hook(
                    sock,
                    HarnessKind::Codex,
                    HookEvent::PreToolUse,
                    json!({
                        "thread_id": raw_session_id,
                        "tool_name": format!("mcp__hyphae__{tool_name}"),
                        "call_id": call_id,
                        "tool_input": arguments
                    }),
                )
                .await;
                assert_eq!(pre, json!({}));
                self.call_tool(tool_name, arguments, Some(json!({ "callId": call_id })))
                    .await
            }
            HarnessKind::Cursor => {
                let pre = run_hook(
                    sock,
                    HarnessKind::Cursor,
                    HookEvent::PreToolUse,
                    json!({
                        "conversation_id": raw_session_id,
                        "tool_name": format!("mcp_hyphae_{tool_name}"),
                        "tool_use_id": call_id,
                        "tool_input": arguments
                    }),
                )
                .await;
                assert_eq!(pre, json!({ "permission": "allow" }));
                self.call_tool(tool_name, arguments, Some(json!({ "toolUseId": call_id })))
                    .await
            }
            HarnessKind::Opencode => {
                let pre = run_hook(
                    sock,
                    HarnessKind::Opencode,
                    HookEvent::PreToolUse,
                    json!({
                        "session_id": raw_session_id,
                        "tool_name": format!("hyphae_{tool_name}"),
                        "call_id": call_id,
                        "tool_input": arguments
                    }),
                )
                .await;
                let tok = pre["callToken"]
                    .as_str()
                    .expect("OpenCode PreToolUse must return callToken");
                assert_eq!(
                    pre["sessionId"].as_str(),
                    Some(format!("opencode:{raw_session_id}").as_str())
                );
                arguments
                    .as_object_mut()
                    .expect("arguments object")
                    .insert("_meshCall".into(), json!(tok));
                self.call_tool(tool_name, arguments, None).await
            }
            HarnessKind::Gemini => {
                let pre = run_hook(
                    sock,
                    HarnessKind::Gemini,
                    HookEvent::PreToolUse,
                    json!({
                        "session_id": raw_session_id,
                        "tool_name": format!("mcp_hyphae_{tool_name}"),
                        "tool_use_id": call_id,
                        "tool_input": arguments
                    }),
                )
                .await;
                assert_eq!(pre["decision"], "allow");
                assert_eq!(pre["hookSpecificOutput"]["hookEventName"], "BeforeTool");
                let overwritten = pre["hookSpecificOutput"]["tool_input"].clone();
                assert!(overwritten["_meshCall"].as_str().is_some());
                self.call_tool(tool_name, overwritten, None).await
            }
            HarnessKind::Openclaw => {
                let pre = run_hook(
                    sock,
                    HarnessKind::Openclaw,
                    HookEvent::PreToolUse,
                    json!({
                        "sessionKey": raw_session_id,
                        "toolName": format!("hyphae__{tool_name}"),
                        "toolCallId": call_id,
                        "params": arguments
                    }),
                )
                .await;
                let tok = pre["callToken"]
                    .as_str()
                    .expect("OpenClaw before-tool-call must return callToken")
                    .to_string();
                let mut with_tok = arguments.as_object().cloned().unwrap_or_default();
                with_tok.insert("_meshCall".into(), json!(tok));
                self.call_tool(tool_name, Value::Object(with_tok), None)
                    .await
            }
            HarnessKind::Herdr => {
                let pre = run_hook(
                    sock,
                    HarnessKind::Herdr,
                    HookEvent::PreToolUse,
                    json!({
                        "session_id": raw_session_id,
                        "tool_name": format!("hyphae.{tool_name}"),
                        "tool_use_id": call_id,
                        "tool_input": arguments
                    }),
                )
                .await;
                assert_eq!(pre, json!({}));
                self.call_tool(
                    tool_name,
                    arguments,
                    Some(json!({ "toolCallId": call_id })),
                )
                .await
            }
            HarnessKind::T3 => {
                let pre = run_hook(
                    sock,
                    HarnessKind::T3,
                    HookEvent::PreToolUse,
                    json!({
                        "session_id": raw_session_id,
                        "tool_name": format!("hyphae:{tool_name}"),
                        "tool_use_id": call_id,
                        "tool_input": arguments
                    }),
                )
                .await;
                assert_eq!(pre, json!({}));
                self.call_tool(tool_name, arguments, Some(json!({ "callId": call_id })))
                    .await
            }
        }
    }

    pub async fn close(self) {
        drop(self.writer);
        let _ = tokio::time::timeout(Duration::from_secs(3), self.task).await;
    }
}
