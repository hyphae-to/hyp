//! Comprehensive E2E & Differential Parity Suite for `hyp-harness`:
//!
//! 1. All 9 Harnesses Live Differential Parity (Antigravity direct + lazy `call_mcp_tool`,
//!    Claude, Codex, Cursor, OpenCode, Gemini, OpenClaw, Herdr, T3).
//! 2. Live Caller Spoofing & Race Protection Matrix (`caller_unverifiable`, single-use replay,
//!    cross-tool token swap, forged `_meshCall`, `caller_ambiguous`, `PostToolUse` `call.end`
//!    cancellation, and `tools/call` racing 20ms ahead of `PreToolUse`).
//! 3. Live §2.5 Delivery Policy, Hybrid Batch Packer, Giant Truncation, Strict Focus Mode,
//!    Filtered/Paginated `hyp_inbox` (with quarantined receipt isolation) & E2EE file drops.
//! 4. `--claude-channel` Failure, Nack (`submitted: false`), Disconnect & Timeout Fallback Matrix.
//! 5. Bridge Identity Ownership (`all read · 1 primary writer + live handoff + fail-closed
//!    `not_target_holder` + Stage 1 Outbound DLP).
//! 6. Cross-OS `LocalDaemon::start_tcp` (`connector.addr`) Differential Parity vs Unix sockets.

mod common;

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{
    TestMcpClient, loopback_zero, run_hook, session_status, wait_for_live_transport,
    wait_for_no_live_transport, wait_for_pending_count,
};
use hyp_crypto::{Ed25519KeyPair, SecretBackend};
use hyp_harness::daemon::{BoxFuture, BridgePoster, InboundItem, LocalDaemon, LocalDaemonConfig};
use hyp_harness::hooks::HookEvent;
use hyp_harness::mcp::McpOptions;
use hyp_harness::protocol::HarnessKind;
use hyp_harness::sock::{
    MAX_SOCKET_LINE_BYTES, connect_daemon_async, daemon_rpc_async, read_bounded_line_async,
    write_ndjson_line_async,
};
use hyp_harness::transport::{PushMode, PushOutcome, PushTransport, TransportFuture};
use hyp_harness::wait::{WaitMode, WaitOptions, run_wait_to_writer};
use hyp_node::engine::{NodeConfig, UnifiedNode};
use hyp_node::gates::{
    SecurityGateConfig, SecurityGatePipeline, Stage1DenyAction, TrustTier as GateTrustTier,
};
use hyp_proto::address::NodeId;
use hyp_proto::manifest::{OkpCurve, OkpJwk};
use hyp_proto::scopes::ScopePreset;
use hyp_store::{GateState, MailboxInsert, MailboxKind, NodeDb, TrustTier, now_ms};
use serde_json::{Map, Value, json};
use tempfile::TempDir;
use tokio::io::BufReader;

fn open_local_node(node_id: &str, dir: &Path) -> Arc<UnifiedNode> {
    let mut cfg = NodeConfig::local(NodeId::new(node_id).unwrap(), dir);
    cfg.secret_backend = Some(SecretBackend::File);
    UnifiedNode::open(cfg).unwrap()
}

fn harness_session_payload(harness: HarnessKind, raw_id: &str) -> Value {
    match harness {
        HarnessKind::Antigravity => json!({
            "conversationId": raw_id,
            "continuationActive": false,
            "terminationReason": "NO_TOOL_CALL"
        }),
        HarnessKind::Cursor => json!({
            "conversation_id": raw_id,
            "loop_count": 0
        }),
        HarnessKind::Codex => json!({
            "thread_id": raw_id
        }),
        _ => json!({
            "session_id": raw_id,
            "stop_hook_active": false
        }),
    }
}

fn extract_drain_text(harness: HarnessKind, hook_out: &Value) -> String {
    match harness {
        HarnessKind::Antigravity => hook_out["injectSteps"][0]["systemMessage"]["systemMessage"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        HarnessKind::Opencode => hook_out["additionalContext"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        HarnessKind::Cursor => hook_out["additional_context"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        HarnessKind::Gemini => {
            assert_eq!(hook_out["hookSpecificOutput"]["hookEventName"], "AfterTool");
            hook_out["hookSpecificOutput"]["additionalContext"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        }
        _ => {
            assert_eq!(
                hook_out["hookSpecificOutput"]["hookEventName"],
                "PostToolUse"
            );
            hook_out["hookSpecificOutput"]["additionalContext"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        }
    }
}

fn extract_pre_turn_drain_text(harness: HarnessKind, hook_out: &Value) -> String {
    match harness {
        HarnessKind::Antigravity => hook_out["injectSteps"][0]["systemMessage"]["systemMessage"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        HarnessKind::Opencode => hook_out["additionalContext"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        HarnessKind::Cursor => {
            assert_eq!(hook_out["continue"], true);
            hook_out["additional_context"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        }
        HarnessKind::Gemini => {
            assert_eq!(
                hook_out["hookSpecificOutput"]["hookEventName"],
                "BeforeAgent"
            );
            hook_out["hookSpecificOutput"]["additionalContext"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        }
        HarnessKind::Openclaw => hook_out["prependContext"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        _ => {
            assert_eq!(
                hook_out["hookSpecificOutput"]["hookEventName"],
                "UserPromptSubmit"
            );
            hook_out["hookSpecificOutput"]["additionalContext"]
                .as_str()
                .unwrap_or_default()
                .to_string()
        }
    }
}

fn extract_stop_reason(harness: HarnessKind, stop_out: &Value) -> String {
    match harness {
        HarnessKind::Antigravity => {
            assert_eq!(stop_out["decision"], "continue");
            stop_out["reason"].as_str().unwrap_or_default().to_string()
        }
        HarnessKind::Cursor => stop_out["followup_message"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        HarnessKind::Gemini => {
            assert_eq!(stop_out["decision"], "deny");
            stop_out["reason"].as_str().unwrap_or_default().to_string()
        }
        HarnessKind::Opencode => stop_out["followupMessage"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        _ => {
            assert_eq!(stop_out["decision"], "block");
            stop_out["reason"].as_str().unwrap_or_default().to_string()
        }
    }
}

// ============================================================================
// Suite 1: All 9 Harnesses Live Differential Parity
// ============================================================================

#[tokio::test]
async fn suite_1_all_nine_harnesses_live_differential_parity() {
    let dir = TempDir::new().unwrap();
    let node = open_local_node("parity@box", dir.path());
    let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .unwrap();
    let sock = daemon.socket_path().to_path_buf();

    let mut sender_mcp = TestMcpClient::spawn(McpOptions::new(sock.clone()));
    sender_mcp.initialize().await;
    let (s_join, s_err) = sender_mcp
        .call_verified_claude(
            &sock,
            "sender-0",
            "hyp_mesh",
            json!({ "action": "join", "handle": "sender" }),
        )
        .await;
    assert!(!s_err, "sender join failed: {s_join}");

    let mut worker_mcp = TestMcpClient::spawn(McpOptions::new(sock.clone()));
    worker_mcp.initialize().await;

    #[derive(Debug, PartialEq, Eq)]
    struct ParityOutcome {
        enrolled_after_join: bool,
        pending_after_drain: u64,
        delivered_count_after_drain: usize,
        drain_contained_msg1: bool,
        stop_contained_msg2: bool,
        reply_sent_ok: bool,
    }

    let cases: Vec<(HarnessKind, bool, &str)> = vec![
        (HarnessKind::Antigravity, false, "ag-direct"),
        (HarnessKind::Antigravity, true, "ag-lazy"),
        (HarnessKind::Claude, false, "claude-1"),
        (HarnessKind::Codex, false, "codex-1"),
        (HarnessKind::Cursor, false, "cursor-1"),
        (HarnessKind::Opencode, false, "opencode-1"),
        (HarnessKind::Gemini, false, "gemini-1"),
        (HarnessKind::Openclaw, false, "openclaw-1"),
        (HarnessKind::Herdr, false, "herdr-1"),
        (HarnessKind::T3, false, "t3-1"),
    ];

    let mut outcomes = Vec::with_capacity(cases.len());

    for (harness, lazy_ag, raw_id) in &cases {
        let handle = format!("h-{raw_id}");
        let session_id = format!("{}:{raw_id}", harness.as_str());
        let hook_payload = harness_session_payload(*harness, raw_id);

        // 1. SessionStart always returns `{}`.
        let ss = run_hook(
            &sock,
            *harness,
            HookEvent::SessionStart,
            hook_payload.clone(),
        )
        .await;
        assert_eq!(ss, json!({}), "SessionStart must return {{}} for {raw_id}");

        // 2. Authentic PreToolUse -> CallRegistry -> MCP `hyp_mesh(join)`
        let join_args = json!({ "action": "join", "handle": handle });
        let (join_txt, join_err) = if *lazy_ag {
            worker_mcp
                .call_verified_antigravity_lazy(&sock, raw_id, "hyp_mesh", join_args)
                .await
        } else {
            worker_mcp
                .call_verified_for_harness(&sock, *harness, raw_id, "hyp_mesh", join_args)
                .await
        };
        assert!(!join_err, "join failed for {raw_id}: {join_txt}");
        let join_val: Value = serde_json::from_str(&join_txt).unwrap();
        assert_eq!(join_val["address"], format!("parity@box/{handle}"));

        let st_after_join = session_status(&sock, &session_id).await;
        assert_eq!(st_after_join["handle"], handle);

        // 3. Send DM #1 from `sender` -> verify mid-turn PostToolUse holds Queue DM cleanly,
        //    then verify TurnStart (`PreInvocation`) drains Queue DM into harness-specific envelope!
        let msg1 = format!("parity-msg-1-{raw_id}");
        let (dm1_txt, dm1_err) = sender_mcp
            .call_verified_claude(
                &sock,
                "sender-0",
                "hyp_send",
                json!({ "to": format!("parity@box/{handle}"), "text": msg1 }),
            )
            .await;
        assert!(!dm1_err, "send msg1 to {raw_id} failed: {dm1_txt}");
        wait_for_pending_count(&sock, &session_id, 1).await;

        let post_held = run_hook(
            &sock,
            *harness,
            HookEvent::PostToolUse,
            hook_payload.clone(),
        )
        .await;
        assert_eq!(
            post_held,
            json!({}),
            "PostToolUse must hold default Queue DM until TurnEnd/TurnStart for {:?}",
            harness
        );

        let drain_out = run_hook(
            &sock,
            *harness,
            HookEvent::PreInvocation,
            hook_payload.clone(),
        )
        .await;
        let drained_text = extract_pre_turn_drain_text(*harness, &drain_out);

        let st_after_drain = session_status(&sock, &session_id).await;

        // Check `hyp_inbox(state:"delivered")` matches identically across all 9 harnesses!
        let delivered_args = json!({ "state": "delivered" });
        let (deliv_txt, deliv_err) = if *lazy_ag {
            worker_mcp
                .call_verified_antigravity_lazy(&sock, raw_id, "hyp_inbox", delivered_args)
                .await
        } else {
            worker_mcp
                .call_verified_for_harness(&sock, *harness, raw_id, "hyp_inbox", delivered_args)
                .await
        };
        assert!(
            !deliv_err,
            "delivered query failed for {raw_id}: {deliv_txt}"
        );
        let deliv_val: Value = serde_json::from_str(&deliv_txt).unwrap();
        let deliv_items = deliv_val["items"].as_array().unwrap();

        // 4. Send DM #2 -> verify Stop hook drains into harness-specific continuation envelope!
        let msg2 = format!("parity-msg-2-{raw_id}");
        let (_, dm2_err) = sender_mcp
            .call_verified_claude(
                &sock,
                "sender-0",
                "hyp_send",
                json!({ "to": format!("parity@box/{handle}"), "text": msg2 }),
            )
            .await;
        assert!(!dm2_err);
        wait_for_pending_count(&sock, &session_id, 1).await;

        let stop_drain = run_hook(&sock, *harness, HookEvent::Stop, hook_payload.clone()).await;
        let stop_reason = if *harness == HarnessKind::Openclaw {
            // OpenClaw `agent_end` is observational-only (`{}`) — flips Active -> Idle without
            // mutating/blocking turn end, preserving DM #2 intact for `before_prompt_build`.
            assert_eq!(stop_drain, json!({}));
            let oc_next = run_hook(
                &sock,
                *harness,
                HookEvent::PreInvocation,
                hook_payload.clone(),
            )
            .await;
            extract_pre_turn_drain_text(*harness, &oc_next)
        } else {
            extract_stop_reason(*harness, &stop_drain)
        };

        // 5. Idle Stop hook (no unread, no live transport):
        //    - Herdr, T3, and OpenClaw rely on native push/ephemeral turn orchestration and
        //      must return `{}` cleanly instead of prompting for Claude Monitor or `hyp wait`.
        //    - Claude, Codex, Antigravity, Cursor, OpenCode, and Gemini prompt with their exact
        //      harness-native background waiter command.
        let stop_idle = run_hook(&sock, *harness, HookEvent::Stop, hook_payload.clone()).await;
        if matches!(
            *harness,
            HarnessKind::Herdr | HarnessKind::T3 | HarnessKind::Openclaw
        ) {
            assert_eq!(
                stop_idle,
                json!({}),
                "idle Stop for {raw_id} must stay silent (no waiter-arm prompt)"
            );
        } else {
            let idle_reason = extract_stop_reason(*harness, &stop_idle);
            assert!(
                idle_reason.contains(&session_id),
                "idle Stop arm prompt for {raw_id} must mention {session_id}: {idle_reason}"
            );
            if *harness == HarnessKind::Claude {
                assert!(
                    idle_reason.contains("Monitor") && idle_reason.contains("hyp watch"),
                    "Claude idle Stop prompt should offer Monitor + hyp watch: {idle_reason}"
                );
            } else {
                assert!(
                    !idle_reason.contains("Monitor"),
                    "non-Claude idle Stop prompt for {raw_id} must never mention Monitor: {idle_reason}"
                );
                assert!(
                    idle_reason.contains("hyp wait"),
                    "standalone idle Stop prompt for {raw_id} must mention hyp wait: {idle_reason}"
                );
            }
            if *harness == HarnessKind::Antigravity {
                assert!(
                    idle_reason.contains("WaitMsBeforeAsync: 500, IsDaemon: false"),
                    "Antigravity idle Stop prompt must include WaitMsBeforeAsync: {idle_reason}"
                );
            } else {
                assert!(
                    !idle_reason.contains("WaitMsBeforeAsync"),
                    "non-Antigravity idle Stop prompt for {raw_id} must not mention WaitMsBeforeAsync: {idle_reason}"
                );
            }
        }

        // 6. Harness sends a reply back to `sender` via `hyp_send`!
        let reply_args = json!({
            "to": "parity@box/sender",
            "text": format!("reply-from-{raw_id}")
        });
        let (rep_txt, rep_err) = if *lazy_ag {
            worker_mcp
                .call_verified_antigravity_lazy(&sock, raw_id, "hyp_send", reply_args)
                .await
        } else {
            worker_mcp
                .call_verified_for_harness(&sock, *harness, raw_id, "hyp_send", reply_args)
                .await
        };
        assert!(!rep_err, "reply send failed for {raw_id}: {rep_txt}");

        outcomes.push(ParityOutcome {
            enrolled_after_join: st_after_join["enrolled"].as_bool() == Some(true),
            pending_after_drain: st_after_drain["pending"].as_u64().unwrap_or(99),
            delivered_count_after_drain: deliv_items.len(),
            drain_contained_msg1: drained_text.contains(&msg1),
            stop_contained_msg2: stop_reason.contains(&msg2),
            reply_sent_ok: !rep_err,
        });
    }

    // Differential assertion: every single harness mode achieved identical post-state!
    let expected = ParityOutcome {
        enrolled_after_join: true,
        pending_after_drain: 0,
        delivered_count_after_drain: 1,
        drain_contained_msg1: true,
        stop_contained_msg2: true,
        reply_sent_ok: true,
    };
    for (idx, outcome) in outcomes.iter().enumerate() {
        assert_eq!(
            outcome, &expected,
            "differential divergence on harness case {:?}",
            cases[idx]
        );
    }

    // Verify `sender` received all 10 replies!
    wait_for_pending_count(&sock, "claude:sender-0", cases.len() as u64).await;
    let (s_inbox_txt, s_inbox_err) = sender_mcp
        .call_verified_claude(
            &sock,
            "sender-0",
            "hyp_inbox",
            json!({ "state": "unread", "limit": 20, "ack": true }),
        )
        .await;
    assert!(!s_inbox_err);
    let s_inbox: Value = serde_json::from_str(&s_inbox_txt).unwrap();
    assert_eq!(s_inbox["items"].as_array().unwrap().len(), cases.len());

    worker_mcp.close().await;
    sender_mcp.close().await;
    daemon.stop().await;
    node.shutdown();
}

// ============================================================================
// Suite 2: Live Caller Spoofing & Race Protection Matrix
// ============================================================================

#[tokio::test]
async fn suite_2_live_caller_spoofing_and_race_protection_matrix() {
    let dir = TempDir::new().unwrap();
    let node = open_local_node("guard@box", dir.path());
    let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .unwrap();
    let sock = daemon.socket_path().to_path_buf();

    let mut mcp = TestMcpClient::spawn(McpOptions::new(sock.clone()));
    mcp.initialize().await;

    // 1. Unverified `tools/call` (no `_meta`, no `_meshCall`) -> `caller_unverifiable`
    let (unv_txt, unv_err) = mcp
        .call_tool(
            "hyp_mesh",
            json!({ "action": "join", "handle": "spoof" }),
            None,
        )
        .await;
    assert!(unv_err, "unverified call must fail closed");
    assert!(
        unv_txt.contains("caller_unverifiable"),
        "expected caller_unverifiable, got: {unv_txt}"
    );

    // 2. Single-use token replay (Antigravity `_meshCall` AND Claude `toolUseId`) -> `caller_not_found`
    let ag_pre = run_hook(
        &sock,
        HarnessKind::Antigravity,
        HookEvent::PreToolUse,
        json!({
            "conversationId": "replay-ag",
            "toolCall": {
                "id": "ag-replay-1",
                "name": "hyp_mesh",
                "args": { "action": "join", "handle": "ag-once" }
            }
        }),
    )
    .await;
    let ag_tok = ag_pre["overwrite"]["_meshCall"]
        .as_str()
        .unwrap()
        .to_string();

    let (first_ag_txt, first_ag_err) = mcp
        .call_tool(
            "hyp_mesh",
            json!({ "action": "join", "handle": "ag-once", "_meshCall": ag_tok }),
            None,
        )
        .await;
    assert!(
        !first_ag_err,
        "1st use of AG token must succeed: {first_ag_txt}"
    );

    // Mint Claude callId & consume it once
    let _ = run_hook(
        &sock,
        HarnessKind::Claude,
        HookEvent::PreToolUse,
        json!({
            "session_id": "replay-cl",
            "tool_use_id": "toolu_replay_once",
            "tool_name": "mcp__hyphae__hyp_mesh",
            "tool_input": { "action": "join", "handle": "cl-once" }
        }),
    )
    .await;
    let (first_cl_txt, first_cl_err) = mcp
        .call_tool(
            "hyp_mesh",
            json!({ "action": "join", "handle": "cl-once" }),
            Some(json!({ "claudecode/toolUseId": "toolu_replay_once" })),
        )
        .await;
    assert!(
        !first_cl_err,
        "1st use of Claude callId must succeed: {first_cl_txt}"
    );

    // Mint cross-tool swap token (PreToolUse for `hyp_inbox`, later used on `hyp_send`)
    let swap_pre = run_hook(
        &sock,
        HarnessKind::Antigravity,
        HookEvent::PreToolUse,
        json!({
            "conversationId": "replay-ag",
            "toolCall": {
                "id": "ag-swap-1",
                "name": "hyp_inbox",
                "args": { "state": "unread" }
            }
        }),
    )
    .await;
    let swap_tok = swap_pre["overwrite"]["_meshCall"]
        .as_str()
        .unwrap()
        .to_string();

    // Register & immediately cancel via PostToolUse `call.end`
    let _ = run_hook(
        &sock,
        HarnessKind::Claude,
        HookEvent::PreToolUse,
        json!({
            "session_id": "replay-cl",
            "tool_use_id": "toolu_cancelled_9",
            "tool_name": "mcp__hyphae__hyp_inbox",
            "tool_input": { "state": "unread" }
        }),
    )
    .await;
    let _ = run_hook(
        &sock,
        HarnessKind::Claude,
        HookEvent::PostToolUse,
        json!({
            "session_id": "replay-cl",
            "tool_use_id": "toolu_cancelled_9"
        }),
    )
    .await;

    // 3. Ambiguous concurrent `callId` across 2 distinct sessions -> `caller_ambiguous`!
    let _ = run_hook(
        &sock,
        HarnessKind::Claude,
        HookEvent::PreToolUse,
        json!({
            "session_id": "amb-session-a",
            "tool_use_id": "toolu_ambiguous_77",
            "tool_name": "mcp__hyphae__hyp_inbox",
            "tool_input": { "state": "unread" }
        }),
    )
    .await;
    let _ = run_hook(
        &sock,
        HarnessKind::Claude,
        HookEvent::PreToolUse,
        json!({
            "session_id": "amb-session-b",
            "tool_use_id": "toolu_ambiguous_77",
            "tool_name": "mcp__hyphae__hyp_inbox",
            "tool_input": { "state": "unread" }
        }),
    )
    .await;
    let (amb_txt, amb_err) = mcp
        .call_tool(
            "hyp_inbox",
            json!({ "state": "unread" }),
            Some(json!({ "claudecode/toolUseId": "toolu_ambiguous_77" })),
        )
        .await;
    assert!(amb_err, "ambiguous callId must fail closed");
    assert!(
        amb_txt.contains("caller_ambiguous"),
        "expected caller_ambiguous, got: {amb_txt}"
    );

    // Run token/callId fail-closed checks concurrently so 1.5s token resolve waits overlap!
    let sock_a = sock.clone();
    let sock_b = sock.clone();
    let sock_c = sock.clone();
    let sock_d = sock.clone();
    let sock_e = sock.clone();
    let (
        (ag_replay_txt, ag_replay_err),
        (cl_replay_txt, cl_replay_err),
        (swap_txt, swap_err),
        (forged_txt, forged_err),
        (cancel_txt, cancel_err),
    ) = tokio::join!(
        async move {
            let mut c = TestMcpClient::spawn(McpOptions::new(sock_a));
            c.initialize().await;
            let res = c
                .call_tool(
                    "hyp_mesh",
                    json!({ "action": "join", "handle": "ag-twice", "_meshCall": ag_tok }),
                    None,
                )
                .await;
            c.close().await;
            res
        },
        async move {
            let mut c = TestMcpClient::spawn(McpOptions::new(sock_b));
            c.initialize().await;
            let res = c
                .call_tool(
                    "hyp_mesh",
                    json!({ "action": "join", "handle": "cl-twice" }),
                    Some(json!({ "claudecode/toolUseId": "toolu_replay_once" })),
                )
                .await;
            c.close().await;
            res
        },
        async move {
            let mut c = TestMcpClient::spawn(McpOptions::new(sock_c));
            c.initialize().await;
            let res = c
                .call_tool(
                    "hyp_send",
                    json!({ "to": "guard@box/cl-once", "text": "swap!", "_meshCall": swap_tok }),
                    None,
                )
                .await;
            c.close().await;
            res
        },
        async move {
            let mut c = TestMcpClient::spawn(McpOptions::new(sock_d));
            c.initialize().await;
            let res = c
                .call_tool(
                    "hyp_mesh",
                    json!({
                        "action": "join",
                        "handle": "forged",
                        "_meshCall": "ct_0000000000000000000000000000000000000000"
                    }),
                    None,
                )
                .await;
            c.close().await;
            res
        },
        async move {
            let mut c = TestMcpClient::spawn(McpOptions::new(sock_e));
            c.initialize().await;
            let res = c
                .call_tool(
                    "hyp_inbox",
                    json!({ "state": "unread" }),
                    Some(json!({ "claudecode/toolUseId": "toolu_cancelled_9" })),
                )
                .await;
            c.close().await;
            res
        }
    );

    assert!(
        ag_replay_err && ag_replay_txt.contains("caller_not_found"),
        "AG replay: {ag_replay_txt}"
    );
    assert!(
        cl_replay_err && cl_replay_txt.contains("caller_not_found"),
        "Claude replay: {cl_replay_txt}"
    );
    assert!(
        swap_err && swap_txt.contains("caller_not_found"),
        "Cross-tool swap: {swap_txt}"
    );
    assert!(
        forged_err && forged_txt.contains("caller_not_found"),
        "Forged token: {forged_txt}"
    );
    assert!(
        cancel_err && cancel_txt.contains("caller_not_found"),
        "Cancelled call.end: {cancel_txt}"
    );

    // 4. `tools/call` racing 20ms BEFORE `PreToolUse` -> wakes cleanly via CallRegistry Notify!
    let sock_race = sock.clone();
    let delayed_hook = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(20)).await;
        run_hook(
            &sock_race,
            HarnessKind::Claude,
            HookEvent::PreToolUse,
            json!({
                "session_id": "race-winner",
                "tool_use_id": "toolu_race_20ms",
                "tool_name": "mcp__hyphae__hyp_mesh",
                "tool_input": { "action": "join", "handle": "racer" }
            }),
        )
        .await;
    });

    let (race_txt, race_err) = mcp
        .call_tool(
            "hyp_mesh",
            json!({ "action": "join", "handle": "racer" }),
            Some(json!({ "claudecode/toolUseId": "toolu_race_20ms" })),
        )
        .await;
    delayed_hook.await.unwrap();
    assert!(
        !race_err,
        "racing tools/call should resolve via Notify: {race_txt}"
    );
    let race_val: Value = serde_json::from_str(&race_txt).unwrap();
    assert_eq!(race_val["address"], "guard@box/racer");

    mcp.close().await;
    daemon.stop().await;
    node.shutdown();
}

// ============================================================================
// Suite 3A: Live §2.5 Delivery Policy, Burst, Hybrid Packer, Truncation,
//           Strict Focus Mode & Filtered/Paginated `hyp_inbox`
// ============================================================================

#[tokio::test]
async fn suite_3a_live_delivery_policy_burst_hybrid_packer_truncation_focus_and_filtered_inbox() {
    let dir = TempDir::new().unwrap();
    let node = open_local_node("delivery@box", dir.path());

    // Attach SecurityGatePipeline sharing the same SQLite DB so we can verify quarantined-ID isolation!
    let gate_db = Arc::new(Mutex::new(
        NodeDb::open(dir.path().join("node.sqlite")).unwrap(),
    ));
    let mut gate_cfg = SecurityGateConfig::default();
    gate_cfg
        .stage1
        .inbound_regex_denylist
        .push("EXFIL_QUARANTINE_TEST".into());
    gate_cfg.stage1.regex_deny_action = Stage1DenyAction::Quarantine;
    let pipeline = Arc::new(SecurityGatePipeline::new(gate_cfg, gate_db, None).unwrap());

    let daemon = LocalDaemon::start(
        Arc::clone(&node),
        Some(Arc::clone(&pipeline)),
        LocalDaemonConfig::default(),
    )
    .await
    .unwrap();
    let sock = daemon.socket_path().to_path_buf();

    let mut mcp = TestMcpClient::spawn(McpOptions::new(sock.clone()));
    mcp.initialize().await;

    for (sess, handle) in [
        ("recv-1", "recv"),
        ("noisy-1", "noisy"),
        ("calm-1", "calm"),
        ("vip-1", "vip"),
    ] {
        let (txt, err) = mcp
            .call_verified_claude(
                &sock,
                sess,
                "hyp_mesh",
                json!({ "action": "join", "handle": handle }),
            )
            .await;
        assert!(!err, "join {handle} failed: {txt}");
    }

    // ---- 3.1 Adaptive Burst Storm (12 rapid messages from `noisy` -> trips Noisy Mode while `calm` delivers normally) ----
    for i in 0..10 {
        let (txt, err) = mcp
            .call_verified_claude(
                &sock,
                "noisy-1",
                "hyp_send",
                json!({ "to": "delivery@box/recv", "text": format!("warmup-burst-{i}") }),
            )
            .await;
        assert!(!err, "warmup {i} failed: {txt}");
    }
    wait_for_pending_count(&sock, "claude:recv-1", 10).await;
    // Ack warmup 10 so rolling arrival window now holds 10 arrivals from `delivery@box/noisy`.
    let (ack_w_txt, ack_w_err) = mcp
        .call_verified_claude(
            &sock,
            "recv-1",
            "hyp_inbox",
            json!({ "state": "unread", "limit": 20, "ack": true }),
        )
        .await;
    assert!(!ack_w_err, "warmup ack failed: {ack_w_txt}");
    assert_eq!(
        serde_json::from_str::<Value>(&ack_w_txt).unwrap()["unread"],
        0
    );

    // Messages #11 and #12 from `noisy` exceed `max_events_per_window = 10` -> trips burst protection!
    for i in 10..12 {
        let (_, err) = mcp
            .call_verified_claude(
                &sock,
                "noisy-1",
                "hyp_send",
                json!({ "to": "delivery@box/recv", "text": format!("tripped-burst-{i}") }),
            )
            .await;
        assert!(!err);
    }
    wait_for_pending_count(&sock, "claude:recv-1", 2).await;

    let burst_drain = run_hook(
        &sock,
        HarnessKind::Claude,
        HookEvent::PreInvocation,
        json!({ "session_id": "recv-1" }),
    )
    .await;
    let burst_ctx = burst_drain["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("burst-demoted arrivals must emit 1-line notify digest");
    assert!(
        burst_ctx.contains("hyphae notify · 2 unread"),
        "expected burst 1-line digest, got: {burst_ctx}"
    );
    assert!(
        !burst_ctx.contains("tripped-burst-10"),
        "burst-demoted bodies must stay in inbox, got: {burst_ctx}"
    );
    assert!(
        daemon
            .delivery()
            .is_source_noisy("claude:recv-1", "delivery@box/noisy", now_ms())
    );

    // Independent peer `calm` is NOT in Noisy Mode -> delivers verbatim inline at TurnStart/TurnEnd!
    let (_, calm_err) = mcp
        .call_verified_claude(
            &sock,
            "calm-1",
            "hyp_send",
            json!({ "to": "delivery@box/recv", "text": "CALM_PEER_DELIVERS_NORMALLY" }),
        )
        .await;
    assert!(!calm_err);
    wait_for_pending_count(&sock, "claude:recv-1", 3).await;

    let calm_drain = run_hook(
        &sock,
        HarnessKind::Claude,
        HookEvent::PreInvocation,
        json!({ "session_id": "recv-1" }),
    )
    .await;
    let calm_ctx = calm_drain["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("calm peer message must deliver inline");
    assert!(calm_ctx.contains("CALM_PEER_DELIVERS_NORMALLY"));
    assert!(calm_ctx.contains("+2 more unread"));

    // Clean out the 2 unread burst messages before hybrid packer test.
    let (_, ack_b_err) = mcp
        .call_verified_claude(
            &sock,
            "recv-1",
            "hyp_inbox",
            json!({ "state": "unread", "ack": true }),
        )
        .await;
    assert!(!ack_b_err);

    // ---- 3.2 Token-Budget Hybrid Batch Packer (1 VIP `interrupt` + 15 noisy -> VIP inline, 15 spilled, 0 duplicate) ----
    let (_, vip_rule_err) = mcp
        .call_verified_claude(
            &sock,
            "recv-1",
            "hyp_inbox",
            json!({ "rules": [{ "target": "@vip", "delivery": "interrupt" }] }),
        )
        .await;
    assert!(!vip_rule_err);

    // `noisy` is already in Noisy Mode (burst-demoted) -> all 15 spill to digest!
    for i in 0..15 {
        let (_, err) = mcp
            .call_verified_claude(
                &sock,
                "noisy-1",
                "hyp_send",
                json!({ "to": "delivery@box/recv", "text": format!("hybrid-noisy-{i:02}") }),
            )
            .await;
        assert!(!err);
    }
    let (_, vip_err) = mcp
        .call_verified_claude(
            &sock,
            "vip-1",
            "hyp_send",
            json!({ "to": "delivery@box/recv", "text": "VIP_HYBRID_INLINE_URGENT" }),
        )
        .await;
    assert!(!vip_err);
    wait_for_pending_count(&sock, "claude:recv-1", 16).await;

    let hybrid_drain = run_hook(
        &sock,
        HarnessKind::Claude,
        HookEvent::PostToolUse,
        json!({ "session_id": "recv-1", "tool_use_id": "drain-hybrid-1" }),
    )
    .await;
    let hybrid_ctx = hybrid_drain["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("hybrid batch must deliver");
    assert!(
        hybrid_ctx.contains("VIP_HYBRID_INLINE_URGENT"),
        "VIP interrupt must pack verbatim inline: {hybrid_ctx}"
    );
    assert!(
        hybrid_ctx.contains("+15 more unread"),
        "15 noisy messages must spill to digest footer: {hybrid_ctx}"
    );
    assert!(
        !hybrid_ctx.contains("hybrid-noisy-00"),
        "spilled noisy messages must not be inlined: {hybrid_ctx}"
    );

    // Subsequent PostToolUse MUST NOT duplicate the 15 already-notified spilled items!
    let no_dup_drain = run_hook(
        &sock,
        HarnessKind::Claude,
        HookEvent::PostToolUse,
        json!({ "session_id": "recv-1", "tool_use_id": "drain-hybrid-nodup" }),
    )
    .await;
    assert_eq!(
        no_dup_drain,
        json!({}),
        "already-notified spilled items must NOT re-emit on subsequent PostToolUse"
    );

    // Read all 15 spilled messages cleanly via cursor-paginated `hyp_inbox` (5 + 5 + 5)!
    let mut collected_texts = Vec::new();
    let mut cursor: Option<String> = None;
    for page_idx in 0..3 {
        let mut args = json!({ "state": "unread", "limit": 5 });
        if let Some(ref c) = cursor {
            args["cursor"] = json!(c);
        }
        let (p_txt, p_err) = mcp
            .call_verified_claude(&sock, "recv-1", "hyp_inbox", args)
            .await;
        assert!(!p_err, "page {page_idx} failed: {p_txt}");
        let p_val: Value = serde_json::from_str(&p_txt).unwrap();
        let items = p_val["items"].as_array().unwrap();
        assert_eq!(items.len(), 5, "page {page_idx} must have 5 items");
        for it in items {
            collected_texts.push(it["text"].as_str().unwrap().to_string());
        }
        if page_idx < 2 {
            assert_eq!(p_val["hasMore"], true);
            cursor = p_val["nextCursor"].as_str().map(ToString::to_string);
            assert!(cursor.is_some());
        } else {
            assert_eq!(p_val["hasMore"], false);
        }
    }
    assert_eq!(collected_texts.len(), 15);
    assert!(
        collected_texts
            .iter()
            .any(|t| t.contains("hybrid-noisy-00"))
    );
    assert!(
        collected_texts
            .iter()
            .any(|t| t.contains("hybrid-noisy-14"))
    );

    // Ack all 15 noisy unread items.
    let (_, ack_15_err) = mcp
        .call_verified_claude(
            &sock,
            "recv-1",
            "hyp_inbox",
            json!({ "state": "unread", "limit": 20, "ack": true }),
        )
        .await;
    assert!(!ack_15_err);

    // ---- 3.3 Single Giant Payload Truncation + Full Retrieval via `hyp_inbox(ids:[...])` ----
    let giant_body = format!(
        "GIANT_HEADER_BEGIN {} GIANT_TAIL_SENTINEL",
        "X".repeat(4_800)
    );
    let (_, giant_send_err) = mcp
        .call_verified_claude(
            &sock,
            "calm-1",
            "hyp_send",
            json!({ "to": "delivery@box/recv", "text": giant_body }),
        )
        .await;
    assert!(!giant_send_err);
    wait_for_pending_count(&sock, "claude:recv-1", 1).await;

    let giant_drain = run_hook(
        &sock,
        HarnessKind::Claude,
        HookEvent::PreInvocation,
        json!({ "session_id": "recv-1" }),
    )
    .await;
    let giant_ctx = giant_drain["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("giant payload must emit truncated preview");
    assert!(giant_ctx.contains("GIANT_HEADER_BEGIN"));
    assert!(!giant_ctx.contains("GIANT_TAIL_SENTINEL"));
    assert!(
        giant_ctx.contains("full body in hyp_inbox(ids:[\""),
        "expected hyp_inbox(ids:[...]) hint, got: {giant_ctx}"
    );

    // Second TurnStart must NOT re-emit the truncated giant preview!
    let giant_nodup = run_hook(
        &sock,
        HarnessKind::Claude,
        HookEvent::PreInvocation,
        json!({ "session_id": "recv-1" }),
    )
    .await;
    assert_eq!(giant_nodup, json!({}));

    // Parse receipt ID from the hint and fetch the complete intact body via `hyp_inbox(ids:[...])`!
    let marker = "full body in hyp_inbox(ids:[\"";
    let start = giant_ctx.find(marker).unwrap() + marker.len();
    let end = giant_ctx[start..].find("\"])").unwrap() + start;
    let giant_receipt = &giant_ctx[start..end];

    let (full_txt, full_err) = mcp
        .call_verified_claude(
            &sock,
            "recv-1",
            "hyp_inbox",
            json!({ "ids": [giant_receipt], "ack": true }),
        )
        .await;
    assert!(!full_err, "hyp_inbox(ids:[...]) failed: {full_txt}");
    let full_val: Value = serde_json::from_str(&full_txt).unwrap();
    let full_items = full_val["items"].as_array().unwrap();
    assert_eq!(full_items.len(), 1);
    let retrieved_text = full_items[0]["text"].as_str().unwrap();
    assert!(retrieved_text.contains("GIANT_HEADER_BEGIN"));
    assert!(retrieved_text.contains("GIANT_TAIL_SENTINEL"));
    assert!(retrieved_text.len() >= 4_800);

    // ---- 3.4 Strict Focus Mode (`focusAllowInterruptVips: false` vs `true`) ----
    let (strict_txt, strict_err) = mcp
        .call_verified_claude(
            &sock,
            "recv-1",
            "hyp_inbox",
            json!({
                "focusMode": true,
                "focusAllowInterruptVips": false,
                "rules": [{ "target": "@vip", "delivery": "interrupt" }]
            }),
        )
        .await;
    assert!(!strict_err, "strict focus mode failed: {strict_txt}");
    let strict_val: Value = serde_json::from_str(&strict_txt).unwrap();
    assert_eq!(strict_val["focusMode"], true);
    assert_eq!(strict_val["focusAllowInterruptVips"], false);

    let (_, vip_held_err) = mcp
        .call_verified_claude(
            &sock,
            "vip-1",
            "hyp_send",
            json!({ "to": "delivery@box/recv", "text": "STRICT_FOCUS_HELD_VIP" }),
        )
        .await;
    assert!(!vip_held_err);
    wait_for_pending_count(&sock, "claude:recv-1", 1).await;

    let strict_drain = run_hook(
        &sock,
        HarnessKind::Claude,
        HookEvent::PreInvocation,
        json!({ "session_id": "recv-1" }),
    )
    .await;
    let strict_ctx = strict_drain["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("strict focus mode should still emit slim 1-line digest");
    assert!(strict_ctx.contains("hyphae notify · 1 unread"));
    assert!(
        !strict_ctx.contains("STRICT_FOCUS_HELD_VIP"),
        "strict focus mode must hold even VIP interrupts in inbox: {strict_ctx}"
    );
    // Ack held VIP item.
    let (_, _) = mcp
        .call_verified_claude(
            &sock,
            "recv-1",
            "hyp_inbox",
            json!({ "state": "unread", "ack": true }),
        )
        .await;

    // Now allow VIP interrupts through Focus Mode!
    let (vip_on_txt, vip_on_err) = mcp
        .call_verified_claude(
            &sock,
            "recv-1",
            "hyp_inbox",
            json!({ "focusMode": true, "focusAllowInterruptVips": true }),
        )
        .await;
    assert!(!vip_on_err, "vip focus toggle failed: {vip_on_txt}");

    let (_, _) = mcp
        .call_verified_claude(
            &sock,
            "vip-1",
            "hyp_send",
            json!({ "to": "delivery@box/recv", "text": "VIP_BREAKS_THROUGH_FOCUS" }),
        )
        .await;
    let (_, _) = mcp
        .call_verified_claude(
            &sock,
            "calm-1",
            "hyp_send",
            json!({ "to": "delivery@box/recv", "text": "CALM_HELD_IN_FOCUS" }),
        )
        .await;
    wait_for_pending_count(&sock, "claude:recv-1", 2).await;

    let vip_drain = run_hook(
        &sock,
        HarnessKind::Claude,
        HookEvent::PostToolUse,
        json!({ "session_id": "recv-1", "tool_use_id": "drain-vip-break" }),
    )
    .await;
    let vip_ctx = vip_drain["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .expect("VIP must break through focus mode");
    assert!(vip_ctx.contains("VIP_BREAKS_THROUGH_FOCUS"));
    assert!(!vip_ctx.contains("CALM_HELD_IN_FOCUS"));
    assert!(vip_ctx.contains("+1 more unread"));

    // ---- 3.5 Filtered `hyp_inbox` (`from`, `node`, `channel`, `summary`, `delivered`, corrupt cursor, quarantined receipt) ----
    // Ingest a `#ops` channel post from remote node `acme-team` (held unread due to Focus Mode)
    // alongside the existing unread `CALM_HELD_IN_FOCUS` DM from `delivery@box/calm`!
    let ch_u = daemon
        .ingest_inbound(InboundItem {
            session_id: "claude:recv-1".into(),
            origin_node: "acme-team".into(),
            item_id: "ops-ch-item-1".into(),
            source: "acme-team/#ops:bob@laptop/codex".into(),
            text: "OPS_CHANNEL_FILTER_TEST".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::Org,
        })
        .await
        .unwrap();
    assert!(ch_u.is_some());
    wait_for_pending_count(&sock, "claude:recv-1", 2).await;

    // Filter by `from`
    let (from_txt, from_err) = mcp
        .call_verified_claude(
            &sock,
            "recv-1",
            "hyp_inbox",
            json!({ "state": "unread", "filter": { "from": "delivery@box/calm" } }),
        )
        .await;
    assert!(!from_err, "from filter failed: {from_txt}");
    let from_val: Value = serde_json::from_str(&from_txt).unwrap();
    let from_items = from_val["items"].as_array().unwrap();
    assert_eq!(from_items.len(), 1);
    assert!(
        from_items[0]["text"]
            .as_str()
            .unwrap()
            .contains("CALM_HELD_IN_FOCUS")
    );

    // Filter by `node` (distinguishes `delivery@box` vs `acme-team` vs non-matching!)
    let (node_local_txt, node_local_err) = mcp
        .call_verified_claude(
            &sock,
            "recv-1",
            "hyp_inbox",
            json!({ "state": "unread", "filter": { "node": "delivery@box" } }),
        )
        .await;
    assert!(!node_local_err);
    assert_eq!(
        serde_json::from_str::<Value>(&node_local_txt).unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let (node_remote_txt, node_remote_err) = mcp
        .call_verified_claude(
            &sock,
            "recv-1",
            "hyp_inbox",
            json!({ "state": "unread", "filter": { "node": "acme-team" } }),
        )
        .await;
    assert!(!node_remote_err);
    assert_eq!(
        serde_json::from_str::<Value>(&node_remote_txt).unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let (node_miss_txt, node_miss_err) = mcp
        .call_verified_claude(
            &sock,
            "recv-1",
            "hyp_inbox",
            json!({ "state": "unread", "filter": { "node": "other@missing" } }),
        )
        .await;
    assert!(!node_miss_err);
    assert_eq!(
        serde_json::from_str::<Value>(&node_miss_txt).unwrap()["items"]
            .as_array()
            .unwrap()
            .len(),
        0
    );

    // Filter by `channel`
    let (ch_flt_txt, ch_flt_err) = mcp
        .call_verified_claude(
            &sock,
            "recv-1",
            "hyp_inbox",
            json!({ "state": "unread", "filter": { "channel": "#ops" } }),
        )
        .await;
    assert!(!ch_flt_err, "channel filter failed: {ch_flt_txt}");
    let ch_items = serde_json::from_str::<Value>(&ch_flt_txt).unwrap()["items"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(ch_items.len(), 1);
    assert!(
        ch_items[0]["text"]
            .as_str()
            .unwrap()
            .contains("OPS_CHANNEL_FILTER_TEST")
    );

    // `summary: true` omits `text` and returns concise `preview`
    let (sum_txt, sum_err) = mcp
        .call_verified_claude(
            &sock,
            "recv-1",
            "hyp_inbox",
            json!({ "state": "unread", "summary": true }),
        )
        .await;
    assert!(!sum_err);
    let sum_items = serde_json::from_str::<Value>(&sum_txt).unwrap()["items"]
        .as_array()
        .unwrap()
        .clone();
    assert!(!sum_items.is_empty());
    assert!(sum_items[0].get("text").is_none());
    assert!(
        sum_items[0]["preview"]
            .as_str()
            .is_some_and(|p| !p.is_empty())
    );

    // `state: "delivered"` contains prior delivered items (VIP breakthrough & hybrid inline)
    let (del_txt, del_err) = mcp
        .call_verified_claude(
            &sock,
            "recv-1",
            "hyp_inbox",
            json!({ "state": "delivered", "limit": 50 }),
        )
        .await;
    assert!(!del_err);
    let del_items = serde_json::from_str::<Value>(&del_txt).unwrap()["items"]
        .as_array()
        .unwrap()
        .clone();
    assert!(del_items.iter().any(|i| {
        i["text"]
            .as_str()
            .unwrap_or("")
            .contains("VIP_HYBRID_INLINE_URGENT")
    }));
    assert!(del_items.iter().any(|i| {
        i["text"]
            .as_str()
            .unwrap_or("")
            .contains("VIP_BREAKS_THROUGH_FOCUS")
    }));

    // Corrupt cursor fails closed!
    let (bad_cur_txt, bad_cur_err) = mcp
        .call_verified_claude(
            &sock,
            "recv-1",
            "hyp_inbox",
            json!({ "state": "unread", "cursor": "!!!not-valid-base64!!!" }),
        )
        .await;
    assert!(
        bad_cur_err,
        "corrupt cursor must fail closed, got: {bad_cur_txt}"
    );

    // Quarantined receipt explicitly queried via `ids: [quarantined_receipt]` returns ZERO body!
    let q_decision = daemon
        .ingest_inbound(InboundItem {
            session_id: "claude:recv-1".into(),
            origin_node: "untrusted@ext".into(),
            item_id: "q-evil-99".into(),
            source: "untrusted@ext/bot".into(),
            text: "TOP SECRET EXFIL_QUARANTINE_TEST DO NOT SHOW".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::Guest,
        })
        .await
        .unwrap();
    assert!(q_decision.is_none());

    let quarantined = daemon
        .node()
        .db()
        .local()
        .list_quarantined(Some("claude:recv-1"), 10)
        .unwrap();
    assert_eq!(quarantined.len(), 1);
    let q_receipt = quarantined[0].receipt.clone();

    let (q_id_txt, q_id_err) = mcp
        .call_verified_claude(
            &sock,
            "recv-1",
            "hyp_inbox",
            json!({ "state": "all", "ids": [q_receipt] }),
        )
        .await;
    assert!(
        !q_id_err,
        "ids lookup returned unexpected error: {q_id_txt}"
    );
    let q_id_val: Value = serde_json::from_str(&q_id_txt).unwrap();
    assert_eq!(
        q_id_val["items"].as_array().unwrap().len(),
        0,
        "quarantined receipt must NEVER be returned even by explicit ids!"
    );
    assert!(!q_id_txt.contains("EXFIL_QUARANTINE_TEST"));

    mcp.close().await;
    daemon.stop().await;
    node.shutdown();
}

// ============================================================================
// Suite 3B: Live `hyp_send({ to, files })` E2EE File Drop via MCP
// ============================================================================

#[tokio::test]
async fn suite_3b_live_e2ee_file_drop_via_mcp() {
    let hub_dir = TempDir::new().unwrap();
    let alice_dir = TempDir::new().unwrap();
    let bob_dir = TempDir::new().unwrap();
    let payload_dir = TempDir::new().unwrap();

    let admin_ca = Ed25519KeyPair::generate().unwrap();
    let admin_jwk = OkpJwk::new(OkpCurve::Ed25519, &admin_ca.public_key_bytes());
    let mut hub_cfg = NodeConfig::router(NodeId::new("file-hub").unwrap(), hub_dir.path());
    hub_cfg.secret_backend = Some(SecretBackend::File);
    hub_cfg.admin_jwk = Some(admin_jwk);
    let hub = UnifiedNode::open(hub_cfg).unwrap();
    let (_hub_addr, _hub_srv) = Arc::clone(&hub).serve(loopback_zero()).await.unwrap();

    let alice_node = open_local_node("alice@filebox", alice_dir.path());
    let bob_node = open_local_node("bob@filebox", bob_dir.path());

    let mut scopes = ScopePreset::Member.expand();
    scopes.push("files:send=*".into());
    let scope_refs: Vec<&str> = scopes.iter().map(String::as_str).collect();

    let (alice_am2, _) = hub
        .create_admin_invite(
            &admin_ca,
            "alice@filebox",
            &scope_refs,
            TrustTier::Org,
            300_000,
        )
        .unwrap();
    let (bob_am2, _) = hub
        .create_admin_invite(
            &admin_ca,
            "bob@filebox",
            &scope_refs,
            TrustTier::Org,
            300_000,
        )
        .unwrap();
    alice_node.accept_am2_invite(&alice_am2).await.unwrap();
    bob_node.accept_am2_invite(&bob_am2).await.unwrap();

    let alice_daemon =
        LocalDaemon::start(Arc::clone(&alice_node), None, LocalDaemonConfig::default())
            .await
            .unwrap();
    let bob_daemon = LocalDaemon::start(Arc::clone(&bob_node), None, LocalDaemonConfig::default())
        .await
        .unwrap();

    let alice_sock = alice_daemon.socket_path().to_path_buf();
    let bob_sock = bob_daemon.socket_path().to_path_buf();

    let mut alice_mcp = TestMcpClient::spawn(McpOptions::new(alice_sock.clone()));
    let mut bob_mcp = TestMcpClient::spawn(McpOptions::new(bob_sock.clone()));
    alice_mcp.initialize().await;
    bob_mcp.initialize().await;

    let (_, a_err) = alice_mcp
        .call_verified_claude(
            &alice_sock,
            "alice-f",
            "hyp_mesh",
            json!({ "action": "join", "handle": "sender" }),
        )
        .await;
    assert!(!a_err);
    let (_, b_err) = bob_mcp
        .call_verified_claude(
            &bob_sock,
            "bob-f",
            "hyp_mesh",
            json!({ "action": "join", "handle": "recv" }),
        )
        .await;
    assert!(!b_err);

    // Create a local file and send it via E2EE `hyp_send({ to, files })`!
    let expected_contents = "Hyphae v2 E2EE MCP file drop test payload 98765\n";
    let src_file = payload_dir.path().join("report.txt");
    std::fs::write(&src_file, expected_contents).unwrap();

    let (send_txt, send_err) = alice_mcp
        .call_verified_claude(
            &alice_sock,
            "alice-f",
            "hyp_send",
            json!({
                "to": "bob@filebox/recv",
                "files": [src_file.to_str().unwrap()],
                "text": "Attached E2EE report"
            }),
        )
        .await;
    assert!(!send_err, "file drop hyp_send failed: {send_txt}");
    let send_val: Value = serde_json::from_str(&send_txt).unwrap();
    assert_eq!(send_val["encrypted"], true);
    let transfer_id = send_val["transferId"]
        .as_str()
        .expect("transferId must be returned");
    assert!(!transfer_id.is_empty());
    assert!(send_val["ciphertextBytes"].as_u64().unwrap_or(0) > 0);

    // Wait for Bob to automatically download, decrypt, verify & enqueue the Transfer notification!
    wait_for_pending_count(&bob_sock, "claude:bob-f", 1).await;

    let (inbox_txt, inbox_err) = bob_mcp
        .call_verified_claude(
            &bob_sock,
            "bob-f",
            "hyp_inbox",
            json!({ "state": "unread", "filter": { "kind": "transfer" }, "ack": true }),
        )
        .await;
    assert!(!inbox_err, "bob transfer inbox failed: {inbox_txt}");
    let inbox_val: Value = serde_json::from_str(&inbox_txt).unwrap();
    let items = inbox_val["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    let notice: Value = serde_json::from_str(items[0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(notice["transferId"], transfer_id);
    let dest_path = notice["files"][0]["diskPath"]
        .as_str()
        .expect("extracted transfer file diskPath");
    let extracted = std::fs::read_to_string(dest_path).expect("extracted file must exist");
    assert_eq!(extracted, expected_contents);

    alice_mcp.close().await;
    bob_mcp.close().await;
    alice_daemon.stop().await;
    bob_daemon.stop().await;
    hub.shutdown();
}

// ============================================================================
// Suite 4: `--claude-channel` Failure, Nack & Timeout Fallback Matrix
// ============================================================================

#[tokio::test]
async fn suite_4_claude_channel_failure_nack_disconnect_and_timeout_fallback_matrix() {
    let dir = TempDir::new().unwrap();
    let node = open_local_node("chan@box", dir.path());
    let cfg = LocalDaemonConfig {
        channel_deliver_timeout: Duration::from_millis(150),
        ..Default::default()
    };
    let daemon = LocalDaemon::start(Arc::clone(&node), None, cfg)
        .await
        .unwrap();
    let sock = daemon.socket_path().to_path_buf();

    // ---- Case 4.1: Explicit `channel.ack(submitted: false)` preserves message for PostToolUse ----
    {
        let (r, mut w) = connect_daemon_async(&sock).await.unwrap();
        let mut reader = BufReader::new(r);
        write_ndjson_line_async(
            &mut w,
            &json!({
                "type": "mcp.hello",
                "backend": "claude",
                "channel": true,
                "clientId": "nack-sess"
            }),
        )
        .await
        .unwrap();
        write_ndjson_line_async(&mut w, &json!({ "type": "channel.ready" }))
            .await
            .unwrap();
        wait_for_live_transport(&sock, "claude:nack-sess").await;

        let push_task = tokio::spawn(async move {
            let line = read_bounded_line_async(&mut reader, MAX_SOCKET_LINE_BYTES)
                .await
                .unwrap()
                .unwrap();
            let pkt: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(pkt["type"], "channel.deliver");
            let delivery_id = pkt["delivery"].as_u64().unwrap();
            write_ndjson_line_async(
                &mut w,
                &json!({ "type": "channel.ack", "delivery": delivery_id, "submitted": false }),
            )
            .await
            .unwrap();
            (reader, w)
        });

        daemon
            .ingest_inbound(InboundItem {
                session_id: "claude:nack-sess".into(),
                origin_node: "peer@net".into(),
                item_id: "nack-item-1".into(),
                source: "peer@net/bot".into(),
                text: "NACK_PRESERVED_PAYLOAD".into(),
                kind: MailboxKind::Message,
                trust_tier: GateTrustTier::Peer,
            })
            .await
            .unwrap();

        let (_r_keep, _w_keep) = tokio::time::timeout(Duration::from_secs(3), push_task)
            .await
            .unwrap()
            .unwrap();

        // Message MUST NOT be lost/acked; TurnStart (`UserPromptSubmit`) hook drains it intact!
        let drain = run_hook(
            &sock,
            HarnessKind::Claude,
            HookEvent::PreInvocation,
            json!({ "session_id": "nack-sess" }),
        )
        .await;
        let ctx = drain["hookSpecificOutput"]["additionalContext"]
            .as_str()
            .expect("nacked channel message must drain via TurnStart hook");
        assert!(ctx.contains("NACK_PRESERVED_PAYLOAD"));
    }

    // ---- Case 4.2: Channel disconnects mid-delivery -> preserved & delivered via `hyp wait` ----
    {
        let (r, mut w) = connect_daemon_async(&sock).await.unwrap();
        let mut reader = BufReader::new(r);
        write_ndjson_line_async(
            &mut w,
            &json!({
                "type": "mcp.hello",
                "backend": "claude",
                "channel": true,
                "clientId": "drop-sess"
            }),
        )
        .await
        .unwrap();
        write_ndjson_line_async(&mut w, &json!({ "type": "channel.ready" }))
            .await
            .unwrap();
        wait_for_live_transport(&sock, "claude:drop-sess").await;

        let drop_task = tokio::spawn(async move {
            let line = read_bounded_line_async(&mut reader, MAX_SOCKET_LINE_BYTES)
                .await
                .unwrap()
                .unwrap();
            let pkt: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(pkt["type"], "channel.deliver");
            // Drop socket abruptly mid-delivery without sending `channel.ack`!
            drop(reader);
            drop(w);
        });

        daemon
            .ingest_inbound(InboundItem {
                session_id: "claude:drop-sess".into(),
                origin_node: "peer@net".into(),
                item_id: "drop-item-1".into(),
                source: "peer@net/bot".into(),
                text: "DISCONNECT_FALLBACK_WAIT_PAYLOAD".into(),
                kind: MailboxKind::Message,
                trust_tier: GateTrustTier::Peer,
            })
            .await
            .unwrap();

        tokio::time::timeout(Duration::from_secs(3), drop_task)
            .await
            .unwrap()
            .unwrap();
        wait_for_no_live_transport(&sock, "claude:drop-sess").await;

        // `hyp wait` immediately receives the preserved message!
        let mut buf = Vec::new();
        let code = tokio::time::timeout(
            Duration::from_secs(3),
            run_wait_to_writer(
                WaitOptions {
                    socket_path: sock.clone(),
                    mode: WaitMode::Once,
                    session_id: Some("claude:drop-sess".into()),
                    handle: None,
                    timeout_seconds: Some(2.0),
                    json: false,
                },
                &mut buf,
            ),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(code, 0);
        let wait_text = String::from_utf8(buf).unwrap();
        assert!(
            wait_text.contains("DISCONNECT_FALLBACK_WAIT_PAYLOAD"),
            "expected preserved message via hyp wait, got: {wait_text:?}"
        );
    }

    // ---- Case 4.3: Channel never acks (150ms timeout fires) -> preserved & drained via `hyp_inbox` ----
    {
        let (r, mut w) = connect_daemon_async(&sock).await.unwrap();
        let mut reader = BufReader::new(r);
        write_ndjson_line_async(
            &mut w,
            &json!({
                "type": "mcp.hello",
                "backend": "claude",
                "channel": true,
                "clientId": "timeout-sess"
            }),
        )
        .await
        .unwrap();
        write_ndjson_line_async(&mut w, &json!({ "type": "channel.ready" }))
            .await
            .unwrap();
        wait_for_live_transport(&sock, "claude:timeout-sess").await;

        let silent_task = tokio::spawn(async move {
            let line = read_bounded_line_async(&mut reader, MAX_SOCKET_LINE_BYTES)
                .await
                .unwrap()
                .unwrap();
            let pkt: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(pkt["type"], "channel.deliver");
            // Intentionally stay connected and NEVER send `channel.ack`!
            (reader, w)
        });

        let start = tokio::time::Instant::now();
        daemon
            .ingest_inbound(InboundItem {
                session_id: "claude:timeout-sess".into(),
                origin_node: "peer@net".into(),
                item_id: "timeout-item-1".into(),
                source: "peer@net/bot".into(),
                text: "TIMEOUT_PRESERVED_INBOX_PAYLOAD".into(),
                kind: MailboxKind::Message,
                trust_tier: GateTrustTier::Peer,
            })
            .await
            .unwrap();
        // `ingest_inbound` awaited `flush_session`, which waited the 150ms `channel_deliver_timeout`!
        assert!(
            start.elapsed() >= Duration::from_millis(120),
            "expected channel_deliver_timeout (~150ms) to elapse, got {:?}",
            start.elapsed()
        );

        let (_r_keep, _w_keep) = tokio::time::timeout(Duration::from_secs(2), silent_task)
            .await
            .unwrap()
            .unwrap();

        // Drain via verified MCP `hyp_inbox`!
        let mut mcp = TestMcpClient::spawn(McpOptions::new(sock.clone()));
        mcp.initialize().await;
        let (inbox_txt, inbox_err) = mcp
            .call_verified_claude(
                &sock,
                "timeout-sess",
                "hyp_inbox",
                json!({ "state": "unread", "ack": true }),
            )
            .await;
        assert!(
            !inbox_err,
            "hyp_inbox after channel timeout failed: {inbox_txt}"
        );
        let inbox_val: Value = serde_json::from_str(&inbox_txt).unwrap();
        let items = inbox_val["items"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert!(
            items[0]["text"]
                .as_str()
                .unwrap()
                .contains("TIMEOUT_PRESERVED_INBOX_PAYLOAD")
        );
        mcp.close().await;
    }

    daemon.stop().await;
    node.shutdown();
}

// ============================================================================
// Suite 5: Bridge Identity Ownership (`primary`, `reader`, `intruder`) + Outbound DLP
// ============================================================================

#[derive(Debug, Clone)]
struct RecordedBridgePost {
    plugin: String,
    target: String,
    text: String,
    meta: Map<String, Value>,
}

struct RecordingBridgePoster {
    posts: Arc<Mutex<Vec<RecordedBridgePost>>>,
}

impl BridgePoster for RecordingBridgePoster {
    fn post<'a>(
        &'a self,
        plugin: &'a str,
        target: &'a str,
        text: &'a str,
        meta: &'a Map<String, Value>,
    ) -> BoxFuture<'a, Result<Value, (String, String)>> {
        let posts = Arc::clone(&self.posts);
        let plugin = plugin.to_string();
        let target = target.to_string();
        let text = text.to_string();
        let meta = meta.clone();
        Box::pin(async move {
            let mut guard = posts.lock().expect("posts lock poisoned");
            let seq = guard.len() + 1;
            guard.push(RecordedBridgePost {
                plugin,
                target,
                text,
                meta,
            });
            Ok(json!({ "messageSeq": seq }))
        })
    }
}

#[tokio::test]
async fn suite_5_bridge_identity_ownership_handoff_and_outbound_dlp_e2e() {
    let dir = TempDir::new().unwrap();
    let node = open_local_node("bridge@box", dir.path());

    // Attach default SecurityGatePipeline (Stage 1 Outbound DLP enabled!).
    let gate_db = Arc::new(Mutex::new(
        NodeDb::open(dir.path().join("node.sqlite")).unwrap(),
    ));
    let pipeline =
        Arc::new(SecurityGatePipeline::new(SecurityGateConfig::default(), gate_db, None).unwrap());

    let daemon = LocalDaemon::start(
        Arc::clone(&node),
        Some(Arc::clone(&pipeline)),
        LocalDaemonConfig::default(),
    )
    .await
    .unwrap();

    // Register mock `telegram` BridgePoster -> automatically enables `hyp_bridge` in `tools/list`!
    let recorded_posts = Arc::new(Mutex::new(Vec::<RecordedBridgePost>::new()));
    daemon.register_bridge_poster(
        "telegram",
        Arc::new(RecordingBridgePoster {
            posts: Arc::clone(&recorded_posts),
        }),
    );

    let sock = daemon.socket_path().to_path_buf();
    let mut mcp = TestMcpClient::spawn(McpOptions::new(sock.clone()));
    mcp.initialize().await;

    // Confirm `tools/list` advertises `hyp_bridge` because a bridge poster is registered!
    let tools = mcp.list_tools().await;
    assert!(
        tools.contains(&"hyp_bridge".to_string()),
        "tools/list must include hyp_bridge when BridgePoster is registered: {tools:?}"
    );

    // Join 3 sessions: `primary`, `reader`, `intruder`.
    for (sess, handle) in [
        ("br-primary", "primary"),
        ("br-reader", "reader"),
        ("br-intruder", "intruder"),
    ] {
        let (txt, err) = mcp
            .call_verified_claude(
                &sock,
                sess,
                "hyp_mesh",
                json!({ "action": "join", "handle": handle }),
            )
            .await;
        assert!(!err, "join {handle} failed: {txt}");
    }

    // Unregistered bridge plugin fails closed with `no_plugins`; unclaimed target fails closed with `not_target_holder`.
    let (no_plug_txt, no_plug_err) = mcp
        .call_verified_claude(
            &sock,
            "br-primary",
            "hyp_send",
            json!({ "to": "slack:ops", "text": "hello" }),
        )
        .await;
    assert!(
        no_plug_err && no_plug_txt.contains("no_plugins"),
        "expected no_plugins: {no_plug_txt}"
    );

    let (unclaimed_txt, unclaimed_err) = mcp
        .call_verified_claude(
            &sock,
            "br-primary",
            "hyp_send",
            json!({ "to": "telegram:dm-alex", "text": "before claim" }),
        )
        .await;
    assert!(
        unclaimed_err && unclaimed_txt.contains("not_target_holder"),
        "expected not_target_holder before claim: {unclaimed_txt}"
    );

    // 1. `primary` claims `telegram:dm-alex` via `handoff`; `reader` subscribes via `link`!
    let (claim_txt, claim_err) = mcp
        .call_verified_claude(
            &sock,
            "br-primary",
            "hyp_bridge",
            json!({ "action": "handoff", "plugin": "telegram", "target": "dm-alex" }),
        )
        .await;
    assert!(!claim_err, "primary claim failed: {claim_txt}");
    assert_eq!(
        serde_json::from_str::<Value>(&claim_txt).unwrap()["sessionId"],
        "claude:br-primary"
    );

    let (link_txt, link_err) = mcp
        .call_verified_claude(
            &sock,
            "br-reader",
            "hyp_bridge",
            json!({ "action": "link", "plugin": "telegram", "target": "dm-alex" }),
        )
        .await;
    assert!(!link_err, "reader link failed: {link_txt}");
    let link_val: Value = serde_json::from_str(&link_txt).unwrap();
    assert_eq!(link_val["role"], "reader");
    assert_eq!(link_val["primarySessionId"], "claude:br-primary");

    // Inspect `targets` view!
    let (targets_txt, targets_err) = mcp
        .call_verified_claude(
            &sock,
            "br-primary",
            "hyp_bridge",
            json!({ "action": "targets" }),
        )
        .await;
    assert!(!targets_err, "targets failed: {targets_txt}");
    let targets_val: Value = serde_json::from_str(&targets_txt).unwrap();
    assert_eq!(targets_val["plugins"], json!(["telegram"]));
    assert_eq!(
        targets_val["targets"][0]["primarySessionId"],
        "claude:br-primary"
    );
    assert_eq!(targets_val["targets"][0]["isPrimary"], true);
    assert_eq!(
        targets_val["targets"][0]["readers"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    // 2. Fail-closed matrix: `intruder` AND `reader` attempting send, handoff, or unlink(all:true)
    //    MUST ALL fail closed with `not_target_holder`!
    for unauthorized_sess in ["br-intruder", "br-reader"] {
        let (s_txt, s_err) = mcp
            .call_verified_claude(
                &sock,
                unauthorized_sess,
                "hyp_send",
                json!({ "to": "telegram:dm-alex", "text": "unauthorized spoof" }),
            )
            .await;
        assert!(
            s_err && s_txt.contains("not_target_holder"),
            "{unauthorized_sess} send must fail closed not_target_holder, got: {s_txt}"
        );

        let (h_txt, h_err) = mcp
            .call_verified_claude(
                &sock,
                unauthorized_sess,
                "hyp_bridge",
                json!({ "action": "handoff", "plugin": "telegram", "target": "dm-alex" }),
            )
            .await;
        assert!(
            h_err && h_txt.contains("not_target_holder"),
            "{unauthorized_sess} handoff hijack must fail closed not_target_holder, got: {h_txt}"
        );

        let (u_txt, u_err) = mcp
            .call_verified_claude(
                &sock,
                unauthorized_sess,
                "hyp_bridge",
                json!({
                    "action": "unlink",
                    "plugin": "telegram",
                    "target": "dm-alex",
                    "all": true
                }),
            )
            .await;
        assert!(
            u_err && u_txt.contains("not_target_holder"),
            "{unauthorized_sess} unlink(all:true) must fail closed not_target_holder, got: {u_txt}"
        );
    }
    assert_eq!(recorded_posts.lock().unwrap().len(), 0);

    // 3. `primary` posts clean text -> succeeds & reaches BridgePoster!
    let (ok_post_txt, ok_post_err) = mcp
        .call_verified_claude(
            &sock,
            "br-primary",
            "hyp_send",
            json!({ "to": "telegram:dm-alex", "text": "Deploy green on prod!" }),
        )
        .await;
    assert!(!ok_post_err, "primary clean post failed: {ok_post_txt}");
    let ok_post_val: Value = serde_json::from_str(&ok_post_txt).unwrap();
    assert_eq!(ok_post_val["delivered"], true);
    assert_eq!(ok_post_val["plugin"], "telegram");
    assert_eq!(ok_post_val["target"], "dm-alex");
    assert_eq!(recorded_posts.lock().unwrap().len(), 1);
    {
        let posts = recorded_posts.lock().unwrap();
        assert_eq!(posts[0].plugin, "telegram");
        assert_eq!(posts[0].target, "dm-alex");
        assert_eq!(posts[0].text, "Deploy green on prod!");
    }

    // 4. `primary` attempting to post synthetic AWS secret -> blocked by Stage 1 Outbound DLP (`0` leaked)!
    let (dlp_txt, dlp_err) = mcp
        .call_verified_claude(
            &sock,
            "br-primary",
            "hyp_send",
            json!({
                "to": "telegram:dm-alex",
                "text": "oops secret key AKIAIOSFODNN7EXAMPLE"
            }),
        )
        .await;
    assert!(
        dlp_err && dlp_txt.contains("outbound_dlp_blocked"),
        "Stage 1 Outbound DLP must block leaked secret to bridge: {dlp_txt}"
    );
    assert_eq!(
        recorded_posts.lock().unwrap().len(),
        1,
        "secret MUST NOT reach BridgePoster"
    );

    // 5. `primary` executes live `handoff` to `reader` -> `reader` becomes primary, old `primary` loses write!
    let (ho_txt, ho_err) = mcp
        .call_verified_claude(
            &sock,
            "br-primary",
            "hyp_bridge",
            json!({
                "action": "handoff",
                "plugin": "telegram",
                "target": "dm-alex",
                "handle": "reader"
            }),
        )
        .await;
    assert!(!ho_err, "live handoff to reader failed: {ho_txt}");
    assert_eq!(
        serde_json::from_str::<Value>(&ho_txt).unwrap()["sessionId"],
        "claude:br-reader"
    );

    // `reader` now posts cleanly!
    let (r_post_txt, r_post_err) = mcp
        .call_verified_claude(
            &sock,
            "br-reader",
            "hyp_send",
            json!({ "to": "telegram:dm-alex", "text": "Taking over as primary writer" }),
        )
        .await;
    assert!(
        !r_post_err,
        "new primary (reader) post failed: {r_post_txt}"
    );
    assert_eq!(recorded_posts.lock().unwrap().len(), 2);
    assert_eq!(
        recorded_posts.lock().unwrap()[1].text,
        "Taking over as primary writer"
    );

    // Old `primary` NOW fails closed with `not_target_holder`!
    let (old_post_txt, old_post_err) = mcp
        .call_verified_claude(
            &sock,
            "br-primary",
            "hyp_send",
            json!({ "to": "telegram:dm-alex", "text": "stale primary write" }),
        )
        .await;
    assert!(
        old_post_err && old_post_txt.contains("not_target_holder"),
        "old primary must fail closed after handoff: {old_post_txt}"
    );
    assert_eq!(recorded_posts.lock().unwrap().len(), 2);

    // New primary (`reader`) can cleanly `unlink(all: true)`!
    let (unlink_all_txt, unlink_all_err) = mcp
        .call_verified_claude(
            &sock,
            "br-reader",
            "hyp_bridge",
            json!({
                "action": "unlink",
                "plugin": "telegram",
                "target": "dm-alex",
                "all": true
            }),
        )
        .await;
    assert!(
        !unlink_all_err,
        "primary unlink(all:true) failed: {unlink_all_txt}"
    );
    assert_eq!(
        serde_json::from_str::<Value>(&unlink_all_txt).unwrap()["removed"],
        true
    );

    // 6. Auto-primary claim on `link` for an unowned target (+ `readOnly: true` opt-out + anti-hijack):
    // 6a. `readOnly: true` on unowned target links as reader without claiming primary.
    let (ro_txt, ro_err) = mcp
        .call_verified_claude(
            &sock,
            "br-intruder",
            "hyp_bridge",
            json!({
                "action": "link",
                "plugin": "telegram",
                "target": "dm-alex",
                "readOnly": true
            }),
        )
        .await;
    assert!(!ro_err, "readOnly link failed: {ro_txt}");
    let ro_val: Value = serde_json::from_str(&ro_txt).unwrap();
    assert_eq!(ro_val["role"], "reader");
    assert_eq!(ro_val["claimedPrimary"], false);
    assert!(ro_val["primarySessionId"].is_null());

    // 6b. First normal `link` on unowned target automatically claims primary ownership and can send immediately!
    let (auto_txt, auto_err) = mcp
        .call_verified_claude(
            &sock,
            "br-primary",
            "hyp_bridge",
            json!({ "action": "link", "plugin": "telegram", "target": "dm-alex" }),
        )
        .await;
    assert!(!auto_err, "auto-primary link failed: {auto_txt}");
    let auto_val: Value = serde_json::from_str(&auto_txt).unwrap();
    assert_eq!(auto_val["role"], "primary");
    assert_eq!(auto_val["claimedPrimary"], true);
    assert_eq!(auto_val["primarySessionId"], "claude:br-primary");

    let (auto_send_txt, auto_send_err) = mcp
        .call_verified_claude(
            &sock,
            "br-primary",
            "hyp_send",
            json!({ "to": "telegram:dm-alex", "text": "immediate reply after link" }),
        )
        .await;
    assert!(
        !auto_send_err,
        "auto-claimed primary must be able to send immediately: {auto_send_txt}"
    );
    assert_eq!(recorded_posts.lock().unwrap().len(), 3);

    // 6c. A subsequent `link` by another session MUST stay strictly `reader` (never hijacks primary!).
    let (second_txt, second_err) = mcp
        .call_verified_claude(
            &sock,
            "br-reader",
            "hyp_bridge",
            json!({ "action": "link", "plugin": "telegram", "target": "dm-alex" }),
        )
        .await;
    assert!(!second_err, "second link failed: {second_txt}");
    let second_val: Value = serde_json::from_str(&second_txt).unwrap();
    assert_eq!(second_val["role"], "reader");
    assert_eq!(second_val["claimedPrimary"], false);
    assert_eq!(second_val["primarySessionId"], "claude:br-primary");

    // 7. First-class bridge reactions: reaction-only, empty removal, combo text+reaction,
    //    fail-closed ownership (`not_target_holder`), Outbound DLP, and input validation!
    assert!(
        recorded_posts.lock().unwrap()[0]
            .meta
            .get("reaction")
            .is_none(),
        "plain text bridge posts must not populate meta.reaction"
    );

    // 7a. Primary holder sends reaction-only (no `text`!) with `replyTo` + `chatId`.
    let (rxn_txt, rxn_err) = mcp
        .call_verified_claude(
            &sock,
            "br-primary",
            "hyp_send",
            json!({
                "to": "telegram:dm-alex",
                "reaction": "👍",
                "replyTo": "77",
                "chatId": "12345"
            }),
        )
        .await;
    assert!(!rxn_err, "primary reaction-only hyp_send failed: {rxn_txt}");
    let rxn_val: Value = serde_json::from_str(&rxn_txt).unwrap();
    assert_eq!(rxn_val["delivered"], true);
    {
        let posts = recorded_posts.lock().unwrap();
        assert_eq!(posts.len(), 4);
        assert_eq!(posts[3].plugin, "telegram");
        assert_eq!(posts[3].target, "dm-alex");
        assert_eq!(posts[3].text, "");
        assert_eq!(posts[3].meta.get("reaction"), Some(&json!("👍")));
        assert_eq!(posts[3].meta.get("replyTo"), Some(&json!("77")));
        assert_eq!(posts[3].meta.get("chatId"), Some(&json!("12345")));
    }

    // 7b. Primary holder removes reaction via empty string `""` (no `text`!).
    let (clear_txt, clear_err) = mcp
        .call_verified_claude(
            &sock,
            "br-primary",
            "hyp_send",
            json!({
                "to": "telegram:dm-alex",
                "reaction": "",
                "replyTo": "77"
            }),
        )
        .await;
    assert!(!clear_err, "primary reaction clear failed: {clear_txt}");
    {
        let posts = recorded_posts.lock().unwrap();
        assert_eq!(posts.len(), 5);
        assert_eq!(posts[4].text, "");
        assert_eq!(posts[4].meta.get("reaction"), Some(&json!("")));
        assert_eq!(posts[4].meta.get("replyTo"), Some(&json!("77")));
    }

    // 7c. Primary holder sends combo reaction + text reply together.
    let (combo_txt, combo_err) = mcp
        .call_verified_claude(
            &sock,
            "br-primary",
            "hyp_send",
            json!({
                "to": "telegram:dm-alex",
                "reaction": "🚀",
                "replyTo": "78",
                "text": "On it!"
            }),
        )
        .await;
    assert!(
        !combo_err,
        "primary reaction+text combo failed: {combo_txt}"
    );
    {
        let posts = recorded_posts.lock().unwrap();
        assert_eq!(posts.len(), 6);
        assert_eq!(posts[5].text, "On it!");
        assert_eq!(posts[5].meta.get("reaction"), Some(&json!("🚀")));
        assert_eq!(posts[5].meta.get("replyTo"), Some(&json!("78")));
    }

    // 7d. Unauthorized `reader` and `intruder` attempting reaction MUST fail closed `not_target_holder`!
    for unauthorized_sess in ["br-reader", "br-intruder"] {
        let (unauth_txt, unauth_err) = mcp
            .call_verified_claude(
                &sock,
                unauthorized_sess,
                "hyp_send",
                json!({
                    "to": "telegram:dm-alex",
                    "reaction": "👍",
                    "replyTo": "77"
                }),
            )
            .await;
        assert!(
            unauth_err && unauth_txt.contains("not_target_holder"),
            "{unauthorized_sess} reaction must fail closed not_target_holder, got: {unauth_txt}"
        );
    }

    // 7e. Outbound DLP gate screens non-empty `reaction` as well as `text`!
    let (rxn_dlp_txt, rxn_dlp_err) = mcp
        .call_verified_claude(
            &sock,
            "br-primary",
            "hyp_send",
            json!({
                "to": "telegram:dm-alex",
                "reaction": "AKIAIOSFODNN7EXAMPLE"
            }),
        )
        .await;
    assert!(
        rxn_dlp_err && rxn_dlp_txt.contains("outbound_dlp_blocked"),
        "Outbound DLP must block secrets smuggled in reaction: {rxn_dlp_txt}"
    );

    // 7f. Invalid reactions (control chars, >32 chars, missing both text & reaction, non-bridge DM / #channel)
    //     MUST all fail closed `invalid_request`!
    let overlong_reaction = "👍".repeat(33);
    for (label, payload) in [
        (
            "newline control char",
            json!({ "to": "telegram:dm-alex", "reaction": "👍\n" }),
        ),
        (
            "carriage return control char",
            json!({ "to": "telegram:dm-alex", "reaction": "👍\r" }),
        ),
        (
            "NUL control char",
            json!({ "to": "telegram:dm-alex", "reaction": "👍\0" }),
        ),
        (
            "ANSI escape control char",
            json!({ "to": "telegram:dm-alex", "reaction": "\u{001b}[31m" }),
        ),
        (
            ">32 chars reaction",
            json!({ "to": "telegram:dm-alex", "reaction": overlong_reaction }),
        ),
        (
            "neither text nor reaction",
            json!({ "to": "telegram:dm-alex" }),
        ),
        (
            "whitespace-only text without reaction",
            json!({ "to": "telegram:dm-alex", "text": "   " }),
        ),
        (
            "reaction on non-bridge DM",
            json!({ "to": "bridge@box/reader", "reaction": "👍" }),
        ),
        (
            "reaction on #channel",
            json!({ "to": "#general", "reaction": "👍", "text": "hi" }),
        ),
    ] {
        let (inv_txt, inv_err) = mcp
            .call_verified_claude(&sock, "br-primary", "hyp_send", payload)
            .await;
        assert!(
            inv_err && inv_txt.contains("invalid_request"),
            "{label} must fail closed invalid_request, got: {inv_txt}"
        );
    }
    assert_eq!(
        recorded_posts.lock().unwrap().len(),
        6,
        "rejected reactions must never reach BridgePoster"
    );

    mcp.close().await;
    daemon.stop().await;
    node.shutdown();
}

// ============================================================================
// Suite 6: Cross-OS `LocalDaemon::start_tcp` (`connector.addr`) Differential Parity
// ============================================================================

#[derive(Debug, PartialEq, Eq)]
struct TransportParitySnapshot {
    tools: Vec<String>,
    joined_address: String,
    wait_contains_msg1: bool,
    post_hook_contains_msg2: bool,
    delivered_count: usize,
    daemon_node_id: String,
    daemon_profile: String,
}

async fn run_transport_parity_scenario(sock: &Path) -> TransportParitySnapshot {
    let mut mcp = TestMcpClient::spawn(McpOptions::new(sock.to_path_buf()));
    mcp.initialize().await;
    let tools = mcp.list_tools().await;

    let (j1_txt, j1_err) = mcp
        .call_verified_claude(
            sock,
            "xport-a",
            "hyp_mesh",
            json!({ "action": "join", "handle": "alpha" }),
        )
        .await;
    assert!(!j1_err, "join alpha failed on {}: {j1_txt}", sock.display());
    let joined_address = serde_json::from_str::<Value>(&j1_txt).unwrap()["address"]
        .as_str()
        .unwrap()
        .to_string();

    let (_, j2_err) = mcp
        .call_verified_claude(
            sock,
            "xport-b",
            "hyp_mesh",
            json!({ "action": "join", "handle": "beta" }),
        )
        .await;
    assert!(!j2_err);

    // 1. Arm `run_wait_to_writer` over `sock` (`connector.addr` or `connector.sock`)
    let wait_sock = sock.to_path_buf();
    let wait_handle = tokio::spawn(async move {
        let mut buf = Vec::new();
        let code = run_wait_to_writer(
            WaitOptions {
                socket_path: wait_sock,
                mode: WaitMode::Once,
                session_id: Some("claude:xport-b".into()),
                handle: None,
                timeout_seconds: Some(3.0),
                json: false,
            },
            &mut buf,
        )
        .await
        .unwrap();
        assert_eq!(code, 0);
        String::from_utf8(buf).unwrap()
    });
    wait_for_live_transport(sock, "claude:xport-b").await;

    let (_, s1_err) = mcp
        .call_verified_claude(
            sock,
            "xport-a",
            "hyp_send",
            json!({ "to": "xport@box/beta", "text": "CROSS_OS_WAIT_MSG_1" }),
        )
        .await;
    assert!(!s1_err);

    let wait_out = tokio::time::timeout(Duration::from_secs(4), wait_handle)
        .await
        .unwrap()
        .unwrap();

    // 2. Send msg2 and drain via synchronous `handle_hook_payload` (`PreInvocation` TurnStart) over `sock`!
    let (_, s2_err) = mcp
        .call_verified_claude(
            sock,
            "xport-a",
            "hyp_send",
            json!({ "to": "xport@box/beta", "text": "CROSS_OS_HOOK_MSG_2" }),
        )
        .await;
    assert!(!s2_err);
    wait_for_pending_count(sock, "claude:xport-b", 1).await;

    let post_out = run_hook(
        sock,
        HarnessKind::Claude,
        HookEvent::PreInvocation,
        json!({ "session_id": "xport-b" }),
    )
    .await;
    let post_ctx = post_out["hookSpecificOutput"]["additionalContext"]
        .as_str()
        .unwrap_or_default()
        .to_string();

    // 3. Query `hyp_inbox(state:"delivered")` and `daemon.status`!
    let (del_txt, del_err) = mcp
        .call_verified_claude(
            sock,
            "xport-b",
            "hyp_inbox",
            json!({ "state": "delivered", "limit": 10 }),
        )
        .await;
    assert!(!del_err);
    let delivered_count = serde_json::from_str::<Value>(&del_txt).unwrap()["items"]
        .as_array()
        .unwrap()
        .len();

    let status = daemon_rpc_async(
        sock,
        &json!({ "type": "daemon.status" }),
        Duration::from_secs(2),
    )
    .await;
    assert!(status.ok);
    let st_res = status.result.unwrap();

    mcp.close().await;

    TransportParitySnapshot {
        tools,
        joined_address,
        wait_contains_msg1: wait_out.contains("CROSS_OS_WAIT_MSG_1"),
        post_hook_contains_msg2: post_ctx.contains("CROSS_OS_HOOK_MSG_2"),
        delivered_count,
        daemon_node_id: st_res["nodeId"].as_str().unwrap().to_string(),
        daemon_profile: st_res["profile"].as_str().unwrap().to_string(),
    }
}

#[tokio::test]
async fn suite_6_cross_os_start_tcp_connector_addr_differential_parity() {
    // 1. Run full scenario over loopback TCP (`LocalDaemon::start_tcp` -> `connector.addr`).
    let tcp_dir = TempDir::new().unwrap();
    let tcp_node = open_local_node("xport@box", tcp_dir.path());
    let addr_file = tcp_dir.path().join("connector.addr");
    let tcp_daemon = LocalDaemon::start_tcp(
        Arc::clone(&tcp_node),
        None,
        LocalDaemonConfig::default(),
        addr_file.clone(),
    )
    .await
    .unwrap();
    let tcp_addr = tcp_daemon
        .tcp_addr()
        .expect("start_tcp must expose tcp_addr");
    let tcp_snapshot = run_transport_parity_scenario(&addr_file).await;

    // Also verify `tcp://127.0.0.1:<port>` works identically for synchronous hooks & async RPC!
    let tcp_url_path = PathBuf::from(format!("tcp://{tcp_addr}"));
    let url_status = daemon_rpc_async(
        &tcp_url_path,
        &json!({ "type": "daemon.status" }),
        Duration::from_secs(2),
    )
    .await;
    assert!(url_status.ok);
    assert_eq!(url_status.result.unwrap()["nodeId"], "xport@box");

    tcp_daemon.stop().await;
    tcp_node.shutdown();

    // 2. Run identical scenario over platform-native transport (`connector.sock` Unix socket on
    //    macOS/Linux; direct `127.0.0.1:<port>` loopback TCP on Windows) and assert 100% parity!
    let native_dir = TempDir::new().unwrap();
    let native_node = open_local_node("xport@box", native_dir.path());
    let native_daemon =
        LocalDaemon::start(Arc::clone(&native_node), None, LocalDaemonConfig::default())
            .await
            .unwrap();
    let native_target = if cfg!(unix) {
        native_daemon.socket_path().to_path_buf()
    } else {
        PathBuf::from(native_daemon.tcp_addr().unwrap().to_string())
    };
    let native_snapshot = run_transport_parity_scenario(&native_target).await;

    native_daemon.stop().await;
    native_node.shutdown();

    assert_eq!(
        tcp_snapshot, native_snapshot,
        "connector.addr loopback TCP and native transport MUST have 100% identical observable results"
    );
    assert!(tcp_snapshot.wait_contains_msg1);
    assert!(tcp_snapshot.post_hook_contains_msg2);
    assert_eq!(tcp_snapshot.delivered_count, 2);
}

// ============================================================================
// Suite 7: Direct P2P Security Gate Lockdown + Human Approval Without Re-Quarantine
// ============================================================================

#[tokio::test]
async fn suite_7_direct_p2p_security_gate_lockdown_and_human_approve_without_requarantine() {
    let dir_alice = TempDir::new().unwrap();
    let dir_bob = TempDir::new().unwrap();

    // 1. Bob runs an HTTP P2P node; Alice pairs directly with Bob via real `hp2p1_` (zero hub).
    let alice = open_local_node("alice@macbook", dir_alice.path());
    let mut bob_cfg = NodeConfig::local(NodeId::new("bob@laptop").unwrap(), dir_bob.path());
    bob_cfg.secret_backend = Some(SecretBackend::File);
    let bob = UnifiedNode::open(bob_cfg).unwrap();
    let (_bob_addr, _bob_srv) = Arc::clone(&bob).serve(loopback_zero()).await.unwrap();

    let peer_scopes = ScopePreset::Member.expand();
    let (hp2p1, _) = bob
        .create_p2p_invite(peer_scopes.clone(), peer_scopes.clone(), 300_000)
        .expect("bob creates hp2p1 invite");
    alice
        .accept_p2p_invite(&hp2p1, peer_scopes)
        .await
        .expect("alice accepts hp2p1 invite over real HTTP P2P");

    // 2. Start Bob's LocalDaemon with a TAMPERED SecurityGatePipeline (`is_policy_tampered == true`).
    let gate_cfg = SecurityGateConfig {
        require_signed_policy: true,
        policy_signature: Some("hmac-sha256:deadbeef00000000".to_string()),
        ..Default::default()
    };
    let gate_db = Arc::new(Mutex::new(
        NodeDb::open(dir_bob.path().join("node.sqlite")).unwrap(),
    ));
    let gate_pipeline = Arc::new(SecurityGatePipeline::new(gate_cfg, gate_db, None).unwrap());
    assert!(
        gate_pipeline.is_policy_tampered(),
        "test setup must run with tampered gate policy"
    );

    let bob_daemon = LocalDaemon::start(
        Arc::clone(&bob),
        Some(Arc::clone(&gate_pipeline)),
        LocalDaemonConfig::default(),
    )
    .await
    .unwrap();
    let bob_sock = bob_daemon.socket_path().to_path_buf();

    // Enroll Bob's Claude session (`bob@laptop:bob`).
    let _ = run_hook(
        &bob_sock,
        HarnessKind::Claude,
        HookEvent::SessionStart,
        json!({ "session_id": "bob-p2p-gate" }),
    )
    .await;
    let mut bob_mcp = TestMcpClient::spawn(McpOptions::new(bob_sock.clone()));
    bob_mcp.initialize().await;
    let (_join_res, join_err) = bob_mcp
        .call_verified_claude(
            &bob_sock,
            "bob-p2p-gate",
            "hyp_mesh",
            json!({ "action": "join", "handle": "bob" }),
        )
        .await;
    assert!(!join_err);

    // 3. Alice sends a real Direct P2P E2EE DM to Bob.
    let sent = alice
        .send_dm("alice", "bob@laptop/bob", "P2P_SECRET_PAYLOAD_42")
        .await
        .expect("direct P2P E2EE DM succeeds at transport layer");
    assert!(sent.encrypted, "Direct P2P DM must be E2EE");

    // Verify `node.rs` attributed `origin_node` to `alice@macbook` (NOT `bob@laptop`),
    // AND Bob's tampered SecurityGatePipeline quarantined it fail-closed!
    let post_locked = run_hook(
        &bob_sock,
        HarnessKind::Claude,
        HookEvent::PostToolUse,
        json!({ "session_id": "bob-p2p-gate", "tool_name": "Bash", "tool_use_id": "tu-p2p-1" }),
    )
    .await;
    assert!(
        !post_locked.to_string().contains("P2P_SECRET_PAYLOAD_42"),
        "tampered gate MUST NOT deliver Direct P2P DM to agent hook: {post_locked}"
    );
    let (inbox_locked, _) = bob_mcp
        .call_verified_claude(&bob_sock, "bob-p2p-gate", "hyp_inbox", json!({}))
        .await;
    assert!(
        !inbox_locked.to_string().contains("P2P_SECRET_PAYLOAD_42"),
        "tampered gate MUST NOT expose quarantined Direct P2P DM via hyp_inbox: {inbox_locked}"
    );

    let quarantined = bob
        .db()
        .local()
        .list_quarantined(None, 50)
        .expect("list_quarantined");
    let p2p_q = quarantined
        .iter()
        .find(|e| e.text.contains("P2P_SECRET_PAYLOAD_42"))
        .expect("Direct P2P DM MUST be quarantined fail-closed under gate_policy_tampered");
    assert_eq!(
        p2p_q.origin_node, "alice@macbook",
        "Direct P2P inbound DM must attribute origin_node to sender_node, never self.node_id"
    );
    assert_eq!(p2p_q.gate_reason.as_deref(), Some("gate_policy_tampered"));
    let p2p_receipt = p2p_q.receipt.clone();

    // 4. Defense-in-depth check: even a synthetic legacy mailbox row with `origin_node == "bob@laptop"`
    //    and remote `source == "alice@macbook/alice"` MUST be quarantined by `reconcile_session_inbox`
    //    (never misclassified as `SelfHost`).
    {
        let db = bob.db();
        db.local()
            .put_in_mailbox(
                &MailboxInsert {
                    session_id: "claude:bob-p2p-gate".to_string(),
                    origin_node: "bob@laptop".to_string(),
                    item_id: "legacy-p2p-row-1".to_string(),
                    source: "alice@macbook/alice".to_string(),
                    text: "LEGACY_SPOOFED_SELFHOST_PAYLOAD".to_string(),
                    kind: MailboxKind::Message,
                    gate_state: GateState::Pending,
                    gate_reason: None,
                    traceparent: None,
                },
                now_ms(),
            )
            .expect("insert legacy row");
    }
    let post_legacy = run_hook(
        &bob_sock,
        HarnessKind::Claude,
        HookEvent::PostToolUse,
        json!({ "session_id": "bob-p2p-gate", "tool_name": "Bash", "tool_use_id": "tu-p2p-2" }),
    )
    .await;
    assert!(
        !post_legacy
            .to_string()
            .contains("LEGACY_SPOOFED_SELFHOST_PAYLOAD"),
        "defense-in-depth MUST quarantine legacy self-origin remote-source row: {post_legacy}"
    );
    let q_after_legacy = bob.db().local().list_quarantined(None, 50).unwrap();
    assert!(
        q_after_legacy
            .iter()
            .any(|e| e.text.contains("LEGACY_SPOOFED_SELFHOST_PAYLOAD")),
        "legacy row must appear in quarantine"
    );

    // 5. Human operator approves `p2p_receipt` (`reviewed_at = Some(...)`) while the live daemon
    //    STILL holds the tampered SecurityGatePipeline in memory. It MUST deliver cleanly and
    //    NEVER be re-quarantined by `reconcile_session_inbox`!
    let approved = bob
        .db()
        .local()
        .approve_quarantined(&p2p_receipt, "human verified", now_ms())
        .expect("approve_quarantined succeeds");
    assert!(approved.reviewed_at.is_some());

    let post_approved = run_hook(
        &bob_sock,
        HarnessKind::Claude,
        HookEvent::PreInvocation,
        json!({ "session_id": "bob-p2p-gate" }),
    )
    .await;
    assert!(
        post_approved.to_string().contains("P2P_SECRET_PAYLOAD_42"),
        "human-approved receipt MUST deliver immediately without being re-quarantined: {post_approved}"
    );

    bob_mcp.close().await;
    bob_daemon.stop().await;
    alice.shutdown();
    bob.shutdown();
}

// ============================================================================
// Suite 8: Handle Descriptions, Multi-Hub Peer Details & Configured Bridge Targets
// ============================================================================

#[tokio::test]
async fn suite_8_handle_descriptions_multihub_peers_and_configured_bridge_targets() {
    let dir_hub_a = TempDir::new().unwrap();
    let dir_hub_b = TempDir::new().unwrap();
    let dir_alice = TempDir::new().unwrap();
    let dir_bob = TempDir::new().unwrap();

    // 1. Start two Router hubs (`hub-alpha`, `hub-beta`) with Admin-CA keys.
    let spawn_hub = |node_id: &str, dir: &Path| {
        let admin_ca = Ed25519KeyPair::generate().unwrap();
        let admin_jwk = OkpJwk::new(OkpCurve::Ed25519, &admin_ca.public_key_bytes());
        let mut cfg = NodeConfig::router(NodeId::new(node_id).unwrap(), dir);
        cfg.secret_backend = Some(SecretBackend::File);
        cfg.admin_jwk = Some(admin_jwk);
        let hub = UnifiedNode::open(cfg).unwrap();
        (hub, admin_ca)
    };
    let (hub_a, ca_a) = spawn_hub("hub-alpha", dir_hub_a.path());
    let (hub_b, ca_b) = spawn_hub("hub-beta", dir_hub_b.path());
    let (_addr_a, _srv_a) = Arc::clone(&hub_a).serve(loopback_zero()).await.unwrap();
    let (_addr_b, _srv_b) = Arc::clone(&hub_b).serve(loopback_zero()).await.unwrap();

    let alice = open_local_node("alice@macbook", dir_alice.path());
    let bob = open_local_node("bob@laptop", dir_bob.path());

    // Pair Alice to BOTH hubs (`hub-alpha` + `hub-beta`), Bob ONLY to `hub-beta`.
    let scopes = ScopePreset::Member.expand();
    let scope_refs: Vec<&str> = scopes.iter().map(String::as_str).collect();
    for (hub, ca, client) in [
        (&hub_a, &ca_a, &alice),
        (&hub_b, &ca_b, &alice),
        (&hub_b, &ca_b, &bob),
    ] {
        let (am2, _) = hub
            .create_admin_invite(
                ca,
                client.node_id().as_str(),
                &scope_refs,
                TrustTier::Org,
                300_000,
            )
            .unwrap();
        client.accept_am2_invite(&am2).await.unwrap();
    }

    // Start Alice's LocalDaemon with SecurityGatePipeline + configured bridge targets!
    let gate_db = Arc::new(Mutex::new(
        NodeDb::open(dir_alice.path().join("node.sqlite")).unwrap(),
    ));
    let gate_pipeline =
        Arc::new(SecurityGatePipeline::new(SecurityGateConfig::default(), gate_db, None).unwrap());
    let alice_daemon = LocalDaemon::start(
        Arc::clone(&alice),
        Some(Arc::clone(&gate_pipeline)),
        LocalDaemonConfig::default(),
    )
    .await
    .unwrap();
    let bob_daemon = LocalDaemon::start(Arc::clone(&bob), None, LocalDaemonConfig::default())
        .await
        .unwrap();

    // Register a configured bridge poster with pre-configured unlinked targets!
    struct NoopBridgePoster;
    impl BridgePoster for NoopBridgePoster {
        fn post<'a>(
            &'a self,
            plugin: &'a str,
            target: &'a str,
            text: &'a str,
            _meta: &'a Map<String, Value>,
        ) -> BoxFuture<'a, Result<Value, (String, String)>> {
            let p = plugin.to_string();
            let t = target.to_string();
            let len = text.len();
            Box::pin(async move { Ok(json!({ "ok": true, "plugin": p, "target": t, "len": len })) })
        }
    }
    alice_daemon.register_bridge_poster_with_targets(
        "telegram",
        vec!["123456789".to_string(), "ops-alerts".to_string()],
        Arc::new(NoopBridgePoster),
    );

    let alice_sock = alice_daemon.socket_path().to_path_buf();
    let bob_sock = bob_daemon.socket_path().to_path_buf();

    let mut alice_mcp = TestMcpClient::spawn(McpOptions::new(alice_sock.clone()));
    let mut bob_mcp = TestMcpClient::spawn(McpOptions::new(bob_sock.clone()));
    alice_mcp.initialize().await;
    bob_mcp.initialize().await;

    // 2. Bob joins with a multiline/control-char description -> sanitized & synced to `hub-beta`!
    let (bob_join_txt, bob_join_err) = bob_mcp
        .call_verified_claude(
            &bob_sock,
            "bob-s8",
            "hyp_mesh",
            json!({
                "action": "join",
                "handle": "bob",
                "description": "Rust\nrelease\tengineer\x07  specializing in E2EE"
            }),
        )
        .await;
    assert!(!bob_join_err, "bob join failed: {bob_join_txt}");
    let bob_join_val: Value = serde_json::from_str(&bob_join_txt).unwrap();
    assert_eq!(bob_join_val["address"], "bob@laptop/bob");
    assert_eq!(
        bob_join_val["description"],
        "Rust release engineer specializing in E2EE"
    );

    // Alice joins with description + `include: ["peers"]` -> discovers Bob's sanitized description & `via: "hub-beta"`!
    let (alice_join_txt, alice_join_err) = alice_mcp
        .call_verified_claude(
            &alice_sock,
            "alice-s8",
            "hyp_mesh",
            json!({
                "action": "join",
                "handle": "alice",
                "description": "Coordinator agent",
                "include": ["peers"]
            }),
        )
        .await;
    assert!(!alice_join_err, "alice join failed: {alice_join_txt}");
    let alice_join_val: Value = serde_json::from_str(&alice_join_txt).unwrap();
    assert_eq!(alice_join_val["description"], "Coordinator agent");
    assert_eq!(alice_join_val["untrustedMetadata"], true);
    assert!(alice_join_val["peerDetails"].is_array());

    // Explicit `hyp_mesh({ action: "peers" })` check
    let (peers_txt, peers_err) = alice_mcp
        .call_verified_claude(
            &alice_sock,
            "alice-s8",
            "hyp_mesh",
            json!({ "action": "peers" }),
        )
        .await;
    assert!(!peers_err, "peers failed: {peers_txt}");
    let peers_val: Value = serde_json::from_str(&peers_txt).unwrap();
    assert_eq!(peers_val["untrustedMetadata"], true);
    assert_eq!(
        peers_val["peers"],
        json!(["alice@macbook/alice", "bob@laptop/bob"])
    );
    let details = peers_val["peerDetails"].as_array().unwrap();
    let alice_det = details
        .iter()
        .find(|d| d["address"] == "alice@macbook/alice")
        .expect("alice peerDetails entry");
    assert_eq!(alice_det["nodeId"], "alice@macbook");
    assert_eq!(alice_det["handle"], "alice");
    assert_eq!(alice_det["description"], "Coordinator agent");
    assert!(
        alice_det.get("via").is_none(),
        "local handle must omit null via field: {alice_det}"
    );
    let bob_det = details
        .iter()
        .find(|d| d["address"] == "bob@laptop/bob")
        .expect("bob peerDetails entry");
    assert_eq!(bob_det["nodeId"], "bob@laptop");
    assert_eq!(bob_det["handle"], "bob");
    assert_eq!(
        bob_det["description"],
        "Rust release engineer specializing in E2EE"
    );
    assert_eq!(bob_det["via"], "hub-beta");

    // 3. Configured (unlinked) bridge targets MUST appear immediately in `hyp_bridge({ action: "targets" })`!
    let (t_before_txt, t_before_err) = alice_mcp
        .call_verified_claude(
            &alice_sock,
            "alice-s8",
            "hyp_bridge",
            json!({ "action": "targets" }),
        )
        .await;
    assert!(!t_before_err, "targets failed: {t_before_txt}");
    let t_before: Value = serde_json::from_str(&t_before_txt).unwrap();
    assert_eq!(t_before["plugins"], json!(["telegram"]));
    let target_list = t_before["targets"].as_array().unwrap();
    assert_eq!(
        target_list.len(),
        2,
        "expected 2 configured targets: {t_before}"
    );
    let tg_chat = target_list
        .iter()
        .find(|t| t["plugin"] == "telegram" && t["target"] == "123456789")
        .expect("telegram:123456789 must be advertised before linking");
    assert_eq!(tg_chat["configured"], true);
    assert_eq!(tg_chat["readers"], json!([]));
    assert!(tg_chat["primarySession"].is_null());
    assert_eq!(tg_chat["callerIsPrimary"], false);
    assert_eq!(tg_chat["callerIsLinked"], false);

    // 4. Link Alice to `telegram:123456789` and verify `deliver_bridge_inbound` wakes Alice's
    //    live `hyp wait` through Security Gates & §2.5 Delivery Policy!
    let (link_txt, link_err) = alice_mcp
        .call_verified_claude(
            &alice_sock,
            "alice-s8",
            "hyp_bridge",
            json!({ "action": "link", "plugin": "telegram", "target": "123456789" }),
        )
        .await;
    assert!(!link_err, "alice link failed: {link_txt}");

    let (t_after_txt, t_after_err) = alice_mcp
        .call_verified_claude(
            &alice_sock,
            "alice-s8",
            "hyp_bridge",
            json!({ "action": "targets" }),
        )
        .await;
    assert!(!t_after_err);
    let t_after: Value = serde_json::from_str(&t_after_txt).unwrap();
    let tg_linked = t_after["targets"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["plugin"] == "telegram" && t["target"] == "123456789")
        .unwrap();
    assert_eq!(tg_linked["configured"], true);
    assert_eq!(tg_linked["callerIsLinked"], true);
    assert_eq!(tg_linked["callerIsPrimary"], true);
    assert_eq!(tg_linked["readers"], json!(["claude:alice-s8"]));

    // Arm live `run_wait_to_writer` on Alice and deliver inbound bridge message!
    let wait_sock = alice_sock.clone();
    let wait_handle = tokio::spawn(async move {
        let mut buf = Vec::new();
        let code = run_wait_to_writer(
            WaitOptions {
                socket_path: wait_sock,
                mode: WaitMode::Once,
                session_id: Some("claude:alice-s8".into()),
                handle: None,
                timeout_seconds: Some(3.0),
                json: false,
            },
            &mut buf,
        )
        .await
        .unwrap();
        assert_eq!(code, 0);
        String::from_utf8(buf).unwrap()
    });
    wait_for_live_transport(&alice_sock, "claude:alice-s8").await;

    let delivered = alice_daemon
        .deliver_bridge_inbound(
            "telegram",
            "123456789",
            "tg-msg-101",
            "[telegram:123456789] alex: Please deploy v0.3.0",
        )
        .await
        .expect("deliver_bridge_inbound succeeds");
    assert_eq!(delivered, 1);

    let wait_out = tokio::time::timeout(Duration::from_secs(4), wait_handle)
        .await
        .unwrap()
        .unwrap();
    assert!(
        wait_out.contains("Please deploy v0.3.0"),
        "live wait must wake with inbound bridge text: {wait_out}"
    );

    // Also verify Security Gate rejects oversized (>16 KiB) Bridge inbound payload fail-closed!
    let giant = "X".repeat(20 * 1024);
    let giant_delivered = alice_daemon
        .deliver_bridge_inbound("telegram", "123456789", "tg-msg-giant", &giant)
        .await
        .expect("deliver_bridge_inbound handles gate decision cleanly");
    assert_eq!(
        giant_delivered, 0,
        "oversized >16 KiB bridge payload must be blocked/quarantined by Security Gate"
    );

    alice_mcp.close().await;
    bob_mcp.close().await;
    alice_daemon.stop().await;
    bob_daemon.stop().await;
    alice.shutdown();
    bob.shutdown();
    hub_a.shutdown();
    hub_b.shutdown();
}

// ============================================================================
// Suite 9: Native PushTransport Routing, Auto-Detection & Safe Hook Fallback
// ============================================================================

struct RecordingPushTransport {
    kind_name: &'static str,
    interruptible: bool,
    next_outcome: Mutex<PushOutcome>,
    delivered: Mutex<Vec<(PushMode, String)>>,
}

impl RecordingPushTransport {
    fn new(kind_name: &'static str, interruptible: bool) -> Self {
        Self {
            kind_name,
            interruptible,
            next_outcome: Mutex::new(PushOutcome::delivered()),
            delivered: Mutex::new(Vec::new()),
        }
    }

    fn set_outcome(&self, outcome: PushOutcome) {
        *self.next_outcome.lock().unwrap() = outcome;
    }

    fn take_delivered(&self) -> Vec<(PushMode, String)> {
        std::mem::take(&mut *self.delivered.lock().unwrap())
    }
}

impl PushTransport for RecordingPushTransport {
    fn kind(&self) -> &'static str {
        self.kind_name
    }

    fn supports_interrupt(&self) -> bool {
        self.interruptible
    }

    fn deliver<'a>(&'a self, text: &'a str, mode: PushMode) -> TransportFuture<'a, PushOutcome> {
        let outcome = self.next_outcome.lock().unwrap().clone();
        self.delivered
            .lock()
            .unwrap()
            .push((mode, text.to_string()));
        Box::pin(async move { outcome })
    }
}

#[tokio::test]
async fn suite_9_push_transport_queue_interrupt_stop_silencing_and_hold_fallback() {
    let dir = TempDir::new().unwrap();
    let node = open_local_node("push@box", dir.path());
    let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .unwrap();
    let sock = daemon.socket_path().to_path_buf();

    let mut sender_mcp = TestMcpClient::spawn(McpOptions::new(sock.clone()));
    sender_mcp.initialize().await;
    let (_, s_err) = sender_mcp
        .call_verified_claude(
            &sock,
            "sender-p9",
            "hyp_mesh",
            json!({ "action": "join", "handle": "sender" }),
        )
        .await;
    assert!(!s_err);

    let mut codex_mcp = TestMcpClient::spawn(McpOptions::new(sock.clone()));
    codex_mcp.initialize().await;
    let (join_txt, join_err) = codex_mcp
        .call_verified_for_harness(
            &sock,
            HarnessKind::Codex,
            "thr-p9",
            "hyp_mesh",
            json!({ "action": "join", "handle": "codex" }),
        )
        .await;
    assert!(!join_err, "codex join failed: {join_txt}");
    let join_val: Value = serde_json::from_str(&join_txt).unwrap();
    assert_eq!(join_val["hasLiveTransport"], false);
    assert_eq!(join_val["transport"]["kind"], "none");

    // Without a push transport, Codex Stop hook prompts to arm `hyp wait`.
    let codex_payload = json!({ "thread_id": "thr-p9" });
    let stop_before = run_hook(
        &sock,
        HarnessKind::Codex,
        HookEvent::Stop,
        codex_payload.clone(),
    )
    .await;
    assert_eq!(stop_before["decision"], "block");
    assert!(
        stop_before["reason"]
            .as_str()
            .unwrap()
            .contains("hyp wait --session codex:thr-p9")
    );

    // Attach a live interrupt-capable PushTransport -> Stop hook becomes silent!
    let mock_transport = Arc::new(RecordingPushTransport::new("mock_push", true));
    daemon.register_session_transport(
        "codex:thr-p9",
        Arc::clone(&mock_transport) as Arc<dyn PushTransport>,
    );
    assert_eq!(
        daemon.session_transport_kind("codex:thr-p9"),
        Some("mock_push")
    );

    let st_live = session_status(&sock, "codex:thr-p9").await;
    assert_eq!(st_live["hasLiveTransport"], true);
    assert_eq!(st_live["transportKind"], "mock_push");

    let stop_with_push = run_hook(
        &sock,
        HarnessKind::Codex,
        HookEvent::Stop,
        codex_payload.clone(),
    )
    .await;
    assert_eq!(
        stop_with_push,
        json!({}),
        "Stop hook must stay silent when live PushTransport is attached"
    );

    // 1. Standard DM -> pushed in Queue mode and marked delivered (pending == 0).
    let (_, dm1_err) = sender_mcp
        .call_verified_claude(
            &sock,
            "sender-p9",
            "hyp_send",
            json!({ "to": "push@box/codex", "text": "hello-via-queue-push" }),
        )
        .await;
    assert!(!dm1_err);

    for _ in 0..100 {
        if !mock_transport.delivered.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    let batch1 = mock_transport.take_delivered();
    assert_eq!(batch1.len(), 1);
    assert_eq!(batch1[0].0, PushMode::Queue);
    assert!(batch1[0].1.contains("hello-via-queue-push"));
    assert_eq!(session_status(&sock, "codex:thr-p9").await["pending"], 0);

    // 2. VIP interrupt rule -> pushed in Interrupt mode!
    let (_, rule_err) = codex_mcp
        .call_verified_for_harness(
            &sock,
            HarnessKind::Codex,
            "thr-p9",
            "hyp_inbox",
            json!({ "rules": [{ "target": "push@box/sender", "delivery": "interrupt" }] }),
        )
        .await;
    assert!(!rule_err);
    // End Codex's setup turn so it is Idle and immediately receives the Interrupt push.
    let _ = run_hook(
        &sock,
        HarnessKind::Codex,
        HookEvent::Stop,
        json!({ "thread_id": "thr-p9" }),
    )
    .await;

    let (_, dm2_err) = sender_mcp
        .call_verified_claude(
            &sock,
            "sender-p9",
            "hyp_send",
            json!({ "to": "push@box/codex", "text": "urgent-interrupt-msg" }),
        )
        .await;
    assert!(!dm2_err);

    for _ in 0..100 {
        if !mock_transport.delivered.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    let batch2 = mock_transport.take_delivered();
    assert_eq!(batch2.len(), 1);
    assert_eq!(batch2[0].0, PushMode::Interrupt);
    assert!(batch2[0].1.contains("urgent-interrupt-msg"));

    // 3. Transport returns Hold("herdr_working") -> message preserved unread in durable SQLite
    //    and drained cleanly via PostToolUse hook!
    mock_transport.set_outcome(PushOutcome::hold("herdr_working"));
    let (_, dm3_err) = sender_mcp
        .call_verified_claude(
            &sock,
            "sender-p9",
            "hyp_send",
            json!({ "to": "push@box/codex", "text": "preserve-on-hold-fallback" }),
        )
        .await;
    assert!(!dm3_err);

    for _ in 0..100 {
        if !mock_transport.delivered.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
    let _ = mock_transport.take_delivered();
    assert_eq!(
        session_status(&sock, "codex:thr-p9").await["pending"],
        1,
        "Hold outcome must preserve message unread in durable SQLite"
    );

    let post_drain = run_hook(
        &sock,
        HarnessKind::Codex,
        HookEvent::PostToolUse,
        codex_payload,
    )
    .await;
    let drained_txt = extract_drain_text(HarnessKind::Codex, &post_drain);
    assert!(
        drained_txt.contains("preserve-on-hold-fallback"),
        "PostToolUse fallback must deliver held message: {drained_txt}"
    );
    assert_eq!(session_status(&sock, "codex:thr-p9").await["pending"], 0);

    codex_mcp.close().await;
    sender_mcp.close().await;
    daemon.stop().await;
    node.shutdown();
}

#[cfg(unix)]
#[tokio::test]
async fn suite_9b_auto_detect_herdr_transport_from_pre_tool_use_hook_and_push_live() {
    use common::run_hook_with_hints;
    use hyp_harness::hooks::HookTransportHints;
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new().unwrap();
    let log_path = dir.path().join("hc-invocations.log");
    let fake_hc = dir.path().join("fake-hc");

    let script = format!(
        r#"#!/bin/sh
printf '%s\n' "$*" >> "{log}"
case "$1" in
  get)
    printf '%s\n' '{{"address":"t9h","state":"live","created_ms":1700000000,"pid":4242,"status":{{"app":"codex","state":"idle"}}}}'
    exit 0
    ;;
  send)
    printf '%s\n' '{{"ok":true}}'
    exit 0
    ;;
  *)
    exit 1
    ;;
esac
"#,
        log = log_path.display()
    );
    std::fs::write(&fake_hc, script).unwrap();
    std::fs::set_permissions(&fake_hc, std::fs::Permissions::from_mode(0o755)).unwrap();

    let node = open_local_node("herdr-auto@box", dir.path());
    let daemon_cfg = LocalDaemonConfig {
        auto_detect_transports: true,
        herdr_bin: Some(fake_hc.display().to_string()),
        t3_default_base_dir: Some(dir.path().join("no-t3")),
        ..Default::default()
    };
    let daemon = LocalDaemon::start(Arc::clone(&node), None, daemon_cfg)
        .await
        .unwrap();
    let sock = daemon.socket_path().to_path_buf();

    let mut sender_mcp = TestMcpClient::spawn(McpOptions::new(sock.clone()));
    sender_mcp.initialize().await;
    let (_, s_err) = sender_mcp
        .call_verified_claude(
            &sock,
            "sender-h9",
            "hyp_mesh",
            json!({ "action": "join", "handle": "sender" }),
        )
        .await;
    assert!(!s_err);

    // Codex PreToolUse carries `HC_TERMINAL_ID = t9h` -> daemon probes fake-hc and auto-attaches HerdrTransport!
    let mut codex_mcp = TestMcpClient::spawn(McpOptions::new(sock.clone()));
    codex_mcp.initialize().await;
    let call_id = "call-codex-herdr-1";
    let pre = run_hook_with_hints(
        &sock,
        HarnessKind::Codex,
        HookEvent::PreToolUse,
        json!({
            "thread_id": "thr-herdr-1",
            "tool_name": "mcp__hyphae__hyp_mesh",
            "tool_use_id": call_id,
            "tool_input": { "action": "join", "handle": "codex-in-herdr" }
        }),
        HookTransportHints {
            herdr_terminal_id: Some("t9h".into()),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(pre, json!({}));

    let (join_txt, join_err) = codex_mcp
        .call_tool(
            "hyp_mesh",
            json!({ "action": "join", "handle": "codex-in-herdr" }),
            Some(json!({ "callId": call_id })),
        )
        .await;
    assert!(!join_err, "codex-in-herdr join failed: {join_txt}");
    let join_val: Value = serde_json::from_str(&join_txt).unwrap();
    assert_eq!(join_val["hasLiveTransport"], true);
    assert_eq!(join_val["transport"]["kind"], "herdr");

    // Codex Stop hook stays completely silent because Herdr transport is live!
    let stop_out = run_hook(
        &sock,
        HarnessKind::Codex,
        HookEvent::Stop,
        json!({ "thread_id": "thr-herdr-1" }),
    )
    .await;
    assert_eq!(stop_out, json!({}));

    // Send a DM from sender -> Herdr auto-pushes a strictly metadata-only wake nudge via
    // `fake-hc send --json --if idle t9h <nudge>` (NEVER leaking untrusted body into terminal prompt!).
    let (_, dm_err) = sender_mcp
        .call_verified_claude(
            &sock,
            "sender-h9",
            "hyp_send",
            json!({ "to": "herdr-auto@box/codex-in-herdr", "text": "wake-up-codex-via-herdr" }),
        )
        .await;
    assert!(!dm_err);

    let mut log_contents = String::new();
    for _ in 0..100 {
        log_contents = std::fs::read_to_string(&log_path).unwrap_or_default();
        if log_contents.contains("send --json --if idle t9h") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(
        log_contents.contains("send --json --if idle t9h")
            && log_contents.contains("<hyphae-wake count=\"1\" handle=\"codex-in-herdr\" urgency=\"queue\">1 Hyphae message(s) queued for @codex-in-herdr. Review any injected Hyphae context or call hyp_inbox({ ack: true }) to read them.</hyphae-wake>"),
        "expected fake-hc to receive guarded metadata-only wake nudge, got:\n{log_contents}"
    );
    assert!(
        !log_contents.contains("wake-up-codex-via-herdr"),
        "Herdr terminal push MUST NOT leak untrusted DM body into user prompt:\n{log_contents}"
    );
    // Unread message MUST stay preserved in SQLite until the woken agent reads it via hyp_inbox!
    assert_eq!(
        session_status(&sock, "codex:thr-herdr-1").await["pending"],
        1
    );

    let inbox_call_id = "call-codex-herdr-inbox-1";
    let pre_inbox = run_hook_with_hints(
        &sock,
        HarnessKind::Codex,
        HookEvent::PreToolUse,
        json!({
            "thread_id": "thr-herdr-1",
            "tool_name": "mcp__hyphae__hyp_inbox",
            "tool_use_id": inbox_call_id,
            "tool_input": { "ack": true }
        }),
        HookTransportHints {
            herdr_terminal_id: Some("t9h".into()),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(pre_inbox, json!({}));
    let (inbox_txt, inbox_err) = codex_mcp
        .call_tool(
            "hyp_inbox",
            json!({ "ack": true }),
            Some(json!({ "callId": inbox_call_id })),
        )
        .await;
    assert!(!inbox_err, "codex-in-herdr hyp_inbox failed: {inbox_txt}");
    assert!(
        inbox_txt.contains("wake-up-codex-via-herdr"),
        "hyp_inbox must deliver the unread DM body with structured provenance: {inbox_txt}"
    );
    assert_eq!(
        session_status(&sock, "codex:thr-herdr-1").await["pending"],
        0
    );

    codex_mcp.close().await;
    sender_mcp.close().await;
    daemon.stop().await;
    node.shutdown();
}
