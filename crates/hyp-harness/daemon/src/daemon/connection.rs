//! Per-connection IPC dispatch, caller attribution and streaming response channels.

use super::{
    ChannelDeliverCommand, DaemonStateLock, LiveChannel, LiveOpenClawService, LiveWaiter,
    LocalDaemonInner, OpenClawWakeAck, OpenClawWakeCommand, TransportHints, WaiterKind,
    handle_call_start, handle_daemon_status, handle_gate_reload_rpc, handle_inbox_wake_rpc,
    handle_mailbox_drain, handle_peers_reload, handle_session_focus, handle_session_hint,
    handle_session_idle, handle_session_leave_channel, handle_session_mute, handle_session_rule,
    handle_session_start, handle_session_status, handle_session_summary, handle_session_unmute,
    handle_session_unsubscribe, handle_sessions_summary, handle_system_wake_rpc,
    harness_natively_uses_hooks, maybe_spawn_transport_probe, run_inspect_watch,
};
use crate::call_registry::{
    CallerErrorCode, CallerResolution, DEFAULT_RESOLVE_WAIT, is_valid_session_id,
};
use hyp_harness_ipc::caller::is_valid_session_token;
use hyp_harness_ipc::hints::is_valid_terminal_id;
use hyp_harness_ipc::protocol::HarnessKind;
use hyp_harness_ipc::sock::{
    MAX_SOCKET_LINE_BYTES, read_bounded_line_async, write_ndjson_line_async,
};
use hyp_harness_transport::transport::openclaw::REASON_OPENCLAW_GATEWAY_UNAVAILABLE;
use hyp_store::uuid_v4;
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot, watch};

#[derive(Debug, Default)]
struct McpSocketContext {
    backend: Option<HarnessKind>,
    channel: bool,
    channel_ready: bool,
    channel_session_id: Option<String>,
    ephemeral_client_id: Option<String>,
    #[allow(dead_code)]
    session_token: Option<String>,
    hints: TransportHints,
}

pub(super) async fn handle_connection<R, W>(
    daemon: Arc<LocalDaemonInner>,
    read_half: R,
    mut write_half: W,
    mut shutdown_rx: watch::Receiver<bool>,
    tcp_endpoint: Option<SocketAddr>,
) where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let conn_id = daemon.next_seq();
    let mut reader = BufReader::new(read_half);
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Value>();
    let (chan_tx, mut chan_rx) = mpsc::unbounded_channel::<ChannelDeliverCommand>();
    let (oc_wake_tx, mut oc_wake_rx) = mpsc::unbounded_channel::<OpenClawWakeCommand>();

    let mut mcp_ctx: Option<McpSocketContext> = None;
    let mut attached_waiter: Option<(String, u64)> = None;
    let mut is_openclaw_service = false;
    let mut pending_channel_acks: HashMap<u64, oneshot::Sender<bool>> = HashMap::new();
    let mut pending_oc_wake_acks: HashMap<u64, oneshot::Sender<OpenClawWakeAck>> = HashMap::new();

    // Writer loop merged into select! so both request replies and async pushes serialize cleanly.
    loop {
        enum Ev {
            Line(Result<Option<String>, hyp_harness_ipc::sock::SockError>),
            Push(Option<Value>),
            ChannelCmd(Option<ChannelDeliverCommand>),
            OpenClawWakeCmd(Option<OpenClawWakeCommand>),
            Shutdown,
        }

        let ev = tokio::select! {
            res = read_bounded_line_async(&mut reader, MAX_SOCKET_LINE_BYTES) => Ev::Line(res),
            msg = out_rx.recv() => Ev::Push(msg),
            cmd = chan_rx.recv() => Ev::ChannelCmd(cmd),
            oc_cmd = oc_wake_rx.recv() => Ev::OpenClawWakeCmd(oc_cmd),
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    Ev::Shutdown
                } else {
                    continue;
                }
            }
        };

        match ev {
            Ev::Shutdown => break,
            Ev::Push(Some(pkt)) => {
                let is_once_done = attached_waiter.as_ref().is_some_and(|(sid, wid)| {
                    !daemon.session_runtime().get(sid).is_some_and(|runtime| {
                        runtime.waiters.iter().any(|waiter| waiter.id == *wid)
                    })
                }) && pkt.get("type").and_then(Value::as_str)
                    == Some("wait.items");

                if write_ndjson_line_async(&mut write_half, &pkt)
                    .await
                    .is_err()
                {
                    break;
                }
                if is_once_done {
                    let _ = write_half.shutdown().await;
                    break;
                }
            }
            Ev::Push(None) => break,
            Ev::ChannelCmd(Some(cmd)) => {
                let pkt = json!({
                    "type": "channel.deliver",
                    "delivery": cmd.delivery_id,
                    "text": cmd.text,
                });
                if write_ndjson_line_async(&mut write_half, &pkt).await.is_ok() {
                    pending_channel_acks.insert(cmd.delivery_id, cmd.ack_tx);
                } else {
                    let _ = cmd.ack_tx.send(false);
                    break;
                }
            }
            Ev::ChannelCmd(None) => break,
            Ev::OpenClawWakeCmd(Some(cmd)) => {
                let pkt = json!({
                    "type": "openclaw.wake",
                    "delivery": cmd.delivery_id,
                    "sessionId": cmd.session_id,
                    "sessionKey": cmd.session_key,
                    "agentId": cmd.agent_id,
                    "batchId": cmd.batch_id,
                    "text": cmd.text,
                });
                if write_ndjson_line_async(&mut write_half, &pkt).await.is_ok() {
                    pending_oc_wake_acks.insert(cmd.delivery_id, cmd.ack_tx);
                } else {
                    let _ = cmd.ack_tx.send(OpenClawWakeAck {
                        ok: false,
                        reason: Some(REASON_OPENCLAW_GATEWAY_UNAVAILABLE.to_string()),
                    });
                    break;
                }
            }
            Ev::OpenClawWakeCmd(None) => break,
            Ev::Line(Ok(None)) | Ev::Line(Err(_)) => break,
            Ev::Line(Ok(Some(line))) => {
                if line.trim().is_empty() {
                    continue;
                }
                let Ok(Value::Object(packet)) = serde_json::from_str::<Value>(&line) else {
                    let _ = write_ndjson_line_async(
                        &mut write_half,
                        &json!({ "ok": false, "error": "invalid_json" }),
                    )
                    .await;
                    break;
                };

                let pkt_type = packet
                    .get("type")
                    .and_then(Value::as_str)
                    .unwrap_or_default();

                let response = match pkt_type {
                    "call.start" => {
                        let resp = handle_call_start(&daemon, &packet);
                        if resp.get("ok").and_then(Value::as_bool) == Some(true) {
                            if let Some(sid) = resp
                                .get("result")
                                .and_then(|r| r.get("sessionId"))
                                .and_then(Value::as_str)
                            {
                                let hints = TransportHints::from_packet(&packet, None);
                                maybe_spawn_transport_probe(&daemon, sid, hints);
                            }
                        }
                        Some(resp)
                    }
                    "session.start" => Some(handle_session_start(&daemon, &packet).await),
                    "session.hint" => Some(handle_session_hint(&daemon, &packet)),
                    "call.end" => {
                        let cid = packet.get("callId").and_then(Value::as_str);
                        let tok = packet.get("callToken").and_then(Value::as_str);
                        daemon.calls.finish_call(cid, tok);
                        Some(json!({ "ok": true, "result": {} }))
                    }
                    "mailbox.drain" => Some(handle_mailbox_drain(&daemon, &packet).await),
                    "session.status" => Some(handle_session_status(&daemon, &packet).await),
                    "session.idle" => Some(handle_session_idle(&daemon, &packet).await),
                    "session.summary" => Some(handle_session_summary(&daemon, &packet)),
                    "sessions.summary" => Some(handle_sessions_summary(
                        &daemon,
                        &packet,
                        tcp_endpoint.is_none(),
                    )),
                    "session.focus" => Some(handle_session_focus(&daemon, &packet).await),
                    "session.mute" => Some(handle_session_mute(&daemon, &packet)),
                    "session.unmute" => Some(handle_session_unmute(&daemon, &packet)),
                    "session.rule" => Some(handle_session_rule(&daemon, &packet)),
                    "session.unsubscribe" => Some(handle_session_unsubscribe(&daemon, &packet)),
                    "session.leave_channel" => {
                        Some(handle_session_leave_channel(&daemon, &packet).await)
                    }
                    "kv.local.challenge" => Some(match tcp_endpoint {
                        Some(endpoint) => {
                            authenticate_tcp_kv(
                                &daemon,
                                &packet,
                                endpoint,
                                &mut reader,
                                &mut write_half,
                            )
                            .await
                        }
                        None => kv_auth_required(),
                    }),
                    "kv.local" => Some(if tcp_endpoint.is_none() {
                        handle_local_kv(&daemon, packet.get("request")).await
                    } else {
                        kv_auth_required()
                    }),
                    "daemon.status" => Some(handle_daemon_status(&daemon).await),
                    "peers.reload" => Some(handle_peers_reload(&daemon).await),
                    "drop.ingest" => Some(daemon.handle_drop_ingest_rpc(&packet).await),
                    "gate.reload" => Some(handle_gate_reload_rpc(&daemon)),
                    "inbox.wake" => Some(handle_inbox_wake_rpc(&daemon, &packet).await),
                    "system.wake" => Some(handle_system_wake_rpc(&daemon, &packet).await),

                    _ => None,
                };
                if let Some(response) = response {
                    let _ = write_ndjson_line_async(&mut write_half, &response).await;
                    break;
                }

                match pkt_type {
                    "inspect.watch" => {
                        run_inspect_watch(
                            &daemon,
                            &packet,
                            tcp_endpoint.is_none(),
                            &mut reader,
                            &mut write_half,
                            &mut shutdown_rx,
                        )
                        .await;
                        break;
                    }
                    // ---- Blocking waiter / streaming watcher ----
                    "wait.subscribe" => {
                        let mode = match packet.get("mode").and_then(Value::as_str) {
                            Some("stream") => WaiterKind::Stream,
                            _ => WaiterKind::Once,
                        };

                        let mut sid = packet
                            .get("sessionId")
                            .and_then(Value::as_str)
                            .filter(|s| is_valid_session_id(s))
                            .map(ToString::to_string);
                        if sid.is_none() {
                            if let Some(tid) = packet
                                .get("herdrTerminalId")
                                .and_then(Value::as_str)
                                .filter(|t| is_valid_terminal_id(t))
                            {
                                let created_ms =
                                    packet.get("herdrCreatedMs").and_then(Value::as_i64);
                                sid = daemon
                                    .resolve_session_by_herdr_terminal(tid, created_ms)
                                    .map(|s| s.id);
                            }
                        }
                        if sid.is_none() {
                            if let Some(h) = packet.get("handle").and_then(Value::as_str) {
                                let clean = h.trim().strip_prefix('@').unwrap_or(h.trim());
                                sid = daemon
                                    .node
                                    .db()
                                    .local()
                                    .session_by_handle(clean)
                                    .ok()
                                    .flatten()
                                    .map(|s| s.id);
                            }
                        }
                        let Some(session_id) = sid else {
                            let _ = write_ndjson_line_async(
                                &mut write_half,
                                &json!({
                                    "type": "wait.error",
                                    "message": "Unknown session or handle. Join the mesh first or pass --session <id>."
                                }),
                            )
                            .await;
                            break;
                        };

                        if let Err(err_code) = daemon.verify_wait_session_auth(&session_id, &packet)
                        {
                            let _ = write_ndjson_line_async(
                                &mut write_half,
                                &json!({
                                    "type": "wait.error",
                                    "code": err_code,
                                    "message": "Invalid or missing sessionToken for this session."
                                }),
                            )
                            .await;
                            break;
                        }

                        let waiter_id = daemon.next_seq();
                        {
                            daemon
                                .session_runtime()
                                .entry(session_id.clone())
                                .or_default()
                                .waiters
                                .push(LiveWaiter {
                                    id: waiter_id,
                                    mode,
                                    tx: out_tx.clone(),
                                });
                        }
                        attached_waiter = Some((session_id.clone(), waiter_id));
                        daemon.mark_session_idle(&session_id);
                        let _ = daemon
                            .node
                            .db()
                            .local()
                            .touch_session(&session_id, daemon.current_time_ms());
                        daemon.bump_ui_rev();

                        let mode_str = match mode {
                            WaiterKind::Once => "once",
                            WaiterKind::Stream => "stream",
                        };
                        if write_ndjson_line_async(
                            &mut write_half,
                            &json!({ "type": "wait.ready", "sessionId": session_id, "mode": mode_str }),
                        )
                        .await
                        .is_err()
                        {
                            break;
                        }

                        // Spawn flush so `out_rx` in this select loop receives pushed items immediately!
                        let flush_daemon = Arc::clone(&daemon);
                        let flush_sid = session_id;
                        tokio::spawn(async move {
                            flush_daemon.flush_session(&flush_sid).await;
                        });
                    }

                    // ---- Native OpenClaw Gateway plugin wake service ----
                    "openclaw.service.ready" => {
                        {
                            let mut guard = daemon
                                .openclaw_service
                                .lock_state("openclaw_service lock poisoned");
                            *guard = Some(LiveOpenClawService {
                                conn_id,
                                tx: oc_wake_tx.clone(),
                            });
                        }
                        daemon.session_runtime().retain(|_, runtime| {
                            runtime.openclaw_session_missing = false;
                            !runtime.is_empty()
                        });
                        is_openclaw_service = true;
                        daemon.bump_ui_rev();
                        if write_ndjson_line_async(
                            &mut write_half,
                            &json!({ "type": "openclaw.service.ack", "ok": true }),
                        )
                        .await
                        .is_err()
                        {
                            break;
                        }
                        let flush_daemon = Arc::clone(&daemon);
                        tokio::spawn(async move {
                            let oc_sessions: Vec<String> = {
                                let db = flush_daemon.node.db();
                                db.local()
                                    .list_sessions()
                                    .unwrap_or_default()
                                    .into_iter()
                                    .filter(|s| s.id.starts_with("openclaw:"))
                                    .map(|s| s.id)
                                    .collect()
                            };
                            for sid in oc_sessions {
                                if flush_daemon.openclaw_plugin_wake_available_for(&sid) {
                                    let _ = flush_daemon.flush_session(&sid).await;
                                }
                            }
                        });
                    }
                    "openclaw.wake.ack" => {
                        if let Some(delivery_id) = packet.get("delivery").and_then(Value::as_u64) {
                            let ok = packet.get("ok").and_then(Value::as_bool) == Some(true);
                            let reason = packet
                                .get("reason")
                                .and_then(Value::as_str)
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                                .map(ToString::to_string);
                            if let Some(tx) = pending_oc_wake_acks.remove(&delivery_id) {
                                let _ = tx.send(OpenClawWakeAck { ok, reason });
                            }
                        }
                    }

                    // ---- Persistent MCP shim protocol ----
                    "mcp.hello" => {
                        let backend = packet
                            .get("backend")
                            .and_then(Value::as_str)
                            .and_then(|s| s.parse::<HarnessKind>().ok());
                        let channel = packet.get("channel").and_then(Value::as_bool) == Some(true);
                        let ephemeral_client_id = packet
                            .get("clientId")
                            .and_then(Value::as_str)
                            .filter(|s| !s.is_empty() && s.len() <= 64)
                            .map(ToString::to_string);
                        let session_token = packet
                            .get("sessionToken")
                            .and_then(Value::as_str)
                            .map(str::trim)
                            .filter(|s| is_valid_session_token(s))
                            .map(ToString::to_string);
                        let hints = TransportHints::from_packet(&packet, backend);
                        mcp_ctx = Some(McpSocketContext {
                            backend,
                            channel,
                            channel_ready: false,
                            channel_session_id: None,
                            ephemeral_client_id,
                            session_token,
                            hints,
                        });
                    }
                    "channel.ready" => {
                        if let Some(ref mut ctx) = mcp_ctx {
                            if ctx.channel {
                                ctx.channel_ready = true;
                                if let Some(ref sid) = ctx.channel_session_id.clone() {
                                    bind_channel(&daemon, conn_id, sid, &chan_tx);
                                } else if let Some(ref cid) = ctx.ephemeral_client_id.clone() {
                                    let sid = format!("claude:{cid}");
                                    let mut patch =
                                        ctx.hints.backend_patch(Some(HarnessKind::Claude));
                                    patch.insert("channel".into(), json!(true));
                                    let _ = daemon.merge_session_backend_and_index(
                                        &sid,
                                        &patch,
                                        daemon.current_time_ms(),
                                    );
                                    ctx.channel_session_id = Some(sid.clone());
                                    bind_channel(&daemon, conn_id, &sid, &chan_tx);
                                }
                            }
                        }
                    }
                    "channel.ack" => {
                        if let Some(delivery_id) = packet.get("delivery").and_then(Value::as_u64) {
                            let submitted =
                                packet.get("submitted").and_then(Value::as_bool) == Some(true);
                            if let Some(tx) = pending_channel_acks.remove(&delivery_id) {
                                let _ = tx.send(submitted);
                            }
                        }
                    }
                    "mcp.caps" => {
                        if let Some(req_id) = packet.get("id").and_then(Value::as_u64) {
                            let resp = json!({
                                "id": req_id,
                                "result": {
                                    "hasPlugins": daemon.has_plugins_capability(),
                                    "hasKv": daemon.has_kv_capability(),
                                }
                            });
                            if write_ndjson_line_async(&mut write_half, &resp)
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                    }
                    "tool.call" => {
                        let Some(req_id) = packet.get("id").and_then(Value::as_u64) else {
                            continue;
                        };
                        let Some(tool_name) = packet.get("name").and_then(Value::as_str) else {
                            let _ = write_ndjson_line_async(
                                &mut write_half,
                                &json!({
                                    "id": req_id,
                                    "error": { "code": "invalid_request", "message": "Missing tool name" }
                                }),
                            )
                            .await;
                            continue;
                        };
                        let args = packet
                            .get("args")
                            .and_then(Value::as_object)
                            .cloned()
                            .unwrap_or_default();
                        let call_id = packet.get("callId").and_then(Value::as_str);
                        let call_token = packet.get("callToken").and_then(Value::as_str);

                        let resolved_session = resolve_tool_caller(
                            &daemon,
                            mcp_ctx.as_mut(),
                            conn_id,
                            &chan_tx,
                            tool_name,
                            call_id,
                            call_token,
                        )
                        .await;

                        let resp = match resolved_session {
                            Ok(session_id) => {
                                match daemon.dispatch_tool(&session_id, tool_name, &args).await {
                                    Ok(result) => json!({ "id": req_id, "result": result }),
                                    Err((code, message)) => json!({
                                        "id": req_id,
                                        "error": { "code": code, "message": message }
                                    }),
                                }
                            }
                            Err((code, message)) => json!({
                                "id": req_id,
                                "error": { "code": code, "message": message }
                            }),
                        };
                        if write_ndjson_line_async(&mut write_half, &resp)
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    _ => {
                        let _ = write_ndjson_line_async(
                            &mut write_half,
                            &json!({"ok": false, "error": "unknown_rpc_type"}),
                        )
                        .await;
                        break;
                    }
                }
            }
        }
    }

    // Cleanup registered live waiter / channel transport on disconnect.
    let mut transport_changed = false;
    if let Some((sid, wid)) = attached_waiter {
        transport_changed |= daemon
            .update_runtime(&sid, |runtime| {
                let before = runtime.waiters.len();
                runtime.waiters.retain(|waiter| waiter.id != wid);
                runtime.waiters.len() != before
            })
            .unwrap_or(false);
    }
    if let Some(ref ctx) = mcp_ctx {
        if let Some(ref sid) = ctx.channel_session_id {
            transport_changed |= daemon
                .update_runtime(sid, |runtime| {
                    if runtime
                        .channel
                        .as_ref()
                        .is_some_and(|channel| channel.conn_id == conn_id)
                    {
                        runtime.channel = None;
                        true
                    } else {
                        false
                    }
                })
                .unwrap_or(false);
        }
    }
    if is_openclaw_service {
        let mut guard = daemon
            .openclaw_service
            .lock_state("openclaw_service lock poisoned");
        if guard.as_ref().is_some_and(|s| s.conn_id == conn_id) {
            *guard = None;
            transport_changed = true;
        }
    }
    if transport_changed {
        daemon.bump_ui_rev();
    }
    for (_, tx) in pending_channel_acks.drain() {
        let _ = tx.send(false);
    }
    for (_, tx) in pending_oc_wake_acks.drain() {
        let _ = tx.send(OpenClawWakeAck {
            ok: false,
            reason: Some(REASON_OPENCLAW_GATEWAY_UNAVAILABLE.to_string()),
        });
    }
}

fn bind_channel(
    daemon: &Arc<LocalDaemonInner>,
    conn_id: u64,
    session_id: &str,
    chan_tx: &mpsc::UnboundedSender<ChannelDeliverCommand>,
) {
    daemon
        .session_runtime()
        .entry(session_id.to_owned())
        .or_default()
        .channel = Some(LiveChannel {
        conn_id,
        tx: chan_tx.clone(),
    });
    daemon.bump_ui_rev();
    let flush_daemon = Arc::clone(daemon);
    let sid = session_id.to_string();
    tokio::spawn(async move {
        flush_daemon.flush_session(&sid).await;
    });
}

async fn resolve_tool_caller(
    daemon: &Arc<LocalDaemonInner>,
    mut mcp_ctx: Option<&mut McpSocketContext>,
    conn_id: u64,
    chan_tx: &mpsc::UnboundedSender<ChannelDeliverCommand>,
    tool_name: &str,
    call_id: Option<&str>,
    call_token: Option<&str>,
) -> Result<String, (String, String)> {
    // 1. Primary path: host-verified PreToolUse registration (`callToken` or `_meta` `callId`).
    if call_id.is_some_and(|s| !s.is_empty()) || call_token.is_some_and(|s| !s.is_empty()) {
        let wait = if call_token.is_some() {
            DEFAULT_RESOLVE_WAIT
        } else {
            Duration::from_millis(250)
        };
        match daemon
            .calls
            .resolve_call(tool_name, call_id, call_token, wait)
            .await
        {
            CallerResolution::Verified {
                session_id,
                harness,
                ..
            } => {
                let patch = mcp_ctx
                    .as_deref()
                    .map(|ctx| ctx.hints.backend_patch(Some(harness)))
                    .unwrap_or_else(|| {
                        let mut m = Map::new();
                        m.insert("kind".into(), json!(harness.as_str()));
                        m
                    });
                let session = daemon.merge_session_backend_and_index(
                    &session_id,
                    &patch,
                    daemon.current_time_ms(),
                );
                daemon.bump_ui_rev();
                if let Some(ctx) = mcp_ctx.as_deref_mut() {
                    if ctx.channel && harness == HarnessKind::Claude {
                        ctx.channel_session_id = Some(session_id.clone());
                        if ctx.channel_ready {
                            bind_channel(daemon, conn_id, &session_id, chan_tx);
                        }
                    }
                    let mut hints = ctx.hints.clone();
                    // Sparse MCP calls must keep T3 hints previously supplied by hooks.
                    // Another probe may start after the hook's own probe has completed.
                    if let Ok(session) = session {
                        let persisted = TransportHints::from_session_backend(
                            &session_id,
                            &session.backend_json,
                        );
                        hints.t3_url = hints.t3_url.or(persisted.t3_url);
                        hints.t3_base_dir = hints.t3_base_dir.or(persisted.t3_base_dir);
                        hints.t3_thread_id = hints.t3_thread_id.or(persisted.t3_thread_id);
                    }
                    if hints.harness.is_none() {
                        hints.harness = Some(harness);
                    }
                    daemon.clear_lazy_hydrate_cooldown(&session_id);
                    maybe_spawn_transport_probe(daemon, &session_id, hints);
                }
                return Ok(session_id);
            }
            CallerResolution::Failed { code, message } => {
                // X6 (P1): NEVER let `--ephemeral` bypass an explicit `_meshCall` token failure
                // (invalid, expired, forged, or replayed token), nor an ambiguous/unverifiable
                // call, nor a missing callId when a real hook-registered session exists for that
                // harness!
                let explicit_token_supplied = call_token.is_some_and(|s| !s.is_empty());
                let ephemeral_opt = mcp_ctx
                    .as_deref()
                    .and_then(|c| c.ephemeral_client_id.as_ref());
                let backend_opt = mcp_ctx.as_deref().and_then(|c| c.backend);
                let backend_has_hooks = backend_opt.is_some_and(harness_natively_uses_hooks);
                let session_has_hooks = ephemeral_opt.is_some_and(|cid| {
                    let harness = backend_opt.unwrap_or(HarnessKind::Claude);
                    let sid = format!("{}:{cid}", harness.as_str());
                    daemon
                        .hook_registered_sessions
                        .lock()
                        .expect("hook_registered_sessions lock poisoned")
                        .contains(&sid)
                });
                if explicit_token_supplied
                    || ephemeral_opt.is_none()
                    || code != CallerErrorCode::CallerNotFound
                    || backend_has_hooks
                    || session_has_hooks
                {
                    return Err((code.as_str().to_string(), message));
                }
            }
        }
    }

    // 2. Explicit opt-in `--ephemeral` scratch mode
    if let Some(ctx) = mcp_ctx {
        if let Some(ref cid) = ctx.ephemeral_client_id {
            let harness = ctx.backend.unwrap_or(HarnessKind::Claude);
            let session_id = format!("{}:{cid}", harness.as_str());
            let patch = ctx.hints.backend_patch(Some(harness));
            let _ = daemon.merge_session_backend_and_index(
                &session_id,
                &patch,
                daemon.current_time_ms(),
            );
            daemon.bump_ui_rev();
            if ctx.channel && harness == HarnessKind::Claude {
                ctx.channel_session_id = Some(session_id.clone());
                if ctx.channel_ready {
                    bind_channel(daemon, conn_id, &session_id, chan_tx);
                }
            }
            let mut hints = ctx.hints.clone();
            if hints.harness.is_none() {
                hints.harness = Some(harness);
            }
            daemon.clear_lazy_hydrate_cooldown(&session_id);
            maybe_spawn_transport_probe(daemon, &session_id, hints);
            return Ok(session_id);
        }
    }

    // 3. Optional test-only bypass when `require_verified_caller == false`
    if !daemon.config.require_verified_caller {
        let sid = format!("ephemeral:{}", uuid_v4());
        let mut patch = Map::new();
        patch.insert("kind".into(), json!("claude"));
        let _ = daemon.merge_session_backend_and_index(&sid, &patch, daemon.current_time_ms());
        daemon.bump_ui_rev();
        return Ok(sid);
    }

    Err((
        "caller_unverifiable".into(),
        "Could not verify calling thread/conversation. Run 'hyp setup <harness>' to install PreToolUse hooks (or pass --ephemeral for scratch testing).".into(),
    ))
}

fn kv_auth_required() -> Value {
    json!({ "ok": false, "error": "Local KV authentication failed." })
}

async fn authenticate_tcp_kv<R, W>(
    daemon: &LocalDaemonInner,
    packet: &Map<String, Value>,
    endpoint: SocketAddr,
    reader: &mut BufReader<R>,
    writer: &mut W,
) -> Value
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let exchange = async {
        let request = hyp_harness_ipc::kv_auth::authenticate_request(
            &daemon.session_token_key,
            packet,
            endpoint,
            reader,
            writer,
        )
        .await?;
        Some(handle_local_kv(daemon, Some(&request)).await)
    };

    tokio::time::timeout(Duration::from_secs(5), exchange)
        .await
        .ok()
        .flatten()
        .unwrap_or_else(kv_auth_required)
}

async fn handle_local_kv(daemon: &LocalDaemonInner, request: Option<&Value>) -> Value {
    use crate::local_kv::{LocalKvAction, LocalKvError, LocalKvRequest, LocalKvResponse};

    let Some(request) = request else {
        return json!({ "ok": false, "error": "Missing local KV request" });
    };
    let request = match serde_json::from_value::<LocalKvRequest>(request.clone()) {
        Ok(request) => request,
        Err(err) => return json!({ "ok": false, "error": err.to_string() }),
    };
    let node = &daemon.node;
    let local = request.host_node == "local" || request.host_node == node.node_id().as_str();
    let result = match &request.action {
        LocalKvAction::Inspect if local => node
            .inspect_kv(daemon.current_time_ms())
            .await
            .map(LocalKvResponse::Inspect)
            .map_err(|err| LocalKvError::Other(err.to_string())),
        LocalKvAction::Keys { after } => node
            .inspect_kv_keys(&request.host_node, &request.namespace, after.as_deref())
            .await
            .map(LocalKvResponse::Keys)
            .map_err(|err| LocalKvError::Other(err.to_string())),
        LocalKvAction::Preview { key } => node
            .preview_kv(&request.host_node, &request.namespace, key)
            .await
            .map(LocalKvResponse::Preview)
            .map_err(|err| LocalKvError::Other(err.to_string())),
        LocalKvAction::Inspect => Err(LocalKvError::InvalidInput(
            "KV inspection requires a local namespace.".into(),
        )),
        _ => request.execute(&node.db(), node.node_id().as_str()),
    };
    if matches!(
        result,
        Ok(LocalKvResponse::Set(_) | LocalKvResponse::Delete { deleted: true, .. })
    ) {
        daemon.node.notify_local_kv_change();
    }
    let response = json!({ "ok": true, "result": { "response": result } });
    if matches!(result, Ok(LocalKvResponse::List { .. }))
        && serde_json::to_vec(&response)
            .is_ok_and(|bytes| bytes.len() > hyp_harness_ipc::sock::MAX_SOCKET_LINE_BYTES)
    {
        let result = Err::<LocalKvResponse, _>(LocalKvError::ListTooLarge {
            state_dir: daemon.node.config().state_dir.clone(),
            node_id: daemon.node.node_id().to_string(),
        });
        return json!({ "ok": true, "result": { "response": result } });
    }
    response
}
