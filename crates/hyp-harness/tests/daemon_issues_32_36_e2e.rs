//! Deterministic E2E regression & differential tests for GitHub Issues #32, #33, #34, #35, and #36:
//! - Issue #32: Focus Mode VIP bypass isolation (never leaks buffered `Notify` items on nudge-only
//!   transports or stamps them `notified = true`) + full restoration & immediate flush on `focus off`.
//! - Issue #33: Runtime wiring of Tier 4 `deliveryRetry.herdrSpawnAllowlist` / `try_herdr_cold_spawn`
//!   inside `LocalDaemon::flush_session` with strict fail-closed guards.
//! - Issue #34: Automatic startup & bounded lazy rehydration of persisted native push transports
//!   (`Herdr`, `CodexQueue`, `T3`) across daemon restarts even when `pending_count == 0`.
//! - Issue #35: Reject auto-attaching `CodexQueueTransport` to non-interactive `codex exec` rollouts
//!   (`"source": "exec"` / `"originator": "codex_exec"`) while attaching cleanly to interactive `"source": "cli"`.
//! - Issue #36: Fail-closed `herdr_bare_shell_rejected` when explicit `--backend herdr` probes a
//!   confirmed bare shell (`status: null` or `status.app: null`), while live coding agents attach cleanly.

mod common;

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::{TestMcpClient, run_hook, session_status};
use hyp_crypto::SecretBackend;
use hyp_harness::daemon::{InboundItem, LocalDaemon, LocalDaemonConfig};
use hyp_harness::hooks::HookEvent;
use hyp_harness::mcp::McpOptions;
use hyp_harness::protocol::HarnessKind;
use hyp_harness::sock::daemon_rpc_async;
use hyp_harness::transport::{PushMode, PushOutcome, PushTransport, TransportFuture};
use hyp_node::engine::{NodeConfig, UnifiedNode};
use hyp_node::gates::TrustTier as GateTrustTier;
use hyp_proto::address::NodeId;
use hyp_store::{MailboxKind, now_ms};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::sync::Notify;

fn open_local_node(node_id: &str, dir: &Path) -> Arc<UnifiedNode> {
    let mut cfg = NodeConfig::local(NodeId::new(node_id).unwrap(), dir);
    cfg.secret_backend = Some(SecretBackend::File);
    UnifiedNode::open(cfg).expect("open UnifiedNode")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedNudge {
    count: usize,
    handle: Option<String>,
    mode: PushMode,
}

struct RecordingNudgeTransport {
    kind: &'static str,
    nudges: Mutex<Vec<RecordedNudge>>,
    notify: Notify,
}

impl RecordingNudgeTransport {
    fn new(kind: &'static str) -> Arc<Self> {
        Arc::new(Self {
            kind,
            nudges: Mutex::new(Vec::new()),
            notify: Notify::new(),
        })
    }

    fn snapshot(&self) -> Vec<RecordedNudge> {
        self.nudges.lock().unwrap().clone()
    }

    async fn wait_for_count(&self, expected: usize, timeout: Duration) -> Vec<RecordedNudge> {
        let deadline = Instant::now() + timeout;
        loop {
            let cur = self.snapshot();
            if cur.len() >= expected {
                return cur;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                panic!(
                    "RecordingNudgeTransport({}) timed out waiting for {expected} nudges (got {}): {cur:?}",
                    self.kind,
                    cur.len()
                );
            }
            let _ = tokio::time::timeout(
                remaining.min(Duration::from_millis(30)),
                self.notify.notified(),
            )
            .await;
        }
    }
}

impl PushTransport for RecordingNudgeTransport {
    fn kind(&self) -> &'static str {
        self.kind
    }

    fn supports_interrupt(&self) -> bool {
        true
    }

    fn deliver<'a>(&'a self, text: &'a str, mode: PushMode) -> TransportFuture<'a, PushOutcome> {
        let extract_attr = |attr: &str| -> Option<String> {
            let needle = format!("{attr}=\"");
            let rest = text.split_once(&needle)?.1;
            Some(rest.split_once('"')?.0.to_string())
        };
        let count = extract_attr("unread")
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1);
        let handle = extract_attr("handle");
        let rec = RecordedNudge {
            count,
            handle,
            mode,
        };
        Box::pin(async move {
            self.nudges.lock().unwrap().push(rec);
            self.notify.notify_waiters();
            PushOutcome::delivered()
        })
    }
}

// ============================================================================
// Issue #32: Focus Mode VIP bypass isolation + clean `focus off` flush
// ============================================================================

#[tokio::test]
async fn issue32_focus_vip_bypass_isolates_buffered_notify_and_flushes_on_focus_off() {
    let dir = TempDir::new().unwrap();
    let node = open_local_node("focus32@local", dir.path());
    let daemon = LocalDaemon::start(
        Arc::clone(&node),
        None,
        LocalDaemonConfig {
            auto_detect_transports: false,
            ..Default::default()
        },
    )
    .await
    .expect("start LocalDaemon");
    let sock = daemon.socket_path().to_path_buf();

    // ------------------------------------------------------------------------
    // 1A: Nudge-only OpenClaw-style transport (`hyp_inbox(ack: true)` on wake)
    // ------------------------------------------------------------------------
    let oc_key = "agent:main:focus-p4";
    let oc_sid = format!("openclaw:{oc_key}");
    let oc_transport = RecordingNudgeTransport::new("openclaw");

    let reg = daemon_rpc_async(
        &sock,
        &json!({
            "type": "session.register",
            "sessionId": oc_sid,
            "harness": "openclaw",
            "openclawSessionKey": oc_key,
            "openclawAgentId": "main"
        }),
        Duration::from_secs(2),
    )
    .await;
    assert!(reg.ok, "register openclaw session: {reg:?}");

    let mut oc_mcp = TestMcpClient::spawn(McpOptions {
        backend: Some(HarnessKind::Openclaw),
        ephemeral: false,
        ..McpOptions::new(sock.clone())
    });
    oc_mcp.initialize().await;

    let join_pre = run_hook(
        &sock,
        HarnessKind::Openclaw,
        HookEvent::PreToolUse,
        json!({
            "sessionKey": oc_key,
            "agentId": "main",
            "toolName": "hyphae__hyp_mesh",
            "toolCallId": "oc-join-32",
            "params": { "action": "join", "handle": "oc-alpha" }
        }),
    )
    .await;
    let join_tok = join_pre["callToken"].as_str().expect("join token");
    let (join_txt, join_err) = oc_mcp
        .call_tool(
            "hyp_mesh",
            json!({ "action": "join", "handle": "oc-alpha", "_meshCall": join_tok }),
            None,
        )
        .await;
    assert!(!join_err, "oc join failed: {join_txt}");

    daemon.register_session_transport(&oc_sid, Arc::clone(&oc_transport) as Arc<dyn PushTransport>);

    // Configure VIP interrupt rule and enable Focus Mode!
    let rule_res = daemon_rpc_async(
        &sock,
        &json!({
            "type": "session.rule",
            "sessionId": oc_sid,
            "target": "focus32@local/vip",
            "delivery": "interrupt"
        }),
        Duration::from_secs(2),
    )
    .await;
    assert!(rule_res.ok, "session.rule failed: {rule_res:?}");
    let focus_on = daemon_rpc_async(
        &sock,
        &json!({ "type": "session.focus", "sessionId": oc_sid, "enabled": true }),
        Duration::from_secs(2),
    )
    .await;
    assert!(focus_on.ok, "session.focus on failed: {focus_on:?}");

    // Send non-urgent `p4BufMsg` while Focus Mode is ON -> MUST buffer silently (0 nudges)!
    let p4_buf = "P4_FOCUS_BUFFERED_OPENCLAW_4004";
    let p4_vip = "P4_FOCUS_VIP_BYPASS_OPENCLAW_4005";
    daemon
        .ingest_inbound(InboundItem {
            session_id: oc_sid.clone(),
            origin_node: "focus32@local".into(),
            item_id: "oc-p4-buf".into(),
            source: "focus32@local/peer".into(),
            text: p4_buf.into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::SelfHost,
        })
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(
        oc_transport.snapshot().is_empty(),
        "Focus-buffered non-urgent DM must NOT trigger a wake nudge"
    );

    // Send VIP `p4VipMsg` while Focus Mode is ON -> MUST wake with count == 1 ONLY!
    daemon
        .ingest_inbound(InboundItem {
            session_id: oc_sid.clone(),
            origin_node: "focus32@local".into(),
            item_id: "oc-p4-vip".into(),
            source: "focus32@local/vip".into(),
            text: p4_vip.into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::SelfHost,
        })
        .await
        .unwrap();

    let nudges = oc_transport.wait_for_count(1, Duration::from_secs(3)).await;
    tokio::time::sleep(Duration::from_millis(60)).await;
    assert_eq!(
        nudges.len(),
        1,
        "expected strictly 1 VIP wake nudge: {nudges:?}"
    );
    assert_eq!(
        nudges[0].count, 1,
        "VIP wake batch MUST NOT fold Focus-buffered Notify item into count: {nudges:?}"
    );
    assert_eq!(nudges[0].mode, PushMode::Interrupt);

    // Verify in SQLite that `p4BufMsg` was NEVER stamped `notified = 1`!
    {
        let db = node.db();
        let rows = db.local().peek_inbox(&oc_sid, 10).unwrap();
        let buf_row = rows
            .iter()
            .find(|r| r.item_id == "oc-p4-buf")
            .expect("buf row");
        let vip_row = rows
            .iter()
            .find(|r| r.item_id == "oc-p4-vip")
            .expect("vip row");
        assert!(
            !buf_row.notified,
            "Focus-buffered item MUST remain notified == false in SQLite during VIP wake!"
        );
        assert!(vip_row.notified, "VIP item must be marked notified == true");
    }

    // OpenClaw wakes on `<hyphae-wake count="1">` and calls `hyp_inbox({ ack: true })` while Focus
    // Mode is STILL ON -> MUST receive & ack ONLY `p4VipMsg`, NEVER leaking `p4BufMsg`!
    let in_pre = run_hook(
        &sock,
        HarnessKind::Openclaw,
        HookEvent::PreToolUse,
        json!({
            "sessionKey": oc_key,
            "agentId": "main",
            "toolName": "hyphae__hyp_inbox",
            "toolCallId": "oc-inbox-vip-32",
            "params": { "ack": true }
        }),
    )
    .await;
    let in_tok = in_pre["callToken"].as_str().expect("inbox token");
    let (vip_in_txt, vip_in_err) = oc_mcp
        .call_tool(
            "hyp_inbox",
            json!({ "ack": true, "_meshCall": in_tok }),
            None,
        )
        .await;
    assert!(!vip_in_err, "oc hyp_inbox failed: {vip_in_txt}");
    let vip_in: Value = serde_json::from_str(&vip_in_txt).unwrap();
    assert_eq!(vip_in["items"].as_array().unwrap().len(), 1, "{vip_in_txt}");
    assert!(
        vip_in_txt.contains(p4_vip),
        "expected VIP payload: {vip_in_txt}"
    );
    assert!(
        !vip_in_txt.contains(p4_buf),
        "Focus-buffered item MUST NOT leak into VIP hyp_inbox(ack: true) pull while Focus is ON: {vip_in_txt}"
    );
    assert_eq!(
        vip_in["unread"], 1,
        "buffered item must stay unread: {vip_in_txt}"
    );
    // OpenClaw VIP turn completes (`agent_end` -> `session.idle`), clearing active-turn lease.
    let _ = run_hook(
        &sock,
        HarnessKind::Openclaw,
        HookEvent::Stop,
        json!({ "sessionKey": oc_key, "agentId": "main" }),
    )
    .await;

    // Now turn Focus Mode OFF -> `p4BufMsg` MUST flush immediately to OpenClaw push transport!
    let focus_off = daemon_rpc_async(
        &sock,
        &json!({ "type": "session.focus", "sessionId": oc_sid, "enabled": false }),
        Duration::from_secs(2),
    )
    .await;
    assert!(focus_off.ok, "session.focus off failed: {focus_off:?}");

    let nudges_after = oc_transport.wait_for_count(2, Duration::from_secs(3)).await;
    assert_eq!(nudges_after.len(), 2);
    assert_eq!(nudges_after[1].count, 1);
    assert_eq!(nudges_after[1].mode, PushMode::Queue);

    // Pull & ack the flushed buffered item.
    let in_pre2 = run_hook(
        &sock,
        HarnessKind::Openclaw,
        HookEvent::PreToolUse,
        json!({
            "sessionKey": oc_key,
            "agentId": "main",
            "toolName": "hyphae__hyp_inbox",
            "toolCallId": "oc-inbox-buf-32",
            "params": { "ack": true }
        }),
    )
    .await;
    let in_tok2 = in_pre2["callToken"].as_str().expect("inbox token 2");
    let (buf_in_txt, buf_in_err) = oc_mcp
        .call_tool(
            "hyp_inbox",
            json!({ "ack": true, "_meshCall": in_tok2 }),
            None,
        )
        .await;
    assert!(!buf_in_err, "{buf_in_txt}");
    assert!(
        buf_in_txt.contains(p4_buf),
        "expected buffered item after focus off: {buf_in_txt}"
    );
    assert_eq!(session_status(&sock, &oc_sid).await["pending"], 0);
    oc_mcp.close().await;

    // ------------------------------------------------------------------------
    // 1B: Hook+push transport (Herdr + Claude) — VIP bypass + PreTurn drain -> `focus off` flush!
    // ------------------------------------------------------------------------
    let hc_raw = "herdr-focus-p4";
    let hc_sid = format!("claude:{hc_raw}");
    let hc_transport = RecordingNudgeTransport::new("herdr");
    {
        let db = node.db();
        let now = now_ms();
        db.local().register_session(&hc_sid, "{}", now).unwrap();
        db.local()
            .set_session_handle(&hc_sid, Some("hc-alpha"), now)
            .unwrap();
    }
    daemon.register_session_transport(&hc_sid, Arc::clone(&hc_transport) as Arc<dyn PushTransport>);
    assert!(
        daemon_rpc_async(
            &sock,
            &json!({
                "type": "session.rule",
                "sessionId": hc_sid,
                "target": "focus32@local/vip",
                "delivery": "interrupt"
            }),
            Duration::from_secs(2),
        )
        .await
        .ok
    );
    assert!(
        daemon_rpc_async(
            &sock,
            &json!({ "type": "session.focus", "sessionId": hc_sid, "enabled": true }),
            Duration::from_secs(2),
        )
        .await
        .ok
    );

    let hc_buf = "P4_FOCUS_BUFFERED_HERDR_5004";
    let hc_vip = "P4_FOCUS_VIP_BYPASS_HERDR_5005";
    daemon
        .ingest_inbound(InboundItem {
            session_id: hc_sid.clone(),
            origin_node: "focus32@local".into(),
            item_id: "hc-p4-buf".into(),
            source: "focus32@local/peer".into(),
            text: hc_buf.into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::SelfHost,
        })
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(hc_transport.snapshot().is_empty());

    daemon
        .ingest_inbound(InboundItem {
            session_id: hc_sid.clone(),
            origin_node: "focus32@local".into(),
            item_id: "hc-p4-vip".into(),
            source: "focus32@local/vip".into(),
            text: hc_vip.into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::SelfHost,
        })
        .await
        .unwrap();
    let hc_n1 = hc_transport.wait_for_count(1, Duration::from_secs(3)).await;
    assert_eq!(hc_n1.len(), 1);
    assert_eq!(hc_n1[0].count, 1);
    assert_eq!(hc_n1[0].mode, PushMode::Interrupt);

    // Simulate inner Claude `UserPromptSubmit` (`PreInvocation` / `PreTurn`) during the VIP turn:
    // RFC 0004: Zero body text (neither `hc_vip` nor `hc_buf`) EVER appears in hooks!
    let pre_turn = run_hook(
        &sock,
        HarnessKind::Claude,
        HookEvent::PreInvocation,
        json!({ "session_id": hc_raw }),
    )
    .await;
    assert!(
        !pre_turn.to_string().contains(hc_buf),
        "Focus-buffered body must NEVER leak into VIP PreInvocation: {pre_turn}"
    );
    assert!(
        !pre_turn.to_string().contains(hc_vip),
        "RFC 0004: raw VIP body must NEVER leak into PreInvocation hook: {pre_turn}"
    );
    // Simulate the woken agent reading & acknowledging ONLY the VIP item via `hyp_inbox` (while
    // `hc_buf` remains isolated & unread in SQLite during Focus Mode!).
    {
        let db = node.db();
        let vip_rcpt = db
            .local()
            .peek_inbox(&hc_sid, 10)
            .unwrap()
            .into_iter()
            .find(|r| r.item_id == "hc-p4-vip")
            .expect("vip row")
            .receipt;
        db.local()
            .acknowledge_inbox(&hc_sid, &[vip_rcpt.as_str()], now_ms())
            .unwrap();
    }
    // Simulate turn completing (`Stop` -> mark idle) so activity lease clears cleanly.
    let _ = run_hook(
        &sock,
        HarnessKind::Claude,
        HookEvent::Stop,
        json!({ "session_id": hc_raw }),
    )
    .await;

    // Now exit Focus Mode -> `hc_buf` MUST NOT stay stranded with `notified=true, urgency=Notify`;
    // it MUST promote back to `Queue` and flush immediately to Herdr!
    assert!(
        daemon_rpc_async(
            &sock,
            &json!({ "type": "session.focus", "sessionId": hc_sid, "enabled": false }),
            Duration::from_secs(2),
        )
        .await
        .ok
    );
    let hc_n2 = hc_transport.wait_for_count(2, Duration::from_secs(3)).await;
    assert_eq!(hc_n2.len(), 2);
    assert_eq!(hc_n2[1].count, 1);
    assert_eq!(hc_n2[1].mode, PushMode::Queue);

    // ------------------------------------------------------------------------
    // 1C: Focus ON -> non-urgent DM (NO VIP) -> Focus OFF -> immediate push flush!
    // ------------------------------------------------------------------------
    let no_vip_sid = "claude:focus-no-vip";
    let no_vip_transport = RecordingNudgeTransport::new("herdr");
    {
        let db = node.db();
        let now = now_ms();
        db.local().register_session(no_vip_sid, "{}", now).unwrap();
        db.local()
            .set_session_handle(no_vip_sid, Some("calm-agent"), now)
            .unwrap();
    }
    daemon.register_session_transport(
        no_vip_sid,
        Arc::clone(&no_vip_transport) as Arc<dyn PushTransport>,
    );
    assert!(
        daemon_rpc_async(
            &sock,
            &json!({ "type": "session.focus", "sessionId": no_vip_sid, "enabled": true }),
            Duration::from_secs(2),
        )
        .await
        .ok
    );
    daemon
        .ingest_inbound(InboundItem {
            session_id: no_vip_sid.into(),
            origin_node: "focus32@local".into(),
            item_id: "novip-buf-1".into(),
            source: "focus32@local/peer".into(),
            text: "NO_VIP_FOCUS_BUFFERED_6001".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::SelfHost,
        })
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(no_vip_transport.snapshot().is_empty());

    assert!(
        daemon_rpc_async(
            &sock,
            &json!({ "type": "session.focus", "sessionId": no_vip_sid, "enabled": false }),
            Duration::from_secs(2),
        )
        .await
        .ok
    );
    let nv_nudges = no_vip_transport
        .wait_for_count(1, Duration::from_secs(3))
        .await;
    assert_eq!(nv_nudges.len(), 1);
    assert_eq!(nv_nudges[0].count, 1);
    assert_eq!(nv_nudges[0].mode, PushMode::Queue);

    daemon.stop().await;
    node.shutdown();
}

// ============================================================================
// Unix-only subprocess E2E tests for Issues #33, #34, #35, and #36
// ============================================================================

#[cfg(unix)]
mod unix_e2e {
    use crate::common::{run_hook_with_hints, wait_for_live_transport};
    use hyp_harness::daemon::DeliveryRetryConfig;
    use hyp_harness::hooks::HookTransportHints;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    use hyp_harness::transport::herdr::{HerdrTarget, HerdrTransport};

    use super::*;

    fn write_executable_script(dir: &Path, name: &str, script: &str) -> PathBuf {
        let tmp = dir.join(format!("{name}.tmp"));
        let dst = dir.join(name);
        fs::write(&tmp, script).unwrap();
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o755)).unwrap();
        fs::rename(&tmp, &dst).unwrap();
        dst
    }

    // ------------------------------------------------------------------------
    // Issue #33: Live `flush_session` Tier 4 Herdr cold-spawn + fail-closed guards
    // ------------------------------------------------------------------------
    #[tokio::test]
    async fn issue33_live_flush_session_triggers_allowlisted_herdr_cold_spawn_and_fails_closed() {
        let dir = TempDir::new().unwrap();
        let state_dir = dir.path().join("state");
        let run_log = dir.path().join("hc_run.log");
        let get_log = dir.path().join("hc_get.log");

        let hc_bin = write_executable_script(
            dir.path(),
            "hc",
            &format!(
                r#"#!/bin/sh
set -eu
CMD="${{1:-}}"
case "$CMD" in
  get)
    printf '%s\n' "$*" >> "{get_log}"
    # Report every terminal as exited/unavailable so dead-terminal fallback exercises cold-spawn.
    printf '%s\n' '{{"address":"t-dead","created_ms":100,"pid":10,"state":"exited","status":null}}'
    exit 0
    ;;
  run)
    printf '%s\n' "$*" >> "{run_log}"
    exit 0
    ;;
  *)
    exit 1
    ;;
esac
"#,
                get_log = get_log.display(),
                run_log = run_log.display(),
            ),
        );

        let node = open_local_node("tier4live@local", &state_dir);
        let daemon = LocalDaemon::start(
            Arc::clone(&node),
            None,
            LocalDaemonConfig {
                auto_detect_transports: false,
                herdr_bin: Some(hc_bin.to_string_lossy().to_string()),
                delivery_retry: DeliveryRetryConfig {
                    herdr_spawn_allowlist: vec!["ci-triage".to_string()],
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .expect("start LocalDaemon");
        let sock = daemon.socket_path().to_path_buf();

        // 1. Allowlisted cold Herdr session (no live transport) -> inbound DM triggers `hc run`
        //    automatically through `flush_session` (NEVER calling `try_herdr_cold_spawn` directly!).
        let cold_sid = "herdr:cold-triage";
        {
            let db = node.db();
            let now = now_ms();
            db.local()
                .register_session(
                    cold_sid,
                    &json!({ "kind": "herdr", "herdrTemplate": "ci-triage" }).to_string(),
                    now,
                )
                .unwrap();
            db.local()
                .set_session_handle(cold_sid, Some("triage-bot"), now)
                .unwrap();
        }
        let secret_dm = "UNTRUSTED_BODY_MUST_NOT_APPEAR_IN_HC_RUN_ARGV_777";
        daemon
            .ingest_inbound(InboundItem {
                session_id: cold_sid.into(),
                origin_node: "tier4live@local".into(),
                item_id: "cold-dm-1".into(),
                source: "tier4live@local/ops".into(),
                text: secret_dm.into(),
                kind: MailboxKind::Message,
                trust_tier: GateTrustTier::SelfHost,
            })
            .await
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(4);
        let spawned_log = loop {
            if let Ok(content) = fs::read_to_string(&run_log) {
                if !content.trim().is_empty() {
                    break content;
                }
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for automatic Tier 4 Herdr cold spawn via flush_session"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert_eq!(
            spawned_log.matches("run ci-triage ").count(),
            1,
            "expected 1 cold spawn:\n{spawned_log}"
        );
        assert!(
            spawned_log.contains("run ci-triage <hyphae-inbox")
                && spawned_log.contains("handle=\"triage-bot\""),
            "unexpected hc run invocation:\n{spawned_log}"
        );
        assert!(
            !spawned_log.contains(secret_dm),
            "Tier 4 cold spawn MUST use metadata-only XML digest, never raw untrusted DM body:\n{spawned_log}"
        );
        // Unread DM stays preserved in SQLite for the newly spawned agent (`notified = 1`).
        assert_eq!(session_status(&sock, cold_sid).await["pending"], 1);
        // Repeated flush MUST NOT spawn a second cold agent!
        daemon.flush_pending_sessions().await;
        tokio::time::sleep(Duration::from_millis(60)).await;
        assert_eq!(
            fs::read_to_string(&run_log)
                .unwrap()
                .matches("run ci-triage ")
                .count(),
            1
        );

        // 2. Dead Herdr transport (`herdr_target_unavailable`) with allowlisted template detaches
        //    and falls through to cold spawn cleanly!
        let dead_sid = "herdr:dead-revive";
        {
            let db = node.db();
            let now = now_ms();
            db.local()
                .register_session(
                    dead_sid,
                    &json!({
                        "kind": "herdr",
                        "herdrTerminalId": "t-dead",
                        "herdrTemplate": "ci-triage"
                    })
                    .to_string(),
                    now,
                )
                .unwrap();
            db.local()
                .set_session_handle(dead_sid, Some("revive-bot"), now)
                .unwrap();
        }
        let dead_target = HerdrTarget::new("t-dead").with_bin(hc_bin.to_string_lossy().to_string());
        daemon.register_session_transport(dead_sid, Arc::new(HerdrTransport::new(dead_target)));
        daemon
            .ingest_inbound(InboundItem {
                session_id: dead_sid.into(),
                origin_node: "tier4live@local".into(),
                item_id: "dead-dm-1".into(),
                source: "tier4live@local/ops".into(),
                text: "revive dead herdr terminal".into(),
                kind: MailboxKind::Message,
                trust_tier: GateTrustTier::SelfHost,
            })
            .await
            .unwrap();
        let deadline2 = Instant::now() + Duration::from_secs(4);
        loop {
            let count = fs::read_to_string(&run_log)
                .map(|s| s.matches("run ci-triage ").count())
                .unwrap_or(0);
            if count >= 2 {
                break;
            }
            assert!(
                Instant::now() < deadline2,
                "expected dead Herdr terminal to fall through to allowlisted cold spawn"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(
            daemon.session_transport_kind(dead_sid).is_none(),
            "dead Herdr transport should have been detached"
        );

        // 3. Non-allowlisted template MUST fail closed with ZERO spawn!
        let unlisted_sid = "herdr:unlisted-tpl";
        {
            let db = node.db();
            let now = now_ms();
            db.local()
                .register_session(
                    unlisted_sid,
                    &json!({ "kind": "herdr", "herdrTemplate": "not-allowed" }).to_string(),
                    now,
                )
                .unwrap();
            db.local()
                .set_session_handle(unlisted_sid, Some("blocked-bot"), now)
                .unwrap();
        }
        daemon
            .ingest_inbound(InboundItem {
                session_id: unlisted_sid.into(),
                origin_node: "tier4live@local".into(),
                item_id: "unlisted-dm-1".into(),
                source: "tier4live@local/ops".into(),
                text: "should never spawn".into(),
                kind: MailboxKind::Message,
                trust_tier: GateTrustTier::SelfHost,
            })
            .await
            .unwrap();

        // 4. Focus-buffered Notify-only & Muted items MUST NEVER trigger cold spawn!
        let gated_sid = "herdr:focus-muted-cold";
        {
            let db = node.db();
            let now = now_ms();
            db.local()
                .register_session(
                    gated_sid,
                    &json!({ "kind": "herdr", "herdrTemplate": "ci-triage" }).to_string(),
                    now,
                )
                .unwrap();
            db.local()
                .set_session_handle(gated_sid, Some("quiet-bot"), now)
                .unwrap();
            db.local()
                .add_mute(gated_sid, "tier4live@local/spam", "test", now)
                .unwrap();
        }
        assert!(
            daemon_rpc_async(
                &sock,
                &json!({ "type": "session.focus", "sessionId": gated_sid, "enabled": true }),
                Duration::from_secs(2),
            )
            .await
            .ok
        );
        daemon
            .ingest_inbound(InboundItem {
                session_id: gated_sid.into(),
                origin_node: "tier4live@local".into(),
                item_id: "muted-dm-1".into(),
                source: "tier4live@local/spam".into(),
                text: "spam".into(),
                kind: MailboxKind::Message,
                trust_tier: GateTrustTier::SelfHost,
            })
            .await
            .unwrap();
        daemon
            .ingest_inbound(InboundItem {
                session_id: gated_sid.into(),
                origin_node: "tier4live@local".into(),
                item_id: "focus-dm-1".into(),
                source: "tier4live@local/ops".into(),
                text: "focus buffered".into(),
                kind: MailboxKind::Message,
                trust_tier: GateTrustTier::SelfHost,
            })
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert_eq!(
            fs::read_to_string(&run_log)
                .unwrap()
                .matches("run ci-triage ")
                .count(),
            2,
            "non-allowlisted, muted, and Focus-buffered items must NEVER cold-spawn"
        );

        daemon.stop().await;
        node.shutdown();
    }

    // ------------------------------------------------------------------------
    // Issue #34: Restart rehydrates persisted Herdr & Codex transports with 0 pending items
    // ------------------------------------------------------------------------
    #[tokio::test]
    async fn issue34_restart_rehydrates_herdr_and_codex_transports_with_zero_pending_items() {
        let dir = TempDir::new().unwrap();
        let state_dir = dir.path().join("state");
        let sock = state_dir.join("connector.sock");
        let hc_send_log = dir.path().join("hc_send.log");
        let hc_get_count = dir.path().join("hc_get_dead_count.log");
        let cx_queue_log = dir.path().join("codex_queue.log");

        let codex_home = dir.path().join("codex-home");
        let sessions_dir = codex_home.join("sessions/2026/11/26");
        fs::create_dir_all(&sessions_dir).unwrap();
        let cx_uuid = "01a217e1-c5f7-7720-a22b-888b924cc340";
        let cx_sid = format!("codex:{cx_uuid}");
        fs::write(
            sessions_dir.join(format!("rollout-2026-11-26T12-00-00-{cx_uuid}.jsonl")),
            format!(
                "{{\"type\":\"session_meta\",\"payload\":{{\"id\":\"{cx_uuid}\",\"originator\":\"codex_cli_rs\",\"source\":\"cli\"}}}}\n"
            ),
        )
        .unwrap();

        let hc_bin = write_executable_script(
            dir.path(),
            "hc",
            &format!(
                r#"#!/bin/sh
set -eu
CMD="${{1:-}}"
case "$CMD" in
  get)
    TID="${{3:-}}"
    case "$TID" in
      t9)
        printf '%s\n' '{{"address":"t9","created_ms":1700000000777,"pid":4242,"state":"live","status":{{"app":"claude-code","state":"idle"}}}}'
        exit 0
        ;;
      t-recycled)
        printf '%s\n' '{{"address":"t-recycled","created_ms":1700009999999,"pid":9999,"state":"live","status":{{"app":"claude-code","state":"idle"}}}}'
        exit 0
        ;;
      t-dead)
        printf '1\n' >> "{dead_log}"
        exit 1
        ;;
      *)
        exit 1
        ;;
    esac
    ;;
  send)
    printf '%s\n' "$*" >> "{send_log}"
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
"#,
                dead_log = hc_get_count.display(),
                send_log = hc_send_log.display(),
            ),
        );

        let codex_bin = write_executable_script(
            dir.path(),
            "codex",
            &format!(
                r#"#!/bin/sh
set -eu
if [ "${{1:-}}" = "queue" ] && [ "${{2:-}}" = "--help" ]; then
  echo "Usage: codex queue --thread <id> --message <msg>"
  exit 0
fi
printf '%s\n' "$*" >> "{cx_log}"
exit 0
"#,
                cx_log = cx_queue_log.display(),
            ),
        );

        let hc_sid = "claude:herdr-zero-pending";
        let recycled_sid = "claude:herdr-recycled";
        let dead_sid = "claude:herdr-dead-cooldown";

        // Phase 1: Persist enrolled sessions with **0 pending items** and shut down cleanly.
        {
            let node = open_local_node("rehydrate34@local", &state_dir);
            let db = node.db();
            let now = now_ms();
            db.local()
                .register_session(
                    hc_sid,
                    &json!({
                        "kind": "claude",
                        "herdrTerminalId": "t9",
                        "herdrCreatedMs": 1700000000777i64
                    })
                    .to_string(),
                    now,
                )
                .unwrap();
            db.local()
                .set_session_handle(hc_sid, Some("herdr-worker"), now)
                .unwrap();

            db.local()
                .register_session(
                    &cx_sid,
                    &json!({
                        "kind": "codex",
                        "codexThreadId": cx_uuid,
                        "codexHome": codex_home.to_string_lossy()
                    })
                    .to_string(),
                    now,
                )
                .unwrap();
            db.local()
                .set_session_handle(&cx_sid, Some("codex-worker"), now)
                .unwrap();

            // Recycled Herdr terminal: persisted created_ms (1700000000111) != live (1700009999999)
            db.local()
                .register_session(
                    recycled_sid,
                    &json!({
                        "kind": "claude",
                        "herdrTerminalId": "t-recycled",
                        "herdrCreatedMs": 1700000000111i64
                    })
                    .to_string(),
                    now,
                )
                .unwrap();
            db.local()
                .set_session_handle(recycled_sid, Some("stale-worker"), now)
                .unwrap();

            // Permanently dead Herdr terminal (for lazy hydration cooldown verification).
            db.local()
                .register_session(
                    dead_sid,
                    &json!({
                        "kind": "claude",
                        "herdrTerminalId": "t-dead"
                    })
                    .to_string(),
                    now,
                )
                .unwrap();
            db.local()
                .set_session_handle(dead_sid, Some("dead-worker"), now)
                .unwrap();

            assert_eq!(db.local().pending_count(hc_sid).unwrap(), 0);
            assert_eq!(db.local().pending_count(&cx_sid).unwrap(), 0);
            drop(db);
            node.shutdown();
        }

        // Phase 2: Restart daemon with **0 pending items** and NO hook/MCP calls!
        let node = open_local_node("rehydrate34@local", &state_dir);
        let daemon = LocalDaemon::start(
            Arc::clone(&node),
            None,
            LocalDaemonConfig {
                socket_path: Some(sock.clone()),
                auto_detect_transports: true,
                herdr_bin: Some(hc_bin.to_string_lossy().to_string()),
                codex_bin: Some(codex_bin.to_string_lossy().to_string()),
                t3_default_base_dir: Some(dir.path().join("no-t3")),
                ..Default::default()
            },
        )
        .await
        .expect("restart LocalDaemon");

        // Both live sessions MUST rehydrate automatically despite 0 pending items!
        wait_for_live_transport(&sock, hc_sid).await;
        wait_for_live_transport(&sock, &cx_sid).await;
        assert_eq!(
            session_status(&sock, hc_sid).await["transportKind"],
            "herdr"
        );
        assert_eq!(
            session_status(&sock, &cx_sid).await["transportKind"],
            "codex_queue"
        );
        // Recycled terminal MUST NOT re-attach across restart!
        assert_eq!(
            session_status(&sock, recycled_sid).await["hasLiveTransport"],
            false,
            "recycled Herdr terminal (created_ms mismatch) must fail closed on restart rehydration"
        );

        // Send DMs *after* restart with ZERO extra hook or MCP calls -> MUST deliver immediately!
        daemon
            .ingest_inbound(InboundItem {
                session_id: hc_sid.into(),
                origin_node: "rehydrate34@local".into(),
                item_id: "post-restart-hc-1".into(),
                source: "rehydrate34@local/lead".into(),
                text: "hello-rehydrated-herdr".into(),
                kind: MailboxKind::Message,
                trust_tier: GateTrustTier::SelfHost,
            })
            .await
            .unwrap();
        daemon
            .ingest_inbound(InboundItem {
                session_id: cx_sid.clone(),
                origin_node: "rehydrate34@local".into(),
                item_id: "post-restart-cx-1".into(),
                source: "rehydrate34@local/lead".into(),
                text: "hello-rehydrated-codex".into(),
                kind: MailboxKind::Message,
                trust_tier: GateTrustTier::SelfHost,
            })
            .await
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            let hc_ok = fs::read_to_string(&hc_send_log)
                .map(|s| s.contains("t9") && s.contains("<hyphae-inbox"))
                .unwrap_or(false);
            let cx_ok = fs::read_to_string(&cx_queue_log)
                .map(|s| s.contains(cx_uuid) && s.contains("<hyphae-inbox"))
                .unwrap_or(false);
            if hc_ok && cx_ok {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for post-restart Herdr & Codex delivery (hc_ok={hc_ok}, cx_ok={cx_ok})"
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        // Phase 3: Send 3 DMs to permanently dead `t-dead` and verify lazy hydration cooldown
        // bounds probes (no probe loop: 1 startup probe + at most 1 lazy probe = <= 2 total!).
        for i in 1..=3 {
            daemon
                .ingest_inbound(InboundItem {
                    session_id: dead_sid.into(),
                    origin_node: "rehydrate34@local".into(),
                    item_id: format!("dead-dm-{i}"),
                    source: "rehydrate34@local/lead".into(),
                    text: format!("ping-{i}"),
                    kind: MailboxKind::Message,
                    trust_tier: GateTrustTier::SelfHost,
                })
                .await
                .unwrap();
        }
        tokio::time::sleep(Duration::from_millis(120)).await;
        let dead_probes = fs::read_to_string(&hc_get_count)
            .map(|s| s.lines().count())
            .unwrap_or(0);
        assert!(
            dead_probes <= 2,
            "permanently dead Herdr target must be cooldown-bounded (expected <=2 probes, got {dead_probes})"
        );

        daemon.stop().await;
        node.shutdown();
    }

    // ------------------------------------------------------------------------
    // Issue #35: Interactive `"source": "cli"` attaches vs `"source": "exec"` refuses auto-attach
    // ------------------------------------------------------------------------
    #[tokio::test]
    async fn issue35_codex_queue_attaches_interactive_cli_but_refuses_non_interactive_exec() {
        let dir = TempDir::new().unwrap();
        let state_dir = dir.path().join("state");
        let codex_home = dir.path().join("codex-home");
        let sessions_dir = codex_home.join("sessions/2026/11/26");
        fs::create_dir_all(&sessions_dir).unwrap();

        let cli_uuid = "01a217e1-c5f7-7720-a22b-888b924cc351";
        let exec_uuid = "01a217e1-c5f7-7720-a22b-888b924cc352";

        fs::write(
            sessions_dir.join(format!("rollout-2026-11-26T12-00-00-{cli_uuid}.jsonl")),
            format!(
                "{{\"timestamp\":\"2026-11-26T12:00:00Z\",\"ordinal\":0,\"type\":\"session_meta\",\"payload\":{{\"id\":\"{cli_uuid}\",\"originator\":\"codex_cli_rs\",\"cli_version\":\"0.172.0\",\"source\":\"cli\"}}}}\n"
            ),
        )
        .unwrap();
        fs::write(
            sessions_dir.join(format!("rollout-2026-11-26T12-01-00-{exec_uuid}.jsonl")),
            format!(
                "{{\"timestamp\":\"2026-11-26T12:01:00Z\",\"ordinal\":0,\"type\":\"session_meta\",\"payload\":{{\"id\":\"{exec_uuid}\",\"originator\":\"codex_exec\",\"cli_version\":\"0.172.0\",\"source\":\"exec\"}}}}\n"
            ),
        )
        .unwrap();

        let queue_log = dir.path().join("codex_queue.log");
        let fake_codex = write_executable_script(
            dir.path(),
            "codex",
            &format!(
                r#"#!/bin/sh
set -eu
if [ "${{1:-}}" = "queue" ] && [ "${{2:-}}" = "--help" ]; then
  echo "Usage: codex queue"
  exit 0
fi
printf '%s\n' "$*" >> "{log}"
exit 0
"#,
                log = queue_log.display(),
            ),
        );

        let node = open_local_node("codex35@local", &state_dir);
        let daemon = LocalDaemon::start(
            Arc::clone(&node),
            None,
            LocalDaemonConfig {
                auto_detect_transports: true,
                herdr_bin: Some(dir.path().join("no-hc").to_string_lossy().to_string()),
                codex_bin: Some(fake_codex.to_string_lossy().to_string()),
                t3_default_base_dir: Some(dir.path().join("no-t3")),
                ..Default::default()
            },
        )
        .await
        .expect("start LocalDaemon");
        let sock = daemon.socket_path().to_path_buf();

        let mut mcp = TestMcpClient::spawn(McpOptions::new(sock.clone()));
        mcp.initialize().await;

        // 1. Non-interactive `codex exec` rollout (`"source": "exec"`) MUST refuse auto-attach!
        let pre_exec = run_hook_with_hints(
            &sock,
            HarnessKind::Codex,
            HookEvent::PreToolUse,
            json!({
                "thread_id": exec_uuid,
                "tool_name": "mcp__hyphae__hyp_mesh",
                "tool_use_id": "call-exec-35",
                "tool_input": { "action": "join", "handle": "cx-exec" }
            }),
            HookTransportHints {
                codex_home: Some(codex_home.display().to_string()),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(pre_exec, json!({}));
        // Finish the hook's rollout probe before the MCP connection triggers its
        // own probe with sparse hints. Both must retain the hook's Codex home.
        assert_eq!(
            session_status(&sock, &format!("codex:{exec_uuid}")).await["hasLiveTransport"],
            false
        );
        let (exec_txt, exec_err) = mcp
            .call_tool(
                "hyp_mesh",
                json!({ "action": "join", "handle": "cx-exec" }),
                Some(json!({ "callId": "call-exec-35" })),
            )
            .await;
        assert!(!exec_err, "{exec_txt}");
        let exec_val: Value = serde_json::from_str(&exec_txt).unwrap();
        assert_eq!(
            exec_val["hasLiveTransport"], false,
            "non-interactive codex exec rollout MUST NOT auto-attach codex_queue: {exec_val}"
        );
        assert_eq!(exec_val["transport"]["kind"], "none");

        // 2. Interactive Codex CLI rollout (`"source": "cli"`) MUST auto-attach cleanly!
        let pre_cli = run_hook_with_hints(
            &sock,
            HarnessKind::Codex,
            HookEvent::PreToolUse,
            json!({
                "thread_id": cli_uuid,
                "tool_name": "mcp__hyphae__hyp_mesh",
                "tool_use_id": "call-cli-35",
                "tool_input": { "action": "join", "handle": "cx-cli" }
            }),
            HookTransportHints {
                codex_home: Some(codex_home.display().to_string()),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(pre_cli, json!({}));
        let (cli_txt, cli_err) = mcp
            .call_tool(
                "hyp_mesh",
                json!({ "action": "join", "handle": "cx-cli" }),
                Some(json!({ "callId": "call-cli-35" })),
            )
            .await;
        assert!(!cli_err, "{cli_txt}");
        let cli_val: Value = serde_json::from_str(&cli_txt).unwrap();
        assert_eq!(cli_val["hasLiveTransport"], true, "{cli_val}");
        assert_eq!(cli_val["transport"]["kind"], "codex_queue");

        // Complete interactive Codex turn (`Stop` -> idle) so L2 push wake fires immediately on DM.
        let stop_cli = run_hook(
            &sock,
            HarnessKind::Codex,
            HookEvent::Stop,
            json!({ "thread_id": cli_uuid }),
        )
        .await;
        assert_eq!(stop_cli, json!({}));

        // 3. Inbound DM to `exec_uuid` NEVER calls `codex queue`, while `cli_uuid` DOES!
        daemon
            .ingest_inbound(InboundItem {
                session_id: format!("codex:{exec_uuid}"),
                origin_node: "codex35@local".into(),
                item_id: "exec-dm-1".into(),
                source: "codex35@local/ops".into(),
                text: "for-exec-resume".into(),
                kind: MailboxKind::Message,
                trust_tier: GateTrustTier::SelfHost,
            })
            .await
            .unwrap();
        daemon
            .ingest_inbound(InboundItem {
                session_id: format!("codex:{cli_uuid}"),
                origin_node: "codex35@local".into(),
                item_id: "cli-dm-1".into(),
                source: "codex35@local/ops".into(),
                text: "for-interactive-cli".into(),
                kind: MailboxKind::Message,
                trust_tier: GateTrustTier::SelfHost,
            })
            .await
            .unwrap();

        let deadline = Instant::now() + Duration::from_secs(3);
        let log_content = loop {
            if let Ok(s) = fs::read_to_string(&queue_log) {
                if s.contains(cli_uuid) {
                    break s;
                }
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for interactive Codex CLI wake"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        tokio::time::sleep(Duration::from_millis(80)).await;
        let final_log = fs::read_to_string(&queue_log).unwrap_or(log_content);
        assert!(final_log.contains(cli_uuid), "{final_log}");
        assert!(
            !final_log.contains(exec_uuid),
            "non-interactive codex exec thread MUST NEVER receive codex queue pushes:\n{final_log}"
        );

        mcp.close().await;
        daemon.stop().await;
        node.shutdown();
    }

    // ------------------------------------------------------------------------
    // Issue #36: Bare-shell `hyp mcp --backend herdr` fails closed with `herdr_bare_shell_rejected`
    // ------------------------------------------------------------------------
    #[tokio::test]
    async fn issue36_herdr_bare_shell_fails_closed_while_live_agent_enrolls_and_attaches() {
        let dir = TempDir::new().unwrap();
        let state_dir = dir.path().join("state");
        let send_log = dir.path().join("hc_send.log");

        let hc_bin = write_executable_script(
            dir.path(),
            "hc",
            &format!(
                r#"#!/bin/sh
set -eu
CMD="${{1:-}}"
case "$CMD" in
  get)
    TID="${{3:-}}"
    case "$TID" in
      t-bare-null)
        printf '%s\n' '{{"address":"t-bare-null","created_ms":1000,"pid":101,"state":"live","status":null}}'
        exit 0
        ;;
      t-bare-app-null)
        printf '%s\n' '{{"address":"t-bare-app-null","created_ms":1001,"pid":102,"state":"live","status":{{"app":null,"state":"idle"}}}}'
        exit 0
        ;;
      t-live)
        printf '%s\n' '{{"address":"t-live","created_ms":1002,"pid":103,"state":"live","status":{{"app":"claude","state":"idle"}}}}'
        exit 0
        ;;
      *)
        exit 1
        ;;
    esac
    ;;
  send)
    printf '%s\n' "$*" >> "{send_log}"
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
"#,
                send_log = send_log.display(),
            ),
        );

        let node = open_local_node("herdr36@local", &state_dir);
        let daemon = LocalDaemon::start(
            Arc::clone(&node),
            None,
            LocalDaemonConfig {
                auto_detect_transports: true,
                herdr_bin: Some(hc_bin.to_string_lossy().to_string()),
                t3_default_base_dir: Some(dir.path().join("no-t3")),
                ..Default::default()
            },
        )
        .await
        .expect("start LocalDaemon");
        let sock = daemon.socket_path().to_path_buf();

        // 1. Direct `session.register` and `session.start` with explicit `backend: "herdr"` on
        //    BOTH bare-shell shapes (`status: null` and `status.app: null`) fail closed!
        for (tid, sid) in [
            ("t-bare-null", "herdr:bare-reg-1"),
            ("t-bare-app-null", "herdr:bare-reg-2"),
        ] {
            let reg = daemon_rpc_async(
                &sock,
                &json!({
                    "type": "session.register",
                    "sessionId": sid,
                    "backend": "herdr",
                    "herdrTerminalId": tid
                }),
                Duration::from_secs(2),
            )
            .await;
            assert!(
                !reg.ok,
                "session.register(--backend herdr) on bare shell {tid} must fail closed: {reg:?}"
            );
            assert!(
                reg.error
                    .as_deref()
                    .is_some_and(|e| e.contains("bare shell")),
                "expected explicit bare-shell error for {tid}: {reg:?}"
            );

            let start = daemon_rpc_async(
                &sock,
                &json!({
                    "type": "session.start",
                    "sessionId": sid,
                    "backend": "herdr",
                    "herdrTerminalId": tid
                }),
                Duration::from_secs(2),
            )
            .await;
            assert!(
                !start.ok,
                "session.start(--backend herdr) on bare shell {tid} must fail closed: {start:?}"
            );
        }

        // 2. Full MCP `hyp_mesh(join)` with `--backend herdr --ephemeral` probing a bare shell
        //    (`status: null` and `status.app: null`) fails closed with `herdr_bare_shell_rejected`,
        //    enrolls ZERO handle, attaches ZERO transport, and sends ZERO bytes!
        for (tid, handle) in [
            ("t-bare-null", "bare-null-handle"),
            ("t-bare-app-null", "bare-app-null-handle"),
        ] {
            // Speak the exact `mcp.hello` + `tool.call` protocol on the Unix socket so we don't
            // mutate process-wide `HC_TERMINAL_ID` env across parallel tests.
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            use tokio::net::UnixStream;

            let stream = UnixStream::connect(&sock).await.unwrap();
            let (r, mut w) = stream.into_split();
            let mut lines = BufReader::new(r).lines();

            let hello = json!({
                "type": "mcp.hello",
                "backend": "herdr",
                "clientId": format!("ephem-{tid}"),
                "herdrTerminalId": tid
            });
            w.write_all(format!("{hello}\n").as_bytes()).await.unwrap();
            let call = json!({
                "type": "tool.call",
                "id": 1,
                "name": "hyp_mesh",
                "args": { "action": "join", "handle": handle }
            });
            w.write_all(format!("{call}\n").as_bytes()).await.unwrap();
            w.flush().await.unwrap();

            let resp_line = tokio::time::timeout(Duration::from_secs(5), lines.next_line())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let resp: Value = serde_json::from_str(&resp_line).unwrap();
            assert_eq!(
                resp["error"]["code"], "herdr_bare_shell_rejected",
                "expected herdr_bare_shell_rejected for bare shell {tid}, got: {resp}"
            );
            assert!(
                node.db()
                    .local()
                    .session_by_handle(handle)
                    .unwrap()
                    .is_none(),
                "rejected bare shell MUST NOT enroll handle '{handle}'"
            );
        }

        // 3. Live coding agent (`app: "claude"`) enrolls and attaches `HerdrTransport` cleanly!
        {
            use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
            use tokio::net::UnixStream;

            let stream = UnixStream::connect(&sock).await.unwrap();
            let (r, mut w) = stream.into_split();
            let mut lines = BufReader::new(r).lines();

            let hello = json!({
                "type": "mcp.hello",
                "backend": "herdr",
                "clientId": "ephem-live-1",
                "herdrTerminalId": "t-live"
            });
            w.write_all(format!("{hello}\n").as_bytes()).await.unwrap();
            let call = json!({
                "type": "tool.call",
                "id": 1,
                "name": "hyp_mesh",
                "args": { "action": "join", "handle": "live-claude" }
            });
            w.write_all(format!("{call}\n").as_bytes()).await.unwrap();
            w.flush().await.unwrap();

            let resp_line = tokio::time::timeout(Duration::from_secs(5), lines.next_line())
                .await
                .unwrap()
                .unwrap()
                .unwrap();
            let resp: Value = serde_json::from_str(&resp_line).unwrap();
            assert!(
                resp.get("error").is_none(),
                "live agent join failed: {resp}"
            );
            assert_eq!(resp["result"]["handle"], "live-claude");
            assert_eq!(resp["result"]["hasLiveTransport"], true);
            assert_eq!(resp["result"]["transport"]["kind"], "herdr");
        }

        // Verify ZERO bytes were ever sent to any bare shell!
        assert!(
            !send_log.exists(),
            "zero hc send invocations may occur for bare shells"
        );

        daemon.stop().await;
        node.shutdown();

        // 4. When `hc` binary is missing (unit-test environment), explicit `--backend herdr`
        //    must NOT falsely emit `herdr_bare_shell_rejected`!
        let no_hc_state = dir.path().join("state-no-hc");
        let node2 = open_local_node("herdr36nohc@local", &no_hc_state);
        let daemon2 = LocalDaemon::start(
            Arc::clone(&node2),
            None,
            LocalDaemonConfig {
                auto_detect_transports: true,
                herdr_bin: Some(dir.path().join("missing-hc").to_string_lossy().to_string()),
                t3_default_base_dir: Some(dir.path().join("no-t3-2")),
                ..Default::default()
            },
        )
        .await
        .expect("start daemon2");
        let sock2 = daemon2.socket_path().to_path_buf();
        let reg2 = daemon_rpc_async(
            &sock2,
            &json!({
                "type": "session.register",
                "sessionId": "herdr:no-hc-unit-test",
                "backend": "herdr",
                "herdrTerminalId": "t99"
            }),
            Duration::from_secs(2),
        )
        .await;
        assert!(
            reg2.ok,
            "missing hc binary must stay graceful (not bare-shell rejected): {reg2:?}"
        );
        daemon2.stop().await;
        node2.shutdown();
    }
}
