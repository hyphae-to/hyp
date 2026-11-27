//! End-to-end tests for the native Herdr (`hc`) [`PushTransport`].
//!
//! Cross-platform tests run on all OSes (including Windows). Real subprocess
//! E2E tests using a deterministic temporary `hc` executable shim run on Unix
//! via `#[cfg(unix)]` so Windows builds with zero warnings.

mod common;

use common::test_digest;

use std::time::Duration;

use hyp_harness::transport::herdr::{
    HerdrTarget, HerdrTransport, parse_herdr_get_output, parse_herdr_interrupt_stopped,
    probe_herdr_terminal, probe_herdr_terminal_with_timeout,
};
use hyp_harness::transport::{PushMode, PushOutcome, PushTransport};

#[test]
fn herdr_transport_metadata_and_trait_object_dispatch() {
    let mut target = HerdrTarget::new("t1");
    target.created_ms = Some(1_700_000_000_000);
    target.pid = Some(9876);
    target.app = Some("claude-code".into());
    let transport = HerdrTransport::new(target.clone());
    assert_eq!(transport.kind(), "herdr");
    assert!(transport.supports_interrupt());
    assert_eq!(transport.target(), &target);
    assert_eq!(transport.herdr_terminal_id(), Some("t1"));
    assert_eq!(transport.herdr_created_ms(), Some(1_700_000_000_000));

    let boxed: Box<dyn PushTransport> = Box::new(transport);
    assert_eq!(boxed.kind(), "herdr");
    assert!(boxed.supports_interrupt());
    assert_eq!(boxed.herdr_terminal_id(), Some("t1"));
    assert_eq!(boxed.herdr_created_ms(), Some(1_700_000_000_000));
    let meta = boxed.target_metadata();
    assert_eq!(meta["herdrTerminalId"], "t1");
    assert_eq!(meta["herdrCreatedMs"], 1_700_000_000_000i64);
    assert_eq!(meta["herdrPid"], 9876);
    assert_eq!(meta["herdrApp"], "claude-code");
}

#[test]
fn herdr_target_serde_and_both_json_shapes() {
    let default_target: HerdrTarget =
        serde_json::from_str(r#"{"terminalId":"t9"}"#).expect("minimal target json");
    assert_eq!(default_target.bin, "hc");
    assert_eq!(default_target.created_ms, None);
    assert_eq!(default_target.pid, None);
    assert_eq!(default_target.app, None);

    let nested = parse_herdr_get_output(
        r#"{"address":"t9","created_ms":1700000000000,"pid":3210,"state":"live","status":{"app":"codex","state":"idle"}}"#,
    )
    .expect("nested v0.1 shape");
    assert_eq!(nested.app.as_deref(), Some("codex"));
    assert_eq!(nested.agent_state, "idle");

    let flat = parse_herdr_get_output(
        r#"{"address":"t9","created_ms":1700000000000,"pid":3210,"state":"live","status":"idle","agent":"claude-code"}"#,
    )
    .expect("flat hc ls shape");
    assert_eq!(flat.app.as_deref(), Some("claude-code"));
    assert_eq!(flat.agent_state, "idle");

    let pinned_claude = HerdrTarget {
        terminal_id: "t9".into(),
        created_ms: Some(1_700_000_000_000),
        pid: Some(3210),
        app: Some("claude-code".into()),
        bin: "hc".into(),
    };
    assert!(pinned_claude.matches_live_terminal(&flat));
    assert!(!pinned_claude.matches_live_terminal(&nested));

    assert!(parse_herdr_interrupt_stopped(r#"{"outcome":"stopped"}"#));
    assert!(!parse_herdr_interrupt_stopped(r#"{"outcome":"aborted"}"#));
}

#[tokio::test]
async fn missing_hc_binary_holds_and_probe_returns_none() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing_bin = dir.path().join("definitely-missing-hc-bin");
    let missing_str = missing_bin.to_string_lossy().to_string();

    assert!(probe_herdr_terminal(&missing_str, "t3").await.is_none());
    assert!(
        probe_herdr_terminal_with_timeout(&missing_str, "t3", Duration::from_millis(500))
            .await
            .is_none()
    );

    let transport = HerdrTransport::new(HerdrTarget::new("t3").with_bin(missing_str))
        .with_timeouts(
            Duration::from_millis(500),
            Duration::from_millis(500),
            Duration::from_millis(500),
        );
    let outcome = transport.deliver(&test_digest(), PushMode::Queue).await;
    assert_eq!(outcome, PushOutcome::hold("herdr_binary_missing"));
}

#[tokio::test]
async fn invalid_terminal_id_fails_closed_without_spawning() {
    for bad_id in ["", "--json", "-t3", "t3 bad", "t3\nnewline"] {
        let transport = HerdrTransport::new(HerdrTarget::new(bad_id).with_bin("hc"));
        assert_eq!(
            transport.deliver(&test_digest(), PushMode::Interrupt).await,
            PushOutcome::hold("herdr_target_unavailable"),
            "bad terminal_id {bad_id:?} must fail closed"
        );
        assert!(probe_herdr_terminal("hc", bad_id).await.is_none());
    }
}

#[cfg(unix)]
mod unix_e2e {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::time::Instant;

    use serde_json::json;

    use super::*;

    /// Deterministic fake `hc` CLI harness backed by an isolated `TempDir`.
    ///
    /// Each invocation records every argument byte-for-byte in `calls/call_<n>_arg_<m>.txt`
    /// and reads its scripted response from per-subcommand files (`get_1.*`, `get_2.*`,
    /// `interrupt.*`, `send.*`) with zero shared global state.
    struct FakeHc {
        _dir: tempfile::TempDir,
        bin_path: PathBuf,
        state_dir: PathBuf,
        calls_dir: PathBuf,
    }

    impl FakeHc {
        fn new() -> Self {
            let dir = tempfile::tempdir().expect("tempdir");
            let state_dir = dir.path().join("state");
            let calls_dir = dir.path().join("calls");
            fs::create_dir_all(&state_dir).unwrap();
            fs::create_dir_all(&calls_dir).unwrap();

            let script = format!(
                r#"#!/bin/sh
set -eu
STATE_DIR="{state}"
CALLS_DIR="{calls}"

# Increment global call counter
N=0
if [ -f "$CALLS_DIR/count" ]; then
  N=$(cat "$CALLS_DIR/count")
fi
N=$((N + 1))
printf '%s' "$N" > "$CALLS_DIR/count"

# Record every argument verbatim (preserves newlines, quotes, $HOME, leading dashes)
I=0
for arg in "$@"; do
  printf '%s' "$arg" > "$CALLS_DIR/call_${{N}}_arg_${{I}}.txt"
  I=$((I + 1))
done
printf '%s' "$I" > "$CALLS_DIR/call_${{N}}_argc"

CMD="${{1:-}}"
case "$CMD" in
  get)
    GN=0
    if [ -f "$STATE_DIR/get_count" ]; then
      GN=$(cat "$STATE_DIR/get_count")
    fi
    GN=$((GN + 1))
    printf '%s' "$GN" > "$STATE_DIR/get_count"

    if [ -f "$STATE_DIR/hang_get" ]; then
      exec sleep 30
    fi
    if [ -f "$STATE_DIR/oversized_get" ]; then
      # Emit ~300 KiB of data (> 256 KiB cap)
      dd if=/dev/zero bs=1024 count=300 2>/dev/null | tr '\0' 'a'
      exit 0
    fi
    if [ -f "$STATE_DIR/get_${{GN}}.stdout" ]; then
      cat "$STATE_DIR/get_${{GN}}.stdout"
    elif [ -f "$STATE_DIR/get.stdout" ]; then
      cat "$STATE_DIR/get.stdout"
    fi
    if [ -f "$STATE_DIR/get_${{GN}}.code" ]; then
      exit "$(cat "$STATE_DIR/get_${{GN}}.code")"
    elif [ -f "$STATE_DIR/get.code" ]; then
      exit "$(cat "$STATE_DIR/get.code")"
    fi
    exit 0
    ;;
  interrupt)
    if [ -f "$STATE_DIR/hang_interrupt" ]; then
      exec sleep 30
    fi
    if [ -f "$STATE_DIR/interrupt.stdout" ]; then
      cat "$STATE_DIR/interrupt.stdout"
    fi
    if [ -f "$STATE_DIR/interrupt.code" ]; then
      exit "$(cat "$STATE_DIR/interrupt.code")"
    fi
    exit 0
    ;;
  send)
    if [ -f "$STATE_DIR/hang_send" ]; then
      exec sleep 30
    fi
    if [ -f "$STATE_DIR/send.stdout" ]; then
      cat "$STATE_DIR/send.stdout"
    fi
    if [ -f "$STATE_DIR/send.code" ]; then
      exit "$(cat "$STATE_DIR/send.code")"
    fi
    exit 0
    ;;
  *)
    printf 'unexpected subcommand: %s\n' "$CMD" >&2
    exit 64
    ;;
esac
"#,
                state = state_dir.display(),
                calls = calls_dir.display(),
            );

            // Atomic write + chmod + rename avoids ETXTBSY on Linux.
            let tmp_path = dir.path().join("hc.tmp");
            let bin_path = dir.path().join("hc");
            fs::write(&tmp_path, script).unwrap();
            fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o755)).unwrap();
            fs::rename(&tmp_path, &bin_path).unwrap();

            Self {
                _dir: dir,
                bin_path,
                state_dir,
                calls_dir,
            }
        }

        fn bin(&self) -> String {
            self.bin_path.to_string_lossy().to_string()
        }

        fn set_get_default(&self, code: i32, stdout: &str) {
            fs::write(self.state_dir.join("get.stdout"), stdout).unwrap();
            fs::write(self.state_dir.join("get.code"), code.to_string()).unwrap();
        }

        fn set_get_seq(&self, seq: usize, code: i32, stdout: &str) {
            fs::write(self.state_dir.join(format!("get_{seq}.stdout")), stdout).unwrap();
            fs::write(
                self.state_dir.join(format!("get_{seq}.code")),
                code.to_string(),
            )
            .unwrap();
        }

        fn set_interrupt(&self, code: i32, stdout: &str) {
            fs::write(self.state_dir.join("interrupt.stdout"), stdout).unwrap();
            fs::write(self.state_dir.join("interrupt.code"), code.to_string()).unwrap();
        }

        fn set_send(&self, code: i32, stdout: &str) {
            fs::write(self.state_dir.join("send.stdout"), stdout).unwrap();
            fs::write(self.state_dir.join("send.code"), code.to_string()).unwrap();
        }

        fn set_flag(&self, name: &str) {
            fs::write(self.state_dir.join(name), "1").unwrap();
        }

        fn clear_flag(&self, name: &str) {
            let _ = fs::remove_file(self.state_dir.join(name));
        }

        fn recorded_calls(&self) -> Vec<Vec<String>> {
            let count_path = self.calls_dir.join("count");
            if !count_path.exists() {
                return Vec::new();
            }
            let count: usize = fs::read_to_string(count_path)
                .unwrap()
                .trim()
                .parse()
                .unwrap();
            let mut all = Vec::with_capacity(count);
            for n in 1..=count {
                let argc: usize = fs::read_to_string(self.calls_dir.join(format!("call_{n}_argc")))
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                let mut args = Vec::with_capacity(argc);
                for i in 0..argc {
                    let arg =
                        fs::read_to_string(self.calls_dir.join(format!("call_{n}_arg_{i}.txt")))
                            .unwrap();
                    args.push(arg);
                }
                all.push(args);
            }
            all
        }

        fn reset_calls(&self) {
            remove_dir_contents(&self.calls_dir);
            let _ = fs::remove_file(self.state_dir.join("get_count"));
        }
    }

    #[tokio::test]
    async fn interrupt_burst_preserves_inbox_read_and_wakes_for_late_arrival() {
        use std::sync::Arc;

        use common::{TestMcpClient, run_hook};
        use hyp_crypto::SecretBackend;
        use hyp_harness::daemon::{InboundItem, LocalDaemon, LocalDaemonConfig};
        use hyp_harness::hooks::HookEvent;
        use hyp_harness::mcp::McpOptions;
        use hyp_harness::protocol::HarnessKind;
        use hyp_node::delivery::{DeliveryRule, DeliveryUrgency};
        use hyp_node::engine::{NodeConfig, UnifiedNode};
        use hyp_node::gates::TrustTier as GateTrustTier;
        use hyp_proto::address::NodeId;
        use hyp_store::MailboxKind;

        const RAW_SESSION: &str = "burst";
        const SESSION: &str = "claude:burst";
        const HOOK_GRACE: Duration = Duration::from_millis(60);
        const COOLDOWN: Duration = Duration::from_millis(800);

        hyp_harness::enable_test_env_isolation();
        let dir = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::local(NodeId::new("burst@local").unwrap(), dir.path());
        config.secret_backend = Some(SecretBackend::File);
        let node = UnifiedNode::open(config).unwrap();
        node.register_session(SESSION, r#"{"kind":"claude"}"#)
            .unwrap();
        let daemon = LocalDaemon::start(
            Arc::clone(&node),
            None,
            LocalDaemonConfig {
                interrupt_hook_grace: HOOK_GRACE,
                interrupt_wake_cooldown: COOLDOWN,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        // Distinct sources keep per-source burst demotion out of the scenario.
        {
            let db = node.db();
            let mut policy = daemon.delivery().policy(&db, SESSION).unwrap();
            for source in ["first", "second", "third", "late", "isolated"] {
                policy.upsert_rule(DeliveryRule::new(
                    format!("peer@net/{source}"),
                    DeliveryUrgency::Interrupt,
                ));
            }
            daemon.delivery().set_policy(&db, SESSION, policy).unwrap();
        }

        let hc = FakeHc::new();
        let state = |state: &str| {
            json!({
                "address": "burst-terminal",
                "pid": 3210,
                "state": "live",
                "status": { "app": "claude-code", "state": state }
            })
            .to_string()
        };
        hc.set_get_default(0, &state("working"));
        for recheck in [2, 4, 6] {
            hc.set_get_seq(recheck, 0, &state("idle"));
        }
        hc.set_interrupt(0, r#"{"outcome":"stopped"}"#);
        hc.set_send(0, r#"{"outcome":"sent"}"#);
        daemon.register_session_transport(
            SESSION,
            Arc::new(HerdrTransport::new(
                HerdrTarget::new("burst-terminal").with_bin(hc.bin()),
            )),
        );

        let sock = daemon.socket_path();
        let mut opts = McpOptions::new(sock.to_owned());
        opts.backend = Some(HarnessKind::Claude);
        let mut mcp = TestMcpClient::spawn(opts);
        mcp.initialize().await;

        let ingest = |source: &'static str| {
            let daemon = &daemon;
            async move {
                assert_eq!(
                    daemon
                        .ingest_inbound(InboundItem {
                            session_id: SESSION.into(),
                            origin_node: "peer@net".into(),
                            item_id: source.into(),
                            source: format!("peer@net/{source}"),
                            text: format!("body-{source}"),
                            kind: MailboxKind::Message,
                            trust_tier: GateTrustTier::Peer,
                        })
                        .await
                        .unwrap(),
                    Some(DeliveryUrgency::Interrupt)
                );
            }
        };
        let wait_until_notified = || {
            let node = &node;
            async move {
                tokio::time::timeout(Duration::from_secs(4), async {
                    while node.db().local().unnotified_count(SESSION).unwrap() != 0 {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                })
                .await
                .expect("pending receipt should get a push wake");
            }
        };
        let count_interrupts = || {
            hc.recorded_calls()
                .iter()
                .filter(|args| args[0] == "interrupt")
                .count()
        };

        run_hook(
            sock,
            HarnessKind::Claude,
            HookEvent::PreInvocation,
            json!({
                "session_id": RAW_SESSION
            }),
        )
        .await;
        ingest("first").await;
        tokio::time::timeout(COOLDOWN, wait_until_notified())
            .await
            .expect("the first interrupt should only wait for hook grace");
        assert_eq!(count_interrupts(), 1);

        // Start the real Claude tool lifecycle, then deliver the burst before the MCP read.
        // Hold at this boundary past hook grace, while the first wake's cooldown is active.
        let arguments = json!({ "state": "unread", "ack": true });
        assert_eq!(
            run_hook(
                sock,
                HarnessKind::Claude,
                HookEvent::PreToolUse,
                json!({
                    "session_id": RAW_SESSION,
                    "tool_use_id": "toolu_burst_read",
                    "tool_name": "mcp__hyphae__hyp_inbox",
                    "tool_input": arguments
                })
            )
            .await,
            json!({})
        );
        ingest("second").await;
        ingest("third").await;
        tokio::time::sleep(HOOK_GRACE * 3).await;
        assert_eq!(
            count_interrupts(),
            1,
            "repeat wake could cancel the inbox tool"
        );
        let (snapshot, is_error) = mcp
            .call_tool(
                "hyp_inbox",
                arguments,
                Some(json!({ "claudecode/toolUseId": "toolu_burst_read" })),
            )
            .await;
        assert!(!is_error, "{snapshot}");
        for source in ["first", "second", "third"] {
            assert!(snapshot.contains(&format!("body-{source}")), "{snapshot}");
        }
        assert_eq!(node.db().local().pending_count(SESSION).unwrap(), 0);

        assert_eq!(
            run_hook(
                sock,
                HarnessKind::Claude,
                HookEvent::PostToolUse,
                json!({
                    "session_id": RAW_SESSION,
                    "tool_use_id": "toolu_burst_read",
                    "tool_name": "mcp__hyphae__hyp_inbox",
                })
            )
            .await,
            json!({})
        );
        ingest("late").await;
        assert_eq!(node.db().local().unnotified_count(SESSION).unwrap(), 1);
        assert_eq!(count_interrupts(), 1);
        wait_until_notified().await;
        assert_eq!(
            count_interrupts(),
            2,
            "late receipt needs a wake without new traffic"
        );
        let (late, is_error) = mcp
            .call_verified_claude(
                sock,
                RAW_SESSION,
                "hyp_inbox",
                json!({ "state": "unread", "ack": true }),
            )
            .await;
        assert!(!is_error && late.contains("body-late"), "{late}");

        tokio::time::sleep(COOLDOWN).await;
        ingest("isolated").await;
        tokio::time::timeout(COOLDOWN, wait_until_notified())
            .await
            .expect("the next isolated interrupt should only wait for hook grace");
        assert_eq!(count_interrupts(), 3);
        mcp.close().await;
        daemon.shutdown();
    }

    fn remove_dir_contents(dir: &Path) {
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let _ = fs::remove_file(entry.path());
            }
        }
    }

    fn nested_json(address: &str, created_ms: i64, pid: u64, app: &str, state: &str) -> String {
        json!({
            "address": address,
            "created_ms": created_ms,
            "pid": pid,
            "state": "live",
            "status": {
                "app": app,
                "state": state,
            }
        })
        .to_string()
    }

    fn flat_json(address: &str, created_ms: i64, pid: u64, agent: &str, status: &str) -> String {
        json!({
            "address": address,
            "created_ms": created_ms,
            "pid": pid,
            "state": "live",
            "status": status,
            "agent": agent,
        })
        .to_string()
    }

    #[tokio::test]
    async fn e2e_probe_pins_created_ms_pid_app_for_both_json_shapes() {
        let hc = FakeHc::new();

        // 1. Nested v0.1 shape
        hc.set_get_default(
            0,
            &nested_json("t3", 1_710_000_000_000, 4242, "codex", "idle"),
        );
        let target = probe_herdr_terminal(&hc.bin(), "t3")
            .await
            .expect("probe must capture nested live terminal");
        assert_eq!(
            target,
            HerdrTarget {
                terminal_id: "t3".into(),
                created_ms: Some(1_710_000_000_000),
                pid: Some(4242),
                app: Some("codex".into()),
                bin: hc.bin(),
            }
        );
        assert_eq!(hc.recorded_calls(), vec![vec!["get", "--json", "t3"]]);

        // 2. Flat `hc ls --json` shape (`status: "idle"` + `agent: "claude-code"`)
        hc.reset_calls();
        hc.set_get_default(
            0,
            &flat_json("t8", 1_720_000_000_000, 9001, "claude-code", "idle"),
        );
        let flat_target = probe_herdr_terminal(&hc.bin(), "t8")
            .await
            .expect("probe must capture flat live terminal");
        assert_eq!(
            flat_target,
            HerdrTarget {
                terminal_id: "t8".into(),
                created_ms: Some(1_720_000_000_000),
                pid: Some(9001),
                app: Some("claude-code".into()),
                bin: hc.bin(),
            }
        );

        // 3. Non-live terminal must not probe
        hc.set_get_default(
            0,
            &json!({
                "address": "t8",
                "created_ms": 1_720_000_000_000_i64,
                "pid": 9001,
                "state": "exited",
                "status": "idle",
                "agent": "claude-code"
            })
            .to_string(),
        );
        assert!(probe_herdr_terminal(&hc.bin(), "t8").await.is_none());

        // 4. Address mismatch must not probe
        hc.set_get_default(0, &nested_json("t9", 1, 2, "codex", "idle"));
        assert!(probe_herdr_terminal(&hc.bin(), "t8").await.is_none());
    }

    #[tokio::test]
    async fn e2e_idle_queue_passes_if_idle_and_preserves_message_verbatim() {
        let hc = FakeHc::new();
        hc.set_get_default(0, &nested_json("t3", 100, 4242, "codex", "idle"));
        hc.set_send(0, r#"{"started":false}"#);

        let target = probe_herdr_terminal(&hc.bin(), "t3").await.unwrap();
        hc.reset_calls();

        let transport = HerdrTransport::new(target);
        let payload =
            crate::common::source_digest(hyp_store::MailboxKind::Message, "peer@box/dev & ops");
        let outcome = transport.deliver(&payload, PushMode::Queue).await;

        assert_eq!(outcome, PushOutcome::Delivered);
        assert_eq!(
            hc.recorded_calls(),
            vec![
                vec!["get", "--json", "t3"],
                vec!["send", "--json", "--if", "idle", "t3", payload.as_str()],
            ]
        );
    }

    #[tokio::test]
    async fn e2e_done_queue_omits_if_idle_and_delivers() {
        let hc = FakeHc::new();
        hc.set_get_default(0, &nested_json("t3", 100, 4242, "codex", "done"));
        hc.set_send(0, r#"{"started":true}"#);

        let target = probe_herdr_terminal(&hc.bin(), "t3").await.unwrap();
        hc.reset_calls();

        let transport = HerdrTransport::new(target);
        let outcome = transport.deliver(&test_digest(), PushMode::Queue).await;

        assert_eq!(outcome, PushOutcome::Delivered);
        assert_eq!(
            hc.recorded_calls(),
            vec![
                vec!["get", "--json", "t3"],
                vec!["send", "--json", "t3", test_digest().as_str()],
            ]
        );
    }

    #[tokio::test]
    async fn e2e_working_queue_holds_and_never_calls_interrupt_or_send() {
        let hc = FakeHc::new();
        hc.set_get_default(0, &nested_json("t3", 100, 4242, "codex", "working"));
        hc.set_interrupt(0, r#"{"outcome":"stopped"}"#);
        hc.set_send(0, r#"{}"#);

        let target = probe_herdr_terminal(&hc.bin(), "t3").await.unwrap();
        hc.reset_calls();

        let transport = HerdrTransport::new(target);
        let outcome = transport.deliver(&test_digest(), PushMode::Queue).await;

        assert_eq!(outcome, PushOutcome::hold("herdr_working"));
        assert_eq!(hc.recorded_calls(), vec![vec!["get", "--json", "t3"]]);
    }

    #[tokio::test]
    async fn e2e_working_interrupt_stops_rechecks_and_delivers_for_idle_and_done() {
        let hc = FakeHc::new();
        hc.set_get_seq(1, 0, &nested_json("t3", 100, 4242, "codex", "working"));
        hc.set_get_seq(2, 0, &nested_json("t3", 100, 4242, "codex", "idle"));
        hc.set_interrupt(0, r#"{"outcome":"stopped"}"#);
        hc.set_send(0, r#"{"started":false}"#);

        let target = HerdrTarget {
            terminal_id: "t3".into(),
            created_ms: Some(100),
            pid: Some(4242),
            app: Some("codex".into()),
            bin: hc.bin(),
        };
        let transport = HerdrTransport::new(target.clone());
        let outcome = transport.deliver(&test_digest(), PushMode::Interrupt).await;

        assert_eq!(outcome, PushOutcome::Delivered);
        assert_eq!(
            hc.recorded_calls(),
            vec![
                vec!["get", "--json", "t3"],
                vec!["interrupt", "--json", "--timeout", "8", "t3"],
                vec!["get", "--json", "t3"],
                vec![
                    "send",
                    "--json",
                    "--if",
                    "idle",
                    "t3",
                    test_digest().as_str()
                ],
            ]
        );

        // Post-interrupt transition to `done` omits `--if idle`.
        hc.reset_calls();
        hc.set_get_seq(1, 0, &nested_json("t3", 100, 4242, "codex", "working"));
        hc.set_get_seq(2, 0, &nested_json("t3", 100, 4242, "codex", "done"));
        let outcome_done = transport.deliver(&test_digest(), PushMode::Interrupt).await;
        assert_eq!(outcome_done, PushOutcome::Delivered);
        assert_eq!(
            hc.recorded_calls(),
            vec![
                vec!["get", "--json", "t3"],
                vec!["interrupt", "--json", "--timeout", "8", "t3"],
                vec!["get", "--json", "t3"],
                vec!["send", "--json", "t3", test_digest().as_str()],
            ]
        );
    }

    #[tokio::test]
    async fn e2e_working_interrupt_unknown_outcome_and_not_ready_cases() {
        let hc = FakeHc::new();
        let target = HerdrTarget {
            terminal_id: "t3".into(),
            created_ms: Some(100),
            pid: Some(4242),
            app: Some("codex".into()),
            bin: hc.bin(),
        };
        let transport = HerdrTransport::new(target);

        // 1. Exit 0 but outcome != "stopped" -> Reject("herdr_interrupt_outcome_unknown")
        hc.set_get_default(0, &nested_json("t3", 100, 4242, "codex", "working"));
        hc.set_interrupt(0, r#"{"outcome":"timeout"}"#);
        let outcome = transport.deliver(&test_digest(), PushMode::Interrupt).await;
        assert_eq!(
            outcome,
            PushOutcome::reject("herdr_interrupt_outcome_unknown")
        );
        assert_eq!(
            hc.recorded_calls(),
            vec![
                vec!["get", "--json", "t3"],
                vec!["interrupt", "--json", "--timeout", "8", "t3"],
            ]
        );

        // 2. Non-zero exit even with outcome == "stopped" -> Reject("herdr_interrupt_outcome_unknown")
        hc.reset_calls();
        hc.set_interrupt(1, r#"{"outcome":"stopped"}"#);
        let outcome = transport.deliver(&test_digest(), PushMode::Interrupt).await;
        assert_eq!(
            outcome,
            PushOutcome::reject("herdr_interrupt_outcome_unknown")
        );
        assert_eq!(hc.recorded_calls().len(), 2);

        // 3. Interrupt stopped, but post-interrupt `get` still shows `working` -> hold_interrupted("herdr_agent_not_ready")
        hc.reset_calls();
        hc.set_interrupt(0, r#"{"outcome":"stopped"}"#);
        hc.set_get_seq(1, 0, &nested_json("t3", 100, 4242, "codex", "working"));
        hc.set_get_seq(2, 0, &nested_json("t3", 100, 4242, "codex", "working"));
        let outcome = transport.deliver(&test_digest(), PushMode::Interrupt).await;
        assert_eq!(
            outcome,
            PushOutcome::hold_interrupted("herdr_agent_not_ready")
        );
        assert_eq!(
            hc.recorded_calls(),
            vec![
                vec!["get", "--json", "t3"],
                vec!["interrupt", "--json", "--timeout", "8", "t3"],
                vec!["get", "--json", "t3"],
            ]
        );
    }

    #[tokio::test]
    async fn e2e_send_guard_refused_codes_9_and_10_and_unknown_send_errors() {
        let hc = FakeHc::new();
        let target = HerdrTarget {
            terminal_id: "t3".into(),
            created_ms: Some(100),
            pid: Some(4242),
            app: Some("codex".into()),
            bin: hc.bin(),
        };
        let transport = HerdrTransport::new(target);

        // Exit 9 without interrupt -> Hold { interrupted: false }
        hc.set_get_default(0, &nested_json("t3", 100, 4242, "codex", "idle"));
        hc.set_send(9, r#"{"error":"guard_refused"}"#);
        assert_eq!(
            transport.deliver(&test_digest(), PushMode::Queue).await,
            PushOutcome::hold("herdr_send_guard_refused")
        );

        // Exit 10 without interrupt -> Hold { interrupted: false }
        hc.set_send(10, r#"{"error":"draft_in_progress"}"#);
        assert_eq!(
            transport.deliver(&test_digest(), PushMode::Queue).await,
            PushOutcome::hold("herdr_send_guard_refused")
        );

        // Exit 9 after interrupt -> Hold { interrupted: true }
        hc.reset_calls();
        hc.set_get_seq(1, 0, &nested_json("t3", 100, 4242, "codex", "working"));
        hc.set_get_seq(2, 0, &nested_json("t3", 100, 4242, "codex", "idle"));
        hc.set_interrupt(0, r#"{"outcome":"stopped"}"#);
        hc.set_send(9, r#"{}"#);
        assert_eq!(
            transport.deliver(&test_digest(), PushMode::Interrupt).await,
            PushOutcome::hold_interrupted("herdr_send_guard_refused")
        );

        // Exit 10 after interrupt -> Hold { interrupted: true }
        hc.reset_calls();
        hc.set_send(10, r#"{}"#);
        assert_eq!(
            transport.deliver(&test_digest(), PushMode::Interrupt).await,
            PushOutcome::hold_interrupted("herdr_send_guard_refused")
        );

        // Non-9/10 non-zero exit (e.g. 2) -> Reject with accurate `interrupted` bit
        hc.reset_calls();
        hc.set_send(2, r#"{}"#);
        assert_eq!(
            transport.deliver(&test_digest(), PushMode::Interrupt).await,
            PushOutcome::Reject {
                reason: "herdr_send_outcome_unknown".into(),
                interrupted: true,
            }
        );

        hc.reset_calls();
        hc.set_get_seq(1, 0, &nested_json("t3", 100, 4242, "codex", "idle"));
        assert_eq!(
            transport.deliver(&test_digest(), PushMode::Queue).await,
            PushOutcome::Reject {
                reason: "herdr_send_outcome_unknown".into(),
                interrupted: false,
            }
        );
    }

    #[tokio::test]
    async fn e2e_recycled_pid_created_ms_or_app_mismatch_never_delivers() {
        let hc = FakeHc::new();
        hc.set_send(0, r#"{}"#);
        hc.set_interrupt(0, r#"{"outcome":"stopped"}"#);

        let pinned = HerdrTarget {
            terminal_id: "t3".into(),
            created_ms: Some(100),
            pid: Some(4242),
            app: Some("codex".into()),
            bin: hc.bin(),
        };
        let transport = HerdrTransport::new(pinned);

        // 1. Recycled PID
        hc.set_get_default(0, &nested_json("t3", 100, 9999, "codex", "idle"));
        assert_eq!(
            transport.deliver(&test_digest(), PushMode::Interrupt).await,
            PushOutcome::hold("herdr_target_unavailable")
        );
        assert_eq!(hc.recorded_calls(), vec![vec!["get", "--json", "t3"]]);

        // 2. Recycled created_ms
        hc.reset_calls();
        hc.set_get_default(0, &nested_json("t3", 101, 4242, "codex", "idle"));
        assert_eq!(
            transport.deliver(&test_digest(), PushMode::Interrupt).await,
            PushOutcome::hold("herdr_target_unavailable")
        );
        assert_eq!(hc.recorded_calls(), vec![vec!["get", "--json", "t3"]]);

        // 3. Different app running in recycled terminal
        hc.reset_calls();
        hc.set_get_default(0, &nested_json("t3", 100, 4242, "vim", "idle"));
        assert_eq!(
            transport.deliver(&test_digest(), PushMode::Interrupt).await,
            PushOutcome::hold("herdr_target_unavailable")
        );
        assert_eq!(hc.recorded_calls(), vec![vec!["get", "--json", "t3"]]);

        // 4. Terminal recycled *between* `interrupt` and re-check `get` -> never calls `send`
        hc.reset_calls();
        hc.set_get_seq(1, 0, &nested_json("t3", 100, 4242, "codex", "working"));
        hc.set_get_seq(2, 0, &nested_json("t3", 100, 9999, "codex", "idle"));
        assert_eq!(
            transport.deliver(&test_digest(), PushMode::Interrupt).await,
            PushOutcome::hold_interrupted("herdr_agent_not_ready")
        );
        assert_eq!(
            hc.recorded_calls(),
            vec![
                vec!["get", "--json", "t3"],
                vec!["interrupt", "--json", "--timeout", "8", "t3"],
                vec!["get", "--json", "t3"],
            ]
        );
    }

    #[tokio::test]
    async fn e2e_flat_status_and_agent_shape_full_delivery_cycle() {
        let hc = FakeHc::new();
        hc.set_get_default(0, &flat_json("t5", 5000, 7777, "claude-code", "idle"));
        hc.set_send(0, r#"{}"#);
        hc.set_interrupt(0, r#"{"outcome":"stopped"}"#);

        let pinned = probe_herdr_terminal(&hc.bin(), "t5")
            .await
            .expect("flat probe succeeds");
        assert_eq!(pinned.app.as_deref(), Some("claude-code"));

        // Queue while idle
        hc.reset_calls();
        let transport = HerdrTransport::new(pinned);
        assert_eq!(
            transport.deliver(&test_digest(), PushMode::Queue).await,
            PushOutcome::Delivered
        );
        assert_eq!(
            hc.recorded_calls(),
            vec![
                vec!["get", "--json", "t5"],
                vec![
                    "send",
                    "--json",
                    "--if",
                    "idle",
                    "t5",
                    test_digest().as_str()
                ],
            ]
        );

        // Interrupt while working -> idle
        hc.reset_calls();
        hc.set_get_seq(1, 0, &flat_json("t5", 5000, 7777, "claude-code", "working"));
        hc.set_get_seq(2, 0, &flat_json("t5", 5000, 7777, "claude-code", "idle"));
        assert_eq!(
            transport.deliver(&test_digest(), PushMode::Interrupt).await,
            PushOutcome::Delivered
        );
        assert_eq!(
            hc.recorded_calls(),
            vec![
                vec!["get", "--json", "t5"],
                vec!["interrupt", "--json", "--timeout", "8", "t5"],
                vec!["get", "--json", "t5"],
                vec![
                    "send",
                    "--json",
                    "--if",
                    "idle",
                    "t5",
                    test_digest().as_str()
                ],
            ]
        );
    }

    #[tokio::test]
    async fn e2e_unknown_agent_state_holds_with_state_reason() {
        let hc = FakeHc::new();
        hc.set_get_default(0, &nested_json("t3", 100, 4242, "codex", "permission"));

        let transport = HerdrTransport::new(HerdrTarget {
            terminal_id: "t3".into(),
            created_ms: Some(100),
            pid: Some(4242),
            app: Some("codex".into()),
            bin: hc.bin(),
        });

        for mode in [PushMode::Queue, PushMode::Interrupt] {
            hc.reset_calls();
            assert_eq!(
                transport.deliver(&test_digest(), mode).await,
                PushOutcome::hold("herdr_permission")
            );
            assert_eq!(hc.recorded_calls(), vec![vec!["get", "--json", "t3"]]);
        }
    }

    #[tokio::test]
    async fn e2e_timeouts_kill_hanging_children_and_fail_closed() {
        let hc = FakeHc::new();
        let target = HerdrTarget {
            terminal_id: "t3".into(),
            created_ms: Some(100),
            pid: Some(4242),
            app: Some("codex".into()),
            bin: hc.bin(),
        };
        let short = Duration::from_millis(250);
        let ok = Duration::from_secs(3);

        // 1. Hanging `get`
        let transport = HerdrTransport::new(target.clone()).with_timeouts(short, ok, ok);
        hc.set_flag("hang_get");
        let start = Instant::now();
        assert_eq!(
            transport.deliver(&test_digest(), PushMode::Queue).await,
            PushOutcome::hold("herdr_target_unavailable")
        );
        assert!(
            start.elapsed() < Duration::from_secs(3),
            "hanging get must be killed promptly on timeout"
        );
        hc.clear_flag("hang_get");

        // 2. Hanging `interrupt`
        let transport = HerdrTransport::new(target.clone()).with_timeouts(ok, short, ok);
        hc.set_get_default(0, &nested_json("t3", 100, 4242, "codex", "working"));
        hc.set_flag("hang_interrupt");
        let start = Instant::now();
        assert_eq!(
            transport.deliver(&test_digest(), PushMode::Interrupt).await,
            PushOutcome::reject("herdr_interrupt_outcome_unknown")
        );
        assert!(start.elapsed() < Duration::from_secs(3));
        hc.clear_flag("hang_interrupt");

        // 3. Hanging `send` (post-interrupt -> Reject { interrupted: true })
        let transport = HerdrTransport::new(target).with_timeouts(ok, ok, short);
        hc.reset_calls();
        hc.set_get_seq(1, 0, &nested_json("t3", 100, 4242, "codex", "working"));
        hc.set_get_seq(2, 0, &nested_json("t3", 100, 4242, "codex", "idle"));
        hc.set_interrupt(0, r#"{"outcome":"stopped"}"#);
        hc.set_flag("hang_send");
        let start = Instant::now();
        assert_eq!(
            transport.deliver(&test_digest(), PushMode::Interrupt).await,
            PushOutcome::Reject {
                reason: "herdr_send_outcome_unknown".into(),
                interrupted: true,
            }
        );
        assert!(start.elapsed() < Duration::from_secs(3));
    }

    #[tokio::test]
    async fn e2e_malformed_and_oversized_get_output_fail_closed() {
        let hc = FakeHc::new();
        let transport = HerdrTransport::new(HerdrTarget::new("t3").with_bin(hc.bin()))
            .with_timeouts(
                Duration::from_secs(2),
                Duration::from_secs(2),
                Duration::from_secs(2),
            );

        hc.set_get_default(0, "{truncated json");
        assert_eq!(
            transport.deliver(&test_digest(), PushMode::Queue).await,
            PushOutcome::hold("herdr_target_unavailable")
        );

        hc.set_flag("oversized_get");
        assert_eq!(
            transport.deliver(&test_digest(), PushMode::Queue).await,
            PushOutcome::hold("herdr_target_unavailable")
        );
    }
}
