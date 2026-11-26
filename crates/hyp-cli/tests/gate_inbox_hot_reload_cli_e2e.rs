//! Subprocess E2E tests for live CLI -> Daemon Hot-Reload (`hyp gate lock` -> `gate.reload`
//! and `hyp inbox approve` / `hyp inbox reject` -> `inbox.wake`) plus offline degradation.
//!
//! Uses a real POSIX PTY (`#[cfg(unix)]`) because `hyp gate lock`, `hyp gate init --lock`,
//! `hyp inbox approve`, and `hyp inbox reject` enforce unskippable interactive TTY confirmation.

#![cfg(unix)]

mod common;

use common::{ManagedProcess, isolated_cmd, run_hyp_in_pty};
use hyp_harness::sock::daemon_rpc_sync;
use hyp_store::{GateState, MailboxInsert, MailboxKind, MailboxPutResult, NodeDb, now_ms};
use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;
use tempfile::TempDir;

const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);

#[test]
fn cli_gate_lock_and_inbox_approve_live_hot_reload_without_restart() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().to_path_buf();
    let state_dir = home.join("state");
    fs::create_dir_all(&state_dir).unwrap();
    let state_str = state_dir.to_str().unwrap();

    // 1. Start a live `hyp daemon` subprocess with default Stage 1 gate.
    let mut daemon_cmd = isolated_cmd(&home);
    daemon_cmd
        .args([
            "daemon",
            "--profile",
            "local",
            "--node-id",
            "live-hot@box",
            "--state-dir",
            state_str,
            "--json",
        ])
        .stdin(Stdio::null());
    let mut daemon = ManagedProcess::spawn("live-hot@box daemon", &mut daemon_cmd);
    let startup = daemon.read_json_line(STARTUP_TIMEOUT);
    assert_eq!(startup["ok"], true, "daemon startup failed: {startup}");
    let sock_path = PathBuf::from(startup["data"]["socketPath"].as_str().unwrap());

    // 2. Configure a new filter via `hyp gate init` (unsigned), then lock via `hyp gate lock --json`!
    let init_out = isolated_cmd(&home)
        .args([
            "gate",
            "init",
            "--adapter",
            "openai-compat",
            "--id",
            "hot-ollama",
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run gate init");
    assert_eq!(init_out.status.code(), Some(0));

    let lock_out = run_hyp_in_pty(
        &home,
        &["gate", "lock", "--state-dir", state_str, "--json"],
        None,
        Some("y\n"),
    );
    assert_eq!(
        lock_out.code, 0,
        "stdout={} tty={}",
        lock_out.stdout, lock_out.tty
    );
    let lock_json = lock_out.parse_json();
    assert_eq!(lock_json["ok"], true);
    assert_eq!(lock_json["data"]["gatePolicySig"], "OK");
    assert_eq!(
        lock_json["data"]["daemonReloaded"], true,
        "live daemon must be hot-reloaded by `hyp gate lock`: {lock_json}"
    );
    assert!(
        !lock_json["next"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str() == Some("hyp service restart")),
        "next steps should not ask for restart when live reload succeeded: {lock_json}"
    );

    // 3. Verify TTY output explicitly confirms live reload with no restart needed.
    let lock_tty = run_hyp_in_pty(
        &home,
        &["gate", "lock", "--state-dir", state_str],
        None,
        Some("y\n"),
    );
    assert_eq!(lock_tty.code, 0, "tty={}", lock_tty.tty);
    assert!(
        lock_tty.stdout.contains(
            "Live daemon reloaded — new Security Gate policy active immediately (no restart needed)."
        ),
        "unexpected TTY output: {}",
        lock_tty.stdout
    );

    // 4. Tamper `node.json` on disk (simulate prompt-injected agent flipping filter) and verify
    //    `gate.reload` RPC fails closed without dropping the live locked policy!
    let node_json_path = state_dir.join("node.json");
    let mut tampered: Value =
        serde_json::from_str(&fs::read_to_string(&node_json_path).unwrap()).unwrap();
    tampered["gate"]["filters"][0]["enabled"] = Value::Bool(false);
    fs::write(
        &node_json_path,
        serde_json::to_string_pretty(&tampered).unwrap(),
    )
    .unwrap();

    let tamper_rpc = daemon_rpc_sync(
        &sock_path,
        &json!({ "type": "gate.reload" }),
        Duration::from_secs(2),
    );
    assert!(
        !tamper_rpc.ok,
        "tampered node.json MUST fail closed on live gate.reload: {tamper_rpc:?}"
    );
    assert!(
        tamper_rpc
            .error
            .as_deref()
            .unwrap_or("")
            .contains("gate_policy_tampered")
    );

    // 5. Re-lock cleanly via `hyp gate lock` -> live daemon heals immediately!
    let relock_out = run_hyp_in_pty(
        &home,
        &["gate", "lock", "--state-dir", state_str, "--json"],
        None,
        Some("y\n"),
    );
    assert_eq!(relock_out.code, 0, "tty={}", relock_out.tty);
    assert_eq!(relock_out.parse_json()["data"]["daemonReloaded"], true);

    // 5b. `hyp gate remove hot-ollama --lock --json` removes the filter, keeps policy locked,
    //     and hot-reloads the live daemon without restart!
    let rem_out = run_hyp_in_pty(
        &home,
        &[
            "gate",
            "remove",
            "hot-ollama",
            "--lock",
            "--state-dir",
            state_str,
            "--json",
        ],
        None,
        Some("y\n"),
    );
    assert_eq!(
        rem_out.code, 0,
        "stdout={} tty={}",
        rem_out.stdout, rem_out.tty
    );
    let rem_json = rem_out.parse_json();
    assert_eq!(rem_json["ok"], true);
    assert_eq!(rem_json["data"]["removedFilter"]["id"], "hot-ollama");
    assert_eq!(rem_json["data"]["filterCount"], 0);
    assert_eq!(rem_json["data"]["gatePolicySig"], "OK");
    assert_eq!(
        rem_json["data"]["daemonReloaded"], true,
        "live daemon must hot-reload after `hyp gate remove --lock`: {rem_json}"
    );

    // 6. Register session + seed 2 quarantined items in `node.sqlite`, then start live `hyp wait`!
    let (r_approve, r_reject) = {
        let db = NodeDb::open(state_dir.join("node.sqlite")).unwrap();
        let now = now_ms();
        db.local()
            .register_session("claude:cli-hot", "{}", now)
            .unwrap();
        let r1 = match db
            .local()
            .put_in_mailbox(
                &MailboxInsert {
                    session_id: "claude:cli-hot".into(),
                    origin_node: "ext@peer".into(),
                    item_id: "hot-approve-item".into(),
                    text: "Approved live wakeup payload #77".into(),
                    kind: MailboxKind::Message,
                    source: "ext@peer/reviewer".into(),
                    gate_state: GateState::Quarantined,
                    gate_reason: Some("low_confidence".into()),
                    traceparent: None,
                },
                now,
            )
            .unwrap()
        {
            MailboxPutResult::Stored { receipt } => receipt,
            other => panic!("unexpected put result: {other:?}"),
        };
        let r2 = match db
            .local()
            .put_in_mailbox(
                &MailboxInsert {
                    session_id: "claude:cli-hot".into(),
                    origin_node: "spam@peer".into(),
                    item_id: "hot-reject-item".into(),
                    text: "Rejected spam payload #88".into(),
                    kind: MailboxKind::Message,
                    source: "spam@peer/bot".into(),
                    gate_state: GateState::Quarantined,
                    gate_reason: Some("prompt_injection".into()),
                    traceparent: None,
                },
                now + 1,
            )
            .unwrap()
        {
            MailboxPutResult::Stored { receipt } => receipt,
            other => panic!("unexpected put result: {other:?}"),
        };
        (r1, r2)
    };

    // Start a live `hyp wait` subprocess for `claude:cli-hot` BEFORE running `hyp inbox approve`!
    let mut wait_cmd = isolated_cmd(&home);
    wait_cmd
        .args([
            "wait",
            "--session",
            "claude:cli-hot",
            "--socket",
            sock_path.to_str().unwrap(),
            "--timeout",
            "10",
            "--json",
        ])
        .stdin(Stdio::null());
    let mut wait_proc = ManagedProcess::spawn("live hyp wait", &mut wait_cmd);

    // Wait briefly until `session.summary` shows `hasLiveTransport: true` (waiter registered).
    let ready_deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let sum = daemon_rpc_sync(
            &sock_path,
            &json!({ "type": "session.summary", "sessionId": "claude:cli-hot", "detail": "compact" }),
            Duration::from_secs(2),
        );
        if sum.ok {
            let res = sum.result.unwrap();
            if res["session"]["hasLiveTransport"] == true {
                assert_eq!(res["session"]["counts"]["quarantined"], 2);
                break;
            }
        }
        assert!(
            std::time::Instant::now() < ready_deadline,
            "timed out waiting for live `hyp wait` transport to attach"
        );
        std::thread::sleep(Duration::from_millis(25));
    }

    // 7. Run `hyp inbox approve <r_approve> --json` while daemon + `hyp wait` are live (NO restart!).
    let app_out = run_hyp_in_pty(
        &home,
        &[
            "inbox",
            "approve",
            &r_approve,
            "--state-dir",
            state_str,
            "--json",
        ],
        None,
        Some("y\n"),
    );
    assert_eq!(app_out.code, 0, "tty={}", app_out.tty);
    let app_json = app_out.parse_json();
    assert_eq!(app_json["ok"], true);
    assert_eq!(app_json["data"]["gateState"], "pending");
    assert_eq!(app_json["data"]["daemonNotified"], true);
    assert_eq!(app_json["data"]["daemonWoken"], true);
    assert_eq!(app_json["data"]["quarantinedRemaining"], 1);

    // Live `hyp wait` subprocess MUST immediately receive the metadata-only XML digest (zero body!)
    // for the approved message and exit 0!
    let wait_json = wait_proc.read_json_line(Duration::from_secs(5));
    let wait_text = wait_json["data"]["items"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        wait_text.contains("<hyphae-inbox ")
            && wait_text.contains("<dm from=\"ext@peer/reviewer\" count=\"1\"/>"),
        "expected metadata-only XML digest in live hyp wait output: {wait_json}"
    );
    assert!(
        !wait_text.contains("Approved live wakeup payload #77"),
        "RFC 0004: live hyp wait must NEVER include raw message body: {wait_json}"
    );
    let wait_status = wait_proc
        .wait_timeout(Duration::from_secs(5))
        .expect("hyp wait should exit after receiving approved message");
    assert_eq!(wait_status.code(), Some(0));

    // 8. Run `hyp inbox reject <r_reject> --mute --json` -> notifies live daemon & clears badge!
    let rej_out = run_hyp_in_pty(
        &home,
        &[
            "inbox",
            "reject",
            &r_reject,
            "--mute",
            "--state-dir",
            state_str,
            "--json",
        ],
        None,
        Some("y\n"),
    );
    assert_eq!(rej_out.code, 0, "tty={}", rej_out.tty);
    let rej_json = rej_out.parse_json();
    assert_eq!(rej_json["ok"], true);
    assert_eq!(rej_json["data"]["gateState"], "rejected");
    assert_eq!(rej_json["data"]["daemonNotified"], true);
    assert_eq!(rej_json["data"]["quarantinedRemaining"], 0);

    let sum_after = daemon_rpc_sync(
        &sock_path,
        &json!({ "type": "session.summary", "sessionId": "claude:cli-hot", "detail": "compact" }),
        Duration::from_secs(2),
    );
    assert!(sum_after.ok);
    let sa = sum_after.result.unwrap();
    assert_eq!(sa["session"]["counts"]["quarantined"], 0);
    assert_eq!(sa["daemon"]["quarantinedGlobal"], 0);

    let _ = daemon.shutdown_gracefully();
}

#[test]
fn cli_offline_daemon_degradation_for_gate_lock_and_inbox_approve_reject() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let state_dir = home.join("state");
    fs::create_dir_all(&state_dir).unwrap();
    let state_str = state_dir.to_str().unwrap();

    // 1. `hyp gate init --lock` with NO daemon running: exits 0, `daemonReloaded: false`.
    let init_out = run_hyp_in_pty(
        home,
        &[
            "gate",
            "init",
            "--adapter",
            "openai-compat",
            "--state-dir",
            state_str,
            "--lock",
            "--json",
        ],
        None,
        Some("y\n"),
    );
    assert_eq!(init_out.code, 0, "tty={}", init_out.tty);
    let init_json = init_out.parse_json();
    assert_eq!(init_json["ok"], true);
    assert_eq!(init_json["data"]["locked"], true);
    assert_eq!(init_json["data"]["daemonReloaded"], false);

    // 2. `hyp gate lock --json` offline: exits 0, `daemonReloaded: false`, recommends restart.
    let lock_out = run_hyp_in_pty(
        home,
        &["gate", "lock", "--state-dir", state_str, "--json"],
        None,
        Some("y\n"),
    );
    assert_eq!(lock_out.code, 0, "tty={}", lock_out.tty);
    let lock_json = lock_out.parse_json();
    assert_eq!(lock_json["ok"], true);
    assert_eq!(lock_json["data"]["gatePolicySig"], "OK");
    assert_eq!(lock_json["data"]["daemonReloaded"], false);
    assert!(
        lock_json["next"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str() == Some("hyp service restart"))
    );

    // 3. `hyp gate lock` TTY offline cleanly notes `hyp service restart` / `hyp node start`.
    let lock_tty = run_hyp_in_pty(
        home,
        &["gate", "lock", "--state-dir", state_str],
        None,
        Some("y\n"),
    );
    assert_eq!(lock_tty.code, 0, "tty={}", lock_tty.tty);
    assert!(
        lock_tty.stdout.contains("hyp service restart")
            && lock_tty.stdout.contains("hyp node start"),
        "expected offline restart note in TTY stdout: {}",
        lock_tty.stdout
    );

    // 4. Seed 2 quarantined items and run `hyp inbox approve` + `hyp inbox reject` offline!
    let (r1, r2) = {
        let db = NodeDb::open(state_dir.join("node.sqlite")).unwrap();
        let now = now_ms();
        let r1 = match db
            .local()
            .put_in_mailbox(
                &MailboxInsert {
                    session_id: "claude:offline-s1".into(),
                    origin_node: "ext@peer".into(),
                    item_id: "off-1".into(),
                    text: "Offline approve payload".into(),
                    kind: MailboxKind::Message,
                    source: "ext@peer/dev".into(),
                    gate_state: GateState::Quarantined,
                    gate_reason: Some("low_confidence".into()),
                    traceparent: None,
                },
                now,
            )
            .unwrap()
        {
            MailboxPutResult::Stored { receipt } => receipt,
            other => panic!("unexpected put result: {other:?}"),
        };
        let r2 = match db
            .local()
            .put_in_mailbox(
                &MailboxInsert {
                    session_id: "claude:offline-s1".into(),
                    origin_node: "ext@peer".into(),
                    item_id: "off-2".into(),
                    text: "Offline reject payload".into(),
                    kind: MailboxKind::Message,
                    source: "ext@peer/spam".into(),
                    gate_state: GateState::Quarantined,
                    gate_reason: Some("prompt_injection".into()),
                    traceparent: None,
                },
                now + 1,
            )
            .unwrap()
        {
            MailboxPutResult::Stored { receipt } => receipt,
            other => panic!("unexpected put result: {other:?}"),
        };
        (r1, r2)
    };

    let app_out = run_hyp_in_pty(
        home,
        &["inbox", "approve", &r1, "--state-dir", state_str, "--json"],
        None,
        Some("y\n"),
    );
    assert_eq!(app_out.code, 0, "tty={}", app_out.tty);
    let app_json = app_out.parse_json();
    assert_eq!(app_json["ok"], true);
    assert_eq!(app_json["data"]["gateState"], "pending");
    assert_eq!(app_json["data"]["daemonNotified"], false);
    assert_eq!(app_json["data"]["daemonWoken"], false);

    let rej_out = run_hyp_in_pty(
        home,
        &["inbox", "reject", &r2, "--state-dir", state_str, "--json"],
        None,
        Some("y\n"),
    );
    assert_eq!(rej_out.code, 0, "tty={}", rej_out.tty);
    let rej_json = rej_out.parse_json();
    assert_eq!(rej_json["ok"], true);
    assert_eq!(rej_json["data"]["gateState"], "rejected");
    assert_eq!(rej_json["data"]["daemonNotified"], false);
}
