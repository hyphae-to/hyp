//! End-to-end tests for `--if-not-running` daemon deduplication and Antigravity
//! sidecar generation (`sidecars/daemon/sidecar.json`).
//!
//! Strict isolation invariant: every test uses ephemeral `tempfile::TempDir`, isolated
//! `HOME` / `--home` / `--state-dir`, and `HYPHAE_SECRET_BACKEND=file` — zero live user
//! config, OS Keychain, LaunchAgent, systemd, or Windows Task Scheduler mutations!

mod common;

use common::{ManagedProcess, isolated_cmd, parse_json_stdout};
use hyp_harness::sock::{DEFAULT_SOCKET_FILENAME, daemon_rpc_sync};
use serde_json::{Value, json};
use std::fs;
use std::time::{Duration, Instant};

#[test]
fn node_start_if_not_running_exits_zero_immediately_when_daemon_alive() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("home");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&state_dir).unwrap();

    // 1. Start a live background daemon in the isolated state directory.
    let mut start_cmd = isolated_cmd(&home);
    start_cmd.args([
        "node",
        "start",
        "--state-dir",
        state_dir.to_str().unwrap(),
        "--node-id",
        "alice@dedup-test",
        "--json",
    ]);
    let mut daemon_proc = ManagedProcess::spawn("hyp node start (primary)", &mut start_cmd);
    let startup_env = daemon_proc.read_json_line(Duration::from_secs(10));
    assert_eq!(
        startup_env["ok"], true,
        "primary daemon startup: {startup_env}"
    );
    let original_pid = startup_env["data"]["pid"]
        .as_u64()
        .expect("primary daemon pid");
    let sock_path = state_dir.join(DEFAULT_SOCKET_FILENAME);

    let initial_status = daemon_rpc_sync(
        &sock_path,
        &json!({ "type": "daemon.status" }),
        Duration::from_millis(500),
    );
    assert!(
        initial_status.ok,
        "primary daemon should answer daemon.status: {initial_status:?}"
    );

    // 2. Invoke `hyp node start --if-not-running` (text mode) — must exit 0 quickly (<2s).
    let t0 = Instant::now();
    let dedup_text = isolated_cmd(&home)
        .args([
            "node",
            "start",
            "--if-not-running",
            "--state-dir",
            state_dir.to_str().unwrap(),
        ])
        .output()
        .expect("run hyp node start --if-not-running");
    let elapsed_text = t0.elapsed();
    assert_eq!(
        dedup_text.status.code(),
        Some(0),
        "expected exit 0 with --if-not-running; stdout={} stderr={}",
        String::from_utf8_lossy(&dedup_text.stdout),
        String::from_utf8_lossy(&dedup_text.stderr)
    );
    assert!(
        elapsed_text < Duration::from_secs(2),
        "expected fast exit (<2s), took {elapsed_text:?}"
    );
    let stdout_text = String::from_utf8_lossy(&dedup_text.stdout);
    assert!(
        stdout_text.contains("OK    Hyphae daemon already running at")
            && stdout_text.contains("exiting cleanly (--if-not-running)."),
        "unexpected --if-not-running stdout: {stdout_text:?}"
    );

    // 3. Invoke `hyp daemon --if-not-running --json` (alias + structured JSON envelope).
    let t1 = Instant::now();
    let dedup_json_out = isolated_cmd(&home)
        .args([
            "daemon",
            "--if-not-running",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run hyp daemon --if-not-running --json");
    let elapsed_json = t1.elapsed();
    assert_eq!(dedup_json_out.status.code(), Some(0));
    assert!(
        elapsed_json < Duration::from_secs(2),
        "expected fast JSON exit (<2s), took {elapsed_json:?}"
    );
    let dedup_json = parse_json_stdout(&dedup_json_out);
    assert_eq!(dedup_json["ok"], true);
    assert_eq!(dedup_json["data"]["alreadyRunning"], true);
    assert_eq!(dedup_json["data"]["pid"], original_pid);
    assert_eq!(dedup_json["data"]["nodeId"], "alice@dedup-test");

    // 4. Nearby mutated case (Unix): without `--if-not-running`, duplicate start fails non-zero
    //    and leaves the live daemon untouched.
    #[cfg(unix)]
    {
        let dup_fail = isolated_cmd(&home)
            .args([
                "node",
                "start",
                "--state-dir",
                state_dir.to_str().unwrap(),
                "--json",
            ])
            .output()
            .expect("run duplicate hyp node start without --if-not-running");
        assert_ne!(
            dup_fail.status.code(),
            Some(0),
            "duplicate start without --if-not-running must fail closed"
        );
    }

    // 5. Verify primary live daemon is still healthy and untouched with the exact same PID.
    let after_status = daemon_rpc_sync(
        &sock_path,
        &json!({ "type": "daemon.status" }),
        Duration::from_millis(500),
    );
    assert!(
        after_status.ok,
        "primary daemon must remain healthy after dedup probes: {after_status:?}"
    );
    let after_result = after_status.result.expect("status result");
    assert_eq!(
        after_result.get("nodeId").and_then(Value::as_str),
        Some("alice@dedup-test")
    );
    let pid_file_val: u64 = fs::read_to_string(state_dir.join("node.pid"))
        .expect("node.pid should still exist")
        .trim()
        .parse()
        .expect("valid numeric node.pid");
    assert_eq!(pid_file_val, original_pid);
    assert!(
        daemon_proc
            .wait_timeout(Duration::from_millis(50))
            .is_none(),
        "primary daemon process must still be alive"
    );

    daemon_proc.shutdown_gracefully();
}

#[test]
fn node_start_if_not_running_starts_cleanly_when_offline_or_stale_socket() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("home");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&state_dir).unwrap();

    // Seed a genuine stale socket on Unix (bound and immediately dropped listener) to verify
    // `--if-not-running` probes actual health rather than blindly trusting file existence.
    let sock_path = state_dir.join(DEFAULT_SOCKET_FILENAME);
    #[cfg(unix)]
    {
        let stale_listener =
            std::os::unix::net::UnixListener::bind(&sock_path).expect("bind stale unix socket");
        drop(stale_listener);
        assert!(sock_path.exists(), "stale socket file should exist on disk");
    }

    let mut start_cmd = isolated_cmd(&home);
    start_cmd.args([
        "node",
        "start",
        "--if-not-running",
        "--state-dir",
        state_dir.to_str().unwrap(),
        "--node-id",
        "bob@stale-test",
        "--json",
    ]);
    let mut daemon_proc = ManagedProcess::spawn("hyp node start --if-not-running", &mut start_cmd);
    let startup_env = daemon_proc.read_json_line(Duration::from_secs(10));
    assert_eq!(startup_env["ok"], true, "startup envelope: {startup_env}");
    assert_eq!(startup_env["data"]["nodeId"], "bob@stale-test");
    assert!(
        startup_env["data"].get("alreadyRunning").is_none(),
        "must actually start the daemon when only a stale socket existed: {startup_env}"
    );

    let live_status = daemon_rpc_sync(
        &sock_path,
        &json!({ "type": "daemon.status" }),
        Duration::from_millis(500),
    );
    assert!(live_status.ok, "newly started daemon must answer RPC");

    // Now a subsequent `--if-not-running` invocation MUST detect the live daemon and exit 0.
    let second = isolated_cmd(&home)
        .args([
            "node",
            "start",
            "--if-not-running",
            "--state-dir",
            state_dir.to_str().unwrap(),
        ])
        .output()
        .expect("run second hyp node start --if-not-running");
    assert_eq!(second.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&second.stdout).contains("exiting cleanly (--if-not-running).")
    );

    daemon_proc.shutdown_gracefully();
}

#[test]
fn setup_antigravity_writes_if_not_running_sidecar_and_is_idempotent() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("home");
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&state_dir).unwrap();

    let fake_bin = "/opt/hyphae/bin/hyp";
    let sidecar_path = home.join(".gemini/config/plugins/hyphae/sidecars/daemon/sidecar.json");

    // 1. Dry-run must NOT write sidecar.json.
    let dry = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "antigravity",
            "--bin",
            fake_bin,
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run dry-run setup");
    assert_eq!(dry.status.code(), Some(0));
    assert!(!sidecar_path.exists());

    // 2. Real setup writes sidecar.json with `--if-not-running` and `restart_policy: on-failure`.
    let run1 = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "antigravity",
            "--bin",
            fake_bin,
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run antigravity setup");
    assert_eq!(
        run1.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&run1.stderr)
    );
    let run1_json = parse_json_stdout(&run1);
    assert_eq!(run1_json["ok"], true);

    let raw_1 = fs::read_to_string(&sidecar_path).expect("read sidecar.json");
    let sidecar: Value = serde_json::from_str(&raw_1).expect("valid sidecar.json");
    assert_eq!(sidecar["command"], fake_bin);
    assert_eq!(
        sidecar["args"],
        json!(["node", "start", "--if-not-running"])
    );
    assert_eq!(sidecar["restart_policy"], "on-failure");

    // 3. Re-running setup must be strictly idempotent (byte-for-byte identical).
    let run2 = isolated_cmd(&home)
        .args([
            "setup",
            "--harness",
            "antigravity",
            "--bin",
            fake_bin,
            "--home",
            home.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("re-run antigravity setup");
    assert_eq!(run2.status.code(), Some(0));
    let raw_2 = fs::read_to_string(&sidecar_path).expect("re-read sidecar.json");
    assert_eq!(raw_1, raw_2, "sidecar.json must be strictly idempotent");
}
