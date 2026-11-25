//! Comprehensive E2E, latency, security fuzzing, streaming, and cross-platform loopback tests
//! for v0.6.0 Stream B: `hyp statusline`, `hyp inspect`, `hyp session`, and `hyp ui`.
//!
//! Strict isolation invariant: every test runs against an ephemeral `tempfile::TempDir`,
//! `HYPHAE_SECRET_BACKEND=file`, isolated `HOME`/`XDG_CONFIG_HOME`, scrubbed `HYPHAE_*` env
//! vars, and live in-process `LocalDaemon` — zero live user config or Keychain mutations.

mod common;

use common::{ManagedProcess, isolated_cmd, parse_json_stdout};
use hyp_crypto::SecretBackend;
use hyp_harness::daemon::{InboundItem, LocalDaemon, LocalDaemonConfig};
use hyp_harness::sock::{MAX_SOCKET_LINE_BYTES, read_bounded_line_async, write_ndjson_line_async};
use hyp_node::engine::{NodeConfig, SubscribeRequest, TopicConfig, UnifiedNode};
use hyp_node::gates::TrustTier as GateTrustTier;
use hyp_proto::address::NodeId;
use hyp_proto::filter::Filter as ProtoFilter;
use hyp_store::{
    CronTimezone, DeliveryMode, GateState, MailboxInsert, MailboxKind, WakeupInsert, WakeupLimits,
    WakeupTriggerKind, WakeupUrgency, now_ms,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::process::{Output, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;

fn make_test_node(node_id: &str, dir: &TempDir) -> Arc<UnifiedNode> {
    let mut cfg = NodeConfig::local(NodeId::new(node_id).unwrap(), dir.path());
    cfg.secret_backend = Some(SecretBackend::File);
    cfg.topics.push(TopicConfig {
        topic: "github".into(),
        kind: Some("github-webhook".into()),
        description: Some("Local GitHub webhook stream".into()),
        metadata: None,
        has_provisioned_publisher: true,
    });
    cfg.topics.push(TopicConfig {
        topic: "alerts".into(),
        kind: Some("prometheus".into()),
        description: Some("Local alerts".into()),
        metadata: None,
        has_provisioned_publisher: true,
    });
    UnifiedNode::open(cfg).expect("open local UnifiedNode")
}

async fn run_hyp_with_stdin(
    home: &Path,
    args: &[&str],
    stdin_bytes: &[u8],
    extra_env: &[(&str, &str)],
) -> Output {
    let home = home.to_path_buf();
    let args: Vec<String> = args.iter().map(|s| (*s).to_string()).collect();
    let stdin_bytes = stdin_bytes.to_vec();
    let extra_env: Vec<(String, String)> = extra_env
        .iter()
        .map(|&(k, v)| (k.to_string(), v.to_string()))
        .collect();

    tokio::task::spawn_blocking(move || {
        let mut cmd = isolated_cmd(&home);
        cmd.env_remove("NO_COLOR")
            .env_remove("HYPHAE_SESSION_ID")
            .env_remove("HC_TERMINAL_ID")
            .env_remove("CLAUDE_SESSION_ID")
            .env_remove("CODEX_THREAD_ID")
            .env_remove("ANTIGRAVITY_SOURCE_METADATA")
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (k, v) in &extra_env {
            cmd.env(k, v);
        }
        let mut child = cmd.spawn().expect("spawn hyp");
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(&stdin_bytes);
        }
        child.wait_with_output().expect("wait hyp")
    })
    .await
    .expect("join blocking hyp subprocess")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn statusline_e2e_hot_path_latency_pill_json_and_quarantine() {
    let dir = TempDir::new().unwrap();
    let node = make_test_node("alice@macbook", &dir);
    let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .expect("start LocalDaemon");
    let sock = daemon.socket_path().to_path_buf();
    let sock_str = sock.to_str().unwrap().to_string();

    let sid = "claude:bench-1";
    node.register_session(sid, r#"{"kind":"claude"}"#).unwrap();
    node.register_handle(sid, "alice").await.unwrap();

    // 2 subscriptions
    node.subscribe_local_or_remote(SubscribeRequest {
        id: Some("sub-gh-1".into()),
        subscriber_session: sid.into(),
        qualified_topic: "local.github".into(),
        filters: vec![ProtoFilter::Exact(BTreeMap::from([(
            "type".to_string(),
            "pr.opened".to_string(),
        )]))],
        coalesce_seconds: 15,
        mode: DeliveryMode::Full,
    })
    .await
    .unwrap();
    node.subscribe_local_or_remote(SubscribeRequest {
        id: Some("sub-al-2".into()),
        subscriber_session: sid.into(),
        qualified_topic: "local.alerts".into(),
        filters: vec![],
        coalesce_seconds: 0,
        mode: DeliveryMode::Full,
    })
    .await
    .unwrap();

    // 1 queued item
    daemon
        .ingest_inbound(InboundItem {
            session_id: sid.into(),
            origin_node: "bob@laptop".into(),
            item_id: "dm-1".into(),
            source: "bob@laptop/dev".into(),
            text: "secret dm text must not appear in statusline".into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::Peer,
        })
        .await
        .unwrap();

    // Focus mode ON + 1 mute
    let focus_res = hyp_harness::sock::daemon_rpc_async(
        &sock,
        &json!({ "type": "session.focus", "sessionId": sid, "enabled": true }),
        Duration::from_secs(2),
    )
    .await;
    assert!(focus_res.ok);
    let mute_res = hyp_harness::sock::daemon_rpc_async(
        &sock,
        &json!({ "type": "session.mute", "sessionId": sid, "source": "#noisy" }),
        Duration::from_secs(2),
    )
    .await;
    assert!(mute_res.ok);

    let stdin_json = br#"{"session_id":"bench-1","workspace":{"current_dir":"/tmp/repo"}}"#;

    // Warm once (OS binary page-in), then benchmark hot-path invocation.
    let warm = run_hyp_with_stdin(
        dir.path(),
        &["statusline", "--socket", &sock_str, "--plain"],
        stdin_json,
        &[],
    )
    .await;
    assert_eq!(warm.status.code(), Some(0));

    let t0 = Instant::now();
    let out = run_hyp_with_stdin(
        dir.path(),
        &["statusline", "--socket", &sock_str, "--plain"],
        stdin_json,
        &[],
    )
    .await;
    let elapsed = t0.elapsed();

    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let line = stdout.trim();
    assert_eq!(
        line, "⟁ @alice · 2 subs · 1 queued · focus · 1 muted",
        "unexpected statusline pill: {line:?}"
    );
    assert!(
        !line.contains('\x1b'),
        "--plain must emit zero ANSI escapes"
    );
    assert!(
        !line.contains("secret dm text"),
        "statusline must never leak message bodies"
    );
    assert!(
        elapsed < Duration::from_millis(100),
        "hyp statusline exceeded 100ms budget: {elapsed:?}"
    );

    // Colored output vs NO_COLOR
    let colored = run_hyp_with_stdin(
        dir.path(),
        &["statusline", "--socket", &sock_str],
        stdin_json,
        &[],
    )
    .await;
    assert_eq!(colored.status.code(), Some(0));
    let colored_str = String::from_utf8_lossy(&colored.stdout);
    assert!(
        colored_str.contains('\x1b'),
        "default statusline should include ANSI color"
    );
    assert!(colored_str.contains("@alice"));
    assert!(colored_str.contains("2 subs"));
    assert!(colored_str.contains("1 queued"));
    assert!(colored_str.contains("focus"));

    let no_color = run_hyp_with_stdin(
        dir.path(),
        &["statusline", "--socket", &sock_str],
        stdin_json,
        &[("NO_COLOR", "1")],
    )
    .await;
    assert_eq!(no_color.status.code(), Some(0));
    assert!(!String::from_utf8_lossy(&no_color.stdout).contains('\x1b'));

    // Add a quarantined item -> red `⚠ 1 held` badge appears
    node.db()
        .local()
        .put_in_mailbox(
            &MailboxInsert {
                session_id: sid.into(),
                origin_node: "untrusted@net".into(),
                item_id: "q-1".into(),
                text: "SENTINEL_QUARANTINE_PAYLOAD".into(),
                kind: MailboxKind::Message,
                source: "SENTINEL_QUARANTINE_SRC".into(),
                gate_state: GateState::Quarantined,
                gate_reason: Some("prompt_injection".into()),
                traceparent: None,
            },
            now_ms(),
        )
        .unwrap();

    let with_q = run_hyp_with_stdin(
        dir.path(),
        &["statusline", "--socket", &sock_str, "--plain"],
        stdin_json,
        &[],
    )
    .await;
    assert_eq!(with_q.status.code(), Some(0));
    let q_line = String::from_utf8_lossy(&with_q.stdout);
    assert!(
        q_line.contains("⚠ 1 held"),
        "expected quarantine badge: {q_line:?}"
    );
    assert!(!q_line.contains("SENTINEL_QUARANTINE"));

    // `--json` outputs raw structured `session.summary` envelope
    let json_out = run_hyp_with_stdin(
        dir.path(),
        &["statusline", "--socket", &sock_str, "--json"],
        stdin_json,
        &[],
    )
    .await;
    assert_eq!(json_out.status.code(), Some(0));
    let parsed = parse_json_stdout(&json_out);
    assert_eq!(parsed["schemaVersion"], 1);
    assert_eq!(parsed["daemon"]["online"], true);
    assert_eq!(parsed["session"]["handle"], "alice");
    assert_eq!(parsed["session"]["counts"]["subscriptions"], 2);
    assert_eq!(parsed["session"]["counts"]["queued"], 1);
    assert_eq!(parsed["session"]["counts"]["quarantined"], 1);

    // Antigravity harness `conversation_id` mapping
    let agy_sid = "antigravity:conv-42";
    node.register_session(agy_sid, r#"{"kind":"antigravity"}"#)
        .unwrap();
    node.register_handle(agy_sid, "agybot").await.unwrap();
    let agy_out = run_hyp_with_stdin(
        dir.path(),
        &[
            "statusline",
            "--harness",
            "antigravity",
            "--socket",
            &sock_str,
            "--plain",
        ],
        br#"{"conversation_id":"conv-42"}"#,
        &[],
    )
    .await;
    assert_eq!(agy_out.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&agy_out.stdout).trim(), "⟁ @agybot");

    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn statusline_unenrolled_hide_vs_dim_and_offline() {
    let dir = TempDir::new().unwrap();
    let node = make_test_node("alice@mac", &dir);
    let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .unwrap();
    let sock = daemon.socket_path().to_path_buf();
    let sock_str = sock.to_str().unwrap().to_string();

    // Registered session that is NOT enrolled and has 0 subs / 0 queued
    node.register_session("claude:idle-1", r#"{"kind":"claude"}"#)
        .unwrap();

    // Default (`--when-unenrolled hide`) prints completely empty stdout
    let hidden = run_hyp_with_stdin(
        dir.path(),
        &["statusline", "--socket", &sock_str, "--plain"],
        br#"{"session_id":"idle-1"}"#,
        &[],
    )
    .await;
    assert_eq!(hidden.status.code(), Some(0));
    assert!(
        hidden.stdout.is_empty(),
        "unenrolled hide must emit empty stdout, got: {:?}",
        String::from_utf8_lossy(&hidden.stdout)
    );

    // `--when-unenrolled dim` prints dim idle indicator
    let dimmed = run_hyp_with_stdin(
        dir.path(),
        &[
            "statusline",
            "--socket",
            &sock_str,
            "--when-unenrolled",
            "dim",
            "--plain",
        ],
        br#"{"session_id":"idle-1"}"#,
        &[],
    )
    .await;
    assert_eq!(dimmed.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&dimmed.stdout).trim(),
        "⟁ hyp: idle"
    );

    // Offline daemon: hide -> empty stdout; dim -> offline pill; --json -> online: false
    // Place in a subdirectory so Windows `connector.addr` sibling lookup does not find `dir`'s live daemon!
    let missing = dir.path().join("offline").join("does-not-exist.sock");
    let missing_str = missing.to_str().unwrap();

    let off_hide = run_hyp_with_stdin(
        dir.path(),
        &["statusline", "--socket", missing_str, "--plain"],
        br#"{"session_id":"idle-1"}"#,
        &[],
    )
    .await;
    assert_eq!(off_hide.status.code(), Some(0));
    assert!(off_hide.stdout.is_empty());

    let off_dim = run_hyp_with_stdin(
        dir.path(),
        &[
            "statusline",
            "--socket",
            missing_str,
            "--when-unenrolled",
            "dim",
            "--plain",
        ],
        br#"{"session_id":"idle-1"}"#,
        &[],
    )
    .await;
    assert_eq!(off_dim.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&off_dim.stdout).trim(),
        "⟁ hyp: offline"
    );

    let off_json = run_hyp_with_stdin(
        dir.path(),
        &["statusline", "--socket", missing_str, "--json"],
        br#"{"session_id":"idle-1"}"#,
        &[],
    )
    .await;
    assert_eq!(off_json.status.code(), Some(0));
    let parsed = parse_json_stdout(&off_json);
    assert_eq!(parsed["daemon"]["online"], false);
    assert!(parsed["session"].is_null());

    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn statusline_chain_file_wrapper_and_fault_isolation() {
    let dir = TempDir::new().unwrap();
    let node = make_test_node("alice@mac", &dir);
    let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .unwrap();
    let sock = daemon.socket_path().to_path_buf();
    let sock_str = sock.to_str().unwrap().to_string();

    node.register_session("claude:chain-1", r#"{"kind":"claude"}"#)
        .unwrap();
    node.register_handle("claude:chain-1", "alice")
        .await
        .unwrap();

    // 1. JSON `{command, args}` chain file that reads stdin and prints line 1
    #[cfg(unix)]
    let chain_spec = json!({
        "command": "sh",
        "args": ["-c", "payload=$(cat); echo \"user-statusline:$payload\""]
    });
    #[cfg(not(unix))]
    let chain_spec = json!({
        "command": "cmd",
        "args": ["/C", "echo user-statusline:ok"]
    });
    let chain_path = dir.path().join("prev-statusline.json");
    std::fs::write(&chain_path, chain_spec.to_string()).unwrap();

    let stdin_payload = br#"{"session_id":"chain-1"}"#;
    let chained = run_hyp_with_stdin(
        dir.path(),
        &[
            "statusline",
            "--socket",
            &sock_str,
            "--plain",
            "--chain-file",
            chain_path.to_str().unwrap(),
        ],
        stdin_payload,
        &[],
    )
    .await;
    assert_eq!(chained.status.code(), Some(0));
    let out_str = String::from_utf8_lossy(&chained.stdout);
    let lines: Vec<&str> = out_str.lines().collect();
    assert_eq!(
        lines.len(),
        2,
        "expected 2 lines (chain + hyphae), got: {lines:?}"
    );
    assert!(
        lines[0].starts_with("user-statusline:"),
        "line 1 must be original statusline: {:?}",
        lines[0]
    );
    #[cfg(unix)]
    assert!(
        lines[0].contains("chain-1"),
        "chained command must receive original stdin bytes: {:?}",
        lines[0]
    );
    assert_eq!(lines[1], "⟁ @alice");

    // 2. Broken / non-zero-exiting chained command MUST NOT break Hyphae output!
    let broken_path = dir.path().join("broken-chain.json");
    std::fs::write(&broken_path, json!({ "command": "exit 42" }).to_string()).unwrap();
    let resilient = run_hyp_with_stdin(
        dir.path(),
        &[
            "statusline",
            "--socket",
            &sock_str,
            "--plain",
            "--chain-file",
            broken_path.to_str().unwrap(),
        ],
        stdin_payload,
        &[],
    )
    .await;
    assert_eq!(resilient.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&resilient.stdout).trim(),
        "⟁ @alice"
    );

    // 3. Missing chain file MUST also fail safe and output Hyphae cleanly
    let missing_chain = dir.path().join("nonexistent-chain.json");
    let still_ok = run_hyp_with_stdin(
        dir.path(),
        &[
            "statusline",
            "--socket",
            &sock_str,
            "--plain",
            "--chain-file",
            missing_chain.to_str().unwrap(),
        ],
        stdin_payload,
        &[],
    )
    .await;
    assert_eq!(still_ok.status.code(), Some(0));
    assert_eq!(
        String::from_utf8_lossy(&still_ok.stdout).trim(),
        "⟁ @alice"
    );

    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn statusline_security_fuzzing_and_ansi_injection_stripping() {
    let dir = TempDir::new().unwrap();
    let node = make_test_node("alice@mac", &dir);
    let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .unwrap();
    let sock = daemon.socket_path().to_path_buf();
    let sock_str = sock.to_str().unwrap().to_string();

    // Level 1–2 fuzzing: malformed JSON, invalid UTF-8, >64 KiB stdin, shell metachars in session_id
    let huge = vec![b'X'; 100 * 1024];
    let fuzz_inputs: Vec<&[u8]> = vec![
        b"",
        b"{not valid json",
        b"\xff\xfe\x00\x01\x1b[31m",
        br#"{"session_id":"$(whoami); rm -rf /"}"#,
        &huge,
    ];
    for payload in fuzz_inputs {
        let out = run_hyp_with_stdin(
            dir.path(),
            &["statusline", "--socket", &sock_str, "--plain"],
            payload,
            &[],
        )
        .await;
        assert_eq!(
            out.status.code(),
            Some(0),
            "fuzz input must never crash or fail"
        );
        assert!(out.stdout.is_empty());
    }

    // Level 3 wire-boundary injection test: spin up a mock loopback TCP daemon returning
    // ANSI CSI + OSC window-title + clear-screen + CR/LF injection inside handle & nodeId!
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mock_addr = listener.local_addr().unwrap();
    let mock_addr_file = dir.path().join("mock-evil.addr");
    std::fs::write(&mock_addr_file, format!("{mock_addr}\n")).unwrap();
    let mock_str = mock_addr_file.to_str().unwrap().to_string();

    let evil_resp = json!({
        "ok": true,
        "result": {
            "schemaVersion": 1,
            "rev": 3,
            "updatedAt": 1_750_000_000_000i64,
            "daemon": {
                "online": true,
                "nodeId": "alice@\x1b[31mhost\x1b]0;titlepwn\x07",
                "version": "0.6.0",
                "profile": "local",
                "peersOnline": 1,
                "quarantinedGlobal": 0
            },
            "session": {
                "sessionId": "claude:evil-ansi-1",
                "harness": "claude",
                "enrolled": true,
                "handle": "\x1b[31mevil\x1b]0;pwn\x07\x1b[2J\r\n",
                "deliveryMode": "queue",
                "focusMode": false,
                "focusAllowInterruptVips": true,
                "mutedAll": false,
                "counts": {
                    "subscriptions": 0,
                    "queued": 0,
                    "unnotified": 0,
                    "quarantined": 0,
                    "mutedRules": 0,
                    "mutedArchived": 0,
                    "channels": 0,
                    "wakeups": 0
                },
                "details": {
                    "subscriptions": [],
                    "queuedItems": [],
                    "mutes": [],
                    "rules": [],
                    "channels": [],
                    "channelEntries": [],
                    "wakeups": []
                }
            }
        }
    });

    let server_task = tokio::spawn(async move {
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().await.unwrap();
            let (r, mut w) = stream.split();
            let mut reader = tokio::io::BufReader::new(r);
            let _ = read_bounded_line_async(&mut reader, MAX_SOCKET_LINE_BYTES).await;
            let _ = write_ndjson_line_async(&mut w, &evil_resp).await;
        }
    });

    // Plain output MUST strip EVERY escape sequence and control char!
    let plain = run_hyp_with_stdin(
        dir.path(),
        &["statusline", "--socket", &mock_str, "--plain"],
        br#"{"session_id":"evil-ansi-1"}"#,
        &[],
    )
    .await;
    assert_eq!(plain.status.code(), Some(0));
    let plain_str = String::from_utf8_lossy(&plain.stdout);
    assert_eq!(plain_str.trim(), "⟁ @evil");
    assert!(!plain_str.contains('\x1b'));
    assert!(!plain_str.contains("pwn"));

    // Colored output MUST STILL strip the injected OSC/CSI sequences!
    let colored = run_hyp_with_stdin(
        dir.path(),
        &["statusline", "--socket", &mock_str],
        br#"{"session_id":"evil-ansi-1"}"#,
        &[],
    )
    .await;
    assert_eq!(colored.status.code(), Some(0));
    let colored_str = String::from_utf8_lossy(&colored.stdout);
    assert!(colored_str.contains("@evil"));
    assert!(!colored_str.contains("pwn"));
    assert!(!colored_str.contains("\x1b]0;"));
    assert!(!colored_str.contains("\x1b[2J"));

    // `hyp inspect` text output MUST also strip every injected sequence!
    let inspect = run_hyp_with_stdin(
        dir.path(),
        &["inspect", "--socket", &mock_str, "--session", "claude:evil-ansi-1"],
        b"",
        &[],
    )
    .await;
    assert_eq!(inspect.status.code(), Some(0));
    let inspect_str = String::from_utf8_lossy(&inspect.stdout);
    assert!(inspect_str.contains("@evil"));
    assert!(inspect_str.contains("alice@host"));
    assert!(!inspect_str.contains('\x1b'));
    assert!(!inspect_str.contains("pwn"));
    assert!(!inspect_str.contains("titlepwn"));

    server_task.await.unwrap();
    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inspect_and_session_controls_e2e_and_watch_stream() {
    let dir = TempDir::new().unwrap();
    let node = make_test_node("alice@macbook", &dir);
    let daemon = LocalDaemon::start(Arc::clone(&node), None, LocalDaemonConfig::default())
        .await
        .unwrap();
    let sock = daemon.socket_path().to_path_buf();
    let sock_str = sock.to_str().unwrap().to_string();

    let sid = "claude:ctrl-1";
    node.register_session(sid, r#"{"kind":"claude"}"#).unwrap();
    node.register_handle(sid, "alice").await.unwrap();
    node.join_channel("#ops", "alice").await.unwrap();
    node.join_channel("#release", "alice").await.unwrap();
    node.subscribe_local_or_remote(SubscribeRequest {
        id: Some("sub-gh-1".into()),
        subscriber_session: sid.into(),
        qualified_topic: "local.github".into(),
        filters: vec![ProtoFilter::Exact(BTreeMap::from([(
            "type".to_string(),
            "pr.review_requested".to_string(),
        )]))],
        coalesce_seconds: 10,
        mode: DeliveryMode::Full,
    })
    .await
    .unwrap();

    // Seed secret untrusted body + wakeup note that MUST NEVER appear in inspect/session output!
    let secret_dm = "SENTINEL_DM_BODY_DO_NOT_LEAK_991";
    let secret_note = "SENTINEL_WAKEUP_NOTE_DO_NOT_LEAK_882";
    daemon
        .ingest_inbound(InboundItem {
            session_id: sid.into(),
            origin_node: "bob@lap".into(),
            item_id: "dm-ctrl-1".into(),
            source: "bob@lap/rev".into(),
            text: secret_dm.into(),
            kind: MailboxKind::Message,
            trust_tier: GateTrustTier::Peer,
        })
        .await
        .unwrap();
    node.db()
        .wakeups()
        .create_wakeup(
            &WakeupInsert {
                id: Some("wk-1".into()),
                owner_session_id: Some(sid.into()),
                target_session_id: Some(sid.into()),
                target_handle: None,
                target_topic: None,
                label: "deploy-check".into(),
                note: secret_note.into(),
                trigger_kind: WakeupTriggerKind::Timer,
                cron_expr: None,
                timezone: CronTimezone::Utc,
                exact_timing: false,
                urgency: WakeupUrgency::Queue,
                ttl_ms: 60_000,
                coalesce: true,
                fire_at: Some(now_ms() + 120_000),
                max_iterations: None,
                cold_revival_template: None,
            },
            &WakeupLimits::default(),
            now_ms(),
        )
        .unwrap();

    // 1. Focus ON (--allow-vips false) using $HYPHAE_SESSION_ID env fallback!
    let focus_on = run_hyp_with_stdin(
        dir.path(),
        &[
            "session",
            "focus",
            "on",
            "--allow-vips",
            "false",
            "--socket",
            &sock_str,
            "--json",
        ],
        b"",
        &[("HYPHAE_SESSION_ID", sid)],
    )
    .await;
    assert_eq!(focus_on.status.code(), Some(0));
    let focus_env = parse_json_stdout(&focus_on);
    assert_eq!(focus_env["ok"], true);
    assert_eq!(focus_env["command"], "session focus");
    assert_eq!(focus_env["data"]["focusMode"], true);
    assert_eq!(focus_env["data"]["focusAllowInterruptVips"], false);

    // 2. Mute `#noisy` with TTL
    let mute = run_hyp_with_stdin(
        dir.path(),
        &[
            "session",
            "mute",
            "#noisy",
            "--ttl",
            "300",
            "--session",
            sid,
            "--socket",
            &sock_str,
            "--json",
        ],
        b"",
        &[],
    )
    .await;
    assert_eq!(mute.status.code(), Some(0));
    let mute_env = parse_json_stdout(&mute);
    assert_eq!(mute_env["ok"], true);
    assert_eq!(mute_env["data"]["pattern"], "#noisy");
    assert_eq!(mute_env["data"]["ttlSeconds"], 300);

    // 3. Delivery rule `bob/rev` -> `interrupt`
    let rule = run_hyp_with_stdin(
        dir.path(),
        &[
            "session",
            "rule",
            "bob/rev",
            "interrupt",
            "--session",
            sid,
            "--socket",
            &sock_str,
            "--json",
        ],
        b"",
        &[],
    )
    .await;
    assert_eq!(rule.status.code(), Some(0));
    let rule_env = parse_json_stdout(&rule);
    assert_eq!(rule_env["ok"], true);
    assert_eq!(rule_env["data"]["target"], "bob/rev");
    assert_eq!(rule_env["data"]["delivery"], "interrupt");

    // 4. `hyp inspect --json` MUST reflect EVERY mutation identically and leak ZERO bodies/notes!
    let inspect_json = run_hyp_with_stdin(
        dir.path(),
        &["inspect", "--socket", &sock_str, "--json"],
        b"",
        &[("HYPHAE_SESSION_ID", sid)],
    )
    .await;
    assert_eq!(inspect_json.status.code(), Some(0));
    let raw_inspect = String::from_utf8_lossy(&inspect_json.stdout);
    assert!(!raw_inspect.contains(secret_dm));
    assert!(!raw_inspect.contains(secret_note));

    let env = parse_json_stdout(&inspect_json);
    assert_eq!(env["ok"], true);
    assert_eq!(env["command"], "inspect");
    let sess = &env["data"]["session"];
    assert_eq!(sess["sessionId"], sid);
    assert_eq!(sess["handle"], "alice");
    assert_eq!(sess["focusMode"], true);
    assert_eq!(sess["focusAllowInterruptVips"], false);
    assert_eq!(sess["counts"]["subscriptions"], 1);
    assert_eq!(sess["counts"]["queued"], 1);
    assert_eq!(sess["counts"]["channels"], 2);
    assert!(
        sess["details"]["mutes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|m| m["pattern"] == "#noisy")
    );
    assert!(
        sess["details"]["rules"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["target"] == "bob/rev" && r["delivery"] == "interrupt")
    );

    // 5. `hyp inspect` plain text renders crisp tables with zero body leakage
    let inspect_txt = run_hyp_with_stdin(
        dir.path(),
        &["inspect", "--session", sid, "--socket", &sock_str],
        b"",
        &[],
    )
    .await;
    assert_eq!(inspect_txt.status.code(), Some(0));
    let txt = String::from_utf8_lossy(&inspect_txt.stdout);
    assert!(txt.contains("@alice"));
    assert!(txt.contains("sub-gh-1"));
    assert!(txt.contains("type=pr.review_requested"));
    assert!(txt.contains("bob@lap/rev"));
    assert!(txt.contains("#noisy"));
    assert!(txt.contains("bob/rev"));
    assert!(txt.contains("#ops"));
    assert!(txt.contains("#release"));
    assert!(txt.contains("deploy-check"));
    assert!(!txt.contains(secret_dm));
    assert!(!txt.contains(secret_note));

    // 6. Live `hyp inspect --watch --json` streaming test (zero polling!)
    let mut watch_cmd = isolated_cmd(dir.path());
    watch_cmd
        .args([
            "inspect",
            "--watch",
            "--session",
            sid,
            "--socket",
            &sock_str,
            "--json",
        ])
        .stdin(Stdio::null());
    let mut watch_proc = ManagedProcess::spawn("hyp inspect --watch", &mut watch_cmd);
    let snap1 = watch_proc.read_json_line(Duration::from_secs(5));
    assert_eq!(snap1["type"], "inspect.snapshot");
    assert_eq!(snap1["session"]["focusMode"], true);
    let rev1 = snap1["rev"].as_u64().unwrap();

    // Mutate state via `hyp session` quick controls -> watch stream receives live push!
    let focus_off = run_hyp_with_stdin(
        dir.path(),
        &[
            "session",
            "focus",
            "off",
            "--session",
            sid,
            "--socket",
            &sock_str,
            "--json",
        ],
        b"",
        &[],
    )
    .await;
    assert_eq!(focus_off.status.code(), Some(0));

    let snap2 = watch_proc.read_json_line(Duration::from_secs(5));
    assert_eq!(snap2["type"], "inspect.snapshot");
    assert!(snap2["rev"].as_u64().unwrap() > rev1);
    assert_eq!(snap2["session"]["focusMode"], false);
    watch_proc.shutdown_gracefully();

    // 7. Reverse remaining mutations via `hyp session` (`unmute`, `rule remove`, `unsubscribe`, `leave`)
    assert_eq!(
        run_hyp_with_stdin(
            dir.path(),
            &[
                "session",
                "unmute",
                "#noisy",
                "--session",
                sid,
                "--socket",
                &sock_str,
                "--json"
            ],
            b"",
            &[]
        )
        .await
        .status
        .code(),
        Some(0)
    );
    assert_eq!(
        run_hyp_with_stdin(
            dir.path(),
            &[
                "session",
                "rule",
                "bob/rev",
                "remove",
                "--session",
                sid,
                "--socket",
                &sock_str,
                "--json"
            ],
            b"",
            &[]
        )
        .await
        .status
        .code(),
        Some(0)
    );
    assert_eq!(
        run_hyp_with_stdin(
            dir.path(),
            &[
                "session",
                "unsubscribe",
                "sub-gh-1",
                "--session",
                sid,
                "--socket",
                &sock_str,
                "--json"
            ],
            b"",
            &[]
        )
        .await
        .status
        .code(),
        Some(0)
    );
    assert_eq!(
        run_hyp_with_stdin(
            dir.path(),
            &[
                "session",
                "leave",
                "#release",
                "--session",
                sid,
                "--socket",
                &sock_str,
                "--json"
            ],
            b"",
            &[]
        )
        .await
        .status
        .code(),
        Some(0)
    );

    // Final `hyp inspect --json` confirms every single removal took effect cleanly!
    let final_inspect = run_hyp_with_stdin(
        dir.path(),
        &["inspect", "--session", sid, "--socket", &sock_str, "--json"],
        b"",
        &[],
    )
    .await;
    assert_eq!(final_inspect.status.code(), Some(0));
    let final_env = parse_json_stdout(&final_inspect);
    let final_sess = &final_env["data"]["session"];
    assert_eq!(final_sess["focusMode"], false);
    assert_eq!(final_sess["counts"]["subscriptions"], 0);
    assert_eq!(final_sess["counts"]["mutedRules"], 0);
    assert_eq!(final_sess["counts"]["channels"], 1);
    assert!(final_sess["details"]["rules"].as_array().unwrap().is_empty());
    assert_eq!(final_sess["details"]["channels"], json!(["#ops"]));

    // `hyp inspect --all --json` returns sessions array
    let all_out = run_hyp_with_stdin(
        dir.path(),
        &["inspect", "--all", "--socket", &sock_str, "--json"],
        b"",
        &[],
    )
    .await;
    assert_eq!(all_out.status.code(), Some(0));
    let all_env = parse_json_stdout(&all_out);
    assert_eq!(all_env["ok"], true);
    assert_eq!(all_env["data"]["sessions"].as_array().unwrap().len(), 1);

    daemon.stop().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ui_non_tty_fallback_tcp_loopback_parity_and_help_flags() {
    let dir = TempDir::new().unwrap();
    let node = make_test_node("alice@win", &dir);
    let addr_file = dir.path().join("connector.addr");
    let daemon = LocalDaemon::start_tcp(
        Arc::clone(&node),
        None,
        LocalDaemonConfig::default(),
        addr_file.clone(),
    )
    .await
    .unwrap();
    let addr_str = addr_file.to_str().unwrap();

    let sid = "claude:tcp-ui-1";
    node.register_session(sid, r#"{"kind":"claude"}"#).unwrap();
    node.register_handle(sid, "alice").await.unwrap();

    // 1. `hyp statusline` works cleanly over loopback TCP `connector.addr`
    let sl = run_hyp_with_stdin(
        dir.path(),
        &["statusline", "--socket", addr_str, "--plain"],
        br#"{"session_id":"tcp-ui-1"}"#,
        &[],
    )
    .await;
    assert_eq!(sl.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&sl.stdout).trim(), "⟁ @alice");

    // 2. `hyp ui` with non-TTY piped stdout cleanly prints `hyp inspect` output and exits 0 without hanging!
    let ui_out = run_hyp_with_stdin(
        dir.path(),
        &["ui", "--socket", addr_str, "--session", sid],
        b"",
        &[],
    )
    .await;
    assert_eq!(ui_out.status.code(), Some(0));
    let ui_txt = String::from_utf8_lossy(&ui_out.stdout);
    assert!(ui_txt.contains("HYPHAE INSPECT"));
    assert!(ui_txt.contains("@alice"));
    assert!(ui_txt.contains(sid));

    // 3. `--help` works for all 4 new subcommands (verifying statusline fast-path falls through to clap!)
    for sub in ["statusline", "inspect", "session", "ui"] {
        let help = run_hyp_with_stdin(dir.path(), &[sub, "--help"], b"", &[]).await;
        assert_eq!(
            help.status.code(),
            Some(0),
            "hyp {sub} --help failed: {}",
            String::from_utf8_lossy(&help.stderr)
        );
    }

    daemon.stop().await;
}
