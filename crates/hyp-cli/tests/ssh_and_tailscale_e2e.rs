//! End-to-end tests for:
//! 1. Full-stack optional `ssh://` peer transport over `UnifiedNode::serve_unix(peer.sock)` +
//!    real compiled `hyp connect --socket <peer.sock>` via a mock `HYPHAE_SSH_BIN` wrapper:
//!    - Zero listening TCP ports, user-only `0600` `peer.sock`
//!    - `hp2p1_` zero-TOFU mutual pairing & signed manifest verification over `ssh://`
//!    - Bidirectional E2EE DM (`dm.e2ee.v1`) + live SSE `/v1/inbox` delivery over `ssh://`
//!    - E2EE Shared KV (`kv.e2ee.v1`) write/read over `ssh://`
//!    - Streaming E2EE file transfer (`transfer.stream.v2`) over `ssh://`
//!    - Deterministic child-process teardown on `shutdown()` (zero leaked mock ssh PIDs!)
//! 2. CLI `hyp node start --bind none` (SSH-only `peer.sock`), `hyp pair ssh <target>`,
//!    `hyp pair guide`, `hyp status` (`transport=ssh`), and SSH option-injection rejection.
//! 3. Smart Tailscale operational detection in `hyp status` & `hyp doctor` (running + serve
//!    matched -> OK; serve route missing -> WARN with exact fix; stopped with `*.ts.net` ->
//!    FAIL in doctor / WARN in status + `tailscale up`; not installed without `*.ts.net` -> clean OK;
//!    mock `HYPHAE_TAILSCALE_BIN` with permission-denied serve probe -> graceful non-failing OK).

mod common;

use common::{ManagedProcess, hyp_bin, isolated_cmd, parse_json_stdout};
use hyp_crypto::SecretBackend;
use hyp_crypto::transfer::TarInputEntry;
use hyp_node::engine::{KvNamespaceConfig, KvWriteRequest, NodeConfig, UnifiedNode};
use hyp_proto::address::NodeId;
use hyp_proto::manifest::{KvMode, KvWriteModel};
use hyp_proto::scopes::ScopePreset;
use hyp_store::{
    MailboxEntry, MailboxKind, NodeDb, PeerInput, PeerProfile, PeerStatus, TrustTier, WriteModel,
    now_ms,
};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[cfg(unix)]
fn write_executable_script(path: &Path, content: &str) {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, content).expect("write script");
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).expect("chmod 0700 script");
}

#[cfg(unix)]
fn is_pid_alive(pid: i32) -> bool {
    if pid <= 0 {
        return false;
    }
    Command::new("kill")
        .args(["-0", &pid.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(unix)]
fn assert_zero_plaintext_in_sqlite(state_dir: &Path, needle: &str) {
    let needle_bytes = needle.as_bytes();
    for filename in ["node.sqlite", "node.sqlite-wal", "node.sqlite-shm"] {
        let p = state_dir.join(filename);
        if p.exists() {
            let bytes = fs::read(&p).expect("read sqlite file");
            assert!(
                !bytes.windows(needle_bytes.len()).any(|w| w == needle_bytes),
                "SECURITY VIOLATION: found plaintext substring {needle:?} in {}!",
                p.display()
            );
        }
    }
}

#[cfg(unix)]
async fn wait_for_mailbox_item<F>(
    node: &Arc<UnifiedNode>,
    session_id: &str,
    predicate: F,
) -> MailboxEntry
where
    F: Fn(&MailboxEntry) -> bool,
{
    let mut rx = node.subscribe_local_inbox();
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);

    loop {
        let items = node.peek_local_inbox(session_id, 50).expect("peek inbox");
        if let Some(found) = items.into_iter().find(|e| predicate(e)) {
            let _ = node.db().local().acknowledge_inbox(
                session_id,
                &[found.receipt.as_str()],
                now_ms(),
            );
            return found;
        }
        let now = tokio::time::Instant::now();
        assert!(
            now < deadline,
            "timed out waiting for mailbox item on node '{}' session '{session_id}'",
            node.node_id()
        );
        let remaining = deadline - now;
        let _ = tokio::time::timeout(remaining, rx.recv()).await;
    }
}

#[cfg(unix)]
struct EnvRestoreGuard {
    key: &'static str,
    prev: Option<std::ffi::OsString>,
}

#[cfg(unix)]
impl EnvRestoreGuard {
    fn set(key: &'static str, val: &Path) -> Self {
        let prev = std::env::var_os(key);
        // SAFETY: serialized via SSH_ENV_LOCK across tests in this binary.
        unsafe {
            std::env::set_var(key, val);
        }
        Self { key, prev }
    }
}

#[cfg(unix)]
impl Drop for EnvRestoreGuard {
    fn drop(&mut self) {
        // SAFETY: serialized via SSH_ENV_LOCK across tests in this binary.
        unsafe {
            match &self.prev {
                Some(v) => std::env::set_var(self.key, v),
                None => std::env::remove_var(self.key),
            }
        }
    }
}

// ============================================================================
// 1. Full-Stack `ssh://` Transport E2E (`serve_unix` + `hyp connect` + E2EE)
// ============================================================================

#[cfg(unix)]
#[tokio::test]
async fn ssh_transport_full_stack_e2ee_dm_sse_kv_transfer_and_zero_pid_leak() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = TempDir::new().unwrap();
    let solace_dir = tmp.path().join("solace");
    let alice_dir = tmp.path().join("alice");
    fs::create_dir_all(&solace_dir).unwrap();
    fs::create_dir_all(&alice_dir).unwrap();

    // 1. Boot `solace` P2P node serving ONLY on `peer.sock` (ZERO TCP listener!)
    let mut solace_cfg = NodeConfig::p2p(NodeId::new("solace").unwrap(), &solace_dir);
    solace_cfg.secret_backend = Some(SecretBackend::File);
    solace_cfg.public_endpoint = Some("ssh://ops@mock-box".to_string());
    solace_cfg.kv_namespaces.push(KvNamespaceConfig {
        name: "shared".to_string(),
        mode: KvMode::E2ee,
        write_model: KvWriteModel::Shared,
    });
    let solace = UnifiedNode::open(solace_cfg).unwrap();
    let peer_sock = solace_dir.join("peer.sock");
    let (bound_sock, _unix_srv) = Arc::clone(&solace)
        .serve_unix(peer_sock.clone())
        .await
        .unwrap();
    assert_eq!(bound_sock, peer_sock);
    assert_eq!(
        solace.peer_socket_path().as_deref(),
        Some(peer_sock.as_path())
    );

    let sock_mode = fs::metadata(&peer_sock).unwrap().permissions().mode() & 0o777;
    assert_eq!(sock_mode, 0o600, "peer.sock must be user-only 0600");

    // 2. Write a mock `HYPHAE_SSH_BIN` wrapper that logs PID + argv and `exec`s real `hyp connect --socket <peer.sock>`.
    let pid_log = tmp.path().join("ssh-pids.log");
    let argv_log = tmp.path().join("ssh-argv.log");
    let mock_ssh = tmp.path().join("mock-ssh.sh");
    let script = format!(
        "#!/bin/sh\n\
         echo \"$$\" >> '{}'\n\
         printf '%s\\n' \"$*\" >> '{}'\n\
         exec '{}' connect --socket '{}'\n",
        pid_log.display(),
        argv_log.display(),
        hyp_bin(),
        peer_sock.display()
    );
    write_executable_script(&mock_ssh, &script);
    let _env_guard = EnvRestoreGuard::set("HYPHAE_SSH_BIN", &mock_ssh);

    // 3. Boot `alice@macbook` local node and pair with `solace` via `hp2p1_` carrying `ssh://ops@mock-box`.
    let mut alice_cfg = NodeConfig::local(NodeId::new("alice@macbook").unwrap(), &alice_dir);
    alice_cfg.secret_backend = Some(SecretBackend::File);
    let alice = UnifiedNode::open(alice_cfg).unwrap();

    let scopes = ScopePreset::Member.expand();
    let (hp2p1_token, offer) = solace
        .create_p2p_invite(scopes.clone(), scopes.clone(), 300_000)
        .unwrap();
    assert_eq!(offer.endpoint, "ssh://ops@mock-box");

    // Signed manifest verification + P2P mutual handshake over `ssh://`!
    let link_info = alice
        .accept_p2p_invite(&hp2p1_token, scopes.clone())
        .await
        .expect("accept_p2p_invite over ssh:// must succeed");
    assert_eq!(link_info.peer_id, "solace");
    assert_eq!(link_info.endpoint, "ssh://ops@mock-box");

    // Verify ssh wrapper received hardened anti-injection argv (`-o BatchMode=yes ... -T -- ops@mock-box ...`)
    let argv_dump = fs::read_to_string(&argv_log).expect("read ssh argv log");
    assert!(
        argv_dump.contains("-o BatchMode=yes") && argv_dump.contains("-- ops@mock-box"),
        "expected hardened SSH argv, got:\n{argv_dump}"
    );

    // 4. Register sessions/handles on both nodes and verify bidirectional E2EE DM + live SSE over `ssh://`!
    solace.register_session("solace:s1", "{}").unwrap();
    solace.register_handle("solace:s1", "ops").await.unwrap();
    alice.register_session("alice:s1", "{}").unwrap();
    alice.register_handle("alice:s1", "dev").await.unwrap();

    let dm_to_solace_secret = "SSH-E2EE-SECRET-ALICE-TO-SOLACE-99182";
    let sent1 = alice
        .send_dm("dev", "solace/ops", dm_to_solace_secret)
        .await
        .expect("E2EE DM alice -> solace over ssh://");
    assert!(sent1.encrypted, "DM over ssh:// MUST remain E2EE encrypted");

    let recv_on_solace = wait_for_mailbox_item(&solace, "solace:s1", |e| {
        e.kind == MailboxKind::Message && e.text.contains(dm_to_solace_secret)
    })
    .await;
    assert_eq!(recv_on_solace.text, dm_to_solace_secret);

    // Reverse direction: solace -> alice delivered over Alice's persistent SSE `/v1/inbox` SSH stream!
    let dm_to_alice_secret = "SSH-SSE-PUSH-SOLACE-TO-ALICE-77412";
    let sent2 = solace
        .send_dm("ops", "alice@macbook/dev", dm_to_alice_secret)
        .await
        .expect("E2EE DM solace -> alice queued for SSE");
    assert!(
        sent2.encrypted,
        "reverse DM over ssh:// MUST remain E2EE encrypted"
    );

    let recv_on_alice = wait_for_mailbox_item(&alice, "alice:s1", |e| {
        e.kind == MailboxKind::Message && e.text.contains(dm_to_alice_secret)
    })
    .await;
    assert_eq!(recv_on_alice.text, dm_to_alice_secret);

    // 5. E2EE Shared KV (`kv.e2ee.v1`) write & read over `ssh://`!
    let kv_secret = "SSH-KV-E2EE-VALUE-33491";
    let kv_written = alice
        .kv_set(KvWriteRequest {
            host_node: "solace".to_string(),
            namespace: "shared".to_string(),
            key: "deploy/status".to_string(),
            value: json!({ "state": "green", "token": kv_secret }),
            write_model: WriteModel::Shared,
            owner_id: None,
            allowlist: None,
            expected_version: None,
            ttl_ms: None,
            encrypt: true,
            e2ee_members: Some(vec!["alice@macbook".to_string(), "solace".to_string()]),
        })
        .await
        .expect("E2EE KV set over ssh://");
    assert_eq!(kv_written.version, 1);

    // Zero plaintext KV value in solace's SQLite database!
    assert_zero_plaintext_in_sqlite(&solace_dir, kv_secret);

    let kv_read_alice = alice
        .kv_get("solace", "shared", "deploy/status")
        .await
        .expect("KV get over ssh://")
        .expect("KV entry exists");
    assert_eq!(kv_read_alice.value["token"], kv_secret);

    let kv_read_solace = solace
        .kv_get("local", "shared", "deploy/status")
        .await
        .expect("KV get locally on solace")
        .expect("KV entry exists on solace");
    assert_eq!(kv_read_solace.value["token"], kv_secret);

    // 6. Streaming E2EE file transfer (`transfer.stream.v2`) over `ssh://`!
    let file_secret = "SSH-TRANSFER-SECRET-BYTES-55201\nLine 2.\n";
    let src_file_path = alice_dir.join("ssh-report.txt");
    fs::write(&src_file_path, file_secret).unwrap();

    let transfer_res = alice
        .send_files(
            "solace",
            Some("ops"),
            &[TarInputEntry {
                archive_path: "notes/ssh-report.txt".to_string(),
                source_path: src_file_path,
            }],
            None,
        )
        .await
        .expect("streaming E2EE file transfer over ssh://");
    assert!(transfer_res.ciphertext_bytes > 0);
    assert!(transfer_res.plaintext_digest.starts_with("sha256:"));
    assert_eq!(transfer_res.to_node, "solace");

    let recv_transfer = wait_for_mailbox_item(&solace, "solace:s1", |e| {
        e.kind == MailboxKind::Transfer && e.text.contains(&transfer_res.id)
    })
    .await;
    assert!(!recv_transfer.text.contains(file_secret));
    let notice_json: Value = serde_json::from_str(&recv_transfer.text).unwrap();
    assert_eq!(
        notice_json["plaintextDigest"],
        transfer_res.plaintext_digest
    );
    let extracted_path = notice_json["files"][0]["diskPath"]
        .as_str()
        .expect("extracted file diskPath");
    assert_eq!(fs::read_to_string(extracted_path).unwrap(), file_secret);
    assert_zero_plaintext_in_sqlite(&solace_dir, "SSH-TRANSFER-SECRET-BYTES");

    // 7. Deterministic child-process teardown on `shutdown()` (zero leaked mock ssh PIDs!)
    alice.shutdown();
    solace.shutdown();

    let recorded_pids: Vec<i32> = fs::read_to_string(&pid_log)
        .expect("read pid log")
        .lines()
        .filter_map(|l| l.trim().parse::<i32>().ok())
        .collect();
    assert!(
        !recorded_pids.is_empty(),
        "expected mock ssh wrapper to record at least one child PID"
    );

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let alive: Vec<i32> = recorded_pids
            .iter()
            .copied()
            .filter(|&pid| is_pid_alive(pid))
            .collect();
        if alive.is_empty() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "LEAKED SSH CHILD PIDS AFTER shutdown(): {alive:?}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ============================================================================
// 2. CLI `hyp node start --bind none`, `hyp pair ssh`, `hyp pair guide`, `hyp status`
// ============================================================================

#[cfg(unix)]
#[test]
fn cli_hyp_pair_ssh_dry_run_live_handshake_status_and_injection_rejection() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = TempDir::new().unwrap();
    let remote_dir = tmp.path().join("remote-state");
    let local_dir = tmp.path().join("local-state");
    fs::create_dir_all(&remote_dir).unwrap();
    fs::create_dir_all(&local_dir).unwrap();

    // 1. Start a real SSH-only remote node (`--bind none` -> ZERO TCP ports, only `peer.sock` 0600!)
    let mut remote_cmd = isolated_cmd(tmp.path());
    remote_cmd
        .args([
            "node",
            "start",
            "--profile",
            "p2p",
            "--node-id",
            "solace",
            "--bind",
            "none",
            "--no-local-socket",
            "--state-dir",
            remote_dir.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null());
    let mut remote_proc = ManagedProcess::spawn("remote ssh-only node", &mut remote_cmd);
    let startup = remote_proc.read_json_line(Duration::from_secs(10));
    assert_eq!(startup["ok"], true, "remote node start failed: {startup}");
    assert!(
        startup["data"]["bind"].is_null(),
        "expected zero TCP bind in SSH-only mode: {startup}"
    );
    let peer_sock = PathBuf::from(
        startup["data"]["peerSocket"]
            .as_str()
            .expect("peerSocket must be set"),
    );
    assert!(peer_sock.exists(), "peer.sock must exist");
    let mode = fs::metadata(&peer_sock).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "peer.sock must be 0600");

    // 2. Build a mock `ssh` script that executes the final remote command locally (replacing `hyp` with our compiled binary).
    let mock_ssh = tmp.path().join("mock-ssh-cli.sh");
    let bin_dir = tmp.path().join("bin");
    fs::create_dir_all(&bin_dir).unwrap();
    let hyp_link = bin_dir.join("hyp");
    std::os::unix::fs::symlink(hyp_bin(), &hyp_link).unwrap();

    let mock_script = format!(
        "#!/bin/sh\n\
         # Advance past ssh flags and `-- <target>` to the final remote command string.\n\
         while [ \"$#\" -gt 1 ]; do\n\
           shift\n\
         done\n\
         REMOTE_CMD=\"$1\"\n\
         export PATH=\"{}:$PATH\"\n\
         export HYPHAE_SECRET_BACKEND=file\n\
         exec /bin/sh -c \"$REMOTE_CMD\"\n",
        bin_dir.display()
    );
    write_executable_script(&mock_ssh, &mock_script);

    // 3. Dry-run `hyp pair ssh` succeeds without contacting remote host
    let dry_out = isolated_cmd(tmp.path())
        .args([
            "pair",
            "ssh",
            "ops@solace",
            "--node-id",
            "alice@macbook",
            "--remote-state-dir",
            remote_dir.to_str().unwrap(),
            "--state-dir",
            local_dir.to_str().unwrap(),
            "--dry-run",
            "--json",
        ])
        .output()
        .expect("run hyp pair ssh --dry-run");
    assert_eq!(dry_out.status.code(), Some(0));
    let dry_env = parse_json_stdout(&dry_out);
    assert_eq!(dry_env["ok"], true);
    assert_eq!(dry_env["data"]["dryRun"], true);
    assert_eq!(dry_env["data"]["transport"], "ssh");

    // 4. Live one-command `hyp pair ssh ops@solace` over mock SSH!
    let live_out = isolated_cmd(tmp.path())
        .env("HYPHAE_SSH_BIN", &mock_ssh)
        .args([
            "pair",
            "ssh",
            "ops@solace",
            "--node-id",
            "alice@macbook",
            "--remote-state-dir",
            remote_dir.to_str().unwrap(),
            "--state-dir",
            local_dir.to_str().unwrap(),
            "--preset",
            "member",
            "--json",
        ])
        .output()
        .expect("run hyp pair ssh");
    assert_eq!(
        live_out.status.code(),
        Some(0),
        "hyp pair ssh failed: stdout={} stderr={}",
        String::from_utf8_lossy(&live_out.stdout),
        String::from_utf8_lossy(&live_out.stderr)
    );
    let live_env = parse_json_stdout(&live_out);
    assert_eq!(live_env["ok"], true);
    assert_eq!(live_env["data"]["transport"], "ssh");
    assert_eq!(live_env["data"]["peerId"], "solace");
    assert_eq!(live_env["data"]["handshakeCompleted"], true);
    let endpoint_str = live_env["data"]["endpoint"].as_str().unwrap();
    assert!(endpoint_str.starts_with("ssh://ops@solace?stateDir="));
    // Security invariant: stdout JSON must NOT echo raw hp2p1_ secret or authCredential
    let raw_stdout = String::from_utf8_lossy(&live_out.stdout);
    assert!(!raw_stdout.contains("hp2p1_"));

    // 5. `hyp status --json` displays the SSH peer cleanly with `transport: "ssh"` & OK status!
    let status_out = isolated_cmd(tmp.path())
        .args([
            "status",
            "--state-dir",
            local_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run hyp status --json");
    assert_eq!(status_out.status.code(), Some(0));
    let status_env = parse_json_stdout(&status_out);
    let peers = status_env["data"]["peers"].as_array().unwrap();
    let solace_row = peers
        .iter()
        .find(|p| p["peer"] == "solace")
        .expect("solace row in status");
    assert_eq!(solace_row["status"], "ok");
    assert_eq!(solace_row["transport"], "ssh");
    assert_eq!(solace_row["e2ee"], "dm+chan");
    assert_eq!(solace_row["kv"], "kv.e2ee.v1");
    assert!(
        solace_row["notes"]
            .as_str()
            .unwrap_or("")
            .contains("transport=ssh"),
        "expected transport=ssh in notes: {solace_row}"
    );

    // 6. `hyp pair guide --json` advertises all 3 transports (`tailscale`, `https`, `ssh`)
    let guide_out = isolated_cmd(tmp.path())
        .args(["pair", "guide", "--json"])
        .output()
        .expect("run hyp pair guide --json");
    assert_eq!(guide_out.status.code(), Some(0));
    let guide_env = parse_json_stdout(&guide_out);
    let transport_ids: Vec<&str> = guide_env["data"]["transports"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|t| t["id"].as_str())
        .collect();
    assert_eq!(transport_ids, vec!["tailscale", "https", "ssh"]);

    // 7. Fail-closed anti-injection tests on CLI flags
    for bad_target in ["-oProxyCommand=id", "ops@box;id", "ops@box$(id)"] {
        let bad_out = isolated_cmd(tmp.path())
            .args(["pair", "ssh", bad_target, "--dry-run", "--json"])
            .output()
            .expect("run bad pair ssh");
        assert_eq!(
            bad_out.status.code(),
            Some(2),
            "expected usage error for {bad_target:?}: {}",
            String::from_utf8_lossy(&bad_out.stdout)
        );
    }

    let _ = remote_proc.shutdown_gracefully();
}

// ============================================================================
// 3. Smart Tailscale Operational Detection in `hyp status` & `hyp doctor`
// ============================================================================

#[test]
fn cli_tailscale_operational_detection_running_stopped_and_not_installed() {
    let tmp = TempDir::new().unwrap();
    let state_dir = tmp.path().join("state");
    fs::create_dir_all(&state_dir).unwrap();

    // Case 1: Not installed & NO *.ts.net endpoints -> clean OK, installed=false, zero tailscale warnings
    let cfg_local = state_dir.join("node.json");
    fs::write(
        &cfg_local,
        serde_json::to_vec_pretty(&json!({
            "v": 2,
            "nodeId": "dev@box",
            "profile": "local",
            "stateDir": state_dir.display().to_string(),
        }))
        .unwrap(),
    )
    .unwrap();
    let _db = NodeDb::open(state_dir.join("node.sqlite")).unwrap();

    let out_none = isolated_cmd(tmp.path())
        .env("HYPHAE_TAILSCALE_STATUS_JSON", "not_installed")
        .args([
            "doctor",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--config",
            cfg_local.to_str().unwrap(),
            "--home",
            tmp.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run doctor without tailscale");
    assert_eq!(out_none.status.code(), Some(0));
    let env_none = parse_json_stdout(&out_none);
    assert_eq!(env_none["ok"], true);
    assert_eq!(env_none["data"]["tailscale"]["installed"], false);
    assert_eq!(env_none["data"]["tailscale"]["state"], "not_installed");
    let checks_none = env_none["data"]["checks"].as_array().unwrap();
    assert!(
        !checks_none.iter().any(|c| c["name"] == "tailscale"),
        "should not emit alarming tailscale check when unused: {checks_none:?}"
    );

    // Case 2: Router with *.ts.net publicUrl + Tailscale Running + Serve matched -> OK
    let cfg_ts = state_dir.join("router.json");
    fs::write(
        &cfg_ts,
        serde_json::to_vec_pretty(&json!({
            "v": 2,
            "nodeId": "acme-tailnet",
            "profile": "router",
            "deploymentProvider": "tailscale",
            "stateDir": state_dir.display().to_string(),
            "listen": {
                "bind": "127.0.0.1:8790",
                "publicUrl": "https://acme.tail9f3a.ts.net"
            }
        }))
        .unwrap(),
    )
    .unwrap();

    let running_json = r#"{"BackendState":"Running","Self":{"DNSName":"acme.tail9f3a.ts.net.","TailscaleIPs":["100.64.0.9"],"Online":true}}"#;
    let serve_ok_json = r#"{"TCP":{"443":{"HTTPS":true}},"Web":{"acme.tail9f3a.ts.net:443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:8790"}}}}}"#;

    let out_ok = isolated_cmd(tmp.path())
        .env("HYPHAE_TAILSCALE_STATUS_JSON", running_json)
        .env("HYPHAE_TAILSCALE_SERVE_STATUS_JSON", serve_ok_json)
        .args([
            "doctor",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--config",
            cfg_ts.to_str().unwrap(),
            "--home",
            tmp.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run doctor with running tailscale + matched serve");
    assert_eq!(out_ok.status.code(), Some(0));
    let env_ok = parse_json_stdout(&out_ok);
    assert_eq!(env_ok["ok"], true);
    assert_eq!(env_ok["data"]["tailscale"]["state"], "running");
    assert_eq!(
        env_ok["data"]["tailscale"]["dnsName"],
        "acme.tail9f3a.ts.net"
    );
    assert_eq!(env_ok["data"]["tailscale"]["serve"]["exposed"], true);
    let checks_ok = env_ok["data"]["checks"].as_array().unwrap();
    assert!(
        checks_ok
            .iter()
            .any(|c| c["name"] == "tailscale" && c["status"] == "ok")
    );
    assert!(
        checks_ok
            .iter()
            .any(|c| c["name"] == "tailscale.serve" && c["status"] == "ok")
    );

    // Case 3: Running + Serve route MISSING -> WARN with exact `tailscale serve --bg --https=443 http://127.0.0.1:8790`
    let out_missing_serve = isolated_cmd(tmp.path())
        .env("HYPHAE_TAILSCALE_STATUS_JSON", running_json)
        .env("HYPHAE_TAILSCALE_SERVE_STATUS_JSON", "{}")
        .args([
            "doctor",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--config",
            cfg_ts.to_str().unwrap(),
            "--home",
            tmp.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run doctor with missing serve route");
    assert_eq!(out_missing_serve.status.code(), Some(0));
    let env_miss = parse_json_stdout(&out_missing_serve);
    assert_eq!(env_miss["data"]["tailscale"]["serve"]["exposed"], false);
    let serve_check = env_miss["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "tailscale.serve")
        .expect("tailscale.serve check");
    assert_eq!(serve_check["status"], "warn");
    assert_eq!(
        serve_check["fix"],
        "tailscale serve --bg --https=443 http://127.0.0.1:8790"
    );

    // Case 4: Tailscale Stopped with a `*.ts.net` peer in node.sqlite -> FAIL in doctor, WARN in status, with `tailscale up` next step
    {
        let db = NodeDb::open(state_dir.join("node.sqlite")).unwrap();
        db.peers()
            .upsert_peer(
                &PeerInput {
                    peer_id: "bob@laptop".to_string(),
                    endpoint: Some("https://bob.tail9f3a.ts.net".to_string()),
                    profile: PeerProfile::P2p,
                    trust_tier: TrustTier::Peer,
                    status: PeerStatus::Active,
                    scopes: ScopePreset::Member.expand(),
                    auth_credential_ref: None,
                },
                now_ms(),
            )
            .unwrap();
    }
    let stopped_json =
        r#"{"BackendState":"Stopped","Self":{"DNSName":"acme.tail9f3a.ts.net.","Online":false}}"#;

    let doc_stopped = isolated_cmd(tmp.path())
        .env("HYPHAE_TAILSCALE_STATUS_JSON", stopped_json)
        .args([
            "doctor",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--config",
            cfg_local.to_str().unwrap(),
            "--home",
            tmp.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run doctor with stopped tailscale + ts.net peer");
    assert_eq!(doc_stopped.status.code(), Some(1));
    let doc_env = parse_json_stdout(&doc_stopped);
    assert_eq!(doc_env["ok"], false);
    let ts_fail = doc_env["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "tailscale")
        .expect("tailscale fail check");
    assert_eq!(ts_fail["status"], "fail");
    assert!(
        doc_env["next"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str().unwrap_or("").contains("tailscale up")),
        "expected `tailscale up` in next steps: {doc_env}"
    );

    let st_stopped = isolated_cmd(tmp.path())
        .env("HYPHAE_TAILSCALE_STATUS_JSON", stopped_json)
        .args([
            "status",
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--config",
            cfg_local.to_str().unwrap(),
            "--home",
            tmp.path().to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run status with stopped tailscale + ts.net peer");
    assert_eq!(st_stopped.status.code(), Some(0));
    let st_env = parse_json_stdout(&st_stopped);
    let ts_warn = st_env["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "tailscale")
        .expect("tailscale warn check");
    assert_eq!(ts_warn["status"], "warn");

    // Case 5: Real bounded subprocess probe via mock `HYPHAE_TAILSCALE_BIN` with permission-denied serve check
    #[cfg(unix)]
    {
        let mock_ts = tmp.path().join("mock-tailscale.sh");
        write_executable_script(
            &mock_ts,
            "#!/bin/sh\n\
             if [ \"$1\" = \"status\" ]; then\n\
               printf '%s\\n' '{\"BackendState\":\"Running\",\"Self\":{\"DNSName\":\"acme.tail9f3a.ts.net.\",\"TailscaleIPs\":[\"100.64.0.9\"],\"Online\":true}}'\n\
               exit 0\n\
             fi\n\
             if [ \"$1\" = \"serve\" ]; then\n\
               echo 'Access denied: serve config denied' >&2\n\
               exit 1\n\
             fi\n\
             exit 1\n",
        );

        let perm_out = isolated_cmd(tmp.path())
            .env("HYPHAE_TAILSCALE_BIN", &mock_ts)
            .args([
                "doctor",
                "--state-dir",
                state_dir.to_str().unwrap(),
                "--config",
                cfg_ts.to_str().unwrap(),
                "--home",
                tmp.path().to_str().unwrap(),
                "--json",
            ])
            .output()
            .expect("run doctor with mock tailscale binary");
        // Note: bob@laptop peer was inserted without cached v2 manifest above, so check tailscale checks specifically!
        let perm_env = parse_json_stdout(&perm_out);
        assert_eq!(perm_env["data"]["tailscale"]["state"], "running");
        assert_eq!(perm_env["data"]["tailscale"]["serve"]["checked"], false);
        let checks = perm_env["data"]["checks"].as_array().unwrap();
        assert!(
            checks
                .iter()
                .any(|c| c["name"] == "tailscale" && c["status"] == "ok"),
            "permission error on `tailscale serve status` must NOT fail tailscale check: {checks:?}"
        );
    }
}
