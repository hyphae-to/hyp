//! Level 5-7 E2E tests for Wave 2: Ops, Reload, Keystore Safety & Release Signing Hardening
//! (`D10`, `D16`, `R1`, `H4`, `H6`, `H18`, `R6`, `R3`, `R4`, `R5`/`D9`, `D7`).

mod common;

#[cfg(unix)]
use common::{ManagedProcess, run_hyp_in_pty};
use common::{hyp_bin, isolated_cmd, parse_json_stdout, repo_plugins_dir};
use http::{Method, Request, Response, StatusCode, header};
use http_body_util::Full;
use hyp_crypto::CryptoError;
#[cfg(unix)]
use hyp_crypto::human::SignedHumanRevocationV1;
use hyp_crypto::human::{HumanAudience, HumanClaimV1, HumanDropKind, encode_hdrop1, seal_human_drop};
use hyp_crypto::keys::Ed25519KeyPair;
use hyp_crypto::keystore::{
    SecretBackend, SecretStore, classify_linux_secret_service_output, classify_mac_keychain_output,
    node_key_secret_names,
};
use hyp_crypto::rfc3339::{format_rfc3339_millis, now_unix_ms};
use hyp_crypto::transfer::{TarInputEntry, TarPackOptions, pack_tar_gz};
use hyp_node::adapters::{
    AdapterError, AdapterHealth, AdapterKind, BoxFuture as AdapterBoxFuture, HelloMode,
    NodeAdapter, NodeAdapterHost, PublishOutcome, PublishStatus, SubprocessConfig,
    SubprocessSupervisor,
};
#[cfg(unix)]
use hyp_node::engine::{NodeConfig, NodeProfile, UnifiedNode};
#[cfg(unix)]
use hyp_proto::address::NodeId;
use hyp_proto::cloudevent::CloudEvent;
#[cfg(unix)]
use hyp_proto::cloudevent::TYPE_HUMAN_REVOCATION_V1;
use hyp_proto::rpc::EventKeyRef;
#[cfg(unix)]
use hyp_store::{
    DeliveryMode, HumanAuthorityInput, HumanAuthorityRole, NodeDb, SubscriptionSpec, now_ms,
};
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as AutoServerBuilder;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::convert::Infallible;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::net::TcpListener;

#[cfg(unix)]
const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

// ============================================================================
// 1. D10 & D16 — Keystore Safety (Never Silently Regenerate Keys) & Service CLI
// ============================================================================

#[test]
fn d10_keystore_backend_errors_and_partial_keys_never_silently_regenerate() {
    let tmp = TempDir::new().unwrap();
    let store = SecretStore::file_only(tmp.path());

    // 1. Pure classifier checks for macOS Keychain & Linux Secret Service backend errors.
    assert!(
        classify_mac_keychain_output("node-sign-abc", Some(44), b"", "errSecItemNotFound")
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        classify_mac_keychain_output(
            "node-sign-abc",
            Some(36),
            b"",
            "security: SecKeychainSearchCopyNext: User interaction is not allowed."
        ),
        Err(CryptoError::Keystore(_))
    ));
    assert!(
        classify_linux_secret_service_output("node-sign-abc", Some(0), b"", "")
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        classify_linux_secret_service_output(
            "node-sign-abc",
            Some(1),
            b"",
            "secret-tool: Cannot autolaunch D-Bus without X11 $DISPLAY"
        ),
        Err(CryptoError::Keystore(_))
    ));

    // 2. Create a valid node identity and record its exact fingerprints.
    let orig = store.load_or_create_node_keys("d10-node@box").unwrap();
    let (v2_sign, v2_enc) = node_key_secret_names("d10-node@box");
    let sign_path = store.secret_file_path(&v2_sign).unwrap();
    let enc_path = store.secret_file_path(&v2_enc).unwrap();
    let orig_sign_bytes = fs::read(&sign_path).unwrap();

    // 3. Backend read error (overly broad 0644 file permissions on Unix) -> MUST fail closed
    //    without regenerating or modifying the existing key file!
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&sign_path, fs::Permissions::from_mode(0o644)).unwrap();
        let err = store
            .load_or_create_node_keys("d10-node@box")
            .expect_err("permission error must fail closed without regenerating keys");
        assert!(matches!(err, CryptoError::Keystore(_)), "got {err:?}");
        assert_eq!(
            fs::read(&sign_path).unwrap(),
            orig_sign_bytes,
            "existing signing key must remain untouched"
        );
        fs::set_permissions(&sign_path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            store.load_or_create_node_keys("d10-node@box").unwrap().kid(),
            orig.kid()
        );
    }

    // 4. Key recorded in secrets/index.json but missing on disk -> MUST fail closed!
    fs::remove_file(&sign_path).unwrap();
    let err = store
        .load_or_create_node_keys("d10-node@box")
        .expect_err("missing indexed key must fail closed");
    assert!(matches!(err, CryptoError::Keystore(_)), "got {err:?}");
    assert!(!sign_path.exists());

    // Restore signing key, then remove encryption key from index+disk (sibling still exists) -> fail closed!
    fs::write(&sign_path, &orig_sign_bytes).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&sign_path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(store.delete(&v2_enc).unwrap());
    let err = store
        .load_or_create_node_keys("d10-node@box")
        .expect_err("missing sibling key must fail closed");
    assert!(matches!(err, CryptoError::Keystore(_)), "got {err:?}");
    assert!(!enc_path.exists());

    // 5. Unsupported OS backend fails closed without writing anything to secrets/.
    let bad_tmp = TempDir::new().unwrap();
    #[cfg(target_os = "macos")]
    let unsupported_backend = SecretBackend::SecretService;
    #[cfg(not(target_os = "macos"))]
    let unsupported_backend = SecretBackend::Keychain;
    let bad_store = SecretStore::new(bad_tmp.path(), unsupported_backend);
    assert!(matches!(
        bad_store.load_or_create_node_keys("unsupported@box"),
        Err(CryptoError::Keystore(_))
    ));
    assert!(!bad_store.secrets_dir().exists());

    // 6. Verify `hyp service install --help` exposes `--state-dir` (`D16`).
    let help_out = isolated_cmd(tmp.path())
        .args(["service", "install", "--help"])
        .output()
        .expect("run hyp service install --help");
    assert_eq!(help_out.status.code(), Some(0));
    let help_txt = String::from_utf8_lossy(&help_out.stdout);
    assert!(
        help_txt.contains("--state-dir"),
        "expected --state-dir flag in `hyp service install --help`: {help_txt}"
    );
}

// ============================================================================
// 2. R1 & H4 — `hyp auth` Hot-Reloads Locked Gate + `--broadcast` Revocation
// ============================================================================

#[cfg(unix)]
#[test]
fn r1_auth_mutations_live_reload_locked_gate_and_h4_broadcasts_revocation() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().to_path_buf();
    let state_dir = home.join("state");
    fs::create_dir_all(&state_dir).unwrap();
    let state_str = state_dir.to_str().unwrap();

    // 1. Start live `hyp daemon` subprocess.
    let mut daemon_cmd = isolated_cmd(&home);
    daemon_cmd
        .args([
            "daemon",
            "--profile",
            "local",
            "--node-id",
            "auth-hot@box",
            "--state-dir",
            state_str,
            "--json",
        ])
        .stdin(Stdio::null());
    let mut daemon = ManagedProcess::spawn("auth-hot@box daemon", &mut daemon_cmd);
    let startup = daemon.read_json_line(STARTUP_TIMEOUT);
    assert_eq!(startup["ok"], true, "daemon startup failed: {startup}");

    // 2. Initialize local admin authority (`hyp auth init`), configure & lock gate (`hyp gate init` + `hyp gate lock`).
    let init_out = isolated_cmd(&home)
        .args([
            "auth",
            "init",
            "--human-id",
            "alice",
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run auth init");
    assert_eq!(init_out.status.code(), Some(0));
    let init_json = parse_json_stdout(&init_out);
    assert_eq!(init_json["ok"], true);
    let alice_kid = init_json["data"]["kid"].as_str().unwrap().to_string();
    let alice_jwk_json = serde_json::to_string(&init_json["data"]["publicJwk"]).unwrap();

    // Configure a Stage-1-only gate policy (zero external LLM / Ollama calls) and lock it.
    fs::write(
        state_dir.join("node.json"),
        serde_json::to_string_pretty(&json!({
            "version": 2,
            "nodeId": "auth-hot@box",
            "profile": "local",
            "gate": {
                "filters": []
            }
        }))
        .unwrap(),
    )
    .unwrap();

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
    assert_eq!(lock_json["data"]["daemonReloaded"], true);

    // 3. Enroll a second human authority (`bob`) while locked daemon is LIVE!
    let bob_kp = Ed25519KeyPair::generate().unwrap();
    let bob_jwk = serde_json::to_string(&bob_kp.to_jwk()).unwrap();
    let add_out = run_hyp_in_pty(
        &home,
        &[
            "auth",
            "add",
            "--human-id",
            "bob",
            "--label",
            "phone-key",
            "--state-dir",
            state_str,
            "--json",
        ],
        Some(&bob_jwk),
        Some("y\n"),
    );
    assert_eq!(
        add_out.code, 0,
        "stdout={} tty={}",
        add_out.stdout, add_out.tty
    );
    let add_json = add_out.parse_json();
    assert_eq!(add_json["ok"], true);
    assert_eq!(add_json["data"]["gatePolicyResigned"], true);
    assert_eq!(
        add_json["data"]["gateReloaded"], true,
        "R1: hyp auth add MUST hot-reload running locked daemon: {add_json}"
    );
    assert!(
        add_json
            .get("warnings")
            .and_then(Value::as_array)
            .map(|a| a.is_empty())
            .unwrap_or(true),
        "expected zero warnings when live gate reload succeeded: {add_json}"
    );
    let bob_kid = add_json["data"]["kid"].as_str().unwrap().to_string();

    // 4. Verify live daemon does NOT quarantine traffic after `hyp auth add`!
    let emit_after_add = isolated_cmd(&home)
        .args([
            "emit",
            "--note",
            "traffic-after-auth-add",
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run hyp emit after auth add");
    assert_eq!(
        emit_after_add.status.code(),
        Some(0),
        "locked daemon must NOT quarantine traffic after live auth add reload! stdout={} stderr={}",
        String::from_utf8_lossy(&emit_after_add.stdout),
        String::from_utf8_lossy(&emit_after_add.stderr)
    );
    assert_eq!(parse_json_stdout(&emit_after_add)["data"]["decision"], "allow");

    // 4b. Subscribe a paired peer (`peer-b@box`) to `human.revocations` BEFORE revoking with `--broadcast`!
    {
        let db = NodeDb::open(state_dir.join("node.sqlite")).unwrap();
        db.events()
            .upsert_subscription(
                &SubscriptionSpec {
                    id: "sub-peer-b-revocations".to_string(),
                    origin_node: "auth-hot@box".to_string(),
                    topic: "human.revocations".to_string(),
                    subscriber: "peer-b@box".to_string(),
                    filters: Vec::new(),
                    coalesce_seconds: 0,
                    max_batch_age_ms: None,
                    max_wakes_per_hour: None,
                    mode: DeliveryMode::Full,
                },
                now_ms(),
            )
            .unwrap();
    }

    // 5. Revoke `bob` with `--bump-epoch --broadcast` while locked daemon is LIVE!
    let rev_out = run_hyp_in_pty(
        &home,
        &[
            "auth",
            "revoke",
            &bob_kid,
            "--bump-epoch",
            "--broadcast",
            "--reason",
            "lost phone",
            "--state-dir",
            state_str,
            "--json",
        ],
        None,
        Some("y\n"),
    );
    assert_eq!(
        rev_out.code, 0,
        "stdout={} tty={}",
        rev_out.stdout, rev_out.tty
    );
    let rev_json = rev_out.parse_json();
    assert_eq!(rev_json["ok"], true);
    assert_eq!(rev_json["data"]["gatePolicyResigned"], true);
    assert_eq!(
        rev_json["data"]["gateReloaded"], true,
        "R1: hyp auth revoke MUST hot-reload running locked daemon: {rev_json}"
    );
    assert_eq!(
        rev_json["data"]["broadcasted"], true,
        "H4: --broadcast must publish revocation event: {rev_json}"
    );
    assert_eq!(rev_json["data"]["broadcastTopic"], "human.revocations");
    assert_eq!(
        rev_json["data"]["broadcastEventType"],
        TYPE_HUMAN_REVOCATION_V1
    );

    // 6. Verify live daemon STILL allows traffic after `hyp auth revoke`!
    let emit_after_rev = isolated_cmd(&home)
        .args([
            "emit",
            "--note",
            "traffic-after-auth-revoke",
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run hyp emit after auth revoke");
    assert_eq!(
        emit_after_rev.status.code(),
        Some(0),
        "locked daemon must NOT quarantine traffic after live auth revoke reload! stdout={}",
        String::from_utf8_lossy(&emit_after_rev.stdout)
    );
    assert_eq!(parse_json_stdout(&emit_after_rev)["data"]["decision"], "allow");

    // 7. Verify the `to.hyphae.human.revocation.v1` CloudEvent was matched into `peer-b@box`'s
    //    `human.revocations` EventStore batch AND a second peer node can ingest it via `ingest_human_revocation`!
    let signed_rev: SignedHumanRevocationV1 = {
        let db = NodeDb::open(state_dir.join("node.sqlite")).unwrap();
        let future_now = now_ms() + 10_000;
        let _ = db.events().tick(future_now);
        let batches = db
            .events()
            .claim_due_batches("peer-b@box", future_now)
            .unwrap();
        assert!(
            !batches.is_empty(),
            "expected subscribed peer 'peer-b@box' to receive human.revocations batch"
        );
        let ev = batches
            .iter()
            .flat_map(|b| b.events.iter())
            .find(|e| e.event_type == TYPE_HUMAN_REVOCATION_V1)
            .expect("expected to.hyphae.human.revocation.v1 CloudEvent in peer batch");
        serde_json::from_value(ev.data.clone()).unwrap()
    };

    let peer_tmp = TempDir::new().unwrap();
    let mut peer_cfg = NodeConfig::new(
        NodeId::new("peer-b@box").unwrap(),
        NodeProfile::Local,
        peer_tmp.path(),
    );
    peer_cfg.secret_backend = Some(SecretBackend::File);
    let peer_node = UnifiedNode::open(peer_cfg).unwrap();
    {
        let pdb = peer_node.db();
        pdb.human()
            .upsert_authority(
                &HumanAuthorityInput {
                    human_id: "alice".to_string(),
                    kid: alice_kid.clone(),
                    label: "alice-admin".to_string(),
                    role: HumanAuthorityRole::Admin,
                    jwk_json: alice_jwk_json,
                    enc_jwk_json: None,
                    prf_salt: None,
                    auth_epoch: 1,
                },
                now_ms(),
            )
            .unwrap();
        pdb.human()
            .upsert_authority(
                &HumanAuthorityInput {
                    human_id: "bob".to_string(),
                    kid: bob_kid.clone(),
                    label: "phone-key".to_string(),
                    role: HumanAuthorityRole::Signer,
                    jwk_json: bob_jwk,
                    enc_jwk_json: None,
                    prf_salt: None,
                    auth_epoch: 1,
                },
                now_ms(),
            )
            .unwrap();
    }
    peer_node
        .ingest_human_revocation(&signed_rev)
        .expect("paired peer must accept broadcasted SignedHumanRevocationV1");
    {
        let pdb = peer_node.db();
        assert!(pdb.human().get_active_authority_by_kid(&bob_kid).unwrap().is_none());
        assert_eq!(pdb.human().min_auth_epoch().unwrap(), 2);
    }

    // 8. Shut down daemon and verify offline `hyp auth add` on a locked gate emits warning + restart hint!
    let _ = daemon.shutdown_gracefully();
    let carol_kp = Ed25519KeyPair::generate().unwrap();
    let carol_jwk = serde_json::to_string(&carol_kp.to_jwk()).unwrap();
    let add2_out = run_hyp_in_pty(
        &home,
        &[
            "auth",
            "add",
            "--human-id",
            "carol",
            "--label",
            "backup",
            "--state-dir",
            state_str,
            "--json",
        ],
        Some(&carol_jwk),
        Some("y\n"),
    );
    assert_eq!(add2_out.code, 0, "tty={}", add2_out.tty);
    let add2_json = add2_out.parse_json();
    assert_eq!(add2_json["data"]["gatePolicyResigned"], true);
    assert_eq!(add2_json["data"]["gateReloaded"], false);
    assert!(
        !add2_json["warnings"].as_array().unwrap().is_empty(),
        "offline locked auth mutation must emit warning: {add2_json}"
    );
    assert!(
        add2_json["next"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some("hyp service restart --json")),
        "offline locked auth mutation must recommend `hyp service restart --json`: {add2_json}"
    );
}

// ============================================================================
// 3. R3 — Supervisor Fresh `{secret}` Resolution on Respawn + `hyp secret` Warnings
// ============================================================================

struct NoopAdapterHost;

impl NodeAdapterHost for NoopAdapterHost {
    fn publish_event<'a>(
        &'a self,
        _to: &'a str,
        _event: CloudEvent,
    ) -> AdapterBoxFuture<'a, Result<PublishOutcome, AdapterError>> {
        Box::pin(async {
            Ok(PublishOutcome {
                status: PublishStatus::Stored,
                matched: 0,
            })
        })
    }

    fn update_status<'a>(
        &'a self,
        _adapter_id: &'a str,
        _health: AdapterHealth,
    ) -> AdapterBoxFuture<'a, ()> {
        Box::pin(async {})
    }

    fn report_delivery_failed<'a>(
        &'a self,
        _adapter_id: &'a str,
        _target: &'a str,
        _events: Vec<EventKeyRef>,
        _reason: &'a str,
    ) -> AdapterBoxFuture<'a, ()> {
        Box::pin(async {})
    }
}

#[cfg(unix)]
#[test]
fn r3_supervisor_invokes_fresh_env_resolver_on_respawn_and_redacts_rotated_secret() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    rt.block_on(async {
        let tmp = TempDir::new().unwrap();
        let store = SecretStore::file_only(tmp.path());
        store
            .set("rot-bot-token", "ROT_SECRET_V1_INITIAL")
            .unwrap();

        let trace_file = tmp.path().join("env_trace.log");
        let gate_file = tmp.path().join("allow_second_run");
        let script_path = tmp.path().join("plugin.sh");
        let script = format!(
            "#!/bin/sh\n\
             printf '%s\\n' \"$CUSTOM_BOT_CRED\" >> \"{}\"\n\
             printf 'stderr_echo=%s\\n' \"$CUSTOM_BOT_CRED\" >&2\n\
             if [ ! -f \"{}\" ]; then\n\
               exit 1\n\
             fi\n\
             sleep 30\n",
            trace_file.display(),
            gate_file.display()
        );
        fs::write(&script_path, script).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&script_path, fs::Permissions::from_mode(0o755)).unwrap();
        }

        let mut cfg = SubprocessConfig::new(
            "rot-plugin",
            AdapterKind::Bridge,
            "/bin/sh",
            vec![script_path.display().to_string()],
            vec!["ops".to_string()],
        );
        cfg.hello_mode = HelloMode::Auto;
        cfg.initial_backoff = Duration::from_millis(80);
        cfg.max_backoff = Duration::from_millis(120);
        cfg.max_rapid_crashes = 0;

        let store_clone = store.clone();
        cfg.env_resolver = Some(Arc::new(move || {
            let val = store_clone
                .get("rot-bot-token")
                .map_err(|e| e.to_string())?;
            let mut m = BTreeMap::new();
            // Intentionally use a non-TOKEN/SECRET name to verify env_resolver values are ALSO redacted!
            m.insert("CUSTOM_BOT_CRED".to_string(), (*val).clone());
            Ok(m)
        }));

        let sup = SubprocessSupervisor::new(cfg);
        let host: Arc<dyn NodeAdapterHost> = Arc::new(NoopAdapterHost);
        sup.start(host).await.unwrap();

        // Wait until first spawn wrote V1 to trace_file.
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(contents) = fs::read_to_string(&trace_file) {
                if contents.contains("ROT_SECRET_V1_INITIAL") {
                    break;
                }
            }
            assert!(Instant::now() < deadline, "timed out waiting for initial spawn");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        // Rotate secret in SecretStore and let the respawned child stay alive.
        store
            .set("rot-bot-token", "ROT_SECRET_V2_UPDATED")
            .unwrap();
        fs::write(&gate_file, b"go").unwrap();

        // Wait until respawned child observes V2!
        let deadline2 = Instant::now() + Duration::from_secs(5);
        loop {
            if let Ok(contents) = fs::read_to_string(&trace_file) {
                if contents.contains("ROT_SECRET_V2_UPDATED") {
                    break;
                }
            }
            assert!(
                Instant::now() < deadline2,
                "timed out waiting for respawn to pick up rotated secret; trace={:?}",
                fs::read_to_string(&trace_file)
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }

        // Give stderr drainer a brief moment, then stop supervisor.
        tokio::time::sleep(Duration::from_millis(50)).await;
        sup.stop().await.unwrap();

        let stderr_lines = sup.recent_stderr();
        assert!(
            stderr_lines.iter().any(|l| l.contains("[REDACTED]")),
            "expected redacted stderr lines: {stderr_lines:?}"
        );
        for line in &stderr_lines {
            assert!(
                !line.contains("ROT_SECRET_V1_INITIAL")
                    && !line.contains("ROT_SECRET_V2_UPDATED"),
                "raw secret leaked into supervisor stderr: {line}"
            );
        }
    });
}

#[test]
fn r3_secret_set_and_delete_warn_when_referenced_in_node_json() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().to_path_buf();
    let state_dir = home.join("state");
    fs::create_dir_all(&state_dir).unwrap();
    let state_str = state_dir.to_str().unwrap();

    fs::write(
        state_dir.join("node.json"),
        serde_json::to_string_pretty(&json!({
            "version": 2,
            "nodeId": "sec-warn@box",
            "profile": "local",
            "plugins": [
                {
                    "id": "telegram",
                    "command": "node",
                    "args": ["/tmp/tg.mjs"],
                    "targets": ["personal"],
                    "env": {
                        "TELEGRAM_BOT_TOKEN": { "secret": "tg-bot-token" }
                    }
                }
            ],
            "sources": [
                {
                    "id": "github-public",
                    "kind": "github-public",
                    "repoTokens": {
                        "acme/*": { "secret": "gh-acme-token" }
                    }
                }
            ],
            "pairing": {
                "adminKey": { "secret": "org-admin-pubkey" }
            }
        }))
        .unwrap(),
    )
    .unwrap();

    // 1. Referenced plugin secret -> warns & suggests `hyp service restart --json`.
    let mut set_tg = isolated_cmd(&home)
        .args(["secret", "set", "tg-bot-token", "--state-dir", state_str, "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    set_tg.stdin.take().unwrap().write_all(b"tg-val-123").unwrap();
    let set_tg_out = set_tg.wait_with_output().unwrap();
    assert_eq!(set_tg_out.status.code(), Some(0));
    let set_tg_json = parse_json_stdout(&set_tg_out);
    assert!(
        set_tg_json["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap_or("").contains("plugins[telegram].env.TELEGRAM_BOT_TOKEN")),
        "expected plugin reference warning: {set_tg_json}"
    );
    assert!(
        set_tg_json["next"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n.as_str() == Some("hyp service restart --json")),
        "expected restart hint: {set_tg_json}"
    );

    // 2. Referenced source secret -> warns & suggests restart.
    let mut set_gh = isolated_cmd(&home)
        .args(["secret", "set", "gh-acme-token", "--state-dir", state_str, "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    set_gh.stdin.take().unwrap().write_all(b"gh-val-456").unwrap();
    let set_gh_out = set_gh.wait_with_output().unwrap();
    assert_eq!(set_gh_out.status.code(), Some(0));
    let set_gh_json = parse_json_stdout(&set_gh_out);
    assert!(
        set_gh_json["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap_or("").contains("sources[github-public]")),
        "expected source reference warning: {set_gh_json}"
    );
    assert!(
        set_gh_json["next"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n.as_str() == Some("hyp service restart --json"))
    );

    // 3. Unreferenced secret -> no warning and no restart hint.
    let mut set_unref = isolated_cmd(&home)
        .args(["secret", "set", "unused-secret", "--state-dir", state_str, "--json"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    set_unref.stdin.take().unwrap().write_all(b"unused-val").unwrap();
    let set_unref_out = set_unref.wait_with_output().unwrap();
    assert_eq!(set_unref_out.status.code(), Some(0));
    let set_unref_json = parse_json_stdout(&set_unref_out);
    assert!(
        set_unref_json
            .get("warnings")
            .and_then(Value::as_array)
            .map(|a| a.is_empty())
            .unwrap_or(true),
        "expected no warnings for unreferenced secret: {set_unref_json}"
    );
    assert!(
        !set_unref_json
            .get("next")
            .and_then(Value::as_array)
            .map(|arr| arr
                .iter()
                .any(|n| n.as_str() == Some("hyp service restart --json")))
            .unwrap_or(false)
    );

    // 4. Delete referenced secret -> warns & suggests restart.
    let del_out = isolated_cmd(&home)
        .args(["secret", "delete", "tg-bot-token", "--state-dir", state_str, "--json"])
        .output()
        .unwrap();
    assert_eq!(del_out.status.code(), Some(0));
    let del_json = parse_json_stdout(&del_out);
    assert!(
        del_json["warnings"]
            .as_array()
            .unwrap()
            .iter()
            .any(|w| w.as_str().unwrap_or("").contains("tg-bot-token")),
        "expected delete warning: {del_json}"
    );
    assert!(
        del_json["next"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n.as_str() == Some("hyp service restart --json"))
    );
}

// ============================================================================
// 4. R4 — `hyp plugin remove` Cleans `node.json` + Query-String Stripping
// ============================================================================

#[test]
fn r4_plugin_remove_cleans_node_json_and_strips_source_location_query_string() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().to_path_buf();
    let state_dir = home.join("state");
    fs::create_dir_all(&state_dir).unwrap();
    let state_str = state_dir.to_str().unwrap();

    // 1. Install telegram & slack from local repo plugins dir.
    for plugin in ["telegram", "slack"] {
        let out = isolated_cmd(&home)
            .args(["plugin", "install", plugin, "--state-dir", state_str, "--json"])
            .output()
            .expect("install plugin");
        assert_eq!(
            out.status.code(),
            Some(0),
            "install {plugin} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    let tg_script = state_dir
        .join("plugins")
        .join("telegram")
        .join("index.mjs")
        .display()
        .to_string();
    let slack_script = state_dir
        .join("plugins")
        .join("slack")
        .join("index.mjs")
        .display()
        .to_string();
    let node_json_path = state_dir.join("node.json");
    fs::write(
        &node_json_path,
        serde_json::to_string_pretty(&json!({
            "version": 2,
            "nodeId": "plug-rm@box",
            "profile": "local",
            "plugins": [
                {
                    "id": "telegram",
                    "command": "node",
                    "args": [tg_script],
                    "targets": ["personal"]
                },
                {
                    "id": "custom-tg-alias",
                    "command": "node",
                    "args": [tg_script],
                    "targets": ["alerts"]
                },
                {
                    "id": "slack",
                    "command": "node",
                    "args": [slack_script],
                    "targets": ["team"]
                }
            ]
        }))
        .unwrap(),
    )
    .unwrap();

    // 2. `--keep-config` removes files on disk while preserving node.json untouched.
    let keep_out = isolated_cmd(&home)
        .args([
            "plugin",
            "remove",
            "telegram",
            "--keep-config",
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(keep_out.status.code(), Some(0));
    let keep_json = parse_json_stdout(&keep_out);
    assert_eq!(keep_json["data"]["removedConfigEntries"], json!([]));
    let cfg_after_keep: Value =
        serde_json::from_str(&fs::read_to_string(&node_json_path).unwrap()).unwrap();
    assert_eq!(cfg_after_keep["plugins"].as_array().unwrap().len(), 3);

    // 3. Reinstall telegram, then run `hyp plugin remove telegram` (default) -> cleans both matching
    //    `plugins[]` entries (`id == telegram` and `args` pointing into `plugins/telegram/`), preserves `slack`,
    //    and emits `hyp service restart --json` in `next`!
    let reinstall = isolated_cmd(&home)
        .args(["plugin", "install", "telegram", "--state-dir", state_str, "--json"])
        .output()
        .unwrap();
    assert_eq!(reinstall.status.code(), Some(0));

    let rm_out = isolated_cmd(&home)
        .args(["plugin", "remove", "telegram", "--state-dir", state_str, "--json"])
        .output()
        .unwrap();
    assert_eq!(rm_out.status.code(), Some(0));
    let rm_json = parse_json_stdout(&rm_out);
    assert_eq!(
        rm_json["data"]["removedConfigEntries"],
        json!(["telegram", "custom-tg-alias"]),
        "expected both matching config entries removed: {rm_json}"
    );
    assert!(
        rm_json["next"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some("hyp service restart --json")),
        "expected restart hint when config entries removed: {rm_json}"
    );
    let cfg_after_rm: Value =
        serde_json::from_str(&fs::read_to_string(&node_json_path).unwrap()).unwrap();
    let remaining = cfg_after_rm["plugins"].as_array().unwrap();
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0]["id"], "slack");

    // 4. Verify `sourceLocation` strips `?sv=...&sig=...` query strings from CDN redirects!
    let archive_path = tmp.path().join("test-plugins.tar.gz");
    let entries: Vec<TarInputEntry> = ["sdk/client.mjs", "sdk/client.py", "telegram/index.mjs"]
        .into_iter()
        .map(|rel| TarInputEntry {
            archive_path: rel.to_string(),
            source_path: repo_plugins_dir().join(rel),
        })
        .collect();
    {
        let file = fs::File::create(&archive_path).unwrap();
        pack_tar_gz(&entries, file, TarPackOptions::default()).unwrap();
    }
    let archive_bytes = Arc::new(fs::read(&archive_path).unwrap());

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (addr, server_handle) = rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let bytes = Arc::clone(&archive_bytes);
        let handle = tokio::spawn(async move {
            for _ in 0..4 {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let bytes_clone = Arc::clone(&bytes);
                let host_addr = addr;
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let b = Arc::clone(&bytes_clone);
                        async move {
                            if req.uri().path() == "/release" {
                                let redirect_target = format!(
                                    "http://{host_addr}/blob/hyp-plugins.tar.gz?sv=2025-01-01&sig=TOP_SECRET_SAS_TOKEN_9999&se=2099-01-01"
                                );
                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(StatusCode::FOUND)
                                        .header(header::LOCATION, redirect_target)
                                        .body(Full::new(Bytes::new()))
                                        .unwrap(),
                                )
                            } else {
                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header(header::CONTENT_TYPE, "application/gzip")
                                        .body(Full::new(Bytes::from((*b).clone())))
                                        .unwrap(),
                                )
                            }
                        }
                    });
                    let _ = AutoServerBuilder::new(TokioExecutor::new())
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });
        (addr, handle)
    });

    let dl_state = home.join("dl-state");
    fs::create_dir_all(&dl_state).unwrap();
    let dl_out = isolated_cmd(&home)
        .env_remove("HYPHAE_PLUGINS_DIR")
        .args([
            "plugin",
            "install",
            "telegram",
            "--url",
            &format!("http://{addr}/release"),
            "--state-dir",
            dl_state.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("install plugin over redirected HTTP");
    server_handle.abort();

    assert_eq!(
        dl_out.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&dl_out.stdout),
        String::from_utf8_lossy(&dl_out.stderr)
    );
    let dl_stdout = String::from_utf8_lossy(&dl_out.stdout);
    let dl_stderr = String::from_utf8_lossy(&dl_out.stderr);
    assert!(
        !dl_stdout.contains("TOP_SECRET_SAS_TOKEN_9999")
            && !dl_stderr.contains("TOP_SECRET_SAS_TOKEN_9999")
            && !dl_stdout.contains("?sv="),
        "SAS query string leaked in output! stdout={dl_stdout} stderr={dl_stderr}"
    );
    let dl_json = parse_json_stdout(&dl_out);
    assert_eq!(dl_json["data"]["source"], "release");
    assert_eq!(
        dl_json["data"]["sourceLocation"],
        format!("http://{addr}/blob/hyp-plugins.tar.gz")
    );
}

// ============================================================================
// 5. R5 / D9 — `hyp doctor` Flags `DAEMON_VERSION_SKEW` + `hyp update --no-restart`
// ============================================================================

#[cfg(unix)]
#[test]
fn r5_doctor_flags_daemon_version_skew_and_update_supports_no_restart() {
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixListener;

    let tmp = TempDir::new().unwrap();
    let home = tmp.path().to_path_buf();
    let state_dir = home.join("state");
    fs::create_dir_all(&state_dir).unwrap();
    let sock_path = state_dir.join("connector.sock");

    fs::write(
        state_dir.join("node.json"),
        serde_json::to_string_pretty(&json!({
            "version": 2,
            "nodeId": "skew-test@box",
            "profile": "local"
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(
        state_dir.join("node.status.json"),
        serde_json::to_string_pretty(&json!({
            "nodeId": "skew-test@box",
            "socketPath": sock_path.display().to_string()
        }))
        .unwrap(),
    )
    .unwrap();

    let reported_version = Arc::new(Mutex::new("0.0.1-stale".to_string()));
    let ver_clone = Arc::clone(&reported_version);
    let listener = UnixListener::bind(&sock_path).unwrap();
    let server_thread = std::thread::spawn(move || {
        for _ in 0..3 {
            let Ok((stream, _)) = listener.accept() else {
                break;
            };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            let _ = reader.read_line(&mut line);
            let ver = ver_clone.lock().unwrap().clone();
            let resp = json!({
                "ok": true,
                "result": {
                    "nodeId": "skew-test@box",
                    "binaryVersion": ver,
                    "pid": 42424
                }
            });
            let mut writer = stream;
            let _ = writeln!(writer, "{resp}");
        }
    });

    // 1. `hyp status --json` surfaces daemonBinaryVersion and daemonPid.
    let status_out = isolated_cmd(&home)
        .args(["status", "--state-dir", state_dir.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert_eq!(status_out.status.code(), Some(0));
    let status_json = parse_json_stdout(&status_out);
    assert_eq!(status_json["data"]["node"]["daemonBinaryVersion"], "0.0.1-stale");
    assert_eq!(status_json["data"]["node"]["daemonPid"], 42424);

    // 2. `hyp doctor --json` emits WARN `DAEMON_VERSION_SKEW` with `hyp service restart --json`!
    let doc_out = isolated_cmd(&home)
        .args(["doctor", "--state-dir", state_dir.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert_eq!(doc_out.status.code(), Some(0));
    let doc_json = parse_json_stdout(&doc_out);
    let skew_check = doc_json["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "DAEMON_VERSION_SKEW")
        .unwrap_or_else(|| panic!("expected DAEMON_VERSION_SKEW check in doctor: {doc_json}"));
    assert_eq!(skew_check["status"], "warn");
    assert_eq!(skew_check["fix"], "hyp service restart --json");
    assert!(
        doc_json["next"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some("hyp service restart --json"))
    );

    // 3. Once daemon reports matching version, `DAEMON_VERSION_SKEW` disappears and `daemon.version` is OK!
    *reported_version.lock().unwrap() = env!("CARGO_PKG_VERSION").to_string();
    let doc_ok_out = isolated_cmd(&home)
        .args(["doctor", "--state-dir", state_dir.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert_eq!(doc_ok_out.status.code(), Some(0));
    let doc_ok_json = parse_json_stdout(&doc_ok_out);
    assert!(
        !doc_ok_json["data"]["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "DAEMON_VERSION_SKEW"),
        "unexpected DAEMON_VERSION_SKEW when versions match: {doc_ok_json}"
    );
    assert!(
        doc_ok_json["data"]["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["name"] == "daemon.version" && c["status"] == "ok")
    );
    let _ = server_thread.join();

    // 4. Verify `hyp update --no-restart` swaps binary cleanly and reports `serviceRestarted: false`
    //    with `hyp service restart --json` in `next`.
    let release_kp = Ed25519KeyPair::generate().unwrap();
    let fake_bin_bytes = fs::read(hyp_bin()).unwrap();
    let fake_sha = hex::encode(Sha256::digest(&fake_bin_bytes));
    let fake_size = fake_bin_bytes.len() as u64;
    let triple = "x86_64-test-triple";

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let (srv_addr, srv_handle) = rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            triple.to_string(),
            json!({
                "sha256": fake_sha,
                "size": fake_size,
                "url": format!("http://{addr}/hyp-bin")
            }),
        );
        let payload_val = json!({
            "artifacts": artifacts,
            "changelogSummary": "Test update",
            "channel": "stable",
            "gitSha": "1234567890abcdef",
            "minProtocol": 1,
            "publishedAt": "2026-12-01T00:00:00Z",
            "version": "9.9.9"
        });
        let signed = release_kp.sign_jcs("release", &payload_val).unwrap();
        let manifest_body = Arc::new(
            serde_json::to_vec(&json!({
                "payload": signed.payload,
                "sig": signed.sig
            }))
            .unwrap(),
        );
        let bin_arc = Arc::new(fake_bin_bytes);

        let handle = tokio::spawn(async move {
            for _ in 0..4 {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let m = Arc::clone(&manifest_body);
                let b = Arc::clone(&bin_arc);
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let m = Arc::clone(&m);
                        let b = Arc::clone(&b);
                        async move {
                            if req.uri().path() == "/manifest.json" {
                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header(header::CONTENT_TYPE, "application/json")
                                        .body(Full::new(Bytes::from((*m).clone())))
                                        .unwrap(),
                                )
                            } else {
                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .body(Full::new(Bytes::from((*b).clone())))
                                        .unwrap(),
                                )
                            }
                        }
                    });
                    let _ = AutoServerBuilder::new(TokioExecutor::new())
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });
        (addr, handle)
    });

    let target_bin = tmp.path().join("target-hyp");
    let upd_out = isolated_cmd(&home)
        .args([
            "update",
            "--channel",
            "stable",
            "--manifest-url",
            &format!("http://{srv_addr}/manifest.json"),
            "--pubkey",
            &release_kp.public_key_b64(),
            "--target",
            triple,
            "--target-bin",
            target_bin.to_str().unwrap(),
            "--state-dir",
            state_dir.to_str().unwrap(),
            "--no-plugins",
            "--no-restart",
            "--json",
        ])
        .output()
        .expect("run hyp update --no-restart");
    srv_handle.abort();
    assert_eq!(
        upd_out.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&upd_out.stdout),
        String::from_utf8_lossy(&upd_out.stderr)
    );
    let upd_json = parse_json_stdout(&upd_out);
    assert_eq!(upd_json["ok"], true);
    assert_eq!(upd_json["data"]["serviceRestarted"], false);
    assert!(
        upd_json["next"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some("hyp service restart --json")),
        "expected restart hint on --no-restart: {upd_json}"
    );
}

// ============================================================================
// 6. H6, H18, & R6 — `hyp drop wait` Reconnect (`Last-Event-ID`), Junk Skip, `relay set` Hint
// ============================================================================

#[test]
fn h6_h18_drop_wait_reconnects_with_last_event_id_ignores_junk_and_r6_relay_set_hint() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().to_path_buf();
    let state_dir = home.join("state");
    fs::create_dir_all(&state_dir).unwrap();
    let state_str = state_dir.to_str().unwrap();

    // 1. Verify R6: `hyp relay set` emits restart warning + `hyp service restart --json` in `next`.
    let relay_set_out = isolated_cmd(&home)
        .args([
            "relay",
            "set",
            "https://drop.example.com",
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run hyp relay set");
    assert_eq!(relay_set_out.status.code(), Some(0));
    let relay_set_json = parse_json_stdout(&relay_set_out);
    assert_eq!(relay_set_json["ok"], true);
    assert!(
        !relay_set_json["warnings"].as_array().unwrap().is_empty(),
        "R6: expected restart warning on relay set: {relay_set_json}"
    );
    assert!(
        relay_set_json["next"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v.as_str() == Some("hyp service restart --json")),
        "R6: expected `hyp service restart --json` in next: {relay_set_json}"
    );

    // 2. Initialize local node + enrolled human authority key.
    let init_out = isolated_cmd(&home)
        .args([
            "auth",
            "init",
            "--human-id",
            "alice",
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run hyp auth init");
    assert_eq!(init_out.status.code(), Some(0));
    let init_json = parse_json_stdout(&init_out);
    let node_id = init_json["data"]["nodeId"].as_str().unwrap().to_string();

    // 3. Produce a VALID sealed `hdrop1_` via `hyp auth sign` AND an INVALID forged `hdrop1_`
    //    signed by an unenrolled attacker key!
    let mut sign_proc = isolated_cmd(&home)
        .args([
            "auth",
            "sign",
            "--kind",
            "directive",
            "--drop-id",
            "drop-e2e-reconnect",
            "--state-dir",
            state_str,
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn hyp auth sign");
    sign_proc
        .stdin
        .take()
        .unwrap()
        .write_all(b"Approve production rollout #42")
        .unwrap();
    let sign_out = sign_proc.wait_with_output().unwrap();
    assert_eq!(
        sign_out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&sign_out.stderr)
    );
    let valid_hdrop1 = parse_json_stdout(&sign_out)["data"]["token"]
        .as_str()
        .unwrap()
        .to_string();

    // Forge a syntactically valid `hdrop1_` signed by an UNTRUSTED attacker key.
    let store = SecretStore::file_only(&state_dir);
    let node_keys = store.load_or_create_node_keys(&node_id).unwrap();
    let attacker_kp = Ed25519KeyPair::generate().unwrap();
    let now = now_unix_ms();
    let forged_claim = HumanClaimV1 {
        v: 1,
        claim_id: "forged-claim-001".to_string(),
        human_id: "attacker".to_string(),
        human_kid: attacker_kp.kid(),
        auth_epoch: 1,
        kind: HumanDropKind::Directive,
        drop_id: "drop-e2e-reconnect".to_string(),
        audience: HumanAudience {
            node_id: node_id.clone(),
            node_enc_kid: node_keys.encryption.kid(),
            handle: None,
        },
        secret_spec: None,
        body: "malicious untrusted directive".to_string(),
        issued_at: format_rfc3339_millis(now),
        expires_at: format_rfc3339_millis(now + 300_000),
    };
    let forged_env = seal_human_drop(
        &forged_claim,
        &attacker_kp,
        &node_keys.encryption.public_key(),
    )
    .unwrap();
    let forged_hdrop1 = encode_hdrop1(&forged_env).unwrap();

    // 4. Start a mock Drop Relay HTTP/SSE server that:
    //    - On stream attempt #1: emits junk item #1 (malformed JSON), junk item #2 (forged untrusted hdrop1_),
    //      then drops the connection abruptly!
    //    - On stream attempt #2: records `Last-Event-ID`, then emits valid item #3 (`valid_hdrop1`)!
    //    - Accepts `POST /v1/drops/drop-e2e-reconnect/ack` and records the ack body.
    let stream_attempts = Arc::new(AtomicUsize::new(0));
    let observed_last_event_ids: Arc<Mutex<Vec<Option<String>>>> = Arc::new(Mutex::new(Vec::new()));
    let observed_ack: Arc<Mutex<Option<Value>>> = Arc::new(Mutex::new(None));

    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();

    let (relay_addr, srv_handle) = rt.block_on(async {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let attempts = Arc::clone(&stream_attempts);
        let last_ids = Arc::clone(&observed_last_event_ids);
        let ack_slot = Arc::clone(&observed_ack);
        let forged = Arc::new(forged_hdrop1);
        let valid = Arc::new(valid_hdrop1);

        let handle = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let attempts = Arc::clone(&attempts);
                let last_ids = Arc::clone(&last_ids);
                let ack_slot = Arc::clone(&ack_slot);
                let forged = Arc::clone(&forged);
                let valid = Arc::clone(&valid);

                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let svc = service_fn(move |req: Request<Incoming>| {
                        let attempts = Arc::clone(&attempts);
                        let last_ids = Arc::clone(&last_ids);
                        let ack_slot = Arc::clone(&ack_slot);
                        let forged = Arc::clone(&forged);
                        let valid = Arc::clone(&valid);
                        async move {
                            let path = req.uri().path().to_string();
                            if req.method() == Method::GET && path.ends_with("/stream") {
                                let last_id = req
                                    .headers()
                                    .get("last-event-id")
                                    .and_then(|v| v.to_str().ok())
                                    .map(ToOwned::to_owned);
                                last_ids.lock().unwrap().push(last_id);
                                let n = attempts.fetch_add(1, Ordering::SeqCst);
                                let body = if n == 0 {
                                    // Connection #1: junk item 1 + forged item 2, then immediate EOF!
                                    format!(
                                        "id: 1\nevent: drop\ndata: {{not-valid-json\n\n\
                                         id: 2\nevent: drop\ndata: {}\n\n",
                                        forged.as_str()
                                    )
                                } else {
                                    // Connection #2: valid drop item 3!
                                    format!(
                                        "id: 3\nevent: drop\ndata: {}\n\n",
                                        valid.as_str()
                                    )
                                };
                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header(header::CONTENT_TYPE, "text/event-stream")
                                        .body(Full::new(Bytes::from(body)))
                                        .unwrap(),
                                )
                            } else if req.method() == Method::POST && path.ends_with("/ack") {
                                use http_body_util::BodyExt as _;
                                let bytes = req
                                    .into_body()
                                    .collect()
                                    .await
                                    .map(|c| c.to_bytes())
                                    .unwrap_or_default();
                                if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                                    *ack_slot.lock().unwrap() = Some(v);
                                }
                                let resp_json = json!({
                                    "ok": true,
                                    "dropId": "drop-e2e-reconnect",
                                    "ackedThroughSeq": 3,
                                    "burned": true,
                                    "remainingItems": 0
                                });
                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header(header::CONTENT_TYPE, "application/json")
                                        .body(Full::new(Bytes::from(
                                            serde_json::to_vec(&resp_json).unwrap(),
                                        )))
                                        .unwrap(),
                                )
                            } else {
                                Ok::<_, Infallible>(
                                    Response::builder()
                                        .status(StatusCode::NOT_FOUND)
                                        .body(Full::new(Bytes::new()))
                                        .unwrap(),
                                )
                            }
                        }
                    });
                    let _ = AutoServerBuilder::new(TokioExecutor::new())
                        .serve_connection(io, svc)
                        .await;
                });
            }
        });
        (addr, handle)
    });

    // 5. Run `hyp drop wait` against the flaky mock relay!
    let wait_out = isolated_cmd(&home)
        .args([
            "drop",
            "wait",
            "--relay",
            &format!("http://{relay_addr}"),
            "--drop-id",
            "drop-e2e-reconnect",
            "--timeout",
            "10",
            "--state-dir",
            state_str,
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run hyp drop wait");
    srv_handle.abort();

    assert_eq!(
        wait_out.status.code(),
        Some(0),
        "hyp drop wait must survive SSE drop + junk items! stdout={} stderr={}",
        String::from_utf8_lossy(&wait_out.stdout),
        String::from_utf8_lossy(&wait_out.stderr)
    );
    let wait_json = parse_json_stdout(&wait_out);
    assert_eq!(wait_json["ok"], true);
    assert_eq!(wait_json["data"]["kind"], "directive");
    assert_eq!(wait_json["data"]["humanId"], "alice");
    assert_eq!(
        wait_json["warnings"].as_array().unwrap().len(),
        2,
        "expected 2 warnings for the 2 ignored junk items: {wait_json}"
    );
    assert!(
        stream_attempts.load(Ordering::SeqCst) >= 2,
        "expected reconnect after mid-stream SSE drop"
    );
    let ids = observed_last_event_ids.lock().unwrap().clone();
    assert_eq!(ids[0], None, "first connection must not send Last-Event-ID");
    assert_eq!(
        ids[1].as_deref(),
        Some("2"),
        "reconnect MUST send Last-Event-ID from last seen SSE event: {ids:?}"
    );
    let ack = observed_ack
        .lock()
        .unwrap()
        .clone()
        .expect("expected burn ack after valid drop");
    assert_eq!(ack["seq"], 3);
    assert_eq!(ack["burn"], true);
}

// ============================================================================
// 7. D7 — Release Workflow Fails Closed Without Signing Key on Tag Releases
// ============================================================================

#[test]
fn d7_release_workflow_fails_closed_when_signing_key_missing_on_v_tags() {
    let wf_path = workspace_root()
        .join(".github")
        .join("workflows")
        .join("release-rust.yml");
    let wf = fs::read_to_string(&wf_path).expect("read .github/workflows/release-rust.yml");

    // 1. Must explicitly check `refs/tags/v` and fail closed (`process.exit(1)`) when signing key is absent.
    assert!(
        wf.contains("refs/tags/v"),
        "workflow must inspect refs/tags/v for tag releases"
    );
    assert!(
        wf.contains("HYPHAE_RELEASE_SIGNING_KEY secret is required (fail-closed)"),
        "workflow must fail closed when HYPHAE_RELEASE_SIGNING_KEY is missing"
    );
    assert!(
        wf.contains("process.exit(1)"),
        "workflow must exit 1 when signing key is missing on tag releases"
    );
    assert!(
        wf.contains("!isTagRelease && isDryRun && allowUnsignedDryRun"),
        "unsigned fallback must be strictly limited to explicitly opted-in non-tag workflow_dispatch dry-runs"
    );
    // 2. Must include post-sign signature verification against pinned DEFAULT_RELEASE_PUBKEY_B64 in update.rs!
    assert!(
        wf.contains("Verify release-manifest.json signature against pinned public key"),
        "workflow must verify signed manifest against pinned public key"
    );
    assert!(
        wf.contains("crates/hyp-cli/src/update.rs")
            && wf.contains("DEFAULT_RELEASE_PUBKEY_B64")
            && wf.contains("crypto.verify"),
        "verification step must check dist/release-manifest.json against DEFAULT_RELEASE_PUBKEY_B64 in update.rs"
    );

    // 3. Confirm `DEFAULT_RELEASE_PUBKEY_B64` in `crates/hyp-cli/src/update.rs` matches the exact
    //    pattern parsed by the release workflow verification step.
    let update_rs =
        fs::read_to_string(workspace_root().join("crates/hyp-cli/src/update.rs")).unwrap();
    let pubkey_line = update_rs
        .lines()
        .find(|l| l.contains("pub const DEFAULT_RELEASE_PUBKEY_B64"))
        .expect("DEFAULT_RELEASE_PUBKEY_B64 constant in update.rs");
    let start = pubkey_line.find('"').unwrap() + 1;
    let end = pubkey_line[start..].find('"').unwrap() + start;
    let pubkey = &pubkey_line[start..end];
    assert_eq!(
        pubkey.len(),
        43,
        "DEFAULT_RELEASE_PUBKEY_B64 must be a 43-char base64url Ed25519 key"
    );
}
