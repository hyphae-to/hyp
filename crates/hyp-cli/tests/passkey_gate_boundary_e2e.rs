//! Live per-operation Passkey approval, migration, and adversarial CLI boundary tests.

mod common;

use common::{ManagedProcess, TestPasskeyAdmin, isolated_cmd, parse_json_stdout};
#[cfg(unix)]
use hyp_crypto::human::HumanApprovalActionKind;
use hyp_crypto::keys::Ed25519KeyPair;
use hyp_crypto::keystore::{SecretBackend, SecretStore};
#[cfg(unix)]
use hyp_harness::sock::daemon_rpc_sync;
use hyp_store::NodeDb;
use serde_json::{Value, json};
use std::fs;
use std::io::Write as _;
#[cfg(unix)]
use std::path::PathBuf;
use std::process::Stdio;
use std::time::{Duration, Instant};
use tempfile::TempDir;

#[cfg(unix)]
const STARTUP_TIMEOUT: Duration = Duration::from_secs(15);

#[test]
fn issue10_prerequisite_rejects_zero_authority_and_local_pkcs8_keys_fail_closed() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let state_dir = home.join("state");
    let config_path = state_dir.join("node.json");
    let state_str = state_dir.to_str().unwrap();
    let cfg_str = config_path.to_str().unwrap();

    // 1. Zero authorities enrolled -> `gate lock`, `gate unlock`, `gate init --lock` all fail closed!
    for args in [
        vec![
            "gate",
            "apply",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--json",
        ],
        vec![
            "gate",
            "apply",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--json",
        ],
        vec![
            "gate",
            "init",
            "--adapter",
            "openai-compat",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--json",
        ],
    ] {
        let out = isolated_cmd(home).args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(1), "args={args:?}");
        let env = parse_json_stdout(&out);
        assert_eq!(env["ok"], false);
        assert_eq!(env["error"]["code"], "PASSKEY_AUTHORITY_REQUIRED");
        assert!(
            env["next"]
                .as_array()
                .unwrap()
                .iter()
                .any(|n| n.as_str().unwrap_or("").contains("hyp auth init --web")),
            "expected actionable `hyp auth init --web` next step: {env}"
        );
    }

    // 2. Enroll ONLY a shell-accessible local PKCS#8 admin key (`hyp auth init` without `--web`).
    let init_local = isolated_cmd(home)
        .args([
            "auth",
            "init",
            "--human-id",
            "laptop-local",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(init_local.status.code(), Some(0));
    let local_kid = parse_json_stdout(&init_local)["data"]["kid"]
        .as_str()
        .unwrap()
        .to_string();

    // Confirm the local PKCS#8 key IS in SecretStore, and MUST NOT satisfy Passkey gate lock/unlock (H2)!
    let secrets = SecretStore::new(&state_dir, SecretBackend::File);
    let (local_secret_name, _) = hyp_node::gates::local_admin_secret_names_for_kid(&local_kid);
    assert!(
        secrets.get(&local_secret_name).is_ok(),
        "non-web auth init stores a local PKCS#8 key under {local_secret_name}"
    );

    {
        let sub = "apply";
        let out = isolated_cmd(home)
            .args([
                "gate",
                sub,
                "--state-dir",
                state_str,
                "--config",
                cfg_str,
                "--json",
            ])
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(1),
            "gate {sub} with local PKCS#8 key must fail closed"
        );
        let env = parse_json_stdout(&out);
        assert_eq!(env["error"]["code"], "PASSKEY_AUTHORITY_REQUIRED");
    }
}

#[cfg(unix)]
#[test]
fn issue10_external_sqlite_lock_seal_survives_node_json_flip_delete_and_gate_init() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let state_dir = home.join("state");
    let config_path = state_dir.join("node.json");
    let state_str = state_dir.to_str().unwrap();
    let cfg_str = config_path.to_str().unwrap();

    // 1. Start a live `hyp daemon` and enroll a Passkey Admin via `--web` (zero local PKCS#8 secret!).
    let mut daemon_cmd = isolated_cmd(home);
    daemon_cmd
        .args([
            "daemon",
            "--profile",
            "local",
            "--node-id",
            "seal-guard@box",
            "--state-dir",
            state_str,
            "--json",
        ])
        .stdin(Stdio::null());
    let mut daemon = ManagedProcess::spawn("seal-guard daemon", &mut daemon_cmd);
    let startup = daemon.read_json_line(STARTUP_TIMEOUT);
    assert_eq!(startup["ok"], true, "daemon startup failed: {startup}");
    let sock_path = PathBuf::from(startup["data"]["socketPath"].as_str().unwrap());

    let passkey = TestPasskeyAdmin::generate("bogdan", "macbook-touchid");
    let enroll_json = passkey.enroll_via_web(home, &state_dir, Some(&config_path));
    assert_eq!(enroll_json["data"]["webEnrolled"]["role"], "admin");
    assert!(enroll_json["data"]["secretName"].is_null());

    // Verify ZERO `human-admin-*` PKCS#8 key was written to SecretStore (H2)!
    let secrets = SecretStore::new(&state_dir, SecretBackend::File);
    assert!(
        !hyp_node::gates::has_local_authority_secret(&secrets, &passkey.kid()),
        "H2: Passkey Admin MUST NOT store any private key in SecretStore!"
    );

    // An agent cannot bypass the CLI by writing an unsigned policy and calling gate.reload,
    // even before this existing installation has its first signed policy evidence.
    let previous_config = fs::read(&config_path).ok();
    let mut unsigned_policy = hyp_node::gates::SecurityGateConfig::default();
    unsigned_policy.stage1.outbound_dlp_enabled = false;
    fs::write(
        &config_path,
        json!({"v":2, "nodeId":"seal-guard@box", "profile":"local", "gate":unsigned_policy})
            .to_string(),
    )
    .unwrap();
    let unsigned_reload = daemon_rpc_sync(
        &sock_path,
        &json!({"type":"gate.reload"}),
        Duration::from_secs(2),
    );
    assert!(!unsigned_reload.ok);
    let rejection = unsigned_reload.error.unwrap();
    assert!(
        rejection.contains("Passkey approval required"),
        "{rejection}"
    );
    match previous_config {
        Some(bytes) => fs::write(&config_path, bytes).unwrap(),
        None => fs::remove_file(&config_path).unwrap(),
    }

    // 2. Configure a Stage 2 filter & lock via Passkey approval!
    let (lock_code, lock_json, lock_stderr, _) = passkey.run_and_approve_json(
        home,
        &[
            "gate",
            "init",
            "--adapter",
            "openai-compat",
            "--id",
            "seal-ollama",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--local",
            "--no-open",
            "--json",
        ],
        None,
    );
    assert_eq!(lock_code, 0, "stderr={lock_stderr}");
    assert_eq!(lock_json["data"]["approved"], true);
    assert_eq!(lock_json["data"]["gatePolicySig"], "OK");
    assert_eq!(lock_json["data"]["daemonReloaded"], true);

    let locked_raw = fs::read_to_string(&config_path).unwrap();

    // 3. G1 Attack A: Running `hyp gate init` (without `--lock`) while locked fails closed!
    let silent_init = isolated_cmd(home)
        .args([
            "gate",
            "init",
            "--adapter",
            "anthropic",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--local",
            "--no-open",
            "--ttl",
            "1",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(silent_init.status.code(), Some(1));
    assert_eq!(
        parse_json_stdout(&silent_init)["error"]["code"],
        "APPROVAL_TIMEOUT"
    );
    assert_eq!(fs::read_to_string(&config_path).unwrap(), locked_raw);

    // 4. G1 Attack B: Prompt-injected agent flips `require_signed_policy: false` & clears `policy_signature`!
    let mut flipped: Value = serde_json::from_str(&locked_raw).unwrap();
    flipped["gate"]["require_signed_policy"] = Value::Bool(false);
    flipped["gate"]
        .as_object_mut()
        .unwrap()
        .remove("policy_signature");
    fs::write(
        &config_path,
        serde_json::to_string_pretty(&flipped).unwrap(),
    )
    .unwrap();

    let doc_flipped = isolated_cmd(home)
        .args([
            "doctor",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(doc_flipped.status.code(), Some(1));
    let doc_flipped_json = parse_json_stdout(&doc_flipped);
    assert_eq!(doc_flipped_json["data"]["gate"]["gatePolicySig"], "FAIL");
    assert_eq!(doc_flipped_json["data"]["gate"]["tampered"], true);

    let reload_flipped = daemon_rpc_sync(
        &sock_path,
        &json!({ "type": "gate.reload" }),
        Duration::from_secs(2),
    );
    assert!(
        !reload_flipped.ok,
        "flipped require_signed_policy MUST fail gate.reload"
    );
    assert!(
        reload_flipped
            .error
            .as_deref()
            .unwrap_or("")
            .contains("gate_policy_tampered")
    );

    // 5. G1 Attack C: Prompt-injected agent DELETES `"gate"` completely from `node.json`!
    let mut deleted: Value = serde_json::from_str(&locked_raw).unwrap();
    deleted.as_object_mut().unwrap().remove("gate");
    fs::write(
        &config_path,
        serde_json::to_string_pretty(&deleted).unwrap(),
    )
    .unwrap();

    let doc_deleted = isolated_cmd(home)
        .args([
            "doctor",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(doc_deleted.status.code(), Some(1));
    let doc_deleted_json = parse_json_stdout(&doc_deleted);
    assert_eq!(doc_deleted_json["data"]["gate"]["gatePolicySig"], "FAIL");
    assert_eq!(doc_deleted_json["data"]["gate"]["tampered"], true);

    let reload_deleted = daemon_rpc_sync(
        &sock_path,
        &json!({ "type": "gate.reload" }),
        Duration::from_secs(2),
    );
    assert!(
        !reload_deleted.ok,
        "deleted gate section MUST fail gate.reload"
    );
    assert!(
        reload_deleted
            .error
            .as_deref()
            .unwrap_or("")
            .contains("gate_policy_tampered")
    );

    // Reapply the restored valid policy with a fresh approval; no unlocked mode exists.
    fs::write(&config_path, &locked_raw).unwrap();
    let (code, result, stderr, action) = passkey.run_and_approve_json(
        home,
        &[
            "gate",
            "apply",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--local",
            "--no-open",
            "--json",
        ],
        None,
    );
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(action.action, HumanApprovalActionKind::GateApply);
    assert_eq!(result["data"]["approved"], true);

    // Restart daemon after Passkey-signed unlock -> boots cleanly with ZERO gate_policy_tampered warning!
    let _ = daemon.shutdown_gracefully();
    let mut daemon2_cmd = isolated_cmd(home);
    daemon2_cmd
        .args([
            "daemon",
            "--profile",
            "local",
            "--node-id",
            "seal-guard@box",
            "--state-dir",
            state_str,
            "--json",
        ])
        .stdin(Stdio::null());
    let mut daemon2 = ManagedProcess::spawn("seal-guard daemon restarted", &mut daemon2_cmd);
    let startup2 = daemon2.read_json_line(STARTUP_TIMEOUT);
    assert_eq!(startup2["ok"], true, "restarted daemon failed: {startup2}");
    assert!(
        !startup2["warnings"]
            .as_array()
            .map(|w| w
                .iter()
                .any(|s| s.as_str().unwrap_or("").contains("gate_policy_tampered")))
            .unwrap_or(false),
        "restarted daemon after Passkey unlock must not report gate_policy_tampered: {startup2}"
    );
    let _ = daemon2.shutdown_gracefully();
}

#[test]
fn issue10_mutated_wrong_signer_replayed_and_wrong_entrypoint_approvals_fail_closed() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let state_dir = home.join("state");
    let config_path = state_dir.join("node.json");
    let state_str = state_dir.to_str().unwrap();
    let cfg_str = config_path.to_str().unwrap();

    // 1. Enroll primary Passkey Admin via `--web`, then enroll a non-admin (`Signer`) AND a
    //    revoked Passkey Admin via Passkey-approved `auth add` / `auth revoke`!
    let admin = TestPasskeyAdmin::generate("bogdan", "admin-touchid");
    admin.enroll_via_web(home, &state_dir, Some(&config_path));

    let signer_only = TestPasskeyAdmin::generate("helper", "signer-only-passkey");
    let signer_bundle = json!({
        "v": 1,
        "humanId": signer_only.human_id,
        "kid": signer_only.kid(),
        "authEpoch": 1,
        "prfSalt": "signer-prf-salt",
        "jwk": signer_only.ed_kp.to_jwk(),
        "encJwk": signer_only.enc_kp.to_jwk(),
    })
    .to_string();
    let (add_s_code, _, add_s_stderr, _) = admin.run_and_approve_json(
        home,
        &[
            "auth",
            "add",
            "--human-id",
            &signer_only.human_id,
            "--label",
            &signer_only.label,
            "--role",
            "signer",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--local",
            "--no-open",
            "--json",
        ],
        Some(&signer_bundle),
    );
    assert_eq!(add_s_code, 0, "stderr={add_s_stderr}");

    let revoked_admin = TestPasskeyAdmin::generate("former-admin", "revoked-touchid");
    let rev_bundle = json!({
        "v": 1,
        "humanId": revoked_admin.human_id,
        "kid": revoked_admin.kid(),
        "authEpoch": 1,
        "prfSalt": "former-prf-salt",
        "jwk": revoked_admin.ed_kp.to_jwk(),
        "encJwk": revoked_admin.enc_kp.to_jwk(),
    })
    .to_string();
    let (add_r_code, _, _, _) = admin.run_and_approve_json(
        home,
        &[
            "auth",
            "add",
            "--human-id",
            &revoked_admin.human_id,
            "--label",
            &revoked_admin.label,
            "--role",
            "admin",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--local",
            "--no-open",
            "--json",
        ],
        Some(&rev_bundle),
    );
    assert_eq!(add_r_code, 0);

    let (rev_code, _, _, _) = admin.run_and_approve_json(
        home,
        &[
            "auth",
            "revoke",
            &revoked_admin.kid(),
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--local",
            "--no-open",
            "--json",
        ],
        None,
    );
    assert_eq!(rev_code, 0);

    // Also seed a non-Passkey local-key Admin (`prf_salt: None`, private key in SecretStore) via Passkey `auth add`.
    let local_admin_kp = Ed25519KeyPair::generate().unwrap();
    let local_admin_jwk = serde_json::to_string(&local_admin_kp.to_jwk()).unwrap();
    let (add_l_code, _, _, _) = admin.run_and_approve_json(
        home,
        &[
            "auth",
            "add",
            "--human-id",
            "shell-key-admin",
            "--label",
            "local-pkcs8",
            "--role",
            "admin",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--local",
            "--no-open",
            "--json",
        ],
        Some(&local_admin_jwk),
    );
    assert_eq!(add_l_code, 0);

    // Configure an unlocked filter with a unique canary secret name to verify ZERO URL leakage (G7)!
    let init_gate = isolated_cmd(home)
        .args([
            "gate",
            "propose",
            "--adapter",
            "anthropic",
            "--id",
            "canary-filter-id-77",
            "--secret",
            "ultra-private-gate-secret-ref",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(init_gate.status.code(), Some(0));

    // 2. Spawn live loopback `hyp gate apply --local --no-open` and hammer it with EVERY mutated attack!
    let mut lock_cmd = isolated_cmd(home);
    lock_cmd
        .args([
            "gate",
            "apply",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--local",
            "--no-open",
            "--ttl",
            "30",
            "--json",
        ])
        .stdin(Stdio::null());
    let mut lock_proc = ManagedProcess::spawn("adversarial hyp gate apply", &mut lock_cmd);

    let deadline = Instant::now() + Duration::from_secs(10);
    let approval_url = loop {
        let rem = deadline.saturating_duration_since(Instant::now());
        assert!(!rem.is_zero(), "timed out waiting for approval URL");
        let line = lock_proc.try_read_stderr_line(rem).unwrap();
        if let Some((_, u)) = line.split_once("Hyphae Passkey approval URL: ") {
            break u.trim().to_string();
        }
    };

    // G7 confidentiality check: URL fragment MUST NOT contain plaintext filter ID or secret ref!
    assert!(
        !approval_url.contains("canary-filter-id-77"),
        "filter ID leaked in plaintext approval URL!"
    );
    assert!(
        !approval_url.contains("ultra-private-gate-secret-ref"),
        "secret ref leaked in plaintext approval URL!"
    );

    let fragment = TestPasskeyAdmin::parse_approval_url(&approval_url);
    let action = admin.open_approval_from_fragment(&fragment);
    // The link carries only the signed action: the policy is named by hash, never by content.
    assert_eq!(
        fragment["approval"]["policySha256"].as_str(),
        action.policy_sha256.as_deref()
    );
    assert!(action.policy_sha256.is_some());

    // Attack 1: Wrong Origin -> HTTP 403!
    let (valid_hdrop1, _) = admin.seal_approval(&fragment, &action);
    let (st_origin, _) = TestPasskeyAdmin::post_approval_to_fragment(
        &fragment,
        &valid_hdrop1,
        "https://evil.example",
    );
    assert_eq!(
        st_origin, 403,
        "mismatched Origin must fail closed with 403"
    );

    // Attack 2: 1-bit flip in `policySha256` -> HTTP 403!
    let mut flipped_sha_action = action.clone();
    let orig_sha = flipped_sha_action.policy_sha256.clone().unwrap();
    let first_ch = if orig_sha.starts_with('a') { 'b' } else { 'a' };
    flipped_sha_action.policy_sha256 = Some(format!("{first_ch}{}", &orig_sha[1..]));
    let (bad_sha_tok, _) = admin.seal_approval(&fragment, &flipped_sha_action);
    let (st_sha, resp_sha) =
        TestPasskeyAdmin::post_approval_to_fragment(&fragment, &bad_sha_tok, "https://hyphae.to");
    assert_eq!(
        st_sha, 403,
        "flipped policySha256 must be rejected: {resp_sha}"
    );

    // Attack 3: Wrong `nodeId` -> HTTP 403!
    let mut wrong_node_action = action.clone();
    wrong_node_action.node_id = "other@node".to_string();
    let (bad_node_tok, _) = admin.seal_approval_with_signer(
        &fragment,
        &wrong_node_action,
        &admin.ed_kp,
        &admin.human_id,
        admin.auth_epoch,
        Some("other@node"),
    );
    let (st_node, resp_node) =
        TestPasskeyAdmin::post_approval_to_fragment(&fragment, &bad_node_tok, "https://hyphae.to");
    assert_eq!(st_node, 403, "wrong nodeId must be rejected: {resp_node}");

    // Attack 4: Non-admin (`Role::Signer`) key -> HTTP 403!
    let (signer_tok, _) = admin.seal_approval_with_signer(
        &fragment,
        &action,
        &signer_only.ed_kp,
        &signer_only.human_id,
        1,
        None,
    );
    let (st_signer, resp_signer) =
        TestPasskeyAdmin::post_approval_to_fragment(&fragment, &signer_tok, "https://hyphae.to");
    assert_eq!(
        st_signer, 403,
        "non-admin Signer must be rejected: {resp_signer}"
    );

    // Attack 5: Revoked Passkey Admin -> HTTP 403!
    let (revoked_tok, _) = admin.seal_approval_with_signer(
        &fragment,
        &action,
        &revoked_admin.ed_kp,
        &revoked_admin.human_id,
        1,
        None,
    );
    let (st_rev, resp_rev) =
        TestPasskeyAdmin::post_approval_to_fragment(&fragment, &revoked_tok, "https://hyphae.to");
    assert_eq!(st_rev, 403, "revoked Admin must be rejected: {resp_rev}");

    // Attack 6: Non-Passkey Admin (`prf_salt: None`) -> HTTP 403!
    let (local_tok, _) = admin.seal_approval_with_signer(
        &fragment,
        &action,
        &local_admin_kp,
        "shell-key-admin",
        1,
        None,
    );
    let (st_local, resp_local) =
        TestPasskeyAdmin::post_approval_to_fragment(&fragment, &local_tok, "https://hyphae.to");
    assert_eq!(
        st_local, 403,
        "non-Passkey Admin without prf_salt must be rejected: {resp_local}"
    );

    // Attack 7: Unenrolled unknown key -> HTTP 403!
    let rogue_kp = Ed25519KeyPair::generate().unwrap();
    let (rogue_tok, _) =
        admin.seal_approval_with_signer(&fragment, &action, &rogue_kp, "bogdan", 1, None);
    let (st_rogue, resp_rogue) =
        TestPasskeyAdmin::post_approval_to_fragment(&fragment, &rogue_tok, "https://hyphae.to");
    assert_eq!(st_rogue, 403, "unknown key must be rejected: {resp_rogue}");

    // Attack 8: Feeding an authentic `kind: "approval"` `hdrop1_` token into `hyp drop ingest` MUST fail closed!
    let mut ingest_child = isolated_cmd(home)
        .args([
            "drop",
            "ingest",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    ingest_child
        .stdin
        .take()
        .unwrap()
        .write_all(valid_hdrop1.as_bytes())
        .unwrap();
    let ingest_out = ingest_child.wait_with_output().unwrap();
    assert_eq!(
        ingest_out.status.code(),
        Some(1),
        "hyp drop ingest MUST reject kind=approval tokens"
    );

    // Finally submit the authentic Passkey Admin approval -> HTTP 201 and CLI exits 0!
    let (st_ok, resp_ok) =
        TestPasskeyAdmin::post_approval_to_fragment(&fragment, &valid_hdrop1, "https://hyphae.to");
    assert_eq!(
        st_ok, 201,
        "authentic Passkey Admin approval must succeed: {resp_ok}"
    );
    let (exit_st, lock_json) = lock_proc.wait_json_output(Duration::from_secs(10));
    assert_eq!(exit_st.code(), Some(0));
    assert_eq!(lock_json["ok"], true);
    assert_eq!(lock_json["data"]["gatePolicySig"], "OK");

    // Attack 9: Replaying the exact same signed `hdrop1_` via `--approval-file` MUST fail closed!
    let replay_file = tmp.path().join("replayed.hdrop1");
    fs::write(&replay_file, &valid_hdrop1).unwrap();
    let replay_out = isolated_cmd(home)
        .args([
            "gate",
            "apply",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--approval-file",
            replay_file.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        replay_out.status.code(),
        Some(2),
        "replayed approval file MUST fail closed"
    );
}

#[test]
fn obsolete_lock_and_offline_approval_paths_are_rejected() {
    let tmp = TempDir::new().unwrap();
    for args in [
        vec!["gate", "lock"],
        vec!["gate", "unlock"],
        vec!["gate", "apply", "--no-wait"],
        vec!["gate", "apply", "--approval-file", "/does-not-exist"],
        vec!["gate", "init", "--adapter", "anthropic", "--lock"],
        vec!["gate", "remove", "guard", "--lock"],
    ] {
        let out = isolated_cmd(tmp.path()).args(&args).output().unwrap();
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(!tmp.path().join(".config/hyphae/node.sqlite").exists());
    }
}

#[test]
fn issue81_auth_add_and_revoke_refuse_to_reseal_tampered_gate() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let state_dir = home.join("state");
    let config_path = state_dir.join("node.json");
    let state_str = state_dir.to_str().unwrap();
    let cfg_str = config_path.to_str().unwrap();

    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        &config_path,
        serde_json::to_string_pretty(&json!({
            "nodeId": "issue81@box",
            "profile": "local"
        }))
        .unwrap(),
    )
    .unwrap();

    let admin = TestPasskeyAdmin::generate("bogdan", "macbook-touchid");
    let enroll_json = admin.enroll_via_web(home, &state_dir, Some(&config_path));
    assert_eq!(enroll_json["data"]["webEnrolled"]["role"], "admin");

    let (lock_code, lock_json, lock_stderr, _) = admin.run_and_approve_json(
        home,
        &[
            "gate",
            "init",
            "--adapter",
            "openai-compat",
            "--id",
            "tamper-check",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--local",
            "--no-open",
            "--json",
        ],
        None,
    );
    assert_eq!(lock_code, 0, "stderr={lock_stderr}");
    assert_eq!(lock_json["data"]["approved"], true);

    let db = NodeDb::open(state_dir.join("node.sqlite")).unwrap();
    let seal_before = db
        .human()
        .get_gate_lock_seal()
        .unwrap()
        .expect("gate_lock_seal row");
    assert_eq!(seal_before.seal_seq, 1);

    // Tamper with `node.json` on disk (disabling the Stage 2 filter without Passkey re-lock).
    let mut cfg: Value = serde_json::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
    cfg["gate"]["filters"][0]["enabled"] = Value::Bool(false);
    fs::write(&config_path, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();

    // `hyp auth add` MUST fail closed with `GATE_POLICY_TAMPERED` and leave `gate_lock_seal` untouched.
    let second_kp = Ed25519KeyPair::generate().unwrap();
    let second_jwk = serde_json::to_string(&second_kp.to_jwk()).unwrap();
    let mut add_child = isolated_cmd(home)
        .args([
            "auth",
            "add",
            "--human-id",
            "alice",
            "--label",
            "phone",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--local",
            "--no-open",
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    add_child
        .stdin
        .take()
        .unwrap()
        .write_all(second_jwk.as_bytes())
        .unwrap();
    let add_out = add_child.wait_with_output().unwrap();
    assert_eq!(add_out.status.code(), Some(1));
    let add_json = parse_json_stdout(&add_out);
    assert_eq!(add_json["error"]["code"], "GATE_POLICY_TAMPERED");
    assert!(
        add_json["next"]
            .as_array()
            .unwrap_or(&Vec::new())
            .iter()
            .any(|s| s.as_str().unwrap_or("").contains("hyp gate apply")),
        "expected next hint to suggest `hyp gate apply`: {add_json}"
    );

    // `hyp auth revoke` MUST also fail closed with `GATE_POLICY_TAMPERED`.
    let revoke_out = isolated_cmd(home)
        .args([
            "auth",
            "revoke",
            &admin.kid(),
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--local",
            "--no-open",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(revoke_out.status.code(), Some(1));
    let revoke_json = parse_json_stdout(&revoke_out);
    assert_eq!(revoke_json["error"]["code"], "GATE_POLICY_TAMPERED");

    // Verify `gate_lock_seal` was NOT overwritten or incremented!
    let seal_after = db
        .human()
        .get_gate_lock_seal()
        .unwrap()
        .expect("gate_lock_seal row");
    assert_eq!(seal_after.seal_seq, seal_before.seal_seq);
    assert_eq!(seal_after.signed_claim_json, seal_before.signed_claim_json);
}

#[test]
fn historical_unlocked_seal_cannot_authorize_mutations_or_reopen_bootstrap() {
    use hyp_crypto::human::{
        HumanApprovalActionV1, HumanAudience, HumanClaimV1, HumanDropKind, sign_human_claim,
    };
    use hyp_crypto::rfc3339::{format_rfc3339_millis, now_unix_ms};
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let state = home.join("state");
    let config = state.join("node.json");
    fs::create_dir_all(&state).unwrap();
    fs::write(
        &config,
        json!({"nodeId":"migration@box", "profile":"local"}).to_string(),
    )
    .unwrap();
    let admin = TestPasskeyAdmin::generate("admin", "historical-passkey");
    admin.enroll_via_web(home, &state, Some(&config));
    let now = now_unix_ms();
    let exp = format_rfc3339_millis(now + 60_000);
    let action = HumanApprovalActionV1 {
        v: 1,
        action: hyp_crypto::human::HumanApprovalActionKind::GateUnlock,
        node_id: "migration@box".into(),
        nonce: "historical_unlock_nonce".into(),
        exp: exp.clone(),
        seal_seq: 1,
        locked: false,
        policy_sha256: None,
        authorities_digest: None,
        target_human_id: None,
        target_kid: None,
        target_role: None,
        bump_epoch: None,
        cascade: None,
        parameters: None,
    };
    let claim = HumanClaimV1 {
        v: 1,
        kind: HumanDropKind::Approval,
        claim_id: "historical_unlock_claim".into(),
        human_id: admin.human_id.clone(),
        human_kid: admin.kid(),
        auth_epoch: 1,
        issued_at: format_rfc3339_millis(now),
        expires_at: exp,
        drop_id: String::new(),
        audience: HumanAudience {
            node_id: "migration@box".into(),
            node_enc_kid: admin.enc_kp.kid(),
            handle: None,
        },
        secret_spec: None,
        body: serde_json::to_string(&action).unwrap(),
    };
    let signed = sign_human_claim(&claim, &admin.ed_kp).unwrap();
    let db = NodeDb::open(state.join("node.sqlite")).unwrap();
    db.human()
        .put_gate_lock_seal(1, &serde_json::to_string(&signed).unwrap(), now)
        .unwrap();
    let before = fs::read(&config).unwrap();
    let out = isolated_cmd(home)
        .args([
            "gate",
            "init",
            "--adapter",
            "openai-compat",
            "--state-dir",
            state.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
            "--local",
            "--no-open",
            "--ttl",
            "1",
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(parse_json_stdout(&out)["error"]["code"], "APPROVAL_TIMEOUT");
    assert_eq!(fs::read(&config).unwrap(), before);
    assert_eq!(
        db.human().get_gate_lock_seal().unwrap().unwrap().seal_seq,
        1
    );
    // Even removing active-key availability cannot turn history into first enrollment.
    db.human()
        .revoke_authority_monotonic(&admin.human_id, &admin.kid(), 1, "{}", now)
        .unwrap();
    let out = isolated_cmd(home)
        .args([
            "auth",
            "init",
            "--web",
            "--state-dir",
            state.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        parse_json_stdout(&out)["error"]["code"],
        "PASSKEY_ADMIN_ENROLLED"
    );
    assert_eq!(db.human().list_authorities(true).unwrap().len(), 1);
}

#[test]
fn live_nonce_parameters_and_pending_state_are_bound_to_one_operation() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let state = home.join("state");
    let config = state.join("node.json");
    let admin = TestPasskeyAdmin::generate("admin", "passkey");
    admin.enroll_via_web(home, &state, Some(&config));
    let mut cmd = isolated_cmd(home);
    cmd.args([
        "gate",
        "init",
        "--adapter",
        "openai-compat",
        "--state-dir",
        state.to_str().unwrap(),
        "--config",
        config.to_str().unwrap(),
        "--local",
        "--no-open",
        "--ttl",
        "15",
        "--json",
    ]);
    let mut process = ManagedProcess::spawn("pending policy mutation", &mut cmd);
    let url = loop {
        let line = process
            .try_read_stderr_line(Duration::from_secs(10))
            .unwrap();
        if let Some((_, url)) = line.split_once("Hyphae Passkey approval URL: ") {
            break url.to_string();
        }
    };
    let fragment = TestPasskeyAdmin::parse_approval_url(&url);
    let action = admin.open_approval_from_fragment(&fragment);
    for mutate in ["nonce", "parameters"] {
        let mut changed = action.clone();
        if mutate == "nonce" {
            changed.nonce = "nonce_from_another_ceremony".into();
        } else {
            changed.parameters.as_mut().unwrap()["policy"]["stage1"]["outbound_dlp_enabled"] =
                json!(false);
        }
        let (token, _) = admin.seal_approval(&fragment, &changed);
        let (status, response) =
            TestPasskeyAdmin::post_approval_to_fragment(&fragment, &token, "https://hyphae.to");
        assert_eq!(status, 403, "{response}");
        assert!(response["error"].as_str().unwrap().contains(mutate));
    }
    // Change the actual input only after the process has announced its exact request.
    let concurrent_config =
        json!({"nodeId": action.node_id, "profile":"local", "concurrentEdit":true}).to_string();
    fs::write(&config, &concurrent_config).unwrap();
    let (token, _) = admin.seal_approval(&fragment, &action);
    let (status, response) =
        TestPasskeyAdmin::post_approval_to_fragment(&fragment, &token, "https://hyphae.to");
    assert_eq!(status, 201, "{response}");
    let (status, result) = process.wait_json_output(Duration::from_secs(10));
    assert_eq!(status.code(), Some(1));
    assert_eq!(result["error"]["code"], "APPROVAL_STATE_CHANGED");
    assert_eq!(fs::read_to_string(&config).unwrap(), concurrent_config);
    let db = NodeDb::open(state.join("node.sqlite")).unwrap();
    assert!(db.human().get_gate_lock_seal().unwrap().is_none());
}

#[test]
fn live_auth_admit_binds_delegation_and_last_admin_cannot_be_revoked() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let state = home.join("state");
    let config = state.join("node.json");
    let admin = TestPasskeyAdmin::generate("admin", "passkey");
    admin.enroll_via_web(home, &state, Some(&config));
    let member = Ed25519KeyPair::generate().unwrap();
    let jwk = serde_json::to_string(&member.to_jwk()).unwrap();
    let (code, result, stderr, action) = admin.run_and_approve_json(
        home,
        &[
            "auth",
            "admit",
            "member",
            "--stdin",
            "--node-prefix",
            "member@*",
            "--max-devices",
            "3",
            "--state-dir",
            state.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
            "--local",
            "--no-open",
            "--json",
        ],
        Some(&jwk),
    );
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(result["data"]["kid"], member.kid());
    assert_eq!(result["data"]["gatePolicyResigned"], true);
    assert_eq!(
        action.action,
        hyp_crypto::human::HumanApprovalActionKind::AuthAdmit
    );
    assert_eq!(action.parameters.unwrap()["delegation"]["maxDevices"], 3);
    let db = NodeDb::open(state.join("node.sqlite")).unwrap();
    assert_eq!(
        db.human()
            .get_delegation_policy("member")
            .unwrap()
            .unwrap()
            .max_devices,
        3
    );
    let before = db.human().get_gate_lock_seal().unwrap();
    let out = isolated_cmd(home)
        .args([
            "auth",
            "revoke",
            &admin.kid(),
            "--state-dir",
            state.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        parse_json_stdout(&out)["error"]["code"],
        "PASSKEY_ADMIN_REQUIRED_AFTER_REVOKE"
    );
    assert_eq!(db.human().get_gate_lock_seal().unwrap(), before);
    assert!(
        db.human()
            .get_active_authority_by_kid(&admin.kid())
            .unwrap()
            .is_some()
    );
    // A verified remote self-revocation is a trust reduction even when the local CLI would
    // refuse to retire its last approver. Historical policy evidence stays valid, not eligible.
    let local_id = db.local().get_metadata("node_id").unwrap().unwrap();
    let mut cfg = hyp_node::engine::NodeConfig::local(
        hyp_proto::address::NodeId::new(local_id).unwrap(),
        &state,
    );
    cfg.secret_backend = Some(SecretBackend::File);
    let node = hyp_node::engine::UnifiedNode::open(cfg).unwrap();
    let reduction = hyp_crypto::human::sign_human_revocation(
        &hyp_crypto::human::HumanRevocationPayloadV1 {
            v: 1,
            human_id: admin.human_id.clone(),
            revoked_kid: admin.kid(),
            new_min_auth_epoch: 1,
            revoked_at: hyp_crypto::rfc3339::format_rfc3339_millis(hyp_store::now_ms()),
            reason: "retired remotely".into(),
            issuer_kid: admin.kid(),
        },
        &admin.ed_kp,
    )
    .unwrap();
    node.ingest_human_revocation(&reduction).unwrap();
    let doctor = isolated_cmd(home)
        .args([
            "doctor",
            "--state-dir",
            state.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    let status = parse_json_stdout(&doctor);
    assert_eq!(status["data"]["gate"]["gatePolicySig"], "OK");
    assert!(
        status["data"]["gate"]["detail"]
            .as_str()
            .unwrap()
            .contains("no eligible Passkey Admin")
    );
    let denied = isolated_cmd(home)
        .args([
            "gate",
            "apply",
            "--state-dir",
            state.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    let denied = parse_json_stdout(&denied);
    assert_eq!(denied["error"]["code"], "PASSKEY_AUTHORITY_REQUIRED");
    assert!(
        denied["next"]
            .as_array()
            .unwrap()
            .iter()
            .all(|next| !next.as_str().unwrap_or_default().contains("auth init"))
    );
    assert_eq!(db.human().get_gate_lock_seal().unwrap(), before);
}

#[test]
fn authority_update_cannot_remove_the_only_approving_admin_and_unreadable_state_is_not_bootstrap() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let state = home.join("state");
    let config = state.join("node.json");
    let admin = TestPasskeyAdmin::generate("admin", "passkey");
    admin.enroll_via_web(home, &state, Some(&config));
    let db = NodeDb::open(state.join("node.sqlite")).unwrap();
    let before = db.human().list_authorities(true).unwrap();
    let mut child = isolated_cmd(home)
        .args([
            "auth",
            "add",
            "--human-id",
            "admin",
            "--label",
            "downgrade",
            "--role",
            "signer",
            "--state-dir",
            state.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(
            serde_json::to_string(&admin.ed_kp.to_jwk())
                .unwrap()
                .as_bytes(),
        )
        .unwrap();
    let result = child.wait_with_output().unwrap();
    assert_eq!(
        parse_json_stdout(&result)["error"]["code"],
        "PASSKEY_AUTHORITY_REQUIRED"
    );
    assert_eq!(db.human().list_authorities(true).unwrap(), before);
    // A corrupt existing database must never be mistaken for a new installation.
    let broken = home.join("broken-state");
    fs::create_dir_all(&broken).unwrap();
    fs::write(broken.join("node.sqlite"), "not a database").unwrap();
    let out = isolated_cmd(home)
        .args([
            "auth",
            "init",
            "--web",
            "--state-dir",
            broken.to_str().unwrap(),
            "--json",
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert_eq!(
        fs::read_to_string(broken.join("node.sqlite")).unwrap(),
        "not a database"
    );
}

#[test]
fn legacy_hmac_policy_migrates_through_first_web_enrollment_and_separate_live_apply() {
    use hyp_node::gates::{SecurityGateConfig, sign_gate_policy};
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let state = home.join("state");
    let config = state.join("node.json");
    fs::create_dir_all(&state).unwrap();
    let secrets = SecretStore::new(&state, SecretBackend::File);
    let mut policy = SecurityGateConfig {
        require_signed_policy: true,
        ..Default::default()
    };
    policy.policy_signature = Some(sign_gate_policy(&policy, &secrets).unwrap());
    let original =
        json!({"nodeId":"legacy-hmac@box", "profile":"local", "gate":policy}).to_string();
    fs::write(&config, &original).unwrap();
    let admin = TestPasskeyAdmin::generate("admin", "first-passkey");
    admin.enroll_via_web(home, &state, Some(&config));
    assert_eq!(fs::read_to_string(&config).unwrap(), original);
    let db = NodeDb::open(state.join("node.sqlite")).unwrap();
    assert!(db.human().get_gate_lock_seal().unwrap().is_none());
    let (code, result, stderr, _) = admin.run_and_approve_json(
        home,
        &[
            "gate",
            "apply",
            "--state-dir",
            state.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
            "--local",
            "--no-open",
            "--json",
        ],
        None,
    );
    assert_eq!(code, 0, "{stderr}");
    assert_eq!(result["data"]["approved"], true);
    let migrated: Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
    assert_eq!(
        migrated["gate"]["stage1"],
        serde_json::to_value(&policy.stage1).unwrap()
    );
    assert!(migrated["gate"]["policy_signature"].is_null());
    assert!(db.human().get_gate_lock_seal().unwrap().is_some());
}

#[test]
fn final_writer_lock_rechecks_prestate_after_the_browser_ceremony() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let state = home.join("state");
    let config = state.join("node.json");
    let admin = TestPasskeyAdmin::generate("admin", "passkey");
    admin.enroll_via_web(home, &state, Some(&config));
    let member = Ed25519KeyPair::generate().unwrap();
    let mut command = isolated_cmd(home);
    command
        .args([
            "auth",
            "add",
            "--human-id",
            "member",
            "--label",
            "member",
            "--role",
            "signer",
            "--state-dir",
            state.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
            "--local",
            "--no-open",
            "--ttl",
            "30",
            "--json",
        ])
        .stdin(Stdio::piped());
    let mut process = ManagedProcess::spawn("serialized authority commit", &mut command);
    process
        .take_stdin()
        .unwrap()
        .write_all(serde_json::to_string(&member.to_jwk()).unwrap().as_bytes())
        .unwrap();
    let url = loop {
        let line = process
            .try_read_stderr_line(Duration::from_secs(10))
            .unwrap();
        if let Some((_, url)) = line.split_once("Hyphae Passkey approval URL: ") {
            break url.to_owned();
        }
    };
    let fragment = TestPasskeyAdmin::parse_approval_url(&url);
    let action = admin.open_approval_from_fragment(&fragment);
    let locker = NodeDb::open(state.join("node.sqlite")).unwrap();
    let concurrent = Ed25519KeyPair::generate().unwrap();
    locker
        .with_write_transaction(|| {
            let (token, _) = admin.seal_approval(&fragment, &action);
            let (status, response) =
                TestPasskeyAdmin::post_approval_to_fragment(&fragment, &token, "https://hyphae.to");
            assert_eq!(status, 201, "{response}");
            loop {
                let line = process
                    .try_read_stderr_line(Duration::from_secs(10))
                    .unwrap();
                if line.contains("Applying approved operation...") {
                    break;
                }
            }
            // The ceremony's after-check already passed. This commit occurs before its blocked final
            // writer can proceed, so only the serialized final check can reject the stale request.
            locker
                .human()
                .upsert_authority(
                    &hyp_store::HumanAuthorityInput {
                        human_id: "concurrent".into(),
                        kid: concurrent.kid(),
                        label: "concurrent".into(),
                        role: hyp_store::HumanAuthorityRole::Signer,
                        jwk_json: serde_json::to_string(&concurrent.to_jwk()).unwrap(),
                        enc_jwk_json: None,
                        prf_salt: None,
                        auth_epoch: 1,
                    },
                    hyp_store::now_ms(),
                )
                .unwrap();
            Ok::<(), hyp_store::StoreError>(())
        })
        .unwrap();

    let (status, result) = process.wait_json_output(Duration::from_secs(10));
    assert_eq!(status.code(), Some(1));
    assert_eq!(result["error"]["code"], "APPROVAL_COMMIT_FAILED");
    assert!(
        result["error"]["message"]
            .as_str()
            .unwrap()
            .contains("prestate changed before commit")
    );
    assert!(
        locker
            .human()
            .get_active_authority_by_kid(&member.kid())
            .unwrap()
            .is_none()
    );
    assert!(
        locker
            .human()
            .get_active_authority_by_kid(&concurrent.kid())
            .unwrap()
            .is_some()
    );
    assert!(locker.human().get_gate_lock_seal().unwrap().is_none());
    let replay_count: i64 = locker
        .connection()
        .query_row(
            "SELECT count(*) FROM human_claim_nonces WHERE kind='approval'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(replay_count, 0);
}

#[test]
fn gate_apply_resolves_legacy_config_identity_from_sqlite() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let state = home.join("state");
    let config = state.join("node.json");
    let admin = TestPasskeyAdmin::generate("admin", "passkey");
    admin.enroll_via_web(home, &state, Some(&config));
    fs::write(
        &config,
        json!({"nodeId":"legacy@box", "gate":{}}).to_string(),
    )
    .unwrap();
    let mut raw: Value = serde_json::from_slice(&fs::read(&config).unwrap()).unwrap();
    let node_id = raw.as_object_mut().unwrap().remove("nodeId").unwrap();
    NodeDb::open(state.join("node.sqlite"))
        .unwrap()
        .local()
        .set_metadata("node_id", node_id.as_str().unwrap())
        .unwrap();
    fs::write(&config, serde_json::to_vec(&raw).unwrap()).unwrap();
    let (code, result, stderr, action) = admin.run_and_approve_json(
        home,
        &[
            "gate",
            "apply",
            "--state-dir",
            state.to_str().unwrap(),
            "--config",
            config.to_str().unwrap(),
            "--local",
            "--no-open",
            "--json",
        ],
        None,
    );
    assert_eq!(code, 0, "{result}: {stderr}");
    assert_eq!(action.node_id, node_id.as_str().unwrap());
}
