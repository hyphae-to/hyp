//! Comprehensive E2E adversarial & differential tests for GitHub Issue #10:
//! Real Passkey-signed human boundary for Security Gate lock/unlock & authority mutations
//! (closing audit findings G1, H1, G6, G7, H2).
//!
//! Covers all 6 mandatory security proofs:
//!   1. `gate lock` / `gate unlock` with 0 authorities AND with ONLY a local CLI PKCS#8 key
//!      (`hyp auth init` non-web) fail closed (`PASSKEY_AUTHORITY_REQUIRED`, `next: hyp auth init --web`)
//!   2. Flipping `require_signed_policy: false` OR deleting `"gate"` in `node.json` while locked
//!      triggers fail-closed tamper detection in `hyp doctor` AND live `hyp daemon` `gate.reload`
//!   3. Running `hyp gate init` (without `--lock`) while locked fails closed (`GATE_LOCKED`)
//!   4. Running `hyp auth add` / `hyp auth revoke` once a Passkey Admin is enrolled prints an approval
//!      URL, rejects unauthorized mutations, updates `gate_lock_seal`, and hot-reloads the live daemon
//!   5. Mutated approvals fail closed: 1-bit flip in `policySha256`, wrong `nodeId`, replayed `nonce`
//!      / `--approval-file` reuse, non-admin (`Signer`) `kid`, revoked `kid`, unknown key, wrong
//!      Origin/CSRF, and `hyp drop ingest` rejecting `kind: "approval"` tokens
//!   6. Full E2E lifecycle: `auth init --web` (zero PKCS#8 secret!) -> `gate init` -> `gate propose`
//!      -> `gate lock` (verifies HPKE-encrypted diff & zero plaintext leak in URL) -> `gate unlock`
//!      -> `auth add` -> `--no-wait` + `--approval-file` -> `hyp doctor` OK!

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
            "lock",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--json",
        ],
        vec![
            "gate",
            "unlock",
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
            "--lock",
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

    for sub in ["lock", "unlock"] {
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
            "--lock",
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
    assert_eq!(lock_json["data"]["locked"], true);
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
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(silent_init.status.code(), Some(1));
    assert_eq!(
        parse_json_stdout(&silent_init)["error"]["code"],
        "GATE_LOCKED"
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

    // 6. Restore `node.json` and cleanly unlock via Passkey-signed `hyp gate unlock` -> live daemon reloads!
    fs::write(&config_path, &locked_raw).unwrap();
    let (unlock_code, unlock_json, unlock_stderr, unlock_action) = passkey.run_and_approve_json(
        home,
        &[
            "gate",
            "unlock",
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
    assert_eq!(unlock_code, 0, "stderr={unlock_stderr}");
    assert_eq!(unlock_action.action, HumanApprovalActionKind::GateUnlock);
    assert_eq!(unlock_json["ok"], true);
    assert_eq!(unlock_json["data"]["locked"], false);

    let doc_unlocked = isolated_cmd(home)
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
    assert_eq!(doc_unlocked.status.code(), Some(0));
    let doc_unlocked_json = parse_json_stdout(&doc_unlocked);
    assert_eq!(
        doc_unlocked_json["data"]["gate"]["gatePolicySig"],
        "UNSIGNED"
    );
    assert_eq!(doc_unlocked_json["data"]["gate"]["tampered"], false);

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
            "init",
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

    // 2. Spawn live loopback `hyp gate lock --local --no-open` and hammer it with EVERY mutated attack!
    let mut lock_cmd = isolated_cmd(home);
    lock_cmd
        .args([
            "gate",
            "lock",
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
    let mut lock_proc = ManagedProcess::spawn("adversarial hyp gate lock", &mut lock_cmd);

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
            "lock",
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
        Some(1),
        "replayed approval file MUST fail closed"
    );
    let replay_env = parse_json_stdout(&replay_out);
    assert_eq!(replay_env["ok"], false);
}

#[test]
fn issue10_offline_no_wait_and_approval_file_full_lifecycle() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let state_dir = home.join("state");
    let config_path = state_dir.join("node.json");
    let state_str = state_dir.to_str().unwrap();
    let cfg_str = config_path.to_str().unwrap();

    let admin = TestPasskeyAdmin::generate("offline-admin", "touchid");
    admin.enroll_via_web(home, &state_dir, Some(&config_path));

    // Stage a filter via `gate propose`, then generate an offline `--no-wait` Passkey approval URL!
    let prop = isolated_cmd(home)
        .args([
            "gate",
            "propose",
            "--adapter",
            "openai-compat",
            "--id",
            "offline-filter",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(prop.status.code(), Some(0));

    let pending_out = isolated_cmd(home)
        .args([
            "gate",
            "lock",
            "--local",
            "--no-wait",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(pending_out.status.code(), Some(0));
    let pending_json = parse_json_stdout(&pending_out);
    assert_eq!(pending_json["data"]["pending"], true);
    assert_eq!(pending_json["data"]["mode"], "offline");
    let url = pending_json["data"]["url"].as_str().unwrap();

    // Sign the offline approval out-of-band and pass it via `--approval-file`!
    let frag = TestPasskeyAdmin::parse_approval_url(url);
    let action = admin.open_approval_from_fragment(&frag);
    let (hdrop1, _) = admin.seal_approval(&frag, &action);
    let approval_file = tmp.path().join("signed-lock.hdrop1");
    fs::write(&approval_file, &hdrop1).unwrap();

    let apply_out = isolated_cmd(home)
        .args([
            "gate",
            "lock",
            "--approval-file",
            approval_file.to_str().unwrap(),
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(
        apply_out.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&apply_out.stdout),
        String::from_utf8_lossy(&apply_out.stderr)
    );
    let apply_json = parse_json_stdout(&apply_out);
    assert_eq!(apply_json["ok"], true);
    assert_eq!(apply_json["data"]["gatePolicySig"], "OK");
    assert_eq!(apply_json["data"]["mergedProposal"], true);

    // Reusing the exact same `--approval-file` a second time fails closed (replay guard)!
    let reuse_out = isolated_cmd(home)
        .args([
            "gate",
            "lock",
            "--approval-file",
            approval_file.to_str().unwrap(),
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--json",
        ])
        .output()
        .unwrap();
    assert_eq!(reuse_out.status.code(), Some(1));

    // Confirm SQLite `gate_lock_seal` is persisted and `hyp doctor` reports OK!
    let db = NodeDb::open(state_dir.join("node.sqlite")).unwrap();
    let seal = db
        .human()
        .get_gate_lock_seal()
        .unwrap()
        .expect("gate_lock_seal row");
    assert_eq!(seal.seal_seq, 1);
    let signed: Value = serde_json::from_str(&seal.signed_claim_json).unwrap();
    let claim: Value = serde_json::from_str(signed["payload"].as_str().unwrap()).unwrap();
    let sealed_action: Value = serde_json::from_str(claim["body"].as_str().unwrap()).unwrap();
    assert_eq!(claim["humanKid"], admin.kid());
    assert_eq!(sealed_action["locked"], true);

    let doc = isolated_cmd(home)
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
    assert_eq!(doc.status.code(), Some(0));
    let doc_json = parse_json_stdout(&doc);
    assert_eq!(doc_json["data"]["gate"]["gatePolicySig"], "OK");
    assert_eq!(doc_json["data"]["gate"]["tampered"], false);
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
            "--lock",
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
    assert_eq!(lock_json["data"]["locked"], true);

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
            .any(|s| s.as_str().unwrap_or("").contains("hyp gate lock")),
        "expected next hint to suggest `hyp gate lock`: {add_json}"
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
