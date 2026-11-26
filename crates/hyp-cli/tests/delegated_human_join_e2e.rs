//! Compiled-binary E2E tests for **Option A: Delegated Human-Cert Admission CLI**:
//! - `hyp auth invite <human-id>` (`hjoin1_` + `https://hyphae.to/join#hjoin1_...`, fail-closed on `*`/`bridge:post`/`forward:via`/bare `*` prefix)
//! - `hyp auth whoami` (`hpub1_` identity card) & `hyp auth admit <human-id> --id <hpub1_>`
//! - `hyp join` one-shot ephemeral loopback server (`GET /health`, Origin CORS enforcement,
//!   5-attempt confirmation code fail-closed lockout, `POST /device-info`, `POST /complete`,
//!   live `/v1/auth/claim` + `/v1/pair/delegated` against a real loopback hub, auto-onboarding)
//! - `hyp join --token-file <hjoin1> --local-key` headless CLI join
//! - `hyp join --remote --print-card` + `hyp join --stdin` zero-invite 2nd device join
//! - `hyp pair join <hub-url>` automatic delegated pairing when local `hcert1_` exists
//! - `hyp status --json` displaying `"admitted via human:<id> (ep <n>)"` provenance notes
//! - `hyp auth revoke <human-id> --cascade` (non-TTY refusal + POSIX PTY confirmed cascade revocation)
//!
//! Strictly isolated (`TempDir`, `127.0.0.1:0`, `HYPHAE_SECRET_BACKEND=file`, isolated `HOME`).

mod common;

#[cfg(unix)]
use common::run_hyp_in_pty;
use common::{ManagedProcess, isolated_cmd, parse_json_stdout};
use http::{Method, Request, StatusCode};
use hyp_crypto::human::{
    HumanInviteClaimV1, NodeCertPayloadV1, decode_hjoin1, decode_hpub1, encode_hcert1,
    sign_human_invite_claim, sign_node_cert, verify_human_invite,
};
use hyp_crypto::keys::{Ed25519KeyPair, OkpJwk, X25519KeyPair};
use hyp_crypto::keystore::{SecretBackend, SecretStore};
use hyp_crypto::rfc3339::{format_rfc3339_millis, now_unix_ms};
use hyp_node::engine::http_util::{HttpClient, empty_body, full_body};
use hyp_node::engine::{E2eePolicy, NodeConfig, UnifiedNode};
use hyp_proto::address::NodeId;
use hyp_proto::manifest::{OkpCurve, OkpJwk as ProtoOkpJwk};
use hyp_store::{
    HumanAuthorityInput, HumanAuthorityRole, HumanNodeCertInput, NodeDb, PeerStatus, now_ms,
};
use serde_json::{Value, json};
use std::fs;
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Output, Stdio};
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;

fn loopback_zero() -> SocketAddr {
    "127.0.0.1:0".parse().expect("valid loopback addr")
}

fn run_hyp_with_stdin(home: &Path, args: &[&str], stdin_data: &str) -> Output {
    let mut child = isolated_cmd(home)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|e| panic!("failed to spawn hyp {args:?}: {e}"));
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin_data.as_bytes())
        .expect("write stdin to hyp");
    child.wait_with_output().expect("wait for hyp output")
}

/// Seeds the hub's Admin-CA secret in the exact file SecretStore key used by `hyp auth invite`
/// (`admin-ca-<sha256(hub_node_id)[..12]>`) and returns the `Ed25519KeyPair`.
fn seed_hub_admin_ca(hub_state_dir: &Path, hub_node_id: &str) -> Ed25519KeyPair {
    use sha2::{Digest, Sha256};
    let store = SecretStore::new(hub_state_dir, SecretBackend::File);
    let kp = Ed25519KeyPair::generate().unwrap();
    let hash = hex::encode(Sha256::digest(hub_node_id.as_bytes()));
    let secret_name = format!("admin-ca-{}", &hash[..12]);
    store
        .set(&secret_name, &kp.export_pkcs8_b64())
        .expect("persist hub admin-ca key");
    kp
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delegated_human_join_cli_e2e_full_lifecycle() {
    let hub_tmp = TempDir::new().unwrap();
    let hub_home = hub_tmp.path();
    let hub_state = hub_home.join("state");
    fs::create_dir_all(&hub_state).unwrap();
    let hub_cfg_path = hub_home.join("node.json");

    // 1. Start a live loopback `acme-team` Router Hub with pinned Org Admin-CA public key.
    let admin_ca = seed_hub_admin_ca(&hub_state, "acme-team");
    let admin_proto_jwk = ProtoOkpJwk::new(OkpCurve::Ed25519, &admin_ca.public_key_bytes());

    let mut hub_cfg = NodeConfig::router(NodeId::new("acme-team").unwrap(), &hub_state);
    hub_cfg.secret_backend = Some(SecretBackend::File);
    hub_cfg.e2ee_policy = E2eePolicy::Required;
    hub_cfg.admin_jwk = Some(admin_proto_jwk);

    let hub = UnifiedNode::open(hub_cfg).unwrap();
    let hub_fp = hub.identity().signing.public_key().fingerprint();
    let (hub_addr, _hub_srv) = Arc::clone(&hub).serve(loopback_zero()).await.unwrap();
    let hub_url = format!("http://{hub_addr}");

    // Write hub `node.json` so CLI commands (`hyp auth invite`, `hyp status`, `hyp auth revoke`)
    // discover nodeId/profile/stateDir cleanly.
    fs::write(
        &hub_cfg_path,
        serde_json::to_string_pretty(&json!({
            "v": 2,
            "nodeId": "acme-team",
            "profile": "router",
            "stateDir": hub_state.display().to_string(),
            "listen": { "publicUrl": hub_url },
            "pairing": {
                "adminKey": admin_ca.to_jwk(),
            }
        }))
        .unwrap(),
    )
    .unwrap();

    let hub_state_str = hub_state.to_str().unwrap();
    let hub_cfg_str = hub_cfg_path.to_str().unwrap();

    // 2. `hyp auth invite philip`: forbidden scopes & bare `*` nodePrefix MUST fail closed!
    for bad_args in [
        vec!["auth", "invite", "philip", "--hub", "acme-team", "--endpoint", &hub_url, "--grant", "*", "--state-dir", hub_state_str, "--config", hub_cfg_str, "--json"],
        vec!["auth", "invite", "philip", "--hub", "acme-team", "--endpoint", &hub_url, "--grant", "bridge:post=slack:ops", "--state-dir", hub_state_str, "--config", hub_cfg_str, "--json"],
        vec!["auth", "invite", "philip", "--hub", "acme-team", "--endpoint", &hub_url, "--grant", "forward:via=hub", "--state-dir", hub_state_str, "--config", hub_cfg_str, "--json"],
        vec!["auth", "invite", "philip", "--hub", "acme-team", "--endpoint", &hub_url, "--node-prefix", "*", "--state-dir", hub_state_str, "--config", hub_cfg_str, "--json"],
    ] {
        let out = isolated_cmd(hub_home)
            .args(&bad_args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_ne!(
            out.status.code(),
            Some(0),
            "forbidden invite args {bad_args:?} MUST fail closed"
        );
        let env = parse_json_stdout(&out);
        assert_eq!(env["ok"], false);
    }

    // 2b. Valid `hyp auth invite philip --json` mints signed `hjoin1_` + `https://hyphae.to/join#hjoin1_...`.
    let inv_out = isolated_cmd(hub_home)
        .args([
            "auth",
            "invite",
            "philip",
            "--hub",
            "acme-team",
            "--endpoint",
            &hub_url,
            "--hub-fingerprint",
            &hub_fp,
            "--node-prefix",
            "philip@*",
            "--max-devices",
            "5",
            "--state-dir",
            hub_state_str,
            "--config",
            hub_cfg_str,
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(
        inv_out.status.code(),
        Some(0),
        "hyp auth invite failed: stderr={}",
        String::from_utf8_lossy(&inv_out.stderr)
    );
    let inv_json = parse_json_stdout(&inv_out);
    assert_eq!(inv_json["ok"], true);
    let hjoin1_token = inv_json["data"]["token"].as_str().unwrap().to_string();
    let join_url = inv_json["data"]["joinUrl"].as_str().unwrap();
    assert!(hjoin1_token.starts_with("hjoin1_"));
    assert_eq!(join_url, format!("https://hyphae.to/join#{hjoin1_token}"));
    let signed_inv = decode_hjoin1(&hjoin1_token).unwrap();
    let verified_inv =
        verify_human_invite(&signed_inv, &admin_ca.public_key(), now_unix_ms()).unwrap();
    assert_eq!(verified_inv.human_id, "philip");
    assert_eq!(verified_inv.node_prefix, "philip@*");
    assert_eq!(verified_inv.max_devices, 5);

    // 3. `hyp auth init` + `hyp auth whoami` (`hpub1_`) + `hyp auth admit` on hub!
    let bob_tmp = TempDir::new().unwrap();
    let bob_state = bob_tmp.path().join("state");
    fs::create_dir_all(&bob_state).unwrap();
    let bob_cfg = bob_tmp.path().join("node.json");
    let bob_init = isolated_cmd(bob_tmp.path())
        .args([
            "auth",
            "init",
            "--human-id",
            "bob",
            "--state-dir",
            bob_state.to_str().unwrap(),
            "--config",
            bob_cfg.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(bob_init.status.code(), Some(0));

    let whoami_out = isolated_cmd(bob_tmp.path())
        .args([
            "auth",
            "whoami",
            "--state-dir",
            bob_state.to_str().unwrap(),
            "--config",
            bob_cfg.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(whoami_out.status.code(), Some(0));
    let whoami_json = parse_json_stdout(&whoami_out);
    let bob_hpub1 = whoami_json["data"]["hpub1"].as_str().unwrap().to_string();
    assert!(bob_hpub1.starts_with("hpub1_"));
    let bob_card = decode_hpub1(&bob_hpub1).unwrap();
    assert_eq!(bob_card.human_id, "bob");

    let admit_out = isolated_cmd(hub_home)
        .args([
            "auth",
            "admit",
            "bob",
            "--id",
            &bob_hpub1,
            "--node-prefix",
            "bob@*",
            "--max-devices",
            "3",
            "--state-dir",
            hub_state_str,
            "--config",
            hub_cfg_str,
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(
        admit_out.status.code(),
        Some(0),
        "hyp auth admit failed: stdout={} stderr={}",
        String::from_utf8_lossy(&admit_out.stdout),
        String::from_utf8_lossy(&admit_out.stderr)
    );
    let admit_json = parse_json_stdout(&admit_out);
    assert_eq!(admit_json["ok"], true);
    assert_eq!(admit_json["data"]["humanId"], "bob");
    assert_eq!(admit_json["data"]["nodePrefix"], "bob@*");
    assert!(
        hub.db()
            .human()
            .get_delegation_policy("bob")
            .unwrap()
            .is_some_and(|p| p.delegation_enabled && p.max_devices == 3)
    );

    // 4. `hyp join --port 0 --no-setup --json`: verify 5-attempt confirmation code lockout!
    let lockout_tmp = TempDir::new().unwrap();
    let lockout_state = lockout_tmp.path().join("state");
    let lockout_cfg = lockout_tmp.path().join("node.json");
    let mut lockout_cmd = isolated_cmd(lockout_tmp.path());
    lockout_cmd
        .args([
            "join",
            "--port",
            "0",
            "--no-setup",
            "--timeout",
            "30",
            "--state-dir",
            lockout_state.to_str().unwrap(),
            "--config",
            lockout_cfg.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null());
    let mut lockout_proc = ManagedProcess::spawn("hyp-join-lockout", &mut lockout_cmd);
    let listen_line = lockout_proc
        .try_read_stderr_line(Duration::from_secs(10))
        .expect("read listening JSON line");
    let listen_ev: Value = serde_json::from_str(listen_line.trim()).unwrap();
    let lockout_url = listen_ev["listenUrl"].as_str().unwrap().to_string();
    let http = HttpClient::new().unwrap();

    // GET /health with allowed origin succeeds with ZERO sensitive fields
    let health_resp = http
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(format!("{lockout_url}/health"))
                .header("origin", "https://hyphae.to")
                .body(empty_body())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(health_resp.status(), StatusCode::OK);
    let (_, health_hdrs, health_body) = HttpClient::collect(health_resp, 64 * 1024).await.unwrap();
    assert_eq!(
        health_hdrs
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("https://hyphae.to")
    );
    assert_eq!(
        health_hdrs
            .get("access-control-allow-private-network")
            .and_then(|v| v.to_str().ok()),
        Some("true")
    );
    let health_val: Value = serde_json::from_slice(&health_body).unwrap();
    assert_eq!(
        health_val,
        json!({ "ok": true, "mode": "hyphae-join", "requiresCode": true })
    );

    // Disallowed Origin MUST be rejected with 403!
    let evil_resp = http
        .request(
            Request::builder()
                .method(Method::GET)
                .uri(format!("{lockout_url}/health"))
                .header("origin", "https://evil.example")
                .body(empty_body())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(evil_resp.status(), StatusCode::FORBIDDEN);

    // 5 bad confirmation codes trigger 429 lockout & fail-closed exit!
    for attempt in 1..=5 {
        let resp = http
            .request(
                Request::builder()
                    .method(Method::POST)
                    .uri(format!("{lockout_url}/device-info"))
                    .header("origin", "https://hyphae.to")
                    .header("content-type", "application/json")
                    .header("x-hyphae-join-code", "000-000")
                    .body(full_body(b"{}".to_vec()))
                    .unwrap(),
            )
            .await
            .unwrap();
        if attempt < 5 {
            assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        } else {
            assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        }
    }
    let lockout_status = lockout_proc
        .wait_timeout(Duration::from_secs(10))
        .expect("lockout process must exit promptly");
    assert!(!lockout_status.success());

    // 5. `hyp join --port 0 --no-setup --json` full browser Passkey handoff against live `acme-team` hub!
    let philip_human = Ed25519KeyPair::generate().unwrap();
    let philip_human_enc = X25519KeyPair::generate().unwrap();

    let p1_tmp = TempDir::new().unwrap();
    let p1_state = p1_tmp.path().join("state");
    let p1_cfg = p1_tmp.path().join("node.json");
    let mut p1_cmd = isolated_cmd(p1_tmp.path());
    p1_cmd
        .args([
            "join",
            "--port",
            "0",
            "--no-setup",
            "--timeout",
            "30",
            "--state-dir",
            p1_state.to_str().unwrap(),
            "--config",
            p1_cfg.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null());
    let mut p1_proc = ManagedProcess::spawn("hyp-join-philip1", &mut p1_cmd);
    let p1_listen_line = p1_proc
        .try_read_stderr_line(Duration::from_secs(10))
        .expect("read p1 listening JSON");
    let p1_listen: Value = serde_json::from_str(p1_listen_line.trim()).unwrap();
    let p1_url = p1_listen["listenUrl"].as_str().unwrap().to_string();
    let p1_code = p1_listen["code"].as_str().unwrap().to_string();

    // Browser calls `POST /device-info` with 6-digit code & `humanId` hint
    let dev_resp = http
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("{p1_url}/device-info"))
                .header("origin", "https://hyphae.to")
                .header("content-type", "application/json")
                .header("x-hyphae-join-code", &p1_code)
                .body(full_body(
                    serde_json::to_vec(&json!({ "humanId": "philip" })).unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(dev_resp.status(), StatusCode::OK);
    let (_, _, dev_body) = HttpClient::collect(dev_resp, 64 * 1024).await.unwrap();
    let dev_info: Value = serde_json::from_slice(&dev_body).unwrap();
    let p1_node_id = dev_info["nodeId"].as_str().unwrap().to_string();
    assert!(
        p1_node_id.starts_with("philip@"),
        "expected proposed nodeId starting with philip@, got '{p1_node_id}'"
    );
    let p1_ed_jwk: OkpJwk = serde_json::from_value(dev_info["ed25519Jwk"].clone()).unwrap();
    let p1_x_jwk: OkpJwk = serde_json::from_value(dev_info["x25519Jwk"].clone()).unwrap();

    // Browser signs `HumanInviteClaimV1` + `hcert1_` and POSTs `/complete`!
    let now = now_unix_ms();
    let p1_claim = HumanInviteClaimV1 {
        invite_id: verified_inv.invite_id.clone(),
        hub_node_id: "acme-team".to_string(),
        human_id: "philip".to_string(),
        signing_jwk: philip_human.to_jwk(),
        enc_jwk: Some(philip_human_enc.to_jwk()),
        prf_salt: Some("prf-salt-cli-e2e".to_string()),
        timestamp: format_rfc3339_millis(now),
    };
    let p1_claim_sig = sign_human_invite_claim(&p1_claim, &philip_human).unwrap();
    let p1_cert = encode_hcert1(
        &sign_node_cert(
            &NodeCertPayloadV1 {
                v: 1,
                node_id: p1_node_id.clone(),
                signing_jwk: p1_ed_jwk,
                encryption_jwk: p1_x_jwk,
                human_id: "philip".to_string(),
                human_kid: philip_human.kid(),
                auth_epoch: 1,
                issued_at: format_rfc3339_millis(now),
                expires_at: format_rfc3339_millis(now + 86_400_000),
            },
            &philip_human,
        )
        .unwrap(),
    )
    .unwrap();

    let complete_bundle = json!({
        "hjoin1": hjoin1_token,
        "humanClaim": p1_claim,
        "humanClaimSig": p1_claim_sig,
        "humanAuthority": {
            "humanId": "philip",
            "signingJwk": philip_human.to_jwk(),
            "encJwk": philip_human_enc.to_jwk(),
            "prfSalt": "prf-salt-cli-e2e",
            "authEpoch": 1,
            "label": "passkey-delegated",
        },
        "nodeCert": p1_cert,
        "hubNodeId": "acme-team",
        "hubEndpoint": hub_url,
        "hubFingerprint": hub_fp,
    });
    let comp_resp = http
        .request(
            Request::builder()
                .method(Method::POST)
                .uri(format!("{p1_url}/complete"))
                .header("origin", "https://hyphae.to")
                .header("content-type", "application/json")
                .header("x-hyphae-join-code", &p1_code)
                .body(full_body(serde_json::to_vec(&complete_bundle).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(comp_resp.status(), StatusCode::OK);

    let p1_status = p1_proc
        .wait_timeout(Duration::from_secs(15))
        .expect("hyp join must complete cleanly");
    assert!(
        p1_status.success(),
        "hyp join failed: stderr={}",
        p1_proc.stderr_snapshot()
    );
    let mut p1_stdout = String::new();
    while let Ok(line) = p1_proc.try_read_line(Duration::from_millis(200)) {
        p1_stdout.push_str(&line);
        p1_stdout.push('\n');
    }
    let p1_result: Value = serde_json::from_str(&p1_stdout).unwrap_or_else(|e| {
        panic!("invalid JSON from hyp join ({e}): stdout={p1_stdout}")
    });
    assert_eq!(p1_result["ok"], true);
    assert_eq!(p1_result["data"]["nodeId"], p1_node_id);
    assert_eq!(p1_result["data"]["hubNodeId"], "acme-team");
    assert_eq!(p1_result["data"]["humanId"], "philip");
    assert!(p1_cfg.exists(), "hyp join must auto-create node.json");

    // 6. `hyp join --remote --print-card` + `hyp join --stdin` (2nd device `philip@vps`, ZERO admin invite!)
    let vps_tmp = TempDir::new().unwrap();
    let vps_state = vps_tmp.path().join("state");
    let vps_cfg = vps_tmp.path().join("node.json");
    let card_out = isolated_cmd(vps_tmp.path())
        .args([
            "join",
            "--remote",
            "--print-card",
            "--node-id",
            "philip@vps",
            "--state-dir",
            vps_state.to_str().unwrap(),
            "--config",
            vps_cfg.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(card_out.status.code(), Some(0));
    let card_json = parse_json_stdout(&card_out);
    let vps_ed_jwk: OkpJwk =
        serde_json::from_value(card_json["data"]["deviceCard"]["ed25519Jwk"].clone()).unwrap();
    let vps_x_jwk: OkpJwk =
        serde_json::from_value(card_json["data"]["deviceCard"]["x25519Jwk"].clone()).unwrap();

    let vps_cert = encode_hcert1(
        &sign_node_cert(
            &NodeCertPayloadV1 {
                v: 1,
                node_id: "philip@vps".to_string(),
                signing_jwk: vps_ed_jwk,
                encryption_jwk: vps_x_jwk,
                human_id: "philip".to_string(),
                human_kid: philip_human.kid(),
                auth_epoch: 1,
                issued_at: format_rfc3339_millis(now_unix_ms()),
                expires_at: format_rfc3339_millis(now_unix_ms() + 86_400_000),
            },
            &philip_human,
        )
        .unwrap(),
    )
    .unwrap();
    let vps_bundle = json!({
        "humanAuthority": {
            "humanId": "philip",
            "signingJwk": philip_human.to_jwk(),
            "encJwk": philip_human_enc.to_jwk(),
            "authEpoch": 1,
            "label": "passkey-delegated",
        },
        "nodeCert": vps_cert,
        "hubNodeId": "acme-team",
        "hubEndpoint": hub_url,
        "hubFingerprint": hub_fp,
    });
    let vps_join_out = run_hyp_with_stdin(
        vps_tmp.path(),
        &[
            "join",
            "--stdin",
            "--no-setup",
            "--node-id",
            "philip@vps",
            "--state-dir",
            vps_state.to_str().unwrap(),
            "--config",
            vps_cfg.to_str().unwrap(),
            "--json",
        ],
        &serde_json::to_string(&vps_bundle).unwrap(),
    );
    assert_eq!(
        vps_join_out.status.code(),
        Some(0),
        "hyp join --stdin failed: stdout={} stderr={}",
        String::from_utf8_lossy(&vps_join_out.stdout),
        String::from_utf8_lossy(&vps_join_out.stderr)
    );
    let vps_join_json = parse_json_stdout(&vps_join_out);
    assert_eq!(vps_join_json["ok"], true);
    assert_eq!(vps_join_json["data"]["nodeId"], "philip@vps");

    // 7. `hyp pair join <hub-url>` on certified device `philip@devbox` auto-selects `delegated` mode!
    let devbox_tmp = TempDir::new().unwrap();
    let devbox_state = devbox_tmp.path().join("state");
    fs::create_dir_all(&devbox_state).unwrap();
    let devbox_secrets = SecretStore::new(&devbox_state, SecretBackend::File);
    let devbox_keys = devbox_secrets
        .load_or_create_node_keys("philip@devbox")
        .unwrap();
    let devbox_cert_signed = sign_node_cert(
        &NodeCertPayloadV1 {
            v: 1,
            node_id: "philip@devbox".to_string(),
            signing_jwk: devbox_keys.signing_jwk(),
            encryption_jwk: devbox_keys.encryption_jwk(),
            human_id: "philip".to_string(),
            human_kid: philip_human.kid(),
            auth_epoch: 1,
            issued_at: format_rfc3339_millis(now_unix_ms()),
            expires_at: format_rfc3339_millis(now_unix_ms() + 86_400_000),
        },
        &philip_human,
    )
    .unwrap();
    {
        let db = NodeDb::open(devbox_state.join("node.sqlite")).unwrap();
        let ts = now_ms();
        db.human()
            .upsert_authority(
                &HumanAuthorityInput {
                    human_id: "philip".to_string(),
                    kid: philip_human.kid(),
                    label: "passkey".to_string(),
                    role: HumanAuthorityRole::Signer,
                    jwk_json: serde_json::to_string(&philip_human.to_jwk()).unwrap(),
                    enc_jwk_json: None,
                    prf_salt: None,
                    auth_epoch: 1,
                },
                ts,
            )
            .unwrap();
        db.human()
            .put_node_cert(&HumanNodeCertInput {
                node_id: "philip@devbox".to_string(),
                human_kid: philip_human.kid(),
                auth_epoch: 1,
                signed_json: serde_json::to_string(&devbox_cert_signed).unwrap(),
                issued_at: ts,
                expires_at: ts + 86_400_000,
            })
            .unwrap();
    }
    let pair_join_out = isolated_cmd(devbox_tmp.path())
        .args([
            "pair",
            "join",
            &hub_url,
            "--node-id",
            "philip@devbox",
            "--state-dir",
            devbox_state.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(
        pair_join_out.status.code(),
        Some(0),
        "hyp pair join delegated failed: stdout={} stderr={}",
        String::from_utf8_lossy(&pair_join_out.stdout),
        String::from_utf8_lossy(&pair_join_out.stderr)
    );
    let pair_join_json = parse_json_stdout(&pair_join_out);
    assert_eq!(pair_join_json["ok"], true);
    assert_eq!(pair_join_json["data"]["mode"], "delegated");
    assert_eq!(pair_join_json["data"]["humanId"], "philip");
    assert_eq!(pair_join_json["data"]["nodeId"], "philip@devbox");

    // 8. `hyp join --token-file <hjoin1> --local-key` headless CLI join!
    let ci_inv_out = isolated_cmd(hub_home)
        .args([
            "auth",
            "invite",
            "cibot",
            "--hub",
            "acme-team",
            "--endpoint",
            &hub_url,
            "--node-prefix",
            "cibot@*",
            "--state-dir",
            hub_state_str,
            "--config",
            hub_cfg_str,
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(ci_inv_out.status.code(), Some(0));
    let ci_hjoin1 = parse_json_stdout(&ci_inv_out)["data"]["token"]
        .as_str()
        .unwrap()
        .to_string();

    let ci_tmp = TempDir::new().unwrap();
    let ci_tok_file = ci_tmp.path().join("invite.hjoin1");
    fs::write(&ci_tok_file, &ci_hjoin1).unwrap();
    let ci_state = ci_tmp.path().join("state");
    let ci_cfg = ci_tmp.path().join("node.json");
    let ci_join_out = isolated_cmd(ci_tmp.path())
        .args([
            "join",
            "--token-file",
            ci_tok_file.to_str().unwrap(),
            "--local-key",
            "--no-setup",
            "--node-id",
            "cibot@runner1",
            "--state-dir",
            ci_state.to_str().unwrap(),
            "--config",
            ci_cfg.to_str().unwrap(),
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(
        ci_join_out.status.code(),
        Some(0),
        "hyp join --token-file --local-key failed: stdout={} stderr={}",
        String::from_utf8_lossy(&ci_join_out.stdout),
        String::from_utf8_lossy(&ci_join_out.stderr)
    );
    let ci_join_json = parse_json_stdout(&ci_join_out);
    assert_eq!(ci_join_json["ok"], true);
    assert_eq!(ci_join_json["data"]["nodeId"], "cibot@runner1");
    assert_eq!(ci_join_json["data"]["humanId"], "cibot");

    // 9. `hyp status --json` on the hub shows `"admitted via human:philip (ep 1)"` in peer notes!
    let status_out = isolated_cmd(hub_home)
        .args([
            "status",
            "--state-dir",
            hub_state_str,
            "--config",
            hub_cfg_str,
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(status_out.status.code(), Some(0));
    let status_json = parse_json_stdout(&status_out);
    let peers_arr = status_json["data"]["peers"].as_array().unwrap();
    let philip_vps_row = peers_arr
        .iter()
        .find(|p| p["peer"] == "philip@vps")
        .expect("philip@vps in hyp status peers");
    assert_eq!(philip_vps_row["admittedByHumanId"], "philip");
    assert_eq!(philip_vps_row["admittedAuthEpoch"], 1);
    assert!(
        philip_vps_row["notes"]
            .as_str()
            .unwrap_or("")
            .contains("admitted via human:philip (ep 1)"),
        "expected provenance note in hyp status, got: {}",
        philip_vps_row["notes"]
    );

    // 10. `hyp auth revoke philip --cascade`: non-TTY MUST fail closed (exit 2, zero mutations)!
    let non_tty_rev = isolated_cmd(hub_home)
        .args([
            "auth",
            "revoke",
            "philip",
            "--cascade",
            "--bump-epoch",
            "--state-dir",
            hub_state_str,
            "--config",
            hub_cfg_str,
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert_eq!(non_tty_rev.status.code(), Some(2));
    assert_eq!(
        parse_json_stdout(&non_tty_rev)["error"]["code"],
        "INTERACTIVE_TTY_REQUIRED"
    );
    assert_eq!(
        hub.db().peers().get_peer("philip@vps").unwrap().unwrap().status,
        PeerStatus::Active
    );

    // 10b. Real POSIX PTY confirmation executes `hyp auth revoke philip --cascade --bump-epoch`!
    #[cfg(unix)]
    {
        let pty_res = run_hyp_in_pty(
            hub_home,
            &[
                "auth",
                "revoke",
                "philip",
                "--cascade",
                "--bump-epoch",
                "--state-dir",
                hub_state_str,
                "--config",
                hub_cfg_str,
                "--json",
            ],
            None,
            Some("y\n"),
        );
        assert_eq!(
            pty_res.code,
            0,
            "PTY hyp auth revoke --cascade failed: stdout={} tty={}",
            pty_res.stdout,
            pty_res.tty
        );
        let rev_json: Value = serde_json::from_str(&pty_res.stdout).unwrap();
        assert_eq!(rev_json["ok"], true);
        let revoked_peers: Vec<&str> = rev_json["data"]["revokedPeers"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        assert!(revoked_peers.contains(&p1_node_id.as_str()));
        assert!(revoked_peers.contains(&"philip@vps"));
        assert!(revoked_peers.contains(&"philip@devbox"));
        assert!(!revoked_peers.contains(&"cibot@runner1"));

        // Verify hub DB state: all 3 Philip devices revoked, `cibot@runner1` untouched!
        for pid in [&p1_node_id, &"philip@vps".to_string(), &"philip@devbox".to_string()] {
            assert_eq!(
                hub.db().peers().get_peer(pid).unwrap().unwrap().status,
                PeerStatus::Revoked,
                "peer '{pid}' must be revoked after --cascade"
            );
        }
        assert_eq!(
            hub.db()
                .peers()
                .get_peer("cibot@runner1")
                .unwrap()
                .unwrap()
                .status,
            PeerStatus::Active
        );
    }
}
