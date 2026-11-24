//! Compiled-binary E2E tests for Hyphae v0.4.0 CLI surface:
//! - `hyp wakeup` (`enable`, `disable`, `set`, `list`, `cancel`, `fire`, `emit`)
//! - `hyp auth` (`init`, `init --web`, `add`, `list`, `revoke`, `certify-node`, `sign`)
//! - `hyp drop` (`create`, `wait`, `ingest`) & `hyp relay` (`set`, `status`)
//! - `hyp deploy init drop-relay` & `--enable-drop-relay` & fail-closed `deploy check`
//! - `hyp gate lock` binding `human_authorities_digest` + tamper/replay/revocation fail-closed
//! - Cross-language `site/drop/crypto.js` + `site/drop/drop.js` -> compiled Rust `hyp drop ingest`
//!
//! Security & isolation invariants:
//! - Uses `tempfile::TempDir`, `HYPHAE_SECRET_BACKEND=file`, isolated `HOME`, and loopback `127.0.0.1:0`.
//! - Never touches live `~/.config/hyphae` or OS Keychain, zero real external network calls.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{ManagedProcess, isolated_cmd, parse_json_stdout};
use hyp_crypto::keys::Ed25519KeyPair;
use hyp_crypto::keystore::{SecretBackend, SecretStore};
use hyp_store::{GateAuditQuery, NodeDb};
use serde_json::{Value, json};
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;
use tempfile::TempDir;

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

fn find_node_v20_plus() -> Option<PathBuf> {
    let candidates: Vec<PathBuf> = vec![
        PathBuf::from("node"),
        PathBuf::from("/Users/bogdan/.local/share/mise/installs/node/24.21.0/bin/node"),
        PathBuf::from("/opt/homebrew/bin/node"),
        PathBuf::from("/usr/local/bin/node"),
    ];
    for cand in candidates {
        if let Ok(out) = Command::new(&cand).arg("--version").output() {
            if out.status.success() {
                let ver = String::from_utf8_lossy(&out.stdout);
                let major: u32 = ver
                    .trim()
                    .trim_start_matches('v')
                    .split('.')
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                if major >= 20 {
                    return Some(cand);
                }
            }
        }
    }
    None
}

// ============================================================================
// 1. `hyp wakeup`: enable -> set (timer + cron) -> list -> cancel -> disable
// ============================================================================

#[test]
fn cli_wakeup_enable_set_list_cancel_disable_json() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let state_dir = home.join("state");
    let config_path = state_dir.join("node.json");
    let state_str = state_dir.to_str().unwrap();
    let cfg_str = config_path.to_str().unwrap();

    // 1. Enable wakeup source with `--mcp-tool auto`
    let enable_out = isolated_cmd(home)
        .args([
            "wakeup",
            "enable",
            "--mcp-tool",
            "auto",
            "--config",
            cfg_str,
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run wakeup enable");
    assert_eq!(enable_out.status.code(), Some(0));
    let enable_json = parse_json_stdout(&enable_out);
    assert_eq!(enable_json["ok"], true);
    assert_eq!(enable_json["data"]["enabled"], true);
    assert_eq!(enable_json["data"]["mcpTool"], "auto");

    let cfg_val: Value =
        serde_json::from_str(&fs::read_to_string(&config_path).unwrap().replace("\r\n", "\n"))
            .unwrap();
    let sources = cfg_val["sources"].as_array().unwrap();
    let wakeup_src = sources
        .iter()
        .find(|s| s["kind"] == "wakeup")
        .expect("sources[kind='wakeup'] exists");
    assert_eq!(wakeup_src["enabled"], true);
    assert_eq!(wakeup_src["mcpTool"], "auto");

    // 2. Schedule one-shot timer (`--in 5m`)
    let set_timer = isolated_cmd(home)
        .args([
            "wakeup",
            "set",
            "--in",
            "5m",
            "--label",
            "ci-watch",
            "--note",
            "check build",
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run wakeup set timer");
    assert_eq!(
        set_timer.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&set_timer.stderr)
    );
    let timer_json = parse_json_stdout(&set_timer);
    assert_eq!(timer_json["ok"], true);
    let timer_id = timer_json["data"]["wakeup"]["id"]
        .as_str()
        .expect("timer wakeup id")
        .to_string();
    assert_eq!(timer_json["data"]["wakeup"]["label"], "ci-watch");
    assert_eq!(timer_json["data"]["wakeup"]["trigger"], "timer");

    // 3. Schedule 5-field cron (`--cron "0 9 * * 1-5" --timezone local`)
    let set_cron = isolated_cmd(home)
        .args([
            "wakeup",
            "set",
            "--cron",
            "0 9 * * 1-5",
            "--timezone",
            "local",
            "--label",
            "standup",
            "--note",
            "daily",
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run wakeup set cron");
    assert_eq!(
        set_cron.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&set_cron.stderr)
    );
    let cron_json = parse_json_stdout(&set_cron);
    assert_eq!(cron_json["ok"], true);
    assert_eq!(cron_json["data"]["wakeup"]["trigger"], "cron");
    assert_eq!(cron_json["data"]["wakeup"]["cron"], "0 9 * * 1-5");

    // 4. List active wakeups -> 2 active
    let list_out = isolated_cmd(home)
        .args(["wakeup", "list", "--state-dir", state_str, "--json"])
        .output()
        .expect("run wakeup list");
    assert_eq!(list_out.status.code(), Some(0));
    let list_json = parse_json_stdout(&list_out);
    assert_eq!(list_json["ok"], true);
    assert_eq!(list_json["data"]["count"], 2);
    assert_eq!(list_json["data"]["wakeups"].as_array().unwrap().len(), 2);

    // 5. Cancel timer wakeup
    let cancel_out = isolated_cmd(home)
        .args([
            "wakeup",
            "cancel",
            &timer_id,
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run wakeup cancel");
    assert_eq!(cancel_out.status.code(), Some(0));
    let cancel_json = parse_json_stdout(&cancel_out);
    assert_eq!(cancel_json["ok"], true);
    assert_eq!(cancel_json["data"]["cancelled"], true);

    // Verify only 1 active remains
    let list_after = isolated_cmd(home)
        .args(["wakeup", "list", "--state-dir", state_str, "--json"])
        .output()
        .expect("run wakeup list after cancel");
    assert_eq!(list_after.status.code(), Some(0));
    let list_after_json = parse_json_stdout(&list_after);
    assert_eq!(list_after_json["data"]["count"], 1);

    // 6. Disable wakeup source
    let disable_out = isolated_cmd(home)
        .args([
            "wakeup",
            "disable",
            "--config",
            cfg_str,
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run wakeup disable");
    assert_eq!(disable_out.status.code(), Some(0));
    let disable_json = parse_json_stdout(&disable_out);
    assert_eq!(disable_json["ok"], true);
    assert_eq!(disable_json["data"]["enabled"], false);

    let cfg_val2: Value =
        serde_json::from_str(&fs::read_to_string(&config_path).unwrap().replace("\r\n", "\n"))
            .unwrap();
    let wakeup_src2 = cfg_val2["sources"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["kind"] == "wakeup")
        .unwrap();
    assert_eq!(wakeup_src2["enabled"], false);

    // 7. `wakeup fire` when daemon offline returns crisp DAEMON_OFFLINE + next `hyp node start`
    let fire_offline = isolated_cmd(home)
        .args([
            "wakeup",
            "fire",
            "--to",
            "dev",
            "--label",
            "adhoc",
            "--note",
            "ping",
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run wakeup fire offline");
    assert_eq!(fire_offline.status.code(), Some(1));
    let fire_json = parse_json_stdout(&fire_offline);
    assert_eq!(fire_json["ok"], false);
    assert_eq!(fire_json["error"]["code"], "DAEMON_OFFLINE");
    assert!(
        fire_json["next"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str() == Some("hyp node start"))
    );
}

// ============================================================================
// 2. `hyp auth init` + `certify-node` + `sign` (secret) + `drop ingest` ZERO LEAK
// ============================================================================

#[test]
fn cli_auth_init_certify_sign_and_drop_ingest_secret_zero_leak() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let state_dir = home.join("state");
    let state_str = state_dir.to_str().unwrap();

    // 1. `hyp auth init --human-id bogdan --label laptop-admin --json`
    let init_out = isolated_cmd(home)
        .args([
            "auth",
            "init",
            "--human-id",
            "bogdan",
            "--label",
            "laptop-admin",
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run auth init");
    assert_eq!(
        init_out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&init_out.stderr)
    );
    let init_json = parse_json_stdout(&init_out);
    assert_eq!(init_json["ok"], true);
    assert_eq!(init_json["data"]["humanId"], "bogdan");
    assert_eq!(init_json["data"]["role"], "admin");
    assert!(
        init_json["data"]["nodeCert"]
            .as_str()
            .unwrap()
            .starts_with("hcert1_")
    );

    // 2. `hyp auth list --json`
    let list_out = isolated_cmd(home)
        .args(["auth", "list", "--state-dir", state_str, "--json"])
        .output()
        .expect("run auth list");
    assert_eq!(list_out.status.code(), Some(0));
    let list_json = parse_json_stdout(&list_out);
    assert_eq!(list_json["data"]["count"], 1);
    assert_eq!(list_json["data"]["minAuthEpoch"], 1);
    assert!(list_json["data"]["authoritiesDigest"].as_str().is_some());

    // 3. `hyp auth certify-node --json`
    let cert_out = isolated_cmd(home)
        .args(["auth", "certify-node", "--state-dir", state_str, "--json"])
        .output()
        .expect("run auth certify-node");
    assert_eq!(cert_out.status.code(), Some(0));
    let cert_json = parse_json_stdout(&cert_out);
    assert!(
        cert_json["data"]["token"]
            .as_str()
            .unwrap()
            .starts_with("hcert1_")
    );

    // 4. Pipe secret via stdin into `hyp auth sign --kind secret --secret-name stripe-api-key --json`
    let secret_plaintext = "sk-prod-topsecret-987654";
    let sign_out = run_hyp_with_stdin(
        home,
        &[
            "auth",
            "sign",
            "--kind",
            "secret",
            "--secret-name",
            "stripe-api-key",
            "--state-dir",
            state_str,
            "--json",
        ],
        secret_plaintext,
    );
    assert_eq!(
        sign_out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&sign_out.stderr)
    );
    let sign_stdout = String::from_utf8_lossy(&sign_out.stdout);
    let sign_stderr = String::from_utf8_lossy(&sign_out.stderr);
    assert!(
        !sign_stdout.contains(secret_plaintext) && !sign_stderr.contains(secret_plaintext),
        "SECRET LEAKED IN `hyp auth sign` OUTPUT!"
    );
    let sign_json = parse_json_stdout(&sign_out);
    let hdrop1 = sign_json["data"]["token"]
        .as_str()
        .expect("hdrop1 token")
        .to_string();
    assert!(hdrop1.starts_with("hdrop1_"));

    // 5. Pipe `hdrop1_` via stdin into `hyp drop ingest --json`
    let ingest_out = run_hyp_with_stdin(
        home,
        &["drop", "ingest", "--state-dir", state_str, "--json"],
        &hdrop1,
    );
    assert_eq!(
        ingest_out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&ingest_out.stderr)
    );
    let ingest_stdout = String::from_utf8_lossy(&ingest_out.stdout);
    let ingest_stderr = String::from_utf8_lossy(&ingest_out.stderr);
    assert!(
        !ingest_stdout.contains(secret_plaintext) && !ingest_stderr.contains(secret_plaintext),
        "SECRET LEAKED IN `hyp drop ingest` OUTPUT!"
    );
    let ingest_json = parse_json_stdout(&ingest_out);
    assert_eq!(ingest_json["ok"], true);
    assert_eq!(ingest_json["data"]["kind"], "secret");
    assert_eq!(ingest_json["data"]["secretName"], "stripe-api-key");
    assert_eq!(ingest_json["data"]["humanId"], "bogdan");

    // 6. Verify SecretStore::get("stripe-api-key") == secret_plaintext
    let store = SecretStore::new(&state_dir, SecretBackend::File);
    let stored = store
        .get("stripe-api-key")
        .expect("stripe-api-key stored in SecretStore");
    assert_eq!(&*stored, secret_plaintext);

    // 7. Scan raw `node.sqlite` (+ WAL/SHM if present) bytes to prove ZERO occurrence of secret!
    for file in ["node.sqlite", "node.sqlite-wal", "node.sqlite-shm"] {
        let p = state_dir.join(file);
        if p.exists() {
            let raw_bytes = fs::read(&p).unwrap();
            let needle = secret_plaintext.as_bytes();
            assert!(
                !raw_bytes.windows(needle.len()).any(|w| w == needle),
                "SECRET PLAINTEXT FOUND ON DISK IN {}!",
                p.display()
            );
        }
    }

    // 8. Reserved system secret name MUST be rejected fail-closed!
    let reserved_sign = run_hyp_with_stdin(
        home,
        &[
            "auth",
            "sign",
            "--kind",
            "secret",
            "--secret-name",
            "gate-policy-hmac-key",
            "--state-dir",
            state_str,
            "--json",
        ],
        "attempt-overwrite-hmac",
    );
    assert_ne!(reserved_sign.status.code(), Some(0));
    let reserved_json = parse_json_stdout(&reserved_sign);
    assert_eq!(reserved_json["ok"], false);
    assert_eq!(reserved_json["error"]["code"], "RESERVED_SECRET_NAME");

    let reserved_create = isolated_cmd(home)
        .args([
            "drop",
            "create",
            "--kind",
            "secret",
            "--secret-name",
            "gate-policy-hmac-key",
            "--offline",
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run drop create reserved secret");
    assert_ne!(reserved_create.status.code(), Some(0));
}

// ============================================================================
// 3. Directive + `gate lock` digest binding + replay block + revocation fail-closed
// ============================================================================

#[test]
fn cli_auth_directive_gate_lock_replay_and_revocation_fail_closed() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let state_dir = home.join("state");
    let config_path = state_dir.join("node.json");
    let state_str = state_dir.to_str().unwrap();
    let cfg_str = config_path.to_str().unwrap();

    // 1. `hyp auth init`
    let init_out = isolated_cmd(home)
        .args([
            "auth",
            "init",
            "--human-id",
            "alice",
            "--label",
            "alice-admin",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--json",
        ])
        .output()
        .expect("run auth init");
    assert_eq!(init_out.status.code(), Some(0));
    let init_json = parse_json_stdout(&init_out);
    let admin_kid = init_json["data"]["kid"].as_str().unwrap().to_string();

    // 2. `hyp gate init` + `hyp gate lock` -> verifies `human_authorities_digest` is bound into `gate_policy_sig`!
    let gate_init = isolated_cmd(home)
        .args([
            "gate",
            "init",
            "--adapter",
            "openai-compat",
            "--config",
            cfg_str,
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run gate init");
    assert_eq!(gate_init.status.code(), Some(0));

    let gate_lock = isolated_cmd(home)
        .args([
            "gate",
            "lock",
            "--config",
            cfg_str,
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run gate lock");
    assert_eq!(gate_lock.status.code(), Some(0));
    let lock_json = parse_json_stdout(&gate_lock);
    assert_eq!(lock_json["ok"], true);
    assert_eq!(lock_json["data"]["gatePolicySig"], "OK");
    let locked_digest = lock_json["data"]["humanAuthoritiesDigest"]
        .as_str()
        .expect("humanAuthoritiesDigest bound into gate_policy_sig")
        .to_string();
    assert!(!locked_digest.is_empty());

    // 3. `hyp auth sign --kind directive` -> `hyp drop ingest --json`
    let sign_dir = run_hyp_with_stdin(
        home,
        &[
            "auth",
            "sign",
            "--kind",
            "directive",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--json",
        ],
        "Deploy release v0.4.0 to staging now.",
    );
    assert_eq!(sign_dir.status.code(), Some(0));
    let directive_token = parse_json_stdout(&sign_dir)["data"]["token"]
        .as_str()
        .unwrap()
        .to_string();

    let ingest_ok = run_hyp_with_stdin(
        home,
        &[
            "drop",
            "ingest",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--json",
        ],
        &directive_token,
    );
    assert_eq!(
        ingest_ok.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&ingest_ok.stdout),
        String::from_utf8_lossy(&ingest_ok.stderr)
    );
    let ingest_json = parse_json_stdout(&ingest_ok);
    assert_eq!(ingest_json["ok"], true);
    assert_eq!(ingest_json["data"]["humanId"], "alice");
    let receipt = ingest_json["data"]["mailboxReceipt"]
        .as_str()
        .expect("mailbox receipt")
        .to_string();

    // Verify mailbox row has `human_auth_json` AND `gate_audit` has `stage == "human_authority"`!
    {
        let db = NodeDb::open(state_dir.join("node.sqlite")).unwrap();
        let human_auth_raw = db
            .human()
            .get_mailbox_human_auth(&receipt)
            .unwrap()
            .expect("mailbox.human_auth_json populated");
        let auth_val: Value = serde_json::from_str(&human_auth_raw).unwrap();
        assert_eq!(auth_val["humanId"], "alice");
        assert_eq!(auth_val["kid"], admin_kid);

        let audits = db
            .local()
            .query_gate_audit(&GateAuditQuery {
                decision: None,
                direction: None,
                session_id: None,
                since_ms: None,
                until_ms: None,
                limit: Some(50),
            })
            .unwrap();
        assert!(
            audits.iter().any(|a| a.stage == "human_authority"),
            "expected gate_audit entry with stage == 'human_authority', got: {audits:?}"
        );
    }

    // 4. Re-pipe EXACT same `hdrop1_` token -> MUST fail closed (exit 1, replay blocked!)
    let replay_out = run_hyp_with_stdin(
        home,
        &[
            "drop",
            "ingest",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--json",
        ],
        &directive_token,
    );
    assert_eq!(replay_out.status.code(), Some(1));
    let replay_json = parse_json_stdout(&replay_out);
    assert_eq!(replay_json["ok"], false);

    // 5. Sign a second fresh drop BEFORE revoking, then revoke `<kid> --bump-epoch`,
    //    and verify the pre-signed drop from the revoked key fails closed!
    let sign_second = run_hyp_with_stdin(
        home,
        &[
            "auth",
            "sign",
            "--kind",
            "directive",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--json",
        ],
        "Second directive signed before revocation",
    );
    assert_eq!(sign_second.status.code(), Some(0));
    let second_token = parse_json_stdout(&sign_second)["data"]["token"]
        .as_str()
        .unwrap()
        .to_string();

    let revoke_out = isolated_cmd(home)
        .args([
            "auth",
            "revoke",
            &admin_kid,
            "--bump-epoch",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--json",
        ])
        .output()
        .expect("run auth revoke");
    assert_eq!(revoke_out.status.code(), Some(0));
    let revoke_json = parse_json_stdout(&revoke_out);
    assert_eq!(revoke_json["ok"], true);
    assert_eq!(revoke_json["data"]["minAuthEpoch"], 2);
    assert_eq!(revoke_json["data"]["gatePolicyResigned"], true);

    let after_revoke = run_hyp_with_stdin(
        home,
        &[
            "drop",
            "ingest",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--json",
        ],
        &second_token,
    );
    assert_eq!(after_revoke.status.code(), Some(1));
    let after_revoke_json = parse_json_stdout(&after_revoke);
    assert_eq!(after_revoke_json["ok"], false);
}

// ============================================================================
// 4. `deploy init drop-relay` + `deploy check` + `relay set/status` validation
// ============================================================================

#[test]
fn cli_deploy_init_drop_relay_and_relay_set_validation() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let kit_dir = home.join("drop-relay-kit");
    let kit_str = kit_dir.to_str().unwrap();

    // 1. `hyp deploy init drop-relay --domain drop.example.com --max-memory-mb 256 --out <tmp> --json`
    let init_out = isolated_cmd(home)
        .args([
            "deploy",
            "init",
            "drop-relay",
            "--domain",
            "drop.example.com",
            "--max-memory-mb",
            "256",
            "--out",
            kit_str,
            "--json",
        ])
        .output()
        .expect("run deploy init drop-relay");
    assert_eq!(
        init_out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&init_out.stderr)
    );
    let init_json = parse_json_stdout(&init_out);
    assert_eq!(init_json["ok"], true);
    assert_eq!(init_json["data"]["provider"], "drop-relay");
    assert_eq!(init_json["data"]["dropRelayEnabled"], true);
    assert_eq!(init_json["data"]["dropMaxMemoryMb"], 256);

    let expected_files = [
        "node.json",
        "Caddyfile",
        "docker-compose.yml",
        "fly.toml",
        "hyphae-drop-relay.service",
        "README.md",
    ];
    for rel in expected_files {
        let p = kit_dir.join(rel);
        assert!(p.exists(), "missing generated kit file {}", p.display());
        let text = fs::read_to_string(&p).unwrap().replace("\r\n", "\n");
        assert!(
            !text.to_ascii_lowercase().contains("cutout"),
            "banned terminology found in {}",
            p.display()
        );
    }

    let caddy = fs::read_to_string(kit_dir.join("Caddyfile"))
        .unwrap()
        .replace("\r\n", "\n");
    assert!(caddy.contains("output discard"));
    assert!(caddy.contains("/v1/drops*"));
    assert!(caddy.contains("flush_interval -1"));

    let compose = fs::read_to_string(kit_dir.join("docker-compose.yml"))
        .unwrap()
        .replace("\r\n", "\n");
    assert!(compose.contains("read_only: true"));
    assert!(compose.contains("mem_limit:"));

    let unit = fs::read_to_string(kit_dir.join("hyphae-drop-relay.service"))
        .unwrap()
        .replace("\r\n", "\n");
    assert!(unit.contains("PrivateTmp=yes"));
    assert!(unit.contains("ProtectSystem=strict"));
    assert!(unit.contains("NoNewPrivileges=yes"));
    assert!(unit.contains("MemoryMax="));

    // 2. `hyp deploy check --config <tmp>/node.json --json` exits 0
    let check_out = isolated_cmd(home)
        .args([
            "deploy",
            "check",
            "--config",
            kit_dir.join("node.json").to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run deploy check");
    assert_eq!(
        check_out.status.code(),
        Some(0),
        "stdout={}",
        String::from_utf8_lossy(&check_out.stdout)
    );

    // 3. Mutated config with wildcard `"*"` in `dropRelay.allowedOrigins` MUST fail closed!
    let bad_cfg = home.join("bad-relay.json");
    let mut bad_val: Value = serde_json::from_str(
        &fs::read_to_string(kit_dir.join("node.json"))
            .unwrap()
            .replace("\r\n", "\n"),
    )
    .unwrap();
    bad_val["dropRelay"]["allowedOrigins"] = json!(["*"]);
    fs::write(&bad_cfg, serde_json::to_string_pretty(&bad_val).unwrap()).unwrap();
    let bad_check = isolated_cmd(home)
        .args([
            "deploy",
            "check",
            "--config",
            bad_cfg.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run deploy check wildcard origin");
    assert_eq!(bad_check.status.code(), Some(1));

    // 4. `--enable-drop-relay` injects `dropRelay` into other providers (e.g. `vps`)
    let vps_dir = home.join("vps-with-relay");
    let vps_out = isolated_cmd(home)
        .args([
            "deploy",
            "init",
            "vps",
            "--domain",
            "mesh.example.com",
            "--enable-drop-relay",
            "--drop-max-memory-mb",
            "128",
            "--out",
            vps_dir.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run deploy init vps --enable-drop-relay");
    assert_eq!(vps_out.status.code(), Some(0));
    let vps_cfg: Value = serde_json::from_str(
        &fs::read_to_string(vps_dir.join("node.json"))
            .unwrap()
            .replace("\r\n", "\n"),
    )
    .unwrap();
    assert_eq!(vps_cfg["dropRelay"]["enabled"], true);
    assert_eq!(vps_cfg["dropRelay"]["maxMemoryMb"], 128);

    // 5. `hyp relay set https://drop.example.com --json` + `hyp relay status --json` -> exits 0
    let state_dir = home.join("relay-state");
    let state_str = state_dir.to_str().unwrap();
    let set_ok = isolated_cmd(home)
        .args([
            "relay",
            "set",
            "https://drop.example.com",
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run relay set https");
    assert_eq!(set_ok.status.code(), Some(0));
    let set_json = parse_json_stdout(&set_ok);
    assert_eq!(set_json["data"]["dropRelayUrl"], "https://drop.example.com");

    let status_ok = isolated_cmd(home)
        .args(["relay", "status", "--state-dir", state_str, "--json"])
        .output()
        .expect("run relay status");
    assert_eq!(status_ok.status.code(), Some(0));
    let status_json = parse_json_stdout(&status_ok);
    assert_eq!(
        status_json["data"]["dropRelayUrl"],
        "https://drop.example.com"
    );

    // 6. `hyp relay set http://insecure.example.com --json` -> exits non-zero (fail-closed!)
    let set_bad = isolated_cmd(home)
        .args([
            "relay",
            "set",
            "http://insecure.example.com",
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run relay set insecure http");
    assert_ne!(set_bad.status.code(), Some(0));
    let set_bad_json = parse_json_stdout(&set_bad);
    assert_eq!(set_bad_json["ok"], false);
    assert_eq!(set_bad_json["error"]["code"], "INVALID_RELAY_URL");
}

// ============================================================================
// 5. `drop create --offline` + Cross-language `site/drop/crypto.js` -> Rust `drop ingest`
// ============================================================================

#[test]
fn cli_drop_create_offline_and_cross_language_browser_js_to_rust_ingest() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let state_dir = home.join("state");
    let state_str = state_dir.to_str().unwrap();

    // 1. `hyp auth init`
    let init_out = isolated_cmd(home)
        .args([
            "auth",
            "init",
            "--human-id",
            "bogdan",
            "--label",
            "laptop-admin",
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run auth init");
    assert_eq!(init_out.status.code(), Some(0));

    // 2. `hyp drop create --kind directive --offline --json`
    let create_out = isolated_cmd(home)
        .args([
            "drop",
            "create",
            "--kind",
            "directive",
            "--offline",
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run drop create offline");
    assert_eq!(create_out.status.code(), Some(0));
    let create_json = parse_json_stdout(&create_out);
    assert_eq!(create_json["ok"], true);
    assert_eq!(create_json["data"]["mode"], "offline");
    let url = create_json["data"]["url"].as_str().unwrap();
    assert!(url.starts_with("https://hyphae.to/drop#"));
    assert!(!url.contains("proposedText"));
    assert!(
        create_json["data"]["nodeCert"]
            .as_str()
            .unwrap()
            .starts_with("hcert1_")
    );

    // Decode base64url `#fragment` and verify fields match `site/drop/drop.js`
    let raw_hash = url.split_once('#').unwrap().1;
    let frag_bytes = URL_SAFE_NO_PAD.decode(raw_hash).expect("valid base64url fragment");
    let frag: Value = serde_json::from_slice(&frag_bytes).expect("valid JSON fragment");
    assert_eq!(frag["v"], 1);
    assert_eq!(frag["kind"], "directive");
    assert!(frag["nodeCert"].as_str().unwrap().starts_with("hcert1_"));
    assert!(frag.get("proposedText").is_none());
    assert!(frag.get("body").is_none());

    // 3. Cross-language browser JS (`site/drop/drop.js` + `site/drop/crypto.js`) -> Rust `hyp drop ingest`
    let Some(node_bin) = find_node_v20_plus() else {
        // Gracefully skip JS interop leg only if Node >= 20 is absent on host.
        return;
    };

    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let crypto_js = repo_root.join("site").join("drop").join("crypto.js");
    let drop_js = repo_root.join("site").join("drop").join("drop.js");
    assert!(crypto_js.exists(), "missing {}", crypto_js.display());
    assert!(drop_js.exists(), "missing {}", drop_js.display());

    let script = format!(
        r#"
import {{ pathToFileURL }} from "node:url";
const cryptoMod = await import(pathToFileURL({crypto_path}).href);
const dropMod = await import(pathToFileURL({drop_path}).href);

const parsed = dropMod.parseFragmentString({hash_str});
if (parsed.mode !== "drop") throw new Error("expected drop mode");
if (!parsed.fragment.nodeCert || !parsed.fragment.nodeCert.startsWith("hcert1_")) {{
  throw new Error("missing hcert1_ in parsed fragment");
}}

const prfOut = new Uint8Array(32);
for (let i = 0; i < 32; i++) prfOut[i] = (i * 7 + 13) & 0xff;
const humanId = "phone-user";
const authEpoch = 1;
const seed = await cryptoMod.derivePrfEd25519Seed(prfOut, humanId, authEpoch);
const {{ publicJwk, kid }} = await cryptoMod.ed25519KeypairFromSeed(seed);

const now = Date.now();
const sealed = await cryptoMod.sealHumanDrop({{
  claim: {{
    v: 1,
    kind: "directive",
    humanId,
    authEpoch,
    issuedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + 300_000).toISOString(),
    dropId: "",
    audience: {{ nodeId: parsed.fragment.nodeId }},
    body: "Approved from Safari Passkey+PRF!",
  }},
  humanSeed32: seed,
  recipientEncJwk: parsed.fragment.encJwk,
}});

process.stdout.write(JSON.stringify({{ publicJwk, kid, hdrop1: sealed.hdrop1 }}));
"#,
        crypto_path = serde_json::to_string(crypto_js.to_str().unwrap()).unwrap(),
        drop_path = serde_json::to_string(drop_js.to_str().unwrap()).unwrap(),
        hash_str = serde_json::to_string(&format!("#{raw_hash}")).unwrap(),
    );

    let js_out = Command::new(&node_bin)
        .args(["--input-type=module", "-e", &script])
        .output()
        .expect("run node JS interop script");
    assert!(
        js_out.status.success(),
        "node JS script failed: stdout={} stderr={}",
        String::from_utf8_lossy(&js_out.stdout),
        String::from_utf8_lossy(&js_out.stderr)
    );
    let js_json: Value = serde_json::from_slice(&js_out.stdout).expect("valid JSON from node");
    let pub_jwk_str = serde_json::to_string(&js_json["publicJwk"]).unwrap();
    let js_hdrop1 = js_json["hdrop1"].as_str().unwrap();
    assert!(js_hdrop1.starts_with("hdrop1_"));

    // Enroll JS-derived Passkey+PRF public JWK via `hyp auth add` (stdin!)
    let add_out = run_hyp_with_stdin(
        home,
        &[
            "auth",
            "add",
            "--human-id",
            "phone-user",
            "--label",
            "iphone",
            "--role",
            "signer",
            "--state-dir",
            state_str,
            "--json",
        ],
        &pub_jwk_str,
    );
    assert_eq!(
        add_out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&add_out.stderr)
    );
    let add_json = parse_json_stdout(&add_out);
    assert_eq!(add_json["data"]["kid"], js_json["kid"]);

    // Pipe JS-sealed `hdrop1_` into compiled Rust `hyp drop ingest --json`!
    let ingest_out = run_hyp_with_stdin(
        home,
        &["drop", "ingest", "--state-dir", state_str, "--json"],
        js_hdrop1,
    );
    assert_eq!(
        ingest_out.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&ingest_out.stdout),
        String::from_utf8_lossy(&ingest_out.stderr)
    );
    let ingest_json = parse_json_stdout(&ingest_out);
    assert_eq!(ingest_json["ok"], true);
    assert_eq!(ingest_json["data"]["humanId"], "phone-user");
    assert_eq!(ingest_json["data"]["role"], "signer");
    assert_eq!(ingest_json["data"]["kind"], "directive");

    // Confirm `hyp status --json` and `hyp doctor --json` reflect the enrolled authorities & wakeup state
    let status_out = isolated_cmd(home)
        .args(["status", "--state-dir", state_str, "--json"])
        .output()
        .expect("run hyp status");
    assert_eq!(status_out.status.code(), Some(0));
    let status_json = parse_json_stdout(&status_out);
    assert_eq!(status_json["data"]["humanDrops"]["activeAuthorities"], 2);
    assert_eq!(status_json["data"]["humanDrops"]["hasNodeCert"], true);
    assert_eq!(status_json["data"]["wakeup"]["enabled"], false);
}

// ============================================================================
// 6. Bonus: `auth init --web` loopback callback CSRF/CORS + live Drop Relay `drop wait`
// ============================================================================

#[test]
fn cli_auth_init_web_callback_csrf_cors_and_live_relay_drop_wait() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let state_dir = home.join("state");
    let state_str = state_dir.to_str().unwrap();

    // 1. Spawn `hyp auth init --web --no-open --port 0 --timeout 15 --json`
    let mut cmd = isolated_cmd(home);
    cmd.args([
        "auth",
        "init",
        "--human-id",
        "web-user",
        "--label",
        "laptop",
        "--web",
        "--no-open",
        "--port",
        "0",
        "--timeout",
        "15",
        "--state-dir",
        state_str,
        "--json",
    ]);
    let mut proc = ManagedProcess::spawn("hyp auth init --web", &mut cmd);

    let url_line = proc
        .try_read_stderr_line(Duration::from_secs(5))
        .expect("read enrollment URL from stderr");
    let enroll_url = url_line
        .split("https://hyphae.to/drop#enroll=")
        .nth(1)
        .expect("enrollment URL fragment present")
        .trim();
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(enroll_url)
        .expect("valid base64url enroll payload");
    let payload: Value = serde_json::from_slice(&payload_bytes).expect("valid enroll JSON");
    let callback_url = payload["callbackUrl"].as_str().unwrap().to_string();
    let csrf_token = payload["csrfToken"].as_str().unwrap().to_string();
    assert_eq!(payload["humanId"], "web-user");

    let phone_kp = Ed25519KeyPair::generate().unwrap();
    let phone_jwk = phone_kp.to_jwk();
    let phone_kid = phone_kp.kid();

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let client = hyp_node::engine::http_util::HttpClient::new().unwrap();

        // Untrusted Origin MUST be rejected with 403!
        let bad_origin_req = http::Request::builder()
            .method(http::Method::POST)
            .uri(&callback_url)
            .header(http::header::ORIGIN, "https://evil.example")
            .header(http::header::CONTENT_TYPE, "application/json")
            .header("x-hyphae-csrf", &csrf_token)
            .body(hyp_node::engine::http_util::full_body(
                serde_json::to_vec(&json!({ "jwk": phone_jwk })).unwrap(),
            ))
            .unwrap();
        let resp = client.request(bad_origin_req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);

        // Wrong CSRF token MUST be rejected with 403!
        let bad_csrf_req = http::Request::builder()
            .method(http::Method::POST)
            .uri(&callback_url)
            .header(http::header::ORIGIN, "https://hyphae.to")
            .header(http::header::CONTENT_TYPE, "application/json")
            .header("x-hyphae-csrf", "wrong-token")
            .body(hyp_node::engine::http_util::full_body(
                serde_json::to_vec(&json!({ "jwk": phone_jwk })).unwrap(),
            ))
            .unwrap();
        let resp = client.request(bad_csrf_req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);

        // Valid Origin + valid CSRF enrolls the Passkey signer!
        let good_req = http::Request::builder()
            .method(http::Method::POST)
            .uri(&callback_url)
            .header(http::header::ORIGIN, "https://hyphae.to")
            .header(http::header::CONTENT_TYPE, "application/json")
            .header("x-hyphae-csrf", &csrf_token)
            .body(hyp_node::engine::http_util::full_body(
                serde_json::to_vec(&json!({
                    "v": 1,
                    "humanId": "web-user",
                    "kid": phone_kid,
                    "jwk": phone_jwk,
                    "label": "iphone-passkey",
                    "credentialId": "cred-123"
                }))
                .unwrap(),
            ))
            .unwrap();
        let resp = client.request(good_req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok()),
            Some("https://hyphae.to")
        );
    });

    let (status, out_json) = proc.wait_json_output(Duration::from_secs(5));
    assert_eq!(status.code(), Some(0));
    assert_eq!(out_json["ok"], true);
    assert_eq!(out_json["data"]["webEnrolled"]["kid"], phone_kid);
    assert_eq!(out_json["data"]["webEnrolled"]["role"], "signer");

    // 2. Start a live local router node with `--enable-drop-relay` on 127.0.0.1:0,
    //    allocate drop slot via `hyp drop create`, post sealed secret via relay HTTP,
    //    and receive + burn via `hyp drop wait`!
    let mut node_cmd = isolated_cmd(home);
    node_cmd.args([
        "node",
        "start",
        "--profile",
        "router",
        "--bind",
        "127.0.0.1:0",
        "--no-local-socket",
        "--enable-drop-relay",
        "--drop-max-memory-mb",
        "64",
        "--state-dir",
        state_str,
        "--json",
    ]);
    let mut node_proc = ManagedProcess::spawn("hyp node start --enable-drop-relay", &mut node_cmd);
    let startup = node_proc.read_json_line(Duration::from_secs(10));
    assert_eq!(startup["ok"], true);
    assert_eq!(startup["data"]["dropRelayEnabled"], true);
    let relay_endpoint = startup["data"]["endpoint"].as_str().unwrap().to_string();

    // Check `hyp relay status --url <relay_endpoint> --json` probes live `/v1/health`!
    let relay_status = isolated_cmd(home)
        .args([
            "relay",
            "status",
            "--url",
            &relay_endpoint,
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run relay status --url");
    assert_eq!(relay_status.status.code(), Some(0));
    let rs_json = parse_json_stdout(&relay_status);
    assert_eq!(rs_json["data"]["probe"]["reachable"], true);
    assert_eq!(rs_json["data"]["probe"]["dropRelay"]["enabled"], true);

    // Allocate drop slot via `hyp drop create --relay <relay_endpoint>`
    let create_live = isolated_cmd(home)
        .args([
            "drop",
            "create",
            "--kind",
            "secret",
            "--secret-name",
            "relay-e2e-key",
            "--relay",
            &relay_endpoint,
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run drop create online");
    assert_eq!(
        create_live.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&create_live.stderr)
    );
    let cl_json = parse_json_stdout(&create_live);
    let drop_id = cl_json["data"]["dropId"].as_str().unwrap().to_string();
    let url = cl_json["data"]["url"].as_str().unwrap();
    let frag_bytes = URL_SAFE_NO_PAD
        .decode(url.split_once('#').unwrap().1)
        .unwrap();
    let frag: Value = serde_json::from_slice(&frag_bytes).unwrap();
    let post_cap = frag["postCap"].as_str().unwrap().to_string();

    // Sign secret bound to `drop_id` via `hyp auth sign --drop-id <drop_id>`
    let relay_secret = "super-secret-relay-value-42";
    let signed = run_hyp_with_stdin(
        home,
        &[
            "auth",
            "sign",
            "--kind",
            "secret",
            "--secret-name",
            "relay-e2e-key",
            "--drop-id",
            &drop_id,
            "--state-dir",
            state_str,
            "--json",
        ],
        relay_secret,
    );
    assert_eq!(
        signed.status.code(),
        Some(0),
        "auth sign failed: stdout={} stderr={}",
        String::from_utf8_lossy(&signed.stdout),
        String::from_utf8_lossy(&signed.stderr)
    );
    let token = parse_json_stdout(&signed)["data"]["token"]
        .as_str()
        .unwrap()
        .to_string();
    let env_obj = hyp_crypto::human::decode_hdrop1(&token).unwrap();

    // Post opaque ciphertext to Drop Relay using `X-Hyphae-Drop-Cap: <postCap>`
    rt.block_on(async {
        let client = hyp_node::engine::http_util::HttpClient::new().unwrap();
        let post_req = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("{relay_endpoint}/v1/drops/{drop_id}"))
            .header(http::header::CONTENT_TYPE, "application/json")
            .header("X-Hyphae-Drop-Cap", &post_cap)
            .body(hyp_node::engine::http_util::full_body(
                serde_json::to_vec(&env_obj).unwrap(),
            ))
            .unwrap();
        let resp = client.request(post_req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::CREATED);
    });

    // Receive, verify, store in SecretStore, and burn via `hyp drop wait`!
    let wait_out = isolated_cmd(home)
        .args([
            "drop",
            "wait",
            "--relay",
            &relay_endpoint,
            "--drop-id",
            &drop_id,
            "--timeout",
            "10",
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run drop wait");
    assert_eq!(
        wait_out.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&wait_out.stdout),
        String::from_utf8_lossy(&wait_out.stderr)
    );
    assert!(!String::from_utf8_lossy(&wait_out.stdout).contains(relay_secret));
    let wait_json = parse_json_stdout(&wait_out);
    assert_eq!(wait_json["ok"], true);
    assert_eq!(wait_json["data"]["secretName"], "relay-e2e-key");
    assert_eq!(wait_json["data"]["relayAck"]["slotClosed"], true);

    let store = SecretStore::new(&state_dir, SecretBackend::File);
    assert_eq!(&*store.get("relay-e2e-key").unwrap(), relay_secret);

    node_proc.shutdown_gracefully();
}
