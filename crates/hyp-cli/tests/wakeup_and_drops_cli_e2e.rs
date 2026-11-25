//! Compiled-binary E2E tests for Hyphae v0.5.0 CLI surface:
//! - `hyp emit` (flag mode, stdin JSON mode, `--sign` Ed25519 `hyphaesig`, `LocalIngestServer` socket)
//! - `hyp auth` (`init`, `init --web` with `encJwk` + Passkey `nodeCert`, `add`, `list`, `revoke`, `certify-node`, `sign`)
//! - `hyp drop` (`create` with HPKE `encDraft`, zero-flag `wait` via `last_drop.json`, `ingest`) & `hyp relay` (`set`, `status`)
//! - `hyp deploy init drop-relay` (including Cloudflare Workers kit README) & `--enable-drop-relay` & fail-closed `deploy check`
//! - `hyp gate propose` -> `hyp gate lock` merging `gate.proposed.json` + `human_authorities_digest` binding
//! - Cross-language Rust -> JS (`encDraft` open) & JS -> Rust (`hdrop1_` ingest) interop
//!
//! Security & isolation invariants:
//! - Uses `tempfile::TempDir`, `HYPHAE_SECRET_BACKEND=file`, isolated `HOME`, and loopback `127.0.0.1:0`.
//! - Never touches live `~/.config/hyphae` or OS Keychain, zero real external network calls.

mod common;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{ManagedProcess, isolated_cmd, parse_json_stdout};
use hyp_crypto::human::{
    NodeCertPayloadV1, derive_prf_ed25519_keypair, derive_prf_x25519_keypair, encode_hcert1,
    sign_node_cert,
};
use hyp_crypto::keys::{Ed25519KeyPair, OkpJwk, X25519KeyPair};
use hyp_crypto::keystore::{SecretBackend, SecretStore};
use hyp_crypto::rfc3339::{format_rfc3339_millis, now_unix_ms};
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
// 1. `hyp emit`: live `LocalIngestServer` socket (unsigned, stdin JSON, `--sign`)
// ============================================================================

#[test]
fn cli_emit_to_live_node_local_ingest_socket_unsigned_and_signed() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let state_dir = home.join("state");
    fs::create_dir_all(&state_dir).unwrap();
    let state_str = state_dir.to_str().unwrap();

    // 1. Offline `hyp emit` returns crisp INGEST_OFFLINE + next `hyp node start`.
    let offline_out = isolated_cmd(home)
        .args([
            "emit",
            "--label",
            "ci-watch",
            "--note",
            "check build",
            "--state-dir",
            state_str,
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run emit offline");
    assert_eq!(offline_out.status.code(), Some(1));
    let offline_json = parse_json_stdout(&offline_out);
    assert_eq!(offline_json["ok"], false);
    assert_eq!(offline_json["error"]["code"], "INGEST_OFFLINE");
    assert!(
        offline_json["next"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str() == Some("hyp node start"))
    );

    // 2. Start compiled `hyp node start` (default `localIngest.enabled == true`!).
    let mut node_cmd = isolated_cmd(home);
    node_cmd.args([
        "node",
        "start",
        "--profile",
        "local",
        "--state-dir",
        state_str,
        "--json",
    ]);
    let mut node_proc = ManagedProcess::spawn("hyp node start (local ingest)", &mut node_cmd);
    let startup = node_proc.read_json_line(Duration::from_secs(10));
    assert_eq!(startup["ok"], true, "startup={startup}");
    assert_eq!(startup["data"]["localIngestEnabled"], true);
    let ingest_sock_str = startup["data"]["localIngestSocket"]
        .as_str()
        .expect("localIngestSocket path present in startup JSON");
    let ingest_sock_path = Path::new(ingest_sock_str);
    assert!(
        ingest_sock_path.exists(),
        "local ingest endpoint must exist at {}",
        ingest_sock_path.display()
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert!(ingest_sock_str.ends_with("ingest.sock"));
        let mode = fs::metadata(ingest_sock_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "ingest.sock must enforce strictly 0600 perms, got {:o}",
            mode
        );
    }

    // 3. Unsigned flag-mode `hyp emit --label ci-watch --note "check build" --json`.
    let emit_out = isolated_cmd(home)
        .args([
            "emit",
            "--label",
            "ci-watch",
            "--note",
            "check build",
            "--state-dir",
            state_str,
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run emit unsigned");
    assert_eq!(
        emit_out.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&emit_out.stdout),
        String::from_utf8_lossy(&emit_out.stderr)
    );
    let emit_json = parse_json_stdout(&emit_out);
    assert_eq!(emit_json["ok"], true);
    assert_eq!(emit_json["data"]["topic"], "local.schedule");
    assert_eq!(emit_json["data"]["decision"], "allow");
    assert_eq!(emit_json["data"]["trustTier"], "external-webhook");

    // 4. Stdin compact JSON mode (`{"label":"cron-stdin","note":"nightly"}`).
    let stdin_emit = run_hyp_with_stdin(
        home,
        &["emit", "--state-dir", state_str, "--json"],
        r#"{"label":"cron-stdin","note":"nightly"}"#,
    );
    assert_eq!(
        stdin_emit.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&stdin_emit.stderr)
    );
    let stdin_json = parse_json_stdout(&stdin_emit);
    assert_eq!(stdin_json["ok"], true);
    assert_eq!(stdin_json["data"]["topic"], "local.schedule");
    assert_eq!(stdin_json["data"]["decision"], "allow");

    // 5. `hyp auth init` + `hyp emit --sign --label prod-op --note "signed trigger" --json`.
    let auth_out = isolated_cmd(home)
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
    assert_eq!(auth_out.status.code(), Some(0));

    let signed_out = isolated_cmd(home)
        .args([
            "emit",
            "--sign",
            "--label",
            "prod-op",
            "--note",
            "signed trigger",
            "--state-dir",
            state_str,
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run emit --sign");
    assert_eq!(
        signed_out.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&signed_out.stdout),
        String::from_utf8_lossy(&signed_out.stderr)
    );
    let signed_json = parse_json_stdout(&signed_out);
    assert_eq!(signed_json["ok"], true);
    assert_eq!(signed_json["data"]["topic"], "local.schedule");
    assert_eq!(signed_json["data"]["decision"], "allow");
    assert_eq!(signed_json["data"]["trustTier"], "human-verified");
    assert_eq!(signed_json["data"]["verifiedHumanId"], "bogdan");

    // 6. Verify `hyp status --json` reports `data.localIngest.enabled == true` & `socketExists == true`.
    let status_out = isolated_cmd(home)
        .args(["status", "--state-dir", state_str, "--json"])
        .output()
        .expect("run status");
    assert_eq!(status_out.status.code(), Some(0));
    let status_json = parse_json_stdout(&status_out);
    assert_eq!(status_json["data"]["localIngest"]["enabled"], true);
    assert_eq!(status_json["data"]["localIngest"]["socketExists"], true);
    assert_eq!(status_json["data"]["localIngest"]["defaultTopic"], "schedule");
    assert_eq!(status_json["data"]["localIngest"]["routesCount"], 1);

    node_proc.shutdown_gracefully();
}

// ============================================================================
// 1b. `hyp drop create --draft` (HPKE `encDraft`) & Cross-Language Rust -> JS Open
// ============================================================================

#[test]
fn cli_drop_create_encrypted_draft_and_cross_language_rust_to_js_open() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let state_dir = home.join("state");
    let state_str = state_dir.to_str().unwrap();

    // 1. Initialize local admin (no companion X25519 `encJwk` yet).
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

    // 2. Without any enrolled X25519 `encJwk`, `--draft` MUST fail closed (NEVER downgrade to plaintext!).
    let no_enc_out = isolated_cmd(home)
        .args([
            "drop",
            "create",
            "--kind",
            "directive",
            "--draft",
            "Approve deploy v0.5.0 to eu-1",
            "--offline",
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run drop create draft without encJwk");
    assert_ne!(no_enc_out.status.code(), Some(0));
    let no_enc_json = parse_json_stdout(&no_enc_out);
    assert_eq!(no_enc_json["ok"], false);
    assert_eq!(no_enc_json["error"]["code"], "NO_HUMAN_ENC_KEY");
    assert!(
        no_enc_json["next"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str() == Some("hyp auth init --web"))
    );

    // 3. Enroll Passkey-PRF authority WITH companion X25519 `encJwk` via `hyp auth add` stdin bundle!
    let mut prf_out = [0u8; 32];
    for (idx, slot) in prf_out.iter_mut().enumerate() {
        *slot = ((idx * 11 + 5) & 0xff) as u8;
    }
    let human_id = "bogdan";
    let auth_epoch = 1u64;
    let prf_salt = "salt-draft-interop-v050";
    let passkey_ed = derive_prf_ed25519_keypair(&prf_out, human_id, auth_epoch).unwrap();
    let passkey_x = derive_prf_x25519_keypair(&prf_out, human_id, auth_epoch).unwrap();

    let bundle_json = serde_json::to_string(&json!({
        "v": 1,
        "humanId": human_id,
        "kid": passkey_ed.kid(),
        "jwk": passkey_ed.to_jwk(),
        "encJwk": passkey_x.to_jwk(),
        "prfSalt": prf_salt,
        "authEpoch": auth_epoch,
    }))
    .unwrap();
    let add_out = run_hyp_with_stdin(
        home,
        &[
            "auth",
            "add",
            "--human-id",
            human_id,
            "--label",
            "iphone-passkey",
            "--role",
            "signer",
            "--state-dir",
            state_str,
            "--json",
        ],
        &bundle_json,
    );
    assert_eq!(
        add_out.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&add_out.stdout),
        String::from_utf8_lossy(&add_out.stderr)
    );
    let add_json = parse_json_stdout(&add_out);
    assert_eq!(add_json["ok"], true);
    assert_eq!(add_json["data"]["encKey"], true);
    assert_eq!(add_json["data"]["encKid"], passkey_x.kid());

    // Confirm `hyp auth list --json` and `hyp status --json` reflect the enrolled `encKey`.
    let list_out = isolated_cmd(home)
        .args(["auth", "list", "--state-dir", state_str, "--json"])
        .output()
        .expect("run auth list");
    assert_eq!(list_out.status.code(), Some(0));
    let list_json = parse_json_stdout(&list_out);
    let auths = list_json["data"]["authorities"].as_array().unwrap();
    assert!(
        auths
            .iter()
            .any(|a| a["kid"] == passkey_ed.kid() && a["encKey"] == true && a["encKid"] == passkey_x.kid()),
        "expected encKey=true in auth list: {list_json}"
    );
    let st_out = isolated_cmd(home)
        .args(["status", "--state-dir", state_str, "--json"])
        .output()
        .expect("run status");
    assert_eq!(st_out.status.code(), Some(0));
    let st_json = parse_json_stdout(&st_out);
    assert_eq!(st_json["data"]["humanDrops"]["hasEncJwkCount"], 1);

    // 4. Create directive drop with encrypted draft + context!
    let draft_text = "Approve deploy v0.5.0 to eu-1";
    let draft_ctx = "PR #412";
    let create_out = isolated_cmd(home)
        .args([
            "drop",
            "create",
            "--kind",
            "directive",
            "--draft",
            draft_text,
            "--context",
            draft_ctx,
            "--offline",
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run drop create with encrypted draft");
    assert_eq!(
        create_out.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&create_out.stdout),
        String::from_utf8_lossy(&create_out.stderr)
    );
    let create_json = parse_json_stdout(&create_out);
    assert_eq!(create_json["ok"], true);
    assert_eq!(create_json["data"]["hasEncDraft"], true);
    let drop_url = create_json["data"]["url"].as_str().unwrap();
    assert!(
        drop_url.starts_with("https://hyphae.to/drop#drop="),
        "expected #drop= URL, got: {drop_url}"
    );
    assert!(!drop_url.contains("Approve deploy"));
    assert!(!drop_url.contains("PR #412"));

    let raw_hash = drop_url.split_once('#').unwrap().1;
    let b64 = raw_hash.strip_prefix("drop=").unwrap();
    let frag_bytes = URL_SAFE_NO_PAD.decode(b64).unwrap();
    let frag_str = String::from_utf8(frag_bytes).unwrap();
    assert!(!frag_str.contains("Approve deploy"));
    assert!(!frag_str.contains("PR #412"));
    let frag: Value = serde_json::from_str(&frag_str).unwrap();
    assert_eq!(frag["encDraft"]["v"], 1);
    assert_eq!(frag["encDraft"]["suite"], "human.draft.v1");
    assert_eq!(frag["encDraft"]["recipientKid"], passkey_x.kid());
    assert!(frag.get("draft").is_none());
    assert!(frag.get("proposedText").is_none());

    // 5. Fail-closed guards: `--kind secret --draft` AND BiDi `\u{202E}` MUST fail closed!
    let secret_draft = isolated_cmd(home)
        .args([
            "drop",
            "create",
            "--kind",
            "secret",
            "--secret-name",
            "demo",
            "--draft",
            "nope",
            "--offline",
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run secret drop with draft");
    assert_ne!(secret_draft.status.code(), Some(0));
    let secret_draft_json = parse_json_stdout(&secret_draft);
    assert_eq!(secret_draft_json["ok"], false);
    assert_eq!(
        secret_draft_json["error"]["code"],
        "DRAFT_FORBIDDEN_FOR_SECRET"
    );

    let bidi_draft = isolated_cmd(home)
        .args([
            "drop",
            "create",
            "--kind",
            "directive",
            "--draft",
            "\u{202E}bad",
            "--offline",
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run bidi draft");
    assert_ne!(bidi_draft.status.code(), Some(0));
    let bidi_json = parse_json_stdout(&bidi_draft);
    assert_eq!(bidi_json["ok"], false);
    assert_eq!(bidi_json["error"]["code"], "INVALID_DRAFT");

    // 6. LIVE CROSS-LANGUAGE RUST -> JS INTEROP TEST (`site/drop/drop.js` + `site/drop/crypto.js`)!
    let Some(node_bin) = find_node_v20_plus() else {
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

    let prf_arr: Vec<u8> = prf_out.to_vec();
    let script = format!(
        r##"
import {{ pathToFileURL }} from "node:url";
const cryptoMod = await import(pathToFileURL({crypto_path}).href);
const dropMod = await import(pathToFileURL({drop_path}).href);

const urlStr = {url_str};
const hashIdx = urlStr.indexOf("#");
if (hashIdx === -1) throw new Error("missing hash fragment");
const parsed = dropMod.parseFragmentString(urlStr.slice(hashIdx));
if (parsed.mode !== "drop") throw new Error("expected drop mode");
if (!parsed.fragment.encDraft || parsed.fragment.encDraft.suite !== "human.draft.v1") {{
  throw new Error("missing human.draft.v1 encDraft in parsed fragment");
}}

const prfOut = new Uint8Array({prf_json});
const encKp = await cryptoMod.derivePrfX25519Keypair(prfOut, {human_id_json}, {auth_epoch});
const opened = await cryptoMod.openHumanDraft({{
  encDraft: parsed.fragment.encDraft,
  recipientPriv32: encKp.privateKeyBytes,
  expectedNodeId: parsed.fragment.nodeId,
}});
process.stdout.write(JSON.stringify(opened));
"##,
        crypto_path = serde_json::to_string(crypto_js.to_str().unwrap()).unwrap(),
        drop_path = serde_json::to_string(drop_js.to_str().unwrap()).unwrap(),
        url_str = serde_json::to_string(drop_url).unwrap(),
        prf_json = serde_json::to_string(&prf_arr).unwrap(),
        human_id_json = serde_json::to_string(human_id).unwrap(),
        auth_epoch = auth_epoch,
    );

    let js_out = Command::new(&node_bin)
        .args(["--input-type=module", "-e", &script])
        .output()
        .expect("run node JS encDraft interop");
    assert!(
        js_out.status.success(),
        "node JS encDraft open failed: stdout={} stderr={}",
        String::from_utf8_lossy(&js_out.stdout),
        String::from_utf8_lossy(&js_out.stderr)
    );
    let opened: Value = serde_json::from_slice(&js_out.stdout).expect("valid JSON from node");
    assert_eq!(opened["text"], draft_text);
    assert_eq!(opened["context"], draft_ctx);
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

    // 4. Pipe secret via stdin into `hyp auth sign --kind secret --secret-name demo-api-key --json`
    let secret_plaintext = "hyphae_zk_test_value_001";
    let sign_out = run_hyp_with_stdin(
        home,
        &[
            "auth",
            "sign",
            "--kind",
            "secret",
            "--secret-name",
            "demo-api-key",
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
    assert_eq!(ingest_json["data"]["secretName"], "demo-api-key");
    assert_eq!(ingest_json["data"]["humanId"], "bogdan");

    // 6. Verify SecretStore::get("demo-api-key") == secret_plaintext
    let store = SecretStore::new(&state_dir, SecretBackend::File);
    let stored = store
        .get("demo-api-key")
        .expect("demo-api-key stored in SecretStore");
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

    let readme = fs::read_to_string(kit_dir.join("README.md"))
        .unwrap()
        .replace("\r\n", "\n");
    assert!(
        readme.contains("workers/drop-relay/"),
        "drop-relay README must mention workers/drop-relay/: {readme}"
    );
    assert!(readme.contains("DropSlotDO"));
    assert!(
        readme.contains("spore.hyphae.to") && !readme.contains("drop.hyphae.to"),
        "drop-relay README must reference spore.hyphae.to instead of drop.hyphae.to: {readme}"
    );
    let useradd_pos = readme
        .find("sudo useradd -r -s /usr/sbin/nologin hyphae || true")
        .expect("drop-relay README missing useradd step");
    let bin_pos = readme
        .find("/usr/local/bin/hyp")
        .expect("drop-relay README missing /usr/local/bin/hyp install");
    let dirs_pos = readme
        .find("sudo mkdir -p /var/lib/hyphae /etc/hyphae && sudo chown -R hyphae:hyphae /var/lib/hyphae /etc/hyphae && sudo chmod 0700 /var/lib/hyphae")
        .expect("drop-relay README missing /var/lib/hyphae setup");
    let systemctl_pos = readme
        .find("systemctl enable --now")
        .expect("drop-relay README missing systemctl enable --now");
    assert!(useradd_pos < systemctl_pos);
    assert!(bin_pos < systemctl_pos);
    assert!(dirs_pos < systemctl_pos);

    let dockerfile = fs::read_to_string(kit_dir.join("Dockerfile"))
        .unwrap()
        .replace("\r\n", "\n");
    assert!(dockerfile.contains(&format!("ARG HYP_VERSION=v{}", env!("CARGO_PKG_VERSION"))));
    assert!(dockerfile.contains("sha256sum -c --ignore-missing"));
    assert!(!dockerfile.contains("COPY Cargo.toml"));

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
    assert!(url.starts_with("https://hyphae.to/drop#drop="));
    assert!(!url.contains("proposedText"));
    assert!(
        create_json["data"]["nodeCert"]
            .as_str()
            .unwrap()
            .starts_with("hcert1_")
    );

    // Decode base64url `#drop=<fragment>` and verify fields match `site/drop/drop.js`
    let raw_hash = url.split_once('#').unwrap().1;
    let frag_b64 = raw_hash.strip_prefix("drop=").unwrap_or(raw_hash);
    let frag_bytes = URL_SAFE_NO_PAD
        .decode(frag_b64)
        .expect("valid base64url fragment");
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

    // Confirm `hyp status --json` and `hyp doctor --json` reflect the enrolled authorities & localIngest state
    let status_out = isolated_cmd(home)
        .args(["status", "--state-dir", state_str, "--json"])
        .output()
        .expect("run hyp status");
    assert_eq!(status_out.status.code(), Some(0));
    let status_json = parse_json_stdout(&status_out);
    assert_eq!(status_json["data"]["humanDrops"]["activeAuthorities"], 2);
    assert_eq!(status_json["data"]["humanDrops"]["hasNodeCert"], true);
    assert_eq!(status_json["data"]["localIngest"]["enabled"], true);
}

// ============================================================================
// 6. `auth init --web` (`encJwk` + Passkey `nodeCert`) + live Drop Relay zero-flag `drop wait`
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
    let enrolled_node_id = payload["nodeId"]
        .as_str()
        .expect("#enroll= must include nodeId")
        .to_string();
    let enrolled_sign_jwk: OkpJwk =
        serde_json::from_value(payload["nodeSignJwk"].clone()).expect("#enroll= nodeSignJwk");
    let enrolled_enc_jwk: OkpJwk =
        serde_json::from_value(payload["nodeEncJwk"].clone()).expect("#enroll= nodeEncJwk");

    let phone_kp = Ed25519KeyPair::generate().unwrap();
    let phone_jwk = phone_kp.to_jwk();
    let phone_kid = phone_kp.kid();
    let phone_enc_kp = X25519KeyPair::generate().unwrap();
    let phone_enc_jwk = phone_enc_kp.to_jwk();
    let phone_enc_kid = phone_enc_kp.kid();

    // Sign NodeCertV1 (`hcert1_`) with the enrolled phone Passkey Ed25519 key!
    let now = now_unix_ms();
    let cert_payload = NodeCertPayloadV1 {
        v: 1,
        node_id: enrolled_node_id,
        signing_jwk: enrolled_sign_jwk,
        encryption_jwk: enrolled_enc_jwk,
        human_id: "web-user".to_string(),
        human_kid: phone_kid.clone(),
        auth_epoch: 1,
        issued_at: format_rfc3339_millis(now),
        expires_at: format_rfc3339_millis(now + 365 * 86_400_000),
    };
    let passkey_signed_cert = sign_node_cert(&cert_payload, &phone_kp).unwrap();
    let passkey_hcert1 = encode_hcert1(&passkey_signed_cert).unwrap();

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

        // Valid Origin + valid CSRF enrolls the Passkey signer WITH `encJwk` and Passkey-signed `nodeCert`!
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
                    "encJwk": phone_enc_jwk,
                    "nodeCert": passkey_hcert1,
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
    assert_eq!(out_json["data"]["webEnrolled"]["encKey"], true);
    assert_eq!(out_json["data"]["webEnrolled"]["encKid"], phone_enc_kid);
    assert_eq!(out_json["data"]["webEnrolled"]["nodeCertSigned"], true);
    assert_eq!(out_json["data"]["nodeCert"], passkey_hcert1);

    // 2. Start a live local router node with `--enable-drop-relay` on 127.0.0.1:0,
    //    allocate drop slot via `hyp drop create`, post sealed secret via relay HTTP,
    //    and receive + burn via zero-flag `hyp drop wait` (auto-reading `last_drop.json`)!
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
    let raw_hash = url.split_once('#').unwrap().1;
    let frag_b64 = raw_hash.strip_prefix("drop=").unwrap_or(raw_hash);
    let frag_bytes = URL_SAFE_NO_PAD.decode(frag_b64).unwrap();
    let frag: Value = serde_json::from_slice(&frag_bytes).unwrap();
    let post_cap = frag["postCap"].as_str().unwrap().to_string();
    assert_eq!(frag["nodeCert"], passkey_hcert1);

    // Verify `<state_dir>/last_drop.json` was persisted atomically (0600 on Unix)!
    let last_drop_path = state_dir.join("last_drop.json");
    assert!(last_drop_path.exists(), "last_drop.json must be written on online drop create");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&last_drop_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "last_drop.json must be 0600, got {:o}", mode);
    }

    // Sign secret bound to `drop_id` via `hyp auth sign --drop-id <drop_id>`
    let relay_secret = "hyphae_zk_relay_test_value_042";
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

    // Receive, verify, store in SecretStore, and burn via zero-flag `hyp drop wait` (reads `last_drop.json`!)
    let wait_out = isolated_cmd(home)
        .args([
            "drop",
            "wait",
            "--timeout",
            "10",
            "--state-dir",
            state_str,
            "--json",
        ])
        .stdin(Stdio::null())
        .output()
        .expect("run zero-flag drop wait");
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
    assert!(
        !last_drop_path.exists(),
        "last_drop.json must be removed after successful ingest & burn"
    );

    let store = SecretStore::new(&state_dir, SecretBackend::File);
    assert_eq!(&*store.get("relay-e2e-key").unwrap(), relay_secret);

    node_proc.shutdown_gracefully();
}

// ============================================================================
// 7. `hyp gate propose` -> `hyp gate lock` merges `gate.proposed.json` & cleans up
// ============================================================================

#[test]
fn cli_gate_propose_then_lock_merges_and_cleans_proposal() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let state_dir = home.join("state");
    let config_path = state_dir.join("node.json");
    let state_str = state_dir.to_str().unwrap();
    let cfg_str = config_path.to_str().unwrap();

    // 1. Stage a proposed filter via `hyp gate propose`
    let prop_out = isolated_cmd(home)
        .args([
            "gate",
            "propose",
            "--adapter",
            "openai-compat",
            "--id",
            "local-ollama-guard",
            "--config",
            cfg_str,
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run gate propose");
    assert_eq!(prop_out.status.code(), Some(0));
    let proposal_path = state_dir.join("gate.proposed.json");
    assert!(proposal_path.exists(), "gate.proposed.json must exist after propose");

    // 2. Lock via `hyp gate lock` -> merges `gate.proposed.json` into `node.json`, signs, and removes proposal!
    let lock_out = isolated_cmd(home)
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
    assert_eq!(
        lock_out.status.code(),
        Some(0),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&lock_out.stdout),
        String::from_utf8_lossy(&lock_out.stderr)
    );
    let lock_json = parse_json_stdout(&lock_out);
    assert_eq!(lock_json["ok"], true);
    assert_eq!(lock_json["data"]["mergedProposal"], true);
    assert_eq!(lock_json["data"]["filterCount"], 1);
    assert_eq!(lock_json["data"]["gatePolicySig"], "OK");
    assert!(
        lock_json["next"]
            .as_array()
            .unwrap()
            .iter()
            .any(|s| s.as_str() == Some("hyp service restart")),
        "gate lock must recommend hyp service restart: {lock_json}"
    );
    assert!(
        !proposal_path.exists(),
        "gate.proposed.json must be deleted after gate lock"
    );

    let cfg_val: Value = serde_json::from_str(
        &fs::read_to_string(&config_path)
            .unwrap()
            .replace("\r\n", "\n"),
    )
    .unwrap();
    assert_eq!(cfg_val["gate"]["require_signed_policy"], true);
    assert_eq!(cfg_val["gate"]["filters"][0]["id"], "local-ollama-guard");
}

// ============================================================================
// 8. `dropPortalUrl` & `HYPHAE_DROP_PORTAL_URL` Override + Fail-Closed Guard
// ============================================================================

#[test]
fn cli_drop_portal_url_override_and_fail_closed_validation() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path();
    let state_dir = home.join("state");
    let config_path = state_dir.join("node.json");
    let state_str = state_dir.to_str().unwrap();
    let cfg_str = config_path.to_str().unwrap();

    // 1. Write `node.json` with `dropPortalUrl` and initialize authority using the same config/nodeId.
    fs::create_dir_all(&state_dir).unwrap();
    fs::write(
        &config_path,
        serde_json::to_string_pretty(&json!({
            "v": 2,
            "nodeId": "portal-test",
            "profile": "local",
            "stateDir": state_str,
            "dropPortalUrl": "https://portal.corp.example/drop/"
        }))
        .unwrap(),
    )
    .unwrap();
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
            "--config",
            cfg_str,
            "--json",
        ])
        .output()
        .expect("run auth init");
    assert_eq!(init_out.status.code(), Some(0));

    // 2. `node.json` `dropPortalUrl` is honored when `HYPHAE_DROP_PORTAL_URL` is unset.
    let cfg_drop = isolated_cmd(home)
        .args([
            "drop",
            "create",
            "--kind",
            "directive",
            "--offline",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--json",
        ])
        .output()
        .expect("run drop create with node.json dropPortalUrl");
    assert_eq!(cfg_drop.status.code(), Some(0));
    let cfg_drop_json = parse_json_stdout(&cfg_drop);
    assert!(
        cfg_drop_json["data"]["url"]
            .as_str()
            .unwrap()
            .starts_with("https://portal.corp.example/drop#drop="),
        "expected node.json dropPortalUrl, got: {cfg_drop_json}"
    );

    // 3. `HYPHAE_DROP_PORTAL_URL=https://drop.acme.com` overrides `node.json` for `drop create` (`#drop=`)!
    let env_drop = isolated_cmd(home)
        .env("HYPHAE_DROP_PORTAL_URL", "https://drop.acme.com")
        .args([
            "drop",
            "create",
            "--kind",
            "directive",
            "--offline",
            "--state-dir",
            state_str,
            "--config",
            cfg_str,
            "--json",
        ])
        .output()
        .expect("run drop create with HYPHAE_DROP_PORTAL_URL");
    assert_eq!(env_drop.status.code(), Some(0));
    let env_drop_json = parse_json_stdout(&env_drop);
    assert!(
        env_drop_json["data"]["url"]
            .as_str()
            .unwrap()
            .starts_with("https://drop.acme.com#drop="),
        "expected https://drop.acme.com#drop=, got: {env_drop_json}"
    );

    // 4. `HYPHAE_DROP_PORTAL_URL=https://drop.acme.com` overrides `hyp auth init --web` (`#enroll=`)
    //    AND scopes loopback callback CORS strictly to `https://drop.acme.com`!
    let mut web_cmd = isolated_cmd(home);
    web_cmd
        .env("HYPHAE_DROP_PORTAL_URL", "https://drop.acme.com")
        .args([
            "auth",
            "init",
            "--human-id",
            "acme-user",
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
            "--config",
            cfg_str,
            "--json",
        ]);
    let mut web_proc = ManagedProcess::spawn("hyp auth init --web (custom portal)", &mut web_cmd);
    let url_line = web_proc
        .try_read_stderr_line(Duration::from_secs(5))
        .expect("read custom portal enroll URL from stderr");
    assert!(
        url_line.contains("https://drop.acme.com#enroll="),
        "expected https://drop.acme.com#enroll= in stderr, got: {url_line}"
    );
    let enroll_b64 = url_line
        .split("https://drop.acme.com#enroll=")
        .nth(1)
        .unwrap()
        .trim();
    let enroll_payload: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(enroll_b64).unwrap()).unwrap();
    let callback_url = enroll_payload["callbackUrl"].as_str().unwrap().to_string();
    let csrf_token = enroll_payload["csrfToken"].as_str().unwrap().to_string();

    let phone_kp = Ed25519KeyPair::generate().unwrap();
    let phone_jwk = phone_kp.to_jwk();
    let phone_kid = phone_kp.kid();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let client = hyp_node::engine::http_util::HttpClient::new().unwrap();
        // Default origin `https://hyphae.to` MUST be rejected when overridden to `https://drop.acme.com`!
        let wrong_origin = http::Request::builder()
            .method(http::Method::POST)
            .uri(&callback_url)
            .header(http::header::ORIGIN, "https://hyphae.to")
            .header(http::header::CONTENT_TYPE, "application/json")
            .header("x-hyphae-csrf", &csrf_token)
            .body(hyp_node::engine::http_util::full_body(
                serde_json::to_vec(&json!({ "jwk": phone_jwk })).unwrap(),
            ))
            .unwrap();
        let resp = client.request(wrong_origin).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);

        // Configured origin `https://drop.acme.com` MUST succeed!
        let ok_req = http::Request::builder()
            .method(http::Method::POST)
            .uri(&callback_url)
            .header(http::header::ORIGIN, "https://drop.acme.com")
            .header(http::header::CONTENT_TYPE, "application/json")
            .header("x-hyphae-csrf", &csrf_token)
            .body(hyp_node::engine::http_util::full_body(
                serde_json::to_vec(&json!({
                    "v": 1,
                    "humanId": "acme-user",
                    "kid": phone_kid,
                    "jwk": phone_jwk,
                    "label": "acme-passkey"
                }))
                .unwrap(),
            ))
            .unwrap();
        let resp = client.request(ok_req).await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get(http::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok()),
            Some("https://drop.acme.com")
        );
    });
    let (web_status, web_json) = web_proc.wait_json_output(Duration::from_secs(5));
    assert_eq!(web_status.code(), Some(0));
    assert_eq!(web_json["ok"], true);

    // 5. Fail-closed: `HYPHAE_DROP_PORTAL_URL=http://evil.example` MUST fail with `CONFIG_ERROR`!
    let bad_drop = isolated_cmd(home)
        .env("HYPHAE_DROP_PORTAL_URL", "http://evil.example")
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
        .expect("run drop create with invalid portal URL");
    assert_eq!(bad_drop.status.code(), Some(1));
    let bad_drop_json = parse_json_stdout(&bad_drop);
    assert_eq!(bad_drop_json["ok"], false);
    assert_eq!(bad_drop_json["error"]["code"], "CONFIG_ERROR");

    let bad_auth = isolated_cmd(home)
        .env("HYPHAE_DROP_PORTAL_URL", "http://evil.example")
        .args([
            "auth",
            "init",
            "--web",
            "--no-open",
            "--state-dir",
            state_str,
            "--json",
        ])
        .output()
        .expect("run auth init --web with invalid portal URL");
    assert_eq!(bad_auth.status.code(), Some(1));
    let bad_auth_json = parse_json_stdout(&bad_auth);
    assert_eq!(bad_auth_json["ok"], false);
    assert_eq!(bad_auth_json["error"]["code"], "CONFIG_ERROR");

    // 6. Fail-closed: invalid `dropPortalUrl` in `node.json` fails `hyp node start` with `CONFIG_ERROR`!
    let bad_node_cfg = home.join("bad-portal-node.json");
    fs::write(
        &bad_node_cfg,
        serde_json::to_string_pretty(&json!({
            "v": 2,
            "nodeId": "bad-portal-node",
            "profile": "local",
            "stateDir": state_str,
            "dropPortalUrl": "http://evil.example"
        }))
        .unwrap(),
    )
    .unwrap();
    let bad_node = isolated_cmd(home)
        .args([
            "node",
            "start",
            "--config",
            bad_node_cfg.to_str().unwrap(),
            "--no-local-socket",
            "--json",
        ])
        .output()
        .expect("run node start with invalid dropPortalUrl");
    assert_eq!(bad_node.status.code(), Some(1));
    let bad_node_json = parse_json_stdout(&bad_node);
    assert_eq!(bad_node_json["ok"], false);
    assert_eq!(bad_node_json["error"]["code"], "CONFIG_ERROR");
}
