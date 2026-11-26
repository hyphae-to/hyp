//! End-to-end compiled `hyp` CLI tests for 1Password (`1password`), LastPass (`lastpass`),
//! and Linux `pass` (`pass`) secret backends via `HYPHAE_SECRET_BACKEND` + binary override shims.
//!
//! Strictly isolated (`TempDir`, fake CLI shims, zero live vaults, zero live OS keyrings).

mod common;

use common::{isolated_cmd, parse_json_stdout};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tempfile::TempDir;

#[cfg(unix)]
fn write_executable(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, body).expect("write executable shim");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod +x");
}

#[cfg(unix)]
fn make_op_shim(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let store = dir.join("op-store");
    let log = dir.join("op-argv.log");
    let mode = dir.join("op-mode.txt");
    let bin = dir.join("fake-op.sh");
    fs::create_dir_all(&store).unwrap();
    fs::write(&mode, "ok").unwrap();
    let script = format!(
        r#"#!/bin/sh
set -eu
STORE='{store}'
LOG='{log}'
MODE=$(cat '{mode}' 2>/dev/null || echo ok)
printf 'CALL: %s\n' "$*" >> "$LOG"
if [ "$MODE" = "locked" ]; then
  echo '[ERROR] You are not currently signed in. Please run "op signin"' >&2
  exit 1
fi
SUB="${{2:-}}"
shift 2
VAULT=""; TARGET=""
while [ $# -gt 0 ]; do
  case "$1" in
    --vault) VAULT="${{2:-}}"; shift 2 ;;
    --format) shift 2 ;;
    --reveal|-) shift 1 ;;
    *) [ -z "$TARGET" ] && TARGET="$1"; shift 1 ;;
  esac
done
VDIR="$STORE/$(printf '%s' "$VAULT" | tr ' /' '__')"
case "$SUB" in
  create)
    BODY=$(cat)
    TITLE=$(printf '%s' "$BODY" | sed -n 's/.*"title":"\([^"]*\)".*/\1/p')
    FILE="$VDIR/$TITLE.json"
    mkdir -p "$(dirname "$FILE")"
    printf '%s\n' "$BODY" > "$FILE"
    printf '%s\n' "$BODY"
    ;;
  edit)
    FILE="$VDIR/$TARGET.json"
    [ -f "$FILE" ] || {{ echo "[ERROR] \"$TARGET\" isn't an item in the \"$VAULT\" vault" >&2; exit 1; }}
    BODY=$(cat); printf '%s\n' "$BODY" > "$FILE"; printf '%s\n' "$BODY"
    ;;
  get)
    FILE="$VDIR/$TARGET.json"
    [ -f "$FILE" ] || {{ echo "[ERROR] \"$TARGET\" isn't an item in the \"$VAULT\" vault" >&2; exit 1; }}
    cat "$FILE"
    ;;
  delete)
    FILE="$VDIR/$TARGET.json"
    [ -f "$FILE" ] || {{ echo "[ERROR] \"$TARGET\" isn't an item in the \"$VAULT\" vault" >&2; exit 1; }}
    rm -f "$FILE"
    ;;
  list)
    HDIR="$VDIR/hyphae"
    printf '['; FIRST=1
    if [ -d "$HDIR" ]; then
      for f in "$HDIR"/*.json; do
        [ -f "$f" ] || continue
        B=$(basename "$f" .json)
        [ "$FIRST" -eq 0 ] && printf ','
        FIRST=0
        printf '{{"id":"hyphae/%s","title":"hyphae/%s"}}' "$B" "$B"
      done
    fi
    printf ']\n'
    ;;
esac
"#,
        store = store.display(),
        log = log.display(),
        mode = mode.display(),
    );
    write_executable(&bin, &script);
    (bin, log, mode)
}

#[cfg(unix)]
fn make_lpass_shim(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let store = dir.join("lpass-store");
    let log = dir.join("lpass-argv.log");
    let mode = dir.join("lpass-mode.txt");
    let bin = dir.join("fake-lpass.sh");
    fs::create_dir_all(&store).unwrap();
    fs::write(&mode, "ok").unwrap();
    let script = format!(
        r#"#!/bin/sh
set -eu
STORE='{store}'
LOG='{log}'
MODE=$(cat '{mode}' 2>/dev/null || echo ok)
printf 'CALL(PIN=%s): %s\n' "${{LPASS_DISABLE_PINENTRY:-UNSET}}" "$*" >> "$LOG"
[ "${{LPASS_DISABLE_PINENTRY:-}}" = "1" ] || {{ echo 'missing LPASS_DISABLE_PINENTRY=1' >&2; exit 99; }}
SUB="${{1:-}}"; shift 1 || true
if [ "$MODE" = "locked" ]; then
  echo 'Error: Not logged in.' >&2
  exit 1
fi
[ "$SUB" = "status" ] && exit 0
ENTRY=""
for a in "$@"; do case "$a" in --*) ;; *) ENTRY="$a" ;; esac; done
case "$SUB" in
  edit)
    F="$STORE/$ENTRY.note"
    [ -f "$F" ] || {{ echo 'Error: Could not find specified account(s).' >&2; exit 1; }}
    cat > "$F"
    ;;
  add)
    F="$STORE/$ENTRY.note"
    mkdir -p "$(dirname "$F")"
    cat > "$F"
    ;;
  show)
    F="$STORE/$ENTRY.note"
    [ -f "$F" ] || {{ echo 'Error: Could not find specified account(s).' >&2; exit 1; }}
    cat "$F"
    ;;
  rm)
    F="$STORE/$ENTRY.note"
    [ -f "$F" ] || {{ echo 'Error: Could not find specified account(s).' >&2; exit 1; }}
    rm -f "$F"
    ;;
  ls)
    D="$STORE/$ENTRY"
    if [ -d "$D" ]; then
      for f in "$D"/*.note; do
        [ -f "$f" ] || continue
        printf '%s/%s [id: 42]\n' "$ENTRY" "$(basename "$f" .note)"
      done
    fi
    ;;
esac
"#,
        store = store.display(),
        log = log.display(),
        mode = mode.display(),
    );
    write_executable(&bin, &script);
    (bin, log, mode)
}

#[cfg(unix)]
fn make_pass_shim(dir: &Path) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let store = dir.join("password-store");
    let log = dir.join("pass-argv.log");
    let mode = dir.join("pass-mode.txt");
    let bin = dir.join("fake-pass.sh");
    fs::create_dir_all(&store).unwrap();
    fs::write(&mode, "ok").unwrap();
    let script = format!(
        r#"#!/bin/sh
set -eu
STORE="${{PASSWORD_STORE_DIR:-{store}}}"
LOG='{log}'
MODE=$(cat '{mode}' 2>/dev/null || echo ok)
printf 'CALL: %s\n' "$*" >> "$LOG"
if [ "$MODE" = "locked" ]; then
  echo 'gpg: decryption failed: No secret key' >&2
  exit 2
fi
SUB="${{1:-}}"; shift 1 || true
ENTRY=""
for a in "$@"; do case "$a" in -*) ;; *) ENTRY="$a" ;; esac; done
case "$SUB" in
  insert)
    F="$STORE/$ENTRY.gpg"
    mkdir -p "$(dirname "$F")"
    cat > "$F"
    ;;
  show)
    F="$STORE/$ENTRY.gpg"
    [ -f "$F" ] || {{ echo "Error: $ENTRY is not in the password store." >&2; exit 1; }}
    cat "$F"
    ;;
  rm)
    F="$STORE/$ENTRY.gpg"
    [ -f "$F" ] || {{ echo "Error: $ENTRY is not in the password store." >&2; exit 1; }}
    rm -f "$F"
    ;;
esac
"#,
        store = store.display(),
        log = log.display(),
        mode = mode.display(),
    );
    write_executable(&bin, &script);
    (bin, store, log, mode)
}

#[cfg(unix)]
#[test]
fn cli_secret_lifecycle_and_non_invasive_doctor_across_all_three_backends() {
    let tmp = TempDir::new().unwrap();
    let (op_bin, op_log, op_mode) = make_op_shim(tmp.path());
    let (lpass_bin, lpass_log, lpass_mode) = make_lpass_shim(tmp.path());
    let (pass_bin, pass_store, pass_log, pass_mode) = make_pass_shim(tmp.path());

    let cases: [(&str, &str, &Path, &str, &str, &Path, &Path); 3] = [
        (
            "1password",
            "HYPHAE_OP_BIN",
            &op_bin,
            "HYPHAE_1PASSWORD_VAULT",
            "HyphaeCI",
            &op_log,
            &op_mode,
        ),
        (
            "lastpass",
            "HYPHAE_LPASS_BIN",
            &lpass_bin,
            "HYPHAE_LASTPASS_PREFIX",
            "ci/hyphae",
            &lpass_log,
            &lpass_mode,
        ),
        (
            "pass",
            "HYPHAE_PASS_BIN",
            &pass_bin,
            "HYPHAE_PASS_PREFIX",
            "ci/hyphae",
            &pass_log,
            &pass_mode,
        ),
    ];

    for (backend, bin_env, bin_path, ns_env, ns_val, argv_log, mode_file) in cases {
        let home = tmp.path().join(format!("home-{backend}"));
        let state = tmp.path().join(format!("state-{backend}"));
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&state).unwrap();

        // 1. `hyp doctor --json` checks binary availability CLEANLY without invoking the CLI or touching secrets!
        let _ = fs::remove_file(argv_log);
        let mut doc_cmd = isolated_cmd(&home);
        doc_cmd
            .env("HYPHAE_SECRET_BACKEND", backend)
            .env(bin_env, bin_path)
            .env(ns_env, ns_val)
            .env("PASSWORD_STORE_DIR", &pass_store)
            .args([
                "doctor",
                "--state-dir",
                state.to_str().unwrap(),
                "--home",
                home.to_str().unwrap(),
                "--json",
            ]);
        let doc_out = doc_cmd.output().expect("run hyp doctor");
        assert_eq!(
            doc_out.status.code(),
            Some(0),
            "{backend} doctor failed: stdout={} stderr={}",
            String::from_utf8_lossy(&doc_out.stdout),
            String::from_utf8_lossy(&doc_out.stderr)
        );
        let doc_json = parse_json_stdout(&doc_out);
        assert_eq!(doc_json["ok"], true, "{backend} doctor json: {doc_json}");
        assert_eq!(doc_json["data"]["secretBackend"]["backend"], backend);
        assert_eq!(doc_json["data"]["secretBackend"]["available"], true);
        assert_eq!(doc_json["data"]["secretBackend"]["namespace"], ns_val);
        let check = doc_json["data"]["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "secrets.backend")
            .expect("secrets.backend check");
        assert_eq!(check["status"], "ok");
        assert!(
            !argv_log.exists(),
            "SECURITY/UX: `hyp doctor` must NEVER invoke {backend} CLI or touch secrets!"
        );

        // 2. `hyp secret set <name>` over stdin -> zero secrets in stdout/stderr or shim argv!
        let secret_val = format!("cli-secret-token-{backend}-multiline\nsecond-line-🚀");
        let mut set_cmd = isolated_cmd(&home);
        set_cmd
            .env("HYPHAE_SECRET_BACKEND", backend)
            .env(bin_env, bin_path)
            .env(ns_env, ns_val)
            .env("PASSWORD_STORE_DIR", &pass_store)
            .args([
                "secret",
                "set",
                "github-token",
                "--state-dir",
                state.to_str().unwrap(),
                "--json",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = set_cmd.spawn().expect("spawn hyp secret set");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(secret_val.as_bytes())
            .unwrap();
        let set_out = child.wait_with_output().unwrap();
        assert_eq!(
            set_out.status.code(),
            Some(0),
            "{backend} secret set failed: stdout={} stderr={}",
            String::from_utf8_lossy(&set_out.stdout),
            String::from_utf8_lossy(&set_out.stderr)
        );
        let set_stdout = String::from_utf8_lossy(&set_out.stdout);
        let set_stderr = String::from_utf8_lossy(&set_out.stderr);
        assert!(!set_stdout.contains(&secret_val));
        assert!(!set_stderr.contains(&secret_val));
        let set_json = parse_json_stdout(&set_out);
        assert_eq!(set_json["ok"], true);
        assert_eq!(set_json["data"]["backend"], backend);
        assert_eq!(set_json["data"]["name"], "github-token");

        // 3. `hyp secret list --json` -> returns metadata only, never values
        let list_out = isolated_cmd(&home)
            .env("HYPHAE_SECRET_BACKEND", backend)
            .env(bin_env, bin_path)
            .env(ns_env, ns_val)
            .env("PASSWORD_STORE_DIR", &pass_store)
            .args([
                "secret",
                "list",
                "--state-dir",
                state.to_str().unwrap(),
                "--json",
            ])
            .output()
            .expect("run hyp secret list");
        assert_eq!(list_out.status.code(), Some(0));
        let list_stdout = String::from_utf8_lossy(&list_out.stdout);
        assert!(!list_stdout.contains(&secret_val));
        let list_json = parse_json_stdout(&list_out);
        assert_eq!(list_json["data"]["backend"], backend);
        let items = list_json["data"]["secrets"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["name"], "github-token");
        assert_eq!(items[0]["backend"], backend);

        // 4. Locked vault -> `hyp secret set` fails closed with exit 1 and zero secret leak
        fs::write(mode_file, "locked").unwrap();
        let mut locked_child = isolated_cmd(&home)
            .env("HYPHAE_SECRET_BACKEND", backend)
            .env(bin_env, bin_path)
            .env(ns_env, ns_val)
            .env("PASSWORD_STORE_DIR", &pass_store)
            .args([
                "secret",
                "set",
                "locked-key",
                "--state-dir",
                state.to_str().unwrap(),
                "--json",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        locked_child
            .stdin
            .take()
            .unwrap()
            .write_all(b"LOCKED_SECRET_CANARY_424242")
            .unwrap();
        let locked_out = locked_child.wait_with_output().unwrap();
        assert_eq!(locked_out.status.code(), Some(1));
        let locked_stdout = String::from_utf8_lossy(&locked_out.stdout);
        let locked_stderr = String::from_utf8_lossy(&locked_out.stderr);
        assert!(!locked_stdout.contains("LOCKED_SECRET_CANARY_424242"));
        assert!(!locked_stderr.contains("LOCKED_SECRET_CANARY_424242"));
        fs::write(mode_file, "ok").unwrap();

        // 5. `hyp secret delete <name>` succeeds cleanly
        let del_out = isolated_cmd(&home)
            .env("HYPHAE_SECRET_BACKEND", backend)
            .env(bin_env, bin_path)
            .env(ns_env, ns_val)
            .env("PASSWORD_STORE_DIR", &pass_store)
            .args([
                "secret",
                "delete",
                "github-token",
                "--state-dir",
                state.to_str().unwrap(),
                "--json",
            ])
            .output()
            .expect("run hyp secret delete");
        assert_eq!(del_out.status.code(), Some(0));
        let del_json = parse_json_stdout(&del_out);
        assert_eq!(del_json["ok"], true);
        assert_eq!(del_json["data"]["deleted"], true);

        // 6. Verify shim argv log never contained any secret material
        let log_contents = fs::read_to_string(argv_log).unwrap_or_default();
        assert!(!log_contents.contains(&secret_val));
        assert!(!log_contents.contains("LOCKED_SECRET_CANARY_424242"));
        assert!(!log_contents.contains("hyphae-b64v1:"));
    }
}

#[test]
fn doctor_fails_closed_when_cli_binary_missing_or_prefix_invalid() {
    let tmp = TempDir::new().unwrap();
    let home = tmp.path().join("home");
    let state = tmp.path().join("state");
    fs::create_dir_all(&home).unwrap();
    fs::create_dir_all(&state).unwrap();

    for (backend, bin_env) in [
        ("1password", "HYPHAE_OP_BIN"),
        ("lastpass", "HYPHAE_LPASS_BIN"),
        ("pass", "HYPHAE_PASS_BIN"),
    ] {
        let out = isolated_cmd(&home)
            .env("HYPHAE_SECRET_BACKEND", backend)
            .env(bin_env, "/nonexistent/hyphae-missing-cli-bin")
            .args([
                "doctor",
                "--state-dir",
                state.to_str().unwrap(),
                "--home",
                home.to_str().unwrap(),
                "--json",
            ])
            .output()
            .expect("run doctor with missing binary");
        assert_eq!(
            out.status.code(),
            Some(1),
            "{backend} doctor must fail when binary missing"
        );
        let env = parse_json_stdout(&out);
        assert_eq!(env["ok"], false);
        assert_eq!(env["data"]["secretBackend"]["backend"], backend);
        assert_eq!(env["data"]["secretBackend"]["available"], false);
        let check = env["data"]["checks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == "secrets.backend")
            .expect("secrets.backend check");
        assert_eq!(check["status"], "fail");
    }

    // Path-traversal HYPHAE_PASS_PREFIX -> doctor fails closed!
    let trav = isolated_cmd(&home)
        .env("HYPHAE_SECRET_BACKEND", "pass")
        .env("HYPHAE_PASS_PREFIX", "../etc/passwd")
        .args([
            "doctor",
            "--state-dir",
            state.to_str().unwrap(),
            "--home",
            home.to_str().unwrap(),
            "--json",
        ])
        .output()
        .expect("run doctor with traversal prefix");
    assert_eq!(trav.status.code(), Some(1));
    let trav_env = parse_json_stdout(&trav);
    assert_eq!(trav_env["ok"], false);
    assert_eq!(trav_env["data"]["secretBackend"]["available"], false);
    let check = trav_env["data"]["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "secrets.backend")
        .expect("secrets.backend check");
    assert_eq!(check["status"], "fail");
}
