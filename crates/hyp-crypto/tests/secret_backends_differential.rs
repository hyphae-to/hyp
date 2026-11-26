//! McKeeman differential, zero-argv security, and fail-closed tests for
//! 1Password (`op`, Issue #26), LastPass (`lpass`, Issue #27), and Linux `pass` (Issue #28)
//! `SecretBackend` implementations.
//!
//! Strictly isolated (`tempfile::TempDir`, zero live vaults, zero live OS keyrings, zero global
//! env mutations — uses per-store builder overrides for parallel-safe execution).

use std::fs;
use std::path::{Path, PathBuf};

use hyp_crypto::CryptoError;
use hyp_crypto::keystore::{
    SecretBackend, SecretStore, classify_lastpass_show_output, classify_onepassword_get_output,
    classify_pass_show_output, detect_backend_with, encode_lossless_payload, parse_backend,
    parse_lastpass_ls_output, parse_onepassword_list_json, validate_lastpass_prefix,
    validate_onepassword_vault, validate_pass_prefix,
};
use tempfile::TempDir;

#[cfg(unix)]
fn write_executable_script(path: &Path, body: &str) {
    use std::os::unix::fs::PermissionsExt;
    fs::write(path, body).expect("write shim script");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod +x shim");
}

#[cfg(windows)]
fn write_windows_ps_shim(cmd_path: &Path, ps1_body: &str) {
    let ps1_path = cmd_path.with_extension("ps1");
    // Windows PowerShell parses a bare "-" as an invalid parameter to -File.
    // Pass the fixture's native arguments through numbered environment entries instead.
    let ps1_args = r#"$args = @(for ($i = 0; $i -lt [int]$env:HYP_TEST_FAKE_ARG_COUNT; $i++) {
  [Environment]::GetEnvironmentVariable("HYP_TEST_FAKE_ARG_$i")
})
"#;
    fs::write(&ps1_path, format!("{ps1_args}{ps1_body}")).expect("write ps1 shim");
    let cmd_body = format!(
        concat!(
            "@echo off\r\n",
            "setlocal DisableDelayedExpansion\r\n",
            "set HYP_TEST_FAKE_ARG_COUNT=0\r\n",
            ":collect\r\n",
            "if \"%~1\"==\"\" goto run\r\n",
            "set \"HYP_TEST_FAKE_ARG_%HYP_TEST_FAKE_ARG_COUNT%=%~1\"\r\n",
            "set /a HYP_TEST_FAKE_ARG_COUNT+=1 >nul\r\n",
            "shift /1\r\n",
            "goto collect\r\n",
            ":run\r\n",
            "powershell -NoProfile -ExecutionPolicy Bypass -File \"{}\"\r\n",
        ),
        ps1_path.display()
    );
    fs::write(cmd_path, cmd_body).expect("write cmd shim");
}

struct FakeCliEnv {
    _tmp: TempDir,
    store_root: PathBuf,
    argv_log: PathBuf,
    mode_file: PathBuf,
    bin_path: PathBuf,
}

impl FakeCliEnv {
    fn set_mode(&self, mode: &str) {
        fs::write(&self.mode_file, mode).expect("write fake cli mode");
    }

    fn read_argv_log(&self) -> String {
        fs::read_to_string(&self.argv_log).unwrap_or_default()
    }

    fn clear_argv_log(&self) {
        let _ = fs::write(&self.argv_log, "");
    }
}

/// Builds a faithful cross-platform fake 1Password (`op`) CLI inside an isolated `TempDir`.
fn build_fake_op_cli() -> FakeCliEnv {
    let tmp = TempDir::new().expect("tempdir");
    let store_root = tmp.path().join("op-vaults");
    let argv_log = tmp.path().join("op-argv.log");
    let mode_file = tmp.path().join("op-mode.txt");
    fs::create_dir_all(&store_root).unwrap();
    fs::write(&mode_file, "ok").unwrap();

    #[cfg(unix)]
    let bin_path = {
        let bin = tmp.path().join("fake-op.sh");
        let script = format!(
            r#"#!/bin/sh
set -eu
STORE='{store}'
LOG='{log}'
MODE_FILE='{mode}'

# Record every argv token on its own line for zero-argv security auditing.
printf 'CALL:' >> "$LOG"
for a in "$@"; do
  printf ' [%s]' "$a" >> "$LOG"
done
printf '\n' >> "$LOG"

MODE=$(cat "$MODE_FILE" 2>/dev/null || echo ok)
if [ "$MODE" = "locked" ]; then
  echo '[ERROR] 2026/11/26 You are not currently signed in. Please run "op signin"' >&2
  exit 1
fi
if [ "$MODE" = "bad_vault" ]; then
  echo '[ERROR] 2026/11/26 "MissingVault" isn'\''t a vault in this account' >&2
  exit 1
fi

CMD="${{1:-}}"
SUB="${{2:-}}"
if [ "$CMD" != "item" ]; then
  echo "[ERROR] unsupported op command: $CMD" >&2
  exit 2
fi
shift 2

if [ "$MODE" = "echo_err" ] && [ "$SUB" = "create" -o "$SUB" = "edit" ]; then
  BODY=$(cat || true)
  echo "[ERROR] failed writing payload: $BODY" >&2
  exit 1
fi

VAULT=""
TARGET=""
while [ $# -gt 0 ]; do
  case "$1" in
    --vault)
      VAULT="${{2:-}}"
      shift 2
      ;;
    --format)
      shift 2
      ;;
    --reveal)
      shift 1
      ;;
    -)
      shift 1
      ;;
    *)
      if [ -z "$TARGET" ]; then
        TARGET="$1"
      fi
      shift 1
      ;;
  esac
done

VAULT_DIR="$STORE/$(printf '%s' "$VAULT" | tr ' /' '__')"

case "$SUB" in
  create)
    BODY=$(cat)
    TITLE=$(printf '%s' "$BODY" | sed -n 's/.*"title":"\([^"]*\)".*/\1/p')
    if [ -z "$TITLE" ]; then
      echo '[ERROR] missing title in stdin JSON' >&2
      exit 1
    fi
    FILE="$VAULT_DIR/$TITLE.json"
    mkdir -p "$(dirname "$FILE")"
    printf '%s\n' "$BODY" > "$FILE"
    printf '%s\n' "$BODY"
    exit 0
    ;;
  edit)
    FILE="$VAULT_DIR/$TARGET.json"
    if [ ! -f "$FILE" ]; then
      echo "[ERROR] \"$TARGET\" isn't an item in the \"$VAULT\" vault" >&2
      exit 1
    fi
    BODY=$(cat)
    printf '%s\n' "$BODY" > "$FILE"
    printf '%s\n' "$BODY"
    exit 0
    ;;
  get)
    FILE="$VAULT_DIR/$TARGET.json"
    if [ ! -f "$FILE" ]; then
      echo "[ERROR] \"$TARGET\" isn't an item in the \"$VAULT\" vault" >&2
      exit 1
    fi
    cat "$FILE"
    exit 0
    ;;
  delete)
    FILE="$VAULT_DIR/$TARGET.json"
    if [ ! -f "$FILE" ]; then
      echo "[ERROR] \"$TARGET\" isn't an item in the \"$VAULT\" vault" >&2
      exit 1
    fi
    rm -f "$FILE"
    exit 0
    ;;
  list)
    HYP_DIR="$VAULT_DIR/hyphae"
    printf '['
    FIRST=1
    if [ -d "$HYP_DIR" ]; then
      for f in "$HYP_DIR"/*.json; do
        [ -f "$f" ] || continue
        BASE=$(basename "$f" .json)
        if [ "$FIRST" -eq 0 ]; then
          printf ','
        fi
        FIRST=0
        printf '{{"id":"hyphae/%s","title":"hyphae/%s"}}' "$BASE" "$BASE"
      done
    fi
    printf ']\n'
    exit 0
    ;;
  *)
    echo "[ERROR] unsupported op item subcommand: $SUB" >&2
    exit 2
    ;;
esac
"#,
            store = store_root.display(),
            log = argv_log.display(),
            mode = mode_file.display(),
        );
        write_executable_script(&bin, &script);
        bin
    };

    #[cfg(windows)]
    let bin_path = {
        let bin = tmp.path().join("fake-op.cmd");
        let ps1 = format!(
            r#"$store = '{store}'
$log = '{log}'
$modeFile = '{mode}'
Add-Content -Path $log -Value ("CALL: " + (($args | ForEach-Object {{ "[$_]" }}) -join " "))
$mode = (Get-Content -Raw $modeFile).Trim()
if ($mode -eq 'locked') {{ [Console]::Error.WriteLine('[ERROR] You are not currently signed in. Please run "op signin"'); exit 1 }}
if ($mode -eq 'bad_vault') {{ [Console]::Error.WriteLine('[ERROR] "MissingVault" isn''t a vault in this account'); exit 1 }}
$sub = $args[1]
if ($mode -eq 'echo_err' -and ($sub -eq 'create' -or $sub -eq 'edit')) {{ $body = [Console]::In.ReadToEnd(); [Console]::Error.WriteLine("[ERROR] failed writing payload: $body"); exit 1 }}
$vault = ''; $target = ''
for ($i = 2; $i -lt $args.Length; $i++) {{
  if ($args[$i] -eq '--vault') {{ $vault = $args[$i+1]; $i++ }}
  elseif ($args[$i] -eq '--format') {{ $i++ }}
  elseif ($args[$i] -eq '--reveal' -or $args[$i] -eq '-') {{ }}
  elseif (-not $target) {{ $target = $args[$i] }}
}}
$vdir = Join-Path $store ($vault -replace '[ /]', '_')
if ($sub -eq 'create') {{
  $body = [Console]::In.ReadToEnd()
  $obj = $body | ConvertFrom-Json
  $file = Join-Path $vdir ($obj.title + '.json')
  New-Item -ItemType Directory -Force -Path (Split-Path $file) | Out-Null
  Set-Content -NoNewline -Path $file -Value $body
  [Console]::Out.WriteLine($body); exit 0
}} elseif ($sub -eq 'edit') {{
  $file = Join-Path $vdir ($target + '.json')
  if (-not (Test-Path $file)) {{ [Console]::Error.WriteLine("[ERROR] ""$target"" isn't an item in the ""$vault"" vault"); exit 1 }}
  $body = [Console]::In.ReadToEnd()
  Set-Content -NoNewline -Path $file -Value $body
  [Console]::Out.WriteLine($body); exit 0
}} elseif ($sub -eq 'get') {{
  $file = Join-Path $vdir ($target + '.json')
  if (-not (Test-Path $file)) {{ [Console]::Error.WriteLine("[ERROR] ""$target"" isn't an item in the ""$vault"" vault"); exit 1 }}
  [Console]::Out.Write((Get-Content -Raw $file)); exit 0
}} elseif ($sub -eq 'delete') {{
  $file = Join-Path $vdir ($target + '.json')
  if (-not (Test-Path $file)) {{ [Console]::Error.WriteLine("[ERROR] ""$target"" isn't an item in the ""$vault"" vault"); exit 1 }}
  Remove-Item -Force $file; exit 0
}} elseif ($sub -eq 'list') {{
  $hdir = Join-Path $vdir 'hyphae'
  $items = @()
  if (Test-Path $hdir) {{
    Get-ChildItem -Path $hdir -Filter '*.json' | ForEach-Object {{
      $b = $_.BaseName
      $items += @{{ id = "hyphae/$b"; title = "hyphae/$b" }}
    }}
  }}
  [Console]::Out.WriteLine((ConvertTo-Json -Compress -InputObject $items)); exit 0
}}
exit 2
"#,
            store = store_root.display(),
            log = argv_log.display(),
            mode = mode_file.display(),
        );
        write_windows_ps_shim(&bin, &ps1);
        bin
    };

    FakeCliEnv {
        _tmp: tmp,
        store_root,
        argv_log,
        mode_file,
        bin_path,
    }
}

/// Builds a faithful cross-platform fake LastPass (`lpass`) CLI inside an isolated `TempDir`.
fn build_fake_lpass_cli() -> FakeCliEnv {
    let tmp = TempDir::new().expect("tempdir");
    let store_root = tmp.path().join("lpass-vault");
    let argv_log = tmp.path().join("lpass-argv.log");
    let mode_file = tmp.path().join("lpass-mode.txt");
    fs::create_dir_all(&store_root).unwrap();
    fs::write(&mode_file, "ok").unwrap();

    #[cfg(unix)]
    let bin_path = {
        let bin = tmp.path().join("fake-lpass.sh");
        let script = format!(
            r#"#!/bin/sh
set -eu
STORE='{store}'
LOG='{log}'
MODE_FILE='{mode}'

printf 'CALL(PINENTRY=%s):' "${{LPASS_DISABLE_PINENTRY:-UNSET}}" >> "$LOG"
for a in "$@"; do
  printf ' [%s]' "$a" >> "$LOG"
done
printf '\n' >> "$LOG"

# Security invariant: Hyphae MUST always pass LPASS_DISABLE_PINENTRY=1!
if [ "${{LPASS_DISABLE_PINENTRY:-}}" != "1" ]; then
  echo 'Error: LPASS_DISABLE_PINENTRY must be 1' >&2
  exit 99
fi

MODE=$(cat "$MODE_FILE" 2>/dev/null || echo ok)
SUB="${{1:-}}"
shift 1 || true

if [ "$SUB" = "status" ]; then
  if [ "$MODE" = "locked" ]; then
    echo 'Not logged in.' >&2
    exit 1
  fi
  exit 0
fi

if [ "$MODE" = "locked" ]; then
  echo 'Error: Not logged in.' >&2
  exit 1
fi
if [ "$MODE" = "echo_err" ]; then
  BODY=$(cat || true)
  echo "Error: cannot save note: $BODY" >&2
  exit 1
fi

case "$SUB" in
  edit)
    ENTRY=""
    for a in "$@"; do
      case "$a" in
        --*) ;;
        *) ENTRY="$a" ;;
      esac
    done
    FILE="$STORE/$ENTRY.note"
    if [ ! -f "$FILE" ]; then
      echo 'Error: Could not find specified account(s).' >&2
      exit 1
    fi
    cat > "$FILE"
    exit 0
    ;;
  add)
    ENTRY=""
    for a in "$@"; do
      case "$a" in
        --*) ;;
        *) ENTRY="$a" ;;
      esac
    done
    FILE="$STORE/$ENTRY.note"
    mkdir -p "$(dirname "$FILE")"
    cat > "$FILE"
    exit 0
    ;;
  show)
    ENTRY=""
    for a in "$@"; do
      case "$a" in
        --*) ;;
        *) ENTRY="$a" ;;
      esac
    done
    FILE="$STORE/$ENTRY.note"
    if [ ! -f "$FILE" ]; then
      echo 'Error: Could not find specified account(s).' >&2
      exit 1
    fi
    cat "$FILE"
    exit 0
    ;;
  rm)
    ENTRY="${{1:-}}"
    FILE="$STORE/$ENTRY.note"
    if [ ! -f "$FILE" ]; then
      echo 'Error: Could not find specified account(s).' >&2
      exit 1
    fi
    rm -f "$FILE"
    exit 0
    ;;
  ls)
    PREFIX="${{1:-}}"
    DIR="$STORE/$PREFIX"
    if [ ! -d "$DIR" ]; then
      exit 0
    fi
    for f in "$DIR"/*.note; do
      [ -f "$f" ] || continue
      BASE=$(basename "$f" .note)
      printf '%s/%s [id: 1001]\n' "$PREFIX" "$BASE"
    done
    exit 0
    ;;
  *)
    echo "Error: unsupported lpass subcommand: $SUB" >&2
    exit 2
    ;;
esac
"#,
            store = store_root.display(),
            log = argv_log.display(),
            mode = mode_file.display(),
        );
        write_executable_script(&bin, &script);
        bin
    };

    #[cfg(windows)]
    let bin_path = {
        let bin = tmp.path().join("fake-lpass.cmd");
        let ps1 = format!(
            r#"$store = '{store}'
$log = '{log}'
$modeFile = '{mode}'
Add-Content -Path $log -Value ("CALL(PINENTRY=$($env:LPASS_DISABLE_PINENTRY)): " + (($args | ForEach-Object {{ "[$_]" }}) -join " "))
if ($env:LPASS_DISABLE_PINENTRY -ne '1') {{ [Console]::Error.WriteLine('Error: LPASS_DISABLE_PINENTRY must be 1'); exit 99 }}
$mode = (Get-Content -Raw $modeFile).Trim()
$sub = $args[0]
if ($sub -eq 'status') {{
  if ($mode -eq 'locked') {{ [Console]::Error.WriteLine('Not logged in.'); exit 1 }}
  exit 0
}}
if ($mode -eq 'locked') {{ [Console]::Error.WriteLine('Error: Not logged in.'); exit 1 }}
if ($mode -eq 'echo_err') {{ $b = [Console]::In.ReadToEnd(); [Console]::Error.WriteLine("Error: cannot save note: $b"); exit 1 }}
$entry = ($args[1..($args.Length-1)] | Where-Object {{ -not $_.StartsWith('--') }} | Select-Object -Last 1)
if ($sub -eq 'edit') {{
  $f = Join-Path $store ($entry + '.note')
  if (-not (Test-Path $f)) {{ [Console]::Error.WriteLine('Error: Could not find specified account(s).'); exit 1 }}
  Set-Content -NoNewline -Path $f -Value ([Console]::In.ReadToEnd()); exit 0
}} elseif ($sub -eq 'add') {{
  $f = Join-Path $store ($entry + '.note')
  New-Item -ItemType Directory -Force -Path (Split-Path $f) | Out-Null
  Set-Content -NoNewline -Path $f -Value ([Console]::In.ReadToEnd()); exit 0
}} elseif ($sub -eq 'show') {{
  $f = Join-Path $store ($entry + '.note')
  if (-not (Test-Path $f)) {{ [Console]::Error.WriteLine('Error: Could not find specified account(s).'); exit 1 }}
  [Console]::Out.Write((Get-Content -Raw $f)); exit 0
}} elseif ($sub -eq 'rm') {{
  $f = Join-Path $store ($entry + '.note')
  if (-not (Test-Path $f)) {{ [Console]::Error.WriteLine('Error: Could not find specified account(s).'); exit 1 }}
  Remove-Item -Force $f; exit 0
}} elseif ($sub -eq 'ls') {{
  $d = Join-Path $store $entry
  if (Test-Path $d) {{
    Get-ChildItem -Path $d -Filter '*.note' | ForEach-Object {{
      [Console]::Out.WriteLine("$entry/$($_.BaseName) [id: 1001]")
    }}
  }}
  exit 0
}}
exit 2
"#,
            store = store_root.display(),
            log = argv_log.display(),
            mode = mode_file.display(),
        );
        write_windows_ps_shim(&bin, &ps1);
        bin
    };

    FakeCliEnv {
        _tmp: tmp,
        store_root,
        argv_log,
        mode_file,
        bin_path,
    }
}

/// Builds a faithful cross-platform fake Linux `pass` CLI inside an isolated `TempDir`.
fn build_fake_pass_cli() -> FakeCliEnv {
    let tmp = TempDir::new().expect("tempdir");
    let store_root = tmp.path().join("password-store");
    let argv_log = tmp.path().join("pass-argv.log");
    let mode_file = tmp.path().join("pass-mode.txt");
    fs::create_dir_all(&store_root).unwrap();
    fs::write(&mode_file, "ok").unwrap();

    #[cfg(unix)]
    let bin_path = {
        let bin = tmp.path().join("fake-pass.sh");
        let script = format!(
            r#"#!/bin/sh
set -eu
LOG='{log}'
MODE_FILE='{mode}'
STORE="${{PASSWORD_STORE_DIR:-{default_store}}}"

printf 'CALL(GPG_OPTS=%s|GPG_TTY=%s|PINENTRY=%s|GNUPGHOME=%s):' \
  "${{PASSWORD_STORE_GPG_OPTS:-UNSET}}" \
  "${{GPG_TTY:-UNSET}}" \
  "${{PINENTRY_USER_DATA:-UNSET}}" \
  "${{GNUPGHOME:-UNSET}}" >> "$LOG"
for a in "$@"; do
  printf ' [%s]' "$a" >> "$LOG"
done
printf '\n' >> "$LOG"

# Verify non-interactive GPG safety flags are always set!
case " ${{PASSWORD_STORE_GPG_OPTS:-}} " in
  *" --batch "*) ;;
  *) echo 'gpg: missing --batch in PASSWORD_STORE_GPG_OPTS' >&2; exit 98 ;;
esac
case " ${{PASSWORD_STORE_GPG_OPTS:-}} " in
  *" --no-tty "*) ;;
  *) echo 'gpg: missing --no-tty in PASSWORD_STORE_GPG_OPTS' >&2; exit 97 ;;
esac

MODE=$(cat "$MODE_FILE" 2>/dev/null || echo ok)
if [ "$MODE" = "locked" ]; then
  echo 'gpg: decryption failed: No secret key' >&2
  exit 2
fi
if [ "$MODE" = "uninitialized" ]; then
  echo 'Error: password store is empty. Try "pass init".' >&2
  exit 1
fi
if [ "$MODE" = "echo_err" ]; then
  BODY=$(cat || true)
  echo "gpg: failed encrypting secret: $BODY" >&2
  exit 2
fi

SUB="${{1:-}}"
shift 1 || true

case "$SUB" in
  insert)
    ENTRY=""
    for a in "$@"; do
      case "$a" in
        -*) ;;
        *) ENTRY="$a" ;;
      esac
    done
    FILE="$STORE/$ENTRY.gpg"
    mkdir -p "$(dirname "$FILE")"
    cat > "$FILE"
    exit 0
    ;;
  show)
    ENTRY="${{1:-}}"
    FILE="$STORE/$ENTRY.gpg"
    if [ ! -f "$FILE" ]; then
      echo "Error: $ENTRY is not in the password store." >&2
      exit 1
    fi
    cat "$FILE"
    exit 0
    ;;
  rm)
    ENTRY=""
    for a in "$@"; do
      case "$a" in
        -*) ;;
        *) ENTRY="$a" ;;
      esac
    done
    FILE="$STORE/$ENTRY.gpg"
    if [ ! -f "$FILE" ]; then
      echo "Error: $ENTRY is not in the password store." >&2
      exit 1
    fi
    rm -f "$FILE"
    exit 0
    ;;
  *)
    echo "Error: unsupported pass subcommand: $SUB" >&2
    exit 2
    ;;
esac
"#,
            log = argv_log.display(),
            mode = mode_file.display(),
            default_store = store_root.display(),
        );
        write_executable_script(&bin, &script);
        bin
    };

    #[cfg(windows)]
    let bin_path = {
        let bin = tmp.path().join("fake-pass.cmd");
        let ps1 = format!(
            r#"$log = '{log}'
$modeFile = '{mode}'
$store = if ($env:PASSWORD_STORE_DIR) {{ $env:PASSWORD_STORE_DIR }} else {{ '{default_store}' }}
Add-Content -Path $log -Value ("CALL(GPG_OPTS=$($env:PASSWORD_STORE_GPG_OPTS)|GPG_TTY=$($env:GPG_TTY)|PINENTRY=$($env:PINENTRY_USER_DATA)|GNUPGHOME=$($env:GNUPGHOME)): " + (($args | ForEach-Object {{ "[$_]" }}) -join " "))
if ($env:PASSWORD_STORE_GPG_OPTS -notmatch '--batch' -or $env:PASSWORD_STORE_GPG_OPTS -notmatch '--no-tty') {{
  [Console]::Error.WriteLine('gpg: missing --batch/--no-tty'); exit 98
}}
$mode = (Get-Content -Raw $modeFile).Trim()
if ($mode -eq 'locked') {{ [Console]::Error.WriteLine('gpg: decryption failed: No secret key'); exit 2 }}
if ($mode -eq 'uninitialized') {{ [Console]::Error.WriteLine('Error: password store is empty. Try "pass init".'); exit 1 }}
if ($mode -eq 'echo_err') {{ $b = [Console]::In.ReadToEnd(); [Console]::Error.WriteLine("gpg: failed encrypting secret: $b"); exit 2 }}
$sub = $args[0]
$entry = ($args[1..($args.Length-1)] | Where-Object {{ -not $_.StartsWith('-') }} | Select-Object -Last 1)
if ($sub -eq 'insert') {{
  $f = Join-Path $store ($entry + '.gpg')
  New-Item -ItemType Directory -Force -Path (Split-Path $f) | Out-Null
  Set-Content -NoNewline -Path $f -Value ([Console]::In.ReadToEnd()); exit 0
}} elseif ($sub -eq 'show') {{
  $f = Join-Path $store ($entry + '.gpg')
  if (-not (Test-Path $f)) {{ [Console]::Error.WriteLine("Error: $entry is not in the password store."); exit 1 }}
  [Console]::Out.Write((Get-Content -Raw $f)); exit 0
}} elseif ($sub -eq 'rm') {{
  $f = Join-Path $store ($entry + '.gpg')
  if (-not (Test-Path $f)) {{ [Console]::Error.WriteLine("Error: $entry is not in the password store."); exit 1 }}
  Remove-Item -Force $f; exit 0
}}
exit 2
"#,
            log = argv_log.display(),
            mode = mode_file.display(),
            default_store = store_root.display(),
        );
        write_windows_ps_shim(&bin, &ps1);
        bin
    };

    FakeCliEnv {
        _tmp: tmp,
        store_root,
        argv_log,
        mode_file,
        bin_path,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum ErrKind {
    InvalidName,
    NotFound,
    Keystore,
    Other,
}

fn classify_err(e: &CryptoError) -> ErrKind {
    match e {
        CryptoError::InvalidSecretName(_) => ErrKind::InvalidName,
        CryptoError::SecretNotFound(_) => ErrKind::NotFound,
        CryptoError::Keystore(_) => ErrKind::Keystore,
        _ => ErrKind::Other,
    }
}

fn sorted_names(store: &SecretStore) -> Vec<String> {
    let list = store.list().expect("list secrets");
    for item in &list {
        assert_eq!(item.backend, store.backend());
        assert!(item.mode_ok, "mode_ok should be true for {}", item.name);
    }
    list.into_iter().map(|m| m.name).collect()
}

/// Runs the exact same stateful differential workload against `File` (reference oracle) AND
/// `OnePassword`, `LastPass`, and `Pass`, asserting bit-exact identical bytes, metadata, and error kinds,
/// plus a complete zero-argv audit across every single CLI invocation.
#[test]
fn differential_oracle_and_zero_argv_audit_for_1password_lastpass_and_pass() {
    let file_dir = TempDir::new().unwrap();
    let op_dir = TempDir::new().unwrap();
    let lpass_dir = TempDir::new().unwrap();
    let pass_dir = TempDir::new().unwrap();
    let gnupg_dir = TempDir::new().unwrap();

    let fake_op = build_fake_op_cli();
    let fake_lpass = build_fake_lpass_cli();
    let fake_pass = build_fake_pass_cli();

    let oracle = SecretStore::file_only(file_dir.path());
    let op_store = SecretStore::new(op_dir.path(), SecretBackend::OnePassword)
        .with_op_bin(&fake_op.bin_path)
        .with_op_vault("Hyphae Team");
    let lpass_store = SecretStore::new(lpass_dir.path(), SecretBackend::LastPass)
        .with_lpass_bin(&fake_lpass.bin_path)
        .with_lpass_prefix("team/hyphae");
    let pass_store = SecretStore::new(pass_dir.path(), SecretBackend::Pass)
        .with_pass_bin(&fake_pass.bin_path)
        .with_pass_prefix("team/hyphae")
        .with_password_store_dir(&fake_pass.store_root)
        .with_gnupg_home(gnupg_dir.path());

    let subjects: [(&str, &SecretStore); 3] = [
        ("1password", &op_store),
        ("lastpass", &lpass_store),
        ("pass", &pass_store),
    ];

    // 1. Empty initial state parity
    let oracle_empty = sorted_names(&oracle);
    assert!(oracle_empty.is_empty());
    let oracle_missing_get = classify_err(&oracle.get("missing-key").unwrap_err());
    assert_eq!(oracle_missing_get, ErrKind::NotFound);
    let oracle_missing_del = oracle.delete("missing-key").unwrap();
    assert!(!oracle_missing_del);

    for (label, store) in subjects {
        assert_eq!(sorted_names(store), oracle_empty, "{label} initial list");
        assert_eq!(
            classify_err(&store.get("missing-key").unwrap_err()),
            oracle_missing_get,
            "{label} missing get"
        );
        assert_eq!(
            store.delete("missing-key").unwrap(),
            oracle_missing_del,
            "{label} missing delete"
        );
    }

    // 2. Diverse payloads: plain ASCII, multiline PEM/JSON, unicode/quotes/shell metachars,
    //    literal `hyphae-b64v1:` prefix, outer whitespace, binary-safe control chars & NUL.
    let payloads: [(&str, &str); 6] = [
        ("api-token", "ghp_InitialSecretToken_ABC123456"),
        (
            "multiline-pem",
            "-----BEGIN PRIVATE KEY-----\nline-2-payload\r\n{\"json\":\"val\"}\n-----END PRIVATE KEY-----",
        ),
        (
            "special-chars",
            "tok-'single'-\"double\"-$HOME-`uname`-\\slash-\t-🚀-日本語",
        ),
        ("b64-literal", "hyphae-b64v1:not-actually-encoded-verbatim"),
        ("padded-val", "  \n  trimmed-secret-body \t\r\n  "),
        ("binary-safe", "bin-\x01\x02\x00\x07-end-marker"),
    ];

    let mut all_sensitive_values: Vec<String> = Vec::new();
    for (name, val) in payloads {
        let trimmed = val.trim();
        all_sensitive_values.push(trimmed.to_string());
        let encoded = encode_lossless_payload(trimmed);
        all_sensitive_values.push((*encoded).clone());
        all_sensitive_values.push(encoded.trim_start_matches("hyphae-b64v1:").to_string());

        let o_saved = oracle.set(name, val).expect("oracle set");
        assert_eq!(o_saved.name, name);
        let o_got = oracle.get(name).expect("oracle get");
        assert_eq!(&*o_got, trimmed);

        for (label, store) in subjects {
            let s_saved = store
                .set(name, val)
                .unwrap_or_else(|e| panic!("{label} set '{name}' failed: {e}"));
            assert_eq!(s_saved.name, name, "{label} saved name");
            assert_eq!(s_saved.backend, store.backend(), "{label} saved backend");
            assert!(
                !s_saved.location.contains(trimmed),
                "{label} location must never contain secret value"
            );
            let s_got = store
                .get(name)
                .unwrap_or_else(|e| panic!("{label} get '{name}' failed: {e}"));
            assert_eq!(
                s_got.as_bytes(),
                o_got.as_bytes(),
                "{label} bit-exact parity mismatch for '{name}'"
            );
        }
    }

    // 3. Overwrite parity (must update in place with zero duplicate entries in list!)
    let rotated = "ghp_RotatedSecretValue_XYZ987654\nsecond-line";
    all_sensitive_values.push(rotated.to_string());
    let rotated_enc = encode_lossless_payload(rotated);
    all_sensitive_values.push((*rotated_enc).clone());
    all_sensitive_values.push(rotated_enc.trim_start_matches("hyphae-b64v1:").to_string());

    oracle.set("api-token", rotated).unwrap();
    let o_rot = oracle.get("api-token").unwrap();
    let o_list = sorted_names(&oracle);

    for (label, store) in subjects {
        store
            .set("api-token", rotated)
            .unwrap_or_else(|e| panic!("{label} overwrite failed: {e}"));
        let s_rot = store.get("api-token").unwrap();
        assert_eq!(s_rot.as_bytes(), o_rot.as_bytes(), "{label} rotated value");
        assert_eq!(sorted_names(store), o_list, "{label} list after overwrite");
    }

    // 4. Error parity: invalid secret names & empty values
    for bad_name in ["", "../escape", "UPPER", "foo/bar", "a..b", ".hidden"] {
        let o_err = classify_err(&oracle.set(bad_name, "val").unwrap_err());
        assert_eq!(o_err, ErrKind::InvalidName);
        for (label, store) in subjects {
            assert_eq!(
                classify_err(&store.set(bad_name, "val").unwrap_err()),
                o_err,
                "{label} invalid set '{bad_name}'"
            );
            assert_eq!(
                classify_err(&store.get(bad_name).unwrap_err()),
                o_err,
                "{label} invalid get '{bad_name}'"
            );
            assert_eq!(
                classify_err(&store.delete(bad_name).unwrap_err()),
                o_err,
                "{label} invalid delete '{bad_name}'"
            );
        }
    }
    let o_empty_err = classify_err(&oracle.set("empty-val", "   \n\t  ").unwrap_err());
    assert_eq!(o_empty_err, ErrKind::Keystore);
    for (label, store) in subjects {
        assert_eq!(
            classify_err(&store.set("empty-val", "   \n\t  ").unwrap_err()),
            o_empty_err,
            "{label} empty value"
        );
    }

    // 5. Persistent Ed25519 + X25519 node identity key lifecycle parity
    let o_k1 = oracle.load_or_create_node_keys("alice@macbook").unwrap();
    let o_k2 = oracle.load_or_create_node_keys("alice@macbook").unwrap();
    assert_eq!(o_k1.kid(), o_k2.kid());
    for (label, store) in subjects {
        let k1 = store
            .load_or_create_node_keys("alice@macbook")
            .unwrap_or_else(|e| panic!("{label} load_or_create_node_keys failed: {e}"));
        let k2 = store
            .load_or_create_node_keys("alice@macbook")
            .unwrap_or_else(|e| panic!("{label} reload node_keys failed: {e}"));
        assert_eq!(k1.kid(), k2.kid(), "{label} node key kid stability");
        assert_eq!(
            k1.fingerprint(),
            k2.fingerprint(),
            "{label} node key fingerprint stability"
        );
    }

    // 6. Delete parity
    assert!(oracle.delete("api-token").unwrap());
    assert!(!oracle.delete("api-token").unwrap());
    assert_eq!(
        classify_err(&oracle.get("api-token").unwrap_err()),
        ErrKind::NotFound
    );
    let o_after_del = sorted_names(&oracle);

    for (label, store) in subjects {
        assert!(store.delete("api-token").unwrap(), "{label} first delete");
        assert!(!store.delete("api-token").unwrap(), "{label} second delete");
        assert_eq!(
            classify_err(&store.get("api-token").unwrap_err()),
            ErrKind::NotFound,
            "{label} get after delete"
        );
        assert_eq!(
            sorted_names(store),
            o_after_del,
            "{label} list after delete"
        );
    }

    // 7. ZERO-ARGV SECURITY AUDIT: verify NO secret value (raw OR base64) ever appeared in argv!
    let logs = [
        ("1password", fake_op.read_argv_log()),
        ("lastpass", fake_lpass.read_argv_log()),
        ("pass", fake_pass.read_argv_log()),
    ];
    for (label, log) in &logs {
        assert!(
            !log.trim().is_empty(),
            "{label} argv log must have recorded subprocess calls"
        );
        for secret in &all_sensitive_values {
            assert!(
                !log.contains(secret.as_str()),
                "SECURITY VIOLATION: {label} CLI argv leaked secret fragment {secret:?}!\nLog:\n{log}"
            );
        }
    }

    // Verify backend-specific security environment flags were enforced on every call.
    let lpass_log = fake_lpass.read_argv_log();
    assert!(
        lpass_log
            .lines()
            .all(|l| l.starts_with("CALL(PINENTRY=1):")),
        "every lpass invocation must set LPASS_DISABLE_PINENTRY=1:\n{lpass_log}"
    );
    let pass_log = fake_pass.read_argv_log();
    assert!(
        pass_log.lines().all(|l| l.contains("--batch")
            && l.contains("--no-tty")
            && l.contains("GPG_TTY=UNSET")),
        "every pass invocation must enforce --batch --no-tty and unset GPG_TTY:\n{pass_log}"
    );
    assert!(
        pass_log.contains(&gnupg_dir.path().display().to_string()),
        "pass invocations must forward GNUPGHOME:\n{pass_log}"
    );
}

#[test]
fn metadata_only_list_discovers_external_entries_without_reading_values() {
    let op_dir = TempDir::new().unwrap();
    let lpass_dir = TempDir::new().unwrap();
    let pass_dir = TempDir::new().unwrap();

    let fake_op = build_fake_op_cli();
    let fake_lpass = build_fake_lpass_cli();
    let fake_pass = build_fake_pass_cli();

    // Seed secrets directly in the external stores (bypassing local index.json).
    let op_ext = fake_op
        .store_root
        .join("Hyphae")
        .join("hyphae")
        .join("synced-op-key.json");
    fs::create_dir_all(op_ext.parent().unwrap()).unwrap();
    fs::write(
        &op_ext,
        r#"{"id":"hyphae/synced-op-key","title":"hyphae/synced-op-key","fields":[{"id":"notesPlain","value":"NEVER_READ_ON_LIST"}]}"#,
    )
    .unwrap();

    let lpass_ext = fake_lpass
        .store_root
        .join("hyphae")
        .join("synced-lpass-key.note");
    fs::create_dir_all(lpass_ext.parent().unwrap()).unwrap();
    fs::write(&lpass_ext, "NEVER_READ_ON_LIST\n").unwrap();

    let pass_ext = fake_pass
        .store_root
        .join("hyphae")
        .join("synced-pass-key.gpg");
    fs::create_dir_all(pass_ext.parent().unwrap()).unwrap();
    fs::write(&pass_ext, "ENCRYPTED_CIPHERTEXT_NEVER_DECRYPTED\n").unwrap();

    let op_store = SecretStore::new(op_dir.path(), SecretBackend::OnePassword)
        .with_op_bin(&fake_op.bin_path)
        .with_op_vault("Hyphae");
    let lpass_store = SecretStore::new(lpass_dir.path(), SecretBackend::LastPass)
        .with_lpass_bin(&fake_lpass.bin_path)
        .with_lpass_prefix("hyphae");
    let pass_store = SecretStore::new(pass_dir.path(), SecretBackend::Pass)
        .with_pass_bin(&fake_pass.bin_path)
        .with_pass_prefix("hyphae")
        .with_password_store_dir(&fake_pass.store_root);

    let op_list = op_store.list().unwrap();
    assert_eq!(op_list.len(), 1);
    assert_eq!(op_list[0].name, "synced-op-key");
    assert_eq!(op_list[0].location, "1password:Hyphae/hyphae/synced-op-key");
    assert!(
        !fake_op.read_argv_log().contains("[get]"),
        "1password list must NEVER call `op item get`"
    );

    let lpass_list = lpass_store.list().unwrap();
    assert_eq!(lpass_list.len(), 1);
    assert_eq!(lpass_list[0].name, "synced-lpass-key");
    assert_eq!(lpass_list[0].location, "lastpass:hyphae/synced-lpass-key");
    assert!(
        !fake_lpass.read_argv_log().contains("[show]"),
        "lastpass list must NEVER call `lpass show`"
    );

    let pass_list = pass_store.list().unwrap();
    assert_eq!(pass_list.len(), 1);
    assert_eq!(pass_list[0].name, "synced-pass-key");
    assert_eq!(pass_list[0].location, "pass:hyphae/synced-pass-key");
    assert!(
        fake_pass.read_argv_log().trim().is_empty(),
        "pass list must scan .gpg metadata on disk without invoking `pass` or GPG"
    );
}

#[test]
fn mutated_and_fail_closed_security_tests() {
    let op_dir = TempDir::new().unwrap();
    let lpass_dir = TempDir::new().unwrap();
    let pass_dir = TempDir::new().unwrap();

    let fake_op = build_fake_op_cli();
    let fake_lpass = build_fake_lpass_cli();
    let fake_pass = build_fake_pass_cli();

    let op_store = SecretStore::new(op_dir.path(), SecretBackend::OnePassword)
        .with_op_bin(&fake_op.bin_path)
        .with_op_vault("Hyphae");
    let lpass_store = SecretStore::new(lpass_dir.path(), SecretBackend::LastPass)
        .with_lpass_bin(&fake_lpass.bin_path)
        .with_lpass_prefix("hyphae");
    let pass_store = SecretStore::new(pass_dir.path(), SecretBackend::Pass)
        .with_pass_bin(&fake_pass.bin_path)
        .with_pass_prefix("hyphae")
        .with_password_store_dir(&fake_pass.store_root);

    // Pre-populate a valid secret in each store first.
    op_store.set("persisted", "top-secret-op-val").unwrap();
    lpass_store
        .set("persisted", "top-secret-lpass-val")
        .unwrap();
    pass_store.set("persisted", "top-secret-pass-val").unwrap();

    // 1. Locked vault -> MUST fail closed with Keystore error (never SecretNotFound) & never drop index entry on delete!
    fake_op.set_mode("locked");
    fake_lpass.set_mode("locked");
    fake_pass.set_mode("locked");

    let op_err = op_store.get("persisted").unwrap_err();
    assert!(matches!(op_err, CryptoError::Keystore(_)), "{op_err}");
    assert!(
        op_err.to_string().contains("op signin")
            && op_err.to_string().contains("OP_SERVICE_ACCOUNT_TOKEN"),
        "expected actionable 1password error: {op_err}"
    );
    assert!(matches!(
        op_store.set("new-key", "super-secret-value-1password"),
        Err(CryptoError::Keystore(_))
    ));
    assert!(matches!(
        op_store.delete("persisted"),
        Err(CryptoError::Keystore(_))
    ));
    assert!(matches!(op_store.list(), Err(CryptoError::Keystore(_))));
    assert!(matches!(
        op_store.load_or_create_node_keys("alice@locked"),
        Err(CryptoError::Keystore(_))
    ));

    let lpass_err = lpass_store.get("persisted").unwrap_err();
    assert!(matches!(lpass_err, CryptoError::Keystore(_)), "{lpass_err}");
    assert!(
        lpass_err.to_string().contains("lpass login"),
        "expected actionable lastpass error: {lpass_err}"
    );
    assert!(matches!(
        lpass_store.set("new-key", "super-secret-value-lastpass"),
        Err(CryptoError::Keystore(_))
    ));
    assert!(matches!(
        lpass_store.delete("persisted"),
        Err(CryptoError::Keystore(_))
    ));
    assert!(matches!(lpass_store.list(), Err(CryptoError::Keystore(_))));
    assert!(matches!(
        lpass_store.load_or_create_node_keys("alice@locked"),
        Err(CryptoError::Keystore(_))
    ));

    let pass_err = pass_store.get("persisted").unwrap_err();
    assert!(matches!(pass_err, CryptoError::Keystore(_)), "{pass_err}");
    assert!(
        pass_err.to_string().contains("gpg-agent"),
        "expected actionable pass error: {pass_err}"
    );
    assert!(matches!(
        pass_store.set("new-key", "super-secret-value-pass"),
        Err(CryptoError::Keystore(_))
    ));
    assert!(matches!(
        pass_store.delete("persisted"),
        Err(CryptoError::Keystore(_))
    ));
    assert!(matches!(
        pass_store.load_or_create_node_keys("alice@locked"),
        Err(CryptoError::Keystore(_))
    ));

    // Unlock again -> verify failed delete left the secret and index completely intact!
    fake_op.set_mode("ok");
    fake_lpass.set_mode("ok");
    fake_pass.set_mode("ok");
    assert_eq!(&*op_store.get("persisted").unwrap(), "top-secret-op-val");
    assert_eq!(
        &*lpass_store.get("persisted").unwrap(),
        "top-secret-lpass-val"
    );
    assert_eq!(
        &*pass_store.get("persisted").unwrap(),
        "top-secret-pass-val"
    );

    // 2. Adversarial stderr secret-echo redaction: even if a buggy CLI echoes stdin on stderr,
    //    returned CryptoError must NEVER leak raw or base64-encoded secret!
    fake_op.set_mode("echo_err");
    fake_lpass.set_mode("echo_err");
    fake_pass.set_mode("echo_err");
    let canary = "CANARY_ULTRA_SECRET_TOKEN_987654321";
    let canary_b64 = encode_lossless_payload(canary);
    for (label, store) in [
        ("1password", &op_store),
        ("lastpass", &lpass_store),
        ("pass", &pass_store),
    ] {
        let err_msg = store
            .set("canary-key", canary)
            .expect_err("echo_err must fail")
            .to_string();
        assert!(
            !err_msg.contains(canary),
            "{label} error leaked raw secret: {err_msg}"
        );
        assert!(
            !err_msg.contains(&*canary_b64),
            "{label} error leaked encoded secret: {err_msg}"
        );
        assert!(
            err_msg.contains("[REDACTED]"),
            "{label} error should show redaction marker: {err_msg}"
        );
    }

    // 3. Missing vault in 1Password and uninitialized store in `pass` MUST fail closed (NOT SecretNotFound!)
    fake_op.set_mode("bad_vault");
    assert!(matches!(
        op_store.get("nonexistent"),
        Err(CryptoError::Keystore(_))
    ));
    fake_pass.set_mode("uninitialized");
    assert!(matches!(
        pass_store.get("nonexistent"),
        Err(CryptoError::Keystore(_))
    ));

    // 4. Missing CLI binary -> clean fail-closed Keystore error
    let missing_op = SecretStore::new(op_dir.path(), SecretBackend::OnePassword)
        .with_op_bin("/nonexistent/hyphae-missing-op");
    let missing_lpass = SecretStore::new(lpass_dir.path(), SecretBackend::LastPass)
        .with_lpass_bin("/nonexistent/hyphae-missing-lpass");
    let missing_pass = SecretStore::new(pass_dir.path(), SecretBackend::Pass)
        .with_pass_bin("/nonexistent/hyphae-missing-pass");

    for (label, store) in [
        ("1password", &missing_op),
        ("lastpass", &missing_lpass),
        ("pass", &missing_pass),
    ] {
        let e = store.set("k", "secret-val").unwrap_err();
        assert!(
            matches!(e, CryptoError::Keystore(_)),
            "{label} missing bin set: {e}"
        );
        assert!(
            !e.to_string().contains("secret-val"),
            "{label} missing bin leaked secret"
        );
    }

    // 5. Path-traversal & flag-injection prefixes/vaults fail closed before spawning any CLI!
    fake_op.clear_argv_log();
    fake_lpass.clear_argv_log();
    fake_pass.clear_argv_log();

    for bad_vault in ["", "   ", "-vault", "a\nb", "a\0b", " lead", "trail "] {
        assert!(
            validate_onepassword_vault(bad_vault).is_err(),
            "vault {bad_vault:?} must fail"
        );
        let bad_store = SecretStore::new(op_dir.path(), SecretBackend::OnePassword)
            .with_op_bin(&fake_op.bin_path)
            .with_op_vault(bad_vault);
        assert!(matches!(
            bad_store.set("ok-name", "val"),
            Err(CryptoError::Keystore(_))
        ));
        assert!(matches!(
            bad_store.get("ok-name"),
            Err(CryptoError::Keystore(_))
        ));
        assert!(matches!(bad_store.list(), Err(CryptoError::Keystore(_))));
    }
    assert!(
        fake_op.read_argv_log().trim().is_empty(),
        "invalid vaults must fail closed before spawning op"
    );

    for bad_prefix in [
        "",
        "   ",
        "../escape",
        "/etc",
        "hyphae/",
        "a/../b",
        "a//b",
        "a\\b",
        "-flag",
        ".hidden",
        "a/.hidden",
        "a\nb",
    ] {
        assert!(
            validate_lastpass_prefix(bad_prefix).is_err(),
            "lpass prefix {bad_prefix:?} must fail"
        );
        let bad_lp = SecretStore::new(lpass_dir.path(), SecretBackend::LastPass)
            .with_lpass_bin(&fake_lpass.bin_path)
            .with_lpass_prefix(bad_prefix);
        assert!(matches!(
            bad_lp.set("ok-name", "val"),
            Err(CryptoError::Keystore(_))
        ));
        assert!(matches!(
            bad_lp.get("ok-name"),
            Err(CryptoError::Keystore(_))
        ));
        assert!(matches!(bad_lp.list(), Err(CryptoError::Keystore(_))));

        assert!(
            validate_pass_prefix(bad_prefix).is_err(),
            "pass prefix {bad_prefix:?} must fail"
        );
        let bad_ps = SecretStore::new(pass_dir.path(), SecretBackend::Pass)
            .with_pass_bin(&fake_pass.bin_path)
            .with_pass_prefix(bad_prefix)
            .with_password_store_dir(&fake_pass.store_root);
        assert!(matches!(
            bad_ps.set("ok-name", "val"),
            Err(CryptoError::Keystore(_))
        ));
        assert!(matches!(
            bad_ps.get("ok-name"),
            Err(CryptoError::Keystore(_))
        ));
        assert!(matches!(
            bad_ps.delete("ok-name"),
            Err(CryptoError::Keystore(_))
        ));
        assert!(matches!(bad_ps.list(), Err(CryptoError::Keystore(_))));
    }
    assert!(
        validate_pass_prefix(".gpg-id").is_err()
            && validate_pass_prefix(".git").is_err()
            && validate_pass_prefix("has space").is_err(),
        "pass prefix must block .gpg-id, .git, and spaces"
    );
    assert!(
        fake_lpass.read_argv_log().trim().is_empty(),
        "invalid lpass prefixes must fail closed before spawning lpass"
    );
    assert!(
        fake_pass.read_argv_log().trim().is_empty(),
        "invalid pass prefixes must fail closed before spawning pass"
    );
}

#[test]
fn backend_parsing_serde_autodetect_and_output_classifiers() {
    // 1. Parse & serde round-trips
    for (raw, expected) in [
        ("1password", SecretBackend::OnePassword),
        ("  1PASSWORD ", SecretBackend::OnePassword),
        ("lastpass", SecretBackend::LastPass),
        ("LastPass", SecretBackend::LastPass),
        ("pass", SecretBackend::Pass),
        ("PASS", SecretBackend::Pass),
        ("file", SecretBackend::File),
        ("keychain", SecretBackend::Keychain),
        ("secret-service", SecretBackend::SecretService),
    ] {
        assert_eq!(parse_backend(raw), Some(expected));
        let json = serde_json::to_string(&expected).unwrap();
        assert_eq!(json, format!("\"{}\"", expected.as_str()));
        let back: SecretBackend = serde_json::from_str(&json).unwrap();
        assert_eq!(back, expected);
    }
    assert_eq!(parse_backend("unknown"), None);
    assert_eq!(parse_backend(""), None);

    // 2. Ephemeral temp-dir auto-fallback remains File unless explicitly overridden
    let tmp = TempDir::new().unwrap();
    assert_eq!(detect_backend_with(tmp.path(), None), SecretBackend::File);
    assert_eq!(
        detect_backend_with(tmp.path(), Some("1password")),
        SecretBackend::OnePassword
    );
    assert_eq!(
        detect_backend_with(tmp.path(), Some("lastpass")),
        SecretBackend::LastPass
    );
    assert_eq!(
        detect_backend_with(tmp.path(), Some("pass")),
        SecretBackend::Pass
    );

    // 3. 1Password classifier handles full item JSON, single-field JSON, raw text, not-found, and fail-closed errors
    let item_json =
        br#"{"id":"abc","title":"hyphae/k","fields":[{"id":"notesPlain","value":"raw-tok"}]}"#;
    assert_eq!(
        &*classify_onepassword_get_output("k", Some(0), item_json, "")
            .unwrap()
            .unwrap(),
        "raw-tok"
    );
    let field_json = br#"{"id":"notesPlain","value":"single-field-tok"}"#;
    assert_eq!(
        &*classify_onepassword_get_output("k", Some(0), field_json, "")
            .unwrap()
            .unwrap(),
        "single-field-tok"
    );
    assert_eq!(
        &*classify_onepassword_get_output("k", Some(0), b"plain-field-val\n", "")
            .unwrap()
            .unwrap(),
        "plain-field-val"
    );
    assert!(
        classify_onepassword_get_output(
            "k",
            Some(1),
            b"",
            "[ERROR] \"hyphae/k\" isn't an item in the \"Hyphae\" vault"
        )
        .unwrap()
        .is_none()
    );
    assert!(matches!(
        classify_onepassword_get_output("k", Some(1), b"", "[ERROR] \"Hyphae\" isn't a vault"),
        Err(CryptoError::Keystore(_))
    ));
    assert!(matches!(
        classify_onepassword_get_output(
            "k",
            Some(1),
            b"",
            "[ERROR] You are not currently signed in"
        ),
        Err(CryptoError::Keystore(_))
    ));
    assert_eq!(
        parse_onepassword_list_json(
            br#"[{"title":"hyphae/beta"},{"title":"other/ignored"},{"title":"hyphae/alpha"},{"title":"hyphae/../bad"}]"#
        )
        .unwrap(),
        vec!["alpha".to_string(), "beta".to_string()]
    );

    // 4. LastPass classifier & ls parser
    assert!(
        classify_lastpass_show_output(
            "k",
            Some(1),
            b"",
            "Error: Could not find specified account(s)."
        )
        .unwrap()
        .is_none()
    );
    assert!(matches!(
        classify_lastpass_show_output("k", Some(1), b"", "Error: Not logged in."),
        Err(CryptoError::Keystore(_))
    ));
    assert_eq!(
        parse_lastpass_ls_output(
            "hyphae",
            "hyphae/zebra [id: 1]\nhyphae/alpha [id: 2]\nother/ignored [id: 3]\nhyphae/../bad [id: 4]\n"
        ),
        vec!["alpha".to_string(), "zebra".to_string()]
    );

    // 5. Pass classifier
    assert!(
        classify_pass_show_output(
            "k",
            Some(1),
            b"",
            "Error: hyphae/k is not in the password store."
        )
        .unwrap()
        .is_none()
    );
    assert!(matches!(
        classify_pass_show_output("k", Some(2), b"", "gpg: decryption failed: No secret key"),
        Err(CryptoError::Keystore(_))
    ));
    assert!(matches!(
        classify_pass_show_output(
            "k",
            Some(1),
            b"",
            "Error: password store is empty. Try \"pass init\"."
        ),
        Err(CryptoError::Keystore(_))
    ));
}
