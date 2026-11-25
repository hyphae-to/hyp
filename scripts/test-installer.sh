#!/usr/bin/env bash
# End-to-end verification suite for scripts/install.sh & site/install.* mirrors.
# Builds the real Rust release binary, serves a real .tar.gz + SHA256SUMS.txt over
# an ephemeral localhost HTTP server, and verifies:
#   1. Happy-path install + `hyp version --json` (`ok: true`)
#   2. Fail-closed 1-byte tampered archive mutation test (non-zero exit, zero binary written)
#   3. `--dry-run`, POSIX syntax (`sh -n`), and byte-identical `scripts/` <-> `site/` mirrors

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="v0.2.0-test"
PREBUILT_BIN="${HYPHAE_PREBUILT_BIN:-}"
SKIP_BUILD="${HYPHAE_SKIP_BUILD:-0}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --prebuilt-bin)
      if [ "$#" -lt 2 ]; then
        echo "FAIL: --prebuilt-bin requires a path" >&2
        exit 2
      fi
      PREBUILT_BIN="$2"
      shift 2
      ;;
    --prebuilt-bin=*)
      PREBUILT_BIN="${1#*=}"
      shift 1
      ;;
    --skip-build)
      SKIP_BUILD=1
      shift 1
      ;;
    --help|-h)
      cat <<'EOF'
Usage: scripts/test-installer.sh [--prebuilt-bin <path>] [--skip-build]

Environment overrides:
  HYPHAE_PREBUILT_BIN   Path to an already-built `hyp` binary (skips `cargo build`)
  HYPHAE_SKIP_BUILD=1   Reuse `target/release/hyp` without invoking `cargo build`
EOF
      exit 0
      ;;
    *)
      echo "FAIL: unknown option: $1 (use --help for usage)" >&2
      exit 2
      ;;
  esac
done

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/hyphae-installer-test.XXXXXX")"
SERVER_PID=""

cleanup() {
  if [ -n "${SERVER_PID:-}" ]; then
    kill "$SERVER_PID" >/dev/null 2>&1 || true
    wait "$SERVER_PID" >/dev/null 2>&1 || true
  fi
  if [ -n "${TMP_ROOT:-}" ] && [ -d "$TMP_ROOT" ]; then
    rm -rf "$TMP_ROOT"
  fi
}
trap cleanup EXIT

detect_host_target() {
  local os_name arch_name
  os_name="$(uname -s)"
  arch_name="$(uname -m)"
  case "$os_name" in
    Darwin)
      case "$arch_name" in
        arm64|aarch64) echo "aarch64-apple-darwin" ;;
        x86_64|amd64)  echo "x86_64-apple-darwin" ;;
        *) echo "Unsupported macOS arch: $arch_name" >&2; exit 1 ;;
      esac
      ;;
    Linux)
      case "$arch_name" in
        x86_64|amd64)
          if [ -f /etc/alpine-release ] || (command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl); then
            echo "x86_64-unknown-linux-musl"
          else
            echo "x86_64-unknown-linux-gnu"
          fi
          ;;
        aarch64|arm64) echo "aarch64-unknown-linux-gnu" ;;
        *) echo "Unsupported Linux arch: $arch_name" >&2; exit 1 ;;
      esac
      ;;
    *)
      echo "Unsupported host OS for test-installer.sh: $os_name" >&2
      exit 1
      ;;
  esac
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print tolower($1)}'
  else
    openssl dgst -sha256 "$1" | awk '{print tolower($NF)}'
  fi
}

if [ -n "$PREBUILT_BIN" ]; then
  RELEASE_BIN="$PREBUILT_BIN"
  if [ ! -f "$RELEASE_BIN" ] || [ ! -x "$RELEASE_BIN" ]; then
    echo "FAIL: prebuilt binary not found or not executable: ${RELEASE_BIN}" >&2
    exit 1
  fi
  echo "==> Using prebuilt release binary: ${RELEASE_BIN}"
elif [ "$SKIP_BUILD" = "1" ] || [ "$SKIP_BUILD" = "true" ]; then
  RELEASE_BIN="${REPO_ROOT}/target/release/hyp"
  if [ ! -f "$RELEASE_BIN" ] || [ ! -x "$RELEASE_BIN" ]; then
    echo "FAIL: --skip-build / HYPHAE_SKIP_BUILD set, but ${RELEASE_BIN} does not exist or is not executable" >&2
    exit 1
  fi
  echo "==> Reusing existing release binary (build skipped): ${RELEASE_BIN}"
else
  echo "==> Building release binary (cargo build --release -p hyp-cli --offline)..."
  (cd "$REPO_ROOT" && cargo build --release -p hyp-cli --offline)
  RELEASE_BIN="${REPO_ROOT}/target/release/hyp"
fi

TARGET="$(detect_host_target)"
ARCHIVE_NAME="hyp-${VERSION}-${TARGET}.tar.gz"
SERVE_ROOT="${TMP_ROOT}/www"
GOOD_DIR="${SERVE_ROOT}/good"
TAMPER_DIR="${SERVE_ROOT}/tampered"
STAGE_DIR="${TMP_ROOT}/stage"
mkdir -p "$GOOD_DIR" "$TAMPER_DIR" "$STAGE_DIR"

cp "$RELEASE_BIN" "${STAGE_DIR}/hyp"
chmod 0755 "${STAGE_DIR}/hyp"
tar -C "$STAGE_DIR" -czf "${GOOD_DIR}/${ARCHIVE_NAME}" hyp

GOOD_SHA="$(sha256_file "${GOOD_DIR}/${ARCHIVE_NAME}")"
printf '%s  %s\n' "$GOOD_SHA" "$ARCHIVE_NAME" > "${GOOD_DIR}/SHA256SUMS.txt"

# Create 1-byte tampered archive with the ORIGINAL valid SHA256SUMS.txt (McKeeman nearby mutation!)
cp "${GOOD_DIR}/${ARCHIVE_NAME}" "${TAMPER_DIR}/${ARCHIVE_NAME}"
cp "${GOOD_DIR}/SHA256SUMS.txt" "${TAMPER_DIR}/SHA256SUMS.txt"
python3 - "${TAMPER_DIR}/${ARCHIVE_NAME}" <<'PY'
import sys
path = sys.argv[1]
with open(path, "r+b") as f:
    data = bytearray(f.read())
    idx = len(data) // 2
    data[idx] ^= 0x01
    f.seek(0)
    f.write(data)
PY

# Launch ephemeral localhost HTTP server on an OS-assigned port (127.0.0.1:0).
PORT_FILE="${TMP_ROOT}/http.port"
python3 - "$SERVE_ROOT" "$PORT_FILE" <<'PY' >/dev/null 2>&1 &
import functools, http.server, os, sys

serve_dir, port_file = sys.argv[1], sys.argv[2]

class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

handler = functools.partial(QuietHandler, directory=serve_dir)
httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
port = httpd.server_address[1]
with open(port_file + ".tmp", "w") as f:
    f.write(str(port))
os.replace(port_file + ".tmp", port_file)
httpd.serve_forever()
PY
SERVER_PID=$!

for _ in $(seq 1 50); do
  if [ -f "$PORT_FILE" ]; then
    break
  fi
  sleep 0.05
done
if [ ! -f "$PORT_FILE" ]; then
  echo "FAIL: local HTTP server did not start" >&2
  exit 1
fi
PORT="$(cat "$PORT_FILE")"
echo "==> Local test server ready at http://127.0.0.1:${PORT} (target=${TARGET})"

# ---------------------------------------------------------------------------
# Test 1: Happy-path install + `hyp version --json` returns ok: true
# ---------------------------------------------------------------------------
echo "==> [Test 1/3] Happy-path install + version --json check..."
TMP_BIN_OK="${TMP_ROOT}/bin-ok"
sh "${REPO_ROOT}/scripts/install.sh" \
  --version "$VERSION" \
  --base-url "http://127.0.0.1:${PORT}/good" \
  --dir "$TMP_BIN_OK" \
  --yes

if [ ! -x "${TMP_BIN_OK}/hyp" ]; then
  echo "FAIL [Test 1]: ${TMP_BIN_OK}/hyp was not installed or is not executable" >&2
  exit 1
fi

VERSION_JSON="$("${TMP_BIN_OK}/hyp" version --json)"
python3 - "$VERSION_JSON" <<'PY'
import json, sys
payload = json.loads(sys.argv[1])
assert payload.get("ok") is True, f"expected ok=true, got {payload}"
assert payload.get("command") == "version", f"expected command=version, got {payload}"
assert payload.get("data", {}).get("version"), f"missing version in {payload}"
print(f"    PASS: installed hyp version={payload['data']['version']} ok=True")
PY

# ---------------------------------------------------------------------------
# Test 2: Tampered archive mutation test (1-bit flip -> fail closed, 0 binary)
# ---------------------------------------------------------------------------
echo "==> [Test 2/3] Tampered archive mutation test (must fail closed)..."
TMP_BIN_TAMPER="${TMP_ROOT}/bin-tamper"
set +e
TAMPER_OUT="$(sh "${REPO_ROOT}/scripts/install.sh" \
  --version "$VERSION" \
  --base-url "http://127.0.0.1:${PORT}/tampered" \
  --dir "$TMP_BIN_TAMPER" \
  --yes 2>&1)"
TAMPER_RC=$?
set -e

if [ "$TAMPER_RC" -eq 0 ]; then
  echo "FAIL [Test 2]: install.sh succeeded on a 1-bit tampered archive!" >&2
  exit 1
fi
if [ -e "${TMP_BIN_TAMPER}/hyp" ]; then
  echo "FAIL [Test 2]: tampered archive wrote a binary to ${TMP_BIN_TAMPER}/hyp!" >&2
  exit 1
fi
if ! printf '%s' "$TAMPER_OUT" | grep -qi "checksum mismatch"; then
  echo "FAIL [Test 2]: expected checksum mismatch error, got:" >&2
  printf '%s\n' "$TAMPER_OUT" >&2
  exit 1
fi
echo "    PASS: tampered archive rejected fail-closed (exit=${TAMPER_RC}, zero files written)"

# ---------------------------------------------------------------------------
# Test 3: --dry-run, POSIX syntax check, and scripts/ <-> site/ mirror parity
# ---------------------------------------------------------------------------
echo "==> [Test 3/3] --dry-run, POSIX sh -n syntax, and mirror parity..."
TMP_BIN_DRY="${TMP_ROOT}/bin-dry"
DRY_OUT="$(sh "${REPO_ROOT}/scripts/install.sh" \
  --version "$VERSION" \
  --base-url "http://127.0.0.1:${PORT}/good" \
  --dir "$TMP_BIN_DRY" \
  --dry-run)"
if [ -e "${TMP_BIN_DRY}/hyp" ]; then
  echo "FAIL [Test 3]: --dry-run wrote ${TMP_BIN_DRY}/hyp!" >&2
  exit 1
fi
if ! printf '%s' "$DRY_OUT" | grep -q "$ARCHIVE_NAME"; then
  echo "FAIL [Test 3]: --dry-run output missing expected archive name '${ARCHIVE_NAME}'" >&2
  exit 1
fi

sh -n "${REPO_ROOT}/scripts/install.sh"
sh -n "${REPO_ROOT}/site/install.sh"

if ! cmp -s "${REPO_ROOT}/scripts/install.sh" "${REPO_ROOT}/site/install.sh"; then
  echo "FAIL [Test 3]: scripts/install.sh and site/install.sh differ!" >&2
  exit 1
fi
if ! cmp -s "${REPO_ROOT}/scripts/install.sh" "${REPO_ROOT}/install.sh"; then
  echo "FAIL [Test 3]: scripts/install.sh and root install.sh differ!" >&2
  exit 1
fi
if ! cmp -s "${REPO_ROOT}/scripts/install.ps1" "${REPO_ROOT}/site/install.ps1"; then
  echo "FAIL [Test 3]: scripts/install.ps1 and site/install.ps1 differ!" >&2
  exit 1
fi
if [ ! -f "${REPO_ROOT}/scripts/uninstall.ps1" ] || [ ! -f "${REPO_ROOT}/site/uninstall.ps1" ]; then
  echo "FAIL [Test 3]: scripts/uninstall.ps1 or site/uninstall.ps1 is missing!" >&2
  exit 1
fi
if ! cmp -s "${REPO_ROOT}/scripts/uninstall.ps1" "${REPO_ROOT}/site/uninstall.ps1"; then
  echo "FAIL [Test 3]: scripts/uninstall.ps1 and site/uninstall.ps1 differ!" >&2
  exit 1
fi
if command -v pwsh >/dev/null 2>&1; then
  (
    cd "$REPO_ROOT"
    pwsh -NoProfile -Command '
      $ErrorActionPreference = "Stop"
      foreach ($path in @("scripts/install.ps1", "site/install.ps1", "scripts/uninstall.ps1", "site/uninstall.ps1")) {
        $tokens = $null
        $errors = $null
        $resolved = (Resolve-Path $path).Path
        [void][System.Management.Automation.Language.Parser]::ParseFile($resolved, [ref]$tokens, [ref]$errors)
        if ($errors -and $errors.Count -gt 0) {
          $msg = ($errors | ForEach-Object { $_.ToString() }) -join "`n"
          throw "PowerShell syntax error(s) in ${path}:`n$msg"
        }
      }
    '
  )
fi
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck -s sh "${REPO_ROOT}/scripts/install.sh"
fi
echo "    PASS: --dry-run clean, POSIX sh -n valid, scripts/ <-> site/ byte-identical"

echo "ALL 3 INSTALLER TESTS PASSED!"
