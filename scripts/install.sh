#!/bin/sh
# Hyphae (`hyp`) binary installer — https://hyphae.to
# Usage:
#   curl -fsSL https://hyphae.to/install.sh | sh
#   curl -fsSL https://hyphae.to/install.sh | sh -s -- --version v0.2.0 --dir "$HOME/.local/bin"

usage() {
  cat <<'EOF'
Hyphae (`hyp`) installer

Usage:
  install.sh [OPTIONS]

Options:
  --version <tag>     Install a specific release tag (e.g. v0.2.0)
  --dir <path>        Install directory (default: $HOME/.local/bin)
  --base-url <url>    Base URL hosting release archives and SHA256SUMS.txt
  --dry-run           Print resolved target, URLs, and install path without writing
  --yes, -y           Non-interactive mode (skip prompts and interactive wizard)
  --force             Force download and reinstall even if already on the same version
  --no-onboard        Skip auto-launching the interactive onboarding wizard
  --help, -h          Show this help message

Environment overrides:
  HYPHAE_VERSION      Same as --version
  HYPHAE_INSTALL_DIR  Same as --dir
  HYPHAE_BASE_URL     Same as --base-url
  HYPHAE_NO_ONBOARD   Set non-empty to skip interactive onboarding (same as --no-onboard)
EOF
}

log() {
  printf '%s\n' "$*"
}

err() {
  printf 'error: %s\n' "$*" >&2
}

is_configured() {
  cfg_dir="${HYPHAE_CONFIG_DIR:-${XDG_CONFIG_HOME:-$HOME/.config}/hyphae}"
  [ -f "${cfg_dir}/node.json" ] || [ -f "${cfg_dir}/connector.json" ]
}

is_interactive_tty() {
  [ "$ASSUME_YES" -eq 0 ] && [ "$DRY_RUN" -eq 0 ] && [ -z "${CI:-}" ] && [ -t 1 ] && [ -r /dev/tty ]
}

read_tty_prompt() {
  printf '%s' "$1"
  PROMPT_REPLY=""
  if ! IFS= read -r PROMPT_REPLY </dev/tty; then
    PROMPT_REPLY=""
  fi
}

print_next_steps() {
  log ""
  log "Next steps:"
  log "  hyp deploy providers   # list one-click self-hosting targets"
  log "  hyp pair guide         # pair laptops, servers, and agents"
  log "  hyp onboard            # interactive mesh setup"
}

cleanup() {
  if [ -n "${STAGED_BIN:-}" ] && [ -e "$STAGED_BIN" ]; then
    rm -f "$STAGED_BIN"
  fi
  if [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
  fi
}

# Validate version tag characters (no path traversal or shell metacharacters).
normalize_and_validate_version() {
  raw_ver="$1"
  case "$raw_ver" in
    [0-9]*)
      raw_ver="v${raw_ver}"
      ;;
  esac
  case "$raw_ver" in
    ""|*/*|*..*|*[!A-Za-z0-9._+-]*)
      err "invalid version tag: '$1'"
      exit 2
      ;;
  esac
  printf '%s' "$raw_ver"
}

detect_target() {
  os_name="$(uname -s)"
  arch_name="$(uname -m)"

  case "$os_name" in
    Darwin)
      case "$arch_name" in
        arm64|aarch64)
          printf 'aarch64-apple-darwin'
          ;;
        x86_64|amd64)
          printf 'x86_64-apple-darwin'
          ;;
        *)
          err "unsupported macOS architecture: $arch_name (supported: arm64, x86_64)"
          exit 1
          ;;
      esac
      ;;
    Linux)
      case "$arch_name" in
        x86_64|amd64)
          is_musl=0
          if [ -f /etc/alpine-release ]; then
            is_musl=1
          elif command -v ldd >/dev/null 2>&1 && ldd --version 2>&1 | grep -qi musl; then
            is_musl=1
          elif [ -e /lib/ld-musl-x86_64.so.1 ] && [ ! -e /lib64/ld-linux-x86-64.so.2 ]; then
            is_musl=1
          fi
          if [ "$is_musl" -eq 1 ]; then
            printf 'x86_64-unknown-linux-musl'
          else
            printf 'x86_64-unknown-linux-gnu'
          fi
          ;;
        aarch64|arm64)
          printf 'aarch64-unknown-linux-gnu'
          ;;
        *)
          err "unsupported Linux architecture: $arch_name (supported: x86_64, aarch64)"
          exit 1
          ;;
      esac
      ;;
    MINGW*|MSYS*|CYGWIN*)
      err "Windows detected. Please install with PowerShell instead:"
      printf '  irm https://hyphae.to/install.ps1 | iex\n' >&2
      exit 1
      ;;
    *)
      err "unsupported operating system: $os_name"
      exit 1
      ;;
  esac
}

wget_https() {
  _wh_url="$1"
  _wh_dest="$2"
  _wh_accept="${3:-}"
  if wget --help 2>&1 | grep -q -- '--https-only'; then
    if wget --help 2>&1 | grep -q -- '--secure-protocol'; then
      if [ -n "$_wh_accept" ]; then
        wget -qO "$_wh_dest" --https-only --secure-protocol=TLSv1_2 \
          --header="Accept: ${_wh_accept}" \
          --header="User-Agent: hyphae-installer" \
          "$_wh_url"
      else
        wget -qO "$_wh_dest" --https-only --secure-protocol=TLSv1_2 \
          --header="User-Agent: hyphae-installer" \
          "$_wh_url"
      fi
    else
      if [ -n "$_wh_accept" ]; then
        wget -qO "$_wh_dest" --https-only \
          --header="Accept: ${_wh_accept}" \
          --header="User-Agent: hyphae-installer" \
          "$_wh_url"
      else
        wget -qO "$_wh_dest" --https-only \
          --header="User-Agent: hyphae-installer" \
          "$_wh_url"
      fi
    fi
  else
    if [ -n "$_wh_accept" ]; then
      wget -qO "$_wh_dest" \
        --header="Accept: ${_wh_accept}" \
        --header="User-Agent: hyphae-installer" \
        "$_wh_url"
    else
      wget -qO "$_wh_dest" \
        --header="User-Agent: hyphae-installer" \
        "$_wh_url"
    fi
  fi
}

download_to_file() {
  dl_url="$1"
  dl_dest="$2"
  case "$dl_url" in
    https://*)
      if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 2 --proto '=https' --tlsv1.2 -H "User-Agent: hyphae-installer" "$dl_url" -o "$dl_dest"
      elif command -v wget >/dev/null 2>&1; then
        wget_https "$dl_url" "$dl_dest"
      else
        err "either curl or wget is required to download Hyphae"
        exit 1
      fi
      ;;
    http://127.0.0.1:*|http://127.0.0.1/*|http://localhost:*|http://localhost/*|"http://[::1]:"*|"http://[::1]/"*)
      if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 2 -H "User-Agent: hyphae-installer" "$dl_url" -o "$dl_dest"
      elif command -v wget >/dev/null 2>&1; then
        wget -qO "$dl_dest" --header="User-Agent: hyphae-installer" "$dl_url"
      else
        err "either curl or wget is required to download Hyphae"
        exit 1
      fi
      ;;
    *)
      err "refusing insecure download URL (expected https://): $dl_url"
      exit 1
      ;;
  esac
}

resolve_latest_version() {
  api_url="https://api.github.com/repos/${REPO}/releases/latest"
  api_body=""
  if command -v curl >/dev/null 2>&1; then
    api_body="$(curl -fsSL --retry 2 --proto '=https' --tlsv1.2 \
      -H "Accept: application/vnd.github+json" \
      -H "User-Agent: hyphae-installer" \
      "$api_url")" || {
      err "failed to query latest release from $api_url (pass --version <tag> to specify explicitly)"
      exit 1
    }
  elif command -v wget >/dev/null 2>&1; then
    api_body="$(wget_https "$api_url" "-" "application/vnd.github+json")" || {
      err "failed to query latest release from $api_url (pass --version <tag> to specify explicitly)"
      exit 1
    }
  else
    err "either curl or wget is required to resolve the latest Hyphae release"
    exit 1
  fi

  resolved="$(printf '%s\n' "$api_body" | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)"
  if [ -z "$resolved" ]; then
    err "could not determine latest release tag from GitHub API (pass --version <tag>)"
    exit 1
  fi
  normalize_and_validate_version "$resolved"
}

compute_sha256() {
  target_file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$target_file" | awk '{print tolower($1)}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$target_file" | awk '{print tolower($1)}'
  elif command -v openssl >/dev/null 2>&1; then
    openssl dgst -sha256 "$target_file" | awk '{print tolower($NF)}'
  else
    err "no SHA-256 verification tool found (need sha256sum, shasum, or openssl); refusing unverified install"
    exit 1
  fi
}

lookup_expected_sha256() {
  sums_file="$1"
  archive_name="$2"
  awk -v fname="$archive_name" '
    {
      if (NF >= 2) {
        h = tolower($1)
        f = $2
        sub(/^\*/, "", f)
        sub(/^\.\//, "", f)
        if (f == fname) {
          print h
          exit 0
        }
      }
    }
  ' "$sums_file"
}

main() {
  set -eu

  REPO="hyphae-to/hyp"
  VERSION="${HYPHAE_VERSION:-}"
  INSTALL_DIR="${HYPHAE_INSTALL_DIR:-$HOME/.local/bin}"
  BASE_URL="${HYPHAE_BASE_URL:-}"
  DRY_RUN=0
  ASSUME_YES=0
  FORCE=0
  NO_ONBOARD=0
  if [ -n "${HYPHAE_NO_ONBOARD:-}" ]; then
    NO_ONBOARD=1
  fi
  TMP_DIR=""
  STAGED_BIN=""
  PROMPT_REPLY=""

  trap cleanup EXIT HUP INT TERM

  while [ "$#" -gt 0 ]; do
    case "$1" in
      --version)
        if [ "$#" -lt 2 ]; then
          err "--version requires a value"
          exit 2
        fi
        VERSION="$2"
        shift 2
        ;;
      --version=*)
        VERSION="${1#*=}"
        shift 1
        ;;
      --dir)
        if [ "$#" -lt 2 ]; then
          err "--dir requires a path"
          exit 2
        fi
        INSTALL_DIR="$2"
        shift 2
        ;;
      --dir=*)
        INSTALL_DIR="${1#*=}"
        shift 1
        ;;
      --base-url)
        if [ "$#" -lt 2 ]; then
          err "--base-url requires a URL"
          exit 2
        fi
        BASE_URL="$2"
        shift 2
        ;;
      --base-url=*)
        BASE_URL="${1#*=}"
        shift 1
        ;;
      --dry-run)
        DRY_RUN=1
        shift 1
        ;;
      --yes|-y)
        ASSUME_YES=1
        shift 1
        ;;
      --force)
        FORCE=1
        shift 1
        ;;
      --no-onboard)
        NO_ONBOARD=1
        shift 1
        ;;
      --help|-h)
        usage
        exit 0
        ;;
      *)
        err "unknown option: $1 (use --help for usage)"
        exit 2
        ;;
    esac
  done

  TARGET="$(detect_target)"

  if [ -n "$VERSION" ]; then
    VERSION="$(normalize_and_validate_version "$VERSION")"
  else
    if [ -n "$BASE_URL" ]; then
      err "--version <tag> is required when using --base-url"
      exit 2
    fi
    VERSION="$(resolve_latest_version)"
  fi

  ARCHIVE_NAME="hyp-${VERSION}-${TARGET}.tar.gz"
  if [ -n "$BASE_URL" ]; then
    BASE_TRIMMED="${BASE_URL%/}"
    ARCHIVE_URL="${BASE_TRIMMED}/${ARCHIVE_NAME}"
    SUMS_URL="${BASE_TRIMMED}/SHA256SUMS.txt"
  else
    RELEASE_BASE="https://github.com/${REPO}/releases/download/${VERSION}"
    ARCHIVE_URL="${RELEASE_BASE}/${ARCHIVE_NAME}"
    SUMS_URL="${RELEASE_BASE}/SHA256SUMS.txt"
  fi

  INSTALL_PATH="${INSTALL_DIR%/}/hyp"

  if [ "$DRY_RUN" -eq 1 ]; then
    log "Hyphae installer dry-run:"
    log "  Version:      ${VERSION}"
    log "  Target:       ${TARGET}"
    log "  Archive URL:  ${ARCHIVE_URL}"
    log "  Checksums:    ${SUMS_URL}"
    log "  Install path: ${INSTALL_PATH}"
    exit 0
  fi

  # Inspect existing installation before downloading so updates and same-version runs behave gracefully.
  WAS_INSTALLED=0
  EXISTING_VER=""
  if [ -x "$INSTALL_PATH" ]; then
    WAS_INSTALLED=1
    EXISTING_VER="$("$INSTALL_PATH" version 2>/dev/null | awk '{print $2}' | sed 's/^v//' || true)"
  fi
  TARGET_VER="${VERSION#v}"

  if [ "$WAS_INSTALLED" -eq 1 ] && [ -n "$EXISTING_VER" ] && [ "$EXISTING_VER" = "$TARGET_VER" ]; then
    if is_interactive_tty && [ "$FORCE" -eq 0 ]; then
      log "Hyphae ${VERSION} is already installed and up to date at ${INSTALL_PATH}."
      if ! is_configured && [ "$NO_ONBOARD" -eq 0 ]; then
        read_tty_prompt "Hyphae is not configured yet. Start interactive onboarding wizard? [Y/n]: "
        case "$PROMPT_REPLY" in
          ""|y|Y|yes|YES)
            log ""
            log "Starting Hyphae interactive setup wizard..."
            "$INSTALL_PATH" onboard </dev/tty
            exit $?
            ;;
          *)
            print_next_steps
            exit 0
            ;;
        esac
      elif is_configured; then
        read_tty_prompt "Open setup/config wizard (w), run doctor (d), reinstall anyway (r), or exit (N)? [w/d/r/N]: "
        case "$PROMPT_REPLY" in
          w|W)
            log ""
            log "Starting Hyphae interactive setup wizard..."
            "$INSTALL_PATH" onboard </dev/tty
            exit $?
            ;;
          d|D)
            "$INSTALL_PATH" doctor
            exit $?
            ;;
          r|R)
            ;;
          *)
            exit 0
            ;;
        esac
      else
        print_next_steps
        exit 0
      fi
    fi
  elif [ "$WAS_INSTALLED" -eq 1 ] && [ -n "$EXISTING_VER" ] && [ "$EXISTING_VER" != "$TARGET_VER" ]; then
    if is_interactive_tty && [ "$FORCE" -eq 0 ]; then
      log "Hyphae v${EXISTING_VER} is already installed at ${INSTALL_PATH}."
      read_tty_prompt "Update to ${VERSION}? [Y/n]: "
      case "$PROMPT_REPLY" in
        ""|y|Y|yes|YES)
          ;;
        *)
          log "Update cancelled."
          exit 0
          ;;
      esac
    fi
  fi

  if ! command -v tar >/dev/null 2>&1; then
    err "tar is required to extract Hyphae"
    exit 1
  fi

  TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/hyphae-install.XXXXXX")"
  ARCHIVE_PATH="${TMP_DIR}/${ARCHIVE_NAME}"
  SUMS_PATH="${TMP_DIR}/SHA256SUMS.txt"
  EXTRACT_DIR="${TMP_DIR}/extract"

  log "Installing Hyphae ${VERSION} (${TARGET})..."
  download_to_file "$ARCHIVE_URL" "$ARCHIVE_PATH"
  download_to_file "$SUMS_URL" "$SUMS_PATH"

  EXPECTED_SHA="$(lookup_expected_sha256 "$SUMS_PATH" "$ARCHIVE_NAME")"
  if [ -z "$EXPECTED_SHA" ]; then
    err "checksum for '${ARCHIVE_NAME}' not found in SHA256SUMS.txt; aborting fail-closed"
    exit 1
  fi
  case "$EXPECTED_SHA" in
    *[!0-9a-f]*)
      err "malformed SHA-256 checksum for '${ARCHIVE_NAME}' in SHA256SUMS.txt; aborting"
      exit 1
      ;;
  esac
  if [ "${#EXPECTED_SHA}" -ne 64 ]; then
    err "invalid SHA-256 checksum length for '${ARCHIVE_NAME}'; aborting"
    exit 1
  fi

  ACTUAL_SHA="$(compute_sha256 "$ARCHIVE_PATH")"
  if [ "$ACTUAL_SHA" != "$EXPECTED_SHA" ]; then
    err "SHA-256 checksum mismatch for '${ARCHIVE_NAME}'!"
    err "  expected: ${EXPECTED_SHA}"
    err "  actual:   ${ACTUAL_SHA}"
    err "refusing to install tampered or corrupted archive"
    exit 1
  fi
  log "Verified SHA-256 checksum (${ACTUAL_SHA})."

  mkdir -p "$EXTRACT_DIR"
  tar -xzf "$ARCHIVE_PATH" -C "$EXTRACT_DIR"

  SOURCE_BIN=""
  if [ -f "${EXTRACT_DIR}/hyp" ]; then
    SOURCE_BIN="${EXTRACT_DIR}/hyp"
  elif [ -f "${EXTRACT_DIR}/hyp-rs" ]; then
    SOURCE_BIN="${EXTRACT_DIR}/hyp-rs"
  else
    err "archive '${ARCHIVE_NAME}' did not contain expected 'hyp' binary"
    exit 1
  fi

  mkdir -p "$INSTALL_DIR"
  STAGED_BIN="${INSTALL_DIR%/}/.hyp.tmp.$$"
  cp "$SOURCE_BIN" "$STAGED_BIN"
  chmod 0755 "$STAGED_BIN"

  # Smoke-test staged binary BEFORE replacing any existing installation.
  if ! "$STAGED_BIN" --version >/dev/null 2>&1; then
    rm -f "$STAGED_BIN"
    STAGED_BIN=""
    err "downloaded binary failed smoke test ('--version'); existing installation left untouched"
    exit 1
  fi

  mv -f "$STAGED_BIN" "$INSTALL_PATH"
  STAGED_BIN=""

  IS_UPDATE=0
  if [ "$WAS_INSTALLED" -eq 1 ] && [ -n "$EXISTING_VER" ] && [ "$EXISTING_VER" != "$TARGET_VER" ]; then
    IS_UPDATE=1
    log "Updated hyp v${EXISTING_VER} -> ${VERSION} at ${INSTALL_PATH}"
  else
    log "Installed hyp to ${INSTALL_PATH}"
  fi
  "$INSTALL_PATH" version

  case ":${PATH:-}:" in
    *":${INSTALL_DIR%/}:"*)
      ;;
    *)
      log ""
      log "NOTE: ${INSTALL_DIR} is not currently on your PATH. Add it to your shell profile:"
      log "  # zsh (~/.zshrc) or bash (~/.bashrc):"
      log "  export PATH=\"${INSTALL_DIR}:\$PATH\""
      log "  # fish (~/.config/fish/config.fish):"
      log "  fish_add_path \"${INSTALL_DIR}\""
      ;;
  esac

  if [ "$IS_UPDATE" -eq 1 ] && is_configured; then
    "$INSTALL_PATH" onboard --install-skill >/dev/null 2>&1 || true
    SERVICE_RESTARTED=0
    if [ -f "$HOME/Library/LaunchAgents/to.hyphae.daemon.plist" ] || [ -f "${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user/hyphae-daemon.service" ]; then
      if "$INSTALL_PATH" service restart >/dev/null 2>&1; then
        SERVICE_RESTARTED=1
        log "Restarted background hyp daemon service."
      fi
    fi
    if is_interactive_tty; then
      log ""
      log "Running post-update health check..."
      "$INSTALL_PATH" doctor || true
      if [ "$SERVICE_RESTARTED" -eq 0 ]; then
        log ""
        log "Tip: Restart any running 'hyp daemon' process (or run 'hyp service install') so the updated binary takes effect."
      fi
    else
      print_next_steps
    fi
  elif ! is_configured && [ "$NO_ONBOARD" -eq 0 ] && is_interactive_tty; then
    log ""
    log "Starting Hyphae interactive setup wizard..."
    "$INSTALL_PATH" onboard </dev/tty
  else
    print_next_steps
  fi
}

main "$@"
