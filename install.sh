#!/bin/sh
# Hyphae (`hyp`) binary installer — https://hyphae.to
# Usage:
#   curl -fsSL https://hyphae.to/install.sh | sh
#   curl -fsSL https://hyphae.to/install.sh | sh -s -- --version v0.2.0 --dir "$HOME/.local/bin"

set -eu

REPO="hyphae-to/hyp"
VERSION="${HYPHAE_VERSION:-}"
INSTALL_DIR="${HYPHAE_INSTALL_DIR:-$HOME/.local/bin}"
BASE_URL="${HYPHAE_BASE_URL:-}"
DRY_RUN=0
ASSUME_YES=0
TMP_DIR=""

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
  --yes, -y           Non-interactive mode
  --help, -h          Show this help message

Environment overrides:
  HYPHAE_VERSION      Same as --version
  HYPHAE_INSTALL_DIR  Same as --dir
  HYPHAE_BASE_URL     Same as --base-url
EOF
}

log() {
  printf '%s\n' "$*"
}

err() {
  printf 'error: %s\n' "$*" >&2
}

cleanup() {
  if [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
  fi
}

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

# Suppress unused-variable warnings while preserving --yes flag semantics.
: "$ASSUME_YES"

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

download_to_file() {
  dl_url="$1"
  dl_dest="$2"
  if command -v curl >/dev/null 2>&1; then
    case "$dl_url" in
      https://*)
        curl -fsSL --retry 2 --proto '=https' --tlsv1.2 -H "User-Agent: hyphae-installer" "$dl_url" -o "$dl_dest"
        ;;
      *)
        curl -fsSL --retry 2 -H "User-Agent: hyphae-installer" "$dl_url" -o "$dl_dest"
        ;;
    esac
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$dl_dest" --header="User-Agent: hyphae-installer" "$dl_url"
  else
    err "either curl or wget is required to download Hyphae"
    exit 1
  fi
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
    api_body="$(wget -qO- \
      --header="Accept: application/vnd.github+json" \
      --header="User-Agent: hyphae-installer" \
      "$api_url")" || {
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
mv -f "$STAGED_BIN" "$INSTALL_PATH"

log "Installed hyp to ${INSTALL_PATH}"
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

log ""
log "Next steps:"
log "  hyp deploy providers   # list one-click self-hosting targets"
log "  hyp pair guide         # pair laptops, servers, and agents"
log "  hyp onboard            # interactive mesh setup"
