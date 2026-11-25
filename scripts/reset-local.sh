#!/usr/bin/env bash
# Reset local Hyphae (`hyp`) state so you can test fresh installs & onboarding from scratch.
#
# Backwards-compatible wrapper around `scripts/uninstall.sh` that keeps `~/.local/bin/hyp`
# by default unless `--all`, `--binary`, or `-b` is passed.
#
# Usage:
#   bash scripts/reset-local.sh                # interactive preview + reset state/configs/harnesses (keeps ~/.local/bin/hyp)
#   bash scripts/reset-local.sh --all          # also remove ~/.local/bin/hyp (for full `curl | sh` from-scratch tests)
#   bash scripts/reset-local.sh --dry-run      # print everything that would be cleaned without changing anything
#   bash scripts/reset-local.sh --all --yes    # non-interactive full wipe

set -eu
if (set -o pipefail) 2>/dev/null; then
  set -o pipefail
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
UNINSTALL_SCRIPT="${SCRIPT_DIR}/uninstall.sh"

if [ ! -f "$UNINSTALL_SCRIPT" ]; then
  printf 'error: missing uninstaller at %s\n' "$UNINSTALL_SCRIPT" >&2
  exit 1
fi

REMOVE_BINARY=0
for _arg in "$@"; do
  case "$_arg" in
    --help|-h)
      cat <<'EOF'
Hyphae local test reset script (delegates to scripts/uninstall.sh)

Usage:
  scripts/reset-local.sh [OPTIONS]

Options:
  --all, --binary, -b   Also remove the installed `hyp` binary (~/.local/bin/hyp)
                        so you can test `curl -fsSL https://hyphae.to/install.sh | sh` from zero
  --dry-run, -n         Show what would be stopped/restored/removed without modifying anything
  --yes, -y             Skip interactive confirmation prompt
  --skip-keychain       Leave OS Keychain / Secret Service `hyphae` entries untouched
  --keep-state          Keep ~/.config/hyphae state/keys/database
  --keep-harnesses      Leave harness configs, skills, statusLines & Herdr mod untouched
  --help, -h            Show this help message
EOF
      exit 0
      ;;
    --all|--binary|-b)
      REMOVE_BINARY=1
      ;;
  esac
done

if [ "$REMOVE_BINARY" -eq 1 ]; then
  exec /usr/bin/env bash "$UNINSTALL_SCRIPT" "$@"
else
  exec /usr/bin/env bash "$UNINSTALL_SCRIPT" --keep-binary "$@"
fi
