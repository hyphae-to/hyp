#!/usr/bin/env bash
# Reset local Hyphae (`hyp`) state so you can test fresh installs & onboarding from scratch.
#
# Usage:
#   bash scripts/reset-local.sh                # interactive preview + reset state, keychain & hyphae-setup skills (keeps ~/.local/bin/hyp)
#   bash scripts/reset-local.sh --all          # also remove ~/.local/bin/hyp (for full `curl | sh` from-scratch tests)
#   bash scripts/reset-local.sh --dry-run      # print everything that would be cleaned without changing anything
#   bash scripts/reset-local.sh --all --yes    # non-interactive full wipe
#
# Safety:
#   - Never deletes user harness settings files (~/.claude/settings.json, ~/.codex/config.toml, etc.);
#     only removes the targeted `hyphae-setup` skill subdirectory.
#   - Never prints macOS Keychain / Linux Secret Service secret values (only account names).

set -euo pipefail

DRY_RUN=0
ASSUME_YES=0
REMOVE_BINARY=0
SKIP_KEYCHAIN=0
INSTALL_DIR="${HYPHAE_INSTALL_DIR:-$HOME/.local/bin}"

usage() {
  cat <<'EOF'
Hyphae local test reset script

Usage:
  scripts/reset-local.sh [OPTIONS]

Options:
  --all, --binary    Also remove the installed `hyp` binary (~/.local/bin/hyp)
                     so you can test `curl -fsSL https://hyphae.to/install.sh | sh` from zero
  --dry-run, -n      Show what would be stopped/removed without modifying anything
  --yes, -y          Skip interactive confirmation prompt
  --skip-keychain    Leave OS Keychain / Secret Service `hyphae` entries untouched
  --help, -h         Show this help message
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --all|--binary|-b)
      REMOVE_BINARY=1
      shift
      ;;
    --dry-run|-n)
      DRY_RUN=1
      shift
      ;;
    --yes|-y)
      ASSUME_YES=1
      shift
      ;;
    --skip-keychain)
      SKIP_KEYCHAIN=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf 'error: unknown option: %s (use --help for usage)\n' "$1" >&2
      exit 2
      ;;
  esac
done

CONFIG_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
STATE_HOME="${XDG_STATE_HOME:-$HOME/.local/state}"
OS_NAME="$(uname -s)"

# ---------------------------------------------------------------------------
# 1. Discover targets to clean
# ---------------------------------------------------------------------------

DIRS_TO_REMOVE=()
for d in \
  "$CONFIG_HOME/hyphae" \
  "$CONFIG_HOME/agents-mesh" \
  "$STATE_HOME/hyphae" \
  "$HOME/.local/share/hyphae"
do
  if [ -e "$d" ] || [ -L "$d" ]; then
    DIRS_TO_REMOVE+=("$d")
  fi
done

SKILL_DIRS_TO_REMOVE=()
for s in \
  "$HOME/.claude/skills/hyphae-setup" \
  "$HOME/.codex/skills/hyphae-setup" \
  "$HOME/.agents/skills/hyphae-setup" \
  "$HOME/.gemini/config/skills/hyphae-setup" \
  "$HOME/.gemini/skills/hyphae-setup" \
  "$CONFIG_HOME/opencode/skills/hyphae-setup" \
  "$HOME/.cursor/skills/hyphae-setup" \
  "$HOME/.openclaw/skills/hyphae-setup"
do
  if [ -e "$s" ] || [ -L "$s" ]; then
    SKILL_DIRS_TO_REMOVE+=("$s")
  fi
done

BINS_TO_REMOVE=()
if [ "$REMOVE_BINARY" -eq 1 ]; then
  for b in "$INSTALL_DIR/hyp" "$INSTALL_DIR/hyp.prev" "$INSTALL_DIR/hyp-rs"; do
    if [ -e "$b" ] || [ -L "$b" ]; then
      BINS_TO_REMOVE+=("$b")
    fi
  done
fi

LAUNCH_AGENTS=()
LAUNCH_PLISTS=()
SYSTEMD_UNITS=()
if [ "$OS_NAME" = "Darwin" ]; then
  while IFS= read -r label; do
    [ -n "$label" ] && LAUNCH_AGENTS+=("$label")
  done < <(launchctl list 2>/dev/null | awk '{print $3}' | grep -iE 'hyphae|t3-mesh|agents-mesh' || true)

  if [ -d "$HOME/Library/LaunchAgents" ]; then
    while IFS= read -r plist; do
      [ -n "$plist" ] && LAUNCH_PLISTS+=("$plist")
    done < <(find "$HOME/Library/LaunchAgents" -maxdepth 1 -type f \( -iname '*hyphae*' -o -iname '*t3-mesh*' -o -iname '*agents-mesh*' \) 2>/dev/null | sort || true)
  fi
elif [ "$OS_NAME" = "Linux" ]; then
  if [ -d "$CONFIG_HOME/systemd/user" ]; then
    while IFS= read -r unit; do
      [ -n "$unit" ] && SYSTEMD_UNITS+=("$unit")
    done < <(find "$CONFIG_HOME/systemd/user" -maxdepth 1 -type f \( -iname '*hyphae*' -o -iname '*agents-mesh*' \) 2>/dev/null | sort || true)
  fi
fi

# Running local Hyphae daemon processes only (never touch shells or coding agents).
DAEMON_PIDS=()
while IFS= read -r entry; do
  [ -z "$entry" ] && continue
  pid="${entry%%:*}"
  if [ "$pid" = "$$" ]; then
    continue
  fi
  DAEMON_PIDS+=("$entry")
done < <(
  ps -eo pid=,args= 2>/dev/null | awk '
    {
      pid = $1
      sub(/^[[:space:]]*[0-9]+[[:space:]]+/, "", $0)
      if ($0 ~ /(^|\/)(hyp|hyp-rs)[[:space:]]+(daemon|node[[:space:]]+start)([[:space:]]|$)/ || $0 ~ /hyphae\.mjs[[:space:]]+(daemon|node)([[:space:]]|$)/) {
        print pid ":" $0
      }
    }
  ' || true
)

# macOS Keychain accounts under service="hyphae" (names only, never secret values!).
KEYCHAIN_ACCOUNTS=()
if [ "$SKIP_KEYCHAIN" -eq 0 ] && [ "$OS_NAME" = "Darwin" ] && command -v security >/dev/null 2>&1; then
  # Only inspect live macOS Keychain when HOME matches real user home (avoids touching live keychain in sandboxed HOME tests).
  REAL_HOME="$(dscl . -read "/Users/$(id -un)" NFSHomeDirectory 2>/dev/null | awk '{print $2}' || printf '%s' "$HOME")"
  if [ "$HOME" = "$REAL_HOME" ]; then
    while IFS= read -r acct; do
      [ -n "$acct" ] && KEYCHAIN_ACCOUNTS+=("$acct")
    done < <(
      security dump-keychain 2>/dev/null | awk '
        BEGIN { acct=""; is_hyphae=0; }
        /^keychain:/ { acct=""; is_hyphae=0; }
        /"acct"<blob>="/ {
          line = $0;
          sub(/.*"acct"<blob>="/, "", line);
          sub(/".*/, "", line);
          acct = line;
        }
        /"svce"<blob>="hyphae"/ {
          is_hyphae = 1;
        }
        is_hyphae && acct != "" {
          print acct;
          acct="";
          is_hyphae=0;
        }
      ' | sort -u || true
    )
  fi
fi

# ---------------------------------------------------------------------------
# 2. Print summary plan
# ---------------------------------------------------------------------------

TOTAL=$((
  ${#DAEMON_PIDS[@]}
  + ${#LAUNCH_AGENTS[@]}
  + ${#LAUNCH_PLISTS[@]}
  + ${#SYSTEMD_UNITS[@]}
  + ${#DIRS_TO_REMOVE[@]}
  + ${#SKILL_DIRS_TO_REMOVE[@]}
  + ${#BINS_TO_REMOVE[@]}
  + ${#KEYCHAIN_ACCOUNTS[@]}
))

printf 'Hyphae local reset plan (HOME=%s)\n' "$HOME"
printf '==================================================\n'

if [ "$TOTAL" -eq 0 ]; then
  printf 'Already clean — nothing to remove.\n'
  if [ "$REMOVE_BINARY" -eq 0 ] && [ -x "$INSTALL_DIR/hyp" ]; then
    printf 'Note: kept binary at %s (pass --all to remove it too).\n' "$INSTALL_DIR/hyp"
  fi
  exit 0
fi

if [ "${#DAEMON_PIDS[@]}" -gt 0 ]; then
  printf '\nRunning daemons to stop (%d):\n' "${#DAEMON_PIDS[@]}"
  for entry in "${DAEMON_PIDS[@]}"; do
    printf '  - PID %s: %s\n' "${entry%%:*}" "${entry#*:}"
  done
fi

if [ "${#LAUNCH_AGENTS[@]}" -gt 0 ] || [ "${#LAUNCH_PLISTS[@]}" -gt 0 ]; then
  printf '\nmacOS LaunchAgents to unload/remove:\n'
  for label in "${LAUNCH_AGENTS[@]}"; do
    printf '  - service: %s\n' "$label"
  done
  for plist in "${LAUNCH_PLISTS[@]}"; do
    printf '  - plist:   %s\n' "$plist"
  done
fi

if [ "${#SYSTEMD_UNITS[@]}" -gt 0 ]; then
  printf '\nLinux systemd user units to stop/remove:\n'
  for unit in "${SYSTEMD_UNITS[@]}"; do
    printf '  - %s\n' "$unit"
  done
fi

if [ "${#DIRS_TO_REMOVE[@]}" -gt 0 ]; then
  printf '\nConfig / state directories to remove (%d):\n' "${#DIRS_TO_REMOVE[@]}"
  for d in "${DIRS_TO_REMOVE[@]}"; do
    printf '  - %s\n' "$d"
  done
fi

if [ "${#SKILL_DIRS_TO_REMOVE[@]}" -gt 0 ]; then
  printf '\nInstalled hyphae-setup skill folders to remove (%d):\n' "${#SKILL_DIRS_TO_REMOVE[@]}"
  for s in "${SKILL_DIRS_TO_REMOVE[@]}"; do
    printf '  - %s\n' "$s"
  done
fi

if [ "${#KEYCHAIN_ACCOUNTS[@]}" -gt 0 ]; then
  printf '\nmacOS Keychain (service="hyphae") items to delete (%d):\n' "${#KEYCHAIN_ACCOUNTS[@]}"
  for acct in "${KEYCHAIN_ACCOUNTS[@]}"; do
    printf '  - %s\n' "$acct"
  done
fi

if [ "${#BINS_TO_REMOVE[@]}" -gt 0 ]; then
  printf '\nBinaries to remove (%d):\n' "${#BINS_TO_REMOVE[@]}"
  for b in "${BINS_TO_REMOVE[@]}"; do
    printf '  - %s\n' "$b"
  done
elif [ -e "$INSTALL_DIR/hyp" ] || [ -L "$INSTALL_DIR/hyp" ]; then
  printf '\nKeeping binary: %s (pass --all to remove it too)\n' "$INSTALL_DIR/hyp"
fi

if [ "$DRY_RUN" -eq 1 ]; then
  printf '\n[dry-run] No files, processes, or keychain entries were modified.\n'
  exit 0
fi

if [ "$ASSUME_YES" -eq 0 ]; then
  if [ -t 0 ] || [ -r /dev/tty ]; then
    printf '\nProceed with local reset? [y/N]: '
    if [ -t 0 ]; then
      IFS= read -r reply || reply=""
    else
      IFS= read -r reply </dev/tty || reply=""
    fi
    case "$reply" in
      y|Y|yes|YES)
        ;;
      *)
        printf 'Aborted.\n'
        exit 0
        ;;
    esac
  else
    printf '\nerror: non-interactive stdin; pass --yes to confirm or --dry-run to preview\n' >&2
    exit 2
  fi
fi

# ---------------------------------------------------------------------------
# 3. Execute cleanup
# ---------------------------------------------------------------------------

for entry in "${DAEMON_PIDS[@]}"; do
  pid="${entry%%:*}"
  kill -TERM "$pid" 2>/dev/null || true
done

if [ "$OS_NAME" = "Darwin" ]; then
  uid="$(id -u)"
  for label in "${LAUNCH_AGENTS[@]}"; do
    launchctl bootout "gui/${uid}/${label}" 2>/dev/null || true
  done
  for plist in "${LAUNCH_PLISTS[@]}"; do
    launchctl bootout "gui/${uid}" "$plist" 2>/dev/null || true
    rm -f "$plist"
  done
elif [ "$OS_NAME" = "Linux" ]; then
  for unit in "${SYSTEMD_UNITS[@]}"; do
    name="$(basename "$unit")"
    systemctl --user disable --now "$name" 2>/dev/null || true
    rm -f "$unit"
  done
  if [ "${#SYSTEMD_UNITS[@]}" -gt 0 ] && command -v systemctl >/dev/null 2>&1; then
    systemctl --user daemon-reload 2>/dev/null || true
  fi
fi

for d in "${DIRS_TO_REMOVE[@]}"; do
  rm -rf "$d"
done

for s in "${SKILL_DIRS_TO_REMOVE[@]}"; do
  rm -rf "$s"
done

for acct in "${KEYCHAIN_ACCOUNTS[@]}"; do
  security delete-generic-password -s hyphae -a "$acct" >/dev/null 2>&1 || true
done

for b in "${BINS_TO_REMOVE[@]}"; do
  rm -f "$b"
done

printf '\nReset complete!\n'
if [ "$REMOVE_BINARY" -eq 1 ]; then
  printf 'Next: test fresh install & onboarding with:\n'
  printf '  curl -fsSL https://hyphae.to/install.sh | sh\n'
else
  printf 'Next: test scratch onboarding with:\n'
  printf '  hyp onboard\n'
fi
