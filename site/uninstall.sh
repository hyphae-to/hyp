#!/usr/bin/env bash
# Hyphae (`hyp`) full uninstaller — https://hyphae.to
#
# Usage:
#   curl -fsSL https://hyphae.to/uninstall.sh | sh
#   bash scripts/uninstall.sh [OPTIONS]
#
# Safely stops running Hyphae daemons, unloads OS services, restores any chained
# Claude Code / Antigravity statusLines BEFORE removing state, surgically removes
# Hyphae entries from shared harness configs (preserving all other user settings),
# cleans standalone Hyphae plugins/commands/skills/Herdr mods, removes state &
# Keychain/Secret Service entries, and removes the `hyp` binary.

set -eu
if (set -o pipefail) 2>/dev/null; then
  set -o pipefail
fi

DRY_RUN=0
ASSUME_YES=0
KEEP_BINARY=0
KEEP_STATE=0
KEEP_KEYCHAIN=0
KEEP_HARNESSES=0
INSTALL_DIR="${HYPHAE_INSTALL_DIR:-$HOME/.local/bin}"

usage() {
  cat <<'EOF'
Hyphae (`hyp`) uninstaller

Usage:
  uninstall.sh [OPTIONS]

Options:
  --dry-run, -n                Print complete removal/restore plan without modifying anything
  --yes, -y                    Skip interactive confirmation prompt
  --keep-binary                Keep installed `hyp` binary (~/.local/bin/hyp)
  --keep-state                 Keep ~/.config/hyphae state, keys, and database
  --keep-keychain              Leave OS Keychain / Linux Secret Service entries untouched
  --skip-keychain              Alias for --keep-keychain
  --keep-harnesses             Leave harness configs, skills, slash commands, statusLines & Herdr mod untouched
  --all, --binary, -b          Remove binary too (default; accepted for backwards compatibility)
  --help, -h                   Show this help message

Environment overrides:
  HYPHAE_INSTALL_DIR           Binary directory (default: $HOME/.local/bin)
  HERDR_APP_HOME               Herdr desktop app directory (default: $XDG_CONFIG_HOME/herdr-app)
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run|-n)
      DRY_RUN=1
      shift
      ;;
    --yes|-y)
      ASSUME_YES=1
      shift
      ;;
    --keep-binary)
      KEEP_BINARY=1
      shift
      ;;
    --keep-state)
      KEEP_STATE=1
      shift
      ;;
    --keep-keychain|--skip-keychain)
      KEEP_KEYCHAIN=1
      shift
      ;;
    --keep-harnesses)
      KEEP_HARNESSES=1
      shift
      ;;
    --all|--binary|-b)
      KEEP_BINARY=0
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
HERDR_APP_DIR="${HERDR_APP_HOME:-$CONFIG_HOME/herdr-app}"
OS_NAME="$(uname -s)"

# Determine whether HOME points to the real OS account home directory.
# When running under an isolated test HOME, never touch live system daemons,
# live launchctl/systemd sessions, or the live OS Keychain / Secret Service.
detect_real_home() {
  _drh_user="$(id -un 2>/dev/null || printf '')"
  _drh_home=""
  if [ "$OS_NAME" = "Darwin" ] && [ -n "$_drh_user" ] && command -v dscl >/dev/null 2>&1; then
    _drh_home="$(dscl . -read "/Users/${_drh_user}" NFSHomeDirectory 2>/dev/null | awk '{print $2}' || true)"
  elif [ -n "$_drh_user" ] && command -v getent >/dev/null 2>&1; then
    _drh_home="$(getent passwd "$_drh_user" 2>/dev/null | cut -d: -f6 || true)"
  elif [ -n "$_drh_user" ] && [ -r /etc/passwd ]; then
    _drh_home="$(awk -F: -v u="$_drh_user" '$1 == u { print $6; exit }' /etc/passwd 2>/dev/null || true)"
  fi
  if [ -z "$_drh_home" ]; then
    _drh_home="$HOME"
  fi
  printf '%s' "$_drh_home"
}

REAL_HOME="$(detect_real_home)"
IS_REAL_HOME=0
if [ -n "$REAL_HOME" ] && [ "${HOME%/}" = "${REAL_HOME%/}" ]; then
  IS_REAL_HOME=1
fi

# ---------------------------------------------------------------------------
# Portable newline-delimited list helpers (macOS bash 3.2 + POSIX sh / dash)
# ---------------------------------------------------------------------------

list_contains() {
  [ -n "$1" ] || return 1
  printf '%s\n' "$1" | grep -F -x -q -e "$2"
}

list_append_unique() {
  _lau_list="$1"
  _lau_item="$2"
  [ -n "$_lau_item" ] || { printf '%s' "$_lau_list"; return 0; }
  if list_contains "$_lau_list" "$_lau_item"; then
    printf '%s' "$_lau_list"
    return 0
  fi
  if [ -z "$_lau_list" ]; then
    printf '%s' "$_lau_item"
  else
    printf '%s\n%s' "$_lau_list" "$_lau_item"
  fi
}

list_count() {
  if [ -z "$1" ]; then
    printf '0'
  else
    printf '%s\n' "$1" | wc -l | awk '{print $1}'
  fi
}

# ---------------------------------------------------------------------------
# Embedded surgical config cleaner (Python 3 primary, Node.js fallback)
# Handles:
#   - Step 2: Restoring chained Claude Code & Antigravity statusLines
#   - Step 3: Surgically removing Hyphae hooks/MCP/TOML/keybindings
#   - Read-only inspection of Herdr layouts referencing hyphae-pane/panel
# ---------------------------------------------------------------------------

CONFIG_CLEANER_TOOL=""
if command -v python3 >/dev/null 2>&1; then
  CONFIG_CLEANER_TOOL="python3"
elif command -v node >/dev/null 2>&1; then
  CONFIG_CLEANER_TOOL="node"
fi

run_config_cleaner() {
  _rcc_mode="$1"
  if [ "$CONFIG_CLEANER_TOOL" = "python3" ]; then
    HYPHAE_CLEAN_MODE="$_rcc_mode" \
    HYPHAE_HOME="$HOME" \
    HYPHAE_CONFIG_HOME="$CONFIG_HOME" \
    HYPHAE_STATE_HOME="$STATE_HOME" \
    HYPHAE_HERDR_APP_DIR="$HERDR_APP_DIR" \
    HYPHAE_OS_NAME="$OS_NAME" \
    python3 - <<'PYEOF'
import glob
import json
import os
import re
import shlex
import stat
import sys
import tempfile

mode = os.environ["HYPHAE_CLEAN_MODE"]
home = os.environ["HYPHAE_HOME"]
config_home = os.environ["HYPHAE_CONFIG_HOME"]
state_home = os.environ["HYPHAE_STATE_HOME"]
herdr_app_dir = os.environ["HYPHAE_HERDR_APP_DIR"]
os_name = os.environ["HYPHAE_OS_NAME"]

HYPHAE_HOOK_NAMES = {
    "hyphae-before-tool",
    "hyphae-after-tool",
    "hyphae-after-agent",
}

HYPHAE_HOOK_RE = re.compile(
    r"(?:^|[\s/\"'])(?:hyp|hyp-rs)(?:\.exe)?[\"']?\s+hook\s+"
    r"(?:claude|codex|cursor|gemini|antigravity|opencode|herdr|t3|openclaw)\b"
    r"|hyphae\.mjs\s+hook\b"
    r"|\bhyphae-hook\b"
    r"|agents-mesh[^\n]*\bhook\b",
    re.IGNORECASE,
)


def emit(kind, path, detail):
    safe_detail = str(detail).replace("\t", " ").replace("\n", " ")
    safe_path = str(path).replace("\t", " ").replace("\n", " ")
    sys.stdout.write(f"{kind}\t{safe_path}\t{safe_detail}\n")


def split_shell_words(cmd):
    try:
        return shlex.split(cmd, posix=True)
    except ValueError:
        return cmd.split()


def is_hyphae_statusline_command(cmd):
    if not isinstance(cmd, str) or not cmd.strip():
        return False
    words = split_shell_words(cmd)
    if len(words) < 2 or words[1] != "statusline":
        return False
    bin_name = os.path.basename(words[0]).lower()
    if bin_name in ("hyp", "hyp.exe", "hyp-rs", "hyp-rs.exe"):
        return True
    return "--harness" in words


def is_hyphae_statusline_value(val):
    if not isinstance(val, dict):
        return False
    return is_hyphae_statusline_command(val.get("command"))


def parse_chain_file(cmd):
    if not isinstance(cmd, str):
        return None
    words = split_shell_words(cmd)
    i = 0
    while i < len(words):
        w = words[i]
        if w == "--chain-file":
            if i + 1 < len(words) and words[i + 1]:
                return words[i + 1]
            return None
        if w.startswith("--chain-file="):
            rest = w[len("--chain-file="):]
            return rest if rest else None
        i += 1
    return None


def find_chain_backup(harness, cmd):
    filename = f"{harness}-statusline-chain.json"
    candidates = []
    ref = parse_chain_file(cmd)
    if ref:
        candidates.append(ref)
    for base in (
        os.path.join(config_home, "hyphae"),
        os.path.join(state_home, "hyphae"),
        os.path.join(home, ".config", "hyphae"),
        os.path.join(home, ".local", "state", "hyphae"),
    ):
        cand = os.path.join(base, filename)
        if cand not in candidates:
            candidates.append(cand)

    for cand in candidates:
        if os.path.isfile(cand):
            try:
                with open(cand, "r", encoding="utf-8") as fh:
                    parsed = json.load(fh)
                if parsed is not None:
                    return cand, parsed
            except Exception:
                continue
    return None, None


def is_hyphae_hook_command(cmd):
    if not isinstance(cmd, str) or not cmd.strip():
        return False
    words = split_shell_words(cmd)
    if len(words) >= 2:
        bin_name = os.path.basename(words[0]).lower()
        if bin_name in ("hyp", "hyp.exe", "hyp-rs", "hyp-rs.exe") and words[1] == "hook":
            return True
    return bool(HYPHAE_HOOK_RE.search(cmd))


def is_hyphae_hook_leaf(entry):
    if not isinstance(entry, dict):
        return False
    if is_hyphae_hook_command(entry.get("command")):
        return True
    if entry.get("name") in HYPHAE_HOOK_NAMES:
        return True
    return False


def clean_hooks_object(doc):
    hooks = doc.get("hooks")
    if not isinstance(hooks, dict):
        return 0
    total_removed = 0
    events_to_delete = []
    for event_name, event_val in list(hooks.items()):
        if not isinstance(event_val, list):
            continue
        event_removed = 0
        new_list = []
        for item in event_val:
            if isinstance(item, dict) and isinstance(item.get("hooks"), list):
                orig_sub = item["hooks"]
                kept_sub = [h for h in orig_sub if not is_hyphae_hook_leaf(h)]
                diff = len(orig_sub) - len(kept_sub)
                if diff > 0:
                    event_removed += diff
                    if kept_sub:
                        updated = dict(item)
                        updated["hooks"] = kept_sub
                        new_list.append(updated)
                else:
                    new_list.append(item)
            elif is_hyphae_hook_leaf(item):
                event_removed += 1
            else:
                new_list.append(item)
        if event_removed > 0:
            total_removed += event_removed
            if new_list:
                hooks[event_name] = new_list
            else:
                events_to_delete.append(event_name)
    for ev in events_to_delete:
        del hooks[ev]
    if total_removed > 0 and len(hooks) == 0:
        del doc["hooks"]
    return total_removed


def remove_nested_key(doc, parents, key):
    chain = []
    cur = doc
    for p in parents:
        if not isinstance(cur, dict) or not isinstance(cur.get(p), dict):
            return False
        chain.append((cur, p))
        cur = cur[p]
    if not isinstance(cur, dict) or key not in cur:
        return False
    del cur[key]
    for parent_dict, parent_key in reversed(chain):
        if isinstance(parent_dict.get(parent_key), dict) and len(parent_dict[parent_key]) == 0:
            del parent_dict[parent_key]
        else:
            break
    return True


def atomic_write_text(path, text):
    target = os.path.realpath(path) if os.path.islink(path) else path
    parent = os.path.dirname(target) or "."
    orig_mode = stat.S_IMODE(os.stat(target).st_mode)
    fd, tmp_path = tempfile.mkstemp(prefix=".hyp-uninstall-", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp_path, orig_mode)
        os.replace(tmp_path, target)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def load_json_object(path):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:
        emit("WARN", path, f"skipped invalid JSON ({exc})")
        return None
    if not isinstance(data, dict):
        emit("WARN", path, "skipped non-object JSON root")
        return None
    return data


def save_json_object(path, doc):
    rendered = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
    atomic_write_text(path, rendered)


def process_statusline_in_doc(doc, harness, path):
    sl = doc.get("statusLine")
    if sl is None or not is_hyphae_statusline_value(sl):
        return False
    cmd = sl.get("command")
    chain_path, original = find_chain_backup(harness, cmd)
    if chain_path is not None:
        doc["statusLine"] = original
        emit("STATUSLINE", path, f"restore original {harness} statusLine from {chain_path}")
    else:
        del doc["statusLine"]
        emit("STATUSLINE", path, f"remove Hyphae {harness} statusLine")
    return True


def dedup_paths(paths):
    seen = set()
    out = []
    for p in paths:
        norm = os.path.normpath(p)
        if norm not in seen:
            seen.add(norm)
            out.append(p)
    return out


# 1. Claude Code ~/.claude/settings.json (statusLine FIRST, then hooks)
claude_settings = os.path.join(home, ".claude", "settings.json")
if os.path.isfile(claude_settings):
    doc = load_json_object(claude_settings)
    if doc is not None:
        sl_changed = process_statusline_in_doc(doc, "claude", claude_settings)
        hooks_removed = clean_hooks_object(doc)
        if hooks_removed > 0:
            emit("EDIT", claude_settings, f"remove {hooks_removed} Hyphae hook entry/entries")
        if mode == "apply" and (sl_changed or hooks_removed > 0):
            save_json_object(claude_settings, doc)

# 2. Antigravity CLI ~/.gemini/antigravity-cli/settings.json (statusLine FIRST)
agy_settings = os.path.join(home, ".gemini", "antigravity-cli", "settings.json")
if os.path.isfile(agy_settings):
    doc = load_json_object(agy_settings)
    if doc is not None:
        sl_changed = process_statusline_in_doc(doc, "antigravity", agy_settings)
        if mode == "apply" and sl_changed:
            save_json_object(agy_settings, doc)

# 3. Claude CLI ~/.claude.json + Claude Desktop claude_desktop_config.json
claude_mcp_files = [os.path.join(home, ".claude.json")]
if os_name == "Darwin":
    claude_mcp_files.append(
        os.path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
    )
claude_mcp_files.append(os.path.join(config_home, "Claude", "claude_desktop_config.json"))
claude_mcp_files.append(os.path.join(home, ".config", "Claude", "claude_desktop_config.json"))
for mcp_path in dedup_paths(claude_mcp_files):
    if os.path.isfile(mcp_path):
        doc = load_json_object(mcp_path)
        if doc is not None and remove_nested_key(doc, ["mcpServers"], "hyphae"):
            emit("EDIT", mcp_path, "remove mcpServers.hyphae")
            if mode == "apply":
                save_json_object(mcp_path, doc)

# 4. Gemini CLI ~/.gemini/settings.json
gemini_settings = os.path.join(home, ".gemini", "settings.json")
if os.path.isfile(gemini_settings):
    doc = load_json_object(gemini_settings)
    if doc is not None:
        reasons = []
        if remove_nested_key(doc, ["mcpServers"], "hyphae"):
            reasons.append("mcpServers.hyphae")
        hooks_removed = clean_hooks_object(doc)
        if hooks_removed > 0:
            reasons.append(f"{hooks_removed} Hyphae hook entry/entries")
        if reasons:
            emit("EDIT", gemini_settings, "remove " + " + ".join(reasons))
            if mode == "apply":
                save_json_object(gemini_settings, doc)

# 5. Cursor ~/.cursor/mcp.json & ~/.cursor/hooks.json
cursor_mcp = os.path.join(home, ".cursor", "mcp.json")
if os.path.isfile(cursor_mcp):
    doc = load_json_object(cursor_mcp)
    if doc is not None and remove_nested_key(doc, ["mcpServers"], "hyphae"):
        emit("EDIT", cursor_mcp, "remove mcpServers.hyphae")
        if mode == "apply":
            save_json_object(cursor_mcp, doc)

cursor_hooks = os.path.join(home, ".cursor", "hooks.json")
if os.path.isfile(cursor_hooks):
    doc = load_json_object(cursor_hooks)
    if doc is not None:
        hooks_removed = clean_hooks_object(doc)
        if hooks_removed > 0:
            emit("EDIT", cursor_hooks, f"remove {hooks_removed} Hyphae hook entry/entries")
            if mode == "apply":
                save_json_object(cursor_hooks, doc)

# 6. Codex ~/.codex/hooks.json & ~/.codex/config.toml
codex_hooks = os.path.join(home, ".codex", "hooks.json")
if os.path.isfile(codex_hooks):
    doc = load_json_object(codex_hooks)
    if doc is not None:
        hooks_removed = clean_hooks_object(doc)
        if hooks_removed > 0:
            emit("EDIT", codex_hooks, f"remove {hooks_removed} Hyphae hook entry/entries")
            if mode == "apply":
                save_json_object(codex_hooks, doc)


def is_codex_hyphae_header(line):
    trimmed = line.strip()
    if not trimmed.startswith("[") or trimmed.startswith("[["):
        return False
    close_idx = trimmed.find("]")
    if close_idx == -1:
        return False
    trailing = trimmed[close_idx + 1:].strip()
    if trailing and not trailing.startswith("#"):
        return False
    inner = "".join(ch for ch in trimmed[1:close_idx] if not ch.isspace())
    return (
        inner in ("mcp_servers.hyphae", 'mcp_servers."hyphae"', "mcp_servers.'hyphae'")
        or inner.startswith("mcp_servers.hyphae.")
        or inner.startswith('mcp_servers."hyphae".')
        or inner.startswith("mcp_servers.'hyphae'.")
    )


def clean_codex_toml(raw):
    lines = raw.splitlines()
    kept = []
    removed_managed = False
    removed_section = False
    in_managed = False
    in_hyphae_section = False
    just_removed = False

    for line in lines:
        trimmed = line.strip()
        if in_managed:
            if trimmed == "# <<< hyphae <<<":
                in_managed = False
                just_removed = True
            continue
        if trimmed == "# >>> hyphae >>>":
            in_managed = True
            removed_managed = True
            continue
        if in_hyphae_section:
            if trimmed.startswith("["):
                in_hyphae_section = False
                just_removed = True
            else:
                continue
        if is_codex_hyphae_header(line):
            in_hyphae_section = True
            removed_section = True
            continue

        if just_removed and trimmed == "":
            if not kept or kept[-1].strip() == "":
                continue
        just_removed = False
        kept.append(line)

    if not removed_managed and not removed_section:
        return raw, []

    while kept and kept[-1].strip() == "":
        kept.pop()
    while kept and kept[0].strip() == "":
        kept.pop(0)

    new_text = ("\n".join(kept) + "\n") if kept else ""
    reasons = []
    if removed_managed:
        reasons.append("# >>> hyphae >>> managed block")
    if removed_section:
        reasons.append("[mcp_servers.hyphae] section")
    return new_text, reasons


codex_toml = os.path.join(home, ".codex", "config.toml")
if os.path.isfile(codex_toml):
    try:
        with open(codex_toml, "r", encoding="utf-8") as fh:
            raw_toml = fh.read()
        next_toml, reasons = clean_codex_toml(raw_toml)
        if reasons:
            emit("EDIT", codex_toml, "remove " + " + ".join(reasons))
            if mode == "apply":
                atomic_write_text(codex_toml, next_toml)
    except Exception as exc:
        emit("WARN", codex_toml, f"skipped unreadable TOML ({exc})")

# 7. OpenCode opencode.json
opencode_files = dedup_paths([
    os.path.join(config_home, "opencode", "opencode.json"),
    os.path.join(home, ".config", "opencode", "opencode.json"),
])
for oc_path in opencode_files:
    if os.path.isfile(oc_path):
        doc = load_json_object(oc_path)
        if doc is not None:
            reasons = []
            if remove_nested_key(doc, ["mcp"], "hyphae"):
                reasons.append("mcp.hyphae")
            if remove_nested_key(doc, ["mcpServers"], "hyphae"):
                reasons.append("mcpServers.hyphae")
            if reasons:
                emit("EDIT", oc_path, "remove " + " + ".join(reasons))
                if mode == "apply":
                    save_json_object(oc_path, doc)

# 8. OpenClaw ~/.openclaw/openclaw.json
openclaw_json = os.path.join(home, ".openclaw", "openclaw.json")
if os.path.isfile(openclaw_json):
    doc = load_json_object(openclaw_json)
    if doc is not None:
        reasons = []
        if remove_nested_key(doc, ["mcp", "servers"], "hyphae"):
            reasons.append("mcp.servers.hyphae")
        if remove_nested_key(doc, ["mcpServers"], "hyphae"):
            reasons.append("mcpServers.hyphae")
        if reasons:
            emit("EDIT", openclaw_json, "remove " + " + ".join(reasons))
            if mode == "apply":
                save_json_object(openclaw_json, doc)

# 9. Native Herdr App keys.json & read-only layout inspection
herdr_dirs = dedup_paths([
    herdr_app_dir,
    os.path.join(home, ".config", "herdr-app"),
])
for hdir in herdr_dirs:
    keys_path = os.path.join(hdir, "keys.json")
    if os.path.isfile(keys_path):
        doc = load_json_object(keys_path)
        if doc is not None:
            g = doc.get("global")
            if isinstance(g, dict) and g.get("cmd-shift-h") == "mod.open:hyphae-panel":
                del g["cmd-shift-h"]
                emit("EDIT", keys_path, 'remove global."cmd-shift-h" -> "mod.open:hyphae-panel"')
                if mode == "apply":
                    save_json_object(keys_path, doc)

    layouts_dir = os.path.join(hdir, "layouts")
    if os.path.isdir(layouts_dir):
        for entry in sorted(os.listdir(layouts_dir)):
            if not entry.endswith(".json") or ".bak." in entry:
                continue
            lpath = os.path.join(layouts_dir, entry)
            if not os.path.isfile(lpath):
                continue
            try:
                with open(lpath, "r", encoding="utf-8") as fh:
                    ltext = fh.read()
            except Exception:
                continue
            refs = []
            if '"hyphae-pane"' in ltext:
                refs.append("hyphae-pane")
            if '"hyphae-panel"' in ltext:
                refs.append("hyphae-panel")
            if not refs:
                continue
            note_parts = [f"references {', '.join(refs)} (left untouched)"]
            if os.path.islink(lpath):
                try:
                    note_parts.append(f"symlink -> {os.readlink(lpath)}")
                except OSError:
                    note_parts.append("symlink")
            backups = sorted(
                glob.glob(os.path.join(layouts_dir, entry + ".bak.*"))
                + glob.glob(os.path.join(hdir, ".backups", "*", entry))
            )
            if backups:
                note_parts.append(f"backup available: {backups[-1]}")
            emit("LAYOUT_NOTE", lpath, "; ".join(note_parts))
PYEOF
  elif [ "$CONFIG_CLEANER_TOOL" = "node" ]; then
    HYPHAE_CLEAN_MODE="$_rcc_mode" \
    HYPHAE_HOME="$HOME" \
    HYPHAE_CONFIG_HOME="$CONFIG_HOME" \
    HYPHAE_STATE_HOME="$STATE_HOME" \
    HYPHAE_HERDR_APP_DIR="$HERDR_APP_DIR" \
    HYPHAE_OS_NAME="$OS_NAME" \
    node - <<'JSEOF'
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const mode = process.env.HYPHAE_CLEAN_MODE;
const home = process.env.HYPHAE_HOME;
const configHome = process.env.HYPHAE_CONFIG_HOME;
const stateHome = process.env.HYPHAE_STATE_HOME;
const herdrAppDir = process.env.HYPHAE_HERDR_APP_DIR;
const osName = process.env.HYPHAE_OS_NAME;

const HYPHAE_HOOK_NAMES = new Set([
  "hyphae-before-tool",
  "hyphae-after-tool",
  "hyphae-after-agent",
]);

const HYPHAE_HOOK_RE =
  /(?:^|[\s/"'])(?:hyp|hyp-rs)(?:\.exe)?["']?\s+hook\s+(?:claude|codex|cursor|gemini|antigravity|opencode|herdr|t3|openclaw)\b|hyphae\.mjs\s+hook\b|\bhyphae-hook\b|agents-mesh[^\n]*\bhook\b/i;

function emit(kind, targetPath, detail) {
  const sp = String(targetPath).replace(/[\t\n]/g, " ");
  const sd = String(detail).replace(/[\t\n]/g, " ");
  process.stdout.write(`${kind}\t${sp}\t${sd}\n`);
}

function splitShellWords(cmd) {
  const words = [];
  let cur = "";
  let inWord = false;
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i];
    if (inSingle) {
      if (ch === "'") inSingle = false;
      else cur += ch;
      continue;
    }
    if (inDouble) {
      if (ch === '"') inDouble = false;
      else if (ch === "\\" && i + 1 < cmd.length && '"\\$`'.includes(cmd[i + 1])) {
        cur += cmd[++i];
      } else cur += ch;
      continue;
    }
    if (ch === "'") {
      inSingle = true;
      inWord = true;
    } else if (ch === '"') {
      inDouble = true;
      inWord = true;
    } else if (ch === "\\") {
      inWord = true;
      if (i + 1 < cmd.length) cur += cmd[++i];
    } else if (/\s/.test(ch)) {
      if (inWord) {
        words.push(cur);
        cur = "";
        inWord = false;
      }
    } else {
      inWord = true;
      cur += ch;
    }
  }
  if (inWord) words.push(cur);
  return words;
}

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function isFile(p) {
  try {
    return fs.statSync(p).isFile();
  } catch {
    return false;
  }
}

function isDir(p) {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
}

function isHyphaeStatuslineCommand(cmd) {
  if (typeof cmd !== "string" || !cmd.trim()) return false;
  const words = splitShellWords(cmd);
  if (words.length < 2 || words[1] !== "statusline") return false;
  const binName = path.basename(words[0]).toLowerCase();
  if (["hyp", "hyp.exe", "hyp-rs", "hyp-rs.exe"].includes(binName)) return true;
  return words.includes("--harness");
}

function isHyphaeStatuslineValue(val) {
  return isPlainObject(val) && isHyphaeStatuslineCommand(val.command);
}

function parseChainFile(cmd) {
  if (typeof cmd !== "string") return null;
  const words = splitShellWords(cmd);
  for (let i = 0; i < words.length; i++) {
    const w = words[i];
    if (w === "--chain-file") {
      return i + 1 < words.length && words[i + 1] ? words[i + 1] : null;
    }
    if (w.startsWith("--chain-file=")) {
      const rest = w.slice("--chain-file=".length);
      return rest || null;
    }
  }
  return null;
}

function findChainBackup(harness, cmd) {
  const filename = `${harness}-statusline-chain.json`;
  const candidates = [];
  const ref = parseChainFile(cmd);
  if (ref) candidates.push(ref);
  for (const base of [
    path.join(configHome, "hyphae"),
    path.join(stateHome, "hyphae"),
    path.join(home, ".config", "hyphae"),
    path.join(home, ".local", "state", "hyphae"),
  ]) {
    const cand = path.join(base, filename);
    if (!candidates.includes(cand)) candidates.push(cand);
  }
  for (const cand of candidates) {
    if (!isFile(cand)) continue;
    try {
      const parsed = JSON.parse(fs.readFileSync(cand, "utf8"));
      if (parsed !== null && parsed !== undefined) return [cand, parsed];
    } catch {
      continue;
    }
  }
  return [null, null];
}

function isHyphaeHookCommand(cmd) {
  if (typeof cmd !== "string" || !cmd.trim()) return false;
  const words = splitShellWords(cmd);
  if (words.length >= 2) {
    const binName = path.basename(words[0]).toLowerCase();
    if (["hyp", "hyp.exe", "hyp-rs", "hyp-rs.exe"].includes(binName) && words[1] === "hook") {
      return true;
    }
  }
  return HYPHAE_HOOK_RE.test(cmd);
}

function isHyphaeHookLeaf(entry) {
  if (!isPlainObject(entry)) return false;
  if (isHyphaeHookCommand(entry.command)) return true;
  if (HYPHAE_HOOK_NAMES.has(entry.name)) return true;
  return false;
}

function cleanHooksObject(doc) {
  if (!isPlainObject(doc.hooks)) return 0;
  const hooks = doc.hooks;
  let totalRemoved = 0;
  for (const eventName of Object.keys(hooks)) {
    const eventVal = hooks[eventName];
    if (!Array.isArray(eventVal)) continue;
    let eventRemoved = 0;
    const nextList = [];
    for (const item of eventVal) {
      if (isPlainObject(item) && Array.isArray(item.hooks)) {
        const keptSub = item.hooks.filter((h) => !isHyphaeHookLeaf(h));
        const diff = item.hooks.length - keptSub.length;
        if (diff > 0) {
          eventRemoved += diff;
          if (keptSub.length > 0) {
            nextList.push({ ...item, hooks: keptSub });
          }
        } else {
          nextList.push(item);
        }
      } else if (isHyphaeHookLeaf(item)) {
        eventRemoved += 1;
      } else {
        nextList.push(item);
      }
    }
    if (eventRemoved > 0) {
      totalRemoved += eventRemoved;
      if (nextList.length > 0) hooks[eventName] = nextList;
      else delete hooks[eventName];
    }
  }
  if (totalRemoved > 0 && Object.keys(hooks).length === 0) {
    delete doc.hooks;
  }
  return totalRemoved;
}

function removeNestedKey(doc, parents, key) {
  const chain = [];
  let cur = doc;
  for (const p of parents) {
    if (!isPlainObject(cur) || !isPlainObject(cur[p])) return false;
    chain.push([cur, p]);
    cur = cur[p];
  }
  if (!isPlainObject(cur) || !Object.prototype.hasOwnProperty.call(cur, key)) return false;
  delete cur[key];
  for (let i = chain.length - 1; i >= 0; i--) {
    const [parentObj, parentKey] = chain[i];
    if (isPlainObject(parentObj[parentKey]) && Object.keys(parentObj[parentKey]).length === 0) {
      delete parentObj[parentKey];
    } else {
      break;
    }
  }
  return true;
}

function atomicWriteText(targetPath, text) {
  let target = targetPath;
  try {
    if (fs.lstatSync(targetPath).isSymbolicLink()) {
      target = fs.realpathSync(targetPath);
    }
  } catch {}
  const origMode = fs.statSync(target).mode & 0o7777;
  const parent = path.dirname(target) || ".";
  const tmpPath = path.join(
    parent,
    `.hyp-uninstall-${process.pid}-${crypto.randomBytes(6).toString("hex")}.tmp`
  );
  try {
    const fd = fs.openSync(tmpPath, "wx", origMode);
    try {
      fs.writeFileSync(fd, text, "utf8");
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.chmodSync(tmpPath, origMode);
    fs.renameSync(tmpPath, target);
  } catch (err) {
    try {
      fs.unlinkSync(tmpPath);
    } catch {}
    throw err;
  }
}

function loadJsonObject(p) {
  try {
    const data = JSON.parse(fs.readFileSync(p, "utf8"));
    if (!isPlainObject(data)) {
      emit("WARN", p, "skipped non-object JSON root");
      return null;
    }
    return data;
  } catch (err) {
    emit("WARN", p, `skipped invalid JSON (${err.message})`);
    return null;
  }
}

function saveJsonObject(p, doc) {
  atomicWriteText(p, JSON.stringify(doc, null, 2) + "\n");
}

function processStatuslineInDoc(doc, harness, p) {
  const sl = doc.statusLine;
  if (sl === null || sl === undefined || !isHyphaeStatuslineValue(sl)) return false;
  const [chainPath, original] = findChainBackup(harness, sl.command);
  if (chainPath !== null) {
    doc.statusLine = original;
    emit("STATUSLINE", p, `restore original ${harness} statusLine from ${chainPath}`);
  } else {
    delete doc.statusLine;
    emit("STATUSLINE", p, `remove Hyphae ${harness} statusLine`);
  }
  return true;
}

function dedupPaths(list) {
  const seen = new Set();
  const out = [];
  for (const p of list) {
    const norm = path.normalize(p);
    if (!seen.has(norm)) {
      seen.add(norm);
      out.push(p);
    }
  }
  return out;
}

// 1. Claude Code ~/.claude/settings.json
const claudeSettings = path.join(home, ".claude", "settings.json");
if (isFile(claudeSettings)) {
  const doc = loadJsonObject(claudeSettings);
  if (doc) {
    const slChanged = processStatuslineInDoc(doc, "claude", claudeSettings);
    const hooksRemoved = cleanHooksObject(doc);
    if (hooksRemoved > 0) {
      emit("EDIT", claudeSettings, `remove ${hooksRemoved} Hyphae hook entry/entries`);
    }
    if (mode === "apply" && (slChanged || hooksRemoved > 0)) {
      saveJsonObject(claudeSettings, doc);
    }
  }
}

// 2. Antigravity CLI ~/.gemini/antigravity-cli/settings.json
const agySettings = path.join(home, ".gemini", "antigravity-cli", "settings.json");
if (isFile(agySettings)) {
  const doc = loadJsonObject(agySettings);
  if (doc) {
    const slChanged = processStatuslineInDoc(doc, "antigravity", agySettings);
    if (mode === "apply" && slChanged) saveJsonObject(agySettings, doc);
  }
}

// 3. Claude CLI & Claude Desktop MCP configs
const claudeMcpFiles = [path.join(home, ".claude.json")];
if (osName === "Darwin") {
  claudeMcpFiles.push(
    path.join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json")
  );
}
claudeMcpFiles.push(path.join(configHome, "Claude", "claude_desktop_config.json"));
claudeMcpFiles.push(path.join(home, ".config", "Claude", "claude_desktop_config.json"));
for (const p of dedupPaths(claudeMcpFiles)) {
  if (!isFile(p)) continue;
  const doc = loadJsonObject(p);
  if (doc && removeNestedKey(doc, ["mcpServers"], "hyphae")) {
    emit("EDIT", p, "remove mcpServers.hyphae");
    if (mode === "apply") saveJsonObject(p, doc);
  }
}

// 4. Gemini CLI ~/.gemini/settings.json
const geminiSettings = path.join(home, ".gemini", "settings.json");
if (isFile(geminiSettings)) {
  const doc = loadJsonObject(geminiSettings);
  if (doc) {
    const reasons = [];
    if (removeNestedKey(doc, ["mcpServers"], "hyphae")) reasons.push("mcpServers.hyphae");
    const hooksRemoved = cleanHooksObject(doc);
    if (hooksRemoved > 0) reasons.push(`${hooksRemoved} Hyphae hook entry/entries`);
    if (reasons.length > 0) {
      emit("EDIT", geminiSettings, "remove " + reasons.join(" + "));
      if (mode === "apply") saveJsonObject(geminiSettings, doc);
    }
  }
}

// 5. Cursor mcp.json & hooks.json
const cursorMcp = path.join(home, ".cursor", "mcp.json");
if (isFile(cursorMcp)) {
  const doc = loadJsonObject(cursorMcp);
  if (doc && removeNestedKey(doc, ["mcpServers"], "hyphae")) {
    emit("EDIT", cursorMcp, "remove mcpServers.hyphae");
    if (mode === "apply") saveJsonObject(cursorMcp, doc);
  }
}
const cursorHooks = path.join(home, ".cursor", "hooks.json");
if (isFile(cursorHooks)) {
  const doc = loadJsonObject(cursorHooks);
  if (doc) {
    const hooksRemoved = cleanHooksObject(doc);
    if (hooksRemoved > 0) {
      emit("EDIT", cursorHooks, `remove ${hooksRemoved} Hyphae hook entry/entries`);
      if (mode === "apply") saveJsonObject(cursorHooks, doc);
    }
  }
}

// 6. Codex hooks.json & config.toml
const codexHooks = path.join(home, ".codex", "hooks.json");
if (isFile(codexHooks)) {
  const doc = loadJsonObject(codexHooks);
  if (doc) {
    const hooksRemoved = cleanHooksObject(doc);
    if (hooksRemoved > 0) {
      emit("EDIT", codexHooks, `remove ${hooksRemoved} Hyphae hook entry/entries`);
      if (mode === "apply") saveJsonObject(codexHooks, doc);
    }
  }
}

function isCodexHyphaeHeader(line) {
  const trimmed = line.trim();
  if (!trimmed.startsWith("[") || trimmed.startsWith("[[")) return false;
  const closeIdx = trimmed.indexOf("]");
  if (closeIdx === -1) return false;
  const trailing = trimmed.slice(closeIdx + 1).trim();
  if (trailing && !trailing.startsWith("#")) return false;
  const inner = trimmed.slice(1, closeIdx).replace(/\s+/g, "");
  return (
    inner === "mcp_servers.hyphae" ||
    inner === 'mcp_servers."hyphae"' ||
    inner === "mcp_servers.'hyphae'" ||
    inner.startsWith("mcp_servers.hyphae.") ||
    inner.startsWith('mcp_servers."hyphae".') ||
    inner.startsWith("mcp_servers.'hyphae'.")
  );
}

function cleanCodexToml(raw) {
  const lines = raw.replace(/\r\n/g, "\n").split("\n");
  if (lines.length > 0 && lines[lines.length - 1] === "") lines.pop();
  const kept = [];
  let removedManaged = false;
  let removedSection = false;
  let inManaged = false;
  let inSection = false;
  let justRemoved = false;

  for (const line of lines) {
    const trimmed = line.trim();
    if (inManaged) {
      if (trimmed === "# <<< hyphae <<<") {
        inManaged = false;
        justRemoved = true;
      }
      continue;
    }
    if (trimmed === "# >>> hyphae >>>") {
      inManaged = true;
      removedManaged = true;
      continue;
    }
    if (inSection) {
      if (trimmed.startsWith("[")) {
        inSection = false;
        justRemoved = true;
      } else {
        continue;
      }
    }
    if (isCodexHyphaeHeader(line)) {
      inSection = true;
      removedSection = true;
      continue;
    }
    if (justRemoved && trimmed === "") {
      if (kept.length === 0 || kept[kept.length - 1].trim() === "") continue;
    }
    justRemoved = false;
    kept.push(line);
  }
  if (!removedManaged && !removedSection) return [raw, []];
  while (kept.length > 0 && kept[kept.length - 1].trim() === "") kept.pop();
  while (kept.length > 0 && kept[0].trim() === "") kept.shift();
  const nextText = kept.length > 0 ? kept.join("\n") + "\n" : "";
  const reasons = [];
  if (removedManaged) reasons.push("# >>> hyphae >>> managed block");
  if (removedSection) reasons.push("[mcp_servers.hyphae] section");
  return [nextText, reasons];
}

const codexToml = path.join(home, ".codex", "config.toml");
if (isFile(codexToml)) {
  try {
    const rawToml = fs.readFileSync(codexToml, "utf8");
    const [nextToml, reasons] = cleanCodexToml(rawToml);
    if (reasons.length > 0) {
      emit("EDIT", codexToml, "remove " + reasons.join(" + "));
      if (mode === "apply") atomicWriteText(codexToml, nextToml);
    }
  } catch (err) {
    emit("WARN", codexToml, `skipped unreadable TOML (${err.message})`);
  }
}

// 7. OpenCode opencode.json
for (const ocPath of dedupPaths([
  path.join(configHome, "opencode", "opencode.json"),
  path.join(home, ".config", "opencode", "opencode.json"),
])) {
  if (!isFile(ocPath)) continue;
  const doc = loadJsonObject(ocPath);
  if (doc) {
    const reasons = [];
    if (removeNestedKey(doc, ["mcp"], "hyphae")) reasons.push("mcp.hyphae");
    if (removeNestedKey(doc, ["mcpServers"], "hyphae")) reasons.push("mcpServers.hyphae");
    if (reasons.length > 0) {
      emit("EDIT", ocPath, "remove " + reasons.join(" + "));
      if (mode === "apply") saveJsonObject(ocPath, doc);
    }
  }
}

// 8. OpenClaw openclaw.json
const openclawJson = path.join(home, ".openclaw", "openclaw.json");
if (isFile(openclawJson)) {
  const doc = loadJsonObject(openclawJson);
  if (doc) {
    const reasons = [];
    if (removeNestedKey(doc, ["mcp", "servers"], "hyphae")) reasons.push("mcp.servers.hyphae");
    if (removeNestedKey(doc, ["mcpServers"], "hyphae")) reasons.push("mcpServers.hyphae");
    if (reasons.length > 0) {
      emit("EDIT", openclawJson, "remove " + reasons.join(" + "));
      if (mode === "apply") saveJsonObject(openclawJson, doc);
    }
  }
}

// 9. Native Herdr App keys.json & read-only layout inspection
for (const hdir of dedupPaths([herdrAppDir, path.join(home, ".config", "herdr-app")])) {
  const keysPath = path.join(hdir, "keys.json");
  if (isFile(keysPath)) {
    const doc = loadJsonObject(keysPath);
    if (doc && isPlainObject(doc.global) && doc.global["cmd-shift-h"] === "mod.open:hyphae-panel") {
      delete doc.global["cmd-shift-h"];
      emit("EDIT", keysPath, 'remove global."cmd-shift-h" -> "mod.open:hyphae-panel"');
      if (mode === "apply") saveJsonObject(keysPath, doc);
    }
  }

  const layoutsDir = path.join(hdir, "layouts");
  if (isDir(layoutsDir)) {
    const entries = fs.readdirSync(layoutsDir).sort();
    for (const entry of entries) {
      if (!entry.endsWith(".json") || entry.includes(".bak.")) continue;
      const lpath = path.join(layoutsDir, entry);
      if (!isFile(lpath)) continue;
      let ltext = "";
      try {
        ltext = fs.readFileSync(lpath, "utf8");
      } catch {
        continue;
      }
      const refs = [];
      if (ltext.includes('"hyphae-pane"')) refs.push("hyphae-pane");
      if (ltext.includes('"hyphae-panel"')) refs.push("hyphae-panel");
      if (refs.length === 0) continue;
      const parts = [`references ${refs.join(", ")} (left untouched)`];
      try {
        if (fs.lstatSync(lpath).isSymbolicLink()) {
          parts.push(`symlink -> ${fs.readlinkSync(lpath)}`);
        }
      } catch {}
      const backups = [];
      for (const b of entries) {
        if (b.startsWith(`${entry}.bak.`)) backups.push(path.join(layoutsDir, b));
      }
      const bRoot = path.join(hdir, ".backups");
      if (isDir(bRoot)) {
        for (const tsDir of fs.readdirSync(bRoot).sort()) {
          const cand = path.join(bRoot, tsDir, entry);
          if (isFile(cand)) backups.push(cand);
        }
      }
      if (backups.length > 0) {
        parts.push(`backup available: ${backups[backups.length - 1]}`);
      }
      emit("LAYOUT_NOTE", lpath, parts.join("; "));
    }
  }
}
JSEOF
  fi
}

# ---------------------------------------------------------------------------
# 1. Discover targets to clean (read-only)
# ---------------------------------------------------------------------------

DAEMON_PIDS=""
if [ "$IS_REAL_HOME" -eq 1 ]; then
  DAEMON_PIDS="$(
    ps -eo pid=,args= 2>/dev/null | awk -v self_pid="$$" -v parent_pid="${PPID:-0}" '
      {
        pid = $1
        sub(/^[[:space:]]*[0-9]+[[:space:]]+/, "", $0)
        if (pid == self_pid || pid == parent_pid) next
        if ($0 ~ /uninstall\.sh|reset-local\.sh/) next
        if ($0 ~ /(^|\/)(hyp|hyp-rs)[[:space:]]+(daemon|node[[:space:]]+start)([[:space:]]|$)/ || $0 ~ /hyphae\.mjs[[:space:]]+(daemon|node)([[:space:]]|$)/) {
          print pid ":" $0
        }
      }
    ' || true
  )"
fi

LAUNCH_AGENTS=""
LAUNCH_PLISTS=""
SYSTEMD_UNITS=""
if [ "$OS_NAME" = "Darwin" ]; then
  if [ "$IS_REAL_HOME" -eq 1 ] && command -v launchctl >/dev/null 2>&1; then
    LAUNCH_AGENTS="$(launchctl list 2>/dev/null | awk '{print $3}' | grep -iE 'hyphae|t3-mesh|agents-mesh' || true)"
  fi
  if [ -d "$HOME/Library/LaunchAgents" ]; then
    LAUNCH_PLISTS="$(find "$HOME/Library/LaunchAgents" -maxdepth 1 \( -type f -o -type l \) \( -iname '*hyphae*' -o -iname '*t3-mesh*' -o -iname '*agents-mesh*' \) 2>/dev/null | sort || true)"
  fi
elif [ "$OS_NAME" = "Linux" ]; then
  for _sd_dir in "$CONFIG_HOME/systemd/user" "$HOME/.config/systemd/user"; do
    if [ -d "$_sd_dir" ]; then
      _sd_found="$(find "$_sd_dir" -maxdepth 1 \( -type f -o -type l \) \( -iname '*hyphae*' -o -iname '*agents-mesh*' \) 2>/dev/null | sort || true)"
      if [ -n "$_sd_found" ]; then
        while IFS= read -r _unit; do
          [ -n "$_unit" ] || continue
          SYSTEMD_UNITS="$(list_append_unique "$SYSTEMD_UNITS" "$_unit")"
        done <<EOF
$_sd_found
EOF
      fi
    fi
  done
fi

STATUSLINE_PLANS=""
CONFIG_EDIT_PLANS=""
LAYOUT_NOTES=""
CLEANER_WARNINGS=""
if [ "$KEEP_HARNESSES" -eq 0 ]; then
  if [ -n "$CONFIG_CLEANER_TOOL" ]; then
    _plan_raw="$(run_config_cleaner plan || true)"
    if [ -n "$_plan_raw" ]; then
      _tab="$(printf '\t')"
      while IFS="$_tab" read -r _kind _path _detail; do
        case "$_kind" in
          STATUSLINE)
            STATUSLINE_PLANS="$(list_append_unique "$STATUSLINE_PLANS" "${_path}: ${_detail}")"
            ;;
          EDIT)
            CONFIG_EDIT_PLANS="$(list_append_unique "$CONFIG_EDIT_PLANS" "${_path}: ${_detail}")"
            ;;
          LAYOUT_NOTE)
            LAYOUT_NOTES="$(list_append_unique "$LAYOUT_NOTES" "${_path}: ${_detail}")"
            ;;
          WARN)
            CLEANER_WARNINGS="$(list_append_unique "$CLEANER_WARNINGS" "${_path}: ${_detail}")"
            ;;
        esac
      done <<EOF
$_plan_raw
EOF
    fi
  else
    CLEANER_WARNINGS="$(list_append_unique "$CLEANER_WARNINGS" "neither python3 nor node found; skipped surgical edits to shared harness JSON/TOML configs")"
  fi
fi

STANDALONE_HARNESS_PATHS=""
SKILL_DIRS_TO_REMOVE=""
if [ "$KEEP_HARNESSES" -eq 0 ]; then
  for _p in \
    "$HOME/.claude/commands/hyphae.md" \
    "$HOME/.claude/commands/hyphae-subs.md" \
    "$HOME/.claude/commands/hyphae-focus.md" \
    "$HOME/.claude/commands/hyphae-mute.md" \
    "$HOME/.gemini/config/plugins/hyphae" \
    "$CONFIG_HOME/opencode/plugins/hyphae.ts" \
    "$HOME/.config/opencode/plugins/hyphae.ts" \
    "$CONFIG_HOME/herdr/hyphae.json" \
    "$HOME/.config/herdr/hyphae.json" \
    "$HOME/.t3/hyphae.json" \
    "$HERDR_APP_DIR/mods/hyphae-pane" \
    "$HERDR_APP_DIR/mods/hyphae-panel" \
    "$HOME/.config/herdr-app/mods/hyphae-pane" \
    "$HOME/.config/herdr-app/mods/hyphae-panel"
  do
    if [ -e "$_p" ] || [ -L "$_p" ]; then
      STANDALONE_HARNESS_PATHS="$(list_append_unique "$STANDALONE_HARNESS_PATHS" "$_p")"
    fi
  done

  for _skill_root in \
    "$HOME/.claude/skills" \
    "$HOME/.codex/skills" \
    "$HOME/.agents/skills" \
    "$HOME/.gemini/config/skills" \
    "$HOME/.gemini/skills" \
    "$CONFIG_HOME/opencode/skills" \
    "$HOME/.config/opencode/skills" \
    "$HOME/.cursor/skills" \
    "$HOME/.openclaw/skills" \
    "$CONFIG_HOME/herdr/skills" \
    "$HOME/.config/herdr/skills" \
    "$HOME/.t3/skills"
  do
    for _skill_name in hyphae hyphae-setup hyphae-schedule hyphae-panel; do
      _s="${_skill_root}/${_skill_name}"
      if [ -e "$_s" ] || [ -L "$_s" ]; then
        SKILL_DIRS_TO_REMOVE="$(list_append_unique "$SKILL_DIRS_TO_REMOVE" "$_s")"
      fi
    done
  done
fi

DIRS_TO_REMOVE=""
if [ "$KEEP_STATE" -eq 0 ]; then
  for _d in \
    "$CONFIG_HOME/hyphae" \
    "$CONFIG_HOME/agents-mesh" \
    "$STATE_HOME/hyphae" \
    "$HOME/.local/share/hyphae"
  do
    if [ -e "$_d" ] || [ -L "$_d" ]; then
      DIRS_TO_REMOVE="$(list_append_unique "$DIRS_TO_REMOVE" "$_d")"
    fi
  done
fi

KEYCHAIN_ACCOUNTS=""
SECRET_SERVICE_ACCOUNTS=""
if [ "$KEEP_KEYCHAIN" -eq 0 ] && [ "$IS_REAL_HOME" -eq 1 ]; then
  if [ "$OS_NAME" = "Darwin" ] && command -v security >/dev/null 2>&1; then
    KEYCHAIN_ACCOUNTS="$(
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
    )"
  elif [ "$OS_NAME" = "Linux" ] && command -v secret-tool >/dev/null 2>&1; then
    # Extract account attribute names ONLY — never print secret values.
    SECRET_SERVICE_ACCOUNTS="$(
      secret-tool search --all service hyphae 2>/dev/null | awk '
        /^attribute\.account = / {
          sub(/^attribute\.account = /, "", $0)
          if ($0 != "") print $0
        }
      ' | sort -u || true
    )"
  fi
fi

BINS_TO_REMOVE=""
if [ "$KEEP_BINARY" -eq 0 ]; then
  for _b in "$INSTALL_DIR/hyp" "$INSTALL_DIR/hyp.prev" "$INSTALL_DIR/hyp-rs"; do
    if [ -e "$_b" ] || [ -L "$_b" ]; then
      BINS_TO_REMOVE="$(list_append_unique "$BINS_TO_REMOVE" "$_b")"
    fi
  done
fi

# ---------------------------------------------------------------------------
# 2. Print scannable preview plan
# ---------------------------------------------------------------------------

C_DAEMONS="$(list_count "$DAEMON_PIDS")"
C_LAUNCH_AGENTS="$(list_count "$LAUNCH_AGENTS")"
C_LAUNCH_PLISTS="$(list_count "$LAUNCH_PLISTS")"
C_SYSTEMD="$(list_count "$SYSTEMD_UNITS")"
C_STATUSLINES="$(list_count "$STATUSLINE_PLANS")"
C_CONFIG_EDITS="$(list_count "$CONFIG_EDIT_PLANS")"
C_STANDALONE="$(list_count "$STANDALONE_HARNESS_PATHS")"
C_SKILLS="$(list_count "$SKILL_DIRS_TO_REMOVE")"
C_DIRS="$(list_count "$DIRS_TO_REMOVE")"
C_KEYCHAIN="$(list_count "$KEYCHAIN_ACCOUNTS")"
C_SECRET_SVC="$(list_count "$SECRET_SERVICE_ACCOUNTS")"
C_BINS="$(list_count "$BINS_TO_REMOVE")"

TOTAL=$((
  C_DAEMONS
  + C_LAUNCH_AGENTS
  + C_LAUNCH_PLISTS
  + C_SYSTEMD
  + C_STATUSLINES
  + C_CONFIG_EDITS
  + C_STANDALONE
  + C_SKILLS
  + C_DIRS
  + C_KEYCHAIN
  + C_SECRET_SVC
  + C_BINS
))

printf 'Hyphae uninstall plan (HOME=%s)\n' "$HOME"
printf '==================================================\n'

if [ "$TOTAL" -eq 0 ]; then
  printf 'Already clean — nothing to remove.\n'
  if [ "$KEEP_BINARY" -eq 1 ] && [ -e "$INSTALL_DIR/hyp" ]; then
    printf 'Note: kept binary at %s (omit --keep-binary to remove it too).\n' "$INSTALL_DIR/hyp"
  fi
  if [ -n "$LAYOUT_NOTES" ]; then
    printf '\nHerdr layout notes (not modified):\n'
    printf '%s\n' "$LAYOUT_NOTES" | while IFS= read -r _note; do
      [ -n "$_note" ] && printf '  - %s\n' "$_note"
    done
  fi
  exit 0
fi

if [ "$C_DAEMONS" -gt 0 ]; then
  printf '\n1. Running daemons to stop (%s):\n' "$C_DAEMONS"
  printf '%s\n' "$DAEMON_PIDS" | while IFS= read -r _entry; do
    [ -n "$_entry" ] && printf '  - PID %s: %s\n' "${_entry%%:*}" "${_entry#*:}"
  done
fi

if [ "$C_LAUNCH_AGENTS" -gt 0 ] || [ "$C_LAUNCH_PLISTS" -gt 0 ]; then
  printf '\n1. macOS LaunchAgents to unload/remove:\n'
  if [ -n "$LAUNCH_AGENTS" ]; then
    printf '%s\n' "$LAUNCH_AGENTS" | while IFS= read -r _label; do
      [ -n "$_label" ] && printf '  - service: %s\n' "$_label"
    done
  fi
  if [ -n "$LAUNCH_PLISTS" ]; then
    printf '%s\n' "$LAUNCH_PLISTS" | while IFS= read -r _plist; do
      [ -n "$_plist" ] && printf '  - plist:   %s\n' "$_plist"
    done
  fi
fi

if [ "$C_SYSTEMD" -gt 0 ]; then
  printf '\n1. Linux systemd user units to stop/remove (%s):\n' "$C_SYSTEMD"
  printf '%s\n' "$SYSTEMD_UNITS" | while IFS= read -r _unit; do
    [ -n "$_unit" ] && printf '  - %s\n' "$_unit"
  done
fi

if [ "$C_STATUSLINES" -gt 0 ]; then
  printf '\n2. StatusLines to restore/remove (%s):\n' "$C_STATUSLINES"
  printf '%s\n' "$STATUSLINE_PLANS" | while IFS= read -r _sl; do
    [ -n "$_sl" ] && printf '  - %s\n' "$_sl"
  done
fi

if [ "$C_CONFIG_EDITS" -gt 0 ]; then
  printf '\n3. Shared harness configs to edit surgically (%s):\n' "$C_CONFIG_EDITS"
  printf '%s\n' "$CONFIG_EDIT_PLANS" | while IFS= read -r _ed; do
    [ -n "$_ed" ] && printf '  - %s\n' "$_ed"
  done
fi

if [ "$C_STANDALONE" -gt 0 ]; then
  printf '\n4. Standalone Hyphae plugins, commands & Herdr mods to remove (%s):\n' "$C_STANDALONE"
  printf '%s\n' "$STANDALONE_HARNESS_PATHS" | while IFS= read -r _sp; do
    [ -n "$_sp" ] && printf '  - %s\n' "$_sp"
  done
fi

if [ "$C_SKILLS" -gt 0 ]; then
  printf '\n4. Installed Hyphae skill folders to remove (%s):\n' "$C_SKILLS"
  printf '%s\n' "$SKILL_DIRS_TO_REMOVE" | while IFS= read -r _sk; do
    [ -n "$_sk" ] && printf '  - %s\n' "$_sk"
  done
fi

if [ "$C_DIRS" -gt 0 ]; then
  printf '\n5. Config / state directories to remove (%s):\n' "$C_DIRS"
  printf '%s\n' "$DIRS_TO_REMOVE" | while IFS= read -r _dir; do
    [ -n "$_dir" ] && printf '  - %s\n' "$_dir"
  done
elif [ "$KEEP_STATE" -eq 1 ]; then
  printf '\n5. Keeping state directories (--keep-state)\n'
fi

if [ "$C_KEYCHAIN" -gt 0 ]; then
  printf '\n6. macOS Keychain (service="hyphae") items to delete (%s):\n' "$C_KEYCHAIN"
  printf '%s\n' "$KEYCHAIN_ACCOUNTS" | while IFS= read -r _acct; do
    [ -n "$_acct" ] && printf '  - %s\n' "$_acct"
  done
fi

if [ "$C_SECRET_SVC" -gt 0 ]; then
  printf '\n6. Linux Secret Service (service="hyphae") items to delete (%s):\n' "$C_SECRET_SVC"
  printf '%s\n' "$SECRET_SERVICE_ACCOUNTS" | while IFS= read -r _acct; do
    [ -n "$_acct" ] && printf '  - %s\n' "$_acct"
  done
fi

if [ "$C_BINS" -gt 0 ]; then
  printf '\n7. Binaries to remove (%s):\n' "$C_BINS"
  printf '%s\n' "$BINS_TO_REMOVE" | while IFS= read -r _bin; do
    [ -n "$_bin" ] && printf '  - %s\n' "$_bin"
  done
elif [ "$KEEP_BINARY" -eq 1 ] && { [ -e "$INSTALL_DIR/hyp" ] || [ -L "$INSTALL_DIR/hyp" ]; }; then
  printf '\n7. Keeping binary: %s (--keep-binary)\n' "$INSTALL_DIR/hyp"
fi

if [ -n "$LAYOUT_NOTES" ]; then
  printf '\nHerdr layout notes (will NOT be modified):\n'
  printf '%s\n' "$LAYOUT_NOTES" | while IFS= read -r _note; do
    [ -n "$_note" ] && printf '  - %s\n' "$_note"
  done
fi

if [ -n "$CLEANER_WARNINGS" ]; then
  printf '\nWarnings:\n'
  printf '%s\n' "$CLEANER_WARNINGS" | while IFS= read -r _warn; do
    [ -n "$_warn" ] && printf '  - %s\n' "$_warn"
  done
fi

if [ "$DRY_RUN" -eq 1 ]; then
  printf '\n[dry-run] No files, processes, configs, or keychain entries were modified.\n'
  exit 0
fi

if [ "$ASSUME_YES" -eq 0 ]; then
  if [ -t 0 ]; then
    printf '\nProceed with uninstall? [y/N]: '
    IFS= read -r _reply || _reply=""
  elif [ -t 1 ] && [ -r /dev/tty ] && [ -z "${CI:-}" ]; then
    printf '\nProceed with uninstall? [y/N]: '
    IFS= read -r _reply </dev/tty || _reply=""
  else
    printf '\nerror: non-interactive stdin; pass --yes to confirm or --dry-run to preview\n' >&2
    exit 2
  fi
  case "$_reply" in
    y|Y|yes|YES)
      ;;
    *)
      printf 'Aborted.\n'
      exit 0
      ;;
  esac
fi

# ---------------------------------------------------------------------------
# 3. Execute cleanup in exact safe order (statusLine restore BEFORE state wipe)
# ---------------------------------------------------------------------------

# Step 1: Stop running Hyphae daemons & unload OS services
if [ -n "$DAEMON_PIDS" ]; then
  printf '%s\n' "$DAEMON_PIDS" | while IFS= read -r _entry; do
    [ -n "$_entry" ] || continue
    _pid="${_entry%%:*}"
    kill -TERM "$_pid" 2>/dev/null || true
  done
fi

if [ "$OS_NAME" = "Darwin" ]; then
  _uid="$(id -u)"
  if [ "$IS_REAL_HOME" -eq 1 ] && [ -n "$LAUNCH_AGENTS" ] && command -v launchctl >/dev/null 2>&1; then
    printf '%s\n' "$LAUNCH_AGENTS" | while IFS= read -r _label; do
      [ -n "$_label" ] && launchctl bootout "gui/${_uid}/${_label}" 2>/dev/null || true
    done
  fi
  if [ -n "$LAUNCH_PLISTS" ]; then
    printf '%s\n' "$LAUNCH_PLISTS" | while IFS= read -r _plist; do
      [ -n "$_plist" ] || continue
      if [ "$IS_REAL_HOME" -eq 1 ] && command -v launchctl >/dev/null 2>&1; then
        launchctl bootout "gui/${_uid}" "$_plist" 2>/dev/null || true
      fi
      rm -f "$_plist"
    done
  fi
elif [ "$OS_NAME" = "Linux" ]; then
  if [ -n "$SYSTEMD_UNITS" ]; then
    printf '%s\n' "$SYSTEMD_UNITS" | while IFS= read -r _unit; do
      [ -n "$_unit" ] || continue
      _name="$(basename "$_unit")"
      if [ "$IS_REAL_HOME" -eq 1 ] && command -v systemctl >/dev/null 2>&1; then
        systemctl --user disable --now "$_name" 2>/dev/null || true
      fi
      rm -f "$_unit"
    done
    if [ "$IS_REAL_HOME" -eq 1 ] && command -v systemctl >/dev/null 2>&1; then
      systemctl --user daemon-reload 2>/dev/null || true
    fi
  fi
fi

# Step 2 & 3: Restore chained statusLines FIRST & surgically clean shared harness configs
# (MUST execute before Step 5 removes $CONFIG_HOME/hyphae chain backups!)
if [ "$KEEP_HARNESSES" -eq 0 ] && [ -n "$CONFIG_CLEANER_TOOL" ]; then
  run_config_cleaner apply >/dev/null
fi

# Step 4: Remove standalone Hyphae plugin/command/mod/config files & skill folders
if [ -n "$STANDALONE_HARNESS_PATHS" ]; then
  printf '%s\n' "$STANDALONE_HARNESS_PATHS" | while IFS= read -r _sp; do
    [ -n "$_sp" ] && rm -rf "$_sp"
  done
fi

if [ -n "$SKILL_DIRS_TO_REMOVE" ]; then
  printf '%s\n' "$SKILL_DIRS_TO_REMOVE" | while IFS= read -r _sk; do
    [ -n "$_sk" ] && rm -rf "$_sk"
  done
fi

# Step 5: Remove state & config directories
if [ -n "$DIRS_TO_REMOVE" ]; then
  printf '%s\n' "$DIRS_TO_REMOVE" | while IFS= read -r _dir; do
    [ -n "$_dir" ] && rm -rf "$_dir"
  done
fi

# Step 6: Remove OS Keychain / Secret Service entries
if [ "$IS_REAL_HOME" -eq 1 ] && [ "$KEEP_KEYCHAIN" -eq 0 ]; then
  if [ -n "$KEYCHAIN_ACCOUNTS" ] && command -v security >/dev/null 2>&1; then
    printf '%s\n' "$KEYCHAIN_ACCOUNTS" | while IFS= read -r _acct; do
      [ -n "$_acct" ] && security delete-generic-password -s hyphae -a "$_acct" >/dev/null 2>&1 || true
    done
  fi
  if [ -n "$SECRET_SERVICE_ACCOUNTS" ] && command -v secret-tool >/dev/null 2>&1; then
    printf '%s\n' "$SECRET_SERVICE_ACCOUNTS" | while IFS= read -r _acct; do
      [ -n "$_acct" ] && secret-tool clear service hyphae account "$_acct" >/dev/null 2>&1 || true
    done
  fi
fi

# Step 7: Remove installed binaries
if [ -n "$BINS_TO_REMOVE" ]; then
  printf '%s\n' "$BINS_TO_REMOVE" | while IFS= read -r _bin; do
    [ -n "$_bin" ] && rm -f "$_bin"
  done
fi

printf '\nHyphae uninstall complete!\n'
if [ -n "$LAYOUT_NOTES" ]; then
  printf '\nReminder — custom Herdr layout(s) still reference Hyphae mods (left untouched):\n'
  printf '%s\n' "$LAYOUT_NOTES" | while IFS= read -r _note; do
    [ -n "$_note" ] && printf '  - %s\n' "$_note"
  done
fi
if [ "$KEEP_BINARY" -eq 0 ]; then
  printf 'Reinstall anytime with:\n'
  printf '  curl -fsSL https://hyphae.to/install.sh | sh\n'
else
  printf 'Kept `hyp` binary. Re-onboard anytime with:\n'
  printf '  hyp onboard\n'
fi
