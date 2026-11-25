#!/bin/sh
# Standalone POSIX installer for the Hyphae native Herdr Mod (`hyphae-pane` + `hyphae-panel`).
# Safe by default:
#   - Copies mods into $HERDR_APP_HOME/mods/ (macOS FSEvents hot-reload friendly; --dev-link for symlinks)
#   - Merges `cmd-shift-h -> mod.open:hyphae-panel` into keys.json only if unbound
#   - NEVER edits symlinked layouts without --patch-layout
#   - NEVER clobbers a customized pane header mod without --force
#   - NEVER edits shipped layouts (`main`, `terminals`, `win98`); supports --clone-layout <name>
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
MOD_PKG_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
HERDR_HOME="${HERDR_APP_HOME:-$HOME/.config/herdr-app}"

DEV_LINK=0
PATCH_LAYOUT=0
FORCE=0
CLONE_LAYOUT=""
SKIP_CHECK=0

usage() {
  cat <<'EOF'
Usage: install.sh [options]

Options:
  --herdr-home <dir>      Target Herdr config directory (default: ~/.config/herdr-app)
  --dev-link              Symlink mod directories instead of copying (for contributors)
  --patch-layout          Allow patching an active symlinked layout JSON in place
  --clone-layout <name>   Clone shipped main.json to <name>.json and enable hyphae-pane + hyphae-panel
  --force                 Allow replacing a customized pane.header.content.mod
  --skip-check            Skip running `herdr-app check` after install
  -h, --help              Show this help
EOF
}

while [ $# -gt 0 ]; do
  case "$1" in
    --herdr-home)
      [ $# -ge 2 ] || { echo "error: --herdr-home requires a path" >&2; exit 2; }
      HERDR_HOME="$2"
      shift 2
      ;;
    --dev-link)
      DEV_LINK=1
      shift
      ;;
    --patch-layout)
      PATCH_LAYOUT=1
      shift
      ;;
    --clone-layout)
      [ $# -ge 2 ] || { echo "error: --clone-layout requires a layout name" >&2; exit 2; }
      CLONE_LAYOUT="$2"
      shift 2
      ;;
    --force)
      FORCE=1
      shift
      ;;
    --skip-check)
      SKIP_CHECK=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown option '$1'" >&2
      usage >&2
      exit 2
      ;;
  esac
done

mkdir -p "$HERDR_HOME/mods"

install_mod_dir() {
  mod_name="$1"
  src="$MOD_PKG_DIR/mods/$mod_name"
  dst="$HERDR_HOME/mods/$mod_name"

  if [ ! -d "$src" ]; then
    echo "error: missing mod source directory $src" >&2
    exit 1
  fi

  if [ "$DEV_LINK" -eq 1 ]; then
    rm -rf "$dst"
    ln -s "$src" "$dst"
    echo "OK    linked $mod_name -> $dst"
  else
    rm -rf "$dst"
    mkdir -p "$dst"
    cp -R "$src/." "$dst/"
    echo "OK    installed $mod_name -> $dst"
  fi
}

install_mod_dir "hyphae-pane"
install_mod_dir "hyphae-panel"

# Merge keys.json and optionally handle layout wiring via Node (if present) or Python 3.
HELPER_LANG=""
if command -v node >/dev/null 2>&1; then
  HELPER_LANG="node"
elif command -v python3 >/dev/null 2>&1; then
  HELPER_LANG="python3"
fi

if [ "$HELPER_LANG" = "node" ]; then
  HERDR_HOME="$HERDR_HOME" PATCH_LAYOUT="$PATCH_LAYOUT" FORCE="$FORCE" CLONE_LAYOUT="$CLONE_LAYOUT" node <<'NODE_EOF'
const fs = require("fs");
const path = require("path");

const herdrHome = process.env.HERDR_HOME;
const patchLayout = process.env.PATCH_LAYOUT === "1";
const force = process.env.FORCE === "1";
const cloneLayout = process.env.CLONE_LAYOUT || "";

const keysPath = path.join(herdrHome, "keys.json");
let keys = {};
if (fs.existsSync(keysPath)) {
  keys = JSON.parse(fs.readFileSync(keysPath, "utf8"));
}
if (!keys.global || typeof keys.global !== "object") keys.global = {};
if (!("cmd-shift-h" in keys.global)) {
  keys.global["cmd-shift-h"] = "mod.open:hyphae-panel";
  fs.writeFileSync(keysPath, JSON.stringify(keys, null, 2) + "\n");
  console.log("OK    keys.json: added global cmd-shift-h -> mod.open:hyphae-panel");
} else {
  console.log("OK    keys.json: preserved existing cmd-shift-h binding (" + JSON.stringify(keys.global["cmd-shift-h"]) + ")");
}

const shipped = new Set(["main", "terminals", "win98"]);
const sharedPath = path.join(herdrHome, "shared.json");
let sharedObj = {};
if (fs.existsSync(sharedPath)) {
  try { sharedObj = JSON.parse(fs.readFileSync(sharedPath, "utf8")); } catch {}
}
const activeLayout = typeof sharedObj.layout === "string" ? sharedObj.layout : "main";
const layoutsDir = path.join(herdrHome, "layouts");

function findNode(node, id) {
  if (!node || typeof node !== "object") return null;
  if (node.id === id) return node;
  for (const child of node.children || []) {
    const f = findNode(child, id);
    if (f) return f;
  }
  return null;
}

function findPaneHeader(node) {
  if (!node || typeof node !== "object") return null;
  if (node.content && node.content.tab && node.content.pane && node.content.pane.header) {
    return node.content.pane.header;
  }
  for (const child of node.children || []) {
    const f = findPaneHeader(child);
    if (f) return f;
  }
  return null;
}

function patchTree(tree) {
  let changed = false;
  const header = findPaneHeader(tree);
  if (header && header.content && typeof header.content === "object") {
    const currentMod = header.content.mod;
    if (currentMod && currentMod !== "pane" && currentMod !== "hyphae-pane" && !force) {
      return { status: "skipped_custom_header", currentMod };
    }
    if (currentMod !== "hyphae-pane") {
      header.content.mod = "hyphae-pane";
      changed = true;
    }
  }
  const panelBody = findNode(tree, "panel-body");
  if (panelBody && Array.isArray(panelBody.children)) {
    if (!panelBody.children.some((c) => c && c.id === "hyphae")) {
      panelBody.children.push({
        id: "hyphae",
        type: "block",
        content: { mod: "hyphae-panel" },
      });
      changed = true;
    }
  }
  return { status: changed ? "patched" : "already_configured" };
}

if (cloneLayout) {
  if (!/^[a-zA-Z0-9][a-zA-Z0-9_-]*$/.test(cloneLayout) || shipped.has(cloneLayout)) {
    console.error("error: invalid --clone-layout name: " + cloneLayout);
    process.exit(2);
  }
  const srcLayout = path.join(layoutsDir, "main.json");
  const dstLayout = path.join(layoutsDir, cloneLayout + ".json");
  if (!fs.existsSync(srcLayout)) {
    console.error("error: shipped main.json not found at " + srcLayout);
    process.exit(1);
  }
  const tree = JSON.parse(fs.readFileSync(srcLayout, "utf8"));
  patchTree(tree);
  fs.mkdirSync(layoutsDir, { recursive: true });
  fs.writeFileSync(dstLayout, JSON.stringify(tree, null, 2) + "\n");
  sharedObj.layout = cloneLayout;
  fs.writeFileSync(sharedPath, JSON.stringify(sharedObj, null, 2) + "\n");
  console.log("OK    cloned main.json -> " + dstLayout + " and activated layout '" + cloneLayout + "'");
  process.exit(0);
}

const activePath = path.join(layoutsDir, activeLayout + ".json");
if (shipped.has(activeLayout)) {
  console.log("NOTE  active layout '" + activeLayout + "' is a shipped Herdr layout; left untouched.");
  console.log("      Press cmd-shift-h to open Hyphae floating inspector, or run with --clone-layout herdr-hyphae.");
  process.exit(0);
}

if (!fs.existsSync(activePath)) {
  console.log("NOTE  active layout file not found (" + activePath + "); cmd-shift-h floating inspector is ready.");
  process.exit(0);
}

const stat = fs.lstatSync(activePath);
if (stat.isSymbolicLink() && !patchLayout) {
  console.log("WARN  active layout '" + activeLayout + ".json' is a symlink — skipped editing.");
  console.log("      Snippet to add to your layout JSON:");
  console.log('        1) pane.header.content.mod = "hyphae-pane"');
  console.log('        2) panel-body.children += { "id": "hyphae", "type": "block", "content": { "mod": "hyphae-panel" } }');
  console.log("      Or copy mods/hyphae-pane/{pill.js,shared-client.js,hyphae.svg} into your custom pane mod");
  console.log('      and import { renderHyphaePill } from "./pill.js" (or re-run with --patch-layout).');
  process.exit(0);
}

const tree = JSON.parse(fs.readFileSync(activePath, "utf8"));
const res = patchTree(tree);
if (res.status === "skipped_custom_header") {
  console.log("WARN  active layout uses custom pane header mod '" + res.currentMod + "' — skipped clobbering.");
  console.log("      Copy mods/hyphae-pane/{pill.js,shared-client.js,hyphae.svg} into mods/" + res.currentMod + "/");
  console.log('      and call renderHyphaePill(...) from "./pill.js" (or re-run with --force).');
  process.exit(0);
}

if (res.status === "patched") {
  const ts = new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "Z");
  const backupDir = path.join(herdrHome, ".backups", ts);
  fs.mkdirSync(backupDir, { recursive: true });
  fs.copyFileSync(activePath, path.join(backupDir, activeLayout + ".json"));
  fs.writeFileSync(activePath, JSON.stringify(tree, null, 2) + "\n");
  console.log("OK    backed up and patched layout " + activePath);
} else {
  console.log("OK    layout " + activePath + " already includes Hyphae");
}
NODE_EOF
elif [ "$HELPER_LANG" = "python3" ]; then
  HERDR_HOME="$HERDR_HOME" PATCH_LAYOUT="$PATCH_LAYOUT" FORCE="$FORCE" CLONE_LAYOUT="$CLONE_LAYOUT" python3 - <<'PY_EOF'
import datetime, json, os, re, shutil, sys

herdr_home = os.environ["HERDR_HOME"]
patch_layout = os.environ["PATCH_LAYOUT"] == "1"
force = os.environ["FORCE"] == "1"
clone_layout = os.environ.get("CLONE_LAYOUT", "")

keys_path = os.path.join(herdr_home, "keys.json")
keys = {}
if os.path.exists(keys_path):
    with open(keys_path, "r", encoding="utf-8") as f:
        keys = json.load(f)
if not isinstance(keys.get("global"), dict):
    keys["global"] = {}
if "cmd-shift-h" not in keys["global"]:
    keys["global"]["cmd-shift-h"] = "mod.open:hyphae-panel"
    with open(keys_path, "w", encoding="utf-8") as f:
        json.dump(keys, f, indent=2)
        f.write("\n")
    print("OK    keys.json: added global cmd-shift-h -> mod.open:hyphae-panel")
else:
    print(f"OK    keys.json: preserved existing cmd-shift-h binding ({keys['global']['cmd-shift-h']!r})")

shipped = {"main", "terminals", "win98"}
shared_path = os.path.join(herdr_home, "shared.json")
shared_obj = {}
if os.path.exists(shared_path):
    try:
        with open(shared_path, "r", encoding="utf-8") as f:
            shared_obj = json.load(f)
    except Exception:
        shared_obj = {}
active_layout = shared_obj.get("layout") if isinstance(shared_obj.get("layout"), str) else "main"
layouts_dir = os.path.join(herdr_home, "layouts")

def find_node(node, target_id):
    if not isinstance(node, dict):
        return None
    if node.get("id") == target_id:
        return node
    for child in node.get("children") or []:
        found = find_node(child, target_id)
        if found is not None:
            return found
    return None

def find_pane_header(node):
    if not isinstance(node, dict):
        return None
    content = node.get("content")
    if isinstance(content, dict) and content.get("tab") and isinstance(content.get("pane"), dict):
        hdr = content["pane"].get("header")
        if isinstance(hdr, dict):
            return hdr
    for child in node.get("children") or []:
        found = find_pane_header(child)
        if found is not None:
            return found
    return None

def patch_tree(tree):
    changed = False
    header = find_pane_header(tree)
    if header and isinstance(header.get("content"), dict):
        current_mod = header["content"].get("mod")
        if current_mod and current_mod not in ("pane", "hyphae-pane") and not force:
            return ("skipped_custom_header", current_mod)
        if current_mod != "hyphae-pane":
            header["content"]["mod"] = "hyphae-pane"
            changed = True
    panel_body = find_node(tree, "panel-body")
    if panel_body and isinstance(panel_body.get("children"), list):
        if not any(isinstance(c, dict) and c.get("id") == "hyphae" for c in panel_body["children"]):
            panel_body["children"].append({
                "id": "hyphae",
                "type": "block",
                "content": {"mod": "hyphae-panel"},
            })
            changed = True
    return ("patched" if changed else "already_configured", None)

if clone_layout:
    if not re.match(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$", clone_layout) or clone_layout in shipped:
        print(f"error: invalid --clone-layout name: {clone_layout}", file=sys.stderr)
        sys.exit(2)
    src_layout = os.path.join(layouts_dir, "main.json")
    dst_layout = os.path.join(layouts_dir, f"{clone_layout}.json")
    if not os.path.exists(src_layout):
        print(f"error: shipped main.json not found at {src_layout}", file=sys.stderr)
        sys.exit(1)
    with open(src_layout, "r", encoding="utf-8") as f:
        tree = json.load(f)
    patch_tree(tree)
    os.makedirs(layouts_dir, exist_ok=True)
    with open(dst_layout, "w", encoding="utf-8") as f:
        json.dump(tree, f, indent=2)
        f.write("\n")
    shared_obj["layout"] = clone_layout
    with open(shared_path, "w", encoding="utf-8") as f:
        json.dump(shared_obj, f, indent=2)
        f.write("\n")
    print(f"OK    cloned main.json -> {dst_layout} and activated layout '{clone_layout}'")
    sys.exit(0)

active_path = os.path.join(layouts_dir, f"{active_layout}.json")
if active_layout in shipped:
    print(f"NOTE  active layout '{active_layout}' is a shipped Herdr layout; left untouched.")
    print("      Press cmd-shift-h to open Hyphae floating inspector, or run with --clone-layout herdr-hyphae.")
    sys.exit(0)

if not os.path.exists(active_path):
    print(f"NOTE  active layout file not found ({active_path}); cmd-shift-h floating inspector is ready.")
    sys.exit(0)

if os.path.islink(active_path) and not patch_layout:
    print(f"WARN  active layout '{active_layout}.json' is a symlink — skipped editing.")
    print("      Snippet to add to your layout JSON:")
    print('        1) pane.header.content.mod = "hyphae-pane"')
    print('        2) panel-body.children += { "id": "hyphae", "type": "block", "content": { "mod": "hyphae-panel" } }')
    print("      Or copy mods/hyphae-pane/{pill.js,shared-client.js,hyphae.svg} into your custom pane mod")
    print('      and import { renderHyphaePill } from "./pill.js" (or re-run with --patch-layout).')
    sys.exit(0)

with open(active_path, "r", encoding="utf-8") as f:
    tree = json.load(f)
status, current_mod = patch_tree(tree)
if status == "skipped_custom_header":
    print(f"WARN  active layout uses custom pane header mod '{current_mod}' — skipped clobbering.")
    print(f"      Copy mods/hyphae-pane/{{pill.js,shared-client.js,hyphae.svg}} into mods/{current_mod}/")
    print('      and call renderHyphaePill(...) from "./pill.js" (or re-run with --force).')
    sys.exit(0)

if status == "patched":
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_dir = os.path.join(herdr_home, ".backups", ts)
    os.makedirs(backup_dir, exist_ok=True)
    shutil.copy2(active_path, os.path.join(backup_dir, f"{active_layout}.json"))
    with open(active_path, "w", encoding="utf-8") as f:
        json.dump(tree, f, indent=2)
        f.write("\n")
    print(f"OK    backed up and patched layout {active_path}")
else:
    print(f"OK    layout {active_path} already includes Hyphae")
PY_EOF
else
  echo "WARN  neither node nor python3 found; skipped keys.json and layout patching."
  echo "      Add \"cmd-shift-h\": \"mod.open:hyphae-panel\" under \"global\" in $HERDR_HOME/keys.json."
fi

if [ "$SKIP_CHECK" -eq 0 ] && command -v herdr-app >/dev/null 2>&1; then
  herdr-app check "$HERDR_HOME/mods/hyphae-pane"
  herdr-app check "$HERDR_HOME/mods/hyphae-panel"
fi
