#!/usr/bin/env bash
set -euo pipefail

# Hyphae (hph) one-line installer
# Usage: bash -c "$(curl -fsSL https://raw.githubusercontent.com/bowd/hyphae/main/install.sh)"

REPO="${HYPHAE_REPO:-https://github.com/bowd/hyphae.git}"
INSTALL_DIR="${HYPHAE_HOME:-$HOME/.local/share/hyphae}"
BIN_DIR="${HYPHAE_BIN_DIR:-$HOME/.local/bin}"

echo "Installing Hyphae (hph)..."

if ! command -v node >/dev/null 2>&1; then
  echo "Error: Node.js 24+ is required. Install Node 24+ (https://nodejs.org or mise/nvm) and re-run." >&2
  exit 1
fi

NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
if [ "${NODE_MAJOR:-0}" -lt 24 ]; then
  echo "Error: Node.js 24+ is required (found $(node -v))." >&2
  exit 1
fi

mkdir -p "$(dirname "$INSTALL_DIR")" "$BIN_DIR"

if [ -d "$INSTALL_DIR/.git" ]; then
  echo "Updating existing checkout in $INSTALL_DIR..."
  git -C "$INSTALL_DIR" pull --ff-only
else
  echo "Cloning $REPO into $INSTALL_DIR..."
  git clone --depth 1 "$REPO" "$INSTALL_DIR"
fi

(cd "$INSTALL_DIR" && npm install --no-audit --no-fund && npm run build)

chmod +x "$INSTALL_DIR/bin/hyphae.mjs"
ln -sf "$INSTALL_DIR/bin/hyphae.mjs" "$BIN_DIR/hph"
ln -sf "$INSTALL_DIR/bin/hyphae.mjs" "$BIN_DIR/hyphae"

echo ""
echo "Installed hph -> $BIN_DIR/hph"
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *) echo "Add $BIN_DIR to your PATH:  export PATH=\"$BIN_DIR:\$PATH\"" ;;
esac

if [ -t 0 ] && [ -t 1 ]; then
  exec "$BIN_DIR/hph" onboard
else
  echo "Next: run 'hph onboard' to wire your harnesses, router, and streams."
fi
