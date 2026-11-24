#!/usr/bin/env bash
# Pin t3-mesh to a T3 nightly: check out the matching t3code tag into vendor/t3code,
# install the client packages we build against, and record the pin in t3-pin.json.
# Usage: scripts/update-t3-pin.sh [npm-version|nightly]   (default: the version in t3-pin.json)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENDOR="$ROOT/vendor/t3code"
PIN="$ROOT/t3-pin.json"
PNPM=(npx -y pnpm@11.10.0)

want="${1:-}"
if [[ -z "$want" ]]; then
  want="$(node -p "require('$PIN').npmVersion")"
elif [[ "$want" == "nightly" ]]; then
  want="$(npm view t3 dist-tags.nightly)"
fi
tag="v$want"
commit="$(git ls-remote https://github.com/pingdotgg/t3code "refs/tags/$tag" | cut -f1)"
if [[ -z "$commit" ]]; then
  echo "no t3code tag $tag" >&2
  exit 1
fi

current=""
if [[ -d "$VENDOR/.git" ]]; then current="$(git -C "$VENDOR" rev-parse HEAD)"; fi
if [[ "$current" != "$commit" ]]; then
  rm -rf "$VENDOR"
  git clone -q --depth 1 --branch "$tag" https://github.com/pingdotgg/t3code "$VENDOR"
fi
(cd "$VENDOR" && "${PNPM[@]}" install --frozen-lockfile --ignore-scripts \
  --filter @t3tools/client-runtime... --filter @t3tools/contracts... >/dev/null)

cat > "$PIN" <<EOF
{
  "npmVersion": "$want",
  "tag": "$tag",
  "commit": "$commit"
}
EOF
(cd "$ROOT" && "${PNPM[@]}" install >/dev/null)
echo "pinned t3 $want ($commit)"
