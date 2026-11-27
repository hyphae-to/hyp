#!/bin/sh
# Stage the site and canonical installer scripts for GitHub Pages.
set -eu

repo_root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
destination=${1:?Usage: stage-pages.sh OUTPUT_DIR}

mkdir "$destination"
cp -R "$repo_root/site/." "$destination"
for script in install.sh uninstall.sh install.ps1 uninstall.ps1; do
  cp "$repo_root/scripts/$script" "$destination/$script"
done
