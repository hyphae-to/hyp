#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";

const files = {
  "kv-view.mjs": [
    "claude-code/hooks/kv-view.mjs",
    "herdr-mod/mods/hyphae-pane/kv-view.js",
    "herdr-mod/mods/hyphae-panel/kv-view.js",
  ],
  "ui-snapshot.mjs": [
    "claude-code/hooks/ui-snapshot.mjs",
    "herdr-mod/mods/hyphae-pane/ui-snapshot.js",
    "herdr-mod/mods/hyphae-panel/ui-snapshot.js",
    "opencode/ui-snapshot.mjs",
  ],
};
const check = process.argv.includes("--check");
for (const [name, targets] of Object.entries(files)) {
  const source = readFileSync(new URL(`../plugins/shared/${name}`, import.meta.url));
  for (const target of targets) {
    const file = new URL(`../plugins/${target}`, import.meta.url);
    if (check) {
      if (!readFileSync(file).equals(source)) {
        console.error(`${target} differs from the shared ${name}. Run node scripts/vendor-ui-modules.mjs.`);
        process.exitCode = 1;
      }
    } else {
      writeFileSync(file, source);
    }
  }
}
