#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";

const source = readFileSync(new URL("../plugins/shared/kv-view.mjs", import.meta.url));
const targets = [
  "claude-code/hooks/kv-view.mjs",
  "herdr-mod/mods/hyphae-pane/kv-view.js",
  "herdr-mod/mods/hyphae-panel/kv-view.js",
];
for (const target of targets) {
  const file = new URL(`../plugins/${target}`, import.meta.url);
  if (process.argv.includes("--check")) {
    if (!readFileSync(file).equals(source)) {
      console.error(`${target} differs from the shared KV view. Run node scripts/vendor-kv-view.mjs.`);
      process.exitCode = 1;
    }
  } else {
    writeFileSync(file, source);
  }
}
