#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";

const registry = new URL("../crates/hyp-cli/src/harness_specs.json", import.meta.url);
const specs = JSON.parse(readFileSync(registry, "utf8"));
const roots = new Set();
for (const spec of specs) {
  for (const root of [spec.setupSkillRoot, spec.runtimeSkillRoot, ...spec.legacySkillRoots]) {
    // The uninstallers already remove Antigravity's entire Hyphae plugin directory.
    if (root && !root.startsWith(".gemini/config/plugins/hyphae/")) roots.add(root);
  }
}
const unixRoots = [];
const windowsRoots = [];
for (const root of roots) {
  if (root.startsWith(".config/")) {
    const relative = root.slice(".config/".length);
    unixRoots.push(`$CONFIG_HOME/${relative}`);
    windowsRoots.push([ "$ConfigHome", relative ]);
    if (relative.startsWith("opencode/")) windowsRoots.push([ "$AppData", relative ]);
  }
  unixRoots.push(`$HOME/${root}`);
  windowsRoots.push([ "$UserHome", root ]);
}

const unix = `  _skill_roots="${unixRoots.join("\n")}"`;
const windows = [
  "    foreach ($sr in @(",
  windowsRoots.map(([base, path]) => `        (Join-Path ${base} "${path.replaceAll("/", "\\")}")`).join(",\n"),
  "    )) {",
  "        Add-UniquePath -List $skillRoots -Seen $skillRootSeen -Path $sr",
  "    }",
].join("\n");
const targets = new Map([
  ["scripts/uninstall.sh", unix],
  ["site/uninstall.sh", unix],
  ["uninstall.sh", unix],
  ["scripts/uninstall.ps1", windows],
  ["site/uninstall.ps1", windows],
]);
const markers = /^( *# BEGIN GENERATED HARNESS SKILL ROOTS)\r?\n[\s\S]*?^( *# END GENERATED HARNESS SKILL ROOTS)/m;
const check = process.argv.includes("--check");
for (const [relative, contents] of targets) {
  const path = new URL(`../${relative}`, import.meta.url);
  const original = readFileSync(path, "utf8");
  if (!markers.test(original)) throw new Error(`Missing generated skill-root block in ${relative}`);
  const newline = original.includes("\r\n") ? "\r\n" : "\n";
  const updated = original.replace(markers, (_, start, end) =>
    [start, contents.replaceAll("\n", newline), end].join(newline),
  );
  if (updated === original) continue;
  if (check) {
    console.error(`${relative} differs from harness_specs.json. Run node scripts/generate-harness-skill-roots.mjs.`);
    process.exitCode = 1;
  } else {
    writeFileSync(path, updated);
  }
}
