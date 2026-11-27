#!/usr/bin/env node
/**
 * Self-contained official Hyphae non-Rust plugin & harness mod packager +
 * change-aware manifest generator (Node.js built-ins only, zero npm deps).
 *
 * Keeps `hyp` a pure-Rust static binary by packaging every official bridge
 * script and harness UI mod into a single POSIX ustar tarball
 * (`dist/hyp-<TAG>-plugins.tar.gz`) together with `plugins-manifest.json`,
 * using the exact same per-file SHA-256 (LF-normalized text, raw bytes for
 * binary `.png`) and deterministic `treeSha256` formula as
 * `crates/hyp-cli/build.rs`.
 *
 * Usage:
 *   node scripts/pack-plugins.mjs --tag v0.6.2 \
 *     [--out-dir dist] \
 *     [--plugins-dir plugins] \
 *     [--prev-tag auto|none|<git-ref>] \
 *     [--notes-out dist/changed-plugins.md] \
 *     [--github-output "$GITHUB_OUTPUT"] \
 *     [--json]
 */

import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

/** Shared with Rust checksum pinning and the harness's generated plugin ID lists. */
export const PLUGIN_SPECS = JSON.parse(
  fs.readFileSync(new URL("../crates/hyp-harness/plugin_specs.json", import.meta.url), "utf8"),
).map(({ id, kind, files }) => ({
  id,
  kind,
  files: files.map(([relPath, isBinary]) => ({ relPath, isBinary })),
}));

/**
 * Normalizes CRLF (`0x0d 0x0a`) -> LF (`0x0a`) at the raw byte level,
 * matching Rust `normalize_crlf` bit-for-bit across all platforms.
 */
export function normalizeCrlf(buf) {
  const out = Buffer.allocUnsafe(buf.length);
  let writeIdx = 0;
  for (let i = 0; i < buf.length; ) {
    if (buf[i] === 0x0d && i + 1 < buf.length && buf[i + 1] === 0x0a) {
      out[writeIdx++] = 0x0a;
      i += 2;
    } else {
      out[writeIdx++] = buf[i];
      i += 1;
    }
  }
  return out.subarray(0, writeIdx);
}

/**
 * Computes lowercase hex SHA-256 (raw bytes if `isBinary`, LF-normalized otherwise).
 */
export function hashFileBytes(buf, isBinary) {
  const payload = isBinary ? buf : normalizeCrlf(buf);
  return {
    payload,
    sha256: crypto.createHash("sha256").update(payload).digest("hex"),
  };
}

/**
 * Byte-order lexicographic comparator matching Rust `str::cmp` (locale-independent).
 */
function byteOrderCmp(a, b) {
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Computes deterministic `treeSha256` over lexicographically sorted
 * `"{relPath}\0{sha256}\n"` lines — identical to `crates/hyp-cli/build.rs`.
 */
export function computeTreeSha256(filesMap) {
  const keys = Object.keys(filesMap).sort(byteOrderCmp);
  const chunks = [];
  for (const relPath of keys) {
    chunks.push(Buffer.from(relPath, "utf8"));
    chunks.push(Buffer.from([0x00]));
    chunks.push(Buffer.from(filesMap[relPath], "ascii"));
    chunks.push(Buffer.from([0x0a]));
  }
  return crypto.createHash("sha256").update(Buffer.concat(chunks)).digest("hex");
}

function resolvePreviousTag(currentTag, prevTagArg, cwd) {
  if (prevTagArg && prevTagArg !== "auto") {
    if (prevTagArg.toLowerCase() === "none") {
      return null;
    }
    try {
      execFileSync("git", ["rev-parse", "--verify", `${prevTagArg}^{commit}`], {
        cwd,
        stdio: ["ignore", "pipe", "ignore"],
      });
      return prevTagArg;
    } catch {
      return null;
    }
  }

  try {
    const stdout = execFileSync(
      "git",
      ["tag", "--list", "v*", "--sort=-v:refname"],
      {
        cwd,
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
      },
    );
    const tags = stdout
      .split(/\r?\n/)
      .map((t) => t.trim())
      .filter((t) => t.length > 0 && t !== currentTag);
    for (const candidate of tags) {
      try {
        execFileSync("git", ["rev-parse", "--verify", `${candidate}^{commit}`], {
          cwd,
          stdio: ["ignore", "pipe", "ignore"],
        });
        return candidate;
      } catch {
        // Ignore unresolvable tag refs and continue.
      }
    }
  } catch {
    // Graceful fallback when running outside git or shallow clone without tags.
  }
  return null;
}

function readGitFileAtRef(gitRef, repoRelPath, cwd) {
  try {
    return execFileSync("git", ["show", `${gitRef}:${repoRelPath}`], {
      cwd,
      maxBuffer: 16 * 1024 * 1024,
      stdio: ["ignore", "pipe", "ignore"],
    });
  } catch {
    return null;
  }
}

function computePreviousPluginTree(spec, prevTag, cwd) {
  if (!prevTag) {
    return null;
  }
  const prevFiles = {};
  for (const file of spec.files) {
    const raw = readGitFileAtRef(prevTag, `plugins/${file.relPath}`, cwd);
    if (raw === null) {
      return null;
    }
    const { sha256 } = hashFileBytes(raw, file.isBinary);
    prevFiles[file.relPath] = sha256;
  }
  return computeTreeSha256(prevFiles);
}

function renderChangedPluginsMarkdown(manifest) {
  const lines = [];
  lines.push("## Official Plugins & Harness Mods");
  lines.push("");
  if (manifest.previousTag) {
    lines.push(
      `Compared against \`${manifest.previousTag}\` (bundled in \`hyp-${manifest.releaseTag}-plugins.tar.gz\`).`,
    );
  } else {
    lines.push(
      `Baseline plugin bundle (\`hyp-${manifest.releaseTag}-plugins.tar.gz\`).`,
    );
  }
  lines.push("");

  const changed = [];
  const unchanged = [];
  for (const [id, info] of Object.entries(manifest.plugins)) {
    if (info.changed) {
      changed.push([id, info]);
    } else {
      unchanged.push([id, info]);
    }
  }

  lines.push("### Changed Plugins");
  lines.push("");
  if (changed.length === 0) {
    lines.push("- None — all official plugins & harness mods are unchanged from the previous release.");
  } else {
    for (const [id, info] of changed) {
      lines.push(
        `- **\`${id}\`** (\`${info.kind}\`) — \`treeSha256:${info.treeSha256.slice(0, 12)}\``,
      );
    }
  }

  if (unchanged.length > 0) {
    lines.push("");
    lines.push(
      `Unchanged (${unchanged.length}): ${unchanged.map(([id]) => `\`${id}\``).join(", ")}.`,
    );
  }
  lines.push("");
  return lines.join("\n");
}

function parseArgs(argv) {
  const opts = {
    tag: "",
    outDir: "dist",
    pluginsDir: "plugins",
    prevTag: "auto",
    notesOut: "",
    githubOutput: "",
    json: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--tag" && i + 1 < argv.length) {
      opts.tag = argv[++i];
    } else if (arg === "--out-dir" && i + 1 < argv.length) {
      opts.outDir = argv[++i];
    } else if (arg === "--plugins-dir" && i + 1 < argv.length) {
      opts.pluginsDir = argv[++i];
    } else if (arg === "--prev-tag" && i + 1 < argv.length) {
      opts.prevTag = argv[++i];
    } else if (arg === "--notes-out" && i + 1 < argv.length) {
      opts.notesOut = argv[++i];
    } else if (arg === "--github-output" && i + 1 < argv.length) {
      opts.githubOutput = argv[++i];
    } else if (arg === "--json") {
      opts.json = true;
    } else if (arg === "-h" || arg === "--help") {
      console.log(
        "Usage: node scripts/pack-plugins.mjs --tag <TAG> [--out-dir dist] [--plugins-dir plugins] [--prev-tag auto|none|<ref>] [--notes-out <file>] [--github-output <file>] [--json]",
      );
      process.exit(0);
    } else {
      console.error(`Unknown or incomplete argument: ${arg}`);
      process.exit(2);
    }
  }

  if (!opts.tag) {
    console.error("Missing required --tag <TAG> (e.g. v0.6.2 or nightly)");
    process.exit(2);
  }
  return opts;
}

export function packPlugins(opts) {
  const cwd = process.cwd();
  const pluginsRoot = path.resolve(cwd, opts.pluginsDir);
  const outDir = path.resolve(cwd, opts.outDir);
  fs.mkdirSync(outDir, { recursive: true });

  const previousTag = resolvePreviousTag(opts.tag, opts.prevTag, cwd);

  // Hash & collect unique files across all official plugin specs.
  const uniqueFilePayloads = new Map();
  const uniqueFileDigests = new Map();

  for (const spec of PLUGIN_SPECS) {
    for (const file of spec.files) {
      if (uniqueFileDigests.has(file.relPath)) {
        continue;
      }
      const fullPath = path.join(pluginsRoot, file.relPath);
      if (!fs.existsSync(fullPath) || !fs.statSync(fullPath).isFile()) {
        throw new Error(`Missing official plugin file: ${fullPath}`);
      }
      const raw = fs.readFileSync(fullPath);
      const { payload, sha256 } = hashFileBytes(raw, file.isBinary);
      uniqueFilePayloads.set(file.relPath, payload);
      uniqueFileDigests.set(file.relPath, sha256);
    }
  }

  // Build plugins-manifest.json with per-plugin treeSha256 & previous-tag comparison.
  const pluginsObj = {};
  const changedPlugins = [];

  for (const spec of PLUGIN_SPECS) {
    const filesMap = {};
    const sortedRelPaths = spec.files.map((f) => f.relPath).sort(byteOrderCmp);
    for (const relPath of sortedRelPaths) {
      filesMap[relPath] = uniqueFileDigests.get(relPath);
    }
    const treeSha256 = computeTreeSha256(filesMap);
    const previousTreeSha256 = computePreviousPluginTree(spec, previousTag, cwd);
    const changed = previousTreeSha256 === null || previousTreeSha256 !== treeSha256;
    if (changed) {
      changedPlugins.push(spec.id);
    }
    pluginsObj[spec.id] = {
      kind: spec.kind,
      treeSha256,
      previousTreeSha256,
      changed,
      files: filesMap,
    };
  }

  const manifest = {
    schemaVersion: 1,
    releaseTag: opts.tag,
    previousTag,
    changedPlugins,
    plugins: pluginsObj,
  };
  const manifestJson = JSON.stringify(manifest, null, 2) + "\n";

  // Stage all unique normalized/binary files + plugins-manifest.json and pack with POSIX ustar.
  const stageDir = fs.mkdtempSync(path.join(os.tmpdir(), "hyp-pack-plugins-"));
  const archiveName = `hyp-${opts.tag}-plugins.tar.gz`;
  const archivePath = path.join(outDir, archiveName);
  const manifestOutPath = path.join(outDir, "plugins-manifest.json");

  try {
    const archiveEntries = [];
    const sortedUniqueRels = Array.from(uniqueFilePayloads.keys()).sort(byteOrderCmp);
    for (const relPath of sortedUniqueRels) {
      const stagedPath = path.join(stageDir, relPath);
      fs.mkdirSync(path.dirname(stagedPath), { recursive: true });
      fs.writeFileSync(stagedPath, uniqueFilePayloads.get(relPath));
      fs.chmodSync(stagedPath, 0o644);
      archiveEntries.push(relPath);
    }

    const stagedManifest = path.join(stageDir, "plugins-manifest.json");
    fs.writeFileSync(stagedManifest, manifestJson, "utf8");
    fs.chmodSync(stagedManifest, 0o644);
    archiveEntries.push("plugins-manifest.json");

    execFileSync(
      "tar",
      ["--format=ustar", "-C", stageDir, "-czf", archivePath, ...archiveEntries],
      {
        stdio: "inherit",
        env: { ...process.env, COPYFILE_DISABLE: "1" },
      },
    );
  } finally {
    fs.rmSync(stageDir, { recursive: true, force: true });
  }

  fs.writeFileSync(manifestOutPath, manifestJson, "utf8");

  const markdownNotes = renderChangedPluginsMarkdown(manifest);
  if (opts.notesOut) {
    const notesPath = path.resolve(cwd, opts.notesOut);
    fs.mkdirSync(path.dirname(notesPath), { recursive: true });
    fs.writeFileSync(notesPath, markdownNotes, "utf8");
  }

  const changedClaudeCode = Boolean(manifest.plugins["claude-code"]?.changed);
  const changedClaudePanel = Boolean(manifest.plugins["claude-panel"]?.changed);
  const changedHerdrMod = Boolean(manifest.plugins["herdr-mod"]?.changed);
  const changedBridges = PLUGIN_SPECS.some(
    (s) => s.kind === "bridge" && Boolean(manifest.plugins[s.id]?.changed),
  );

  if (opts.githubOutput) {
    const ghLines = [
      `previous_tag=${previousTag || ""}`,
      `changed_plugins=${changedPlugins.join(",")}`,
      `changed_count=${changedPlugins.length}`,
      `changed_claude_code=${changedClaudeCode}`,
      `changed_claude_panel=${changedClaudePanel}`,
      `changed_herdr_mod=${changedHerdrMod}`,
      `changed_bridges=${changedBridges}`,
    ];
    fs.appendFileSync(opts.githubOutput, ghLines.join("\n") + "\n", "utf8");
  }

  return {
    archivePath,
    manifestOutPath,
    manifest,
    markdownNotes,
    outputs: {
      previousTag,
      changedPlugins,
      changedClaudeCode,
      changedClaudePanel,
      changedHerdrMod,
      changedBridges,
    },
  };
}

if (
  process.argv[1] &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href
) {
  const opts = parseArgs(process.argv.slice(2));
  const result = packPlugins(opts);
  if (opts.json) {
    process.stdout.write(JSON.stringify(result.manifest, null, 2) + "\n");
  } else {
    console.log(
      `Packaged ${result.archivePath} (${PLUGIN_SPECS.length} plugins; changed vs ${result.manifest.previousTag || "baseline"}: ${result.manifest.changedPlugins.length ? result.manifest.changedPlugins.join(", ") : "none"})`,
    );
  }
}
