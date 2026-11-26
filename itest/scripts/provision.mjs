#!/usr/bin/env node
/**
 * Hyphae Black-Box Integration Test Toolchain Provisioner (`itest/scripts/provision.mjs`).
 *
 * Modes:
 *  - Isolated cache (default): populates `~/.cache/hyphae-itest/toolchains/<lock-hash>/`
 *    with pinned npm prefixes (never mutating global npm or `~/.local/bin`).
 *  - Host discovery (`--use-host-bins` or `HYPHAE_ITEST_USE_HOST_BINS=1`): locates already-
 *    installed local binaries (env overrides, sandbox paths, PATH, `~/.local/bin`, etc.),
 *    probes versions, compares against `itest/versions.lock.json`, and prints resolved paths.
 *
 * Also exports `resolveToolBinaries()` / `resolveToolBinary()` for direct import by test suites.
 */

import { execFileSync } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const ITEST_ROOT = path.resolve(__dirname, "..");
export const LOCKFILE_PATH = path.join(ITEST_ROOT, "versions.lock.json");

export function loadVersionsLock() {
  const raw = fs.readFileSync(LOCKFILE_PATH, "utf8");
  const parsed = JSON.parse(raw);
  const hash = crypto.createHash("sha256").update(raw, "utf8").digest("hex").slice(0, 16);
  return { lock: parsed, hash };
}

export function defaultCacheDir() {
  const envCache = process.env.HYPHAE_ITEST_CACHE_DIR?.trim();
  if (envCache) return path.resolve(envCache);
  return path.join(os.homedir(), ".cache", "hyphae-itest");
}

function isExecutableFile(p) {
  try {
    const stat = fs.statSync(p);
    if (!stat.isFile()) return false;
    if (process.platform === "win32") return true;
    fs.accessSync(p, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function findInPath(binName, pathEnv = process.env.PATH || "") {
  const exts = process.platform === "win32" ? [".exe", ".cmd", ".bat", ""] : [""];
  for (const dir of pathEnv.split(path.delimiter)) {
    if (!dir) continue;
    for (const ext of exts) {
      const candidate = path.join(dir, `${binName}${ext}`);
      if (isExecutableFile(candidate)) return candidate;
    }
  }
  return null;
}

function envVarForTool(tool) {
  return `${tool.toUpperCase().replace(/[^A-Z0-9]/g, "_")}_BIN`;
}

function extraHostCandidates(tool, home = os.homedir()) {
  const bin = tool;
  const list = [
    path.join(home, ".local", "bin", bin),
    path.join("/opt/homebrew/bin", bin),
    path.join("/usr/local/bin", bin),
  ];
  if (tool === "openclaw") {
    list.unshift(
      path.join(home, "Workspace", "openclaw-hyphae-sandbox", "runtime", "node_modules", ".bin", "openclaw"),
    );
  }
  if (tool === "opencode") {
    list.unshift(path.join(home, ".opencode", "bin", "opencode"));
  }
  if (tool === "claude") {
    list.push(path.join(home, ".claude", "local", "claude"));
  }
  return list;
}

function cacheBinPath(cacheDir, lockHash, toolName, spec) {
  const root = path.join(cacheDir, "toolchains", lockHash);
  const ext = process.platform === "win32" ? ".cmd" : "";
  if (spec.kind === "npm") {
    return path.join(root, "npm", toolName, "node_modules", ".bin", `${spec.bin}${ext}`);
  }
  return path.join(root, "bin", `${spec.bin}${process.platform === "win32" ? ".exe" : ""}`);
}

export function probeBinaryVersion(binPath, versionArgs = ["--version"]) {
  try {
    const out = execFileSync(binPath, versionArgs, {
      encoding: "utf8",
      timeout: 10_000,
      stdio: ["ignore", "pipe", "pipe"],
      maxBuffer: 1024 * 1024,
    });
    const lines = out
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l && !l.toLowerCase().includes("security warning:"));
    return lines[0] || out.trim().split(/\r?\n/)[0] || null;
  } catch (err) {
    const stderr = typeof err?.stderr === "string" ? err.stderr : "";
    const stdout = typeof err?.stdout === "string" ? err.stdout : "";
    const first = `${stdout}\n${stderr}`
      .split(/\r?\n/)
      .map((l) => l.trim())
      .find((l) => l && !l.toLowerCase().includes("security warning:"));
    return first || null;
  }
}

function versionMatchesPin(detectedVersion, pinnedVersion) {
  if (!detectedVersion || !pinnedVersion) return false;
  return detectedVersion.includes(pinnedVersion);
}

/**
 * Resolves a single tool binary according to precedence:
 *   1. Explicit `<TOOL>_BIN` env override
 *   2. Isolated cache (`~/.cache/hyphae-itest/toolchains/<hash>/...`) unless `preferHost` is true
 *   3. Host binary discovery (sandbox paths, PATH, `~/.local/bin`, etc.)
 */
export function resolveToolBinary(toolName, options = {}) {
  const { lock, hash } = loadVersionsLock();
  const spec = lock.tools[toolName];
  if (!spec) {
    throw new Error(`Unknown tool '${toolName}' (not in versions.lock.json)`);
  }
  const cacheDir = options.cacheDir || defaultCacheDir();
  const preferHost =
    options.useHostBins ??
    (process.env.HYPHAE_ITEST_USE_HOST_BINS === "1" || process.env.HYPHAE_ITEST_USE_HOST_BINS === "true");
  const probeVersion = options.probeVersion !== false;

  const envKey = envVarForTool(toolName);
  const envVal = process.env[envKey]?.trim();
  let resolvedPath = null;
  let source = "missing";

  if (envVal) {
    if (!fs.existsSync(envVal)) {
      throw new Error(`${envKey} points to non-existent binary: ${envVal}`);
    }
    resolvedPath = path.resolve(envVal);
    source = `env:${envKey}`;
  }

  const cached = cacheBinPath(cacheDir, hash, toolName, spec);
  if (!resolvedPath && !preferHost && isExecutableFile(cached)) {
    resolvedPath = cached;
    source = "cache";
  }

  if (!resolvedPath) {
    // Check host candidates: PATH first for standard binaries, and sandbox/known paths.
    // For openclaw, prefer PATH if present or sandbox fallback (if preferHost, check sandbox & PATH).
    const candidates = [];
    const fromPath = findInPath(spec.bin);
    if (fromPath) candidates.push({ p: fromPath, src: "host:PATH" });
    for (const extra of extraHostCandidates(toolName)) {
      if (isExecutableFile(extra) && !candidates.some((c) => c.p === extra)) {
        candidates.push({
          p: extra,
          src: extra.includes("openclaw-hyphae-sandbox") ? "host:openclaw-sandbox" : "host:local",
        });
      }
    }
    if (candidates.length > 0) {
      resolvedPath = candidates[0].p;
      source = candidates[0].src;
    }
  }

  if (!resolvedPath && preferHost && isExecutableFile(cached)) {
    resolvedPath = cached;
    source = "cache";
  }

  const detectedVersion =
    resolvedPath && probeVersion ? probeBinaryVersion(resolvedPath, spec.versionArgs) : null;

  return {
    tool: toolName,
    tier: spec.tier,
    pinnedVersion: spec.version,
    path: resolvedPath,
    source,
    found: Boolean(resolvedPath),
    version: detectedVersion,
    matchesPin: versionMatchesPin(detectedVersion, spec.version),
  };
}

export function resolveToolBinaries(options = {}) {
  const { lock, hash } = loadVersionsLock();
  const selected = options.tools?.length ? options.tools : Object.keys(lock.tools);
  const tools = {};
  for (const name of selected) {
    tools[name] = resolveToolBinary(name, options);
  }
  return {
    lockHash: hash,
    cacheDir: options.cacheDir || defaultCacheDir(),
    useHostBins: Boolean(options.useHostBins),
    tools,
  };
}

function installNpmTool(cacheDir, lockHash, toolName, spec) {
  const prefixDir = path.join(cacheDir, "toolchains", lockHash, "npm", toolName);
  const binPath = cacheBinPath(cacheDir, lockHash, toolName, spec);
  if (isExecutableFile(binPath)) {
    return { installed: false, path: binPath, note: "cache hit" };
  }
  fs.mkdirSync(prefixDir, { recursive: true });
  const pkgSpec = `${spec.package}@${spec.version}`;
  execFileSync(
    process.platform === "win32" ? "npm.cmd" : "npm",
    [
      "install",
      "--prefix",
      prefixDir,
      "--no-audit",
      "--no-fund",
      "--loglevel=error",
      pkgSpec,
    ],
    {
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 300_000,
    },
  );
  if (!isExecutableFile(binPath)) {
    throw new Error(`npm install succeeded for ${pkgSpec} but binary not found at ${binPath}`);
  }
  return { installed: true, path: binPath, note: `installed ${pkgSpec}` };
}

function parseCliArgs(argv) {
  const opts = {
    useHostBins:
      process.env.HYPHAE_ITEST_USE_HOST_BINS === "1" ||
      process.env.HYPHAE_ITEST_USE_HOST_BINS === "true",
    json: false,
    check: false,
    cacheDir: defaultCacheDir(),
    tools: [],
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--use-host-bins") {
      opts.useHostBins = true;
    } else if (arg === "--json") {
      opts.json = true;
    } else if (arg === "--check") {
      opts.check = true;
    } else if (arg === "--cache-dir" && argv[i + 1]) {
      opts.cacheDir = path.resolve(argv[++i]);
    } else if (arg === "--tools" && argv[i + 1]) {
      opts.tools = argv[++i]
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);
    } else if (arg === "-h" || arg === "--help") {
      console.log(
        [
          "Usage: node itest/scripts/provision.mjs [options]",
          "",
          "Options:",
          "  --use-host-bins       Discover already-installed local binaries instead of installing into cache",
          "  --check               Verify available binaries without installing",
          "  --cache-dir <dir>     Override cache dir (default: ~/.cache/hyphae-itest)",
          "  --tools <a,b,c>       Comma-separated subset of tools from versions.lock.json",
          "  --json                Print resolved binary paths and version table as JSON",
        ].join("\n"),
      );
      process.exit(0);
    }
  }
  return opts;
}

function formatTable(report) {
  const rows = Object.values(report.tools);
  const headers = ["TOOL", "TIER", "PINNED", "STATUS", "SOURCE", "VERSION", "PATH"];
  const body = rows.map((r) => [
    r.tool,
    `T${r.tier}`,
    r.pinnedVersion,
    !r.found ? "MISSING" : r.matchesPin ? "OK" : "DRIFT",
    r.source,
    (r.version || "-").slice(0, 36),
    r.path || "-",
  ]);
  const widths = headers.map((h, i) => Math.max(h.length, ...body.map((row) => row[i].length)));
  const fmt = (cols) => cols.map((c, i) => c.padEnd(widths[i])).join("  ");
  return [
    `Hyphae itest toolchain (lock=${report.lockHash}, mode=${report.useHostBins ? "host-bins" : "cache"})`,
    fmt(headers),
    widths.map((w) => "-".repeat(w)).join("  "),
    ...body.map(fmt),
  ].join("\n");
}

function main() {
  const opts = parseCliArgs(process.argv.slice(2));
  const { lock, hash } = loadVersionsLock();
  const selected = opts.tools.length ? opts.tools : Object.keys(lock.tools);

  const actions = {};
  if (!opts.useHostBins && !opts.check) {
    for (const toolName of selected) {
      const spec = lock.tools[toolName];
      if (!spec) {
        throw new Error(`Unknown tool '${toolName}'`);
      }
      if (spec.kind === "npm") {
        actions[toolName] = installNpmTool(opts.cacheDir, hash, toolName, spec);
      } else {
        actions[toolName] = {
          installed: false,
          note: `native binary; install manually (${spec.installHint || "see docs"}) or use --use-host-bins`,
        };
      }
    }
  }

  const report = resolveToolBinaries({
    cacheDir: opts.cacheDir,
    useHostBins: opts.useHostBins,
    tools: selected,
    probeVersion: true,
  });
  report.actions = actions;

  if (opts.json) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(formatTable(report));
  }
}

const isEntrypoint =
  process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isEntrypoint) {
  main();
}
