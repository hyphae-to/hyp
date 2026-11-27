// Metadata snapshot parsing and display helpers for Hyphae harnesses.

const FORBIDDEN_BODY_KEYS = new Set([
  "body",
  "text",
  "note",
  "payload",
  "data",
  "content",
  "message",
  "raw",
  "ciphertext",
  "plaintext",
  "secret",
  "token",
  "quarantinedText",
  "quarantinedItems",
]);

const UNSAFE_OBJECT_KEYS = new Set(["__proto__", "constructor", "prototype"]);
/**
 * Strips ANSI escape sequences (OSC/DCS/CSI/ESC), C0/C1 control characters,
 * zero-width characters, and Unicode BiDi overrides WITHOUT truncating length.
 * Use this for CLI control arguments (`mute`, `unmute`, `unsubscribe`, `leave`, `rule`).
 */
export function sanitizeControlValue(raw) {
  if (raw === null || raw === undefined) return "";
  return String(raw)
    // Strip OSC sequences (\x1b] ... \x07 or \x1b\\)
    .replace(/\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)/g, "")
    // Strip DCS / SOS / PM / APC strings
    .replace(/\u001b[PX^_][^\u001b]*(?:\u001b\\)?/g, "")
    // Strip CSI sequences (\x1b[ ... final byte)
    .replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, "")
    // Strip remaining 2-byte ESC sequences
    .replace(/\u001b[@-Z\\-_]/g, "")
    // Strip remaining ESC and C0/C1 control characters
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, "")
    // Strip Unicode BiDi overrides/isolates/marks + zero-width / BOM
    .replace(/[\u061c\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, "")
    .trim();
}

/**
 * Strips ANSI escape sequences and control/BiDi characters from untrusted
 * metadata fields (`handle`, `topic`, `source`, `channel`, `label`) before display.
 */
export function sanitizeUiText(raw, maxLen = 120) {
  const str = sanitizeControlValue(raw);
  if (str.length <= maxLen) return str;
  return str.slice(0, Math.max(0, maxLen - 1)) + "…";
}

/**
 * Recursively removes any forbidden body, CloudEvent `data`, wakeup `note`, or
 * secret/token fields as defense-in-depth before any UI code inspects the data.
 */
export function stripMetadataOnly(value, depth = 0) {
  if (depth > 32) return null;
  if (Array.isArray(value)) {
    return value.map((item) => stripMetadataOnly(item, depth + 1));
  }
  if (!value || typeof value !== "object") {
    return value;
  }
  const out = {};
  for (const [key, val] of Object.entries(value)) {
    if (FORBIDDEN_BODY_KEYS.has(key) || UNSAFE_OBJECT_KEYS.has(key)) continue;
    out[key] = stripMetadataOnly(val, depth + 1);
  }
  return out;
}

function asRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value)
    ? value
    : null;
}

function expandStateDir(rawDir, baseHome, cfgDir) {
  const sd = rawDir.trim();
  if (!sd) return "";
  if (sd === "~") return baseHome;
  if (sd.startsWith("~/") || sd.startsWith("~\\")) {
    return `${baseHome}/${sd.slice(2).replace(/^[\\/]+/, "")}`;
  }
  if (sd.startsWith("/") || /^[A-Za-z]:[\\/]/.test(sd)) {
    return sd;
  }
  const rel = sd.replace(/^(?:\.[\\/])+/, "");
  return rel ? `${cfgDir}/${rel}` : cfgDir;
}

/**
 * Resolves ordered candidate `<state_dir>/ui` directories and `state.json` paths,
 * matching `crates/hyp-cli/src/config_file.rs`.
 *
 * Precedence:
 *   1. `HYPHAE_STATE_DIR` environment variable (`<HYPHAE_STATE_DIR>/ui/state.json`)
 *   2. `stateDir` in `~/.config/hyphae/node.json` (or legacy `connector.json`)
 *   3. `~/.config/hyphae/ui/state.json`
 *   4. `~/.config/hyphae/state/ui/state.json`
 */
export function resolveUiStateCandidates(
  homeDir,
  envStateDir = null,
  nodeJsonText = null,
) {
  const baseHome =
    typeof homeDir === "string" ? homeDir.replace(/[\\/]+$/, "") : "";
  const cfgDir = baseHome ? `${baseHome}/.config/hyphae` : ".config/hyphae";
  const dirs = [];

  const pushDir = (dir) => {
    const normalized = String(dir).replace(/[\\/]+$/, "");
    if (normalized && !dirs.includes(normalized)) {
      dirs.push(normalized);
    }
  };

  if (typeof envStateDir === "string" && envStateDir.trim()) {
    const resolved = expandStateDir(envStateDir, baseHome, cfgDir);
    if (resolved) pushDir(`${resolved.replace(/[\\/]+$/, "")}/ui`);
  }

  if (typeof nodeJsonText === "string" && nodeJsonText.trim()) {
    try {
      const parsed = asRecord(JSON.parse(nodeJsonText));
      const sd =
        parsed && typeof parsed.stateDir === "string"
          ? parsed.stateDir.trim()
          : "";
      if (sd) {
        const resolved = expandStateDir(sd, baseHome, cfgDir);
        if (resolved) pushDir(`${resolved.replace(/[\\/]+$/, "")}/ui`);
      }
    } catch {
      // Ignore malformed config and fall back to default paths.
    }
  }

  if (baseHome) {
    pushDir(`${cfgDir}/ui`);
    pushDir(`${cfgDir}/state/ui`);
  }

  return {
    dirs,
    files: dirs.map((d) => `${d}/state.json`),
  };
}

/** Reads the metadata record from a raw snapshot or successful CLI envelope. */
export function parseSnapshotMetadata(rawText) {
  if (typeof rawText !== "string" || !rawText.trim()) return null;
  let root;
  try {
    root = asRecord(JSON.parse(rawText));
  } catch {
    return null;
  }
  if (!root || root.ok === false) return null;
  if ("ok" in root) {
    root = asRecord(root.data) ?? asRecord(root.result) ?? root;
  }
  return stripMetadataOnly(root);
}
