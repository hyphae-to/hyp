// Optional, metadata-only, zero-polling Hyphae TUI status widget for OpenCode (`tui.json`).
//
// Security invariants (matching `plugins/claude-code/hooks/state.ts`):
//   - Consumes strictly metadata-only snapshots (`<state_dir>/ui/state.json`).
//   - Recursively strips forbidden body/payload/note/secret fields as defense-in-depth.
//   - Strips ANSI escape sequences (OSC/CSI/DCS/ESC), C0/C1 control characters,
//     zero-width characters, and Unicode BiDi override/isolate characters from all
//     untrusted external strings before rendering.
//   - Strictly zero-polling: uses `fs.watch` on `<state_dir>/ui/` (never `setInterval`)
//     and cleans up every watcher/timer on dispose.
//   - Human-CLI quarantine boundary: displays quarantined counts only and directs the
//     user to `hyp gate review`; never displays quarantined payloads or sources.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";

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
const WATCH_DEBOUNCE_MS = 50;
const MAX_SNAPSHOT_BYTES = 1024 * 1024;

/**
 * Strips ANSI escape sequences (OSC, CSI, DCS/APC/PM/SOS, ESC), C0/C1 control
 * characters, zero-width joiners/marks, and Unicode BiDi override/isolate
 * characters from untrusted external strings before rendering.
 */
export function sanitizeUiText(raw, maxLen = 120) {
  if (raw === null || raw === undefined) return "";
  const cleaned = String(raw)
    // OSC sequences: ESC ] ... (BEL | ST)
    .replace(/\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)/g, "")
    // DCS / SOS / PM / APC strings: ESC [PX^_] ... ST
    .replace(/\u001b[PX^_][^\u001b]*(?:\u001b\\)?/g, "")
    // CSI sequences: ESC [ params intermediates final
    .replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, "")
    // Remaining 2-byte ESC sequences
    .replace(/\u001b[@-Z\\-_]/g, "")
    // C0 / DEL / C1 control characters (includes remaining bare ESC)
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, "")
    // Unicode BiDi overrides/isolates/marks + zero-width / BOM characters
    .replace(/[\u061c\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, "")
    .trim();

  if (cleaned.length <= maxLen) return cleaned;
  return `${cleaned.slice(0, Math.max(0, maxLen - 1))}…`;
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

function asNum(value, fallback = 0) {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function asCount(value) {
  return Math.max(0, Math.floor(asNum(value, 0)));
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
 * matching `crates/hyp-cli/src/config_file.rs` and `plugins/claude-code/hooks/state.ts`.
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

function parseSessionSummary(raw) {
  const obj = asRecord(raw);
  if (!obj) return null;
  const sessionId = sanitizeUiText(obj.sessionId, 128);
  if (!sessionId) return null;

  const countsObj = asRecord(obj.counts);
  const unreadObj = asRecord(obj.unreadBreakdown);
  const detailsObj = asRecord(obj.details);

  const rawBridges = Array.isArray(detailsObj?.bridges) ? detailsObj.bridges : [];
  const bridges = [];
  for (const item of rawBridges) {
    const b = asRecord(item);
    if (!b) continue;
    const plugin = sanitizeUiText(b.plugin, 40);
    const target = sanitizeUiText(b.target, 64);
    const label =
      sanitizeUiText(b.label, 96) ||
      (plugin && target ? `${plugin}:${target}` : plugin || target);
    if (!label) continue;
    bridges.push({
      plugin: plugin || label.split(":")[0] || "bridge",
      target: target || label.split(":").slice(1).join(":") || "*",
      label,
      role: b.role === "primary" ? "primary" : "reader",
    });
  }

  const rawCompactBridges = Array.isArray(obj.bridges) ? obj.bridges : [];
  const compactBridges = rawCompactBridges
    .map((b) => sanitizeUiText(b, 96))
    .filter((b) => b.length > 0);
  const effectiveBridgeLabels =
    compactBridges.length > 0 ? compactBridges : bridges.map((b) => b.label);

  const rawSubs = Array.isArray(detailsObj?.subscriptions)
    ? detailsObj.subscriptions
    : [];
  const subscriptions = [];
  for (const item of rawSubs) {
    const s = asRecord(item);
    if (!s) continue;
    const id = sanitizeUiText(s.id, 128);
    const topic = sanitizeUiText(s.topic, 120);
    if (!id && !topic) continue;
    subscriptions.push({
      id: id || topic,
      key:
        typeof s.key === "string" && s.key.trim()
          ? sanitizeUiText(s.key, 80)
          : null,
      originNode: sanitizeUiText(s.originNode, 64) || "local",
      topic: topic || id,
      mode: sanitizeUiText(s.mode, 24) || "queue",
      coalesceSeconds: asCount(s.coalesceSeconds),
      filterSummary: sanitizeUiText(s.filterSummary, 140),
    });
  }

  const rawQueued = Array.isArray(detailsObj?.queuedItems)
    ? detailsObj.queuedItems
    : [];
  const queuedItems = [];
  for (const item of rawQueued) {
    const q = asRecord(item);
    if (!q) continue;
    queuedItems.push({
      receipt: sanitizeUiText(q.receipt, 64),
      kind: sanitizeUiText(q.kind, 24) || "message",
      source: sanitizeUiText(q.source, 96) || "unknown",
      originNode: sanitizeUiText(q.originNode, 64),
      receivedAt: asNum(q.receivedAt, 0),
      notified: Boolean(q.notified),
      urgency: sanitizeUiText(q.urgency, 24) || "queue",
    });
  }

  const rawMutes = Array.isArray(detailsObj?.mutes) ? detailsObj.mutes : [];
  const mutes = [];
  for (const item of rawMutes) {
    const m = asRecord(item);
    if (!m) continue;
    const pattern = sanitizeUiText(m.pattern, 120);
    if (!pattern) continue;
    mutes.push({
      pattern,
      scope: m.scope === "connector" ? "connector" : "session",
      mutedAt: asNum(m.mutedAt, 0),
    });
  }

  const rawRules = Array.isArray(detailsObj?.rules) ? detailsObj.rules : [];
  const rules = [];
  for (const item of rawRules) {
    const r = asRecord(item);
    if (!r) continue;
    const target = sanitizeUiText(r.target, 120);
    if (!target) continue;
    rules.push({
      target,
      delivery: sanitizeUiText(r.delivery, 24) || "queue",
    });
  }

  const rawChannels = Array.isArray(detailsObj?.channels)
    ? detailsObj.channels
    : [];
  const channels = rawChannels
    .map((c) => sanitizeUiText(c, 96))
    .filter((c) => c.length > 0);

  const rawChanEntries = Array.isArray(detailsObj?.channelEntries)
    ? detailsObj.channelEntries
    : [];
  const channelEntries = [];
  for (const item of rawChanEntries) {
    const c = asRecord(item);
    if (!c) continue;
    const channel = sanitizeUiText(c.channel, 96);
    if (!channel) continue;
    channelEntries.push({
      hostNode: sanitizeUiText(c.hostNode, 64) || "local",
      channel,
      mode: sanitizeUiText(c.mode, 24) || "open",
    });
  }

  const rawWakeups = Array.isArray(detailsObj?.wakeups)
    ? detailsObj.wakeups
    : [];
  const wakeups = [];
  for (const item of rawWakeups) {
    const w = asRecord(item);
    if (!w) continue;
    const id = sanitizeUiText(w.id, 64);
    const label = sanitizeUiText(w.label, 96);
    if (!id && !label) continue;
    wakeups.push({
      id: id || label,
      label: label || id,
      triggerKind: sanitizeUiText(w.triggerKind, 24) || "once",
      nextFireAt: asNum(w.nextFireAt, 0),
      urgency: sanitizeUiText(w.urgency, 24) || "notify",
      state: sanitizeUiText(w.state, 24) || "armed",
    });
  }

  const rawSources = Array.isArray(unreadObj?.sources) ? unreadObj.sources : [];
  const sources = rawSources
    .map((s) => sanitizeUiText(s, 80))
    .filter((s) => s.length > 0);

  const handleRaw =
    typeof obj.handle === "string" && obj.handle.trim()
      ? sanitizeUiText(obj.handle, 48)
      : null;
  const addressRaw =
    typeof obj.address === "string" && obj.address.trim()
      ? sanitizeUiText(obj.address, 96)
      : null;
  const transportRaw =
    typeof obj.transportKind === "string" && obj.transportKind.trim()
      ? sanitizeUiText(obj.transportKind, 32)
      : null;

  return {
    sessionId,
    harness: sanitizeUiText(obj.harness, 32) || "unknown",
    enrolled: Boolean(obj.enrolled),
    handle: handleRaw,
    address: addressRaw,
    lastSeen: asNum(obj.lastSeen, 0),
    transportKind: transportRaw,
    hasLiveTransport: Boolean(obj.hasLiveTransport),
    deliveryMode: sanitizeUiText(obj.deliveryMode, 24) || "queue",
    focusMode: Boolean(obj.focusMode),
    focusAllowInterruptVips: Boolean(obj.focusAllowInterruptVips),
    mutedAll: Boolean(obj.mutedAll),
    bridges: effectiveBridgeLabels,
    counts: {
      subscriptions: asCount(countsObj?.subscriptions ?? subscriptions.length),
      bridges: asCount(
        countsObj?.bridges ?? Math.max(bridges.length, effectiveBridgeLabels.length),
      ),
      queued: asCount(countsObj?.queued ?? queuedItems.length),
      unnotified: asCount(countsObj?.unnotified ?? 0),
      quarantined: asCount(countsObj?.quarantined ?? 0),
      mutedRules: asCount(countsObj?.mutedRules ?? mutes.length),
      mutedArchived: asCount(countsObj?.mutedArchived ?? 0),
      channels: asCount(
        countsObj?.channels ?? (channelEntries.length || channels.length),
      ),
      wakeups: asCount(countsObj?.wakeups ?? wakeups.length),
    },
    unreadBreakdown: {
      messages: asCount(unreadObj?.messages ?? 0),
      events: asCount(unreadObj?.events ?? 0),
      plugins: asCount(unreadObj?.plugins ?? 0),
      transfers: asCount(unreadObj?.transfers ?? 0),
      kv: asCount(unreadObj?.kv ?? 0),
      sources,
    },
    details: {
      bridges,
      subscriptions,
      queuedItems,
      mutes,
      rules,
      channels,
      channelEntries,
      wakeups,
    },
  };
}

/**
 * Parses either raw `<state_dir>/ui/state.json` or a `hyp inspect --all --json`
 * CLI envelope into a strictly sanitized, metadata-only snapshot.
 */
export function parseSnapshotJson(rawText) {
  if (typeof rawText !== "string" || !rawText.trim()) return null;
  if (rawText.length > MAX_SNAPSHOT_BYTES) return null;

  let parsed;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    return null;
  }

  const stripped = asRecord(stripMetadataOnly(parsed));
  if (!stripped) return null;

  let root = stripped;
  if ("ok" in stripped) {
    if (stripped.ok === false) return null;
    // Note: `data` is in FORBIDDEN_BODY_KEYS for nested payloads, so support
    // envelope unwrap via original parsed top-level `data`/`result` ONLY after
    // applying `stripMetadataOnly` directly to that sub-object.
    const rawEnvelope = asRecord(parsed);
    const envelopeInner =
      asRecord(rawEnvelope?.data) ?? asRecord(rawEnvelope?.result);
    if (envelopeInner) {
      const sanitizedInner = asRecord(stripMetadataOnly(envelopeInner));
      if (sanitizedInner) root = sanitizedInner;
    }
  }

  const daemonObj = asRecord(root.daemon);
  const daemon = daemonObj
    ? {
        online: Boolean(daemonObj.online),
        pid: asCount(daemonObj.pid),
        nodeId: sanitizeUiText(daemonObj.nodeId, 64) || "local",
        version: sanitizeUiText(daemonObj.version, 32),
        profile: sanitizeUiText(daemonObj.profile, 32),
        peersOnline: asCount(daemonObj.peersOnline),
        quarantinedGlobal: asCount(daemonObj.quarantinedGlobal),
      }
    : null;

  const rawSessions = Array.isArray(root.sessions)
    ? root.sessions
    : root.session
      ? [root.session]
      : [];
  const sessions = [];
  for (const item of rawSessions) {
    const s = parseSessionSummary(item);
    if (s) sessions.push(s);
  }

  return {
    schemaVersion: asCount(root.schemaVersion) || 1,
    rev: asCount(root.rev),
    updatedAt: asNum(root.updatedAt, 0),
    daemon,
    sessions,
  };
}

/**
 * Matches the active OpenCode session against the snapshot:
 *   1. Explicit `selectedSessionId` override
 *   2. Exact `opencode:<opencodeSessionId>` or raw `<opencodeSessionId>`
 *   3. Root ancestor `opencode:<rootSessionId>` (when viewing a subtask session)
 *   4. `$HYPHAE_SESSION_ID` fallback
 *   5. Otherwise returns `active: null` (zero clutter).
 */
export function resolveActiveOpencodeSession(
  snapshot,
  opencodeSessionId,
  rootSessionId = null,
  envHyphaeSessionId = null,
  selectedSessionId = null,
) {
  const sessions = snapshot?.sessions ?? [];
  if (sessions.length === 0) {
    return { active: null, matchedBy: "none", sessions };
  }

  if (typeof selectedSessionId === "string" && selectedSessionId.trim()) {
    const sel = sessions.find((s) => s.sessionId === selectedSessionId.trim());
    if (sel) return { active: sel, matchedBy: "selected", sessions };
  }

  const matchOpencodeId = (rawId, tag) => {
    if (typeof rawId !== "string" || !rawId.trim()) return null;
    const trimmed = rawId.trim();
    const prefixed = trimmed.startsWith("opencode:")
      ? trimmed
      : `opencode:${trimmed}`;
    const exactPrefixed = sessions.find((s) => s.sessionId === prefixed);
    if (exactPrefixed) return { active: exactPrefixed, matchedBy: tag, sessions };
    const exactRaw = sessions.find((s) => s.sessionId === trimmed);
    if (exactRaw) return { active: exactRaw, matchedBy: tag, sessions };
    return null;
  };

  const directMatch = matchOpencodeId(opencodeSessionId, "opencode");
  if (directMatch) return directMatch;

  if (rootSessionId && rootSessionId !== opencodeSessionId) {
    const rootMatch = matchOpencodeId(rootSessionId, "opencode-root");
    if (rootMatch) return rootMatch;
  }

  const envId =
    typeof envHyphaeSessionId === "string" ? envHyphaeSessionId.trim() : "";
  if (envId) {
    const envMatch = sessions.find((s) => s.sessionId === envId);
    if (envMatch) return { active: envMatch, matchedBy: "env", sessions };
  }

  return { active: null, matchedBy: "none", sessions };
}

/**
 * Computes total visible quarantined count (never exposes quarantined payloads or sources).
 */
export function getQuarantinedCount(snapshot, active) {
  const globalCount = snapshot?.daemon?.quarantinedGlobal ?? 0;
  const sessionCount = active?.counts?.quarantined ?? 0;
  const maxSession = (snapshot?.sessions ?? []).reduce(
    (acc, s) => Math.max(acc, s.counts?.quarantined ?? 0),
    0,
  );
  return Math.max(globalCount, sessionCount, maxSession);
}

/**
 * Formats a compact single-line metadata-only status badge for OpenCode's TUI.
 * Returns `undefined` when the current session is unenrolled and has no alerts.
 */
export function formatStatusLine(snapshot, active, quarantined) {
  if (quarantined > 0) {
    return `⚠ hyphae: ${quarantined} held · run \`hyp gate review\``;
  }
  if (!snapshot || !active) {
    return undefined;
  }
  const hasActivity =
    active.enrolled ||
    active.counts.bridges > 0 ||
    active.counts.subscriptions > 0 ||
    active.counts.queued > 0;
  if (!hasActivity) {
    return undefined;
  }

  const parts = [active.handle ? `⟁ @${active.handle}` : "⟁ hyphae"];

  const firstBridge = active.bridges[0];
  if (firstBridge && active.bridges.length === 1) {
    parts.push(firstBridge);
  } else if (firstBridge && active.bridges.length > 1) {
    parts.push(`${firstBridge} +${active.bridges.length - 1}`);
  } else if (active.counts.bridges > 0) {
    parts.push(
      active.counts.bridges === 1
        ? "1 bridge"
        : `${active.counts.bridges} bridges`,
    );
  }

  if (active.counts.subscriptions > 0) {
    parts.push(
      active.counts.subscriptions === 1
        ? "1 sub"
        : `${active.counts.subscriptions} subs`,
    );
  }
  if (active.counts.queued > 0) {
    parts.push(`${active.counts.queued} queued`);
  }
  if (active.focusMode) {
    parts.push("FOCUS");
  }
  if (active.mutedAll) {
    parts.push("muted");
  } else if (active.counts.mutedRules > 0) {
    parts.push(`${active.counts.mutedRules} muted`);
  }

  return parts.join(" · ");
}

/**
 * Formats sanitized, metadata-only lines for OpenCode's `sidebar.content` slot.
 */
export function formatSidebarLines(snapshot, active, quarantined) {
  const lines = [];
  if (quarantined > 0) {
    lines.push(`⚠ ${quarantined} held by Security Gate — run \`hyp gate review\``);
  }

  if (!snapshot) {
    lines.push("Hyphae daemon offline");
    return lines;
  }

  if (!active) {
    const enrolledCount = snapshot.sessions.filter((s) => s.enrolled).length;
    if (enrolledCount > 0) {
      lines.push(`Not joined (${enrolledCount} active on node)`);
    } else {
      lines.push("Not joined · run /hyphae");
    }
    return lines;
  }

  const identity = active.address || (active.handle ? `@${active.handle}` : active.sessionId);
  const modeTag = active.focusMode ? "FOCUS" : active.deliveryMode || "queue";
  lines.push(`${identity} · ${modeTag}`);

  const stats = [];
  stats.push(`${active.counts.subscriptions} subs`);
  stats.push(`${active.counts.queued} queued`);
  if (active.counts.channels > 0) stats.push(`${active.counts.channels} ch`);
  if (active.counts.bridges > 0) stats.push(`${active.counts.bridges} bridges`);
  if (active.mutedAll) {
    stats.push("muted*");
  } else if (active.counts.mutedRules > 0) {
    stats.push(`${active.counts.mutedRules} muted`);
  }
  lines.push(stats.join(" · "));

  if (active.unreadBreakdown.sources.length > 0) {
    const preview = active.unreadBreakdown.sources.slice(0, 3).join(", ");
    const suffix =
      active.unreadBreakdown.sources.length > 3
        ? ` +${active.unreadBreakdown.sources.length - 3}`
        : "";
    lines.push(`From: ${preview}${suffix}`);
  }

  if (active.details.channels.length > 0) {
    lines.push(`Channels: ${active.details.channels.slice(0, 4).join(" ")}`);
  }

  return lines;
}

function readTextSafe(filePath) {
  try {
    const stat = fs.statSync(filePath);
    if (!stat.isFile() || stat.size > MAX_SNAPSHOT_BYTES) return null;
    return fs.readFileSync(filePath, "utf8");
  } catch {
    return null;
  }
}

function readNodeConfigText(homeDir) {
  const cfgDir = path.join(homeDir, ".config", "hyphae");
  return (
    readTextSafe(path.join(cfgDir, "node.json")) ??
    readTextSafe(path.join(cfgDir, "connector.json"))
  );
}

/**
 * Zero-polling reactive controller that watches `<state_dir>/ui/` via `fs.watch`
 * and notifies subscribers whenever `state.json` or the active OpenCode session changes.
 */
export function createHyphaeTuiController(options = {}) {
  const homeDir = options.homeDir ?? os.homedir();
  const env = options.env ?? process.env;
  const watchFn = options.watch ?? fs.watch;
  const readFileFn = options.readFile ?? readTextSafe;
  const getSessionInfo =
    typeof options.getSessionInfo === "function"
      ? options.getSessionInfo
      : () => ({ sessionID: undefined, rootSessionID: undefined });
  const onUpdate =
    typeof options.onUpdate === "function" ? options.onUpdate : () => {};

  const nodeJsonText =
    options.nodeJsonText !== undefined
      ? options.nodeJsonText
      : readNodeConfigText(homeDir);
  const candidates = resolveUiStateCandidates(
    homeDir,
    env?.HYPHAE_STATE_DIR ?? null,
    nodeJsonText,
  );

  let disposed = false;
  let debounceTimer = null;
  const watchers = new Map();
  let currentState = {
    snapshot: null,
    active: null,
    matchedBy: "none",
    quarantined: 0,
    statusLine: undefined,
    sidebarLines: [],
    sourceFile: null,
  };

  function loadBestSnapshot() {
    for (const file of candidates.files) {
      const raw = readFileFn(file);
      if (!raw) continue;
      const parsed = parseSnapshotJson(raw);
      if (parsed) {
        return { snapshot: parsed, sourceFile: file };
      }
    }
    return { snapshot: null, sourceFile: null };
  }

  function ensureWatchers() {
    if (disposed) return;
    const targets = new Set();
    for (const dir of candidates.dirs) {
      if (fs.existsSync(dir)) {
        targets.add(dir);
      } else {
        const parent = path.dirname(dir);
        if (parent && fs.existsSync(parent)) {
          targets.add(parent);
        }
      }
    }

    for (const dir of targets) {
      if (watchers.has(dir)) continue;
      try {
        const watcher = watchFn(dir, { persistent: false }, (_eventType, filename) => {
          if (disposed) return;
          const name = typeof filename === "string" ? filename : "";
          // Only react to `state.json`, atomic temp renames, or `ui` dir creation.
          if (name && name !== "ui" && !name.startsWith("state.json")) {
            return;
          }
          scheduleRefresh();
        });
        watcher?.on?.("error", () => {
          closeWatcher(dir);
        });
        watchers.set(dir, watcher);
      } catch {
        // Non-fatal: directory may not exist yet or platform watcher unavailable.
      }
    }
  }

  function closeWatcher(dir) {
    const w = watchers.get(dir);
    if (!w) return;
    watchers.delete(dir);
    try {
      w.close();
    } catch {
      // Ignore close errors during cleanup.
    }
  }

  function refresh() {
    if (disposed) return currentState;
    ensureWatchers();
    const { snapshot, sourceFile } = loadBestSnapshot();
    let sessionInfo = { sessionID: undefined, rootSessionID: undefined };
    try {
      sessionInfo = getSessionInfo() || sessionInfo;
    } catch {
      // Fail-safe against TUI router quirks.
    }
    const resolved = resolveActiveOpencodeSession(
      snapshot,
      sessionInfo.sessionID,
      sessionInfo.rootSessionID,
      env?.HYPHAE_SESSION_ID ?? null,
    );
    const quarantined = getQuarantinedCount(snapshot, resolved.active);
    currentState = {
      snapshot,
      active: resolved.active,
      matchedBy: resolved.matchedBy,
      quarantined,
      statusLine: formatStatusLine(snapshot, resolved.active, quarantined),
      sidebarLines: formatSidebarLines(snapshot, resolved.active, quarantined),
      sourceFile,
    };
    try {
      onUpdate(currentState);
    } catch {
      // Never propagate UI listener errors.
    }
    return currentState;
  }

  function scheduleRefresh() {
    if (disposed) return;
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      debounceTimer = null;
      refresh();
    }, WATCH_DEBOUNCE_MS);
    debounceTimer.unref?.();
  }

  function dispose() {
    if (disposed) return;
    disposed = true;
    if (debounceTimer) {
      clearTimeout(debounceTimer);
      debounceTimer = null;
    }
    for (const dir of Array.from(watchers.keys())) {
      closeWatcher(dir);
    }
  }

  refresh();

  return {
    getState: () => currentState,
    refresh,
    dispose,
    candidates,
  };
}

function resolveV2SessionInfo(api) {
  try {
    const route = api?.ui?.router?.current?.();
    const sessionID =
      route?.type === "session" && typeof route.sessionID === "string"
        ? route.sessionID
        : undefined;
    if (!sessionID) return { sessionID: undefined, rootSessionID: undefined };

    let cur = sessionID;
    const seen = new Set();
    while (typeof cur === "string" && !seen.has(cur)) {
      seen.add(cur);
      const sess = api?.data?.session?.get?.(cur);
      if (!sess || !sess.parentID) {
        return { sessionID, rootSessionID: cur };
      }
      cur = sess.parentID;
    }
    return { sessionID, rootSessionID: sessionID };
  } catch {
    return { sessionID: undefined, rootSessionID: undefined };
  }
}

function resolveV1SessionInfo(api) {
  try {
    const route = api?.route?.current;
    const sessionID =
      route?.name === "session" && typeof route?.params?.sessionID === "string"
        ? route.params.sessionID
        : undefined;
    if (!sessionID) return { sessionID: undefined, rootSessionID: undefined };

    const sess = api?.state?.session?.get?.(sessionID);
    const rootSessionID =
      typeof sess?.parentID === "string" && sess.parentID
        ? sess.parentID
        : sessionID;
    return { sessionID, rootSessionID };
  } catch {
    return { sessionID: undefined, rootSessionID: undefined };
  }
}

function maybeNotifyAlert(api, prevState, nextState) {
  const prevQ = prevState?.quarantined ?? 0;
  const nextQ = nextState?.quarantined ?? 0;
  if (nextQ <= prevQ) return;

  const message = `Hyphae: ${nextQ} held by Security Gate — run \`hyp gate review\``;
  try {
    if (typeof api?.ui?.toast === "function") {
      api.ui.toast({ title: "Hyphae", message, variant: "warning" });
    } else if (typeof api?.client?.tui?.showToast === "function") {
      void Promise.resolve(
        api.client.tui.showToast({
          body: { title: "Hyphae", message, variant: "warning" },
        }),
      ).catch(() => {});
    }
  } catch {
    // Fail-safe on optional toast surface.
  }
}

/**
 * OpenCode v2 TUI plugin entry (`setup(api)`).
 * Zero-polling: driven exclusively by `fs.watch` on `<state_dir>/ui/` and `api.data.listen`.
 */
export function setup(api) {
  let prevState = null;
  const controller = createHyphaeTuiController({
    getSessionInfo: () => resolveV2SessionInfo(api),
    onUpdate: (nextState) => {
      maybeNotifyAlert(api, prevState, nextState);
      prevState = nextState;
    },
  });

  let slotDispose = null;
  if (typeof api?.ui?.slot === "function") {
    try {
      const reg = api.ui.slot("sidebar.content", {
        id: "hyphae-status",
        title: "Hyphae",
        render: () => {
          const st = controller.getState();
          return {
            statusLine: st.statusLine,
            lines: st.sidebarLines,
          };
        },
      });
      if (typeof reg === "function") {
        slotDispose = reg;
      } else if (typeof reg?.dispose === "function") {
        slotDispose = () => reg.dispose();
      }
    } catch {
      // Fail-safe if OpenCode TUI slot signature differs in a future build.
    }
  }

  let unlisten = null;
  if (typeof api?.data?.listen === "function") {
    try {
      unlisten = api.data.listen(() => {
        controller.refresh();
      });
    } catch {
      unlisten = null;
    }
  }

  return () => {
    controller.dispose();
    try {
      if (typeof unlisten === "function") unlisten();
    } catch {
      // Ignore listener teardown errors.
    }
    try {
      if (typeof slotDispose === "function") slotDispose();
    } catch {
      // Ignore slot teardown errors.
    }
  };
}

/**
 * OpenCode v1 TUI plugin entry (`tui(api)`).
 * Zero-polling: driven exclusively by `fs.watch` on `<state_dir>/ui/` and TUI events.
 */
export async function tui(api) {
  let prevState = null;
  const controller = createHyphaeTuiController({
    getSessionInfo: () => resolveV1SessionInfo(api),
    onUpdate: (nextState) => {
      maybeNotifyAlert(api, prevState, nextState);
      prevState = nextState;
    },
  });

  if (typeof api?.slots?.register === "function") {
    try {
      api.slots.register({
        id: "hyphae-status",
        slot: "sidebar_content",
        render: () => {
          const st = controller.getState();
          return {
            statusLine: st.statusLine,
            lines: st.sidebarLines,
          };
        },
      });
    } catch {
      // Fail-safe across TUI versions.
    }
  }

  let offEvent = null;
  if (typeof api?.event?.on === "function") {
    try {
      offEvent = api.event.on("route.change", () => controller.refresh());
    } catch {
      offEvent = null;
    }
  }

  const cleanup = () => {
    controller.dispose();
    try {
      if (typeof offEvent === "function") offEvent();
    } catch {
      // Ignore event teardown errors.
    }
  };

  if (typeof api?.lifecycle?.onDispose === "function") {
    api.lifecycle.onDispose(cleanup);
  }
  return cleanup;
}

export default {
  id: "hyphae.opencode.tui",
  // Dependency-free dual-surface entry: OpenCode v2 invokes `setup(api)`
  // while OpenCode v1 invokes `tui(api)`.
  setup,
  tui,
};
