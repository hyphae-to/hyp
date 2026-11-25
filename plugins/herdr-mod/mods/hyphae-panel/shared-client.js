// Pure-JS Hyphae UI state client shared by `hyphae-pane` and `hyphae-panel`.
//
// Security invariant: consumes strictly metadata-only snapshots (`ui/state.json`
// locally via `watchFolder` + `readTextFile`, and `hyp inspect --all --json` on
// remote SSH machines via `exec(..., { on: machine })`). Never renders or retains
// message bodies, CloudEvent `data`, wakeup `note`s, quarantined text, or secrets.

const REMOTE_REFRESH_MS = 10_000;
const REMOTE_MAX_BACKOFF_MS = 60_000;
const REMOTE_CACHE_KEY = "hyphae.remoteCache";
const CONTROL_TIMEOUT_MS = 10_000;
const REMOTE_INSPECT_TIMEOUT_MS = 8_000;

const FORBIDDEN_BODY_KEYS = new Set([
  "body",
  "text",
  "note",
  "payload",
  "ciphertext",
  "secret",
  "token",
]);

/**
 * Strips ANSI escape sequences and C0/C1 control characters from untrusted
 * metadata fields (`handle`, `topic`, `source`, `channel`, `label`) before display.
 */
export function sanitizeUiText(raw, maxLen = 120) {
  if (raw === null || raw === undefined) return "";
  const str = String(raw)
    // Strip OSC sequences (\x1b] ... \x07 or \x1b\\)
    .replace(/\u001b\][^\u0007\u001b]*(?:\u0007|\u001b\\)/g, "")
    // Strip CSI sequences (\x1b[ ... final byte)
    .replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, "")
    // Strip remaining ESC and C0/C1 control characters
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, "")
    .trim();
  if (str.length <= maxLen) return str;
  return str.slice(0, Math.max(0, maxLen - 1)) + "…";
}

/**
 * Appends a 2-digit hex alpha suffix only when `color` is a plain `#rrggbb` value.
 */
export function withAlpha(color, hexAlpha) {
  if (typeof color === "string" && /^#[0-9a-fA-F]{6}$/.test(color)) {
    return `${color}${hexAlpha}`;
  }
  return color;
}

/**
 * Parses a Herdr terminal address into `{ machine, rawTid, address }`.
 * - `"t4g"` -> `{ machine: null, rawTid: "t4g", address: "t4g" }`
 * - `"solace/t4g"` -> `{ machine: "solace", rawTid: "t4g", address: "solace/t4g" }`
 */
export function parseTerminalAddress(terminal) {
  if (typeof terminal !== "string") {
    return { machine: null, rawTid: null, address: null };
  }
  const trimmed = terminal.trim();
  if (!trimmed) {
    return { machine: null, rawTid: null, address: null };
  }
  const slash = trimmed.indexOf("/");
  if (slash === -1) {
    return { machine: null, rawTid: trimmed, address: trimmed };
  }
  const machine = trimmed.slice(0, slash).trim();
  const rawTid = trimmed.slice(slash + 1).trim();
  if (!machine || !rawTid) {
    return { machine: null, rawTid: rawTid || trimmed, address: trimmed };
  }
  return { machine, rawTid, address: `${machine}/${rawTid}` };
}

/**
 * Resolves ordered candidate `<state_dir>/ui` directories and `state.json` paths,
 * faithful to `crates/hyp-cli/src/config_file.rs` (`resolve_state_dir`).
 *
 * Default `state_dir` is `~/.config/hyphae` -> `~/.config/hyphae/ui/state.json`.
 * If `node.json` specifies `stateDir`, `<stateDir>/ui` takes highest precedence.
 * Also includes `~/.config/hyphae/state/ui` as a fallback for custom layouts.
 */
export function resolveUiStateCandidates(homeDir, nodeJsonText = null) {
  const baseHome = typeof homeDir === "string" ? homeDir.replace(/[\\/]+$/, "") : "";
  const cfgDir = `${baseHome}/.config/hyphae`;
  const dirs = [];

  const pushDir = (dir) => {
    if (!dir) return;
    const normalized = dir.replace(/\/+$/, "");
    if (!dirs.includes(normalized)) dirs.push(normalized);
  };

  if (typeof nodeJsonText === "string" && nodeJsonText.trim()) {
    try {
      const parsed = JSON.parse(nodeJsonText);
      const sd = parsed && typeof parsed.stateDir === "string" ? parsed.stateDir.trim() : "";
      if (sd) {
        let resolved;
        if (sd === "~") {
          resolved = baseHome;
        } else if (sd.startsWith("~/")) {
          resolved = `${baseHome}/${sd.slice(2)}`;
        } else if (sd.startsWith("/") || /^[A-Za-z]:[\\/]/.test(sd)) {
          resolved = sd;
        } else {
          resolved = `${cfgDir}/${sd}`;
        }
        pushDir(`${resolved.replace(/[\\/]+$/, "")}/ui`);
      }
    } catch {
      // Ignore malformed config and fall back to default paths.
    }
  }

  pushDir(`${cfgDir}/ui`);
  pushDir(`${cfgDir}/state/ui`);

  return {
    dirs,
    files: dirs.map((d) => `${d}/state.json`),
  };
}

/**
 * Recursively strips any forbidden body/secret keys as defense-in-depth so UI
 * code can never accidentally retain or render untrusted message contents.
 */
function stripMetadataOnly(value) {
  if (Array.isArray(value)) return value.map(stripMetadataOnly);
  if (!value || typeof value !== "object") return value;
  const out = {};
  for (const [k, v] of Object.entries(value)) {
    if (FORBIDDEN_BODY_KEYS.has(k)) continue;
    out[k] = stripMetadataOnly(v);
  }
  return out;
}

/**
 * Parses either a raw `<state_dir>/ui/state.json` snapshot or a `hyp inspect --all --json`
 * CLI envelope (`{ ok: true, data: { ... } }`), returning a normalized metadata-only snapshot.
 */
export function parseSnapshotJson(rawText) {
  if (typeof rawText !== "string" || !rawText.trim()) return null;
  let parsed;
  try {
    parsed = JSON.parse(rawText);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object") return null;

  let root = parsed;
  if ("ok" in parsed && parsed.data && typeof parsed.data === "object") {
    if (parsed.ok === false) return null;
    root = parsed.data;
  } else if ("ok" in parsed && parsed.result && typeof parsed.result === "object") {
    if (parsed.ok === false) return null;
    root = parsed.result;
  }

  const sessions = Array.isArray(root.sessions)
    ? root.sessions.filter((s) => s && typeof s === "object").map(stripMetadataOnly)
    : root.session && typeof root.session === "object"
      ? [stripMetadataOnly(root.session)]
      : [];

  const byHerdrTerminal =
    root.byHerdrTerminal && typeof root.byHerdrTerminal === "object" && !Array.isArray(root.byHerdrTerminal)
      ? { ...root.byHerdrTerminal }
      : {};

  return {
    schemaVersion: Number(root.schemaVersion) || 1,
    rev: Number(root.rev) || 0,
    updatedAt: Number(root.updatedAt) || 0,
    daemon: root.daemon && typeof root.daemon === "object" ? stripMetadataOnly(root.daemon) : null,
    sessions,
    byHerdrTerminal,
  };
}

/**
 * Finds a layout tree node by `id` (e.g. `"hyphae"`, `"panel-body"`, `"panel"`).
 */
export function findLayoutNode(node, id) {
  if (!node || typeof node !== "object") return null;
  if (node.id === id) return node;
  const children = Array.isArray(node.children) ? node.children : [];
  for (const child of children) {
    const found = findLayoutNode(child, id);
    if (found) return found;
  }
  return null;
}

function createdMsMatches(expectedCreatedMs, sessionCreatedMs) {
  if (!Number.isFinite(expectedCreatedMs) || !Number.isFinite(sessionCreatedMs)) {
    return true;
  }
  return expectedCreatedMs === sessionCreatedMs;
}

function compareCandidateRank(a, b, expectedCreatedMs) {
  const aExact = Number.isFinite(expectedCreatedMs) && a.herdrCreatedMs === expectedCreatedMs ? 1 : 0;
  const bExact = Number.isFinite(expectedCreatedMs) && b.herdrCreatedMs === expectedCreatedMs ? 1 : 0;
  if (aExact !== bExact) return aExact - bExact;

  const aSeen = Number(a.lastSeen) || 0;
  const bSeen = Number(b.lastSeen) || 0;
  if (aSeen !== bSeen) return aSeen - bSeen;

  const aEnrolled = a.enrolled ? 1 : 0;
  const bEnrolled = b.enrolled ? 1 : 0;
  if (aEnrolled !== bEnrolled) return aEnrolled - bEnrolled;

  const aLive = a.hasLiveTransport ? 1 : 0;
  const bLive = b.hasLiveTransport ? 1 : 0;
  if (aLive !== bLive) return aLive - bLive;

  const aId = String(a.sessionId ?? "");
  const bId = String(b.sessionId ?? "");
  // Tie-break deterministically to match Rust `sess.id < prev_sess.id`.
  if (aId !== bId) return aId < bId ? 1 : -1;
  return 0;
}

/**
 * Resolves the active Hyphae session for a raw Herdr terminal ID (`"t4g"`),
 * honoring `byHerdrTerminal` and anti-recycle `expectedCreatedMs` pinning.
 */
export function resolveSessionForTerminal(snapshot, rawTid, expectedCreatedMs = null) {
  if (!snapshot || !rawTid) return null;
  const sessions = Array.isArray(snapshot.sessions) ? snapshot.sessions : [];
  if (sessions.length === 0) return null;

  const mappedId = snapshot.byHerdrTerminal?.[rawTid];
  if (mappedId) {
    const mapped = sessions.find((s) => s.sessionId === mappedId);
    if (mapped && createdMsMatches(expectedCreatedMs, mapped.herdrCreatedMs)) {
      return mapped;
    }
  }

  let best = null;
  for (const sess of sessions) {
    if (sess.herdrTerminalId !== rawTid) continue;
    if (!createdMsMatches(expectedCreatedMs, sess.herdrCreatedMs)) continue;
    if (!best || compareCandidateRank(sess, best, expectedCreatedMs) > 0) {
      best = sess;
    }
  }
  return best;
}

/**
 * Resolves a session by exact `sessionId`.
 */
export function resolveSessionById(snapshot, sessionId) {
  if (!snapshot || !sessionId) return null;
  const sessions = Array.isArray(snapshot.sessions) ? snapshot.sessions : [];
  return sessions.find((s) => s.sessionId === sessionId) ?? null;
}

/**
 * Computes crisp, metadata-only display metrics for the pane header pill.
 * Returns `{ visible: false, ... }` when the terminal is unenrolled and has
 * zero subscriptions, queued items, and quarantined items (zero visual clutter).
 */
export function formatPillMetrics(entry) {
  if (!entry || typeof entry !== "object") {
    return {
      visible: false,
      enrolled: false,
      handle: null,
      subs: 0,
      queued: 0,
      unnotified: 0,
      quarantined: 0,
      mutedRules: 0,
      channels: 0,
      wakeups: 0,
      focusMode: false,
      mutedAll: false,
      tone: "idle",
      chip: null,
      compactLabel: "",
      mediumLabel: "",
      wideLabel: "",
      alertLabel: null,
    };
  }

  const counts = entry.counts && typeof entry.counts === "object" ? entry.counts : {};
  const subs = Math.max(0, Number(counts.subscriptions) || 0);
  const queued = Math.max(0, Number(counts.queued) || 0);
  const unnotified = Math.max(0, Number(counts.unnotified) || 0);
  const quarantined = Math.max(0, Number(counts.quarantined) || 0);
  const mutedRules = Math.max(0, Number(counts.mutedRules) || 0);
  const channels = Math.max(0, Number(counts.channels) || 0);
  const wakeups = Math.max(0, Number(counts.wakeups) || 0);

  const enrolled = Boolean(entry.enrolled);
  const focusMode = Boolean(entry.focusMode);
  const mutedAll = Boolean(entry.mutedAll);
  const handle = entry.handle ? sanitizeUiText(entry.handle, 32) : null;

  const visible = enrolled || subs > 0 || queued > 0 || quarantined > 0;
  if (!visible) {
    return {
      visible: false,
      enrolled: false,
      handle,
      subs,
      queued,
      unnotified,
      quarantined,
      mutedRules,
      channels,
      wakeups,
      focusMode,
      mutedAll,
      tone: "idle",
      chip: null,
      compactLabel: "",
      mediumLabel: "",
      wideLabel: "",
      alertLabel: null,
    };
  }

  let tone = "active";
  if (quarantined > 0) tone = "alert";
  else if (queued > 0) tone = "queued";
  else if (focusMode) tone = "focus";
  else if (mutedAll) tone = "muted";

  const chip = mutedAll ? "muted" : focusMode ? "focus" : null;
  const alertLabel = quarantined > 0 ? `⚠ ${quarantined}` : null;

  let compactLabel;
  if (queued > 0) {
    compactLabel = `${subs}·${queued}`;
  } else if (subs > 0) {
    compactLabel = `${subs}s`;
  } else {
    compactLabel = handle ? `@${handle}` : "0s";
  }

  const medParts = [];
  if (focusMode) medParts.push("focus");
  if (mutedAll) medParts.push("muted");
  if (subs > 0 || queued === 0) medParts.push(`${subs}s`);
  if (queued > 0) medParts.push(`${queued}q`);
  const mediumLabel = medParts.join(" · ");

  const wideParts = [];
  if (handle) wideParts.push(`@${handle}`);
  if (focusMode) wideParts.push("FOCUS");
  if (mutedAll) wideParts.push("muted*");
  wideParts.push(subs === 1 ? "1 sub" : `${subs} subs`);
  if (queued > 0) wideParts.push(`${queued} queued`);
  const wideLabel = wideParts.join(" · ");

  return {
    visible: true,
    enrolled,
    handle,
    subs,
    queued,
    unnotified,
    quarantined,
    mutedRules,
    channels,
    wakeups,
    focusMode,
    mutedAll,
    tone,
    chip,
    compactLabel,
    mediumLabel,
    wideLabel,
    alertLabel,
  };
}

/**
 * Formats a past epoch millisecond timestamp as a short relative age (`now`, `12s`, `4m`, `2h`, `3d`).
 */
export function formatRelativeAge(tsMs, nowMs = Date.now()) {
  if (!Number.isFinite(tsMs) || tsMs <= 0) return "";
  const deltaSec = Math.max(0, Math.floor((nowMs - tsMs) / 1000));
  if (deltaSec < 5) return "now";
  if (deltaSec < 60) return `${deltaSec}s`;
  const mins = Math.floor(deltaSec / 60);
  if (mins < 60) return `${mins}m`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 48) return `${hrs}h`;
  return `${Math.floor(hrs / 24)}d`;
}

/**
 * Formats a future epoch millisecond timestamp (`in 45s`, `in 12m`, `due`).
 */
export function formatNextFire(tsMs, nowMs = Date.now()) {
  if (!Number.isFinite(tsMs) || tsMs <= 0) return "—";
  const deltaSec = Math.floor((tsMs - nowMs) / 1000);
  if (deltaSec <= 0) return "due";
  if (deltaSec < 60) return `in ${deltaSec}s`;
  const mins = Math.floor(deltaSec / 60);
  if (mins < 60) return `in ${mins}m`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 48) return `in ${hrs}h`;
  return `in ${Math.floor(hrs / 24)}d`;
}

/**
 * Builds deterministic `hyp session <subcmd>` CLI argv for local or remote quick controls.
 */
export function buildSessionControlArgs(action, target, payload = {}) {
  const targetArgs = [];
  if (target?.rawTid) {
    targetArgs.push("--herdr-terminal", String(target.rawTid));
  } else if (target?.sessionId) {
    targetArgs.push("--session", String(target.sessionId));
  } else if (target?.handle) {
    targetArgs.push("--handle", String(target.handle));
  }

  const pushPositional = (arr, val) => {
    const s = String(val);
    if (s.startsWith("-")) arr.push("--", s);
    else arr.push(s);
  };

  switch (action) {
    case "focus":
      return ["session", "focus", ...targetArgs, payload.enabled ? "on" : "off", "--json"];
    case "mute": {
      const args = ["session", "mute", ...targetArgs];
      if (payload.scope === "connector") args.push("--scope", "connector");
      args.push("--json");
      pushPositional(args, payload.pattern);
      return args;
    }
    case "unmute": {
      const args = ["session", "unmute", ...targetArgs];
      if (payload.scope === "connector") args.push("--scope", "connector");
      args.push("--json");
      pushPositional(args, payload.pattern);
      return args;
    }
    case "rule": {
      const args = ["session", "rule", ...targetArgs, "--json"];
      pushPositional(args, payload.target);
      args.push(String(payload.delivery));
      return args;
    }
    case "unsubscribe": {
      const args = ["session", "unsubscribe", ...targetArgs, "--json"];
      pushPositional(args, payload.id ?? payload.key ?? "");
      return args;
    }
    case "leave": {
      const args = ["session", "leave", ...targetArgs, "--json"];
      pushPositional(args, payload.channel);
      return args;
    }
    default:
      throw new Error(`Unsupported session control action: ${action}`);
  }
}

/**
 * Executes a session quick control command via `host.exec` locally or on a remote SSH machine.
 */
export async function executeSessionControl(host, action, target, payload = {}) {
  const args = buildSessionControlArgs(action, target, payload);
  const opts = { timeout: CONTROL_TIMEOUT_MS };
  if (target?.machine) opts.on = target.machine;
  const res = await host.exec("hyp", args, opts);
  let parsed = null;
  try {
    parsed = JSON.parse(res.stdout || "null");
  } catch {
    parsed = null;
  }
  if (res.code !== 0 || (parsed && parsed.ok === false)) {
    const msg =
      parsed?.error?.message ||
      (typeof parsed?.error === "string" ? parsed.error : null) ||
      res.stderr?.trim() ||
      `hyp session ${action} failed (exit ${res.code})`;
    return { ok: false, error: sanitizeUiText(msg, 180), result: parsed };
  }
  return { ok: true, error: null, result: parsed };
}

/**
 * Stateful per-mod-instance Hyphae client handling:
 * - Zero-polling local `watchFolder(<state_dir>/ui)` + `readTextFile(state.json)`
 * - Explicit `watch.cancel()` cleanup via `dispose()` (called from `async close(cx)`)
 * - Deduplicated remote SSH machine cache (`shared("hyphae.remoteCache")`) with backoff
 */
export function createHyphaeClient(host) {
  let localSnapshot = null;
  let localUiDirs = [];
  let activeWatchDir = null;
  let activeWatch = null;
  let watchRunning = false;
  let disposed = false;
  let localLoadInFlight = false;
  const remoteInFlight = new Set();

  async function resolveLocalDirs() {
    if (localUiDirs.length > 0) return localUiDirs;
    const h = host.home();
    let cfgText = await host.readTextFile(`${h}/.config/hyphae/node.json`).catch(() => null);
    if (!cfgText) {
      cfgText = await host.readTextFile(`${h}/.config/hyphae/connector.json`).catch(() => null);
    }
    const { dirs } = resolveUiStateCandidates(h, cfgText);
    localUiDirs = dirs;
    return localUiDirs;
  }

  async function loadLocalOnce() {
    if (disposed || localLoadInFlight) return localSnapshot;
    localLoadInFlight = true;
    try {
      const dirs = await resolveLocalDirs();
      for (const dir of dirs) {
        const text = await host.readTextFile(`${dir}/state.json`).catch(() => null);
        if (text !== null) {
          const snap = parseSnapshotJson(text);
          if (snap) {
            localSnapshot = snap;
            activeWatchDir = dir;
            return localSnapshot;
          }
        }
      }
      if (!activeWatchDir && dirs.length > 0) {
        activeWatchDir = dirs[0];
      }
      return localSnapshot;
    } finally {
      localLoadInFlight = false;
    }
  }

  function startLocalWatch(cx) {
    if (disposed || watchRunning) return;
    watchRunning = true;
    cx.spawn(async (spawnCx) => {
      try {
        await loadLocalOnce();
        if (disposed) return;
        spawnCx.notify();

        while (!disposed) {
          const targetDir = activeWatchDir || (await resolveLocalDirs())[0];
          if (!targetDir) break;
          let watch;
          try {
            watch = host.watchFolder(targetDir);
            activeWatch = watch;
            const changed = await watch;
            activeWatch = null;
            if (disposed) break;
            if (Array.isArray(changed) && changed.length === 0) {
              // Cancelled or reclaimed watch: reload once then exit if disposed.
              if (disposed) break;
            }
            await loadLocalOnce();
            if (!disposed) spawnCx.notify();
          } catch {
            activeWatch = null;
            // Directory may not exist yet (daemon not started); stop tight loop and let gentle timer retry.
            break;
          }
        }
      } finally {
        watchRunning = false;
      }
    });
  }

  function getRemoteCache() {
    const raw = host.shared(REMOTE_CACHE_KEY);
    return raw && typeof raw === "object" && !Array.isArray(raw) ? raw : {};
  }

  function updateRemoteCache(machine, entry) {
    const prev = getRemoteCache();
    host.setShared(REMOTE_CACHE_KEY, { ...prev, [machine]: entry });
  }

  function getSnapshot(machine = null) {
    if (!machine) return localSnapshot;
    const cached = getRemoteCache()[machine];
    return cached?.snapshot ?? null;
  }

  function getRemoteStatus(machine) {
    if (!machine) return null;
    return getRemoteCache()[machine] ?? null;
  }

  function ensureRemoteFresh(machine, cx, force = false) {
    if (!machine || disposed || remoteInFlight.has(machine)) return;
    const now = Date.now();
    const cached = getRemoteCache()[machine];
    const minInterval = cached?.backoffMs || REMOTE_REFRESH_MS;
    if (!force && cached?.fetchedAt && now - cached.fetchedAt < minInterval) {
      return;
    }

    remoteInFlight.add(machine);
    cx.spawn(async (spawnCx) => {
      try {
        const res = await host.exec("hyp", ["inspect", "--all", "--json"], {
          on: machine,
          timeout: REMOTE_INSPECT_TIMEOUT_MS,
        });
        if (disposed) return;
        if (res.code === 0) {
          const snap = parseSnapshotJson(res.stdout);
          if (snap) {
            updateRemoteCache(machine, {
              snapshot: snap,
              fetchedAt: Date.now(),
              backoffMs: REMOTE_REFRESH_MS,
              error: null,
            });
            spawnCx.notify();
            return;
          }
        }
        const prev = getRemoteCache()[machine];
        const nextBackoff = Math.min(
          REMOTE_MAX_BACKOFF_MS,
          (prev?.backoffMs || REMOTE_REFRESH_MS) * 2
        );
        updateRemoteCache(machine, {
          snapshot: prev?.snapshot ?? null,
          fetchedAt: Date.now(),
          backoffMs: nextBackoff,
          error: sanitizeUiText(res.stderr || `hyp inspect failed (${res.code})`, 140),
        });
        spawnCx.notify();
      } catch (err) {
        if (disposed) return;
        const prev = getRemoteCache()[machine];
        const nextBackoff = Math.min(
          REMOTE_MAX_BACKOFF_MS,
          (prev?.backoffMs || REMOTE_REFRESH_MS) * 2
        );
        updateRemoteCache(machine, {
          snapshot: prev?.snapshot ?? null,
          fetchedAt: Date.now(),
          backoffMs: nextBackoff,
          error: sanitizeUiText(String(err), 140),
        });
        spawnCx.notify();
      } finally {
        remoteInFlight.delete(machine);
      }
    });
  }

  function resolveTerminal(terminalAddress) {
    const parsed = parseTerminalAddress(terminalAddress);
    if (!parsed.rawTid) return { ...parsed, entry: null, snapshot: null };
    const snapshot = getSnapshot(parsed.machine);
    let expectedCreatedMs = null;
    if (typeof host.terminals === "function") {
      const term = host.terminals().find((x) => x && x.address === parsed.address);
      if (term && Number.isFinite(term.created_ms)) {
        expectedCreatedMs = term.created_ms;
      }
    }
    const entry = resolveSessionForTerminal(snapshot, parsed.rawTid, expectedCreatedMs);
    return { ...parsed, entry, snapshot };
  }

  function ensureLocal(cx) {
    if (disposed) return;
    if (!watchRunning) {
      startLocalWatch(cx);
    }
  }

  async function refreshNow(machine, cx) {
    if (disposed) return;
    if (!machine) {
      localUiDirs = [];
      await loadLocalOnce();
      if (!watchRunning && !disposed) startLocalWatch(cx);
      if (!disposed) cx.notify();
    } else {
      ensureRemoteFresh(machine, cx, true);
    }
  }

  function dispose() {
    disposed = true;
    if (activeWatch && typeof activeWatch.cancel === "function") {
      try {
        activeWatch.cancel();
      } catch {
        // Ignore already-settled watch cancellation.
      }
    }
    activeWatch = null;
  }

  return {
    ensureLocal,
    ensureRemoteFresh,
    getSnapshot,
    getRemoteStatus,
    resolveTerminal,
    refreshNow,
    dispose,
  };
}
