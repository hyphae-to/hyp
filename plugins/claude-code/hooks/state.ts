// Pure, metadata-only Hyphae UI state helpers for the Claude Code side-panel mod.
//
// Security invariants:
//   - Consumes strictly metadata-only snapshots (`<state_dir>/ui/state.json`).
//   - Strips forbidden body/payload/note/secret fields recursively as defense-in-depth.
//   - Strips ANSI escape sequences (OSC/CSI/DCS/ESC), C0/C1 control characters,
//     zero-width characters, and Unicode BiDi override/isolate characters from all
//     untrusted external strings before rendering.
//   - Builds strict argv arrays (never shell strings) for `hyp session` quick controls,
//     inserting `--` before any positional argument starting with `-`.

import { parseKvInspection, type KvInspection } from './kv-view.mjs';
import { parseSnapshotMetadata, sanitizeControlValue, sanitizeUiText } from './ui-snapshot.mjs';
export { resolveUiStateCandidates, sanitizeControlValue, sanitizeUiText, stripMetadataOnly } from './ui-snapshot.mjs';

export type PanelTab = 'subs' | 'queue' | 'rules' | 'mesh' | 'kv';

export interface DaemonSummary {
  online: boolean;
  pid: number;
  nodeId: string;
  rawNodeId?: string;
  version: string;
  profile: string;
  peersOnline: number;
  quarantinedGlobal: number;
}

export interface SessionCounts {
  subscriptions: number;
  bridges: number;
  queued: number;
  unnotified: number;
  quarantined: number;
  mutedRules: number;
  mutedArchived: number;
  channels: number;
}

export interface BridgeLinkSummary {
  plugin: string;
  target: string;
  label: string;
  role: 'primary' | 'reader';
}

export interface UnreadBreakdown {
  messages: number;
  events: number;
  plugins: number;
  transfers: number;
  kv: number;
  sources: string[];
}

export interface SubscriptionSummary {
  id: string;
  rawId?: string;
  key: string | null;
  rawKey?: string | null;
  originNode: string;
  topic: string;
  mode: string;
  coalesceSeconds: number;
  filterSummary: string;
}

export interface QueuedItemMeta {
  receipt: string;
  kind: string;
  source: string;
  originNode: string;
  receivedAt: number;
  notified: boolean;
  urgency: string;
}

export interface MuteSummary {
  pattern: string;
  rawPattern?: string;
  scope: 'session' | 'connector';
  mutedAt: number;
}

export interface DeliveryRuleSummary {
  target: string;
  rawTarget?: string;
  delivery: string;
}

export interface ChannelEntrySummary {
  hostNode: string;
  rawHostNode?: string;
  channel: string;
  rawChannel?: string;
  mode: string;
}

export interface SessionDetails {
  bridges: BridgeLinkSummary[];
  subscriptions: SubscriptionSummary[];
  queuedItems: QueuedItemMeta[];
  mutes: MuteSummary[];
  rules: DeliveryRuleSummary[];
  channels: string[];
  rawChannels?: string[];
  channelEntries: ChannelEntrySummary[];
}

export interface SessionSummary {
  sessionId: string;
  harness: string;
  enrolled: boolean;
  handle: string | null;
  address: string | null;
  lastSeen: number;
  transportKind: string | null;
  hasLiveTransport: boolean;
  deliveryMode: string;
  focusMode: boolean;
  focusAllowInterruptVips: boolean;
  mutedAll: boolean;
  bridges: string[];
  counts: SessionCounts;
  unreadBreakdown: UnreadBreakdown;
  details: SessionDetails;
}

export interface HyphaeSnapshot {
  schemaVersion: number;
  rev: number;
  updatedAt: number;
  daemon: DaemonSummary | null;
  sessions: SessionSummary[];
  kv: KvInspection | null;
}

export interface ResolvedSessionResult {
  active: SessionSummary | null;
  matchedBy: 'selected' | 'env' | 'claude' | 'none';
  sessions: SessionSummary[];
}

export type SessionControlAction =
  | { kind: 'focus'; enabled: boolean }
  | { kind: 'unsubscribe'; id: string }
  | { kind: 'mute'; pattern: string; scope?: 'session' | 'connector' }
  | { kind: 'unmute'; pattern: string; scope?: 'session' | 'connector' }
  | { kind: 'leave'; channel: string }
  | { kind: 'rule'; target: string; delivery: 'interrupt' | 'queue' | 'notify' | 'mute' };

export interface SessionControlTarget {
  sessionId?: string | null;
  handle?: string | null;
}

/**
 * Qualifies a channel target as `<hostNode>/<channel>` so `hyp session leave`
 * targets the exact host node and never resolves bare `#channel` to a default Hub.
 */
export function qualifyChannelTarget(
  hostNode: string | null | undefined,
  channel: string,
  fallbackNodeId?: string | null,
): string {
  const cleanChannel = sanitizeControlValue(channel);
  if (!cleanChannel) return '';
  if (cleanChannel.includes('/')) return cleanChannel;
  const cleanHost = sanitizeControlValue(hostNode) || sanitizeControlValue(fallbackNodeId) || 'local';
  return `${cleanHost}/${cleanChannel}`;
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function asNum(value: unknown, fallback = 0): number {
  const n = Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function asCount(value: unknown): number {
  return Math.max(0, Math.floor(asNum(value, 0)));
}

function asStr(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

function parseSessionSummary(raw: unknown): SessionSummary | null {
  const obj = asRecord(raw);
  if (!obj) return null;
  const sessionId = sanitizeControlValue(obj.sessionId);
  if (!sessionId) return null;

  const countsObj = asRecord(obj.counts);
  const unreadObj = asRecord(obj.unreadBreakdown);
  const detailsObj = asRecord(obj.details);

  const rawBridges = Array.isArray(detailsObj?.bridges) ? detailsObj.bridges : [];
  const bridges: BridgeLinkSummary[] = [];
  for (const item of rawBridges) {
    const b = asRecord(item);
    if (!b) continue;
    const plugin = sanitizeUiText(b.plugin, 40);
    const target = sanitizeUiText(b.target, 64);
    const label = sanitizeUiText(b.label, 96) || (plugin && target ? `${plugin}:${target}` : plugin || target);
    if (!label) continue;
    bridges.push({
      plugin: plugin || label.split(':')[0] || 'bridge',
      target: target || label.split(':').slice(1).join(':') || '*',
      label,
      role: b.role === 'primary' ? 'primary' : 'reader',
    });
  }

  const rawCompactBridges = Array.isArray(obj.bridges) ? obj.bridges : [];
  const compactBridges = rawCompactBridges
    .map((b) => sanitizeUiText(b, 96))
    .filter((b) => b.length > 0);
  const effectiveBridgeLabels =
    compactBridges.length > 0 ? compactBridges : bridges.map((b) => b.label);

  const rawSubs = Array.isArray(detailsObj?.subscriptions) ? detailsObj.subscriptions : [];
  const subscriptions: SubscriptionSummary[] = [];
  for (const item of rawSubs) {
    const s = asRecord(item);
    if (!s) continue;
    const rawId = sanitizeControlValue(s.id);
    const rawKey = typeof s.key === 'string' && s.key.trim() ? sanitizeControlValue(s.key) : null;
    const rawTopic = sanitizeControlValue(s.topic);
    const id = sanitizeUiText(s.id, 128);
    const topic = sanitizeUiText(s.topic, 120);
    if (!rawId && !rawTopic) continue;
    subscriptions.push({
      id: id || topic,
      rawId: rawId || rawKey || rawTopic,
      key: rawKey ? sanitizeUiText(rawKey, 80) : null,
      rawKey,
      originNode: sanitizeUiText(s.originNode, 64) || 'local',
      topic: topic || id,
      mode: sanitizeUiText(s.mode, 24) || 'queue',
      coalesceSeconds: asCount(s.coalesceSeconds),
      filterSummary: sanitizeUiText(s.filterSummary, 140),
    });
  }

  const rawQueued = Array.isArray(detailsObj?.queuedItems) ? detailsObj.queuedItems : [];
  const queuedItems: QueuedItemMeta[] = [];
  for (const item of rawQueued) {
    const q = asRecord(item);
    if (!q) continue;
    queuedItems.push({
      receipt: sanitizeUiText(q.receipt, 64),
      kind: sanitizeUiText(q.kind, 24) || 'message',
      source: sanitizeUiText(q.source, 96) || 'unknown',
      originNode: sanitizeUiText(q.originNode, 64),
      receivedAt: asNum(q.receivedAt, 0),
      notified: Boolean(q.notified),
      urgency: sanitizeUiText(q.urgency, 24) || 'queue',
    });
  }

  const rawMutes = Array.isArray(detailsObj?.mutes) ? detailsObj.mutes : [];
  const mutes: MuteSummary[] = [];
  for (const item of rawMutes) {
    const m = asRecord(item);
    if (!m) continue;
    const rawPattern = sanitizeControlValue(m.pattern);
    if (!rawPattern) continue;
    mutes.push({
      pattern: sanitizeUiText(rawPattern, 120),
      rawPattern,
      scope: m.scope === 'connector' ? 'connector' : 'session',
      mutedAt: asNum(m.mutedAt, 0),
    });
  }

  const rawRules = Array.isArray(detailsObj?.rules) ? detailsObj.rules : [];
  const rules: DeliveryRuleSummary[] = [];
  for (const item of rawRules) {
    const r = asRecord(item);
    if (!r) continue;
    const rawTarget = sanitizeControlValue(r.target);
    if (!rawTarget) continue;
    rules.push({
      target: sanitizeUiText(rawTarget, 120),
      rawTarget,
      delivery: sanitizeUiText(r.delivery, 24) || 'queue',
    });
  }

  const rawChannelsList = Array.isArray(detailsObj?.channels) ? detailsObj.channels : [];
  const rawChannels = rawChannelsList
    .map((c) => sanitizeControlValue(c))
    .filter((c) => c.length > 0);
  const channels = rawChannels.map((c) => sanitizeUiText(c, 96));

  const rawChanEntries = Array.isArray(detailsObj?.channelEntries) ? detailsObj.channelEntries : [];
  const channelEntries: ChannelEntrySummary[] = [];
  for (const item of rawChanEntries) {
    const c = asRecord(item);
    if (!c) continue;
    const rawChannel = sanitizeControlValue(c.channel);
    if (!rawChannel) continue;
    const rawHostNode = sanitizeControlValue(c.hostNode) || 'local';
    channelEntries.push({
      hostNode: sanitizeUiText(rawHostNode, 64) || 'local',
      rawHostNode,
      channel: sanitizeUiText(rawChannel, 96),
      rawChannel,
      mode: sanitizeUiText(c.mode, 24) || 'open',
    });
  }

  const rawSources = Array.isArray(unreadObj?.sources) ? unreadObj.sources : [];
  const sources = rawSources.map((s) => sanitizeUiText(s, 80)).filter((s) => s.length > 0);

  const handleRaw = typeof obj.handle === 'string' && obj.handle.trim() ? sanitizeUiText(obj.handle, 48) : null;
  const addressRaw = typeof obj.address === 'string' && obj.address.trim() ? sanitizeUiText(obj.address, 96) : null;
  const transportRaw =
    typeof obj.transportKind === 'string' && obj.transportKind.trim()
      ? sanitizeUiText(obj.transportKind, 32)
      : null;

  return {
    sessionId,
    harness: sanitizeUiText(obj.harness, 32) || 'unknown',
    enrolled: Boolean(obj.enrolled),
    handle: handleRaw,
    address: addressRaw,
    lastSeen: asNum(obj.lastSeen, 0),
    transportKind: transportRaw,
    hasLiveTransport: Boolean(obj.hasLiveTransport),
    deliveryMode: sanitizeUiText(obj.deliveryMode, 24) || 'queue',
    focusMode: Boolean(obj.focusMode),
    focusAllowInterruptVips: Boolean(obj.focusAllowInterruptVips),
    mutedAll: Boolean(obj.mutedAll),
    bridges: effectiveBridgeLabels,
    counts: {
      subscriptions: asCount(countsObj?.subscriptions ?? subscriptions.length),
      bridges: asCount(countsObj?.bridges ?? Math.max(bridges.length, effectiveBridgeLabels.length)),
      queued: asCount(countsObj?.queued ?? queuedItems.length),
      unnotified: asCount(countsObj?.unnotified ?? 0),
      quarantined: asCount(countsObj?.quarantined ?? 0),
      mutedRules: asCount(countsObj?.mutedRules ?? mutes.length),
      mutedArchived: asCount(countsObj?.mutedArchived ?? 0),
      channels: asCount(countsObj?.channels ?? (channelEntries.length || channels.length)),
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
      rawChannels,
      channelEntries,
    },
  };
}

/**
 * Parses either raw `<state_dir>/ui/state.json` or a `hyp inspect --all --json`
 * CLI envelope into a strictly sanitized, metadata-only `HyphaeSnapshot`.
 */
export function parseSnapshotJson(rawText: string): HyphaeSnapshot | null {
  const root = parseSnapshotMetadata(rawText);
  if (!root) return null;

  const daemonObj = asRecord(root.daemon);
  const rawNodeId = daemonObj ? sanitizeControlValue(daemonObj.nodeId) || 'local' : 'local';
  const daemon: DaemonSummary | null = daemonObj
    ? {
        online: Boolean(daemonObj.online),
        pid: asCount(daemonObj.pid),
        nodeId: sanitizeUiText(rawNodeId, 64) || 'local',
        rawNodeId,
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
  const sessions: SessionSummary[] = [];
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
    kv: parseKvInspection(root.kv),
  };
}

/**
 * Matches the active Claude Code session against the snapshot:
 *   1. User-selected session ID override (when inspecting another session in multi-session view)
 *   2. Exact `$HYPHAE_SESSION_ID` match (e.g. `claude:<id>`)
 *   3. `claude:<claudeSessionId>` or raw `<claudeSessionId>` match
 *   4. Otherwise returns `active: null` so the UI degrades cleanly to all-sessions summary.
 */
export function resolveActiveSession(
  snapshot: HyphaeSnapshot | null,
  claudeSessionId: string | null | undefined,
  envHyphaeSessionId?: string | null,
  selectedSessionId?: string | null,
): ResolvedSessionResult {
  const sessions = snapshot?.sessions ?? [];
  if (sessions.length === 0) {
    return { active: null, matchedBy: 'none', sessions };
  }

  if (selectedSessionId) {
    const sel = sessions.find((s) => s.sessionId === selectedSessionId);
    if (sel) return { active: sel, matchedBy: 'selected', sessions };
  }

  const envId = typeof envHyphaeSessionId === 'string' ? envHyphaeSessionId.trim() : '';
  if (envId) {
    const envMatch = sessions.find((s) => s.sessionId === envId);
    if (envMatch) return { active: envMatch, matchedBy: 'env', sessions };
  }

  const rawClaude = typeof claudeSessionId === 'string' ? claudeSessionId.trim() : '';
  if (rawClaude) {
    const prefixed = rawClaude.startsWith('claude:') ? rawClaude : `claude:${rawClaude}`;
    const exactPrefixed = sessions.find((s) => s.sessionId === prefixed);
    if (exactPrefixed) return { active: exactPrefixed, matchedBy: 'claude', sessions };

    const exactRaw = sessions.find((s) => s.sessionId === rawClaude);
    if (exactRaw) return { active: exactRaw, matchedBy: 'claude', sessions };
  }

  return { active: null, matchedBy: 'none', sessions };
}

/**
 * Consistently computes `max(session.counts.quarantined, daemon.quarantinedGlobal)`
 * across status bars and panels (never exposes quarantined payloads or sources).
 */
export function getQuarantinedCount(
  snapshot: HyphaeSnapshot | null,
  active: SessionSummary | null,
): number {
  const globalCount = snapshot?.daemon?.quarantinedGlobal ?? 0;
  const sessionCount = active?.counts.quarantined ?? 0;
  return Math.max(sessionCount, globalCount);
}

/**
 * Formats a past epoch millisecond timestamp as a short relative age (`now`, `12s`, `4m`, `2h`, `3d`).
 */
export function formatRelativeAge(tsMs: number, nowMs: number): string {
  if (!Number.isFinite(tsMs) || tsMs <= 0) return '';
  const deltaSec = Math.max(0, Math.floor((nowMs - tsMs) / 1000));
  if (deltaSec < 5) return 'now';
  if (deltaSec < 60) return `${deltaSec}s`;
  const mins = Math.floor(deltaSec / 60);
  if (mins < 60) return `${mins}m`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 48) return `${hrs}h`;
  return `${Math.floor(hrs / 24)}d`;
}

function assertSafeArgValue(raw: string, label: string): string {
  const trimmed = raw.trim();
  if (!trimmed) {
    throw new Error(`Empty ${label} argument`);
  }
  if (/[\u0000-\u001f\u007f]/.test(trimmed)) {
    throw new Error(`Control characters not allowed in ${label}`);
  }
  return trimmed;
}

function pushPositional(args: string[], value: string, label: string): void {
  const clean = assertSafeArgValue(value, label);
  if (clean.startsWith('-')) {
    args.push('--', clean);
  } else {
    args.push(clean);
  }
}

/**
 * Builds deterministic `['hyp', 'session', ...]` argv arrays for quick controls.
 * NEVER uses shell string interpolation and guards flag-like positional arguments with `--`.
 */
export function buildSessionControlArgs(
  action: SessionControlAction,
  target: SessionControlTarget,
): string[] {
  const targetArgs: string[] = [];
  if (target.sessionId && target.sessionId.trim()) {
    targetArgs.push('--session', assertSafeArgValue(target.sessionId, 'sessionId'));
  } else if (target.handle && target.handle.trim()) {
    targetArgs.push('--handle', assertSafeArgValue(target.handle, 'handle'));
  }

  switch (action.kind) {
    case 'focus':
      return ['hyp', 'session', 'focus', ...targetArgs, action.enabled ? 'on' : 'off', '--json'];
    case 'unsubscribe': {
      const args = ['hyp', 'session', 'unsubscribe', ...targetArgs, '--json'];
      pushPositional(args, action.id, 'subscription id');
      return args;
    }
    case 'mute': {
      const args = ['hyp', 'session', 'mute', ...targetArgs];
      if (action.scope === 'connector') args.push('--scope', 'connector');
      args.push('--json');
      pushPositional(args, action.pattern, 'mute pattern');
      return args;
    }
    case 'unmute': {
      const args = ['hyp', 'session', 'unmute', ...targetArgs];
      if (action.scope === 'connector') args.push('--scope', 'connector');
      args.push('--json');
      pushPositional(args, action.pattern, 'unmute pattern');
      return args;
    }
    case 'leave': {
      const args = ['hyp', 'session', 'leave', ...targetArgs, '--json'];
      pushPositional(args, action.channel, 'channel');
      return args;
    }
    case 'rule': {
      const args = ['hyp', 'session', 'rule', ...targetArgs, '--json'];
      pushPositional(args, action.target, 'rule target');
      args.push(assertSafeArgValue(action.delivery, 'delivery urgency'));
      return args;
    }
  }
}

/**
 * Parses a `hyp --json` command result into a concise, sanitized status message.
 */
export function parseControlCommandResult(
  exitCode: number,
  stdout: string,
  stderr: string,
  actionLabel: string,
): { ok: boolean; message: string } {
  let parsed: Record<string, unknown> | null = null;
  try {
    parsed = asRecord(JSON.parse(stdout || 'null'));
  } catch {
    parsed = null;
  }

  if (exitCode !== 0 || (parsed && parsed.ok === false)) {
    const errObj = asRecord(parsed?.error);
    const errText =
      asStr(errObj?.message) ||
      (typeof parsed?.error === 'string' ? parsed.error : '') ||
      stderr.trim() ||
      `${actionLabel} failed (exit ${exitCode})`;
    return { ok: false, message: sanitizeUiText(errText, 140) };
  }

  const summary = asStr(parsed?.summary);
  return {
    ok: true,
    message: sanitizeUiText(summary || `${actionLabel} applied`, 140),
  };
}

export interface HerdrModDetectionEnv {
  homeDir?: string;
  herdrAppHome?: string;
  hcTerminalId?: string;
  hcTerminalSocket?: string;
  cfBundleId?: string;
  panelStatusEnv?: string;
}

/**
 * Determines whether the inline prompt status strip should be auto-suppressed because
 * the session is running inside Herdr with the native Hyphae Herdr mod active
 * (or because `HYPHAE_PANEL_STATUS=off` was explicitly set).
 */
export async function shouldSuppressPromptStrip(
  env: HerdrModDetectionEnv,
  readText: (path: string) => Promise<string | null>,
): Promise<boolean> {
  const override = (env.panelStatusEnv ?? '').trim().toLowerCase();
  if (override === 'off' || override === '0' || override === 'false') {
    return true;
  }
  if (override === 'on' || override === '1' || override === 'true') {
    return false;
  }

  const inHerdr = Boolean(
    (env.hcTerminalId && env.hcTerminalId.trim()) ||
      (env.hcTerminalSocket && env.hcTerminalSocket.trim()) ||
      (env.cfBundleId && env.cfBundleId.trim() === 'dev.herdr.app'),
  );
  if (!inHerdr) {
    return false;
  }

  const baseHerdr = (env.herdrAppHome ?? '').trim().replace(/[\\/]+$/, '') ||
    (env.homeDir ? `${env.homeDir.replace(/[\\/]+$/, '')}/.config/herdr-app` : '');
  if (!baseHerdr) {
    return false;
  }

  // 1. Live mod advertisement in Herdr's persisted `shared.json` (`hyphae.modActive` or `workspace.panels`).
  const sharedRaw = await readText(`${baseHerdr}/shared.json`);
  let activeLayout: string | null = null;
  if (sharedRaw) {
    try {
      const parsed = asRecord(JSON.parse(sharedRaw));
      if (parsed) {
        const modActive = asRecord(parsed['hyphae.modActive']);
        if (modActive && (modActive.pane === true || modActive.panel === true)) {
          return true;
        }
        const panels = parsed['workspace.panels'];
        if (Array.isArray(panels) && panels.some((p) => p === 'hyphae')) {
          return true;
        }
        activeLayout = asStr(parsed.layout) || null;
      }
    } catch {
      // Malformed shared.json: fall through to installed mod manifest check.
    }
  }

  // 2. Installed native Herdr mod files (`mods/hyphae-pane/mod.json` or `mods/hyphae-panel/mod.json`).
  const [paneMod, panelMod] = await Promise.all([
    readText(`${baseHerdr}/mods/hyphae-pane/mod.json`),
    readText(`${baseHerdr}/mods/hyphae-panel/mod.json`),
  ]);
  if (!paneMod && !panelMod) {
    return false;
  }

  if (activeLayout && !/[\\/]|^\.\.?$/.test(activeLayout)) {
    const layoutRaw = await readText(`${baseHerdr}/layouts/${activeLayout}.json`);
    if (layoutRaw !== null) {
      return layoutRaw.includes('hyphae-pane') || layoutRaw.includes('hyphae-panel');
    }
  }
  return true;
}

/**
 * Formats the quiet, compact status indicator rendered in `AbovePrompt` outside Herdr.
 * Returns `undefined` when the current session is unenrolled and has no alerts (zero clutter).
 */
export function formatPersistentStatusLine(
  snapshot: HyphaeSnapshot | null,
  active: SessionSummary | null,
  quarantined: number,
): string | undefined {
  if (quarantined > 0) {
    return `⚠ ${quarantined} held · hyp gate review`;
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

  const parts: string[] = [];
  if (active.handle) {
    parts.push(`@${active.handle}`);
  }

  const firstBridge = active.bridges[0];
  if (firstBridge && active.bridges.length === 1) {
    parts.push(firstBridge);
  } else if (firstBridge && active.bridges.length > 1) {
    parts.push(`${firstBridge} +${active.bridges.length - 1}`);
  } else if (active.counts.bridges > 0) {
    parts.push(active.counts.bridges === 1 ? '1 bridge' : `${active.counts.bridges} bridges`);
  }

  if (active.counts.subscriptions > 0) {
    parts.push(
      active.counts.subscriptions === 1 ? '1 sub' : `${active.counts.subscriptions} subs`,
    );
  }
  if (active.counts.queued > 0) {
    parts.push(`${active.counts.queued} queued`);
  }
  if (active.focusMode) {
    parts.push('focus');
  }
  if (active.mutedAll) {
    parts.push('muted');
  } else if (active.counts.mutedRules > 0) {
    parts.push(`${active.counts.mutedRules} muted`);
  }

  if (parts.length === 0) {
    return undefined;
  }
  return parts.join(' · ');
}

/**
 * Parses optional `/hyp-panel` command arguments.
 */
export function parsePanelCommandArgs(
  rawArgs: string,
):
  | { action: 'open'; tab?: PanelTab }
  | { action: 'close' }
  | { action: 'status'; enabled: boolean } {
  const tokens = rawArgs.trim().toLowerCase().split(/\s+/).filter(Boolean);
  if (tokens.length === 0) return { action: 'open' };
  const first = tokens[0];
  if (first === 'close' || first === 'hide') {
    return { action: 'close' };
  }
  if (first === 'status' || first === 'strip' || first === 'badge') {
    const second = tokens[1];
    return { action: 'status', enabled: second !== 'off' && second !== 'false' && second !== '0' };
  }
  if (first === 'subs' || first === 'subscriptions' || first === 'bridges' || first === 'links') {
    return { action: 'open', tab: 'subs' };
  }
  if (first === 'queue' || first === 'inbox') return { action: 'open', tab: 'queue' };
  if (first === 'rules' || first === 'mutes') return { action: 'open', tab: 'rules' };
  if (first === 'mesh' || first === 'channels') return { action: 'open', tab: 'mesh' };
  if (first === 'kv') return { action: 'open', tab: 'kv' };
  return { action: 'open' };
}
