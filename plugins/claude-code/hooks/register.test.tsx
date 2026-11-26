import { describe, expect, mock, test } from 'claude-code/testing';
import {
  buildSessionControlArgs,
  formatPersistentStatusLine,
  getQuarantinedCount,
  parseSnapshotJson,
  qualifyChannelTarget,
  resolveUiStateCandidates,
  sanitizeUiText,
  shouldSuppressPromptStrip,
} from './state';

const PANE_PROPS = {
  title: 'Hyphae Mesh',
  isFocused: true,
  bodyColumns: 64,
  placement: 'dock' as const,
  scroll: { offset: 0, bodyRows: 36 },
  view: {},
};

const ABOVE_PROMPT_PROPS = {
  bodyColumns: 100,
  isWorking: false,
  maxRows: 3,
  hasSurvey: false,
  isCollapsed: false,
  scroll: { offset: 0, bodyRows: 3 },
  view: {},
};

const VIEWPORT = { columns: 120, rows: 40 };

function collectStrings(node: unknown, out: string[] = []): string[] {
  if (typeof node === 'string') {
    out.push(node);
    return out;
  }
  if (Array.isArray(node)) {
    for (const item of node) collectStrings(item, out);
    return out;
  }
  if (node && typeof node === 'object') {
    for (const [key, val] of Object.entries(node as Record<string, unknown>)) {
      // Ignore function references and internal type names that aren't user-visible content,
      // while collecting props/children/label/text/key values.
      if (typeof val === 'function') continue;
      if (key === 'type' || key === 'kind' || key === 'tag') continue;
      collectStrings(val, out);
    }
  }
  return out;
}

function collectButtonKeys(node: unknown, out: string[] = []): string[] {
  if (Array.isArray(node)) {
    for (const item of node) collectButtonKeys(item, out);
    return out;
  }
  if (node && typeof node === 'object') {
    const obj = node as Record<string, unknown>;
    const props = obj.props && typeof obj.props === 'object' ? (obj.props as Record<string, unknown>) : obj;
    if (typeof props.label === 'string' && typeof props.key === 'string') {
      out.push(`${props.key}:${props.label}`);
    } else if (typeof obj.key === 'string' && typeof props.label === 'string') {
      out.push(`${obj.key}:${props.label}`);
    }
    for (const val of Object.values(obj)) {
      if (typeof val === 'object' && val !== null) collectButtonKeys(val, out);
    }
  }
  return out;
}

function makeRichSnapshotJson(overrides?: {
  sessionId?: string;
  focusMode?: boolean;
  quarantined?: number;
  quarantinedGlobal?: number;
  adversarial?: boolean;
}): string {
  const sid = overrides?.sessionId ?? 'claude:sess-42';
  const focusMode = overrides?.focusMode ?? false;
  const quarantined = overrides?.quarantined ?? 0;
  const quarantinedGlobal = overrides?.quarantinedGlobal ?? quarantined;
  const adv = overrides?.adversarial ?? false;

  const escRed = '\u001b[31m';
  const escReset = '\u001b[0m';
  const oscTrap = '\u001b]52;c;ZXZpbA==\u0007';
  const bidiTrap = '\u202e\u2066\u200f';

  const snap: Record<string, unknown> = {
    schemaVersion: 1,
    rev: 7,
    updatedAt: 1_700_000_000_000,
    daemon: {
      online: true,
      pid: 4321,
      nodeId: adv ? `${escRed}${bidiTrap}laptop${escReset}` : 'laptop',
      version: '0.6.0',
      profile: 'local',
      peersOnline: 3,
      quarantinedGlobal,
      ...(adv ? { secret: 'DAEMON_SECRET_LEAK', token: 'RAW_SECRET_TOKEN' } : {}),
    },
    sessions: [
      {
        sessionId: sid,
        harness: 'claude',
        enrolled: true,
        handle: adv ? `${oscTrap}${bidiTrap}alice${escReset}` : 'alice',
        address: 'laptop/alice',
        lastSeen: 1_700_000_000_000,
        transportKind: 'claude_channel',
        hasLiveTransport: true,
        deliveryMode: 'queue',
        focusMode,
        focusAllowInterruptVips: true,
        mutedAll: false,
        bridges: [adv ? `${escRed}telegram:personal${bidiTrap}${escReset}` : 'telegram:personal'],
        counts: {
          subscriptions: 1,
          bridges: 1,
          queued: 2,
          unnotified: 1,
          quarantined,
          mutedRules: 1,
          mutedArchived: 0,
          channels: 1,
        },
        unreadBreakdown: {
          messages: 1,
          events: 1,
          plugins: 0,
          transfers: 0,
          kv: 0,
          sources: ['bob@peer'],
        },
        details: {
          bridges: [
            {
              plugin: 'telegram',
              target: adv ? `${oscTrap}personal${bidiTrap}` : 'personal',
              label: adv ? `${escRed}telegram:personal${bidiTrap}${escReset}` : 'telegram:personal',
              role: 'primary',
              ...(adv ? { token: 'BRIDGE_TOKEN_LEAK' } : {}),
            },
          ],
          subscriptions: [
            {
              id: adv ? '-rf; $(whoami) | cat /etc/passwd' : 'sub-ci-1',
              key: 'ci',
              originNode: 'hub',
              topic: adv ? `${escRed}${bidiTrap}ci.builds${escReset}` : 'ci.builds',
              mode: 'notify',
              coalesceSeconds: 15,
              filterSummary: adv ? `${oscTrap}branch=main${bidiTrap}` : 'branch=main',
              ...(adv ? { body: 'SUB_BODY_SENTINEL', data: { leak: 'CLOUDEVENT_DATA_LEAK' } } : {}),
            },
          ],
          queuedItems: [
            {
              receipt: 'rcpt-1',
              kind: 'message',
              source: adv ? `${escRed}bob@peer${bidiTrap}${escReset}` : 'bob@peer',
              originNode: 'peer',
              receivedAt: 1_699_999_970_000,
              notified: false,
              urgency: 'interrupt',
              ...(adv
                ? {
                    body: 'SECRET_DM_BODY',
                    text: 'SECRET_MAILBOX_TEXT',
                    payload: 'SECRET_PAYLOAD_LEAK',
                    ciphertext: 'CIPHERTEXT_LEAK',
                  }
                : {}),
            },
            {
              receipt: 'rcpt-2',
              kind: 'event',
              source: 'ops/deploy',
              originNode: 'hub',
              receivedAt: 1_699_999_900_000,
              notified: true,
              urgency: 'queue',
              ...(adv ? { data: 'CLOUDEVENT_DATA_LEAK' } : {}),
            },
          ],
          mutes: [
            {
              pattern: adv ? `${escRed}#noisy${bidiTrap}${escReset}` : '#noisy',
              scope: 'connector',
              mutedAt: 1_699_999_800_000,
            },
          ],
          rules: [
            {
              target: 'pager@ops',
              delivery: 'interrupt',
            },
          ],
          channels: ['#ops'],
          channelEntries: [
            {
              hostNode: 'laptop',
              channel: adv ? `${oscTrap}#ops${bidiTrap}` : '#ops',
              mode: 'open',
            },
          ],
          ...(adv
            ? {
                quarantinedText: 'QUARANTINE_TEXT_LEAK',
                quarantinedItems: [{ body: 'QUARANTINE_BODY_LEAK' }],
              }
            : {}),
        },
      },
      {
        sessionId: 'codex:other-9',
        harness: 'codex',
        enrolled: true,
        handle: 'builder',
        address: 'laptop/builder',
        lastSeen: 1_699_999_500_000,
        transportKind: 'waiter',
        hasLiveTransport: true,
        deliveryMode: 'queue',
        focusMode: true,
        focusAllowInterruptVips: true,
        mutedAll: false,
        counts: {
          subscriptions: 0,
          queued: 0,
          unnotified: 0,
          quarantined: 0,
          mutedRules: 0,
          mutedArchived: 0,
          channels: 0,
        },
        unreadBreakdown: {
          messages: 0,
          events: 0,
          plugins: 0,
          transfers: 0,
          kv: 0,
          sources: [],
        },
        details: {
          subscriptions: [],
          queuedItems: [],
          mutes: [],
          rules: [],
          channels: [],
          channelEntries: [],
        },
      },
    ],
  };

  return JSON.stringify(snap);
}

describe('hyphae pure state & security helpers', () => {
  test('sanitizes ANSI OSC/CSI/DCS, control chars, and Unicode BiDi traps', () => {
    const dirty = '\u001b]52;c;ZXZpbA==\u0007\u001b[31m\u202ehello\u2066\u0007world\u001b[0m\u200f';
    const clean = sanitizeUiText(dirty);
    expect(clean).toBe('helloworld');
    expect(clean.includes('\u001b')).toBe(false);
    expect(clean.includes('\u202e')).toBe(false);
    expect(clean.includes('\u2066')).toBe(false);
  });

  test('resolves ui/state.json candidates honoring HYPHAE_STATE_DIR and node.json stateDir', () => {
    const res = resolveUiStateCandidates(
      '/Users/dev',
      '/tmp/override-state',
      JSON.stringify({ stateDir: '~/custom-hyphae' }),
    );
    expect(res.files).toEqual([
      '/tmp/override-state/ui/state.json',
      '/Users/dev/custom-hyphae/ui/state.json',
      '/Users/dev/.config/hyphae/ui/state.json',
      '/Users/dev/.config/hyphae/state/ui/state.json',
    ]);
  });

  test('parseSnapshotJson strips forbidden body/data/note/secret fields recursively', () => {
    const snap = parseSnapshotJson(makeRichSnapshotJson({ adversarial: true }));
    expect(snap).not.toBeNull();
    const serialized = JSON.stringify(snap);
    for (const sentinel of [
      'SECRET_DM_BODY',
      'SECRET_MAILBOX_TEXT',
      'SECRET_PAYLOAD_LEAK',
      'CLOUDEVENT_DATA_LEAK',
      'RAW_SECRET_TOKEN',
      'DAEMON_SECRET_LEAK',
      'QUARANTINE_TEXT_LEAK',
      'SUB_BODY_SENTINEL',
      'CIPHERTEXT_LEAK',
    ]) {
      expect(serialized.includes(sentinel)).toBe(false);
    }
  });

  test('parseSnapshotJson unwraps hyp inspect --json { ok, data } envelope before stripping nested data', () => {
    const inner = JSON.parse(makeRichSnapshotJson({ adversarial: true }));
    const envelope = JSON.stringify({
      ok: true,
      command: 'inspect',
      data: inner,
    });
    const snap = parseSnapshotJson(envelope);
    expect(snap).not.toBeNull();
    expect(snap!.daemon?.nodeId).toBe('laptop');
    expect(snap!.sessions.length).toBe(2);
    expect(snap!.sessions[0]?.handle).toBe('alice');
    const serialized = JSON.stringify(snap);
    expect(serialized.includes('CLOUDEVENT_DATA_LEAK')).toBe(false);
    expect(serialized.includes('SECRET_DM_BODY')).toBe(false);
    expect(parseSnapshotJson(JSON.stringify({ ok: false, error: 'offline' }))).toBeNull();
  });

  test('getQuarantinedCount consistently computes max(session.counts.quarantined, daemon.quarantinedGlobal)', () => {
    const snap = parseSnapshotJson(
      makeRichSnapshotJson({ sessionId: 'claude:sess-42', quarantined: 0, quarantinedGlobal: 3 }),
    );
    expect(snap).not.toBeNull();
    expect(getQuarantinedCount(snap, snap!.sessions[0] ?? null)).toBe(3);

    const snapLocalOnly = parseSnapshotJson(
      makeRichSnapshotJson({ sessionId: 'claude:sess-42', quarantined: 2, quarantinedGlobal: 1 }),
    );
    expect(getQuarantinedCount(snapLocalOnly, snapLocalOnly!.sessions[0] ?? null)).toBe(2);

    // Other session's stale count is ignored if daemon.quarantinedGlobal is 0 and active is 0
    const snapOther = JSON.parse(makeRichSnapshotJson({ quarantined: 0, quarantinedGlobal: 0 }));
    snapOther.sessions[1].counts.quarantined = 5;
    const parsedOther = parseSnapshotJson(JSON.stringify(snapOther));
    expect(getQuarantinedCount(parsedOther, parsedOther!.sessions[0] ?? null)).toBe(0);
  });

  test('qualifyChannelTarget always qualifies local and remote channels without double prefixing', () => {
    expect(qualifyChannelTarget('laptop', '#ops', 'laptop')).toBe('laptop/#ops');
    expect(qualifyChannelTarget('local', '#ops', 'laptop')).toBe('local/#ops');
    expect(qualifyChannelTarget('', '#ops', 'laptop')).toBe('laptop/#ops');
    expect(qualifyChannelTarget('', '#ops', '')).toBe('local/#ops');
    expect(qualifyChannelTarget('acme-hub', '#release', 'laptop')).toBe('acme-hub/#release');
    expect(qualifyChannelTarget('local', 'acme-hub/#release', 'laptop')).toBe('acme-hub/#release');
  });

  test('buildSessionControlArgs guards flag-like arguments with -- and rejects control chars', () => {
    const argv = buildSessionControlArgs(
      { kind: 'unsubscribe', id: '-rf; $(whoami)' },
      { sessionId: 'claude:sess-42' },
    );
    expect(argv).toEqual([
      'hyp',
      'session',
      'unsubscribe',
      '--session',
      'claude:sess-42',
      '--json',
      '--',
      '-rf; $(whoami)',
    ]);

    expect(() =>
      buildSessionControlArgs({ kind: 'leave', channel: '#ops\nrm -rf /' }, { sessionId: 'claude:1' }),
    ).toThrow();
  });
});

describe('hyphae native Claude Code side-panel mod', () => {
  test('registers /hyphae-panel on session.start, never emits loud ui.status text, and opens/closes panel', async ($, on) => {
    const registered: { name: string; immediate?: boolean }[] = [];
    const opened: { id: string; title?: string; focus?: boolean; closeOnEscape?: boolean }[] = [];
    const closed: string[] = [];
    const statusUpdates: (string | undefined)[] = [];

    mock.clock(on, { now: 1_700_000_000_000 });
    mock.env(on, { HOME: '/fake-home' });
    on('session.id', () => ({ value: 'sess-42' }));
    on('fs.read', (_$, e) => {
      if (e.path === '/fake-home/.config/hyphae/ui/state.json') {
        return { value: makeRichSnapshotJson({ sessionId: 'claude:sess-42', focusMode: true }) };
      }
      return { deny: 'ENOENT' };
    });
    on('session.start', (_$, e) => ({ cwd: e.cwd }));
    on('command.register', (_$, e) => {
      registered.push({ name: e.name, immediate: e.immediate });
      return { value: { command: e.name } };
    });
    on('ui.status', (_$, e) => {
      statusUpdates.push(e.text);
      return { value: undefined };
    });
    on('ui.open', (_$, e) => {
      opened.push({
        id: e.id,
        title: e.title,
        focus: e.focus,
        closeOnEscape: e.closeOnEscape,
      });
      return { value: { isPlaced: true } };
    });
    on('ui.close', (_$, e) => {
      closed.push(e.id);
      return { value: undefined };
    });
    on('ui.invalidate', () => ({ value: undefined }));

    await $.session.start({ cwd: '/workspace', surface: 'terminal', isInteractive: true });
    expect(registered).toEqual([{ name: 'hyphae-panel', immediate: true }]);
    // Never emits non-empty `$.ui.status(...)` (Claude Code styles it as a bright yellow ⚠ warning).
    expect(statusUpdates.every((t) => t === undefined)).toBe(true);

    // Compact prompt indicator renders quietly in AbovePrompt outside Herdr (no repeated "hyphae" or "/hyphae-panel").
    const stripMount = await $.ui.mount({
      plugin: 'hyphae',
      surface: 'terminal',
      component: 'AbovePrompt',
      requestId: 'hyphae-above-prompt',
      props: ABOVE_PROMPT_PROPS,
      viewport: VIEWPORT,
    });
    expect(await stripMount.keepsBeneath()).toBe(false);
    const stripText = collectStrings(await stripMount.drawn()).join('\n');
    expect(stripText).toContain('@alice · telegram:personal · 1 sub · 2 queued · focus · 1 muted');
    expect(stripText).not.toContain('/hyphae-panel');
    expect(stripText).not.toContain('hyphae @alice');

    // Users can silence and re-enable the quiet prompt strip via `/hyphae-panel status off|on`.
    await $.command.run({
      command: 'hyphae-panel',
      args: 'status off',
      origin: { kind: 'composer' },
      presentation: { isFullscreen: false, columns: 120 },
    });
    await stripMount.redraw(ABOVE_PROMPT_PROPS);
    expect(await stripMount.keepsBeneath()).toBe(true);

    await $.command.run({
      command: 'hyphae-panel',
      args: 'status on',
      origin: { kind: 'composer' },
      presentation: { isFullscreen: false, columns: 120 },
    });
    await stripMount.redraw(ABOVE_PROMPT_PROPS);
    expect(await stripMount.keepsBeneath()).toBe(false);
    await stripMount.unmount();

    await $.command.run({
      command: 'hyphae-panel',
      args: '',
      origin: { kind: 'composer' },
      presentation: { isFullscreen: false, columns: 120 },
    });
    expect(opened).toEqual([
      {
        id: 'hyphae-panel',
        title: 'Hyphae',
        focus: true,
        closeOnEscape: true,
      },
    ]);

    await $.command.run({
      command: 'hyphae-panel',
      args: 'close',
      origin: { kind: 'composer' },
      presentation: { isFullscreen: false, columns: 120 },
    });
    expect(closed).toEqual(['hyphae-panel']);
  });

  test('renders active handle, quarantine alert, tabs, and strips ANSI/BiDi/body fields', async ($, on) => {
    const stateJson = makeRichSnapshotJson({
      sessionId: 'claude:sess-42',
      focusMode: true,
      quarantined: 2,
      quarantinedGlobal: 2,
      adversarial: true,
    });

    mock.clock(on, { now: 1_700_000_000_000 });
    mock.env(on, { HOME: '/fake-home', HYPHAE_STATE_DIR: '/custom-state' });
    on('session.id', () => ({ value: 'sess-42' }));
    on('ui.invalidate', () => ({ value: undefined }));
    on('ui.status', () => ({ value: undefined }));
    on('fs.read', (_$, e) => {
      if (e.path === '/custom-state/ui/state.json') {
        return { value: stateJson };
      }
      return { deny: 'ENOENT' };
    });

    const mounted = await $.ui.mount({
      plugin: 'hyphae',
      surface: 'terminal',
      component: 'Pane',
      requestId: 'hyphae-panel',
      props: PANE_PROPS,
      viewport: VIEWPORT,
    });

    const checkInvariants = (drawn: unknown): string => {
      const joined = collectStrings(drawn).join('\n');
      const buttons = collectButtonKeys(drawn).join('\n').toLowerCase();

      // Anti-body-leakage: ZERO body/data/note/secret/quarantine content anywhere!
      for (const sentinel of [
        'SECRET_DM_BODY',
        'SECRET_MAILBOX_TEXT',
        'SECRET_PAYLOAD_LEAK',
        'CLOUDEVENT_DATA_LEAK',
        'RAW_SECRET_TOKEN',
        'DAEMON_SECRET_LEAK',
        'QUARANTINE_TEXT_LEAK',
        'SUB_BODY_SENTINEL',
        'CIPHERTEXT_LEAK',
      ]) {
        expect(joined.includes(sentinel)).toBe(false);
      }

      // Anti-ANSI and anti-BiDi spoofing
      expect(joined.includes('\u001b')).toBe(false);
      expect(joined.includes('\u202e')).toBe(false);
      expect(joined.includes('\u2066')).toBe(false);
      expect(joined.includes('\u200f')).toBe(false);

      // Human-CLI quarantine boundary: NEVER an approve or reject button in agent UI!
      expect(buttons.includes('approve')).toBe(false);
      expect(buttons.includes('reject')).toBe(false);

      return joined;
    };

    // Tab 1: Bridges + Streams (default)
    const subsDrawn = await mounted.drawn();
    const subsText = checkInvariants(subsDrawn);
    expect(subsText).toContain('@alice');
    expect(subsText).toContain('● online');
    expect(subsText).toContain('laptop · 3 peers');
    expect(subsText).toContain('FOCUS');
    expect(subsText).toContain('⚠ 2 quarantined items');
    expect(subsText).toContain('hyp gate review');
    expect(subsText).toContain('untrusted external data');
    expect(subsText).toContain('Subs 2');
    expect(subsText).toContain('Bridges (1)');
    expect(subsText).toContain('telegram:personal');
    expect(subsText).toContain('primary');
    expect(subsText).toContain('ci.builds');
    expect(subsText).toContain('branch=main');
    expect(subsText).not.toContain('BRIDGE_TOKEN_LEAK');
    // No duplicate close button (Claude Code's native Pane chrome provides ×) and no double "(f)"/"(r)" hotkey labels.
    expect(collectButtonKeys(subsDrawn)).not.toContain('hyphae-close');
    expect(subsText).not.toContain('(f)');
    expect(subsText).not.toContain('(r)');

    // Tab 2: Queue (metadata only)
    await mounted.press({ key: 'hyphae-tab-queue' });
    await mounted.redraw(PANE_PROPS);
    const queueText = checkInvariants(await mounted.drawn());
    expect(queueText).toContain('Queued Metadata');
    expect(queueText).toContain('bob@peer');
    expect(queueText).toContain('ops/deploy');
    expect(queueText).toContain('interrupt');
    expect(queueText).toContain('30s');

    // Tab 3: Rules & Mutes
    await mounted.press({ key: 'hyphae-tab-rules' });
    await mounted.redraw(PANE_PROPS);
    const rulesText = checkInvariants(await mounted.drawn());
    expect(rulesText).toContain('#noisy');
    expect(rulesText).toContain('connector');
    expect(rulesText).toContain('pager@ops -> interrupt');

    // Tab 4: Channels & Mesh
    await mounted.press({ key: 'hyphae-tab-mesh' });
    await mounted.redraw(PANE_PROPS);
    const meshText = checkInvariants(await mounted.drawn());
    expect(meshText).toContain('#ops');

    await mounted.unmount();
  });

  test('degrades gracefully when ui/state.json is missing or malformed', async ($, on) => {
    const closed: string[] = [];
    let readMode: 'missing' | 'malformed' = 'missing';

    mock.clock(on, { now: 1_700_000_000_000 });
    mock.env(on, { HOME: '/empty-home' });
    on('session.id', () => ({ value: 'sess-offline' }));
    on('ui.invalidate', () => ({ value: undefined }));
    on('ui.status', () => ({ value: undefined }));
    on('ui.close', (_$, e) => {
      closed.push(e.id);
      return { value: undefined };
    });
    on('fs.read', () => {
      if (readMode === 'malformed') {
        return { value: '{not valid json' };
      }
      return { deny: 'ENOENT' };
    });

    const mounted = await $.ui.mount({
      plugin: 'hyphae',
      surface: 'terminal',
      component: 'Pane',
      requestId: 'hyphae-panel',
      props: PANE_PROPS,
      viewport: VIEWPORT,
    });

    const text = collectStrings(await mounted.drawn()).join('\n');
    expect(text).toContain('offline');
    expect(text).toContain('hyp node start');
    expect(text).toContain('untrusted external data');

    // Malformed JSON also degrades cleanly without throwing
    readMode = 'malformed';
    await mounted.press({ key: 'hyphae-refresh' });
    await mounted.redraw(PANE_PROPS);
    const malformedText = collectStrings(await mounted.drawn()).join('\n');
    expect(malformedText).toContain('offline');
    expect(collectButtonKeys(await mounted.drawn())).not.toContain('hyphae-close');

    await mounted.unmount();
  });

  test('falls back to all-sessions summary when current Claude session is unbound', async ($, on) => {
    const stateJson = makeRichSnapshotJson({ sessionId: 'claude:different-session' });

    mock.clock(on, { now: 1_700_000_000_000 });
    mock.env(on, { HOME: '/fake-home' });
    on('session.id', () => ({ value: 'unregistered-99' }));
    on('ui.invalidate', () => ({ value: undefined }));
    on('ui.status', () => ({ value: undefined }));
    on('fs.read', (_$, e) => {
      if (e.path === '/fake-home/.config/hyphae/node.json') {
        return { value: JSON.stringify({ stateDir: '~/my-state' }) };
      }
      if (e.path === '/fake-home/my-state/ui/state.json') {
        return { value: stateJson };
      }
      return { deny: 'ENOENT' };
    });

    const mounted = await $.ui.mount({
      plugin: 'hyphae',
      surface: 'terminal',
      component: 'Pane',
      requestId: 'hyphae-panel',
      props: PANE_PROPS,
      viewport: VIEWPORT,
    });

    const summaryText = collectStrings(await mounted.drawn()).join('\n');
    expect(summaryText).toContain('Local Sessions');
    expect(summaryText).toContain('@alice');
    expect(summaryText).toContain('@builder');

    // Clicking Inspect focuses that session cleanly.
    await mounted.press({ key: 'hyphae-select-0' });
    await mounted.redraw(PANE_PROPS);
    const inspectedText = collectStrings(await mounted.drawn()).join('\n');
    expect(inspectedText).toContain('Streams (1)');
    expect(inspectedText).toContain('telegram:personal');
    expect(inspectedText).toContain('ci.builds');

    await mounted.unmount();
  });

  test('button controls invoke hyp session with strict argv arrays and zero shell injection', async ($, on) => {
    const ranArgvs: (readonly string[])[] = [];
    const stateJson = makeRichSnapshotJson({
      sessionId: 'claude:sess-42',
      focusMode: false,
      adversarial: true,
    });

    mock.clock(on, { now: 1_700_000_000_000 });
    mock.env(on, { HOME: '/fake-home' });
    on('session.id', () => ({ value: 'sess-42' }));
    on('ui.invalidate', () => ({ value: undefined }));
    on('ui.status', () => ({ value: undefined }));
    on('fs.read', (_$, e) => {
      if (e.path === '/fake-home/.config/hyphae/ui/state.json') {
        return { value: stateJson };
      }
      return { deny: 'ENOENT' };
    });
    on('process.run', (_$, e) => {
      ranArgvs.push(e.argv);
      return {
        value: {
          exitCode: 0,
          stdout: JSON.stringify({ ok: true, summary: 'Updated session state' }),
          stderr: '',
          isStdoutTruncated: false,
          isStderrTruncated: false,
        },
      };
    });

    const mounted = await $.ui.mount({
      plugin: 'hyphae',
      surface: 'terminal',
      component: 'Pane',
      requestId: 'hyphae-panel',
      props: PANE_PROPS,
      viewport: VIEWPORT,
    });

    // 1. Toggle Focus ON
    await mounted.press({ key: 'hyphae-toggle-focus' });
    // 2. Unsubscribe flag-like + shell-metacharacter subscription ID safely with `--`
    await mounted.press({ key: 'hyphae-unsub-0' });
    // 3. Switch to Rules tab and click Unmute (connector scope)
    await mounted.press({ key: 'hyphae-tab-rules' });
    await mounted.redraw(PANE_PROPS);
    await mounted.press({ key: 'hyphae-unmute-0' });
    // 4. Switch to Mesh tab and click Leave channel
    await mounted.press({ key: 'hyphae-tab-mesh' });
    await mounted.redraw(PANE_PROPS);
    await mounted.press({ key: 'hyphae-leave-0' });

    expect(ranArgvs).toEqual([
      ['hyp', 'session', 'focus', '--session', 'claude:sess-42', 'on', '--json'],
      [
        'hyp',
        'session',
        'unsubscribe',
        '--session',
        'claude:sess-42',
        '--json',
        '--',
        '-rf; $(whoami) | cat /etc/passwd',
      ],
      ['hyp', 'session', 'unmute', '--session', 'claude:sess-42', '--scope', 'connector', '--json', '#noisy'],
      ['hyp', 'session', 'leave', '--session', 'claude:sess-42', '--json', 'laptop/#ops'],
    ]);

    await mounted.unmount();
  });

  test('controls preserve full untruncated IDs/patterns/channels beyond display maxLen (U9 & U2)', async ($, on) => {
    const ranArgvs: (readonly string[])[] = [];
    const longSubId = `sub-${'x'.repeat(145)}`;
    const longMute = `#noisy-mute-pattern-${'y'.repeat(135)}`;
    const longChannel = `#long-channel-name-${'z'.repeat(105)}`;
    const snapObj = JSON.parse(makeRichSnapshotJson({ sessionId: 'claude:sess-42' }));
    snapObj.sessions[0].details.subscriptions[0].id = longSubId;
    snapObj.sessions[0].details.mutes[0].pattern = longMute;
    snapObj.sessions[0].details.channelEntries = [
      { hostNode: 'local', channel: longChannel, mode: 'open' },
      { hostNode: 'acme-hub', channel: '#release', mode: 'restricted' },
    ];

    mock.clock(on, { now: 1_700_000_000_000 });
    mock.env(on, { HOME: '/fake-home' });
    on('session.id', () => ({ value: 'sess-42' }));
    on('ui.invalidate', () => ({ value: undefined }));
    on('ui.status', () => ({ value: undefined }));
    on('fs.read', (_$, e) => {
      if (e.path === '/fake-home/.config/hyphae/ui/state.json') {
        return { value: JSON.stringify(snapObj) };
      }
      return { deny: 'ENOENT' };
    });
    on('process.run', (_$, e) => {
      ranArgvs.push(e.argv);
      return {
        value: {
          exitCode: 0,
          stdout: JSON.stringify({ ok: true, summary: 'ok' }),
          stderr: '',
          isStdoutTruncated: false,
          isStderrTruncated: false,
        },
      };
    });

    const mounted = await $.ui.mount({
      plugin: 'hyphae',
      surface: 'terminal',
      component: 'Pane',
      requestId: 'hyphae-panel',
      props: PANE_PROPS,
      viewport: VIEWPORT,
    });

    await mounted.press({ key: 'hyphae-unsub-0' });
    await mounted.press({ key: 'hyphae-tab-rules' });
    await mounted.redraw(PANE_PROPS);
    await mounted.press({ key: 'hyphae-unmute-0' });
    await mounted.press({ key: 'hyphae-tab-mesh' });
    await mounted.redraw(PANE_PROPS);
    await mounted.press({ key: 'hyphae-leave-0' });
    await mounted.press({ key: 'hyphae-leave-1' });

    expect(ranArgvs).toEqual([
      ['hyp', 'session', 'unsubscribe', '--session', 'claude:sess-42', '--json', longSubId],
      ['hyp', 'session', 'unmute', '--session', 'claude:sess-42', '--scope', 'connector', '--json', longMute],
      ['hyp', 'session', 'leave', '--session', 'claude:sess-42', '--json', `local/${longChannel}`],
      ['hyp', 'session', 'leave', '--session', 'claude:sess-42', '--json', 'acme-hub/#release'],
    ]);
    for (const argv of ranArgvs) {
      expect(argv.join(' ').includes('…')).toBe(false);
    }

    await mounted.unmount();
  });

  test('AbovePrompt auto-hides inside Herdr when herdr-mod is active, stays quiet outside Herdr, and alerts on quarantine', async ($, on) => {
    let quarantinedCount = 0;
    const opened: string[] = [];

    let invalidatedCount = 0;
    const clock = mock.clock(on, { now: 1_700_000_000_000 });
    mock.env(on, { HOME: '/fake-home', HC_TERMINAL_ID: 't42' });
    on('session.id', () => ({ value: 'sess-42' }));
    on('ui.invalidate', () => {
      invalidatedCount += 1;
      return { value: undefined };
    });
    on('ui.status', () => ({ value: undefined }));
    on('ui.open', (_$, e) => {
      opened.push(e.id);
      return { value: { isPlaced: true } };
    });
    on('fs.read', (_$, e) => {
      if (e.path === '/fake-home/.config/hyphae/ui/state.json') {
        return {
          value: makeRichSnapshotJson({
            sessionId: 'claude:sess-42',
            quarantined: quarantinedCount,
            quarantinedGlobal: quarantinedCount,
          }),
        };
      }
      if (e.path === '/fake-home/.config/herdr-app/shared.json') {
        return {
          value: JSON.stringify({
            layout: 'personal',
            'hyphae.modActive': { pane: true, panel: true, updatedAt: 1_700_000_000_000 },
          }),
        };
      }
      return { deny: 'ENOENT' };
    });

    // Pure status-line helper stays hidden when unenrolled and has zero alerts
    expect(formatPersistentStatusLine(null, null, 0)).toBeUndefined();
    expect(formatPersistentStatusLine(null, null, 2)).toContain('⚠ 2 held');

    // Pure Herdr suppression detector verifies env + shared.json advertisement
    expect(
      await shouldSuppressPromptStrip(
        { homeDir: '/fake-home', hcTerminalId: 't42' },
        async (p) =>
          p === '/fake-home/.config/herdr-app/shared.json'
            ? JSON.stringify({ 'hyphae.modActive': { pane: true } })
            : null,
      ),
    ).toBe(true);
    expect(
      await shouldSuppressPromptStrip({ homeDir: '/fake-home' }, async () => null),
    ).toBe(false);

    // Zero clutter in AbovePrompt inside Herdr when Herdr mod is active and quarantined === 0
    const cleanMount = await $.ui.mount({
      plugin: 'hyphae',
      surface: 'terminal',
      component: 'AbovePrompt',
      requestId: 'hyphae-above-prompt',
      props: ABOVE_PROMPT_PROPS,
      viewport: VIEWPORT,
    });
    expect(await cleanMount.keepsBeneath()).toBe(true);
    await cleanMount.unmount();

    // When quarantined > 0, renders 1-line red emergency warning + plain panel opener even inside Herdr
    quarantinedCount = 3;
    const alertMount = await $.ui.mount({
      plugin: 'hyphae',
      surface: 'terminal',
      component: 'AbovePrompt',
      requestId: 'hyphae-above-prompt',
      props: ABOVE_PROMPT_PROPS,
      viewport: VIEWPORT,
    });
    expect(await alertMount.keepsBeneath()).toBe(false);
    const alertText = collectStrings(await alertMount.drawn()).join('\n');
    expect(alertText).toContain('3 quarantined');
    expect(alertText).toContain('hyp gate review');

    const beforeOpenInvalidations = invalidatedCount;
    await alertMount.press({ key: 'hyphae-strip-open' });
    expect(opened).toEqual(['hyphae-panel']);
    expect(invalidatedCount).toBeGreaterThan(beforeOpenInvalidations);
    // U17: opening panel from AbovePrompt quarantine strip MUST start the 5s refresh timer!
    const afterOpenInvalidations = invalidatedCount;
    await clock.advance(5_000);
    expect(invalidatedCount).toBeGreaterThan(afterOpenInvalidations);
    await alertMount.unmount();
  });
});
