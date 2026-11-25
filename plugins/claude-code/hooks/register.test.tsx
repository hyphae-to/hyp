import { describe, expect, mock, test } from 'claude-code/testing';
import {
  buildSessionControlArgs,
  parseSnapshotJson,
  resolveUiStateCandidates,
  sanitizeUiText,
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
        counts: {
          subscriptions: 1,
          queued: 2,
          unnotified: 1,
          quarantined,
          mutedRules: 1,
          mutedArchived: 0,
          channels: 1,
          wakeups: 1,
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
          wakeups: [
            {
              id: 'wk-1',
              label: adv ? `${escRed}daily-check${bidiTrap}${escReset}` : 'daily-check',
              triggerKind: 'cron',
              nextFireAt: 1_700_000_600_000,
              urgency: 'notify',
              state: 'armed',
              ...(adv ? { note: 'WAKEUP_SECRET_NOTE' } : {}),
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
          wakeups: 0,
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
          wakeups: [],
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
      'WAKEUP_SECRET_NOTE',
      'RAW_SECRET_TOKEN',
      'DAEMON_SECRET_LEAK',
      'QUARANTINE_TEXT_LEAK',
      'SUB_BODY_SENTINEL',
      'CIPHERTEXT_LEAK',
    ]) {
      expect(serialized.includes(sentinel)).toBe(false);
    }
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
  test('registers /hyphae-panel on session.start and opens/closes the side panel', async ($, on) => {
    const registered: { name: string; immediate?: boolean }[] = [];
    const opened: { id: string; title?: string; focus?: boolean; closeOnEscape?: boolean }[] = [];
    const closed: string[] = [];

    mock.clock(on, { now: 1_700_000_000_000 });
    on('session.start', (_$, e) => ({ cwd: e.cwd }));
    on('command.register', (_$, e) => {
      registered.push({ name: e.name, immediate: e.immediate });
      return { value: { command: e.name } };
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

    await $.command.run({
      command: 'hyphae-panel',
      args: '',
      origin: { kind: 'composer' },
      presentation: { isFullscreen: false, columns: 120 },
    });
    expect(opened).toEqual([
      {
        id: 'hyphae-panel',
        title: 'Hyphae Mesh',
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
        'WAKEUP_SECRET_NOTE',
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

    // Tab 1: Subscriptions (default)
    const subsText = checkInvariants(await mounted.drawn());
    expect(subsText).toContain('@alice');
    expect(subsText).toContain('ONLINE · laptop');
    expect(subsText).toContain('FOCUS');
    expect(subsText).toContain('⚠ 2 quarantined items');
    expect(subsText).toContain('hyp gate review');
    expect(subsText).toContain('Untrusted external mesh metadata');
    expect(subsText).toContain('ci.builds');
    expect(subsText).toContain('branch=main');

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
    expect(meshText).toContain('daily-check');
    expect(meshText).toContain('in 10m');

    await mounted.unmount();
  });

  test('degrades gracefully when ui/state.json is missing or malformed', async ($, on) => {
    const closed: string[] = [];
    let readMode: 'missing' | 'malformed' = 'missing';

    mock.clock(on, { now: 1_700_000_000_000 });
    mock.env(on, { HOME: '/empty-home' });
    on('session.id', () => ({ value: 'sess-offline' }));
    on('ui.invalidate', () => ({ value: undefined }));
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
    expect(text).toContain('OFFLINE');
    expect(text).toContain('hyp node start');
    expect(text).toContain('untrusted external data');

    // Malformed JSON also degrades cleanly without throwing
    readMode = 'malformed';
    await mounted.press({ key: 'hyphae-refresh' });
    await mounted.redraw(PANE_PROPS);
    const malformedText = collectStrings(await mounted.drawn()).join('\n');
    expect(malformedText).toContain('OFFLINE');

    await mounted.press({ key: 'hyphae-close' });
    expect(closed).toEqual(['hyphae-panel']);

    await mounted.unmount();
  });

  test('falls back to all-sessions summary when current Claude session is unbound', async ($, on) => {
    const stateJson = makeRichSnapshotJson({ sessionId: 'claude:different-session' });

    mock.clock(on, { now: 1_700_000_000_000 });
    mock.env(on, { HOME: '/fake-home' });
    on('session.id', () => ({ value: 'unregistered-99' }));
    on('ui.invalidate', () => ({ value: undefined }));
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
    expect(summaryText).toContain('Local Sessions Summary');
    expect(summaryText).toContain('@alice');
    expect(summaryText).toContain('@builder');

    // Clicking Inspect focuses that session cleanly.
    await mounted.press({ key: 'hyphae-select-0' });
    await mounted.redraw(PANE_PROPS);
    const inspectedText = collectStrings(await mounted.drawn()).join('\n');
    expect(inspectedText).toContain('Subscriptions (1)');
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
      ['hyp', 'session', 'leave', '--session', 'claude:sess-42', '--json', '#ops'],
    ]);

    await mounted.unmount();
  });

  test('AbovePrompt strip stays hidden by default and surfaces quarantine warning when > 0', async ($, on) => {
    let quarantinedCount = 0;
    const opened: string[] = [];

    mock.clock(on, { now: 1_700_000_000_000 });
    mock.env(on, { HOME: '/fake-home' });
    on('session.id', () => ({ value: 'sess-42' }));
    on('ui.invalidate', () => ({ value: undefined }));
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
      return { deny: 'ENOENT' };
    });

    // Zero clutter when quarantined === 0 and strip not explicitly enabled
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

    // User can opt in via `/hyphae-panel strip on` and opt back out via `strip off`
    await $.command.run({
      command: 'hyphae-panel',
      args: 'strip on',
      origin: { kind: 'composer' },
      presentation: { isFullscreen: false, columns: 120 },
    });
    const optInMount = await $.ui.mount({
      plugin: 'hyphae',
      surface: 'terminal',
      component: 'AbovePrompt',
      requestId: 'hyphae-above-prompt',
      props: ABOVE_PROMPT_PROPS,
      viewport: VIEWPORT,
    });
    expect(await optInMount.keepsBeneath()).toBe(false);
    expect(collectStrings(await optInMount.drawn()).join('\n')).toContain('Hyphae @alice');
    await optInMount.unmount();

    await $.command.run({
      command: 'hyphae-panel',
      args: 'strip off',
      origin: { kind: 'composer' },
      presentation: { isFullscreen: false, columns: 120 },
    });

    // When quarantined > 0, renders 1-line red warning + Panel opener button
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

    await alertMount.press({ key: 'hyphae-strip-open' });
    expect(opened).toEqual(['hyphae-panel']);
    await alertMount.unmount();
  });
});
