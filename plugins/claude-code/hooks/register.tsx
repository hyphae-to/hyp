import type { Register } from 'claude-code';
import {
  buildSessionControlArgs,
  formatNextFire,
  formatPersistentStatusLine,
  formatRelativeAge,
  getQuarantinedCount,
  parseControlCommandResult,
  parsePanelCommandArgs,
  parseSnapshotJson,
  resolveActiveSession,
  resolveUiStateCandidates,
  sanitizeUiText,
  type HyphaeSnapshot,
  type PanelTab,
  type SessionControlAction,
  type SessionSummary,
} from './state';

const PANE_ID = 'hyphae-panel';
const COMMAND_NAME = 'hyphae-panel';
const REFRESH_INTERVAL_MS = 5_000;
const CONTROL_TIMEOUT_MS = 10_000;
const MAX_VISIBLE_ROWS = 12;

interface PanelUiState {
  tab: PanelTab;
  selectedSessionId: string | null;
  statusEnabled: boolean;
  lastStatusText: string | undefined;
  notice: { ok: boolean; text: string } | null;
  paneRefreshTimer: { cancel(): void } | null;
  statusRefreshTimer: { cancel(): void } | null;
}

function createInitialState(): PanelUiState {
  return {
    tab: 'subs',
    selectedSessionId: null,
    statusEnabled: true,
    lastStatusText: undefined,
    notice: null,
    paneRefreshTimer: null,
    statusRefreshTimer: null,
  };
}

interface SnapshotLoadResult {
  snapshot: HyphaeSnapshot | null;
  stateFile: string | null;
}

async function loadHyphaeSnapshot(
  homeDir: string,
  envStateDir: string | undefined,
  readText: (path: string) => Promise<string | null>,
): Promise<SnapshotLoadResult> {
  const baseHome = homeDir.replace(/[\\/]+$/, '');
  let nodeJsonText: string | null = null;
  if (baseHome) {
    nodeJsonText =
      (await readText(`${baseHome}/.config/hyphae/node.json`)) ??
      (await readText(`${baseHome}/.config/hyphae/connector.json`));
  }

  const { files } = resolveUiStateCandidates(baseHome, envStateDir, nodeJsonText);
  for (const filePath of files) {
    const raw = await readText(filePath);
    if (raw !== null) {
      const snapshot = parseSnapshotJson(raw);
      if (snapshot) {
        return { snapshot, stateFile: filePath };
      }
    }
  }
  return { snapshot: null, stateFile: files[0] ?? null };
}

function applyStatusText(
  $: { ui: { status(text: string | undefined): void } },
  uiState: PanelUiState,
  nextText: string | undefined,
): void {
  if (nextText === uiState.lastStatusText) return;
  uiState.lastStatusText = nextText;
  try {
    $.ui.status(nextText);
  } catch {
    // Ignore if host surface does not support status line updates.
  }
}

async function syncPersistentStatus(
  $: {
    fs: { read(path: string, opts: { as: 'text' }): Promise<unknown> };
    env: { get(name: string): Promise<string | undefined> };
    session: { id(): Promise<string> };
    ui: { status(text: string | undefined): void };
  },
  uiState: PanelUiState,
): Promise<void> {
  if (!uiState.statusEnabled) {
    applyStatusText($, uiState, undefined);
    return;
  }

  const safeReadText = async (path: string): Promise<string | null> => {
    try {
      const res = await $.fs.read(path, { as: 'text' });
      return typeof res === 'string' ? res : null;
    } catch {
      return null;
    }
  };

  const [homeDir, envStateDir, envSessionId, claudeSessionId] = await Promise.all([
    $.env.get('HOME').then((v) => v ?? '').catch(() => ''),
    $.env.get('HYPHAE_STATE_DIR').catch(() => undefined),
    $.env.get('HYPHAE_SESSION_ID').catch(() => undefined),
    $.session.id().catch(() => ''),
  ]);

  const { snapshot } = await loadHyphaeSnapshot(homeDir, envStateDir, safeReadText);
  const resolved = resolveActiveSession(
    snapshot,
    claudeSessionId,
    envSessionId,
    uiState.selectedSessionId,
  );
  const quarantined = getQuarantinedCount(snapshot, resolved.active);
  const line = formatPersistentStatusLine(snapshot, resolved.active, quarantined);
  applyStatusText($, uiState, line);
}

export const register: Register = (on) => {
  const uiState = createInitialState();

  const stopTimer = (timer: { cancel(): void } | null): null => {
    if (timer) {
      try {
        timer.cancel();
      } catch {
        // Ignore timer already cancelled.
      }
    }
    return null;
  };

  const stopPaneRefreshTimer = (): void => {
    uiState.paneRefreshTimer = stopTimer(uiState.paneRefreshTimer);
  };

  const stopStatusRefreshTimer = (): void => {
    uiState.statusRefreshTimer = stopTimer(uiState.statusRefreshTimer);
  };

  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: COMMAND_NAME,
      description:
        'Open the native Hyphae Mesh side panel (metadata-only inspector, bridges & controls)',
      argumentHint: '[subs|queue|rules|mesh|status on|off|close]',
      immediate: true,
    });

    await syncPersistentStatus($, uiState).catch(() => {});
    stopStatusRefreshTimer();
    uiState.statusRefreshTimer = $.clock.every(REFRESH_INTERVAL_MS, () => {
      void syncPersistentStatus($, uiState).catch(() => {});
    });

    return next(e);
  });

  on('command.run', { command: COMMAND_NAME }, async ($, e) => {
    const parsed = parsePanelCommandArgs(e.args);

    if (parsed.action === 'close') {
      stopPaneRefreshTimer();
      await $.ui.close({ id: PANE_ID });
      return { text: 'Closed Hyphae Mesh side panel.', isTextDisplayOnly: true };
    }

    if (parsed.action === 'status') {
      uiState.statusEnabled = parsed.enabled;
      await syncPersistentStatus($, uiState).catch(() => {});
      $.ui.invalidate('ui.render');
      return {
        text: `Hyphae status indicator ${parsed.enabled ? 'enabled' : 'disabled'}.`,
        isTextDisplayOnly: true,
      };
    }

    if (parsed.tab) {
      uiState.tab = parsed.tab;
    }
    uiState.notice = null;

    await $.ui.open({
      id: PANE_ID,
      title: 'Hyphae Mesh',
      focus: true,
      closeOnEscape: true,
    });

    await syncPersistentStatus($, uiState).catch(() => {});
    stopPaneRefreshTimer();
    uiState.paneRefreshTimer = $.clock.every(REFRESH_INTERVAL_MS, () => {
      $.ui.invalidate('ui.render');
    });
    $.ui.invalidate('ui.render');

    return { text: 'Opened Hyphae Mesh side panel.', isTextDisplayOnly: true };
  });

  on('ui.close', { id: PANE_ID }, async (_$, e, next) => {
    stopPaneRefreshTimer();
    return next(e);
  });

  on('session.end', async ($, e, next) => {
    stopPaneRefreshTimer();
    stopStatusRefreshTimer();
    applyStatusText($, uiState, undefined);
    return next(e);
  });

  on('ui.render', { component: 'Pane' }, async ($, e, next) => {
    if (e.requestId !== PANE_ID) {
      return next(e);
    }

    const { Box, Text, Button } = $.ui.resolve(e);

    const safeReadText = async (path: string): Promise<string | null> => {
      try {
        const res = await $.fs.read(path, { as: 'text' });
        return typeof res === 'string' ? res : null;
      } catch {
        return null;
      }
    };

    const [homeDir, envStateDir, envSessionId, claudeSessionId, nowMs] = await Promise.all([
      $.env.get('HOME').then((v) => v ?? '').catch(() => ''),
      $.env.get('HYPHAE_STATE_DIR').catch(() => undefined),
      $.env.get('HYPHAE_SESSION_ID').catch(() => undefined),
      $.session.id().catch(() => ''),
      $.clock.now().catch(() => Date.now()),
    ]);

    const { snapshot, stateFile } = await loadHyphaeSnapshot(homeDir, envStateDir, safeReadText);
    const resolved = resolveActiveSession(
      snapshot,
      claudeSessionId,
      envSessionId,
      uiState.selectedSessionId,
    );
    const active: SessionSummary | null = resolved.active;
    const quarantined = getQuarantinedCount(snapshot, active);

    // Keep the persistent bottom status line in sync whenever the panel redraws.
    const statusText = uiState.statusEnabled
      ? formatPersistentStatusLine(snapshot, active, quarantined)
      : undefined;
    applyStatusText($, uiState, statusText);

    const runSessionControl = async (
      action: SessionControlAction,
      targetSession: SessionSummary,
      label: string,
    ): Promise<void> => {
      try {
        const argv = buildSessionControlArgs(action, {
          sessionId: targetSession.sessionId,
          handle: targetSession.handle,
        });
        const res = await $.process.run(argv, { timeoutMs: CONTROL_TIMEOUT_MS });
        const outcome = parseControlCommandResult(res.exitCode, res.stdout, res.stderr, label);
        uiState.notice = { ok: outcome.ok, text: outcome.message };
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        uiState.notice = { ok: false, text: sanitizeUiText(msg, 140) || `${label} failed` };
      }
      $.ui.invalidate('ui.render');
    };

    const closePanel = async (): Promise<void> => {
      stopPaneRefreshTimer();
      await $.ui.close({ id: PANE_ID });
    };

    // Offline / missing ui/state.json graceful degradation
    if (!snapshot) {
      return (
        <Box flexDirection="column" paddingX={1} paddingY={1} gap={1}>
          <Box flexDirection="row" justifyContent="space-between" gap={1}>
            <Box flexDirection="row" gap={1}>
              <Text bold color="cyan">
                hyphae
              </Text>
              <Text color="yellow">○ offline</Text>
            </Box>
            <Box key="hover-hyphae-close-offline">
              <Button
                key="hyphae-close"
                plain
                role="dismiss"
                hover={{ color: 'white' }}
                onPress={closePanel}
              >
                <Text dimColor>× close</Text>
              </Button>
            </Box>
          </Box>
          <Box
            flexDirection="column"
            borderStyle="round"
            borderDimColor
            paddingX={1}
            paddingY={0}
            gap={0}
          >
            <Text color="yellow">Hyphae daemon offline or ui/state.json not found.</Text>
            {stateFile ? <Text dimColor>{`Checked: ${sanitizeUiText(stateFile, 96)}`}</Text> : null}
            <Text dimColor>Start your local node with `hyp node start` or check `hyp doctor`.</Text>
          </Box>
          {uiState.notice ? (
            <Text color={uiState.notice.ok ? 'green' : 'red'}>{uiState.notice.text}</Text>
          ) : null}
          <Box flexDirection="row" gap={2}>
            <Box key="hover-hyphae-refresh-offline">
              <Button
                key="hyphae-refresh"
                plain
                hotkey="r"
                hover={{ color: 'cyan' }}
                onPress={() => {
                  uiState.notice = { ok: true, text: 'Refreshed Hyphae state.' };
                  $.ui.invalidate('ui.render');
                }}
              >
                <Text dimColor>↻ refresh (r)</Text>
              </Button>
            </Box>
          </Box>
          <Text dimColor>metadata only · untrusted external data · Esc to close</Text>
        </Box>
      );
    }

    const daemon = snapshot.daemon;
    const nodeId = daemon?.nodeId || 'local';
    const daemonOnline = daemon ? daemon.online : true;
    const peersOnline = daemon?.peersOnline ?? 0;
    const handleLabel = active?.handle ? `@${active.handle}` : active ? 'unenrolled' : 'all sessions';

    const bridgeCount = active
      ? Math.max(active.counts.bridges, active.details.bridges.length)
      : snapshot.sessions.reduce(
          (acc, s) => acc + Math.max(s.counts.bridges, s.details.bridges.length),
          0,
        );
    const streamSubsCount = active
      ? active.counts.subscriptions
      : snapshot.sessions.reduce((acc, s) => acc + s.counts.subscriptions, 0);
    const subsCount = bridgeCount + streamSubsCount;
    const queueCount = active
      ? active.counts.queued
      : snapshot.sessions.reduce((acc, s) => acc + s.counts.queued, 0);
    const rulesCount = active
      ? active.details.mutes.length + active.details.rules.length
      : snapshot.sessions.reduce(
          (acc, s) => acc + s.details.mutes.length + s.details.rules.length,
          0,
        );
    const meshCount = active
      ? active.details.channelEntries.length || active.details.channels.length
      : snapshot.sessions.length;

    const renderTabBody = () => {
      if (!active) {
        const visibleSessions = snapshot.sessions.slice(0, MAX_VISIBLE_ROWS);
        return (
          <Box flexDirection="column" gap={1}>
            <Text bold>Local Sessions</Text>
            <Text dimColor>
              No active Claude session matched ({sanitizeUiText(claudeSessionId || 'unbound', 48)}
              ). Select a session below or enroll with hyp_mesh.
            </Text>
            {visibleSessions.length === 0 ? (
              <Text dimColor>No registered sessions on this node yet.</Text>
            ) : (
              visibleSessions.map((sess, idx) => {
                const sessSubs = sess.counts.subscriptions + sess.counts.bridges;
                const bridgeSuffix =
                  sess.bridges.length > 0 ? ` · ${sess.bridges[0]}` : '';
                return (
                  <Box
                    key={`sess-row-${idx}`}
                    flexDirection="row"
                    justifyContent="space-between"
                    gap={1}
                  >
                    <Text>
                      {`${sess.handle ? `@${sess.handle}` : sess.sessionId} · ${sess.harness}${bridgeSuffix} · ${sessSubs}s · ${sess.counts.queued}q${sess.focusMode ? ' · FOCUS' : ''}`}
                    </Text>
                    <Box key={`hover-select-${idx}`}>
                      <Button
                        key={`hyphae-select-${idx}`}
                        plain
                        hover={{ color: 'cyan' }}
                        onPress={() => {
                          uiState.selectedSessionId = sess.sessionId;
                          uiState.notice = null;
                          $.ui.invalidate('ui.render');
                        }}
                      >
                        <Text color="cyan">inspect →</Text>
                      </Button>
                    </Box>
                  </Box>
                );
              })
            )}
          </Box>
        );
      }

      if (uiState.tab === 'subs') {
        const bridges = active.details.bridges.slice(0, MAX_VISIBLE_ROWS);
        const subs = active.details.subscriptions.slice(0, MAX_VISIBLE_ROWS);
        return (
          <Box flexDirection="column" gap={1}>
            {bridges.length > 0 ? (
              <Box flexDirection="column" gap={0}>
                <Text bold>{`Bridges (${bridges.length})`}</Text>
                {bridges.map((bridge, idx) => (
                  <Box
                    key={`bridge-row-${idx}`}
                    flexDirection="row"
                    justifyContent="space-between"
                    gap={1}
                  >
                    <Box flexDirection="row" gap={1}>
                      <Text color={bridge.role === 'primary' ? 'green' : 'cyan'}>●</Text>
                      <Text bold color="cyan">
                        {bridge.label}
                      </Text>
                    </Box>
                    <Box flexDirection="row" gap={1}>
                      <Text
                        bold={bridge.role === 'primary'}
                        color={bridge.role === 'primary' ? 'green' : undefined}
                        dimColor={bridge.role !== 'primary'}
                      >
                        {bridge.role}
                      </Text>
                      <Text dimColor>· bridge</Text>
                    </Box>
                  </Box>
                ))}
              </Box>
            ) : null}

            <Box flexDirection="column" gap={0}>
              <Text bold>{`Streams (${active.counts.subscriptions})`}</Text>
              {subs.length === 0 ? (
                <Text dimColor>
                  {bridges.length > 0
                    ? 'No stream subscriptions · use hyp_stream to subscribe.'
                    : 'No linked bridges or stream subscriptions. Use hyp_bridge or hyp_stream.'}
                </Text>
              ) : (
                subs.map((sub, idx) => {
                  const subId = sub.id || sub.key || sub.topic;
                  const detailLine = [
                    sub.mode,
                    sub.originNode,
                    sub.coalesceSeconds > 0 ? `${sub.coalesceSeconds}s coalesce` : '',
                    sub.filterSummary ? `filter: ${sub.filterSummary}` : '',
                  ]
                    .filter(Boolean)
                    .join(' · ');
                  return (
                    <Box
                      key={`sub-row-${idx}`}
                      flexDirection="row"
                      justifyContent="space-between"
                      gap={1}
                    >
                      <Box flexDirection="column" flexGrow={1}>
                        <Text bold color="cyan">
                          {sub.topic}
                        </Text>
                        <Text dimColor>{detailLine}</Text>
                      </Box>
                      <Box key={`hover-unsub-${idx}`}>
                        <Button
                          key={`hyphae-unsub-${idx}`}
                          plain
                          hover={{ color: 'red' }}
                          onPress={() =>
                            runSessionControl(
                              { kind: 'unsubscribe', id: subId },
                              active,
                              `Unsubscribe ${sub.topic}`,
                            )
                          }
                        >
                          <Text dimColor>× unsub</Text>
                        </Button>
                      </Box>
                    </Box>
                  );
                })
              )}
            </Box>
          </Box>
        );
      }

      if (uiState.tab === 'queue') {
        const b = active.unreadBreakdown;
        const items = active.details.queuedItems.slice(0, MAX_VISIBLE_ROWS);
        const breakdownLine = `msg:${b.messages} · ev:${b.events} · bridge:${b.plugins} · files:${b.transfers} · kv:${b.kv}`;
        return (
          <Box flexDirection="column" gap={1}>
            <Text bold>{`Queued Metadata (${active.counts.queued} unread · ${active.counts.unnotified} unnotified)`}</Text>
            <Text dimColor>{breakdownLine}</Text>
            {items.length === 0 ? (
              <Text dimColor>Queue is clear.</Text>
            ) : (
              items.map((item, idx) => {
                const age = formatRelativeAge(item.receivedAt, nowMs);
                const urgencyColor =
                  item.urgency === 'interrupt'
                    ? 'red'
                    : item.urgency === 'notify'
                      ? 'yellow'
                      : 'cyan';
                return (
                  <Box key={`q-row-${idx}`} flexDirection="row" gap={1}>
                    <Text color={urgencyColor}>{item.urgency}</Text>
                    <Text bold>{item.kind}</Text>
                    <Text>{item.source}</Text>
                    {age ? <Text dimColor>{age}</Text> : null}
                  </Box>
                );
              })
            )}
            <Text dimColor>
              Metadata only — use hyp_inbox to read or acknowledge unread items.
            </Text>
          </Box>
        );
      }

      if (uiState.tab === 'rules') {
        const mutes = active.details.mutes.slice(0, MAX_VISIBLE_ROWS);
        const rules = active.details.rules.slice(0, MAX_VISIBLE_ROWS);
        return (
          <Box flexDirection="column" gap={1}>
            <Text bold>{`Mutes (${active.details.mutes.length}) · Delivery Rules (${active.details.rules.length})`}</Text>
            <Text dimColor>
              {`Default mode: ${active.deliveryMode} · Focus: ${active.focusMode ? 'ON' : 'OFF'}${active.focusAllowInterruptVips ? ' (VIP interrupts allowed)' : ''}`}
            </Text>
            {mutes.length === 0 ? (
              <Text dimColor>No active mute patterns.</Text>
            ) : (
              mutes.map((m, idx) => {
                const age = formatRelativeAge(m.mutedAt, nowMs);
                return (
                  <Box
                    key={`mute-row-${idx}`}
                    flexDirection="row"
                    justifyContent="space-between"
                    gap={1}
                  >
                    <Text>{`mute ${m.pattern} (${m.scope}${age ? ` · ${age}` : ''})`}</Text>
                    <Box key={`hover-unmute-${idx}`}>
                      <Button
                        key={`hyphae-unmute-${idx}`}
                        plain
                        hover={{ color: 'cyan' }}
                        onPress={() =>
                          runSessionControl(
                            { kind: 'unmute', pattern: m.pattern, scope: m.scope },
                            active,
                            `Unmute ${m.pattern}`,
                          )
                        }
                      >
                        <Text dimColor>× unmute</Text>
                      </Button>
                    </Box>
                  </Box>
                );
              })
            )}
            {rules.length > 0 ? (
              <Box flexDirection="column" gap={0}>
                <Text bold>Per-Source Rules</Text>
                {rules.map((r, idx) => (
                  <Text key={`rule-row-${idx}`}>{`${r.target} -> ${r.delivery}`}</Text>
                ))}
              </Box>
            ) : null}
          </Box>
        );
      }

      // 'mesh' tab: Channels, Wakeups (metadata-only), and peer count
      const chanRows =
        active.details.channelEntries.length > 0
          ? active.details.channelEntries.slice(0, MAX_VISIBLE_ROWS)
          : active.details.channels.slice(0, MAX_VISIBLE_ROWS).map((ch) => ({
              hostNode: nodeId,
              channel: ch,
              mode: 'open',
            }));
      const wakeups = active.details.wakeups.slice(0, 6);

      return (
        <Box flexDirection="column" gap={1}>
          <Text bold>{`Channels (${chanRows.length}) · Peers Online (${peersOnline})`}</Text>
          {chanRows.length === 0 ? (
            <Text dimColor>Not joined to any #channels. Use hyp_mesh to join.</Text>
          ) : (
            chanRows.map((ch, idx) => {
              const display =
                ch.hostNode && ch.hostNode !== 'local' && ch.hostNode !== nodeId
                  ? `${ch.hostNode}/${ch.channel}`
                  : ch.channel;
              return (
                <Box
                  key={`ch-row-${idx}`}
                  flexDirection="row"
                  justifyContent="space-between"
                  gap={1}
                >
                  <Text>{`${display} (${ch.mode})`}</Text>
                  <Box key={`hover-leave-${idx}`}>
                    <Button
                      key={`hyphae-leave-${idx}`}
                      plain
                      hover={{ color: 'red' }}
                      onPress={() =>
                        runSessionControl(
                          { kind: 'leave', channel: display },
                          active,
                          `Leave ${display}`,
                        )
                      }
                    >
                      <Text dimColor>× leave</Text>
                    </Button>
                  </Box>
                </Box>
              );
            })
          )}
          {wakeups.length > 0 ? (
            <Box flexDirection="column" gap={0}>
              <Text bold>{`Wakeups (${wakeups.length})`}</Text>
              {wakeups.map((w, idx) => (
                <Text key={`wk-row-${idx}`} dimColor>
                  {`${w.label} · ${w.triggerKind} · ${w.urgency} · ${formatNextFire(w.nextFireAt, nowMs)}`}
                </Text>
              ))}
            </Box>
          ) : null}
        </Box>
      );
    };

    const tabs: { id: PanelTab; hotkey: string; label: string }[] = [
      { id: 'subs', hotkey: '1', label: `Subs ${subsCount}` },
      { id: 'queue', hotkey: '2', label: `Queue ${queueCount}` },
      { id: 'rules', hotkey: '3', label: `Rules ${rulesCount}` },
      { id: 'mesh', hotkey: '4', label: `Mesh ${meshCount}` },
    ];

    const headerBridgeText =
      active && active.bridges.length > 0
        ? active.bridges.length === 1
          ? active.bridges[0]
          : `${active.bridges[0]} +${active.bridges.length - 1}`
        : null;

    return (
      <Box flexDirection="column" paddingX={1} paddingY={1} gap={1}>
        {/* Header */}
        <Box flexDirection="column" gap={0}>
          <Box flexDirection="row" justifyContent="space-between" gap={1}>
            <Box flexDirection="row" gap={1}>
              <Text bold color="cyan">
                hyphae
              </Text>
              <Text dimColor>·</Text>
              <Text bold>{handleLabel}</Text>
            </Box>
            <Box flexDirection="row" gap={1}>
              <Text color={daemonOnline ? 'green' : 'yellow'}>
                {daemonOnline ? `● online · ${nodeId}` : `○ offline · ${nodeId}`}
              </Text>
              <Box key="hover-hyphae-close">
                <Button
                  key="hyphae-close"
                  plain
                  role="dismiss"
                  hover={{ color: 'white' }}
                  onPress={closePanel}
                >
                  <Text dimColor> ×</Text>
                </Button>
              </Box>
            </Box>
          </Box>
          <Box flexDirection="row" gap={1} flexWrap="wrap">
            <Text dimColor>{`${peersOnline} peers`}</Text>
            {active?.transportKind ? <Text dimColor>{`· ${active.transportKind}`}</Text> : null}
            {headerBridgeText ? <Text color="cyan">{`· ${headerBridgeText}`}</Text> : null}
            {active?.focusMode ? (
              <Text bold color="yellow">
                · FOCUS
              </Text>
            ) : null}
            {active?.mutedAll ? (
              <Text bold color="yellow">
                · MUTED*
              </Text>
            ) : null}
            {active?.counts.mutedArchived ? (
              <Text dimColor>{`· ${active.counts.mutedArchived} muted-archived`}</Text>
            ) : null}
          </Box>
        </Box>

        {/* Red Quarantine Alert (STRICTLY human-CLI-only — NEVER an approve/reject button!) */}
        {quarantined > 0 ? (
          <Box flexDirection="column" borderStyle="round" borderColor="red" paddingX={1}>
            <Text bold color="red">
              {`⚠ ${quarantined} quarantined item${quarantined === 1 ? '' : 's'}`}
            </Text>
            <Text color="red">
              Human CLI boundary: review directly in your terminal via `hyp gate review`.
            </Text>
          </Box>
        ) : null}

        {/* Sleek Borderless Controls (zero [ ... ] brackets) */}
        <Box flexDirection="row" gap={2} flexWrap="wrap">
          {active ? (
            <Box key="hover-hyphae-focus">
              <Button
                key="hyphae-toggle-focus"
                plain
                hotkey="f"
                hover={{ color: 'yellow' }}
                onPress={() =>
                  runSessionControl(
                    { kind: 'focus', enabled: !active.focusMode },
                    active,
                    active.focusMode ? 'Focus OFF' : 'Focus ON',
                  )
                }
              >
                <Text
                  bold={active.focusMode}
                  color={active.focusMode ? 'yellow' : undefined}
                  dimColor={!active.focusMode}
                >
                  {active.focusMode ? '● focus on (f)' : '○ focus (f)'}
                </Text>
              </Button>
            </Box>
          ) : null}
          <Box key="hover-hyphae-refresh">
            <Button
              key="hyphae-refresh"
              plain
              hotkey="r"
              hover={{ color: 'cyan' }}
              onPress={() => {
                uiState.notice = { ok: true, text: 'Refreshed Hyphae metadata.' };
                $.ui.invalidate('ui.render');
              }}
            >
              <Text dimColor>↻ refresh (r)</Text>
            </Button>
          </Box>
          <Box key="hover-hyphae-status">
            <Button
              key="hyphae-toggle-status"
              plain
              hover={{ color: 'cyan' }}
              onPress={() => {
                uiState.statusEnabled = !uiState.statusEnabled;
                applyStatusText(
                  $,
                  uiState,
                  uiState.statusEnabled
                    ? formatPersistentStatusLine(snapshot, active, quarantined)
                    : undefined,
                );
                uiState.notice = {
                  ok: true,
                  text: `Status indicator ${uiState.statusEnabled ? 'ON' : 'OFF'}.`,
                };
                $.ui.invalidate('ui.render');
              }}
            >
              <Text color={uiState.statusEnabled ? 'green' : undefined} dimColor={!uiState.statusEnabled}>
                {uiState.statusEnabled ? '● status' : '○ status'}
              </Text>
            </Button>
          </Box>
          {uiState.selectedSessionId ? (
            <Box key="hover-hyphae-all-sessions">
              <Button
                key="hyphae-all-sessions"
                plain
                hover={{ color: 'cyan' }}
                onPress={() => {
                  uiState.selectedSessionId = null;
                  $.ui.invalidate('ui.render');
                }}
              >
                <Text dimColor>← all sessions</Text>
              </Button>
            </Box>
          ) : null}
        </Box>

        {/* Action Feedback */}
        {uiState.notice ? (
          <Text color={uiState.notice.ok ? 'green' : 'red'}>{uiState.notice.text}</Text>
        ) : null}

        {/* Underlined Tab Bar (zero [ ... ] brackets) */}
        {active ? (
          <Box flexDirection="row" gap={2} flexWrap="wrap">
            {tabs.map((tab) => {
              const isActive = uiState.tab === tab.id;
              return (
                <Box key={`hover-tab-${tab.id}`}>
                  <Button
                    key={`hyphae-tab-${tab.id}`}
                    plain
                    hotkey={tab.hotkey}
                    hover={{ color: 'cyan' }}
                    onPress={() => {
                      uiState.tab = tab.id;
                      $.ui.invalidate('ui.render');
                    }}
                  >
                    <Text
                      bold={isActive}
                      underline={isActive}
                      color={isActive ? 'cyan' : undefined}
                      dimColor={!isActive}
                    >
                      {tab.label}
                    </Text>
                  </Button>
                </Box>
              );
            })}
          </Box>
        ) : null}

        {/* Tab Content */}
        <Box
          flexDirection="column"
          borderStyle="round"
          borderDimColor
          paddingX={1}
          paddingY={0}
        >
          {renderTabBody()}
        </Box>

        <Text dimColor>metadata only · untrusted external data · Esc to close</Text>
      </Box>
    );
  });

  // Emergency-only AbovePrompt banner: 100% hidden unless Security Gate has quarantined items.
  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    const safeReadText = async (path: string): Promise<string | null> => {
      try {
        const res = await $.fs.read(path, { as: 'text' });
        return typeof res === 'string' ? res : null;
      } catch {
        return null;
      }
    };

    const [homeDir, envStateDir, envSessionId, claudeSessionId] = await Promise.all([
      $.env.get('HOME').then((v) => v ?? '').catch(() => ''),
      $.env.get('HYPHAE_STATE_DIR').catch(() => undefined),
      $.env.get('HYPHAE_SESSION_ID').catch(() => undefined),
      $.session.id().catch(() => ''),
    ]);

    const { snapshot } = await loadHyphaeSnapshot(homeDir, envStateDir, safeReadText);
    const resolved = resolveActiveSession(
      snapshot,
      claudeSessionId,
      envSessionId,
      uiState.selectedSessionId,
    );
    const quarantined = getQuarantinedCount(snapshot, resolved.active);

    if (quarantined === 0) {
      return next(e);
    }

    const { Box, Text, Button } = $.ui.resolve(e);
    return (
      <Box flexDirection="row" gap={1} paddingX={1}>
        <Text bold color="red">
          {`⚠ hyphae: ${quarantined} quarantined — run \`hyp gate review\` in terminal`}
        </Text>
        <Box key="hover-hyphae-strip-open">
          <Button
            key="hyphae-strip-open"
            plain
            hover={{ color: 'white' }}
            onPress={async () => {
              await $.ui.open({
                id: PANE_ID,
                title: 'Hyphae Mesh',
                focus: true,
                closeOnEscape: true,
              });
            }}
          >
            <Text color="cyan">open panel →</Text>
          </Button>
        </Box>
      </Box>
    );
  });
};
