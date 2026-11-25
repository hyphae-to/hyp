import type { Register } from 'claude-code';
import {
  buildSessionControlArgs,
  formatNextFire,
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
  abovePromptEnabled: boolean;
  notice: { ok: boolean; text: string } | null;
  refreshTimer: { cancel(): void } | null;
}

function createInitialState(): PanelUiState {
  return {
    tab: 'subs',
    selectedSessionId: null,
    abovePromptEnabled: false,
    notice: null,
    refreshTimer: null,
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

export const register: Register = (on) => {
  const uiState = createInitialState();

  const stopRefreshTimer = (): void => {
    if (uiState.refreshTimer) {
      try {
        uiState.refreshTimer.cancel();
      } catch {
        // Ignore timer already cancelled.
      }
      uiState.refreshTimer = null;
    }
  };

  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: COMMAND_NAME,
      description:
        'Open the native Hyphae Mesh side panel (metadata-only inspector & session controls)',
      argumentHint: '[subs|queue|rules|mesh|strip on|off|close]',
      immediate: true,
    });
    return next(e);
  });

  on('command.run', { command: COMMAND_NAME }, async ($, e) => {
    const parsed = parsePanelCommandArgs(e.args);

    if (parsed.action === 'close') {
      stopRefreshTimer();
      await $.ui.close({ id: PANE_ID });
      return { text: 'Closed Hyphae Mesh side panel.', isTextDisplayOnly: true };
    }

    if (parsed.action === 'strip') {
      uiState.abovePromptEnabled = parsed.enabled;
      $.ui.invalidate('ui.render');
      return {
        text: `Hyphae above-prompt badge ${parsed.enabled ? 'enabled' : 'disabled'}.`,
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

    stopRefreshTimer();
    uiState.refreshTimer = $.clock.every(REFRESH_INTERVAL_MS, () => {
      $.ui.invalidate('ui.render');
    });
    $.ui.invalidate('ui.render');

    return { text: 'Opened Hyphae Mesh side panel.', isTextDisplayOnly: true };
  });

  on('ui.close', { id: PANE_ID }, async (_$, e, next) => {
    stopRefreshTimer();
    return next(e);
  });

  on('session.end', async (_$, e, next) => {
    stopRefreshTimer();
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

    // Offline / missing ui/state.json graceful degradation
    if (!snapshot) {
      return (
        <Box flexDirection="column" paddingX={1} paddingY={1} gap={1}>
          <Box flexDirection="row" justifyContent="space-between" gap={1}>
            <Text bold color="cyan">
              Hyphae Mesh
            </Text>
            <Text color="yellow">OFFLINE</Text>
          </Box>
          <Text dimColor>
            Metadata-only view · untrusted external data · zero bodies or secrets
          </Text>
          <Box flexDirection="column" borderStyle="round" borderColor="gray" paddingX={1} gap={0}>
            <Text color="yellow">Hyphae daemon offline or ui/state.json not found.</Text>
            {stateFile ? <Text dimColor>{`Checked: ${sanitizeUiText(stateFile, 96)}`}</Text> : null}
            <Text dimColor>Start your local node with `hyp node start` or check `hyp doctor`.</Text>
          </Box>
          {uiState.notice ? (
            <Text color={uiState.notice.ok ? 'green' : 'red'}>{uiState.notice.text}</Text>
          ) : null}
          <Box flexDirection="row" gap={1}>
            <Button
              key="hyphae-refresh"
              label="Refresh"
              variant="secondary"
              onPress={() => {
                uiState.notice = { ok: true, text: 'Refreshed Hyphae state.' };
                $.ui.invalidate('ui.render');
              }}
            />
            <Button
              key="hyphae-close"
              label="Close"
              role="dismiss"
              onPress={async () => {
                stopRefreshTimer();
                await $.ui.close({ id: PANE_ID });
              }}
            />
          </Box>
        </Box>
      );
    }

    const daemon = snapshot.daemon;
    const nodeId = daemon?.nodeId || 'local';
    const daemonOnline = daemon ? daemon.online : true;
    const peersOnline = daemon?.peersOnline ?? 0;
    const handleLabel = active?.handle ? `@${active.handle}` : active ? 'unenrolled' : 'all sessions';

    const subsCount = active
      ? active.counts.subscriptions
      : snapshot.sessions.reduce((acc, s) => acc + s.counts.subscriptions, 0);
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
            <Text bold>Local Sessions Summary</Text>
            <Text dimColor>
              No active Claude session matched ({sanitizeUiText(claudeSessionId || 'unbound', 48)}
              ). Select a session below or enroll with hyp_mesh.
            </Text>
            {visibleSessions.length === 0 ? (
              <Text dimColor>No registered sessions on this node yet.</Text>
            ) : (
              visibleSessions.map((sess, idx) => (
                <Box
                  key={`sess-row-${idx}`}
                  flexDirection="row"
                  justifyContent="space-between"
                  gap={1}
                >
                  <Text>
                    {`${sess.handle ? `@${sess.handle}` : sess.sessionId} · ${sess.harness} · ${sess.counts.subscriptions}s · ${sess.counts.queued}q${sess.focusMode ? ' · FOCUS' : ''}`}
                  </Text>
                  <Button
                    key={`hyphae-select-${idx}`}
                    label="Inspect"
                    variant="secondary"
                    onPress={() => {
                      uiState.selectedSessionId = sess.sessionId;
                      uiState.notice = null;
                      $.ui.invalidate('ui.render');
                    }}
                  />
                </Box>
              ))
            )}
          </Box>
        );
      }

      if (uiState.tab === 'subs') {
        const subs = active.details.subscriptions.slice(0, MAX_VISIBLE_ROWS);
        return (
          <Box flexDirection="column" gap={1}>
            <Text bold>{`Subscriptions (${active.counts.subscriptions})`}</Text>
            {subs.length === 0 ? (
              <Text dimColor>No active stream subscriptions. Use hyp_stream to subscribe.</Text>
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
                    <Button
                      key={`hyphae-unsub-${idx}`}
                      label="Unsub"
                      variant="secondary"
                      onPress={() =>
                        runSessionControl(
                          { kind: 'unsubscribe', id: subId },
                          active,
                          `Unsubscribe ${sub.topic}`,
                        )
                      }
                    />
                  </Box>
                );
              })
            )}
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
                    <Text color={urgencyColor}>{`[${item.urgency}]`}</Text>
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
                    <Text>{`MUTE ${m.pattern} (${m.scope}${age ? ` · ${age}` : ''})`}</Text>
                    <Button
                      key={`hyphae-unmute-${idx}`}
                      label="Unmute"
                      variant="secondary"
                      onPress={() =>
                        runSessionControl(
                          { kind: 'unmute', pattern: m.pattern, scope: m.scope },
                          active,
                          `Unmute ${m.pattern}`,
                        )
                      }
                    />
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

      // 'mesh' tab: Channels, Wakeups (metadata-only), and other sessions
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
                  <Button
                    key={`hyphae-leave-${idx}`}
                    label="Leave"
                    variant="secondary"
                    onPress={() =>
                      runSessionControl(
                        { kind: 'leave', channel: display },
                        active,
                        `Leave ${display}`,
                      )
                    }
                  />
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

    return (
      <Box flexDirection="column" paddingX={1} paddingY={1} gap={1}>
        {/* Header */}
        <Box flexDirection="column" gap={0}>
          <Box flexDirection="row" justifyContent="space-between" gap={1}>
            <Text bold color="cyan">
              {`Hyphae · ${handleLabel}`}
            </Text>
            <Text color={daemonOnline ? 'green' : 'yellow'}>
              {daemonOnline ? `ONLINE · ${nodeId}` : `OFFLINE · ${nodeId}`}
            </Text>
          </Box>
          <Box flexDirection="row" gap={1}>
            <Text dimColor>{`${peersOnline} peers`}</Text>
            {active?.transportKind ? <Text dimColor>{`· ${active.transportKind}`}</Text> : null}
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
          <Text dimColor>Untrusted external mesh metadata · zero message bodies or secrets</Text>
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

        {/* Interactive Quick Controls */}
        <Box flexDirection="row" gap={1} flexWrap="wrap">
          {active ? (
            <Button
              key="hyphae-toggle-focus"
              label={active.focusMode ? 'Focus: ON' : 'Focus: OFF'}
              variant={active.focusMode ? 'primary' : 'secondary'}
              onPress={() =>
                runSessionControl(
                  { kind: 'focus', enabled: !active.focusMode },
                  active,
                  active.focusMode ? 'Focus OFF' : 'Focus ON',
                )
              }
            />
          ) : null}
          <Button
            key="hyphae-refresh"
            label="Refresh"
            variant="secondary"
            onPress={() => {
              uiState.notice = { ok: true, text: 'Refreshed Hyphae metadata.' };
              $.ui.invalidate('ui.render');
            }}
          />
          <Button
            key="hyphae-toggle-strip"
            label={uiState.abovePromptEnabled ? 'Strip: ON' : 'Strip: OFF'}
            variant="secondary"
            onPress={() => {
              uiState.abovePromptEnabled = !uiState.abovePromptEnabled;
              $.ui.invalidate('ui.render');
            }}
          />
          {uiState.selectedSessionId ? (
            <Button
              key="hyphae-all-sessions"
              label="All Sessions"
              variant="secondary"
              onPress={() => {
                uiState.selectedSessionId = null;
                $.ui.invalidate('ui.render');
              }}
            />
          ) : null}
          <Button
            key="hyphae-close"
            label="Close"
            role="dismiss"
            onPress={async () => {
              stopRefreshTimer();
              await $.ui.close({ id: PANE_ID });
            }}
          />
        </Box>

        {/* Action Feedback */}
        {uiState.notice ? (
          <Text color={uiState.notice.ok ? 'green' : 'red'}>{uiState.notice.text}</Text>
        ) : null}

        {/* Section Tabs */}
        {active ? (
          <Box flexDirection="row" gap={1} flexWrap="wrap">
            <Button
              key="hyphae-tab-subs"
              label={`Subs (${subsCount})`}
              variant={uiState.tab === 'subs' ? 'primary' : 'secondary'}
              onPress={() => {
                uiState.tab = 'subs';
                $.ui.invalidate('ui.render');
              }}
            />
            <Button
              key="hyphae-tab-queue"
              label={`Queue (${queueCount})`}
              variant={uiState.tab === 'queue' ? 'primary' : 'secondary'}
              onPress={() => {
                uiState.tab = 'queue';
                $.ui.invalidate('ui.render');
              }}
            />
            <Button
              key="hyphae-tab-rules"
              label={`Rules (${rulesCount})`}
              variant={uiState.tab === 'rules' ? 'primary' : 'secondary'}
              onPress={() => {
                uiState.tab = 'rules';
                $.ui.invalidate('ui.render');
              }}
            />
            <Button
              key="hyphae-tab-mesh"
              label={`Mesh (${meshCount})`}
              variant={uiState.tab === 'mesh' ? 'primary' : 'secondary'}
              onPress={() => {
                uiState.tab = 'mesh';
                $.ui.invalidate('ui.render');
              }}
            />
          </Box>
        ) : null}

        {/* Tab Content */}
        <Box flexDirection="column" borderStyle="round" borderColor="gray" paddingX={1} paddingY={0}>
          {renderTabBody()}
        </Box>
      </Box>
    );
  });

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
    const active = resolved.active;
    const quarantined = getQuarantinedCount(snapshot, active);

    // Zero-clutter default: hide completely unless quarantined > 0 or user opted in.
    if (quarantined === 0 && !uiState.abovePromptEnabled) {
      return next(e);
    }

    const { Box, Text, Button } = $.ui.resolve(e);

    if (quarantined > 0) {
      return (
        <Box flexDirection="row" gap={1} paddingX={1}>
          <Text bold color="red">
            {`⚠ Hyphae: ${quarantined} quarantined — run \`hyp gate review\` in terminal`}
          </Text>
          <Button
            key="hyphae-strip-open"
            label="Panel"
            plain
            onPress={async () => {
              await $.ui.open({
                id: PANE_ID,
                title: 'Hyphae Mesh',
                focus: true,
                closeOnEscape: true,
              });
            }}
          />
        </Box>
      );
    }

    const summary = active
      ? `Hyphae ${active.handle ? `@${active.handle}` : active.sessionId} · ${active.counts.subscriptions}s · ${active.counts.queued}q${active.focusMode ? ' · FOCUS' : ''}`
      : snapshot
        ? `Hyphae · ${snapshot.daemon?.nodeId ?? 'local'} · ${snapshot.sessions.length} sessions`
        : 'Hyphae · offline';

    return (
      <Box flexDirection="row" gap={1} paddingX={1}>
        <Text color="cyan">{summary}</Text>
        <Button
          key="hyphae-strip-open"
          label="Panel"
          plain
          onPress={async () => {
            await $.ui.open({
              id: PANE_ID,
              title: 'Hyphae Mesh',
              focus: true,
              closeOnEscape: true,
            });
          }}
        />
      </Box>
    );
  });
};
