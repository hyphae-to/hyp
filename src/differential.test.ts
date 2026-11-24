/**
 * Differential Testing Suite for Hyphae, grounded in William M. McKeeman's
 * "Differential Testing for Software" (Digital Technical Journal, Vol. 10 No. 1, 1998).
 *
 * Covers three differential pillars:
 *   1. Stateful Model Oracle vs. real RouterCore + Connector + SQLite State (Levels 4–6)
 *   2. Cross-Harness Parity Matrix across all 7 durable-mailbox harnesses ("comparable systems")
 *   3. Nearby-Altered Perturbations + Differential Filter Evaluator (Levels 1–4)
 */
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { startDaemon, type RunningDaemon } from "./daemon.ts";
import type { Backend } from "./delivery.ts";
import {
  MESH_TOOLS,
  addressPattern,
  channelPattern,
  decodeItem,
  formatItem,
  handlePattern,
  normalizeChannelName,
  normalizeMeshToolName,
  normalizeMutePattern,
  type DeliveryMode,
  type HarnessKind,
} from "./protocol.ts";
import { RouterError } from "./router.ts";
import { isHandle, parseAddress } from "./core/address.ts";
import {
  MAX_ATTRIBUTE_CHARS,
  MAX_DATA_BYTES,
  MAX_EVENT_BYTES,
  checkCloudEvent,
  type CloudEvent,
} from "./core/router/cloudevent.ts";
import { DEFAULT_LIMITS, RouterCore } from "./core/router/core.ts";
import {
  MAX_FILTERS_BYTES,
  MAX_FILTER_DEPTH,
  checkFilters,
  matchesFilters,
  type Filter,
} from "./core/router/filter.ts";
import { serveRouter } from "./core/router/server.ts";

// ============================================================================
// Deterministic PRNG (mulberry32) & diagnostic helpers
// ============================================================================

const DEFAULT_SEED = 0x5eed1998;

function resolveSeed(): number {
  const raw = process.env.HYPHAE_DIFF_SEED;
  if (!raw) return DEFAULT_SEED;
  const parsed = raw.startsWith("0x") || raw.startsWith("0X")
    ? Number.parseInt(raw.slice(2), 16)
    : Number.parseInt(raw, 10);
  if (!Number.isFinite(parsed)) return DEFAULT_SEED;
  return parsed >>> 0;
}

function mulberry32(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

class Rng {
  readonly seed: number;
  readonly #next: () => number;

  constructor(seed: number) {
    this.seed = seed >>> 0;
    this.#next = mulberry32(this.seed);
  }

  next(): number {
    return this.#next();
  }

  int(maxExclusive: number): number {
    return Math.floor(this.#next() * maxExclusive);
  }

  bool(probability = 0.5): boolean {
    return this.#next() < probability;
  }

  pick<T>(items: readonly T[]): T {
    return items[this.int(items.length)];
  }
}

function formatFailureContext(seed: number, history: readonly string[], label: string): string {
  const tail = history.slice(-15);
  return [
    `${label} (HYPHAE_DIFF_SEED=0x${seed.toString(16)})`,
    `Last ${tail.length} of ${history.length} steps:`,
    ...tail.map((line) => `  ${line}`),
  ].join("\n");
}

async function waitForConnectorOnline(routerCore: RouterCore, timeoutMs = 4_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const peers = routerCore.peers();
    if (peers.length > 0 && peers.every((peer) => peer.online)) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`Connector did not attach SSE stream within ${timeoutMs}ms`);
}

async function waitForRouterQuiescence(
  routerReadDb: DatabaseSync,
  daemon: RunningDaemon,
  timeoutMs = 3_000,
): Promise<void> {
  const countPending = routerReadDb.prepare("SELECT COUNT(*) AS n FROM messages WHERE state = 'pending'");
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const pending = Number(countPending.get()?.n ?? 0);
    if (pending === 0) {
      await daemon.connector.drain();
      if (Number(countPending.get()?.n ?? 0) === 0) return;
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  const stuck = routerReadDb.prepare("SELECT id, from_addr, to_addr, reason FROM messages WHERE state = 'pending'").all();
  throw new Error(`Router still had ${stuck.length} pending message(s) after ${timeoutMs}ms: ${JSON.stringify(stuck)}`);
}

// ============================================================================
// Pure In-Memory Specification Oracle (Test 1)
// ============================================================================

interface OracleMailboxEntry {
  readonly from: string;
  readonly text: string;
  readonly source: string;
  notified: boolean;
}

interface OracleSession {
  readonly id: string;
  handle: string | null;
  deliveryMode: DeliveryMode;
  mailbox: OracleMailboxEntry[];
}

interface OracleMute {
  readonly scope: "connector" | "session";
  readonly pattern: string;
}

class ModelOracle {
  readonly connectorId: string;
  readonly #sessions = new Map<string, OracleSession>();
  readonly #channels = new Map<string, Set<string>>();
  readonly #connectorMutes = new Set<string>();
  readonly #sessionMutes = new Map<string, Set<string>>();

  constructor(connectorId: string, sessionIds: readonly string[]) {
    this.connectorId = connectorId;
    for (const id of sessionIds) {
      this.#sessions.set(id, { id, handle: null, deliveryMode: "full", mailbox: [] });
      this.#sessionMutes.set(id, new Set());
    }
  }

  #session(id: string): OracleSession {
    const s = this.#sessions.get(id);
    if (!s) throw new Error(`Unknown oracle session ${id}`);
    return s;
  }

  #address(handle: string | null): string | null {
    return handle === null ? null : `${this.connectorId}/${handle}`;
  }

  #sessionByHandle(handle: string): OracleSession | undefined {
    for (const session of this.#sessions.values()) {
      if (session.handle === handle) return session;
    }
    return undefined;
  }

  #removeAddressFromChannels(address: string): void {
    for (const [channel, members] of this.#channels) {
      members.delete(address);
      if (members.size === 0) this.#channels.delete(channel);
    }
  }

  #muteCandidates(from: string, rawText: string): string[] {
    const lowerFrom = from.toLowerCase();
    const connector = lowerFrom.split("/")[0];
    const candidates = [lowerFrom, `${connector}/*`];
    const chMatch = /^\[(#[^\]\s]+)\]\s/.exec(rawText);
    if (chMatch) candidates.push(chMatch[1].toLowerCase());
    return candidates;
  }

  #isMuted(sessionId: string, from: string, rawText: string): boolean {
    const sessionRules = this.#sessionMutes.get(sessionId);
    for (const candidate of this.#muteCandidates(from, rawText)) {
      if (this.#connectorMutes.has(candidate) || sessionRules?.has(candidate)) return true;
    }
    return false;
  }

  #messageSource(from: string, rawText: string): string {
    const chMatch = /^\[(#[^\]\s]+)\]\s/.exec(rawText);
    return chMatch ? `${chMatch[1]} (${from})` : from;
  }

  #deliverMessage(from: string, to: string, rawText: string): void {
    const [connector, handle] = to.split("/");
    if (connector !== this.connectorId || !handle) return;
    const recipient = this.#sessionByHandle(handle);
    if (!recipient) return;
    if (this.#isMuted(recipient.id, from, rawText)) return;
    const formatted = formatItem({ id: "oracle", kind: "message", from, to, text: rawText });
    recipient.mailbox.push({
      from,
      text: formatted,
      source: this.#messageSource(from, rawText),
      notified: false,
    });
  }

  handleOf(sessionId: string): string | null {
    return this.#session(sessionId).handle;
  }

  addressOf(sessionId: string): string | null {
    return this.#address(this.#session(sessionId).handle);
  }

  deliveryModeOf(sessionId: string): DeliveryMode {
    return this.#session(sessionId).deliveryMode;
  }

  pendingCount(sessionId: string): number {
    return this.#session(sessionId).mailbox.length;
  }

  unnotifiedCount(sessionId: string): number {
    return this.#session(sessionId).mailbox.filter((m) => !m.notified).length;
  }

  mailboxTextsSorted(sessionId: string): string[] {
    return this.#session(sessionId).mailbox.map((m) => m.text).sort();
  }

  distinctSources(sessionId: string): string[] {
    return [...new Set(this.#session(sessionId).mailbox.map((m) => m.source).filter((s) => s.length > 0))].sort();
  }

  peers(): Array<{ address: string; online: boolean }> {
    return [...this.#sessions.values()]
      .filter((s) => s.handle !== null)
      .map((s) => ({ address: `${this.connectorId}/${s.handle!}`, online: true }))
      .sort((a, b) => (a.address < b.address ? -1 : a.address > b.address ? 1 : 0));
  }

  channels(filterChannel?: string): Array<{ channel: string; members: string[] }> {
    const list: Array<{ channel: string; members: string[] }> = [];
    for (const [channel, members] of this.#channels) {
      if (filterChannel !== undefined && channel !== filterChannel) continue;
      if (members.size === 0) continue;
      list.push({ channel, members: [...members].sort() });
    }
    return list.sort((a, b) => (a.channel < b.channel ? -1 : a.channel > b.channel ? 1 : 0));
  }

  mutesFor(sessionId: string): OracleMute[] {
    const connectorRules: OracleMute[] = [...this.#connectorMutes]
      .sort()
      .map((pattern) => ({ scope: "connector", pattern }));
    const sessionRules: OracleMute[] = [...(this.#sessionMutes.get(sessionId) ?? [])]
      .sort()
      .map((pattern) => ({ scope: "session", pattern }));
    return [...connectorRules, ...sessionRules];
  }

  join(sessionId: string, handle: string): { ok: true; address: string } | { ok: false; code: string } {
    if (!handlePattern.test(handle)) return { ok: false, code: "invalid" };
    const owner = this.#sessionByHandle(handle);
    if (owner && owner.id !== sessionId) return { ok: false, code: "handle_taken" };
    const session = this.#session(sessionId);
    if (session.handle !== null && session.handle !== handle) {
      this.#removeAddressFromChannels(`${this.connectorId}/${session.handle}`);
    }
    session.handle = handle;
    return { ok: true, address: `${this.connectorId}/${handle}` };
  }

  leave(sessionId: string): { left: boolean } {
    const session = this.#session(sessionId);
    if (session.handle === null) return { left: false };
    this.#removeAddressFromChannels(`${this.connectorId}/${session.handle}`);
    session.handle = null;
    return { left: true };
  }

  send(sessionId: string, to: string, text: string): { ok: true } | { ok: false; code: string } {
    const session = this.#session(sessionId);
    if (session.handle === null) return { ok: false, code: "not_enrolled" };
    const parsed = parseAddress(to);
    if (!parsed || parsed.connectorId !== this.connectorId || !this.#sessionByHandle(parsed.handle)) {
      return { ok: false, code: "unknown_recipient" };
    }
    this.#deliverMessage(`${this.connectorId}/${session.handle}`, to, text);
    return { ok: true };
  }

  channelJoin(sessionId: string, rawChannel: string): { ok: true; channel: string; address: string; members: string[] } | { ok: false; code: string } {
    const channel = normalizeChannelName(rawChannel);
    if (!channel) return { ok: false, code: "invalid" };
    const session = this.#session(sessionId);
    if (session.handle === null) return { ok: false, code: "not_enrolled" };
    const address = `${this.connectorId}/${session.handle}`;
    const members = this.#channels.get(channel) ?? new Set<string>();
    members.add(address);
    this.#channels.set(channel, members);
    return { ok: true, channel, address, members: [...members].sort() };
  }

  channelLeave(sessionId: string, rawChannel: string): { ok: true; channel: string; address: string; left: boolean } | { ok: false; code: string } {
    const channel = normalizeChannelName(rawChannel);
    if (!channel) return { ok: false, code: "invalid" };
    const session = this.#session(sessionId);
    if (session.handle === null) return { ok: false, code: "not_enrolled" };
    const address = `${this.connectorId}/${session.handle}`;
    const members = this.#channels.get(channel);
    const left = members ? members.delete(address) : false;
    if (members && members.size === 0) this.#channels.delete(channel);
    return { ok: true, channel, address, left };
  }

  channelPost(sessionId: string, rawChannel: string, text: string): { ok: true; channel: string; deliveredTo: string[] } | { ok: false; code: string } {
    const channel = normalizeChannelName(rawChannel);
    if (!channel || text.length === 0) return { ok: false, code: "invalid" };
    const session = this.#session(sessionId);
    if (session.handle === null) return { ok: false, code: "not_enrolled" };
    const senderAddress = `${this.connectorId}/${session.handle}`;
    const members = this.#channels.get(channel);
    if (!members || !members.has(senderAddress)) return { ok: false, code: "not_member" };
    const recipients = [...members].filter((m) => m !== senderAddress).sort();
    const taggedText = `[${channel}] ${text}`;
    for (const recipient of recipients) {
      this.#deliverMessage(senderAddress, recipient, taggedText);
    }
    return { ok: true, channel, deliveredTo: recipients };
  }

  mute(sessionId: string, target: string, scope: "connector" | "session"): { muted: string; scope: "connector" | "session" } {
    const pattern = normalizeMutePattern(target);
    if (!pattern) throw new Error(`Invalid mute pattern in oracle: ${target}`);
    if (scope === "connector") this.#connectorMutes.add(pattern);
    else this.#sessionMutes.get(sessionId)!.add(pattern);
    return { muted: pattern, scope };
  }

  unmute(sessionId: string, target: string, scope: "connector" | "session"): { pattern: string; scope: "connector" | "session"; removed: boolean } {
    const pattern = normalizeMutePattern(target);
    if (!pattern) throw new Error(`Invalid unmute pattern in oracle: ${target}`);
    const removed = scope === "connector"
      ? this.#connectorMutes.delete(pattern)
      : this.#sessionMutes.get(sessionId)!.delete(pattern);
    return { pattern, scope, removed };
  }

  setMode(sessionId: string, mode: DeliveryMode): { deliveryMode: DeliveryMode; unread: number } {
    const session = this.#session(sessionId);
    session.deliveryMode = mode;
    return { deliveryMode: mode, unread: session.mailbox.length };
  }

  inboxPeek(sessionId: string, ackedTexts: readonly string[] = []): { deliveryMode: DeliveryMode; unread: number; itemTexts: string[] } {
    const session = this.#session(sessionId);
    if (ackedTexts.length > 0) {
      const toRemove = new Set(ackedTexts);
      session.mailbox = session.mailbox.filter((m) => !toRemove.has(m.text));
    }
    for (const item of session.mailbox) item.notified = true;
    return {
      deliveryMode: session.deliveryMode,
      unread: session.mailbox.length,
      itemTexts: session.mailbox.map((m) => m.text).sort(),
    };
  }

  inboxAcknowledgeAll(sessionId: string): { deliveryMode: DeliveryMode; unread: number; drainedTexts: string[] } {
    const session = this.#session(sessionId);
    const drainedTexts = session.mailbox.map((m) => m.text).sort();
    session.mailbox = [];
    return { deliveryMode: session.deliveryMode, unread: 0, drainedTexts };
  }

  drainForPush(sessionId: string):
    | { mode: "full"; drainedTexts: string[] }
    | { mode: "notify"; expectedDigest: null | { unread: number; sources: string[] } } {
    const session = this.#session(sessionId);
    if (session.deliveryMode === "full") {
      const drainedTexts = session.mailbox.map((m) => m.text).sort();
      session.mailbox = [];
      return { mode: "full", drainedTexts };
    }
    const unnotified = session.mailbox.filter((m) => !m.notified).length;
    if (unnotified === 0) return { mode: "notify", expectedDigest: null };
    const unread = session.mailbox.length;
    const sources = this.distinctSources(sessionId);
    for (const item of session.mailbox) item.notified = true;
    return { mode: "notify", expectedDigest: { unread, sources } };
  }
}

// ============================================================================
// Test 1: Stateful Differential Oracle vs. Real RouterCore + Connector + SQLite
// ============================================================================

test("differential: stateful ModelOracle matches real RouterCore + Connector + SQLite State across 120 operations", { timeout: 15_000 }, async () => {
  const seed = resolveSeed();
  const rng = new Rng(seed);
  const history: string[] = [];
  const dir = mkdtempSync(join(tmpdir(), "hyphae-diff-oracle-"));
  const routerDbPath = join(dir, "router.sqlite");

  const connectorId = "diff@oracle";
  const routerCore = new RouterCore({
    dbPath: routerDbPath,
    limits: { ...DEFAULT_LIMITS, maxPerHourPerRecipient: 10_000 },
  });
  const token = routerCore.addConnector(connectorId);
  const router = await serveRouter({ core: routerCore, host: "127.0.0.1", port: 0 });
  const daemon = await startDaemon({
    connectorId,
    directory: join(dir, "state"),
    routers: [{ name: "primary", url: router.url, token }],
  }, { quiet: true });

  const routerReadDb = new DatabaseSync(routerDbPath, { readOnly: true });
  routerReadDb.exec("PRAGMA busy_timeout = 2000;");

  try {
    const sessions: Array<{ id: string; backend: Backend }> = [
      { id: "antigravity:diff-ag", backend: { kind: "antigravity" } },
      { id: "claude:diff-cl", backend: { kind: "claude" } },
      { id: "codex:diff-cx", backend: { kind: "codex" } },
      { id: "openclaw:diff-oc", backend: { kind: "openclaw" } },
    ];
    for (const s of sessions) daemon.state.register(s.id, s.backend);

    // Wait for connector SSE stream to attach before starting the differential trace
    await daemon.connector.call(sessions[0].id, "hyp_join", { handle: "bootstrap-probe" });
    await waitForConnectorOnline(routerCore);
    await daemon.connector.call(sessions[0].id, "hyp_leave", {});

    const sessionIds = sessions.map((s) => s.id);
    const oracle = new ModelOracle(connectorId, sessionIds);

    const handlePool = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"];
    const channelPool = ["#incidents", "#deploys", "#triage"];
    const opCounts = new Map<string, number>();
    const bump = (op: string) => opCounts.set(op, (opCounts.get(op) ?? 0) + 1);

    const verifyFullEquivalence = async (stepIndex: number) => {
      const ctx = (detail: string) => formatFailureContext(seed, history, `Step ${stepIndex}: ${detail}`);

      // 1. Router peer directory equivalence
      const probeSid = sessionIds[stepIndex % sessionIds.length];
      const peersRes = await daemon.connector.call(probeSid, "hyp_peers", {}) as {
        self: string | null;
        peers: Array<{ address: string; online: boolean }>;
      };
      assert.equal(peersRes.self, oracle.addressOf(probeSid), ctx("hyp_peers.self mismatch"));
      assert.deepEqual(peersRes.peers, oracle.peers(), ctx("hyp_peers.peers mismatch"));

      // 2. Router channels equivalence
      const channelsRes = await daemon.connector.call(probeSid, "hyp_channels", {}) as {
        channels: Array<{ channel: string; members: string[] }>;
      };
      assert.deepEqual(channelsRes.channels, oracle.channels(), ctx("hyp_channels mismatch"));

      // 3. Per-session SQLite state, mutes, deliveryMode, unread counts, and exact mailbox contents
      for (const sid of sessionIds) {
        const status = daemon.connector.sessionStatus(sid);
        assert.ok(status, ctx(`missing sessionStatus for ${sid}`));
        assert.equal(status.handle, oracle.handleOf(sid), ctx(`handle mismatch for ${sid}`));
        assert.equal(status.deliveryMode, oracle.deliveryModeOf(sid), ctx(`deliveryMode mismatch for ${sid}`));
        assert.equal(status.pending, oracle.pendingCount(sid), ctx(`pendingCount mismatch for ${sid}`));
        assert.equal(status.unnotified, oracle.unnotifiedCount(sid), ctx(`unnotifiedCount mismatch for ${sid}`));

        const actualMutes = daemon.connector.listMutes(sid).map((m) => ({
          scope: m.scope === "*" ? ("connector" as const) : ("session" as const),
          pattern: m.pattern,
        }));
        assert.deepEqual(actualMutes, oracle.mutesFor(sid), ctx(`mutes mismatch for ${sid}`));

        // Read-only peekMailbox checks exact buffered payload set without altering notified flags
        const actualMailboxTexts = daemon.connector.peekMailbox(sid, 100).map((m) => m.text).sort();
        assert.deepEqual(actualMailboxTexts, oracle.mailboxTextsSorted(sid), ctx(`mailbox contents mismatch for ${sid}`));
      }
    };

    const TOTAL_STEPS = 120;
    // Guarantee every single operation class is exercised deterministically, then run randomized stateful sequences.
    const forcedPrefix = [
      "hyp_join", "hyp_join", "hyp_join", "hyp_join",
      "hyp_channel_join", "hyp_channel_join", "hyp_channel_post",
      "hyp_send", "hyp_mode", "hyp_send", "drainForPush",
      "hyp_mute", "hyp_send", "hyp_mutes", "hyp_unmute",
      "hyp_inbox", "hyp_peers", "hyp_channels", "hyp_channel_leave", "hyp_leave",
    ];

    for (let step = 1; step <= TOTAL_STEPS; step++) {
      let op: string;
      if (step <= forcedPrefix.length) {
        op = forcedPrefix[step - 1];
      } else {
        const roll = rng.next();
        if (roll < 0.12) op = "hyp_join";
        else if (roll < 0.19) op = "hyp_leave";
        else if (roll < 0.35) op = "hyp_send";
        else if (roll < 0.45) op = "hyp_channel_join";
        else if (roll < 0.56) op = "hyp_channel_post";
        else if (roll < 0.62) op = "hyp_channel_leave";
        else if (roll < 0.70) op = "hyp_mute";
        else if (roll < 0.78) op = "hyp_unmute";
        else if (roll < 0.85) op = "hyp_mode";
        else if (roll < 0.91) op = "hyp_inbox";
        else if (roll < 0.95) op = "drainForPush";
        else if (roll < 0.97) op = "hyp_peers";
        else if (roll < 0.985) op = "hyp_channels";
        else op = "hyp_mutes";
      }

      // Keep connector wildcard mute brief so messages flow throughout the trace
      const hasWildcardMute = oracle.mutesFor(sessionIds[0]).some((m) => m.scope === "connector" && m.pattern === `${connectorId}/*`);
      if (hasWildcardMute && step > forcedPrefix.length && rng.bool(0.35)) {
        op = "hyp_unmute";
      }

      // Select a session suited for the operation (with occasional invalid/unenrolled calls to test fail-closed parity)
      const enrolledSids = sessionIds.filter((id) => oracle.handleOf(id) !== null);
      const unenrolledSids = sessionIds.filter((id) => oracle.handleOf(id) === null);
      let sid = rng.pick(sessionIds);
      if (step <= 4) {
        sid = sessionIds[step - 1];
      } else if (
        (op === "hyp_send" || op === "hyp_channel_join" || op === "hyp_channel_post" || op === "hyp_channel_leave") &&
        enrolledSids.length > 0 &&
        rng.bool(0.85)
      ) {
        sid = rng.pick(enrolledSids);
      } else if (op === "hyp_join" && unenrolledSids.length > 0 && rng.bool(0.75)) {
        sid = rng.pick(unenrolledSids);
      } else if ((op === "hyp_inbox" || op === "drainForPush") && sessionIds.some((id) => oracle.pendingCount(id) > 0)) {
        const nonEmpty = sessionIds.filter((id) => oracle.pendingCount(id) > 0);
        if (rng.bool(0.85)) sid = rng.pick(nonEmpty);
      }

      bump(op);
      let needsQuiescence = false;

      switch (op) {
        case "hyp_join": {
          const handle = step <= 4 ? handlePool[step - 1] : rng.pick(handlePool);
          history.push(`#${step} ${sid} hyp_join(${handle})`);
          const expected = oracle.join(sid, handle);
          if (expected.ok) {
            const actual = await daemon.connector.call(sid, "hyp_join", { handle }) as { address: string };
            assert.equal(actual.address, expected.address, formatFailureContext(seed, history, "hyp_join address mismatch"));
          } else {
            await assert.rejects(
              () => daemon.connector.call(sid, "hyp_join", { handle }),
              (err: unknown) => err instanceof RouterError && err.code === expected.code,
              formatFailureContext(seed, history, `hyp_join expected RouterError(${expected.code})`),
            );
          }
          break;
        }

        case "hyp_leave": {
          history.push(`#${step} ${sid} hyp_leave()`);
          const expected = oracle.leave(sid);
          const actual = await daemon.connector.call(sid, "hyp_leave", {}) as { left: boolean };
          assert.equal(actual.left, expected.left, formatFailureContext(seed, history, "hyp_leave mismatch"));
          break;
        }

        case "hyp_send": {
          const targetHandle = enrolledSids.length > 0 && rng.bool(0.85)
            ? oracle.handleOf(rng.pick(enrolledSids))!
            : rng.pick(handlePool);
          const to = `${connectorId}/${targetHandle}`;
          const text = `dm-step-${step}-v${rng.int(1000)}`;
          history.push(`#${step} ${sid} hyp_send(${to}, "${text}")`);
          const expected = oracle.send(sid, to, text);
          if (expected.ok) {
            const actual = await daemon.connector.call(sid, "hyp_send", { to, text }) as { status: string; messageId: string };
            assert.equal(actual.status, "stored", formatFailureContext(seed, history, "hyp_send status mismatch"));
            assert.equal(typeof actual.messageId, "string");
            needsQuiescence = true;
          } else {
            await assert.rejects(
              () => daemon.connector.call(sid, "hyp_send", { to, text }),
              (err: unknown) => err instanceof RouterError && err.code === expected.code,
              formatFailureContext(seed, history, `hyp_send expected RouterError(${expected.code})`),
            );
          }
          break;
        }

        case "hyp_channel_join": {
          const rawChannel = step <= forcedPrefix.length
            ? channelPool[0]
            : (rng.bool(0.5) ? rng.pick(channelPool) : rng.pick(channelPool).slice(1));
          history.push(`#${step} ${sid} hyp_channel_join(${rawChannel})`);
          const expected = oracle.channelJoin(sid, rawChannel);
          if (expected.ok) {
            const actual = await daemon.connector.call(sid, "hyp_channel_join", { channel: rawChannel }) as {
              channel: string;
              address: string;
              members: string[];
            };
            assert.deepEqual(
              { channel: actual.channel, address: actual.address, members: actual.members },
              { channel: expected.channel, address: expected.address, members: expected.members },
              formatFailureContext(seed, history, "hyp_channel_join mismatch"),
            );
          } else {
            await assert.rejects(
              () => daemon.connector.call(sid, "hyp_channel_join", { channel: rawChannel }),
              (err: unknown) => err instanceof RouterError && err.code === expected.code,
              formatFailureContext(seed, history, `hyp_channel_join expected RouterError(${expected.code})`),
            );
          }
          break;
        }

        case "hyp_channel_leave": {
          const channel = rng.pick(channelPool);
          history.push(`#${step} ${sid} hyp_channel_leave(${channel})`);
          const expected = oracle.channelLeave(sid, channel);
          if (expected.ok) {
            const actual = await daemon.connector.call(sid, "hyp_channel_leave", { channel }) as {
              channel: string;
              address: string;
              left: boolean;
            };
            assert.deepEqual(
              { channel: actual.channel, address: actual.address, left: actual.left },
              { channel: expected.channel, address: expected.address, left: expected.left },
              formatFailureContext(seed, history, "hyp_channel_leave mismatch"),
            );
          } else {
            await assert.rejects(
              () => daemon.connector.call(sid, "hyp_channel_leave", { channel }),
              (err: unknown) => err instanceof RouterError && err.code === expected.code,
              formatFailureContext(seed, history, `hyp_channel_leave expected RouterError(${expected.code})`),
            );
          }
          break;
        }

        case "hyp_channel_post": {
          const activeChannels = oracle.channels();
          const addr = oracle.addressOf(sid);
          const myChannels = addr ? activeChannels.filter((c) => c.members.includes(addr)).map((c) => c.channel) : [];
          const channel = myChannels.length > 0 && rng.bool(0.8) ? rng.pick(myChannels) : rng.pick(channelPool);
          const text = `ch-step-${step}-v${rng.int(1000)}`;
          history.push(`#${step} ${sid} hyp_channel_post(${channel}, "${text}")`);
          const expected = oracle.channelPost(sid, channel, text);
          if (expected.ok) {
            const actual = await daemon.connector.call(sid, "hyp_channel_post", { channel, text }) as {
              channel: string;
              deliveredTo: string[];
              failed: unknown[];
            };
            assert.equal(actual.channel, expected.channel, formatFailureContext(seed, history, "hyp_channel_post channel mismatch"));
            assert.deepEqual(actual.deliveredTo, expected.deliveredTo, formatFailureContext(seed, history, "hyp_channel_post deliveredTo mismatch"));
            assert.deepEqual(actual.failed, [], formatFailureContext(seed, history, "hyp_channel_post unexpected failures"));
            if (expected.deliveredTo.length > 0) needsQuiescence = true;
          } else {
            await assert.rejects(
              () => daemon.connector.call(sid, "hyp_channel_post", { channel, text }),
              (err: unknown) => err instanceof RouterError && err.code === expected.code,
              formatFailureContext(seed, history, `hyp_channel_post expected RouterError(${expected.code})`),
            );
          }
          break;
        }

        case "hyp_mute": {
          const scope: "connector" | "session" = rng.bool(0.55) ? "session" : "connector";
          const targetKind = rng.next();
          let target: string;
          if (targetKind < 0.55) target = `${connectorId}/${rng.pick(handlePool)}`;
          else if (targetKind < 0.90) target = rng.pick(channelPool);
          else target = `${connectorId}/*`;
          history.push(`#${step} ${sid} hyp_mute(${target}, scope=${scope})`);
          const expected = oracle.mute(sid, target, scope);
          const actual = await daemon.connector.call(sid, "hyp_mute", scope === "session" ? { target, scope: "session" } : { target }) as {
            muted: string;
            scope: string;
          };
          assert.deepEqual(actual, expected, formatFailureContext(seed, history, "hyp_mute mismatch"));
          break;
        }

        case "hyp_unmute": {
          const existing = oracle.mutesFor(sid);
          let target: string;
          let scope: "connector" | "session";
          if (hasWildcardMute && rng.bool(0.6)) {
            target = `${connectorId}/*`;
            scope = "connector";
          } else if (existing.length > 0 && rng.bool(0.75)) {
            const chosen = rng.pick(existing);
            target = chosen.pattern;
            scope = chosen.scope;
          } else {
            target = rng.bool(0.5) ? `${connectorId}/${rng.pick(handlePool)}` : rng.pick(channelPool);
            scope = rng.bool(0.5) ? "session" : "connector";
          }
          history.push(`#${step} ${sid} hyp_unmute(${target}, scope=${scope})`);
          const expected = oracle.unmute(sid, target, scope);
          const actual = await daemon.connector.call(sid, "hyp_unmute", scope === "session" ? { target, scope: "session" } : { target }) as {
            pattern: string;
            scope: string;
            removed: boolean;
          };
          assert.deepEqual(actual, expected, formatFailureContext(seed, history, "hyp_unmute mismatch"));
          break;
        }

        case "hyp_mutes": {
          history.push(`#${step} ${sid} hyp_mutes()`);
          const actual = await daemon.connector.call(sid, "hyp_mutes", {}) as {
            mutes: Array<{ pattern: string; scope: "connector" | "session" }>;
          };
          const normalized = actual.mutes.map((m) => ({ scope: m.scope, pattern: m.pattern }));
          assert.deepEqual(normalized, oracle.mutesFor(sid), formatFailureContext(seed, history, "hyp_mutes mismatch"));
          break;
        }

        case "hyp_mode": {
          const nextMode: DeliveryMode = step <= forcedPrefix.length
            ? "notify"
            : (oracle.deliveryModeOf(sid) === "full" ? "notify" : "full");
          history.push(`#${step} ${sid} hyp_mode(${nextMode})`);
          const expected = oracle.setMode(sid, nextMode);
          const actual = await daemon.connector.call(sid, "hyp_mode", { mode: nextMode }) as {
            deliveryMode: DeliveryMode;
            unread: number;
          };
          assert.deepEqual(actual, expected, formatFailureContext(seed, history, "hyp_mode mismatch"));
          break;
        }

        case "hyp_inbox": {
          const modeRoll = rng.next();
          if (modeRoll < 0.45) {
            history.push(`#${step} ${sid} hyp_inbox(acknowledgeAll=true)`);
            const expected = oracle.inboxAcknowledgeAll(sid);
            const actual = await daemon.connector.call(sid, "hyp_inbox", { acknowledgeAll: true, limit: 50 }) as {
              deliveryMode: DeliveryMode;
              unread: number;
              items: Array<{ text: string; receipt: string }>;
            };
            assert.equal(actual.deliveryMode, expected.deliveryMode, formatFailureContext(seed, history, "hyp_inbox(all) deliveryMode"));
            assert.equal(actual.unread, expected.unread, formatFailureContext(seed, history, "hyp_inbox(all) unread"));
            assert.deepEqual(actual.items.map((i) => i.text).sort(), expected.drainedTexts, formatFailureContext(seed, history, "hyp_inbox(all) items"));
          } else if (modeRoll < 0.75 && oracle.pendingCount(sid) > 0) {
            const peeked = daemon.connector.peekMailbox(sid, 50);
            const chosen = peeked[0];
            history.push(`#${step} ${sid} hyp_inbox(acknowledge=[1])`);
            const expected = oracle.inboxPeek(sid, [chosen.text]);
            const actual = await daemon.connector.call(sid, "hyp_inbox", { acknowledge: [chosen.receipt], limit: 50 }) as {
              deliveryMode: DeliveryMode;
              unread: number;
              items: Array<{ text: string; receipt: string }>;
            };
            assert.equal(actual.deliveryMode, expected.deliveryMode, formatFailureContext(seed, history, "hyp_inbox(ack1) deliveryMode"));
            assert.equal(actual.unread, expected.unread, formatFailureContext(seed, history, "hyp_inbox(ack1) unread"));
            assert.deepEqual(actual.items.map((i) => i.text).sort(), expected.itemTexts, formatFailureContext(seed, history, "hyp_inbox(ack1) items"));
          } else {
            history.push(`#${step} ${sid} hyp_inbox(peek)`);
            const expected = oracle.inboxPeek(sid);
            const actual = await daemon.connector.call(sid, "hyp_inbox", { limit: 50 }) as {
              deliveryMode: DeliveryMode;
              unread: number;
              items: Array<{ text: string; receipt: string }>;
            };
            assert.equal(actual.deliveryMode, expected.deliveryMode, formatFailureContext(seed, history, "hyp_inbox(peek) deliveryMode"));
            assert.equal(actual.unread, expected.unread, formatFailureContext(seed, history, "hyp_inbox(peek) unread"));
            assert.deepEqual(actual.items.map((i) => i.text).sort(), expected.itemTexts, formatFailureContext(seed, history, "hyp_inbox(peek) items"));
          }
          break;
        }

        case "drainForPush": {
          history.push(`#${step} ${sid} drainForPush()`);
          const expected = oracle.drainForPush(sid);
          const actual = daemon.connector.drainForPush(sid, 50);
          if (expected.mode === "full") {
            assert.deepEqual(
              actual.map((i) => i.text).sort(),
              expected.drainedTexts,
              formatFailureContext(seed, history, "drainForPush(full) items mismatch"),
            );
          } else if (expected.expectedDigest === null) {
            assert.deepEqual(actual, [], formatFailureContext(seed, history, "drainForPush(notify) expected empty when already notified"));
          } else {
            assert.equal(actual.length, 1, formatFailureContext(seed, history, "drainForPush(notify) expected single digest banner"));
            const banner = actual[0].text;
            const n = expected.expectedDigest.unread;
            const expectedPrefix = `hyphae notice · ${n} unread (${n} ${n === 1 ? "message" : "messages"})`;
            assert.ok(
              banner.startsWith(expectedPrefix),
              formatFailureContext(seed, history, `drainForPush(notify) banner '${banner}' did not start with '${expectedPrefix}'`),
            );
            assert.ok(
              banner.endsWith("· call hyp_inbox to read"),
              formatFailureContext(seed, history, `drainForPush(notify) banner '${banner}' missing hyp_inbox hint`),
            );
            // Slim notify banner must NEVER leak raw message bodies
            assert.doesNotMatch(
              banner,
              /(?:dm-step-|ch-step-)/,
              formatFailureContext(seed, history, `drainForPush(notify) leaked payload body in '${banner}'`),
            );
            // Subsequent drainForPush without new arrivals must stay quiet
            assert.deepEqual(
              daemon.connector.drainForPush(sid, 50),
              [],
              formatFailureContext(seed, history, "second drainForPush(notify) must return []"),
            );
          }
          break;
        }

        case "hyp_peers": {
          history.push(`#${step} ${sid} hyp_peers()`);
          const actual = await daemon.connector.call(sid, "hyp_peers", {}) as {
            self: string | null;
            peers: Array<{ address: string; online: boolean }>;
          };
          assert.equal(actual.self, oracle.addressOf(sid), formatFailureContext(seed, history, "hyp_peers self"));
          assert.deepEqual(actual.peers, oracle.peers(), formatFailureContext(seed, history, "hyp_peers list"));
          break;
        }

        case "hyp_channels": {
          const filter = rng.bool(0.5) ? rng.pick(channelPool) : undefined;
          history.push(`#${step} ${sid} hyp_channels(${filter ?? "all"})`);
          const actual = await daemon.connector.call(sid, "hyp_channels", filter ? { channel: filter } : {}) as {
            channels: Array<{ channel: string; members: string[] }>;
          };
          assert.deepEqual(actual.channels, oracle.channels(filter), formatFailureContext(seed, history, "hyp_channels mismatch"));
          break;
        }
      }

      if (needsQuiescence) {
        await waitForRouterQuiescence(routerReadDb, daemon);
      }

      await verifyFullEquivalence(step);
    }

    // Verify all 14 operation classes were actually covered during the run
    for (const requiredOp of [
      "hyp_join", "hyp_leave", "hyp_send",
      "hyp_channel_join", "hyp_channel_post", "hyp_channel_leave",
      "hyp_mute", "hyp_unmute", "hyp_mutes", "hyp_mode",
      "hyp_inbox", "hyp_peers", "hyp_channels", "drainForPush",
    ]) {
      assert.ok((opCounts.get(requiredOp) ?? 0) > 0, `Expected operation ${requiredOp} to be executed at least once`);
    }
  } finally {
    routerReadDb.close();
    await daemon.stop();
    await router.close();
    routerCore.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// ============================================================================
// Test 2: Cross-Harness Parity Differential Matrix (7 durable-mailbox harnesses)
// ============================================================================

const DURABLE_HARNESSES: readonly Exclude<HarnessKind, "herdr">[] = [
  "antigravity",
  "claude",
  "codex",
  "cursor",
  "opencode",
  "gemini",
  "openclaw",
];

interface HarnessTrace {
  readonly capabilities: {
    readonly modes: readonly string[];
    readonly deliveryMode: DeliveryMode;
    readonly unread: number;
    readonly mutes: number;
    readonly inbound: string;
  };
  readonly direct: {
    readonly pendingBeforeDrain: number;
    readonly drainedTexts: string[];
    readonly pendingAfterDrain: number;
  };
  readonly channel: {
    readonly joinedMembers: string[];
    readonly fanoutTexts: string[];
    readonly selfEchoCount: number;
    readonly peerReceivedFromSelf: string[];
    readonly leaveResult: boolean;
  };
  readonly mute: {
    readonly muteRes: { muted: string; scope: string };
    readonly listedMutes: Array<{ pattern: string; scope: string; mutedBy: string }>;
    readonly pendingWhileMuted: number;
    readonly drainWhileMuted: string[];
    readonly unmuteRes: { pattern: string; scope: string; removed: boolean };
    readonly pendingAfterUnmute: number;
    readonly drainAfterUnmute: string[];
  };
  readonly notify: {
    readonly modeOn: { deliveryMode: DeliveryMode; unread: number };
    readonly pendingBeforeDigest: number;
    readonly unnotifiedBeforeDigest: number;
    readonly digestTexts: string[];
    readonly secondDigestTexts: string[];
    readonly pendingAfterDigest: number;
    readonly unnotifiedAfterDigest: number;
    readonly inboxAckAll: {
      readonly deliveryMode: DeliveryMode;
      readonly unread: number;
      readonly texts: string[];
    };
    readonly pendingFinal: number;
  };
}

test("differential: cross-harness parity matrix produces identical normalized outcomes across all 7 durable-mailbox harnesses", { timeout: 15_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "hyphae-diff-parity-"));
  const routerDbPath = join(dir, "router.sqlite");
  const connectorId = "parity@matrix";

  const routerCore = new RouterCore({
    dbPath: routerDbPath,
    limits: { ...DEFAULT_LIMITS, maxPerHourPerRecipient: 10_000 },
  });
  const token = routerCore.addConnector(connectorId);
  const router = await serveRouter({ core: routerCore, host: "127.0.0.1", port: 0 });
  const daemon = await startDaemon({
    connectorId,
    directory: join(dir, "state"),
    routers: [{ name: "primary", url: router.url, token }],
  }, { quiet: true });

  const routerReadDb = new DatabaseSync(routerDbPath, { readOnly: true });
  routerReadDb.exec("PRAGMA busy_timeout = 2000;");

  try {
    // Register shared peer sessions used to send messages and participate in #channels
    const senderSid = "claude:matrix-sender";
    const senderHandle = "peer-sender";
    const senderAddr = `${connectorId}/${senderHandle}`;
    const chPeerSid = "antigravity:matrix-chpeer";
    const chPeerHandle = "ch-peer";
    const chPeerAddr = `${connectorId}/${chPeerHandle}`;

    daemon.state.register(senderSid, { kind: "claude" });
    daemon.state.register(chPeerSid, { kind: "antigravity" });
    await daemon.connector.call(senderSid, "hyp_join", { handle: senderHandle });
    await daemon.connector.call(chPeerSid, "hyp_join", { handle: chPeerHandle });
    await waitForConnectorOnline(routerCore);
    await daemon.connector.call(chPeerSid, "hyp_channel_join", { channel: "#parity-room" });

    // Register ALL 7 durable-mailbox harnesses simultaneously on the same daemon + router
    const subjects = DURABLE_HARNESSES.map((kind) => ({
      kind,
      sessionId: `${kind}:parity-session`,
      handle: `agent-${kind}`,
      address: `${connectorId}/agent-${kind}`,
    }));

    for (const subject of subjects) {
      daemon.state.register(subject.sessionId, { kind: subject.kind });
      await daemon.connector.call(subject.sessionId, "hyp_join", { handle: subject.handle });
    }

    const traces = new Map<string, HarnessTrace>();

    for (const subject of subjects) {
      const { sessionId, address } = subject;
      const normalizeAddr = (text: string) => text.replaceAll(address, "<SELF>");

      // 1. Capabilities
      const caps = await daemon.connector.call(sessionId, "hyp_capabilities", {}) as {
        modes: string[];
        deliveryMode: DeliveryMode;
        unread: number;
        mutes: number;
        inbound: string;
      };

      // 2. Direct message delivery (hyp_send)
      await daemon.connector.call(senderSid, "hyp_send", { to: address, text: "parity-direct-hello" });
      await waitForRouterQuiescence(routerReadDb, daemon);
      const pendingBeforeDrain = daemon.state.pendingCount(sessionId);
      const directDrained = daemon.connector.drainForPush(sessionId, 10).map((item) => normalizeAddr(item.text));
      const pendingAfterDrain = daemon.state.pendingCount(sessionId);

      // 3. #channel fan-out (hyp_channel_join + hyp_channel_post + hyp_channel_leave)
      const chJoin = await daemon.connector.call(sessionId, "hyp_channel_join", { channel: "#parity-room" }) as {
        members: string[];
      };
      const joinedMembers = chJoin.members.map(normalizeAddr).sort();

      await daemon.connector.call(chPeerSid, "hyp_channel_post", {
        channel: "#parity-room",
        text: "parity-channel-broadcast",
      });
      await waitForRouterQuiescence(routerReadDb, daemon);
      const fanoutTexts = daemon.connector.drainForPush(sessionId, 10).map((item) => normalizeAddr(item.text));

      await daemon.connector.call(sessionId, "hyp_channel_post", {
        channel: "#parity-room",
        text: "parity-channel-reply",
      });
      await waitForRouterQuiescence(routerReadDb, daemon);
      const selfEchoCount = daemon.state.pendingCount(sessionId);
      const peerReceivedFromSelf = daemon.connector.drainForPush(chPeerSid, 10).map((item) => normalizeAddr(item.text));

      const chLeave = await daemon.connector.call(sessionId, "hyp_channel_leave", { channel: "#parity-room" }) as {
        left: boolean;
      };

      // 4. Session mute + unmute (hyp_mute / hyp_unmute)
      const muteRes = await daemon.connector.call(sessionId, "hyp_mute", {
        target: senderAddr,
        scope: "session",
      }) as { muted: string; scope: string };

      const mutesList = await daemon.connector.call(sessionId, "hyp_mutes", {}) as {
        mutes: Array<{ pattern: string; scope: string; mutedBy: string }>;
      };
      const listedMutes = mutesList.mutes.map((m) => ({
        pattern: m.pattern,
        scope: m.scope,
        mutedBy: normalizeAddr(m.mutedBy),
      }));

      await daemon.connector.call(senderSid, "hyp_send", { to: address, text: "parity-muted-drop" });
      await waitForRouterQuiescence(routerReadDb, daemon);
      const pendingWhileMuted = daemon.state.pendingCount(sessionId);
      const drainWhileMuted = daemon.connector.drainForPush(sessionId, 10).map((item) => normalizeAddr(item.text));

      const unmuteRes = await daemon.connector.call(sessionId, "hyp_unmute", {
        target: senderAddr,
        scope: "session",
      }) as { pattern: string; scope: string; removed: boolean };

      await daemon.connector.call(senderSid, "hyp_send", { to: address, text: "parity-unmuted-ok" });
      await waitForRouterQuiescence(routerReadDb, daemon);
      const pendingAfterUnmute = daemon.state.pendingCount(sessionId);
      const drainAfterUnmute = daemon.connector.drainForPush(sessionId, 10).map((item) => normalizeAddr(item.text));

      // 5. notify-mode slim digest -> hyp_inbox(acknowledgeAll: true)
      const modeOn = await daemon.connector.call(sessionId, "hyp_mode", { mode: "notify" }) as {
        deliveryMode: DeliveryMode;
        unread: number;
      };
      await daemon.connector.call(senderSid, "hyp_send", { to: address, text: "parity-notify-body-1" });
      await daemon.connector.call(senderSid, "hyp_send", { to: address, text: "parity-notify-body-2" });
      await waitForRouterQuiescence(routerReadDb, daemon);

      const pendingBeforeDigest = daemon.state.pendingCount(sessionId);
      const unnotifiedBeforeDigest = daemon.state.unnotifiedCount(sessionId);
      const digestTexts = daemon.connector.drainForPush(sessionId, 10).map((item) => normalizeAddr(item.text));
      const secondDigestTexts = daemon.connector.drainForPush(sessionId, 10).map((item) => normalizeAddr(item.text));
      const pendingAfterDigest = daemon.state.pendingCount(sessionId);
      const unnotifiedAfterDigest = daemon.state.unnotifiedCount(sessionId);

      const inboxRes = await daemon.connector.call(sessionId, "hyp_inbox", { acknowledgeAll: true }) as {
        deliveryMode: DeliveryMode;
        unread: number;
        items: Array<{ text: string }>;
      };
      const pendingFinal = daemon.state.pendingCount(sessionId);

      await daemon.connector.call(sessionId, "hyp_mode", { mode: "full" });

      traces.set(subject.kind, {
        capabilities: {
          modes: caps.modes,
          deliveryMode: caps.deliveryMode,
          unread: caps.unread,
          mutes: caps.mutes,
          inbound: caps.inbound,
        },
        direct: { pendingBeforeDrain, drainedTexts: directDrained, pendingAfterDrain },
        channel: {
          joinedMembers,
          fanoutTexts,
          selfEchoCount,
          peerReceivedFromSelf,
          leaveResult: chLeave.left,
        },
        mute: {
          muteRes,
          listedMutes,
          pendingWhileMuted,
          drainWhileMuted,
          unmuteRes,
          pendingAfterUnmute,
          drainAfterUnmute,
        },
        notify: {
          modeOn,
          pendingBeforeDigest,
          unnotifiedBeforeDigest,
          digestTexts,
          secondDigestTexts,
          pendingAfterDigest,
          unnotifiedAfterDigest,
          inboxAckAll: {
            deliveryMode: inboxRes.deliveryMode,
            unread: inboxRes.unread,
            texts: inboxRes.items.map((i) => normalizeAddr(i.text)).sort(),
          },
          pendingFinal,
        },
      });
    }

    // Verify baseline trace itself meets expected semantics (guards against uniform breakage)
    const baseline = traces.get("antigravity")!;
    assert.equal(baseline.direct.pendingBeforeDrain, 1);
    assert.match(baseline.direct.drainedTexts[0], /parity-direct-hello/);
    assert.equal(baseline.channel.selfEchoCount, 0);
    assert.match(baseline.channel.fanoutTexts[0], /\[#parity-room\] parity-channel-broadcast/);
    assert.equal(baseline.mute.pendingWhileMuted, 0);
    assert.equal(baseline.mute.pendingAfterUnmute, 1);
    assert.equal(baseline.notify.digestTexts.length, 1);
    assert.match(baseline.notify.digestTexts[0], /2 unread \(2 messages\) · from parity@matrix\/peer-sender/);
    assert.doesNotMatch(baseline.notify.digestTexts[0], /parity-notify-body/);
    assert.deepEqual(baseline.notify.secondDigestTexts, []);
    assert.equal(baseline.notify.inboxAckAll.texts.length, 2);
    assert.equal(baseline.notify.pendingFinal, 0);

    // Differential assertion: ALL 7 harnesses must produce bit-for-bit identical normalized traces!
    for (const kind of DURABLE_HARNESSES) {
      assert.deepEqual(
        traces.get(kind),
        baseline,
        `Cross-harness parity divergence detected: harness '${kind}' diverged from baseline 'antigravity'`,
      );
    }
  } finally {
    routerReadDb.close();
    await daemon.stop();
    await router.close();
    routerCore.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

// ============================================================================
// Test 3: Nearby-Altered Perturbation Suite & Independent Filter Reference Oracle
// ============================================================================

/**
 * Independent reference implementation of CloudEvents Subscriptions API filter evaluation,
 * written purely from specification without sharing code with `src/core/router/filter.ts`.
 */
function referenceExtractComparableStrings(raw: unknown): string[] {
  if (typeof raw === "string") return [raw];
  if (typeof raw === "boolean") return [raw ? "true" : "false"];
  if (typeof raw === "number") return [Object.is(raw, -0) ? "0" : String(raw)];
  if (Array.isArray(raw)) {
    const out: string[] = [];
    for (const element of raw) {
      if (typeof element === "string") out.push(element);
      else if (typeof element === "boolean") out.push(element ? "true" : "false");
      else if (typeof element === "number") out.push(Object.is(element, -0) ? "0" : String(element));
    }
    return out;
  }
  return [];
}

function referenceLookupAttribute(event: CloudEvent, key: string): string[] {
  if (key.startsWith("data.")) {
    const field = key.slice(5);
    if (!Object.prototype.hasOwnProperty.call(event.data, field)) return [];
    return referenceExtractComparableStrings(event.data[field]);
  }
  if (key === "data") return [];
  if (!Object.prototype.hasOwnProperty.call(event, key)) return [];
  return referenceExtractComparableStrings(event[key]);
}

function referenceEvalFilter(filter: Filter, event: CloudEvent): boolean {
  if ("exact" in filter) {
    for (const [key, expected] of Object.entries(filter.exact)) {
      const values = referenceLookupAttribute(event, key);
      if (!values.some((v) => v === expected)) return false;
    }
    return true;
  }
  if ("prefix" in filter) {
    for (const [key, expected] of Object.entries(filter.prefix)) {
      const values = referenceLookupAttribute(event, key);
      if (!values.some((v) => v.startsWith(expected))) return false;
    }
    return true;
  }
  if ("suffix" in filter) {
    for (const [key, expected] of Object.entries(filter.suffix)) {
      const values = referenceLookupAttribute(event, key);
      if (!values.some((v) => v.endsWith(expected))) return false;
    }
    return true;
  }
  if ("all" in filter) {
    for (const child of filter.all) {
      if (!referenceEvalFilter(child, event)) return false;
    }
    return true;
  }
  if ("any" in filter) {
    for (const child of filter.any) {
      if (referenceEvalFilter(child, event)) return true;
    }
    return false;
  }
  return !referenceEvalFilter(filter.not, event);
}

function referenceMatchesFilters(filters: readonly Filter[], event: CloudEvent): boolean {
  for (const filter of filters) {
    if (!referenceEvalFilter(filter, event)) return false;
  }
  return true;
}

test("differential: nearby-altered perturbations fail closed across protocol, CloudEvents, filters, and decodeItem", () => {
  // --- 1. Handles (boundary = 64 chars) ---
  const validHandles = ["a", "0", "alice-1.dev_2", "a".repeat(64)];
  for (const h of validHandles) {
    assert.equal(handlePattern.test(h), true, `Expected valid handle: ${h}`);
    assert.equal(isHandle(h), true, `Expected isHandle parity for: ${h}`);
  }
  const mutatedHandles = [
    "",
    "a".repeat(65),         // length +1 over boundary
    "-lead-dash",
    ".lead-dot",
    "_lead-under",
    "Alice",                // uppercase
    "alice ",               // trailing space
    " alice",               // leading space
    "alice\0bob",           // NUL byte
    "alice\nbob",           // control byte
    "alice/bob",            // slash
    "alice@host",           // @ not allowed in handle
    "alicé",                // non-ASCII
  ];
  for (const h of mutatedHandles) {
    assert.equal(handlePattern.test(h), false, `Expected mutated handle rejected: ${JSON.stringify(h)}`);
    assert.equal(isHandle(h), false, `Expected isHandle parity rejection: ${JSON.stringify(h)}`);
  }

  // --- 2. Addresses (`connector/handle`, each <= 64 chars) ---
  const validAddresses = [
    "a/b",
    "alice@laptop.local/codex-1",
    `${"c".repeat(64)}/${"h".repeat(64)}`,
  ];
  for (const addr of validAddresses) {
    assert.equal(addressPattern.test(addr), true, `Expected valid address: ${addr}`);
    assert.notEqual(parseAddress(addr), null, `Expected parseAddress parity: ${addr}`);
  }
  const mutatedAddresses = [
    "",
    "no-slash",
    "a/b/c",
    `${"c".repeat(65)}/ok`,
    `ok/${"h".repeat(65)}`,
    "Alice@host/codex",
    "alice@host/Codex",
    "alice@host/codex\0",
    "alice@host/codex\n",
    "@host/codex",
    "alice@host/-bad",
  ];
  for (const addr of mutatedAddresses) {
    assert.equal(addressPattern.test(addr), false, `Expected mutated address rejected: ${JSON.stringify(addr)}`);
    assert.equal(parseAddress(addr), null, `Expected parseAddress parity rejection: ${JSON.stringify(addr)}`);
  }

  // --- 3. Channel names (boundary = '#' + 63 chars = 64 total) ---
  assert.equal(normalizeChannelName("incidents"), "#incidents");
  assert.equal(normalizeChannelName("  #Deploys.Prod_1  "), "#deploys.prod_1");
  assert.equal(normalizeChannelName("#" + "a".repeat(63)), "#" + "a".repeat(63));
  assert.equal(channelPattern.test("#" + "a".repeat(63)), true);

  const mutatedChannels = [
    "",
    "   ",
    "#",
    "##double",
    "#" + "a".repeat(64),   // length +1 over boundary
    "#-leading-dash",
    "#.leading-dot",
    "#has space",
    "#nul\0byte",
    "#ctrl\r\nmid",
    "#bell\x07char",
    "#bad/slash",
    "#bad@at",
  ];
  for (const ch of mutatedChannels) {
    assert.equal(normalizeChannelName(ch), null, `Expected mutated channel rejected: ${JSON.stringify(ch)}`);
    assert.equal(channelPattern.test(ch), false, `Expected channelPattern rejected: ${JSON.stringify(ch)}`);
  }
  assert.equal(channelPattern.test("#ctrl\r\n"), false);

  // --- 4. Mute patterns ---
  const validMutes: Array<[string, string]> = [
    ["alice@laptop/codex", "alice@laptop/codex"],
    ["  ALICE@LAPTOP/* ", "alice@laptop/*"],
    ["#Deploys", "#deploys"],
    ["topic:GitHub.Events", "topic:github.events"],
    ["plugin:slack-ops", "plugin:slack-ops"],
  ];
  for (const [input, expected] of validMutes) {
    assert.equal(normalizeMutePattern(input), expected, `Expected valid mute pattern: ${input}`);
  }
  const mutatedMutes = [
    "",
    "   ",
    "*",
    "/*",
    "alice@laptop/**",
    "alice@laptop/",
    `${"a".repeat(65)}/*`,
    "#" + "a".repeat(64),
    "topic:",
    "topic:" + "a".repeat(65),
    "topic:bad space",
    "topic:bad\0nul",
    "plugin:",
    "plugin:" + "a".repeat(65),
    "plugin:-bad",
    "unknown:foo",
    "a".repeat(141),
  ];
  for (const m of mutatedMutes) {
    assert.equal(normalizeMutePattern(m), null, `Expected mutated mute rejected: ${JSON.stringify(m)}`);
  }

  // --- 5. MCP tool name normalization ---
  for (const tool of MESH_TOOLS) {
    assert.equal(normalizeMeshToolName(tool), tool);
    assert.equal(normalizeMeshToolName(`mcp__hyphae__${tool}`), tool);
    assert.equal(normalizeMeshToolName(`mcp_hyphae_${tool}`), tool);
    assert.equal(normalizeMeshToolName(`hyphae.${tool}`), tool);
    assert.equal(normalizeMeshToolName(`hyphae/${tool}`), tool);
    assert.equal(normalizeMeshToolName(`hyphae:${tool}`), tool);
  }
  const mutatedToolNames = [
    "",
    "hyp_",
    "hyp_nonexistent",
    "HYP_JOIN",
    "hyp_join ",
    "hyp_join\0",
    "hyp_join_extra",
    "evilhyp_join",
    "__proto__",
    "constructor",
    "toString",
  ];
  for (const name of mutatedToolNames) {
    assert.equal(normalizeMeshToolName(name), null, `Expected mutated tool name rejected: ${JSON.stringify(name)}`);
  }

  // --- 6. CloudEvent validation perturbations ---
  const validEvent: Record<string, unknown> = {
    specversion: "1.0",
    id: "evt-001",
    source: "github/hyphae",
    type: "com.github.push",
    datacontenttype: "application/json",
    subject: "refs/heads/main",
    time: "2026-11-24T09:00:00Z",
    repo: "hyphae",
    data: { branch: "main", commits: 2 },
  };
  assert.equal(checkCloudEvent(validEvent).ok, true);

  const mutatedEvents: Array<[string, unknown, "invalid_event" | "too_large"]> = [
    ["null body", null, "invalid_event"],
    ["array body", [], "invalid_event"],
    ["wrong specversion", { ...validEvent, specversion: "0.3" }, "invalid_event"],
    ["numeric specversion", { ...validEvent, specversion: 1.0 }, "invalid_event"],
    ["wrong datacontenttype", { ...validEvent, datacontenttype: "text/plain" }, "invalid_event"],
    ["empty id", { ...validEvent, id: "" }, "invalid_event"],
    ["numeric source", { ...validEvent, source: 42 }, "invalid_event"],
    ["missing type", { ...validEvent, type: undefined }, "invalid_event"],
    ["non-string subject", { ...validEvent, subject: 123 }, "invalid_event"],
    ["invalid RFC3339 time", { ...validEvent, time: "2026-13-45T99:00:00Z" }, "invalid_event"],
    ["non-RFC3339 time string", { ...validEvent, time: "yesterday" }, "invalid_event"],
    ["null data", { ...validEvent, data: null }, "invalid_event"],
    ["array data", { ...validEvent, data: [1, 2] }, "invalid_event"],
    ["uppercase ext name", { ...validEvent, BadExt: "v" }, "invalid_event"],
    ["underscore ext name", { ...validEvent, bad_ext: "v" }, "invalid_event"],
    ["ext name length +1 (>20)", { ...validEvent, ["e".repeat(21)]: "v" }, "invalid_event"],
    ["non-string ext value", { ...validEvent, extnum: 7 }, "invalid_event"],
    ["attribute length +1 (>256)", { ...validEvent, subject: "s".repeat(MAX_ATTRIBUTE_CHARS + 1) }, "too_large"],
    ["data bytes +1 (>8KiB)", { ...validEvent, data: { blob: "x".repeat(MAX_DATA_BYTES) } }, "too_large"],
    [
      "event bytes +1 (>12KiB) with data <= 8KiB",
      {
        ...validEvent,
        data: { blob: "x".repeat(MAX_DATA_BYTES - 32) },
        ...Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`ext${i}`, "v".repeat(240)])),
      },
      "too_large",
    ],
  ];
  for (const [label, candidate, expectedError] of mutatedEvents) {
    const res = checkCloudEvent(candidate);
    assert.equal(res.ok, false, `Expected CloudEvent perturbation '${label}' to fail`);
    assert.equal(res.error, expectedError, `Expected CloudEvent error '${expectedError}' for '${label}', got '${res.error}'`);
  }

  // --- 7. Filter AST perturbations ---
  // Exact max depth (= 8) must pass; depth +1 (= 9) must fail closed!
  const buildNestedNot = (depth: number): unknown => {
    let node: unknown = { exact: { type: "a" } };
    for (let i = 1; i < depth; i++) node = { not: node };
    return [node];
  };
  assert.equal(checkFilters(buildNestedNot(MAX_FILTER_DEPTH)).ok, true);
  assert.equal(checkFilters(buildNestedNot(MAX_FILTER_DEPTH + 1)).ok, false);

  const mutatedFilters: Array<[string, unknown]> = [
    ["not an array (null)", null],
    ["not an array (object)", { exact: { type: "a" } }],
    ["empty filter object", [{}]],
    ["unknown dialect", [{ regex: { type: ".*" } }]],
    ["two dialects on same node", [{ exact: { type: "a" }, prefix: { source: "b" } }]],
    ["empty exact object", [{ exact: {} }]],
    ["empty prefix object", [{ prefix: {} }]],
    ["empty suffix object", [{ suffix: {} }]],
    ["empty all array", [{ all: [] }]],
    ["empty any array", [{ any: [] }]],
    ["swapped type in exact value (number)", [{ exact: { type: 123 } }]],
    ["swapped type in prefix value (null)", [{ prefix: { type: null } }]],
    ["swapped type in suffix value (array)", [{ suffix: { type: ["a"] } }]],
    ["swapped type in not (string)", [{ not: "exact" }]],
    ["swapped type in all (object)", [{ all: { exact: { type: "a" } } }]],
    ["empty key", [{ exact: { "": "a" } }]],
    ["uppercase attribute key", [{ exact: { Type: "a" } }]],
    ["attribute key length +1 (>20)", [{ exact: { ["a".repeat(21)]: "a" } }]],
    ["empty data. field", [{ exact: { "data.": "a" } }]],
    ["whitespace in data. field", [{ exact: { "data.bad field": "a" } }]],
    ["data. field length +1 (>128)", [{ exact: { [`data.${"x".repeat(129)}`]: "a" } }]],
    ["filters exceeding 4KiB", [{ exact: { type: "x".repeat(MAX_FILTERS_BYTES + 1) } }]],
  ];
  for (const [label, candidate] of mutatedFilters) {
    const res = checkFilters(candidate);
    assert.equal(res.ok, false, `Expected mutated filter '${label}' to be rejected`);
  }

  // --- 8. Malformed decodeItem payloads ---
  assert.ok(decodeItem({ id: "m1", kind: "message", from: "a@h/x", to: "b@h/y", text: "hi" }));
  assert.ok(decodeItem({ id: "m2", from: "a@h/x", to: "b@h/y", text: "hi" }));
  assert.ok(decodeItem({ id: "e1", kind: "event", subscriptionId: "s1", topic: "ci", events: [{ type: "x" }] }));

  const mutatedItems: Array<[string, Record<string, unknown>]> = [
    ["empty id", { id: "", kind: "message", from: "a@h/x", to: "b@h/y", text: "hi" }],
    ["id length +1 (>256)", { id: "i".repeat(257), kind: "message", from: "a@h/x", to: "b@h/y", text: "hi" }],
    ["numeric id", { id: 123, kind: "message", from: "a@h/x", to: "b@h/y", text: "hi" }],
    ["uppercase from", { id: "m1", kind: "message", from: "A@h/x", to: "b@h/y", text: "hi" }],
    ["missing slash in to", { id: "m1", kind: "message", from: "a@h/x", to: "invalid", text: "hi" }],
    ["NUL byte in from", { id: "m1", kind: "message", from: "a@h/x\0", to: "b@h/y", text: "hi" }],
    ["non-string text", { id: "m1", kind: "message", from: "a@h/x", to: "b@h/y", text: { nested: true } }],
    ["unknown kind", { id: "m1", kind: "transfer", from: "a@h/x", to: "b@h/y", text: "hi" }],
    ["event non-array events", { id: "e1", kind: "event", subscriptionId: "s1", topic: "ci", events: "not-array" }],
    ["event array with null", { id: "e1", kind: "event", subscriptionId: "s1", topic: "ci", events: [null] }],
    ["event array with nested array", { id: "e1", kind: "event", subscriptionId: "s1", topic: "ci", events: [[]] }],
    ["event missing topic", { id: "e1", kind: "event", subscriptionId: "s1", events: [{}] }],
  ];
  for (const [label, payload] of mutatedItems) {
    assert.equal(decodeItem(payload), undefined, `Expected decodeItem perturbation '${label}' to return undefined`);
  }
});

test("differential: matchesFilters agrees 100% with independent reference evaluator across 250 generated filter/event pairs", () => {
  const seed = resolveSeed();
  const rng = new Rng(seed ^ 0x9e3779b9);

  const types = ["com.github.push", "com.github.pull_request", "com.ci.failed", "com.ci.passed", "com.ops.alert"];
  const sources = ["github/hyphae", "github/core", "ci/build", "ops/prom"];
  const subjects = ["main", "feat/diff", "release-v1", "hotfix.tmp"];
  const envs = ["prod", "staging", "dev"];
  const keys = [
    "type", "source", "subject", "env", "missingattr", "data",
    "data.repo", "data.severity", "data.count", "data.urgent",
    "data.tags", "data.nested", "data.nullable", "data.obj",
    "data.missing", "data.toString", "data.constructor",
  ];
  const candidateValues = [
    "com.github.push", "com.github.", ".push", "com.ci.", "failed",
    "github/", "hyphae", "core", "main", ".tmp", "prod", "dev",
    "high", "low", "0", "3", "42", "true", "false", "alpha", "beta", "nope", "",
  ];

  const genEvent = (index: number): CloudEvent => {
    const data: Record<string, unknown> = {
      repo: rng.pick(["hyphae", "core", "docs"]),
      severity: rng.pick(["high", "medium", "low"]),
      count: rng.pick([0, 3, 42, -0]),
      urgent: rng.bool(0.5),
      tags: rng.pick([
        ["alpha", "beta"],
        [3, true, "high"],
        [],
        ["alpha", ["nested-ignored"], null, { ignored: 1 }],
      ]),
      nested: [["deep"]],
      nullable: null,
      obj: { inner: "value" },
    };
    const raw: Record<string, unknown> = {
      specversion: "1.0",
      id: `diff-evt-${index}`,
      source: rng.pick(sources),
      type: rng.pick(types),
      datacontenttype: "application/json",
      env: rng.pick(envs),
      data,
    };
    if (rng.bool(0.8)) raw.subject = rng.pick(subjects);
    if (rng.bool(0.5)) raw.time = "2026-11-24T09:00:00Z";
    const checked = checkCloudEvent(raw);
    assert.equal(checked.ok, true, `Generated event #${index} must be schema-valid (seed=0x${seed.toString(16)})`);
    return checked.event;
  };

  const genLeafValue = (event: CloudEvent, key: string, dialect: "exact" | "prefix" | "suffix"): string => {
    // 60% of leaf predicates target an actual value from the event (exact/prefix/suffix)
    // so both matching and non-matching branches of complex ASTs are richly exercised.
    if (rng.bool(0.6)) {
      const actuals = referenceLookupAttribute(event, key);
      if (actuals.length > 0) {
        const chosen = rng.pick(actuals);
        if (dialect === "exact") return chosen;
        if (dialect === "prefix") return chosen.slice(0, Math.max(0, Math.min(chosen.length, 1 + rng.int(chosen.length + 1))));
        return chosen.slice(Math.max(0, chosen.length - (1 + rng.int(chosen.length + 1))));
      }
    }
    return rng.pick(candidateValues);
  };

  const genFilter = (event: CloudEvent, depth: number): Filter => {
    const canRecurse = depth < 4;
    const roll = rng.next();
    if (!canRecurse || roll < 0.6) {
      const dialect = rng.pick(["exact", "prefix", "suffix"] as const);
      const pairCount = rng.bool(0.75) ? 1 : 2;
      const pairs: Record<string, string> = {};
      for (let i = 0; i < pairCount; i++) {
        const key = rng.pick(keys);
        pairs[key] = genLeafValue(event, key, dialect);
      }
      return { [dialect]: pairs } as Filter;
    }
    if (roll < 0.74) {
      const count = 1 + rng.int(3);
      return { all: Array.from({ length: count }, () => genFilter(event, depth + 1)) };
    }
    if (roll < 0.88) {
      const count = 1 + rng.int(3);
      return { any: Array.from({ length: count }, () => genFilter(event, depth + 1)) };
    }
    return { not: genFilter(event, depth + 1) };
  };

  let trueCount = 0;
  let falseCount = 0;
  const PAIRS = 250;

  for (let i = 0; i < PAIRS; i++) {
    const event = genEvent(i);
    const filterCount = i === 0 ? 0 : 1 + rng.int(3);
    const rawFilters = Array.from({ length: filterCount }, () => genFilter(event, 1));

    const checked = checkFilters(rawFilters);
    assert.equal(
      checked.ok,
      true,
      `Generated filter #${i} failed checkFilters (seed=0x${seed.toString(16)}): ${JSON.stringify(rawFilters)}`,
    );

    const actual = matchesFilters(checked.filters, event);
    const expected = referenceMatchesFilters(checked.filters, event);
    assert.equal(
      actual,
      expected,
      `Filter divergence on pair #${i} (HYPHAE_DIFF_SEED=0x${seed.toString(16)}):\n` +
        `  filters=${JSON.stringify(checked.filters)}\n` +
        `  event=${JSON.stringify(event)}\n` +
        `  actual=${actual}, reference=${expected}`,
    );

    if (actual) trueCount++;
    else falseCount++;
  }

  // Ensure the generated workload covers both matching and non-matching cases meaningfully
  assert.ok(trueCount >= 20, `Expected >=20 matching pairs, got ${trueCount} (seed=0x${seed.toString(16)})`);
  assert.ok(falseCount >= 20, `Expected >=20 non-matching pairs, got ${falseCount} (seed=0x${seed.toString(16)})`);
});
