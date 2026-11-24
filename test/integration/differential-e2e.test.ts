/**
 * End-to-End Differential, Fuzz & Forgotten-Input Integration Suite for Hyphae (`hyp`),
 * grounded in William M. McKeeman's "Differential Testing for Software"
 * (Digital Technical Journal, Vol. 10 No. 1, 1998).
 *
 * Covers three high-value integration pillars:
 *   1. Multi-Connector, Multi-Router & Plugin-Host Stateful Differential Oracle (Levels 5–6)
 *   2. Level 1–2 Framing, Lexical & Boundary Perturbation Resilience (fd-3, Unix socket, HTTP)
 *   3. Forgotten CLI Inputs & Agent-First Output Contract (`--json` / `--plain` / `--pretty` / env / exit codes)
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHmac, randomUUID } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { createConnection } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { pathToFileURL } from "node:url";
import { EXIT_ERROR, EXIT_OK, EXIT_USAGE } from "../../src/cli-ui.ts";
import { loadConfig } from "../../src/config.ts";
import { parseAddress } from "../../src/core/address.ts";
import { DEFAULT_RECEIVER_LIMITS, serveReceiver } from "../../src/core/github/receiver.ts";
import { signatureHeader } from "../../src/core/github/signature.ts";
import { formatPluginDelivery } from "../../src/core/plugins/delivery.ts";
import type { CloudEvent } from "../../src/core/router/cloudevent.ts";
import { DEFAULT_LIMITS, RouterCore } from "../../src/core/router/core.ts";
import { DEFAULT_EVENT_LIMITS } from "../../src/core/router/events.ts";
import type { Filter } from "../../src/core/router/filter.ts";
import { serveRouter, type RunningRouter } from "../../src/core/router/server.ts";
import { startDaemon, type RunningDaemon } from "../../src/daemon.ts";
import type { Backend } from "../../src/delivery.ts";
import { daemonRpc } from "../../src/hooks.ts";
import {
  formatItem,
  handlePattern,
  normalizeChannelName,
  normalizeMutePattern,
  type DeliveryMode,
} from "../../src/protocol.ts";
import { RouterError } from "../../src/router.ts";
import {
  setupAntigravity,
  setupClaude,
  setupCodex,
  setupCursor,
  setupGemini,
  setupOpenClaw,
  setupOpenCode,
} from "../../src/setup.ts";
import { freePort, MeshTopology, waitFor } from "./harness/topology.ts";
import { deliverGithubWebhook, deliverSignedWebhook, makeGithubPullRequestPayload } from "./shims/services.ts";

// ============================================================================
// Deterministic PRNG (mulberry32), Failure Diagnostics & Shared Utilities
// ============================================================================

const DEFAULT_SEED = 0x5eed2026;
// eslint-disable-next-line no-control-regex
const ANSI_RE = /\x1b\[/;
const CLI_SCRIPT = join(process.cwd(), "src", "cli.ts");
const PLUGIN_SDK_URL = pathToFileURL(join(process.cwd(), "plugins", "sdk", "client.mjs")).href;

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
    return items[this.int(items.length)]!;
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

function runCliAsync(
  args: readonly string[],
  options: {
    readonly env?: Record<string, string | undefined>;
    readonly stdin?: string;
    readonly timeoutMs?: number;
  } = {},
): Promise<{ readonly code: number | null; readonly stdout: string; readonly stderr: string }> {
  return new Promise((resolve, reject) => {
    const env: NodeJS.ProcessEnv = { ...process.env };
    delete env.HYPHAE_OUTPUT;
    delete env.NO_COLOR;
    delete env.HYPHAE_SOCKET;
    delete env.AGENTS_MESH_SOCKET;
    env.HYPHAE_SECRET_BACKEND = "file";
    if (options.env) {
      for (const [k, v] of Object.entries(options.env)) {
        if (v === undefined) delete env[k];
        else env[k] = v;
      }
    }
    const child = spawn(process.execPath, [CLI_SCRIPT, ...args], {
      env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (d: Buffer) => out.push(d));
    child.stderr.on("data", (d: Buffer) => err.push(d));

    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      reject(new Error(`CLI timed out after ${options.timeoutMs ?? 15_000}ms: hyp ${args.join(" ")}`));
    }, options.timeoutMs ?? 15_000).unref();

    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("exit", (code) => {
      clearTimeout(timer);
      resolve({
        code,
        stdout: Buffer.concat(out).toString("utf8"),
        stderr: Buffer.concat(err).toString("utf8"),
      });
    });

    if (options.stdin !== undefined) {
      child.stdin.write(options.stdin);
    }
    child.stdin.end();
  });
}

// ============================================================================
// Pure In-Memory Multi-Node + Plugin-Host Differential Oracle (Test 1)
// ============================================================================

type RouterId = "team" | "priv";

interface OracleSubscription {
  readonly id: string;
  readonly key: string;
  readonly topic: string;
  readonly routerLink: string;
  readonly routerId: RouterId;
  readonly filters: readonly Filter[];
}

interface OracleMailboxItem {
  readonly kind: "message" | "event" | "plugin";
  readonly source: string;
  readonly text: string;
  notified: boolean;
}

interface OracleSession {
  readonly id: string;
  readonly connectorId: string;
  handle: string | null;
  deliveryMode: DeliveryMode;
  readonly sessionMutes: Set<string>;
  readonly subscriptions: Map<string, OracleSubscription>;
  mailbox: OracleMailboxItem[];
}

interface OracleConnector {
  readonly id: string;
  readonly primaryRouter: RouterId;
  readonly routerLinks: ReadonlyMap<string, RouterId>;
  readonly connectorMutes: Set<string>;
  readonly sessionIds: readonly string[];
  readonly bridge?: {
    readonly plugin: string;
    readonly target: string;
    readonly configuredHandle: string;
    handoffSessionId: string | null;
    readonly linkedSessions: Set<string>;
  };
}

interface OracleMute {
  readonly scope: "connector" | "session";
  readonly pattern: string;
}

/** Pure in-memory CloudEvents Subscriptions API filter evaluator for differential verification. */
function oracleMatchesSingleFilter(filter: Filter, event: CloudEvent): boolean {
  if ("exact" in filter && filter.exact) {
    return Object.entries(filter.exact).every(([k, v]) => event[k] === v);
  }
  if ("prefix" in filter && filter.prefix) {
    return Object.entries(filter.prefix).every(([k, v]) => typeof event[k] === "string" && String(event[k]).startsWith(v));
  }
  if ("suffix" in filter && filter.suffix) {
    return Object.entries(filter.suffix).every(([k, v]) => typeof event[k] === "string" && String(event[k]).endsWith(v));
  }
  if ("all" in filter && filter.all) {
    return filter.all.every((sub) => oracleMatchesSingleFilter(sub, event));
  }
  if ("any" in filter && filter.any) {
    return filter.any.some((sub) => oracleMatchesSingleFilter(sub, event));
  }
  if ("not" in filter && filter.not) {
    return !oracleMatchesSingleFilter(filter.not, event);
  }
  return true;
}

function oracleMatchesFilters(filters: readonly Filter[], event: CloudEvent): boolean {
  if (filters.length === 0) return true;
  return filters.every((f) => oracleMatchesSingleFilter(f, event));
}

class MultiNodeOracle {
  readonly #routerTopics = new Map<RouterId, ReadonlySet<string>>();
  readonly #routerChannels = new Map<RouterId, Map<string, Set<string>>>();
  readonly #connectors = new Map<string, OracleConnector>();
  readonly #sessions = new Map<string, OracleSession>();

  constructor(
    routers: Readonly<Record<RouterId, readonly string[]>>,
    connectors: ReadonlyArray<{
      readonly id: string;
      readonly primaryRouter: RouterId;
      readonly routerLinks: Readonly<Record<string, RouterId>>;
      readonly sessionIds: readonly string[];
      readonly bridge?: { readonly plugin: string; readonly target: string; readonly configuredHandle: string };
    }>,
  ) {
    for (const [rid, topics] of Object.entries(routers) as Array<[RouterId, readonly string[]]>) {
      this.#routerTopics.set(rid, new Set(topics));
      this.#routerChannels.set(rid, new Map());
    }
    for (const spec of connectors) {
      this.#connectors.set(spec.id, {
        id: spec.id,
        primaryRouter: spec.primaryRouter,
        routerLinks: new Map(Object.entries(spec.routerLinks)),
        connectorMutes: new Set(),
        sessionIds: spec.sessionIds,
        ...(spec.bridge
          ? {
              bridge: {
                plugin: spec.bridge.plugin,
                target: spec.bridge.target,
                configuredHandle: spec.bridge.configuredHandle,
                handoffSessionId: null,
                linkedSessions: new Set<string>(),
              },
            }
          : {}),
      });
      for (const sid of spec.sessionIds) {
        this.#sessions.set(sid, {
          id: sid,
          connectorId: spec.id,
          handle: null,
          deliveryMode: "full",
          sessionMutes: new Set(),
          subscriptions: new Map(),
          mailbox: [],
        });
      }
    }
  }

  #session(sid: string): OracleSession {
    const s = this.#sessions.get(sid);
    if (!s) throw new Error(`Unknown oracle session ${sid}`);
    return s;
  }

  #connector(cid: string): OracleConnector {
    const c = this.#connectors.get(cid);
    if (!c) throw new Error(`Unknown oracle connector ${cid}`);
    return c;
  }

  #sessionByHandle(cid: string, handle: string): OracleSession | undefined {
    const conn = this.#connector(cid);
    for (const sid of conn.sessionIds) {
      const s = this.#session(sid);
      if (s.handle === handle) return s;
    }
    return undefined;
  }

  #removeFromRouterChannels(routerId: RouterId, address: string): void {
    const map = this.#routerChannels.get(routerId)!;
    for (const [channel, members] of map) {
      members.delete(address);
      if (members.size === 0) map.delete(channel);
    }
  }

  #isMuted(session: OracleSession, candidates: readonly string[]): boolean {
    const conn = this.#connector(session.connectorId);
    for (const c of candidates) {
      const low = c.toLowerCase();
      if (conn.connectorMutes.has(low) || session.sessionMutes.has(low)) return true;
    }
    return false;
  }

  #deliverMessage(from: string, to: string, rawText: string, senderRouter: RouterId): boolean {
    const parsed = parseAddress(to);
    if (!parsed) return false;
    const targetConn = this.#connectors.get(parsed.connectorId);
    if (!targetConn || targetConn.primaryRouter !== senderRouter) return false;
    const recipient = this.#sessionByHandle(parsed.connectorId, parsed.handle);
    if (!recipient) return false;

    const lowerFrom = from.toLowerCase();
    const senderConn = lowerFrom.split("/")[0]!;
    const candidates = [lowerFrom, `${senderConn}/*`];
    const chMatch = /^\[(#[^\]\s]+)\]\s/.exec(rawText);
    if (chMatch) candidates.push(chMatch[1]!.toLowerCase());

    if (!this.#isMuted(recipient, candidates)) {
      const formatted = formatItem({ id: "oracle", kind: "message", from, to, text: rawText });
      const source = chMatch ? `${chMatch[1]} (${from})` : from;
      recipient.mailbox.push({ kind: "message", source, text: formatted, notified: false });
    }
    return true;
  }

  // ---- Query / state inspection ----

  connectorOf(sid: string): string {
    return this.#session(sid).connectorId;
  }

  primaryRouterOf(cid: string): RouterId {
    return this.#connector(cid).primaryRouter;
  }

  handleOf(sid: string): string | null {
    return this.#session(sid).handle;
  }

  addressOf(sid: string): string | null {
    const s = this.#session(sid);
    return s.handle === null ? null : `${s.connectorId}/${s.handle}`;
  }

  deliveryModeOf(sid: string): DeliveryMode {
    return this.#session(sid).deliveryMode;
  }

  pendingCount(sid: string): number {
    return this.#session(sid).mailbox.length;
  }

  unnotifiedCount(sid: string): number {
    return this.#session(sid).mailbox.filter((m) => !m.notified).length;
  }

  subscriptionCount(sid: string): number {
    return this.#session(sid).subscriptions.size;
  }

  subscriptionsOf(sid: string): Array<{ id: string; key: string; topic: string; router: string; filters: readonly Filter[] }> {
    return [...this.#session(sid).subscriptions.values()]
      .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0))
      .map(({ id, key, topic, routerLink, filters }) => ({ id, key, topic, router: routerLink, filters }));
  }

  mailboxTextsSorted(sid: string): string[] {
    return this.#session(sid).mailbox.map((m) => m.text).sort();
  }

  peersOnRouter(routerId: RouterId): Array<{ address: string; online: boolean }> {
    const out: Array<{ address: string; online: boolean }> = [];
    for (const conn of this.#connectors.values()) {
      if (conn.primaryRouter !== routerId) continue;
      for (const sid of conn.sessionIds) {
        const s = this.#session(sid);
        if (s.handle !== null) {
          out.push({ address: `${conn.id}/${s.handle}`, online: true });
        }
      }
    }
    return out.sort((a, b) => (a.address < b.address ? -1 : a.address > b.address ? 1 : 0));
  }

  channelsOnRouter(routerId: RouterId): Array<{ channel: string; members: string[] }> {
    const map = this.#routerChannels.get(routerId)!;
    const out: Array<{ channel: string; members: string[] }> = [];
    for (const [channel, members] of map) {
      if (members.size === 0) continue;
      out.push({ channel, members: [...members].sort() });
    }
    return out.sort((a, b) => (a.channel < b.channel ? -1 : a.channel > b.channel ? 1 : 0));
  }

  mutesFor(sid: string): OracleMute[] {
    const s = this.#session(sid);
    const conn = this.#connector(s.connectorId);
    const connRules: OracleMute[] = [...conn.connectorMutes]
      .sort()
      .map((pattern) => ({ scope: "connector", pattern }));
    const sessRules: OracleMute[] = [...s.sessionMutes]
      .sort()
      .map((pattern) => ({ scope: "session", pattern }));
    return [...connRules, ...sessRules];
  }

  // ---- Bridge / Plugin helpers ----

  #resolveBridgePrimary(cid: string): OracleSession | undefined {
    const bridge = this.#connector(cid).bridge;
    if (!bridge) return undefined;
    if (bridge.handoffSessionId !== null) {
      return this.#sessions.get(bridge.handoffSessionId);
    }
    return this.#sessionByHandle(cid, bridge.configuredHandle);
  }

  #bridgeHolderStatus(callerSid: string): {
    readonly current: OracleSession | undefined;
    readonly configured: OracleSession | undefined;
    readonly isPrimary: boolean;
    readonly isLinked: boolean;
  } {
    const s = this.#session(callerSid);
    const bridge = this.#connector(s.connectorId).bridge!;
    const current = this.#resolveBridgePrimary(s.connectorId);
    const configured = this.#sessionByHandle(s.connectorId, bridge.configuredHandle);
    const isPrimary = callerSid === current?.id || callerSid === configured?.id;
    const isLinked = bridge.linkedSessions.has(callerSid);
    return { current, configured, isPrimary, isLinked };
  }

  bridgeRecipients(cid: string): OracleSession[] {
    const bridge = this.#connector(cid).bridge;
    if (!bridge) return [];
    const map = new Map<string, OracleSession>();
    const primary = this.#resolveBridgePrimary(cid);
    if (primary) map.set(primary.id, primary);
    for (const sid of bridge.linkedSessions) {
      const s = this.#sessions.get(sid);
      if (s) map.set(s.id, s);
    }
    return [...map.values()];
  }

  bridgeLinkedSorted(cid: string): Array<{ sessionId: string; handle: string | null }> {
    const bridge = this.#connector(cid).bridge;
    if (!bridge) return [];
    return [...bridge.linkedSessions]
      .sort()
      .map((sid) => ({ sessionId: sid, handle: this.#session(sid).handle }));
  }

  pluginTargetsFor(callerSid: string):
    | { ok: true; targets: Array<{ plugin: string; target: string; sessionId: string | null; handle: string | null; linkedSessions: Array<{ sessionId: string; handle: string | null }> }> }
    | { ok: false; code: "no_plugins" } {
    const s = this.#session(callerSid);
    const bridge = this.#connector(s.connectorId).bridge;
    if (!bridge) return { ok: false, code: "no_plugins" };
    const { current, isPrimary, isLinked } = this.#bridgeHolderStatus(callerSid);
    if (!isPrimary && !isLinked) return { ok: true, targets: [] };
    return {
      ok: true,
      targets: [
        {
          plugin: bridge.plugin,
          target: bridge.target,
          sessionId: current?.id ?? null,
          handle: current?.handle ?? bridge.configuredHandle,
          linkedSessions: this.bridgeLinkedSorted(s.connectorId),
        },
      ],
    };
  }

  // ---- Operations ----

  join(sid: string, handle: string): { ok: true; address: string } | { ok: false; code: string } {
    if (!handlePattern.test(handle)) return { ok: false, code: "invalid" };
    const s = this.#session(sid);
    const owner = this.#sessionByHandle(s.connectorId, handle);
    if (owner && owner.id !== sid) return { ok: false, code: "handle_taken" };
    if (s.handle !== null && s.handle !== handle) {
      this.#removeFromRouterChannels(this.#connector(s.connectorId).primaryRouter, `${s.connectorId}/${s.handle}`);
    }
    s.handle = handle;
    return { ok: true, address: `${s.connectorId}/${handle}` };
  }

  leave(sid: string): { left: boolean } {
    const s = this.#session(sid);
    if (s.handle === null) return { left: false };
    this.#removeFromRouterChannels(this.#connector(s.connectorId).primaryRouter, `${s.connectorId}/${s.handle}`);
    s.handle = null;
    return { left: true };
  }

  send(sid: string, to: string, text: string): { ok: true } | { ok: false; code: string } {
    const s = this.#session(sid);
    if (s.handle === null) return { ok: false, code: "not_enrolled" };
    const senderRouter = this.#connector(s.connectorId).primaryRouter;
    const deliveredOk = this.#deliverMessage(`${s.connectorId}/${s.handle}`, to, text, senderRouter);
    if (!deliveredOk) return { ok: false, code: "unknown_recipient" };
    return { ok: true };
  }

  channelJoin(sid: string, rawChannel: string):
    | { ok: true; channel: string; address: string; members: string[] }
    | { ok: false; code: string } {
    const channel = normalizeChannelName(rawChannel);
    if (!channel) return { ok: false, code: "invalid" };
    const s = this.#session(sid);
    if (s.handle === null) return { ok: false, code: "not_enrolled" };
    const routerId = this.#connector(s.connectorId).primaryRouter;
    const address = `${s.connectorId}/${s.handle}`;
    const map = this.#routerChannels.get(routerId)!;
    const members = map.get(channel) ?? new Set<string>();
    members.add(address);
    map.set(channel, members);
    return { ok: true, channel, address, members: [...members].sort() };
  }

  channelLeave(sid: string, rawChannel: string):
    | { ok: true; channel: string; address: string; left: boolean }
    | { ok: false; code: string } {
    const channel = normalizeChannelName(rawChannel);
    if (!channel) return { ok: false, code: "invalid" };
    const s = this.#session(sid);
    if (s.handle === null) return { ok: false, code: "not_enrolled" };
    const routerId = this.#connector(s.connectorId).primaryRouter;
    const address = `${s.connectorId}/${s.handle}`;
    const map = this.#routerChannels.get(routerId)!;
    const members = map.get(channel);
    const left = members ? members.delete(address) : false;
    if (members && members.size === 0) map.delete(channel);
    return { ok: true, channel, address, left };
  }

  channelPost(sid: string, rawChannel: string, text: string):
    | { ok: true; channel: string; deliveredTo: string[] }
    | { ok: false; code: string } {
    const channel = normalizeChannelName(rawChannel);
    if (!channel || text.length === 0) return { ok: false, code: "invalid" };
    const s = this.#session(sid);
    if (s.handle === null) return { ok: false, code: "not_enrolled" };
    const routerId = this.#connector(s.connectorId).primaryRouter;
    const senderAddress = `${s.connectorId}/${s.handle}`;
    const members = this.#routerChannels.get(routerId)!.get(channel);
    if (!members || !members.has(senderAddress)) return { ok: false, code: "not_member" };
    const recipients = [...members].filter((m) => m !== senderAddress).sort();
    const tagged = `[${channel}] ${text}`;
    for (const recipient of recipients) {
      this.#deliverMessage(senderAddress, recipient, tagged, routerId);
    }
    return { ok: true, channel, deliveredTo: recipients };
  }

  checkSubscribe(sid: string, key: string, topic: string, routerLink: string, filters: readonly Filter[]):
    | { ok: true; routerId: RouterId; outcome: "created" | "updated" | "unchanged"; existingId?: string }
    | { ok: false; code: string } {
    const s = this.#session(sid);
    const conn = this.#connector(s.connectorId);
    const routerId = conn.routerLinks.get(routerLink);
    if (!routerId) return { ok: false, code: "invalid" };
    const existing = s.subscriptions.get(key);
    if (existing && (existing.routerLink !== routerLink || existing.topic !== topic)) {
      return { ok: false, code: "invalid" };
    }
    if (!this.#routerTopics.get(routerId)!.has(topic)) {
      return { ok: false, code: "unknown_topic" };
    }
    if (!existing) return { ok: true, routerId, outcome: "created" };
    const changed = JSON.stringify(existing.filters) !== JSON.stringify(filters);
    return { ok: true, routerId, outcome: changed ? "updated" : "unchanged", existingId: existing.id };
  }

  commitSubscribe(sid: string, sub: OracleSubscription): void {
    this.#session(sid).subscriptions.set(sub.key, sub);
  }

  unsubscribe(sid: string, key: string): { removed: boolean } {
    const s = this.#session(sid);
    return { removed: s.subscriptions.delete(key) };
  }

  publishEvent(routerId: RouterId, topic: string, event: CloudEvent): { matched: number } {
    let matched = 0;
    for (const s of this.#sessions.values()) {
      for (const sub of s.subscriptions.values()) {
        if (sub.routerId !== routerId || sub.topic !== topic) continue;
        if (!oracleMatchesFilters(sub.filters, event)) continue;
        matched++;
        if (!this.#isMuted(s, [`topic:${topic.toLowerCase()}`])) {
          const formatted = formatItem({
            id: "oracle",
            kind: "event",
            subscriptionId: sub.id,
            topic,
            events: [event as Record<string, unknown>],
          });
          s.mailbox.push({ kind: "event", source: topic, text: formatted, notified: false });
        }
      }
    }
    return { matched };
  }

  bridgeLink(callerSid: string, targetSid: string):
    | { ok: true; sessionId: string; handle: string | null; linkedSessions: Array<{ sessionId: string; handle: string | null }> }
    | { ok: false; code: string } {
    const caller = this.#session(callerSid);
    const conn = this.#connector(caller.connectorId);
    if (!conn.bridge) return { ok: false, code: "no_plugins" };
    const dest = this.#sessions.get(targetSid);
    if (!dest || dest.connectorId !== caller.connectorId) return { ok: false, code: "unknown_session" };
    const { current, configured, isPrimary } = this.#bridgeHolderStatus(callerSid);
    const hasActiveHolder = current !== undefined || configured !== undefined;
    if (hasActiveHolder && !isPrimary) return { ok: false, code: "not_target_holder" };
    conn.bridge.linkedSessions.add(dest.id);
    return {
      ok: true,
      sessionId: dest.id,
      handle: dest.handle,
      linkedSessions: this.bridgeLinkedSorted(caller.connectorId),
    };
  }

  bridgeUnlink(callerSid: string, opts: { readonly targetSid?: string; readonly all?: boolean }):
    | { ok: true; removed: boolean; removedCount: number; linkedSessions: Array<{ sessionId: string; handle: string | null }> }
    | { ok: false; code: string } {
    const caller = this.#session(callerSid);
    const conn = this.#connector(caller.connectorId);
    if (!conn.bridge) return { ok: false, code: "no_plugins" };
    const { isPrimary } = this.#bridgeHolderStatus(callerSid);
    if (opts.all === true) {
      if (!isPrimary) return { ok: false, code: "not_target_holder" };
      const removedCount = conn.bridge.linkedSessions.size;
      conn.bridge.linkedSessions.clear();
      return { ok: true, removed: removedCount > 0, removedCount, linkedSessions: [] };
    }
    const destId = opts.targetSid ?? callerSid;
    const dest = this.#sessions.get(destId);
    if (!dest || dest.connectorId !== caller.connectorId) return { ok: false, code: "unknown_session" };
    if (!isPrimary && dest.id !== callerSid) return { ok: false, code: "not_target_holder" };
    const existed = conn.bridge.linkedSessions.delete(dest.id);
    return {
      ok: true,
      removed: existed,
      removedCount: existed ? 1 : 0,
      linkedSessions: this.bridgeLinkedSorted(caller.connectorId),
    };
  }

  pluginHandoff(callerSid: string, destSid: string):
    | { ok: true; plugin: string; target: string; sessionId: string }
    | { ok: false; code: string } {
    const caller = this.#session(callerSid);
    const conn = this.#connector(caller.connectorId);
    if (!conn.bridge) return { ok: false, code: "no_plugins" };
    const { isPrimary } = this.#bridgeHolderStatus(callerSid);
    if (!isPrimary) return { ok: false, code: "not_target_holder" };
    const dest = this.#sessions.get(destSid);
    if (!dest || dest.connectorId !== caller.connectorId) return { ok: false, code: "unknown_session" };
    conn.bridge.handoffSessionId = dest.id;
    return { ok: true, plugin: conn.bridge.plugin, target: conn.bridge.target, sessionId: dest.id };
  }

  emitPluginEvent(cid: string, event: CloudEvent): { deliveredRecipients: number } {
    const conn = this.#connector(cid);
    const bridge = conn.bridge;
    if (!bridge) throw new Error(`Connector ${cid} has no bridge`);
    const recipients = this.bridgeRecipients(cid);
    if (recipients.length === 0) throw new Error(`Oracle refused emitPluginEvent with 0 recipients`);
    const formatted = formatPluginDelivery(bridge.plugin, {
      id: "oracle",
      subscriptionId: "oracle",
      topic: "oracle",
      events: [event],
      sentAt: "2026-11-24T12:00:00Z",
    });
    let deliveredRecipients = 0;
    for (const r of recipients) {
      if (!this.#isMuted(r, [`plugin:${bridge.plugin.toLowerCase()}`])) {
        r.mailbox.push({ kind: "plugin", source: `plugin:${bridge.plugin}`, text: formatted, notified: false });
        deliveredRecipients++;
      }
    }
    return { deliveredRecipients };
  }

  mute(sid: string, target: string, scope: "connector" | "session"): { muted: string; scope: "connector" | "session" } {
    const pattern = normalizeMutePattern(target);
    if (!pattern) throw new Error(`Invalid mute target: ${target}`);
    const s = this.#session(sid);
    if (scope === "connector") this.#connector(s.connectorId).connectorMutes.add(pattern);
    else s.sessionMutes.add(pattern);
    return { muted: pattern, scope };
  }

  unmute(sid: string, target: string, scope: "connector" | "session"): { pattern: string; scope: "connector" | "session"; removed: boolean } {
    const pattern = normalizeMutePattern(target);
    if (!pattern) throw new Error(`Invalid unmute target: ${target}`);
    const s = this.#session(sid);
    const removed = scope === "connector"
      ? this.#connector(s.connectorId).connectorMutes.delete(pattern)
      : s.sessionMutes.delete(pattern);
    return { pattern, scope, removed };
  }

  setMode(sid: string, mode: DeliveryMode): { deliveryMode: DeliveryMode; unread: number } {
    const s = this.#session(sid);
    s.deliveryMode = mode;
    return { deliveryMode: mode, unread: s.mailbox.length };
  }

  inboxPeek(sid: string, ackedTexts: readonly string[] = []): { deliveryMode: DeliveryMode; unread: number; itemTexts: string[] } {
    const s = this.#session(sid);
    if (ackedTexts.length > 0) {
      const remaining = [...ackedTexts];
      s.mailbox = s.mailbox.filter((m) => {
        const idx = remaining.indexOf(m.text);
        if (idx >= 0) {
          remaining.splice(idx, 1);
          return false;
        }
        return true;
      });
    }
    for (const item of s.mailbox) item.notified = true;
    return {
      deliveryMode: s.deliveryMode,
      unread: s.mailbox.length,
      itemTexts: s.mailbox.map((m) => m.text).sort(),
    };
  }

  inboxAcknowledgeAll(sid: string): { deliveryMode: DeliveryMode; unread: number; drainedTexts: string[] } {
    const s = this.#session(sid);
    const drainedTexts = s.mailbox.map((m) => m.text).sort();
    s.mailbox = [];
    return { deliveryMode: s.deliveryMode, unread: 0, drainedTexts };
  }

  drainForPush(sid: string):
    | { readonly mode: "full"; readonly drainedTexts: string[] }
    | {
        readonly mode: "notify";
        readonly expectedDigest: null | {
          readonly unread: number;
          readonly messages: number;
          readonly events: number;
          readonly plugins: number;
          readonly distinctSources: string[];
        };
      } {
    const s = this.#session(sid);
    if (s.deliveryMode === "full") {
      const drainedTexts = s.mailbox.map((m) => m.text).sort();
      s.mailbox = [];
      return { mode: "full", drainedTexts };
    }
    const unnotified = s.mailbox.filter((m) => !m.notified).length;
    if (unnotified === 0) return { mode: "notify", expectedDigest: null };
    let messages = 0;
    let events = 0;
    let plugins = 0;
    const sources = new Set<string>();
    for (const item of s.mailbox) {
      if (item.kind === "event") events++;
      else if (item.kind === "plugin") plugins++;
      else messages++;
      if (item.source) sources.add(item.source);
      item.notified = true;
    }
    return {
      mode: "notify",
      expectedDigest: {
        unread: s.mailbox.length,
        messages,
        events,
        plugins,
        distinctSources: [...sources].sort(),
      },
    };
  }
}

async function waitForConnectorsOnline(core: RouterCore, expectedConnectors: readonly string[], timeoutMs = 6_000): Promise<void> {
  await waitFor(() => {
    const peers = core.peers();
    return expectedConnectors.every((cid) => peers.some((p) => p.address.startsWith(`${cid}/`) && p.online));
  }, { timeoutMs, intervalMs: 15, label: `connectors [${expectedConnectors.join(", ")}] online` });
}

async function waitForMultiNodeQuiescence(
  dbs: readonly DatabaseSync[],
  daemons: readonly RunningDaemon[],
  timeoutMs = 5_000,
): Promise<void> {
  const countOpenOrPending = (db: DatabaseSync): number => {
    const hasMessages = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='messages'").get();
    const pendingMsgs = hasMessages
      ? Number(db.prepare("SELECT COUNT(*) AS n FROM messages WHERE state = 'pending'").get()?.n ?? 0)
      : 0;
    const pendingBatches = Number(db.prepare("SELECT COUNT(*) AS n FROM batches WHERE state IN ('open', 'pending')").get()?.n ?? 0);
    return pendingMsgs + pendingBatches;
  };
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const totalPending = dbs.reduce((sum, db) => sum + countOpenOrPending(db), 0);
    if (totalPending === 0) {
      await Promise.all(daemons.map((d) => d.connector.drain()));
      const afterDrain = dbs.reduce((sum, db) => sum + countOpenOrPending(db), 0);
      if (afterDrain === 0) return;
    }
    await new Promise((r) => setTimeout(r, 8));
  }
  const counts = dbs.map((db) => countOpenOrPending(db));
  throw new Error(`Multi-node topology did not reach quiescence within ${timeoutMs}ms (pending counts=${JSON.stringify(counts)})`);
}

// ============================================================================
// TEST 1 — Multi-Connector, Multi-Router & Plugin-Host Differential Oracle
// ============================================================================

test(
  "differential e2e (Levels 5–6): MultiNodeOracle matches 2 routers + 3 connectors + 6 harnesses + live fd-3 bridge plugin across 90 seeded operations",
  { timeout: 30_000 },
  async () => {
    const seed = resolveSeed();
    const rng = new Rng(seed);
    const history: string[] = [];
    const rootDir = mkdtempSync(join(tmpdir(), "hi-diff-"));

    const teamDbPath = join(rootDir, "team.sqlite");
    const privDbPath = join(rootDir, "priv.sqlite");
    const teamCore = new RouterCore({
      dbPath: teamDbPath,
      topics: new Map([["deploy", ["ci-bot"]]]),
      limits: { ...DEFAULT_LIMITS, maxPerHourPerRecipient: 10_000 },
      eventLimits: { ...DEFAULT_EVENT_LIMITS, maxBatchesPerHourPerSubscription: 10_000 },
    });
    const privCore = new RouterCore({
      dbPath: privDbPath,
      topics: new Map([["alerts", ["ops-bot"]]]),
      limits: { ...DEFAULT_LIMITS, maxPerHourPerRecipient: 10_000 },
      eventLimits: { ...DEFAULT_EVENT_LIMITS, maxBatchesPerHourPerSubscription: 10_000 },
    });

    const ciToken = teamCore.events.addPublisher("ci-bot", ["deploy"]);
    const opsToken = privCore.events.addPublisher("ops-bot", ["alerts"]);
    const alexTeamToken = teamCore.addConnector("alex@laptop");
    const alexPrivToken = privCore.addConnector("alex@laptop");
    const aliceTeamToken = teamCore.addConnector("alice@laptop");
    const jackPrivToken = privCore.addConnector("jack@prod");

    let teamRouter: RunningRouter | undefined;
    let privRouter: RunningRouter | undefined;
    let alexDaemon: RunningDaemon | undefined;
    let aliceDaemon: RunningDaemon | undefined;
    let jackDaemon: RunningDaemon | undefined;
    let teamReadDb: DatabaseSync | undefined;
    let privReadDb: DatabaseSync | undefined;
    let pluginLocalDb: DatabaseSync | undefined;

    try {
      teamRouter = await serveRouter({ core: teamCore, host: "127.0.0.1", port: 0 });
      privRouter = await serveRouter({ core: privCore, host: "127.0.0.1", port: 0 });

      // Write deterministic fd-3 mock chat-bridge plugin exposing a loopback HTTP trigger
      const bridgePort = await freePort();
      const bridgeScript = join(rootDir, "chat-bridge.mjs");
      writeFileSync(
        bridgeScript,
        [
          `import { createServer } from "node:http";`,
          `import { MeshPluginClient } from ${JSON.stringify(PLUGIN_SDK_URL)};`,
          `const mesh = new MeshPluginClient({`,
          `  onPost: async (params) => ({ ok: true, echoed: params.text ?? "" }),`,
          `});`,
          `const hello = await mesh.ready;`,
          `const port = Number(process.env.BRIDGE_PORT);`,
          `const srv = createServer(async (req, res) => {`,
          `  if (req.method === "GET" && req.url === "/health") {`,
          `    res.writeHead(200, { "content-type": "application/json" });`,
          `    res.end(JSON.stringify({ ok: true, targets: hello.targets }));`,
          `    return;`,
          `  }`,
          `  if (req.method === "POST" && req.url === "/emit") {`,
          `    const chunks = [];`,
          `    for await (const c of req) chunks.push(c);`,
          `    const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));`,
          `    const reply = await mesh.send(body.to ?? hello.targets[0], body.event);`,
          `    res.writeHead(200, { "content-type": "application/json" });`,
          `    res.end(JSON.stringify(reply));`,
          `    return;`,
          `  }`,
          `  res.writeHead(404).end();`,
          `});`,
          `srv.listen(port, "127.0.0.1");`,
        ].join("\n") + "\n",
        "utf8",
      );

      const alexStateDir = join(rootDir, "a0");
      const aliceStateDir = join(rootDir, "a1");
      const jackStateDir = join(rootDir, "a2");

      alexDaemon = await startDaemon({
        connectorId: "alex@laptop",
        directory: alexStateDir,
        routers: [
          { name: "primary", url: teamRouter.url, token: alexTeamToken },
          { name: "priv", url: privRouter.url, token: alexPrivToken },
        ],
        plugins: [
          {
            name: "chat-bridge",
            exec: process.execPath,
            args: [bridgeScript],
            env: { BRIDGE_PORT: String(bridgePort) },
            cwd: rootDir,
            targets: [
              {
                name: "inbox",
                handle: "alex-lead",
                coalesceSeconds: 0,
                maxWaitSeconds: 1,
                wakesPerHour: 3600,
              },
            ],
          },
        ],
      }, { quiet: true });

      aliceDaemon = await startDaemon({
        connectorId: "alice@laptop",
        directory: aliceStateDir,
        routers: [{ name: "primary", url: teamRouter.url, token: aliceTeamToken }],
      }, { quiet: true });

      jackDaemon = await startDaemon({
        connectorId: "jack@prod",
        directory: jackStateDir,
        routers: [{ name: "primary", url: privRouter.url, token: jackPrivToken }],
      }, { quiet: true });

      const daemonsByConnector = new Map<string, RunningDaemon>([
        ["alex@laptop", alexDaemon],
        ["alice@laptop", aliceDaemon],
        ["jack@prod", jackDaemon],
      ]);
      const allDaemons = [alexDaemon, aliceDaemon, jackDaemon];

      // Register 6 diverse harness sessions across the 3 connectors
      const sessionDefs: ReadonlyArray<{ readonly id: string; readonly connectorId: string; readonly backend: Backend }> = [
        { id: "antigravity:alex-ag", connectorId: "alex@laptop", backend: { kind: "antigravity" } },
        { id: "claude:alex-cl", connectorId: "alex@laptop", backend: { kind: "claude" } },
        { id: "codex:alice-cx", connectorId: "alice@laptop", backend: { kind: "codex" } },
        { id: "opencode:alice-oc", connectorId: "alice@laptop", backend: { kind: "opencode" } },
        { id: "cursor:jack-cu", connectorId: "jack@prod", backend: { kind: "cursor" } },
        { id: "openclaw:jack-ow", connectorId: "jack@prod", backend: { kind: "openclaw" } },
      ];
      for (const s of sessionDefs) {
        daemonsByConnector.get(s.connectorId)!.state.register(s.id, s.backend);
      }

      // Bootstrap: wait for all router SSE streams + fd-3 chat-bridge child plugin readiness
      await alexDaemon.connector.call("antigravity:alex-ag", "hyp_join", { handle: "boot-a" });
      await aliceDaemon.connector.call("codex:alice-cx", "hyp_join", { handle: "boot-b" });
      await jackDaemon.connector.call("cursor:jack-cu", "hyp_join", { handle: "boot-c" });
      await Promise.all([
        waitForConnectorsOnline(teamCore, ["alex@laptop", "alice@laptop"]),
        waitForConnectorsOnline(privCore, ["jack@prod"]),
        waitFor(async () => {
          const res = await fetch(`http://127.0.0.1:${bridgePort}/health`).catch(() => null);
          return res?.ok ? true : false;
        }, { timeoutMs: 8_000, intervalMs: 30, label: "chat-bridge fd-3 child plugin ready" }),
      ]);
      await alexDaemon.connector.call("antigravity:alex-ag", "hyp_leave", {});
      await aliceDaemon.connector.call("codex:alice-cx", "hyp_leave", {});
      await jackDaemon.connector.call("cursor:jack-cu", "hyp_leave", {});

      teamReadDb = new DatabaseSync(teamDbPath, { readOnly: true });
      privReadDb = new DatabaseSync(privDbPath, { readOnly: true });
      pluginLocalDb = new DatabaseSync(join(alexStateDir, "local.db"), { readOnly: true });
      for (const db of [teamReadDb, privReadDb, pluginLocalDb]) db.exec("PRAGMA busy_timeout = 2000;");
      const allReadDbs = [teamReadDb, privReadDb, pluginLocalDb];

      const oracle = new MultiNodeOracle(
        { team: ["deploy"], priv: ["alerts"] },
        [
          {
            id: "alex@laptop",
            primaryRouter: "team",
            routerLinks: { primary: "team", priv: "priv" },
            sessionIds: ["antigravity:alex-ag", "claude:alex-cl"],
            bridge: { plugin: "chat-bridge", target: "inbox", configuredHandle: "alex-lead" },
          },
          {
            id: "alice@laptop",
            primaryRouter: "team",
            routerLinks: { primary: "team" },
            sessionIds: ["codex:alice-cx", "opencode:alice-oc"],
          },
          {
            id: "jack@prod",
            primaryRouter: "priv",
            routerLinks: { primary: "priv" },
            sessionIds: ["cursor:jack-cu", "openclaw:jack-ow"],
          },
        ],
      );

      const sessionIds = sessionDefs.map((s) => s.id);
      const daemonFor = (sid: string): RunningDaemon => daemonsByConnector.get(oracle.connectorOf(sid))!;

      const handlePools: Readonly<Record<string, readonly string[]>> = {
        "alex@laptop": ["alex-lead", "alex-side", "alex-ops"],
        "alice@laptop": ["alice-dev", "alice-rev", "alice-qa"],
        "jack@prod": ["jack-sre", "jack-db", "jack-net"],
      };
      const channelPool = ["#warroom", "#deploys", "#triage"];
      const teamSubKeys = ["team:deploy-all", "team:deploy-prod"];
      const privSubKeys = ["priv:alerts-all", "priv:alerts-crit"];

      const publishToRouter = async (routerId: RouterId, topic: string, event: CloudEvent): Promise<{ status: number; matched: number }> => {
        const url = routerId === "team" ? teamRouter!.url : privRouter!.url;
        const token = routerId === "team" ? ciToken : opsToken;
        const res = await fetch(`${url}/v1/events?topic=${encodeURIComponent(topic)}`, {
          method: "POST",
          headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
          body: JSON.stringify(event),
        });
        const body = (await res.json()) as { status?: string; matched?: number };
        return { status: res.status, matched: Number(body.matched ?? 0) };
      };

      const verifyFullEquivalence = async (stepIndex: number): Promise<void> => {
        const ctx = (detail: string) => formatFailureContext(seed, history, `Step ${stepIndex}: ${detail}`);

        // 1. Router peer directory & channel equivalence on BOTH team and priv routers
        for (const [probeSid, routerId] of [
          ["antigravity:alex-ag", "team"],
          ["codex:alice-cx", "team"],
          ["cursor:jack-cu", "priv"],
        ] as const) {
          const peersRes = (await daemonFor(probeSid).connector.call(probeSid, "hyp_peers", {})) as {
            self: string | null;
            peers: Array<{ address: string; online: boolean }>;
          };
          assert.equal(peersRes.self, oracle.addressOf(probeSid), ctx(`hyp_peers.self mismatch for ${probeSid}`));
          assert.deepEqual(peersRes.peers, oracle.peersOnRouter(routerId), ctx(`hyp_peers.peers mismatch on ${routerId}`));

          const chRes = (await daemonFor(probeSid).connector.call(probeSid, "hyp_channels", {})) as {
            channels: Array<{ channel: string; members: string[] }>;
          };
          assert.deepEqual(chRes.channels, oracle.channelsOnRouter(routerId), ctx(`hyp_channels mismatch on ${routerId}`));
        }

        // 2. Plugin bridge targets & linked sessions equivalence on alex@laptop
        for (const sid of ["antigravity:alex-ag", "claude:alex-cl"]) {
          const expectedTargets = oracle.pluginTargetsFor(sid);
          assert.equal(expectedTargets.ok, true);
          const actualTargets = (await alexDaemon!.connector.call(sid, "hyp_plugin_targets", {})) as {
            targets: Array<{
              plugin: string;
              target: string;
              sessionId: string | null;
              handle: string | null;
              linkedSessions: Array<{ sessionId: string; handle: string | null }>;
            }>;
          };
          const normalizedActual = actualTargets.targets.map((t) => ({
            ...t,
            linkedSessions: [...t.linkedSessions].sort((a, b) => (a.sessionId < b.sessionId ? -1 : a.sessionId > b.sessionId ? 1 : 0)),
          }));
          assert.deepEqual(normalizedActual, expectedTargets.targets, ctx(`hyp_plugin_targets mismatch for ${sid}`));
        }

        // 3. Per-session SQLite state, subscriptions, mutes, deliveryMode, unread/unnotified & exact mailbox sets
        for (const sid of sessionIds) {
          const d = daemonFor(sid);
          const status = d.connector.sessionStatus(sid);
          assert.ok(status, ctx(`missing sessionStatus for ${sid}`));
          assert.equal(status.handle, oracle.handleOf(sid), ctx(`handle mismatch for ${sid}`));
          assert.equal(status.address, oracle.addressOf(sid), ctx(`address mismatch for ${sid}`));
          assert.equal(status.deliveryMode, oracle.deliveryModeOf(sid), ctx(`deliveryMode mismatch for ${sid}`));
          assert.equal(status.subscriptions, oracle.subscriptionCount(sid), ctx(`subscriptions count mismatch for ${sid}`));
          assert.equal(status.pending, oracle.pendingCount(sid), ctx(`pending count mismatch for ${sid}`));
          assert.equal(status.unnotified, oracle.unnotifiedCount(sid), ctx(`unnotified count mismatch for ${sid}`));

          const actualMutes = d.connector.listMutes(sid).map((m) => ({
            scope: m.scope === "*" ? ("connector" as const) : ("session" as const),
            pattern: m.pattern,
          }));
          assert.deepEqual(actualMutes, oracle.mutesFor(sid), ctx(`mutes mismatch for ${sid}`));

          const actualSubsRes = (await d.connector.call(sid, "hyp_subscriptions", {})) as {
            subscriptions: Array<{ id: string; key: string; topic: string; router: string; filters: readonly Filter[] }>;
          };
          const actualSubs = actualSubsRes.subscriptions
            .map(({ id, key, topic, router, filters }) => ({ id, key, topic, router, filters }))
            .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
          assert.deepEqual(actualSubs, oracle.subscriptionsOf(sid), ctx(`subscriptions mismatch for ${sid}`));

          const actualMailbox = d.connector.peekMailbox(sid, 100).map((m) => m.text).sort();
          assert.deepEqual(actualMailbox, oracle.mailboxTextsSorted(sid), ctx(`mailbox contents mismatch for ${sid}`));
        }
      };

      const opCounts = new Map<string, number>();
      const bump = (op: string) => opCounts.set(op, (opCounts.get(op) ?? 0) + 1);

      // Forced prefix deterministically covers EVERY operation class + cross-router isolation + plugin fan-in
      type ForcedStep = { readonly op: string; readonly sid?: string; readonly detail?: Record<string, unknown> };
      const forcedPrefix: readonly ForcedStep[] = [
        { op: "hyp_join", sid: "antigravity:alex-ag", detail: { handle: "alex-lead" } },
        { op: "hyp_join", sid: "claude:alex-cl", detail: { handle: "alex-side" } },
        { op: "hyp_join", sid: "codex:alice-cx", detail: { handle: "alice-dev" } },
        { op: "hyp_join", sid: "opencode:alice-oc", detail: { handle: "alice-rev" } },
        { op: "hyp_join", sid: "cursor:jack-cu", detail: { handle: "jack-sre" } },
        { op: "hyp_join", sid: "openclaw:jack-ow", detail: { handle: "jack-db" } },
        // Cross-connector DM on team + cross-router isolation check (alice cannot reach jack!)
        { op: "hyp_send", sid: "antigravity:alex-ag", detail: { to: "alice@laptop/alice-dev" } },
        { op: "hyp_send", sid: "codex:alice-cx", detail: { to: "jack@prod/jack-sre" } }, // MUST fail: unknown_recipient!
        { op: "hyp_send", sid: "cursor:jack-cu", detail: { to: "alex@laptop/alex-lead" } }, // MUST fail: unknown_recipient!
        { op: "hyp_send", sid: "cursor:jack-cu", detail: { to: "jack@prod/jack-db" } },
        // Cross-connector #channel on team + isolated #channel on priv
        { op: "hyp_channel_join", sid: "antigravity:alex-ag", detail: { channel: "#warroom" } },
        { op: "hyp_channel_join", sid: "codex:alice-cx", detail: { channel: "warroom" } },
        { op: "hyp_channel_join", sid: "cursor:jack-cu", detail: { channel: "#warroom" } },
        { op: "hyp_channel_join", sid: "openclaw:jack-ow", detail: { channel: "#warroom" } },
        { op: "hyp_channel_post", sid: "antigravity:alex-ag", detail: { channel: "#warroom" } },
        { op: "hyp_channel_post", sid: "cursor:jack-cu", detail: { channel: "#warroom" } },
        // Multi-router subscriptions: alex subscribes to BOTH team (`deploy`) AND priv (`alerts` via router:"priv")!
        { op: "hyp_subscribe", sid: "antigravity:alex-ag", detail: { key: "team:deploy-all", topic: "deploy", router: "primary", filters: [] } },
        { op: "hyp_subscribe", sid: "codex:alice-cx", detail: { key: "team:deploy-prod", topic: "deploy", router: "primary", filters: [{ exact: { type: "com.acme.deploy.prod" } }] } },
        { op: "hyp_subscribe", sid: "claude:alex-cl", detail: { key: "priv:alerts-all", topic: "alerts", router: "priv", filters: [] } },
        { op: "hyp_subscribe", sid: "cursor:jack-cu", detail: { key: "priv:alerts-crit", topic: "alerts", router: "primary", filters: [{ prefix: { subject: "crit/" } }] } },
        { op: "hyp_subscribe", sid: "codex:alice-cx", detail: { key: "priv:bad-link", topic: "alerts", router: "priv", filters: [] } }, // MUST fail: unknown router
        { op: "publish_event", detail: { routerId: "team", topic: "deploy", type: "com.acme.deploy.prod", subject: "svc/checkout" } },
        { op: "publish_event", detail: { routerId: "priv", topic: "alerts", type: "com.acme.alert.firing", subject: "crit/db-primary" } },
        // Bridge link + fd-3 inbound fan-in + handoff + unlink
        { op: "hyp_bridge_link", sid: "antigravity:alex-ag", detail: { targetSid: "claude:alex-cl" } },
        { op: "plugin_emit" },
        { op: "hyp_plugin_handoff", sid: "antigravity:alex-ag", detail: { targetSid: "claude:alex-cl" } },
        { op: "hyp_bridge_unlink", sid: "claude:alex-cl", detail: { targetSid: "claude:alex-cl" } },
        // Notify mode + digest + idempotency + mutes (topic, plugin, #channel) + inbox
        { op: "hyp_mode", sid: "claude:alex-cl", detail: { mode: "notify" } },
        { op: "plugin_emit" },
        { op: "drainForPush", sid: "claude:alex-cl" },
        { op: "hyp_mute", sid: "claude:alex-cl", detail: { target: "plugin:chat-bridge", scope: "session" } },
        { op: "hyp_mute", sid: "antigravity:alex-ag", detail: { target: "topic:deploy", scope: "connector" } },
        { op: "hyp_mutes", sid: "claude:alex-cl" },
        { op: "hyp_unmute", sid: "claude:alex-cl", detail: { target: "plugin:chat-bridge", scope: "session" } },
        { op: "hyp_unmute", sid: "antigravity:alex-ag", detail: { target: "topic:deploy", scope: "connector" } },
        { op: "hyp_inbox", sid: "antigravity:alex-ag", detail: { mode: "ack1" } },
        { op: "hyp_inbox", sid: "codex:alice-cx", detail: { mode: "all" } },
        { op: "hyp_unsubscribe", sid: "codex:alice-cx", detail: { key: "team:deploy-prod" } },
        { op: "hyp_channel_leave", sid: "openclaw:jack-ow", detail: { channel: "#warroom" } },
        { op: "hyp_leave", sid: "opencode:alice-oc" },
      ];

      const TOTAL_STEPS = 90;

      for (let step = 1; step <= TOTAL_STEPS; step++) {
        const forced = step <= forcedPrefix.length ? forcedPrefix[step - 1] : undefined;
        let op: string;
        if (forced) {
          op = forced.op;
        } else {
          const roll = rng.next();
          if (roll < 0.08) op = "hyp_join";
          else if (roll < 0.13) op = "hyp_leave";
          else if (roll < 0.25) op = "hyp_send";
          else if (roll < 0.32) op = "hyp_channel_join";
          else if (roll < 0.40) op = "hyp_channel_post";
          else if (roll < 0.45) op = "hyp_channel_leave";
          else if (roll < 0.53) op = "hyp_subscribe";
          else if (roll < 0.58) op = "hyp_unsubscribe";
          else if (roll < 0.67) op = "publish_event";
          else if (roll < 0.72) op = "hyp_bridge_link";
          else if (roll < 0.76) op = "hyp_bridge_unlink";
          else if (roll < 0.80) op = "hyp_plugin_handoff";
          else if (roll < 0.86) op = "plugin_emit";
          else if (roll < 0.90) op = "hyp_mute";
          else if (roll < 0.93) op = "hyp_unmute";
          else if (roll < 0.96) op = "hyp_mode";
          else if (roll < 0.985) op = "hyp_inbox";
          else op = "drainForPush";
        }

        // Guard: plugin_emit requires at least one recipient on alex@laptop so LocalEvents doesn't hold for 30s
        if (op === "plugin_emit" && oracle.bridgeRecipients("alex@laptop").length === 0) {
          op = "hyp_bridge_link";
        }

        let sid = forced?.sid ?? rng.pick(sessionIds);
        if (!forced) {
          if (op === "hyp_bridge_link" || op === "hyp_bridge_unlink" || op === "hyp_plugin_handoff") {
            sid = rng.bool(0.85) ? rng.pick(["antigravity:alex-ag", "claude:alex-cl"]) : rng.pick(sessionIds);
          } else if (op === "hyp_inbox" || op === "drainForPush") {
            const nonEmpty = sessionIds.filter((id) => oracle.pendingCount(id) > 0);
            if (nonEmpty.length > 0 && rng.bool(0.85)) sid = rng.pick(nonEmpty);
          } else if (op === "hyp_send" || op === "hyp_channel_post") {
            const enrolled = sessionIds.filter((id) => oracle.handleOf(id) !== null);
            if (enrolled.length > 0 && rng.bool(0.85)) sid = rng.pick(enrolled);
          }
        }

        bump(op);
        let needsQuiescence = false;

        switch (op) {
          case "hyp_join": {
            const cid = oracle.connectorOf(sid);
            const handle = (forced?.detail?.handle as string | undefined) ?? rng.pick(handlePools[cid]!);
            history.push(`#${step} ${sid} hyp_join(${handle})`);
            const expected = oracle.join(sid, handle);
            if (expected.ok) {
              const actual = (await daemonFor(sid).connector.call(sid, "hyp_join", { handle })) as { address: string };
              assert.equal(actual.address, expected.address, formatFailureContext(seed, history, "hyp_join mismatch"));
            } else {
              await assert.rejects(
                () => daemonFor(sid).connector.call(sid, "hyp_join", { handle }),
                (err: unknown) => err instanceof RouterError && err.code === expected.code,
                formatFailureContext(seed, history, `hyp_join expected RouterError(${expected.code})`),
              );
            }
            break;
          }

          case "hyp_leave": {
            history.push(`#${step} ${sid} hyp_leave()`);
            const expected = oracle.leave(sid);
            const actual = (await daemonFor(sid).connector.call(sid, "hyp_leave", {})) as { left: boolean };
            assert.equal(actual.left, expected.left, formatFailureContext(seed, history, "hyp_leave mismatch"));
            break;
          }

          case "hyp_send": {
            let to = forced?.detail?.to as string | undefined;
            if (!to) {
              const senderRouter = oracle.primaryRouterOf(oracle.connectorOf(sid));
              const sameRouterPeers = oracle.peersOnRouter(senderRouter);
              const otherRouterPeers = oracle.peersOnRouter(senderRouter === "team" ? "priv" : "team");
              if (sameRouterPeers.length > 0 && rng.bool(0.75)) {
                to = rng.pick(sameRouterPeers).address;
              } else if (otherRouterPeers.length > 0 && rng.bool(0.6)) {
                // Deliberate cross-router isolation probe
                to = rng.pick(otherRouterPeers).address;
              } else {
                const targetConn = rng.pick(["alex@laptop", "alice@laptop", "jack@prod"]);
                to = `${targetConn}/${rng.pick(handlePools[targetConn]!)}`;
              }
            }
            const text = `dm-step-${step}-n${rng.int(1000)}`;
            history.push(`#${step} ${sid} hyp_send(${to}, "${text}")`);
            const expected = oracle.send(sid, to, text);
            if (expected.ok) {
              const actual = (await daemonFor(sid).connector.call(sid, "hyp_send", { to, text })) as { status: string; messageId: string };
              assert.equal(actual.status, "stored", formatFailureContext(seed, history, "hyp_send status mismatch"));
              assert.equal(typeof actual.messageId, "string");
              needsQuiescence = true;
            } else {
              await assert.rejects(
                () => daemonFor(sid).connector.call(sid, "hyp_send", { to, text }),
                (err: unknown) => err instanceof RouterError && err.code === expected.code,
                formatFailureContext(seed, history, `hyp_send expected RouterError(${expected.code})`),
              );
            }
            break;
          }

          case "hyp_channel_join": {
            const rawChannel = (forced?.detail?.channel as string | undefined) ??
              (rng.bool(0.5) ? rng.pick(channelPool) : rng.pick(channelPool).slice(1));
            history.push(`#${step} ${sid} hyp_channel_join(${rawChannel})`);
            const expected = oracle.channelJoin(sid, rawChannel);
            if (expected.ok) {
              const actual = (await daemonFor(sid).connector.call(sid, "hyp_channel_join", { channel: rawChannel })) as {
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
                () => daemonFor(sid).connector.call(sid, "hyp_channel_join", { channel: rawChannel }),
                (err: unknown) => err instanceof RouterError && err.code === expected.code,
                formatFailureContext(seed, history, `hyp_channel_join expected RouterError(${expected.code})`),
              );
            }
            break;
          }

          case "hyp_channel_leave": {
            const channel = (forced?.detail?.channel as string | undefined) ?? rng.pick(channelPool);
            history.push(`#${step} ${sid} hyp_channel_leave(${channel})`);
            const expected = oracle.channelLeave(sid, channel);
            if (expected.ok) {
              const actual = (await daemonFor(sid).connector.call(sid, "hyp_channel_leave", { channel })) as {
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
                () => daemonFor(sid).connector.call(sid, "hyp_channel_leave", { channel }),
                (err: unknown) => err instanceof RouterError && err.code === expected.code,
                formatFailureContext(seed, history, `hyp_channel_leave expected RouterError(${expected.code})`),
              );
            }
            break;
          }

          case "hyp_channel_post": {
            const routerId = oracle.primaryRouterOf(oracle.connectorOf(sid));
            const addr = oracle.addressOf(sid);
            const myChannels = addr
              ? oracle.channelsOnRouter(routerId).filter((c) => c.members.includes(addr)).map((c) => c.channel)
              : [];
            const channel = (forced?.detail?.channel as string | undefined) ??
              (myChannels.length > 0 && rng.bool(0.8) ? rng.pick(myChannels) : rng.pick(channelPool));
            const text = `ch-step-${step}-n${rng.int(1000)}`;
            history.push(`#${step} ${sid} hyp_channel_post(${channel}, "${text}")`);
            const expected = oracle.channelPost(sid, channel, text);
            if (expected.ok) {
              const actual = (await daemonFor(sid).connector.call(sid, "hyp_channel_post", { channel, text })) as {
                channel: string;
                deliveredTo: string[];
                failed: unknown[];
              };
              assert.equal(actual.channel, expected.channel, formatFailureContext(seed, history, "hyp_channel_post channel mismatch"));
              assert.deepEqual(actual.deliveredTo, expected.deliveredTo, formatFailureContext(seed, history, "hyp_channel_post deliveredTo mismatch"));
              assert.deepEqual(actual.failed, [], formatFailureContext(seed, history, "hyp_channel_post failed non-empty"));
              if (expected.deliveredTo.length > 0) needsQuiescence = true;
            } else {
              await assert.rejects(
                () => daemonFor(sid).connector.call(sid, "hyp_channel_post", { channel, text }),
                (err: unknown) => err instanceof RouterError && err.code === expected.code,
                formatFailureContext(seed, history, `hyp_channel_post expected RouterError(${expected.code})`),
              );
            }
            break;
          }

          case "hyp_subscribe": {
            const cid = oracle.connectorOf(sid);
            let key: string;
            let topic: string;
            let routerLink: string;
            let filters: readonly Filter[];
            if (forced?.detail) {
              key = forced.detail.key as string;
              topic = forced.detail.topic as string;
              routerLink = forced.detail.router as string;
              filters = forced.detail.filters as readonly Filter[];
            } else {
              const usePrivOnAlex = cid === "alex@laptop" && rng.bool(0.5);
              if (cid === "jack@prod" || usePrivOnAlex) {
                routerLink = cid === "alex@laptop" ? "priv" : "primary";
                topic = rng.bool(0.9) ? "alerts" : "nonexistent";
                key = rng.pick(privSubKeys);
                filters = rng.pick<readonly Filter[]>([
                  [],
                  [{ prefix: { subject: "crit/" } }],
                  [{ exact: { type: "com.acme.alert.firing" } }],
                ]);
              } else {
                routerLink = rng.bool(0.92) ? "primary" : "priv";
                topic = rng.bool(0.9) ? "deploy" : "alerts";
                key = rng.pick(teamSubKeys);
                filters = rng.pick<readonly Filter[]>([
                  [],
                  [{ exact: { type: "com.acme.deploy.prod" } }],
                  [{ prefix: { subject: "svc/" } }],
                ]);
              }
            }
            history.push(`#${step} ${sid} hyp_subscribe(key=${key}, router=${routerLink}, topic=${topic})`);
            const check = oracle.checkSubscribe(sid, key, topic, routerLink, filters);
            if (check.ok) {
              const actual = (await daemonFor(sid).connector.call(sid, "hyp_subscribe", {
                key,
                topic,
                router: routerLink,
                filters,
                coalesceSeconds: 0,
              })) as { id: string; outcome: string };
              assert.equal(actual.outcome, check.outcome, formatFailureContext(seed, history, "hyp_subscribe outcome mismatch"));
              if (check.existingId) {
                assert.equal(actual.id, check.existingId, formatFailureContext(seed, history, "hyp_subscribe id changed unexpectedly"));
              }
              oracle.commitSubscribe(sid, {
                id: actual.id,
                key,
                topic,
                routerLink,
                routerId: check.routerId,
                filters,
              });
            } else {
              await assert.rejects(
                () => daemonFor(sid).connector.call(sid, "hyp_subscribe", {
                  key,
                  topic,
                  router: routerLink,
                  filters,
                  coalesceSeconds: 0,
                }),
                (err: unknown) => err instanceof RouterError && err.code === check.code,
                formatFailureContext(seed, history, `hyp_subscribe expected RouterError(${check.code})`),
              );
            }
            break;
          }

          case "hyp_unsubscribe": {
            const existing = oracle.subscriptionsOf(sid);
            const key = (forced?.detail?.key as string | undefined) ??
              (existing.length > 0 && rng.bool(0.8) ? rng.pick(existing).key : rng.pick([...teamSubKeys, ...privSubKeys]));
            history.push(`#${step} ${sid} hyp_unsubscribe(${key})`);
            const expected = oracle.unsubscribe(sid, key);
            const actual = (await daemonFor(sid).connector.call(sid, "hyp_unsubscribe", { key })) as { removed: boolean };
            assert.equal(actual.removed, expected.removed, formatFailureContext(seed, history, "hyp_unsubscribe mismatch"));
            break;
          }

          case "publish_event": {
            const routerId: RouterId = (forced?.detail?.routerId as RouterId | undefined) ?? (rng.bool(0.5) ? "team" : "priv");
            const topic = (forced?.detail?.topic as string | undefined) ?? (routerId === "team" ? "deploy" : "alerts");
            const type = (forced?.detail?.type as string | undefined) ??
              (routerId === "team"
                ? rng.pick(["com.acme.deploy.prod", "com.acme.deploy.staging"])
                : rng.pick(["com.acme.alert.firing", "com.acme.alert.resolved"]));
            const subject = (forced?.detail?.subject as string | undefined) ??
              (routerId === "team"
                ? rng.pick(["svc/checkout", "svc/auth", "batch/nightly"])
                : rng.pick(["crit/db-primary", "warn/cache-hit"]));
            const event: CloudEvent = {
              specversion: "1.0",
              id: `ev-step-${step}-${rng.int(10_000)}`,
              source: routerId === "team" ? "ci/acme" : "ops/prod",
              type,
              subject,
              time: "2026-11-24T12:00:00Z",
              datacontenttype: "application/json",
              data: { step, routerId, topic, seq: rng.int(1000) },
            };
            history.push(`#${step} publish_event(${routerId}/${topic}, type=${type}, subject=${subject})`);
            const expected = oracle.publishEvent(routerId, topic, event);
            const actual = await publishToRouter(routerId, topic, event);
            assert.equal(actual.status, 202, formatFailureContext(seed, history, "publish_event HTTP status mismatch"));
            assert.equal(actual.matched, expected.matched, formatFailureContext(seed, history, "publish_event matched count mismatch"));
            if (expected.matched > 0) needsQuiescence = true;
            break;
          }

          case "hyp_bridge_link": {
            const targetSid = (forced?.detail?.targetSid as string | undefined) ??
              rng.pick(["antigravity:alex-ag", "claude:alex-cl"]);
            history.push(`#${step} ${sid} hyp_bridge_link(${targetSid})`);
            const expected = oracle.bridgeLink(sid, targetSid);
            if (expected.ok) {
              const actual = (await daemonFor(sid).connector.call(sid, "hyp_bridge_link", {
                plugin: "chat-bridge",
                target: "inbox",
                sessionId: targetSid,
              })) as { sessionId: string; handle: string | null; linkedSessions: Array<{ sessionId: string; handle: string | null }> };
              assert.equal(actual.sessionId, expected.sessionId, formatFailureContext(seed, history, "hyp_bridge_link sessionId mismatch"));
              assert.equal(actual.handle, expected.handle, formatFailureContext(seed, history, "hyp_bridge_link handle mismatch"));
              const sortedActual = [...actual.linkedSessions].sort((a, b) => (a.sessionId < b.sessionId ? -1 : a.sessionId > b.sessionId ? 1 : 0));
              assert.deepEqual(sortedActual, expected.linkedSessions, formatFailureContext(seed, history, "hyp_bridge_link linkedSessions mismatch"));
            } else {
              await assert.rejects(
                () => daemonFor(sid).connector.call(sid, "hyp_bridge_link", {
                  plugin: "chat-bridge",
                  target: "inbox",
                  sessionId: targetSid,
                }),
                (err: unknown) => err instanceof RouterError && err.code === expected.code,
                formatFailureContext(seed, history, `hyp_bridge_link expected RouterError(${expected.code})`),
              );
            }
            break;
          }

          case "hyp_bridge_unlink": {
            const unlinkAll = !forced?.detail && rng.bool(0.35);
            const targetSid = (forced?.detail?.targetSid as string | undefined) ??
              rng.pick(["antigravity:alex-ag", "claude:alex-cl"]);
            history.push(`#${step} ${sid} hyp_bridge_unlink(${unlinkAll ? "all=true" : targetSid})`);
            const expected = oracle.bridgeUnlink(sid, unlinkAll ? { all: true } : { targetSid });
            const args = unlinkAll
              ? { plugin: "chat-bridge", target: "inbox", all: true }
              : { plugin: "chat-bridge", target: "inbox", sessionId: targetSid };
            if (expected.ok) {
              const actual = (await daemonFor(sid).connector.call(sid, "hyp_bridge_unlink", args)) as {
                removed: boolean;
                removedCount: number;
                linkedSessions: Array<{ sessionId: string; handle: string | null }>;
              };
              assert.equal(actual.removed, expected.removed, formatFailureContext(seed, history, "hyp_bridge_unlink removed mismatch"));
              assert.equal(actual.removedCount, expected.removedCount, formatFailureContext(seed, history, "hyp_bridge_unlink removedCount mismatch"));
              const sortedActual = [...actual.linkedSessions].sort((a, b) => (a.sessionId < b.sessionId ? -1 : a.sessionId > b.sessionId ? 1 : 0));
              assert.deepEqual(sortedActual, expected.linkedSessions, formatFailureContext(seed, history, "hyp_bridge_unlink linkedSessions mismatch"));
            } else {
              await assert.rejects(
                () => daemonFor(sid).connector.call(sid, "hyp_bridge_unlink", args),
                (err: unknown) => err instanceof RouterError && err.code === expected.code,
                formatFailureContext(seed, history, `hyp_bridge_unlink expected RouterError(${expected.code})`),
              );
            }
            break;
          }

          case "hyp_plugin_handoff": {
            const targetSid = (forced?.detail?.targetSid as string | undefined) ??
              rng.pick(["antigravity:alex-ag", "claude:alex-cl"]);
            history.push(`#${step} ${sid} hyp_plugin_handoff(${targetSid})`);
            const expected = oracle.pluginHandoff(sid, targetSid);
            if (expected.ok) {
              const actual = (await daemonFor(sid).connector.call(sid, "hyp_plugin_handoff", {
                plugin: "chat-bridge",
                target: "inbox",
                sessionId: targetSid,
              })) as { plugin: string; target: string; sessionId: string };
              assert.deepEqual(actual, { plugin: expected.plugin, target: expected.target, sessionId: expected.sessionId }, formatFailureContext(seed, history, "hyp_plugin_handoff mismatch"));
            } else {
              await assert.rejects(
                () => daemonFor(sid).connector.call(sid, "hyp_plugin_handoff", {
                  plugin: "chat-bridge",
                  target: "inbox",
                  sessionId: targetSid,
                }),
                (err: unknown) => err instanceof RouterError && err.code === expected.code,
                formatFailureContext(seed, history, `hyp_plugin_handoff expected RouterError(${expected.code})`),
              );
            }
            break;
          }

          case "plugin_emit": {
            const event: CloudEvent = {
              specversion: "1.0",
              id: `bridge-step-${step}-${rng.int(10_000)}`,
              source: "chat/room-ops",
              type: "com.chat.message.created",
              subject: `thread-${step}`,
              time: "2026-11-24T12:00:00Z",
              datacontenttype: "application/json",
              data: { step, author: "human", text: `chat-msg-${step}` },
            };
            history.push(`#${step} plugin_emit(chat-bridge/inbox, id=${event.id})`);
            oracle.emitPluginEvent("alex@laptop", event);
            const emitRes = await fetch(`http://127.0.0.1:${bridgePort}/emit`, {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({ to: "inbox", event }),
            });
            assert.equal(emitRes.status, 200, formatFailureContext(seed, history, "plugin_emit HTTP status mismatch"));
            const reply = (await emitRes.json()) as { type: string; status?: string };
            assert.equal(reply.type, "ack", formatFailureContext(seed, history, `plugin_emit expected fd-3 ack, got ${JSON.stringify(reply)}`));
            assert.equal(reply.status, "stored");
            needsQuiescence = true;
            break;
          }

          case "hyp_mute": {
            const scope: "connector" | "session" = (forced?.detail?.scope as "connector" | "session" | undefined) ??
              (rng.bool(0.55) ? "session" : "connector");
            let target = forced?.detail?.target as string | undefined;
            if (!target) {
              const kind = rng.next();
              if (kind < 0.25) {
                const c = rng.pick(["alex@laptop", "alice@laptop", "jack@prod"]);
                target = `${c}/${rng.pick(handlePools[c]!)}`;
              } else if (kind < 0.40) {
                target = `${rng.pick(["alex@laptop", "alice@laptop", "jack@prod"])}/*`;
              } else if (kind < 0.60) {
                target = rng.pick(channelPool);
              } else if (kind < 0.80) {
                target = rng.pick(["topic:deploy", "topic:alerts"]);
              } else {
                target = "plugin:chat-bridge";
              }
            }
            history.push(`#${step} ${sid} hyp_mute(${target}, scope=${scope})`);
            const expected = oracle.mute(sid, target, scope);
            const actual = (await daemonFor(sid).connector.call(
              sid,
              "hyp_mute",
              scope === "session" ? { target, scope: "session" } : { target },
            )) as { muted: string; scope: string };
            assert.deepEqual(actual, expected, formatFailureContext(seed, history, "hyp_mute mismatch"));
            break;
          }

          case "hyp_unmute": {
            const existing = oracle.mutesFor(sid);
            let target = forced?.detail?.target as string | undefined;
            let scope = forced?.detail?.scope as "connector" | "session" | undefined;
            if (!target) {
              if (existing.length > 0 && rng.bool(0.8)) {
                const chosen = rng.pick(existing);
                target = chosen.pattern;
                scope = chosen.scope;
              } else {
                target = rng.pick(["#warroom", "topic:deploy", "plugin:chat-bridge", "alex@laptop/*"]);
                scope = rng.bool(0.5) ? "session" : "connector";
              }
            }
            scope ??= "connector";
            history.push(`#${step} ${sid} hyp_unmute(${target}, scope=${scope})`);
            const expected = oracle.unmute(sid, target, scope);
            const actual = (await daemonFor(sid).connector.call(
              sid,
              "hyp_unmute",
              scope === "session" ? { target, scope: "session" } : { target },
            )) as { pattern: string; scope: string; removed: boolean };
            assert.deepEqual(actual, expected, formatFailureContext(seed, history, "hyp_unmute mismatch"));
            break;
          }

          case "hyp_mutes": {
            history.push(`#${step} ${sid} hyp_mutes()`);
            const actual = (await daemonFor(sid).connector.call(sid, "hyp_mutes", {})) as {
              mutes: Array<{ pattern: string; scope: "connector" | "session" }>;
            };
            const normalized = actual.mutes.map((m) => ({ scope: m.scope, pattern: m.pattern }));
            assert.deepEqual(normalized, oracle.mutesFor(sid), formatFailureContext(seed, history, "hyp_mutes mismatch"));
            break;
          }

          case "hyp_mode": {
            const mode: DeliveryMode = (forced?.detail?.mode as DeliveryMode | undefined) ??
              (oracle.deliveryModeOf(sid) === "full" ? "notify" : "full");
            history.push(`#${step} ${sid} hyp_mode(${mode})`);
            const expected = oracle.setMode(sid, mode);
            const actual = (await daemonFor(sid).connector.call(sid, "hyp_mode", { mode })) as {
              deliveryMode: DeliveryMode;
              unread: number;
            };
            assert.deepEqual(actual, expected, formatFailureContext(seed, history, "hyp_mode mismatch"));
            break;
          }

          case "hyp_inbox": {
            const subMode = (forced?.detail?.mode as string | undefined) ??
              (rng.next() < 0.45 ? "all" : rng.next() < 0.75 ? "ack1" : "peek");
            if (subMode === "all") {
              history.push(`#${step} ${sid} hyp_inbox(acknowledgeAll=true)`);
              const expected = oracle.inboxAcknowledgeAll(sid);
              const actual = (await daemonFor(sid).connector.call(sid, "hyp_inbox", { acknowledgeAll: true, limit: 50 })) as {
                deliveryMode: DeliveryMode;
                unread: number;
                items: Array<{ text: string; receipt: string }>;
              };
              assert.equal(actual.deliveryMode, expected.deliveryMode, formatFailureContext(seed, history, "hyp_inbox(all) deliveryMode"));
              assert.equal(actual.unread, expected.unread, formatFailureContext(seed, history, "hyp_inbox(all) unread"));
              assert.deepEqual(actual.items.map((i) => i.text).sort(), expected.drainedTexts, formatFailureContext(seed, history, "hyp_inbox(all) items"));
            } else if (subMode === "ack1" && oracle.pendingCount(sid) > 0) {
              const peeked = daemonFor(sid).connector.peekMailbox(sid, 50);
              const chosen = peeked[0]!;
              history.push(`#${step} ${sid} hyp_inbox(acknowledge=[1])`);
              const expected = oracle.inboxPeek(sid, [chosen.text]);
              const actual = (await daemonFor(sid).connector.call(sid, "hyp_inbox", { acknowledge: [chosen.receipt], limit: 50 })) as {
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
              const actual = (await daemonFor(sid).connector.call(sid, "hyp_inbox", { limit: 50 })) as {
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
            const actual = daemonFor(sid).connector.drainForPush(sid, 100);
            if (expected.mode === "full") {
              assert.deepEqual(actual.map((i) => i.text).sort(), expected.drainedTexts, formatFailureContext(seed, history, "drainForPush(full) mismatch"));
            } else if (expected.expectedDigest === null) {
              assert.deepEqual(actual, [], formatFailureContext(seed, history, "drainForPush(notify empty) expected []"));
            } else {
              assert.equal(actual.length, 1, formatFailureContext(seed, history, "drainForPush(notify) expected 1 digest item"));
              const digestText = actual[0]!.text;
              assert.match(
                digestText,
                new RegExp(`^hyphae notice · ${expected.expectedDigest.unread} unread`),
                formatFailureContext(seed, history, "drainForPush(notify) unread count mismatch"),
              );
              if (expected.expectedDigest.messages > 0) {
                assert.match(digestText, new RegExp(`${expected.expectedDigest.messages} message`));
              }
              if (expected.expectedDigest.events > 0) {
                assert.match(digestText, new RegExp(`${expected.expectedDigest.events} event`));
              }
              if (expected.expectedDigest.plugins > 0) {
                assert.match(digestText, new RegExp(`${expected.expectedDigest.plugins} bridge item`));
              }
              if (expected.expectedDigest.distinctSources.length <= 4) {
                for (const src of expected.expectedDigest.distinctSources) {
                  assert.ok(digestText.includes(src), formatFailureContext(seed, history, `digest missing source "${src}": ${digestText}`));
                }
              }
              // Verify idempotency: immediate second drainForPush in notify mode MUST return []
              const repeat = daemonFor(sid).connector.drainForPush(sid, 100);
              assert.deepEqual(repeat, [], formatFailureContext(seed, history, "drainForPush(notify) was not idempotent"));
            }
            break;
          }
        }

        if (needsQuiescence) {
          await waitForMultiNodeQuiescence(allReadDbs, allDaemons);
        }
        await verifyFullEquivalence(step);
      }

      // Confirm every single operation class executed
      for (const requiredOp of [
        "hyp_join", "hyp_leave", "hyp_send",
        "hyp_channel_join", "hyp_channel_post", "hyp_channel_leave",
        "hyp_subscribe", "hyp_unsubscribe", "publish_event",
        "hyp_bridge_link", "hyp_bridge_unlink", "hyp_plugin_handoff", "plugin_emit",
        "hyp_mute", "hyp_unmute", "hyp_mutes",
        "hyp_mode", "hyp_inbox", "drainForPush",
      ]) {
        assert.ok((opCounts.get(requiredOp) ?? 0) > 0, `Operation ${requiredOp} was never exercised`);
      }
    } finally {
      try { teamReadDb?.close(); } catch {}
      try { privReadDb?.close(); } catch {}
      try { pluginLocalDb?.close(); } catch {}
      await Promise.all([
        alexDaemon?.stop().catch(() => {}),
        aliceDaemon?.stop().catch(() => {}),
        jackDaemon?.stop().catch(() => {}),
      ]);
      await teamRouter?.close().catch(() => {});
      await privRouter?.close().catch(() => {});
      try { teamCore.close(); } catch {}
      try { privCore.close(); } catch {}
      rmSync(rootDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  },
);

// ============================================================================
// TEST 2 — Level 1–2 Framing, Lexical & Boundary Perturbation Resilience
// ============================================================================

/**
 * Sends a raw HTTP POST using `node:http` so early server rejections (e.g. HTTP 413 with
 * `Connection: close` before reading a huge body) still deliver the 413 response cleanly
 * instead of tripping Undici `fetch` EPIPE races while writing the oversized request stream.
 */
function httpPostRaw(
  url: string,
  headers: Readonly<Record<string, string>>,
  body: string | Buffer,
  options: { readonly declaredContentLength?: number } = {},
): Promise<{ readonly status: number; readonly body: string }> {
  return new Promise((resolve, reject) => {
    const raw = Buffer.isBuffer(body) ? body : Buffer.from(body, "utf8");
    const contentLength = options.declaredContentLength ?? raw.length;
    let settled = false;
    const finish = (value: { readonly status: number; readonly body: string }) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(value);
    };
    const fail = (err: unknown) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      reject(err);
    };
    const req = httpRequest(
      url,
      {
        method: "POST",
        headers: { ...headers, "content-length": String(contentLength) },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => finish({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
        res.on("close", () => finish({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
        res.on("error", () => finish({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
      },
    );
    const timer = setTimeout(() => {
      req.destroy();
      fail(new Error(`httpPostRaw timed out for ${url}`));
    }, 5_000).unref();
    req.on("error", (err) => {
      // If response already arrived, ignore write-side EPIPE/ECONNRESET from early server close
      if (!settled) fail(err);
    });
    if (options.declaredContentLength !== undefined) {
      // Send only headers + small prefix when testing early Content-Length rejection so the server
      // rejects with 413 immediately without racing a multi-megabyte TCP buffer write.
      req.write(raw);
    } else {
      req.end(raw);
    }
  });
}

function sendRawSocketBytes(
  socketPath: string,
  payloads: ReadonlyArray<Buffer | string>,
  opts: { readonly abruptDestroyAfterMs?: number } = {},
): Promise<{ readonly data: string; readonly closed: boolean }> {
  return new Promise((resolve) => {
    const sock = createConnection(socketPath);
    const chunks: Buffer[] = [];
    let settled = false;
    const finish = (closed: boolean) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve({ data: Buffer.concat(chunks).toString("utf8"), closed });
    };
    const timer = setTimeout(() => {
      sock.destroy();
      finish(false);
    }, 3_000).unref();

    sock.on("data", (d: Buffer) => chunks.push(d));
    sock.on("close", () => finish(true));
    sock.on("error", () => finish(true));
    sock.on("connect", () => {
      for (const p of payloads) {
        if (!sock.destroyed) sock.write(p);
      }
      if (opts.abruptDestroyAfterMs !== undefined) {
        setTimeout(() => sock.destroy(), opts.abruptDestroyAfterMs).unref();
      }
    });
  });
}

test(
  "differential e2e (Levels 1–2): framing, lexical & boundary perturbations across fd-3 plugin, Unix daemon socket, router /v1/events, github-webhook & webhook bridge",
  { timeout: 30_000 },
  async () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => { unhandled.push(reason); };
    process.on("unhandledRejection", onUnhandled);

    const rootDir = mkdtempSync(join(tmpdir(), "hi-fuzz-"));
    const routerDbPath = join(rootDir, "router.sqlite");
    const routerCore = new RouterCore({
      dbPath: routerDbPath,
      topics: new Map([
        ["deploy", ["pub-deploy"]],
        ["github", ["pub-github"]],
      ]),
      limits: { ...DEFAULT_LIMITS, maxPerHourPerRecipient: 10_000 },
      eventLimits: { ...DEFAULT_EVENT_LIMITS, maxBatchesPerHourPerSubscription: 10_000 },
    });
    const deployPubToken = routerCore.events.addPublisher("pub-deploy", ["deploy"]);
    const githubPubToken = routerCore.events.addPublisher("pub-github", ["github"]);
    const connToken = routerCore.addConnector("fuzz@local");

    let router: RunningRouter | undefined;
    let ghReceiver: Awaited<ReturnType<typeof serveReceiver>> | undefined;
    let daemon: RunningDaemon | undefined;

    try {
      router = await serveRouter({ core: routerCore, host: "127.0.0.1", port: 0 });
      const ghSecret = "fuzz-github-hmac-secret-01";
      ghReceiver = await serveReceiver({
        host: "127.0.0.1",
        port: 0,
        routerUrl: router.url,
        topic: "github",
        secret: ghSecret,
        token: githubPubToken,
        limits: DEFAULT_RECEIVER_LIMITS,
      });

      // Raw controllable fd-3 plugin script capable of writing arbitrary/oversized/malformed/fragmented bytes
      const ctrlPort = await freePort();
      const webhookPort = await freePort();
      const webhookSecret = "fuzz-webhook-hmac-secret-02";
      const fuzzPluginScript = join(rootDir, "raw-fd3-plugin.mjs");
      writeFileSync(
        fuzzPluginScript,
        [
          `import { createReadStream, createWriteStream } from "node:fs";`,
          `import { createServer } from "node:http";`,
          `import { createInterface } from "node:readline";`,
          `const fd = Number(process.env.T3_MESH_FD ?? process.env.AGENTS_MESH_FD ?? 3);`,
          `const out = createWriteStream("", { fd, autoClose: false });`,
          `const input = createReadStream("", { fd, autoClose: false });`,
          `const rl = createInterface({ input });`,
          `let helloMsg = null;`,
          `const waiters = [];`,
          `const queued = [];`,
          `rl.on("line", (line) => {`,
          `  if (!line.trim()) return;`,
          `  const parsed = JSON.parse(line);`,
          `  if (!helloMsg && parsed.type === "hello") { helloMsg = parsed; return; }`,
          `  if (waiters.length > 0) waiters.shift()(parsed);`,
          `  else queued.push(parsed);`,
          `});`,
          `const nextReply = (timeoutMs = 5000) => {`,
          `  if (queued.length > 0) return Promise.resolve(queued.shift());`,
          `  return new Promise((resolve, reject) => {`,
          `    const t = setTimeout(() => reject(new Error("fd3 reply timeout")), timeoutMs);`,
          `    waiters.push((msg) => { clearTimeout(t); resolve(msg); });`,
          `  });`,
          `};`,
          `const port = Number(process.env.CTRL_PORT);`,
          `createServer(async (req, res) => {`,
          `  if (req.method === "GET" && req.url === "/health") {`,
          `    res.writeHead(helloMsg ? 200 : 503, { "content-type": "application/json" });`,
          `    res.end(JSON.stringify({ ok: Boolean(helloMsg), hello: helloMsg }));`,
          `    return;`,
          `  }`,
          `  if (req.method === "POST" && req.url === "/raw") {`,
          `    const bufs = [];`,
          `    for await (const c of req) bufs.push(c);`,
          `    const body = JSON.parse(Buffer.concat(bufs).toString("utf8"));`,
          `    const replyPromise = body.expectReply !== false ? nextReply() : Promise.resolve(null);`,
          `    for (const part of body.chunks) {`,
          `      out.write(part.data);`,
          `      if (part.delayMs) await new Promise((r) => setTimeout(r, part.delayMs));`,
          `    }`,
          `    const reply = await replyPromise;`,
          `    res.writeHead(200, { "content-type": "application/json" });`,
          `    res.end(JSON.stringify({ reply }));`,
          `    return;`,
          `  }`,
          `  res.writeHead(404).end();`,
          `}).listen(port, "127.0.0.1");`,
        ].join("\n") + "\n",
        "utf8",
      );

      // Write config using loadConfig so built-in `webhook` plugin and custom raw fd-3 plugin both launch
      const cfgDir = join(rootDir, "cfg");
      mkdirSync(join(cfgDir, "s"), { recursive: true, mode: 0o700 });
      const tokFile = join(cfgDir, "primary.token");
      writeFileSync(tokFile, `${connToken}\n`, { mode: 0o600 });
      chmodSync(tokFile, 0o600);
      const cfgPath = join(cfgDir, "connector.json");
      writeFileSync(
        cfgPath,
        JSON.stringify({
          connectorId: "fuzz@local",
          stateDir: "s",
          routers: [{ name: "primary", url: router.url, tokenFile: "primary.token" }],
          plugins: [
            {
              name: "fuzz-fd3",
              exec: process.execPath,
              args: [fuzzPluginScript],
              env: { CTRL_PORT: String(ctrlPort) },
              cwd: rootDir,
              targets: [{ name: "inbox", handle: "fd3-recv", coalesceSeconds: 0, maxWaitSeconds: 1, wakesPerHour: 3600 }],
            },
            {
              name: "hook-bridge",
              builtin: "webhook",
              env: {
                WEBHOOK_HOST: "127.0.0.1",
                WEBHOOK_PORT: String(webhookPort),
                WEBHOOK_PATH: "/hook",
                WEBHOOK_TARGET: "alerts",
                WEBHOOK_SECRET: webhookSecret,
              },
              targets: [{ name: "alerts", handle: "hook-recv", coalesceSeconds: 0, maxWaitSeconds: 1, wakesPerHour: 3600 }],
            },
          ],
        }, null, 2),
        { mode: 0o600 },
      );
      chmodSync(cfgPath, 0o600);

      daemon = await startDaemon(loadConfig(cfgPath), { quiet: true });

      // Register sessions for fd-3 plugin, router topics, and webhook bridge
      daemon.state.register("claude:fd3", { kind: "claude" });
      daemon.state.register("codex:router-sub", { kind: "codex" });
      daemon.state.register("cursor:hook", { kind: "cursor" });
      await daemon.connector.call("claude:fd3", "hyp_join", { handle: "fd3-recv" });
      await daemon.connector.call("codex:router-sub", "hyp_join", { handle: "router-recv" });
      await daemon.connector.call("cursor:hook", "hyp_join", { handle: "hook-recv" });

      await daemon.connector.call("codex:router-sub", "hyp_subscribe", {
        key: "fuzz:deploy",
        topic: "deploy",
        filters: [],
        coalesceSeconds: 0,
      });
      await daemon.connector.call("codex:router-sub", "hyp_subscribe", {
        key: "fuzz:github",
        topic: "github",
        filters: [{ exact: { repo: "acme/fuzz" } }],
        coalesceSeconds: 0,
      });

      await Promise.all([
        waitForConnectorsOnline(routerCore, ["fuzz@local"]),
        waitFor(async () => {
          const res = await fetch(`http://127.0.0.1:${ctrlPort}/health`).catch(() => null);
          return res?.ok ? true : false;
        }, { timeoutMs: 8_000, intervalMs: 30, label: "raw fd-3 fuzz plugin ready" }),
      ]);

      const sendFd3Raw = async (chunks: ReadonlyArray<{ readonly data: string; readonly delayMs?: number }>) => {
        const res = await fetch(`http://127.0.0.1:${ctrlPort}/raw`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ chunks, expectReply: true }),
        });
        assert.equal(res.status, 200);
        return (await res.json()) as { reply: Record<string, unknown> };
      };

      // ---- PART A: fd-3 Plugin Protocol Framing Perturbations ----

      // A1. Valid CloudEvent -> ack & delivered
      const validEv1 = {
        specversion: "1.0",
        id: "fd3-valid-1",
        source: "fuzz/fd3",
        type: "com.fuzz.ok",
        datacontenttype: "application/json",
        data: { phase: "valid-1" },
      };
      const r1 = await sendFd3Raw([{ data: JSON.stringify({ type: "event", to: "inbox", event: validEv1 }) + "\n" }]);
      assert.equal(r1.reply.type, "ack");
      assert.equal(r1.reply.status, "stored");
      const fd3First = await waitFor(() => {
        const items = daemon!.connector.drainMailbox("claude:fd3", 10);
        return items.length > 0 ? items : null;
      }, { label: "fd3 valid-1 delivery" });
      assert.match(fd3First[0]!.text, /valid-1/);

      // A2. Oversized fd-3 line (>64 KiB, e.g. 72 KiB JSON line) -> nack(too_large), zero crash!
      const hugeLine = JSON.stringify({
        type: "event",
        to: "inbox",
        event: {
          specversion: "1.0",
          id: "fd3-oversized",
          source: "fuzz/fd3",
          type: "com.fuzz.huge",
          datacontenttype: "application/json",
          data: { pad: "X".repeat(72 * 1024) },
        },
      }) + "\n";
      assert.ok(Buffer.byteLength(hugeLine) > 64 * 1024);
      const r2 = await sendFd3Raw([{ data: hugeLine }]);
      assert.equal(r2.reply.type, "nack");
      assert.equal(r2.reply.error, "too_large");

      // A3. Malformed JSON line (`{broken`) -> clean nack(invalid_event)
      const r3 = await sendFd3Raw([{ data: "{broken\n" }]);
      assert.equal(r3.reply.type, "nack");
      assert.equal(r3.reply.error, "invalid_event");

      // A4. Invalid CloudEvent (`specversion: "9.9"`) -> clean nack(invalid_event)
      const r4 = await sendFd3Raw([{
        data: JSON.stringify({
          type: "event",
          to: "inbox",
          event: {
            specversion: "9.9",
            id: "fd3-bad-ver",
            source: "fuzz/fd3",
            type: "com.fuzz.bad",
            datacontenttype: "application/json",
            data: {},
          },
        }) + "\n",
      }]);
      assert.equal(r4.reply.type, "nack");
      assert.equal(r4.reply.error, "invalid_event");

      // A5. Fragmented multi-chunk valid NDJSON line split across 4 writes with 10ms delays -> reassembled & delivered!
      const fragLine = JSON.stringify({
        type: "event",
        to: "inbox",
        event: {
          specversion: "1.0",
          id: "fd3-frag-1",
          source: "fuzz/fd3",
          type: "com.fuzz.fragmented",
          datacontenttype: "application/json",
          data: { phase: "fragmented-reassembled" },
        },
      }) + "\n";
      const q = Math.floor(fragLine.length / 4);
      const r5 = await sendFd3Raw([
        { data: fragLine.slice(0, q), delayMs: 10 },
        { data: fragLine.slice(q, q * 2), delayMs: 10 },
        { data: fragLine.slice(q * 2, q * 3), delayMs: 10 },
        { data: fragLine.slice(q * 3) },
      ]);
      assert.equal(r5.reply.type, "ack");
      assert.equal(r5.reply.status, "stored");
      const fd3Frag = await waitFor(() => {
        const items = daemon!.connector.drainMailbox("claude:fd3", 10);
        return items.length > 0 ? items : null;
      }, { label: "fd3 fragmented delivery" });
      assert.match(fd3Frag[0]!.text, /fragmented-reassembled/);

      // A6. Subsequent valid CloudEvent -> still delivers cleanly!
      const r6 = await sendFd3Raw([{
        data: JSON.stringify({
          type: "event",
          to: "inbox",
          event: {
            specversion: "1.0",
            id: "fd3-recovery-1",
            source: "fuzz/fd3",
            type: "com.fuzz.recovery",
            datacontenttype: "application/json",
            data: { phase: "post-fuzz-recovery" },
          },
        }) + "\n",
      }]);
      assert.equal(r6.reply.type, "ack");
      const fd3Rec = await waitFor(() => {
        const items = daemon!.connector.drainMailbox("claude:fd3", 10);
        return items.length > 0 ? items : null;
      }, { label: "fd3 recovery delivery" });
      assert.match(fd3Rec[0]!.text, /post-fuzz-recovery/);

      // ---- PART B: Unix Daemon Socket Perturbations ----

      // B1. Garbage non-JSON bytes + invalid UTF-8 sequences + newline -> error JSON or clean close
      const b1 = await sendRawSocketBytes(daemon.socketPath, [
        Buffer.from([0xff, 0xfe, 0x80, 0x7b, 0x67, 0x61, 0x72, 0x62, 0x61, 0x67, 0x65, 0x0a]),
      ]);
      assert.equal(b1.closed, true, "daemon should close malformed Unix socket client");
      if (b1.data.trim().length > 0) {
        const parsed = JSON.parse(b1.data.trim()) as { ok: boolean; error?: string };
        assert.equal(parsed.ok, false);
      }

      // B2. Unterminated half-line followed by abrupt socket destroy -> daemon stays alive
      const b2 = await sendRawSocketBytes(daemon.socketPath, ['{"type":"daemon.sta'], { abruptDestroyAfterMs: 30 });
      assert.equal(b2.closed, true);

      // B3. Oversized line (>1 MiB, with newline AND unterminated) -> rejected cleanly without OOM/crash
      const oversizedJsonLine = `${JSON.stringify({ type: "daemon.status", pad: "Z".repeat(1_150_000) })}\n`;
      assert.ok(Buffer.byteLength(oversizedJsonLine) > 1024 * 1024);
      const b3 = await sendRawSocketBytes(daemon.socketPath, [oversizedJsonLine]);
      assert.equal(b3.closed, true, "daemon must close oversized >1 MiB line client");
      if (b3.data.trim().length > 0) {
        const parsed = JSON.parse(b3.data.trim()) as { ok: boolean; error?: string };
        assert.equal(parsed.ok, false);
        assert.equal(parsed.error, "line_too_large");
      }

      const b3b = await sendRawSocketBytes(daemon.socketPath, ["Y".repeat(1_150_000)]);
      assert.equal(b3b.closed, true, "daemon must reject unterminated >1 MiB burst without waiting for newline");
      if (b3b.data.trim().length > 0) {
        const parsed = JSON.parse(b3b.data.trim()) as { ok: boolean; error?: string };
        assert.equal(parsed.ok, false);
        assert.equal(parsed.error, "line_too_large");
      }

      // B4. Immediately afterward, valid daemon.status RPC succeeds with ok: true!
      const statusRpc = await daemonRpc(daemon.socketPath, { type: "daemon.status" });
      assert.equal(statusRpc.ok, true);
      assert.equal(statusRpc.result?.connectorId, "fuzz@local");

      // ---- PART C: HTTP Receiver & Router Perturbations ----

      // C1. Live Router /v1/events perturbations + clean recovery
      const routerOversized = await httpPostRaw(
        `${router.url}/v1/events?topic=deploy`,
        { authorization: `Bearer ${deployPubToken}`, "content-type": "application/json" },
        JSON.stringify({ pad: "A".repeat(72 * 1024) }),
      );
      assert.equal(routerOversized.status, 413);

      const routerBadJson = await fetch(`${router.url}/v1/events?topic=deploy`, {
        method: "POST",
        headers: { authorization: `Bearer ${deployPubToken}`, "content-type": "application/json" },
        body: '{"specversion":"1.0",',
      });
      assert.equal(routerBadJson.status, 400);

      const routerWrongCt = await fetch(`${router.url}/v1/events?topic=deploy`, {
        method: "POST",
        headers: { authorization: `Bearer ${deployPubToken}`, "content-type": "text/plain" },
        body: "not-json-at-all",
      });
      assert.equal(routerWrongCt.status, 400);

      const routerNoAuth = await fetch(`${router.url}/v1/events?topic=deploy`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      });
      assert.equal(routerNoAuth.status, 401);

      // Recovery: valid CloudEvent immediately afterward -> 202 and delivered end-to-end!
      const routerOk = await fetch(`${router.url}/v1/events?topic=deploy`, {
        method: "POST",
        headers: { authorization: `Bearer ${deployPubToken}`, "content-type": "application/json" },
        body: JSON.stringify({
          specversion: "1.0",
          id: "router-recovery-1",
          source: "ci/fuzz",
          type: "com.acme.deploy.ok",
          datacontenttype: "application/json",
          data: { marker: "router-recovered-ok" },
        }),
      });
      assert.equal(routerOk.status, 202);
      const routerItems = await waitFor(() => {
        const items = daemon!.connector.drainMailbox("codex:router-sub", 10);
        return items.length > 0 ? items : null;
      }, { label: "router /v1/events recovery delivery" });
      assert.match(routerItems[0]!.text, /router-recovered-ok/);

      // C2. Live github-webhook receiver perturbations + clean recovery
      // Exceeds DEFAULT_RECEIVER_LIMITS.maxBodyBytes (1 MiB): receiver refuses unread with 413
      const ghOversized = await httpPostRaw(
        `${ghReceiver.url}/hooks/github`,
        {
          "content-type": "application/json",
          "x-github-event": "pull_request",
          "x-github-delivery": randomUUID(),
          "x-hub-signature-256": signatureHeader(ghSecret, "{}"),
        },
        "{",
        { declaredContentLength: 1_100_000 },
      );
      assert.equal(ghOversized.status, 413);

      const ghMalformedBody = '{"action":"opened",';
      const ghBadJson = await fetch(`${ghReceiver.url}/hooks/github`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-github-event": "pull_request",
          "x-github-delivery": randomUUID(),
          "x-hub-signature-256": signatureHeader(ghSecret, ghMalformedBody),
        },
        body: ghMalformedBody,
      });
      assert.equal(ghBadJson.status, 400);

      const ghWrongCtBody = '{"action":"opened"}';
      const ghWrongCt = await fetch(`${ghReceiver.url}/hooks/github`, {
        method: "POST",
        headers: {
          "content-type": "text/plain",
          "x-github-event": "pull_request",
          "x-github-delivery": randomUUID(),
          "x-hub-signature-256": signatureHeader(ghSecret, ghWrongCtBody),
        },
        body: ghWrongCtBody,
      });
      assert.equal(ghWrongCt.status, 400);

      // Single-byte flipped HMAC signature -> 401
      const ghValidPayload = makeGithubPullRequestPayload({
        repo: "acme/fuzz",
        number: 77,
        title: "Recover cleanly after GitHub fuzz",
        author: "bob",
      });
      const goodSig = signatureHeader(ghSecret, JSON.stringify(ghValidPayload));
      const flippedLastChar = goodSig.endsWith("0") ? "1" : "0";
      const ghFlippedSig = await deliverGithubWebhook({
        receiverUrl: ghReceiver.url,
        secret: ghSecret,
        event: "pull_request",
        payload: ghValidPayload,
        overrideSignature: goodSig.slice(0, -1) + flippedLastChar,
      });
      assert.equal(ghFlippedSig.status, 401);

      // Recovery: valid signed GitHub webhook -> 202 and delivered end-to-end!
      const ghOk = await deliverGithubWebhook({
        receiverUrl: ghReceiver.url,
        secret: ghSecret,
        event: "pull_request",
        payload: ghValidPayload,
      });
      assert.equal(ghOk.status, 202);
      const ghItems = await waitFor(() => {
        const items = daemon!.connector.drainMailbox("codex:router-sub", 10);
        return items.length > 0 ? items : null;
      }, { label: "github-webhook recovery delivery" });
      assert.match(ghItems[0]!.text, /Recover cleanly after GitHub fuzz/);

      // C3. Live webhook bridge plugin perturbations + clean recovery
      const webhookUrl = `http://127.0.0.1:${webhookPort}/hook`;
      // Wait for webhook plugin port to bind by probing an unsigned request (expects 401)
      const hookNoSig = await deliverSignedWebhook({
        url: webhookUrl,
        secret: webhookSecret,
        payload: { msg: "unauth" },
        overrideSignature: null,
      });
      assert.equal(hookNoSig.status, 401);

      // Oversized HTTP body (>64 KiB, e.g. 72 KiB) -> 413
      const hookOversizedRaw = JSON.stringify({ pad: "W".repeat(72 * 1024) });
      const hookOversized = await httpPostRaw(
        webhookUrl,
        {
          "content-type": "application/json",
          "x-webhook-signature-256": `sha256=${createHmac("sha256", webhookSecret).update(hookOversizedRaw).digest("hex")}`,
        },
        hookOversizedRaw,
      );
      assert.equal(hookOversized.status, 413);

      // Truncated/non-JSON with wrong content-type (signed) -> never 500 or crash (wrapped cleanly into { raw } -> 202)
      const hookTruncRaw = '{"broken":';
      const hookTrunc = await fetch(webhookUrl, {
        method: "POST",
        headers: {
          "content-type": "text/plain",
          "x-webhook-signature-256": `sha256=${createHmac("sha256", webhookSecret).update(hookTruncRaw).digest("hex")}`,
        },
        body: hookTruncRaw,
      });
      assert.ok(hookTrunc.status === 202 || hookTrunc.status === 400, `Expected 202 or 400, got ${hookTrunc.status}`);
      assert.ok(hookTrunc.status < 500, "webhook bridge must never return 500 on malformed body");

      // Recovery: valid signed JSON webhook -> 202 and delivered end-to-end!
      const hookOk = await deliverSignedWebhook({
        url: webhookUrl,
        secret: webhookSecret,
        payload: {
          type: "com.fuzz.webhook.recovered",
          source: "webhook/fuzz",
          data: { marker: "webhook-bridge-recovered-ok" },
        },
      });
      assert.equal(hookOk.status, 202);
      const hookItems = await waitFor(() => {
        const items = daemon!.connector.drainMailbox("cursor:hook", 10);
        return items.some((i) => i.text.includes("webhook-bridge-recovered-ok")) ? items : null;
      }, { label: "webhook bridge recovery delivery" });
      assert.ok(hookItems.some((i) => i.text.includes("webhook-bridge-recovered-ok")));

      // Verify zero unhandled promise rejections throughout every perturbation
      assert.deepEqual(unhandled, [], `Unexpected unhandledRejection(s): ${JSON.stringify(unhandled)}`);
    } finally {
      process.off("unhandledRejection", onUnhandled);
      await ghReceiver?.close().catch(() => {});
      await daemon?.stop().catch(() => {});
      await router?.close().catch(() => {});
      try { routerCore.close(); } catch {}
      rmSync(rootDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  },
);

// ============================================================================
// TEST 3 — Forgotten CLI Inputs & Agent-First Output Contract
// ============================================================================

test(
  "differential e2e (Forgotten Inputs): hyp CLI output contract (--json/--plain/--pretty/HYPHAE_OUTPUT/NO_COLOR) and exit codes 0|1|2 against live & stopped daemons",
  { timeout: 30_000 },
  async () => {
    const topo = new MeshTopology("hi-cli-");
    try {
      const isoHome = topo.subDir("home");
      const isoXdg = topo.subDir("xdg");
      const cliEnv: Record<string, string> = {
        HOME: isoHome,
        XDG_CONFIG_HOME: isoXdg,
      };

      // Wire all configurable harnesses into the ISOLATED temp HOME so `hyp status` passes
      // deterministically regardless of which harness binaries exist on the host PATH.
      const runtime = { nodeBin: process.execPath, cliScript: CLI_SCRIPT };
      setupAntigravity({ scope: "user", homeDir: isoHome, runtime });
      setupClaude({ scope: "user", homeDir: isoHome, runtime });
      setupCodex({ scope: "user", homeDir: isoHome, runtime });
      setupCursor({ scope: "user", homeDir: isoHome, runtime });
      setupOpenCode({ scope: "user", homeDir: isoHome, runtime });
      setupGemini({ scope: "user", homeDir: isoHome, runtime });
      setupOpenClaw({ scope: "user", homeDir: isoHome, runtime });

      const router = await topo.addRouter({ name: "team" });
      const liveConn = await topo.addConnector({
        connectorId: "cli@tester",
        links: [{ name: "primary", router }],
        rawPlugins: [], // Forces MeshTopology to write a real 0600 connector.json + 0600 primary.token!
      });
      assert.ok(existsSync(liveConn.configPath), "connector.json should exist");

      liveConn.daemon.state.register("claude:cli-sess-1", { kind: "claude" });
      await liveConn.daemon.connector.call("claude:cli-sess-1", "hyp_join", { handle: "cli-agent" });
      liveConn.daemon.connector.muteTarget("#baseline-noise", "*", "test-seed");

      const stoppedDir = topo.subDir("stopped");
      const stoppedConfigPath = join(stoppedDir, "connector.json");
      const stoppedSocketPath = join(stoppedDir, "connector.sock");

      // 1. --version --json vs --version --plain (exit 0)
      const [verJson, verPlain] = await Promise.all([
        runCliAsync(["--version", "--json"], { env: cliEnv }),
        runCliAsync(["--version", "--plain"], { env: cliEnv }),
      ]);
      assert.equal(verJson.code, EXIT_OK);
      assert.equal(ANSI_RE.test(verJson.stdout), false);
      const verParsed = JSON.parse(verJson.stdout) as { ok: boolean; command: string; data: { name: string; version: string } };
      assert.equal(verParsed.ok, true);
      assert.equal(verParsed.command, "version");
      assert.equal(verParsed.data.name, "hyphae");
      assert.match(verParsed.data.version, /^\d+\.\d+\.\d+/);

      assert.equal(verPlain.code, EXIT_OK);
      assert.equal(ANSI_RE.test(verPlain.stdout), false);
      assert.equal(verPlain.stdout.trim(), `hyphae ${verParsed.data.version}`);

      // 2. --help --json vs --help --plain (exit 0; JSON lists commands, vocabulary, exitCodes)
      const [helpJson, helpPlain] = await Promise.all([
        runCliAsync(["--help", "--json"], { env: cliEnv }),
        runCliAsync(["--help", "--plain"], { env: cliEnv }),
      ]);
      assert.equal(helpJson.code, EXIT_OK);
      assert.equal(ANSI_RE.test(helpJson.stdout), false);
      const helpParsed = JSON.parse(helpJson.stdout) as {
        ok: boolean;
        command: string;
        data: {
          commands: Array<{ name: string }>;
          vocabulary: Record<string, string>;
          exitCodes: Record<string, string>;
        };
      };
      assert.equal(helpParsed.ok, true);
      assert.equal(helpParsed.command, "help");
      assert.ok(helpParsed.data.commands.some((c) => c.name === "status"));
      assert.ok(helpParsed.data.commands.some((c) => c.name === "mute"));
      for (const term of ["Node", "Connector", "Stream", "Bridge", "Session", "Rule"]) {
        assert.equal(typeof helpParsed.data.vocabulary[term], "string", `Missing vocabulary term ${term}`);
      }
      assert.ok(helpParsed.data.exitCodes["0"]);
      assert.ok(helpParsed.data.exitCodes["1"]);
      assert.ok(helpParsed.data.exitCodes["2"]);

      assert.equal(helpPlain.code, EXIT_OK);
      assert.equal(ANSI_RE.test(helpPlain.stdout), false);
      assert.match(helpPlain.stdout, /CORE COMMANDS:/);

      // 3. Live daemon `status` across --json / --plain / --pretty / HYPHAE_OUTPUT=json / NO_COLOR=1 / flag precedence
      const statusBase = ["status", liveConn.configPath, "--socket", liveConn.socketPath];
      const [stJson, stPlain, stPretty, stEnvJson, stNoColor, stPrecedence] = await Promise.all([
        runCliAsync([...statusBase, "--json"], { env: cliEnv }),
        runCliAsync([...statusBase, "--plain"], { env: cliEnv }),
        runCliAsync([...statusBase, "--pretty"], { env: cliEnv }),
        runCliAsync(statusBase, { env: { ...cliEnv, HYPHAE_OUTPUT: "json" } }),
        runCliAsync(statusBase, { env: { ...cliEnv, NO_COLOR: "1" } }),
        runCliAsync([...statusBase, "--plain"], { env: { ...cliEnv, HYPHAE_OUTPUT: "pretty" } }),
      ]);

      assert.equal(stJson.code, EXIT_OK, `Expected live status --json exit 0, stdout=${stJson.stdout}`);
      assert.equal(ANSI_RE.test(stJson.stdout), false);
      const stData = JSON.parse(stJson.stdout) as {
        ok: boolean;
        command: string;
        data: {
          daemonReachable: boolean;
          connectorId: string;
          sessions: Array<{ id: string; handle: string | null }>;
          mutes: Array<{ pattern: string }>;
          checks: Array<{ name: string; ok: boolean }>;
        };
      };
      assert.equal(stData.ok, true);
      assert.equal(stData.command, "status");
      assert.equal(stData.data.daemonReachable, true);
      assert.equal(stData.data.connectorId, "cli@tester");
      assert.ok(stData.data.sessions.some((s) => s.id === "claude:cli-sess-1" && s.handle === "cli-agent"));
      assert.ok(stData.data.mutes.some((m) => m.pattern === "#baseline-noise"));

      // --plain and NO_COLOR=1 and explicit --plain over HYPHAE_OUTPUT=pretty must contain ZERO ANSI
      for (const [label, res] of [
        ["--plain", stPlain],
        ["NO_COLOR=1", stNoColor],
        ["--plain over HYPHAE_OUTPUT=pretty", stPrecedence],
      ] as const) {
        assert.equal(res.code, EXIT_OK, `${label} should exit 0`);
        assert.equal(ANSI_RE.test(res.stdout), false, `${label} must emit ZERO ANSI escape codes`);
        assert.match(res.stdout, /^COMMAND: status/m);
        assert.match(res.stdout, /^STATUS: ok/m);
        assert.match(res.stdout, /cli@tester/);
      }

      // --pretty MUST contain ANSI escape codes
      assert.equal(stPretty.code, EXIT_OK);
      assert.equal(ANSI_RE.test(stPretty.stdout), true, "--pretty must emit ANSI styling");
      assert.match(stPretty.stdout, /Hyphae Status/);

      // HYPHAE_OUTPUT=json MUST parse cleanly to the same structured contract
      assert.equal(stEnvJson.code, EXIT_OK);
      assert.equal(ANSI_RE.test(stEnvJson.stdout), false);
      const stEnvParsed = JSON.parse(stEnvJson.stdout) as { ok: boolean; command: string; data: { daemonReachable: boolean; connectorId: string } };
      assert.equal(stEnvParsed.ok, true);
      assert.equal(stEnvParsed.command, "status");
      assert.equal(stEnvParsed.data.daemonReachable, true);
      assert.equal(stEnvParsed.data.connectorId, "cli@tester");

      // 4. `status --json` against an unreachable stopped socket -> exit 1 (EXIT_ERROR), ok: false, actionable next steps!
      const stStopped = await runCliAsync(
        ["status", stoppedConfigPath, "--socket", stoppedSocketPath, "--json"],
        { env: cliEnv },
      );
      assert.equal(stStopped.code, EXIT_ERROR);
      assert.equal(ANSI_RE.test(stStopped.stdout), false);
      const stStoppedParsed = JSON.parse(stStopped.stdout) as {
        ok: boolean;
        command: string;
        next?: string[];
        data: { daemonReachable: boolean };
      };
      assert.equal(stStoppedParsed.ok, false);
      assert.equal(stStoppedParsed.command, "status");
      assert.equal(stStoppedParsed.data.daemonReachable, false);
      assert.ok(Array.isArray(stStoppedParsed.next) && stStoppedParsed.next.length > 0, "unreachable status must include next fix steps");

      // 5. `sessions --socket <live>` -> exit 0, valid JSON array containing enrolled session
      const sessRes = await runCliAsync(["sessions", "--socket", liveConn.socketPath], { env: cliEnv });
      assert.equal(sessRes.code, EXIT_OK);
      assert.equal(ANSI_RE.test(sessRes.stdout), false);
      const sessArr = JSON.parse(sessRes.stdout) as Array<{ id: string; handle: string | null; enrolled: boolean }>;
      assert.ok(Array.isArray(sessArr));
      assert.ok(sessArr.some((s) => s.id === "claude:cli-sess-1" && s.handle === "cli-agent" && s.enrolled === true));

      // 6. `mute #diff-noisy --json` -> `mutes --json` -> `unmute #diff-noisy --json` (differential parity with daemon.connector.listMutes())
      const muteAdd = await runCliAsync(["mute", "#diff-noisy", "--socket", liveConn.socketPath, "--json"], { env: cliEnv });
      assert.equal(muteAdd.code, EXIT_OK);
      assert.equal(ANSI_RE.test(muteAdd.stdout), false);
      const muteAddParsed = JSON.parse(muteAdd.stdout) as { ok: boolean; command: string; data: { rule: { pattern: string } } };
      assert.equal(muteAddParsed.ok, true);
      assert.equal(muteAddParsed.command, "mute");
      assert.equal(muteAddParsed.data.rule.pattern, "#diff-noisy");

      const mutesList = await runCliAsync(["mutes", "--socket", liveConn.socketPath, "--json"], { env: cliEnv });
      assert.equal(mutesList.code, EXIT_OK);
      const mutesParsed = JSON.parse(mutesList.stdout) as { ok: boolean; command: string; data: { mutes: Array<{ scope: string; pattern: string }> } };
      assert.equal(mutesParsed.ok, true);
      assert.equal(mutesParsed.command, "mutes");
      const actualDaemonMutes = liveConn.daemon.connector.listMutes().map((m) => ({ scope: m.scope, pattern: m.pattern }));
      const cliMutes = mutesParsed.data.mutes.map((m) => ({ scope: m.scope, pattern: m.pattern }));
      assert.deepEqual(cliMutes, actualDaemonMutes, "CLI `mutes --json` must match daemon.connector.listMutes()");
      assert.ok(cliMutes.some((m) => m.pattern === "#diff-noisy"));

      const muteRm = await runCliAsync(["unmute", "#diff-noisy", "--socket", liveConn.socketPath, "--json"], { env: cliEnv });
      assert.equal(muteRm.code, EXIT_OK);
      const muteRmParsed = JSON.parse(muteRm.stdout) as { ok: boolean; command: string; data: { pattern: string; removed: boolean } };
      assert.equal(muteRmParsed.ok, true);
      assert.equal(muteRmParsed.command, "unmute");
      assert.equal(muteRmParsed.data.pattern, "#diff-noisy");
      assert.equal(muteRmParsed.data.removed, true);
      assert.equal(liveConn.daemon.connector.listMutes().some((m) => m.pattern === "#diff-noisy"), false);

      // 7. `connect list --json`, `connect guide github-webhook --json` (exit 0) vs `connect guide nonexistent --json` (exit 2)
      const [connList, guideGh, guideBad, skillPathJson, skillPathPlain] = await Promise.all([
        runCliAsync(["connect", "list", "--config", liveConn.configPath, "--json"], { env: cliEnv }),
        runCliAsync(["connect", "guide", "github-webhook", "--json"], { env: cliEnv }),
        runCliAsync(["connect", "guide", "nonexistent", "--json"], { env: cliEnv }),
        runCliAsync(["skill", "path", "--json"], { env: cliEnv }),
        runCliAsync(["skill", "path", "--plain"], { env: cliEnv }),
      ]);

      assert.equal(connList.code, EXIT_OK);
      const connListParsed = JSON.parse(connList.stdout) as { ok: boolean; command: string; data: { exists: boolean; streams: unknown[]; bridges: unknown[] } };
      assert.equal(connListParsed.ok, true);
      assert.equal(connListParsed.command, "connect list");
      assert.equal(connListParsed.data.exists, true);

      assert.equal(guideGh.code, EXIT_OK);
      const guideGhParsed = JSON.parse(guideGh.stdout) as { ok: boolean; command: string; data: { id: string; kind: string } };
      assert.equal(guideGhParsed.ok, true);
      assert.equal(guideGhParsed.command, "connect guide");
      assert.equal(guideGhParsed.data.id, "github-webhook");
      assert.equal(guideGhParsed.data.kind, "stream");

      assert.equal(guideBad.code, EXIT_USAGE);
      const guideBadParsed = JSON.parse(guideBad.stdout) as { ok: boolean; error: { code: string } };
      assert.equal(guideBadParsed.ok, false);
      assert.equal(guideBadParsed.error.code, "USAGE_ERROR");

      // 8. `skill path --json` & `--plain` (exit 0)
      assert.equal(skillPathJson.code, EXIT_OK);
      const skillParsed = JSON.parse(skillPathJson.stdout) as { ok: boolean; command: string; data: { path: string } };
      assert.equal(skillParsed.ok, true);
      assert.equal(skillParsed.command, "skill path");
      assert.match(skillParsed.data.path, /SKILL\.md$/);
      assert.ok(existsSync(skillParsed.data.path));
      assert.equal(skillPathPlain.code, EXIT_OK);
      assert.equal(ANSI_RE.test(skillPathPlain.stdout), false);
      assert.equal(skillPathPlain.stdout.trim(), skillParsed.data.path);

      // 9. Forgotten / invalid usage inputs -> ALL exit 2 (EXIT_USAGE) with valid JSON { ok: false, error: { code: "USAGE_ERROR" } }
      const usageCases: ReadonlyArray<readonly string[]> = [
        ["nope", "--json"],
        ["onboard", "--port", "99999", "--json"],
        ["unmute", "--json"],
        ["mute", "#a", "#b", "--json"],
        ["connect", "add", "--json"],
        ["status", "--not-a-real-flag", "--json"],
        ["secret", "set", "--json"],
        ["setup", "--json"],
      ];
      const usageResults = await Promise.all(usageCases.map((args) => runCliAsync(args, { env: cliEnv })));
      for (let i = 0; i < usageCases.length; i++) {
        const args = usageCases[i]!;
        const res = usageResults[i]!;
        assert.equal(
          res.code,
          EXIT_USAGE,
          `Expected exit ${EXIT_USAGE} for \`hyp ${args.join(" ")}\` (got code=${res.code}, stdout=${res.stdout}, stderr=${res.stderr})`,
        );
        assert.equal(ANSI_RE.test(res.stdout), false, `JSON usage error must have zero ANSI: hyp ${args.join(" ")}`);
        const parsed = JSON.parse(res.stdout) as { ok: boolean; error: { code: string; message: string } };
        assert.equal(parsed.ok, false, `Expected ok=false for hyp ${args.join(" ")}`);
        assert.equal(parsed.error.code, "USAGE_ERROR", `Expected USAGE_ERROR for hyp ${args.join(" ")}`);
        assert.ok(parsed.error.message.length > 0);
      }
    } finally {
      await topo.cleanup();
    }
  },
);
