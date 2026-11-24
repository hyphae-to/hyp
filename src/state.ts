import { randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import type { Backend } from "./delivery.ts";
import type { RouterConfig } from "./router.ts";
import type { DeliveryMode, Subscription, UnreadDigest } from "./protocol.ts";

export interface Session {
  id: string;
  backend: Backend;
  handle: string | null;
  lastSeen: number;
  deliveryMode: DeliveryMode;
}

export interface MuteRule {
  scope: string;
  pattern: string;
  mutedAt: number;
  mutedBy: string;
}

export interface MailboxEntry {
  receipt: string;
  router: string;
  text: string;
  received: number;
  kind?: "message" | "event" | "plugin";
  source?: string;
}

export interface PluginTargetHandoff {
  plugin: string;
  target: string;
  sessionId: string;
  setAt: number;
  setBy: string;
}

export type StoredSubscription = Subscription & { sessionId: string };

export class State {
  readonly #db: DatabaseSync;

  constructor(path: string, identity: string) {
    this.#db = new DatabaseSync(path);
    this.#db.exec(`
      CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, backend TEXT NOT NULL, handle TEXT UNIQUE, last_seen INTEGER NOT NULL DEFAULT 0, delivery_mode TEXT NOT NULL DEFAULT 'full');
      CREATE TABLE IF NOT EXISTS session_subscriptions (id TEXT PRIMARY KEY, router TEXT NOT NULL, session TEXT NOT NULL,
        key TEXT NOT NULL, value TEXT NOT NULL, UNIQUE(session, key));
      CREATE TABLE IF NOT EXISTS deliveries (router TEXT, id TEXT, state TEXT NOT NULL, created INTEGER NOT NULL, PRIMARY KEY (router, id));
      CREATE TABLE IF NOT EXISTS mailbox (receipt TEXT PRIMARY KEY, session TEXT NOT NULL,
        router TEXT NOT NULL, item TEXT NOT NULL, text TEXT NOT NULL, received INTEGER NOT NULL,
        kind TEXT NOT NULL DEFAULT 'message', source TEXT NOT NULL DEFAULT '', notified INTEGER NOT NULL DEFAULT 0,
        UNIQUE(router, item));
      CREATE TABLE IF NOT EXISTS plugin_targets (plugin TEXT NOT NULL, target TEXT NOT NULL,
        session TEXT NOT NULL, set_at INTEGER NOT NULL, set_by TEXT NOT NULL, PRIMARY KEY (plugin, target));
      CREATE TABLE IF NOT EXISTS muted_sources (scope TEXT NOT NULL, pattern TEXT NOT NULL,
        muted_at INTEGER NOT NULL, muted_by TEXT NOT NULL, PRIMARY KEY (scope, pattern));
    `);
    const columns = this.#db.prepare("PRAGMA table_info(sessions)").all() as Array<{ name?: unknown }>;
    if (!columns.some((column) => column.name === "last_seen")) {
      this.#db.exec("ALTER TABLE sessions ADD COLUMN last_seen INTEGER NOT NULL DEFAULT 0");
    }
    if (!columns.some((column) => column.name === "delivery_mode")) {
      this.#db.exec("ALTER TABLE sessions ADD COLUMN delivery_mode TEXT NOT NULL DEFAULT 'full'");
    }
    const mailboxCols = this.#db.prepare("PRAGMA table_info(mailbox)").all() as Array<{ name?: unknown }>;
    if (!mailboxCols.some((column) => column.name === "kind")) {
      this.#db.exec("ALTER TABLE mailbox ADD COLUMN kind TEXT NOT NULL DEFAULT 'message'");
    }
    if (!mailboxCols.some((column) => column.name === "source")) {
      this.#db.exec("ALTER TABLE mailbox ADD COLUMN source TEXT NOT NULL DEFAULT ''");
    }
    if (!mailboxCols.some((column) => column.name === "notified")) {
      this.#db.exec("ALTER TABLE mailbox ADD COLUMN notified INTEGER NOT NULL DEFAULT 0");
    }
    this.#db.prepare("INSERT OR IGNORE INTO metadata VALUES ('identity', ?)").run(identity);
    if (this.#db.prepare("SELECT value FROM metadata WHERE key = 'identity'").get()?.value !== identity) {
      this.#db.close();
      throw new Error("This state directory belongs to another connector or the single-session prototype");
    }
    this.#db.prepare("DELETE FROM deliveries WHERE created < ?").run(Date.now() - 7 * 86_400_000);
  }

  bindRouters(routers: RouterConfig[]): void {
    for (const { name, url } of routers) {
      const key = `router:${name}`;
      this.#db.prepare("INSERT OR IGNORE INTO metadata VALUES (?, ?)").run(key, url);
      if (this.#db.prepare("SELECT value FROM metadata WHERE key = ?").get(key)?.value !== url) {
        throw new Error(`Router ${name} belongs to a different origin in this state directory`);
      }
    }
  }

  close(): void { this.#db.close(); }

  register(id: string, backend: Backend, now = Date.now()): void {
    this.#db.prepare(`INSERT INTO sessions (id, backend, last_seen) VALUES (?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET backend = excluded.backend, last_seen = excluded.last_seen`).run(
      id, JSON.stringify(backend), now,
    );
  }

  touch(id: string, now = Date.now()): void {
    this.#db.prepare("UPDATE sessions SET last_seen = ? WHERE id = ?").run(now, id);
  }

  session(id: string): Session | undefined {
    const row = this.#db.prepare("SELECT * FROM sessions WHERE id = ?").get(id);
    return row === undefined ? undefined : this.#decodeSession(row);
  }

  sessions(): Session[] {
    return this.#db.prepare("SELECT * FROM sessions ORDER BY last_seen DESC, id").all()
      .map((row) => this.#decodeSession(row));
  }

  byHandle(handle: string): Session | undefined {
    const row = this.#db.prepare("SELECT * FROM sessions WHERE handle = ?").get(handle);
    return row === undefined ? undefined : this.#decodeSession(row);
  }

  /** Matches either exact sessionId or `<harness>:<threadId>` suffix (for t3-mesh drop-in compatibility). */
  byThreadId(threadId: string): Session | undefined {
    const exact = this.session(threadId);
    if (exact) return exact;
    const suffix = `:${threadId}`;
    return this.sessions().find((s) => s.id.endsWith(suffix));
  }

  pluginTarget(plugin: string, target: string): PluginTargetHandoff | undefined {
    const row = this.#db.prepare("SELECT plugin, target, session, set_at, set_by FROM plugin_targets WHERE plugin = ? AND target = ?").get(plugin, target);
    if (!row) return undefined;
    return {
      plugin: String(row.plugin),
      target: String(row.target),
      sessionId: String(row.session),
      setAt: Number(row.set_at),
      setBy: String(row.set_by),
    };
  }

  setPluginTarget(handoff: PluginTargetHandoff): void {
    this.#db.prepare("INSERT OR REPLACE INTO plugin_targets (plugin, target, session, set_at, set_by) VALUES (?, ?, ?, ?, ?)").run(
      handoff.plugin, handoff.target, handoff.sessionId, handoff.setAt, handoff.setBy,
    );
  }

  removePluginTarget(plugin: string, target: string): void {
    this.#db.prepare("DELETE FROM plugin_targets WHERE plugin = ? AND target = ?").run(plugin, target);
  }

  #decodeSession(row: Record<string, unknown>): Session {
    return {
      id: String(row.id),
      backend: JSON.parse(String(row.backend)) as Backend,
      handle: typeof row.handle === "string" ? row.handle : null,
      lastSeen: typeof row.last_seen === "number" ? row.last_seen : Number(row.last_seen ?? 0),
      deliveryMode: row.delivery_mode === "notify" ? "notify" : "full",
    };
  }

  setDeliveryMode(id: string, mode: DeliveryMode): void {
    this.#db.prepare("UPDATE sessions SET delivery_mode = ?, last_seen = ? WHERE id = ?").run(mode, Date.now(), id);
  }

  addMute(pattern: string, scope: string, mutedBy: string): MuteRule {
    const mutedAt = Date.now();
    this.#db.prepare("INSERT OR REPLACE INTO muted_sources (scope, pattern, muted_at, muted_by) VALUES (?, ?, ?, ?)").run(
      scope, pattern, mutedAt, mutedBy,
    );
    return { scope, pattern, mutedAt, mutedBy };
  }

  removeMute(pattern: string, scope: string): boolean {
    const res = this.#db.prepare("DELETE FROM muted_sources WHERE scope = ? AND pattern = ?").run(scope, pattern);
    return Number(res.changes ?? 0) > 0;
  }

  listMutes(sessionId?: string): MuteRule[] {
    const rows = sessionId
      ? this.#db.prepare("SELECT scope, pattern, muted_at, muted_by FROM muted_sources WHERE scope = '*' OR scope = ? ORDER BY scope, pattern").all(sessionId)
      : this.#db.prepare("SELECT scope, pattern, muted_at, muted_by FROM muted_sources WHERE scope = '*' ORDER BY pattern").all();
    return rows.map((row) => ({
      scope: String(row.scope),
      pattern: String(row.pattern),
      mutedAt: Number(row.muted_at),
      mutedBy: String(row.muted_by),
    }));
  }

  isMuted(sessionId: string, candidates: readonly string[]): string | undefined {
    if (candidates.length === 0) return undefined;
    const stmt = this.#db.prepare("SELECT pattern FROM muted_sources WHERE (scope = '*' OR scope = ?) AND pattern = ? LIMIT 1");
    for (const candidate of candidates) {
      const row = stmt.get(sessionId, candidate.toLowerCase());
      if (row && typeof row.pattern === "string") return row.pattern;
    }
    return undefined;
  }

  handles(): string[] {
    return this.#db.prepare("SELECT handle FROM sessions WHERE handle IS NOT NULL ORDER BY handle").all().map(({ handle }) => String(handle));
  }

  setHandle(id: string, handle: string | null): void {
    this.#db.prepare("UPDATE sessions SET handle = ?, last_seen = ? WHERE id = ?").run(handle, Date.now(), id);
  }

  subscriptions(): StoredSubscription[] {
    return this.#db.prepare("SELECT value FROM session_subscriptions ORDER BY key").all()
      .map(({ value }) => JSON.parse(String(value)) as StoredSubscription);
  }

  subscriptionsFor(sessionId: string): StoredSubscription[] {
    return this.#db.prepare("SELECT value FROM session_subscriptions WHERE session = ? ORDER BY key").all(sessionId)
      .map(({ value }) => JSON.parse(String(value)) as StoredSubscription);
  }

  store(subscription: StoredSubscription): void {
    this.#db.prepare("INSERT OR REPLACE INTO session_subscriptions VALUES (?, ?, ?, ?, ?)").run(
      subscription.id, subscription.router, subscription.sessionId, subscription.key, JSON.stringify(subscription),
    );
  }

  remove(id: string): void {
    this.#db.prepare("DELETE FROM session_subscriptions WHERE id = ?").run(id);
  }

  receipt(router: string, id: string): string | undefined {
    const value = this.#db.prepare("SELECT state FROM deliveries WHERE router = ? AND id = ?").get(router, id)?.state;
    return typeof value === "string" ? value : undefined;
  }

  record(router: string, id: string, state: string): void {
    this.#db.prepare("INSERT OR REPLACE INTO deliveries VALUES (?, ?, ?, ?)").run(router, id, state, Date.now());
  }

  clear(router: string, id: string): void {
    this.#db.prepare("DELETE FROM deliveries WHERE router = ? AND id = ?").run(router, id);
  }

  putInInbox(
    session: string,
    router: string,
    item: string,
    text: string,
    meta: { kind?: "message" | "event" | "plugin"; source?: string } = {},
  ): boolean {
    this.#db.exec("BEGIN");
    try {
      const count = this.#db.prepare("SELECT count(*) AS n FROM mailbox WHERE session = ?").get(session)?.n;
      if (Number(count) >= 100) {
        this.#db.exec("ROLLBACK");
        return false;
      }
      this.#db.prepare(
        "INSERT OR IGNORE INTO mailbox (receipt, session, router, item, text, received, kind, source, notified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)",
      ).run(randomUUID(), session, router, item, text, Date.now(), meta.kind ?? "message", meta.source ?? "");
      this.record(router, item, "submitted");
      this.#db.exec("COMMIT");
      return true;
    } catch (error) {
      this.#db.exec("ROLLBACK");
      throw error;
    }
  }

  pendingCount(session: string): number {
    return Number(this.#db.prepare("SELECT count(*) AS n FROM mailbox WHERE session = ?").get(session)?.n ?? 0);
  }

  unnotifiedCount(session: string): number {
    return Number(this.#db.prepare("SELECT count(*) AS n FROM mailbox WHERE session = ? AND notified = 0").get(session)?.n ?? 0);
  }

  unreadDigest(session: string): UnreadDigest {
    const rows = this.#db.prepare("SELECT kind, source, notified FROM mailbox WHERE session = ? ORDER BY received DESC").all(session);
    let messages = 0;
    let events = 0;
    let plugins = 0;
    let unnotified = 0;
    const sources: string[] = [];
    const seen = new Set<string>();
    for (const row of rows) {
      if (Number(row.notified ?? 0) === 0) unnotified++;
      const kind = String(row.kind ?? "message");
      if (kind === "event") events++;
      else if (kind === "plugin") plugins++;
      else messages++;
      const src = String(row.source ?? "").trim();
      if (src && !seen.has(src)) {
        seen.add(src);
        sources.push(src);
      }
    }
    return { unread: rows.length, unnotified, messages, events, plugins, sources };
  }

  markMailboxNotified(session: string): void {
    this.#db.prepare("UPDATE mailbox SET notified = 1 WHERE session = ? AND notified = 0").run(session);
  }

  peekInbox(session: string, limit = 5): MailboxEntry[] {
    return this.#db.prepare("SELECT receipt, router, text, received, kind, source FROM mailbox WHERE session = ? ORDER BY received, receipt LIMIT ?")
      .all(session, limit)
      .map((row) => ({
        receipt: String(row.receipt),
        router: String(row.router),
        text: String(row.text),
        received: Number(row.received),
        kind: row.kind === "event" || row.kind === "plugin" ? row.kind : "message",
        ...(typeof row.source === "string" && row.source.length > 0 ? { source: row.source } : {}),
      }));
  }

  acknowledgeInbox(session: string, receipts: readonly string[]): void {
    const remove = this.#db.prepare("DELETE FROM mailbox WHERE session = ? AND receipt = ?");
    for (const receipt of receipts) remove.run(session, receipt);
  }

  /** Atomically pops up to `limit` queued items for immediate push/hook delivery. */
  drainInbox(session: string, limit = 10): MailboxEntry[] {
    this.#db.exec("BEGIN");
    try {
      const entries = this.peekInbox(session, limit);
      if (entries.length > 0) {
        this.acknowledgeInbox(session, entries.map((entry) => entry.receipt));
      }
      this.#db.exec("COMMIT");
      return entries;
    } catch (error) {
      this.#db.exec("ROLLBACK");
      throw error;
    }
  }

  inbox(session: string, acknowledge: string[], options: { limit?: number; acknowledgeAll?: boolean } = {}): MailboxEntry[] {
    const limit = options.limit ?? 20;
    this.acknowledgeInbox(session, acknowledge);
    if (options.acknowledgeAll) {
      return this.drainInbox(session, limit);
    }
    this.markMailboxNotified(session);
    return this.peekInbox(session, limit);
  }

  /** Removes inactive sessions older than `cutoffMs`, returning affected routers and pruned session IDs. */
  pruneSessions(cutoffMs: number, activeSessionIds: ReadonlySet<string> = new Set()): { pruned: string[]; routers: string[] } {
    const stale = this.#db.prepare("SELECT id FROM sessions WHERE last_seen > 0 AND last_seen < ?").all(cutoffMs)
      .map(({ id }) => String(id))
      .filter((id) => !activeSessionIds.has(id));
    if (stale.length === 0) return { pruned: [], routers: [] };
    const routers = new Set<string>();
    this.#db.exec("BEGIN");
    try {
      for (const id of stale) {
        const session = this.session(id);
        if (session?.handle) routers.add("primary");
        for (const sub of this.subscriptionsFor(id)) routers.add(sub.router);
        this.#db.prepare("DELETE FROM session_subscriptions WHERE session = ?").run(id);
        this.#db.prepare("DELETE FROM mailbox WHERE session = ?").run(id);
        this.#db.prepare("DELETE FROM muted_sources WHERE scope = ?").run(id);
        this.#db.prepare("DELETE FROM sessions WHERE id = ?").run(id);
      }
      this.#db.exec("COMMIT");
    } catch (error) {
      this.#db.exec("ROLLBACK");
      throw error;
    }
    return { pruned: stale, routers: [...routers] };
  }
}
