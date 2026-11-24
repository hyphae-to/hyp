import { randomUUID } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import type { Backend } from "./delivery.ts";
import type { RouterConfig } from "./router.ts";
import type { Subscription } from "./protocol.ts";

export interface Session {
  id: string;
  backend: Backend;
  handle: string | null;
  lastSeen: number;
}

export interface MailboxEntry {
  receipt: string;
  router: string;
  text: string;
  received: number;
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
      CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, backend TEXT NOT NULL, handle TEXT UNIQUE, last_seen INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS session_subscriptions (id TEXT PRIMARY KEY, router TEXT NOT NULL, session TEXT NOT NULL,
        key TEXT NOT NULL, value TEXT NOT NULL, UNIQUE(session, key));
      CREATE TABLE IF NOT EXISTS deliveries (router TEXT, id TEXT, state TEXT NOT NULL, created INTEGER NOT NULL, PRIMARY KEY (router, id));
      CREATE TABLE IF NOT EXISTS mailbox (receipt TEXT PRIMARY KEY, session TEXT NOT NULL,
        router TEXT NOT NULL, item TEXT NOT NULL, text TEXT NOT NULL, received INTEGER NOT NULL, UNIQUE(router, item));
      CREATE TABLE IF NOT EXISTS plugin_targets (plugin TEXT NOT NULL, target TEXT NOT NULL,
        session TEXT NOT NULL, set_at INTEGER NOT NULL, set_by TEXT NOT NULL, PRIMARY KEY (plugin, target));
    `);
    const columns = this.#db.prepare("PRAGMA table_info(sessions)").all() as Array<{ name?: unknown }>;
    if (!columns.some((column) => column.name === "last_seen")) {
      this.#db.exec("ALTER TABLE sessions ADD COLUMN last_seen INTEGER NOT NULL DEFAULT 0");
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
    };
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

  putInInbox(session: string, router: string, item: string, text: string): boolean {
    this.#db.exec("BEGIN");
    try {
      const count = this.#db.prepare("SELECT count(*) AS n FROM mailbox WHERE session = ?").get(session)?.n;
      if (Number(count) >= 100) {
        this.#db.exec("ROLLBACK");
        return false;
      }
      this.#db.prepare("INSERT OR IGNORE INTO mailbox VALUES (?, ?, ?, ?, ?, ?)").run(randomUUID(), session, router, item, text, Date.now());
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

  peekInbox(session: string, limit = 5): MailboxEntry[] {
    return this.#db.prepare("SELECT receipt, router, text, received FROM mailbox WHERE session = ? ORDER BY received, receipt LIMIT ?")
      .all(session, limit)
      .map((row) => ({
        receipt: String(row.receipt),
        router: String(row.router),
        text: String(row.text),
        received: Number(row.received),
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

  inbox(session: string, acknowledge: string[]): MailboxEntry[] {
    this.acknowledgeInbox(session, acknowledge);
    return this.peekInbox(session, 5);
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
