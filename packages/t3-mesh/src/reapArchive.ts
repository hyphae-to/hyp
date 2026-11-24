// The archive scripts/reap-threads.ts writes before it deletes anything: every row of T3's state
// database that names one of the deleted threads, copied table for table into a separate SQLite
// file, with an index of the thread groups it holds. T3's database is opened read-only (never written,
// never a second server against it); a group is deleted only after its rows are copied and counted.
//
// Look a group up with:
//   SELECT * FROM archived_groups WHERE builder_number = 4482;     -- a builder
//   SELECT * FROM archived_groups WHERE parent_title LIKE 'Bayfold Release Manager%';
// then read any T3 table by its thread ids, e.g.
//   SELECT * FROM orchestration_v2_projection_messages
//   WHERE thread_id IN (SELECT value FROM json_each((SELECT thread_ids FROM archived_groups WHERE ...)));
import { DatabaseSync, type SQLInputValue } from "node:sqlite";

/** Columns naming a thread in T3's state database, the old event log's stream id among them. */
export const THREAD_COLUMNS = ["thread_id", "source_thread_id", "target_thread_id", "child_thread_id", "stream_id", "aggregate_id"];

export interface ArchivedGroup {
  readonly rootThreadId: string;
  readonly title: string;
  readonly parentThreadId: string | null;
  readonly parentTitle: string | null;
  readonly threadIds: readonly string[];
  readonly lastActiveAt: number;
}

export interface ArchivedWorktree {
  readonly path: string;
  readonly threadIds: readonly string[];
  readonly branch: string | null;
  readonly head: string | null;
  /** Null when removed; otherwise why it was kept. */
  readonly keptReason: string | null;
}

interface CopiedTable {
  readonly name: string;
  readonly columns: readonly string[];
  readonly match: readonly string[];
}

const quote = (name: string) => `"${name.replaceAll('"', '""')}"`;

// archived_builders (root column builder_thread_id) was this table's first name; open() renames it.
const INDEX_SCHEMA = `
CREATE TABLE IF NOT EXISTS archived_groups (
  root_thread_id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  parent_thread_id TEXT,
  parent_title TEXT,
  builder_number INTEGER,
  thread_ids TEXT NOT NULL,
  last_active_at TEXT NOT NULL,
  archived_at TEXT NOT NULL,
  deleted_at TEXT,
  deleted_threads INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS archived_worktrees (
  path TEXT PRIMARY KEY,
  thread_ids TEXT NOT NULL,
  branch TEXT,
  head TEXT,
  removed_at TEXT,
  kept_reason TEXT,
  recorded_at TEXT NOT NULL
);`;

/**
 * Worktree paths of T3's live (not deleted) threads that are missing from `known`, read from T3's
 * database read-only. T3's shell leaves archived threads out, and their worktrees must stay.
 */
export function worktreesOfOtherThreads(sourcePath: string, known: ReadonlySet<string>): string[] {
  const source = new DatabaseSync(sourcePath, { readOnly: true });
  try {
    source.exec("PRAGMA busy_timeout = 5000;");
    const rows = source
      .prepare(
        `SELECT thread_id, json_extract(payload_json, '$.worktreePath') AS path FROM orchestration_v2_projection_threads
         WHERE deleted_at IS NULL AND json_extract(payload_json, '$.worktreePath') IS NOT NULL`,
      )
      .all();
    return rows.filter((row) => !known.has(String(row.thread_id))).map((row) => String(row.path));
  } finally {
    source.close();
  }
}

export class GroupArchive {
  readonly #source: DatabaseSync;
  readonly #archive: DatabaseSync;
  readonly #tables: readonly CopiedTable[];

  private constructor(source: DatabaseSync, archive: DatabaseSync, tables: readonly CopiedTable[]) {
    this.#source = source;
    this.#archive = archive;
    this.#tables = tables;
  }

  /** Opens T3's database read-only and the archive read-write, creating the archive's tables. */
  static open(sourcePath: string, archivePath: string): GroupArchive {
    const source = new DatabaseSync(sourcePath, { readOnly: true });
    const archive = new DatabaseSync(archivePath);
    try {
      archive.exec("PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;");
      source.exec("PRAGMA busy_timeout = 5000;");
      const named = (name: string) => archive.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name) !== undefined;
      if (named("archived_builders") && !named("archived_groups")) {
        archive.exec(`ALTER TABLE archived_builders RENAME TO archived_groups;
          ALTER TABLE archived_groups RENAME COLUMN builder_thread_id TO root_thread_id;
          ALTER TABLE archived_groups ADD COLUMN parent_thread_id TEXT;
          ALTER TABLE archived_groups ADD COLUMN parent_title TEXT;`);
      }
      archive.exec(INDEX_SCHEMA);
      archive.exec("CREATE INDEX IF NOT EXISTS archived_groups_builder_number ON archived_groups (builder_number)");
      const tables: CopiedTable[] = [];
      const schema = source
        .prepare("SELECT name, sql FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .all();
      for (const row of schema) {
        const name = String(row.name);
        const sql = String(row.sql);
        if (/^CREATE\s+VIRTUAL/i.test(sql)) continue;
        const columns = source.prepare(`SELECT name FROM pragma_table_info(?)`).all(name).map((c) => String(c.name));
        const match = columns.filter((column) => THREAD_COLUMNS.includes(column));
        if (match.length === 0) continue;
        archive.exec(sql.replace(/^CREATE\s+TABLE\s+(IF\s+NOT\s+EXISTS\s+)?/i, "CREATE TABLE IF NOT EXISTS "));
        // A newer T3 may have added columns since the archive table was created.
        const have = new Set(archive.prepare(`SELECT name FROM pragma_table_info(?)`).all(name).map((c) => String(c.name)));
        for (const column of columns) {
          if (!have.has(column)) archive.exec(`ALTER TABLE ${quote(name)} ADD COLUMN ${quote(column)}`);
        }
        tables.push({ name, columns, match });
      }
      // T3's own indexes, so lookups by thread id and the count check stay fast as the archive grows.
      const names = JSON.stringify(tables.map((table) => table.name));
      const indexes = source
        .prepare("SELECT sql FROM sqlite_master WHERE type = 'index' AND sql IS NOT NULL AND tbl_name IN (SELECT value FROM json_each(?))")
        .all(names);
      for (const index of indexes) {
        archive.exec(String(index.sql).replace(/^CREATE\s+(UNIQUE\s+)?INDEX\s+(IF\s+NOT\s+EXISTS\s+)?/i, "CREATE $1INDEX IF NOT EXISTS "));
      }
      return new GroupArchive(source, archive, tables);
    } catch (error) {
      source.close();
      archive.close();
      throw error;
    }
  }

  /**
   * Copies every row naming one of the groups' threads and records the groups, in one archive
   * transaction over one consistent read of T3's database. Throws, writing nothing, if any table's
   * archived rows fall short of T3's; nothing may be deleted then.
   */
  archive(groups: readonly ArchivedGroup[], now: number): { readonly rows: number } {
    const ids = JSON.stringify(groups.flatMap((group) => group.threadIds));
    const where = (table: CopiedTable) =>
      table.match.map((column) => `${quote(column)} IN (SELECT value FROM json_each(:ids))`).join(" OR ");
    let rows = 0;
    this.#source.exec("BEGIN");
    this.#archive.exec("BEGIN IMMEDIATE");
    try {
      for (const table of this.#tables) {
        const columns = table.columns.map(quote).join(", ");
        const select = this.#source.prepare(`SELECT ${columns} FROM ${quote(table.name)} WHERE ${where(table)}`);
        select.setReadBigInts(true);
        const insert = this.#archive.prepare(
          `INSERT OR REPLACE INTO ${quote(table.name)} (${columns}) VALUES (${table.columns.map(() => "?").join(", ")})`,
        );
        let copied = 0;
        for (const row of select.iterate({ ids })) {
          insert.run(...table.columns.map((column): SQLInputValue => row[column] ?? null));
          copied += 1;
        }
        const count = `SELECT count(*) AS n FROM ${quote(table.name)} WHERE ${where(table)}`;
        const archived = Number(this.#archive.prepare(count).get({ ids })?.n ?? 0);
        if (archived < copied) throw new Error(`${table.name}: archived ${archived} rows of ${copied}`);
        rows += copied;
      }
      const record = this.#archive.prepare(
        `INSERT INTO archived_groups
           (root_thread_id, title, parent_thread_id, parent_title, builder_number, thread_ids, last_active_at, archived_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (root_thread_id) DO UPDATE SET title = excluded.title, parent_thread_id = excluded.parent_thread_id,
           parent_title = excluded.parent_title, thread_ids = excluded.thread_ids,
           last_active_at = excluded.last_active_at, archived_at = excluded.archived_at`,
      );
      for (const group of groups) {
        const number = /^builder-(\d+)/i.exec(group.title)?.[1];
        record.run(
          group.rootThreadId,
          group.title,
          group.parentThreadId,
          group.parentTitle,
          number === undefined ? null : Number(number),
          JSON.stringify(group.threadIds),
          new Date(group.lastActiveAt).toISOString(),
          new Date(now).toISOString(),
        );
      }
      this.#archive.exec("COMMIT");
    } catch (error) {
      this.#archive.exec("ROLLBACK");
      throw error;
    } finally {
      this.#source.exec("COMMIT");
    }
    return { rows };
  }

  /** Records how many of a group's threads T3 deleted; deleted_at is set once all of them are. */
  markDeleted(rootThreadId: string, deletedThreads: number, complete: boolean, now: number): void {
    this.#archive
      .prepare("UPDATE archived_groups SET deleted_threads = ?, deleted_at = ? WHERE root_thread_id = ?")
      .run(deletedThreads, complete ? new Date(now).toISOString() : null, rootThreadId);
  }

  /** Records a worktree's outcome; a retry that finds no branch or HEAD keeps the ones recorded first. */
  recordWorktree(worktree: ArchivedWorktree, now: number): void {
    const at = new Date(now).toISOString();
    this.#archive
      .prepare(
        `INSERT INTO archived_worktrees (path, thread_ids, branch, head, removed_at, kept_reason, recorded_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)
         ON CONFLICT (path) DO UPDATE SET thread_ids = excluded.thread_ids,
           branch = coalesce(excluded.branch, archived_worktrees.branch), head = coalesce(excluded.head, archived_worktrees.head),
           removed_at = excluded.removed_at, kept_reason = excluded.kept_reason, recorded_at = excluded.recorded_at`,
      )
      .run(
        worktree.path,
        JSON.stringify(worktree.threadIds),
        worktree.branch,
        worktree.head,
        worktree.keptReason === null ? at : null,
        worktree.keptReason,
        at,
      );
  }

  /** Worktrees recorded as kept (not removed), to retry: their threads are already deleted. */
  keptWorktrees(): { readonly path: string; readonly threadIds: readonly string[] }[] {
    return this.#archive
      .prepare("SELECT path, thread_ids FROM archived_worktrees WHERE removed_at IS NULL ORDER BY recorded_at")
      .all()
      .map((row) => ({ path: String(row.path), threadIds: stringArray(JSON.parse(String(row.thread_ids))) }));
  }

  close(): void {
    this.#source.close();
    this.#archive.close();
  }
}

/** A JSON array of strings, as this archive writes thread_ids. */
function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : [];
}
