import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { GroupArchive, worktreesOfOtherThreads } from "./reapArchive.ts";

// A small stand-in for T3's state database: thread-keyed tables, the old event log, a table with no
// thread column and an FTS table, each of which the archive must copy or skip.
function makeSource(dir: string): string {
  const path = join(dir, "statev2.sqlite");
  const db = new DatabaseSync(path);
  db.exec(`
    CREATE TABLE orchestration_v2_projection_messages (message_id TEXT PRIMARY KEY, thread_id TEXT NOT NULL, body BLOB, n INTEGER);
    CREATE INDEX idx_messages_thread ON orchestration_v2_projection_messages (thread_id);
    CREATE TABLE orchestration_v2_projection_subagents (id TEXT PRIMARY KEY, thread_id TEXT, child_thread_id TEXT);
    CREATE TABLE orchestration_events (sequence INTEGER PRIMARY KEY, stream_id TEXT, payload TEXT);
    CREATE TABLE projection_projects (project_id TEXT PRIMARY KEY, title TEXT);
    CREATE VIRTUAL TABLE message_search USING fts5(body);
    INSERT INTO orchestration_v2_projection_messages VALUES
      ('m1', 'b', x'00ff', 9007199254740993), ('m2', 'r', 'review', 2), ('m3', 'lead', 'keep', 3);
    INSERT INTO orchestration_v2_projection_subagents VALUES ('s1', 'lead', 'b'), ('s2', 'lead', 'other');
    INSERT INTO orchestration_events VALUES (1, 'b', '{}'), (2, 'lead', '{}');
    INSERT INTO projection_projects VALUES ('p', 'Project');
  `);
  db.close();
  return path;
}

const BUILDER = {
  rootThreadId: "b",
  title: "builder-4482: lending docs",
  parentThreadId: "lead",
  parentTitle: "Bayfold Lead Gen1",
  threadIds: ["r", "b"],
  lastActiveAt: Date.parse("2026-10-20T00:00:00Z"),
};

test("archive: copies every row naming the threads, exactly, and indexes the builder", () => {
  const dir = mkdtempSync(join(tmpdir(), "reap-archive-"));
  try {
    const archive = GroupArchive.open(makeSource(dir), join(dir, "builders.sqlite"));
    assert.deepEqual(archive.archive([BUILDER], Date.parse("2026-11-13T00:00:00Z")), { rows: 4 });
    archive.markDeleted("b", 2, true, Date.parse("2026-11-13T00:01:00Z"));
    archive.recordWorktree({ path: "/w/b", threadIds: ["b", "r"], branch: "t3/docs", head: "abc", keptReason: null }, Date.parse("2026-11-13T00:02:00Z"));
    archive.close();

    const db = new DatabaseSync(join(dir, "builders.sqlite"), { readOnly: true });
    db.prepare("SELECT 1").get();
    const messages = db.prepare("SELECT message_id, thread_id, body, n FROM orchestration_v2_projection_messages ORDER BY message_id");
    messages.setReadBigInts(true);
    assert.deepEqual(
      messages.all().map((row) => ({ ...row })),
      [
        { message_id: "m1", thread_id: "b", body: new Uint8Array([0, 255]), n: 9007199254740993n },
        { message_id: "m2", thread_id: "r", body: "review", n: 2n },
      ],
    );
    assert.deepEqual(db.prepare("SELECT id FROM orchestration_v2_projection_subagents").all().map((r) => r.id), ["s1"]);
    assert.deepEqual(db.prepare("SELECT sequence FROM orchestration_events").all().map((r) => r.sequence), [1]);
    const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all().map((r) => r.name);
    assert.ok(!tables.includes("projection_projects") && !tables.includes("message_search"), "no thread column, or FTS");
    assert.ok(db.prepare("SELECT 1 FROM sqlite_master WHERE name = 'idx_messages_thread'").get(), "T3's index copied");
    assert.deepEqual(
      { ...db.prepare("SELECT parent_title, builder_number, thread_ids, deleted_at, deleted_threads FROM archived_groups").get() },
      { parent_title: "Bayfold Lead Gen1", builder_number: 4482, thread_ids: '["r","b"]', deleted_at: "2026-11-13T00:01:00.000Z", deleted_threads: 2 },
    );
    assert.deepEqual(
      { ...db.prepare("SELECT branch, head, removed_at, kept_reason FROM archived_worktrees").get() },
      { branch: "t3/docs", head: "abc", removed_at: "2026-11-13T00:02:00.000Z", kept_reason: null },
    );
    db.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("archive: a second run adds what a newer T3 added, and re-archiving a builder does not duplicate it", () => {
  const dir = mkdtempSync(join(tmpdir(), "reap-archive-"));
  try {
    const source = makeSource(dir);
    const first = GroupArchive.open(source, join(dir, "builders.sqlite"));
    first.archive([BUILDER], 1);
    first.close();

    const db = new DatabaseSync(source);
    db.exec("ALTER TABLE orchestration_v2_projection_messages ADD COLUMN streaming INTEGER DEFAULT 0");
    db.exec("INSERT INTO orchestration_v2_projection_messages VALUES ('m4', 'r', 'late', 4, 1)");
    db.close();
    const second = GroupArchive.open(source, join(dir, "builders.sqlite"));
    assert.deepEqual(second.archive([BUILDER], 2), { rows: 5 });
    second.close();

    const archived = new DatabaseSync(join(dir, "builders.sqlite"), { readOnly: true });
    assert.deepEqual(
      archived.prepare("SELECT message_id, streaming FROM orchestration_v2_projection_messages ORDER BY message_id").all().map((r) => [r.message_id, r.streaming]),
      [["m1", 0], ["m2", 0], ["m4", 1]],
    );
    assert.equal(archived.prepare("SELECT count(*) AS n FROM archived_groups").get()?.n, 1);
    archived.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("archive: worktrees of live threads the shell does not list are read from T3's database", () => {
  const dir = mkdtempSync(join(tmpdir(), "reap-archive-"));
  try {
    const path = join(dir, "statev2.sqlite");
    const db = new DatabaseSync(path);
    db.exec(`CREATE TABLE orchestration_v2_projection_threads (thread_id TEXT PRIMARY KEY, deleted_at TEXT, payload_json TEXT);
      INSERT INTO orchestration_v2_projection_threads VALUES
        ('archived', NULL, '{"worktreePath":"/w/heron"}'), ('listed', NULL, '{"worktreePath":"/w/b"}'),
        ('gone', '2026-11-01', '{"worktreePath":"/w/old"}'), ('no-worktree', NULL, '{"worktreePath":null}');`);
    db.close();
    assert.deepEqual(worktreesOfOtherThreads(path, new Set(["listed"])), ["/w/heron"]);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("archive: an archive from before groups (archived_builders) is renamed in place, rows kept", () => {
  const dir = mkdtempSync(join(tmpdir(), "reap-archive-"));
  try {
    const path = join(dir, "threads.sqlite");
    const old = new DatabaseSync(path);
    old.exec(`CREATE TABLE archived_builders (builder_thread_id TEXT PRIMARY KEY, title TEXT NOT NULL, builder_number INTEGER,
        thread_ids TEXT NOT NULL, last_active_at TEXT NOT NULL, archived_at TEXT NOT NULL, deleted_at TEXT,
        deleted_threads INTEGER NOT NULL DEFAULT 0);
      INSERT INTO archived_builders VALUES ('old', 'builder-2338: x', 2338, '["old"]', '2026-10-18', '2026-11-13', '2026-11-13', 1);`);
    old.close();
    const archive = GroupArchive.open(makeSource(dir), path);
    archive.archive([{ ...BUILDER, rootThreadId: "b2", title: "Map RPC usage", threadIds: ["r"] }], 1);
    archive.close();
    const db = new DatabaseSync(path, { readOnly: true });
    assert.deepEqual(
      db.prepare("SELECT root_thread_id, builder_number, parent_title FROM archived_groups ORDER BY root_thread_id").all().map((r) => ({ ...r })),
      [
        { root_thread_id: "b2", builder_number: null, parent_title: "Bayfold Lead Gen1" },
        { root_thread_id: "old", builder_number: 2338, parent_title: null },
      ],
    );
    assert.equal(db.prepare("SELECT 1 FROM sqlite_master WHERE name = 'archived_builders'").get(), undefined);
    db.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("archive: kept worktrees are listed for retry; a retry keeps the branch and HEAD recorded first", () => {
  const dir = mkdtempSync(join(tmpdir(), "reap-archive-"));
  try {
    const archive = GroupArchive.open(makeSource(dir), join(dir, "threads.sqlite"));
    archive.recordWorktree({ path: "/w/a", threadIds: ["a"], branch: "t3/a", head: "aaa", keptReason: "spawn git ENOENT" }, 1);
    archive.recordWorktree({ path: "/w/b", threadIds: ["b"], branch: "t3/b", head: "bbb", keptReason: null }, 2);
    assert.deepEqual(archive.keptWorktrees(), [{ path: "/w/a", threadIds: ["a"] }]);
    // Retried after the folder was already gone: removed, branch and HEAD kept from the first record.
    archive.recordWorktree({ path: "/w/a", threadIds: ["a"], branch: null, head: null, keptReason: null }, 3);
    assert.deepEqual(archive.keptWorktrees(), []);
    archive.close();
    const db = new DatabaseSync(join(dir, "threads.sqlite"), { readOnly: true });
    assert.deepEqual({ ...db.prepare("SELECT branch, head, kept_reason FROM archived_worktrees WHERE path = '/w/a'").get() }, { branch: "t3/a", head: "aaa", kept_reason: null });
    db.close();
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
