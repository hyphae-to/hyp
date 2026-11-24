import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { gitState, workingDirectoryFor } from "./fork.ts";

const git = (cwd: string, ...args: string[]) => execFileSync("git", ["-C", cwd, ...args], { stdio: "pipe" }).toString().trim();

function repos(): { base: string; origin: string; work: string } {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "t3-mesh-fork-")));
  const origin = join(base, "origin.git");
  const work = join(base, "work");
  execFileSync("git", ["init", "-q", "--bare", "-b", "main", origin]);
  execFileSync("git", ["clone", "-q", origin, work], { stdio: "pipe" });
  git(work, "config", "user.email", "t@example.com");
  git(work, "config", "user.name", "t");
  writeFileSync(join(work, "a.txt"), "a");
  git(work, "add", "a.txt");
  git(work, "commit", "-q", "-m", "a");
  git(work, "push", "-q", "-u", "origin", "main");
  return { base, origin, work };
}

test("gitState accepts a clean, pushed branch and refuses uncommitted or unpushed work", async () => {
  const { base, work } = repos();
  try {
    const clean = await gitState(work);
    assert.ok(clean.ok);
    assert.equal(clean.state.branch, "main");
    assert.equal(clean.state.commit, git(work, "rev-parse", "HEAD"));

    writeFileSync(join(work, "b.txt"), "b");
    const dirty = await gitState(work);
    assert.ok(!dirty.ok);
    assert.match(dirty.message, /uncommitted changes/);

    git(work, "add", "b.txt");
    git(work, "commit", "-q", "-m", "b");
    const unpushed = await gitState(work);
    assert.ok(!unpushed.ok);
    assert.match(unpushed.message, /not pushed/);

    git(work, "checkout", "-q", "-b", "topic");
    const noUpstream = await gitState(work);
    assert.ok(!noUpstream.ok);
    assert.match(noUpstream.message, /no upstream/);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});

test("gitState treats a directory outside git as having no git state", async () => {
  const dir = realpathSync(mkdtempSync(join(tmpdir(), "t3-mesh-nogit-")));
  try {
    assert.deepEqual(await gitState(dir), { ok: true, state: { branch: null, commit: null } });
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("workingDirectoryFor finds the worktree that has the branch checked out", async () => {
  const { base, work } = repos();
  try {
    const tree = join(base, "tree");
    git(work, "worktree", "add", "-q", "-b", "feature", tree);
    assert.equal(await workingDirectoryFor(work, "feature"), realpathSync(tree));
    assert.equal(await workingDirectoryFor(work, "missing"), work);
    assert.equal(await workingDirectoryFor(work, null), work);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
});
