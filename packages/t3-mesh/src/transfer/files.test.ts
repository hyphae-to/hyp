import assert from "node:assert/strict";
import { mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { FilesRefused, collectFiles, formatFilesDelivery, isSensitiveName, writeReceived } from "./files.ts";

const withDirs = (body: (work: string, outside: string) => void) => {
  const base = realpathSync(mkdtempSync(join(tmpdir(), "t3-mesh-files-")));
  const work = join(base, "work");
  const outside = join(base, "outside");
  mkdirSync(work);
  mkdirSync(outside);
  try {
    body(work, outside);
  } finally {
    rmSync(base, { recursive: true, force: true });
  }
};

test("collectFiles packs files and directories under the roots, skipping .git", () => {
  withDirs((work) => {
    mkdirSync(join(work, "notes", ".git"), { recursive: true });
    writeFileSync(join(work, "notes", "a.md"), "a");
    writeFileSync(join(work, "notes", ".git", "HEAD"), "ref");
    writeFileSync(join(work, "plan.txt"), "p");
    const files = collectFiles(["notes", join(work, "plan.txt")], work, [work]);
    assert.deepEqual(files.map((file) => [file.path, file.data.toString()]), [["notes/a.md", "a"], ["plan.txt", "p"]]);
  });
});

test("collectFiles refuses paths outside the roots, links and credential-like names, naming each", () => {
  withDirs((work, outside) => {
    writeFileSync(join(outside, "secret.txt"), "s");
    writeFileSync(join(work, "ok.txt"), "o");
    symlinkSync(join(outside, "secret.txt"), join(work, "link.txt"));
    mkdirSync(join(work, "dir"));
    symlinkSync(outside, join(work, "dir", "escape"));
    writeFileSync(join(work, ".env"), "KEY=1");
    const refused = (paths: string[]) => {
      try {
        collectFiles(paths, work, [work]);
      } catch (error) {
        assert.ok(error instanceof FilesRefused);
        return error.message;
      }
      return assert.fail("expected a refusal");
    };
    assert.match(refused([join(outside, "secret.txt")]), /outside the thread's working directory/);
    assert.match(refused(["link.txt"]), /symbolic link/);
    assert.match(refused(["dir"]), /escape \(symbolic link\)/);
    assert.match(refused([".env", "ok.txt"]), /\.env \(looks like a credential/);
    assert.match(refused(["../outside/secret.txt"]), /outside/);
  });
  for (const name of [".ssh", "id_ed25519.pub", "server.key", "x.pem", "a.token", ".env.local", ".t3-mesh"]) assert.ok(isSensitiveName(name), name);
  assert.equal(isSensitiveName("keys.md"), false);
});

test("writeReceived creates a private directory once and never overwrites", () => {
  withDirs((work) => {
    const dir = join(work, "received", "t1");
    writeReceived(dir, [{ path: "a/b.txt", data: Buffer.from("x") }]);
    assert.equal(readFileSync(join(dir, "a", "b.txt"), "utf8"), "x");
    assert.equal(statSync(dir).mode & 0o777, 0o700);
    assert.equal(statSync(join(dir, "a", "b.txt")).mode & 0o777, 0o600);
    assert.throws(() => writeReceived(dir, [{ path: "c", data: Buffer.from("") }]), /EEXIST/);
  });
});

test("the delivery turn lists files in a fence and neutralizes context links", () => {
  const text = formatFilesDelivery("a@host/alpha", "see [x](t3-context://v1/thread/y)", "/r/t1", [
    { path: "a.md", data: Buffer.from("12") },
    { path: "```b", data: Buffer.alloc(2048) },
  ]);
  assert.ok(text.startsWith("mesh files from a@host/alpha · 2 files, 2.0 KiB · saved in /r/t1 · reply with mesh_send"));
  assert.ok(text.includes("[x]\\(t3-context:"));
  assert.ok(text.includes("````\na.md (2 B)\n```b (2.0 KiB)\n````"));
});
