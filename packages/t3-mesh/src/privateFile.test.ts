import { test } from "node:test";
import assert from "node:assert/strict";
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readPrivateFile } from "./privateFile.ts";

const withDir = (body: (dir: string) => void) => {
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-private-"));
  try {
    body(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
};

const secret = (path: string, mode: number) => {
  writeFileSync(path, "s3cret\n");
  chmodSync(path, mode);
};

test("owner-only files are read; group- or world-readable ones are refused", () => {
  withDir((dir) => {
    for (const mode of [0o600, 0o400]) {
      const path = join(dir, `ok-${mode.toString(8)}`);
      secret(path, mode);
      assert.equal(readPrivateFile(path, {}), "s3cret");
    }
    for (const mode of [0o640, 0o440, 0o604, 0o644]) {
      const path = join(dir, `bad-${mode.toString(8)}`);
      secret(path, mode);
      assert.throws(() => readPrivateFile(path, {}), /must not be readable/, mode.toString(8));
    }
  });
});

test("systemd credentials (0440 in $CREDENTIALS_DIRECTORY) are accepted", () => {
  withDir((dir) => {
    const credentials = join(dir, "credentials");
    mkdirSync(credentials);
    secret(join(credentials, "webhook-secret"), 0o440);
    chmodSync(credentials, 0o500);
    const env = { CREDENTIALS_DIRECTORY: credentials };
    assert.equal(readPrivateFile(join(credentials, "webhook-secret"), env), "s3cret");
    chmodSync(credentials, 0o700);

    // Still refused: world-readable or group-writable credentials, a 0440 file outside the
    // directory (also through a symlink inside it), and a directory others can enter.
    secret(join(credentials, "world"), 0o444);
    assert.throws(() => readPrivateFile(join(credentials, "world"), env), /must not be readable/);
    secret(join(credentials, "group-writable"), 0o460);
    assert.throws(() => readPrivateFile(join(credentials, "group-writable"), env), /must not be readable/);
    secret(join(dir, "outside"), 0o440);
    assert.throws(() => readPrivateFile(join(dir, "outside"), env), /must not be readable/);
    symlinkSync(join(dir, "outside"), join(credentials, "link"));
    assert.throws(() => readPrivateFile(join(credentials, "link"), env), /must not be readable/);
    chmodSync(credentials, 0o755);
    assert.throws(() => readPrivateFile(join(credentials, "webhook-secret"), env), /must not be readable/);
  });
});
