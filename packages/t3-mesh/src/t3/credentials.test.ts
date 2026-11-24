import assert from "node:assert/strict";
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, test } from "node:test";
import { issueConnectorToken, readStoredToken } from "./credentials.ts";

const LABEL = "t3-mesh macbook";

interface Fixture {
  readonly dir: string;
  readonly bin: string;
  readonly calls: string;
  readonly baseUrl: string;
  readonly server: Server;
}

let fixture: Fixture;

/** A fake `t3` that logs its argv and answers `session issue` / `session list` from files in `dir`. */
function writeFakeT3(dir: string): string {
  const bin = join(dir, "t3");
  writeFileSync(
    bin,
    `#!/bin/sh
echo "$*" >> "${join(dir, "calls")}"
case "$1 $2 $3" in
  "auth session issue") echo '{"sessionId":"admin-1","token":"admin-token"}' ;;
  "auth session list") cat "${join(dir, "sessions.json")}" ;;
  "auth session revoke") echo "Revoked session $6." ;;
  *) exit 2 ;;
esac
`,
  );
  chmodSync(bin, 0o755);
  return bin;
}

function session(sessionId: string, issuedAt: string, label?: string) {
  return {
    sessionId,
    method: "bearer-session-token",
    scopes: ["orchestration:read", "orchestration:operate"],
    subject: "connector",
    client: label === undefined ? { deviceType: "unknown" } : { label, deviceType: "unknown" },
    connected: false,
    issuedAt,
    expiresAt: "2026-12-06T00:00:00.000Z",
    lastConnectedAt: null,
  };
}

beforeEach(async () => {
  const dir = mkdtempSync(join(tmpdir(), "t3mesh-credentials-"));
  const bin = writeFakeT3(dir);
  // Mimics T3 0.1.8: the auth API routes we use, and the SPA fallback (HTML) for anything else.
  const server = createServer((request, response) => {
    if (request.method === "POST" && request.url === "/api/auth/pairing-token") {
      response.writeHead(200, { "content-type": "application/json" }).end('{"credential":"pairing-1"}');
    } else if (request.method === "POST" && request.url === "/oauth/token") {
      response
        .writeHead(200, { "content-type": "application/json; charset=utf-8" })
        .end('{"access_token":"new-token","expires_in":2592000,"scope":"orchestration:read orchestration:operate"}');
    } else {
      response.writeHead(200, { "content-type": "text/html" }).end("<!doctype html><html></html>");
    }
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  fixture = { dir, bin, calls: join(dir, "calls"), baseUrl: `http://127.0.0.1:${port}`, server };
});

afterEach(async () => {
  await new Promise<void>((resolve) => fixture.server.close(() => resolve()));
  rmSync(fixture.dir, { recursive: true, force: true });
});

const calls = (): string[] => readFileSync(fixture.calls, "utf8").trim().split("\n");
const issue = () =>
  issueConnectorToken({ bin: fixture.bin, home: fixture.dir }, fixture.baseUrl, LABEL, join(fixture.dir, "token.json"));

test("revokes older same-label sessions through the CLI, keeping the newest", async () => {
  writeFileSync(
    join(fixture.dir, "sessions.json"),
    JSON.stringify([
      session("new", "2026-11-06T10:00:00.000Z", LABEL),
      session("old-2", "2026-10-07T10:00:00.000Z", LABEL),
      session("other", "2026-09-01T10:00:00.000Z", "someone else"),
      session("admin-1", "2026-11-06T09:59:59.000Z", `${LABEL} (bootstrap)`),
      session("browser", "2026-09-01T10:00:00.000Z"),
      session("old-1", "2026-09-07T10:00:00.000Z", LABEL),
    ]),
  );
  const result = await issue();
  assert.equal(result.cleanupError, undefined);
  assert.equal(result.revoked, 2);
  assert.equal(result.stored.token, "new-token");
  assert.deepEqual(readStoredToken(join(fixture.dir, "token.json")), result.stored);
  assert.equal(statSync(join(fixture.dir, "token.json")).mode & 0o777, 0o600);

  const revoked = calls()
    .filter((line) => line.startsWith("auth session revoke"))
    .map((line) => line.split(" ").at(-1));
  assert.deepEqual(revoked, ["old-1", "old-2", "admin-1"]);
});

test("a failed cleanup is reported, not thrown, and the new token stays written", async () => {
  writeFileSync(join(fixture.dir, "sessions.json"), "not json");
  const result = await issue();
  assert.equal(result.revoked, 0);
  assert.match(result.cleanupError ?? "", /JSON/);
  assert.equal(readStoredToken(join(fixture.dir, "token.json")).token, "new-token");
  assert.ok(calls().includes(`auth session revoke --base-dir ${fixture.dir} admin-1`));
});

test("an HTML answer from the token routes fails loudly, before any token is written", async () => {
  await assert.rejects(
    issueConnectorToken(
      { bin: fixture.bin, home: fixture.dir },
      `${fixture.baseUrl}/spa`,
      LABEL,
      join(fixture.dir, "token.json"),
    ),
    /POST \/spa\/api\/auth\/pairing-token: expected JSON, got text\/html/,
  );
  assert.throws(() => statSync(join(fixture.dir, "token.json")));
  assert.ok(calls().includes(`auth session revoke --base-dir ${fixture.dir} admin-1`));
});
