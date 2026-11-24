// The connector's T3 credential: a bearer token narrowed to orchestration:read + orchestration:operate.
// T3 access tokens last 30 days and a narrowed token cannot mint another, so issuing and renewing
// use a 5-minute administrative session from the local `t3` CLI (the connector runs as the
// instance's own OS user), which is revoked right after. Previous connector tokens are revoked too,
// through the CLI: T3 0.1.8 dropped the GET /api/auth/clients listing, and its SPA fallback answers
// that path with HTML.
import { execFile } from "node:child_process";
import { existsSync, readdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";
import * as Schema from "effect/Schema";

const run = promisify(execFile);

export const CONNECTOR_SCOPES = ["orchestration:read", "orchestration:operate"] as const;
/** Renew when less than this much lifetime is left. */
export const RENEW_BEFORE_MS = 7 * 24 * 60 * 60 * 1000;

const AdminSession = Schema.Struct({ sessionId: Schema.String, token: Schema.String });
const PairingCredential = Schema.Struct({ credential: Schema.String });
const AccessToken = Schema.Struct({ access_token: Schema.String, expires_in: Schema.Number, scope: Schema.String });
const ClientSessions = Schema.Array(
  Schema.Struct({
    sessionId: Schema.String,
    issuedAt: Schema.String,
    client: Schema.Struct({ label: Schema.optionalKey(Schema.String) }),
  }),
);
const TokenFile = Schema.Struct({ token: Schema.String, expiresAt: Schema.String });
export type StoredToken = typeof TokenFile.Type;

export interface IssuedToken {
  readonly stored: StoredToken;
  /** Older same-label sessions revoked after the new token was written. */
  readonly revoked: number;
  /** Why revoking older sessions failed. The new token is in place regardless. */
  readonly cleanupError?: string;
}

const decodeTokenFile = Schema.decodeUnknownSync(TokenFile);

export interface T3Cli {
  /** Path to the `t3` binary. */
  readonly bin: string;
  /** T3CODE_HOME of the instance, e.g. ~/.t3. */
  readonly home: string;
}

/** `t3` on PATH, else the newest binary under <home>/runtime/versions. */
export function findT3Bin(home: string, configured: string | undefined): string {
  if (configured !== undefined) return configured;
  for (const dir of (process.env.PATH ?? "").split(":")) {
    if (dir !== "" && existsSync(join(dir, "t3"))) return join(dir, "t3");
  }
  const versions = join(home, "runtime", "versions");
  const newest = existsSync(versions)
    ? readdirSync(versions)
        .filter((version) => existsSync(join(versions, version, "t3")))
        .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }))
        .at(-1)
    : undefined;
  if (newest === undefined) throw new Error(`no t3 binary on PATH or under ${versions}; set t3.bin in config.json`);
  return join(versions, newest, "t3");
}

export function readStoredToken(path: string): StoredToken {
  return decodeTokenFile(JSON.parse(readFileSync(path, "utf8")));
}

export const needsRenewal = (stored: StoredToken, now = Date.now()): boolean =>
  Date.parse(stored.expiresAt) - now < RENEW_BEFORE_MS;

/** The JSON body of a successful response; anything else (an error status, an HTML fallback page) throws. */
async function readJson(response: Response, what: string): Promise<unknown> {
  if (!response.ok) throw new Error(`${what}: HTTP ${response.status}`);
  const type = response.headers.get("content-type") ?? "";
  if (!type.includes("application/json")) throw new Error(`${what}: expected JSON, got ${type || "no content-type"}`);
  return response.json();
}

async function postJson(url: string, token: string, body: unknown): Promise<unknown> {
  const response = await fetch(url, {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return readJson(response, `POST ${new URL(url).pathname}`);
}

/** Revokes every session labelled `label` except the newest, which is the one just issued. */
async function revokeOlderSessions(cli: T3Cli, label: string): Promise<number> {
  const { stdout } = await run(cli.bin, ["auth", "session", "list", "--base-dir", cli.home, "--json"]);
  const older = Schema.decodeUnknownSync(ClientSessions)(JSON.parse(stdout))
    .filter((session) => session.client.label === label)
    .sort((a, b) => Date.parse(a.issuedAt) - Date.parse(b.issuedAt))
    .slice(0, -1);
  for (const session of older) {
    await run(cli.bin, ["auth", "session", "revoke", "--base-dir", cli.home, session.sessionId]);
  }
  return older.length;
}

/**
 * Issues a fresh narrowed token, writes it to `path` (0600), then revokes older tokens with the same
 * label. A failed revoke is reported in `cleanupError` rather than thrown, since the new token is
 * already in place; the next renewal retries it.
 */
export async function issueConnectorToken(
  cli: T3Cli,
  baseUrl: string,
  label: string,
  path: string,
): Promise<IssuedToken> {
  const { stdout } = await run(cli.bin, [
    "auth",
    "session",
    "issue",
    "--base-dir",
    cli.home,
    "--ttl",
    "5m",
    "--label",
    `${label} (bootstrap)`,
    "--json",
  ]);
  const admin = Schema.decodeUnknownSync(AdminSession)(JSON.parse(stdout));
  try {
    const pairing = Schema.decodeUnknownSync(PairingCredential)(
      await postJson(`${baseUrl}/api/auth/pairing-token`, admin.token, { label, scopes: CONNECTOR_SCOPES }),
    );
    const exchange = await fetch(`${baseUrl}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "urn:ietf:params:oauth:grant-type:token-exchange",
        subject_token: pairing.credential,
        subject_token_type: "urn:t3:params:oauth:token-type:environment-bootstrap",
        requested_token_type: "urn:ietf:params:oauth:token-type:access_token",
        client_label: label,
      }),
    });
    const access = Schema.decodeUnknownSync(AccessToken)(await readJson(exchange, "POST /oauth/token"));
    const granted = new Set(access.scope.split(" "));
    if (granted.size !== CONNECTOR_SCOPES.length || !CONNECTOR_SCOPES.every((scope) => granted.has(scope))) {
      throw new Error(`T3 granted unexpected scopes: ${access.scope}`);
    }
    const stored: StoredToken = {
      token: access.access_token,
      expiresAt: new Date(Date.now() + access.expires_in * 1000).toISOString(),
    };
    const temp = `${path}.tmp`;
    writeFileSync(temp, JSON.stringify(stored) + "\n", { mode: 0o600 });
    renameSync(temp, path);

    try {
      return { stored, revoked: await revokeOlderSessions(cli, label) };
    } catch (error) {
      return { stored, revoked: 0, cleanupError: error instanceof Error ? error.message : String(error) };
    }
  } finally {
    await run(cli.bin, ["auth", "session", "revoke", "--base-dir", cli.home, admin.sessionId]).catch(() => undefined);
  }
}
