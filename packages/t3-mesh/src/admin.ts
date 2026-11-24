// `t3-mesh admin ...`: the mesh admin's commands (SPEC.md section 14.6), run on the admin's machine.
// The admin key signs grants and revocations; it lives in the macOS Keychain (elsewhere a 0600 file).
import { execFile, spawn } from "node:child_process";
import type { KeyObject } from "node:crypto";
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { parseArgs, promisify } from "node:util";
import * as Schema from "effect/Schema";
import { loadConfig } from "./config.ts";
import { EntrySchema, SignedSchema, issueGrant, openRevocation, signRevocation, verifyEntry } from "./identity/grant.ts";
import { exportPrivateKey, fingerprint, generatePrivateKey, importPrivateKey, publicKeyFromRaw, rawPublicKey } from "./identity/keys.ts";
import { expandScopes } from "./identity/scopes.ts";
import { readPrivateFile } from "./privateFile.ts";

const run = promisify(execFile);

export const adminUsage = `  admin init [--mesh <name>] [--key-file <path>]
  admin key [--mesh <name>] [--key-file <path>]
  admin pair <connector id> --scope <scope> [--scope ...] [--ttl 10m] --router <url> [--mesh <name>] [--key-file <path>]
  admin revoke <connector id> [--config ~/.t3-mesh/config.json] [--mesh <name>] [--key-file <path>]
  admin list [--config ~/.t3-mesh/config.json]`;

export class AdminUsageError extends Error {}

const KEYCHAIN_SERVICE = "t3-mesh-admin";
const MAX_TTL_MS = 24 * 60 * 60 * 1000;

interface KeyLocation {
  readonly mesh: string;
  /** Explicit key file; otherwise the Keychain on macOS and ~/.t3-mesh-admin/<mesh>.key elsewhere. */
  readonly keyFile: string | undefined;
}

const defaultKeyFile = (mesh: string): string => join(homedir(), ".t3-mesh-admin", `${mesh}.key`);
const useKeychain = (location: KeyLocation): boolean => location.keyFile === undefined && process.platform === "darwin";

/** `security -i` reads its command from stdin, so the key never appears in a process list. */
async function securityInteractive(command: string): Promise<void> {
  const child = spawn("security", ["-i"], { stdio: ["pipe", "ignore", "pipe"] });
  let stderr = "";
  child.stderr.on("data", (chunk: Buffer) => (stderr += chunk.toString("utf8")));
  child.stdin.end(`${command}\n`);
  const code = await new Promise<number | null>((resolve) => child.on("close", resolve));
  if (code !== 0 || stderr.trim() !== "") throw new Error(`security failed: ${stderr.trim() || `exit ${code}`}`);
}

async function loadAdminKey(location: KeyLocation): Promise<KeyObject> {
  if (useKeychain(location)) {
    const found = await run("security", ["find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", location.mesh, "-w"]).catch(() => null);
    if (found === null) throw new Error(`no admin key for mesh ${location.mesh} in the Keychain; run t3-mesh admin init`);
    return importPrivateKey(found.stdout.trim(), "ed25519");
  }
  const file = location.keyFile ?? defaultKeyFile(location.mesh);
  if (!existsSync(file)) throw new Error(`no admin key at ${file}; run t3-mesh admin init`);
  return importPrivateKey(readPrivateFile(file), "ed25519");
}

async function createAdminKey(location: KeyLocation): Promise<KeyObject> {
  const exists = await loadAdminKey(location).then(
    () => true,
    () => false,
  );
  if (exists) throw new Error(`an admin key for mesh ${location.mesh} already exists; refusing to replace it`);
  const key = generatePrivateKey("ed25519");
  const exported = exportPrivateKey(key);
  if (useKeychain(location)) {
    // base64url has no characters the security command parser treats specially.
    await securityInteractive(
      `add-generic-password -s ${KEYCHAIN_SERVICE} -a ${location.mesh} -l "t3-mesh admin key (${location.mesh})" -w ${exported}`,
    );
  } else {
    const file = location.keyFile ?? defaultKeyFile(location.mesh);
    mkdirSync(join(file, ".."), { recursive: true, mode: 0o700 });
    writeFileSync(file, exported + "\n", { mode: 0o600, flag: "wx" });
  }
  return key;
}

export function parseTtl(text: string): number {
  const match = /^(\d+)([smh])$/.exec(text);
  if (match?.[1] === undefined) throw new AdminUsageError(`--ttl must look like 30s, 10m or 1h, got ${text}`);
  const unitMs = match[2] === "s" ? 1000 : match[2] === "m" ? 60_000 : 3_600_000;
  const ms = Number(match[1]) * unitMs;
  if (ms <= 0 || ms > MAX_TTL_MS) throw new AdminUsageError("--ttl must be more than 0 and at most 24h");
  return ms;
}

const Directory = Schema.Struct({
  adminKey: Schema.String,
  entries: Schema.Array(EntrySchema),
  revocations: Schema.Array(SignedSchema),
});

async function postJson(url: string, body: unknown): Promise<unknown> {
  const response = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(15_000),
  });
  const parsed: unknown = await response.json().catch(() => null);
  if (!response.ok) throw new Error(`${url}: HTTP ${response.status} ${JSON.stringify(parsed)}`);
  return parsed;
}

/** The directory, read with this machine's connector token. */
async function fetchDirectory(configPath: string): Promise<{ readonly routerUrl: string; readonly directory: typeof Directory.Type }> {
  const config = loadConfig(configPath);
  if (config.router.mode !== "http") throw new Error(`${configPath} uses a loopback router`);
  const response = await fetch(`${config.router.url}/v1/directory`, {
    headers: { authorization: `Bearer ${config.router.token}` },
    signal: AbortSignal.timeout(15_000),
  });
  if (!response.ok) throw new Error(`directory: HTTP ${response.status} ${await response.text()}`);
  return { routerUrl: config.router.url, directory: Schema.decodeUnknownSync(Directory)(await response.json()) };
}

/** Current identity per connector, checked against `adminKey`, with whether it was revoked. */
function currentIdentities(directory: typeof Directory.Type, adminKey: KeyObject) {
  const revoked = new Set(
    directory.revocations.flatMap((signed) => {
      const revocation = openRevocation(signed, adminKey);
      return revocation === null ? [] : [revocation.grantId];
    }),
  );
  const current = new Map<string, { identity: Extract<ReturnType<typeof verifyEntry>, { ok: true }>["identity"]; revoked: boolean }>();
  for (const entry of directory.entries) {
    const verified = verifyEntry(entry, adminKey);
    if (!verified.ok) continue;
    const previous = current.get(verified.identity.connectorId);
    if (previous !== undefined && Date.parse(previous.identity.issuedAt) > Date.parse(verified.identity.issuedAt)) continue;
    current.set(verified.identity.connectorId, { identity: verified.identity, revoked: revoked.has(verified.identity.grantId) });
  }
  return current;
}

const say = (line: string) => process.stdout.write(`${line}\n`);
const note = (line: string) => process.stderr.write(`${line}\n`);

export async function runAdminCommand(args: readonly string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args: [...args],
    allowPositionals: true,
    options: {
      mesh: { type: "string", default: "default" },
      "key-file": { type: "string" },
      scope: { type: "string", multiple: true, default: [] },
      ttl: { type: "string", default: "10m" },
      router: { type: "string" },
      config: { type: "string", default: join(homedir(), ".t3-mesh", "config.json") },
    },
  });
  const location: KeyLocation = { mesh: values.mesh, keyFile: values["key-file"] };
  if (!/^[a-z0-9][a-z0-9._-]{0,31}$/.test(location.mesh)) throw new AdminUsageError("--mesh must match [a-z0-9][a-z0-9._-]{0,31}");
  const [subcommand, argument] = positionals;

  if (subcommand === "init") {
    const key = await createAdminKey(location);
    const raw = rawPublicKey(key);
    say(raw);
    note(`created the admin key for mesh ${location.mesh} (fingerprint ${fingerprint(raw)}${useKeychain(location) ? ", in the Keychain" : ""})`);
    note(`pin it on the router: t3-mesh router serve ... --admin-key ${raw}`);
  } else if (subcommand === "key") {
    const raw = rawPublicKey(await loadAdminKey(location));
    say(raw);
    note(`fingerprint ${fingerprint(raw)}`);
  } else if (subcommand === "pair") {
    if (argument === undefined) throw new AdminUsageError("admin pair needs a connector id");
    if (values.router === undefined) throw new AdminUsageError("admin pair needs --router <url>");
    const scopes = expandScopes(values.scope);
    const issued = issueGrant(await loadAdminKey(location), argument, scopes, parseTtl(values.ttl));
    await postJson(`${new URL(values.router).origin}/v1/grants`, issued.signed);
    note(`grant ${issued.grant.id} for ${argument}: ${scopes.join(" ")}; pair by ${issued.grant.pairBy}`);
    note("pairing code (one use; pipe it into `t3-mesh init --pair` on the connector's host):");
    say(issued.code);
  } else if (subcommand === "revoke") {
    if (argument === undefined) throw new AdminUsageError("admin revoke needs a connector id");
    const adminKey = await loadAdminKey(location);
    const { routerUrl, directory } = await fetchDirectory(values.config);
    const current = currentIdentities(directory, publicKeyFromRaw(rawPublicKey(adminKey), "ed25519")).get(argument);
    if (current === undefined) throw new Error(`${argument} has no paired entry`);
    if (current.revoked) {
      say(`${argument}'s current grant is already revoked`);
      return;
    }
    await postJson(`${routerUrl}/v1/revocations`, signRevocation(adminKey, argument, current.identity.grantId));
    say(`revoked ${argument} (grant ${current.identity.grantId})`);
  } else if (subcommand === "list") {
    const { directory } = await fetchDirectory(values.config);
    // Check against our own admin key when this machine has it; the router's copy proves nothing.
    const local = await loadAdminKey(location).then(
      (key) => rawPublicKey(key),
      () => null,
    );
    if (local !== null && local !== directory.adminKey) throw new Error("the router serves a different admin key than this machine's");
    const adminKey = publicKeyFromRaw(local ?? directory.adminKey, "ed25519");
    note(`admin key ${fingerprint(local ?? directory.adminKey)}${local === null ? " (as served by the router; no local admin key to check it against)" : ""}`);
    for (const [connectorId, { identity, revoked }] of [...currentIdentities(directory, adminKey)].sort(([a], [b]) => a.localeCompare(b))) {
      say(
        `${connectorId}${revoked ? " (revoked)" : ""}  paired ${identity.issuedAt}  sign ${fingerprint(identity.signingKey)}  ` +
          `enc ${fingerprint(identity.encryptionKey)}  ${identity.scopes.join(" ")}`,
      );
    }
  } else {
    throw new AdminUsageError(`unknown admin command ${positionals.join(" ")}`);
  }
}
