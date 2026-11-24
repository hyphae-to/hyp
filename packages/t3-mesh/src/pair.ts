// `t3-mesh pair --config <path>`: pairs an already set-up connector with the router (SPEC.md section
// 14.3), reading the code from stdin. Writes keys.json (once), the new router token and
// identity.adminKey; the T3 token, MCP registration and service unit stay as they are. Restart the
// daemon afterwards (scripts/pair.sh does).
import { readFileSync, renameSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import * as Schema from "effect/Schema";
import { loadConfig } from "./config.ts";
import { keysFor, pairWithRouter, writeKeys } from "./identity/pairClient.ts";

const RouterSection = Schema.Struct({ router: Schema.Struct({ mode: Schema.Literal("http"), tokenFile: Schema.String }) });

/** Writes `text` to `path` (0600) through a temporary file, so a crash leaves the old or the new file. */
function replaceFile(path: string, text: string): void {
  const temporary = `${path}.tmp`;
  writeFileSync(temporary, text, { mode: 0o600 });
  renameSync(temporary, path);
}

export async function pairConnector(configPath: string, code: string): Promise<{ readonly connectorId: string; readonly scopes: readonly string[] }> {
  const path = resolve(configPath);
  const config = loadConfig(path);
  if (config.router.mode !== "http") throw new Error("a loopback connector has no router to pair with");
  const raw: unknown = JSON.parse(readFileSync(path, "utf8"));
  const tokenFile = resolve(config.stateDir, Schema.decodeUnknownSync(RouterSection)(raw).router.tokenFile);

  const keysPath = join(config.stateDir, "keys.json");
  const { keys, created } = keysFor(keysPath);
  // Written before pairing: a pairing that fails halfway leaves keys the next attempt reuses.
  if (created) writeKeys(keysPath, keys);
  const paired = await pairWithRouter(config.router.url, code, keys, config.connectorId);
  // The router has already replaced the old token, so the new one is written before anything else.
  replaceFile(tokenFile, `${paired.token}\n`);
  if (typeof raw !== "object" || raw === null) throw new Error(`${path} is not a JSON object`);
  replaceFile(path, `${JSON.stringify({ ...raw, identity: { adminKey: paired.adminKey } }, null, 2)}\n`);
  return { connectorId: paired.connectorId, scopes: paired.scopes };
}
