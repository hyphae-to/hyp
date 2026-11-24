// `t3-mesh init`: set up the connector for one T3 instance, run as that instance's OS user.
// Creates the state dir, issues the narrowed T3 token, writes config.json, and optionally
// registers the MCP server with Claude and Codex and installs a systemd user unit.
import { execFile } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, writeFileSync } from "node:fs";
import { homedir, hostname, userInfo } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { isConnectorId } from "./address.ts";
import { loadConfig } from "./config.ts";
import { keysFor, pairWithRouter, readCodeFromStdin, writeKeys } from "./identity/pairClient.ts";
import { readPrivateFile } from "./privateFile.ts";
import { findT3Bin, issueConnectorToken } from "./t3/credentials.ts";
import { T3Connection } from "./t3/connection.ts";

const run = promisify(execFile);
const CLI_PATH = fileURLToPath(new URL("./cli.ts", import.meta.url));

export interface InitOptions {
  readonly stateDir: string;
  readonly connectorId: string | undefined;
  readonly t3Url: string;
  readonly t3Home: string;
  readonly t3Bin: string | undefined;
  /** Router URL and a file holding this connector's router token; both absent means loopback. */
  readonly routerUrl: string | undefined;
  readonly routerTokenFile: string | undefined;
  /** Pair with the router using a code read from stdin (SPEC.md section 14.3) instead of a token file. */
  readonly pair: boolean;
  readonly registerMcp: boolean;
  readonly systemd: boolean;
}

const say = (line: string) => process.stdout.write(`${line}\n`);

async function hasCommand(command: string): Promise<boolean> {
  return run("sh", ["-c", `command -v ${command}`]).then(
    () => true,
    () => false,
  );
}

export async function init(options: InitOptions): Promise<void> {
  const stateDir = resolve(options.stateDir);
  let connectorId = options.connectorId ?? `${userInfo().username}@${hostname().split(".")[0]}`;
  if (!isConnectorId(connectorId)) throw new Error(`invalid connector id ${connectorId}`);
  if (options.pair) {
    if (options.routerUrl === undefined || options.routerTokenFile !== undefined) {
      throw new Error("--pair needs --router-url and no --router-token-file (the router issues the token)");
    }
  } else if ((options.routerUrl === undefined) !== (options.routerTokenFile === undefined)) {
    throw new Error("--router-url and --router-token-file go together (omit both for a loopback router)");
  }

  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  chmodSync(stateDir, 0o700);
  let identity: { readonly adminKey: string } | undefined;
  if (options.pair && options.routerUrl !== undefined) {
    const code = readCodeFromStdin();
    const keysPath = join(stateDir, "keys.json");
    const { keys, created } = keysFor(keysPath);
    // Written before pairing: a pairing that fails halfway leaves keys the next attempt reuses.
    if (created) writeKeys(keysPath, keys);
    const paired = await pairWithRouter(options.routerUrl, code, keys, options.connectorId);
    connectorId = paired.connectorId;
    writeFileSync(join(stateDir, "router.token"), paired.token + "\n", { mode: 0o600 });
    chmodSync(join(stateDir, "router.token"), 0o600);
    identity = { adminKey: paired.adminKey };
    say(`paired as ${connectorId} (${paired.scopes.join(" ")})`);
  } else if (options.routerTokenFile !== undefined) {
    readPrivateFile(options.routerTokenFile);
    copyFileSync(options.routerTokenFile, join(stateDir, "router.token"));
    chmodSync(join(stateDir, "router.token"), 0o600);
  }
  const t3Home = resolve(options.t3Home);
  writeFileSync(
    join(stateDir, "config.json"),
    JSON.stringify(
      {
        connectorId,
        t3: { url: options.t3Url, home: t3Home, ...(options.t3Bin === undefined ? {} : { bin: options.t3Bin }) },
        router:
          options.routerUrl === undefined
            ? { mode: "loopback" }
            : { mode: "http", url: options.routerUrl, tokenFile: "router.token" },
        ...(identity === undefined ? {} : { identity }),
      },
      null,
      2,
    ) + "\n",
    { mode: 0o600 },
  );
  say(`wrote ${join(stateDir, "config.json")} (connector ${connectorId})`);

  const config = loadConfig(join(stateDir, "config.json"));
  const { stored, revoked, cleanupError } = await issueConnectorToken(
    { bin: findT3Bin(t3Home, options.t3Bin), home: t3Home },
    config.t3Url,
    `t3-mesh ${connectorId}`,
    config.t3TokenPath,
  );
  say(`issued T3 token (orchestration:read, orchestration:operate), expires ${stored.expiresAt}`);
  if (cleanupError !== undefined) say(`warning: could not revoke older connector tokens: ${cleanupError}`);
  else if (revoked > 0) say(`revoked ${revoked} older connector token(s)`);

  const connection = await T3Connection.open(config.t3Url, stored.token);
  say(`connected to T3 ${connection.descriptor.serverVersion} (environment ${connection.descriptor.environmentId})`);
  await connection.close();

  const mcpCommand = [process.execPath, CLI_PATH, "mcp", "--socket", config.socketPath];
  if (options.registerMcp) {
    if (await hasCommand("claude")) {
      await run("claude", ["mcp", "remove", "--scope", "user", "t3-mesh"]).catch(() => undefined);
      await run("claude", ["mcp", "add", "--scope", "user", "t3-mesh", "--", ...mcpCommand]);
      say("registered t3-mesh MCP server with Claude (user scope)");
    }
    if (await hasCommand("codex")) {
      await run("codex", ["mcp", "remove", "t3-mesh"]).catch(() => undefined);
      await run("codex", ["mcp", "add", "t3-mesh", "--", ...mcpCommand]);
      say("registered t3-mesh MCP server with Codex");
    }
  } else {
    say(`MCP server command (register with --register-mcp): ${mcpCommand.join(" ")}`);
  }

  if (options.systemd) {
    const unitDir = join(homedir(), ".config", "systemd", "user");
    mkdirSync(unitDir, { recursive: true });
    const unitPath = join(unitDir, "t3-mesh.service");
    writeFileSync(
      unitPath,
      [
        "[Unit]",
        "Description=t3-mesh connector",
        "After=t3code.service network-online.target",
        "",
        "[Service]",
        `ExecStart=${process.execPath} ${CLI_PATH} daemon --config ${join(stateDir, "config.json")}`,
        `Environment=PATH=${process.env.PATH ?? "/usr/bin:/bin"}`,
        "Restart=always",
        "RestartSec=5",
        "",
        "[Install]",
        "WantedBy=default.target",
        "",
      ].join("\n"),
    );
    await run("systemctl", ["--user", "daemon-reload"]);
    await run("systemctl", ["--user", "enable", "--now", "t3-mesh.service"]);
    say(`installed and started ${unitPath}`);
  } else {
    say(`run the daemon with: ${process.execPath} ${CLI_PATH} daemon --config ${join(stateDir, "config.json")}`);
  }
  if (!existsSync(config.statePath)) say("no threads enrolled yet; agents join with the mesh_join tool");
}
