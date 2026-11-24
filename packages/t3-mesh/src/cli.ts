#!/usr/bin/env node
// t3-mesh init --t3-home <T3CODE_HOME> [--t3-url ...] [--router-url ... --router-token-file ...] [--register-mcp] [--systemd]
// t3-mesh daemon --config <state dir>/config.json
// t3-mesh mcp --socket <state dir>/daemon.sock
// t3-mesh router serve --db <path> --audit <path> [--host 127.0.0.1] [--port 8790] [--topic <name>=<publisher id>[,...]]...
// t3-mesh router add-connector <id> --db <path> --token-out <path>
// t3-mesh router revoke-connector <id> --db <path>
// t3-mesh router add-publisher <id> --topic <name> --db <path> --token-out <path>
// t3-mesh router revoke-publisher <id> --db <path>
// t3-mesh router github-receiver --listen <host:port> --router <url> --topic <name> --secret-file <path> --token-file <path>
import { homedir } from "node:os";
import { join } from "node:path";
import { readFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { loadConfig } from "./config.ts";
import { Daemon } from "./daemon.ts";
import { init } from "./init.ts";
import { readCodeFromStdin } from "./identity/pairClient.ts";
import { pairConnector } from "./pair.ts";
import { statusProblem } from "./statusExport.ts";
import { errorMessage, log } from "./log.ts";
import { runShim } from "./mcp/shim.ts";
import { AdminUsageError, adminUsage, runAdminCommand } from "./admin.ts";
import { routerUsage, RouterUsageError, runRouterCommand } from "./router/commands.ts";

const usage = `usage:
  t3-mesh init --t3-home <path> [--state-dir ~/.t3-mesh] [--connector-id user@host] [--t3-url http://127.0.0.1:3773]
               [--t3-bin <path>] [--router-url <url> (--router-token-file <path> | --pair)] [--register-mcp] [--systemd]
               (--pair reads a pairing code from stdin)
  t3-mesh pair [--config ~/.t3-mesh/config.json]   (pairs an existing connector; code on stdin)
  t3-mesh daemon --config <path>
  t3-mesh status [--config ~/.t3-mesh/config.json]   (the daemon's execution status export, JSON; exit 3 when off or stale)
  t3-mesh mcp --socket <path>
  t3-mesh router <command>
${routerUsage}
  t3-mesh admin <command>
${adminUsage}`;

const fail = (message: string): never => {
  process.stderr.write(`${message}\n\n${usage}\n`);
  process.exit(2);
};

if (process.argv[2] === "admin") {
  try {
    await runAdminCommand(process.argv.slice(3));
  } catch (error) {
    if (error instanceof AdminUsageError) fail(error.message);
    process.stderr.write(`t3-mesh admin: ${errorMessage(error)}\n`);
    process.exit(1);
  }
} else if (process.argv[2] === "router") {
  try {
    await runRouterCommand(process.argv.slice(3));
  } catch (error) {
    if (error instanceof RouterUsageError) fail(error.message);
    log("error", "fatal", { error: errorMessage(error) });
    process.exit(1);
  }
} else {
  await runConnectorCommand();
}

/**
 * Exit 3 when the export is off, missing, unreadable, stale or future-dated, or written while not
 * connected to T3: consumers must treat that as unknown.
 */
function printStatus(path: string | null): number {
  if (path === null) {
    process.stderr.write("status export is off (statusExport.enabled in config.json)\n");
    return 3;
  }
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    process.stderr.write(`no status at ${path}; is the daemon running?\n`);
    return 3;
  }
  process.stdout.write(text);
  const problem = statusProblem(text, Date.now());
  if (problem !== null) {
    process.stderr.write(`${problem}: treat it as unknown\n`);
    return 3;
  }
  return 0;
}

async function runConnectorCommand(): Promise<void> {
  const { values, positionals } = parseArgs({
    args: process.argv.slice(2),
    allowPositionals: true,
    options: {
      config: { type: "string" },
      socket: { type: "string" },
      "state-dir": { type: "string", default: join(homedir(), ".t3-mesh") },
      "connector-id": { type: "string" },
      "t3-url": { type: "string", default: "http://127.0.0.1:3773" },
      "t3-home": { type: "string" },
      "t3-bin": { type: "string" },
      "router-url": { type: "string" },
      "router-token-file": { type: "string" },
      "register-mcp": { type: "boolean", default: false },
      systemd: { type: "boolean", default: false },
      pair: { type: "boolean", default: false },
    },
  });
  const required = (name: "config" | "socket" | "t3-home"): string =>
    values[name] ?? fail(`missing --${name}`);

  const [command] = positionals;
  try {
    if (command === "init") {
      await init({
        stateDir: values["state-dir"],
        connectorId: values["connector-id"],
        t3Url: values["t3-url"],
        t3Home: required("t3-home"),
        t3Bin: values["t3-bin"],
        routerUrl: values["router-url"],
        routerTokenFile: values["router-token-file"],
        pair: values.pair,
        registerMcp: values["register-mcp"],
        systemd: values.systemd,
      });
      process.exit(0);
    } else if (command === "pair") {
      const paired = await pairConnector(values.config ?? join(homedir(), ".t3-mesh", "config.json"), readCodeFromStdin());
      process.stdout.write(`paired ${paired.connectorId} (${paired.scopes.join(" ")}); restart the daemon to use the new token\n`);
      process.exit(0);
    } else if (command === "daemon") {
      await new Daemon(loadConfig(required("config"))).run();
    } else if (command === "status") {
      process.exit(printStatus(loadConfig(values.config ?? join(homedir(), ".t3-mesh", "config.json")).statusPath));
    } else if (command === "mcp") {
      runShim(required("socket"));
    } else {
      fail(`unknown command ${positionals.join(" ")}`);
    }
  } catch (error) {
    log("error", "fatal", { error: errorMessage(error) });
    process.exit(1);
  }
}
