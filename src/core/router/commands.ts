// `hyp router ...` subcommands. Imports only router modules, effect and node builtins so the
// router can run standalone with zero extra harness dependencies.
import { writeFileSync } from "node:fs";
import { parseArgs } from "node:util";
import { isConnectorId } from "../address.ts";
import { serveReceiver } from "../github/receiver.ts";
import { isRawKey } from "../identity/keys.ts";
import { readPrivateFile } from "../privateFile.ts";
import { isTopic } from "./cloudevent.ts";
import { RouterCore } from "./core.ts";
import { serveRouter } from "./server.ts";

export const routerUsage = `  serve --db <path> --audit <path> [--host 127.0.0.1] [--port 8790] [--topic <name>=<publisher id>[,<publisher id>...]]...
        [--admin-key <base64url>] [--require-pairing]
  add-connector <id> --db <path> --token-out <path>
  revoke-connector <id> --db <path>
  add-publisher <id> --topic <name> [--topic <name>...] --db <path> --token-out <path>
  revoke-publisher <id> --db <path>
  github-receiver --listen <host:port> --router <url> --topic <name> --secret-file <path> --token-file <path>`;

export class RouterUsageError extends Error {}

/** Parses `host:port` (`[::1]:port` for IPv6). */
export function parseListen(value: string): { readonly host: string; readonly port: number } {
  const colon = value.lastIndexOf(":");
  const host = value.slice(0, colon).replace(/^\[(.*)\]$/, "$1");
  const portText = value.slice(colon + 1);
  const port = Number(portText);
  if (colon <= 0 || host.length === 0 || !/^\d{1,5}$/.test(portText) || port > 65535) {
    throw new RouterUsageError(`--listen must be host:port, got ${value}`);
  }
  return { host, port };
}

/** Parses repeated `--topic name=publisher[,publisher...]` into topic -> publisher IDs. */
export function parseTopicFlags(flags: readonly string[]): Map<string, string[]> {
  const topics = new Map<string, string[]>();
  for (const flag of flags) {
    const equals = flag.indexOf("=");
    const name = equals < 0 ? flag : flag.slice(0, equals);
    const publishers = equals < 0 ? [] : flag.slice(equals + 1).split(",").filter((id) => id.length > 0);
    if (!isTopic(name)) throw new RouterUsageError(`invalid topic name in --topic ${flag}`);
    if (publishers.length === 0) throw new RouterUsageError(`--topic ${flag} lists no publishers (--topic <name>=<publisher id>)`);
    const bad = publishers.filter((id) => !isConnectorId(id));
    if (bad.length > 0) throw new RouterUsageError(`invalid publisher id ${bad.join(", ")} in --topic ${flag}`);
    topics.set(name, [...new Set([...(topics.get(name) ?? []), ...publishers])]);
  }
  return topics;
}

// args: everything after "router", e.g. ["serve", "--db", "..."].
export async function runRouterCommand(args: readonly string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args: [...args],
    allowPositionals: true,
    options: {
      db: { type: "string" },
      audit: { type: "string" },
      host: { type: "string", default: "127.0.0.1" },
      port: { type: "string", default: "8790" },
      "token-out": { type: "string" },
      topic: { type: "string", multiple: true, default: [] },
      listen: { type: "string" },
      router: { type: "string" },
      "secret-file": { type: "string" },
      "token-file": { type: "string" },
      "admin-key": { type: "string" },
      "require-pairing": { type: "boolean", default: false },
    },
  });
  const required = (name: "db" | "audit" | "token-out" | "listen" | "router" | "secret-file" | "token-file"): string => {
    const value = values[name];
    if (value === undefined) throw new RouterUsageError(`missing --${name}`);
    return value;
  };
  const id = (value: string | undefined, kind: string): string => {
    if (value === undefined) throw new RouterUsageError(`missing ${kind} id`);
    return value;
  };

  const [subcommand, argument] = positionals;
  if (subcommand === "serve") {
    const topics = parseTopicFlags(values.topic);
    const adminKey = values["admin-key"] ?? null;
    if (adminKey !== null && !isRawKey(adminKey)) throw new RouterUsageError("--admin-key must be a raw Ed25519 public key in base64url");
    if (values["require-pairing"] && adminKey === null) throw new RouterUsageError("--require-pairing needs --admin-key");
    const core = new RouterCore({
      dbPath: required("db"),
      auditPath: required("audit"),
      topics,
      adminKey,
      requirePairing: values["require-pairing"],
    });
    await serveRouter({ core, host: values.host, port: Number(values.port) });
  } else if (subcommand === "add-connector") {
    const connectorId = id(argument, "connector");
    const core = new RouterCore({ dbPath: required("db") });
    const token = core.addConnector(connectorId);
    writeFileSync(required("token-out"), token + "\n", { mode: 0o600, flag: "wx" });
    core.close();
    process.stdout.write(`added connector ${connectorId}; token written to ${values["token-out"]}\n`);
  } else if (subcommand === "revoke-connector") {
    const connectorId = id(argument, "connector");
    const core = new RouterCore({ dbPath: required("db") });
    const revoked = core.revokeConnector(connectorId);
    core.close();
    process.stdout.write(revoked ? `revoked ${connectorId}\n` : `${connectorId} not found or already revoked\n`);
  } else if (subcommand === "add-publisher") {
    const publisherId = id(argument, "publisher");
    if (values.topic.length === 0) throw new RouterUsageError("missing --topic");
    const bad = values.topic.filter((topic) => !isTopic(topic));
    if (bad.length > 0) throw new RouterUsageError(`invalid topic name ${bad.join(", ")}`);
    const tokenOut = required("token-out");
    const core = new RouterCore({ dbPath: required("db") });
    const token = core.events.addPublisher(publisherId, values.topic);
    writeFileSync(tokenOut, token + "\n", { mode: 0o600, flag: "wx" });
    core.close();
    process.stdout.write(
      `added publisher ${publisherId} (publish:${values.topic.join(", publish:")}); token written to ${tokenOut}\n`,
    );
  } else if (subcommand === "revoke-publisher") {
    const publisherId = id(argument, "publisher");
    const core = new RouterCore({ dbPath: required("db") });
    const revoked = core.events.revokePublisher(publisherId);
    core.close();
    process.stdout.write(revoked ? `revoked ${publisherId}\n` : `${publisherId} not found or already revoked\n`);
  } else if (subcommand === "github-receiver") {
    // Its own process: no --db, only the webhook secret and a publisher token, both from files.
    const [topic, ...extra] = values.topic;
    if (topic === undefined || extra.length > 0 || !isTopic(topic)) throw new RouterUsageError("github-receiver needs one --topic");
    const { host, port } = parseListen(required("listen"));
    await serveReceiver({
      host,
      port,
      routerUrl: required("router"),
      topic,
      secret: readPrivateFile(required("secret-file")),
      token: readPrivateFile(required("token-file")),
    });
  } else {
    throw new RouterUsageError(`unknown router command ${positionals.join(" ")}`);
  }
}
