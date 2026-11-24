#!/usr/bin/env node
import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import {
  classifyCliError,
  CliOperationalError,
  CliUsageError,
  emitError,
  emitResult,
  EXIT_ERROR,
  extractGlobalOutputFlags,
  renderHelp,
  type CliCheck,
  type CliField,
  type CliSection,
  type CliTable,
  type CliTableRow,
  type OutputMode,
} from "./cli-ui.ts";
import { loadConfig } from "./config.ts";
import { startDaemon } from "./daemon.ts";
import { detectLocalEnvironment, discoverRemoteMachines, onboardRemoteOverSsh, probeRemoteHost } from "./discover.ts";
import { daemonRpc, runHook, type HookEvent } from "./hooks.ts";
import { createKeyRegistration, loadOrCreateConnectorKeys } from "./identity.ts";
import { runMcp } from "./mcp.ts";
import { ALL_GUIDES, CONNECTOR_BRIDGE_GUIDES, findGuide, ROUTER_STREAM_GUIDES } from "./plugin-catalog.ts";
import { addressPattern, connectorPattern, handlePattern, isHarness, object } from "./protocol.ts";
import { detectExposedTailscaleUrl, encodeInvite, exposeTailscale, unexposeTailscale } from "./remote.ts";
import { RouterLink } from "./router.ts";
import { defaultT3BaseDir, t3StateDbPath } from "./t3.ts";
import { parseAddress } from "./core/address.ts";
import { fingerprint as keyFingerprint, isRawKey } from "./core/identity/keys.ts";
import { packFiles } from "./core/transfer/pack.ts";
import { seal as sealTransfer } from "./core/transfer/seal.ts";
import {
  captureSecretViaWeb,
  collectSecretRefs,
  deleteSecret,
  detectSecretBackend,
  listSecrets,
  readSecret,
  secretBackendLabel,
  writeSecretDetailed,
} from "./secrets.ts";
import {
  ALL_CONFIGURABLE_HARNESSES,
  installSkill,
  readCanonicalSkill,
  resolveCanonicalSkillPath,
  resolveRuntimePaths,
  runDoctor,
  runOnboard,
  setupAntigravity,
  setupClaude,
  setupCodex,
  setupCursor,
  setupGemini,
  setupOpenClaw,
  setupOpenCode,
  setupService,
  setupT3,
  type ConfigurableHarness,
  type SetupResult,
  type SkillTarget,
} from "./setup.ts";
import { runWait } from "./wait.ts";
import { RouterCore } from "./core/router/core.ts";

const configDir = (() => {
  const base = process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config");
  const primary = join(base, "hyphae");
  const legacy = join(base, "agents-mesh");
  if (!existsSync(join(primary, "connector.json")) && existsSync(join(legacy, "connector.json"))) {
    return legacy;
  }
  return primary;
})();
const defaultConfigPath = () => join(configDir, "connector.json");
const defaultSocketPath = () => process.env.HYPHAE_SOCKET ?? process.env.AGENTS_MESH_SOCKET ?? join(configDir, "state", "connector.sock");

const validEvents = new Set<HookEvent>(["pre-tool-use", "post-tool-use", "pre-invocation", "stop"]);
const rawProtocolCommands = new Set(["mcp", "hook", "wait", "watch"]);
const configurableHarnessSet = new Set<string>(ALL_CONFIGURABLE_HARNESSES);

function readStdinLine(): Promise<string> {
  return new Promise((resolveStdin) => {
    const chunks: Buffer[] = [];
    process.stdin.on("data", (chunk: Buffer) => chunks.push(chunk));
    process.stdin.on("end", () => resolveStdin(Buffer.concat(chunks).toString("utf8").trim()));
    process.stdin.on("error", () => resolveStdin(""));
  });
}

function readPackageVersion(): string {
  try {
    const here = dirname(fileURLToPath(import.meta.url));
    const pkgRoot = here.endsWith(join("dist", "src")) ? resolve(here, "..", "..") : resolve(here, "..");
    const pkg = JSON.parse(readFileSync(join(pkgRoot, "package.json"), "utf8")) as { version?: unknown };
    return typeof pkg.version === "string" ? pkg.version : "0.0.0";
  } catch {
    return "0.0.0";
  }
}

function parsePortFlag(raw: string | undefined, flagName: string, allowZero = false): number | undefined {
  if (raw === undefined) return undefined;
  const parsed = Number(raw);
  const min = allowZero ? 0 : 1;
  if (!Number.isInteger(parsed) || parsed < min || parsed > 65535) {
    throw new CliUsageError(`Expected integer ${flagName} between ${min} and 65535, got '${raw}'`);
  }
  return parsed;
}

function dedupeStrings(items: readonly string[]): string[] {
  return [...new Set(items.filter((item) => item.trim().length > 0))];
}

function cleanFixCommand(fix: string): string {
  const match = /^Run `([^`]+)`$/.exec(fix.trim());
  return match ? match[1]! : fix.trim();
}

async function renderHealthStatus(
  command: "status" | "doctor",
  cfgPath: string,
  socketPath: string,
  mode: OutputMode,
): Promise<void> {
  const [doctorChecks, daemonRes] = await Promise.all([
    runDoctor(cfgPath, socketPath),
    daemonRpc(socketPath, { type: "daemon.status" }, 1_000),
  ]);

  const daemonData = daemonRes.ok && object(daemonRes.result) ? daemonRes.result : null;
  const checks: CliCheck[] = doctorChecks.map((check) => ({
    name: check.name,
    status: check.ok ? "ok" : "fail",
    detail: check.detail,
    ...(check.fix ? { fix: check.fix } : {}),
  }));

  const passed = checks.filter((c) => c.status === "ok").length;
  const failed = checks.length - passed;
  const total = checks.length;
  const allOk = failed === 0;

  const fields: CliField[] = [];
  if (daemonData) {
    const connectorId = typeof daemonData.connectorId === "string" ? daemonData.connectorId : "unknown";
    const routers = Array.isArray(daemonData.routers) ? daemonData.routers.map(String) : [];
    const localRouter = typeof daemonData.localRouter === "string" ? daemonData.localRouter : null;
    const sessions = Array.isArray(daemonData.sessions) ? daemonData.sessions : [];
    const streams = Array.isArray(daemonData.streams) ? daemonData.streams.map(String) : [];
    const bridges = Array.isArray(daemonData.plugins) ? daemonData.plugins.map(String) : [];
    const rules = Array.isArray(daemonData.mutes) ? daemonData.mutes : [];

    fields.push({ label: "Connector", value: connectorId });
    fields.push({
      label: "Nodes",
      value: localRouter
        ? `${routers.join(", ") || "primary"} (embedded ${localRouter})`
        : routers.join(", ") || "(none)",
    });
    fields.push({
      label: "Socket",
      value: typeof daemonData.socketPath === "string" ? daemonData.socketPath : socketPath,
    });
    fields.push({ label: "Sessions", value: `${sessions.length} registered` });
    fields.push({
      label: "Streams",
      value: streams.length > 0 ? `${streams.length} (${streams.join(", ")})` : "0",
    });
    fields.push({
      label: "Bridges",
      value: bridges.length > 0 ? `${bridges.length} (${bridges.join(", ")})` : "0",
    });
    fields.push({ label: "Rules", value: `${rules.length} mute rule(s)` });
  } else {
    fields.push({ label: "Config", value: cfgPath });
    fields.push({ label: "Socket", value: `${socketPath} (unreachable)` });
  }

  const next = dedupeStrings(
    checks
      .filter((c) => c.status !== "ok" && c.fix)
      .map((c) => cleanFixCommand(c.fix!)),
  );

  emitResult(
    {
      ok: allOk,
      command,
      title: command === "doctor" ? "Hyphae Doctor" : "Hyphae Status",
      summary: `${passed}/${total} checks passed${failed > 0 ? `, ${failed} failed` : ""}`,
      fields,
      checks,
      ...(next.length > 0 ? { next } : {}),
      data: {
        ...(daemonData ?? {}),
        daemonReachable: daemonData !== null,
        configPath: cfgPath,
        socketPath: daemonData && typeof daemonData.socketPath === "string" ? daemonData.socketPath : socketPath,
        checks: doctorChecks,
        counts: { passed, failed, total },
      },
    },
    mode,
  );

  if (!allOk) process.exitCode = EXIT_ERROR;
}

interface ExecutionContext {
  command: string;
  mode: OutputMode;
}

async function runCli(ctx: ExecutionContext): Promise<void> {
  const rawArgv = process.argv.slice(2);
  const isRawProtocol = rawArgv.length > 0 && rawProtocolCommands.has(rawArgv[0]!);

  const extracted = isRawProtocol
    ? { mode: "plain" as OutputMode, explicitMode: undefined, args: rawArgv }
    : extractGlobalOutputFlags(rawArgv);

  ctx.mode = extracted.mode;
  const mode = extracted.mode;
  const explicitMode = extracted.explicitMode;

  const [rawAction, ...rawArgs] = extracted.args;
  let action = rawAction;
  let args = rawArgs;
  ctx.command = action ?? "help";

  if (action === "--version" || action === "-v" || action === "version") {
    ctx.command = "version";
    const version = readPackageVersion();
    if (mode === "json") {
      emitResult(
        {
          ok: true,
          command: "version",
          title: "Hyphae",
          summary: `hyphae ${version}`,
          data: { name: "hyphae", version },
        },
        mode,
      );
    } else {
      console.log(`hyphae ${version}`);
    }
    return;
  }

  // Map clean `hyp share <tailscale|invite|stop>` onto `node <expose|invite|unexpose>` while keeping accurate command names
  let shareOrigin = false;
  if (action === "share") {
    shareOrigin = true;
    const [sub, ...rest] = args;
    if (sub === "tailscale") {
      ctx.command = "share tailscale";
      action = "node";
      args = ["expose", "tailscale", ...rest];
    } else if (sub === "stop" || sub === "unexpose") {
      ctx.command = "share stop";
      action = "node";
      args = ["unexpose", "tailscale", ...rest];
    } else if (sub === "invite") {
      ctx.command = "share invite";
      action = "node";
      args = ["invite", ...rest];
    } else {
      throw new CliUsageError(
        sub ? `Unknown share subcommand '${sub}'` : "Missing share subcommand",
        {
          usage: "hyp share <tailscale [--service hyphae] | invite <user@host> | stop>",
          fix: "Run `hyp share tailscale --service hyphae` to expose your local Node",
        },
      );
    }
  }

  if (action === "skill") {
    const { values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: { dir: { type: "string" } },
    });
    const [sub = "print", target = "all"] = positionals;
    ctx.command = `skill ${sub}`;
    if (sub === "print") {
      process.stdout.write(readCanonicalSkill());
      return;
    }
    if (sub === "path") {
      const skillPath = resolveCanonicalSkillPath();
      if (mode === "json") {
        emitResult(
          {
            ok: true,
            command: "skill path",
            title: "Canonical Skill Path",
            fields: [{ label: "Path", value: skillPath }],
            data: { path: skillPath },
          },
          mode,
        );
      } else {
        console.log(skillPath);
      }
      return;
    }
    if (sub === "install") {
      const valid = new Set<SkillTarget>(["antigravity", "claude", "codex", "cursor", "openclaw", "project", "all"]);
      if (!valid.has(target as SkillTarget)) {
        throw new CliUsageError(`Unknown skill target '${target}'`, {
          usage: "hyp skill install [antigravity|claude|codex|cursor|openclaw|project|all] [--dir <path>]",
          fix: "Use one of: antigravity, claude, codex, cursor, openclaw, project, all",
        });
      }
      const res = installSkill(target as SkillTarget, { projectDir: values.dir });
      emitResult(
        {
          ok: true,
          command: "skill install",
          title: "Skill Installed",
          summary: `Installed Hyphae skill for ${target} (${res.files.length} file(s))`,
          fields: [
            { label: "Target", value: target },
            { label: "Files", value: String(res.files.length) },
          ],
          tables: [
            {
              title: "Installed Files",
              columns: [{ key: "path", header: "Path" }],
              rows: res.files.map((filePath) => ({ path: filePath })),
            },
          ],
          next: ["Restart open harness sessions so the updated skill is discovered"],
          data: { target, files: res.files },
        },
        mode,
      );
      return;
    }
    throw new CliUsageError(`Unknown skill subcommand '${sub}'`, {
      usage: "hyp skill [install [harness|project|all] | print | path]",
    });
  }

  if (action === "node" || action === "router") {
    const [sub, ...rest] = args;
    if (sub === "expose") {
      const cmdName = shareOrigin ? "share tailscale" : "node expose";
      ctx.command = cmdName;
      const { values, positionals } = parseArgs({
        args: rest,
        allowPositionals: true,
        options: {
          service: { type: "string" },
          port: { type: "string" },
          https: { type: "string" },
          "dry-run": { type: "boolean" },
        },
      });
      if (positionals[0] !== "tailscale") {
        throw new CliUsageError("Expected 'tailscale' exposure target", {
          usage: "hyp share tailscale [--service <name>] [--port 8790] [--https <port>] [--dry-run]",
        });
      }
      const localPort = parsePortFlag(values.port, "--port") ?? 8790;
      const httpsPort = parsePortFlag(values.https, "--https");
      const res = exposeTailscale({
        localPort,
        service: values.service,
        httpsPort,
        dryRun: values["dry-run"] === true,
      });
      emitResult(
        {
          ok: true,
          command: cmdName,
          title: res.applied ? "Node Exposed on Tailscale" : "Tailscale Exposure (Dry Run)",
          summary: `${res.applied ? "Exposed" : "Dry run"} (${res.mode}) at ${res.url}`,
          fields: [
            { label: "Node URL", value: res.url },
            { label: "Mode", value: res.mode },
            { label: "Applied", value: res.applied ? "yes" : "no (dry-run)" },
            { label: "Command", value: res.command.join(" ") },
          ],
          next: [`hyp share invite <user@host> --router ${res.url}`],
          data: res,
        },
        mode,
      );
      return;
    }
    if (sub === "unexpose") {
      const cmdName = shareOrigin ? "share stop" : "node unexpose";
      ctx.command = cmdName;
      const { values, positionals } = parseArgs({
        args: rest,
        allowPositionals: true,
        options: { service: { type: "string" }, https: { type: "string" } },
      });
      if (positionals[0] !== "tailscale") {
        throw new CliUsageError("Expected 'tailscale' target to unexpose", {
          usage: "hyp share stop [--service <name>] [--https 8790]",
        });
      }
      const httpsPort = parsePortFlag(values.https, "--https");
      const cmd = unexposeTailscale({
        service: values.service,
        httpsPort,
      });
      emitResult(
        {
          ok: true,
          command: cmdName,
          title: "Tailscale Exposure Removed",
          summary: "Stopped exposing local Node on Tailscale",
          fields: [{ label: "Command", value: cmd.join(" ") }],
          data: { removed: true, command: cmd },
        },
        mode,
      );
      return;
    }
    if (sub === "invite") {
      const cmdName = shareOrigin ? "share invite" : "node invite";
      ctx.command = cmdName;
      const { values, positionals } = parseArgs({
        args: rest,
        allowPositionals: true,
        options: {
          router: { type: "string" },
          db: { type: "string" },
          port: { type: "string" },
        },
      });
      const connectorId = positionals[0];
      if (!connectorId || !connectorPattern.test(connectorId)) {
        throw new CliUsageError(
          connectorId ? `Invalid connector ID '${connectorId}' (expected user@host)` : "Missing connector ID (<user@host>)",
          {
            usage: "hyp share invite <user@host> [--router https://...] [--db <router.sqlite>]",
          },
        );
      }
      const localPort = parsePortFlag(values.port, "--port") ?? 8790;
      const dbPath = resolve(values.db ?? join(configDir, "router", "router.sqlite"));
      const routerUrl = values.router ?? detectExposedTailscaleUrl(localPort);
      if (!routerUrl) {
        throw new CliOperationalError(
          "Could not detect an exposed Tailscale Node URL.",
          {
            code: "NODE_URL_UNAVAILABLE",
            fix: "Pass --router https://<host> or run `hyp share tailscale` first",
          },
        );
      }
      const core = new RouterCore({ dbPath });
      let token: string;
      try {
        token = core.addConnector(connectorId);
      } finally {
        core.close();
      }
      const code = encodeInvite({ connectorId, router: routerUrl, token });
      const joinCommand = `hyp onboard --join <<< '${code}'`;
      const revokeCommand = `hyp node revoke-connector ${connectorId} --db ${dbPath}`;
      emitResult(
        {
          ok: true,
          command: cmdName,
          title: "Remote Connector Invite Created",
          summary: `Created Connector '${connectorId}' for Node ${routerUrl}`,
          fields: [
            { label: "Connector", value: connectorId },
            { label: "Node URL", value: routerUrl },
            { label: "Node DB", value: dbPath },
            { label: "Remote Command", value: joinCommand },
          ],
          warnings: ["Treat this invite string like a private password; it keeps the token out of CLI argv/ps when passed via stdin."],
          next: [joinCommand, revokeCommand],
          data: {
            connectorId,
            routerUrl,
            dbPath,
            inviteCode: code,
            joinCommand,
            revokeCommand,
          },
        },
        mode,
      );
      return;
    }

    const { routerUsage, runRouterCommand } = await import("./core/router/commands.ts");
    if (args.length === 0 || args[0] === "--help" || args[0] === "-h") {
      ctx.command = "node";
      const subcommands = [
        "expose tailscale [--service <name>] [--port 8790] [--https <port>] [--dry-run]",
        "unexpose tailscale [--service <name>] [--https 8790]",
        "invite <user@host> [--router https://...] [--db <router.sqlite>]",
        ...routerUsage.split("\n").map((line) => line.trim()).filter(Boolean),
      ];
      emitResult(
        {
          ok: true,
          command: "node",
          title: "Node Administration Commands",
          summary: "Manage standalone Hyphae Nodes, Connectors, publishers, and receivers",
          sections: [{ title: "Subcommands", lines: subcommands.map((line) => `hyp node ${line}`) }],
          next: ["hyp share tailscale --service hyphae", "hyp share invite <user@host>"],
          data: { subcommands },
        },
        mode,
      );
    } else {
      ctx.command = `node ${args[0]}`;
      await runRouterCommand(args);
    }
    return;
  }

  if (action === "secret") {
    const { values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: {
        "config-dir": { type: "string" },
        web: { type: "boolean" },
        "no-open": { type: "boolean" },
      },
    });
    const [sub, target] = positionals;
    ctx.command = sub ? `secret ${sub}` : "secret";
    const dir = resolve(values["config-dir"] ?? configDir);

    if (sub === "set") {
      if (!target) {
        throw new CliUsageError("Missing secret name", {
          usage: "hyp secret set <name> [--web] [--no-open] [--config-dir <dir>]",
          fix: "In agent sessions, run `hyp secret set <name> --web` so the human enters the value out-of-band",
        });
      }
      if (values.web === true) {
        const res = await captureSecretViaWeb(target, {
          configDir: dir,
          openBrowser: values["no-open"] !== true,
          onReady: (url) => {
            process.stderr.write(`Waiting for secret '${target}' via local out-of-band form:\n  ${url}\n`);
          },
        });
        emitResult(
          {
            ok: true,
            command: "secret set",
            title: "Secret Saved",
            summary: `Saved secret '${target}' in ${secretBackendLabel(res.backend)}`,
            fields: [
              { label: "Secret", value: target },
              { label: "Store", value: secretBackendLabel(res.backend) },
              { label: "Location", value: res.location },
            ],
            next: ["hyp secret check"],
            data: { name: target, backend: res.backend, location: res.location, path: res.path, source: "web" },
          },
          mode,
        );
        return;
      }

      let value: string;
      if (process.stdin.isTTY && process.stdout.isTTY) {
        const clack = await import("@clack/prompts");
        const entered = await clack.password({ message: `Enter secret value for '${target}'` });
        if (clack.isCancel(entered) || typeof entered !== "string" || entered.trim().length === 0) {
          throw new CliOperationalError("Secret entry cancelled", { code: "CANCELLED" });
        }
        value = entered;
      } else {
        value = await readStdinLine();
        if (!value) {
          throw new CliOperationalError(`No secret received on stdin for '${target}'`, {
            code: "MISSING_SECRET_INPUT",
            fix: `In non-TTY / agent sessions, use: hyp secret set ${target} --web`,
          });
        }
      }
      const saved = writeSecretDetailed(target, value, dir);
      emitResult(
        {
          ok: true,
          command: "secret set",
          title: "Secret Saved",
          summary: `Saved secret '${target}' in ${secretBackendLabel(saved.backend)}`,
          fields: [
            { label: "Secret", value: target },
            { label: "Store", value: secretBackendLabel(saved.backend) },
            { label: "Location", value: saved.location },
          ],
          next: ["hyp secret check"],
          data: { name: target, backend: saved.backend, location: saved.location, path: saved.path },
        },
        mode,
      );
      return;
    }

    if (sub === "list") {
      const secrets = listSecrets(dir);
      const activeBackend = detectSecretBackend(dir);
      const secretsDirectory = join(dir, "secrets");
      const badSecrets = secrets.filter((s) => !s.modeOk);
      const warnings = badSecrets.map((s) => `Secret '${s.name}' has overly broad file permissions (${s.path})`);
      const next = badSecrets.length > 0
        ? badSecrets.map((s) => `chmod 600 ${s.path}`)
        : secrets.length === 0
          ? ["hyp secret set <name> --web"]
          : ["hyp secret check"];

      emitResult(
        {
          ok: true,
          command: "secret list",
          title: "Secrets",
          summary: secrets.length === 0
            ? `No secrets stored (default store: ${secretBackendLabel(activeBackend)})`
            : `${secrets.length} secret(s) stored (${badSecrets.length === 0 ? "all OK" : `${badSecrets.length} permission warning(s)`})`,
          fields: [{ label: "Default Store", value: secretBackendLabel(activeBackend) }],
          tables: [
            {
              title: "Stored Secrets",
              columns: [
                { key: "status", header: "Status" },
                { key: "name", header: "Secret" },
                { key: "backend", header: "Store" },
                { key: "location", header: "Location" },
              ],
              rows: secrets.map((s) => ({
                status: s.modeOk ? "OK" : "BAD_MODE",
                name: s.name,
                backend: secretBackendLabel(s.backend),
                location: s.location,
              })),
              emptyText: `No secrets stored (default store: ${secretBackendLabel(activeBackend)})`,
            },
          ],
          ...(warnings.length > 0 ? { warnings } : {}),
          next,
          data: {
            defaultBackend: activeBackend,
            directory: secretsDirectory,
            count: secrets.length,
            secrets,
          },
        },
        mode,
      );
      return;
    }

    if (sub === "rm" || sub === "delete") {
      if (!target) {
        throw new CliUsageError("Missing secret name to remove", {
          usage: "hyp secret rm <name> [--config-dir <dir>]",
        });
      }
      const removed = deleteSecret(target, dir);
      emitResult(
        {
          ok: true,
          command: "secret rm",
          title: removed ? "Secret Removed" : "Secret Not Found",
          summary: removed ? `Removed secret '${target}'` : `Secret '${target}' was not found`,
          fields: [
            { label: "Secret", value: target },
            { label: "Removed", value: removed ? "yes" : "no" },
          ],
          data: { name: target, removed },
        },
        mode,
      );
      return;
    }

    if (sub === "check") {
      const cfgPath = resolve(target ?? (values["config-dir"] ? join(dir, "connector.json") : defaultConfigPath()));
      if (!existsSync(cfgPath)) {
        throw new CliOperationalError(`Config not found: ${cfgPath}`, {
          code: "CONFIG_NOT_FOUND",
          fix: "Run `hyp onboard` first or pass an explicit connector.json path",
        });
      }
      const raw = JSON.parse(readFileSync(cfgPath, "utf8")) as Record<string, unknown>;
      const refs = collectSecretRefs(raw);
      const checks: CliCheck[] = [];
      const refResults: Array<{ secret: string; owner: string; envKey: string; ok: boolean; error?: string }> = [];

      for (const ref of refs) {
        try {
          readSecret(ref.secret, dirname(cfgPath));
          checks.push({
            name: ref.secret,
            status: "ok",
            detail: `${ref.owner} -> ${ref.envKey} (verified)`,
          });
          refResults.push({ secret: ref.secret, owner: ref.owner, envKey: ref.envKey, ok: true });
        } catch (error) {
          const message = error instanceof Error ? error.message : String(error);
          checks.push({
            name: ref.secret,
            status: "fail",
            detail: `${ref.owner} -> ${ref.envKey}: ${message}`,
            fix: `hyp secret set ${ref.secret} --web`,
          });
          refResults.push({ secret: ref.secret, owner: ref.owner, envKey: ref.envKey, ok: false, error: message });
        }
      }

      const passed = refResults.filter((r) => r.ok).length;
      const failed = refResults.length - passed;
      const allOk = failed === 0;
      const next = dedupeStrings(checks.filter((c) => c.status !== "ok" && c.fix).map((c) => c.fix!));

      emitResult(
        {
          ok: allOk,
          command: "secret check",
          title: "Secret Verification",
          summary: refs.length === 0
            ? "No secret references configured in connector.json"
            : `${passed}/${refs.length} secret reference(s) valid${failed > 0 ? `, ${failed} failed` : ""}`,
          fields: [{ label: "Config", value: cfgPath }],
          ...(checks.length > 0 ? { checks } : {}),
          ...(next.length > 0 ? { next } : {}),
          data: {
            configPath: cfgPath,
            total: refs.length,
            passed,
            failed,
            refs: refResults,
          },
        },
        mode,
      );
      if (!allOk) process.exitCode = EXIT_ERROR;
      return;
    }

    throw new CliUsageError(
      sub ? `Unknown secret subcommand '${sub}'` : "Missing secret subcommand",
      {
        usage: "hyp secret <set <name> [--web] | list | rm <name> | check [config]>",
      },
    );
  }

  if (action === "connect" || action === "plugin" || action === "stream") {
    const { values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: { config: { type: "string" } },
    });
    const [sub = action === "connect" ? "add" : undefined, name] = positionals;
    ctx.command = sub ? `connect ${sub}` : "connect";
    const cfgPath = resolve(values.config ?? defaultConfigPath());

    if (sub === "setup" || sub === "add") {
      if (mode === "json") {
        throw new CliUsageError("Interactive setup wizard cannot run with --json", {
          usage: "hyp connect <list | guide [id]> --json",
          fix: "Run `hyp connect guide --json` to inspect available Streams and Bridges",
        });
      }
      const { runPluginSetupWizard } = await import("./onboard-interactive.ts");
      await runPluginSetupWizard(cfgPath);
      return;
    }

    if (sub === "guide") {
      if (name) {
        const g = findGuide(name);
        if (!g) {
          throw new CliUsageError(`Unknown Stream or Bridge '${name}'`, {
            usage: "hyp connect guide [id]",
            fix: `Available IDs: ${ALL_GUIDES.map((x) => x.id).join(", ")}`,
          });
        }
        const kindLabel = g.kind === "router-stream" ? "Stream" : "Bridge";
        const kindDetail = g.kind === "router-stream"
          ? "Node Stream (1-to-many topic with CloudEvents filters)"
          : "Connector Bridge (external chat thread <-> local agent handle)";
        const tables: CliTable[] = g.secrets.length > 0
          ? [
              {
                title: "Secrets",
                columns: [
                  { key: "secretName", header: "Secret" },
                  { key: "envKey", header: "Env Key" },
                  { key: "required", header: "Required" },
                  { key: "prompt", header: "Description" },
                ],
                rows: g.secrets.map((s) => ({
                  secretName: s.secretName,
                  envKey: s.envKey,
                  required: s.required ? "yes" : "optional",
                  prompt: s.prompt,
                })),
              },
            ]
          : [];
        const sections: CliSection[] = [
          { title: "Setup Instructions", lines: g.instructions },
          { title: "Agent Usage", lines: g.agentUsage },
        ];
        const next = [
          ...g.secrets.filter((s) => s.required).map((s) => `hyp secret set ${s.secretName} --web`),
          "hyp connect add",
        ];

        emitResult(
          {
            ok: true,
            command: "connect guide",
            title: g.label,
            summary: `${kindLabel} — ${g.tagline}`,
            fields: [
              { label: "ID", value: g.id },
              { label: "Kind", value: kindDetail },
              { label: "Default Name", value: g.defaultName },
              { label: g.kind === "router-stream" ? "Default Topic" : "Default Handle", value: g.defaultTopicOrTarget },
              { label: "Summary", value: g.summary },
            ],
            ...(tables.length > 0 ? { tables } : {}),
            sections,
            next,
            data: {
              id: g.id,
              kind: kindLabel.toLowerCase(),
              guide: g,
            },
          },
          mode,
        );
        return;
      }

      emitResult(
        {
          ok: true,
          command: "connect guide",
          title: "Streams & Bridges Catalog",
          summary: `${ROUTER_STREAM_GUIDES.length} Node Stream(s) and ${CONNECTOR_BRIDGE_GUIDES.length} Connector Bridge(s)`,
          tables: [
            {
              title: "Node Streams (1-to-many topics)",
              columns: [
                { key: "id", header: "ID" },
                { key: "label", header: "Stream" },
                { key: "topic", header: "Topic" },
                { key: "tagline", header: "Description" },
              ],
              rows: ROUTER_STREAM_GUIDES.map((g) => ({
                id: g.id,
                label: g.label,
                topic: g.defaultTopicOrTarget,
                tagline: g.tagline,
              })),
            },
            {
              title: "Connector Bridges (chat integrations)",
              columns: [
                { key: "id", header: "ID" },
                { key: "label", header: "Bridge" },
                { key: "handle", header: "Handle" },
                { key: "tagline", header: "Description" },
              ],
              rows: CONNECTOR_BRIDGE_GUIDES.map((g) => ({
                id: g.id,
                label: g.label,
                handle: g.defaultTopicOrTarget,
                tagline: g.tagline,
              })),
            },
          ],
          next: ["hyp connect guide <id>", "hyp connect add"],
          data: {
            streams: ROUTER_STREAM_GUIDES,
            bridges: CONNECTOR_BRIDGE_GUIDES,
            guides: ALL_GUIDES,
          },
        },
        mode,
      );
      return;
    }

    if (sub === "list") {
      if (!existsSync(cfgPath)) {
        emitResult(
          {
            ok: true,
            command: "connect list",
            title: "Configured Streams & Bridges",
            summary: `No connector config at ${cfgPath}`,
            fields: [{ label: "Config", value: `${cfgPath} (missing)` }],
            warnings: [`Config file not found at ${cfgPath}`],
            next: ["hyp onboard"],
            data: { configPath: cfgPath, exists: false, streams: [], bridges: [] },
          },
          mode,
        );
        return;
      }
      const raw = JSON.parse(readFileSync(cfgPath, "utf8")) as Record<string, unknown>;
      const rawStreams = object(raw.localRouter) && Array.isArray(raw.localRouter.streams) ? raw.localRouter.streams : [];
      const rawPlugins = Array.isArray(raw.plugins) ? raw.plugins : [];

      const streams = rawStreams.filter(object).map((st) => ({
        name: String(st.name ?? ""),
        topic: String(st.topic ?? ""),
        source: typeof st.builtin === "string" ? `builtin:${st.builtin}` : String(st.exec ?? ""),
      }));
      const bridges = rawPlugins.filter(object).map((pl) => {
        const targets = Array.isArray(pl.targets)
          ? pl.targets.filter(object).map((t) => `${String(t.name)}=>${String(t.handle ?? t.sessionId ?? t.threadId ?? "?")}`)
          : [];
        return {
          name: String(pl.name ?? ""),
          source: typeof pl.builtin === "string" ? `builtin:${pl.builtin}` : String(pl.exec ?? ""),
          targets: targets.join(", ") || "(none)",
          targetList: targets,
        };
      });

      emitResult(
        {
          ok: true,
          command: "connect list",
          title: "Configured Streams & Bridges",
          summary: `${streams.length} Stream(s), ${bridges.length} Bridge(s)`,
          fields: [{ label: "Config", value: cfgPath }],
          tables: [
            {
              title: "Node Streams (1-to-many topics)",
              columns: [
                { key: "name", header: "Stream" },
                { key: "topic", header: "Topic" },
                { key: "source", header: "Source" },
              ],
              rows: streams,
              emptyText: "No Streams configured.",
            },
            {
              title: "Connector Bridges (chat integrations)",
              columns: [
                { key: "name", header: "Bridge" },
                { key: "source", header: "Source" },
                { key: "targets", header: "Targets" },
              ],
              rows: bridges.map(({ name: bridgeName, source, targets }) => ({ name: bridgeName, source, targets })),
              emptyText: "No Bridges configured.",
            },
          ],
          next: ["hyp connect guide", "hyp connect add"],
          data: {
            configPath: cfgPath,
            exists: true,
            streams,
            bridges: bridges.map(({ name: bridgeName, source, targetList }) => ({
              name: bridgeName,
              source,
              targets: targetList,
            })),
          },
        },
        mode,
      );
      return;
    }

    throw new CliUsageError(
      sub ? `Unknown ${action} subcommand '${sub}'` : `Missing ${action} subcommand`,
      {
        usage: `hyp ${action} <${action === "stream" ? "add" : "setup"}|list|guide [name]> [--config <path>]`,
      },
    );
  }

  if (action === "discover") {
    const { values } = parseArgs({ args, allowPositionals: false, options: { "probe-ssh": { type: "boolean" } } });
    const env = detectLocalEnvironment();
    const machines = discoverRemoteMachines(undefined, env);
    const probes = values["probe-ssh"] ? await Promise.all(machines.map((m) => probeRemoteHost(m))) : undefined;
    console.log(JSON.stringify({ local: env, remoteMachines: probes ?? machines }, null, 2));
    return;
  }

  if (action === "onboard" || action === "up") {
    ctx.command = "onboard";
    const { values } = parseArgs({
      args,
      allowPositionals: false,
      options: {
        yes: { type: "boolean", short: "y" },
        agent: { type: "string" },
        assist: { type: "boolean" },
        prompt: { type: "boolean" },
        id: { type: "string" },
        router: { type: "string" },
        "token-file": { type: "string" },
        join: { type: "boolean" },
        "remote-ssh": { type: "string" },
        replace: { type: "boolean" },
        offline: { type: "boolean" },
        port: { type: "string" },
        config: { type: "string" },
        "no-start": { type: "boolean" },
        "install-service": { type: "boolean" },
      },
    });
    const cfgPath = values.config ?? defaultConfigPath();

    // Agent-assisted onboarding (`--prompt` prints raw concierge prompt verbatim)
    if (values.prompt === true || values.assist === true || values.agent !== undefined) {
      const { buildAgentOnboardingPrompt, detectAvailableAssistAgents, gatherOnboardingContext, launchAgentAssist } = await import("./assist.ts");
      const ctxInfo = await gatherOnboardingContext(cfgPath, defaultSocketPath());
      const prompt = buildAgentOnboardingPrompt(ctxInfo);
      if (values.prompt === true) {
        console.log(prompt);
        return;
      }
      const available = detectAvailableAssistAgents(ctxInfo.local);
      const chosen = (values.agent || available[0]) as "agy" | "claude" | "codex" | "opencode" | undefined;
      if (!chosen || !["agy", "claude", "codex", "opencode"].includes(chosen)) {
        throw new CliOperationalError(
          `No supported CLI agent found (${available.join(", ") || "none"}).`,
          {
            code: "NO_ASSIST_AGENT",
            fix: "Run `hyp onboard --prompt` to paste into Claude Desktop, Cursor, or another agent",
          },
        );
      }
      process.exitCode = launchAgentAssist(chosen, prompt);
      return;
    }

    const port = parsePortFlag(values.port, "--port", true);

    // Remote machine onboarding over SSH: create invite on local Node and pipe over SSH stdin.
    if (values["remote-ssh"]) {
      const host = values["remote-ssh"];
      const probe = await probeRemoteHost({ host, sources: ["cli"] });
      if (!probe.sshReachable) {
        throw new CliOperationalError(`Cannot reach ${host} over SSH: ${probe.error ?? "failed"}`, {
          code: "SSH_UNREACHABLE",
          fix: `Verify \`ssh ${host}\` succeeds, then re-run \`hyp onboard --remote-ssh ${host}\``,
        });
      }
      const remoteRouter = values.router ?? detectExposedTailscaleUrl(port ?? 8790);
      if (!remoteRouter) {
        throw new CliOperationalError("No exposed Node URL detected.", {
          code: "NODE_URL_UNAVAILABLE",
          fix: "Run `hyp share tailscale` first or pass --router https://...",
        });
      }
      const remoteId = values.id ?? `${probe.user ?? "user"}@${probe.hostname ?? host}`;
      const dbPath = join(dirname(resolve(values.config ?? defaultConfigPath())), "router", "router.sqlite");
      const core = new RouterCore({ dbPath });
      let remoteToken: string;
      try {
        remoteToken = core.addConnector(remoteId);
      } finally {
        core.close();
      }
      const code = encodeInvite({ connectorId: remoteId, router: remoteRouter, token: remoteToken });
      const sshRes = await onboardRemoteOverSsh({ host, inviteCode: code, installService: values["install-service"] === true });
      if (!sshRes.ok) {
        throw new CliOperationalError(
          `Remote onboarding on ${host} failed: ${(sshRes.stderr || sshRes.stdout).trim() || "unknown error"}`,
          {
            code: "REMOTE_ONBOARD_FAILED",
            fix: `Manual command: hyp onboard --join <<< '${code}'`,
          },
        );
      }
      emitResult(
        {
          ok: true,
          command: "onboard",
          title: "Remote Host Onboarded",
          summary: `Provisioned Connector '${remoteId}' on ${host}`,
          fields: [
            { label: "Host", value: host },
            { label: "Connector", value: remoteId },
            { label: "Node URL", value: remoteRouter },
          ],
          ...(sshRes.stdout.trim()
            ? { sections: [{ title: "Remote Output", lines: sshRes.stdout.trim().split("\n") }] }
            : {}),
          next: ["hyp status"],
          data: {
            host,
            connectorId: remoteId,
            routerUrl: remoteRouter,
            stdout: sshRes.stdout.trim(),
          },
        },
        mode,
      );
      return;
    }

    // Interactive TTY wizard when no explicit non-interactive flags/modes are given
    const nonInteractive = values.yes === true || values.join === true || values.router !== undefined ||
      values.id !== undefined || explicitMode === "json" || !process.stdin.isTTY || !process.stdout.isTTY;
    if (!nonInteractive) {
      const { runInteractiveOnboard } = await import("./onboard-interactive.ts");
      await runInteractiveOnboard({ configPath: values.config ?? defaultConfigPath(), port });
      return;
    }

    let inviteCode: string | undefined;
    if (values.join) {
      if (process.stdin.isTTY) process.stderr.write("Paste invite code (am1_...) then press Ctrl+D:\n");
      inviteCode = await readStdinLine();
      if (!inviteCode) {
        throw new CliOperationalError("No invite code received on stdin", {
          code: "MISSING_INVITE",
          fix: "Pipe an invite code: hyp onboard --join <<< 'am1_...'",
        });
      }
    }
    const result = await runOnboard({
      configPath: values.config ?? defaultConfigPath(),
      connectorId: values.id,
      routerUrl: values.router,
      tokenFile: values["token-file"],
      inviteCode,
      replace: values.replace === true,
      offline: values.offline === true,
      port,
      startDaemon: values["no-start"] !== true,
      installService: values["install-service"] === true,
    });

    const nodeKind = result.localRouter
      ? "embedded local Node"
      : result.remoteVerified
        ? "remote verified"
        : "remote";
    const fields: CliField[] = [
      { label: "Connector", value: result.connectorId },
      { label: "Config", value: `${result.configPath} (${result.configCreated ? "written" : "existing"})` },
      { label: "Node", value: `${result.routerUrl} (${nodeKind})` },
      { label: "Daemon", value: result.daemonRunning ? `running at ${result.socketPath}` : "stopped" },
      {
        label: "Harnesses",
        value: result.configuredHarnesses.length > 0
          ? result.configuredHarnesses.map((h) => h.harness).join(", ")
          : "none detected",
      },
    ];
    if (result.servicePath) {
      fields.push({ label: "Service", value: result.servicePath });
    }

    const next: string[] = [];
    if (!result.daemonRunning) next.push("hyp daemon");
    if (result.configuredHarnesses.length === 0) {
      next.push("hyp setup <antigravity|claude|codex|cursor|opencode|gemini|openclaw>");
    }
    for (const cmd of result.serviceInstructions ?? []) next.push(cmd);
    next.push("hyp status");
    next.push("Restart open harness apps/sessions once, then call hyp_join");

    emitResult(
      {
        ok: true,
        command: "onboard",
        title: "Hyphae Onboarding Complete",
        summary: `Connector ${result.connectorId} ready (${result.daemonRunning ? "daemon running" : "daemon stopped"})`,
        fields,
        next,
        data: result,
      },
      mode,
    );
    return;
  }

  if (action === "init") {
    const { values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: { id: { type: "string" }, router: { type: "string" }, "token-file": { type: "string" } },
    });
    if (positionals.length > 1 || values.id === undefined || !connectorPattern.test(values.id) || !values.router || !values["token-file"]) {
      throw new CliUsageError("Missing or invalid init arguments", {
        usage: "hyp init [config] --id <user@host> --router <origin> --token-file <file>",
      });
    }
    const path = resolve(positionals[0] ?? defaultConfigPath());
    const config = {
      connectorId: values.id,
      stateDir: "state",
      routers: [{ name: "primary", url: values.router, tokenFile: resolve(values["token-file"]) }],
    };
    mkdirSync(dirname(path), { mode: 0o700, recursive: true });
    writeFileSync(path, JSON.stringify(config, null, 2) + "\n", { mode: 0o600, flag: "wx" });
    if (mode === "json") {
      emitResult(
        {
          ok: true,
          command: "init",
          title: "Config Initialized",
          summary: `Wrote config at ${path}`,
          fields: [
            { label: "Config", value: path },
            { label: "Connector", value: values.id },
            { label: "Node", value: values.router },
          ],
          data: { path, connectorId: values.id, router: values.router },
        },
        mode,
      );
    } else {
      console.log(path);
    }
    return;
  }

  if (action === "daemon") {
    const { values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: { socket: { type: "string" } },
    });
    if (positionals.length > 1) {
      throw new CliUsageError("Unexpected extra positional arguments", {
        usage: "hyp daemon [config] [--socket <path>]",
      });
    }
    const config = loadConfig(positionals[0] ?? defaultConfigPath());
    const running = await startDaemon(config, { socketPath: values.socket });
    await new Promise<void>((resolveStop) => {
      const stop = () => { void running.stop().finally(resolveStop); };
      process.once("SIGINT", stop);
      process.once("SIGTERM", stop);
    });
    return;
  }

  if (action === "mcp") {
    const { values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: {
        backend: { type: "string" },
        thread: { type: "string" },
        resume: { type: "boolean" },
        remote: { type: "string" },
        "t3-url": { type: "string" },
        "t3-base-dir": { type: "string" },
        "claude-channel": { type: "boolean" },
        ephemeral: { type: "boolean" },
      },
    });
    const backend = values.backend;
    if (positionals.length > 1 || (backend !== undefined && !isHarness(backend))) {
      throw new CliUsageError("Invalid mcp arguments", {
        usage: "hyp mcp [socket] [--claude-channel] [--backend <harness>] [--thread <uuid>] [--resume] [--remote <addr>] [--t3-url <url>] [--t3-base-dir <dir>] [--ephemeral]",
      });
    }
    runMcp(positionals[0] ?? defaultSocketPath(), {
      ...(backend ? { backend } : {}),
      channel: values["claude-channel"] === true,
      threadId: values.thread,
      resume: values.resume === true,
      remote: values.remote,
      ...(values["t3-url"] ? { t3Url: values["t3-url"] } : {}),
      ...(values["t3-base-dir"] ? { t3BaseDir: values["t3-base-dir"] } : {}),
      ephemeral: values.ephemeral === true,
    });
    return;
  }

  if (action === "hook") {
    const { values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: { socket: { type: "string" } },
    });
    const [harness, event] = positionals;
    if (positionals.length !== 2 || !isHarness(harness) || harness === "herdr" || !validEvents.has(event as HookEvent)) {
      throw new CliUsageError("Invalid hook harness or event", {
        usage: "hyp hook <antigravity|claude|codex|cursor|opencode|gemini|openclaw> <pre-tool-use|post-tool-use|pre-invocation|stop> [--socket <path>]",
      });
    }
    const runtime = resolveRuntimePaths();
    const quote = (v: string) => (/^[A-Za-z0-9_./:@=-]+$/.test(v) ? v : `'${v.replace(/'/g, `'\\''`)}'`);
    await runHook({
      harness,
      event: event as HookEvent,
      socketPath: values.socket ?? defaultSocketPath(),
      explicitSocket: values.socket,
      cliPath: `${quote(runtime.nodeBin)} ${quote(runtime.cliScript)}`,
    });
    return;
  }

  if (action === "wait" || action === "watch") {
    const { values } = parseArgs({
      args,
      allowPositionals: false,
      options: {
        session: { type: "string" },
        handle: { type: "string" },
        socket: { type: "string" },
        timeout: { type: "string" },
        stream: { type: "boolean" },
      },
    });
    const timeoutSeconds = values.timeout !== undefined ? Number(values.timeout) : undefined;
    if (timeoutSeconds !== undefined && (!Number.isFinite(timeoutSeconds) || timeoutSeconds < 0)) {
      throw new CliUsageError("Expected non-negative --timeout seconds", {
        usage: "hyp wait [--stream] [--session <id> | --handle <handle>] [--timeout <sec>]",
      });
    }
    process.exitCode = await runWait({
      socketPath: values.socket ?? defaultSocketPath(),
      mode: action === "watch" || values.stream === true ? "stream" : "once",
      sessionId: values.session,
      handle: values.handle,
      timeoutSeconds,
    });
    return;
  }

  if (action === "setup") {
    const { values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: {
        scope: { type: "string" },
        dir: { type: "string" },
        socket: { type: "string" },
        config: { type: "string" },
        "no-sidecar": { type: "boolean" },
        channel: { type: "boolean" },
        remote: { type: "string" },
        "t3-url": { type: "string" },
        "t3-base-dir": { type: "string" },
        install: { type: "boolean" },
      },
    });
    const target = positionals[0];
    const scope = (values.scope ?? "user") as "user" | "project";
    if (!target || positionals.length > 1) {
      throw new CliUsageError(target ? "Expected a single setup target" : "Missing setup target", {
        usage: "hyp setup <antigravity|claude|codex|cursor|opencode|gemini|openclaw|t3|all|service> [--scope user|project]",
      });
    }
    if (scope !== "user" && scope !== "project") {
      throw new CliUsageError(`Invalid --scope '${values.scope}' (expected 'user' or 'project')`, {
        usage: "hyp setup <target> [--scope user|project]",
      });
    }

    if (target === "service") {
      ctx.command = "setup service";
      const result = setupService({
        install: values.install === true,
        configPath: resolve(values.config ?? defaultConfigPath()),
      });
      if (result.installed) {
        emitResult(
          {
            ok: true,
            command: "setup service",
            title: "OS Service Installed",
            summary: `Installed service definition at ${result.path}`,
            fields: [
              { label: "Service File", value: result.path },
              { label: "Installed", value: "yes" },
            ],
            next: result.instructions,
            data: result,
          },
          mode,
        );
      } else {
        emitResult(
          {
            ok: true,
            command: "setup service",
            title: "OS Service Preview",
            summary: `Preview only — pass --install to write ${result.path}`,
            fields: [
              { label: "Target Path", value: result.path },
              { label: "Installed", value: "no (preview)" },
            ],
            sections: [{ title: "Service Unit", lines: result.content.trimEnd().split("\n") }],
            next: ["hyp setup service --install"],
            data: result,
          },
          mode,
        );
      }
      return;
    }

    if (target !== "all" && !configurableHarnessSet.has(target)) {
      throw new CliUsageError(`Unknown setup target '${target}'`, {
        usage: "hyp setup <antigravity|claude|codex|cursor|opencode|gemini|openclaw|t3|all|service>",
        fix: `Valid targets: ${ALL_CONFIGURABLE_HARNESSES.join(", ")}, all, service`,
      });
    }

    const setupOpts = {
      scope,
      projectDir: values.dir,
      socketPath: values.socket,
      configPath: values.config,
      noSidecar: values["no-sidecar"] === true,
      channel: values.channel === true,
      codexRemote: values.remote,
      t3Url: values["t3-url"],
      t3BaseDir: values["t3-base-dir"],
    };
    const t3Initialized = Boolean(values["t3-url"] || values["t3-base-dir"] || existsSync(t3StateDbPath(defaultT3BaseDir())));
    const targets: ConfigurableHarness[] = target === "all"
      ? ALL_CONFIGURABLE_HARNESSES.filter((item) => item !== "t3" || t3Initialized)
      : [target as ConfigurableHarness];
    const results: SetupResult[] = targets.map((item) => {
      if (item === "antigravity") return setupAntigravity(setupOpts);
      if (item === "claude") return setupClaude(setupOpts);
      if (item === "codex") return setupCodex(setupOpts);
      if (item === "cursor") return setupCursor(setupOpts);
      if (item === "opencode") return setupOpenCode(setupOpts);
      if (item === "gemini") return setupGemini(setupOpts);
      if (item === "t3") return setupT3(setupOpts);
      return setupOpenClaw(setupOpts);
    });

    const totalFiles = results.reduce((acc, r) => acc + r.files.length, 0);
    const sections: CliSection[] = results.map((res) => ({
      title: `Harness: ${res.harness}`,
      lines: [
        ...res.files.map((f) => `file: ${f}`),
        ...res.notes.map((n) => `note: ${n}`),
      ],
    }));

    emitResult(
      {
        ok: true,
        command: "setup",
        title: "Harness Setup Complete",
        summary: `Configured ${results.length} harness(es) in ${scope} scope (${totalFiles} file(s) written)`,
        fields: [
          { label: "Scope", value: scope },
          { label: "Harnesses", value: results.map((r) => r.harness).join(", ") },
        ],
        tables: [
          {
            title: "Configured Harnesses",
            columns: [
              { key: "harness", header: "Harness" },
              { key: "files", header: "Files", align: "right" },
              { key: "primary", header: "Primary Config" },
            ],
            rows: results.map((r) => ({
              harness: r.harness,
              files: r.files.length,
              primary: r.files[0] ?? "(none)",
            })),
          },
        ],
        sections,
        next: [
          "hyp status",
          "Restart open harness apps/sessions to load updated MCP and hooks",
        ],
        data: { scope, targets: results },
      },
      mode,
    );
    return;
  }

  if (action === "status" || action === "sessions") {
    const { values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: {
        socket: { type: "string" },
        config: { type: "string" },
        sessions: { type: "boolean" },
        discover: { type: "boolean" },
        "probe-ssh": { type: "boolean" },
        prune: { type: "boolean" },
        "older-than-hours": { type: "string" },
      },
    });
    if (positionals.length > 1) {
      throw new CliUsageError("Expected at most one config path argument", {
        usage: "hyp status [config] [--sessions | --discover | --probe-ssh | --prune]",
      });
    }
    if (values.discover === true || values["probe-ssh"] === true) {
      const env = detectLocalEnvironment();
      const machines = discoverRemoteMachines(undefined, env);
      const probes = values["probe-ssh"] ? await Promise.all(machines.map((m) => probeRemoteHost(m))) : undefined;
      console.log(JSON.stringify({ local: env, remoteMachines: probes ?? machines }, null, 2));
      return;
    }
    const socketPath = values.socket ?? defaultSocketPath();
    if (values.prune === true) {
      const hours = values["older-than-hours"] !== undefined ? Number(values["older-than-hours"]) : 168;
      if (!Number.isFinite(hours) || hours < 0) {
        throw new CliUsageError("Expected non-negative --older-than-hours", {
          usage: "hyp status --prune [--older-than-hours <hours>]",
        });
      }
      const res = await daemonRpc(socketPath, { type: "daemon.prune", maxAgeMs: hours * 3_600_000 });
      if (!res.ok || !res.result) {
        throw new CliOperationalError(`Connector daemon not reachable at ${socketPath}`, {
          code: "DAEMON_UNREACHABLE",
          fix: "Run `hyp daemon` or `hyp onboard`",
        });
      }
      console.log(JSON.stringify(res.result, null, 2));
      return;
    }
    if (action === "sessions" || values.sessions === true) {
      const res = await daemonRpc(socketPath, { type: "daemon.status" });
      if (!res.ok || !res.result) {
        throw new CliOperationalError(`Connector daemon not reachable at ${socketPath}`, {
          code: "DAEMON_UNREACHABLE",
          fix: "Run `hyp daemon` or `hyp onboard`",
        });
      }
      console.log(JSON.stringify(res.result.sessions, null, 2));
      return;
    }

    const cfgPath = resolve(values.config ?? positionals[0] ?? defaultConfigPath());
    await renderHealthStatus("status", cfgPath, socketPath, mode);
    return;
  }

  if (action === "mute" || action === "unmute" || action === "mutes") {
    const { values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: { socket: { type: "string" }, list: { type: "boolean" } },
    });
    const socketPath = values.socket ?? defaultSocketPath();
    if (action === "mutes" || values.list === true || (action === "mute" && (positionals.length === 0 || positionals[0] === "list"))) {
      ctx.command = "mutes";
      const res = await daemonRpc(socketPath, { type: "mute.list" });
      if (!res.ok || !res.result) {
        throw new CliOperationalError(`Connector daemon not reachable at ${socketPath}`, {
          code: "DAEMON_UNREACHABLE",
          fix: "Run `hyp daemon` or `hyp onboard`",
        });
      }
      const mutes = Array.isArray(res.result.mutes)
        ? (res.result.mutes as Array<{ pattern?: string; scope?: string; mutedBy?: string; mutedAt?: string }>)
        : [];
      const rows: CliTableRow[] = mutes.map((m) => ({
        pattern: m.pattern ?? "",
        scope: m.scope === "*" || !m.scope ? "connector" : m.scope,
        mutedBy: m.mutedBy ?? "cli",
      }));

      emitResult(
        {
          ok: true,
          command: "mutes",
          title: "Mute Rules",
          summary: mutes.length === 0 ? "No active connector-level mute rules" : `${mutes.length} active mute rule(s)`,
          tables: [
            {
              title: "Active Rules",
              columns: [
                { key: "pattern", header: "Pattern" },
                { key: "scope", header: "Scope" },
                { key: "mutedBy", header: "Muted By" },
              ],
              rows,
              emptyText: "No active connector-level mute rules.",
            },
          ],
          next: mutes.length === 0
            ? ["hyp mute <user@host/handle | user@host/* | #channel | topic:name | plugin:name>"]
            : ["hyp unmute <pattern>"],
          data: { mutes },
        },
        mode,
      );
      return;
    }

    const target = positionals[0];
    if (!target || positionals.length > 1) {
      throw new CliUsageError(target ? "Expected a single mute target" : `Missing target for ${action}`, {
        usage: `hyp ${action} <user@host/handle | user@host/* | #channel | topic:name | plugin:name>`,
      });
    }
    const res = await daemonRpc(socketPath, { type: action === "mute" ? "mute.add" : "mute.remove", target });
    if (!res.ok || !res.result) {
      throw new CliOperationalError(
        res.error ?? `Could not ${action} '${target}' (is the Connector daemon running at ${socketPath}?)`,
        {
          code: action === "mute" ? "MUTE_FAILED" : "UNMUTE_FAILED",
          fix: "Verify the daemon is running (`hyp status`) and the target pattern is valid",
        },
      );
    }

    if (action === "mute") {
      const rule = object(res.result.rule) ? res.result.rule : {};
      const pattern = typeof rule.pattern === "string" ? rule.pattern : target;
      const scope = rule.scope === "*" || typeof rule.scope !== "string" ? "connector" : rule.scope;
      const mutedBy = typeof rule.mutedBy === "string" ? rule.mutedBy : "cli";
      emitResult(
        {
          ok: true,
          command: "mute",
          title: "Mute Rule Added",
          summary: `Muted '${pattern}' (${scope} scope)`,
          fields: [
            { label: "Pattern", value: pattern },
            { label: "Scope", value: scope },
            { label: "Muted By", value: mutedBy },
          ],
          next: ["hyp mutes", `hyp unmute ${pattern}`],
          data: res.result,
        },
        mode,
      );
    } else {
      const pattern = typeof res.result.pattern === "string" ? res.result.pattern : target;
      const removed = res.result.removed === true;
      emitResult(
        {
          ok: true,
          command: "unmute",
          title: removed ? "Mute Rule Removed" : "Mute Rule Not Found",
          summary: removed ? `Unmuted '${pattern}'` : `No matching mute rule for '${pattern}'`,
          fields: [
            { label: "Pattern", value: pattern },
            { label: "Removed", value: removed ? "yes" : "no" },
          ],
          next: ["hyp mutes"],
          data: res.result,
        },
        mode,
      );
    }
    return;
  }

  if (action === "send-files") {
    ctx.command = "send-files";
    const { values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: {
        note: { type: "string", short: "m" },
        from: { type: "string" },
        socket: { type: "string" },
        config: { type: "string" },
      },
    });
    const [to, ...rawFiles] = positionals;
    if (!to || !addressPattern.test(to) || rawFiles.length === 0 || rawFiles.length > 50) {
      throw new CliUsageError(
        !to
          ? "Missing destination (<connector/handle>) and file paths"
          : !addressPattern.test(to)
            ? `Invalid destination '${to}' (expected direct peer address <connector>/<handle>)`
            : rawFiles.length === 0
              ? "Expected at least one file path to send"
              : "At most 50 files can be sent per transfer",
        {
          usage: "hyp send-files <connector/handle> <file...> [--note <text>] [--from <handle>] [--config <path>] [--socket <path>]",
        },
      );
    }
    if (values.from !== undefined && !handlePattern.test(values.from)) {
      throw new CliUsageError(`Invalid --from handle '${values.from}'`, {
        usage: "hyp send-files <connector/handle> <file...> [--note <text>] [--from <handle>]",
      });
    }
    const files = rawFiles.map((file) => resolve(file));
    const cfgPath = resolve(values.config ?? defaultConfigPath());
    let socketPath = values.socket;
    if (!socketPath) {
      if (values.config && existsSync(cfgPath)) {
        try {
          socketPath = join(loadConfig(cfgPath).directory, "connector.sock");
        } catch {
          socketPath = defaultSocketPath();
        }
      } else {
        socketPath = defaultSocketPath();
      }
    }

    type TransferOut = {
      transferId: string;
      status: string;
      encrypted: boolean;
      to: string;
      files: Array<{ name: string; size: number; sha256: string }>;
      ciphertextBytes: number;
      recipientFingerprint: string;
    };

    let via: "daemon" | "standalone" = "daemon";
    let transferResult: TransferOut;

    const rpcRes = await daemonRpc(
      socketPath,
      {
        type: "transfer.send",
        to,
        files,
        ...(values.note ? { text: values.note } : {}),
        ...(values.from ? { fromHandle: values.from } : {}),
      },
      60_000,
    );

    if (rpcRes.ok && rpcRes.result) {
      transferResult = rpcRes.result as unknown as TransferOut;
    } else if (rpcRes.error !== undefined) {
      throw new CliOperationalError(rpcRes.error, {
        code: "TRANSFER_FAILED",
        fix: "Verify the recipient connector is online and registered on the router, and that all file paths exist",
      });
    } else {
      // Fallback: standalone direct upload using connector.json + connector secret store keys.
      if (!existsSync(cfgPath)) {
        throw new CliOperationalError(
          `Connector daemon not reachable at ${socketPath} and config not found at ${cfgPath}`,
          {
            code: "DAEMON_UNREACHABLE",
            fix: "Run `hyp daemon` or pass `--config <connector.json>`",
          },
        );
      }
      via = "standalone";
      const config = loadConfig(cfgPath);
      const primaryCfg = config.routers.find((r) => r.name === "primary");
      if (!primaryCfg) {
        throw new CliOperationalError("No primary router configured in connector.json", { code: "CONFIG_INVALID" });
      }
      const target = parseAddress(to);
      if (!target) {
        throw new CliUsageError(`Invalid destination '${to}'`);
      }
      const keys = loadOrCreateConnectorKeys(config.directory, config.connectorId);
      const router = new RouterLink(primaryCfg);
      await router.registerKeys(createKeyRegistration(config.connectorId, keys));
      const peerKeys = await router.peerKeys();
      const recipient = peerKeys.find((entry) => entry.connectorId === target.connectorId);
      if (!recipient || !isRawKey(recipient.encryptionKey)) {
        throw new CliOperationalError(
          `Recipient connector ${target.connectorId} has not registered encryption keys on the router`,
          {
            code: "RECIPIENT_KEYS_UNAVAILABLE",
            fix: `Ensure ${target.connectorId}'s connector daemon has connected to the router at least once`,
          },
        );
      }
      const packed = packFiles(files, {
        ...(values.from ? { fromHandle: values.from } : {}),
        ...(values.note ? { note: values.note } : {}),
      });
      const transferId = randomUUID();
      const sealed = sealTransfer(
        {
          id: transferId,
          type: "files",
          from: config.connectorId,
          to: target.connectorId,
          toHandle: target.handle,
          ttlMs: 24 * 60 * 60 * 1000,
        },
        packed.payload,
        keys.signingKey,
        recipient.encryptionKey,
      );
      await router.sendTransfer(transferId, sealed.header, sealed.ciphertext);
      transferResult = {
        transferId,
        status: "stored",
        encrypted: true,
        to,
        files: packed.manifest.files.map(({ name, size, sha256 }) => ({ name, size, sha256 })),
        ciphertextBytes: sealed.ciphertext.length,
        recipientFingerprint: keyFingerprint(recipient.encryptionKey),
      };
    }

    const fileRows: CliTableRow[] = transferResult.files.map((file) => ({
      name: file.name,
      size: `${file.size} B`,
      sha256: file.sha256.slice(0, 12),
    }));

    emitResult(
      {
        ok: true,
        command: "send-files",
        title: "Encrypted Files Sent",
        summary: `Sent ${transferResult.files.length} E2EE file(s) to ${transferResult.to} (${transferResult.ciphertextBytes} B ciphertext)`,
        fields: [
          { label: "Destination", value: transferResult.to },
          { label: "Transfer ID", value: transferResult.transferId },
          { label: "Encryption", value: "E2EE (X25519 + AES-256-GCM + Ed25519)" },
          { label: "Recipient Key", value: transferResult.recipientFingerprint },
          { label: "Ciphertext", value: `${transferResult.ciphertextBytes} B` },
          { label: "Via", value: via },
        ],
        tables: [
          {
            title: "Files",
            columns: [
              { key: "name", header: "File" },
              { key: "size", header: "Size", align: "right" },
              { key: "sha256", header: "SHA-256" },
            ],
            rows: fileRows,
          },
        ],
        data: { ...transferResult, via },
      },
      mode,
    );
    return;
  }

  if (action === "prune") {
    const { values } = parseArgs({
      args,
      allowPositionals: false,
      options: { "older-than-hours": { type: "string" }, socket: { type: "string" } },
    });
    const hours = values["older-than-hours"] !== undefined ? Number(values["older-than-hours"]) : 168;
    if (!Number.isFinite(hours) || hours < 0) {
      throw new CliUsageError("Expected non-negative --older-than-hours", {
        usage: "hyp prune [--older-than-hours <hours>] [--socket <path>]",
      });
    }
    const socketPath = values.socket ?? defaultSocketPath();
    const res = await daemonRpc(socketPath, { type: "daemon.prune", maxAgeMs: hours * 3_600_000 });
    if (!res.ok || !res.result) {
      throw new CliOperationalError(`Connector daemon not reachable at ${socketPath}`, {
        code: "DAEMON_UNREACHABLE",
        fix: "Run `hyp daemon` or `hyp onboard`",
      });
    }
    console.log(JSON.stringify(res.result, null, 2));
    return;
  }

  if (action === "doctor") {
    const { values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: { socket: { type: "string" }, config: { type: "string" } },
    });
    if (positionals.length > 1) {
      throw new CliUsageError("Expected at most one config path argument", {
        usage: "hyp doctor [config] [--socket <path>]",
      });
    }
    const cfgPath = resolve(values.config ?? positionals[0] ?? defaultConfigPath());
    await renderHealthStatus("doctor", cfgPath, values.socket ?? defaultSocketPath(), mode);
    return;
  }

  if (action === undefined || action === "--help" || action === "-h" || action === "help") {
    ctx.command = "help";
    const { values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: { all: { type: "boolean", short: "a" } },
    });
    if (positionals.length > 0) {
      throw new CliUsageError(`Unexpected help argument '${positionals[0]}'`, {
        usage: "hyp --help [--all] [--json | --plain | --pretty]",
      });
    }
    console.log(renderHelp(values.all === true, mode, readPackageVersion()));
    return;
  }

  throw new CliUsageError(`Unknown command '${action}'`, {
    usage: "hyp <command> [args] [--json | --plain | --pretty]",
    fix: "Run `hyp --help` to list available commands or `hyp --help --json` for the machine schema",
  });
}

const ctx: ExecutionContext = { command: "hyp", mode: "plain" };

await runCli(ctx).catch((error: unknown) => {
  const { cliError, exitCode } = classifyCliError(error);
  emitError(ctx.command, cliError, ctx.mode);
  process.exitCode = exitCode;
});
