#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { loadConfig } from "./config.ts";
import { startDaemon } from "./daemon.ts";
import { detectLocalEnvironment, discoverRemoteMachines, onboardRemoteOverSsh, probeRemoteHost } from "./discover.ts";
import { daemonRpc, runHook, type HookEvent } from "./hooks.ts";
import { runMcp } from "./mcp.ts";
import { ALL_GUIDES, findGuide } from "./plugin-catalog.ts";
import { connectorPattern, isHarness, object } from "./protocol.ts";
import { detectExposedTailscaleUrl, encodeInvite, exposeTailscale, unexposeTailscale } from "./remote.ts";
import { captureSecretViaWeb, collectSecretRefs, deleteSecret, listSecrets, readSecret, writeSecret } from "./secrets.ts";
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

const usage = `Hyphae (hyp) — cross-harness agent mesh & event node

Core commands:
  hyp onboard [--assist | --prompt | --join | --remote-ssh <host>]
      Set up private/public nodes, harnesses, streams, bridges & SSH hosts
  hyp status [--sessions | --discover | --probe-ssh | --prune]
      Health check (Node 24, daemon, nodes, 0600 secrets, harnesses & live peers)
  hyp connect [add | list | guide [name]]
      Configure or inspect node event streams (GitHub, Prometheus) & chat bridges (Slack, Telegram)
  hyp secret <set <name> [--web] | list | rm <name> | check>
      Manage 0600 secrets privately (hidden TTY prompt or --web out-of-band browser form)
  hyp share <tailscale | invite <user@host> | stop>
      Expose your node on Tailscale Services and generate remote invite codes
  hyp setup <antigravity|claude|codex|cursor|opencode|gemini|openclaw|all|service>
      Wire (or re-wire) MCP, hooks, rules, skills, or OS auto-start service
  hyp skill [install [antigravity|claude|codex|cursor|openclaw|project|all] | print | path]
      Install or print the standalone Hyphae agent skill (starting point for any agent)

Runtime:
  hyp daemon | hyp wait [--stream]

Run \`hyp --help --all\` for advanced & plumbing commands (node, mcp, hook, init).`;

const fullUsage = `${usage}

Advanced & plumbing commands (aliases kept for hooks/scripts):
  hyp init [config] --id <user@host> --router <origin> --token-file <file>
  hyp mcp [socket] [--claude-channel] [--backend herdr|openclaw] [--thread UUID] [--resume] [--remote <addr>] [--ephemeral]
  hyp hook <antigravity|claude|codex|cursor|opencode|gemini|openclaw> <pre-tool-use|post-tool-use|pre-invocation|stop>
  hyp watch [--session <id> | --handle <handle>] [--timeout <sec>]   (alias: hyp wait --stream)
  hyp doctor | sessions | prune | discover | plugin | stream         (aliases under status / connect)
  hyp node <expose|unexpose|invite|serve|add-connector|revoke-connector|add-publisher|revoke-publisher|github-receiver>`;

function readStdinLine(): Promise<string> {
  return new Promise((resolve) => {
    const chunks: Buffer[] = [];
    process.stdin.on("data", (chunk: Buffer) => chunks.push(chunk));
    process.stdin.on("end", () => resolve(Buffer.concat(chunks).toString("utf8").trim()));
    process.stdin.on("error", () => resolve(""));
  });
}

const validEvents = new Set<HookEvent>(["pre-tool-use", "post-tool-use", "pre-invocation", "stop"]);

async function main(): Promise<void> {
  const [rawAction, ...rawArgs] = process.argv.slice(2);
  let action = rawAction;
  let args = rawArgs;

  // Map clean `hyp share <tailscale|invite|stop>` onto `router <expose|invite|unexpose>`
  if (action === "share") {
    const [sub, ...rest] = args;
    if (sub === "tailscale") { action = "router"; args = ["expose", "tailscale", ...rest]; }
    else if (sub === "stop" || sub === "unexpose") { action = "router"; args = ["unexpose", "tailscale", ...rest]; }
    else if (sub === "invite") { action = "router"; args = ["invite", ...rest]; }
    else {
      throw new Error("Usage: hyp share <tailscale [--service hyphae] | invite <user@host> | stop>");
    }
  }

  if (action === "skill") {
    const { values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: { dir: { type: "string" } },
    });
    const [sub = "print", target = "all"] = positionals;
    if (sub === "print") {
      process.stdout.write(readCanonicalSkill());
      return;
    }
    if (sub === "path") {
      console.log(resolveCanonicalSkillPath());
      return;
    }
    if (sub === "install") {
      const valid = new Set<SkillTarget>(["antigravity", "claude", "codex", "cursor", "openclaw", "project", "all"]);
      if (!valid.has(target as SkillTarget)) {
        throw new Error("Usage: hyp skill install [antigravity|claude|codex|cursor|openclaw|project|all] [--dir <path>]");
      }
      const res = installSkill(target as SkillTarget, { projectDir: values.dir });
      console.log("Installed Hyphae skill:");
      for (const f of res.files) console.log(`  - ${f}`);
      return;
    }
    throw new Error("Usage: hyp skill [install [harness|project|all] | print | path]");
  }

  if (action === "node" || action === "router") {
    const [sub, ...rest] = args;
    if (sub === "expose") {
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
        throw new Error("Usage: hyp router expose tailscale [--service <name>] [--port 8790] [--https <port>] [--dry-run]");
      }
      const res = exposeTailscale({
        localPort: values.port ? Number(values.port) : 8790,
        service: values.service,
        httpsPort: values.https ? Number(values.https) : undefined,
        dryRun: values["dry-run"] === true,
      });
      console.log(`${res.applied ? "Exposed" : "Dry run"} (${res.mode}): ${res.url}`);
      console.log(`  Command : ${res.command.join(" ")}`);
      console.log(`\nTo invite another machine on your tailnet:\n  hyp router invite <user@host> --router ${res.url}`);
      return;
    }
    if (sub === "unexpose") {
      const { values, positionals } = parseArgs({
        args: rest,
        allowPositionals: true,
        options: { service: { type: "string" }, https: { type: "string" } },
      });
      if (positionals[0] !== "tailscale") {
        throw new Error("Usage: hyp router unexpose tailscale [--service <name>] [--https 8790]");
      }
      const cmd = unexposeTailscale({
        service: values.service,
        httpsPort: values.https ? Number(values.https) : undefined,
      });
      console.log(`Removed Tailscale exposure: ${cmd.join(" ")}`);
      return;
    }
    if (sub === "invite") {
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
        throw new Error("Usage: hyp router invite <user@host> [--router https://...] [--db <router.sqlite>]");
      }
      const dbPath = resolve(values.db ?? join(configDir, "router", "router.sqlite"));
      const routerUrl = values.router ?? detectExposedTailscaleUrl(values.port ? Number(values.port) : 8790);
      if (!routerUrl) {
        throw new Error("Could not detect an exposed Tailscale router URL. Pass --router https://<host> or run `hyp router expose tailscale` first.");
      }
      const core = new RouterCore({ dbPath });
      let token: string;
      try {
        token = core.addConnector(connectorId);
      } finally {
        core.close();
      }
      const code = encodeInvite({ connectorId, router: routerUrl, token });
      console.log(`Created connector '${connectorId}' on ${dbPath} for ${routerUrl}\n`);
      console.log("Run this on the remote machine (keeps the token out of CLI argv/ps):");
      console.log(`  hyp onboard --join <<< '${code}'`);
      console.log("\nTreat this invite string like a private password; revoke anytime with:");
      console.log(`  hyp router revoke-connector ${connectorId} --db ${dbPath}`);
      return;
    }
    const { routerUsage, runRouterCommand } = await import("./core/router/commands.ts");
    if (args.length === 0 || args[0] === "--help") {
      console.log(
        `  expose tailscale [--service <name>] [--port 8790] [--https <port>] [--dry-run]\n` +
        `  unexpose tailscale [--service <name>] [--https 8790]\n` +
        `  invite <user@host> [--router https://...] [--db <router.sqlite>]\n` +
        routerUsage,
      );
    } else {
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
    const dir = resolve(values["config-dir"] ?? configDir);
    if (sub === "set") {
      if (!target) throw new Error("Usage: hyp secret set <name> [--web] (reads from hidden TTY prompt, browser form, or stdin)");
      if (values.web === true) {
        const res = await captureSecretViaWeb(target, {
          configDir: dir,
          openBrowser: values["no-open"] !== true,
          onReady: (url) => {
            process.stderr.write(`Waiting for secret '${target}' via local out-of-band form:\n  ${url}\n`);
          },
        });
        console.log(`Saved secret '${target}' (0600) at ${res.path}`);
        return;
      }
      let value: string;
      if (process.stdin.isTTY && process.stdout.isTTY) {
        const clack = await import("@clack/prompts");
        const entered = await clack.password({ message: `Enter secret value for '${target}'` });
        if (clack.isCancel(entered) || typeof entered !== "string" || entered.trim().length === 0) {
          throw new Error("Secret entry cancelled");
        }
        value = entered;
      } else {
        value = await readStdinLine();
        if (!value) {
          throw new Error(`No secret received on stdin. In non-TTY / agent sessions, use: hyp secret set ${target} --web`);
        }
      }
      const path = writeSecret(target, value, dir);
      console.log(`Saved secret '${target}' (0600) at ${path}`);
      return;
    }
    if (sub === "list") {
      const secrets = listSecrets(dir);
      if (secrets.length === 0) {
        console.log(`No secrets stored in ${join(dir, "secrets")}`);
        return;
      }
      for (const s of secrets) {
        console.log(`[${s.modeOk ? "OK" : "BAD_MODE"}] ${s.name} (${s.bytes} B) — ${s.path}`);
      }
      return;
    }
    if (sub === "rm" || sub === "delete") {
      if (!target) throw new Error("Usage: hyp secret rm <name>");
      const removed = deleteSecret(target, dir);
      console.log(removed ? `Removed secret '${target}'` : `Secret '${target}' not found`);
      return;
    }
    if (sub === "check") {
      const cfgPath = resolve(target ?? defaultConfigPath());
      if (!existsSync(cfgPath)) throw new Error(`Config not found: ${cfgPath}`);
      const raw = JSON.parse(readFileSync(cfgPath, "utf8")) as Record<string, unknown>;
      const refs = collectSecretRefs(raw);
      if (refs.length === 0) {
        console.log("No secret references configured in connector.json.");
        return;
      }
      let ok = true;
      for (const ref of refs) {
        try {
          readSecret(ref.secret, dirname(cfgPath));
          console.log(`[OK]   ${ref.secret} (${ref.owner} -> ${ref.envKey})`);
        } catch (error) {
          ok = false;
          console.log(`[FAIL] ${ref.secret} (${ref.owner} -> ${ref.envKey}): ${error instanceof Error ? error.message : String(error)}`);
        }
      }
      if (!ok) process.exitCode = 1;
      return;
    }
    throw new Error("Usage: hyp secret <set <name>|list|rm <name>|check [config]>");
  }

  if (action === "connect" || action === "plugin" || action === "stream") {
    const { values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: { config: { type: "string" } },
    });
    const [sub = action === "connect" ? "add" : undefined, name] = positionals;
    const cfgPath = resolve(values.config ?? defaultConfigPath());
    if (sub === "setup" || sub === "add") {
      const { runPluginSetupWizard } = await import("./onboard-interactive.ts");
      await runPluginSetupWizard(cfgPath);
      return;
    }
    if (sub === "guide") {
      if (name) {
        const g = findGuide(name);
        if (!g) throw new Error(`Unknown plugin/stream '${name}'. Available: ${ALL_GUIDES.map((x) => x.id).join(", ")}`);
        const { formatGuideCard } = await import("./onboard-interactive.ts");
        console.log(formatGuideCard(g));
        return;
      }
      for (const g of ALL_GUIDES) {
        console.log(`${g.id.padEnd(18)} [${g.kind}] ${g.label} — ${g.tagline}`);
      }
      console.log("\nRun `hyp plugin guide <id>` for full setup instructions, or `hyp plugin setup` for interactive setup.");
      return;
    }
    if (sub === "list") {
      if (!existsSync(cfgPath)) {
        console.log(`No config at ${cfgPath}. Run \`hyp onboard\` first.`);
        return;
      }
      const raw = JSON.parse(readFileSync(cfgPath, "utf8")) as Record<string, unknown>;
      const streams = object(raw.localRouter) && Array.isArray(raw.localRouter.streams) ? raw.localRouter.streams : [];
      const plugins = Array.isArray(raw.plugins) ? raw.plugins : [];
      console.log("Router Data Streams (1-to-many topics with CloudEvents filters):");
      if (streams.length === 0) console.log("  (none)");
      for (const st of streams) {
        if (!object(st)) continue;
        console.log(`  - ${String(st.name)} -> topic:${String(st.topic)} (${typeof st.builtin === "string" ? `builtin:${st.builtin}` : String(st.exec)})`);
      }
      console.log("\nConnector Thread Bridges (1-to-1 agent handles / local secrets):");
      if (plugins.length === 0) console.log("  (none)");
      for (const pl of plugins) {
        if (!object(pl)) continue;
        const targets = Array.isArray(pl.targets)
          ? pl.targets.filter(object).map((t) => `${String(t.name)}=>${String(t.handle ?? t.sessionId ?? t.threadId ?? "?")}`).join(", ")
          : "";
        console.log(`  - ${String(pl.name)} (${typeof pl.builtin === "string" ? `builtin:${pl.builtin}` : String(pl.exec)}) [${targets}]`);
      }
      return;
    }
    throw new Error(`Usage: hyphae ${action} <${action === "stream" ? "add" : "setup"}|list|guide [name]> [--config <path>]`);
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

    // Agent-assisted onboarding (`--prompt` prints concierge prompt; `--agent <name>` / `--assist` launches interactive agent)
    if (values.prompt === true || values.assist === true || values.agent !== undefined) {
      const { buildAgentOnboardingPrompt, detectAvailableAssistAgents, gatherOnboardingContext, launchAgentAssist } = await import("./assist.ts");
      const ctx = await gatherOnboardingContext(cfgPath, defaultSocketPath());
      const prompt = buildAgentOnboardingPrompt(ctx);
      if (values.prompt === true) {
        console.log(prompt);
        return;
      }
      const available = detectAvailableAssistAgents(ctx.local);
      const chosen = (values.agent || available[0]) as "agy" | "claude" | "codex" | "opencode" | undefined;
      if (!chosen || !["agy", "claude", "codex", "opencode"].includes(chosen)) {
        throw new Error(`No supported CLI agent found (${available.join(", ") || "none"}). Run \`hyp onboard --prompt\` to paste into Claude Desktop or Cursor.`);
      }
      process.exitCode = launchAgentAssist(chosen, prompt);
      return;
    }
    const port = values.port !== undefined ? Number(values.port) : undefined;
    if (port !== undefined && (!Number.isInteger(port) || port < 0 || port > 65535)) {
      throw new Error("Expected integer --port between 0 and 65535");
    }

    // Remote machine onboarding over SSH: create invite on local router and pipe over SSH stdin.
    if (values["remote-ssh"]) {
      const host = values["remote-ssh"];
      const probe = await probeRemoteHost({ host, sources: ["cli"] });
      if (!probe.sshReachable) throw new Error(`Cannot reach ${host} over SSH: ${probe.error ?? "failed"}`);
      const remoteRouter = values.router ?? detectExposedTailscaleUrl(port ?? 8790);
      if (!remoteRouter) {
        throw new Error("No exposed router URL detected. Run `hyp router expose tailscale` first or pass --router https://...");
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
        throw new Error(`Remote onboarding on ${host} failed:\n${sshRes.stderr || sshRes.stdout}\nManual command: hyp onboard --join <<< '${code}'`);
      }
      console.log(sshRes.stdout.trim());
      return;
    }

    // Interactive TTY wizard when no explicit mode flags are given
    const nonInteractive = values.yes === true || values.join === true || values.router !== undefined ||
      values.id !== undefined || !process.stdin.isTTY || !process.stdout.isTTY;
    if (!nonInteractive) {
      const { runInteractiveOnboard } = await import("./onboard-interactive.ts");
      await runInteractiveOnboard({ configPath: values.config ?? defaultConfigPath(), port });
      return;
    }

    let inviteCode: string | undefined;
    if (values.join) {
      if (process.stdin.isTTY) process.stderr.write("Paste invite code (am1_...) then press Ctrl+D:\n");
      inviteCode = await readStdinLine();
      if (!inviteCode) throw new Error("No invite code received on stdin");
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
    console.log(`hyp onboard complete!`);
    console.log(`  Connector ID : ${result.connectorId}`);
    console.log(`  Config       : ${result.configPath}${result.configCreated ? " (written)" : " (existing)"}`);
    console.log(`  Router       : ${result.routerUrl}${result.localRouter ? " (embedded local router)" : result.remoteVerified ? " (remote verified)" : " (remote)"}`);
    console.log(`  Daemon       : ${result.daemonRunning ? `running at ${result.socketPath}` : "stopped (run `hyp daemon`)"}`);
    if (result.configuredHarnesses.length > 0) {
      console.log(`  Harnesses    : ${result.configuredHarnesses.map((h) => h.harness).join(", ")}`);
    } else {
      console.log("  Harnesses    : none detected (run `hyp setup <antigravity|claude|codex>`)");
    }
    if (result.servicePath) {
      console.log(`  Service      : ${result.servicePath}`);
      for (const cmd of result.serviceInstructions ?? []) console.log(`                 ${cmd}`);
    }
    console.log("\nRestart any open Desktop apps/sessions once so they pick up the updated MCP & hooks, then have agents call `hyp_join`.");
    return;
  }

  if (action === "init") {
    const { values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: { id: { type: "string" }, router: { type: "string" }, "token-file": { type: "string" } },
    });
    if (positionals.length > 1 || values.id === undefined || !connectorPattern.test(values.id) || !values.router || !values["token-file"]) {
      throw new Error(usage);
    }
    const path = resolve(positionals[0] ?? defaultConfigPath());
    const config = {
      connectorId: values.id,
      stateDir: "state",
      routers: [{ name: "primary", url: values.router, tokenFile: resolve(values["token-file"]) }],
    };
    mkdirSync(dirname(path), { mode: 0o700, recursive: true });
    writeFileSync(path, JSON.stringify(config, null, 2) + "\n", { mode: 0o600, flag: "wx" });
    console.log(path);
    return;
  }

  if (action === "daemon") {
    const { values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: { socket: { type: "string" } },
    });
    if (positionals.length > 1) throw new Error(usage);
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
        "claude-channel": { type: "boolean" },
        ephemeral: { type: "boolean" },
      },
    });
    const backend = values.backend;
    if (positionals.length > 1 || (backend !== undefined && !isHarness(backend))) throw new Error(usage);
    runMcp(positionals[0] ?? defaultSocketPath(), {
      ...(backend ? { backend } : {}),
      channel: values["claude-channel"] === true,
      threadId: values.thread,
      resume: values.resume === true,
      remote: values.remote,
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
      throw new Error(usage);
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
      throw new Error("Expected non-negative --timeout seconds");
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
        install: { type: "boolean" },
      },
    });
    const target = positionals[0];
    const scope = (values.scope ?? "user") as "user" | "project";
    if (!target || (scope !== "user" && scope !== "project")) throw new Error(usage);

    if (target === "service") {
      const result = setupService({
        install: values.install === true,
        configPath: resolve(values.config ?? defaultConfigPath()),
      });
      if (result.installed) {
        console.log(`Installed service file: ${result.path}`);
        console.log("Next:");
        for (const line of result.instructions) console.log(`  ${line}`);
      } else {
        console.log(`# Target path: ${result.path}\n# Pass --install to write this file.\n`);
        console.log(result.content);
      }
      return;
    }

    const setupOpts = {
      scope,
      projectDir: values.dir,
      socketPath: values.socket,
      configPath: values.config,
      noSidecar: values["no-sidecar"] === true,
      channel: values.channel === true,
      codexRemote: values.remote,
    };
    const targets = target === "all" ? [...ALL_CONFIGURABLE_HARNESSES] : [target];
    for (const item of targets) {
      const result = item === "antigravity"
        ? setupAntigravity(setupOpts)
        : item === "claude"
          ? setupClaude(setupOpts)
          : item === "codex"
            ? setupCodex(setupOpts)
            : item === "cursor"
              ? setupCursor(setupOpts)
              : item === "opencode"
                ? setupOpenCode(setupOpts)
                : item === "gemini"
                  ? setupGemini(setupOpts)
                  : item === "openclaw"
                    ? setupOpenClaw(setupOpts)
                    : null;
      if (!result) throw new Error(usage);
      console.log(`[${result.harness}] Configured:`);
      for (const file of result.files) console.log(`  - ${file}`);
      for (const note of result.notes) console.log(`  * ${note}`);
    }
    return;
  }

  if (action === "status" || action === "sessions") {
    const { values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: {
        socket: { type: "string" },
        json: { type: "boolean" },
        sessions: { type: "boolean" },
        discover: { type: "boolean" },
        "probe-ssh": { type: "boolean" },
        prune: { type: "boolean" },
        "older-than-hours": { type: "string" },
      },
    });
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
      if (!Number.isFinite(hours) || hours < 0) throw new Error("Expected non-negative --older-than-hours");
      const res = await daemonRpc(socketPath, { type: "daemon.prune", maxAgeMs: hours * 3_600_000 });
      if (!res.ok || !res.result) throw new Error(`Daemon not reachable at ${socketPath}`);
      console.log(JSON.stringify(res.result, null, 2));
      return;
    }
    if (action === "sessions" || values.sessions === true || values.json === true) {
      const res = await daemonRpc(socketPath, { type: "daemon.status" });
      if (!res.ok || !res.result) throw new Error(`Daemon not reachable at ${socketPath}`);
      console.log(JSON.stringify(action === "sessions" || values.sessions ? res.result.sessions : res.result, null, 2));
      return;
    }
    const checks = await runDoctor(positionals[0] ?? defaultConfigPath(), socketPath);
    let allOk = true;
    for (const check of checks) {
      const icon = check.ok ? "OK" : "FAIL";
      console.log(`[${icon}] ${check.name}: ${check.detail}`);
      if (!check.ok) {
        allOk = false;
        if (check.fix) console.log(`       fix: ${check.fix}`);
      }
    }
    if (!allOk) process.exitCode = 1;
    return;
  }

  if (action === "prune") {
    const { values } = parseArgs({
      args,
      allowPositionals: false,
      options: { "older-than-hours": { type: "string" }, socket: { type: "string" } },
    });
    const hours = values["older-than-hours"] !== undefined ? Number(values["older-than-hours"]) : 168;
    if (!Number.isFinite(hours) || hours < 0) throw new Error("Expected non-negative --older-than-hours");
    const socketPath = values.socket ?? defaultSocketPath();
    const res = await daemonRpc(socketPath, { type: "daemon.prune", maxAgeMs: hours * 3_600_000 });
    if (!res.ok || !res.result) throw new Error(`Daemon not reachable at ${socketPath}`);
    console.log(JSON.stringify(res.result, null, 2));
    return;
  }

  if (action === "doctor") {
    const { values, positionals } = parseArgs({
      args,
      allowPositionals: true,
      options: { socket: { type: "string" } },
    });
    const checks = await runDoctor(positionals[0] ?? defaultConfigPath(), values.socket ?? defaultSocketPath());
    let allOk = true;
    for (const check of checks) {
      const icon = check.ok ? "OK" : "FAIL";
      console.log(`[${icon}] ${check.name}: ${check.detail}`);
      if (!check.ok) {
        allOk = false;
        if (check.fix) console.log(`       fix: ${check.fix}`);
      }
    }
    if (!allOk) process.exitCode = 1;
    return;
  }

  if (action === undefined || action === "--help" || action === "-h" || action === "help") {
    console.log(args.includes("--all") ? fullUsage : usage);
  } else throw new Error(usage);
}

await main().catch((error: unknown) => {
  console.error(error instanceof Error ? error.message : "hyphae failed");
  process.exitCode = 1;
});
