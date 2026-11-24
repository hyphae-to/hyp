import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { styleText } from "node:util";
import * as p from "@clack/prompts";
import { detectAvailableAssistAgents, buildAgentOnboardingPrompt, gatherOnboardingContext, launchAgentAssist } from "./assist.ts";
import { detectLocalEnvironment, discoverRemoteMachines, onboardRemoteOverSsh, probeRemoteHost, type RemoteProbeResult } from "./discover.ts";
import {
  ALL_GUIDES,
  CONNECTOR_BRIDGE_GUIDES,
  ROUTER_STREAM_GUIDES,
  type PluginOrStreamGuide,
} from "./plugin-catalog.ts";
import { connectorPattern, handlePattern, object } from "./protocol.ts";
import { detectExposedTailscaleUrl, encodeInvite, exposeTailscale } from "./remote.ts";
import { writeSecret } from "./secrets.ts";
import { defaultConnectorId, runOnboard, type AdditionalRouterSpec, type ConfigurableHarness } from "./setup.ts";
import { isTopic } from "./core/router/cloudevent.ts";
import { RouterCore } from "./core/router/core.ts";

export interface InteractiveOnboardOptions {
  readonly configPath: string;
  readonly port?: number;
}

function unwrap<T>(value: T): Exclude<T, symbol> {
  if (p.isCancel(value)) {
    p.cancel("Cancelled.");
    process.exit(0);
  }
  return value as Exclude<T, symbol>;
}

const badge = {
  ok: (text: string) => styleText("green", `● ${text}`),
  dim: (text: string) => styleText("dim", text),
  accent: (text: string) => styleText(["cyan", "bold"], text),
  bold: (text: string) => styleText("bold", text),
  warn: (text: string) => styleText("yellow", text),
  tag: (text: string, color: "bgCyan" | "bgMagenta" | "bgBlue" | "bgGreen" = "bgCyan") =>
    styleText([color, "black", "bold"], ` ${text} `),
};

const HARNESS_META: Array<{
  value: ConfigurableHarness;
  label: string;
  envKey: "antigravity" | "claude" | "codex" | "cursor" | "opencode" | "gemini" | "openclaw";
  detail: string;
}> = [
  { value: "antigravity", label: "Antigravity", envKey: "antigravity", detail: "Desktop / IDE / CLI plugin + hooks + sidecar" },
  { value: "claude", label: "Claude Code & Desktop", envKey: "claude", detail: "CLI & Desktop Code tab MCP + PreToolUse/Stop hooks" },
  { value: "codex", label: "Codex CLI & Desktop", envKey: "codex", detail: "config.toml MCP + rollout verification + hooks" },
  { value: "cursor", label: "Cursor", envKey: "cursor", detail: "mcp.json + beforeMCPExecution / stop followup hooks" },
  { value: "opencode", label: "OpenCode", envKey: "opencode", detail: "opencode.json MCP + TypeScript lifecycle plugin" },
  { value: "gemini", label: "Gemini CLI", envKey: "gemini", detail: "settings.json MCP + BeforeTool / AfterAgent hooks" },
  { value: "openclaw", label: "OpenClaw Orchestrator", envKey: "openclaw", detail: "openclaw.json MCP gateway + fleet orchestrator skill" },
];

export function formatGuideCard(guide: PluginOrStreamGuide): string {
  const lines = [
    `${badge.bold(guide.label)}  ${badge.dim(guide.kind === "router-stream" ? "[Router Data Stream · 1-to-many pub/sub]" : "[Connector Thread Bridge · 1-to-1 handle]")}`,
    badge.dim(guide.summary),
    "",
    badge.accent("Setup instructions:"),
    ...guide.instructions.map((l) => `  ${l}`),
    "",
    badge.accent("How agents use it:"),
    ...guide.agentUsage.map((l) => `  ${styleText("green", l)}`),
  ];
  return lines.join("\n");
}

async function promptSecretsForGuide(guide: PluginOrStreamGuide, configDir: string, prefixName: string): Promise<Record<string, unknown>> {
  const env: Record<string, unknown> = {};
  for (const spec of guide.secrets) {
    const secretName = prefixName === guide.defaultName ? spec.secretName : `${prefixName}-${spec.secretName}`;
    const value = unwrap(
      await p.password({
        message: `${spec.prompt} -> stored in secrets/${secretName}.secret (0600)`,
        validate: (v) => (spec.required && (!v || v.trim().length === 0) ? "This secret is required (or press Ctrl+C to skip)" : undefined),
      }),
    );
    if (value && value.trim().length > 0) {
      writeSecret(secretName, value.trim(), configDir);
      env[spec.envKey] = spec.useFile ? { secretFile: secretName } : { secret: secretName };
      p.log.success(`Saved private secret ${styleText("cyan", secretName)} (mode 0600)`);
    }
  }
  return env;
}

/**
 * Interactive wizard to configure router-level data streams (`github-webhook`, `webhook-stream`,
 * or custom fd-3 data source executables). Stores secrets privately in `~/.config/hyphae/secrets/`.
 */
export async function promptRouterStreams(configDir: string): Promise<Record<string, unknown>[]> {
  const cardLines = ROUTER_STREAM_GUIDES.flatMap((g) => [
    `${badge.accent(g.label)}  ${badge.dim(`(${g.id})`)}`,
    `  ${badge.dim(g.tagline)}`,
    "",
  ]);
  p.note(cardLines.join("\n").trimEnd(), "Router Data Streams (agents subscribe with CloudEvents filters)");

  const chosen = unwrap(
    await p.multiselect({
      message: "Select router data streams to enable (Space to toggle, Enter to continue)",
      required: false,
      options: ROUTER_STREAM_GUIDES.map((g) => ({
        value: g.id,
        label: g.label,
        hint: g.tagline,
      })),
    }),
  );

  const streams: Record<string, unknown>[] = [];
  for (const id of chosen) {
    const guide = ROUTER_STREAM_GUIDES.find((g) => g.id === id)!;
    p.note(formatGuideCard(guide), `${guide.label} — setup guide`);

    const name = unwrap(
      await p.text({
        message: "Stream name",
        initialValue: guide.defaultName,
        validate: (v) => (v && /^[a-z0-9][a-z0-9._-]{0,31}$/.test(v) ? undefined : "Use lowercase letters, digits, '.', '_', '-'"),
      }),
    );
    const topic = unwrap(
      await p.text({
        message: `Router topic agents will subscribe to (hyp_subscribe({ topic: "..." }))`,
        initialValue: guide.defaultTopicOrTarget,
        validate: (v) => (v && isTopic(v) ? undefined : "Use lowercase topic name (e.g. github, ci, linear)"),
      }),
    );

    const env = await promptSecretsForGuide(guide, configDir, name);

    if (id === "github-webhook") {
      const port = unwrap(
        await p.text({
          message: "Local HTTP port for GitHub webhook receiver (/hooks/github)",
          initialValue: "8791",
          validate: (v) => {
            const n = Number(v);
            return Number.isInteger(n) && n > 0 && n <= 65535 ? undefined : "Enter a valid TCP port";
          },
        }),
      );
      env.GITHUB_WEBHOOK_PORT = port;
      streams.push({ name, topic, builtin: "github-webhook", env });
    } else if (id === "webhook-stream") {
      const port = unwrap(
        await p.text({
          message: "Local HTTP port for webhook receiver (/webhook)",
          initialValue: "8792",
          validate: (v) => {
            const n = Number(v);
            return Number.isInteger(n) && n > 0 && n <= 65535 ? undefined : "Enter a valid TCP port";
          },
        }),
      );
      env.WEBHOOK_PORT = port;
      env.WEBHOOK_TARGET = topic;
      env.WEBHOOK_SOURCE = `stream/${name}`;
      streams.push({ name, topic, builtin: "webhook-stream", env });
    } else {
      const execPath = unwrap(
        await p.text({
          message: "Absolute path to custom data source executable (Node/Python/binary speaking fd-3 protocol)",
          placeholder: "/usr/bin/python3",
          validate: (v) => (v && isAbsolute(v.trim()) ? undefined : "Must be an absolute path"),
        }),
      ).trim();
      const scriptArg = unwrap(
        await p.text({
          message: "Optional script path / argument (leave blank if executable is standalone)",
          placeholder: "/path/to/my_source.py",
        }),
      ).trim();
      const extraSecret = unwrap(
        await p.confirm({
          message: "Attach a private secret to this data source's environment?",
          initialValue: false,
        }),
      );
      if (extraSecret) {
        const envKey = unwrap(
          await p.text({
            message: "Environment variable name",
            placeholder: "API_KEY",
            validate: (v) => (v && /^[A-Za-z_][A-Za-z0-9_]*$/.test(v) ? undefined : "Invalid env var name"),
          }),
        );
        const secretName = unwrap(
          await p.text({
            message: "Secret name in ~/.config/hyphae/secrets/",
            initialValue: `${name}-${envKey.toLowerCase().replace(/_/g, "-")}`,
            validate: (v) => (v && /^[a-z0-9][a-z0-9._-]{0,63}$/.test(v) ? undefined : "Invalid secret name"),
          }),
        );
        const secretVal = unwrap(await p.password({ message: `Secret value for ${envKey}` }));
        if (secretVal && secretVal.trim().length > 0) {
          writeSecret(secretName, secretVal.trim(), configDir);
          env[envKey] = { secret: secretName };
          p.log.success(`Saved private secret ${styleText("cyan", secretName)} (mode 0600)`);
        }
      }
      streams.push({
        name,
        topic,
        exec: execPath,
        ...(scriptArg ? { args: [scriptArg] } : {}),
        ...(Object.keys(env).length > 0 ? { env } : {}),
      });
    }
  }
  return streams;
}

/**
 * Interactive wizard to configure connector-level messaging & bridge plugins (`slack`, `telegram`,
 * `webhook`, or custom / existing `t3-mesh` plugins). Stores secrets privately (`0600`).
 */
export async function promptConnectorPlugins(configDir: string): Promise<Record<string, unknown>[]> {
  const cardLines = CONNECTOR_BRIDGE_GUIDES.flatMap((g) => [
    `${badge.accent(g.label)}  ${badge.dim(`(${g.id})`)}`,
    `  ${badge.dim(g.tagline)}`,
    "",
  ]);
  p.note(cardLines.join("\n").trimEnd(), "Connector Thread Bridges (connect threads to 3rd-party messaging tools)");

  const chosen = unwrap(
    await p.multiselect({
      message: "Select messaging / thread bridge plugins to enable (Space to toggle, Enter to continue)",
      required: false,
      options: CONNECTOR_BRIDGE_GUIDES.map((g) => ({
        value: g.id,
        label: g.label,
        hint: g.tagline,
      })),
    }),
  );

  const plugins: Record<string, unknown>[] = [];
  for (const id of chosen) {
    const guide = CONNECTOR_BRIDGE_GUIDES.find((g) => g.id === id)!;
    p.note(formatGuideCard(guide), `${guide.label} — setup guide`);

    const name = unwrap(
      await p.text({
        message: "Plugin name",
        initialValue: guide.defaultName,
        validate: (v) => (v && /^[a-z0-9][a-z0-9._-]{0,31}$/.test(v) ? undefined : "Use lowercase letters, digits, '.', '_', '-'"),
      }),
    );
    const targetHandle = unwrap(
      await p.text({
        message: "Target agent handle (whichever agent runs `hyp_join({ handle })` receives messages)",
        initialValue: guide.defaultTopicOrTarget,
        validate: (v) => (v && handlePattern.test(v) ? undefined : "Use lowercase handle (e.g. pm, assistant, ops)"),
      }),
    );

    const env = await promptSecretsForGuide(guide, configDir, name);

    if (id === "slack") {
      env.SLACK_TARGET = targetHandle;
      const allowedUsers = unwrap(
        await p.text({
          message: "Allowed Slack user IDs (optional allowlist, e.g. U01234567 — recommended)",
          placeholder: "U01234567",
        }),
      ).trim();
      if (allowedUsers) env.SLACK_ALLOWED_USERS = allowedUsers;
      plugins.push({
        name,
        builtin: "slack",
        env,
        targets: [{ name: targetHandle, handle: targetHandle, coalesceSeconds: 3, maxWaitSeconds: 20, wakesPerHour: 120 }],
      });
    } else if (id === "telegram") {
      env.TELEGRAM_TARGET = targetHandle;
      const allowedUsers = unwrap(
        await p.text({
          message: "Allowed Telegram numeric user IDs (optional allowlist from @userinfobot — recommended)",
          placeholder: "123456789",
        }),
      ).trim();
      if (allowedUsers) env.TELEGRAM_ALLOWED_USERS = allowedUsers;
      plugins.push({
        name,
        builtin: "telegram",
        env,
        targets: [{ name: targetHandle, handle: targetHandle, coalesceSeconds: 2, maxWaitSeconds: 10, wakesPerHour: 120 }],
      });
    } else if (id === "webhook") {
      const port = unwrap(
        await p.text({
          message: "Local HTTP port (loopback 127.0.0.1)",
          initialValue: "8795",
          validate: (v) => {
            const n = Number(v);
            return Number.isInteger(n) && n > 0 && n <= 65535 ? undefined : "Enter a valid TCP port";
          },
        }),
      );
      env.WEBHOOK_PORT = port;
      env.WEBHOOK_TARGET = targetHandle;
      plugins.push({
        name,
        builtin: "webhook",
        env,
        targets: [{ name: targetHandle, handle: targetHandle, coalesceSeconds: 2, maxWaitSeconds: 15, wakesPerHour: 120 }],
      });
    } else {
      const execPath = unwrap(
        await p.text({
          message: "Absolute path to plugin executable (e.g. /usr/bin/python3 or /path/to/plugin)",
          placeholder: "/usr/bin/python3",
          validate: (v) => (v && isAbsolute(v.trim()) ? undefined : "Must be an absolute path"),
        }),
      ).trim();
      const scriptArg = unwrap(
        await p.text({
          message: "Optional script path / argument (leave blank if executable is standalone)",
          placeholder: "/path/to/bridge.py",
        }),
      ).trim();
      plugins.push({
        name,
        exec: execPath,
        ...(scriptArg ? { args: [scriptArg] } : {}),
        ...(Object.keys(env).length > 0 ? { env } : {}),
        targets: [{ name: targetHandle, handle: targetHandle, coalesceSeconds: 5, maxWaitSeconds: 30, wakesPerHour: 120 }],
      });
    }
  }
  return plugins;
}

/** Standalone interactive `hyp plugin setup` command. */
export async function runPluginSetupWizard(configPath: string): Promise<void> {
  const absConfig = resolve(configPath);
  const configDir = dirname(absConfig);
  p.intro(`${badge.tag("hyphae")} ${badge.dim("plugin & stream setup")}`);

  if (!existsSync(absConfig)) {
    p.log.error(`No config found at ${absConfig}. Run \`hyp onboard\` first.`);
    process.exitCode = 1;
    return;
  }

  const kind = unwrap(
    await p.select({
      message: "What do you want to configure?",
      options: [
        {
          value: "bridge",
          label: "Connector Thread Bridge (Slack, Telegram, Webhook, custom t3-mesh plugin)",
          hint: "1-to-1 local bridge pinned to an agent handle · secrets stay on this machine",
        },
        {
          value: "stream",
          label: "Router Data Stream (GitHub Events, Signed Webhook, custom data source)",
          hint: "1-to-many topic feed on your router · any agent subscribes with filters",
        },
        {
          value: "guide",
          label: "View setup instructions & agent examples only",
          hint: "Browse all built-in plugins & streams",
        },
      ],
    }),
  );

  if (kind === "guide") {
    const pick = unwrap(
      await p.select({
        message: "Select a plugin or stream guide",
        options: ALL_GUIDES.map((g) => ({ value: g.id, label: g.label, hint: g.tagline })),
      }),
    );
    const guide = ALL_GUIDES.find((g) => g.id === pick)!;
    p.note(formatGuideCard(guide), guide.label);
    p.outro("Run `hyp plugin setup` anytime to configure it interactively.");
    return;
  }

  const rawCfg = JSON.parse(readFileSync(absConfig, "utf8")) as Record<string, unknown>;
  if (kind === "bridge") {
    const added = await promptConnectorPlugins(configDir);
    if (added.length > 0) {
      const existing = Array.isArray(rawCfg.plugins) ? rawCfg.plugins : [];
      const names = new Set(added.map((pl) => String(pl.name ?? "")));
      rawCfg.plugins = [...existing.filter((pl) => !object(pl) || !names.has(String(pl.name ?? ""))), ...added];
      writeFileSync(absConfig, JSON.stringify(rawCfg, null, 2) + "\n", { mode: 0o600 });
      chmodSync(absConfig, 0o600);
      p.log.success(`Updated ${absConfig} with ${added.length} connector plugin(s).`);
    }
  } else {
    if (!object(rawCfg.localRouter)) {
      p.log.warn("This machine does not run a localRouter in connector.json. Router streams run on the router host.");
      p.outro("Run `hyp stream add` on your router host.");
      return;
    }
    const added = await promptRouterStreams(configDir);
    if (added.length > 0) {
      const existing = Array.isArray(rawCfg.localRouter.streams) ? rawCfg.localRouter.streams : [];
      const names = new Set(added.map((st) => String(st.name ?? "")));
      rawCfg.localRouter = {
        ...rawCfg.localRouter,
        streams: [...existing.filter((st) => !object(st) || !names.has(String(st.name ?? ""))), ...added],
      };
      writeFileSync(absConfig, JSON.stringify(rawCfg, null, 2) + "\n", { mode: 0o600 });
      chmodSync(absConfig, 0o600);
      p.log.success(`Updated ${absConfig} with ${added.length} router data stream(s).`);
    }
  }

  p.outro(`Restart ${styleText("cyan", "hyp daemon")} to activate the new configuration, then verify with ${styleText("cyan", "hyp secret check")}.`);
}

/**
 * Full interactive onboarding wizard powered by `@clack/prompts`:
 * - Environment detection card (6 harnesses + Herdr Core + T3 Code + Tailscale)
 * - Capability cards + multi-select for router roles (Private Router, Public Router, Join Shared Router)
 * - Checkbox multi-select for agent harnesses, router data streams, and connector thread bridges
 * - Private `0600` secrets store + step-by-step setup guides
 * - Tailscale Service / Serve private exposure + parallel SSH remote host onboarding
 */
export async function runInteractiveOnboard(options: InteractiveOnboardOptions): Promise<void> {
  const absConfig = resolve(options.configPath);
  const configDir = dirname(absConfig);

  p.intro(`${badge.tag("hyphae")} ${badge.dim("cross-harness agent mesh onboarding")}`);

  const scanSpinner = p.spinner();
  scanSpinner.start("Scanning local harnesses, Herdr Core, T3 Code, and Tailscale...");
  const env = detectLocalEnvironment();
  scanSpinner.stop("Environment detected");

  const summaryLines = [
    ...HARNESS_META.map((h) =>
      env[h.envKey]
        ? `${badge.ok(h.label.padEnd(22))} ${badge.dim(h.detail)}`
        : `${badge.dim(`○ ${h.label.padEnd(22)} not installed`)}`,
    ),
    "",
    env.herdr.installed
      ? `${badge.ok("Herdr Core".padEnd(22))} ${badge.dim(
          `${env.herdr.inTerminal ? `terminal ${env.herdr.terminalId}` : "installed"}${
            env.herdr.machines.length > 0 ? ` · remotes: ${env.herdr.machines.map((m) => m.name).join(", ")}` : ""
          }`,
        )}`
      : `${badge.dim("○ Herdr Core             not installed")}`,
    env.t3.meshConfigured
      ? `${badge.ok("T3 Code / t3-mesh".padEnd(22))} ${badge.dim(`${env.t3.connectorId ?? "?"} -> ${env.t3.routerUrl ?? "?"}`)}`
      : env.t3.installed
        ? `${badge.ok("T3 Code".padEnd(22))} ${badge.dim("installed (no ~/.t3-mesh/config.json)")}`
        : `${badge.dim("○ T3 Code                not installed")}`,
    env.tailscale
      ? `${badge.ok("Tailscale".padEnd(22))} ${badge.dim("available for private tailnet router exposure")}`
      : `${badge.dim("○ Tailscale              not installed")}`,
  ];
  p.note(summaryLines.join("\n"), "Detected environment");

  // Optional: let an AI agent act as interactive onboarding concierge!
  const assistAgents = detectAvailableAssistAgents(env);
  if (assistAgents.length > 0) {
    const setupStyle = unwrap(
      await p.select({
        message: "How would you like to set up hyphae?",
        options: [
          { value: "tui", label: "Interactive terminal wizard (Recommended · fast selectors & cards)", hint: "Zero typing · spacebar multi-select" },
          { value: "agent", label: `Guided by an AI agent (${assistAgents.join(" / ")})`, hint: "Conversational concierge that inspects & configures everything with you" },
        ],
        initialValue: "tui",
      }),
    );
    if (setupStyle === "agent") {
      const pickedAgent = assistAgents.length === 1
        ? assistAgents[0]
        : unwrap(
            await p.select({
              message: "Which AI agent should guide your setup?",
              options: assistAgents.map((a) => ({ value: a, label: a })),
            }),
          );
      const ctxSpin = p.spinner();
      ctxSpin.start("Preparing secret-free machine snapshot for your onboarding agent...");
      const ctx = await gatherOnboardingContext(absConfig, join(configDir, "state", "connector.sock"));
      const prompt = buildAgentOnboardingPrompt(ctx);
      ctxSpin.stop(`Launching ${pickedAgent} onboarding concierge...`);
      p.outro(`Handing off to ${styleText("cyan", pickedAgent)}.`);
      process.exitCode = launchAgentAssist(pickedAgent, prompt);
      return;
    }
  }

  // 1. Router Roles — rich capability cards + select ONE OR MORE!
  const routerCards = [
    `${badge.tag("PRIVATE ROUTER", "bgGreen")}  ${badge.bold("Local & Tailscale Private Mesh")}`,
    `  • Connect all your own agent sessions across harnesses & machines`,
    `  • Subscribe to ${styleText("cyan", "GitHub events")} & ${styleText("cyan", "custom data streams")} with CloudEvents filters`,
    `  • Bridge threads to ${styleText("cyan", "3rd-party messaging tools")} via plugins (Slack, Telegram, webhooks)`,
    "",
    `${badge.tag("PUBLIC ROUTER", "bgMagenta")}  ${badge.bold("Internet-Reachable Webhook & Event Hub")}`,
    `  • Receive live webhooks from external services (GitHub, Linear, Sentry, CI) & external peers`,
    `  • Loopback router behind hardened HTTPS (Caddy / nginx / Funnel) with HMAC + per-topic ACLs`,
    "",
    `${badge.tag("JOIN SHARED ROUTER", "bgBlue")}  ${badge.bold("Connect to an Existing Team or T3 Mesh Router")}`,
    `  • Join via one-shot invite (${styleText("cyan", "am1_...")}) or HTTPS URL + token file${env.t3.routerUrl ? ` (detected: ${env.t3.routerUrl})` : ""}`,
    `  • Works solo as your primary router, OR alongside your private router as a secondary event router`,
  ].join("\n");
  p.note(routerCards, "Router capabilities — select one or more");

  const hasExisting = existsSync(absConfig);
  type RouterRole = "private" | "public" | "shared" | "keep";
  const roles = unwrap(
    await p.multiselect({
      message: "Select one or more router setups (Space to toggle, Enter to confirm)",
      required: true,
      initialValues: [hasExisting ? "keep" : "private"] as RouterRole[],
      options: [
        ...(hasExisting
          ? [{ value: "keep" as const, label: "Keep existing connector.json", hint: absConfig }]
          : []),
        {
          value: "private" as const,
          label: "Setup Private Router",
          hint: "Connect all your sessions · GitHub/custom streams · Slack/Telegram plugins",
        },
        {
          value: "public" as const,
          label: "Setup Public Router",
          hint: "HTTPS webhook & event hub for internet senders & remote collaborators",
        },
        {
          value: "shared" as const,
          label: "Join a Shared Router",
          hint: env.t3.routerUrl ? `Join via invite or ${env.t3.routerUrl}` : "Join via am1_... invite or HTTPS URL + token",
        },
      ],
    }),
  );

  const wantsLocal = roles.includes("private") || roles.includes("public");
  const wantsPublic = roles.includes("public");
  const wantsShared = roles.includes("shared");
  const keepExistingOnly = roles.includes("keep") && !wantsLocal && !wantsShared;

  let connectorId: string | undefined;
  let inviteCode: string | undefined;
  let routerUrl: string | undefined;
  let tokenFile: string | undefined;
  let replace = false;
  const additionalRouters: AdditionalRouterSpec[] = [];

  if (wantsLocal) {
    replace = hasExisting && !roles.includes("keep");
    connectorId = unwrap(
      await p.text({
        message: "Connector ID for this machine",
        placeholder: defaultConnectorId(),
        initialValue: defaultConnectorId(),
        validate: (v) => (v && connectorPattern.test(v) ? undefined : "Expected format like user@hostname"),
      }),
    );
  }

  if (wantsShared) {
    const asSecondary = wantsLocal || roles.includes("keep");
    const sharedName = asSecondary
      ? unwrap(
          await p.text({
            message: "Name for this shared router (agents pass `router: \"<name>\"` in hyp_subscribe)",
            initialValue: env.t3.routerUrl ? "t3" : "shared",
            validate: (v) => (v && /^[a-z][a-z0-9-]{0,31}$/.test(v) && v !== "primary" ? undefined : "Lowercase name (not 'primary')"),
          }),
        )
      : "primary";

    const joinMethod = unwrap(
      await p.select({
        message: `How do you want to authenticate with shared router '${sharedName}'?`,
        options: [
          { value: "invite", label: "One-shot invite bundle (am1_...)", hint: "Live HTTPS + bearer auth verification" },
          {
            value: "manual",
            label: "HTTPS router URL + existing token file",
            hint: env.t3.routerUrl ? `Pre-fills ${env.t3.routerUrl}` : "WireGuard / Tailscale / Caddy HTTPS",
          },
        ],
      }),
    );

    if (joinMethod === "invite") {
      const code = unwrap(
        await p.password({
          message: "Paste invite bundle (am1_...)",
          validate: (v) => (v && v.trim().startsWith("am1_") ? undefined : "Invite bundle must start with am1_"),
        }),
      ).trim();
      if (asSecondary) {
        additionalRouters.push({ name: sharedName, inviteCode: code });
      } else {
        replace = true;
        inviteCode = code;
      }
    } else {
      if (!asSecondary && !connectorId) {
        replace = true;
        connectorId = unwrap(
          await p.text({
            message: "Connector ID for this machine",
            placeholder: defaultConnectorId(),
            initialValue: defaultConnectorId(),
            validate: (v) => (v && connectorPattern.test(v) ? undefined : "Expected format like user@hostname"),
          }),
        );
      }
      const url = unwrap(
        await p.text({
          message: `HTTPS URL for router '${sharedName}'`,
          placeholder: env.t3.routerUrl ?? "https://hyphae.tailnet.ts.net",
          initialValue: env.t3.routerUrl ?? "",
          validate: (v) => (v && /^https?:\/\/.+/.test(v) ? undefined : "Enter a valid https:// router URL"),
        }),
      );
      const tokFile = unwrap(
        await p.text({
          message: `Path to connector token file (0600) for '${sharedName}'`,
          placeholder: "~/.config/hyphae/tokens/shared.token",
          validate: (v) => (v && v.trim().length > 0 ? undefined : "Token file path is required"),
        }),
      );
      if (asSecondary) {
        additionalRouters.push({ name: sharedName, url, tokenFile: tokFile });
      } else {
        replace = true;
        routerUrl = url;
        tokenFile = tokFile;
      }
    }
  }

  // 2. Harnesses multi-select (all 6 harnesses)
  const detectedHarnesses = HARNESS_META.filter((h) => env[h.envKey]).map((h) => h.value);
  const selectedHarnesses = unwrap(
    await p.multiselect({
      message: "Select agent harnesses to configure (Space to toggle, Enter to confirm)",
      required: false,
      initialValues: detectedHarnesses,
      options: HARNESS_META.map((h) => ({
        value: h.value,
        label: h.label,
        hint: env[h.envKey] ? `detected · ${h.detail}` : `not detected · ${h.detail}`,
      })),
    }),
  );

  if (env.herdr.installed) {
    p.log.info(
      `Herdr Core detected: agents inside Herdr can also attach via ${styleText("cyan", "hyp mcp --backend herdr")} for native ${styleText("cyan", "hc interrupt")} + ${styleText("cyan", "hc send")}.`,
    );
  }

  // 3. Router Data Streams (when running a local private or public router)
  const localRouterStreams = wantsLocal || (!keepExistingOnly && hasExisting)
    ? await promptRouterStreams(configDir)
    : [];

  // 4. Connector Thread Bridge Plugins (Slack, Telegram, Webhook, custom)
  const plugins = await promptConnectorPlugins(configDir);

  // 5. OS Background Service
  const installService = unwrap(
    await p.confirm({
      message: process.platform === "darwin"
        ? "Install macOS LaunchAgent so hyphae starts automatically at login?"
        : "Install systemd --user service so hyphae starts automatically at login?",
      initialValue: false,
    }),
  );

  // 6. Apply setup
  const applySpinner = p.spinner();
  applySpinner.start("Configuring hyphae, streams, plugins, harnesses, and daemon...");
  let result;
  try {
    result = await runOnboard({
      configPath: absConfig,
      connectorId,
      routerUrl,
      tokenFile,
      inviteCode,
      ...(additionalRouters.length > 0 ? { additionalRouters } : {}),
      ...(localRouterStreams.length > 0 ? { localRouterStreams } : {}),
      ...(wantsLocal ? { localRouterExposure: wantsPublic ? "public" : "private" } : {}),
      replace,
      port: options.port,
      harnesses: selectedHarnesses,
      ...(plugins.length > 0 ? { plugins } : {}),
      startDaemon: true,
      installService,
    });
    applySpinner.stop("Local setup complete");
  } catch (error) {
    applySpinner.stop("Local setup failed");
    p.log.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
    return;
  }

  const appliedLines = [
    `Connector ID : ${badge.accent(result.connectorId)}`,
    `Config       : ${result.configPath}${result.configCreated ? " (written)" : " (updated)"}`,
    `Primary      : ${result.routerUrl}${result.localRouter ? ` (${wantsPublic ? "public-ready" : "private"} embedded router)` : result.remoteVerified ? " (remote verified)" : ""}`,
    ...(additionalRouters.length > 0 ? [`Shared       : ${additionalRouters.map((r) => r.name).join(", ")}`] : []),
    `Daemon       : ${result.daemonRunning ? badge.ok(`running at ${result.socketPath}`) : badge.warn("not running")}`,
    `Harnesses    : ${result.configuredHarnesses.length > 0 ? result.configuredHarnesses.map((h) => h.harness).join(", ") : "none selected"}`,
    ...(localRouterStreams.length > 0 ? [`Data Streams : ${localRouterStreams.map((s) => `${String(s.name)} -> topic:${String(s.topic)}`).join(", ")}`] : []),
    ...(plugins.length > 0 ? [`Bridges      : ${plugins.map((pl) => String(pl.name)).join(", ")}`] : []),
    ...(result.servicePath ? [`Service      : ${result.servicePath}`] : []),
  ];
  p.note(appliedLines.join("\n"), "Mesh configuration summary");

  // 7. Public router HTTPS hardening instructions (when Public Router selected)
  if (wantsPublic) {
    const port = options.port ?? 8790;
    const ghStream = localRouterStreams.find((s) => s.builtin === "github-webhook");
    const ghPort = ghStream && object(ghStream.env) && typeof ghStream.env.GITHUB_WEBHOOK_PORT === "string"
      ? ghStream.env.GITHUB_WEBHOOK_PORT
      : "8791";
    p.note(
      [
        "Your router binds loopback (127.0.0.1) by design — put TLS + rate limits in front of it:",
        "",
        badge.accent("Option A — Caddy (automatic Let's Encrypt HTTPS):"),
        "  mesh.yourdomain.com {",
        `    handle /hooks/github { reverse_proxy 127.0.0.1:${ghPort} }`,
        `    handle { reverse_proxy 127.0.0.1:${port} }`,
        "  }",
        "",
        badge.accent("Option B — Expose ONLY GitHub webhook receiver publicly via Tailscale Funnel:"),
        `  tailscale funnel --bg --https=443 --set-path=/hooks/github http://127.0.0.1:${ghPort}`,
        "  (Keep the main router private on your tailnet with `hyp router expose tailscale`!)",
        "",
        badge.accent("Invite external machines:"),
        "  hyp router invite user@remote --router https://mesh.yourdomain.com",
      ].join("\n"),
      "Public router HTTPS & webhook exposure",
    );
  }

  // 8. Private Tailscale exposure selector (when local router + Tailscale available)
  let exposedUrl = result.localRouter ? detectExposedTailscaleUrl(options.port ?? 8790) : null;
  if (result.localRouter && env.tailscale) {
    if (exposedUrl) {
      p.log.success(`Private Tailscale exposure already active at ${styleText("cyan", exposedUrl)}`);
    } else {
      const tsMode = unwrap(
        await p.select({
          message: "Expose your local router privately on your Tailscale tailnet?",
          options: [
            { value: "service", label: "Tailscale Service (svc:hyphae)", hint: "Recommended · stable https://hyphae.<tailnet>.ts.net" },
            { value: "serve", label: "Node-scoped Tailscale Serve", hint: "Zero tailnet admin setup · https://<node>.<tailnet>.ts.net:8790" },
            { value: "skip", label: "Keep loopback-only (127.0.0.1)", hint: "Run `hyp router expose tailscale` later" },
          ],
          initialValue: "skip",
        }),
      );

      if (tsMode === "service" || tsMode === "serve") {
        let serviceName: string | undefined;
        if (tsMode === "service") {
          serviceName = unwrap(
            await p.text({
              message: "Tailscale Service name",
              placeholder: "hyphae",
              initialValue: "hyphae",
              validate: (v) => (v && /^[a-z0-9][a-z0-9-]{0,62}$/.test(v) ? undefined : "Use lowercase letters, digits, and hyphens"),
            }),
          );
        }
        const tsSpinner = p.spinner();
        tsSpinner.start("Configuring private Tailscale Serve...");
        try {
          const exposed = exposeTailscale({
            localPort: options.port ?? 8790,
            ...(serviceName ? { service: serviceName } : {}),
          });
          exposedUrl = exposed.url;
          tsSpinner.stop(`Exposed privately at ${styleText("cyan", exposed.url)} (${exposed.mode})`);
        } catch (error) {
          tsSpinner.stop("Tailscale exposure skipped");
          p.log.warn(error instanceof Error ? error.message : String(error));
        }
      }
    }
  }

  // 9. Discover remote machines from Herdr / SSH config / Tailscale & onboard via checkbox selector
  const discovered = discoverRemoteMachines(undefined, env);
  if (discovered.length > 0) {
    const shouldProbe = unwrap(
      await p.confirm({
        message: `Found ${discovered.length} remote machine(s) (${discovered.map((m) => m.host).join(", ")}). Probe SSH reachability?`,
        initialValue: true,
      }),
    );

    if (shouldProbe) {
      const probeSpinner = p.spinner();
      probeSpinner.start(`Probing ${discovered.length} remote machine(s) over SSH...`);
      const probes: RemoteProbeResult[] = await Promise.all(discovered.map((m) => probeRemoteHost(m)));
      probeSpinner.stop("SSH probe complete");

      const probeLines = probes.map((pr) => {
        if (pr.sshReachable) {
          const extra = [
            pr.nodeVersion || "node?",
            pr.hasHyphae ? "hyphae:yes" : "hyphae:no",
            pr.hasT3Mesh ? "t3-mesh:yes" : "",
            pr.harnesses.length > 0 ? `[${pr.harnesses.join(",")}]` : "",
          ].filter(Boolean).join(" · ");
          return `${badge.ok(pr.host.padEnd(20))} ${styleText("cyan", `${pr.user ?? "?"}@${pr.hostname ?? pr.host}`)} ${badge.dim(extra)}`;
        }
        return `${badge.warn(`✕ ${pr.host.padEnd(20)}`)} ${badge.dim(pr.error ?? "unreachable")}`;
      });
      p.note(probeLines.join("\n"), "Remote machines");

      const reachable = probes.filter((pr) => pr.sshReachable);
      if (reachable.length > 0 && result.localRouter && exposedUrl) {
        const toOnboard = unwrap(
          await p.multiselect({
            message: "Select remote machines to invite & onboard over SSH (Space to toggle)",
            required: false,
            options: reachable.map((m) => ({
              value: m.host,
              label: `${m.host} (${m.user ?? "?"}@${m.hostname ?? m.host})`,
              hint: `${m.hasHyphae ? "auto-onboard ready" : "generates invite"} · ${m.harnesses.join(", ") || "no harnesses"}`,
            })),
          }),
        );

        const dbPath = join(configDir, "router", "router.sqlite");
        for (const hostName of toOnboard) {
          const host = reachable.find((m) => m.host === hostName)!;
          const matched = discovered.find((d) => d.host === hostName);
          const sshTarget = matched?.sshTarget ?? hostName;
          const defaultRemoteId = `${host.user ?? "user"}@${host.hostname ?? hostName}`;
          const remoteId = unwrap(
            await p.text({
              message: `Connector ID for ${hostName}`,
              initialValue: defaultRemoteId,
              validate: (v) => (v && connectorPattern.test(v) ? undefined : "Expected format like user@host"),
            }),
          );

          const core = new RouterCore({ dbPath });
          let remoteToken: string;
          try {
            remoteToken = core.addConnector(remoteId);
          } finally {
            core.close();
          }
          const code = encodeInvite({ connectorId: remoteId, router: exposedUrl, token: remoteToken });

          if (host.hasHyphae) {
            const sshSpin = p.spinner();
            sshSpin.start(`Onboarding ${hostName} (${sshTarget}) as ${remoteId}...`);
            const sshRes = await onboardRemoteOverSsh({ host: sshTarget, inviteCode: code, installService: true });
            if (sshRes.ok) {
              sshSpin.stop(`Onboarded ${hostName} as ${remoteId}`);
            } else {
              sshSpin.stop(`Remote onboard failed on ${hostName}`);
              p.log.warn(sshRes.stderr.trim() || sshRes.stdout.trim());
              p.note(`ssh ${sshTarget} 'hyp onboard --join' <<< '${code}'`, `Manual invite for ${hostName}`);
            }
          } else {
            p.note(
              [
                `hyphae is not installed on ${hostName} yet.`,
                `After installing Node 24 + hyphae on ${sshTarget}, run:`,
                "",
                `  hyp onboard --join --install-service <<< '${code}'`,
              ].join("\n"),
              `Invite created for ${remoteId}`,
            );
          }
        }
      } else if (reachable.length > 0 && !exposedUrl) {
        p.log.info(`Tip: run ${styleText("cyan", "hyp router expose tailscale --service hyphae")} to invite those remote machines over your tailnet.`);
      }
    }
  }

  p.outro(
    `${badge.ok("Ready!")} Run ${styleText("cyan", "hyp doctor")}, ${styleText("cyan", "hyp plugin setup")}, or ${styleText("cyan", "hyp secret list")} anytime.`,
  );
}
