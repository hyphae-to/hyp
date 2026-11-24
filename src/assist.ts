import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { detectLocalEnvironment, discoverRemoteMachines } from "./discover.ts";
import { ALL_GUIDES } from "./plugin-catalog.ts";
import { object } from "./protocol.ts";
import { collectSecretRefs, listSecrets } from "./secrets.ts";
import { resolveRuntimePaths, runDoctor } from "./setup.ts";

export type AssistAgent = "agy" | "claude" | "codex" | "opencode";

export interface OnboardingContext {
  readonly cli: string;
  readonly configPath: string;
  readonly hasConfig: boolean;
  readonly local: ReturnType<typeof detectLocalEnvironment>;
  readonly remoteMachines: ReturnType<typeof discoverRemoteMachines>;
  readonly doctor: Awaited<ReturnType<typeof runDoctor>>;
  readonly secrets: ReturnType<typeof listSecrets>;
  readonly secretRefs: ReturnType<typeof collectSecretRefs>;
  readonly availablePluginsAndStreams: Array<{ id: string; kind: string; label: string; tagline: string }>;
}

/**
 * Collects a strictly secret-free snapshot of the current machine so an AI coding agent
 * can guide the user through onboarding safely and accurately.
 */
export async function gatherOnboardingContext(configPath: string, socketPath: string): Promise<OnboardingContext> {
  const absConfig = resolve(configPath);
  const configDir = dirname(absConfig);
  const runtime = resolveRuntimePaths();
  const local = detectLocalEnvironment();
  const remoteMachines = discoverRemoteMachines(undefined, local);
  const doctor = await runDoctor(absConfig, socketPath);
  const secrets = listSecrets(configDir);
  let secretRefs: ReturnType<typeof collectSecretRefs> = [];
  if (existsSync(absConfig)) {
    try {
      const raw = JSON.parse(readFileSync(absConfig, "utf8")) as unknown;
      if (object(raw)) secretRefs = collectSecretRefs(raw);
    } catch {}
  }
  return {
    cli: `${runtime.nodeBin} ${runtime.cliScript}`,
    configPath: absConfig,
    hasConfig: existsSync(absConfig),
    local,
    remoteMachines,
    doctor,
    secrets,
    secretRefs,
    availablePluginsAndStreams: ALL_GUIDES.map((g) => ({
      id: g.id,
      kind: g.kind,
      label: g.label,
      tagline: g.tagline,
    })),
  };
}

/**
 * Generates a self-contained, security-aware onboarding concierge prompt that can be passed
 * to `claude`, `codex`, `agy`, `opencode`, or pasted into Claude Desktop / Cursor.
 */
export function buildAgentOnboardingPrompt(ctx: OnboardingContext): string {
  return [
    "You are the interactive onboarding concierge for `hyphae` (a cross-harness agent mesh & event router).",
    "Your goal is to make setup effortless for the user by interviewing them briefly, explaining options clearly, and running the right CLI commands for them.",
    "",
    "## Hard Security Rules (NEVER break these)",
    "- NEVER read, print, log, or ask the user to paste raw secrets/API tokens/webhook secrets into chat or CLI arguments.",
    "- Whenever a plugin, stream, or router needs a secret, run `hyp secret set <name> --web` so the user enters it in a one-shot local browser password box (stored in macOS Keychain / Linux Secret Service with private file fallback, completely out-of-band from the LLM context), OR let them run `hyp secret set <name>` in their own terminal.",
    "- Reference secrets in `connector.json` ONLY via `{ \"secret\": \"<name>\" }` or `{ \"secretFile\": \"<name>\" }`.",
    "- NEVER expose the main router with `tailscale funnel`; use private `hyp share tailscale --service hyphae` for private routers, and scope any public webhook exposure strictly to `/hooks/github` or a hardened reverse proxy.",
    "- Always enforce allowlists (`SLACK_ALLOWED_USERS`, `TELEGRAM_ALLOWED_USERS`, `WHATSAPP_ALLOWED_NUMBERS`) before enabling external chat bridges.",
    "- When configuring `github-webhook` (via Repo/Org Webhook OR GitHub App), ALWAYS ask which repositories (`GITHUB_REPOS`) or orgs (`GITHUB_ORGS`) the webhook/App is installed on and write them into the stream config so `hyp_topics` and `hyp_subscribe` can immediately detect unreachable repos instead of silently waiting forever.",
    "- Prefer `--json` when invoking `hyp` CLI commands (`hyp --help --json`, `hyp status --json`, `hyp connect guide <id> --json`, `hyp secret check --json`) for clean machine-readable output.",
    "",
    "## Detected Machine Snapshot (secret-free)",
    "```json",
    JSON.stringify(ctx, null, 2),
    "```",
    "",
    "## Step-by-Step Concierge Flow",
    "1. Summarize what you detected on this machine in 3–5 crisp bullets (harnesses, Herdr Core, T3 Code, Tailscale, remote machines, and any failing `status` checks).",
    "2. Ask the user which Node role(s) they want (they can pick ONE OR MORE):",
    "   - **Private Node** (local + optional Tailscale tailnet): connect all your sessions across harnesses/machines, subscribe to GitHub/Prometheus events & custom streams with filters, and bridge threads to Slack/Telegram/WhatsApp.",
    "   - **Public-Webhook / Team Node**: hardened HTTPS webhook/event hub for internet senders (GitHub, Linear, Sentry, CI) & teammates.",
    "   - **Join a Team Node**: connect to an existing shared Team Node (as primary or secondary event Node).",
    "3. Ask which harnesses to enable (`antigravity`, `claude`, `codex`, `cursor`, `opencode`, `gemini`, `openclaw`, `t3`, plus Herdr `--backend herdr`), which Node Streams (`github-webhook`, `prometheus-webhook`, `webhook-stream`, custom fd-3 source), and which Connector Bridges (`slack`, `telegram`, `whatsapp`, `webhook`, custom) they want.",
    "4. For any selected stream or bridge, run `hyp connect guide <id> --json` to retrieve the exact step-by-step setup instructions and walk the user through them (e.g. GitHub App vs Repo Webhook `/hooks/github` + `GITHUB_REPOS`/`GITHUB_ORGS`, then verifying `ping` delivery with `hyp_topics`).",
    "5. Execute the setup commands using `" + ctx.cli + "` (`onboard --yes`, `setup <harness>`, `share tailscale`, `status --discover --probe-ssh`, `connect guide <id>`, `secret set <name> --web`, `secret check`, `status`).",
    "6. If remote SSH machines are discovered (Herdr / `~/.ssh/config` / Tailscale), offer to probe them with `hyp status --discover --probe-ssh` and walk through inviting reachable ones with `hyp onboard --remote-ssh <host>`.",
    "7. Finish by running `" + ctx.cli + " status --json` and giving the user a 2-line test they can run right now (`hyp_join`, `hyp_topics`, `hyp_channel_join('#incidents')`, `hyp_peers`).",
    "",
    "Start by greeting the user concisely with the detected snapshot and asking your first question.",
  ].join("\n");
}

export function detectAvailableAssistAgents(env: ReturnType<typeof detectLocalEnvironment>): AssistAgent[] {
  const list: AssistAgent[] = [];
  if (env.claude) list.push("claude");
  if (env.codex) list.push("codex");
  if (env.antigravity) list.push("agy");
  if (env.opencode) list.push("opencode");
  return list;
}

/**
 * Spawns an interactive CLI coding agent pre-seeded with the onboarding concierge prompt.
 */
export function launchAgentAssist(agent: AssistAgent, prompt: string): number {
  const invocations: Record<AssistAgent, { bin: string; args: string[] }> = {
    claude: { bin: "claude", args: [prompt] },
    codex: { bin: "codex", args: [prompt] },
    agy: { bin: "agy", args: ["-i", prompt] },
    opencode: { bin: "opencode", args: ["--prompt", prompt] },
  };
  const { bin, args } = invocations[agent];
  const res = spawnSync(bin, args, { stdio: "inherit" });
  if (res.error) {
    throw new Error(`Failed to launch '${bin}': ${res.error.message}`);
  }
  return res.status ?? 0;
}
