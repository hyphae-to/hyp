import { styleText } from "node:util";
import {
  S_BAR,
  S_BAR_END,
  S_BAR_H,
  S_BAR_START,
  S_INFO,
  S_RADIO_ACTIVE,
  S_STEP_ERROR,
  S_STEP_SUBMIT,
  S_WARN,
} from "@clack/prompts";

export type OutputMode = "json" | "plain" | "pretty";
export type CheckStatus = "ok" | "warn" | "fail";
export type CommandGroup = "core" | "runtime" | "advanced";

export const EXIT_OK = 0;
export const EXIT_ERROR = 1;
export const EXIT_USAGE = 2;

export interface OutputModeEnv {
  readonly env?: NodeJS.ProcessEnv;
  readonly isTTY?: boolean;
}

export interface GlobalOutputFlags {
  readonly mode: OutputMode;
  readonly explicitMode: OutputMode | undefined;
  readonly args: string[];
}

export interface CliField {
  readonly label: string;
  readonly value: string;
}

export interface CliCheck {
  readonly name: string;
  readonly status: CheckStatus;
  readonly detail: string;
  readonly fix?: string;
}

export interface CliTableColumn {
  readonly key: string;
  readonly header: string;
  readonly align?: "left" | "right";
}

export type CliTableCell = string | number | boolean | null | undefined;
export type CliTableRow = Readonly<Record<string, CliTableCell>>;

export interface CliTable {
  readonly title?: string;
  readonly columns: readonly CliTableColumn[];
  readonly rows: readonly CliTableRow[];
  readonly emptyText?: string;
}

export interface CliSection {
  readonly title: string;
  readonly lines?: readonly string[];
  readonly fields?: readonly CliField[];
  readonly table?: CliTable;
}

export interface CliResult<T = unknown> {
  readonly ok: boolean;
  readonly command: string;
  readonly title: string;
  readonly summary?: string;
  readonly fields?: readonly CliField[];
  readonly checks?: readonly CliCheck[];
  readonly tables?: readonly CliTable[];
  readonly sections?: readonly CliSection[];
  readonly warnings?: readonly string[];
  readonly next?: readonly string[];
  readonly data: T;
}

export interface CliError {
  readonly code: string;
  readonly message: string;
  readonly fix?: string;
  readonly usage?: string;
  readonly details?: unknown;
}

export interface JsonEnvelope<T = unknown> {
  readonly ok: boolean;
  readonly command: string;
  readonly summary?: string;
  readonly data?: T;
  readonly warnings?: readonly string[];
  readonly next?: readonly string[];
  readonly error?: CliError;
}

export interface CliFlagSpec {
  readonly flag: string;
  readonly description: string;
}

export interface CliCommandSpec {
  readonly name: string;
  readonly aliases?: readonly string[];
  readonly group: CommandGroup;
  readonly summary: string;
  readonly usage: string;
  readonly flags?: readonly CliFlagSpec[];
  readonly examples?: readonly string[];
  readonly rawStream?: boolean;
}

export class CliUsageError extends Error {
  readonly code = "USAGE_ERROR";
  readonly usage?: string;
  readonly fix?: string;

  constructor(message: string, options?: { usage?: string; fix?: string }) {
    super(message);
    this.name = "CliUsageError";
    this.usage = options?.usage;
    this.fix = options?.fix;
  }
}

export class CliOperationalError extends Error {
  readonly code: string;
  readonly fix?: string;
  readonly details?: unknown;

  constructor(message: string, options?: { code?: string; fix?: string; details?: unknown }) {
    super(message);
    this.name = "CliOperationalError";
    this.code = options?.code ?? "ERROR";
    this.fix = options?.fix;
    this.details = options?.details;
  }
}

export const CLI_VOCABULARY: Readonly<Record<string, string>> = {
  Node: "Hyphae router hosting topics, peer routing, and event streams",
  Connector: "Local daemon bridging harnesses, chat bridges, and nodes",
  Stream: "1-to-many node topic feed with CloudEvents subscriptions",
  Bridge: "Connector chat plugin binding external threads to local agent handles",
  Session: "Connected harness conversation registered with the local connector",
  Rule: "Connector or session mute rule filtering noisy peers, channels, topics, or bridges",
  Secret: "Private credential stored in your OS Keychain / Secret Service (or local private file fallback)",
};

export const CLI_GLOBAL_FLAGS: readonly CliFlagSpec[] = [
  { flag: "--json", description: "Emit structured JSON envelope { ok, command, summary, data, warnings, next, error }" },
  { flag: "--plain", description: "Emit clean agent-first plain text with zero ANSI codes (default when non-TTY)" },
  { flag: "--pretty", description: "Force rich styled TTY layout even when stdout is piped" },
  { flag: "-h, --help", description: "Show command catalog (--all includes advanced & plumbing commands; --json emits full schema)" },
  { flag: "-v, --version", description: "Print Hyphae version (supports --json)" },
];

export const CLI_EXIT_CODES: Readonly<Record<string, string>> = {
  "0": "Success",
  "1": "Operational or verification failure (daemon unreachable, failed status/secret check, runtime error)",
  "2": "Usage or invalid argument error",
};

export const CLI_COMMANDS: readonly CliCommandSpec[] = [
  {
    name: "onboard",
    aliases: ["up"],
    group: "core",
    summary: "Set up local or remote Nodes, harnesses, Streams, Bridges & SSH hosts",
    usage: "hyp onboard [--yes] [--assist | --prompt | --join | --remote-ssh <host>]",
    flags: [
      { flag: "-y, --yes", description: "Run non-interactively using detected defaults" },
      { flag: "--assist", description: "Launch an installed coding agent with onboarding context" },
      { flag: "--prompt", description: "Print the onboarding concierge prompt verbatim" },
      { flag: "--join", description: "Read a remote Node invite code from stdin and join" },
      { flag: "--remote-ssh <host>", description: "Provision and onboard a remote machine over SSH" },
      { flag: "--id <user@host>", description: "Override Connector ID" },
      { flag: "--router <url>", description: "Connect to an existing remote Node URL (requires --token-file)" },
      { flag: "--port <port>", description: "Port for embedded local Node (default: 8790)" },
      { flag: "--install-service", description: "Install OS auto-start service for the Connector daemon" },
    ],
    examples: [
      "hyp onboard --yes",
      "hyp onboard --join <<< 'am1_...'",
      "hyp onboard --remote-ssh devbox",
    ],
  },
  {
    name: "status",
    aliases: ["doctor"],
    group: "core",
    summary: "Health check (Node 24, Connector daemon, Nodes, Secrets, harnesses & live Sessions)",
    usage: "hyp status [config] [--sessions | --discover | --probe-ssh | --prune]",
    flags: [
      { flag: "--socket <path>", description: "Override local Connector socket path" },
      { flag: "--sessions", description: "Output active Sessions as a raw JSON array" },
      { flag: "--discover", description: "Inspect local harnesses and SSH/Tailscale peers as JSON" },
      { flag: "--probe-ssh", description: "Probe discovered remote hosts over SSH and output JSON" },
      { flag: "--prune", description: "Prune stale offline Sessions (use with --older-than-hours)" },
    ],
    examples: [
      "hyp status",
      "hyp status --json",
      "hyp status --sessions",
    ],
  },
  {
    name: "connect",
    aliases: ["plugin", "stream"],
    group: "core",
    summary: "Configure or inspect Node Streams (GitHub, Prometheus, webhooks) & Connector Bridges (Slack, Telegram)",
    usage: "hyp connect [add | list | guide [id]] [--config <path>]",
    flags: [
      { flag: "--config <path>", description: "Path to connector.json" },
    ],
    examples: [
      "hyp connect list",
      "hyp connect guide",
      "hyp connect guide github-webhook --json",
    ],
  },
  {
    name: "secret",
    group: "core",
    summary: "Manage Secrets privately via OS Keychain / Secret Service (hidden TTY prompt, --web browser form, or stdin)",
    usage: "hyp secret <set <name> [--web] | list | rm <name> | check [config]>",
    flags: [
      { flag: "--web", description: "Capture secret via ephemeral localhost browser form (recommended for agents)" },
      { flag: "--no-open", description: "Print localhost capture URL without opening a browser" },
      { flag: "--config-dir <dir>", description: "Override Hyphae config directory containing secrets/" },
    ],
    examples: [
      "hyp secret set github-webhook-secret --web",
      "hyp secret list --json",
      "hyp secret check",
    ],
  },
  {
    name: "share",
    group: "core",
    summary: "Expose your local Node on Tailscale Services and generate remote Connector invite codes",
    usage: "hyp share <tailscale [--service hyphae] | invite <user@host> | stop>",
    flags: [
      { flag: "--service <name>", description: "Tailscale Service name (e.g. hyphae)" },
      { flag: "--port <port>", description: "Local Node port (default: 8790)" },
      { flag: "--https <port>", description: "External Tailscale HTTPS port" },
      { flag: "--router <url>", description: "Explicit exposed Node URL for invite" },
      { flag: "--dry-run", description: "Preview tailscale serve command without applying" },
    ],
    examples: [
      "hyp share tailscale --service hyphae",
      "hyp share invite alice@workstation",
      "hyp share stop",
    ],
  },
  {
    name: "setup",
    group: "core",
    summary: "Wire (or re-wire) MCP, hooks, rules, skills, or OS auto-start service for harnesses",
    usage: "hyp setup <antigravity|claude|codex|cursor|opencode|gemini|openclaw|all|service> [--scope user|project]",
    flags: [
      { flag: "--scope <user|project>", description: "Target user-wide or project-local harness config (default: user)" },
      { flag: "--dir <path>", description: "Project directory when --scope project is set" },
      { flag: "--install", description: "Write the OS service unit file when target is 'service'" },
      { flag: "--channel", description: "Enable Claude channel mode when setting up claude" },
      { flag: "--no-sidecar", description: "Skip Antigravity daemon sidecar generation" },
    ],
    examples: [
      "hyp setup claude",
      "hyp setup all --json",
      "hyp setup service --install",
    ],
  },
  {
    name: "skill",
    group: "core",
    summary: "Install, print, or locate the standalone Hyphae agent skill (SKILL.md)",
    usage: "hyp skill [install [antigravity|claude|codex|cursor|openclaw|project|all] | print | path]",
    flags: [
      { flag: "--dir <path>", description: "Project directory when installing for target 'project'" },
    ],
    examples: [
      "hyp skill install all",
      "hyp skill path",
      "hyp skill print",
    ],
  },
  {
    name: "mute",
    aliases: ["unmute", "mutes"],
    group: "core",
    summary: "Manage Connector mute Rules for peers, #channels, topic:<name>, or plugin:<name>",
    usage: "hyp mute <target> | hyp unmute <target> | hyp mutes",
    flags: [
      { flag: "--socket <path>", description: "Override local Connector socket path" },
      { flag: "--list", description: "List active mute Rules" },
    ],
    examples: [
      "hyp mute '#noisy'",
      "hyp mutes --json",
      "hyp unmute '#noisy'",
    ],
  },
  {
    name: "daemon",
    group: "runtime",
    summary: "Run the local Connector daemon (and embedded Node if configured) in the foreground",
    usage: "hyp daemon [config] [--socket <path>]",
    flags: [
      { flag: "--socket <path>", description: "Override Connector Unix socket path" },
    ],
  },
  {
    name: "wait",
    aliases: ["watch"],
    group: "runtime",
    summary: "Wait for incoming Connector messages (--stream / watch streams NDJSON events)",
    usage: "hyp wait [--stream] [--session <id> | --handle <handle>] [--timeout <sec>]",
    flags: [
      { flag: "--stream", description: "Keep streaming NDJSON notifications instead of exiting on first message" },
      { flag: "--session <id>", description: "Target Session ID" },
      { flag: "--handle <handle>", description: "Target enrolled handle" },
      { flag: "--timeout <sec>", description: "Maximum wait time in seconds" },
    ],
    rawStream: true,
  },
  {
    name: "init",
    group: "advanced",
    summary: "Create a minimal connector.json pointing at a remote Node and print its path",
    usage: "hyp init [config] --id <user@host> --router <origin> --token-file <file>",
  },
  {
    name: "mcp",
    group: "advanced",
    summary: "Run the stdio MCP server bound to the local Connector socket",
    usage: "hyp mcp [socket] [--claude-channel] [--backend <harness>] [--thread <uuid>] [--resume] [--remote <addr>] [--ephemeral]",
    rawStream: true,
  },
  {
    name: "hook",
    group: "advanced",
    summary: "Execute a harness lifecycle hook reading stdin JSON and writing hook output",
    usage: "hyp hook <antigravity|claude|codex|cursor|opencode|gemini|openclaw> <pre-tool-use|post-tool-use|pre-invocation|stop>",
    rawStream: true,
  },
  {
    name: "node",
    aliases: ["router"],
    group: "advanced",
    summary: "Administer standalone Nodes, Connectors, publishers, and GitHub webhook receivers",
    usage: "hyp node <expose|unexpose|invite|serve|add-connector|revoke-connector|add-publisher|revoke-publisher|github-receiver>",
  },
  {
    name: "sessions",
    group: "advanced",
    summary: "Output live Connector Sessions as a raw JSON array (alias for `hyp status --sessions`)",
    usage: "hyp sessions [--socket <path>]",
  },
  {
    name: "discover",
    group: "advanced",
    summary: "Inspect local environment and remote SSH/Tailscale hosts as JSON (alias for `hyp status --discover`)",
    usage: "hyp discover [--probe-ssh]",
  },
  {
    name: "prune",
    group: "advanced",
    summary: "Remove stale offline Sessions older than --older-than-hours (alias for `hyp status --prune`)",
    usage: "hyp prune [--older-than-hours <hours>] [--socket <path>]",
  },
];

// eslint-disable-next-line no-control-regex
const ANSI_PATTERN = /\x1b\[[0-9;]*m/g;

export function stripAnsi(text: string): string {
  return text.replace(ANSI_PATTERN, "");
}

function visibleLength(text: string): number {
  return stripAnsi(text).length;
}

function paint(format: Parameters<typeof styleText>[0], text: string): string {
  return styleText(format, text, { validateStream: false });
}

function parseExplicitOutputMode(args: readonly string[]): OutputMode | undefined {
  let explicit: OutputMode | undefined;
  for (const arg of args) {
    if (arg === "--") break;
    if (arg === "--json") explicit = "json";
    else if (arg === "--plain") explicit = "plain";
    else if (arg === "--pretty") explicit = "pretty";
  }
  return explicit;
}

export function resolveOutputMode(
  args: readonly string[] = [],
  options: OutputModeEnv = {},
): OutputMode {
  const explicit = parseExplicitOutputMode(args);
  if (explicit) return explicit;

  const env = options.env ?? process.env;
  const envMode = env.HYPHAE_OUTPUT?.trim().toLowerCase();
  if (envMode === "json" || envMode === "plain" || envMode === "pretty") {
    return envMode;
  }

  if (env.NO_COLOR !== undefined && env.NO_COLOR !== "") {
    return "plain";
  }

  const isTTY = options.isTTY ?? Boolean(process.stdout.isTTY);
  return isTTY ? "pretty" : "plain";
}

export function extractGlobalOutputFlags(
  argv: readonly string[],
  options: OutputModeEnv = {},
): GlobalOutputFlags {
  const args: string[] = [];
  let afterDoubleDash = false;
  let explicitMode: OutputMode | undefined;

  for (const token of argv) {
    if (!afterDoubleDash && token === "--") {
      afterDoubleDash = true;
      args.push(token);
      continue;
    }
    if (!afterDoubleDash && (token === "--json" || token === "--plain" || token === "--pretty")) {
      explicitMode = token.slice(2) as OutputMode;
      continue;
    }
    args.push(token);
  }

  const mode = resolveOutputMode(argv, options);
  return { mode, explicitMode, args };
}

function statusPill(status: CheckStatus, mode: OutputMode): string {
  const label = status === "ok" ? "OK" : status === "warn" ? "WARN" : "FAIL";
  if (mode === "plain") {
    return `[${label}]`.padEnd(6);
  }
  if (status === "ok") return paint(["bgGreen", "black", "bold"], " OK ");
  if (status === "warn") return paint(["bgYellow", "black", "bold"], " WARN ");
  return paint(["bgRed", "white", "bold"], " FAIL ");
}

function inlineCheckTag(status: CheckStatus, mode: OutputMode): string {
  if (mode === "plain") {
    if (status === "ok") return "[OK]  ";
    if (status === "warn") return "[WARN]";
    return "[FAIL]";
  }
  if (status === "ok") return paint(["green", "bold"], `${S_STEP_SUBMIT} OK  `);
  if (status === "warn") return paint(["yellow", "bold"], `${S_WARN} WARN`);
  return paint(["red", "bold"], `${S_STEP_ERROR} FAIL`);
}

function formatTableCell(raw: CliTableCell, mode: OutputMode): string {
  const text = raw === null || raw === undefined ? "" : stripAnsi(String(raw));
  if (mode !== "pretty") return text;
  if (text === "OK" || text === "yes" || text === "running") {
    return paint(["green", "bold"], text);
  }
  if (text === "WARN") {
    return paint(["yellow", "bold"], text);
  }
  if (text === "FAIL" || text === "BAD_MODE" || text === "stopped") {
    return paint(["red", "bold"], text);
  }
  return text;
}

export function renderTable(
  columns: readonly CliTableColumn[],
  rows: readonly CliTableRow[],
  mode: OutputMode,
  options: { emptyText?: string; indent?: string } = {},
): string {
  const indent = options.indent ?? (mode === "pretty" ? `${paint("dim", S_BAR)}  ` : "  ");
  if (mode === "json") {
    return JSON.stringify(rows, null, 2);
  }
  if (rows.length === 0) {
    const empty = options.emptyText ?? "(none)";
    return `${indent}${mode === "pretty" ? paint("dim", empty) : empty}`;
  }

  const formattedRows = rows.map((row) =>
    columns.map((col) => formatTableCell(row[col.key], mode)),
  );
  const widths = columns.map((col, idx) => {
    const headerWidth = col.header.length;
    const cellWidth = formattedRows.reduce((max, r) => Math.max(max, visibleLength(r[idx] ?? "")), 0);
    return Math.max(headerWidth, cellWidth);
  });

  const padCell = (value: string, width: number, align: "left" | "right" = "left"): string => {
    const gap = Math.max(0, width - visibleLength(value));
    return align === "right" ? `${" ".repeat(gap)}${value}` : `${value}${" ".repeat(gap)}`;
  };

  const lastIdx = columns.length - 1;
  const lines: string[] = [];
  const headerLine = columns
    .map((col, idx) => {
      const label = col.header.toUpperCase();
      const padded = idx === lastIdx && col.align !== "right"
        ? label
        : padCell(label, widths[idx]!, col.align);
      return mode === "pretty" ? paint(["dim", "bold"], padded) : padded;
    })
    .join("  ");
  lines.push(`${indent}${headerLine}`);

  if (mode === "pretty") {
    const rule = widths.map((w) => S_BAR_H.repeat(w)).join("  ");
    lines.push(`${indent}${paint("dim", rule)}`);
  }

  for (const row of formattedRows) {
    const line = columns
      .map((col, idx) => {
        const cell = row[idx] ?? "";
        return idx === lastIdx && col.align !== "right"
          ? cell
          : padCell(cell, widths[idx]!, col.align);
      })
      .join("  ");
    lines.push(`${indent}${line}`);
  }

  return lines.join("\n");
}

export function renderChecks(
  checks: readonly CliCheck[],
  mode: OutputMode,
  options: { indent?: string } = {},
): string {
  if (mode === "json") {
    return JSON.stringify(checks, null, 2);
  }
  const indent = options.indent ?? (mode === "pretty" ? `${paint("dim", S_BAR)}  ` : "  ");
  if (checks.length === 0) {
    return `${indent}${mode === "pretty" ? paint("dim", "(no checks)") : "(no checks)"}`;
  }

  const nameWidth = checks.reduce((max, c) => Math.max(max, c.name.length), 0);
  const lines: string[] = [];

  for (const check of checks) {
    const detail = stripAnsi(check.detail);
    const paddedName = check.name.padEnd(nameWidth);
    if (mode === "pretty") {
      const tag = inlineCheckTag(check.status, "pretty");
      const nameStyled = paint(["cyan", "bold"], paddedName);
      const detailStyled = check.status === "fail" ? paint("red", detail) : detail;
      lines.push(`${indent}${tag}  ${nameStyled}  ${detailStyled}`);
      if (check.fix) {
        lines.push(`${indent}        ${paint("dim", "↳ fix:")} ${paint("yellow", stripAnsi(check.fix))}`);
      }
    } else {
      const tag = inlineCheckTag(check.status, "plain");
      lines.push(`${indent}${tag} ${paddedName}  ${detail}`);
      if (check.fix) {
        lines.push(`${indent}       fix: ${stripAnsi(check.fix)}`);
      }
    }
  }

  return lines.join("\n");
}

function renderFields(fields: readonly CliField[], mode: OutputMode, indent: string): string[] {
  if (fields.length === 0) return [];
  const labelWidth = fields.reduce((max, f) => Math.max(max, f.label.length), 0);
  const lines: string[] = [];
  for (const field of fields) {
    const cleanVal = stripAnsi(field.value);
    if (mode === "pretty") {
      lines.push(`${indent}${paint("dim", field.label.padEnd(labelWidth))}  ${cleanVal}`);
    } else {
      const key = field.label.toLowerCase().replace(/\s+/g, "_");
      lines.push(`${indent}${key}: ${cleanVal}`);
    }
  }
  return lines;
}

export function renderResult<T>(result: CliResult<T>, mode: OutputMode): string {
  if (mode === "json") {
    const envelope: JsonEnvelope<T> = {
      ok: result.ok,
      command: result.command,
      ...(result.summary ? { summary: stripAnsi(result.summary) } : {}),
      data: result.data,
      ...(result.warnings && result.warnings.length > 0 ? { warnings: result.warnings.map(stripAnsi) } : {}),
      ...(result.next && result.next.length > 0 ? { next: result.next.map(stripAnsi) } : {}),
    };
    return JSON.stringify(envelope, null, 2);
  }

  if (mode === "plain") {
    const lines: string[] = [
      `COMMAND: ${result.command}`,
      `STATUS: ${result.ok ? "ok" : "error"}`,
    ];
    if (result.summary) {
      lines.push(`SUMMARY: ${stripAnsi(result.summary)}`);
    }
    if (result.fields && result.fields.length > 0) {
      lines.push("");
      lines.push(...renderFields(result.fields, "plain", ""));
    }
    if (result.checks && result.checks.length > 0) {
      lines.push("");
      lines.push("CHECKS:");
      lines.push(renderChecks(result.checks, "plain", { indent: "  " }));
    }
    if (result.tables) {
      for (const table of result.tables) {
        lines.push("");
        if (table.title) lines.push(`${table.title.toUpperCase()}:`);
        lines.push(renderTable(table.columns, table.rows, "plain", { emptyText: table.emptyText, indent: "  " }));
      }
    }
    if (result.sections) {
      for (const section of result.sections) {
        lines.push("");
        lines.push(`${section.title.toUpperCase()}:`);
        if (section.fields && section.fields.length > 0) {
          lines.push(...renderFields(section.fields, "plain", "  "));
        }
        if (section.lines && section.lines.length > 0) {
          for (const l of section.lines) lines.push(`  ${stripAnsi(l)}`);
        }
        if (section.table) {
          lines.push(renderTable(section.table.columns, section.table.rows, "plain", {
            emptyText: section.table.emptyText,
            indent: "  ",
          }));
        }
      }
    }
    if (result.warnings && result.warnings.length > 0) {
      lines.push("");
      lines.push("WARNINGS:");
      for (const w of result.warnings) lines.push(`  - ${stripAnsi(w)}`);
    }
    if (result.next && result.next.length > 0) {
      lines.push("");
      lines.push("NEXT:");
      for (const n of result.next) lines.push(`  ${stripAnsi(n)}`);
    }
    return lines.join("\n");
  }

  // Pretty TTY mode
  const bar = paint("dim", S_BAR);
  const rail = `${bar}  `;
  const pill = statusPill(result.ok ? "ok" : "fail", "pretty");
  const lines: string[] = [
    `${paint("dim", S_BAR_START)} ${pill} ${paint("bold", stripAnsi(result.title))}  ${paint("dim", `hyp ${result.command}`)}`,
  ];

  if (result.summary) {
    lines.push(`${rail}${paint("dim", stripAnsi(result.summary))}`);
  }

  if (result.fields && result.fields.length > 0) {
    lines.push(bar);
    lines.push(...renderFields(result.fields, "pretty", rail));
  }

  if (result.checks && result.checks.length > 0) {
    lines.push(bar);
    lines.push(`${rail}${paint(["cyan", "bold"], "Checks")}`);
    lines.push(renderChecks(result.checks, "pretty", { indent: rail }));
  }

  if (result.tables) {
    for (const table of result.tables) {
      lines.push(bar);
      if (table.title) lines.push(`${rail}${paint(["cyan", "bold"], stripAnsi(table.title))}`);
      lines.push(renderTable(table.columns, table.rows, "pretty", { emptyText: table.emptyText, indent: rail }));
    }
  }

  if (result.sections) {
    for (const section of result.sections) {
      lines.push(bar);
      lines.push(`${rail}${paint(["cyan", "bold"], stripAnsi(section.title))}`);
      if (section.fields && section.fields.length > 0) {
        lines.push(...renderFields(section.fields, "pretty", rail));
      }
      if (section.lines && section.lines.length > 0) {
        for (const l of section.lines) lines.push(`${rail}${stripAnsi(l)}`);
      }
      if (section.table) {
        lines.push(renderTable(section.table.columns, section.table.rows, "pretty", {
          emptyText: section.table.emptyText,
          indent: rail,
        }));
      }
    }
  }

  if (result.warnings && result.warnings.length > 0) {
    lines.push(bar);
    lines.push(`${rail}${paint(["yellow", "bold"], `${S_WARN} Warnings`)}`);
    for (const w of result.warnings) {
      lines.push(`${rail}${paint("yellow", `• ${stripAnsi(w)}`)}`);
    }
  }

  if (result.next && result.next.length > 0) {
    lines.push(bar);
    lines.push(`${rail}${paint(["dim", "bold"], "Next")}`);
    for (const n of result.next) {
      lines.push(`${rail}${paint("cyan", `→ ${stripAnsi(n)}`)}`);
    }
  }

  lines.push(paint("dim", S_BAR_END));
  return lines.join("\n");
}

export function renderError(command: string, error: CliError, mode: OutputMode): string {
  const cleanError: CliError = {
    code: error.code,
    message: stripAnsi(error.message),
    ...(error.usage ? { usage: stripAnsi(error.usage) } : {}),
    ...(error.fix ? { fix: stripAnsi(error.fix) } : {}),
    ...(error.details !== undefined ? { details: error.details } : {}),
  };

  if (mode === "json") {
    const envelope: JsonEnvelope = {
      ok: false,
      command,
      error: cleanError,
    };
    return JSON.stringify(envelope, null, 2);
  }

  if (mode === "plain") {
    const lines = [`ERROR [${cleanError.code}] (${command}): ${cleanError.message}`];
    if (cleanError.usage) lines.push(`USAGE: ${cleanError.usage}`);
    if (cleanError.fix) lines.push(`FIX: ${cleanError.fix}`);
    return lines.join("\n");
  }

  const bar = paint("dim", S_BAR);
  const rail = `${bar}  `;
  const lines = [
    `${paint("dim", S_BAR_START)} ${statusPill("fail", "pretty")} ${paint(["red", "bold"], cleanError.code)}  ${paint("dim", `hyp ${command}`)}`,
    `${rail}${paint("red", cleanError.message)}`,
  ];
  if (cleanError.usage) {
    lines.push(`${rail}${paint("dim", "Usage:")} ${cleanError.usage}`);
  }
  if (cleanError.fix) {
    lines.push(`${rail}${paint("dim", "Fix:  ")} ${paint("cyan", cleanError.fix)}`);
  }
  lines.push(paint("dim", S_BAR_END));
  return lines.join("\n");
}

export function renderHelp(all: boolean, mode: OutputMode, version = "0.0.0"): string {
  if (mode === "json") {
    const envelope: JsonEnvelope = {
      ok: true,
      command: "help",
      summary: "Hyphae (hyp) — cross-harness agent mesh & event node",
      data: {
        name: "hyphae",
        cli: "hyp",
        version,
        all,
        vocabulary: CLI_VOCABULARY,
        outputModes: {
          defaultNonTTY: "plain",
          defaultTTY: "pretty",
          flags: ["--json", "--plain", "--pretty"],
          env: ["HYPHAE_OUTPUT=json|plain|pretty", "NO_COLOR"],
        },
        globalFlags: CLI_GLOBAL_FLAGS,
        exitCodes: CLI_EXIT_CODES,
        commands: CLI_COMMANDS,
      },
    };
    return JSON.stringify(envelope, null, 2);
  }

  const visible = all ? CLI_COMMANDS : CLI_COMMANDS.filter((c) => c.group !== "advanced");
  const byGroup = (group: CommandGroup) => visible.filter((c) => c.group === group);
  const core = byGroup("core");
  const runtime = byGroup("runtime");
  const advanced = byGroup("advanced");

  if (mode === "plain") {
    const lines: string[] = [
      `HYPHAE (hyp) v${version} — cross-harness agent mesh & event node`,
      "",
      "USAGE:",
      "  hyp <command> [args] [--json | --plain | --pretty]",
    ];

    const appendGroup = (title: string, items: readonly CliCommandSpec[]) => {
      if (items.length === 0) return;
      lines.push("", `${title}:`);
      for (const cmd of items) {
        const aliasSuffix = cmd.aliases && cmd.aliases.length > 0 ? ` (aliases: ${cmd.aliases.join(", ")})` : "";
        lines.push(`  ${cmd.usage}`);
        lines.push(`      ${cmd.summary}${aliasSuffix}`);
      }
    };

    appendGroup("CORE COMMANDS", core);
    appendGroup("RUNTIME COMMANDS", runtime);
    appendGroup("ADVANCED & PLUMBING COMMANDS", advanced);

    lines.push("", "GLOBAL FLAGS:");
    const flagWidth = CLI_GLOBAL_FLAGS.reduce((m, f) => Math.max(m, f.flag.length), 0);
    for (const f of CLI_GLOBAL_FLAGS) {
      lines.push(`  ${f.flag.padEnd(flagWidth)}  ${f.description}`);
    }

    lines.push("", "EXIT CODES:");
    for (const [code, desc] of Object.entries(CLI_EXIT_CODES)) {
      lines.push(`  ${code}  ${desc}`);
    }

    lines.push("", "NEXT:");
    if (!all) {
      lines.push("  hyp --help --all   # include advanced & plumbing commands (node, mcp, hook, init)");
    }
    lines.push("  hyp --help --json  # machine-readable command catalog for agents");
    return lines.join("\n");
  }

  // Pretty TTY mode
  const bar = paint("dim", S_BAR);
  const rail = `${bar}  `;
  const lines: string[] = [
    `${paint("dim", S_BAR_START)} ${paint(["bgCyan", "black", "bold"], " HYP ")} ${paint("bold", "Hyphae")} ${paint("dim", `v${version}`)} ${paint("dim", "— cross-harness agent mesh & event node")}`,
    `${rail}${paint("dim", "Usage:")} ${paint("cyan", "hyp <command> [args]")} ${paint("dim", "[--json | --plain | --pretty]")}`,
  ];

  const appendPrettyGroup = (title: string, items: readonly CliCommandSpec[]) => {
    if (items.length === 0) return;
    lines.push(bar);
    lines.push(`${rail}${paint(["cyan", "bold"], `${S_RADIO_ACTIVE} ${title}`)}`);
    for (const cmd of items) {
      const aliasSuffix = cmd.aliases && cmd.aliases.length > 0
        ? ` ${paint("dim", `(${cmd.aliases.join(", ")})`)}`
        : "";
      lines.push(`${rail}${paint("bold", cmd.usage)}${aliasSuffix}`);
      lines.push(`${rail}  ${paint("dim", cmd.summary)}`);
    }
  };

  appendPrettyGroup("Core Commands", core);
  appendPrettyGroup("Runtime", runtime);
  appendPrettyGroup("Advanced & Plumbing", advanced);

  lines.push(bar);
  lines.push(`${rail}${paint(["cyan", "bold"], `${S_INFO} Global Flags`)}`);
  const flagWidth = CLI_GLOBAL_FLAGS.reduce((m, f) => Math.max(m, f.flag.length), 0);
  for (const f of CLI_GLOBAL_FLAGS) {
    lines.push(`${rail}${paint("green", f.flag.padEnd(flagWidth))}  ${paint("dim", f.description)}`);
  }

  lines.push(bar);
  lines.push(`${rail}${paint(["dim", "bold"], "Exit Codes")}  ${paint("dim", "0=ok  1=operational/check failure  2=usage error")}`);
  if (!all) {
    lines.push(`${rail}${paint("dim", "Tip:")} Run ${paint("cyan", "hyp --help --all")} for advanced commands or ${paint("cyan", "hyp --help --json")} for agent schema.`);
  } else {
    lines.push(`${rail}${paint("dim", "Tip:")} Run ${paint("cyan", "hyp --help --json")} for machine-readable agent schema.`);
  }
  lines.push(paint("dim", S_BAR_END));
  return lines.join("\n");
}

export function classifyCliError(error: unknown): { cliError: CliError; exitCode: number } {
  if (error instanceof CliUsageError) {
    return {
      exitCode: EXIT_USAGE,
      cliError: {
        code: error.code,
        message: error.message,
        ...(error.usage ? { usage: error.usage } : {}),
        ...(error.fix ? { fix: error.fix } : {}),
      },
    };
  }

  if (error instanceof CliOperationalError) {
    return {
      exitCode: EXIT_ERROR,
      cliError: {
        code: error.code,
        message: error.message,
        ...(error.fix ? { fix: error.fix } : {}),
        ...(error.details !== undefined ? { details: error.details } : {}),
      },
    };
  }

  if (error instanceof Error) {
    const codeProp = (error as { code?: unknown }).code;
    if (typeof codeProp === "string" && codeProp.startsWith("ERR_PARSE_ARGS_")) {
      return {
        exitCode: EXIT_USAGE,
        cliError: {
          code: "USAGE_ERROR",
          message: error.message,
          fix: "Run `hyp --help` to inspect valid flags and arguments",
        },
      };
    }
    if (error.name === "RouterUsageError" || error.constructor?.name === "RouterUsageError") {
      return {
        exitCode: EXIT_USAGE,
        cliError: {
          code: "USAGE_ERROR",
          message: error.message,
          fix: "Run `hyp node --help` for valid node subcommands",
        },
      };
    }
    return {
      exitCode: EXIT_ERROR,
      cliError: {
        code: "ERROR",
        message: error.message,
      },
    };
  }

  return {
    exitCode: EXIT_ERROR,
    cliError: {
      code: "ERROR",
      message: typeof error === "string" ? error : "hyphae failed",
    },
  };
}

export function emitResult<T>(result: CliResult<T>, mode: OutputMode): void {
  process.stdout.write(`${renderResult(result, mode)}\n`);
}

export function emitError(command: string, error: CliError, mode: OutputMode): void {
  const rendered = `${renderError(command, error, mode)}\n`;
  if (mode === "json") {
    process.stdout.write(rendered);
  } else {
    process.stderr.write(rendered);
  }
}
