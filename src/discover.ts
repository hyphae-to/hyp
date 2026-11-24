import { execFile, execFileSync, spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { object } from "./protocol.ts";

export interface HerdrDetection {
  readonly installed: boolean;
  readonly inTerminal: boolean;
  readonly terminalId?: string;
  readonly machines: Array<{ name: string; state: string; target?: string }>;
}

export interface T3Detection {
  readonly installed: boolean;
  readonly homeDir?: string;
  readonly meshConfigured: boolean;
  readonly connectorId?: string;
  readonly routerUrl?: string;
  readonly plugins: string[];
}

export interface LocalEnvironment {
  readonly antigravity: boolean;
  readonly claude: boolean;
  readonly codex: boolean;
  readonly cursor: boolean;
  readonly opencode: boolean;
  readonly gemini: boolean;
  readonly openclaw: boolean;
  readonly herdr: HerdrDetection;
  readonly t3: T3Detection;
  readonly tailscale: boolean;
}

export interface DiscoveredMachine {
  readonly host: string;
  readonly sshTarget?: string;
  readonly sources: string[];
  readonly herdrState?: string;
  readonly tailscaleDns?: string;
}

export interface RemoteProbeResult {
  readonly host: string;
  readonly sources: string[];
  readonly sshReachable: boolean;
  readonly herdrConnected: boolean;
  readonly user?: string;
  readonly hostname?: string;
  readonly nodeVersion?: string;
  readonly hasHyphae?: boolean;
  readonly hasT3Mesh?: boolean;
  readonly harnesses: string[];
  readonly error?: string;
}

function hasBin(name: string): boolean {
  try {
    execFileSync("which", [name], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

export function detectLocalEnvironment(home = homedir(), env: NodeJS.ProcessEnv = process.env): LocalEnvironment {
  const antigravity = existsSync(join(home, ".gemini", "antigravity-cli")) || existsSync(join(home, ".gemini", "config")) || hasBin("agy");
  const claude = existsSync(join(home, ".claude")) || existsSync(join(home, ".claude.json")) || hasBin("claude");
  const codex = existsSync(join(home, ".codex")) || hasBin("codex");
  const cursor = existsSync(join(home, ".cursor")) || hasBin("cursor");
  const opencode = existsSync(join(home, ".config", "opencode")) || hasBin("opencode");
  const gemini = existsSync(join(home, ".gemini", "settings.json")) || hasBin("gemini");
  const openclaw = existsSync(join(home, ".openclaw")) || hasBin("openclaw");
  const tailscale = hasBin("tailscale");

  // Herdr Core detection
  const hcInstalled = hasBin("hc");
  const machines: Array<{ name: string; state: string; target?: string }> = [];
  if (hcInstalled) {
    try {
      const raw = execFileSync("hc", ["machine", "ls", "--json"], { encoding: "utf8", timeout: 3_000, stdio: ["ignore", "pipe", "ignore"] });
      const parsed: unknown = JSON.parse(raw);
      if (object(parsed) && Array.isArray(parsed.machines)) {
        for (const m of parsed.machines) {
          if (object(m) && typeof m.name === "string") {
            machines.push({
              name: m.name,
              state: typeof m.state === "string" ? m.state : "unknown",
              ...(typeof m.target === "string" && m.target.length > 0 ? { target: m.target } : {}),
            });
          }
        }
      }
    } catch {
      try {
        const raw = execFileSync("hc", ["ls", "--json"], { encoding: "utf8", timeout: 3_000, stdio: ["ignore", "pipe", "ignore"] });
        const parsed: unknown = JSON.parse(raw);
        if (object(parsed) && Array.isArray(parsed.machines)) {
          for (const m of parsed.machines) {
            if (object(m) && typeof m.name === "string") {
              machines.push({ name: m.name, state: typeof m.state === "string" ? m.state : "unknown" });
            }
          }
        }
      } catch {}
    }
  }

  // T3 Code mesh detection (never reads tokens/secrets)
  const t3Home = join(home, ".t3");
  const t3Installed = existsSync(t3Home) || hasBin("t3");
  const t3MeshCfgPath = join(home, ".t3-mesh", "config.json");
  let t3ConnectorId: string | undefined;
  let t3RouterUrl: string | undefined;
  let t3Plugins: string[] = [];
  const t3MeshConfigured = existsSync(t3MeshCfgPath);
  if (t3MeshConfigured) {
    try {
      const raw: unknown = JSON.parse(readFileSync(t3MeshCfgPath, "utf8"));
      if (object(raw)) {
        if (typeof raw.connectorId === "string") t3ConnectorId = raw.connectorId;
        if (object(raw.router) && typeof raw.router.url === "string") t3RouterUrl = raw.router.url;
        if (Array.isArray(raw.plugins)) {
          t3Plugins = raw.plugins
            .filter((p): p is Record<string, unknown> => object(p) && typeof p.name === "string")
            .map((p) => String(p.name));
        }
      }
    } catch {}
  }

  return {
    antigravity,
    claude,
    codex,
    cursor,
    opencode,
    gemini,
    openclaw,
    tailscale,
    herdr: {
      installed: hcInstalled,
      inTerminal: typeof env.HC_TERMINAL_ID === "string" && env.HC_TERMINAL_ID.length > 0,
      ...(env.HC_TERMINAL_ID ? { terminalId: env.HC_TERMINAL_ID } : {}),
      machines,
    },
    t3: {
      installed: t3Installed,
      ...(existsSync(t3Home) ? { homeDir: t3Home } : {}),
      meshConfigured: t3MeshConfigured,
      ...(t3ConnectorId ? { connectorId: t3ConnectorId } : {}),
      ...(t3RouterUrl ? { routerUrl: t3RouterUrl } : {}),
      plugins: t3Plugins,
    },
  };
}

const SKIP_SSH_HOSTS = new Set(["github.com", "gitlab.com", "bitbucket.org", "ssh.github.com"]);

export function parseSshConfigHosts(sshConfigContent: string): string[] {
  const hosts: string[] = [];
  for (const line of sshConfigContent.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!/^Host\s+/i.test(trimmed)) continue;
    const tokens = trimmed.replace(/^Host\s+/i, "").split(/\s+/);
    for (const token of tokens) {
      if (!token || token.includes("*") || token.includes("?") || token.startsWith("!")) continue;
      if (SKIP_SSH_HOSTS.has(token.toLowerCase())) continue;
      hosts.push(token);
      break; // take primary alias per Host block to avoid duplicates like `great-northern gn`
    }
  }
  return [...new Set(hosts)];
}

/**
 * Discovers candidate remote machines from:
 * 1. Herdr Core (`hc ls --json` -> `.machines`)
 * 2. `~/.ssh/config` host blocks
 * 3. Tailscale online peers (`tailscale status --json`)
 */
export function discoverRemoteMachines(home = homedir(), localEnv?: LocalEnvironment): DiscoveredMachine[] {
  const env = localEnv ?? detectLocalEnvironment(home);
  const byHost = new Map<string, { sources: Set<string>; sshTarget?: string; herdrState?: string; tailscaleDns?: string }>();

  const add = (host: string, source: string, extra?: { sshTarget?: string; herdrState?: string; tailscaleDns?: string }) => {
    const key = host.trim();
    if (!key) return;
    const existing = byHost.get(key) ?? { sources: new Set<string>() };
    existing.sources.add(source);
    if (extra?.sshTarget && !existing.sshTarget) existing.sshTarget = extra.sshTarget;
    if (extra?.herdrState) existing.herdrState = extra.herdrState;
    if (extra?.tailscaleDns) existing.tailscaleDns = extra.tailscaleDns;
    byHost.set(key, existing);
  };

  for (const m of env.herdr.machines) {
    add(m.name, "herdr", { herdrState: m.state, ...(m.target ? { sshTarget: m.target } : {}) });
  }

  const sshConfigPath = join(home, ".ssh", "config");
  if (existsSync(sshConfigPath)) {
    try {
      for (const host of parseSshConfigHosts(readFileSync(sshConfigPath, "utf8"))) {
        add(host, "ssh-config");
      }
    } catch {}
  }

  if (env.tailscale) {
    try {
      const raw = execFileSync("tailscale", ["status", "--json"], { encoding: "utf8", timeout: 3_000, stdio: ["ignore", "pipe", "ignore"] });
      const parsed: unknown = JSON.parse(raw);
      const suffix = object(parsed) && typeof parsed.MagicDNSSuffix === "string" ? parsed.MagicDNSSuffix : "";
      if (object(parsed) && object(parsed.Peer)) {
        for (const peer of Object.values(parsed.Peer)) {
          if (!object(peer) || peer.Online !== true) continue;
          const os = typeof peer.OS === "string" ? peer.OS.toLowerCase() : "";
          if (os === "ios" || os === "android") continue;
          const dnsRaw = typeof peer.DNSName === "string" ? peer.DNSName : "";
          // Filter out Mullvad / external exit-node peers outside our own tailnet
          if (suffix && !dnsRaw.endsWith(`.${suffix}.`)) continue;
          const dns = dnsRaw.replace(/\.$/, "");
          const short = typeof peer.HostName === "string" && peer.HostName.length > 0 && peer.HostName !== "localhost"
            ? peer.HostName
            : dns.split(".")[0] ?? "";
          if (short) add(short, "tailscale", { ...(dns ? { tailscaleDns: dns } : {}) });
        }
      }
    } catch {}
  }

  return [...byHost.entries()].map(([host, info]) => ({
    host,
    ...(info.sshTarget ? { sshTarget: info.sshTarget } : {}),
    sources: [...info.sources],
    ...(info.herdrState ? { herdrState: info.herdrState } : {}),
    ...(info.tailscaleDns ? { tailscaleDns: info.tailscaleDns } : {}),
  }));
}

const REMOTE_PROBE_SCRIPT = [
  'echo "USER=$(whoami)"',
  'echo "HOST=$(hostname -s 2>/dev/null || hostname)"',
  'echo "NODE=$(node -v 2>/dev/null || true)"',
  'echo "MESH=$(command -v hyp 2>/dev/null || command -v hyphae 2>/dev/null || true)"',
  'echo "T3MESH=$(test -f ~/.t3-mesh/config.json && echo yes || echo no)"',
  'H=""',
  '(test -d ~/.gemini/config || command -v agy >/dev/null 2>&1) && H="$H antigravity"',
  '(test -d ~/.claude || command -v claude >/dev/null 2>&1) && H="$H claude"',
  '(test -d ~/.codex || command -v codex >/dev/null 2>&1) && H="$H codex"',
  '(test -d ~/.cursor || command -v cursor >/dev/null 2>&1) && H="$H cursor"',
  '(test -d ~/.config/opencode || command -v opencode >/dev/null 2>&1) && H="$H opencode"',
  '(test -f ~/.gemini/settings.json || command -v gemini >/dev/null 2>&1) && H="$H gemini"',
  '(test -d ~/.openclaw || command -v openclaw >/dev/null 2>&1) && H="$H openclaw"',
  'command -v hc >/dev/null 2>&1 && H="$H herdr"',
  '(test -d ~/.t3 || command -v t3 >/dev/null 2>&1) && H="$H t3"',
  'echo "HARNESSES=$H"',
  "exit 0",
].join("; ");

const SAFE_SSH_TARGET = /^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$/;
const SAFE_REMOTE_BIN = /^[A-Za-z0-9_./-]{1,128}$/;

export function probeRemoteHost(machine: DiscoveredMachine, timeoutMs = 8_000): Promise<RemoteProbeResult> {
  const herdrConnected = machine.herdrState === "connected";
  const target = machine.sshTarget ?? machine.host;
  if (!SAFE_SSH_TARGET.test(target)) {
    return Promise.resolve({
      host: machine.host,
      sources: machine.sources,
      sshReachable: false,
      herdrConnected,
      harnesses: [],
      error: "Rejected unsafe SSH target name",
    });
  }
  return new Promise((resolve) => {
    execFile(
      "ssh",
      [
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=5",
        "-o", "StrictHostKeyChecking=accept-new",
        "--",
        target,
        `sh -c '${REMOTE_PROBE_SCRIPT.replace(/'/g, "'\\''")}'`,
      ],
      { timeout: timeoutMs, maxBuffer: 64_000 },
      (error, stdout, stderr) => {
        if (error) {
          resolve({
            host: machine.host,
            sources: machine.sources,
            sshReachable: false,
            herdrConnected,
            harnesses: [],
            error: (stderr || error.message).trim().split("\n").filter((l) => !l.includes("setlocale"))[0]
              ?? (stderr || error.message).trim().split("\n")[0],
          });
          return;
        }
        const kv = new Map<string, string>();
        for (const line of stdout.split(/\r?\n/)) {
          const eq = line.indexOf("=");
          if (eq > 0) kv.set(line.slice(0, eq), line.slice(eq + 1).trim());
        }
        resolve({
          host: machine.host,
          sources: machine.sources,
          sshReachable: true,
          herdrConnected,
          user: kv.get("USER") || undefined,
          hostname: kv.get("HOST") || undefined,
          nodeVersion: kv.get("NODE") || undefined,
          hasHyphae: Boolean(kv.get("MESH")),
          hasT3Mesh: kv.get("T3MESH") === "yes",
          harnesses: (kv.get("HARNESSES") ?? "").split(/\s+/).filter(Boolean),
        });
      },
    );
  });
}

/**
 * Onboards a remote machine over SSH by piping the one-shot `am1_...` invite over stdin
 * (so the connector token never appears in remote argv or shell history).
 */
export function onboardRemoteOverSsh(options: {
  readonly host: string;
  readonly inviteCode: string;
  readonly installService?: boolean;
  readonly remoteBin?: string;
}): Promise<{ ok: boolean; stdout: string; stderr: string }> {
  const bin = options.remoteBin ?? "hyp";
  if (!SAFE_SSH_TARGET.test(options.host)) {
    return Promise.resolve({ ok: false, stdout: "", stderr: `Unsafe SSH host: ${options.host}` });
  }
  if (!SAFE_REMOTE_BIN.test(bin)) {
    return Promise.resolve({ ok: false, stdout: "", stderr: `Unsafe remote binary path: ${bin}` });
  }
  const flags = ["--join", "--replace", ...(options.installService ? ["--install-service"] : [])].join(" ");
  const inner = `if command -v ${bin} >/dev/null 2>&1; then ${bin} onboard ${flags}; elif command -v hyphae >/dev/null 2>&1; then hyphae onboard ${flags}; elif [ -x "$HOME/.local/bin/hyp" ]; then "$HOME/.local/bin/hyp" onboard ${flags}; else echo "hyp (hyphae) not found in PATH on $(hostname)" >&2; exit 127; fi`;
  const remoteCmd = `sh -c '${inner.replace(/'/g, "'\\''")}'`;

  return new Promise((resolve) => {
    const child = spawn(
      "ssh",
      ["-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "--", options.host, remoteCmd],
      { stdio: ["pipe", "pipe", "pipe"] },
    );
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (d: Buffer) => out.push(d));
    child.stderr.on("data", (d: Buffer) => err.push(d));
    child.stdin.end(options.inviteCode + "\n");
    child.once("exit", (code) => {
      resolve({
        ok: code === 0,
        stdout: Buffer.concat(out).toString("utf8"),
        stderr: Buffer.concat(err).toString("utf8"),
      });
    });
  });
}
