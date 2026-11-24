import { execFileSync } from "node:child_process";
import { connectorPattern, object } from "./protocol.ts";

export interface InviteBundle {
  readonly v: 1;
  readonly connectorId: string;
  readonly router: string;
  readonly token: string;
}

const INVITE_PREFIX = "am1_";

export function normalizeRouterOrigin(rawUrl: string): string {
  const url = new URL(rawUrl);
  const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  if (!(url.protocol === "https:" || (url.protocol === "http:" && loopback)) ||
      url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
    throw new Error(`Router URL must be an HTTPS origin or loopback HTTP origin (got ${rawUrl})`);
  }
  return url.origin;
}

/** Encodes a one-shot onboarding invite (`am1_<base64url>`). Deliver privately and pass via stdin. */
export function encodeInvite(bundle: Omit<InviteBundle, "v">): string {
  if (!connectorPattern.test(bundle.connectorId)) {
    throw new Error(`Invalid connector ID: ${bundle.connectorId}`);
  }
  const router = normalizeRouterOrigin(bundle.router);
  const token = bundle.token.trim();
  if (token.length === 0 || !/^[!-~]+$/.test(token)) {
    throw new Error("Invalid connector token");
  }
  const payload: InviteBundle = { v: 1, connectorId: bundle.connectorId, router, token };
  return INVITE_PREFIX + Buffer.from(JSON.stringify(payload), "utf8").toString("base64url");
}

export function decodeInvite(code: string): InviteBundle {
  const trimmed = code.trim();
  if (!trimmed.startsWith(INVITE_PREFIX)) {
    throw new Error("Invalid invite code (expected string starting with 'am1_')");
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(trimmed.slice(INVITE_PREFIX.length), "base64url").toString("utf8"));
  } catch {
    throw new Error("Invite code is not valid base64url JSON");
  }
  if (!object(parsed) || parsed.v !== 1 || typeof parsed.connectorId !== "string" ||
      typeof parsed.router !== "string" || typeof parsed.token !== "string") {
    throw new Error("Malformed invite bundle");
  }
  if (!connectorPattern.test(parsed.connectorId)) throw new Error("Invalid connectorId in invite");
  const router = normalizeRouterOrigin(parsed.router);
  const token = parsed.token.trim();
  if (token.length === 0 || !/^[!-~]+$/.test(token)) throw new Error("Invalid token in invite");
  return { v: 1, connectorId: parsed.connectorId, router, token };
}

export interface RouterProbeResult {
  readonly ok: boolean;
  readonly status?: number;
  readonly peers?: number;
  readonly error?: string;
}

/** Verifies HTTPS/VPN reachability and bearer token auth against `GET /v1/peers`. */
export async function probeRouter(
  routerUrl: string,
  token: string,
  timeoutMs = 5_000,
): Promise<RouterProbeResult> {
  const origin = normalizeRouterOrigin(routerUrl);
  try {
    const res = await fetch(`${origin}/v1/peers`, {
      method: "GET",
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
      headers: { authorization: `Bearer ${token}` },
    });
    if (res.ok) {
      const body: unknown = await res.json().catch(() => null);
      const peers = object(body) && Array.isArray(body.peers) ? body.peers.length : undefined;
      return { ok: true, status: res.status, peers };
    }
    if (res.status === 401 || res.status === 403) {
      return { ok: false, status: res.status, error: `Authentication refused (HTTP ${res.status}); check connector token` };
    }
    return { ok: false, status: res.status, error: `Router returned HTTP ${res.status}` };
  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    return { ok: false, error: `Could not reach ${origin} (${msg}). Verify VPN/Tailscale connectivity and router status.` };
  }
}

export interface TailscaleStatusInfo {
  readonly backendState: string;
  readonly dnsName: string;
  readonly magicDnsSuffix: string;
}

export type ExecRunner = (bin: string, args: readonly string[]) => string;

const defaultExec: ExecRunner = (bin, args) =>
  execFileSync(bin, [...args], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

export function readTailscaleStatus(exec: ExecRunner = defaultExec): TailscaleStatusInfo {
  let raw: string;
  try {
    raw = exec("tailscale", ["status", "--json"]);
  } catch (error) {
    throw new Error(`Could not run 'tailscale status --json': ${error instanceof Error ? error.message : String(error)}`);
  }
  const parsed: unknown = JSON.parse(raw);
  if (!object(parsed)) throw new Error("Unexpected tailscale status output");
  const backendState = typeof parsed.BackendState === "string" ? parsed.BackendState : "Unknown";
  const self = object(parsed.Self) ? parsed.Self : {};
  const dnsName = typeof self.DNSName === "string" ? self.DNSName.replace(/\.$/, "") : "";
  const suffix = typeof parsed.MagicDNSSuffix === "string"
    ? parsed.MagicDNSSuffix.replace(/^\.+|\.+$/g, "")
    : dnsName.includes(".")
      ? dnsName.slice(dnsName.indexOf(".") + 1)
      : "";
  return { backendState, dnsName, magicDnsSuffix: suffix };
}

export function normalizeTailscaleServiceName(raw: string): { readonly serviceFlag: string; readonly hostLabel: string } {
  const stripped = raw.startsWith("svc:") ? raw.slice(4) : raw;
  if (!/^[a-z0-9][a-z0-9-]{0,62}$/.test(stripped)) {
    throw new Error(`Invalid Tailscale service name "${raw}" (use lowercase letters, digits, hyphens; e.g. hyphae)`);
  }
  return { serviceFlag: `svc:${stripped}`, hostLabel: stripped };
}

export interface ExposeTailscaleOptions {
  /** Local loopback port where hph router listens (default 8790). */
  readonly localPort?: number;
  /** Expose as a Tailscale Service (`--service=svc:<name>`) with its own tailnet DNS name & VIP. */
  readonly service?: string;
  /** External HTTPS port (defaults to 443 for --service, 8790 for node-scoped serve). */
  readonly httpsPort?: number;
  /** Return command and URL without executing `tailscale serve`. */
  readonly dryRun?: boolean;
  readonly exec?: ExecRunner;
}

export interface ExposeTailscaleResult {
  readonly command: string[];
  readonly url: string;
  readonly mode: "service" | "node";
  readonly serviceFlag?: string;
  readonly applied: boolean;
}

/**
 * Exposes the loopback router privately on your Tailnet via `tailscale serve` (never public Funnel):
 * - With `--service <name>` (e.g. `hyphae` or `svc:hyphae`): registers a Tailscale Service
 *   at `https://<name>.<tailnet>.ts.net` (port 443 by default).
 * - Without `--service`: exposes on this node's MagicDNS name `https://<node>.<tailnet>.ts.net:<httpsPort>`.
 */
export function exposeTailscale(options: ExposeTailscaleOptions = {}): ExposeTailscaleResult {
  const exec = options.exec ?? defaultExec;
  const localPort = options.localPort ?? 8790;
  if (!Number.isInteger(localPort) || localPort < 1 || localPort > 65535) {
    throw new Error("Expected --port between 1 and 65535");
  }
  const status = readTailscaleStatus(exec);
  if (status.backendState !== "Running") {
    throw new Error(`Tailscale is not running (state: ${status.backendState}). Run 'tailscale up' first.`);
  }

  const target = `http://127.0.0.1:${localPort}`;
  if (options.service) {
    const { serviceFlag, hostLabel } = normalizeTailscaleServiceName(options.service);
    if (!status.magicDnsSuffix) {
      throw new Error("Tailscale MagicDNS suffix not found. Enable MagicDNS in your tailnet admin console.");
    }
    const httpsPort = options.httpsPort ?? 443;
    const args = ["serve", "--bg", "--yes", `--service=${serviceFlag}`, `--https=${httpsPort}`, target];
    if (!options.dryRun) exec("tailscale", args);
    const portSuffix = httpsPort === 443 ? "" : `:${httpsPort}`;
    return {
      command: ["tailscale", ...args],
      url: `https://${hostLabel}.${status.magicDnsSuffix}${portSuffix}`,
      mode: "service",
      serviceFlag,
      applied: !options.dryRun,
    };
  }

  if (!status.dnsName) {
    throw new Error("Tailscale node MagicDNS name not found. Enable MagicDNS in your tailnet admin console.");
  }
  const httpsPort = options.httpsPort ?? localPort;
  const args = ["serve", "--bg", "--yes", `--https=${httpsPort}`, target];
  if (!options.dryRun) exec("tailscale", args);
  const portSuffix = httpsPort === 443 ? "" : `:${httpsPort}`;
  return {
    command: ["tailscale", ...args],
    url: `https://${status.dnsName}${portSuffix}`,
    mode: "node",
    applied: !options.dryRun,
  };
}

export function unexposeTailscale(options: { service?: string; httpsPort?: number; exec?: ExecRunner } = {}): string[] {
  const exec = options.exec ?? defaultExec;
  if (options.service) {
    const { serviceFlag } = normalizeTailscaleServiceName(options.service);
    const args = ["serve", "clear", serviceFlag];
    exec("tailscale", args);
    return ["tailscale", ...args];
  }
  const httpsPort = options.httpsPort ?? 8790;
  const args = ["serve", `--https=${httpsPort}`, "off"];
  exec("tailscale", args);
  return ["tailscale", ...args];
}

/**
 * Best-effort detection of an already-exposed Tailscale HTTPS URL for a local router port
 * (used by `hph router invite` when `--router` is omitted).
 */
export function detectExposedTailscaleUrl(localPort = 8790, exec: ExecRunner = defaultExec): string | null {
  try {
    const status = readTailscaleStatus(exec);
    if (status.backendState !== "Running") return null;
    const raw = exec("tailscale", ["serve", "status", "--json"]);
    const parsed: unknown = JSON.parse(raw);
    if (!object(parsed)) return null;
    const targetSuffix = `:${localPort}`;

    // Check Tailscale Services first (preferred stable VIP URL)
    if (object(parsed.Services)) {
      for (const [svcKey, svcVal] of Object.entries(parsed.Services)) {
        if (!object(svcVal) || !object(svcVal.Web)) continue;
        for (const [hostPort, webVal] of Object.entries(svcVal.Web)) {
          if (!object(webVal) || !object(webVal.Handlers)) continue;
          for (const handler of Object.values(webVal.Handlers)) {
            if (object(handler) && typeof handler.Proxy === "string" && handler.Proxy.endsWith(targetSuffix)) {
              const name = svcKey.replace(/^svc:/, "");
              const portMatch = /:(\d+)$/.exec(hostPort);
              const port = portMatch ? Number(portMatch[1]) : 443;
              if (status.magicDnsSuffix) {
                return `https://${name}.${status.magicDnsSuffix}${port === 443 ? "" : `:${port}`}`;
              }
            }
          }
        }
      }
    }

    // Check node-scoped Web handlers
    if (object(parsed.Web)) {
      for (const [hostPort, webVal] of Object.entries(parsed.Web)) {
        if (!object(webVal) || !object(webVal.Handlers)) continue;
        for (const handler of Object.values(webVal.Handlers)) {
          if (object(handler) && typeof handler.Proxy === "string" && handler.Proxy.endsWith(targetSuffix)) {
            const [host, portStr] = hostPort.split(":");
            const port = portStr ? Number(portStr) : 443;
            if (host) return `https://${host.replace(/\.$/, "")}${port === 443 ? "" : `:${port}`}`;
          }
        }
      }
    }
  } catch {
    return null;
  }
  return null;
}
