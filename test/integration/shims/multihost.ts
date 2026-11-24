import { execFileSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import {
  createServer as createHttpServer,
  request as httpRequest,
  type ClientRequest,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { createServer as createHttpsServer, request as httpsRequest } from "node:https";
import type { Socket } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

function forwardRequest(
  target: URL,
  req: IncomingMessage,
  res: ServerResponse,
  upstreamReqs: Set<ClientRequest>,
): ClientRequest {
  const headers: Record<string, string | string[] | undefined> = { ...req.headers };
  headers.host = target.host;
  delete headers["transfer-encoding"];

  const requestFn = target.protocol === "https:" ? httpsRequest : httpRequest;
  const proxyReq = requestFn(
    {
      protocol: target.protocol,
      hostname: target.hostname,
      port: target.port || (target.protocol === "https:" ? 443 : 80),
      method: req.method,
      path: req.url ?? "/",
      headers,
    },
    (proxyRes) => {
      if (res.destroyed) {
        proxyRes.destroy();
        return;
      }
      res.writeHead(proxyRes.statusCode ?? 502, proxyRes.headers);
      // Flush headers immediately so SSE streams (e.g. GET /v1/inbox) start flowing without buffering.
      res.flushHeaders();
      proxyRes.pipe(res);
      proxyRes.on("error", () => {
        if (!res.destroyed) res.destroy();
      });
    },
  );

  upstreamReqs.add(proxyReq);
  proxyReq.on("close", () => {
    upstreamReqs.delete(proxyReq);
  });
  proxyReq.on("error", (err) => {
    upstreamReqs.delete(proxyReq);
    if (!res.headersSent) {
      res.writeHead(502, { "content-type": "text/plain", connection: "close" });
      res.end(`Bad Gateway: ${err.message}`);
    } else if (!res.destroyed) {
      res.destroy();
    }
  });

  res.on("close", () => {
    if (!res.writableEnded) {
      proxyReq.destroy();
    }
  });

  req.pipe(proxyReq);
  return proxyReq;
}

export interface TlsReverseProxy {
  readonly url: string;
  readonly port: number;
  readonly caCertPath: string;
  close(): Promise<void>;
}

/**
 * Generates an ephemeral self-signed localhost TLS certificate via `openssl` and starts
 * a streaming HTTPS reverse proxy on `127.0.0.1:0` forwarding HTTP & SSE traffic to `targetUrl`.
 */
export async function startTlsReverseProxy(targetUrl: string): Promise<TlsReverseProxy> {
  const target = new URL(targetUrl);
  const certDir = mkdtempSync(join(tmpdir(), "hi-tls-"));
  const keyPath = join(certDir, "key.pem");
  const certPath = join(certDir, "cert.pem");

  try {
    execFileSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        keyPath,
        "-out",
        certPath,
        "-days",
        "1",
        "-subj",
        "/CN=localhost",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,digitalSignature,keyEncipherment,keyCertSign",
        "-addext",
        "subjectAltName=DNS:localhost,IP:127.0.0.1",
      ],
      { stdio: ["ignore", "pipe", "pipe"] },
    );
  } catch (error) {
    rmSync(certDir, { recursive: true, force: true });
    throw new Error(`Failed to generate self-signed TLS cert with openssl: ${error instanceof Error ? error.message : String(error)}`);
  }

  const upstreamReqs = new Set<ClientRequest>();
  const server = createHttpsServer(
    {
      key: readFileSync(keyPath),
      cert: readFileSync(certPath),
    },
    (req, res) => {
      forwardRequest(target, req, res, upstreamReqs);
    },
  );

  await new Promise<void>((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", () => resolveListen());
  });

  const addr = server.address();
  if (!addr || typeof addr === "string") {
    server.close();
    rmSync(certDir, { recursive: true, force: true });
    throw new Error("TLS reverse proxy failed to bind to loopback TCP port");
  }

  let closed = false;
  return {
    url: `https://127.0.0.1:${addr.port}`,
    port: addr.port,
    caCertPath: certPath,
    async close() {
      if (closed) return;
      closed = true;
      for (const req of [...upstreamReqs]) {
        try { req.destroy(); } catch {}
      }
      upstreamReqs.clear();
      server.closeAllConnections();
      await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
      rmSync(certDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    },
  };
}

export interface ChaosProxy {
  readonly url: string;
  readonly port: number;
  /** Immediately destroys all active client/upstream sockets and rejects new requests with 503. */
  sever(): void;
  /** Restores normal HTTP & SSE forwarding. */
  heal(): void;
  isSevered(): boolean;
  /** Adds artificial latency (in ms) before forwarding new requests. */
  setLatencyMs(ms: number): void;
  close(): Promise<void>;
}

/**
 * Loopback HTTP/SSE fault-injection proxy that can simulate a single-host network
 * partition (`sever()` / `heal()`) and artificial latency while keeping the target router alive.
 */
export async function startChaosProxy(targetUrl: string): Promise<ChaosProxy> {
  const target = new URL(targetUrl);
  let severed = false;
  let closed = false;
  let latencyMs = 0;

  const clientSockets = new Set<Socket>();
  const upstreamReqs = new Set<ClientRequest>();
  const pendingDelayed = new Set<{ timer: NodeJS.Timeout; reject: () => void }>();

  const rejectPartitioned = (res: ServerResponse) => {
    if (res.destroyed) return;
    if (!res.headersSent) {
      res.writeHead(503, { "content-type": "text/plain", connection: "close" });
      res.end("Network partitioned by ChaosProxy");
    } else {
      res.destroy();
    }
  };

  const server = createHttpServer((req, res) => {
    if (severed || closed) {
      rejectPartitioned(res);
      return;
    }

    const delay = latencyMs;
    if (delay > 0) {
      req.pause();
      const entry = {
        timer: setTimeout(() => {
          pendingDelayed.delete(entry);
          if (severed || closed || req.destroyed || res.destroyed) {
            rejectPartitioned(res);
            return;
          }
          forwardRequest(target, req, res, upstreamReqs);
        }, delay),
        reject: () => {
          clearTimeout(entry.timer);
          rejectPartitioned(res);
        },
      };
      pendingDelayed.add(entry);
      res.on("close", () => {
        if (pendingDelayed.has(entry)) {
          pendingDelayed.delete(entry);
          clearTimeout(entry.timer);
        }
      });
      return;
    }

    forwardRequest(target, req, res, upstreamReqs);
  });

  server.on("connection", (socket) => {
    clientSockets.add(socket);
    socket.on("close", () => {
      clientSockets.delete(socket);
    });
  });

  await new Promise<void>((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", () => resolveListen());
  });

  const addr = server.address();
  if (!addr || typeof addr === "string") {
    server.close();
    throw new Error("Chaos proxy failed to bind to loopback TCP port");
  }

  const sever = () => {
    severed = true;
    for (const entry of [...pendingDelayed]) {
      pendingDelayed.delete(entry);
      entry.reject();
    }
    for (const uReq of [...upstreamReqs]) {
      try { uReq.destroy(); } catch {}
    }
    upstreamReqs.clear();
    for (const sock of [...clientSockets]) {
      try { sock.destroy(); } catch {}
    }
    clientSockets.clear();
  };

  return {
    url: `http://127.0.0.1:${addr.port}`,
    port: addr.port,
    sever,
    heal() {
      severed = false;
    },
    isSevered() {
      return severed;
    },
    setLatencyMs(ms: number) {
      latencyMs = Math.max(0, Math.floor(ms));
    },
    async close() {
      if (closed) return;
      closed = true;
      sever();
      server.closeAllConnections();
      await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
    },
  };
}

export interface VirtualSshHostOptions {
  readonly rootDir: string;
  readonly hostAlias: string;
  readonly remoteHome: string;
  readonly remoteXdgConfig: string;
  readonly hypPath?: string;
  readonly extraEnv?: Readonly<Record<string, string>>;
}

export interface SshInvocationRecord {
  readonly argv: string[];
  readonly ts: number;
}

export interface VirtualSshHost {
  readonly hostAlias: string;
  readonly binDir: string;
  readonly remoteBinDir: string;
  readonly sshPath: string;
  readonly hypWrapperPath: string;
  readonly remoteHome: string;
  readonly remoteXdgConfig: string;
  readonly invocationLogPath: string;
  readInvocations(): SshInvocationRecord[];
  /** Stops any detached daemons launched against `remoteXdgConfig`. */
  cleanup(): Promise<void>;
}

function shSingleQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

/**
 * Creates a mock `ssh` executable inside an isolated temp `bin/` directory that intercepts
 * `ssh ... -- <hostAlias> <remoteCmd>` and executes `<remoteCmd>` locally with
 * `HOME=remoteHome`, `XDG_CONFIG_HOME=remoteXdgConfig`, and `PATH` containing a `hyp`
 * wrapper pointing at `node src/cli.ts`, forwarding stdin/stdout/stderr/exit code faithfully.
 */
export function createVirtualSshHost(opts: VirtualSshHostOptions): VirtualSshHost {
  const rootDir = resolve(opts.rootDir);
  const remoteHome = resolve(opts.remoteHome);
  const remoteXdgConfig = resolve(opts.remoteXdgConfig);
  const hypPath = resolve(opts.hypPath ?? join(process.cwd(), "src", "cli.ts"));

  const binDir = join(rootDir, "bin");
  const remoteBinDir = join(rootDir, "remote-bin");
  mkdirSync(binDir, { recursive: true, mode: 0o700 });
  mkdirSync(remoteBinDir, { recursive: true, mode: 0o700 });
  mkdirSync(remoteHome, { recursive: true, mode: 0o700 });
  mkdirSync(remoteXdgConfig, { recursive: true, mode: 0o700 });

  const nodeBin = process.execPath;
  const nodeBinDir = dirname(nodeBin);
  const invocationLogPath = join(rootDir, "ssh-invocations.jsonl");

  // Wrapper script exposed as `hyp` inside the virtual remote host's PATH.
  const hypWrapperPath = join(remoteBinDir, "hyp");
  const hypExec = /\.(?:ts|mts|js|mjs|cjs)$/.test(hypPath)
    ? `exec ${shSingleQuote(nodeBin)} ${shSingleQuote(hypPath)} "$@"`
    : `exec ${shSingleQuote(hypPath)} "$@"`;
  writeFileSync(hypWrapperPath, `#!/bin/sh\n${hypExec}\n`, { mode: 0o755 });
  chmodSync(hypWrapperPath, 0o755);

  const mockConfig = {
    hostAlias: opts.hostAlias,
    remoteHome,
    remoteXdgConfig,
    remoteBinDir,
    nodeBinDir,
    invocationLogPath,
    extraEnv: opts.extraEnv ?? {},
  };

  // Node-based mock `ssh` executable for exact argv logging and faithful stdio/exit forwarding.
  const sshPath = join(binDir, "ssh");
  const sshScript = `#!${nodeBin}
import { spawn } from "node:child_process";
import { appendFileSync } from "node:fs";

const cfg = ${JSON.stringify(mockConfig)};
const args = process.argv.slice(2);

try {
  appendFileSync(cfg.invocationLogPath, JSON.stringify({ argv: args, ts: Date.now() }) + "\\n", "utf8");
} catch {}

const VALUE_FLAGS = new Set([
  "-B", "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J",
  "-L", "-l", "-m", "-O", "-o", "-p", "-Q", "-R", "-S", "-W", "-w",
]);

let target = "";
let cmdParts = [];
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === "--") {
    target = args[i + 1] ?? "";
    cmdParts = args.slice(i + 2);
    break;
  }
  if (a.startsWith("-")) {
    if (VALUE_FLAGS.has(a)) i++;
    continue;
  }
  target = a;
  cmdParts = args.slice(i + 1);
  break;
}

const targetHost = target.includes("@") ? target.slice(target.indexOf("@") + 1) : target;
if (!targetHost || targetHost !== cfg.hostAlias) {
  process.stderr.write(\`ssh: Could not resolve hostname \${target || "<empty>"}: nodename nor servname provided\\n\`);
  process.exit(255);
}

const remoteCmd = cmdParts.join(" ");
const remoteEnv = {
  HOME: cfg.remoteHome,
  XDG_CONFIG_HOME: cfg.remoteXdgConfig,
  PATH: \`\${cfg.remoteBinDir}:\${cfg.nodeBinDir}:/usr/bin:/bin\`,
  USER: process.env.USER || "remote",
  TERM: process.env.TERM || "dumb",
  ...(process.env.NODE_EXTRA_CA_CERTS ? { NODE_EXTRA_CA_CERTS: process.env.NODE_EXTRA_CA_CERTS } : {}),
  ...cfg.extraEnv,
};

const child = spawn("/bin/sh", ["-c", remoteCmd], {
  stdio: "inherit",
  env: remoteEnv,
});

child.on("error", (err) => {
  process.stderr.write(\`virtual-ssh exec error: \${err.message}\\n\`);
  process.exit(255);
});

child.on("exit", (code, signal) => {
  if (signal) process.exit(128);
  process.exit(code ?? 0);
});
`;
  writeFileSync(sshPath, sshScript, { mode: 0o755 });
  chmodSync(sshPath, 0o755);

  const findRemoteDaemons = (): number[] => {
    try {
      const psOut = execFileSync("ps", ["-eo", "pid=,args="], { encoding: "utf8" });
      const pids: number[] = [];
      for (const line of psOut.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        const space = trimmed.search(/\s+/);
        if (space === -1) continue;
        const pid = Number(trimmed.slice(0, space));
        const cmd = trimmed.slice(space).trim();
        if (Number.isInteger(pid) && pid > 0 && pid !== process.pid && cmd.includes(remoteXdgConfig)) {
          pids.push(pid);
        }
      }
      return pids;
    } catch {
      return [];
    }
  };

  return {
    hostAlias: opts.hostAlias,
    binDir,
    remoteBinDir,
    sshPath,
    hypWrapperPath,
    remoteHome,
    remoteXdgConfig,
    invocationLogPath,
    readInvocations() {
      if (!existsSync(invocationLogPath)) return [];
      return readFileSync(invocationLogPath, "utf8")
        .split("\n")
        .filter((line) => line.trim().length > 0)
        .map((line) => JSON.parse(line) as SshInvocationRecord);
    },
    async cleanup() {
      const pids = findRemoteDaemons();
      for (const pid of pids) {
        try { process.kill(pid, "SIGTERM"); } catch {}
      }
      if (pids.length > 0) {
        const deadline = Date.now() + 2_000;
        while (Date.now() < deadline && findRemoteDaemons().length > 0) {
          await new Promise((r) => setTimeout(r, 50));
        }
        for (const pid of findRemoteDaemons()) {
          try { process.kill(pid, "SIGKILL"); } catch {}
        }
      }
    },
  };
}
