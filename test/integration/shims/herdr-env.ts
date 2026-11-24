import { spawn, type ChildProcess } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { join } from "node:path";
import { daemonRpc } from "../../../src/hooks.ts";
import { object } from "../../../src/protocol.ts";
import { McpClient, waitFor } from "../harness/topology.ts";

export type VirtualInterruptOutcome = "stopped" | "still_working" | "exited" | "unknown" | "failed";

export interface VirtualTerminalInput {
  readonly address: string;
  /** Agent application name (e.g. `"claude"`, `"codex"`). Omit or pass `null` with `status: null` for bare shells. */
  readonly app?: string | null;
  /**
   * Agent status state (`"idle" | "working" | "done" | "blocked" | "error"`) when live,
   * or terminal lifecycle state (`"exited" | "finished"`) which marks the terminal non-live.
   */
  readonly state?: string;
  /** Explicit terminal liveness override. Defaults to `true` unless `state` is `"exited"` or `"finished"`. */
  readonly live?: boolean;
  /** Pass `null` for bare shells, or a custom object for perturbed OSC 7501 status payloads. */
  readonly status?: null | Record<string, unknown>;
  readonly pid?: number | null;
  readonly created_ms?: number;
  /** Override the `address` field returned by `hc get` (for testing address-mismatch protection). */
  readonly reportedAddress?: string;
  /** One-shot or queued exit code(s) returned by upcoming `hc send` calls (e.g. `9` or `10` for guard refusal). */
  readonly nextSendExitCode?: number | readonly number[] | null;
  /** Outcome returned by `hc interrupt` (`"stopped"` transitions terminal state to `"idle"` by default). */
  readonly interruptOutcome?: VirtualInterruptOutcome;
  /** State transitioned to after `hc interrupt` returns `"stopped"` (default `"idle"`). */
  readonly stateAfterInterrupt?: string;
  /** Optional non-zero exit code for `hc get` (simulates unavailable/vanished terminal). */
  readonly getExitCode?: number;
}

export interface VirtualTerminalPatch {
  readonly app?: string | null;
  readonly state?: string;
  readonly live?: boolean;
  readonly status?: null | Record<string, unknown>;
  readonly pid?: number | null;
  readonly created_ms?: number;
  readonly reportedAddress?: string | null;
  readonly nextSendExitCode?: number | readonly number[] | null;
  readonly interruptOutcome?: VirtualInterruptOutcome;
  readonly stateAfterInterrupt?: string;
  readonly getExitCode?: number | null;
}

export interface VirtualTerminalSnapshot {
  readonly address: string;
  readonly reportedAddress?: string;
  readonly live: boolean;
  readonly lifecycleState: string;
  readonly pid: number | null;
  readonly created_ms: number;
  readonly status: Record<string, unknown> | null;
  readonly turn: number;
}

export interface VirtualHerdrMachine {
  readonly name: string;
  readonly state: string;
  readonly target?: string;
  readonly id?: string;
  readonly host?: string;
  readonly version?: string;
}

export interface VirtualHerdrInvocation {
  readonly args: readonly string[];
  readonly subcommand: string;
  readonly exitCode: number;
  readonly timestamp: number;
}

export interface VirtualSentMessage {
  readonly address: string;
  readonly text: string;
  readonly guard: string | null;
  readonly args: readonly string[];
  readonly timestamp: number;
}

export interface VirtualHerdrServer {
  readonly url: string;
  readonly port: number;
  readonly binDir: string;
  readonly hcPath: string;
  readonly invocations: readonly VirtualHerdrInvocation[];
  addTerminal(input: VirtualTerminalInput): VirtualTerminalSnapshot;
  setTerminal(address: string, patch: VirtualTerminalPatch): VirtualTerminalSnapshot;
  getTerminal(address: string): VirtualTerminalSnapshot | undefined;
  addMachine(machine: VirtualHerdrMachine): void;
  setMachineLsFailure(fail: boolean): void;
  sentMessages(address: string): readonly VirtualSentMessage[];
  waitForSend(
    address: string,
    predicate?: (message: VirtualSentMessage) => boolean,
    timeoutMs?: number,
  ): Promise<VirtualSentMessage>;
  waitForInvocation(
    predicate: (invocation: VirtualHerdrInvocation) => boolean,
    timeoutMs?: number,
  ): Promise<VirtualHerdrInvocation>;
  envWithVirtualHc(extraEnv?: NodeJS.ProcessEnv): NodeJS.ProcessEnv;
  close(): Promise<void>;
}

interface InternalTerminal {
  address: string;
  reportedAddress?: string;
  live: boolean;
  nonLiveState: string;
  pid: number | null;
  created_ms: number;
  status: Record<string, unknown> | null;
  nextSendExitCodes: number[];
  interruptOutcome: VirtualInterruptOutcome;
  stateAfterInterrupt: string;
  getExitCode: number | null;
  turn: number;
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, "'\\''")}'`;
}

function normalizeExitCodes(value: number | readonly number[] | null | undefined): number[] {
  if (value === null || value === undefined) return [];
  return Array.isArray(value) ? [...value] : [value as number];
}

function readJsonBody(req: IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")));
      } catch (error) {
        reject(error);
      }
    });
    req.on("error", reject);
  });
}

function snapshotTerminal(term: InternalTerminal): VirtualTerminalSnapshot {
  return {
    address: term.address,
    ...(term.reportedAddress ? { reportedAddress: term.reportedAddress } : {}),
    live: term.live,
    lifecycleState: term.live ? "live" : term.nonLiveState,
    pid: term.pid,
    created_ms: term.created_ms,
    status: term.status ? { ...term.status } : null,
    turn: term.turn,
  };
}

function serializeTerminalWire(term: InternalTerminal): Record<string, unknown> {
  const status = term.live && term.status !== null ? { ...term.status } : null;
  return {
    address: term.reportedAddress ?? term.address,
    state: term.live ? "live" : term.nonLiveState,
    pid: term.pid,
    created_ms: term.created_ms,
    status,
    reported: status !== null,
  };
}

function serializeMachineWire(machine: VirtualHerdrMachine): Record<string, unknown> {
  return {
    name: machine.name,
    state: machine.state,
    ...(machine.target !== undefined ? { target: machine.target } : {}),
    id: machine.id ?? `core-${machine.name}`,
    host: machine.host ?? machine.name,
    version: machine.version ?? "0.1.22-virtual",
  };
}

function parseSendArgs(args: readonly string[]): {
  address?: string;
  text?: string;
  guard: string | null;
} {
  let guard: string | null = null;
  let i = 0;
  let address: string | undefined;
  let text: string | undefined;

  while (i < args.length) {
    const token = args[i]!;
    if (address === undefined) {
      if (token === "--") {
        i += 1;
        address = args[i];
        text = args[i + 1];
        break;
      }
      if (token === "--json" || token === "--force" || token === "--wait") {
        i += 1;
        continue;
      }
      if (token === "--if") {
        guard = args[i + 1] ?? null;
        i += 2;
        continue;
      }
      if (token.startsWith("--if=")) {
        guard = token.slice("--if=".length);
        i += 1;
        continue;
      }
      if (token === "--timeout") {
        i += 2;
        continue;
      }
      if (token.startsWith("--timeout=")) {
        i += 1;
        continue;
      }
      address = token;
      text = args[i + 1];
      break;
    }
    i += 1;
  }

  return { address, text, guard };
}

function parseSingleTargetArgs(args: readonly string[], envTerminalId: string | null): string | undefined {
  let i = 0;
  while (i < args.length) {
    const token = args[i]!;
    if (token === "--json") {
      i += 1;
      continue;
    }
    if (token === "--timeout") {
      i += 2;
      continue;
    }
    if (token.startsWith("--timeout=")) {
      i += 1;
      continue;
    }
    if (token === "--") {
      return args[i + 1] ?? envTerminalId ?? undefined;
    }
    if (token.startsWith("-")) {
      i += 1;
      continue;
    }
    return token;
  }
  return envTerminalId ?? undefined;
}

/**
 * Starts a stateful loopback virtual Herdr Core (`hc`) controller and installs an executable
 * `hc` shim binary under `<rootDir>/hc-bin/hc`.
 *
 * Designed to be prepended to `PATH` for isolated `hyp daemon`, `hyp status --discover`,
 * and `hyp doctor` subprocesses without ever touching real Herdr terminals or `~/.config/herdr-core`.
 */
export async function startVirtualHerdrServer(rootDir: string): Promise<VirtualHerdrServer> {
  mkdirSync(rootDir, { recursive: true, mode: 0o700 });
  const binDir = join(rootDir, "hc-bin");
  mkdirSync(binDir, { recursive: true, mode: 0o700 });

  const terminals = new Map<string, InternalTerminal>();
  const machines: VirtualHerdrMachine[] = [];
  const invocations: VirtualHerdrInvocation[] = [];
  const sentByAddress = new Map<string, VirtualSentMessage[]>();
  const invocationWaiters = new Set<(inv: VirtualHerdrInvocation) => void>();
  const sendWaiters = new Set<(msg: VirtualSentMessage) => void>();

  let nextPid = 41_000;
  let nextCreatedMs = 1_730_000_000_000;
  let failMachineLs = false;

  const recordInvocation = (args: readonly string[], exitCode: number): VirtualHerdrInvocation => {
    const inv: VirtualHerdrInvocation = {
      args: [...args],
      subcommand: args[0] === "machine" && args[1] ? `machine ${args[1]}` : (args[0] ?? ""),
      exitCode,
      timestamp: Date.now(),
    };
    invocations.push(inv);
    for (const listener of [...invocationWaiters]) listener(inv);
    return inv;
  };

  const handleHcCommand = (
    args: readonly string[],
    envTerminalId: string | null,
  ): { code: number; stdout: string; stderr: string; deliveredMsg?: VirtualSentMessage } => {
    const [cmd, ...rest] = args;
    if (cmd === "--version" || cmd === "-V") {
      return { code: 0, stdout: "hc 0.1.22-virtual\n", stderr: "" };
    }

    if (cmd === "get") {
      const target = parseSingleTargetArgs(rest, envTerminalId);
      if (!target) {
        return { code: 1, stdout: "", stderr: JSON.stringify({ error: "missing_terminal" }) + "\n" };
      }
      const term = terminals.get(target);
      if (!term) {
        return { code: 1, stdout: "", stderr: JSON.stringify({ error: "not_found", address: target }) + "\n" };
      }
      if (term.getExitCode !== null && term.getExitCode !== 0) {
        return { code: term.getExitCode, stdout: "", stderr: JSON.stringify({ error: "simulated_get_error" }) + "\n" };
      }
      return { code: 0, stdout: JSON.stringify(serializeTerminalWire(term)) + "\n", stderr: "" };
    }

    if (cmd === "send") {
      const { address, text, guard } = parseSendArgs(rest);
      if (!address || text === undefined) {
        return { code: 2, stdout: "", stderr: "usage: hc send [--json] [--if <status>] <terminal> <text>\n" };
      }
      const term = terminals.get(address);
      if (!term || !term.live) {
        return { code: 1, stdout: "", stderr: JSON.stringify({ error: "target_unavailable", address }) + "\n" };
      }
      if (term.nextSendExitCodes.length > 0) {
        const forcedCode = term.nextSendExitCodes.shift()!;
        if (forcedCode !== 0) {
          return {
            code: forcedCode,
            stdout: "",
            stderr: JSON.stringify({
              error: forcedCode === 9 || forcedCode === 10 ? "guard_refused" : "send_failed",
              code: forcedCode,
            }) + "\n",
          };
        }
      }
      const currentState = term.status && typeof term.status.state === "string" ? term.status.state : null;
      if (guard !== null && currentState !== guard) {
        return {
          code: 9,
          stdout: "",
          stderr: JSON.stringify({ error: "guard_refused", expected: guard, actual: currentState }) + "\n",
        };
      }
      term.turn += 1;
      const deliveredMsg: VirtualSentMessage = {
        address: term.address,
        text,
        guard,
        args: [...args],
        timestamp: Date.now(),
      };
      const list = sentByAddress.get(term.address) ?? [];
      list.push(deliveredMsg);
      sentByAddress.set(term.address, list);
      return {
        code: 0,
        stdout: JSON.stringify({ started: false, status: currentState, turn: term.turn }) + "\n",
        stderr: "",
        deliveredMsg,
      };
    }

    if (cmd === "interrupt") {
      const target = parseSingleTargetArgs(rest, envTerminalId);
      if (!target) {
        return { code: 1, stdout: "", stderr: JSON.stringify({ error: "missing_terminal" }) + "\n" };
      }
      const term = terminals.get(target);
      if (!term || !term.live) {
        return { code: 1, stdout: "", stderr: JSON.stringify({ error: "target_unavailable", address: target }) + "\n" };
      }
      if (term.interruptOutcome === "failed") {
        return { code: 1, stdout: "", stderr: JSON.stringify({ error: "interrupt_failed" }) + "\n" };
      }
      if (term.interruptOutcome === "stopped") {
        if (term.status !== null) {
          term.status = { ...term.status, state: term.stateAfterInterrupt };
        }
        return { code: 0, stdout: JSON.stringify({ outcome: "stopped", key: "esc" }) + "\n", stderr: "" };
      }
      if (term.interruptOutcome === "exited") {
        term.live = false;
        term.nonLiveState = "exited";
      }
      return { code: 0, stdout: JSON.stringify({ outcome: term.interruptOutcome, key: "esc" }) + "\n", stderr: "" };
    }

    if (cmd === "machine" && rest[0] === "ls") {
      if (failMachineLs) {
        return { code: 1, stdout: "", stderr: JSON.stringify({ error: "machine_ls_failed" }) + "\n" };
      }
      return {
        code: 0,
        stdout: JSON.stringify({ machines: machines.map(serializeMachineWire) }) + "\n",
        stderr: "",
      };
    }

    if (cmd === "ls") {
      return {
        code: 0,
        stdout: JSON.stringify({
          terminals: [...terminals.values()].map(serializeTerminalWire),
          hidden_finished: 0,
          machines: machines.map(serializeMachineWire),
        }) + "\n",
        stderr: "",
      };
    }

    return { code: 2, stdout: "", stderr: `unsupported virtual hc args: ${args.join(" ")}\n` };
  };

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    if (req.method !== "POST" || req.url !== "/hc") {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not_found" }));
      return;
    }
    void readJsonBody(req)
      .then((body) => {
        const args = object(body) && Array.isArray(body.args)
          ? body.args.map((a) => String(a))
          : [];
        const envTerminalId = object(body) && object(body.env) && typeof body.env.HC_TERMINAL_ID === "string"
          ? body.env.HC_TERMINAL_ID
          : null;
        const result = handleHcCommand(args, envTerminalId);
        recordInvocation(args, result.code);
        if (result.deliveredMsg) {
          for (const listener of [...sendWaiters]) listener(result.deliveredMsg);
        }
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ code: result.code, stdout: result.stdout, stderr: result.stderr }));
      })
      .catch((error: unknown) => {
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ code: 1, stdout: "", stderr: error instanceof Error ? error.message : String(error) }));
      });
  });

  await new Promise<void>((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", () => resolveListen());
  });

  const addr = server.address();
  if (!addr || typeof addr === "string") {
    server.close();
    throw new Error("Virtual Herdr controller failed to bind to loopback TCP port");
  }
  const port = addr.port;
  const url = `http://127.0.0.1:${port}`;

  // Place client script outside hc-bin so hc-bin exposes only the executable `hc` shim.
  const clientScriptPath = join(rootDir, "hc-client.mjs");
  const clientScript = `import { request } from "node:http";
const payload = JSON.stringify({
  args: process.argv.slice(2),
  env: { HC_TERMINAL_ID: process.env.HC_TERMINAL_ID ?? null },
});
const req = request(
  {
    hostname: "127.0.0.1",
    port: ${port},
    path: "/hc",
    method: "POST",
    headers: {
      "content-type": "application/json",
      "content-length": Buffer.byteLength(payload),
    },
  },
  (res) => {
    const chunks = [];
    res.on("data", (chunk) => chunks.push(chunk));
    res.on("end", () => {
      try {
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
        if (body.stdout) process.stdout.write(body.stdout);
        if (body.stderr) process.stderr.write(body.stderr);
        process.exitCode = typeof body.code === "number" ? body.code : 1;
      } catch (err) {
        process.stderr.write("virtual hc parse error: " + String(err) + "\\n");
        process.exitCode = 1;
      }
    });
  },
);
req.on("error", (err) => {
  process.stderr.write("virtual hc controller error: " + err.message + "\\n");
  process.exitCode = 1;
});
req.end(payload);
`;
  writeFileSync(clientScriptPath, clientScript, { mode: 0o644 });

  const hcPath = join(binDir, "hc");
  writeFileSync(
    hcPath,
    `#!/bin/sh\nexec ${shellQuote(process.execPath)} ${shellQuote(clientScriptPath)} "$@"\n`,
    { mode: 0o755 },
  );
  chmodSync(hcPath, 0o755);

  let closed = false;
  return {
    url,
    port,
    binDir,
    hcPath,
    get invocations() {
      return invocations;
    },

    addTerminal(input) {
      const isNonLiveState = input.state === "exited" || input.state === "finished";
      const live = input.live !== undefined ? input.live : !isNonLiveState;
      const nonLiveState = isNonLiveState ? input.state! : "finished";
      const pid = input.pid !== undefined ? input.pid : ++nextPid;
      const created_ms = input.created_ms !== undefined ? input.created_ms : (nextCreatedMs += 1_000);

      let status: Record<string, unknown> | null;
      if (input.status === null) {
        status = null;
      } else if (input.status !== undefined) {
        status = { ...input.status };
      } else if (input.app === null || (input.app === undefined && isNonLiveState)) {
        status = null;
      } else if (input.app === undefined && input.state === undefined) {
        status = null;
      } else {
        status = {
          ...(input.app !== undefined ? { app: input.app } : {}),
          state: isNonLiveState ? "idle" : (input.state ?? "idle"),
        };
      }

      const term: InternalTerminal = {
        address: input.address,
        ...(input.reportedAddress ? { reportedAddress: input.reportedAddress } : {}),
        live,
        nonLiveState,
        pid,
        created_ms,
        status,
        nextSendExitCodes: normalizeExitCodes(input.nextSendExitCode),
        interruptOutcome: input.interruptOutcome ?? "stopped",
        stateAfterInterrupt: input.stateAfterInterrupt ?? "idle",
        getExitCode: input.getExitCode ?? null,
        turn: 0,
      };
      terminals.set(input.address, term);
      return snapshotTerminal(term);
    },

    setTerminal(address, patch) {
      const term = terminals.get(address);
      if (!term) throw new Error(`Unknown virtual Herdr terminal '${address}'`);

      if (patch.live !== undefined) {
        term.live = patch.live;
        if (!patch.live && term.nonLiveState === "live") term.nonLiveState = "finished";
      }
      if (patch.state !== undefined) {
        if (patch.state === "exited" || patch.state === "finished") {
          term.live = false;
          term.nonLiveState = patch.state;
        } else {
          if (patch.live === undefined) term.live = true;
          term.status = { ...(term.status ?? {}), state: patch.state };
        }
      }
      if (patch.status !== undefined) {
        term.status = patch.status === null ? null : { ...patch.status };
      }
      if (patch.app !== undefined) {
        if (patch.app === null) {
          if (term.status) {
            const next = { ...term.status };
            delete next.app;
            term.status = next;
          }
        } else {
          term.status = { ...(term.status ?? { state: "idle" }), app: patch.app };
        }
      }
      if (patch.pid !== undefined) term.pid = patch.pid;
      if (patch.created_ms !== undefined) term.created_ms = patch.created_ms;
      if (patch.reportedAddress !== undefined) {
        term.reportedAddress = patch.reportedAddress ?? undefined;
      }
      if (patch.nextSendExitCode !== undefined) {
        term.nextSendExitCodes = normalizeExitCodes(patch.nextSendExitCode);
      }
      if (patch.interruptOutcome !== undefined) term.interruptOutcome = patch.interruptOutcome;
      if (patch.stateAfterInterrupt !== undefined) term.stateAfterInterrupt = patch.stateAfterInterrupt;
      if (patch.getExitCode !== undefined) term.getExitCode = patch.getExitCode;

      return snapshotTerminal(term);
    },

    getTerminal(address) {
      const term = terminals.get(address);
      return term ? snapshotTerminal(term) : undefined;
    },

    addMachine(machine) {
      const idx = machines.findIndex((m) => m.name === machine.name);
      if (idx >= 0) machines[idx] = machine;
      else machines.push(machine);
    },

    setMachineLsFailure(fail) {
      failMachineLs = fail;
    },

    sentMessages(address) {
      return [...(sentByAddress.get(address) ?? [])];
    },

    waitForSend(address, predicate, timeoutMs = 6_000) {
      const matches = (msg: VirtualSentMessage) => msg.address === address && (!predicate || predicate(msg));
      const existing = (sentByAddress.get(address) ?? []).find(matches);
      if (existing) return Promise.resolve(existing);

      return new Promise<VirtualSentMessage>((resolvePromise, rejectPromise) => {
        const timer = setTimeout(() => {
          sendWaiters.delete(onSend);
          const seen = (sentByAddress.get(address) ?? []).map((m) => m.text);
          rejectPromise(
            new Error(`Timed out after ${timeoutMs}ms waiting for hc send to ${address} (saw ${seen.length} sends)`),
          );
        }, timeoutMs).unref();
        const onSend = (msg: VirtualSentMessage) => {
          if (matches(msg)) {
            clearTimeout(timer);
            sendWaiters.delete(onSend);
            resolvePromise(msg);
          }
        };
        sendWaiters.add(onSend);
      });
    },

    waitForInvocation(predicate, timeoutMs = 6_000) {
      const existing = invocations.find(predicate);
      if (existing) return Promise.resolve(existing);

      return new Promise<VirtualHerdrInvocation>((resolvePromise, rejectPromise) => {
        const timer = setTimeout(() => {
          invocationWaiters.delete(onInv);
          const summary = invocations.slice(-10).map((i) => i.args.join(" ")).join(" | ");
          rejectPromise(
            new Error(`Timed out after ${timeoutMs}ms waiting for hc invocation (recent: ${summary || "none"})`),
          );
        }, timeoutMs).unref();
        const onInv = (inv: VirtualHerdrInvocation) => {
          if (predicate(inv)) {
            clearTimeout(timer);
            invocationWaiters.delete(onInv);
            resolvePromise(inv);
          }
        };
        invocationWaiters.add(onInv);
      });
    },

    envWithVirtualHc(extraEnv: NodeJS.ProcessEnv = {}) {
      const basePath = extraEnv.PATH ?? process.env.PATH ?? "/usr/bin:/bin";
      const env: NodeJS.ProcessEnv = {
        ...process.env,
        PATH: `${binDir}:${basePath}`,
      };
      delete env.HC_TERMINAL_ID;
      delete env.ANTIGRAVITY_SOURCE_METADATA;
      delete env.CLAUDE_SESSION_ID;
      delete env.CODEX_THREAD_ID;
      delete env.HYPHAE_SOCKET;
      delete env.AGENTS_MESH_SOCKET;
      return { ...env, ...extraEnv, PATH: `${binDir}:${basePath}` };
    },

    async close() {
      if (closed) return;
      closed = true;
      invocationWaiters.clear();
      sendWaiters.clear();
      server.closeAllConnections();
      await new Promise<void>((resolveClose) => server.close(() => resolveClose()));
    },
  };
}

export interface IsolatedDaemonOptions {
  readonly rootDir: string;
  readonly name: string;
  readonly connectorId: string;
  readonly routerUrl: string;
  readonly token: string;
  readonly env: NodeJS.ProcessEnv;
  readonly auditPath?: string;
}

export interface IsolatedDaemonHandle {
  readonly configDir: string;
  readonly configPath: string;
  readonly socketPath: string;
  readonly homeDir: string;
  readonly proc: ChildProcess;
  readonly stdout: string[];
  readonly stderr: string[];
  openMcp(extraArgs?: string[], extraEnv?: NodeJS.ProcessEnv): Promise<McpClient>;
  stop(): Promise<void>;
}

export function readAuditEvents(auditPath: string): Array<Record<string, unknown>> {
  if (!existsSync(auditPath)) return [];
  const raw = readFileSync(auditPath, "utf8");
  const out: Array<Record<string, unknown>> = [];
  for (const line of raw.split("\n")) {
    if (!line.trim()) continue;
    try {
      const parsed: unknown = JSON.parse(line);
      if (object(parsed)) out.push(parsed);
    } catch {}
  }
  return out;
}

/**
 * Spawns a real `node src/cli.ts daemon <configPath>` subprocess with strictly isolated
 * `HOME`, `XDG_CONFIG_HOME`, `connector.json`, `0600` token file, and caller-provided `PATH`.
 */
export async function startIsolatedDaemonSubprocess(options: IsolatedDaemonOptions): Promise<IsolatedDaemonHandle> {
  const configDir = join(options.rootDir, options.name);
  const stateDir = join(configDir, "s");
  const homeDir = join(configDir, "h");
  const xdgConfig = join(homeDir, ".config");
  mkdirSync(stateDir, { recursive: true, mode: 0o700 });
  mkdirSync(xdgConfig, { recursive: true, mode: 0o700 });

  const tokenFile = join(configDir, "primary.token");
  writeFileSync(tokenFile, `${options.token}\n`, { mode: 0o600 });
  chmodSync(tokenFile, 0o600);

  const configPath = join(configDir, "connector.json");
  writeFileSync(
    configPath,
    JSON.stringify(
      {
        connectorId: options.connectorId,
        stateDir: "s",
        routers: [{ name: "primary", url: options.routerUrl, tokenFile }],
      },
      null,
      2,
    ) + "\n",
    { mode: 0o600 },
  );
  chmodSync(configPath, 0o600);

  const socketPath = join(stateDir, "connector.sock");
  const cliScript = join(process.cwd(), "src", "cli.ts");
  const daemonEnv: NodeJS.ProcessEnv = {
    ...options.env,
    HOME: homeDir,
    XDG_CONFIG_HOME: xdgConfig,
    XDG_DATA_HOME: join(homeDir, ".local", "share"),
    XDG_CACHE_HOME: join(homeDir, ".cache"),
    XDG_STATE_HOME: join(homeDir, ".local", "state"),
  };
  delete daemonEnv.HC_TERMINAL_ID;

  const proc = spawn(process.execPath, [cliScript, "daemon", configPath], {
    env: daemonEnv,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const stdout: string[] = [];
  const stderr: string[] = [];
  proc.stdout.on("data", (d: Buffer) => stdout.push(d.toString("utf8")));
  proc.stderr.on("data", (d: Buffer) => stderr.push(d.toString("utf8")));

  const mcpClients = new Set<McpClient>();
  let stopped = false;

  const stop = async (): Promise<void> => {
    if (stopped) return;
    stopped = true;
    for (const client of [...mcpClients]) {
      await client.close().catch(() => {});
    }
    mcpClients.clear();
    if (proc.exitCode === null) {
      await new Promise<void>((resolveExit) => {
        const timer = setTimeout(() => {
          if (proc.exitCode === null) {
            try { proc.kill("SIGKILL"); } catch {}
          }
          resolveExit();
        }, 2_500).unref();
        proc.once("exit", () => {
          clearTimeout(timer);
          resolveExit();
        });
        try { proc.kill("SIGTERM"); } catch {
          clearTimeout(timer);
          resolveExit();
        }
      });
    }
  };

  try {
    await waitFor(
      async () => {
        if (proc.exitCode !== null) {
          throw new Error(`Daemon exited early with code ${proc.exitCode}: ${stderr.join("")}`);
        }
        const status = await daemonRpc(socketPath, { type: "daemon.status" });
        if (!status.ok) return false;
        if (options.auditPath) {
          const events = readAuditEvents(options.auditPath);
          return events.some((ev) => ev.event === "connector.online" && ev.connector === options.connectorId);
        }
        return true;
      },
      { timeoutMs: 8_000, intervalMs: 50, label: `isolated daemon ${options.connectorId} ready` },
    );
  } catch (error) {
    await stop();
    throw error;
  }

  return {
    configDir,
    configPath,
    socketPath,
    homeDir,
    proc,
    stdout,
    stderr,
    async openMcp(extraArgs = [], extraEnv = {}) {
      const mcpEnv: NodeJS.ProcessEnv = {
        ...daemonEnv,
        ...extraEnv,
      };
      if (!Object.prototype.hasOwnProperty.call(extraEnv, "HC_TERMINAL_ID")) {
        delete mcpEnv.HC_TERMINAL_ID;
      }
      const client = new McpClient(socketPath, extraArgs, mcpEnv);
      mcpClients.add(client);
      await client.initialize();
      return client;
    },
    stop,
  };
}
