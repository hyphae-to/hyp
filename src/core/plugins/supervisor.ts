// Runs one plugin process (SPEC.md sections 13.3 and 13.6): spawns it with the channel on fd 3,
// answers its event lines, logs its stdout and stderr, and restarts it with backoff when it exits
// or closes fd 3.
import { randomUUID } from "node:crypto";
import { spawn, type ChildProcess } from "node:child_process";
import { Duplex } from "node:stream";
import type { PluginConfig } from "./types.ts";
import { errorMessage, log } from "../log.ts";
import {
  encodeLine,
  LineSplitter,
  lineTooLarge,
  MAX_LINE_BYTES,
  nack,
  parsePluginLine,
  PROTOCOL_VERSION,
  type ConnectorLine,
} from "./protocol.ts";
import type { StoreOutcome } from "./store.ts";

/** Variables passed through from the daemon's environment, when set. */
const PASSED_ENV = ["HOME", "PATH", "LANG", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"] as const;
const MAX_OUTPUT_LINE_BYTES = 2 * 1024;

export interface SupervisorOptions {
  readonly initialBackoffMs?: number;
  readonly maxBackoffMs?: number;
  /** A process that ran this long before exiting restarts after the initial backoff again. */
  readonly resetAfterMs?: number;
  /** Between SIGTERM and SIGKILL. */
  readonly killTimeoutMs?: number;
  /** The daemon's environment, of which only PASSED_ENV is passed on. */
  readonly parentEnv?: NodeJS.ProcessEnv;
}

/** Stores one event line for a target. */
export type StoreEvent = (to: string, event: unknown) => StoreOutcome;

interface Running {
  readonly child: ChildProcess;
  readonly channel: Duplex;
  readonly startedAt: number;
  /** Set once the process is being stopped or killed; later lines are ignored. */
  ending: boolean;
}

export function pluginEnv(plugin: PluginConfig, parentEnv: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const name of PASSED_ENV) {
    const value = parentEnv[name];
    if (value !== undefined) env[name] = value;
  }
  return {
    ...env,
    ...plugin.env,
    T3_MESH_FD: "3",
    T3_MESH_PLUGIN: plugin.name,
    T3_MESH_PROTOCOL: String(PROTOCOL_VERSION),
  };
}

export class PluginProcess {
  readonly #plugin: PluginConfig;
  readonly #store: StoreEvent;
  readonly #initialBackoffMs: number;
  readonly #maxBackoffMs: number;
  readonly #resetAfterMs: number;
  readonly #killTimeoutMs: number;
  readonly #parentEnv: NodeJS.ProcessEnv;
  #backoffMs: number;
  #running: Running | null = null;
  #restartTimer: NodeJS.Timeout | null = null;
  #stopping = false;
  #exited: Promise<void> = Promise.resolve();
  readonly #pendingRequests = new Map<
    string,
    { resolve: (value: { ok: true; result: unknown } | { ok: false; error: string }) => void; timer: NodeJS.Timeout }
  >();

  constructor(plugin: PluginConfig, store: StoreEvent, options: SupervisorOptions = {}) {
    this.#plugin = plugin;
    this.#store = store;
    this.#initialBackoffMs = options.initialBackoffMs ?? 1_000;
    this.#maxBackoffMs = options.maxBackoffMs ?? 60_000;
    this.#resetAfterMs = options.resetAfterMs ?? 60_000;
    this.#killTimeoutMs = options.killTimeoutMs ?? 10_000;
    this.#parentEnv = options.parentEnv ?? process.env;
    this.#backoffMs = this.#initialBackoffMs;
  }

  get name(): string {
    return this.#plugin.name;
  }

  /** Whether a process is up and its channel open. */
  get running(): boolean {
    return this.#running !== null && !this.#running.ending;
  }

  start(): void {
    if (this.#running !== null || this.#stopping) return;
    let child: ChildProcess;
    try {
      child = spawn(this.#plugin.exec, [...this.#plugin.args], {
        cwd: this.#plugin.cwd,
        env: pluginEnv(this.#plugin, this.#parentEnv),
        stdio: ["ignore", "pipe", "pipe", "pipe"],
      });
    } catch (error) {
      // E.g. ENOTDIR for a cwd that is a file: thrown at once, with no process to wait for.
      const restartInMs = this.#nextBackoff(0);
      log("error", "plugin.exited", { plugin: this.#plugin.name, uptimeMs: 0, error: errorMessage(error), restartInMs });
      this.#scheduleRestart(restartInMs);
      return;
    }
    const channel = child.stdio[3];
    if (!(channel instanceof Duplex)) {
      child.kill("SIGKILL");
      const restartInMs = this.#nextBackoff(0);
      log("error", "plugin.exited", { plugin: this.#plugin.name, uptimeMs: 0, error: "fd 3 is not a pipe", restartInMs });
      this.#scheduleRestart(restartInMs);
      return;
    }
    const running: Running = { child, channel, startedAt: Date.now(), ending: false };
    this.#running = running;
    let resolveExited: () => void = () => undefined;
    this.#exited = new Promise<void>((resolve) => {
      resolveExited = resolve;
    });

    let gone = false;
    const onGone = (fields: Readonly<Record<string, unknown>>) => {
      if (gone) return;
      gone = true;
      running.ending = true;
      if (this.#running === running) this.#running = null;
      channel.destroy();
      for (const [reqId, pending] of this.#pendingRequests) {
        clearTimeout(pending.timer);
        pending.resolve({ ok: false, error: "plugin_exited" });
        this.#pendingRequests.delete(reqId);
      }
      const uptimeMs = Date.now() - running.startedAt;
      const restartInMs = this.#stopping ? null : this.#nextBackoff(uptimeMs);
      log(this.#stopping ? "info" : "warn", "plugin.exited", { plugin: this.#plugin.name, pid: child.pid, uptimeMs, ...fields, restartInMs });
      if (restartInMs !== null) this.#scheduleRestart(restartInMs);
      resolveExited();
    };
    child.once("exit", (code, signal) => onGone({ code, signal }));
    child.once("error", (error) => onGone({ error: errorMessage(error) }));

    this.#pipeOutput(running, "stdout");
    this.#pipeOutput(running, "stderr");
    this.#readChannel(running);
    log("info", "plugin.started", { plugin: this.#plugin.name, pid: child.pid });
    this.send({
      type: "hello",
      protocol: PROTOCOL_VERSION,
      plugin: this.#plugin.name,
      targets: this.#plugin.targets.map((target) => target.name),
    });
  }

  /** Writes one line to the plugin; false when it is not running. */
  send(line: ConnectorLine): boolean {
    const running = this.#running;
    if (running === null || running.ending || !running.channel.writable) return false;
    running.channel.write(encodeLine(line));
    return true;
  }

  /** Sends a connector -> plugin request over fd 3 and awaits the matching `response` line. */
  request(
    method: "post",
    target: string,
    params: Readonly<Record<string, unknown>>,
    timeoutMs = 15_000,
  ): Promise<{ ok: true; result: unknown } | { ok: false; error: string }> {
    const id = randomUUID();
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.#pendingRequests.delete(id);
        resolve({ ok: false, error: "plugin_request_timeout" });
      }, timeoutMs);
      timer.unref();
      this.#pendingRequests.set(id, { resolve, timer });
      const sent = this.send({ type: "request", id, method, target, params });
      if (!sent) {
        clearTimeout(timer);
        this.#pendingRequests.delete(id);
        resolve({ ok: false, error: "plugin_offline" });
      }
    });
  }

  /** SIGTERM, then SIGKILL after the kill timeout; no restart. Resolves when the process is gone. */
  async stop(): Promise<void> {
    this.#stopping = true;
    if (this.#restartTimer !== null) clearTimeout(this.#restartTimer);
    this.#restartTimer = null;
    const running = this.#running;
    if (running !== null) this.#terminate(running);
    await this.#exited;
  }

  #terminate(running: Running): void {
    running.ending = true;
    running.child.kill("SIGTERM");
    const timer = setTimeout(() => running.child.kill("SIGKILL"), this.#killTimeoutMs);
    timer.unref();
    running.child.once("exit", () => clearTimeout(timer));
  }

  /** Delay before the next start: back to the initial one after a long enough run, doubling otherwise. */
  #nextBackoff(uptimeMs: number): number {
    if (uptimeMs >= this.#resetAfterMs) this.#backoffMs = this.#initialBackoffMs;
    const delay = this.#backoffMs;
    this.#backoffMs = Math.min(this.#backoffMs * 2, this.#maxBackoffMs);
    return delay;
  }

  #scheduleRestart(delayMs: number): void {
    if (this.#stopping) return;
    this.#restartTimer = setTimeout(() => {
      this.#restartTimer = null;
      this.start();
    }, delayMs);
  }

  #pipeOutput(running: Running, stream: "stdout" | "stderr"): void {
    const source = running.child[stream];
    if (source === null) return;
    const splitter = new LineSplitter(MAX_OUTPUT_LINE_BYTES);
    const emit = (line: string, truncated: boolean) =>
      log("info", `plugin.${stream}`, { plugin: this.#plugin.name, line, ...(truncated ? { truncated } : {}) });
    source.on("data", (chunk: Buffer) => splitter.push(chunk, emit));
    source.on("end", () => splitter.flush(emit));
  }

  #readChannel(running: Running): void {
    // An overlong line is discarded unbuffered up to its newline and answered with a nack.
    const splitter = new LineSplitter(MAX_LINE_BYTES, false);
    running.channel.on("data", (chunk: Buffer) => {
      if (running.ending) return;
      splitter.push(chunk, (line, truncated) => {
        if (running.ending) return;
        if (!truncated) {
          this.#handleLine(line);
          return;
        }
        log("warn", "plugin.event_rejected", { plugin: this.#plugin.name, error: "too_large", lineLimit: MAX_LINE_BYTES });
        this.send(lineTooLarge());
      });
    });
    const closed = (reason: string) => {
      if (running.ending) return;
      log("warn", "plugin.channel_closed", { plugin: this.#plugin.name, pid: running.child.pid, reason });
      this.#terminate(running);
    };
    running.channel.on("end", () => closed("end"));
    running.channel.on("close", () => closed("close"));
    running.channel.on("error", (error) => closed(errorMessage(error)));
  }

  #handleLine(text: string): void {
    if (text.trim() === "") return;
    const line = parsePluginLine(text);
    if (line.kind === "response") {
      const pending = this.#pendingRequests.get(line.id);
      if (pending) {
        clearTimeout(pending.timer);
        this.#pendingRequests.delete(line.id);
        pending.resolve(line.ok ? { ok: true, result: line.result ?? null } : { ok: false, error: line.error ?? "plugin_request_failed" });
      }
      return;
    }
    if (line.kind === "nack") {
      log("warn", "plugin.event_rejected", { plugin: this.#plugin.name, error: line.nack.error });
      this.send(line.nack);
      return;
    }
    const stored = this.#store(line.to, line.event);
    if (stored.ok && line.id !== null && line.source !== null) {
      log("info", "plugin.event_stored", {
        plugin: this.#plugin.name,
        target: line.to,
        id: line.id,
        source: line.source,
        status: stored.status,
      });
      this.send({ type: "ack", id: line.id, source: line.source, status: stored.status });
      return;
    }
    const error = stored.ok ? "unavailable" : stored.error;
    log("warn", "plugin.event_rejected", { plugin: this.#plugin.name, error });
    this.send(
      stored.ok
        ? nack(line.id, line.source, "unavailable", "internal: stored an event without id or source")
        : nack(line.id, line.source, stored.error, stored.message),
    );
  }
}
