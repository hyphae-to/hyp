import { spawn, type ChildProcess } from "node:child_process";
import type { Duplex } from "node:stream";
import { createInterface } from "node:readline";
import type { RouterStreamConfig } from "./config.ts";
import { object } from "./protocol.ts";
import { serveReceiver, type RunningReceiver } from "../packages/t3-mesh/src/github/receiver.ts";
import { log } from "../packages/t3-mesh/src/log.ts";
import type { RouterCore } from "../packages/t3-mesh/src/router/core.ts";
import type { Publisher } from "../packages/t3-mesh/src/router/events.ts";

const MAX_FRAME_BYTES = 64 * 1024;
const MAX_BACKOFF_MS = 30_000;
const BASE_BACKOFF_MS = 1_000;
const STABLE_UPTIME_MS = 60_000;
/** Only safe baseline vars pass from daemon into stream children (never inherit host API keys or tokens). */
const PASSED_ENV = ["HOME", "PATH", "LANG", "TMPDIR", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"] as const;

function buildIsolatedStreamEnv(cfg: RouterStreamConfig): NodeJS.ProcessEnv {
  const base: NodeJS.ProcessEnv = {};
  for (const key of PASSED_ENV) {
    const val = process.env[key];
    if (val !== undefined) base[key] = val;
  }
  return {
    ...base,
    ...cfg.env,
    T3_MESH_FD: "3",
    AGENTS_MESH_FD: "3",
    T3_MESH_PLUGIN: cfg.name,
    AGENTS_MESH_STREAM: cfg.name,
    AGENTS_MESH_TOPIC: cfg.topic,
    T3_MESH_PROTOCOL: "1",
  };
}

export function streamPublisherId(streamName: string): string {
  return `stream-${streamName}`;
}

/**
 * Builds the `topic -> allowed publisher IDs` map required by `RouterCore` so every configured
 * router data stream is authorized to publish to its topic automatically.
 */
export function buildStreamTopicMap(
  streams: readonly RouterStreamConfig[],
  existing?: ReadonlyMap<string, readonly string[]>,
): Map<string, string[]> {
  const map = new Map<string, string[]>();
  if (existing) {
    for (const [topic, pubs] of existing.entries()) map.set(topic, [...pubs]);
  }
  for (const stream of streams) {
    const pubId = streamPublisherId(stream.name);
    const list = map.get(stream.topic) ?? [];
    if (!list.includes(pubId)) list.push(pubId);
    map.set(stream.topic, list);
  }
  return map;
}

interface SupervisedStream {
  readonly config: RouterStreamConfig;
  child: ChildProcess | null;
  receiver: RunningReceiver | null;
  restartTimer: NodeJS.Timeout | null;
  backoffMs: number;
}

/**
 * Supervises router-level data source plugins ("streams") feeding CloudEvents directly into
 * `RouterCore.events.publish(...)` so any enrolled agent across any harness or machine can
 * subscribe with CloudEvents filters (`mesh_subscribe`).
 *
 * Supports:
 * - `builtin: "github-webhook"` — runs t3-mesh's hardened GitHub HMAC webhook receiver
 * - `builtin: "webhook-stream"` — runs the built-in signed HTTP webhook source over fd 3
 * - custom `exec` + `args` — any executable speaking the standard fd-3 NDJSON protocol v1
 */
export class RouterStreamHost {
  readonly #core: RouterCore;
  readonly #routerUrl: string;
  readonly #streams: SupervisedStream[];
  #stopped = false;

  constructor(core: RouterCore, routerUrl: string, streams: readonly RouterStreamConfig[]) {
    this.#core = core;
    this.#routerUrl = routerUrl;
    this.#streams = streams.map((config) => ({
      config,
      child: null,
      receiver: null,
      restartTimer: null,
      backoffMs: BASE_BACKOFF_MS,
    }));
  }

  get names(): string[] {
    return this.#streams.map((s) => s.config.name);
  }

  get topics(): string[] {
    return [...new Set(this.#streams.map((s) => s.config.topic))];
  }

  async start(): Promise<void> {
    for (const entry of this.#streams) {
      if (entry.config.builtin === "github-webhook") {
        await this.#startGithubReceiver(entry);
      } else {
        this.#core.events.addPublisher(streamPublisherId(entry.config.name), [entry.config.topic]);
        this.#spawnFd3Stream(entry);
      }
    }
  }

  async stop(): Promise<void> {
    this.#stopped = true;
    const waits: Promise<void>[] = [];
    for (const entry of this.#streams) {
      if (entry.restartTimer) {
        clearTimeout(entry.restartTimer);
        entry.restartTimer = null;
      }
      if (entry.receiver) {
        const rec = entry.receiver;
        entry.receiver = null;
        waits.push(rec.close().catch(() => {}));
      }
      const child = entry.child;
      if (child) {
        entry.child = null;
        waits.push(
          new Promise<void>((resolve) => {
            const killTimer = setTimeout(() => {
              try { child.kill("SIGKILL"); } catch {}
              resolve();
            }, 3_000).unref();
            child.once("exit", () => {
              clearTimeout(killTimer);
              resolve();
            });
            try { child.kill("SIGTERM"); } catch { resolve(); }
          }),
        );
      }
    }
    await Promise.all(waits);
  }

  async #startGithubReceiver(entry: SupervisedStream): Promise<void> {
    const cfg = entry.config;
    const host = cfg.env.GITHUB_WEBHOOK_HOST || "127.0.0.1";
    const port = Number(cfg.env.GITHUB_WEBHOOK_PORT ?? "8791");
    const secret = cfg.env.GITHUB_WEBHOOK_SECRET;
    if (!secret) {
      log("error", "stream.error", { stream: cfg.name, message: "Missing GITHUB_WEBHOOK_SECRET" });
      return;
    }
    const pubId = streamPublisherId(cfg.name);
    const token = this.#core.events.addPublisher(pubId, [cfg.topic]);
    const receiver = await serveReceiver({
      host,
      port,
      routerUrl: this.#routerUrl,
      topic: cfg.topic,
      secret,
      token,
    });
    entry.receiver = receiver;
    log("info", "stream.started", { stream: cfg.name, kind: "github-webhook", topic: cfg.topic, url: receiver.url });
  }

  #spawnFd3Stream(entry: SupervisedStream): void {
    if (this.#stopped) return;
    const cfg = entry.config;
    if (!cfg.exec) return;
    const startedAt = Date.now();
    const publisher: Publisher = {
      id: streamPublisherId(cfg.name),
      topics: new Set([cfg.topic]),
    };

    const child = spawn(cfg.exec, [...cfg.args], {
      cwd: cfg.cwd,
      env: buildIsolatedStreamEnv(cfg),
      stdio: ["ignore", "ignore", "pipe", "pipe"],
    });
    entry.child = child;
    log("info", "stream.started", { stream: cfg.name, topic: cfg.topic, pid: child.pid ?? null });

    if (child.stderr) {
      const errRl = createInterface({ input: child.stderr, crlfDelay: Infinity });
      errRl.on("error", () => {});
      errRl.on("line", (line) => {
        if (line.trim()) log("info", "stream.stderr", { stream: cfg.name, line });
      });
    }

    const pipe = child.stdio[3] as Duplex | null;
    if (pipe) {
      const sendFrame = (frame: Record<string, unknown>) => {
        if (!pipe.destroyed && pipe.writable) pipe.write(JSON.stringify(frame) + "\n");
      };
      sendFrame({
        type: "hello",
        protocol: 1,
        plugin: cfg.name,
        role: "router-stream",
        topic: cfg.topic,
        targets: [cfg.topic],
      });

      const rl = createInterface({ input: pipe, crlfDelay: Infinity });
      rl.on("error", () => {});
      rl.on("line", (line) => {
        if (Buffer.byteLength(line, "utf8") > MAX_FRAME_BYTES) {
          sendFrame({ type: "nack", id: "", source: "", reason: "too_large", message: "frame exceeds 64 KiB" });
          return;
        }
        let parsed: unknown;
        try { parsed = JSON.parse(line); } catch {
          sendFrame({ type: "nack", id: "", source: "", reason: "invalid", message: "invalid JSON" });
          return;
        }
        if (!object(parsed) || parsed.type !== "event" || !object(parsed.event)) {
          sendFrame({ type: "nack", id: "", source: "", reason: "invalid", message: "expected event frame" });
          return;
        }
        const ev = parsed.event;
        const id = typeof ev.id === "string" ? ev.id : "";
        const source = typeof ev.source === "string" ? ev.source : "";
        const res = this.#core.events.publish(publisher, cfg.topic, ev);
        if (res.ok) {
          log("info", "stream.event_published", { stream: cfg.name, topic: cfg.topic, id, source, matched: res.matched });
          sendFrame({ type: "ack", id, source, status: res.status === "stored" ? "stored" : "duplicate" });
        } else {
          sendFrame({ type: "nack", id, source, reason: res.error, message: res.message });
        }
      });
    }

    child.once("exit", (code, signal) => {
      if (entry.child === child) entry.child = null;
      const uptimeMs = Date.now() - startedAt;
      if (uptimeMs >= STABLE_UPTIME_MS) entry.backoffMs = BASE_BACKOFF_MS;
      const restartInMs = this.#stopped ? null : entry.backoffMs;
      log("info", "stream.exited", { stream: cfg.name, pid: child.pid ?? null, uptimeMs, code, signal, restartInMs });
      if (!this.#stopped) {
        entry.restartTimer = setTimeout(() => {
          entry.restartTimer = null;
          this.#spawnFd3Stream(entry);
        }, entry.backoffMs).unref();
        entry.backoffMs = Math.min(entry.backoffMs * 2, MAX_BACKOFF_MS);
      }
    });
  }
}
