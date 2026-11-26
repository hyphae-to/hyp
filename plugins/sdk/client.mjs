import { createReadStream, createWriteStream } from "node:fs";
import net from "node:net";
import { createInterface } from "node:readline";

const DEFAULT_ACK_TIMEOUT_MS = 60_000;
const MAX_ECHO_ID_CHARS = 256;

function correlationIdForEvent(event) {
  if (typeof event?.id !== "string" || event.id.length === 0) return null;
  return Array.from(event.id).slice(0, MAX_ECHO_ID_CHARS).join("");
}

function parseLoopbackAddr(raw) {
  const trimmed = String(raw ?? "").trim();
  let host = "";
  let portStr = "";
  if (trimmed.startsWith("[")) {
    const closeIdx = trimmed.indexOf("]");
    if (closeIdx < 0 || trimmed[closeIdx + 1] !== ":") {
      throw new Error(`Invalid HYPHAE_PLUGIN_ADDR: ${trimmed}`);
    }
    host = trimmed.slice(1, closeIdx);
    portStr = trimmed.slice(closeIdx + 2);
  } else {
    const colonIdx = trimmed.lastIndexOf(":");
    if (colonIdx <= 0 || trimmed.indexOf(":") !== colonIdx) {
      throw new Error(`Invalid HYPHAE_PLUGIN_ADDR: ${trimmed}`);
    }
    host = trimmed.slice(0, colonIdx);
    portStr = trimmed.slice(colonIdx + 1);
  }
  const normalizedHost = host.trim().toLowerCase();
  if (normalizedHost !== "127.0.0.1" && normalizedHost !== "::1" && normalizedHost !== "localhost") {
    throw new Error(`Refusing non-loopback HYPHAE_PLUGIN_ADDR host '${host}'`);
  }
  if (!/^\d+$/.test(portStr)) {
    throw new Error(`Invalid HYPHAE_PLUGIN_ADDR port: ${portStr}`);
  }
  const port = Number(portStr);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`Invalid HYPHAE_PLUGIN_ADDR port: ${portStr}`);
  }
  return { host: normalizedHost, port };
}

/**
 * Minimal Node 24 client for the Hyphae local plugin channel
 * (Unix fd 3 or authenticated loopback TCP via HYPHAE_PLUGIN_ADDR, protocol v1).
 */
export class MeshPluginClient {
  plugin;
  targets;
  #out;
  #input;
  #rl;
  #pending = new Map();
  #pendingNoId = [];
  #closed = false;
  #fatal = false;
  #fatalHandler = null;
  #onPost;
  #onWake;
  #onError;

  constructor({
    fd,
    onStatus,
    onDeliveryFailed,
    onPost,
    onWake,
    onError,
    handleFatalErrors = true,
  } = {}) {
    this.plugin = process.env.HYPHAE_PLUGIN ?? process.env.AGENTS_MESH_PLUGIN ?? process.env.T3_MESH_PLUGIN ?? "plugin";
    this.#onPost = onPost;
    this.#onWake = onWake;
    this.#onError = onError;

    const pluginAddr = fd === undefined ? process.env.HYPHAE_PLUGIN_ADDR?.trim() : "";
    let input;
    let channelSock = null;
    let tcpToken = "";
    if (pluginAddr) {
      const { host, port } = parseLoopbackAddr(pluginAddr);
      const token = process.env.HYPHAE_PLUGIN_TOKEN ?? "";
      delete process.env.HYPHAE_PLUGIN_TOKEN;
      if (!token) {
        throw new Error("HYPHAE_PLUGIN_TOKEN is required when HYPHAE_PLUGIN_ADDR is set");
      }
      tcpToken = token;
      channelSock = net.createConnection({ host, port });
      channelSock.setNoDelay(true);
      channelSock.write(JSON.stringify({ type: "auth", token }) + "\n");
      this.#out = channelSock;
      input = channelSock;
    } else {
      const resolvedFd = fd ?? Number(process.env.HYPHAE_FD ?? process.env.AGENTS_MESH_FD ?? process.env.T3_MESH_FD ?? 3);
      // Prefer a non-blocking net.Socket over fd 3 (socketpair / pipe) so libuv uses
      // epoll/kqueue rather than parking a worker thread in a blocking fs.read() that can
      // wedge process exit after post-hello errors. Fall back to fs streams only for
      // non-socket/pipe file descriptors (e.g., regular files in synthetic tests).
      try {
        channelSock = new net.Socket({ fd: resolvedFd, readable: true, writable: true });
        this.#out = channelSock;
        input = channelSock;
      } catch {
        this.#out = createWriteStream("", { fd: resolvedFd, autoClose: false });
        input = createReadStream("", { fd: resolvedFd, autoClose: false });
        this.#out.on("error", () => {});
        input.on("error", () => {});
      }
    }

    this.#input = input;
    const rl = createInterface({ input });
    this.#rl = rl;
    rl.on("error", () => {});

    // Once the plugin channel is open, a ref'd reader keeps a crashed Node process alive
    // instead of returning control to SubprocessSupervisor's restart backoff / CrashLoopBackOff.
    // Log one clean, stack-free line (never leaking stack frames or the TCP handshake token),
    // tear down the channel, and exit non-zero promptly.
    if (handleFatalErrors) {
      this.#fatalHandler = (error) => {
        if (this.#fatal) return;
        this.#fatal = true;
        this.#closed = true;
        try {
          let detail =
            error instanceof Error
              ? error.message
              : error === undefined || error === null
                ? "unknown error"
                : String(error);
          if (tcpToken) {
            detail = detail.replaceAll(tcpToken, "[REDACTED]");
          }
          detail = detail.replace(/[\r\n\x00-\x1f\x7f]+/g, " ").trim().slice(0, 512) || "unknown error";
          console.error(`${this.plugin} plugin fatal: ${detail}`);
        } catch {
          // Best-effort stderr reporting; never block process exit.
        }
        this.#teardownChannel();
        const killFallback = setTimeout(() => {
          try {
            process.kill(process.pid, "SIGKILL");
          } catch {}
        }, 250);
        killFallback.unref?.();
        process.exit(1);
      };
      process.on("uncaughtException", this.#fatalHandler);
      process.on("unhandledRejection", this.#fatalHandler);
    }

    this.ready = new Promise((resolve, reject) => {
      let greeted = false;
      let settled = false;
      const failReady = (err) => {
        if (!settled) {
          settled = true;
          reject(err);
        }
      };
      if (channelSock) {
        channelSock.on("error", (err) => {
          this.#closed = true;
          if (!greeted) {
            failReady(err);
          }
        });
      }
      rl.on("line", (line) => {
        if (!line.trim()) return;
        let msg;
        try { msg = JSON.parse(line); } catch { return; }
        if (!greeted) {
          greeted = true;
          if (msg.type !== "hello" || msg.protocol !== 1 || !Array.isArray(msg.targets)) {
            failReady(new Error(`Unexpected mesh plugin hello: ${line}`));
            return;
          }
          this.targets = msg.targets;
          settled = true;
          resolve(msg);
          return;
        }
        if (msg.type === "ack" || msg.type === "nack") {
          this.#resolveAckOrNack(msg);
        } else if (msg.type === "status") {
          onStatus?.(msg);
        } else if (msg.type === "delivery_failed") {
          onDeliveryFailed?.(msg);
        } else if (msg.type === "request" && typeof msg.id === "string") {
          void this.#handleRequest(msg);
        } else if (msg.method === "system.wake" && msg.id === undefined) {
          this.#handleSystemWake(msg);
        }
      });
      rl.on("close", () => {
        this.#closed = true;
        this.#detachFatalHandlers();
        if (!greeted) failReady(new Error("Mesh plugin channel closed before hello"));
        const closedErr = new Error("Mesh plugin channel closed");
        for (const bucket of this.#pending.values()) {
          while (bucket.length > 0) {
            const entry = bucket.shift();
            clearTimeout(entry.timer);
            entry.reject(closedErr);
          }
        }
        this.#pending.clear();
        while (this.#pendingNoId.length > 0) {
          const entry = this.#pendingNoId.shift();
          clearTimeout(entry.timer);
          entry.reject(closedErr);
        }
        if (greeted && !this.#fatal) {
          process.exit(0);
        }
      });
    });
  }

  #detachFatalHandlers() {
    if (!this.#fatalHandler) return;
    process.off("uncaughtException", this.#fatalHandler);
    process.off("unhandledRejection", this.#fatalHandler);
    this.#fatalHandler = null;
  }

  #teardownChannel() {
    this.#detachFatalHandlers();
    try {
      this.#rl?.close();
    } catch {}
    try {
      this.#input?.destroy();
    } catch {}
    if (this.#out && this.#out !== this.#input) {
      try {
        this.#out.destroy();
      } catch {}
    }
  }

  #resolveAckOrNack(msg) {
    const msgId = typeof msg.id === "string" && msg.id.length > 0 ? msg.id : null;
    if (msgId !== null) {
      const bucket = this.#pending.get(msgId);
      if (bucket && bucket.length > 0) {
        const entry = bucket.shift();
        if (bucket.length === 0) {
          this.#pending.delete(msgId);
        }
        clearTimeout(entry.timer);
        entry.resolve(msg);
      }
      return;
    }
    if (this.#pendingNoId.length > 0) {
      const entry = this.#pendingNoId.shift();
      clearTimeout(entry.timer);
      entry.resolve(msg);
      return;
    }
    // Unsolicited or id-less host error frame: surface cleanly without shifting id-correlated requests.
    if (typeof this.#onError === "function") {
      this.#onError(msg);
    } else {
      console.error(`hyphae plugin id-less ${msg.type}: ${msg.error ?? msg.message ?? "unknown"}`);
    }
  }

  #removePendingEntry(corrId, entry) {
    if (corrId !== null) {
      const bucket = this.#pending.get(corrId);
      if (!bucket) return;
      const idx = bucket.indexOf(entry);
      if (idx >= 0) bucket.splice(idx, 1);
      if (bucket.length === 0) this.#pending.delete(corrId);
    } else {
      const idx = this.#pendingNoId.indexOf(entry);
      if (idx >= 0) this.#pendingNoId.splice(idx, 1);
    }
  }

  /** Register or replace the outbound `hyp_plugin_post` handler for this plugin. */
  onPost(handler) {
    this.#onPost = handler;
  }

  /** Register or replace the host sleep/wake recovery notification handler (`system.wake`). */
  onWake(handler) {
    this.#onWake = handler;
  }

  #handleSystemWake(msg) {
    if (typeof this.#onWake !== "function") return;
    const rawSlept = Number(msg.params?.sleptMs ?? 0);
    const sleptMs = Number.isFinite(rawSlept) && rawSlept >= 0 ? rawSlept : 0;
    try {
      void Promise.resolve(this.#onWake({ sleptMs })).catch((err) => {
        console.error(
          `${this.plugin} plugin wake handler error: ${err instanceof Error ? err.message : String(err)}`,
        );
      });
    } catch (err) {
      console.error(
        `${this.plugin} plugin wake handler error: ${err instanceof Error ? err.message : String(err)}`,
      );
    }
  }

  async #handleRequest(msg) {
    const reply = (payload) => {
      if (this.#closed) return;
      this.#out.write(JSON.stringify({ type: "response", id: msg.id, ...payload }) + "\n");
    };
    if (msg.method !== "post") {
      reply({ ok: false, error: `unsupported_method:${String(msg.method ?? "")}` });
      return;
    }
    if (typeof this.#onPost !== "function") {
      reply({ ok: false, error: "post_not_supported" });
      return;
    }
    try {
      const result = await this.#onPost({
        target: msg.target,
        ...(msg.params && typeof msg.params === "object" ? msg.params : {}),
      });
      reply({ ok: true, result: result ?? { sent: true } });
    } catch (error) {
      reply({ ok: false, error: error instanceof Error ? error.message : String(error) });
    }
  }

  /** Sends one CloudEvent 1.0 to `to` (configured target name) and awaits durable id-correlated ack/nack. */
  async send(to, event, { timeoutMs = DEFAULT_ACK_TIMEOUT_MS } = {}) {
    if (this.#closed) throw new Error("Mesh plugin channel closed");
    const line = JSON.stringify({ type: "event", to, event }) + "\n";
    const corrId = correlationIdForEvent(event);
    return new Promise((resolve, reject) => {
      const entry = { resolve, reject, timer: null };
      if (timeoutMs > 0 && Number.isFinite(timeoutMs)) {
        entry.timer = setTimeout(() => {
          this.#removePendingEntry(corrId, entry);
          reject(new Error(`Timed out waiting for ack/nack${corrId ? ` for event '${corrId}'` : ""}`));
        }, timeoutMs);
        entry.timer.unref?.();
      }
      if (corrId !== null) {
        let bucket = this.#pending.get(corrId);
        if (!bucket) {
          bucket = [];
          this.#pending.set(corrId, bucket);
        }
        bucket.push(entry);
      } else {
        this.#pendingNoId.push(entry);
      }
      this.#out.write(line, (error) => {
        if (error) {
          this.#removePendingEntry(corrId, entry);
          clearTimeout(entry.timer);
          reject(error);
        }
      });
    });
  }
}
