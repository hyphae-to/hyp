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
  #pending = new Map();
  #pendingNoId = [];
  #closed = false;
  #onPost;
  #onError;

  constructor({
    fd,
    onStatus,
    onDeliveryFailed,
    onPost,
    onError,
  } = {}) {
    this.plugin = process.env.HYPHAE_PLUGIN ?? process.env.AGENTS_MESH_PLUGIN ?? process.env.T3_MESH_PLUGIN ?? "plugin";
    this.#onPost = onPost;
    this.#onError = onError;

    const pluginAddr = fd === undefined ? process.env.HYPHAE_PLUGIN_ADDR?.trim() : "";
    let input;
    let tcpSock = null;
    if (pluginAddr) {
      const { host, port } = parseLoopbackAddr(pluginAddr);
      const token = process.env.HYPHAE_PLUGIN_TOKEN ?? "";
      delete process.env.HYPHAE_PLUGIN_TOKEN;
      if (!token) {
        throw new Error("HYPHAE_PLUGIN_TOKEN is required when HYPHAE_PLUGIN_ADDR is set");
      }
      tcpSock = net.createConnection({ host, port });
      tcpSock.setNoDelay(true);
      tcpSock.write(JSON.stringify({ type: "auth", token }) + "\n");
      this.#out = tcpSock;
      input = tcpSock;
    } else {
      const resolvedFd = fd ?? Number(process.env.HYPHAE_FD ?? process.env.AGENTS_MESH_FD ?? process.env.T3_MESH_FD ?? 3);
      this.#out = createWriteStream("", { fd: resolvedFd, autoClose: false });
      input = createReadStream("", { fd: resolvedFd, autoClose: false });
    }

    const rl = createInterface({ input });
    rl.on("error", () => {});

    this.ready = new Promise((resolve, reject) => {
      let greeted = false;
      let settled = false;
      const failReady = (err) => {
        if (!settled) {
          settled = true;
          reject(err);
        }
      };
      if (tcpSock) {
        tcpSock.on("error", (err) => {
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
        }
      });
      rl.on("close", () => {
        this.#closed = true;
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
        if (greeted) {
          process.exit(0);
        }
      });
    });
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
