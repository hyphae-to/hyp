import { createReadStream, createWriteStream } from "node:fs";
import { createInterface } from "node:readline";

const DEFAULT_ACK_TIMEOUT_MS = 60_000;
const MAX_ECHO_ID_CHARS = 256;

function correlationIdForEvent(event) {
  if (typeof event?.id !== "string" || event.id.length === 0) return null;
  return Array.from(event.id).slice(0, MAX_ECHO_ID_CHARS).join("");
}

/**
 * Minimal Node 24 client for the Hyphae local plugin channel (fd 3, protocol v1).
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
    fd = Number(process.env.HYPHAE_FD ?? process.env.AGENTS_MESH_FD ?? process.env.T3_MESH_FD ?? 3),
    onStatus,
    onDeliveryFailed,
    onPost,
    onError,
  } = {}) {
    this.plugin = process.env.HYPHAE_PLUGIN ?? process.env.AGENTS_MESH_PLUGIN ?? process.env.T3_MESH_PLUGIN ?? "plugin";
    this.#onPost = onPost;
    this.#onError = onError;
    this.#out = createWriteStream("", { fd, autoClose: false });
    const input = createReadStream("", { fd, autoClose: false });
    const rl = createInterface({ input });
    rl.on("error", () => {});

    this.ready = new Promise((resolve, reject) => {
      let greeted = false;
      rl.on("line", (line) => {
        if (!line.trim()) return;
        let msg;
        try { msg = JSON.parse(line); } catch { return; }
        if (!greeted) {
          greeted = true;
          if (msg.type !== "hello" || msg.protocol !== 1 || !Array.isArray(msg.targets)) {
            reject(new Error(`Unexpected mesh plugin hello: ${line}`));
            return;
          }
          this.targets = msg.targets;
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
        if (!greeted) reject(new Error("Mesh plugin channel closed before hello"));
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
        process.exit(0);
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
