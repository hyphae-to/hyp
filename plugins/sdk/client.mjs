import { createReadStream, createWriteStream } from "node:fs";
import { createInterface } from "node:readline";

/**
 * Minimal Node 24 client for the hyphae / t3-mesh local plugin channel (fd 3, protocol v1).
 * Works identically under both `hyp daemon` and `t3-mesh daemon`.
 */
export class MeshPluginClient {
  plugin;
  targets;
  #out;
  #pending = [];
  #closed = false;
  #onPost;

  constructor({ fd = Number(process.env.T3_MESH_FD ?? process.env.AGENTS_MESH_FD ?? 3), onStatus, onDeliveryFailed, onPost } = {}) {
    this.plugin = process.env.T3_MESH_PLUGIN ?? process.env.AGENTS_MESH_PLUGIN ?? "plugin";
    this.#onPost = onPost;
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
          const next = this.#pending.shift();
          if (next) next.resolve(msg);
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
        while (this.#pending.length > 0) {
          this.#pending.shift().reject(new Error("Mesh plugin channel closed"));
        }
        process.exit(0);
      });
    });
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

  /** Sends one CloudEvent 1.0 to `to` (configured target name) and awaits durable ack/nack. */
  async send(to, event) {
    if (this.#closed) throw new Error("Mesh plugin channel closed");
    const line = JSON.stringify({ type: "event", to, event }) + "\n";
    return new Promise((resolve, reject) => {
      this.#pending.push({ resolve, reject });
      this.#out.write(line, (error) => {
        if (error) {
          const idx = this.#pending.findIndex((p) => p.resolve === resolve);
          if (idx >= 0) this.#pending.splice(idx, 1);
          reject(error);
        }
      });
    });
  }
}
