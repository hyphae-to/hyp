import { createReadStream, createWriteStream } from "node:fs";
import net from "node:net";

const MAX_FRAME_BYTES = 64 * 1024;
const DEFAULT_ACK_TIMEOUT_MS = 60_000;
export const RPC_UNAVAILABLE = -32005;

export class PluginRpcError extends Error {
  constructor({ code, message, data }) {
    super(message);
    this.name = "PluginRpcError";
    this.code = code;
    this.data = data;
  }
}

function parseLoopbackAddr(raw) {
  const trimmed = String(raw ?? "").trim();
  let host;
  let portStr;
  if (trimmed.startsWith("[")) {
    const end = trimmed.indexOf("]");
    if (end < 0 || trimmed[end + 1] !== ":") throw new Error("Invalid HYPHAE_PLUGIN_ADDR");
    host = trimmed.slice(1, end);
    portStr = trimmed.slice(end + 2);
  } else {
    const end = trimmed.lastIndexOf(":");
    if (end <= 0 || trimmed.indexOf(":") !== end) throw new Error("Invalid HYPHAE_PLUGIN_ADDR");
    host = trimmed.slice(0, end);
    portStr = trimmed.slice(end + 1);
  }
  host = host.trim().toLowerCase();
  if (!["127.0.0.1", "::1", "localhost"].includes(host)) throw new Error("Refusing non-loopback HYPHAE_PLUGIN_ADDR");
  const port = Number(portStr);
  if (!/^\d+$/.test(portStr) || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error("Invalid HYPHAE_PLUGIN_ADDR port");
  return { host, port };
}

const object = (value) => value !== null && typeof value === "object" && !Array.isArray(value);
const has = (value, key) => Object.hasOwn(value, key);
const validId = (id) => typeof id === "string" || (typeof id === "number" && Number.isSafeInteger(id));

/** Node 24 client for JSON-RPC 2.0 over private Unix fd 3 or authenticated loopback TCP. */
export class MeshPluginClient {
  plugin;
  targets;
  #out;
  #input;
  #pending = new Map();
  #nextId = 1;
  #activeRequests = 0;
  #closed = false;
  #greeted = false;
  #fatal = false;
  #fatalHandler = null;
  #onPost;
  #onWake;
  #onStatus;
  #onDeliveryFailed;
  #onError;
  #resolveReady;
  #rejectReady;
  #helloTimer;
  #buffer = Buffer.alloc(0);

  constructor({ fd, onStatus, onDeliveryFailed, onPost, onWake, onError, handleFatalErrors = true, helloTimeoutMs = 10_000 } = {}) {
    this.plugin = process.env.HYPHAE_PLUGIN ?? process.env.AGENTS_MESH_PLUGIN ?? process.env.T3_MESH_PLUGIN ?? "plugin";
    this.#onPost = onPost;
    this.#onWake = onWake;
    this.#onStatus = onStatus;
    this.#onDeliveryFailed = onDeliveryFailed;
    this.#onError = onError;
    this.ready = new Promise((resolve, reject) => { this.#resolveReady = resolve; this.#rejectReady = reject; });
    const addr = fd === undefined ? process.env.HYPHAE_PLUGIN_ADDR?.trim() : "";
    let tcpToken = "";
    if (addr) {
      const { host, port } = parseLoopbackAddr(addr);
      tcpToken = process.env.HYPHAE_PLUGIN_TOKEN ?? "";
      delete process.env.HYPHAE_PLUGIN_TOKEN;
      if (!tcpToken) throw new Error("HYPHAE_PLUGIN_TOKEN is required when HYPHAE_PLUGIN_ADDR is set");
      const socket = net.createConnection({ host, port });
      socket.setNoDelay(true);
      // Transport authentication is separate from the v2 plugin protocol, on Windows and Unix.
      socket.write(JSON.stringify({ type: "auth", token: tcpToken }) + "\n");
      this.#input = socket;
      this.#out = socket;
    } else {
      const resolvedFd = fd ?? Number(process.env.HYPHAE_FD ?? process.env.AGENTS_MESH_FD ?? process.env.T3_MESH_FD ?? 3);
      try {
        const socket = new net.Socket({ fd: resolvedFd, readable: true, writable: true });
        this.#input = socket;
        this.#out = socket;
      } catch {
        this.#input = createReadStream("", { fd: resolvedFd, autoClose: false });
        this.#out = createWriteStream("", { fd: resolvedFd, autoClose: false });
      }
    }
    if (handleFatalErrors) {
      this.#fatalHandler = (error) => {
        if (this.#fatal) return;
        this.#fatal = true;
        let detail = error instanceof Error ? error.message : String(error ?? "unknown error");
        if (tcpToken) detail = detail.replaceAll(tcpToken, "[REDACTED]");
        detail = detail.replace(/[\r\n\x00-\x1f\x7f]+/g, " ").trim().slice(0, 512) || "unknown error";
        console.error(`${this.plugin} plugin fatal: ${detail}`);
        this.#teardownChannel();
        const timer = setTimeout(() => { try { process.kill(process.pid, "SIGKILL"); } catch {} }, 250);
        timer.unref();
        process.exit(1);
      };
      process.on("uncaughtException", this.#fatalHandler);
      process.on("unhandledRejection", this.#fatalHandler);
    }
    this.#input.on("data", (chunk) => this.#readChunk(chunk));
    this.#input.on("error", (error) => this.#finish(error));
    if (this.#out !== this.#input) this.#out.on("error", (error) => this.#finish(error));
    this.#input.on("end", () => this.#finish(this.#buffer.length ? new Error("Incomplete plugin frame") : null));
    this.#input.on("close", () => this.#finish(null));
    this.#helloTimer = setTimeout(() => this.#finish(new Error("Timed out waiting for JSON-RPC v2 hello")), helloTimeoutMs);
    this.#helloTimer.unref();
  }

  #teardownChannel() {
    if (this.#fatalHandler) {
      process.off("uncaughtException", this.#fatalHandler);
      process.off("unhandledRejection", this.#fatalHandler);
      this.#fatalHandler = null;
    }
    clearTimeout(this.#helloTimer);
    this.#input?.destroy();
    if (this.#out !== this.#input) this.#out?.destroy();
  }

  #finish(error) {
    if (this.#closed) return;
    const fatal = this.#fatalHandler;
    this.#closed = true;
    const failure = error ?? new Error("Mesh plugin channel closed");
    if (!this.#greeted) this.#rejectReady(failure);
    for (const pending of this.#pending.values()) {
      clearTimeout(pending.timer);
      pending.reject(failure);
    }
    this.#pending.clear();
    this.#teardownChannel();
    if (error && fatal) fatal(error);
    else if (error) this.#reportError(error);
    else if (this.#greeted && fatal) process.exit(0);
  }

  #reportError(error) {
    if (this.#onError) this.#onError(error);
    else console.error(`hyphae plugin channel error: ${error.message}`);
  }

  #readChunk(chunk) {
    if (this.#closed) return;
    // Never retain more than one bounded line, even if the peer never sends a newline.
    let offset = 0;
    while (offset < chunk.length && !this.#closed) {
      const newline = chunk.indexOf(10, offset);
      const end = newline < 0 ? chunk.length : newline;
      const segment = chunk.subarray(offset, end);
      if (this.#buffer.length + segment.length > MAX_FRAME_BYTES + 1) {
        this.#finish(new Error("Plugin frame exceeds 64 KiB"));
        return;
      }
      this.#buffer = Buffer.concat([this.#buffer, segment]);
      if (newline < 0) return;
      const line = this.#buffer.at(-1) === 13 ? this.#buffer.subarray(0, -1) : this.#buffer;
      this.#buffer = Buffer.alloc(0);
      if (line.length > MAX_FRAME_BYTES) { this.#finish(new Error("Plugin frame exceeds 64 KiB")); return; }
      if (line.length) {
        try { this.#handleFrame(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(line))); }
        catch { this.#finish(new Error("Invalid JSON-RPC v2 plugin frame")); return; }
      }
      offset = end + 1;
    }
  }

  #handleFrame(msg) {
    if (!object(msg) || msg.jsonrpc !== "2.0") throw new Error("JSON-RPC 2.0 required");
    if (!this.#greeted) {
      if (msg.method !== "hyphae/hello" || has(msg, "id") || has(msg, "result") || has(msg, "error") ||
          !object(msg.params) || msg.params.protocol !== 2 || !Array.isArray(msg.params.targets) ||
          !msg.params.targets.every((target) => typeof target === "string")) throw new Error("Host v2 hello required");
      this.#greeted = true;
      this.targets = msg.params.targets;
      clearTimeout(this.#helloTimer);
      this.#resolveReady(msg.params);
      return;
    }
    if (has(msg, "method")) {
      if (typeof msg.method !== "string" || has(msg, "result") || has(msg, "error")) throw new Error("Invalid request");
      if (has(msg, "id")) {
        if (!validId(msg.id)) throw new Error("Invalid request ID");
        if (this.#activeRequests >= 32) {
          this.#writeFrame({ jsonrpc: "2.0", id: msg.id, error: { code: RPC_UNAVAILABLE, message: "plugin busy" } });
          return;
        }
        this.#activeRequests++;
        void this.#handleRequest(msg).catch((error) => this.#finish(error))
          .finally(() => { this.#activeRequests--; });
      } else if (msg.method === "hyphae/status") this.#onStatus?.(msg.params);
      else if (msg.method === "hyphae/deliveryFailed") this.#onDeliveryFailed?.(msg.params);
      else if (msg.method === "system.wake") this.#handleWake(msg.params);
      return;
    }
    if (!has(msg, "id") || (msg.id !== null && !validId(msg.id)) || has(msg, "result") === has(msg, "error")) throw new Error("Invalid response");
    if (has(msg, "error") && (!object(msg.error) || !Number.isInteger(msg.error.code) || typeof msg.error.message !== "string")) throw new Error("Invalid error response");
    const pending = this.#pending.get(msg.id);
    if (!pending) {
      if (msg.id === null && msg.error) this.#reportError(new PluginRpcError(msg.error));
      return;
    }
    this.#pending.delete(msg.id);
    clearTimeout(pending.timer);
    if (msg.error) pending.reject(new PluginRpcError(msg.error));
    else pending.resolve(msg.result);
  }

  #writeFrame(frame, onError) {
    if (this.#closed) throw new Error("Mesh plugin channel closed");
    const json = JSON.stringify(frame);
    if (Buffer.byteLength(json, "utf8") > MAX_FRAME_BYTES) throw new PluginRpcError({ code: -32001, message: "Plugin frame exceeds 64 KiB" });
    this.#out.write(json + "\n", (error) => { if (error) onError?.(error); });
  }

  close() { this.#finish(null); }

  onPost(handler) { this.#onPost = handler; }
  onWake(handler) { this.#onWake = handler; }

  #handleWake(params) {
    if (!this.#onWake) return;
    const slept = Number(params?.sleptMs ?? 0);
    try {
      void Promise.resolve(this.#onWake({ sleptMs: Number.isFinite(slept) && slept >= 0 ? slept : 0 }))
        .catch((error) => console.error(`${this.plugin} plugin wake handler error: ${error.message}`));
    } catch (error) { console.error(`${this.plugin} plugin wake handler error: ${error.message}`); }
  }

  async #handleRequest(msg) {
    const reply = (payload) => { if (!this.#closed) this.#writeFrame({ jsonrpc: "2.0", id: msg.id, ...payload }); };
    if (msg.method !== "hyphae/post" || !this.#onPost) {
      reply({ error: { code: -32601, message: msg.method === "hyphae/post" ? "post_not_supported" : `unsupported_method:${msg.method.slice(0, 128)}` } });
      return;
    }
    if (!object(msg.params) || typeof msg.params.target !== "string" || !object(msg.params.params)) {
      reply({ error: { code: -32602, message: "invalid post params" } });
      return;
    }
    try {
      const result = await this.#onPost({ ...msg.params.params, target: msg.params.target });
      reply({ result: result ?? { sent: true } });
    } catch (error) {
      reply({ error: { code: -32603, message: String(error?.message ?? error).slice(0, 512) } });
    }
  }

  /** Publish a CloudEvent and return its durable result. JSON-RPC errors reject with PluginRpcError. */
  async send(to, event, { timeoutMs = DEFAULT_ACK_TIMEOUT_MS } = {}) {
    await this.ready;
    if (this.#closed) throw new Error("Mesh plugin channel closed");
    if (this.#pending.size >= 128) throw new Error("Too many pending plugin requests");
    const id = `publish-${this.#nextId++}`;
    const result = await new Promise((resolve, reject) => {
      const entry = { resolve, reject, timer: null };
      if (Number.isFinite(timeoutMs) && timeoutMs > 0) {
        entry.timer = setTimeout(() => {
          this.#pending.delete(id);
          reject(new Error("Timed out waiting for publish response"));
        }, timeoutMs);
        entry.timer.unref();
      }
      this.#pending.set(id, entry);
      const fail = (error) => {
        this.#pending.delete(id);
        clearTimeout(entry.timer);
        reject(error);
      };
      try { this.#writeFrame({ jsonrpc: "2.0", id, method: "hyphae/publish", params: { to, event } }, fail); }
      catch (error) { fail(error); }
    });
    if (!object(result) || !["stored", "duplicate"].includes(result.status)) throw new Error("Invalid publish result");
    return result;
  }
}
