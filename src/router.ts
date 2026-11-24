import { setTimeout as delay } from "node:timers/promises";
import { decodeItem, object, reject, type InboxItem, type Outcome, type Subscription } from "./protocol.ts";

export interface RouterConfig {
  name: string;
  url: string;
  token: string;
}

export interface PeerKeyEntry {
  readonly connectorId: string;
  readonly signingKey: string;
  readonly encryptionKey: string;
  readonly source: string;
}

export class RouterError extends Error {
  readonly code: string;
  readonly status?: number;

  constructor(code: string, message: string, status?: number) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

export class RouterLink {
  readonly config: RouterConfig;

  constructor(config: RouterConfig) {
    this.config = config;
  }

  async #parseError(response: Response): Promise<RouterError> {
    const error: unknown = await response.json().catch(() => null);
    const fallbackCode = response.status === 404 ? "not_found" : "router_unavailable";
    return new RouterError(
      object(error) && typeof error.error === "string" ? error.error : fallbackCode,
      object(error) && typeof error.message === "string" ? error.message : `${this.config.name} returned HTTP ${response.status}`,
      response.status,
    );
  }

  async #request(method: string, path: string, body?: unknown, signal = AbortSignal.timeout(15_000)) {
    let response: Response;
    try {
      response = await fetch(this.config.url + path, {
        method, redirect: "error", signal,
        headers: {
          authorization: `Bearer ${this.config.token}`,
          ...(body === undefined ? {} : { "content-type": "application/json" }),
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch {
      throw new RouterError("router_unavailable", `${this.config.name} is unavailable`);
    }
    if (response.ok) return response;
    throw await this.#parseError(response);
  }

  async registerKeys(reg: unknown): Promise<void> {
    await this.#request("PUT", "/v1/keys", reg);
  }

  async peerKeys(): Promise<PeerKeyEntry[]> {
    const payload: unknown = await (await this.#request("GET", "/v1/keys")).json();
    if (!object(payload) || !Array.isArray(payload.keys)) {
      throw new RouterError("router_protocol", "Invalid keys response");
    }
    const result: PeerKeyEntry[] = [];
    for (const entry of payload.keys) {
      if (
        object(entry) &&
        typeof entry.connectorId === "string" &&
        typeof entry.signingKey === "string" &&
        typeof entry.encryptionKey === "string" &&
        typeof entry.source === "string"
      ) {
        result.push({
          connectorId: entry.connectorId,
          signingKey: entry.signingKey,
          encryptionKey: entry.encryptionKey,
          source: entry.source,
        });
      }
    }
    return result;
  }

  async sendTransfer(
    id: string,
    signedHeader: { readonly payload: string; readonly sig: string },
    ciphertext: Buffer,
  ): Promise<void> {
    let response: Response;
    try {
      response = await fetch(`${this.config.url}/v1/transfers/${encodeURIComponent(id)}`, {
        method: "PUT",
        redirect: "error",
        signal: AbortSignal.timeout(60_000),
        headers: {
          authorization: `Bearer ${this.config.token}`,
          "hyphae-transfer": Buffer.from(JSON.stringify(signedHeader), "utf8").toString("base64url"),
          "content-type": "application/octet-stream",
        },
        body: new Uint8Array(ciphertext),
      });
    } catch {
      throw new RouterError("router_unavailable", `${this.config.name} is unavailable`);
    }
    if (!response.ok) throw await this.#parseError(response);
  }

  async fetchTransfer(id: string): Promise<Buffer> {
    let response: Response;
    try {
      response = await fetch(`${this.config.url}/v1/transfers/${encodeURIComponent(id)}`, {
        method: "GET",
        redirect: "error",
        signal: AbortSignal.timeout(60_000),
        headers: {
          authorization: `Bearer ${this.config.token}`,
        },
      });
    } catch {
      throw new RouterError("router_unavailable", `${this.config.name} is unavailable`);
    }
    if (!response.ok) throw await this.#parseError(response);
    return Buffer.from(await response.arrayBuffer());
  }

  async handles(handles: string[]): Promise<void> {
    await this.#request("PUT", "/v1/handles", { handles });
  }

  async subscriptions(subscriptions: Subscription[]): Promise<{
    unknownTopics: string[];
    diagnostics: Record<string, unknown[]>;
  }> {
    const specs = subscriptions.map(({ id, topic, filters, coalesceSeconds }) => ({ id, topic, filters, coalesceSeconds }));
    const response = await this.#request("PUT", "/v1/subscriptions", { subscriptions: specs });
    const payload: unknown = await response.json();
    if (!object(payload) || !Array.isArray(payload.unknownTopics) ||
        !payload.unknownTopics.every((value): value is string => typeof value === "string")) {
      throw new RouterError("router_protocol", "Invalid subscription response");
    }
    const diagnostics: Record<string, unknown[]> = {};
    if (object(payload.diagnostics)) {
      for (const [subId, list] of Object.entries(payload.diagnostics)) {
        if (Array.isArray(list)) diagnostics[subId] = list;
      }
    }
    return { unknownTopics: payload.unknownTopics, diagnostics };
  }

  async query(path: "/v1/peers" | "/v1/subscriptions/status" | "/v1/topics"): Promise<unknown> {
    return (await this.#request("GET", path)).json();
  }

  async send(id: string, fromHandle: string, to: string, text: string): Promise<unknown> {
    return (await this.#request("POST", "/v1/messages", { id, fromHandle, to, text })).json();
  }

  async joinChannel(handle: string, channel: string): Promise<unknown> {
    return (await this.#request("POST", "/v1/channels/join", { handle, channel })).json();
  }

  async leaveChannel(handle: string, channel: string): Promise<unknown> {
    return (await this.#request("POST", "/v1/channels/leave", { handle, channel })).json();
  }

  async channels(channel?: string): Promise<unknown> {
    const query = channel ? `?channel=${encodeURIComponent(channel)}` : "";
    return (await this.#request("GET", `/v1/channels${query}`)).json();
  }

  async postChannel(id: string, fromHandle: string, channel: string, text: string): Promise<unknown> {
    return (await this.#request("POST", "/v1/channels/post", { id, fromHandle, channel, text })).json();
  }

  async #ack(id: string, outcome: Outcome) {
    await this.#request("POST", `/v1/messages/${encodeURIComponent(id)}/ack`, outcome);
  }

  async listen(
    signal: AbortSignal,
    sync: () => Promise<void>,
    receive: (item: InboxItem) => Promise<Outcome>,
  ): Promise<void> {
    const inFlight = new Set<string>();
    let backoff = 1000;
    while (!signal.aborted) {
      try {
        await sync();
        const response = await this.#request("GET", "/v1/inbox", undefined, signal);
        if (!response.body) throw new Error("missing inbox stream");
        backoff = 1000;
        let buffer = "";
        const decoder = new TextDecoder();
        for await (const data of response.body) {
          buffer += decoder.decode(data, { stream: true });
          let end = buffer.indexOf("\n\n");
          while (end !== -1) {
            const frame = buffer.slice(0, end);
            buffer = buffer.slice(end + 2);
            end = buffer.indexOf("\n\n");
            const dataLine = frame.split("\n").filter((line) => line.startsWith("data: ")).map((line) => line.slice(6)).join("\n");
            if (!dataLine) continue;
            let value: unknown;
            try { value = JSON.parse(dataLine); } catch { continue; }
            if (!object(value) || typeof value.id !== "string" || value.id.length === 0 || value.id.length > 256) continue;
            const id = value.id;
            if (inFlight.has(id)) continue;
            const item = decodeItem(value);
            inFlight.add(id);
            void (async () => {
              try {
                const outcome = item === undefined ? reject("unsupported_or_invalid_item") : await receive(item);
                await this.#ack(id, outcome);
              } catch {
                if (!signal.aborted) console.error(`Router ${this.config.name} could not settle an inbox item`);
              } finally {
                inFlight.delete(id);
              }
            })();
          }
          if (buffer.length > 2_000_000) throw new Error("oversize router frame");
        }
      } catch {
        if (!signal.aborted) console.error(`Router ${this.config.name} disconnected; reconnecting`);
      }
      await delay(backoff, undefined, { signal }).catch(() => {});
      backoff = Math.min(backoff * 2, 30_000);
    }
  }
}
