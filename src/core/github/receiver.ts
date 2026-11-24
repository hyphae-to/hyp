// `hyp router github-receiver`: the GitHub webhook endpoint. Internet-facing through Tailscale
// Funnel or reverse proxy, so it runs isolated: it holds only the webhook secret and a publisher
// token, never opens the router's database, never calls GitHub, and talks only to the router.
//
// POST /hooks/github: verify X-Hub-Signature-256 over the raw body (401 if bad or missing),
// normalize, publish to the router, and answer GitHub 202 once the router has stored the event,
// 200 for events that are not published or already published with other content (409), 503 when
// the router is unavailable (the delivery shows as failed and can be redelivered).
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { checkCloudEvent, type CloudEvent } from "../router/cloudevent.ts";
import { errorMessage, log } from "../log.ts";
import { normalize } from "./normalize.ts";
import { verifySignature } from "./signature.ts";

export const HOOK_PATH = "/hooks/github";
/** GitHub gives up on a delivery after 10 s; answer before that. */
const ROUTER_TIMEOUT_MS = 5_000;
const DELIVERY_ID = /^[A-Za-z0-9-]{1,128}$/;
const EVENT_NAME = /^[a-z_]{1,64}$/;

/**
 * Bounds on what unauthenticated clients can make the receiver hold: the signature can only be
 * checked once the whole body is in memory.
 */
export interface ReceiverLimits {
  /** GitHub caps payloads at 25 MB, but the events published fit well under this; larger ones are refused unread. */
  readonly maxBodyBytes: number;
  /** Request body bytes held across all requests at once, counted by declared length; over it, 503. */
  readonly maxBytesInFlight: number;
  readonly maxConnections: number;
  /** For headers and for the whole request; GitHub itself gives up after 10 s. */
  readonly requestTimeoutMs: number;
  /** How often expired requests are found and closed. */
  readonly checkIntervalMs: number;
}

export const DEFAULT_RECEIVER_LIMITS: ReceiverLimits = {
  maxBodyBytes: 1024 * 1024,
  maxBytesInFlight: 16 * 1024 * 1024,
  maxConnections: 64,
  requestTimeoutMs: 10_000,
  checkIntervalMs: 1_000,
};

export interface ReceiverOptions {
  readonly host: string;
  /** 0 picks a free port. */
  readonly port: number;
  /** Router base URL, e.g. http://127.0.0.1:8790. */
  readonly routerUrl: string;
  readonly topic: string;
  readonly secret: string;
  readonly token: string;
  readonly now?: () => Date;
  readonly limits?: ReceiverLimits;
}

export interface RunningReceiver {
  readonly url: string;
  close(): Promise<void>;
}

class TooLarge extends Error {}

async function readBody(request: IncomingMessage, maxBytes: number): Promise<Buffer> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    size += buffer.length;
    if (size > maxBytes) throw new TooLarge();
    chunks.push(buffer);
  }
  return Buffer.concat(chunks);
}

/** The declared body length; null without a valid Content-Length (e.g. chunked). */
const declaredLength = (request: IncomingMessage): number | null => {
  const value = request.headers["content-length"];
  return value !== undefined && /^\d{1,15}$/.test(value) ? Number(value) : null;
};

/** Answers and closes the connection rather than reading the rest of the body. */
const refuse = (response: ServerResponse, status: number, body: Readonly<Record<string, unknown>>) => {
  response.setHeader("connection", "close");
  reply(response, status, body);
};

const reply = (response: ServerResponse, status: number, body: Readonly<Record<string, unknown>>) => {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
};

const header = (request: IncomingMessage, name: string): string | null => {
  const value = request.headers[name];
  return typeof value === "string" ? value : null;
};

type PublishOutcome =
  | { readonly kind: "stored"; readonly matched: number }
  | { readonly kind: "conflict" }
  | { readonly kind: "unavailable"; readonly reason: string }
  | { readonly kind: "refused"; readonly status: number; readonly error: string };

async function publish(options: ReceiverOptions, event: CloudEvent): Promise<PublishOutcome> {
  let response: Response;
  try {
    response = await fetch(`${options.routerUrl}/v1/events?topic=${encodeURIComponent(options.topic)}`, {
      method: "POST",
      redirect: "error",
      headers: { authorization: `Bearer ${options.token}`, "content-type": "application/json" },
      body: JSON.stringify(event),
      signal: AbortSignal.timeout(ROUTER_TIMEOUT_MS),
    });
  } catch (error) {
    return { kind: "unavailable", reason: errorMessage(error) };
  }
  const body: unknown = await response.json().catch(() => null);
  const field = (name: string): unknown =>
    typeof body === "object" && body !== null && name in body ? (body as Record<string, unknown>)[name] : undefined;
  if (response.ok) {
    const matched = field("matched");
    return { kind: "stored", matched: typeof matched === "number" ? matched : 0 };
  }
  const error = field("error");
  if (response.status === 409 && error === "id_conflict") return { kind: "conflict" };
  if (response.status >= 500) return { kind: "unavailable", reason: `HTTP ${response.status}` };
  return { kind: "refused", status: response.status, error: typeof error === "string" ? error : "unknown" };
}

export async function serveReceiver(options: ReceiverOptions): Promise<RunningReceiver> {
  const now = options.now ?? (() => new Date());
  const routerUrl = new URL(options.routerUrl);
  if (routerUrl.protocol !== "https:" && !["127.0.0.1", "localhost", "[::1]"].includes(routerUrl.hostname)) {
    throw new Error("the router URL must be https or loopback; the publisher token must not cross the network in clear");
  }
  if (options.secret.length === 0) throw new Error("the webhook secret is empty");
  const resolved: ReceiverOptions = { ...options, routerUrl: routerUrl.origin };
  const limits = options.limits ?? DEFAULT_RECEIVER_LIMITS;
  let bytesInFlight = 0;

  const handle = async (request: IncomingMessage, response: ServerResponse): Promise<void> => {
    // Compared as a string: the request target is client input and need not parse as a URL.
    if ((request.url ?? "").split("?")[0] !== HOOK_PATH) {
      reply(response, 404, { error: "not_found" });
      return;
    }
    if (request.method !== "POST") {
      response.setHeader("allow", "POST");
      reply(response, 405, { error: "method_not_allowed" });
      return;
    }
    // Unauthenticated until the signature checks out, so only a well-formed delivery ID is logged.
    const claimedDelivery = header(request, "x-github-delivery");
    const loggedDelivery = claimedDelivery !== null && DELIVERY_ID.test(claimedDelivery) ? claimedDelivery : null;
    const declared = declaredLength(request);
    if (declared !== null && declared > limits.maxBodyBytes) {
      log("warn", "github.too_large", { delivery: loggedDelivery, bytes: declared });
      refuse(response, 413, { error: "too_large" });
      return;
    }
    const reserved = declared ?? limits.maxBodyBytes;
    if (bytesInFlight + reserved > limits.maxBytesInFlight) {
      log("warn", "github.busy", { delivery: loggedDelivery, bytesInFlight });
      refuse(response, 503, { error: "busy" });
      return;
    }
    bytesInFlight += reserved;
    try {
      let body: Buffer;
      try {
        body = await readBody(request, Math.min(reserved, limits.maxBodyBytes));
      } catch (error) {
        if (!(error instanceof TooLarge)) throw error;
        log("warn", "github.too_large", { delivery: loggedDelivery });
        refuse(response, 413, { error: "too_large" });
        return;
      }
      if (!verifySignature(resolved.secret, body, request.headers["x-hub-signature-256"])) {
        log("warn", "github.bad_signature", {
          hasSignature: request.headers["x-hub-signature-256"] !== undefined,
          bytes: body.length,
        });
        reply(response, 401, { error: "bad_signature" });
        return;
      }
      // Signed by GitHub from here on; still treated as untrusted content.
      const event = header(request, "x-github-event");
      const delivery = header(request, "x-github-delivery");
      if (event === null || delivery === null || !EVENT_NAME.test(event) || !DELIVERY_ID.test(delivery)) {
        log("warn", "github.bad_headers", { event, delivery });
        reply(response, 400, { error: "bad_headers" });
        return;
      }
      if (!/^application\/json\b/i.test(header(request, "content-type") ?? "")) {
        log("warn", "github.bad_content_type", { delivery, contentType: header(request, "content-type") });
        reply(response, 400, { error: "content_type", message: "configure the webhook with content type application/json" });
        return;
      }
      let payload: unknown;
      try {
        payload = JSON.parse(body.toString("utf8"));
      } catch {
        log("warn", "github.bad_json", { delivery, event });
        reply(response, 400, { error: "bad_json" });
        return;
      }

      const normalized = normalize({ event, id: delivery, payload, receivedAt: now() });
      if (!normalized.publish) {
        log("info", "github.ignored", { delivery, event, reason: normalized.reason });
        reply(response, 200, { status: "ignored" });
        return;
      }
      const checked = checkCloudEvent(normalized.event);
      if (!checked.ok) {
        log("error", "github.unpublishable", { delivery, type: normalized.event.type, error: checked.message });
        reply(response, 500, { error: "unpublishable" });
        return;
      }
      const context = { delivery, type: normalized.event.type, repo: normalized.event["repo"] };
      const outcome = await publish(resolved, normalized.event);
      switch (outcome.kind) {
        case "stored":
          log("info", "github.published", { ...context, matched: outcome.matched });
          reply(response, 202, { status: "stored" });
          return;
        case "conflict":
          // Already published under this delivery ID with other content; a redelivery changes nothing.
          log("warn", "github.id_conflict", context);
          reply(response, 200, { status: "already_published" });
          return;
        case "unavailable":
          log("warn", "github.router_unavailable", { ...context, reason: outcome.reason });
          reply(response, 503, { error: "router_unavailable" });
          return;
        case "refused":
          // Our configuration (token, grant, topic) or our normalization is wrong; keep the delivery redeliverable.
          log("error", "github.router_refused", { ...context, status: outcome.status, error: outcome.error });
          reply(response, 503, { error: "router_refused" });
          return;
      }
    } finally {
      bytesInFlight -= reserved;
    }
  };

  const server = createServer({ connectionsCheckingInterval: limits.checkIntervalMs }, (request, response) => {
    handle(request, response).catch((error: unknown) => {
      log("error", "github.request_failed", { error: errorMessage(error) });
      if (!response.headersSent) reply(response, 500, { error: "internal" });
      else response.destroy();
    });
  });
  server.maxConnections = limits.maxConnections;
  server.requestTimeout = limits.requestTimeoutMs;
  server.headersTimeout = limits.requestTimeoutMs;
  await new Promise<void>((resolve) => server.listen(options.port, options.host, resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("receiver is not listening on TCP");
  log("info", "github.listening", { host: options.host, port: address.port, router: resolved.routerUrl, topic: options.topic });
  return {
    url: `http://${options.host}:${address.port}`,
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
