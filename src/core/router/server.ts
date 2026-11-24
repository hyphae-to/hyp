// `hyp router serve`: the HTTP router. Listens on loopback; Tailscale Serve or a reverse proxy
// terminates TLS in front of it. Connectors and publishers authenticate with their bearer token.
import { createHash } from "node:crypto";
import { createReadStream, createWriteStream, rmSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import * as Schema from "../validate.ts";
import { errorMessage, log } from "../log.ts";
import { MAX_EVENT_BYTES } from "./cloudevent.ts";
import { RouterCore } from "./core.ts";
import type { PublishError } from "./events.ts";
import type { PairingError, PairingResult } from "./pairing.ts";
import type { TransferError } from "./transfers.ts";
import { MAX_TEXT_BYTES, toRouterOutcome, type SendError } from "./types.ts";

const MAX_BODY_BYTES = MAX_TEXT_BYTES * 2 + 4096;
/** The event limit applies to the event as re-serialized; this leaves room for whitespace. */
const MAX_EVENT_BODY_BYTES = MAX_EVENT_BYTES * 2 + 4096;
/** 200 subscriptions with 4 KiB of filters each. */
const MAX_SUBSCRIPTIONS_BODY_BYTES = 1024 * 1024;
/** Upper bound on a single deadline timer sleep (1 hour), so long-horizon deadlines re-check safely. */
const MAX_TICK_SLEEP_MS = 60 * 60 * 1000;
/** Backoff before retrying a failed tick (e.g. SQLite stayed busy past busy_timeout). */
const TICK_ERROR_RETRY_MS = 1_000;
const KEEPALIVE_MS = 15_000;

const HandlesBody = Schema.Struct({ handles: Schema.Array(Schema.String) });
const Origin = Schema.Struct({ environmentId: Schema.String, threadId: Schema.String });
const SendBody = Schema.Struct({
  id: Schema.String,
  fromHandle: Schema.String,
  to: Schema.String,
  text: Schema.String,
  // Optional for connectors that predate it.
  origin: Schema.optionalKey(Schema.NullOr(Origin)),
});
const AckBody = Schema.Union([
  Schema.Struct({ outcome: Schema.Literal("delivered") }),
  Schema.Struct({ outcome: Schema.Literals(["rejected", "hold"]), reason: Schema.String }),
]);
const decodeHandles = Schema.decodeUnknownOption(HandlesBody);
const decodeSend = Schema.decodeUnknownOption(SendBody);
const SubscriptionsBody = Schema.Struct({
  subscriptions: Schema.Array(
    Schema.Struct({ id: Schema.String, topic: Schema.String, filters: Schema.Unknown, coalesceSeconds: Schema.Number }),
  ),
});
const decodeAck = Schema.decodeUnknownOption(AckBody);
const decodeSubscriptions = Schema.decodeUnknownOption(SubscriptionsBody);

const SEND_STATUS: Readonly<Record<SendError, number>> = {
  unknown_recipient: 404,
  rate_limited: 429,
  queue_full: 429,
  too_large: 413,
  id_conflict: 409,
  invalid: 400,
  not_granted: 403,
  router_unavailable: 503,
};

const PAIRING_STATUS: Readonly<Record<PairingError, number>> = {
  not_configured: 503,
  unauthorized: 401,
  not_found: 404,
  already_paired: 409,
  expired: 410,
  invalid: 400,
};

const PUBLISH_STATUS: Readonly<Record<PublishError, number>> = {
  unknown_topic: 404,
  not_granted: 403,
  invalid_event: 400,
  too_large: 413,
  id_conflict: 409,
};

class HttpError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const json = (response: ServerResponse, status: number, body: unknown) => {
  response.writeHead(status, { "content-type": "application/json" });
  response.end(JSON.stringify(body));
};

const pairingJson = <A>(response: ServerResponse, result: PairingResult<A>) => {
  if (result.ok) json(response, 200, result.value);
  else json(response, PAIRING_STATUS[result.error], { error: result.error, message: result.message });
};

const TRANSFER_STATUS: Readonly<Record<TransferError, number>> = {
  invalid: 400,
  unauthorized: 401,
  not_granted: 403,
  unknown_recipient: 404,
  too_large: 413,
  queue_full: 429,
  id_conflict: 409,
};

const SignedHeader = Schema.fromJsonString(Schema.Struct({ payload: Schema.String, sig: Schema.String }));

/**
 * Writes a request body to `path` (0600) while hashing it, never holding it in memory. More than
 * `expected` bytes is refused; the file is removed on any failure.
 */
async function streamToFile(request: IncomingMessage, path: string, expected: number): Promise<{ path: string; size: number; sha256: string }> {
  const declared = Number(request.headers["content-length"] ?? "NaN");
  if (Number.isFinite(declared) && declared !== expected) {
    throw new HttpError(400, "invalid", `body is ${declared} bytes; the header says ${expected}`);
  }
  const hash = createHash("sha256");
  let size = 0;
  const out = createWriteStream(path, { mode: 0o600, flags: "wx" });
  try {
    await pipeline(
      request,
      new Transform({
        transform(chunk: Buffer, _encoding, done) {
          size += chunk.length;
          if (size > expected) return done(new HttpError(413, "too_large", `body exceeds the ${expected} bytes in the header`));
          hash.update(chunk);
          done(null, chunk);
        },
      }),
      out,
    );
  } catch (error) {
    rmSync(path, { force: true });
    throw error;
  }
  return { path, size, sha256: hash.digest("hex") };
}

/** Grants, bindings and revocations are a few KiB; the limit only bounds unauthenticated bodies. */
const MAX_PAIRING_BODY_BYTES = 64 * 1024;

async function readJson(request: IncomingMessage, limit = MAX_BODY_BYTES, invalid = "invalid"): Promise<unknown> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(String(chunk));
    size += buffer.length;
    if (size > limit) throw new HttpError(413, "too_large", "request body too large");
    chunks.push(buffer);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    throw new HttpError(400, invalid, "body is not JSON");
  }
}

export interface RouterServerOptions {
  readonly core: RouterCore;
  readonly host: string;
  /** 0 picks a free port. */
  readonly port: number;
}

export interface RunningRouter {
  readonly url: string;
  close(): Promise<void>;
}

export async function serveRouter(options: RouterServerOptions): Promise<RunningRouter> {
  const { core } = options;
  let closed = false;
  let ticking = false;
  let tickTimer: NodeJS.Timeout | null = null;

  const armTimer = (delayMs: number) => {
    tickTimer = setTimeout(runTick, delayMs);
    tickTimer.unref();
  };

  const scheduleTick = () => {
    if (closed || ticking) return;
    if (tickTimer !== null) {
      clearTimeout(tickTimer);
      tickTimer = null;
    }
    let nextAt: number | null;
    try {
      nextAt = core.nextDeadlineMs();
    } catch (error) {
      log("error", "router.tick_failed", { error: errorMessage(error) });
      armTimer(TICK_ERROR_RETRY_MS);
      return;
    }
    if (nextAt === null) return;
    const delayMs = Math.min(MAX_TICK_SLEEP_MS, Math.max(1, nextAt - core.now()));
    armTimer(delayMs);
  };

  const runTick = () => {
    tickTimer = null;
    if (closed) return;
    ticking = true;
    let failed = false;
    try {
      core.tick();
    } catch (error) {
      failed = true;
      log("error", "router.tick_failed", { error: errorMessage(error) });
    } finally {
      ticking = false;
    }
    if (closed) return;
    if (failed) armTimer(TICK_ERROR_RETRY_MS);
    else scheduleTick();
  };

  core.setScheduleListener(scheduleTick);
  scheduleTick();

  const server = createServer(async (request, response) => {
    try {
      const token = /^Bearer (.+)$/.exec(request.headers.authorization ?? "")?.[1];
      const url = new URL(request.url ?? "/", "http://router");
      const route = `${request.method ?? "GET"} ${url.pathname}`;

      // Publisher tokens can call this route and nothing else; connector tokens cannot call it.
      if (route === "POST /v1/events") {
        const publisher = token === undefined ? null : core.events.authenticatePublisher(token);
        if (publisher === null) {
          if (token !== undefined && core.authenticate(token) !== null) {
            throw new HttpError(403, "not_granted", "connector tokens cannot publish");
          }
          throw new HttpError(401, "unauthorized", "missing or invalid publisher token");
        }
        const topic = url.searchParams.get("topic") ?? "";
        const result = core.events.publish(publisher, topic, await readJson(request, MAX_EVENT_BODY_BYTES, "invalid_event"));
        if (result.ok) json(response, 202, { status: result.status, matched: result.matched });
        else json(response, PUBLISH_STATUS[result.error], { error: result.error, message: result.message });
        return;
      }

      // Pairing routes take no bearer token: grants and revocations carry the admin signature,
      // bindings the pairing key's (SPEC.md section 14.3).
      if (route === "POST /v1/grants") {
        pairingJson(response, core.pairing.addGrant(await readJson(request, MAX_PAIRING_BODY_BYTES)));
        return;
      }
      if (route === "POST /v1/revocations") {
        pairingJson(response, core.pairing.addRevocation(await readJson(request, MAX_PAIRING_BODY_BYTES)));
        return;
      }
      const pairingMatch = /^(GET|POST) \/v1\/pairing\/([0-9a-f-]{36})$/.exec(route);
      if (pairingMatch?.[2] !== undefined) {
        const grantId = pairingMatch[2];
        if (pairingMatch[1] === "GET") pairingJson(response, core.pairing.pendingGrant(grantId));
        else pairingJson(response, core.pairing.pair(grantId, await readJson(request, MAX_PAIRING_BODY_BYTES)));
        return;
      }

      const connectorId = token === undefined ? null : core.authenticate(token);
      if (connectorId === null) throw new HttpError(401, "unauthorized", "missing or invalid connector token");

      if (route === "GET /v1/directory") {
        pairingJson(response, core.pairing.directory());
        return;
      }
      if (route === "PUT /v1/keys") {
        const result = core.registerKeys(connectorId, await readJson(request, MAX_PAIRING_BODY_BYTES));
        if (result.ok) {
          json(response, 200, {
            connectorId: result.connectorId,
            signingKey: result.signingKey,
            encryptionKey: result.encryptionKey,
          });
        } else {
          json(response, result.error === "unauthorized" ? 401 : 400, {
            error: result.error,
            message: result.message,
          });
        }
        return;
      }
      if (route === "GET /v1/keys") {
        json(response, 200, { keys: core.connectorKeys() });
        return;
      }
      const transferMatch = /^(PUT|GET) \/v1\/transfers\/([0-9a-f-]{36})$/.exec(route);
      if (transferMatch?.[2] !== undefined) {
        const id = transferMatch[2];
        if (transferMatch[1] === "GET") {
          const stored = core.transfers.readPath(connectorId, id);
          if (stored === null) throw new HttpError(404, "not_found", "no such pending transfer for this connector");
          response.writeHead(200, { "content-type": "application/octet-stream", "content-length": stored.size });
          await pipeline(createReadStream(stored.path), response);
          return;
        }
        const headerText = request.headers["hyphae-transfer"] ?? request.headers["t3-mesh-transfer"];
        if (typeof headerText !== "string") throw new HttpError(400, "invalid", "missing transfer signature header");
        const decoded = Schema.decodeUnknownOption(SignedHeader)(Buffer.from(headerText, "base64url").toString("utf8"));
        if (decoded._tag === "None") throw new HttpError(400, "invalid", "invalid transfer signature header");
        // Refused or already stored transfers are answered before the body is read.
        const checked = core.transfers.check(connectorId, id, decoded.value);
        if (!checked.ok) {
          json(response, TRANSFER_STATUS[checked.error], { error: checked.error, message: checked.message });
          request.resume();
          return;
        }
        if (checked.duplicate) {
          json(response, 200, { status: "stored" });
          request.resume();
          return;
        }
        const upload = await streamToFile(request, core.transfers.uploadPath(id), checked.header.size);
        const result = core.transfers.store(decoded.value, checked.header, upload);
        if (result.ok) json(response, 200, { status: "stored" });
        else json(response, TRANSFER_STATUS[result.error], { error: result.error, message: result.message });
        return;
      }

      if (route === "PUT /v1/handles") {
        const body = decodeHandles(await readJson(request));
        if (body._tag === "None") throw new HttpError(400, "invalid", "expected {handles: string[]}");
        const result = core.setHandles(connectorId, body.value.handles);
        if (!result.ok) throw new HttpError(400, "invalid", `invalid handles: ${result.invalid.join(", ")}`);
        json(response, 200, { handles: body.value.handles });
        return;
      }
      if (route === "PUT /v1/subscriptions") {
        const body = decodeSubscriptions(await readJson(request, MAX_SUBSCRIPTIONS_BODY_BYTES));
        if (body._tag === "None") {
          throw new HttpError(400, "invalid", "expected {subscriptions: [{id, topic, filters, coalesceSeconds}]}");
        }
        if (body.value.subscriptions.length > 0 && !core.scopesOf(connectorId).has("events:subscribe")) {
          throw new HttpError(403, "not_granted", `${connectorId} is not granted events:subscribe`);
        }
        const result = core.events.setSubscriptions(connectorId, body.value.subscriptions);
        if (result.ok) {
          json(response, 200, {
            subscriptions: body.value.subscriptions.length,
            unknownTopics: result.unknownTopics,
            diagnostics: result.diagnostics,
          });
        } else {
          const { ok: _ok, ...error } = result;
          json(response, result.error === "id_conflict" ? 409 : 400, error);
        }
        return;
      }
      if (route === "POST /v1/messages") {
        const body = decodeSend(await readJson(request));
        if (body._tag === "None") throw new HttpError(400, "invalid", "expected {id, fromHandle, to, text}");
        const result = core.submit(connectorId, { ...body.value, origin: body.value.origin ?? null });
        if (result.ok) json(response, 200, { status: result.status });
        else json(response, SEND_STATUS[result.error], { error: result.error, message: result.message });
        return;
      }
      if (route === "POST /v1/channels/join") {
        const raw = await readJson(request);
        if (typeof raw !== "object" || raw === null || typeof (raw as Record<string, unknown>).channel !== "string" || typeof (raw as Record<string, unknown>).handle !== "string") {
          throw new HttpError(400, "invalid", "expected {channel, handle}");
        }
        const { channel, handle } = raw as { channel: string; handle: string };
        const result = core.joinChannel(connectorId, handle, channel);
        if (result.ok) json(response, 200, { channel: result.channel, address: result.address, members: result.members });
        else json(response, result.error === "not_enrolled" ? 403 : 400, { error: result.error, message: result.message });
        return;
      }
      if (route === "POST /v1/channels/leave") {
        const raw = await readJson(request);
        if (typeof raw !== "object" || raw === null || typeof (raw as Record<string, unknown>).channel !== "string" || typeof (raw as Record<string, unknown>).handle !== "string") {
          throw new HttpError(400, "invalid", "expected {channel, handle}");
        }
        const { channel, handle } = raw as { channel: string; handle: string };
        const result = core.leaveChannel(connectorId, handle, channel);
        if (result.ok) json(response, 200, { channel: result.channel, address: result.address, left: result.left });
        else json(response, 400, { error: result.error, message: result.message });
        return;
      }
      if (route === "GET /v1/channels") {
        const filter = url.searchParams.get("channel") ?? undefined;
        json(response, 200, { channels: core.channels(filter) });
        return;
      }
      if (route === "POST /v1/channels/post") {
        const raw = await readJson(request);
        const rec = raw as Record<string, unknown> | null;
        if (typeof rec !== "object" || rec === null || typeof rec.id !== "string" || typeof rec.channel !== "string" || typeof rec.fromHandle !== "string" || typeof rec.text !== "string") {
          throw new HttpError(400, "invalid", "expected {id, channel, fromHandle, text}");
        }
        const result = core.postChannel(connectorId, { id: rec.id, channel: rec.channel, fromHandle: rec.fromHandle, text: rec.text });
        if (result.ok) json(response, 200, { channel: result.channel, deliveredTo: result.deliveredTo, failed: result.failed });
        else json(response, result.error === "invalid" ? 400 : 403, { error: result.error, message: result.message });
        return;
      }
      const ackMatch = /^POST \/v1\/messages\/([^/]+)\/ack$/.exec(route);
      if (ackMatch?.[1] !== undefined) {
        const body = decodeAck(await readJson(request));
        if (body._tag === "None") throw new HttpError(400, "invalid", "expected {outcome, reason?}");
        const outcome = toRouterOutcome(body.value);
        const settled = core.ack(connectorId, decodeURIComponent(ackMatch[1]), outcome);
        json(response, settled ? 200 : 404, settled ? { ok: true } : { error: "not_found", message: "no such pending message" });
        return;
      }
      if (route === "GET /v1/subscriptions/status") {
        json(response, 200, { subscriptions: core.events.deliveryStatus(connectorId) });
        return;
      }
      if (route === "GET /v1/topics") {
        json(response, 200, { topics: core.events.topicCatalog() });
        return;
      }
      if (route === "GET /v1/peers") {
        json(response, 200, { peers: core.peers() });
        return;
      }
      if (route === "GET /v1/inbox") {
        response.writeHead(200, {
          "content-type": "text/event-stream",
          "cache-control": "no-cache",
          connection: "keep-alive",
        });
        response.write(": connected\n\n");
        const keepalive = setInterval(() => response.write(": keepalive\n\n"), KEEPALIVE_MS);
        const detach = core.attach(connectorId, (item) => {
          response.write(`event: ${item.kind}\ndata: ${JSON.stringify(item)}\n\n`);
        });
        log("info", "inbox.attached", { connector: connectorId });
        request.on("close", () => {
          clearInterval(keepalive);
          detach();
          log("info", "inbox.detached", { connector: connectorId });
        });
        return;
      }
      throw new HttpError(404, "not_found", `no route ${route}`);
    } catch (error) {
      // A streamed download failed mid-body: the status is already sent, so end the connection.
      if (response.headersSent) {
        log("warn", "router.response_failed", { error: errorMessage(error) });
        response.destroy();
        return;
      }
      if (error instanceof HttpError) {
        json(response, error.status, { error: error.code, message: error.message });
      } else {
        log("error", "router.request_failed", { error: errorMessage(error) });
        json(response, 500, { error: "internal", message: "internal error" });
      }
    }
  });
  await new Promise<void>((resolve) => server.listen(options.port, options.host, resolve));
  const address = server.address();
  if (address === null || typeof address === "string") throw new Error("router is not listening on TCP");
  const { port } = address;
  log("info", "router.listening", { host: options.host, port, topics: [...core.events.topics.keys()] });
  for (const missing of core.events.unprovisionedPublishers()) {
    log("warn", "router.publisher_missing", { ...missing, hint: "add-publisher <id> --topic <topic>" });
  }
  return {
    url: `http://${options.host}:${port}`,
    close: () =>
      new Promise<void>((resolve) => {
        closed = true;
        core.setScheduleListener(null);
        if (tickTimer !== null) {
          clearTimeout(tickTimer);
          tickTimer = null;
        }
        server.closeAllConnections();
        server.close(() => resolve());
      }),
  };
}
