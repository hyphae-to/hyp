#!/usr/bin/env node
/**
 * Built-in zero-dependency WhatsApp Business Cloud API plugin for Hyphae (Node 24+).
 * Receives Meta Cloud API webhooks (GET verification + signed POST messages) and supports
 * outbound replies via `mesh.onPost` (`hyp_plugin_post`).
 *
 * Configuration via env:
 *   WHATSAPP_HOST                                       - Bind host (default 127.0.0.1)
 *   WHATSAPP_PORT                                       - Bind port (default 8796)
 *   WHATSAPP_PATH                                       - Webhook path (default /whatsapp)
 *   WHATSAPP_TARGET                                     - Target name (defaults to "whatsapp" or first target in hello)
 *   WHATSAPP_VERIFY_TOKEN_FILE or WHATSAPP_VERIFY_TOKEN - Meta webhook verification token (GET handshake)
 *   WHATSAPP_APP_SECRET_FILE or WHATSAPP_APP_SECRET     - Meta App Secret for X-Hub-Signature-256 HMAC verification
 *   WHATSAPP_ALLOW_UNSIGNED                             - Set to "1" to explicitly allow unsigned POSTs without WHATSAPP_APP_SECRET
 *   WHATSAPP_ACCESS_TOKEN_FILE or WHATSAPP_ACCESS_TOKEN - Meta Cloud API bearer token for outbound sends
 *   WHATSAPP_PHONE_NUMBER_ID                            - WhatsApp Business Phone Number ID
 *   WHATSAPP_ALLOWED_NUMBERS                            - Comma-separated allowlisted E.164 / digit phone numbers
 *   WHATSAPP_ALLOW_ALL                                  - Set to "1" to explicitly allow any sender/recipient
 *   WHATSAPP_DEFAULT_TO                                 - Optional default outbound recipient phone number
 *   WHATSAPP_API_BASE                                   - Graph API base URL (default https://graph.facebook.com/v21.0)
 */
import { createHmac, randomUUID, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { MeshPluginClient } from "../sdk/client.mjs";

const MAX_BODY_BYTES = 1024 * 1024;

function readOptionalSecret(fileEnv, valEnv) {
  const file = process.env[fileEnv]?.trim();
  if (file) {
    const value = readFileSync(file, "utf8").trim();
    return value || null;
  }
  const value = process.env[valEnv]?.trim();
  return value || null;
}

function normalizePhone(raw) {
  return String(raw ?? "").replace(/\D/g, "");
}

function parseAllowedNumbers(name) {
  const raw = process.env[name]?.trim();
  if (!raw) return null;
  const normalized = raw
    .split(",")
    .map((entry) => normalizePhone(entry))
    .filter(Boolean);
  return normalized.length > 0 ? new Set(normalized) : null;
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const bufA = Buffer.from(a, "utf8");
  const bufB = Buffer.from(b, "utf8");
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

function sendJson(res, status, body, extraHeaders = {}) {
  res
    .writeHead(status, { "content-type": "application/json; charset=utf-8", ...extraHeaders })
    .end(JSON.stringify(body));
}

async function readRawBody(req, maxBytes) {
  const contentLength = Number(req.headers["content-length"]);
  if (Number.isFinite(contentLength) && contentLength > maxBytes) {
    return null;
  }
  const chunks = [];
  let bytes = 0;
  for await (const chunk of req) {
    bytes += chunk.length;
    if (bytes > maxBytes) {
      return null;
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
}

function extractMessageText(msg) {
  const type = typeof msg.type === "string" ? msg.type : "unknown";
  let text = "";
  if (type === "text" && typeof msg.text?.body === "string") {
    text = msg.text.body;
  } else if (type === "image") {
    text = msg.image?.caption ? `[image] ${msg.image.caption}` : "[image]";
  } else if (type === "video") {
    text = msg.video?.caption ? `[video] ${msg.video.caption}` : "[video]";
  } else if (type === "document") {
    const filename = msg.document?.filename ? ` (${msg.document.filename})` : "";
    text = msg.document?.caption ? `[document${filename}] ${msg.document.caption}` : `[document${filename}]`;
  } else if (type === "audio") {
    text = msg.audio?.voice ? "[voice]" : "[audio]";
  } else if (type === "sticker") {
    text = "[sticker]";
  } else if (type === "button") {
    text = msg.button?.text || msg.button?.payload || "[button]";
  } else if (type === "interactive") {
    const interactive = msg.interactive;
    text =
      interactive?.button_reply?.title ||
      interactive?.list_reply?.title ||
      interactive?.button_reply?.id ||
      interactive?.list_reply?.id ||
      "[interactive]";
  } else if (type === "location") {
    const loc = msg.location;
    text = loc?.name ? `[location] ${loc.name}` : `[location: ${loc?.latitude ?? "?"},${loc?.longitude ?? "?"}]`;
  } else if (type === "reaction") {
    text = msg.reaction?.emoji ? `[reaction] ${msg.reaction.emoji}` : "[reaction]";
  } else if (typeof msg.text?.body === "string") {
    text = msg.text.body;
  } else {
    text = `[${type}]`;
  }
  return String(text).slice(0, 4000);
}

const host = process.env.WHATSAPP_HOST?.trim() || "127.0.0.1";
const port = Number(process.env.WHATSAPP_PORT ?? "8796");
if (!Number.isInteger(port) || port < 0 || port > 65535) {
  throw new Error(`Invalid WHATSAPP_PORT: ${process.env.WHATSAPP_PORT}`);
}
const rawPath = process.env.WHATSAPP_PATH?.trim() || "/whatsapp";
const expectedPath = rawPath.startsWith("/") ? rawPath : `/${rawPath}`;

const verifyToken = readOptionalSecret("WHATSAPP_VERIFY_TOKEN_FILE", "WHATSAPP_VERIFY_TOKEN");
const appSecret = readOptionalSecret("WHATSAPP_APP_SECRET_FILE", "WHATSAPP_APP_SECRET");
const accessToken = readOptionalSecret("WHATSAPP_ACCESS_TOKEN_FILE", "WHATSAPP_ACCESS_TOKEN");
const configuredPhoneNumberId = process.env.WHATSAPP_PHONE_NUMBER_ID?.trim() || null;
const defaultTo = process.env.WHATSAPP_DEFAULT_TO?.trim() || null;

function resolveApiBase(raw, fallback) {
  const value = (raw?.trim() || fallback).replace(/\/+$/, "");
  const parsed = new URL(value);
  const loopback = ["127.0.0.1", "localhost", "[::1]"].includes(parsed.hostname);
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback)) {
    throw new Error(`WHATSAPP_API_BASE must use https:// or loopback http:// (got ${value})`);
  }
  return value;
}

const apiBase = resolveApiBase(process.env.WHATSAPP_API_BASE, "https://graph.facebook.com/v21.0");
const allowedNumbers = parseAllowedNumbers("WHATSAPP_ALLOWED_NUMBERS");
const allowAll = process.env.WHATSAPP_ALLOW_ALL === "1";
const allowUnsigned = process.env.WHATSAPP_ALLOW_UNSIGNED === "1";

if (!allowedNumbers && !allowAll) {
  throw new Error(
    "Refusing to start WhatsApp bridge without WHATSAPP_ALLOWED_NUMBERS (set WHATSAPP_ALLOW_ALL=1 to explicitly allow any sender)",
  );
}

let lastFrom = null;
let lastPhoneNumberId = configuredPhoneNumberId;
const seenRecipients = new Set();
const lastMessageIdByRecipient = new Map();

const mesh = new MeshPluginClient({
  onDeliveryFailed: (msg) =>
    console.error(`whatsapp plugin delivery_failed target=${msg.target} reason=${msg.reason}`),
});

async function sendWhatsAppMessage(phoneNumberId, payload) {
  const endpoint = `${apiBase}/${encodeURIComponent(phoneNumberId)}/messages`;
  const res = await fetch(endpoint, {
    method: "POST",
    headers: {
      authorization: `Bearer ${accessToken}`,
      "content-type": "application/json; charset=utf-8",
    },
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(15_000),
  });
  const respText = await res.text();
  let json = null;
  try {
    json = respText ? JSON.parse(respText) : null;
  } catch {}
  if (!res.ok) {
    const detail = json?.error?.message || respText.slice(0, 300) || `HTTP ${res.status}`;
    throw new Error(`WhatsApp Cloud API POST failed (${res.status}): ${detail}`);
  }
  return json;
}

mesh.onPost(async (params) => {
  const hasReaction = typeof params?.reaction === "string";
  const reaction = hasReaction ? params.reaction.trim() : "";
  const rawText = typeof params?.text === "string" ? params.text : "";
  const hasText = rawText.trim().length > 0;
  if (!hasReaction && !hasText) {
    throw new Error("WhatsApp post requires non-empty text or reaction");
  }
  if (!accessToken) {
    throw new Error("WHATSAPP_ACCESS_TOKEN (or WHATSAPP_ACCESS_TOKEN_FILE) is not configured");
  }
  const phoneNumberId = configuredPhoneNumberId || lastPhoneNumberId;
  if (!phoneNumberId) {
    throw new Error("WHATSAPP_PHONE_NUMBER_ID is not configured and no inbound message has established one");
  }
  const explicitRecipient =
    (typeof params?.to === "string" && params.to.trim()) ||
    (typeof params?.chatId === "string" && params.chatId.trim()) ||
    (typeof params?.channel === "string" && params.channel.trim()) ||
    "";
  let rawRecipient = explicitRecipient;
  if (!rawRecipient) {
    if (defaultTo) {
      rawRecipient = defaultTo;
    } else if (seenRecipients.size > 1) {
      throw new Error(
        "Multiple WhatsApp recipients have been seen; specify an explicit recipient (to) or set WHATSAPP_DEFAULT_TO",
      );
    } else if (lastFrom) {
      rawRecipient = lastFrom;
    }
  }
  if (!rawRecipient) {
    throw new Error("WhatsApp post requires recipient (to, WHATSAPP_DEFAULT_TO, or prior inbound message)");
  }
  const recipient = normalizePhone(rawRecipient);
  if (!recipient) {
    throw new Error("WhatsApp post recipient must contain phone digits");
  }
  if (!allowAll && (!allowedNumbers || !allowedNumbers.has(recipient))) {
    throw new Error(`Outbound recipient ${recipient} is not in WHATSAPP_ALLOWED_NUMBERS`);
  }

  const replyTo = typeof params?.replyTo === "string" && params.replyTo.trim() ? params.replyTo.trim() : undefined;

  let targetMsgId;
  let reactionJson = null;
  if (hasReaction) {
    targetMsgId = replyTo ?? lastMessageIdByRecipient.get(recipient);
    if (!targetMsgId) {
      throw new Error(`No WhatsApp message_id specified via replyTo and no recent inbound message from ${recipient} to react to`);
    }
    reactionJson = await sendWhatsAppMessage(phoneNumberId, {
      messaging_product: "whatsapp",
      recipient_type: "individual",
      to: recipient,
      type: "reaction",
      reaction: {
        message_id: targetMsgId,
        emoji: reaction,
      },
    });
  }

  let textJson = null;
  if (hasText) {
    textJson = await sendWhatsAppMessage(phoneNumberId, {
      messaging_product: "whatsapp",
      recipient_type: "individual",
      to: recipient,
      type: "text",
      text: { preview_url: false, body: rawText },
      ...(replyTo ? { context: { message_id: replyTo } } : {}),
    });
  }

  return {
    ok: true,
    to: recipient,
    phoneNumberId,
    ...(hasReaction
      ? {
          reacted: true,
          reaction,
          reactedMessageId: targetMsgId,
          reactionMessageId: reactionJson?.messages?.[0]?.id ?? null,
        }
      : {}),
    ...(hasText ? { messageId: textJson?.messages?.[0]?.id ?? null } : {}),
  };
});

const hello = await mesh.ready;
const target =
  process.env.WHATSAPP_TARGET?.trim() ||
  (hello.targets.includes("whatsapp") ? "whatsapp" : hello.targets[0]);
if (!target || !hello.targets.includes(target)) {
  throw new Error(`Target '${target}' not in configured targets: ${hello.targets.join(", ")}`);
}

const server = createServer(async (req, res) => {
  const url = new URL(req.url ?? "/", "http://localhost");

  if (req.method === "GET" && url.pathname === "/health" && expectedPath !== "/health") {
    sendJson(res, 200, { ok: true, protocol: "whatsapp-cloud", lastMessageId: lastMessageIdByRecipient.size > 0 });
    return;
  }

  if (url.pathname !== expectedPath) {
    sendJson(res, 404, { error: "not_found" });
    return;
  }

  if (req.method === "GET") {
    const mode = url.searchParams.get("hub.mode");
    const token = url.searchParams.get("hub.verify_token");
    const challenge = url.searchParams.get("hub.challenge");
    if (!verifyToken || mode !== "subscribe" || !token || !safeEqual(token, verifyToken)) {
      sendJson(res, 403, { error: "forbidden" });
      return;
    }
    if (!challenge) {
      sendJson(res, 400, { error: "missing_challenge" });
      return;
    }
    res.writeHead(200, { "content-type": "text/plain; charset=utf-8" }).end(challenge);
    return;
  }

  if (req.method !== "POST") {
    sendJson(res, 405, { error: "method_not_allowed" });
    return;
  }

  const raw = await readRawBody(req, MAX_BODY_BYTES);
  if (raw === null) {
    sendJson(res, 413, { error: "payload_too_large" }, { connection: "close" });
    return;
  }

  if (appSecret) {
    const header = req.headers["x-hub-signature-256"];
    const expected = "sha256=" + createHmac("sha256", appSecret).update(raw).digest("hex");
    if (typeof header !== "string" || !safeEqual(header.toLowerCase(), expected)) {
      sendJson(res, 401, { error: "invalid_signature" });
      return;
    }
  } else if (!allowUnsigned) {
    sendJson(res, 403, { error: "app_secret_not_configured" });
    return;
  }

  let payload;
  try {
    payload = JSON.parse(raw.toString("utf8"));
  } catch {
    sendJson(res, 400, { error: "invalid_json" });
    return;
  }
  if (!payload || typeof payload !== "object" || Array.isArray(payload)) {
    sendJson(res, 400, { error: "invalid_payload" });
    return;
  }

  let delivered = 0;
  let ignored = 0;

  const entries = Array.isArray(payload.entry) ? payload.entry : [];
  for (const entry of entries) {
    const changes = Array.isArray(entry?.changes) ? entry.changes : [];
    for (const change of changes) {
      const value = change?.value;
      if (!value || typeof value !== "object") continue;

      const phoneNumberId =
        (typeof value.metadata?.phone_number_id === "string" && value.metadata.phone_number_id.trim()) ||
        configuredPhoneNumberId ||
        null;

      const contactsByPhone = new Map();
      if (Array.isArray(value.contacts)) {
        for (const contact of value.contacts) {
          const waId = normalizePhone(contact?.wa_id);
          const profileName = typeof contact?.profile?.name === "string" ? contact.profile.name : null;
          if (waId && profileName) contactsByPhone.set(waId, profileName);
        }
      }

      const messages = Array.isArray(value.messages) ? value.messages : [];
      for (const msg of messages) {
        if (!msg || typeof msg !== "object") continue;
        const fromRaw = typeof msg.from === "string" ? msg.from.trim() : "";
        const fromNorm = normalizePhone(fromRaw);

        if (!allowAll && (!allowedNumbers || !fromNorm || !allowedNumbers.has(fromNorm))) {
          ignored += 1;
          console.error(
            `whatsapp ignored message from non-allowlisted sender id=${typeof msg.id === "string" ? msg.id.slice(0, 64) : "unknown"}`,
          );
          continue;
        }

        const text = extractMessageText(msg);
        const fromValue = fromRaw || fromNorm;
        lastFrom = fromValue;
        if (fromNorm) {
          seenRecipients.add(fromNorm);
        }
        if (phoneNumberId) lastPhoneNumberId = phoneNumberId;
        if (typeof msg.id === "string" && msg.id.trim()) {
          const cleanMsgId = msg.id.trim();
          if (fromNorm) {
            lastMessageIdByRecipient.set(fromNorm, cleanMsgId);
            if (lastMessageIdByRecipient.size > 1000) {
              lastMessageIdByRecipient.delete(lastMessageIdByRecipient.keys().next().value);
            }
          }
        }

        const tsNum =
          msg.timestamp !== undefined && msg.timestamp !== null && String(msg.timestamp).trim() !== ""
            ? Number(msg.timestamp)
            : Number.NaN;
        const eventTime =
          Number.isFinite(tsNum) && tsNum > 0
            ? new Date(tsNum * 1000).toISOString()
            : new Date().toISOString();

        const eventId = (typeof msg.id === "string" && msg.id.trim() ? msg.id.trim() : randomUUID()).slice(0, 256);
        const event = {
          specversion: "1.0",
          id: eventId,
          type: "com.whatsapp.message.received",
          source: `whatsapp/${(phoneNumberId || "unknown").slice(0, 200)}`,
          subject: `wa/${fromValue.slice(0, 200)}`,
          time: eventTime,
          datacontenttype: "application/json",
          data: {
            from: fromValue,
            name: contactsByPhone.get(fromNorm) ?? null,
            message_id: typeof msg.id === "string" ? msg.id : null,
            type: typeof msg.type === "string" ? msg.type : "unknown",
            text,
            phone_number_id: phoneNumberId,
          },
        };

        try {
          const reply = await mesh.send(target, event);
          if (reply.type === "ack") {
            delivered += 1;
          } else {
            console.error(`whatsapp mesh nack id=${eventId} error=${reply.error ?? reply.reason ?? "unknown"}`);
            if (reply.error === "unavailable" || reply.reason === "unavailable") {
              sendJson(res, 503, { ok: false, error: "mesh_unavailable", delivered, ignored });
              return;
            }
          }
        } catch (error) {
          console.error(`whatsapp mesh send error: ${error instanceof Error ? error.message : String(error)}`);
          sendJson(res, 503, { ok: false, error: "mesh_error", delivered, ignored });
          return;
        }
      }
    }
  }

  sendJson(res, 200, { ok: true, delivered, ignored });
});

server.on("error", (error) => {
  console.error(`whatsapp server error: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
});

let shuttingDown = false;
function shutdown(signal = "SIGTERM") {
  if (shuttingDown) return;
  shuttingDown = true;
  const finish = () => {
    process.removeListener("SIGTERM", shutdown);
    process.removeListener("SIGINT", shutdown);
    try {
      process.kill(process.pid, signal);
    } catch {
      process.exit(0);
    }
  };
  server.close(finish);
  server.closeAllConnections?.();
  setTimeout(finish, 2_000).unref();
}
process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);

server.listen(port, host, () => {
  const addr = server.address();
  const actualPort = addr && typeof addr === "object" ? addr.port : port;
  console.error(
    `whatsapp plugin ready protocol=whatsapp-cloud listen=http://${host}:${actualPort}${expectedPath} target=${target}`,
  );
});
