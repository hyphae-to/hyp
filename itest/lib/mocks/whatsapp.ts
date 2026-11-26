/**
 * Loopback Meta WhatsApp Business Cloud API wire-mock (`127.0.0.1:0`) + signed webhook emitter.
 *
 * Implements:
 *  - Outbound Graph API mock: `POST /<phoneNumberId>/messages` (validates `Bearer <accessToken>`,
 *    records text & reaction outbound payloads)
 *  - Inbound `GET` subscribe challenge helper (`hub.mode=subscribe`, `hub.verify_token`, `hub.challenge`)
 *  - Inbound `POST` webhook emitter with `X-Hub-Signature-256: sha256=<hex>` + 1-bit tamper mode
 */

import http from "node:http";
import { closeHttpServer, flipHexBit, hmacHex, readHttpBody, waitUntil, writeJson } from "./helpers.ts";

export interface RecordedWhatsAppOutbound {
  phoneNumberId: string;
  authorization: string;
  body: Record<string, any>;
  messageId: string;
}

export interface WhatsAppMockOptions {
  accessToken: string;
  phoneNumberId?: string;
}

export class WhatsAppMockServer {
  readonly server: http.Server;
  readonly port: number;
  readonly apiBase: string;
  readonly accessToken: string;
  readonly outbound: RecordedWhatsAppOutbound[] = [];

  private nextMsgSeq = 1;

  private constructor(server: http.Server, port: number, options: WhatsAppMockOptions) {
    this.server = server;
    this.port = port;
    this.apiBase = `http://127.0.0.1:${port}/v21.0`;
    this.accessToken = options.accessToken;
  }

  static async start(options: WhatsAppMockOptions): Promise<WhatsAppMockServer> {
    let instance!: WhatsAppMockServer;

    const server = http.createServer(async (req, res) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      const match = /^\/(?:v[\d.]+\/)?([^/]+)\/messages$/.exec(url.pathname);
      if (req.method !== "POST" || !match) {
        writeJson(res, 404, { error: { message: "Not Found", code: 404 } });
        return;
      }
      const auth = String(req.headers.authorization ?? "");
      if (auth !== `Bearer ${options.accessToken}`) {
        writeJson(res, 401, { error: { message: "Invalid OAuth access token", code: 190 } });
        return;
      }

      const raw = await readHttpBody(req);
      let body: Record<string, any> = {};
      try {
        body = JSON.parse(raw.toString("utf8"));
      } catch {
        writeJson(res, 400, { error: { message: "Invalid JSON" } });
        return;
      }

      const phoneNumberId = decodeURIComponent(match[1]);
      const messageId = `wamid.out.${instance.nextMsgSeq++}`;
      instance.outbound.push({
        phoneNumberId,
        authorization: auth,
        body,
        messageId,
      });

      writeJson(res, 200, {
        messaging_product: "whatsapp",
        contacts: [{ input: body.to, wa_id: body.to }],
        messages: [{ id: messageId }],
      });
    });

    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = server.address();
    const port = typeof addr === "object" && addr ? addr.port : 0;
    instance = new WhatsAppMockServer(server, port, options);
    return instance;
  }

  waitForOutbound(
    predicate: (rec: RecordedWhatsAppOutbound) => boolean,
    timeoutMs = 15_000,
  ): Promise<RecordedWhatsAppOutbound> {
    return waitUntil(
      () => this.outbound.find(predicate) ?? false,
      "whatsapp outbound message",
      timeoutMs,
    );
  }

  close(): Promise<void> {
    return closeHttpServer(this.server);
  }
}

/** Issues Meta's `GET` webhook subscribe verification handshake. */
export async function sendWhatsAppVerifyChallenge(
  webhookUrl: string,
  opts: { mode?: string; verifyToken: string; challenge: string },
): Promise<{ status: number; text: string }> {
  const url = new URL(webhookUrl);
  url.searchParams.set("hub.mode", opts.mode ?? "subscribe");
  url.searchParams.set("hub.verify_token", opts.verifyToken);
  url.searchParams.set("hub.challenge", opts.challenge);
  const res = await fetch(url);
  return { status: res.status, text: await res.text() };
}

/** Builds an authentic Meta WhatsApp Cloud API inbound webhook JSON payload. */
export function buildWhatsAppWebhookPayload(opts: {
  phoneNumberId: string;
  from: string;
  contactName?: string;
  messageId: string;
  text?: string;
  type?: string;
  extraMessageFields?: Record<string, unknown>;
  timestamp?: number;
}): Record<string, unknown> {
  const type = opts.type ?? "text";
  const msg: Record<string, unknown> = {
    from: opts.from,
    id: opts.messageId,
    timestamp: String(opts.timestamp ?? Math.floor(Date.now() / 1000)),
    type,
    ...(type === "text" ? { text: { body: opts.text ?? "" } } : {}),
    ...(opts.extraMessageFields ?? {}),
  };
  return {
    object: "whatsapp_business_account",
    entry: [
      {
        id: "WABA_ITEST",
        changes: [
          {
            field: "messages",
            value: {
              messaging_product: "whatsapp",
              metadata: {
                display_phone_number: "15550001234",
                phone_number_id: opts.phoneNumberId,
              },
              contacts: [
                {
                  profile: { name: opts.contactName ?? "Alice" },
                  wa_id: opts.from.replace(/\D/g, ""),
                },
              ],
              messages: [msg],
            },
          },
        ],
      },
    ],
  };
}

/** Computes `sha256=<hex>` HMAC signature for Meta Cloud API webhooks. */
export function signWhatsAppWebhook(raw: string | Buffer, appSecret: string): string {
  return `sha256=${hmacHex("sha256", appSecret, raw)}`;
}

/** Sends a signed (or 1-bit tampered / unsigned) Meta Cloud API webhook POST. */
export async function sendWhatsAppWebhook(
  webhookUrl: string,
  opts: {
    payload: unknown;
    appSecret: string;
    tamperSignature?: boolean;
    omitSignature?: boolean;
  },
): Promise<{ status: number; json: any; text: string; signature?: string }> {
  const raw = typeof opts.payload === "string" ? opts.payload : JSON.stringify(opts.payload);
  const headers: Record<string, string> = { "content-type": "application/json" };
  let signature: string | undefined;
  if (!opts.omitSignature) {
    const valid = signWhatsAppWebhook(raw, opts.appSecret);
    signature = opts.tamperSignature ? flipHexBit(valid) : valid;
    headers["x-hub-signature-256"] = signature;
  }
  const res = await fetch(webhookUrl, { method: "POST", headers, body: raw });
  const text = await res.text();
  let json: any = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return { status: res.status, json, text, signature };
}
