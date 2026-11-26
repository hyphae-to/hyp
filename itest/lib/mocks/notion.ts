/**
 * Loopback Notion `POST /v1/search` poll API (`127.0.0.1:0`) + webhook emitter supporting BOTH:
 *  1. One-time unsigned `{ verification_token }` setup handshake (1st valid + 2nd hijack attempt!)
 *  2. Signed `x-notion-signature: sha256=<hex>` event deliveries (with 1-bit tamper helper)
 */

import http from "node:http";
import { closeHttpServer, flipHexBit, hmacHex, readHttpBody, writeJson } from "./helpers.ts";

export interface NotionMockPage {
  id: string;
  title: string;
  created_time: string;
  last_edited_time: string;
  url?: string;
  in_trash?: boolean;
  archived?: boolean;
  parent?: Record<string, unknown>;
  last_edited_by?: { id: string };
}

export interface RecordedNotionSearch {
  authorization: string | null;
  notionVersion: string | null;
  body: Record<string, any>;
  status: number;
}

export interface NotionMockOptions {
  token: string;
  expectedVersion?: string;
  pageSize?: number;
}

export class NotionMockServer {
  readonly server: http.Server;
  readonly port: number;
  readonly apiBase: string;
  readonly requests: RecordedNotionSearch[] = [];

  private readonly token: string;
  private readonly expectedVersion: string | null;
  private readonly pageSize: number;
  private pages: NotionMockPage[] = [];

  private constructor(server: http.Server, port: number, options: NotionMockOptions) {
    this.server = server;
    this.port = port;
    this.apiBase = `http://127.0.0.1:${port}`;
    this.token = options.token;
    this.expectedVersion = options.expectedVersion ?? null;
    this.pageSize = options.pageSize ?? 50;
  }

  static async start(options: NotionMockOptions): Promise<NotionMockServer> {
    let instance!: NotionMockServer;

    const server = http.createServer(async (req, res) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      if (req.method !== "POST" || url.pathname !== "/v1/search") {
        writeJson(res, 404, { object: "error", status: 404, message: "Not Found" });
        return;
      }
      const auth =
        typeof req.headers.authorization === "string" ? req.headers.authorization : null;
      const notionVersion =
        typeof req.headers["notion-version"] === "string" ? req.headers["notion-version"] : null;
      const raw = await readHttpBody(req);
      let body: Record<string, any> = {};
      try {
        body = JSON.parse(raw.toString("utf8"));
      } catch {
        body = {};
      }

      const finish = (status: number, payload: unknown) => {
        instance.requests.push({ authorization: auth, notionVersion, body, status });
        writeJson(res, status, payload);
      };

      if (auth !== `Bearer ${instance.token}`) {
        finish(401, { object: "error", status: 401, code: "unauthorized", message: "API token is invalid." });
        return;
      }
      if (instance.expectedVersion && notionVersion !== instance.expectedVersion) {
        finish(400, { object: "error", status: 400, message: `Unexpected Notion-Version: ${notionVersion}` });
        return;
      }

      const sorted = [...instance.pages].sort(
        (a, b) => Date.parse(b.last_edited_time) - Date.parse(a.last_edited_time),
      );
      const offset = Number(body.start_cursor ?? "0") || 0;
      const limit = Math.min(Number(body.page_size ?? instance.pageSize) || instance.pageSize, instance.pageSize);
      const slice = sorted.slice(offset, offset + limit);
      const nextOffset = offset + slice.length;
      const hasMore = nextOffset < sorted.length;

      finish(200, {
        object: "list",
        has_more: hasMore,
        next_cursor: hasMore ? String(nextOffset) : null,
        results: slice.map((p) => ({
          object: "page",
          id: p.id,
          created_time: p.created_time,
          last_edited_time: p.last_edited_time,
          url: p.url ?? `https://notion.so/${p.id}`,
          in_trash: Boolean(p.in_trash),
          archived: Boolean(p.archived),
          parent: p.parent ?? { type: "workspace", workspace: true },
          last_edited_by: p.last_edited_by ?? { id: "user-itest" },
          properties: {
            Name: {
              id: "title",
              type: "title",
              title: [{ plain_text: p.title }],
            },
          },
        })),
      });
    });

    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = server.address();
    const port = typeof addr === "object" && addr ? addr.port : 0;
    instance = new NotionMockServer(server, port, options);
    return instance;
  }

  setPages(pages: NotionMockPage[]): void {
    this.pages = [...pages];
  }

  upsertPage(page: NotionMockPage): void {
    const idx = this.pages.findIndex((p) => p.id === page.id);
    if (idx >= 0) this.pages[idx] = { ...page };
    else this.pages.unshift({ ...page });
  }

  close(): Promise<void> {
    return closeHttpServer(this.server);
  }
}

/** Sends Notion's one-time unsigned `{ verification_token }` handshake POST. */
export async function sendNotionVerificationHandshake(
  webhookUrl: string,
  verificationToken: string,
): Promise<{ status: number; json: any; text: string }> {
  const res = await fetch(webhookUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ verification_token: verificationToken }),
  });
  const text = await res.text();
  let json: any = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return { status: res.status, json, text };
}

/** Computes `sha256=<lowercase hex>` for Notion's `X-Notion-Signature` header. */
export function signNotionWebhook(raw: string | Buffer, verificationToken: string): string {
  return `sha256=${hmacHex("sha256", verificationToken, raw)}`;
}

/** Sends a signed (or 1-bit tampered / unsigned) Notion webhook event POST. */
export async function sendNotionWebhookEvent(
  webhookUrl: string,
  opts: {
    payload: unknown;
    verificationToken: string;
    tamperSignature?: boolean;
    omitSignature?: boolean;
  },
): Promise<{ status: number; json: any; text: string; signature?: string }> {
  const raw = typeof opts.payload === "string" ? opts.payload : JSON.stringify(opts.payload);
  const headers: Record<string, string> = { "content-type": "application/json" };
  let signature: string | undefined;
  if (!opts.omitSignature) {
    const valid = signNotionWebhook(raw, opts.verificationToken);
    signature = opts.tamperSignature ? flipHexBit(valid) : valid;
    headers["x-notion-signature"] = signature;
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
