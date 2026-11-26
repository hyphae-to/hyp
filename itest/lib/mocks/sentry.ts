/**
 * Loopback Sentry organization issues REST poll API (`127.0.0.1:0`) + signed
 * `Sentry-Hook-Signature` (raw lowercase hex HMAC-SHA256) webhook emitter.
 */

import http from "node:http";
import { closeHttpServer, flipHexBit, hmacHex, writeJson } from "./helpers.ts";

export interface SentryMockIssue {
  id: string;
  shortId: string;
  title: string;
  culprit?: string;
  level?: string;
  status?: string;
  substatus?: string;
  firstSeen: string;
  lastSeen?: string;
  count?: string | number;
  userCount?: number;
  isUnhandled?: boolean;
  permalink?: string;
  project: { slug: string; platform?: string };
}

export interface RecordedSentryRequest {
  org: string;
  projects: string[];
  environments: string[];
  query: string | null;
  authorization: string | null;
  status: number;
}

export interface SentryMockOptions {
  authToken: string;
  org: string;
}

export class SentryMockServer {
  readonly server: http.Server;
  readonly port: number;
  readonly apiBase: string;
  readonly requests: RecordedSentryRequest[] = [];

  private readonly authToken: string;
  private readonly org: string;
  private issues: SentryMockIssue[] = [];
  private next429RetryAfter: number | null = null;

  private constructor(server: http.Server, port: number, options: SentryMockOptions) {
    this.server = server;
    this.port = port;
    this.apiBase = `http://127.0.0.1:${port}`;
    this.authToken = options.authToken;
    this.org = options.org;
  }

  static async start(options: SentryMockOptions): Promise<SentryMockServer> {
    let instance!: SentryMockServer;

    const server = http.createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      const match = /^\/api\/0\/organizations\/([^/]+)\/issues\/?$/.exec(url.pathname);
      if (req.method !== "GET" || !match) {
        writeJson(res, 404, { detail: "Not Found" });
        return;
      }
      const org = decodeURIComponent(match[1]);
      const auth =
        typeof req.headers.authorization === "string" ? req.headers.authorization : null;
      const projects = url.searchParams.getAll("project");
      const environments = url.searchParams.getAll("environment");
      const query = url.searchParams.get("query");

      const finish = (status: number, body: unknown, extraHeaders: Record<string, string> = {}) => {
        instance.requests.push({ org, projects, environments, query, authorization: auth, status });
        writeJson(res, status, body, extraHeaders);
      };

      if (auth !== `Bearer ${instance.authToken}`) {
        finish(401, { detail: "Invalid token" });
        return;
      }
      if (org !== instance.org) {
        finish(404, { detail: "Organization not found" });
        return;
      }
      if (instance.next429RetryAfter !== null) {
        const retryAfter = instance.next429RetryAfter;
        instance.next429RetryAfter = null;
        finish(429, { detail: "Rate limit exceeded" }, { "retry-after": String(retryAfter) });
        return;
      }

      let filtered = [...instance.issues];
      if (projects.length > 0) {
        const allow = new Set(projects);
        filtered = filtered.filter((i) => allow.has(i.project.slug));
      }
      finish(200, filtered);
    });

    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = server.address();
    const port = typeof addr === "object" && addr ? addr.port : 0;
    instance = new SentryMockServer(server, port, options);
    return instance;
  }

  setIssues(issues: SentryMockIssue[]): void {
    this.issues = [...issues];
  }

  addIssue(issue: SentryMockIssue): void {
    this.issues.unshift(issue);
  }

  failNextWith429(retryAfterSec = 1): void {
    this.next429RetryAfter = retryAfterSec;
  }

  close(): Promise<void> {
    return closeHttpServer(this.server);
  }
}

/** Computes raw lowercase hex HMAC-SHA256 for Sentry's `Sentry-Hook-Signature` header (no prefix!). */
export function signSentryWebhook(raw: string | Buffer, clientSecret: string): string {
  return hmacHex("sha256", clientSecret, raw);
}

/** Sends a signed (or 1-bit tampered / unsigned) Sentry internal-integration webhook POST. */
export async function sendSentryWebhook(
  webhookUrl: string,
  opts: {
    resource: "issue" | "error" | "event_alert" | "metric_alert" | "comment" | "installation";
    payload: unknown;
    clientSecret: string;
    tamperSignature?: boolean;
    omitSignature?: boolean;
    requestId?: string;
  },
): Promise<{ status: number; json: any; text: string; signature?: string }> {
  const raw = typeof opts.payload === "string" ? opts.payload : JSON.stringify(opts.payload);
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "sentry-hook-resource": opts.resource,
    ...(opts.requestId ? { "request-id": opts.requestId } : {}),
  };
  let signature: string | undefined;
  if (!opts.omitSignature) {
    const valid = signSentryWebhook(raw, opts.clientSecret);
    signature = opts.tamperSignature ? flipHexBit(valid) : valid;
    headers["sentry-hook-signature"] = signature;
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
