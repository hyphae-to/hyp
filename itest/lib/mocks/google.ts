/**
 * Loopback Google OAuth2 PKCE + Gmail History API + Google Calendar v3 API wire-mocks (`127.0.0.1:0`).
 *
 * Implements:
 *  - `GoogleOAuthMockServer`: RFC 7636 PKCE (`S256` `code_verifier` check) + `refresh_token` exchange +
 *    configurable `expires_in` + injectable `invalid_grant` revocation
 *  - `GmailMockServer`: `/gmail/v1/users/me/profile`, `/history` (multi-page + `404` expired cursor +
 *    `429 Retry-After`), `/messages/:id` strictly verifying `format=metadata` ONLY (never `full`/`raw`!)
 *  - `GoogleCalendarMockServer`: `/calendar/v3/calendars/:id/events` supporting `.created`/`.updated`/
 *    `.cancelled` change polls (`updatedMin`, `410 Gone`, `nextPageToken`) and `.starting` reminder polls
 *    (`timeMin`/`timeMax`, declined & all-day events)
 */

import crypto from "node:crypto";
import http from "node:http";
import { closeHttpServer, readHttpBody, writeJson } from "./helpers.ts";

// ---------------------------------------------------------------------------
// 1. Google OAuth2 PKCE & Refresh Token Mock
// ---------------------------------------------------------------------------

export interface RecordedOAuthRequest {
  grantType: string;
  params: Record<string, string>;
  status: number;
}

export interface GoogleOAuthMockOptions {
  clientId: string;
  clientSecret?: string;
  validRefreshToken?: string;
  issuedAccessToken?: string;
  issuedRefreshToken?: string;
  expiresInSeconds?: number;
}

export class GoogleOAuthMockServer {
  readonly server: http.Server;
  readonly port: number;
  readonly tokenUrl: string;
  readonly requests: RecordedOAuthRequest[] = [];

  private readonly clientId: string;
  private readonly clientSecret: string;
  private validRefreshToken: string;
  private issuedAccessToken: string;
  private issuedRefreshToken: string;
  private expiresInSeconds: number;
  private revoked = false;
  private readonly pendingAuthCodes = new Map<string, { codeChallenge: string; scope: string }>();

  private constructor(server: http.Server, port: number, options: GoogleOAuthMockOptions) {
    this.server = server;
    this.port = port;
    this.tokenUrl = `http://127.0.0.1:${port}/token`;
    this.clientId = options.clientId;
    this.clientSecret = options.clientSecret ?? "";
    this.validRefreshToken = options.validRefreshToken ?? "refresh-itest-token";
    this.issuedAccessToken = options.issuedAccessToken ?? "access-itest-token";
    this.issuedRefreshToken = options.issuedRefreshToken ?? this.validRefreshToken;
    this.expiresInSeconds = options.expiresInSeconds ?? 3600;
  }

  static async start(options: GoogleOAuthMockOptions): Promise<GoogleOAuthMockServer> {
    let instance!: GoogleOAuthMockServer;

    const server = http.createServer(async (req, res) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      if (req.method !== "POST" || url.pathname !== "/token") {
        writeJson(res, 404, { error: "not_found" });
        return;
      }
      const raw = (await readHttpBody(req)).toString("utf8");
      const form = new URLSearchParams(raw);
      const params = Object.fromEntries(form.entries());
      const grantType = form.get("grant_type") ?? "";

      const finish = (status: number, body: unknown) => {
        instance.requests.push({ grantType, params, status });
        writeJson(res, status, body);
      };

      if (form.get("client_id") !== instance.clientId) {
        finish(400, { error: "invalid_client", error_description: "Unknown client_id" });
        return;
      }
      if (instance.clientSecret && form.get("client_secret") !== instance.clientSecret) {
        finish(401, { error: "invalid_client", error_description: "Bad client_secret" });
        return;
      }

      if (grantType === "authorization_code") {
        const code = form.get("code") ?? "";
        const verifier = form.get("code_verifier") ?? "";
        const pending = instance.pendingAuthCodes.get(code);
        if (!pending) {
          finish(400, { error: "invalid_grant", error_description: "Unknown authorization code" });
          return;
        }
        const derived = crypto.createHash("sha256").update(verifier).digest("base64url");
        if (derived !== pending.codeChallenge) {
          finish(400, { error: "invalid_grant", error_description: "PKCE code_verifier mismatch" });
          return;
        }
        instance.pendingAuthCodes.delete(code);
        finish(200, {
          access_token: instance.issuedAccessToken,
          refresh_token: instance.issuedRefreshToken,
          expires_in: instance.expiresInSeconds,
          token_type: "Bearer",
          scope: pending.scope,
        });
        return;
      }

      if (grantType === "refresh_token") {
        if (instance.revoked || form.get("refresh_token") !== instance.validRefreshToken) {
          finish(400, {
            error: "invalid_grant",
            error_description: "Token has been expired or revoked.",
          });
          return;
        }
        finish(200, {
          access_token: instance.issuedAccessToken,
          expires_in: instance.expiresInSeconds,
          token_type: "Bearer",
        });
        return;
      }

      finish(400, { error: "unsupported_grant_type" });
    });

    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = server.address();
    const port = typeof addr === "object" && addr ? addr.port : 0;
    instance = new GoogleOAuthMockServer(server, port, options);
    return instance;
  }

  /** Registers an expected PKCE S256 challenge for an authorization code consent test. */
  registerAuthCode(code: string, codeChallenge: string, scope = "https://www.googleapis.com/auth/gmail.readonly"): void {
    this.pendingAuthCodes.set(code, { codeChallenge, scope });
  }

  setRevoked(revoked: boolean): void {
    this.revoked = revoked;
  }

  setAccessToken(token: string): void {
    this.issuedAccessToken = token;
  }

  close(): Promise<void> {
    return closeHttpServer(this.server);
  }
}

// ---------------------------------------------------------------------------
// 2. Gmail History API Mock
// ---------------------------------------------------------------------------

export interface GmailMockMessage {
  id: string;
  threadId: string;
  labelIds: string[];
  from: string;
  to: string;
  subject: string;
  snippet: string;
  internalDateMs?: number;
  sizeEstimate?: number;
  historyId: string;
}

export interface RecordedGmailRequest {
  pathname: string;
  searchParams: Record<string, string>;
  status: number;
}

export interface GmailMockOptions {
  accessToken: string;
  emailAddress?: string;
  initialHistoryId?: string;
  pageSize?: number;
  /** If true (default), returns HTTP 400 if any `/messages/:id` request asks for anything other than `format=metadata`. */
  strictMetadataOnly?: boolean;
}

export class GmailMockServer {
  readonly server: http.Server;
  readonly port: number;
  readonly apiBase: string;
  readonly requests: RecordedGmailRequest[] = [];
  readonly nonMetadataRequests: RecordedGmailRequest[] = [];

  private readonly accessToken: string;
  private readonly emailAddress: string;
  private currentHistoryId: string;
  private readonly pageSize: number;
  private readonly strictMetadataOnly: boolean;
  private readonly messages = new Map<string, GmailMockMessage>();
  private readonly historyRecords: Array<{ historyId: string; message: GmailMockMessage }> = [];
  private expireNextHistory = false;
  private next429RetryAfter: number | null = null;

  private constructor(server: http.Server, port: number, options: GmailMockOptions) {
    this.server = server;
    this.port = port;
    this.apiBase = `http://127.0.0.1:${port}`;
    this.accessToken = options.accessToken;
    this.emailAddress = options.emailAddress ?? "ada@example.com";
    this.currentHistoryId = options.initialHistoryId ?? "100";
    this.pageSize = options.pageSize ?? 50;
    this.strictMetadataOnly = options.strictMetadataOnly !== false;
  }

  static async start(options: GmailMockOptions): Promise<GmailMockServer> {
    let instance!: GmailMockServer;

    const server = http.createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      const paramsObj = Object.fromEntries(url.searchParams.entries());
      const finish = (status: number, body: unknown, extraHeaders: Record<string, string> = {}) => {
        instance.requests.push({ pathname: url.pathname, searchParams: paramsObj, status });
        writeJson(res, status, body, extraHeaders);
      };

      if (req.headers.authorization !== `Bearer ${instance.accessToken}`) {
        finish(401, { error: { code: 401, message: "Invalid Credentials" } });
        return;
      }

      if (instance.next429RetryAfter !== null) {
        const retryAfter = instance.next429RetryAfter;
        instance.next429RetryAfter = null;
        finish(
          429,
          { error: { code: 429, message: "Rate Limit Exceeded" } },
          { "retry-after": String(retryAfter) },
        );
        return;
      }

      if (url.pathname === "/gmail/v1/users/me/profile") {
        finish(200, {
          emailAddress: instance.emailAddress,
          historyId: instance.currentHistoryId,
        });
        return;
      }

      if (url.pathname === "/gmail/v1/users/me/history") {
        if (instance.expireNextHistory) {
          instance.expireNextHistory = false;
          finish(404, { error: { code: 404, message: "Requested entity was not found." } });
          return;
        }
        const startHistoryId = BigInt(url.searchParams.get("startHistoryId") ?? "0");
        const labelFilter = url.searchParams.get("labelId");
        const offset = Number(url.searchParams.get("pageToken") ?? "0") || 0;

        const matching = instance.historyRecords.filter((rec) => {
          if (BigInt(rec.historyId) <= startHistoryId) return false;
          if (labelFilter && !rec.message.labelIds.includes(labelFilter)) return false;
          return true;
        });

        const page = matching.slice(offset, offset + instance.pageSize);
        const nextOffset = offset + page.length;
        finish(200, {
          historyId: instance.currentHistoryId,
          history: page.map((rec) => ({
            id: rec.historyId,
            messagesAdded: [
              {
                message: {
                  id: rec.message.id,
                  threadId: rec.message.threadId,
                  labelIds: rec.message.labelIds,
                },
              },
            ],
          })),
          ...(nextOffset < matching.length ? { nextPageToken: String(nextOffset) } : {}),
        });
        return;
      }

      const msgMatch = /^\/gmail\/v1\/users\/me\/messages\/([^/]+)$/.exec(url.pathname);
      if (msgMatch) {
        const format = url.searchParams.get("format");
        if (format !== "metadata") {
          const bad: RecordedGmailRequest = {
            pathname: url.pathname,
            searchParams: paramsObj,
            status: 400,
          };
          instance.nonMetadataRequests.push(bad);
          if (instance.strictMetadataOnly) {
            finish(400, {
              error: {
                code: 400,
                message: `Privacy violation: expected format=metadata, got format=${String(format)}`,
              },
            });
            return;
          }
        }
        const id = decodeURIComponent(msgMatch[1]);
        const msg = instance.messages.get(id);
        if (!msg) {
          finish(404, { error: { code: 404, message: "Message not found" } });
          return;
        }
        finish(200, {
          id: msg.id,
          threadId: msg.threadId,
          labelIds: msg.labelIds,
          snippet: msg.snippet,
          internalDate: String(msg.internalDateMs ?? Date.now()),
          sizeEstimate: msg.sizeEstimate ?? 2048,
          payload: {
            headers: [
              { name: "From", value: msg.from },
              { name: "To", value: msg.to },
              { name: "Subject", value: msg.subject },
              { name: "Date", value: new Date(msg.internalDateMs ?? Date.now()).toUTCString() },
            ],
          },
        });
        return;
      }

      finish(404, { error: { code: 404, message: "Not Found" } });
    });

    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = server.address();
    const port = typeof addr === "object" && addr ? addr.port : 0;
    instance = new GmailMockServer(server, port, options);
    return instance;
  }

  addMessage(msg: GmailMockMessage): void {
    this.messages.set(msg.id, msg);
    this.historyRecords.push({ historyId: msg.historyId, message: msg });
    if (BigInt(msg.historyId) > BigInt(this.currentHistoryId)) {
      this.currentHistoryId = msg.historyId;
    }
  }

  setCurrentHistoryId(historyId: string): void {
    this.currentHistoryId = historyId;
  }

  expireNextHistoryFetch(): void {
    this.expireNextHistory = true;
  }

  failNextWith429(retryAfterSec = 1): void {
    this.next429RetryAfter = retryAfterSec;
  }

  close(): Promise<void> {
    return closeHttpServer(this.server);
  }
}

// ---------------------------------------------------------------------------
// 3. Google Calendar v3 API Mock
// ---------------------------------------------------------------------------

export interface CalendarMockEvent {
  id: string;
  status: "confirmed" | "tentative" | "cancelled";
  summary?: string;
  description?: string;
  created?: string;
  updated: string;
  start?: { dateTime?: string; date?: string };
  end?: { dateTime?: string; date?: string };
  htmlLink?: string;
  hangoutLink?: string;
  location?: string;
  organizer?: { email: string };
  attendees?: Array<{ email?: string; self?: boolean; responseStatus?: string }>;
}

export interface RecordedCalendarRequest {
  calendarId: string;
  kind: "changes" | "starting";
  searchParams: Record<string, string>;
  status: number;
}

export interface GoogleCalendarMockOptions {
  accessToken: string;
  pageSize?: number;
}

export class GoogleCalendarMockServer {
  readonly server: http.Server;
  readonly port: number;
  readonly apiBase: string;
  readonly requests: RecordedCalendarRequest[] = [];

  private readonly accessToken: string;
  private readonly pageSize: number;
  private readonly changeEvents = new Map<string, CalendarMockEvent[]>();
  private readonly upcomingEvents = new Map<string, CalendarMockEvent[]>();
  private expireNextUpdatedMinFlag = false;

  private constructor(server: http.Server, port: number, options: GoogleCalendarMockOptions) {
    this.server = server;
    this.port = port;
    this.apiBase = `http://127.0.0.1:${port}`;
    this.accessToken = options.accessToken;
    this.pageSize = options.pageSize ?? 50;
  }

  static async start(options: GoogleCalendarMockOptions): Promise<GoogleCalendarMockServer> {
    let instance!: GoogleCalendarMockServer;

    const server = http.createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      const match = /^\/calendar\/v3\/calendars\/([^/]+)\/events$/.exec(url.pathname);
      if (req.method !== "GET" || !match) {
        writeJson(res, 404, { error: { code: 404, message: "Not Found" } });
        return;
      }
      const calendarId = decodeURIComponent(match[1]);
      const paramsObj = Object.fromEntries(url.searchParams.entries());
      const kind: "changes" | "starting" = url.searchParams.has("updatedMin")
        ? "changes"
        : "starting";

      const finish = (status: number, body: unknown) => {
        instance.requests.push({ calendarId, kind, searchParams: paramsObj, status });
        writeJson(res, status, body);
      };

      if (req.headers.authorization !== `Bearer ${instance.accessToken}`) {
        finish(401, { error: { code: 401, message: "Invalid Credentials" } });
        return;
      }

      if (kind === "changes" && instance.expireNextUpdatedMinFlag) {
        instance.expireNextUpdatedMinFlag = false;
        finish(410, { error: { code: 410, message: "Sync token or updatedMin is no longer valid" } });
        return;
      }

      const sourceList =
        kind === "changes"
          ? (instance.changeEvents.get(calendarId) ?? [])
          : (instance.upcomingEvents.get(calendarId) ?? []);

      let filtered = [...sourceList];
      if (kind === "changes") {
        const updatedMinMs = Date.parse(url.searchParams.get("updatedMin") ?? "");
        if (!Number.isNaN(updatedMinMs)) {
          filtered = filtered.filter((ev) => Date.parse(ev.updated) >= updatedMinMs);
        }
      }

      const offset = Number(url.searchParams.get("pageToken") ?? "0") || 0;
      const page = filtered.slice(offset, offset + instance.pageSize);
      const nextOffset = offset + page.length;

      finish(200, {
        kind: "calendar#events",
        items: page,
        ...(nextOffset < filtered.length ? { nextPageToken: String(nextOffset) } : {}),
      });
    });

    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = server.address();
    const port = typeof addr === "object" && addr ? addr.port : 0;
    instance = new GoogleCalendarMockServer(server, port, options);
    return instance;
  }

  setChangeEvents(calendarId: string, events: CalendarMockEvent[]): void {
    this.changeEvents.set(calendarId, [...events]);
  }

  setUpcomingEvents(calendarId: string, events: CalendarMockEvent[]): void {
    this.upcomingEvents.set(calendarId, [...events]);
  }

  expireNextUpdatedMin(): void {
    this.expireNextUpdatedMinFlag = true;
  }

  close(): Promise<void> {
    return closeHttpServer(this.server);
  }
}
