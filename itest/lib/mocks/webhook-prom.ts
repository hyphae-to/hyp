/**
 * Loopback Prometheus Alertmanager v4 emitter, signed generic webhook emitter, and
 * outbound `WEBHOOK_POST_URL` callback verifier server (`127.0.0.1:0`).
 */

import crypto from "node:crypto";
import http from "node:http";
import {
  closeHttpServer,
  flipHexBit,
  hmacHex,
  readHttpBody,
  waitUntil,
  writeJson,
} from "./helpers.ts";

export interface AlertmanagerAlertSpec {
  status: "firing" | "resolved";
  alertname: string;
  severity: string;
  service?: string;
  instance?: string;
  summary?: string;
  description?: string;
  fingerprint?: string;
  startsAt?: string;
  endsAt?: string;
  extraLabels?: Record<string, string>;
  extraAnnotations?: Record<string, string>;
}

/** Builds an authentic Prometheus Alertmanager v4 webhook JSON payload. */
export function buildAlertmanagerPayload(
  alerts: AlertmanagerAlertSpec[],
  opts: { receiver?: string; externalURL?: string } = {},
): Record<string, any> {
  const nowIso = new Date().toISOString();
  const groupStatus = alerts.some((a) => a.status === "firing") ? "firing" : "resolved";
  return {
    version: "4",
    groupKey: "{}:{alertname=\"itest\"}",
    truncatedAlerts: 0,
    status: groupStatus,
    receiver: opts.receiver ?? "hyphae-oncall",
    groupLabels: { alertname: alerts[0]?.alertname ?? "Alert" },
    commonLabels: {},
    commonAnnotations: {},
    externalURL: opts.externalURL ?? "http://alertmanager.local:9093",
    alerts: alerts.map((a, idx) => ({
      status: a.status,
      labels: {
        alertname: a.alertname,
        severity: a.severity,
        ...(a.service ? { service: a.service } : {}),
        ...(a.instance ? { instance: a.instance } : {}),
        ...(a.extraLabels ?? {}),
      },
      annotations: {
        ...(a.summary ? { summary: a.summary } : {}),
        ...(a.description ? { description: a.description } : {}),
        ...(a.extraAnnotations ?? {}),
      },
      startsAt: a.startsAt ?? nowIso,
      endsAt: a.endsAt ?? (a.status === "resolved" ? nowIso : "0001-01-01T00:00:00Z"),
      generatorURL: `http://prometheus.local:9090/graph?g0.expr=${encodeURIComponent(a.alertname)}`,
      fingerprint: a.fingerprint ?? `fp-itest-${idx + 1}`,
    })),
  };
}

/** Builds an oversized (>1 MiB) Alertmanager JSON body to assert `413 Payload Too Large`. */
export function buildOversizedAlertmanagerBody(minBytes = 1_100_000): string {
  const pad = "A".repeat(minBytes);
  return JSON.stringify(
    buildAlertmanagerPayload([
      {
        status: "firing",
        alertname: "OversizedAlert",
        severity: "critical",
        description: pad,
      },
    ]),
  );
}

/** Sends a Prometheus Alertmanager v4 webhook with Bearer, Basic, and/or HMAC-SHA256 auth. */
export async function sendAlertmanagerWebhook(
  url: string,
  opts: {
    payload?: unknown;
    rawOverride?: string;
    bearerToken?: string;
    basicAuth?: { user: string; pass: string };
    hmacSecret?: string;
    tamperSignature?: boolean;
  },
): Promise<{ status: number; json: any; text: string }> {
  const raw =
    opts.rawOverride ??
    (typeof opts.payload === "string" ? opts.payload : JSON.stringify(opts.payload ?? {}));
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (opts.bearerToken) {
    headers.authorization = `Bearer ${opts.bearerToken}`;
  } else if (opts.basicAuth) {
    const b64 = Buffer.from(`${opts.basicAuth.user}:${opts.basicAuth.pass}`, "utf8").toString(
      "base64",
    );
    headers.authorization = `Basic ${b64}`;
  }
  if (opts.hmacSecret) {
    const valid = `sha256=${hmacHex("sha256", opts.hmacSecret, raw)}`;
    headers["x-webhook-signature-256"] = opts.tamperSignature ? flipHexBit(valid) : valid;
  }
  const res = await fetch(url, { method: "POST", headers, body: raw });
  const text = await res.text();
  let json: any = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return { status: res.status, json, text };
}

/**
 * Sends a generic signed webhook matching BOTH Rust `GenericWebhookAdapter` AND Node `plugins/webhook`:
 *  - When `timestamp` is provided, sets `X-Webhook-Timestamp` and signs `${ts}.${raw}`
 *  - `"now"` uses current epoch seconds; `"expired"` uses 10 minutes in the past (>5m replay window!)
 */
export async function sendGenericWebhook(
  url: string,
  opts: {
    payload?: unknown;
    rawOverride?: string;
    secret?: string;
    timestamp?: "now" | "expired" | string | number;
    tamperSignature?: boolean;
    omitSignature?: boolean;
    extraHeaders?: Record<string, string>;
  },
): Promise<{ status: number; json: any; text: string; signature?: string; timestamp?: string }> {
  const raw =
    opts.rawOverride ??
    (typeof opts.payload === "string" ? opts.payload : JSON.stringify(opts.payload ?? {}));
  const headers: Record<string, string> = {
    "content-type": "application/json",
    ...(opts.extraHeaders ?? {}),
  };

  let tsStr: string | undefined;
  if (opts.timestamp === "now") {
    tsStr = String(Math.floor(Date.now() / 1000));
  } else if (opts.timestamp === "expired") {
    tsStr = String(Math.floor((Date.now() - 10 * 60_000) / 1000));
  } else if (opts.timestamp !== undefined) {
    tsStr = String(opts.timestamp);
  }
  if (tsStr !== undefined) {
    headers["x-webhook-timestamp"] = tsStr;
  }

  let signature: string | undefined;
  if (opts.secret && !opts.omitSignature) {
    const signedInput = tsStr !== undefined ? `${tsStr}.${raw}` : raw;
    const valid = `sha256=${hmacHex("sha256", opts.secret, signedInput)}`;
    signature = opts.tamperSignature ? flipHexBit(valid) : valid;
    headers["x-webhook-signature-256"] = signature;
  }

  const res = await fetch(url, { method: "POST", headers, body: raw });
  const text = await res.text();
  let json: any = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return { status: res.status, json, text, signature, timestamp: tsStr };
}

export interface RecordedWebhookCallback {
  headers: http.IncomingHttpHeaders;
  raw: string;
  json: any;
  signatureHeader: string | null;
  signatureValid: boolean;
  timestampMs: number;
}

/**
 * Loopback outbound callback receiver (`WEBHOOK_POST_URL`) verifying HMAC-SHA256 signatures
 * attached by `plugins/webhook` on outbound `hyp_send` replies.
 */
export class WebhookCallbackServer {
  readonly server: http.Server;
  readonly port: number;
  readonly url: string;
  readonly callbacks: RecordedWebhookCallback[] = [];

  private constructor(server: http.Server, port: number) {
    this.server = server;
    this.port = port;
    this.url = `http://127.0.0.1:${port}/callback`;
  }

  static async start(opts: { secret?: string } = {}): Promise<WebhookCallbackServer> {
    let instance!: WebhookCallbackServer;

    const server = http.createServer(async (req, res) => {
      const rawBuf = await readHttpBody(req);
      const raw = rawBuf.toString("utf8");
      let json: any = null;
      try {
        json = JSON.parse(raw);
      } catch {
        json = null;
      }
      const sigHeader =
        typeof req.headers["x-webhook-signature-256"] === "string"
          ? req.headers["x-webhook-signature-256"].trim().toLowerCase()
          : null;
      let signatureValid = !opts.secret;
      if (opts.secret && sigHeader) {
        const expected = `sha256=${hmacHex("sha256", opts.secret, rawBuf)}`;
        const a = Buffer.from(sigHeader, "utf8");
        const b = Buffer.from(expected, "utf8");
        signatureValid = a.length === b.length && crypto.timingSafeEqual(a, b);
      }
      instance.callbacks.push({
        headers: { ...req.headers },
        raw,
        json,
        signatureHeader: sigHeader,
        signatureValid,
        timestampMs: Date.now(),
      });
      writeJson(res, 200, { ok: true });
    });

    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = server.address();
    const port = typeof addr === "object" && addr ? addr.port : 0;
    instance = new WebhookCallbackServer(server, port);
    return instance;
  }

  waitForCallback(
    predicate: (cb: RecordedWebhookCallback) => boolean,
    timeoutMs = 15_000,
  ): Promise<RecordedWebhookCallback> {
    return waitUntil(
      () => this.callbacks.find(predicate) ?? false,
      "webhook outbound callback",
      timeoutMs,
    );
  }

  close(): Promise<void> {
    return closeHttpServer(this.server);
  }
}
