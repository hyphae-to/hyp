/**
 * Loopback Vercel `/v7/deployments` state-machine poll API (`127.0.0.1:0`) + signed
 * `x-vercel-signature` (**HMAC-SHA1** raw lowercase hex) webhook emitter.
 */

import http from "node:http";
import { closeHttpServer, flipHexBit, hmacHex, writeJson } from "./helpers.ts";

export type VercelDeploymentPhase = "QUEUED" | "BUILDING" | "READY" | "ERROR" | "CANCELED";

export interface VercelMockDeployment {
  uid: string;
  name: string;
  projectId: string;
  created: number;
  readyState: VercelDeploymentPhase;
  target: "production" | null;
  url: string;
  inspectorUrl?: string;
  errorCode?: string;
  errorMessage?: string;
  creator?: { username?: string; githubLogin?: string };
  meta?: Record<string, string>;
}

export interface RecordedVercelRequest {
  pathname: string;
  teamId: string | null;
  slug: string | null;
  authorization: string | null;
  status: number;
}

export interface VercelMockOptions {
  token: string;
}

export class VercelMockServer {
  readonly server: http.Server;
  readonly port: number;
  readonly apiBase: string;
  readonly requests: RecordedVercelRequest[] = [];

  private readonly token: string;
  private readonly deployments = new Map<string, VercelMockDeployment>();

  private constructor(server: http.Server, port: number, options: VercelMockOptions) {
    this.server = server;
    this.port = port;
    this.apiBase = `http://127.0.0.1:${port}`;
    this.token = options.token;
  }

  static async start(options: VercelMockOptions): Promise<VercelMockServer> {
    let instance!: VercelMockServer;

    const server = http.createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      if (req.method !== "GET" || url.pathname !== "/v7/deployments") {
        writeJson(res, 404, { error: { message: "Not Found" } });
        return;
      }
      const auth =
        typeof req.headers.authorization === "string" ? req.headers.authorization : null;
      const teamId = url.searchParams.get("teamId");
      const slug = url.searchParams.get("slug");

      const finish = (status: number, body: unknown) => {
        instance.requests.push({ pathname: url.pathname, teamId, slug, authorization: auth, status });
        writeJson(res, status, body);
      };

      if (auth !== `Bearer ${instance.token}`) {
        finish(403, { error: { code: "forbidden", message: "Invalid Vercel token" } });
        return;
      }

      const list = [...instance.deployments.values()].sort((a, b) => b.created - a.created);
      finish(200, {
        deployments: list,
        pagination: { count: list.length, next: null, prev: null },
      });
    });

    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = server.address();
    const port = typeof addr === "object" && addr ? addr.port : 0;
    instance = new VercelMockServer(server, port, options);
    return instance;
  }

  upsertDeployment(dep: VercelMockDeployment): void {
    this.deployments.set(dep.uid, { ...dep });
  }

  /** Transitions a deployment's `readyState` (`BUILDING -> READY | ERROR | CANCELED`). */
  transitionDeployment(
    uid: string,
    readyState: VercelDeploymentPhase,
    extra: Partial<Pick<VercelMockDeployment, "errorCode" | "errorMessage">> = {},
  ): void {
    const dep = this.deployments.get(uid);
    if (!dep) {
      throw new Error(`VercelMockServer: unknown deployment uid '${uid}'`);
    }
    this.deployments.set(uid, { ...dep, readyState, ...extra });
  }

  close(): Promise<void> {
    return closeHttpServer(this.server);
  }
}

/** Computes raw lowercase hex **HMAC-SHA1** for Vercel's `x-vercel-signature` header. */
export function signVercelWebhook(raw: string | Buffer, secret: string): string {
  return hmacHex("sha1", secret, raw);
}

/** Sends a signed (or 1-bit tampered / wrong-algorithm SHA-256 / unsigned) Vercel webhook POST. */
export async function sendVercelWebhook(
  webhookUrl: string,
  opts: {
    payload: unknown;
    secret: string;
    tamperSignature?: boolean;
    useWrongSha256?: boolean;
    omitSignature?: boolean;
  },
): Promise<{ status: number; json: any; text: string; signature?: string }> {
  const raw = typeof opts.payload === "string" ? opts.payload : JSON.stringify(opts.payload);
  const headers: Record<string, string> = { "content-type": "application/json" };
  let signature: string | undefined;
  if (!opts.omitSignature) {
    const valid = opts.useWrongSha256
      ? hmacHex("sha256", opts.secret, raw)
      : signVercelWebhook(raw, opts.secret);
    signature = opts.tamperSignature ? flipHexBit(valid) : valid;
    headers["x-vercel-signature"] = signature;
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
