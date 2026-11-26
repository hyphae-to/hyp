/**
 * Stateful loopback GitHub REST API + signed `X-Hub-Signature-256` webhook wire-mock (`127.0.0.1:0`).
 *
 * Implements:
 *  - `GET /repos/:owner/:repo` (public/private visibility + strict token check)
 *  - `GET /repos/:owner/:repo/events` with RFC 9110 `ETag` / `If-None-Match` (`200 -> 304 -> 200`),
 *    `X-Poll-Interval`, `X-RateLimit-Remaining`, and injectable `429 Retry-After` backoff
 *  - Per-request `Authorization` header recording for strict multi-org `repoTokens` isolation checks
 *  - Golden signed webhook emitters (`pull_request`, `workflow_run`, `check_run`) + 1-bit tamper helper
 */

import http from "node:http";
import {
  closeHttpServer,
  flipHexBit,
  hmacHex,
  waitUntil,
  writeJson,
} from "./helpers.ts";

export interface GitHubRepoState {
  repo: string;
  visibility: "public" | "private";
  /** If set, private visibility check requires `Bearer <requiredToken>`. */
  requiredToken?: string;
  events: Array<Record<string, any>>;
  version: number;
}

export interface RecordedGitHubRequest {
  method: string;
  pathname: string;
  repo: string;
  endpoint: "repo" | "events" | "other";
  authorization: string | null;
  ifNoneMatch: string | null;
  status: number;
  timestampMs: number;
}

export interface GitHubMockOptions {
  pollIntervalSeconds?: number;
  rateLimitRemaining?: number;
}

export class GitHubMockServer {
  readonly server: http.Server;
  readonly port: number;
  readonly apiBaseUrl: string;
  readonly requests: RecordedGitHubRequest[] = [];

  private readonly repos = new Map<string, GitHubRepoState>();
  private readonly next429ByRepo = new Map<string, number>();
  private pollIntervalSeconds: number;
  private rateLimitRemaining: number;

  private constructor(server: http.Server, port: number, options: GitHubMockOptions) {
    this.server = server;
    this.port = port;
    this.apiBaseUrl = `http://127.0.0.1:${port}`;
    this.pollIntervalSeconds = options.pollIntervalSeconds ?? 1;
    this.rateLimitRemaining = options.rateLimitRemaining ?? 4999;
  }

  static async start(options: GitHubMockOptions = {}): Promise<GitHubMockServer> {
    let instance!: GitHubMockServer;

    const server = http.createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      const auth =
        typeof req.headers.authorization === "string" ? req.headers.authorization : null;
      const ifNoneMatch =
        typeof req.headers["if-none-match"] === "string" ? req.headers["if-none-match"] : null;

      const record = (
        repo: string,
        endpoint: "repo" | "events" | "other",
        status: number,
      ) => {
        instance.requests.push({
          method: req.method ?? "GET",
          pathname: url.pathname,
          repo,
          endpoint,
          authorization: auth,
          ifNoneMatch,
          status,
          timestampMs: Date.now(),
        });
      };

      const eventsMatch = /^\/repos\/([^/]+\/[^/]+)\/events$/.exec(url.pathname);
      if (req.method === "GET" && eventsMatch) {
        const repo = eventsMatch[1].toLowerCase();
        const state = instance.repos.get(repo);
        if (!state) {
          record(repo, "events", 404);
          writeJson(res, 404, { message: "Not Found" });
          return;
        }
        if (state.visibility === "private" && state.requiredToken) {
          if (auth !== `Bearer ${state.requiredToken}`) {
            record(repo, "events", 404);
            writeJson(res, 404, { message: "Not Found" });
            return;
          }
        }
        if (instance.next429ByRepo.has(repo)) {
          const retryAfter = instance.next429ByRepo.get(repo)!;
          instance.next429ByRepo.delete(repo);
          record(repo, "events", 429);
          writeJson(
            res,
            429,
            { message: "API rate limit exceeded" },
            {
              "retry-after": String(retryAfter),
              "x-poll-interval": String(instance.pollIntervalSeconds),
              "x-ratelimit-remaining": "0",
            },
          );
          return;
        }

        const etag = `W/"${repo}-v${state.version}"`;
        const commonHeaders = {
          etag,
          "x-poll-interval": String(instance.pollIntervalSeconds),
          "x-ratelimit-remaining": String(instance.rateLimitRemaining),
        };
        if (ifNoneMatch && ifNoneMatch.trim() === etag) {
          record(repo, "events", 304);
          res.writeHead(304, commonHeaders);
          res.end();
          return;
        }
        record(repo, "events", 200);
        writeJson(res, 200, state.events, commonHeaders);
        return;
      }

      const repoMatch = /^\/repos\/([^/]+\/[^/]+)$/.exec(url.pathname);
      if (req.method === "GET" && repoMatch) {
        const repo = repoMatch[1].toLowerCase();
        const state = instance.repos.get(repo);
        if (!state) {
          record(repo, "repo", 404);
          writeJson(res, 404, { message: "Not Found" });
          return;
        }
        if (state.visibility === "private" && state.requiredToken) {
          if (auth !== `Bearer ${state.requiredToken}`) {
            record(repo, "repo", 404);
            writeJson(res, 404, { message: "Not Found" });
            return;
          }
        }
        record(repo, "repo", 200);
        writeJson(res, 200, {
          full_name: state.repo,
          visibility: state.visibility,
          private: state.visibility === "private",
          default_branch: "main",
        });
        return;
      }

      record("", "other", 404);
      writeJson(res, 404, { message: "Not Found" });
    });

    await new Promise<void>((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", () => resolve());
    });
    const addr = server.address();
    const port = typeof addr === "object" && addr ? addr.port : 0;
    instance = new GitHubMockServer(server, port, options);
    return instance;
  }

  /** Registers or updates a GitHub repository in the mock. */
  registerRepo(
    repo: string,
    opts: {
      visibility?: "public" | "private";
      requiredToken?: string;
      initialEvents?: Array<Record<string, any>>;
    } = {},
  ): void {
    const key = repo.toLowerCase();
    this.repos.set(key, {
      repo: key,
      visibility: opts.visibility ?? "public",
      requiredToken: opts.requiredToken,
      events: [...(opts.initialEvents ?? [])],
      version: 1,
    });
  }

  /** Prepends a GitHub Events API item (newest-first) and bumps the repo ETag so next poll returns 200. */
  pushRepoEvent(repo: string, event: Record<string, any>): void {
    const key = repo.toLowerCase();
    const state = this.repos.get(key);
    if (!state) {
      throw new Error(`GitHubMockServer: repo '${repo}' is not registered`);
    }
    state.events.unshift(event);
    state.version += 1;
  }

  /** Injects a one-shot `429 Too Many Requests` + `Retry-After` on the next events poll for `repo`. */
  failNextEventsPollWith429(repo: string, retryAfterSec = 1): void {
    this.next429ByRepo.set(repo.toLowerCase(), retryAfterSec);
  }

  requestsForRepo(repo: string): RecordedGitHubRequest[] {
    const key = repo.toLowerCase();
    return this.requests.filter((r) => r.repo === key);
  }

  waitForEventPollStatus(
    repo: string,
    status: number,
    minCount = 1,
    timeoutMs = 15_000,
  ): Promise<RecordedGitHubRequest[]> {
    const key = repo.toLowerCase();
    return waitUntil(
      () => {
        const matches = this.requests.filter(
          (r) => r.repo === key && r.endpoint === "events" && r.status === status,
        );
        return matches.length >= minCount ? matches : false;
      },
      `github ${key} events status=${status} (count >= ${minCount})`,
      timeoutMs,
    );
  }

  close(): Promise<void> {
    return closeHttpServer(this.server);
  }
}

/** Builds a GitHub REST Events API `PullRequestEvent` item for `GET /repos/:owner/:repo/events`. */
export function buildGitHubApiPullRequestEvent(opts: {
  id: string;
  repo: string;
  number: number;
  action?: string;
  title: string;
  body?: string;
  author?: string;
  headBranch?: string;
  baseBranch?: string;
  createdAt?: string;
}): Record<string, any> {
  return {
    id: opts.id,
    type: "PullRequestEvent",
    actor: { login: opts.author ?? "alice", type: "User" },
    repo: { name: opts.repo },
    created_at: opts.createdAt ?? new Date().toISOString(),
    payload: {
      action: opts.action ?? "opened",
      number: opts.number,
      pull_request: {
        number: opts.number,
        title: opts.title,
        body: opts.body ?? "",
        state: "open",
        draft: false,
        html_url: `https://github.com/${opts.repo}/pull/${opts.number}`,
        head: { ref: opts.headBranch ?? "feat/itest", sha: "deadbeef1234" },
        base: { ref: opts.baseBranch ?? "main" },
        labels: [],
        assignees: [],
      },
    },
  };
}

/** Builds a golden GitHub `pull_request` webhook payload. */
export function buildGitHubPullRequestWebhook(opts: {
  repo: string;
  number: number;
  action?: string;
  title: string;
  body?: string;
  author?: string;
}): Record<string, any> {
  const [owner] = opts.repo.split("/");
  return {
    action: opts.action ?? "opened",
    number: opts.number,
    repository: { full_name: opts.repo, default_branch: "main" },
    organization: { login: owner },
    sender: { login: opts.author ?? "alice", type: "User" },
    pull_request: {
      number: opts.number,
      title: opts.title,
      body: opts.body ?? "",
      state: "open",
      draft: false,
      html_url: `https://github.com/${opts.repo}/pull/${opts.number}`,
      head: { ref: "feat/webhook", sha: "abc1234def56" },
      base: { ref: "main" },
      labels: [{ name: "bug" }],
      assignees: [],
    },
  };
}

/** Builds a golden GitHub `workflow_run` webhook payload. */
export function buildGitHubWorkflowRunWebhook(opts: {
  repo: string;
  runId: number;
  name: string;
  conclusion: string;
  author?: string;
  headBranch?: string;
}): Record<string, any> {
  const [owner] = opts.repo.split("/");
  return {
    action: "completed",
    repository: { full_name: opts.repo, default_branch: "main" },
    organization: { login: owner },
    sender: { login: opts.author ?? "github-actions[bot]", type: "Bot" },
    workflow_run: {
      id: opts.runId,
      name: opts.name,
      conclusion: opts.conclusion,
      head_branch: opts.headBranch ?? "main",
      head_sha: "cafebabe9876",
      html_url: `https://github.com/${opts.repo}/actions/runs/${opts.runId}`,
      run_attempt: 1,
      path: ".github/workflows/ci.yml",
      pull_requests: [],
    },
  };
}

/** Builds a golden GitHub `check_run` webhook payload. */
export function buildGitHubCheckRunWebhook(opts: {
  repo: string;
  checkRunId: number;
  name: string;
  conclusion: string;
  author?: string;
  headBranch?: string;
}): Record<string, any> {
  const [owner] = opts.repo.split("/");
  return {
    action: "completed",
    repository: { full_name: opts.repo, default_branch: "main" },
    organization: { login: owner },
    sender: { login: opts.author ?? "ci-bot", type: "Bot" },
    check_run: {
      id: opts.checkRunId,
      name: opts.name,
      status: "completed",
      conclusion: opts.conclusion,
      head_sha: "f00dbabe1122",
      html_url: `https://github.com/${opts.repo}/runs/${opts.checkRunId}`,
      check_suite: { head_branch: opts.headBranch ?? "main" },
      pull_requests: [],
    },
  };
}

/** Computes `sha256=<lowercase hex>` GitHub `X-Hub-Signature-256`. */
export function signGitHubWebhook(raw: string | Buffer, secret: string): string {
  return `sha256=${hmacHex("sha256", secret, raw)}`;
}

/** Sends a signed (or 1-bit tampered) GitHub webhook delivery. */
export async function sendGitHubWebhook(
  url: string,
  opts: {
    event: string;
    deliveryId: string;
    payload: unknown;
    secret: string;
    tamperSignature?: boolean;
    omitSignature?: boolean;
  },
): Promise<{ status: number; json: any; text: string; signature?: string }> {
  const raw = typeof opts.payload === "string" ? opts.payload : JSON.stringify(opts.payload);
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "x-github-event": opts.event,
    "x-github-delivery": opts.deliveryId,
  };
  let signature: string | undefined;
  if (!opts.omitSignature) {
    const valid = signGitHubWebhook(raw, opts.secret);
    signature = opts.tamperSignature ? flipHexBit(valid) : valid;
    headers["x-hub-signature-256"] = signature;
  }
  const res = await fetch(url, { method: "POST", headers, body: raw });
  const text = await res.text();
  let json: any = null;
  try {
    json = JSON.parse(text);
  } catch {
    json = null;
  }
  return { status: res.status, json, text, signature };
}
