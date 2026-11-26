/**
 * End-to-end tests for the official event-source plugins (agentmail, sentry, gmail,
 * google-calendar, vercel, notion) and the Google OAuth helper.
 *
 * Each test spawns the real plugin script with fd 3 wired to this process (the same JSON-RPC v2
 * NDJSON channel `SubprocessSupervisor` speaks), points it at loopback mock provider
 * servers, and asserts on the CloudEvents it publishes. Zero npm dependencies, zero real
 * network calls, every temp dir and child process cleaned up.
 *
 *   node --test plugins/test/sources.test.mjs
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, createHmac } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";
import { runConsent } from "../sdk/google-oauth.mjs";

const PLUGINS = join(dirname(fileURLToPath(import.meta.url)), "..");
const cleanups = [];
after(async () => {
  for (const fn of cleanups.reverse()) await fn();
});

function tempDir() {
  const dir = mkdtempSync(join(tmpdir(), "hyp-plugin-test-"));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

async function until(check, label, timeoutMs = 8000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await check();
    if (value) return value;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error(`timed out waiting for ${label}`);
}

/** Loopback HTTP mock; `handler(req, body)` returns `{ status?, json }`. Records every request. */
async function mockServer(handler) {
  const requests = [];
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const chunk of req) chunks.push(chunk);
    const body = Buffer.concat(chunks).toString("utf8");
    const record = { method: req.method, url: req.url, headers: req.headers, body };
    requests.push(record);
    const out = (await handler(record)) ?? { status: 404, json: { error: "not_found" } };
    res.writeHead(out.status ?? 200, { "content-type": "application/json" }).end(JSON.stringify(out.json ?? {}));
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  cleanups.push(() => new Promise((resolve) => { server.closeAllConnections(); server.close(resolve); }));
  return { base: `http://127.0.0.1:${server.address().port}`, requests };
}

/** Spawns a plugin with fd 3 as the Hyphae channel; acks every event unless `ackWith` says otherwise. */
function startPlugin(name, env, { targets = [name], ackWith } = {}) {
  const child = spawn(process.execPath, [join(PLUGINS, name, "index.mjs")], {
    env: { PATH: process.env.PATH, HOME: process.env.HOME, HYPHAE_FD: "3", HYPHAE_PLUGIN: name, ...env },
    stdio: ["ignore", "ignore", "pipe", "pipe"],
  });
  const channel = child.stdio[3];
  const events = [];
  let stderr = "";
  let exit = null;
  child.stderr.on("error", () => {});
  child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
  channel.on("error", () => {});
  const rl = createInterface({ input: channel });
  rl.on("error", () => {});
  child.on("exit", (code, signal) => {
    exit = { code, signal };
    rl.close();
  });
  rl.on("line", (line) => {
    const msg = JSON.parse(line);
    if (msg.method !== "hyphae/publish") return;
    const reply = ackWith ? ackWith(msg, events.length) : { result: { status: "stored" } };
    if (Object.hasOwn(reply, "result")) events.push({ to: msg.params.to, event: msg.params.event });
    channel.write(JSON.stringify({ jsonrpc: "2.0", ...reply, id: msg.id }) + "\n");
  });
  channel.write(JSON.stringify({ jsonrpc: "2.0", method: "hyphae/hello", params: { protocol: 2, plugin: name, targets } }) + "\n");
  cleanups.push(() => new Promise((resolve) => {
    rl.close();
    if (exit !== null) {
      channel.destroy();
      return resolve();
    }
    child.once("exit", () => {
      channel.destroy();
      resolve();
    });
    child.kill("SIGKILL");
  }));
  return {
    events,
    stderr: () => stderr,
    exited: () => until(() => exit, `${name} exit`),
    webhookUrl: async () => {
      const match = await until(() => stderr.match(/webhook listening on (http:\/\/127\.0\.0\.1:\d+\S*)/), `${name} webhook listener`);
      return match[1];
    },
  };
}

const post = (url, body, headers = {}) => fetch(url, { method: "POST", headers: { "content-type": "application/json", ...headers }, body });
const hmac = (alg, secret, raw) => createHmac(alg, secret).update(raw).digest("hex");
/** Flips the lowest bit of one hex digit: a 1-bit mutation of an otherwise valid signature. */
const flipBit = (hex) => hex.slice(0, -1) + (parseInt(hex.at(-1), 16) ^ 1).toString(16);
const past = (ms) => new Date(Date.now() - ms).toISOString();

// ---------------------------------------------------------------------------------------
// Fail-closed startup guards
// ---------------------------------------------------------------------------------------

test("plugins refuse to start without credentials or with a non-HTTPS provider base", async () => {
  const cases = [
    ["agentmail", {}, /AGENTMAIL_API_KEY/],
    ["agentmail", { AGENTMAIL_API_KEY: "k", AGENTMAIL_WS_URL: "ws://example.com/v0" }, /AGENTMAIL_WS_URL must use wss:/],
    ["sentry", { SENTRY_ORG: "acme" }, /SENTRY_AUTH_TOKEN/],
    ["sentry", { SENTRY_AUTH_TOKEN: "t" }, /SENTRY_ORG/],
    ["sentry", { SENTRY_MODE: "webhook" }, /SENTRY_CLIENT_SECRET/],
    ["sentry", { SENTRY_MODE: "push" }, /SENTRY_MODE must be/],
    ["sentry", { SENTRY_AUTH_TOKEN: "t", SENTRY_ORG: "acme", SENTRY_API_BASE: "http://sentry.example.com" }, /SENTRY_API_BASE must use https:/],
    ["vercel", {}, /VERCEL_TOKEN/],
    ["vercel", { VERCEL_MODE: "webhook" }, /VERCEL_WEBHOOK_SECRET/],
    ["notion", {}, /NOTION_TOKEN/],
    ["notion", { NOTION_MODE: "webhook" }, /NOTION_VERIFICATION_TOKEN/],
    ["gmail", { GOOGLE_REFRESH_TOKEN: "r" }, /GOOGLE_CLIENT_ID/],
    ["gmail", { GOOGLE_CLIENT_ID: "c" }, /GOOGLE_REFRESH_TOKEN/],
    ["gmail", { GOOGLE_CLIENT_ID: "c", GOOGLE_REFRESH_TOKEN: "r", GOOGLE_TOKEN_URL: "http://example.com/token" }, /GOOGLE_TOKEN_URL must use https:/],
    ["google-calendar", { GOOGLE_CLIENT_ID: "c" }, /GOOGLE_REFRESH_TOKEN/],
  ];
  await Promise.all(cases.map(async ([name, env, expected]) => {
    const plugin = startPlugin(name, env);
    const { code } = await plugin.exited();
    assert.notEqual(code, 0, `${name} ${JSON.stringify(env)} must exit non-zero`);
    assert.match(plugin.stderr(), expected);
    assert.equal(plugin.events.length, 0);
  }));
});

// ---------------------------------------------------------------------------------------
// Sentry
// ---------------------------------------------------------------------------------------

test("sentry poll: emits only issues first seen after the cursor, once, and persists state 0600", async () => {
  const dir = tempDir();
  const stateFile = join(dir, "sentry.json");
  writeFileSync(stateFile, JSON.stringify({ cursor: past(3_600_000), seen: { 7: 1 } }));
  const mock = await mockServer((req) => {
    if (!req.url.startsWith("/api/0/organizations/acme/issues/")) return null;
    return {
      json: [
        { id: "9", shortId: "API-9", title: "TypeError: x is undefined", culprit: "checkout()", level: "error", status: "unresolved", firstSeen: past(60_000), lastSeen: past(1_000), count: "12", userCount: 3, permalink: "https://sentry.io/acme/api/issues/9/", project: { slug: "api" }, isUnhandled: true },
        { id: "7", shortId: "API-7", title: "already delivered", firstSeen: past(120_000), project: { slug: "api" } },
        { id: "1", shortId: "API-1", title: "older than cursor", firstSeen: past(86_400_000), project: { slug: "api" } },
      ],
    };
  });
  const plugin = startPlugin("sentry", { SENTRY_AUTH_TOKEN: "sntrys_test", SENTRY_ORG: "acme", SENTRY_PROJECTS: "api", SENTRY_API_BASE: mock.base, SENTRY_STATE_FILE: stateFile });
  await until(() => plugin.events.length === 1, "sentry issue event");
  await until(() => JSON.parse(readFileSync(stateFile, "utf8")).seen["9"] === 1, "sentry state");

  const { to, event } = plugin.events[0];
  assert.equal(to, "sentry");
  assert.equal(event.specversion, "1.0");
  assert.equal(event.type, "io.sentry.issue.created");
  assert.equal(event.id, "sentry:acme:issue:9:created");
  assert.equal(event.source, "sentry/acme/api");
  assert.deepEqual(
    { short_id: event.data.short_id, level: event.data.level, project: event.data.project, count: event.data.count, unhandled: event.data.unhandled },
    { short_id: "API-9", level: "error", project: "api", count: 12, unhandled: true },
  );
  assert.equal(mock.requests[0].headers.authorization, "Bearer sntrys_test");
  assert.match(mock.requests[0].url, /project=api/);
  assert.equal(statSync(stateFile).mode & 0o777, 0o600);
  assert.ok(!plugin.stderr().includes("sntrys_test"), "token must never reach stderr");
});

test("sentry webhook: valid signature publishes; 1-bit flip, missing signature and wrong path fail closed", async () => {
  const secret = "sentry-client-secret";
  const plugin = startPlugin("sentry", { SENTRY_MODE: "webhook", SENTRY_CLIENT_SECRET: secret, SENTRY_WEBHOOK_PORT: "0" });
  const url = await plugin.webhookUrl();
  const raw = JSON.stringify({ action: "created", actor: { type: "application", id: "sentry", name: "Sentry" }, data: { issue: { id: "42", shortId: "WEB-42", title: "Boom", level: "fatal", status: "unresolved", project: { slug: "web" }, web_url: "https://sentry.io/issues/42/" } } });
  const sig = hmac("sha256", secret, raw);

  assert.equal((await post(url, raw, { "sentry-hook-resource": "issue", "sentry-hook-signature": flipBit(sig) })).status, 401);
  assert.equal((await post(url, raw, { "sentry-hook-resource": "issue" })).status, 401);
  assert.equal((await post(url, raw + " ", { "sentry-hook-resource": "issue", "sentry-hook-signature": sig })).status, 401);
  assert.equal((await post(url.replace("/sentry", "/other"), raw, { "sentry-hook-resource": "issue", "sentry-hook-signature": sig })).status, 404);
  assert.equal(plugin.events.length, 0, "nothing may be published before a valid signature");

  assert.equal((await post(url, raw, { "sentry-hook-resource": "issue", "sentry-hook-signature": sig })).status, 202);
  assert.equal(plugin.events.length, 1);
  const { event } = plugin.events[0];
  assert.equal(event.type, "io.sentry.issue.created");
  assert.equal(event.id, `sentry:sha256:${createHash("sha256").update(raw).digest("hex")}`);
  assert.equal(event.data.short_id, "WEB-42");
  assert.equal(event.data.level, "fatal");

  // Installation lifecycle hooks are verified but never forwarded to agents.
  const install = JSON.stringify({ action: "created", data: { installation: { uuid: "u" } } });
  assert.equal((await post(url, install, { "sentry-hook-resource": "installation", "sentry-hook-signature": hmac("sha256", secret, install) })).status, 202);
  assert.equal(plugin.events.length, 1);
});

// ---------------------------------------------------------------------------------------
// Vercel
// ---------------------------------------------------------------------------------------

test("vercel poll: announces new deployments and terminal transitions, never old history", async () => {
  const dir = tempDir();
  const stateFile = join(dir, "vercel.json");
  const since = Date.now() - 3_600_000;
  writeFileSync(stateFile, JSON.stringify({ since, states: { dpl_building: "BUILDING" } }));
  const mock = await mockServer((req) => {
    if (!req.url.startsWith("/v7/deployments")) return null;
    return {
      json: {
        deployments: [
          { uid: "dpl_new", name: "web", projectId: "prj_1", created: Date.now() - 5_000, readyState: "BUILDING", target: "production", url: "web-abc.vercel.app", inspectorUrl: "https://vercel.com/acme/web/abc", creator: { username: "ada" }, meta: { githubCommitRef: "main", githubCommitSha: "8f3a1c", githubCommitMessage: "fix checkout", githubOrg: "acme", githubRepo: "web" } },
          { uid: "dpl_building", name: "web", projectId: "prj_1", created: since + 1_000, readyState: "ERROR", target: null, url: "web-old.vercel.app", errorCode: "BUILD_FAILED" },
          { uid: "dpl_ancient", name: "web", projectId: "prj_1", created: since - 86_400_000, readyState: "READY", target: "production", url: "web-ancient.vercel.app" },
          { uid: "dpl_other", name: "docs", projectId: "prj_2", created: Date.now() - 4_000, readyState: "READY", target: "production", url: "docs.vercel.app" },
        ],
        pagination: { count: 4, next: null, prev: null },
      },
    };
  });
  const plugin = startPlugin("vercel", { VERCEL_TOKEN: "vercel_test", VERCEL_TEAM_ID: "team_1", VERCEL_PROJECTS: "web", VERCEL_API_BASE: mock.base, VERCEL_STATE_FILE: stateFile });
  await until(() => plugin.events.length === 2, "vercel events");

  const byId = Object.fromEntries(plugin.events.map(({ event }) => [event.id, event]));
  assert.deepEqual(Object.keys(byId).sort(), ["vercel:dpl_building:error", "vercel:dpl_new:created"]);
  assert.equal(byId["vercel:dpl_building:error"].type, "com.vercel.deployment.error");
  assert.equal(byId["vercel:dpl_building:error"].data.environment, "preview");
  assert.equal(byId["vercel:dpl_building:error"].data.error_code, "BUILD_FAILED");
  const created = byId["vercel:dpl_new:created"];
  assert.equal(created.source, "vercel/web");
  assert.deepEqual(
    { environment: created.data.environment, branch: created.data.branch, repo: created.data.repo, url: created.data.url },
    { environment: "production", branch: "main", repo: "acme/web", url: "https://web-abc.vercel.app" },
  );
  assert.match(mock.requests[0].url, /teamId=team_1/);
  assert.equal(mock.requests[0].headers.authorization, "Bearer vercel_test");
  await until(() => JSON.parse(readFileSync(stateFile, "utf8")).states.dpl_ancient === "READY", "vercel state");
});

test("vercel webhook: HMAC-SHA1 over the raw body gates publishing", async () => {
  const secret = "vercel-webhook-secret";
  const plugin = startPlugin("vercel", { VERCEL_MODE: "webhook", VERCEL_WEBHOOK_SECRET: secret, VERCEL_WEBHOOK_PORT: "0" });
  const url = await plugin.webhookUrl();
  const raw = JSON.stringify({ id: "evt_1", type: "deployment.succeeded", createdAt: 1764000000000, payload: { team: { id: "team_1" }, user: { id: "usr_1" }, target: "production", project: { id: "prj_1" }, deployment: { id: "dpl_1", name: "web", url: "web-abc.vercel.app", meta: { githubCommitRef: "main" } }, links: { deployment: "https://vercel.com/acme/web/abc" } } });
  const sig = hmac("sha1", secret, raw);

  assert.equal((await post(url, raw, { "x-vercel-signature": flipBit(sig) })).status, 401);
  assert.equal((await post(url, raw, { "x-vercel-signature": hmac("sha256", secret, raw) })).status, 401);
  assert.equal(plugin.events.length, 0);
  assert.equal((await post(url, raw, { "x-vercel-signature": sig })).status, 202);
  const { event } = plugin.events[0];
  assert.equal(event.id, "vercel:evt_1");
  assert.equal(event.type, "com.vercel.deployment.succeeded");
  assert.equal(event.time, "2025-11-24T16:00:00.000Z");
  assert.deepEqual({ env: event.data.environment, branch: event.data.branch, dep: event.data.deployment_id }, { env: "production", branch: "main", dep: "dpl_1" });
});

// ---------------------------------------------------------------------------------------
// Notion
// ---------------------------------------------------------------------------------------

test("notion poll: classifies created vs updated pages and dedupes minute-granular edit times", async () => {
  const dir = tempDir();
  const stateFile = join(dir, "notion.json");
  const cursor = past(3_600_000);
  const editedAgain = past(600_000);
  writeFileSync(stateFile, JSON.stringify({ cursor, seen: { "page-same": editedAgain } }));
  const title = (text) => ({ Name: { id: "title", type: "title", title: [{ plain_text: text }] } });
  const mock = await mockServer((req) => {
    if (req.url !== "/v1/search") return null;
    return {
      json: {
        object: "list",
        has_more: false,
        next_cursor: null,
        results: [
          { object: "page", id: "page-new", created_time: past(300_000), last_edited_time: past(240_000), url: "https://notion.so/page-new", parent: { type: "database_id", database_id: "db-1" }, properties: title("Launch plan"), last_edited_by: { id: "user-1" } },
          { object: "page", id: "page-same", created_time: past(86_400_000), last_edited_time: editedAgain, properties: title("Unchanged since last emit") },
          { object: "page", id: "page-edit", created_time: past(86_400_000), last_edited_time: past(900_000), url: "https://notion.so/page-edit", parent: { type: "workspace", workspace: true }, properties: title("Roadmap") },
          { object: "page", id: "page-old", created_time: past(172_800_000), last_edited_time: past(86_400_000), properties: title("Before cursor") },
        ],
      },
    };
  });
  const plugin = startPlugin("notion", { NOTION_TOKEN: "ntn_test", NOTION_API_BASE: mock.base, NOTION_STATE_FILE: stateFile });
  await until(() => plugin.events.length === 2, "notion events");

  assert.deepEqual(plugin.events.map(({ event }) => [event.subject, event.type]), [
    ["page-edit", "so.notion.page.updated"],
    ["page-new", "so.notion.page.created"],
  ]);
  const created = plugin.events[1].event;
  assert.equal(created.data.title, "Launch plan");
  assert.deepEqual({ type: created.data.parent_type, id: created.data.parent_id }, { type: "database_id", id: "db-1" });
  assert.equal(mock.requests[0].headers.authorization, "Bearer ntn_test");
  assert.equal(mock.requests[0].headers["notion-version"], "2022-06-28");
  assert.deepEqual(JSON.parse(mock.requests[0].body).sort, { timestamp: "last_edited_time", direction: "descending" });
});

test("notion webhook: setup handshake pins the token once, then only signed events publish", async () => {
  const dir = tempDir();
  const tokenFile = join(dir, "notion-verification-token");
  const plugin = startPlugin("notion", { NOTION_MODE: "webhook", NOTION_VERIFICATION_TOKEN_FILE: tokenFile, NOTION_WEBHOOK_PORT: "0" });
  const url = await plugin.webhookUrl();
  const token = "hyphae_test_verification_token_0001";
  const raw = JSON.stringify({ id: "367cba44", timestamp: "2024-12-05T23:55:34.285Z", workspace_id: "ws-1", workspace_name: "Quantify Labs", type: "page.created", authors: [{ id: "user-1", type: "person" }], attempt_number: 1, entity: { id: "page-1", type: "page" }, data: { parent: { id: "page-0", type: "page" } } });
  const sign = (secret) => `sha256=${hmac("sha256", secret, raw)}`;

  // Before the handshake there is no secret, so even a "signed" event is refused.
  assert.equal((await post(url, raw, { "x-notion-signature": sign(token) })).status, 401);
  assert.equal((await post(url, JSON.stringify({ verification_token: token }))).status, 200);
  assert.equal(readFileSync(tokenFile, "utf8").trim(), token);
  assert.equal(statSync(tokenFile).mode & 0o777, 0o600);
  assert.ok(!plugin.stderr().includes(token), "verification token must never reach stderr");

  // A second handshake must not replace the pinned token.
  assert.equal((await post(url, JSON.stringify({ verification_token: "attacker_token_attacker_token_1234" }))).status, 401);
  assert.equal(readFileSync(tokenFile, "utf8").trim(), token);
  assert.equal((await post(url, raw, { "x-notion-signature": sign("attacker_token_attacker_token_1234") })).status, 401);
  assert.equal(plugin.events.length, 0);

  assert.equal((await post(url, raw, { "x-notion-signature": sign(token) })).status, 202);
  const { event } = plugin.events[0];
  assert.equal(event.id, "notion:367cba44");
  assert.equal(event.type, "so.notion.page.created");
  assert.equal(event.source, "notion/ws-1");
  assert.deepEqual({ page: event.data.page_id, parent: event.data.parent_id, author: event.data.author_type }, { page: "page-1", parent: "page-0", author: "person" });
});

// ---------------------------------------------------------------------------------------
// Google: Gmail, Calendar, OAuth consent
// ---------------------------------------------------------------------------------------

function googleTokenMock() {
  return mockServer((req) => {
    const form = new URLSearchParams(req.body);
    if (form.get("grant_type") !== "refresh_token" || form.get("refresh_token") !== "refresh-test" || form.get("client_id") !== "client-test") {
      return { status: 400, json: { error: "invalid_grant" } };
    }
    return { json: { access_token: "access-test", expires_in: 3600, token_type: "Bearer" } };
  });
}
const googleEnv = (tokens) => ({ GOOGLE_CLIENT_ID: "client-test", GOOGLE_REFRESH_TOKEN: "refresh-test", GOOGLE_TOKEN_URL: `${tokens.base}/token` });

test("gmail: delivers new inbox mail as metadata + snippet, skips drafts, advances the history cursor", async () => {
  const dir = tempDir();
  const stateFile = join(dir, "gmail.json");
  writeFileSync(stateFile, JSON.stringify({ historyId: "100", seen: {} }));
  const tokens = await googleTokenMock();
  const gmail = await mockServer((req) => {
    if (req.headers.authorization !== "Bearer access-test") return { status: 401, json: { error: { message: "unauthenticated" } } };
    const url = new URL(req.url, "http://x");
    if (url.pathname === "/gmail/v1/users/me/profile") return { json: { emailAddress: "ada@example.com", historyId: "100" } };
    if (url.pathname === "/gmail/v1/users/me/history") {
      return {
        json: {
          historyId: "140",
          history: [
            { id: "120", messagesAdded: [{ message: { id: "m1", threadId: "t1", labelIds: ["INBOX", "UNREAD"] } }] },
            { id: "130", messagesAdded: [{ message: { id: "m2", threadId: "t2", labelIds: ["DRAFT"] } }, { message: { id: "m1", threadId: "t1", labelIds: ["INBOX"] } }] },
          ],
        },
      };
    }
    if (url.pathname === "/gmail/v1/users/me/messages/m1") {
      return { json: { id: "m1", threadId: "t1", labelIds: ["INBOX", "UNREAD"], snippet: "x".repeat(500), internalDate: "1764000000000", sizeEstimate: 2048, payload: { headers: [{ name: "From", value: "Grace <grace@example.com>" }, { name: "Subject", value: "Invoice #1042" }, { name: "To", value: "ada@example.com" }] } } };
    }
    return null;
  });
  const plugin = startPlugin("gmail", { ...googleEnv(tokens), GMAIL_API_BASE: gmail.base, GMAIL_STATE_FILE: stateFile, GMAIL_PREVIEW_CHARS: "50" });
  await until(() => plugin.events.length === 1, "gmail event");
  await until(() => JSON.parse(readFileSync(stateFile, "utf8")).historyId === "140", "gmail cursor");

  const { event } = plugin.events[0];
  assert.equal(event.type, "com.google.gmail.message.received");
  assert.equal(event.id, "gmail:ada@example.com:m1");
  assert.equal(event.source, "gmail/ada@example.com");
  assert.equal(event.time, "2025-11-24T16:00:00.000Z");
  assert.deepEqual({ from: event.data.from, subject: event.data.subject, unread: event.data.unread }, { from: "Grace <grace@example.com>", subject: "Invoice #1042", unread: true });
  assert.equal(event.data.preview.length, 50, "snippet must be clipped to GMAIL_PREVIEW_CHARS");
  const history = gmail.requests.find((r) => r.url.includes("/history"));
  assert.match(history.url, /startHistoryId=100/);
  assert.match(history.url, /labelId=INBOX/);
  assert.ok(gmail.requests.every((r) => !r.url.includes("format=full") && !r.url.includes("format=raw")), "message bodies must never be requested");
  assert.ok(!gmail.requests.some((r) => r.url.includes("/messages/m2")), "drafts must not be fetched");
  assert.ok(!plugin.stderr().includes("refresh-test") && !plugin.stderr().includes("access-test"));
});

test("gmail: an expired history cursor re-baselines instead of replaying or crashing", async () => {
  const dir = tempDir();
  const stateFile = join(dir, "gmail.json");
  writeFileSync(stateFile, JSON.stringify({ historyId: "5", seen: {} }));
  const tokens = await googleTokenMock();
  const gmail = await mockServer((req) => {
    const url = new URL(req.url, "http://x");
    if (url.pathname.endsWith("/profile")) return { json: { emailAddress: "ada@example.com", historyId: "9000" } };
    if (url.pathname.endsWith("/history")) return { status: 404, json: { error: { code: 404, message: "Requested entity was not found." } } };
    return null;
  });
  const plugin = startPlugin("gmail", { ...googleEnv(tokens), GMAIL_API_BASE: gmail.base, GMAIL_STATE_FILE: stateFile });
  await until(() => JSON.parse(readFileSync(stateFile, "utf8")).historyId === "9000", "gmail re-baseline");
  assert.match(plugin.stderr(), /history cursor expired/);
  assert.equal(plugin.events.length, 0);
});

test("gmail: a revoked refresh token reports invalid_grant without leaking it", async () => {
  const tokens = await mockServer(() => ({ status: 400, json: { error: "invalid_grant", error_description: "Token has been expired or revoked." } }));
  const plugin = startPlugin("gmail", { GOOGLE_CLIENT_ID: "client-test", GOOGLE_REFRESH_TOKEN: "revoked-refresh", GOOGLE_TOKEN_URL: `${tokens.base}/token`, GMAIL_API_BASE: "http://127.0.0.1:9" });
  // After fd 3 is open a fatal error must stop the process outright (never linger as a "running" plugin).
  const { code, signal } = await plugin.exited();
  assert.ok(code !== 0 || signal !== null);
  assert.match(plugin.stderr(), /gmail plugin fatal: .*invalid_grant/);
  assert.ok(!plugin.stderr().includes("    at "), "fatal errors log one line, not a stack trace");
  assert.ok(!plugin.stderr().includes("revoked-refresh"));
});

test("google-calendar: emits change events and one 'starting' reminder per occurrence", async () => {
  const dir = tempDir();
  const stateFile = join(dir, "calendar.json");
  writeFileSync(stateFile, JSON.stringify({ cursor: past(3_600_000), seen: {}, reminded: {} }));
  const tokens = await googleTokenMock();
  const created = past(120_000);
  const soon = new Date(Date.now() + 4 * 60_000).toISOString();
  const calendar = await mockServer((req) => {
    if (req.headers.authorization !== "Bearer access-test") return { status: 401, json: {} };
    const url = new URL(req.url, "http://x");
    if (url.pathname !== "/calendar/v3/calendars/primary/events") return null;
    if (url.searchParams.has("updatedMin")) {
      return {
        json: {
          items: [
            { id: "ev-new", status: "confirmed", summary: "Design review", created, updated: created, start: { dateTime: soon }, end: { dateTime: soon }, htmlLink: "https://calendar.google.com/ev-new", organizer: { email: "grace@example.com" }, attendees: [{ email: "ada@example.com", self: true, responseStatus: "accepted" }, { email: "grace@example.com" }], hangoutLink: "https://meet.google.com/abc" },
            { id: "ev-gone", status: "cancelled", updated: past(60_000) },
          ],
        },
      };
    }
    return {
      json: {
        items: [
          { id: "ev-new", status: "confirmed", summary: "Design review", start: { dateTime: soon }, end: { dateTime: soon }, attendees: [{ self: true, responseStatus: "accepted" }] },
          { id: "ev-declined", status: "confirmed", summary: "Skipped", start: { dateTime: soon }, end: { dateTime: soon }, attendees: [{ self: true, responseStatus: "declined" }] },
          { id: "ev-allday", status: "confirmed", summary: "Offsite", start: { date: "2030-01-01" }, end: { date: "2030-01-02" } },
        ],
      },
    };
  });
  const plugin = startPlugin("google-calendar", { ...googleEnv(tokens), CALENDAR_API_BASE: calendar.base, CALENDAR_STATE_FILE: stateFile });
  await until(() => plugin.events.length === 3, "calendar events");

  const types = plugin.events.map(({ event }) => `${event.subject}:${event.type.split(".").at(-1)}`).sort();
  assert.deepEqual(types, ["ev-gone:cancelled", "ev-new:created", "ev-new:starting"]);
  const starting = plugin.events.find(({ event }) => event.type.endsWith(".starting")).event;
  assert.equal(starting.source, "google-calendar/primary");
  assert.ok(starting.data.minutes_until >= 3 && starting.data.minutes_until <= 4);
  const createdEvent = plugin.events.find(({ event }) => event.type.endsWith(".created")).event;
  assert.deepEqual(
    { title: createdEvent.data.title, attendees: createdEvent.data.attendees, mine: createdEvent.data.my_response, meet: createdEvent.data.meeting_url },
    { title: "Design review", attendees: 2, mine: "accepted", meet: "https://meet.google.com/abc" },
  );
  const changes = calendar.requests.find((r) => r.url.includes("updatedMin"));
  assert.match(changes.url, /showDeleted=true/);
  await until(() => Object.keys(JSON.parse(readFileSync(stateFile, "utf8")).reminded).length === 1, "calendar reminder state");
});

test("google-oauth consent: PKCE + state round trip yields the refresh token; wrong state is ignored", async () => {
  let challenge = "";
  const tokens = await mockServer((req) => {
    const form = new URLSearchParams(req.body);
    const derived = createHash("sha256").update(form.get("code_verifier") ?? "").digest("base64url");
    if (form.get("grant_type") !== "authorization_code" || form.get("code") !== "auth-code" || derived !== challenge) {
      return { status: 400, json: { error: "invalid_grant" } };
    }
    return { json: { access_token: "a", refresh_token: "refresh-from-consent", scope: "https://www.googleapis.com/auth/gmail.readonly" } };
  });
  const result = await runConsent({
    clientId: "client-test",
    clientSecret: "",
    scopes: ["https://www.googleapis.com/auth/gmail.readonly"],
    tokenUrl: `${tokens.base}/token`,
    onUrl: async (raw) => {
      const consent = new URL(raw);
      assert.equal(consent.origin + consent.pathname, "https://accounts.google.com/o/oauth2/v2/auth");
      assert.equal(consent.searchParams.get("code_challenge_method"), "S256");
      assert.equal(consent.searchParams.get("access_type"), "offline");
      challenge = consent.searchParams.get("code_challenge");
      const redirect = consent.searchParams.get("redirect_uri");
      assert.match(redirect, /^http:\/\/127\.0\.0\.1:\d+\/oauth2\/callback$/);
      // A forged redirect with the wrong state must be rejected and must not end the flow.
      assert.equal((await fetch(`${redirect}?code=stolen&state=wrong`)).status, 400);
      assert.equal((await fetch(`${redirect}?code=auth-code&state=${consent.searchParams.get("state")}`)).status, 200);
    },
  });
  assert.equal(result.refreshToken, "refresh-from-consent");
  assert.equal(tokens.requests.length, 1, "only the genuine redirect may reach the token endpoint");
  assert.equal(new URLSearchParams(tokens.requests[0].body).get("code"), "auth-code");
});

test("google-oauth CLI refuses to print a refresh token and rejects unknown scopes before any network call", async () => {
  const run = (args) => new Promise((resolve) => {
    const child = spawn(process.execPath, [join(PLUGINS, "sdk", "google-oauth.mjs"), ...args], { stdio: ["ignore", "pipe", "pipe"] });
    let stderr = "";
    let stdout = "";
    child.stderr.on("data", (c) => { stderr += c; });
    child.stdout.on("data", (c) => { stdout += c; });
    child.on("exit", (code) => resolve({ code, stderr, stdout }));
  });
  const usage = await run([]);
  assert.equal(usage.code, 2);
  const badScope = await run(["auth", "--client-id", "client-test", "--scopes", "drive"]);
  assert.equal(badScope.code, 1);
  assert.match(badScope.stderr, /Unknown scope 'drive'/);
  assert.equal(badScope.stdout, "");
});

// ---------------------------------------------------------------------------------------
// AgentMail (minimal RFC 6455 mock server: handshake, masked client frames, text frames out)
// ---------------------------------------------------------------------------------------

async function agentmailMock(onSubscribe) {
  const seen = { urls: [], subscribes: [] };
  const sockets = new Set();
  const server = createServer();
  server.on("upgrade", (req, socket) => {
    sockets.add(socket);
    seen.urls.push(req.url);
    const accept = createHash("sha1").update(req.headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
    socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
    const send = (obj) => {
      const payload = Buffer.from(JSON.stringify(obj));
      const head = payload.length < 126 ? Buffer.from([0x81, payload.length]) : Buffer.from([0x81, 126, payload.length >> 8, payload.length & 0xff]);
      socket.write(Buffer.concat([head, payload]));
    };
    let buffer = Buffer.alloc(0);
    socket.on("data", (chunk) => {
      buffer = Buffer.concat([buffer, chunk]);
      while (buffer.length >= 6) {
        let len = buffer[1] & 0x7f;
        let offset = 2;
        if (len === 126) { len = buffer.readUInt16BE(2); offset = 4; }
        if (buffer.length < offset + 4 + len) return;
        const mask = buffer.subarray(offset, offset + 4);
        const payload = Buffer.from(buffer.subarray(offset + 4, offset + 4 + len));
        for (let i = 0; i < payload.length; i += 1) payload[i] ^= mask[i % 4];
        const opcode = buffer[0] & 0x0f;
        buffer = buffer.subarray(offset + 4 + len);
        if (opcode === 8) {
          // Complete the closing handshake like a real server, so the client's close event fires.
          socket.end(Buffer.from([0x88, 0x00]));
          return;
        }
        if (opcode !== 1) continue;
        const frame = JSON.parse(payload.toString("utf8"));
        seen.subscribes.push(frame);
        onSubscribe(send, frame);
      }
    });
    socket.on("error", () => {});
  });
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  // Upgraded sockets are no longer HTTP connections, so they must be destroyed explicitly.
  cleanups.push(() => new Promise((resolve) => { for (const socket of sockets) socket.destroy(); server.close(resolve); }));
  return { url: `ws://127.0.0.1:${server.address().port}/v0`, seen };
}

const liveMail = (id, timestamp, extra = {}) => ({
  type: "event",
  event_type: "message.received",
  event_id: `evt_${id}`,
  message: { inbox_id: "billing@agentmail.to", thread_id: "thr_1", message_id: `<${id}@mail>`, from: "Grace <grace@example.com>", to: ["billing@agentmail.to"], subject: "Invoice overdue", preview: "p".repeat(900), labels: ["received", "unread"], timestamp, size: 4096, attachments: [{}, {}], ...extra },
  thread: { inbox_id: "billing@agentmail.to", thread_id: "thr_1" },
});

test("agentmail: subscribes over WebSocket and forwards mail as metadata + clipped preview", async () => {
  const dir = tempDir();
  const stateFile = join(dir, "agentmail.json");
  const api = await mockServer(() => ({ json: { count: 0, messages: [] } }));
  const mock = await agentmailMock((send, frame) => {
    send({ type: "subscribed", event_types: frame.event_types, inbox_ids: frame.inbox_ids });
    send({ type: "event", event_type: "not valid!", event_id: "evt_bad", message: {} });
    send(liveMail("msg1", "2025-11-24T16:00:00Z", { text: "FULL BODY MUST NOT BE FORWARDED", html: "<b>FULL BODY</b>" }));
  });
  const plugin = startPlugin("agentmail", { AGENTMAIL_API_KEY: "am_test_key", AGENTMAIL_WS_URL: mock.url, AGENTMAIL_API_BASE: api.base, AGENTMAIL_STATE_FILE: stateFile, AGENTMAIL_INBOXES: "billing@agentmail.to", AGENTMAIL_PREVIEW_CHARS: "120" });
  await until(() => plugin.events.length === 1, "agentmail event");

  assert.deepEqual(mock.seen.subscribes[0], { type: "subscribe", event_types: ["message.received"], inbox_ids: ["billing@agentmail.to"] });
  assert.equal(mock.seen.urls[0], "/v0?api_key=am_test_key");
  const { event } = plugin.events[0];
  assert.equal(event.id, "agentmail:billing@agentmail.to:<msg1@mail>");
  assert.equal(event.type, "to.agentmail.message.received");
  assert.equal(event.source, "agentmail/billing@agentmail.to");
  assert.equal(event.time, "2025-11-24T16:00:00.000Z");
  assert.deepEqual(
    { from: event.data.from, subject: event.data.subject, labels: event.data.labels, attachments: event.data.attachments, event_id: event.data.event_id, replayed: event.data.replayed },
    { from: "Grace <grace@example.com>", subject: "Invoice overdue", labels: ["received", "unread"], attachments: 2, event_id: "evt_msg1", replayed: false },
  );
  assert.equal(event.data.preview.length, 120);
  assert.ok(!JSON.stringify(event).includes("FULL BODY"), "message bodies must never be forwarded");
  assert.ok(!plugin.stderr().includes("am_test_key"), "API key must never reach stderr");
  // First sight of an inbox starts at "now": the catch-up lists nothing and replays nothing.
  assert.ok(!api.requests.some((r) => r.url.includes("/messages")), "a first run must not list old mail");
  await until(() => JSON.parse(readFileSync(stateFile, "utf8")).cursors["billing@agentmail.to"], "agentmail cursor");
});

test("agentmail: on connect, mail received while disconnected is caught up over REST and keyed like live mail", async () => {
  const dir = tempDir();
  const stateFile = join(dir, "agentmail.json");
  // m0 was delivered before the disconnect, at exactly the cursor instant. AgentMail's `after` filter
  // includes that instant, so the listing returns m0 again and the plugin must skip it.
  writeFileSync(stateFile, JSON.stringify({ cursors: { "billing@agentmail.to": "2025-11-24T15:00:00.000Z" }, atCursor: { "billing@agentmail.to": ["<m0@mail>"] } }));
  const missed = (id, timestamp, labels = ["received"]) => ({ inbox_id: "billing@agentmail.to", thread_id: "thr_9", message_id: `<${id}@mail>`, labels, timestamp, from: "ops@example.com", to: ["billing@agentmail.to"], subject: `Missed ${id}`, preview: "while you were away", size: 100 });
  const api = await mockServer((req) => {
    if (req.headers.authorization !== "Bearer am_test_key") return { status: 401, json: { name: "Unauthorized", message: "bad key" } };
    const url = new URL(req.url, "http://x");
    if (url.pathname !== "/v0/inboxes/billing%40agentmail.to/messages") return null;
    if (url.searchParams.get("page_token") === "p2") return { json: { count: 1, messages: [missed("m3", "2025-11-24T15:30:00Z")] } };
    return { json: { count: 3, next_page_token: "p2", messages: [missed("m0", "2025-11-24T15:00:00Z"), missed("m1", "2025-11-24T15:10:00Z"), missed("sent1", "2025-11-24T15:15:00Z", ["sent"]), missed("m2", "2025-11-24T15:20:00Z")] } };
  });
  // m2 also arrives live, and before the catch-up has listed anything. It must not move the cursor
  // past m1 (which would lose it), and both copies must carry the same id so the node stores it once.
  const mock = await agentmailMock((send, frame) => {
    send({ type: "subscribed", event_types: frame.event_types });
    send(liveMail("m2", "2025-11-24T15:20:00Z"));
  });
  const plugin = startPlugin("agentmail", { AGENTMAIL_API_KEY: "am_test_key", AGENTMAIL_WS_URL: mock.url, AGENTMAIL_API_BASE: api.base, AGENTMAIL_STATE_FILE: stateFile, AGENTMAIL_INBOXES: "billing@agentmail.to" });
  await until(() => plugin.events.length === 4, "agentmail live + catch-up events");

  const ids = plugin.events.map(({ event }) => event.id);
  const id = (m) => `agentmail:billing@agentmail.to:<${m}@mail>`;
  assert.deepEqual([...new Set(ids)].sort(), [id("m1"), id("m2"), id("m3")], "sent mail is skipped; live and replayed m2 share one id");
  assert.equal(ids.filter((v) => v === id("m2")).length, 2);
  const replayed = plugin.events.filter(({ event }) => event.data.replayed).map(({ event }) => event.subject);
  assert.deepEqual(replayed, ["thr_9/<m1@mail>", "thr_9/<m2@mail>", "thr_9/<m3@mail>"], "catch-up publishes oldest first across pages");
  const first = new URL(api.requests[0].url, "http://x").searchParams;
  assert.deepEqual(
    { after: first.get("after"), ascending: first.get("ascending"), labels: first.get("labels") },
    { after: "2025-11-24T15:00:00.000Z", ascending: "true", labels: "received" },
  );
  await until(() => JSON.parse(readFileSync(stateFile, "utf8")).cursors["billing@agentmail.to"] === "2025-11-24T15:30:00.000Z", "agentmail cursor advanced to the newest caught-up message");
  assert.match(plugin.stderr(), /caught up on 3 message\(s\)/);
  assert.ok(!ids.includes(id("m0")), "the message already delivered at the cursor instant must not be replayed");
  assert.deepEqual(JSON.parse(readFileSync(stateFile, "utf8")).atCursor["billing@agentmail.to"], ["<m3@mail>"]);
  assert.ok(!plugin.stderr().includes("am_test_key"));
});

test("agentmail: a failed publish stops the connection from advancing the cursor past the lost message", async () => {
  const dir = tempDir();
  const stateFile = join(dir, "agentmail.json");
  const cursor = "2025-11-24T15:00:00.000Z";
  writeFileSync(stateFile, JSON.stringify({ cursors: { "billing@agentmail.to": cursor } }));
  const api = await mockServer(() => ({ json: { count: 0, messages: [] } }));
  let connections = 0;
  const mock = await agentmailMock((send, frame) => {
    connections += 1;
    send({ type: "subscribed", event_types: frame.event_types });
    if (connections === 1) {
      send(liveMail("lost", "2025-11-24T15:10:00Z"));
      send(liveMail("later", "2025-11-24T15:20:00Z"));
    }
  });
  let attempts = 0;
  startPlugin(
    "agentmail",
    { AGENTMAIL_API_KEY: "am_test_key", AGENTMAIL_WS_URL: mock.url, AGENTMAIL_API_BASE: api.base, AGENTMAIL_STATE_FILE: stateFile, AGENTMAIL_INBOXES: "billing@agentmail.to" },
    { ackWith: () => { attempts += 1; return { error: { code: -32005, message: "unavailable" } }; } },
  );
  // The plugin reconnects after the failure; by then both live events have been handled.
  await until(() => connections >= 2, "agentmail reconnect after failed publish");
  assert.equal(attempts, 1, "the event behind the failed one must not be published on that connection");
  assert.equal(JSON.parse(readFileSync(stateFile, "utf8")).cursors["billing@agentmail.to"], cursor, "cursor must stay before the lost message");
});

test("a node that cannot store yet makes the plugin retry instead of dropping the event", async () => {
  const dir = tempDir();
  const stateFile = join(dir, "sentry.json");
  writeFileSync(stateFile, JSON.stringify({ cursor: past(3_600_000), seen: {} }));
  const mock = await mockServer(() => ({ json: [{ id: "5", shortId: "API-5", title: "retry me", firstSeen: past(60_000), project: { slug: "api" } }] }));
  let attempts = 0;
  const plugin = startPlugin(
    "sentry",
    { SENTRY_AUTH_TOKEN: "t", SENTRY_ORG: "acme", SENTRY_API_BASE: mock.base, SENTRY_STATE_FILE: stateFile, SENTRY_POLL_SECONDS: "15" },
    { ackWith: () => { attempts += 1; return attempts === 1 ? { error: { code: -32005, message: "unavailable" } } : { result: { status: "stored" } }; } },
  );
  await until(() => attempts === 1, "first (nacked) publish");
  assert.deepEqual(JSON.parse(readFileSync(stateFile, "utf8")).seen, {}, "a nacked event must not be marked as delivered");
  assert.equal(plugin.events.length, 0);
  await until(() => plugin.stderr().includes("temporarily unavailable"), "retry log");
});

test("webhook + Tailscale Funnel: publishes only the plugin path, logs the public URL, and stays signed", async () => {
  const dir = tempDir();
  const calls = join(dir, "tailscale-calls.log");
  const fake = join(dir, "tailscale");
  // Stand-in for the Tailscale CLI: records its arguments and answers `status --json`.
  writeFileSync(fake, `#!/bin/sh\necho "$@" >> "${calls}"\nif [ "$1" = "status" ]; then echo '{"Self":{"DNSName":"hub.tail1234.ts.net."}}'; fi\n`, { mode: 0o755 });
  const secret = "sentry-client-secret";
  const plugin = startPlugin("sentry", { SENTRY_MODE: "webhook", SENTRY_CLIENT_SECRET: secret, SENTRY_WEBHOOK_PORT: "0", SENTRY_WEBHOOK_FUNNEL: "8443", TAILSCALE_BIN: fake });
  const url = await plugin.webhookUrl();
  await until(() => plugin.stderr().includes("public webhook URL (Tailscale Funnel): https://hub.tail1234.ts.net:8443/sentry"), "funnel URL log");

  const port = new URL(url).port;
  assert.deepEqual(readFileSync(calls, "utf8").trim().split("\n"), [
    `funnel --bg --https=8443 --set-path=/sentry http://127.0.0.1:${port}`,
    "status --json",
  ]);

  // Funnel may deliver the request with or without the mount path; both are accepted, both stay signed.
  const raw = JSON.stringify({ action: "unresolved", data: { issue: { id: "7", shortId: "WEB-7", title: "Regressed", status: "unresolved", substatus: "regressed", project: { slug: "web" } } } });
  const headers = { "sentry-hook-resource": "issue", "sentry-hook-signature": hmac("sha256", secret, raw) };
  const root = url.replace(/\/sentry$/, "/");
  assert.equal((await post(root, raw, { ...headers, "sentry-hook-signature": flipBit(headers["sentry-hook-signature"]) })).status, 401);
  assert.equal(plugin.events.length, 0);
  assert.equal((await post(root, raw, headers)).status, 202);
  assert.equal((await post(url, raw, headers)).status, 202);
  assert.equal(plugin.events[0].event.type, "io.sentry.issue.unresolved");
  assert.equal(plugin.events[0].event.data.substatus, "regressed");
  assert.equal(plugin.events[0].event.id, plugin.events[1].event.id, "the same delivery on either path is one event to the node");
});

test("webhook + Tailscale Funnel: a missing or failing tailscale leaves the listener local-only and running", async () => {
  const plugin = startPlugin("vercel", { VERCEL_MODE: "webhook", VERCEL_WEBHOOK_SECRET: "s", VERCEL_WEBHOOK_PORT: "0", VERCEL_WEBHOOK_FUNNEL: "8443", TAILSCALE_BIN: "/nonexistent/tailscale" });
  const url = await plugin.webhookUrl();
  await until(() => plugin.stderr().includes("could not enable Tailscale Funnel (listener stays local-only)"), "funnel failure log");
  const raw = JSON.stringify({ id: "evt_2", type: "deployment.error", payload: { deployment: { id: "dpl_2", name: "web" } } });
  assert.equal((await post(url, raw, { "x-vercel-signature": hmac("sha1", "s", raw) })).status, 202);
  assert.equal(plugin.events.length, 1);

  // Misconfiguration fails closed at startup: bad port, or a listener that is not on loopback.
  for (const env of [{ VERCEL_WEBHOOK_FUNNEL: "80" }, { VERCEL_WEBHOOK_FUNNEL: "8443", VERCEL_WEBHOOK_HOST: "0.0.0.0" }]) {
    const bad = startPlugin("vercel", { VERCEL_MODE: "webhook", VERCEL_WEBHOOK_SECRET: "s", VERCEL_WEBHOOK_PORT: "0", ...env });
    const { code, signal } = await bad.exited();
    assert.ok(code !== 0 || signal !== null);
    assert.match(bad.stderr(), /VERCEL_WEBHOOK_FUNNEL (must be 443, 8443 or 10000|requires the listener to stay on loopback)/);
  }
});

test("sdk: a bridge that crashes after connecting exits instead of hanging as 'running'", async () => {
  // TELEGRAM_TARGET names a target the node did not offer, so the bridge throws right after hello,
  // while its channel read is pending: the exact state that used to hang forever.
  const plugin = startPlugin("telegram", { TELEGRAM_BOT_TOKEN: "123456:FAKE", TELEGRAM_ALLOWED_USERS: "42", TELEGRAM_TARGET: "not-offered", TELEGRAM_API_BASE: "http://127.0.0.1:9" });
  const { code, signal } = await plugin.exited();
  assert.ok(code !== 0 || signal !== null, "the process must be gone");
  assert.match(plugin.stderr(), /telegram plugin fatal: Target 'not-offered' not in configured targets/);
  assert.ok(!plugin.stderr().includes("123456:FAKE"), "bot token must never reach stderr");
  assert.ok(!plugin.stderr().includes("    at "), "fatal errors log one line, not a stack trace");
});

// ---------------------------------------------------------------------------------------
// Onboarding trees (hyphae.onboarding/v1)
// ---------------------------------------------------------------------------------------

const SOURCE_PLUGINS = ["agentmail", "sentry", "gmail", "google-calendar", "vercel", "notion"];
const STEP_TYPES = new Set(["ask", "input", "secret", "human", "run", "config", "verify", "subtree", "done"]);
const nextTargets = (next) => (next === undefined ? [] : typeof next === "string" ? [next] : Object.values(next.cases));

function validateTree(tree, label) {
  assert.equal(tree.schema, "hyphae.onboarding/v1", `${label} schema`);
  for (const field of ["id", "title", "summary", "kind", "status", "privacy", "start"]) {
    assert.equal(typeof tree[field], "string", `${label}.${field}`);
  }
  assert.ok(tree.steps[tree.start], `${label} start step exists`);
  const reached = new Set();
  const stack = [tree.start];
  while (stack.length > 0) {
    const id = stack.pop();
    if (reached.has(id)) continue;
    const step = tree.steps[id];
    assert.ok(step, `${label} references missing step '${id}'`);
    assert.ok(STEP_TYPES.has(step.type), `${label}.${id} has unknown type '${step.type}'`);
    if (step.type === "done") assert.equal(step.next, undefined, `${label}.${id} done must be terminal`);
    else assert.ok(step.next, `${label}.${id} needs next`);
    if (step.type === "ask") assert.ok(Array.isArray(step.options) && step.options.length >= 2 && step.question, `${label}.${id} ask needs a question and options`);
    if (step.type === "input" && step.validate) assert.doesNotThrow(() => new RegExp(step.validate), `${label}.${id} validate regex`);
    if (step.type === "secret") assert.match(step.name, /^[a-z][a-z0-9-]+$/, `${label}.${id} secret name`);
    if (step.type === "verify") assert.ok(step.command && step.expect && step.onFail, `${label}.${id} verify needs command, expect and onFail`);
    reached.add(id);
    stack.push(...nextTargets(step.next));
  }
  assert.deepEqual(Object.keys(tree.steps).filter((id) => !reached.has(id)), [], `${label} has unreachable steps`);
  assert.ok([...reached].some((id) => tree.steps[id].type === "done"), `${label} never reaches done`);
  return reached;
}

test("every event-source plugin ships a valid onboarding tree that follows the generic skeleton", () => {
  for (const name of SOURCE_PLUGINS) {
    const tree = JSON.parse(readFileSync(join(PLUGINS, name, "onboarding.json"), "utf8"));
    validateTree(tree, name);
    assert.equal(tree.id, name);
    assert.equal(tree.start, "placement", `${name} must first settle where the plugin runs`);
    assert.deepEqual(tree.steps.placement.options.map((o) => o.value), ["local", "hub"]);
    assert.equal(tree.steps.install.command, `hyp plugin install ${name} --json`);

    const entry = tree.steps.wire.merge.plugins[0];
    assert.equal(entry.id, name);
    assert.equal(entry.kind, "source");
    const script = readFileSync(join(PLUGINS, name, "index.mjs"), "utf8") + readFileSync(join(PLUGINS, "sdk", "google-oauth.mjs"), "utf8");
    const secretSteps = new Set(Object.values(tree.steps).filter((s) => s.type === "secret").map((s) => s.name));
    for (const [key, value] of Object.entries(entry.env)) {
      assert.ok(script.includes(key), `${name} tree wires env ${key}, which the plugin never reads`);
      // A credential in config must never be a literal, and (Google aside, where the consent helper
      // stores them) must have a secret step that tells the human how to create it.
      if (/(TOKEN|SECRET|KEY)$/.test(key)) assert.equal(typeof value.secret, "string", `${name} env ${key} must be a secret reference`);
      if (value?.secret && !value.secret.startsWith("google-")) assert.ok(secretSteps.has(value.secret), `${name} has no secret step for '${value.secret}'`);
    }
    // Personal-data plugins must stop and check who can subscribe before anything is wired.
    if (tree.privacy === "private") {
      assert.equal(tree.steps.expose.type, "verify");
      assert.equal(tree.steps.expose.command, "hyp pair list --json");
    }
    assert.equal(tree.steps.done.subscribe.arguments.topic.cases.local, `local.${name}`);
  }
});

test("the setup skill's root tree is valid and its plugin catalog matches the shipped trees", () => {
  const skill = readFileSync(join(PLUGINS, "..", "skills", "hyphae-setup", "SKILL.md"), "utf8");
  const block = skill.match(/### Root tree \(Mode 1\)[\s\S]*?```json\n([\s\S]*?)\n```/);
  assert.ok(block, "root tree block present in hyphae-setup SKILL.md");
  const root = JSON.parse(block[1]);
  validateTree(root, "root");
  assert.equal(root.kind, "node");
  const catalog = root.steps.plugins.options;
  assert.deepEqual(catalog.map((o) => o.value).sort(), [...SOURCE_PLUGINS].sort());
  for (const option of catalog) {
    const tree = JSON.parse(readFileSync(join(PLUGINS, option.value, "onboarding.json"), "utf8"));
    assert.equal(option.label, tree.title, `catalog label for ${option.value}`);
  }
  assert.match(root.steps.plugin_each.from, /onboardingPath/);
});
