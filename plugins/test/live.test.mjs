/**
 * LIVE tests for the event-source plugins. They talk to the real providers with real
 * credentials, so they are never run in CI and every test skips itself unless its
 * credentials are present in the environment.
 *
 * Keep credentials out of shell history and out of this process's argv: store them with
 * `hyp secret set <name> --web` and inject them with `hyp exec`. `hyp exec` refuses secrets
 * that node.json references, so use dedicated test keys under `live-*` names:
 *
 *   hyp secret set live-agentmail-api-key --web
 *   hyp exec --env AGENTMAIL_API_KEY=live-agentmail-api-key -- node --test plugins/test/live.test.mjs
 *
 * Environment per provider (a provider is skipped when its first variable is unset):
 *   AgentMail  AGENTMAIL_API_KEY, [AGENTMAIL_LIVE_INBOX], [AGENTMAIL_LIVE_FROM_INBOX], [AGENTMAIL_API_BASE], [AGENTMAIL_WS_URL]
 *   Sentry     SENTRY_AUTH_TOKEN, SENTRY_ORG, [SENTRY_API_BASE]
 *   Vercel     VERCEL_TOKEN, [VERCEL_TEAM_ID]
 *   Notion     NOTION_TOKEN
 *   Google     GOOGLE_CLIENT_ID, GOOGLE_REFRESH_TOKEN, [GOOGLE_CLIENT_SECRET]   (Gmail and Calendar)
 *              + GMAIL_LIVE_ADDRESS and AGENTMAIL_API_KEY for the Gmail end-to-end test (a real mail is sent)
 *
 * What is exercised: the real plugin script, spawned with fd 3 wired to this process exactly
 * like the node's supervisor does. AgentMail is tested end to end (a real message is sent and
 * must arrive live, then again through the reconnect catch-up). The polling plugins get a smoke
 * test: authenticate, complete a first poll cleanly, publish nothing from history.
 */
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { createInterface } from "node:readline";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";

const PLUGINS = join(dirname(fileURLToPath(import.meta.url)), "..");
const env = (name) => process.env[name]?.trim() ?? "";
const pick = (...names) => Object.fromEntries(names.filter((n) => env(n)).map((n) => [n, env(n)]));
const cleanups = [];
after(async () => {
  for (const fn of cleanups.reverse()) await fn();
});

const stateDir = mkdtempSync(join(tmpdir(), "hyp-plugin-live-"));
cleanups.push(() => rmSync(stateDir, { recursive: true, force: true }));

async function until(check, label, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const value = await check();
    if (value) return value;
    await new Promise((r) => setTimeout(r, 100));
  }
  throw new Error(`timed out after ${Math.round(timeoutMs / 1000)}s waiting for ${label}`);
}

function startPlugin(name, pluginEnv) {
  const child = spawn(process.execPath, [join(PLUGINS, name, "index.mjs")], {
    env: { PATH: process.env.PATH, HOME: process.env.HOME, HYPHAE_FD: "3", HYPHAE_PLUGIN: name, ...pluginEnv },
    stdio: ["ignore", "ignore", "pipe", "pipe"],
  });
  const channel = child.stdio[3];
  const events = [];
  let stderr = "";
  let exit = null;
  child.stderr.on("data", (chunk) => { stderr += chunk.toString("utf8"); });
  child.on("exit", (code, signal) => { exit = { code, signal }; });
  channel.on("error", () => {});
  createInterface({ input: channel }).on("line", (line) => {
    const msg = JSON.parse(line);
    if (msg.method !== "hyphae/publish") return;
    events.push(msg.params.event);
    channel.write(JSON.stringify({ jsonrpc: "2.0", id: msg.id, result: { status: "stored" } }) + "\n");
  });
  channel.write(JSON.stringify({ jsonrpc: "2.0", method: "hyphae/hello", params: { protocol: 2, plugin: name, targets: [name] } }) + "\n");
  const stop = () => new Promise((resolve) => {
    if (exit !== null) return resolve();
    child.once("exit", resolve);
    child.kill("SIGKILL");
  });
  cleanups.push(stop);
  return { events, stderr: () => stderr, exited: () => exit, stop };
}

/** Starts a polling plugin and checks that its first poll against the real API is clean and silent. */
async function smoke(name, pluginEnv, { secrets }) {
  const plugin = startPlugin(name, { ...pluginEnv, HYPHAE_STATE_DIR: stateDir });
  await until(() => plugin.stderr().includes(" polling ") || plugin.exited(), `${name} to start polling`, 30_000);
  assert.equal(plugin.exited(), null, `${name} exited at startup:\n${plugin.stderr()}`);
  // Give the first poll time to complete; any auth, scope or shape problem is logged as a poll error.
  await new Promise((r) => setTimeout(r, 6_000));
  assert.equal(plugin.exited(), null, `${name} crashed during its first poll:\n${plugin.stderr()}`);
  assert.ok(!/poll error|fatal/.test(plugin.stderr()), `${name} first poll failed:\n${plugin.stderr()}`);
  assert.equal(plugin.events.length, 0, `${name} must not replay history on a first run`);
  for (const secret of secrets) assert.ok(!plugin.stderr().includes(secret), `${name} leaked a credential to stderr`);
  await plugin.stop();
}

// ---------------------------------------------------------------------------------------
// AgentMail: real message in, live event out, then the reconnect catch-up
// ---------------------------------------------------------------------------------------

test("agentmail live: a real message arrives as an event, and one sent while offline is caught up", { skip: !env("AGENTMAIL_API_KEY") && "AGENTMAIL_API_KEY not set", timeout: 180_000 }, async () => {
  const key = env("AGENTMAIL_API_KEY");
  const apiBase = (env("AGENTMAIL_API_BASE") || "https://api.agentmail.to").replace(/\/+$/, "");
  const api = async (path, body) => {
    const res = await fetch(`${apiBase}${path}`, {
      method: body ? "POST" : "GET",
      headers: { authorization: `Bearer ${key}`, ...(body ? { "content-type": "application/json" } : {}) },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(20_000),
    });
    const json = await res.json().catch(() => ({}));
    assert.ok(res.ok, `AgentMail ${path} returned HTTP ${res.status}: ${json.message ?? json.name ?? ""}`);
    return json;
  };

  let inbox = env("AGENTMAIL_LIVE_INBOX");
  if (!inbox) {
    const listed = await api("/v0/inboxes?limit=10");
    inbox = listed.inboxes?.find((i) => i.status !== "deactivated")?.inbox_id;
    assert.ok(inbox, "the API key can read no inbox; create one in the AgentMail console or set AGENTMAIL_LIVE_INBOX");
  }
  const from = env("AGENTMAIL_LIVE_FROM_INBOX") || inbox;
  const pluginEnv = { ...pick("AGENTMAIL_API_KEY", "AGENTMAIL_API_BASE", "AGENTMAIL_WS_URL"), AGENTMAIL_INBOXES: inbox, AGENTMAIL_STATE_FILE: join(stateDir, "agentmail-live.json") };
  const send = (subject) => api(`/v0/inboxes/${encodeURIComponent(from)}/messages/send`, { to: [inbox], subject, text: "Hyphae live plugin test. Safe to delete." });
  const hint = from === inbox ? " (the message was sent from the inbox to itself; if AgentMail does not deliver that as received mail, set AGENTMAIL_LIVE_FROM_INBOX to a second inbox)" : "";

  // 1. Live delivery over the WebSocket.
  const run = randomBytes(4).toString("hex");
  const first = startPlugin("agentmail", pluginEnv);
  await until(() => first.stderr().includes("subscribed") || first.exited(), "agentmail subscription", 30_000);
  assert.equal(first.exited(), null, `agentmail exited at startup:\n${first.stderr()}`);
  const liveSubject = `hyphae-live-${run}-a`;
  await send(liveSubject);
  const live = await until(() => first.events.find((e) => e.data.subject === liveSubject), `the live event for '${liveSubject}'${hint}`, 60_000);
  assert.equal(live.type, "to.agentmail.message.received");
  assert.equal(live.source, `agentmail/${inbox}`);
  assert.equal(live.id, `agentmail:${inbox}:${live.data.message_id}`);
  assert.equal(live.data.replayed, false);
  assert.ok(!first.stderr().includes(key), "API key leaked to stderr");
  await first.stop();

  // 2. A message sent while the plugin is down must be delivered by the catch-up on the next start.
  const missedSubject = `hyphae-live-${run}-b`;
  await send(missedSubject);
  await new Promise((r) => setTimeout(r, 5_000)); // let AgentMail finish delivering before reconnecting
  const second = startPlugin("agentmail", pluginEnv);
  const missed = await until(() => second.events.find((e) => e.data.subject === missedSubject), `the caught-up event for '${missedSubject}'`, 60_000);
  assert.equal(missed.data.replayed, true, "a message received while offline must come from the REST catch-up");
  assert.ok(!second.events.some((e) => e.data.subject === liveSubject), "mail already delivered before the restart must not be replayed");
  await second.stop();
});

// ---------------------------------------------------------------------------------------
// Polling plugins: authenticated first poll
// ---------------------------------------------------------------------------------------

test("sentry live: token and org are accepted and the first poll is clean", { skip: !env("SENTRY_AUTH_TOKEN") && "SENTRY_AUTH_TOKEN not set", timeout: 60_000 }, async () => {
  assert.ok(env("SENTRY_ORG"), "set SENTRY_ORG to your organization slug");
  await smoke("sentry", pick("SENTRY_AUTH_TOKEN", "SENTRY_ORG", "SENTRY_PROJECTS", "SENTRY_API_BASE"), { secrets: [env("SENTRY_AUTH_TOKEN")] });
});

test("vercel live: token is accepted and the first poll is clean", { skip: !env("VERCEL_TOKEN") && "VERCEL_TOKEN not set", timeout: 60_000 }, async () => {
  await smoke("vercel", pick("VERCEL_TOKEN", "VERCEL_TEAM_ID", "VERCEL_TEAM_SLUG", "VERCEL_PROJECTS"), { secrets: [env("VERCEL_TOKEN")] });
});

test("notion live: integration token is accepted and the first poll is clean", { skip: !env("NOTION_TOKEN") && "NOTION_TOKEN not set", timeout: 60_000 }, async () => {
  await smoke("notion", pick("NOTION_TOKEN", "NOTION_VERSION"), { secrets: [env("NOTION_TOKEN")] });
});

const googleSkip = !(env("GOOGLE_CLIENT_ID") && env("GOOGLE_REFRESH_TOKEN")) && "GOOGLE_CLIENT_ID / GOOGLE_REFRESH_TOKEN not set";
const googleEnv = () => pick("GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "GOOGLE_REFRESH_TOKEN");
const googleSecrets = () => [env("GOOGLE_REFRESH_TOKEN"), env("GOOGLE_CLIENT_SECRET")].filter(Boolean);

test("gmail live: refresh token works, the mailbox baseline is read and the first poll is clean", { skip: googleSkip, timeout: 60_000 }, async () => {
  await smoke("gmail", googleEnv(), { secrets: googleSecrets() });
});

test("gmail live e2e: a real mail sent to the account arrives as one event", { skip: (googleSkip || (!env("AGENTMAIL_API_KEY") && "AGENTMAIL_API_KEY not set (used to send the test mail)") || (!env("GMAIL_LIVE_ADDRESS") && "GMAIL_LIVE_ADDRESS not set")), timeout: 240_000 }, async () => {
  const key = env("AGENTMAIL_API_KEY");
  const apiBase = (env("AGENTMAIL_API_BASE") || "https://api.agentmail.to").replace(/\/+$/, "");
  const to = env("GMAIL_LIVE_ADDRESS");
  const listed = await (await fetch(`${apiBase}/v0/inboxes?limit=10`, { headers: { authorization: `Bearer ${key}` } })).json();
  const from = env("AGENTMAIL_LIVE_INBOX") || listed.inboxes?.find((i) => i.status !== "deactivated")?.inbox_id;
  assert.ok(from, "no AgentMail inbox available to send the test mail from");

  const plugin = startPlugin("gmail", { ...googleEnv(), GMAIL_POLL_SECONDS: "20", GMAIL_STATE_FILE: join(stateDir, "gmail-e2e.json") });
  await until(() => plugin.stderr().includes(" polling ") || plugin.exited(), "gmail to start polling", 30_000);
  assert.equal(plugin.exited(), null, `gmail exited at startup:\n${plugin.stderr()}`);

  const subject = `hyphae-gmail-live-${randomBytes(4).toString("hex")}`;
  const sent = await fetch(`${apiBase}/v0/inboxes/${encodeURIComponent(from)}/messages/send`, {
    method: "POST",
    headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
    body: JSON.stringify({ to: [to], subject, text: "Hyphae Gmail plugin live test. Safe to delete." }),
  });
  assert.ok(sent.ok, `AgentMail send returned HTTP ${sent.status}`);

  const event = await until(() => plugin.events.find((e) => e.data.subject === subject), `the Gmail event for '${subject}' (check the mail was not filed outside INBOX, e.g. as spam)`, 180_000);
  assert.equal(event.type, "com.google.gmail.message.received");
  assert.equal(event.source, `gmail/${to}`);
  assert.match(event.data.from, new RegExp(from.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")));
  assert.ok(event.data.preview.length <= 200, "preview must be clipped");
  assert.equal(plugin.events.filter((e) => e.data.subject === subject).length, 1, "the mail must be delivered exactly once");
  for (const secret of googleSecrets()) assert.ok(!plugin.stderr().includes(secret), "gmail leaked a credential to stderr");
  await plugin.stop();
});

test("google-calendar live: refresh token works and the first poll is clean", { skip: googleSkip, timeout: 60_000 }, async () => {
  await smoke("google-calendar", googleEnv(), { secrets: googleSecrets() });
});
