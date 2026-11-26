#!/usr/bin/env node
/**
 * Zero-dependency Google OAuth 2.0 helper for the Hyphae `gmail` and
 * `google-calendar` plugins (Node 24+).
 *
 * As a library it exchanges a stored refresh token for short-lived access
 * tokens. Run directly, it performs the one-time consent as an installed
 * ("Desktop app") client: PKCE + loopback redirect, entirely on this machine.
 * Tokens go from Google to this process to the node's secret store; no Hyphae
 * server is involved at any point.
 *
 *   node google-oauth.mjs auth --client-file ~/Downloads/client_secret_*.json --scopes gmail,calendar
 *
 * Options:
 *   --client-file <path>   OAuth client JSON downloaded from Google Cloud Console (Desktop app)
 *   --client-id <id>       Client ID, when not using --client-file (secret, if any, via GOOGLE_CLIENT_SECRET)
 *   --scopes <list>        Comma-separated: gmail, calendar, or full scope URLs (default: gmail,calendar)
 *   --port <n>             Fixed loopback port (default: random). Use a fixed port to consent for a
 *                          remote hub through `ssh -L <n>:127.0.0.1:<n> <hub>`.
 *   --secret-name <name>   Secret to store the refresh token under (default: google-refresh-token)
 *   --hyp <path>           `hyp` binary used to store secrets (default: hyp)
 *   --state-dir <dir>      Passed through to `hyp secret set --state-dir`
 *   --notify-label <label> Label of the local event emitted when consent completes, so a waiting
 *                          agent thread is woken instead of polling (default: plugin-setup; "none" disables).
 *                          Subscribe with hyp_stream({ topic: "local.schedule", filters: [{ exact: { label } }] }).
 *   --stdout               Write the refresh token to stdout instead of the secret store.
 *                          Refused on a terminal: pipe it, e.g. `| ssh hub hyp secret set google-refresh-token`.
 */
import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer } from "node:http";
import { pathToFileURL } from "node:url";

export const GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth";
export const GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token";

export const SCOPE_ALIASES = {
  gmail: "https://www.googleapis.com/auth/gmail.readonly",
  calendar: "https://www.googleapis.com/auth/calendar.events.readonly",
};

function resolveTokenUrl(raw) {
  const value = (raw?.trim() || GOOGLE_TOKEN_URL).replace(/\/+$/, "");
  const parsed = new URL(value);
  const loopback = ["127.0.0.1", "localhost", "[::1]"].includes(parsed.hostname);
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback)) {
    throw new Error("GOOGLE_TOKEN_URL must use https:// or loopback http://");
  }
  return value;
}

async function postForm(url, fields) {
  const res = await fetch(url, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
    body: new URLSearchParams(fields).toString(),
    signal: AbortSignal.timeout(20_000),
  });
  let body = {};
  try {
    body = await res.json();
  } catch {}
  if (!res.ok) {
    const code = typeof body.error === "string" ? body.error : `http_${res.status}`;
    const error = new Error(`Google token endpoint returned ${code}`);
    error.code = code;
    throw error;
  }
  return body;
}

/**
 * Returns `async () => accessToken`, refreshing 60 s before expiry. Reads
 * `GOOGLE_CLIENT_ID`, optional `GOOGLE_CLIENT_SECRET`, and
 * `GOOGLE_REFRESH_TOKEN` / `GOOGLE_REFRESH_TOKEN_FILE` from the plugin env.
 */
export function googleAccessTokenProvider({ clientId, clientSecret, refreshToken, tokenUrl } = {}) {
  const id = clientId ?? process.env.GOOGLE_CLIENT_ID?.trim();
  const secret = clientSecret ?? process.env.GOOGLE_CLIENT_SECRET?.trim();
  const file = process.env.GOOGLE_REFRESH_TOKEN_FILE?.trim();
  const refresh = refreshToken ?? (file ? readFileSync(file, "utf8").trim() : process.env.GOOGLE_REFRESH_TOKEN?.trim());
  if (!id) throw new Error("Set GOOGLE_CLIENT_ID to your Google OAuth client ID");
  if (!refresh) {
    throw new Error('Set GOOGLE_REFRESH_TOKEN (via { "secret": "<name>" }); create it with `node google-oauth.mjs auth`');
  }
  const url = resolveTokenUrl(tokenUrl ?? process.env.GOOGLE_TOKEN_URL);
  let cached = "";
  let expiresAt = 0;
  return async function accessToken() {
    if (cached && Date.now() < expiresAt - 60_000) return cached;
    let body;
    try {
      body = await postForm(url, {
        grant_type: "refresh_token",
        client_id: id,
        refresh_token: refresh,
        ...(secret ? { client_secret: secret } : {}),
      });
    } catch (error) {
      if (error.code === "invalid_grant") {
        throw new Error("Google refresh token was revoked or expired (invalid_grant); run `node google-oauth.mjs auth` again");
      }
      throw error;
    }
    if (typeof body.access_token !== "string" || !body.access_token) throw new Error("Google token response had no access_token");
    cached = body.access_token;
    expiresAt = Date.now() + Math.max(Number(body.expires_in) || 3600, 120) * 1000;
    return cached;
  };
}

function parseArgs(argv) {
  const out = { _: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--stdout") out.stdout = true;
    else if (arg.startsWith("--")) {
      const value = argv[i + 1];
      if (value === undefined || value.startsWith("--")) throw new Error(`${arg} needs a value`);
      out[arg.slice(2)] = value;
      i += 1;
    } else out._.push(arg);
  }
  return out;
}

function loadClient(args) {
  if (args["client-file"]) {
    const parsed = JSON.parse(readFileSync(args["client-file"], "utf8"));
    const block = parsed.installed ?? parsed.web ?? parsed;
    if (typeof block.client_id !== "string" || !block.client_id) throw new Error("client file has no client_id");
    return { clientId: block.client_id, clientSecret: typeof block.client_secret === "string" ? block.client_secret : "" };
  }
  if (args["client-id"]) return { clientId: args["client-id"], clientSecret: process.env.GOOGLE_CLIENT_SECRET?.trim() ?? "" };
  throw new Error("Pass --client-file <client_secret.json> or --client-id <id>");
}

function storeSecret(hyp, name, value, stateDir) {
  return new Promise((resolve, reject) => {
    const child = spawn(hyp, ["secret", "set", name, ...(stateDir ? ["--state-dir", stateDir] : [])], {
      stdio: ["pipe", "ignore", "inherit"],
    });
    child.on("error", (error) => reject(new Error(`could not run '${hyp} secret set ${name}': ${error.message}`)));
    child.on("exit", (code) => (code === 0 ? resolve() : reject(new Error(`'${hyp} secret set ${name}' exited with ${code}`))));
    child.stdin.end(value);
  });
}

/**
 * Tells the local node that an out-of-band setup step finished, as a `local.schedule` event a
 * waiting agent thread can subscribe to. Best effort and metadata only: never a token or secret.
 */
function emitSetupEvent(hyp, label, note) {
  return new Promise((resolve) => {
    const child = spawn(hyp, ["emit", "--label", label, "--note", note], { stdio: "ignore" });
    child.on("error", () => resolve(false));
    child.on("exit", (code) => resolve(code === 0));
  });
}

/** Runs the consent flow and resolves `{ refreshToken, scopes }`. Exported for tests (`authUrl`/`tokenUrl` overrides). */
export async function runConsent({ clientId, clientSecret, scopes, port = 0, authUrl = GOOGLE_AUTH_URL, tokenUrl = GOOGLE_TOKEN_URL, onUrl }) {
  const verifier = randomBytes(48).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const state = randomBytes(24).toString("base64url");

  const code = await new Promise((resolve, reject) => {
    const server = createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      if (url.pathname !== "/oauth2/callback") {
        res.writeHead(404).end();
        return;
      }
      const done = (status, text, outcome) => {
        res.writeHead(status, { "content-type": "text/plain; charset=utf-8" }).end(text);
        server.close();
        outcome();
      };
      if (url.searchParams.get("state") !== state) {
        // Wrong or missing state: not our redirect. Keep waiting for the real one.
        res.writeHead(400, { "content-type": "text/plain; charset=utf-8" }).end("State mismatch.");
        return;
      }
      const error = url.searchParams.get("error");
      if (error) return done(400, "Google sign-in was not completed. You can close this tab.", () => reject(new Error(`Google returned ${error}`)));
      const value = url.searchParams.get("code");
      if (!value) return done(400, "Missing authorization code.", () => reject(new Error("redirect had no code")));
      done(200, "Hyphae is connected to Google. You can close this tab.", () => resolve({ value, redirectUri }));
    });
    let redirectUri = "";
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      redirectUri = `http://127.0.0.1:${server.address().port}/oauth2/callback`;
      const consent = new URL(authUrl);
      consent.search = new URLSearchParams({
        client_id: clientId,
        redirect_uri: redirectUri,
        response_type: "code",
        scope: scopes.join(" "),
        code_challenge: challenge,
        code_challenge_method: "S256",
        access_type: "offline",
        prompt: "consent",
        state,
      }).toString();
      onUrl(consent.toString());
    });
  });

  const body = await postForm(resolveTokenUrl(tokenUrl), {
    grant_type: "authorization_code",
    code: code.value,
    client_id: clientId,
    redirect_uri: code.redirectUri,
    code_verifier: verifier,
    ...(clientSecret ? { client_secret: clientSecret } : {}),
  });
  if (typeof body.refresh_token !== "string" || !body.refresh_token) {
    throw new Error("Google returned no refresh token; remove the app under myaccount.google.com/permissions and run auth again");
  }
  return { refreshToken: body.refresh_token, scopes: typeof body.scope === "string" ? body.scope.split(" ") : scopes };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args._[0] !== "auth") {
    console.error("Usage: node google-oauth.mjs auth --client-file <client_secret.json> [--scopes gmail,calendar] [--port N] [--secret-name NAME] [--hyp PATH] [--state-dir DIR] [--stdout]");
    process.exit(2);
  }
  if (args.stdout && process.stdout.isTTY) {
    console.error("Refusing to print a refresh token to a terminal. Pipe --stdout into `hyp secret set <name>` (for example over ssh).");
    process.exit(2);
  }
  const { clientId, clientSecret } = loadClient(args);
  const scopes = (args.scopes ?? "gmail,calendar").split(",").map((s) => s.trim()).filter(Boolean).map((s) => SCOPE_ALIASES[s] ?? s);
  for (const scope of scopes) {
    if (!scope.startsWith("https://www.googleapis.com/auth/")) throw new Error(`Unknown scope '${scope}' (use gmail, calendar, or a full scope URL)`);
  }
  const port = args.port === undefined ? 0 : Number(args.port);
  if (!Number.isInteger(port) || port < 0 || port > 65_535) throw new Error("--port must be 0-65535");

  const { refreshToken } = await runConsent({
    clientId,
    clientSecret,
    scopes,
    port,
    authUrl: process.env.GOOGLE_AUTH_URL?.trim() || GOOGLE_AUTH_URL,
    tokenUrl: process.env.GOOGLE_TOKEN_URL?.trim() || GOOGLE_TOKEN_URL,
    onUrl: (url) => console.error(`Open this URL in a browser on this machine (or through your ssh tunnel) and approve access:\n\n${url}\n`),
  });

  const secretName = args["secret-name"] ?? "google-refresh-token";
  if (args.stdout) {
    process.stdout.write(refreshToken);
  } else {
    const hyp = args.hyp ?? "hyp";
    await storeSecret(hyp, secretName, refreshToken, args["state-dir"]);
    if (clientSecret) await storeSecret(hyp, "google-client-secret", clientSecret, args["state-dir"]);
  }
  const notifyLabel = args["notify-label"] ?? "plugin-setup";
  if (notifyLabel !== "none") {
    const where = args.stdout ? "written to stdout" : `stored as secret '${secretName}'`;
    await emitSetupEvent(args.hyp ?? "hyp", notifyLabel, `google-oauth: consent complete for scopes ${(args.scopes ?? "gmail,calendar")}; refresh token ${where}`);
  }
  console.error(
    [
      "Google consent complete.",
      args.stdout ? "Refresh token written to stdout." : `Refresh token stored as secret '${secretName}'.`,
      !args.stdout && clientSecret ? "Client secret stored as secret 'google-client-secret'." : "",
      `Set GOOGLE_CLIENT_ID=${clientId} in the plugin env (the client ID is not a secret).`,
    ].filter(Boolean).join("\n"),
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(`google-oauth: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  });
}
