import { spawn } from "node:child_process";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { object } from "./protocol.ts";

export const SECRET_NAME_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;

export function defaultConfigDir(): string {
  return join(process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config"), "hyphae");
}

export function secretsDir(configDir = defaultConfigDir()): string {
  return join(resolve(configDir), "secrets");
}

export function assertValidSecretName(name: string): void {
  if (!SECRET_NAME_PATTERN.test(name)) {
    throw new Error(`Invalid secret name "${name}" (use lowercase letters, digits, '.', '_', '-')`);
  }
}

export function secretFilePath(name: string, configDir = defaultConfigDir()): string {
  assertValidSecretName(name);
  return join(secretsDir(configDir), `${name}.secret`);
}

/**
 * Writes a secret into `~/.config/hyphae/secrets/<name>.secret` with strict `0600` permissions
 * inside a `0700` directory. Secret values are never stored in `connector.json`.
 */
export function writeSecret(name: string, value: string, configDir = defaultConfigDir()): string {
  assertValidSecretName(name);
  const trimmed = value.trim();
  if (trimmed.length === 0) throw new Error(`Secret "${name}" cannot be empty`);
  const dir = secretsDir(configDir);
  mkdirSync(dir, { mode: 0o700, recursive: true });
  chmodSync(dir, 0o700);
  const path = secretFilePath(name, configDir);
  writeFileSync(path, trimmed + "\n", { mode: 0o600 });
  chmodSync(path, 0o600);
  return path;
}

/**
 * Reads a secret after verifying private ownership and `0600` permissions.
 */
export function readSecret(name: string, configDir = defaultConfigDir()): string {
  const dir = secretsDir(configDir);
  if (!existsSync(dir)) {
    throw new Error(`Missing secret "${name}" (${secretFilePath(name, configDir)}). Set it with: hyp secret set ${name}`);
  }
  const dirSt = lstatSync(dir);
  if (!dirSt.isDirectory() || dirSt.isSymbolicLink() || (dirSt.mode & 0o077) !== 0 ||
      (process.getuid !== undefined && dirSt.uid !== process.getuid())) {
    throw new Error(`Secrets directory ${dir} must be a private 0700 directory owned by the current user`);
  }
  const path = secretFilePath(name, configDir);
  if (!resolve(path).startsWith(resolve(dir) + "/")) {
    throw new Error(`Secret path escapes secrets directory`);
  }
  if (!existsSync(path)) {
    throw new Error(`Missing secret "${name}" (${path}). Set it with: hyp secret set ${name}`);
  }
  const st = lstatSync(path);
  if (!st.isFile() || st.isSymbolicLink()) {
    throw new Error(`Secret "${name}" at ${path} must be a regular file`);
  }
  if (process.getuid !== undefined && st.uid !== process.getuid()) {
    throw new Error(`Secret "${name}" at ${path} is not owned by the current user`);
  }
  if ((st.mode & 0o077) !== 0) {
    throw new Error(`Secret "${name}" at ${path} has overly broad permissions (run: chmod 600 ${path})`);
  }
  const value = readFileSync(path, "utf8").trim();
  if (value.length === 0) {
    throw new Error(`Secret "${name}" at ${path} is empty`);
  }
  return value;
}

export function deleteSecret(name: string, configDir = defaultConfigDir()): boolean {
  const path = secretFilePath(name, configDir);
  if (!existsSync(path)) return false;
  rmSync(path, { force: true });
  return true;
}

export interface SecretMetadata {
  readonly name: string;
  readonly path: string;
  readonly modeOk: boolean;
  readonly bytes: number;
}

/** Lists secret metadata without ever reading or returning secret contents. */
export function listSecrets(configDir = defaultConfigDir()): SecretMetadata[] {
  const dir = secretsDir(configDir);
  if (!existsSync(dir)) return [];
  const results: SecretMetadata[] = [];
  for (const entry of readdirSync(dir)) {
    if (!entry.endsWith(".secret")) continue;
    const name = entry.slice(0, -".secret".length);
    if (!SECRET_NAME_PATTERN.test(name)) continue;
    const path = join(dir, entry);
    try {
      const st = lstatSync(path);
      if (!st.isFile()) continue;
      results.push({
        name,
        path,
        modeOk: (st.mode & 0o077) === 0 && (process.getuid === undefined || st.uid === process.getuid()),
        bytes: st.size,
      });
    } catch {}
  }
  return results.sort((a, b) => a.name.localeCompare(b.name));
}

export type SecretEnvValue = string | { readonly secret: string } | { readonly secretFile: string };

export interface ResolvedEnv {
  readonly env: Record<string, string>;
  readonly secretRefs: string[];
}

const ENV_KEY = /^[A-Za-z_][A-Za-z0-9_]*$/;

/**
 * Resolves plugin/stream `env` entries supporting:
 * - plain string values
 * - `{ "secret": "<name>" }` -> reads value from private `0600` secret file (injected only into that child process)
 * - `{ "secretFile": "<name>" }` -> verifies secret exists & is `0600`, passes its file path to the child
 */
export function resolveEnvWithSecrets(
  rawEnv: unknown,
  configDir: string,
  label: string,
): ResolvedEnv {
  if (rawEnv === undefined) return { env: {}, secretRefs: [] };
  if (!object(rawEnv)) throw new Error(`${label} env must be an object`);
  const env: Record<string, string> = {};
  const secretRefs: string[] = [];
  for (const [key, value] of Object.entries(rawEnv)) {
    if (!ENV_KEY.test(key)) throw new Error(`${label} env key '${key}' is invalid`);
    if (typeof value === "string") {
      env[key] = value;
    } else if (object(value) && typeof value.secret === "string") {
      secretRefs.push(value.secret);
      env[key] = readSecret(value.secret, configDir);
    } else if (object(value) && typeof value.secretFile === "string") {
      secretRefs.push(value.secretFile);
      // Validate permissions & existence up front, then pass path
      readSecret(value.secretFile, configDir);
      env[key] = secretFilePath(value.secretFile, configDir);
    } else {
      throw new Error(`${label} env.${key} must be a string, { secret: "<name>" }, or { secretFile: "<name>" }`);
    }
  }
  return { env, secretRefs: [...new Set(secretRefs)] };
}

/** Collects referenced secret names from raw JSON config without reading secret values (for `secret check`). */
export function collectSecretRefs(rawConfig: Record<string, unknown>): Array<{ owner: string; envKey: string; secret: string }> {
  const refs: Array<{ owner: string; envKey: string; secret: string }> = [];
  const scanEnv = (owner: string, rawEnv: unknown) => {
    if (!object(rawEnv)) return;
    for (const [envKey, value] of Object.entries(rawEnv)) {
      if (object(value) && typeof value.secret === "string") refs.push({ owner, envKey, secret: value.secret });
      else if (object(value) && typeof value.secretFile === "string") refs.push({ owner, envKey, secret: value.secretFile });
    }
  };
  if (Array.isArray(rawConfig.plugins)) {
    for (const pl of rawConfig.plugins) {
      if (object(pl) && typeof pl.name === "string") scanEnv(`plugin:${pl.name}`, pl.env);
    }
  }
  if (object(rawConfig.localRouter) && Array.isArray(rawConfig.localRouter.streams)) {
    for (const st of rawConfig.localRouter.streams) {
      if (object(st) && typeof st.name === "string") scanEnv(`stream:${st.name}`, st.env);
    }
  }
  return refs;
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function openUrlInBrowser(url: string): boolean {
  try {
    const cmd = process.platform === "darwin" ? "open" : process.platform === "win32" ? "cmd" : "xdg-open";
    const args = process.platform === "win32" ? ["/c", "start", "", url] : [url];
    const child = spawn(cmd, args, { detached: true, stdio: "ignore" });
    child.unref();
    return true;
  } catch {
    return false;
  }
}

export interface WebSecretCaptureOptions {
  readonly configDir?: string;
  readonly openBrowser?: boolean;
  readonly timeoutMs?: number;
  readonly port?: number;
  readonly onReady?: (url: string) => void;
}

/**
 * Out-of-band localhost secret capture (MCP URL-mode pattern):
 * Spins up an ephemeral `127.0.0.1` one-shot password form with a random URL token,
 * writes the submitted secret directly to `0600 ~/.config/hyphae/secrets/<name>.secret`,
 * shuts down immediately, and NEVER returns or prints the secret value to the caller/LLM.
 */
export function captureSecretViaWeb(
  name: string,
  options: WebSecretCaptureOptions = {},
): Promise<{ path: string; url: string }> {
  assertValidSecretName(name);
  const configDir = options.configDir ?? defaultConfigDir();
  const timeoutMs = options.timeoutMs ?? 5 * 60_000;
  const token = randomBytes(24).toString("base64url");
  const expectedPath = `/s/${token}`;
  const expectedBuf = Buffer.from(token);

  const safeName = escapeHtml(name);
  const formHtml = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hyphae · Save secret ${safeName}</title>
<style>
  body{margin:0;min-height:100vh;display:grid;place-items:center;background:#ece8df;color:#161714;font-family:-apple-system,BlinkMacSystemFont,Inter,sans-serif}
  .card{width:min(440px,92vw);background:#f6f4ee;border:1px solid rgba(22,23,20,.18);border-radius:18px;padding:28px;box-shadow:0 24px 50px -18px rgba(18,19,16,.28)}
  .tag{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;color:#41591d;background:rgba(65,89,29,.12);padding:3px 9px;border-radius:999px;display:inline-block;margin-bottom:14px}
  h1{margin:0 0 8px;font-size:22px;letter-spacing:-.02em}
  p{margin:0 0 18px;font-size:14px;color:#4c4a42;line-height:1.5}
  input{width:100%;box-sizing:border-box;padding:12px 13px;border-radius:10px;border:1px solid rgba(22,23,20,.24);background:#fff;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:14px;margin-bottom:14px}
  input:focus{outline:none;border-color:#41591d}
  button{width:100%;padding:11px 16px;border:none;border-radius:999px;background:#41591d;color:#f6f4ee;font-size:14px;font-weight:600;cursor:pointer}
  button:hover{background:#324614}
  .meta{margin-top:14px;font-size:12px;color:#787469}
</style></head><body>
<form class="card" method="POST" action="${expectedPath}">
  <span class="tag">hyphae · 0600 out-of-band</span>
  <h1>Save secret: <code>${safeName}</code></h1>
  <p>Saved directly to <code>0600</code> local storage. This value never passes through any AI model, chat log, or terminal history.</p>
  <input type="hidden" name="token" value="${token}" />
  <input type="password" name="value" placeholder="Paste secret value..." autocomplete="off" autofocus required />
  <button type="submit">Save secret &amp; close</button>
  <div class="meta">One-shot loopback server (127.0.0.1). Shuts down immediately after save.</div>
</form></body></html>`;

  const doneHtml = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Saved · Hyphae</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#ece8df;color:#161714;font-family:-apple-system,BlinkMacSystemFont,Inter,sans-serif}.card{background:#f6f4ee;border:1px solid rgba(22,23,20,.18);border-radius:18px;padding:28px;max-width:400px;text-align:center}h1{margin:0 0 8px;color:#41591d;font-size:21px}p{margin:0;color:#4c4a42;font-size:14px}</style>
</head><body><div class="card"><h1>Saved <code>${safeName}</code> (0600)</h1><p>The local server has shut down. You can close this tab and return to your agent.</p></div></body></html>`;

  return new Promise((resolvePromise, rejectPromise) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const finish = (err?: Error, result?: { path: string; url: string }) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      server.close(() => {
        if (err) rejectPromise(err);
        else resolvePromise(result!);
      });
    };

    const server = createServer((req, res) => {
      const reqUrl = (req.url ?? "/").split("?")[0];
      if (reqUrl !== expectedPath) {
        res.writeHead(404, { "content-type": "text/plain" }).end("Not found");
        return;
      }
      if (req.method === "GET") {
        res.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "cache-control": "no-store",
        }).end(formHtml);
        return;
      }
      if (req.method === "POST") {
        const chunks: Buffer[] = [];
        let total = 0;
        req.on("data", (chunk: Buffer) => {
          total += chunk.length;
          if (total > 64 * 1024) {
            res.writeHead(413, { "content-type": "text/plain" }).end("Payload too large");
            req.destroy();
            return;
          }
          chunks.push(chunk);
        });
        req.on("end", () => {
          const body = Buffer.concat(chunks).toString("utf8");
          const params = new URLSearchParams(body);
          const submittedToken = params.get("token") ?? "";
          const submittedBuf = Buffer.from(submittedToken);
          if (submittedBuf.length !== expectedBuf.length || !timingSafeEqual(submittedBuf, expectedBuf)) {
            res.writeHead(403, { "content-type": "text/plain" }).end("Invalid token");
            return;
          }
          const value = (params.get("value") ?? "").trim();
          if (value.length === 0) {
            res.writeHead(400, { "content-type": "text/plain" }).end("Secret value cannot be empty");
            return;
          }
          try {
            const savedPath = writeSecret(name, value, configDir);
            res.writeHead(200, {
              "content-type": "text/html; charset=utf-8",
              "cache-control": "no-store",
            }).end(doneHtml);
            finish(undefined, { path: savedPath, url });
          } catch (error) {
            const msg = error instanceof Error ? error.message : "Failed to save secret";
            res.writeHead(500, { "content-type": "text/plain" }).end(msg);
            finish(error instanceof Error ? error : new Error(msg));
          }
        });
        return;
      }
      res.writeHead(405, { "content-type": "text/plain" }).end("Method not allowed");
    });

    let url = "";
    server.on("error", (err) => finish(err instanceof Error ? err : new Error(String(err))));
    server.listen(options.port ?? 0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        finish(new Error("Failed to bind loopback secret prompt"));
        return;
      }
      url = `http://127.0.0.1:${addr.port}${expectedPath}`;
      if (options.openBrowser !== false) openUrlInBrowser(url);
      options.onReady?.(url);
      timer = setTimeout(() => finish(new Error(`Timed out waiting for secret '${name}' in browser`)), timeoutMs);
      timer.unref?.();
    });
  });
}
