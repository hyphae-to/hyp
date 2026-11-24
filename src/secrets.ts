import { spawn, spawnSync } from "node:child_process";
import { randomBytes, timingSafeEqual } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { homedir, tmpdir } from "node:os";
import { join, resolve, sep } from "node:path";
import { object } from "./protocol.ts";

export const SECRET_NAME_PATTERN = /^[a-z0-9][a-z0-9._-]{0,63}$/;

export type SecretBackend = "keychain" | "secret-service" | "file";

export interface SavedSecretResult {
  readonly name: string;
  readonly backend: SecretBackend;
  readonly location: string;
  /** Backwards-compatible alias for `location` (file path for `file` backend, URI for OS keyrings). */
  readonly path: string;
}

interface SecretIndexEntry {
  readonly backend: SecretBackend;
  readonly updatedAt: number;
  readonly service?: string;
}

interface SecretIndexFile {
  readonly version: 1;
  readonly secrets: Record<string, SecretIndexEntry>;
}

const MACOS_SECURITY_BIN = "/usr/bin/security";

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

function secretIndexPath(configDir: string): string {
  return join(secretsDir(configDir), "index.json");
}

function keychainServiceName(): string {
  const override = process.env.HYPHAE_KEYCHAIN_SERVICE?.trim();
  return override && /^[A-Za-z0-9._-]{1,64}$/.test(override) ? override : "hyphae";
}

export function secretBackendLabel(backend: SecretBackend): string {
  if (backend === "keychain") return "macOS Keychain";
  if (backend === "secret-service") return "Linux Secret Service";
  return "local file store";
}

function isInsideTempDir(configDir: string): boolean {
  const abs = resolve(configDir);
  const candidates = [resolve(tmpdir()), "/tmp", "/private/tmp", "/var/folders"];
  return candidates.some((base) => abs === base || abs.startsWith(base + sep));
}

function hasCommand(bin: string): boolean {
  const check = spawnSync("which", [bin], { encoding: "utf8" });
  return check.status === 0 && check.stdout.trim().length > 0;
}

/**
 * Resolves the active secret storage backend:
 * 1. Explicit `HYPHAE_SECRET_BACKEND=keychain|secret-service|file` override
 * 2. Isolated temporary config directories default to `file` so tests never touch the OS keyring
 * 3. macOS -> native macOS Keychain (`/usr/bin/security`)
 * 4. Linux desktop session with `secret-tool` + D-Bus -> Freedesktop Secret Service (GNOME Keyring / KWallet)
 * 5. Fallback -> private user-only local file store
 */
export function detectSecretBackend(configDir = defaultConfigDir()): SecretBackend {
  const explicit = process.env.HYPHAE_SECRET_BACKEND?.trim().toLowerCase();
  if (explicit === "keychain" || explicit === "secret-service" || explicit === "file") {
    return explicit;
  }
  if (isInsideTempDir(configDir)) return "file";
  if (process.platform === "darwin" && existsSync(MACOS_SECURITY_BIN)) {
    return "keychain";
  }
  if (process.platform === "linux" && process.env.DBUS_SESSION_BUS_ADDRESS && hasCommand("secret-tool")) {
    return "secret-service";
  }
  return "file";
}

function readSecretIndex(configDir: string): SecretIndexFile {
  const path = secretIndexPath(configDir);
  if (!existsSync(path)) return { version: 1, secrets: {} };
  try {
    const raw = JSON.parse(readFileSync(path, "utf8")) as unknown;
    if (!object(raw) || !object(raw.secrets)) return { version: 1, secrets: {} };
    const secrets: Record<string, SecretIndexEntry> = {};
    for (const [name, entry] of Object.entries(raw.secrets)) {
      if (!SECRET_NAME_PATTERN.test(name) || !object(entry)) continue;
      const backend = entry.backend;
      if (backend !== "keychain" && backend !== "secret-service" && backend !== "file") continue;
      secrets[name] = {
        backend,
        updatedAt: typeof entry.updatedAt === "number" ? entry.updatedAt : 0,
        ...(typeof entry.service === "string" && entry.service.length > 0 ? { service: entry.service } : {}),
      };
    }
    return { version: 1, secrets };
  } catch {
    return { version: 1, secrets: {} };
  }
}

function writeSecretIndex(configDir: string, index: SecretIndexFile): void {
  const dir = secretsDir(configDir);
  mkdirSync(dir, { mode: 0o700, recursive: true });
  chmodSync(dir, 0o700);
  const path = secretIndexPath(configDir);
  writeFileSync(path, JSON.stringify(index, null, 2) + "\n", { mode: 0o600 });
  chmodSync(path, 0o600);
}

// ---- macOS Keychain backend (`/usr/bin/security`, secret passed via stdin hex -X, never argv) ----

const KEYCHAIN_B64_PREFIX = "hyphae-b64v1:";

function encodeMacKeychainPayload(value: string): string {
  // `/usr/bin/security find-generic-password -w` auto-converts secrets containing non-printable
  // or non-ASCII bytes (e.g. tabs, newlines, UTF-8) into ambiguous hex output. Wrapping only those
  // values in an ASCII base64url envelope keeps normal API tokens human-readable in Keychain Access
  // while guaranteeing 100% lossless round-trip for arbitrary UTF-8, multiline PEM keys, and hex tokens.
  if (/[^\x20-\x7e]/.test(value) || value.startsWith(KEYCHAIN_B64_PREFIX)) {
    return `${KEYCHAIN_B64_PREFIX}${Buffer.from(value, "utf8").toString("base64url")}`;
  }
  return value;
}

function decodeMacKeychainPayload(raw: string): string {
  if (raw.startsWith(KEYCHAIN_B64_PREFIX)) {
    return Buffer.from(raw.slice(KEYCHAIN_B64_PREFIX.length), "base64url").toString("utf8");
  }
  return raw;
}

function writeMacKeychain(name: string, value: string, service: string): string {
  const payload = encodeMacKeychainPayload(value);
  const hex = Buffer.from(payload, "utf8").toString("hex");
  const cmd = `add-generic-password -U -s ${service} -a ${name} -X ${hex}\n`;
  const res = spawnSync(MACOS_SECURITY_BIN, ["-i"], { input: cmd, encoding: "utf8" });
  if (res.error) throw res.error;
  const stderr = (res.stderr ?? "").trim();
  if (res.status !== 0 || /security:|SecKeychain|error:/i.test(stderr)) {
    throw new Error(stderr || `macOS Keychain write failed (exit ${res.status})`);
  }
  return `keychain:${service}/${name}`;
}

function readMacKeychain(name: string, service: string): string | null {
  const res = spawnSync(MACOS_SECURITY_BIN, ["find-generic-password", "-s", service, "-a", name, "-w"], {
    encoding: "utf8",
  });
  if (res.error || res.status !== 0) return null;
  const raw = res.stdout.replace(/\r?\n$/, "");
  if (raw.length === 0) return null;
  const decoded = decodeMacKeychainPayload(raw).trim();
  return decoded.length > 0 ? decoded : null;
}

function deleteMacKeychain(name: string, service: string): boolean {
  const res = spawnSync(MACOS_SECURITY_BIN, ["delete-generic-password", "-s", service, "-a", name], {
    encoding: "utf8",
  });
  return !res.error && res.status === 0;
}

// ---- Linux Freedesktop Secret Service (`secret-tool`, secret passed via stdin, never argv) ----

function writeLinuxSecretService(name: string, value: string, service: string): string {
  const res = spawnSync(
    "secret-tool",
    ["store", `--label=Hyphae: ${name}`, "service", service, "account", name],
    { input: value, encoding: "utf8" },
  );
  if (res.error) throw res.error;
  if (res.status !== 0) {
    throw new Error((res.stderr ?? "").trim() || `secret-tool store failed (exit ${res.status})`);
  }
  return `secret-service:${service}/${name}`;
}

function readLinuxSecretService(name: string, service: string): string | null {
  const res = spawnSync("secret-tool", ["lookup", "service", service, "account", name], { encoding: "utf8" });
  if (res.error || res.status !== 0) return null;
  const value = res.stdout.replace(/\r?\n$/, "").trim();
  return value.length > 0 ? value : null;
}

function deleteLinuxSecretService(name: string, service: string): boolean {
  const existed = readLinuxSecretService(name, service) !== null;
  if (!existed) return false;
  const res = spawnSync("secret-tool", ["clear", "service", service, "account", name], { encoding: "utf8" });
  return !res.error && res.status === 0;
}

// ---- Private local file backend (fallback for headless servers / containers / isolated test dirs) ----

function writeFileSecret(name: string, value: string, configDir: string): string {
  const dir = secretsDir(configDir);
  mkdirSync(dir, { mode: 0o700, recursive: true });
  chmodSync(dir, 0o700);
  const path = secretFilePath(name, configDir);
  writeFileSync(path, value + "\n", { mode: 0o600 });
  chmodSync(path, 0o600);
  return path;
}

function readFileSecret(name: string, configDir: string): string {
  const dir = secretsDir(configDir);
  if (!existsSync(dir)) {
    throw new Error(`Missing secret "${name}". Set it with: hyp secret set ${name}`);
  }
  const dirSt = lstatSync(dir);
  if (
    !dirSt.isDirectory() ||
    dirSt.isSymbolicLink() ||
    (dirSt.mode & 0o077) !== 0 ||
    (process.getuid !== undefined && dirSt.uid !== process.getuid())
  ) {
    throw new Error(`Secrets directory ${dir} must be private and owned by the current user`);
  }
  const path = secretFilePath(name, configDir);
  if (!resolve(path).startsWith(resolve(dir) + sep)) {
    throw new Error(`Secret path escapes secrets directory`);
  }
  if (!existsSync(path)) {
    throw new Error(`Missing secret "${name}". Set it with: hyp secret set ${name}`);
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

/**
 * Stores a secret using the best available OS credential store (macOS Keychain or Linux Secret Service),
 * falling back to private local file storage when no system keyring is available.
 * Secret values are never stored in `connector.json` or passed via CLI argv.
 */
export function writeSecretDetailed(name: string, value: string, configDir = defaultConfigDir()): SavedSecretResult {
  assertValidSecretName(name);
  const trimmed = value.trim();
  if (trimmed.length === 0) throw new Error(`Secret "${name}" cannot be empty`);

  const explicit = process.env.HYPHAE_SECRET_BACKEND?.trim().toLowerCase();
  const preferred = detectSecretBackend(configDir);
  const service = keychainServiceName();

  let backend: SecretBackend = preferred;
  let location: string;

  if (preferred === "keychain") {
    try {
      location = writeMacKeychain(name, trimmed, service);
      // Remove any stale legacy plaintext copy on disk once saved in Keychain.
      rmSync(secretFilePath(name, configDir), { force: true });
    } catch (error) {
      if (explicit === "keychain") throw error;
      backend = "file";
      location = writeFileSecret(name, trimmed, configDir);
    }
  } else if (preferred === "secret-service") {
    try {
      location = writeLinuxSecretService(name, trimmed, service);
      rmSync(secretFilePath(name, configDir), { force: true });
    } catch (error) {
      if (explicit === "secret-service") throw error;
      backend = "file";
      location = writeFileSecret(name, trimmed, configDir);
    }
  } else {
    backend = "file";
    location = writeFileSecret(name, trimmed, configDir);
  }

  const index = readSecretIndex(configDir);
  index.secrets[name] = {
    backend,
    updatedAt: Date.now(),
    ...(backend !== "file" ? { service } : {}),
  };
  writeSecretIndex(configDir, index);

  return { name, backend, location, path: location };
}

/** Stores a secret and returns its storage location (keyring URI or file path). */
export function writeSecret(name: string, value: string, configDir = defaultConfigDir()): string {
  return writeSecretDetailed(name, value, configDir).location;
}

/** Reads a secret from its configured OS keyring or private local file. */
export function readSecret(name: string, configDir = defaultConfigDir()): string {
  assertValidSecretName(name);
  const index = readSecretIndex(configDir);
  const entry = index.secrets[name];
  const service = entry?.service ?? keychainServiceName();

  if (entry?.backend === "keychain") {
    const val = readMacKeychain(name, service);
    if (val !== null) return val;
    throw new Error(`Missing secret "${name}" in macOS Keychain (service "${service}"). Set it with: hyp secret set ${name} --web`);
  }
  if (entry?.backend === "secret-service") {
    const val = readLinuxSecretService(name, service);
    if (val !== null) return val;
    throw new Error(`Missing secret "${name}" in Linux Secret Service. Set it with: hyp secret set ${name} --web`);
  }
  if (entry?.backend === "file" || existsSync(secretFilePath(name, configDir))) {
    return readFileSecret(name, configDir);
  }

  // Fallback lookup in active OS keyring in case index.json wasn't present yet.
  const active = detectSecretBackend(configDir);
  if (active === "keychain") {
    const val = readMacKeychain(name, service);
    if (val !== null) return val;
  } else if (active === "secret-service") {
    const val = readLinuxSecretService(name, service);
    if (val !== null) return val;
  }

  throw new Error(`Missing secret "${name}". Set it with: hyp secret set ${name} --web`);
}

export function deleteSecret(name: string, configDir = defaultConfigDir()): boolean {
  assertValidSecretName(name);
  const index = readSecretIndex(configDir);
  const entry = index.secrets[name];
  const service = entry?.service ?? keychainServiceName();
  let removed = false;

  if (entry?.backend === "keychain") {
    removed = deleteMacKeychain(name, service) || removed;
  } else if (entry?.backend === "secret-service") {
    removed = deleteLinuxSecretService(name, service) || removed;
  }

  const filePath = secretFilePath(name, configDir);
  if (existsSync(filePath)) {
    rmSync(filePath, { force: true });
    removed = true;
  }

  const runtimePath = join(secretsDir(configDir), ".runtime", `${name}.secret`);
  if (existsSync(runtimePath)) {
    rmSync(runtimePath, { force: true });
  }

  if (entry) {
    delete index.secrets[name];
    writeSecretIndex(configDir, index);
    removed = true;
  } else if (!removed) {
    const active = detectSecretBackend(configDir);
    if (active === "keychain") removed = deleteMacKeychain(name, service);
    else if (active === "secret-service") removed = deleteLinuxSecretService(name, service);
  }

  return removed;
}

export interface SecretMetadata {
  readonly name: string;
  readonly backend: SecretBackend;
  readonly location: string;
  readonly path: string;
  readonly modeOk: boolean;
  readonly bytes: number | null;
}

/** Lists secret metadata without ever reading or returning secret contents. */
export function listSecrets(configDir = defaultConfigDir()): SecretMetadata[] {
  const dir = secretsDir(configDir);
  const byName = new Map<string, SecretMetadata>();

  const index = readSecretIndex(configDir);
  for (const [name, entry] of Object.entries(index.secrets)) {
    const service = entry.service ?? keychainServiceName();
    if (entry.backend === "keychain" || entry.backend === "secret-service") {
      const location = `${entry.backend}:${service}/${name}`;
      byName.set(name, {
        name,
        backend: entry.backend,
        location,
        path: location,
        modeOk: true,
        bytes: null,
      });
    } else {
      const path = secretFilePath(name, configDir);
      if (existsSync(path)) {
        try {
          const st = lstatSync(path);
          if (st.isFile()) {
            byName.set(name, {
              name,
              backend: "file",
              location: path,
              path,
              modeOk: (st.mode & 0o077) === 0 && (process.getuid === undefined || st.uid === process.getuid()),
              bytes: st.size,
            });
          }
        } catch {}
      }
    }
  }

  if (existsSync(dir)) {
    for (const entry of readdirSync(dir)) {
      if (!entry.endsWith(".secret")) continue;
      const name = entry.slice(0, -".secret".length);
      if (!SECRET_NAME_PATTERN.test(name) || byName.has(name)) continue;
      const path = join(dir, entry);
      try {
        const st = lstatSync(path);
        if (!st.isFile()) continue;
        byName.set(name, {
          name,
          backend: "file",
          location: path,
          path,
          modeOk: (st.mode & 0o077) === 0 && (process.getuid === undefined || st.uid === process.getuid()),
          bytes: st.size,
        });
      } catch {}
    }
  }

  return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
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
 * - `{ "secret": "<name>" }` -> reads value from OS Keychain / Secret Service / local store (injected only into that child process)
 * - `{ "secretFile": "<name>" }` -> resolves to a private file path (materialized from keyring if stored in OS Keychain / Secret Service)
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
      const secretVal = readSecret(value.secretFile, configDir);
      const filePath = secretFilePath(value.secretFile, configDir);
      if (existsSync(filePath)) {
        env[key] = filePath;
      } else {
        const runtimeDir = join(secretsDir(configDir), ".runtime");
        mkdirSync(runtimeDir, { mode: 0o700, recursive: true });
        chmodSync(runtimeDir, 0o700);
        const materialized = join(runtimeDir, `${value.secretFile}.secret`);
        writeFileSync(materialized, secretVal + "\n", { mode: 0o600 });
        chmodSync(materialized, 0o600);
        env[key] = materialized;
      }
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

export interface WebSecretCaptureResult {
  readonly backend: SecretBackend;
  readonly location: string;
  readonly path: string;
  readonly url: string;
}

/**
 * Out-of-band localhost secret capture:
 * Spins up an ephemeral `127.0.0.1` one-shot password form with a random URL token,
 * saves the submitted secret to the active OS keyring (macOS Keychain / Linux Secret Service,
 * or local private store fallback), closes all connections immediately so the CLI never hangs
 * on browser keep-alive sockets, and NEVER returns or prints the secret value to the caller/LLM.
 */
export function captureSecretViaWeb(
  name: string,
  options: WebSecretCaptureOptions = {},
): Promise<WebSecretCaptureResult> {
  assertValidSecretName(name);
  const configDir = options.configDir ?? defaultConfigDir();
  const timeoutMs = options.timeoutMs ?? 5 * 60_000;
  const token = randomBytes(24).toString("base64url");
  const expectedPath = `/s/${token}`;
  const expectedBuf = Buffer.from(token);
  const targetBackend = detectSecretBackend(configDir);
  const backendLabel = escapeHtml(secretBackendLabel(targetBackend));

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
  <span class="tag">hyphae · ${backendLabel}</span>
  <h1>Save secret: <code>${safeName}</code></h1>
  <p>Saved directly to your ${backendLabel}. This value never passes through any AI model, chat log, or terminal history.</p>
  <input type="hidden" name="token" value="${token}" />
  <input type="password" name="value" placeholder="Paste secret value..." autocomplete="off" autofocus required />
  <button type="submit">Save secret &amp; close</button>
  <div class="meta">One-shot loopback server (127.0.0.1). Shuts down immediately after save.</div>
</form></body></html>`;

  const renderDoneHtml = (savedBackend: SecretBackend) => `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Saved · Hyphae</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#ece8df;color:#161714;font-family:-apple-system,BlinkMacSystemFont,Inter,sans-serif}.card{background:#f6f4ee;border:1px solid rgba(22,23,20,.18);border-radius:18px;padding:28px;max-width:400px;text-align:center}h1{margin:0 0 8px;color:#41591d;font-size:21px}p{margin:0;color:#4c4a42;font-size:14px}</style>
</head><body><div class="card"><h1>Saved <code>${safeName}</code></h1><p>Stored in ${escapeHtml(secretBackendLabel(savedBackend))}. The local server has shut down—you can close this tab and return to your terminal.</p></div></body></html>`;

  return new Promise((resolvePromise, rejectPromise) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const finish = (err?: Error, result?: WebSecretCaptureResult, immediateClose = false) => {
      if (settled) return;
      settled = true;
      if (timer) clearTimeout(timer);
      const settle = () => {
        if (err) rejectPromise(err);
        else resolvePromise(result!);
      };
      // Force-close idle keep-alive sockets right away and any remaining browser sockets shortly
      // after flushing the response so the CLI never hangs waiting on HTTP/1.1 keep-alive.
      const forceTimer = setTimeout(() => {
        server.closeAllConnections?.();
      }, immediateClose ? 0 : 120);
      forceTimer.unref?.();
      server.close(() => {
        clearTimeout(forceTimer);
        settle();
      });
      server.closeIdleConnections?.();
      if (immediateClose) server.closeAllConnections?.();
    };

    const server = createServer((req, res) => {
      const reqUrl = (req.url ?? "/").split("?")[0];
      if (reqUrl === "/favicon.ico") {
        res.writeHead(204, { connection: "close" }).end();
        return;
      }
      if (reqUrl !== expectedPath) {
        res.writeHead(404, { "content-type": "text/plain", connection: "close" }).end("Not found");
        return;
      }
      if (req.method === "GET") {
        res.writeHead(200, {
          "content-type": "text/html; charset=utf-8",
          "cache-control": "no-store",
          connection: "close",
        }).end(formHtml);
        return;
      }
      if (req.method === "POST") {
        const chunks: Buffer[] = [];
        let total = 0;
        let aborted = false;
        req.on("data", (chunk: Buffer) => {
          if (aborted) return;
          total += chunk.length;
          if (total > 64 * 1024) {
            aborted = true;
            res.writeHead(413, { "content-type": "text/plain", connection: "close" }).end("Payload too large");
            req.destroy();
            return;
          }
          chunks.push(chunk);
        });
        req.on("end", () => {
          if (aborted) return;
          const body = Buffer.concat(chunks).toString("utf8");
          const params = new URLSearchParams(body);
          const submittedToken = params.get("token") ?? "";
          const submittedBuf = Buffer.from(submittedToken);
          if (submittedBuf.length !== expectedBuf.length || !timingSafeEqual(submittedBuf, expectedBuf)) {
            res.writeHead(403, { "content-type": "text/plain", connection: "close" }).end("Invalid token");
            return;
          }
          const value = (params.get("value") ?? "").trim();
          if (value.length === 0) {
            res.writeHead(400, { "content-type": "text/plain", connection: "close" }).end("Secret value cannot be empty");
            return;
          }
          try {
            const saved = writeSecretDetailed(name, value, configDir);
            const result: WebSecretCaptureResult = {
              backend: saved.backend,
              location: saved.location,
              path: saved.path,
              url,
            };
            res.writeHead(200, {
              "content-type": "text/html; charset=utf-8",
              "cache-control": "no-store",
              connection: "close",
            });
            res.end(renderDoneHtml(saved.backend), () => finish(undefined, result));
          } catch (error) {
            const msg = error instanceof Error ? error.message : "Failed to save secret";
            res.writeHead(500, { "content-type": "text/plain", connection: "close" });
            res.end(msg, () => finish(error instanceof Error ? error : new Error(msg), undefined, true));
          }
        });
        return;
      }
      res.writeHead(405, { "content-type": "text/plain", connection: "close" }).end("Method not allowed");
    });
    server.keepAliveTimeout = 1000;

    let url = "";
    server.on("error", (err) => finish(err instanceof Error ? err : new Error(String(err)), undefined, true));
    server.listen(options.port ?? 0, "127.0.0.1", () => {
      const addr = server.address();
      if (!addr || typeof addr === "string") {
        finish(new Error("Failed to bind loopback secret prompt"), undefined, true);
        return;
      }
      url = `http://127.0.0.1:${addr.port}${expectedPath}`;
      if (options.openBrowser !== false) openUrlInBrowser(url);
      options.onReady?.(url);
      timer = setTimeout(() => finish(new Error(`Timed out waiting for secret '${name}' in browser`), undefined, true), timeoutMs);
      timer.unref?.();
    });
  });
}
