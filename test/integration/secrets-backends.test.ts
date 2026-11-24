import assert from "node:assert/strict";
import { execFile, spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { promisify } from "node:util";
import { loadConfig } from "../../src/config.ts";
import { startDaemon } from "../../src/daemon.ts";
import {
  deleteSecret,
  detectSecretBackend,
  listSecrets,
  readSecret,
  secretFilePath,
  secretsDir,
  writeSecretDetailed,
} from "../../src/secrets.ts";
import { runOnboard } from "../../src/setup.ts";
import { freePort, MeshTopology, waitFor } from "./harness/topology.ts";
import { startVirtualSecretService } from "./shims/secret-service.ts";
import { deliverGithubWebhook, deliverSignedWebhook, makeGithubPullRequestPayload } from "./shims/services.ts";

const execFileAsync = promisify(execFile);
const CLI_PATH = join(process.cwd(), "src", "cli.ts");

interface CliRunResult {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
  json<T = Record<string, unknown>>(): T;
}

function runHypCli(
  args: readonly string[],
  options: {
    readonly env: NodeJS.ProcessEnv;
    readonly stdin?: string;
    readonly timeoutMs?: number;
  },
): Promise<CliRunResult> {
  return new Promise((resolve, reject) => {
    const proc = spawn(process.execPath, [CLI_PATH, ...args], {
      env: options.env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    proc.stdout.on("data", (chunk: Buffer) => out.push(chunk));
    proc.stderr.on("data", (chunk: Buffer) => err.push(chunk));

    const timer = setTimeout(() => {
      proc.kill("SIGKILL");
      reject(new Error(`hyp ${args.join(" ")} timed out after ${options.timeoutMs ?? 10_000}ms`));
    }, options.timeoutMs ?? 10_000).unref();

    proc.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    proc.once("exit", (code) => {
      clearTimeout(timer);
      const stdout = Buffer.concat(out).toString("utf8");
      const stderr = Buffer.concat(err).toString("utf8");
      resolve({
        code,
        stdout,
        stderr,
        json<T = Record<string, unknown>>() {
          return JSON.parse(stdout) as T;
        },
      });
    });

    if (options.stdin !== undefined) {
      proc.stdin.write(options.stdin);
    }
    proc.stdin.end();
  });
}

function httpRequest(
  url: string,
  options: {
    readonly method: string;
    readonly headers?: Record<string, string>;
    readonly body?: string;
    readonly agent: http.Agent;
  },
): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(url, { method: options.method, headers: options.headers, agent: options.agent }, (res) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => {
        resolve({
          status: res.statusCode ?? 0,
          headers: res.headers,
          body: Buffer.concat(chunks).toString("utf8"),
        });
      });
    });
    req.on("error", reject);
    if (options.body !== undefined) req.write(options.body);
    req.end();
  });
}

async function withProcessEnv<T>(
  overrides: Readonly<Record<string, string | undefined>>,
  fn: () => Promise<T> | T,
): Promise<T> {
  const saved = new Map<string, string | undefined>();
  for (const [key, val] of Object.entries(overrides)) {
    saved.set(key, process.env[key]);
    if (val === undefined) delete process.env[key];
    else process.env[key] = val;
  }
  try {
    return await fn();
  } finally {
    for (const [key, prev] of saved.entries()) {
      if (prev === undefined) delete process.env[key];
      else process.env[key] = prev;
    }
  }
}

function listPlaintextSecretFiles(configDir: string): string[] {
  const dir = secretsDir(configDir);
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((entry) => entry.endsWith(".secret"));
}

function readIndexSecretNames(configDir: string): string[] {
  const indexPath = join(secretsDir(configDir), "index.json");
  if (!existsSync(indexPath)) return [];
  const raw = JSON.parse(readFileSync(indexPath, "utf8")) as { secrets?: Record<string, unknown> };
  return Object.keys(raw.secrets ?? {});
}

test(
  "Linux Secret Service (virtual secret-tool shim): full CLI, migration, daemon plugins ({secret} + {secretFile}), and cleanup",
  { timeout: 30_000 },
  async () => {
    const topo = new MeshTopology("hi-ss-");
    const vss = startVirtualSecretService(topo.subDir("shim"));
    topo.track(() => vss.close());

    const configDir = topo.subDir("cfg");
    const xdgDir = topo.subDir("xdg");
    const homeDir = topo.subDir("home");
    const service = `hyphae-vss-${randomUUID().slice(0, 10)}`;

    const cliEnv: NodeJS.ProcessEnv = {
      ...vss.envWithPath(process.env),
      HOME: homeDir,
      XDG_CONFIG_HOME: xdgDir,
      HYPHAE_SECRET_BACKEND: "secret-service",
      HYPHAE_KEYCHAIN_SERVICE: service,
    };

    const asciiSecret = "whsec_ascii_direct_hmac_9f8e7d6c5b4a";
    const specialSecret = `tok_$HOME_"dbl"_'sgl'_\\slash\t&!@#%^*()`;
    const utf8MultilineSecret = `line1-🚀-hyphae\nline2-🔐-key="val"\nline3-日本語-end`;
    const fileSecret = "whsec_materialized_file_hmac_42_beta";
    const allSecretValues = [asciiSecret, specialSecret, utf8MultilineSecret, fileSecret];

    try {
      // Seed a legacy plaintext `.secret` file to prove `hyp secret set` migrates it into Secret Service and deletes the plaintext file.
      mkdirSync(secretsDir(configDir), { recursive: true, mode: 0o700 });
      const legacyFile = secretFilePath("wh-file-hmac", configDir);
      writeFileSync(legacyFile, "old-legacy-plaintext-value\n", { mode: 0o600 });
      chmodSync(legacyFile, 0o600);
      assert.equal(existsSync(legacyFile), true);

      // Store all 4 secrets via the real `hyp secret set` CLI over stdin.
      const toStore: Array<[string, string]> = [
        ["wh-hmac", asciiSecret],
        ["special-chars", specialSecret],
        ["utf8-multiline", utf8MultilineSecret],
        ["wh-file-hmac", fileSecret],
      ];

      for (const [name, value] of toStore) {
        const res = await runHypCli(
          ["secret", "set", name, "--config-dir", configDir, "--json"],
          { env: cliEnv, stdin: `${value}\n` },
        );
        assert.equal(res.code, 0, `hyp secret set ${name} failed: ${res.stderr}\n${res.stdout}`);
        const envJson = res.json<{
          ok: boolean;
          command: string;
          data: { name: string; backend: string; location: string; path: string };
        }>();
        assert.equal(envJson.ok, true);
        assert.equal(envJson.command, "secret set");
        assert.equal(envJson.data.name, name);
        assert.equal(envJson.data.backend, "secret-service");
        assert.equal(envJson.data.location, `secret-service:${service}/${name}`);
        assert.equal(res.stdout.includes(value), false, `secret '${name}' must never leak into stdout`);
        assert.equal(res.stderr.includes(value), false, `secret '${name}' must never leak into stderr`);
      }

      // Legacy plaintext file was migrated & deleted; zero `.secret` files remain directly under secrets/.
      assert.equal(existsSync(legacyFile), false, "legacy plaintext .secret file must be deleted after migration");
      assert.deepEqual(listPlaintextSecretFiles(configDir), []);

      // Verify `hyp secret list --json` returns metadata only (no secret values) with `secret-service` backend.
      const listRes = await runHypCli(["secret", "list", "--config-dir", configDir, "--json"], { env: cliEnv });
      assert.equal(listRes.code, 0, listRes.stderr);
      const listJson = listRes.json<{
        ok: boolean;
        command: string;
        data: {
          defaultBackend: string;
          count: number;
          secrets: Array<{ name: string; backend: string; location: string; modeOk: boolean; bytes: number | null }>;
        };
      }>();
      assert.equal(listJson.ok, true);
      assert.equal(listJson.command, "secret list");
      assert.equal(listJson.data.defaultBackend, "secret-service");
      assert.equal(listJson.data.count, 4);
      for (const item of listJson.data.secrets) {
        assert.equal(item.backend, "secret-service");
        assert.equal(item.location, `secret-service:${service}/${item.name}`);
        assert.equal(item.modeOk, true);
        assert.equal(item.bytes, null);
      }
      for (const secretVal of allSecretValues) {
        assert.equal(listRes.stdout.includes(secretVal), false, "secret list must never leak secret values");
      }

      // Verify lossless in-process readSecret round-trip for ASCII, special chars, UTF-8/multiline, and migrated file secret.
      await withProcessEnv(
        {
          PATH: cliEnv.PATH,
          HYPHAE_SECRET_BACKEND: "secret-service",
          HYPHAE_KEYCHAIN_SERVICE: service,
        },
        () => {
          assert.equal(readSecret("wh-hmac", configDir), asciiSecret);
          assert.equal(readSecret("special-chars", configDir), specialSecret);
          assert.equal(readSecret("utf8-multiline", configDir), utf8MultilineSecret);
          assert.equal(readSecret("wh-file-hmac", configDir), fileSecret);
        },
      );

      // Verify from the secret-tool invocation log that NO secret value EVER appeared in argv (stdin only!).
      const invocationsAfterStore = vss.invocations;
      assert.ok(invocationsAfterStore.some((inv) => inv.subcommand === "store"));
      for (const inv of invocationsAfterStore) {
        for (const secretVal of allSecretValues) {
          assert.equal(
            inv.argvJoined.includes(secretVal),
            false,
            `secret value leaked into secret-tool argv: ${inv.argvJoined}`,
          );
        }
      }

      // Build connector.json with TWO webhook bridge plugins using BOTH `{ secret: "wh-hmac" }` AND `{ secretFile: "wh-file-hmac" }`.
      const router = await topo.addRouter({ name: "ss-hub" });
      const token = router.addConnector("ops@linux-box");
      const tokenFile = join(configDir, "primary.token");
      writeFileSync(tokenFile, `${token}\n`, { mode: 0o600 });
      chmodSync(tokenFile, 0o600);

      const directPort = await freePort();
      const filePort = await freePort();
      const configPath = join(configDir, "connector.json");
      writeFileSync(
        configPath,
        JSON.stringify(
          {
            connectorId: "ops@linux-box",
            stateDir: "state",
            routers: [{ name: "primary", url: router.url, tokenFile }],
            plugins: [
              {
                name: "wh-direct",
                builtin: "webhook",
                env: {
                  WEBHOOK_HOST: "127.0.0.1",
                  WEBHOOK_PORT: String(directPort),
                  WEBHOOK_PATH: "/hook-direct",
                  WEBHOOK_TARGET: "inbox",
                  WEBHOOK_SECRET: { secret: "wh-hmac" },
                },
                targets: [{ name: "inbox", handle: "ops-direct", coalesceSeconds: 0, maxWaitSeconds: 5, wakesPerHour: 120 }],
              },
              {
                name: "wh-file",
                builtin: "webhook",
                env: {
                  WEBHOOK_HOST: "127.0.0.1",
                  WEBHOOK_PORT: String(filePort),
                  WEBHOOK_PATH: "/hook-file",
                  WEBHOOK_TARGET: "inbox",
                  WEBHOOK_SECRET_FILE: { secretFile: "wh-file-hmac" },
                },
                targets: [{ name: "inbox", handle: "ops-file", coalesceSeconds: 0, maxWaitSeconds: 5, wakesPerHour: 120 }],
              },
            ],
          },
          null,
          2,
        ),
        { mode: 0o600 },
      );
      chmodSync(configPath, 0o600);

      // Verify raw connector.json contains zero plaintext secret values.
      const rawCfg = readFileSync(configPath, "utf8");
      assert.equal(rawCfg.includes(asciiSecret), false);
      assert.equal(rawCfg.includes(fileSecret), false);

      // Run real `hyp secret check <configPath> --json` and verify both references resolve cleanly.
      const checkRes = await runHypCli(["secret", "check", configPath, "--json"], { env: cliEnv });
      assert.equal(checkRes.code, 0, `${checkRes.stderr}\n${checkRes.stdout}`);
      const checkJson = checkRes.json<{
        ok: boolean;
        command: string;
        data: { total: number; passed: number; failed: number };
      }>();
      assert.equal(checkJson.ok, true);
      assert.equal(checkJson.command, "secret check");
      assert.equal(checkJson.data.total, 2);
      assert.equal(checkJson.data.passed, 2);
      assert.equal(checkJson.data.failed, 0);

      // Start a real Hyphae daemon loading both secrets exclusively from the virtual Secret Service.
      const config = await withProcessEnv(
        {
          PATH: cliEnv.PATH,
          HYPHAE_SECRET_BACKEND: "secret-service",
          HYPHAE_KEYCHAIN_SERVICE: service,
        },
        () => loadConfig(configPath),
      );
      const daemon = await startDaemon(config, { quiet: true });
      topo.track(() => daemon.stop());

      // Confirm zero plaintext `.secret` files in secrets/, while `.runtime/wh-file-hmac.secret` is 0600 inside 0700 `.runtime/`.
      assert.deepEqual(listPlaintextSecretFiles(configDir), []);
      const runtimeDir = join(secretsDir(configDir), ".runtime");
      const runtimeFile = join(runtimeDir, "wh-file-hmac.secret");
      assert.equal(existsSync(runtimeDir), true);
      assert.equal(existsSync(runtimeFile), true);
      assert.equal(existsSync(join(runtimeDir, "wh-hmac.secret")), false, "{ secret } must NOT materialize a runtime file");
      assert.equal(lstatSync(runtimeDir).mode & 0o777, 0o700, ".runtime directory must have 0700 permissions");
      assert.equal(lstatSync(runtimeFile).mode & 0o777, 0o600, "materialized secretFile must have 0600 permissions");
      assert.equal(readFileSync(runtimeFile, "utf8").trim(), fileSecret);

      // Register sessions for both webhook targets and deliver tampered (401) + valid signed (202) webhooks.
      daemon.state.register("claude:direct-agent", { kind: "claude" });
      daemon.state.register("codex:file-agent", { kind: "codex" });
      await daemon.connector.call("claude:direct-agent", "hyp_join", { handle: "ops-direct" });
      await daemon.connector.call("codex:file-agent", "hyp_join", { handle: "ops-file" });

      const badDirect = await deliverSignedWebhook({
        url: `http://127.0.0.1:${directPort}/hook-direct`,
        secret: asciiSecret,
        payload: { message: "tampered-direct" },
        overrideSignature: "sha256=" + "0".repeat(64),
      });
      assert.equal(badDirect.status, 401);

      const okDirect = await deliverSignedWebhook({
        url: `http://127.0.0.1:${directPort}/hook-direct`,
        secret: asciiSecret,
        payload: { message: "verified-secret-service-direct" },
      });
      assert.equal(okDirect.status, 202);

      const badFile = await deliverSignedWebhook({
        url: `http://127.0.0.1:${filePort}/hook-file`,
        secret: fileSecret,
        payload: { message: "tampered-file" },
        overrideSignature: "sha256=" + "f".repeat(64),
      });
      assert.equal(badFile.status, 401);

      const okFile = await deliverSignedWebhook({
        url: `http://127.0.0.1:${filePort}/hook-file`,
        secret: fileSecret,
        payload: { message: "verified-secret-service-file" },
      });
      assert.equal(okFile.status, 202);

      const [directItems, fileItems] = await Promise.all([
        waitFor(() => {
          const items = daemon.connector.drainMailbox("claude:direct-agent", 5);
          return items.length > 0 ? items : null;
        }, { label: "ops-direct receiving direct-secret webhook" }),
        waitFor(() => {
          const items = daemon.connector.drainMailbox("codex:file-agent", 5);
          return items.length > 0 ? items : null;
        }, { label: "ops-file receiving secretFile webhook" }),
      ]);
      assert.match(directItems[0].text, /verified-secret-service-direct/);
      assert.doesNotMatch(directItems[0].text, /tampered-direct/);
      assert.match(fileItems[0].text, /verified-secret-service-file/);
      assert.doesNotMatch(fileItems[0].text, /tampered-file/);

      await daemon.stop();

      // Remove `wh-hmac` via real `hyp secret rm --json` and `wh-file-hmac` via `deleteSecret`.
      const rmRes = await runHypCli(["secret", "rm", "wh-hmac", "--config-dir", configDir, "--json"], { env: cliEnv });
      assert.equal(rmRes.code, 0, rmRes.stderr);
      const rmJson = rmRes.json<{ ok: boolean; command: string; data: { name: string; removed: boolean } }>();
      assert.equal(rmJson.ok, true);
      assert.equal(rmJson.command, "secret rm");
      assert.equal(rmJson.data.removed, true);
      assert.equal(vss.store.has(service, "wh-hmac"), false);
      assert.equal(readIndexSecretNames(configDir).includes("wh-hmac"), false);

      const deletedFileSecret = await withProcessEnv(
        {
          PATH: cliEnv.PATH,
          HYPHAE_SECRET_BACKEND: "secret-service",
          HYPHAE_KEYCHAIN_SERVICE: service,
        },
        () => deleteSecret("wh-file-hmac", configDir),
      );
      assert.equal(deletedFileSecret, true);
      assert.equal(vss.store.has(service, "wh-file-hmac"), false, "deleteSecret must remove entry from secret-tool");
      assert.equal(readIndexSecretNames(configDir).includes("wh-file-hmac"), false, "deleteSecret must remove entry from index.json");
      assert.equal(existsSync(runtimeFile), false, "deleteSecret must remove materialized .runtime/<name>.secret");

      // Second removal returns removed: false cleanly.
      const rmAgain = await runHypCli(["secret", "rm", "wh-file-hmac", "--config-dir", configDir, "--json"], { env: cliEnv });
      assert.equal(rmAgain.code, 0);
      assert.equal(rmAgain.json<{ data: { removed: boolean } }>().data.removed, false);

      // Re-verify no secret value ever leaked into secret-tool argv across the entire lifecycle.
      for (const inv of vss.invocations) {
        for (const secretVal of allSecretValues) {
          assert.equal(inv.argvJoined.includes(secretVal), false, `secret value leaked into argv: ${inv.argvJoined}`);
        }
      }
    } finally {
      await topo.cleanup();
    }
  },
);

test(
  "fail-closed vs fallback semantics, external secret deletion detection, temp-dir isolation, and invalid secret names",
  { timeout: 25_000 },
  async () => {
    const rootDir = mkdtempSync(join(tmpdir(), "hi-fc-"));
    const vss = startVirtualSecretService(join(rootDir, "shim"));
    const configDir = join(rootDir, "cfg");
    const xdgDir = join(rootDir, "xdg");
    const homeDir = join(rootDir, "home");
    mkdirSync(configDir, { recursive: true, mode: 0o700 });
    mkdirSync(xdgDir, { recursive: true, mode: 0o700 });
    mkdirSync(homeDir, { recursive: true, mode: 0o700 });

    const service = `hyphae-fc-${randomUUID().slice(0, 10)}`;
    const cliEnv: NodeJS.ProcessEnv = {
      ...vss.envWithPath(process.env),
      HOME: homeDir,
      XDG_CONFIG_HOME: xdgDir,
      HYPHAE_SECRET_BACKEND: "secret-service",
      HYPHAE_KEYCHAIN_SERVICE: service,
    };

    try {
      // 1. Explicit HYPHAE_SECRET_BACKEND=secret-service + store failure MUST fail closed (no silent plaintext fallback).
      vss.setFailMode("store", 1, "secret-tool: keyring is locked");

      await withProcessEnv(
        {
          PATH: cliEnv.PATH,
          HYPHAE_SECRET_BACKEND: "secret-service",
          HYPHAE_KEYCHAIN_SERVICE: service,
        },
        () => {
          assert.throws(
            () => writeSecretDetailed("fail-closed-token", "must-not-hit-disk", configDir),
            /keyring is locked|secret-tool store failed/i,
          );
        },
      );
      assert.equal(existsSync(secretFilePath("fail-closed-token", configDir)), false);
      assert.deepEqual(listPlaintextSecretFiles(configDir), []);
      assert.deepEqual(listSecrets(configDir), []);

      // Also verify CLI `hyp secret set` fails closed with non-zero exit and zero plaintext file written.
      const failCli = await runHypCli(
        ["secret", "set", "fail-closed-cli", "--config-dir", configDir, "--json"],
        { env: cliEnv, stdin: "must-not-hit-disk-cli\n" },
      );
      assert.notEqual(failCli.code, 0, "hyp secret set must fail closed when explicit secret-service store fails");
      const failEnvelope = failCli.json<{ ok: boolean; error?: { message: string } }>();
      assert.equal(failEnvelope.ok, false);
      assert.match(failEnvelope.error?.message ?? "", /keyring is locked|secret-tool/i);
      assert.equal(existsSync(secretFilePath("fail-closed-cli", configDir)), false);
      assert.deepEqual(listPlaintextSecretFiles(configDir), []);

      // 2. Store a secret cleanly, then delete it EXTERNALLY from secret-tool while keeping index.json intact.
      vss.setFailMode(null);
      await withProcessEnv(
        {
          PATH: cliEnv.PATH,
          HYPHAE_SECRET_BACKEND: "secret-service",
          HYPHAE_KEYCHAIN_SERVICE: service,
        },
        () => {
          const saved = writeSecretDetailed("orphaned-token", "live-secret-value-1", configDir);
          assert.equal(saved.backend, "secret-service");
          assert.equal(readSecret("orphaned-token", configDir), "live-secret-value-1");
        },
      );

      const cfgPath = join(configDir, "connector.json");
      writeFileSync(
        cfgPath,
        JSON.stringify(
          {
            connectorId: "fc@host",
            stateDir: "state",
            routers: [],
            plugins: [
              {
                name: "wh",
                builtin: "webhook",
                env: { WEBHOOK_SECRET: { secret: "orphaned-token" } },
                targets: [{ name: "inbox", handle: "agent" }],
              },
            ],
          },
          null,
          2,
        ),
        { mode: 0o600 },
      );

      // External deletion directly from secret-tool store (index.json still points to secret-service).
      assert.equal(vss.store.delete(service, "orphaned-token"), true);
      assert.equal(readIndexSecretNames(configDir).includes("orphaned-token"), true);

      await withProcessEnv(
        {
          PATH: cliEnv.PATH,
          HYPHAE_SECRET_BACKEND: "secret-service",
          HYPHAE_KEYCHAIN_SERVICE: service,
        },
        () => {
          assert.throws(
            () => readSecret("orphaned-token", configDir),
            /Missing secret "orphaned-token" in Linux Secret Service/,
          );
        },
      );

      // Real CLI `hyp secret check --json` must exit 1 with ok: false and actionable `fix` command.
      const checkOrphan = await runHypCli(["secret", "check", cfgPath, "--json"], { env: cliEnv });
      assert.equal(checkOrphan.code, 1, `expected exit code 1, got ${checkOrphan.code}: ${checkOrphan.stdout}`);
      const orphanJson = checkOrphan.json<{
        ok: boolean;
        command: string;
        next?: string[];
        data: { failed: number; passed: number; refs: Array<{ secret: string; ok: boolean; error?: string }> };
      }>();
      assert.equal(orphanJson.ok, false);
      assert.equal(orphanJson.command, "secret check");
      assert.equal(orphanJson.data.failed, 1);
      assert.equal(orphanJson.data.passed, 0);
      assert.equal(orphanJson.data.refs[0]?.secret, "orphaned-token");
      assert.equal(orphanJson.data.refs[0]?.ok, false);
      assert.ok(
        orphanJson.next?.includes("hyp secret set orphaned-token --web"),
        `expected actionable fix command in next, got: ${JSON.stringify(orphanJson.next)}`,
      );

      // Lookup fault on an existing secret also fails closed.
      vss.store.set(service, "orphaned-token", "restored-secret");
      vss.setFailMode("lookup", 1, "secret-tool: D-Bus session disconnected");
      const checkFault = await runHypCli(["secret", "check", cfgPath, "--json"], { env: cliEnv });
      assert.equal(checkFault.code, 1);
      assert.equal(checkFault.json<{ ok: boolean }>().ok, false);
      vss.setFailMode(null);

      // 3. `isInsideTempDir` safety invariant: without HYPHAE_SECRET_BACKEND, temp dirs ALWAYS resolve to `file`.
      await withProcessEnv({ HYPHAE_SECRET_BACKEND: undefined }, () => {
        assert.equal(detectSecretBackend(configDir), "file");
      });
      const unsetEnv: NodeJS.ProcessEnv = { ...cliEnv };
      delete unsetEnv.HYPHAE_SECRET_BACKEND;
      const listTempRes = await runHypCli(["secret", "list", "--config-dir", configDir, "--json"], { env: unsetEnv });
      assert.equal(listTempRes.code, 0, listTempRes.stderr);
      assert.equal(listTempRes.json<{ data: { defaultBackend: string } }>().data.defaultBackend, "file");

      // 4. Invalid secret names & empty secret values rejected cleanly (both in-process and CLI).
      const invalidNames = ["../escape", "UPPER", "bad space", "", ".hidden", "-leading", "a".repeat(65)];
      for (const badName of invalidNames) {
        assert.throws(() => writeSecretDetailed(badName, "val", configDir), /Invalid secret name/);
        assert.throws(() => readSecret(badName, configDir), /Invalid secret name/);
        assert.throws(() => deleteSecret(badName, configDir), /Invalid secret name/);
      }
      assert.throws(() => writeSecretDetailed("valid-name", "   \n\t  ", configDir), /cannot be empty/i);

      for (const badCliName of ["../escape", "UPPER", "bad space"]) {
        const badRes = await runHypCli(
          ["secret", "set", badCliName, "--config-dir", configDir, "--json"],
          { env: cliEnv, stdin: "some-value\n" },
        );
        assert.notEqual(badRes.code, 0, `expected invalid secret name '${badCliName}' to fail`);
        assert.equal(badRes.json<{ ok: boolean }>().ok, false);
      }
      assert.equal(existsSync(join(rootDir, "escape.secret")), false);
    } finally {
      vss.close();
      rmSync(rootDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  },
);

test(
  "real CLI `hyp secret set --web --no-open --json`: keep-alive close latency and adversarial HTTP security",
  { timeout: 25_000 },
  async () => {
    const rootDir = mkdtempSync(join(tmpdir(), "hi-web-"));
    const vss = startVirtualSecretService(join(rootDir, "shim"));
    const configDir = join(rootDir, "cfg");
    const xdgDir = join(rootDir, "xdg");
    const homeDir = join(rootDir, "home");
    mkdirSync(configDir, { recursive: true, mode: 0o700 });
    mkdirSync(xdgDir, { recursive: true, mode: 0o700 });
    mkdirSync(homeDir, { recursive: true, mode: 0o700 });

    const service = `hyphae-web-${randomUUID().slice(0, 10)}`;
    const cliEnv: NodeJS.ProcessEnv = {
      ...vss.envWithPath(process.env),
      HOME: homeDir,
      XDG_CONFIG_HOME: xdgDir,
      HYPHAE_SECRET_BACKEND: "secret-service",
      HYPHAE_KEYCHAIN_SERVICE: service,
    };

    const agent = new http.Agent({ keepAlive: true, keepAliveMsecs: 30_000, maxSockets: 4 });
    const proc = spawn(
      process.execPath,
      [CLI_PATH, "secret", "set", "web-cli-token", "--web", "--no-open", "--json", "--config-dir", configDir],
      { env: cliEnv, stdio: ["ignore", "pipe", "pipe"] },
    );

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let stderrText = "";
    proc.stdout.on("data", (d: Buffer) => stdoutChunks.push(d));
    proc.stderr.on("data", (d: Buffer) => {
      stderrChunks.push(d);
      stderrText += d.toString("utf8");
    });

    let exitAt = 0;
    const exitPromise = new Promise<number | null>((resolve) => {
      proc.once("exit", (code) => {
        exitAt = Date.now();
        resolve(code);
      });
    });

    const submittedSecret = "web-captured-secret-$42-🔐-!@#";

    try {
      // Wait for the real CLI process to print the one-shot loopback capture URL on stderr.
      const captureUrl = await waitFor(
        () => {
          const m = /(http:\/\/127\.0\.0\.1:\d+\/s\/[A-Za-z0-9_-]+)/.exec(stderrText);
          return m?.[1] ?? null;
        },
        { label: "hyp secret set --web capture URL on stderr", timeoutMs: 8_000 },
      );
      const parsedUrl = new URL(captureUrl);
      const origin = parsedUrl.origin;

      // 1. /favicon.ico -> 204 + connection: close
      const favRes = await httpRequest(`${origin}/favicon.ico`, {
        method: "GET",
        headers: { connection: "keep-alive" },
        agent,
      });
      assert.equal(favRes.status, 204);
      assert.equal(favRes.headers.connection, "close");

      // 2. Wrong path -> 404
      const wrongPathRes = await httpRequest(`${origin}/s/wrong-token`, {
        method: "GET",
        headers: { connection: "keep-alive" },
        agent,
      });
      assert.equal(wrongPathRes.status, 404);
      assert.equal(wrongPathRes.headers.connection, "close");

      // 3. Unsupported HTTP method (PUT) on valid path -> 405
      const putRes = await httpRequest(captureUrl, {
        method: "PUT",
        headers: { connection: "keep-alive" },
        agent,
      });
      assert.equal(putRes.status, 405);
      assert.equal(putRes.headers.connection, "close");

      // 4. GET valid path -> 200, mentions Linux Secret Service, includes CSRF token
      const formRes = await httpRequest(captureUrl, {
        method: "GET",
        headers: { connection: "keep-alive" },
        agent,
      });
      assert.equal(formRes.status, 200);
      assert.equal(formRes.headers.connection, "close");
      assert.equal(formRes.headers["cache-control"], "no-store");
      assert.match(formRes.body, /Linux Secret Service/);
      const tokenMatch = /name="token" value="([^"]+)"/.exec(formRes.body);
      assert.ok(tokenMatch?.[1], "expected hidden CSRF token input in HTML form");
      const csrfToken = tokenMatch[1];

      // 5. POST with tampered CSRF token (exact same byte length, 1 char flipped) -> 403
      const flippedChar = csrfToken[0] === "A" ? "B" : "A";
      const tamperedToken = flippedChar + csrfToken.slice(1);
      assert.equal(tamperedToken.length, csrfToken.length);
      const badCsrfBody = new URLSearchParams({ token: tamperedToken, value: "ignored" }).toString();
      const badCsrfRes = await httpRequest(captureUrl, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          "content-length": String(Buffer.byteLength(badCsrfBody)),
          connection: "keep-alive",
        },
        body: badCsrfBody,
        agent,
      });
      assert.equal(badCsrfRes.status, 403);
      assert.equal(badCsrfRes.headers.connection, "close");

      // 6. POST with valid CSRF token + empty/whitespace value -> 400
      const emptyBody = new URLSearchParams({ token: csrfToken, value: "   " }).toString();
      const emptyRes = await httpRequest(captureUrl, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          "content-length": String(Buffer.byteLength(emptyBody)),
          connection: "keep-alive",
        },
        body: emptyBody,
        agent,
      });
      assert.equal(emptyRes.status, 400);
      assert.equal(emptyRes.headers.connection, "close");

      // 7. POST with >64 KiB payload -> 413
      const oversizedBody = new URLSearchParams({
        token: csrfToken,
        value: "x".repeat(70 * 1024),
      }).toString();
      const oversizedRes = await httpRequest(captureUrl, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          "content-length": String(Buffer.byteLength(oversizedBody)),
          connection: "keep-alive",
        },
        body: oversizedBody,
        agent,
      });
      assert.equal(oversizedRes.status, 413);
      assert.equal(oversizedRes.headers.connection, "close");

      // 8. Valid POST over explicit `connection: keep-alive` -> 200 + `connection: close` + `Saved`
      const validBody = new URLSearchParams({ token: csrfToken, value: submittedSecret }).toString();
      const postRes = await httpRequest(captureUrl, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          "content-length": String(Buffer.byteLength(validBody)),
          connection: "keep-alive",
        },
        body: validBody,
        agent,
      });
      const postDoneAt = Date.now();
      assert.equal(postRes.status, 200);
      assert.equal(postRes.headers.connection, "close");
      assert.match(postRes.body, /Saved/);
      assert.match(postRes.body, /Linux Secret Service/);

      // Assert the real `hyp` CLI exits with code 0 within < 2000ms (zero keep-alive hang!).
      const exitCode = await exitPromise;
      const exitLatencyMs = exitAt - postDoneAt;
      assert.equal(exitCode, 0, `expected hyp CLI exit 0, got ${exitCode}; stderr: ${stderrText}`);
      assert.ok(
        exitLatencyMs < 2_000,
        `expected hyp secret set --web to exit within 2000ms after POST, took ${exitLatencyMs}ms`,
      );

      const stdoutText = Buffer.concat(stdoutChunks).toString("utf8");
      const fullStderr = Buffer.concat(stderrChunks).toString("utf8");
      assert.equal(stdoutText.includes(submittedSecret), false, "captured secret must NEVER appear in stdout");
      assert.equal(fullStderr.includes(submittedSecret), false, "captured secret must NEVER appear in stderr");

      const envelope = JSON.parse(stdoutText) as {
        ok: boolean;
        command: string;
        data: { name: string; backend: string; source: string; location: string; path: string };
      };
      assert.equal(envelope.ok, true);
      assert.equal(envelope.command, "secret set");
      assert.equal(envelope.data.name, "web-cli-token");
      assert.equal(envelope.data.backend, "secret-service");
      assert.equal(envelope.data.source, "web");
      assert.equal(envelope.data.location, `secret-service:${service}/web-cli-token`);

      // Secret is stored ONLY in virtual Secret Service and readable via readSecret (zero `.secret` files on disk).
      assert.deepEqual(listPlaintextSecretFiles(configDir), []);
      assert.equal(vss.store.get(service, "web-cli-token")?.value, submittedSecret);
      await withProcessEnv(
        {
          PATH: cliEnv.PATH,
          HYPHAE_SECRET_BACKEND: "secret-service",
          HYPHAE_KEYCHAIN_SERVICE: service,
        },
        () => {
          assert.equal(readSecret("web-cli-token", configDir), submittedSecret);
        },
      );
      for (const inv of vss.invocations) {
        assert.equal(inv.argvJoined.includes(submittedSecret), false, "captured secret must never appear in secret-tool argv");
      }
    } finally {
      agent.destroy();
      if (proc.exitCode === null) proc.kill("SIGKILL");
      vss.close();
      rmSync(rootDir, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
    }
  },
);

test(
  "real macOS Keychain end-to-end daemon + live github-webhook stream ({secret}) and webhook bridge ({secretFile})",
  { skip: process.platform !== "darwin" || !existsSync("/usr/bin/security"), timeout: 30_000 },
  async () => {
    const topo = new MeshTopology("hi-kc-");
    const hubDir = topo.subDir("h");
    const xdgDir = topo.subDir("xdg");
    const homeDir = topo.subDir("home");
    const service = `hyphae-int-${randomUUID().slice(0, 12)}`;
    const ghSecretName = "gh-kc-secret";
    const whSecretName = "wh-kc-file-secret";
    const ghSecretValue = `ghwh_kc_$99!"#%&()*+,-./:;<=>?@[]`;
    const whSecretValue = "whkc_file_secret_v1_alpha99_delta";
    const createdSecrets = [ghSecretName, whSecretName];

    // Keep real HOME so macOS `/usr/bin/security` resolves the user's unlocked login keychain,
    // while isolating config via XDG_CONFIG_HOME + --config-dir and an ephemeral HYPHAE_KEYCHAIN_SERVICE.
    const kcCliEnv: NodeJS.ProcessEnv = {
      ...process.env,
      XDG_CONFIG_HOME: xdgDir,
      HYPHAE_SECRET_BACKEND: "keychain",
      HYPHAE_KEYCHAIN_SERVICE: service,
    };

    try {
      // 1. Store both secrets in real macOS Keychain under the ephemeral service via `hyp secret set`.
      for (const [name, value] of [
        [ghSecretName, ghSecretValue],
        [whSecretName, whSecretValue],
      ] as const) {
        const res = await runHypCli(
          ["secret", "set", name, "--config-dir", hubDir, "--json"],
          { env: kcCliEnv, stdin: `${value}\n` },
        );
        assert.equal(res.code, 0, `hyp secret set ${name} failed: ${res.stderr}\n${res.stdout}`);
        const envJson = res.json<{
          ok: boolean;
          data: { name: string; backend: string; location: string };
        }>();
        assert.equal(envJson.ok, true);
        assert.equal(envJson.data.name, name);
        assert.equal(envJson.data.backend, "keychain");
        assert.equal(envJson.data.location, `keychain:${service}/${name}`);
        assert.equal(res.stdout.includes(value), false);
        assert.equal(res.stderr.includes(value), false);
      }

      // Confirm zero plaintext `.secret` files exist on disk under `<hubDir>/secrets/`.
      assert.deepEqual(listPlaintextSecretFiles(hubDir), []);

      // 2. Provision embedded router + github-webhook stream (`{ secret }`) + webhook bridge (`{ secretFile }`).
      const routerPort = await freePort();
      const ghPort = await freePort();
      const whPort = await freePort();
      const configPath = join(hubDir, "connector.json");

      await runOnboard({
        configPath,
        connectorId: "kc@macbook",
        port: routerPort,
        homeDir,
        harnesses: [],
        startDaemon: false,
        localRouterExposure: "private",
        localRouterStreams: [
          {
            name: "github",
            topic: "github",
            builtin: "github-webhook",
            env: {
              GITHUB_WEBHOOK_HOST: "127.0.0.1",
              GITHUB_WEBHOOK_PORT: String(ghPort),
              GITHUB_WEBHOOK_SECRET: { secret: ghSecretName },
            },
          },
        ],
        plugins: [
          {
            name: "wh",
            builtin: "webhook",
            env: {
              WEBHOOK_HOST: "127.0.0.1",
              WEBHOOK_PORT: String(whPort),
              WEBHOOK_PATH: "/kc-hook",
              WEBHOOK_TARGET: "inbox",
              WEBHOOK_SECRET_FILE: { secretFile: whSecretName },
            },
            targets: [{ name: "inbox", handle: "kc-agent", coalesceSeconds: 0, maxWaitSeconds: 5, wakesPerHour: 120 }],
          },
        ],
      });

      const rawConfig = readFileSync(configPath, "utf8");
      assert.equal(rawConfig.includes(ghSecretValue), false);
      assert.equal(rawConfig.includes(whSecretValue), false);

      // Verify `hyp secret check` passes against real macOS Keychain.
      const checkRes = await runHypCli(["secret", "check", configPath, "--json"], { env: kcCliEnv });
      assert.equal(checkRes.code, 0, `${checkRes.stderr}\n${checkRes.stdout}`);
      const checkJson = checkRes.json<{ ok: boolean; data: { total: number; passed: number; failed: number } }>();
      assert.equal(checkJson.ok, true);
      assert.equal(checkJson.data.total, 2);
      assert.equal(checkJson.data.passed, 2);

      // Boot daemon with Keychain-resolved config.
      const loadedConfig = await withProcessEnv(
        { HYPHAE_SECRET_BACKEND: "keychain", HYPHAE_KEYCHAIN_SERVICE: service },
        () => loadConfig(configPath),
      );
      const daemon = await startDaemon(loadedConfig, { quiet: true });
      topo.track(() => daemon.stop());

      // Confirm zero plaintext `.secret` files, while `.runtime/wh-kc-file-secret.secret` is 0600 in 0700 `.runtime/`.
      assert.deepEqual(listPlaintextSecretFiles(hubDir), []);
      const runtimeDir = join(secretsDir(hubDir), ".runtime");
      const runtimeFile = join(runtimeDir, `${whSecretName}.secret`);
      assert.equal(existsSync(runtimeFile), true);
      assert.equal(lstatSync(runtimeDir).mode & 0o777, 0o700);
      assert.equal(lstatSync(runtimeFile).mode & 0o777, 0o600);
      assert.equal(readFileSync(runtimeFile, "utf8").trim(), whSecretValue);

      // Register agent session subscribed to GitHub PRs and bound to `kc-agent` for webhook bridge delivery.
      daemon.state.register("claude:kc-agent", { kind: "claude" });
      await daemon.connector.call("claude:kc-agent", "hyp_join", { handle: "kc-agent" });
      await daemon.connector.call("claude:kc-agent", "hyp_subscribe", {
        key: "gh:kc-prs",
        topic: "github",
        filters: [{ exact: { type: "com.github.pull_request.opened", repo: "acme/keychain-app" } }],
        coalesceSeconds: 0,
      });

      // 3. Deliver tampered (401) + valid signed (202) GitHub PR webhook.
      const prPayload = makeGithubPullRequestPayload({
        repo: "acme/keychain-app",
        number: 77,
        title: "Verify macOS Keychain secret delivery",
        author: "bogdan",
      });
      const badGh = await deliverGithubWebhook({
        receiverUrl: `http://127.0.0.1:${ghPort}`,
        secret: ghSecretValue,
        event: "pull_request",
        payload: prPayload,
        overrideSignature: "sha256=" + "0".repeat(64),
      });
      assert.equal(badGh.status, 401);

      const okGh = await deliverGithubWebhook({
        receiverUrl: `http://127.0.0.1:${ghPort}`,
        secret: ghSecretValue,
        event: "pull_request",
        payload: prPayload,
      });
      assert.equal(okGh.status, 202);

      // 4. Deliver tampered (401) + valid signed (202) webhook POST verified via `.runtime/wh-kc-file-secret.secret`.
      const badWh = await deliverSignedWebhook({
        url: `http://127.0.0.1:${whPort}/kc-hook`,
        secret: whSecretValue,
        payload: { message: "tampered-kc-webhook" },
        overrideSignature: "sha256=" + "1".repeat(64),
      });
      assert.equal(badWh.status, 401);

      const okWh = await deliverSignedWebhook({
        url: `http://127.0.0.1:${whPort}/kc-hook`,
        secret: whSecretValue,
        payload: { message: "verified-kc-file-webhook" },
      });
      assert.equal(okWh.status, 202);

      const items = await waitFor(
        () => {
          if (daemon.state.pendingCount("claude:kc-agent") < 2) return null;
          return daemon.connector.drainMailbox("claude:kc-agent", 10);
        },
        { label: "kc-agent receiving both GitHub PR and webhook bridge events" },
      );
      const combined = items.map((i) => i.text).join("\n");
      assert.match(combined, /Verify macOS Keychain secret delivery/);
      assert.match(combined, /verified-kc-file-webhook/);
      assert.doesNotMatch(combined, /tampered-kc-webhook/);

      await daemon.stop();

      // 5. Delete both secrets and verify Keychain entries AND `.runtime/` materialized file are removed.
      await withProcessEnv(
        { HYPHAE_SECRET_BACKEND: "keychain", HYPHAE_KEYCHAIN_SERVICE: service },
        () => {
          assert.equal(deleteSecret(ghSecretName, hubDir), true);
        },
      );
      const rmWh = await runHypCli(["secret", "rm", whSecretName, "--config-dir", hubDir, "--json"], { env: kcCliEnv });
      assert.equal(rmWh.code, 0, rmWh.stderr);
      assert.equal(rmWh.json<{ ok: boolean; data: { removed: boolean } }>().data.removed, true);

      assert.equal(existsSync(runtimeFile), false, ".runtime materialized file must be removed on secret deletion");
      assert.deepEqual(listSecrets(hubDir), []);

      // Directly confirm via `/usr/bin/security` that neither item remains in macOS Keychain.
      for (const name of createdSecrets) {
        await assert.rejects(
          execFileAsync("/usr/bin/security", ["find-generic-password", "-s", service, "-a", name, "-w"]),
          `Keychain item '${service}/${name}' should have been deleted`,
        );
      }
    } finally {
      // Unconditional cleanup of every ephemeral macOS Keychain item created by this test.
      await withProcessEnv(
        { HYPHAE_SECRET_BACKEND: "keychain", HYPHAE_KEYCHAIN_SERVICE: service },
        async () => {
          for (const name of createdSecrets) {
            try {
              deleteSecret(name, hubDir);
            } catch {}
            await execFileAsync("/usr/bin/security", ["delete-generic-password", "-s", service, "-a", name]).catch(() => {});
          }
        },
      );
      await topo.cleanup();
    }
  },
);
