import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import {
  captureSecretViaWeb,
  deleteSecret,
  detectSecretBackend,
  listSecrets,
  readSecret,
  resolveEnvWithSecrets,
  secretBackendLabel,
  secretFilePath,
  writeSecretDetailed,
} from "./secrets.ts";

function makeTempConfigDir(): string {
  return mkdtempSync(join(tmpdir(), "hyphae-secrets-test-"));
}

function httpRequest(
  url: string,
  options: { method: string; headers?: Record<string, string>; body?: string; agent: http.Agent },
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
    if (options.body) req.write(options.body);
    req.end();
  });
}

test("detectSecretBackend isolates temp dirs to file store and honors explicit overrides", () => {
  const dir = makeTempConfigDir();
  const prevBackend = process.env.HYPHAE_SECRET_BACKEND;
  try {
    delete process.env.HYPHAE_SECRET_BACKEND;
    assert.equal(detectSecretBackend(dir), "file");

    process.env.HYPHAE_SECRET_BACKEND = "keychain";
    assert.equal(detectSecretBackend(dir), "keychain");
    assert.equal(secretBackendLabel("keychain"), "macOS Keychain");
    assert.equal(secretBackendLabel("secret-service"), "Linux Secret Service");
    assert.equal(secretBackendLabel("file"), "local file store");
  } finally {
    if (prevBackend === undefined) delete process.env.HYPHAE_SECRET_BACKEND;
    else process.env.HYPHAE_SECRET_BACKEND = prevBackend;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("file backend round-trip, listing, env resolution, and deletion", () => {
  const dir = makeTempConfigDir();
  const prevBackend = process.env.HYPHAE_SECRET_BACKEND;
  try {
    process.env.HYPHAE_SECRET_BACKEND = "file";
    const saved = writeSecretDetailed("api-token", "  super-secret-value-123  ", dir);
    assert.equal(saved.backend, "file");
    assert.equal(saved.location, secretFilePath("api-token", dir));
    assert.equal(saved.path, saved.location);

    assert.equal(readSecret("api-token", dir), "super-secret-value-123");

    const listed = listSecrets(dir);
    assert.equal(listed.length, 1);
    assert.equal(listed[0]?.name, "api-token");
    assert.equal(listed[0]?.backend, "file");
    assert.equal(listed[0]?.modeOk, true);

    const resolved = resolveEnvWithSecrets(
      {
        DIRECT: { secret: "api-token" },
        FILE_REF: { secretFile: "api-token" },
        PLAIN: "hello",
      },
      dir,
      "plugin:test",
    );
    assert.equal(resolved.env.DIRECT, "super-secret-value-123");
    assert.equal(resolved.env.FILE_REF, secretFilePath("api-token", dir));
    assert.equal(resolved.env.PLAIN, "hello");
    assert.deepEqual(resolved.secretRefs, ["api-token"]);

    assert.equal(deleteSecret("api-token", dir), true);
    assert.equal(deleteSecret("api-token", dir), false);
    assert.throws(() => readSecret("api-token", dir), /Missing secret/);
  } finally {
    if (prevBackend === undefined) delete process.env.HYPHAE_SECRET_BACKEND;
    else process.env.HYPHAE_SECRET_BACKEND = prevBackend;
    rmSync(dir, { recursive: true, force: true });
  }
});

test("captureSecretViaWeb shuts down immediately even with HTTP/1.1 keep-alive browser sockets", async () => {
  const dir = makeTempConfigDir();
  const prevBackend = process.env.HYPHAE_SECRET_BACKEND;
  const agent = new http.Agent({ keepAlive: true, keepAliveMsecs: 30_000, maxSockets: 4 });
  try {
    process.env.HYPHAE_SECRET_BACKEND = "file";

    let readyUrl = "";
    let resolveReady!: (url: string) => void;
    const readyPromise = new Promise<string>((resolve) => {
      resolveReady = resolve;
    });

    const capturePromise = captureSecretViaWeb("web-keepalive-test", {
      configDir: dir,
      openBrowser: false,
      timeoutMs: 10_000,
      onReady: (url) => {
        readyUrl = url;
        resolveReady(url);
      },
    });

    const url = await readyPromise;
    assert.ok(url.startsWith("http://127.0.0.1:"));

    // Simulate a real browser opening the form over keep-alive + requesting /favicon.ico.
    const formRes = await httpRequest(url, {
      method: "GET",
      headers: { connection: "keep-alive" },
      agent,
    });
    assert.equal(formRes.status, 200);
    assert.equal(formRes.headers.connection, "close");

    const origin = new URL(url).origin;
    const favRes = await httpRequest(`${origin}/favicon.ico`, {
      method: "GET",
      headers: { connection: "keep-alive" },
      agent,
    });
    assert.equal(favRes.status, 204);

    const tokenMatch = /name="token" value="([^"]+)"/.exec(formRes.body);
    assert.ok(tokenMatch?.[1], "expected CSRF token in web form");

    const startedPost = Date.now();
    const postBody = new URLSearchParams({
      token: tokenMatch[1],
      value: "s3cr3t-via-web-form!",
    }).toString();

    const postRes = await httpRequest(url, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "content-length": String(Buffer.byteLength(postBody)),
        connection: "keep-alive",
      },
      body: postBody,
      agent,
    });
    assert.equal(postRes.status, 200);
    assert.equal(postRes.headers.connection, "close");
    assert.match(postRes.body, /Saved/);

    const result = await capturePromise;
    const elapsedMs = Date.now() - startedPost;
    assert.ok(elapsedMs < 1500, `expected captureSecretViaWeb to resolve quickly after POST, took ${elapsedMs}ms`);
    assert.equal(result.backend, "file");
    assert.equal(result.url, readyUrl);
    assert.equal(readSecret("web-keepalive-test", dir), "s3cr3t-via-web-form!");
  } finally {
    agent.destroy();
    if (prevBackend === undefined) delete process.env.HYPHAE_SECRET_BACKEND;
    else process.env.HYPHAE_SECRET_BACKEND = prevBackend;
    rmSync(dir, { recursive: true, force: true });
  }
});

test(
  "macOS Keychain backend stores secrets out-of-file with special chars, materializes secretFile, and cleans up",
  { skip: process.platform !== "darwin" || !existsSync("/usr/bin/security") },
  () => {
    const dir = makeTempConfigDir();
    const prevBackend = process.env.HYPHAE_SECRET_BACKEND;
    const prevService = process.env.HYPHAE_KEYCHAIN_SERVICE;
    const service = `hyphae-test-${randomUUID().slice(0, 12)}`;
    const secretName = "kc-special-secret";
    const secretVal = `xoxb-1234 "quoted" 'single' $dollar \\slash\t& line2\n🔥 more!`;
    const hexSecretName = "kc-hex-secret";
    const hexSecretVal = "deadbeef0123456789abcdef0123456789abcdef";

    try {
      process.env.HYPHAE_SECRET_BACKEND = "keychain";
      process.env.HYPHAE_KEYCHAIN_SERVICE = service;

      // Seed a legacy plaintext file first to confirm migration into Keychain removes it.
      const legacyDir = join(dir, "secrets");
      mkdirSync(legacyDir, { recursive: true, mode: 0o700 });
      const legacyPath = secretFilePath(secretName, dir);
      writeFileSync(legacyPath, "old-plaintext-value\n", { mode: 0o600 });
      assert.equal(existsSync(legacyPath), true);
      const saved = writeSecretDetailed(secretName, secretVal, dir);

      assert.equal(saved.backend, "keychain");
      assert.equal(saved.location, `keychain:${service}/${secretName}`);
      assert.equal(existsSync(legacyPath), false, "plaintext .secret file must not exist when stored in Keychain");

      assert.equal(readSecret(secretName, dir), secretVal);

      // Pure hex values must also round-trip unmodified without being mis-decoded.
      writeSecretDetailed(hexSecretName, hexSecretVal, dir);
      assert.equal(readSecret(hexSecretName, dir), hexSecretVal);

      const listed = listSecrets(dir);
      assert.equal(listed.length, 2);
      const specialEntry = listed.find((s) => s.name === secretName);
      assert.ok(specialEntry);
      assert.equal(specialEntry.backend, "keychain");
      assert.equal(specialEntry.location, `keychain:${service}/${secretName}`);
      assert.equal(specialEntry.bytes, null);

      const resolved = resolveEnvWithSecrets(
        {
          TOKEN: { secret: secretName },
          TOKEN_FILE: { secretFile: secretName },
        },
        dir,
        "plugin:kc-test",
      );
      assert.equal(resolved.env.TOKEN, secretVal);
      assert.ok(resolved.env.TOKEN_FILE && existsSync(resolved.env.TOKEN_FILE));
      assert.equal(readFileSync(resolved.env.TOKEN_FILE, "utf8").trim(), secretVal);

      assert.equal(deleteSecret(secretName, dir), true);
      assert.equal(deleteSecret(hexSecretName, dir), true);
      assert.equal(existsSync(resolved.env.TOKEN_FILE), false, "runtime materialized file should be deleted on deleteSecret");
      assert.throws(() => readSecret(secretName, dir), /Missing secret/);
    } finally {
      try {
        deleteSecret(secretName, dir);
      } catch {}
      try {
        deleteSecret(hexSecretName, dir);
      } catch {}
      if (prevBackend === undefined) delete process.env.HYPHAE_SECRET_BACKEND;
      else process.env.HYPHAE_SECRET_BACKEND = prevBackend;
      if (prevService === undefined) delete process.env.HYPHAE_KEYCHAIN_SERVICE;
      else process.env.HYPHAE_KEYCHAIN_SERVICE = prevService;
      rmSync(dir, { recursive: true, force: true });
    }
  },
);
