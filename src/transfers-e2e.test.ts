import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { test } from "node:test";
import { gzipSync } from "node:zlib";
import { issueGrant, parsePairingCode, signBinding } from "./core/identity/grant.ts";
import {
  fingerprint,
  generatePrivateKey,
  publicKeyFromRaw,
  rawPublicKey,
} from "./core/identity/keys.ts";
import { RouterCore } from "./core/router/core.ts";
import { serveRouter } from "./core/router/server.ts";
import { PACK_MAGIC, packFiles, unpackFiles } from "./core/transfer/pack.ts";
import { open as openTransfer, OpenError, seal as sealTransfer } from "./core/transfer/seal.ts";
import { startDaemon } from "./daemon.ts";
import {
  connectorKeySecretNames,
  createKeyRegistration,
  loadOrCreateConnectorKeys,
  verifyKeyRegistration,
} from "./identity.ts";
import { UNTRUSTED_PROVENANCE } from "./protocol.ts";
import { RouterError } from "./router.ts";
import { State } from "./state.ts";

const CLI_PATH = join(process.cwd(), "src", "cli.ts");

function encodeTransferHeader(header: { payload: string; sig: string }): string {
  return Buffer.from(JSON.stringify(header), "utf8").toString("base64url");
}

function buildRawPack(manifest: unknown, fileData: Buffer = Buffer.alloc(0), magic = PACK_MAGIC): Buffer {
  const magicBuf = Buffer.from(magic, "ascii");
  const manifestBuf = Buffer.from(JSON.stringify(manifest), "utf8");
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(manifestBuf.length, 0);
  return gzipSync(Buffer.concat([magicBuf, lenBuf, manifestBuf, fileData]));
}

async function waitFor(predicate: () => boolean, timeoutMs = 5_000, label = "condition"): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((r) => setTimeout(r, 20));
  }
  throw new Error(`Timed out waiting for ${label}`);
}

function runCliAsync(args: readonly string[]): Promise<{ status: number | null; stdout: string; stderr: string }> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, ["--experimental-strip-types", CLI_PATH, ...args], {
      stdio: ["ignore", "pipe", "pipe"],
      env: { ...process.env, NO_COLOR: "1" },
    });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => out.push(chunk));
    child.stderr.on("data", (chunk: Buffer) => err.push(chunk));
    const timer = setTimeout(() => {
      child.kill("SIGKILL");
      rejectPromise(new Error(`CLI timed out: hyp ${args.join(" ")}`));
    }, 15_000).unref();
    child.on("error", (error) => {
      clearTimeout(timer);
      rejectPromise(error);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolvePromise({
        status: code,
        stdout: Buffer.concat(out).toString("utf8"),
        stderr: Buffer.concat(err).toString("utf8"),
      });
    });
  });
}

test("identity: persistent secret-store keypairs, per-connector isolation, and key-reg mutation failures", () => {
  const dir = mkdtempSync(join(tmpdir(), "hyp-id-"));
  try {
    const first = loadOrCreateConnectorKeys(dir, "alex@laptop");
    const reloaded = loadOrCreateConnectorKeys(dir, "alex@laptop");
    const other = loadOrCreateConnectorKeys(dir, "alice@laptop");

    assert.equal(first.signingPublic, reloaded.signingPublic);
    assert.equal(first.encryptionPublic, reloaded.encryptionPublic);
    assert.equal(first.fingerprint, reloaded.fingerprint);
    assert.notEqual(first.signingPublic, other.signingPublic);
    assert.notEqual(first.encryptionPublic, other.encryptionPublic);

    // Private keys live under private 0700 secrets/ directory with 0600 file permissions
    const names = connectorKeySecretNames("alex@laptop");
    const signPath = join(dir, "secrets", `${names.signing}.secret`);
    const encPath = join(dir, "secrets", `${names.encryption}.secret`);
    assert.equal(statSync(join(dir, "secrets")).mode & 0o777, 0o700);
    assert.equal(statSync(signPath).mode & 0o777, 0o600);
    assert.equal(statSync(encPath).mode & 0o777, 0o600);

    // Valid key registration verifies
    const reg = createKeyRegistration("alex@laptop", first);
    const ok = verifyKeyRegistration("alex@laptop", reg);
    assert.equal(ok.ok, true);

    // Nearby mutations must all fail closed
    assert.equal(verifyKeyRegistration("alice@laptop", reg).ok, false, "wrong connectorId must fail");
    assert.equal(
      verifyKeyRegistration("alex@laptop", {
        ...reg,
        proof: { ...reg.proof, sig: "A".repeat(reg.proof.sig.length) },
      }).ok,
      false,
      "corrupted signature must fail",
    );
    assert.equal(
      verifyKeyRegistration("alex@laptop", {
        ...reg,
        encryptionKey: other.encryptionPublic,
      }).ok,
      false,
      "swapped encryptionKey without re-signing must fail",
    );
    assert.equal(
      verifyKeyRegistration("alex@laptop", {
        ...reg,
        signingKey: Buffer.alloc(32, 0).toString("base64url"),
      }).ok,
      false,
      "small-order Ed25519 key must fail",
    );
    assert.equal(
      verifyKeyRegistration("alex@laptop", {
        ...reg,
        encryptionKey: Buffer.alloc(32, 0).toString("base64url"),
      }).ok,
      false,
      "all-zero X25519 key must fail",
    );
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("pack: round-trip multi-file dedup + adversarial traversal, SHA-256 mismatch, and gzip bomb all fail with zero disk writes", () => {
  const dir = mkdtempSync(join(tmpdir(), "hyp-pack-"));
  try {
    const srcA = join(dir, "a");
    const srcB = join(dir, "b");
    mkdirSync(srcA, { recursive: true });
    mkdirSync(srcB, { recursive: true });

    const textBytes = Buffer.from("hello hyphae encrypted pack!\nline 2\n", "utf8");
    const binBytes = Buffer.from([0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff, 0xde, 0xad, 0xbe, 0xef]);
    const emptyBytes = Buffer.alloc(0);

    const f1 = join(srcA, "report.txt");
    const f2 = join(srcB, "report.txt"); // basename collision
    const f3 = join(srcA, "blob.bin");
    const f4 = join(srcA, "empty.dat");
    writeFileSync(f1, textBytes);
    writeFileSync(f2, Buffer.from("second report", "utf8"));
    writeFileSync(f3, binBytes);
    writeFileSync(f4, emptyBytes);

    const packed = packFiles([f1, f2, f3, f4], { fromHandle: "alex", note: "check these files" });
    assert.deepEqual(
      packed.manifest.files.map((f) => f.name),
      ["report.txt", "report-2.txt", "blob.bin", "empty.dat"],
    );

    const dest = join(dir, "out-valid");
    const unpacked = unpackFiles(packed.payload, dest);
    assert.equal(unpacked.fromHandle, "alex");
    assert.equal(unpacked.note, "check these files");
    assert.equal(unpacked.files.length, 4);
    assert.equal(statSync(dest).mode & 0o777, 0o700);
    for (const file of unpacked.files) {
      assert.equal(statSync(file.path).mode & 0o777, 0o600);
    }
    assert.equal(Buffer.compare(readFileSync(join(dest, "report.txt")), textBytes), 0);
    assert.equal(Buffer.compare(readFileSync(join(dest, "report-2.txt")), Buffer.from("second report", "utf8")), 0);
    assert.equal(Buffer.compare(readFileSync(join(dest, "blob.bin")), binBytes), 0);
    assert.equal(Buffer.compare(readFileSync(join(dest, "empty.dat")), emptyBytes), 0);

    // Invalid packFiles inputs fail closed
    assert.throws(() => packFiles([]), /at least one file/i);
    assert.throws(() => packFiles([join(dir, "nonexistent.txt")]), /not found/i);
    assert.throws(() => packFiles([srcA]), /not a regular file/i);
    assert.throws(() => packFiles([f1, f2], { maxFiles: 1 }), /too many files/i);
    assert.throws(() => packFiles([f1], { maxRawBytes: 5 }), /exceed limit/i);

    // Adversarial unpack payloads must throw and leave zero files/dirs on disk
    const hello = Buffer.from("payload", "utf8");
    const helloSha = createHash("sha256").update(hello).digest("hex");

    const badCases: Array<{ label: string; payload: Buffer; opts?: { maxRawBytes?: number } }> = [
      {
        label: "parent traversal ../escape.txt",
        payload: buildRawPack({ v: 1, files: [{ name: "../escape.txt", size: hello.length, sha256: helloSha }] }, hello),
      },
      {
        label: "absolute path /etc/passwd",
        payload: buildRawPack({ v: 1, files: [{ name: "/etc/passwd", size: hello.length, sha256: helloSha }] }, hello),
      },
      {
        label: "backslash traversal",
        payload: buildRawPack({ v: 1, files: [{ name: "..\\escape.txt", size: hello.length, sha256: helloSha }] }, hello),
      },
      {
        label: "leading dot hidden file",
        payload: buildRawPack({ v: 1, files: [{ name: ".bashrc", size: hello.length, sha256: helloSha }] }, hello),
      },
      {
        label: "null byte in name",
        payload: buildRawPack({ v: 1, files: [{ name: "a.txt\0b", size: hello.length, sha256: helloSha }] }, hello),
      },
      {
        label: "exact duplicate filename",
        payload: buildRawPack(
          {
            v: 1,
            files: [
              { name: "dup.txt", size: hello.length, sha256: helloSha },
              { name: "dup.txt", size: hello.length, sha256: helloSha },
            ],
          },
          Buffer.concat([hello, hello]),
        ),
      },
      {
        label: "case-insensitive duplicate filename",
        payload: buildRawPack(
          {
            v: 1,
            files: [
              { name: "Dup.txt", size: hello.length, sha256: helloSha },
              { name: "dup.txt", size: hello.length, sha256: helloSha },
            ],
          },
          Buffer.concat([hello, hello]),
        ),
      },
      {
        label: "SHA-256 mismatch",
        payload: buildRawPack(
          { v: 1, files: [{ name: "tampered.txt", size: hello.length, sha256: "0".repeat(64) }] },
          hello,
        ),
      },
      {
        label: "trailing bytes after declared files",
        payload: buildRawPack(
          { v: 1, files: [{ name: "ok.txt", size: hello.length, sha256: helloSha }] },
          Buffer.concat([hello, Buffer.from("extra")]),
        ),
      },
      {
        label: "wrong magic header",
        payload: buildRawPack({ v: 1, files: [{ name: "ok.txt", size: hello.length, sha256: helloSha }] }, hello, "HYP9"),
      },
      {
        label: "gzip bomb exceeding maxRawBytes",
        payload: gzipSync(Buffer.alloc(4 * 1024 * 1024, 0x41)),
        opts: { maxRawBytes: 64 * 1024 },
      },
    ];

    for (let i = 0; i < badCases.length; i += 1) {
      const tc = badCases[i]!;
      const badDest = join(dir, `bad-dest-${i}`);
      assert.throws(() => unpackFiles(tc.payload, badDest, tc.opts), `Expected unpackFiles to reject: ${tc.label}`);
      assert.equal(existsSync(badDest), false, `Failed unpack (${tc.label}) must not create destDir or leave files`);
      assert.equal(existsSync(join(dir, "escape.txt")), false, `Traversal (${tc.label}) escaped destDir!`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("E2E encrypted file transfer: zero-knowledge router, immediate SSE delivery, byte-exact 0600/0700 extraction, and blob deletion on ack", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hyp-xfer-e2e-"));
  const dbPath = join(dir, "router.sqlite");
  const transferDir = join(dir, "router-transfers");
  const routerCore = new RouterCore({ dbPath, transferDir });
  const alexToken = routerCore.addConnector("alex@laptop");
  const aliceToken = routerCore.addConnector("alice@laptop");
  const router = await serveRouter({ core: routerCore, host: "127.0.0.1", port: 0 });

  const alexDir = join(dir, "alex");
  const aliceDir = join(dir, "alice");
  mkdirSync(alexDir, { mode: 0o700, recursive: true });
  mkdirSync(aliceDir, { mode: 0o700, recursive: true });

  // Prepare source files with unique secret markers
  const secretMarkerA = "TOP_SECRET_FILE_ALPHA_948271_DO_NOT_LEAK_TO_ROUTER";
  const secretNote = "TOP_SECRET_NOTE_739182_ENCRYPTED_END_TO_END";
  const binaryPayload = Buffer.concat([
    Buffer.from("BIN_HEADER_001", "utf8"),
    randomBytes(4096),
    Buffer.from([0x00, 0xff, 0x13, 0x37]),
  ]);
  const srcDir = join(dir, "src-files");
  mkdirSync(srcDir, { recursive: true });
  const fileA = join(srcDir, "secret-design.md");
  const fileB = join(srcDir, "trace.bin");
  writeFileSync(fileA, `${secretMarkerA}\nbody line\n`, "utf8");
  writeFileSync(fileB, binaryPayload);

  // Start Alex's daemon first (Alice is NOT connected yet, and has not registered keys yet)
  const alexDaemon = await startDaemon(
    {
      connectorId: "alex@laptop",
      configDir: alexDir,
      directory: join(alexDir, "state"),
      routers: [{ name: "primary", url: router.url, token: alexToken }],
    },
    { quiet: true },
  );

  let aliceDaemon: Awaited<ReturnType<typeof startDaemon>> | undefined;
  try {
    alexDaemon.state.register("claude:alex", { kind: "claude" });

    // Unenrolled session cannot send files
    await assert.rejects(
      () => alexDaemon.connector.call("claude:alex", "hyp_send", { to: "alice@laptop/alice", files: [fileA] }),
      (err: unknown) => err instanceof RouterError && err.code === "not_enrolled",
    );

    await alexDaemon.connector.call("claude:alex", "hyp_join", { handle: "alex" });

    // Input validation mutations fail closed
    await assert.rejects(
      () => alexDaemon.connector.call("claude:alex", "hyp_send", { to: "#incidents", files: [fileA] }),
      (err: unknown) => err instanceof RouterError && err.code === "invalid",
    );
    await assert.rejects(
      () => alexDaemon.connector.call("claude:alex", "hyp_send", { to: "slack:ops", files: [fileA] }),
      (err: unknown) => err instanceof RouterError && err.code === "invalid",
    );
    await assert.rejects(
      () => alexDaemon.connector.call("claude:alex", "hyp_send", { to: "alice@laptop/alice", files: [] }),
      (err: unknown) => err instanceof RouterError && err.code === "invalid",
    );
    await assert.rejects(
      () => alexDaemon.connector.call("claude:alex", "hyp_send", { to: "alice@laptop/alice", files: ["relative.txt"] }),
      (err: unknown) => err instanceof RouterError && err.code === "invalid",
    );

    // Recipient without registered keys fails closed with recipient_keys_unavailable
    await assert.rejects(
      () => alexDaemon.connector.call("claude:alex", "hyp_send", { to: "alice@laptop/alice", files: [fileA] }),
      (err: unknown) => err instanceof RouterError && err.code === "recipient_keys_unavailable",
    );

    // Pre-create Alice's keys and pre-register them + pre-seed Alice's handle in her state.sqlite
    // while Alice's daemon is OFFLINE so we can inspect the pending transfer at rest on the router!
    const aliceKeys = loadOrCreateConnectorKeys(join(aliceDir, "state"), "alice@laptop");
    const regRes = await fetch(`${router.url}/v1/keys`, {
      method: "PUT",
      headers: { authorization: `Bearer ${aliceToken}`, "content-type": "application/json" },
      body: JSON.stringify(createKeyRegistration("alice@laptop", aliceKeys)),
    });
    assert.equal(regRes.status, 200);

    mkdirSync(join(aliceDir, "state"), { mode: 0o700, recursive: true });
    const preState = new State(
      join(aliceDir, "state", "state.sqlite"),
      JSON.stringify(["alice@laptop", "multi-session-v1"]),
    );
    preState.register("claude:alice", { kind: "claude" });
    preState.setHandle("claude:alice", "alice");
    preState.close();

    // Send encrypted 2-file transfer while Alice is offline
    const sendRes = (await alexDaemon.connector.call("claude:alex", "hyp_send", {
      to: "alice@laptop/alice",
      files: [fileA, fileB],
      text: secretNote,
    })) as {
      transferId: string;
      status: string;
      encrypted: boolean;
      to: string;
      files: Array<{ name: string; size: number; sha256: string }>;
      ciphertextBytes: number;
      recipientFingerprint: string;
    };

    assert.equal(sendRes.status, "stored");
    assert.equal(sendRes.encrypted, true);
    assert.equal(sendRes.to, "alice@laptop/alice");
    assert.equal(sendRes.files.length, 2);
    assert.equal(sendRes.recipientFingerprint, fingerprint(aliceKeys.encryptionPublic));

    // ZERO-KNOWLEDGE ROUTER ASSERTION: inspect ciphertext blob + router.sqlite + WAL while pending!
    const routerBlobPath = join(transferDir, sendRes.transferId);
    assert.equal(existsSync(routerBlobPath), true, "Pending transfer ciphertext file must exist on router disk");
    const ciphertextOnDisk = readFileSync(routerBlobPath);
    assert.equal(ciphertextOnDisk.length, sendRes.ciphertextBytes);

    const dbBytes = Buffer.concat([
      readFileSync(dbPath),
      ...(existsSync(`${dbPath}-wal`) ? [readFileSync(`${dbPath}-wal`)] : []),
    ]);
    for (const secret of [secretMarkerA, secretNote, "secret-design.md", "trace.bin", "BIN_HEADER_001"]) {
      assert.equal(
        ciphertextOnDisk.includes(Buffer.from(secret, "utf8")),
        false,
        `Router ciphertext leaked plaintext token: ${secret}`,
      );
      assert.equal(
        dbBytes.includes(Buffer.from(secret, "utf8")),
        false,
        `Router SQLite leaked plaintext token: ${secret}`,
      );
    }

    // Now bring Alice's daemon online — it should automatically fetch, verify, decrypt, unpack, deliver, and ack!
    aliceDaemon = await startDaemon(
      {
        connectorId: "alice@laptop",
        configDir: aliceDir,
        directory: join(aliceDir, "state"),
        routers: [{ name: "primary", url: router.url, token: aliceToken }],
      },
      { quiet: true },
    );

    await waitFor(() => aliceDaemon!.state.pendingCount("claude:alice") >= 1, 5_000, "Alice receives E2EE files");

    // Router must have deleted the ciphertext file immediately after `delivered` ack!
    await waitFor(() => !existsSync(routerBlobPath), 3_000, "Router deletes acked ciphertext blob");

    const inbox = (await aliceDaemon.connector.call("claude:alice", "hyp_inbox", { ack: true })) as {
      unread: number;
      items: Array<{ text: string; source?: string }>;
    };
    assert.equal(inbox.items.length, 1);
    const notice = inbox.items[0]!.text;
    assert.match(notice, /hyphae files from alex@laptop\/alex/);
    assert.ok(notice.includes(`transfer ${sendRes.transferId}`));
    assert.ok(notice.includes("2 files"));
    assert.ok(notice.includes("E2EE verified"));
    assert.ok(notice.includes("secret-design.md"));
    assert.ok(notice.includes("trace.bin"));
    assert.ok(notice.includes(UNTRUSTED_PROVENANCE));
    assert.ok(notice.includes(secretNote));
    assert.equal(notice.includes(secretMarkerA), false, "Raw file contents must NEVER be dumped into agent prompt!");

    const savedDir = join(aliceDir, "state", "transfers", "inbox", sendRes.transferId);
    assert.ok(notice.includes(`saved to: ${savedDir}`));
    assert.equal(statSync(savedDir).mode & 0o777, 0o700);
    assert.equal(statSync(join(savedDir, "secret-design.md")).mode & 0o777, 0o600);
    assert.equal(statSync(join(savedDir, "trace.bin")).mode & 0o777, 0o600);
    assert.equal(Buffer.compare(readFileSync(join(savedDir, "secret-design.md")), readFileSync(fileA)), 0);
    assert.equal(Buffer.compare(readFileSync(join(savedDir, "trace.bin")), binaryPayload), 0);

    // LIVE IMMEDIATE SSE PUSH TEST (must arrive well under the 1000ms router tick!)
    const startMs = Date.now();
    const liveSend = (await alexDaemon.connector.call("claude:alex", "hyp_send", {
      to: "alice@laptop/alice",
      files: [fileA],
    })) as { transferId: string };
    await waitFor(() => aliceDaemon!.state.pendingCount("claude:alice") >= 1, 2_000, "Live immediate SSE transfer");
    const elapsedMs = Date.now() - startMs;
    assert.ok(elapsedMs < 800, `Expected immediate SSE push (<800ms, before 1s tick), took ${elapsedMs}ms`);
    await aliceDaemon.connector.call("claude:alice", "hyp_inbox", { ack: true });
    assert.equal(existsSync(join(transferDir, liveSend.transferId)), false);
    // Revoking a connector clears its registered keys on the router
    assert.equal(routerCore.connectorKeys().some((k) => k.connectorId === "alice@laptop"), true);
    assert.equal(routerCore.revokeConnector("alice@laptop"), true);
    assert.equal(routerCore.connectorKeys().some((k) => k.connectorId === "alice@laptop"), false);
  } finally {
    await aliceDaemon?.stop();
    await alexDaemon.stop();
    await router.close();
    routerCore.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("security mutations: tampered ciphertext on router and rogue/tampered header signatures fail closed with 0 files extracted", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hyp-xfer-mut-"));
  const dbPath = join(dir, "router.sqlite");
  const transferDir = join(dir, "router-transfers");
  const routerCore = new RouterCore({ dbPath, transferDir });
  const alexToken = routerCore.addConnector("alex@laptop");
  const aliceToken = routerCore.addConnector("alice@laptop");
  const router = await serveRouter({ core: routerCore, host: "127.0.0.1", port: 0 });

  const alexDir = join(dir, "alex");
  const aliceDir = join(dir, "alice");
  mkdirSync(alexDir, { mode: 0o700, recursive: true });
  mkdirSync(aliceDir, { mode: 0o700, recursive: true });

  const sampleFile = join(dir, "payload.txt");
  writeFileSync(sampleFile, "integrity-checked-secret-data", "utf8");

  const alexKeys = loadOrCreateConnectorKeys(join(alexDir, "state"), "alex@laptop");
  const aliceKeys = loadOrCreateConnectorKeys(join(aliceDir, "state"), "alice@laptop");

  // Register both keys on the router
  for (const [id, tok, keys] of [
    ["alex@laptop", alexToken, alexKeys],
    ["alice@laptop", aliceToken, aliceKeys],
  ] as const) {
    const res = await fetch(`${router.url}/v1/keys`, {
      method: "PUT",
      headers: { authorization: `Bearer ${tok}`, "content-type": "application/json" },
      body: JSON.stringify(createKeyRegistration(id, keys)),
    });
    assert.equal(res.status, 200);
  }

  let aliceDaemon: Awaited<ReturnType<typeof startDaemon>> | undefined;
  try {
    const packed = packFiles([sampleFile], { fromHandle: "alex" });

    // Mutation 1: Signed with a rogue Ed25519 key -> router rejects 401 unauthorized AND open() rejects bad_signature
    const rogueSigning = generatePrivateKey("ed25519");
    const rogueId = randomUUID();
    const rogueSealed = sealTransfer(
      { id: rogueId, type: "files", from: "alex@laptop", to: "alice@laptop", toHandle: "alice", ttlMs: 60_000 },
      packed.payload,
      rogueSigning,
      aliceKeys.encryptionPublic,
    );
    const roguePut = await fetch(`${router.url}/v1/transfers/${rogueId}`, {
      method: "PUT",
      headers: {
        authorization: `Bearer ${alexToken}`,
        "hyphae-transfer": encodeTransferHeader(rogueSealed.header),
        "content-type": "application/octet-stream",
      },
      body: new Uint8Array(rogueSealed.ciphertext),
    });
    assert.equal(roguePut.status, 401);
    assert.throws(
      () => openTransfer(rogueSealed.header, rogueSealed.ciphertext, publicKeyFromRaw(alexKeys.signingPublic, "ed25519"), aliceKeys.encryptionKey),
      (err: unknown) => err instanceof OpenError && err.reason === "bad_signature",
    );

    // Mutation 2: Valid upload, then flip 1 byte in stored ciphertext on router disk BEFORE Alice downloads
    const validId = randomUUID();
    const validSealed = sealTransfer(
      { id: validId, type: "files", from: "alex@laptop", to: "alice@laptop", toHandle: "alice", ttlMs: 60_000 },
      packed.payload,
      alexKeys.signingKey,
      aliceKeys.encryptionPublic,
    );

    // Tampered header signature byte -> 401
    const badSigPut = await fetch(`${router.url}/v1/transfers/${validId}`, {
      method: "PUT",
      headers: {
        authorization: `Bearer ${alexToken}`,
        "hyphae-transfer": encodeTransferHeader({
          payload: validSealed.header.payload,
          sig: `${validSealed.header.sig.slice(0, -1)}${validSealed.header.sig.endsWith("A") ? "B" : "A"}`,
        }),
        "content-type": "application/octet-stream",
      },
      body: new Uint8Array(validSealed.ciphertext),
    });
    assert.equal(badSigPut.status, 401);

    // Store valid transfer while Alice is offline
    const okPut = await fetch(`${router.url}/v1/transfers/${validId}`, {
      method: "PUT",
      headers: {
        authorization: `Bearer ${alexToken}`,
        "hyphae-transfer": encodeTransferHeader(validSealed.header),
        "content-type": "application/octet-stream",
      },
      body: new Uint8Array(validSealed.ciphertext),
    });
    assert.equal(okPut.status, 200);

    // Flip 1 byte in stored ciphertext on router disk (simulating compromised/corrupt router storage!)
    const blobPath = join(transferDir, validId);
    const tampered = Buffer.from(readFileSync(blobPath));
    tampered[Math.floor(tampered.length / 2)] ^= 0x01;
    writeFileSync(blobPath, tampered, { mode: 0o600 });

    // Pre-seed Alice's handle and start Alice's daemon
    mkdirSync(join(aliceDir, "state"), { mode: 0o700, recursive: true });
    const preState = new State(
      join(aliceDir, "state", "state.sqlite"),
      JSON.stringify(["alice@laptop", "multi-session-v1"]),
    );
    preState.register("claude:alice", { kind: "claude" });
    preState.setHandle("claude:alice", "alice");
    preState.close();

    aliceDaemon = await startDaemon(
      {
        connectorId: "alice@laptop",
        configDir: aliceDir,
        directory: join(aliceDir, "state"),
        routers: [{ name: "primary", url: router.url, token: aliceToken }],
      },
      { quiet: true },
    );

    // Wait for router to mark transfer rejected with reason 'corrupt'
    const inspectDb = new DatabaseSync(dbPath, { readOnly: true });
    try {
      await waitFor(() => {
        const row = inspectDb.prepare("SELECT state, reason FROM transfers WHERE id = ?").get(validId) as
          | { state?: string; reason?: string }
          | undefined;
        return row?.state === "rejected" && row?.reason === "corrupt";
      }, 5_000, "corrupt transfer rejection");
    } finally {
      inspectDb.close();
    }

    assert.equal(aliceDaemon.state.pendingCount("claude:alice"), 0, "Corrupt transfer must deliver 0 inbox items");
    assert.equal(existsSync(join(aliceDir, "state", "transfers", "inbox", validId)), false, "Corrupt transfer must write 0 files");
    assert.equal(existsSync(blobPath), false, "Router must delete rejected transfer blob");
  } finally {
    await aliceDaemon?.stop();
    await router.close();
    routerCore.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("paired (--admin-key) router strictly enforces admin-signed grants and file scopes; PUT /v1/keys cannot bypass pairing", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hyp-xfer-paired-"));
  const adminKey = generatePrivateKey("ed25519");
  const routerCore = new RouterCore({
    dbPath: join(dir, "router.sqlite"),
    adminKey: rawPublicKey(adminKey),
  });
  const router = await serveRouter({ core: routerCore, host: "127.0.0.1", port: 0 });

  async function pairConnector(connectorId: string, scopes: readonly string[]) {
    const signingKey = generatePrivateKey("ed25519");
    const encryptionKey = generatePrivateKey("x25519");
    const issued = issueGrant(adminKey, connectorId, scopes, 60_000);
    const grantRes = await fetch(`${router.url}/v1/grants`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(issued.signed),
    });
    assert.equal(grantRes.status, 200);
    const code = parsePairingCode(issued.code)!;
    const binding = signBinding(issued.grant, code, signingKey, encryptionKey);
    const pairRes = await fetch(`${router.url}/v1/pairing/${issued.grant.id}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ binding }),
    });
    assert.equal(pairRes.status, 200);
    const body = (await pairRes.json()) as { token: string };
    return {
      connectorId,
      token: body.token,
      signingKey,
      encryptionKey,
      signingPublic: rawPublicKey(signingKey),
      encryptionPublic: rawPublicKey(encryptionKey),
    };
  }

  try {
    const sender = await pairConnector("sender@paired", ["messages:*", "files:send"]);
    const receiver = await pairConnector("recv@paired", ["messages:*", "files:receive"]);
    const msgOnly = await pairConnector("msgonly@paired", ["messages:*"]);
    const rogueToken = routerCore.addConnector("rogue@unpaired");

    // Unpaired rogue connector registers keys via PUT /v1/keys
    const rogueKeys = loadOrCreateConnectorKeys(join(dir, "rogue"), "rogue@unpaired");
    const rogueReg = await fetch(`${router.url}/v1/keys`, {
      method: "PUT",
      headers: { authorization: `Bearer ${rogueToken}`, "content-type": "application/json" },
      body: JSON.stringify(createKeyRegistration("rogue@unpaired", rogueKeys)),
    });
    assert.equal(rogueReg.status, 200);

    // Paired sender tries to override its keys via PUT /v1/keys — GET /v1/keys must still prefer paired keys!
    const fakeKeys = loadOrCreateConnectorKeys(join(dir, "fake"), "sender@paired");
    await fetch(`${router.url}/v1/keys`, {
      method: "PUT",
      headers: { authorization: `Bearer ${sender.token}`, "content-type": "application/json" },
      body: JSON.stringify(createKeyRegistration("sender@paired", fakeKeys)),
    });
    const keysRes = (await (await fetch(`${router.url}/v1/keys`, {
      headers: { authorization: `Bearer ${sender.token}` },
    })).json()) as { keys: Array<{ connectorId: string; signingKey: string; encryptionKey: string; source: string }> };
    const senderKeyEntry = keysRes.keys.find((k) => k.connectorId === "sender@paired");
    assert.ok(senderKeyEntry);
    assert.equal(senderKeyEntry.source, "paired");
    assert.equal(senderKeyEntry.signingKey, sender.signingPublic);
    assert.equal(senderKeyEntry.encryptionKey, sender.encryptionPublic);

    const payload = Buffer.from("paired-transfer-bytes", "utf8");

    // 1. Unpaired rogue connector CANNOT send transfers even after PUT /v1/keys -> 403 not_granted
    const rogueTransferId = randomUUID();
    const rogueSealed = sealTransfer(
      { id: rogueTransferId, type: "files", from: "rogue@unpaired", to: "recv@paired", toHandle: "bob", ttlMs: 60_000 },
      payload,
      rogueKeys.signingKey,
      receiver.encryptionPublic,
    );
    const rogueSend = await fetch(`${router.url}/v1/transfers/${rogueTransferId}`, {
      method: "PUT",
      headers: {
        authorization: `Bearer ${rogueToken}`,
        "hyphae-transfer": encodeTransferHeader(rogueSealed.header),
      },
      body: new Uint8Array(rogueSealed.ciphertext),
    });
    assert.equal(rogueSend.status, 403, "Unpaired connector must not bypass pairing via PUT /v1/keys");

    // 2. Paired sender CANNOT send to unpaired rogue connector -> 404 unknown_recipient
    const toRogueId = randomUUID();
    const toRogueSealed = sealTransfer(
      { id: toRogueId, type: "files", from: "sender@paired", to: "rogue@unpaired", toHandle: "r", ttlMs: 60_000 },
      payload,
      sender.signingKey,
      rogueKeys.encryptionPublic,
    );
    const toRogueSend = await fetch(`${router.url}/v1/transfers/${toRogueId}`, {
      method: "PUT",
      headers: {
        authorization: `Bearer ${sender.token}`,
        "hyphae-transfer": encodeTransferHeader(toRogueSealed.header),
      },
      body: new Uint8Array(toRogueSealed.ciphertext),
    });
    assert.equal(toRogueSend.status, 404, "Paired router must refuse transfers to unpaired connector");

    // 3. Paired sender signing with non-paired PUT /v1/keys key -> 401 unauthorized
    const fakeId = randomUUID();
    const fakeSealed = sealTransfer(
      { id: fakeId, type: "files", from: "sender@paired", to: "recv@paired", toHandle: "bob", ttlMs: 60_000 },
      payload,
      fakeKeys.signingKey,
      receiver.encryptionPublic,
    );
    const fakeSend = await fetch(`${router.url}/v1/transfers/${fakeId}`, {
      method: "PUT",
      headers: {
        authorization: `Bearer ${sender.token}`,
        "hyphae-transfer": encodeTransferHeader(fakeSealed.header),
      },
      body: new Uint8Array(fakeSealed.ciphertext),
    });
    assert.equal(fakeSend.status, 401, "Paired sender cannot sign transfers with self-registered key");

    // 4. Paired connector without files:receive scope -> 403 not_granted
    const noScopeId = randomUUID();
    const noScopeSealed = sealTransfer(
      { id: noScopeId, type: "files", from: "sender@paired", to: "msgonly@paired", toHandle: "m", ttlMs: 60_000 },
      payload,
      sender.signingKey,
      msgOnly.encryptionPublic,
    );
    const noScopeSend = await fetch(`${router.url}/v1/transfers/${noScopeId}`, {
      method: "PUT",
      headers: {
        authorization: `Bearer ${sender.token}`,
        "hyphae-transfer": encodeTransferHeader(noScopeSealed.header),
      },
      body: new Uint8Array(noScopeSealed.ciphertext),
    });
    assert.equal(noScopeSend.status, 403, "Recipient without files:receive scope must be refused");

    // 5. Valid paired transfer with matching files:send + files:receive scopes succeeds!
    const okId = randomUUID();
    const okSealed = sealTransfer(
      { id: okId, type: "files", from: "sender@paired", to: "recv@paired", toHandle: "bob", ttlMs: 60_000 },
      payload,
      sender.signingKey,
      receiver.encryptionPublic,
    );
    const okSend = await fetch(`${router.url}/v1/transfers/${okId}`, {
      method: "PUT",
      headers: {
        authorization: `Bearer ${sender.token}`,
        "hyphae-transfer": encodeTransferHeader(okSealed.header),
      },
      body: new Uint8Array(okSealed.ciphertext),
    });
    assert.equal(okSend.status, 200);
  } finally {
    await router.close();
    routerCore.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("mute rules (connector wildcard & exact handle) and notify mode work with inbound encrypted file transfers", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hyp-xfer-mute-"));
  const dbPath = join(dir, "router.sqlite");
  const transferDir = join(dir, "router-transfers");
  const routerCore = new RouterCore({ dbPath, transferDir });
  const alexToken = routerCore.addConnector("alex@laptop");
  const aliceToken = routerCore.addConnector("alice@laptop");
  const router = await serveRouter({ core: routerCore, host: "127.0.0.1", port: 0 });

  const alexDir = join(dir, "alex");
  const aliceDir = join(dir, "alice");
  mkdirSync(alexDir, { mode: 0o700, recursive: true });
  mkdirSync(aliceDir, { mode: 0o700, recursive: true });

  const file = join(dir, "notes.txt");
  writeFileSync(file, "sensitive-notify-body-12345", "utf8");

  const alexDaemon = await startDaemon(
    {
      connectorId: "alex@laptop",
      configDir: alexDir,
      directory: join(alexDir, "state"),
      routers: [{ name: "primary", url: router.url, token: alexToken }],
    },
    { quiet: true },
  );
  const aliceDaemon = await startDaemon(
    {
      connectorId: "alice@laptop",
      configDir: aliceDir,
      directory: join(aliceDir, "state"),
      routers: [{ name: "primary", url: router.url, token: aliceToken }],
    },
    { quiet: true },
  );

  try {
    alexDaemon.state.register("claude:alex", { kind: "claude" });
    aliceDaemon.state.register("claude:alice", { kind: "claude" });
    await alexDaemon.connector.call("claude:alex", "hyp_join", { handle: "alex" });
    await aliceDaemon.connector.call("claude:alice", "hyp_join", { handle: "alice" });
    await waitFor(() => routerCore.connectorKeys().length === 2, 3_000, "both keys registered");

    // 1. Connector-wildcard mute (`alex@laptop/*`) drops inbound transfer without writing files
    await aliceDaemon.connector.call("claude:alice", "hyp_mute", { target: "alex@laptop/*", scope: "session" });
    const muted1 = (await alexDaemon.connector.call("claude:alex", "hyp_send", {
      to: "alice@laptop/alice",
      files: [file],
    })) as { transferId: string };
    await waitFor(() => !existsSync(join(transferDir, muted1.transferId)), 3_000, "muted transfer settled");
    assert.equal(aliceDaemon.state.pendingCount("claude:alice"), 0);
    assert.equal(existsSync(join(aliceDir, "state", "transfers", "inbox", muted1.transferId)), false);

    // 2. Exact peer handle mute (`alex@laptop/alex`) drops inbound transfer and cleans up extracted files
    await aliceDaemon.connector.call("claude:alice", "hyp_unmute", { target: "alex@laptop/*", scope: "session" });
    await aliceDaemon.connector.call("claude:alice", "hyp_mute", { target: "alex@laptop/alex", scope: "session" });
    const muted2 = (await alexDaemon.connector.call("claude:alex", "hyp_send", {
      to: "alice@laptop/alice",
      files: [file],
    })) as { transferId: string };
    await waitFor(() => !existsSync(join(transferDir, muted2.transferId)), 3_000, "handle-muted transfer settled");
    assert.equal(aliceDaemon.state.pendingCount("claude:alice"), 0);
    assert.equal(existsSync(join(aliceDir, "state", "transfers", "inbox", muted2.transferId)), false);

    // 3. Unmute & switch to `notify` delivery mode: push drain returns slim digest, hyp_inbox returns full file notice
    await aliceDaemon.connector.call("claude:alice", "hyp_unmute", { target: "alex@laptop/alex", scope: "session" });
    await aliceDaemon.connector.call("claude:alice", "hyp_mode", { mode: "notify" });
    const notifySend = (await alexDaemon.connector.call("claude:alex", "hyp_send", {
      to: "alice@laptop/alice",
      files: [file],
      text: "review in notify mode",
    })) as { transferId: string };
    await waitFor(() => aliceDaemon.state.pendingCount("claude:alice") === 1, 3_000, "notify transfer buffered");

    const pushed = aliceDaemon.connector.drainForPush("claude:alice", 10);
    assert.equal(pushed.length, 1);
    assert.match(pushed[0]!.text, /hyphae notice · 1 unread \(1 message\) · from alex@laptop\/alex · call hyp_inbox to read/);
    assert.equal(pushed[0]!.text.includes("review in notify mode"), false);

    const fullInbox = (await aliceDaemon.connector.call("claude:alice", "hyp_inbox", { ack: true })) as {
      items: Array<{ text: string }>;
    };
    assert.equal(fullInbox.items.length, 1);
    assert.ok(fullInbox.items[0]!.text.includes("E2EE verified"));
    assert.ok(fullInbox.items[0]!.text.includes("review in notify mode"));
    const saved = join(aliceDir, "state", "transfers", "inbox", notifySend.transferId, "notes.txt");
    assert.equal(readFileSync(saved, "utf8"), "sensitive-notify-body-12345");
  } finally {
    await aliceDaemon.stop();
    await alexDaemon.stop();
    await router.close();
    routerCore.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("CLI `hyp send-files`: works via running daemon, standalone fallback, and exits 2 on usage errors", async () => {
  const dir = mkdtempSync(join(tmpdir(), "hyp-xfer-cli-"));
  const routerCore = new RouterCore({ dbPath: join(dir, "router.sqlite") });
  const alexToken = routerCore.addConnector("alex@laptop");
  const aliceToken = routerCore.addConnector("alice@laptop");
  const router = await serveRouter({ core: routerCore, host: "127.0.0.1", port: 0 });

  const alexDir = join(dir, "alex");
  const aliceDir = join(dir, "alice");
  mkdirSync(alexDir, { mode: 0o700, recursive: true });
  mkdirSync(aliceDir, { mode: 0o700, recursive: true });

  const alexTokenFile = join(alexDir, "router.token");
  writeFileSync(alexTokenFile, `${alexToken}\n`, { mode: 0o600 });
  const alexCfgPath = join(alexDir, "connector.json");
  writeFileSync(
    alexCfgPath,
    JSON.stringify({
      connectorId: "alex@laptop",
      stateDir: "state",
      routers: [{ name: "primary", url: router.url, tokenFile: "router.token" }],
    }),
    { mode: 0o600 },
  );

  const file1 = join(dir, "cli-one.txt");
  const file2 = join(dir, "cli-two.bin");
  writeFileSync(file1, "sent via hyp send-files CLI", "utf8");
  writeFileSync(file2, Buffer.from([1, 2, 3, 4, 5]));

  const alexDaemon = await startDaemon(
    {
      connectorId: "alex@laptop",
      configDir: alexDir,
      directory: join(alexDir, "state"),
      routers: [{ name: "primary", url: router.url, token: alexToken }],
    },
    { quiet: true },
  );
  const aliceDaemon = await startDaemon(
    {
      connectorId: "alice@laptop",
      configDir: aliceDir,
      directory: join(aliceDir, "state"),
      routers: [{ name: "primary", url: router.url, token: aliceToken }],
    },
    { quiet: true },
  );

  let alexStopped = false;
  try {
    aliceDaemon.state.register("claude:alice", { kind: "claude" });
    await aliceDaemon.connector.call("claude:alice", "hyp_join", { handle: "alice" });
    await waitFor(() => routerCore.connectorKeys().length === 2, 3_000, "keys registered for CLI test");

    // 1. Usage error -> exit code 2
    const badUsage = await runCliAsync(["send-files", "#channel", file1, "--json"]);
    assert.equal(badUsage.status, 2);
    assert.equal(JSON.parse(badUsage.stdout).error.code, "USAGE_ERROR");

    // 2. Via running daemon IPC
    const viaDaemon = await runCliAsync([
      "send-files",
      "alice@laptop/alice",
      file1,
      file2,
      "--note",
      "from-daemon-cli",
      "--from",
      "cli-user",
      "--socket",
      alexDaemon.socketPath,
      "--json",
    ]);
    assert.equal(viaDaemon.status, 0, `daemon send-files failed: ${viaDaemon.stderr}\n${viaDaemon.stdout}`);
    const daemonJson = JSON.parse(viaDaemon.stdout) as {
      ok: boolean;
      command: string;
      data: { transferId: string; encrypted: boolean; via: string; files: Array<{ name: string }> };
    };
    assert.equal(daemonJson.ok, true);
    assert.equal(daemonJson.command, "send-files");
    assert.equal(daemonJson.data.encrypted, true);
    assert.equal(daemonJson.data.via, "daemon");
    assert.equal(daemonJson.data.files.length, 2);

    await waitFor(() => aliceDaemon.state.pendingCount("claude:alice") === 1, 3_000, "CLI daemon transfer received");
    const inbox1 = (await aliceDaemon.connector.call("claude:alice", "hyp_inbox", { ack: true })) as {
      items: Array<{ text: string }>;
    };
    assert.ok(inbox1.items[0]!.text.includes("alex@laptop/cli-user"));
    assert.ok(inbox1.items[0]!.text.includes("from-daemon-cli"));
    const savedDir1 = join(aliceDir, "state", "transfers", "inbox", daemonJson.data.transferId);
    assert.deepEqual(readdirSync(savedDir1).sort(), ["cli-one.txt", "cli-two.bin"]);
    assert.equal(readFileSync(join(savedDir1, "cli-one.txt"), "utf8"), "sent via hyp send-files CLI");

    // 3. Standalone fallback when daemon is stopped
    await alexDaemon.stop();
    alexStopped = true;
    const standalone = await runCliAsync([
      "send-files",
      "alice@laptop/alice",
      file1,
      "--config",
      alexCfgPath,
      "--socket",
      join(dir, "missing.sock"),
      "--note",
      "from-standalone-cli",
      "--json",
    ]);
    assert.equal(standalone.status, 0, `standalone send-files failed: ${standalone.stderr}\n${standalone.stdout}`);
    const standaloneJson = JSON.parse(standalone.stdout) as {
      ok: boolean;
      data: { transferId: string; encrypted: boolean; via: string };
    };
    assert.equal(standaloneJson.ok, true);
    assert.equal(standaloneJson.data.encrypted, true);
    assert.equal(standaloneJson.data.via, "standalone");

    await waitFor(() => aliceDaemon.state.pendingCount("claude:alice") === 1, 3_000, "CLI standalone transfer received");
    const inbox2 = (await aliceDaemon.connector.call("claude:alice", "hyp_inbox", { ack: true })) as {
      items: Array<{ text: string }>;
    };
    assert.ok(inbox2.items[0]!.text.includes("from-standalone-cli"));
    const savedDir2 = join(aliceDir, "state", "transfers", "inbox", standaloneJson.data.transferId);
    assert.equal(readFileSync(join(savedDir2, "cli-one.txt"), "utf8"), "sent via hyp send-files CLI");
  } finally {
    await aliceDaemon.stop();
    if (!alexStopped) await alexDaemon.stop();
    await router.close();
    routerCore.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
