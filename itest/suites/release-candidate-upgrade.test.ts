import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { once } from "node:events";
import fs from "node:fs";
import { createServer } from "node:http";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { HypCli } from "../lib/hyp-cli.ts";
import { REPO_ROOT, withSandbox } from "../lib/sandbox.ts";
import { waitForCondition } from "../lib/util.ts";

const runFile = promisify(execFile);

function archiveName(tag: string) {
  assert.match(tag, /^v[0-9A-Za-z._+-]+$/);
  const arch = process.arch === "arm64" ? "aarch64" : "x86_64";
  const os = process.platform === "darwin" ? "apple-darwin" : "unknown-linux-gnu";
  return `hyp-${tag}-${arch}-${os}.tar.gz`;
}

function sha256(bytes: Buffer) {
  return createHash("sha256").update(bytes).digest("hex");
}

async function readArchive(directory: string, name: string) {
  const archive = path.join(directory, name);
  const bytes = fs.readFileSync(archive);
  const sums = fs.readFileSync(path.join(directory, "SHA256SUMS.txt"), "utf8");
  const digest = sums.split("\n")
    .find((line) => line.slice(66) === name)?.slice(0, 64);
  assert.equal(sha256(bytes), digest, `${name} must match published checksum`);
  const { stdout: binary } = await runFile("tar", ["-xOf", archive, "hyp"], {
    encoding: "buffer",
    maxBuffer: 128 * 1024 * 1024,
    timeout: 30_000,
  });
  return { binary, bytes, sums };
}

async function readNodeStatus(cli: HypCli, pid: number) {
  const statusPath = path.join(cli.sandbox.paths.hyphaeStateDir, "node.status.json");
  const readStatus = (): unknown => JSON.parse(fs.readFileSync(statusPath, "utf8"));
  const belongsToDaemon = (status: unknown): status is Record<string, unknown> =>
    typeof status === "object" && status !== null && "pid" in status && status.pid === pid;
  await waitForCondition(
    () => fs.existsSync(statusPath) && belongsToDaemon(readStatus()),
    10_000,
    "current daemon status",
  );
  const status = readStatus();
  assert.ok(belongsToDaemon(status));
  return status;
}

test("candidate installer preserves identity and delivery to the existing paired release", {
  timeout: 120_000,
}, async () => {
  const { PREVIOUS_RELEASE_TAG, PREVIOUS_RELEASE_DIR, CANDIDATE_TAG, CANDIDATE_DIR } = process.env;
  assert.ok(PREVIOUS_RELEASE_TAG && PREVIOUS_RELEASE_DIR && CANDIDATE_TAG && CANDIDATE_DIR,
    "set PREVIOUS_RELEASE_TAG, PREVIOUS_RELEASE_DIR, CANDIDATE_TAG, and CANDIDATE_DIR");
  assert.ok(process.platform === "linux" || process.platform === "darwin");
  assert.ok(process.arch === "x64" || process.arch === "arm64");

  const candidateName = archiveName(CANDIDATE_TAG);
  const previous = await readArchive(PREVIOUS_RELEASE_DIR, archiveName(PREVIOUS_RELEASE_TAG));
  const candidate = await readArchive(CANDIDATE_DIR, candidateName);
  const server = createServer((request, response) => {
    if (request.url === `/candidate/${candidateName}`) {
      response.end(candidate.bytes);
    } else if (request.url === "/candidate/SHA256SUMS.txt") {
      response.end(candidate.sums);
    } else {
      response.writeHead(404).end();
    }
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address === "object");
  try {
    await withSandbox("release-upgrade-peer", async (peer) => {
      await withSandbox("release-upgrade-client", async (client) => {
        const peerBinary = path.join(peer.paths.binDir, "hyp");
        const installedBinary = path.join(client.paths.binDir, "hyp");
        fs.writeFileSync(peerBinary, previous.binary, { mode: 0o755 });
        fs.writeFileSync(installedBinary, previous.binary, { mode: 0o755 });
        const receiver = new HypCli(peer, peerBinary);
        const sender = new HypCli(client, installedBinary);
        const version = await sender.exec(["version", "--json"]);
        assert.equal(version.json?.data?.version, PREVIOUS_RELEASE_TAG.slice(1));

        await receiver.onboard({
          nodeId: "upgrade@peer",
          noSkills: true,
          noCommands: true,
          extraArgs: ["--profile", "p2p"],
        });
        await sender.onboard({
          nodeId: "upgrade@client",
          noSkills: true,
          noCommands: true,
          extraArgs: ["--profile", "p2p"],
        });
        const peerDaemon = await receiver.startDaemon({ extraArgs: ["--bind", "127.0.0.1:0"] });
        const { endpoint } = await readNodeStatus(receiver, peerDaemon.handle.pid);
        assert.ok(typeof endpoint === "string");
        assert.match(endpoint, /^http:\/\/127\.0\.0\.1:[1-9][0-9]*$/);

        const invite = await receiver.exec([
          "pair", "invite", "--mode", "p2p", "--node-id", "upgrade@peer", "--endpoint", endpoint,
          "--grant", "dm:send,dm:receive", "--request", "dm:send,dm:receive",
          "--state-dir", peer.paths.hyphaeStateDir, "--json",
        ]);
        const token = invite.json?.data?.token;
        assert.ok(typeof token === "string" && token.startsWith("hp2p1_"), "expected P2P invite");
        const accepted = await sender.exec([
          "pair", "accept", "--node-id", "upgrade@client",
          "--state-dir", client.paths.hyphaeStateDir, "--json",
        ], { input: `${token}\n` });
        assert.equal(accepted.json?.data?.handshakeCompleted, true);
        assert.equal(accepted.json?.data?.peerId, "upgrade@peer");

        const sink = await receiver.openPeer("upgrade-sink");
        const deliver = async (label: string) => {
          const message = `${label} ${randomUUID()}`;
          const source = await sender.openPeer("upgrade-source");
          try {
            const receipt = await source.send("upgrade@peer/upgrade-sink", message);
            assert.equal(receipt.encrypted, true, "P2P message must be encrypted");
            await waitForCondition(async () => {
              const inbox = await sink.inbox({ ack: false });
              return JSON.stringify(inbox).includes(message);
            }, 15_000, label);
            await sink.inbox({ ack: true });
            const reply = `reply to ${message}`;
            const replyReceipt = await sink.send("upgrade@client/upgrade-source", reply);
            assert.equal(replyReceipt.encrypted, true, "P2P reply must be encrypted");
            await waitForCondition(async () => {
              const inbox = await source.inbox({ ack: false });
              return JSON.stringify(inbox).includes(reply);
            }, 15_000, `${label} reply`);
          } finally {
            try {
              await source.mesh({ action: "leave" });
            } finally {
              await source.close();
            }
          }
        };

        try {
          const previousDaemon = await sender.startDaemon({ extraArgs: ["--bind", "127.0.0.1:0"] });
          const identity = await readNodeStatus(sender, previousDaemon.handle.pid);
          assert.equal(identity.nodeId, "upgrade@client");
          assert.ok(typeof identity.kid === "string" && identity.kid.length > 0);
          assert.ok(typeof identity.fingerprint === "string" && identity.fingerprint.length > 0);
          await deliver("before upgrade");
          const priorConfig = fs.readFileSync(sender.nodeConfigPath);
          const priorBinaryInode = fs.statSync(installedBinary).ino;
          await sender.stopDaemon();

          await runFile("sh", [
            path.join(REPO_ROOT, "scripts/install.sh"),
            "--version", CANDIDATE_TAG,
            "--base-url", `http://127.0.0.1:${address.port}/candidate`,
            "--dir", client.paths.binDir, "--force", "--no-onboard",
          ], { env: client.env, timeout: 30_000 });
          assert.notEqual(fs.statSync(installedBinary).ino, priorBinaryInode,
            "installer must replace the installed executable");
          assert.equal(sha256(fs.readFileSync(installedBinary)), sha256(candidate.binary),
            "installer must replace the released binary with the exact candidate");
          assert.equal(sha256(fs.readFileSync(sender.nodeConfigPath)), sha256(priorConfig),
            "installer must preserve the existing node configuration");

          const candidateDaemon = await sender.startDaemon({ extraArgs: ["--bind", "127.0.0.1:0"] });
          const upgradedIdentity = await readNodeStatus(sender, candidateDaemon.handle.pid);
          for (const key of ["nodeId", "kid", "fingerprint"]) {
            assert.equal(upgradedIdentity[key], identity[key], `upgraded node must preserve ${key}`);
          }
          await deliver("after upgrade");
        } finally {
          await sink.close();
        }
      });
    });
  } finally {
    server.close();
    await once(server, "close");
  }
});
