/**
 * Phase 4 Black-Box Suite: Mixed-Version `N` vs `N-1` Schema Compatibility Matrix (Blind Spot B4).
 *
 * 100% deterministic with zero external network downloads in default runs (using Node 24's built-in
 * `node:sqlite` `DatabaseSync` and exact read-only migration SQL from `crates/hyp-store/migrations/`),
 * while also supporting optional real `HYP_PREV_BIN` (`N-1` binary) cross-checks when cached in CI!
 *
 * Verifies:
 *  1. Forward migration (`schema v5 -> v7` AND `schema v6 -> v7`):
 *     - Automatic atomic pre-migration `backups/node.sqlite.v{5,6}-to-v7-*.bak` backup (`0600` perms!).
 *     - Zero data loss across `sessions`, `peers`, `mailbox`, `human_authorities`, `human_claim_nonces`,
 *       and `muted_sources`.
 *     - `hyp status --json` and `hyp doctor --json` exit `0` with `ok: true` and report schema `v7`!
 *     - `hyp daemon` boots cleanly against the upgraded database!
 *  2. Future schema downgrade protection (`schema v99 -> v7`):
 *     - `hyp status --json` exits `1`, `ok: false`, `error.code === "SCHEMA_TOO_NEW"` with `hyp update` / `backups/` fix.
 *     - `hyp doctor --json` exits `1`, `ok: false`, `error.code === "SCHEMA_TOO_NEW"` and `store.sqlite` FAIL check.
 *     - `hyp daemon` refuses to boot (non-zero exit, fail-closed!).
 *     - `node.sqlite` is NEVER corrupted, downgraded, or stripped (`MAX(version)` remains `99`, integrity OK!).
 *  3. Optional real `HYP_PREV_BIN` (`N-1`) cross-binary skew check (skipped cleanly when unset).
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import test from "node:test";
import { HypCli } from "../lib/hyp-cli.ts";
import { REPO_ROOT, withSandbox } from "../lib/sandbox.ts";

const MIGRATIONS_DIR = path.join(REPO_ROOT, "crates", "hyp-store", "migrations");

const MIGRATION_FILES: Array<{ version: number; file: string }> = [
  { version: 1, file: "0001_initial_v2.sql" },
  { version: 2, file: "0002_discovery_and_routes.sql" },
  { version: 3, file: "0003_wakeups.sql" },
  { version: 4, file: "0004_human_authority.sql" },
  { version: 5, file: "0005_human_enc_jwk.sql" },
  { version: 6, file: "0006_muted_sources_expires_at.sql" },
];

/**
 * Seeds a genuine historical `node.sqlite` at exact schema version `targetVersion` (`5` or `6`)
 * containing realistic rows across `sessions`, `peers`, `mailbox`, `human_authorities`,
 * `human_claim_nonces`, and `muted_sources`.
 */
function seedHistoricalNodeDb(dbPath: string, targetVersion: 5 | 6): void {
  fs.mkdirSync(path.dirname(dbPath), { recursive: true, mode: 0o700 });
  const db = new DatabaseSync(dbPath);
  try {
    db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;");
    db.exec(`
      CREATE TABLE IF NOT EXISTS schema_version (
        version INTEGER PRIMARY KEY,
        applied_at INTEGER NOT NULL
      );
    `);

    const appliedAt = 1_790_000_000_000;
    for (const m of MIGRATION_FILES) {
      if (m.version > targetVersion) break;
      const sql = fs.readFileSync(path.join(MIGRATIONS_DIR, m.file), "utf8");
      db.exec(sql);
      db.prepare("INSERT INTO schema_version (version, applied_at) VALUES (?, ?)").run(
        m.version,
        appliedAt + m.version * 1_000,
      );
    }

    // Seed realistic rows matching the target schema version.
    db.prepare(
      `INSERT INTO sessions (id, backend_json, handle, last_seen, delivery_mode, created_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
    ).run("claude:legacy-sess-1", '{"harness":"claude"}', "legacy-agent", appliedAt, "full", appliedAt);

    const cachedManifest = JSON.stringify({
      v: 1,
      nodeId: "acme-hub",
      profile: "router",
      hyphaeVersion: "2.2.0",
      protocolRange: { min: 1, max: 2 },
      manifestVersion: 1,
      issuedAt: "2026-11-24T00:00:00Z",
      expiresAt: "2028-11-24T00:00:00Z",
      audience: `compat-v${targetVersion}@local`,
      identity: {
        signingJwk: { kty: "OKP", crv: "Ed25519", x: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" },
        encryptionJwk: { kty: "OKP", crv: "X25519", x: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" },
        kid: "hub-kid-1",
      },
      capabilities: [
        "manifest.v1",
        "dm.v1",
        "dm.e2ee.v1",
        "channel.v1",
        "channel.e2ee.v1",
        "events.v1",
        "sub.pushdown.v1",
        "kv.v1",
        "kv.e2ee.v1",
      ],
      policy: {
        requirePairing: true,
        requireE2ee: true,
        maxTextBytes: 32768,
        maxTransferBytes: 52428800,
      },
      advertised: { topics: [], channels: [], kvNamespaces: [], rpcCommands: [] },
    });

    db.prepare(
      `INSERT INTO peers (peer_id, endpoint, profile, trust_tier, status, scopes_json, manifest_json, manifest_version, observed_e2ee_caps_json, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      "acme-hub",
      "https://hub.acme.example",
      "router",
      "org",
      "active",
      '["dm:send","dm:receive"]',
      cachedManifest,
      1,
      '["dm.e2ee.v1","channel.e2ee.v1"]',
      appliedAt,
      appliedAt,
    );

    db.prepare(
      `INSERT INTO mailbox (receipt, session_id, origin_node, item_id, text, received_at, kind, source, notified, gate_state)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      `rcpt-v${targetVersion}-001`,
      "claude:legacy-sess-1",
      "local",
      `item-v${targetVersion}-001`,
      `PRESERVED_V${targetVersion}_MAILBOX_PAYLOAD`,
      appliedAt,
      "message",
      "peer@box/alice",
      0,
      "pending",
    );

    db.prepare(
      `INSERT INTO human_authorities (human_id, kid, label, role, jwk_json, auth_epoch, status, created_at, enc_jwk_json)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    ).run(
      "alice-admin",
      "kid-legacy-01",
      "laptop-admin",
      "admin",
      '{"kty":"OKP","crv":"Ed25519","x":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}',
      1,
      "active",
      appliedAt,
      '{"kty":"OKP","crv":"X25519","x":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"}',
    );

    db.prepare(
      `INSERT INTO human_claim_nonces (claim_id, human_kid, kind, expires_at, consumed_at)
       VALUES (?, ?, ?, ?, ?)`,
    ).run(`claim-v${targetVersion}-1`, "kid-legacy-01", "directive", appliedAt + 600_000, appliedAt);

    if (targetVersion === 6) {
      db.prepare(
        `INSERT INTO muted_sources (scope, pattern, muted_at, muted_by, expires_at)
         VALUES (?, ?, ?, ?, ?)`,
      ).run("global", "noisy-peer/*", appliedAt, "legacy-agent", appliedAt + 3_600_000);
    } else {
      db.prepare(
        `INSERT INTO muted_sources (scope, pattern, muted_at, muted_by)
         VALUES (?, ?, ?, ?)`,
      ).run("global", "noisy-peer/*", appliedAt, "legacy-agent");
    }

    db.exec("PRAGMA wal_checkpoint(TRUNCATE);");
  } finally {
    db.close();
  }
  fs.chmodSync(dbPath, 0o600);
}

// ---------------------------------------------------------------------------
// 1. Forward Migration (`v5 -> v8` and `v6 -> v8`) with Pre-Migration Backup & Zero Data Loss
// ---------------------------------------------------------------------------

for (const fromVersion of [5, 6] as const) {
  test(`Schema Compat — forward migration v${fromVersion} -> v8 creates 0600 backup, preserves all rows, passes status/doctor/daemon`, async () => {
    await withSandbox(`schema-compat-v${fromVersion}-to-v8`, async (sandbox) => {
      const hyp = new HypCli(sandbox);
      const dbPath = path.join(sandbox.paths.hyphaeStateDir, "node.sqlite");
      seedHistoricalNodeDb(dbPath, fromVersion);

      fs.writeFileSync(
        hyp.nodeConfigPath,
        JSON.stringify(
          {
            v: 2,
            nodeId: `compat-v${fromVersion}@local`,
            profile: "local",
            stateDir: sandbox.paths.hyphaeStateDir,
          },
          null,
          2,
        ) + "\n",
        { mode: 0o600 },
      );

      // Run `hyp doctor --json` to trigger atomic v{5,6} -> v8 migration + VACUUM INTO backup!
      const docRes = await hyp.doctor();
      assert.equal(docRes.exitCode, 0, `hyp doctor failed after v${fromVersion}->v8 migration: ${docRes.stderr}`);
      assert.equal(docRes.json?.ok, true, `hyp doctor not ok: ${docRes.stdout}`);

      const statusRes = await hyp.status();
      assert.equal(statusRes.exitCode, 0, `hyp status failed: ${statusRes.stderr}`);
      assert.equal(statusRes.json?.ok, true);
      assert.equal(statusRes.json?.data?.storage?.schemaVersion, 8);

      // Verify pre-migration `.bak` backup created with strictly `0600` permissions!
      const backupsDir = path.join(sandbox.paths.hyphaeStateDir, "backups");
      assert.ok(fs.existsSync(backupsDir), "Pre-migration backups/ directory must exist");
      const backups = fs
        .readdirSync(backupsDir)
        .filter((f) => f.startsWith(`node.sqlite.v${fromVersion}-to-v8-`) && f.endsWith(".bak"));
      assert.equal(
        backups.length,
        1,
        `Expected 1 pre-migration v${fromVersion}-to-v8 backup in ${backupsDir}, found: ${JSON.stringify(backups)}`,
      );
      const backupMode = fs.statSync(path.join(backupsDir, backups[0])).mode & 0o777;
      assert.equal(backupMode, 0o600, `Pre-migration backup must be 0600, got ${backupMode.toString(8)}`);

      // Inspect migrated `node.sqlite` directly to confirm v8 schema + ZERO data loss across all tables!
      const db = new DatabaseSync(dbPath, { readOnly: true });
      try {
        const verRow = db.prepare("SELECT MAX(version) AS v FROM schema_version").get() as { v: number };
        assert.equal(verRow.v, 8, "Schema version must be upgraded to 8");

        const sess = db
          .prepare("SELECT id, handle FROM sessions WHERE id = ?")
          .get("claude:legacy-sess-1") as any;
        assert.equal(sess?.handle, "legacy-agent", "sessions row must survive migration");

        const peer = db
          .prepare("SELECT peer_id, endpoint, admitted_by_human_id FROM peers WHERE peer_id = ?")
          .get("acme-hub") as any;
        assert.equal(peer?.endpoint, "https://hub.acme.example", "peers row must survive migration");
        assert.equal(peer?.admitted_by_human_id, null, "v7 admitted_by_human_id column must be added");

        const mail = db
          .prepare("SELECT text FROM mailbox WHERE receipt = ?")
          .get(`rcpt-v${fromVersion}-001`) as any;
        assert.equal(
          mail?.text,
          `PRESERVED_V${fromVersion}_MAILBOX_PAYLOAD`,
          "mailbox row must survive migration",
        );

        const human = db
          .prepare("SELECT human_id, enc_jwk_json FROM human_authorities WHERE kid = ?")
          .get("kid-legacy-01") as any;
        assert.equal(human?.human_id, "alice-admin", "human_authorities row must survive migration");
        assert.ok(String(human?.enc_jwk_json).includes("X25519"));

        const nonce = db
          .prepare("SELECT claim_id, kind FROM human_claim_nonces WHERE claim_id = ?")
          .get(`claim-v${fromVersion}-1`) as any;
        assert.equal(nonce?.kind, "directive", "human_claim_nonces row must survive v7 table rebuild");

        const mute = db
          .prepare("SELECT pattern, expires_at FROM muted_sources WHERE pattern = ?")
          .get("noisy-peer/*") as any;
        assert.equal(mute?.pattern, "noisy-peer/*", "muted_sources row must survive migration");
        if (fromVersion === 6) {
          assert.ok(typeof mute?.expires_at === "number" && mute.expires_at > 0);
        } else {
          assert.equal(mute?.expires_at, null);
        }

        const delegTbl = db
          .prepare(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'human_delegation_policies'",
          )
          .get() as any;
        assert.equal(delegTbl?.name, "human_delegation_policies", "v7 table must be created");

        const sealTbl = db
          .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'gate_lock_seal'")
          .get() as any;
        assert.equal(sealTbl?.name, "gate_lock_seal", "v8 gate_lock_seal table must be created");
      } finally {
        db.close();
      }

      // Boot live `hyp daemon` against the upgraded v7 database and confirm it serves cleanly!
      await hyp.startDaemon();
      const ins = await hyp.inspect({ all: true });
      assert.equal(ins.exitCode, 0);
      assert.equal(ins.json?.ok, true);
    });
  });
}

// ---------------------------------------------------------------------------
// 2. Future Schema Fail-Closed Downgrade Guard (`v99 -> v7`)
// ---------------------------------------------------------------------------

test("Schema Compat — future schema v99 fails closed (SCHEMA_TOO_NEW) on status, doctor & daemon without corrupting or downgrading DB", async () => {
  await withSandbox("schema-compat-future-v99", async (sandbox) => {
    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "future-v99@local", noSkills: true, noCommands: true });
    await hyp.startDaemon();
    await hyp.stopDaemon();

    const dbPath = path.join(sandbox.paths.hyphaeStateDir, "node.sqlite");
    assert.ok(fs.existsSync(dbPath), "node.sqlite must exist after daemon boot");

    // Advance schema_version to v99 (simulating a newer future binary opening this state dir).
    const db = new DatabaseSync(dbPath);
    try {
      db.prepare("INSERT INTO schema_version (version, applied_at) VALUES (99, ?)").run(Date.now());
      db.prepare(
        `INSERT INTO peers (peer_id, endpoint, profile, trust_tier, status, scopes_json, created_at, updated_at)
         VALUES ('future-peer', 'https://future.example', 'router', 'org', 'active', '[]', 1, 1)`,
      ).run();
      db.exec("PRAGMA wal_checkpoint(TRUNCATE);");
    } finally {
      db.close();
    }

    // 2a. `hyp status --json` MUST fail closed with `SCHEMA_TOO_NEW` + actionable upgrade hint!
    const statusRes = await hyp.status({ allowFailure: true });
    assert.equal(statusRes.exitCode, 1, `hyp status must exit 1 on v99 schema: ${statusRes.stdout}`);
    assert.equal(statusRes.json?.ok, false);
    assert.equal(
      statusRes.json?.error?.code,
      "SCHEMA_TOO_NEW",
      `Expected SCHEMA_TOO_NEW on hyp status: ${statusRes.stdout}`,
    );
    assert.ok(
      String(statusRes.json?.error?.fix ?? "").includes("hyp update") &&
        String(statusRes.json?.error?.fix ?? "").includes("backups/"),
      `SCHEMA_TOO_NEW fix must reference hyp update and backups/: ${statusRes.stdout}`,
    );

    // 2b. `hyp doctor --json` MUST fail closed with `SCHEMA_TOO_NEW` and failing `store.sqlite` check!
    const doctorRes = await hyp.doctor({ allowFailure: true });
    assert.equal(doctorRes.exitCode, 1, `hyp doctor must exit 1 on v99 schema: ${doctorRes.stdout}`);
    assert.equal(doctorRes.json?.ok, false);
    assert.equal(
      doctorRes.json?.error?.code,
      "SCHEMA_TOO_NEW",
      `Expected SCHEMA_TOO_NEW on hyp doctor: ${doctorRes.stdout}`,
    );
    const sqliteCheck = (doctorRes.json?.data?.checks ?? []).find((c: any) => c.name === "store.sqlite");
    assert.equal(sqliteCheck?.status, "fail", `Expected store.sqlite fail check: ${doctorRes.stdout}`);
    assert.ok(String(sqliteCheck?.fix ?? "").includes("hyp update"));

    // 2c. `hyp daemon` MUST refuse to boot (exit non-zero, never start socket or downgrade DB)!
    const daemonRes = await hyp.exec(
      [
        "daemon",
        "--state-dir",
        sandbox.paths.hyphaeStateDir,
        "--socket",
        hyp.socketPath,
        "--config",
        hyp.nodeConfigPath,
        "--json",
      ],
      { allowFailure: true, timeoutMs: 10_000 },
    );
    assert.notEqual(
      daemonRes.exitCode,
      0,
      `hyp daemon MUST fail closed on schema v99: stdout=${daemonRes.stdout} stderr=${daemonRes.stderr}`,
    );
    const combinedErr = `${daemonRes.stdout}\n${daemonRes.stderr}`;
    assert.ok(
      combinedErr.includes("99") || combinedErr.toLowerCase().includes("schema"),
      `hyp daemon error must mention schema skew: ${combinedErr}`,
    );

    // 2d. Verify `node.sqlite` was NEVER downgraded or corrupted!
    const verifyDb = new DatabaseSync(dbPath, { readOnly: true });
    try {
      const integ = verifyDb.prepare("PRAGMA integrity_check;").get() as Record<string, string>;
      assert.equal(Object.values(integ)[0], "ok", "DB integrity_check must stay ok");
      const maxVer = verifyDb.prepare("SELECT MAX(version) AS v FROM schema_version").get() as { v: number };
      assert.equal(maxVer.v, 99, "Future schema version 99 must NEVER be downgraded");
      const peer = verifyDb
        .prepare("SELECT peer_id FROM peers WHERE peer_id = 'future-peer'")
        .get() as any;
      assert.equal(peer?.peer_id, "future-peer", "Future peer row must remain intact");
    } finally {
      verifyDb.close();
    }
  });
});

// ---------------------------------------------------------------------------
// 3. Optional Real `HYP_PREV_BIN` (`N-1`) Cross-Binary Compatibility Check
// ---------------------------------------------------------------------------

test("Schema Compat — optional real HYP_PREV_BIN (N-1) vs HYP_BIN (N) upgrade & downgrade cross-check", async (t) => {
  const prevBin = process.env.HYP_PREV_BIN?.trim();
  if (!prevBin || !fs.existsSync(prevBin)) {
    t.skip("HYP_PREV_BIN not set (set HYP_PREV_BIN=/path/to/prev-hyp in CI to test live N-1 vs N binary skew)");
    return;
  }

  await withSandbox("schema-compat-prev-bin", async (sandbox) => {
    const prevHyp = new HypCli(sandbox, prevBin);
    const curHyp = new HypCli(sandbox);

    // 1. Initialize & boot real `N-1` binary to create authentic N-1 state dir.
    await prevHyp.onboard({ nodeId: "skew-cross@local", noSkills: true, noCommands: true });
    await prevHyp.startDaemon();
    const prevStatus = await prevHyp.status();
    const prevSchema = prevStatus.json?.data?.storage?.schemaVersion ?? 0;
    await prevHyp.stopDaemon();

    // 2. Upgrade with current `N` binary -> must succeed cleanly!
    const curDoc = await curHyp.doctor();
    assert.equal(curDoc.exitCode, 0, `Current N binary doctor failed on N-1 state dir: ${curDoc.stderr}`);
    const curStatus = await curHyp.status();
    assert.equal(curStatus.exitCode, 0);
    const curSchema = curStatus.json?.data?.storage?.schemaVersion ?? 0;
    assert.ok(curSchema >= prevSchema, `Schema version regressed: prev=${prevSchema}, cur=${curSchema}`);

    // 3. If schema version incremented (`curSchema > prevSchema`), verify real `N-1` CLI fails closed cleanly!
    if (curSchema > prevSchema) {
      const skewStatus = await prevHyp.status({ allowFailure: true });
      assert.notEqual(skewStatus.exitCode, 0, "N-1 hyp status must fail closed against upgraded N DB");
      const skewText = `${skewStatus.stdout}\n${skewStatus.stderr}`;
      assert.ok(
        skewStatus.json?.error?.code === "SCHEMA_TOO_NEW" || skewText.toLowerCase().includes("schema"),
        `Expected schema skew error from N-1 CLI: ${skewText}`,
      );
      // Confirm DB remains healthy for `N` after `N-1` refused it!
      const recheck = await curHyp.doctor();
      assert.equal(recheck.exitCode, 0, "Upgraded N DB must remain intact after N-1 rejection");
    }
  });
});
