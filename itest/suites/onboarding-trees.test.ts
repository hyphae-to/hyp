/**
 * Phase 3 Black-Box Integration Suite: Official Plugin SHA-256 Verification, Mutated Tamper
 * Detection, and `hyphae.onboarding/v1` Tree Walker & Config Merge Safety Validator.
 */

import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { HypCli } from "../lib/hyp-cli.ts";
import { REPO_ROOT, withSandbox } from "../lib/sandbox.ts";

const PLUGINS_SRC_DIR = path.join(REPO_ROOT, "plugins");
const ALLOWED_STEP_TYPES = new Set([
  "ask",
  "input",
  "secret",
  "human",
  "run",
  "config",
  "verify",
  "subtree",
  "done",
]);
const ALLOWED_KINDS = new Set(["source", "bridge", "node"]);
const ALLOWED_PRIVACY = new Set(["private", "team", "public"]);
const SECRET_LIKE_ENV_RE = /(TOKEN|SECRET|KEY|PASSWORD|AUTH|PASS)$/;

function nextTargets(next: any): string[] {
  if (next === undefined || next === null) return [];
  if (typeof next === "string") return [next];
  if (typeof next === "object" && next.cases && typeof next.cases === "object") {
    return Object.values(next.cases).filter((v): v is string => typeof v === "string");
  }
  return [];
}

function validateOnboardingTree(tree: any, label: string, pluginSourceCode?: string): void {
  assert.equal(tree.schema, "hyphae.onboarding/v1", `${label}: schema must be hyphae.onboarding/v1`);
  for (const field of ["id", "title", "summary", "kind", "status", "privacy", "start"]) {
    assert.equal(typeof tree[field], "string", `${label}.${field} must be a string`);
    assert.ok(tree[field].trim().length > 0, `${label}.${field} must be non-empty`);
  }
  assert.ok(ALLOWED_KINDS.has(tree.kind), `${label}: invalid kind '${tree.kind}'`);
  assert.ok(ALLOWED_PRIVACY.has(tree.privacy), `${label}: invalid privacy '${tree.privacy}'`);
  assert.ok(tree.steps && typeof tree.steps === "object", `${label}: steps map required`);
  assert.ok(tree.steps[tree.start], `${label}: start step '${tree.start}' must exist`);

  // Graph reachability & per-step schema invariants.
  const reached = new Set<string>();
  const stack: string[] = [tree.start];
  const secretSteps = new Set<string>();

  while (stack.length > 0) {
    const stepId = stack.pop()!;
    if (reached.has(stepId)) continue;
    const step = tree.steps[stepId];
    assert.ok(step && typeof step === "object", `${label}: missing referenced step '${stepId}'`);
    assert.ok(ALLOWED_STEP_TYPES.has(step.type), `${label}.${stepId}: unknown step type '${step.type}'`);

    if (step.type === "done") {
      assert.equal(step.next, undefined, `${label}.${stepId}: done step must be terminal`);
    } else {
      assert.ok(step.next !== undefined, `${label}.${stepId}: non-done step must define next`);
      const targets = nextTargets(step.next);
      assert.ok(targets.length > 0, `${label}.${stepId}: next must resolve to >=1 step`);
      for (const target of targets) {
        assert.ok(tree.steps[target], `${label}.${stepId}: next target '${target}' does not exist`);
      }
      stack.push(...targets);
    }

    if (step.type === "ask") {
      assert.equal(typeof step.question, "string", `${label}.${stepId}: ask needs question`);
      assert.equal(typeof step.var, "string", `${label}.${stepId}: ask needs var`);
      assert.ok(
        Array.isArray(step.options) && step.options.length >= 2,
        `${label}.${stepId}: ask needs >=2 options`,
      );
      for (const opt of step.options) {
        assert.equal(typeof opt.value, "string", `${label}.${stepId}: option needs string value`);
        assert.equal(typeof opt.label, "string", `${label}.${stepId}: option needs string label`);
      }
    }

    if (step.type === "input") {
      assert.equal(typeof step.question, "string", `${label}.${stepId}: input needs question`);
      assert.equal(typeof step.var, "string", `${label}.${stepId}: input needs var`);
      if (step.validate !== undefined) {
        assert.doesNotThrow(
          () => new RegExp(step.validate),
          `${label}.${stepId}: input.validate must be a valid RegExp`,
        );
      }
    }

    if (step.type === "secret") {
      assert.match(step.name, /^[a-z][a-z0-9-]+$/, `${label}.${stepId}: invalid secret name`);
      assert.ok(Array.isArray(step.how) && step.how.length > 0, `${label}.${stepId}: secret needs how[]`);
      secretSteps.add(step.name);
    }

    if (step.type === "verify") {
      assert.equal(typeof step.command, "string", `${label}.${stepId}: verify needs command`);
      assert.equal(typeof step.expect, "string", `${label}.${stepId}: verify needs expect`);
      assert.equal(typeof step.onFail, "string", `${label}.${stepId}: verify needs onFail`);
    }

    if (step.type === "config") {
      assert.equal(typeof step.file, "string", `${label}.${stepId}: config needs file`);
      assert.ok(step.merge && typeof step.merge === "object", `${label}.${stepId}: config needs merge object`);
      // Security invariant: NO secret-like env key in merge may ever be a literal secret!
      const plugins = Array.isArray(step.merge.plugins) ? step.merge.plugins : [];
      for (const pluginEntry of plugins) {
        assert.equal(typeof pluginEntry.id, "string");
        assert.ok(Array.isArray(pluginEntry.targets) && pluginEntry.targets.length > 0);
        const env = pluginEntry.env ?? {};
        for (const [envKey, envVal] of Object.entries<any>(env)) {
          if (pluginSourceCode) {
            assert.ok(
              pluginSourceCode.includes(envKey),
              `${label}: onboarding config wires env '${envKey}' which is never referenced in plugin code`,
            );
          }
          if (SECRET_LIKE_ENV_RE.test(envKey)) {
            assert.equal(
              typeof envVal,
              "object",
              `${label}: secret-like env '${envKey}' MUST be a { "secret": "<name>" } reference, never a plaintext string`,
            );
            assert.equal(
              typeof envVal?.secret,
              "string",
              `${label}: secret-like env '${envKey}' missing .secret name`,
            );
            if (!envVal.secret.startsWith("google-")) {
              assert.ok(
                secretSteps.has(envVal.secret) ||
                  Object.values<any>(tree.steps).some(
                    (s) => s.type === "secret" && s.name === envVal.secret,
                  ),
                `${label}: secret ref '${envVal.secret}' has no corresponding secret step`,
              );
            }
          }
        }
      }
    }

    reached.add(stepId);
  }

  const unreachable = Object.keys(tree.steps).filter((id) => !reached.has(id));
  assert.deepEqual(unreachable, [], `${label}: unreachable onboarding steps found: ${unreachable.join(", ")}`);
  assert.ok(
    [...reached].some((id) => tree.steps[id].type === "done"),
    `${label}: tree must reach at least one terminal done step`,
  );

  // Privacy invariant: `privacy === "private"` trees MUST audit paired audience via `hyp pair list --json`
  // BEFORE installing/wiring the plugin!
  if (tree.privacy === "private") {
    const hasAudienceVerify = Object.values<any>(tree.steps).some(
      (s) => s.type === "verify" && typeof s.command === "string" && s.command.includes("hyp pair list"),
    );
    assert.equal(
      hasAudienceVerify,
      true,
      `${label}: privacy="private" onboarding tree MUST include a verify step running 'hyp pair list --json'`,
    );
  }
}

function discoverOnboardingTrees(rootDir: string): Array<{ id: string; treePath: string; sourceCode: string }> {
  if (!fs.existsSync(rootDir)) return [];
  const found: Array<{ id: string; treePath: string; sourceCode: string }> = [];
  const sdkOauth = fs.existsSync(path.join(rootDir, "sdk", "google-oauth.mjs"))
    ? fs.readFileSync(path.join(rootDir, "sdk", "google-oauth.mjs"), "utf8")
    : "";
  for (const entry of fs.readdirSync(rootDir, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const treePath = path.join(rootDir, entry.name, "onboarding.json");
    if (!fs.existsSync(treePath)) continue;
    const scriptPath = path.join(rootDir, entry.name, "index.mjs");
    const sourceCode =
      (fs.existsSync(scriptPath) ? fs.readFileSync(scriptPath, "utf8") : "") + "\n" + sdkOauth;
    found.push({ id: entry.name, treePath, sourceCode });
  }
  return found.sort((a, b) => a.id.localeCompare(b.id));
}

// ---------------------------------------------------------------------------
// 1. Official Plugin Install + Verify + 1-Byte Mutated Tamper Test
// ---------------------------------------------------------------------------

test("Plugins & Onboarding — hyp plugin install --from-dir + hyp plugin verify + 1-byte tamper fail-closed + --force recovery", async () => {
  await withSandbox("plugin-install-verify-tamper", async (sandbox) => {
    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "plug-verify@local", noSkills: true, noCommands: true });

    const officialPlugins = ["telegram", "slack", "whatsapp", "webhook", "prometheus"];
    for (const name of officialPlugins) {
      const res = await hyp.plugin([
        "install",
        name,
        "--from-dir",
        PLUGINS_SRC_DIR,
        "--home",
        sandbox.paths.homeDir,
      ]);
      assert.equal(res.exitCode, 0, `install ${name} failed: ${res.stderr}`);
      assert.equal(res.json?.ok, true);
      const rec = (res.json?.data?.plugins ?? []).find((p: any) => p.name === name);
      assert.equal(rec?.verified, true, `${name} must report verified:true`);
      assert.ok(fs.existsSync(rec.scriptPath), `${name} scriptPath must exist on disk`);
    }

    // Verify receipt store permissions (`0600`).
    const receiptPath = path.join(sandbox.paths.hyphaeStateDir, "plugins", "installed.json");
    assert.ok(fs.existsSync(receiptPath), "installed.json receipt must exist");
    assert.equal(fs.statSync(receiptPath).mode & 0o777, 0o600, "installed.json must be 0600");

    // Clean `hyp plugin verify --json` MUST exit 0!
    const verifyClean = await hyp.plugin(["verify", "--home", sandbox.paths.homeDir]);
    assert.equal(verifyClean.exitCode, 0, `clean verify failed: ${verifyClean.stdout}`);
    assert.equal(verifyClean.json?.ok, true);

    // Mutated tamper test: flip 1 byte in installed `telegram/index.mjs` on disk!
    const tgScript = path.join(sandbox.paths.hyphaeStateDir, "plugins", "telegram", "index.mjs");
    const origBytes = fs.readFileSync(tgScript);
    const tampered = Buffer.from(origBytes);
    tampered[tampered.length - 1] ^= 0x01;
    fs.writeFileSync(tgScript, tampered);

    // 1. `hyp plugin verify --json` MUST fail closed with exit 1!
    const verifyTampered = await hyp.plugin(["verify", "--home", sandbox.paths.homeDir], {
      allowFailure: true,
    });
    assert.equal(
      verifyTampered.exitCode,
      1,
      `1-byte tampered plugin MUST cause hyp plugin verify to exit 1: ${verifyTampered.stdout}`,
    );
    assert.equal(verifyTampered.json?.ok, false);
    assert.match(verifyTampered.stdout, /modified|mismatch|SHA-256/i);

    // 2. Re-running `hyp plugin install telegram --from-dir ...` WITHOUT `--force` MUST refuse to clobber!
    const noForce = await hyp.plugin(
      ["install", "telegram", "--from-dir", PLUGINS_SRC_DIR, "--home", sandbox.paths.homeDir],
      { allowFailure: true },
    );
    assert.equal(noForce.exitCode, 1, "install without --force must fail closed on modified plugin");
    assert.equal(noForce.json?.error?.code, "PLUGIN_MODIFIED");

    // 3. Re-running with `--force` atomically restores clean verified state -> verify exits 0 again!
    const withForce = await hyp.plugin([
      "install",
      "telegram",
      "--from-dir",
      PLUGINS_SRC_DIR,
      "--home",
      sandbox.paths.homeDir,
      "--force",
    ]);
    assert.equal(withForce.exitCode, 0);
    const verifyRestored = await hyp.plugin(["verify", "--home", sandbox.paths.homeDir]);
    assert.equal(verifyRestored.exitCode, 0, `restored verify failed: ${verifyRestored.stdout}`);
  });
});

// ---------------------------------------------------------------------------
// 2. `hyphae.onboarding/v1` Tree Walker & Config Merge Safety Validator
// ---------------------------------------------------------------------------

test("Plugins & Onboarding — hyphae.onboarding/v1 tree schema, reachability, privacy audience gate, and config merge safety", async () => {
  const searchDirs = [
    ...(process.env.HYPHAE_ITEST_SAAS_PLUGINS_DIR
      ? [process.env.HYPHAE_ITEST_SAAS_PLUGINS_DIR.trim()]
      : []),
    PLUGINS_SRC_DIR,
  ];
  let trees: Array<{ id: string; treePath: string; sourceCode: string }> = [];
  for (const dir of searchDirs) {
    trees = discoverOnboardingTrees(dir);
    if (trees.length > 0) break;
  }

  // Always validate the walker itself against a golden `hyphae.onboarding/v1` tree AND a mutated
  // insecure tree (plaintext secret / missing audience check on private tree) so the validator
  // always executes on `main` even before `feat/saas-source-plugins` lands!
  const goldenPrivateTree = {
    schema: "hyphae.onboarding/v1",
    id: "golden-mail",
    title: "Golden Mail",
    summary: "Reference private source tree",
    kind: "source",
    status: "beta",
    privacy: "private",
    start: "placement",
    steps: {
      placement: {
        type: "ask",
        var: "host",
        question: "Where should this plugin run?",
        options: [
          { value: "local", label: "This machine" },
          { value: "hub", label: "Hub" },
        ],
        next: "key",
      },
      key: {
        type: "secret",
        on: "host",
        name: "golden-api-key",
        how: ["Create API key", "Run hyp secret set golden-api-key"],
        next: "expose",
      },
      expose: {
        type: "verify",
        on: "host",
        command: "hyp pair list --json",
        expect: "Only user-owned devices hold stream:subscribe=*",
        onFail: "Stop and confirm with user",
        next: "wire",
      },
      wire: {
        type: "config",
        on: "host",
        file: "node.json",
        merge: {
          plugins: [
            {
              id: "golden-mail",
              kind: "source",
              command: "{{install.data.nodePath}}",
              args: ["{{install.data.plugins[0].scriptPath}}"],
              targets: ["golden-mail"],
              env: {
                GOLDEN_API_KEY: { secret: "golden-api-key" },
              },
            },
          ],
        },
        next: "done",
      },
      done: {
        type: "done",
        text: "Done.",
      },
    },
  };
  validateOnboardingTree(goldenPrivateTree, "golden-private-tree", "process.env.GOLDEN_API_KEY");

  // Mutated negative check #1: plaintext secret in `wire` must fail!
  const mutatedPlaintext = structuredClone(goldenPrivateTree);
  (mutatedPlaintext.steps.wire.merge.plugins[0].env as any).GOLDEN_API_KEY = "sk_plaintext_leak";
  assert.throws(
    () => validateOnboardingTree(mutatedPlaintext, "mutated-plaintext"),
    /MUST be a \{ "secret": "<name>" \} reference/,
  );

  // Mutated negative check #2: `privacy: "private"` missing `hyp pair list` audience gate must fail!
  const mutatedNoAudience = structuredClone(goldenPrivateTree);
  mutatedNoAudience.steps.key.next = "wire";
  delete (mutatedNoAudience.steps as any).expose;
  assert.throws(
    () => validateOnboardingTree(mutatedNoAudience, "mutated-no-audience"),
    /hyp pair list/,
  );

  if (trees.length === 0) {
    // No shipped `onboarding.json` trees on `main` yet (they ship in `feat/saas-source-plugins`).
    return;
  }

  // Validate every real `onboarding.json` tree discovered!
  await withSandbox("onboarding-trees-real-merge", async (sandbox) => {
    const hyp = new HypCli(sandbox);
    await hyp.onboard({ nodeId: "onboard-tree@local", noSkills: true, noCommands: true });

    for (const item of trees) {
      const tree = JSON.parse(fs.readFileSync(item.treePath, "utf8"));
      validateOnboardingTree(tree, item.id, item.sourceCode);
      assert.equal(tree.id, item.id, `tree.id must match directory name '${item.id}'`);

      // Simulate config merge safety: every secret ref in `wire` can be materialized cleanly into
      // `node.json` with zero plaintext secrets, and `hyp doctor --json` parses the merged config!
      const wireStep = tree.steps.wire;
      assert.equal(wireStep?.type, "config", `${item.id}: missing wire config step`);
      const mergedEntry = structuredClone(wireStep.merge.plugins[0]);
      mergedEntry.command = process.execPath;
      mergedEntry.args = [path.join(path.dirname(item.treePath), "index.mjs")];

      const cleanEnv: Record<string, unknown> = {};
      for (const [k, v] of Object.entries<any>(mergedEntry.env ?? {})) {
        if (typeof v === "object" && v !== null && typeof v.secret === "string") {
          cleanEnv[k] = { secret: v.secret };
          await hyp.secretSet(v.secret, `itest-secret-for-${v.secret}`);
        } else if (typeof v === "object" && v !== null && typeof v.value === "string") {
          cleanEnv[k] = v.value;
        } else if (typeof v === "string" && !v.includes("{{")) {
          cleanEnv[k] = v;
        }
      }
      mergedEntry.env = cleanEnv;

      const nodeJson = JSON.parse(fs.readFileSync(hyp.nodeConfigPath, "utf8"));
      nodeJson.plugins = [mergedEntry];
      const serialized = JSON.stringify(nodeJson, null, 2) + "\n";
      assert.equal(
        serialized.includes("itest-secret-for-"),
        false,
        `${item.id}: merged node.json MUST NEVER contain raw secret values`,
      );
      fs.writeFileSync(hyp.nodeConfigPath, serialized, { mode: 0o600 });

      // Confirm compiled `hyp status --json` parses the merged `node.json` cleanly without CONFIG_ERROR!
      const statusRes = await hyp.status({ allowFailure: true });
      assert.notEqual(
        statusRes.json?.error?.code,
        "CONFIG_ERROR",
        `${item.id}: merged node.json caused CONFIG_ERROR: ${statusRes.stdout}`,
      );
    }
  });
});
