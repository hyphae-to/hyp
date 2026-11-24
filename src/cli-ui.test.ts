import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import {
  CLI_COMMANDS,
  classifyCliError,
  CliOperationalError,
  CliUsageError,
  EXIT_ERROR,
  EXIT_USAGE,
  extractGlobalOutputFlags,
  renderChecks,
  renderError,
  renderHelp,
  renderResult,
  renderTable,
  resolveOutputMode,
  type CliCheck,
  type CliResult,
} from "./cli-ui.ts";

// eslint-disable-next-line no-control-regex
const ANSI_RE = /\x1b\[/;
const CLI_PATH = join(process.cwd(), "src", "cli.ts");

function runCli(
  args: readonly string[],
  options: { input?: string; env?: Record<string, string | undefined> } = {},
): { status: number | null; stdout: string; stderr: string } {
  const env: NodeJS.ProcessEnv = { ...process.env };
  delete env.HYPHAE_OUTPUT;
  delete env.NO_COLOR;
  if (options.env) {
    for (const [k, v] of Object.entries(options.env)) {
      if (v === undefined) delete env[k];
      else env[k] = v;
    }
  }
  const res = spawnSync(process.execPath, ["--experimental-strip-types", CLI_PATH, ...args], {
    encoding: "utf8",
    input: options.input,
    env,
    timeout: 15_000,
  });
  return {
    status: res.status,
    stdout: res.stdout ?? "",
    stderr: res.stderr ?? "",
  };
}

describe("cli-ui output mode resolution", () => {
  it("defaults to plain in non-TTY and pretty in TTY", () => {
    assert.equal(resolveOutputMode([], { isTTY: false, env: {} }), "plain");
    assert.equal(resolveOutputMode([], { isTTY: true, env: {} }), "pretty");
  });

  it("respects NO_COLOR and HYPHAE_OUTPUT", () => {
    assert.equal(resolveOutputMode([], { isTTY: true, env: { NO_COLOR: "1" } }), "plain");
    assert.equal(resolveOutputMode([], { isTTY: true, env: { NO_COLOR: "" } }), "pretty");
    assert.equal(resolveOutputMode([], { isTTY: true, env: { HYPHAE_OUTPUT: "json" } }), "json");
    assert.equal(resolveOutputMode([], { isTTY: false, env: { HYPHAE_OUTPUT: "pretty" } }), "pretty");
    assert.equal(resolveOutputMode([], { isTTY: true, env: { HYPHAE_OUTPUT: "PLAIN" } }), "plain");
  });

  it("gives explicit CLI flags top precedence and respects `--` separator", () => {
    assert.equal(resolveOutputMode(["status", "--json"], { isTTY: true, env: { HYPHAE_OUTPUT: "pretty" } }), "json");
    assert.equal(resolveOutputMode(["--plain", "status"], { isTTY: true, env: {} }), "plain");
    assert.equal(resolveOutputMode(["status", "--pretty"], { isTTY: false, env: {} }), "pretty");
    assert.equal(resolveOutputMode(["--pretty", "--json"], { isTTY: false, env: {} }), "json");

    const extracted = extractGlobalOutputFlags(["connect", "--json", "guide", "--", "--plain"], { isTTY: false, env: {} });
    assert.equal(extracted.mode, "json");
    assert.equal(extracted.explicitMode, "json");
    assert.deepEqual(extracted.args, ["connect", "guide", "--", "--plain"]);
  });
});

describe("cli-ui renderers", () => {
  const sampleChecks: CliCheck[] = [
    { name: "node", status: "ok", detail: "v24.21.0" },
    { name: "secrets", status: "warn", detail: "1 optional secret unset" },
    { name: "daemon", status: "fail", detail: "Not reachable", fix: "hyp daemon" },
  ];

  const sampleResult: CliResult<{ count: number }> = {
    ok: false,
    command: "status",
    title: "Hyphae Status",
    summary: "1/3 checks passed, 1 failed",
    fields: [
      { label: "Connector", value: "alice@macbook" },
      { label: "Node", value: "\x1b[32mhttp://127.0.0.1:8790\x1b[39m" },
    ],
    checks: sampleChecks,
    tables: [
      {
        title: "Streams",
        columns: [
          { key: "name", header: "Stream" },
          { key: "count", header: "Events", align: "right" },
        ],
        rows: [{ name: "github", count: 42 }],
      },
    ],
    warnings: ["Embedded Node is not exposed on Tailscale"],
    next: ["hyp daemon"],
    data: { count: 3 },
  };

  it("renderResult emits clean ANSI-free structured plain text", () => {
    const out = renderResult(sampleResult, "plain");
    assert.equal(ANSI_RE.test(out), false, "plain mode must never contain ANSI escape codes");
    assert.match(out, /^COMMAND: status/m);
    assert.match(out, /^STATUS: error/m);
    assert.match(out, /^SUMMARY: 1\/3 checks passed, 1 failed/m);
    assert.match(out, /^connector: alice@macbook/m);
    assert.match(out, /^node: http:\/\/127\.0\.0\.1:8790$/m);
    assert.match(out, /\[OK\]\s+node\s+v24\.21\.0/);
    assert.match(out, /\[WARN\]\s+secrets\s+1 optional secret unset/);
    assert.match(out, /\[FAIL\]\s+daemon\s+Not reachable/);
    assert.match(out, /fix: hyp daemon/);
    assert.match(out, /^STREAMS:/m);
    assert.match(out, /^WARNINGS:/m);
    assert.match(out, /^NEXT:/m);
  });

  it("renderResult emits valid ANSI-free JSON envelope", () => {
    const out = renderResult(sampleResult, "json");
    assert.equal(ANSI_RE.test(out), false, "json mode must never contain ANSI escape codes");
    const parsed = JSON.parse(out) as Record<string, unknown>;
    assert.equal(parsed.ok, false);
    assert.equal(parsed.command, "status");
    assert.equal(parsed.summary, "1/3 checks passed, 1 failed");
    assert.deepEqual(parsed.data, { count: 3 });
    assert.deepEqual(parsed.warnings, ["Embedded Node is not exposed on Tailscale"]);
    assert.deepEqual(parsed.next, ["hyp daemon"]);
  });

  it("renderResult emits rich styled ANSI output in pretty mode", () => {
    const out = renderResult(sampleResult, "pretty");
    assert.equal(ANSI_RE.test(out), true, "pretty mode should emit ANSI styling");
    assert.match(out, /Hyphae Status/);
    assert.match(out, /alice@macbook/);
    assert.match(out, /hyp daemon/);
  });

  it("renderTable and renderChecks work standalone across all 3 modes", () => {
    const cols = [
      { key: "name", header: "Secret" },
      { key: "bytes", header: "Bytes", align: "right" as const },
    ];
    const rows = [{ name: "github-webhook-secret", bytes: 65 }];

    const plainTable = renderTable(cols, rows, "plain");
    assert.equal(ANSI_RE.test(plainTable), false);
    assert.match(plainTable, /SECRET\s+BYTES/);
    assert.match(plainTable, /github-webhook-secret\s+65/);

    const prettyTable = renderTable(cols, rows, "pretty");
    assert.equal(ANSI_RE.test(prettyTable), true);
    assert.match(prettyTable, /github-webhook-secret/);

    const jsonTable = renderTable(cols, rows, "json");
    assert.equal(ANSI_RE.test(jsonTable), false);
    assert.deepEqual(JSON.parse(jsonTable), rows);

    const plainChecks = renderChecks(sampleChecks, "plain");
    assert.equal(ANSI_RE.test(plainChecks), false);
    assert.match(plainChecks, /\[FAIL\] daemon/);

    const prettyChecks = renderChecks(sampleChecks, "pretty");
    assert.equal(ANSI_RE.test(prettyChecks), true);
    assert.match(prettyChecks, /fix:/);
  });

  it("renderError formats cleanly across plain, json, and pretty modes", () => {
    const err = {
      code: "USAGE_ERROR",
      message: "Missing secret name",
      usage: "hyp secret set <name> [--web]",
      fix: "Run `hyp secret set my-key --web`",
    };

    const plain = renderError("secret set", err, "plain");
    assert.equal(ANSI_RE.test(plain), false);
    assert.match(plain, /^ERROR \[USAGE_ERROR\] \(secret set\): Missing secret name$/m);
    assert.match(plain, /^USAGE: hyp secret set <name> \[--web\]$/m);
    assert.match(plain, /^FIX: Run `hyp secret set my-key --web`$/m);

    const json = renderError("secret set", err, "json");
    assert.equal(ANSI_RE.test(json), false);
    const parsed = JSON.parse(json) as { ok: boolean; command: string; error: Record<string, unknown> };
    assert.equal(parsed.ok, false);
    assert.equal(parsed.command, "secret set");
    assert.equal(parsed.error.code, "USAGE_ERROR");
    assert.equal(parsed.error.usage, err.usage);

    const pretty = renderError("secret set", err, "pretty");
    assert.equal(ANSI_RE.test(pretty), true);
    assert.match(pretty, /USAGE_ERROR/);
    assert.match(pretty, /Missing secret name/);
  });

  it("renderHelp renders core, full, and JSON schema modes cleanly", () => {
    const plainShort = renderHelp(false, "plain", "0.1.0");
    assert.equal(ANSI_RE.test(plainShort), false);
    assert.match(plainShort, /CORE COMMANDS:/);
    assert.doesNotMatch(plainShort, /ADVANCED & PLUMBING COMMANDS:/);

    const plainAll = renderHelp(true, "plain", "0.1.0");
    assert.equal(ANSI_RE.test(plainAll), false);
    assert.match(plainAll, /ADVANCED & PLUMBING COMMANDS:/);
    assert.match(plainAll, /hyp mcp/);

    const pretty = renderHelp(false, "pretty", "0.1.0");
    assert.equal(ANSI_RE.test(pretty), true);
    assert.match(pretty, /Core Commands/);

    const json = renderHelp(false, "json", "0.1.0");
    assert.equal(ANSI_RE.test(json), false);
    const parsed = JSON.parse(json) as {
      ok: boolean;
      command: string;
      data: { commands: unknown[]; vocabulary: Record<string, string>; exitCodes: Record<string, string> };
    };
    assert.equal(parsed.ok, true);
    assert.equal(parsed.command, "help");
    assert.equal(parsed.data.commands.length, CLI_COMMANDS.length);
    assert.ok(parsed.data.vocabulary.Node);
    assert.ok(parsed.data.vocabulary.Stream);
    assert.ok(parsed.data.vocabulary.Bridge);
    assert.equal(parsed.data.exitCodes["2"], "Usage or invalid argument error");
  });

  it("classifyCliError maps usage errors to exit code 2 and operational errors to exit code 1", () => {
    const usageRes = classifyCliError(new CliUsageError("bad flag", { usage: "hyp status" }));
    assert.equal(usageRes.exitCode, EXIT_USAGE);
    assert.equal(usageRes.cliError.code, "USAGE_ERROR");

    const opRes = classifyCliError(new CliOperationalError("daemon down", { code: "DAEMON_UNREACHABLE" }));
    assert.equal(opRes.exitCode, EXIT_ERROR);
    assert.equal(opRes.cliError.code, "DAEMON_UNREACHABLE");

    const parseArgsErr = Object.assign(new TypeError("Unknown option '--bogus'"), {
      code: "ERR_PARSE_ARGS_UNKNOWN_OPTION",
    });
    const parseRes = classifyCliError(parseArgsErr);
    assert.equal(parseRes.exitCode, EXIT_USAGE);
    assert.equal(parseRes.cliError.code, "USAGE_ERROR");
  });
});

describe("cli.ts subprocess integration", () => {
  it("supports --help, --help --all, --help --pretty, and --help --json", () => {
    const plain = runCli(["--help"]);
    assert.equal(plain.status, 0);
    assert.equal(ANSI_RE.test(plain.stdout), false);
    assert.match(plain.stdout, /CORE COMMANDS:/);
    assert.match(plain.stdout, /hyp status/);

    const all = runCli(["--help", "--all"]);
    assert.equal(all.status, 0);
    assert.equal(ANSI_RE.test(all.stdout), false);
    assert.match(all.stdout, /ADVANCED & PLUMBING COMMANDS:/);
    assert.match(all.stdout, /hyp hook/);

    const pretty = runCli(["--help", "--pretty"]);
    assert.equal(pretty.status, 0);
    assert.equal(ANSI_RE.test(pretty.stdout), true);

    const json = runCli(["--help", "--json"]);
    assert.equal(json.status, 0);
    assert.equal(ANSI_RE.test(json.stdout), false);
    const parsed = JSON.parse(json.stdout) as { ok: boolean; command: string; data: { commands: Array<{ name: string }> } };
    assert.equal(parsed.ok, true);
    assert.equal(parsed.command, "help");
    assert.ok(parsed.data.commands.some((c) => c.name === "status"));
    assert.ok(parsed.data.commands.some((c) => c.name === "mcp"));
  });

  it("supports --version (plain compatibility) and --version --json", () => {
    const plain = runCli(["--version"]);
    assert.equal(plain.status, 0);
    assert.equal(ANSI_RE.test(plain.stdout), false);
    assert.match(plain.stdout.trim(), /^hyphae \d+\.\d+\.\d+/);

    const json = runCli(["--version", "--json"]);
    assert.equal(json.status, 0);
    assert.equal(ANSI_RE.test(json.stdout), false);
    const parsed = JSON.parse(json.stdout) as { ok: boolean; command: string; data: { name: string; version: string } };
    assert.equal(parsed.ok, true);
    assert.equal(parsed.command, "version");
    assert.equal(parsed.data.name, "hyphae");
    assert.match(parsed.data.version, /^\d+\.\d+\.\d+/);
  });

  it("renders connect guide and connect guide <id> cleanly in plain and --json modes", () => {
    const listJson = runCli(["connect", "guide", "--json"]);
    assert.equal(listJson.status, 0);
    assert.equal(ANSI_RE.test(listJson.stdout), false);
    const listParsed = JSON.parse(listJson.stdout) as {
      ok: boolean;
      command: string;
      data: { streams: Array<{ id: string }>; bridges: Array<{ id: string }>; guides: Array<{ id: string }> };
    };
    assert.equal(listParsed.ok, true);
    assert.equal(listParsed.command, "connect guide");
    assert.ok(listParsed.data.streams.some((s) => s.id === "github-webhook"));
    assert.ok(listParsed.data.bridges.length > 0);
    assert.ok(listParsed.data.guides.length >= listParsed.data.streams.length + listParsed.data.bridges.length);

    const singleJson = runCli(["connect", "guide", "github-webhook", "--json"]);
    assert.equal(singleJson.status, 0);
    assert.equal(ANSI_RE.test(singleJson.stdout), false);
    const singleParsed = JSON.parse(singleJson.stdout) as {
      ok: boolean;
      command: string;
      data: { id: string; kind: string; guide: { id: string; defaultTopicOrTarget: string } };
    };
    assert.equal(singleParsed.ok, true);
    assert.equal(singleParsed.command, "connect guide");
    assert.equal(singleParsed.data.id, "github-webhook");
    assert.equal(singleParsed.data.kind, "stream");
    assert.equal(singleParsed.data.guide.defaultTopicOrTarget, "github");

    const singlePlain = runCli(["connect", "guide", "github-webhook"]);
    assert.equal(singlePlain.status, 0);
    assert.equal(ANSI_RE.test(singlePlain.stdout), false, "plain connect guide must emit zero ANSI");
    assert.match(singlePlain.stdout, /COMMAND: connect guide/);
    assert.match(singlePlain.stdout, /SETUP INSTRUCTIONS:/);
  });

  it("handles secret list, set (via stdin without leaking value), check, and rm in an isolated temp dir", () => {
    const tmp = mkdtempSync(join(tmpdir(), "hyphae-cli-ui-test-"));
    try {
      const empty = runCli(["secret", "list", "--config-dir", tmp, "--json"]);
      assert.equal(empty.status, 0);
      assert.equal(ANSI_RE.test(empty.stdout), false);
      const emptyParsed = JSON.parse(empty.stdout) as { ok: boolean; command: string; data: { count: number; secrets: unknown[] } };
      assert.equal(emptyParsed.ok, true);
      assert.equal(emptyParsed.command, "secret list");
      assert.equal(emptyParsed.data.count, 0);
      assert.deepEqual(emptyParsed.data.secrets, []);

      const secretValue = "super-sensitive-value-do-not-print";
      const setRes = runCli(["secret", "set", "demo-token", "--config-dir", tmp, "--json"], { input: `${secretValue}\n` });
      assert.equal(setRes.status, 0);
      assert.equal(setRes.stdout.includes(secretValue), false, "secret value must never appear in stdout");
      assert.equal(setRes.stderr.includes(secretValue), false, "secret value must never appear in stderr");
      const setParsed = JSON.parse(setRes.stdout) as { ok: boolean; command: string; data: { name: string; backend: string; location: string } };
      assert.equal(setParsed.ok, true);
      assert.equal(setParsed.command, "secret set");
      assert.equal(setParsed.data.name, "demo-token");
      assert.equal(setParsed.data.backend, "file");
      assert.ok(setParsed.data.location.endsWith("demo-token.secret"));

      const populated = runCli(["secret", "list", "--config-dir", tmp, "--json"]);
      assert.equal(populated.status, 0);
      assert.equal(populated.stdout.includes(secretValue), false);
      const popParsed = JSON.parse(populated.stdout) as {
        ok: boolean;
        data: { count: number; secrets: Array<{ name: string; modeOk: boolean }> };
      };
      assert.equal(popParsed.data.count, 1);
      assert.equal(popParsed.data.secrets[0]?.name, "demo-token");
      assert.equal(popParsed.data.secrets[0]?.modeOk, true);

      const cfgPath = join(tmp, "connector.json");
      writeFileSync(
        cfgPath,
        JSON.stringify({
          connectorId: "test@local",
          stateDir: "state",
          routers: [],
          plugins: [
            { name: "demo", exec: "/bin/true", env: { DEMO_TOKEN: { secret: "demo-token" } }, targets: [] },
          ],
        }),
        { mode: 0o600 },
      );

      const checkOk = runCli(["secret", "check", cfgPath, "--json"]);
      assert.equal(checkOk.status, 0);
      assert.equal(checkOk.stdout.includes(secretValue), false);
      const checkOkParsed = JSON.parse(checkOk.stdout) as { ok: boolean; command: string; data: { passed: number; failed: number } };
      assert.equal(checkOkParsed.ok, true);
      assert.equal(checkOkParsed.command, "secret check");
      assert.equal(checkOkParsed.data.passed, 1);
      assert.equal(checkOkParsed.data.failed, 0);

      const rmRes = runCli(["secret", "rm", "demo-token", "--config-dir", tmp, "--json"]);
      assert.equal(rmRes.status, 0);
      const rmParsed = JSON.parse(rmRes.stdout) as { ok: boolean; data: { removed: boolean } };
      assert.equal(rmParsed.ok, true);
      assert.equal(rmParsed.data.removed, true);

      const checkFail = runCli(["secret", "check", cfgPath, "--json"]);
      assert.equal(checkFail.status, 1);
      const checkFailParsed = JSON.parse(checkFail.stdout) as { ok: boolean; data: { passed: number; failed: number } };
      assert.equal(checkFailParsed.ok, false);
      assert.equal(checkFailParsed.data.failed, 1);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("preserves raw single-line outputs for skill path and init, and supports connect list & status --json", () => {
    const tmp = mkdtempSync(join(tmpdir(), "hyphae-cli-compat-test-"));
    try {
      const skillPath = runCli(["skill", "path"]);
      assert.equal(skillPath.status, 0);
      assert.equal(ANSI_RE.test(skillPath.stdout), false);
      assert.match(skillPath.stdout.trim(), /SKILL\.md$/);

      const cfgPath = join(tmp, "connector.json");
      const tokenPath = join(tmp, "router.token");
      writeFileSync(tokenPath, "tok_test\n", { mode: 0o600 });

      const initRes = runCli(["init", cfgPath, "--id", "alice@test", "--router", "http://127.0.0.1:8790", "--token-file", tokenPath]);
      assert.equal(initRes.status, 0);
      assert.equal(initRes.stdout.trim(), cfgPath);

      const connectList = runCli(["connect", "list", "--config", cfgPath, "--json"]);
      assert.equal(connectList.status, 0);
      const listData = JSON.parse(connectList.stdout) as { ok: boolean; command: string; data: { exists: boolean; streams: unknown[]; bridges: unknown[] } };
      assert.equal(listData.ok, true);
      assert.equal(listData.command, "connect list");
      assert.equal(listData.data.exists, true);
      assert.deepEqual(listData.data.streams, []);
      assert.deepEqual(listData.data.bridges, []);

      const statusRes = runCli(
        ["status", cfgPath, "--socket", join(tmp, "missing.sock"), "--json"],
        { env: { HOME: tmp, XDG_CONFIG_HOME: tmp } },
      );
      assert.equal(statusRes.status, 1);
      assert.equal(ANSI_RE.test(statusRes.stdout), false);
      const statusData = JSON.parse(statusRes.stdout) as {
        ok: boolean;
        command: string;
        data: { daemonReachable: boolean; checks: unknown[]; counts: { total: number; failed: number } };
      };
      assert.equal(statusData.ok, false);
      assert.equal(statusData.command, "status");
      assert.equal(statusData.data.daemonReachable, false);
      assert.ok(statusData.data.counts.total > 0);
      assert.ok(statusData.data.counts.failed > 0);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });

  it("returns exit code 2 for invalid commands, flags, and usage errors (plain and --json)", () => {
    const cases: readonly (readonly string[])[] = [
      ["nonexistent-command"],
      ["status", "--not-a-valid-flag"],
      ["secret"],
      ["secret", "set"],
      ["share"],
      ["setup"],
      ["setup", "unknown-harness"],
      ["connect", "guide", "does-not-exist"],
      ["unmute"],
      ["onboard", "--port", "99999"],
    ];

    for (const args of cases) {
      const plain = runCli(args);
      assert.equal(plain.status, 2, `Expected exit 2 for: hyp ${args.join(" ")} (got ${plain.status}, stderr=${plain.stderr})`);
      assert.equal(ANSI_RE.test(plain.stderr), false, `Plain error must not emit ANSI for: ${args.join(" ")}`);
      assert.match(plain.stderr, /ERROR \[USAGE_ERROR\]/);

      const json = runCli([...args, "--json"]);
      assert.equal(json.status, 2, `Expected exit 2 in --json mode for: hyp ${args.join(" ")}`);
      assert.equal(ANSI_RE.test(json.stdout), false);
      const parsed = JSON.parse(json.stdout) as { ok: boolean; error: { code: string; message: string } };
      assert.equal(parsed.ok, false);
      assert.equal(parsed.error.code, "USAGE_ERROR");
      assert.ok(parsed.error.message.length > 0);
    }
  });
});
