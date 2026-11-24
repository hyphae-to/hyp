import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { loadConfig } from "./config.ts";
import { startDaemon } from "./daemon.ts";
import { writeSecret } from "./secrets.ts";
import { runOnboard } from "./setup.ts";

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = createServer();
    srv.listen(0, "127.0.0.1", () => {
      const addr = srv.address();
      srv.close(() => {
        if (addr && typeof addr === "object") resolve(addr.port);
        else reject(new Error("Could not allocate free port"));
      });
    });
  });
}

async function postGithubWebhook(
  port: number,
  secret: string,
  event: string,
  deliveryId: string,
  payload: Record<string, unknown>,
): Promise<Response> {
  const raw = JSON.stringify(payload);
  const sig = "sha256=" + createHmac("sha256", secret).update(raw).digest("hex");
  const deadline = Date.now() + 5_000;
  while (Date.now() < deadline) {
    try {
      return await fetch(`http://127.0.0.1:${port}/hooks/github`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-github-event": event,
          "x-github-delivery": deliveryId,
          "x-hub-signature-256": sig,
        },
        body: raw,
      });
    } catch {
      await new Promise((r) => setTimeout(r, 80));
    }
  }
  throw new Error("GitHub webhook receiver did not listen in time");
}

test("hyp_topics & hyp_subscribe detect unmonitored GitHub repos, wrong attributes, and verify live delivery", { timeout: 15_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "hyphae-reach-"));
  const routerPort = await freePort();
  const ghPort = await freePort();
  const ghSecret = "gh-reachability-secret";

  try {
    writeSecret("github-webhook-secret", ghSecret, dir);
    const configPath = join(dir, "connector.json");
    await runOnboard({
      configPath,
      connectorId: "bogdan@reach",
      port: routerPort,
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
            GITHUB_WEBHOOK_SECRET: { secret: "github-webhook-secret" },
            GITHUB_REPOS: "hyphae-to/hyp",
            GITHUB_ORGS: "hyphae-labs",
          },
        },
      ],
    });

    const daemon = await startDaemon(loadConfig(configPath), { quiet: true });
    try {
      daemon.state.register("antigravity:ag-1", { kind: "antigravity" });
      await daemon.connector.call("antigravity:ag-1", "hyp_join", { handle: "dev" });

      // 1. hyp_topics exposes declared scope, schema, and setupGuide to models BEFORE subscribing
      const topicsRes = await daemon.connector.call("antigravity:ag-1", "hyp_topics", {}) as {
        routers: Array<{
          router: string;
          supported: boolean;
          topics: Array<{
            topic: string;
            metadata: {
              kind: string;
              scope?: { repos?: string[]; orgs?: string[] };
              schema?: { attributes?: string[]; filterExamples?: string[] };
              setupGuide?: string;
            };
            observed: { eventCount: number; repos: string[] };
          }>;
        }>;
      };
      assert.equal(topicsRes.routers.length, 1);
      assert.equal(topicsRes.routers[0].supported, true);
      const ghTopic = topicsRes.routers[0].topics.find((t) => t.topic === "github");
      assert.ok(ghTopic);
      assert.equal(ghTopic.metadata.kind, "github-webhook");
      assert.deepEqual(ghTopic.metadata.scope?.repos, ["hyphae-to/hyp"]);
      assert.deepEqual(ghTopic.metadata.scope?.orgs, ["hyphae-labs"]);
      assert.ok(ghTopic.metadata.schema?.attributes?.includes("repo"));
      assert.match(ghTopic.metadata.setupGuide ?? "", /GITHUB_REPOS/);
      assert.equal(ghTopic.observed.eventCount, 0);

      // 2. Subscribing to an UNMONITORED repo returns reachable: false + unmonitored_repo diagnostic
      const unmonitored = await daemon.connector.call("antigravity:ag-1", "hyp_subscribe", {
        key: "gh:dead-repo",
        topic: "github",
        filters: [{ exact: { repo: "other-org/uninstalled-repo" } }],
        coalesceSeconds: 0,
      }) as { reachable: boolean; diagnostics?: Array<{ severity: string; code: string; message: string; remediation?: string }> };
      assert.equal(unmonitored.reachable, false);
      assert.ok(unmonitored.diagnostics?.some((d) => d.code === "unmonitored_repo" && d.severity === "error"));
      assert.ok(unmonitored.diagnostics?.some((d) => d.code === "topic_no_events_yet" && d.severity === "info"));

      // 3. strict: true FAILS CLOSED on unmonitored repo and rolls back subscription
      await assert.rejects(
        () => daemon.connector.call("antigravity:ag-1", "hyp_subscribe", {
          key: "gh:strict-dead",
          topic: "github",
          filters: [{ exact: { repo: "other-org/nope" } }],
          coalesceSeconds: 0,
          strict: true,
        }),
        /NOT in the configured 'github' stream scope/i,
      );

      // 4. Generalized filter mistake family (t3-mesh subject vs repo, URL prefix, source without github.com/, unknown attr)
      const wrongSubject = await daemon.connector.call("antigravity:ag-1", "hyp_subscribe", {
        key: "gh:wrong-subj",
        topic: "github",
        filters: [{ prefix: { subject: "hyphae-to/hyp" } }],
        coalesceSeconds: 0,
      }) as { reachable: boolean; diagnostics?: Array<{ code: string; suggestedFilter?: unknown }> };
      assert.equal(wrongSubject.reachable, false);
      const subjDiag = wrongSubject.diagnostics?.find((d) => d.code === "invalid_github_subject_filter");
      assert.ok(subjDiag);
      assert.deepEqual(subjDiag.suggestedFilter, { exact: { repo: "hyphae-to/hyp" } });

      const wrongRepoUrl = await daemon.connector.call("antigravity:ag-1", "hyp_subscribe", {
        key: "gh:wrong-url",
        topic: "github",
        filters: [{ exact: { repo: "https://github.com/hyphae-to/hyp" } }],
        coalesceSeconds: 0,
      }) as { reachable: boolean; diagnostics?: Array<{ code: string; suggestedFilter?: unknown }> };
      assert.equal(wrongRepoUrl.reachable, false);
      assert.ok(wrongRepoUrl.diagnostics?.some((d) => d.code === "invalid_github_repo_format"));

      const wrongSource = await daemon.connector.call("antigravity:ag-1", "hyp_subscribe", {
        key: "gh:wrong-source",
        topic: "github",
        filters: [{ exact: { source: "hyphae-to/hyp" } }],
        coalesceSeconds: 0,
      }) as { reachable: boolean; diagnostics?: Array<{ code: string }> };
      assert.equal(wrongSource.reachable, false);
      assert.ok(wrongSource.diagnostics?.some((d) => d.code === "invalid_github_source_format"));

      const unknownAttr = await daemon.connector.call("antigravity:ag-1", "hyp_subscribe", {
        key: "gh:unknown-attr",
        topic: "github",
        filters: [{ exact: { repository: "hyphae-to/hyp" } }],
        coalesceSeconds: 0,
      }) as { diagnostics?: Array<{ code: string }> };
      assert.ok(unknownAttr.diagnostics?.some((d) => d.code === "unknown_filter_attribute"));

      // 5. Valid GitHub subject filter (`pull/12`) & negated repo filter must NOT trigger false positives!
      const validNegAndSubject = await daemon.connector.call("antigravity:ag-1", "hyp_subscribe", {
        key: "gh:valid-subj",
        topic: "github",
        filters: [
          { exact: { repo: "hyphae-labs/sdk" } },
          { prefix: { subject: "pull/" } },
          { not: { exact: { repo: "other-org/excluded" } } },
        ],
        coalesceSeconds: 0,
        strict: true,
      }) as { reachable: boolean; diagnostics?: Array<{ code: string }> };
      assert.equal(validNegAndSubject.reachable, true);
      assert.ok(!(validNegAndSubject.diagnostics ?? []).some((d) => d.code === "invalid_github_subject_filter" || d.code === "unmonitored_repo"));

      // 6. Valid monitored repo subscription with strict: true succeeds and receives real signed PR webhook!
      const monitored = await daemon.connector.call("antigravity:ag-1", "hyp_subscribe", {
        key: "gh:hyp",
        topic: "github",
        filters: [{ exact: { repo: "hyphae-to/hyp" } }],
        coalesceSeconds: 0,
        strict: true,
      }) as { reachable: boolean };
      assert.equal(monitored.reachable, true);

      const hookRes = await postGithubWebhook(ghPort, ghSecret, "pull_request", "deliv-reach-1", {
        action: "opened",
        number: 7,
        repository: { full_name: "hyphae-to/hyp", default_branch: "main" },
        sender: { login: "bogdan", type: "User" },
        pull_request: {
          number: 7,
          title: "Add reachability lint",
          html_url: "https://github.com/hyphae-to/hyp/pull/7",
          state: "open",
          draft: false,
          labels: [],
          assignees: [],
          head: { ref: "feat/reach", sha: "abc1234" },
          base: { ref: "main" },
          body: "Checks monitored repos.",
        },
      });
      assert.equal(hookRes.status, 202);

      const deadline = Date.now() + 4_000;
      while (daemon.state.pendingCount("antigravity:ag-1") < 1 && Date.now() < deadline) {
        await new Promise((r) => setTimeout(r, 50));
      }
      const items = daemon.connector.drainMailbox("antigravity:ag-1", 5);
      assert.equal(items.length, 1);
      assert.match(items[0].text, /Add reachability lint/);

      // 7. hyp_topics now reflects the observed delivery and repo!
      const topicsAfter = await daemon.connector.call("antigravity:ag-1", "hyp_topics", { router: "primary" }) as {
        routers: Array<{ topics: Array<{ topic: string; observed: { eventCount: number; repos: string[] } }> }>;
      };
      const ghAfter = topicsAfter.routers[0].topics.find((t) => t.topic === "github");
      assert.equal(ghAfter?.observed.eventCount, 1);
      assert.deepEqual(ghAfter?.observed.repos, ["hyphae-to/hyp"]);
    } finally {
      await daemon.stop();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test("unobserved_repo warning triggers when router has seen webhooks from other repos without static scope", { timeout: 15_000 }, async () => {
  const dir = mkdtempSync(join(tmpdir(), "hyphae-unobs-"));
  const routerPort = await freePort();
  const ghPort = await freePort();
  const ghSecret = "gh-unobs-secret";

  try {
    writeSecret("github-webhook-secret", ghSecret, dir);
    const configPath = join(dir, "connector.json");
    await runOnboard({
      configPath,
      connectorId: "bogdan@unobs",
      port: routerPort,
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
            GITHUB_WEBHOOK_SECRET: { secret: "github-webhook-secret" },
          },
        },
      ],
    });

    const daemon = await startDaemon(loadConfig(configPath), { quiet: true });
    try {
      daemon.state.register("claude:c-1", { kind: "claude" });
      await daemon.connector.call("claude:c-1", "hyp_join", { handle: "dev" });

      // Deliver a ping webhook from hyphae-to/hyp so router has observed it
      const pingRes = await postGithubWebhook(ghPort, ghSecret, "ping", "deliv-ping-1", {
        zen: "Keep it logically awesome.",
        repository: { full_name: "hyphae-to/hyp", default_branch: "main" },
        sender: { login: "bogdan", type: "User" },
      });
      assert.equal(pingRes.status, 202);

      // Subscribing to a DIFFERENT repo emits unobserved_repo warning (not silent!)
      const res = await daemon.connector.call("claude:c-1", "hyp_subscribe", {
        key: "gh:unseen",
        topic: "github",
        filters: [{ exact: { repo: "hyphae-to/never-wired" } }],
        coalesceSeconds: 0,
      }) as { reachable: boolean; diagnostics?: Array<{ severity: string; code: string; message: string }> };
      assert.equal(res.reachable, true);
      const warn = res.diagnostics?.find((d) => d.code === "unobserved_repo");
      assert.ok(warn);
      assert.equal(warn.severity, "warn");
      assert.match(warn.message, /hyphae-to\/hyp/);
    } finally {
      await daemon.stop();
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
