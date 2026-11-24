import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { builderFilters, BUILDER_RECORD_KINDS, canonicalJson } from "./builderFilters.ts";
import { normalize, type Delivery } from "./github/normalize.ts";
import type { ToolResponse } from "./ipc.ts";
import { HttpRouterLink } from "./router/client.ts";
import { RouterCore } from "./router/core.ts";
import { serveRouter } from "./router/server.ts";
import { EnrollmentStore } from "./store.ts";
import { Subscriptions } from "./subscriptions.ts";

// mesh_subscribe with keys, and the builder template (docs/builder-subscriptions.md E2). Events are
// real GitHub fixtures run through the receiver's normalize() and the router's own matcher.

const HUB = "github-hub@bayfold-co-ops";
const REPO = "bayfold/infra";
const KEY = `assignment:${REPO}#8`;
// Rendered by slice A's tools/work_records.py render().
const A_REQUEST = "Work request: work.assigned on bayfold/monorepo#4045, operation 11111111, step 1.\n\n<!-- bayfold-request:v1 -->\n```json\n{\n  \"kind\": \"work.assigned\",\n  \"operation_id\": \"11111111-1111-4111-8111-111111111111\",\n  \"payload\": {\n    \"owner\": \"builder-4045\",\n    \"prs\": [\n      5001\n    ],\n    \"task_generation\": 2\n  },\n  \"previous_record_id\": null,\n  \"record_id\": \"22222222-2222-4222-8222-222222222222\",\n  \"schema\": 1,\n  \"sequence\": 1,\n  \"work\": \"bayfold/monorepo#4045\"\n}\n```\n\n<!-- agent:builder-4045 -->\n";
// A writer record rendered by A (with provenance), from the conformance corpus; only the kind varies.
const A_RECORD = (
  JSON.parse(readFileSync(new URL("./github/conformance/work-records.json", import.meta.url), "utf8")) as {
    cases: Array<{ name: string; body: string }>;
  }
).cases.find((c) => c.name === "record rendered by A")?.body ?? "";
const record = (kind: string) => A_RECORD.replace('"kind": "work.assigned"', `"kind": "${kind}"`);

const result = (response: ToolResponse): Record<string, unknown> => {
  if (!response.ok) throw new Error(`${response.error.code}: ${response.error.message}`);
  return response.result as Record<string, unknown>;
};
const code = (response: ToolResponse): string => (response.ok ? "ok" : response.error.code);

let deliveries = 0;
type JsonObject = Record<string, unknown>;
/** The object at `key`, for editing fixture payloads; fails the test if it is not one. */
const at = (value: JsonObject, key: string): JsonObject => {
  const inner = value[key];
  if (typeof inner !== "object" || inner === null || Array.isArray(inner)) throw new Error(`${key} is not an object`);
  return inner as JsonObject;
};
const fixture = (name: string, edit: (payload: JsonObject) => void = () => {}): Delivery => {
  const parsed = JSON.parse(readFileSync(new URL(`./github/fixtures/${name}.json`, import.meta.url), "utf8")) as {
    event: string;
    payload: JsonObject;
  };
  edit(parsed.payload);
  deliveries += 1;
  return { event: parsed.event, id: `d-${deliveries}`, payload: parsed.payload, receivedAt: new Date() };
};

const setup = async () => {
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-subscribe-"));
  const core = new RouterCore({ dbPath: ":memory:", topics: new Map([["github", [HUB]]]) });
  const router = await serveRouter({ core, host: "127.0.0.1", port: 0 });
  const link = new HttpRouterLink(router.url, core.addConnector("b@host"));
  core.events.addPublisher(HUB, ["github"]);
  const statePath = join(dir, "state.json");
  const subscriptions = new Subscriptions(EnrollmentStore.load(statePath), link);
  const matched = (delivery: Delivery): number => {
    const normalized = normalize(delivery);
    if (!normalized.publish) throw new Error(normalized.reason);
    const published = core.events.publish({ id: HUB, topics: new Set(["github"]) }, "github", normalized.event);
    if (!published.ok) throw new Error(published.message);
    return published.matched;
  };
  return {
    core,
    statePath,
    subscriptions,
    matched,
    close: async () => {
      await link.stop();
      await router.close();
      core.close();
      rmSync(dir, { recursive: true, force: true });
    },
  };
};

const builder = { kind: "builder", repo: REPO, issue: 8, pr: 9, branch: "tailscale/identity-scopes", signer: "builder-8", parents: [{ repo: REPO, pr: 7 }] };

test("subscribe is idempotent per thread and key: one subscription however often a builder resumes", async () => {
  const { subscriptions, statePath, close } = await setup();
  try {
    const first = result(await subscriptions.subscribe("child", { key: KEY, topic: "github", template: builder }));
    assert.equal(first["outcome"], "created");
    for (let i = 0; i < 3; i += 1) {
      const again = result(await subscriptions.subscribe("child", { key: KEY, topic: "github", template: builder }));
      assert.deepEqual([again["id"], again["outcome"]], [first["id"], "unchanged"]);
    }
    const listed = result(subscriptions.list("child"))["subscriptions"] as Array<{ id: string; key?: string }>;
    assert.deepEqual(listed.map((s) => [s.id, s.key]), [[first["id"], KEY]]);
    // Persisted with its key; a reloaded store keeps it.
    const state = JSON.parse(readFileSync(statePath, "utf8")) as { subscriptions: Array<{ key?: string }> };
    assert.equal(state.subscriptions[0]?.key, KEY);
    assert.equal(EnrollmentStore.load(statePath).subscriptionsOf("child")[0]?.key, KEY);
    // Another thread's same key is its own subscription.
    const other = result(await subscriptions.subscribe("other", { key: KEY, topic: "github", template: builder }));
    assert.notEqual(other["id"], first["id"]);
    assert.equal(subscriptions.count(), 2);
  } finally {
    await close();
  }
});

test("changed scope updates the same subscription in place, and the router routes by the new filters", async () => {
  const { subscriptions, matched, close } = await setup();
  try {
    const { pr: _pr, branch: _branch, ...noPr } = builder;
    const first = result(await subscriptions.subscribe("child", { key: KEY, topic: "github", template: noPr }));
    const ci = () => fixture("workflow_run.completed", (p) => (at(p, "workflow_run")["pull_requests"] = [{ number: 9 }, { number: 12 }]));
    assert.equal(matched(ci()), 0, "before the PR exists, its CI is not this builder's");
    const updated = result(await subscriptions.subscribe("child", { key: KEY, topic: "github", template: builder }));
    assert.deepEqual([updated["id"], updated["outcome"]], [first["id"], "updated"]);
    assert.equal(subscriptions.count(), 1);
    assert.equal(matched(ci()), 1, "a run naming PR 9 among others now matches");
  } finally {
    await close();
  }
});

/** A comment on an issue (not a PR) of `repo`, by a bot, with this body. */
const onIssue = (issue: number, body: string, repo = REPO): Delivery =>
  fixture("issue_comment.created", (p) => {
    const target = at(p, "issue");
    target["number"] = issue;
    delete target["pull_request"];
    at(p, "repository")["full_name"] = repo;
    at(p, "comment")["body"] = body;
  });

const metadataChange = (target: "issue" | "pr", action: "labeled" | "unlabeled" | "assigned", authorType: "User" | "Bot"): Delivery =>
  fixture(target === "issue" ? "issues.opened" : "pull_request.labeled", (p) => {
    p["action"] = action;
    p["sender"] = { login: authorType === "User" ? "someone" : "release[bot]", type: authorType };
    at(p, target === "issue" ? "issue" : "pull_request")["number"] = target === "issue" ? 8 : 9;
    if (target === "pr") p["number"] = 9;
    p["label"] = { name: "status:in-merge-queue" };
    p["assignee"] = { login: "someone", type: "User" };
  });

/** Events and whether `builder` wakes on each. */
const wakeCases = (): Array<[string, Delivery, number]> => {
  const human = { login: "someone", type: "User" };
  return [
    ["review on its PR", fixture("pull_request_review.submitted"), 1],
    ["human comment on its PR", fixture("issue_comment.created", (p) => { p["sender"] = human; at(p, "comment")["body"] = "please rebase"; }), 1],
    ["job.finished record", fixture("issue_comment.created", (p) => { at(p, "comment")["body"] = record("job.finished"); }), 1],
    ["hold.resolved record", fixture("issue_comment.created", (p) => { at(p, "comment")["body"] = record("hold.resolved"); }), 1],
    ["work.assigned record on its PR", fixture("issue_comment.created", (p) => { at(p, "comment")["body"] = record("work.assigned"); }), 1],
    ["work.assigned record on its issue", onIssue(8, record("work.assigned")), 1],
    ["untrusted request, even of an allowed kind", fixture("issue_comment.created", (p) => { p["sender"] = human; at(p, "comment")["body"] = A_REQUEST; }), 0],
    ["bookkeeping record", fixture("issue_comment.created", (p) => { at(p, "comment")["body"] = record("job.requested"); }), 0],
    ["malformed record", fixture("issue_comment.created", (p) => { at(p, "comment")["body"] = record("job.finished").replace("```json", "```"); }), 0],
    ["its own signed bot post on its issue", onIssue(8, "done <!-- agent:builder-8 -->"), 0],
    ["its own signed bot post", fixture("issue_comment.created", (p) => { at(p, "comment")["body"] = "done <!-- agent:builder-8 -->"; }), 0],
    ["another agent's signed bot post", fixture("issue_comment.created", (p) => { at(p, "comment")["body"] = "reviewed <!-- agent:reviewer -->"; }), 1],
    ...["lead", "release", "pm"].flatMap((signer): Array<[string, Delivery, number]> => {
      const signed = `Please reconcile <!-- agent:${signer} -->`;
      const prComment = (number: number, body = signed, repo = REPO) => fixture("issue_comment.created", (p) => {
        at(p, "issue")["number"] = number;
        at(p, "repository")["full_name"] = repo;
        at(p, "comment")["body"] = body;
      });
      const inlineComment = (body: string) => fixture("pull_request_review_comment.created", (p) => {
        p["sender"] = { login: "review[bot]", type: "Bot" };
        at(p, "pull_request")["number"] = 9;
        at(p, "comment")["body"] = body;
      });
      return [
        [`${signer} signed on own issue`, onIssue(8, signed), 1],
        [`${signer} signed on own PR`, prComment(9), 1],
        [`${signer} signed inline review`, fixture("pull_request_review_comment.created", (p) => {
          p["sender"] = { login: "review[bot]", type: "Bot" };
          at(p, "pull_request")["number"] = 9;
          at(p, "comment")["body"] = signed;
        }), 1],
        [`${signer} signed on unrelated issue`, onIssue(12, signed), 0],
        [`${signer} signed on unrelated PR`, prComment(12), 0],
        [`${signer} signed in unrelated repo`, prComment(9, signed, "bayfold/other"), 0],
        [`${signer} signed request`, prComment(9, A_REQUEST + signed), 0],
        [`${signer} signed bookkeeping`, prComment(9, record("job.requested") + signed), 0],
        [`${signer} signed malformed record`, prComment(9, record("job.finished").replace("```json", "```") + signed), 0],
        [`${signer} signed allowlisted record`, prComment(9, record("job.finished") + signed), 1],
        [`${signer} signed inline request`, inlineComment(A_REQUEST + signed), 0],
        [`${signer} signed inline bookkeeping`, inlineComment(record("job.requested") + signed), 0],
        [`${signer} signed inline malformed record`, inlineComment(record("job.finished").replace("```json", "```") + signed), 0],
        [`${signer} signed inline allowlisted record`, inlineComment(record("job.finished") + signed), 0],
        [`${signer} signed inline marker beyond text limit`, inlineComment("x".repeat(5000) + "\n" + A_REQUEST + signed), 0],
        ...([
          ["request", A_REQUEST],
          ["bookkeeping", record("job.requested")],
          ["malformed record", record("job.finished").replace("```json", "```")],
        ] as const).flatMap(([name, body]): Array<[string, Delivery, number]> => {
          const oversized = "😀".repeat(33_000) + "\n" + body + signed;
          assert.ok(oversized.length > 65_536 && [...oversized].length < 65_536);
          return [
            [`${signer} non-BMP issue ${name} beyond parsing limit`, prComment(9, oversized), 0],
            [`${signer} non-BMP inline ${name} beyond parsing limit`, inlineComment(oversized), 0],
          ];
        }),
      ];
    }),
    ["empty bot signature", onIssue(8, "please reconcile <!-- agent: -->"), 0],
    ["self signed inline review", fixture("pull_request_review_comment.created", (p) => {
      at(p, "pull_request")["number"] = 9;
      at(p, "comment")["body"] = "done <!-- agent:builder-8 -->";
    }), 0],
    ["an unsigned bot comment", fixture("issue_comment.created", (p) => { at(p, "comment")["body"] = "Coverage report: 91%"; }), 0],
    ["a person's inline review comment", fixture("pull_request_review_comment.created", (p) => { p["sender"] = human; at(p, "comment")["user"] = human; at(p, "pull_request")["number"] = 9; }), 1],
    ["an unsigned bot's inline review comment", fixture("pull_request_review_comment.created", (p) => { p["sender"] = { login: "lint[bot]", type: "Bot" }; at(p, "comment")["body"] = "lint report"; at(p, "pull_request")["number"] = 9; }), 0],
    ["CI of its branch with no PR", fixture("workflow_run.completed", (p) => { at(p, "workflow_run")["head_branch"] = "tailscale/identity-scopes"; }), 1],
    ["CI of another PR and branch", fixture("workflow_run.completed", (p) => { at(p, "workflow_run")["pull_requests"] = [{ number: 12 }]; }), 0],
    ["parent PR merged", fixture("pull_request.closed.merged", (p) => { at(p, "pull_request")["number"] = 7; p["number"] = 7; }), 1],
    ["unrelated PR merged", fixture("pull_request.closed.merged", (p) => { at(p, "pull_request")["number"] = 6; p["number"] = 6; }), 0],
    ["its issue opened", fixture("issues.opened", (p) => { at(p, "issue")["number"] = 8; }), 1],
    ["another issue", fixture("issues.opened"), 0],
    ["same number in another repo", fixture("pull_request_review.submitted", (p) => { at(p, "repository")["full_name"] = "bayfold/other"; }), 0],
    ["request.withdrawn record on its PR", fixture("issue_comment.created", (p) => { at(p, "comment")["body"] = record("request.withdrawn"); }), 1],
    ["request.withdrawn record on its issue", onIssue(8, record("request.withdrawn")), 1],
    ["request.withdrawn record on other work in its repo", onIssue(12, record("request.withdrawn")), 0],
    ["request.withdrawn record on the same number in another repo", onIssue(8, record("request.withdrawn"), "bayfold/other"), 0],
    ["a person's request claiming request.withdrawn", fixture("issue_comment.created", (p) => { p["sender"] = { login: "someone", type: "User" }; at(p, "comment")["body"] = A_REQUEST.replace('"kind": "work.assigned"', '"kind": "request.withdrawn"'); }), 0],
    ...(["issue", "pr"] as const).flatMap((target) =>
      (["labeled", "unlabeled", "assigned"] as const).flatMap((action) =>
        (["User", "Bot"] as const).map((authorType): [string, Delivery, number] =>
          [`${authorType} ${action} its ${target}`, metadataChange(target, action, authorType), 0]))),
  ];
};

test("the builder template wakes on its own work only", async () => {
  const { subscriptions, matched, close } = await setup();
  try {
    result(await subscriptions.subscribe("child", { key: KEY, topic: "github", template: builder }));
    for (const [name, delivery, expected] of wakeCases()) assert.equal(matched(delivery), expected, name);
  } finally {
    await close();
  }
});

test("omitting signer allows all nonempty signed bots, including the builder's own", async () => {
  const { subscriptions, matched, close } = await setup();
  try {
    const { signer: _signer, ...withoutSigner } = builder;
    result(await subscriptions.subscribe("child", { key: KEY, topic: "github", template: withoutSigner }));
    assert.equal(matched(onIssue(8, "done <!-- agent:builder-8 -->")), 1);
    assert.equal(matched(onIssue(8, "please reconcile <!-- agent:lead -->")), 1);
    assert.equal(matched(onIssue(8, "unsigned")), 0);
    assert.equal(matched(onIssue(8, "<!-- agent: -->")), 0);
  } finally {
    await close();
  }
});

test("repeating the template call refreshes a stored metadata-matching subscription in place", async () => {
  const { subscriptions, matched, close } = await setup();
  try {
    const first = result(await subscriptions.subscribe("child", {
      key: KEY, topic: "github", filters: [{ exact: { repo: REPO, subject: "pull/9" } }],
    }));
    assert.equal(matched(metadataChange("pr", "labeled", "Bot")), 1, "legacy filters match queue labels");
    const refreshed = result(await subscriptions.subscribe("child", { key: KEY, topic: "github", template: builder }));
    assert.deepEqual([refreshed["id"], refreshed["outcome"]], [first["id"], "updated"]);
    assert.equal(subscriptions.count(), 1);
    assert.equal(matched(metadataChange("pr", "labeled", "Bot")), 0, "new label events are excluded");
    assert.equal(matched(fixture("pull_request_review.submitted")), 1, "reviews still wake the builder");
    assert.equal(matched(onIssue(8, record("work.assigned"))), 1, "writer assignments still wake the builder");
  } finally {
    await close();
  }
});

test("same-key refresh enables signed bot wakes and preserves pending batches", async () => {
  const { core, subscriptions, matched, close } = await setup();
  try {
    const first = result(await subscriptions.subscribe("child", {
      key: KEY, topic: "github", coalesceSeconds: 0,
      filters: [{ exact: { repo: REPO, subject: "pull/9", "data.author_type": "User" } }],
    }));
    const signed = () => fixture("issue_comment.created", (p) => {
      at(p, "comment")["body"] = "please reconcile <!-- agent:lead -->";
    });
    assert.equal(matched(signed()), 0, "stored filters do not gain new template behavior");
    assert.equal(matched(fixture("issue_comment.created", (p) => {
      p["sender"] = { login: "someone", type: "User" };
      at(p, "comment")["body"] = "please rebase";
    })), 1);
    core.events.tick();
    assert.equal(core.events.deliveryStatus("b@host")[0]?.pending, 1);
    const refreshed = result(await subscriptions.subscribe("child", {
      key: KEY, topic: "github", template: builder, coalesceSeconds: 0,
    }));
    assert.deepEqual([refreshed["id"], refreshed["outcome"]], [first["id"], "updated"]);
    assert.equal(core.events.deliveryStatus("b@host")[0]?.pending, 1, "pending batch survives refresh");
    assert.equal(matched(signed()), 1);
  } finally {
    await close();
  }
});

/** The explicit filters docs/builder-subscriptions.md documents for a builder of bayfold/infra#8, PR 9. */
const documentedFilters = (): unknown => {
  const doc = readFileSync(new URL("../docs/builder-subscriptions.md", import.meta.url), "utf8");
  const block = /<!-- explicit-builder-filters -->\n```json\n([\s\S]*?)\n```/.exec(doc)?.[1];
  if (block === undefined) throw new Error("no explicit-builder-filters block in docs/builder-subscriptions.md");
  return JSON.parse(block);
};

test("the documented explicit filters route exactly like the template, withdrawal included", async () => {
  const { subscriptions, matched, close } = await setup();
  try {
    const compact = { kind: "builder", repo: REPO, issue: 8, pr: 9, signer: "builder-8" };
    result(await subscriptions.subscribe("template", { key: KEY, topic: "github", template: compact }));
    result(await subscriptions.subscribe("explicit", { key: KEY, topic: "github", filters: documentedFilters() }));
    let both = 0;
    for (const [name, delivery] of wakeCases()) {
      const count = matched(delivery);
      assert.notEqual(count, 1, `${name}: the template and the explicit filters disagree`);
      if (count === 2) both += 1;
    }
    assert.ok(both >= 8, `only ${both} events woke both`);
  } finally {
    await close();
  }
});

test("a withdrawal wakes the builder of the affected work, parked or not, and no other", async () => {
  const { subscriptions, matched, close } = await setup();
  try {
    // Two builders in one repo. Parking changes nothing here: the connector holds no wake back.
    result(await subscriptions.subscribe("builder-8", { key: KEY, topic: "github", template: builder }));
    result(await subscriptions.subscribe("builder-12", { key: `assignment:${REPO}#12`, topic: "github", template: { kind: "builder", repo: REPO, issue: 12 } }));
    const withdrawn = record("request.withdrawn");
    assert.equal(matched(onIssue(8, withdrawn)), 1, "builder-8's work");
    assert.equal(matched(onIssue(12, withdrawn)), 1, "builder-12's work");
    assert.equal(matched(onIssue(13, withdrawn)), 0, "nobody's work");
    // The same comment without the record marker is a bot's post and wakes nobody.
    assert.equal(matched(onIssue(8, "withdrawn")), 0);
  } finally {
    await close();
  }
});

test("subscribe refuses to move a key to another topic; the subscription and its batches stay put", async () => {
  const { core, subscriptions, matched, close } = await setup();
  try {
    core.events.addPublisher("ci-hub@bayfold-co-ops", ["ci"]);
    const created = result(await subscriptions.subscribe("child", { key: KEY, topic: "github", template: builder, coalesceSeconds: 0 }));
    // One batch waiting at the router (the connector is not receiving).
    assert.equal(matched(fixture("pull_request_review.submitted")), 1);
    core.events.tick();
    assert.equal(core.events.deliveryStatus("b@host")[0]?.pending, 1);
    const moved = await subscriptions.subscribe("child", { key: KEY, topic: "ci", filters: [] });
    assert.equal(code(moved), "invalid");
    assert.match(moved.ok ? "" : moved.error.message, /subscribed to github; unsubscribe it before subscribing it on ci/);
    const listed = result(subscriptions.list("child"))["subscriptions"] as Array<{ id: string; topic: string }>;
    assert.deepEqual(listed.map((s) => [s.id, s.topic]), [[created["id"], "github"]]);
    assert.equal(core.events.deliveryStatus("b@host")[0]?.pending, 1, "the waiting batch survived the refusal");
    assert.equal(result(await subscriptions.subscribe("child", { key: KEY, topic: "github", template: builder, coalesceSeconds: 0 }))["outcome"], "unchanged");
  } finally {
    await close();
  }
});

test("unsubscribe by key on disposition; bad subscribe calls change nothing", async () => {
  const { subscriptions, close } = await setup();
  try {
    const created = result(await subscriptions.subscribe("child", { key: KEY, topic: "github", template: builder }));
    assert.equal(code(await subscriptions.subscribe("child", { key: "assignment:bayfold/infra#9", topic: "github", template: builder })), "invalid", "template keyed to another issue");
    assert.equal(code(await subscriptions.subscribe("child", { key: KEY, topic: "github" })), "invalid", "neither filters nor template");
    assert.equal(code(await subscriptions.subscribe("child", { key: KEY, topic: "github", filters: [], template: builder })), "invalid", "both");
    assert.equal(code(await subscriptions.subscribe("child", { key: "no scope", topic: "github", filters: [] })), "invalid", "bad key");
    assert.equal(code(await subscriptions.subscribe("child", { key: KEY, topic: "github", template: { ...builder, repo: "nope" } })), "invalid");
    assert.equal(code(await subscriptions.subscribe("child", { key: KEY, topic: "github", template: { ...builder, parents: [{ repo: REPO }] } })), "invalid");
    assert.equal(code(await subscriptions.subscribe("child", { key: KEY, topic: "github", filters: [{ nope: {} }] })), "invalid_filter");
    assert.equal(subscriptions.count(), 1);
    assert.equal(code(await subscriptions.unsubscribe("child", { id: "x", key: KEY })), "invalid", "id and key together");
    assert.deepEqual(result(await subscriptions.unsubscribe("someone-else", { key: KEY })), { removed: false });
    assert.deepEqual(result(await subscriptions.unsubscribe("child", { key: KEY })), { removed: true });
    assert.equal(subscriptions.threadOf(String(created["id"])), undefined);
    assert.equal(subscriptions.count(), 0);
  } finally {
    await close();
  }
});

test("canonical filters compare equal however they were written; generated filters fit the router", () => {
  assert.equal(canonicalJson([{ exact: { b: "2", a: "1" } }]), canonicalJson([{ exact: { a: "1", b: "2" } }]));
  const parents = Array.from({ length: 10 }, (_, i) => ({ repo: "bayfold/monorepo", pr: 4000 + i }));
  const built = builderFilters({ ...builder, parents });
  assert.ok(built.ok, "ten parents still fit the 4 KiB filter limit");
  assert.ok(builderFilters({ ...builder, parents: [...parents, { repo: REPO, pr: 1 }] }).ok === false);
  assert.ok(BUILDER_RECORD_KINDS.every((kind) => !kind.startsWith("job.requested")));
});
