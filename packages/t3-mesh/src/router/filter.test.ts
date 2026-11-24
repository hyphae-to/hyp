import { test } from "node:test";
import assert from "node:assert/strict";
import type { CloudEvent } from "./cloudevent.ts";
import { checkFilters, matchesFilters, MAX_FILTER_DEPTH } from "./filter.ts";

const event = (data: Record<string, unknown>, attributes: Record<string, string> = {}): CloudEvent => ({
  specversion: "1.0",
  id: "a1b2c3d4-0001-11f0-8000-000000000001",
  source: "github.com/bayfold/infra",
  type: "com.github.pull_request.labeled",
  subject: "pull/9",
  datacontenttype: "application/json",
  repo: "bayfold/infra",
  action: "labeled",
  actor: "bowd",
  ...attributes,
  data: {
    number: 9,
    title: "tailscale: document the CI identities' actual scopes",
    state: "open",
    draft: false,
    author: "bowd",
    author_type: "User",
    labels: ["agent:infra"],
    assignees: [],
    branch: "tailscale/identity-scopes",
    base: "main",
    conclusion: null,
    mentions: [],
    signed_by: null,
    ...data,
  },
});

const matches = (filters: unknown, value: CloudEvent): boolean => {
  const checked = checkFilters(filters);
  if (!checked.ok) throw new Error(`${checked.path}: ${checked.message}`);
  return matchesFilters(checked.filters, value);
};

test("SPEC.md 12.3 examples", () => {
  const labelled = [{ exact: { "data.labels": "agent:infra" } }];
  assert.equal(matches(labelled, event({})), true);
  assert.equal(matches(labelled, event({ labels: ["bug"] })), false);

  const mentionedNotSelf = [{ exact: { "data.mentions": "agent:infra" } }, { not: { exact: { "data.signed_by": "infra" } } }];
  assert.equal(matches(mentionedNotSelf, event({ mentions: ["agent:ops", "agent:infra"] })), true);
  assert.equal(matches(mentionedNotSelf, event({ mentions: ["agent:infra"], signed_by: "infra" })), false);
  assert.equal(matches(mentionedNotSelf, event({ mentions: ["agent:infra"], signed_by: "ops" })), true);

  const ciFailing = [
    { exact: { type: "com.github.workflow_run.completed", "data.conclusion": "failure", "data.branch": "main" } },
  ];
  const run = { type: "com.github.workflow_run.completed" };
  assert.equal(matches(ciFailing, event({ conclusion: "failure", branch: "main" }, run)), true);
  assert.equal(matches(ciFailing, event({ conclusion: "success", branch: "main" }, run)), false);
  assert.equal(matches(ciFailing, event({ conclusion: "failure", branch: "dev" }, run)), false);

  const infraPrs = [{ exact: { repo: "bayfold/infra" } }, { prefix: { type: "com.github.pull_request." } }];
  assert.equal(matches(infraPrs, event({})), true);
  assert.equal(matches(infraPrs, event({}, { type: "com.github.pull_request_review.submitted" })), false);
  assert.equal(matches(infraPrs, event({}, { repo: "bayfold/t3-mesh" })), false);
});

test("an empty filter array matches everything", () => {
  assert.equal(matches([], event({})), true);
});

test("prefix, suffix, all and any", () => {
  assert.equal(matches([{ suffix: { type: ".labeled" } }], event({})), true);
  assert.equal(matches([{ prefix: { "data.branch": "tailscale/" } }], event({})), true);
  assert.equal(matches([{ prefix: { "data.branch": "Tailscale/" } }], event({})), false, "case-sensitive");
  assert.equal(matches([{ all: [{ exact: { actor: "bowd" } }, { exact: { action: "labeled" } }] }], event({})), true);
  assert.equal(matches([{ all: [{ exact: { actor: "bowd" } }, { exact: { action: "opened" } }] }], event({})), false);
  assert.equal(matches([{ any: [{ exact: { actor: "nobody" } }, { exact: { action: "labeled" } }] }], event({})), true);
  assert.equal(matches([{ any: [{ exact: { actor: "nobody" } }, { exact: { action: "opened" } }] }], event({})), false);
});

test("numbers and booleans compare by their JSON text", () => {
  assert.equal(matches([{ exact: { "data.number": "9" } }], event({})), true);
  assert.equal(matches([{ exact: { "data.number": "09" } }], event({})), false);
  assert.equal(matches([{ exact: { "data.draft": "false" } }], event({})), true);
  assert.equal(matches([{ prefix: { "data.number": "1" } }], event({ number: 12 })), true);
});

test("arrays match on any scalar element; nested arrays and objects never match", () => {
  assert.equal(matches([{ exact: { "data.labels": "b" } }], event({ labels: ["a", "b"] })), true);
  assert.equal(matches([{ exact: { "data.labels": "7" } }], event({ labels: [7, true] })), true);
  assert.equal(matches([{ exact: { "data.labels": "true" } }], event({ labels: [7, true] })), true);
  assert.equal(matches([{ exact: { "data.labels": "a" } }], event({ labels: [["a"], { a: "a" }, null] })), false);
  assert.equal(matches([{ exact: { "data.labels": "a" } }], event({ labels: [] })), false);
});

test("null and missing never match, except under not", () => {
  assert.equal(matches([{ exact: { "data.signed_by": "null" } }], event({})), false);
  assert.equal(matches([{ prefix: { "data.signed_by": "" } }], event({})), false);
  assert.equal(matches([{ exact: { "data.nonexistent": "x" } }], event({})), false);
  assert.equal(matches([{ exact: { missingattr: "x" } }], event({})), false);
  assert.equal(matches([{ not: { exact: { "data.signed_by": "infra" } } }], event({})), true);
  assert.equal(matches([{ not: { exact: { "data.nonexistent": "x" } } }], event({})), true);
  assert.equal(matches([{ not: { not: { exact: { "data.signed_by": "infra" } } } }], event({})), false);
});

test("data paths are one level deep, and object values never match", () => {
  const nested = event({ head: { ref: "main" } });
  assert.equal(matches([{ exact: { "data.head.ref": "main" } }], nested), false);
  assert.equal(matches([{ exact: { "data.head": "[object Object]" } }], nested), false);
  assert.equal(matches([{ exact: { data: "x" } }], nested), false);
});

test("prototype names are not fields", () => {
  assert.equal(matches([{ prefix: { "data.constructor": "" } }], event({})), false);
  assert.equal(matches([{ prefix: { "data.__proto__": "" } }], event({})), false);
  assert.equal(matches([{ prefix: { constructor: "" } }], event({})), false);
});

test("every key of an exact object must match", () => {
  assert.equal(matches([{ exact: { actor: "bowd", repo: "bayfold/infra" } }], event({})), true);
  assert.equal(matches([{ exact: { actor: "bowd", repo: "bayfold/other" } }], event({})), false);
});

test("rejects malformed filters with the path of the bad node", () => {
  const bad = (filters: unknown) => {
    const checked = checkFilters(filters);
    return checked.ok ? "ok" : checked.path;
  };
  assert.equal(bad({ exact: {} }), "filters");
  assert.equal(bad([{}]), "filters[0]");
  assert.equal(bad([{ exact: { a: "b" }, prefix: { a: "b" } }]), "filters[0]");
  assert.equal(bad([{ sql: "true" }]), "filters[0]");
  assert.equal(bad([{ cel: "true" }]), "filters[0]");
  assert.equal(bad([{ exact: {} }]), "filters[0].exact");
  assert.equal(bad([{ exact: { "data.number": 9 } }]), 'filters[0].exact["data.number"]');
  assert.equal(bad([{ exact: { Type: "x" } }]), 'filters[0].exact["Type"]');
  assert.equal(bad([{ exact: { "data.": "x" } }]), 'filters[0].exact["data."]');
  assert.equal(bad([{ any: [] }]), "filters[0].any");
  assert.equal(bad([{ all: [{ exact: { a: "b" } }, { not: { nope: {} } }] }]), "filters[0].all[1].not");
  assert.equal(bad([{ exact: { a: "b" } }]), "ok");
});

test("limits nesting and size", () => {
  let filter: unknown = { exact: { a: "b" } };
  for (let depth = 1; depth < MAX_FILTER_DEPTH; depth++) filter = { not: filter };
  assert.equal(checkFilters([filter]).ok, true);
  const tooDeep = checkFilters([{ not: filter }]);
  assert.equal(tooDeep.ok, false);
  const tooBig = checkFilters([{ exact: { "data.title": "x".repeat(4096) } }]);
  assert.equal(tooBig.ok ? "ok" : tooBig.message, "filters exceed 4096 bytes");
});
