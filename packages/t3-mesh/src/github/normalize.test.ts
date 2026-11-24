import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { checkCloudEvent, MAX_DATA_BYTES } from "../router/cloudevent.ts";
import { cut, extractMentions, extractSignature, normalize, type Delivery, type PublishedData } from "./normalize.ts";

const receivedAt = new Date("2026-10-07T12:40:01.234Z");

const fixture = (name: string): Delivery => {
  const parsed = JSON.parse(readFileSync(new URL(`./fixtures/${name}.json`, import.meta.url), "utf8")) as {
    event: string;
    delivery: string;
    payload: unknown;
  };
  return { event: parsed.event, id: parsed.delivery, payload: parsed.payload, receivedAt };
};

const published = (delivery: Delivery) => {
  const result = normalize(delivery);
  if (!result.publish) throw new Error(`not published: ${result.reason}`);
  const checked = checkCloudEvent(result.event);
  assert.ok(checked.ok, "the router accepts it");
  return result.event;
};

const none: PublishedData = {
  number: null,
  title: null,
  url: null,
  state: null,
  draft: null,
  author: null,
  author_type: null,
  labels: [],
  assignees: [],
  branch: null,
  base: null,
  head_sha: null,
  conclusion: null,
  text: null,
  mentions: [],
  signed_by: null,
  pr_numbers: [],
  run_id: null,
  run_attempt: null,
  workflow_path: null,
  record_marker: null,
  record_kind: null,
  record_id: null,
  record_operation_id: null,
  record_work: null,
  record_sequence: null,
};
const common = {
  specversion: "1.0",
  source: "github.com/bayfold/infra",
  time: "2026-10-07T12:40:01Z",
  datacontenttype: "application/json",
  repo: "bayfold/infra",
};
const pr9 = {
  number: 9,
  pr_numbers: [9],
  title: "tailscale: document the CI identities' actual scopes",
  url: "https://github.com/bayfold/infra/pull/9",
};
const SHA = "0f3c2a7d6b1e4c5a9f8e7d6c5b4a39281706f5e4";

test("pull_request.labeled: the hub/README.md example", () => {
  assert.deepEqual(published(fixture("pull_request.labeled")), {
    ...common,
    id: "a1b2c3d4-0001-11f0-8000-000000000001",
    type: "com.github.pull_request.labeled",
    subject: "pull/9",
    action: "labeled",
    actor: "bowd",
    data: {
      ...none,
      ...pr9,
      state: "open",
      draft: false,
      author: "bowd",
      author_type: "User",
      labels: ["agent:infra"],
      branch: "tailscale/identity-scopes",
      base: "main",
      head_sha: SHA,
    },
  });
});

test("pull_request.opened carries the body as text, with mentions", () => {
  const event = published(fixture("pull_request.opened"));
  assert.equal(event.type, "com.github.pull_request.opened");
  assert.deepEqual(event.data, {
    ...none,
    ...pr9,
    state: "open",
    draft: false,
    author: "bowd",
    author_type: "User",
    branch: "tailscale/identity-scopes",
    base: "main",
    head_sha: SHA,
    text: "Documents the scopes.\n\nagent:infra please check, and cc agent:ops.\n",
    mentions: ["agent:infra", "agent:ops"],
  });
});

test("pull_request.closed when merged has state merged and no text", () => {
  const event = published(fixture("pull_request.closed.merged"));
  assert.equal(event.type, "com.github.pull_request.closed");
  assert.equal(event.data["state"], "merged");
  assert.equal(event.data["text"], null);
  assert.deepEqual(event.data["mentions"], []);
});

test("pull_request_review.submitted", () => {
  assert.deepEqual(published(fixture("pull_request_review.submitted")), {
    ...common,
    id: "a1b2c3d4-0001-11f0-8000-000000000020",
    type: "com.github.pull_request_review.submitted",
    subject: "pull/9",
    action: "submitted",
    actor: "bowd",
    data: {
      ...none,
      ...pr9,
      url: "https://github.com/bayfold/infra/pull/9#pullrequestreview-3000001",
      state: "changes_requested",
      author: "bowd",
      author_type: "User",
      labels: ["agent:infra"],
      head_sha: SHA,
      text: "Needs a test. agent:infra",
      mentions: ["agent:infra"],
    },
  });
});

test("pull_request_review_comment.created by the bot is signed", () => {
  assert.deepEqual(published(fixture("pull_request_review_comment.created")), {
    ...common,
    id: "a1b2c3d4-0001-11f0-8000-000000000030",
    type: "com.github.pull_request_review_comment.created",
    subject: "pull/9",
    action: "created",
    actor: "bf-operator[bot]",
    data: {
      ...none,
      ...pr9,
      url: "https://github.com/bayfold/infra/pull/9#discussion_r4000001",
      author: "bf-operator[bot]",
      author_type: "Bot",
      labels: ["agent:infra"],
      text: "Fixed in 0f3c2a7.\n<!-- agent:infra -->",
      signed_by: "infra",
    },
  });
});

test("issues.opened", () => {
  assert.deepEqual(published(fixture("issues.opened")), {
    ...common,
    id: "a1b2c3d4-0001-11f0-8000-000000000040",
    type: "com.github.issues.opened",
    subject: "issues/12",
    action: "opened",
    actor: "bowd",
    data: {
      ...none,
      number: 12,
      title: "router: wake cap too low for CI bursts",
      url: "https://github.com/bayfold/infra/issues/12",
      state: "open",
      author: "bowd",
      author_type: "User",
      labels: ["agent:infra"],
      assignees: ["bowd"],
      text: "CI bursts hit the cap. agent:infra",
      mentions: ["agent:infra"],
    },
  });
});

test("issue_comment.created on a PR has a pull/ subject; the marker is a signature, not a mention", () => {
  assert.deepEqual(published(fixture("issue_comment.created")), {
    ...common,
    id: "a1b2c3d4-0001-11f0-8000-000000000050",
    type: "com.github.issue_comment.created",
    subject: "pull/9",
    action: "created",
    actor: "bf-operator[bot]",
    data: {
      ...none,
      ...pr9,
      url: "https://github.com/bayfold/infra/pull/9#issuecomment-5000001",
      author: "bf-operator[bot]",
      author_type: "Bot",
      labels: ["agent:infra"],
      text: "Rebased on main; agent:ops can merge.\n\n<!-- agent:infra -->",
      mentions: ["agent:ops"],
      signed_by: "infra",
    },
  });
  const onIssue = fixture("issue_comment.created");
  const payload = structuredClone(onIssue.payload) as { issue: Record<string, unknown> };
  delete payload.issue["pull_request"];
  assert.equal(published({ ...onIssue, payload }).subject, "issues/9");
});

test("issue_comment.created carries routing keys of a work record; they never authenticate", () => {
  const delivery = fixture("issue_comment.created");
  const payload = structuredClone(delivery.payload) as {
    comment: { body: string };
    sender: { login: string; type: string };
  };
  // Rendered by slice A's tools/work_records.py render(); posted here by a plain user account.
  payload.comment.body = "Work request: work.assigned on bayfold/monorepo#4045, operation 11111111, step 1.\n\n<!-- bayfold-request:v1 -->\n```json\n{\n  \"kind\": \"work.assigned\",\n  \"operation_id\": \"11111111-1111-4111-8111-111111111111\",\n  \"payload\": {\n    \"owner\": \"builder-4045\",\n    \"prs\": [\n      5001\n    ],\n    \"task_generation\": 2\n  },\n  \"previous_record_id\": null,\n  \"record_id\": \"22222222-2222-4222-8222-222222222222\",\n  \"schema\": 1,\n  \"sequence\": 1,\n  \"work\": \"bayfold/monorepo#4045\"\n}\n```\n\n<!-- agent:builder-4045 -->\n";
  payload.sender = { login: "someone", type: "User" };
  const data = published({ ...delivery, payload }).data;
  assert.equal(data["record_marker"], "bayfold-request:v1");
  assert.equal(data["record_kind"], "work.assigned");
  assert.equal(data["record_operation_id"], "11111111-1111-4111-8111-111111111111");
  assert.equal(data["record_work"], "bayfold/monorepo#4045");
  // A user's signature marker is not a signature: signed_by stays tied to Bot authors only.
  assert.equal(data["signed_by"], null);
  assert.equal(data["author_type"], "User");
  // Submitted reviews never carry record keys, even when their text has the same body.
  const review = fixture("pull_request_review.submitted");
  const reviewPayload = structuredClone(review.payload) as { review: { body: string } };
  reviewPayload.review.body = payload.comment.body;
  assert.equal(published({ ...review, payload: reviewPayload }).data["record_kind"], null);
});

test("inline comments expose work markers but never writer record keys, before truncation", () => {
  const delivery = fixture("pull_request_review_comment.created");
  const record = (JSON.parse(readFileSync(new URL("./conformance/work-records.json", import.meta.url), "utf8")) as {
    cases: Array<{ name: string; body: string }>;
  }).cases.find((entry) => entry.name === "record rendered by A")!.body;
  for (const [marker, body] of [
    ["bayfold-record:v1", record],
    ["bayfold-request:v1", "<!-- bayfold-request:v1 -->\nmalformed"],
  ] as const) {
    const payload = structuredClone(delivery.payload) as {
      comment: { body: string }; sender: { login: string; type: string };
    };
    payload.sender = { login: "author[bot]", type: "Bot" };
    payload.comment.body = "x".repeat(5000) + "\n" + body + "\n<!-- agent:lead -->";
    const data = published({ ...delivery, payload }).data;
    assert.equal(data["record_marker"], marker);
    for (const key of ["record_kind", "record_id", "record_operation_id", "record_work", "record_sequence"]) {
      assert.equal(data[key], null, key);
    }
    assert.equal(data["signed_by"], "lead");
    assert.ok(!(data["text"] as string).includes("<!-- bayfold-"), "marker was beyond truncated text");
  }
});

test("workflow_run.completed", () => {
  assert.deepEqual(published(fixture("workflow_run.completed")), {
    ...common,
    id: "a1b2c3d4-0001-11f0-8000-000000000060",
    type: "com.github.workflow_run.completed",
    subject: "actions/runs/7000000001",
    action: "completed",
    actor: "bowd",
    data: {
      ...none,
      title: "hosts",
      url: "https://github.com/bayfold/infra/actions/runs/7000000001",
      author: "bowd",
      author_type: "User",
      branch: "main",
      head_sha: "2222222222222222222222222222222222222222",
      conclusion: "failure",
      run_id: 7000000001,
      run_attempt: 2,
      workflow_path: ".github/workflows/hosts.yml",
    },
  });
  const delivery = fixture("workflow_run.completed");
  const withPr = structuredClone(delivery.payload) as { workflow_run: { pull_requests: unknown[] } };
  withPr.workflow_run.pull_requests = [{ number: 9 }];
  assert.equal(published({ ...delivery, payload: withPr }).data["number"], 9);
  assert.deepEqual(published({ ...delivery, payload: withPr }).data["pr_numbers"], [9]);
  // Several PRs: `number` stays null for existing filters; `pr_numbers` names them all, once each.
  withPr.workflow_run.pull_requests = [{ number: 9 }, { number: 10 }, { number: 9 }, { number: "x" }];
  const many = published({ ...delivery, payload: withPr }).data;
  assert.equal(many["number"], null);
  assert.deepEqual(many["pr_numbers"], [9, 10]);
});

test("push to the default branch", () => {
  assert.deepEqual(published(fixture("push")), {
    ...common,
    id: "a1b2c3d4-0001-11f0-8000-000000000070",
    type: "com.github.push",
    subject: "refs/heads/main",
    actor: "bowd",
    data: {
      ...none,
      url: "https://github.com/bayfold/infra/compare/111111111111...222222222222",
      author: "bowd",
      author_type: "User",
      branch: "main",
      head_sha: "2222222222222222222222222222222222222222",
    },
  });
});

test("a subject the delivery header could not show is left out; the branch stays in data", () => {
  const push = fixture("push");
  const payload = push.payload as { repository: Record<string, unknown> };
  const withRef = (ref: string) =>
    published({
      ...push,
      payload: { ...payload, ref, repository: { ...payload.repository, default_branch: ref.replace("refs/heads/", "") } },
    });
  for (const branch of ["feat+x", "user@fix", "café", "a".repeat(118)]) {
    const event = withRef(`refs/heads/${branch}`);
    assert.equal(event.subject, undefined, branch);
    assert.equal(event.data["branch"], branch);
  }
  assert.equal(withRef(`refs/heads/${"a".repeat(117)}`).subject, `refs/heads/${"a".repeat(117)}`, "128 characters");
  assert.equal(withRef("refs/heads/feat/x_y-1.2").subject, "refs/heads/feat/x_y-1.2");
});

test("ping from the org hook", () => {
  assert.deepEqual(published(fixture("ping")), {
    specversion: "1.0",
    id: "a1b2c3d4-0001-11f0-8000-000000000080",
    source: "github.com/bayfold",
    type: "com.github.ping",
    time: "2026-10-07T12:40:01Z",
    datacontenttype: "application/json",
    actor: "bowd",
    data: { ...none, author: "bowd", author_type: "User" },
  });
});

test("drops events and actions that are not in the table", () => {
  const dropped = (delivery: Delivery) => normalize(delivery).publish === false;
  const labeled = fixture("pull_request.labeled");
  const withAction = (action: string | undefined) => {
    const payload = structuredClone(labeled.payload) as Record<string, unknown>;
    if (action === undefined) delete payload["action"];
    else payload["action"] = action;
    return { ...labeled, payload };
  };
  for (const action of ["edited", "unassigned", "review_requested", "auto_merge_enabled", undefined]) {
    assert.ok(dropped(withAction(action)), String(action));
  }
  for (const event of ["star", "fork", "release", "check_run", "workflow_job", "constructor", "__proto__"]) {
    assert.ok(dropped({ ...labeled, event }), event);
  }
  const push = fixture("push");
  for (const ref of ["refs/heads/feature", "refs/tags/v1.0.0"]) {
    const payload = { ...(push.payload as Record<string, unknown>), ref };
    assert.ok(dropped({ ...push, payload }), ref);
  }
  const run = fixture("workflow_run.completed");
  const requested = { ...(run.payload as Record<string, unknown>), action: "requested" };
  assert.ok(dropped({ ...run, payload: requested }));
  assert.ok(dropped({ ...labeled, payload: [] }));
});

test("a human typing the marker does not sign", () => {
  const delivery = fixture("issue_comment.created");
  const payload = structuredClone(delivery.payload) as { sender: { type: string } };
  payload.sender.type = "User";
  const event = published({ ...delivery, payload });
  assert.equal(event.data["author_type"], "User");
  assert.equal(event.data["signed_by"], null);
});

test("cuts title and text; mentions and signature come from the full text", () => {
  const delivery = fixture("issue_comment.created");
  const payload = structuredClone(delivery.payload) as {
    issue: { title: string };
    comment: { body: string };
  };
  payload.issue.title = "T".repeat(500);
  payload.comment.body = `${"x".repeat(5000)} agent:late\n<!-- agent:deploy -->`;
  const event = published({ ...delivery, payload });
  const title = String(event.data["title"]);
  const text = String(event.data["text"]);
  assert.equal(Array.from(title).length, 200);
  assert.ok(title.endsWith("[...]"));
  assert.equal(Array.from(text).length, 1000);
  assert.ok(text.endsWith("[...]"));
  assert.deepEqual(event.data["mentions"], ["agent:late"]);
  assert.equal(event.data["signed_by"], "deploy");
});

test("data always fits 8 KiB", () => {
  const delivery = fixture("issues.opened");
  const payload = structuredClone(delivery.payload) as {
    issue: { title: string; body: string; labels: unknown[]; assignees: unknown[] };
  };
  payload.issue.title = "😀".repeat(400);
  payload.issue.body = "😀".repeat(3000);
  payload.issue.labels = Array.from({ length: 100 }, (_, i) => ({ name: `label-${i}-${"y".repeat(40)}` }));
  payload.issue.assignees = Array.from({ length: 10 }, (_, i) => ({ login: `user${i}` }));
  const event = published({ ...delivery, payload });
  assert.ok(Buffer.byteLength(JSON.stringify(event.data), "utf8") <= MAX_DATA_BYTES);
  assert.ok(Array.isArray(event.data["labels"]));
});

test("mention and marker extraction", () => {
  assert.deepEqual(extractMentions("agent:infra, agent:ops. agent:infra again (agent:deploy-bot)"), [
    "agent:infra",
    "agent:ops",
    "agent:deploy-bot",
  ]);
  assert.deepEqual(extractMentions("see https://x/agent:infra or myagent:infra or Agent:Infra or agent:"), []);
  assert.deepEqual(extractMentions("sign <!-- agent:infra --> only"), []);
  assert.deepEqual(extractMentions("trailing agent:infra."), ["agent:infra"]);
  // No right-hand prefix matches: a longer or capitalized name addresses nobody.
  assert.deepEqual(extractMentions("agent:fooBar agent:infra2 agent:bad_Name agent:ci"), ["agent:infra2", "agent:ci"]);
  assert.deepEqual(extractMentions("agent:ops: please look, and agent:infra/x"), ["agent:ops", "agent:infra"]);
  const long = "a".repeat(65);
  assert.deepEqual(extractMentions(`agent:${long} and agent:${long.slice(1)}.`), [`agent:${long.slice(1)}`]);
  assert.deepEqual(extractMentions(`agent:${long.slice(1)}... done`), [`agent:${long.slice(1)}`]);
  assert.equal(extractSignature("a <!-- agent:one --> b <!--agent:two-->"), "two");
  assert.equal(extractSignature("<!-- agent:Bad -->"), null);
  assert.equal(extractSignature("no marker"), null);
  assert.equal(cut("short", 10), "short");
  assert.equal(cut("0123456789ab", 10), "01234[...]");
});
