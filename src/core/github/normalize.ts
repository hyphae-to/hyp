// GitHub webhook delivery -> CloudEvent on the `github` topic. `data` is a fixed-shape summary,
// never GitHub's raw body: every field is present (null or [] when it does not apply), text is cut,
// and the whole object fits the router's 8 KiB limit. All of it is untrusted user content.
import { MAX_ATTRIBUTE_CHARS, MAX_DATA_BYTES, type CloudEvent } from "../router/cloudevent.ts";
import { emptyRecordKeys, recordKeys, type RecordKeys } from "./records.ts";

export const MAX_TITLE_CHARS = 200;
export const MAX_TEXT_CHARS = 1000;
const CUT = "[...]";
const MAX_MENTIONS = 20;
const MAX_LIST = 50;

/** Events and actions that are published; everything else is dropped. `null`: the event has no action. */
const PUBLISHED: Readonly<Record<string, readonly string[] | null>> = {
  pull_request: [
    "opened",
    "reopened",
    "closed",
    "synchronize",
    "ready_for_review",
    "converted_to_draft",
    "labeled",
    "unlabeled",
    "assigned",
  ],
  pull_request_review: ["submitted", "dismissed"],
  pull_request_review_comment: ["created"],
  issues: ["opened", "reopened", "closed", "labeled", "unlabeled", "assigned"],
  issue_comment: ["created"],
  workflow_run: ["completed"],
  push: null,
  ping: null,
};

export interface GitHubData {
  number: number | null;
  title: string | null;
  url: string | null;
  state: string | null;
  draft: boolean | null;
  author: string | null;
  author_type: "User" | "Bot" | null;
  labels: string[];
  assignees: string[];
  branch: string | null;
  base: string | null;
  head_sha: string | null;
  conclusion: string | null;
  text: string | null;
  mentions: string[];
  signed_by: string | null;
  /**
   * Every PR the event concerns: all PRs a workflow run names, or the one PR of a PR, review or PR
   * comment event. `number` keeps its single-PR meaning for existing filters.
   */
  pr_numbers: number[];
  run_id: number | null;
  run_attempt: number | null;
  workflow_path: string | null;
}

/** `data` as published: the GitHub summary plus routing keys of work records (records.ts). */
export type PublishedData = GitHubData & RecordKeys;

export interface Delivery {
  /** `X-GitHub-Event`. */
  readonly event: string;
  /** `X-GitHub-Delivery`. */
  readonly id: string;
  readonly payload: unknown;
  readonly receivedAt: Date;
}

export type Normalized =
  | { readonly publish: true; readonly event: CloudEvent }
  | { readonly publish: false; readonly reason: string };

// ---- reading untyped JSON ----

type Json = Readonly<Record<string, unknown>>;

const isObject = (value: unknown): value is Json => typeof value === "object" && value !== null && !Array.isArray(value);
const object = (value: unknown, key: string): Json | null => {
  if (!isObject(value)) return null;
  const inner = value[key];
  return isObject(inner) ? inner : null;
};
const string = (value: unknown, key: string): string | null => {
  if (!isObject(value)) return null;
  const inner = value[key];
  return typeof inner === "string" ? inner : null;
};
const integer = (value: unknown, key: string): number | null => {
  if (!isObject(value)) return null;
  const inner = value[key];
  return typeof inner === "number" && Number.isSafeInteger(inner) ? inner : null;
};
const boolean = (value: unknown, key: string): boolean | null => {
  if (!isObject(value)) return null;
  const inner = value[key];
  return typeof inner === "boolean" ? inner : null;
};
/** `key` of each object in the array at `value[list]`, e.g. label names. */
const names = (value: unknown, list: string, key: string): string[] => {
  if (!isObject(value)) return [];
  const items = value[list];
  if (!Array.isArray(items)) return [];
  return items.flatMap((item) => {
    const name = string(item, key);
    return name === null ? [] : [name];
  });
};

// ---- text ----

/** Cuts to at most `max` characters (code points), ending in "[...]" when cut. */
export function cut(text: string, max: number): string {
  const chars = Array.from(text);
  return chars.length <= max ? text : chars.slice(0, max - CUT.length).join("") + CUT;
}

const SUBJECT = /^[A-Za-z0-9._/-]{1,128}$/;
const MARKER = /<!--\s*agent:([a-z0-9][a-z0-9._-]{0,63})\s*-->/g;
// Bounded on both sides: `agent:fooBar` or a name over 64 characters is no mention at all, rather
// than a mention of its prefix. Trailing `._-` past 64 characters are allowed, as sentence punctuation.
const MENTION = /(?<![A-Za-z0-9_:/.-])agent:([a-z0-9][a-z0-9._-]{0,63})[._-]*(?![A-Za-z0-9._-])/g;

/**
 * `agent:<name>` tokens in the text, outside `<!-- agent:<name> -->` signature markers, in order
 * of first appearance. Trailing `.`, `_` or `-` belong to the sentence, not the name.
 */
export function extractMentions(text: string): string[] {
  const found = new Set<string>();
  for (const match of text.replace(MARKER, " ").matchAll(MENTION)) {
    const name = (match[1] ?? "").replace(/[._-]+$/, "");
    if (name.length > 0) found.add(`agent:${name}`);
    if (found.size >= MAX_MENTIONS) break;
  }
  return [...found];
}

/** The name in the last `<!-- agent:<name> -->` marker. */
export function extractSignature(text: string): string | null {
  let name: string | null = null;
  for (const match of text.matchAll(MARKER)) name = match[1] ?? null;
  return name;
}

// ---- normalization ----

const emptyData = (): GitHubData => ({
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
});

const bytes = (data: PublishedData): number => Buffer.byteLength(JSON.stringify(data), "utf8");

/**
 * Shrinks `data` until it fits the router's limit: text first, then lists, then the title. PR
 * numbers go last of the lists, since subscribers route CI results by them.
 */
function fit(data: PublishedData): PublishedData {
  const fitted = {
    ...data,
    labels: data.labels.slice(0, MAX_LIST),
    assignees: data.assignees.slice(0, MAX_LIST),
    pr_numbers: data.pr_numbers.slice(0, MAX_LIST),
  };
  while (bytes(fitted) > MAX_DATA_BYTES) {
    const textChars = fitted.text === null ? 0 : Array.from(fitted.text).length;
    if (textChars > CUT.length + 50) fitted.text = cut(fitted.text ?? "", Math.floor(textChars / 2));
    else if (fitted.labels.length > 0) fitted.labels.pop();
    else if (fitted.assignees.length > 0) fitted.assignees.pop();
    else if (fitted.mentions.length > 0) fitted.mentions.pop();
    else if (fitted.pr_numbers.length > 0) fitted.pr_numbers.pop();
    else if (fitted.text !== null) fitted.text = null;
    else if (fitted.title !== null && Array.from(fitted.title).length > CUT.length + 20) {
      fitted.title = cut(fitted.title, Math.floor(Array.from(fitted.title).length / 2));
    } else break;
  }
  return fitted;
}

const prState = (pr: Json | null): string | null => {
  if (pr === null) return null;
  if (boolean(pr, "merged") === true || string(pr, "merged_at") !== null) return "merged";
  return string(pr, "state");
};

/** Fills the per-event fields of hub/README.md's table; returns the subject. */
function fillEvent(event: string, action: string | null, payload: Json, data: GitHubData): string | null {
  switch (event) {
    case "pull_request": {
      const pr = object(payload, "pull_request");
      data.number = integer(pr, "number") ?? integer(payload, "number");
      data.title = string(pr, "title");
      data.url = string(pr, "html_url");
      data.state = prState(pr);
      data.draft = boolean(pr, "draft");
      data.labels = names(pr, "labels", "name");
      data.assignees = names(pr, "assignees", "login");
      data.branch = string(object(pr, "head"), "ref");
      data.base = string(object(pr, "base"), "ref");
      data.head_sha = string(object(pr, "head"), "sha");
      if (action === "opened") data.text = string(pr, "body");
      data.pr_numbers = data.number === null ? [] : [data.number];
      return data.number === null ? null : `pull/${data.number}`;
    }
    case "pull_request_review": {
      const pr = object(payload, "pull_request");
      const review = object(payload, "review");
      data.number = integer(pr, "number");
      data.title = string(pr, "title");
      data.url = string(review, "html_url") ?? string(pr, "html_url");
      data.labels = names(pr, "labels", "name");
      data.state = string(review, "state");
      data.head_sha = string(object(pr, "head"), "sha");
      data.text = string(review, "body");
      data.pr_numbers = data.number === null ? [] : [data.number];
      return data.number === null ? null : `pull/${data.number}`;
    }
    case "pull_request_review_comment": {
      const pr = object(payload, "pull_request");
      const comment = object(payload, "comment");
      data.number = integer(pr, "number");
      data.title = string(pr, "title");
      data.url = string(comment, "html_url") ?? string(pr, "html_url");
      data.labels = names(pr, "labels", "name");
      data.text = string(comment, "body");
      data.pr_numbers = data.number === null ? [] : [data.number];
      return data.number === null ? null : `pull/${data.number}`;
    }
    case "issues": {
      const issue = object(payload, "issue");
      data.number = integer(issue, "number");
      data.title = string(issue, "title");
      data.url = string(issue, "html_url");
      data.state = string(issue, "state");
      data.labels = names(issue, "labels", "name");
      data.assignees = names(issue, "assignees", "login");
      if (action === "opened") data.text = string(issue, "body");
      return data.number === null ? null : `issues/${data.number}`;
    }
    case "issue_comment": {
      const issue = object(payload, "issue");
      const comment = object(payload, "comment");
      data.number = integer(issue, "number");
      data.title = string(issue, "title");
      data.url = string(comment, "html_url") ?? string(issue, "html_url");
      data.labels = names(issue, "labels", "name");
      data.text = string(comment, "body");
      // Comments on PRs come as issue_comment too; the issue then has a pull_request link.
      const kind = object(issue, "pull_request") === null ? "issues" : "pull";
      if (kind === "pull" && data.number !== null) data.pr_numbers = [data.number];
      return data.number === null ? null : `${kind}/${data.number}`;
    }
    case "workflow_run": {
      const run = object(payload, "workflow_run");
      data.title = string(run, "name") ?? string(object(payload, "workflow"), "name");
      data.url = string(run, "html_url");
      data.conclusion = string(run, "conclusion");
      data.branch = string(run, "head_branch");
      data.head_sha = string(run, "head_sha");
      const prs = isObject(run) && Array.isArray(run["pull_requests"]) ? run["pull_requests"] : [];
      data.number = prs.length === 1 ? integer(prs[0], "number") : null;
      const numbers = prs.map((pr) => integer(pr, "number")).filter((n): n is number => n !== null && n > 0);
      data.pr_numbers = [...new Set(numbers)];
      const id = integer(run, "id");
      data.run_id = id;
      data.run_attempt = integer(run, "run_attempt");
      data.workflow_path = string(run, "path");
      return id === null ? null : `actions/runs/${id}`;
    }
    case "push": {
      const ref = string(payload, "ref") ?? "";
      data.branch = ref.startsWith("refs/heads/") ? ref.slice("refs/heads/".length) : null;
      data.head_sha = string(payload, "after");
      data.url = string(payload, "compare");
      return ref.startsWith("refs/heads/") ? ref : null;
    }
    default:
      return null;
  }
}

export function normalize(delivery: Delivery): Normalized {
  const { event, payload } = delivery;
  if (!isObject(payload)) return { publish: false, reason: "payload is not an object" };
  const action = string(payload, "action");
  const actions = PUBLISHED[event];
  if (actions === undefined || !Object.hasOwn(PUBLISHED, event)) return { publish: false, reason: `event ${event} is not published` };
  if (actions !== null && (action === null || !actions.includes(action))) {
    return { publish: false, reason: `${event}.${action ?? "(none)"} is not published` };
  }
  const repository = object(payload, "repository");
  const repo = string(repository, "full_name");
  if (event === "push") {
    const defaultBranch = string(repository, "default_branch");
    if (defaultBranch === null || string(payload, "ref") !== `refs/heads/${defaultBranch}`) {
      return { publish: false, reason: "push to a branch other than the default" };
    }
  }

  const data = emptyData();
  const sender = object(payload, "sender");
  data.author = string(sender, "login");
  data.author_type = sender === null ? null : string(sender, "type") === "Bot" ? "Bot" : "User";
  const subject = fillEvent(event, actions === null ? null : action, payload, data);

  const fullText = data.text;
  // Work records and requests are issue comments (records.ts); routing keys only, read from the
  // whole body before it is cut. Inline comments expose only marker presence so comment filters
  // can exclude them, never the keys that admit a writer record. Other events carry null keys.
  const keys: RecordKeys = event === "issue_comment" ? recordKeys(fullText) : emptyRecordKeys();
  if (event === "pull_request_review_comment") keys.record_marker = recordKeys(fullText).record_marker;
  if (fullText !== null) {
    // Extracted from the whole text, before it is cut, so a late mention or trailing marker survives.
    data.mentions = extractMentions(fullText);
    data.signed_by = data.author_type === "Bot" ? extractSignature(fullText) : null;
    data.text = cut(fullText, MAX_TEXT_CHARS);
  }
  if (data.title !== null) data.title = cut(data.title, MAX_TITLE_CHARS);

  const org = string(object(payload, "organization"), "login");
  const source = repo !== null ? `github.com/${repo}` : org !== null ? `github.com/${org}` : "github.com";
  const attributes: Record<string, string> = {};
  const set = (name: string, value: string | null) => {
    // An attribute over the router's limit is left out rather than cut, since cutting changes its meaning.
    if (value !== null && value.length > 0 && value.length <= MAX_ATTRIBUTE_CHARS) attributes[name] = value;
  };
  // Only a subject the connector's delivery header shows as is (SPEC.md 12.6); a branch with `+`, `@`
  // or non-ASCII characters would show as `?`, so it is left out and stays in `data.branch`.
  set("subject", subject !== null && SUBJECT.test(subject) ? subject : null);
  set("repo", repo);
  if (actions !== null) set("action", action);
  set("actor", data.author);

  return {
    publish: true,
    event: {
      specversion: "1.0",
      id: delivery.id,
      source,
      type: actions === null ? `com.github.${event}` : `com.github.${event}.${action}`,
      time: delivery.receivedAt.toISOString().replace(/\.\d{3}Z$/, "Z"),
      datacontenttype: "application/json",
      ...attributes,
      data: { ...fit({ ...data, ...keys }) },
    },
  };
}
