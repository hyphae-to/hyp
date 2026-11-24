// Canonical GitHub filters for one builder assignment (docs/builder-subscriptions.md E2), so a builder
// subscribes to exactly its own work instead of hand-writing filters: its issue and PR, the CI runs
// of that PR or branch, the merge or closure of named parent dependencies, and on comments only
// human ones, other signed bots without work markers, or the work records a builder acts on.
// Label and GitHub assignment changes do not wake it; work.assigned records still do. No org- or release-wide matches.
//
// Matching is routing, not authority: a builder rereads GitHub before acting on any wake.
import * as Schema from "effect/Schema";
import { isHandle } from "./address.ts";
import { checkFilters, type Filter } from "./router/filter.ts";

/**
 * Writer records a builder acts on; other record kinds are bookkeeping and do not wake it.
 * `request.withdrawn` (a founder revoked an accepted request on this work) wakes the builder, parked
 * or not, only to re-read A's current authority and reconcile. The event grants and revokes nothing:
 * a stale or replayed one cannot restore an assignment.
 */
export const BUILDER_RECORD_KINDS = [
  "job.finished",
  "job.dispatch_unknown",
  "hold.set",
  "hold.resolved",
  "work.assigned",
  "work.disposed",
  "merge.removed",
  "merge.landed",
  "request.refused",
  "request.deferred",
  "request.withdrawn",
] as const;

const MAX_PARENTS = 10;
const REPO = /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/;
// The receiver omits a subject a branch name would break (SPEC.md 12.8); data.branch is matched instead.
const BRANCH = /^[A-Za-z0-9._/+@-]{1,255}$/;

const Positive = Schema.Number.check(Schema.isInt(), Schema.isGreaterThan(0));
const Parent = Schema.Struct({ repo: Schema.String, pr: Schema.optionalKey(Positive), issue: Schema.optionalKey(Positive) });
export const BuilderTemplate = Schema.Struct({
  kind: Schema.Literal("builder"),
  repo: Schema.String,
  issue: Positive,
  pr: Schema.optionalKey(Positive),
  branch: Schema.optionalKey(Schema.String),
  signer: Schema.optionalKey(Schema.String),
  parents: Schema.optionalKey(Schema.Array(Parent)),
});
export type BuilderTemplate = typeof BuilderTemplate.Type;
const decodeTemplate = Schema.decodeUnknownOption(BuilderTemplate);

export type TemplateResult =
  | { readonly ok: true; readonly filters: readonly Filter[]; readonly key: string }
  | { readonly ok: false; readonly message: string };

/**
 * Comments, issue or inline review, must be a person's or a signed bot's without a work marker,
 * or writer records of a kind the builder acts on (records are issue comments). The signed-bot
 * branch cannot bypass the record-kind allowlist or admit untrusted requests/malformed records.
 * A nonempty signature is routing metadata, never authority; receivers re-read GitHub and verify
 * the trusted author before acting. Other events pass through, reviews included (the reviewer is an app).
 */
const COMMENT_TYPES = ["com.github.issue_comment.created", "com.github.pull_request_review_comment.created"];
const commentGate = (): Filter => ({
  any: [
    { all: COMMENT_TYPES.map((type) => ({ not: { exact: { type } } })) },
    { all: [{ exact: { "data.author_type": "User" } }, { not: { prefix: { "data.record_marker": "bayfold-" } } }] },
    {
      all: [
        { exact: { "data.author_type": "Bot" } },
        // prefix "" requires a present string; not exact "" excludes the empty string.
        { prefix: { "data.signed_by": "" } },
        { not: { exact: { "data.signed_by": "" } } },
        { not: { prefix: { "data.record_marker": "bayfold-" } } },
      ],
    },
    {
      all: [
        { exact: { type: "com.github.issue_comment.created" } },
        { exact: { "data.record_marker": "bayfold-record:v1" } },
        { any: BUILDER_RECORD_KINDS.map((kind) => ({ exact: { "data.record_kind": kind } })) },
      ],
    },
  ],
});

/** Filters for one builder assignment, and the assignment key they belong to. */
export function builderFilters(template: unknown): TemplateResult {
  const parsed = decodeTemplate(template);
  if (parsed._tag === "None") {
    return { ok: false, message: "template needs {kind: 'builder', repo, issue, pr?, branch?, signer?, parents?}" };
  }
  const { repo, issue, pr, branch, signer, parents = [] } = parsed.value;
  if (!REPO.test(repo)) return { ok: false, message: `repo must be owner/name, got ${JSON.stringify(repo)}` };
  if (branch !== undefined && !BRANCH.test(branch)) return { ok: false, message: "branch has characters GitHub refs do not" };
  if (signer !== undefined && !isHandle(signer)) return { ok: false, message: "signer must be a mesh handle" };
  if (parents.length > MAX_PARENTS) return { ok: false, message: `at most ${MAX_PARENTS} parents` };
  for (const parent of parents) {
    if (!REPO.test(parent.repo)) return { ok: false, message: `parent repo must be owner/name, got ${JSON.stringify(parent.repo)}` };
    if ((parent.pr === undefined) === (parent.issue === undefined)) {
      return { ok: false, message: "each parent names exactly one of pr or issue" };
    }
  }

  const own: Filter[] = [{ all: [{ exact: { repo, subject: `issues/${issue}` } }, commentGate()] }];
  if (pr !== undefined) own.push({ all: [{ exact: { repo, subject: `pull/${pr}` } }, commentGate()] });
  const ci: Filter[] = [];
  if (pr !== undefined) ci.push({ exact: { "data.pr_numbers": String(pr) } });
  if (branch !== undefined) ci.push({ exact: { "data.branch": branch } });
  if (ci.length > 0) own.push({ all: [{ exact: { repo, type: "com.github.workflow_run.completed" } }, { any: ci }] });
  for (const parent of parents) {
    own.push(
      parent.pr !== undefined
        ? { exact: { repo: parent.repo, subject: `pull/${parent.pr}`, type: "com.github.pull_request.closed" } }
        : { exact: { repo: parent.repo, subject: `issues/${parent.issue}`, type: "com.github.issues.closed" } },
    );
  }
  // Queue/board bookkeeping must not wake a parked builder. These are GitHub event-type suffixes,
  // not record kinds: the authoritative work.assigned issue comment still passes commentGate().
  const filters: Filter[] = [
    { any: own },
    { not: { any: [".labeled", ".unlabeled", ".assigned"].map((type) => ({ suffix: { type } })) } },
  ];
  // With signer omitted all signed bots without work markers pass; supply it for loop avoidance.
  // Loop avoidance only: the builder's own signed bot posts. A signature is never authentication.
  if (signer !== undefined) filters.push({ not: { exact: { "data.signed_by": signer } } });
  const checked = checkFilters(filters);
  if (!checked.ok) return { ok: false, message: `${checked.path}: ${checked.message}` };
  return { ok: true, filters: checked.filters, key: `assignment:${repo}#${issue}` };
}

/** JSON with object keys sorted at every level, so equal filters compare equal however they were written. */
export function canonicalJson(value: unknown): string {
  const sort = (node: unknown): unknown => {
    if (Array.isArray(node)) return node.map(sort);
    if (node !== null && typeof node === "object") {
      return Object.fromEntries(
        Object.keys(node)
          .sort()
          .map((key) => [key, sort((node as Record<string, unknown>)[key])]),
      );
    }
    return node;
  };
  return JSON.stringify(sort(value));
}
