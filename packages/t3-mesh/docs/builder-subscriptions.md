# Builder subscriptions and status (process-system slice E)

Companion to [bayfold/monorepo#4523](https://github.com/bayfold/monorepo/issues/4523) under
integration [#4516](https://github.com/bayfold/monorepo/pull/4516). Behaviour source:
monorepo `docs/design/process-system.md` §§2–3, 9. **Status: deployed 2026-11-10 at t3-mesh `11180d9`:
the receiver and router through bayfold/infra#271, the connectors with `scripts/upgrade.sh
--connector-only`.** Lead attestation (E6) stays off until it is provisioned.

Bogdan's direction (2026-11-09): keep it simple, even at the cost of breaking existing callers;
the skill is updated and new builders use the new flow. One subscribe tool, with a required key.
The connector does no admission: no slot grant, no cap or pause check on wakes. Caps are enforced
only where new work is scheduled, from a usage tally; a parked builder that wakes simply shows up
as usage, and some jitter is accepted.

Tested T3 runtime: `0.1.8-nightly.20261109.4399` (this branch's `t3-pin.json` and
`vendor/t3code`), the version solace runs. The old `3238` pin is not evidence for it.

## Deploy targets

| Part | Runs on | Rolled out by |
|---|---|---|
| E1 normalization | GitHub receiver, bayfold-co-ops | bayfold/infra `t3_mesh_commit` pin |
| E5 router status endpoint | router, bayfold-co-ops | same pin |
| E2–E4 subscribe tool, tidy, status export | each connector host | `scripts/upgrade.sh --connector-only` |

A cutover needs both pins to name the same tested commit. Older connectors and routers
ignore the new fields; new tools return `unavailable` against an old router.

## E1. Normalized GitHub fields (receiver)

Added to `data` on every event (always present; `null`/`[]` when not applicable):

| Field | Source |
|---|---|
| `pr_numbers` | every PR a `workflow_run` names; `[number]` for PR, review and PR-comment events |
| `run_id`, `run_attempt`, `workflow_path` | `workflow_run.id`, `.run_attempt`, `.path` |
| `record_marker` | `bayfold-request:v1` or `bayfold-record:v1` (exact marker line in an issue or inline review comment) |
| `record_kind`, `record_id`, `record_operation_id`, `record_work`, `record_sequence` | the one ```json block after the marker (A's envelope) |

Inline review comments carry only `record_marker`; their other record keys stay null. Writer
records are issue comments. This keeps signed inline requests, malformed records and bookkeeping
out of the ordinary comment path without admitting inline writer records.
Bodies over the envelope parser's 65,536 UTF-16 code-unit limit retain marker presence too; the
remaining record keys stay null. Non-BMP text can reach that limit within GitHub's character limit.

The grammar is slice A's, not a second one. `src/github/conformance/work-records.json` is A's own
conformance corpus, copied unmodified from bayfold/monorepo at `71e1eeee75`
(`tools/tests/data/work-records-conformance.json`), which was reviewed and approved at that exact head
(review 5836292885, PR bayfold/monorepo#4535).
- A's generator writes it from A's real `tools/work_records.py`, recorded in the corpus's `source`
  block: git blob `377d0071b3`. `generate_work_records_conformance.py --check` passes at that head.
- E pins it by SHA-256 (`e436ca30bd…`).
- It has 50 cases, among them CRLF, duplicate keys, `1.0` sequences, provenance rules, size, lone
  surrogates, an attestation carrier, a non-string kind, and both sides of each JSON limit.
- `src/github/records.test.ts` requires A's verdict on every case, and E's kind list is A's (24).
- **JSON limits.** A states its limits explicitly, so no interpreter setting changes a verdict. The
  corpus header carries them, and `JSON_LIMITS` in `src/github/records.ts` must equal it:
  - a block over 16384 bytes is `size`;
  - an integer literal over 640 digits, sign excluded, is `json`; a float has no digit limit;
  - arrays and objects nested deeper than 32 levels, with the root as level 1 and only brackets
    outside strings counted, are `json`.
  Either way the comment routes with its marker alone. Beyond the corpus, the test file checks A's
  verdicts at 5688f6aa2a, b1168eca05 and 71e1eeee75 (Python 3.12.13) on bodies at and around each limit, including nesting
  that only the depth check refuses. The walk over the parsed document keeps its own stack, so it
  never depends on the depth limit.

Two deliberate differences from A:
- Content A refuses under its `payload` code still routes, because routing does not re-implement
  payload schemas; the writer refuses it.
- A `work` reference beyond GitHub's own limits (owner 39 characters, repository 100, issue number 9
  digits; 150 characters at most) routes with its marker alone, though A's envelope check accepts any
  length. It keeps the event small. The connector signs only references the receiver routes (E6).

To move to a newer corpus, copy A's next reviewed file and update the pin; E keeps no generator of its own.

The ```json block is found the way A's `fence_blocks` finds it, in one forward pass over the lines: the
regex `^```json[ \t]*\n(.*?)\n```[ \t]*$` (multiline, dot-all) found repeatedly, without its quadratic
search. A lazy regex retried from every unclosed opener, so 64 KiB of unclosed openers cost about 470 ms
of receiver CPU; the line scan takes a few milliseconds. A made the same change at b1168eca05, and the
corpus covers the fence grammar.

**`record_*` fields route notifications; they never authenticate.** Authority stays
with the trusted writer's validation and a fresh GitHub read. `data.number` keeps its one-PR meaning.

`check_suite` is **not** added: `workflow_run.completed` covers Actions CI. It would be added
only for a demonstrated gap, mapped to one result per head to avoid double wakes.

## E2. One subscription per key (connector)

`mesh_subscribe` now takes a required key and creates or updates (breaking change). The caller is
resolved as in SPEC §3, the verified calling thread:

```text
mesh_subscribe {key, topic, filters?, template?, coalesceSeconds?}
  -> {id, outcome: "created" | "updated" | "unchanged", filters}
```

- `key` names what the subscription is for, e.g. `assignment:<owner>/<repo>#<issue>` or
  `watch:bayfold/infra#12` (pattern `^[a-z][a-z0-9-]{0,31}:[A-Za-z0-9._/#:-]{1,120}$`). It is unique per
  (thread, key):
  - the same canonical filters and coalescing return `unchanged`;
  - different ones update the subscription in place (same ID; the router keeps pending batches,
    SPEC §12.5);
  - a different topic is refused (`invalid`), because the router would drop the pending batches;
    unsubscribe first.

  A call without a key is refused (`invalid`). Keyless subscriptions made before the change keep
  working until unsubscribed by ID.
- Give exactly one of `filters` (raw, SPEC §12.3) or `template`:

```text
template: {kind: "builder", repo, issue, pr?, branch?, signer?,
           parents?: [{repo, pr?, issue?}]}
```

  The template generates canonical narrow filters. It matches:
  - the issue and PR subjects;
  - `workflow_run.completed` where `data.pr_numbers` has the PR or `data.branch` is the branch;
  - a parent PR's `pull_request.closed`, or a parent issue's `issues.closed`;
  - comments, on the issue or inline in a review, that are either a person's
    (`author_type: User`) or a bot with nonempty `signed_by`, both without a work marker,
    or writer records in issue comments of kind `job.finished`,
    `job.dispatch_unknown`, `hold.set`, `hold.resolved`, `work.assigned`, `work.disposed`,
    `merge.removed`, `merge.landed`, `request.refused`, `request.deferred` or `request.withdrawn`.

  Reviews themselves pass, because the reviewer is an app. `signer` drops the builder's own signed
  posts (loop avoidance only); when omitted, every signed bot without a work marker can wake it.
  Unsigned bots do not pass. A generic signature cannot admit requests, bookkeeping or malformed
  work records. `signed_by` is routing metadata, never authentication: re-read GitHub and verify
  the trusted author before acting on a wake. Coalescing defaults to 30 s. The generated filters are
  returned so callers can record them. GitHub `*.labeled`, `*.unlabeled` and `*.assigned` events do not wake it,
  whether a person or a bot changes the metadata. This includes the merge queue's
  `status:in-merge-queue` label. Writer `work.assigned` records still wake it: they arrive as issue
  comments, not GitHub assignment events. Other events on its own issue or PR still wake it,
  including pushes and app reviews. The template stays (Bogdan,
  2026-11-10); the explicit filters below are for callers that want them.
- **Template updates:** filters are expanded by the connector when `mesh_subscribe` is called;
  the stored subscription contains the filters, not the template. After deploying an updated
  connector with this signed-comment change, existing builders must repeat their same-key template
  call to update those filters in place (same subscription ID; pending batches kept). A connector restart alone re-sends the
  stored filters and does not refresh them. Pending events already matched before the update
  can still be delivered. Explicit-filter callers must add the equivalent exclusions themselves.
- **Signed-comment rollout:** update the GitHub receiver first, so inline review comments expose
  work-marker presence, then the connector, then repeat each builder's same-key template call.
  A connector-only update against the old receiver cannot enforce inline work-marker exclusions.
- **Withdrawal** (decision of 2026-11-09, process-system interfaces, slice E):
  - A writer's `request.withdrawn` record on the builder's own issue or PR wakes it, parked or not.
    A records it when a founder revokes an accepted request.
  - The wake only prompts the builder to re-read A's current authority and reconcile. The event
    grants and revokes nothing, and a stale or replayed one cannot restore an assignment.
  - There is no Stop, interruption, cancellation or capacity check in the connector.
  - A withdrawal on other work does not wake the builder.
- **Explicit filters** route exactly like the template, without it. These are for a builder of
  `bayfold/infra#8` with PR 9 that signs as `builder-8`:
  - With a branch, add `{"exact": {"repo": …, "type": "com.github.workflow_run.completed",
    "data.branch": "<branch>"}}` to the outer `any`.
  - With parents, add each parent's `pull_request.closed` or `issues.closed` filter there too.
  - `src/builderSubscriptions.test.ts` reads this block and checks it routes like the template.

<!-- explicit-builder-filters -->
```json
[
  {"any": [
    {"all": [
      {"exact": {"repo": "bayfold/infra"}},
      {"any": [{"exact": {"subject": "issues/8"}}, {"exact": {"subject": "pull/9"}}]},
      {"any": [
        {"all": [
          {"not": {"exact": {"type": "com.github.issue_comment.created"}}},
          {"not": {"exact": {"type": "com.github.pull_request_review_comment.created"}}}
        ]},
        {"all": [{"exact": {"data.author_type": "User"}}, {"not": {"prefix": {"data.record_marker": "bayfold-"}}}]},
        {"all": [
          {"exact": {"data.author_type": "Bot"}},
          {"prefix": {"data.signed_by": ""}},
          {"not": {"exact": {"data.signed_by": ""}}},
          {"not": {"prefix": {"data.record_marker": "bayfold-"}}}
        ]},
        {"all": [
          {"exact": {"type": "com.github.issue_comment.created"}},
          {"exact": {"data.record_marker": "bayfold-record:v1"}},
          {"any": [
            {"exact": {"data.record_kind": "job.finished"}},
            {"exact": {"data.record_kind": "job.dispatch_unknown"}},
            {"exact": {"data.record_kind": "hold.set"}},
            {"exact": {"data.record_kind": "hold.resolved"}},
            {"exact": {"data.record_kind": "work.assigned"}},
            {"exact": {"data.record_kind": "work.disposed"}},
            {"exact": {"data.record_kind": "merge.removed"}},
            {"exact": {"data.record_kind": "merge.landed"}},
            {"exact": {"data.record_kind": "request.refused"}},
            {"exact": {"data.record_kind": "request.deferred"}},
            {"exact": {"data.record_kind": "request.withdrawn"}}
          ]}
        ]}
      ]}
    ]},
    {"exact": {"repo": "bayfold/infra", "type": "com.github.workflow_run.completed", "data.pr_numbers": "9"}}
  ]},
  {"not": {"any": [
    {"suffix": {"type": ".labeled"}},
    {"suffix": {"type": ".unlabeled"}},
    {"suffix": {"type": ".assigned"}}
  ]}},
  {"not": {"exact": {"data.signed_by": "builder-8"}}}
]
```
- `mesh_unsubscribe` accepts `{key}` or `{id}`. `mesh_subscriptions` returns each subscription's
  `key` and, with E5, its `delivery`.
- State: `state.json` subscriptions carry `key`; files from before keys still load.

## E3. Parked builders and standing roles stay unsettled

- `scripts/tidy-children.ts`: a child holding an `assignment:` subscription is held
  (`parked on an assignment`) regardless of idle age. A `role:` subscription (for example
  `role:release` or `role:lead`) also holds a thread, with reason `holds a role subscription`.
  Role threads are normally top-level; tidy also protects them if they are children.
  Settled, archived or deleted threads still lose their subscriptions (SPEC §12.3), so an intentional user settlement wins.
- **T3 settles idle threads itself** after `sidebarAutoSettleAfterDays` (2 days on solace;
  `ThreadSettlementService`), which would end a parked builder's or standing role's subscriptions.
  On 2026-11-11, T3 auto-settled the Release Manager thread and dropped its `role:release` GitHub
  subscription. Both `assignment:` and `role:` keys now protect their threads from auto-settlement.
  - When a thread subscribes with an `assignment:` or `role:` key, the connector dispatches the supported
    `thread.auto-settle.set {enabled: false}`.
  - When its last protected subscription (`assignment:` or `role:`) is removed, it dispatches
    `{enabled: true}`. A thread holding both kinds stays opted out until both are gone.
  - The command ID is the subscription's, so a resume never overrides a user who turned it back on.
  - A user's settle still wins (verified on 4399, `scripts/lifecycle-trial.ts`).
  - If the opt-out fails, `mesh_subscribe` returns a `warning`, since the subscription alone does
    not keep the thread from being settled. Calling it again with the same key retries the opt-out.
  - A fork moves the subscriptions with their keys: the target opts its thread out and the source
    turns auto-settle back on. The target's first turn names each key it could not recreate, with
    the refusal's code, and each protected key whose opt-out failed, so its agent can call
    `mesh_subscribe` again.
  - The target recreates them once, before the fork's first turn. It records each key as it is
    stored, and the outcome when done, in `<stateDir>/forks/<forkId>.json`. A fork offered again
    (its result could not be sent) reuses that outcome: it recreates nothing, so nothing the agent
    removed or changed after its first turn is undone, and that turn's subscription notes are the
    same (T3 replays an accepted first turn as it was). An offer that overlaps a run still going
    joins it. A run cut short by a stop is finished by the next offer, without creating again the
    keys it recorded. Each key is created only if the thread has none, checked in the queue
    `mesh_subscribe` uses. What failed is left to the agent, as its first turn says.
  - Known limit: an event for a subscription already recreated can wake the thread before its first
    turn. A key it removes then stays removed if the run had recorded it; one the run has not reached
    yet is created when it gets there.
  - Known limits:
    - re-enabling on the last unsubscribe also clears an opt-out the user had set before the
      protected subscription;
    - a subscription the router refuses and the connector drops does not re-enable auto-settle
      (except when the drop happens during the same thread's own unsubscribe, which then sees its
      last protected subscription gone);
    - nor do subscriptions removed because the thread was settled (a user's settle, the 30 s sweep,
      startup reconciliation). T3's settle and unsettle leave the opt-out as it was, so a parked
      builder the user settles and later unsettles stays opted out of auto-settle.
- Wakes are delivered like any subscription's. The connector holds nothing for pause, Stop or an
  interrupted run. The status export reports interruptions (E4) for whoever schedules work. T3 4399
  records a user's thread Stop and a narrow `run.interrupt` alike (`latestRunStopRequested`), so the
  flag cannot tell them apart. (Substrate gap, reported to the consultant: T3 would need to persist
  the stop's `holdQueue`.)
- Waking a finished *delegated* child, shown by a model-driven run (`scripts/model-trial.ts`; see
  Evidence):
  - The child runs a new turn in its own thread, with its history.
  - T3 does not continue the original delegated task. It attaches the run to a new task named after
    the connector's command, `node:delegated-task:mesh-event:<batch>:<attempt>`.
  - When that turn ends, its result reaches the parent as a completion for the new task, which starts
    a parent turn. So every wake of a parked builder costs one turn on its parent (the Lead, for
    Lead-delegated builders), and the parent sees a task ID it did not start.

## E4. No admission in the connector; narrow status export for the usage tally

The connector does not gate event delivery. Capacity is enforced where new work is scheduled: the
Lead before `delegate_task`, PM before a recovery send, and slice D's tooling. Those check a usage
tally against the caps. A parked builder that wakes simply adds to the tally, and while slots are
full no additional work is created. Small overshoots (jitter) are accepted; the caps are not
enforced exactly. The connector keeps no slot accounting, grants nothing and calls no helper.

**Status export, the tally's input from this T3:** a file written atomically every 15 s when
`statusExport.enabled` (off by default). `t3-mesh status` prints it and exits 3 when the export is
off, missing, unreadable or more than 60 s old: treat that as unknown. It is read-only for its
consumers; the connector acts on nothing in it.

```ts
interface ExecutionStatus {
  schema: 1; connector: string; generatedAt: string;
  t3ObservedAt: string | null;  // now while connected to T3 (loopback), null while disconnected
  threads: Array<{ threadId: string; parentThreadId: string | null; state: DeliveryState; status: string;
    interruptRequested: boolean;  // latest run (finished or stopping) had a stop/interrupt; a resume clears it
    assignments: string[]; activeRunId: string | null }>;
  counts: { busy: number; parked: number; interrupted: number };
}
```

Threads listed: busy ones, idle ones holding an `assignment:` subscription (`parked`), and
unsettled interrupted ones, standing roles included. A settled thread still holding an assignment
is listed, but not counted, until the 30 s sweep removes its subscriptions. `parked` threads count toward flow, not
execution; busy covers queued, preparing and starting.

## E5. Delivery visibility for reconciliation

Router: `GET /v1/subscriptions/status` (connector token, own subscriptions only, read through
that connector's subscriptions by index):

```ts
{ subscriptions: Array<{ id: string; pending: number; oldestPendingAt: string | null;
  heldReason: string | null;              // the reason for the latest hold, e.g. t3_unavailable
  delivered: number; lastDeliveredAt: string | null;
  rejected: Record<string, number>;
  dropped: Record<string, number>;        // expired, queue_full (removed subscriptions' batches are deleted, not counted)
  lastDroppedAt: string | null }> }      // counts cover the retention window (24 h)
```

Surfaced through `mesh_subscriptions` (`delivery`; null when the router cannot say). Delivery or a
completed run is **not** handled acknowledgement: GitHub work records own follow-up, and PM
reconciles from GitHub when retention (24 h, 100 pending batches) has dropped events.

## E6. Role-decision attestation for slice A's `Origin` seam (built; off unless configured)

Slice A's writer accepts a role's decision only from `Trust.<role>_origins` (`Origin.verify(env,
request, state, probe) -> Verdict`; PR bayfold/monorepo#4522). Shared bots and the founder are
never role identities. This provides the tested Mesh/T3 origin, with no new record kind or store:

- **Signer (connector):** `mesh_attest {role, recordId, envelopeSha256, work}`. The connector
  checks the *verified calling thread* (SPEC §3) is configured for the role
  (`config.json` `attest.roles.<role>: [threadId…]`, own keys only; absent means `not_configured`;
  no readable identity key, e.g. before pairing, means `not_paired`, without the key's path). It then signs with
  its paired Ed25519 identity key (`keys.json`), as SignatureKind `attestation`, i.e. the bytes
  `t3-mesh/v1/attestation\n` + payload JSON:
  `{v:1, kind:"bayfold-decision", role, connector, threadId, record_id, envelope_sha256, work, issuedAt}`.
  `envelope_sha256` is A's `envelope_digest(env)`, the same binding as the founder's `bayfold-approve`.
  A payload too long for the verifiers' limit is refused (`invalid`) rather than signed.
- **Carrier:** the agent appends the returned `bayfold-attest: v1 <payload b64url> <sig b64url>` line
  to its request comment (after the json block; since efdb4fc301 A's `render(..., attestation=)` places it). The line
  is carried byte-for-byte, posted promptly (freshness is measured at the comment's creation), and a
  retried submit reuses the same comment rather than re-attesting.
- **Wire format** (`readAttestation` in `src/attest.ts`, `read_attestation` in the Python reference;
  one format, no fork):
  - lines split on `\n` and trimmed of spaces, tabs and `\r`; exactly one starts `bayfold-attest:`, and
    it is exactly `bayfold-attest: v1 <payload> <signature>` with single spaces;
  - both fields canonical unpadded base64url, the payload field at most 1024 characters (no nesting
    deep enough to exhaust a parser); the signature is 64 bytes over the raw payload bytes;
  - neither the pinned key nor the signature's R is a small-order point, in any encoding. Backends
    disagree on both: Python's bundled OpenSSL 4.0.3 verifies forgeries under a small-order key, and
    accepts a key holder's signature with an identity R; Node's 3.5.8 does neither.
  - the payload is strict UTF-8 JSON with exactly the nine keys, no duplicates or NaN; `v` is the
    integer 1 and the rest are strings; `issuedAt` is `YYYY-MM-DDTHH:MM:SS.mmmZ`, a real time, year
    0001 or later.

  The Python verifier never raises: malformed input or comment metadata is a refusal (freshness uses
  subtraction only, so times near A's range limits cannot overflow), because A's `_origin` catches
  only `Unavailable`.
- **Verifier (writer):** `docs/reference/mesh_attestation_origin.py` implements `Origin`. It checks:
  - exactly one line;
  - the signature by the pinned connector key;
  - role, connector and configured thread;
  - record_id, digest and work equal to this request;
  - issuedAt ≤ comment time + 60 s and ≥ comment time − 10 min;
  - the comment is unedited, and is the first request comment carrying this record ID (A's rule for
    founder approvals);
  - the founder has not revoked this record anywhere on the issue (`state.revocations`). The
    first-comment rule sees only comments that still exist. Without this check, deleting the
    original or editing its record ID away, then reposting the same bytes after a `bayfold-revoke`,
    would replay the attestation within its 10 minutes.

  Shared weakness with A's founder rule: anyone who can comment can edit an older comment into a
  copy carrying the record ID. The real request is then not the first, and is refused for good; it
  needs a new record ID. Nothing is accepted that way.

  The reference Origin's revocation check sees only revocation comments that still exist. A
  deleted `bayfold-revoke` comment, or one edited so it no longer carries the line, would let a
  repost of the attested request be accepted again within the attestation's 10 minutes. A's
  adopted writer closes this once any writer pass has read the revocation:
  - it records every founder revocation durably (`revocation.recorded`);
  - it counts its own `revoked` refusal receipt as revocation evidence (bayfold/monorepo#4522, in
    `work_mesh_origin`).

  What remains is a revocation posted and deleted before any writer pass reads the issue. Only
  GitHub's permissions on deleting others' comments limit that.

  Otherwise it refuses, failing closed.
- **Evidence:** `src/fixtures/attestation-vector.json` uses a fixed-seed key over a request rendered by A's
  real `render()`, with A's real digest. Its `cases` are full request comments with the verdict both
  verifiers must give. That covers the valid line (also with CRLF and indented), impossible, padded and
  non-canonical encodings, wrong signature length, separators, versions, extra fields, two lines, and
  signed payloads that are not JSON, not UTF-8, carry a BOM, are UTF-16, have `v` true or 1.0, NaN,
  duplicate or extra or missing keys, a list `threadId`, another kind, or an `issuedAt` without zone,
  with an offset, impossible or in year 0000, a deeply nested payload, a payload field over 1024
  characters, and a key holder's signature with an identity R: 32 cases. `smallOrderKeys` lists
  eight small-order key encodings both sides refuse.
  TS: `src/attest.test.ts`, which also checks the whole vector file is current.
  Python self-test, 56/56 against A's `work_records.py` at 6096f8ac47, 4e9c83b508, efdb4fc301, 5688f6aa2a, b1168eca05 and 71e1eeee75 (the pinned corpus's head):
  - the 10 binding and freshness cases, one with a comment time at the end of A's range;
  - the 8 small-order keys;
  - the 32 shared cases;
  - six end-to-end cases through A's own `reduce` and `evaluate`:
    - the Lead's attested request is accepted, and so is the same request posted later when nothing
      was revoked;
    - it is not accepted after a founder revocation;
    - nor is a repost after the revocation, whether the original was edited, edited to drop its
      record ID, or deleted.

  The reviewer's differential probes agree too: 90 extra cases, 0 TS/Python forks; 14 small-order
  encodings plus 2,000 random keys, 0 disagreements. A adopted the format at efdb4fc301 as
  `tools/work_mesh_origin.py`. Its test pins a byte-identical copy of this vector (sha256 `0e94a7b2…`)
  and names this reference module's sha256, so a change here must be adopted there deliberately.
- **Provisioning (cutover; needs Bogdan):**
  - configure `attest.roles.lead` on the Lead's connector;
  - pin that connector's public key (`rawPublicKey` of `keys.json` signing; listed in the router
    directory after pairing) and the Lead thread IDs in the writer's `Trust.lead_origins`.

  It proves which thread asked through which connector, not that the decision is right. A prompt-injected
  Lead could still attest a bad request; scope checks stay in the writer. Revoking the connector in
  the mesh does not revoke its attestations, because the writer pins the key: only removing it from
  `Trust.lead_origins` (or rotating the key and re-pinning) does.

## Dependencies

- From A (published): the marker/envelope format, which E1 parses read-only, and A's conformance
  corpus, pinned at 71e1eeee75 (E1).
- From D/PM/Lead: the usage tally and cap check at scheduling time, reading the status export. The
  connector needs nothing back.
- Overlap: bayfold/t3-mesh PR #32 also edits `scripts/tidy-children.ts` (a settle T3 refuses
  is not a failure). Whichever merges second rebases; this branch does not duplicate it.

## Evidence

There are three kinds, kept apart. Unit test totals at a head say nothing about the dev proof, and
the reverse:
- unit tests on fixtures (vendored T3 contracts, no live T3);
- the lifecycle proof on a disposable dev T3 0.1.8-nightly.20261109.4399, the live runtime;
- what is still unproven.

**Unit tests** (`node --test 'src/**/*.test.ts'`, pinned vendored contracts, no live T3):

| Acceptance case | How | Result |
|---|---|---|
| One subscription per (thread, key); a call without a key is refused; excludes unrelated PRs | `src/builderSubscriptions.test.ts`, `src/subscriptions.test.ts`, real router matcher | pass |
| A `request.withdrawn` record wakes the builder of the affected issue or PR (template or documented explicit filters); withdrawal on other work, another repo's same number, or a person's request does not; the documented explicit filters route like the template on every wake case | `src/builderSubscriptions.test.ts`, real router matcher | pass |
| A fork carries every subscription with its key (a keyless one from before as `legacy:<id>`); the target recreates them, also from an older sender without keys | `src/subscriptions.test.ts` (two real routers) | pass |
| A fork's target names each key it could not recreate (a string that is not a key is not echoed) and each failed assignment opt-out | `src/subscriptions.test.ts` (`recreateForkedSubscriptions`, real router) | pass |
| A fork recreates once: offered again, it reuses the recorded outcome and runs nothing, so a removed assignment stays removed and a narrowed watch keeps its filters; an offer overlapping a run still going joins it; a run cut short is finished without creating its recorded keys again (one removed meanwhile stays removed; a held assignment gets its opt-out again); a `mesh_subscribe` made while the recreate runs is never overwritten; each key is recorded inside the subscription queue, before a change queued behind it | `src/subscriptions.test.ts` (real router; a gated router link for the race; `recreateOnce`, `subscribeIfMissing`) | pass |
| Review / CI (multi-PR run, branch-only run) / parent merge wakes | real webhook fixtures → `normalize()` → router | pass |
| Other agents' signed bot comments and ordinary human comments on the builder's issue/PR, inline included, wake; self-signed or unsigned bot comments, unrelated work, requests, bookkeeping and malformed records do not. Inline work markers never admit writer records, including allowlisted kinds. | `src/builderSubscriptions.test.ts`, `src/github/normalize.test.ts`, real router matcher | pass |
| Repeating the same-key template call enables signed-comment wakes in place and preserves the pending batch | `src/builderSubscriptions.test.ts`, real router | pass |
| Resume twice → still one subscription; scope change updates in place; topic change refused with a waiting batch kept | same | pass |
| Role subscribe opts out, warns on failure and retries with the same ID; mixed assignment/role keys re-enable only when the last protected key leaves, in either order | `src/subscriptions.test.ts` (fake T3 callback) | pass |
| A fork opts out for a role key, reports failures and retries a held role after a stop | `src/subscriptions.test.ts` (fake T3 callback) | pass |
| >65-minute parked or role-holding child survives tidy (fake clock); an intentional settlement still wins | `src/lifecycle.test.ts` | pass |
| The status export lists busy, parked and interrupted threads (standing roles and stopping runs included), nothing else; role keys do not count as parked assignments; unknown while disconnected | `src/lifecycle.test.ts` | pass |
| `t3-mesh status`: exit 0 for a fresh status; 3 for stale, future-dated, disconnected or unreadable | `src/lifecycle.test.ts` (rules), the CLI run on fresh, stale and corrupt files | pass |
| Router status query uses the connector's subscriptions (no batch table scan) | `src/deliveryStatus.test.ts` (EXPLAIN QUERY PLAN) | pass |
| Retention expiry visible for reconciliation; old router = unknown | `src/deliveryStatus.test.ts` (HTTP, fake clock) | pass |
| Record keys agree with A's parser on all 50 cases of A's reviewed corpus (71e1eeee75, pinned by SHA-256 with its parser blob); E's kinds are A's 24; E's JSON limits equal the corpus header (16384 bytes, 640 integer digits, depth 32); bodies at and around each limit, including nesting only the depth check refuses, get A's verdict (Python 3.12.13); a `work` longer than GitHub allows does not route; json blocks are found as A's `fence_blocks` finds them (its results on 14 edge cases; the earlier regex on 2,000 seeded layouts), and 64 KiB of unclosed openers takes under 50 ms of CPU (about 3 ms; the regex took about 470) | `src/github/records.test.ts` | pass |
| Role attestation: TS and the Python Origin agree on 32 shared wire-format cases; small-order keys and R; binding, freshness, never raising; replay after revocation (edited, record-dropped or deleted original) not accepted through A's reduce/evaluate | vector + `docs/reference/mesh_attestation_origin.py` vs A 6096f8ac47, efdb4fc301, 5688f6aa2a, b1168eca05 and 71e1eeee75 | 56/56 pass |

**Dev lifecycle proof** (`scripts/lifecycle-trial.ts <t3 binary>`, disposable base dir, no model
credentials, nothing outbound):

| Case | Result on dev 4399 |
|---|---|
| `thread.auto-settle.set` off accepted from a connector client and shown in the shell | pass |
| A repeated command ID does not override the user's re-enable; a new assignment applies | pass |
| The shell carries `latestRunStopRequested` (informational only) | pass |
| A user's settle wins over the opt-out; the connector classifies it settled | pass |

**Model-driven proof** (`scripts/model-trial.ts <t3 binary> --model claude-opus-5-5`, disposable base
dir, real Opus turns with the operator's existing Claude login; 2026-11-09 on dev 4399):

| Case | Result |
|---|---|
| The same wake command (`mesh-event:<batch>:1`) sent three times: first, again on the same connection (a lost ack), and again on a new T3 connection (standing in for a restart; the connector process was not restarted) | T3 returns the same receipt (sequence 107) all three times; the child gets one message and one run |
| A finished delegated child woken by message.dispatch as the connector does | It runs a new turn in its own thread, with its history (it replied as asked) |
| Task generation | Not the original task: T3 attaches the run to a new delegated task, `node:delegated-task:mesh-event:<batch>:1` |
| Parent result route | The child's new result reaches the parent as a completion for that new task and starts a parent turn (1 → 2 runs) |

**Unproven, not claimed:**

| Case | Needs |
|---|---|
| T3's own auto-settlement of a delegated child over days, in practice | time on a dev instance |
| A wake end to end from GitHub through the receiver, router and connector into a parked builder (the trial dispatched the wake itself) | the first live builders after the 2026-11-10 cutover |

Not covered here, by design: production deploy, the connector pin (`upgrade.sh`) and the infra
router/receiver pin (listed in the cutover manifest), enabling the status export, and moving live
builders off T3 PR watches. Those are cutover steps.
