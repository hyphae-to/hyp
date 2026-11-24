// Routing keys of bayfold work records and requests in GitHub comments (process-system slice E;
// docs/builder-subscriptions.md E1). The grammar is slice A's tools/work_records.py, not a separate one:
// src/github/conformance/work-records.json is slice A's own reviewed conformance corpus, copied unmodified,
// and records.test.ts requires the same verdict on every case.
//
// These fields only let subscribers filter (e.g. wake a builder for `job.finished`, not for every
// bookkeeping record). They never authenticate: anyone can post a comment with a marker. The
// trusted writer validates records, and consumers read GitHub again before acting. One deliberate
// difference from A: a payload or provenance whose *contents* A refuses (A's `payload` code) still
// routes, because routing does not re-implement the writer's payload schemas; the writer refuses it.

export const RECORD_MARKER = "<!-- bayfold-record:v1 -->";
export const REQUEST_MARKER = "<!-- bayfold-request:v1 -->";

/** A's kinds (tools/work_records.py at 71e1eeee75); records.test.ts checks them against A's corpus. */
export const RECORD_KINDS: ReadonlySet<string> = new Set([
  "hold.resolved",
  "hold.set",
  "job.claim_expired",
  "job.claimed",
  "job.dispatch_unknown",
  "job.dispatched",
  "job.dispatching",
  "job.finished",
  "job.handled",
  "job.requested",
  "merge.admitted",
  "merge.landed",
  "merge.removed",
  "promotion.aborted",
  "promotion.done",
  "promotion.requested",
  "request.deferred",
  "request.refused",
  "request.withdrawn",
  "revocation.recorded",
  "subscription.desired",
  "work.assigned",
  "work.disposed",
  "work.parked",
]);
/** A's ENVELOPE_KEYS; a record also carries `provenance`, a request never does. */
export const ENVELOPE_KEYS: readonly string[] = [
  "kind",
  "operation_id",
  "payload",
  "previous_record_id",
  "record_id",
  "schema",
  "sequence",
  "work",
];

export interface RecordKeys {
  /** `bayfold-record:v1` or `bayfold-request:v1` when a marker line is present (even if the rest is bad). */
  record_marker: string | null;
  record_kind: string | null;
  record_id: string | null;
  record_operation_id: string | null;
  record_work: string | null;
  record_sequence: number | null;
}

export const emptyRecordKeys = (): RecordKeys => ({
  record_marker: null,
  record_kind: null,
  record_id: null,
  record_operation_id: null,
  record_work: null,
  record_sequence: null,
});

// Python's re.M treats only "\n" as a line break; JavaScript's `m` flag also breaks lines at "\r",
// "\u2028" and "\u2029". Lines are therefore delimited explicitly, never with `^`/`$` and `m`.
const markerLine = (marker: string): RegExp =>
  new RegExp(`(?<=^|\\n)[ \\t]*${marker.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}[ \\t]*(?=\\n|$)`, "g");
const RECORD_LINE = markerLine(RECORD_MARKER);
const REQUEST_LINE = markerLine(REQUEST_MARKER);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
// A's WORK_REF, bounded by GitHub's own limits (owner 39, repository 100, issue number 9 digits), so a
// record with an absurd `work` cannot push the event past the receiver's size limit and lose it. This
// is a deliberate difference from A, which accepts any length: such a record routes with its marker alone.
const WORK = /^[A-Za-z0-9_.-]{1,39}\/[A-Za-z0-9_.-]{1,100}#[1-9][0-9]{0,8}$/;
/** Whether `work` is an owner/repo#issue reference within GitHub's limits: what E routes and attests. */
export const isWorkReference = (work: string): boolean => WORK.test(work);
const MAX_SEQUENCE = 10_000;
/**
 * A's explicit JSON limits (MAX_JSON_BYTES, MAX_JSON_INT_DIGITS, MAX_JSON_DEPTH in tools/work_records.py),
 * which records.test.ts requires to equal the pinned corpus's header. A refuses a block over the size
 * (`size`), an integer literal with more digits, sign excluded, or arrays and objects nested deeper,
 * the root counting as one level (`json`). Such a comment routes with its marker alone.
 */
export const JSON_LIMITS = { maxJsonBytes: 16_384, maxJsonIntDigits: 640, maxJsonDepth: 32 } as const;
/** Bound envelope parsing by UTF-16 code units; larger bodies still expose marker presence. */
const MAX_BODY_CODE_UNITS = 65_536;

const isObject = (value: unknown): value is Readonly<Record<string, unknown>> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

/**
 * Whether every string in a parsed JSON value, keys included, is well-formed UTF-16. JSON.parse
 * accepts an escaped lone surrogate ("\\ud800"); A's loader refuses the document as invalid JSON.
 * The walk keeps its own stack, so a deep document can never overflow the call stack and fail the
 * whole delivery, whatever the depth limit.
 */
const wellFormed = (value: unknown): boolean => {
  const pending: unknown[] = [value];
  while (pending.length > 0) {
    const next = pending.pop();
    if (typeof next === "string") {
      if (!next.isWellFormed()) return false;
    } else if (Array.isArray(next)) {
      for (const inner of next) pending.push(inner);
    } else if (next !== null && typeof next === "object") {
      for (const [key, inner] of Object.entries(next)) {
        if (!key.isWellFormed()) return false;
        pending.push(inner);
      }
    }
  }
  return true;
};

const NUMBER = /-?([0-9]+)(\.[0-9]+)?([eE][-+]?[0-9]+)?/y;
const LITERAL = /true|false|null/y;

/**
 * What JSON.parse cannot tell about valid JSON text: whether any object repeats a key (after
 * unescaping), at any depth; whether any integer literal (no fraction or exponent) has more digits than
 * A reads; whether arrays and objects nest deeper than A allows, counting brackets outside strings with
 * the root as level 1; and the raw token of each top-level primitive value. A's loader refuses all
 * three, and A requires `int` for schema and sequence, so `1.0` or `1e0` are not 1 there.
 */
export function scanJson(text: string): {
  readonly duplicate: boolean;
  readonly longInteger: boolean;
  readonly tooDeep: boolean;
  readonly topLevel: ReadonlyMap<string, string>;
} {
  const stack: Array<Set<string> | null> = [];
  const topLevel = new Map<string, string>();
  let longInteger = false;
  let expectKey = false;
  let pendingKey: string | null = null;
  const primitive = (token: string) => {
    if (stack.length === 1 && pendingKey !== null) topLevel.set(pendingKey, token);
    pendingKey = null;
  };
  for (let i = 0; i < text.length; i += 1) {
    const char = text[i] ?? "";
    if (char === "{" || char === "[") {
      // A top-level value that is an object or array is not a primitive token.
      if (stack.length === 1) pendingKey = null;
      stack.push(char === "{" ? new Set() : null);
      if (stack.length > JSON_LIMITS.maxJsonDepth) return { duplicate: false, longInteger, tooDeep: true, topLevel };
      expectKey = char === "{";
    } else if (char === "}" || char === "]") {
      stack.pop();
      expectKey = false;
    } else if (char === ",") {
      expectKey = stack.at(-1) instanceof Set;
    } else if (char === '"') {
      let end = i + 1;
      while (end < text.length && text[end] !== '"') end += text[end] === "\\" ? 2 : 1;
      const keys = stack.at(-1);
      if (expectKey && keys instanceof Set) {
        const key = JSON.parse(text.slice(i, end + 1)) as string;
        if (keys.has(key)) return { duplicate: true, longInteger, tooDeep: false, topLevel };
        keys.add(key);
        expectKey = false;
        if (stack.length === 1) pendingKey = key;
      } else {
        primitive(text.slice(i, end + 1));
      }
      i = end;
    } else if (char === "-" || (char >= "0" && char <= "9")) {
      NUMBER.lastIndex = i;
      const match = NUMBER.exec(text);
      const token = match?.[0] ?? char;
      if (match?.[2] === undefined && match?.[3] === undefined && (match?.[1]?.length ?? 0) > JSON_LIMITS.maxJsonIntDigits) longInteger = true;
      primitive(token);
      i += token.length - 1;
    } else if (char === "t" || char === "f" || char === "n") {
      LITERAL.lastIndex = i;
      const token = LITERAL.exec(text)?.[0] ?? char;
      primitive(token);
      i += token.length - 1;
    }
  }
  return { duplicate: false, longInteger, tooDeep: false, topLevel };
}

const OPENER = /^```json[ \t]*$/;
const CLOSER = /^```[ \t]*$/;

/**
 * The contents of the ```json blocks in `body` from `from` on, exactly as A's `fence_blocks(body, from)`
 * finds them, which is the regex `^```json[ \t]*\n(.*?)\n```[ \t]*$` (re.M, re.S) found repeatedly:
 * - a block opens on a line that is "```json" and then only spaces or tabs, ended by "\n";
 * - it closes on the first later line, never the one right after the opener, that is "```" and then only
 *   spaces or tabs; its content is everything in between;
 * - the search resumes after the closing line. An opener with no closer after it matches nothing, and
 *   neither does any later opener, since a closer after one would be after all earlier ones.
 * One forward pass over the lines. A lazy regex retried its match from every unclosed opener, which
 * made a comment of many openers quadratic.
 */
export function jsonBlocks(body: string, from: number): string[] {
  const blocks: string[] = [];
  let start = from;
  if (from > 0 && body[from - 1] !== "\n") {
    const newline = body.indexOf("\n", from);
    if (newline === -1) return blocks;
    start = newline + 1;
  }
  let content: number | null = null;
  for (;;) {
    const newline = body.indexOf("\n", start);
    const line = body.slice(start, newline === -1 ? body.length : newline);
    if (content === null) {
      if (newline !== -1 && OPENER.test(line)) content = newline + 1;
    } else if (start > content && CLOSER.test(line)) {
      blocks.push(body.slice(content, start - 1));
      content = null;
    }
    if (newline === -1) return blocks;
    start = newline + 1;
  }
}

/** A JSON integer literal, as Python's json reads into `int`. */
const INTEGER_TOKEN = /^-?(0|[1-9][0-9]*)$/;

/**
 * The routing keys of a comment body. A record marker wins over a request marker. Anything A's
 * json_block or envelope checks refuse keeps only `record_marker` (so it is not taken for an ordinary
 * comment) and leaves every other key null.
 */
export function recordKeys(body: string | null): RecordKeys {
  const keys = emptyRecordKeys();
  if (body === null) return keys;
  const records = [...body.matchAll(RECORD_LINE)];
  const requests = [...body.matchAll(REQUEST_LINE)];
  const which = records.length > 0 ? "record" : requests.length > 0 ? "request" : null;
  if (which === null) return keys;
  keys.record_marker = which === "record" ? "bayfold-record:v1" : "bayfold-request:v1";
  // A GitHub-length body can exceed this bound when it includes non-BMP characters. Retain the
  // marker even when refusing envelope parsing, so a signature cannot admit it as an ordinary post.
  if (body.length > MAX_BODY_CODE_UNITS) return keys;
  const lines = which === "record" ? records : requests;
  if (lines.length !== 1 || (which === "record" && requests.length > 0)) return keys;
  const after = (lines[0]?.index ?? 0) + (lines[0]?.[0].length ?? 0);
  const blocks = jsonBlocks(body, after);
  if (blocks.length !== 1) return keys;
  const text = blocks[0] ?? "";
  if (Buffer.byteLength(text, "utf8") > JSON_LIMITS.maxJsonBytes) return keys;
  let document: unknown;
  try {
    document = JSON.parse(text);
  } catch {
    return keys;
  }
  const scanned = scanJson(text);
  if (scanned.duplicate || scanned.longInteger || scanned.tooDeep || !isObject(document) || !wellFormed(document)) return keys;
  // A requires a JSON integer for these, not merely an integral number.
  for (const key of ["schema", "sequence"]) if (!INTEGER_TOKEN.test(scanned.topLevel.get(key) ?? "")) return keys;
  const expected = which === "record" ? [...ENVELOPE_KEYS, "provenance"].sort() : ENVELOPE_KEYS;
  const present = Object.keys(document).sort();
  if (present.length !== expected.length || present.some((key, i) => key !== expected[i])) return keys;
  if (document["schema"] !== 1) return keys;
  const { kind, record_id: recordId, operation_id: operationId, work, sequence, previous_record_id: previous } = document;
  if (typeof recordId !== "string" || !UUID.test(recordId)) return keys;
  if (typeof operationId !== "string" || !UUID.test(operationId)) return keys;
  if (typeof kind !== "string" || !RECORD_KINDS.has(kind)) return keys;
  if (typeof work !== "string" || !isWorkReference(work)) return keys;
  if (typeof sequence !== "number" || !Number.isInteger(sequence) || sequence < 1 || sequence > MAX_SEQUENCE) return keys;
  if (sequence === 1 ? previous !== null : typeof previous !== "string" || !UUID.test(previous) || previous === recordId) {
    return keys;
  }
  keys.record_kind = kind;
  keys.record_id = recordId;
  keys.record_operation_id = operationId;
  keys.record_work = work;
  keys.record_sequence = sequence;
  return keys;
}
