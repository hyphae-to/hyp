// Subscription filters (SPEC.md section 12.3): the CloudEvents Subscriptions API dialects exact,
// prefix, suffix, all, any and not, over event attributes and top-level `data.<field>` values.
// Shared by the router (matching, and refusing bad filters) and the connector (checking filters
// before it accepts a subscription).
import type { CloudEvent } from "./cloudevent.ts";

export const MAX_FILTERS_BYTES = 4 * 1024;
export const MAX_FILTER_DEPTH = 8;

export type Filter =
  | { readonly exact: Readonly<Record<string, string>> }
  | { readonly prefix: Readonly<Record<string, string>> }
  | { readonly suffix: Readonly<Record<string, string>> }
  | { readonly all: readonly Filter[] }
  | { readonly any: readonly Filter[] }
  | { readonly not: Filter };

export type FilterCheck =
  | { readonly ok: true; readonly filters: readonly Filter[] }
  | { readonly ok: false; readonly path: string; readonly message: string };

/** An attribute name, or `data.<field>` for a top-level field of `data`. */
const KEY = /^(?:[a-z0-9]{1,20}|data\.[^\s]{1,128})$/;
const DIALECTS = ["exact", "prefix", "suffix", "all", "any", "not"] as const;

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

class FilterError extends Error {
  readonly path: string;
  constructor(path: string, message: string) {
    super(message);
    this.path = path;
  }
}

function checkFilter(value: unknown, path: string, depth: number): Filter {
  if (depth > MAX_FILTER_DEPTH) throw new FilterError(path, `filters nest deeper than ${MAX_FILTER_DEPTH}`);
  if (!isRecord(value)) throw new FilterError(path, "a filter must be an object with one dialect key");
  const keys = Object.keys(value);
  const dialect = keys[0];
  if (keys.length !== 1 || dialect === undefined || !(DIALECTS as readonly string[]).includes(dialect)) {
    throw new FilterError(path, `a filter must have exactly one key of ${DIALECTS.join(", ")}`);
  }
  const body = value[dialect];
  const at = `${path}.${dialect}`;
  switch (dialect) {
    case "exact":
    case "prefix":
    case "suffix": {
      if (!isRecord(body) || Object.keys(body).length === 0) {
        throw new FilterError(at, "expected an object of attribute: string, with at least one key");
      }
      for (const [key, expected] of Object.entries(body)) {
        if (!KEY.test(key)) {
          throw new FilterError(`${at}[${JSON.stringify(key)}]`, "keys are attribute names or data.<field>");
        }
        if (typeof expected !== "string") throw new FilterError(`${at}[${JSON.stringify(key)}]`, "values must be strings");
      }
      return { [dialect]: body as Record<string, string> } as Filter;
    }
    case "all":
    case "any": {
      if (!Array.isArray(body) || body.length === 0) throw new FilterError(at, "expected a non-empty array of filters");
      const filters = body.map((item, index) => checkFilter(item, `${at}[${index}]`, depth + 1));
      return dialect === "all" ? { all: filters } : { any: filters };
    }
    default:
      return { not: checkFilter(body, at, depth + 1) };
  }
}

/** Checks a subscription's `filters` array; on failure, `path` points at the bad node. */
export function checkFilters(value: unknown): FilterCheck {
  if (!Array.isArray(value)) return { ok: false, path: "filters", message: "filters must be an array" };
  if (Buffer.byteLength(JSON.stringify(value), "utf8") > MAX_FILTERS_BYTES) {
    return { ok: false, path: "filters", message: `filters exceed ${MAX_FILTERS_BYTES} bytes` };
  }
  try {
    return { ok: true, filters: value.map((item, index) => checkFilter(item, `filters[${index}]`, 1)) };
  } catch (error) {
    if (error instanceof FilterError) return { ok: false, path: error.path, message: error.message };
    throw error;
  }
}

/** Comparable texts of a value: strings as-is, numbers and booleans as JSON, arrays element-wise; null and objects give none. */
function texts(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (typeof value === "number" || typeof value === "boolean") return [JSON.stringify(value)];
  if (Array.isArray(value)) return value.flatMap((item) => (Array.isArray(item) ? [] : texts(item)));
  return [];
}

function lookup(event: CloudEvent, key: string): string[] {
  if (key.startsWith("data.")) {
    const field = key.slice(5);
    return Object.hasOwn(event.data, field) ? texts(event.data[field]) : [];
  }
  if (key === "data" || !Object.hasOwn(event, key)) return [];
  return texts(event[key]);
}

const compare = (
  pairs: Readonly<Record<string, string>>,
  event: CloudEvent,
  test: (actual: string, expected: string) => boolean,
): boolean =>
  Object.entries(pairs).every(([key, expected]) => lookup(event, key).some((actual) => test(actual, expected)));

export function matchesFilter(filter: Filter, event: CloudEvent): boolean {
  if ("exact" in filter) return compare(filter.exact, event, (actual, expected) => actual === expected);
  if ("prefix" in filter) return compare(filter.prefix, event, (actual, expected) => actual.startsWith(expected));
  if ("suffix" in filter) return compare(filter.suffix, event, (actual, expected) => actual.endsWith(expected));
  if ("all" in filter) return filter.all.every((inner) => matchesFilter(inner, event));
  if ("any" in filter) return filter.any.some((inner) => matchesFilter(inner, event));
  return !matchesFilter(filter.not, event);
}

/** The top-level array is ANDed; an empty array matches every event. */
export const matchesFilters = (filters: readonly Filter[], event: CloudEvent): boolean =>
  filters.every((filter) => matchesFilter(filter, event));
