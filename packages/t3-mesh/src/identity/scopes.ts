// Scopes in grants (SPEC.md section 14.4). A grant lists them expanded; shorthand is only accepted
// when signing.
import { isConnectorId } from "../address.ts";

export const RUNTIME_MODES = ["approval-required", "auto-accept-edits", "auto", "full-access"] as const;
export type RuntimeMode = (typeof RUNTIME_MODES)[number];

export const isRuntimeMode = (value: string): value is RuntimeMode => (RUNTIME_MODES as readonly string[]).includes(value);

/** The lower of two runtime modes. */
export const lowerMode = (a: RuntimeMode, b: RuntimeMode): RuntimeMode =>
  RUNTIME_MODES.indexOf(a) <= RUNTIME_MODES.indexOf(b) ? a : b;

const BASE_SCOPES = [
  "messages:send",
  "messages:receive",
  "events:subscribe",
  "files:send",
  "files:receive",
  "forks:send",
  "forks:receive",
] as const;
type BaseScope = (typeof BASE_SCOPES)[number];
const isBaseScope = (value: string): value is BaseScope => (BASE_SCOPES as readonly string[]).includes(value);

/** Every scope at its widest: what `*` expands to. */
export const ALL_SCOPES: readonly string[] = [
  "messages:send",
  "messages:receive",
  "events:subscribe",
  "files:send",
  "files:receive",
  "forks:send",
  "forks:receive/full-access",
];

/** What a connector token without a pairing entry may do (SPEC.md section 14.4). */
export const UNPAIRED_SCOPES: readonly string[] = ["messages:send", "messages:receive", "events:subscribe"];

const SHORTHAND: Readonly<Record<string, readonly string[]>> = {
  "*": ALL_SCOPES,
  "messages:*": ["messages:send", "messages:receive"],
  "events:*": ["events:subscribe"],
  "files:*": ["files:send", "files:receive"],
  "forks:*": ["forks:send", "forks:receive/full-access"],
};

export class ScopeError extends Error {}

interface ParsedScope {
  readonly base: BaseScope;
  /** Send scopes: the connectors allowed, or null for any. */
  readonly recipients: readonly string[] | null;
  /** forks:receive: the highest runtime mode. */
  readonly mode: RuntimeMode | null;
}

function parseScope(scope: string): ParsedScope {
  const fail = (why: string): never => {
    throw new ScopeError(`invalid scope ${JSON.stringify(scope)}: ${why}`);
  };
  if (scope.startsWith("forks:receive")) {
    const mode = scope.slice("forks:receive".length);
    if (!mode.startsWith("/")) return fail(`forks:receive needs a mode: forks:receive/<${RUNTIME_MODES.join("|")}>`);
    const name = mode.slice(1);
    return isRuntimeMode(name) ? { base: "forks:receive", recipients: null, mode: name } : fail(`unknown mode ${name}`);
  }
  const equals = scope.indexOf("=");
  const base = equals < 0 ? scope : scope.slice(0, equals);
  if (!isBaseScope(base)) return fail(`unknown scope; known: ${BASE_SCOPES.join(", ")}`);
  if (equals < 0) return { base, recipients: null, mode: null };
  if (base !== "files:send" && base !== "forks:send") return fail("only send scopes take =<connector ids>");
  const recipients = scope.slice(equals + 1).split(",");
  const bad = recipients.filter((id) => !isConnectorId(id));
  if (recipients.length === 0 || bad.length > 0) return fail(`invalid connector id ${bad.join(", ") || "(none)"}`);
  return { base, recipients: [...new Set(recipients)].sort(), mode: null };
}

const formatScope = (scope: ParsedScope): string =>
  scope.mode !== null ? `${scope.base}/${scope.mode}` : scope.recipients !== null ? `${scope.base}=${scope.recipients.join(",")}` : scope.base;

/**
 * Expands shorthand and checks every scope; the result is what a grant lists. Throws ScopeError on
 * an unknown scope or two forms of the same scope.
 */
export function expandScopes(input: readonly string[]): string[] {
  if (input.length === 0) throw new ScopeError("a grant needs at least one scope");
  const byBase = new Map<BaseScope, ParsedScope>();
  for (const scope of input.flatMap((item) => SHORTHAND[item] ?? [item])) {
    const parsed = parseScope(scope);
    const existing = byBase.get(parsed.base);
    if (existing !== undefined && formatScope(existing) !== formatScope(parsed)) {
      throw new ScopeError(`${formatScope(existing)} and ${formatScope(parsed)} are two forms of ${parsed.base}`);
    }
    byBase.set(parsed.base, parsed);
  }
  return BASE_SCOPES.flatMap((base) => {
    const scope = byBase.get(base);
    return scope === undefined ? [] : [formatScope(scope)];
  });
}

/** What a list of granted scopes allows. Unknown entries (from a newer version) are ignored. */
export class ScopeSet {
  readonly #scopes = new Map<BaseScope, ParsedScope>();

  constructor(scopes: readonly string[]) {
    for (const scope of scopes) {
      try {
        const parsed = parseScope(scope);
        this.#scopes.set(parsed.base, parsed);
      } catch {
        // A scope this version does not know grants nothing here.
      }
    }
  }

  has(base: "messages:send" | "messages:receive" | "events:subscribe" | "files:receive"): boolean {
    return this.#scopes.has(base);
  }

  /** Whether the holder may send `kind` to connector `to`. */
  maySend(kind: "files" | "forks", to: string): boolean {
    const scope = this.#scopes.get(kind === "files" ? "files:send" : "forks:send");
    return scope !== undefined && (scope.recipients === null || scope.recipients.includes(to));
  }

  /** The highest mode a received fork may run in, or null without forks:receive. */
  forkCeiling(): RuntimeMode | null {
    return this.#scopes.get("forks:receive")?.mode ?? null;
  }

  mayForkOut(): boolean {
    return this.#scopes.has("forks:send");
  }
}
