// Zero-dependency runtime schema validators replacing `effect/Schema` across `src/core/`.
// Keeps identical Option/Sync decode semantics with zero third-party bundle or cold-start tax.

export type Option<T> = { readonly _tag: "Some"; readonly value: T } | { readonly _tag: "None" };

export const some = <T>(value: T): Option<T> => ({ _tag: "Some", value });
export const none: Option<never> = { _tag: "None" };

export interface Codec<T> {
  readonly Type: T;
  readonly decode: (input: unknown) => Option<T>;
  readonly optional?: boolean;
}

type OptionalCodec<T> = Codec<T> & { readonly optional: true };

type StructFields = Readonly<Record<string, Codec<any>>>;

type RequiredKeys<F extends StructFields> = {
  [K in keyof F]: F[K] extends { readonly optional: true } ? never : K;
}[keyof F];

type OptionalKeys<F extends StructFields> = {
  [K in keyof F]: F[K] extends { readonly optional: true } ? K : never;
}[keyof F];

type StructOutput<F extends StructFields> = {
  readonly [K in RequiredKeys<F>]: F[K]["Type"];
} & {
  readonly [K in OptionalKeys<F>]?: F[K]["Type"];
};

function makeCodec<T>(decode: (input: unknown) => Option<T>): Codec<T> {
  return { Type: undefined as unknown as T, decode };
}

export const String: Codec<string> = makeCodec((v) => (typeof v === "string" ? some(v) : none));

export const Number: Codec<number> = makeCodec((v) => (typeof v === "number" && globalThis.Number.isFinite(v) ? some(v) : none));

export const Boolean: Codec<boolean> = makeCodec((v) => (typeof v === "boolean" ? some(v) : none));

export const Unknown: Codec<unknown> = makeCodec((v) => some(v));

export function Literal<const T extends string | number | boolean>(expected: T): Codec<T> {
  return makeCodec((v) => (v === expected ? some(expected) : none));
}

export function Literals<const T extends readonly (string | number | boolean)[]>(values: T): Codec<T[number]> {
  const allowed = new Set<unknown>(values);
  return makeCodec((v) => (allowed.has(v) ? some(v as T[number]) : none));
}

export function NullOr<T>(inner: Codec<T>): Codec<T | null> {
  return makeCodec((v) => (v === null ? some(null) : inner.decode(v)));
}

export function optionalKey<T>(inner: Codec<T>): OptionalCodec<T> {
  return { Type: undefined as unknown as T, decode: inner.decode, optional: true };
}

export function Array<T>(item: Codec<T>): Codec<readonly T[]> {
  return makeCodec((v) => {
    if (!globalThis.Array.isArray(v)) return none;
    const out: T[] = [];
    for (const el of v) {
      const res = item.decode(el);
      if (res._tag === "None") return none;
      out.push(res.value);
    }
    return some(out);
  });
}

export function Struct<const F extends StructFields>(fields: F): Codec<StructOutput<F>> {
  const entries = Object.entries(fields);
  return makeCodec((v) => {
    if (typeof v !== "object" || v === null || globalThis.Array.isArray(v)) return none;
    const rec = v as Record<string, unknown>;
    const out: Record<string, unknown> = {};
    for (const [key, codec] of entries) {
      const hasKey = Object.prototype.hasOwnProperty.call(rec, key) && rec[key] !== undefined;
      if (!hasKey) {
        if (codec.optional) continue;
        return none;
      }
      const res = codec.decode(rec[key]);
      if (res._tag === "None") return none;
      out[key] = res.value;
    }
    return some(out as StructOutput<F>);
  });
}

export function Union<const T extends readonly Codec<any>[]>(members: T): Codec<T[number]["Type"]> {
  return makeCodec((v) => {
    for (const member of members) {
      const res = member.decode(v);
      if (res._tag === "Some") return res;
    }
    return none;
  });
}

export function fromJsonString<T>(inner: Codec<T>): Codec<T> {
  return makeCodec((v) => {
    if (typeof v !== "string") return none;
    let parsed: unknown;
    try {
      parsed = JSON.parse(v);
    } catch {
      return none;
    }
    return inner.decode(parsed);
  });
}

export function decodeUnknownOption<T>(codec: Codec<T>): (input: unknown) => Option<T> {
  return (input) => codec.decode(input);
}

export function decodeUnknownSync<T>(codec: Codec<T>): (input: unknown) => T {
  return (input) => {
    const res = codec.decode(input);
    if (res._tag === "None") {
      throw new TypeError("Schema decode failed: unexpected value shape");
    }
    return res.value;
  };
}
