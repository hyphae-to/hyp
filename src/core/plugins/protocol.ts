// The plugin channel (SPEC.md section 13.3): newline-delimited JSON on fd 3, at most 64 KiB per line.
// Parsing of plugin lines, the connector's replies, and a line splitter that bounds what it buffers.
import * as Schema from "../validate.ts";

export const PROTOCOL_VERSION = 1;
/**
 * Room for a 12 KiB event written with every non-ASCII character escaped (\uXXXX, up to six bytes
 * per UTF-8 byte). Event limits are measured on the parsed event, as at the router.
 */
export const MAX_LINE_BYTES = 64 * 1024;

/** The nack for a line over MAX_LINE_BYTES, which is discarded unread. */
export const lineTooLarge = (): Extract<ConnectorLine, { type: "nack" }> =>
  nack(null, null, "too_large", `the line is over ${MAX_LINE_BYTES} bytes; line limit ${MAX_LINE_BYTES}`);
/** Echoed `id` and `source` are cut to this; a longer one fails the CloudEvent check anyway. */
const MAX_ECHO_CHARS = 256;

export type NackError =
  | "invalid_event"
  | "too_large"
  | "unknown_target"
  | "id_conflict"
  | "unavailable"
  | "unsupported_type";

/** Connector -> plugin. `request` and `response` are reserved for a later connector -> plugin channel. */
export type ConnectorLine =
  | { readonly type: "hello"; readonly protocol: number; readonly plugin: string; readonly targets: readonly string[] }
  | { readonly type: "ack"; readonly id: string; readonly source: string; readonly status: "stored" | "duplicate" }
  | {
      readonly type: "nack";
      readonly id: string | null;
      readonly source: string | null;
      readonly error: NackError;
      readonly message: string;
    }
  | {
      readonly type: "status";
      readonly target: string;
      readonly pending: number;
      readonly oldestAgeSeconds: number;
      readonly t3Connected: boolean;
    }
  | {
      /** A stored batch could not be delivered and was dropped (SPEC.md section 13.4). */
      readonly type: "delivery_failed";
      readonly target: string;
      readonly events: readonly { readonly id: string; readonly source: string }[];
      readonly reason: string;
    }
  | {
      /** Bidirectional connector -> plugin request (e.g. outbound `hyp_plugin_post`). */
      readonly type: "request";
      readonly id: string;
      readonly method: "post";
      readonly target: string;
      readonly params: Readonly<Record<string, unknown>>;
    };

/** A plugin line: an event to store, a response to a connector request, or the nack it gets without reaching the store. */
export type PluginLine =
  | { readonly kind: "event"; readonly to: string; readonly event: unknown; readonly id: string | null; readonly source: string | null }
  | { readonly kind: "response"; readonly id: string; readonly ok: boolean; readonly result?: unknown; readonly error?: string }
  | { readonly kind: "nack"; readonly nack: Extract<ConnectorLine, { type: "nack" }> };

const Line = Schema.Struct({ type: Schema.String });
const EventLine = Schema.Struct({ type: Schema.Literal("event"), to: Schema.String, event: Schema.Unknown });
const ResponseLine = Schema.Struct({
  type: Schema.Literal("response"),
  id: Schema.String,
  ok: Schema.Boolean,
  result: Schema.optionalKey(Schema.Unknown),
  error: Schema.optionalKey(Schema.String),
});
const EventKey = Schema.Struct({ id: Schema.optionalKey(Schema.Unknown), source: Schema.optionalKey(Schema.Unknown) });
const decodeLine = Schema.decodeUnknownOption(Line);
const decodeEventLine = Schema.decodeUnknownOption(EventLine);
const decodeResponseLine = Schema.decodeUnknownOption(ResponseLine);
const decodeEventKey = Schema.decodeUnknownOption(EventKey);

const echo = (value: unknown): string | null => (typeof value === "string" ? value.slice(0, MAX_ECHO_CHARS) : null);

export const nack = (
  id: string | null,
  source: string | null,
  error: NackError,
  message: string,
): Extract<ConnectorLine, { type: "nack" }> => ({ type: "nack", id, source, error, message });

export function parsePluginLine(text: string): PluginLine {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    return { kind: "nack", nack: nack(null, null, "invalid_event", "the line is not JSON") };
  }
  const line = decodeLine(value);
  if (line._tag === "None") {
    return { kind: "nack", nack: nack(null, null, "invalid_event", "a line must be a JSON object with a string type") };
  }
  if (line.value.type === "response") {
    const resp = decodeResponseLine(value);
    if (resp._tag === "None") {
      return { kind: "nack", nack: nack(null, null, "invalid_event", 'a response line is {"type":"response","id":<id>,"ok":<bool>}') };
    }
    return {
      kind: "response",
      id: resp.value.id,
      ok: resp.value.ok,
      ...(resp.value.result !== undefined ? { result: resp.value.result } : {}),
      ...(resp.value.error !== undefined ? { error: resp.value.error } : {}),
    };
  }
  if (line.value.type !== "event") {
    // Not a protocol violation: later protocol versions may add types.
    return {
      kind: "nack",
      nack: nack(null, null, "unsupported_type", `unsupported type ${JSON.stringify(line.value.type.slice(0, 64))}`),
    };
  }
  const key = decodeEventKey(typeof value === "object" && value !== null && "event" in value ? value.event : undefined);
  const id = key._tag === "Some" ? echo(key.value.id) : null;
  const source = key._tag === "Some" ? echo(key.value.source) : null;
  const event = decodeEventLine(value);
  if (event._tag === "None") {
    return { kind: "nack", nack: nack(id, source, "invalid_event", 'an event line is {"type":"event","to":<target>,"event":<CloudEvent>}') };
  }
  return { kind: "event", to: event.value.to, event: event.value.event, id, source };
}

export const encodeLine = (line: ConnectorLine): string => `${JSON.stringify(line)}\n`;

/**
 * Splits a byte stream into lines, keeping at most `maxBytes` of each: what it buffers is bounded
 * even when a peer never sends a newline. A longer line is cut to its first `maxBytes`, or with
 * `keepPrefix` false discarded entirely (emitted as "" with `truncated`). A trailing "\r" is dropped.
 */
export class LineSplitter {
  readonly #maxBytes: number;
  readonly #keepPrefix: boolean;
  #parts: Buffer[] = [];
  #size = 0;
  #overflow = false;

  constructor(maxBytes: number, keepPrefix = true) {
    this.#maxBytes = maxBytes;
    this.#keepPrefix = keepPrefix;
  }

  /** Whether the line being read is already longer than `maxBytes`. */
  get overflowing(): boolean {
    return this.#overflow;
  }

  /** Calls `onLine` for each complete line with its first `maxBytes` bytes and whether it was cut. */
  push(chunk: Buffer, onLine: (line: string, truncated: boolean) => void): void {
    let start = 0;
    for (;;) {
      const newline = chunk.indexOf(0x0a, start);
      this.#take(chunk.subarray(start, newline < 0 ? chunk.length : newline));
      if (newline < 0) return;
      this.#emit(onLine);
      start = newline + 1;
    }
  }

  /** Emits an unterminated last line, if any. */
  flush(onLine: (line: string, truncated: boolean) => void): void {
    if (this.#size > 0 || this.#overflow) this.#emit(onLine);
  }

  #take(part: Buffer): void {
    if (this.#overflow && !this.#keepPrefix) return;
    const room = this.#maxBytes - this.#size;
    if (part.length > room) {
      this.#overflow = true;
      if (!this.#keepPrefix) {
        this.#parts = [];
        this.#size = 0;
        return;
      }
    }
    const kept = part.subarray(0, Math.max(0, Math.min(room, part.length)));
    if (kept.length === 0) return;
    this.#parts.push(kept);
    this.#size += kept.length;
  }

  #emit(onLine: (line: string, truncated: boolean) => void): void {
    const text = Buffer.concat(this.#parts).toString("utf8");
    const truncated = this.#overflow;
    this.#parts = [];
    this.#size = 0;
    this.#overflow = false;
    onLine(text.endsWith("\r") ? text.slice(0, -1) : text, truncated);
  }
}
