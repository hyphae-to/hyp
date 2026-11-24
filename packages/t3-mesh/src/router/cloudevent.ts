// CloudEvents 1.0 (structured JSON mode) as published to router topics (SPEC.md section 12.2):
// validation, size limits and the idempotency digest. Also used by publishers to check what they send.
import { createHash } from "node:crypto";

export const TOPIC = /^[a-z0-9][a-z0-9._-]{0,63}$/;
export const isTopic = (value: string): boolean => TOPIC.test(value);

export const MAX_DATA_BYTES = 8 * 1024;
export const MAX_EVENT_BYTES = 12 * 1024;
export const MAX_ATTRIBUTE_CHARS = 256;

/** Extension attribute names: lowercase alphanumeric, at most 20 characters (CloudEvents 1.0). */
const EXTENSION_NAME = /^[a-z0-9]{1,20}$/;
const REQUIRED = ["id", "source", "type"] as const;
const OPTIONAL = ["subject", "time"] as const;
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

export interface CloudEvent {
  readonly specversion: "1.0";
  readonly id: string;
  readonly source: string;
  readonly type: string;
  readonly datacontenttype: "application/json";
  readonly subject?: string;
  readonly time?: string;
  readonly data: Readonly<Record<string, unknown>>;
  /** Extension attributes: string values. */
  readonly [attribute: string]: unknown;
}

export type EventCheck =
  | { readonly ok: true; readonly event: CloudEvent; readonly bytes: number }
  | { readonly ok: false; readonly error: "invalid_event" | "too_large"; readonly message: string };

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const invalid = (message: string): EventCheck => ({ ok: false, error: "invalid_event", message });
const tooLarge = (message: string): EventCheck => ({ ok: false, error: "too_large", message });

export function checkCloudEvent(value: unknown): EventCheck {
  if (!isRecord(value)) return invalid("the body must be a CloudEvent JSON object");
  if (value["specversion"] !== "1.0") return invalid('specversion must be "1.0"');
  if (value["datacontenttype"] !== "application/json") return invalid('datacontenttype must be "application/json"');
  for (const name of REQUIRED) {
    const attribute = value[name];
    if (typeof attribute !== "string" || attribute.length === 0) return invalid(`${name} must be a non-empty string`);
  }
  for (const name of OPTIONAL) {
    if (name in value && typeof value[name] !== "string") return invalid(`${name} must be a string`);
  }
  const time = value["time"];
  if (typeof time === "string" && (!RFC3339.test(time) || Number.isNaN(Date.parse(time)))) {
    return invalid("time must be an RFC 3339 timestamp");
  }
  const data = value["data"];
  if (!isRecord(data)) return invalid("data must be a JSON object");
  for (const [name, attribute] of Object.entries(value)) {
    if (name === "data") continue;
    if (!EXTENSION_NAME.test(name)) return invalid(`attribute name ${JSON.stringify(name.slice(0, 64))} is not lowercase alphanumeric`);
    if (typeof attribute !== "string") return invalid(`attribute ${name} must be a string`);
    if (attribute.length > MAX_ATTRIBUTE_CHARS) {
      return tooLarge(`attribute ${name} is ${attribute.length} characters; limit ${MAX_ATTRIBUTE_CHARS}`);
    }
  }
  const dataBytes = Buffer.byteLength(JSON.stringify(data), "utf8");
  if (dataBytes > MAX_DATA_BYTES) return tooLarge(`data is ${dataBytes} bytes; limit ${MAX_DATA_BYTES}`);
  const bytes = Buffer.byteLength(JSON.stringify(value), "utf8");
  if (bytes > MAX_EVENT_BYTES) return tooLarge(`event is ${bytes} bytes; limit ${MAX_EVENT_BYTES}`);
  return { ok: true, event: value as CloudEvent, bytes };
}

/** JSON with object keys sorted, so equal content gives equal text regardless of key order. */
export function canonicalJson(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (isRecord(value)) {
    const keys = Object.keys(value).sort();
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

/**
 * Idempotency digest of an event: everything but `time`, which a publisher may stamp with the
 * receipt time and which then differs on a redelivery.
 */
export function eventDigest(event: CloudEvent): string {
  const { time: _time, ...rest } = event;
  return createHash("sha256").update(canonicalJson(rest)).digest("hex");
}
