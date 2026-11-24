import { test } from "node:test";
import assert from "node:assert/strict";
import { checkCloudEvent, eventDigest, type CloudEvent } from "./cloudevent.ts";

const base = {
  specversion: "1.0",
  id: "d1",
  source: "github.com/bayfold/infra",
  type: "com.github.ping",
  datacontenttype: "application/json",
  time: "2026-10-07T12:40:01Z",
  repo: "bayfold/infra",
  data: { number: null },
};

const error = (value: unknown): string => {
  const checked = checkCloudEvent(value);
  return checked.ok ? "ok" : checked.error;
};

test("accepts a minimal event", () => {
  assert.equal(error(base), "ok");
  const { time: _time, repo: _repo, ...minimal } = base;
  assert.equal(error(minimal), "ok");
});

test("rejects missing or malformed attributes", () => {
  assert.equal(error(null), "invalid_event");
  assert.equal(error([]), "invalid_event");
  assert.equal(error({ ...base, specversion: "0.3" }), "invalid_event");
  assert.equal(error({ ...base, datacontenttype: "text/plain" }), "invalid_event");
  for (const name of ["id", "source", "type"]) {
    assert.equal(error({ ...base, [name]: "" }), "invalid_event", name);
    assert.equal(error({ ...base, [name]: 1 }), "invalid_event", name);
  }
  assert.equal(error({ ...base, subject: 4 }), "invalid_event");
  assert.equal(error({ ...base, time: "yesterday" }), "invalid_event");
  assert.equal(error({ ...base, time: "2026-13-45T99:00:00Z" }), "invalid_event");
  assert.equal(error({ ...base, data: [] }), "invalid_event");
  assert.equal(error({ ...base, data: null }), "invalid_event");
  assert.equal(error({ ...base, data: "text" }), "invalid_event");
  assert.equal(error({ ...base, data_base64: "AA==" }), "invalid_event");
  assert.equal(error({ ...base, Repo: "x" }), "invalid_event");
  assert.equal(error({ ...base, averyveryverylongattributename: "x" }), "invalid_event");
  assert.equal(error({ ...base, repo: 4 }), "invalid_event");
  assert.equal(error({ ...base, repo: null }), "invalid_event");
});

test("size limits are too_large", () => {
  assert.equal(error({ ...base, subject: "x".repeat(256) }), "ok");
  assert.equal(error({ ...base, subject: "x".repeat(257) }), "too_large");
  assert.equal(error({ ...base, data: { text: "x".repeat(8 * 1024 - 20) } }), "ok");
  assert.equal(error({ ...base, data: { text: "x".repeat(8 * 1024) } }), "too_large");
  // Under 8 KiB of data but over 12 KiB in total.
  const attributes = Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`ext${i}`, "y".repeat(250)]));
  assert.equal(error({ ...base, ...attributes, data: { text: "x".repeat(7000) } }), "too_large");
});

test("too_large messages name the size and the limit that was hit", () => {
  const message = (value: unknown) => {
    const checked = checkCloudEvent(value);
    return checked.ok ? "ok" : checked.message;
  };
  assert.equal(message({ ...base, data: { text: "x".repeat(9000) } }), "data is 9011 bytes; limit 8192");
  assert.equal(message({ ...base, subject: "x".repeat(300) }), "attribute subject is 300 characters; limit 256");
  const attributes = Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`ext${i}`, "y".repeat(250)]));
  assert.match(message({ ...base, ...attributes, data: { text: "x".repeat(7000) } }), /^event is \d+ bytes; limit 12288$/);
});

test("the digest ignores time and key order", () => {
  const checked = checkCloudEvent(base);
  assert.ok(checked.ok);
  const reordered = { ...Object.fromEntries(Object.entries(base).reverse()), time: "2026-10-08T00:00:00Z" } as CloudEvent;
  assert.equal(eventDigest(checked.event), eventDigest(reordered));
  assert.notEqual(eventDigest(checked.event), eventDigest({ ...checked.event, data: { number: 1 } }));
  assert.notEqual(eventDigest(checked.event), eventDigest({ ...checked.event, subject: "pull/1" }));
});
