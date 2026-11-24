import { test } from "node:test";
import assert from "node:assert/strict";
import { encodeLine, LineSplitter, MAX_LINE_BYTES, parsePluginLine } from "./protocol.ts";

const event = { specversion: "1.0", id: "e1", source: "slack/T1", type: "com.slack.message", datacontenttype: "application/json", data: {} };

test("an event line carries its target, event, id and source", () => {
  assert.deepEqual(parsePluginLine(JSON.stringify({ type: "event", to: "moneypenny", event })), {
    kind: "event",
    to: "moneypenny",
    event,
    id: "e1",
    source: "slack/T1",
  });
});

test("lines that cannot be parsed get a nack with id null", () => {
  for (const text of ["not json", "[1,2]", "42", '{"no":"type"}', '{"type":7}']) {
    const line = parsePluginLine(text);
    assert.equal(line.kind, "nack", text);
    if (line.kind !== "nack") continue;
    assert.equal(line.nack.id, null);
    assert.equal(line.nack.source, null);
    assert.equal(line.nack.error, "invalid_event");
  }
});

test("unknown types get unsupported_type, reserved ones included", () => {
  for (const type of ["request", "response", "hello", "x".repeat(500)]) {
    const line = parsePluginLine(JSON.stringify({ type }));
    assert.equal(line.kind === "nack" ? line.nack.error : line.kind, "unsupported_type");
    assert.ok(line.kind === "nack" && line.nack.message.length < 100, "the echoed type is cut");
  }
});

test("a malformed event line is invalid_event, echoing a string id and source", () => {
  const line = parsePluginLine(JSON.stringify({ type: "event", event }));
  assert.deepEqual(line.kind === "nack" ? [line.nack.id, line.nack.source, line.nack.error] : null, ["e1", "slack/T1", "invalid_event"]);
  const numeric = parsePluginLine(JSON.stringify({ type: "event", to: 3, event: { ...event, id: 5, source: "s".repeat(400) } }));
  assert.deepEqual(numeric.kind === "nack" ? [numeric.nack.id, numeric.nack.source?.length] : null, [null, 256]);
});

test("replies are one JSON object per line", () => {
  assert.equal(
    encodeLine({ type: "ack", id: "e1", source: "s", status: "duplicate" }),
    '{"type":"ack","id":"e1","source":"s","status":"duplicate"}\n',
  );
});

test("the line splitter keeps at most maxBytes per line and reports overflow before the newline", () => {
  const splitter = new LineSplitter(8);
  const lines: Array<[string, boolean]> = [];
  const collect = (line: string, truncated: boolean) => lines.push([line, truncated]);
  splitter.push(Buffer.from("ab\r\ncd"), collect);
  assert.deepEqual(lines, [["ab", false]]);
  splitter.push(Buffer.from("efghijkl"), collect);
  assert.equal(splitter.overflowing, true);
  splitter.push(Buffer.from("m\nn"), collect);
  assert.deepEqual(lines.slice(1), [["cdefghij", true]]);
  assert.equal(splitter.overflowing, false);
  splitter.flush(collect);
  assert.deepEqual(lines.slice(2), [["n", false]]);
  assert.equal(MAX_LINE_BYTES, 64 * 1024);
});

test("without keepPrefix an overlong line is dropped unbuffered and reported empty at its newline", () => {
  const splitter = new LineSplitter(4, false);
  const lines: Array<[string, boolean]> = [];
  const collect = (line: string, truncated: boolean) => lines.push([line, truncated]);
  splitter.push(Buffer.from("abcdefgh"), collect);
  splitter.push(Buffer.from("ijkl"), collect);
  assert.equal(splitter.overflowing, true);
  splitter.push(Buffer.from("mn\nok\n"), collect);
  assert.deepEqual(lines, [
    ["", true],
    ["ok", false],
  ]);
});

test("multi-byte characters split across chunks survive", () => {
  const splitter = new LineSplitter(64);
  const lines: string[] = [];
  const bytes = Buffer.from("héllo\n");
  splitter.push(bytes.subarray(0, 2), (line) => lines.push(line));
  splitter.push(bytes.subarray(2), (line) => lines.push(line));
  assert.deepEqual(lines, ["héllo"]);
});
