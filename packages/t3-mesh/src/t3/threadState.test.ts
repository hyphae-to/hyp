import { test } from "node:test";
import assert from "node:assert/strict";
import * as DateTime from "effect/DateTime";
import { classifyThread, type ThreadStateFields } from "./threadState.ts";

const base: ThreadStateFields = {
  status: "idle",
  archivedAt: null,
  deletedAt: null,
  settledAt: null,
  settledOverride: null,
};
const someTime = DateTime.nowUnsafe();

test("classifies run statuses", () => {
  assert.equal(classifyThread(base, "active"), "idle");
  assert.equal(classifyThread({ ...base, status: "completed" }, "active"), "idle");
  assert.equal(classifyThread({ ...base, status: "running" }, "active"), "busy");
  assert.equal(classifyThread({ ...base, status: "waiting" }, "active"), "busy");
  assert.equal(classifyThread({ ...base, status: "interrupted" }, "active"), "stopped");
  assert.equal(classifyThread({ ...base, status: "failed" }, "active"), "failed");
});

test("archive wins over everything", () => {
  assert.equal(classifyThread({ ...base, status: "running" }, "archive"), "archived");
});

test("settled unless overridden active, and never while busy", () => {
  assert.equal(classifyThread({ ...base, settledAt: someTime }, "active"), "settled");
  assert.equal(classifyThread({ ...base, settledAt: someTime, settledOverride: "active" }, "active"), "idle");
  assert.equal(classifyThread({ ...base, settledOverride: "settled" }, "active"), "settled");
  assert.equal(classifyThread({ ...base, status: "running", settledAt: someTime }, "active"), "busy");
});
