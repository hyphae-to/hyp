import { test } from "node:test";
import assert from "node:assert/strict";
import { classifyRefusal, MAX_REFUSED_ATTEMPTS } from "./refusal.ts";

test("a steer into an ending run is held and retried as a queued message", () => {
  for (const message of [
    "No running provider turn found for active run run:thread:211d20cd:ordinal:101.",
    "Target run run:x is completed and cannot be steered.",
    "Provider thread pt:1 has no active provider session for steering.",
    "Wait for context compaction to finish before steering the thread.",
  ]) {
    // Even past the refusal limit: the queued retry cannot hit the steer path again.
    const refusal = classifyRefusal(message, MAX_REFUSED_ATTEMPTS + 2);
    assert.equal(refusal.outcome.kind, "hold", message);
    assert.equal(refusal.queueNext, true, message);
  }
});

test("other refusals are retried a few times, then rejected", () => {
  const message = "Thread thread:x is archived.";
  for (let attempt = 1; attempt < MAX_REFUSED_ATTEMPTS; attempt++) {
    assert.deepEqual(classifyRefusal(message, attempt).outcome.kind, "hold");
  }
  assert.deepEqual(classifyRefusal(message, MAX_REFUSED_ATTEMPTS), {
    outcome: { kind: "rejected", reason: `t3_rejected: ${message}` },
    queueNext: false,
  });
});

test("a stale command ID is held without counting as a refusal of the message", () => {
  assert.deepEqual(classifyRefusal("Command mesh:1:1 was previously rejected.", 9).outcome, {
    kind: "hold",
    reason: "stale_command_id",
  });
});
