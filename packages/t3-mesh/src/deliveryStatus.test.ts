import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ToolResponse } from "./ipc.ts";
import { HttpRouterLink } from "./router/client.ts";
import { RouterCore } from "./router/core.ts";
import { DatabaseSync } from "node:sqlite";
import { DEFAULT_EVENT_LIMITS, DELIVERY_STATUS_SQL, EVENTS_SCHEMA } from "./router/events.ts";
import { serveRouter } from "./router/server.ts";
import type { InboxItem, InboundOutcome } from "./router/types.ts";
import { EnrollmentStore } from "./store.ts";
import { Subscriptions } from "./subscriptions.ts";

// Delivery visibility for reconciliation (docs/builder-subscriptions.md E5): what the router delivered,
// held, rejected or dropped per subscription, over HTTP, with a fake router clock for retention.

const HUB = "github-hub@bayfold-co-ops";
const KEY = "assignment:bayfold/infra#8";

const event = (id: string) => ({
  specversion: "1.0",
  id,
  source: "github.com/bayfold/infra",
  type: "com.github.pull_request_review.submitted",
  subject: "pull/9",
  datacontenttype: "application/json",
  repo: "bayfold/infra",
  data: { number: 9 },
});

const result = (response: ToolResponse): Record<string, unknown> => {
  if (!response.ok) throw new Error(`${response.error.code}: ${response.error.message}`);
  return response.result as Record<string, unknown>;
};

const waitFor = async (condition: () => boolean, timeoutMs = 5000) => {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) throw new Error("timed out");
    await new Promise((resolve) => setTimeout(resolve, 20));
  }
};

test("mesh_subscriptions reports delivered, held, rejected and expired batches; delivery is not handling", async () => {
  let now = Date.parse("2026-11-09T20:00:00Z");
  const dir = mkdtempSync(join(tmpdir(), "t3-mesh-delivery-"));
  const core = new RouterCore({
    dbPath: ":memory:",
    topics: new Map([["github", [HUB]]]),
    eventLimits: DEFAULT_EVENT_LIMITS,
    now: () => now,
  });
  const router = await serveRouter({ core, host: "127.0.0.1", port: 0 });
  const link = new HttpRouterLink(router.url, core.addConnector("b@host"));
  core.events.addPublisher(HUB, ["github"]);
  const subscriptions = new Subscriptions(EnrollmentStore.load(join(dir, "state.json")), link);
  try {
    const subscribed = result(
      await subscriptions.subscribe("child", { key: KEY, topic: "github", filters: [{ exact: { subject: "pull/9" } }], coalesceSeconds: 0 }),
    );
    const id = String(subscribed["id"]);
    // Before anything arrives: listed with zero counts, not as unknown.
    const empty = result(await subscriptions.listWithDelivery("child"))["subscriptions"] as Array<{ delivery: unknown }>;
    assert.deepEqual(empty[0]?.delivery, {
      pending: 0, oldestPendingAt: null, heldReason: null, delivered: 0, lastDeliveredAt: null, rejected: {}, dropped: {}, lastDroppedAt: null,
    });

    // The connector answers: deliver the first, reject the second, hold the rest (as a delivery-policy hold would).
    const answers: InboundOutcome[] = [
      { kind: "delivered" },
      { kind: "rejected", reason: "no_valid_events" },
    ];
    const seen: string[] = [];
    link.start(async (item: InboxItem) => {
      if (item.kind !== "event") return { kind: "delivered" };
      seen.push(item.id);
      return answers.shift() ?? { kind: "hold", reason: "policy:running" };
    });
    const publish = (eventId: string) => core.events.publish({ id: HUB, topics: new Set(["github"]) }, "github", event(eventId));
    for (const eventId of ["e1", "e2", "e3"]) {
      assert.equal((publish(eventId) as { matched?: number }).matched, 1);
      core.events.tick();
      await waitFor(() => seen.length >= Number(eventId.slice(1)));
    }
    await waitFor(() => {
      const status = core.events.deliveryStatus("b@host")[0];
      return status !== undefined && status.heldReason === "policy:running";
    });
    const mid = result(await subscriptions.listWithDelivery("child"))["subscriptions"] as Array<{ id: string; key: string; delivery: Record<string, unknown> }>;
    assert.equal(mid[0]?.id, id);
    assert.equal(mid[0]?.key, KEY);
    assert.equal(mid[0]?.delivery["delivered"], 1);
    assert.deepEqual(mid[0]?.delivery["rejected"], { no_valid_events: 1 });
    assert.equal(mid[0]?.delivery["pending"], 1);
    assert.equal(mid[0]?.delivery["heldReason"], "policy:running");

    // Past retention, the held batch is dropped unseen: visible as expired, for PM to recover from GitHub.
    await link.stop();
    now += DEFAULT_EVENT_LIMITS.retentionMs + 1000;
    core.events.tick();
    const after = core.events.deliveryStatus("b@host")[0];
    assert.equal(after?.pending, 0);
    assert.deepEqual(after?.dropped, { expired: 1 });
    assert.ok(after?.lastDroppedAt !== null);
  } finally {
    await link.stop();
    await router.close();
    core.close();
    rmSync(dir, { recursive: true, force: true });
  }
});

test("a router without the endpoint gives delivery null (unknown), not an empty history", async () => {
  const old = createServer((request, response) => {
    response.writeHead(request.url === "/v1/subscriptions/status" ? 404 : 200, { "content-type": "application/json" });
    response.end(JSON.stringify({ error: "not_found", message: "no route" }));
  });
  await new Promise<void>((resolve) => old.listen(0, "127.0.0.1", resolve));
  try {
    const link = new HttpRouterLink(`http://127.0.0.1:${(old.address() as AddressInfo).port}`, "token");
    assert.equal(await link.subscriptionStatus(), null);
    await link.stop();
  } finally {
    old.close();
  }
});

test("the status query reads only the asking connector's batches, by index", () => {
  const db = new DatabaseSync(":memory:");
  try {
    db.exec(EVENTS_SCHEMA);
    const plan = db
      .prepare(`EXPLAIN QUERY PLAN ${DELIVERY_STATUS_SQL}`)
      .all("a@host", "a@host")
      .map((row) => String(row["detail"]));
    assert.ok(plan.some((d) => /SEARCH subscriptions USING (COVERING )?INDEX subscriptions_connector/.test(d)), plan.join("\n"));
    assert.ok(plan.some((d) => /SEARCH batches USING INDEX batches_subscription \(subscription_id=\?/.test(d)), plan.join("\n"));
    assert.ok(!plan.some((d) => /SCAN batches/.test(d)), plan.join("\n"));
  } finally {
    db.close();
  }
});
