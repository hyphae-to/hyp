import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import * as Schema from "effect/Schema";
import { OrchestrationV2ThreadShellJson, type OrchestrationV2Command } from "@t3tools/contracts";
import { formatEventDelivery } from "./eventDelivery.ts";
import { eventRouterDelivery, InboundDelivery } from "./inbound.ts";
import type { InboxItem } from "./router/types.ts";
import type { T3Connection } from "./t3/connection.ts";
import { DEFAULT_POLICY } from "./t3/threadState.ts";

const thread = Schema.decodeUnknownSync(OrchestrationV2ThreadShellJson)(
  JSON.parse(readFileSync(new URL("./t3/fixtures/thread-shell.json", import.meta.url), "utf8")),
);
const event: InboxItem = {
  kind: "event", id: "same-batch", subscriptionId: "subscription", topic: "github", sentAt: "2026-11-21T00:00:00Z",
  events: [{ specversion: "1.0", id: "event", source: "github.com/bowd/test", type: "com.github.push", datacontenttype: "application/json", data: {} }],
};

test("extra-router delivery namespaces command IDs, refusal attempts and queue-only fallback", async () => {
  const commands: OrchestrationV2Command[] = [];
  const connection: Pick<T3Connection, "shellEntry" | "dispatch"> = {
    shellEntry: () => ({ thread, location: "active" }),
    dispatch: async (command) => {
      commands.push(command);
      return commands.length === 1
        ? { ok: false, kind: "rejected", message: "No running provider turn found" }
        : { ok: true, sequence: commands.length };
    },
  };
  const delivery = new InboundDelivery({ policy: DEFAULT_POLICY, delivery: "steer" });
  const privateDelivery = eventRouterDelivery("private", (batch, prefix) =>
    delivery.dispatch(connection, thread.id, prefix, batch.id, formatEventDelivery(batch), null),
  );
  assert.equal((await privateDelivery(event)).kind, "hold");
  assert.deepEqual(await privateDelivery(event), { kind: "delivered" });
  // A primary batch and another extra router can reuse the same ID without inheriting the refusal.
  assert.deepEqual(await delivery.dispatch(connection, thread.id, "mesh-event", event.id, "primary", null), { kind: "delivered" });
  const otherDelivery = eventRouterDelivery("other", (batch, prefix) =>
    delivery.dispatch(connection, thread.id, prefix, batch.id, "other", null),
  );
  await otherDelivery(event);
  await privateDelivery(event); // Lost ack replays the successful command ID.
  assert.deepEqual(commands.map((command) => command.commandId), [
    "mesh-event-router:private:same-batch:1", "mesh-event-router:private:same-batch:2", "mesh-event:same-batch:1",
    "mesh-event-router:other:same-batch:1", "mesh-event-router:private:same-batch:2",
  ]);
  assert.deepEqual(commands.map((command) => command.type === "message.dispatch" ? command.deliveryIntent : null), [
    "auto", undefined, "auto", "auto", undefined,
  ]);
  const first = commands[0];
  assert.ok(first?.type === "message.dispatch");
  assert.equal(first.messageId, first.commandId);
  assert.match(first.text, /mesh event github/);
});

test("extra routers reject message and transfer items without dispatching them", async () => {
  let called = false;
  const receive = eventRouterDelivery("private", async () => { called = true; return { kind: "delivered" }; });
  const message: InboxItem = { kind: "message", id: "message", from: "b@host/a", to: "b@host/b", text: "no", sentAt: "now", origin: null };
  const transfer: InboxItem = { kind: "transfer", id: "transfer", from: "b@host", type: "fork", size: 0, header: { payload: "x", sig: "x" }, sentAt: "now" };
  assert.deepEqual(await receive(message), { kind: "rejected", reason: "event_only_router" });
  assert.deepEqual(await receive(transfer), { kind: "rejected", reason: "event_only_router" });
  assert.equal(called, false);
});

test("a primary ID containing the router name cannot collide with an extra event's ID or retry keys", async () => {
  const commands: OrchestrationV2Command[] = [];
  const connection: Pick<T3Connection, "shellEntry" | "dispatch"> = {
    shellEntry: () => ({ thread, location: "active" }),
    dispatch: async (command) => {
      commands.push(command);
      return commands.length === 1
        ? { ok: false, kind: "rejected", message: "No running provider turn found" }
        : { ok: true, sequence: commands.length };
    },
  };
  const delivery = new InboundDelivery({ policy: DEFAULT_POLICY, delivery: "steer" });
  await delivery.dispatch(connection, thread.id, "mesh-event", "private:abc", "primary", null);
  const receive = eventRouterDelivery("private", (batch, prefix) => delivery.dispatch(connection, thread.id, prefix, batch.id, "private", null));
  await receive({ ...event, id: "abc" });
  await delivery.dispatch(connection, thread.id, "mesh-event", "private:abc", "primary", null);
  assert.deepEqual(commands.map((command) => command.commandId), [
    "mesh-event:private:abc:1", "mesh-event-router:private:abc:1", "mesh-event:private:abc:2",
  ]);
  assert.deepEqual(commands.map((command) => command.type === "message.dispatch" ? command.deliveryIntent : null), ["auto", "auto", undefined]);
});

test("an event's explicit delivery mode selects queue or native restart", async () => {
  const intents: Array<string | undefined> = [];
  const connection: Pick<T3Connection, "shellEntry" | "dispatch"> = {
    shellEntry: () => ({ thread: { ...thread, status: "running" }, location: "active" }),
    dispatch: async (command) => {
      assert.equal(command.type, "message.dispatch");
      intents.push(command.deliveryIntent);
      return command.deliveryIntent === "restart"
        ? { ok: false, kind: "rejected", message: "providerInstanceId cannot satisfy a required interrupt-and-restart" }
        : { ok: true, sequence: intents.length };
    },
  };
  const delivery = new InboundDelivery({ policy: DEFAULT_POLICY, delivery: "steer" });
  assert.equal((await delivery.dispatch(connection, thread.id, "mesh-event", "a", "event", null, "queue")).kind, "delivered");
  for (let retry = 0; retry < 4; retry++) {
    const outcome = await delivery.dispatch(connection, thread.id, "mesh-event", "b", "event", null, "interrupt");
    assert.equal(outcome.kind, "hold");
  }
  assert.deepEqual(intents, [undefined, "restart", "restart", "restart", "restart"]);
});
