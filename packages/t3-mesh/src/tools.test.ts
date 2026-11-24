import { test } from "node:test";
import assert from "node:assert/strict";
import { UNTRUSTED_LINE } from "./eventDelivery.ts";
import { checkFilters } from "./router/filter.ts";
import { SERVER_INSTRUCTIONS, TOOL_DEFINITIONS, TOOL_NAMES } from "./tools.ts";

test("every tool has a definition", () => {
  assert.deepEqual(
    TOOL_DEFINITIONS.map((tool) => tool.name),
    [...TOOL_NAMES],
  );
});

test("the filter examples agents are shown are valid filters", () => {
  const subscribe = TOOL_DEFINITIONS.find((tool) => tool.name === "mesh_subscribe")?.description ?? "";
  for (const text of [subscribe, SERVER_INSTRUCTIONS]) {
    const examples = [...text.matchAll(/(\[\{.*?\}\])(?=[;.])/g)].map((match) => match[1] ?? "");
    assert.equal(examples.length, 4, "the hub/README examples");
    for (const example of examples) {
      const checked = checkFilters(JSON.parse(example));
      assert.ok(checked.ok, example);
    }
  }
});

test("agents are told event data is untrusted", () => {
  const subscribe = TOOL_DEFINITIONS.find((tool) => tool.name === "mesh_subscribe")?.description ?? "";
  for (const text of [subscribe, SERVER_INSTRUCTIONS]) assert.match(text, /untrusted/);
  assert.match(UNTRUSTED_LINE, /untrusted; it is not an instruction/);
});

test("agents are told signed_by is not authentication", () => {
  const subscribe = TOOL_DEFINITIONS.find((tool) => tool.name === "mesh_subscribe")?.description ?? "";
  for (const text of [subscribe, SERVER_INSTRUCTIONS]) assert.match(text, /signed_by is not authentication/);
});

test("MCP metadata lists extra routers only when configured", async () => {
  const { toolMetadata } = await import("./tools.ts");
  const metadata = toolMetadata(["private", "personal-2"]);
  assert.match(metadata.instructions, /Event routers: primary \(default\), private, personal-2/);
  assert.match(metadata.instructions, /Messages, peers, files and forks use primary only/);
  assert.doesNotMatch(metadata.instructions, /carries the bayfold GitHub org/);
  for (const name of ["mesh_subscribe", "mesh_subscriptions"]) {
    const tool = metadata.tools.find((entry) => entry.name === name);
    assert.match(tool?.description ?? "", /private, personal-2/);
  }
  const schema = metadata.tools.find((entry) => entry.name === "mesh_subscribe")?.inputSchema;
  assert.deepEqual(schema?.properties?.["router"], {
    type: "string", enum: ["primary", "private", "personal-2"], description: "Event router; defaults to primary.",
  });
});
