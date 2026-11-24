#!/usr/bin/env node
// Ultra-thin CLI dispatcher: routes hot-path protocol commands (`hook`, `mcp`, `wait`, `watch`)
// to `cli-fast.ts` without eagerly importing daemon, setup, RouterCore, or TUI modules.
const cmd = process.argv[2];
if (cmd === "hook" || cmd === "mcp" || cmd === "wait" || cmd === "watch") {
  const { runFastCli } = await import("./cli-fast.ts");
  await runFastCli(process.argv.slice(2));
} else {
  await import("./cli-full.ts");
}
