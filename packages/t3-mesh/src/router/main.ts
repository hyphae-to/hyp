#!/usr/bin/env node
// Router-only entrypoint: needs only `effect` (the version in vendor/t3code's contracts) and node
// builtins, not the vendored T3 packages. Its dependencies are pinned in router/package.json and
// router/package-lock.json; install them at the tree root, next to src/. Same subcommands as `t3-mesh router`:
// node src/router/main.ts serve --db <path> --audit <path> [--host 127.0.0.1] [--port 8790] [--topic <name>=<publisher id>[,...]]...
// node src/router/main.ts add-connector <id> --db <path> --token-out <path>
// node src/router/main.ts revoke-connector <id> --db <path>
// node src/router/main.ts add-publisher <id> --topic <name> --db <path> --token-out <path>
// node src/router/main.ts revoke-publisher <id> --db <path>
// node src/router/main.ts github-receiver --listen <host:port> --router <url> --topic <name> --secret-file <path> --token-file <path>
import { errorMessage, log } from "../log.ts";
import { routerUsage, RouterUsageError, runRouterCommand } from "./commands.ts";

try {
  await runRouterCommand(process.argv.slice(2));
} catch (error) {
  if (error instanceof RouterUsageError) {
    process.stderr.write(`${error.message}\n\nusage: node src/router/main.ts <command>\n${routerUsage}\n`);
    process.exit(2);
  }
  log("error", "fatal", { error: errorMessage(error) });
  process.exit(1);
}
