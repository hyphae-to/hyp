// A plugin process for the supervisor tests. Appends a start record and every line it receives on
// fd 3 to $RECORD, writes $LINES (a JSON array of strings) on fd 3, then behaves as $MODE says:
//   crash-first   exit 1 shortly after the first start; stay up after later ones
//   close-fd3     close fd 3 and stay up
//   flood         write a line longer than 64 KiB before $LINES
//   ignore-term   ignore SIGTERM
//   exit-after    exit 1 after $EXIT_AFTER_MS
// It exits when fd 3 closes, as a plugin should.
import { appendFileSync, readFileSync } from "node:fs";
import { Socket } from "node:net";

const env = process.env;
const record = env["RECORD"] ?? "/dev/null";
const mode = env["MODE"] ?? "";
const parsedLines: unknown = JSON.parse(env["LINES"] ?? "[]");
const lines = Array.isArray(parsedLines) ? parsedLines.filter((line) => typeof line === "string") : [];

const starts = readFileSync(record, "utf8").split("\n").filter((line) => line.startsWith('{"start"')).length;
appendFileSync(
  record,
  JSON.stringify({
    start: starts + 1,
    fd: env["T3_MESH_FD"] ?? null,
    plugin: env["T3_MESH_PLUGIN"] ?? null,
    protocol: env["T3_MESH_PROTOCOL"] ?? null,
    configured: env["CONFIGURED"] ?? null,
    leaked: env["NOT_PASSED"] ?? null,
    cwd: process.cwd(),
  }) + "\n",
);

const channel = new Socket({ fd: 3, readable: true, writable: true });
let buffer = "";
channel.setEncoding("utf8");
channel.on("data", (chunk: string) => {
  buffer += chunk;
  for (let newline = buffer.indexOf("\n"); newline >= 0; newline = buffer.indexOf("\n")) {
    appendFileSync(record, buffer.slice(0, newline + 1));
    buffer = buffer.slice(newline + 1);
  }
});
channel.on("end", () => process.exit(0));
channel.on("error", () => process.exit(0));

if (mode === "flood") channel.write(`${"x".repeat(70 * 1024)}\n`);
for (const line of lines) channel.write(`${line}\n`);
process.stdout.write("plugin says hi\n");
process.stderr.write(`${"e".repeat(3000)}\n`);

if (mode === "crash-first" && starts === 0) setTimeout(() => process.exit(1), 300);
if (mode === "close-fd3") {
  channel.removeAllListeners("end");
  channel.removeAllListeners("error");
  channel.destroy();
}
if (mode === "ignore-term") process.on("SIGTERM", () => undefined);
if (mode === "exit-after") setTimeout(() => process.exit(1), Number(env["EXIT_AFTER_MS"] ?? "0"));
setInterval(() => undefined, 1_000);
