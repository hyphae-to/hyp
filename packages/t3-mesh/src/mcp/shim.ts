// `t3-mesh mcp`: the stdio MCP server that providers spawn. It holds no credentials; each
// tools/call is forwarded with its provider tool-call ID to the daemon, which verifies the caller.
import { createConnection } from "node:net";
import { createInterface } from "node:readline";
import * as Schema from "effect/Schema";
import { decodeToolResponse, type IpcRequest, type ToolResponse } from "../ipc.ts";
import { MCP_SERVER_NAME } from "../t3/caller.ts";
import { toolMetadata } from "../tools.ts";

const JsonRpcId = Schema.Union([Schema.String, Schema.Number]);
const JsonRpcMessage = Schema.Struct({
  id: Schema.optional(Schema.NullOr(JsonRpcId)),
  method: Schema.optional(Schema.String),
  params: Schema.optional(Schema.Unknown),
});
const CallParams = Schema.Struct({
  name: Schema.String,
  arguments: Schema.optional(Schema.Unknown),
  _meta: Schema.optional(Schema.Record(Schema.String, Schema.Unknown)),
});
const InitializeParams = Schema.Struct({ protocolVersion: Schema.optional(Schema.String) });

const decodeMessage = Schema.decodeUnknownOption(JsonRpcMessage);
const decodeCallParams = Schema.decodeUnknownOption(CallParams);
const decodeInitializeParams = Schema.decodeUnknownOption(InitializeParams);

type JsonRpcId = typeof JsonRpcId.Type;

const write = (message: Readonly<Record<string, unknown>>) =>
  process.stdout.write(JSON.stringify({ jsonrpc: "2.0", ...message }) + "\n");
const reply = (id: JsonRpcId, result: unknown) => write({ id, result });
const replyError = (id: JsonRpcId, code: number, message: string) => write({ id, error: { code, message } });

/** Claude Code sends `claudecode/toolUseId`; Codex sends `callId`. */
export function providerCallId(meta: Readonly<Record<string, unknown>> | undefined): string | null {
  const claude = meta?.["claudecode/toolUseId"];
  if (typeof claude === "string" && claude.length > 0) return claude;
  const codex = meta?.["callId"];
  if (typeof codex === "string" && codex.length > 0) return codex;
  return null;
}

function callDaemon(socketPath: string, request: IpcRequest, timeoutMs?: number): Promise<ToolResponse> {
  return new Promise((resolve) => {
    const socket = createConnection(socketPath);
    let buffer = "";
    if (timeoutMs !== undefined) socket.setTimeout(timeoutMs, () => {
      resolve({ ok: false, error: { code: "daemon_unavailable", message: "t3-mesh daemon timed out" } });
      socket.destroy();
    });
    socket.on("end", () => resolve({ ok: false, error: { code: "daemon_protocol", message: "t3-mesh daemon closed without a response" } }));
    socket.setEncoding("utf8");
    socket.on("connect", () => socket.write(JSON.stringify(request) + "\n"));
    socket.on("data", (chunk: string) => {
      buffer += chunk;
      const newline = buffer.indexOf("\n");
      if (newline < 0) return;
      socket.end();
      try {
        resolve(decodeToolResponse(JSON.parse(buffer.slice(0, newline))));
      } catch {
        resolve({ ok: false, error: { code: "daemon_protocol", message: "unreadable response from t3-mesh daemon" } });
      }
    });
    socket.on("error", (error) =>
      resolve({ ok: false, error: { code: "daemon_unavailable", message: `t3-mesh daemon: ${error.message}` } }),
    );
  });
}

/** A missing, older or unavailable daemon still allows primary-only MCP initialization. */
export async function daemonMetadata(socketPath: string, timeoutMs = 1500): Promise<ReturnType<typeof toolMetadata>> {
  const response = await callDaemon(socketPath, { type: "metadata" }, timeoutMs);
  const parsed = response.ok
    ? Schema.decodeUnknownOption(Schema.Struct({ eventRouters: Schema.Array(Schema.String) }))(response.result)
    : null;
  return toolMetadata(parsed?._tag === "Some" ? parsed.value.eventRouters : []);
}

export function runShim(socketPath: string): void {
  const metadata = daemonMetadata(socketPath);
  createInterface({ input: process.stdin }).on("line", async (line) => {
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      return;
    }
    const message = decodeMessage(parsed);
    if (message._tag === "None") return;
    const { id, method, params } = message.value;
    if (id === undefined || id === null || method === undefined) return; // notifications need no reply

    switch (method) {
      case "initialize": {
        const init = decodeInitializeParams(params ?? {});
        reply(id, {
          protocolVersion: init._tag === "Some" ? (init.value.protocolVersion ?? "2025-06-18") : "2025-06-18",
          capabilities: { tools: {} },
          serverInfo: { name: MCP_SERVER_NAME, version: "0.0.1" },
          instructions: (await metadata).instructions,
        });
        return;
      }
      case "ping":
        reply(id, {});
        return;
      case "tools/list":
        reply(id, { tools: (await metadata).tools });
        return;
      case "tools/call": {
        const call = decodeCallParams(params);
        if (call._tag === "None") {
          replyError(id, -32602, "invalid tools/call params");
          return;
        }
        const response = await callDaemon(socketPath, {
          tool: call.value.name,
          arguments: call.value.arguments ?? {},
          callId: providerCallId(call.value._meta),
        });
        reply(
          id,
          response.ok
            ? { content: [{ type: "text", text: JSON.stringify(response.result) }] }
            : { content: [{ type: "text", text: `${response.error.code}: ${response.error.message}` }], isError: true },
        );
        return;
      }
      default:
        replyError(id, -32601, `method not found: ${method}`);
    }
  });
}
